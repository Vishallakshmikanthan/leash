"""
daemon/agent_api.py - Dedicated Agent Plane server strictly confined to agent tool submissions.
Enforces per-session capability tokens, CWD confinement, and provenance reporting.
Cannot decide, pair, view audit logs, or manage sessions.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from aiohttp import web

from contracts.models import (
    ActionKind,
    ActionRequest,
    Decision,
    ProvenanceEvent,
    ProvenanceKind,
    TaintContext,
)
from daemon.paths import agent_socket_path
from session.manager import SessionManager, confine_cwd

logger = logging.getLogger("leash.daemon.agent_api")


class AgentApiServer:
    """Agent Plane HTTP/IPC server handling agent requests authenticated with session capability tokens."""

    def __init__(
        self,
        session_mgr: SessionManager,
        submit_action_fn: Callable[[ActionRequest], Any],
        emit_provenance_fn: Optional[Callable[[ProvenanceEvent], Any]] = None,
        get_pending_fn: Optional[Callable[[str], Optional[Decision]]] = None,
        host: str = "127.0.0.1",
        port: int = 8766,
    ):
        self.session_mgr = session_mgr
        self.submit_action_fn = submit_action_fn
        self.emit_provenance_fn = emit_provenance_fn
        self.get_pending_fn = get_pending_fn
        self.host = host
        self.port = port
        self.app = web.Application()
        self._setup_routes()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.unix_site: Optional[web.UnixSite] = None

    def _setup_routes(self) -> None:
        self.app.router.add_post("/v1/action", self._handle_post_action)
        self.app.router.add_get("/v1/action/{id}", self._handle_get_action)
        self.app.router.add_post("/v1/provenance", self._handle_post_provenance)

    def _authenticate(self, request: web.Request):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header[7:].strip()
        if not token:
            return None
        return self.session_mgr.get_session_by_token(token)

    async def _handle_post_action(self, request: web.Request) -> web.Response:
        session = self._authenticate(request)
        if not session:
            return web.json_response({"error": "unauthorized: missing or invalid session capability token"}, status=401)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json payload"}, status=400)

        raw_cwd = body.get("cwd", session.worktree_path)
        try:
            safe_cwd = confine_cwd(raw_cwd, session.worktree_path)
        except PermissionError as e:
            logger.warning(f"CWD confinement violation for session {session.session_id}: {e}")
            return web.json_response({"error": f"forbidden: {e}"}, status=403)

        action_id = body.get("id") or f"act_{uuid.uuid4().hex[:12]}"
        kind_str = body.get("kind", "shell")
        try:
            kind = ActionKind(kind_str)
        except ValueError:
            kind = ActionKind.SHELL

        taint_raw = body.get("taint", {})
        taint = TaintContext.from_dict(taint_raw) if isinstance(taint_raw, dict) else TaintContext()

        action_req = ActionRequest(
            id=action_id,
            session=session.session_id,  # Bound strictly to authenticated session
            ts=int(body.get("ts", time.time())),
            nonce=body.get("nonce") or uuid.uuid4().hex[:16],
            kind=kind,
            agent=session.agent,
            cwd=safe_cwd,
            command=body.get("command"),
            target_path=body.get("target_path"),
            tool_name=body.get("tool_name"),
            tool_args=body.get("tool_args"),
            worktree=session.worktree_path,
            taint=taint,
            scope_flags=body.get("scope_flags", []),
        )

        res = self.submit_action_fn(action_req)
        decision = await res if asyncio.iscoroutine(res) else res

        return web.json_response({
            "action_id": decision.action_id,
            "session": decision.session,
            "verdict": decision.verdict.value if hasattr(decision.verdict, "value") else str(decision.verdict),
            "by": decision.by.value if hasattr(decision.by, "value") else str(decision.by),
            "note": decision.note,
        })

    async def _handle_get_action(self, request: web.Request) -> web.Response:
        session = self._authenticate(request)
        if not session:
            return web.json_response({"error": "unauthorized"}, status=401)

        action_id = request.match_info["id"]
        if self.get_pending_fn:
            decision = self.get_pending_fn(action_id)
            if decision:
                return web.json_response({
                    "action_id": decision.action_id,
                    "verdict": decision.verdict.value if hasattr(decision.verdict, "value") else str(decision.verdict),
                    "by": decision.by.value if hasattr(decision.by, "value") else str(decision.by),
                    "note": decision.note,
                })
        return web.json_response({"action_id": action_id, "status": "pending"})

    async def _handle_post_provenance(self, request: web.Request) -> web.Response:
        session = self._authenticate(request)
        if not session:
            return web.json_response({"error": "unauthorized"}, status=401)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)

        kind_str = body.get("kind", "untrusted_file_read")
        try:
            kind = ProvenanceKind(kind_str)
        except ValueError:
            kind = ProvenanceKind.UNTRUSTED_FILE_READ

        p_event = ProvenanceEvent(
            id=body.get("id") or f"prov_{uuid.uuid4().hex[:10]}",
            session=session.session_id,
            ts=int(body.get("ts", time.time())),
            kind=kind,
            source=body.get("source", "unspecified"),
            line=body.get("line"),
            flags=body.get("flags", []),
            snippet=body.get("snippet"),
            nonce=body.get("nonce", ""),
        )

        self.session_mgr.record_provenance_event(p_event)
        if self.emit_provenance_fn:
            res = self.emit_provenance_fn(p_event)
            if asyncio.iscoroutine(res):
                await res

        return web.json_response({"status": "recorded", "id": p_event.id})

    async def start(self) -> None:
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        # Always bind to 127.0.0.1 for local TCP plane
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        logger.info(f"Agent Plane TCP server running on {self.host}:{self.port}")

        # On Unix, also bind to domain socket with 0600 permissions
        if sys.platform != "win32":
            sock_path = agent_socket_path()
            if sock_path.exists():
                try:
                    sock_path.unlink()
                except OSError:
                    pass
            sock_path.parent.mkdir(parents=True, exist_ok=True)
            self.unix_site = web.UnixSite(self.runner, str(sock_path))
            await self.unix_site.start()
            try:
                sock_path.chmod(0o600)
            except OSError:
                pass
            logger.info(f"Agent Plane Unix domain socket running on {sock_path}")

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
