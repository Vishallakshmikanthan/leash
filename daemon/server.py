"""
daemon/server.py - Async WebSocket & HTTP server connecting Laptop interceptor to Android Guard and local tools.
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import time
import uuid

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from aiohttp import web

from contracts.crypto import LeashSigner
from contracts.models import (
    ActionKind,
    ActionRequest,
    CommandResult,
    DecidedBy,
    Decision,
    ProvenanceEvent,
    ProvenanceKind,
    RiskAssessment,
    Severity,
    Verdict,
)

from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from gates.secret_fence import CanaryManager, SecretRedactor
from session.manager import SessionManager


logger = logging.getLogger("leash.daemon")


@dataclass
class ConnectedPhone:
    ws: web.WebSocketResponse
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    authenticated: bool = False
    connected_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    client_ip: str = "unknown"


class LeashDaemonServer:
    """Core daemon managing WebSocket transport, security evaluation, and approvals."""

    def __init__(
        self,
        config: DaemonConfig,
        session_mgr: SessionManager,
        audit_logger: AuditLogger,
        policy_evaluator: Optional[PolicyEvaluator] = None,
        local_decider: Optional[Callable[[ActionRequest, RiskAssessment], Awaitable[Decision]]] = None,
    ):
        self.config = config
        self.session_mgr = session_mgr
        self.audit_logger = audit_logger
        self.evaluator = policy_evaluator or PolicyEvaluator(config.allow_command_patterns)
        self.signer = LeashSigner(config.shared_secret)
        self.local_decider = local_decider
        self.canary_mgr = CanaryManager()
        self.redactor = SecretRedactor(custom_canary_tokens=set(self.canary_mgr.registered_canaries.keys()))

        # Active phone client connections (WebSocket)
        self.connected_clients: Set[web.WebSocketResponse] = set()
        self.authenticated_clients: Set[web.WebSocketResponse] = set()
        self.clients: Dict[web.WebSocketResponse, ConnectedPhone] = {}

        self.pending_decisions: Dict[str, asyncio.Future[Decision]] = {}
        self.pending_metadata: Dict[str, Dict[str, Any]] = {}

        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.default_session_id: Optional[str] = None
        self._running = False

    def register_local_decider(
        self, decider: Optional[Callable[[ActionRequest, RiskAssessment], Awaitable[Decision]]]
    ) -> None:
        """Register a programmatic decision callback for automated testing / dev approval."""
        self.local_decider = decider

    def has_decision_channel(self) -> bool:
        """Checks if a decision channel (authenticated Phone Guard, local decider, or dev mode) is available."""
        if len(self.authenticated_clients) > 0:
            return True
        if self.local_decider is not None:
            return True
        if self.config.dev_mode:
            return True
        return False

    async def start(self) -> None:
        """Start the dual WebSocket & HTTP server."""
        self.app = web.Application()
        self.app.router.add_get("/", self._handle_root)
        self.app.router.add_get("/ws", self._handle_ws_route)
        self.app.router.add_get("/status", self._handle_status)
        self.app.router.add_get("/health", self._handle_status)
        self.app.router.add_get("/pairing", self._handle_pairing)
        self.app.router.add_get("/pending", self._handle_get_pending)
        self.app.router.add_get("/audit", self._handle_get_audit)
        self.app.router.add_get("/sessions", self._handle_get_sessions)
        self.app.router.add_post("/sessions", self._handle_post_sessions)
        self.app.router.add_get("/sessions/{session_id}", self._handle_get_session_details)
        self.app.router.add_post("/sessions/{session_id}/pause", self._handle_post_pause_session)
        self.app.router.add_post("/sessions/{session_id}/resume", self._handle_post_resume_session)
        self.app.router.add_post("/sessions/{session_id}/terminate", self._handle_post_terminate_session)
        self.app.router.add_post("/sessions/{session_id}/rewind", self._handle_post_rewind_session)
        self.app.router.add_get("/sessions/{session_id}/snapshots", self._handle_get_session_snapshots)
        self.app.router.add_post("/sessions/{session_id}/scope", self._handle_post_session_scope)
        self.app.router.add_get("/sessions/{session_id}/activity", self._handle_get_session_activity)
        self.app.router.add_post("/action", self._handle_post_action)
        self.app.router.add_post("/decision", self._handle_post_decision)
        self.app.router.add_post("/provenance", self._handle_post_provenance)
        self.app.router.add_get("/sessions/{session_id}/provenance", self._handle_get_session_provenance)
        self.app.router.add_post("/api/package-gate/allow-once", self._handle_post_package_allow_once)
        self.app.router.add_get("/api/package-gate/status", self._handle_get_package_gate_status)


        # Ensure at least one session exists
        if not self.default_session_id:
            default_session = self.session_mgr.create_session()
            self.default_session_id = default_session.session_id

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.config.host, self.config.port)
        await self.site.start()
        self._running = True
        logger.info(f"Leash Daemon started on {self.config.host}:{self.config.port}")

    async def stop(self) -> None:
        """Gracefully shut down connections and server."""
        self._running = False
        # Cancel any pending decision futures
        for action_id, fut in list(self.pending_decisions.items()):
            if not fut.done():
                fut.cancel()
        self.pending_decisions.clear()
        self.pending_metadata.clear()

        # Close all active WebSockets
        for ws in list(self.connected_clients):
            try:
                await ws.close(code=1000, message=b"Server shutting down")
            except Exception:
                pass
        self.connected_clients.clear()
        self.authenticated_clients.clear()
        self.clients.clear()

        if self.runner:
            await self.runner.cleanup()
            self.runner = None
            self.site = None
        logger.info("Leash Daemon stopped.")

    # -------------------------------------------------------------------------
    # Route Handlers
    # -------------------------------------------------------------------------

    async def _handle_root(self, request: web.Request) -> web.Response:
        """Handles root path: upgrades to WebSocket if requested, or returns status JSON."""
        if request.headers.get("Upgrade", "").lower() == "websocket":
            return await self._handle_ws(request)
        return await self._handle_status(request)

    async def _handle_ws_route(self, request: web.Request) -> web.Response:
        return await self._handle_ws(request)

    async def _handle_ws(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        client_ip = request.remote or "unknown"
        phone = ConnectedPhone(ws=ws, client_ip=client_ip)
        self.clients[ws] = phone
        self.connected_clients.add(ws)

        # In dev mode, auto-authenticate connection for test convenience unless strict
        if self.config.dev_mode:
            phone.authenticated = True
            self.authenticated_clients.add(ws)

        logger.info(f"Phone Guard connected via WebSocket from {client_ip}")

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    await self._process_incoming_ws_message(ws, msg.data)
                elif msg.type == web.WSMsgType.ERROR:
                    logger.warning(f"WebSocket connection closed with error: {ws.exception()}")
        finally:
            self.connected_clients.discard(ws)
            self.authenticated_clients.discard(ws)
            self.clients.pop(ws, None)
            logger.info(f"Phone Guard disconnected from {client_ip}")

            # Enforce fail-closed if no decision channel remains
            if not self.has_decision_channel() and not self.config.dev_mode:
                for action_id, fut in list(self.pending_decisions.items()):
                    if not fut.done():
                        fail_dec = Decision(
                            id=f"d_fail_closed_{action_id}",
                            action_id=action_id,
                            session=self.pending_metadata.get(action_id, {}).get("request", ActionRequest(
                                id=action_id, session=self.default_session_id or "s_default", ts=int(time.time()), nonce="", kind=ActionKind.SHELL, agent="", cwd=""
                            )).session,
                            ts=int(time.time()),
                            nonce=self.signer.generate_nonce(),
                            verdict=Verdict.DENY,
                            by=DecidedBy.TIMEOUT,
                            note="Connection severed to Phone Guard: failed closed.",
                        )
                        fut.set_result(fail_dec)

        return ws

    async def _handle_status(self, request: web.Request) -> web.Response:
        phones_info = [
            {
                "device_id": c.device_id,
                "device_name": c.device_name,
                "authenticated": c.authenticated,
                "connected_at": c.connected_at,
                "last_heartbeat": c.last_heartbeat,
                "ip": c.client_ip,
            }
            for c in self.clients.values()
        ]
        return web.json_response({
            "status": "ok",
            "version": "1.0.0",
            "connected_phones": len(self.connected_clients),
            "authenticated_phones": len(self.authenticated_clients),
            "phones": phones_info,
            "pending_decisions": len(self.pending_decisions),
            "default_session": self.default_session_id,
            "decision_channel_available": self.has_decision_channel(),
            "auto_allow_low_risk": self.config.auto_allow_low_risk,
            "fail_closed_high_risk": self.config.fail_closed_high_risk,
            "dev_mode": self.config.dev_mode,
        })

    async def _handle_pairing(self, request: web.Request) -> web.Response:
        return web.json_response({
            "host": self.config.host,
            "port": self.config.port,
            "shared_secret": self.config.shared_secret,
            "protocol_version": "1.0",
            "qr_uri": f"leash://pair?host={self.config.host}&port={self.config.port}&secret={self.config.shared_secret}",
            "status": "ready",
        })

    async def _handle_get_pending(self, request: web.Request) -> web.Response:
        now = time.time()
        pending_list = []
        for action_id, meta in self.pending_metadata.items():
            req: ActionRequest = meta["request"]
            assessment: RiskAssessment = meta["assessment"]
            start_ts = meta["start_time"]
            pending_list.append({
                "action_id": action_id,
                "session_id": req.session,
                "kind": req.kind.value,
                "command": req.command,
                "target_path": req.target_path,
                "severity": assessment.severity.value,
                "category": assessment.category,
                "summary": assessment.summary,
                "why": assessment.why,
                "tainted": req.taint.tainted,
                "elapsed_seconds": round(now - start_ts, 2),
            })
        return web.json_response({"count": len(pending_list), "pending": pending_list})

    async def _handle_get_audit(self, request: web.Request) -> web.Response:
        session_id = request.query.get("session")
        if session_id:
            activity = self.audit_logger.get_session_activity(session_id)
            return web.json_response(activity)
        limit_str = request.query.get("limit")
        limit = int(limit_str) if limit_str and limit_str.isdigit() else 100
        events = self.audit_logger.read_all_events(limit=limit)
        sessions = self.audit_logger.list_sessions()
        return web.json_response({"events": events, "sessions": sessions, "total_events": len(events)})

    async def _handle_get_sessions(self, request: web.Request) -> web.Response:
        active_only = request.query.get("active", "").lower() in ("true", "1")
        sessions = self.session_mgr.list_sessions(active_only=active_only)
        sessions_data = [s.to_dict() for s in sessions]
        # Also include any historic sessions found in audit log
        audit_sessions = self.audit_logger.list_sessions()
        known_ids = {s.get("session_id") for s in sessions_data if isinstance(s, dict)}
        for asess in audit_sessions:
            asid = asess.get("session_id") if isinstance(asess, dict) else str(asess)
            if asid and asid not in known_ids:
                sessions_data.append(asess if isinstance(asess, dict) else {
                    "session_id": asid,
                    "created_at": 0,
                    "worktree_path": "",
                    "repo_path": str(self.session_mgr.repo_root),
                    "agent": "coding-agent",
                    "state": "terminated",
                })
                known_ids.add(asid)
        return web.json_response({
            "sessions": sessions_data,
            "count": len(sessions_data),
            "active_session": self.session_mgr.active_session_id,
        })

    async def _handle_post_sessions(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            body = {}

        allowed_paths = body.get("allowed_paths")
        allowed_commands = body.get("allowed_commands")
        allowed_hosts = body.get("allowed_hosts")
        agent_name = body.get("agent") or body.get("agent_name") or "coding-agent"
        task_description = body.get("task_description")
        session_id = body.get("session_id") or body.get("session")
        base_ref = body.get("base_ref", "HEAD")

        scope = self.session_mgr.create_session(
            allowed_paths=allowed_paths,
            allowed_commands=allowed_commands,
            allowed_hosts=allowed_hosts,
            agent_name=agent_name,
            task_description=task_description,
            session_id=session_id,
            base_ref=base_ref,
        )

        await self.broadcast_to_phone("session_created", scope.to_dict())
        return web.json_response(scope.to_dict(), status=201)

    async def _handle_get_session_details(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        details = self.session_mgr.get_session_details(session_id)
        if not details:
            return web.json_response({"error": f"Session '{session_id}' not found"}, status=404)
        return web.json_response(details)

    async def _handle_post_pause_session(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        ok = self.session_mgr.pause_session(session_id)
        if not ok:
            return web.json_response(
                {"error": f"Could not pause session '{session_id}' (not active or not found)"}, status=400
            )
        session = self.session_mgr.get_session(session_id)
        payload = session.to_dict() if session else {"session_id": session_id, "state": "paused"}
        await self.broadcast_to_phone("session_state_changed", payload)
        return web.json_response({"status": "ok", "session_id": session_id, "state": "paused"})

    async def _handle_post_resume_session(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        ok = self.session_mgr.resume_session(session_id)
        if not ok:
            return web.json_response(
                {"error": f"Could not resume session '{session_id}' (not paused or not found)"}, status=400
            )
        session = self.session_mgr.get_session(session_id)
        payload = session.to_dict() if session else {"session_id": session_id, "state": "active"}
        await self.broadcast_to_phone("session_state_changed", payload)
        return web.json_response({"status": "ok", "session_id": session_id, "state": "active"})

    async def _handle_post_terminate_session(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        try:
            body = await request.json()
        except Exception:
            body = {}
        reason = body.get("reason", "User requested termination")
        cleanup_worktree = bool(body.get("cleanup_worktree", True))
        save_branch = bool(body.get("save_branch", True))

        scope = self.session_mgr.terminate_session(
            session_id=session_id,
            reason=reason,
            cleanup_worktree=cleanup_worktree,
            save_branch=save_branch,
        )
        if not scope:
            return web.json_response({"error": f"Session '{session_id}' not found"}, status=404)

        await self.broadcast_to_phone("session_state_changed", scope.to_dict())
        return web.json_response(scope.to_dict())

    async def _handle_post_rewind_session(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        try:
            body = await request.json()
        except Exception:
            body = {}
        git_ref = body.get("git_ref")
        ok = self.session_mgr.rewind(session_id, git_ref)
        if not ok:
            return web.json_response({"error": f"Rewind failed for session '{session_id}'"}, status=400)

        await self.broadcast_to_phone("rewind_executed", {
            "session_id": session_id, "git_ref": git_ref, "success": True
        })
        return web.json_response({"status": "ok", "session_id": session_id, "rewound": True})

    async def _handle_get_session_snapshots(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        snaps = self.session_mgr.list_snapshots(session_id)
        return web.json_response({"session_id": session_id, "snapshots": [s.to_dict() for s in snaps]})

    async def _handle_post_session_scope(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        scope = self.session_mgr.update_session_scope(
            session_id=session_id,
            allowed_paths=body.get("allowed_paths"),
            allowed_commands=body.get("allowed_commands"),
            allowed_hosts=body.get("allowed_hosts"),
        )
        if not scope:
            return web.json_response({"error": f"Session '{session_id}' not found"}, status=404)
        return web.json_response(scope.to_dict())

    async def _handle_get_session_activity(self, request: web.Request) -> web.Response:
        session_id = request.match_info.get("session_id", "")
        activity = self.audit_logger.get_session_activity(session_id)
        return web.json_response(activity)

    async def _handle_post_action(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        # Build ActionRequest
        action_id = body.get("id") or f"a_{uuid.uuid4().hex[:12]}"
        session_id = body.get("session") or self.default_session_id or "s_default"
        kind_str = body.get("kind", "shell")
        try:
            kind = ActionKind(kind_str)
        except ValueError:
            kind = ActionKind.SHELL

        action_req = ActionRequest(
            id=action_id,
            session=session_id,
            ts=body.get("ts") or int(time.time()),
            nonce=body.get("nonce") or self.signer.generate_nonce(),
            kind=kind,
            command=body.get("command"),
            target_path=body.get("target_path"),
            tool_name=body.get("tool_name"),
            tool_args=body.get("tool_args"),
            cwd=body.get("cwd", "."),
            agent=body.get("agent", "coding-agent"),
            worktree=body.get("worktree"),
            scope_flags=body.get("scope_flags", []),
        )

        should_execute = bool(body.get("execute", False))
        if should_execute:
            cmd_result = await self.execute_action(action_req)
            return web.json_response(cmd_result.to_dict())
        else:
            decision = await self.submit_action(action_req)
            assessment = self.evaluator.evaluate(action_req)
            return web.json_response({
                "decision": decision.to_dict(),
                "assessment": assessment.to_dict(),
            })

    async def _handle_post_decision(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        action_id = data.get("action_id")
        if not action_id or action_id not in self.pending_decisions:
            return web.json_response(
                {"error": f"No pending decision found for action_id: {action_id}"}, status=404
            )

        verdict_str = data.get("verdict", "deny").lower()
        verdict = Verdict.ALLOW if verdict_str == "allow" else Verdict.DENY
        by_str = data.get("by", "tap").lower()
        try:
            by = DecidedBy(by_str)
        except ValueError:
            by = DecidedBy.TAP

        decision = Decision(
            id=data.get("id") or f"d_{uuid.uuid4().hex[:12]}",
            action_id=action_id,
            session=data.get("session") or self.pending_metadata.get(action_id, {}).get("request", ActionRequest(
                id=action_id, session=self.default_session_id or "s_default", ts=int(time.time()), nonce="", kind=ActionKind.SHELL, agent="", cwd=""
            )).session,
            ts=data.get("ts") or int(time.time()),
            nonce=data.get("nonce") or self.signer.generate_nonce(),
            verdict=verdict,
            by=by,
            note=data.get("note", "Decision received via dev approval channel."),
        )

        if verdict == Verdict.ALLOW and (
            data.get("allow_once")
            or "allow-once" in (decision.note or "").lower()
            or "allow_once" in (decision.note or "").lower()
        ):
            self._register_allow_once_from_decision(action_id, decision)

        fut = self.pending_decisions[action_id]
        if not fut.done():
            fut.set_result(decision)

        return web.json_response({"status": "ok", "action_id": action_id, "verdict": verdict.value})

    def _register_allow_once_from_decision(
        self, action_id: str, decision: Decision, request: Optional[ActionRequest] = None
    ) -> None:
        """Registers a safe allow-once authorization from an approval decision."""
        if not self.evaluator.package_gate:
            return
        req = request
        if not req:
            meta = self.pending_metadata.get(action_id, {})
            req = meta.get("request")
        if not req:
            return
        from gates.package_gate import PackageActionParser
        parsed = PackageActionParser.parse_action(req)
        for pkg in parsed.packages:
            self.evaluator.package_gate.allow_once(
                package_name=pkg.name,
                version=pkg.version,
                session_id=decision.session,
                decider=decision.by.value,
                note=decision.note or "Allow-once granted via approval flow",
            )

    async def _handle_post_package_allow_once(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body"}, status=400)

        pkg = body.get("package") or body.get("package_name")
        if not pkg:
            return web.json_response({"error": "Field 'package' is required"}, status=400)

        version = body.get("version")
        session_id = body.get("session_id") or self.default_session_id
        decider = body.get("decided_by", "biometric")
        note = body.get("note", "Allow-once granted via API")

        if self.evaluator.package_gate:
            grant = self.evaluator.package_gate.allow_once(
                package_name=pkg,
                version=version,
                session_id=session_id,
                decider=decider,
                note=note,
            )
            return web.json_response({
                "status": "ok",
                "grant_id": grant.grant_id,
                "package": grant.package_name,
                "version": grant.version,
                "session_id": grant.session_id,
                "decided_by": grant.decided_by,
            })
        return web.json_response({"error": "PackageGate not active"}, status=503)

    async def _handle_get_package_gate_status(self, request: web.Request) -> web.Response:
        if not self.evaluator.package_gate:
            return web.json_response({"active": False})

        gate = self.evaluator.package_gate
        return web.json_response({
            "active": True,
            "offline_mode": gate.offline_mode,
            "popular_packages_count": len(gate.knowledge.popular_packages),
            "known_packages_count": len(gate.knowledge.known_packages),
            "allow_once_grants": gate.allow_once_mgr.list_grants(),
        })

    # -------------------------------------------------------------------------
    # WebSocket Message Processing
    # -------------------------------------------------------------------------

    async def _process_incoming_ws_message(self, ws: web.WebSocketResponse, raw_msg: str) -> None:
        if not raw_msg:
            return
        phone = self.clients.get(ws)
        if not phone:
            return

        try:
            data = json.loads(raw_msg)
            msg_type = data.get("type")
            payload = data.get("payload", {})

            # 1. Pairing & Authentication Handshake
            if msg_type in ("auth", "pair"):
                device_id = payload.get("device_id", "phone_guard")
                device_name = payload.get("device_name", "Android Guard")
                ts = payload.get("ts")
                nonce = payload.get("nonce", "")
                sig = payload.get("sig", "")

                clean_dict = {
                    "device_id": device_id,
                    "device_name": device_name,
                    "nonce": nonce,
                    "ts": ts,
                }
                canon_bytes = json.dumps(clean_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
                valid = self.signer.verify(canon_bytes, sig, int(ts) if ts is not None else 0, nonce)

                if valid or self.config.dev_mode:
                    phone.authenticated = True
                    phone.device_id = device_id
                    phone.device_name = device_name
                    phone.last_heartbeat = time.time()
                    self.authenticated_clients.add(ws)

                    ack_nonce = self.signer.generate_nonce()
                    ack_ts = int(time.time())
                    ack_dict = {
                        "nonce": ack_nonce,
                        "server_version": "1.0",
                        "session_id": self.default_session_id or "s_default",
                        "status": "authenticated",
                        "ts": ack_ts,
                    }
                    ack_sig = self.signer.sign(
                        json.dumps(ack_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
                    )
                    ack_dict["sig"] = ack_sig
                    await ws.send_str(json.dumps({"type": "auth_ack", "payload": ack_dict}))
                    logger.info(f"Phone Guard authenticated successfully: {device_id} ({device_name})")
                else:
                    logger.warning(f"Phone Guard authentication failed from {phone.client_ip}")
                    err_msg = {
                        "type": "auth_error",
                        "payload": {"reason": "Authentication failed: invalid signature, timestamp drift, or replayed nonce"},
                    }
                    await ws.send_str(json.dumps(err_msg))
                    await ws.close(code=4001, message=b"Authentication failed")

            # 2. Decision Exchange
            elif msg_type == "decision":
                if not phone.authenticated and not self.config.dev_mode:
                    logger.warning(f"Unauthenticated decision rejected from {phone.client_ip}")
                    await ws.send_str(json.dumps({
                        "type": "error",
                        "payload": {"code": "UNAUTHENTICATED", "message": "Authentication required."}
                    }))
                    return

                decision = Decision.from_dict(payload)

                # Verify HMAC signature and freshness
                valid = True
                if decision.sig:
                    valid = self.signer.verify(
                        decision.payload_for_signature(),
                        decision.sig,
                        decision.ts,
                        decision.nonce,
                    )
                elif not self.config.dev_mode:
                    valid = False

                if not valid:
                    logger.warning(f"Rejected invalid signature for decision {decision.id}")
                    await ws.send_str(json.dumps({
                        "type": "error",
                        "payload": {
                            "action_id": decision.action_id,
                            "code": "INVALID_SIGNATURE",
                            "message": "Signature verification failed, expired timestamp, or replayed nonce",
                        }
                    }))
                    return

                action_id = decision.action_id
                if action_id in self.pending_decisions:
                    fut = self.pending_decisions[action_id]
                    if not fut.done():
                        if decision.verdict == Verdict.ALLOW and (
                            payload.get("allow_once")
                            or "allow-once" in (decision.note or "").lower()
                            or "allow_once" in (decision.note or "").lower()
                        ):
                            self._register_allow_once_from_decision(action_id, decision)
                        fut.set_result(decision)
                        # Send reliable confirmation ack back to phone
                        await ws.send_str(json.dumps({
                            "type": "decision_ack",
                            "payload": {
                                "action_id": action_id,
                                "decision_id": decision.id,
                                "status": "accepted",
                                "verdict": decision.verdict.value,
                            }
                        }))
                else:
                    logger.warning(f"Received decision for untracked action_id {action_id}")
                    await ws.send_str(json.dumps({
                        "type": "error",
                        "payload": {
                            "action_id": action_id,
                            "code": "UNKNOWN_ACTION",
                            "message": "No pending action found matching action_id",
                        }
                    }))

            # 2b. Package Allow-Once Direct Message
            elif msg_type == "package_allow_once":
                pkg = payload.get("package") or payload.get("package_name")
                ver = payload.get("version")
                sess = payload.get("session_id") or self.default_session_id
                if pkg and self.evaluator.package_gate:
                    grant = self.evaluator.package_gate.allow_once(
                        package_name=pkg,
                        version=ver,
                        session_id=sess,
                        decider="biometric",
                        note=payload.get("note", "Allow-once granted via phone Guard"),
                    )
                    await ws.send_str(json.dumps({
                        "type": "package_allow_once_ack",
                        "payload": {
                            "grant_id": grant.grant_id,
                            "package": grant.package_name,
                            "session_id": grant.session_id,
                            "status": "authorized",
                        }
                    }))

            # 3. Heartbeat / Liveness
            elif msg_type == "heartbeat":
                phone.last_heartbeat = time.time()
                echo_nonce = payload.get("nonce", "")
                ack_nonce = self.signer.generate_nonce()
                now_ts = int(time.time())
                ack_dict = {
                    "echo_nonce": echo_nonce,
                    "nonce": ack_nonce,
                    "ts": now_ts,
                }
                ack_sig = self.signer.sign(
                    json.dumps(ack_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
                )
                ack_dict["sig"] = ack_sig
                await ws.send_str(json.dumps({
                    "type": "heartbeat_ack",
                    "payload": ack_dict,
                }))

            # 4. Request Audit History for Session
            elif msg_type == "get_audit_history":
                sess_id = payload.get("session_id") or self.default_session_id or "s_default"
                activity = self.audit_logger.get_session_activity(sess_id)
                await ws.send_str(json.dumps({
                    "type": "audit_history",
                    "payload": activity,
                }))

            # 5. Request Sessions Overview
            elif msg_type == "get_sessions":
                sessions = [s.to_dict() for s in self.session_mgr.list_sessions()]
                await ws.send_str(json.dumps({
                    "type": "sessions_list",
                    "payload": {"sessions": sessions, "count": len(sessions)},
                }))

            # 6. Session Lifecycle Messages from Phone
            elif msg_type == "create_session":
                sess = self.session_mgr.create_session(
                    allowed_paths=payload.get("allowed_paths"),
                    allowed_commands=payload.get("allowed_commands"),
                    allowed_hosts=payload.get("allowed_hosts"),
                    agent_name=payload.get("agent", "coding-agent"),
                    task_description=payload.get("task_description"),
                )
                await ws.send_str(json.dumps({
                    "type": "session_created",
                    "payload": sess.to_dict(),
                }))

            elif msg_type == "terminate_session":
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                scope = self.session_mgr.terminate_session(
                    session_id=sess_id or "",
                    reason=payload.get("reason", "Terminated via phone"),
                    cleanup_worktree=payload.get("cleanup_worktree", True),
                    save_branch=payload.get("save_branch", True),
                )
                await ws.send_str(json.dumps({
                    "type": "session_terminated",
                    "payload": scope.to_dict() if scope else {},
                }))

            elif msg_type == "pause_session":
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                ok = self.session_mgr.pause_session(sess_id or "")
                await ws.send_str(json.dumps({
                    "type": "session_paused",
                    "payload": {"session_id": sess_id, "success": ok},
                }))

            elif msg_type == "resume_session":
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                ok = self.session_mgr.resume_session(sess_id or "")
                await ws.send_str(json.dumps({
                    "type": "session_resumed",
                    "payload": {"session_id": sess_id, "success": ok},
                }))

            elif msg_type in ("rewind", "rewind_session"):
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                git_ref = payload.get("git_ref")
                ok = self.session_mgr.rewind(sess_id or "", git_ref)
                await ws.send_str(json.dumps({
                    "type": "rewind_result",
                    "payload": {"session_id": sess_id, "git_ref": git_ref, "success": ok},
                }))

            elif msg_type == "get_session_details":
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                details = self.session_mgr.get_session_details(sess_id or "")
                await ws.send_str(json.dumps({
                    "type": "session_details",
                    "payload": details or {},
                }))

            elif msg_type == "query_provenance":
                sess_id = payload.get("session_id") or self.session_mgr.active_session_id
                events = [e.to_dict() for e in self.session_mgr.get_provenance_events(sess_id or "")]
                taint = self.session_mgr.get_taint_context(sess_id or "")
                await ws.send_str(json.dumps({
                    "type": "provenance_status",
                    "payload": {
                        "session_id": sess_id,
                        "tainted": taint.tainted,
                        "taint": taint.to_dict(),
                        "events": events,
                    }
                }))

        except Exception as e:
            logger.error(f"Error handling phone message: {e}")

    async def broadcast_to_phone(self, msg_type: str, payload: dict) -> bool:
        targets = self.authenticated_clients if self.authenticated_clients else self.connected_clients
        if not targets:
            return False

        message_str = json.dumps({"type": msg_type, "payload": payload})
        dead_clients = set()

        for ws in list(targets):
            try:
                await ws.send_str(message_str)
            except Exception:
                dead_clients.add(ws)

        for dw in dead_clients:
            self.connected_clients.discard(dw)
            self.authenticated_clients.discard(dw)
            self.clients.pop(dw, None)

        return len(self.authenticated_clients) > 0 or len(self.connected_clients) > 0

    async def emit_provenance_event(self, event: ProvenanceEvent) -> bool:
        """Signs and broadcasts ProvenanceEvent to Phone Guard, taints session, logs audit."""
        if not event.nonce:
            event.nonce = self.signer.generate_nonce()
        if not event.sig:
            event.sig = self.signer.sign(event.payload_for_signature())

        # Record in session manager (taints session state)
        self.session_mgr.record_provenance_event(event)

        # Record in audit log
        self.audit_logger.record_event(
            event_type="provenance_event",
            session_id=event.session,
            action_id=event.id,
            kind=event.kind.value,
            verdict="taint",
            risk_severity="high",
            decided_by="provenance_gate",
            target_path=event.source,
            tainted=True,
            metadata={"flags": event.flags, "snippet": event.snippet, "line": event.line},
        )

        # Broadcast event to connected Android Guard
        return await self.broadcast_to_phone("provenance_event", event.to_dict())


    # -------------------------------------------------------------------------
    # Interception Core
    # -------------------------------------------------------------------------

    async def submit_action(self, request: ActionRequest) -> Decision:
        """Evaluates ActionRequest, auto-allows or waits for approval, records audit log."""
        start_time = time.time()

        # 1. Bind request to session, agent, worktree, scope flags, taint, and runaway guard
        request = self.session_mgr.bind_action(request)
        taint = request.taint

        # Emit any unbroadcasted provenance events recorded for this session
        for p_evt in self.session_mgr.get_provenance_events(request.session):
            if not getattr(p_evt, "_broadcasted", False):
                p_evt._broadcasted = True
                asyncio.create_task(self.emit_provenance_event(p_evt))


        # 2. Enforce session lifecycle states (terminated / paused block immediately)
        if "session-terminated" in request.scope_flags:
            reason = "Execution denied: session has been terminated."
            return Decision(
                id=f"d_term_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=Verdict.DENY,
                by=DecidedBy.RULE,
                note=reason,
            )
        if "session-paused" in request.scope_flags:
            reason = "Execution denied: session is currently paused."
            return Decision(
                id=f"d_paused_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=Verdict.DENY,
                by=DecidedBy.RULE,
                note=reason,
            )

        # Sign request if unsigned
        if not request.sig:
            request.sig = self.signer.sign(request.payload_for_signature())

        # 3. Local rule triage (Quick Allow for clean low-risk)
        if self.config.auto_allow_low_risk and self.evaluator.is_quick_allow(request):
            latency = (time.time() - start_time) * 1000
            evt = self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict="allow",
                risk_severity="low",
                risk_category="normal-development",
                decided_by="auto",
                agent=request.agent,
                worktree=request.worktree,
                risk_assessment={
                    "severity": "low",
                    "category": "normal-development",
                    "summary": "Safe standard development command auto-allowed by policy",
                    "why": "Command matches low-risk allow patterns",
                    "rule_ids": ["R-ALLOW-TESTS"],
                },
                latency_ms=latency,
                tainted=taint.tainted,
            )
            asyncio.create_task(self.broadcast_to_phone("audit_event", evt.to_dict()))
            return Decision(
                id=f"d_auto_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=Verdict.ALLOW,
                by=DecidedBy.AUTO,
                note="Auto-allowed by local policy.",
            )

        # 3. Evaluate risk assessment
        assessment = self.evaluator.evaluate(request)

        # Immediate Canary Alert handling
        if assessment.category == "canary-touched" or "R-SECRET-CANARY" in assessment.rule_ids:
            canary_target = request.target_path or request.command or "canary_secret"
            self.audit_logger.record_canary_alert(
                session_id=request.session,
                action_id=request.id,
                target_or_command=request.command or request.target_path or "",
                canary_token_or_file=canary_target,
                agent=request.agent,
                worktree=request.worktree,
            )
            p_canary = ProvenanceEvent(
                id=f"p_canary_{uuid.uuid4().hex[:8]}",
                session=request.session,
                ts=int(time.time()),
                kind=ProvenanceKind.CANARY_READ,
                source=canary_target,
                line=1,
                flags=["canary-breach", "security-alert"],
                snippet=f"Canary credential breached: {canary_target}",
            )
            self.session_mgr.record_provenance_event(p_canary)
            asyncio.create_task(
                self.broadcast_to_phone(
                    "canary_alert",
                    {
                        "action_id": request.id,
                        "session_id": request.session,
                        "target": canary_target,
                        "summary": assessment.summary,
                        "why": assessment.why,
                        "severity": "critical",
                    },
                )
            )

        # 4. Low risk permitted automatically if clean
        if assessment.severity == Severity.LOW and not taint.tainted and self.config.auto_allow_low_risk:
            latency = (time.time() - start_time) * 1000
            evt = self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict="allow",
                risk_severity="low",
                risk_category=assessment.category,
                decided_by="rule",
                agent=request.agent,
                worktree=request.worktree,
                risk_assessment=assessment.to_dict(),
                latency_ms=latency,
                tainted=False,
            )
            asyncio.create_task(self.broadcast_to_phone("audit_event", evt.to_dict()))
            return Decision(
                id=f"d_rule_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=Verdict.ALLOW,
                by=DecidedBy.RULE,
                note="Safe standard development action allowed by rule.",
            )

        # 5. Pre-action snapshot for High risk
        snapshot_ref = None
        if assessment.severity in (Severity.HIGH, Severity.CRITICAL):
            snapshot = self.session_mgr.create_pre_action_snapshot(
                request.session, f"Pre-action snapshot for {request.id}: {request.command or request.kind.value}"
            )
            if snapshot:
                snapshot_ref = snapshot.git_ref

        # 6. Check if decision channel is available (Fail Closed if unavailable)
        channel_available = self.has_decision_channel()
        if not channel_available:
            verdict = (
                Verdict.DENY
                if assessment.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)
                else Verdict.ALLOW
            )
            decided_by = DecidedBy.RULE if verdict == Verdict.ALLOW else DecidedBy.TIMEOUT
            note = (
                "Decision channel unavailable: failed closed for risky operation."
                if verdict == Verdict.DENY
                else "Decision channel unavailable: low risk permitted."
            )

            latency = (time.time() - start_time) * 1000
            evt = self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict=verdict.value,
                risk_severity=assessment.severity.value,
                risk_category=assessment.category,
                decided_by=decided_by.value,
                agent=request.agent,
                worktree=request.worktree,
                risk_assessment=assessment.to_dict(),
                latency_ms=latency,
                snapshot_ref=snapshot_ref,
                tainted=taint.tainted,
                metadata={"note": note},
            )
            asyncio.create_task(self.broadcast_to_phone("audit_event", evt.to_dict()))
            return Decision(
                id=f"d_offline_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=verdict,
                by=decided_by,
                note=note,
            )

        # 7. Pause execution and wait for Decision
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[Decision] = loop.create_future()
        self.pending_decisions[request.id] = fut
        self.pending_metadata[request.id] = {
            "request": request,
            "assessment": assessment,
            "start_time": start_time,
            "snapshot_ref": snapshot_ref,
        }

        # Broadcast to connected Phone Guard (sanitizing approval card to prevent leaking raw secrets)
        clean_req = request.to_dict()
        if clean_req.get("command"):
            clean_req["command"] = self.redactor.redact(clean_req["command"])
        if clean_req.get("target_path"):
            clean_req["target_path"] = self.redactor.redact(clean_req["target_path"])
        payload = {
            "request": clean_req,
            "assessment": assessment.to_dict(),
        }
        await self.broadcast_to_phone("action_request", payload)


        # Trigger programmatic local decider if registered
        if self.local_decider is not None:
            async def _invoke_local_decider():
                try:
                    res = self.local_decider(request, assessment)
                    dec = await res if inspect.isawaitable(res) else res
                    if request.id in self.pending_decisions and not fut.done():
                        fut.set_result(dec)
                except Exception as ex:

                    logger.error(f"Error in local decider callback: {ex}")

            asyncio.create_task(_invoke_local_decider())

        # Await decision with timeout
        try:
            decision = await asyncio.wait_for(fut, timeout=self.config.timeout_seconds)
        except asyncio.TimeoutError:
            decision = Decision(
                id=f"d_timeout_{request.id}",
                action_id=request.id,
                session=request.session,
                ts=int(time.time()),
                nonce=self.signer.generate_nonce(),
                verdict=Verdict.DENY,
                by=DecidedBy.TIMEOUT,
                note=f"Timed out after {self.config.timeout_seconds}s waiting for approval.",
            )
        finally:
            self.pending_decisions.pop(request.id, None)
            self.pending_metadata.pop(request.id, None)

        latency = (time.time() - start_time) * 1000
        evt = self.audit_logger.record_action(
            session_id=request.session,
            action_id=request.id,
            kind=request.kind.value,
            command=request.command,
            target_path=request.target_path,
            verdict=decision.verdict.value,
            risk_severity=assessment.severity.value,
            risk_category=assessment.category,
            decided_by=decision.by.value,
            agent=request.agent,
            worktree=request.worktree,
            risk_assessment=assessment.to_dict(),
            latency_ms=latency,
            snapshot_ref=snapshot_ref,
            tainted=taint.tainted,
            metadata={"note": decision.note},
        )
        await self.broadcast_to_phone("audit_event", evt.to_dict())

        # If decision was allow-once, register grant
        if decision.verdict == Verdict.ALLOW and (
            "allow-once" in (decision.note or "").lower() or "allow_once" in (decision.note or "").lower()
        ):
            self._register_allow_once_from_decision(request.id, decision, request=request)

        # Record Package Gate audit event if package action
        if assessment.category == "package-install" or any("R-PKG-" in r for r in assessment.rule_ids):
            from gates.package_gate import PackageActionParser
            parsed = PackageActionParser.parse_action(request)
            pkg_name = parsed.packages[0].name if parsed.packages else (request.command or "package")
            version = parsed.packages[0].version if parsed.packages else None
            self.audit_logger.record_package_gate_event(
                session_id=request.session,
                action_id=request.id,
                package_name=pkg_name,
                version=version,
                verdict=decision.verdict.value,
                risk_severity=assessment.severity.value,
                decided_by=decision.by.value,
                reasons=assessment.rule_ids,
                warnings=[assessment.summary],
                allow_once=("allow-once" in (decision.note or "").lower() or "allow_once" in (decision.note or "").lower()),
                command=request.command,
                agent=request.agent,
                worktree=request.worktree,
                metadata={"note": decision.note},
            )

        return decision

    async def execute_action(self, request: ActionRequest) -> CommandResult:
        """Evaluates action, enforces policy, and executes command if allowed."""
        start_time = time.time()
        assessment = self.evaluator.evaluate(request)
        decision = await self.submit_action(request)

        if decision.verdict == Verdict.DENY:
            reason = decision.note or "Blocked by Leash safety policy."
            stderr_msg = (
                f"\n[LEASH BLOCKED] Execution denied by safety policy: {request.command or request.kind.value}\n"
                f"Reason: {reason}\n"
            )
            duration_ms = (time.time() - start_time) * 1000
            cmd_result = CommandResult(
                action_id=request.id,
                session_id=request.session,
                verdict=Verdict.DENY,
                allowed=False,
                exit_code=126,
                stdout="",
                stderr=stderr_msg,
                blocked_reason=reason,
                risk_assessment=assessment,
                duration_ms=duration_ms,
            )
        elif request.kind == ActionKind.SHELL and request.command:
            try:
                proc = await asyncio.create_subprocess_shell(
                    request.command,
                    cwd=request.cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await proc.communicate()
                exit_code = proc.returncode if proc.returncode is not None else 0
                raw_stdout = stdout_bytes.decode("utf-8", errors="replace")
                raw_stderr = stderr_bytes.decode("utf-8", errors="replace")
                stdout_str = self.redactor.redact(raw_stdout)
                stderr_str = self.redactor.redact(raw_stderr)
            except Exception as e:
                exit_code = 1
                stdout_str = ""
                stderr_str = self.redactor.redact(f"Execution error: {e}")


            duration_ms = (time.time() - start_time) * 1000
            cmd_result = CommandResult(
                action_id=request.id,
                session_id=request.session,
                verdict=Verdict.ALLOW,
                allowed=True,
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                risk_assessment=assessment,
                duration_ms=duration_ms,
            )
        else:
            duration_ms = (time.time() - start_time) * 1000
            cmd_result = CommandResult(
                action_id=request.id,
                session_id=request.session,
                verdict=Verdict.ALLOW,
                allowed=True,
                exit_code=0,
                stdout="",
                stderr="",
                risk_assessment=assessment,
                duration_ms=duration_ms,
            )

        # Record structured execution result in persistent audit log
        self.audit_logger.record_execution_result(
            session_id=request.session,
            action_id=request.id,
            allowed=cmd_result.allowed,
            exit_code=cmd_result.exit_code,
            duration_ms=cmd_result.duration_ms,
            stdout_snippet=cmd_result.stdout[:500] if cmd_result.stdout else None,
            stderr_snippet=cmd_result.stderr[:500] if cmd_result.stderr else None,
            blocked_reason=cmd_result.blocked_reason,
        )

        # Feed command result to session runaway guard
        self.session_mgr.record_action_result(request.session, request, cmd_result.exit_code)

        # Broadcast execution outcome to connected Phone Guard
        await self.broadcast_to_phone("execution_result", {
            "action_id": request.id,
            "session_id": request.session,
            "allowed": cmd_result.allowed,
            "exit_code": cmd_result.exit_code,
            "duration_ms": cmd_result.duration_ms,
            "stdout_snippet": cmd_result.stdout[:500] if cmd_result.stdout else "",
            "stderr_snippet": cmd_result.stderr[:500] if cmd_result.stderr else "",
            "blocked_reason": cmd_result.blocked_reason,
        })

        return cmd_result

    async def _handle_post_provenance(self, request: web.Request) -> web.Response:
        """HTTP endpoint to report an untrusted ingestion event."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        session_id = data.get("session_id") or self.default_session_id or "s_default"
        source = data.get("source", "untrusted-input")
        line = data.get("line")
        flags = data.get("flags", ["untrusted-read"])
        snippet = data.get("snippet")

        event = ProvenanceEvent(
            id=f"p_{uuid.uuid4().hex[:12]}",
            session=session_id,
            ts=int(time.time()),
            kind=ProvenanceKind.UNTRUSTED_READ,
            source=source,
            line=int(line) if line is not None else 1,
            flags=flags,
            snippet=snippet,
        )
        await self.emit_provenance_event(event)
        return web.json_response({"status": "ok", "event": event.to_dict()}, status=201)

    async def _handle_get_session_provenance(self, request: web.Request) -> web.Response:
        """HTTP endpoint returning provenance events and active taint state for a session."""
        session_id = request.match_info["session_id"]
        session = self.session_mgr.get_session(session_id)
        if not session:
            return web.json_response({"error": "Session not found"}, status=404)

        events = [e.to_dict() for e in self.session_mgr.get_provenance_events(session_id)]
        taint = self.session_mgr.get_taint_context(session_id)
        return web.json_response({
            "session_id": session_id,
            "tainted": taint.tainted,
            "taint": taint.to_dict(),
            "events": events,
            "events_count": len(events),
        })

