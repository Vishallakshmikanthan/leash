"""
daemon/server.py - Async WebSocket & HTTP server connecting Laptop interceptor to Android Guard and local tools.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
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
    RiskAssessment,
    Severity,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from session.manager import SessionManager

logger = logging.getLogger("leash.daemon")


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

        # Active phone client connections (WebSocket)
        self.connected_clients: Set[web.WebSocketResponse] = set()
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
        """Checks if a decision channel (Phone Guard, local decider, or dev mode) is available."""
        if len(self.connected_clients) > 0:
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
        self.app.router.add_get("/pending", self._handle_get_pending)
        self.app.router.add_post("/action", self._handle_post_action)
        self.app.router.add_post("/decision", self._handle_post_decision)

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

        self.connected_clients.add(ws)
        client_ip = request.remote or "unknown"
        logger.info(f"Phone Guard connected via WebSocket from {client_ip}")

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    await self._process_incoming_ws_message(msg.data)
                elif msg.type == web.WSMsgType.ERROR:
                    logger.warning(f"WebSocket connection closed with error: {ws.exception()}")
        finally:
            self.connected_clients.discard(ws)
            logger.info(f"Phone Guard disconnected from {client_ip}")

        return ws

    async def _handle_status(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "ok",
            "version": "0.1.0",
            "connected_phones": len(self.connected_clients),
            "pending_decisions": len(self.pending_decisions),
            "default_session": self.default_session_id,
            "decision_channel_available": self.has_decision_channel(),
            "auto_allow_low_risk": self.config.auto_allow_low_risk,
            "fail_closed_high_risk": self.config.fail_closed_high_risk,
            "dev_mode": self.config.dev_mode,
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

        fut = self.pending_decisions[action_id]
        if not fut.done():
            fut.set_result(decision)

        return web.json_response({"status": "ok", "action_id": action_id, "verdict": verdict.value})

    # -------------------------------------------------------------------------
    # WebSocket Message Processing
    # -------------------------------------------------------------------------

    async def _process_incoming_ws_message(self, raw_msg: str) -> None:
        if not raw_msg:
            return
        try:
            data = json.loads(raw_msg)
            msg_type = data.get("type")

            if msg_type == "decision":
                decision_data = data.get("payload", {})
                decision = Decision.from_dict(decision_data)

                # Verify HMAC signature unless dev_mode allows unsigned
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
                    return

                action_id = decision.action_id
                if action_id in self.pending_decisions:
                    fut = self.pending_decisions[action_id]
                    if not fut.done():
                        fut.set_result(decision)

            elif msg_type == "heartbeat":
                await self.broadcast_to_phone("heartbeat_ack", {"ts": int(time.time())})

        except Exception as e:
            logger.error(f"Error handling phone message: {e}")

    async def broadcast_to_phone(self, msg_type: str, payload: dict) -> bool:
        if not self.connected_clients:
            return False

        message_str = json.dumps({"type": msg_type, "payload": payload})
        dead_clients = set()

        for ws in self.connected_clients:
            try:
                await ws.send_str(message_str)
            except Exception:
                dead_clients.add(ws)

        for dw in dead_clients:
            self.connected_clients.discard(dw)

        return len(self.connected_clients) > 0

    # -------------------------------------------------------------------------
    # Interception Core
    # -------------------------------------------------------------------------

    async def submit_action(self, request: ActionRequest) -> Decision:
        """Evaluates ActionRequest, auto-allows or waits for approval, records audit log."""
        start_time = time.time()

        # 1. Update request with session taint context
        taint = self.session_mgr.get_taint_context(request.session)
        request.taint = taint

        # Sign request if unsigned
        if not request.sig:
            request.sig = self.signer.sign(request.payload_for_signature())

        # 2. Local rule triage (Quick Allow for clean low-risk)
        if self.config.auto_allow_low_risk and self.evaluator.is_quick_allow(request):
            latency = (time.time() - start_time) * 1000
            self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict="allow",
                risk_severity="low",
                decided_by="auto",
                latency_ms=latency,
                tainted=taint.tainted,
            )
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

        # 4. Low risk permitted automatically if clean
        if assessment.severity == Severity.LOW and not taint.tainted and self.config.auto_allow_low_risk:
            latency = (time.time() - start_time) * 1000
            self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict="allow",
                risk_severity="low",
                risk_category=assessment.category,
                decided_by="rule",
                latency_ms=latency,
                tainted=False,
            )
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
            self.audit_logger.record_action(
                session_id=request.session,
                action_id=request.id,
                kind=request.kind.value,
                command=request.command,
                target_path=request.target_path,
                verdict=verdict.value,
                risk_severity=assessment.severity.value,
                risk_category=assessment.category,
                decided_by=decided_by.value,
                latency_ms=latency,
                snapshot_ref=snapshot_ref,
                tainted=taint.tainted,
            )
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

        # Broadcast to connected Phone Guard
        payload = {
            "request": request.to_dict(),
            "assessment": assessment.to_dict(),
        }
        await self.broadcast_to_phone("action_request", payload)

        # Trigger programmatic local decider if registered
        if self.local_decider is not None:
            async def _invoke_local_decider():
                try:
                    dec = await self.local_decider(request, assessment)
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
        self.audit_logger.record_action(
            session_id=request.session,
            action_id=request.id,
            kind=request.kind.value,
            command=request.command,
            target_path=request.target_path,
            verdict=decision.verdict.value,
            risk_severity=assessment.severity.value,
            risk_category=assessment.category,
            decided_by=decision.by.value,
            latency_ms=latency,
            snapshot_ref=snapshot_ref,
            tainted=taint.tainted,
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
            return CommandResult(
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

        # Allowed: execute shell command
        if request.kind == ActionKind.SHELL and request.command:
            try:
                proc = await asyncio.create_subprocess_shell(
                    request.command,
                    cwd=request.cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_bytes, stderr_bytes = await proc.communicate()
                exit_code = proc.returncode if proc.returncode is not None else 0
                stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                stderr_str = stderr_bytes.decode("utf-8", errors="replace")
            except Exception as e:
                exit_code = 1
                stdout_str = ""
                stderr_str = f"Execution error: {e}"

            duration_ms = (time.time() - start_time) * 1000
            return CommandResult(
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

        # For non-shell actions (file_read, file_edit, etc.)
        duration_ms = (time.time() - start_time) * 1000
        return CommandResult(
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
