"""
daemon/server.py - Async WebSocket / TCP server connecting the Laptop daemon to the Android Guard app.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Callable, Dict, Optional, Set

from contracts.crypto import LeashSigner
from contracts.models import (
    ActionKind,
    ActionRequest,
    Decision,
    DecidedBy,
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
    """Core daemon managing WebSocket transport, security evaluation, and phone approvals."""

    def __init__(
        self,
        config: DaemonConfig,
        session_mgr: SessionManager,
        audit_logger: AuditLogger,
        policy_evaluator: Optional[PolicyEvaluator] = None,
    ):
        self.config = config
        self.session_mgr = session_mgr
        self.audit_logger = audit_logger
        self.evaluator = policy_evaluator or PolicyEvaluator(config.allow_command_patterns)
        self.signer = LeashSigner(config.shared_secret)

        # Active phone client connections
        self.connected_clients: Set[asyncio.StreamWriter] = set()
        self.pending_decisions: Dict[str, asyncio.Future[Decision]] = {}
        self.server: Optional[asyncio.AbstractServer] = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self.server = await asyncio.start_server(
            self._handle_client, self.config.host, self.config.port
        )
        logger.info(f"Leash Daemon listening on {self.config.host}:{self.config.port}")

    async def stop(self) -> None:
        self._running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for writer in list(self.connected_clients):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self.connected_clients.clear()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connected_clients.add(writer)
        logger.info("Phone Guard connected.")
        try:
            while self._running:
                line = await reader.readline()
                if not line:
                    break
                await self._process_incoming_message(line.decode("utf-8").strip())
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            self.connected_clients.discard(writer)
            logger.info("Phone Guard disconnected.")

    async def _process_incoming_message(self, raw_msg: str) -> None:
        if not raw_msg:
            return
        try:
            data = json.loads(raw_msg)
            msg_type = data.get("type")

            if msg_type == "decision":
                decision_data = data.get("payload", {})
                decision = Decision.from_dict(decision_data)

                # Verify signature
                valid = self.signer.verify(
                    decision.payload_for_signature(),
                    decision.sig,
                    decision.ts,
                    decision.nonce,
                )
                if not valid:
                    logger.warning(f"Rejected invalid signature for decision {decision.id}")
                    return

                action_id = decision.action_id
                if action_id in self.pending_decisions:
                    fut = self.pending_decisions[action_id]
                    if not fut.done():
                        fut.set_result(decision)

            elif msg_type == "heartbeat":
                # Heartbeat ack
                pass

        except Exception as e:
            logger.error(f"Error handling phone message: {e}")

    async def broadcast_to_phone(self, msg_type: str, payload: dict) -> bool:
        if not self.connected_clients:
            return False

        message_str = json.dumps({"type": msg_type, "payload": payload}) + "\n"
        message_bytes = message_str.encode("utf-8")

        dead_writers = set()
        for writer in self.connected_clients:
            try:
                writer.write(message_bytes)
                await writer.drain()
            except Exception:
                dead_writers.add(writer)

        for dw in dead_writers:
            self.connected_clients.discard(dw)

        return len(self.connected_clients) > 0

    async def submit_action(self, request: ActionRequest) -> Decision:
        start_time = time.time()

        # 1. Update request with session taint context
        taint = self.session_mgr.get_taint_context(request.session)
        request.taint = taint

        # Sign the request
        if not request.sig:
            request.sig = self.signer.sign(request.payload_for_signature())

        # 2. Local rule triage
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

        # 4. If snapshot needed (High risk / Destructive operations), capture before approval
        snapshot_ref = None
        if assessment.severity == Severity.HIGH:
            snapshot = self.session_mgr.create_pre_action_snapshot(
                request.session, f"Pre-action snapshot for {request.id}: {request.command or request.kind.value}"
            )
            if snapshot:
                snapshot_ref = snapshot.git_ref

        # 5. Check if phone is connected (Fail Closed for dangerous actions)
        if not self.connected_clients:
            verdict = Verdict.DENY if assessment.severity in (Severity.HIGH, Severity.MEDIUM) else Verdict.ALLOW
            decided_by = DecidedBy.RULE if verdict == Verdict.ALLOW else DecidedBy.TIMEOUT
            note = "Phone unreachable: failed closed for risky operation." if verdict == Verdict.DENY else "Phone unreachable: low risk permitted."

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

        # 6. Dispatch to Phone & await Decision
        fut = asyncio.get_running_loop().create_future()
        self.pending_decisions[request.id] = fut

        payload = {
            "request": request.to_dict(),
            "assessment": assessment.to_dict(),
        }
        await self.broadcast_to_phone("action_request", payload)

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
                note=f"Timed out after {self.config.timeout_seconds}s waiting for phone approval.",
            )
        finally:
            self.pending_decisions.pop(request.id, None)

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
