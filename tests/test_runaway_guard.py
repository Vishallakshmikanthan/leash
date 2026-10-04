"""
tests/test_runaway_guard.py - Comprehensive test suite for Leash Runaway Guard (N6).
Validates detection of:
1. Repeated failing commands (streaks and identical retries)
2. Repeated file edit loops and oscillation
3. Excessive action frequency (cadence rate bursts)
4. Configured session time limit expiration
5. Agent pausing, Android Guard notification, user decision requirement, and audit logging
6. Normal development activity preservation (quick allow and standard workflows)
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Dict, Any

import pytest

from contracts.crypto import LeashSigner
from contracts.models import (
    ActionKind,
    ActionRequest,
    CommandResult,
    DecidedBy,
    Decision,
    SessionState,
    Severity,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from daemon.receipt_builder import ReceiptBuilder
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from session.runaway_guard import RunawayGuard


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def audit_logger(temp_dir: Path) -> AuditLogger:
    log_file = temp_dir / "audit.jsonl"
    return AuditLogger(log_file)


@pytest.fixture
def session_mgr(temp_dir: Path) -> SessionManager:
    return SessionManager(repo_root=temp_dir)


# -----------------------------------------------------------------------------
# 1. Unit Tests: RunawayGuard Core Detection Logic
# -----------------------------------------------------------------------------

def test_repeated_failing_commands_streak():
    """Detects repeated consecutive command failures exceeding threshold."""
    guard = RunawayGuard(failure_threshold=3)

    assert guard.record_result("make build", 1) is None
    assert guard.is_tripped() is False
    assert guard.get_stats()["failing_command_streak"] == 1

    assert guard.record_result("make build", 2) is None
    assert guard.is_tripped() is False
    assert guard.get_stats()["failing_command_streak"] == 2

    # 3rd failure trips the guard
    trip_reason = guard.record_result("make build", 1)
    assert trip_reason is not None
    assert "consecutively" in trip_reason.lower()
    assert guard.is_tripped() is True
    assert guard.get_trip_type() == "repeated_failures"

    # Subsequent check_action blocks immediately because guard is tripped
    req = ActionRequest(
        id="act_subsequent",
        session="s_test",
        ts=int(time.time()),
        nonce="nonce1",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd=".",
        command="ls",
    )
    warning = guard.check_action(req)
    assert warning is not None
    assert "consecutively" in warning.lower()

    # Reset clears tripped state
    guard.reset()
    assert guard.is_tripped() is False
    assert guard.get_trip_reason() is None
    assert guard.check_action(req) is None


def test_repeated_failing_commands_mixed_streak_and_success_reset():
    """Consecutive failures across different commands trip guard; success resets streak."""
    guard = RunawayGuard(failure_threshold=3)

    # 2 failures followed by 1 success resets the streak
    assert guard.record_result("npm test", 1) is None
    assert guard.record_result("npm test -- -u", 1) is None
    assert guard.record_result("npm test", 0) is None
    assert guard.is_tripped() is False
    assert guard.get_stats()["failing_command_streak"] == 0

    # Next failures start fresh
    assert guard.record_result("cargo build", 101) is None
    assert guard.record_result("cargo check", 101) is None
    trip = guard.record_result("cargo run", 101)
    assert trip is not None
    assert guard.is_tripped() is True


def test_file_edit_loop_detection():
    """Detects repeated edits to the same file exceeding loop threshold."""
    guard = RunawayGuard(file_edit_loop_threshold=4, loop_window_seconds=10)

    req = ActionRequest(
        id="edit_1",
        session="s_test",
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.FILE_EDIT,
        agent="agent",
        cwd=".",
        target_path="src/parser.py",
    )

    for i in range(3):
        req.id = f"edit_{i}"
        assert guard.check_action(req) is None

    # 4th edit to same target trips edit loop
    req.id = "edit_trip"
    warning = guard.check_action(req)
    assert warning is not None
    assert "file edit loop detected" in warning.lower()
    assert "src/parser.py" in warning
    assert guard.is_tripped() is True
    assert guard.get_trip_type() == "edit_loop"


def test_file_edit_oscillation_detection():
    """Detects rapid oscillating edits back and forth between files."""
    guard = RunawayGuard(file_edit_loop_threshold=5, loop_window_seconds=10)

    files = ["src/a.py", "src/b.py"]
    warning = None
    for i in range(5):
        target = files[i % 2]
        req = ActionRequest(
            id=f"osc_{i}",
            session="s_test",
            ts=int(time.time()),
            nonce=f"n_{i}",
            kind=ActionKind.FILE_EDIT,
            agent="agent",
            cwd=".",
            target_path=target,
        )
        w = guard.check_action(req)
        if w:
            warning = w
            break

    assert warning is not None
    assert "oscillation loop detected" in warning.lower()
    assert guard.is_tripped() is True


def test_excessive_action_frequency_cadence_burst():
    """Detects excessive action frequency (rapid burst) within rate limit window."""
    guard = RunawayGuard(rate_limit_count=5, rate_limit_window=2)

    warning = None
    for i in range(5):
        req = ActionRequest(
            id=f"burst_{i}",
            session="s_test",
            ts=int(time.time()),
            nonce=f"n_{i}",
            kind=ActionKind.SHELL,
            agent="agent",
            cwd=".",
            command=f"echo {i}",
        )
        w = guard.check_action(req)
        if w:
            warning = w
            break

    assert warning is not None
    assert "cadence burst detected" in warning.lower()
    assert guard.is_tripped() is True
    assert guard.get_trip_type() == "action_frequency"


def test_session_time_limit_expiration():
    """Detects when a session exceeds its configured time limit."""
    now = time.time()
    # Session configured with 60s limit, started 65s ago
    guard = RunawayGuard(time_limit_seconds=60, created_at=now - 65)

    # 1. Direct timeout check
    timeout_reason = guard.check_timeout(now)
    assert timeout_reason is not None
    assert "exceeded configured time limit" in timeout_reason.lower()
    assert guard.is_tripped() is True
    assert guard.get_trip_type() == "time_limit_exceeded"

    # 2. check_action also trips on timeout
    guard.reset()
    guard.created_at = now - 70
    req = ActionRequest(
        id="act_timeout",
        session="s_test",
        ts=int(now),
        nonce="ntime",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd=".",
        command="pytest",
    )
    action_warning = guard.check_action(req)
    assert action_warning is not None
    assert "exceeded configured time limit" in action_warning.lower()


def test_normal_development_activity_unaffected():
    """Normal development commands and edits under thresholds do NOT trip the runaway guard."""
    guard = RunawayGuard(
        failure_threshold=3,
        loop_window_seconds=15,
        loop_count_threshold=5,
        rate_limit_count=15,
        file_edit_loop_threshold=5,
        time_limit_seconds=3600,
    )

    # Normal edits across different files
    for filename in ["models.py", "views.py", "urls.py"]:
        req = ActionRequest(
            id=f"edit_{filename}",
            session="s_dev",
            ts=int(time.time()),
            nonce="n",
            kind=ActionKind.FILE_EDIT,
            agent="agent",
            cwd=".",
            target_path=filename,
        )
        assert guard.check_action(req) is None

    # Normal successful commands
    for cmd in ["pytest", "git status", "git diff"]:
        req = ActionRequest(
            id=f"cmd_{cmd}",
            session="s_dev",
            ts=int(time.time()),
            nonce="n",
            kind=ActionKind.SHELL,
            agent="agent",
            cwd=".",
            command=cmd,
        )
        assert guard.check_action(req) is None
        assert guard.record_result(cmd, 0) is None

    assert guard.is_tripped() is False


# -----------------------------------------------------------------------------
# 2. SessionManager Integration
# -----------------------------------------------------------------------------

def test_session_manager_runaway_binding_and_pausing(session_mgr: SessionManager):
    """SessionManager binds runaway guard, flags runaway-behavior-detected, and pauses session."""
    session = session_mgr.create_session(time_limit_seconds=10)
    session_id = session.session_id

    assert session.state == SessionState.ACTIVE
    guard = session_mgr.session_guards[session_id]
    guard.failure_threshold = 2

    # Simulate command failure streak
    req1 = ActionRequest(
        id="act_fail1",
        session=session_id,
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd=".",
        command="python broken.py",
    )
    assert session_mgr.record_action_result(session_id, req1, 1) is None
    assert session_mgr.get_session(session_id).state == SessionState.ACTIVE

    # 2nd failure trips runaway guard and automatically pauses session
    trip_reason = session_mgr.record_action_result(session_id, req1, 1)
    assert trip_reason is not None
    assert session_mgr.get_session(session_id).state == SessionState.PAUSED

    # Next action bound to this session receives runaway-behavior-detected flag
    req2 = ActionRequest(
        id="act_subsequent",
        session=session_id,
        ts=int(time.time()),
        nonce="n2",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd=".",
        command="python broken.py",
    )
    bound_req = session_mgr.bind_action(req2)
    assert "runaway-behavior-detected" in bound_req.scope_flags

    # Resuming session clears runaway trip state
    assert session_mgr.resume_session(session_id, reset_runaway=True) is True
    assert session_mgr.get_session(session_id).state == SessionState.ACTIVE
    assert guard.is_tripped() is False


# -----------------------------------------------------------------------------
# 3. Policy Evaluator & Risk Rules
# -----------------------------------------------------------------------------

def test_policy_evaluator_evaluates_runaway_flag():
    """PolicyEvaluator assigns R-RUNAWAY-DETECTED and HIGH severity to runaway requests."""
    evaluator = PolicyEvaluator()

    req = ActionRequest(
        id="act_runaway",
        session="s_01",
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd=".",
        command="python script.py",
        scope_flags=["runaway-behavior-detected"],
    )

    # Cannot be quick-allowed
    assert evaluator.is_quick_allow(req) is False

    assessment = evaluator.evaluate(req)
    assert assessment.category == "runaway-behavior-detected"
    assert assessment.severity == Severity.HIGH
    assert "R-RUNAWAY-DETECTED" in assessment.rule_ids
    assert "runaway behavior detected" in assessment.summary.lower()


# -----------------------------------------------------------------------------
# 4. End-to-End Daemon Integration Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_daemon_runaway_guard_flow_and_approval(temp_dir: Path, audit_logger: AuditLogger):
    """When runaway is detected: pauses agent, alerts phone, requires user decision, logs audit."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=0,
        shared_secret="test-secret",
        dev_mode=True,
    )
    session_mgr = SessionManager(repo_root=temp_dir)
    session = session_mgr.create_session()
    session_id = session.session_id

    # Create server
    server = LeashDaemonServer(
        config=config,
        session_mgr=session_mgr,
        audit_logger=audit_logger,
    )
    await server.start()

    try:
        # Trip runaway guard on command result
        guard = session_mgr.session_guards[session_id]
        guard.failure_threshold = 2
        fail_req = ActionRequest(
            id="cmd_f1",
            session=session_id,
            ts=int(time.time()),
            nonce="n1",
            kind=ActionKind.SHELL,
            agent="test-agent",
            cwd=".",
            command="make test",
        )

        session_mgr.record_action_result(session_id, fail_req, 1)
        # 2nd failure trips
        trip_reason = session_mgr.record_action_result(session_id, fail_req, 1)
        assert trip_reason is not None
        assert session_mgr.get_session(session_id).state == SessionState.PAUSED

        # Next action submitted by agent
        next_req = ActionRequest(
            id="cmd_f3",
            session=session_id,
            ts=int(time.time()),
            nonce="n3",
            kind=ActionKind.SHELL,
            agent="test-agent",
            cwd=".",
            command="make test",
        )

        # Register human decider that approves the action
        approved_future = asyncio.get_running_loop().create_future()

        async def _human_decider(req, assessment):
            assert assessment.category == "runaway-behavior-detected"
            assert assessment.severity == Severity.HIGH
            return Decision(
                id="d_human_approve",
                action_id=req.id,
                session=req.session,
                ts=int(time.time()),
                nonce="nonce_dec",
                verdict=Verdict.ALLOW,
                by=DecidedBy.TAP,
                note="Human approved resuming runaway agent",
            )

        server.register_local_decider(_human_decider)

        decision = await server.submit_action(next_req)
        assert decision.verdict == Verdict.ALLOW

        # Session unpaused and runaway guard reset upon approval
        assert session_mgr.get_session(session_id).state == SessionState.ACTIVE
        assert guard.is_tripped() is False

        # Verify audit history records runaway alert
        events = audit_logger.read_session_events(session_id)
        runaway_events = [e for e in events if e.get("event_type") == "runaway_security_alert" or e.get("kind") == "runaway_alert"]
        assert len(runaway_events) >= 1
        assert runaway_events[0]["risk_category"] == "runaway-behavior-detected"

        # Verify PR Receipt Builder parses runaway events
        risk_extracted = ReceiptBuilder.extract_risk_events(events)
        runaway_receipt_items = [r for r in risk_extracted if r["type"] == "RUNAWAY_ALERT"]
        assert len(runaway_receipt_items) >= 1
        assert "Runaway Behavior Detected" in runaway_receipt_items[0]["title"]

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_daemon_runaway_decision_endpoint(temp_dir: Path, audit_logger: AuditLogger):
    """POST /sessions/{session_id}/runaway/decision directly unpauses or terminates session."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=0,
        shared_secret="test-secret",
        dev_mode=True,
    )
    session_mgr = SessionManager(repo_root=temp_dir)
    session = session_mgr.create_session()
    session_id = session.session_id

    server = LeashDaemonServer(config=config, session_mgr=session_mgr, audit_logger=audit_logger)
    await server.start()

    try:
        guard = session_mgr.session_guards[session_id]
        guard.trip("Manually tripped for testing", trip_type="manual")
        session_mgr.pause_session(session_id)
        assert session_mgr.get_session(session_id).state == SessionState.PAUSED

        # Client makes POST request to resume runaway session
        from aiohttp import ClientSession
        port = server.site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/sessions/{session_id}/runaway/decision"

        async with ClientSession() as client:
            # 1. Resume decision
            async with client.post(url, json={"verdict": "resume", "note": "All good"}) as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["state"] == "active"
                assert data["resumed"] is True

            assert session_mgr.get_session(session_id).state == SessionState.ACTIVE
            assert guard.is_tripped() is False

            # 2. Terminate decision
            async with client.post(url, json={"verdict": "terminate", "note": "Stop runaway agent"}) as resp:
                assert resp.status == 200
                data = await resp.json()
                assert data["state"] == "terminated"

            assert session_mgr.get_session(session_id).state == SessionState.TERMINATED

    finally:
        await server.stop()
