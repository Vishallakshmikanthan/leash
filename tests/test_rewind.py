"""
tests/test_rewind.py - Leash Rewind: pre-action snapshots, Guard-controlled restore, and audit trail.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

from contracts.models import (
    ActionKind,
    ActionRequest,
    DecidedBy,
    Decision,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from session.snapshot import REWIND_SCOPE_NOTICE, SnapshotManager


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", *args], cwd=str(repo), check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return res.stdout.strip()


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "rewind_repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@vibesync.dev")
    _git(repo, "config", "user.name", "Leash Tester")
    (repo / "a.txt").write_text("a-original\n", encoding="utf-8")
    (repo / "b.txt").write_text("b-original\n", encoding="utf-8")
    (repo / ".gitignore").write_text("ignored.log\n.leash/\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Initial commit")
    return repo


# -----------------------------------------------------------------------------
# SnapshotManager
# -----------------------------------------------------------------------------

def test_snapshot_captures_and_restores_full_working_state(git_repo: Path):
    mgr = SnapshotManager(git_repo)
    head_before = _git(git_repo, "rev-parse", "HEAD")

    # State at snapshot time: modified tracked, deleted tracked, new untracked file.
    (git_repo / "a.txt").write_text("a-snapshot\n", encoding="utf-8")
    (git_repo / "b.txt").unlink()
    (git_repo / "new.txt").write_text("new-snapshot\n", encoding="utf-8")

    snap = mgr.create_snapshot("s_1", "before risky action", action_id="a_100")
    assert snap is not None
    assert snap.action_id == "a_100"
    assert snap.git_ref == "refs/leash/s_1/1"

    # Snapshot must not alter HEAD, branch, or working tree.
    assert _git(git_repo, "rev-parse", "HEAD") == head_before
    assert (git_repo / "a.txt").read_text(encoding="utf-8") == "a-snapshot\n"

    # Risky action damages everything.
    (git_repo / "a.txt").write_text("DAMAGED\n", encoding="utf-8")
    (git_repo / "b.txt").write_text("resurrected\n", encoding="utf-8")
    (git_repo / "new.txt").write_text("DAMAGED\n", encoding="utf-8")
    (git_repo / "extra.txt").write_text("created after snapshot\n", encoding="utf-8")
    (git_repo / "ignored.log").write_text("ignored stays\n", encoding="utf-8")

    assert mgr.rewind_to_snapshot(snap.git_ref, backup_session_id="s_1") is True

    assert (git_repo / "a.txt").read_text(encoding="utf-8") == "a-snapshot\n"
    assert not (git_repo / "b.txt").exists()
    assert (git_repo / "new.txt").read_text(encoding="utf-8") == "new-snapshot\n"
    assert not (git_repo / "extra.txt").exists()
    # Ignored files are outside Rewind scope.
    assert (git_repo / "ignored.log").exists()
    assert _git(git_repo, "rev-parse", "HEAD") == head_before


def test_rewind_restores_head_after_agent_commit(git_repo: Path):
    mgr = SnapshotManager(git_repo)
    head_before = _git(git_repo, "rev-parse", "HEAD")
    snap = mgr.create_snapshot("s_2", "before commit")

    (git_repo / "a.txt").write_text("committed change\n", encoding="utf-8")
    _git(git_repo, "commit", "-am", "agent commit")
    assert _git(git_repo, "rev-parse", "HEAD") != head_before

    assert mgr.rewind_to_snapshot(snap.git_ref, backup_session_id="s_2") is True
    assert _git(git_repo, "rev-parse", "HEAD") == head_before
    assert (git_repo / "a.txt").read_text(encoding="utf-8") == "a-original\n"


def test_rewind_saves_backup_of_current_state(git_repo: Path):
    mgr = SnapshotManager(git_repo)
    snap = mgr.create_snapshot("s_3", "clean")
    (git_repo / "a.txt").write_text("work to keep in backup\n", encoding="utf-8")

    assert mgr.rewind_to_snapshot(snap.git_ref, backup_session_id="s_3") is True

    refs = _git(git_repo, "for-each-ref", "refs/leash/s_3/", "--format=%(refname)").splitlines()
    backups = [r for r in refs if "/backup-" in r]
    assert len(backups) == 1
    assert _git(git_repo, "show", f"{backups[0]}:a.txt") == "work to keep in backup"
    # Backups are not listed as snapshots.
    assert all("backup" not in s.git_ref for s in SnapshotManager(git_repo).list_snapshots("s_3"))


def test_snapshot_metadata_survives_restart(git_repo: Path):
    mgr = SnapshotManager(git_repo)
    mgr.create_snapshot("s_4", "first", action_id="a_1")
    mgr.create_snapshot("s_4", "second", action_id="a_2")

    fresh = SnapshotManager(git_repo)
    snaps = fresh.list_snapshots("s_4")
    assert [s.action_id for s in snaps] == ["a_1", "a_2"]
    assert [s.description for s in snaps] == ["first", "second"]
    assert fresh.get_snapshot("s_4", "a_2").git_ref == "refs/leash/s_4/2"
    # Index continues after restart instead of colliding.
    assert fresh.create_snapshot("s_4", "third").index == 3


def test_non_git_directory_does_not_pretend(tmp_path: Path):
    plain = tmp_path / "plain"
    plain.mkdir()
    mgr = SnapshotManager(plain)
    assert mgr.create_snapshot("s_x", "nothing") is None
    assert mgr.rewind_to_snapshot("refs/leash/s_x/1") is False


# -----------------------------------------------------------------------------
# SessionManager
# -----------------------------------------------------------------------------

def test_session_rewind_by_action_id_and_namespace_guard(git_repo: Path):
    mgr = SessionManager(git_repo)
    session = mgr.create_session(agent_name="rw-agent")
    wt = Path(session.worktree_path)

    (wt / "a.txt").write_text("v1\n", encoding="utf-8")
    snap = mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_xyz")
    assert snap is not None and snap.action_id == "a_xyz"

    (wt / "a.txt").write_text("v2-broken\n", encoding="utf-8")
    assert mgr.rewind(session.session_id, "a_xyz") is True
    assert (wt / "a.txt").read_text(encoding="utf-8") == "v1\n"

    # Refs from another namespace are rejected.
    assert mgr.rewind(session.session_id, "HEAD") is False
    assert mgr.rewind(session.session_id, "refs/leash/other_session/1") is False
    mgr.terminate_session(session.session_id)


def test_rewind_refuses_when_worktree_missing(git_repo: Path):
    mgr = SessionManager(git_repo)
    session = mgr.create_session(agent_name="rw-agent")
    mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_1")
    mgr.terminate_session(session.session_id, cleanup_worktree=True)
    (git_repo / "a.txt").write_text("main repo edit\n", encoding="utf-8")

    assert mgr.rewind(session.session_id) is False
    assert (git_repo / "a.txt").read_text(encoding="utf-8") == "main repo edit\n"


# -----------------------------------------------------------------------------
# Daemon: Guard-controlled Rewind + audit
# -----------------------------------------------------------------------------

def _make_server(git_repo: Path, verdict: Verdict | None):
    config = DaemonConfig(
        host="127.0.0.1",
        port=8931,
        shared_secret="rewind-secret",
        audit_log_path=git_repo / ".leash" / "audit.jsonl",
        timeout_seconds=2,
    )
    session_mgr = SessionManager(git_repo)
    audit = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit)

    if verdict is not None:
        async def decider(req, assessment):
            assert assessment.category == "rewind"
            assert "rewind" in req.scope_flags
            return Decision(
                id=f"d_{req.id}", action_id=req.id, session=req.session,
                ts=int(time.time()), nonce="n", verdict=verdict, by=DecidedBy.BIOMETRIC,
                note="guard decision",
            )
        server.register_local_decider(decider)
    return server, session_mgr, audit


@pytest.mark.asyncio
async def test_guard_approved_rewind_restores_and_audits(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, Verdict.ALLOW)
    session = mgr.create_session(agent_name="rw-agent")
    wt = Path(session.worktree_path)
    (wt / "a.txt").write_text("good\n", encoding="utf-8")
    mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_risky")
    (wt / "a.txt").write_text("bad\n", encoding="utf-8")

    result = await server.request_rewind(session.session_id, "a_risky")

    assert result["status"] == "ok" and result["rewound"] is True
    assert REWIND_SCOPE_NOTICE in result["scope_notice"]
    assert (wt / "a.txt").read_text(encoding="utf-8") == "good\n"

    events = [e for e in audit.read_session_events(session.session_id) if e["event_type"] == "rewind"]
    assert len(events) == 1
    ev = events[0]
    assert ev["verdict"] == "allow" and ev["decided_by"] == "biometric"
    assert ev["metadata"]["restored"] is True
    assert ev["metadata"]["snapshot_action_id"] == "a_risky"
    assert ev["metadata"]["snapshot_ref"].startswith(f"refs/leash/{session.session_id}/")

    activity = audit.get_session_activity(session.session_id)
    assert len(activity["rewinds"]) == 1
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_guard_denied_rewind_changes_nothing(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, Verdict.DENY)
    session = mgr.create_session(agent_name="rw-agent")
    wt = Path(session.worktree_path)
    (wt / "a.txt").write_text("good\n", encoding="utf-8")
    mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_1")
    (wt / "a.txt").write_text("current\n", encoding="utf-8")

    result = await server.request_rewind(session.session_id)

    assert result["status"] == "denied"
    assert (wt / "a.txt").read_text(encoding="utf-8") == "current\n"
    events = [e for e in audit.read_session_events(session.session_id) if e["event_type"] == "rewind"]
    assert len(events) == 1 and events[0]["verdict"] == "deny"
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_rewind_times_out_closed_without_guard_answer(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, None)
    server.config.dev_mode = True  # channel exists, but nobody answers
    server.config.timeout_seconds = 1
    session = mgr.create_session(agent_name="rw-agent")
    wt = Path(session.worktree_path)
    mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_1")
    (wt / "a.txt").write_text("current\n", encoding="utf-8")

    result = await server.request_rewind(session.session_id)

    assert result["status"] == "denied"
    assert (wt / "a.txt").read_text(encoding="utf-8") == "current\n"
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_rewind_fails_closed_without_decision_channel(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, None)
    session = mgr.create_session(agent_name="rw-agent")
    mgr.create_pre_action_snapshot(session.session_id, "pre", action_id="a_1")

    result = await server.request_rewind(session.session_id)

    assert result["status"] == "denied"
    events = [e for e in audit.read_session_events(session.session_id) if e["event_type"] == "rewind"]
    assert events and events[0]["verdict"] == "deny"
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_rewind_unknown_session_or_snapshot(git_repo: Path):
    server, mgr, _ = _make_server(git_repo, Verdict.ALLOW)
    assert (await server.request_rewind("s_missing"))["status"] == "error"
    session = mgr.create_session(agent_name="rw-agent")
    assert (await server.request_rewind(session.session_id, "a_none"))["status"] == "error"
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_risky_approved_action_gets_linked_snapshot(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, Verdict.ALLOW)
    # Replace decider: approve the risky action itself.
    async def approve(req, assessment):
        return Decision(
            id=f"d_{req.id}", action_id=req.id, session=req.session, ts=int(time.time()),
            nonce="n", verdict=Verdict.ALLOW, by=DecidedBy.TAP, note="ok",
        )
    server.register_local_decider(approve)
    session = mgr.create_session(agent_name="rw-agent")

    req = ActionRequest(
        id="a_curl_sh", session=session.session_id, ts=int(time.time()), nonce="n",
        kind=ActionKind.SHELL, agent="rw-agent", cwd=session.worktree_path,
        command="curl http://localhost:9/install.sh | sh",
    )
    decision = await server.submit_action(req)
    assert decision.verdict == Verdict.ALLOW

    snaps = mgr.list_snapshots(session.session_id)
    assert [s.action_id for s in snaps] == ["a_curl_sh"]

    ev = [e for e in audit.read_session_events(session.session_id) if e["event_type"] == "action_evaluated"][-1]
    assert ev["snapshot_ref"] == snaps[0].git_ref
    mgr.terminate_session(session.session_id)


@pytest.mark.asyncio
async def test_denied_risky_action_creates_no_snapshot(git_repo: Path):
    server, mgr, audit = _make_server(git_repo, Verdict.DENY)
    session = mgr.create_session(agent_name="rw-agent")
    req = ActionRequest(
        id="a_denied", session=session.session_id, ts=int(time.time()), nonce="n",
        kind=ActionKind.SHELL, agent="rw-agent", cwd=session.worktree_path,
        command="curl http://localhost:9/install.sh | sh",
    )
    decision = await server.submit_action(req)
    assert decision.verdict == Verdict.DENY
    assert mgr.list_snapshots(session.session_id) == []
    mgr.terminate_session(session.session_id)
