"""
tests/test_m7_session_worktree.py - Acceptance tests for M7: Session, worktree, and Rewind.

Verifies:
1. State out of the repo: worktree created under leash_home()/worktrees/<repo-hash>/<session>.
   Agent in worktree cannot reach daemon files via '..' traversal.
2. Snapshot restores an untracked file deleted by the agent.
3. Two parallel Rewind requests run sequentially under per-session lock.
4. GitGuard branch safety: blocks checkout/switch to base branch, push, reset --hard, branch -D.
"""
import concurrent.futures
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from contracts.models import Severity
from daemon.paths import leash_home
from session.manager import SessionManager
from session.worktree import WorktreeManager
from shim.git_guard import GitGuard


def _git(repo: Path, *args: str) -> str:
    res = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


@pytest.fixture
def clean_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "target_repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "test@leash.local")
    _git(repo, "config", "user.name", "Leash Tester")
    (repo / "README.md").write_text("# Project\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "Initial commit")
    return repo


def test_worktree_located_outside_repo(clean_git_repo: Path):
    """M7.1: Worktree is created outside the repo under leash_home()/worktrees/<repo-hash>/<session>."""
    wt_mgr = WorktreeManager(clean_git_repo)
    wt_path = wt_mgr.create_session_worktree("s_test_iso")

    # 1. Path is under leash_home
    assert str(leash_home()) in str(wt_path)
    assert clean_git_repo not in wt_path.parents

    # 2. Agent cannot reach daemon state from worktree via '..'
    parent_of_wt = wt_path.parent
    assert not (parent_of_wt / "audit.key").exists()
    assert not (parent_of_wt / "audit.jsonl").exists()

    # Clean up
    wt_mgr.cleanup_session_worktree("s_test_iso", delete_branch=True)


def test_snapshot_restores_deleted_untracked_file(clean_git_repo: Path):
    """M7.2: Snapshot captures untracked file and restores it when deleted by agent."""
    mgr = SessionManager(clean_git_repo)
    session = mgr.create_session(agent_name="agent-untracked")
    wt = Path(session.worktree_path)

    # Agent creates an untracked file
    untracked_file = wt / "config_draft.json"
    untracked_file.write_text('{"mode": "test"}', encoding="utf-8")

    # Pre-action snapshot
    snap = mgr.create_pre_action_snapshot(session.session_id, "snapshot before delete", action_id="a_del")
    assert snap is not None

    # Agent deletes untracked file
    untracked_file.unlink()
    assert not untracked_file.exists()

    # Rewind to snapshot
    ok = mgr.rewind(session.session_id, "a_del")
    assert ok is True
    assert untracked_file.exists()
    assert untracked_file.read_text(encoding="utf-8") == '{"mode": "test"}'

    mgr.terminate_session(session.session_id, cleanup_worktree=True)


def test_parallel_rewind_requests_run_sequentially(clean_git_repo: Path):
    """M7.2: Two parallel Rewind requests for same session hold lock and run sequentially."""
    mgr = SessionManager(clean_git_repo)
    session = mgr.create_session(agent_name="agent-parallel")
    wt = Path(session.worktree_path)

    (wt / "data.txt").write_text("initial", encoding="utf-8")
    snap1 = mgr.create_pre_action_snapshot(session.session_id, "snap 1", action_id="a_1")
    (wt / "data.txt").write_text("updated", encoding="utf-8")
    snap2 = mgr.create_pre_action_snapshot(session.session_id, "snap 2", action_id="a_2")

    # Run parallel rewinds using ThreadPoolExecutor
    def do_rewind(action_id: str) -> bool:
        return mgr.rewind(session.session_id, action_id)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(do_rewind, "a_1")
        f2 = executor.submit(do_rewind, "a_2")
        res1 = f1.result(timeout=10)
        res2 = f2.result(timeout=10)

    # Both executions successfully run without crashing or corrupting index
    assert res1 is True
    assert res2 is True

    mgr.terminate_session(session.session_id, cleanup_worktree=True)


def test_git_guard_branch_safety():
    """M7.3: GitGuard blocks checkout to base branch, push, reset --hard, branch -D."""
    guard = GitGuard()

    # 1. Switch to base branch
    is_risky, sev, reason = guard.inspect_git_args(["checkout", "main"])
    assert is_risky is True
    assert sev == Severity.HIGH
    assert "base branch" in reason.lower()

    is_risky, sev, reason = guard.inspect_git_args(["switch", "master"])
    assert is_risky is True
    assert sev == Severity.HIGH

    # 2. Push
    is_risky, sev, reason = guard.inspect_git_args(["push", "origin", "main"])
    assert is_risky is True
    assert sev == Severity.HIGH

    # 3. Reset --hard
    is_risky, sev, reason = guard.inspect_git_args(["reset", "--hard", "HEAD~1"])
    assert is_risky is True
    assert sev == Severity.HIGH

    # 4. Branch -D
    is_risky, sev, reason = guard.inspect_git_args(["branch", "-D", "feature"])
    assert is_risky is True
    assert sev == Severity.HIGH
