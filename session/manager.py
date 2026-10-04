"""
session/manager.py - Session lifecycle and provenance state coordinator.
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from contracts.models import ActionRequest, ProvenanceEvent, SessionScope, SnapshotRef, TaintContext
from session.runaway_guard import RunawayGuard
from session.scope import ScopeContract
from session.snapshot import SnapshotManager
from session.worktree import WorktreeManager


class SessionManager:
    """Manages active Leash sessions, worktree isolation, provenance tracking, and snapshots."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.worktree_mgr = WorktreeManager(repo_root)
        self.snapshot_mgr = SnapshotManager(repo_root)
        self.active_sessions: Dict[str, SessionScope] = {}
        self.session_guards: Dict[str, RunawayGuard] = {}
        self.session_taints: Dict[str, TaintContext] = {}

    def create_session(
        self,
        allowed_paths: Optional[List[str]] = None,
        allowed_commands: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
    ) -> SessionScope:
        session_id = f"s_{uuid.uuid4().hex[:12]}"
        worktree_path = self.worktree_mgr.create_session_worktree(session_id)

        scope = SessionScope(
            session_id=session_id,
            created_at=int(time.time()),
            worktree_path=str(worktree_path),
            repo_path=str(self.repo_root),
            allowed_paths=allowed_paths or [str(worktree_path), str(self.repo_root)],
            allowed_commands=allowed_commands or [],
            allowed_hosts=allowed_hosts or ["localhost", "127.0.0.1"],
            tainted=False,
            taint_events=[],
            snapshots=[],
        )

        self.active_sessions[session_id] = scope
        self.session_guards[session_id] = RunawayGuard()
        self.session_taints[session_id] = TaintContext(tainted=False)
        return scope

    def get_session(self, session_id: str) -> Optional[SessionScope]:
        return self.active_sessions.get(session_id)

    def record_provenance_event(self, event: ProvenanceEvent) -> None:
        """Taints session state when an untrusted read occurs (F1)."""
        session = self.active_sessions.get(event.session)
        if session:
            session.tainted = True
            session.taint_events.append(event.id)

        self.session_taints[event.session] = TaintContext(
            tainted=True,
            source=event.source,
            line=event.line,
        )

    def get_taint_context(self, session_id: str) -> TaintContext:
        return self.session_taints.get(session_id, TaintContext(tainted=False))

    def create_pre_action_snapshot(self, session_id: str, desc: str) -> Optional[SnapshotRef]:
        snapshot = self.snapshot_mgr.create_snapshot(session_id, desc)
        if snapshot and session_id in self.active_sessions:
            self.active_sessions[session_id].snapshots.append(snapshot.git_ref)
        return snapshot

    def rewind(self, git_ref: str) -> bool:
        return self.snapshot_mgr.rewind_to_snapshot(git_ref)
