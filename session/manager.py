"""
session/manager.py - Session lifecycle, worktree isolation, task scope contracts, provenance, and runaway protection coordinator.
"""
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from contracts.models import (
    ActionRequest,
    ProvenanceEvent,
    SessionScope,
    SessionState,
    SnapshotRef,
    TaintContext,
)
from gates.provenance_tracker import ProvenanceTracker
from session.runaway_guard import RunawayGuard
from session.scope import ScopeContract
from session.snapshot import SnapshotManager
from session.worktree import WorktreeManager

logger = logging.getLogger("leash.session.manager")


class SessionManager:
    """Manages active Leash sessions, worktree isolation, provenance tracking, snapshots, and runaway protection."""

    def __init__(self, repo_root: Path, provenance_tracker: Optional[ProvenanceTracker] = None):
        self.repo_root = Path(repo_root).resolve()
        self.worktree_mgr = WorktreeManager(self.repo_root)
        self.snapshot_mgr = SnapshotManager(self.repo_root)
        self.provenance_tracker = provenance_tracker or ProvenanceTracker()

        self.sessions: Dict[str, SessionScope] = {}
        self.session_guards: Dict[str, RunawayGuard] = {}
        self.session_taints: Dict[str, TaintContext] = {}
        self.session_scopes: Dict[str, ScopeContract] = {}
        self.session_action_history: Dict[str, List[str]] = {}
        self.session_provenance_history: Dict[str, List[ProvenanceEvent]] = {}
        self.session_changed_files: Dict[str, List[Dict[str, Any]]] = {}
        self.session_receipts: Dict[str, str] = {}
        self.active_session_id: Optional[str] = None


    @property
    def active_sessions(self) -> Dict[str, SessionScope]:
        """Backwards compatibility accessor for active sessions dictionary."""
        return {
            sid: s for sid, s in self.sessions.items() if s.state in (SessionState.ACTIVE, SessionState.INITIALIZING)
        }

    def create_session(
        self,
        allowed_paths: Optional[List[str]] = None,
        allowed_commands: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
        agent_name: str = "coding-agent",
        task_description: Optional[str] = None,
        session_id: Optional[str] = None,
        base_ref: str = "HEAD",
    ) -> SessionScope:
        """Initializes a new session with an isolated Git worktree and declared task scope."""
        sess_id = session_id or f"s_{uuid.uuid4().hex[:12]}"
        worktree_path = self.worktree_mgr.create_session_worktree(sess_id, base_ref=base_ref)
        branch_name = self.worktree_mgr.get_branch_name(sess_id)

        # Allow worktree directory and main repo root by default
        effective_allowed_paths = allowed_paths or [str(worktree_path), str(self.repo_root)]
        if str(worktree_path) not in effective_allowed_paths:
            effective_allowed_paths.append(str(worktree_path))

        effective_allowed_commands = allowed_commands or []
        effective_allowed_hosts = allowed_hosts or ["localhost", "127.0.0.1"]

        scope_contract = ScopeContract(
            allowed_paths=effective_allowed_paths,
            allowed_commands=effective_allowed_commands,
            allowed_hosts=effective_allowed_hosts,
        )

        scope = SessionScope(
            session_id=sess_id,
            created_at=int(time.time()),
            worktree_path=str(worktree_path),
            repo_path=str(self.repo_root),
            allowed_paths=effective_allowed_paths,
            allowed_commands=effective_allowed_commands,
            allowed_hosts=effective_allowed_hosts,
            agent=agent_name,
            state=SessionState.ACTIVE,
            task_description=task_description,
            branch_name=branch_name,
            tainted=False,
            taint_events=[],
            snapshots=[],
        )

        self.sessions[sess_id] = scope
        self.session_guards[sess_id] = RunawayGuard()
        self.session_taints[sess_id] = TaintContext(tainted=False)
        self.session_scopes[sess_id] = scope_contract
        self.session_action_history[sess_id] = []
        self.active_session_id = sess_id

        logger.info(f"Created session {sess_id} for agent '{agent_name}' in worktree '{worktree_path}'")
        return scope

    def get_session(self, session_id: str) -> Optional[SessionScope]:
        """Retrieves session metadata by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self, active_only: bool = False) -> List[SessionScope]:
        """Lists all registered sessions, optionally filtering for active only."""
        if active_only:
            return [s for s in self.sessions.values() if s.state == SessionState.ACTIVE]
        return list(self.sessions.values())

    def plant_canary_in_session(self, session_id: str) -> Optional[Path]:
        """Plants a harmless fake canary credential file into the session worktree."""
        from gates.secret_fence import CanaryManager
        session = self.sessions.get(session_id)
        if not session or not session.worktree_path:
            return None
        mgr = CanaryManager()
        return mgr.plant_canary_env(Path(session.worktree_path))


    def bind_action(self, request: ActionRequest) -> ActionRequest:
        """Associates an ActionRequest with its session, agent, and worktree; checks scope and runaway."""
        # 1. Resolve session
        session_id = request.session
        if not session_id:
            if self.active_session_id and self.active_session_id in self.sessions:
                session_id = self.active_session_id
                request.session = session_id
            else:
                default_scope = self.create_session(agent_name=request.agent or "coding-agent")
                session_id = default_scope.session_id
                request.session = session_id
        elif session_id not in self.sessions:
            # Explicit session ID given that hasn't been created yet
            new_scope = self.create_session(
                session_id=session_id,
                agent_name=request.agent or "coding-agent",
            )
            session_id = new_scope.session_id

        session = self.sessions[session_id]

        # 2. Check session lifecycle state
        if session.state == SessionState.PAUSED:
            if "session-paused" not in request.scope_flags:
                request.scope_flags.append("session-paused")
        elif session.state in (SessionState.TERMINATED, SessionState.FAILED):
            if "session-terminated" not in request.scope_flags:
                request.scope_flags.append("session-terminated")

        # 3. Associate agent and worktree
        if request.agent and request.agent != "unknown":
            if session.agent in ("unknown", "coding-agent"):
                session.agent = request.agent
        else:
            request.agent = session.agent

        if not request.worktree:
            request.worktree = session.worktree_path

        # If CWD is default or empty, set to session worktree
        if not request.cwd or request.cwd == ".":
            request.cwd = session.worktree_path

        # 4. Attach session taint context
        taint = self.get_taint_context(session_id)
        if not taint.tainted and request.taint and request.taint.tainted:
            # Request arrived with explicit taint: taint session
            p_event = self.provenance_tracker.create_provenance_event(
                session_id=session_id,
                source=request.taint.source or "untrusted-input",
                line=request.taint.line or 1,
                flags=["explicit-taint"],
                snippet=f"Action explicitly flagged with taint from {request.taint.source}",
            )
            self.record_provenance_event(p_event)
            taint = self.get_taint_context(session_id)
        elif not taint.tainted:
            detected = self.provenance_tracker.detect_untrusted_read(
                request,
                base_dir=session.worktree_path or str(self.repo_root),
                candidate_dirs=[session.worktree_path, session.repo_path, str(self.repo_root), request.cwd],
            )

            if detected:
                src, line, flags, snip = detected
                p_event = self.provenance_tracker.create_provenance_event(
                    session_id=session_id,
                    source=src,
                    line=line,
                    flags=flags,
                    snippet=snip,
                )
                self.record_provenance_event(p_event)
                taint = self.get_taint_context(session_id)

        request.taint = taint


        # 5. Detect scope drift against declared contract (allowed paths, commands, hosts)
        scope_contract = self.session_scopes.get(session_id)
        if scope_contract:
            drift_flags = scope_contract.validate_action(request)
            for flag in drift_flags:
                if flag not in request.scope_flags:
                    request.scope_flags.append(flag)

        # 6. Check runaway guard
        guard = self.session_guards.get(session_id)
        if guard:
            warning = guard.check_action(request)
            if warning and "runaway-behavior-detected" not in request.scope_flags:
                request.scope_flags.append("runaway-behavior-detected")

        # 7. Record action in session history
        self.session_action_history.setdefault(session_id, []).append(request.id)

        return request

    def pause_session(self, session_id: str) -> bool:
        """Transitions an active session to PAUSED state."""
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.ACTIVE:
            return False
        session.state = SessionState.PAUSED
        logger.info(f"Session {session_id} paused")
        return True

    def resume_session(self, session_id: str) -> bool:
        """Transitions a paused session back to ACTIVE state."""
        session = self.sessions.get(session_id)
        if not session or session.state != SessionState.PAUSED:
            return False
        session.state = SessionState.ACTIVE
        logger.info(f"Session {session_id} resumed")
        return True

    def terminate_session(
        self,
        session_id: str,
        reason: str = "completed",
        cleanup_worktree: bool = True,
        save_branch: bool = True,
    ) -> Optional[SessionScope]:
        """Cleanly terminates an agent session, saves changes, and cleans up the worktree."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        session.state = SessionState.TERMINATING

        # Capture changed files prior to cleaning up worktree
        changed_files = self.worktree_mgr.get_changed_files(session_id)
        session.changed_files = changed_files
        self.session_changed_files[session_id] = changed_files

        # Save any uncommitted work in the worktree
        if save_branch:
            commit_sha = self.worktree_mgr.save_worktree_changes(
                session_id, message=f"Snapshot before terminating session {session_id}: {reason}"
            )
            if commit_sha:
                logger.info(f"Saved worktree changes for {session_id} (commit {commit_sha[:8]})")
                refreshed_changes = self.worktree_mgr.get_changed_files(session_id)
                if refreshed_changes:
                    session.changed_files = refreshed_changes
                    self.session_changed_files[session_id] = refreshed_changes

        # Clean up git worktree isolation directory
        if cleanup_worktree:
            self.worktree_mgr.cleanup_session_worktree(session_id, delete_branch=not save_branch)

        session.state = SessionState.TERMINATED
        session.terminated_at = int(time.time())
        session.termination_reason = reason

        # Reset active session ID if this was the active one
        if self.active_session_id == session_id:
            active_candidates = [
                s.session_id for s in self.sessions.values() if s.state == SessionState.ACTIVE
            ]
            self.active_session_id = active_candidates[0] if active_candidates else None

        logger.info(f"Session {session_id} cleanly terminated ({reason})")
        return session

    def get_changed_files(self, session_id: str) -> List[Dict[str, Any]]:
        """Returns detected changed files for a session."""
        if session_id in self.session_changed_files:
            return list(self.session_changed_files[session_id])
        session = self.sessions.get(session_id)
        if session and session.changed_files:
            return list(session.changed_files)
        return self.worktree_mgr.get_changed_files(session_id)

    def set_session_receipt(self, session_id: str, markdown: str) -> None:
        """Saves generated receipt markdown onto session record."""
        self.session_receipts[session_id] = markdown
        session = self.sessions.get(session_id)
        if session:
            session.receipt_markdown = markdown

    def get_session_receipt(self, session_id: str) -> Optional[str]:
        """Returns cached markdown receipt if available."""
        if session_id in self.session_receipts:
            return self.session_receipts[session_id]
        session = self.sessions.get(session_id)
        return session.receipt_markdown if session else None


    def update_session_scope(
        self,
        session_id: str,
        allowed_paths: Optional[List[str]] = None,
        allowed_commands: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
    ) -> Optional[SessionScope]:
        """Updates the task scope contract for an existing session."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        if allowed_paths is not None:
            session.allowed_paths = allowed_paths
        if allowed_commands is not None:
            session.allowed_commands = allowed_commands
        if allowed_hosts is not None:
            session.allowed_hosts = allowed_hosts

        self.session_scopes[session_id] = ScopeContract(
            allowed_paths=session.allowed_paths,
            allowed_commands=session.allowed_commands,
            allowed_hosts=session.allowed_hosts,
        )
        return session

    def record_provenance_event(self, event: ProvenanceEvent) -> None:
        """Taints session state when an untrusted read occurs (F1)."""
        session = self.sessions.get(event.session)
        if session:
            session.tainted = True
            if event.id not in session.taint_events:
                session.taint_events.append(event.id)

        self.session_taints[event.session] = TaintContext(
            tainted=True,
            source=event.source,
            line=event.line,
        )
        self.session_provenance_history.setdefault(event.session, []).append(event)

    def get_taint_context(self, session_id: str) -> TaintContext:
        """Retrieves active taint context for the given session."""
        return self.session_taints.get(session_id, TaintContext(tainted=False))

    def get_provenance_events(self, session_id: str) -> List[ProvenanceEvent]:
        """Retrieves list of provenance events recorded for this session."""
        return list(self.session_provenance_history.get(session_id, []))

    def is_session_tainted(self, session_id: str) -> bool:
        """Returns True if the session has ingested untrusted content."""
        return self.get_taint_context(session_id).tainted

    def add_untrusted_source(self, source_or_pattern: str) -> None:
        """Registers an additional untrusted source pattern or path."""
        self.provenance_tracker.add_untrusted_source(source_or_pattern)

    def configure_untrusted_sources(self, sources: List[str]) -> None:
        """Configures custom untrusted sources."""
        self.provenance_tracker.configure_untrusted_sources(sources)


    def create_pre_action_snapshot(
        self, session_id: str, desc: str, action_id: Optional[str] = None
    ) -> Optional[SnapshotRef]:
        """Creates a point-in-time hidden Git ref snapshot before a risky operation."""
        session = self.sessions.get(session_id)
        worktree_path = Path(session.worktree_path) if session else None
        snapshot = self.snapshot_mgr.create_snapshot(
            session_id, desc, worktree_path=worktree_path, action_id=action_id
        )
        if snapshot and session:
            session.snapshots.append(snapshot.git_ref)
        return snapshot

    def resolve_snapshot(self, session_id: str, ref_or_action: Optional[str] = None) -> Optional[SnapshotRef]:
        """Resolves a snapshot by git ref or action ID; defaults to the latest snapshot."""
        if ref_or_action:
            return self.snapshot_mgr.get_snapshot(session_id, ref_or_action)
        return self.snapshot_mgr.get_latest_snapshot(session_id)

    def rewind(self, session_id: str, git_ref: Optional[str] = None) -> bool:
        """Restores repository or worktree files to snapshot state (repository files only)."""
        session = self.sessions.get(session_id)
        snap = self.resolve_snapshot(session_id, git_ref)
        target_ref = snap.git_ref if snap else git_ref
        if not target_ref and session and session.snapshots:
            target_ref = session.snapshots[-1]

        if not target_ref:
            return False
        # Never rewind to a ref outside this session's namespace.
        if not target_ref.startswith(f"refs/leash/{session_id}/"):
            return False

        if session and session.worktree_path and not Path(session.worktree_path).exists():
            return False  # never fall back to rewinding the main repository
        worktree_path = Path(session.worktree_path) if session else None
        ok = self.snapshot_mgr.rewind_to_snapshot(
            target_ref, worktree_path=worktree_path, backup_session_id=session_id
        )
        if ok:
            # Snapshots taken after the target describe a state that no longer exists in the tree,
            # but they stay available as history.
            logger.info(f"Session {session_id} rewound to {target_ref}")
        return ok

    def list_snapshots(self, session_id: str) -> List[SnapshotRef]:
        """Lists snapshots captured for the given session."""
        return self.snapshot_mgr.list_snapshots(session_id)

    def record_action_result(self, session_id: str, request: ActionRequest, exit_code: int) -> Optional[str]:
        """Feeds command outcome back into runaway guard to track failure streaks."""
        guard = self.session_guards.get(session_id)
        if guard and request.command:
            return guard.record_result(request.command, exit_code)
        return None

    def get_session_details(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Returns comprehensive diagnostic status of a session."""
        session = self.sessions.get(session_id)
        if not session:
            return None

        guard = self.session_guards.get(session_id)
        guard_stats = guard.get_stats() if guard else {}
        worktree_status = self.worktree_mgr.get_worktree_status(session_id)
        snapshots = [s.to_dict() for s in self.list_snapshots(session_id)]

        return {
            "session": session.to_dict(),
            "worktree_status": worktree_status,
            "guard_stats": guard_stats,
            "snapshots": snapshots,
            "taint": self.get_taint_context(session_id).to_dict(),
            "actions_count": len(self.session_action_history.get(session_id, [])),
        }

    def shutdown_all(self, cleanup_worktrees: bool = True) -> None:
        """Cleanly terminates all active sessions."""
        for session_id in list(self.sessions.keys()):
            sess = self.sessions[session_id]
            if sess.state in (SessionState.ACTIVE, SessionState.PAUSED):
                self.terminate_session(session_id, reason="Daemon shutdown", cleanup_worktree=cleanup_worktrees)
