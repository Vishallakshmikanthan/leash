"""
session/snapshot.py - Hidden Git ref snapshots and Rewind mechanism (N4).
"""
from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from contracts.models import SnapshotRef

logger = logging.getLogger("leash.session.snapshot")


class SnapshotManager:
    """Creates point-in-time git snapshots under refs/leash/<session>/<n> and enables Rewind."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()
        self._session_counters: Dict[str, int] = {}
        self._cached_snapshots: Dict[str, List[SnapshotRef]] = {}

    def _is_git_repo(self) -> bool:
        try:
            res = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            return res.returncode == 0 and res.stdout.strip() == "true"
        except Exception:
            return False

    def create_snapshot(
        self, session_id: str, description: str, worktree_path: Optional[Path] = None
    ) -> Optional[SnapshotRef]:
        """Creates a snapshot commit and hidden git ref for the current working state."""
        idx = self._session_counters.get(session_id, 0) + 1
        self._session_counters[session_id] = idx
        ref_name = f"refs/leash/{session_id}/{idx}"

        working_dir = Path(worktree_path).resolve() if worktree_path and Path(worktree_path).exists() else self.repo_root

        if not self._is_git_repo():
            # In non-git mode, return synthetic snapshot record
            snap = SnapshotRef(
                session=session_id,
                index=idx,
                git_ref=ref_name,
                commit_sha=f"sha_{idx:08x}",
                created_at=int(time.time()),
                description=description,
            )
            self._cached_snapshots.setdefault(session_id, []).append(snap)
            return snap

        try:
            # 1. Capture uncommitted changes via git stash create
            res = subprocess.run(
                ["git", "stash", "create", f"Leash snapshot {idx}: {description}"],
                cwd=str(working_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            commit_sha = res.stdout.strip()

            # If working tree has no uncommitted changes, point to HEAD commit
            if not commit_sha:
                head_res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(working_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                commit_sha = head_res.stdout.strip()

            if not commit_sha:
                return None

            # 2. Store hidden git ref under refs/leash/<session>/<idx>
            subprocess.run(
                ["git", "update-ref", ref_name, commit_sha],
                cwd=str(self.repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            snap = SnapshotRef(
                session=session_id,
                index=idx,
                git_ref=ref_name,
                commit_sha=commit_sha,
                created_at=int(time.time()),
                description=description,
            )
            self._cached_snapshots.setdefault(session_id, []).append(snap)
            return snap
        except Exception as ex:
            logger.warning(f"Failed to create git snapshot for {session_id}: {ex}")
            return None

    def rewind_to_snapshot(
        self, git_ref: str, worktree_path: Optional[Path] = None, clean_untracked: bool = True
    ) -> bool:
        """Restores repository or worktree tracked files to the specified snapshot state."""
        working_dir = Path(worktree_path).resolve() if worktree_path and Path(worktree_path).exists() else self.repo_root

        if not self._is_git_repo():
            return True

        try:
            # Check ref exists
            subprocess.run(
                ["git", "rev-parse", "--verify", git_ref],
                cwd=str(self.repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Restore working tree to snapshot state
            subprocess.run(
                ["git", "reset", "--hard", git_ref],
                cwd=str(working_dir),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if clean_untracked:
                subprocess.run(
                    ["git", "clean", "-fd"],
                    cwd=str(working_dir),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            return True
        except Exception as ex:
            logger.error(f"Rewind failed for ref {git_ref}: {ex}")
            return False

    def list_snapshots(self, session_id: str) -> List[SnapshotRef]:
        """Returns all snapshots captured for the given session."""
        if session_id in self._cached_snapshots:
            return list(self._cached_snapshots[session_id])

        snapshots: List[SnapshotRef] = []
        if self._is_git_repo():
            try:
                prefix = f"refs/leash/{session_id}/"
                res = subprocess.run(
                    ["git", "for-each-ref", prefix, "--format=%(refname) %(objectname)"],
                    cwd=str(self.repo_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ref_name, sha = parts[0], parts[1]
                            idx_str = ref_name.rsplit("/", 1)[-1]
                            idx = int(idx_str) if idx_str.isdigit() else 1
                            snapshots.append(
                                SnapshotRef(
                                    session=session_id,
                                    index=idx,
                                    git_ref=ref_name,
                                    commit_sha=sha,
                                    created_at=int(time.time()),
                                    description=f"Snapshot {idx}",
                                )
                            )
            except Exception:
                pass

        snapshots.sort(key=lambda s: s.index)
        self._cached_snapshots[session_id] = snapshots
        return snapshots

    def get_latest_snapshot(self, session_id: str) -> Optional[SnapshotRef]:
        """Returns the most recent snapshot for the session."""
        snaps = self.list_snapshots(session_id)
        return snaps[-1] if snaps else None

    def delete_snapshots(self, session_id: str) -> None:
        """Cleans up all hidden refs for a session."""
        self._cached_snapshots.pop(session_id, None)
        self._session_counters.pop(session_id, None)
        if self._is_git_repo():
            try:
                prefix = f"refs/leash/{session_id}/"
                res = subprocess.run(
                    ["git", "for-each-ref", prefix, "--format=%(refname)"],
                    cwd=str(self.repo_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if res.returncode == 0:
                    for ref_name in res.stdout.splitlines():
                        ref_name = ref_name.strip()
                        if ref_name:
                            subprocess.run(
                                ["git", "update-ref", "-d", ref_name],
                                cwd=str(self.repo_root),
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                check=False,
                            )
            except Exception:
                pass
