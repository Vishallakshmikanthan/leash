"""
session/snapshot.py - Hidden Git ref snapshots and Rewind mechanism (N4).
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import List, Optional

from contracts.models import SnapshotRef


class SnapshotManager:
    """Creates point-in-time git snapshots under refs/leash/<session>/<n> and enables Rewind."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()
        self._counter: int = 0

    def create_snapshot(self, session_id: str, description: str) -> Optional[SnapshotRef]:
        self._counter += 1
        ref_name = f"refs/leash/{session_id}/{self._counter}"

        try:
            # 1. Stage changes or get commit tree
            # git stash create returns a commit SHA representing current working state without altering working tree
            res = subprocess.run(
                ["git", "stash", "create", f"Leash snapshot {self._counter}: {description}"],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            commit_sha = res.stdout.strip()
            if not commit_sha:
                # If working tree is clean, point to HEAD
                head_res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(self.repo_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                commit_sha = head_res.stdout.strip()

            if not commit_sha:
                return None

            # 2. Update hidden ref
            subprocess.run(
                ["git", "update-ref", ref_name, commit_sha],
                cwd=str(self.repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            return SnapshotRef(
                session=session_id,
                index=self._counter,
                git_ref=ref_name,
                commit_sha=commit_sha,
                created_at=int(time.time()),
                description=description,
            )
        except Exception:
            return None

    def rewind_to_snapshot(self, git_ref: str) -> bool:
        """Restores repository tracked files to the snapshot state."""
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
                cwd=str(self.repo_root),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return True
        except Exception:
            return False
