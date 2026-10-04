"""
session/worktree.py - Git worktree isolation per session (F4).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Optional


class WorktreeManager:
    """Creates and destroys isolated Git worktrees for agent sessions."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()

    def create_session_worktree(self, session_id: str) -> Path:
        branch_name = f"leash/{session_id}"
        worktree_path = self.repo_root / ".leash" / "worktrees" / session_id
        worktree_path.parent.mkdir(parents=True, exist_ok=True)

        if not worktree_path.exists():
            cmd = ["git", "worktree", "add", "-b", branch_name, str(worktree_path)]
            try:
                subprocess.run(
                    cmd,
                    cwd=str(self.repo_root),
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Fallback to local directory if git worktree fails (e.g., bare repo or no commits)
                worktree_path.mkdir(parents=True, exist_ok=True)

        return worktree_path

    def cleanup_session_worktree(self, session_id: str) -> None:
        worktree_path = self.repo_root / ".leash" / "worktrees" / session_id
        if worktree_path.exists():
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(worktree_path)],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
