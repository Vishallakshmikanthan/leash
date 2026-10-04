"""
session/worktree.py - Git worktree isolation per session (F4).
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("leash.session.worktree")


def _handle_remove_readonly(func, path, exc_info):
    """Clear readonly bit and retry deletion for Windows path locks/readonly files."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class WorktreeManager:
    """Creates, inspects, and destroys isolated Git worktrees for agent sessions."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()

    def _is_git_repo(self) -> bool:
        """Check if repo_root is inside a valid git repository."""
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
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def _branch_exists(self, branch_name: str) -> bool:
        """Check if a branch exists locally."""
        try:
            res = subprocess.run(
                ["git", "show-ref", "--verify", f"refs/heads/{branch_name}"],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            return res.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_worktree_path(self, session_id: str) -> Path:
        """Returns the canonical worktree directory path for a session."""
        return self.repo_root / ".leash" / "worktrees" / session_id

    def get_branch_name(self, session_id: str) -> str:
        """Returns the canonical git branch name for a session."""
        return f"leash/{session_id}"

    def create_session_worktree(self, session_id: str, base_ref: str = "HEAD") -> Path:
        """Creates an isolated git worktree on branch leash/<session_id>."""
        branch_name = self.get_branch_name(session_id)
        worktree_path = self.get_worktree_path(session_id)
        worktree_path.parent.mkdir(parents=True, exist_ok=True)

        if not self._is_git_repo():
            # Not a git repo: fallback to plain directory isolation
            worktree_path.mkdir(parents=True, exist_ok=True)
            return worktree_path

        if not worktree_path.exists():
            # If branch already exists, attach to it; otherwise create branch with -b
            if self._branch_exists(branch_name):
                cmd = ["git", "worktree", "add", str(worktree_path), branch_name]
            else:
                cmd = ["git", "worktree", "add", "-b", branch_name, str(worktree_path), base_ref]

            try:
                res = subprocess.run(
                    cmd,
                    cwd=str(self.repo_root),
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                if res.returncode != 0:
                    logger.warning(
                        f"git worktree add failed ({res.stderr.strip()}), falling back to directory creation"
                    )
                    worktree_path.mkdir(parents=True, exist_ok=True)
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                logger.warning(f"Git execution error ({e}), falling back to directory creation")
                worktree_path.mkdir(parents=True, exist_ok=True)

        return worktree_path

    def cleanup_session_worktree(
        self, session_id: str, delete_branch: bool = False, force: bool = True
    ) -> bool:
        """Removes the session worktree and optionally deletes the git branch."""
        worktree_path = self.get_worktree_path(session_id)
        branch_name = self.get_branch_name(session_id)
        success = True

        if self._is_git_repo():
            # 1. Remove git worktree registration
            cmd = ["git", "worktree", "remove"]
            if force:
                cmd.append("--force")
            cmd.append(str(worktree_path))

            res = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                text=True,
            )
            # Prune obsolete worktree references
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            # 2. Delete branch if requested
            if delete_branch and self._branch_exists(branch_name):
                subprocess.run(
                    ["git", "branch", "-D", branch_name],
                    cwd=str(self.repo_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )

        # 3. Clean up directory if still present
        if worktree_path.exists():
            try:
                shutil.rmtree(worktree_path, onerror=_handle_remove_readonly)
            except Exception as ex:
                logger.warning(f"Could not completely remove worktree dir {worktree_path}: {ex}")
                success = False

        return success

    def get_worktree_status(self, session_id: str) -> Dict[str, Any]:
        """Inspects status of the session worktree (exists, clean/dirty, modified files)."""
        worktree_path = self.get_worktree_path(session_id)
        branch_name = self.get_branch_name(session_id)

        if not worktree_path.exists():
            return {
                "session_id": session_id,
                "exists": False,
                "worktree_path": str(worktree_path),
                "branch_name": branch_name,
                "is_clean": True,
                "changes": [],
            }

        changes: List[str] = []
        is_clean = True
        commit_sha = ""

        if self._is_git_repo():
            try:
                status_res = subprocess.run(
                    ["git", "status", "--porcelain"],
                    cwd=str(worktree_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if status_res.returncode == 0:
                    lines = [line.strip() for line in status_res.stdout.splitlines() if line.strip()]
                    changes = lines
                    is_clean = len(lines) == 0

                head_res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(worktree_path),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                if head_res.returncode == 0:
                    commit_sha = head_res.stdout.strip()
            except Exception:
                pass

        return {
            "session_id": session_id,
            "exists": True,
            "worktree_path": str(worktree_path),
            "branch_name": branch_name,
            "commit_sha": commit_sha,
            "is_clean": is_clean,
            "changes": changes,
        }

    def list_worktrees(self) -> List[Dict[str, Any]]:
        """Lists active worktrees from git worktree list."""
        if not self._is_git_repo():
            return []

        try:
            res = subprocess.run(
                ["git", "worktree", "list", "--porcelain"],
                cwd=str(self.repo_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if res.returncode != 0:
                return []

            worktrees = []
            curr: Dict[str, str] = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    if curr:
                        worktrees.append(curr)
                        curr = {}
                    continue
                parts = line.split(" ", 1)
                key = parts[0]
                val = parts[1] if len(parts) > 1 else ""
                curr[key] = val
            if curr:
                worktrees.append(curr)
            return worktrees
        except Exception:
            return []

    def save_worktree_changes(
        self, session_id: str, message: str = "Auto-save on session termination"
    ) -> Optional[str]:
        """Stages and commits any uncommitted worktree changes."""
        worktree_path = self.get_worktree_path(session_id)
        if not worktree_path.exists() or not self._is_git_repo():
            return None

        try:
            # Check if dirty
            status_res = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=str(worktree_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if not status_res.stdout.strip():
                return None  # Nothing to commit

            subprocess.run(
                ["git", "add", "-A"],
                cwd=str(worktree_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
            )
            commit_res = subprocess.run(
                ["git", "commit", "-m", message],
                cwd=str(worktree_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            head_res = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=str(worktree_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            return head_res.stdout.strip()
        except Exception as ex:
            logger.warning(f"Failed to auto-save worktree changes for {session_id}: {ex}")
            return None
