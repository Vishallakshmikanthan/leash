"""
session/snapshot.py - Hidden Git ref snapshots and Rewind mechanism (N4).

Scope of Rewind
---------------
Rewind restores files that Git can see in the repository or session worktree:
tracked files and untracked files that are not ignored. It does NOT undo external
effects: network requests, global package installs, changes outside the repository,
ignored files (for example node_modules), or processes that were started.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from contracts.models import SnapshotRef

logger = logging.getLogger("leash.session.snapshot")

REWIND_SCOPE_NOTICE = (
    "Rewind restores repository files only (tracked files and non-ignored untracked files). "
    "It cannot undo network requests, global installs, ignored files, "
    "changes outside the repository, or running processes."
)

_GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "Leash",
    "GIT_AUTHOR_EMAIL": "leash@localhost",
    "GIT_COMMITTER_NAME": "Leash",
    "GIT_COMMITTER_EMAIL": "leash@localhost",
}

_SESSION_TRAILER = "Leash-Session: "
_ACTION_TRAILER = "Leash-Action: "
_DESC_TRAILER = "Leash-Description: "


class SnapshotError(RuntimeError):
    pass


class SnapshotManager:
    """Creates point-in-time git snapshots under refs/leash/<session>/<n> and enables Rewind."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root).resolve()
        self._session_counters: Dict[str, int] = {}
        self._cached_snapshots: Dict[str, List[SnapshotRef]] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Git helpers
    # ------------------------------------------------------------------

    def _git(
        self,
        args: List[str],
        cwd: Path,
        env: Optional[Dict[str, str]] = None,
        check: bool = True,
        input_text: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        return subprocess.run(
            ["git"] + args,
            cwd=str(cwd),
            env=full_env,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
        )

    def _is_git_repo(self) -> bool:
        try:
            res = self._git(["rev-parse", "--is-inside-work-tree"], self.repo_root, check=False)
            return res.returncode == 0 and res.stdout.strip() == "true"
        except Exception:
            return False

    def _resolve_dir(self, worktree_path: Optional[Path]) -> Path:
        if worktree_path and Path(worktree_path).exists():
            return Path(worktree_path).resolve()
        return self.repo_root

    def _next_index(self, session_id: str) -> int:
        """Next index is based on existing refs so counters survive daemon restarts."""
        idx = self._session_counters.get(session_id, 0)
        try:
            res = self._git(
                ["for-each-ref", f"refs/leash/{session_id}/", "--format=%(refname)"],
                self.repo_root,
                check=False,
            )
            for line in res.stdout.splitlines():
                tail = line.strip().rsplit("/", 1)[-1]
                if tail.isdigit():
                    idx = max(idx, int(tail))
        except Exception:
            pass
        idx += 1
        self._session_counters[session_id] = idx
        return idx

    def _capture_tree(self, working_dir: Path) -> Optional[tuple]:
        """Builds a commit holding the full working state (tracked + untracked, not ignored).

        Uses a temporary index so the real index and working tree stay untouched.
        Returns (commit_sha, head_sha) or None when the repository has no commits.
        """
        head = self._git(["rev-parse", "--verify", "HEAD"], working_dir, check=False)
        head_sha = head.stdout.strip()
        if head.returncode != 0 or not head_sha:
            return None
        fd, tmp_index = tempfile.mkstemp(prefix="leash_idx_")
        os.close(fd)
        os.unlink(tmp_index)
        env = {"GIT_INDEX_FILE": tmp_index}
        try:
            self._git(["read-tree", "HEAD"], working_dir, env=env)
            self._git(["add", "-A"], working_dir, env=env)
            tree = self._git(["write-tree"], working_dir, env=env).stdout.strip()
            return tree, head_sha
        finally:
            try:
                os.unlink(tmp_index)
            except OSError:
                pass

    def _commit_state(
        self, working_dir: Path, session_id: str, description: str, action_id: Optional[str]
    ) -> Optional[tuple]:
        captured = self._capture_tree(working_dir)
        if not captured:
            return None
        tree, head_sha = captured
        message = (
            f"Leash snapshot: {description}\n\n"
            f"{_SESSION_TRAILER}{session_id}\n"
            f"{_ACTION_TRAILER}{action_id or ''}\n"
            f"{_DESC_TRAILER}{description}\n"
        )
        commit = self._git(
            ["commit-tree", tree, "-p", head_sha],
            working_dir,
            env=_GIT_IDENTITY_ENV,
            input_text=message,
        ).stdout.strip()
        return commit, head_sha

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_snapshot(
        self,
        session_id: str,
        description: str,
        worktree_path: Optional[Path] = None,
        action_id: Optional[str] = None,
    ) -> Optional[SnapshotRef]:
        """Creates a snapshot commit and hidden git ref for the current working state."""
        with self._lock:
            working_dir = self._resolve_dir(worktree_path)

            if not self._is_git_repo():
                # Non-git directory: no real snapshot is possible.
                logger.warning("Snapshot skipped: %s is not a git repository", self.repo_root)
                return None

            try:
                state = self._commit_state(working_dir, session_id, description, action_id)
                if not state:
                    return None
                commit_sha, _ = state
                idx = self._next_index(session_id)
                ref_name = f"refs/leash/{session_id}/{idx}"
                self._git(["update-ref", ref_name, commit_sha], self.repo_root)

                snap = SnapshotRef(
                    session=session_id,
                    index=idx,
                    git_ref=ref_name,
                    commit_sha=commit_sha,
                    created_at=int(time.time()),
                    description=description,
                    action_id=action_id,
                )
                self._cached_snapshots.setdefault(session_id, []).append(snap)
                return snap
            except Exception as ex:
                logger.warning(f"Failed to create git snapshot for {session_id}: {ex}")
                return None

    def rewind_to_snapshot(
        self,
        git_ref: str,
        worktree_path: Optional[Path] = None,
        clean_untracked: bool = True,
        backup_session_id: Optional[str] = None,
    ) -> bool:
        """Restores repository or worktree files to the specified snapshot state.

        Before changing anything, the current state is saved to a backup ref
        (refs/leash/<session>/backup-<n>) so a Rewind can itself be recovered.
        The branch HEAD is restored to the commit that was checked out at snapshot time.
        """
        with self._lock:
            working_dir = self._resolve_dir(worktree_path)

            if not self._is_git_repo():
                return False

            try:
                self._git(["rev-parse", "--verify", f"{git_ref}^{{commit}}"], self.repo_root)
                parent_sha = self._git(["rev-parse", "--verify", f"{git_ref}^"], self.repo_root).stdout.strip()
                snap_tree = self._git(["rev-parse", f"{git_ref}^{{tree}}"], self.repo_root).stdout.strip()

                # 1. Safety backup of the current state.
                if backup_session_id:
                    self._save_backup(working_dir, backup_session_id)

                # 2. Return HEAD, index and tracked files to the snapshot-time commit.
                self._git(["reset", "--hard", parent_sha], working_dir)

                # 3. Remove untracked (non-ignored) files created after the snapshot.
                if clean_untracked:
                    self._git(["clean", "-fd"], working_dir, check=False)

                # 4. Write snapshot files over the working tree via a temporary index.
                fd, tmp_index = tempfile.mkstemp(prefix="leash_idx_")
                os.close(fd)
                os.unlink(tmp_index)
                env = {"GIT_INDEX_FILE": tmp_index}
                try:
                    self._git(["read-tree", snap_tree], working_dir, env=env)
                    self._git(["checkout-index", "-a", "-f"], working_dir, env=env)
                finally:
                    try:
                        os.unlink(tmp_index)
                    except OSError:
                        pass

                # 5. Delete files that were tracked at HEAD but absent at snapshot time.
                deleted = self._git(
                    ["diff-tree", "-r", "--name-only", "--no-renames", "--diff-filter=D", parent_sha, snap_tree],
                    working_dir,
                    check=False,
                ).stdout.splitlines()
                for rel in deleted:
                    rel = rel.strip()
                    if not rel:
                        continue
                    target = (working_dir / rel).resolve()
                    try:
                        target.relative_to(working_dir)
                    except ValueError:
                        continue
                    if target.is_file() or target.is_symlink():
                        target.unlink()

                # 6. Reset index to HEAD so Git status shows the restored differences.
                self._git(["reset", "-q"], working_dir, check=False)
                return True
            except Exception as ex:
                logger.error(f"Rewind failed for ref {git_ref}: {ex}")
                return False

    def _save_backup(self, working_dir: Path, session_id: str) -> Optional[str]:
        try:
            state = self._commit_state(working_dir, session_id, "Automatic backup before Rewind", None)
            if not state:
                return None
            commit_sha, _ = state
            n = int(time.time() * 1000)
            ref_name = f"refs/leash/{session_id}/backup-{n}"
            self._git(["update-ref", ref_name, commit_sha], self.repo_root)
            return ref_name
        except Exception as ex:
            logger.warning(f"Rewind backup failed: {ex}")
            return None

    def get_snapshot(self, session_id: str, ref_or_action: str) -> Optional[SnapshotRef]:
        """Finds a snapshot by git ref or by the action ID it was created for."""
        for snap in self.list_snapshots(session_id):
            if snap.git_ref == ref_or_action or (snap.action_id and snap.action_id == ref_or_action):
                return snap
        return None

    def list_snapshots(self, session_id: str) -> List[SnapshotRef]:
        """Returns all snapshots captured for the given session."""
        with self._lock:
            if session_id in self._cached_snapshots:
                return list(self._cached_snapshots[session_id])

            snapshots: List[SnapshotRef] = []
            if self._is_git_repo():
                try:
                    prefix = f"refs/leash/{session_id}/"
                    res = self._git(
                        ["for-each-ref", prefix, "--format=%(refname) %(objectname)"],
                        self.repo_root,
                        check=False,
                    )
                    if res.returncode == 0:
                        for line in res.stdout.splitlines():
                            parts = line.strip().split()
                            if len(parts) < 2:
                                continue
                            ref_name, sha = parts[0], parts[1]
                            idx_str = ref_name.rsplit("/", 1)[-1]
                            if not idx_str.isdigit():
                                continue  # skip backup refs
                            snapshots.append(self._read_snapshot(session_id, int(idx_str), ref_name, sha))
                except Exception:
                    pass

            snapshots.sort(key=lambda s: s.index)
            self._cached_snapshots[session_id] = snapshots
            return snapshots

    def _read_snapshot(self, session_id: str, idx: int, ref_name: str, sha: str) -> SnapshotRef:
        description = f"Snapshot {idx}"
        action_id: Optional[str] = None
        created = int(time.time())
        try:
            res = self._git(["log", "-1", "--format=%ct%n%B", sha], self.repo_root, check=False)
            lines = res.stdout.splitlines()
            if lines and lines[0].strip().isdigit():
                created = int(lines[0].strip())
            for line in lines[1:]:
                if line.startswith(_ACTION_TRAILER):
                    action_id = line[len(_ACTION_TRAILER):].strip() or None
                elif line.startswith(_DESC_TRAILER):
                    description = line[len(_DESC_TRAILER):].strip() or description
        except Exception:
            pass
        return SnapshotRef(
            session=session_id,
            index=idx,
            git_ref=ref_name,
            commit_sha=sha,
            created_at=created,
            description=description,
            action_id=action_id,
        )

    def get_latest_snapshot(self, session_id: str) -> Optional[SnapshotRef]:
        """Returns the most recent snapshot for the session."""
        snaps = self.list_snapshots(session_id)
        return snaps[-1] if snaps else None

    def delete_snapshots(self, session_id: str) -> None:
        """Cleans up all hidden refs for a session."""
        with self._lock:
            self._cached_snapshots.pop(session_id, None)
            self._session_counters.pop(session_id, None)
            if self._is_git_repo():
                try:
                    prefix = f"refs/leash/{session_id}/"
                    res = self._git(["for-each-ref", prefix, "--format=%(refname)"], self.repo_root, check=False)
                    if res.returncode == 0:
                        for ref_name in res.stdout.splitlines():
                            ref_name = ref_name.strip()
                            if ref_name:
                                self._git(["update-ref", "-d", ref_name], self.repo_root, check=False)
                except Exception:
                    pass
