"""
daemon/container.py - Container containment runtime (L2) using Docker, Podman, or bubblewrap.
Restricts file system access strictly to the session worktree and cuts off raw network.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("leash.daemon.container")


class ContainerRuntime:
    """Manages L2 containment isolation for agent sessions."""

    def __init__(self, runtime_bin: Optional[str] = None):
        self.runtime_bin = runtime_bin or self.detect_runtime()

    @staticmethod
    def detect_runtime() -> Optional[str]:
        for candidate in ("docker", "podman", "bwrap"):
            found = shutil.which(candidate)
            if found:
                return candidate
        return None

    def is_available(self) -> bool:
        return self.runtime_bin is not None

    def build_contained_command(
        self,
        agent_cmd: List[str],
        worktree_path: str,
        session_token: str,
        agent_url: str,
        enable_network: bool = False,
        image: str = "python:3.11-slim",
    ) -> List[str]:
        """
        Builds the invocation command line for the detected container engine.
        Mounts only worktree_path into /workspace.
        Disables networking unless explicitly permitted.
        """
        runtime = self.runtime_bin or "docker"
        real_worktree = str(Path(worktree_path).resolve())

        if runtime in ("docker", "podman"):
            cmd = [
                runtime,
                "run",
                "--rm",
                "-i",
                "-v", f"{real_worktree}:/workspace:rw",
                "-w", "/workspace",
                "-e", f"LEASH_SESSION_TOKEN={session_token}",
                "-e", f"LEASH_AGENT_URL={agent_url}",
                "-e", "LEASH_CONTAINED=1",
                "-e", "HOME=/tmp",
            ]
            if not enable_network:
                cmd.extend(["--network", "none"])

            cmd.append(image)
            cmd.extend(agent_cmd)
            return cmd

        elif runtime == "bwrap":
            cmd = [
                "bwrap",
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--proc", "/proc",
                "--dev", "/dev",
                "--tmpfs", "/tmp",
                "--bind", real_worktree, "/workspace",
                "--chdir", "/workspace",
                "--setenv", "LEASH_SESSION_TOKEN", session_token,
                "--setenv", "LEASH_AGENT_URL", agent_url,
                "--setenv", "LEASH_CONTAINED", "1",
                "--setenv", "HOME", "/tmp",
            ]
            if not enable_network:
                cmd.append("--unshare-net")

            if os.path.exists("/lib64"):
                cmd.extend(["--ro-bind", "/lib64", "/lib64"])
            if os.path.exists("/bin"):
                cmd.extend(["--ro-bind", "/bin", "/bin"])

            cmd.extend(agent_cmd)
            return cmd

        # Fallback if no container installed
        raise RuntimeError("No container engine (docker, podman, bwrap) found on host for L2 Contained execution.")
