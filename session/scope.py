"""
session/scope.py - Task scope contract enforcement (N3).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

from contracts.models import ActionRequest


class ScopeContract:
    """Validates that actions stay within agreed path, command, and host boundaries."""

    def __init__(
        self,
        allowed_paths: Optional[List[str]] = None,
        allowed_commands: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
    ):
        self.allowed_paths = [os.path.abspath(p) for p in (allowed_paths or ["."])]
        self.allowed_commands = allowed_commands or []
        self.allowed_hosts = allowed_hosts or ["localhost", "127.0.0.1"]

    def validate_action(self, request: ActionRequest) -> List[str]:
        flags: List[str] = []

        # Check path boundaries
        if request.target_path:
            abs_target = os.path.abspath(request.target_path)
            within_any = any(abs_target.startswith(allowed) for allowed in self.allowed_paths)
            if not within_any:
                flags.append("outside-allowed-paths")

        # Check command boundaries
        if request.command and self.allowed_commands:
            first_token = request.command.strip().split()[0]
            if first_token not in self.allowed_commands:
                flags.append("outside-allowed-commands")

        return flags
