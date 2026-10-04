"""
shim/git_guard.py - Git Command Guard routing push, reset, and clean through Leash safety layer.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, Decision, Verdict
from shim.shell_wrapper import ShellShim


class GitGuard:
    """Specialized wrapper around git CLI preventing accidental history rewrites or leaks."""

    DANGEROUS_SUBCOMMANDS = {"push", "reset", "clean", "checkout", "rebase"}

    def __init__(self, shim: ShellShim):
        self.shim = shim

    def run_git(self, git_args: List[str]) -> int:
        if not git_args:
            return self.shim.intercept_and_run(["git"])

        subcommand = git_args[0]
        # Inspect dangerous flags
        is_risky = subcommand in self.DANGEROUS_SUBCOMMANDS
        full_command = ["git"] + git_args

        # Route through shell shim
        return self.shim.intercept_and_run(full_command)
