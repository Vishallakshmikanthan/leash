"""
gates/workflow_watchlist.py - Watchlist for sensitive files (CI workflows, Dockerfiles, lockfiles).
"""
from __future__ import annotations

import re
from typing import Optional

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


class WorkflowWatchlistGate(BaseGate):
    """Flags edits or writes to sensitive configuration files like GitHub Actions or Dockerfiles."""

    SENSITIVE_FILES_PATTERN = re.compile(
        r"(\.github/workflows/.*|Dockerfile.*|docker-compose.*\.ya?ml|package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|requirements\.txt|pyproject\.toml|Makefile|\.npmrc|\.yarnrc|leash\.ya?ml)",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "WorkflowWatchlist"

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        target = request.target_path or ""
        cmd = request.command or ""

        is_sensitive = False
        file_matched = ""

        if request.kind in (ActionKind.FILE_EDIT, ActionKind.FILE_READ):
            match = self.SENSITIVE_FILES_PATTERN.search(target)
            if match:
                is_sensitive = True
                file_matched = match.group(0)

        elif request.kind == ActionKind.SHELL and cmd:
            match = self.SENSITIVE_FILES_PATTERN.search(cmd)
            if match and any(op in cmd for op in [">", "rm", "mv", "sed", "echo"]):
                is_sensitive = True
                file_matched = match.group(0)

        if is_sensitive:
            return GateResult(
                triggered=True,
                rule_id="R-CFG-SENSITIVE-FILE",
                category="sensitive-file-edits",
                severity=Severity.HIGH,
                summary=f"Modification to protected workflow/build config: {file_matched}",
                why="Tampering with CI workflows or lockfiles can introduce supply chain attacks.",
                safer_alternative="Review manual pull request diffs for CI/build pipeline adjustments.",
            )

        return None
