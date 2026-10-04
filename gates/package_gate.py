"""
gates/package_gate.py - Package Gate (N1): checks package install operations for typosquatting/risk.
"""
from __future__ import annotations

import re
from typing import List, Optional, Set

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes basic edit distance to flag typosquats."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class PackageGate(BaseGate):
    """Detects suspicious or typosquatted package installations in offline mode."""

    POPULAR_PACKAGES: Set[str] = {
        "requests", "flask", "django", "numpy", "pandas", "pytest", "scipy",
        "react", "express", "lodash", "axios", "typescript", "chalk", "webpack",
        "tokio", "serde", "syn", "anyhow"
    }

    INSTALL_COMMAND_PATTERN = re.compile(
        r"(?:pip\s+install|npm\s+(?:i|install)|yarn\s+add|cargo\s+add)\s+([a-zA-Z0-9_\-\.\s]+)",
        re.IGNORECASE,
    )

    @property
    def name(self) -> str:
        return "PackageGate"

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        cmd = request.command or ""
        if request.kind not in (ActionKind.SHELL, ActionKind.INSTALL):
            return None

        match = self.INSTALL_COMMAND_PATTERN.search(cmd)
        if not match:
            return None

        raw_pkgs = match.group(1).split()
        for pkg in raw_pkgs:
            # Strip flags
            if pkg.startswith("-"):
                continue
            pkg_name = pkg.split("==")[0].split(">=")[0].split("@")[0].strip().lower()
            if not pkg_name:
                continue

            # Check if exactly in popular list
            if pkg_name in self.POPULAR_PACKAGES:
                continue

            # Check for typosquatting (edit distance == 1)
            for popular in self.POPULAR_PACKAGES:
                if levenshtein_distance(pkg_name, popular) == 1:
                    return GateResult(
                        triggered=True,
                        rule_id="R-PKG-TYPOSQUAT",
                        category="package-install",
                        severity=Severity.HIGH,
                        summary=f"Package '{pkg_name}' is suspiciously close to popular package '{popular}'.",
                        why="Typosquatting packages often contain infostealers or reverse shells.",
                        safer_alternative=f"Verify if you intended to install '{popular}' instead.",
                    )

            # Untrusted arbitrary install
            if len(pkg_name) > 2:
                return GateResult(
                    triggered=True,
                    rule_id="R-PKG-NEW-INSTALL",
                    category="package-install",
                    severity=Severity.MEDIUM,
                    summary=f"Installing external package '{pkg_name}'.",
                    why="Installing packages executes arbitrary lifecycle install scripts.",
                    safer_alternative="Pin dependencies in lockfile with checksum verification.",
                )

        return None
