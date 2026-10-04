"""
gates/package_gate.py - Package Gate (N1): checks package install operations for typosquatting/risk.
"""
from __future__ import annotations

import re
from typing import List, Optional, Set

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance supporting insertions, deletions, substitutions, and transpositions."""
    d = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1) # transposition

    return d[(len1 - 1, len2 - 1)]


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

            # Check for typosquatting
            for popular in self.POPULAR_PACKAGES:
                dist = damerau_levenshtein_distance(pkg_name, popular)
                if dist == 1 or (len(popular) >= 7 and dist <= 2):
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
