"""
gates/secret_fence.py - Secret Fence (N2): blocks credential/key exposure and canary reads.
"""
from __future__ import annotations

import re
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


class SecretFenceGate(BaseGate):
    """Detects attempts to read or leak credentials, private keys, .env, or canary secrets."""

    SENSITIVE_PATTERNS = [
        re.compile(r"(^|/|\b)\.env(\.[a-zA-Z0-9_-]+)?(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\b)\.ssh/(id_rsa|id_ed25519|known_hosts|config)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\b)\.aws/(credentials|config)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\b)canary[-_]?secret(\b|$)", re.IGNORECASE),
    ]

    COMMAND_EXPOSURE_PATTERNS = [
        re.compile(r"\bcat\s+.*\.env\b", re.IGNORECASE),
        re.compile(r"\bcat\s+.*\.ssh/\b", re.IGNORECASE),
        re.compile(r"\bprintenv\b|\benv\b|\bexport\b", re.IGNORECASE),
        re.compile(r"\b(CANARY_KEY|LEASH_CANARY_TOKEN)\b", re.IGNORECASE),
    ]

    @property
    def name(self) -> str:
        return "SecretFence"

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        target = request.target_path or ""
        cmd = request.command or ""

        # Check target path for file reads/edits
        if request.kind in (ActionKind.FILE_READ, ActionKind.FILE_EDIT):
            for pat in self.SENSITIVE_PATTERNS:
                if pat.search(target):
                    is_canary = "canary" in target.lower()
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-CANARY" if is_canary else "R-SECRET-PATH",
                        category="canary-touched" if is_canary else "secret-exposure",
                        severity=Severity.HIGH,
                        summary=f"Attempted access to sensitive credential file: {target}",
                        why="Agent is attempting to read private keys or environment secrets.",
                        safer_alternative="Use scoped environment variables or mock configs without secrets.",
                    )

        # Check shell commands
        if request.kind == ActionKind.SHELL and cmd:
            for pat in self.COMMAND_EXPOSURE_PATTERNS:
                if pat.search(cmd):
                    is_canary = "CANARY" in cmd
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-CMD-CANARY" if is_canary else "R-SECRET-CMD",
                        category="canary-touched" if is_canary else "secret-exposure",
                        severity=Severity.HIGH,
                        summary="Command accesses or prints sensitive environment or secret variables.",
                        why="Output from this command may expose secrets or access tokens.",
                        safer_alternative="Reference variables directly in application code without printing.",
                    )

        return None
