"""
gates/hidden_text.py - Hidden-Text Scanner (N7): detects invisible Unicode, bidirectional overrides.
"""
from __future__ import annotations

import unicodedata
from typing import List, Optional, Tuple

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


class HiddenTextGate(BaseGate):
    """Scans content and commands for hidden characters and bidirectional overrides."""

    BIDI_CONTROL_CODEPOINTS = {
        0x202A,  # Left-to-Right Embedding
        0x202B,  # Right-to-Left Embedding
        0x202C,  # Pop Directional Formatting
        0x202D,  # Left-to-Right Override
        0x202E,  # Right-to-Left Override
        0x2066,  # Left-to-Right Isolate
        0x2067,  # Right-to-Left Isolate
        0x2068,  # First Strong Isolate
        0x2069,  # Pop Directional Isolate
    }

    ZERO_WIDTH_CODEPOINTS = {
        0x200B,  # Zero-width space
        0x200C,  # Zero-width non-joiner
        0x200D,  # Zero-width joiner
        0xFEFF,  # Zero-width no-break space
    }

    @property
    def name(self) -> str:
        return "HiddenTextScanner"

    def scan_string(self, text: str) -> List[Tuple[int, str]]:
        anomalies: List[Tuple[int, str]] = []
        for idx, ch in enumerate(text):
            cp = ord(ch)
            if cp in self.BIDI_CONTROL_CODEPOINTS:
                anomalies.append((idx, f"BiDi Control (U+{cp:04X})"))
            elif cp in self.ZERO_WIDTH_CODEPOINTS:
                anomalies.append((idx, f"Zero-Width (U+{cp:04X})"))
        return anomalies

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        content_to_check = []
        if request.command:
            content_to_check.append(("command", request.command))
        if request.target_path:
            content_to_check.append(("target_path", request.target_path))

        for label, text in content_to_check:
            anomalies = self.scan_string(text)
            if anomalies:
                types = ", ".join(set(a[1] for a in anomalies))
                return GateResult(
                    triggered=True,
                    rule_id="R-TXT-HIDDEN-UNICODE",
                    category="hidden-text",
                    severity=Severity.MEDIUM,
                    summary=f"Invisible Unicode or BiDi control character found in {label}.",
                    why=f"Found: {types}. Hidden Unicode can disguise malicious shell payloads.",
                    safer_alternative="Strip invisible control characters from the input before executing.",
                )

        return None
