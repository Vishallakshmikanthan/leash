"""
daemon/office_kit.py - Office Kit integration for clipboard control channel and receipt/diff transfer.
"""
from __future__ import annotations

import hmac
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from contracts.crypto import LeashSigner
from contracts.models import DecidedBy, Decision, Verdict

logger = logging.getLogger("leash.office_kit")


@dataclass
class ClipboardDecision:
    action_id: str
    verdict: Verdict
    nonce: str
    sig: str
    raw_token: str
    valid: bool


class OfficeKitClipboard:
    """Manages clipboard-based out-of-band communication and token verification."""

    TOKEN_PREFIX = "LEASH-DECISION"

    @classmethod
    def format_decision_token(
        cls,
        action_id: str,
        verdict: Verdict,
        session_id: str,
        signer: LeashSigner,
        nonce: Optional[str] = None,
    ) -> str:
        """Formats a signed decision token for clipboard transfer: LEASH-DECISION:<id>:<verdict>:<nonce>:<sig>"""
        nonce_val = nonce or signer.generate_nonce()
        v_str = verdict.value.lower()
        payload = f"{action_id}:{v_str}:{session_id}:{nonce_val}".encode("utf-8")
        sig = signer.sign(payload)
        return f"{cls.TOKEN_PREFIX}:{action_id}:{v_str}:{nonce_val}:{sig}"

    @classmethod
    def parse_decision_token(
        cls, token_str: str, session_id: str, signer: LeashSigner
    ) -> Optional[ClipboardDecision]:
        """Parses and verifies a clipboard token."""
        if not token_str or not token_str.startswith(cls.TOKEN_PREFIX):
            return None

        parts = token_str.strip().split(":")
        # Supported formats:
        # LEASH-DECISION:<id>:<verdict>:<nonce>:<sig> (5 parts)
        # LEASH-DECISION:<id>:<verdict>:<sig> (4 parts)
        if len(parts) == 5:
            _, action_id, verdict_str, nonce, sig = parts
        elif len(parts) == 4:
            _, action_id, verdict_str, sig = parts
            nonce = "clip"
        else:
            return None

        try:
            verdict = Verdict(verdict_str.lower())
        except ValueError:
            return None

        # Verify signature
        valid = False
        if len(parts) == 5:
            payload = f"{action_id}:{verdict_str.lower()}:{session_id}:{nonce}".encode("utf-8")
            valid = hmac.compare_digest(signer.sign(payload), sig)
        else:
            # Fallback format: action_id:verdict_str
            payload = f"{action_id}:{verdict_str.lower()}".encode("utf-8")
            valid = hmac.compare_digest(signer.sign(payload), sig)

        return ClipboardDecision(
            action_id=action_id,
            verdict=verdict,
            nonce=nonce,
            sig=sig,
            raw_token=token_str,
            valid=valid,
        )

    @classmethod
    def get_clipboard_text(cls) -> Optional[str]:
        """Reads text from system clipboard using platform utilities."""
        try:
            if sys.platform == "win32":
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                )
                if proc.returncode == 0:
                    return proc.stdout.strip()
            elif sys.platform == "darwin":
                proc = subprocess.run(["pbpaste"], capture_output=True, text=True, timeout=2.0)
                if proc.returncode == 0:
                    return proc.stdout.strip()
            else:
                proc = subprocess.run(["xclip", "-selection", "clipboard", "-o"], capture_output=True, text=True, timeout=2.0)
                if proc.returncode == 0:
                    return proc.stdout.strip()
        except Exception as e:
            logger.debug(f"Failed to read clipboard: {e}")
        return None

    @classmethod
    def set_clipboard_text(cls, text: str) -> bool:
        """Writes text to system clipboard using platform utilities."""
        try:
            if sys.platform == "win32":
                proc = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", "$input | Set-Clipboard"],
                    input=text,
                    text=True,
                    timeout=2.0,
                )
                return proc.returncode == 0
            elif sys.platform == "darwin":
                proc = subprocess.run(["pbcopy"], input=text, text=True, timeout=2.0)
                return proc.returncode == 0
            else:
                proc = subprocess.run(["xclip", "-selection", "clipboard"], input=text, text=True, timeout=2.0)
                return proc.returncode == 0
        except Exception as e:
            logger.debug(f"Failed to write clipboard: {e}")
            return False


class OfficeKitTransfer:
    """Handles file exports and clipboard sync for agent receipts and diffs."""

    def __init__(self, export_dir: Path = Path(".leash/office_kit")):
        self.export_dir = Path(export_dir)
        self.export_dir.mkdir(parents=True, exist_ok=True)

    def export_receipt(self, session_id: str, receipt_markdown: str) -> Path:
        """Exports receipt to Office Kit drop folder for device sync."""
        target_path = self.export_dir / f"receipt_{session_id}.md"
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(receipt_markdown)
        logger.info(f"Exported receipt to Office Kit folder: {target_path}")
        return target_path

    def export_diff(self, session_id: str, diff_text: str) -> Path:
        """Exports diff patch to Office Kit drop folder."""
        target_path = self.export_dir / f"diff_{session_id}.patch"
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(diff_text)
        logger.info(f"Exported diff to Office Kit folder: {target_path}")
        return target_path

    def sync_diff_to_clipboard(self, diff_text: str) -> bool:
        """Copies active session diff to system clipboard."""
        return OfficeKitClipboard.set_clipboard_text(diff_text)

    def sync_receipt_to_clipboard(self, receipt_text: str) -> bool:
        """Copies active session receipt to system clipboard."""
        return OfficeKitClipboard.set_clipboard_text(receipt_text)
