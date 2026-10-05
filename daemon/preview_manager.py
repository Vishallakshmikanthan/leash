"""
daemon/preview_manager.py - Preview-before-approval engine for downloaded scripts (F3).
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import urllib.request
import urllib.error
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("leash.preview")


@dataclass
class ScriptPreview:
    target: str
    is_remote: bool
    total_lines: int
    head_snippet: str
    rule_ids: List[str] = field(default_factory=list)
    risks_detected: List[str] = field(default_factory=list)
    summary: str = ""
    why: str = ""
    safer_alternative: str = ""
    preview_truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScriptPreviewManager:
    """Safely previews and inspects scripts before user approval (F3)."""

    MAX_PREVIEW_LINES = 50
    MAX_FETCH_BYTES = 256 * 1024  # 256KB cap to prevent buffer flooding
    FETCH_TIMEOUT_SECONDS = 5.0

    DANGEROUS_PATTERNS = [
        (re.compile(r'\b(rm\s+-rf|del\s+/s)\b', re.IGNORECASE), "R-PREV-DESTRUCTIVE", "Destructive recursive delete operation found inside script."),
        (re.compile(r'(\.env|id_rsa|credentials|\.ssh|\.aws)', re.IGNORECASE), "R-PREV-SECRET-REF", "References credentials or sensitive secret files inside script."),
        (re.compile(r'\b(curl|wget|nc|netcat)\b.*\|.*(sh|bash|python)', re.IGNORECASE), "R-PREV-NESTED-EXEC", "Nested script execution piping remote network payload into shell."),
        (re.compile(r'\b(chmod\s+777|chmod\s+\+x)\b', re.IGNORECASE), "R-PREV-CHMOD", "Permission escalation / broad executable permission changes."),
        (re.compile(r'\b(sudo|doas|runas)\b', re.IGNORECASE), "R-PREV-SUDO", "Privilege elevation request."),
        (re.compile(r'\b(export|set)\s+[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)=', re.IGNORECASE), "R-PREV-SECRET-LEAK", "Script sets or touches authentication tokens."),
        (re.compile(r'(base64\s+-d|base64\s+--decode|openssl\s+enc|xxd)', re.IGNORECASE), "R-PREV-OBFUSCATION", "Potential obfuscation decoder command found."),
    ]

    @classmethod
    def extract_script_target(cls, command_or_target: str) -> Optional[str]:
        """Extracts a script URL or local script path from a shell command or raw target."""
        if not command_or_target:
            return None

        # Direct URL or file
        cleaned = command_or_target.strip().strip("\"'")
        if cleaned.startswith("http://") or cleaned.startswith("https://") or cleaned.endswith(".sh") or cleaned.endswith(".py"):
            return cleaned

        # Regex search for URLs
        url_match = re.search(r'https?://[^\s|;\'"]+', command_or_target)
        if url_match:
            return url_match.group(0)

        # Inspect command tokens for script arguments (e.g. bash myscript.sh or python setup.py)
        try:
            tokens = shlex.split(command_or_target, posix=False)
            for tok in tokens:
                clean_tok = tok.strip("\"'")
                if any(clean_tok.endswith(ext) for ext in (".sh", ".py", ".bash", ".ps1", ".bat", ".cmd")):
                    return clean_tok
        except Exception:
            pass

        return None

    @classmethod
    def validate_target_url(cls, url: str) -> Optional[str]:
        """Validates that a URL does not target private or loopback addresses (M6.4)."""
        import ipaddress
        import socket
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return "Invalid URL: missing hostname"

        if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
            return "Access blocked: target is loopback address (refused)"

        try:
            addrinfo = socket.getaddrinfo(hostname, None)
            for family, _, _, _, sockaddr in addrinfo:
                ip_str = sockaddr[0]
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return f"Access blocked: resolved IP {ip_str} is a private/loopback/internal address (refused)"
        except Exception as e:
            return f"DNS resolution failed: {e}"
        return None

    @classmethod
    def fetch_or_read_content(
        cls, target: str, base_dir: Optional[str] = None
    ) -> tuple[Optional[str], bool, Optional[str]]:
        """Reads local file or downloads remote script content safely with timeout, byte cap, and SSRF checks."""
        import urllib.parse
        is_remote = target.startswith("http://") or target.startswith("https://")

        if is_remote:
            validation_error = cls.validate_target_url(target)
            if validation_error:
                return None, True, validation_error

            current_url = target
            redirect_count = 0
            max_redirects = 3

            class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    nonlocal redirect_count, current_url
                    redirect_count += 1
                    if redirect_count > max_redirects:
                        raise urllib.error.HTTPError(req.full_url, code, "Exceeded maximum redirect limit (3)", headers, fp)
                    err = ScriptPreviewManager.validate_target_url(newurl)
                    if err:
                        raise urllib.error.HTTPError(newurl, code, f"Redirect target refused: {err}", headers, fp)
                    current_url = newurl
                    return super().redirect_request(req, fp, code, msg, headers, newurl)

            try:
                opener = urllib.request.build_opener(SafeRedirectHandler)
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "Leash-Script-Preview/1.0"}
                )
                with opener.open(req, timeout=cls.FETCH_TIMEOUT_SECONDS) as resp:
                    raw_bytes = resp.read(cls.MAX_FETCH_BYTES)
                    text = raw_bytes.decode("utf-8", errors="replace")
                    return text, True, None
            except Exception as e:
                logger.warning(f"Failed to fetch script preview from {target}: {e}")
                return None, True, str(e)
        else:
            # Local file
            path = Path(target)
            if not path.is_absolute() and base_dir:
                path = Path(base_dir) / target

            if not path.exists():
                return None, False, f"File not found: {target}"
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read(cls.MAX_FETCH_BYTES)
                    return text, False, None
            except Exception as e:
                return None, False, str(e)

    @classmethod
    def generate_preview(
        cls, command_or_target: str, base_dir: Optional[str] = None
    ) -> ScriptPreview:
        """Generates a structured ScriptPreview containing snippet, risk analysis, and summary."""
        target = cls.extract_script_target(command_or_target) or command_or_target
        content, is_remote, error = cls.fetch_or_read_content(target, base_dir=base_dir)

        if error or content is None:
            return ScriptPreview(
                target=target,
                is_remote=is_remote,
                total_lines=0,
                head_snippet=f"[Script preview unavailable: {error or 'Unable to load content'}]",
                rule_ids=["R-PREV-UNAVAILABLE"],
                risks_detected=[f"Script content could not be retrieved: {error}"],
                summary="Could not download or read script for preview.",
                why="The target URL or file could not be fetched safely.",
                safer_alternative="Do not execute remote script without inspecting its source in a browser or editor first.",
            )

        lines = content.splitlines()
        total_lines = len(lines)
        head_lines = lines[:cls.MAX_PREVIEW_LINES]
        head_snippet = "\n".join(head_lines)
        truncated = total_lines > cls.MAX_PREVIEW_LINES

        # Analyze dangerous commands inside script
        rule_ids: List[str] = []
        risks_detected: List[str] = []

        for pattern, rule_id, desc in cls.DANGEROUS_PATTERNS:
            if pattern.search(content):
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)
                    risks_detected.append(desc)

        # Summary and why
        if risks_detected:
            summary = f"Script preview reveals {len(risks_detected)} potential security risk(s)."
            why = " ".join(risks_detected[:2])
            safer_alternative = "Audit the script contents thoroughly or run only inside a disposable container."
        else:
            summary = f"Script inspected cleanly ({total_lines} lines). No obvious destructive patterns found."
            why = "No raw deletes, nested curl executions, or credential exfiltration detected in preview head."
            safer_alternative = "Verify standard expected operations before approving."

        return ScriptPreview(
            target=target,
            is_remote=is_remote,
            total_lines=total_lines,
            head_snippet=head_snippet,
            rule_ids=rule_ids,
            risks_detected=risks_detected,
            summary=summary,
            why=why,
            safer_alternative=safer_alternative,
            preview_truncated=truncated,
        )
