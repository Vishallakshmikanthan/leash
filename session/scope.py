"""
session/scope.py - Task scope contract enforcement and drift detection (N3, F2).
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from contracts.models import ActionRequest


class IntentDriftDetector:
    """Detects whether an agent action drifts from the declared session task intent (F2)."""

    STOPWORDS = {
        "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "with", "by", "of", "from",
        "this", "that", "is", "are", "be", "as", "into", "it", "its", "run", "do", "make", "work"
    }

    RISKY_UNINTENDED_KEYWORDS = {
        "curl", "wget", "nc", "netcat", "eval", "exec", "rm", "delete", "drop", "wipe",
        "format", "token", "password", "secret", "private", "id_rsa", "canary", "miner"
    }

    @classmethod
    def extract_keywords(cls, text: str) -> Set[str]:
        words = re.findall(r'[a-zA-Z0-9_\-\./]+', text.lower())
        return {w for w in words if len(w) >= 2 and w not in cls.STOPWORDS}

    @classmethod
    def evaluate_drift(
        cls, request: ActionRequest, task_description: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """Evaluates whether an ActionRequest appears drifted from the declared task."""
        if not task_description or not task_description.strip():
            return None

        task_clean = task_description.strip().lower()
        task_keywords = cls.extract_keywords(task_clean)
        if not task_keywords:
            return None

        action_text = f"{request.command or ''} {request.target_path or ''} {request.tool_name or ''}".lower()
        action_keywords = cls.extract_keywords(action_text)

        # 1. Look for explicit risky drift (e.g. task says "fix typo in docs", action downloads remote shell or touches secrets)
        maintenance_stems = ("test", "doc", "readme", "lint", "format", "typo", "css", "style")
        is_maintenance_task = any(
            any(k.startswith(stem) for stem in maintenance_stems)
            for k in task_keywords
        )
        has_risky_divergence = any(k in action_keywords for k in cls.RISKY_UNINTENDED_KEYWORDS)

        if is_maintenance_task and has_risky_divergence:
            return {
                "drift": True,
                "reason": f"Action performs sensitive/network operation ('{request.command or request.target_path}') inconsistent with maintenance task '{task_description}'",
                "task_description": task_description,
                "confidence": 0.85,
            }

        # 2. Check for target file path mismatch if specific files or extensions were mentioned in task
        explicit_extensions = {ext for ext in [".py", ".kt", ".js", ".ts", ".html", ".css", ".md", ".json"] if ext in task_clean}
        if explicit_extensions and request.target_path:
            target_ext = os.path.splitext(request.target_path)[1].lower()
            if target_ext and target_ext not in explicit_extensions and not any(k in action_keywords for k in task_keywords):
                return {
                    "drift": True,
                    "reason": f"Target path '{request.target_path}' differs in domain from task context '{task_description}'",
                    "task_description": task_description,
                    "confidence": 0.70,
                }

        # 3. Keyword overlap check for substantial actions
        if len(action_keywords) >= 3:
            overlap = task_keywords.intersection(action_keywords)
            if not overlap and any(op in action_text for op in ("--force", "clean", "reset", "curl", "chmod", "kill")):
                return {
                    "drift": True,
                    "reason": f"Destructive command has zero overlap with declared task goals '{task_description}'",
                    "task_description": task_description,
                    "confidence": 0.75,
                }

        return None


class ScopeContract:
    """Validates that actions stay within agreed path, command, and host boundaries.
    
    Detects actions that drift outside the declared task scope and raises scope flags.
    """

    SENSITIVE_WATCHLIST = [
        ".github/workflows",
        ".gitlab-ci.yml",
        ".circleci",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "requirements.txt",
        ".env",
        ".bashrc",
        ".zshrc",
        ".profile",
    ]

    NETWORK_COMMANDS = {"curl", "wget", "nc", "netcat", "ssh", "scp", "telnet", "ping", "ftp"}

    def __init__(
        self,
        allowed_paths: Optional[List[str]] = None,
        allowed_commands: Optional[List[str]] = None,
        allowed_hosts: Optional[List[str]] = None,
        watchlist: Optional[List[str]] = None,
    ):
        raw_paths = allowed_paths or ["."]
        self.allowed_paths: List[str] = [
            os.path.normcase(os.path.abspath(os.path.expanduser(p))) for p in raw_paths
        ]
        self.allowed_commands: List[str] = [cmd.strip() for cmd in (allowed_commands or []) if cmd.strip()]
        self.allowed_hosts: Set[str] = {
            h.lower().strip() for h in (allowed_hosts or ["localhost", "127.0.0.1"]) if h.strip()
        }
        self.watchlist = watchlist or self.SENSITIVE_WATCHLIST

    def _is_path_allowed(self, path_str: str, base_dir: Optional[str] = None) -> bool:
        """Determines if a normalized path is inside any of the allowed paths."""
        try:
            if not os.path.isabs(path_str):
                base = base_dir if base_dir else os.getcwd()
                abs_p = os.path.normcase(os.path.abspath(os.path.join(base, path_str)))
            else:
                abs_p = os.path.normcase(os.path.abspath(os.path.expanduser(path_str)))

            for allowed in self.allowed_paths:
                # Check exact match or subpath
                if abs_p == allowed or abs_p.startswith(allowed.rstrip(os.sep) + os.sep):
                    return True
            return False
        except Exception:
            return False

    def _extract_hosts_from_command(self, cmd_str: str) -> List[str]:
        """Extracts hostnames or domains targeted in command strings."""
        hosts: List[str] = []

        url_matches = re.findall(r'(?:https?|ftp|ssh|git)://([^/\s\'":]+)', cmd_str, re.IGNORECASE)
        for u in url_matches:
            hosts.append(u.lower())

        try:
            tokens = shlex.split(cmd_str, posix=False)
            for idx, token in enumerate(tokens):
                clean_tok = token.strip("\"'")
                if "@" in clean_tok and not clean_tok.startswith("-"):
                    parts = clean_tok.split("@", 1)
                    if parts[1] and "." in parts[1]:
                        hosts.append(parts[1].lower())
                elif any(clean_tok.startswith(pfx) for pfx in ("http://", "https://", "ftp://")):
                    parsed = urlparse(clean_tok)
                    if parsed.hostname:
                        hosts.append(parsed.hostname.lower())
        except Exception:
            pass

        return list(set(hosts))

    def _extract_executables(self, cmd_str: str) -> List[str]:
        """Extracts all command executables from chained pipelines or operators."""
        segments = re.split(r'\s*(?:&&|\|\||;|\|)\s*', cmd_str)
        executables: List[str] = []

        for seg in segments:
            seg = seg.strip()
            if not seg:
                continue
            try:
                tokens = shlex.split(seg, posix=False)
                if tokens:
                    exe = tokens[0].strip("\"'").replace("\\", "/")
                    base_exe = os.path.basename(exe)
                    executables.append(base_exe.lower())
            except Exception:
                first = seg.split()[0].replace("\\", "/")
                executables.append(os.path.basename(first).lower())

        return executables

    def _extract_path_arguments(self, cmd_str: str) -> List[str]:
        """Identifies arguments that look like filesystem paths."""
        paths: List[str] = []
        try:
            tokens = shlex.split(cmd_str, posix=False)
            for tok in tokens[1:]:
                clean = tok.strip("\"'")
                if clean.startswith("-") or clean.startswith("/"):
                    if len(clean) > 2 and clean[1] == ":" or clean.startswith("//") or clean.startswith("/"):
                        paths.append(clean)
                elif any(sep in clean for sep in ("/", "\\")) or "." in clean:
                    paths.append(clean)
        except Exception:
            pass
        return paths

    def validate_action(
        self, request: ActionRequest, task_description: Optional[str] = None
    ) -> List[str]:
        """Inspects an ActionRequest and returns drift flags if outside scope."""
        flags: List[str] = []

        # 1. Path Scope & Traversal Check
        paths_to_verify: List[str] = []
        if request.target_path:
            paths_to_verify.append(request.target_path)

        if request.command:
            extracted_paths = self._extract_path_arguments(request.command)
            paths_to_verify.extend(extracted_paths)

        base_dir = request.cwd if request.cwd and request.cwd != "." else None

        for p in paths_to_verify:
            if ".." in p:
                norm = os.path.normpath(p)
                if norm.startswith("..") or ".." in norm.split(os.sep):
                    if "path-traversal-detected" not in flags:
                        flags.append("path-traversal-detected")

            if not self._is_path_allowed(p, base_dir=base_dir):
                if "outside-allowed-paths" not in flags:
                    flags.append("outside-allowed-paths")

            p_clean = p.replace("\\", "/").lower()
            for item in self.watchlist:
                item_clean = item.lower()
                if item_clean in p_clean or p_clean.endswith(item_clean):
                    if "sensitive-watchlist-hit" not in flags:
                        flags.append("sensitive-watchlist-hit")
                    break

        # 2. Command Scope Check
        if request.command and self.allowed_commands:
            allowed_set = {c.lower() for c in self.allowed_commands}
            executables = self._extract_executables(request.command)
            for exe in executables:
                base_name = exe.rsplit(".", 1)[0] if "." in exe else exe
                if exe not in allowed_set and base_name not in allowed_set:
                    if "outside-allowed-commands" not in flags:
                        flags.append("outside-allowed-commands")
                    break

        # 3. Host Scope Check
        if request.command:
            targeted_hosts = self._extract_hosts_from_command(request.command)
            for host in targeted_hosts:
                if host not in self.allowed_hosts:
                    if "outside-allowed-hosts" not in flags:
                        flags.append("outside-allowed-hosts")
                    break

        # 4. Intent Drift Check (F2)
        if task_description:
            drift_res = IntentDriftDetector.evaluate_drift(request, task_description)
            if drift_res and drift_res.get("drift"):
                if "intent-drift-suspected" not in flags:
                    flags.append("intent-drift-suspected")

        return flags

    def check_drift(
        self, request: ActionRequest, task_description: Optional[str] = None
    ) -> Dict[str, Any]:
        """Provides detailed structured report on scope drift."""
        flags = self.validate_action(request, task_description=task_description)
        intent_info = (
            IntentDriftDetector.evaluate_drift(request, task_description)
            if task_description
            else None
        )
        return {
            "in_scope": len(flags) == 0,
            "drift_detected": len(flags) > 0,
            "flags": flags,
            "intent_drift": intent_info,
            "allowed_paths": self.allowed_paths,
            "allowed_commands": self.allowed_commands,
            "allowed_hosts": list(self.allowed_hosts),
        }

    def is_in_scope(
        self, request: ActionRequest, task_description: Optional[str] = None
    ) -> bool:
        """Convenience boolean check for clean scope compliance."""
        return len(self.validate_action(request, task_description=task_description)) == 0
