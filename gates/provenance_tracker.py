"""
gates/provenance_tracker.py - Provenance tracking, untrusted source detection, and taint management (F1).
"""
from __future__ import annotations

import fnmatch
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from contracts.models import (
    ActionKind,
    ActionRequest,
    ProvenanceEvent,
    ProvenanceKind,
    Severity,
    TaintContext,
)
from daemon.shell_parser import DOWNLOAD_TOOLS, ShellParser
from gates.base import BaseGate, GateResult
from gates.hidden_text import HiddenTextGate


class ProvenanceTracker:
    """Tracks ingestion of untrusted content and propagates session taint context."""

    DEFAULT_UNTRUSTED_PATTERNS: Set[str] = {
        "readme",
        "readme.*",
        "*.md",
        "issue*",
        "issue*.txt",
        "issue*.md",
        "issue_template*",
        "bug_report*",
        "feature_request*",
        "ticket*",
        "prompt*",
        "prompt*.txt",
        "prompt*.md",
        "untrusted*",
    }

    DEFAULT_UNTRUSTED_EXTENSIONS: Set[str] = {
        ".html",
        ".htm",
        ".rss",
        ".atom",
        ".url",
        ".webloc",
    }

    DEFAULT_UNTRUSTED_DIRS: Set[str] = {
        "downloads",
        "web_cache",
        "cache",
        "fetched",
        "tmp/web",
        "docs",
        "issues",
    }

    INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE), "prompt-injection"),
        (re.compile(r"system\s+prompt", re.IGNORECASE), "prompt-injection"),
        (re.compile(r"(?:run|execute|launch)\s+the\s+following(?:\s+command)?", re.IGNORECASE), "shell-instructions"),
        (re.compile(r"curl\s+.*\|\s*(?:ba|z)?sh", re.IGNORECASE), "remote-pipe-shell"),
        (re.compile(r"wget\s+.*\|\s*(?:ba|z)?sh", re.IGNORECASE), "remote-pipe-shell"),
        (re.compile(r"rm\s+-rf\s+[/~]", re.IGNORECASE), "destructive-command"),
        (re.compile(r"eval\s*\(", re.IGNORECASE), "eval-execution"),
        (re.compile(r"(?:bash|sh)\s+-c", re.IGNORECASE), "subshell-execution"),
        (re.compile(r"cat\s+.*\.env", re.IGNORECASE), "secret-exposure"),
        (re.compile(r"curl\s+-(?:d|F|X\s*POST).*http", re.IGNORECASE), "data-exfil"),
    ]

    FILE_READ_TOOLS: Set[str] = {
        "cat",
        "head",
        "tail",
        "more",
        "less",
        "bat",
        "grep",
        "awk",
        "sed",
        "type",
        "get-content",
        "gc",
        "open",
    }

    TOOL_CALL_READ_NAMES: Set[str] = {
        "read_file",
        "view_file",
        "cat_file",
        "get_file_contents",
        "open_file",
        "read_url",
        "fetch_web",
        "fetch_url",
        "read_issue",
        "get_issue",
    }

    def __init__(
        self,
        untrusted_patterns: Optional[Set[str]] = None,
        untrusted_extensions: Optional[Set[str]] = None,
        untrusted_dirs: Optional[Set[str]] = None,
    ):
        self.untrusted_patterns: Set[str] = (
            set(untrusted_patterns) if untrusted_patterns is not None else set(self.DEFAULT_UNTRUSTED_PATTERNS)
        )
        self.untrusted_extensions: Set[str] = (
            set(untrusted_extensions) if untrusted_extensions is not None else set(self.DEFAULT_UNTRUSTED_EXTENSIONS)
        )
        self.untrusted_dirs: Set[str] = (
            set(untrusted_dirs) if untrusted_dirs is not None else set(self.DEFAULT_UNTRUSTED_DIRS)
        )
        self.custom_sources: Set[str] = set()
        self._hidden_scanner = HiddenTextGate()

    def add_untrusted_source(self, source_or_pattern: str) -> None:
        """Configures an additional untrusted source pattern or path."""
        self.custom_sources.add(source_or_pattern.strip())

    def remove_untrusted_source(self, source_or_pattern: str) -> None:
        """Removes a configured untrusted source."""
        self.custom_sources.discard(source_or_pattern.strip())
        self.untrusted_patterns.discard(source_or_pattern.strip())

    def configure_untrusted_sources(self, sources: List[str]) -> None:
        """Replaces custom configured untrusted sources."""
        self.custom_sources = {s.strip() for s in sources if s.strip()}

    def is_untrusted_source(self, path_or_url: str) -> bool:
        """Determines if a given path, filename, or URL represents an untrusted source."""
        if not path_or_url:
            return False

        clean = path_or_url.strip()
        lower = clean.lower()

        # 1. Web URLs
        if any(lower.startswith(pfx) for pfx in ("http://", "https://", "ftp://")):
            return True

        # 2. Custom explicit sources
        for custom in self.custom_sources:
            if clean == custom or lower == custom.lower():
                return True
            if fnmatch.fnmatch(lower, custom.lower()):
                return True

        # 3. Path parsing
        norm_path = clean.replace("\\", "/")
        filename = norm_path.split("/")[-1].lower()

        # Check README filename directly
        if filename.startswith("readme"):
            return True

        # Check filename patterns
        for pattern in self.untrusted_patterns:
            if fnmatch.fnmatch(filename, pattern.lower()):
                return True

        # Check file extension
        _, ext = os.path.splitext(filename)
        if ext.lower() in self.untrusted_extensions:
            return True

        # Check directory membership (e.g. downloads/, web_cache/)
        parts = [p.lower() for p in norm_path.split("/")]
        for udir in self.untrusted_dirs:
            udir_norm = udir.replace("\\", "/").lower()
            if udir_norm in parts or norm_path.lower().startswith(udir_norm + "/"):
                return True

        return False

    def scan_content_for_injection(self, content: str) -> Tuple[int, Optional[str], List[str]]:
        """Scans content lines for prompt injection, hidden text, and executable command payloads.
        
        Returns:
            Tuple of (line_number, snippet, flags)
        """
        if not content:
            return (1, None, ["untrusted-doc"])

        lines = content.splitlines()
        detected_line: Optional[int] = None
        detected_snippet: Optional[str] = None
        flags: List[str] = []

        # 1. Comprehensive Hidden Text Scanner scan across full content
        hidden_findings = self._hidden_scanner.scan_text(content, file_path="content")
        for hf in hidden_findings:
            if "hidden-text" not in flags:
                flags.append("hidden-text")
            if hf.pattern_type == "bidi_control" and "bidi-override" not in flags:
                flags.append("bidi-override")
            elif hf.pattern_type == "unicode_tags" and "tag-steganography" not in flags:
                flags.append("tag-steganography")
            elif hf.pattern_type == "concealed_instruction" and "concealed-instruction" not in flags:
                flags.append("concealed-instruction")
            elif hf.pattern_type == "hidden_comment" and "hidden-comment" not in flags:
                flags.append("hidden-comment")

            if detected_line is None:
                detected_line = hf.line
                detected_snippet = hf.snippet[:120]

        in_code_block = False

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue

            # Track markdown code fence
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                continue

            # 2. Known injection / malicious command patterns
            for pattern, flag in self.INJECTION_PATTERNS:
                if pattern.search(line):
                    if flag not in flags:
                        flags.append(flag)
                    if detected_line is None:
                        detected_line = idx
                        detected_snippet = stripped[:120]

            # 3. Executable commands inside code blocks
            if in_code_block and (stripped.startswith("curl ") or stripped.startswith("sh ") or stripped.startswith("bash ")):
                if "codeblock-command" not in flags:
                    flags.append("codeblock-command")
                if detected_line is None:
                    detected_line = idx
                    detected_snippet = stripped[:120]

        if detected_line is not None:
            if not flags:
                flags.append("untrusted-doc")
            return (detected_line, detected_snippet, flags)

        # Fallback to line 1 or first non-empty line
        for idx, line in enumerate(lines, start=1):
            if line.strip():
                return (idx, line.strip()[:120], ["untrusted-doc"])

        return (1, None, ["untrusted-doc"])

    def analyze_read(
        self,
        source_path_or_url: str,
        content: Optional[str] = None,
        base_dir: Optional[str] = None,
        line_hint: Optional[int] = None,
        candidate_dirs: Optional[List[str]] = None,
    ) -> Tuple[int, Optional[str], List[str]]:
        """Analyzes an untrusted read target, determining line number, snippet, and risk flags."""
        if line_hint is not None and line_hint > 0:
            return (line_hint, f"Read at line {line_hint}", ["untrusted-doc"])

        # If content provided directly
        if content is not None:
            return self.scan_content_for_injection(content)

        # Web URLs
        if any(source_path_or_url.lower().startswith(pfx) for pfx in ("http://", "https://", "ftp://")):
            return (1, f"Remote web content from {source_path_or_url}", ["web-derived", "untrusted-doc"])

        # Try reading file from disk
        candidate_paths = []
        if os.path.isabs(source_path_or_url):
            candidate_paths.append(Path(source_path_or_url))
        else:
            dirs = []
            if base_dir:
                dirs.append(base_dir)
            if candidate_dirs:
                dirs.extend(candidate_dirs)
            for d in dirs:
                if d:
                    candidate_paths.append(Path(d) / source_path_or_url)
            candidate_paths.append(Path(source_path_or_url))

        for p in candidate_paths:
            try:
                if p.is_file():
                    text = p.read_text(encoding="utf-8", errors="replace")
                    return self.scan_content_for_injection(text)
            except Exception:
                pass

        return (1, None, ["untrusted-doc"])

    def detect_untrusted_read(
        self,
        request: ActionRequest,
        base_dir: Optional[str] = None,
        candidate_dirs: Optional[List[str]] = None,
    ) -> Optional[Tuple[str, int, List[str], Optional[str]]]:
        """Inspects an ActionRequest to determine if it reads from an untrusted source.
        
        Returns:
            Tuple of (source, line, flags, snippet) if untrusted read detected, else None.
        """
        all_dirs = [d for d in [base_dir, request.cwd, request.worktree] if d]
        if candidate_dirs:
            all_dirs.extend([d for d in candidate_dirs if d])

        # 1. FILE_READ
        if request.kind == ActionKind.FILE_READ and request.target_path:
            if self.is_untrusted_source(request.target_path):
                line, snippet, flags = self.analyze_read(
                    request.target_path,
                    base_dir=base_dir or request.cwd or request.worktree,
                    line_hint=request.taint.line if request.taint else None,
                    candidate_dirs=all_dirs,
                )
                filename = os.path.basename(request.target_path.replace("\\", "/")) or request.target_path
                return (filename, line, flags, snippet)


        # 2. TOOL_CALL
        if request.kind == ActionKind.TOOL_CALL and request.tool_name:
            t_name = request.tool_name.lower()
            if any(t_name == read_tool or t_name.endswith(f"_{read_tool}") for read_tool in self.TOOL_CALL_READ_NAMES):
                args = request.tool_args or {}
                target = (
                    args.get("file_path")
                    or args.get("path")
                    or args.get("AbsolutePath")
                    or args.get("target_path")
                    or args.get("url")
                    or args.get("source")
                )
                if target and isinstance(target, str) and self.is_untrusted_source(target):
                    line_hint = (
                        args.get("line")
                        or args.get("start_line")
                        or args.get("StartLine")
                        or args.get("line_number")
                    )
                    try:
                        line_hint_int = int(line_hint) if line_hint is not None else None
                    except (ValueError, TypeError):
                        line_hint_int = None

                    line, snippet, flags = self.analyze_read(
                        target,
                        base_dir=base_dir or request.cwd or request.worktree,
                        line_hint=line_hint_int,
                        candidate_dirs=all_dirs,
                    )
                    filename = os.path.basename(target.replace("\\", "/")) or target
                    return (filename, line, flags, snippet)

        # 3. SHELL (e.g. cat README.md, head issue.txt, curl http://...)
        if request.kind == ActionKind.SHELL and request.command:
            parsed = ShellParser.parse(request.command)
            for pipe in parsed.pipelines:
                for stage in pipe.stages:
                    exe = stage.canonical_executable.lower()

                    # Shell file reader tools
                    if exe in self.FILE_READ_TOOLS:
                        for arg in stage.args:
                            if not arg.startswith("-") and self.is_untrusted_source(arg):
                                line, snippet, flags = self.analyze_read(
                                    arg,
                                    base_dir=base_dir or request.cwd or request.worktree,
                                    candidate_dirs=all_dirs,
                                )
                                filename = os.path.basename(arg.replace("\\", "/")) or arg
                                return (filename, line, flags, snippet)


                    # Web download tools
                    if exe in DOWNLOAD_TOOLS:
                        for arg in stage.args:
                            if any(arg.lower().startswith(pfx) for pfx in ("http://", "https://", "ftp://")):
                                flags = ["web-derived", "untrusted-doc"]
                                return (arg, 1, flags, f"Web download via {exe}: {arg}")

                    # GitHub CLI issue/pr/comment reads
                    if exe == "gh" and any(sub in stage.args for sub in ("issue", "pr", "api")):
                        cmd_desc = f"gh {' '.join(stage.args)}"
                        return (cmd_desc, 1, ["gh-derived", "untrusted-doc"], f"GitHub API read via {cmd_desc}")

        return None

    def create_provenance_event(
        self,
        session_id: str,
        source: str,
        line: Optional[int] = None,
        flags: Optional[List[str]] = None,
        snippet: Optional[str] = None,
        kind: Optional[ProvenanceKind] = None,
    ) -> ProvenanceEvent:
        """Constructs a signed or ready-to-sign ProvenanceEvent."""
        fl = flags or ["untrusted-doc"]
        if kind is None:
            if "hidden-text" in fl or "bidi-override" in fl or "tag-steganography" in fl or "concealed-instruction" in fl:
                kind = ProvenanceKind.HIDDEN_TEXT_DETECTED
            else:
                kind = ProvenanceKind.UNTRUSTED_READ
        return ProvenanceEvent(
            id=f"p_{uuid.uuid4().hex[:12]}",
            session=session_id,
            ts=int(time.time()),
            kind=kind,
            source=source,
            line=line or 1,
            flags=fl,
            snippet=snippet,
        )


class ProvenanceTrackerGate(BaseGate):
    """Modular security gate detecting actions influenced by untrusted text (F1)."""

    def __init__(self, tracker: Optional[ProvenanceTracker] = None):
        self.tracker = tracker or ProvenanceTracker()

    @property
    def name(self) -> str:
        return "ProvenanceTrackerGate"

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        # 1. Action executed in an already tainted session
        if request.taint and request.taint.tainted:
            src = request.taint.source or "untrusted content"
            ln = f":{request.taint.line}" if request.taint.line else ""
            return GateResult(
                triggered=True,
                rule_id="R-TAINT-INFLUENCE",
                category="untrusted-text-influence",
                severity=Severity.HIGH,
                summary=f"[TAINTED] Action influenced by untrusted source: {src}",
                why=(
                    f"Action executed after agent read untrusted content at {src}{ln}. "
                    "Untrusted text instructions can manipulate shell actions via prompt injection."
                ),
                safer_alternative="Inspect originating text and verify action necessity before approving.",
            )

        # 2. Check if current action itself reads an untrusted source
        detected = self.tracker.detect_untrusted_read(request)
        if detected:
            source, line, flags, snippet = detected
            return GateResult(
                triggered=True,
                rule_id="R-UNTRUSTED-READ",
                category="untrusted-text-influence",
                severity=Severity.MEDIUM,
                summary=f"Reading untrusted content from {source} (line {line}).",
                why=f"Reading {source} will mark the session as tainted ({', '.join(flags)}).",
                safer_alternative="Ensure untrusted documents do not contain hidden prompt instructions.",
            )

        return None
