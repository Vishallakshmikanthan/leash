"""
gates/hidden_text.py - Hidden-Text Scanner (N7): detects invisible Unicode, bidirectional control
characters, hidden comments, and concealed instructions in accessed or modified files.
"""
from __future__ import annotations

import base64
import os
import re
import subprocess
import unicodedata
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


# -----------------------------------------------------------------------------
# 1. Finding Data Model
# -----------------------------------------------------------------------------

@dataclass
class HiddenTextFinding:
    """Structured report of a concealed text, invisible Unicode, or hidden instruction anomaly."""
    file_path: str
    line: int
    column: int
    pattern_type: str  # e.g., "bidi_control", "zero_width", "unicode_tags", "hidden_comment", "concealed_instruction", "ansi_escape", "homoglyph"
    pattern_name: str  # e.g., "Right-to-Left Override (RLO U+202E)", "Concealed HTML Instruction Comment"
    codepoint_hex: Optional[str]
    snippet: str
    risk_reason: str
    severity: Severity = Severity.MEDIUM

    def location_str(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        res["location"] = self.location_str()
        return res


# -----------------------------------------------------------------------------
# 2. Scanner Implementation
# -----------------------------------------------------------------------------

class HiddenTextScanner:
    """Core scanner detecting invisible Unicode, bidirectional controls, hidden comments, and concealed instructions."""

    # Bidirectional control characters (Trojan Source - CVE-2021-42574)
    BIDI_CONTROL_CODEPOINTS: Dict[int, Tuple[str, str]] = {
        0x202A: ("LRE", "Left-to-Right Embedding"),
        0x202B: ("RLE", "Right-to-Left Embedding"),
        0x202C: ("PDF", "Pop Directional Formatting"),
        0x202D: ("LRO", "Left-to-Right Override"),
        0x202E: ("RLO", "Right-to-Left Override"),
        0x2066: ("LRI", "Left-to-Right Isolate"),
        0x2067: ("RLI", "Right-to-Left Isolate"),
        0x2068: ("FSI", "First Strong Isolate"),
        0x2069: ("PDI", "Pop Directional Isolate"),
        0x200E: ("LRM", "Left-to-Right Mark"),
        0x200F: ("RLM", "Right-to-Left Mark"),
        0x061C: ("ALM", "Arabic Letter Mark"),
    }

    # Zero-width spaces, joiners, invisible separators & fillers
    ZERO_WIDTH_CODEPOINTS: Dict[int, str] = {
        0x200B: "Zero-Width Space (ZWSP)",
        0x200C: "Zero-Width Non-Joiner (ZWNJ)",
        0x200D: "Zero-Width Joiner (ZWJ)",
        0xFEFF: "Zero-Width No-Break Space / BOM (ZWNBSP)",
        0x2060: "Word Joiner (WJ)",
        0x00AD: "Soft Hyphen (SHY)",
        0x034F: "Combining Grapheme Joiner (CGJ)",
        0x180E: "Mongolian Vowel Separator (MVS)",
        0x202F: "Narrow No-Break Space (NNBSP)",
        0x205F: "Medium Mathematical Space (MMSP)",
        0x115F: "Hangul Choseong Filler (Invisible)",
        0x1160: "Hangul Jungseong Filler (Invisible)",
        0x3164: "Hangul Filler (Invisible Space)",
        0xFFA0: "Halfwidth Hangul Filler (Invisible)",
        0x2061: "Function Application (Invisible)",
        0x2062: "Invisible Times",
        0x2063: "Invisible Separator",
        0x2064: "Invisible Plus",
    }

    # Tag characters (U+E0000 to U+E007F) used for ASCII steganography / invisible prompts
    TAG_CODEPOINTS_RANGE: Tuple[int, int] = (0xE0000, 0xE007F)

    # ANSI terminal escapes that conceal text or manipulate output
    ANSI_CONCEAL_RE = re.compile(r"\x1b\[(?:[0-9;]*8m|2K|1A|\?25l|\]0;[^\x07\x1b]*)")

    # Common Cyrillic confusables that mimic Latin ASCII characters
    CYRILLIC_HOMOGLYPHS: Dict[str, str] = {
        "\u0430": "a",  # Cyrillic small letter a
        "\u0441": "c",  # Cyrillic small letter es
        "\u0435": "e",  # Cyrillic small letter ie
        "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
        "\u0458": "j",  # Cyrillic small letter je
        "\u043e": "o",  # Cyrillic small letter o
        "\u0440": "p",  # Cyrillic small letter er
        "\u0455": "s",  # Cyrillic small letter dze
        "\u0445": "x",  # Cyrillic small letter ha
        "\u0443": "y",  # Cyrillic small letter u
        "\u0410": "A",  # Cyrillic capital letter A
        "\u0412": "B",  # Cyrillic capital letter Ve
        "\u0421": "C",  # Cyrillic capital letter Es
        "\u0415": "E",  # Cyrillic capital letter Ie
        "\u041d": "H",  # Cyrillic capital letter En
        "\u0406": "I",  # Cyrillic capital letter Byelorussian-Ukrainian I
        "\u0408": "J",  # Cyrillic capital letter Je
        "\u041a": "K",  # Cyrillic capital letter Ka
        "\u041c": "M",  # Cyrillic capital letter Em
        "\u041e": "O",  # Cyrillic capital letter O
        "\u0420": "P",  # Cyrillic capital letter Er
        "\u0422": "T",  # Cyrillic capital letter Te
        "\u0425": "X",  # Cyrillic capital letter Ha
        "\u0423": "Y",  # Cyrillic capital letter U
    }

    # Concealed prompt injection & instruction patterns in hidden comments
    INSTRUCTION_KEYWORDS = [
        re.compile(r"(?i)system\s+prompt\s*:"),
        re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions"),
        re.compile(r"(?i)you\s+are\s+now\s+in\s+developer\s+mode"),
        re.compile(r"(?i)assistant\s*:\s*execute"),
        re.compile(r"(?i)leash\s*:\s*(?:override|bypass|disable)"),
        re.compile(r"(?i)curl\s+.*\|\s*(?:ba|z)?sh"),
        re.compile(r"(?i)wget\s+.*\|\s*(?:ba|z)?sh"),
        re.compile(r"(?i)rm\s+-rf\s+[/~]"),
        re.compile(r"(?i)(?:cat|type)\s+.*\.env"),
        re.compile(r"(?i)base64\s+-(?:d|-decode)"),
        re.compile(r"(?i)powershell\s+-(?:enc|encodedcommand)"),
        re.compile(r"(?i)eval\s*\("),
    ]

    # Markdown hidden comment syntaxes: [//]: # (...) or [comment]: <> (...)
    MARKDOWN_COMMENT_RE = re.compile(
        r"(?:\[//\]:\s*#\s*\((.*?)\)|\[comment\]:\s*<>\s*\((.*?)\)|\[hidden\]:\s*#\s*\((.*?)\))",
        re.DOTALL,
    )

    # HTML comments: <!-- ... -->
    HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

    def scan_string(self, text: str) -> List[Tuple[int, str]]:
        """Legacy helper returning a list of (index, anomaly_description)."""
        findings = self.scan_text(text, file_path="string")
        return [(f.column - 1, f"{f.pattern_name} ({f.codepoint_hex or ''})".strip()) for f in findings]

    def scan_text(self, text: str, file_path: str = "buffer") -> List[HiddenTextFinding]:
        """Comprehensive scan of text content returning structured HiddenTextFinding items."""
        if not text:
            return []

        findings: List[HiddenTextFinding] = []
        lines = text.splitlines(keepends=True)
        running_char_offset = 0

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.rstrip("\r\n")

            # 1. BiDi, Zero-Width, Tag, and Homoglyph character inspection
            for col_no, ch in enumerate(line, start=1):
                cp = ord(ch)

                # A. Bidirectional Control Characters
                if cp in self.BIDI_CONTROL_CODEPOINTS:
                    abbr, desc = self.BIDI_CONTROL_CODEPOINTS[cp]
                    findings.append(
                        HiddenTextFinding(
                            file_path=file_path,
                            line=line_no,
                            column=col_no,
                            pattern_type="bidi_control",
                            pattern_name=f"BiDi Control {abbr} ({desc})",
                            codepoint_hex=f"U+{cp:04X}",
                            snippet=self._format_snippet(line, col_no),
                            risk_reason=(
                                "Trojan Source (CVE-2021-42574): Bidirectional override characters change visual text display "
                                "order so rendered code diverges from logical compiler or shell execution order."
                            ),
                            severity=Severity.HIGH,
                        )
                    )

                # B. Zero-Width and Invisible Characters
                elif cp in self.ZERO_WIDTH_CODEPOINTS:
                    desc = self.ZERO_WIDTH_CODEPOINTS[cp]
                    findings.append(
                        HiddenTextFinding(
                            file_path=file_path,
                            line=line_no,
                            column=col_no,
                            pattern_type="zero_width",
                            pattern_name=desc,
                            codepoint_hex=f"U+{cp:04X}",
                            snippet=self._format_snippet(line, col_no),
                            risk_reason=(
                                "Invisible zero-width Unicode characters disguise payloads, evade string filters, "
                                "or smuggle hidden instructions to AI agents."
                            ),
                            severity=Severity.MEDIUM,
                        )
                    )

                # C. Unicode Tag Characters (Steganography channel)
                elif self.TAG_CODEPOINTS_RANGE[0] <= cp <= self.TAG_CODEPOINTS_RANGE[1]:
                    # Decode tag character back to ASCII if in ASCII range (U+E0020 - U+E007E)
                    ascii_equiv = chr(cp - 0xE0000) if 0xE0020 <= cp <= 0xE007E else "?"
                    findings.append(
                        HiddenTextFinding(
                            file_path=file_path,
                            line=line_no,
                            column=col_no,
                            pattern_type="unicode_tags",
                            pattern_name=f"Unicode Tag Steganography [-> '{ascii_equiv}']",
                            codepoint_hex=f"U+{cp:04X}",
                            snippet=self._format_snippet(line, col_no),
                            risk_reason=(
                                "Unicode Tag characters encode a covert invisible ASCII channel used in indirect "
                                "prompt injection and payload smuggling."
                            ),
                            severity=Severity.HIGH,
                        )
                    )

                # D. Mixed-Script Homoglyph Confusables in Latin words
                elif ch in self.CYRILLIC_HOMOGLYPHS:
                    # Check if surrounded by ASCII alphanumeric chars (spoofing a Latin identifier or command)
                    left_char = line[col_no - 2] if col_no > 1 else ""
                    right_char = line[col_no] if col_no < len(line) else ""
                    if (left_char and left_char.isascii() and left_char.isalpha()) or (
                        right_char and right_char.isascii() and right_char.isalpha()
                    ):
                        target_latin = self.CYRILLIC_HOMOGLYPHS[ch]
                        findings.append(
                            HiddenTextFinding(
                                file_path=file_path,
                                line=line_no,
                                column=col_no,
                                pattern_type="homoglyph",
                                pattern_name=f"Mixed-Script Homoglyph (Cyrillic '{ch}' for Latin '{target_latin}')",
                                codepoint_hex=f"U+{cp:04X}",
                                snippet=self._format_snippet(line, col_no),
                                risk_reason=(
                                    f"Homoglyph substitution: Non-ASCII Cyrillic character visually imitates Latin '{target_latin}' "
                                    "to spoof trusted identifiers or command arguments."
                                ),
                                severity=Severity.MEDIUM,
                            )
                        )

            # 2. ANSI Conceal / Terminal rewrite escape sequences
            for match in self.ANSI_CONCEAL_RE.finditer(line):
                col_no = match.start() + 1
                findings.append(
                    HiddenTextFinding(
                        file_path=file_path,
                        line=line_no,
                        column=col_no,
                        pattern_type="ansi_escape",
                        pattern_name="ANSI Terminal Conceal / Output Rewrite Sequence",
                        codepoint_hex=None,
                        snippet=self._format_snippet(line, col_no),
                        risk_reason=(
                            "ANSI terminal escape sequence conceals instructions or rewrites terminal lines "
                            "to hide executed commands from developer visibility."
                        ),
                        severity=Severity.HIGH,
                    )
                )

        # 3. Carriage return without newline (\r not followed by \n)
        for m in re.finditer(r"\r(?!\n)", text):
            line_no, col_no = self._offset_to_line_col(text, m.start())
            start = max(0, m.start() - 15)
            end = min(len(text), m.start() + 20)
            snip = text[start:end].replace("\r", "[\\r]")
            findings.append(
                HiddenTextFinding(
                    file_path=file_path,
                    line=line_no,
                    column=col_no,
                    pattern_type="ansi_escape",
                    pattern_name="Carriage Return Terminal Overwrite (\\r)",
                    codepoint_hex="U+000D",
                    snippet=snip,
                    risk_reason=(
                        "Terminal line overwrite via unescaped carriage return hides preceding shell commands."
                    ),
                    severity=Severity.MEDIUM,
                )
            )

        # 4. Hidden Comment & Concealed Instruction Inspection across full text
        findings.extend(self._scan_hidden_comments(text, file_path=file_path))

        return findings

    def _scan_hidden_comments(self, text: str, file_path: str) -> List[HiddenTextFinding]:
        """Scans HTML comments, markdown hidden comments, and encoded payloads for concealed instructions."""
        findings: List[HiddenTextFinding] = []

        # A. HTML comments: <!-- ... -->
        for match in self.HTML_COMMENT_RE.finditer(text):
            comment_body = match.group(1).strip()
            if not comment_body:
                continue

            start_offset = match.start()
            line_no, col_no = self._offset_to_line_col(text, start_offset)

            # Check if comment contains prompt injection or dangerous instructions
            detected_keyword = self._find_instruction_keyword(comment_body)
            has_base64_payload = self._check_base64_payload(comment_body)

            if detected_keyword:
                findings.append(
                    HiddenTextFinding(
                        file_path=file_path,
                        line=line_no,
                        column=col_no,
                        pattern_type="concealed_instruction",
                        pattern_name=f"Concealed HTML Instruction Comment ({detected_keyword})",
                        codepoint_hex=None,
                        snippet=comment_body[:100],
                        risk_reason=(
                            f"Hidden HTML comment contains instructions ({detected_keyword}) invisible in rendered "
                            "markdown/documentation, attempting indirect prompt injection against AI coding agents."
                        ),
                        severity=Severity.HIGH,
                    )
                )
            elif has_base64_payload:
                decoded_sample, reason = has_base64_payload
                findings.append(
                    HiddenTextFinding(
                        file_path=file_path,
                        line=line_no,
                        column=col_no,
                        pattern_type="concealed_instruction",
                        pattern_name="Obfuscated Base64 Payload in Hidden Comment",
                        codepoint_hex=None,
                        snippet=f"Decoded: {decoded_sample[:80]}",
                        risk_reason=(
                            f"Hidden comment conceals base64-encoded instructions ({reason}) designed to bypass static review."
                        ),
                        severity=Severity.HIGH,
                    )
                )
            elif len(comment_body) > 250 and ("payload" in comment_body.lower() or "exec" in comment_body.lower()):
                findings.append(
                    HiddenTextFinding(
                        file_path=file_path,
                        line=line_no,
                        column=col_no,
                        pattern_type="hidden_comment",
                        pattern_name="Suspicious Oversized Hidden Comment Block",
                        codepoint_hex=None,
                        snippet=comment_body[:100],
                        risk_reason=(
                            "Suspicious oversized hidden comment block containing execution or payload terminology."
                        ),
                        severity=Severity.MEDIUM,
                    )
                )

        # B. Markdown Hidden Comment Syntaxes: [//]: # (...) or [comment]: <> (...)
        for match in self.MARKDOWN_COMMENT_RE.finditer(text):
            comment_content = next((g for g in match.groups() if g is not None), "").strip()
            if not comment_content:
                continue

            start_offset = match.start()
            line_no, col_no = self._offset_to_line_col(text, start_offset)
            detected_keyword = self._find_instruction_keyword(comment_content)

            if detected_keyword:
                findings.append(
                    HiddenTextFinding(
                        file_path=file_path,
                        line=line_no,
                        column=col_no,
                        pattern_type="concealed_instruction",
                        pattern_name=f"Concealed Markdown Instruction Comment ({detected_keyword})",
                        codepoint_hex=None,
                        snippet=comment_content[:100],
                        risk_reason=(
                            f"Markdown hidden comment syntax contains prompt instructions ({detected_keyword}) "
                            "concealed from normal documentation preview."
                        ),
                        severity=Severity.HIGH,
                    )
                )

        return findings

    def _find_instruction_keyword(self, text: str) -> Optional[str]:
        """Checks if text contains prompt injection or dangerous instructions."""
        for pattern in self.INSTRUCTION_KEYWORDS:
            m = pattern.search(text)
            if m:
                return m.group(0).strip()
        return None

    def _check_base64_payload(self, text: str) -> Optional[Tuple[str, str]]:
        """Checks if a string contains base64-encoded shell or prompt instructions."""
        b64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
        for cand in b64_candidates:
            try:
                decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore").strip()
                if len(decoded) >= 8:
                    kw = self._find_instruction_keyword(decoded)
                    if kw:
                        return (decoded, f"Decodes to prompt/shell instruction: '{kw}'")
                    if any(cmd in decoded.lower() for cmd in ("curl ", "bash ", "rm -rf", "wget ", "powershell")):
                        return (decoded, "Decodes to executable shell command")
            except Exception:
                continue
        return None

    def _offset_to_line_col(self, text: str, offset: int) -> Tuple[int, int]:
        prefix = text[:offset]
        line = prefix.count("\n") + 1
        last_nl = prefix.rfind("\n")
        col = offset - last_nl if last_nl != -1 else offset + 1
        return line, col

    def _format_snippet(self, line: str, col: int, radius: int = 30) -> str:
        start = max(0, col - 1 - radius)
        end = min(len(line), col - 1 + radius)
        snip = line[start:end]
        # Replace non-printable control characters with visual markers in snippet
        clean_snip = "".join(f"[U+{ord(c):04X}]" if ord(c) in self.ZERO_WIDTH_CODEPOINTS or ord(c) in self.BIDI_CONTROL_CODEPOINTS else c for c in snip)
        return clean_snip

    def scan_file(self, file_path: Path | str) -> List[HiddenTextFinding]:
        """Scans a file on disk for invisible characters and hidden instructions."""
        p = Path(file_path)
        if not p.is_file():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            return self.scan_text(content, file_path=str(p))
        except Exception:
            return []

    def scan_diff(self, diff_content: str, file_path: str = "diff") -> List[HiddenTextFinding]:
        """Scans added lines in a unified git diff for newly introduced hidden text."""
        findings: List[HiddenTextFinding] = []
        current_file = file_path
        current_line_no = 1

        for raw_line in diff_content.splitlines():
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:].strip()
                continue
            if raw_line.startswith("@@"):
                # Parse hunk header: @@ -1,5 +10,6 @@
                m = re.search(r"\+(\d+)", raw_line)
                if m:
                    current_line_no = int(m.group(1))
                continue

            if raw_line.startswith("+") and not raw_line.startswith("+++"):
                added_text = raw_line[1:]
                line_findings = self.scan_text(added_text, file_path=current_file)
                for f in line_findings:
                    f.line = current_line_no
                    findings.append(f)
                current_line_no += 1
            elif not raw_line.startswith("-"):
                current_line_no += 1

        return findings

    def scan_git_staged(self, repo_root: Path | str) -> List[HiddenTextFinding]:
        """Scans staged git changes (git diff --cached) for concealed text."""
        try:
            res = subprocess.run(
                ["git", "diff", "--cached"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout:
                return self.scan_diff(res.stdout, file_path=f"{repo_root}/staged")
        except Exception:
            pass
        return []

    def clean_text(self, text: str) -> str:
        """Utility removing invisible Unicode, bidirectional overrides, and ANSI conceal escapes."""
        cleaned_chars = []
        for ch in text:
            cp = ord(ch)
            if cp in self.BIDI_CONTROL_CODEPOINTS:
                continue
            if cp in self.ZERO_WIDTH_CODEPOINTS:
                continue
            if self.TAG_CODEPOINTS_RANGE[0] <= cp <= self.TAG_CODEPOINTS_RANGE[1]:
                continue
            cleaned_chars.append(ch)

        res = "".join(cleaned_chars)
        res = self.ANSI_CONCEAL_RE.sub("", res)
        return res


# -----------------------------------------------------------------------------
# 3. Security Gate Implementation
# -----------------------------------------------------------------------------

class HiddenTextGate(BaseGate):
    """
    Hidden-Text Security Gate (N7):
    Detects invisible Unicode, bidirectional controls, hidden comments, and concealed instructions
    in commands, files read/modified by agents, tool arguments, and staged git commits.
    """

    # Retain class attributes for backward compatibility
    BIDI_CONTROL_CODEPOINTS = set(HiddenTextScanner.BIDI_CONTROL_CODEPOINTS.keys())
    ZERO_WIDTH_CODEPOINTS = set(HiddenTextScanner.ZERO_WIDTH_CODEPOINTS.keys())

    def __init__(self, scanner: Optional[HiddenTextScanner] = None):
        self.scanner = scanner or HiddenTextScanner()

    @property
    def name(self) -> str:
        return "HiddenTextScanner"

    def scan_string(self, text: str) -> List[Tuple[int, str]]:
        return self.scanner.scan_string(text)

    def scan_text(self, text: str, file_path: str = "buffer") -> List[HiddenTextFinding]:
        return self.scanner.scan_text(text, file_path=file_path)

    def scan_file(self, file_path: Path | str) -> List[HiddenTextFinding]:
        return self.scanner.scan_file(file_path)

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        """Evaluates an ActionRequest across shell commands, file reads/edits, tool args, and git commits."""
        findings: List[HiddenTextFinding] = []

        # ---------------------------------------------------------------------
        # 1. Inspect Shell Commands & Git Commits
        # ---------------------------------------------------------------------
        if request.kind == ActionKind.SHELL and request.command:
            cmd = request.command
            findings.extend(self.scanner.scan_text(cmd, file_path="command"))

            # Inspect Git Commits (commit messages and staged diffs)
            if re.search(r"\bgit\s+commit\b", cmd, re.IGNORECASE):
                msg_match = re.search(r"-m\s+[\"']([^\"']+)[\"']", cmd)
                if msg_match:
                    commit_msg = msg_match.group(1)
                    findings.extend(self.scanner.scan_text(commit_msg, file_path="git_commit_msg"))

                # Check staged git files if in a repository directory
                cwd = request.cwd or request.worktree
                if cwd and os.path.exists(cwd):
                    findings.extend(self.scanner.scan_git_staged(cwd))

        # ---------------------------------------------------------------------
        # 2. Inspect Target Path (filenames containing hidden Unicode/BiDi/homoglyphs)
        # ---------------------------------------------------------------------
        if request.target_path:
            findings.extend(self.scanner.scan_text(request.target_path, file_path="target_path"))

        # ---------------------------------------------------------------------
        # 3. Inspect Tool Arguments & File Edits
        # ---------------------------------------------------------------------
        if request.tool_args:
            # Check content payloads passed via tool arguments (e.g. write_to_file, replace_file_content)
            for key in ("content", "new_content", "CodeContent", "ReplacementContent", "text", "patch"):
                val = request.tool_args.get(key)
                if isinstance(val, str) and val:
                    target_file = request.target_path or str(request.tool_args.get("TargetFile") or "tool_content")
                    findings.extend(self.scanner.scan_text(val, file_path=target_file))

        # ---------------------------------------------------------------------
        # 4. Inspect Files Read or Modified on Disk
        # ---------------------------------------------------------------------
        if request.kind in (ActionKind.FILE_READ, ActionKind.FILE_EDIT) and request.target_path:
            target_path = request.target_path
            candidate_paths: List[Path] = []
            if os.path.isabs(target_path):
                candidate_paths.append(Path(target_path))
            else:
                for base in [request.cwd, request.worktree, "."]:
                    if base:
                        candidate_paths.append(Path(base) / target_path)

            for cand in candidate_paths:
                if cand.is_file():
                    findings.extend(self.scanner.scan_file(cand))
                    break

        if not findings:
            return None

        # ---------------------------------------------------------------------
        # 5. Build Structured GateResult
        # ---------------------------------------------------------------------
        # Select primary finding
        bidi_findings = [f for f in findings if f.pattern_type == "bidi_control"]
        tag_findings = [f for f in findings if f.pattern_type == "unicode_tags"]
        inst_findings = [f for f in findings if f.pattern_type == "concealed_instruction"]
        comment_findings = [f for f in findings if f.pattern_type == "hidden_comment"]

        if bidi_findings:
            primary = bidi_findings[0]
            rule_id = "R-TXT-BIDI-OVERRIDE"
            severity = Severity.HIGH
        elif tag_findings:
            primary = tag_findings[0]
            rule_id = "R-TXT-TAG-STEGANOGRAPHY"
            severity = Severity.HIGH
        elif inst_findings:
            primary = inst_findings[0]
            rule_id = "R-TXT-CONCEALED-INSTRUCTION"
            severity = Severity.HIGH
        elif comment_findings:
            primary = comment_findings[0]
            rule_id = "R-TXT-HIDDEN-COMMENT"
            severity = Severity.MEDIUM
        else:
            primary = findings[0]
            rule_id = "R-TXT-HIDDEN-UNICODE"
            severity = primary.severity

        distinct_patterns = list(dict.fromkeys(f.pattern_name for f in findings))
        pattern_summary = ", ".join(distinct_patterns[:3])

        return GateResult(
            triggered=True,
            rule_id=rule_id,
            category="hidden-text-detected",
            severity=severity,
            summary=f"Concealed text detected in {primary.file_path}:{primary.line} ({primary.pattern_name}).",
            why=(
                f"File: {primary.file_path}, Location: line {primary.line}, col {primary.column}. "
                f"Detected: {pattern_summary}. {primary.risk_reason}"
            ),
            safer_alternative=(
                "Inspect file in raw hexadecimal/byte mode, strip concealed control characters, "
                "and verify file contents before executing or committing."
            ),
            details={
                "file_path": primary.file_path,
                "location": primary.location_str(),
                "pattern": primary.pattern_name,
                "pattern_type": primary.pattern_type,
                "risk_reason": primary.risk_reason,
                "total_findings": len(findings),
                "findings": [f.to_dict() for f in findings[:25]],
            },
        )
