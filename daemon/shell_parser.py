"""
daemon/shell_parser.py - Structured shell command tokenizer, pipeline splitter, and AST parser.
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


CONTROL_OPERATORS = ["&&", "||", ";;", ">>", "<<", "&>", "2>&1", "2>", "1>", ">", "<", "|", ";", "&"]

WRAPPER_COMMANDS = {
    "sudo", "su", "nohup", "env", "time", "xargs", "doas", "nice", "ionice"
}

SHELL_INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "powershell", "pwsh", "cmd", "cmd.exe"
}

SCRIPT_INTERPRETERS = SHELL_INTERPRETERS | {
    "python", "python3", "python2", "node", "nodejs", "perl", "ruby", "php"
}

DOWNLOAD_TOOLS = {
    "curl", "wget", "http", "fetch", "lynx", "invoke-webrequest", "iwr"
}


@dataclass
class CommandSegment:
    """Represents a single parsed command within a pipeline or chain."""
    raw: str
    tokens: List[str]
    executable: str
    args: List[str]
    flags: Set[str] = field(default_factory=set)
    options: Dict[str, List[str]] = field(default_factory=dict)
    redirections: List[Tuple[str, str]] = field(default_factory=list)
    subcommand: Optional[CommandSegment] = None
    env_vars: Dict[str, str] = field(default_factory=dict)
    pipeline_index: int = 0
    pipeline_length: int = 1

    @property
    def canonical_executable(self) -> str:
        """Returns the lowercased basename of the executable (e.g. /usr/bin/git -> git)."""
        exe = self.executable.replace("\\", "/").split("/")[-1].lower()
        if exe.endswith(".exe"):
            exe = exe[:-4]
        return exe

    def has_flag(self, *flag_names: str) -> bool:
        """Checks if any of the given flag names are present (e.g. '-f', '--force')."""
        for f in flag_names:
            if f in self.flags:
                return True
        return False

    def get_option_values(self, *option_names: str) -> List[str]:
        """Returns all values passed for the given option names."""
        values: List[str] = []
        for opt in option_names:
            values.extend(self.options.get(opt, []))
        return values


@dataclass
class Pipeline:
    """Represents a sequence of commands piped together (cmd1 | cmd2 | cmd3)."""
    raw: str
    stages: List[CommandSegment]

    @property
    def is_piped(self) -> bool:
        return len(self.stages) > 1


@dataclass
class ParsedShell:
    """Root structure representing a fully parsed shell command line."""
    raw: str
    pipelines: List[Pipeline]
    has_subshell: bool = False
    subshell_commands: List[str] = field(default_factory=list)
    parse_error: Optional[str] = None

    def all_commands(self) -> List[CommandSegment]:
        """Returns a flat list of all parsed command segments across all pipelines and subcommands."""
        result: List[CommandSegment] = []
        for pipe in self.pipelines:
            for stage in pipe.stages:
                result.append(stage)
                curr = stage.subcommand
                while curr:
                    result.append(curr)
                    curr = curr.subcommand
        return result


class ShellParser:
    """Parses shell command strings using structured tokenization and lexical analysis."""

    SUBSHELL_PATTERN = re.compile(r"\$\((.+?)\)|`(.+?)`", re.DOTALL)

    @classmethod
    def _split_into_tokens(cls, cmd_str: str) -> Tuple[List[str], Optional[str]]:
        """Tokenizes shell string using shlex, safely falling back if syntax is malformed."""
        try:
            tokens = shlex.split(cmd_str, posix=True)
            return tokens, None
        except ValueError as e:
            # Handle unclosed quotes or syntax errors gracefully
            tokens = [t for t in cmd_str.strip().split() if t]
            return tokens, str(e)

    @classmethod
    def _delimit_operators(cls, cmd_str: str) -> str:
        """Inserts safe whitespace boundaries around shell control operators outside quotes."""
        res: List[str] = []
        in_single = False
        in_double = False
        i = 0
        n = len(cmd_str)

        while i < n:
            ch = cmd_str[i]

            # Handle quotes
            if ch == "'" and not in_double:
                in_single = not in_single
                res.append(ch)
                i += 1
                continue
            elif ch == '"' and not in_single:
                in_double = not in_double
                res.append(ch)
                i += 1
                continue

            if in_single or in_double:
                res.append(ch)
                i += 1
                continue

            # Check 2-char operators: &&, ||, >>, <<, &>
            if i + 1 < n:
                two = cmd_str[i:i + 2]
                if two in ("&&", "||", ">>", "<<", "&>", "2>"):
                    res.extend([" ", two, " "])
                    i += 2
                    continue

            # Check 1-char operators: |, ;, &, >, <
            if ch in ("|", ";", "&", ">", "<"):
                res.extend([" ", ch, " "])
                i += 1
                continue

            res.append(ch)
            i += 1

        return "".join(res)

    @classmethod
    def parse_command_segment(cls, tokens: List[str], raw: str, pipeline_index: int = 0, pipeline_length: int = 1) -> Optional[CommandSegment]:
        if not tokens:
            return None

        # 1. Extract leading environment assignments (e.g. FOO=1 BAR=2 cmd args)
        env_vars: Dict[str, str] = {}
        idx = 0
        while idx < len(tokens) and "=" in tokens[idx] and not tokens[idx].startswith("-"):
            eq_idx = tokens[idx].index("=")
            key = tokens[idx][:eq_idx]
            val = tokens[idx][eq_idx + 1:]
            if key.isidentifier():
                env_vars[key] = val
                idx += 1
            else:
                break

        if idx >= len(tokens):
            return None

        executable = tokens[idx]
        remaining = tokens[idx + 1:]

        # 2. Parse arguments, flags, options, and redirections
        args: List[str] = []
        flags: Set[str] = set()
        options: Dict[str, List[str]] = {}
        redirections: List[Tuple[str, str]] = []

        i = 0
        while i < len(remaining):
            t = remaining[i]

            # Redirection operator
            if t in (">", ">>", "<", "&>", "2>", "1>"):
                target = remaining[i + 1] if i + 1 < len(remaining) else ""
                redirections.append((t, target))
                i += 2
                continue

            # Option or flag
            if t.startswith("-"):
                # Long option with = (e.g. --data=@file, --output=out.sh)
                if "=" in t and t.startswith("--"):
                    opt_k, opt_v = t.split("=", 1)
                    options.setdefault(opt_k, []).append(opt_v)
                    flags.add(opt_k)
                    i += 1
                    continue

                flags.add(t)

                # Check if next token is value for this option
                if i + 1 < len(remaining) and not remaining[i + 1].startswith("-") and remaining[i + 1] not in CONTROL_OPERATORS:
                    options.setdefault(t, []).append(remaining[i + 1])
                    # Note: we do not automatically advance i here for all flags because some flags are boolean.
                    # But for known value-bearing flags (e.g. -m, -o, -d, -c, --data) we can associate.
                    if t in ("-m", "-o", "-d", "-u", "-c", "-e", "-i", "-t", "-f", "--file", "--output", "--data", "--data-raw", "--data-binary", "--upload-file"):
                        i += 2
                        continue

                # Short combined flags like -rf or -fdx
                if len(t) > 2 and not t.startswith("--") and t[1:].isalpha():
                    for char in t[1:]:
                        flags.add(f"-{char}")

                i += 1
                continue

            args.append(t)
            i += 1

        segment = CommandSegment(
            raw=raw,
            tokens=tokens,
            executable=executable,
            args=args,
            flags=flags,
            options=options,
            redirections=redirections,
            env_vars=env_vars,
            pipeline_index=pipeline_index,
            pipeline_length=pipeline_length,
        )

        # 3. Detect and unpack wrapper commands (sudo, sh -c, env, xargs, etc.)
        canonical = segment.canonical_executable
        if canonical in WRAPPER_COMMANDS and remaining:
            sub_raw = " ".join(remaining)
            segment.subcommand = cls.parse_command_segment(remaining, sub_raw, pipeline_index, pipeline_length)
        elif canonical in SHELL_INTERPRETERS and segment.has_flag("-c") and options.get("-c"):
            c_val = options["-c"][0]
            sub_tokens, _ = cls._split_into_tokens(c_val)
            if sub_tokens:
                segment.subcommand = cls.parse_command_segment(sub_tokens, c_val, 0, 1)

        return segment

    @classmethod
    def parse(cls, cmd_str: str) -> ParsedShell:
        """Parses a full shell command line string into pipelines, stages, and command segments."""
        if not cmd_str or not cmd_str.strip():
            return ParsedShell(raw="", pipelines=[])

        raw_clean = cmd_str.strip()

        # Check for subshells: $(...) or `...`
        subshell_matches = cls.SUBSHELL_PATTERN.findall(raw_clean)
        subshell_commands: List[str] = []
        for match in subshell_matches:
            val = match[0] or match[1]
            if val.strip():
                subshell_commands.append(val.strip())

        has_subshell = len(subshell_commands) > 0

        # Split control operators with whitespace
        delimited = cls._delimit_operators(raw_clean)
        tokens, parse_error = cls._split_into_tokens(delimited)

        if not tokens:
            return ParsedShell(raw=raw_clean, pipelines=[], has_subshell=has_subshell, parse_error=parse_error)

        # Break tokens into pipelines by sequence operators (&&, ||, ;, &)
        # and then each pipeline into stages by pipe (|)
        pipelines: List[Pipeline] = []
        current_pipeline_tokens: List[List[str]] = [[]]
        current_stage_idx = 0

        for tok in tokens:
            if tok in ("&&", "||", ";", "&"):
                # Complete current pipeline if it has content
                valid_stages = [s for s in current_pipeline_tokens if s]
                if valid_stages:
                    stages: List[CommandSegment] = []
                    pipe_len = len(valid_stages)
                    for p_idx, st_toks in enumerate(valid_stages):
                        st_raw = " ".join(st_toks)
                        seg = cls.parse_command_segment(st_toks, st_raw, p_idx, pipe_len)
                        if seg:
                            stages.append(seg)
                    if stages:
                        pipe_raw = " | ".join(s.raw for s in stages)
                        pipelines.append(Pipeline(raw=pipe_raw, stages=stages))

                current_pipeline_tokens = [[]]
                current_stage_idx = 0
            elif tok == "|":
                current_pipeline_tokens.append([])
                current_stage_idx += 1
            else:
                current_pipeline_tokens[current_stage_idx].append(tok)

        # Append final pipeline
        valid_stages = [s for s in current_pipeline_tokens if s]
        if valid_stages:
            stages = []
            pipe_len = len(valid_stages)
            for p_idx, st_toks in enumerate(valid_stages):
                st_raw = " ".join(st_toks)
                seg = cls.parse_command_segment(st_toks, st_raw, p_idx, pipe_len)
                if seg:
                    stages.append(seg)
            if stages:
                pipe_raw = " | ".join(s.raw for s in stages)
                pipelines.append(Pipeline(raw=pipe_raw, stages=stages))

        return ParsedShell(
            raw=raw_clean,
            pipelines=pipelines,
            has_subshell=has_subshell,
            subshell_commands=subshell_commands,
            parse_error=parse_error,
        )
