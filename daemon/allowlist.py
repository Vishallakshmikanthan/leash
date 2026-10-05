"""
daemon/allowlist.py - Argument-aware allowlist and policy outcome decision engine (M4).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from contracts.models import ActionRequest, PolicyOutcome
from daemon.shell_parser import CommandSegment, ParsedShell

# Sensitive paths that can never be accessed via simple allowlist
SENSITIVE_PATH_PATTERNS = {
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".azure",
    ".kube",
    ".env",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "/etc/shadow",
    "/etc/passwd",
    "shadow",
}


class ArgumentAwareAllowlist:
    """Evaluates individual commands and arguments to grant explicit ALLOW, ASK, or DENY outcomes."""

    def __init__(self, mode: str = "balanced", worktree_root: Optional[Path] = None):
        self.mode = mode.lower()  # "strict", "balanced", or "learning"
        self.worktree_root = worktree_root.resolve() if worktree_root else Path.cwd().resolve()
        self.session_written_files: Set[str] = set()
        self.package_json_hash: Optional[str] = self._compute_package_json_scripts_hash()

    def set_worktree(self, path: Path) -> None:
        self.worktree_root = path.resolve()
        self.package_json_hash = self._compute_package_json_scripts_hash()

    def record_agent_written_file(self, file_path: str) -> None:
        """Tracks files modified or created by the agent during this session (M4.4)."""
        resolved = str(Path(file_path).resolve())
        self.session_written_files.add(resolved)

    def _compute_package_json_scripts_hash(self) -> Optional[str]:
        pkg = self.worktree_root / "package.json"
        if not pkg.exists():
            return None
        try:
            with open(pkg, "r", encoding="utf-8") as f:
                data = json.load(f)
            scripts = data.get("scripts", {})
            encoded = json.dumps(scripts, sort_keys=True).encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()
        except Exception:
            return None

    def _is_path_safe(self, raw_path: str, cwd: Optional[str] = None) -> bool:
        """Verifies path resolves inside worktree and does not touch sensitive credential paths."""
        base = Path(cwd).resolve() if cwd else self.worktree_root

        # Check explicit sensitive tokens in path string
        raw_norm = raw_path.replace("\\", "/")
        for sensitive in SENSITIVE_PATH_PATTERNS:
            if sensitive in raw_norm:
                return False

        try:
            expanded = os.path.expanduser(raw_path)
            candidate = Path(expanded)
            if not candidate.is_absolute():
                resolved = (base / candidate).resolve()
            else:
                resolved = candidate.resolve()
        except Exception:
            return False

        resolved_str = str(resolved).lower().replace("\\", "/")
        for sensitive in SENSITIVE_PATH_PATTERNS:
            if sensitive in resolved_str:
                return False

        # Must be within worktree root or provided cwd
        try:
            resolved.relative_to(self.worktree_root)
            return True
        except ValueError:
            if cwd:
                try:
                    resolved.relative_to(Path(cwd).resolve())
                    return True
                except ValueError:
                    pass
            return False

    def evaluate_segment(self, segment: CommandSegment, cwd: Optional[str] = None) -> Tuple[PolicyOutcome, str]:
        """Evaluates a single command segment against argument-aware rules."""
        exe = segment.canonical_executable

        # Opaque forms are never ALLOW
        if segment.is_opaque:
            return PolicyOutcome.ASK, f"Opaque shell execution form detected for '{exe}'."

        # In strict mode, only exact known allow rules qualify; everything else asks
        # 1. pytest
        if exe in ("pytest", "py.test"):
            # Denied options: -p, -c, --rootdir outside worktree, --import-mode
            if segment.has_flag("-p", "-c"):
                return PolicyOutcome.ASK, f"pytest invoked with dangerous custom plugin/config flag: {segment.flags}"
            for opt in ("-c", "-p", "--rootdir", "--import-mode"):
                if opt in segment.options:
                    return PolicyOutcome.ASK, f"pytest argument {opt} requires review."

            # Verify target test paths
            for arg in segment.args:
                if arg.startswith("-"):
                    continue
                # Split possible path:test_func
                path_part = arg.split("::")[0]
                if not self._is_path_safe(path_part, cwd):
                    return PolicyOutcome.ASK, f"pytest path outside worktree or sensitive: {arg}"

            return PolicyOutcome.ALLOW, "pytest with safe test arguments."

        # 2. git
        if exe == "git":
            # Denied git flags that execute external commands or override config
            for f in segment.flags:
                if f in ("--ext-diff", "--upload-pack", "--exec-path") or f.startswith("--exec-path="):
                    return PolicyOutcome.ASK, f"git external executable execution flag: {f}"
                if f == "-c" or f.startswith("-c="):
                    return PolicyOutcome.ASK, f"git configuration override (-c) requires review."
                if f.startswith("--config"):
                    return PolicyOutcome.ASK, f"git config flag requires review."

            # Check options
            if "-c" in segment.options or "--exec-path" in segment.options or "--ext-diff" in segment.options:
                return PolicyOutcome.ASK, "git configuration override or ext-diff option requires review."

            # Subcommand check
            subcmd = None
            for arg in segment.args:
                if not arg.startswith("-"):
                    subcmd = arg
                    break

            if not subcmd:
                if segment.has_flag("-v", "--version", "--help"):
                    return PolicyOutcome.ALLOW, "git version or help."
                return PolicyOutcome.ASK, "git invoked without safe subcommand."

            # Safe subcommands
            if subcmd in ("status", "diff", "log", "show", "branch", "rev-parse", "version", "--version"):
                # Ensure diff has no ext-diff
                if subcmd == "diff" and segment.has_flag("--ext-diff"):
                    return PolicyOutcome.ASK, "git diff --ext-diff executes external diff binary."
                return PolicyOutcome.ALLOW, f"git safe inspection command: {subcmd}."

            if subcmd in ("add", "commit"):
                return PolicyOutcome.ALLOW, f"git safe staging command: {subcmd}."

            if subcmd in ("checkout", "switch") and (segment.has_flag("-b", "-c") or len(segment.args) == 2):
                return PolicyOutcome.ALLOW, f"git branch navigation: {subcmd}."

            # Actions requiring confirmation
            if subcmd in ("push", "reset", "clean", "merge", "rebase"):
                return PolicyOutcome.ASK, f"git state-altering command '{subcmd}' requires phone approval."

            if subcmd == "config":
                args_str = " ".join(segment.args)
                if "core.hookspath" in args_str.lower():
                    return PolicyOutcome.ASK, "git config core.hooksPath manipulation detected."
                return PolicyOutcome.ASK, "git config modification requires approval."

            return PolicyOutcome.ASK, f"git command '{subcmd}' not on auto-allow list."

        # 3. ls / dir
        if exe in ("ls", "dir"):
            for arg in segment.args:
                if arg.startswith("-"):
                    continue
                if not self._is_path_safe(arg, cwd):
                    return PolicyOutcome.ASK, f"Directory listing on external/sensitive path: {arg}"
            return PolicyOutcome.ALLOW, "Directory listing inside safe worktree."

        # 4. npm test / npm run <script>
        if exe == "npm":
            subcmd = segment.args[0] if segment.args else ""
            if subcmd == "test":
                current_hash = self._compute_package_json_scripts_hash()
                if self.package_json_hash is not None and current_hash != self.package_json_hash:
                    return PolicyOutcome.ASK, "package.json scripts modified during session; npm test requires review."
                return PolicyOutcome.ALLOW, "npm test with verified unmodified scripts."

            if subcmd == "run" and len(segment.args) > 1:
                script_name = segment.args[1]
                if script_name in ("test", "lint", "build", "check", "start"):
                    current_hash = self._compute_package_json_scripts_hash()
                    if self.package_json_hash is not None and current_hash != self.package_json_hash:
                        return PolicyOutcome.ASK, "package.json scripts modified; npm run requires review."
                    return PolicyOutcome.ALLOW, f"npm run {script_name} with verified scripts."

            return PolicyOutcome.ASK, f"npm command '{' '.join(segment.args)}' requires approval."

        # 5. Linters, typecheckers & formatters: ruff, black, flake8, mypy, tsc
        if exe in ("ruff", "black", "flake8", "mypy", "tsc", "pylint", "isort"):
            for opt in ("--config", "-c"):
                if opt in segment.options:
                    for cfg_val in segment.options[opt]:
                        if not self._is_path_safe(cfg_val, cwd):
                            return PolicyOutcome.ASK, f"{exe} config file outside worktree: {cfg_val}"
            for arg in segment.args:
                if not arg.startswith("-") and not self._is_path_safe(arg, cwd):
                    return PolicyOutcome.ASK, f"{exe} path outside worktree: {arg}"
            return PolicyOutcome.ALLOW, f"Safe formatting/linting via {exe}."

        # 6. Interpreters running files or standard test modules
        if exe in ("python", "python3", "node", "bash", "sh", "zsh"):
            # python -m unittest / pytest
            if exe in ("python", "python3") and segment.has_flag("-m"):
                m_opts = segment.options.get("-m", [])
                m_arg = m_opts[0] if m_opts else (segment.args[0] if segment.args else "")
                if m_arg in ("unittest", "pytest", "test"):
                    return PolicyOutcome.ALLOW, f"Python module testing: {m_arg}."

            # Check version flags
            if segment.has_flag("--version", "-v", "-V"):
                return PolicyOutcome.ALLOW, f"Version check for {exe}."

            # Inline commands like python -c are handled by rules/opaque checks
            if segment.has_flag("-c") or "-c" in segment.options:
                return PolicyOutcome.ASK, f"Inline script execution via {exe} -c requires review."

            script_file = None
            for arg in segment.args:
                if not arg.startswith("-"):
                    script_file = arg
                    break

            if script_file:
                base = Path(cwd).resolve() if cwd else self.worktree_root
                try:
                    full_p = str((base / script_file).resolve())
                except Exception:
                    full_p = script_file

                if full_p in self.session_written_files or str(Path(script_file).resolve()) in self.session_written_files:
                    return PolicyOutcome.ASK, f"Interpreter {exe} executing agent-modified file '{script_file}'."

                if not self._is_path_safe(script_file, cwd):
                    return PolicyOutcome.ASK, f"Interpreter {exe} executing script outside worktree or sensitive path: {script_file}"

                if self.mode == "balanced" and script_file in ("index.js", "main.py", "app.py", "server.js"):
                    return PolicyOutcome.ALLOW, f"Standard entrypoint execution: {exe} {script_file}."

                return PolicyOutcome.ASK, f"Script execution via {exe} {script_file} requires approval."
            else:
                return PolicyOutcome.ASK, f"Interactive interpreter session for {exe} requires approval."

        # 7. Safe read utilities and compiled build/test tools: pwd, echo, cat, cargo, go, mvn, gradle
        if self.mode == "balanced":
            if exe == "pwd":
                return PolicyOutcome.ALLOW, "pwd inspection."
            if exe == "echo":
                return PolicyOutcome.ALLOW, "echo output."
            if exe == "cargo" and segment.args and segment.args[0] in ("test", "build", "check"):
                return PolicyOutcome.ALLOW, f"cargo {segment.args[0]} clean run."
            if exe == "go" and segment.args and segment.args[0] in ("test", "build", "vet"):
                return PolicyOutcome.ALLOW, f"go {segment.args[0]} clean run."
            if exe in ("mvn", "gradle") and segment.args and any(a in ("test", "build", "package", "check") for a in segment.args):
                return PolicyOutcome.ALLOW, f"{exe} safe build/test lifecycle."
            if exe == "cat":
                for arg in segment.args:
                    if not arg.startswith("-") and not self._is_path_safe(arg, cwd):
                        return PolicyOutcome.ASK, f"cat reading sensitive or external path: {arg}"
                return PolicyOutcome.ALLOW, "cat reading safe file in worktree."

        return PolicyOutcome.ASK, f"Command '{exe}' is not on the explicit allowlist."

    def evaluate_parsed(self, parsed: ParsedShell, cwd: Optional[str] = None) -> Tuple[PolicyOutcome, str]:
        """Evaluates an entire parsed shell command line. The worst outcome across all segments wins."""
        if not parsed.pipelines:
            return PolicyOutcome.ALLOW, "Empty command."

        # Opaque forms or subshells require ASK
        if parsed.has_opaque_command:
            return PolicyOutcome.ASK, "Command contains opaque shell constructs, variable expansion, or subshells."

        # Pipes from reader to network require DENY
        if parsed.has_reader_to_network_pipe:
            return PolicyOutcome.DENY, "Piping data from local file reader to network tool is denied."

        worst_outcome = PolicyOutcome.ALLOW
        reasons: List[str] = []

        all_cmds = parsed.all_commands()
        if not all_cmds:
            return PolicyOutcome.ALLOW, "No executable segments found."

        for cmd in all_cmds:
            outcome, reason = self.evaluate_segment(cmd, cwd)
            reasons.append(reason)
            if outcome == PolicyOutcome.DENY:
                return PolicyOutcome.DENY, reason
            elif outcome == PolicyOutcome.ASK:
                worst_outcome = PolicyOutcome.ASK

        combined_reason = "; ".join(reasons)
        return worst_outcome, combined_reason
