"""
daemon/risk_rules.py - Core rule definitions and risk classification catalog.
"""
from __future__ import annotations

import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from contracts.models import ActionKind, ActionRequest, Severity
from daemon.shell_parser import CommandSegment, ParsedShell, SCRIPT_INTERPRETERS, DOWNLOAD_TOOLS


@dataclass
class RuleMatch:
    """Outcome of an individual rule match."""
    rule_id: str
    category: str
    severity: Severity
    summary: str
    why: str
    safer_alternative: str
    details: Dict[str, Any] = field(default_factory=dict)


class BaseRule(ABC):
    """Abstract base class for all Leash policy rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        pass

    @property
    @abstractmethod
    def default_severity(self) -> Severity:
        pass

    @abstractmethod
    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        """Evaluates an ActionRequest and its parsed shell structure."""
        pass


# -----------------------------------------------------------------------------
# 1. Remote Script Execution Rule
# -----------------------------------------------------------------------------

class RemoteScriptExecutionRule(BaseRule):
    """Detects piping downloaded remote scripts into shell or subshell execution."""

    @property
    def rule_id(self) -> str:
        return "R-NET-PIPE-EXEC"

    @property
    def category(self) -> str:
        return "remote-script-execution"

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        if request.kind != ActionKind.SHELL and not request.command:
            return None

        # 1. Pipeline check: curl ... | sh
        for pipeline in parsed_shell.pipelines:
            if pipeline.is_piped:
                for idx in range(len(pipeline.stages) - 1):
                    upstream = pipeline.stages[idx]
                    downstream = pipeline.stages[idx + 1]

                    up_exe = upstream.canonical_executable
                    down_exe = downstream.canonical_executable

                    if up_exe in DOWNLOAD_TOOLS and (down_exe in SCRIPT_INTERPRETERS or downstream.has_flag("-c")):
                        return RuleMatch(
                            rule_id="R-NET-PIPE-EXEC",
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Piping remote content from {up_exe} directly into {down_exe}.",
                            why="Executing uninspected remote scripts can run arbitrary malicious code without verification.",
                            safer_alternative=f"Download script with {up_exe} to a file, inspect it, then execute.",
                            details={"fetcher": up_exe, "interpreter": down_exe},
                        )

        # 2. Subshell check: sh -c "$(curl ...)" or eval $(wget ...)
        if parsed_shell.has_subshell:
            for sub_cmd in parsed_shell.subshell_commands:
                sub_lower = sub_cmd.lower()
                for tool in DOWNLOAD_TOOLS:
                    if tool in sub_lower:
                        return RuleMatch(
                            rule_id="R-NET-SUB-EXEC",
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Subshell execution evaluates downloaded payload from {tool}.",
                            why="Inline execution of remote network content bypasses pre-execution verification.",
                            safer_alternative="Download script to local file, inspect contents, and execute explicitly.",
                            details={"subshell": sub_cmd},
                        )

        # 3. Chained download and execute in single command: curl -o s.sh ... && bash s.sh
        downloaded_files: Set[str] = set()
        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable
            if exe in DOWNLOAD_TOOLS:
                # Check -o or -O or --output
                outputs = cmd.get_option_values("-o", "-O", "--output")
                for out in outputs:
                    downloaded_files.add(os.path.basename(out).lower())

            if downloaded_files:
                for arg in cmd.args:
                    arg_base = os.path.basename(arg).lower()
                    if arg_base in downloaded_files and (exe in SCRIPT_INTERPRETERS or "./" in cmd.raw):
                        return RuleMatch(
                            rule_id="R-NET-DOWNLOAD-EXEC",
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Command immediately executes newly downloaded script '{arg_base}'.",
                            why="Executing downloaded files within the same command chain prevents human inspection.",
                            safer_alternative="Audit the downloaded script before running it in a separate step.",
                            details={"downloaded_file": arg_base},
                        )

        return None


# -----------------------------------------------------------------------------
# 2. Destructive File Operations Rule
# -----------------------------------------------------------------------------

class DestructiveFileOperationsRule(BaseRule):
    """Detects recursive deletes, root wipes, and raw disk/filesystem destructive operations."""

    CRITICAL_ROOT_TARGETS = {"/", "/*", "~", "~/*", "$home", "..", "../..", ".", "./"}
    SYSTEM_DIRECTORIES = {"/etc", "/usr", "/var", "/bin", "/sbin", "/boot", "/lib", "/sys", "/dev"}
    DESTRUCTIVE_RAW_COMMANDS = {"mkfs", "wipefs", "fdisk", "shred", "format"}

    @property
    def rule_id(self) -> str:
        return "R-FS-DESTRUCTIVE"

    @property
    def category(self) -> str:
        return "destructive-file-operations"

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        raw_cmd = (request.command or "").strip()

        # Fork bomb check
        if ":(){ :|:& };:" in raw_cmd or ":(){:|:&};:" in raw_cmd.replace(" ", ""):
            return RuleMatch(
                rule_id="R-FS-DESTRUCTIVE",
                category=self.category,
                severity=Severity.HIGH,
                summary="Fork bomb pattern detected.",
                why="Fork bombs exhaust system process tables and crash the host operating system.",
                safer_alternative="Do not run fork bombs.",
            )

        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable

            # 1. rm commands
            if exe in ("rm", "unlink"):
                is_recursive = cmd.has_flag("-r", "-R", "--recursive")
                is_force = cmd.has_flag("-f", "--force")

                # Check targets
                for arg in cmd.args:
                    clean_arg = arg.strip().lower()
                    if clean_arg in self.CRITICAL_ROOT_TARGETS or any(clean_arg.startswith(s) for s in self.SYSTEM_DIRECTORIES):
                        return RuleMatch(
                            rule_id="R-FS-DESTRUCTIVE-ROOT",
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Destructive deletion targeting critical filesystem path: {arg}",
                            why="Deleting root, parent, or system directories permanently destroys your development environment.",
                            safer_alternative="Constrain file deletion to specific project-relative paths.",
                            details={"target": arg},
                        )

                if is_recursive:
                    return RuleMatch(
                        rule_id="R-FS-DESTRUCTIVE",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Recursive directory deletion detected: {cmd.raw}",
                        why="Recursive deletion can wipe extensive source code directories irreversibly.",
                        safer_alternative="Delete target files individually or use git clean with dry-run.",
                        details={"force": is_force},
                    )

            # 2. Raw disk/partition format commands
            if exe in self.DESTRUCTIVE_RAW_COMMANDS or any(exe.startswith("mkfs.") for s in [1]):
                return RuleMatch(
                    rule_id="R-FS-DESTRUCTIVE",
                    category=self.category,
                    severity=Severity.HIGH,
                    summary=f"Disk formatting or filesystem destruction command: {exe}",
                    why="Filesystem formatting and partition wiping permanently erases storage volumes.",
                    safer_alternative="Perform disk manipulation only inside dedicated sandbox VMs.",
                    details={"tool": exe},
                )

            # 3. dd targeting raw devices
            if exe == "dd":
                for arg in cmd.args:
                    if arg.startswith("of=/dev/") or arg.startswith("of=\\\\.\\"):
                        return RuleMatch(
                            rule_id="R-FS-DESTRUCTIVE",
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Raw disk overwrite via dd: {arg}",
                            why="Direct writes to raw disk block devices destroy filesystem superblocks and partition tables.",
                            safer_alternative="Target standard regular files rather than block devices.",
                            details={"target": arg},
                        )

            # 4. Windows destructive deletions
            if exe in ("rmdir", "rd") and cmd.has_flag("/s", "-s"):
                return RuleMatch(
                    rule_id="R-FS-DESTRUCTIVE",
                    category=self.category,
                    severity=Severity.HIGH,
                    summary="Windows recursive directory deletion (rmdir /s).",
                    why="Recursive folder deletion removes subdirectories and files without confirmation.",
                    safer_alternative="Remove specific files without the /s recursive flag.",
                )

        return None


# -----------------------------------------------------------------------------
# 3. Forceful Git Operations Rule
# -----------------------------------------------------------------------------

class ForcefulGitOperationsRule(BaseRule):
    """Detects git force pushes, hard resets, and destructive clean operations."""

    @property
    def rule_id(self) -> str:
        return "R-GIT-FORCE"

    @property
    def category(self) -> str:
        return "history-rewrite-force-push"

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        if request.kind not in (ActionKind.SHELL, ActionKind.GIT) and not request.command:
            return None

        for cmd in parsed_shell.all_commands():
            if cmd.canonical_executable != "git":
                continue

            subcmd = cmd.args[0].lower() if cmd.args else ""

            # 1. git push --force / -f / +ref
            if subcmd == "push":
                is_force = cmd.has_flag("-f", "--force", "--force-with-lease")
                has_delete = cmd.has_flag("--delete", "-d")
                has_plus_ref = any(a.startswith("+") and len(a) > 1 for a in cmd.args[1:])

                if is_force or has_plus_ref:
                    return RuleMatch(
                        rule_id="R-GIT-FORCE-PUSH",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary="Git force push operation detected.",
                        why="Force pushes overwrite remote history and can destroy unmerged team commits.",
                        safer_alternative="Pull and merge latest remote commits before standard pushing.",
                        details={"args": cmd.args},
                    )

                if has_delete:
                    return RuleMatch(
                        rule_id="R-GIT-FORCE-DELETE",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary="Git remote branch deletion detected.",
                        why="Deleting remote branches permanently removes shared branches on the upstream repository.",
                        safer_alternative="Confirm branch retirement before deleting upstream refs.",
                        details={"args": cmd.args},
                    )

            # 2. git reset --hard / --merge
            elif subcmd == "reset":
                if cmd.has_flag("--hard", "--merge"):
                    return RuleMatch(
                        rule_id="R-GIT-RESET-HARD",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary="Git hard reset operation detected.",
                        why="Hard resets discard uncommitted working tree changes and unreferenced commits permanently.",
                        safer_alternative="Use 'git stash' or create a backup branch before resetting.",
                        details={"args": cmd.args},
                    )

            # 3. git clean -f / -fd / -fdx
            elif subcmd == "clean":
                if cmd.has_flag("-f", "--force"):
                    return RuleMatch(
                        rule_id="R-GIT-CLEAN-FORCE",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary="Git clean force deletion of untracked files.",
                        why="Clean removes untracked source files and build configurations without undo support.",
                        safer_alternative="Run 'git clean -n' first to dry-run and preview affected files.",
                        details={"args": cmd.args},
                    )

            # 4. git branch -D
            elif subcmd == "branch" and cmd.has_flag("-D"):
                return RuleMatch(
                    rule_id="R-GIT-BRANCH-FORCE",
                    category=self.category,
                    severity=Severity.HIGH,
                    summary="Git forced branch deletion (-D).",
                    why="Force deleting a branch bypasses merge checks and can lose unmerged work.",
                    safer_alternative="Use 'git branch -d' to safely verify merge status.",
                    details={"args": cmd.args},
                )

        return None


# -----------------------------------------------------------------------------
# 4. Secret Exposure Rule
# -----------------------------------------------------------------------------

class SecretExposureRule(BaseRule):
    """Detects reads or exposure of .env, ssh keys, cloud credentials, or inline secret tokens."""

    SECRET_PATHS = [
        re.compile(r"(^|/|\\)\.env(\.[a-zA-Z0-9_-]+)?(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.envrc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.environment(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.aws[/\\](credentials|config)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.config[/\\]gcloud[/\\](credentials\.db|application_default_credentials\.json|legacy_credentials)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.azure[/\\](credentials|azureProfile\.json|accessTokens\.json)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.kube[/\\](config|credentials)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.?netrc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)(\.dockercfg|\.docker[/\\]config\.json)(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.git-credentials(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.npmrc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.pypirc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.cargo[/\\]credentials(\.toml)?(\b|$)", re.IGNORECASE),
        re.compile(r".*\.(pem|pkcs12|pfx|key|keystore)$", re.IGNORECASE),
        re.compile(r"(^|/|\\)canary[-_]?secret.*(\b|$)", re.IGNORECASE),
    ]

    INLINE_SECRET_PATTERNS = [
        ("AWS Key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("GitHub Token", re.compile(r"\b(gh[pousr]_[a-zA-Z0-9_]{36,255}|github_pat_[a-zA-Z0-9_]{60,255})\b")),
        ("OpenAI Key", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b")),
        ("Anthropic Key", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b")),
        ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b")),
        ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
        ("Stripe Key", re.compile(r"\b[sr]k_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
        ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
        ("Canary Token", re.compile(r"\b(CANARY_KEY|LEASH_CANARY_[A-Za-z0-9_-]+|canary_secret[A-Za-z0-9_-]*)\b", re.IGNORECASE)),
    ]


    @property
    def rule_id(self) -> str:
        return "R-SECRET-PATH"

    @property
    def category(self) -> str:
        return "secret-exposure"

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        target = request.target_path or ""
        cmd_raw = request.command or ""

        # Canary check
        is_canary = ("canary" in target.lower()) or ("canary" in cmd_raw.lower())

        # 1. Target path checks for file operations
        if request.kind in (ActionKind.FILE_READ, ActionKind.FILE_EDIT) and target:
            for pat in self.SECRET_PATHS:
                if pat.search(target) or is_canary:
                    return RuleMatch(
                        rule_id="R-SECRET-CANARY" if is_canary else "R-SECRET-PATH",
                        category="canary-touched" if is_canary else "secret-exposure",
                        severity=Severity.HIGH,
                        summary=f"Attempted access to secret credential path: {target}",
                        why="Accessing environment files or private keys risks exposing secrets to agent memory or logs.",
                        safer_alternative="Use scoped mock credentials or test environment fixtures.",
                        details={"path": target, "is_canary": is_canary},
                    )

        # 2. Inline token checks in command
        for label, pat in self.INLINE_SECRET_PATTERNS:
            if pat.search(cmd_raw):
                is_token_canary = "Canary" in label or is_canary
                return RuleMatch(
                    rule_id="R-SECRET-CANARY" if is_token_canary else "R-SECRET-INLINE",
                    category="canary-touched" if is_token_canary else "secret-exposure",
                    severity=Severity.HIGH,
                    summary=f"Command exposes inline {label} credential token.",
                    why="Hardcoding or passing API secrets on the command line leaks credentials to shell history and process lists.",
                    safer_alternative="Pass credentials via secure environment variables or a secrets manager.",
                    details={"token_type": label},
                )

        # 3. Shell commands reading secret files or dumping env
        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable

            # Environment dumping commands
            if exe in ("printenv", "env", "export") and not cmd.args:
                return RuleMatch(
                    rule_id="R-SECRET-CMD",
                    category="secret-exposure",
                    severity=Severity.HIGH,
                    summary=f"Command dumps full environment variables ({exe}).",
                    why="Dumping the entire environment table exposes system secrets and API tokens.",
                    safer_alternative="Query only the specific, non-sensitive variable needed.",
                    details={"tool": exe},
                )

            # Cat / reading commands targeting secret files
            if exe in ("cat", "head", "tail", "less", "more", "grep", "type", "get-content"):
                for arg in cmd.args:
                    arg_is_canary = "canary" in arg.lower()
                    for pat in self.SECRET_PATHS:
                        if pat.search(arg) or arg_is_canary:
                            return RuleMatch(
                                rule_id="R-SECRET-CANARY" if (is_canary or arg_is_canary) else "R-SECRET-CMD",
                                category="canary-touched" if (is_canary or arg_is_canary) else "secret-exposure",
                                severity=Severity.HIGH,
                                summary=f"Command attempts to display contents of secret file: {arg}",
                                why="Printing secret files exposes sensitive keys in command output buffers.",
                                safer_alternative="Verify configuration presence without printing raw secret values.",
                                details={"target": arg, "is_canary": is_canary or arg_is_canary},
                            )

        return None


# -----------------------------------------------------------------------------
# 5. Sensitive-File Changes Rule
# -----------------------------------------------------------------------------

class SensitiveFileChangesRule(BaseRule):
    """Detects edits or writes to CI workflows, Dockerfiles, and package lockfiles."""

    SENSITIVE_FILES_PATTERN = re.compile(
        r"(\.github/workflows/.*\.ya?ml|\.gitlab-ci\.ya?ml|Dockerfile.*|docker-compose.*\.ya?ml|package\.json|package-lock\.json|Cargo\.lock|Cargo\.toml|requirements\.txt|poetry\.lock|pyproject\.toml|/etc/passwd|/etc/sudoers|/etc/hosts)",
        re.IGNORECASE,
    )

    @property
    def rule_id(self) -> str:
        return "R-CFG-SENSITIVE-FILE"

    @property
    def category(self) -> str:
        return "sensitive-file-edits"

    @property
    def default_severity(self) -> Severity:
        return Severity.HIGH

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        target = request.target_path or ""

        # 1. FILE_EDIT action kind
        if request.kind == ActionKind.FILE_EDIT and target:
            match = self.SENSITIVE_FILES_PATTERN.search(target)
            if match:
                return RuleMatch(
                    rule_id=self.rule_id,
                    category=self.category,
                    severity=Severity.HIGH,
                    summary=f"Modification to protected workflow or build config: {match.group(0)}",
                    why="Altering CI workflows, container specifications, or lockfiles can inject build backdoors.",
                    safer_alternative="Submit changes to CI or package configs via reviewed pull requests.",
                    details={"file": match.group(0)},
                )

        # 2. Shell redirections or modifying commands
        for cmd in parsed_shell.all_commands():
            # Check redirections (e.g. > .github/workflows/ci.yml)
            for op, dest in cmd.redirections:
                if op in (">", ">>", "&>"):
                    match = self.SENSITIVE_FILES_PATTERN.search(dest)
                    if match:
                        return RuleMatch(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Redirection overwrites protected workflow or build config: {dest}",
                            why="Overwriting build or CI configs via shell redirection bypasses code review controls.",
                            safer_alternative="Apply configuration edits with explicit manual verification.",
                            details={"destination": dest, "operator": op},
                        )

            # Check modifying tools (sed -i, rm, mv, tee)
            exe = cmd.canonical_executable
            if exe in ("sed", "rm", "mv", "cp", "tee") or (exe == "echo" and cmd.redirections):
                for arg in cmd.args:
                    match = self.SENSITIVE_FILES_PATTERN.search(arg)
                    if match:
                        return RuleMatch(
                            rule_id=self.rule_id,
                            category=self.category,
                            severity=Severity.HIGH,
                            summary=f"Command modifies protected configuration file: {arg}",
                            why="Direct modification of critical infrastructure files risks CI/CD supply chain poisoning.",
                            safer_alternative="Review manual pull request diffs for CI and dependency manifests.",
                            details={"target": arg, "tool": exe},
                        )

        return None


# -----------------------------------------------------------------------------
# 6. Permission Changes Rule
# -----------------------------------------------------------------------------

class PermissionChangesRule(BaseRule):
    """Detects permission modifications (chmod, chown, icacls)."""

    BROAD_PERMISSIONS = {"777", "a+rwx", "u+s", "+s", "666"}

    @property
    def rule_id(self) -> str:
        return "R-PERM-CHANGE"

    @property
    def category(self) -> str:
        return "permission-changes"

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable

            # 1. chmod
            if exe == "chmod":
                is_recursive = cmd.has_flag("-R", "--recursive")
                is_broad = any(arg in self.BROAD_PERMISSIONS for arg in cmd.args) or any(
                    f in ("777", "a+rwx") for f in cmd.flags
                )

                if is_broad or (is_recursive and ("777" in cmd.raw or "755" in cmd.raw)):
                    return RuleMatch(
                        rule_id="R-PERM-CHANGE-BROAD",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Overly permissive chmod operation: {cmd.raw}",
                        why="World-writable permissions (777) or broad recursive changes compromise host isolation.",
                        safer_alternative="Apply least privilege permissions (e.g. 644 for files, 755 for scripts).",
                        details={"recursive": is_recursive, "broad": is_broad},
                    )

                return RuleMatch(
                    rule_id="R-PERM-CHANGE",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    summary=f"File permission change: {cmd.raw}",
                    why="Changing permissions can grant execution privileges to untrusted scripts.",
                    safer_alternative="Verify executable files individually before changing mode.",
                    details={"args": cmd.args},
                )

            # 2. chown / chgrp
            if exe in ("chown", "chgrp"):
                is_recursive = cmd.has_flag("-R", "--recursive")
                is_root = any("root" in arg for arg in cmd.args)
                severity = Severity.HIGH if (is_recursive or is_root) else Severity.MEDIUM

                return RuleMatch(
                    rule_id="R-PERM-CHOWN",
                    category=self.category,
                    severity=severity,
                    summary=f"Ownership change detected: {cmd.raw}",
                    why="Modifying file ownership to root or recursively across workspace affects system security.",
                    safer_alternative="Keep files owned by standard unprivileged developer account.",
                    details={"is_root": is_root, "is_recursive": is_recursive},
                )

            # 3. Windows icacls / takeown
            if exe in ("icacls", "takeown"):
                return RuleMatch(
                    rule_id="R-PERM-WIN",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    summary=f"Windows Access Control change ({exe}).",
                    why="Modifying Windows ACLs alters discretionary access controls.",
                    safer_alternative="Maintain standard workspace ACL inheritance.",
                )

        return None


# -----------------------------------------------------------------------------
# 7. Outbound Data Transfer Rule
# -----------------------------------------------------------------------------

class OutboundDataTransferRule(BaseRule):
    """Detects outbound file transmission or exfiltration via curl, wget, scp, rsync, or sockets."""

    NETWORK_SOCKET_TOOLS = {"nc", "ncat", "netcat", "socat"}

    @property
    def rule_id(self) -> str:
        return "R-NET-OUTBOUND"

    @property
    def category(self) -> str:
        return "outbound-data-transfer"

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable

            # 1. curl file upload: -d @file, -F file=@..., -T file
            if exe == "curl":
                # Check for @file in options or flags
                upload_opts = cmd.get_option_values("-d", "--data", "--data-binary", "--data-raw", "-F", "--form", "-T", "--upload-file")
                is_file_upload = any("@" in v or v.startswith("/") or v.startswith(".") for v in upload_opts)
                if not is_file_upload:
                    is_file_upload = any("@" in f for f in cmd.flags)

                if is_file_upload:
                    return RuleMatch(
                        rule_id="R-NET-EXFIL",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Outbound file exfiltration via curl: {cmd.raw}",
                        why="Uploading local files to external endpoints can leak source code or secrets.",
                        safer_alternative="Verify endpoint authenticity or use mock API responses locally.",
                        details={"args": cmd.args},
                    )

            # 2. wget post file
            if exe == "wget":
                post_opts = cmd.get_option_values("--post-file")
                if post_opts or any("--post-file" in f for f in cmd.flags):
                    return RuleMatch(
                        rule_id="R-NET-EXFIL",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Outbound file transmission via wget: {cmd.raw}",
                        why="Posting local file content to external hosts risks data exfiltration.",
                        safer_alternative="Inspect outbound data payloads before dispatching requests.",
                    )

            # 3. scp / sftp / rsync to remote host
            if exe in ("scp", "sftp", "rsync"):
                # Remote targets typically contain ':' (e.g. user@host:path)
                has_remote = any(":" in arg and not arg.startswith("http") for arg in cmd.args)
                if has_remote:
                    return RuleMatch(
                        rule_id="R-NET-EXFIL",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Remote file copy ({exe}) to external destination.",
                        why="Transferring files across the network copies repository assets off the machine.",
                        safer_alternative="Retain files inside the local project worktree.",
                        details={"tool": exe},
                    )

            # 4. Raw network socket tools with input redirection or pipes
            if exe in self.NETWORK_SOCKET_TOOLS:
                has_input_redir = any(op == "<" for op, _ in cmd.redirections)
                is_piped_in = cmd.pipeline_index > 0

                if has_input_redir or is_piped_in:
                    return RuleMatch(
                        rule_id="R-NET-EXFIL",
                        category=self.category,
                        severity=Severity.HIGH,
                        summary=f"Data exfiltration via raw network socket ({exe}).",
                        why="Streaming local data directly into raw TCP/UDP sockets is an exfiltration indicator.",
                        safer_alternative="Use authenticated, encrypted application protocols.",
                        details={"tool": exe},
                    )

            # 5. Cloud storage uploads (aws s3 cp, gsutil cp)
            if exe in ("aws", "gsutil", "az"):
                sub = cmd.args[0].lower() if cmd.args else ""
                if sub in ("s3", "cp", "sync", "storage"):
                    has_cloud_target = any(a.startswith("s3://") or a.startswith("gs://") for a in cmd.args)
                    if has_cloud_target:
                        return RuleMatch(
                            rule_id="R-NET-OUTBOUND",
                            category=self.category,
                            severity=Severity.MEDIUM,
                            summary=f"Cloud storage upload detected ({exe}).",
                            why="Copying local files to cloud storage buckets exposes development artifacts externally.",
                            safer_alternative="Verify cloud bucket permissions and destination paths.",
                            details={"tool": exe},
                        )

        return None


# -----------------------------------------------------------------------------
# 8. Package Installation Rule
# -----------------------------------------------------------------------------

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance supporting insertions, deletions, substitutions, and transpositions."""
    d: Dict[Tuple[int, int], int] = {}
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


class PackageInstallationRule(BaseRule):
    """Detects package manager installations, suspicious external packages, and typosquats."""

    POPULAR_PACKAGES: Set[str] = {
        "requests", "flask", "django", "numpy", "pandas", "pytest", "scipy", "aiohttp",
        "react", "express", "lodash", "axios", "typescript", "chalk", "webpack", "next",
        "tokio", "serde", "syn", "anyhow", "clap", "tracing"
    }

    PACKAGE_MANAGERS = {
        "npm": ["install", "i", "add"],
        "yarn": ["add"],
        "pnpm": ["add", "install"],
        "pip": ["install"],
        "pip3": ["install"],
        "cargo": ["add", "install"],
        "gem": ["install"],
        "go": ["get", "install"],
        "composer": ["require"],
    }

    @property
    def rule_id(self) -> str:
        return "R-PKG-INSTALL"

    @property
    def category(self) -> str:
        return "package-install"

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        if request.kind == ActionKind.INSTALL:
            return RuleMatch(
                rule_id="R-PKG-INSTALL",
                category=self.category,
                severity=Severity.MEDIUM,
                summary=f"Package installation requested: {request.command or request.tool_name}",
                why="Installing packages executes arbitrary package lifecycle scripts.",
                safer_alternative="Pin dependencies with exact hashes in lockfile.",
            )

        for cmd in parsed_shell.all_commands():
            exe = cmd.canonical_executable
            if exe in self.PACKAGE_MANAGERS:
                allowed_subcommands = self.PACKAGE_MANAGERS[exe]
                if cmd.args and cmd.args[0].lower() in allowed_subcommands:
                    raw_pkgs = cmd.args[1:]
                    for pkg in raw_pkgs:
                        if pkg.startswith("-"):
                            continue
                        clean_pkg = pkg.split("==")[0].split(">=")[0].split("@")[0].strip().lower()
                        if not clean_pkg:
                            continue

                        # Check typosquatting against popular packages
                        for popular in self.POPULAR_PACKAGES:
                            dist = damerau_levenshtein_distance(clean_pkg, popular)
                            if clean_pkg != popular and (dist == 1 or (len(popular) >= 7 and dist <= 2)):
                                return RuleMatch(
                                    rule_id="R-PKG-TYPOSQUAT",
                                    category=self.category,
                                    severity=Severity.HIGH,
                                    summary=f"Package '{clean_pkg}' is suspiciously close to popular package '{popular}'.",
                                    why="Typosquatting packages frequently conceal infostealers or reverse shells.",
                                    safer_alternative=f"Verify if you intended to install '{popular}' instead.",
                                    details={"pkg": clean_pkg, "popular": popular},
                                )

                    # Arbitrary package install
                    return RuleMatch(
                        rule_id="R-PKG-NEW-INSTALL",
                        category=self.category,
                        severity=Severity.MEDIUM,
                        summary=f"Installing external packages via {exe}: {' '.join(raw_pkgs[:3])}",
                        why="Package installations run third-party lifecycle code on your development host.",
                        safer_alternative="Pin exact package versions and inspect dependency trees.",
                        details={"manager": exe, "packages": raw_pkgs},
                    )

        return None


# -----------------------------------------------------------------------------
# 9. Scope Violations Rule
# -----------------------------------------------------------------------------

class ScopeViolationsRule(BaseRule):
    """Detects operations outside defined task scope or directory traversal attempts."""

    @property
    def rule_id(self) -> str:
        return "R-SCOPE-DRIFT"

    @property
    def category(self) -> str:
        return "scope-drift"

    @property
    def default_severity(self) -> Severity:
        return Severity.MEDIUM

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        # 1. Explicit scope flags from caller/session manager
        if request.scope_flags:
            return RuleMatch(
                rule_id="R-SCOPE-DRIFT",
                category=self.category,
                severity=Severity.MEDIUM,
                summary="Action touches paths or commands outside defined session scope.",
                why=f"Triggered scope flags: {', '.join(request.scope_flags)}",
                safer_alternative="Adjust session scope or constrain work to approved directories.",
                details={"flags": request.scope_flags},
            )

        # 2. Path traversal in target path or command arguments
        targets_to_check = []
        if request.target_path:
            targets_to_check.append(request.target_path)
        for cmd in parsed_shell.all_commands():
            targets_to_check.extend(cmd.args)

        for t in targets_to_check:
            # Traversal patterns
            if "../.." in t or "..\\.." in t:
                return RuleMatch(
                    rule_id="R-SCOPE-TRAVERSAL",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    summary=f"Path traversal detected escaping workspace boundary: {t}",
                    why="Navigating above the repository root violates sandbox boundary constraints.",
                    safer_alternative="Use project-relative paths within the designated worktree.",
                    details={"path": t},
                )

        return None


# -----------------------------------------------------------------------------
# 10. Normal Development Rule
# -----------------------------------------------------------------------------

class NormalDevelopmentRule(BaseRule):
    """Permits standard development activities (tests, linters, safe git, builds)."""

    SAFE_COMMANDS = {
        "pytest", "ruff", "flake8", "black", "mypy", "pylint", "isort", "eslint", "prettier",
        "ls", "dir", "pwd", "echo", "which", "where", "whoami", "hostname",
        "head", "tail", "wc", "grep", "find",
    }

    SAFE_GIT_SUBCOMMANDS = {
        "status", "diff", "log", "show", "branch", "rev-parse", "version", "--version", "describe"
    }

    @property
    def rule_id(self) -> str:
        return "R-DEV-ALLOW"

    @property
    def category(self) -> str:
        return "normal-development"

    @property
    def default_severity(self) -> Severity:
        return Severity.LOW

    def evaluate(self, request: ActionRequest, parsed_shell: ParsedShell) -> Optional[RuleMatch]:
        # If no commands found, or safe non-shell actions
        if request.kind in (ActionKind.FILE_READ, ActionKind.TOOL_CALL) and not request.command:
            return RuleMatch(
                rule_id="R-DEV-ALLOW",
                category=self.category,
                severity=Severity.LOW,
                summary="Standard project read or safe tool invocation.",
                why="Non-sensitive file inspection within workspace.",
                safer_alternative="None needed.",
            )

        commands = parsed_shell.all_commands()
        if not commands:
            return RuleMatch(
                rule_id="R-DEV-ALLOW",
                category=self.category,
                severity=Severity.LOW,
                summary="Standard development activity.",
                why="Command poses no recognized risk.",
                safer_alternative="None needed.",
            )

        # Check if all commands in parsed shell are benign
        all_safe = True
        for cmd in commands:
            exe = cmd.canonical_executable

            if exe in self.SAFE_COMMANDS:
                continue

            # git status, diff, log, etc.
            if exe == "git" and cmd.args and cmd.args[0].lower() in self.SAFE_GIT_SUBCOMMANDS:
                continue

            # Python/node version queries or unittest
            if exe in ("python", "python3", "node", "cargo", "rustc", "go") and (
                cmd.has_flag("--version", "-v", "-V") or (cmd.args and cmd.args[0].lower() in ("test", "build"))
            ):
                continue

            # npm test / npm run build
            if exe in ("npm", "yarn", "pnpm") and cmd.args and cmd.args[0].lower() in ("test", "run", "build"):
                continue

            all_safe = False
            break

        if all_safe:
            return RuleMatch(
                rule_id="R-DEV-ALLOW",
                category=self.category,
                severity=Severity.LOW,
                summary="Standard development command.",
                why="Matches safe development workflow allow-list.",
                safer_alternative="None needed.",
            )

        return None
