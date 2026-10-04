"""
gates/secret_fence.py - Secret Fence (N2): blocks credential exposure, scans commits, redacts secrets, and manages canaries.
"""
from __future__ import annotations

import math
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from contracts.models import ActionKind, ActionRequest, ProvenanceEvent, ProvenanceKind, Severity
from gates.base import BaseGate, GateResult


# -----------------------------------------------------------------------------
# 1. Credential Regex Patterns & High Entropy Detection
# -----------------------------------------------------------------------------

KNOWN_CREDENTIAL_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    # AWS Access Key ID
    ("AWS Access Key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # AWS Secret Access Key
    (
        "AWS Secret Key",
        re.compile(r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "[REDACTED_AWS_SECRET]",
    ),
    # GitHub Personal Access Tokens & App Tokens
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"), "[REDACTED_GITHUB_TOKEN]"),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,255}\b"), "[REDACTED_GITHUB_PAT]"),
    # OpenAI & Anthropic API Keys
    ("OpenAI API Key", re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "[REDACTED_OPENAI_KEY]"),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"), "[REDACTED_ANTHROPIC_KEY]"),
    # Google AI / GCP API Keys
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z-_]{35}\b"), "[REDACTED_GOOGLE_KEY]"),
    # Slack Tokens
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Stripe Keys
    ("Stripe API Key", re.compile(r"\b[sr]k_(?:test|live)_[0-9a-zA-Z]{24,}\b"), "[REDACTED_STRIPE_KEY]"),
    # Private RSA / OpenSSH / EC Keys
    (
        "Private Key Header",
        re.compile(
            r"-----BEGIN\s+(?:RSA\s+|OPENSSH\s+|DSA\s+|EC\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|OPENSSH\s+|DSA\s+|EC\s+)?PRIVATE\s+KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # Bearer & Auth Headers
    ("Bearer Token", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*"), "Bearer [REDACTED_TOKEN]"),
    # JWT Tokens
    ("JWT Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    # Generic API Keys or Passwords in assignments
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|auth[_-]?token|password|passwd|secret[_-]?key|client[_-]?secret)[\s:=]+['\"]?([A-Za-z0-9\-_.~!@#$%^&*+/]{8,})['\"]?"
        ),
        "[REDACTED_CREDENTIAL]",
    ),
    # Canary Tokens
    (
        "Leash Canary Token",
        re.compile(r"\b(?:CANARY_KEY|LEASH_CANARY_[A-Za-z0-9_-]+|canary_secret[A-Za-z0-9_-]*)\b", re.IGNORECASE),
        "[REDACTED_CANARY_TOKEN]",
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(text: str, min_length: int = 18, entropy_threshold: float = 3.6) -> List[Tuple[str, float]]:
    """Identifies candidate secret tokens based on length and Shannon entropy."""
    candidates = []
    # Tokenize words of alphabetic/numeric/base64 chars
    tokens = re.findall(r"[A-Za-z0-9_\-+/]{16,}", text)
    for token in tokens:
        # Ignore common non-secret programming constructs (e.g. repeated long strings or url paths)
        if len(token) >= min_length:
            ent = calculate_shannon_entropy(token)
            if ent >= entropy_threshold:
                # Exclude purely alphabetic words or simple lowercase words
                has_upper = any(c.isupper() for c in token)
                has_lower = any(c.islower() for c in token)
                has_digit = any(c.isdigit() for c in token)
                if (has_upper and has_lower) or (has_digit and (has_upper or has_lower)):
                    candidates.append((token, ent))
    return candidates


# -----------------------------------------------------------------------------
# 2. Secret Redactor
# -----------------------------------------------------------------------------

class SecretRedactor:
    """Scans and masks sensitive credentials in command outputs, approval cards, and audit logs."""

    def __init__(self, custom_canary_tokens: Optional[Set[str]] = None):
        self.canary_tokens = custom_canary_tokens or set()

    def add_canary_token(self, token: str) -> None:
        self.canary_tokens.add(token)

    def redact(self, text: Optional[str], mask_canaries: bool = True) -> str:
        """Sanitizes sensitive values from text, replacing secrets with redaction labels."""
        if not text:
            return ""

        clean = text

        # Redact specific registered canary tokens
        if mask_canaries:
            for c_token in self.canary_tokens:
                if c_token and c_token in clean:
                    clean = clean.replace(c_token, "[REDACTED_CANARY_TOKEN]")

        # Redact known regex patterns
        for _label, pattern, replacement in KNOWN_CREDENTIAL_PATTERNS:
            clean = pattern.sub(replacement, clean)

        # Redact high-entropy secret assignments (e.g. KEY="h98F7g4f7832...")
        high_entropy = find_high_entropy_strings(clean, min_length=20, entropy_threshold=3.8)
        for token, _ent in high_entropy:
            if not token.startswith("[REDACTED_"):
                clean = clean.replace(token, "[REDACTED_HIGH_ENTROPY_SECRET]")

        return clean


# -----------------------------------------------------------------------------
# 3. Harmless Canary Manager
# -----------------------------------------------------------------------------

@dataclass
class CanaryCredential:
    token: str
    label: str
    file_path: Optional[str] = None
    created_at: int = 0
    description: str = "Harmless canary credential"


class CanaryManager:
    """Manages plantable fake canary credentials that immediately trigger security alerts when accessed."""

    DEFAULT_CANARY_TOKENS = {
        "CANARY_KEY",
        "LEASH_CANARY_TOKEN",
        "leash_fake_canary_token_9921_safe_for_testing",
        "LEASH_CANARY_AKIA_IOSFODNN7EXAMPLE",
        "leash_canary_sk_live_998877665544332211",
    }

    def __init__(self, canary_dir: Optional[Path] = None):
        self.canary_dir = canary_dir or Path(".leash/canaries")
        self.registered_canaries: Dict[str, CanaryCredential] = {}
        for token in self.DEFAULT_CANARY_TOKENS:
            self.register_token(token, "default-canary")

    def register_token(self, token: str, label: str, file_path: Optional[str] = None) -> CanaryCredential:
        cred = CanaryCredential(token=token, label=label, file_path=file_path)
        self.registered_canaries[token] = cred
        return cred

    def is_canary_token(self, text: str) -> bool:
        if not text:
            return False
        for token in self.registered_canaries:
            if token.lower() in text.lower():
                return True
        return False

    def is_canary_path(self, path_str: str) -> bool:
        if not path_str:
            return False
        norm = path_str.replace("\\", "/").lower()
        if "canary" in norm:
            return True
        for cred in self.registered_canaries.values():
            if cred.file_path and cred.file_path.replace("\\", "/").lower() in norm:
                return True
        return False

    def plant_canary_env(self, target_dir: Path) -> Path:
        """Plants a harmless fake canary .env file to detect unauthorized reads."""
        target_dir.mkdir(parents=True, exist_ok=True)
        canary_file = target_dir / ".env.canary"
        content = (
            "# HARMLESS LEASH CANARY CREDENTIAL FILE (DO NOT USE IN PRODUCTION)\n"
            "# Any read or exfiltration attempt triggers an immediate Leash alert.\n"
            "LEASH_CANARY_AKIA=LEASH_CANARY_AKIA_IOSFODNN7EXAMPLE\n"
            "LEASH_CANARY_SECRET=leash_canary_sk_live_998877665544332211\n"
            "CANARY_KEY=leash_fake_canary_token_9921_safe_for_testing\n"
        )
        canary_file.write_text(content, encoding="utf-8")
        self.register_token(
            "LEASH_CANARY_AKIA_IOSFODNN7EXAMPLE",
            label="canary_aws_key",
            file_path=str(canary_file),
        )
        self.register_token(
            "leash_canary_sk_live_998877665544332211",
            label="canary_stripe_secret",
            file_path=str(canary_file),
        )
        return canary_file


# -----------------------------------------------------------------------------
# 4. Secret Fence Security Gate
# -----------------------------------------------------------------------------

class SecretFenceGate(BaseGate):
    """
    Secret Fence (N2):
    1. Blocks agent reads of .env, ~/.ssh, cloud credentials, Docker/Kube/Git configs.
    2. Detects commands dumping environment tables or reading credential files.
    3. Scans Git commits & pushes for secrets and high-entropy tokens.
    4. Detects harmless canary credentials and triggers security alerts.
    """

    SENSITIVE_PATHS: List[re.Pattern[str]] = [
        # Environment files
        re.compile(r"(^|/|\\)\.env(\.[a-zA-Z0-9_-]+)?(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.envrc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.environment(\b|$)", re.IGNORECASE),
        # SSH keys and configuration
        re.compile(r"(^|/|\\)\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config)(\b|$)", re.IGNORECASE),
        # AWS credentials & config
        re.compile(r"(^|/|\\)\.aws[/\\](credentials|config)(\b|$)", re.IGNORECASE),
        # Google Cloud credentials
        re.compile(r"(^|/|\\)\.config[/\\]gcloud[/\\](credentials\.db|application_default_credentials\.json|legacy_credentials[/\\])", re.IGNORECASE),
        # Azure credentials
        re.compile(r"(^|/|\\)\.azure[/\\](credentials|azureProfile\.json|accessTokens\.json)(\b|$)", re.IGNORECASE),
        # Kubernetes credentials
        re.compile(r"(^|/|\\)\.kube[/\\](config|credentials)(\b|$)", re.IGNORECASE),
        # Netrc credentials
        re.compile(r"(^|/|\\)\.?netrc(\b|$)", re.IGNORECASE),
        # Docker configuration
        re.compile(r"(^|/|\\)(\.dockercfg|\.docker[/\\]config\.json)(\b|$)", re.IGNORECASE),
        # Git credentials & tokens
        re.compile(r"(^|/|\\)\.git-credentials(\b|$)", re.IGNORECASE),
        # Package manager auth tokens
        re.compile(r"(^|/|\\)\.npmrc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.pypirc(\b|$)", re.IGNORECASE),
        re.compile(r"(^|/|\\)\.cargo[/\\]credentials(\.toml)?(\b|$)", re.IGNORECASE),
        # Private key certificates
        re.compile(r".*\.(pem|pkcs12|pfx|key|keystore)$", re.IGNORECASE),
        # Canary secret indicators
        re.compile(r"(^|/|\\)canary[-_]?secret.*(\b|$)", re.IGNORECASE),
    ]

    COMMAND_EXPOSURE_PATTERNS: List[re.Pattern[str]] = [
        # Printing env files
        re.compile(r"\b(?:cat|type|head|tail|less|more|grep|awk|sed|Get-Content|gc)\s+.*\.env(\.[a-zA-Z0-9_-]+)?\b", re.IGNORECASE),
        # Printing SSH keys
        re.compile(r"\b(?:cat|type|head|tail|less|more|Get-Content|gc)\s+.*\.ssh[/\\]\b", re.IGNORECASE),
        # Printing AWS or cloud configs
        re.compile(r"\b(?:cat|type|head|tail|less|more|Get-Content|gc)\s+.*(?:\.aws[/\\]|\.config[/\\]gcloud[/\\]|\.azure[/\\]|\.kube[/\\])\b", re.IGNORECASE),
        # Dumping environment tables
        re.compile(r"^(?:printenv|env|export|Get-ChildItem\s+env:)$", re.IGNORECASE),
        re.compile(r"\bprintenv\b|\benv\b(?!\s*-\w)|\bexport\s+-p\b", re.IGNORECASE),
        # Exfiltration via curl/wget
        re.compile(r"\bcurl\b.*(?:\s+-d\s+@|\s+-F\s+.*=@).*(?:\.env|\.ssh|\.aws|\.kube)", re.IGNORECASE),
        re.compile(r"\bwget\b.*--post-file=.*(?:\.env|\.ssh|\.aws|\.kube)", re.IGNORECASE),
        # Copying sensitive files
        re.compile(r"\b(?:cp|copy|xcopy|mv|move)\s+.*?(?:\.ssh|\.aws|\.env|\.kube|\.azure|\.config[/\\]gcloud|id_rsa|credentials|id_ed25519)\b.*", re.IGNORECASE),
    ]


    def __init__(self, canary_manager: Optional[CanaryManager] = None):
        self.canary_mgr = canary_manager or CanaryManager()
        self.redactor = SecretRedactor(custom_canary_tokens=set(self.canary_mgr.registered_canaries.keys()))

    @property
    def name(self) -> str:
        return "SecretFence"

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        target = request.target_path or ""
        cmd = request.command or ""

        # ---------------------------------------------------------------------
        # 1. Canary Access Checks (Highest Priority Alert)
        # ---------------------------------------------------------------------
        if self.canary_mgr.is_canary_path(target) or self.canary_mgr.is_canary_token(cmd) or self.canary_mgr.is_canary_path(cmd):
            return GateResult(
                triggered=True,
                rule_id="R-SECRET-CANARY",
                category="canary-touched",
                severity=Severity.HIGH,
                summary=f"Canary credential access detected: {target or cmd}",
                why="Agent accessed or exposed a designated canary credential token.",
                safer_alternative="Do not access or exfiltrate canary secrets.",
            )

        # ---------------------------------------------------------------------
        # 2. File Reads / Edits Targeting Sensitive Paths
        # ---------------------------------------------------------------------
        if request.kind in (ActionKind.FILE_READ, ActionKind.FILE_EDIT) and target:
            for pat in self.SENSITIVE_PATHS:
                if pat.search(target):
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-PATH",
                        category="secret-exposure",
                        severity=Severity.HIGH,
                        summary=f"Attempted access to protected credential file: {target}",
                        why="Agent is attempting to read private keys, cloud tokens, or environment secrets.",
                        safer_alternative="Use scoped environment variables or test fixtures without secrets.",
                    )

        # ---------------------------------------------------------------------
        # 3. Shell Commands Targeting Sensitive Files or Dumping Env
        # ---------------------------------------------------------------------
        if request.kind == ActionKind.SHELL and cmd:
            for pat in self.COMMAND_EXPOSURE_PATTERNS:
                if pat.search(cmd):
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-CMD",
                        category="secret-exposure",
                        severity=Severity.HIGH,
                        summary="Command accesses, copies, or prints sensitive environment or secret files.",
                        why="Output from this command leaks secrets, keys, or access tokens into process output buffers.",
                        safer_alternative="Reference variables directly in application code without printing raw contents.",
                    )

        # ---------------------------------------------------------------------
        # 4. Git Commit & Push Scanning
        # ---------------------------------------------------------------------
        if request.kind in (ActionKind.SHELL, ActionKind.GIT) and cmd:
            git_result = self._scan_git_operation(request, cmd)
            if git_result:
                return git_result

        # ---------------------------------------------------------------------
        # 5. Inline Secret Token Detection in Shell Commands or Tools
        # ---------------------------------------------------------------------
        content_to_check = cmd
        if request.tool_args:
            content_to_check += " " + str(request.tool_args)

        for label, pat, _replacement in KNOWN_CREDENTIAL_PATTERNS:
            if label != "Generic Secret Assignment" and pat.search(content_to_check):
                return GateResult(
                    triggered=True,
                    rule_id="R-SECRET-INLINE",
                    category="secret-exposure",
                    severity=Severity.HIGH,
                    summary=f"Command contains inline {label} credential token.",
                    why="Inline secrets in command strings are exposed to process lists, shell history, and logs.",
                    safer_alternative="Pass credentials via secure configuration or environment variables.",
                )


        # ---------------------------------------------------------------------
        # 6. High-Entropy Secret Detection
        # ---------------------------------------------------------------------
        high_entropy = find_high_entropy_strings(content_to_check, min_length=24, entropy_threshold=3.85)
        # Verify it's not a common Git SHA or safe hash command
        if high_entropy and not self._is_safe_hash_operation(cmd, high_entropy):
            secret_preview = high_entropy[0][0][:6] + "..."
            return GateResult(
                triggered=True,
                rule_id="R-SECRET-ENTROPY",
                category="secret-exposure",
                severity=Severity.HIGH,
                summary=f"High-entropy secret token detected in command: {secret_preview}",
                why="High-entropy alphanumeric strings typically represent unredacted API keys, private tokens, or secrets.",
                safer_alternative="Store secret tokens in secure key vaults or use mocked credentials.",
            )

        return None

    def _is_safe_hash_operation(self, cmd: str, candidates: List[Tuple[str, float]]) -> bool:
        """Determines if high-entropy strings are harmless git commit SHAs or package hashes."""
        cmd_lower = cmd.lower()
        if any(tool in cmd_lower for tool in ("git log", "git rev-parse", "git show", "git checkout", "sha256sum", "md5sum")):
            return True
        # If all candidates are 40-char lowercase hex strings (git commits), allow if in git context
        for token, _ in candidates:
            if len(token) == 40 and all(c in "0123456789abcdef" for c in token.lower()):
                if "git" in cmd_lower:
                    return True
        return False

    def _scan_git_operation(self, request: ActionRequest, cmd: str) -> Optional[GateResult]:
        """Scans git commit and push operations for committed secrets and sensitive files."""
        cmd_clean = cmd.strip()

        # Check Git Commit commands
        if re.search(r"\bgit\s+commit\b", cmd_clean, re.IGNORECASE):
            # Check commit message (-m "...") for inline secrets
            msg_match = re.search(r"-m\s+[\"']([^\"']+)[\"']", cmd_clean)
            if msg_match:
                commit_msg = msg_match.group(1)
                for label, pat, _ in KNOWN_CREDENTIAL_PATTERNS:
                    if pat.search(commit_msg):
                        return GateResult(
                            triggered=True,
                            rule_id="R-SECRET-COMMIT",
                            category="secret-exposure",
                            severity=Severity.HIGH,
                            summary=f"Git commit message contains inline {label}.",
                            why="Commit messages are permanent parts of git history and easily exposed in logs.",
                            safer_alternative="Remove credentials from commit messages before committing.",
                        )
                entropy_matches = find_high_entropy_strings(commit_msg, min_length=24, entropy_threshold=3.9)
                if entropy_matches:
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-COMMIT",
                        category="secret-exposure",
                        severity=Severity.HIGH,
                        summary="Git commit message contains high-entropy credential secret.",
                        why="Committing raw secret tokens leaks credentials permanently to git history.",
                        safer_alternative="Strip secrets from commit messages.",
                    )

            # Check staged files in git working directory if possible
            staged_check = self._scan_staged_git_diff(request.cwd)
            if staged_check:
                return staged_check

        # Check Git Push commands
        if re.search(r"\bgit\s+push\b", cmd_clean, re.IGNORECASE):
            push_check = self._scan_unpushed_git_commits(request.cwd)
            if push_check:
                return push_check

        return None

    def _scan_staged_git_diff(self, cwd: str) -> Optional[GateResult]:
        """Inspects git staged changes (git diff --cached) for added credentials."""
        try:
            # Check staged files list
            res_files = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res_files.returncode == 0 and res_files.stdout:
                for line in res_files.stdout.splitlines():
                    clean_path = line.strip()
                    for pat in self.SENSITIVE_PATHS:
                        if pat.search(clean_path):
                            return GateResult(
                                triggered=True,
                                rule_id="R-SECRET-COMMIT",
                                category="secret-exposure",
                                severity=Severity.HIGH,
                                summary=f"Staged git commit includes protected credential file: {clean_path}",
                                why="Committing sensitive environment or key files leaks secrets to repository history.",
                                safer_alternative="Add sensitive files to .gitignore and unstage with 'git reset HEAD <file>'.",
                            )

            # Check staged diff content for added lines with secrets
            res_diff = subprocess.run(
                ["git", "diff", "--cached", "-U0"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res_diff.returncode == 0 and res_diff.stdout:
                findings = self.scan_diff_text(res_diff.stdout)
                if findings:
                    desc, rule = findings[0]
                    return GateResult(
                        triggered=True,
                        rule_id=rule,
                        category="canary-touched" if "canary" in rule.lower() else "secret-exposure",
                        severity=Severity.HIGH,
                        summary=f"Staged git commit diff contains {desc}.",
                        why="Committing secrets exposes credentials to version control history.",
                        safer_alternative="Remove the secrets from the staged diff before committing.",
                    )
        except Exception:
            pass
        return None

    def _scan_unpushed_git_commits(self, cwd: str) -> Optional[GateResult]:
        """Inspects unpushed git commits before push."""
        try:
            res_diff = subprocess.run(
                ["git", "diff", "@{u}..HEAD"],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res_diff.returncode == 0 and res_diff.stdout:
                findings = self.scan_diff_text(res_diff.stdout)
                if findings:
                    desc, rule = findings[0]
                    return GateResult(
                        triggered=True,
                        rule_id="R-SECRET-PUSH",
                        category="canary-touched" if "canary" in rule.lower() else "secret-exposure",
                        severity=Severity.HIGH,
                        summary=f"Git push rejected: unpushed commits contain {desc}.",
                        why="Pushing commits with secrets exposes credentials to remote remotes and collaborators.",
                        safer_alternative="Rewind or amend commits to remove secrets before pushing.",
                    )
        except Exception:
            pass
        return None

    def scan_diff_text(self, diff_text: str) -> List[Tuple[str, str]]:
        """Scans added lines in a unified diff for secret patterns and high-entropy strings."""
        findings = []
        for line in diff_text.splitlines():
            # Only inspect additions, ignore deletions
            if line.startswith("+") and not line.startswith("+++"):
                added_content = line[1:].strip()
                # 1. Canary tokens
                if self.canary_mgr.is_canary_token(added_content):
                    findings.append(("Canary Token", "R-SECRET-CANARY"))
                    continue

                # 2. Known credential patterns
                for label, pat, _ in KNOWN_CREDENTIAL_PATTERNS:
                    if label != "Generic Secret Assignment" and pat.search(added_content):
                        findings.append((label, "R-SECRET-COMMIT"))
                        break

                # 3. High entropy additions
                high_ent = find_high_entropy_strings(added_content, min_length=24, entropy_threshold=3.9)
                if high_ent:
                    findings.append(("High-Entropy Secret", "R-SECRET-ENTROPY"))

        return findings

    def redact_secrets(self, text: Optional[str]) -> str:
        """Utility method to sanitize secrets using the internal redactor."""
        return self.redactor.redact(text)
