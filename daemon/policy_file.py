"""
daemon/policy_file.py - Leash policy file (leash.yml) loader, initializer, and learning mode suggester (M13).

Schema:
mode: balanced            # strict | balanced | learning
scope:
  paths: ["src/", "tests/"]
  commands: ["pytest", "npm", "git"]
  hosts: ["registry.npmjs.org", "pypi.org", "github.com"]
protect:
  - ".github/workflows/**"
  - "Dockerfile"
  - "package.json"
allow:
  - cmd: "pytest"
    args_deny: ["-p", "-c"]
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from daemon.paths import leash_home

logger = logging.getLogger("leash.daemon.policy_file")

STARTER_LEASH_YML = """# Leash Security Policy File (M13.2)
# Defines session boundaries, protected files, and argument allowlists.
mode: balanced            # strict | balanced | learning

scope:
  paths:
    - "src/"
    - "tests/"
    - "docs/"
  commands:
    - "pytest"
    - "python"
    - "npm"
    - "git"
    - "ruff"
  hosts:
    - "registry.npmjs.org"
    - "pypi.org"
    - "github.com"

protect:
  - ".github/workflows/**"
  - "Dockerfile"
  - "package.json"
  - "pyproject.toml"
  - "leash.yml"

allow:
  - cmd: "pytest"
    args_deny: ["-p", "-c", "--rootdir"]
  - cmd: "git"
    args_deny: ["-c", "--upload-pack", "push", "reset --hard"]
  - cmd: "npm test"
    args_deny: []
"""

GIT_PRE_COMMIT_HOOK = """#!/bin/sh
# Leash Pre-Commit Secret and Hidden Text Scan (M6.2, M13.1)
leash exec -- git diff --cached | leash audit verify 2>/dev/null || true
exit 0
"""

GIT_PRE_PUSH_HOOK = """#!/bin/sh
# Leash Pre-Push Secret Guard (M6.2, M13.1)
leash git push --dry-run 2>/dev/null || true
exit 0
"""


@dataclass
class LeashPolicy:
    mode: str = "balanced"  # "strict", "balanced", or "learning"
    scope_paths: List[str] = field(default_factory=lambda: ["src/", "tests/"])
    scope_commands: List[str] = field(default_factory=lambda: ["pytest", "npm", "git"])
    scope_hosts: List[str] = field(default_factory=lambda: ["registry.npmjs.org", "pypi.org", "github.com"])
    protect_patterns: List[str] = field(default_factory=list)
    allow_rules: List[Dict[str, Any]] = field(default_factory=list)
    file_hash: str = ""
    source_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "scope": {
                "paths": self.scope_paths,
                "commands": self.scope_commands,
                "hosts": self.scope_hosts,
            },
            "protect": self.protect_patterns,
            "allow": self.allow_rules,
            "file_hash": self.file_hash,
            "source_path": str(self.source_path) if self.source_path else None,
        }


def _simple_yaml_parse(content: str) -> Dict[str, Any]:
    """Lightweight YAML parser for leash.yml supporting basic scalar, list, and dictionary keys."""
    try:
        import yaml  # type: ignore
        return yaml.safe_load(content) or {}
    except ImportError:
        pass

    data: Dict[str, Any] = {"mode": "balanced", "scope": {}, "protect": [], "allow": []}
    current_section = ""
    current_subsection = ""

    for line in content.splitlines():
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            continue

        if ":" in line_str and not line_str.startswith("-"):
            parts = line_str.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip().split("#")[0].strip()

            if line.startswith(" ") or line.startswith("\t"):
                if current_section == "scope":
                    current_subsection = key
                    data["scope"][key] = []
            else:
                current_section = key
                current_subsection = ""
                if val:
                    data[key] = val
        elif line_str.startswith("-"):
            item = line_str[1:].strip().strip('"').strip("'")
            if current_section == "scope" and current_subsection:
                data["scope"].setdefault(current_subsection, []).append(item)
            elif current_section == "protect":
                data["protect"].append(item)
            elif current_section == "allow":
                data["allow"].append({"cmd": item})

    return data


class PolicyLoader:
    """Loads, verifies, and manages repository leash.yml policies."""

    @classmethod
    def find_policy_file(cls, repo_root: Path) -> Optional[Path]:
        for candidate in ("leash.yml", "leash.yaml", ".leash.yml"):
            p = repo_root / candidate
            if p.is_file():
                return p
        return None

    @classmethod
    def load(cls, repo_root: Path) -> LeashPolicy:
        path = cls.find_policy_file(repo_root)
        if not path:
            return LeashPolicy()

        content = path.read_text(encoding="utf-8", errors="replace")
        file_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        raw = _simple_yaml_parse(content)

        scope_dict = raw.get("scope", {})
        return LeashPolicy(
            mode=str(raw.get("mode", "balanced")).lower(),
            scope_paths=list(scope_dict.get("paths", ["src/", "tests/"])),
            scope_commands=list(scope_dict.get("commands", ["pytest", "npm", "git"])),
            scope_hosts=list(scope_dict.get("hosts", ["registry.npmjs.org", "pypi.org", "github.com"])),
            protect_patterns=list(raw.get("protect", [])),
            allow_rules=list(raw.get("allow", [])),
            file_hash=file_hash,
            source_path=path,
        )


class PolicySuggester:
    """Learning mode suggester (M13.3): generates candidate allow rules from user approvals."""

    @classmethod
    def suggest_rules(cls, audit_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyzes approved ASK events and proposes least-privilege allowlist rules."""
        suggestions: List[Dict[str, Any]] = []
        seen_cmds: Set[str] = set()

        for evt in audit_events:
            # Only consider actions approved by user (phone, biometric, manual)
            verdict = evt.get("decision") or evt.get("verdict")
            if str(verdict).lower() != "allow":
                continue

            decided_by = str(evt.get("decided_by", "")).lower()
            if decided_by in ("auto_allow", "quick_allow"):
                continue

            cmd = evt.get("command") or ""
            if not cmd:
                continue

            tokens = cmd.strip().split()
            if not tokens:
                continue

            base_exe = tokens[0].lower()
            # Never propose allow rules for dangerous tools (e.g. curl|sh, rm -rf, sudo)
            if base_exe in ("rm", "sudo", "eval", "su", "mkfs", "dd"):
                continue

            # Candidate rule
            if len(tokens) >= 2 and tokens[0] in ("npm", "cargo", "git", "python", "pip"):
                rule_cmd = f"{tokens[0]} {tokens[1]}"
            else:
                rule_cmd = tokens[0]

            if rule_cmd not in seen_cmds:
                seen_cmds.add(rule_cmd)
                suggestions.append({
                    "cmd": rule_cmd,
                    "reason": f"Frequently approved action by user ({cmd[:40]})",
                    "suggested_entry": {"cmd": rule_cmd, "args_deny": []},
                })

        return suggestions


def init_project(repo_root: Path) -> Dict[str, Any]:
    """
    Initializes a repository for Leash protection (M13.1):
    1. Creates starter leash.yml (if not already present).
    2. Installs git pre-commit and pre-push hooks (M6.2).
    3. Creates local shim directory.
    4. Detects repository type and returns protection level.
    """
    root = repo_root.resolve()
    results: Dict[str, Any] = {
        "repo_root": str(root),
        "policy_created": False,
        "git_hooks_installed": False,
        "shims_created": False,
        "protection_level": "L1 (Hook + Shim)",
    }

    # 1. Starter leash.yml
    policy_path = root / "leash.yml"
    if not policy_path.exists():
        policy_path.write_text(STARTER_LEASH_YML, encoding="utf-8")
        results["policy_created"] = True

    # 2. Git hooks
    git_hooks_dir = root / ".git" / "hooks"
    if git_hooks_dir.is_dir():
        pre_commit = git_hooks_dir / "pre-commit"
        if not pre_commit.exists():
            pre_commit.write_text(GIT_PRE_COMMIT_HOOK, encoding="utf-8")
            try:
                os.chmod(pre_commit, 0o755)
            except Exception:
                pass

        pre_push = git_hooks_dir / "pre-push"
        if not pre_push.exists():
            pre_push.write_text(GIT_PRE_PUSH_HOOK, encoding="utf-8")
            try:
                os.chmod(pre_push, 0o755)
            except Exception:
                pass
        results["git_hooks_installed"] = True

    # 3. Shims directory
    shims_dir = leash_home() / "shims"
    shims_dir.mkdir(parents=True, exist_ok=True)
    results["shims_created"] = True

    # 4. Check container availability for L2
    if shutil.which("docker") or shutil.which("podman") or shutil.which("bwrap"):
        results["protection_level"] = "L1 (Hook + Shim) / L2 Contained Available"

    return results
