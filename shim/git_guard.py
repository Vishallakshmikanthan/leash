"""
shim/git_guard.py - Git Command Guard routing push, reset, and clean through Leash safety layer.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, CommandResult, Severity, Verdict
from gates.secret_fence import SecretFenceGate, SecretRedactor
from shim.shell_wrapper import ShellShim


class GitGuard:
    """Specialized wrapper around git CLI preventing accidental history rewrites or leaks."""

    DANGEROUS_SUBCOMMANDS = {"push", "commit", "reset", "clean", "checkout", "rebase", "branch"}
    FORCE_FLAGS = {"-f", "--force", "--hard", "-x", "-d", "-D", "--delete"}

    def __init__(self, shim: Optional[ShellShim] = None):
        self.shim = shim or ShellShim()
        self.secret_fence = SecretFenceGate()
        self.redactor = SecretRedactor()

    def inspect_git_args(self, git_args: List[str]) -> tuple[bool, Severity, str]:
        """Analyzes git arguments for force pushes, destructive resets, or risk factors."""
        if not git_args:
            return False, Severity.LOW, "git status check"

        subcommand = git_args[0].lower()

        # 1. Force push detection
        if subcommand == "push":
            has_force = any(arg in self.FORCE_FLAGS for arg in git_args[1:])
            if has_force:
                return True, Severity.CRITICAL, "Force push detected. Can overwrite shared remote history."
            return True, Severity.HIGH, "Git push to remote repository."

        # 2. Hard reset or destructive clean
        if subcommand == "reset" and any(arg in ("--hard", "--merge") for arg in git_args[1:]):
            return True, Severity.HIGH, "Hard git reset. Can permanently discard uncommitted changes."

        if subcommand == "clean" and any(arg in ("-f", "--force", "-fd", "-fdx") for arg in git_args[1:]):
            return True, Severity.HIGH, "Git clean with force flag. Permanently removes untracked files."

        # 3. Branch deletion
        if subcommand == "branch" and any(arg in ("-D", "--delete") for arg in git_args[1:]):
            return True, Severity.HIGH, "Git branch force deletion."

        # 3b. Checkout/switch to base branch protection (M7.3)
        if subcommand in ("checkout", "switch"):
            target_branch = next((arg for arg in git_args[1:] if not arg.startswith("-")), "")
            if target_branch in ("main", "master", "develop", "dev", "trunk"):
                return True, Severity.HIGH, f"Blocked switch/checkout to protected base branch '{target_branch}'. Agent must remain in session branch."

        # 4. Commit secret check
        if subcommand == "commit":
            # Check staged diff for secret exposure
            diff_text = self._get_staged_diff()
            if diff_text:
                req = ActionRequest(
                    id="a_git_staged_check",
                    session=self.shim.session_id,
                    ts=0,
                    nonce="",
                    kind=ActionKind.GIT,
                    agent="git-guard",
                    cwd=os.getcwd(),
                    command=f"git {' '.join(git_args)}",
                    target_path="git:staged",
                )
                res = self.secret_fence.evaluate(req)
                if res and res.triggered:
                    return True, Severity.HIGH, f"Git commit blocked: staged files contain secrets ({res.summary})"

        if subcommand in self.DANGEROUS_SUBCOMMANDS:
            return True, Severity.LOW, f"Standard git {subcommand} operation."

        return False, Severity.LOW, "Standard git read command."

    def _get_staged_diff(self) -> str:
        """Retrieves cached/staged diff for commit scanning."""
        try:
            res = subprocess.run(
                ["git", "diff", "--cached"],
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    def run_git(self, git_args: List[str], cwd: Optional[str] = None) -> int:
        """Executes a git command under Leash safety inspection."""
        if not git_args:
            git_args = ["status"]

        full_command = ["git"] + git_args
        cmd_str = " ".join(full_command)

        is_risky, severity, reason = self.inspect_git_args(git_args)

        # Execute through standard shell shim
        result = self.shim.execute(cmd_str, cwd=cwd)

        if not result.allowed:
            sys.stderr.write(result.stderr or f"\n[LEASH BLOCKED] Git command rejected: {reason}\n")
            return result.exit_code or 126

        if result.stdout:
            sys.stdout.write(result.stdout)
            sys.stdout.flush()
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()

        return result.exit_code


def main() -> None:
    parser = argparse.ArgumentParser(prog="leash-git", description="Leash Git Guard")
    parser.add_argument("git_args", nargs=argparse.REMAINDER, help="Git arguments to run")
    args = parser.parse_args()

    git_args = args.git_args
    if git_args and git_args[0] == "--":
        git_args = git_args[1:]

    guard = GitGuard()
    exit_code = guard.run_git(git_args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
