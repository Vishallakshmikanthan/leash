"""
daemon/policy_evaluator.py - Rule engine and risk scoring with shlex tokenization.
"""
from __future__ import annotations

import shlex
import uuid
from typing import List, Optional, Tuple

from contracts.models import ActionKind, ActionRequest, RiskAssessment, Severity
from gates.base import BaseGate, GateResult
from gates.hidden_text import HiddenTextGate
from gates.package_gate import PackageGate
from gates.secret_fence import SecretFenceGate
from gates.workflow_watchlist import WorkflowWatchlistGate


class PolicyEvaluator:
    """Evaluates ActionRequests with local rules, gates, and taint escalation."""

    DESTRUCTIVE_PATTERNS = [
        "rm -rf", "rm -r", "dd if=", "mkfs", ":(){ :|:& };:", "chmod -R 777",
    ]

    GIT_FORCE_PATTERNS = [
        "push --force", "push -f", "reset --hard", "clean -fdx", "clean -f",
    ]

    REMOTE_SCRIPT_PATTERNS = [
        ("curl", "sh"), ("curl", "bash"), ("wget", "sh"), ("wget", "bash"),
    ]

    def __init__(self, allow_command_patterns: Optional[List[str]] = None):
        self.allow_patterns = allow_command_patterns or [
            "pytest", "npm test", "npm run test", "cargo test", "git status", "git diff", "git log", "ls", "pwd", "echo"
        ]
        self.gates: List[BaseGate] = [
            SecretFenceGate(),
            PackageGate(),
            HiddenTextGate(),
            WorkflowWatchlistGate(),
        ]

    def is_quick_allow(self, request: ActionRequest) -> bool:
        if request.taint.tainted:
            return False

        if request.kind == ActionKind.SHELL and request.command:
            cmd = request.command.strip()
            for pattern in self.allow_patterns:
                if cmd == pattern or cmd.startswith(pattern + " "):
                    return True
        return False

    def evaluate(self, request: ActionRequest) -> RiskAssessment:
        rule_ids: List[str] = []
        severity = Severity.LOW
        category = "normal-development"
        summary = "Standard development command."
        why = "Matches safe workflow allow-list."
        safer_alternative = "None needed."

        cmd = request.command or ""

        # 1. Check Destructive file operations
        for pat in self.DESTRUCTIVE_PATTERNS:
            if pat in cmd:
                rule_ids.append("R-FS-DESTRUCTIVE")
                severity = Severity.HIGH
                category = "destructive-file-operations"
                summary = f"Destructive command detected: {pat}"
                why = "Recursive deletion can irreversibly destroy source code and system files."
                safer_alternative = "Target specific files without recursive force flags."
                break

        # 2. Check Git rewrite / force push
        if severity != Severity.HIGH:
            for pat in self.GIT_FORCE_PATTERNS:
                if pat in cmd:
                    rule_ids.append("R-GIT-FORCE")
                    severity = Severity.HIGH
                    category = "history-rewrite-force-push"
                    summary = f"Git history rewrite command detected: {pat}"
                    why = "Force pushes and hard resets destroy uncommitted work or remote history."
                    safer_alternative = "Use normal push or revert commits instead of hard resets."
                    break

        # 3. Check Remote script execution (curl | sh)
        if severity != Severity.HIGH and "|" in cmd:
            for fetcher, runner in self.REMOTE_SCRIPT_PATTERNS:
                if fetcher in cmd and runner in cmd:
                    rule_ids.append("R-NET-PIPE-SH")
                    severity = Severity.HIGH
                    category = "remote-script-execution"
                    summary = f"Piping remote content from {fetcher} into {runner}."
                    why = "Cannot inspect or verify code before execution."
                    safer_alternative = f"Download script with {fetcher}, inspect it, then execute."
                    break

        # 4. Check modular gates
        for gate in self.gates:
            gate_res = gate.evaluate(request)
            if gate_res and gate_res.triggered:
                rule_ids.append(gate_res.rule_id)
                # Elevate severity if higher
                if (gate_res.severity == Severity.HIGH) or (gate_res.severity == Severity.MEDIUM and severity == Severity.LOW):
                    severity = gate_res.severity
                    category = gate_res.category
                    summary = gate_res.summary
                    why = gate_res.why
                    safer_alternative = gate_res.safer_alternative

        # 5. Check Scope flags
        if request.scope_flags and severity == Severity.LOW:
            severity = Severity.MEDIUM
            category = "scope-drift"
            summary = "Action touches paths or commands outside defined session scope."
            why = f"Triggered scope flags: {', '.join(request.scope_flags)}"
            safer_alternative = "Adjust session scope or constrain work to approved directories."

        # 6. Taint escalation (F1)
        tainted_escalation = False
        if request.taint.tainted:
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
                tainted_escalation = True
                category = "untrusted-text-influence"
                summary = f"[TAINTED] Action escalated to HIGH following untrusted read: {request.taint.source or 'unknown'}"
                why = f"Triggered after agent ingested untrusted content at {request.taint.source}:{request.taint.line}."
            elif severity == Severity.LOW:
                # low risk retains low unless suspicious
                pass

        return RiskAssessment(
            id=f"r_{uuid.uuid4().hex[:12]}",
            action_id=request.id,
            severity=severity,
            category=category,
            rule_ids=rule_ids if rule_ids else ["R-DEV-ALLOW"],
            summary=summary,
            why=why,
            safer_alternative=safer_alternative,
            tainted_escalation=tainted_escalation,
            taint_source=request.taint.source if request.taint.tainted else None,
            taint_line=request.taint.line if request.taint.tainted else None,
        )
