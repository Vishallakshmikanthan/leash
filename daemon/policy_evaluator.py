"""
daemon/policy_evaluator.py - Rule-first risk engine with structured shell parsing, modular gates, and taint escalation.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, RiskAssessment, Severity
from daemon.risk_rules import (
    BaseRule,
    DestructiveFileOperationsRule,
    ForcefulGitOperationsRule,
    NormalDevelopmentRule,
    OutboundDataTransferRule,
    PackageInstallationRule,
    PermissionChangesRule,
    RemoteScriptExecutionRule,
    RuleMatch,
    ScopeViolationsRule,
    SecretExposureRule,
    SensitiveFileChangesRule,
    UntrustedTextInfluenceRule,
)
from daemon.shell_parser import ParsedShell, ShellParser
from gates.base import BaseGate, GateResult
from gates.hidden_text import HiddenTextGate
from gates.package_gate import PackageGate
from gates.provenance_tracker import ProvenanceTrackerGate
from gates.secret_fence import SecretFenceGate
from gates.workflow_watchlist import WorkflowWatchlistGate


class PolicyEvaluator:
    """Evaluates ActionRequests with structured shell parsing, modular security gates, and provenance escalation."""

    def __init__(
        self,
        allow_command_patterns: Optional[List[str]] = None,
        custom_rules: Optional[List[BaseRule]] = None,
        custom_gates: Optional[List[BaseGate]] = None,
    ):
        self.allow_patterns = allow_command_patterns or [
            "pytest", "npm test", "npm run test", "cargo test", "git status",
            "git diff", "git log", "git --version", "python --version", "ls", "pwd",
            "ruff", "flake8", "black"
        ]

        # Core rules catalog
        self.rules: List[BaseRule] = custom_rules or [
            RemoteScriptExecutionRule(),
            DestructiveFileOperationsRule(),
            ForcefulGitOperationsRule(),
            SecretExposureRule(),
            SensitiveFileChangesRule(),
            PermissionChangesRule(),
            OutboundDataTransferRule(),
            PackageInstallationRule(),
            ScopeViolationsRule(),
            UntrustedTextInfluenceRule(),
            NormalDevelopmentRule(),
        ]

        # Modular security gates
        self.gates: List[BaseGate] = custom_gates or [
            SecretFenceGate(),
            PackageGate(),
            HiddenTextGate(),
            WorkflowWatchlistGate(),
            ProvenanceTrackerGate(),
        ]
        self.package_gate: Optional[PackageGate] = next(
            (g for g in self.gates if isinstance(g, PackageGate)), None
        )

    def register_rule(self, rule: BaseRule) -> None:
        """Dynamically registers an additional policy rule."""
        self.rules.insert(0, rule)

    def register_gate(self, gate: BaseGate) -> None:
        """Dynamically registers an additional security gate."""
        self.gates.append(gate)
        if isinstance(gate, PackageGate):
            self.package_gate = gate

    def is_quick_allow(self, request: ActionRequest) -> bool:
        """Quickly checks whether an ActionRequest can be safely executed without phone notification."""
        if request.taint.tainted or request.scope_flags:
            return False

        if request.kind == ActionKind.SHELL and request.command:
            cmd = request.command.strip()
            # If compound command with pipes, chaining, or redirections, never quick-allow
            if any(char in cmd for char in ["|", ";", "&", ">", "<", "`", "$"]):
                return False

            # Check if any security gate flags it
            for gate in self.gates:
                res = gate.evaluate(request)
                if res and res.triggered:
                    return False

            # Check if any high or medium rule triggers
            parsed = ShellParser.parse(cmd)
            for rule in self.rules:
                if isinstance(rule, NormalDevelopmentRule):
                    continue
                match = rule.evaluate(request, parsed)
                if match and match.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL):
                    return False

            # Check allow patterns
            for pattern in self.allow_patterns:
                if cmd == pattern or cmd.startswith(pattern + " "):
                    return True

        return False

    def evaluate(self, request: ActionRequest) -> RiskAssessment:
        """Evaluates an ActionRequest and returns a comprehensive RiskAssessment."""
        # 1. Parse shell command structured AST
        cmd_str = request.command or ""
        parsed = ShellParser.parse(cmd_str)

        all_matches: List[RuleMatch] = []
        rule_ids: List[str] = []

        # 2. Evaluate all rules
        for rule in self.rules:
            match = rule.evaluate(request, parsed)
            if match:
                all_matches.append(match)
                if match.rule_id not in rule_ids:
                    rule_ids.append(match.rule_id)

        # 3. Evaluate all modular security gates
        for gate in self.gates:
            gate_res = gate.evaluate(request)
            if gate_res and gate_res.triggered:
                if gate_res.rule_id not in rule_ids:
                    rule_ids.append(gate_res.rule_id)
                all_matches.append(
                    RuleMatch(
                        rule_id=gate_res.rule_id,
                        category=gate_res.category,
                        severity=gate_res.severity,
                        summary=gate_res.summary,
                        why=gate_res.why,
                        safer_alternative=gate_res.safer_alternative,
                        details=gate_res.details or {},
                    )
                )

        # 4. Determine highest severity match
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        # Filter out normal development if dangerous matches exist
        non_dev_matches = [m for m in all_matches if m.category != "normal-development"]
        candidates = non_dev_matches if non_dev_matches else all_matches

        if candidates:
            # Sort by severity descending
            candidates.sort(key=lambda m: severity_order.get(m.severity, 0), reverse=True)
            primary = candidates[0]
            severity = primary.severity
            category = primary.category
            summary = primary.summary
            why = primary.why
            safer_alternative = primary.safer_alternative
        else:
            severity = Severity.LOW
            category = "normal-development"
            summary = "Standard development activity."
            why = "Matches safe development workflow."
            safer_alternative = "None needed."
            if not rule_ids:
                rule_ids.append("R-DEV-ALLOW")

        # 5. Provenance-based escalation (F1)
        tainted_escalation = False
        if request.taint.tainted:
            tainted_escalation = True
            source = request.taint.source or "unknown"
            line_str = f":{request.taint.line}" if request.taint.line is not None else ""

            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
                category = "untrusted-text-influence"
                summary = f"[TAINTED] Action escalated to HIGH following untrusted read: {source}"
                why = f"Triggered after agent ingested untrusted content at {source}{line_str}."
            elif severity == Severity.HIGH:
                category = "untrusted-text-influence" if category == "normal-development" else category
                summary = f"[TAINTED] High-risk action following untrusted read: {source} - {summary}"
                why = f"{why} Originating untrusted source: {source}{line_str}."
            elif severity == Severity.LOW:
                severity = Severity.MEDIUM
                category = "untrusted-text-influence"
                summary = f"[TAINTED] Action escalated to MEDIUM following untrusted read: {source}"
                why = f"Triggered after agent ingested untrusted content at {source}{line_str}."
            elif severity == Severity.CRITICAL:
                why = f"{why} Session is tainted by untrusted content from {source}{line_str}."

            if "R-TAINT-INFLUENCE" not in rule_ids:
                rule_ids.insert(0, "R-TAINT-INFLUENCE")


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
