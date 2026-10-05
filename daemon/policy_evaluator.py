"""
daemon/policy_evaluator.py - Rule-first risk engine with structured shell parsing, modular gates, and taint escalation.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, PolicyOutcome, RiskAssessment, Severity
from daemon.allowlist import ArgumentAwareAllowlist
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
    RunawayBehaviorRule,
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
from daemon.risk_explainer import RiskExplanationEngine, StructuredExplanation


class PolicyEvaluator:
    """Evaluates ActionRequests with structured shell parsing, modular security gates, and provenance escalation."""

    def __init__(
        self,
        allow_command_patterns: Optional[List[str]] = None,
        custom_rules: Optional[List[BaseRule]] = None,
        custom_gates: Optional[List[BaseGate]] = None,
        mode: str = "balanced",
    ):
        self.mode = mode.lower()  # "strict", "balanced", or "learning"
        self.allowlist = ArgumentAwareAllowlist(mode=self.mode)
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
            RunawayBehaviorRule(),
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
        self.explainer = RiskExplanationEngine()

    def set_model_explainer(self, model_fn, timeout_seconds: float = 1.5) -> None:
        """Sets or updates the model explanation provider."""
        self.explainer.set_model_runner(model_fn, timeout_seconds=timeout_seconds)

    def register_rule(self, rule: BaseRule) -> None:
        """Dynamically registers an additional policy rule."""
        self.rules.insert(0, rule)

    def register_gate(self, gate: BaseGate) -> None:
        """Dynamically registers an additional security gate."""
        self.gates.append(gate)
        if isinstance(gate, PackageGate):
            self.package_gate = gate

    def is_quick_allow(self, request: ActionRequest) -> bool:
        """Quickly checks whether an ActionRequest can be safely executed without phone notification (M4.1)."""
        if request.taint.tainted or request.scope_flags:
            return False

        assessment = self.evaluate(request)
        return assessment.outcome == PolicyOutcome.ALLOW

    def evaluate(self, request: ActionRequest) -> RiskAssessment:
        """Evaluates an ActionRequest and returns a comprehensive RiskAssessment with explicit PolicyOutcome (M4.1)."""
        # 1. Parse shell command structured AST
        cmd_str = request.command or ""
        parsed = ShellParser.parse(cmd_str)

        all_matches: List[RuleMatch] = []
        rule_ids: List[str] = []

        # 2. Argument-aware allowlist evaluation (M4.3)
        allow_outcome = PolicyOutcome.ASK
        allow_reason = "Non-shell action requires evaluation."
        if request.kind == ActionKind.SHELL:
            allow_outcome, allow_reason = self.allowlist.evaluate_parsed(parsed, cwd=request.cwd)
        elif request.kind in (ActionKind.FILE_READ, ActionKind.TOOL_CALL):
            target_p = request.target_path or (request.tool_args.get("path") if isinstance(request.tool_args, dict) else None)
            if target_p:
                if self.allowlist._is_path_safe(str(target_p), cwd=request.cwd or request.worktree):
                    allow_outcome = PolicyOutcome.ALLOW
                    allow_reason = "Safe workspace file read or tool call."
                else:
                    allow_outcome = PolicyOutcome.ASK
                    allow_reason = "Target path outside worktree or matches sensitive credential pattern."
            else:
                allow_outcome = PolicyOutcome.ALLOW
                allow_reason = "Safe non-shell tool invocation."

        # 3. Check hard-deny pipe rules: reader to network (M4.5)
        if parsed.has_reader_to_network_pipe:
            all_matches.append(
                RuleMatch(
                    rule_id="R-NET-EXFIL-PIPE",
                    category="outbound-data-transfer",
                    severity=Severity.HIGH,
                    summary="Piping data from local file reader into network command is denied.",
                    why="Chaining local reading tools (tar, cat) directly into network tools (ssh, nc, curl) indicates exfiltration.",
                    safer_alternative="Inspect data locally before transferring via explicit reviewed steps.",
                )
            )
            rule_ids.append("R-NET-EXFIL-PIPE")

        # 4. Evaluate all rules
        for rule in self.rules:
            match = rule.evaluate(request, parsed)
            if match:
                all_matches.append(match)
                if match.rule_id not in rule_ids:
                    rule_ids.append(match.rule_id)

        # 5. Evaluate all modular security gates
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

        # 6. Determine highest severity match
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
        }

        # Filter out normal development if dangerous matches exist
        non_dev_matches = [m for m in all_matches if m.category != "normal-development"]

        # Hard DENY rule IDs (M4.1: matches a hard rule)
        HARD_DENY_RULES = {
            "R-FS-DESTRUCTIVE-ROOT",
            "R-FS-DESTRUCTIVE",
            "R-NET-PIPE-EXEC",
            "R-NET-EXFIL-PIPE",
            "R-NET-EXFIL-SECRET",
            "R-GIT-RESET-HARD",
            "R-SECRET-CANARY",
        }

        if non_dev_matches:
            candidates = non_dev_matches
            candidates.sort(key=lambda m: severity_order.get(m.severity, 0), reverse=True)
            primary = candidates[0]
            severity = primary.severity
            category = primary.category
            summary = primary.summary
            why = primary.why
            safer_alternative = primary.safer_alternative

            # Check if any candidate is a hard DENY rule
            is_hard_deny = any(m.rule_id in HARD_DENY_RULES for m in non_dev_matches) or (
                primary.category == "destructive-file-operations" and ("mkfs" in cmd_str or "~" in cmd_str)
            )
            outcome = PolicyOutcome.DENY if is_hard_deny else PolicyOutcome.ASK
        else:
            if allow_outcome == PolicyOutcome.ALLOW and not request.taint.tainted and not request.scope_flags:
                severity = Severity.LOW
                category = "normal-development"
                summary = "Safe standard development action allowed by policy."
                why = allow_reason
                safer_alternative = "None needed."
                outcome = PolicyOutcome.ALLOW
                if not rule_ids:
                    rule_ids.append("R-DEV-ALLOW")
            elif allow_outcome == PolicyOutcome.DENY:
                severity = Severity.HIGH
                category = "policy-deny"
                summary = f"Denied by policy: {allow_reason}"
                why = allow_reason
                safer_alternative = "Consult project security policy."
                outcome = PolicyOutcome.DENY
                rule_ids.append("R-ALLOWLIST-DENY")
            else:
                severity = Severity.MEDIUM
                category = "unknown-command"
                summary = f"Unknown or unverified command requires approval: {allow_reason}"
                why = "Commands not on explicit allowlist require human confirmation."
                safer_alternative = "Use explicit standard development commands."
                outcome = PolicyOutcome.ASK
                rule_ids.append("R-UNKNOWN-ASK")

        # 7. Provenance-based escalation (M5.2)
        tainted_escalation = False
        if request.taint.tainted:
            tainted_escalation = True
            source = request.taint.source or "unknown"
            line_str = f":{request.taint.line}" if request.taint.line is not None else ""

            if outcome == PolicyOutcome.ALLOW:
                outcome = PolicyOutcome.ASK
                severity = Severity.MEDIUM
                category = "untrusted-text-influence"
                summary = f"[TAINTED] Action escalated to ASK following untrusted read: {source}"
                why = f"Triggered after agent ingested untrusted content at {source}{line_str}."
            elif severity == Severity.MEDIUM:
                severity = Severity.HIGH
                category = "untrusted-text-influence"
                summary = f"[TAINTED] Action escalated to HIGH following untrusted read: {source}"
                why = f"Triggered after agent ingested untrusted content at {source}{line_str}."
            elif severity == Severity.HIGH:
                category = "untrusted-text-influence" if category == "normal-development" else category
                summary = f"[TAINTED] High-risk action following untrusted read: {source} - {summary}"
                why = f"{why} Originating untrusted source: {source}{line_str}."
            elif severity == Severity.CRITICAL:
                why = f"{why} Session is tainted by untrusted content from {source}{line_str}."

            if "R-TAINT-INFLUENCE" not in rule_ids:
                rule_ids.insert(0, "R-TAINT-INFLUENCE")

        assessment = RiskAssessment(
            id=f"r_{uuid.uuid4().hex[:12]}",
            action_id=request.id,
            severity=severity,
            category=category,
            rule_ids=rule_ids if rule_ids else ["R-DEV-ALLOW"],
            summary=summary,
            why=why,
            safer_alternative=safer_alternative,
            outcome=outcome,
            tainted_escalation=tainted_escalation,
            taint_source=request.taint.source if request.taint.tainted else None,
            taint_line=request.taint.line if request.taint.tainted else None,
        )

        return self.explainer.enrich_assessment(request, assessment)
