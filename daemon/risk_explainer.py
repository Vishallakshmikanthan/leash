"""
daemon/risk_explainer.py - On-device risk explanation system for Leash.
Generates concise, plain-language explanations (summary, why it matters, safer alternative)
using an on-device model with an immediate, deterministic, category-specific rule-based
template fallback whenever the model is unavailable, slow, or invalid.
Enforcement remains 100% controlled by the existing rule engine.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable, Dict, Optional

from contracts.models import ActionRequest, RiskAssessment, Severity

logger = logging.getLogger("leash.risk_explainer")


@dataclass
class StructuredExplanation:
    """Standardized output schema for risk explanations."""
    summary: str
    why: str
    safer_alternative: str
    source: str  # "model" or "template"
    latency_ms: float = 0.0
    category: str = "normal-development"
    severity: str = "low"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StructuredExplanation:
        return cls(
            summary=str(data.get("summary", "")).strip(),
            why=str(data.get("why", "")).strip(),
            safer_alternative=str(data.get("safer_alternative", "")).strip(),
            source=str(data.get("source", "template")),
            latency_ms=float(data.get("latency_ms", 0.0)),
            category=str(data.get("category", "normal-development")),
            severity=str(data.get("severity", "low")),
        )


class TemplateFallbackEngine:
    """
    Immediate, deterministic rule-based template engine.
    Ensures zero blank cards and instant plain-language explanations
    tailored to every risk category and shell command structure.
    """

    @classmethod
    def _extract_target(cls, command: str) -> str:
        """Extracts the primary target file or path from command."""
        tokens = command.strip().split()
        for tok in reversed(tokens):
            if not tok.startswith("-") and not tok.startswith("--") and tok not in ("|", "&&", ";", ">", "<"):
                return tok
        return "target resource"

    @classmethod
    def _extract_fetcher_and_interpreter(cls, command: str) -> tuple[str, str]:
        cmd_lower = command.lower()
        fetcher = "curl" if "curl" in cmd_lower else ("wget" if "wget" in cmd_lower else "download tool")
        interp = "bash" if "bash" in cmd_lower else ("python" if "python" in cmd_lower else ("sh" if "sh" in cmd_lower else "shell"))
        return fetcher, interp

    @classmethod
    def generate(
        cls,
        command: str,
        category: str,
        severity: str = "low",
        context: Optional[Dict[str, Any]] = None,
    ) -> StructuredExplanation:
        """Generates a complete plain-language explanation from deterministic templates."""
        ctx = context or {}
        cmd = command.strip()
        cat = category.lower()
        target = ctx.get("target_path") or cls._extract_target(cmd)
        taint_source = ctx.get("taint_source")
        taint_line = ctx.get("taint_line")
        line_str = f":{taint_line}" if taint_line else ""
        existing_sum = ctx.get("existing_summary")
        existing_why = ctx.get("existing_why")
        existing_alt = ctx.get("existing_alternative")
        if existing_alt == "None needed.":
            existing_alt = None

        # Category 1: Remote Script Execution (pipe to sh)
        if cat in ("remote-script-execution", "r-net-pipe-exec"):
            fetcher, interp = cls._extract_fetcher_and_interpreter(cmd)
            summary = existing_sum or f"Piping unverified remote content from {fetcher} directly into {interp}."
            why = existing_why or (
                "Executing uninspected remote code bypasses local verification and can immediately "
                "compromise host credentials and system integrity."
            )
            safer_alt = existing_alt or f"Download script with `{fetcher} -O <file>`, inspect code manually, then execute."

        # Category 2: Destructive File Operations
        elif cat in ("destructive-file-operations", "destructive-deletion", "r-fs-root-rm", "r-fs-recursive-rm"):
            summary = existing_sum or f"Recursive deletion targeting directory or system files: `{target}`."
            why = existing_why or (
                "Irreversibly removes files and directories without recycling or confirmation, "
                "which can destroy project code or system assets."
            )
            safer_alt = existing_alt or f"Inspect files with `git status` or remove specific targets rather than `{target}`."

        # Category 3: Forceful Git Operations
        elif cat in ("forceful-git-operations", "force-git", "r-git-force-push", "r-git-hard-reset"):
            if "push" in cmd.lower():
                summary = existing_sum or "Force-pushing local changes to remote repository branch."
                why = existing_why or "Overwriting remote history destroys unmerged commits from collaborators on shared branches."
                safer_alt = existing_alt or "Use `git push --force-with-lease` or pull and rebase before pushing."
            else:
                summary = existing_sum or "Hard resetting git working tree and index."
                why = existing_why or "Discards all uncommitted changes and local worktree modifications permanently."
                safer_alt = existing_alt or "Use `git stash` to preserve modifications before changing git HEAD state."

        # Category 4: Secret Exposure & Canary Credentials
        elif cat in ("secret-exposure", "canary-touched", "r-secret-read", "r-secret-canary"):
            summary = existing_sum or f"Reading sensitive or private credential file: `{target}`."
            why = existing_why or (
                "Exposing secret tokens, private keys, or credentials prints sensitive data into command "
                "output buffers and LLM context history."
            )
            safer_alt = existing_alt or f"Reference environment variables directly instead of printing `{target}` contents."

        # Category 5: Package Installation & Supply Chain
        elif cat in ("package-install", "package-gate", "r-pkg-install", "r-pkg-typosquat"):
            pkg = ctx.get("package_name") or target
            warnings = ctx.get("warnings") or []
            warn_str = f" ({warnings[0]})" if warnings else ""
            summary = existing_sum or f"Installing package `{pkg}` from public registry{warn_str}."
            why = existing_why or (
                "External packages execute arbitrary pre-install lifecycle scripts and may contain typosquatted "
                "or hijacked malicious dependencies."
            )
            safer_alt = existing_alt or f"Verify package spelling `{pkg}` and inspect dependencies in lockfile before installing."

        # Category 6: Sensitive File Changes
        elif cat in ("sensitive-file-changes", "system-config-tamper"):
            summary = existing_sum or f"Attempting to modify system or host configuration: `{target}`."
            why = existing_why or "Modifying operating system files can alter network routing, DNS resolution, or user access controls."
            safer_alt = existing_alt or f"Confine edits to project repository files instead of modifying `{target}`."

        # Category 7: Permission Changes
        elif cat in ("permission-changes", "r-perm-chmod-broad"):
            summary = existing_sum or f"Broadening filesystem permissions with command `{cmd[:40]}`."
            why = existing_why or "Granting unrestricted read/write/execute rights creates privilege escalation vectors for other processes."
            safer_alt = existing_alt or "Apply least-privilege permission masks such as `chmod 755` or `chmod 644`."

        # Category 8: Outbound Data Transfer
        elif cat in ("outbound-data-transfer", "r-net-outbound"):
            summary = existing_sum or f"Transmitting data to external network endpoint: `{cmd[:45]}`."
            why = existing_why or "Unapproved network egress can exfiltrate local source code, environment secrets, or establish reverse shells."
            safer_alt = existing_alt or "Use local mock servers or request explicit network endpoint authorization."

        # Category 9: Untrusted Text Influence (Prompt Injection)
        elif cat in ("untrusted-text-influence", "prompt-injection", "r-taint-influence"):
            src = taint_source or "untrusted documentation"
            summary = ctx.get("existing_summary") or f"Action triggered after agent read untrusted content from `{src}{line_str}`."
            why = (
                ctx.get("existing_why")
                or f"External text in `{src}` may contain hidden prompt injection instructions attempting to hijack the agent to run dangerous commands."
            )
            safer_alt = ctx.get("existing_alternative") or f"Verify that `{cmd[:35]}` aligns with your original task rather than instructions in `{src}`."

        # Category 10: Hidden Text & Unicode Evasion
        elif cat in ("hidden-text-detected", "hidden-unicode"):
            summary = ctx.get("existing_summary") or "Command contains invisible Unicode or bidirectional control characters."
            why = ctx.get("existing_why") or "Invisible codepoints disguise malicious command segments so on-screen text does not match shell execution."
            safer_alt = ctx.get("existing_alternative") or "Re-type command in clean ASCII and verify raw character byte encoding."

        # Category 11: Scope Violations / Task Contract Drift
        elif cat in ("scope-violations", "scope-drift", "r-scope-violation"):
            summary = ctx.get("existing_summary") or f"Command or path `{target}` drifts outside declared session task scope."
            why = ctx.get("existing_why") or "The agent is executing outside the boundaries set at session start, risking unintended system impact."
            safer_alt = ctx.get("existing_alternative") or "Update allowed paths and commands in session scope contract before running."

        # Category 12: Runaway Behavior / Failure Loops
        elif cat in ("runaway-behavior-detected", "runaway-guard"):
            summary = ctx.get("existing_summary") or f"Agent is stuck in an execution failure loop with command `{cmd[:35]}`."
            why = ctx.get("existing_why") or "Consecutive failures indicate the agent is thrashing, which drains rate limits and risks file corruption."
            safer_alt = ctx.get("existing_alternative") or "Interrupt loop, review error message, and provide corrective instructions to agent."

        # Category 13: Rewind / Snapshot Rollback
        elif cat in ("rewind", "r-rewind"):
            snap = ctx.get("snapshot_ref") or "latest pre-action snapshot"
            summary = ctx.get("existing_summary") or f"Restoring git worktree state back to `{snap}`."
            why = ctx.get("existing_why") or "Rolling back discards uncommitted work in the worktree and resets repository files to the snapshot."
            safer_alt = ctx.get("existing_alternative") or "Inspect current worktree diff before executing rollback."

        # Default / Normal Development
        else:
            summary = ctx.get("existing_summary") or f"Executing standard development command: `{cmd[:45]}`."
            why = ctx.get("existing_why") or "Standard development command matching normal repository workflow."
            safer_alt = ctx.get("existing_alternative") or "None required."

        return StructuredExplanation(
            summary=summary,
            why=why,
            safer_alternative=safer_alt,
            source="template",
            category=category,
            severity=severity,
        )


class OnDeviceModelRunner:
    """
    Simulates or executes an on-device language model (e.g. Gemma 2B / Llama 3.2 via on-device runtime).
    Enforces strict output schema validation and maximum timeout.
    """

    def __init__(
        self,
        model_fn: Optional[Callable[[str, str, str, Dict[str, Any]], Awaitable[str] | str]] = None,
        timeout_seconds: float = 1.5,
    ):
        self.model_fn = model_fn
        self.timeout_seconds = timeout_seconds

    def build_prompt(self, command: str, category: str, severity: str, context: Dict[str, Any]) -> str:
        """Constructs a compact, zero-shot structured instruction prompt."""
        ctx_lines = []
        if context.get("target_path"):
            ctx_lines.append(f"Target: {context['target_path']}")
        if context.get("taint_source"):
            ctx_lines.append(f"Tainted by: {context['taint_source']}:{context.get('taint_line', 1)}")
        if context.get("agent"):
            ctx_lines.append(f"Agent: {context['agent']}")
        ctx_str = "; ".join(ctx_lines) if ctx_lines else "None"

        return (
            "You are Leash, an on-device AI bodyguard for coding agents. Explain this risky action in plain English.\n"
            f"Command: {command}\n"
            f"Category: {category}\n"
            f"Severity: {severity}\n"
            f"Context: {ctx_str}\n\n"
            "Return STRICT JSON with keys:\n"
            '{"summary": "<one plain sentence>", "why": "<why this matters / danger>", "safer_alternative": "<safer alternative>"}'
        )

    def validate_output(self, raw_text: str) -> Optional[Dict[str, str]]:
        """Validates that model output satisfies the strict JSON schema contract."""
        if not raw_text or not raw_text.strip():
            return None

        # Clean code fence if wrapped
        text = raw_text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        try:
            parsed = json.loads(text)
        except Exception:
            # Fallback: regex search for JSON block
            json_match = re.search(r"\{[\s\S]*\}", text)
            if not json_match:
                return None
            try:
                parsed = json.loads(json_match.group(0))
            except Exception:
                return None

        if not isinstance(parsed, dict):
            return None

        summary = str(parsed.get("summary", "")).strip()
        why = str(parsed.get("why", "")).strip()
        safer_alt = str(parsed.get("safer_alternative", "")).strip()

        # Contract: all three fields must be non-empty strings
        if not summary or not why or not safer_alt:
            return None

        return {
            "summary": summary,
            "why": why,
            "safer_alternative": safer_alt,
        }

    async def generate_async(
        self, command: str, category: str, severity: str, context: Dict[str, Any]
    ) -> Optional[Dict[str, str]]:
        """Invokes the model function with strict timeout and schema verification."""
        if self.model_fn is None:
            return None

        try:
            # Wrap execution with timeout
            async def _invoke():
                res = self.model_fn(command, category, severity, context)
                if asyncio.iscoroutine(res) or hasattr(res, "__await__"):
                    return await res
                return res

            raw_resp = await asyncio.wait_for(_invoke(), timeout=self.timeout_seconds)
            return self.validate_output(str(raw_resp))
        except asyncio.TimeoutError:
            logger.warning(f"On-device model exceeded timeout ({self.timeout_seconds}s); falling back to template")
            return None
        except Exception as ex:
            logger.warning(f"On-device model execution failed ({ex}); falling back to template")
            return None


class RiskExplanationEngine:
    """
    Coordinates on-device model explanations with deterministic rule-based template fallback.
    Guarantees:
    1. Enforcement remains 100% controlled by the existing rule engine.
    2. The model only explains the decision.
    3. Immediate template fallback whenever the model is unavailable, invalid, or too slow.
    4. Strict JSON output contract: summary, why, safer_alternative.
    5. Zero blank cards under all failure conditions.
    """

    def __init__(
        self,
        model_runner: Optional[OnDeviceModelRunner] = None,
        default_timeout_seconds: float = 1.5,
    ):
        self.model_runner = model_runner or OnDeviceModelRunner(timeout_seconds=default_timeout_seconds)
        self.template_engine = TemplateFallbackEngine

    def set_model_function(
        self,
        fn: Optional[Callable[[str, str, str, Dict[str, Any]], Awaitable[str] | str]],
        timeout_seconds: float = 1.5,
    ) -> None:
        """Configures or replaces the on-device model inference callable."""
        self.model_runner = OnDeviceModelRunner(model_fn=fn, timeout_seconds=timeout_seconds)

    def set_model_runner(
        self,
        fn: Optional[Callable[[str, str, str, Dict[str, Any]], Awaitable[str] | str]],
        timeout_seconds: float = 1.5,
    ) -> None:
        """Configures or replaces the on-device model inference callable."""
        self.set_model_function(fn, timeout_seconds=timeout_seconds)

    async def explain_async(
        self,
        command: str,
        category: str,
        severity: str = "low",
        context: Optional[Dict[str, Any]] = None,
    ) -> StructuredExplanation:
        """
        Asynchronously generates a structured explanation.
        Attempts model generation; falls back immediately to deterministic template on any failure.
        """
        start_time = time.time()
        ctx = dict(context or {})

        # 1. Attempt on-device model generation
        if self.model_runner and self.model_runner.model_fn is not None:
            model_res = await self.model_runner.generate_async(command, category, severity, ctx)
            if model_res:
                latency = (time.time() - start_time) * 1000
                return StructuredExplanation(
                    summary=model_res["summary"],
                    why=model_res["why"],
                    safer_alternative=model_res["safer_alternative"],
                    source="model",
                    latency_ms=latency,
                    category=category,
                    severity=severity,
                )

        # 2. Template Fallback (Immediate, Deterministic, Zero Blank Fields)
        latency = (time.time() - start_time) * 1000
        fallback = self.template_engine.generate(command, category, severity=severity, context=ctx)
        fallback.latency_ms = latency
        return fallback

    def explain(
        self,
        command: str,
        category: str,
        severity: str = "low",
        context: Optional[Dict[str, Any]] = None,
    ) -> StructuredExplanation:
        """
        Synchronous explanation entry point.
        Uses cached/template fallback synchronously, or runs asyncio loop safely.
        """
        start_time = time.time()
        ctx = dict(context or {})

        # If a synchronous model function is provided and running outside active event loop
        if self.model_runner and self.model_runner.model_fn is not None:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Running event loop: fallback to deterministic template synchronously
                    # to prevent event loop blocking, while async callers get full model inference
                    fallback = self.template_engine.generate(command, category, severity=severity, context=ctx)
                    fallback.latency_ms = (time.time() - start_time) * 1000
                    return fallback
                else:
                    return loop.run_until_complete(
                        self.explain_async(command, category, severity=severity, context=ctx)
                    )
            except RuntimeError:
                return asyncio.run(
                    self.explain_async(command, category, severity=severity, context=ctx)
                )

        fallback = self.template_engine.generate(command, category, severity=severity, context=ctx)
        fallback.latency_ms = (time.time() - start_time) * 1000
        return fallback

    def enrich_assessment(
        self,
        request: ActionRequest,
        assessment: RiskAssessment,
        explanation: Optional[StructuredExplanation] = None,
    ) -> RiskAssessment:
        """
        Attaches the structured explanation to the RiskAssessment without altering
        the security verdict, severity, or rule ids determined by the rule engine.
        """
        expl = explanation or self.explain(
            command=request.command or request.target_path or "",
            category=assessment.category,
            severity=assessment.severity.value if hasattr(assessment.severity, "value") else str(assessment.severity),
            context={
                "target_path": request.target_path,
                "agent": request.agent,
                "cwd": request.cwd,
                "taint_source": request.taint.source if request.taint else None,
                "taint_line": request.taint.line if request.taint else None,
                "rule_ids": assessment.rule_ids,
                "existing_summary": assessment.summary,
                "existing_why": assessment.why,
                "existing_alternative": assessment.safer_alternative,
            },
        )

        assessment.summary = expl.summary
        assessment.why = expl.why
        assessment.safer_alternative = expl.safer_alternative
        return assessment
