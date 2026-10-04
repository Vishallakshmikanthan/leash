"""
daemon/receipt_builder.py - Builds Markdown PR-ready receipts from session audit logs.
Generates an auditable, comprehensive, pull-request-ready Agent Receipt detailing
actions, approvals, denials, blocked actions, changed files, added dependencies,
risk events, and overall session outcome.
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


class ReceiptBuilder:
    """Generates an auditable agent receipt for inclusion in Pull Requests."""

    @classmethod
    def extract_dependencies(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts added/evaluated dependencies from package gate events and shell commands."""
        deps: Dict[str, Dict[str, Any]] = {}

        # 1. Structured Package Gate events
        for e in events:
            ev_type = e.get("event_type")
            meta = e.get("metadata") or {}
            if ev_type == "package_gate_evaluation" or e.get("risk_category") == "package-install":
                pkg_name = meta.get("package_name") or e.get("target_path") or e.get("command", "")
                if not pkg_name:
                    continue
                version = meta.get("version") or "unspecified"
                verdict = (e.get("verdict") or "allow").upper()
                warnings = meta.get("warnings") or []
                reasons = meta.get("reasons") or []
                allow_once = meta.get("allow_once", False)
                lockfile_verified = meta.get("lockfile_verified", False)

                checks = []
                if lockfile_verified:
                    checks.append("Lockfile verified")
                else:
                    checks.append("Direct install")
                if warnings:
                    checks.extend(warnings)
                elif reasons:
                    checks.extend(reasons)
                else:
                    checks.append("Supply chain clean")

                deps[pkg_name] = {
                    "package": pkg_name,
                    "version": version,
                    "verdict": verdict,
                    "allow_once": allow_once,
                    "checks": ", ".join(checks),
                    "notes": meta.get("note") or ("Allow-once granted" if allow_once else "Evaluated by Package Gate"),
                }

        # 2. Heuristic extraction from shell install commands
        pkg_cmd_re = re.compile(
            r"(?:pip|pip3)\s+install\s+([a-zA-Z0-9_.\-]+(?:==[a-zA-Z0-9_.\-]+)?)|"
            r"(?:npm|yarn|pnpm)\s+(?:install|add)\s+([@a-zA-Z0-9_./\-]+)|"
            r"(?:cargo)\s+add\s+([a-zA-Z0-9_.\-]+)"
        )
        for e in events:
            cmd = e.get("command") or ""
            match = pkg_cmd_re.search(cmd)
            if match:
                raw_pkg = next((m for m in match.groups() if m), None)
                if raw_pkg and raw_pkg not in deps:
                    parts = raw_pkg.split("==") if "==" in raw_pkg else [raw_pkg, "latest"]
                    name = parts[0]
                    ver = parts[1] if len(parts) > 1 else "latest"
                    verdict = (e.get("verdict") or "allow").upper()
                    deps[name] = {
                        "package": name,
                        "version": ver,
                        "verdict": verdict,
                        "allow_once": False,
                        "checks": "Shell command intercepted",
                        "notes": "Extracted from install command",
                    }

        return list(deps.values())

    @classmethod
    def extract_risk_events(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts security and risk events (Canary alerts, prompt injection, high/critical risk)."""
        risk_events: List[Dict[str, Any]] = []

        for e in events:
            ev_type = e.get("event_type")
            cat = e.get("risk_category") or ""
            sev = (e.get("risk_severity") or "low").upper()
            verdict = (e.get("verdict") or "allow").upper()
            meta = e.get("metadata") or {}

            # Canary alert
            if ev_type == "canary_security_alert" or cat == "canary-touched":
                risk_events.append({
                    "type": "CANARY_ALERT",
                    "badge": "🛑 CRITICAL",
                    "title": "Canary Secret Access Attempted",
                    "details": f"Attempted unauthorized access to canary credential `{e.get('target_path') or meta.get('canary')}`",
                    "action": e.get("command") or e.get("target_path"),
                    "verdict": verdict,
                    "ts": e.get("ts", 0),
                })
            # Provenance / Prompt Injection
            elif ev_type == "provenance_event" or e.get("tainted") and cat in ("prompt-injection", "untrusted-read"):
                src = e.get("target_path") or meta.get("snippet") or "external input"
                line = meta.get("line")
                line_str = f":{line}" if line else ""
                risk_events.append({
                    "type": "PROVENANCE_TAINT",
                    "badge": "⚠️ TAINT DETECTED",
                    "title": "Untrusted Ingestion / Prompt Injection Suspected",
                    "details": f"Agent ingested untrusted content from `{src}{line_str}`. Session marked tainted.",
                    "action": meta.get("snippet") or src,
                    "verdict": verdict,
                    "ts": e.get("ts", 0),
                })
            # Rewind
            elif ev_type == "rewind":
                restored = meta.get("restored", False)
                status_str = "Restored successfully" if restored else "Restoration failed / denied"
                risk_events.append({
                    "type": "REWIND",
                    "badge": "⏪ REWIND",
                    "title": "Repository Snapshot Rollback",
                    "details": f"Session rewound to `{meta.get('snapshot_ref')}` ({status_str})",
                    "action": meta.get("note") or "Rewind executed",
                    "verdict": verdict,
                    "ts": e.get("ts", 0),
                })
            # Critical or High severity actions
            elif sev in ("CRITICAL", "HIGH") and verdict == "DENY":
                ra = e.get("risk_assessment") or {}
                why = ra.get("why") or meta.get("why") or "High risk action restricted by security policy"
                risk_events.append({
                    "type": "HIGH_RISK_BLOCK",
                    "badge": f"⛔ {sev}",
                    "title": ra.get("summary") or cat or "High Risk Operation Blocked",
                    "details": why,
                    "action": e.get("command") or e.get("target_path"),
                    "verdict": verdict,
                    "ts": e.get("ts", 0),
                })

        return risk_events

    @classmethod
    def extract_blocked_actions(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts all denied or blocked actions with reasons and safer alternatives."""
        blocked = []
        for e in events:
            verdict = (e.get("verdict") or "allow").lower()
            if verdict == "deny":
                ts = e.get("ts", 0)
                time_str = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%H:%M:%S")
                ra = e.get("risk_assessment") or {}
                meta = e.get("metadata") or {}
                cmd = e.get("command") or e.get("target_path") or "-"
                why = ra.get("why") or meta.get("blocked_reason") or meta.get("note") or "Blocked by Leash security policy"
                alt = ra.get("safer_alternative") or "Use scoped command within approved parameters"
                gate = e.get("risk_category") or (ra.get("rule_ids", [None])[0]) or e.get("decided_by") or "Security Gate"

                blocked.append({
                    "time": time_str,
                    "command": cmd,
                    "severity": (e.get("risk_severity") or "high").upper(),
                    "gate": gate,
                    "reason": why,
                    "safer_alternative": alt,
                    "decided_by": e.get("decided_by", "rule"),
                })
        return blocked

    @classmethod
    def extract_changed_files_from_events(cls, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts changed files mentioned in audit events (file_edit, git commits, etc.)."""
        seen: Dict[str, Dict[str, Any]] = {}
        for e in events:
            kind = e.get("kind") or ""
            target = e.get("target_path")
            if target and (kind in ("file_edit", "file_read", "git") or "edit" in kind):
                if target not in seen:
                    seen[target] = {
                        "path": target,
                        "status": "M" if kind != "file_read" else "R",
                        "status_label": "Modified" if kind != "file_read" else "Read",
                        "additions": 0,
                        "deletions": 0,
                    }
        return list(seen.values())

    @classmethod
    def determine_session_outcome(
        cls,
        events: List[Dict[str, Any]],
        termination_reason: Optional[str] = None,
        tainted: bool = False,
    ) -> Dict[str, str]:
        """Calculates the high-level security outcome and review recommendation for PR."""
        denied_count = sum(1 for e in events if e.get("verdict") == "deny")
        total_actions = len(events)
        canary_alerts = any(
            e.get("event_type") == "canary_security_alert" or e.get("risk_category") == "canary-touched"
            for e in events
        )

        if canary_alerts:
            return {
                "badge": "🛑 CRITICAL VIOLATION INTERCEPTED",
                "verdict": "BLOCKED ATTACK",
                "summary": "Agent attempted to read or exfiltrate private canary secrets. Action was blocked by Secret Fence.",
                "recommendation": "DO NOT MERGE without inspecting canary alert and agent logs.",
            }
        elif denied_count > 0:
            return {
                "badge": "🛡️ PROTECTED (RISKS MITIGATED)",
                "verdict": "VERIFIED WITH BLOCKS",
                "summary": f"Leash successfully intercepted and blocked {denied_count} unauthorized action(s). Allowed actions completed cleanly.",
                "recommendation": "Review the blocked actions section before merging to ensure intended agent behavior.",
            }
        elif tainted:
            return {
                "badge": "⚠️ COMPLETED (TAINTED SESSION)",
                "verdict": "PROVENANCE WARNING",
                "summary": "Agent ingested untrusted external documentation during the session. All actions conformed to policy.",
                "recommendation": "Inspect diff carefully for any subtle instructions derived from external text.",
            }
        elif total_actions == 0:
            return {
                "badge": "⚪ EMPTY SESSION",
                "verdict": "NO ACTIONS",
                "summary": "Session completed without any evaluated actions.",
                "recommendation": "No safety implications.",
            }
        else:
            return {
                "badge": "✅ CLEAN COMPLETION",
                "verdict": "VERIFIED SAFE",
                "summary": "All actions conformed to declared scope and low-risk allow patterns. Zero security violations.",
                "recommendation": "Standard code review applies. Safety layer verified clean execution.",
            }

    @classmethod
    def generate_markdown(
        cls,
        session_id: str,
        events: List[Dict[str, Any]],
        session_scope: Optional[Any] = None,
        changed_files: Optional[List[Dict[str, Any]]] = None,
        dependencies: Optional[List[Dict[str, Any]]] = None,
        risk_events: Optional[List[Dict[str, Any]]] = None,
        outcome: Optional[str] = None,
        termination_reason: Optional[str] = None,
        worktree_path: Optional[str] = None,
        branch_name: Optional[str] = None,
        agent_name: Optional[str] = None,
        task_description: Optional[str] = None,
    ) -> str:
        """Generates a clear, PR-ready Markdown Agent Receipt."""
        # 1. Resolve metadata from session_scope if provided
        scope_dict: Dict[str, Any] = {}
        if session_scope:
            if hasattr(session_scope, "to_dict"):
                scope_dict = session_scope.to_dict()
            elif isinstance(session_scope, dict):
                scope_dict = session_scope

        agent = agent_name or scope_dict.get("agent") or "coding-agent"
        worktree = worktree_path or scope_dict.get("worktree_path") or "default"
        branch = branch_name or scope_dict.get("branch_name") or f"leash/{session_id}"
        task_desc = task_description or scope_dict.get("task_description") or "Agent development task"
        reason = termination_reason or scope_dict.get("termination_reason") or "Session completed"
        is_tainted = bool(scope_dict.get("tainted")) or any(e.get("tainted") for e in events)

        # Infer agent name from events if not explicitly set
        if agent in ("unknown", "coding-agent"):
            for e in events:
                if e.get("agent") and e["agent"] not in ("unknown", "coding-agent"):
                    agent = e["agent"]
                    break

        # 2. Aggregate metrics
        total_actions = len(events)
        allowed_count = sum(1 for e in events if e.get("verdict") == "allow")
        denied_count = sum(1 for e in events if e.get("verdict") == "deny")
        tainted_count = sum(1 for e in events if e.get("tainted"))

        decisions_by_method: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        for e in events:
            method = e.get("decided_by", "auto")
            decisions_by_method[method] = decisions_by_method.get(method, 0) + 1
            sev = (e.get("risk_severity") or "low").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # 3. Resolve sections
        effective_changed_files = (
            changed_files
            or scope_dict.get("changed_files")
            or cls.extract_changed_files_from_events(events)
        )
        effective_deps = dependencies or cls.extract_dependencies(events)
        effective_risk_events = risk_events or cls.extract_risk_events(events)
        blocked_actions = cls.extract_blocked_actions(events)
        outcome_info = cls.determine_session_outcome(events, termination_reason=reason, tainted=is_tainted)
        if outcome:
            outcome_info["badge"] = outcome

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 4. Construct PR-ready Markdown document
        lines: List[str] = []

        # Header
        lines.append(f"# 🛡️ Leash Agent Session Receipt: `{session_id}`\n")
        lines.append(f"> **Session Outcome:** `{outcome_info['badge']}` | **Verdict:** `{outcome_info['verdict']}`  ")
        lines.append(f"> **Agent:** `{agent}` | **Branch:** `{branch}` | **Generated:** {now_str}\n")
        lines.append(f"{outcome_info['summary']}\n")
        lines.append("---\n")

        # Executive Summary Table
        lines.append("## 📊 Executive Summary\n")
        lines.append("| Metric | Count | Details |")
        lines.append("| :--- | :--- | :--- |")
        lines.append(f"| **Total Actions Evaluated** | `{total_actions}` | Intercepted at shell & tool boundary |")
        method_str = ", ".join(f"{k}: {v}" for k, v in decisions_by_method.items()) or "none"
        lines.append(f"| **Approved / Allowed** | `{allowed_count}` | Breakdown: {method_str} |")
        lines.append(f"| **Denied / Blocked** | `{denied_count}` | Prevented unauthorized or risky operations |")
        lines.append(f"| **Tainted Invocations** | `{tainted_count}` | Influenced by untrusted input (README/issues) |")
        lines.append(f"| **Changed Files** | `{len(effective_changed_files)}` | Modified / added in session worktree |")
        lines.append(f"| **Dependencies Evaluated** | `{len(effective_deps)}` | Verified by Package Gate |")
        lines.append(f"| **Security & Risk Events** | `{len(effective_risk_events)}` | Canary, injection, or high-risk detections |")
        lines.append("")

        # Session Scope & Context
        lines.append("## 🎯 Session Scope & Environment\n")
        lines.append(f"- **Task Description:** {task_desc}")
        lines.append(f"- **Git Worktree Isolation:** `{worktree}`")
        lines.append(f"- **Session Branch:** `{branch}`")
        lines.append(f"- **Lifecycle Termination:** {reason}")
        taint_status = "⚠️ Active (external content ingested)" if is_tainted else "✅ Clean (no untrusted reads)"
        lines.append(f"- **Provenance Status:** {taint_status}\n")

        # Blocked Actions Section (if any)
        lines.append("## ⛔ Blocked Actions & Security Interventions\n")
        if blocked_actions:
            lines.append("| Time | Attempted Action | Risk | Gate / Trigger | Why Blocked | Safer Alternative |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for b in blocked_actions:
                cmd_san = b["command"].replace("|", "\\|").replace("\n", " ")
                if len(cmd_san) > 50:
                    cmd_san = cmd_san[:47] + "..."
                why_san = b["reason"].replace("|", "\\|")
                alt_san = b["safer_alternative"].replace("|", "\\|")
                lines.append(f"| {b['time']} | `{cmd_san}` | **{b['severity']}** | {b['gate']} | {why_san} | {alt_san} |")
            lines.append("")
        else:
            lines.append("✅ *Zero actions blocked. All agent operations complied with security policy.*\n")

        # Changed Files Section
        lines.append("## 📁 Changed Files\n")
        if effective_changed_files:
            lines.append("| Status | File Path | Additions | Deletions |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for f in effective_changed_files:
                f_path = f.get("path") or f.get("file") or str(f)
                status_label = f.get("status_label") or f.get("status") or "Modified"
                adds = f.get("additions", 0)
                dels = f.get("deletions", 0)
                lines.append(f"| `{status_label}` | `{f_path}` | `+{adds}` | `-{dels}` |")
            lines.append("")
        else:
            lines.append("✨ *No persistent filesystem modifications detected for this session.*\n")

        # Added Dependencies Section (Package Gate)
        lines.append("## 📦 Added Dependencies (Package Gate)\n")
        if effective_deps:
            lines.append("| Package | Version | Verdict | Security Checks | Notes |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for d in effective_deps:
                pkg = d.get("package")
                ver = d.get("version") or "latest"
                verd = d.get("verdict", "ALLOW")
                verd_str = f"**{verd}**" if verd == "ALLOW" else f"⛔ **{verd}**"
                checks = d.get("checks") or "Verified"
                notes = d.get("notes") or "-"
                lines.append(f"| `{pkg}` | `{ver}` | {verd_str} | {checks} | {notes} |")
            lines.append("")
        else:
            lines.append("📦 *No new external dependencies were introduced or requested.*\n")

        # Security & Risk Events Section
        lines.append("## 🚨 Security & Risk Events\n")
        if effective_risk_events:
            for r in effective_risk_events:
                lines.append(f"- {r['badge']} **{r['title']}**")
                lines.append(f"  - **Details:** {r['details']}")
                if r.get("action"):
                    act_san = str(r['action']).replace('\n', ' ')
                    lines.append(f"  - **Target / Action:** `{act_san[:80]}`")
            lines.append("")
        else:
            lines.append("🛡️ *No security anomalies, canary exposures, or high-risk warnings recorded.*\n")

        # Complete Evaluated Actions Table (Collapsible for PR readability)
        lines.append("## 📝 Complete Evaluated Actions Timeline\n")
        lines.append(f"<details><summary><b>Click to expand full action log ({total_actions} actions)</b></summary>\n")
        lines.append("| Time | Kind | Command / Target | Severity | Verdict | By | Reason / Note |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

        for e in events:
            ts = e.get("ts", 0)
            time_str = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%H:%M:%S")
            kind = e.get("kind", "shell")
            cmd_or_target = (e.get("command") or e.get("target_path") or "-").replace("\n", " ")
            cmd_san = cmd_or_target.replace("|", "\\|")
            if len(cmd_san) > 55:
                cmd_san = cmd_san[:52] + "..."
            cmd_display = f"`{cmd_san}`"
            severity = (e.get("risk_severity") or "low").upper()
            verdict = (e.get("verdict") or "allow").upper()
            decided_by = e.get("decided_by", "auto")
            ra = e.get("risk_assessment") or {}
            note = ra.get("why") or e.get("metadata", {}).get("note") or ra.get("summary") or "-"
            note_san = str(note).replace("|", "\\|").replace("\n", " ")
            if len(note_san) > 45:
                note_san = note_san[:42] + "..."

            lines.append(f"| {time_str} | {kind} | {cmd_display} | {severity} | **{verdict}** | {decided_by} | {note_san} |")

        lines.append("\n</details>\n")

        # Pull Request Reviewer Recommendation & Checklist
        lines.append("## 📋 Pull Request Reviewer Guidance\n")
        lines.append(f"> **Recommendation:** {outcome_info['recommendation']}\n")
        lines.append("- [x] Interception & policy verification enforced by on-device Leash.")
        if blocked_actions:
            lines.append(f"- [ ] Review {len(blocked_actions)} blocked action(s) for developer intent.")
        else:
            lines.append("- [x] Zero unauthorized actions attempted.")
        if effective_deps:
            lines.append(f"- [ ] Verify {len(effective_deps)} package dependency addition(s).")
        if is_tainted:
            lines.append("- [ ] Note: Session was tainted; review changes for indirect prompt injection.")
        lines.append("- [ ] Confirm no secrets, canaries, or keys are committed to the PR diff.\n")

        # Footer
        lines.append("---\n*Verified by **Leash** on-device AI safety layer. Zero cloud telemetry. PR-ready receipt.*")

        return "\n".join(lines)

    @classmethod
    def save_receipt(
        cls,
        session_id: str,
        events: List[Dict[str, Any]],
        output_path: Path,
        session_scope: Optional[Any] = None,
        changed_files: Optional[List[Dict[str, Any]]] = None,
        dependencies: Optional[List[Dict[str, Any]]] = None,
        risk_events: Optional[List[Dict[str, Any]]] = None,
        outcome: Optional[str] = None,
        **kwargs: Any,
    ) -> Path:
        """Saves generated Markdown receipt to the designated file path."""
        content = cls.generate_markdown(
            session_id=session_id,
            events=events,
            session_scope=session_scope,
            changed_files=changed_files,
            dependencies=dependencies,
            risk_events=risk_events,
            outcome=outcome,
            **kwargs,
        )
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(content)
        return out_p
