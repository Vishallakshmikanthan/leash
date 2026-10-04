"""
daemon/audit_logger.py - Append-only, structured, privacy-preserving JSONL audit logger for Leash sessions.
"""
from __future__ import annotations

import datetime
import json
import re
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from contracts.models import AuditEvent, ExecutionResult


from gates.secret_fence import SecretRedactor

_GLOBAL_REDACTOR = SecretRedactor()


def sanitize_text(text: Optional[str], max_len: int = 1000) -> Optional[str]:
    """Lightweight privacy scrubber removing secrets, canaries, and truncating long output."""
    if not text:
        return text
    clean = _GLOBAL_REDACTOR.redact(text)
    if len(clean) > max_len:
        clean = clean[:max_len] + "... [TRUNCATED]"
    return clean



class AuditLogger:
    """Thread-safe append-only, privacy-preserving audit logger writing to a JSONL file."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: AuditEvent) -> None:
        """Appends an AuditEvent to the JSONL log file with privacy scrubbing."""
        dict_rep = event.to_dict()
        # Redact potentially sensitive fields
        if "command" in dict_rep and dict_rep["command"]:
            dict_rep["command"] = sanitize_text(dict_rep["command"], max_len=1000)
        if "target_path" in dict_rep and dict_rep["target_path"]:
            dict_rep["target_path"] = sanitize_text(dict_rep["target_path"], max_len=500)
        if "execution_result" in dict_rep and isinstance(dict_rep["execution_result"], dict):
            res = dict_rep["execution_result"]
            if "stdout_snippet" in res and res["stdout_snippet"]:
                res["stdout_snippet"] = sanitize_text(res["stdout_snippet"], max_len=600)
            if "stderr_snippet" in res and res["stderr_snippet"]:
                res["stderr_snippet"] = sanitize_text(res["stderr_snippet"], max_len=600)

        line = json.dumps(dict_rep) + "\n"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)

    def record_action(
        self,
        session_id: str,
        action_id: str,
        kind: str,
        verdict: str,
        risk_severity: str,
        decided_by: str,
        command: Optional[str] = None,
        target_path: Optional[str] = None,
        risk_category: Optional[str] = None,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
        risk_assessment: Optional[Dict[str, Any]] = None,
        execution_result: Optional[Dict[str, Any]] = None,
        latency_ms: Optional[float] = None,
        snapshot_ref: Optional[str] = None,
        tainted: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Records an intercepted action with full context and structured risk assessment."""
        event = AuditEvent(
            event_id=f"evt_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="action_evaluated",
            action_id=action_id,
            kind=kind,
            command=sanitize_text(command, max_len=1000),
            target_path=sanitize_text(target_path, max_len=500),
            risk_severity=risk_severity,
            risk_category=risk_category,
            verdict=verdict,
            decided_by=decided_by,
            agent=agent or "unknown",
            worktree=worktree,
            risk_assessment=risk_assessment,
            execution_result=execution_result,
            latency_ms=latency_ms,
            snapshot_ref=snapshot_ref,
            tainted=tainted,
            metadata=metadata or {},
        )
        self.log(event)
        return event

    def record_execution_result(
        self,
        session_id: str,
        action_id: str,
        allowed: bool,
        exit_code: int,
        duration_ms: float = 0.0,
        stdout_snippet: Optional[str] = None,
        stderr_snippet: Optional[str] = None,
        blocked_reason: Optional[str] = None,
    ) -> AuditEvent:
        """Records the execution outcome of an action as a structured execution event."""
        exec_dict = {
            "allowed": allowed,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout_snippet": sanitize_text(stdout_snippet, max_len=600),
            "stderr_snippet": sanitize_text(stderr_snippet, max_len=600),
            "blocked_reason": sanitize_text(blocked_reason, max_len=500),
        }
        event = AuditEvent(
            event_id=f"evt_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="action_executed",
            action_id=action_id,
            kind="execution",
            risk_severity="low" if allowed else "high",
            verdict="allow" if allowed else "deny",
            decided_by="execution",
            execution_result=exec_dict,
            metadata={"exit_code": exit_code, "duration_ms": duration_ms},
        )
        self.log(event)
        return event

    def record_event(
        self,
        event_type: str,
        session_id: str,
        action_id: str,
        kind: str,
        verdict: str,
        risk_severity: str,
        decided_by: str,
        target_path: Optional[str] = None,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
        tainted: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=f"evt_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type=event_type,
            action_id=action_id,
            kind=kind,
            target_path=sanitize_text(target_path, max_len=500),
            risk_severity=risk_severity,
            verdict=verdict,
            decided_by=decided_by,
            agent=agent,
            worktree=worktree,
            tainted=tainted,
            metadata=metadata or {},
        )
        self.log(event)
        return event

    def record_provenance_event(
        self,
        event: Any,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
    ) -> AuditEvent:
        """Records a provenance untrusted content ingestion event."""
        metadata = {
            "flags": getattr(event, "flags", []),
            "snippet": sanitize_text(getattr(event, "snippet", None), max_len=300),
            "line": getattr(event, "line", None),
            "provenance_kind": getattr(event.kind, "value", str(getattr(event, "kind", ""))),
        }
        return self.record_event(
            event_type="provenance_event",
            session_id=event.session,
            action_id=event.id,
            kind=getattr(event.kind, "value", str(getattr(event, "kind", ""))),
            verdict="taint",
            risk_severity="high",
            decided_by="provenance_gate",
            target_path=getattr(event, "source", None),
            agent=agent,
            worktree=worktree,
            tainted=True,
            metadata=metadata,
        )


    def record_canary_alert(
        self,
        session_id: str,
        action_id: str,
        target_or_command: str,
        canary_token_or_file: str,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
    ) -> AuditEvent:
        """Records an immediate critical security alert when a canary credential is accessed or exposed."""
        event = AuditEvent(
            event_id=f"evt_canary_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="canary_security_alert",
            action_id=action_id,
            kind="canary_alert",
            command=sanitize_text(target_or_command, max_len=500),
            target_path=sanitize_text(canary_token_or_file, max_len=500),
            risk_severity="critical",
            risk_category="canary-touched",
            verdict="deny",
            decided_by="canary_fence",
            agent=agent or "unknown",
            worktree=worktree,
            tainted=True,
            metadata={
                "alert": "CANARY_CREDENTIAL_ACCESSED",
                "canary": sanitize_text(canary_token_or_file, max_len=100),
                "action": sanitize_text(target_or_command, max_len=200),
            },
        )
        self.log(event)
        return event

    def record_hidden_text_event(
        self,
        session_id: str,
        action_id: str,
        file_path: str,
        line: int,
        pattern_name: str,
        risk_reason: str,
        snippet: Optional[str] = None,
        severity: str = "medium",
        verdict: str = "deny",
        decided_by: str = "hidden_text_scanner",
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Records a hidden text / invisible Unicode / concealed instruction security event."""
        meta = {
            "file_path": sanitize_text(file_path, max_len=300),
            "line": line,
            "pattern_name": pattern_name,
            "risk_reason": risk_reason,
            "snippet": sanitize_text(snippet, max_len=300),
        }
        if metadata:
            meta.update(metadata)

        event = AuditEvent(
            event_id=f"evt_txt_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="hidden_text_detected",
            action_id=action_id,
            kind="hidden_text_detected",
            command=None,
            target_path=sanitize_text(file_path, max_len=500),
            risk_severity=severity,
            risk_category="hidden-text-detected",
            verdict=verdict,
            decided_by=decided_by,
            agent=agent or "unknown",
            worktree=worktree,
            tainted=True,
            metadata=meta,
        )
        self.log(event)
        return event

    def record_runaway_alert(
        self,
        session_id: str,
        action_id: str,
        reason: str,
        category: str = "runaway-behavior-detected",
        severity: str = "high",
        runaway_type: str = "general",
        command: Optional[str] = None,
        target_path: Optional[str] = None,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
        stats: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Records an immediate security alert when runaway behavior (failure streak, loop, burst, timeout) is detected."""
        meta = {
            "alert": "RUNAWAY_BEHAVIOR_DETECTED",
            "reason": sanitize_text(reason, max_len=300),
            "runaway_type": runaway_type,
            "stats": stats or {},
        }
        if metadata:
            meta.update(metadata)

        event = AuditEvent(
            event_id=f"evt_runaway_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="runaway_security_alert",
            action_id=action_id,
            kind="runaway_alert",
            command=sanitize_text(command, max_len=500),
            target_path=sanitize_text(target_path, max_len=500),
            risk_severity=severity,
            risk_category=category,
            verdict="paused",
            decided_by="runaway_guard",
            agent=agent or "unknown",
            worktree=worktree,
            metadata=meta,
        )
        self.log(event)
        return event

    def record_package_gate_event(
        self,
        session_id: str,
        action_id: str,
        package_name: str,
        verdict: str,
        risk_severity: str,
        decided_by: str = "package_gate",
        version: Optional[str] = None,
        reasons: Optional[List[str]] = None,
        warnings: Optional[List[str]] = None,
        allow_once: bool = False,
        lockfile_verified: bool = False,
        offline_mode: bool = True,
        command: Optional[str] = None,
        agent: Optional[str] = None,
        worktree: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """Records a package gate supply chain evaluation event."""
        meta = {
            "package_name": package_name,
            "version": version,
            "reasons": reasons or [],
            "warnings": warnings or [],
            "allow_once": allow_once,
            "lockfile_verified": lockfile_verified,
            "offline_mode": offline_mode,
        }
        if metadata:
            meta.update(metadata)

        event = AuditEvent(
            event_id=f"evt_pkg_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="package_gate_evaluation",
            action_id=action_id,
            kind="package_install",
            command=sanitize_text(command or f"install {package_name}", max_len=500),
            target_path=package_name,
            risk_severity=risk_severity,
            risk_category="package-install",
            verdict=verdict,
            decided_by=decided_by,
            agent=agent or "unknown",
            worktree=worktree,
            metadata=meta,
        )
        self.log(event)
        return event


    def read_session_events(self, session_id: str) -> List[Dict[str, Any]]:
        """Reads raw audit events recorded for a given session."""
        if not self.log_path.exists():
            return []
        events: List[Dict[str, Any]] = []
        with self._lock:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("session_id") == session_id:
                            events.append(record)
                    except json.JSONDecodeError:
                        continue
        return events

    def read_all_events(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Reads all audit events across all sessions, newest first."""
        if not self.log_path.exists():
            return []
        events: List[Dict[str, Any]] = []
        with self._lock:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        events.reverse()
        if limit is not None:
            return events[:limit]
        return events

    def list_sessions(self) -> List[Dict[str, Any]]:
        """Returns a list of all distinct sessions with activity overview."""
        if not self.log_path.exists():
            return []
        session_map: Dict[str, Dict[str, Any]] = {}
        with self._lock:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                        s_id = rec.get("session_id")
                        if not s_id:
                            continue
                        if s_id not in session_map:
                            session_map[s_id] = {
                                "session_id": s_id,
                                "agent": rec.get("agent") or "unknown",
                                "worktree": rec.get("worktree"),
                                "start_time": rec.get("ts", 0),
                                "last_activity": rec.get("ts", 0),
                                "total_actions": 0,
                                "allowed_count": 0,
                                "denied_count": 0,
                                "tainted": False,
                            }
                        s_entry = session_map[s_id]
                        s_entry["last_activity"] = max(s_entry["last_activity"], rec.get("ts", 0))
                        if rec.get("agent") and rec["agent"] != "unknown":
                            s_entry["agent"] = rec["agent"]
                        if rec.get("worktree"):
                            s_entry["worktree"] = rec["worktree"]
                        if rec.get("tainted"):
                            s_entry["tainted"] = True

                        if rec.get("event_type") == "action_evaluated":
                            s_entry["total_actions"] += 1
                            if rec.get("verdict") == "allow":
                                s_entry["allowed_count"] += 1
                            elif rec.get("verdict") == "deny":
                                s_entry["denied_count"] += 1
                    except json.JSONDecodeError:
                        continue

        sessions = list(session_map.values())
        sessions.sort(key=lambda s: s["last_activity"], reverse=True)
        return sessions

    def get_session_activity(self, session_id: str) -> Dict[str, Any]:
        """
        Builds a comprehensive, session-level activity view.
        Explains what the agent attempted, what Leash allowed or blocked, and why.
        Correlates action evaluation with its execution result.
        """
        raw_events = self.read_session_events(session_id)
        if not raw_events:
            return {
                "session_id": session_id,
                "agent": "unknown",
                "worktree": None,
                "total_actions": 0,
                "allowed_count": 0,
                "blocked_count": 0,
                "tainted_count": 0,
                "decisions_by_method": {},
                "severity_breakdown": {},
                "timeline": [],
                "rewinds": [],
            }

        actions: Dict[str, Dict[str, Any]] = {}
        ordered_action_ids: List[str] = []
        exec_map: Dict[str, Dict[str, Any]] = {}
        rewinds: List[Dict[str, Any]] = []

        agent_name = "unknown"
        worktree_path = None
        tainted_session = False

        for ev in raw_events:
            if ev.get("agent") and ev["agent"] != "unknown":
                agent_name = ev["agent"]
            if ev.get("worktree"):
                worktree_path = ev["worktree"]
            if ev.get("tainted"):
                tainted_session = True

            ev_type = ev.get("event_type")
            act_id = ev.get("action_id")

            if ev_type == "action_evaluated" and act_id:
                if act_id not in actions:
                    actions[act_id] = ev
                    ordered_action_ids.append(act_id)
                else:
                    # Update with newer data if needed
                    actions[act_id].update(ev)
            elif ev_type == "action_executed" and act_id:
                exec_map[act_id] = ev.get("execution_result") or {}
            elif ev_type == "rewind":
                meta = ev.get("metadata") or {}
                rewinds.append({
                    "rewind_id": act_id,
                    "ts": ev.get("ts", 0),
                    "verdict": ev.get("verdict"),
                    "decided_by": ev.get("decided_by"),
                    "snapshot_ref": meta.get("snapshot_ref"),
                    "snapshot_action_id": meta.get("snapshot_action_id"),
                    "restored": meta.get("restored", False),
                    "note": meta.get("note"),
                    "scope_notice": meta.get("scope_notice"),
                })

        # Merge execution results into action evaluations
        timeline: List[Dict[str, Any]] = []
        allowed_count = 0
        blocked_count = 0
        tainted_count = 0
        methods: Dict[str, int] = {}
        severities: Dict[str, int] = {}

        for act_id in ordered_action_ids:
            act = actions[act_id]
            ts = act.get("ts", 0)
            iso_time = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()
            verdict = act.get("verdict", "allow")
            decided_by = act.get("decided_by", "auto")
            severity = act.get("risk_severity", "low")
            is_tainted = act.get("tainted", False)

            if verdict == "allow":
                allowed_count += 1
            else:
                blocked_count += 1

            if is_tainted:
                tainted_count += 1

            methods[decided_by] = methods.get(decided_by, 0) + 1
            severities[severity] = severities.get(severity, 0) + 1

            # Resolve execution result: first check if embedded in act, then check exec_map
            exec_res = act.get("execution_result") or exec_map.get(act_id)
            if not exec_res:
                exec_res = {
                    "allowed": verdict == "allow",
                    "exit_code": 0 if verdict == "allow" else 126,
                    "duration_ms": act.get("latency_ms", 0.0),
                    "blocked_reason": act.get("metadata", {}).get("blocked_reason") or (
                        "Blocked by Leash policy" if verdict == "deny" else None
                    ),
                }

            risk_assessment = act.get("risk_assessment") or {}
            why_text = risk_assessment.get("why") or act.get("metadata", {}).get("why") or (
                "Standard safe command allowed by rule" if verdict == "allow" else "Action restricted by security policy"
            )
            summary_text = risk_assessment.get("summary") or act.get("risk_category") or "Evaluated action"

            timeline_item = {
                "action_id": act_id,
                "ts": ts,
                "timestamp_iso": iso_time,
                "kind": act.get("kind", "shell"),
                "command": act.get("command") or act.get("target_path") or "-",
                "target_path": act.get("target_path"),
                "agent": act.get("agent") or agent_name,
                "worktree": act.get("worktree") or worktree_path,
                "verdict": verdict,
                "decision_method": decided_by,
                "risk_severity": severity,
                "risk_category": act.get("risk_category", "general"),
                "risk_summary": summary_text,
                "why": why_text,
                "safer_alternative": risk_assessment.get("safer_alternative"),
                "rule_ids": risk_assessment.get("rule_ids", []),
                "tainted": is_tainted,
                "taint_source": risk_assessment.get("taint_source"),
                "taint_line": risk_assessment.get("taint_line"),
                "snapshot_ref": act.get("snapshot_ref"),
                "latency_ms": act.get("latency_ms", 0.0),
                "execution_result": exec_res,
            }
            timeline.append(timeline_item)

        return {
            "session_id": session_id,
            "agent": agent_name,
            "worktree": worktree_path,
            "tainted": tainted_session,
            "total_actions": len(timeline),
            "allowed_count": allowed_count,
            "blocked_count": blocked_count,
            "tainted_count": tainted_count,
            "decisions_by_method": methods,
            "severity_breakdown": severities,
            "timeline": timeline,
            "rewinds": rewinds,
        }
