"""
daemon/audit_logger.py - Append-only JSONL audit logging for Leash sessions.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from contracts.models import AuditEvent


class AuditLogger:
    """Thread-safe append-only audit logger writing to a JSONL file."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self._lock = threading.Lock()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict()) + "\n"
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
        latency_ms: Optional[float] = None,
        snapshot_ref: Optional[str] = None,
        tainted: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=f"evt_{int(time.time()*1000)}",
            session_id=session_id,
            ts=int(time.time()),
            event_type="action_evaluated",
            action_id=action_id,
            kind=kind,
            command=command,
            target_path=target_path,
            risk_severity=risk_severity,
            risk_category=risk_category,
            verdict=verdict,
            decided_by=decided_by,
            latency_ms=latency_ms,
            snapshot_ref=snapshot_ref,
            tainted=tainted,
            metadata=metadata or {},
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
            target_path=target_path,
            risk_severity=risk_severity,
            verdict=verdict,
            decided_by=decided_by,
            tainted=tainted,
            metadata=metadata or {},
        )
        self.log(event)
        return event

    def read_session_events(self, session_id: str) -> List[Dict[str, Any]]:
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
