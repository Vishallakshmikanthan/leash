"""
contracts/models.py - Core domain models for the Leash protocol.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionKind(str, Enum):
    SHELL = "shell"
    FILE_READ = "file_read"
    FILE_EDIT = "file_edit"
    TOOL_CALL = "tool_call"
    INSTALL = "install"
    GIT = "git"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class DecidedBy(str, Enum):
    BIOMETRIC = "biometric"
    TAP = "tap"
    AUTO = "auto"
    TIMEOUT = "timeout"
    RULE = "rule"


class ProvenanceKind(str, Enum):
    UNTRUSTED_READ = "untrusted_read"
    HIDDEN_TEXT_DETECTED = "hidden_text_detected"
    CANARY_READ = "canary_read"
    PROMPT_INJECTION_SUSPECTED = "prompt_injection_suspected"


class SessionState(str, Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    PAUSED = "paused"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    FAILED = "failed"


@dataclass
class TaintContext:
    tainted: bool = False
    source: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TaintContext:
        return cls(
            tainted=bool(data.get("tainted", False)),
            source=data.get("source"),
            line=data.get("line"),
        )


@dataclass
class ActionRequest:
    id: str
    session: str
    ts: int
    nonce: str
    kind: ActionKind
    agent: str
    cwd: str
    command: Optional[str] = None
    target_path: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    worktree: Optional[str] = None
    taint: TaintContext = field(default_factory=TaintContext)
    scope_flags: List[str] = field(default_factory=list)
    sig: str = ""

    def payload_for_signature(self) -> bytes:
        """Deterministic canonical representation for signing."""
        clean_dict = {
            "id": self.id,
            "session": self.session,
            "ts": self.ts,
            "nonce": self.nonce,
            "kind": self.kind.value if isinstance(self.kind, ActionKind) else self.kind,
            "agent": self.agent,
            "cwd": self.cwd,
            "command": self.command,
            "target_path": self.target_path,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "worktree": self.worktree,
            "taint": self.taint.to_dict() if isinstance(self.taint, TaintContext) else self.taint,
            "scope_flags": self.scope_flags,
        }
        return json.dumps(clean_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["kind"] = self.kind.value if isinstance(self.kind, ActionKind) else self.kind
        if isinstance(self.taint, TaintContext):
            res["taint"] = self.taint.to_dict()
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ActionRequest:
        taint_raw = data.get("taint", {})
        taint = TaintContext.from_dict(taint_raw) if isinstance(taint_raw, dict) else TaintContext()
        return cls(
            id=data["id"],
            session=data["session"],
            ts=data["ts"],
            nonce=data["nonce"],
            kind=ActionKind(data["kind"]),
            agent=data.get("agent", "unknown"),
            cwd=data.get("cwd", "."),
            command=data.get("command"),
            target_path=data.get("target_path"),
            tool_name=data.get("tool_name"),
            tool_args=data.get("tool_args"),
            worktree=data.get("worktree"),
            taint=taint,
            scope_flags=data.get("scope_flags", []),
            sig=data.get("sig", ""),
        )


@dataclass
class Decision:
    id: str
    action_id: str
    session: str
    ts: int
    nonce: str
    verdict: Verdict
    by: DecidedBy
    note: Optional[str] = None
    sig: str = ""

    def payload_for_signature(self) -> bytes:
        clean_dict = {
            "action_id": self.action_id,
            "by": self.by.value if isinstance(self.by, DecidedBy) else self.by,
            "id": self.id,
            "nonce": self.nonce,
            "note": self.note or "",
            "session": self.session,
            "ts": self.ts,
            "verdict": self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict,
        }
        return json.dumps(clean_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["verdict"] = self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict
        res["by"] = self.by.value if isinstance(self.by, DecidedBy) else self.by
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Decision:
        return cls(
            id=data["id"],
            action_id=data["action_id"],
            session=data["session"],
            ts=data["ts"],
            nonce=data["nonce"],
            verdict=Verdict(data["verdict"]),
            by=DecidedBy(data["by"]),
            note=data.get("note"),
            sig=data.get("sig", ""),
        )


@dataclass
class CommandResult:
    action_id: str
    session_id: str
    verdict: Verdict
    allowed: bool
    exit_code: int
    stdout: str
    stderr: str
    blocked_reason: Optional[str] = None
    risk_assessment: Optional[RiskAssessment] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["verdict"] = self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict
        if self.risk_assessment:
            res["risk_assessment"] = self.risk_assessment.to_dict()
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CommandResult:
        assessment_raw = data.get("risk_assessment")
        assessment = RiskAssessment.from_dict(assessment_raw) if assessment_raw else None
        return cls(
            action_id=data["action_id"],
            session_id=data["session_id"],
            verdict=Verdict(data["verdict"]),
            allowed=bool(data["allowed"]),
            exit_code=int(data["exit_code"]),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            blocked_reason=data.get("blocked_reason"),
            risk_assessment=assessment,
            duration_ms=float(data.get("duration_ms", 0.0)),
        )


@dataclass
class RiskAssessment:
    id: str
    action_id: str
    severity: Severity
    category: str
    rule_ids: List[str]
    summary: str
    why: str
    safer_alternative: str
    tainted_escalation: bool = False
    taint_source: Optional[str] = None
    taint_line: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["severity"] = self.severity.value if isinstance(self.severity, Severity) else self.severity
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RiskAssessment:
        return cls(
            id=data["id"],
            action_id=data["action_id"],
            severity=Severity(data["severity"]),
            category=data["category"],
            rule_ids=data.get("rule_ids", []),
            summary=data["summary"],
            why=data["why"],
            safer_alternative=data["safer_alternative"],
            tainted_escalation=bool(data.get("tainted_escalation", False)),
            taint_source=data.get("taint_source"),
            taint_line=data.get("taint_line"),
        )


@dataclass
class ProvenanceEvent:
    id: str
    session: str
    ts: int
    kind: ProvenanceKind
    source: str
    line: Optional[int] = None
    flags: List[str] = field(default_factory=list)
    snippet: Optional[str] = None
    nonce: str = ""
    sig: str = ""

    def payload_for_signature(self) -> bytes:
        clean_dict = {
            "flags": self.flags,
            "id": self.id,
            "kind": self.kind.value if isinstance(self.kind, ProvenanceKind) else self.kind,
            "line": self.line,
            "nonce": self.nonce,
            "session": self.session,
            "snippet": self.snippet,
            "source": self.source,
            "ts": self.ts,
        }
        return json.dumps(clean_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["kind"] = self.kind.value if isinstance(self.kind, ProvenanceKind) else self.kind
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProvenanceEvent:
        return cls(
            id=data["id"],
            session=data["session"],
            ts=data["ts"],
            kind=ProvenanceKind(data["kind"]),
            source=data["source"],
            line=data.get("line"),
            flags=data.get("flags", []),
            snippet=data.get("snippet"),
            nonce=data.get("nonce", ""),
            sig=data.get("sig", ""),
        )



@dataclass
class SnapshotRef:
    session: str
    index: int
    git_ref: str
    commit_sha: str
    created_at: int
    description: str
    action_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SessionScope:
    session_id: str
    created_at: int
    worktree_path: str
    repo_path: str
    allowed_paths: List[str] = field(default_factory=list)
    allowed_commands: List[str] = field(default_factory=list)
    allowed_hosts: List[str] = field(default_factory=list)
    agent: str = "coding-agent"
    state: SessionState = SessionState.ACTIVE
    task_description: Optional[str] = None
    branch_name: Optional[str] = None
    tainted: bool = False
    taint_events: List[str] = field(default_factory=list)
    snapshots: List[str] = field(default_factory=list)
    terminated_at: Optional[int] = None
    termination_reason: Optional[str] = None
    changed_files: List[Dict[str, Any]] = field(default_factory=list)
    receipt_markdown: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["state"] = self.state.value if isinstance(self.state, SessionState) else str(self.state)
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SessionScope:
        state_raw = data.get("state", "active")
        try:
            state = SessionState(state_raw)
        except ValueError:
            state = SessionState.ACTIVE
        return cls(
            session_id=data["session_id"],
            created_at=int(data["created_at"]),
            worktree_path=data["worktree_path"],
            repo_path=data["repo_path"],
            allowed_paths=data.get("allowed_paths", []),
            allowed_commands=data.get("allowed_commands", []),
            allowed_hosts=data.get("allowed_hosts", []),
            agent=data.get("agent", "coding-agent"),
            state=state,
            task_description=data.get("task_description"),
            branch_name=data.get("branch_name"),
            tainted=bool(data.get("tainted", False)),
            taint_events=data.get("taint_events", []),
            snapshots=data.get("snapshots", []),
            terminated_at=data.get("terminated_at"),
            termination_reason=data.get("termination_reason"),
            changed_files=data.get("changed_files", []),
            receipt_markdown=data.get("receipt_markdown"),
        )


@dataclass
class ExecutionResult:
    allowed: bool
    exit_code: int
    duration_ms: float = 0.0
    stdout_snippet: Optional[str] = None
    stderr_snippet: Optional[str] = None
    blocked_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExecutionResult:
        return cls(
            allowed=bool(data.get("allowed", False)),
            exit_code=int(data.get("exit_code", 0)),
            duration_ms=float(data.get("duration_ms", 0.0)),
            stdout_snippet=data.get("stdout_snippet"),
            stderr_snippet=data.get("stderr_snippet"),
            blocked_reason=data.get("blocked_reason"),
        )


@dataclass
class AuditEvent:
    event_id: str
    session_id: str
    ts: int
    event_type: str
    action_id: str
    kind: str
    risk_severity: str
    verdict: str
    decided_by: str
    command: Optional[str] = None
    target_path: Optional[str] = None
    risk_category: Optional[str] = None
    agent: Optional[str] = None
    worktree: Optional[str] = None
    risk_assessment: Optional[Dict[str, Any]] = None
    execution_result: Optional[Dict[str, Any]] = None
    latency_ms: Optional[float] = None
    snapshot_ref: Optional[str] = None
    tainted: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuditEvent:
        return cls(
            event_id=data["event_id"],
            session_id=data["session_id"],
            ts=int(data["ts"]),
            event_type=data.get("event_type", "action_evaluated"),
            action_id=data.get("action_id", ""),
            kind=data.get("kind", "shell"),
            risk_severity=data.get("risk_severity", "low"),
            verdict=data.get("verdict", "allow"),
            decided_by=data.get("decided_by", "auto"),
            command=data.get("command"),
            target_path=data.get("target_path"),
            risk_category=data.get("risk_category"),
            agent=data.get("agent"),
            worktree=data.get("worktree"),
            risk_assessment=data.get("risk_assessment"),
            execution_result=data.get("execution_result"),
            latency_ms=data.get("latency_ms"),
            snapshot_ref=data.get("snapshot_ref"),
            tainted=bool(data.get("tainted", False)),
            metadata=data.get("metadata", {}),
        )

