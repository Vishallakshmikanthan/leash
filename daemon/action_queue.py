"""
daemon/action_queue.py - Multi-agent approval queue with card grouping (M12.3).

Features:
- Tracks pending actions across concurrent agent sessions with agent name and worktree.
- Groups ASK-level actions with identical rules and similar commands ("3 agents want to run npm install").
- Keeps High / Critical risk actions strictly single.
- Supports group inspection and atomic group decision application.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from contracts.models import ActionRequest, Decision, PolicyOutcome, RiskAssessment, Severity


@dataclass
class QueueItem:
    action_id: str
    session_id: str
    agent_name: str
    worktree: str
    request: ActionRequest
    assessment: RiskAssessment
    future: asyncio.Future[Decision]
    created_at: float


@dataclass
class ActionGroup:
    group_id: str
    title: str
    rule_id: str
    severity: str
    action_ids: List[str]
    members: List[Dict[str, Any]] = field(default_factory=list)


class MultiAgentActionQueue:
    """Manages concurrent approval requests from multiple agent sessions with grouping."""

    def __init__(self):
        self._items: Dict[str, QueueItem] = {}

    def add(
        self,
        request: ActionRequest,
        assessment: RiskAssessment,
        future: asyncio.Future[Decision],
        agent_name: str = "coding-agent",
        worktree: str = "",
        created_at: float = 0.0,
    ) -> None:
        self._items[request.id] = QueueItem(
            action_id=request.id,
            session_id=request.session,
            agent_name=agent_name,
            worktree=worktree,
            request=request,
            assessment=assessment,
            future=future,
            created_at=created_at,
        )

    def remove(self, action_id: str) -> Optional[QueueItem]:
        return self._items.pop(action_id, None)

    def get(self, action_id: str) -> Optional[QueueItem]:
        return self._items.get(action_id)

    def list_items(self) -> List[QueueItem]:
        return list(self._items.values())

    def get_grouped_queue(self) -> List[Dict[str, Any]]:
        """Groups pending ASK-level actions by rule and base command; high-risk actions stay single."""
        # Buckets for grouping candidate actions: key = (primary_rule, base_cmd)
        ask_buckets: Dict[Tuple[str, str], List[QueueItem]] = {}
        singles: List[QueueItem] = []

        for item in self._items.values():
            sev = item.assessment.severity
            # High or Critical severity actions cannot be grouped
            if sev in (Severity.HIGH, Severity.CRITICAL) or item.assessment.outcome == PolicyOutcome.DENY:
                singles.append(item)
                continue

            rule = item.assessment.rule_ids[0] if item.assessment.rule_ids else "R-GENERAL"
            cmd = (item.request.command or item.request.target_path or "").strip()
            # Extract first 2 tokens as base command (e.g. "npm install", "pip install", "pytest")
            tokens = cmd.split()
            base_cmd = " ".join(tokens[:2]).lower() if len(tokens) >= 2 else (tokens[0].lower() if tokens else "")

            key = (rule, base_cmd)
            ask_buckets.setdefault(key, []).append(item)

        results: List[Dict[str, Any]] = []

        # Process buckets
        for (rule, base_cmd), bucket in ask_buckets.items():
            if len(bucket) >= 2:
                # Grouped card
                group_id = f"group_{rule.lower()}_{abs(hash(base_cmd)) % 10000}"
                member_details = [
                    {
                        "action_id": q.action_id,
                        "session_id": q.session_id,
                        "agent": q.agent_name,
                        "worktree": q.worktree,
                        "command": q.request.command,
                        "target_path": q.request.target_path,
                    }
                    for q in bucket
                ]
                agent_count = len(bucket)
                title = f"{agent_count} agents want to run '{base_cmd}'"
                results.append({
                    "is_group": True,
                    "group_id": group_id,
                    "title": title,
                    "rule_id": rule,
                    "severity": bucket[0].assessment.severity.value,
                    "count": agent_count,
                    "action_ids": [q.action_id for q in bucket],
                    "members": member_details,
                })
            else:
                singles.extend(bucket)

        # Append single action cards
        for item in singles:
            results.append({
                "is_group": False,
                "action_id": item.action_id,
                "session_id": item.session_id,
                "agent": item.agent_name,
                "worktree": item.worktree,
                "command": item.request.command,
                "target_path": item.request.target_path,
                "rule_ids": item.assessment.rule_ids,
                "severity": item.assessment.severity.value,
                "summary": item.assessment.summary,
            })

        return results

    def resolve_group(self, group_action_ids: List[str], decision_template: Decision) -> List[str]:
        """Applies a decision to all pending items in a group."""
        resolved: List[str] = []
        for aid in group_action_ids:
            item = self._items.get(aid)
            if item and not item.future.done():
                d = Decision(
                    id=f"d_grp_{aid}",
                    action_id=aid,
                    session=item.session_id,
                    ts=decision_template.ts,
                    nonce=decision_template.nonce,
                    verdict=decision_template.verdict,
                    by=decision_template.by,
                    note=decision_template.note,
                    sig=getattr(decision_template, "sig", ""),
                )
                item.future.set_result(d)
                resolved.append(aid)
                self.remove(aid)
        return resolved
