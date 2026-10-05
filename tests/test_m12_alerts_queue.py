"""
tests/test_m12_alerts_queue.py - Comprehensive tests for M12:
1. Done and stuck alerts (M12.1)
2. Runaway guard cadence, loops, and timeouts (M12.2)
3. Multi-agent queue card grouping and single high-risk retention (M12.3)
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
import pytest

from contracts.models import (
    ActionKind,
    ActionRequest,
    DecidedBy,
    Decision,
    PolicyOutcome,
    RiskAssessment,
    Severity,
    Verdict,
)
from daemon.action_queue import MultiAgentActionQueue
from session.manager import SessionManager
from session.runaway_guard import RunawayGuard


def make_request(cmd: str = "", aid: str = "a1", sess: str = "s1") -> ActionRequest:
    return ActionRequest(
        id=aid,
        session=sess,
        ts=int(time.time()),
        nonce="n1",
        kind=ActionKind.SHELL,
        command=cmd,
        cwd=".",
        agent="test-agent",
    )


def test_session_done_and_stuck_notifications(tmp_path: Path):
    session_mgr = SessionManager(tmp_path)
    session = session_mgr.create_session(agent_name="coder-bot")

    # 1. Done notification
    done_ev = session_mgr.notify_done(session.session_id, exit_code=0, message="Task completed successfully.")
    assert done_ev["status"] == "done"
    assert done_ev["exit_code"] == 0
    assert done_ev["agent"] == "coder-bot"
    assert "completed successfully" in done_ev["message"]

    # 2. Stuck notification
    stuck_ev = session_mgr.notify_stuck(session.session_id, reason="Looping on failing build command")
    assert stuck_ev["status"] == "stuck"
    assert stuck_ev["agent"] == "coder-bot"
    assert "Looping on failing" in stuck_ev["reason"]


def test_runaway_guard_trips():
    guard = RunawayGuard(
        failure_threshold=3,
        loop_count_threshold=3,
        loop_window_seconds=10,
        rate_limit_count=5,
        rate_limit_window=2,
    )

    # 1. Repeated failing command
    guard.record_result("npm test", exit_code=1)
    assert guard.is_tripped() is False
    guard.record_result("npm test", exit_code=1)
    assert guard.is_tripped() is False
    trip_msg = guard.record_result("npm test", exit_code=1)
    assert guard.is_tripped() is True
    assert "repeated failing command" in (trip_msg or "").lower()

    # Reset
    guard.reset()
    assert guard.is_tripped() is False

    # 2. Identical command loop
    req = make_request("cargo check", aid="a_loop")
    guard.check_action(req)
    guard.check_action(req)
    loop_trip = guard.check_action(req)
    assert guard.is_tripped() is True
    assert "loop detected" in (loop_trip or "").lower()


@pytest.mark.asyncio
async def test_multi_agent_queue_grouping():
    queue = MultiAgentActionQueue()
    loop = asyncio.get_running_loop()

    # Create 3 ASK-level requests from 3 different agents/worktrees for npm install
    req1 = make_request("npm install lodash", aid="a1", sess="s1")
    req2 = make_request("npm install express", aid="a2", sess="s2")
    req3 = make_request("npm install chalk", aid="a3", sess="s3")

    # High risk action from agent 4
    req_high = make_request("rm -rf /tmp/data", aid="a4", sess="s4")

    fut1 = loop.create_future()
    fut2 = loop.create_future()
    fut3 = loop.create_future()
    fut4 = loop.create_future()

    assess_pkg = RiskAssessment(
        id="r1",
        action_id="a",
        severity=Severity.MEDIUM,
        category="package-install",
        rule_ids=["R-PKG-NEW-INSTALL"],
        outcome=PolicyOutcome.ASK,
        summary="Package install",
        why="Installing external package introduces third-party code.",
        safer_alternative="Pin dependencies.",
    )
    assess_high = RiskAssessment(
        id="r4",
        action_id="a4",
        severity=Severity.HIGH,
        category="destructive",
        rule_ids=["R-FS-RM"],
        outcome=PolicyOutcome.ASK,
        summary="Destructive deletion",
        why="Deletes filesystem paths recursively.",
        safer_alternative="Review path.",
    )

    queue.add(req1, assess_pkg, fut1, agent_name="agent-alpha", worktree="/repo/wt1")
    queue.add(req2, assess_pkg, fut2, agent_name="agent-beta", worktree="/repo/wt2")
    queue.add(req3, assess_pkg, fut3, agent_name="agent-gamma", worktree="/repo/wt3")
    queue.add(req_high, assess_high, fut4, agent_name="agent-delta", worktree="/repo/wt4")

    # Get grouped queue cards
    cards = queue.get_grouped_queue()

    # Should contain 1 grouped card (for the 3 npm install commands) and 1 single card (for the high risk action)
    assert len(cards) == 2

    grouped_card = next(c for c in cards if c["is_group"] is True)
    assert grouped_card["count"] == 3
    assert "3 agents want to run 'npm install'" in grouped_card["title"]
    assert len(grouped_card["members"]) == 3
    assert grouped_card["members"][0]["agent"] == "agent-alpha"
    assert grouped_card["members"][1]["agent"] == "agent-beta"
    assert grouped_card["members"][2]["agent"] == "agent-gamma"

    single_card = next(c for c in cards if c["is_group"] is False)
    assert single_card["action_id"] == "a4"
    assert single_card["agent"] == "agent-delta"
    assert single_card["severity"] == "high"

    # Resolving group applies decision to all 3 members
    template = Decision(
        id="d_tpl",
        action_id="",
        session="",
        ts=int(time.time()),
        nonce="n_dec",
        verdict=Verdict.ALLOW,
        by=DecidedBy.BIOMETRIC,
    )
    resolved = queue.resolve_group(grouped_card["action_ids"], template)
    assert len(resolved) == 3
    assert fut1.done() and fut1.result().verdict == Verdict.ALLOW
    assert fut2.done() and fut2.result().verdict == Verdict.ALLOW
    assert fut3.done() and fut3.result().verdict == Verdict.ALLOW
    assert not fut4.done()
