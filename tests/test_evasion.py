"""
tests/test_evasion.py - Validates evasion defense and records detection capabilities (F6).
"""
import json
from pathlib import Path
import pytest

from contracts.models import ActionKind, ActionRequest, PolicyOutcome, Severity
from daemon.policy_evaluator import PolicyEvaluator


@pytest.fixture
def evaluator():
    return PolicyEvaluator()


def test_evasion_corpus_evaluation(evaluator):
    corpus_path = Path("corpus/evasion_cases.json")
    assert corpus_path.exists(), "corpus/evasion_cases.json must exist"

    with open(corpus_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    assert len(cases) == 27, f"Expected exactly 27 evasion cases from gap report, found {len(cases)}"

    detected_count = 0
    results_summary = []

    for case in cases:
        case_id = case["id"]
        technique = case["technique"]
        cmd = case["cmd"]
        expected_outcome = case.get("expected_outcome", "ask")

        req = ActionRequest(
            id=f"a_{case_id}",
            session="s_evasion_test",
            ts=1700000000,
            nonce=f"n_{case_id}",
            kind=ActionKind.SHELL,
            command=cmd,
            agent="test-agent",
            cwd=".",
        )

        assessment = evaluator.evaluate(req)

        # None of the 27 evasion attacks may be auto-allowed
        assert assessment.outcome != PolicyOutcome.ALLOW, f"Evasion {case_id} ({technique}) was auto-allowed: {cmd}"

        # Matches expected outcome (ASK or DENY)
        if expected_outcome == "deny":
            assert assessment.outcome == PolicyOutcome.DENY, f"Evasion {case_id} expected DENY, got {assessment.outcome}: {cmd}"
        else:
            assert assessment.outcome in (PolicyOutcome.ASK, PolicyOutcome.DENY), f"Evasion {case_id} expected ASK or DENY, got {assessment.outcome}: {cmd}"

        detected_count += 1
        results_summary.append({
            "id": case_id,
            "technique": technique,
            "severity": assessment.severity.value,
            "outcome": assessment.outcome.value,
            "category": assessment.category,
            "rule_ids": assessment.rule_ids,
        })

    # Assert 100% of evasion cases are stopped from auto-execution
    detection_rate = detected_count / len(cases)
    assert detection_rate == 1.0, f"All 27 evasion attacks must be intercepted (got {detection_rate:.1%})"


def test_normal_development_commands_allow_rate(evaluator):
    """M4 Acceptance: Normal development corpus gives ALLOW for >= 95% of entries in balanced mode."""
    normal_path = Path("corpus/normal_commands.json")
    assert normal_path.exists(), "corpus/normal_commands.json must exist"

    with open(normal_path, "r", encoding="utf-8") as f:
        commands = json.load(f)

    allow_count = 0
    for item in commands:
        cmd = item["cmd"]
        req = ActionRequest(
            id=f"a_norm_{allow_count}",
            session="s_normal_dev",
            ts=1700000000,
            nonce=f"n_norm_{allow_count}",
            kind=ActionKind.SHELL,
            command=cmd,
            agent="dev-agent",
            cwd=".",
        )
        assessment = evaluator.evaluate(req)
        if assessment.outcome == PolicyOutcome.ALLOW:
            allow_count += 1

    pass_rate = allow_count / len(commands)
    assert pass_rate >= 0.95, f"Normal development allow rate {pass_rate:.1%} must be >= 95%"


def test_unparseable_command_gives_ask(evaluator):
    """M4 Acceptance: Any command that the parser cannot parse gives ASK."""
    req = ActionRequest(
        id="a_malformed_1",
        session="s_malformed",
        ts=1700000000,
        nonce="n_malformed",
        kind=ActionKind.SHELL,
        command="for ((i=0; i<10; i++)) do echo '((('; done \"unclosed quote",
        agent="test-agent",
        cwd=".",
    )
    assessment = evaluator.evaluate(req)
    assert assessment.outcome == PolicyOutcome.ASK
