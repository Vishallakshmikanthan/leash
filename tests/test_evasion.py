"""
tests/test_evasion.py - Validates evasion defense and records detection capabilities (F6).
"""
import json
from pathlib import Path
import pytest

from contracts.models import ActionKind, ActionRequest, Severity
from daemon.policy_evaluator import PolicyEvaluator


@pytest.fixture
def evaluator():
    return PolicyEvaluator()


def test_evasion_corpus_evaluation(evaluator):
    corpus_path = Path("corpus/evasion_cases.json")
    assert corpus_path.exists(), "corpus/evasion_cases.json must exist"

    with open(corpus_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    assert len(cases) >= 10, "Plan requires testing at least 10 evasion tricks"

    detected_count = 0
    results_summary = []

    for case in cases:
        case_id = case["id"]
        technique = case["technique"]
        cmd = case["cmd"]

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
        # Any non-low severity or security gate trigger constitutes detection
        detected = assessment.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

        if detected:
            detected_count += 1

        results_summary.append({
            "id": case_id,
            "technique": technique,
            "severity": assessment.severity.value,
            "category": assessment.category,
            "rule_ids": assessment.rule_ids,
            "detected": detected,
        })

    # Assert that high-fidelity evasion attacks are caught
    detection_rate = detected_count / len(cases)
    assert detection_rate >= 0.80, f"Detection rate {detection_rate:.1%} must be at least 80%"
    assert detected_count >= 10
