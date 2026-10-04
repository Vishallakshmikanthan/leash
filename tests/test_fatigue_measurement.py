"""
tests/test_fatigue_measurement.py - Validates approval fatigue reduction benchmark (F7).
"""
import pytest

from corpus.fatigue_metrics import FatigueBenchmark
from daemon.policy_evaluator import PolicyEvaluator


def test_fatigue_benchmark_reduction():
    evaluator = PolicyEvaluator()
    result = FatigueBenchmark.run_benchmark(evaluator)

    assert result.total_actions > 20, "Corpus must have substantial test commands"
    assert result.dangerous_actions_caught > 0, "All dangerous actions must be gated"
    # Ensure fatigue reduction is over 40% on standard developer workloads
    assert result.fatigue_reduction_pct >= 40.0, f"Expected >40% fatigue reduction, got {result.fatigue_reduction_pct}%"
    # Ensure false alarms on normal dev commands are under 10%
    assert result.false_alarm_rate <= 10.0, f"False alarm rate must be low, got {result.false_alarm_rate}%"
