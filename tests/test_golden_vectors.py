"""
tests/test_golden_vectors.py - Validates canonical JSON vectors against contracts/golden/canonical_vectors.json
"""
import json
from pathlib import Path
from contracts.crypto import canonical_json


def test_golden_canonical_vectors():
    golden_path = Path("contracts/golden/canonical_vectors.json")
    assert golden_path.exists(), "canonical_vectors.json must exist"

    with open(golden_path, "r", encoding="utf-8") as f:
        cases = json.load(f)

    for case in cases:
        input_data = case["input"]
        expected = case["expected_canonical_sorted"]
        result = canonical_json(input_data).decode("utf-8")
        assert result == expected, f"Failed on case {case['id']}: {result} != {expected}"
