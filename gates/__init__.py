"""
gates package - security gates for Leash.
"""
from gates.base import BaseGate, GateResult
from gates.secret_fence import (
    CanaryCredential,
    CanaryManager,
    SecretFenceGate,
    SecretRedactor,
    calculate_shannon_entropy,
    find_high_entropy_strings,
)
from gates.package_gate import PackageGate
from gates.hidden_text import HiddenTextGate
from gates.workflow_watchlist import WorkflowWatchlistGate

__all__ = [
    "BaseGate",
    "GateResult",
    "SecretFenceGate",
    "SecretRedactor",
    "CanaryManager",
    "CanaryCredential",
    "calculate_shannon_entropy",
    "find_high_entropy_strings",
    "PackageGate",
    "HiddenTextGate",
    "WorkflowWatchlistGate",
]

