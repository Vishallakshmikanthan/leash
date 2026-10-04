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
from gates.package_gate import (
    AllowOnceManager,
    LockfileInspector,
    PackageGate,
    PackageKnowledge,
)
from gates.hidden_text import HiddenTextFinding, HiddenTextGate, HiddenTextScanner
from gates.workflow_watchlist import WorkflowWatchlistGate
from gates.provenance_tracker import ProvenanceTracker, ProvenanceTrackerGate

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
    "PackageKnowledge",
    "LockfileInspector",
    "AllowOnceManager",
    "HiddenTextFinding",
    "HiddenTextGate",
    "HiddenTextScanner",
    "WorkflowWatchlistGate",
    "ProvenanceTracker",
    "ProvenanceTrackerGate",
]


