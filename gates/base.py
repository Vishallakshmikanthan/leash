"""
gates/base.py - Base interface and registry for Leash security gates.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from contracts.models import ActionRequest, Severity


@dataclass
class GateResult:
    triggered: bool
    rule_id: str
    category: str
    severity: Severity
    summary: str
    why: str
    safer_alternative: str


class BaseGate(ABC):
    """Abstract base class for all security gates."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable gate name."""
        pass

    @abstractmethod
    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        """Evaluates an ActionRequest. Returns GateResult if triggered, None otherwise."""
        pass
