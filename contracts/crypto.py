"""
contracts/crypto.py - Cryptographic signatures and validation for Leash protocol.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, Optional, Set


def canonical_json(data: Dict[str, Any]) -> bytes:
    """Deterministic canonical representation for signing (sorted keys, compact separators)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class LeashSigner:
    """Handles HMAC-SHA256 signing and verification for protocol messages."""

    def __init__(self, shared_secret: str, max_drift_seconds: int = 60):
        self.secret_bytes = shared_secret.encode("utf-8")
        self.max_drift_seconds = max_drift_seconds
        self._seen_nonces: Dict[str, float] = {}

    @property
    def seen_nonces_count(self) -> int:
        return len(self._seen_nonces)

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        return secrets.token_hex(length // 2)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.secret_bytes, payload, hashlib.sha256).hexdigest()

    def sign_dict(self, data: Dict[str, Any]) -> str:
        clean = {k: v for k, v in data.items() if k != "sig"}
        return self.sign(canonical_json(clean))

    def sign_action(self, data: Dict[str, Any]) -> str:
        return self.sign_dict(data)

    def verify(self, payload: bytes, signature: str, ts: int, nonce: str) -> bool:
        current_time = time.time()
        # 1. Freshness check
        if abs(current_time - ts) > self.max_drift_seconds:
            return False

        # Prune nonces older than drift window
        cutoff = current_time - self.max_drift_seconds
        self._seen_nonces = {n: t for n, t in self._seen_nonces.items() if t > cutoff}

        # 2. Replay check
        if nonce in self._seen_nonces:
            return False

        # 3. Signature verification
        expected = self.sign(payload)
        if not hmac.compare_digest(expected, signature):
            return False

        self._seen_nonces[nonce] = float(ts)
        return True

    def verify_dict(self, data: Dict[str, Any]) -> bool:
        sig = data.get("sig", "")
        ts = data.get("ts")
        nonce = data.get("nonce", "")
        if not sig or ts is None or not nonce:
            return False
        clean = {k: v for k, v in data.items() if k != "sig"}
        return self.verify(canonical_json(clean), sig, int(ts), nonce)
