"""
contracts/crypto.py - Cryptographic signatures and validation for Leash protocol.
"""
from __future__ import annotations

import hmac
import hashlib
import os
import time
import secrets
from typing import Set


class LeashSigner:
    """Handles HMAC-SHA256 signing and verification for protocol messages."""

    def __init__(self, shared_secret: str, max_drift_seconds: int = 60):
        self.secret_bytes = shared_secret.encode("utf-8")
        self.max_drift_seconds = max_drift_seconds
        self._seen_nonces: Set[str] = set()

    @staticmethod
    def generate_nonce(length: int = 16) -> str:
        return secrets.token_hex(length // 2)

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.secret_bytes, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str, ts: int, nonce: str) -> bool:
        # 1. Freshness check
        current_time = int(time.time())
        if abs(current_time - ts) > self.max_drift_seconds:
            return False

        # 2. Replay check
        if nonce in self._seen_nonces:
            return False

        # 3. Signature verification
        expected = self.sign(payload)
        if not hmac.compare_digest(expected, signature):
            return False

        self._seen_nonces.add(nonce)
        # Cap set size to prevent memory leak
        if len(self._seen_nonces) > 10000:
            self._seen_nonces.clear()
        return True
