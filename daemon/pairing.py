"""
daemon/pairing.py - Device registration, one-time pairing tokens, and ECDSA decision verification.
"""
from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from contracts.crypto import (
    canonical_json,
    compute_action_digest,
    verify_device_signature,
)
from contracts.models import ActionRequest
from daemon.paths import devices_file_path

logger = logging.getLogger("leash.daemon.pairing")


@dataclass
class PairedDevice:
    device_id: str
    device_name: str
    public_key_der_b64: str
    created_at: float = field(default_factory=time.time)
    revoked: bool = False

    @property
    def public_key_der(self) -> bytes:
        return base64.b64decode(self.public_key_der_b64)


class DeviceStore:
    """Persistent storage for registered approver devices."""

    def __init__(self, file_path: Optional[Path] = None):
        self.file_path = file_path or devices_file_path()
        self.devices: Dict[str, PairedDevice] = {}
        self.load()

    def load(self) -> None:
        if not self.file_path.exists():
            return
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.devices = {
                k: PairedDevice(**v) for k, v in data.items()
            }
        except Exception as e:
            logger.warning(f"Failed to load devices from {self.file_path}: {e}")

    def save(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: asdict(v) for k, v in self.devices.items()}
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        try:
            self.file_path.chmod(0o600)
        except (AttributeError, OSError):
            pass

    def add_device(self, device_id: str, device_name: str, public_key_der: bytes) -> PairedDevice:
        dev = PairedDevice(
            device_id=device_id,
            device_name=device_name,
            public_key_der_b64=base64.b64encode(public_key_der).decode("ascii"),
            created_at=time.time(),
            revoked=False,
        )
        self.devices[device_id] = dev
        self.save()
        return dev

    def get_device(self, device_id: str) -> Optional[PairedDevice]:
        dev = self.devices.get(device_id)
        if dev and not dev.revoked:
            return dev
        return None

    def revoke_device(self, device_id: str) -> bool:
        if device_id in self.devices:
            self.devices[device_id].revoked = True
            self.save()
            return True
        return False

    def list_devices(self) -> List[PairedDevice]:
        return list(self.devices.values())


class PairingManager:
    """Manages one-time pairing tokens with expiration and rate limiting."""

    def __init__(self, lockout_threshold: int = 5, lockout_seconds: int = 300):
        self.lockout_threshold = lockout_threshold
        self.lockout_seconds = lockout_seconds
        self.active_tokens: Dict[str, float] = {}  # token -> expires_at
        self.failed_attempts: int = 0
        self.locked_until: float = 0.0

    def is_locked_out(self) -> bool:
        return time.time() < self.locked_until

    def create_pairing_token(self, validity_seconds: int = 120) -> str:
        token = secrets.token_hex(16)
        self.active_tokens[token] = time.time() + validity_seconds
        return token

    def verify_and_consume_token(self, token: str) -> bool:
        now = time.time()
        if self.is_locked_out():
            return False

        expires_at = self.active_tokens.get(token)
        if not expires_at:
            self._record_failure()
            return False

        if now > expires_at:
            del self.active_tokens[token]
            self._record_failure()
            return False

        # Success - single use
        del self.active_tokens[token]
        self.failed_attempts = 0
        return True

    def _record_failure(self) -> None:
        self.failed_attempts += 1
        if self.failed_attempts >= self.lockout_threshold:
            self.locked_until = time.time() + self.lockout_seconds

    @staticmethod
    def format_pairing_qr(host: str, port: int, cert_fingerprint: str, token: str) -> str:
        return f"leash://pair?host={host}&port={port}&fp={cert_fingerprint}&token={token}"


def verify_signed_decision_payload(
    action: ActionRequest,
    payload: Dict[str, Any],
    device_store: DeviceStore,
    max_drift: int = 60,
) -> Tuple[bool, str]:
    """
    Validates a signed decision payload:
    {
      "action_id": ...,
      "action_digest": ...,
      "verdict": ...,
      "decided_by": ...,
      "ts": ...,
      "nonce_server": ...,
      "device_id": ...,
      "sig": ... (hex or b64 DER)
    }
    """
    device_id = payload.get("device_id")
    if not device_id:
        return False, "missing device_id"

    device = device_store.get_device(device_id)
    if not device:
        return False, "unknown or revoked device"

    ts = payload.get("ts")
    if ts is None or abs(time.time() - float(ts)) > max_drift:
        return False, "timestamp expired or drifted"

    # Verify action digest
    expected_digest = compute_action_digest(
        command=action.command,
        cwd=action.cwd,
        kind=action.kind.value if hasattr(action.kind, "value") else str(action.kind),
        target_path=action.target_path,
        session=action.session,
        nonce=action.nonce,
    )
    if payload.get("action_digest") != expected_digest:
        return False, "action digest mismatch"

    # Verify server nonce
    if payload.get("nonce_server") != action.nonce:
        return False, "server nonce mismatch"

    # Verify ECDSA signature
    sig_raw = payload.get("sig", "")
    try:
        try:
            sig_der = bytes.fromhex(sig_raw)
        except ValueError:
            sig_der = base64.b64decode(sig_raw)
    except Exception:
        return False, "invalid signature format"

    signed_data = {
        "action_digest": payload.get("action_digest"),
        "action_id": payload.get("action_id"),
        "decided_by": payload.get("decided_by"),
        "nonce_server": payload.get("nonce_server"),
        "ts": int(ts),
        "verdict": payload.get("verdict"),
    }
    canonical_bytes = canonical_json(signed_data)

    if not verify_device_signature(device.public_key_der, canonical_bytes, sig_der):
        return False, "cryptographic signature verification failed"

    return True, "valid"
