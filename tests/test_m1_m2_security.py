"""
tests/test_m1_m2_security.py - Acceptance tests for M1 (Trust boundary & control plane) and M2 (Device pairing & transport)
"""
import asyncio
import base64
import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest
import aiohttp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from contracts.crypto import canonical_json, compute_action_digest
from contracts.models import ActionKind, ActionRequest, DecidedBy, Verdict
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.pairing import DeviceStore, PairingManager, verify_signed_decision_payload
from daemon.paths import leash_home
from daemon.server import LeashDaemonServer
from session.manager import SessionManager, confine_cwd


@pytest.fixture
def temp_workspace():
    td = tempfile.mkdtemp(prefix="leash_test_")
    yield Path(td)
    shutil.rmtree(td, ignore_errors=True)


@pytest.mark.asyncio
async def test_m1_routes_closed_in_production(temp_workspace):
    """M1 acceptance: POST /decision and GET /pairing return 404 in production mode."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=8931,
        agent_plane_port=8932,
        enable_test_routes=False,  # Production mode
        shared_secret="super-secret-key-12345",
    )
    session_mgr = SessionManager(temp_workspace)
    audit_logger = AuditLogger(temp_workspace / "audit.jsonl")
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    try:
        async with aiohttp.ClientSession() as client:
            # 1. POST /decision returns 404
            async with client.post(f"http://127.0.0.1:{config.port}/decision", json={"verdict": "allow"}) as resp:
                assert resp.status == 404

            # 2. GET /pairing returns 404
            async with client.get(f"http://127.0.0.1:{config.port}/pairing") as resp:
                assert resp.status == 404

            # 3. GET /pending returns 404
            async with client.get(f"http://127.0.0.1:{config.port}/pending") as resp:
                assert resp.status == 404

            # 4. GET /api/pair/pin does NOT return shared_secret
            async with client.get(f"http://127.0.0.1:{config.port}/api/pair/pin") as resp:
                assert resp.status == 200
                data = await resp.json()
                assert "shared_secret" not in data
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_m1_agent_plane_capability_tokens(temp_workspace):
    """M1 acceptance: Agent Plane requires valid session capability token and confines CWD."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=8933,
        agent_plane_port=8934,
        enable_test_routes=False,
    )
    session_mgr = SessionManager(temp_workspace)
    audit_logger = AuditLogger(temp_workspace / "audit.jsonl")
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    session = session_mgr.create_session()
    valid_token = session_mgr.get_session_token(session.session_id)
    assert valid_token is not None

    try:
        async with aiohttp.ClientSession() as client:
            agent_url = f"http://127.0.0.1:{config.agent_plane_port}/v1/action"

            # 1. Missing Authorization header returns 401
            async with client.post(agent_url, json={"command": "ls"}) as resp:
                assert resp.status == 401

            # 2. Invalid Bearer token returns 401
            headers_bad = {"Authorization": "Bearer bad-token-xyz"}
            async with client.post(agent_url, headers=headers_bad, json={"command": "ls"}) as resp:
                assert resp.status == 401

            # 3. Valid token with CWD escaping session worktree returns 403
            headers_good = {"Authorization": f"Bearer {valid_token}"}
            escape_payload = {"command": "ls", "cwd": "/etc"}
            async with client.post(agent_url, headers=headers_good, json=escape_payload) as resp:
                assert resp.status == 403

            # 4. Valid token and safe command inside worktree succeeds
            safe_payload = {"command": "ls", "cwd": session.worktree_path}
            async with client.post(agent_url, headers=headers_good, json=safe_payload) as resp:
                assert resp.status == 200
                res = await resp.json()
                assert res["action_id"] is not None
                assert res["verdict"] == "allow"
    finally:
        await server.stop()


def test_m1_confine_cwd(temp_workspace):
    """M1 acceptance: confine_cwd prevents directory traversal."""
    root = temp_workspace / "worktree"
    root.mkdir(parents=True, exist_ok=True)

    # Valid subpaths
    sub = root / "subdir"
    sub.mkdir()
    assert confine_cwd("subdir", str(root)) == str(sub.resolve())
    assert confine_cwd(".", str(root)) == str(root.resolve())

    # Path traversal outside root raises PermissionError
    with pytest.raises(PermissionError):
        confine_cwd("../../outside", str(root))

    with pytest.raises(PermissionError):
        confine_cwd("C:\\Windows" if os.name == "nt" else "/etc", str(root))


def test_m2_pairing_tokens_lifecycle():
    """M2 acceptance: one-time pairing token single-use, expiration, and rate-limiting lockout."""
    mgr = PairingManager(lockout_threshold=3, lockout_seconds=60)
    token = mgr.create_pairing_token(validity_seconds=120)

    # 1. Valid token consumption succeeds
    assert mgr.verify_and_consume_token(token) is True

    # 2. Second use of same token fails
    assert mgr.verify_and_consume_token(token) is False

    # 3. Expired token fails
    expired_token = mgr.create_pairing_token(validity_seconds=-1)
    assert mgr.verify_and_consume_token(expired_token) is False

    # 4. Wrong tokens trigger rate-limit lockout
    mgr.verify_and_consume_token("wrong-1")
    mgr.verify_and_consume_token("wrong-2")
    assert mgr.is_locked_out() is True
    # Once locked out, even valid token fails
    good_token = mgr.create_pairing_token(validity_seconds=120)
    assert mgr.verify_and_consume_token(good_token) is False


def test_m2_ecdsa_signed_decisions(temp_workspace):
    """M2 acceptance: decisions signed for action A cannot approve action B, and revoked devices are rejected."""
    # Generate ECDSA P-256 key pair for simulated Android phone
    phone_key = ec.generate_private_key(ec.SECP256R1())
    pub_der = phone_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    store = DeviceStore(temp_workspace / "devices.json")
    dev = store.add_device(device_id="dev_pixel8", device_name="Pixel 8", public_key_der=pub_der)

    action_a = ActionRequest(
        id="act_A",
        session="s_test",
        ts=int(time.time()),
        nonce="srv_nonce_A",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd="/repo",
        command="git status",
    )

    action_b = ActionRequest(
        id="act_B",
        session="s_test",
        ts=int(time.time()),
        nonce="srv_nonce_B",
        kind=ActionKind.SHELL,
        agent="agent",
        cwd="/repo",
        command="rm -rf /",
    )

    digest_a = compute_action_digest("git status", "/repo", "shell", None, "s_test", "srv_nonce_A")
    now_ts = int(time.time())

    # Phone signs approval for Action A
    signed_payload_a = {
        "action_digest": digest_a,
        "action_id": "act_A",
        "decided_by": "phone-biometric",
        "nonce_server": "srv_nonce_A",
        "ts": now_ts,
        "verdict": "allow",
    }
    canon_bytes = canonical_json(signed_payload_a)
    sig_der = phone_key.sign(canon_bytes, ec.ECDSA(hashes.SHA256()))

    decision_payload = {
        **signed_payload_a,
        "device_id": "dev_pixel8",
        "sig": sig_der.hex(),
    }

    # 1. Verifying Action A succeeds
    valid, reason = verify_signed_decision_payload(action_a, decision_payload, store)
    assert valid is True, f"Failed: {reason}"

    # 2. Replaying Action A's signed decision on Action B FAILS (digest & nonce mismatch)
    valid_b, reason_b = verify_signed_decision_payload(action_b, decision_payload, store)
    assert valid_b is False
    assert "digest mismatch" in reason_b or "nonce mismatch" in reason_b

    # 3. Revoking the device causes verification to FAIL
    store.revoke_device("dev_pixel8")
    valid_revoked, reason_revoked = verify_signed_decision_payload(action_a, decision_payload, store)
    assert valid_revoked is False
    assert "revoked" in reason_revoked
