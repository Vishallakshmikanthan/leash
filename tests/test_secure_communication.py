"""
tests/test_secure_communication.py - Comprehensive tests for the Leash secure communication layer.
"""
from __future__ import annotations

import asyncio
import json
import socket
import time
import uuid
from pathlib import Path

import aiohttp
import pytest

from contracts.crypto import LeashSigner, canonical_json
from contracts.models import (
    ActionKind,
    ActionRequest,
    DecidedBy,
    Decision,
    ProvenanceEvent,
    ProvenanceKind,
    Severity,
    Verdict,
)
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.policy_evaluator import PolicyEvaluator
from daemon.server import LeashDaemonServer
from session.manager import SessionManager


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


@pytest.fixture
def comm_fixture(tmp_path: Path):
    port = get_free_port()
    config = DaemonConfig(
        host="127.0.0.1",
        port=port,
        shared_secret="guard-super-secret-key-42",
        pairing_code_file=tmp_path / "pairing.json",
        audit_log_path=tmp_path / "audit.jsonl",
        receipt_output_path=tmp_path / "receipt.md",
        timeout_seconds=5,
        fail_closed_high_risk=True,
        auto_allow_low_risk=True,
        dev_mode=False,  # Enforce strict production security
    )
    session_mgr = SessionManager(tmp_path)
    audit_logger = AuditLogger(config.audit_log_path)
    evaluator = PolicyEvaluator(config.allow_command_patterns)
    server = LeashDaemonServer(config, session_mgr, audit_logger, evaluator)
    return {
        "config": config,
        "session_mgr": session_mgr,
        "audit_logger": audit_logger,
        "evaluator": evaluator,
        "server": server,
        "tmp_path": tmp_path,
        "port": port,
        "secret": config.shared_secret,
    }


def make_signed_auth_payload(signer: LeashSigner, device_id: str, device_name: str, ts: int, nonce: str) -> dict:
    clean_dict = {
        "device_id": device_id,
        "device_name": device_name,
        "nonce": nonce,
        "ts": ts,
    }
    canon_bytes = canonical_json(clean_dict)
    sig = signer.sign(canon_bytes)
    return {
        "type": "auth",
        "payload": {
            "device_id": device_id,
            "device_name": device_name,
            "ts": ts,
            "nonce": nonce,
            "sig": sig,
        },
    }


@pytest.mark.asyncio
async def test_pairing_endpoint_info(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()

    async with aiohttp.ClientSession() as client:
        resp = await client.get(f"http://127.0.0.1:{config.port}/pairing")
        assert resp.status == 200
        data = await resp.json()
        assert data["host"] == "127.0.0.1"
        assert data["port"] == config.port
        assert data["shared_secret"] == config.shared_secret
        assert "leash://pair" in data["qr_uri"]

    await server.stop()


@pytest.mark.asyncio
async def test_handshake_authentication_success(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        nonce = signer.generate_nonce()
        ts = int(time.time())
        auth_msg = make_signed_auth_payload(signer, "pixel_phone", "Pixel 8 Pro", ts, nonce)

        await ws.send_str(json.dumps(auth_msg))
        raw_resp = await ws.receive_str()
        ack = json.loads(raw_resp)

        assert ack["type"] == "auth_ack"
        assert ack["payload"]["status"] == "authenticated"
        assert len(server.authenticated_clients) == 1
        assert server.has_decision_channel() is True

        # Check server status endpoint reflects authenticated phone
        status_resp = await client.get(f"http://127.0.0.1:{config.port}/status")
        status_data = await status_resp.json()
        assert status_data["authenticated_phones"] == 1
        assert status_data["phones"][0]["device_id"] == "pixel_phone"

        await ws.close()

    await server.stop()


@pytest.mark.asyncio
async def test_handshake_authentication_failure_bad_signature(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        bad_auth = {
            "type": "auth",
            "payload": {
                "device_id": "rogue_device",
                "device_name": "Attacker",
                "ts": int(time.time()),
                "nonce": "n_bad",
                "sig": "0000000000000000000000000000000000000000000000000000000000000000",
            },
        }
        await ws.send_str(json.dumps(bad_auth))
        raw_resp = await ws.receive_str()
        err = json.loads(raw_resp)
        assert err["type"] == "auth_error"
        assert "Authentication failed" in err["payload"]["reason"]
        assert len(server.authenticated_clients) == 0

    await server.stop()


@pytest.mark.asyncio
async def test_handshake_authentication_failure_expired_timestamp(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        # Timestamp from 5 minutes ago (exceeds max_drift_seconds=60)
        old_ts = int(time.time()) - 300
        nonce = signer.generate_nonce()
        stale_auth = make_signed_auth_payload(signer, "pixel_phone", "Pixel 8 Pro", old_ts, nonce)

        await ws.send_str(json.dumps(stale_auth))
        raw_resp = await ws.receive_str()
        err = json.loads(raw_resp)
        assert err["type"] == "auth_error"

    await server.stop()


@pytest.mark.asyncio
async def test_replay_protection_blocks_duplicate_nonce(comm_fixture):
    signer = LeashSigner("secret", max_drift_seconds=60)
    payload = b"test payload"
    ts = int(time.time())
    nonce = "fixed_nonce_123"
    sig = signer.sign(payload)

    # First verification must succeed
    assert signer.verify(payload, sig, ts, nonce) is True

    # Immediate replay of the same nonce must fail
    assert signer.verify(payload, sig, ts, nonce) is False


@pytest.mark.asyncio
async def test_heartbeat_exchange(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        # Authenticate first
        auth_msg = make_signed_auth_payload(signer, "pixel_phone", "Pixel", int(time.time()), signer.generate_nonce())
        await ws.send_str(json.dumps(auth_msg))
        await ws.receive_str()

        # Send heartbeat
        hb_nonce = signer.generate_nonce()
        hb_msg = {
            "type": "heartbeat",
            "payload": {"ts": int(time.time()), "nonce": hb_nonce},
        }
        await ws.send_str(json.dumps(hb_msg))
        raw_ack = await ws.receive_str()
        ack = json.loads(raw_ack)

        assert ack["type"] == "heartbeat_ack"
        assert ack["payload"]["echo_nonce"] == hb_nonce
        assert "sig" in ack["payload"]
        await ws.close()

    await server.stop()


@pytest.mark.asyncio
async def test_provenance_event_exchange(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        # Authenticate
        auth_msg = make_signed_auth_payload(signer, "pixel_phone", "Pixel", int(time.time()), signer.generate_nonce())
        await ws.send_str(json.dumps(auth_msg))
        await ws.receive_str()

        # Trigger provenance event broadcast from server
        session = comm_fixture["session_mgr"].create_session()
        p_event = ProvenanceEvent(
            id=f"p_{uuid.uuid4().hex[:12]}",
            session=session.session_id,
            ts=int(time.time()),
            kind=ProvenanceKind.UNTRUSTED_READ,
            source="README.md",
            line=42,
            flags=["untrusted-doc", "prompt-injection-risk"],
            snippet="Read of README.md",
        )

        emit_task = asyncio.create_task(server.emit_provenance_event(p_event))

        # Client receives provenance event over WebSocket
        raw_msg = await ws.receive_str()
        await emit_task
        data = json.loads(raw_msg)

        assert data["type"] == "provenance_event"
        rec_event = data["payload"]
        assert rec_event["id"] == p_event.id
        assert rec_event["kind"] == "untrusted_read"
        assert rec_event["source"] == "README.md"
        assert rec_event["sig"] != ""

        # Verify cryptographic signature of provenance event
        rec_obj = ProvenanceEvent.from_dict(rec_event)
        phone_verifier = LeashSigner(config.shared_secret)
        is_valid = phone_verifier.verify(
            rec_obj.payload_for_signature(),
            rec_obj.sig,
            rec_obj.ts,
            rec_obj.nonce,
        )
        assert is_valid is True

        # Verify session state was tainted
        assert comm_fixture["session_mgr"].get_taint_context(session.session_id).tainted is True

        await ws.close()

    await server.stop()


@pytest.mark.asyncio
async def test_action_request_decision_correlation_and_ack(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    session = comm_fixture["session_mgr"].create_session()

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        # 1. Authenticate
        auth_msg = make_signed_auth_payload(signer, "pixel_phone", "Pixel", int(time.time()), signer.generate_nonce())
        await ws.send_str(json.dumps(auth_msg))
        await ws.receive_str()

        # Background phone responder: receives action_request and sends back Decision
        async def phone_guard_handler():
            raw = await ws.receive_str()
            incoming = json.loads(raw)
            assert incoming["type"] == "action_request"
            req_dict = incoming["payload"]["request"]
            action_id = req_dict["id"]
            sess_id = req_dict["session"]

            # Verify action request signature
            req_obj = ActionRequest.from_dict(req_dict)
            assert signer.verify(req_obj.payload_for_signature(), req_obj.sig, req_obj.ts, req_obj.nonce) is True

            # Formulate signed decision
            dec_nonce = signer.generate_nonce()
            dec_ts = int(time.time())
            dec = Decision(
                id=f"d_{dec_nonce}",
                action_id=action_id,
                session=sess_id,
                ts=dec_ts,
                nonce=dec_nonce,
                verdict=Verdict.ALLOW,
                by=DecidedBy.BIOMETRIC,
                note="Biometric fingerprint verified by user",
            )
            dec.sig = signer.sign(dec.payload_for_signature())

            await ws.send_str(json.dumps({"type": "decision", "payload": dec.to_dict()}))

            # Expect decision_ack confirmation from server
            ack_raw = await ws.receive_str()
            ack_data = json.loads(ack_raw)
            assert ack_data["type"] == "decision_ack"
            assert ack_data["payload"]["action_id"] == action_id
            assert ack_data["payload"]["verdict"] == "allow"

        responder_task = asyncio.create_task(phone_guard_handler())

        # Submit risky action requiring phone decision
        req = ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=session.session_id,
            ts=int(time.time()),
            nonce="nonce_action_01",
            kind=ActionKind.SHELL,
            command="python -c \"print('secure_correlated_execution')\"",
            cwd=str(comm_fixture["tmp_path"]),
            agent="test-agent",
            scope_flags=["outside-allowed-paths"],
        )

        result = await server.execute_action(req)
        await responder_task
        await ws.close()

    await server.stop()

    assert result.allowed is True
    assert result.verdict == Verdict.ALLOW
    assert "secure_correlated_execution" in result.stdout


@pytest.mark.asyncio
async def test_fail_closed_on_unauthenticated_client_decision(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    session = comm_fixture["session_mgr"].create_session()

    async with aiohttp.ClientSession() as client:
        # Connect client without authenticating
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")

        dec_nonce = signer.generate_nonce()
        unauth_dec = Decision(
            id=f"d_{dec_nonce}",
            action_id="a_fake_123",
            session=session.session_id,
            ts=int(time.time()),
            nonce=dec_nonce,
            verdict=Verdict.ALLOW,
            by=DecidedBy.TAP,
        )
        unauth_dec.sig = signer.sign(unauth_dec.payload_for_signature())

        # Attempt to submit decision without auth handshake
        await ws.send_str(json.dumps({"type": "decision", "payload": unauth_dec.to_dict()}))
        raw_resp = await ws.receive_str()
        resp = json.loads(raw_resp)

        assert resp["type"] == "error"
        assert resp["payload"]["code"] == "UNAUTHENTICATED"
        await ws.close()

    await server.stop()


@pytest.mark.asyncio
async def test_fail_closed_on_phone_disconnect_during_pending_action(comm_fixture):
    server: LeashDaemonServer = comm_fixture["server"]
    config: DaemonConfig = comm_fixture["config"]
    await server.start()
    signer = LeashSigner(config.shared_secret)

    session = comm_fixture["session_mgr"].create_session()

    async with aiohttp.ClientSession() as client:
        ws = await client.ws_connect(f"ws://127.0.0.1:{config.port}/ws")
        # 1. Authenticate phone
        auth_msg = make_signed_auth_payload(signer, "pixel_phone", "Pixel", int(time.time()), signer.generate_nonce())
        await ws.send_str(json.dumps(auth_msg))
        await ws.receive_str()

        action_id = f"a_{uuid.uuid4().hex[:12]}"
        req = ActionRequest(
            id=action_id,
            session=session.session_id,
            ts=int(time.time()),
            nonce="nonce_sever_test",
            kind=ActionKind.SHELL,
            command="echo 'should be blocked by disconnect'",
            cwd=str(comm_fixture["tmp_path"]),
            agent="test-agent",
            scope_flags=["outside-allowed-paths"],
        )

        async def trigger_disconnect_after_broadcast():
            # Wait for action_request broadcast
            msg = await ws.receive_str()
            data = json.loads(msg)
            assert data["type"] == "action_request"
            # Sever connection abruptly while action is pending approval!
            await ws.close(code=1006)

        disc_task = asyncio.create_task(trigger_disconnect_after_broadcast())
        result = await server.execute_action(req)
        await disc_task

    await server.stop()

    # Fail closed: must deny execution immediately when connection is severed
    assert result.allowed is False
    assert result.verdict == Verdict.DENY
    assert result.exit_code == 126
    assert "Connection severed to Phone Guard: failed closed." in result.blocked_reason
