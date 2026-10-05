"""
tests/test_server_web_portal.py - Tests for the Leash Web Pairing Portal and PIN verification.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from aiohttp import ClientSession

from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.server import LeashDaemonServer
from session.manager import SessionManager


@pytest.mark.asyncio
async def test_pairing_pin_api_and_web_portal(tmp_path: Path):
    port = 8929
    config = DaemonConfig.load_default()
    config.port = port
    config.host = "127.0.0.1"
    config.dev_mode = True

    session_mgr = SessionManager(tmp_path)
    audit_logger = AuditLogger(tmp_path / "audit.jsonl")
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    try:
        async with ClientSession() as client:
            base_url = f"http://127.0.0.1:{port}"

            # 1. Fetch current PIN via GET /api/pair/pin
            async with client.get(f"{base_url}/api/pair/pin") as res:
                assert res.status == 200
                data = await res.json()
                assert "pin" in data
                assert len(data["pin"]) == 6
                original_pin = data["pin"]
                assert "ips" in data

            # 2. Verify with wrong PIN via POST /api/pair/pin/verify
            async with client.post(f"{base_url}/api/pair/pin/verify", json={"pin": "000000"}) as bad_res:
                assert bad_res.status == 401
                bad_data = await bad_res.json()
                assert bad_data["success"] is False

            # 3. Verify with correct PIN
            async with client.post(
                f"{base_url}/api/pair/pin/verify",
                json={"pin": original_pin, "device_name": "Test Pixel"}
            ) as good_res:
                assert good_res.status == 200
                good_data = await good_res.json()
                assert good_data["success"] is True
                assert "shared_secret" in good_data
                assert good_data["shared_secret"] == config.shared_secret

            # 4. Old PIN is rotated and no longer valid
            async with client.post(f"{base_url}/api/pair/pin/verify", json={"pin": original_pin}) as reused_res:
                assert reused_res.status == 401

            # 5. Refresh PIN via POST /api/pair/pin/refresh
            async with client.post(f"{base_url}/api/pair/pin/refresh") as refresh_res:
                assert refresh_res.status == 200
                refresh_data = await refresh_res.json()
                assert "pin" in refresh_data
                assert len(refresh_data["pin"]) == 6

            # 6. Test Web Portal HTML rendering via GET / with Accept: text/html
            headers = {"Accept": "text/html,application/xhtml+xml"}
            async with client.get(f"{base_url}/", headers=headers) as html_res:
                assert html_res.status == 200
                assert "text/html" in html_res.headers["Content-Type"]
                html = await html_res.text()
                assert "Leash Security Portal" in html
                assert "One-Time Pairing Code" in html

            # 7. Test Web Portal direct GET /pair route
            async with client.get(f"{base_url}/pair") as pair_res:
                assert pair_res.status == 200
                html_pair = await pair_res.text()
                assert "Leash Security Portal" in html_pair

    finally:
        await server.stop()
