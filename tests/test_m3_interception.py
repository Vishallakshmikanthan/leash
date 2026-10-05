"""
tests/test_m3_interception.py - Acceptance tests for M3 (Interception layer & agent adapters)
"""
import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import aiohttp

from contracts.models import ActionKind, ActionRequest, ProtectionLevel, Severity, Verdict
from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.container import ContainerRuntime
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from shim.adapters.claude_code import ClaudeCodeAdapter
from shim.adapters.generic import GenericJsonAdapter
from shim.shims import install_shims, find_real_binary, SHIM_TARGETS


@pytest.fixture
def temp_env():
    td = tempfile.mkdtemp(prefix="leash_m3_")
    yield Path(td)
    shutil.rmtree(td, ignore_errors=True)


def test_m3_1_protection_levels():
    """M3.1 Acceptance: Protection levels L1 Cooperative, L2 Contained, L3 Isolated."""
    assert ProtectionLevel.L1_COOPERATIVE.value == "L1 Cooperative"
    assert ProtectionLevel.L2_CONTAINED.value == "L2 Contained"
    assert ProtectionLevel.L3_ISOLATED.value == "L3 Isolated"


def test_m3_3_install_shims(temp_env):
    """M3.3 Acceptance: PATH shims generated for all targets."""
    shims_dir = install_shims(temp_env / "shims")
    assert shims_dir.exists()

    for target in SHIM_TARGETS:
        if os.name == "nt":
            shim_file = shims_dir / f"{target}.cmd"
        else:
            shim_file = shims_dir / target
        assert shim_file.exists(), f"Shim for {target} not found"
        content = shim_file.read_text(encoding="utf-8")
        assert "leash exec" in content


def test_m3_3_container_command_isolation(temp_env):
    """M3.3 Acceptance: Container isolation mounts only worktree and disables network."""
    runtime = ContainerRuntime(runtime_bin="docker")
    worktree = temp_env / "worktree"
    worktree.mkdir()

    cmd = runtime.build_contained_command(
        agent_cmd=["python", "agent.py"],
        worktree_path=str(worktree),
        session_token="test_tok_123",
        agent_url="http://127.0.0.1:8766",
        enable_network=False,
    )

    # 1. Runs docker non-interactively and cleans up
    assert cmd[0] == "docker"
    assert "run" in cmd
    assert "--rm" in cmd

    # 2. Network is disabled (--network none)
    assert "--network" in cmd
    idx = cmd.index("--network")
    assert cmd[idx + 1] == "none"

    # 3. Mounts only the worktree to /workspace
    worktree_mount = f"{str(worktree.resolve())}:/workspace:rw"
    assert "-v" in cmd
    v_idx = cmd.index("-v")
    assert cmd[v_idx + 1] == worktree_mount

    # 4. Sets HOME away from host home
    assert "HOME=/tmp" in " ".join(cmd)


@pytest.mark.asyncio
async def test_m3_2_claude_code_adapter_pretool_hook(temp_env):
    """M3.2 Acceptance: Claude Code adapter intercepts tool calls and blocks denied actions."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=8941,
        agent_plane_port=8942,
        enable_test_routes=False,
    )
    session_mgr = SessionManager(temp_env)
    session = session_mgr.create_session()
    token = session_mgr.get_session_token(session.session_id)
    audit_logger = AuditLogger(temp_env / "audit.jsonl")

    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    adapter = ClaudeCodeAdapter(
        agent_url=f"http://127.0.0.1:{config.agent_plane_port}",
        session_token=token,
    )

    try:
        # 1. Benign tool call: allowed
        benign_hook_input = json.dumps({
            "tool_name": "Bash",
            "tool_input": {
                "command": "git status",
                "cwd": session.worktree_path,
            }
        })
        exit_code = await asyncio.to_thread(adapter.handle, benign_hook_input)
        assert exit_code == 0

        # 2. Dangerous tool call (rm -rf /): blocked with exit code 1
        dangerous_hook_input = json.dumps({
            "tool_name": "Bash",
            "tool_input": {
                "command": "rm -rf /",
                "cwd": session.worktree_path,
            }
        })
        exit_code_deny = await asyncio.to_thread(adapter.handle, dangerous_hook_input)
        assert exit_code_deny == 1

        # 3. File Read tool call (safe development file: allowed)
        read_hook_input = json.dumps({
            "tool_name": "FileRead",
            "tool_input": {
                "path": "src/main.py",
                "cwd": session.worktree_path,
            }
        })
        exit_code_read = await asyncio.to_thread(adapter.handle, read_hook_input)
        assert exit_code_read == 0

        # 4. Untrusted file read (README.md triggers untrusted-text-influence, blocked when fail-closed)
        untrusted_read_input = json.dumps({
            "tool_name": "FileRead",
            "tool_input": {
                "path": "README.md",
                "cwd": session.worktree_path,
            }
        })
        exit_code_untrusted = await asyncio.to_thread(adapter.handle, untrusted_read_input)
        assert exit_code_untrusted == 1
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_m3_2_generic_json_adapter(temp_env):
    """M3.2 Acceptance: Generic JSON adapter parses stdin and queries Agent Plane."""
    config = DaemonConfig(
        host="127.0.0.1",
        port=8943,
        agent_plane_port=8944,
        enable_test_routes=False,
    )
    session_mgr = SessionManager(temp_env)
    session = session_mgr.create_session()
    token = session_mgr.get_session_token(session.session_id)
    audit_logger = AuditLogger(temp_env / "audit.jsonl")

    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    adapter = GenericJsonAdapter(
        agent_url=f"http://127.0.0.1:{config.agent_plane_port}",
        session_token=token,
    )

    try:
        payload = json.dumps({
            "kind": "shell",
            "command": "python --version",
            "cwd": session.worktree_path,
        })
        exit_code = await asyncio.to_thread(adapter.handle, payload)
        assert exit_code == 0
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_m3_4_mcp_proxy_interception(temp_env):
    """M3.4 Acceptance: MCP proxy adapter evaluates tool_call actions."""
    from shim.mcp_proxy import McpAdapter

    config = DaemonConfig(
        host="127.0.0.1",
        port=8945,
        agent_plane_port=8946,
        enable_test_routes=False,
    )
    session_mgr = SessionManager(temp_env)
    session = session_mgr.create_session()
    token = session_mgr.get_session_token(session.session_id)
    audit_logger = AuditLogger(temp_env / "audit.jsonl")

    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()

    adapter = McpAdapter(
        agent_url=f"http://127.0.0.1:{config.agent_plane_port}",
        session_token=token,
    )

    try:
        # Safe MCP tool invocation
        safe_action = adapter.translate_to_action({
            "name": "read_file",
            "arguments": {"path": "src/main.py", "cwd": session.worktree_path},
        })
        allowed, note, _ = await asyncio.to_thread(adapter.submit_to_agent_plane, safe_action)
        assert allowed is True

        # Risky MCP tool invocation (rm -rf / without approval -> blocked fail closed)
        risky_action = adapter.translate_to_action({
            "name": "bash",
            "arguments": {"command": "rm -rf /", "cwd": session.worktree_path},
        })
        allowed_risky, _, _ = await asyncio.to_thread(adapter.submit_to_agent_plane, risky_action)
        assert allowed_risky is False
    finally:
        await server.stop()

