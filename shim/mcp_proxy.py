"""
shim/mcp_proxy.py - Model Context Protocol (MCP) JSON-RPC interceptor proxy.
Intercepts tool calls, checks approvals with Leash Agent Plane, and blocks unauthorized executions.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import List, Optional

from shim.adapters.claude_code import ClaudeCodeAdapter

logger = logging.getLogger("leash.shim.mcp_proxy")


class McpProxy:
    """Proxies stdio JSON-RPC communication between an agent and an MCP server."""

    def __init__(self, server_cmd: List[str], agent_url: Optional[str] = None, session_token: Optional[str] = None):
        self.server_cmd = server_cmd
        self.agent_url = agent_url or os.environ.get("LEASH_AGENT_URL", "http://127.0.0.1:8766")
        self.session_token = session_token or os.environ.get("LEASH_SESSION_TOKEN", "")
        self.adapter = ClaudeCodeAdapter(self.agent_url, self.session_token)

    async def run(self) -> int:
        proc = await asyncio.create_subprocess_exec(
            self.server_cmd[0],
            *self.server_cmd[1:],
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def _forward_server_output():
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()

        async def _forward_server_errors():
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()

        asyncio.create_task(_forward_server_output())
        asyncio.create_task(_forward_server_errors())

        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line_bytes = await reader.readline()
            if not line_bytes:
                break

            line_str = line_bytes.decode("utf-8", errors="replace").strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                # Forward non-json directly
                proc.stdin.write(line_bytes)
                await proc.stdin.drain()
                continue

            # Check if this is a tools/call method
            method = msg.get("method")
            if method == "tools/call":
                params = msg.get("params", {})
                tool_name = params.get("name", "unknown")
                tool_args = params.get("arguments", {})

                # Evaluate with Agent Plane
                action_dict = self.adapter.translate_to_action({
                    "name": tool_name,
                    "arguments": tool_args,
                })
                allowed, note, _ = self.adapter.submit_to_agent_plane(action_dict)

                if not allowed:
                    err_res = {
                        "jsonrpc": "2.0",
                        "id": msg.get("id"),
                        "error": {
                            "code": -32000,
                            "message": f"Tool execution blocked by Leash Guard: {note}",
                        },
                    }
                    sys.stdout.write(json.dumps(err_res) + "\n")
                    sys.stdout.flush()
                    continue

            proc.stdin.write(line_bytes)
            await proc.stdin.drain()

        return await proc.wait()


# Export McpAdapter as alias to ClaudeCodeAdapter for MCP proxying
McpAdapter = ClaudeCodeAdapter

