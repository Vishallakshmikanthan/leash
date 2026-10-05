"""
shim/adapters/claude_code.py - Hook adapter for Claude Code PreToolUse protocol.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from shim.adapters.base import BaseAgentAdapter


class ClaudeCodeAdapter(BaseAgentAdapter):
    """
    Adapter for Claude Code PreToolUse hook.
    Claude Code supplies JSON on stdin with tool name and arguments.
    """

    def parse_hook_input(self, raw_input: str) -> Dict[str, Any]:
        if not raw_input.strip():
            return {}
        return json.loads(raw_input)

    def translate_to_action(self, parsed_payload: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = (
            parsed_payload.get("tool_name")
            or parsed_payload.get("tool")
            or parsed_payload.get("name")
            or "unknown"
        )
        tool_input = (
            parsed_payload.get("tool_input")
            or parsed_payload.get("input")
            or parsed_payload.get("arguments")
            or {}
        )

        name_lower = tool_name.lower()

        # 1. Shell commands (Bash / Terminal / Exec)
        if any(term in name_lower for term in ("bash", "sh", "terminal", "exec", "command")):
            cmd = tool_input.get("command") or tool_input.get("cmd") or ""
            return {
                "kind": "shell",
                "command": cmd,
                "cwd": tool_input.get("cwd", "."),
                "tool_name": tool_name,
                "tool_args": tool_input,
            }

        # 2. File Reads (View / Read / Glob)
        elif any(term in name_lower for term in ("read", "view", "cat", "open")):
            target_path = tool_input.get("path") or tool_input.get("file_path") or tool_input.get("target_path")
            return {
                "kind": "file_read",
                "target_path": target_path,
                "cwd": tool_input.get("cwd", "."),
                "tool_name": tool_name,
                "tool_args": tool_input,
            }

        # 3. File Edits / Writes (Edit / Write / Replace / Patch)
        elif any(term in name_lower for term in ("edit", "write", "replace", "patch", "modify")):
            target_path = tool_input.get("path") or tool_input.get("file_path") or tool_input.get("target_path")
            return {
                "kind": "file_edit",
                "target_path": target_path,
                "cwd": tool_input.get("cwd", "."),
                "tool_name": tool_name,
                "tool_args": tool_input,
            }

        # 4. Web Fetch / Network
        elif any(term in name_lower for term in ("fetch", "http", "curl", "web")):
            return {
                "kind": "tool_call",
                "tool_name": tool_name,
                "tool_args": tool_input,
                "cwd": ".",
            }

        # 5. Default generic tool call
        return {
            "kind": "tool_call",
            "tool_name": tool_name,
            "tool_args": tool_input,
            "cwd": ".",
        }
