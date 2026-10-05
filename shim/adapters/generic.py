"""
shim/adapters/generic.py - Generic JSON agent hook adapter.
"""
from __future__ import annotations

import json
from typing import Any, Dict

from shim.adapters.base import BaseAgentAdapter


class GenericJsonAdapter(BaseAgentAdapter):
    """
    Generic adapter accepting JSON on standard input with schema:
    {
      "kind": "shell" | "file_read" | "file_edit" | "tool_call",
      "command": "...",
      "target_path": "...",
      "cwd": "...",
      "tool_name": "...",
      "tool_args": {...}
    }
    """

    def parse_hook_input(self, raw_input: str) -> Dict[str, Any]:
        if not raw_input.strip():
            return {}
        return json.loads(raw_input)

    def translate_to_action(self, parsed_payload: Dict[str, Any]) -> Dict[str, Any]:
        kind = parsed_payload.get("kind")
        if not kind:
            if "command" in parsed_payload:
                kind = "shell"
            elif "target_path" in parsed_payload:
                kind = "file_read"
            else:
                kind = "tool_call"

        return {
            "kind": kind,
            "command": parsed_payload.get("command"),
            "target_path": parsed_payload.get("target_path"),
            "cwd": parsed_payload.get("cwd", "."),
            "tool_name": parsed_payload.get("tool_name"),
            "tool_args": parsed_payload.get("tool_args"),
        }
