"""
shim/adapters/base.py - Base adapter interface for AI agent tool hooks.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("leash.shim.adapters")


class BaseAgentAdapter(ABC):
    """Abstract base class for converting agent tool-use hooks into Leash ActionRequests."""

    def __init__(self, agent_url: Optional[str] = None, session_token: Optional[str] = None):
        self.agent_url = agent_url or os.environ.get("LEASH_AGENT_URL", "http://127.0.0.1:8766")
        self.session_token = session_token or os.environ.get("LEASH_SESSION_TOKEN", "")

    @abstractmethod
    def parse_hook_input(self, raw_input: str) -> Dict[str, Any]:
        """Parses the raw JSON or string provided to the hook via stdin or CLI args."""
        pass

    @abstractmethod
    def translate_to_action(self, parsed_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Translates the agent-specific tool call into Leash ActionRequest fields."""
        pass

    def submit_to_agent_plane(self, action_dict: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Sends action to Leash Agent Plane (POST /v1/action) using session capability token.
        Returns: (allowed, message, response_dict)
        """
        url = f"{self.agent_url}/v1/action"
        data = json.dumps(action_dict).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.session_token}",
        }

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                status = resp.status
                body = json.loads(resp.read().decode("utf-8"))
                allowed = body.get("verdict") == "allow"
                note = body.get("note") or ""
                return allowed, note, body
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            logger.error(f"Agent plane rejected action (HTTP {e.code}): {err_body}")
            return False, f"HTTP Error {e.code}: {err_body}", {}
        except Exception as e:
            logger.error(f"Failed to communicate with Leash agent plane: {e}")
            return False, f"Connection error: {str(e)}", {}

    def handle(self, raw_input: str) -> int:
        """
        Full hook lifecycle:
        1. Parse agent input
        2. Translate to Leash action
        3. Submit to Agent Plane
        4. Output response and return exit code (0 = allowed, 1 = blocked)
        """
        try:
            parsed = self.parse_hook_input(raw_input)
            action = self.translate_to_action(parsed)
            allowed, note, res = self.submit_to_agent_plane(action)

            if allowed:
                return 0
            else:
                sys.stderr.write(f"[LEASH BLOCKED] Action denied by Leash Guard: {note}\n")
                return 1
        except Exception as e:
            sys.stderr.write(f"[LEASH ERROR] Failed evaluating hook: {e}\n")
            return 1
