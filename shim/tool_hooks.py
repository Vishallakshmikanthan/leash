"""
shim/tool_hooks.py - Tool-level callbacks for intercepting file reads, edits, and tool calls.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import time
import uuid
from typing import Any, Dict, Optional

from contracts.models import (
    ActionKind,
    ActionRequest,
    Decision,
    ProvenanceEvent,
    ProvenanceKind,
    Verdict,
)
from daemon.server import LeashDaemonServer
from session.manager import SessionManager


class ToolHooks:
    """Pre-execution hooks for AI agents supporting tool callbacks."""

    UNTRUSTED_SOURCES = {"README.md", "README", "ISSUE_TEMPLATE", "issue.txt", "prompt.txt"}

    def __init__(self, session_id: str, server: LeashDaemonServer, session_mgr: SessionManager):
        self.session_id = session_id
        self.server = server
        self.session_mgr = session_mgr

    def _run_sync(self, coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    async def async_on_pre_file_read(self, file_path: str) -> bool:
        """Async callback before agent reads a file."""
        # 1. Check for untrusted read (F1 provenance)
        filename = file_path.split("/")[-1].split("\\")[-1]
        if filename in self.UNTRUSTED_SOURCES:
            p_event = ProvenanceEvent(
                id=f"p_{uuid.uuid4().hex[:12]}",
                session=self.session_id,
                ts=int(time.time()),
                kind=ProvenanceKind.UNTRUSTED_READ,
                source=filename,
                line=1,
                flags=["untrusted-doc"],
                snippet=f"Read of {filename}",
            )
            self.session_mgr.record_provenance_event(p_event)

        # 2. Submit ActionRequest for read evaluation
        req = ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=self.session_id,
            ts=int(time.time()),
            nonce=uuid.uuid4().hex[:8],
            kind=ActionKind.FILE_READ,
            target_path=file_path,
            agent="agent-tool-hook",
            cwd=".",
        )
        decision = await self.server.submit_action(req)
        return decision.verdict == Verdict.ALLOW

    def on_pre_file_read(self, file_path: str) -> bool:
        """Synchronous wrapper for on_pre_file_read."""
        return self._run_sync(self.async_on_pre_file_read(file_path))

    async def async_on_pre_file_edit(self, file_path: str, new_content: str) -> bool:
        """Async callback before agent edits or writes to a file."""
        req = ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=self.session_id,
            ts=int(time.time()),
            nonce=uuid.uuid4().hex[:8],
            kind=ActionKind.FILE_EDIT,
            target_path=file_path,
            agent="agent-tool-hook",
            cwd=".",
        )
        decision = await self.server.submit_action(req)
        return decision.verdict == Verdict.ALLOW

    def on_pre_file_edit(self, file_path: str, new_content: str) -> bool:
        """Synchronous wrapper for on_pre_file_edit."""
        return self._run_sync(self.async_on_pre_file_edit(file_path, new_content))

    async def async_on_pre_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Async callback before agent executes a tool function."""
        req = ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=self.session_id,
            ts=int(time.time()),
            nonce=uuid.uuid4().hex[:8],
            kind=ActionKind.TOOL_CALL,
            tool_name=tool_name,
            tool_args=tool_args,
            agent="agent-tool-hook",
            cwd=".",
        )
        decision = await self.server.submit_action(req)
        return decision.verdict == Verdict.ALLOW

    def on_pre_tool_call(self, tool_name: str, tool_args: Dict[str, Any]) -> bool:
        """Synchronous wrapper for on_pre_tool_call."""
        return self._run_sync(self.async_on_pre_tool_call(tool_name, tool_args))
