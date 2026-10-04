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
from gates.provenance_tracker import ProvenanceTracker
from session.manager import SessionManager


class ToolHooks:
    """Pre-execution hooks for AI agents supporting tool callbacks."""

    def __init__(
        self,
        session_id: str,
        server: LeashDaemonServer,
        session_mgr: SessionManager,
        provenance_tracker: Optional[ProvenanceTracker] = None,
    ):
        self.session_id = session_id
        self.server = server
        self.session_mgr = session_mgr
        self.tracker = provenance_tracker or session_mgr.provenance_tracker or ProvenanceTracker()

    def _run_sync(self, coro):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, coro).result()
        return asyncio.run(coro)

    async def async_on_pre_file_read(self, file_path: str, line: Optional[int] = None) -> bool:
        """Async callback before agent reads a file."""
        # 1. Check for untrusted read (F1 provenance)
        if self.tracker.is_untrusted_source(file_path):
            session = self.session_mgr.get_session(self.session_id)
            base_dir = session.worktree_path if session else None
            detected_line, snippet, flags = self.tracker.analyze_read(
                file_path, base_dir=base_dir, line_hint=line
            )
            filename = file_path.replace("\\", "/").split("/")[-1] or file_path

            p_event = self.tracker.create_provenance_event(
                session_id=self.session_id,
                source=filename,
                line=detected_line,
                flags=flags,
                snippet=snippet,
            )
            await self.server.emit_provenance_event(p_event)

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

    def on_pre_file_read(self, file_path: str, line: Optional[int] = None) -> bool:
        """Synchronous wrapper for on_pre_file_read."""
        return self._run_sync(self.async_on_pre_file_read(file_path, line=line))

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
        # Check if tool invocation reads untrusted content
        target_path = (
            tool_args.get("file_path")
            or tool_args.get("path")
            or tool_args.get("AbsolutePath")
            or tool_args.get("target_path")
            or tool_args.get("url")
        )
        if target_path and isinstance(target_path, str) and self.tracker.is_untrusted_source(target_path):
            line_hint = (
                tool_args.get("line")
                or tool_args.get("start_line")
                or tool_args.get("StartLine")
                or tool_args.get("line_number")
            )
            try:
                line_hint_int = int(line_hint) if line_hint is not None else None
            except (ValueError, TypeError):
                line_hint_int = None

            session = self.session_mgr.get_session(self.session_id)
            base_dir = session.worktree_path if session else None
            detected_line, snippet, flags = self.tracker.analyze_read(
                target_path, base_dir=base_dir, line_hint=line_hint_int
            )
            filename = target_path.replace("\\", "/").split("/")[-1] or target_path

            p_event = self.tracker.create_provenance_event(
                session_id=self.session_id,
                source=filename,
                line=detected_line,
                flags=flags,
                snippet=snippet,
            )
            await self.server.emit_provenance_event(p_event)

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

