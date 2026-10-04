"""
shim/shell_wrapper.py - Command interceptor shim routing agent executions through Leash daemon.
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from typing import List, Optional

from contracts.models import ActionKind, ActionRequest, Decision, Verdict
from daemon.server import LeashDaemonServer


class ShellShim:
    """Interception wrapper executing in place of default shell."""

    def __init__(self, session_id: str, daemon_server: Optional[LeashDaemonServer] = None):
        self.session_id = session_id
        self.daemon_server = daemon_server

    def intercept_and_run(self, cmd_args: List[str], cwd: Optional[str] = None) -> int:
        cmd_str = " ".join(cmd_args)
        cwd = cwd or os.getcwd()

        request = ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=self.session_id,
            ts=int(time.time()),
            nonce=uuid.uuid4().hex[:8],
            kind=ActionKind.SHELL,
            command=cmd_str,
            cwd=cwd,
            agent=os.environ.get("LEASH_AGENT_NAME", "coding-agent"),
        )

        decision: Optional[Decision] = None
        if self.daemon_server:
            # Synchronous wait for async evaluation
            import asyncio
            decision = asyncio.run(self.daemon_server.submit_action(request))
        else:
            # Fallback mock decision if running standalone shim
            decision = Decision(
                id=f"d_mock_{request.id}",
                action_id=request.id,
                session=self.session_id,
                ts=int(time.time()),
                nonce="mock_nonce",
                verdict=Verdict.ALLOW,
                by=contracts.models.DecidedBy.AUTO,
            )

        if decision.verdict == Verdict.DENY:
            sys.stderr.write(f"\n[LEASH BLOCKED] Execution denied by safety policy: {cmd_str}\n")
            if decision.note:
                sys.stderr.write(f"Reason: {decision.note}\n")
            return 126  # Standard command invocation failure code

        # Allowed: invoke real command
        proc = subprocess.run(cmd_args, cwd=cwd)
        return proc.returncode
