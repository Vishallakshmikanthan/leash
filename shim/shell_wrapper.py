"""
shim/shell_wrapper.py - Command interceptor shim routing agent executions through Leash daemon.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import List, Optional

from contracts.models import (
    ActionKind,
    ActionRequest,
    CommandResult,
    DecidedBy,
    Decision,
    Severity,
    Verdict,
)
from daemon.policy_evaluator import PolicyEvaluator
from daemon.server import LeashDaemonServer


class ShellShim:
    """Interception wrapper executing in place of default shell, returning structured results."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        daemon_server: Optional[LeashDaemonServer] = None,
        daemon_url: Optional[str] = None,
        agent_name: Optional[str] = None,
    ):
        self.session_id = session_id or os.environ.get("LEASH_SESSION_ID", "s_default")
        self.daemon_server = daemon_server
        self.daemon_url = daemon_url or os.environ.get("LEASH_DAEMON_URL", "http://127.0.0.1:8765")
        self.agent_name = agent_name or os.environ.get("LEASH_AGENT_NAME", "coding-agent")
        self._local_evaluator = PolicyEvaluator()

    def _build_request(self, command: str, cwd: Optional[str] = None) -> ActionRequest:
        return ActionRequest(
            id=f"a_{uuid.uuid4().hex[:12]}",
            session=self.session_id,
            ts=int(time.time()),
            nonce=uuid.uuid4().hex[:8],
            kind=ActionKind.SHELL,
            command=command,
            cwd=cwd or os.getcwd(),
            agent=self.agent_name,
        )

    def execute(self, command: str, cwd: Optional[str] = None) -> CommandResult:
        """Synchronously execute a command through the Leash interception pipeline."""
        req = self._build_request(command, cwd)

        # 1. In-process daemon server
        if self.daemon_server:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # Caller has an active event loop: create task or future
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(asyncio.run, self.daemon_server.execute_action(req)).result()
            else:
                return asyncio.run(self.daemon_server.execute_action(req))

        # 2. Out-of-process daemon HTTP endpoint
        if self.daemon_url:
            try:
                endpoint = f"{self.daemon_url.rstrip('/')}/action"
                payload = req.to_dict()
                payload["execute"] = True
                data = json.dumps(payload).encode("utf-8")
                http_req = urllib.request.Request(
                    endpoint, data=data, headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(http_req, timeout=self._get_timeout()) as resp:
                    resp_body = json.loads(resp.read().decode("utf-8"))
                    return CommandResult.from_dict(resp_body)
            except (urllib.error.URLError, ConnectionRefusedError, TimeoutError, OSError) as e:
                # If daemon is unreachable: Fail Closed for dangerous operations
                return self._evaluate_offline_fail_closed(req, reason=f"Daemon unreachable ({e})")

        # 3. Fallback standalone evaluation
        return self._evaluate_offline_fail_closed(req, reason="No daemon configured")

    async def async_execute(self, command: str, cwd: Optional[str] = None) -> CommandResult:
        """Asynchronously execute a command through the Leash interception pipeline."""
        req = self._build_request(command, cwd)
        if self.daemon_server:
            return await self.daemon_server.execute_action(req)
        return await asyncio.to_thread(self.execute, command, cwd)

    def intercept_and_run(self, cmd_args: List[str], cwd: Optional[str] = None) -> int:
        """Standard shell interception entrypoint returning process exit code."""
        cmd_str = " ".join(cmd_args)
        result = self.execute(cmd_str, cwd=cwd)

        if not result.allowed:
            sys.stderr.write(result.stderr)
            return result.exit_code

        # Output captured stdout/stderr
        if result.stdout:
            sys.stdout.write(result.stdout)
            sys.stdout.flush()
        if result.stderr:
            sys.stderr.write(result.stderr)
            sys.stderr.flush()

        return result.exit_code

    def _get_timeout(self) -> float:
        try:
            return float(os.environ.get("LEASH_TIMEOUT_SECONDS", "35"))
        except ValueError:
            return 35.0

    def _evaluate_offline_fail_closed(self, request: ActionRequest, reason: str) -> CommandResult:
        """Local fail-closed behavior when daemon channel cannot be reached."""
        start_time = time.time()
        assessment = self._local_evaluator.evaluate(request)

        # Allow low risk commands like pytest, ls, git status
        if assessment.severity == Severity.LOW and self._local_evaluator.is_quick_allow(request):
            try:
                proc = subprocess.run(
                    request.command or "",
                    shell=True,
                    cwd=request.cwd,
                    capture_output=True,
                    text=True,
                )
                return CommandResult(
                    action_id=request.id,
                    session_id=request.session,
                    verdict=Verdict.ALLOW,
                    allowed=True,
                    exit_code=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    risk_assessment=assessment,
                    duration_ms=(time.time() - start_time) * 1000,
                )
            except Exception as ex:
                return CommandResult(
                    action_id=request.id,
                    session_id=request.session,
                    verdict=Verdict.ALLOW,
                    allowed=True,
                    exit_code=1,
                    stdout="",
                    stderr=str(ex),
                    risk_assessment=assessment,
                    duration_ms=(time.time() - start_time) * 1000,
                )

        # Medium or High risk: Fail Closed
        blocked_msg = (
            f"\n[LEASH BLOCKED] Execution denied by safety policy: {request.command}\n"
            f"Reason: {reason}: failed closed for risky operation ({assessment.category}).\n"
        )
        return CommandResult(
            action_id=request.id,
            session_id=request.session,
            verdict=Verdict.DENY,
            allowed=False,
            exit_code=126,
            stdout="",
            stderr=blocked_msg,
            blocked_reason=f"{reason}: failed closed ({assessment.category})",
            risk_assessment=assessment,
            duration_ms=(time.time() - start_time) * 1000,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Leash Shell Interceptor")
    parser.add_argument("--json", action="store_true", help="Output structured CommandResult JSON")
    parser.add_argument("--session", default=None, help="Session ID")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute")
    args = parser.parse_args()

    if not args.cmd:
        sys.stderr.write("Usage: python -m shim.shell_wrapper [--json] [--session S_ID] -- <command>\n")
        sys.exit(1)

    cmd_args = args.cmd
    if cmd_args[0] == "--":
        cmd_args = cmd_args[1:]

    shim = ShellShim(session_id=args.session)
    if args.json:
        result = shim.execute(" ".join(cmd_args))
        print(json.dumps(result.to_dict(), indent=2))
        sys.exit(result.exit_code)
    else:
        exit_code = shim.intercept_and_run(cmd_args)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
