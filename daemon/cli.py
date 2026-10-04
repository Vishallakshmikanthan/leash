"""
daemon/cli.py - Leash CLI for running agent sessions, pairing, reporting, and command execution.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.receipt_builder import ReceiptBuilder
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from shim.shell_wrapper import ShellShim


def cmd_pair(args: argparse.Namespace) -> None:
    config = DaemonConfig.load_default()
    qr_uri = f"leash://pair?host={config.host}&port={config.port}&secret={config.shared_secret}&version=1.0"
    pairing_info = {
        "host": config.host,
        "port": config.port,
        "shared_secret": config.shared_secret,
        "protocol_version": "1.0",
        "qr_uri": qr_uri,
        "created_at": int(time.time()),
    }
    config.pairing_code_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config.pairing_code_file, "w", encoding="utf-8") as f:
        json.dump(pairing_info, f, indent=2)

    print("=== LEASH PAIRING CREDENTIALS ===")
    print(f"Host:       {config.host}")
    print(f"Port:       {config.port}")
    print(f"Secret:     {config.shared_secret}")
    print(f"QR URI:     {qr_uri}")
    print(f"Pairing info written to: {config.pairing_code_file}")
    print("================================")



def cmd_report(args: argparse.Namespace) -> None:
    config = DaemonConfig.load_default()
    audit_logger = AuditLogger(config.audit_log_path)
    session_id = args.session

    events = audit_logger.read_session_events(session_id)
    if not events:
        print(f"No audit events found for session: {session_id}")
        return

    out_file = config.receipt_output_path
    ReceiptBuilder.save_receipt(session_id, events, out_file)
    print(f"Report generated successfully: {out_file}")
    print(ReceiptBuilder.generate_markdown(session_id, events))


async def run_server(config: DaemonConfig) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    session_mgr = SessionManager(Path("."))
    audit_logger = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()
    print(f"Leash Daemon server running on http://{config.host}:{config.port} (WebSocket ready)")
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        await server.stop()


async def run_agent_session(agent_cmd: list[str], config: DaemonConfig) -> int:
    session_mgr = SessionManager(Path("."))
    session = session_mgr.create_session()
    audit_logger = AuditLogger(config.audit_log_path)

    server = LeashDaemonServer(config, session_mgr, audit_logger)
    server.default_session_id = session.session_id
    await server.start()

    print(f"[+] Leash Session Started: {session.session_id}")
    print(f"[+] Worktree: {session.worktree_path}")
    print(f"[+] Daemon listening on port {config.port}")

    # Set environment variables for the agent subprocess
    env = os.environ.copy()
    env["LEASH_SESSION_ID"] = session.session_id
    env["LEASH_DAEMON_URL"] = f"http://127.0.0.1:{config.port}"
    env["LEASH_PORT"] = str(config.port)
    env["LEASH_SHARED_SECRET"] = config.shared_secret
    env["LEASH_WORKTREE"] = session.worktree_path

    # Clean command args
    if agent_cmd and agent_cmd[0] == "--":
        agent_cmd = agent_cmd[1:]

    print(f"[+] Launching agent: {' '.join(agent_cmd)}\n")
    proc = await asyncio.create_subprocess_exec(
        agent_cmd[0],
        *agent_cmd[1:],
        env=env,
        cwd=session.worktree_path if Path(session.worktree_path).exists() else ".",
    )

    exit_code = await proc.wait()
    print(f"\n[+] Agent exited with status: {exit_code}")

    # Generate receipt
    events = audit_logger.read_session_events(session.session_id)
    if events:
        out_file = config.receipt_output_path
        ReceiptBuilder.save_receipt(session.session_id, events, out_file)
        print(f"[+] Agent receipt written to {out_file}")

    await server.stop()
    return exit_code


def cmd_exec(args: argparse.Namespace) -> None:
    cmd_args = args.cmd
    if cmd_args and cmd_args[0] == "--":
        cmd_args = cmd_args[1:]
    command_str = " ".join(cmd_args)

    shim = ShellShim(session_id=args.session)
    if args.json:
        result = shim.execute(command_str)
        print(json.dumps(result.to_dict(), indent=2))
        sys.exit(result.exit_code)
    else:
        exit_code = shim.intercept_and_run(cmd_args)
        sys.exit(exit_code)


def main() -> None:
    parser = argparse.ArgumentParser(prog="leash", description="Leash: Phone-based safety layer for AI coding agents.")
    subparsers = parser.add_subparsers(dest="command")

    # leash pair
    subparsers.add_parser("pair", help="Generate pairing token and connection info for Phone Guard")

    # leash server
    subparsers.add_parser("server", help="Start the Leash daemon server")

    # leash report
    report_parser = subparsers.add_parser("report", help="Generate Markdown agent receipt for PR")
    report_parser.add_argument("--session", required=True, help="Session ID to report")

    # leash exec [--json] [--session S_ID] -- <command>
    exec_parser = subparsers.add_parser("exec", help="Execute a command through the Leash interceptor")
    exec_parser.add_argument("--json", action="store_true", help="Output JSON CommandResult")
    exec_parser.add_argument("--session", default=None, help="Session ID")
    exec_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to execute")

    # leash run -- <command>
    run_parser = subparsers.add_parser("run", help="Run agent in an isolated Leash session")
    run_parser.add_argument("agent_cmd", nargs=argparse.REMAINDER, help="Agent command to execute")

    args = parser.parse_args()

    if args.command == "pair":
        cmd_pair(args)
    elif args.command == "server":
        config = DaemonConfig.load_default()
        asyncio.run(run_server(config))
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "exec":
        cmd_exec(args)
    elif args.command == "run":
        if not args.agent_cmd:
            print("Error: Specify agent command after '--'. Example: leash run -- python agent.py")
            sys.exit(1)
        config = DaemonConfig.load_default()
        exit_code = asyncio.run(run_agent_session(args.agent_cmd, config))
        sys.exit(exit_code)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
