"""
daemon/cli.py - Leash CLI for running agent sessions, pairing, and reporting.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from daemon.audit_logger import AuditLogger
from daemon.config import DaemonConfig
from daemon.receipt_builder import ReceiptBuilder
from daemon.server import LeashDaemonServer
from session.manager import SessionManager


def cmd_pair(args: argparse.Namespace) -> None:
    config = DaemonConfig.load_default()
    pairing_info = {
        "host": config.host,
        "port": config.port,
        "shared_secret": config.shared_secret,
        "protocol_version": "1.0",
    }
    config.pairing_code_file.parent.mkdir(parents=True, exist_ok=True)
    with open(config.pairing_code_file, "w", encoding="utf-8") as f:
        json.dump(pairing_info, f, indent=2)

    print("=== LEASH PAIRING CREDENTIALS ===")
    print(f"Host: {config.host}")
    print(f"Port: {config.port}")
    print(f"Secret: {config.shared_secret}")
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
    session_mgr = SessionManager(Path("."))
    audit_logger = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit_logger)
    await server.start()
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        await server.stop()


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
    elif args.command == "run":
        if not args.agent_cmd:
            print("Error: Specify agent command after '--'. Example: leash run -- python agent.py")
            sys.exit(1)
        print(f"Starting Leash session for command: {' '.join(args.agent_cmd)}")
        # Start server and run command
        config = DaemonConfig.load_default()
        asyncio.run(run_server(config))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
