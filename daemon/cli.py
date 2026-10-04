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


def cmd_audit(args: argparse.Namespace) -> None:
    config = DaemonConfig.load_default()
    audit_logger = AuditLogger(config.audit_log_path)

    if args.sessions:
        sessions = audit_logger.list_sessions()
        if args.json:
            print(json.dumps({"sessions": sessions}, indent=2))
            return
        if not sessions:
            print("No recorded sessions found in audit log.")
            return
        print("\n=== RECORDED LEASH SESSIONS ===")
        print(f"{'SESSION ID':<22} {'AGENT':<16} {'ACTIONS':<8} {'ALLOWED':<8} {'BLOCKED':<8} {'TAINTED':<8}")
        print("-" * 72)
        for s in sessions:
            taint_str = "YES" if s.get("tainted") else "NO"
            print(f"{s['session_id']:<22} {s['agent']:<16} {s['total_actions']:<8} {s['allowed_count']:<8} {s['denied_count']:<8} {taint_str:<8}")
        print("===============================\n")
        return

    session_id = args.session
    if not session_id:
        sessions = audit_logger.list_sessions()
        if sessions:
            session_id = sessions[0]["session_id"]
        else:
            print("No audit history found.")
            return

    activity = audit_logger.get_session_activity(session_id)
    if args.json:
        print(json.dumps(activity, indent=2))
        return

    timeline = activity.get("timeline", [])
    if args.tail and args.tail > 0:
        timeline = timeline[-args.tail:]

    print("\n" + "=" * 80)
    print(f" LEASH SESSION ACTIVITY: {activity['session_id']}")
    print(f" Agent: {activity.get('agent', 'unknown')} | Worktree: {activity.get('worktree') or 'default'}")
    taint_status = "TAINTED (RISK ELEVATED)" if activity.get("tainted") else "CLEAN"
    print(f" Provenance: {taint_status}")
    print(f" Total Actions: {activity['total_actions']} | Allowed: {activity['allowed_count']} | Blocked: {activity['blocked_count']} | Tainted: {activity['tainted_count']}")

    if activity.get("decisions_by_method"):
        methods_str = ", ".join(f"{k}: {v}" for k, v in activity["decisions_by_method"].items())
        print(f" Decision Methods: {methods_str}")
    if activity.get("severity_breakdown"):
        sev_str = ", ".join(f"{k.upper()}: {v}" for k, v in activity["severity_breakdown"].items())
        print(f" Risk Severities: {sev_str}")
    print("=" * 80)

    if not timeline:
        print(" No actions recorded for this session.")
        print("=" * 80 + "\n")
        return

    print(f"\n{'TIME':<10} {'VERDICT':<9} {'METHOD':<10} {'SEV':<8} {'COMMAND / ATTEMPT':<40}")
    print("-" * 80)

    for item in timeline:
        time_part = item["timestamp_iso"].split("T")[1][:8] if "T" in item["timestamp_iso"] else str(item["ts"])
        verdict = item["verdict"].upper()
        method = item["decision_method"]
        sev = item["risk_severity"].upper()
        cmd = item["command"].replace("\n", " ")
        if len(cmd) > 38:
            cmd = cmd[:35] + "..."

        print(f"{time_part:<10} {verdict:<9} {method:<10} {sev:<8} {cmd:<40}")
        print(f"  └─ Why: {item['why']}")
        exec_res = item.get("execution_result") or {}
        if verdict == "ALLOW":
            exit_code = exec_res.get("exit_code", 0)
            duration = exec_res.get("duration_ms", 0.0)
            print(f"  └─ Execution: Exit {exit_code} ({duration:.1f}ms)")
        else:
            reason = exec_res.get("blocked_reason") or item.get("why") or "Denied by policy"
            print(f"  └─ Execution: BLOCKED - {reason}")
        if item.get("tainted"):
            src = item.get("taint_source") or "untrusted input"
            line = f":{item['taint_line']}" if item.get("taint_line") else ""
            print(f"  └─ Taint Influence: {src}{line}")
        print()

    print("=" * 80 + "\n")


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

    # leash audit [--session S_ID] [--sessions] [--json] [--tail N]
    audit_parser = subparsers.add_parser("audit", help="Inspect session audit log, decisions, and execution results")
    audit_parser.add_argument("--session", default=None, help="Session ID to view activity for")
    audit_parser.add_argument("--sessions", action="store_true", help="List all recorded sessions")
    audit_parser.add_argument("--json", action="store_true", help="Output raw structured JSON")
    audit_parser.add_argument("--tail", type=int, default=None, help="Show last N activity events")

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
    elif args.command == "audit":
        cmd_audit(args)
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
