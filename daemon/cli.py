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
from daemon.office_kit import OfficeKitClipboard, OfficeKitTransfer
from daemon.preview_manager import ScriptPreviewManager
from daemon.receipt_builder import ReceiptBuilder
from daemon.server import LeashDaemonServer
from session.manager import SessionManager
from shim.git_guard import GitGuard
from shim.shell_wrapper import ShellShim

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


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
    session_mgr = SessionManager(Path("."))
    session_id = args.session

    if not session_id:
        sessions = audit_logger.list_sessions()
        if sessions:
            session_id = sessions[0]["session_id"]
        else:
            print("No recorded sessions found in audit log.")
            return

    events = audit_logger.read_session_events(session_id)
    scope = session_mgr.get_session(session_id)
    changed_files = session_mgr.get_changed_files(session_id)

    if not events and not scope:
        print(f"No audit events found for session: {session_id}")
        return

    out_file = config.receipt_output_path
    ReceiptBuilder.save_receipt(
        session_id,
        events,
        out_file,
        session_scope=scope,
        changed_files=changed_files,
    )
    receipt_md = ReceiptBuilder.generate_markdown(
        session_id,
        events,
        session_scope=scope,
        changed_files=changed_files,
    )
    print(f"Report generated successfully: {out_file}\n")
    print(receipt_md)


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

    # Cleanly terminate session & generate comprehensive receipt
    reason = f"Agent completed with exit code {exit_code}"
    scope = session_mgr.terminate_session(session.session_id, reason=reason, cleanup_worktree=True)
    events = audit_logger.read_session_events(session.session_id)
    changed_files = session_mgr.get_changed_files(session.session_id)
    out_file = config.receipt_output_path

    ReceiptBuilder.save_receipt(
        session_id=session.session_id,
        events=events,
        output_path=out_file,
        session_scope=scope,
        changed_files=changed_files,
        termination_reason=reason,
    )
    receipt_md = ReceiptBuilder.generate_markdown(
        session_id=session.session_id,
        events=events,
        session_scope=scope,
        changed_files=changed_files,
        termination_reason=reason,
    )
    session_mgr.set_session_receipt(session.session_id, receipt_md)
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


def cmd_git(args: argparse.Namespace) -> None:
    git_args = args.git_args
    if git_args and git_args[0] == "--":
        git_args = git_args[1:]
    guard = GitGuard()
    exit_code = guard.run_git(git_args)
    sys.exit(exit_code)


def cmd_preview(args: argparse.Namespace) -> None:
    target = args.target
    preview = ScriptPreviewManager.generate_preview(target)
    if args.json:
        print(json.dumps(preview.to_dict(), indent=2))
        return

    print("\n=== LEASH SCRIPT PREVIEW (F3) ===")
    print(f"Target:      {preview.target} ({'Remote URL' if preview.is_remote else 'Local file'})")
    print(f"Lines:       {preview.total_lines}")
    print(f"Summary:     {preview.summary}")
    print(f"Why:         {preview.why}")
    print(f"Alternative: {preview.safer_alternative}")
    if preview.risks_detected:
        print("\nIdentified Risks:")
        for r in preview.risks_detected:
            print(f"  - {r}")
    print("\n--- Script Head (First 50 lines) ---")
    print(preview.head_snippet)
    print("===================================\n")


def cmd_rewind(args: argparse.Namespace) -> None:
    session_mgr = SessionManager(Path("."))
    session_id = args.session
    if not session_id:
        sessions = session_mgr.list_sessions(active_only=True) or session_mgr.list_sessions()
        if sessions:
            session_id = sessions[0].session_id
        else:
            print("No sessions found to rewind.")
            sys.exit(1)

    ok = session_mgr.rewind(session_id, git_ref=args.snapshot)
    if ok:
        print(f"[+] Successfully rewound session '{session_id}' to {args.snapshot or 'latest snapshot'}.")
    else:
        print(f"[-] Rewind failed for session '{session_id}'. Ensure snapshot ref exists and covers repo files only.")
        sys.exit(1)


def cmd_office_kit(args: argparse.Namespace) -> None:
    session_mgr = SessionManager(Path("."))
    transfer = OfficeKitTransfer()
    subaction = args.action

    if subaction == "sync-diff":
        session_id = args.session or session_mgr.active_session_id
        changed = session_mgr.get_changed_files(session_id) if session_id else []
        diff_text = f"# Diff for session {session_id}\n# Changed files: {len(changed)}\n"
        for c in changed:
            diff_text += f"- {c.get('path', 'unknown')} ({c.get('status', 'modified')})\n"
        transfer.sync_diff_to_clipboard(diff_text)
        print(f"[+] Synced diff for session {session_id} to clipboard.")
    elif subaction == "clip-decision":
        clip = OfficeKitClipboard.get_clipboard_text() or ""
        print(f"Clipboard content: {clip[:80]}...")
    elif subaction == "export":
        session_id = args.session or session_mgr.active_session_id
        receipt_md = session_mgr.get_session_receipt(session_id) or "# Leash Receipt"
        path = transfer.export_receipt(session_id or "default", receipt_md)
        print(f"[+] Receipt exported to {path}")


def cmd_session(args: argparse.Namespace) -> None:
    session_mgr = SessionManager(Path("."))
    action = args.action
    session_id = args.session

    if action == "list":
        sessions = session_mgr.list_sessions()
        print("\n=== RECORDED LEASH SESSIONS ===")
        for s in sessions:
            print(f"- {s.session_id} | Agent: {s.agent} | State: {s.state.value} | Worktree: {s.worktree_path}")
        print("===============================\n")
    elif action == "pause":
        if not session_id:
            print("Specify --session <id>")
            return
        ok = session_mgr.pause_session(session_id)
        print(f"[+] Session {session_id} paused: {ok}")
    elif action == "resume":
        if not session_id:
            print("Specify --session <id>")
            return
        ok = session_mgr.resume_session(session_id)
        print(f"[+] Session {session_id} resumed: {ok}")
    elif action == "terminate":
        if not session_id:
            print("Specify --session <id>")
            return
        s = session_mgr.terminate_session(session_id, reason="User terminated from CLI")
        print(f"[+] Session {session_id} terminated: {bool(s)}")


def cmd_demo(args: argparse.Namespace) -> None:
    from demo.run_demo import run_demo_suite
    run_demo_suite()


def main() -> None:
    parser = argparse.ArgumentParser(prog="leash", description="Leash: Phone-based safety layer for AI coding agents.")
    subparsers = parser.add_subparsers(dest="command")

    # leash pair
    subparsers.add_parser("pair", help="Generate pairing token and connection info for Phone Guard")

    # leash server
    subparsers.add_parser("server", help="Start the Leash daemon server")

    # leash report
    report_parser = subparsers.add_parser("report", help="Generate Markdown agent receipt for PR")
    report_parser.add_argument("--session", default=None, help="Session ID to report (defaults to latest)")

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

    # leash git <git_args...>
    git_parser = subparsers.add_parser("git", help="Run git commands safely through Leash Git Guard")
    git_parser.add_argument("git_args", nargs=argparse.REMAINDER, help="Git arguments to execute")

    # leash preview <target>
    preview_parser = subparsers.add_parser("preview", help="Preview and inspect a downloaded script before approval (F3)")
    preview_parser.add_argument("target", help="URL or file path of script to inspect")
    preview_parser.add_argument("--json", action="store_true", help="Output preview as JSON")

    # leash rewind [--session S_ID] [--snapshot REF]
    rewind_parser = subparsers.add_parser("rewind", help="Restore repository files to point-in-time snapshot (N4)")
    rewind_parser.add_argument("--session", default=None, help="Session ID to rewind")
    rewind_parser.add_argument("--snapshot", default=None, help="Specific snapshot ref or action ID")

    # leash session <list|pause|resume|terminate> [--session S_ID]
    sess_parser = subparsers.add_parser("session", help="Manage session lifecycle and safety states")
    sess_parser.add_argument("action", choices=["list", "pause", "resume", "terminate"], help="Action to perform")
    sess_parser.add_argument("--session", default=None, help="Session ID")

    # leash office-kit <sync-diff|clip-decision|export>
    ok_parser = subparsers.add_parser("office-kit", help="Office Kit clipboard and file transfer utilities")
    ok_parser.add_argument("action", choices=["sync-diff", "clip-decision", "export"], help="Action to perform")
    ok_parser.add_argument("--session", default=None, help="Session ID")

    # leash demo
    subparsers.add_parser("demo", help="Run the automated 4-scene Leash demo runner")

    # leash run [--task ...] [--scope-paths ...] -- <command>
    run_parser = subparsers.add_parser("run", help="Run agent in an isolated Leash session with task scope")
    run_parser.add_argument("--task", default=None, help="Task description for intent drift tracking (F2)")
    run_parser.add_argument("--scope-paths", nargs="*", default=None, help="Allowed path boundaries")
    run_parser.add_argument("--scope-cmds", nargs="*", default=None, help="Allowed command executables")
    run_parser.add_argument("--scope-hosts", nargs="*", default=None, help="Allowed network hosts")
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
    elif args.command == "git":
        cmd_git(args)
    elif args.command == "preview":
        cmd_preview(args)
    elif args.command == "rewind":
        cmd_rewind(args)
    elif args.command == "session":
        cmd_session(args)
    elif args.command == "office-kit":
        cmd_office_kit(args)
    elif args.command == "demo":
        cmd_demo(args)
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
