"""
reference-agent/agent.py - Scripted AI coding agent runner for automated tests and demo fallback.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import List

# Ensure leash root is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from .scenarios import (
        SCENE_1_INJECTION,
        SCENE_2_PACKAGE_GATE,
        SCENE_3_NORMAL_DEV,
        SCENE_4_REWIND_TEST,
        SCENE_5_PREVIEW_AND_SCOPE,
        ScenarioStep,
    )
except ImportError:
    from scenarios import (
        SCENE_1_INJECTION,
        SCENE_2_PACKAGE_GATE,
        SCENE_3_NORMAL_DEV,
        SCENE_4_REWIND_TEST,
        SCENE_5_PREVIEW_AND_SCOPE,
        ScenarioStep,
    )
from shim.shell_wrapper import ShellShim
from shim.tool_hooks import ToolHooks


class ReferenceAgent:
    """Simulates an autonomous coding agent executing steps through Leash guards."""

    def __init__(self, shim: ShellShim, hooks: ToolHooks):
        self.shim = shim
        self.hooks = hooks

    def execute_step(self, step: ScenarioStep) -> bool:
        print(f"\n[Agent Action] {step.name}: {step.description}")

        if step.kind == "file_read" and step.target_path:
            allowed = self.hooks.on_pre_file_read(step.target_path)
            print(f"  -> File Read Allowed: {allowed}")
            return allowed

        elif step.kind == "file_edit" and step.target_path:
            allowed = self.hooks.on_pre_file_edit(step.target_path, "modified content")
            print(f"  -> File Edit Allowed: {allowed}")
            return allowed

        elif step.kind == "tool_call" and step.tool_name:
            allowed = self.hooks.on_pre_tool_call(step.tool_name, step.tool_args or {})
            print(f"  -> Tool Call Allowed: {allowed}")
            return allowed

        elif step.kind == "shell" and step.command:
            result = self.shim.execute(step.command)
            print(f"  -> Shell Action Allowed: {result.allowed} (exit code: {result.exit_code})")
            if not result.allowed:
                print(f"  -> Blocked Reason: {result.blocked_reason}")
            return result.allowed

        return False

    def run_scenario(self, scenario: List[ScenarioStep]) -> None:
        print(f"--- Running Scenario with {len(scenario)} steps ---")
        for i, step in enumerate(scenario, 1):
            print(f"Step {i}/{len(scenario)}:")
            self.execute_step(step)
            time.sleep(0.2)
        print("--- Scenario Completed ---\n")


def main():
    import argparse
    from daemon.audit_logger import AuditLogger
    from daemon.config import DaemonConfig
    from daemon.server import LeashDaemonServer
    from session.manager import SessionManager

    parser = argparse.ArgumentParser(description="Reference Agent Runner")
    parser.add_argument("--scenario", choices=["1", "2", "3", "4", "5", "all"], default="all")
    args = parser.parse_args()

    config = DaemonConfig.load_default()
    session_mgr = SessionManager(Path("."))
    session = session_mgr.create_session()
    audit_logger = AuditLogger(config.audit_log_path)
    server = LeashDaemonServer(config, session_mgr, audit_logger)

    hooks = ToolHooks(session.session_id, server, session_mgr)
    shim = ShellShim(session_id=session.session_id, daemon_server=server)
    agent = ReferenceAgent(shim, hooks)

    scenarios_map = {
        "1": SCENE_1_INJECTION,
        "2": SCENE_2_PACKAGE_GATE,
        "3": SCENE_3_NORMAL_DEV,
        "4": SCENE_4_REWIND_TEST,
        "5": SCENE_5_PREVIEW_AND_SCOPE,
    }

    if args.scenario == "all":
        for num, sc in scenarios_map.items():
            print(f"\n===== SCENE {num} =====")
            agent.run_scenario(sc)
    else:
        agent.run_scenario(scenarios_map[args.scenario])


if __name__ == "__main__":
    main()
