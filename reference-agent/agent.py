"""
reference-agent/agent.py - Scripted AI coding agent runner for automated tests and demo fallback.
"""
from __future__ import annotations

import sys
import time
from typing import List

try:
    from .scenarios import (
        SCENE_1_INJECTION,
        SCENE_2_PACKAGE_GATE,
        SCENE_3_NORMAL_DEV,
        SCENE_4_REWIND_TEST,
        ScenarioStep,
    )
except ImportError:
    from scenarios import (
        SCENE_1_INJECTION,
        SCENE_2_PACKAGE_GATE,
        SCENE_3_NORMAL_DEV,
        SCENE_4_REWIND_TEST,
        ScenarioStep,
    )
from shim.tool_hooks import ToolHooks
from shim.shell_wrapper import ShellShim


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
            exit_code = self.shim.intercept_and_run(step.command.split())
            print(f"  -> Shell Command Exit Code: {exit_code}")
            return exit_code == 0

        return False

    def run_scenario(self, scenario: List[ScenarioStep]) -> None:
        print(f"--- Running Scenario with {len(scenario)} steps ---")
        for i, step in enumerate(scenario, 1):
            print(f"Step {i}/{len(scenario)}:")
            self.execute_step(step)
            time.sleep(0.5)
        print("--- Scenario Completed ---\n")
