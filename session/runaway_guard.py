"""
session/runaway_guard.py - Runaway Guard (N6): detects repeated failures, edit loops, timeouts.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from contracts.models import ActionKind, ActionRequest


class RunawayGuard:
    """Monitors action cadence to detect spinning loops, repeated failures, or rapid-fire actions."""

    def __init__(
        self,
        failure_threshold: int = 3,
        loop_window_seconds: int = 15,
        loop_count_threshold: int = 5,
        rate_limit_count: int = 15,
        rate_limit_window: int = 5,
        file_edit_loop_threshold: int = 5,
    ):
        self.failure_threshold = failure_threshold
        self.loop_window_seconds = loop_window_seconds
        self.loop_count_threshold = loop_count_threshold
        self.rate_limit_count = rate_limit_count
        self.rate_limit_window = rate_limit_window
        self.file_edit_loop_threshold = file_edit_loop_threshold

        self._recent_commands: Deque[Tuple[str, float]] = deque()
        self._recent_actions: Deque[Tuple[str, float]] = deque()
        self._recent_edits: Deque[Tuple[str, float]] = deque()
        self._failing_command_streak: int = 0
        self._last_command: Optional[str] = None
        self._tripped: bool = False
        self._trip_reason: Optional[str] = None
        self._total_actions_tracked: int = 0

    def is_tripped(self) -> bool:
        """Returns True if runaway behavior has been detected."""
        return self._tripped

    def get_trip_reason(self) -> Optional[str]:
        return self._trip_reason

    def reset(self) -> None:
        """Resets the runaway trip state."""
        self._tripped = False
        self._trip_reason = None
        self._failing_command_streak = 0
        self._last_command = None
        self._recent_commands.clear()
        self._recent_actions.clear()
        self._recent_edits.clear()

    def check_action(self, request: ActionRequest) -> Optional[str]:
        """Inspects an ActionRequest prior to execution for looping or rate burst behavior."""
        now = time.time()
        self._total_actions_tracked += 1

        # 1. Rate burst detection
        self._recent_actions.append((request.id, now))
        while self._recent_actions and (now - self._recent_actions[0][1]) > self.rate_limit_window:
            self._recent_actions.popleft()

        if len(self._recent_actions) >= self.rate_limit_count:
            reason = (
                f"Runaway cadence burst detected: {len(self._recent_actions)} actions "
                f"in {self.rate_limit_window}s."
            )
            self._tripped = True
            self._trip_reason = reason
            return reason

        # 2. Command execution loop detection
        if request.kind == ActionKind.SHELL and request.command:
            cmd_warning = self.record_command(request.command)
            if cmd_warning:
                return cmd_warning

        # 3. File edit loop detection
        if request.kind == ActionKind.FILE_EDIT and request.target_path:
            path = request.target_path
            self._recent_edits.append((path, now))
            while self._recent_edits and (now - self._recent_edits[0][1]) > self.loop_window_seconds:
                self._recent_edits.popleft()

            edits_to_target = sum(1 for p, _ in self._recent_edits if p == path)
            if edits_to_target >= self.file_edit_loop_threshold:
                reason = (
                    f"File edit loop detected ({edits_to_target} edits to {path} "
                    f"within {self.loop_window_seconds}s)."
                )
                self._tripped = True
                self._trip_reason = reason
                return reason

        return None

    def record_command(self, cmd: str) -> Optional[str]:
        now = time.time()
        clean_cmd = cmd.strip()
        self._recent_commands.append((clean_cmd, now))

        # Evict old entries outside window
        while self._recent_commands and (now - self._recent_commands[0][1]) > self.loop_window_seconds:
            self._recent_commands.popleft()

        # Check identical command repetitions in short window
        identical_count = sum(1 for c, _ in self._recent_commands if c == clean_cmd)
        if identical_count >= self.loop_count_threshold:
            reason = (
                f"Command execution loop detected ({identical_count} identical calls "
                f"within {self.loop_window_seconds}s)."
            )
            self._tripped = True
            self._trip_reason = reason
            return reason

        return None

    def record_result(self, cmd: str, exit_code: int) -> Optional[str]:
        clean_cmd = cmd.strip() if cmd else ""
        if exit_code != 0:
            if self._last_command == clean_cmd:
                self._failing_command_streak += 1
            else:
                self._last_command = clean_cmd
                self._failing_command_streak = 1

            if self._failing_command_streak >= self.failure_threshold:
                reason = (
                    f"Agent repeated failing command {self._failing_command_streak} times consecutively."
                )
                self._tripped = True
                self._trip_reason = reason
                return reason
        else:
            self._failing_command_streak = 0
            self._last_command = None

        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "tripped": self._tripped,
            "trip_reason": self._trip_reason,
            "failing_command_streak": self._failing_command_streak,
            "total_actions_tracked": self._total_actions_tracked,
            "recent_actions_window_count": len(self._recent_actions),
            "recent_commands_window_count": len(self._recent_commands),
        }
