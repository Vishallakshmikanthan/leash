"""
session/runaway_guard.py - Runaway Guard (N6): detects repeated failures, edit loops, timeouts.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Optional, Tuple

from contracts.models import ActionRequest


class RunawayGuard:
    """Monitors action cadence to detect spinning loops or repeated execution failures."""

    def __init__(self, failure_threshold: int = 3, loop_window_seconds: int = 15, loop_count_threshold: int = 5):
        self.failure_threshold = failure_threshold
        self.loop_window_seconds = loop_window_seconds
        self.loop_count_threshold = loop_count_threshold

        self._recent_commands: Deque[Tuple[str, float]] = deque()
        self._failing_command_streak: int = 0
        self._last_command: Optional[str] = None

    def record_command(self, cmd: str) -> Optional[str]:
        now = time.time()
        self._recent_commands.append((cmd, now))

        # Evict old entries outside window
        while self._recent_commands and (now - self._recent_commands[0][1]) > self.loop_window_seconds:
            self._recent_commands.popleft()

        # Check identical command repetitions in short window
        identical_count = sum(1 for c, _ in self._recent_commands if c == cmd)
        if identical_count >= self.loop_count_threshold:
            return f"Command execution loop detected ({identical_count} identical calls within {self.loop_window_seconds}s)."

        return None

    def record_result(self, cmd: str, exit_code: int) -> Optional[str]:
        if exit_code != 0:
            if self._last_command == cmd:
                self._failing_command_streak += 1
            else:
                self._last_command = cmd
                self._failing_command_streak = 1

            if self._failing_command_streak >= self.failure_threshold:
                return f"Agent repeated failing command {self._failing_command_streak} times consecutively."
        else:
            self._failing_command_streak = 0
            self._last_command = None

        return None
