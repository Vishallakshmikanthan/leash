"""
session/runaway_guard.py - Runaway Guard (N6): detects repeated failures, edit loops, timeouts.
"""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from contracts.models import ActionKind, ActionRequest


class RunawayGuard:
    """Monitors action cadence to detect spinning loops, repeated failures, edit loops, rapid-fire actions, and session time limit expiration."""

    def __init__(
        self,
        failure_threshold: int = 3,
        loop_window_seconds: int = 15,
        loop_count_threshold: int = 5,
        rate_limit_count: int = 15,
        rate_limit_window: int = 5,
        file_edit_loop_threshold: int = 5,
        time_limit_seconds: Optional[int] = None,
        created_at: Optional[float] = None,
    ):
        self.failure_threshold = failure_threshold
        self.loop_window_seconds = loop_window_seconds
        self.loop_count_threshold = loop_count_threshold
        self.rate_limit_count = rate_limit_count
        self.rate_limit_window = rate_limit_window
        self.file_edit_loop_threshold = file_edit_loop_threshold
        self.time_limit_seconds = time_limit_seconds
        self.created_at = created_at if created_at is not None else time.time()

        self._recent_commands: Deque[Tuple[str, float]] = deque()
        self._recent_actions: Deque[Tuple[str, float]] = deque()
        self._recent_edits: Deque[Tuple[str, float]] = deque()
        self._failing_command_streak: int = 0
        self._failing_cmd_counts: Dict[str, int] = {}
        self._last_command: Optional[str] = None
        self._tripped: bool = False
        self._trip_reason: Optional[str] = None
        self._trip_type: Optional[str] = None
        self._total_actions_tracked: int = 0

    def is_tripped(self) -> bool:
        """Returns True if runaway behavior has been detected."""
        return self._tripped

    def get_trip_reason(self) -> Optional[str]:
        return self._trip_reason

    def get_trip_type(self) -> Optional[str]:
        return self._trip_type

    def trip(self, reason: str, trip_type: str = "manual") -> None:
        """Explicitly trips the runaway guard."""
        self._tripped = True
        self._trip_reason = reason
        self._trip_type = trip_type

    def reset(self) -> None:
        """Resets the runaway trip state."""
        self._tripped = False
        self._trip_reason = None
        self._trip_type = None
        self._failing_command_streak = 0
        self._failing_cmd_counts.clear()
        self._last_command = None
        self._recent_commands.clear()
        self._recent_actions.clear()
        self._recent_edits.clear()

    def check_timeout(self, now: Optional[float] = None) -> Optional[str]:
        """Checks if session has exceeded its configured time limit."""
        if self.time_limit_seconds is not None and self.time_limit_seconds > 0:
            curr = now if now is not None else time.time()
            elapsed = curr - self.created_at
            if elapsed > self.time_limit_seconds:
                reason = (
                    f"Session exceeded configured time limit of {self.time_limit_seconds}s "
                    f"(elapsed: {int(elapsed)}s)."
                )
                self.trip(reason, trip_type="time_limit_exceeded")
                return reason
        return None

    def check_action(self, request: ActionRequest) -> Optional[str]:
        """Inspects an ActionRequest prior to execution for looping, burst, or timeout behavior."""
        # 0. If already tripped from a prior event, block subsequent execution immediately
        if self._tripped:
            return self._trip_reason or "Runaway guard tripped."

        now = time.time()
        self._total_actions_tracked += 1

        # 1. Configured Session Time Limit Check
        timeout_warning = self.check_timeout(now)
        if timeout_warning:
            return timeout_warning

        # 2. Rate burst detection (cadence frequency)
        self._recent_actions.append((request.id, now))
        while self._recent_actions and (now - self._recent_actions[0][1]) > self.rate_limit_window:
            self._recent_actions.popleft()

        if len(self._recent_actions) >= self.rate_limit_count:
            reason = (
                f"Runaway cadence burst detected: {len(self._recent_actions)} actions "
                f"in {self.rate_limit_window}s."
            )
            self.trip(reason, trip_type="action_frequency")
            return reason

        # 3. Command execution loop detection
        if request.kind == ActionKind.SHELL and request.command:
            cmd_warning = self.record_command(request.command)
            if cmd_warning:
                return cmd_warning

        # 4. File edit loop detection (both FILE_EDIT kind and target_path file edits)
        target_path = request.target_path
        if not target_path and request.command:
            # Extract target from file editing shell commands if present
            cmd = request.command.strip()
            if ">" in cmd:
                parts = cmd.split(">")
                if len(parts) >= 2:
                    candidate = parts[-1].strip().split()[0].strip("\"'")
                    if candidate and not candidate.startswith("&"):
                        target_path = candidate

        if request.kind == ActionKind.FILE_EDIT or target_path:
            path = target_path or "unspecified_file"
            self._recent_edits.append((path, now))
            while self._recent_edits and (now - self._recent_edits[0][1]) > self.loop_window_seconds:
                self._recent_edits.popleft()

            # 4a. Single file edit loop threshold
            edits_to_target = sum(1 for p, _ in self._recent_edits if p == path)
            if edits_to_target >= self.file_edit_loop_threshold:
                reason = (
                    f"File edit loop detected ({edits_to_target} edits to {path} "
                    f"within {self.loop_window_seconds}s)."
                )
                self.trip(reason, trip_type="edit_loop")
                return reason

            # 4b. Multi-file edit oscillation detection (rapid alternating edits across <= 2 files)
            if len(self._recent_edits) >= max(4, self.file_edit_loop_threshold):
                unique_files = {p for p, _ in self._recent_edits}
                if len(unique_files) <= 2:
                    reason = (
                        f"File edit oscillation loop detected ({len(self._recent_edits)} edits "
                        f"alternating across {len(unique_files)} files within {self.loop_window_seconds}s)."
                    )
                    self.trip(reason, trip_type="edit_loop")
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
            self.trip(reason, trip_type="command_loop")
            return reason

        return None

    def record_result(self, cmd: str, exit_code: int) -> Optional[str]:
        clean_cmd = cmd.strip() if cmd else ""
        if exit_code != 0:
            self._failing_command_streak += 1
            if clean_cmd:
                self._failing_cmd_counts[clean_cmd] = self._failing_cmd_counts.get(clean_cmd, 0) + 1

            if self._last_command == clean_cmd and self._failing_cmd_counts.get(clean_cmd, 0) >= self.failure_threshold:
                reason = (
                    f"Agent repeated failing command {self._failing_cmd_counts[clean_cmd]} times consecutively."
                )
                self.trip(reason, trip_type="repeated_failures")
                return reason
            elif self._failing_command_streak >= self.failure_threshold:
                reason = (
                    f"Agent repeated failing command {self._failing_command_streak} times consecutively."
                )
                self.trip(reason, trip_type="repeated_failures")
                return reason

            self._last_command = clean_cmd
        else:
            self._failing_command_streak = 0
            self._failing_cmd_counts.clear()
            self._last_command = None

        return None

    def get_stats(self) -> Dict[str, Any]:
        now = time.time()
        elapsed = now - self.created_at
        remaining = max(0.0, self.time_limit_seconds - elapsed) if self.time_limit_seconds else None
        return {
            "tripped": self._tripped,
            "trip_reason": self._trip_reason,
            "trip_type": self._trip_type,
            "failing_command_streak": self._failing_command_streak,
            "total_actions_tracked": self._total_actions_tracked,
            "recent_actions_window_count": len(self._recent_actions),
            "recent_commands_window_count": len(self._recent_commands),
            "recent_edits_window_count": len(self._recent_edits),
            "time_limit_seconds": self.time_limit_seconds,
            "elapsed_seconds": round(elapsed, 2),
            "remaining_seconds": round(remaining, 2) if remaining is not None else None,
        }
