"""
daemon/receipt_builder.py - Builds Markdown PR-ready receipts from session audit logs.
"""
from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any, Dict, List


class ReceiptBuilder:
    """Generates an auditable agent receipt for inclusion in Pull Requests."""

    @staticmethod
    def generate_markdown(session_id: str, events: List[Dict[str, Any]]) -> str:
        total_actions = len(events)
        allowed = sum(1 for e in events if e.get("verdict") == "allow")
        denied = sum(1 for e in events if e.get("verdict") == "deny")
        tainted_actions = sum(1 for e in events if e.get("tainted"))

        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        md = []
        md.append(f"# Leash Agent Receipt: `{session_id}`\n")
        md.append(f"**Generated:** {now_str}\n")
        md.append("## Summary\n")
        md.append(f"- **Total Actions Evaluated:** {total_actions}")
        md.append(f"- **Allowed:** {allowed}")
        md.append(f"- **Denied / Blocked:** {denied}")
        md.append(f"- **Tainted Invocations:** {tainted_actions}\n")

        md.append("## Evaluated Actions\n")
        md.append("| Time | Kind | Command / Target | Risk | Verdict | By |")
        md.append("| --- | --- | --- | --- | --- | --- |")

        for e in events:
            ts = e.get("ts", 0)
            time_str = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%H:%M:%S")
            kind = e.get("kind", "unknown")
            cmd_or_target = (e.get("command") or e.get("target_path") or "-")
            # sanitize pipe chars for markdown table
            cmd_sanitized = cmd_or_target.replace("|", "\\|")
            if len(cmd_sanitized) > 60:
                cmd_sanitized = cmd_sanitized[:57] + "..."
            cmd_display = f"`{cmd_sanitized}`"
            severity = e.get("risk_severity", "low")
            verdict = e.get("verdict", "allow")
            decided_by = e.get("decided_by", "auto")

            md.append(f"| {time_str} | {kind} | {cmd_display} | {severity} | **{verdict}** | {decided_by} |")

        md.append("\n---\n*Verified by Leash on-device safety layer.*")
        return "\n".join(md)

    @classmethod
    def save_receipt(cls, session_id: str, events: List[Dict[str, Any]], output_path: Path) -> Path:
        content = cls.generate_markdown(session_id, events)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return output_path
