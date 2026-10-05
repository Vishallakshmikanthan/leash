"""
daemon/config.py - Configuration management for the Leash daemon.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class DaemonConfig:
    host: str = "0.0.0.0"
    port: int = 8765
    shared_secret: str = "leash-dev-secret-change-me"
    pairing_code_file: Path = Path(".leash/pairing.json")
    audit_log_path: Path = Path(".leash/audit.jsonl")
    receipt_output_path: Path = Path(".leash/receipt.md")
    timeout_seconds: int = 30
    fail_closed_high_risk: bool = True
    auto_allow_low_risk: bool = True
    dev_mode: bool = False
    allow_unsigned_local: bool = True
    local_approval_channel: bool = True
    use_tls: bool = False
    enable_test_routes: bool = field(default_factory=lambda: os.environ.get("LEASH_TEST_ROUTES") == "1")
    agent_plane_port: int = 8766
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None
    allow_command_patterns: List[str] = field(default_factory=lambda: [
        "pytest",
        "npm test",
        "npm run test",
        "cargo test",
        "git status",
        "git diff",
        "git log",
        "git --version",
        "python --version",
        "ls",
        "pwd",
        "ruff",
        "flake8",
        "black",
    ])

    @classmethod
    def load_default(cls, base_dir: Path = Path(".")) -> DaemonConfig:
        leash_dir = base_dir / ".leash"
        leash_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            pairing_code_file=leash_dir / "pairing.json",
            audit_log_path=leash_dir / "audit.jsonl",
            receipt_output_path=leash_dir / "receipt.md",
            shared_secret=os.environ.get("LEASH_SHARED_SECRET", "leash-dev-secret-change-me"),
        )
