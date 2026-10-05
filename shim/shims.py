"""
shim/shims.py - PATH shims generating intercepting launchers for dangerous CLI tools.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from daemon.paths import leash_home

SHIM_TARGETS = [
    "bash", "sh", "zsh", "python", "python3", "node", "npm", "npx",
    "pip", "pipx", "uv", "curl", "wget", "git", "ssh", "scp", "rsync",
    "nc", "tar"
]


def get_shims_dir() -> Path:
    p = leash_home() / "shims"
    p.mkdir(parents=True, exist_ok=True)
    return p


def install_shims(shims_dir: Optional[Path] = None) -> Path:
    """
    Installs lightweight intercepting shims into shims_dir.
    Each launcher executes `leash exec -- <binary> "$@"`.
    """
    target_dir = shims_dir or get_shims_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    is_windows = sys.platform == "win32"

    for name in SHIM_TARGETS:
        if is_windows:
            bat_path = target_dir / f"{name}.cmd"
            content = f"@echo off\r\nleash exec -- {name} %*\r\n"
            bat_path.write_text(content, encoding="utf-8")
        else:
            sh_path = target_dir / name
            content = f"#!/bin/sh\nexec leash exec -- {name} \"$@\"\n"
            sh_path.write_text(content, encoding="utf-8")
            try:
                sh_path.chmod(0o755)
            except OSError:
                pass

    return target_dir


def find_real_binary(name: str, shims_dir: Optional[Path] = None) -> Optional[str]:
    """Finds original system executable for the command, avoiding the shim directory."""
    avoid_dir = str(shims_dir or get_shims_dir()).lower()
    path_entries = os.environ.get("PATH", "").split(os.pathsep)

    for entry in path_entries:
        if not entry or entry.lower() == avoid_dir:
            continue
        candidate = Path(entry) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        if sys.platform == "win32":
            for ext in (".exe", ".cmd", ".bat"):
                cand_ext = Path(entry) / f"{name}{ext}"
                if cand_ext.is_file():
                    return str(cand_ext)
    return shutil.which(name)
