"""
daemon/paths.py - Platform-aware state directory and file paths for Leash.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path


def leash_home() -> Path:
    """
    Returns the root state directory for Leash:
      - Linux: $XDG_STATE_HOME/leash or ~/.local/state/leash
      - macOS: ~/Library/Application Support/Leash
      - Windows: %APPDATA%/Leash
    Creates directory with 0700 permissions if not already present.
    """
    custom = os.environ.get("LEASH_HOME")
    if custom:
        path = Path(custom)
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            path = Path(appdata) / "Leash"
        else:
            path = Path.home() / ".leash"
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / "Leash"
    else:
        xdg_state = os.environ.get("XDG_STATE_HOME")
        if xdg_state:
            path = Path(xdg_state) / "leash"
        else:
            path = Path.home() / ".local" / "state" / "leash"

    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        try:
            path.chmod(0o700)
        except (AttributeError, OSError, NotImplementedError):
            pass
    return path


def state_db_path() -> Path:
    return leash_home() / "state.db"


def audit_log_path() -> Path:
    return leash_home() / "audit.jsonl"


def devices_file_path() -> Path:
    return leash_home() / "devices.json"


def tls_cert_path() -> Path:
    return leash_home() / "server.crt"


def tls_key_path() -> Path:
    return leash_home() / "server.key"


def agent_socket_path() -> Path:
    return leash_home() / "agent.sock"
