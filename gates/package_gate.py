"""
gates/package_gate.py - Package Gate (N1): Supply chain defense, typosquatting prevention,
install script inspection, lockfile verification, and safe allow-once authorizations.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from contracts.models import ActionKind, ActionRequest, Severity
from gates.base import BaseGate, GateResult


# -----------------------------------------------------------------------------
# Distance & Similarity Algorithms
# -----------------------------------------------------------------------------

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Damerau-Levenshtein distance supporting insertions, deletions, substitutions, and transpositions."""
    d: Dict[Tuple[int, int], int] = {}
    len1 = len(s1)
    len2 = len(s2)
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,        # deletion
                d[(i, j - 1)] + 1,        # insertion
                d[(i - 1, j - 1)] + cost, # substitution
            )
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)  # transposition

    return d[(len1 - 1, len2 - 1)]


# -----------------------------------------------------------------------------
# Bundled Package Knowledge Base
# -----------------------------------------------------------------------------

class PackageKnowledge:
    """Offline knowledge base containing popular packages, known ecosystems, verified versions, and typosquats."""

    DEFAULT_POPULAR_PACKAGES: Set[str] = {
        "requests", "flask", "django", "numpy", "pandas", "pytest", "scipy", "aiohttp",
        "fastapi", "pydantic", "urllib3", "cryptography", "torch", "boto3", "jinja2",
        "celery", "sqlalchemy", "matplotlib", "transformers", "httpx", "wheel", "setuptools",
        "react", "express", "lodash", "axios", "typescript", "chalk", "webpack", "colors",
        "moment", "commander", "debug", "vue", "next", "cors", "dotenv", "jest", "mocha",
        "eslint", "prettier", "body-parser", "tokio", "serde", "syn", "anyhow", "clap",
        "tracing", "rand", "reqwest", "thiserror", "futures", "gin", "mux", "logrus", "testify"
    }

    DEFAULT_TYPOSQUATS: List[Dict[str, str]] = [
        {"input": "requsts", "target": "requests", "threat": "infostealer", "ecosystem": "pypi"},
        {"input": "reqeusts", "target": "requests", "threat": "credential_theft", "ecosystem": "pypi"},
        {"input": "falsk", "target": "flask", "threat": "reverse_shell", "ecosystem": "pypi"},
        {"input": "djagno", "target": "django", "threat": "credential_logger", "ecosystem": "pypi"},
        {"input": "lodsh", "target": "lodash", "threat": "data_exfil", "ecosystem": "npm"},
        {"input": "exppress", "target": "express", "threat": "backdoor", "ecosystem": "npm"},
        {"input": "colors-pro", "target": "colors", "threat": "preinstall_infostealer", "ecosystem": "npm"},
        {"input": "cross-env-dev", "target": "cross-env", "threat": "env_data_exfil", "ecosystem": "npm"},
        {"input": "python-dotenvs", "target": "python-dotenv", "threat": "env_credential_harvester", "ecosystem": "pypi"},
        {"input": "setup-tools", "target": "setuptools", "threat": "build_script_malware", "ecosystem": "pypi"},
        {"input": "urllib", "target": "urllib3", "threat": "network_hijack", "ecosystem": "pypi"},
    ]

    DEFAULT_KNOWN_INSTALL_SCRIPTS: Dict[str, Dict[str, Any]] = {
        "colors-pro": {"scripts": ["preinstall", "install"], "threat": "infostealer_payload"},
        "evil-pkg": {"scripts": ["postinstall"], "threat": "reverse_shell"},
        "node-sass": {"scripts": ["install"], "threat": "native_build"},
        "sqlite3": {"scripts": ["install"], "threat": "native_compilation"},
        "puppeteer": {"scripts": ["postinstall"], "threat": "binary_fetch"},
    }

    DEFAULT_KNOWN_PACKAGES: Dict[str, Dict[str, Any]] = {
        "requests": {"ecosystem": "pypi", "versions": ["2.31.0", "2.32.0", "2.32.3"], "has_install_script": False},
        "flask": {"ecosystem": "pypi", "versions": ["3.0.0", "3.0.3"], "has_install_script": False},
        "express": {"ecosystem": "npm", "versions": ["4.18.2", "4.19.2", "4.21.0"], "has_install_script": False},
        "lodash": {"ecosystem": "npm", "versions": ["4.17.21"], "has_install_script": False},
        "pytest": {"ecosystem": "pypi", "versions": ["8.3.3", "8.3.4"], "has_install_script": False},
        "tokio": {"ecosystem": "cargo", "versions": ["1.38.0", "1.40.0"], "has_install_script": False},
        "react": {"ecosystem": "npm", "versions": ["18.2.0", "18.3.1", "19.0.0"], "has_install_script": False},
    }

    SUSPICIOUS_VERSION_REGEXES = [
        re.compile(r"^0\.0\.0$"),
        re.compile(r"^0\.0\.1$"),
        re.compile(r"^0\.0\.2$"),
        re.compile(r"^.*-alpha\.0$"),
        re.compile(r"^.*-dev$"),
    ]

    LOOKALIKE_AFFIXES = {
        "pro", "official", "secure", "v2", "dev", "js", "py", "python", "core", "client", "node", "sec"
    }

    def __init__(self, corpus_path: Optional[Path | str] = None):
        self.popular_packages: Set[str] = set(self.DEFAULT_POPULAR_PACKAGES)
        self.typosquat_map: Dict[str, Dict[str, str]] = {
            t["input"].lower(): t for t in self.DEFAULT_TYPOSQUATS
        }
        self.known_install_scripts: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_KNOWN_INSTALL_SCRIPTS)
        self.known_packages: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_KNOWN_PACKAGES)
        self.ecosystems: Dict[str, Set[str]] = {}

        if corpus_path:
            self.load_corpus(Path(corpus_path))
        else:
            # Attempt to load project bundled corpus
            default_path = Path(__file__).resolve().parent.parent / "corpus" / "packages.json"
            if default_path.is_file():
                self.load_corpus(default_path)

    def load_corpus(self, path: Path) -> None:
        """Loads extended knowledge from JSON corpus."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "popular" in data and isinstance(data["popular"], list):
                self.popular_packages.update(pkg.lower() for pkg in data["popular"])

            if "ecosystems" in data and isinstance(data["ecosystems"], dict):
                for eco, pkgs in data["ecosystems"].items():
                    self.ecosystems[eco] = {p.lower() for p in pkgs}
                    self.popular_packages.update(self.ecosystems[eco])

            if "typosquats" in data and isinstance(data["typosquats"], list):
                for t in data["typosquats"]:
                    if isinstance(t, dict) and "input" in t:
                        self.typosquat_map[t["input"].lower()] = t

            if "packages_with_install_scripts" in data and isinstance(data["packages_with_install_scripts"], list):
                for p in data["packages_with_install_scripts"]:
                    if isinstance(p, dict) and "name" in p:
                        self.known_install_scripts[p["name"].lower()] = p

            if "known_packages" in data and isinstance(data["known_packages"], dict):
                for k, v in data["known_packages"].items():
                    self.known_packages[k.lower()] = v

        except Exception:
            # Fallback to in-memory defaults on corpus load error
            pass

    def is_popular(self, pkg_name: str) -> bool:
        """Checks if package is directly in the popular package catalog."""
        return pkg_name.lower() in self.popular_packages

    def is_known_package(self, pkg_name: str) -> bool:
        """Checks if package exists in configured known packages or popular packages."""
        name = pkg_name.lower()
        return name in self.known_packages or name in self.popular_packages

    def get_known_metadata(self, pkg_name: str) -> Optional[Dict[str, Any]]:
        return self.known_packages.get(pkg_name.lower())

    def find_typosquat_match(self, pkg_name: str) -> Optional[Tuple[str, str]]:
        """
        Identifies whether a package name is suspiciously close to a popular package.
        Returns (popular_target, threat_description) if detected.
        """
        clean = pkg_name.lower().strip()

        # 1. Exact typosquat catalog match
        if clean in self.typosquat_map:
            t = self.typosquat_map[clean]
            return t["target"], t.get("threat", "infostealer")

        # Skip if it is already an exact popular package
        if clean in self.popular_packages:
            return None

        # 2. Check affix-based lookalikes (e.g. colors-pro -> colors, requests-py -> requests)
        for delim in ("-", "_"):
            if delim in clean:
                parts = clean.split(delim)
                # Single prefix or suffix attached to a popular package
                if len(parts) == 2:
                    p1, p2 = parts[0], parts[1]
                    if p1 in self.popular_packages and p2 in self.LOOKALIKE_AFFIXES:
                        return p1, f"unauthorized {p2} lookalike suffix targeting '{p1}'"
                    if p2 in self.popular_packages and p1 in self.LOOKALIKE_AFFIXES:
                        return p2, f"unauthorized {p1} lookalike prefix targeting '{p2}'"

        # 3. Damerau-Levenshtein distance against popular packages
        for popular in self.popular_packages:
            dist = damerau_levenshtein_distance(clean, popular)
            if dist == 0:
                continue

            # Strict typosquat heuristic:
            # Short names (<= 4 chars): distance 1
            # Medium/Long names (>= 5 chars): distance <= 2
            if len(popular) <= 4:
                if dist == 1:
                    return popular, f"name transposition/edit distance 1 from '{popular}'"
            elif len(popular) <= 6:
                if dist == 1:
                    return popular, f"look-alike variant of '{popular}'"
            else:
                if dist <= 2:
                    return popular, f"close distance ({dist}) from popular '{popular}'"

        return None

    def has_install_scripts(self, pkg_name: str) -> Tuple[bool, Optional[str]]:
        """Checks if package is known to execute lifecycle install scripts."""
        clean = pkg_name.lower()
        if clean in self.known_install_scripts:
            info = self.known_install_scripts[clean]
            scripts = info.get("script_types") or info.get("scripts", ["install"])
            return True, f"contains lifecycle scripts: {', '.join(scripts)}"

        pkg_meta = self.known_packages.get(clean)
        if pkg_meta and pkg_meta.get("has_install_script", False):
            return True, "package metadata marks active lifecycle install script"

        return False, None

    def is_suspicious_or_very_new_version(self, pkg_name: str, version: Optional[str]) -> Tuple[bool, Optional[str]]:
        """Detects whether package version is brand new (0.0.1, 0.0.0, alpha) or unvetted."""
        if not version:
            return False, None

        clean_v = version.strip().lstrip("v").lstrip("=")
        for pattern in self.SUSPICIOUS_VERSION_REGEXES:
            if pattern.search(clean_v):
                return True, f"suspicious initial/unvetted version '{version}'"

        # If known package and version is not in known verified versions
        meta = self.known_packages.get(pkg_name.lower())
        if meta and "versions" in meta and meta["versions"]:
            if clean_v not in meta["versions"]:
                # Version mismatch against known stable versions
                return True, f"unverified version '{version}' not present in known stable releases ({meta['versions'][-1]})"

        return False, None


# -----------------------------------------------------------------------------
# Local Lockfile Inspector
# -----------------------------------------------------------------------------

@dataclass
class LockedPackageInfo:
    name: str
    version: str
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    lockfile_source: str = ""


class LockfileInspector:
    """Parses local lockfiles to verify locked dependencies and detect untrusted registry tampering."""

    LOCKFILE_NAMES = (
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "requirements.txt",
    )

    INSECURE_REGISTRIES = (
        "http://",
        "ngrok.io",
        "pastebin.com",
        "raw.githubusercontent.com",
    )

    def find_lockfiles(self, base_path: Path | str) -> List[Path]:
        """Locates all recognized lockfiles in given directory or parent hierarchy."""
        found: List[Path] = []
        curr = Path(base_path).resolve()

        # Check current dir and parents up to 3 levels
        checked = 0
        while curr and checked < 4:
            for name in self.LOCKFILE_NAMES:
                candidate = curr / name
                if candidate.is_file() and candidate not in found:
                    found.append(candidate)
            if curr.parent == curr:
                break
            curr = curr.parent
            checked += 1

        return found

    def inspect_workspace(self, base_path: Path | str) -> Dict[str, LockedPackageInfo]:
        """Parses all packages locked within workspace."""
        locked: Dict[str, LockedPackageInfo] = {}
        lockfiles = self.find_lockfiles(base_path)

        for lpath in lockfiles:
            try:
                name = lpath.name.lower()
                if name == "package-lock.json":
                    self._parse_package_lock(lpath, locked)
                elif name == "yarn.lock":
                    self._parse_yarn_lock(lpath, locked)
                elif name == "poetry.lock":
                    self._parse_poetry_lock(lpath, locked)
                elif name == "pipfile.lock":
                    self._parse_pipfile_lock(lpath, locked)
                elif name == "cargo.lock":
                    self._parse_cargo_lock(lpath, locked)
                elif name == "requirements.txt":
                    self._parse_requirements_txt(lpath, locked)
            except Exception:
                continue

        return locked

    def _parse_package_lock(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # v2 / v3 format with packages
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if not isinstance(info, dict):
                    continue
                pkg_name = pkg_path.split("node_modules/")[-1].strip().lower()
                if pkg_name and pkg_name != "":
                    locked[pkg_name] = LockedPackageInfo(
                        name=pkg_name,
                        version=str(info.get("version", "")),
                        resolved=info.get("resolved"),
                        integrity=info.get("integrity"),
                        lockfile_source=str(path.name),
                    )

        # v1 format with dependencies
        deps = data.get("dependencies", {})
        if isinstance(deps, dict):
            for pkg_name, info in deps.items():
                if isinstance(info, dict) and pkg_name.lower() not in locked:
                    locked[pkg_name.lower()] = LockedPackageInfo(
                        name=pkg_name.lower(),
                        version=str(info.get("version", "")),
                        resolved=info.get("resolved"),
                        integrity=info.get("integrity"),
                        lockfile_source=str(path.name),
                    )

    def _parse_yarn_lock(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        content = path.read_text(encoding="utf-8", errors="replace")
        current_pkg = ""
        current_version = ""
        current_resolved = ""
        current_integrity = ""

        for line in content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if line_str.endswith(":") and not line_str.startswith("version"):
                # Header: e.g. "lodash@^4.17.21", lodash@>=4.0.0:
                header = line_str[:-1].split(",")[0].strip().strip('"').strip("'")
                # Strip version constraint
                if "@" in header:
                    current_pkg = header.split("@")[0].lower()
                else:
                    current_pkg = header.lower()
            elif line_str.startswith("version "):
                current_version = line_str.replace("version ", "").strip().strip('"')
            elif line_str.startswith("resolved "):
                current_resolved = line_str.replace("resolved ", "").strip().strip('"')
            elif line_str.startswith("integrity "):
                current_integrity = line_str.replace("integrity ", "").strip().strip('"')

            if current_pkg and current_version:
                locked[current_pkg] = LockedPackageInfo(
                    name=current_pkg,
                    version=current_version,
                    resolved=current_resolved or None,
                    integrity=current_integrity or None,
                    lockfile_source=str(path.name),
                )

    def _parse_poetry_lock(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        content = path.read_text(encoding="utf-8", errors="replace")
        curr_name = ""
        curr_ver = ""
        for line in content.splitlines():
            line_str = line.strip()
            if line_str == "[[package]]":
                if curr_name and curr_ver:
                    locked[curr_name] = LockedPackageInfo(
                        name=curr_name, version=curr_ver, lockfile_source=str(path.name)
                    )
                curr_name = ""
                curr_ver = ""
            elif line_str.startswith("name = "):
                curr_name = line_str.split("=")[-1].strip().strip('"').lower()
            elif line_str.startswith("version = "):
                curr_ver = line_str.split("=")[-1].strip().strip('"')

        if curr_name and curr_ver:
            locked[curr_name] = LockedPackageInfo(
                name=curr_name, version=curr_ver, lockfile_source=str(path.name)
            )

    def _parse_pipfile_lock(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for section in ("default", "develop"):
            sec_dict = data.get(section, {})
            if isinstance(sec_dict, dict):
                for pkg_name, info in sec_dict.items():
                    if isinstance(info, dict):
                        ver = str(info.get("version", "")).lstrip("=")
                        hashes = info.get("hashes", [])
                        locked[pkg_name.lower()] = LockedPackageInfo(
                            name=pkg_name.lower(),
                            version=ver,
                            integrity=hashes[0] if hashes else None,
                            lockfile_source=str(path.name),
                        )

    def _parse_cargo_lock(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        content = path.read_text(encoding="utf-8", errors="replace")
        curr_name = ""
        curr_ver = ""
        curr_chk = ""
        for line in content.splitlines():
            line_str = line.strip()
            if line_str == "[[package]]":
                if curr_name and curr_ver:
                    locked[curr_name] = LockedPackageInfo(
                        name=curr_name, version=curr_ver, integrity=curr_chk or None, lockfile_source=str(path.name)
                    )
                curr_name = ""
                curr_ver = ""
                curr_chk = ""
            elif line_str.startswith("name = "):
                curr_name = line_str.split("=")[-1].strip().strip('"').lower()
            elif line_str.startswith("version = "):
                curr_ver = line_str.split("=")[-1].strip().strip('"')
            elif line_str.startswith("checksum = "):
                curr_chk = line_str.split("=")[-1].strip().strip('"')

        if curr_name and curr_ver:
            locked[curr_name] = LockedPackageInfo(
                name=curr_name, version=curr_ver, integrity=curr_chk or None, lockfile_source=str(path.name)
            )

    def _parse_requirements_txt(self, path: Path, locked: Dict[str, LockedPackageInfo]) -> None:
        content = path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue
            if "==" in line_str:
                parts = line_str.split("==")
                pkg = parts[0].strip().lower()
                ver = parts[1].split()[0].split(";")[0].strip()
                locked[pkg] = LockedPackageInfo(name=pkg, version=ver, lockfile_source=str(path.name))

    def detect_lockfile_tampering(self, lockfile_path: Path | str) -> List[str]:
        """Scans lockfile for unencrypted HTTP download locations or suspicious registry domains."""
        findings: List[str] = []
        path = Path(lockfile_path)
        if not path.is_file():
            return findings

        content = path.read_text(encoding="utf-8", errors="replace")
        for bad in self.INSECURE_REGISTRIES:
            if bad in content:
                findings.append(f"Insecure registry URL found ({bad}) in lockfile {path.name}")

        return findings


# -----------------------------------------------------------------------------
# Allow-Once Manager (Safe One-Time Authorizations)
# -----------------------------------------------------------------------------

@dataclass
class AllowOnceGrant:
    grant_id: str
    package_name: str
    version: Optional[str]
    session_id: Optional[str]
    created_at: float
    decided_by: str
    note: Optional[str] = None
    consumed: bool = False
    consumed_at: Optional[float] = None


class AllowOnceManager:
    """Thread-safe store managing safe, single-use package approvals."""

    def __init__(self):
        self._lock = threading.Lock()
        self._grants: Dict[str, AllowOnceGrant] = {}

    def allow_once(
        self,
        package_name: str,
        version: Optional[str] = None,
        session_id: Optional[str] = None,
        decider: str = "biometric",
        note: Optional[str] = None,
    ) -> AllowOnceGrant:
        """Issues an allow-once grant for a specific package and session."""
        grant_id = f"grant_pkg_{uuid.uuid4().hex[:8]}"
        clean_pkg = package_name.lower().strip()
        grant = AllowOnceGrant(
            grant_id=grant_id,
            package_name=clean_pkg,
            version=version,
            session_id=session_id,
            created_at=time.time(),
            decided_by=decider,
            note=note or f"Allow-once granted for package '{clean_pkg}'",
            consumed=False,
        )
        with self._lock:
            self._grants[grant_id] = grant
        return grant

    def check_and_consume(
        self,
        package_name: str,
        version: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[AllowOnceGrant]:
        """Checks if a matching unused allow-once grant exists; if so, consumes it immediately."""
        clean_pkg = package_name.lower().strip()
        with self._lock:
            for grant in self._grants.values():
                if grant.consumed:
                    continue
                if grant.package_name != clean_pkg:
                    continue
                # Session matching: if grant has session_id, must match
                if grant.session_id and session_id and grant.session_id != session_id:
                    continue
                # Version matching: if grant specifies version, must match
                if grant.version and version and grant.version != version:
                    continue

                # Valid match found: consume once
                grant.consumed = True
                grant.consumed_at = time.time()
                return grant

        return None

    def is_allowed_once(
        self,
        package_name: str,
        version: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """Inspects if an unconsumed allow-once grant exists without consuming it."""
        clean_pkg = package_name.lower().strip()
        with self._lock:
            for grant in self._grants.values():
                if not grant.consumed and grant.package_name == clean_pkg:
                    if grant.session_id and session_id and grant.session_id != session_id:
                        continue
                    if grant.version and version and grant.version != version:
                        continue
                    return True
        return False

    def list_grants(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "grant_id": g.grant_id,
                    "package_name": g.package_name,
                    "version": g.version,
                    "session_id": g.session_id,
                    "created_at": g.created_at,
                    "decided_by": g.decided_by,
                    "note": g.note,
                    "consumed": g.consumed,
                    "consumed_at": g.consumed_at,
                }
                for g in self._grants.values()
            ]

    def revoke_grant(self, grant_id_or_pkg: str) -> bool:
        with self._lock:
            if grant_id_or_pkg in self._grants:
                del self._grants[grant_id_or_pkg]
                return True
            to_del = [gid for gid, g in self._grants.items() if g.package_name == grant_id_or_pkg.lower()]
            for gid in to_del:
                del self._grants[gid]
            return len(to_del) > 0

    def clear(self) -> None:
        with self._lock:
            self._grants.clear()


# -----------------------------------------------------------------------------
# Package Action Parser
# -----------------------------------------------------------------------------

@dataclass
class ParsedPackageSpec:
    raw: str
    name: str
    version: Optional[str] = None
    flags: List[str] = field(default_factory=list)


@dataclass
class ParsedPackageAction:
    is_package_action: bool
    manager: Optional[str] = None
    ecosystem: Optional[str] = None
    packages: List[ParsedPackageSpec] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    has_ignore_scripts: bool = False
    is_lockfile_edit: bool = False
    target_path: Optional[str] = None


class PackageActionParser:
    """Parses shell commands and file edit actions into structured package operations."""

    PACKAGE_MANAGERS: Dict[str, Tuple[str, List[str]]] = {
        "npm": ("npm", ["install", "i", "add"]),
        "yarn": ("npm", ["add"]),
        "pnpm": ("npm", ["add", "install"]),
        "bun": ("npm", ["add", "install"]),
        "pip": ("pypi", ["install"]),
        "pip3": ("pypi", ["install"]),
        "poetry": ("pypi", ["add"]),
        "pipenv": ("pypi", ["install"]),
        "uv": ("pypi", ["add", "pip"]),
        "cargo": ("cargo", ["add", "install"]),
        "go": ("go", ["get", "install"]),
        "gem": ("gem", ["install"]),
        "composer": ("composer", ["require"]),
    }

    LOCKFILE_FILENAMES = {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "cargo.lock",
    }

    MANIFEST_FILENAMES = {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "pipfile",
        "cargo.toml",
    }

    @classmethod
    def parse_action(cls, request: ActionRequest) -> ParsedPackageAction:
        """Extracts package install specifications from an ActionRequest."""
        # 1. Check direct ActionKind.INSTALL
        if request.kind == ActionKind.INSTALL:
            pkg_name = request.command or request.tool_name or ""
            target = request.target_path or ""
            return ParsedPackageAction(
                is_package_action=True,
                manager="install_tool",
                ecosystem="generic",
                packages=[ParsedPackageSpec(raw=pkg_name, name=pkg_name.lower().strip())],
                target_path=target,
            )

        # 2. Check file edit targeting manifest or lockfile
        if request.kind == ActionKind.FILE_EDIT and request.target_path:
            p = Path(request.target_path).name.lower()
            if p in cls.LOCKFILE_FILENAMES:
                return ParsedPackageAction(
                    is_package_action=True,
                    is_lockfile_edit=True,
                    target_path=request.target_path,
                )
            if p in cls.MANIFEST_FILENAMES:
                return ParsedPackageAction(
                    is_package_action=True,
                    is_lockfile_edit=False,
                    target_path=request.target_path,
                )

        # 3. Shell command inspection
        cmd = request.command or ""
        if not cmd:
            return ParsedPackageAction(is_package_action=False)

        tokens = cmd.strip().split()
        if not tokens:
            return ParsedPackageAction(is_package_action=False)

        # Normalize python -m pip install
        if len(tokens) >= 4 and tokens[0].lower() in ("python", "python3", "py") and tokens[1].lower() == "-m" and tokens[2].lower() == "pip":
            manager = "pip"
            subcommand = tokens[3].lower()
            arg_tokens = tokens[4:]
        else:
            manager = tokens[0].lower()
            subcommand = tokens[1].lower() if len(tokens) > 1 else ""
            arg_tokens = tokens[2:] if len(tokens) > 2 else []

        if manager in cls.PACKAGE_MANAGERS:
            ecosystem, allowed_subcmds = cls.PACKAGE_MANAGERS[manager]
            if subcommand in allowed_subcmds:
                parsed_pkgs: List[ParsedPackageSpec] = []
                flags: List[str] = []
                has_ignore_scripts = False

                for tok in arg_tokens:
                    if tok.startswith("-"):
                        flags.append(tok)
                        if tok in ("--ignore-scripts", "--ignore-script"):
                            has_ignore_scripts = True
                        continue

                    # Skip options like requirements file pointers or flags with values
                    if tok.endswith(".txt") or tok.endswith(".whl") or tok.endswith(".tar.gz"):
                        continue

                    # Extract name and version
                    clean_tok = tok
                    version = None
                    if "==" in clean_tok:
                        parts = clean_tok.split("==")
                        pkg_name = parts[0].strip()
                        version = parts[1].strip()
                    elif ">=" in clean_tok:
                        parts = clean_tok.split(">=")
                        pkg_name = parts[0].strip()
                        version = parts[1].strip()
                    elif "@" in clean_tok and not clean_tok.startswith("@"):
                        parts = clean_tok.split("@")
                        pkg_name = parts[0].strip()
                        version = parts[1].strip()
                    elif clean_tok.startswith("@") and clean_tok.count("@") > 1:
                        # Scoped package e.g. @scope/pkg@1.0.0
                        idx = clean_tok.rfind("@")
                        pkg_name = clean_tok[:idx].strip()
                        version = clean_tok[idx + 1:].strip()
                    else:
                        pkg_name = clean_tok.strip()

                    if pkg_name:
                        parsed_pkgs.append(
                            ParsedPackageSpec(raw=clean_tok, name=pkg_name.lower(), version=version)
                        )

                return ParsedPackageAction(
                    is_package_action=True,
                    manager=manager,
                    ecosystem=ecosystem,
                    packages=parsed_pkgs,
                    flags=flags,
                    has_ignore_scripts=has_ignore_scripts,
                )

        return ParsedPackageAction(is_package_action=False)


# -----------------------------------------------------------------------------
# Package Gate
# -----------------------------------------------------------------------------

class PackageGate(BaseGate):
    """
    Package Gate (N1): Supply chain interceptor verifying package authenticity,
    catching typosquats, blocking unreviewed install scripts, checking lockfiles,
    and supporting safe allow-once approvals in offline and online modes.
    """

    def __init__(
        self,
        knowledge: Optional[PackageKnowledge] = None,
        lockfile_inspector: Optional[LockfileInspector] = None,
        allow_once_mgr: Optional[AllowOnceManager] = None,
        offline_mode: bool = True,
    ):
        self.knowledge = knowledge or PackageKnowledge()
        self.lockfile_inspector = lockfile_inspector or LockfileInspector()
        self.allow_once_mgr = allow_once_mgr or AllowOnceManager()
        self.offline_mode = offline_mode

    @property
    def name(self) -> str:
        return "PackageGate"

    def allow_once(
        self,
        package_name: str,
        version: Optional[str] = None,
        session_id: Optional[str] = None,
        decider: str = "biometric",
        note: Optional[str] = None,
    ) -> AllowOnceGrant:
        """Grants a safe allow-once exception for a package installation."""
        return self.allow_once_mgr.allow_once(
            package_name=package_name,
            version=version,
            session_id=session_id,
            decider=decider,
            note=note,
        )

    def is_allowed_once(
        self,
        package_name: str,
        version: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> bool:
        """Inspects if an active allow-once authorization is available."""
        return self.allow_once_mgr.is_allowed_once(package_name, version, session_id)

    def evaluate(self, request: ActionRequest) -> Optional[GateResult]:
        """Evaluates an ActionRequest for supply chain and package installation risks."""
        parsed_action = PackageActionParser.parse_action(request)
        if not parsed_action.is_package_action:
            return None

        workspace_root = Path(request.cwd or ".").resolve()

        # 1. Evaluate Direct Lockfile Edit Risks
        if parsed_action.is_lockfile_edit:
            tampering = self.lockfile_inspector.detect_lockfile_tampering(
                workspace_root / (parsed_action.target_path or "")
            )
            reasons = [
                f"Direct modification to protected dependency lockfile: {parsed_action.target_path}",
                "Lockfile edits can introduce unpinned backdoored dependencies and alter checksum verification.",
            ]
            if tampering:
                reasons.extend(tampering)

            return GateResult(
                triggered=True,
                rule_id="R-PKG-LOCKFILE",
                category="package-install",
                severity=Severity.HIGH,
                summary=f"Suspicious dependency lockfile modification: {parsed_action.target_path}",
                why="Warning reasons:\n" + "\n".join(f"• {r}" for r in reasons),
                safer_alternative="Generate lockfiles deterministically via package managers with integrity verification.",
                reasons=reasons,
                details={"target_path": parsed_action.target_path, "tampering": tampering},
            )

        # 2. Inspect workspace lockfiles for existing pinned packages
        locked_packages = self.lockfile_inspector.inspect_workspace(workspace_root)

        # 3. Evaluate each target package
        for pkg_spec in parsed_action.packages:
            pkg_name = pkg_spec.name
            version = pkg_spec.version

            # Check safe allow-once authorization
            consumed_grant = self.allow_once_mgr.check_and_consume(
                package_name=pkg_name,
                version=version,
                session_id=request.session,
            )
            if consumed_grant:
                # Safe allow-once authorized! Pass through without warning
                return None

            reasons: List[str] = []
            primary_threat = ""
            rule_id = "R-PKG-NEW-INSTALL"
            severity = Severity.MEDIUM
            is_typosquat = False
            has_script = False
            is_unknown = False
            is_new_ver = False

            # Check 1: Typosquatting / Look-alike package name
            typosquat_info = self.knowledge.find_typosquat_match(pkg_name)
            if typosquat_info:
                target_pop, threat_desc = typosquat_info
                is_typosquat = True
                primary_threat = threat_desc
                rule_id = "R-PKG-TYPOSQUAT"
                severity = Severity.HIGH
                reasons.append(
                    f"Package '{pkg_name}' is suspiciously close to popular package '{target_pop}' ({threat_desc})."
                )

            # Check 2: Lifecycle Install Scripts (preinstall, postinstall, install)
            has_install_script, script_desc = self.knowledge.has_install_scripts(pkg_name)
            if has_install_script and not parsed_action.has_ignore_scripts:
                has_script = True
                if severity != Severity.CRITICAL:
                    severity = Severity.HIGH
                if not is_typosquat:
                    rule_id = "R-PKG-INSTALL-SCRIPT"
                reasons.append(
                    f"Package '{pkg_name}' contains lifecycle install scripts ({script_desc}) executing host commands."
                )

            # Check 3: Check against local lockfile (offline ground truth)
            in_lockfile = pkg_name in locked_packages
            if in_lockfile:
                locked_info = locked_packages[pkg_name]
                if version and locked_info.version and version != locked_info.version:
                    reasons.append(
                        f"Requested version '{version}' mismatches locked version '{locked_info.version}' in {locked_info.lockfile_source}."
                    )
            else:
                # Check 4: Package does not exist in configured package knowledge & not in lockfile
                if not self.knowledge.is_known_package(pkg_name):
                    is_unknown = True
                    if not is_typosquat and not has_script:
                        rule_id = "R-PKG-UNKNOWN"
                    reasons.append(
                        f"Package '{pkg_name}' does not exist in configured package knowledge and is not verified in local lockfile."
                    )

            # Check 5: Very new or suspicious version
            is_suspicious_ver, ver_desc = self.knowledge.is_suspicious_or_very_new_version(pkg_name, version)
            if is_suspicious_ver:
                is_new_ver = True
                if not is_typosquat and not has_script and not is_unknown:
                    rule_id = "R-PKG-NEW-VERSION"
                reasons.append(
                    f"Package version '{version}' is very new or unvetted: {ver_desc}."
                )

            # If clean popular package or already safely locked with no other warnings, allow
            if not reasons:
                if self.knowledge.is_popular(pkg_name) or in_lockfile:
                    continue

                # Standard new package installation with no specific threat
                rule_id = "R-PKG-NEW-INSTALL"
                reasons.append(
                    f"Installing external package '{pkg_name}' introduces third-party code and lifecycle dependencies."
                )

            # Determine composite severity
            if is_typosquat or has_script or (is_unknown and is_new_ver):
                severity = Severity.HIGH
            elif severity == Severity.MEDIUM and request.taint.tainted:
                severity = Severity.HIGH

            # Build clear plain-English summary & why
            if is_typosquat:
                target_pop = typosquat_info[0] if typosquat_info else "popular package"
                summary = f"Package Gate warning: '{pkg_name}' is suspiciously close to '{target_pop}'."
                alt = f"Verify if you intended to install '{target_pop}' instead, or use Guard allow-once with fingerprint."
            elif has_script:
                summary = f"Package Gate warning: '{pkg_name}' executes lifecycle install scripts."
                alt = f"Inspect scripts before installation or use --ignore-scripts flag."
            elif is_unknown:
                summary = f"Package Gate warning: '{pkg_name}' does not exist in package knowledge."
                alt = f"Verify package author, pin exact version in lockfile, or grant allow-once with fingerprint."
            elif is_new_ver:
                summary = f"Package Gate warning: '{pkg_name}' version '{version}' is very new."
                alt = f"Install a verified older stable release or inspect package commit history."
            else:
                summary = f"Package Gate warning: installing external package '{pkg_name}'."
                alt = "Pin dependencies in lockfile with checksum verification."

            why_text = (
                f"Warning reasons for '{pkg_name}':\n"
                + "\n".join(f"• {r}" for r in reasons)
            )

            details_dict = {
                "package": pkg_name,
                "version": version,
                "manager": parsed_action.manager,
                "ecosystem": parsed_action.ecosystem,
                "reasons": reasons,
                "is_typosquat": is_typosquat,
                "has_install_script": has_script,
                "is_unknown": is_unknown,
                "is_new_version": is_new_ver,
                "in_lockfile": in_lockfile,
                "offline_mode": self.offline_mode,
                "allow_once_available": True,
            }

            return GateResult(
                triggered=True,
                rule_id=rule_id,
                category="package-install",
                severity=severity,
                summary=summary,
                why=why_text,
                safer_alternative=alt,
                reasons=reasons,
                details=details_dict,
            )

        # Fallback for generic package commands without individual package args (e.g. npm install without args)
        return None
