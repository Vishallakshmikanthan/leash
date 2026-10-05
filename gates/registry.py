"""
gates/registry.py - Live package registry client with caching and offline fallback for Package Gate (M6.1).

Queries npm (https://registry.npmjs.org/<name>) and PyPI (https://pypi.org/pypi/<name>/json).
Caches responses on disk for 24 hours. Timeout 3 seconds.
Falls back to offline mode on any network error.
"""
from __future__ import annotations

import datetime
import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from daemon.paths import leash_home

logger = logging.getLogger("leash.gates.registry")


@dataclass
class RegistryPackageInfo:
    ecosystem: str
    name: str
    exists: bool = False
    latest_version: Optional[str] = None
    first_publish_date: Optional[str] = None
    first_published_days_ago: Optional[float] = None
    is_recent: bool = False  # first publish under 7 days ago
    has_install_scripts: bool = False
    install_scripts: List[str] = field(default_factory=list)
    maintainers: List[str] = field(default_factory=list)
    offline: bool = False
    cached: bool = False
    error: Optional[str] = None


class RegistryClient:
    """Client for querying npm and PyPI package registries with caching and 3s timeout."""

    CACHE_TTL_SECONDS = 24 * 3600  # 24 hours
    DEFAULT_TIMEOUT_SECONDS = 3.0

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        force_offline: bool = False,
    ):
        self.cache_dir = cache_dir or (leash_home() / "cache" / "registry")
        self.timeout = timeout
        self.force_offline = force_offline
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _get_cache_path(self, ecosystem: str, package_name: str) -> Path:
        safe_name = package_name.replace("/", "__").replace("@", "_")
        return self.cache_dir / ecosystem / f"{safe_name}.json"

    def _read_cache(self, ecosystem: str, package_name: str) -> Optional[Dict[str, Any]]:
        path = self._get_cache_path(ecosystem, package_name)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                entry = json.load(f)
            cached_at = entry.get("_cached_at", 0)
            if time.time() - cached_at < self.CACHE_TTL_SECONDS:
                return entry.get("data")
        except Exception:
            pass
        return None

    def _write_cache(self, ecosystem: str, package_name: str, data: Dict[str, Any]) -> None:
        path = self._get_cache_path(ecosystem, package_name)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "_cached_at": time.time(),
                "data": data,
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entry, f)
        except Exception as ex:
            logger.debug(f"Failed to cache registry response: {ex}")

    def query_pypi(self, package_name: str) -> RegistryPackageInfo:
        """Queries PyPI registry (https://pypi.org/pypi/<name>/json) for upload history and metadata."""
        clean_name = package_name.strip().lower()
        if self.force_offline:
            return RegistryPackageInfo(ecosystem="pypi", name=clean_name, offline=True, error="Offline mode")

        # 1. Check cache
        cached_data = self._read_cache("pypi", clean_name)
        if cached_data is not None:
            return self._parse_pypi_data(clean_name, cached_data, cached=True)

        url = f"https://pypi.org/pypi/{clean_name}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "Leash-Package-Gate/1.0"})

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._write_cache("pypi", clean_name, data)
                return self._parse_pypi_data(clean_name, data, cached=False)
        except urllib.error.HTTPError as he:
            if he.code == 404:
                return RegistryPackageInfo(ecosystem="pypi", name=clean_name, exists=False)
            logger.warning(f"PyPI registry query failed with HTTP {he.code}: {he}")
            return RegistryPackageInfo(ecosystem="pypi", name=clean_name, offline=True, error=str(he))
        except Exception as ex:
            logger.warning(f"PyPI registry network error ({clean_name}): {ex}")
            return RegistryPackageInfo(ecosystem="pypi", name=clean_name, offline=True, error=str(ex))

    def _parse_pypi_data(self, name: str, data: Dict[str, Any], cached: bool = False) -> RegistryPackageInfo:
        info = data.get("info", {})
        releases = data.get("releases", {})
        latest_ver = info.get("version")

        # Find earliest upload time across all releases
        first_dt: Optional[datetime.datetime] = None
        for ver, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601") or f.get("upload_time")
                if upload_time:
                    try:
                        # Normalize ISO string
                        dt = datetime.datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                        if first_dt is None or dt < first_dt:
                            first_dt = dt
                    except Exception:
                        pass

        days_ago = None
        is_recent = False
        if first_dt:
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=datetime.timezone.utc)
            delta = datetime.datetime.now(datetime.timezone.utc) - first_dt
            days_ago = delta.total_seconds() / 86400.0
            is_recent = days_ago < 7.0

        maintainers = []
        author = info.get("author") or info.get("maintainer")
        if author:
            maintainers.append(author)

        return RegistryPackageInfo(
            ecosystem="pypi",
            name=name,
            exists=True,
            latest_version=latest_ver,
            first_publish_date=first_dt.isoformat() if first_dt else None,
            first_published_days_ago=days_ago,
            is_recent=is_recent,
            has_install_scripts=False,  # PyPI setup.py / pyproject build
            maintainers=maintainers,
            cached=cached,
            offline=False,
        )

    def query_npm(self, package_name: str) -> RegistryPackageInfo:
        """Queries npm registry (https://registry.npmjs.org/<name>) for manifest, dates, and scripts."""
        clean_name = package_name.strip()
        if self.force_offline:
            return RegistryPackageInfo(ecosystem="npm", name=clean_name, offline=True, error="Offline mode")

        # 1. Check cache
        cached_data = self._read_cache("npm", clean_name)
        if cached_data is not None:
            return self._parse_npm_data(clean_name, cached_data, cached=True)

        # Handle scoped packages @scope/pkg
        encoded_name = clean_name.replace("/", "%2F") if clean_name.startswith("@") else clean_name
        url = f"https://registry.npmjs.org/{encoded_name}"
        req = urllib.request.Request(url, headers={"User-Agent": "Leash-Package-Gate/1.0"})

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._write_cache("npm", clean_name, data)
                return self._parse_npm_data(clean_name, data, cached=False)
        except urllib.error.HTTPError as he:
            if he.code == 404:
                return RegistryPackageInfo(ecosystem="npm", name=clean_name, exists=False)
            logger.warning(f"npm registry query failed with HTTP {he.code}: {he}")
            return RegistryPackageInfo(ecosystem="npm", name=clean_name, offline=True, error=str(he))
        except Exception as ex:
            logger.warning(f"npm registry network error ({clean_name}): {ex}")
            return RegistryPackageInfo(ecosystem="npm", name=clean_name, offline=True, error=str(ex))

    def _parse_npm_data(self, name: str, data: Dict[str, Any], cached: bool = False) -> RegistryPackageInfo:
        time_map = data.get("time", {})
        created_str = time_map.get("created")
        first_dt: Optional[datetime.datetime] = None
        if created_str:
            try:
                first_dt = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except Exception:
                pass

        days_ago = None
        is_recent = False
        if first_dt:
            if first_dt.tzinfo is None:
                first_dt = first_dt.replace(tzinfo=datetime.timezone.utc)
            delta = datetime.datetime.now(datetime.timezone.utc) - first_dt
            days_ago = delta.total_seconds() / 86400.0
            is_recent = days_ago < 7.0

        dist_tags = data.get("dist-tags", {})
        latest_ver = dist_tags.get("latest")

        # Inspect latest version for lifecycle install scripts
        versions = data.get("versions", {})
        latest_manifest = versions.get(latest_ver, {}) if latest_ver else {}
        scripts = latest_manifest.get("scripts", {})
        dangerous_lifecycle = [k for k in ("preinstall", "install", "postinstall") if k in scripts]

        maintainers = []
        for m in data.get("maintainers", []):
            if isinstance(m, dict) and "name" in m:
                maintainers.append(m["name"])
            elif isinstance(m, str):
                maintainers.append(m)

        return RegistryPackageInfo(
            ecosystem="npm",
            name=name,
            exists=True,
            latest_version=latest_ver,
            first_publish_date=first_dt.isoformat() if first_dt else None,
            first_published_days_ago=days_ago,
            is_recent=is_recent,
            has_install_scripts=len(dangerous_lifecycle) > 0,
            install_scripts=dangerous_lifecycle,
            maintainers=maintainers,
            cached=cached,
            offline=False,
        )

    def query(self, package_name: str, ecosystem: str = "auto") -> RegistryPackageInfo:
        """Unified query dispatcher for npm or PyPI."""
        eco = ecosystem.lower()
        if eco == "npm" or (eco == "auto" and package_name.startswith("@")):
            return self.query_npm(package_name)
        return self.query_pypi(package_name)
