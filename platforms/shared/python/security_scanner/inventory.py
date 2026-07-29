"""Installed application inventory collection (macOS / Windows).

Read-only. Produces a normalized list of installed apps that downstream EOL and
CPE/CVE lookups can consume. Network is never used here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .checks.host.common import current_platform
from .checks.host.runner import powershell, run_command

INVENTORY_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True)
class InstalledApp:
    name: str
    version: str
    source: str = ""
    vendor: str = ""

    def key(self) -> tuple[str, str]:
        return (self.name.strip().lower(), self.version.strip())


def collect_installed_apps(
    *,
    platform: str | None = None,
    timeout: float = INVENTORY_TIMEOUT_SECONDS,
) -> tuple[list[InstalledApp], list[str]]:
    resolved = platform or current_platform()
    if resolved == "macos":
        return _collect_macos(timeout)
    if resolved == "windows":
        return _collect_windows(timeout)
    return [], [f"App inventory is not supported on platform: {resolved}"]


def _collect_macos(timeout: float) -> tuple[list[InstalledApp], list[str]]:
    result = run_command(["system_profiler", "-json", "SPApplicationsDataType"], timeout=timeout)
    if not result.ok:
        return [], [f"system_profiler inventory failed: {result.error or result.stderr.strip()}"]
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return [], [f"system_profiler returned invalid JSON: {exc}"]
    raw = payload.get("SPApplicationsDataType", []) if isinstance(payload, dict) else []
    apps: list[InstalledApp] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("_name", "")).strip()
        if not name:
            continue
        apps.append(
            InstalledApp(
                name=name,
                version=str(item.get("version", "")).strip(),
                source=str(item.get("obtained_from", "")).strip(),
            )
        )
    return _dedupe(apps), []


def _collect_windows(timeout: float) -> tuple[list[InstalledApp], list[str]]:
    # Read both 64-bit and 32-bit uninstall registry hives, emit JSON lines.
    script = (
        "$paths=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object @{N='name';E={$_.DisplayName}}, @{N='version';E={$_.DisplayVersion}}, "
        "@{N='vendor';E={$_.Publisher}} | ConvertTo-Json -Compress"
    )
    result = powershell(script, timeout=timeout)
    if not result.ok:
        return [], [f"registry inventory failed: {result.error or result.stderr.strip()}"]
    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        return [], [f"registry inventory returned invalid JSON: {exc}"]
    if isinstance(payload, dict):  # ConvertTo-Json emits a bare object for a single row
        payload = [payload]
    apps: list[InstalledApp] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "")).strip()
        if not name:
            continue
        apps.append(
            InstalledApp(
                name=name,
                version=str(item.get("version", "") or "").strip(),
                source="windows-registry",
                vendor=str(item.get("vendor", "") or "").strip(),
            )
        )
    return _dedupe(apps), []


def _dedupe(apps: list[InstalledApp]) -> list[InstalledApp]:
    seen: set[tuple[str, str]] = set()
    unique: list[InstalledApp] = []
    for app in sorted(apps, key=lambda a: (a.name.lower(), a.version)):
        if app.key() in seen:
            continue
        seen.add(app.key())
        unique.append(app)
    return unique
