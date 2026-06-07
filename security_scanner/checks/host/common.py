"""Shared helpers for host/endpoint security checks."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from ...models import Finding


# A host check takes no file argument; it queries the machine and returns findings.
HostCheck = Callable[[], list[Finding]]


def current_platform() -> str:
    """Normalize ``sys.platform`` to: ``macos``, ``windows``, ``linux``, or ``other``."""

    value = sys.platform
    if value == "darwin":
        return "macos"
    if value.startswith("win"):
        return "windows"
    if value.startswith("linux"):
        return "linux"
    return "other"


def os_release() -> tuple[str, str, str]:
    """Return ``(endoflife_product, full_version, cycle)`` for the host OS.

    ``cycle`` is the endoflife.date release identifier (e.g. macOS major "14",
    Windows "11"). Returns empty strings when it cannot be determined.
    """

    from .runner import powershell, run_command

    platform = current_platform()
    if platform == "macos":
        result = run_command(["sw_vers", "-productVersion"])
        if not result.ok or not result.text:
            return ("macos", "", "")
        version = result.text.strip()
        cycle = version.split(".", 1)[0]
        return ("macos", version, cycle)
    if platform == "windows":
        result = powershell("[System.Environment]::OSVersion.Version.Build")
        build = result.text.strip() if result.ok else ""
        # Windows 11 is build >= 22000; otherwise treat as Windows 10.
        cycle = "11" if build.isdigit() and int(build) >= 22000 else "10"
        return ("windows", build, cycle)
    return ("", "", "")


def host_finding(
    rule_id: str,
    severity: str,
    title: str,
    resource: str,
    *,
    evidence: str = "",
    description: str = "",
    recommendation: str = "",
) -> Finding:
    """Build a host Finding.

    ``resource`` is a stable, file-less identifier (e.g.
    ``"macos/system-integrity-protection"``). It is mirrored into ``path`` so the
    existing reporting/SARIF/diff/ignore pipelines (which key off ``path``) keep
    working without special-casing host findings.
    """

    return Finding(
        rule_id=rule_id,
        category="host",
        severity=severity,
        title=title,
        path=Path(resource),
        evidence=evidence,
        description=description,
        recommendation=recommendation,
        resource=resource,
    )
