"""Host/endpoint security checks.

Unlike the file-based checks, host checks query the local machine's security
posture once per scan. ``check_host`` selects the right platform module, runs its
registered checks, and isolates per-check failures as warnings so one broken
probe never aborts the scan.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...models import Finding
from .common import HostCheck, current_platform


@dataclass(frozen=True)
class HostScanOptions:
    """Opt-in toggles for slower / network-dependent host checks."""

    enable_inventory: bool = False
    enable_eol: bool = False
    enable_cve: bool = False
    nvd_api_key: str | None = None
    max_cve_apps: int = 20
    timeout: float = 20.0


def _platform_checks(platform: str) -> tuple[HostCheck, ...]:
    if platform == "macos":
        from . import host_macos

        return host_macos.HOST_CHECKS
    if platform == "windows":
        from . import host_windows

        return host_windows.HOST_CHECKS
    return ()


def check_host(
    *,
    platform: str | None = None,
    options: HostScanOptions | None = None,
) -> tuple[list[Finding], list[str]]:
    """Run host posture checks for the current (or given) platform.

    Returns ``(findings, warnings)``. On unsupported platforms returns no findings
    and a single explanatory warning. Inventory/EOL/CVE checks run only when the
    matching option is enabled.
    """

    resolved = platform or current_platform()
    opts = options or HostScanOptions()
    checks = _platform_checks(resolved)
    if not checks and resolved not in {"macos", "windows"}:
        return [], [f"Host security checks are not supported on platform: {resolved}"]

    findings: list[Finding] = []
    warnings: list[str] = []
    for check in checks:
        try:
            findings.extend(check())
        except Exception as exc:  # noqa: BLE001 - isolate a single probe's failure
            warnings.append(f"Host check {check.__name__} failed: {exc}")

    findings.extend(_run_inventory_checks(opts, warnings))
    return findings, warnings


def _run_inventory_checks(opts: HostScanOptions, warnings: list[str]) -> list[Finding]:
    if not (opts.enable_inventory or opts.enable_eol or opts.enable_cve):
        return []
    from . import inventory_checks

    findings: list[Finding] = []
    if opts.enable_inventory:
        try:
            inv, inv_warn = inventory_checks.inventory_summary_finding()
            findings.extend(inv)
            warnings.extend(inv_warn)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Inventory check failed: {exc}")
    if opts.enable_eol:
        try:
            eol, eol_warn = inventory_checks.os_eol_finding(timeout=opts.timeout)
            findings.extend(eol)
            warnings.extend(eol_warn)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"EOL check failed: {exc}")
    if opts.enable_cve:
        try:
            cve, cve_warn = inventory_checks.app_cve_findings(
                api_key=opts.nvd_api_key, max_apps=opts.max_cve_apps, timeout=opts.timeout
            )
            findings.extend(cve)
            warnings.extend(cve_warn)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"App CVE check failed: {exc}")
    return findings


__all__ = ["check_host", "current_platform", "HostScanOptions"]
