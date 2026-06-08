"""Host/endpoint security checks.

Unlike the file-based checks, host checks query the local machine's security
posture once per scan. ``check_host`` selects the right platform module, runs its
registered checks, and isolates per-check failures as warnings so one broken
probe never aborts the scan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ...models import Finding
from .common import HostCheck, current_platform, host_finding


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

    posture: list[Finding] = []
    warnings: list[str] = []
    for check in checks:
        try:
            posture.extend(check())
        except Exception as exc:  # noqa: BLE001 - isolate a single probe's failure
            warnings.append(f"Host check {check.__name__} failed: {exc}")

    findings: list[Finding] = []
    # Posture drift (#3): compare against the saved baseline, then refresh it.
    if posture:
        try:
            findings.extend(_drift_findings(posture))
            _save_baseline(posture)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Posture drift check failed: {exc}")
    findings.extend(posture)

    findings.extend(_run_inventory_checks(opts, warnings))
    return findings, warnings


def _baseline_path() -> Path:
    return Path.home() / ".koda" / "host-posture-baseline.json"


def _load_baseline() -> dict[str, str]:
    try:
        return json.loads(_baseline_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_baseline(posture: list[Finding]) -> None:
    mapping = {finding.resource: finding.severity for finding in posture if finding.resource}
    path = _baseline_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(mapping), encoding="utf-8")
    except OSError:
        pass


def _drift_findings(posture: list[Finding]) -> list[Finding]:
    baseline = _load_baseline()
    if not baseline:
        return []
    drift: list[Finding] = []
    for finding in posture:
        if not finding.resource:
            continue
        previous = baseline.get(finding.resource)
        if previous is None:
            continue
        was_problem = previous != "info"
        is_problem = finding.severity != "info"
        if not was_problem and is_problem:
            drift.append(
                host_finding(
                    "host.drift.regressed", "high",
                    f"Security posture regressed: {finding.title}",
                    f"drift/{finding.resource}",
                    evidence=f"previously info, now {finding.severity}",
                    recommendation="A recent change weakened this control. Investigate immediately.",
                )
            )
        elif was_problem and not is_problem:
            drift.append(
                host_finding(
                    "host.drift.improved", "info",
                    f"Security posture improved: {finding.title}",
                    f"drift/{finding.resource}",
                    evidence=f"previously {previous}, now info",
                )
            )
    return drift


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
