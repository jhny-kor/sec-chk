"""Inventory-driven host findings: app inventory, OS EOL, and app CVEs.

These are opt-in (network / slower) and are run by ``check_host`` only when the
corresponding option is enabled. Each helper isolates its own failures and
returns findings plus warnings.
"""

from __future__ import annotations

from ...models import Finding
from .common import host_finding, os_release


def inventory_summary_finding() -> tuple[list[Finding], list[str]]:
    from ...inventory import collect_installed_apps

    apps, warnings = collect_installed_apps()
    if not apps:
        return [], warnings
    versioned = sum(1 for app in apps if app.version)
    finding = host_finding(
        "host.inventory.installed-apps",
        "info",
        f"{len(apps)} installed applications inventoried",
        "host/installed-apps",
        evidence=f"{len(apps)} apps ({versioned} with versions)",
        description="Installed-software inventory is the basis for vulnerability and end-of-life checks.",
    )
    return [finding], warnings


def os_eol_finding(*, timeout: float = 12.0) -> tuple[list[Finding], list[str]]:
    from ...eol_data import query_cycle_eol

    product, version, cycle = os_release()
    if not product or not cycle:
        return [], ["Could not determine OS release for EOL lookup."]
    result, warnings = query_cycle_eol(product, cycle, timeout_seconds=timeout)
    if result is None:
        return [], warnings
    resource = f"host/os-eol/{product}-{cycle}"
    if result.is_eol:
        return [
            host_finding(
                "host.eol.os-end-of-life",
                "high",
                f"Operating system {product} {version or cycle} is end-of-life",
                resource,
                evidence=result.summary,
                description="End-of-life operating systems no longer receive security updates, leaving known vulnerabilities unpatched.",
                recommendation="Upgrade to a supported OS release.",
            )
        ], warnings
    if result.support_unknown:
        return [
            host_finding(
                "host.eol.os-support-unknown",
                "low",
                f"Operating system {product} {version or cycle} support status is unknown",
                resource,
                evidence=result.summary,
            )
        ], warnings
    return [
        host_finding(
            "host.eol.os-supported",
            "info",
            f"Operating system {product} {version or cycle} is within its support window",
            resource,
            evidence=result.summary,
        )
    ], warnings


def app_cve_findings(
    *,
    api_key: str | None = None,
    max_apps: int = 20,
    timeout: float = 20.0,
) -> tuple[list[Finding], list[str]]:
    from ...cpe_lookup import query_app_vulnerabilities
    from ...inventory import collect_installed_apps

    apps, inv_warnings = collect_installed_apps()
    if not apps:
        return [], inv_warnings
    vulns, warnings = query_app_vulnerabilities(
        apps, api_key=api_key, max_apps=max_apps, timeout_seconds=timeout
    )
    findings: list[Finding] = []
    for vuln in vulns:
        severity = _severity_from_cvss(vuln.cvss)
        findings.append(
            host_finding(
                "host.cve.installed-app",
                severity,
                f"{vuln.app.name} {vuln.app.version}: {vuln.cve}",
                f"host/app-cve/{vuln.app.name}",
                evidence=f"{vuln.cve}"
                + (f" (CVSS {vuln.cvss})" if vuln.cvss is not None else "")
                + f" — {vuln.url}",
                description=(vuln.description[:300] + "…")
                if len(vuln.description) > 300
                else vuln.description,
                recommendation="Verify the match against the vendor advisory and update the app if affected. NVD keyword matches may include false positives.",
            )
        )
    return findings, inv_warnings + warnings


def _severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"
