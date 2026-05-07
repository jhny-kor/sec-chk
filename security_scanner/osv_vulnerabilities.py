from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from .models import DependencyComponent, Finding


OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULNERABILITY_URL = "https://osv.dev/vulnerability"
OSV_BATCH_SIZE = 100


def query_osv_findings(
    components: tuple[DependencyComponent, ...],
    *,
    timeout_seconds: float = 12.0,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    warnings: list[str] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for batch in _batches(components, OSV_BATCH_SIZE):
        try:
            response = _post_querybatch(batch, timeout_seconds)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            warnings.append(f"OSV query failed: {exc}")
            continue

        results = response.get("results", [])
        if not isinstance(results, list):
            warnings.append("OSV query returned an unexpected response shape.")
            continue

        for component, result in zip(batch, results, strict=False):
            if not isinstance(result, dict):
                continue
            if result.get("next_page_token"):
                warnings.append(f"OSV result for {component.name}@{component.version} was paginated; showing the first page only.")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id", "")).strip()
                if not vuln_id:
                    continue
                key = (*component.key(), vuln_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(_finding_from_vulnerability(component, vuln_id))
    return findings, warnings


def _post_querybatch(components: tuple[DependencyComponent, ...], timeout_seconds: float) -> dict[str, object]:
    body = json.dumps(
        {
            "queries": [
                {
                    "package": {
                        "ecosystem": component.ecosystem,
                        "name": component.name,
                    },
                    "version": component.version,
                }
                for component in components
            ]
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OSV_QUERY_BATCH_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "sec-chk-local-security-scanner",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _finding_from_vulnerability(component: DependencyComponent, vuln_id: str) -> Finding:
    url = f"{OSV_VULNERABILITY_URL}/{vuln_id}"
    location = Path(component.path)
    return Finding(
        rule_id="dependency.osv-known-vulnerability",
        category="dependencies",
        severity="high",
        title="Known vulnerable dependency reported by OSV",
        path=location,
        target=component.target,
        line=component.line,
        evidence=f"{component.ecosystem} {component.name}@{component.version}: {vuln_id}",
        description="OSV reports a known vulnerability for this exact dependency version.",
        recommendation=f"Review {url}, then upgrade, patch, replace, or document a compensating control.",
    )


def _batches(components: tuple[DependencyComponent, ...], size: int):
    for index in range(0, len(components), size):
        yield components[index : index + size]
