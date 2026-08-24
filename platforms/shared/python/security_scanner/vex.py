from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import __version__
from .models import Finding
from .vuln_intel import extract_cve_ids


def cyclonedx_vex_payload(findings: list[Finding]) -> dict[str, object]:
    vulnerabilities: list[dict[str, object]] = []
    for finding in findings:
        if finding.rule_id != "dependency.osv-known-vulnerability":
            continue
        vuln_ids = extract_cve_ids([finding.evidence, finding.title]) or (_osv_id(finding.evidence),)
        for vuln_id in [item for item in vuln_ids if item]:
            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "source": {"name": "KODA OSV lookup"},
                    "ratings": [{"severity": finding.severity}],
                    "analysis": {
                        "state": "in_triage",
                        "detail": "KODA generated this VEX entry as a review placeholder. Confirm exploitability before marking affected, not_affected, or resolved.",
                    },
                    "affects": [
                        {
                            "ref": _component_ref(finding),
                        }
                    ],
                    "properties": [
                        {"name": "koda:rule_id", "value": finding.rule_id},
                        {"name": "koda:target", "value": finding.target},
                        {"name": "koda:path", "value": str(finding.path)},
                    ],
                }
            )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "KODA",
                        "version": __version__,
                    }
                ]
            },
        },
        "vulnerabilities": vulnerabilities,
    }


def render_cyclonedx_vex(findings: list[Finding]) -> str:
    return json.dumps(cyclonedx_vex_payload(findings), indent=2, ensure_ascii=False)


def _osv_id(evidence: str) -> str:
    marker = evidence.split(":", 1)[-1].strip().split()[0] if ":" in evidence else ""
    return marker.strip("(),;")


def _component_ref(finding: Finding) -> str:
    prefix = finding.evidence.split(":", 1)[0].strip()
    if " " not in prefix or "@" not in prefix:
        return str(finding.path)
    ecosystem, name_version = prefix.split(" ", 1)
    name, version = name_version.rsplit("@", 1)
    if ecosystem == "npm":
        return f"pkg:npm/{name}@{version}"
    if ecosystem == "PyPI":
        return f"pkg:pypi/{name.lower()}@{version}"
    return f"{ecosystem}:{name}@{version}"
