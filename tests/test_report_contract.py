from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.models import CATEGORIES, SEVERITIES, Finding
from security_scanner.reporting import render_json


class ReportContractTests(unittest.TestCase):
    def test_json_report_preserves_platform_contract_fields(self) -> None:
        finding = Finding(
            rule_id="host.linux.ssh-root-login",
            category="host",
            severity="high",
            title="SSH root login is allowed",
            path=Path("/etc/ssh/sshd_config"),
            target="server",
            line=12,
            evidence="PermitRootLogin yes",
            description="Root SSH login expands blast radius.",
            recommendation="Set PermitRootLogin no.",
            resource="linux/ssh-root-login",
            reachable="unknown",
            triage_verdict="uncertain",
            triage_confidence=0.5,
            triage_note="manual review required",
        )

        payload = json.loads(render_json([finding], target_names=("server",), target_paths={"server": "/srv/app"}))
        item = payload["findings"][0]

        self.assertEqual(
            set(item),
            {
                "rule_id",
                "category",
                "severity",
                "title",
                "target",
                "path",
                "line",
                "evidence",
                "description",
                "recommendation",
                "resource",
                "reachable",
                "triage_verdict",
                "triage_confidence",
                "triage_note",
            },
        )
        self.assertIn(item["severity"], SEVERITIES)
        self.assertIn(item["category"], CATEGORIES)
        self.assertEqual(item["resource"], "linux/ssh-root-login")


if __name__ == "__main__":
    unittest.main()
