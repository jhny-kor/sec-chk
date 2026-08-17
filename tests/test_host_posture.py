from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHARED_PYTHON = ROOT / "platforms" / "shared" / "python"
if str(SHARED_PYTHON) not in sys.path:
    sys.path.insert(0, str(SHARED_PYTHON))

from security_scanner.checks.host import host_linux, host_macos, host_windows, runner  # noqa: E402
from security_scanner.models import SEVERITY_RANK, VERIFICATION_STATUSES  # noqa: E402
from security_scanner.standards import SECURITY_STANDARDS  # noqa: E402

FAILED_PROBE = runner.CommandResult(command="probe", ok=False, returncode=1, error="command not found")


class UnevaluatedControlsStayVisibleTests(unittest.TestCase):
    """A control whose probe fails must still be reported, not dropped.

    Silently returning no finding makes an unevaluated control indistinguishable
    from one that passed, which is the worst possible default for a posture report.
    """

    def test_macos_reports_every_control_when_all_probes_fail(self) -> None:
        with mock.patch.object(host_macos, "run_command", return_value=FAILED_PROBE):
            findings = [f for check in host_macos.HOST_CHECKS for f in check()]
        self.assertEqual(len(findings), len(host_macos.HOST_CHECKS))

    def test_windows_reports_every_control_when_all_probes_fail(self) -> None:
        with mock.patch.object(host_windows, "powershell", return_value=FAILED_PROBE):
            findings = [f for check in host_windows.HOST_CHECKS for f in check()]
        self.assertEqual(len(findings), len(host_windows.HOST_CHECKS))
        self.assertTrue(all(f.verification_status == "unverified" for f in findings))

    def test_linux_reports_every_control_when_all_probes_fail(self) -> None:
        with mock.patch.object(host_linux, "run_command", return_value=FAILED_PROBE), mock.patch.object(
            host_linux, "_sshd_option", return_value=""
        ), mock.patch.object(host_linux.Path, "stat", side_effect=OSError):
            findings = [f for check in host_linux.HOST_CHECKS for f in check()]
        self.assertEqual(len(findings), len(host_linux.HOST_CHECKS))

    def test_unverified_is_an_evidence_gap_not_a_risk_verdict(self) -> None:
        with mock.patch.object(host_macos, "run_command", return_value=FAILED_PROBE):
            findings = [f for check in host_macos.HOST_CHECKS for f in check()]
        unverified = [f for f in findings if f.verification_status == "unverified"]
        self.assertTrue(unverified)
        for finding in unverified:
            self.assertEqual(finding.severity, "info")
            self.assertLess(SEVERITY_RANK[finding.severity], SEVERITY_RANK["high"])

    def test_unverified_is_a_valid_contract_status(self) -> None:
        self.assertIn("unverified", VERIFICATION_STATUSES)


class UnverifiedControlsMapToBenchmarksTests(unittest.TestCase):
    """The macOS app emits these ids under App Sandbox, so they must map."""

    def _registered(self, standard_id: str) -> set[str]:
        standard = next(item for item in SECURITY_STANDARDS if item.id == standard_id)
        return {rule_id for category in standard.categories for rule_id in category.rule_ids}

    def _emitted(self, module) -> set[str]:
        source = Path(module.__file__).read_text(encoding="utf-8")
        import re

        return set(re.findall(r'"(host\.[a-z0-9.-]+-unverified)"', source))

    def test_macos_unverified_ids_are_mapped_to_the_cis_benchmark(self) -> None:
        registered = self._registered("cis-macos-benchmark")
        unmapped = sorted(self._emitted(host_macos) - registered)
        self.assertEqual(unmapped, [])

    def test_windows_unverified_ids_are_mapped_to_the_cis_benchmark(self) -> None:
        registered = self._registered("cis-windows-benchmark")
        unmapped = sorted(self._emitted(host_windows) - registered)
        self.assertEqual(unmapped, [])

    def test_macos_app_unverified_ids_are_mapped_to_the_cis_benchmark(self) -> None:
        """The App Sandbox build reports every host item as Unverified, so an
        unmapped id would leave the whole benchmark empty on the Mac App Store."""
        import re

        scanner = (
            ROOT / "platforms" / "macos" / "app" / "KODA" / "KODA" / "NativeSecurityScanner.swift"
        ).read_text(encoding="utf-8")
        emitted = set(re.findall(r'"(host\.macos\.[a-z0-9.-]+-unverified)"', scanner))
        self.assertTrue(emitted, "the macOS app should emit Unverified host ids")
        unmapped = sorted(emitted - self._registered("cis-macos-benchmark"))
        self.assertEqual(unmapped, [])


class MacosScreenLockProbeTests(unittest.TestCase):
    """`defaults read com.apple.screensaver askForPassword` is unset on current
    macOS, so the check must use the supported sysadminctl probe instead."""

    def _result(self, stdout: str = "", stderr: str = "") -> runner.CommandResult:
        return runner.CommandResult(command="sysadminctl", ok=True, returncode=0, stdout=stdout, stderr=stderr)

    def test_immediate_lock_on_stderr_is_a_pass(self) -> None:
        with mock.patch.object(
            host_macos, "run_command", return_value=self._result(stderr="screenLock delay is immediate")
        ):
            findings = host_macos.check_screen_lock()
        self.assertEqual([f.rule_id for f in findings], ["host.macos.screen-lock-enabled"])

    def test_long_delay_is_a_finding(self) -> None:
        with mock.patch.object(
            host_macos, "run_command", return_value=self._result(stderr="screenLock delay is 900 seconds")
        ):
            findings = host_macos.check_screen_lock()
        self.assertEqual([f.rule_id for f in findings], ["host.macos.screen-lock-disabled"])

    def test_unreadable_probe_reports_unverified_rather_than_nothing(self) -> None:
        with mock.patch.object(host_macos, "run_command", return_value=FAILED_PROBE):
            findings = host_macos.check_screen_lock()
        self.assertEqual([f.rule_id for f in findings], ["host.macos.screen-lock-unverified"])

    def test_screen_lock_probe_is_allowlisted(self) -> None:
        self.assertIn("sysadminctl", runner.ALLOWED_COMMANDS)


if __name__ == "__main__":
    unittest.main()
