import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LinuxSuiteContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.launcher = (ROOT / "platforms/linux/suite/koda-suite").read_text()
        cls.compose = (ROOT / "platforms/linux/suite/compose.integration.yaml").read_text()
        cls.gateway = (ROOT / "platforms/linux/suite/gateway.conf.template").read_text()

    def test_all_three_products_are_routed_and_health_checked(self) -> None:
        self.assertIn('/koda/live', self.launcher)
        self.assertIn('/api/v1/healthz', self.launcher)
        self.assertIn('/dependency-track/api/version', self.launcher)
        self.assertIn('/dependency-track/static/config.json', self.launcher)
        self.assertIn('location ^~ /koda/', self.gateway)
        self.assertIn('location /api/', self.gateway)
        self.assertIn('location /dependency-track/', self.gateway)
        self.assertIn('location = /dependency-track/static/config.json', self.gateway)
        self.assertIn('add_header Cache-Control "no-store" always;', self.gateway)
        self.assertIn('proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}/;', self.gateway)
        self.assertNotIn('proxy_pass http://${DTRACK_FRONTEND_UPSTREAM}${DTRACK_BASE_PATH}/;', self.gateway)

    def test_env_parser_is_quiet_on_linux_awk(self) -> None:
        self.assertIn('value="$(awk -F= -v key="$key"', self.launcher)
        self.assertNotIn('\\047\\"', self.launcher)

    def test_lifecycle_uses_one_integrated_offline_compose_contract(self) -> None:
        self.assertIn('suite_compose "$prefix" up -d --no-build --pull never', self.launcher)
        self.assertIn('suite_compose "$prefix" ps', self.launcher)
        self.assertIn('suite_compose "$prefix" stop', self.launcher)
        self.assertIn('compose.airgap.yaml', self.launcher)
        self.assertIn('compose.integration.yaml', self.launcher)

    def test_koda_has_no_direct_host_port(self) -> None:
        self.assertIn('KODA_PUBLISH_DASHBOARD=0', self.launcher)
        self.assertIn('.HostConfig.PortBindings', self.launcher)
        self.assertNotIn('ports:', self.compose)
        self.assertIn('external: true', self.compose)

    def test_packager_requires_both_verified_offline_payloads(self) -> None:
        packager = (ROOT / "platforms/linux/package-suite-offline.sh").read_text()

        self.assertIn('KODA_DOCKER_BUNDLE', packager)
        self.assertIn('KODA_TRACKER_BUNDLE', packager)
        self.assertIn('"$tracker_verifier" "$tracker_bundle"', packager)
        self.assertIn('KODA_BUNDLE=bundles/', packager)
        self.assertIn('TRACKER_BUNDLE=bundles/', packager)
        self.assertIn('single assignment per key', packager)
        self.assertIn('TROUBLESHOOTING.ko.md', packager)
        self.assertIn('"$script_dir/TROUBLESHOOTING.ko.md"', self.launcher)

    def test_verify_command_accepts_intact_release_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            release = Path(temp)
            (release / 'bundles').mkdir()
            (release / 'gateway').mkdir()
            (release / 'bundles/koda.tar.gz').write_bytes(b'koda')
            (release / 'bundles/tracker.tar.gz').write_bytes(b'tracker')
            (release / 'compose.integration.yaml').write_text('services: {}\n')
            (release / 'gateway/gateway.conf.template').write_text('server {}\n')
            metadata = '''TARGET_PLATFORM=linux/amd64
DISTRIBUTION_SCOPE=internal-only
KODA_BUNDLE=bundles/koda.tar.gz
TRACKER_BUNDLE=bundles/tracker.tar.gz
TRACKER_VULNERABILITY_BUNDLE=absent
AUTHORITY=tracker
AUTH_CONTRACT_VERSION=1
AUTH_COOKIE_NAME=__Host-koda_session
AUTH_COOKIE_SCHEMA_VERSION=2
TRACKER_SESSION_ENDPOINT=/api/v1/auth/session
KODA_BASE_PATH=/koda/
GATEWAY_AUTH_MODE=auth_request
KODA_PORTAL_SCHEMA_VERSION=1
KODA_RBAC_CATALOG_VERSION=koda-rbac-v1
'''
            (release / 'metadata.env').write_text(metadata)
            script = release / 'koda-suite'
            script.write_text(self.launcher)
            script.chmod(0o755)
            files = sorted(path for path in release.rglob('*') if path.is_file())
            manifest = ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(release)}\n'
                for path in files
            )
            (release / 'manifest.sha256').write_text(manifest)

            result = subprocess.run(
                [str(script), 'verify'], cwd=release, text=True, capture_output=True,
                env={**os.environ, 'HOME': temp}, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('release integrity OK', result.stdout)

            (release / 'bundles/koda.tar.gz').write_bytes(b'tampered')
            result = subprocess.run(
                [str(script), 'verify'], cwd=release, text=True, capture_output=True,
                env={**os.environ, 'HOME': temp}, check=False,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
