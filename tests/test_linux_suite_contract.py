import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class LinuxSuiteContractTests(unittest.TestCase):
    def test_dependency_track_routes_are_checked(self) -> None:
        launcher = (ROOT / "platforms/linux/suite/koda-suite").read_text()
        gateway = (ROOT / "platforms/linux/suite/gateway.conf.template").read_text()

        self.assertIn("/dependency-track/api/version", launcher)
        self.assertIn("/dependency-track/\" \"Dependency-Track", launcher)
        self.assertIn("location = /dependency-track { return 308 /dependency-track/; }", gateway)


if __name__ == "__main__":
    unittest.main()
