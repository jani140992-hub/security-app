import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.cloud_compliance_controls import (
    CloudComplianceEngine,
    CLOUD_CONTROLS_CATALOG,
    CSA_DOMAINS,
    ControlLevel
)


class TestCloudComplianceCatalog(unittest.TestCase):
    def test_domains_count(self):
        self.assertEqual(len(CSA_DOMAINS), 17)

    def test_controls_count(self):
        self.assertGreaterEqual(len(CLOUD_CONTROLS_CATALOG), 180)

    def test_get_control(self):
        ctrl = CloudComplianceEngine.get_control("CCM4-AIS-01")
        self.assertIsNotNone(ctrl)
        self.assertEqual(ctrl.domain_code, "AIS")
        self.assertIn("Application", ctrl.title)

    def test_audit_readiness(self):
        passing = {f"CCM4-AIS-{i:02d}" for i in range(1, 10)}
        res = CloudComplianceEngine.audit_framework_readiness(passing)
        self.assertEqual(res["passed_controls"], 9)
        self.assertIn("readiness_percent", res)

    def test_framework_summary(self):
        summary = CloudComplianceEngine.get_framework_summary()
        self.assertEqual(summary["total_domains"], 17)
        self.assertGreater(summary["total_controls"], 150)


if __name__ == "__main__":
    unittest.main()
