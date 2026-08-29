import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.nist_sp800_53 import (
    NistSp80053Engine,
    CONTROLS_CATALOG,
    FAMILIES_CATALOG,
    BaselineImpact
)
from aegisguard.catalogs.cis_benchmarks import (
    CisBenchmarkEngine,
    BENCHMARKS_CATALOG,
    RECOMMENDATIONS_CATALOG
)


class TestComplianceEngines(unittest.TestCase):
    def test_nist_framework_loaded(self):
        self.assertGreaterEqual(len(FAMILIES_CATALOG), 18)
        self.assertGreaterEqual(len(CONTROLS_CATALOG), 150)

    def test_nist_control_lookup(self):
        ctrl = NistSp80053Engine.get_control("AC-2")
        self.assertIsNotNone(ctrl)
        self.assertEqual(ctrl.family_id, "AC")
        self.assertIn(BaselineImpact.LOW, ctrl.baseline_impact)

    def test_nist_compliance_evaluation(self):
        passing = {"AC-1", "AC-2", "AU-2", "AU-3", "SI-4", "SC-7"}
        res = NistSp80053Engine.evaluate_compliance(passing, BaselineImpact.LOW)
        self.assertIn("compliance_score_percent", res)
        self.assertEqual(res["passed_count"], 6)

    def test_cis_benchmarks_loaded(self):
        self.assertEqual(len(BENCHMARKS_CATALOG), 5)
        self.assertGreater(len(RECOMMENDATIONS_CATALOG), 100)

    def test_cis_audit_posture(self):
        res = CisBenchmarkEngine.audit_system_posture("CIS-UBUNTU-22.04", {"CIS-UBUNTU-22.04-1.1.1"})
        self.assertGreater(res["total_rules"], 30)
        self.assertEqual(res["passed_count"], 1)


if __name__ == "__main__":
    unittest.main()
