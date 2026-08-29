import unittest
import sys
from pathlib import Path

# Ensure root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.mitre_attack_enterprise import (
    MitreAttackEngine,
    TACTICS_CATALOG,
    TECHNIQUES_CATALOG,
    SeverityLevel
)


class TestMitreAttackCatalog(unittest.TestCase):
    def test_tactics_count(self):
        self.assertEqual(len(TACTICS_CATALOG), 14)

    def test_technique_retrieval(self):
        t1190 = MitreAttackEngine.get_technique("T1190")
        self.assertIsNotNone(t1190)
        self.assertEqual(t1190.name, "Exploit Public-Facing Application")
        self.assertEqual(t1190.tactic_id, "TA0001")
        self.assertEqual(t1190.severity, SeverityLevel.CRITICAL)

    def test_subtechniques_exist(self):
        sub = MitreAttackEngine.get_technique("T1059.001")
        self.assertIsNotNone(sub)
        self.assertTrue(sub.subtechnique)
        self.assertEqual(sub.parent_technique_id, "T1059")

    def test_search_techniques(self):
        matches = MitreAttackEngine.search_techniques("PowerShell")
        self.assertGreater(len(matches), 0)

    def test_coverage_summary(self):
        summary = MitreAttackEngine.get_matrix_coverage_summary()
        self.assertEqual(summary["total_tactics"], 14)
        self.assertGreater(summary["total_techniques"], 300)


if __name__ == "__main__":
    unittest.main()
