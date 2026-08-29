import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.api.app import get_system_overview


class TestAegisApi(unittest.TestCase):
    def test_system_overview(self):
        overview = get_system_overview()
        self.assertEqual(overview["status"], "OPERATIONAL")
        self.assertEqual(overview["platform"], "AegisGuard Enterprise Cyber Defense & SecOps")
        self.assertIn("mitre_matrix", overview)
        self.assertIn("cve_database", overview)
        self.assertIn("nist_framework", overview)
        self.assertIn("cis_benchmarks", overview)
        self.assertIn("sigma_rules", overview)
        self.assertIn("threat_intel", overview)
        self.assertIn("owasp_top10", overview)


if __name__ == "__main__":
    unittest.main()
