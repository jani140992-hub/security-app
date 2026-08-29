import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.cve_cwe_database import (
    CveDatabaseEngine,
    CvssV31Calculator,
    CVE_CATALOG,
    CWE_CATALOG,
    Severity
)


class TestCveDatabaseAndCvss(unittest.TestCase):
    def test_cve_catalog_populated(self):
        self.assertGreaterEqual(len(CVE_CATALOG), 300)
        self.assertGreaterEqual(len(CWE_CATALOG), 20)

    def test_cve_search(self):
        results = CveDatabaseEngine.search("Kubernetes")
        self.assertGreater(len(results), 0)

    def test_cvss_calculation_high_critical(self):
        # Critical Vector: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        calc = CvssV31Calculator.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(calc["base_score"], 9.8)
        self.assertEqual(calc["severity"], Severity.CRITICAL)

    def test_cvss_scope_changed(self):
        # Scope Changed Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
        calc = CvssV31Calculator.calculate_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(calc["base_score"], 10.0)
        self.assertEqual(calc["severity"], Severity.CRITICAL)

    def test_database_summary(self):
        summary = CveDatabaseEngine.get_database_summary()
        self.assertGreater(summary["total_cves"], 300)
        self.assertGreater(summary["critical_count"], 50)


if __name__ == "__main__":
    unittest.main()
