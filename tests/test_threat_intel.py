import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.catalogs.stix_threat_intel import (
    ThreatIntelligenceEngine,
    THREAT_ACTORS_CATALOG,
    IOC_CATALOG,
    IocType
)
from aegisguard.threat_intel.feed import ThreatIntelEnricher


class TestThreatIntelligence(unittest.TestCase):
    def test_actors_catalog(self):
        self.assertGreaterEqual(len(THREAT_ACTORS_CATALOG), 10)
        apt29 = ThreatIntelligenceEngine.get_actor_by_name("APT29")
        self.assertIsNotNone(apt29)
        self.assertIn("Cozy Bear", apt29.aliases)

    def test_ioc_lookup(self):
        ioc = ThreatIntelligenceEngine.lookup_ioc("198.51.100.42")
        self.assertIsNotNone(ioc)
        self.assertEqual(ioc.ioc_type, IocType.IPV4)

    def test_enrichment(self):
        enr = ThreatIntelEnricher.enrich_ip("198.51.100.42")
        self.assertTrue(enr["is_known_threat"])
        self.assertGreaterEqual(enr["confidence_score"], 80)

    def test_stix_bundle_export(self):
        bundle = ThreatIntelligenceEngine.export_stix_bundle()
        self.assertEqual(bundle["type"], "bundle")
        self.assertGreater(len(bundle["objects"]), 30)


if __name__ == "__main__":
    unittest.main()
