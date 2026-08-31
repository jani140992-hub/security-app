import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.threat_intel.diamond_model import (
    DiamondModelAnalyzer,
    DiamondEventVertex,
    ThreatCampaignCluster
)


class TestDiamondModelAnalyzer(unittest.TestCase):
    def test_jaccard_similarity(self):
        set_1 = {"T1059.001", "T1003.001", "T1071.001"}
        set_2 = {"T1059.001", "T1003.001", "T1190"}
        sim = DiamondModelAnalyzer.calculate_jaccard_similarity(set_1, set_2)
        self.assertGreater(sim, 0.4)

    def test_campaign_correlation(self):
        e1 = DiamondEventVertex(
            event_id="evt-1",
            adversary="APT29",
            capabilities=["Beacon-C2", "T1059.001", "T1003.001"],
            infrastructure=["198.51.100.42"],
            victim="srv-finance-01",
            phase="Execution"
        )
        e2 = DiamondEventVertex(
            event_id="evt-2",
            adversary="APT29",
            capabilities=["Beacon-C2", "T1071.001"],
            infrastructure=["198.51.100.42"],
            victim="srv-app-02",
            phase="Command and Control"
        )
        e3 = DiamondEventVertex(
            event_id="evt-3",
            adversary="FIN7",
            capabilities=["Carbanak", "T1055.002"],
            infrastructure=["203.0.113.88"],
            victim="srv-pos-01",
            phase="Persistence"
        )

        clusters = DiamondModelAnalyzer.correlate_events([e1, e2, e3])
        self.assertEqual(len(clusters), 2)
        apt29_cluster = next(c for c in clusters if c.primary_adversary == "APT29")
        self.assertEqual(len(apt29_cluster.associated_events), 2)


if __name__ == "__main__":
    unittest.main()
