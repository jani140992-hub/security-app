"""
Diamond Model of Intrusion Analysis & Campaign Correlation Engine.
Implements formal 4-vertex Diamond Model representations (Adversary, Capability,
Infrastructure, Victim) and computes TTP Jaccard similarity across incident campaigns.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import math
import uuid


@dataclass
class DiamondEventVertex:
    event_id: str
    adversary: str
    capabilities: List[str]  # Tools, exploits, malware
    infrastructure: List[str]  # IP addresses, C2 domains, ASNs
    victim: str  # Hostname, industry sector, cloud tenant
    phase: str  # Recon, Weaponization, Delivery, Exploitation, C2, Actions
    confidence: float = 0.85


@dataclass
class ThreatCampaignCluster:
    cluster_id: str
    primary_adversary: str
    associated_events: List[DiamondEventVertex] = field(default_factory=list)
    confidence_score: float = 0.0
    common_ttps: List[str] = field(default_factory=list)


class DiamondModelAnalyzer:
    """Intrusion event clustering and adversary campaign correlation engine."""

    @classmethod
    def calculate_jaccard_similarity(cls, set_a: Set[str], set_b: Set[str]) -> float:
        if not set_a or not set_b:
            return 0.0
        intersection = len(set_a.intersection(set_b))
        union = len(set_a.union(set_b))
        return round(intersection / union, 4) if union else 0.0

    @classmethod
    def correlate_events(cls, events: List[DiamondEventVertex], similarity_threshold: float = 0.4) -> List[ThreatCampaignCluster]:
        clusters: List[ThreatCampaignCluster] = []

        for evt in events:
            assigned = False
            evt_capabilities = set(evt.capabilities)
            evt_infra = set(evt.infrastructure)

            for cluster in clusters:
                # Compare against all events in cluster
                cluster_capabilities = set().union(*[set(e.capabilities) for e in cluster.associated_events])
                cluster_infra = set().union(*[set(e.infrastructure) for e in cluster.associated_events])

                cap_sim = cls.calculate_jaccard_similarity(evt_capabilities, cluster_capabilities)
                inf_sim = cls.calculate_jaccard_similarity(evt_infra, cluster_infra)
                overall_score = (cap_sim * 0.6) + (inf_sim * 0.4)

                if overall_score >= similarity_threshold or (evt.adversary and evt.adversary == cluster.primary_adversary):
                    cluster.associated_events.append(evt)
                    cluster.common_ttps = list(cluster_capabilities.union(evt_capabilities))
                    cluster.confidence_score = max(cluster.confidence_score, evt.confidence)
                    assigned = True
                    break

            if not assigned:
                clusters.append(ThreatCampaignCluster(
                    cluster_id=f"cluster-{uuid.uuid4()}",
                    primary_adversary=evt.adversary or "Unknown Adversary",
                    associated_events=[evt],
                    confidence_score=evt.confidence,
                    common_ttps=list(evt.capabilities)
                ))

        return clusters
