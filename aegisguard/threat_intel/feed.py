"""
Threat Intelligence Feed Sync and Indicator Enrichment Engine.
Consumes external STIX/TAXII feeds, updates active confidence scores,
and calculates host compromise risk based on observed IOC hits.
"""

from typing import Dict, List, Any, Optional
import datetime
from aegisguard.catalogs.stix_threat_intel import ThreatIntelligenceEngine, IndicatorOfCompromise, IocType


class ThreatIntelEnricher:
    """Enrich security events and hosts with threat intelligence context."""

    @classmethod
    def enrich_ip(cls, ip_address: str) -> Dict[str, Any]:
        ioc = ThreatIntelligenceEngine.lookup_ioc(ip_address)
        if not ioc:
            return {
                "ip": ip_address,
                "is_known_threat": False,
                "confidence_score": 0,
                "risk_category": "BENIGN"
            }

        actor = ThreatIntelligenceEngine.get_actor_by_name(ioc.associated_actor)
        malware = ThreatIntelligenceEngine.get_malware_by_name(ioc.associated_malware)

        return {
            "ip": ip_address,
            "is_known_threat": True,
            "confidence_score": ioc.confidence,
            "risk_category": "CRITICAL" if ioc.confidence >= 90 else "HIGH",
            "description": ioc.description,
            "associated_malware": ioc.associated_malware,
            "associated_actor": ioc.associated_actor,
            "actor_motivation": actor.motivation if actor else "Unknown",
            "actor_targets": actor.target_sectors if actor else [],
            "mitre_techniques": actor.associated_mitre_techniques if actor else []
        }

    @classmethod
    def calculate_host_threat_score(cls, observed_ips: List[str], observed_hashes: List[str]) -> Dict[str, Any]:
        threat_hits = []
        total_risk = 0

        for ip in observed_ips:
            res = cls.enrich_ip(ip)
            if res["is_known_threat"]:
                threat_hits.append(res)
                total_risk += res["confidence_score"]

        for h in observed_hashes:
            ioc = ThreatIntelligenceEngine.lookup_ioc(h)
            if ioc:
                threat_hits.append({
                    "hash": h,
                    "is_known_threat": True,
                    "confidence_score": ioc.confidence,
                    "description": ioc.description,
                    "associated_malware": ioc.associated_malware
                })
                total_risk += ioc.confidence

        score = min(100, total_risk)
        severity = "CRITICAL" if score >= 80 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 20 else "LOW"))

        return {
            "threat_score": score,
            "threat_level": severity,
            "total_indicators_evaluated": len(observed_ips) + len(observed_hashes),
            "threat_hits_count": len(threat_hits),
            "hits": threat_hits
        }
