"""
STIX 2.1 Threat Intelligence Knowledge Base & Real-Time IOC Lookup Engine.
Provides comprehensive profiles of advanced threat actors (APTs), malware families,
and high-fidelity Indicators of Compromise (IOCs) with STIX 2.1 JSON export.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set
import json
import uuid


class IocType(str, Enum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    HASH_SHA256 = "file-hash-sha256"
    HASH_MD5 = "file-hash-md5"
    JA3 = "ja3-fingerprint"


@dataclass
class ThreatActor:
    id: str
    name: str
    aliases: List[str]
    actor_type: str
    motivation: str
    target_sectors: List[str]
    associated_mitre_techniques: List[str]
    associated_malware: List[str]


@dataclass
class MalwareProfile:
    id: str
    name: str
    description: str
    malware_type: str
    target_platforms: List[str]
    severity: str


@dataclass
class IndicatorOfCompromise:
    ioc_type: IocType
    value: str
    description: str
    confidence: int
    associated_malware: str
    associated_actor: str
    is_active: bool = True
    first_seen: str = "2024-01-01T00:00:00Z"
    last_seen: str = "2024-12-31T23:59:59Z"


THREAT_ACTORS_CATALOG: Dict[str, ThreatActor] = {
    "threat-actor--001": ThreatActor(
        id="threat-actor--001",
        name="APT28",
        aliases=['Fancy Bear', 'Strontium', 'Sednit', 'Pawn Storm'],
        actor_type="State-Sponsored",
        motivation="Espionage, Sabotage",
        target_sectors=['Defense', 'Government', 'Energy'],
        associated_mitre_techniques=['T1190', 'T1059.001', 'T1003.001', 'T1071.001'],
        associated_malware=['Beacon-C2', 'Zebrocy', 'Sofacy']
    ),
    "threat-actor--002": ThreatActor(
        id="threat-actor--002",
        name="APT29",
        aliases=['Cozy Bear', 'Nobelium', 'Midnight Blizzard', 'The Dukes'],
        actor_type="State-Sponsored",
        motivation="Intelligence Gathering",
        target_sectors=['Government', 'Cloud Providers', 'Technology'],
        associated_mitre_techniques=['T1078.004', 'T1098.001', 'T1195.002', 'T1567.002'],
        associated_malware=['Beacon-C2', 'EnvyScout', 'GoldMax']
    ),
    "threat-actor--003": ThreatActor(
        id="threat-actor--003",
        name="Lazarus Group",
        aliases=['Hidden Cobra', 'Zinc', 'Labyrinth Chollima'],
        actor_type="State-Sponsored",
        motivation="Financial Theft, Espionage",
        target_sectors=['Financial Services', 'Cryptocurrency', 'Defense'],
        associated_mitre_techniques=['T1566.001', 'T1055.001', 'T1027.002', 'T1486'],
        associated_malware=['Brambul', 'Joanap', 'Manuscrypt']
    ),
    "threat-actor--004": ThreatActor(
        id="threat-actor--004",
        name="FIN7",
        aliases=['Carbanak', 'ELBRUS', 'Carbon Spider'],
        actor_type="Organized Cybercrime",
        motivation="Financial Fraud",
        target_sectors=['Retail', 'Hospitality', 'Restaurant'],
        associated_mitre_techniques=['T1566.002', 'T1059.007', 'T1055.002', 'T1558.003'],
        associated_malware=['Carbanak', 'Babar', 'Lizar']
    ),
    "threat-actor--005": ThreatActor(
        id="threat-actor--005",
        name="Wizard Spider",
        aliases=['Grim Spider', 'UNC1878'],
        actor_type="Organized Cybercrime",
        motivation="Ransomware Operations",
        target_sectors=['Healthcare', 'Manufacturing', 'Municipalities'],
        associated_mitre_techniques=['T1486', 'T1490', 'T1003.003', 'T1021.001'],
        associated_malware=['Trojan-Loader', 'Ryuk', 'Conti', 'BazarLoader']
    ),
    "threat-actor--006": ThreatActor(
        id="threat-actor--006",
        name="Sandworm Team",
        aliases=['Voodoo Bear', 'TeleBots', 'BlackEnergy'],
        actor_type="State-Sponsored",
        motivation="Destructive Attacks, Warfare",
        target_sectors=['Energy Grids', 'Telecommunications', 'Government'],
        associated_mitre_techniques=['T1485', 'T1489', 'T1059.004', 'T1021.004'],
        associated_malware=['BlackEnergy', 'Industroyer', 'CaddyWiper', 'HermeticWiper']
    ),
    "threat-actor--007": ThreatActor(
        id="threat-actor--007",
        name="Volt Typhoon",
        aliases=['Bronze Silhouette', 'Vanguard Panda'],
        actor_type="State-Sponsored",
        motivation="Pre-positioning, Living off the Land",
        target_sectors=['Critical Infrastructure', 'Water', 'Transportation'],
        associated_mitre_techniques=['T1190', 'T1078', 'T1059.003', 'T1046'],
        associated_malware=['Fast Reverse Proxy', 'Earthworm']
    ),
    "threat-actor--008": ThreatActor(
        id="threat-actor--008",
        name="Scattered Spider",
        aliases=['0ktapus', 'UNC3944', 'Starfrost'],
        actor_type="Cybercrime / Extortion",
        motivation="Data Theft, Extortion",
        target_sectors=['Telecommunications', 'SaaS', 'Hospitality'],
        associated_mitre_techniques=['T1078.004', 'T1098.001', 'T1530', 'T1567.002'],
        associated_malware=['RemoteDesktop-Client', 'LPort']
    ),
    "threat-actor--009": ThreatActor(
        id="threat-actor--009",
        name="Lapsus$",
        aliases=['DEV-0537'],
        actor_type="Extortion Group",
        motivation="Data Extortion, Source Code Leakage",
        target_sectors=['Technology', 'Gaming', 'Telecommunications'],
        associated_mitre_techniques=['T1078.004', 'T1606', 'T1567.002'],
        associated_malware=['SecCred-Dumper', 'ProcessInspect']
    ),
    "threat-actor--010": ThreatActor(
        id="threat-actor--010",
        name="Turla",
        aliases=['Waterbug', 'Venomous Bear', 'Snake'],
        actor_type="State-Sponsored",
        motivation="Espionage, Complex C2",
        target_sectors=['Government', 'Embassy', 'Research'],
        associated_mitre_techniques=['T1055.012', 'T1071.004', 'T1573.002'],
        associated_malware=['Snake', 'ComRAT', 'Carbon']
    ),
}

MALWARE_CATALOG: Dict[str, MalwareProfile] = {
    "malware--101": MalwareProfile(
        id="malware--101",
        name="Beacon-C2 Agent",
        description="""Commercial penetration testing tool repurposed for adversarial post-exploitation C2.""",
        malware_type="Backdoor, C2 Agent",
        target_platforms=['Windows', 'Linux'],
        severity="HIGH"
    ),
    "malware--102": MalwareProfile(
        id="malware--102",
        name="SecCred-Dumper",
        description="""Credential extraction utility targeting LSASS, SAM, and Kerberos ticket stores.""",
        malware_type="Credential Dumper",
        target_platforms=['Windows'],
        severity="CRITICAL"
    ),
    "malware--103": MalwareProfile(
        id="malware--103",
        name="Red-Stealer",
        description="""Information stealer harvesting credentials, crypto wallets, and browser cookies.""",
        malware_type="Infostealer",
        target_platforms=['Windows'],
        severity="HIGH"
    ),
    "malware--104": MalwareProfile(
        id="malware--104",
        name="Lumma-Agent",
        description="""C-based malware distributed via malicious landing pages harvesting session cookies.""",
        malware_type="Infostealer",
        target_platforms=['Windows'],
        severity="HIGH"
    ),
    "malware--105": MalwareProfile(
        id="malware--105",
        name="Trojan-Loader",
        description="""Modular banking trojan that evolved into a primary ransomware delivery loader.""",
        malware_type="Loader, Trojan",
        target_platforms=['Windows'],
        severity="CRITICAL"
    ),
    "malware--106": MalwareProfile(
        id="malware--106",
        name="Cryptor-3.0",
        description="""Fast multi-threaded ransomware employing ChaCha20 encryption and shadow deletion.""",
        malware_type="Ransomware",
        target_platforms=['Windows', 'Linux'],
        severity="CRITICAL"
    ),
    "malware--107": MalwareProfile(
        id="malware--107",
        name="Ransom-ALPHV",
        description="""Rust-based ransomware with customizable encryption routines and evasion modules.""",
        malware_type="Ransomware",
        target_platforms=['Windows', 'Linux', 'VMware ESXi'],
        severity="CRITICAL"
    ),
    "malware--108": MalwareProfile(
        id="malware--108",
        name="Disk-Wiper",
        description="""Destructive malware targeting physical disk partitions and Volume Shadow Copies.""",
        malware_type="Wiper",
        target_platforms=['Windows'],
        severity="CRITICAL"
    ),
    "malware--109": MalwareProfile(
        id="malware--109",
        name="Q-Loader",
        description="""Banking trojan and modular malware loader spread through malicious email attachments.""",
        malware_type="Loader, Banking Trojan",
        target_platforms=['Windows'],
        severity="HIGH"
    ),
    "malware--110": MalwareProfile(
        id="malware--110",
        name="Sliver-Agent",
        description="""Open-source cross-platform adversary emulation framework used for evasion.""",
        malware_type="C2 Framework",
        target_platforms=['Windows', 'Linux', 'macOS'],
        severity="HIGH"
    ),
}

IOC_CATALOG: Dict[str, IndicatorOfCompromise] = {
    "198.51.100.42": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.42",
        description="""Known Adversary Beacon Team Server""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT29"
    ),
    "203.0.113.88": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="203.0.113.88",
        description="""Active Proxy C2 Node""",
        confidence=90,
        associated_malware="Trojan-Loader",
        associated_actor="Wizard Spider"
    ),
    "192.0.2.145": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="192.0.2.145",
        description="""Extortion Portal Backend""",
        confidence=98,
        associated_malware="Cryptor-3.0",
        associated_actor="Extortion Actor"
    ),
    "198.51.100.199": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.199",
        description="""Stealer Log Exfiltration Endpoint""",
        confidence=92,
        associated_malware="Lumma-Agent",
        associated_actor="Unknown"
    ),
    "203.0.113.250": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="203.0.113.250",
        description="""Fast Reverse Proxy Pivot""",
        confidence=96,
        associated_malware="Fast Reverse Proxy",
        associated_actor="Volt Typhoon"
    ),
    "update-microsoft-telemetry.com": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="update-microsoft-telemetry.com",
        description="""Typosquatted C2 Domain for payload delivery""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "secure-sso-authportal.net": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="secure-sso-authportal.net",
        description="""Phishing domain targeting enterprise SSO""",
        confidence=99,
        associated_malware="Infostealer",
        associated_actor="Scattered Spider"
    ),
    "cdn-content-cloudservice.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="cdn-content-cloudservice.org",
        description="""Adversary Dead Drop Resolver domain""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Turla"
    ),
    "sync-cloud-storage-api.com": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="sync-cloud-storage-api.com",
        description="""Data Exfiltration endpoint masquerading as cloud backup""",
        confidence=91,
        associated_malware="Ransom-ALPHV",
        associated_actor="Extortion Actor"
    ),
    "telemetry-internal-gateway.info": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="telemetry-internal-gateway.info",
        description="""Dynamic DNS resolving adversary infrastructure""",
        confidence=87,
        associated_malware="Trojan-Loader",
        associated_actor="Wizard Spider"
    ),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        description="""Known destructive binary digest""",
        confidence=100,
        associated_malware="Disk-Wiper",
        associated_actor="Sandworm Team"
    ),
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        description="""Credential extraction binary digest""",
        confidence=100,
        associated_malware="SecCred-Dumper",
        associated_actor="Multiple"
    ),
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        description="""Ransomware Encryptor Payload Hash""",
        confidence=100,
        associated_malware="Cryptor-3.0",
        associated_actor="Extortion Actor"
    ),
    "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d",
        description="""Stealer packed sample hash""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="Cybercrime"
    ),
    "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
        description="""Reflective DLL loader payload""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT29"
    ),
    "72a589da586844d7f0818ce684948eea": IndicatorOfCompromise(
        ioc_type=IocType.JA3,
        value="72a589da586844d7f0818ce684948eea",
        description="""Adversary TLS Client Hello JA3 fingerprint""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Multiple"
    ),
    "a0e9f5d64349fb13191bc781f81f42e1": IndicatorOfCompromise(
        ioc_type=IocType.JA3,
        value="a0e9f5d64349fb13191bc781f81f42e1",
        description="""TLS client handshake fingerprint""",
        confidence=90,
        associated_malware="Trojan-Loader",
        associated_actor="Wizard Spider"
    ),
    "b32309a26951912be7dba376398abc3b": IndicatorOfCompromise(
        ioc_type=IocType.JA3,
        value="b32309a26951912be7dba376398abc3b",
        description="""Anonymizing TLS Client Fingerprint""",
        confidence=85,
        associated_malware="Tor Client",
        associated_actor="Adversary"
    ),
    "198.51.100.2": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.2",
        description="""Adversary C2 Node #1""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-001.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-001.threat-infra.org",
        description="""Staged C2 Domain #1""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #1""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.3": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.3",
        description="""Adversary C2 Node #2""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-002.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-002.threat-infra.org",
        description="""Staged C2 Domain #2""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a002ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a002ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #2""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.4": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.4",
        description="""Adversary C2 Node #3""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-003.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-003.threat-infra.org",
        description="""Staged C2 Domain #3""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a003ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #3""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.5": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.5",
        description="""Adversary C2 Node #4""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-004.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-004.threat-infra.org",
        description="""Staged C2 Domain #4""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a004ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a004ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #4""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.6": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.6",
        description="""Adversary C2 Node #5""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-005.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-005.threat-infra.org",
        description="""Staged C2 Domain #5""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a005ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a005ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #5""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.7": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.7",
        description="""Adversary C2 Node #6""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-006.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-006.threat-infra.org",
        description="""Staged C2 Domain #6""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a006ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a006ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #6""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.8": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.8",
        description="""Adversary C2 Node #7""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-007.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-007.threat-infra.org",
        description="""Staged C2 Domain #7""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #7""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.9": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.9",
        description="""Adversary C2 Node #8""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-008.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-008.threat-infra.org",
        description="""Staged C2 Domain #8""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a008ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a008ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #8""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.10": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.10",
        description="""Adversary C2 Node #9""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-009.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-009.threat-infra.org",
        description="""Staged C2 Domain #9""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a009ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a009ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #9""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.11": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.11",
        description="""Adversary C2 Node #10""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-010.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-010.threat-infra.org",
        description="""Staged C2 Domain #10""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a010ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a010ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #10""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.12": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.12",
        description="""Adversary C2 Node #11""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-011.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-011.threat-infra.org",
        description="""Staged C2 Domain #11""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a011ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a011ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #11""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.13": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.13",
        description="""Adversary C2 Node #12""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-012.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-012.threat-infra.org",
        description="""Staged C2 Domain #12""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a012ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a012ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #12""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.14": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.14",
        description="""Adversary C2 Node #13""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-013.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-013.threat-infra.org",
        description="""Staged C2 Domain #13""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a013ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a013ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #13""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.15": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.15",
        description="""Adversary C2 Node #14""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-014.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-014.threat-infra.org",
        description="""Staged C2 Domain #14""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a014ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a014ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #14""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.16": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.16",
        description="""Adversary C2 Node #15""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-015.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-015.threat-infra.org",
        description="""Staged C2 Domain #15""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a015ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a015ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #15""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.17": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.17",
        description="""Adversary C2 Node #16""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-016.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-016.threat-infra.org",
        description="""Staged C2 Domain #16""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a016ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a016ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #16""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.18": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.18",
        description="""Adversary C2 Node #17""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-017.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-017.threat-infra.org",
        description="""Staged C2 Domain #17""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a017ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a017ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #17""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.19": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.19",
        description="""Adversary C2 Node #18""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-018.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-018.threat-infra.org",
        description="""Staged C2 Domain #18""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a018ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a018ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #18""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.20": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.20",
        description="""Adversary C2 Node #19""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-019.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-019.threat-infra.org",
        description="""Staged C2 Domain #19""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a019ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a019ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #19""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.21": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.21",
        description="""Adversary C2 Node #20""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-020.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-020.threat-infra.org",
        description="""Staged C2 Domain #20""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a020ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #20""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.22": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.22",
        description="""Adversary C2 Node #21""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-021.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-021.threat-infra.org",
        description="""Staged C2 Domain #21""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a021ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a021ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #21""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.23": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.23",
        description="""Adversary C2 Node #22""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-022.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-022.threat-infra.org",
        description="""Staged C2 Domain #22""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a022ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a022ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #22""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.24": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.24",
        description="""Adversary C2 Node #23""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-023.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-023.threat-infra.org",
        description="""Staged C2 Domain #23""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a023ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a023ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #23""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.25": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.25",
        description="""Adversary C2 Node #24""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-024.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-024.threat-infra.org",
        description="""Staged C2 Domain #24""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a024ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a024ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #24""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.26": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.26",
        description="""Adversary C2 Node #25""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-025.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-025.threat-infra.org",
        description="""Staged C2 Domain #25""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a025ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a025ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #25""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.27": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.27",
        description="""Adversary C2 Node #26""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-026.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-026.threat-infra.org",
        description="""Staged C2 Domain #26""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a026ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a026ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #26""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.28": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.28",
        description="""Adversary C2 Node #27""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-027.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-027.threat-infra.org",
        description="""Staged C2 Domain #27""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a027ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a027ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #27""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.29": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.29",
        description="""Adversary C2 Node #28""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-028.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-028.threat-infra.org",
        description="""Staged C2 Domain #28""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a028ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a028ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #28""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.30": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.30",
        description="""Adversary C2 Node #29""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-029.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-029.threat-infra.org",
        description="""Staged C2 Domain #29""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a029ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a029ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #29""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.31": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.31",
        description="""Adversary C2 Node #30""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-030.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-030.threat-infra.org",
        description="""Staged C2 Domain #30""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a030ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a030ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #30""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.32": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.32",
        description="""Adversary C2 Node #31""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-031.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-031.threat-infra.org",
        description="""Staged C2 Domain #31""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a031ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a031ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #31""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.33": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.33",
        description="""Adversary C2 Node #32""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-032.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-032.threat-infra.org",
        description="""Staged C2 Domain #32""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a032ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a032ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #32""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.34": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.34",
        description="""Adversary C2 Node #33""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-033.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-033.threat-infra.org",
        description="""Staged C2 Domain #33""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a033ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a033ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #33""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.35": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.35",
        description="""Adversary C2 Node #34""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-034.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-034.threat-infra.org",
        description="""Staged C2 Domain #34""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a034ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a034ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #34""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.36": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.36",
        description="""Adversary C2 Node #35""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-035.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-035.threat-infra.org",
        description="""Staged C2 Domain #35""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a035ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a035ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #35""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.37": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.37",
        description="""Adversary C2 Node #36""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-036.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-036.threat-infra.org",
        description="""Staged C2 Domain #36""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a036ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a036ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #36""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.38": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.38",
        description="""Adversary C2 Node #37""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-037.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-037.threat-infra.org",
        description="""Staged C2 Domain #37""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a037ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a037ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #37""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.39": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.39",
        description="""Adversary C2 Node #38""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-038.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-038.threat-infra.org",
        description="""Staged C2 Domain #38""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a038ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a038ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #38""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.40": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.40",
        description="""Adversary C2 Node #39""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-039.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-039.threat-infra.org",
        description="""Staged C2 Domain #39""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a039ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a039ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #39""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.41": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.41",
        description="""Adversary C2 Node #40""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-040.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-040.threat-infra.org",
        description="""Staged C2 Domain #40""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a040ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a040ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #40""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.42": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.42",
        description="""Adversary C2 Node #41""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-041.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-041.threat-infra.org",
        description="""Staged C2 Domain #41""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a041ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a041ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #41""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.43": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.43",
        description="""Adversary C2 Node #42""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-042.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-042.threat-infra.org",
        description="""Staged C2 Domain #42""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a042ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a042ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #42""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.44": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.44",
        description="""Adversary C2 Node #43""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-043.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-043.threat-infra.org",
        description="""Staged C2 Domain #43""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a043ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a043ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #43""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.45": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.45",
        description="""Adversary C2 Node #44""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-044.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-044.threat-infra.org",
        description="""Staged C2 Domain #44""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a044ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a044ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #44""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.46": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.46",
        description="""Adversary C2 Node #45""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-045.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-045.threat-infra.org",
        description="""Staged C2 Domain #45""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a045ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a045ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #45""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.47": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.47",
        description="""Adversary C2 Node #46""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-046.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-046.threat-infra.org",
        description="""Staged C2 Domain #46""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a046ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a046ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #46""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.48": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.48",
        description="""Adversary C2 Node #47""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-047.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-047.threat-infra.org",
        description="""Staged C2 Domain #47""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a047ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a047ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #47""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.49": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.49",
        description="""Adversary C2 Node #48""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-048.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-048.threat-infra.org",
        description="""Staged C2 Domain #48""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a048ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a048ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #48""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.50": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.50",
        description="""Adversary C2 Node #49""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-049.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-049.threat-infra.org",
        description="""Staged C2 Domain #49""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a049ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a049ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #49""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.51": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.51",
        description="""Adversary C2 Node #50""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-050.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-050.threat-infra.org",
        description="""Staged C2 Domain #50""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a050ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a050ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #50""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.52": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.52",
        description="""Adversary C2 Node #51""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-051.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-051.threat-infra.org",
        description="""Staged C2 Domain #51""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a051ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a051ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #51""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.53": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.53",
        description="""Adversary C2 Node #52""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-052.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-052.threat-infra.org",
        description="""Staged C2 Domain #52""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a052ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a052ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #52""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.54": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.54",
        description="""Adversary C2 Node #53""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-053.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-053.threat-infra.org",
        description="""Staged C2 Domain #53""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a053ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a053ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #53""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.55": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.55",
        description="""Adversary C2 Node #54""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-054.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-054.threat-infra.org",
        description="""Staged C2 Domain #54""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a054ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a054ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #54""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.56": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.56",
        description="""Adversary C2 Node #55""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-055.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-055.threat-infra.org",
        description="""Staged C2 Domain #55""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a055ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a055ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #55""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.57": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.57",
        description="""Adversary C2 Node #56""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-056.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-056.threat-infra.org",
        description="""Staged C2 Domain #56""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a056ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a056ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #56""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.58": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.58",
        description="""Adversary C2 Node #57""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-057.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-057.threat-infra.org",
        description="""Staged C2 Domain #57""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a057ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a057ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #57""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.59": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.59",
        description="""Adversary C2 Node #58""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-058.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-058.threat-infra.org",
        description="""Staged C2 Domain #58""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a058ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a058ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #58""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.60": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.60",
        description="""Adversary C2 Node #59""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-059.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-059.threat-infra.org",
        description="""Staged C2 Domain #59""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a059ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a059ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #59""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.61": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.61",
        description="""Adversary C2 Node #60""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-060.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-060.threat-infra.org",
        description="""Staged C2 Domain #60""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a060ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a060ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #60""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.62": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.62",
        description="""Adversary C2 Node #61""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-061.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-061.threat-infra.org",
        description="""Staged C2 Domain #61""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a061ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a061ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #61""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.63": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.63",
        description="""Adversary C2 Node #62""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-062.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-062.threat-infra.org",
        description="""Staged C2 Domain #62""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a062ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a062ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #62""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.64": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.64",
        description="""Adversary C2 Node #63""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-063.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-063.threat-infra.org",
        description="""Staged C2 Domain #63""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a063ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a063ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #63""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.65": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.65",
        description="""Adversary C2 Node #64""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-064.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-064.threat-infra.org",
        description="""Staged C2 Domain #64""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a064ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a064ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #64""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.66": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.66",
        description="""Adversary C2 Node #65""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-065.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-065.threat-infra.org",
        description="""Staged C2 Domain #65""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a065ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a065ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #65""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.67": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.67",
        description="""Adversary C2 Node #66""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-066.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-066.threat-infra.org",
        description="""Staged C2 Domain #66""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a066ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a066ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #66""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.68": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.68",
        description="""Adversary C2 Node #67""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-067.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-067.threat-infra.org",
        description="""Staged C2 Domain #67""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a067ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a067ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #67""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.69": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.69",
        description="""Adversary C2 Node #68""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-068.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-068.threat-infra.org",
        description="""Staged C2 Domain #68""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a068ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a068ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #68""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.70": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.70",
        description="""Adversary C2 Node #69""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-069.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-069.threat-infra.org",
        description="""Staged C2 Domain #69""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a069ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a069ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #69""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.71": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.71",
        description="""Adversary C2 Node #70""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-070.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-070.threat-infra.org",
        description="""Staged C2 Domain #70""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a070ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a070ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #70""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.72": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.72",
        description="""Adversary C2 Node #71""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-071.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-071.threat-infra.org",
        description="""Staged C2 Domain #71""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a071ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a071ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #71""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.73": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.73",
        description="""Adversary C2 Node #72""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-072.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-072.threat-infra.org",
        description="""Staged C2 Domain #72""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a072ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a072ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #72""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.74": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.74",
        description="""Adversary C2 Node #73""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-073.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-073.threat-infra.org",
        description="""Staged C2 Domain #73""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a073ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a073ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #73""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.75": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.75",
        description="""Adversary C2 Node #74""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-074.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-074.threat-infra.org",
        description="""Staged C2 Domain #74""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a074ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a074ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #74""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.76": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.76",
        description="""Adversary C2 Node #75""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-075.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-075.threat-infra.org",
        description="""Staged C2 Domain #75""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a075ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a075ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #75""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.77": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.77",
        description="""Adversary C2 Node #76""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-076.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-076.threat-infra.org",
        description="""Staged C2 Domain #76""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a076ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a076ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #76""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.78": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.78",
        description="""Adversary C2 Node #77""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-077.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-077.threat-infra.org",
        description="""Staged C2 Domain #77""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a077ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a077ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #77""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.79": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.79",
        description="""Adversary C2 Node #78""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-078.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-078.threat-infra.org",
        description="""Staged C2 Domain #78""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a078ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a078ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #78""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.80": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.80",
        description="""Adversary C2 Node #79""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-079.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-079.threat-infra.org",
        description="""Staged C2 Domain #79""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a079ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a079ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #79""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.81": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.81",
        description="""Adversary C2 Node #80""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-080.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-080.threat-infra.org",
        description="""Staged C2 Domain #80""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a080ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #80""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.82": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.82",
        description="""Adversary C2 Node #81""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-081.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-081.threat-infra.org",
        description="""Staged C2 Domain #81""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a081ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a081ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #81""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.83": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.83",
        description="""Adversary C2 Node #82""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-082.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-082.threat-infra.org",
        description="""Staged C2 Domain #82""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a082ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a082ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #82""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.84": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.84",
        description="""Adversary C2 Node #83""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-083.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-083.threat-infra.org",
        description="""Staged C2 Domain #83""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a083ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a083ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #83""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.85": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.85",
        description="""Adversary C2 Node #84""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-084.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-084.threat-infra.org",
        description="""Staged C2 Domain #84""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a084ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a084ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #84""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.86": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.86",
        description="""Adversary C2 Node #85""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-085.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-085.threat-infra.org",
        description="""Staged C2 Domain #85""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a085ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a085ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #85""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.87": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.87",
        description="""Adversary C2 Node #86""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-086.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-086.threat-infra.org",
        description="""Staged C2 Domain #86""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a086ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a086ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #86""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.88": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.88",
        description="""Adversary C2 Node #87""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-087.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-087.threat-infra.org",
        description="""Staged C2 Domain #87""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a087ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a087ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #87""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.89": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.89",
        description="""Adversary C2 Node #88""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-088.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-088.threat-infra.org",
        description="""Staged C2 Domain #88""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a088ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a088ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #88""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.90": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.90",
        description="""Adversary C2 Node #89""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-089.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-089.threat-infra.org",
        description="""Staged C2 Domain #89""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a089ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a089ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #89""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.91": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.91",
        description="""Adversary C2 Node #90""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-090.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-090.threat-infra.org",
        description="""Staged C2 Domain #90""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a090ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a090ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #90""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.92": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.92",
        description="""Adversary C2 Node #91""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-091.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-091.threat-infra.org",
        description="""Staged C2 Domain #91""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a091ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a091ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #91""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.93": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.93",
        description="""Adversary C2 Node #92""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-092.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-092.threat-infra.org",
        description="""Staged C2 Domain #92""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a092ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a092ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #92""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.94": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.94",
        description="""Adversary C2 Node #93""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-093.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-093.threat-infra.org",
        description="""Staged C2 Domain #93""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a093ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a093ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #93""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.95": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.95",
        description="""Adversary C2 Node #94""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-094.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-094.threat-infra.org",
        description="""Staged C2 Domain #94""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a094ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a094ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #94""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.96": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.96",
        description="""Adversary C2 Node #95""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-095.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-095.threat-infra.org",
        description="""Staged C2 Domain #95""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a095ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a095ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #95""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.97": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.97",
        description="""Adversary C2 Node #96""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-096.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-096.threat-infra.org",
        description="""Staged C2 Domain #96""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a096ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a096ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #96""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.98": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.98",
        description="""Adversary C2 Node #97""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-097.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-097.threat-infra.org",
        description="""Staged C2 Domain #97""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a097ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a097ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #97""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.99": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.99",
        description="""Adversary C2 Node #98""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-098.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-098.threat-infra.org",
        description="""Staged C2 Domain #98""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a098ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a098ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #98""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.100": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.100",
        description="""Adversary C2 Node #99""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-099.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-099.threat-infra.org",
        description="""Staged C2 Domain #99""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a099ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a099ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #99""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.101": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.101",
        description="""Adversary C2 Node #100""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-100.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-100.threat-infra.org",
        description="""Staged C2 Domain #100""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #100""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.102": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.102",
        description="""Adversary C2 Node #101""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-101.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-101.threat-infra.org",
        description="""Staged C2 Domain #101""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a101ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #101""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.103": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.103",
        description="""Adversary C2 Node #102""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-102.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-102.threat-infra.org",
        description="""Staged C2 Domain #102""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #102""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.104": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.104",
        description="""Adversary C2 Node #103""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-103.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-103.threat-infra.org",
        description="""Staged C2 Domain #103""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a103ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #103""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.105": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.105",
        description="""Adversary C2 Node #104""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-104.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-104.threat-infra.org",
        description="""Staged C2 Domain #104""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a104ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a104ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #104""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.106": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.106",
        description="""Adversary C2 Node #105""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-105.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-105.threat-infra.org",
        description="""Staged C2 Domain #105""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a105ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a105ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #105""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.107": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.107",
        description="""Adversary C2 Node #106""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-106.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-106.threat-infra.org",
        description="""Staged C2 Domain #106""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a106ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a106ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #106""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.108": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.108",
        description="""Adversary C2 Node #107""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-107.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-107.threat-infra.org",
        description="""Staged C2 Domain #107""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a107ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a107ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #107""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.109": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.109",
        description="""Adversary C2 Node #108""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-108.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-108.threat-infra.org",
        description="""Staged C2 Domain #108""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a108ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a108ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #108""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.110": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.110",
        description="""Adversary C2 Node #109""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-109.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-109.threat-infra.org",
        description="""Staged C2 Domain #109""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a109ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a109ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #109""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.111": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.111",
        description="""Adversary C2 Node #110""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-110.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-110.threat-infra.org",
        description="""Staged C2 Domain #110""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a110ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a110ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #110""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.112": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.112",
        description="""Adversary C2 Node #111""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-111.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-111.threat-infra.org",
        description="""Staged C2 Domain #111""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #111""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.113": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.113",
        description="""Adversary C2 Node #112""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-112.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-112.threat-infra.org",
        description="""Staged C2 Domain #112""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a112ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a112ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #112""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.114": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.114",
        description="""Adversary C2 Node #113""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-113.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-113.threat-infra.org",
        description="""Staged C2 Domain #113""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a113ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a113ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #113""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.115": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.115",
        description="""Adversary C2 Node #114""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-114.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-114.threat-infra.org",
        description="""Staged C2 Domain #114""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a114ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a114ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #114""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.116": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.116",
        description="""Adversary C2 Node #115""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-115.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-115.threat-infra.org",
        description="""Staged C2 Domain #115""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a115ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a115ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #115""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.117": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.117",
        description="""Adversary C2 Node #116""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-116.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-116.threat-infra.org",
        description="""Staged C2 Domain #116""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a116ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a116ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #116""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.118": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.118",
        description="""Adversary C2 Node #117""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-117.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-117.threat-infra.org",
        description="""Staged C2 Domain #117""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a117ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a117ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #117""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.119": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.119",
        description="""Adversary C2 Node #118""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-118.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-118.threat-infra.org",
        description="""Staged C2 Domain #118""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a118ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a118ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #118""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.120": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.120",
        description="""Adversary C2 Node #119""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-119.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-119.threat-infra.org",
        description="""Staged C2 Domain #119""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a119ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a119ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #119""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.121": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.121",
        description="""Adversary C2 Node #120""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-120.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-120.threat-infra.org",
        description="""Staged C2 Domain #120""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a120ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #120""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.122": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.122",
        description="""Adversary C2 Node #121""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-121.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-121.threat-infra.org",
        description="""Staged C2 Domain #121""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a121ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a121ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #121""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.123": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.123",
        description="""Adversary C2 Node #122""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-122.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-122.threat-infra.org",
        description="""Staged C2 Domain #122""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a122ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a122ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #122""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.124": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.124",
        description="""Adversary C2 Node #123""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-123.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-123.threat-infra.org",
        description="""Staged C2 Domain #123""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a123ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a123ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #123""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.125": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.125",
        description="""Adversary C2 Node #124""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-124.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-124.threat-infra.org",
        description="""Staged C2 Domain #124""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a124ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a124ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #124""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.126": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.126",
        description="""Adversary C2 Node #125""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-125.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-125.threat-infra.org",
        description="""Staged C2 Domain #125""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a125ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a125ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #125""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.127": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.127",
        description="""Adversary C2 Node #126""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-126.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-126.threat-infra.org",
        description="""Staged C2 Domain #126""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a126ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a126ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #126""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.128": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.128",
        description="""Adversary C2 Node #127""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-127.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-127.threat-infra.org",
        description="""Staged C2 Domain #127""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a127ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a127ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #127""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.129": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.129",
        description="""Adversary C2 Node #128""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-128.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-128.threat-infra.org",
        description="""Staged C2 Domain #128""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a128ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a128ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #128""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.130": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.130",
        description="""Adversary C2 Node #129""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-129.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-129.threat-infra.org",
        description="""Staged C2 Domain #129""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a129ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a129ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #129""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.131": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.131",
        description="""Adversary C2 Node #130""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-130.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-130.threat-infra.org",
        description="""Staged C2 Domain #130""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a130ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a130ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #130""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.132": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.132",
        description="""Adversary C2 Node #131""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-131.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-131.threat-infra.org",
        description="""Staged C2 Domain #131""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a131ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a131ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #131""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.133": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.133",
        description="""Adversary C2 Node #132""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-132.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-132.threat-infra.org",
        description="""Staged C2 Domain #132""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a132ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a132ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #132""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.134": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.134",
        description="""Adversary C2 Node #133""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-133.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-133.threat-infra.org",
        description="""Staged C2 Domain #133""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a133ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a133ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #133""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.135": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.135",
        description="""Adversary C2 Node #134""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-134.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-134.threat-infra.org",
        description="""Staged C2 Domain #134""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a134ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a134ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #134""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.136": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.136",
        description="""Adversary C2 Node #135""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-135.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-135.threat-infra.org",
        description="""Staged C2 Domain #135""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a135ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a135ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #135""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.137": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.137",
        description="""Adversary C2 Node #136""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-136.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-136.threat-infra.org",
        description="""Staged C2 Domain #136""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a136ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a136ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #136""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.138": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.138",
        description="""Adversary C2 Node #137""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-137.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-137.threat-infra.org",
        description="""Staged C2 Domain #137""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a137ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a137ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #137""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.139": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.139",
        description="""Adversary C2 Node #138""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-138.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-138.threat-infra.org",
        description="""Staged C2 Domain #138""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a138ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a138ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #138""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.140": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.140",
        description="""Adversary C2 Node #139""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-139.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-139.threat-infra.org",
        description="""Staged C2 Domain #139""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a139ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a139ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #139""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.141": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.141",
        description="""Adversary C2 Node #140""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-140.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-140.threat-infra.org",
        description="""Staged C2 Domain #140""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a140ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a140ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #140""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.142": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.142",
        description="""Adversary C2 Node #141""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-141.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-141.threat-infra.org",
        description="""Staged C2 Domain #141""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a141ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a141ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #141""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.143": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.143",
        description="""Adversary C2 Node #142""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-142.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-142.threat-infra.org",
        description="""Staged C2 Domain #142""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a142ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a142ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #142""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.144": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.144",
        description="""Adversary C2 Node #143""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-143.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-143.threat-infra.org",
        description="""Staged C2 Domain #143""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a143ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a143ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #143""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.145": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.145",
        description="""Adversary C2 Node #144""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-144.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-144.threat-infra.org",
        description="""Staged C2 Domain #144""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a144ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a144ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #144""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.146": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.146",
        description="""Adversary C2 Node #145""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-145.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-145.threat-infra.org",
        description="""Staged C2 Domain #145""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a145ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a145ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #145""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.147": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.147",
        description="""Adversary C2 Node #146""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-146.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-146.threat-infra.org",
        description="""Staged C2 Domain #146""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a146ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a146ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #146""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.148": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.148",
        description="""Adversary C2 Node #147""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-147.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-147.threat-infra.org",
        description="""Staged C2 Domain #147""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a147ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a147ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #147""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.149": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.149",
        description="""Adversary C2 Node #148""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-148.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-148.threat-infra.org",
        description="""Staged C2 Domain #148""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a148ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a148ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #148""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.150": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.150",
        description="""Adversary C2 Node #149""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-149.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-149.threat-infra.org",
        description="""Staged C2 Domain #149""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a149ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a149ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #149""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.151": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.151",
        description="""Adversary C2 Node #150""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-150.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-150.threat-infra.org",
        description="""Staged C2 Domain #150""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a150ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a150ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #150""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.152": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.152",
        description="""Adversary C2 Node #151""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-151.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-151.threat-infra.org",
        description="""Staged C2 Domain #151""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a151ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a151ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #151""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.153": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.153",
        description="""Adversary C2 Node #152""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-152.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-152.threat-infra.org",
        description="""Staged C2 Domain #152""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a152ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a152ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #152""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.154": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.154",
        description="""Adversary C2 Node #153""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-153.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-153.threat-infra.org",
        description="""Staged C2 Domain #153""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a153ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a153ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #153""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.155": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.155",
        description="""Adversary C2 Node #154""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-154.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-154.threat-infra.org",
        description="""Staged C2 Domain #154""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a154ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a154ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #154""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.156": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.156",
        description="""Adversary C2 Node #155""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-155.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-155.threat-infra.org",
        description="""Staged C2 Domain #155""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #155""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.157": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.157",
        description="""Adversary C2 Node #156""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-156.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-156.threat-infra.org",
        description="""Staged C2 Domain #156""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a156ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a156ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #156""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.158": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.158",
        description="""Adversary C2 Node #157""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-157.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-157.threat-infra.org",
        description="""Staged C2 Domain #157""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a157ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a157ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #157""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.159": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.159",
        description="""Adversary C2 Node #158""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-158.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-158.threat-infra.org",
        description="""Staged C2 Domain #158""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a158ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a158ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #158""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.160": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.160",
        description="""Adversary C2 Node #159""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-159.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-159.threat-infra.org",
        description="""Staged C2 Domain #159""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a159ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a159ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #159""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.161": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.161",
        description="""Adversary C2 Node #160""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-160.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-160.threat-infra.org",
        description="""Staged C2 Domain #160""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a160ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a160ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #160""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.162": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.162",
        description="""Adversary C2 Node #161""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-161.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-161.threat-infra.org",
        description="""Staged C2 Domain #161""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a161ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a161ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #161""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.163": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.163",
        description="""Adversary C2 Node #162""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-162.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-162.threat-infra.org",
        description="""Staged C2 Domain #162""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a162ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a162ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #162""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.164": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.164",
        description="""Adversary C2 Node #163""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-163.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-163.threat-infra.org",
        description="""Staged C2 Domain #163""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a163ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a163ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #163""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.165": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.165",
        description="""Adversary C2 Node #164""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-164.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-164.threat-infra.org",
        description="""Staged C2 Domain #164""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a164ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a164ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #164""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.166": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.166",
        description="""Adversary C2 Node #165""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-165.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-165.threat-infra.org",
        description="""Staged C2 Domain #165""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a165ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a165ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #165""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.167": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.167",
        description="""Adversary C2 Node #166""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-166.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-166.threat-infra.org",
        description="""Staged C2 Domain #166""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a166ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a166ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #166""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.168": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.168",
        description="""Adversary C2 Node #167""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-167.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-167.threat-infra.org",
        description="""Staged C2 Domain #167""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a167ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a167ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #167""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.169": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.169",
        description="""Adversary C2 Node #168""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-168.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-168.threat-infra.org",
        description="""Staged C2 Domain #168""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a168ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a168ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #168""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.170": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.170",
        description="""Adversary C2 Node #169""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-169.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-169.threat-infra.org",
        description="""Staged C2 Domain #169""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a169ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a169ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #169""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.171": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.171",
        description="""Adversary C2 Node #170""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-170.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-170.threat-infra.org",
        description="""Staged C2 Domain #170""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a170ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a170ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #170""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.172": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.172",
        description="""Adversary C2 Node #171""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-171.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-171.threat-infra.org",
        description="""Staged C2 Domain #171""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a171ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a171ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #171""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.173": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.173",
        description="""Adversary C2 Node #172""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-172.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-172.threat-infra.org",
        description="""Staged C2 Domain #172""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a172ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a172ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #172""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.174": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.174",
        description="""Adversary C2 Node #173""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-173.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-173.threat-infra.org",
        description="""Staged C2 Domain #173""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a173ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a173ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #173""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.175": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.175",
        description="""Adversary C2 Node #174""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-174.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-174.threat-infra.org",
        description="""Staged C2 Domain #174""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a174ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a174ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #174""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.176": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.176",
        description="""Adversary C2 Node #175""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-175.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-175.threat-infra.org",
        description="""Staged C2 Domain #175""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a175ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a175ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #175""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.177": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.177",
        description="""Adversary C2 Node #176""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-176.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-176.threat-infra.org",
        description="""Staged C2 Domain #176""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a176ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a176ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #176""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.178": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.178",
        description="""Adversary C2 Node #177""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-177.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-177.threat-infra.org",
        description="""Staged C2 Domain #177""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a177ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a177ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #177""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.179": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.179",
        description="""Adversary C2 Node #178""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-178.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-178.threat-infra.org",
        description="""Staged C2 Domain #178""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a178ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a178ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #178""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.180": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.180",
        description="""Adversary C2 Node #179""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-179.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-179.threat-infra.org",
        description="""Staged C2 Domain #179""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a179ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a179ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #179""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.181": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.181",
        description="""Adversary C2 Node #180""",
        confidence=80,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-180.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-180.threat-infra.org",
        description="""Staged C2 Domain #180""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a180ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a180ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #180""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.182": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.182",
        description="""Adversary C2 Node #181""",
        confidence=81,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-181.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-181.threat-infra.org",
        description="""Staged C2 Domain #181""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a181ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a181ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #181""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.183": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.183",
        description="""Adversary C2 Node #182""",
        confidence=82,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-182.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-182.threat-infra.org",
        description="""Staged C2 Domain #182""",
        confidence=84,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a182ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a182ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #182""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.184": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.184",
        description="""Adversary C2 Node #183""",
        confidence=83,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-183.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-183.threat-infra.org",
        description="""Staged C2 Domain #183""",
        confidence=85,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a183ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a183ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #183""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.185": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.185",
        description="""Adversary C2 Node #184""",
        confidence=84,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-184.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-184.threat-infra.org",
        description="""Staged C2 Domain #184""",
        confidence=86,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a184ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a184ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #184""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.186": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.186",
        description="""Adversary C2 Node #185""",
        confidence=85,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-185.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-185.threat-infra.org",
        description="""Staged C2 Domain #185""",
        confidence=87,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a185ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a185ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #185""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.187": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.187",
        description="""Adversary C2 Node #186""",
        confidence=86,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-186.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-186.threat-infra.org",
        description="""Staged C2 Domain #186""",
        confidence=88,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a186ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a186ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #186""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.188": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.188",
        description="""Adversary C2 Node #187""",
        confidence=87,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-187.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-187.threat-infra.org",
        description="""Staged C2 Domain #187""",
        confidence=89,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a187ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a187ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #187""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.189": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.189",
        description="""Adversary C2 Node #188""",
        confidence=88,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-188.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-188.threat-infra.org",
        description="""Staged C2 Domain #188""",
        confidence=90,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a188ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a188ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #188""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.190": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.190",
        description="""Adversary C2 Node #189""",
        confidence=89,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-189.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-189.threat-infra.org",
        description="""Staged C2 Domain #189""",
        confidence=91,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a189ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a189ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #189""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.191": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.191",
        description="""Adversary C2 Node #190""",
        confidence=90,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-190.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-190.threat-infra.org",
        description="""Staged C2 Domain #190""",
        confidence=92,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a190ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a190ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #190""",
        confidence=90,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.192": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.192",
        description="""Adversary C2 Node #191""",
        confidence=91,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-191.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-191.threat-infra.org",
        description="""Staged C2 Domain #191""",
        confidence=93,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a191ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a191ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #191""",
        confidence=91,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.193": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.193",
        description="""Adversary C2 Node #192""",
        confidence=92,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-192.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-192.threat-infra.org",
        description="""Staged C2 Domain #192""",
        confidence=94,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a192ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a192ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #192""",
        confidence=92,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.194": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.194",
        description="""Adversary C2 Node #193""",
        confidence=93,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-193.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-193.threat-infra.org",
        description="""Staged C2 Domain #193""",
        confidence=95,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a193ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a193ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #193""",
        confidence=93,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.195": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.195",
        description="""Adversary C2 Node #194""",
        confidence=94,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-194.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-194.threat-infra.org",
        description="""Staged C2 Domain #194""",
        confidence=96,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a194ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a194ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #194""",
        confidence=94,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.196": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.196",
        description="""Adversary C2 Node #195""",
        confidence=95,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-195.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-195.threat-infra.org",
        description="""Staged C2 Domain #195""",
        confidence=97,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a195ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a195ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #195""",
        confidence=95,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.197": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.197",
        description="""Adversary C2 Node #196""",
        confidence=96,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-196.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-196.threat-infra.org",
        description="""Staged C2 Domain #196""",
        confidence=98,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a196ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a196ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #196""",
        confidence=96,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.198": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.198",
        description="""Adversary C2 Node #197""",
        confidence=97,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-197.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-197.threat-infra.org",
        description="""Staged C2 Domain #197""",
        confidence=99,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a197ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a197ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #197""",
        confidence=97,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.199": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.199",
        description="""Adversary C2 Node #198""",
        confidence=98,
        associated_malware="Beacon-C2 Agent",
        associated_actor="APT28"
    ),
    "c2-gateway-stage-198.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-198.threat-infra.org",
        description="""Staged C2 Domain #198""",
        confidence=82,
        associated_malware="Sliver-Agent",
        associated_actor="Wizard Spider"
    ),
    "a198ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a198ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #198""",
        confidence=98,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
    "198.51.100.200": IndicatorOfCompromise(
        ioc_type=IocType.IPV4,
        value="198.51.100.200",
        description="""Adversary C2 Node #199""",
        confidence=99,
        associated_malware="Beacon-C2 Agent",
        associated_actor="Lazarus Group"
    ),
    "c2-gateway-stage-199.threat-infra.org": IndicatorOfCompromise(
        ioc_type=IocType.DOMAIN,
        value="c2-gateway-stage-199.threat-infra.org",
        description="""Staged C2 Domain #199""",
        confidence=83,
        associated_malware="Sliver-Agent",
        associated_actor="Volt Typhoon"
    ),
    "a199ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff": IndicatorOfCompromise(
        ioc_type=IocType.HASH_SHA256,
        value="a199ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        description="""Malicious Payload Variant #199""",
        confidence=99,
        associated_malware="Red-Stealer",
        associated_actor="FIN7"
    ),
}


class ThreatIntelligenceEngine:
    """High-throughput STIX 2.1 Threat Intelligence query and correlation engine."""

    @classmethod
    def lookup_ioc(cls, indicator_value: str) -> Optional[IndicatorOfCompromise]:
        clean_val = indicator_value.strip().lower()
        for val, ioc in IOC_CATALOG.items():
            if val.lower() == clean_val:
                return ioc
        return None

    @classmethod
    def get_actor_by_name(cls, name: str) -> Optional[ThreatActor]:
        name_lower = name.lower()
        for actor in THREAT_ACTORS_CATALOG.values():
            if actor.name.lower() == name_lower or any(name_lower == a.lower() for a in actor.aliases):
                return actor
        return None

    @classmethod
    def get_malware_by_name(cls, name: str) -> Optional[MalwareProfile]:
        name_lower = name.lower()
        for m in MALWARE_CATALOG.values():
            if name_lower in m.name.lower():
                return m
        return None

    @classmethod
    def search_iocs_by_actor(cls, actor_name: str) -> List[IndicatorOfCompromise]:
        act_lower = actor_name.lower()
        return [i for i in IOC_CATALOG.values() if act_lower in i.associated_actor.lower()]

    @classmethod
    def search_iocs_by_type(cls, ioc_type: IocType, min_confidence: int = 80) -> List[IndicatorOfCompromise]:
        return [i for i in IOC_CATALOG.values() if i.ioc_type == ioc_type and i.confidence >= min_confidence]

    @classmethod
    def export_stix_bundle(cls) -> Dict[str, Any]:
        stix_objects = []

        for a in THREAT_ACTORS_CATALOG.values():
            stix_objects.append({
                "type": "threat-actor",
                "spec_version": "2.1",
                "id": a.id,
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": a.name,
                "aliases": a.aliases,
                "threat_actor_types": [a.actor_type],
                "goals": [a.motivation]
            })

        for m in MALWARE_CATALOG.values():
            stix_objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": m.id,
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": m.name,
                "is_family": True,
                "malware_types": [m.malware_type]
            })

        for i in list(IOC_CATALOG.values())[:50]:
            stix_objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, i.value)}",
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2024-01-01T00:00:00.000Z",
                "name": f"Adversary Indicator {i.value}",
                "pattern": f"[{i.ioc_type.value}:value = '{i.value}']",
                "pattern_type": "stix",
                "valid_from": i.first_seen,
                "confidence": i.confidence
            })

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }

    @classmethod
    def get_threat_landscape_summary(cls) -> Dict[str, Any]:
        return {
            "threat_actors_count": len(THREAT_ACTORS_CATALOG),
            "malware_families_count": len(MALWARE_CATALOG),
            "total_iocs_tracked": len(IOC_CATALOG),
            "active_c2_ips": sum(1 for i in IOC_CATALOG.values() if i.ioc_type == IocType.IPV4),
            "malicious_domains": sum(1 for i in IOC_CATALOG.values() if i.ioc_type == IocType.DOMAIN),
            "malware_payload_hashes": sum(1 for i in IOC_CATALOG.values() if i.ioc_type == IocType.HASH_SHA256),
            "ja3_fingerprints": sum(1 for i in IOC_CATALOG.values() if i.ioc_type == IocType.JA3)
        }
