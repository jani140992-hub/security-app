"""
MITRE ATT&CK Enterprise Matrix & Knowledge Base Catalog.
Contains 14 tactics, full technique hierarchies, sub-techniques,
mitigations, and detection rules aligned with MITRE ATT&CK Enterprise Matrix.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any


class AttackTactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class TacticMetadata:
    id: str
    name: str
    description: str
    phase_order: int
    url: str


@dataclass
class TechniqueMitigation:
    mitigation_id: str
    name: str
    description: str
    control_type: str


@dataclass
class DetectionRuleTemplate:
    query_type: str
    query: str
    data_source: str
    log_event_id: Optional[str] = None


@dataclass
class AttackTechnique:
    id: str
    name: str
    tactic_id: str
    tactic_name: str
    description: str
    platforms: List[str]
    data_sources: List[str]
    permissions_required: List[str]
    mitigations: List[TechniqueMitigation]
    detection_rules: List[DetectionRuleTemplate]
    threat_actors: List[str]
    severity: SeverityLevel
    subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    cvss_score_impact: float = 7.5
    url: str = ""

    def __post_init__(self):
        if not self.url:
            self.url = f"https://attack.mitre.org/techniques/{self.id.replace('.', '/')}/"


TACTICS_CATALOG: Dict[str, TacticMetadata] = {
    "TA0043": TacticMetadata(
        id="TA0043",
        name="Reconnaissance",
        description="""The adversary is trying to gather information they can use to plan future operations.""",
        phase_order=1,
        url="https://attack.mitre.org/tactics/TA0043/"
    ),
    "TA0042": TacticMetadata(
        id="TA0042",
        name="Resource Development",
        description="""The adversary is trying to establish resources they can use to support operations.""",
        phase_order=2,
        url="https://attack.mitre.org/tactics/TA0042/"
    ),
    "TA0001": TacticMetadata(
        id="TA0001",
        name="Initial Access",
        description="""The adversary is trying to get into your enterprise network.""",
        phase_order=3,
        url="https://attack.mitre.org/tactics/TA0001/"
    ),
    "TA0002": TacticMetadata(
        id="TA0002",
        name="Execution",
        description="""The adversary is trying to run malicious code on internal hosts.""",
        phase_order=4,
        url="https://attack.mitre.org/tactics/TA0002/"
    ),
    "TA0003": TacticMetadata(
        id="TA0003",
        name="Persistence",
        description="""The adversary is trying to maintain their foothold across restarts and interruptions.""",
        phase_order=5,
        url="https://attack.mitre.org/tactics/TA0003/"
    ),
    "TA0004": TacticMetadata(
        id="TA0004",
        name="Privilege Escalation",
        description="""The adversary is trying to gain higher-level permissions (SYSTEM/Root).""",
        phase_order=6,
        url="https://attack.mitre.org/tactics/TA0004/"
    ),
    "TA0005": TacticMetadata(
        id="TA0005",
        name="Defense Evasion",
        description="""The adversary is trying to avoid detection by EDR, SIEM, and firewalls.""",
        phase_order=7,
        url="https://attack.mitre.org/tactics/TA0005/"
    ),
    "TA0006": TacticMetadata(
        id="TA0006",
        name="Credential Access",
        description="""The adversary is trying to steal account names, passwords, and Kerberos tickets.""",
        phase_order=8,
        url="https://attack.mitre.org/tactics/TA0006/"
    ),
    "TA0007": TacticMetadata(
        id="TA0007",
        name="Discovery",
        description="""The adversary is trying to observe and map the internal environment.""",
        phase_order=9,
        url="https://attack.mitre.org/tactics/TA0007/"
    ),
    "TA0008": TacticMetadata(
        id="TA0008",
        name="Lateral Movement",
        description="""The adversary is trying to pivot through your internal network.""",
        phase_order=10,
        url="https://attack.mitre.org/tactics/TA0008/"
    ),
    "TA0009": TacticMetadata(
        id="TA0009",
        name="Collection",
        description="""The adversary is trying to gather sensitive business data of interest.""",
        phase_order=11,
        url="https://attack.mitre.org/tactics/TA0009/"
    ),
    "TA0011": TacticMetadata(
        id="TA0011",
        name="Command and Control",
        description="""The adversary is trying to communicate with compromised systems.""",
        phase_order=12,
        url="https://attack.mitre.org/tactics/TA0011/"
    ),
    "TA0010": TacticMetadata(
        id="TA0010",
        name="Exfiltration",
        description="""The adversary is trying to steal and transmit confidential data outside.""",
        phase_order=13,
        url="https://attack.mitre.org/tactics/TA0010/"
    ),
    "TA0040": TacticMetadata(
        id="TA0040",
        name="Impact",
        description="""The adversary is trying to manipulate, interrupt, or destroy systems and critical data.""",
        phase_order=14,
        url="https://attack.mitre.org/tactics/TA0040/"
    ),
}

TECHNIQUES_CATALOG: Dict[str, AttackTechnique] = {
    "T1595": AttackTechnique(
        id="T1595",
        name="Active Scanning",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Active Scanning (T1595) during the Reconnaissance phase to advance compromises across Network, External. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Network', 'External'],
        data_sources=['Network Traffic: Network Traffic Flow'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1001",
                name="Hardening & Prevention for Active Scanning",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2001",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Active Scanning -- selection CommandLine contains T1595",
                data_source="Network Traffic: Network Traffic Flow",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1595",
                data_source="Network Traffic: Network Traffic Flow",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team', 'Volt Typhoon'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1595.001": AttackTechnique(
        id="T1595.001",
        name="Active Scanning: Process Memory Hollowing",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Active Scanning: Process Memory Hollowing (T1595.001) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Process: Process Modification", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300101",
                name="Subtechnique Mitigation T1595.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Active Scanning: Process Memory Hollowing -- condition selection CommandLine contains T1595.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1595.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1595",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1595.002": AttackTechnique(
        id="T1595.002",
        name="Active Scanning: Windows Access Token Theft",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Active Scanning: Windows Access Token Theft (T1595.002) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Token: Token Impersonation", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300102",
                name="Subtechnique Mitigation T1595.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Active Scanning: Windows Access Token Theft -- condition selection CommandLine contains T1595.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1595.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1595",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1595.003": AttackTechnique(
        id="T1595.003",
        name="Active Scanning: NTLM Hash Pass-Through Replay",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Active Scanning: NTLM Hash Pass-Through Replay (T1595.003) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300103",
                name="Subtechnique Mitigation T1595.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Active Scanning: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1595.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1595.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1595",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1595.004": AttackTechnique(
        id="T1595.004",
        name="Active Scanning: Active Directory Kerberoasting",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Active Scanning: Active Directory Kerberoasting (T1595.004) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300104",
                name="Subtechnique Mitigation T1595.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Active Scanning: Active Directory Kerberoasting -- condition selection CommandLine contains T1595.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1595.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1595",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1592": AttackTechnique(
        id="T1592",
        name="Gather Victim Host Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Host Information (T1592) during the Reconnaissance phase to advance compromises across Hardware, Network. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Hardware', 'Network'],
        data_sources=['Application Log: Application Web Logs'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1002",
                name="Hardening & Prevention for Gather Victim Host Information",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2002",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Host Information -- selection CommandLine contains T1592",
                data_source="Application Log: Application Web Logs",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1592",
                data_source="Application Log: Application Web Logs",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1592.001": AttackTechnique(
        id="T1592.001",
        name="Gather Victim Host Information: Kerberos AS-REP Roasting",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Host Information: Kerberos AS-REP Roasting (T1592.001) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Hardware', 'Network'],
        data_sources=["Active Directory: Kerberos Request", "Application Log: Application Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300201",
                name="Subtechnique Mitigation T1592.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Host Information: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1592.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1592.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1592",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1592.002": AttackTechnique(
        id="T1592.002",
        name="Gather Victim Host Information: Active Directory Golden Ticket",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Host Information: Active Directory Golden Ticket (T1592.002) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Hardware', 'Network'],
        data_sources=["Authentication: User Authentication", "Application Log: Application Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300202",
                name="Subtechnique Mitigation T1592.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Host Information: Active Directory Golden Ticket -- condition selection CommandLine contains T1592.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1592.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1592",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1592.003": AttackTechnique(
        id="T1592.003",
        name="Gather Victim Host Information: Kerberos Service Silver Ticket",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Host Information: Kerberos Service Silver Ticket (T1592.003) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Hardware', 'Network'],
        data_sources=["Authentication: User Authentication", "Application Log: Application Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300203",
                name="Subtechnique Mitigation T1592.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Host Information: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1592.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1592.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1592",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1592.004": AttackTechnique(
        id="T1592.004",
        name="Gather Victim Host Information: VSS Volume Shadow Deletion",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Host Information: VSS Volume Shadow Deletion (T1592.004) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Hardware', 'Network'],
        data_sources=["Process: Process Creation", "Application Log: Application Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300204",
                name="Subtechnique Mitigation T1592.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Host Information: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1592.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1592.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1592",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1589": AttackTechnique(
        id="T1589",
        name="Gather Victim Identity Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Identity Information (T1589) during the Reconnaissance phase to advance compromises across Cloud, External. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Cloud', 'External'],
        data_sources=['Identity: Credential Token'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1003",
                name="Hardening & Prevention for Gather Victim Identity Information",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2003",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Identity Information -- selection CommandLine contains T1589",
                data_source="Identity: Credential Token",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1589",
                data_source="Identity: Credential Token",
                log_event_id="1"
            )
        ],
        threat_actors=['Scattered Spider', 'FIN7'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1589.001": AttackTechnique(
        id="T1589.001",
        name="Gather Victim Identity Information: Boot Configuration Tampering",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Identity Information: Boot Configuration Tampering (T1589.001) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Process: Process Creation", "Identity: Credential Token"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300301",
                name="Subtechnique Mitigation T1589.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Identity Information: Boot Configuration Tampering -- condition selection CommandLine contains T1589.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1589.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Scattered Spider', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1589",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1589.002": AttackTechnique(
        id="T1589.002",
        name="Gather Victim Identity Information: High-Entropy AES Cryptor Loop",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Identity Information: High-Entropy AES Cryptor Loop (T1589.002) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["File: File Modification", "Identity: Credential Token"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300302",
                name="Subtechnique Mitigation T1589.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Identity Information: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1589.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1589.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['Scattered Spider', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1589",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1589.003": AttackTechnique(
        id="T1589.003",
        name="Gather Victim Identity Information: Audit Log Eviction and Shred",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Identity Information: Audit Log Eviction and Shred (T1589.003) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Command: Command Execution", "Identity: Credential Token"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300303",
                name="Subtechnique Mitigation T1589.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Identity Information: Audit Log Eviction and Shred -- condition selection CommandLine contains T1589.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1589.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['Scattered Spider', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1589",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1589.004": AttackTechnique(
        id="T1589.004",
        name="Gather Victim Identity Information: IAM Role Policy Assumption",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Identity Information: IAM Role Policy Assumption (T1589.004) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Cloud Audit: CloudTrail", "Identity: Credential Token"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300304",
                name="Subtechnique Mitigation T1589.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Identity Information: IAM Role Policy Assumption -- condition selection CommandLine contains T1589.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1589.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['Scattered Spider', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1589",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1590": AttackTechnique(
        id="T1590",
        name="Gather Victim Network Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Network Information (T1590) during the Reconnaissance phase to advance compromises across Network, External. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Network', 'External'],
        data_sources=['Network Traffic: DNS Query'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1004",
                name="Hardening & Prevention for Gather Victim Network Information",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2004",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Network Information -- selection CommandLine contains T1590",
                data_source="Network Traffic: DNS Query",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1590",
                data_source="Network Traffic: DNS Query",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'MuddyWater'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1590.001": AttackTechnique(
        id="T1590.001",
        name="Gather Victim Network Information: S3 Storage Mass Data Extraction",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Network Information: S3 Storage Mass Data Extraction (T1590.001) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Cloud Audit: CloudTrail", "Network Traffic: DNS Query"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300401",
                name="Subtechnique Mitigation T1590.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Network Information: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1590.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1590.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT33', 'MuddyWater'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1590",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1590.002": AttackTechnique(
        id="T1590.002",
        name="Gather Victim Network Information: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Network Information: Kubernetes Host PID Namespace Escape (T1590.002) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Container: Container Creation", "Network Traffic: DNS Query"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300402",
                name="Subtechnique Mitigation T1590.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Network Information: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1590.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1590.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT33', 'MuddyWater'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1590",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1590.003": AttackTechnique(
        id="T1590.003",
        name="Gather Victim Network Information: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Network Information: Asynchronous DNS TXT Data Exfil (T1590.003) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Network Traffic: DNS Query", "Network Traffic: DNS Query"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300403",
                name="Subtechnique Mitigation T1590.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Network Information: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1590.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1590.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT33', 'MuddyWater'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1590",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1590.004": AttackTechnique(
        id="T1590.004",
        name="Gather Victim Network Information: PowerShell Execution Architecture",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Gather Victim Network Information: PowerShell Execution Architecture (T1590.004) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'External'],
        data_sources=["Process: Process Creation", "Network Traffic: DNS Query"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300404",
                name="Subtechnique Mitigation T1590.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Gather Victim Network Information: PowerShell Execution Architecture -- condition selection CommandLine contains T1590.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1590.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT33', 'MuddyWater'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1590",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1598": AttackTechnique(
        id="T1598",
        name="Phishing for Information",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Phishing for Information (T1598) during the Reconnaissance phase to advance compromises across External, Email. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['External', 'Email'],
        data_sources=['Application Log: Email Logs'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1005",
                name="Hardening & Prevention for Phishing for Information",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2005",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing for Information -- selection CommandLine contains T1598",
                data_source="Application Log: Email Logs",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1598",
                data_source="Application Log: Email Logs",
                log_event_id="1"
            )
        ],
        threat_actors=['Gamaredon Group', 'Kimsuky'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1598.001": AttackTechnique(
        id="T1598.001",
        name="Phishing for Information: Command Prompt Batch Chaining",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Phishing for Information: Command Prompt Batch Chaining (T1598.001) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['External', 'Email'],
        data_sources=["Process: Process Creation", "Application Log: Email Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300501",
                name="Subtechnique Mitigation T1598.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing for Information: Command Prompt Batch Chaining -- condition selection CommandLine contains T1598.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1598.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['Gamaredon Group', 'Kimsuky'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1598",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1598.002": AttackTechnique(
        id="T1598.002",
        name="Phishing for Information: Unix Shell Staged Pipeline",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Phishing for Information: Unix Shell Staged Pipeline (T1598.002) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['External', 'Email'],
        data_sources=["Process: Process Creation", "Application Log: Email Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300502",
                name="Subtechnique Mitigation T1598.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing for Information: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1598.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1598.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['Gamaredon Group', 'Kimsuky'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1598",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1598.003": AttackTechnique(
        id="T1598.003",
        name="Phishing for Information: Python Direct Socket Shellcode",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Phishing for Information: Python Direct Socket Shellcode (T1598.003) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['External', 'Email'],
        data_sources=["Process: Process Creation", "Application Log: Email Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300503",
                name="Subtechnique Mitigation T1598.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing for Information: Python Direct Socket Shellcode -- condition selection CommandLine contains T1598.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1598.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['Gamaredon Group', 'Kimsuky'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1598",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1598.004": AttackTechnique(
        id="T1598.004",
        name="Phishing for Information: DLL Search Order Hijacking",
        tactic_id="TA0043",
        tactic_name="Reconnaissance",
        description="""Adversaries execute Phishing for Information: DLL Search Order Hijacking (T1598.004) during Reconnaissance. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['External', 'Email'],
        data_sources=["Module: Module Load", "Application Log: Email Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300504",
                name="Subtechnique Mitigation T1598.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing for Information: DLL Search Order Hijacking -- condition selection CommandLine contains T1598.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1598.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['Gamaredon Group', 'Kimsuky'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1598",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1583": AttackTechnique(
        id="T1583",
        name="Acquire Infrastructure",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Acquire Infrastructure (T1583) during the Resource Development phase to advance compromises across Cloud, External. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Cloud', 'External'],
        data_sources=['Cloud Audit: Cloud Infrastructure'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1006",
                name="Hardening & Prevention for Acquire Infrastructure",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2006",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Acquire Infrastructure -- selection CommandLine contains T1583",
                data_source="Cloud Audit: Cloud Infrastructure",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1583",
                data_source="Cloud Audit: Cloud Infrastructure",
                log_event_id="1"
            )
        ],
        threat_actors=['Lazarus Group', 'APT28'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1583.001": AttackTechnique(
        id="T1583.001",
        name="Acquire Infrastructure: Process Memory Hollowing",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Acquire Infrastructure: Process Memory Hollowing (T1583.001) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Process: Process Modification", "Cloud Audit: Cloud Infrastructure"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300601",
                name="Subtechnique Mitigation T1583.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Acquire Infrastructure: Process Memory Hollowing -- condition selection CommandLine contains T1583.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1583.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['Lazarus Group', 'APT28'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1583",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1583.002": AttackTechnique(
        id="T1583.002",
        name="Acquire Infrastructure: Windows Access Token Theft",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Acquire Infrastructure: Windows Access Token Theft (T1583.002) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Token: Token Impersonation", "Cloud Audit: Cloud Infrastructure"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300602",
                name="Subtechnique Mitigation T1583.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Acquire Infrastructure: Windows Access Token Theft -- condition selection CommandLine contains T1583.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1583.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['Lazarus Group', 'APT28'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1583",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1583.003": AttackTechnique(
        id="T1583.003",
        name="Acquire Infrastructure: NTLM Hash Pass-Through Replay",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Acquire Infrastructure: NTLM Hash Pass-Through Replay (T1583.003) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Authentication: User Authentication", "Cloud Audit: Cloud Infrastructure"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300603",
                name="Subtechnique Mitigation T1583.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Acquire Infrastructure: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1583.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1583.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['Lazarus Group', 'APT28'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1583",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1583.004": AttackTechnique(
        id="T1583.004",
        name="Acquire Infrastructure: Active Directory Kerberoasting",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Acquire Infrastructure: Active Directory Kerberoasting (T1583.004) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Active Directory: Kerberos Request", "Cloud Audit: Cloud Infrastructure"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300604",
                name="Subtechnique Mitigation T1583.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Acquire Infrastructure: Active Directory Kerberoasting -- condition selection CommandLine contains T1583.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1583.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['Lazarus Group', 'APT28'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1583",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1584": AttackTechnique(
        id="T1584",
        name="Compromise Infrastructure",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Compromise Infrastructure (T1584) during the Resource Development phase to advance compromises across Network, DNS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Network', 'DNS'],
        data_sources=['Network Traffic: Domain Name'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1007",
                name="Hardening & Prevention for Compromise Infrastructure",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2007",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Compromise Infrastructure -- selection CommandLine contains T1584",
                data_source="Network Traffic: Domain Name",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1584",
                data_source="Network Traffic: Domain Name",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1584.001": AttackTechnique(
        id="T1584.001",
        name="Compromise Infrastructure: Kerberos AS-REP Roasting",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Compromise Infrastructure: Kerberos AS-REP Roasting (T1584.001) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'DNS'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: Domain Name"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300701",
                name="Subtechnique Mitigation T1584.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Compromise Infrastructure: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1584.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1584.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1584",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1584.002": AttackTechnique(
        id="T1584.002",
        name="Compromise Infrastructure: Active Directory Golden Ticket",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Compromise Infrastructure: Active Directory Golden Ticket (T1584.002) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'DNS'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Domain Name"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300702",
                name="Subtechnique Mitigation T1584.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Compromise Infrastructure: Active Directory Golden Ticket -- condition selection CommandLine contains T1584.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1584.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1584",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1584.003": AttackTechnique(
        id="T1584.003",
        name="Compromise Infrastructure: Kerberos Service Silver Ticket",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Compromise Infrastructure: Kerberos Service Silver Ticket (T1584.003) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'DNS'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Domain Name"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300703",
                name="Subtechnique Mitigation T1584.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Compromise Infrastructure: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1584.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1584.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1584",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1584.004": AttackTechnique(
        id="T1584.004",
        name="Compromise Infrastructure: VSS Volume Shadow Deletion",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Compromise Infrastructure: VSS Volume Shadow Deletion (T1584.004) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Network', 'DNS'],
        data_sources=["Process: Process Creation", "Network Traffic: Domain Name"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300704",
                name="Subtechnique Mitigation T1584.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Compromise Infrastructure: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1584.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1584.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1584",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1585": AttackTechnique(
        id="T1585",
        name="Establish Accounts",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Establish Accounts (T1585) during the Resource Development phase to advance compromises across Cloud, External. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Cloud', 'External'],
        data_sources=['Identity: Account Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1008",
                name="Hardening & Prevention for Establish Accounts",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2008",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Establish Accounts -- selection CommandLine contains T1585",
                data_source="Identity: Account Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1585",
                data_source="Identity: Account Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1585.001": AttackTechnique(
        id="T1585.001",
        name="Establish Accounts: Boot Configuration Tampering",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Establish Accounts: Boot Configuration Tampering (T1585.001) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Process: Process Creation", "Identity: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300801",
                name="Subtechnique Mitigation T1585.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Establish Accounts: Boot Configuration Tampering -- condition selection CommandLine contains T1585.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1585.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1585",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1585.002": AttackTechnique(
        id="T1585.002",
        name="Establish Accounts: High-Entropy AES Cryptor Loop",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Establish Accounts: High-Entropy AES Cryptor Loop (T1585.002) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["File: File Modification", "Identity: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300802",
                name="Subtechnique Mitigation T1585.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Establish Accounts: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1585.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1585.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1585",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1585.003": AttackTechnique(
        id="T1585.003",
        name="Establish Accounts: Audit Log Eviction and Shred",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Establish Accounts: Audit Log Eviction and Shred (T1585.003) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Command: Command Execution", "Identity: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300803",
                name="Subtechnique Mitigation T1585.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Establish Accounts: Audit Log Eviction and Shred -- condition selection CommandLine contains T1585.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1585.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1585",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1585.004": AttackTechnique(
        id="T1585.004",
        name="Establish Accounts: IAM Role Policy Assumption",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Establish Accounts: IAM Role Policy Assumption (T1585.004) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'External'],
        data_sources=["Cloud Audit: CloudTrail", "Identity: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300804",
                name="Subtechnique Mitigation T1585.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Establish Accounts: IAM Role Policy Assumption -- condition selection CommandLine contains T1585.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1585.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1585",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1587": AttackTechnique(
        id="T1587",
        name="Develop Capabilities",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Develop Capabilities (T1587) during the Resource Development phase to advance compromises across File, Software. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['File', 'Software'],
        data_sources=['File: File Metadata'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1009",
                name="Hardening & Prevention for Develop Capabilities",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2009",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Develop Capabilities -- selection CommandLine contains T1587",
                data_source="File: File Metadata",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1587",
                data_source="File: File Metadata",
                log_event_id="1"
            )
        ],
        threat_actors=['DarkSide', 'BlackCat'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1587.001": AttackTechnique(
        id="T1587.001",
        name="Develop Capabilities: S3 Storage Mass Data Extraction",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Develop Capabilities: S3 Storage Mass Data Extraction (T1587.001) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['File', 'Software'],
        data_sources=["Cloud Audit: CloudTrail", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300901",
                name="Subtechnique Mitigation T1587.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Develop Capabilities: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1587.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1587.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['DarkSide', 'BlackCat'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1587",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1587.002": AttackTechnique(
        id="T1587.002",
        name="Develop Capabilities: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Develop Capabilities: Kubernetes Host PID Namespace Escape (T1587.002) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['File', 'Software'],
        data_sources=["Container: Container Creation", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300902",
                name="Subtechnique Mitigation T1587.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Develop Capabilities: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1587.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1587.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['DarkSide', 'BlackCat'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1587",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1587.003": AttackTechnique(
        id="T1587.003",
        name="Develop Capabilities: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Develop Capabilities: Asynchronous DNS TXT Data Exfil (T1587.003) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['File', 'Software'],
        data_sources=["Network Traffic: DNS Query", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300903",
                name="Subtechnique Mitigation T1587.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Develop Capabilities: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1587.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1587.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['DarkSide', 'BlackCat'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1587",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1587.004": AttackTechnique(
        id="T1587.004",
        name="Develop Capabilities: PowerShell Execution Architecture",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Develop Capabilities: PowerShell Execution Architecture (T1587.004) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['File', 'Software'],
        data_sources=["Process: Process Creation", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M300904",
                name="Subtechnique Mitigation T1587.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M400904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Develop Capabilities: PowerShell Execution Architecture -- condition selection CommandLine contains T1587.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1587.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['DarkSide', 'BlackCat'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1587",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1588": AttackTechnique(
        id="T1588",
        name="Obtain Capabilities",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Obtain Capabilities (T1588) during the Resource Development phase to advance compromises across Software, Tools. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Software', 'Tools'],
        data_sources=['Vulnerability: Exploit Kit'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1010",
                name="Hardening & Prevention for Obtain Capabilities",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2010",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obtain Capabilities -- selection CommandLine contains T1588",
                data_source="Vulnerability: Exploit Kit",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1588",
                data_source="Vulnerability: Exploit Kit",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1588.001": AttackTechnique(
        id="T1588.001",
        name="Obtain Capabilities: Command Prompt Batch Chaining",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Obtain Capabilities: Command Prompt Batch Chaining (T1588.001) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Software', 'Tools'],
        data_sources=["Process: Process Creation", "Vulnerability: Exploit Kit"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301001",
                name="Subtechnique Mitigation T1588.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obtain Capabilities: Command Prompt Batch Chaining -- condition selection CommandLine contains T1588.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1588.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT29', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1588",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1588.002": AttackTechnique(
        id="T1588.002",
        name="Obtain Capabilities: Unix Shell Staged Pipeline",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Obtain Capabilities: Unix Shell Staged Pipeline (T1588.002) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Software', 'Tools'],
        data_sources=["Process: Process Creation", "Vulnerability: Exploit Kit"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301002",
                name="Subtechnique Mitigation T1588.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obtain Capabilities: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1588.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1588.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT29', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1588",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1588.003": AttackTechnique(
        id="T1588.003",
        name="Obtain Capabilities: Python Direct Socket Shellcode",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Obtain Capabilities: Python Direct Socket Shellcode (T1588.003) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Software', 'Tools'],
        data_sources=["Process: Process Creation", "Vulnerability: Exploit Kit"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301003",
                name="Subtechnique Mitigation T1588.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obtain Capabilities: Python Direct Socket Shellcode -- condition selection CommandLine contains T1588.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1588.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT29', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1588",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1588.004": AttackTechnique(
        id="T1588.004",
        name="Obtain Capabilities: DLL Search Order Hijacking",
        tactic_id="TA0042",
        tactic_name="Resource Development",
        description="""Adversaries execute Obtain Capabilities: DLL Search Order Hijacking (T1588.004) during Resource Development. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Software', 'Tools'],
        data_sources=["Module: Module Load", "Vulnerability: Exploit Kit"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301004",
                name="Subtechnique Mitigation T1588.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obtain Capabilities: DLL Search Order Hijacking -- condition selection CommandLine contains T1588.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1588.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT29', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1588",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1189": AttackTechnique(
        id="T1189",
        name="Drive-by Compromise",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Drive-by Compromise (T1189) during the Initial Access phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Network Traffic: Content', 'Application Log: Web'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1011",
                name="Hardening & Prevention for Drive-by Compromise",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2011",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Drive-by Compromise -- selection CommandLine contains T1189",
                data_source="Network Traffic: Content",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1189",
                data_source="Network Traffic: Content",
                log_event_id="1"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1189.001": AttackTechnique(
        id="T1189.001",
        name="Drive-by Compromise: Process Memory Hollowing",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Drive-by Compromise: Process Memory Hollowing (T1189.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Modification", "Network Traffic: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301101",
                name="Subtechnique Mitigation T1189.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Drive-by Compromise: Process Memory Hollowing -- condition selection CommandLine contains T1189.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1189.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1189",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1189.002": AttackTechnique(
        id="T1189.002",
        name="Drive-by Compromise: Windows Access Token Theft",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Drive-by Compromise: Windows Access Token Theft (T1189.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Token: Token Impersonation", "Network Traffic: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301102",
                name="Subtechnique Mitigation T1189.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Drive-by Compromise: Windows Access Token Theft -- condition selection CommandLine contains T1189.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1189.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1189",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1189.003": AttackTechnique(
        id="T1189.003",
        name="Drive-by Compromise: NTLM Hash Pass-Through Replay",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Drive-by Compromise: NTLM Hash Pass-Through Replay (T1189.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301103",
                name="Subtechnique Mitigation T1189.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Drive-by Compromise: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1189.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1189.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1189",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1189.004": AttackTechnique(
        id="T1189.004",
        name="Drive-by Compromise: Active Directory Kerberoasting",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Drive-by Compromise: Active Directory Kerberoasting (T1189.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301104",
                name="Subtechnique Mitigation T1189.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Drive-by Compromise: Active Directory Kerberoasting -- condition selection CommandLine contains T1189.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1189.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1189",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1190": AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Exploit Public-Facing Application (T1190) during the Initial Access phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['Application Log: Web Logs', 'Network Traffic: Flow'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1012",
                name="Hardening & Prevention for Exploit Public-Facing Application",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2012",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploit Public-Facing Application -- selection CommandLine contains T1190",
                data_source="Application Log: Web Logs",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1190",
                data_source="Application Log: Web Logs",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1190.001": AttackTechnique(
        id="T1190.001",
        name="Exploit Public-Facing Application: Kerberos AS-REP Roasting",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Exploit Public-Facing Application: Kerberos AS-REP Roasting (T1190.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Active Directory: Kerberos Request", "Application Log: Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301201",
                name="Subtechnique Mitigation T1190.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploit Public-Facing Application: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1190.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1190.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1190",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1190.002": AttackTechnique(
        id="T1190.002",
        name="Exploit Public-Facing Application: Active Directory Golden Ticket",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Exploit Public-Facing Application: Active Directory Golden Ticket (T1190.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Authentication: User Authentication", "Application Log: Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301202",
                name="Subtechnique Mitigation T1190.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploit Public-Facing Application: Active Directory Golden Ticket -- condition selection CommandLine contains T1190.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1190.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1190",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1190.003": AttackTechnique(
        id="T1190.003",
        name="Exploit Public-Facing Application: Kerberos Service Silver Ticket",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Exploit Public-Facing Application: Kerberos Service Silver Ticket (T1190.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Authentication: User Authentication", "Application Log: Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301203",
                name="Subtechnique Mitigation T1190.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploit Public-Facing Application: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1190.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1190.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Volt Typhoon'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1190",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1190.004": AttackTechnique(
        id="T1190.004",
        name="Exploit Public-Facing Application: VSS Volume Shadow Deletion",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Exploit Public-Facing Application: VSS Volume Shadow Deletion (T1190.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "Application Log: Web Logs"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301204",
                name="Subtechnique Mitigation T1190.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploit Public-Facing Application: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1190.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1190.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Volt Typhoon'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1190",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1133": AttackTechnique(
        id="T1133",
        name="External Remote Services",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute External Remote Services (T1133) during the Initial Access phase to advance compromises across Windows, Linux, Network. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Network'],
        data_sources=['Logon Session: Creation', 'Authentication: User'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1013",
                name="Hardening & Prevention for External Remote Services",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2013",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect External Remote Services -- selection CommandLine contains T1133",
                data_source="Logon Session: Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1133",
                data_source="Logon Session: Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1133.001": AttackTechnique(
        id="T1133.001",
        name="External Remote Services: Boot Configuration Tampering",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute External Remote Services: Boot Configuration Tampering (T1133.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Network'],
        data_sources=["Process: Process Creation", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301301",
                name="Subtechnique Mitigation T1133.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect External Remote Services: Boot Configuration Tampering -- condition selection CommandLine contains T1133.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1133.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1133",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1133.002": AttackTechnique(
        id="T1133.002",
        name="External Remote Services: High-Entropy AES Cryptor Loop",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute External Remote Services: High-Entropy AES Cryptor Loop (T1133.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Network'],
        data_sources=["File: File Modification", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301302",
                name="Subtechnique Mitigation T1133.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect External Remote Services: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1133.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1133.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1133",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1133.003": AttackTechnique(
        id="T1133.003",
        name="External Remote Services: Audit Log Eviction and Shred",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute External Remote Services: Audit Log Eviction and Shred (T1133.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Network'],
        data_sources=["Command: Command Execution", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301303",
                name="Subtechnique Mitigation T1133.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect External Remote Services: Audit Log Eviction and Shred -- condition selection CommandLine contains T1133.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1133.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1133",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1133.004": AttackTechnique(
        id="T1133.004",
        name="External Remote Services: IAM Role Policy Assumption",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute External Remote Services: IAM Role Policy Assumption (T1133.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Network'],
        data_sources=["Cloud Audit: CloudTrail", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301304",
                name="Subtechnique Mitigation T1133.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect External Remote Services: IAM Role Policy Assumption -- condition selection CommandLine contains T1133.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1133.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1133",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1566": AttackTechnique(
        id="T1566",
        name="Phishing",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Phishing (T1566) during the Initial Access phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Email Message: Content', 'Network Traffic: Content'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1014",
                name="Hardening & Prevention for Phishing",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2014",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing -- selection CommandLine contains T1566",
                data_source="Email Message: Content",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1566",
                data_source="Email Message: Content",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Kimsuky', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1566.001": AttackTechnique(
        id="T1566.001",
        name="Phishing: S3 Storage Mass Data Extraction",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Phishing: S3 Storage Mass Data Extraction (T1566.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "Email Message: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301401",
                name="Subtechnique Mitigation T1566.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1566.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1566.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT28', 'Kimsuky', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1566",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1566.002": AttackTechnique(
        id="T1566.002",
        name="Phishing: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Phishing: Kubernetes Host PID Namespace Escape (T1566.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Container: Container Creation", "Email Message: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301402",
                name="Subtechnique Mitigation T1566.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1566.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1566.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT28', 'Kimsuky', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1566",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1566.003": AttackTechnique(
        id="T1566.003",
        name="Phishing: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Phishing: Asynchronous DNS TXT Data Exfil (T1566.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Network Traffic: DNS Query", "Email Message: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301403",
                name="Subtechnique Mitigation T1566.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1566.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1566.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT28', 'Kimsuky', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1566",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1566.004": AttackTechnique(
        id="T1566.004",
        name="Phishing: PowerShell Execution Architecture",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Phishing: PowerShell Execution Architecture (T1566.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Email Message: Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301404",
                name="Subtechnique Mitigation T1566.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Phishing: PowerShell Execution Architecture -- condition selection CommandLine contains T1566.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1566.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT28', 'Kimsuky', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1566",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078": AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Valid Accounts (T1078) during the Initial Access phase to advance compromises across Windows, Linux, Cloud, Azure AD. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud', 'Azure AD'],
        data_sources=['Authentication: User', 'Logon Session: Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1015",
                name="Hardening & Prevention for Valid Accounts",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2015",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts -- selection CommandLine contains T1078",
                data_source="Authentication: User",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1078",
                data_source="Authentication: User",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1078.001": AttackTechnique(
        id="T1078.001",
        name="Valid Accounts: Command Prompt Batch Chaining",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Valid Accounts: Command Prompt Batch Chaining (T1078.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud', 'Azure AD'],
        data_sources=["Process: Process Creation", "Authentication: User"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301501",
                name="Subtechnique Mitigation T1078.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Command Prompt Batch Chaining -- condition selection CommandLine contains T1078.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT29', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1078",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078.002": AttackTechnique(
        id="T1078.002",
        name="Valid Accounts: Unix Shell Staged Pipeline",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Valid Accounts: Unix Shell Staged Pipeline (T1078.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud', 'Azure AD'],
        data_sources=["Process: Process Creation", "Authentication: User"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301502",
                name="Subtechnique Mitigation T1078.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1078.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT29', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1078",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1078.003": AttackTechnique(
        id="T1078.003",
        name="Valid Accounts: Python Direct Socket Shellcode",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Valid Accounts: Python Direct Socket Shellcode (T1078.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud', 'Azure AD'],
        data_sources=["Process: Process Creation", "Authentication: User"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301503",
                name="Subtechnique Mitigation T1078.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Python Direct Socket Shellcode -- condition selection CommandLine contains T1078.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT29', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1078",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078.004": AttackTechnique(
        id="T1078.004",
        name="Valid Accounts: DLL Search Order Hijacking",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Valid Accounts: DLL Search Order Hijacking (T1078.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud', 'Azure AD'],
        data_sources=["Module: Module Load", "Authentication: User"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301504",
                name="Subtechnique Mitigation T1078.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: DLL Search Order Hijacking -- condition selection CommandLine contains T1078.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT29', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1078",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1195": AttackTechnique(
        id="T1195",
        name="Supply Chain Compromise",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Supply Chain Compromise (T1195) during the Initial Access phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: Creation', 'Application Log: Software'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1016",
                name="Hardening & Prevention for Supply Chain Compromise",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2016",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Supply Chain Compromise -- selection CommandLine contains T1195",
                data_source="File: Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1195",
                data_source="File: Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['SolarWinds Actor', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1195.001": AttackTechnique(
        id="T1195.001",
        name="Supply Chain Compromise: Process Memory Hollowing",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Supply Chain Compromise: Process Memory Hollowing (T1195.001) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Modification", "File: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301601",
                name="Subtechnique Mitigation T1195.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Supply Chain Compromise: Process Memory Hollowing -- condition selection CommandLine contains T1195.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1195.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['SolarWinds Actor', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1195",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1195.002": AttackTechnique(
        id="T1195.002",
        name="Supply Chain Compromise: Windows Access Token Theft",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Supply Chain Compromise: Windows Access Token Theft (T1195.002) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Token: Token Impersonation", "File: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301602",
                name="Subtechnique Mitigation T1195.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Supply Chain Compromise: Windows Access Token Theft -- condition selection CommandLine contains T1195.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1195.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['SolarWinds Actor', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1195",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1195.003": AttackTechnique(
        id="T1195.003",
        name="Supply Chain Compromise: NTLM Hash Pass-Through Replay",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Supply Chain Compromise: NTLM Hash Pass-Through Replay (T1195.003) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "File: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301603",
                name="Subtechnique Mitigation T1195.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Supply Chain Compromise: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1195.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1195.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['SolarWinds Actor', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1195",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1195.004": AttackTechnique(
        id="T1195.004",
        name="Supply Chain Compromise: Active Directory Kerberoasting",
        tactic_id="TA0001",
        tactic_name="Initial Access",
        description="""Adversaries execute Supply Chain Compromise: Active Directory Kerberoasting (T1195.004) during Initial Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "File: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301604",
                name="Subtechnique Mitigation T1195.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Supply Chain Compromise: Active Directory Kerberoasting -- condition selection CommandLine contains T1195.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1195.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['SolarWinds Actor', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1195",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1059": AttackTechnique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Command and Scripting Interpreter (T1059) during the Execution phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Creation', 'Command: Command Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1017",
                name="Hardening & Prevention for Command and Scripting Interpreter",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2017",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Command and Scripting Interpreter -- selection CommandLine contains T1059",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1059",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1059.001": AttackTechnique(
        id="T1059.001",
        name="Command and Scripting Interpreter: Kerberos AS-REP Roasting",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Command and Scripting Interpreter: Kerberos AS-REP Roasting (T1059.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301701",
                name="Subtechnique Mitigation T1059.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Command and Scripting Interpreter: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1059.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1059.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT28', 'APT29', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1059",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1059.002": AttackTechnique(
        id="T1059.002",
        name="Command and Scripting Interpreter: Active Directory Golden Ticket",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Command and Scripting Interpreter: Active Directory Golden Ticket (T1059.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301702",
                name="Subtechnique Mitigation T1059.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Command and Scripting Interpreter: Active Directory Golden Ticket -- condition selection CommandLine contains T1059.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1059.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT28', 'APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1059",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1059.003": AttackTechnique(
        id="T1059.003",
        name="Command and Scripting Interpreter: Kerberos Service Silver Ticket",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Command and Scripting Interpreter: Kerberos Service Silver Ticket (T1059.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301703",
                name="Subtechnique Mitigation T1059.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Command and Scripting Interpreter: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1059.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1059.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT28', 'APT29', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1059",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1059.004": AttackTechnique(
        id="T1059.004",
        name="Command and Scripting Interpreter: VSS Volume Shadow Deletion",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Command and Scripting Interpreter: VSS Volume Shadow Deletion (T1059.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301704",
                name="Subtechnique Mitigation T1059.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Command and Scripting Interpreter: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1059.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1059.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1059",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1053": AttackTechnique(
        id="T1053",
        name="Scheduled Task/Job",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Scheduled Task/Job (T1053) during the Execution phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Scheduled Job: Creation', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1018",
                name="Hardening & Prevention for Scheduled Task/Job",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2018",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Scheduled Task/Job -- selection CommandLine contains T1053",
                data_source="Scheduled Job: Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1053",
                data_source="Scheduled Job: Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1053.001": AttackTechnique(
        id="T1053.001",
        name="Scheduled Task/Job: Boot Configuration Tampering",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Scheduled Task/Job: Boot Configuration Tampering (T1053.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Scheduled Job: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301801",
                name="Subtechnique Mitigation T1053.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Scheduled Task/Job: Boot Configuration Tampering -- condition selection CommandLine contains T1053.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1053.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1053",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1053.002": AttackTechnique(
        id="T1053.002",
        name="Scheduled Task/Job: High-Entropy AES Cryptor Loop",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Scheduled Task/Job: High-Entropy AES Cryptor Loop (T1053.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["File: File Modification", "Scheduled Job: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301802",
                name="Subtechnique Mitigation T1053.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Scheduled Task/Job: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1053.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1053.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1053",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1053.003": AttackTechnique(
        id="T1053.003",
        name="Scheduled Task/Job: Audit Log Eviction and Shred",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Scheduled Task/Job: Audit Log Eviction and Shred (T1053.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Command: Command Execution", "Scheduled Job: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301803",
                name="Subtechnique Mitigation T1053.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Scheduled Task/Job: Audit Log Eviction and Shred -- condition selection CommandLine contains T1053.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1053.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1053",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1053.004": AttackTechnique(
        id="T1053.004",
        name="Scheduled Task/Job: IAM Role Policy Assumption",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Scheduled Task/Job: IAM Role Policy Assumption (T1053.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "Scheduled Job: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301804",
                name="Subtechnique Mitigation T1053.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Scheduled Task/Job: IAM Role Policy Assumption -- condition selection CommandLine contains T1053.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1053.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1053",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1204": AttackTechnique(
        id="T1204",
        name="User Execution",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute User Execution (T1204) during the Execution phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Creation', 'File: File Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1019",
                name="Hardening & Prevention for User Execution",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2019",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect User Execution -- selection CommandLine contains T1204",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1204",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['FIN7', 'MuddyWater'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1204.001": AttackTechnique(
        id="T1204.001",
        name="User Execution: S3 Storage Mass Data Extraction",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute User Execution: S3 Storage Mass Data Extraction (T1204.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301901",
                name="Subtechnique Mitigation T1204.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect User Execution: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1204.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1204.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['FIN7', 'MuddyWater'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1204",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1204.002": AttackTechnique(
        id="T1204.002",
        name="User Execution: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute User Execution: Kubernetes Host PID Namespace Escape (T1204.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Container: Container Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301902",
                name="Subtechnique Mitigation T1204.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect User Execution: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1204.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1204.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['FIN7', 'MuddyWater'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1204",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1204.003": AttackTechnique(
        id="T1204.003",
        name="User Execution: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute User Execution: Asynchronous DNS TXT Data Exfil (T1204.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Network Traffic: DNS Query", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301903",
                name="Subtechnique Mitigation T1204.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect User Execution: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1204.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1204.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['FIN7', 'MuddyWater'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1204",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1204.004": AttackTechnique(
        id="T1204.004",
        name="User Execution: PowerShell Execution Architecture",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute User Execution: PowerShell Execution Architecture (T1204.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M301904",
                name="Subtechnique Mitigation T1204.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M401904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect User Execution: PowerShell Execution Architecture -- condition selection CommandLine contains T1204.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1204.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['FIN7', 'MuddyWater'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1204",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1047": AttackTechnique(
        id="T1047",
        name="Windows Management Instrumentation",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Windows Management Instrumentation (T1047) during the Execution phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['WMI: WMI Creation', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1020",
                name="Hardening & Prevention for Windows Management Instrumentation",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2020",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Windows Management Instrumentation -- selection CommandLine contains T1047",
                data_source="WMI: WMI Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1047",
                data_source="WMI: WMI Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1047.001": AttackTechnique(
        id="T1047.001",
        name="Windows Management Instrumentation: Command Prompt Batch Chaining",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Windows Management Instrumentation: Command Prompt Batch Chaining (T1047.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "WMI: WMI Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302001",
                name="Subtechnique Mitigation T1047.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Windows Management Instrumentation: Command Prompt Batch Chaining -- condition selection CommandLine contains T1047.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1047.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1047",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1047.002": AttackTechnique(
        id="T1047.002",
        name="Windows Management Instrumentation: Unix Shell Staged Pipeline",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Windows Management Instrumentation: Unix Shell Staged Pipeline (T1047.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "WMI: WMI Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302002",
                name="Subtechnique Mitigation T1047.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Windows Management Instrumentation: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1047.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1047.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1047",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1047.003": AttackTechnique(
        id="T1047.003",
        name="Windows Management Instrumentation: Python Direct Socket Shellcode",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Windows Management Instrumentation: Python Direct Socket Shellcode (T1047.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "WMI: WMI Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302003",
                name="Subtechnique Mitigation T1047.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Windows Management Instrumentation: Python Direct Socket Shellcode -- condition selection CommandLine contains T1047.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1047.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1047",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1047.004": AttackTechnique(
        id="T1047.004",
        name="Windows Management Instrumentation: DLL Search Order Hijacking",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Windows Management Instrumentation: DLL Search Order Hijacking (T1047.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Module: Module Load", "WMI: WMI Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302004",
                name="Subtechnique Mitigation T1047.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Windows Management Instrumentation: DLL Search Order Hijacking -- condition selection CommandLine contains T1047.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1047.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1047",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1055": AttackTechnique(
        id="T1055",
        name="Process Injection",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Process Injection (T1055) during the Execution phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Process: Process Modification', 'Process: Process Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1021",
                name="Hardening & Prevention for Process Injection",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2021",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Process Injection -- selection CommandLine contains T1055",
                data_source="Process: Process Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1055",
                data_source="Process: Process Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Turla', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1055.001": AttackTechnique(
        id="T1055.001",
        name="Process Injection: Process Memory Hollowing",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Process Injection: Process Memory Hollowing (T1055.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Modification", "Process: Process Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302101",
                name="Subtechnique Mitigation T1055.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Process Injection: Process Memory Hollowing -- condition selection CommandLine contains T1055.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1055.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['Turla', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1055",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1055.002": AttackTechnique(
        id="T1055.002",
        name="Process Injection: Windows Access Token Theft",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Process Injection: Windows Access Token Theft (T1055.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Token: Token Impersonation", "Process: Process Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302102",
                name="Subtechnique Mitigation T1055.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Process Injection: Windows Access Token Theft -- condition selection CommandLine contains T1055.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1055.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['Turla', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1055",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1055.003": AttackTechnique(
        id="T1055.003",
        name="Process Injection: NTLM Hash Pass-Through Replay",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Process Injection: NTLM Hash Pass-Through Replay (T1055.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Process: Process Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302103",
                name="Subtechnique Mitigation T1055.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Process Injection: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1055.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1055.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['Turla', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1055",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1055.004": AttackTechnique(
        id="T1055.004",
        name="Process Injection: Active Directory Kerberoasting",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute Process Injection: Active Directory Kerberoasting (T1055.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Process: Process Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302104",
                name="Subtechnique Mitigation T1055.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Process Injection: Active Directory Kerberoasting -- condition selection CommandLine contains T1055.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1055.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['Turla', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1055",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1569": AttackTechnique(
        id="T1569",
        name="System Services",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute System Services (T1569) during the Execution phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Service: Service Creation', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1022",
                name="Hardening & Prevention for System Services",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2022",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Services -- selection CommandLine contains T1569",
                data_source="Service: Service Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1569",
                data_source="Service: Service Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'APT32'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1569.001": AttackTechnique(
        id="T1569.001",
        name="System Services: Kerberos AS-REP Roasting",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute System Services: Kerberos AS-REP Roasting (T1569.001) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302201",
                name="Subtechnique Mitigation T1569.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Services: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1569.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1569.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Sandworm Team', 'APT32'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1569",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1569.002": AttackTechnique(
        id="T1569.002",
        name="System Services: Active Directory Golden Ticket",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute System Services: Active Directory Golden Ticket (T1569.002) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302202",
                name="Subtechnique Mitigation T1569.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Services: Active Directory Golden Ticket -- condition selection CommandLine contains T1569.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1569.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Sandworm Team', 'APT32'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1569",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1569.003": AttackTechnique(
        id="T1569.003",
        name="System Services: Kerberos Service Silver Ticket",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute System Services: Kerberos Service Silver Ticket (T1569.003) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302203",
                name="Subtechnique Mitigation T1569.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Services: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1569.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1569.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Sandworm Team', 'APT32'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1569",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1569.004": AttackTechnique(
        id="T1569.004",
        name="System Services: VSS Volume Shadow Deletion",
        tactic_id="TA0002",
        tactic_name="Execution",
        description="""Adversaries execute System Services: VSS Volume Shadow Deletion (T1569.004) during Execution. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302204",
                name="Subtechnique Mitigation T1569.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Services: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1569.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1569.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Sandworm Team', 'APT32'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1569",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1547": AttackTechnique(
        id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Boot or Logon Autostart Execution (T1547) during the Persistence phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Windows Registry: Key Modification', 'File: Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1023",
                name="Hardening & Prevention for Boot or Logon Autostart Execution",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2023",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Boot or Logon Autostart Execution -- selection CommandLine contains T1547",
                data_source="Windows Registry: Key Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1547",
                data_source="Windows Registry: Key Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1547.001": AttackTechnique(
        id="T1547.001",
        name="Boot or Logon Autostart Execution: Boot Configuration Tampering",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Boot or Logon Autostart Execution: Boot Configuration Tampering (T1547.001) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Windows Registry: Key Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302301",
                name="Subtechnique Mitigation T1547.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Boot or Logon Autostart Execution: Boot Configuration Tampering -- condition selection CommandLine contains T1547.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1547.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1547",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1547.002": AttackTechnique(
        id="T1547.002",
        name="Boot or Logon Autostart Execution: High-Entropy AES Cryptor Loop",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Boot or Logon Autostart Execution: High-Entropy AES Cryptor Loop (T1547.002) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["File: File Modification", "Windows Registry: Key Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302302",
                name="Subtechnique Mitigation T1547.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Boot or Logon Autostart Execution: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1547.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1547.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1547",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1547.003": AttackTechnique(
        id="T1547.003",
        name="Boot or Logon Autostart Execution: Audit Log Eviction and Shred",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Boot or Logon Autostart Execution: Audit Log Eviction and Shred (T1547.003) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Command: Command Execution", "Windows Registry: Key Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302303",
                name="Subtechnique Mitigation T1547.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Boot or Logon Autostart Execution: Audit Log Eviction and Shred -- condition selection CommandLine contains T1547.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1547.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1547",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1547.004": AttackTechnique(
        id="T1547.004",
        name="Boot or Logon Autostart Execution: IAM Role Policy Assumption",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Boot or Logon Autostart Execution: IAM Role Policy Assumption (T1547.004) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Windows Registry: Key Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302304",
                name="Subtechnique Mitigation T1547.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Boot or Logon Autostart Execution: IAM Role Policy Assumption -- condition selection CommandLine contains T1547.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1547.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1547",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1543": AttackTechnique(
        id="T1543",
        name="Create or Modify System Process",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create or Modify System Process (T1543) during the Persistence phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Service: Service Creation', 'File: File Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1024",
                name="Hardening & Prevention for Create or Modify System Process",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2024",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create or Modify System Process -- selection CommandLine contains T1543",
                data_source="Service: Service Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1543",
                data_source="Service: Service Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1543.001": AttackTechnique(
        id="T1543.001",
        name="Create or Modify System Process: S3 Storage Mass Data Extraction",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create or Modify System Process: S3 Storage Mass Data Extraction (T1543.001) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302401",
                name="Subtechnique Mitigation T1543.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create or Modify System Process: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1543.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1543.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1543",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1543.002": AttackTechnique(
        id="T1543.002",
        name="Create or Modify System Process: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create or Modify System Process: Kubernetes Host PID Namespace Escape (T1543.002) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Container: Container Creation", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302402",
                name="Subtechnique Mitigation T1543.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create or Modify System Process: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1543.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1543.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1543",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1543.003": AttackTechnique(
        id="T1543.003",
        name="Create or Modify System Process: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create or Modify System Process: Asynchronous DNS TXT Data Exfil (T1543.003) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Network Traffic: DNS Query", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302403",
                name="Subtechnique Mitigation T1543.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create or Modify System Process: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1543.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1543.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1543",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1543.004": AttackTechnique(
        id="T1543.004",
        name="Create or Modify System Process: PowerShell Execution Architecture",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create or Modify System Process: PowerShell Execution Architecture (T1543.004) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Service: Service Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302404",
                name="Subtechnique Mitigation T1543.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create or Modify System Process: PowerShell Execution Architecture -- condition selection CommandLine contains T1543.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1543.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1543",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1136": AttackTechnique(
        id="T1136",
        name="Create Account",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create Account (T1136) during the Persistence phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['User Account: Account Creation', 'Cloud Audit: Logs'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1025",
                name="Hardening & Prevention for Create Account",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2025",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create Account -- selection CommandLine contains T1136",
                data_source="User Account: Account Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1136",
                data_source="User Account: Account Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1136.001": AttackTechnique(
        id="T1136.001",
        name="Create Account: Command Prompt Batch Chaining",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create Account: Command Prompt Batch Chaining (T1136.001) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "User Account: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302501",
                name="Subtechnique Mitigation T1136.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create Account: Command Prompt Batch Chaining -- condition selection CommandLine contains T1136.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1136.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1136",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1136.002": AttackTechnique(
        id="T1136.002",
        name="Create Account: Unix Shell Staged Pipeline",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create Account: Unix Shell Staged Pipeline (T1136.002) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "User Account: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302502",
                name="Subtechnique Mitigation T1136.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create Account: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1136.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1136.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1136",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1136.003": AttackTechnique(
        id="T1136.003",
        name="Create Account: Python Direct Socket Shellcode",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create Account: Python Direct Socket Shellcode (T1136.003) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "User Account: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302503",
                name="Subtechnique Mitigation T1136.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create Account: Python Direct Socket Shellcode -- condition selection CommandLine contains T1136.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1136.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1136",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1136.004": AttackTechnique(
        id="T1136.004",
        name="Create Account: DLL Search Order Hijacking",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Create Account: DLL Search Order Hijacking (T1136.004) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Module: Module Load", "User Account: Account Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302504",
                name="Subtechnique Mitigation T1136.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Create Account: DLL Search Order Hijacking -- condition selection CommandLine contains T1136.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1136.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1136",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1098": AttackTechnique(
        id="T1098",
        name="Account Manipulation",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Account Manipulation (T1098) during the Persistence phase to advance compromises across Windows, Azure AD, AWS IAM. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Azure AD', 'AWS IAM'],
        data_sources=['Cloud Audit: Policy', 'Directory: Modification'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1026",
                name="Hardening & Prevention for Account Manipulation",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2026",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Manipulation -- selection CommandLine contains T1098",
                data_source="Cloud Audit: Policy",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1098",
                data_source="Cloud Audit: Policy",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1098.001": AttackTechnique(
        id="T1098.001",
        name="Account Manipulation: Process Memory Hollowing",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Account Manipulation: Process Memory Hollowing (T1098.001) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Azure AD', 'AWS IAM'],
        data_sources=["Process: Process Modification", "Cloud Audit: Policy"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302601",
                name="Subtechnique Mitigation T1098.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Manipulation: Process Memory Hollowing -- condition selection CommandLine contains T1098.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1098.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT29', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1098",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1098.002": AttackTechnique(
        id="T1098.002",
        name="Account Manipulation: Windows Access Token Theft",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Account Manipulation: Windows Access Token Theft (T1098.002) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Azure AD', 'AWS IAM'],
        data_sources=["Token: Token Impersonation", "Cloud Audit: Policy"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302602",
                name="Subtechnique Mitigation T1098.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Manipulation: Windows Access Token Theft -- condition selection CommandLine contains T1098.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1098.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT29', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1098",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1098.003": AttackTechnique(
        id="T1098.003",
        name="Account Manipulation: NTLM Hash Pass-Through Replay",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Account Manipulation: NTLM Hash Pass-Through Replay (T1098.003) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Azure AD', 'AWS IAM'],
        data_sources=["Authentication: User Authentication", "Cloud Audit: Policy"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302603",
                name="Subtechnique Mitigation T1098.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Manipulation: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1098.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1098.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT29', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1098",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1098.004": AttackTechnique(
        id="T1098.004",
        name="Account Manipulation: Active Directory Kerberoasting",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Account Manipulation: Active Directory Kerberoasting (T1098.004) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Azure AD', 'AWS IAM'],
        data_sources=["Active Directory: Kerberos Request", "Cloud Audit: Policy"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302604",
                name="Subtechnique Mitigation T1098.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Manipulation: Active Directory Kerberoasting -- condition selection CommandLine contains T1098.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1098.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT29', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1098",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1546": AttackTechnique(
        id="T1546",
        name="Event Triggered Execution",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Event Triggered Execution (T1546) during the Persistence phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Windows Registry: Modification', 'WMI: Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1027",
                name="Hardening & Prevention for Event Triggered Execution",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2027",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Event Triggered Execution -- selection CommandLine contains T1546",
                data_source="Windows Registry: Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1546",
                data_source="Windows Registry: Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'Rocke'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1546.001": AttackTechnique(
        id="T1546.001",
        name="Event Triggered Execution: Kerberos AS-REP Roasting",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Event Triggered Execution: Kerberos AS-REP Roasting (T1546.001) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Windows Registry: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302701",
                name="Subtechnique Mitigation T1546.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Event Triggered Execution: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1546.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1546.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Sandworm Team', 'Rocke'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1546",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1546.002": AttackTechnique(
        id="T1546.002",
        name="Event Triggered Execution: Active Directory Golden Ticket",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Event Triggered Execution: Active Directory Golden Ticket (T1546.002) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Windows Registry: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302702",
                name="Subtechnique Mitigation T1546.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Event Triggered Execution: Active Directory Golden Ticket -- condition selection CommandLine contains T1546.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1546.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Sandworm Team', 'Rocke'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1546",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1546.003": AttackTechnique(
        id="T1546.003",
        name="Event Triggered Execution: Kerberos Service Silver Ticket",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Event Triggered Execution: Kerberos Service Silver Ticket (T1546.003) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Windows Registry: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302703",
                name="Subtechnique Mitigation T1546.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Event Triggered Execution: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1546.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1546.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Sandworm Team', 'Rocke'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1546",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1546.004": AttackTechnique(
        id="T1546.004",
        name="Event Triggered Execution: VSS Volume Shadow Deletion",
        tactic_id="TA0003",
        tactic_name="Persistence",
        description="""Adversaries execute Event Triggered Execution: VSS Volume Shadow Deletion (T1546.004) during Persistence. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Windows Registry: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302704",
                name="Subtechnique Mitigation T1546.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Event Triggered Execution: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1546.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1546.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Sandworm Team', 'Rocke'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1546",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1548": AttackTechnique(
        id="T1548",
        name="Abuse Elevation Control Mechanism",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Abuse Elevation Control Mechanism (T1548) during the Privilege Escalation phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Creation', 'File: File Modification'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1028",
                name="Hardening & Prevention for Abuse Elevation Control Mechanism",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2028",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Abuse Elevation Control Mechanism -- selection CommandLine contains T1548",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1548",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1548.001": AttackTechnique(
        id="T1548.001",
        name="Abuse Elevation Control Mechanism: Boot Configuration Tampering",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Abuse Elevation Control Mechanism: Boot Configuration Tampering (T1548.001) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302801",
                name="Subtechnique Mitigation T1548.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Abuse Elevation Control Mechanism: Boot Configuration Tampering -- condition selection CommandLine contains T1548.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1548.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1548",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1548.002": AttackTechnique(
        id="T1548.002",
        name="Abuse Elevation Control Mechanism: High-Entropy AES Cryptor Loop",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Abuse Elevation Control Mechanism: High-Entropy AES Cryptor Loop (T1548.002) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["File: File Modification", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302802",
                name="Subtechnique Mitigation T1548.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Abuse Elevation Control Mechanism: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1548.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1548.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1548",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1548.003": AttackTechnique(
        id="T1548.003",
        name="Abuse Elevation Control Mechanism: Audit Log Eviction and Shred",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Abuse Elevation Control Mechanism: Audit Log Eviction and Shred (T1548.003) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Command: Command Execution", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302803",
                name="Subtechnique Mitigation T1548.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Abuse Elevation Control Mechanism: Audit Log Eviction and Shred -- condition selection CommandLine contains T1548.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1548.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1548",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1548.004": AttackTechnique(
        id="T1548.004",
        name="Abuse Elevation Control Mechanism: IAM Role Policy Assumption",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Abuse Elevation Control Mechanism: IAM Role Policy Assumption (T1548.004) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302804",
                name="Subtechnique Mitigation T1548.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Abuse Elevation Control Mechanism: IAM Role Policy Assumption -- condition selection CommandLine contains T1548.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1548.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1548",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1068": AttackTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Exploitation for Privilege Escalation (T1068) during the Privilege Escalation phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Process: Process Creation', 'Application Log: System'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1029",
                name="Hardening & Prevention for Exploitation for Privilege Escalation",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2029",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploitation for Privilege Escalation -- selection CommandLine contains T1068",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1068",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Lazarus Group', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1068.001": AttackTechnique(
        id="T1068.001",
        name="Exploitation for Privilege Escalation: S3 Storage Mass Data Extraction",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Exploitation for Privilege Escalation: S3 Storage Mass Data Extraction (T1068.001) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302901",
                name="Subtechnique Mitigation T1068.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploitation for Privilege Escalation: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1068.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1068.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['Lazarus Group', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1068",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1068.002": AttackTechnique(
        id="T1068.002",
        name="Exploitation for Privilege Escalation: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Exploitation for Privilege Escalation: Kubernetes Host PID Namespace Escape (T1068.002) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Container: Container Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302902",
                name="Subtechnique Mitigation T1068.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploitation for Privilege Escalation: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1068.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1068.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['Lazarus Group', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1068",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1068.003": AttackTechnique(
        id="T1068.003",
        name="Exploitation for Privilege Escalation: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Exploitation for Privilege Escalation: Asynchronous DNS TXT Data Exfil (T1068.003) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Network Traffic: DNS Query", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302903",
                name="Subtechnique Mitigation T1068.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploitation for Privilege Escalation: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1068.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1068.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['Lazarus Group', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1068",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1068.004": AttackTechnique(
        id="T1068.004",
        name="Exploitation for Privilege Escalation: PowerShell Execution Architecture",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Exploitation for Privilege Escalation: PowerShell Execution Architecture (T1068.004) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M302904",
                name="Subtechnique Mitigation T1068.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M402904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exploitation for Privilege Escalation: PowerShell Execution Architecture -- condition selection CommandLine contains T1068.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1068.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['Lazarus Group', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1068",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1134": AttackTechnique(
        id="T1134",
        name="Access Token Manipulation",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Access Token Manipulation (T1134) during the Privilege Escalation phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['Process: Process Access', 'Token: Token Impersonation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1030",
                name="Hardening & Prevention for Access Token Manipulation",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2030",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Access Token Manipulation -- selection CommandLine contains T1134",
                data_source="Process: Process Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1134",
                data_source="Process: Process Access",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1134.001": AttackTechnique(
        id="T1134.001",
        name="Access Token Manipulation: Command Prompt Batch Chaining",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Access Token Manipulation: Command Prompt Batch Chaining (T1134.001) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303001",
                name="Subtechnique Mitigation T1134.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Access Token Manipulation: Command Prompt Batch Chaining -- condition selection CommandLine contains T1134.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1134.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1134",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1134.002": AttackTechnique(
        id="T1134.002",
        name="Access Token Manipulation: Unix Shell Staged Pipeline",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Access Token Manipulation: Unix Shell Staged Pipeline (T1134.002) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303002",
                name="Subtechnique Mitigation T1134.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Access Token Manipulation: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1134.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1134.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1134",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1134.003": AttackTechnique(
        id="T1134.003",
        name="Access Token Manipulation: Python Direct Socket Shellcode",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Access Token Manipulation: Python Direct Socket Shellcode (T1134.003) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303003",
                name="Subtechnique Mitigation T1134.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Access Token Manipulation: Python Direct Socket Shellcode -- condition selection CommandLine contains T1134.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1134.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1134",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1134.004": AttackTechnique(
        id="T1134.004",
        name="Access Token Manipulation: DLL Search Order Hijacking",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Access Token Manipulation: DLL Search Order Hijacking (T1134.004) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Module: Module Load", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303004",
                name="Subtechnique Mitigation T1134.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Access Token Manipulation: DLL Search Order Hijacking -- condition selection CommandLine contains T1134.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1134.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1134",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078.P": AttackTechnique(
        id="T1078.P",
        name="Valid Accounts: Privileged Escalation",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Valid Accounts: Privileged Escalation (T1078.P) during the Privilege Escalation phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['Authentication: Privilege Elevation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1031",
                name="Hardening & Prevention for Valid Accounts: Privileged Escalation",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2031",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Privileged Escalation -- selection CommandLine contains T1078.P",
                data_source="Authentication: Privilege Elevation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1078.P",
                data_source="Authentication: Privilege Elevation",
                log_event_id="1"
            )
        ],
        threat_actors=['Scattered Spider', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1078.P.001": AttackTechnique(
        id="T1078.P.001",
        name="Valid Accounts: Privileged Escalation: Process Memory Hollowing",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Valid Accounts: Privileged Escalation: Process Memory Hollowing (T1078.P.001) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Modification", "Authentication: Privilege Elevation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303101",
                name="Subtechnique Mitigation T1078.P.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Privileged Escalation: Process Memory Hollowing -- condition selection CommandLine contains T1078.P.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.P.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['Scattered Spider', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1078.P",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078.P.002": AttackTechnique(
        id="T1078.P.002",
        name="Valid Accounts: Privileged Escalation: Windows Access Token Theft",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Valid Accounts: Privileged Escalation: Windows Access Token Theft (T1078.P.002) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Token: Token Impersonation", "Authentication: Privilege Elevation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303102",
                name="Subtechnique Mitigation T1078.P.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Privileged Escalation: Windows Access Token Theft -- condition selection CommandLine contains T1078.P.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.P.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['Scattered Spider', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1078.P",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1078.P.003": AttackTechnique(
        id="T1078.P.003",
        name="Valid Accounts: Privileged Escalation: NTLM Hash Pass-Through Replay",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Valid Accounts: Privileged Escalation: NTLM Hash Pass-Through Replay (T1078.P.003) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Authentication: User Authentication", "Authentication: Privilege Elevation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303103",
                name="Subtechnique Mitigation T1078.P.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Privileged Escalation: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1078.P.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.P.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['Scattered Spider', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1078.P",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1078.P.004": AttackTechnique(
        id="T1078.P.004",
        name="Valid Accounts: Privileged Escalation: Active Directory Kerberoasting",
        tactic_id="TA0004",
        tactic_name="Privilege Escalation",
        description="""Adversaries execute Valid Accounts: Privileged Escalation: Active Directory Kerberoasting (T1078.P.004) during Privilege Escalation. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Active Directory: Kerberos Request", "Authentication: Privilege Elevation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303104",
                name="Subtechnique Mitigation T1078.P.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Valid Accounts: Privileged Escalation: Active Directory Kerberoasting -- condition selection CommandLine contains T1078.P.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1078.P.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['Scattered Spider', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1078.P",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1070": AttackTechnique(
        id="T1070",
        name="Indicator Removal on Host",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Indicator Removal on Host (T1070) during the Defense Evasion phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Deletion', 'Command: Command Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1032",
                name="Hardening & Prevention for Indicator Removal on Host",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2032",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Indicator Removal on Host -- selection CommandLine contains T1070",
                data_source="File: File Deletion",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1070",
                data_source="File: File Deletion",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1070.001": AttackTechnique(
        id="T1070.001",
        name="Indicator Removal on Host: Kerberos AS-REP Roasting",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Indicator Removal on Host: Kerberos AS-REP Roasting (T1070.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "File: File Deletion"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303201",
                name="Subtechnique Mitigation T1070.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Indicator Removal on Host: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1070.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1070.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1070",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1070.002": AttackTechnique(
        id="T1070.002",
        name="Indicator Removal on Host: Active Directory Golden Ticket",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Indicator Removal on Host: Active Directory Golden Ticket (T1070.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "File: File Deletion"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303202",
                name="Subtechnique Mitigation T1070.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Indicator Removal on Host: Active Directory Golden Ticket -- condition selection CommandLine contains T1070.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1070.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1070",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1070.003": AttackTechnique(
        id="T1070.003",
        name="Indicator Removal on Host: Kerberos Service Silver Ticket",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Indicator Removal on Host: Kerberos Service Silver Ticket (T1070.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "File: File Deletion"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303203",
                name="Subtechnique Mitigation T1070.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Indicator Removal on Host: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1070.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1070.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1070",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1070.004": AttackTechnique(
        id="T1070.004",
        name="Indicator Removal on Host: VSS Volume Shadow Deletion",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Indicator Removal on Host: VSS Volume Shadow Deletion (T1070.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Deletion"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303204",
                name="Subtechnique Mitigation T1070.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Indicator Removal on Host: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1070.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1070.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1070",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1027": AttackTechnique(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Obfuscated Files or Information (T1027) during the Defense Evasion phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Metadata', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1033",
                name="Hardening & Prevention for Obfuscated Files or Information",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2033",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obfuscated Files or Information -- selection CommandLine contains T1027",
                data_source="File: File Metadata",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1027",
                data_source="File: File Metadata",
                log_event_id="1"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1027.001": AttackTechnique(
        id="T1027.001",
        name="Obfuscated Files or Information: Boot Configuration Tampering",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Obfuscated Files or Information: Boot Configuration Tampering (T1027.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303301",
                name="Subtechnique Mitigation T1027.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obfuscated Files or Information: Boot Configuration Tampering -- condition selection CommandLine contains T1027.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1027.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1027",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1027.002": AttackTechnique(
        id="T1027.002",
        name="Obfuscated Files or Information: High-Entropy AES Cryptor Loop",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Obfuscated Files or Information: High-Entropy AES Cryptor Loop (T1027.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["File: File Modification", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303302",
                name="Subtechnique Mitigation T1027.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obfuscated Files or Information: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1027.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1027.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1027",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1027.003": AttackTechnique(
        id="T1027.003",
        name="Obfuscated Files or Information: Audit Log Eviction and Shred",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Obfuscated Files or Information: Audit Log Eviction and Shred (T1027.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Command: Command Execution", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303303",
                name="Subtechnique Mitigation T1027.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obfuscated Files or Information: Audit Log Eviction and Shred -- condition selection CommandLine contains T1027.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1027.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1027",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1027.004": AttackTechnique(
        id="T1027.004",
        name="Obfuscated Files or Information: IAM Role Policy Assumption",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Obfuscated Files or Information: IAM Role Policy Assumption (T1027.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "File: File Metadata"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303304",
                name="Subtechnique Mitigation T1027.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Obfuscated Files or Information: IAM Role Policy Assumption -- condition selection CommandLine contains T1027.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1027.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1027",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1562": AttackTechnique(
        id="T1562",
        name="Impair Defenses",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Impair Defenses (T1562) during the Defense Evasion phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['Service: Modification', 'Windows Registry: Modification'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1034",
                name="Hardening & Prevention for Impair Defenses",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2034",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Impair Defenses -- selection CommandLine contains T1562",
                data_source="Service: Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1562",
                data_source="Service: Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1562.001": AttackTechnique(
        id="T1562.001",
        name="Impair Defenses: S3 Storage Mass Data Extraction",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Impair Defenses: S3 Storage Mass Data Extraction (T1562.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Cloud Audit: CloudTrail", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303401",
                name="Subtechnique Mitigation T1562.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Impair Defenses: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1562.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1562.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1562",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1562.002": AttackTechnique(
        id="T1562.002",
        name="Impair Defenses: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Impair Defenses: Kubernetes Host PID Namespace Escape (T1562.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Container: Container Creation", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303402",
                name="Subtechnique Mitigation T1562.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Impair Defenses: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1562.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1562.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1562",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1562.003": AttackTechnique(
        id="T1562.003",
        name="Impair Defenses: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Impair Defenses: Asynchronous DNS TXT Data Exfil (T1562.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Network Traffic: DNS Query", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303403",
                name="Subtechnique Mitigation T1562.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Impair Defenses: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1562.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1562.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1562",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1562.004": AttackTechnique(
        id="T1562.004",
        name="Impair Defenses: PowerShell Execution Architecture",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Impair Defenses: PowerShell Execution Architecture (T1562.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303404",
                name="Subtechnique Mitigation T1562.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Impair Defenses: PowerShell Execution Architecture -- condition selection CommandLine contains T1562.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1562.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1562",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1036": AttackTechnique(
        id="T1036",
        name="Masquerading",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Masquerading (T1036) during the Defense Evasion phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Creation', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1035",
                name="Hardening & Prevention for Masquerading",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2035",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Masquerading -- selection CommandLine contains T1036",
                data_source="File: File Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1036",
                data_source="File: File Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1036.001": AttackTechnique(
        id="T1036.001",
        name="Masquerading: Command Prompt Batch Chaining",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Masquerading: Command Prompt Batch Chaining (T1036.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303501",
                name="Subtechnique Mitigation T1036.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Masquerading: Command Prompt Batch Chaining -- condition selection CommandLine contains T1036.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1036.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT29', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1036",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1036.002": AttackTechnique(
        id="T1036.002",
        name="Masquerading: Unix Shell Staged Pipeline",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Masquerading: Unix Shell Staged Pipeline (T1036.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303502",
                name="Subtechnique Mitigation T1036.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Masquerading: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1036.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1036.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1036",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1036.003": AttackTechnique(
        id="T1036.003",
        name="Masquerading: Python Direct Socket Shellcode",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Masquerading: Python Direct Socket Shellcode (T1036.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303503",
                name="Subtechnique Mitigation T1036.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Masquerading: Python Direct Socket Shellcode -- condition selection CommandLine contains T1036.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1036.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT29', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1036",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1036.004": AttackTechnique(
        id="T1036.004",
        name="Masquerading: DLL Search Order Hijacking",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Masquerading: DLL Search Order Hijacking (T1036.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303504",
                name="Subtechnique Mitigation T1036.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Masquerading: DLL Search Order Hijacking -- condition selection CommandLine contains T1036.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1036.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT29', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1036",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1218": AttackTechnique(
        id="T1218",
        name="System Binary Proxy Execution",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute System Binary Proxy Execution (T1218) during the Defense Evasion phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['Process: Process Creation', 'Command: Command Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1036",
                name="Hardening & Prevention for System Binary Proxy Execution",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2036",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Binary Proxy Execution -- selection CommandLine contains T1218",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1218",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1218.001": AttackTechnique(
        id="T1218.001",
        name="System Binary Proxy Execution: Process Memory Hollowing",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute System Binary Proxy Execution: Process Memory Hollowing (T1218.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Modification", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303601",
                name="Subtechnique Mitigation T1218.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Binary Proxy Execution: Process Memory Hollowing -- condition selection CommandLine contains T1218.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1218.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1218",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1218.002": AttackTechnique(
        id="T1218.002",
        name="System Binary Proxy Execution: Windows Access Token Theft",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute System Binary Proxy Execution: Windows Access Token Theft (T1218.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Token: Token Impersonation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303602",
                name="Subtechnique Mitigation T1218.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Binary Proxy Execution: Windows Access Token Theft -- condition selection CommandLine contains T1218.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1218.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1218",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1218.003": AttackTechnique(
        id="T1218.003",
        name="System Binary Proxy Execution: NTLM Hash Pass-Through Replay",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute System Binary Proxy Execution: NTLM Hash Pass-Through Replay (T1218.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303603",
                name="Subtechnique Mitigation T1218.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Binary Proxy Execution: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1218.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1218.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1218",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1218.004": AttackTechnique(
        id="T1218.004",
        name="System Binary Proxy Execution: Active Directory Kerberoasting",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute System Binary Proxy Execution: Active Directory Kerberoasting (T1218.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Active Directory: Kerberos Request", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303604",
                name="Subtechnique Mitigation T1218.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Binary Proxy Execution: Active Directory Kerberoasting -- condition selection CommandLine contains T1218.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1218.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1218",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1497": AttackTechnique(
        id="T1497",
        name="Virtualization/Sandbox Evasion",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Virtualization/Sandbox Evasion (T1497) during the Defense Evasion phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Process: Process Creation', 'System: Time Check'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1037",
                name="Hardening & Prevention for Virtualization/Sandbox Evasion",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2037",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Virtualization/Sandbox Evasion -- selection CommandLine contains T1497",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1497",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Turla', 'DarkSide'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1497.001": AttackTechnique(
        id="T1497.001",
        name="Virtualization/Sandbox Evasion: Kerberos AS-REP Roasting",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Virtualization/Sandbox Evasion: Kerberos AS-REP Roasting (T1497.001) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303701",
                name="Subtechnique Mitigation T1497.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Virtualization/Sandbox Evasion: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1497.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1497.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Turla', 'DarkSide'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1497",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1497.002": AttackTechnique(
        id="T1497.002",
        name="Virtualization/Sandbox Evasion: Active Directory Golden Ticket",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Virtualization/Sandbox Evasion: Active Directory Golden Ticket (T1497.002) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303702",
                name="Subtechnique Mitigation T1497.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Virtualization/Sandbox Evasion: Active Directory Golden Ticket -- condition selection CommandLine contains T1497.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1497.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Turla', 'DarkSide'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1497",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1497.003": AttackTechnique(
        id="T1497.003",
        name="Virtualization/Sandbox Evasion: Kerberos Service Silver Ticket",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Virtualization/Sandbox Evasion: Kerberos Service Silver Ticket (T1497.003) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303703",
                name="Subtechnique Mitigation T1497.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Virtualization/Sandbox Evasion: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1497.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1497.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Turla', 'DarkSide'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1497",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1497.004": AttackTechnique(
        id="T1497.004",
        name="Virtualization/Sandbox Evasion: VSS Volume Shadow Deletion",
        tactic_id="TA0005",
        tactic_name="Defense Evasion",
        description="""Adversaries execute Virtualization/Sandbox Evasion: VSS Volume Shadow Deletion (T1497.004) during Defense Evasion. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303704",
                name="Subtechnique Mitigation T1497.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Virtualization/Sandbox Evasion: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1497.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1497.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Turla', 'DarkSide'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1497",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1003": AttackTechnique(
        id="T1003",
        name="OS Credential Dumping",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute OS Credential Dumping (T1003) during the Credential Access phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Process: Process Access', 'Windows Registry: Key Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1038",
                name="Hardening & Prevention for OS Credential Dumping",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2038",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect OS Credential Dumping -- selection CommandLine contains T1003",
                data_source="Process: Process Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1003",
                data_source="Process: Process Access",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1003.001": AttackTechnique(
        id="T1003.001",
        name="OS Credential Dumping: Boot Configuration Tampering",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute OS Credential Dumping: Boot Configuration Tampering (T1003.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303801",
                name="Subtechnique Mitigation T1003.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect OS Credential Dumping: Boot Configuration Tampering -- condition selection CommandLine contains T1003.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1003.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1003",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1003.002": AttackTechnique(
        id="T1003.002",
        name="OS Credential Dumping: High-Entropy AES Cryptor Loop",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute OS Credential Dumping: High-Entropy AES Cryptor Loop (T1003.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["File: File Modification", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303802",
                name="Subtechnique Mitigation T1003.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect OS Credential Dumping: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1003.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1003.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1003",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1003.003": AttackTechnique(
        id="T1003.003",
        name="OS Credential Dumping: Audit Log Eviction and Shred",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute OS Credential Dumping: Audit Log Eviction and Shred (T1003.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Command: Command Execution", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303803",
                name="Subtechnique Mitigation T1003.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect OS Credential Dumping: Audit Log Eviction and Shred -- condition selection CommandLine contains T1003.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1003.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1003",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1003.004": AttackTechnique(
        id="T1003.004",
        name="OS Credential Dumping: IAM Role Policy Assumption",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute OS Credential Dumping: IAM Role Policy Assumption (T1003.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303804",
                name="Subtechnique Mitigation T1003.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect OS Credential Dumping: IAM Role Policy Assumption -- condition selection CommandLine contains T1003.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1003.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT28', 'APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1003",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1110": AttackTechnique(
        id="T1110",
        name="Brute Force",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Brute Force (T1110) during the Credential Access phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['Authentication: User Authentication', 'Logon Session: Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1039",
                name="Hardening & Prevention for Brute Force",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2039",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Brute Force -- selection CommandLine contains T1110",
                data_source="Authentication: User Authentication",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1110",
                data_source="Authentication: User Authentication",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1110.001": AttackTechnique(
        id="T1110.001",
        name="Brute Force: S3 Storage Mass Data Extraction",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Brute Force: S3 Storage Mass Data Extraction (T1110.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Cloud Audit: CloudTrail", "Authentication: User Authentication"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303901",
                name="Subtechnique Mitigation T1110.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Brute Force: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1110.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1110.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1110",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1110.002": AttackTechnique(
        id="T1110.002",
        name="Brute Force: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Brute Force: Kubernetes Host PID Namespace Escape (T1110.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Container: Container Creation", "Authentication: User Authentication"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303902",
                name="Subtechnique Mitigation T1110.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Brute Force: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1110.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1110.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1110",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1110.003": AttackTechnique(
        id="T1110.003",
        name="Brute Force: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Brute Force: Asynchronous DNS TXT Data Exfil (T1110.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Network Traffic: DNS Query", "Authentication: User Authentication"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303903",
                name="Subtechnique Mitigation T1110.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Brute Force: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1110.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1110.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1110",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1110.004": AttackTechnique(
        id="T1110.004",
        name="Brute Force: PowerShell Execution Architecture",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Brute Force: PowerShell Execution Architecture (T1110.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "Authentication: User Authentication"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M303904",
                name="Subtechnique Mitigation T1110.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M403904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Brute Force: PowerShell Execution Architecture -- condition selection CommandLine contains T1110.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1110.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT33', 'Scattered Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1110",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1555": AttackTechnique(
        id="T1555",
        name="Credentials from Password Stores",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Credentials from Password Stores (T1555) during the Credential Access phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Access', 'Process: Process Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1040",
                name="Hardening & Prevention for Credentials from Password Stores",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2040",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Credentials from Password Stores -- selection CommandLine contains T1555",
                data_source="File: File Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1555",
                data_source="File: File Access",
                log_event_id="1"
            )
        ],
        threat_actors=['RedLine Stealer', 'Vidar'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1555.001": AttackTechnique(
        id="T1555.001",
        name="Credentials from Password Stores: Command Prompt Batch Chaining",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Credentials from Password Stores: Command Prompt Batch Chaining (T1555.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304001",
                name="Subtechnique Mitigation T1555.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Credentials from Password Stores: Command Prompt Batch Chaining -- condition selection CommandLine contains T1555.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1555.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['RedLine Stealer', 'Vidar'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1555",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1555.002": AttackTechnique(
        id="T1555.002",
        name="Credentials from Password Stores: Unix Shell Staged Pipeline",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Credentials from Password Stores: Unix Shell Staged Pipeline (T1555.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304002",
                name="Subtechnique Mitigation T1555.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Credentials from Password Stores: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1555.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1555.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['RedLine Stealer', 'Vidar'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1555",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1555.003": AttackTechnique(
        id="T1555.003",
        name="Credentials from Password Stores: Python Direct Socket Shellcode",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Credentials from Password Stores: Python Direct Socket Shellcode (T1555.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304003",
                name="Subtechnique Mitigation T1555.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Credentials from Password Stores: Python Direct Socket Shellcode -- condition selection CommandLine contains T1555.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1555.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['RedLine Stealer', 'Vidar'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1555",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1555.004": AttackTechnique(
        id="T1555.004",
        name="Credentials from Password Stores: DLL Search Order Hijacking",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Credentials from Password Stores: DLL Search Order Hijacking (T1555.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304004",
                name="Subtechnique Mitigation T1555.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Credentials from Password Stores: DLL Search Order Hijacking -- condition selection CommandLine contains T1555.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1555.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['RedLine Stealer', 'Vidar'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1555",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1558": AttackTechnique(
        id="T1558",
        name="Steal or Forge Kerberos Tickets",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Steal or Forge Kerberos Tickets (T1558) during the Credential Access phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['Active Directory: Kerberos Ticket Request'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1041",
                name="Hardening & Prevention for Steal or Forge Kerberos Tickets",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2041",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Steal or Forge Kerberos Tickets -- selection CommandLine contains T1558",
                data_source="Active Directory: Kerberos Ticket Request",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1558",
                data_source="Active Directory: Kerberos Ticket Request",
                log_event_id="1"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1558.001": AttackTechnique(
        id="T1558.001",
        name="Steal or Forge Kerberos Tickets: Process Memory Hollowing",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Steal or Forge Kerberos Tickets: Process Memory Hollowing (T1558.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Modification", "Active Directory: Kerberos Ticket Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304101",
                name="Subtechnique Mitigation T1558.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Steal or Forge Kerberos Tickets: Process Memory Hollowing -- condition selection CommandLine contains T1558.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1558.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1558",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1558.002": AttackTechnique(
        id="T1558.002",
        name="Steal or Forge Kerberos Tickets: Windows Access Token Theft",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Steal or Forge Kerberos Tickets: Windows Access Token Theft (T1558.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Token: Token Impersonation", "Active Directory: Kerberos Ticket Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304102",
                name="Subtechnique Mitigation T1558.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Steal or Forge Kerberos Tickets: Windows Access Token Theft -- condition selection CommandLine contains T1558.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1558.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1558",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1558.003": AttackTechnique(
        id="T1558.003",
        name="Steal or Forge Kerberos Tickets: NTLM Hash Pass-Through Replay",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Steal or Forge Kerberos Tickets: NTLM Hash Pass-Through Replay (T1558.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Authentication: User Authentication", "Active Directory: Kerberos Ticket Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304103",
                name="Subtechnique Mitigation T1558.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Steal or Forge Kerberos Tickets: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1558.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1558.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1558",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1558.004": AttackTechnique(
        id="T1558.004",
        name="Steal or Forge Kerberos Tickets: Active Directory Kerberoasting",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Steal or Forge Kerberos Tickets: Active Directory Kerberoasting (T1558.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Active Directory: Kerberos Request", "Active Directory: Kerberos Ticket Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304104",
                name="Subtechnique Mitigation T1558.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Steal or Forge Kerberos Tickets: Active Directory Kerberoasting -- condition selection CommandLine contains T1558.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1558.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1558",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1552": AttackTechnique(
        id="T1552",
        name="Unsecured Credentials",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Unsecured Credentials (T1552) during the Credential Access phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['File: File Access', 'Cloud Audit: Secrets'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1042",
                name="Hardening & Prevention for Unsecured Credentials",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2042",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Unsecured Credentials -- selection CommandLine contains T1552",
                data_source="File: File Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1552",
                data_source="File: File Access",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'TeamTNT'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1552.001": AttackTechnique(
        id="T1552.001",
        name="Unsecured Credentials: Kerberos AS-REP Roasting",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Unsecured Credentials: Kerberos AS-REP Roasting (T1552.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Active Directory: Kerberos Request", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304201",
                name="Subtechnique Mitigation T1552.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Unsecured Credentials: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1552.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1552.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT29', 'TeamTNT'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1552",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1552.002": AttackTechnique(
        id="T1552.002",
        name="Unsecured Credentials: Active Directory Golden Ticket",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Unsecured Credentials: Active Directory Golden Ticket (T1552.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Authentication: User Authentication", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304202",
                name="Subtechnique Mitigation T1552.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Unsecured Credentials: Active Directory Golden Ticket -- condition selection CommandLine contains T1552.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1552.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT29', 'TeamTNT'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1552",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1552.003": AttackTechnique(
        id="T1552.003",
        name="Unsecured Credentials: Kerberos Service Silver Ticket",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Unsecured Credentials: Kerberos Service Silver Ticket (T1552.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Authentication: User Authentication", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304203",
                name="Subtechnique Mitigation T1552.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Unsecured Credentials: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1552.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1552.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT29', 'TeamTNT'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1552",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1552.004": AttackTechnique(
        id="T1552.004",
        name="Unsecured Credentials: VSS Volume Shadow Deletion",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Unsecured Credentials: VSS Volume Shadow Deletion (T1552.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304204",
                name="Subtechnique Mitigation T1552.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Unsecured Credentials: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1552.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1552.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT29', 'TeamTNT'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1552",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1606": AttackTechnique(
        id="T1606",
        name="Forge Web Credentials",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Forge Web Credentials (T1606) during the Credential Access phase to advance compromises across Cloud, SaaS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Cloud', 'SaaS'],
        data_sources=['Cloud Audit: Token Issuance', 'Authentication: SAML'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1043",
                name="Hardening & Prevention for Forge Web Credentials",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2043",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Forge Web Credentials -- selection CommandLine contains T1606",
                data_source="Cloud Audit: Token Issuance",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1606",
                data_source="Cloud Audit: Token Issuance",
                log_event_id="1"
            )
        ],
        threat_actors=['SolarWinds Actor', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1606.001": AttackTechnique(
        id="T1606.001",
        name="Forge Web Credentials: Boot Configuration Tampering",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Forge Web Credentials: Boot Configuration Tampering (T1606.001) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'SaaS'],
        data_sources=["Process: Process Creation", "Cloud Audit: Token Issuance"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304301",
                name="Subtechnique Mitigation T1606.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Forge Web Credentials: Boot Configuration Tampering -- condition selection CommandLine contains T1606.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1606.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['SolarWinds Actor', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1606",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1606.002": AttackTechnique(
        id="T1606.002",
        name="Forge Web Credentials: High-Entropy AES Cryptor Loop",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Forge Web Credentials: High-Entropy AES Cryptor Loop (T1606.002) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'SaaS'],
        data_sources=["File: File Modification", "Cloud Audit: Token Issuance"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304302",
                name="Subtechnique Mitigation T1606.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Forge Web Credentials: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1606.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1606.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['SolarWinds Actor', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1606",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1606.003": AttackTechnique(
        id="T1606.003",
        name="Forge Web Credentials: Audit Log Eviction and Shred",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Forge Web Credentials: Audit Log Eviction and Shred (T1606.003) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'SaaS'],
        data_sources=["Command: Command Execution", "Cloud Audit: Token Issuance"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304303",
                name="Subtechnique Mitigation T1606.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Forge Web Credentials: Audit Log Eviction and Shred -- condition selection CommandLine contains T1606.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1606.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['SolarWinds Actor', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1606",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1606.004": AttackTechnique(
        id="T1606.004",
        name="Forge Web Credentials: IAM Role Policy Assumption",
        tactic_id="TA0006",
        tactic_name="Credential Access",
        description="""Adversaries execute Forge Web Credentials: IAM Role Policy Assumption (T1606.004) during Credential Access. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'SaaS'],
        data_sources=["Cloud Audit: CloudTrail", "Cloud Audit: Token Issuance"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304304",
                name="Subtechnique Mitigation T1606.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Forge Web Credentials: IAM Role Policy Assumption -- condition selection CommandLine contains T1606.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1606.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['SolarWinds Actor', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1606",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1087": AttackTechnique(
        id="T1087",
        name="Account Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Account Discovery (T1087) during the Discovery phase to advance compromises across Windows, Linux, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=['Process: Process Creation', 'Command: Command Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1044",
                name="Hardening & Prevention for Account Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2044",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Discovery -- selection CommandLine contains T1087",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1087",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1087.001": AttackTechnique(
        id="T1087.001",
        name="Account Discovery: S3 Storage Mass Data Extraction",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Account Discovery: S3 Storage Mass Data Extraction (T1087.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304401",
                name="Subtechnique Mitigation T1087.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Discovery: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1087.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1087.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1087",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1087.002": AttackTechnique(
        id="T1087.002",
        name="Account Discovery: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Account Discovery: Kubernetes Host PID Namespace Escape (T1087.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Container: Container Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304402",
                name="Subtechnique Mitigation T1087.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Discovery: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1087.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1087.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1087",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1087.003": AttackTechnique(
        id="T1087.003",
        name="Account Discovery: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Account Discovery: Asynchronous DNS TXT Data Exfil (T1087.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Network Traffic: DNS Query", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304403",
                name="Subtechnique Mitigation T1087.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Discovery: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1087.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1087.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1087",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1087.004": AttackTechnique(
        id="T1087.004",
        name="Account Discovery: PowerShell Execution Architecture",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Account Discovery: PowerShell Execution Architecture (T1087.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'Cloud'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304404",
                name="Subtechnique Mitigation T1087.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Account Discovery: PowerShell Execution Architecture -- condition selection CommandLine contains T1087.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1087.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT28', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1087",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1083": AttackTechnique(
        id="T1083",
        name="File and Directory Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute File and Directory Discovery (T1083) during the Discovery phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Creation', 'Command: Command Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1045",
                name="Hardening & Prevention for File and Directory Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2045",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect File and Directory Discovery -- selection CommandLine contains T1083",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1083",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1083.001": AttackTechnique(
        id="T1083.001",
        name="File and Directory Discovery: Command Prompt Batch Chaining",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute File and Directory Discovery: Command Prompt Batch Chaining (T1083.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304501",
                name="Subtechnique Mitigation T1083.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect File and Directory Discovery: Command Prompt Batch Chaining -- condition selection CommandLine contains T1083.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1083.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1083",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1083.002": AttackTechnique(
        id="T1083.002",
        name="File and Directory Discovery: Unix Shell Staged Pipeline",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute File and Directory Discovery: Unix Shell Staged Pipeline (T1083.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304502",
                name="Subtechnique Mitigation T1083.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect File and Directory Discovery: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1083.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1083.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1083",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1083.003": AttackTechnique(
        id="T1083.003",
        name="File and Directory Discovery: Python Direct Socket Shellcode",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute File and Directory Discovery: Python Direct Socket Shellcode (T1083.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304503",
                name="Subtechnique Mitigation T1083.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect File and Directory Discovery: Python Direct Socket Shellcode -- condition selection CommandLine contains T1083.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1083.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1083",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1083.004": AttackTechnique(
        id="T1083.004",
        name="File and Directory Discovery: DLL Search Order Hijacking",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute File and Directory Discovery: DLL Search Order Hijacking (T1083.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304504",
                name="Subtechnique Mitigation T1083.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect File and Directory Discovery: DLL Search Order Hijacking -- condition selection CommandLine contains T1083.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1083.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT32', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1083",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1046": AttackTechnique(
        id="T1046",
        name="Network Service Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Network Service Discovery (T1046) during the Discovery phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Network Traffic: Network Traffic Flow', 'Command: Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1046",
                name="Hardening & Prevention for Network Service Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2046",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Network Service Discovery -- selection CommandLine contains T1046",
                data_source="Network Traffic: Network Traffic Flow",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1046",
                data_source="Network Traffic: Network Traffic Flow",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1046.001": AttackTechnique(
        id="T1046.001",
        name="Network Service Discovery: Process Memory Hollowing",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Network Service Discovery: Process Memory Hollowing (T1046.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Modification", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304601",
                name="Subtechnique Mitigation T1046.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Network Service Discovery: Process Memory Hollowing -- condition selection CommandLine contains T1046.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1046.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1046",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1046.002": AttackTechnique(
        id="T1046.002",
        name="Network Service Discovery: Windows Access Token Theft",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Network Service Discovery: Windows Access Token Theft (T1046.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Token: Token Impersonation", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304602",
                name="Subtechnique Mitigation T1046.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Network Service Discovery: Windows Access Token Theft -- condition selection CommandLine contains T1046.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1046.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1046",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1046.003": AttackTechnique(
        id="T1046.003",
        name="Network Service Discovery: NTLM Hash Pass-Through Replay",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Network Service Discovery: NTLM Hash Pass-Through Replay (T1046.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304603",
                name="Subtechnique Mitigation T1046.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Network Service Discovery: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1046.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1046.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1046",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1046.004": AttackTechnique(
        id="T1046.004",
        name="Network Service Discovery: Active Directory Kerberoasting",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Network Service Discovery: Active Directory Kerberoasting (T1046.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: Network Traffic Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304604",
                name="Subtechnique Mitigation T1046.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Network Service Discovery: Active Directory Kerberoasting -- condition selection CommandLine contains T1046.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1046.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT33', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1046",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1082": AttackTechnique(
        id="T1082",
        name="System Information Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute System Information Discovery (T1082) during the Discovery phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Creation', 'Command: Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1047",
                name="Hardening & Prevention for System Information Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2047",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Information Discovery -- selection CommandLine contains T1082",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1082",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'APT29'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1082.001": AttackTechnique(
        id="T1082.001",
        name="System Information Discovery: Kerberos AS-REP Roasting",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute System Information Discovery: Kerberos AS-REP Roasting (T1082.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304701",
                name="Subtechnique Mitigation T1082.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Information Discovery: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1082.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1082.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT28', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1082",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1082.002": AttackTechnique(
        id="T1082.002",
        name="System Information Discovery: Active Directory Golden Ticket",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute System Information Discovery: Active Directory Golden Ticket (T1082.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304702",
                name="Subtechnique Mitigation T1082.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Information Discovery: Active Directory Golden Ticket -- condition selection CommandLine contains T1082.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1082.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT28', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1082",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1082.003": AttackTechnique(
        id="T1082.003",
        name="System Information Discovery: Kerberos Service Silver Ticket",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute System Information Discovery: Kerberos Service Silver Ticket (T1082.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304703",
                name="Subtechnique Mitigation T1082.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Information Discovery: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1082.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1082.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT28', 'APT29'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1082",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1082.004": AttackTechnique(
        id="T1082.004",
        name="System Information Discovery: VSS Volume Shadow Deletion",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute System Information Discovery: VSS Volume Shadow Deletion (T1082.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304704",
                name="Subtechnique Mitigation T1082.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect System Information Discovery: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1082.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1082.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'APT29'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1082",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1018": AttackTechnique(
        id="T1018",
        name="Remote System Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Remote System Discovery (T1018) during the Discovery phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Network Traffic: Flow', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1048",
                name="Hardening & Prevention for Remote System Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2048",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote System Discovery -- selection CommandLine contains T1018",
                data_source="Network Traffic: Flow",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1018",
                data_source="Network Traffic: Flow",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1018.001": AttackTechnique(
        id="T1018.001",
        name="Remote System Discovery: Boot Configuration Tampering",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Remote System Discovery: Boot Configuration Tampering (T1018.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Network Traffic: Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304801",
                name="Subtechnique Mitigation T1018.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote System Discovery: Boot Configuration Tampering -- condition selection CommandLine contains T1018.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1018.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1018",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1018.002": AttackTechnique(
        id="T1018.002",
        name="Remote System Discovery: High-Entropy AES Cryptor Loop",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Remote System Discovery: High-Entropy AES Cryptor Loop (T1018.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["File: File Modification", "Network Traffic: Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304802",
                name="Subtechnique Mitigation T1018.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote System Discovery: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1018.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1018.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1018",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1018.003": AttackTechnique(
        id="T1018.003",
        name="Remote System Discovery: Audit Log Eviction and Shred",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Remote System Discovery: Audit Log Eviction and Shred (T1018.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Command: Command Execution", "Network Traffic: Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304803",
                name="Subtechnique Mitigation T1018.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote System Discovery: Audit Log Eviction and Shred -- condition selection CommandLine contains T1018.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1018.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1018",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1018.004": AttackTechnique(
        id="T1018.004",
        name="Remote System Discovery: IAM Role Policy Assumption",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Remote System Discovery: IAM Role Policy Assumption (T1018.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Network Traffic: Flow"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304804",
                name="Subtechnique Mitigation T1018.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote System Discovery: IAM Role Policy Assumption -- condition selection CommandLine contains T1018.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1018.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT29', 'FIN6'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1018",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1518": AttackTechnique(
        id="T1518",
        name="Software Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Software Discovery (T1518) during the Discovery phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Process: Process Creation', 'Windows Registry: Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1049",
                name="Hardening & Prevention for Software Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2049",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Software Discovery -- selection CommandLine contains T1518",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1518",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1518.001": AttackTechnique(
        id="T1518.001",
        name="Software Discovery: S3 Storage Mass Data Extraction",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Software Discovery: S3 Storage Mass Data Extraction (T1518.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304901",
                name="Subtechnique Mitigation T1518.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Software Discovery: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1518.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1518.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1518",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1518.002": AttackTechnique(
        id="T1518.002",
        name="Software Discovery: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Software Discovery: Kubernetes Host PID Namespace Escape (T1518.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Container: Container Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304902",
                name="Subtechnique Mitigation T1518.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Software Discovery: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1518.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1518.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1518",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1518.003": AttackTechnique(
        id="T1518.003",
        name="Software Discovery: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Software Discovery: Asynchronous DNS TXT Data Exfil (T1518.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Network Traffic: DNS Query", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304903",
                name="Subtechnique Mitigation T1518.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Software Discovery: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1518.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1518.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1518",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1518.004": AttackTechnique(
        id="T1518.004",
        name="Software Discovery: PowerShell Execution Architecture",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Software Discovery: PowerShell Execution Architecture (T1518.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M304904",
                name="Subtechnique Mitigation T1518.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M404904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Software Discovery: PowerShell Execution Architecture -- condition selection CommandLine contains T1518.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1518.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['Wizard Spider', 'Sandworm Team'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1518",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1613": AttackTechnique(
        id="T1613",
        name="Container and Resource Discovery",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Container and Resource Discovery (T1613) during the Discovery phase to advance compromises across Kubernetes, Docker. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Kubernetes', 'Docker'],
        data_sources=['Container: API Request', 'Pod: Discovery'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1050",
                name="Hardening & Prevention for Container and Resource Discovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2050",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Container and Resource Discovery -- selection CommandLine contains T1613",
                data_source="Container: API Request",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1613",
                data_source="Container: API Request",
                log_event_id="1"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1613.001": AttackTechnique(
        id="T1613.001",
        name="Container and Resource Discovery: Command Prompt Batch Chaining",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Container and Resource Discovery: Command Prompt Batch Chaining (T1613.001) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Kubernetes', 'Docker'],
        data_sources=["Process: Process Creation", "Container: API Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305001",
                name="Subtechnique Mitigation T1613.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Container and Resource Discovery: Command Prompt Batch Chaining -- condition selection CommandLine contains T1613.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1613.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1613",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1613.002": AttackTechnique(
        id="T1613.002",
        name="Container and Resource Discovery: Unix Shell Staged Pipeline",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Container and Resource Discovery: Unix Shell Staged Pipeline (T1613.002) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Kubernetes', 'Docker'],
        data_sources=["Process: Process Creation", "Container: API Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305002",
                name="Subtechnique Mitigation T1613.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Container and Resource Discovery: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1613.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1613.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1613",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1613.003": AttackTechnique(
        id="T1613.003",
        name="Container and Resource Discovery: Python Direct Socket Shellcode",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Container and Resource Discovery: Python Direct Socket Shellcode (T1613.003) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Kubernetes', 'Docker'],
        data_sources=["Process: Process Creation", "Container: API Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305003",
                name="Subtechnique Mitigation T1613.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Container and Resource Discovery: Python Direct Socket Shellcode -- condition selection CommandLine contains T1613.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1613.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1613",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1613.004": AttackTechnique(
        id="T1613.004",
        name="Container and Resource Discovery: DLL Search Order Hijacking",
        tactic_id="TA0007",
        tactic_name="Discovery",
        description="""Adversaries execute Container and Resource Discovery: DLL Search Order Hijacking (T1613.004) during Discovery. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Kubernetes', 'Docker'],
        data_sources=["Module: Module Load", "Container: API Request"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305004",
                name="Subtechnique Mitigation T1613.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Container and Resource Discovery: DLL Search Order Hijacking -- condition selection CommandLine contains T1613.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1613.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1613",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1021": AttackTechnique(
        id="T1021",
        name="Remote Services",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Services (T1021) during the Lateral Movement phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Logon Session: Creation', 'Network Traffic: Connection'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1051",
                name="Hardening & Prevention for Remote Services",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2051",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Services -- selection CommandLine contains T1021",
                data_source="Logon Session: Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1021",
                data_source="Logon Session: Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1021.001": AttackTechnique(
        id="T1021.001",
        name="Remote Services: Process Memory Hollowing",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Services: Process Memory Hollowing (T1021.001) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Modification", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305101",
                name="Subtechnique Mitigation T1021.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Services: Process Memory Hollowing -- condition selection CommandLine contains T1021.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1021.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1021",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1021.002": AttackTechnique(
        id="T1021.002",
        name="Remote Services: Windows Access Token Theft",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Services: Windows Access Token Theft (T1021.002) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Token: Token Impersonation", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305102",
                name="Subtechnique Mitigation T1021.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Services: Windows Access Token Theft -- condition selection CommandLine contains T1021.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1021.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1021",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1021.003": AttackTechnique(
        id="T1021.003",
        name="Remote Services: NTLM Hash Pass-Through Replay",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Services: NTLM Hash Pass-Through Replay (T1021.003) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305103",
                name="Subtechnique Mitigation T1021.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Services: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1021.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1021.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1021",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1021.004": AttackTechnique(
        id="T1021.004",
        name="Remote Services: Active Directory Kerberoasting",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Services: Active Directory Kerberoasting (T1021.004) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305104",
                name="Subtechnique Mitigation T1021.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Services: Active Directory Kerberoasting -- condition selection CommandLine contains T1021.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1021.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT29', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1021",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1570": AttackTechnique(
        id="T1570",
        name="Lateral Tool Transfer",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Lateral Tool Transfer (T1570) during the Lateral Movement phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['File: File Creation', 'Network Traffic: Flow'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1052",
                name="Hardening & Prevention for Lateral Tool Transfer",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2052",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Lateral Tool Transfer -- selection CommandLine contains T1570",
                data_source="File: File Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1570",
                data_source="File: File Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1570.001": AttackTechnique(
        id="T1570.001",
        name="Lateral Tool Transfer: Kerberos AS-REP Roasting",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Lateral Tool Transfer: Kerberos AS-REP Roasting (T1570.001) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305201",
                name="Subtechnique Mitigation T1570.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Lateral Tool Transfer: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1570.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1570.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1570",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1570.002": AttackTechnique(
        id="T1570.002",
        name="Lateral Tool Transfer: Active Directory Golden Ticket",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Lateral Tool Transfer: Active Directory Golden Ticket (T1570.002) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305202",
                name="Subtechnique Mitigation T1570.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Lateral Tool Transfer: Active Directory Golden Ticket -- condition selection CommandLine contains T1570.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1570.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1570",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1570.003": AttackTechnique(
        id="T1570.003",
        name="Lateral Tool Transfer: Kerberos Service Silver Ticket",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Lateral Tool Transfer: Kerberos Service Silver Ticket (T1570.003) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305203",
                name="Subtechnique Mitigation T1570.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Lateral Tool Transfer: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1570.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1570.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1570",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1570.004": AttackTechnique(
        id="T1570.004",
        name="Lateral Tool Transfer: VSS Volume Shadow Deletion",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Lateral Tool Transfer: VSS Volume Shadow Deletion (T1570.004) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305204",
                name="Subtechnique Mitigation T1570.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Lateral Tool Transfer: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1570.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1570.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1570",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1550": AttackTechnique(
        id="T1550",
        name="Use Alternate Authentication Material",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Use Alternate Authentication Material (T1550) during the Lateral Movement phase to advance compromises across Windows, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Cloud'],
        data_sources=['Logon Session: Creation', 'Authentication: Ticket'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1053",
                name="Hardening & Prevention for Use Alternate Authentication Material",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2053",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Use Alternate Authentication Material -- selection CommandLine contains T1550",
                data_source="Logon Session: Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1550",
                data_source="Logon Session: Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1550.001": AttackTechnique(
        id="T1550.001",
        name="Use Alternate Authentication Material: Boot Configuration Tampering",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Use Alternate Authentication Material: Boot Configuration Tampering (T1550.001) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Process: Process Creation", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305301",
                name="Subtechnique Mitigation T1550.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Use Alternate Authentication Material: Boot Configuration Tampering -- condition selection CommandLine contains T1550.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1550.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1550",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1550.002": AttackTechnique(
        id="T1550.002",
        name="Use Alternate Authentication Material: High-Entropy AES Cryptor Loop",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Use Alternate Authentication Material: High-Entropy AES Cryptor Loop (T1550.002) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["File: File Modification", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305302",
                name="Subtechnique Mitigation T1550.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Use Alternate Authentication Material: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1550.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1550.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1550",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1550.003": AttackTechnique(
        id="T1550.003",
        name="Use Alternate Authentication Material: Audit Log Eviction and Shred",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Use Alternate Authentication Material: Audit Log Eviction and Shred (T1550.003) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Command: Command Execution", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305303",
                name="Subtechnique Mitigation T1550.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Use Alternate Authentication Material: Audit Log Eviction and Shred -- condition selection CommandLine contains T1550.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1550.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1550",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1550.004": AttackTechnique(
        id="T1550.004",
        name="Use Alternate Authentication Material: IAM Role Policy Assumption",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Use Alternate Authentication Material: IAM Role Policy Assumption (T1550.004) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Cloud Audit: CloudTrail", "Logon Session: Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305304",
                name="Subtechnique Mitigation T1550.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Use Alternate Authentication Material: IAM Role Policy Assumption -- condition selection CommandLine contains T1550.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1550.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1550",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1563": AttackTechnique(
        id="T1563",
        name="Remote Service Session Hijacking",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Service Session Hijacking (T1563) during the Lateral Movement phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['Logon Session: Hijack', 'Process: Process Creation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1054",
                name="Hardening & Prevention for Remote Service Session Hijacking",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2054",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Service Session Hijacking -- selection CommandLine contains T1563",
                data_source="Logon Session: Hijack",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1563",
                data_source="Logon Session: Hijack",
                log_event_id="1"
            )
        ],
        threat_actors=['APT33', 'FIN8'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1563.001": AttackTechnique(
        id="T1563.001",
        name="Remote Service Session Hijacking: S3 Storage Mass Data Extraction",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Service Session Hijacking: S3 Storage Mass Data Extraction (T1563.001) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Cloud Audit: CloudTrail", "Logon Session: Hijack"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305401",
                name="Subtechnique Mitigation T1563.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Service Session Hijacking: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1563.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1563.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT33', 'FIN8'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1563",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1563.002": AttackTechnique(
        id="T1563.002",
        name="Remote Service Session Hijacking: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Service Session Hijacking: Kubernetes Host PID Namespace Escape (T1563.002) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Container: Container Creation", "Logon Session: Hijack"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305402",
                name="Subtechnique Mitigation T1563.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Service Session Hijacking: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1563.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1563.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT33', 'FIN8'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1563",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1563.003": AttackTechnique(
        id="T1563.003",
        name="Remote Service Session Hijacking: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Service Session Hijacking: Asynchronous DNS TXT Data Exfil (T1563.003) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Network Traffic: DNS Query", "Logon Session: Hijack"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305403",
                name="Subtechnique Mitigation T1563.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Service Session Hijacking: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1563.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1563.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT33', 'FIN8'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1563",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1563.004": AttackTechnique(
        id="T1563.004",
        name="Remote Service Session Hijacking: PowerShell Execution Architecture",
        tactic_id="TA0008",
        tactic_name="Lateral Movement",
        description="""Adversaries execute Remote Service Session Hijacking: PowerShell Execution Architecture (T1563.004) during Lateral Movement. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Logon Session: Hijack"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305404",
                name="Subtechnique Mitigation T1563.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Remote Service Session Hijacking: PowerShell Execution Architecture -- condition selection CommandLine contains T1563.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1563.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT33', 'FIN8'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1563",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1115": AttackTechnique(
        id="T1115",
        name="Clipboard Data",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Clipboard Data (T1115) during the Collection phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Process: Process Access', 'Command: Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1055",
                name="Hardening & Prevention for Clipboard Data",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2055",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Clipboard Data -- selection CommandLine contains T1115",
                data_source="Process: Process Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1115",
                data_source="Process: Process Access",
                log_event_id="1"
            )
        ],
        threat_actors=['Lazarus Group', 'DarkHydrus'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1115.001": AttackTechnique(
        id="T1115.001",
        name="Clipboard Data: Command Prompt Batch Chaining",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Clipboard Data: Command Prompt Batch Chaining (T1115.001) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305501",
                name="Subtechnique Mitigation T1115.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Clipboard Data: Command Prompt Batch Chaining -- condition selection CommandLine contains T1115.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1115.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['Lazarus Group', 'DarkHydrus'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1115",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1115.002": AttackTechnique(
        id="T1115.002",
        name="Clipboard Data: Unix Shell Staged Pipeline",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Clipboard Data: Unix Shell Staged Pipeline (T1115.002) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305502",
                name="Subtechnique Mitigation T1115.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Clipboard Data: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1115.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1115.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['Lazarus Group', 'DarkHydrus'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1115",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1115.003": AttackTechnique(
        id="T1115.003",
        name="Clipboard Data: Python Direct Socket Shellcode",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Clipboard Data: Python Direct Socket Shellcode (T1115.003) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305503",
                name="Subtechnique Mitigation T1115.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Clipboard Data: Python Direct Socket Shellcode -- condition selection CommandLine contains T1115.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1115.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['Lazarus Group', 'DarkHydrus'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1115",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1115.004": AttackTechnique(
        id="T1115.004",
        name="Clipboard Data: DLL Search Order Hijacking",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Clipboard Data: DLL Search Order Hijacking (T1115.004) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "Process: Process Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305504",
                name="Subtechnique Mitigation T1115.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Clipboard Data: DLL Search Order Hijacking -- condition selection CommandLine contains T1115.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1115.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['Lazarus Group', 'DarkHydrus'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1115",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1056": AttackTechnique(
        id="T1056",
        name="Input Capture",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Input Capture (T1056) during the Collection phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Driver: Driver Load', 'Process: Process Modification'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1056",
                name="Hardening & Prevention for Input Capture",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2056",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Input Capture -- selection CommandLine contains T1056",
                data_source="Driver: Driver Load",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1056",
                data_source="Driver: Driver Load",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1056.001": AttackTechnique(
        id="T1056.001",
        name="Input Capture: Process Memory Hollowing",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Input Capture: Process Memory Hollowing (T1056.001) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Modification", "Driver: Driver Load"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305601",
                name="Subtechnique Mitigation T1056.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Input Capture: Process Memory Hollowing -- condition selection CommandLine contains T1056.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1056.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1056",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1056.002": AttackTechnique(
        id="T1056.002",
        name="Input Capture: Windows Access Token Theft",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Input Capture: Windows Access Token Theft (T1056.002) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Token: Token Impersonation", "Driver: Driver Load"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305602",
                name="Subtechnique Mitigation T1056.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Input Capture: Windows Access Token Theft -- condition selection CommandLine contains T1056.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1056.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1056",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1056.003": AttackTechnique(
        id="T1056.003",
        name="Input Capture: NTLM Hash Pass-Through Replay",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Input Capture: NTLM Hash Pass-Through Replay (T1056.003) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Driver: Driver Load"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305603",
                name="Subtechnique Mitigation T1056.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Input Capture: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1056.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1056.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1056",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1056.004": AttackTechnique(
        id="T1056.004",
        name="Input Capture: Active Directory Kerberoasting",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Input Capture: Active Directory Kerberoasting (T1056.004) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "Driver: Driver Load"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305604",
                name="Subtechnique Mitigation T1056.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Input Capture: Active Directory Kerberoasting -- condition selection CommandLine contains T1056.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1056.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['APT28', 'FIN7'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1056",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1005": AttackTechnique(
        id="T1005",
        name="Data from Local System",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Local System (T1005) during the Collection phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['File: File Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1057",
                name="Hardening & Prevention for Data from Local System",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2057",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Local System -- selection CommandLine contains T1005",
                data_source="File: File Access",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1005",
                data_source="File: File Access",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.LOW,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "LOW" == "CRITICAL" else 7.1
    ),
    "T1005.001": AttackTechnique(
        id="T1005.001",
        name="Data from Local System: Kerberos AS-REP Roasting",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Local System: Kerberos AS-REP Roasting (T1005.001) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305701",
                name="Subtechnique Mitigation T1005.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Local System: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1005.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1005.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1005",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1005.002": AttackTechnique(
        id="T1005.002",
        name="Data from Local System: Active Directory Golden Ticket",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Local System: Active Directory Golden Ticket (T1005.002) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305702",
                name="Subtechnique Mitigation T1005.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Local System: Active Directory Golden Ticket -- condition selection CommandLine contains T1005.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1005.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1005",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1005.003": AttackTechnique(
        id="T1005.003",
        name="Data from Local System: Kerberos Service Silver Ticket",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Local System: Kerberos Service Silver Ticket (T1005.003) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305703",
                name="Subtechnique Mitigation T1005.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Local System: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1005.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1005.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1005",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1005.004": AttackTechnique(
        id="T1005.004",
        name="Data from Local System: VSS Volume Shadow Deletion",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Local System: VSS Volume Shadow Deletion (T1005.004) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "File: File Access"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305704",
                name="Subtechnique Mitigation T1005.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Local System: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1005.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1005.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT29', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1005",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1114": AttackTechnique(
        id="T1114",
        name="Email Collection",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Email Collection (T1114) during the Collection phase to advance compromises across Office 365, Exchange. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Office 365', 'Exchange'],
        data_sources=['Application Log: Mailbox', 'Cloud Audit: Graph API'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1058",
                name="Hardening & Prevention for Email Collection",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2058",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Email Collection -- selection CommandLine contains T1114",
                data_source="Application Log: Mailbox",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1114",
                data_source="Application Log: Mailbox",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'SolarWinds Actor'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1114.001": AttackTechnique(
        id="T1114.001",
        name="Email Collection: Boot Configuration Tampering",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Email Collection: Boot Configuration Tampering (T1114.001) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Office 365', 'Exchange'],
        data_sources=["Process: Process Creation", "Application Log: Mailbox"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305801",
                name="Subtechnique Mitigation T1114.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Email Collection: Boot Configuration Tampering -- condition selection CommandLine contains T1114.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1114.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'SolarWinds Actor'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1114",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1114.002": AttackTechnique(
        id="T1114.002",
        name="Email Collection: High-Entropy AES Cryptor Loop",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Email Collection: High-Entropy AES Cryptor Loop (T1114.002) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Office 365', 'Exchange'],
        data_sources=["File: File Modification", "Application Log: Mailbox"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305802",
                name="Subtechnique Mitigation T1114.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Email Collection: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1114.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1114.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT28', 'SolarWinds Actor'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1114",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1114.003": AttackTechnique(
        id="T1114.003",
        name="Email Collection: Audit Log Eviction and Shred",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Email Collection: Audit Log Eviction and Shred (T1114.003) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Office 365', 'Exchange'],
        data_sources=["Command: Command Execution", "Application Log: Mailbox"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305803",
                name="Subtechnique Mitigation T1114.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Email Collection: Audit Log Eviction and Shred -- condition selection CommandLine contains T1114.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1114.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT28', 'SolarWinds Actor'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1114",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1114.004": AttackTechnique(
        id="T1114.004",
        name="Email Collection: IAM Role Policy Assumption",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Email Collection: IAM Role Policy Assumption (T1114.004) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Office 365', 'Exchange'],
        data_sources=["Cloud Audit: CloudTrail", "Application Log: Mailbox"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305804",
                name="Subtechnique Mitigation T1114.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Email Collection: IAM Role Policy Assumption -- condition selection CommandLine contains T1114.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1114.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT28', 'SolarWinds Actor'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1114",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1530": AttackTechnique(
        id="T1530",
        name="Data from Cloud Storage",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Cloud Storage (T1530) during the Collection phase to advance compromises across AWS S3, Azure Blob, GCP. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['AWS S3', 'Azure Blob', 'GCP'],
        data_sources=['Cloud Audit: S3 GetObject', 'Storage: Access'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1059",
                name="Hardening & Prevention for Data from Cloud Storage",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2059",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Cloud Storage -- selection CommandLine contains T1530",
                data_source="Cloud Audit: S3 GetObject",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1530",
                data_source="Cloud Audit: S3 GetObject",
                log_event_id="1"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1530.001": AttackTechnique(
        id="T1530.001",
        name="Data from Cloud Storage: S3 Storage Mass Data Extraction",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Cloud Storage: S3 Storage Mass Data Extraction (T1530.001) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['AWS S3', 'Azure Blob', 'GCP'],
        data_sources=["Cloud Audit: CloudTrail", "Cloud Audit: S3 GetObject"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305901",
                name="Subtechnique Mitigation T1530.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Cloud Storage: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1530.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1530.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1530",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1530.002": AttackTechnique(
        id="T1530.002",
        name="Data from Cloud Storage: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Cloud Storage: Kubernetes Host PID Namespace Escape (T1530.002) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['AWS S3', 'Azure Blob', 'GCP'],
        data_sources=["Container: Container Creation", "Cloud Audit: S3 GetObject"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305902",
                name="Subtechnique Mitigation T1530.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Cloud Storage: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1530.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1530.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1530",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1530.003": AttackTechnique(
        id="T1530.003",
        name="Data from Cloud Storage: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Cloud Storage: Asynchronous DNS TXT Data Exfil (T1530.003) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['AWS S3', 'Azure Blob', 'GCP'],
        data_sources=["Network Traffic: DNS Query", "Cloud Audit: S3 GetObject"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305903",
                name="Subtechnique Mitigation T1530.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Cloud Storage: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1530.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1530.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1530",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1530.004": AttackTechnique(
        id="T1530.004",
        name="Data from Cloud Storage: PowerShell Execution Architecture",
        tactic_id="TA0009",
        tactic_name="Collection",
        description="""Adversaries execute Data from Cloud Storage: PowerShell Execution Architecture (T1530.004) during Collection. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['AWS S3', 'Azure Blob', 'GCP'],
        data_sources=["Process: Process Creation", "Cloud Audit: S3 GetObject"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M305904",
                name="Subtechnique Mitigation T1530.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M405904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data from Cloud Storage: PowerShell Execution Architecture -- condition selection CommandLine contains T1530.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1530.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1530",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1071": AttackTechnique(
        id="T1071",
        name="Application Layer Protocol",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Application Layer Protocol (T1071) during the Command and Control phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Network Traffic: HTTP/HTTPS', 'Network Traffic: DNS'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1060",
                name="Hardening & Prevention for Application Layer Protocol",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2060",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Application Layer Protocol -- selection CommandLine contains T1071",
                data_source="Network Traffic: HTTP/HTTPS",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1071",
                data_source="Network Traffic: HTTP/HTTPS",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1071.001": AttackTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Command Prompt Batch Chaining",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Application Layer Protocol: Command Prompt Batch Chaining (T1071.001) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: HTTP/HTTPS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306001",
                name="Subtechnique Mitigation T1071.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Application Layer Protocol: Command Prompt Batch Chaining -- condition selection CommandLine contains T1071.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1071.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1071",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1071.002": AttackTechnique(
        id="T1071.002",
        name="Application Layer Protocol: Unix Shell Staged Pipeline",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Application Layer Protocol: Unix Shell Staged Pipeline (T1071.002) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: HTTP/HTTPS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306002",
                name="Subtechnique Mitigation T1071.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Application Layer Protocol: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1071.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1071.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1071",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1071.003": AttackTechnique(
        id="T1071.003",
        name="Application Layer Protocol: Python Direct Socket Shellcode",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Application Layer Protocol: Python Direct Socket Shellcode (T1071.003) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: HTTP/HTTPS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306003",
                name="Subtechnique Mitigation T1071.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Application Layer Protocol: Python Direct Socket Shellcode -- condition selection CommandLine contains T1071.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1071.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1071",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1071.004": AttackTechnique(
        id="T1071.004",
        name="Application Layer Protocol: DLL Search Order Hijacking",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Application Layer Protocol: DLL Search Order Hijacking (T1071.004) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "Network Traffic: HTTP/HTTPS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306004",
                name="Subtechnique Mitigation T1071.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Application Layer Protocol: DLL Search Order Hijacking -- condition selection CommandLine contains T1071.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1071.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT28', 'Cobalt Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1071",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1573": AttackTechnique(
        id="T1573",
        name="Encrypted Channel",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Encrypted Channel (T1573) during the Command and Control phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Network Traffic: TLS Content'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1061",
                name="Hardening & Prevention for Encrypted Channel",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2061",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Encrypted Channel -- selection CommandLine contains T1573",
                data_source="Network Traffic: TLS Content",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1573",
                data_source="Network Traffic: TLS Content",
                log_event_id="1"
            )
        ],
        threat_actors=['Lazarus Group', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1573.001": AttackTechnique(
        id="T1573.001",
        name="Encrypted Channel: Process Memory Hollowing",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Encrypted Channel: Process Memory Hollowing (T1573.001) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Modification", "Network Traffic: TLS Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306101",
                name="Subtechnique Mitigation T1573.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Encrypted Channel: Process Memory Hollowing -- condition selection CommandLine contains T1573.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1573.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['Lazarus Group', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1573",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1573.002": AttackTechnique(
        id="T1573.002",
        name="Encrypted Channel: Windows Access Token Theft",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Encrypted Channel: Windows Access Token Theft (T1573.002) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Token: Token Impersonation", "Network Traffic: TLS Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306102",
                name="Subtechnique Mitigation T1573.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Encrypted Channel: Windows Access Token Theft -- condition selection CommandLine contains T1573.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1573.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['Lazarus Group', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1573",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1573.003": AttackTechnique(
        id="T1573.003",
        name="Encrypted Channel: NTLM Hash Pass-Through Replay",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Encrypted Channel: NTLM Hash Pass-Through Replay (T1573.003) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "Network Traffic: TLS Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306103",
                name="Subtechnique Mitigation T1573.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Encrypted Channel: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1573.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1573.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['Lazarus Group', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1573",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1573.004": AttackTechnique(
        id="T1573.004",
        name="Encrypted Channel: Active Directory Kerberoasting",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Encrypted Channel: Active Directory Kerberoasting (T1573.004) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: TLS Content"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306104",
                name="Subtechnique Mitigation T1573.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Encrypted Channel: Active Directory Kerberoasting -- condition selection CommandLine contains T1573.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1573.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['Lazarus Group', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1573",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1105": AttackTechnique(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Ingress Tool Transfer (T1105) during the Command and Control phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Creation', 'Network Traffic: Flow'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1062",
                name="Hardening & Prevention for Ingress Tool Transfer",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2062",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Ingress Tool Transfer -- selection CommandLine contains T1105",
                data_source="File: File Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1105",
                data_source="File: File Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1105.001": AttackTechnique(
        id="T1105.001",
        name="Ingress Tool Transfer: Kerberos AS-REP Roasting",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Ingress Tool Transfer: Kerberos AS-REP Roasting (T1105.001) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Active Directory: Kerberos Request", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306201",
                name="Subtechnique Mitigation T1105.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Ingress Tool Transfer: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1105.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1105.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1105",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1105.002": AttackTechnique(
        id="T1105.002",
        name="Ingress Tool Transfer: Active Directory Golden Ticket",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Ingress Tool Transfer: Active Directory Golden Ticket (T1105.002) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306202",
                name="Subtechnique Mitigation T1105.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Ingress Tool Transfer: Active Directory Golden Ticket -- condition selection CommandLine contains T1105.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1105.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1105",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1105.003": AttackTechnique(
        id="T1105.003",
        name="Ingress Tool Transfer: Kerberos Service Silver Ticket",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Ingress Tool Transfer: Kerberos Service Silver Ticket (T1105.003) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Authentication: User Authentication", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306203",
                name="Subtechnique Mitigation T1105.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Ingress Tool Transfer: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1105.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1105.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1105",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1105.004": AttackTechnique(
        id="T1105.004",
        name="Ingress Tool Transfer: VSS Volume Shadow Deletion",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Ingress Tool Transfer: VSS Volume Shadow Deletion (T1105.004) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306204",
                name="Subtechnique Mitigation T1105.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Ingress Tool Transfer: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1105.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1105.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT28', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1105",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1572": AttackTechnique(
        id="T1572",
        name="Protocol Tunneling",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Protocol Tunneling (T1572) during the Command and Control phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Network Traffic: Encapsulation'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1063",
                name="Hardening & Prevention for Protocol Tunneling",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2063",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Protocol Tunneling -- selection CommandLine contains T1572",
                data_source="Network Traffic: Encapsulation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1572",
                data_source="Network Traffic: Encapsulation",
                log_event_id="1"
            )
        ],
        threat_actors=['APT32', 'OilRig'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1572.001": AttackTechnique(
        id="T1572.001",
        name="Protocol Tunneling: Boot Configuration Tampering",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Protocol Tunneling: Boot Configuration Tampering (T1572.001) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Network Traffic: Encapsulation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306301",
                name="Subtechnique Mitigation T1572.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406301",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Protocol Tunneling: Boot Configuration Tampering -- condition selection CommandLine contains T1572.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1572.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['APT32', 'OilRig'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1572",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1572.002": AttackTechnique(
        id="T1572.002",
        name="Protocol Tunneling: High-Entropy AES Cryptor Loop",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Protocol Tunneling: High-Entropy AES Cryptor Loop (T1572.002) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["File: File Modification", "Network Traffic: Encapsulation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306302",
                name="Subtechnique Mitigation T1572.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406302",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Protocol Tunneling: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1572.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1572.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['APT32', 'OilRig'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1572",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1572.003": AttackTechnique(
        id="T1572.003",
        name="Protocol Tunneling: Audit Log Eviction and Shred",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Protocol Tunneling: Audit Log Eviction and Shred (T1572.003) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Command: Command Execution", "Network Traffic: Encapsulation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306303",
                name="Subtechnique Mitigation T1572.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406303",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Protocol Tunneling: Audit Log Eviction and Shred -- condition selection CommandLine contains T1572.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1572.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['APT32', 'OilRig'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1572",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1572.004": AttackTechnique(
        id="T1572.004",
        name="Protocol Tunneling: IAM Role Policy Assumption",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Protocol Tunneling: IAM Role Policy Assumption (T1572.004) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Network Traffic: Encapsulation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306304",
                name="Subtechnique Mitigation T1572.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406304",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Protocol Tunneling: IAM Role Policy Assumption -- condition selection CommandLine contains T1572.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1572.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['APT32', 'OilRig'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1572",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1090": AttackTechnique(
        id="T1090",
        name="Proxy",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Proxy (T1090) during the Command and Control phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Network Traffic: Multi-hop SOCKS'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1064",
                name="Hardening & Prevention for Proxy",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2064",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Proxy -- selection CommandLine contains T1090",
                data_source="Network Traffic: Multi-hop SOCKS",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1090",
                data_source="Network Traffic: Multi-hop SOCKS",
                log_event_id="1"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1090.001": AttackTechnique(
        id="T1090.001",
        name="Proxy: S3 Storage Mass Data Extraction",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Proxy: S3 Storage Mass Data Extraction (T1090.001) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "Network Traffic: Multi-hop SOCKS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306401",
                name="Subtechnique Mitigation T1090.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406401",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Proxy: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1090.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1090.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1090",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1090.002": AttackTechnique(
        id="T1090.002",
        name="Proxy: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Proxy: Kubernetes Host PID Namespace Escape (T1090.002) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Container: Container Creation", "Network Traffic: Multi-hop SOCKS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306402",
                name="Subtechnique Mitigation T1090.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406402",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Proxy: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1090.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1090.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1090",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1090.003": AttackTechnique(
        id="T1090.003",
        name="Proxy: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Proxy: Asynchronous DNS TXT Data Exfil (T1090.003) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Network Traffic: DNS Query", "Network Traffic: Multi-hop SOCKS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306403",
                name="Subtechnique Mitigation T1090.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406403",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Proxy: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1090.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1090.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1090",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1090.004": AttackTechnique(
        id="T1090.004",
        name="Proxy: PowerShell Execution Architecture",
        tactic_id="TA0011",
        tactic_name="Command and Control",
        description="""Adversaries execute Proxy: PowerShell Execution Architecture (T1090.004) during Command and Control. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: Multi-hop SOCKS"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306404",
                name="Subtechnique Mitigation T1090.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406404",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Proxy: PowerShell Execution Architecture -- condition selection CommandLine contains T1090.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1090.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['APT29', 'Turla'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1090",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1041": AttackTechnique(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over C2 Channel (T1041) during the Exfiltration phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['Network Traffic: Flow Rate'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1065",
                name="Hardening & Prevention for Exfiltration Over C2 Channel",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2065",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over C2 Channel -- selection CommandLine contains T1041",
                data_source="Network Traffic: Flow Rate",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1041",
                data_source="Network Traffic: Flow Rate",
                log_event_id="1"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1041.001": AttackTechnique(
        id="T1041.001",
        name="Exfiltration Over C2 Channel: Command Prompt Batch Chaining",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over C2 Channel: Command Prompt Batch Chaining (T1041.001) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: Flow Rate"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306501",
                name="Subtechnique Mitigation T1041.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406501",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over C2 Channel: Command Prompt Batch Chaining -- condition selection CommandLine contains T1041.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1041.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1041",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1041.002": AttackTechnique(
        id="T1041.002",
        name="Exfiltration Over C2 Channel: Unix Shell Staged Pipeline",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over C2 Channel: Unix Shell Staged Pipeline (T1041.002) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: Flow Rate"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306502",
                name="Subtechnique Mitigation T1041.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406502",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over C2 Channel: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1041.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1041.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1041",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1041.003": AttackTechnique(
        id="T1041.003",
        name="Exfiltration Over C2 Channel: Python Direct Socket Shellcode",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over C2 Channel: Python Direct Socket Shellcode (T1041.003) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "Network Traffic: Flow Rate"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306503",
                name="Subtechnique Mitigation T1041.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406503",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over C2 Channel: Python Direct Socket Shellcode -- condition selection CommandLine contains T1041.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1041.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1041",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1041.004": AttackTechnique(
        id="T1041.004",
        name="Exfiltration Over C2 Channel: DLL Search Order Hijacking",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over C2 Channel: DLL Search Order Hijacking (T1041.004) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Module: Module Load", "Network Traffic: Flow Rate"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306504",
                name="Subtechnique Mitigation T1041.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406504",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over C2 Channel: DLL Search Order Hijacking -- condition selection CommandLine contains T1041.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1041.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['APT28', 'Lazarus Group'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1041",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1048": AttackTechnique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Alternative Protocol (T1048) during the Exfiltration phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Network Traffic: DNS / ICMP'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1066",
                name="Hardening & Prevention for Exfiltration Over Alternative Protocol",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2066",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Alternative Protocol -- selection CommandLine contains T1048",
                data_source="Network Traffic: DNS / ICMP",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1048",
                data_source="Network Traffic: DNS / ICMP",
                log_event_id="1"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1048.001": AttackTechnique(
        id="T1048.001",
        name="Exfiltration Over Alternative Protocol: Process Memory Hollowing",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Alternative Protocol: Process Memory Hollowing (T1048.001) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Modification", "Network Traffic: DNS / ICMP"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306601",
                name="Subtechnique Mitigation T1048.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406601",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Alternative Protocol: Process Memory Hollowing -- condition selection CommandLine contains T1048.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1048.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1048",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1048.002": AttackTechnique(
        id="T1048.002",
        name="Exfiltration Over Alternative Protocol: Windows Access Token Theft",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Alternative Protocol: Windows Access Token Theft (T1048.002) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Token: Token Impersonation", "Network Traffic: DNS / ICMP"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306602",
                name="Subtechnique Mitigation T1048.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406602",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Alternative Protocol: Windows Access Token Theft -- condition selection CommandLine contains T1048.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1048.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1048",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1048.003": AttackTechnique(
        id="T1048.003",
        name="Exfiltration Over Alternative Protocol: NTLM Hash Pass-Through Replay",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Alternative Protocol: NTLM Hash Pass-Through Replay (T1048.003) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Network Traffic: DNS / ICMP"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306603",
                name="Subtechnique Mitigation T1048.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406603",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Alternative Protocol: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1048.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1048.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1048",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1048.004": AttackTechnique(
        id="T1048.004",
        name="Exfiltration Over Alternative Protocol: Active Directory Kerberoasting",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Alternative Protocol: Active Directory Kerberoasting (T1048.004) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: DNS / ICMP"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306604",
                name="Subtechnique Mitigation T1048.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406604",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Alternative Protocol: Active Directory Kerberoasting -- condition selection CommandLine contains T1048.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1048.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['FIN7', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1048",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1567": AttackTechnique(
        id="T1567",
        name="Exfiltration Over Web Service",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Web Service (T1567) during the Exfiltration phase to advance compromises across Windows, Cloud. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Cloud'],
        data_sources=['Network Traffic: Cloud Storage API'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1067",
                name="Hardening & Prevention for Exfiltration Over Web Service",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2067",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Web Service -- selection CommandLine contains T1567",
                data_source="Network Traffic: Cloud Storage API",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1567",
                data_source="Network Traffic: Cloud Storage API",
                log_event_id="1"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1567.001": AttackTechnique(
        id="T1567.001",
        name="Exfiltration Over Web Service: Kerberos AS-REP Roasting",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Web Service: Kerberos AS-REP Roasting (T1567.001) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Active Directory: Kerberos Request", "Network Traffic: Cloud Storage API"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306701",
                name="Subtechnique Mitigation T1567.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406701",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Web Service: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1567.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1567.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1567",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1567.002": AttackTechnique(
        id="T1567.002",
        name="Exfiltration Over Web Service: Active Directory Golden Ticket",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Web Service: Active Directory Golden Ticket (T1567.002) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Cloud Storage API"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306702",
                name="Subtechnique Mitigation T1567.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406702",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Web Service: Active Directory Golden Ticket -- condition selection CommandLine contains T1567.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1567.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1567",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1567.003": AttackTechnique(
        id="T1567.003",
        name="Exfiltration Over Web Service: Kerberos Service Silver Ticket",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Web Service: Kerberos Service Silver Ticket (T1567.003) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Authentication: User Authentication", "Network Traffic: Cloud Storage API"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306703",
                name="Subtechnique Mitigation T1567.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406703",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Web Service: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1567.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1567.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1567",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1567.004": AttackTechnique(
        id="T1567.004",
        name="Exfiltration Over Web Service: VSS Volume Shadow Deletion",
        tactic_id="TA0010",
        tactic_name="Exfiltration",
        description="""Adversaries execute Exfiltration Over Web Service: VSS Volume Shadow Deletion (T1567.004) during Exfiltration. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Cloud'],
        data_sources=["Process: Process Creation", "Network Traffic: Cloud Storage API"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306704",
                name="Subtechnique Mitigation T1567.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406704",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Exfiltration Over Web Service: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1567.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1567.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Scattered Spider', 'Lapsus$'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1567",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1486": AttackTechnique(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Encrypted for Impact (T1486) during the Impact phase to advance compromises across Windows, Linux, macOS. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=['File: File Modification', 'File: File Deletion'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1068",
                name="Hardening & Prevention for Data Encrypted for Impact",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2068",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Encrypted for Impact -- selection CommandLine contains T1486",
                data_source="File: File Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1486",
                data_source="File: File Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit', 'BlackCat'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1486.001": AttackTechnique(
        id="T1486.001",
        name="Data Encrypted for Impact: Boot Configuration Tampering",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Encrypted for Impact: Boot Configuration Tampering (T1486.001) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Process: Process Creation", "File: File Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306801",
                name="Subtechnique Mitigation T1486.001",
                description="Block unauthorized invocation of Boot Configuration Tampering using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406801",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Boot Configuration Tampering via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Encrypted for Impact: Boot Configuration Tampering -- condition selection CommandLine contains T1486.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1486.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit', 'BlackCat'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1486",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1486.002": AttackTechnique(
        id="T1486.002",
        name="Data Encrypted for Impact: High-Entropy AES Cryptor Loop",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Encrypted for Impact: High-Entropy AES Cryptor Loop (T1486.002) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["File: File Modification", "File: File Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306802",
                name="Subtechnique Mitigation T1486.002",
                description="Block unauthorized invocation of High-Entropy AES Cryptor Loop using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406802",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of High-Entropy AES Cryptor Loop via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Encrypted for Impact: High-Entropy AES Cryptor Loop -- condition selection CommandLine contains T1486.002",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1486.002* and event.action: process_created",
                data_source="File: File Modification",
                log_event_id="EDR Ransomware Detection"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit', 'BlackCat'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1486",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1486.003": AttackTechnique(
        id="T1486.003",
        name="Data Encrypted for Impact: Audit Log Eviction and Shred",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Encrypted for Impact: Audit Log Eviction and Shred (T1486.003) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Command: Command Execution", "File: File Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306803",
                name="Subtechnique Mitigation T1486.003",
                description="Block unauthorized invocation of Audit Log Eviction and Shred using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406803",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Audit Log Eviction and Shred via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Encrypted for Impact: Audit Log Eviction and Shred -- condition selection CommandLine contains T1486.003",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1486.003* and event.action: process_created",
                data_source="Command: Command Execution",
                log_event_id="Event ID 1102 / Auditd"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit', 'BlackCat'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1486",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1486.004": AttackTechnique(
        id="T1486.004",
        name="Data Encrypted for Impact: IAM Role Policy Assumption",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Encrypted for Impact: IAM Role Policy Assumption (T1486.004) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux', 'macOS'],
        data_sources=["Cloud Audit: CloudTrail", "File: File Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306804",
                name="Subtechnique Mitigation T1486.004",
                description="Block unauthorized invocation of IAM Role Policy Assumption using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406804",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of IAM Role Policy Assumption via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Encrypted for Impact: IAM Role Policy Assumption -- condition selection CommandLine contains T1486.004",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1486.004* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail AssumeRole Event"
            )
        ],
        threat_actors=['Wizard Spider', 'LockBit', 'BlackCat'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1486",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1489": AttackTechnique(
        id="T1489",
        name="Service Stop",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Service Stop (T1489) during the Impact phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Service: Modification', 'Process: Termination'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1069",
                name="Hardening & Prevention for Service Stop",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2069",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Service Stop -- selection CommandLine contains T1489",
                data_source="Service: Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1489",
                data_source="Service: Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "HIGH" == "CRITICAL" else 7.1
    ),
    "T1489.001": AttackTechnique(
        id="T1489.001",
        name="Service Stop: S3 Storage Mass Data Extraction",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Service Stop: S3 Storage Mass Data Extraction (T1489.001) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Cloud Audit: CloudTrail", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306901",
                name="Subtechnique Mitigation T1489.001",
                description="Block unauthorized invocation of S3 Storage Mass Data Extraction using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406901",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of S3 Storage Mass Data Extraction via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Service Stop: S3 Storage Mass Data Extraction -- condition selection CommandLine contains T1489.001",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1489.001* and event.action: process_created",
                data_source="Cloud Audit: CloudTrail",
                log_event_id="CloudTrail GetObject Burst"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1489",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1489.002": AttackTechnique(
        id="T1489.002",
        name="Service Stop: Kubernetes Host PID Namespace Escape",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Service Stop: Kubernetes Host PID Namespace Escape (T1489.002) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Container: Container Creation", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306902",
                name="Subtechnique Mitigation T1489.002",
                description="Block unauthorized invocation of Kubernetes Host PID Namespace Escape using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406902",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kubernetes Host PID Namespace Escape via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Service Stop: Kubernetes Host PID Namespace Escape -- condition selection CommandLine contains T1489.002",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1489.002* and event.action: process_created",
                data_source="Container: Container Creation",
                log_event_id="K8s API Audit Log"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1489",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1489.003": AttackTechnique(
        id="T1489.003",
        name="Service Stop: Asynchronous DNS TXT Data Exfil",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Service Stop: Asynchronous DNS TXT Data Exfil (T1489.003) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Network Traffic: DNS Query", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306903",
                name="Subtechnique Mitigation T1489.003",
                description="Block unauthorized invocation of Asynchronous DNS TXT Data Exfil using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406903",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Asynchronous DNS TXT Data Exfil via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Service Stop: Asynchronous DNS TXT Data Exfil -- condition selection CommandLine contains T1489.003",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1489.003* and event.action: process_created",
                data_source="Network Traffic: DNS Query",
                log_event_id="Zeek DNS.log / Pi-hole"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1489",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1489.004": AttackTechnique(
        id="T1489.004",
        name="Service Stop: PowerShell Execution Architecture",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Service Stop: PowerShell Execution Architecture (T1489.004) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Creation", "Service: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M306904",
                name="Subtechnique Mitigation T1489.004",
                description="Block unauthorized invocation of PowerShell Execution Architecture using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M406904",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of PowerShell Execution Architecture via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Service Stop: PowerShell Execution Architecture -- condition selection CommandLine contains T1489.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1489.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 / Sysmon 1"
            )
        ],
        threat_actors=['Sandworm Team', 'Wizard Spider'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1489",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1490": AttackTechnique(
        id="T1490",
        name="Inhibit System Recovery",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Inhibit System Recovery (T1490) during the Impact phase to advance compromises across Windows. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows'],
        data_sources=['Process: Process Creation', 'Command: Execution'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1070",
                name="Hardening & Prevention for Inhibit System Recovery",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2070",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Inhibit System Recovery -- selection CommandLine contains T1490",
                data_source="Process: Process Creation",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1490",
                data_source="Process: Process Creation",
                log_event_id="1"
            )
        ],
        threat_actors=['Wizard Spider', 'DarkSide'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1490.001": AttackTechnique(
        id="T1490.001",
        name="Inhibit System Recovery: Command Prompt Batch Chaining",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Inhibit System Recovery: Command Prompt Batch Chaining (T1490.001) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307001",
                name="Subtechnique Mitigation T1490.001",
                description="Block unauthorized invocation of Command Prompt Batch Chaining using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407001",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Command Prompt Batch Chaining via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Inhibit System Recovery: Command Prompt Batch Chaining -- condition selection CommandLine contains T1490.001",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1490.001* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688"
            )
        ],
        threat_actors=['Wizard Spider', 'DarkSide'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1490",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1490.002": AttackTechnique(
        id="T1490.002",
        name="Inhibit System Recovery: Unix Shell Staged Pipeline",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Inhibit System Recovery: Unix Shell Staged Pipeline (T1490.002) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307002",
                name="Subtechnique Mitigation T1490.002",
                description="Block unauthorized invocation of Unix Shell Staged Pipeline using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407002",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Unix Shell Staged Pipeline via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Inhibit System Recovery: Unix Shell Staged Pipeline -- condition selection CommandLine contains T1490.002",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1490.002* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Linux Auditd EXECVE"
            )
        ],
        threat_actors=['Wizard Spider', 'DarkSide'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1490",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1490.003": AttackTechnique(
        id="T1490.003",
        name="Inhibit System Recovery: Python Direct Socket Shellcode",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Inhibit System Recovery: Python Direct Socket Shellcode (T1490.003) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Process: Process Creation", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307003",
                name="Subtechnique Mitigation T1490.003",
                description="Block unauthorized invocation of Python Direct Socket Shellcode using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407003",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Python Direct Socket Shellcode via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Inhibit System Recovery: Python Direct Socket Shellcode -- condition selection CommandLine contains T1490.003",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1490.003* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Sysmon Linux Event 1"
            )
        ],
        threat_actors=['Wizard Spider', 'DarkSide'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1490",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1490.004": AttackTechnique(
        id="T1490.004",
        name="Inhibit System Recovery: DLL Search Order Hijacking",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Inhibit System Recovery: DLL Search Order Hijacking (T1490.004) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows'],
        data_sources=["Module: Module Load", "Process: Process Creation"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307004",
                name="Subtechnique Mitigation T1490.004",
                description="Block unauthorized invocation of DLL Search Order Hijacking using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407004",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of DLL Search Order Hijacking via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Inhibit System Recovery: DLL Search Order Hijacking -- condition selection CommandLine contains T1490.004",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1490.004* and event.action: process_created",
                data_source="Module: Module Load",
                log_event_id="Sysmon Event 7 (ImageLoad)"
            )
        ],
        threat_actors=['Wizard Spider', 'DarkSide'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1490",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1485": AttackTechnique(
        id="T1485",
        name="Data Destruction",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Destruction (T1485) during the Impact phase to advance compromises across Windows, Linux. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Windows', 'Linux'],
        data_sources=['Drive: Modification', 'File: Deletion'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1071",
                name="Hardening & Prevention for Data Destruction",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2071",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Destruction -- selection CommandLine contains T1485",
                data_source="Drive: Modification",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1485",
                data_source="Drive: Modification",
                log_event_id="1"
            )
        ],
        threat_actors=['Sandworm Team', 'HermeticWiper'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "CRITICAL" == "CRITICAL" else 7.1
    ),
    "T1485.001": AttackTechnique(
        id="T1485.001",
        name="Data Destruction: Process Memory Hollowing",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Destruction: Process Memory Hollowing (T1485.001) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Process: Process Modification", "Drive: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307101",
                name="Subtechnique Mitigation T1485.001",
                description="Block unauthorized invocation of Process Memory Hollowing using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407101",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Process Memory Hollowing via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Destruction: Process Memory Hollowing -- condition selection CommandLine contains T1485.001",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1485.001* and event.action: process_created",
                data_source="Process: Process Modification",
                log_event_id="Sysmon Event 10 / EDR Memory"
            )
        ],
        threat_actors=['Sandworm Team', 'HermeticWiper'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1485",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1485.002": AttackTechnique(
        id="T1485.002",
        name="Data Destruction: Windows Access Token Theft",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Destruction: Windows Access Token Theft (T1485.002) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Token: Token Impersonation", "Drive: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307102",
                name="Subtechnique Mitigation T1485.002",
                description="Block unauthorized invocation of Windows Access Token Theft using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407102",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Windows Access Token Theft via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Destruction: Windows Access Token Theft -- condition selection CommandLine contains T1485.002",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1485.002* and event.action: process_created",
                data_source="Token: Token Impersonation",
                log_event_id="Event ID 4624 / Type 9"
            )
        ],
        threat_actors=['Sandworm Team', 'HermeticWiper'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1485",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1485.003": AttackTechnique(
        id="T1485.003",
        name="Data Destruction: NTLM Hash Pass-Through Replay",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Destruction: NTLM Hash Pass-Through Replay (T1485.003) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Authentication: User Authentication", "Drive: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307103",
                name="Subtechnique Mitigation T1485.003",
                description="Block unauthorized invocation of NTLM Hash Pass-Through Replay using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407103",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of NTLM Hash Pass-Through Replay via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Destruction: NTLM Hash Pass-Through Replay -- condition selection CommandLine contains T1485.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1485.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / NTLM"
            )
        ],
        threat_actors=['Sandworm Team', 'HermeticWiper'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1485",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1485.004": AttackTechnique(
        id="T1485.004",
        name="Data Destruction: Active Directory Kerberoasting",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Data Destruction: Active Directory Kerberoasting (T1485.004) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Windows', 'Linux'],
        data_sources=["Active Directory: Kerberos Request", "Drive: Modification"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307104",
                name="Subtechnique Mitigation T1485.004",
                description="Block unauthorized invocation of Active Directory Kerberoasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407104",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Kerberoasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Data Destruction: Active Directory Kerberoasting -- condition selection CommandLine contains T1485.004",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1485.004* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4769 Ticket Options 0x40810000"
            )
        ],
        threat_actors=['Sandworm Team', 'HermeticWiper'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1485",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1496": AttackTechnique(
        id="T1496",
        name="Resource Hijacking",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Resource Hijacking (T1496) during the Impact phase to advance compromises across Cloud, Linux, Containers. Threat actors bypass edge perimeters and manipulate infrastructure to establish operational persistence.""",
        platforms=['Cloud', 'Linux', 'Containers'],
        data_sources=['Process: High CPU Utilization', 'Cloud Audit: Compute'],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M1072",
                name="Hardening & Prevention for Resource Hijacking",
                description="Enforce strict RBAC controls, apply software restriction policies, disable unused features, and patch software components.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M2072",
                name="Telemetry & Audit Logging",
                description="Configure detailed audit logging, centralize telemetry in SIEM, and correlate event anomalies with threat intelligence feeds.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Resource Hijacking -- selection CommandLine contains T1496",
                data_source="Process: High CPU Utilization",
                log_event_id="4688"
            ),
            DetectionRuleTemplate(
                query_type="Splunk SPL",
                query="index=security sourcetype=WinEventLog (EventCode=4688 OR EventCode=1) | search T1496",
                data_source="Process: High CPU Utilization",
                log_event_id="1"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.MEDIUM,
        subtechnique=False,
        parent_technique_id=None,
        cvss_score_impact=8.8 if "MEDIUM" == "CRITICAL" else 7.1
    ),
    "T1496.001": AttackTechnique(
        id="T1496.001",
        name="Resource Hijacking: Kerberos AS-REP Roasting",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Resource Hijacking: Kerberos AS-REP Roasting (T1496.001) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'Linux', 'Containers'],
        data_sources=["Active Directory: Kerberos Request", "Process: High CPU Utilization"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307201",
                name="Subtechnique Mitigation T1496.001",
                description="Block unauthorized invocation of Kerberos AS-REP Roasting using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407201",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos AS-REP Roasting via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Resource Hijacking: Kerberos AS-REP Roasting -- condition selection CommandLine contains T1496.001",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1496.001* and event.action: process_created",
                data_source="Active Directory: Kerberos Request",
                log_event_id="Event ID 4768 / Result 0x0"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1496",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1496.002": AttackTechnique(
        id="T1496.002",
        name="Resource Hijacking: Active Directory Golden Ticket",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Resource Hijacking: Active Directory Golden Ticket (T1496.002) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'Linux', 'Containers'],
        data_sources=["Authentication: User Authentication", "Process: High CPU Utilization"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307202",
                name="Subtechnique Mitigation T1496.002",
                description="Block unauthorized invocation of Active Directory Golden Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407202",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Active Directory Golden Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Resource Hijacking: Active Directory Golden Ticket -- condition selection CommandLine contains T1496.002",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1496.002* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4624 / 4672 Domain Admin"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1496",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
    "T1496.003": AttackTechnique(
        id="T1496.003",
        name="Resource Hijacking: Kerberos Service Silver Ticket",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Resource Hijacking: Kerberos Service Silver Ticket (T1496.003) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'Linux', 'Containers'],
        data_sources=["Authentication: User Authentication", "Process: High CPU Utilization"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307203",
                name="Subtechnique Mitigation T1496.003",
                description="Block unauthorized invocation of Kerberos Service Silver Ticket using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407203",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of Kerberos Service Silver Ticket via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Resource Hijacking: Kerberos Service Silver Ticket -- condition selection CommandLine contains T1496.003",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1496.003* and event.action: process_created",
                data_source="Authentication: User Authentication",
                log_event_id="Event ID 4769 Service Ticket"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.HIGH,
        subtechnique=True,
        parent_technique_id="T1496",
        cvss_score_impact=9.4 if "HIGH" == "CRITICAL" else 8.1
    ),
    "T1496.004": AttackTechnique(
        id="T1496.004",
        name="Resource Hijacking: VSS Volume Shadow Deletion",
        tactic_id="TA0040",
        tactic_name="Impact",
        description="""Adversaries execute Resource Hijacking: VSS Volume Shadow Deletion (T1496.004) during Impact. This subtechnique circumvents traditional perimeter controls and endpoint inspection policies.""",
        platforms=['Cloud', 'Linux', 'Containers'],
        data_sources=["Process: Process Creation", "Process: High CPU Utilization"],
        permissions_required=["User", "Administrator", "SYSTEM"],
        mitigations=[
            TechniqueMitigation(
                mitigation_id="M307204",
                name="Subtechnique Mitigation T1496.004",
                description="Block unauthorized invocation of VSS Volume Shadow Deletion using AppLocker/WDAC application control, SELinux enforcement, and zero-trust credentials.",
                control_type="Preventive"
            ),
            TechniqueMitigation(
                mitigation_id="M407204",
                name="Behavioral Anomaly Detection",
                description="Alert on abnormal invocations of VSS Volume Shadow Deletion via heuristic EDR telemetry and real-time SIEM thresholding.",
                control_type="Detective"
            )
        ],
        detection_rules=[
            DetectionRuleTemplate(
                query_type="Sigma",
                query="title: Detect Resource Hijacking: VSS Volume Shadow Deletion -- condition selection CommandLine contains T1496.004",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            ),
            DetectionRuleTemplate(
                query_type="Elastic KQL",
                query="process.command_line: *T1496.004* and event.action: process_created",
                data_source="Process: Process Creation",
                log_event_id="Event ID 4688 CommandLine"
            )
        ],
        threat_actors=['TeamTNT', 'Kinsing'],
        severity=SeverityLevel.CRITICAL,
        subtechnique=True,
        parent_technique_id="T1496",
        cvss_score_impact=9.4 if "CRITICAL" == "CRITICAL" else 8.1
    ),
}


class MitreAttackEngine:
    """Search, query, and analysis engine for MITRE ATT&CK Enterprise Matrix."""

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[AttackTechnique]:
        return TECHNIQUES_CATALOG.get(technique_id)

    @classmethod
    def get_tactic(cls, tactic_id: str) -> Optional[TacticMetadata]:
        return TACTICS_CATALOG.get(tactic_id)

    @classmethod
    def get_techniques_by_tactic(cls, tactic_id: str) -> List[AttackTechnique]:
        return [t for t in TECHNIQUES_CATALOG.values() if t.tactic_id == tactic_id]

    @classmethod
    def get_techniques_by_platform(cls, platform: str) -> List[AttackTechnique]:
        plat_lower = platform.lower()
        return [t for t in TECHNIQUES_CATALOG.values() if any(plat_lower in p.lower() for p in t.platforms)]

    @classmethod
    def get_techniques_by_actor(cls, actor_name: str) -> List[AttackTechnique]:
        actor_lower = actor_name.lower()
        return [t for t in TECHNIQUES_CATALOG.values() if any(actor_lower in a.lower() for a in t.threat_actors)]

    @classmethod
    def search_techniques(cls, keyword: str) -> List[AttackTechnique]:
        kw = keyword.lower()
        return [
            t for t in TECHNIQUES_CATALOG.values()
            if kw in t.id.lower() or kw in t.name.lower() or kw in t.description.lower()
        ]

    @classmethod
    def get_matrix_coverage_summary(cls) -> Dict[str, Any]:
        tactics_summary = {}
        for tid, meta in TACTICS_CATALOG.items():
            techs = cls.get_techniques_by_tactic(tid)
            tactics_summary[tid] = {
                "tactic_name": meta.name,
                "techniques_count": len(techs),
                "critical_count": sum(1 for t in techs if t.severity == SeverityLevel.CRITICAL),
                "high_count": sum(1 for t in techs if t.severity == SeverityLevel.HIGH),
                "subtechniques_count": sum(1 for t in techs if t.subtechnique),
            }
        return {
            "total_tactics": len(TACTICS_CATALOG),
            "total_techniques": len(TECHNIQUES_CATALOG),
            "tactics": tactics_summary
        }
