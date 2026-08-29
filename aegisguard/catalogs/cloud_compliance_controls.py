"""
Cloud Security Alliance (CSA) Cloud Controls Matrix (CCM v4.0) & ISO 27001 Framework Catalog.
Provides baseline controls, audit specifications, and automated posture verification checks.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class ControlLevel(str, Enum):
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class CloudControlDomain:
    code: str
    title: str
    description: str


@dataclass
class CloudSecurityControl:
    control_id: str
    domain_code: str
    title: str
    description: str
    implementation_guidance: str
    audit_specification: str
    mapped_iso_control: str
    level: ControlLevel
    is_applicable: bool = True
    evaluation_script: str = ""

    def __post_init__(self):
        if not self.evaluation_script:
            self.evaluation_script = f"audit_{self.domain_code.lower()}_{self.control_id.replace('-', '_').lower()}()"


CSA_DOMAINS: Dict[str, CloudControlDomain] = {
    "AIS": CloudControlDomain(
        code="AIS",
        title="Application & Interface Security",
        description="""Controls governing web services, APIs, and application lifecycle security."""
    ),
    "AAC": CloudControlDomain(
        code="AAC",
        title="Audit Assurance & Compliance",
        description="""Controls for independent assessment, audit logs, and continuous compliance monitoring."""
    ),
    "BCR": CloudControlDomain(
        code="BCR",
        title="Business Continuity Management & Operational Resilience",
        description="""Disaster recovery, backup procedures, and failover capabilities."""
    ),
    "CCC": CloudControlDomain(
        code="CCC",
        title="Change Control & Configuration Management",
        description="""Baseline configuration standards, change approvals, and release pipelines."""
    ),
    "CRY": CloudControlDomain(
        code="CRY",
        title="Cryptography, Encryption & Key Management",
        description="""Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit."""
    ),
    "DCS": CloudControlDomain(
        code="DCS",
        title="Datacenter Security",
        description="""Physical perimeter security, hardware decommissioning, and power redundancy."""
    ),
    "DSP": CloudControlDomain(
        code="DSP",
        title="Data Security & Privacy Lifecycle Management",
        description="""Data classification, handling, retention, anonymization, and DLP enforcement."""
    ),
    "GRM": CloudControlDomain(
        code="GRM",
        title="Governance, Risk & Compliance",
        description="""Enterprise risk management framework, policies, and executive oversight."""
    ),
    "HRS": CloudControlDomain(
        code="HRS",
        title="Human Resources Security",
        description="""Employee background checks, onboarding/offboarding, and security awareness training."""
    ),
    "IAM": CloudControlDomain(
        code="IAM",
        title="Identity & Access Management",
        description="""Least privilege, RBAC, multi-factor authentication, and privileged access workflows."""
    ),
    "IVS": CloudControlDomain(
        code="IVS",
        title="Infrastructure & Virtualization Security",
        description="""Hypervisor isolation, cloud VPC segmentation, and network boundary security."""
    ),
    "IPY": CloudControlDomain(
        code="IPY",
        title="Interoperability & Portability",
        description="""Data portability, standardized APIs, and cloud vendor lock-in mitigations."""
    ),
    "SEF": CloudControlDomain(
        code="SEF",
        title="Security Incident Management, E-Discovery & Forensics",
        description="""Incident response plans, triage, root-cause forensic investigations, and notification."""
    ),
    "MOS": CloudControlDomain(
        code="MOS",
        title="Mobile Security",
        description="""Device posture validation, mobile application management (MAM), and remote wipe capabilities."""
    ),
    "STA": CloudControlDomain(
        code="STA",
        title="Supply Chain Management, Transparency & Accountability",
        description="""Third-party vendor risk assessment, SBOM verification, and sub-processor tracking."""
    ),
    "TVM": CloudControlDomain(
        code="TVM",
        title="Threat & Vulnerability Management",
        description="""Continuous vulnerability scanning, penetration testing, and automated patch cadence."""
    ),
    "UEM": CloudControlDomain(
        code="UEM",
        title="Universal Endpoint Management",
        description="""EDR sensor telemetry, host firewall hardening, and USB peripheral controls."""
    ),
}

CLOUD_CONTROLS_CATALOG: Dict[str, CloudSecurityControl] = {
    "CCM4-AIS-01": CloudSecurityControl(
        control_id="CCM4-AIS-01",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 1",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AIS-02": CloudSecurityControl(
        control_id="CCM4-AIS-02",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 2",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-AIS-03": CloudSecurityControl(
        control_id="CCM4-AIS-03",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 3",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AIS-04": CloudSecurityControl(
        control_id="CCM4-AIS-04",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 4",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-AIS-05": CloudSecurityControl(
        control_id="CCM4-AIS-05",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 5",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AIS-06": CloudSecurityControl(
        control_id="CCM4-AIS-06",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 6",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-AIS-07": CloudSecurityControl(
        control_id="CCM4-AIS-07",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 7",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AIS-08": CloudSecurityControl(
        control_id="CCM4-AIS-08",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 8",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-AIS-09": CloudSecurityControl(
        control_id="CCM4-AIS-09",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 9",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AIS-10": CloudSecurityControl(
        control_id="CCM4-AIS-10",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 10",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-AIS-11": CloudSecurityControl(
        control_id="CCM4-AIS-11",
        domain_code="AIS",
        title="Application & Interface Security Standard Control 11",
        description="""The organization shall implement and continuously enforce application & interface security specifications across cloud workloads: Controls governing web services, APIs, and application lifecycle security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AIS-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ais_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-01": CloudSecurityControl(
        control_id="CCM4-AAC-01",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 1",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-02": CloudSecurityControl(
        control_id="CCM4-AAC-02",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 2",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-AAC-03": CloudSecurityControl(
        control_id="CCM4-AAC-03",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 3",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-04": CloudSecurityControl(
        control_id="CCM4-AAC-04",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 4",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-AAC-05": CloudSecurityControl(
        control_id="CCM4-AAC-05",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 5",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-06": CloudSecurityControl(
        control_id="CCM4-AAC-06",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 6",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-AAC-07": CloudSecurityControl(
        control_id="CCM4-AAC-07",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 7",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-08": CloudSecurityControl(
        control_id="CCM4-AAC-08",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 8",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-AAC-09": CloudSecurityControl(
        control_id="CCM4-AAC-09",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 9",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-AAC-10": CloudSecurityControl(
        control_id="CCM4-AAC-10",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 10",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-AAC-11": CloudSecurityControl(
        control_id="CCM4-AAC-11",
        domain_code="AAC",
        title="Audit Assurance & Compliance Standard Control 11",
        description="""The organization shall implement and continuously enforce audit assurance & compliance specifications across cloud workloads: Controls for independent assessment, audit logs, and continuous compliance monitoring.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-AAC-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of aac_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-01": CloudSecurityControl(
        control_id="CCM4-BCR-01",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 1",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-02": CloudSecurityControl(
        control_id="CCM4-BCR-02",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 2",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-BCR-03": CloudSecurityControl(
        control_id="CCM4-BCR-03",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 3",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-04": CloudSecurityControl(
        control_id="CCM4-BCR-04",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 4",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-BCR-05": CloudSecurityControl(
        control_id="CCM4-BCR-05",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 5",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-06": CloudSecurityControl(
        control_id="CCM4-BCR-06",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 6",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-BCR-07": CloudSecurityControl(
        control_id="CCM4-BCR-07",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 7",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-08": CloudSecurityControl(
        control_id="CCM4-BCR-08",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 8",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-BCR-09": CloudSecurityControl(
        control_id="CCM4-BCR-09",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 9",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-BCR-10": CloudSecurityControl(
        control_id="CCM4-BCR-10",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 10",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-BCR-11": CloudSecurityControl(
        control_id="CCM4-BCR-11",
        domain_code="BCR",
        title="Business Continuity Management & Operational Resilience Standard Control 11",
        description="""The organization shall implement and continuously enforce business continuity management & operational resilience specifications across cloud workloads: Disaster recovery, backup procedures, and failover capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-BCR-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of bcr_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-01": CloudSecurityControl(
        control_id="CCM4-CCC-01",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 1",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-02": CloudSecurityControl(
        control_id="CCM4-CCC-02",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 2",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-CCC-03": CloudSecurityControl(
        control_id="CCM4-CCC-03",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 3",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-04": CloudSecurityControl(
        control_id="CCM4-CCC-04",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 4",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-CCC-05": CloudSecurityControl(
        control_id="CCM4-CCC-05",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 5",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-06": CloudSecurityControl(
        control_id="CCM4-CCC-06",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 6",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-CCC-07": CloudSecurityControl(
        control_id="CCM4-CCC-07",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 7",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-08": CloudSecurityControl(
        control_id="CCM4-CCC-08",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 8",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-CCC-09": CloudSecurityControl(
        control_id="CCM4-CCC-09",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 9",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CCC-10": CloudSecurityControl(
        control_id="CCM4-CCC-10",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 10",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-CCC-11": CloudSecurityControl(
        control_id="CCM4-CCC-11",
        domain_code="CCC",
        title="Change Control & Configuration Management Standard Control 11",
        description="""The organization shall implement and continuously enforce change control & configuration management specifications across cloud workloads: Baseline configuration standards, change approvals, and release pipelines.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CCC-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ccc_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-01": CloudSecurityControl(
        control_id="CCM4-CRY-01",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 1",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-02": CloudSecurityControl(
        control_id="CCM4-CRY-02",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 2",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-CRY-03": CloudSecurityControl(
        control_id="CCM4-CRY-03",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 3",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-04": CloudSecurityControl(
        control_id="CCM4-CRY-04",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 4",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-CRY-05": CloudSecurityControl(
        control_id="CCM4-CRY-05",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 5",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-06": CloudSecurityControl(
        control_id="CCM4-CRY-06",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 6",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-CRY-07": CloudSecurityControl(
        control_id="CCM4-CRY-07",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 7",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-08": CloudSecurityControl(
        control_id="CCM4-CRY-08",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 8",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-CRY-09": CloudSecurityControl(
        control_id="CCM4-CRY-09",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 9",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-CRY-10": CloudSecurityControl(
        control_id="CCM4-CRY-10",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 10",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-CRY-11": CloudSecurityControl(
        control_id="CCM4-CRY-11",
        domain_code="CRY",
        title="Cryptography, Encryption & Key Management Standard Control 11",
        description="""The organization shall implement and continuously enforce cryptography, encryption & key management specifications across cloud workloads: Cryptographic protocols, PKI, key lifecycle management, and encryption at rest/transit.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-CRY-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of cry_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-01": CloudSecurityControl(
        control_id="CCM4-DCS-01",
        domain_code="DCS",
        title="Datacenter Security Standard Control 1",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-02": CloudSecurityControl(
        control_id="CCM4-DCS-02",
        domain_code="DCS",
        title="Datacenter Security Standard Control 2",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-DCS-03": CloudSecurityControl(
        control_id="CCM4-DCS-03",
        domain_code="DCS",
        title="Datacenter Security Standard Control 3",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-04": CloudSecurityControl(
        control_id="CCM4-DCS-04",
        domain_code="DCS",
        title="Datacenter Security Standard Control 4",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-DCS-05": CloudSecurityControl(
        control_id="CCM4-DCS-05",
        domain_code="DCS",
        title="Datacenter Security Standard Control 5",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-06": CloudSecurityControl(
        control_id="CCM4-DCS-06",
        domain_code="DCS",
        title="Datacenter Security Standard Control 6",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-DCS-07": CloudSecurityControl(
        control_id="CCM4-DCS-07",
        domain_code="DCS",
        title="Datacenter Security Standard Control 7",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-08": CloudSecurityControl(
        control_id="CCM4-DCS-08",
        domain_code="DCS",
        title="Datacenter Security Standard Control 8",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-DCS-09": CloudSecurityControl(
        control_id="CCM4-DCS-09",
        domain_code="DCS",
        title="Datacenter Security Standard Control 9",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DCS-10": CloudSecurityControl(
        control_id="CCM4-DCS-10",
        domain_code="DCS",
        title="Datacenter Security Standard Control 10",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-DCS-11": CloudSecurityControl(
        control_id="CCM4-DCS-11",
        domain_code="DCS",
        title="Datacenter Security Standard Control 11",
        description="""The organization shall implement and continuously enforce datacenter security specifications across cloud workloads: Physical perimeter security, hardware decommissioning, and power redundancy.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DCS-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dcs_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-01": CloudSecurityControl(
        control_id="CCM4-DSP-01",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 1",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-02": CloudSecurityControl(
        control_id="CCM4-DSP-02",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 2",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-DSP-03": CloudSecurityControl(
        control_id="CCM4-DSP-03",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 3",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-04": CloudSecurityControl(
        control_id="CCM4-DSP-04",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 4",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-DSP-05": CloudSecurityControl(
        control_id="CCM4-DSP-05",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 5",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-06": CloudSecurityControl(
        control_id="CCM4-DSP-06",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 6",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-DSP-07": CloudSecurityControl(
        control_id="CCM4-DSP-07",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 7",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-08": CloudSecurityControl(
        control_id="CCM4-DSP-08",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 8",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-DSP-09": CloudSecurityControl(
        control_id="CCM4-DSP-09",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 9",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-DSP-10": CloudSecurityControl(
        control_id="CCM4-DSP-10",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 10",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-DSP-11": CloudSecurityControl(
        control_id="CCM4-DSP-11",
        domain_code="DSP",
        title="Data Security & Privacy Lifecycle Management Standard Control 11",
        description="""The organization shall implement and continuously enforce data security & privacy lifecycle management specifications across cloud workloads: Data classification, handling, retention, anonymization, and DLP enforcement.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-DSP-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of dsp_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-01": CloudSecurityControl(
        control_id="CCM4-GRM-01",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 1",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-02": CloudSecurityControl(
        control_id="CCM4-GRM-02",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 2",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-GRM-03": CloudSecurityControl(
        control_id="CCM4-GRM-03",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 3",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-04": CloudSecurityControl(
        control_id="CCM4-GRM-04",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 4",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-GRM-05": CloudSecurityControl(
        control_id="CCM4-GRM-05",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 5",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-06": CloudSecurityControl(
        control_id="CCM4-GRM-06",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 6",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-GRM-07": CloudSecurityControl(
        control_id="CCM4-GRM-07",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 7",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-08": CloudSecurityControl(
        control_id="CCM4-GRM-08",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 8",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-GRM-09": CloudSecurityControl(
        control_id="CCM4-GRM-09",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 9",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-GRM-10": CloudSecurityControl(
        control_id="CCM4-GRM-10",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 10",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-GRM-11": CloudSecurityControl(
        control_id="CCM4-GRM-11",
        domain_code="GRM",
        title="Governance, Risk & Compliance Standard Control 11",
        description="""The organization shall implement and continuously enforce governance, risk & compliance specifications across cloud workloads: Enterprise risk management framework, policies, and executive oversight.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-GRM-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of grm_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-01": CloudSecurityControl(
        control_id="CCM4-HRS-01",
        domain_code="HRS",
        title="Human Resources Security Standard Control 1",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-02": CloudSecurityControl(
        control_id="CCM4-HRS-02",
        domain_code="HRS",
        title="Human Resources Security Standard Control 2",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-HRS-03": CloudSecurityControl(
        control_id="CCM4-HRS-03",
        domain_code="HRS",
        title="Human Resources Security Standard Control 3",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-04": CloudSecurityControl(
        control_id="CCM4-HRS-04",
        domain_code="HRS",
        title="Human Resources Security Standard Control 4",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-HRS-05": CloudSecurityControl(
        control_id="CCM4-HRS-05",
        domain_code="HRS",
        title="Human Resources Security Standard Control 5",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-06": CloudSecurityControl(
        control_id="CCM4-HRS-06",
        domain_code="HRS",
        title="Human Resources Security Standard Control 6",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-HRS-07": CloudSecurityControl(
        control_id="CCM4-HRS-07",
        domain_code="HRS",
        title="Human Resources Security Standard Control 7",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-08": CloudSecurityControl(
        control_id="CCM4-HRS-08",
        domain_code="HRS",
        title="Human Resources Security Standard Control 8",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-HRS-09": CloudSecurityControl(
        control_id="CCM4-HRS-09",
        domain_code="HRS",
        title="Human Resources Security Standard Control 9",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-HRS-10": CloudSecurityControl(
        control_id="CCM4-HRS-10",
        domain_code="HRS",
        title="Human Resources Security Standard Control 10",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-HRS-11": CloudSecurityControl(
        control_id="CCM4-HRS-11",
        domain_code="HRS",
        title="Human Resources Security Standard Control 11",
        description="""The organization shall implement and continuously enforce human resources security specifications across cloud workloads: Employee background checks, onboarding/offboarding, and security awareness training.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-HRS-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of hrs_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-01": CloudSecurityControl(
        control_id="CCM4-IAM-01",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 1",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-02": CloudSecurityControl(
        control_id="CCM4-IAM-02",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 2",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-IAM-03": CloudSecurityControl(
        control_id="CCM4-IAM-03",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 3",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-04": CloudSecurityControl(
        control_id="CCM4-IAM-04",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 4",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-IAM-05": CloudSecurityControl(
        control_id="CCM4-IAM-05",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 5",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-06": CloudSecurityControl(
        control_id="CCM4-IAM-06",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 6",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-IAM-07": CloudSecurityControl(
        control_id="CCM4-IAM-07",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 7",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-08": CloudSecurityControl(
        control_id="CCM4-IAM-08",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 8",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-IAM-09": CloudSecurityControl(
        control_id="CCM4-IAM-09",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 9",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IAM-10": CloudSecurityControl(
        control_id="CCM4-IAM-10",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 10",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-IAM-11": CloudSecurityControl(
        control_id="CCM4-IAM-11",
        domain_code="IAM",
        title="Identity & Access Management Standard Control 11",
        description="""The organization shall implement and continuously enforce identity & access management specifications across cloud workloads: Least privilege, RBAC, multi-factor authentication, and privileged access workflows.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IAM-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of iam_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-01": CloudSecurityControl(
        control_id="CCM4-IVS-01",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 1",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-02": CloudSecurityControl(
        control_id="CCM4-IVS-02",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 2",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-IVS-03": CloudSecurityControl(
        control_id="CCM4-IVS-03",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 3",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-04": CloudSecurityControl(
        control_id="CCM4-IVS-04",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 4",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-IVS-05": CloudSecurityControl(
        control_id="CCM4-IVS-05",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 5",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-06": CloudSecurityControl(
        control_id="CCM4-IVS-06",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 6",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-IVS-07": CloudSecurityControl(
        control_id="CCM4-IVS-07",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 7",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-08": CloudSecurityControl(
        control_id="CCM4-IVS-08",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 8",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-IVS-09": CloudSecurityControl(
        control_id="CCM4-IVS-09",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 9",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IVS-10": CloudSecurityControl(
        control_id="CCM4-IVS-10",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 10",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-IVS-11": CloudSecurityControl(
        control_id="CCM4-IVS-11",
        domain_code="IVS",
        title="Infrastructure & Virtualization Security Standard Control 11",
        description="""The organization shall implement and continuously enforce infrastructure & virtualization security specifications across cloud workloads: Hypervisor isolation, cloud VPC segmentation, and network boundary security.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IVS-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ivs_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-01": CloudSecurityControl(
        control_id="CCM4-IPY-01",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 1",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-02": CloudSecurityControl(
        control_id="CCM4-IPY-02",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 2",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-IPY-03": CloudSecurityControl(
        control_id="CCM4-IPY-03",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 3",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-04": CloudSecurityControl(
        control_id="CCM4-IPY-04",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 4",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-IPY-05": CloudSecurityControl(
        control_id="CCM4-IPY-05",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 5",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-06": CloudSecurityControl(
        control_id="CCM4-IPY-06",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 6",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-IPY-07": CloudSecurityControl(
        control_id="CCM4-IPY-07",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 7",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-08": CloudSecurityControl(
        control_id="CCM4-IPY-08",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 8",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-IPY-09": CloudSecurityControl(
        control_id="CCM4-IPY-09",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 9",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-IPY-10": CloudSecurityControl(
        control_id="CCM4-IPY-10",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 10",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-IPY-11": CloudSecurityControl(
        control_id="CCM4-IPY-11",
        domain_code="IPY",
        title="Interoperability & Portability Standard Control 11",
        description="""The organization shall implement and continuously enforce interoperability & portability specifications across cloud workloads: Data portability, standardized APIs, and cloud vendor lock-in mitigations.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-IPY-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of ipy_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-01": CloudSecurityControl(
        control_id="CCM4-SEF-01",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 1",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-02": CloudSecurityControl(
        control_id="CCM4-SEF-02",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 2",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-SEF-03": CloudSecurityControl(
        control_id="CCM4-SEF-03",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 3",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-04": CloudSecurityControl(
        control_id="CCM4-SEF-04",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 4",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-SEF-05": CloudSecurityControl(
        control_id="CCM4-SEF-05",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 5",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-06": CloudSecurityControl(
        control_id="CCM4-SEF-06",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 6",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-SEF-07": CloudSecurityControl(
        control_id="CCM4-SEF-07",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 7",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-08": CloudSecurityControl(
        control_id="CCM4-SEF-08",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 8",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-SEF-09": CloudSecurityControl(
        control_id="CCM4-SEF-09",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 9",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-SEF-10": CloudSecurityControl(
        control_id="CCM4-SEF-10",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 10",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-SEF-11": CloudSecurityControl(
        control_id="CCM4-SEF-11",
        domain_code="SEF",
        title="Security Incident Management, E-Discovery & Forensics Standard Control 11",
        description="""The organization shall implement and continuously enforce security incident management, e-discovery & forensics specifications across cloud workloads: Incident response plans, triage, root-cause forensic investigations, and notification.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-SEF-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sef_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-01": CloudSecurityControl(
        control_id="CCM4-MOS-01",
        domain_code="MOS",
        title="Mobile Security Standard Control 1",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-02": CloudSecurityControl(
        control_id="CCM4-MOS-02",
        domain_code="MOS",
        title="Mobile Security Standard Control 2",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-MOS-03": CloudSecurityControl(
        control_id="CCM4-MOS-03",
        domain_code="MOS",
        title="Mobile Security Standard Control 3",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-04": CloudSecurityControl(
        control_id="CCM4-MOS-04",
        domain_code="MOS",
        title="Mobile Security Standard Control 4",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-MOS-05": CloudSecurityControl(
        control_id="CCM4-MOS-05",
        domain_code="MOS",
        title="Mobile Security Standard Control 5",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-06": CloudSecurityControl(
        control_id="CCM4-MOS-06",
        domain_code="MOS",
        title="Mobile Security Standard Control 6",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-MOS-07": CloudSecurityControl(
        control_id="CCM4-MOS-07",
        domain_code="MOS",
        title="Mobile Security Standard Control 7",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-08": CloudSecurityControl(
        control_id="CCM4-MOS-08",
        domain_code="MOS",
        title="Mobile Security Standard Control 8",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-MOS-09": CloudSecurityControl(
        control_id="CCM4-MOS-09",
        domain_code="MOS",
        title="Mobile Security Standard Control 9",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-MOS-10": CloudSecurityControl(
        control_id="CCM4-MOS-10",
        domain_code="MOS",
        title="Mobile Security Standard Control 10",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-MOS-11": CloudSecurityControl(
        control_id="CCM4-MOS-11",
        domain_code="MOS",
        title="Mobile Security Standard Control 11",
        description="""The organization shall implement and continuously enforce mobile security specifications across cloud workloads: Device posture validation, mobile application management (MAM), and remote wipe capabilities.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-MOS-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of mos_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-01": CloudSecurityControl(
        control_id="CCM4-STA-01",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 1",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-02": CloudSecurityControl(
        control_id="CCM4-STA-02",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 2",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-STA-03": CloudSecurityControl(
        control_id="CCM4-STA-03",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 3",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-04": CloudSecurityControl(
        control_id="CCM4-STA-04",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 4",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-STA-05": CloudSecurityControl(
        control_id="CCM4-STA-05",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 5",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-06": CloudSecurityControl(
        control_id="CCM4-STA-06",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 6",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-STA-07": CloudSecurityControl(
        control_id="CCM4-STA-07",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 7",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-08": CloudSecurityControl(
        control_id="CCM4-STA-08",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 8",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-STA-09": CloudSecurityControl(
        control_id="CCM4-STA-09",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 9",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-STA-10": CloudSecurityControl(
        control_id="CCM4-STA-10",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 10",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-STA-11": CloudSecurityControl(
        control_id="CCM4-STA-11",
        domain_code="STA",
        title="Supply Chain Management, Transparency & Accountability Standard Control 11",
        description="""The organization shall implement and continuously enforce supply chain management, transparency & accountability specifications across cloud workloads: Third-party vendor risk assessment, SBOM verification, and sub-processor tracking.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-STA-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of sta_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-01": CloudSecurityControl(
        control_id="CCM4-TVM-01",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 1",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-02": CloudSecurityControl(
        control_id="CCM4-TVM-02",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 2",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-TVM-03": CloudSecurityControl(
        control_id="CCM4-TVM-03",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 3",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-04": CloudSecurityControl(
        control_id="CCM4-TVM-04",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 4",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-TVM-05": CloudSecurityControl(
        control_id="CCM4-TVM-05",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 5",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-06": CloudSecurityControl(
        control_id="CCM4-TVM-06",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 6",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-TVM-07": CloudSecurityControl(
        control_id="CCM4-TVM-07",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 7",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-08": CloudSecurityControl(
        control_id="CCM4-TVM-08",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 8",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-TVM-09": CloudSecurityControl(
        control_id="CCM4-TVM-09",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 9",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-TVM-10": CloudSecurityControl(
        control_id="CCM4-TVM-10",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 10",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-TVM-11": CloudSecurityControl(
        control_id="CCM4-TVM-11",
        domain_code="TVM",
        title="Threat & Vulnerability Management Standard Control 11",
        description="""The organization shall implement and continuously enforce threat & vulnerability management specifications across cloud workloads: Continuous vulnerability scanning, penetration testing, and automated patch cadence.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-TVM-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of tvm_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-01": CloudSecurityControl(
        control_id="CCM4-UEM-01",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 1",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-01. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_1 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.2",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-02": CloudSecurityControl(
        control_id="CCM4-UEM-02",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 2",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-02. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_2 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.3",
        level=ControlLevel.HIGH
    ),
    "CCM4-UEM-03": CloudSecurityControl(
        control_id="CCM4-UEM-03",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 3",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-03. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_3 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.4",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-04": CloudSecurityControl(
        control_id="CCM4-UEM-04",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 4",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-04. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_4 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.9.5",
        level=ControlLevel.HIGH
    ),
    "CCM4-UEM-05": CloudSecurityControl(
        control_id="CCM4-UEM-05",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 5",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-05. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_5 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.10.6",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-06": CloudSecurityControl(
        control_id="CCM4-UEM-06",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 6",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-06. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_6 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.11.7",
        level=ControlLevel.HIGH
    ),
    "CCM4-UEM-07": CloudSecurityControl(
        control_id="CCM4-UEM-07",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 7",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-07. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_7 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.12.8",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-08": CloudSecurityControl(
        control_id="CCM4-UEM-08",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 8",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-08. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_8 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.5.9",
        level=ControlLevel.HIGH
    ),
    "CCM4-UEM-09": CloudSecurityControl(
        control_id="CCM4-UEM-09",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 9",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-09. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_9 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.6.10",
        level=ControlLevel.CRITICAL
    ),
    "CCM4-UEM-10": CloudSecurityControl(
        control_id="CCM4-UEM-10",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 10",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-10. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_10 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.7.11",
        level=ControlLevel.HIGH
    ),
    "CCM4-UEM-11": CloudSecurityControl(
        control_id="CCM4-UEM-11",
        domain_code="UEM",
        title="Universal Endpoint Management Standard Control 11",
        description="""The organization shall implement and continuously enforce universal endpoint management specifications across cloud workloads: EDR sensor telemetry, host firewall hardening, and USB peripheral controls.""",
        implementation_guidance="""Deploy automated continuous monitoring to verify compliance with CCM4-UEM-11. Ensure telemetry is forwarded to centralized SIEM.""",
        audit_specification="""Verify configuration of uem_policy_11 against cloud provider API endpoints.""",
        mapped_iso_control="ISO-27001-A.8.12",
        level=ControlLevel.CRITICAL
    ),
}


class CloudComplianceEngine:
    """Auditing and compliance verification engine for CSA CCM and ISO 27001."""

    @classmethod
    def get_control(cls, control_id: str) -> Optional[CloudSecurityControl]:
        return CLOUD_CONTROLS_CATALOG.get(control_id)

    @classmethod
    def get_controls_by_domain(cls, domain_code: str) -> List[CloudSecurityControl]:
        return [c for c in CLOUD_CONTROLS_CATALOG.values() if c.domain_code == domain_code]

    @classmethod
    def get_critical_controls(cls) -> List[CloudSecurityControl]:
        return [c for c in CLOUD_CONTROLS_CATALOG.values() if c.level == ControlLevel.CRITICAL]

    @classmethod
    def search(cls, query: str) -> List[CloudSecurityControl]:
        q = query.lower()
        return [
            c for c in CLOUD_CONTROLS_CATALOG.values()
            if q in c.control_id.lower() or q in c.title.lower() or q in c.description.lower()
        ]

    @classmethod
    def audit_framework_readiness(cls, passing_control_ids: Set[str]) -> Dict[str, Any]:
        total = len(CLOUD_CONTROLS_CATALOG)
        passed = sum(1 for cid in passing_control_ids if cid in CLOUD_CONTROLS_CATALOG)
        score_pct = round((passed / total) * 100, 2) if total else 0.0

        return {
            "total_controls": total,
            "passed_controls": passed,
            "failed_controls": total - passed,
            "readiness_percent": score_pct,
            "status": "COMPLIANT" if score_pct >= 90 else ("ACTION_REQUIRED" if score_pct >= 70 else "NON_COMPLIANT")
        }

    @classmethod
    def get_framework_summary(cls) -> Dict[str, Any]:
        domains = {}
        for c in CLOUD_CONTROLS_CATALOG.values():
            domains[c.domain_code] = domains.get(c.domain_code, 0) + 1

        return {
            "total_controls": len(CLOUD_CONTROLS_CATALOG),
            "total_domains": len(CSA_DOMAINS),
            "critical_controls_count": sum(1 for c in CLOUD_CONTROLS_CATALOG.values() if c.level == ControlLevel.CRITICAL),
            "high_controls_count": sum(1 for c in CLOUD_CONTROLS_CATALOG.values() if c.level == ControlLevel.HIGH),
            "domain_breakdown": domains
        }
