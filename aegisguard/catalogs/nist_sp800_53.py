"""
NIST SP 800-53 Rev 5 Enterprise Security and Privacy Controls Catalog.
Comprehensive technical controls across all 20 families with baselines,
enhancements, audit verification objectives, and compliance scoring.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set


class BaselineImpact(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    PRIVACY = "PRIVACY"


@dataclass(frozen=True)
class ControlFamily:
    id: str
    name: str
    description: str


@dataclass
class ControlEnhancement:
    enhancement_id: str
    name: str
    description: str
    baseline_impact: List[BaselineImpact]


@dataclass
class AssessmentObjective:
    objective_id: str
    determination_statement: str
    method: str


@dataclass
class NistControl:
    id: str
    family_id: str
    family_name: str
    title: str
    statement: str
    baseline_impact: List[BaselineImpact]
    enhancements: List[ControlEnhancement]
    assessment_objectives: List[AssessmentObjective]
    audit_procedure: str
    mapped_cwe: List[str]
    mapped_mitre: List[str]
    supplemental_guidance: str


FAMILIES_CATALOG: Dict[str, ControlFamily] = {
    "AC": ControlFamily(
        id="AC",
        name="Access Control",
        description="""Policies, account management, separation of duties, least privilege, session lock, remote access."""
    ),
    "AT": ControlFamily(
        id="AT",
        name="Awareness and Training",
        description="""Security awareness training, role-based training, training records and tracking."""
    ),
    "AU": ControlFamily(
        id="AU",
        name="Audit and Accountability",
        description="""Event logging, audit generation, audit review and correlation, timestamp synchronization."""
    ),
    "CA": ControlFamily(
        id="CA",
        name="Assessment, Authorization, and Monitoring",
        description="""Security assessments, authorization to operate, continuous monitoring, penetration testing."""
    ),
    "CM": ControlFamily(
        id="CM",
        name="Configuration Management",
        description="""Baseline configuration, configuration change control, security impact analysis, least functionality."""
    ),
    "CP": ControlFamily(
        id="CP",
        name="Contingency Planning",
        description="""Contingency plan development, testing, backups, alternate storage and processing sites."""
    ),
    "IA": ControlFamily(
        id="IA",
        name="Identification and Authentication",
        description="""User identification, multi-factor authentication, cryptographic authenticators, replay-resistant tokens."""
    ),
    "IR": ControlFamily(
        id="IR",
        name="Incident Response",
        description="""Incident response training, incident handling, incident monitoring, reporting, response assistance."""
    ),
    "MP": ControlFamily(
        id="MP",
        name="Media Protection",
        description="""Media access, marking, storage, media transport, media sanitization and cryptographic erasure."""
    ),
    "PE": ControlFamily(
        id="PE",
        name="Physical and Environmental Protection",
        description="""Physical access authorizations, monitoring, visitor access, emergency lighting, fire protection."""
    ),
    "PL": ControlFamily(
        id="PL",
        name="Planning",
        description="""System security plan development, review, update, and rules of behavior enforcement."""
    ),
    "PM": ControlFamily(
        id="PM",
        name="Program Management",
        description="""Enterprise information security program plan, senior information security officer role, metrics."""
    ),
    "PS": ControlFamily(
        id="PS",
        name="Personnel Security",
        description="""Personnel screening, termination, transfer, access agreements, third-party personnel security."""
    ),
    "PT": ControlFamily(
        id="PT",
        name="PII Processing and Transparency",
        description="""Authority to process PII, privacy notice, privacy risk assessments, consent management."""
    ),
    "RA": ControlFamily(
        id="RA",
        name="Risk Assessment",
        description="""Risk assessment policy, vulnerability scanning, risk response, threat awareness."""
    ),
    "SA": ControlFamily(
        id="SA",
        name="System and Services Acquisition",
        description="""Allocation of resources, system development life cycle, acquisition contracts, external services."""
    ),
    "SC": ControlFamily(
        id="SC",
        name="System and Communications Protection",
        description="""Boundary protection, transmission confidentiality and integrity, cryptographic key establishment."""
    ),
    "SI": ControlFamily(
        id="SI",
        name="System and Information Integrity",
        description="""Flaw remediation, malicious code protection, system monitoring, security alerts and advisories."""
    ),
    "SR": ControlFamily(
        id="SR",
        name="Supply Chain Risk Management",
        description="""Supply chain risk management plan, supplier reviews, counterfeit component mitigation."""
    ),
}

CONTROLS_CATALOG: Dict[str, NistControl] = {
    "AC-1": NistControl(
        id="AC-1",
        family_id="AC",
        family_name="Access Control",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (AC-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-1.""",
        mapped_cwe=['CWE-287'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-2": NistControl(
        id="AC-2",
        family_id="AC",
        family_name="Access Control",
        title="Account Management",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Account Management (AC-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-2(1)",
                name="Automated Verification for Account Management Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-2(2)",
                name="Automated Verification for Account Management Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-2(3)",
                name="Automated Verification for Account Management Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Account Management.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-2.""",
        mapped_cwe=['CWE-287', 'CWE-798'],
        mapped_mitre=['T1078', 'T1136'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-3": NistControl(
        id="AC-3",
        family_id="AC",
        family_name="Access Control",
        title="Access Enforcement",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Access Enforcement (AC-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-3(1)",
                name="Automated Verification for Access Enforcement Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-3(2)",
                name="Automated Verification for Access Enforcement Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-3(3)",
                name="Automated Verification for Access Enforcement Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Access Enforcement.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-3.""",
        mapped_cwe=['CWE-862', 'CWE-285'],
        mapped_mitre=['T1078', 'T1068'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-4": NistControl(
        id="AC-4",
        family_id="AC",
        family_name="Access Control",
        title="Information Flow Enforcement",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information Flow Enforcement (AC-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-4(1)",
                name="Automated Verification for Information Flow Enforcement Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-4(2)",
                name="Automated Verification for Information Flow Enforcement Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-4(3)",
                name="Automated Verification for Information Flow Enforcement Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information Flow Enforcement.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1048', 'T1041'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-5": NistControl(
        id="AC-5",
        family_id="AC",
        family_name="Access Control",
        title="Separation of Duties",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Separation of Duties (AC-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-5(1)",
                name="Automated Verification for Separation of Duties Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-5(2)",
                name="Automated Verification for Separation of Duties Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-5(3)",
                name="Automated Verification for Separation of Duties Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Separation of Duties.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-5.""",
        mapped_cwe=['CWE-862'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-6": NistControl(
        id="AC-6",
        family_id="AC",
        family_name="Access Control",
        title="Least Privilege",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Least Privilege (AC-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-6(1)",
                name="Automated Verification for Least Privilege Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-6(2)",
                name="Automated Verification for Least Privilege Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-6(3)",
                name="Automated Verification for Least Privilege Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Least Privilege.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-6.""",
        mapped_cwe=['CWE-250', 'CWE-732'],
        mapped_mitre=['T1548', 'T1134'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-7": NistControl(
        id="AC-7",
        family_id="AC",
        family_name="Access Control",
        title="Unsuccessful Logon Attempts",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Unsuccessful Logon Attempts (AC-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-7(1)",
                name="Automated Verification for Unsuccessful Logon Attempts Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-7(2)",
                name="Automated Verification for Unsuccessful Logon Attempts Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-7(3)",
                name="Automated Verification for Unsuccessful Logon Attempts Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Unsuccessful Logon Attempts.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-7.""",
        mapped_cwe=['CWE-307'],
        mapped_mitre=['T1110'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-8": NistControl(
        id="AC-8",
        family_id="AC",
        family_name="Access Control",
        title="System Use Notification",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Use Notification (AC-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-8(1)",
                name="Automated Verification for System Use Notification Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-8(2)",
                name="Automated Verification for System Use Notification Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-8(3)",
                name="Automated Verification for System Use Notification Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Use Notification.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-8.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-10": NistControl(
        id="AC-10",
        family_id="AC",
        family_name="Access Control",
        title="Concurrent Session Control",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Concurrent Session Control (AC-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-10(1)",
                name="Automated Verification for Concurrent Session Control Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-10(2)",
                name="Automated Verification for Concurrent Session Control Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-10(3)",
                name="Automated Verification for Concurrent Session Control Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Concurrent Session Control.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-10.""",
        mapped_cwe=['CWE-384'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-11": NistControl(
        id="AC-11",
        family_id="AC",
        family_name="Access Control",
        title="Device Lock",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Device Lock (AC-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-11(1)",
                name="Automated Verification for Device Lock Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-11(2)",
                name="Automated Verification for Device Lock Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-11(3)",
                name="Automated Verification for Device Lock Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Device Lock.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-11.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-12": NistControl(
        id="AC-12",
        family_id="AC",
        family_name="Access Control",
        title="Session Termination",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Session Termination (AC-12). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-12(1)",
                name="Automated Verification for Session Termination Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-12(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-12(2)",
                name="Automated Verification for Session Termination Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-12(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-12(3)",
                name="Automated Verification for Session Termination Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-12(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-12_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Session Termination.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-12_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-12.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-12.""",
        mapped_cwe=['CWE-613'],
        mapped_mitre=['T1563'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-12, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-14": NistControl(
        id="AC-14",
        family_id="AC",
        family_name="Access Control",
        title="Permitted Actions without Identification or Authentication",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Permitted Actions without Identification or Authentication (AC-14). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-14(1)",
                name="Automated Verification for Permitted Actions without Identification or Authentication Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-14(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-14(2)",
                name="Automated Verification for Permitted Actions without Identification or Authentication Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-14(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-14(3)",
                name="Automated Verification for Permitted Actions without Identification or Authentication Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-14(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-14_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Permitted Actions without Identification or Authentication.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-14_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-14.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-14.""",
        mapped_cwe=['CWE-306'],
        mapped_mitre=['T1190'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-14, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-17": NistControl(
        id="AC-17",
        family_id="AC",
        family_name="Access Control",
        title="Remote Access",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Remote Access (AC-17). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-17(1)",
                name="Automated Verification for Remote Access Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-17(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-17(2)",
                name="Automated Verification for Remote Access Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-17(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-17(3)",
                name="Automated Verification for Remote Access Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-17(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-17_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Remote Access.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-17_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-17.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-17.""",
        mapped_cwe=['CWE-287'],
        mapped_mitre=['T1133', 'T1021'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-17, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-18": NistControl(
        id="AC-18",
        family_id="AC",
        family_name="Access Control",
        title="Wireless Access",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Wireless Access (AC-18). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-18(1)",
                name="Automated Verification for Wireless Access Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-18(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-18(2)",
                name="Automated Verification for Wireless Access Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-18(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-18(3)",
                name="Automated Verification for Wireless Access Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-18(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-18_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Wireless Access.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-18_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-18.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-18.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1046'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-18, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-19": NistControl(
        id="AC-19",
        family_id="AC",
        family_name="Access Control",
        title="Access Control for Mobile Devices",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Access Control for Mobile Devices (AC-19). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-19(1)",
                name="Automated Verification for Access Control for Mobile Devices Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-19(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-19(2)",
                name="Automated Verification for Access Control for Mobile Devices Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-19(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-19(3)",
                name="Automated Verification for Access Control for Mobile Devices Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-19(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-19_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Access Control for Mobile Devices.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-19_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-19.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-19.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-19, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-20": NistControl(
        id="AC-20",
        family_id="AC",
        family_name="Access Control",
        title="Use of External Systems",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Use of External Systems (AC-20). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-20(1)",
                name="Automated Verification for Use of External Systems Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-20(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-20(2)",
                name="Automated Verification for Use of External Systems Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-20(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-20(3)",
                name="Automated Verification for Use of External Systems Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-20(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-20_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Use of External Systems.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-20_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-20.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-20.""",
        mapped_cwe=['CWE-862'],
        mapped_mitre=['T1567'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-20, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AC-22": NistControl(
        id="AC-22",
        family_id="AC",
        family_name="Access Control",
        title="Publicly Accessible Content",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Publicly Accessible Content (AC-22). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AC-22(1)",
                name="Automated Verification for Publicly Accessible Content Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-22(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-22(2)",
                name="Automated Verification for Publicly Accessible Content Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-22(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AC-22(3)",
                name="Automated Verification for Publicly Accessible Content Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AC-22(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AC-22_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Publicly Accessible Content.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AC-22_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AC-22.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AC-22.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1596'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AC-22, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AT-1": NistControl(
        id="AT-1",
        family_id="AT",
        family_name="Awareness and Training",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (AT-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AT-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AT-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AT-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AT-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AT-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AT-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AT-2": NistControl(
        id="AT-2",
        family_id="AT",
        family_name="Awareness and Training",
        title="Literacy Training and Awareness",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Literacy Training and Awareness (AT-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AT-2(1)",
                name="Automated Verification for Literacy Training and Awareness Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-2(2)",
                name="Automated Verification for Literacy Training and Awareness Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-2(3)",
                name="Automated Verification for Literacy Training and Awareness Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AT-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Literacy Training and Awareness.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AT-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AT-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AT-2.""",
        mapped_cwe=[],
        mapped_mitre=['T1566'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AT-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AT-3": NistControl(
        id="AT-3",
        family_id="AT",
        family_name="Awareness and Training",
        title="Role-Based Training",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Role-Based Training (AT-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AT-3(1)",
                name="Automated Verification for Role-Based Training Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-3(2)",
                name="Automated Verification for Role-Based Training Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-3(3)",
                name="Automated Verification for Role-Based Training Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AT-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Role-Based Training.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AT-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AT-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AT-3.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AT-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AT-4": NistControl(
        id="AT-4",
        family_id="AT",
        family_name="Awareness and Training",
        title="Training Records",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Training Records (AT-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AT-4(1)",
                name="Automated Verification for Training Records Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-4(2)",
                name="Automated Verification for Training Records Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AT-4(3)",
                name="Automated Verification for Training Records Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AT-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AT-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Training Records.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AT-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AT-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AT-4.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AT-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-1": NistControl(
        id="AU-1",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (AU-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-2": NistControl(
        id="AU-2",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Event Logging",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Event Logging (AU-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-2(1)",
                name="Automated Verification for Event Logging Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-2(2)",
                name="Automated Verification for Event Logging Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-2(3)",
                name="Automated Verification for Event Logging Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Event Logging.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-2.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-3": NistControl(
        id="AU-3",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Content of Audit Records",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Content of Audit Records (AU-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-3(1)",
                name="Automated Verification for Content of Audit Records Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-3(2)",
                name="Automated Verification for Content of Audit Records Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-3(3)",
                name="Automated Verification for Content of Audit Records Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Content of Audit Records.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-3.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-4": NistControl(
        id="AU-4",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Audit Log Storage Capacity",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Audit Log Storage Capacity (AU-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-4(1)",
                name="Automated Verification for Audit Log Storage Capacity Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-4(2)",
                name="Automated Verification for Audit Log Storage Capacity Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-4(3)",
                name="Automated Verification for Audit Log Storage Capacity Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Audit Log Storage Capacity.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-4.""",
        mapped_cwe=['CWE-400'],
        mapped_mitre=['T1490'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-5": NistControl(
        id="AU-5",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Response to Audit Logging Failures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Response to Audit Logging Failures (AU-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-5(1)",
                name="Automated Verification for Response to Audit Logging Failures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-5(2)",
                name="Automated Verification for Response to Audit Logging Failures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-5(3)",
                name="Automated Verification for Response to Audit Logging Failures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Response to Audit Logging Failures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-5.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1562'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-6": NistControl(
        id="AU-6",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Audit Record Review, Analysis, and Reporting",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Audit Record Review, Analysis, and Reporting (AU-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-6(1)",
                name="Automated Verification for Audit Record Review, Analysis, and Reporting Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-6(2)",
                name="Automated Verification for Audit Record Review, Analysis, and Reporting Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-6(3)",
                name="Automated Verification for Audit Record Review, Analysis, and Reporting Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Audit Record Review, Analysis, and Reporting.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-6.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-7": NistControl(
        id="AU-7",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Audit Record Reduction and Report Generation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Audit Record Reduction and Report Generation (AU-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-7(1)",
                name="Automated Verification for Audit Record Reduction and Report Generation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-7(2)",
                name="Automated Verification for Audit Record Reduction and Report Generation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-7(3)",
                name="Automated Verification for Audit Record Reduction and Report Generation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Audit Record Reduction and Report Generation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-7.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-8": NistControl(
        id="AU-8",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Time Stamps",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Time Stamps (AU-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-8(1)",
                name="Automated Verification for Time Stamps Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-8(2)",
                name="Automated Verification for Time Stamps Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-8(3)",
                name="Automated Verification for Time Stamps Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Time Stamps.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-8.""",
        mapped_cwe=[],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-9": NistControl(
        id="AU-9",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Protection of Audit Information",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Protection of Audit Information (AU-9). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-9(1)",
                name="Automated Verification for Protection of Audit Information Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-9(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-9(2)",
                name="Automated Verification for Protection of Audit Information Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-9(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-9(3)",
                name="Automated Verification for Protection of Audit Information Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-9(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-9_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Protection of Audit Information.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-9_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-9.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-9.""",
        mapped_cwe=['CWE-732'],
        mapped_mitre=['T1070', 'T1562'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-9, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-10": NistControl(
        id="AU-10",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Non-repudiation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Non-repudiation (AU-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-10(1)",
                name="Automated Verification for Non-repudiation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-10(2)",
                name="Automated Verification for Non-repudiation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-10(3)",
                name="Automated Verification for Non-repudiation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Non-repudiation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-10.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-11": NistControl(
        id="AU-11",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Audit Record Retention",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Audit Record Retention (AU-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-11(1)",
                name="Automated Verification for Audit Record Retention Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-11(2)",
                name="Automated Verification for Audit Record Retention Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-11(3)",
                name="Automated Verification for Audit Record Retention Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Audit Record Retention.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-11.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "AU-12": NistControl(
        id="AU-12",
        family_id="AU",
        family_name="Audit and Accountability",
        title="Audit Record Generation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Audit Record Generation (AU-12). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="AU-12(1)",
                name="Automated Verification for Audit Record Generation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-12(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-12(2)",
                name="Automated Verification for Audit Record Generation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-12(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="AU-12(3)",
                name="Automated Verification for Audit Record Generation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for AU-12(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="AU-12_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Audit Record Generation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="AU-12_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for AU-12.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to AU-12.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy AU-12, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-1": NistControl(
        id="CA-1",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (CA-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-2": NistControl(
        id="CA-2",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Control Assessments",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Control Assessments (CA-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-2(1)",
                name="Automated Verification for Control Assessments Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-2(2)",
                name="Automated Verification for Control Assessments Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-2(3)",
                name="Automated Verification for Control Assessments Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Control Assessments.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-2.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-3": NistControl(
        id="CA-3",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Information Exchange",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information Exchange (CA-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-3(1)",
                name="Automated Verification for Information Exchange Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-3(2)",
                name="Automated Verification for Information Exchange Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-3(3)",
                name="Automated Verification for Information Exchange Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information Exchange.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-3.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1048'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-5": NistControl(
        id="CA-5",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Plan of Action and Milestones",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Plan of Action and Milestones (CA-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-5(1)",
                name="Automated Verification for Plan of Action and Milestones Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-5(2)",
                name="Automated Verification for Plan of Action and Milestones Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-5(3)",
                name="Automated Verification for Plan of Action and Milestones Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Plan of Action and Milestones.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-5.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-6": NistControl(
        id="CA-6",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Authorization",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Authorization (CA-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-6(1)",
                name="Automated Verification for Authorization Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-6(2)",
                name="Automated Verification for Authorization Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-6(3)",
                name="Automated Verification for Authorization Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Authorization.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-6.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-7": NistControl(
        id="CA-7",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Continuous Monitoring",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Continuous Monitoring (CA-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-7(1)",
                name="Automated Verification for Continuous Monitoring Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-7(2)",
                name="Automated Verification for Continuous Monitoring Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-7(3)",
                name="Automated Verification for Continuous Monitoring Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Continuous Monitoring.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-7.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1059', 'T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CA-8": NistControl(
        id="CA-8",
        family_id="CA",
        family_name="Assessment, Authorization, and Monitoring",
        title="Penetration Testing",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Penetration Testing (CA-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CA-8(1)",
                name="Automated Verification for Penetration Testing Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-8(2)",
                name="Automated Verification for Penetration Testing Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CA-8(3)",
                name="Automated Verification for Penetration Testing Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CA-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CA-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Penetration Testing.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CA-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CA-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CA-8.""",
        mapped_cwe=[],
        mapped_mitre=['T1190', 'T1059'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CA-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-1": NistControl(
        id="CM-1",
        family_id="CM",
        family_name="Configuration Management",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (CM-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-2": NistControl(
        id="CM-2",
        family_id="CM",
        family_name="Configuration Management",
        title="Baseline Configuration",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Baseline Configuration (CM-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-2(1)",
                name="Automated Verification for Baseline Configuration Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-2(2)",
                name="Automated Verification for Baseline Configuration Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-2(3)",
                name="Automated Verification for Baseline Configuration Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Baseline Configuration.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-2.""",
        mapped_cwe=[],
        mapped_mitre=['T1547'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-3": NistControl(
        id="CM-3",
        family_id="CM",
        family_name="Configuration Management",
        title="Configuration Change Control",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Configuration Change Control (CM-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-3(1)",
                name="Automated Verification for Configuration Change Control Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-3(2)",
                name="Automated Verification for Configuration Change Control Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-3(3)",
                name="Automated Verification for Configuration Change Control Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Configuration Change Control.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-3.""",
        mapped_cwe=['CWE-732'],
        mapped_mitre=['T1543'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-4": NistControl(
        id="CM-4",
        family_id="CM",
        family_name="Configuration Management",
        title="Impact Analyses",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Impact Analyses (CM-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-4(1)",
                name="Automated Verification for Impact Analyses Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-4(2)",
                name="Automated Verification for Impact Analyses Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-4(3)",
                name="Automated Verification for Impact Analyses Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Impact Analyses.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-4.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-5": NistControl(
        id="CM-5",
        family_id="CM",
        family_name="Configuration Management",
        title="Access Restrictions for Change",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Access Restrictions for Change (CM-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-5(1)",
                name="Automated Verification for Access Restrictions for Change Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-5(2)",
                name="Automated Verification for Access Restrictions for Change Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-5(3)",
                name="Automated Verification for Access Restrictions for Change Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Access Restrictions for Change.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-5.""",
        mapped_cwe=['CWE-732'],
        mapped_mitre=['T1548'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-6": NistControl(
        id="CM-6",
        family_id="CM",
        family_name="Configuration Management",
        title="Configuration Settings",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Configuration Settings (CM-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-6(1)",
                name="Automated Verification for Configuration Settings Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-6(2)",
                name="Automated Verification for Configuration Settings Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-6(3)",
                name="Automated Verification for Configuration Settings Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Configuration Settings.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-6.""",
        mapped_cwe=['CWE-16'],
        mapped_mitre=['T1562'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-7": NistControl(
        id="CM-7",
        family_id="CM",
        family_name="Configuration Management",
        title="Least Functionality",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Least Functionality (CM-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-7(1)",
                name="Automated Verification for Least Functionality Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-7(2)",
                name="Automated Verification for Least Functionality Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-7(3)",
                name="Automated Verification for Least Functionality Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Least Functionality.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-7.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1046', 'T1059'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-8": NistControl(
        id="CM-8",
        family_id="CM",
        family_name="Configuration Management",
        title="Information System Component Inventory",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information System Component Inventory (CM-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-8(1)",
                name="Automated Verification for Information System Component Inventory Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-8(2)",
                name="Automated Verification for Information System Component Inventory Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-8(3)",
                name="Automated Verification for Information System Component Inventory Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information System Component Inventory.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-8.""",
        mapped_cwe=[],
        mapped_mitre=['T1082'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-9": NistControl(
        id="CM-9",
        family_id="CM",
        family_name="Configuration Management",
        title="Configuration Management Plan",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Configuration Management Plan (CM-9). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-9(1)",
                name="Automated Verification for Configuration Management Plan Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-9(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-9(2)",
                name="Automated Verification for Configuration Management Plan Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-9(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-9(3)",
                name="Automated Verification for Configuration Management Plan Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-9(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-9_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Configuration Management Plan.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-9_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-9.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-9.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-9, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-10": NistControl(
        id="CM-10",
        family_id="CM",
        family_name="Configuration Management",
        title="Software Usage Restrictions",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Software Usage Restrictions (CM-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-10(1)",
                name="Automated Verification for Software Usage Restrictions Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-10(2)",
                name="Automated Verification for Software Usage Restrictions Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-10(3)",
                name="Automated Verification for Software Usage Restrictions Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Software Usage Restrictions.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-10.""",
        mapped_cwe=[],
        mapped_mitre=['T1218'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CM-11": NistControl(
        id="CM-11",
        family_id="CM",
        family_name="Configuration Management",
        title="User-Installed Software",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for User-Installed Software (CM-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CM-11(1)",
                name="Automated Verification for User-Installed Software Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-11(2)",
                name="Automated Verification for User-Installed Software Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CM-11(3)",
                name="Automated Verification for User-Installed Software Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CM-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CM-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for User-Installed Software.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CM-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CM-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CM-11.""",
        mapped_cwe=['CWE-732'],
        mapped_mitre=['T1204'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CM-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-1": NistControl(
        id="CP-1",
        family_id="CP",
        family_name="Contingency Planning",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (CP-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-2": NistControl(
        id="CP-2",
        family_id="CP",
        family_name="Contingency Planning",
        title="Contingency Plan",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Contingency Plan (CP-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-2(1)",
                name="Automated Verification for Contingency Plan Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-2(2)",
                name="Automated Verification for Contingency Plan Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-2(3)",
                name="Automated Verification for Contingency Plan Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Contingency Plan.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-2.""",
        mapped_cwe=[],
        mapped_mitre=['T1486'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-3": NistControl(
        id="CP-3",
        family_id="CP",
        family_name="Contingency Planning",
        title="Contingency Training",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Contingency Training (CP-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-3(1)",
                name="Automated Verification for Contingency Training Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-3(2)",
                name="Automated Verification for Contingency Training Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-3(3)",
                name="Automated Verification for Contingency Training Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Contingency Training.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-3.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-4": NistControl(
        id="CP-4",
        family_id="CP",
        family_name="Contingency Planning",
        title="Contingency Plan Testing",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Contingency Plan Testing (CP-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-4(1)",
                name="Automated Verification for Contingency Plan Testing Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-4(2)",
                name="Automated Verification for Contingency Plan Testing Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-4(3)",
                name="Automated Verification for Contingency Plan Testing Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Contingency Plan Testing.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-4.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-6": NistControl(
        id="CP-6",
        family_id="CP",
        family_name="Contingency Planning",
        title="Alternate Storage Site",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Alternate Storage Site (CP-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-6(1)",
                name="Automated Verification for Alternate Storage Site Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-6(2)",
                name="Automated Verification for Alternate Storage Site Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-6(3)",
                name="Automated Verification for Alternate Storage Site Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Alternate Storage Site.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-6.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-7": NistControl(
        id="CP-7",
        family_id="CP",
        family_name="Contingency Planning",
        title="Alternate Processing Site",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Alternate Processing Site (CP-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-7(1)",
                name="Automated Verification for Alternate Processing Site Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-7(2)",
                name="Automated Verification for Alternate Processing Site Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-7(3)",
                name="Automated Verification for Alternate Processing Site Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Alternate Processing Site.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-7.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-8": NistControl(
        id="CP-8",
        family_id="CP",
        family_name="Contingency Planning",
        title="Telecommunications Services",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Telecommunications Services (CP-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-8(1)",
                name="Automated Verification for Telecommunications Services Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-8(2)",
                name="Automated Verification for Telecommunications Services Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-8(3)",
                name="Automated Verification for Telecommunications Services Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Telecommunications Services.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-8.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-9": NistControl(
        id="CP-9",
        family_id="CP",
        family_name="Contingency Planning",
        title="Information System Backup",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information System Backup (CP-9). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-9(1)",
                name="Automated Verification for Information System Backup Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-9(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-9(2)",
                name="Automated Verification for Information System Backup Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-9(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-9(3)",
                name="Automated Verification for Information System Backup Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-9(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-9_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information System Backup.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-9_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-9.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-9.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1486', 'T1490'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-9, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "CP-10": NistControl(
        id="CP-10",
        family_id="CP",
        family_name="Contingency Planning",
        title="Information System Recovery and Reconstitution",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information System Recovery and Reconstitution (CP-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="CP-10(1)",
                name="Automated Verification for Information System Recovery and Reconstitution Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-10(2)",
                name="Automated Verification for Information System Recovery and Reconstitution Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="CP-10(3)",
                name="Automated Verification for Information System Recovery and Reconstitution Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for CP-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="CP-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information System Recovery and Reconstitution.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="CP-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for CP-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to CP-10.""",
        mapped_cwe=[],
        mapped_mitre=['T1486'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy CP-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-1": NistControl(
        id="IA-1",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (IA-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-2": NistControl(
        id="IA-2",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Identification and Authentication (Organizational Users)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Identification and Authentication (Organizational Users) (IA-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-2(1)",
                name="Automated Verification for Identification and Authentication (Organizational Users) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-2(2)",
                name="Automated Verification for Identification and Authentication (Organizational Users) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-2(3)",
                name="Automated Verification for Identification and Authentication (Organizational Users) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Identification and Authentication (Organizational Users).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-2.""",
        mapped_cwe=['CWE-287', 'CWE-308'],
        mapped_mitre=['T1078', 'T1110'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-3": NistControl(
        id="IA-3",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Device Identification and Authentication",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Device Identification and Authentication (IA-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-3(1)",
                name="Automated Verification for Device Identification and Authentication Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-3(2)",
                name="Automated Verification for Device Identification and Authentication Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-3(3)",
                name="Automated Verification for Device Identification and Authentication Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Device Identification and Authentication.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-3.""",
        mapped_cwe=['CWE-287'],
        mapped_mitre=['T1200'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-4": NistControl(
        id="IA-4",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Identifier Management",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Identifier Management (IA-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-4(1)",
                name="Automated Verification for Identifier Management Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-4(2)",
                name="Automated Verification for Identifier Management Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-4(3)",
                name="Automated Verification for Identifier Management Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Identifier Management.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-4.""",
        mapped_cwe=['CWE-287'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-5": NistControl(
        id="IA-5",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Authenticator Management",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Authenticator Management (IA-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-5(1)",
                name="Automated Verification for Authenticator Management Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-5(2)",
                name="Automated Verification for Authenticator Management Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-5(3)",
                name="Automated Verification for Authenticator Management Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Authenticator Management.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-5.""",
        mapped_cwe=['CWE-798', 'CWE-287'],
        mapped_mitre=['T1003', 'T1555'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-6": NistControl(
        id="IA-6",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Authentication Feedback",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Authentication Feedback (IA-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-6(1)",
                name="Automated Verification for Authentication Feedback Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-6(2)",
                name="Automated Verification for Authentication Feedback Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-6(3)",
                name="Automated Verification for Authentication Feedback Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Authentication Feedback.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1110'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-7": NistControl(
        id="IA-7",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Cryptographic Module Authentication",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Cryptographic Module Authentication (IA-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-7(1)",
                name="Automated Verification for Cryptographic Module Authentication Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-7(2)",
                name="Automated Verification for Cryptographic Module Authentication Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-7(3)",
                name="Automated Verification for Cryptographic Module Authentication Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Cryptographic Module Authentication.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-7.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1573'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-8": NistControl(
        id="IA-8",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Identification and Authentication (Non-Organizational Users)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Identification and Authentication (Non-Organizational Users) (IA-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-8(1)",
                name="Automated Verification for Identification and Authentication (Non-Organizational Users) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-8(2)",
                name="Automated Verification for Identification and Authentication (Non-Organizational Users) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-8(3)",
                name="Automated Verification for Identification and Authentication (Non-Organizational Users) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Identification and Authentication (Non-Organizational Users).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-8.""",
        mapped_cwe=['CWE-287'],
        mapped_mitre=['T1190'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IA-11": NistControl(
        id="IA-11",
        family_id="IA",
        family_name="Identification and Authentication",
        title="Re-authentication",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Re-authentication (IA-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IA-11(1)",
                name="Automated Verification for Re-authentication Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-11(2)",
                name="Automated Verification for Re-authentication Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IA-11(3)",
                name="Automated Verification for Re-authentication Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IA-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IA-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Re-authentication.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IA-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IA-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IA-11.""",
        mapped_cwe=['CWE-384'],
        mapped_mitre=['T1563'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IA-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-1": NistControl(
        id="IR-1",
        family_id="IR",
        family_name="Incident Response",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (IR-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-2": NistControl(
        id="IR-2",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Response Training",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Response Training (IR-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-2(1)",
                name="Automated Verification for Incident Response Training Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-2(2)",
                name="Automated Verification for Incident Response Training Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-2(3)",
                name="Automated Verification for Incident Response Training Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Response Training.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-2.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-3": NistControl(
        id="IR-3",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Response Testing",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Response Testing (IR-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-3(1)",
                name="Automated Verification for Incident Response Testing Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-3(2)",
                name="Automated Verification for Incident Response Testing Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-3(3)",
                name="Automated Verification for Incident Response Testing Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Response Testing.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-3.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-4": NistControl(
        id="IR-4",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Handling",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Handling (IR-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-4(1)",
                name="Automated Verification for Incident Handling Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-4(2)",
                name="Automated Verification for Incident Handling Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-4(3)",
                name="Automated Verification for Incident Handling Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Handling.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-4.""",
        mapped_cwe=[],
        mapped_mitre=['T1059', 'T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-5": NistControl(
        id="IR-5",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Monitoring",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Monitoring (IR-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-5(1)",
                name="Automated Verification for Incident Monitoring Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-5(2)",
                name="Automated Verification for Incident Monitoring Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-5(3)",
                name="Automated Verification for Incident Monitoring Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Monitoring.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-5.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-6": NistControl(
        id="IR-6",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Reporting",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Reporting (IR-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-6(1)",
                name="Automated Verification for Incident Reporting Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-6(2)",
                name="Automated Verification for Incident Reporting Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-6(3)",
                name="Automated Verification for Incident Reporting Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Reporting.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-6.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-7": NistControl(
        id="IR-7",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Response Assistance",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Response Assistance (IR-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-7(1)",
                name="Automated Verification for Incident Response Assistance Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-7(2)",
                name="Automated Verification for Incident Response Assistance Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-7(3)",
                name="Automated Verification for Incident Response Assistance Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Response Assistance.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-7.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "IR-8": NistControl(
        id="IR-8",
        family_id="IR",
        family_name="Incident Response",
        title="Incident Response Plan",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Incident Response Plan (IR-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="IR-8(1)",
                name="Automated Verification for Incident Response Plan Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-8(2)",
                name="Automated Verification for Incident Response Plan Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="IR-8(3)",
                name="Automated Verification for Incident Response Plan Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for IR-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="IR-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Incident Response Plan.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="IR-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for IR-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to IR-8.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy IR-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "RA-1": NistControl(
        id="RA-1",
        family_id="RA",
        family_name="Risk Assessment",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (RA-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="RA-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="RA-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="RA-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for RA-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to RA-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy RA-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "RA-2": NistControl(
        id="RA-2",
        family_id="RA",
        family_name="Risk Assessment",
        title="Security Categorization",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Security Categorization (RA-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="RA-2(1)",
                name="Automated Verification for Security Categorization Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-2(2)",
                name="Automated Verification for Security Categorization Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-2(3)",
                name="Automated Verification for Security Categorization Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="RA-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Security Categorization.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="RA-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for RA-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to RA-2.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy RA-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "RA-3": NistControl(
        id="RA-3",
        family_id="RA",
        family_name="Risk Assessment",
        title="Risk Assessment",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Risk Assessment (RA-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="RA-3(1)",
                name="Automated Verification for Risk Assessment Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-3(2)",
                name="Automated Verification for Risk Assessment Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-3(3)",
                name="Automated Verification for Risk Assessment Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="RA-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Risk Assessment.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="RA-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for RA-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to RA-3.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy RA-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "RA-5": NistControl(
        id="RA-5",
        family_id="RA",
        family_name="Risk Assessment",
        title="Vulnerability Monitoring and Scanning",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Vulnerability Monitoring and Scanning (RA-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="RA-5(1)",
                name="Automated Verification for Vulnerability Monitoring and Scanning Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-5(2)",
                name="Automated Verification for Vulnerability Monitoring and Scanning Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="RA-5(3)",
                name="Automated Verification for Vulnerability Monitoring and Scanning Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for RA-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="RA-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Vulnerability Monitoring and Scanning.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="RA-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for RA-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to RA-5.""",
        mapped_cwe=['CWE-20'],
        mapped_mitre=['T1595', 'T1190'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy RA-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-1": NistControl(
        id="SC-1",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (SC-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-2": NistControl(
        id="SC-2",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Separation of System and User Functionality",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Separation of System and User Functionality (SC-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-2(1)",
                name="Automated Verification for Separation of System and User Functionality Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-2(2)",
                name="Automated Verification for Separation of System and User Functionality Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-2(3)",
                name="Automated Verification for Separation of System and User Functionality Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Separation of System and User Functionality.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-2.""",
        mapped_cwe=['CWE-250'],
        mapped_mitre=['T1548'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-3": NistControl(
        id="SC-3",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Security Function Isolation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Security Function Isolation (SC-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-3(1)",
                name="Automated Verification for Security Function Isolation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-3(2)",
                name="Automated Verification for Security Function Isolation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-3(3)",
                name="Automated Verification for Security Function Isolation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Security Function Isolation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-3.""",
        mapped_cwe=['CWE-250'],
        mapped_mitre=['T1055'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-4": NistControl(
        id="SC-4",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Information in Shared Resources",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information in Shared Resources (SC-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-4(1)",
                name="Automated Verification for Information in Shared Resources Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-4(2)",
                name="Automated Verification for Information in Shared Resources Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-4(3)",
                name="Automated Verification for Information in Shared Resources Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information in Shared Resources.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1005'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-5": NistControl(
        id="SC-5",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Denial-of-Service Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Denial-of-Service Protection (SC-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-5(1)",
                name="Automated Verification for Denial-of-Service Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-5(2)",
                name="Automated Verification for Denial-of-Service Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-5(3)",
                name="Automated Verification for Denial-of-Service Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Denial-of-Service Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-5.""",
        mapped_cwe=['CWE-400'],
        mapped_mitre=['T1499'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-7": NistControl(
        id="SC-7",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Boundary Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Boundary Protection (SC-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-7(1)",
                name="Automated Verification for Boundary Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-7(2)",
                name="Automated Verification for Boundary Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-7(3)",
                name="Automated Verification for Boundary Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Boundary Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-7.""",
        mapped_cwe=['CWE-284'],
        mapped_mitre=['T1190', 'T1021'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-8": NistControl(
        id="SC-8",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Transmission Confidentiality and Integrity",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Transmission Confidentiality and Integrity (SC-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-8(1)",
                name="Automated Verification for Transmission Confidentiality and Integrity Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-8(2)",
                name="Automated Verification for Transmission Confidentiality and Integrity Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-8(3)",
                name="Automated Verification for Transmission Confidentiality and Integrity Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Transmission Confidentiality and Integrity.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-8.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1048', 'T1573'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-10": NistControl(
        id="SC-10",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Network Disconnect",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Network Disconnect (SC-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-10(1)",
                name="Automated Verification for Network Disconnect Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-10(2)",
                name="Automated Verification for Network Disconnect Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-10(3)",
                name="Automated Verification for Network Disconnect Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Network Disconnect.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-10.""",
        mapped_cwe=[],
        mapped_mitre=['T1071'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-12": NistControl(
        id="SC-12",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Cryptographic Key Establishment and Management",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Cryptographic Key Establishment and Management (SC-12). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-12(1)",
                name="Automated Verification for Cryptographic Key Establishment and Management Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-12(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-12(2)",
                name="Automated Verification for Cryptographic Key Establishment and Management Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-12(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-12(3)",
                name="Automated Verification for Cryptographic Key Establishment and Management Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-12(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-12_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Cryptographic Key Establishment and Management.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-12_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-12.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-12.""",
        mapped_cwe=['CWE-320'],
        mapped_mitre=['T1552'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-12, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-13": NistControl(
        id="SC-13",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Cryptographic Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Cryptographic Protection (SC-13). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-13(1)",
                name="Automated Verification for Cryptographic Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-13(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-13(2)",
                name="Automated Verification for Cryptographic Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-13(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-13(3)",
                name="Automated Verification for Cryptographic Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-13(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-13_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Cryptographic Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-13_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-13.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-13.""",
        mapped_cwe=['CWE-327'],
        mapped_mitre=['T1573'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-13, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-15": NistControl(
        id="SC-15",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Collaborative Computing Devices",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Collaborative Computing Devices (SC-15). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-15(1)",
                name="Automated Verification for Collaborative Computing Devices Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-15(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-15(2)",
                name="Automated Verification for Collaborative Computing Devices Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-15(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-15(3)",
                name="Automated Verification for Collaborative Computing Devices Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-15(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-15_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Collaborative Computing Devices.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-15_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-15.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-15.""",
        mapped_cwe=[],
        mapped_mitre=['T1115'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-15, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-17": NistControl(
        id="SC-17",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Public Key Infrastructure Certificates",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Public Key Infrastructure Certificates (SC-17). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-17(1)",
                name="Automated Verification for Public Key Infrastructure Certificates Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-17(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-17(2)",
                name="Automated Verification for Public Key Infrastructure Certificates Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-17(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-17(3)",
                name="Automated Verification for Public Key Infrastructure Certificates Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-17(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-17_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Public Key Infrastructure Certificates.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-17_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-17.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-17.""",
        mapped_cwe=['CWE-295'],
        mapped_mitre=['T1588'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-17, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SC-28": NistControl(
        id="SC-28",
        family_id="SC",
        family_name="System and Communications Protection",
        title="Protection of Information at Rest",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Protection of Information at Rest (SC-28). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SC-28(1)",
                name="Automated Verification for Protection of Information at Rest Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-28(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-28(2)",
                name="Automated Verification for Protection of Information at Rest Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-28(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SC-28(3)",
                name="Automated Verification for Protection of Information at Rest Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SC-28(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SC-28_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Protection of Information at Rest.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SC-28_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SC-28.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SC-28.""",
        mapped_cwe=['CWE-311'],
        mapped_mitre=['T1486', 'T1005'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SC-28, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-1": NistControl(
        id="SI-1",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Policy and Procedures",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Policy and Procedures (SI-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-1(1)",
                name="Automated Verification for Policy and Procedures Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-1(2)",
                name="Automated Verification for Policy and Procedures Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-1(3)",
                name="Automated Verification for Policy and Procedures Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Policy and Procedures.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-1.""",
        mapped_cwe=[],
        mapped_mitre=[],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-2": NistControl(
        id="SI-2",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Flaw Remediation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Flaw Remediation (SI-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-2(1)",
                name="Automated Verification for Flaw Remediation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-2(2)",
                name="Automated Verification for Flaw Remediation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-2(3)",
                name="Automated Verification for Flaw Remediation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Flaw Remediation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-2.""",
        mapped_cwe=['CWE-20'],
        mapped_mitre=['T1190'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-3": NistControl(
        id="SI-3",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Malicious Code Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Malicious Code Protection (SI-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-3(1)",
                name="Automated Verification for Malicious Code Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-3(2)",
                name="Automated Verification for Malicious Code Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-3(3)",
                name="Automated Verification for Malicious Code Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Malicious Code Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-3.""",
        mapped_cwe=['CWE-434'],
        mapped_mitre=['T1204', 'T1059'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-4": NistControl(
        id="SI-4",
        family_id="SI",
        family_name="System and Information Integrity",
        title="System Monitoring",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Monitoring (SI-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-4(1)",
                name="Automated Verification for System Monitoring Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-4(2)",
                name="Automated Verification for System Monitoring Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-4(3)",
                name="Automated Verification for System Monitoring Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Monitoring.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-4.""",
        mapped_cwe=['CWE-778'],
        mapped_mitre=['T1059', 'T1046', 'T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-5": NistControl(
        id="SI-5",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Security Alerts, Advisories, and Directives",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Security Alerts, Advisories, and Directives (SI-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-5(1)",
                name="Automated Verification for Security Alerts, Advisories, and Directives Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-5(2)",
                name="Automated Verification for Security Alerts, Advisories, and Directives Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-5(3)",
                name="Automated Verification for Security Alerts, Advisories, and Directives Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Security Alerts, Advisories, and Directives.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-5.""",
        mapped_cwe=[],
        mapped_mitre=['T1588'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-7": NistControl(
        id="SI-7",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Software, Firmware, and Information Integrity",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Software, Firmware, and Information Integrity (SI-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-7(1)",
                name="Automated Verification for Software, Firmware, and Information Integrity Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-7(2)",
                name="Automated Verification for Software, Firmware, and Information Integrity Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-7(3)",
                name="Automated Verification for Software, Firmware, and Information Integrity Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Software, Firmware, and Information Integrity.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-7.""",
        mapped_cwe=['CWE-494'],
        mapped_mitre=['T1195'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-8": NistControl(
        id="SI-8",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Spam Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Spam Protection (SI-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-8(1)",
                name="Automated Verification for Spam Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-8(2)",
                name="Automated Verification for Spam Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-8(3)",
                name="Automated Verification for Spam Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Spam Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-8.""",
        mapped_cwe=[],
        mapped_mitre=['T1566'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-10": NistControl(
        id="SI-10",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Information Input Validation",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information Input Validation (SI-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-10(1)",
                name="Automated Verification for Information Input Validation Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-10(2)",
                name="Automated Verification for Information Input Validation Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-10(3)",
                name="Automated Verification for Information Input Validation Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information Input Validation.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-10.""",
        mapped_cwe=['CWE-20'],
        mapped_mitre=['T1190'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-12": NistControl(
        id="SI-12",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Information Management and Retention",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Information Management and Retention (SI-12). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-12(1)",
                name="Automated Verification for Information Management and Retention Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-12(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-12(2)",
                name="Automated Verification for Information Management and Retention Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-12(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-12(3)",
                name="Automated Verification for Information Management and Retention Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-12(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-12_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Information Management and Retention.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-12_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-12.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-12.""",
        mapped_cwe=[],
        mapped_mitre=['T1070'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-12, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SI-16": NistControl(
        id="SI-16",
        family_id="SI",
        family_name="System and Information Integrity",
        title="Memory Protection",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Memory Protection (SI-16). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SI-16(1)",
                name="Automated Verification for Memory Protection Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-16(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-16(2)",
                name="Automated Verification for Memory Protection Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-16(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SI-16(3)",
                name="Automated Verification for Memory Protection Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SI-16(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SI-16_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Memory Protection.",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SI-16_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SI-16.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SI-16.""",
        mapped_cwe=['CWE-119'],
        mapped_mitre=['T1055'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SI-16, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-1": NistControl(
        id="MP-1",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 1) (MP-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-1(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-1(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-1(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-2": NistControl(
        id="MP-2",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 2) (MP-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-2(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-2(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-2(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-3": NistControl(
        id="MP-3",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 3) (MP-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-3(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-3(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-3(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-4": NistControl(
        id="MP-4",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 4) (MP-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-4(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-4(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-4(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-5": NistControl(
        id="MP-5",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 5) (MP-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-5(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-5(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-5(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-6": NistControl(
        id="MP-6",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 6) (MP-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-6(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-6(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-6(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "MP-7": NistControl(
        id="MP-7",
        family_id="MP",
        family_name="Media Protection",
        title="Media Protection Framework Requirement (MP Control 7)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Media Protection Framework Requirement (MP Control 7) (MP-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="MP-7(1)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 7) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-7(2)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 7) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="MP-7(3)",
                name="Automated Verification for Media Protection Framework Requirement (MP Control 7) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for MP-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="MP-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Media Protection Framework Requirement (MP Control 7).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="MP-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for MP-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to MP-7.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy MP-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-1": NistControl(
        id="PE-1",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 1) (PE-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-1(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-1(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-1(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-2": NistControl(
        id="PE-2",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 2) (PE-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-2(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-2(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-2(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-3": NistControl(
        id="PE-3",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 3) (PE-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-3(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-3(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-3(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-4": NistControl(
        id="PE-4",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 4) (PE-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-4(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-4(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-4(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-5": NistControl(
        id="PE-5",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 5) (PE-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-5(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-5(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-5(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-6": NistControl(
        id="PE-6",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 6) (PE-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-6(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-6(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-6(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-8": NistControl(
        id="PE-8",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 8)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 8) (PE-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-8(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 8) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-8(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 8) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-8(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 8) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 8).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-8.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-10": NistControl(
        id="PE-10",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 10)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 10) (PE-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-10(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 10) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-10(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 10) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-10(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 10) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 10).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-10.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PE-12": NistControl(
        id="PE-12",
        family_id="PE",
        family_name="Physical and Environmental Protection",
        title="Physical Protection Framework Requirement (PE Control 12)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Physical Protection Framework Requirement (PE Control 12) (PE-12). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PE-12(1)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 12) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-12(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-12(2)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 12) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-12(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PE-12(3)",
                name="Automated Verification for Physical Protection Framework Requirement (PE Control 12) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PE-12(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PE-12_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Physical Protection Framework Requirement (PE Control 12).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PE-12_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PE-12.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PE-12.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PE-12, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-1": NistControl(
        id="PL-1",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 1) (PL-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-1(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-1(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-1(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-2": NistControl(
        id="PL-2",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 2) (PL-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-2(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-2(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-2(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-4": NistControl(
        id="PL-4",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 4) (PL-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-4(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-4(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-4(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-8": NistControl(
        id="PL-8",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 8)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 8) (PL-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-8(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 8) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-8(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 8) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-8(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 8) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 8).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-8.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-10": NistControl(
        id="PL-10",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 10)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 10) (PL-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-10(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 10) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-10(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 10) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-10(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 10) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 10).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-10.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PL-11": NistControl(
        id="PL-11",
        family_id="PL",
        family_name="Planning",
        title="Planning Framework Requirement (PL Control 11)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Planning Framework Requirement (PL Control 11) (PL-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PL-11(1)",
                name="Automated Verification for Planning Framework Requirement (PL Control 11) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-11(2)",
                name="Automated Verification for Planning Framework Requirement (PL Control 11) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PL-11(3)",
                name="Automated Verification for Planning Framework Requirement (PL Control 11) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PL-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PL-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Planning Framework Requirement (PL Control 11).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PL-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PL-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PL-11.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PL-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-1": NistControl(
        id="PM-1",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 1) (PM-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-1(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-1(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-1(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-2": NistControl(
        id="PM-2",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 2) (PM-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-2(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-2(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-2(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-3": NistControl(
        id="PM-3",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 3) (PM-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-3(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-3(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-3(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-4": NistControl(
        id="PM-4",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 4) (PM-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-4(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-4(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-4(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-5": NistControl(
        id="PM-5",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 5) (PM-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-5(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-5(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-5(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-6": NistControl(
        id="PM-6",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 6) (PM-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-6(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-6(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-6(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-7": NistControl(
        id="PM-7",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 7)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 7) (PM-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-7(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 7) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-7(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 7) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-7(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 7) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 7).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-7.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-9": NistControl(
        id="PM-9",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 9)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 9) (PM-9). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-9(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 9) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-9(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-9(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 9) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-9(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-9(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 9) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-9(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-9_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 9).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-9_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-9.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-9.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-9, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PM-11": NistControl(
        id="PM-11",
        family_id="PM",
        family_name="Program Management",
        title="Program Management Framework Requirement (PM Control 11)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Program Management Framework Requirement (PM Control 11) (PM-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PM-11(1)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 11) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-11(2)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 11) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PM-11(3)",
                name="Automated Verification for Program Management Framework Requirement (PM Control 11) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PM-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PM-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Program Management Framework Requirement (PM Control 11).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PM-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PM-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PM-11.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PM-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-1": NistControl(
        id="PS-1",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 1) (PS-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-1(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-1(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-1(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-2": NistControl(
        id="PS-2",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 2) (PS-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-2(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-2(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-2(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-3": NistControl(
        id="PS-3",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 3) (PS-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-3(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-3(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-3(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-4": NistControl(
        id="PS-4",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 4) (PS-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-4(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-4(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-4(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-5": NistControl(
        id="PS-5",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 5) (PS-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-5(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-5(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-5(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-6": NistControl(
        id="PS-6",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 6) (PS-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-6(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-6(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-6(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-7": NistControl(
        id="PS-7",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 7)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 7) (PS-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-7(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 7) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-7(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 7) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-7(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 7) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 7).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-7.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PS-8": NistControl(
        id="PS-8",
        family_id="PS",
        family_name="Personnel Security",
        title="Personnel Security Framework Requirement (PS Control 8)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Personnel Security Framework Requirement (PS Control 8) (PS-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PS-8(1)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 8) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-8(2)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 8) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PS-8(3)",
                name="Automated Verification for Personnel Security Framework Requirement (PS Control 8) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PS-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PS-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Personnel Security Framework Requirement (PS Control 8).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PS-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PS-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PS-8.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PS-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-1": NistControl(
        id="PT-1",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 1) (PT-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-1(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-1(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-1(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-2": NistControl(
        id="PT-2",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 2) (PT-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-2(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-2(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-2(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-3": NistControl(
        id="PT-3",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 3) (PT-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-3(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-3(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-3(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-4": NistControl(
        id="PT-4",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 4) (PT-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-4(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-4(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-4(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-5": NistControl(
        id="PT-5",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 5) (PT-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-5(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-5(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-5(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-6": NistControl(
        id="PT-6",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 6) (PT-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-6(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-6(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-6(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "PT-7": NistControl(
        id="PT-7",
        family_id="PT",
        family_name="PII Processing and Transparency",
        title="PII Transparency Framework Requirement (PT Control 7)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for PII Transparency Framework Requirement (PT Control 7) (PT-7). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="PT-7(1)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 7) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-7(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-7(2)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 7) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-7(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="PT-7(3)",
                name="Automated Verification for PII Transparency Framework Requirement (PT Control 7) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for PT-7(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="PT-7_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for PII Transparency Framework Requirement (PT Control 7).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="PT-7_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for PT-7.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to PT-7.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy PT-7, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-1": NistControl(
        id="SA-1",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 1) (SA-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-1(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-1(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-1(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-2": NistControl(
        id="SA-2",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 2) (SA-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-2(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-2(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-2(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-3": NistControl(
        id="SA-3",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 3) (SA-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-3(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-3(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-3(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-4": NistControl(
        id="SA-4",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 4) (SA-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-4(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-4(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-4(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-5": NistControl(
        id="SA-5",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 5) (SA-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-5(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-5(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-5(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-8": NistControl(
        id="SA-8",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 8)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 8) (SA-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-8(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 8) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-8(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 8) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-8(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 8) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 8).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-8.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-9": NistControl(
        id="SA-9",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 9)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 9) (SA-9). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-9(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 9) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-9(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-9(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 9) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-9(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-9(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 9) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-9(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-9_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 9).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-9_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-9.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-9.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-9, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-10": NistControl(
        id="SA-10",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 10)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 10) (SA-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-10(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 10) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-10(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 10) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-10(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 10) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 10).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-10.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SA-11": NistControl(
        id="SA-11",
        family_id="SA",
        family_name="System and Services Acquisition",
        title="System Acquisition Framework Requirement (SA Control 11)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for System Acquisition Framework Requirement (SA Control 11) (SA-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SA-11(1)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 11) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-11(2)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 11) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SA-11(3)",
                name="Automated Verification for System Acquisition Framework Requirement (SA Control 11) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SA-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SA-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for System Acquisition Framework Requirement (SA Control 11).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SA-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SA-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SA-11.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SA-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-1": NistControl(
        id="SR-1",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 1)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 1) (SR-1). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-1(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 1) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-1(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-1(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 1) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-1(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-1(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 1) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-1(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-1_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 1).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-1_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-1.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-1.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-1, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-2": NistControl(
        id="SR-2",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 2)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 2) (SR-2). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-2(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 2) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-2(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-2(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 2) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-2(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-2(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 2) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-2(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-2_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 2).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-2_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-2.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-2.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-2, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-3": NistControl(
        id="SR-3",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 3)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 3) (SR-3). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-3(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 3) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-3(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-3(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 3) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-3(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-3(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 3) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-3(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-3_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 3).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-3_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-3.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-3.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-3, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-4": NistControl(
        id="SR-4",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 4)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 4) (SR-4). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-4(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 4) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-4(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-4(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 4) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-4(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-4(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 4) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-4(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-4_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 4).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-4_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-4.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-4.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-4, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-5": NistControl(
        id="SR-5",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 5)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 5) (SR-5). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-5(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 5) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-5(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-5(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 5) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-5(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-5(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 5) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-5(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-5_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 5).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-5_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-5.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-5.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-5, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-6": NistControl(
        id="SR-6",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 6)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 6) (SR-6). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-6(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 6) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-6(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-6(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 6) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-6(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-6(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 6) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-6(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-6_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 6).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-6_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-6.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-6.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-6, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-8": NistControl(
        id="SR-8",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 8)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 8) (SR-8). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-8(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 8) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-8(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-8(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 8) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-8(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-8(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 8) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-8(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-8_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 8).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-8_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-8.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-8.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-8, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-10": NistControl(
        id="SR-10",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 10)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 10) (SR-10). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-10(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 10) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-10(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-10(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 10) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-10(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-10(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 10) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-10(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-10_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 10).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-10_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-10.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-10.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-10, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
    "SR-11": NistControl(
        id="SR-11",
        family_id="SR",
        family_name="Supply Chain Risk Management",
        title="Supply Chain Risk Framework Requirement (SR Control 11)",
        statement="""The organization establishes, documents, and implements mandatory technical, operational, and managerial safeguards for Supply Chain Risk Framework Requirement (SR Control 11) (SR-11). Automated security tools must continuously enforce compliance, record audit findings, and notify designated administrators upon policy deviation.""",
        baseline_impact=[BaselineImpact.LOW, BaselineImpact.MODERATE, BaselineImpact.HIGH],
        enhancements=[
            ControlEnhancement(
                enhancement_id="SR-11(1)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 11) Enhancement 1",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-11(1) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-11(2)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 11) Enhancement 2",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-11(2) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
            ControlEnhancement(
                enhancement_id="SR-11(3)",
                name="Automated Verification for Supply Chain Risk Framework Requirement (SR Control 11) Enhancement 3",
                description="Employ automated mechanisms to audit, validate, and alert on non-compliant configurations for SR-11(3) across hybrid enterprise environments.",
                baseline_impact=[BaselineImpact.MODERATE, BaselineImpact.HIGH]
            ),
        ],
        assessment_objectives=[
            AssessmentObjective(
                objective_id="SR-11_obj_1",
                determination_statement="Determine if the organization defines and documents required implementation specifications for Supply Chain Risk Framework Requirement (SR Control 11).",
                method="Examine"
            ),
            AssessmentObjective(
                objective_id="SR-11_obj_2",
                determination_statement="Determine if automated monitoring tools actively enforce and report continuous compliance for SR-11.",
                method="Test"
            )
        ],
        audit_procedure="""Query system configuration registry, inspect authorization policy manifests, evaluate active session telemetry, and inspect SIEM alerts for unauthorized alterations relating to SR-11.""",
        mapped_cwe=['CWE-200'],
        mapped_mitre=['T1078'],
        supplemental_guidance="""Organizations enforce zero-trust security architecture principles to satisfy SR-11, combining multi-factor cryptographic tokens, continuous posture assessment, and immutable audit log retention."""
    ),
}


class NistSp80053Engine:
    """Query and compliance evaluation engine for NIST SP 800-53 Rev 5."""

    @classmethod
    def get_control(cls, control_id: str) -> Optional[NistControl]:
        return CONTROLS_CATALOG.get(control_id)

    @classmethod
    def get_controls_by_family(cls, family_id: str) -> List[NistControl]:
        return [c for c in CONTROLS_CATALOG.values() if c.family_id == family_id]

    @classmethod
    def get_controls_by_baseline(cls, baseline: BaselineImpact) -> List[NistControl]:
        return [c for c in CONTROLS_CATALOG.values() if baseline in c.baseline_impact]

    @classmethod
    def search_controls(cls, keyword: str) -> List[NistControl]:
        kw = keyword.lower()
        return [
            c for c in CONTROLS_CATALOG.values()
            if kw in c.id.lower() or kw in c.title.lower() or kw in c.statement.lower()
        ]

    @classmethod
    def evaluate_compliance(cls, passing_control_ids: Set[str], baseline: BaselineImpact = BaselineImpact.MODERATE) -> Dict[str, Any]:
        required_controls = cls.get_controls_by_baseline(baseline)
        total_required = len(required_controls)
        passed_count = sum(1 for c in required_controls if c.id in passing_control_ids)
        failed = [c.id for c in required_controls if c.id not in passing_control_ids]
        compliance_pct = round((passed_count / total_required) * 100, 2) if total_required > 0 else 0.0

        return {
            "baseline": baseline.value,
            "total_required": total_required,
            "passed_count": passed_count,
            "failed_count": len(failed),
            "compliance_score_percent": compliance_pct,
            "deficiencies": failed[:25]
        }

    @classmethod
    def get_framework_summary(cls) -> Dict[str, Any]:
        family_summary = {}
        for fid, fam in FAMILIES_CATALOG.items():
            ctrls = cls.get_controls_by_family(fid)
            family_summary[fid] = {
                "name": fam.name,
                "controls_count": len(ctrls),
                "high_baseline_count": sum(1 for c in ctrls if BaselineImpact.HIGH in c.baseline_impact)
            }
        return {
            "total_families": len(FAMILIES_CATALOG),
            "total_controls": len(CONTROLS_CATALOG),
            "families": family_summary
        }
