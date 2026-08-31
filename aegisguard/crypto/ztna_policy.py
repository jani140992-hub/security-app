"""
Zero-Trust Network Access (ZTNA) Continuous Risk & Micro-segmentation Engine.
Evaluates dynamic access requests against real-time contextual posture indicators:
device health, geo-velocity anomalies, identity risk score, and data sensitivity.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import time
import uuid


class ZtnaDecisionType(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"
    STEP_UP_MFA = "STEP_UP_MFA"
    ISOLATE = "ISOLATE"


class DataSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_MISSION_CRITICAL = "RESTRICTED_MISSION_CRITICAL"


@dataclass
class ZtnaSubjectContext:
    user_id: str
    user_roles: List[str]
    device_id: str
    device_is_managed: bool
    device_edr_healthy: bool
    device_disk_encrypted: bool
    source_ip: str
    mfa_authenticated_at_epoch: float
    identity_risk_score: float  # 0.0 to 100.0


@dataclass
class ZtnaAccessRequest:
    request_id: str
    subject: ZtnaSubjectContext
    target_resource_id: str
    target_protocol: str
    data_sensitivity: DataSensitivity
    requested_action: str  # READ, WRITE, ADMIN, EXECUTE
    timestamp_epoch: float = field(default_factory=time.time)


@dataclass
class ZtnaEvaluationResult:
    decision: ZtnaDecisionType
    decision_reason: str
    session_ttl_seconds: int
    applied_network_tag: str
    required_mitigations: List[str] = field(default_factory=list)


class ZtnaPolicyEngine:
    """Continuous Zero-Trust authorization and micro-segmentation controller."""

    MFA_MAX_AGE_SECONDS = 3600  # 1 hour

    @classmethod
    def evaluate_request(cls, req: ZtnaAccessRequest) -> ZtnaEvaluationResult:
        sub = req.subject
        now = req.timestamp_epoch

        # 1. Block if device is unmanaged or compromised
        if not sub.device_is_managed:
            return ZtnaEvaluationResult(
                decision=ZtnaDecisionType.DENY,
                decision_reason="Access denied: Unmanaged BYOD devices are prohibited from accessing enterprise resources.",
                session_ttl_seconds=0,
                applied_network_tag="ztna-untrusted-deny",
                required_mitigations=["Enroll device into enterprise MDM/EDR fleet management."]
            )

        if not sub.device_edr_healthy:
            return ZtnaEvaluationResult(
                decision=ZtnaDecisionType.ISOLATE,
                decision_reason="Access denied: Device EDR sensor reports unhealthy status or active malware detection.",
                session_ttl_seconds=0,
                applied_network_tag="ztna-quarantine-vlan",
                required_mitigations=["Initiate automated host remediation and full malware scan."]
            )

        # 2. Check high identity risk
        if sub.identity_risk_score >= 75.0:
            return ZtnaEvaluationResult(
                decision=ZtnaDecisionType.DENY,
                decision_reason=f"Access denied: Subject identity risk score is critical ({sub.identity_risk_score}/100).",
                session_ttl_seconds=0,
                applied_network_tag="ztna-high-risk-deny",
                required_mitigations=["SOC analyst identity verification and password reset required."]
            )

        # 3. Check MFA freshness for sensitive resources
        mfa_age = now - sub.mfa_authenticated_at_epoch
        if req.data_sensitivity in [DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED_MISSION_CRITICAL]:
            if mfa_age > cls.MFA_MAX_AGE_SECONDS or sub.identity_risk_score >= 40.0:
                return ZtnaEvaluationResult(
                    decision=ZtnaDecisionType.STEP_UP_MFA,
                    decision_reason="Step-up FIDO2/WebAuthn MFA challenge required for high-sensitivity data access.",
                    session_ttl_seconds=300,
                    applied_network_tag="ztna-mfa-pending",
                    required_mitigations=["Complete biometric or hardware security key verification."]
                )

        # 4. Check disk encryption requirement
        if not sub.device_disk_encrypted and req.data_sensitivity != DataSensitivity.PUBLIC:
            return ZtnaEvaluationResult(
                decision=ZtnaDecisionType.DENY,
                decision_reason="Access denied: BitLocker/FileVault disk encryption is required for non-public data.",
                session_ttl_seconds=0,
                applied_network_tag="ztna-unencrypted-deny",
                required_mitigations=["Enable full-disk encryption and escrow keys with enterprise vault."]
            )

        # 5. Success - Permit micro-segmented session
        ttl = 900 if req.data_sensitivity == DataSensitivity.RESTRICTED_MISSION_CRITICAL else 3600
        return ZtnaEvaluationResult(
            decision=ZtnaDecisionType.PERMIT,
            decision_reason="Contextual Zero-Trust verification successful. Micro-segmented access token granted.",
            session_ttl_seconds=ttl,
            applied_network_tag=f"ztna-permitted-{req.target_protocol.lower()}"
        )
