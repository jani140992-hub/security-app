"""
Core Data Models for AegisGuard Platform.
Defines unified schemas for NormalizedSecurityEvent, SecurityAlert,
SecurityIncident, AssetRecord, CloudResource, and AuditFinding.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union
import datetime
import uuid


class EventSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    REMEDIATED = "REMEDIATED"
    CLOSED = "CLOSED"


class AssetType(str, Enum):
    ENDPOINT_WINDOWS = "ENDPOINT_WINDOWS"
    ENDPOINT_LINUX = "ENDPOINT_LINUX"
    ENDPOINT_MACOS = "ENDPOINT_MACOS"
    SERVER = "SERVER"
    CLOUD_INSTANCE = "CLOUD_INSTANCE"
    KUBERNETES_NODE = "KUBERNETES_NODE"
    CONTAINER = "CONTAINER"
    FIREWALL = "FIREWALL"
    DATABASE = "DATABASE"


@dataclass
class NormalizedSecurityEvent:
    """Unified Open Cybersecurity Schema Framework (OCSF) inspired event model."""
    event_id: str
    timestamp: str
    source_type: str  # syslog, evtx, cloudtrail, suricata, nginx
    event_type: str  # process_creation, logon, network_connection, cloud_api
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    hostname: Optional[str] = None
    user_name: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    action: Optional[str] = None  # ALLOW, BLOCK, SUCCESS, FAILURE
    raw_payload: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    """Security alert triggered by detection rules, IOC hits, or anomaly thresholding."""
    alert_id: str
    title: str
    description: str
    severity: EventSeverity
    rule_id: str
    rule_source: str  # Sigma, Mitre, IOC, Anomaly
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    source_event_ids: List[str] = field(default_factory=list)
    asset_id: Optional[str] = None
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    is_suppressed: bool = False
    false_positive_score: float = 0.0


@dataclass
class SecurityIncident:
    """Enterprise incident tracking correlated alerts, blast radius, and containment state."""
    incident_id: str
    title: str
    summary: str
    severity: EventSeverity
    status: IncidentStatus
    assigned_analyst: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    updated_at: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
    associated_alert_ids: List[str] = field(default_factory=list)
    impacted_assets: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    containment_actions_taken: List[str] = field(default_factory=list)
    remediation_notes: str = ""


@dataclass
class AssetRecord:
    """Enterprise asset inventory entry with risk scoring and posture state."""
    asset_id: str
    hostname: str
    ip_addresses: List[str]
    mac_address: Optional[str]
    os_name: str
    os_version: str
    asset_type: AssetType
    criticality: str  # LOW, MEDIUM, HIGH, MISSION_CRITICAL
    owner: str
    risk_score: float = 0.0
    active_vulnerabilities: List[str] = field(default_factory=list)
    last_seen: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat() + "Z")
