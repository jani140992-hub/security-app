"""
Real-Time Event Stream Correlation & Behavioral Detection Engine.
Applies stateful sliding time windows to detect rapid authentication failure bursts,
mass file alteration spikes, lateral movement pivoting, rhythmic periodic beaconing,
and high-volume external data exfiltration anomalies.
"""

import time
import uuid
import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple
from aegisguard.core.models import NormalizedSecurityEvent, SecurityAlert, EventSeverity
from aegisguard.catalogs.sigma_detection_rules import SigmaRuleCompiler
from aegisguard.catalogs.stix_threat_intel import ThreatIntelligenceEngine, IocType


class CorrelationEngine:
    """Stateful streaming correlation engine with sliding time windows."""

    def __init__(self, time_window_seconds: int = 300):
        self.time_window = time_window_seconds
        self.failed_logins: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self.file_modifications: Dict[str, List[float]] = defaultdict(list)
        self.outbound_connections: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self.outbound_bandwidth_bytes: Dict[Tuple[str, str], int] = defaultdict(int)
        self.generated_alerts: List[SecurityAlert] = []

    def clean_old_entries(self, current_time: float):
        cutoff = current_time - self.time_window
        for k in list(self.failed_logins.keys()):
            self.failed_logins[k] = [t for t in self.failed_logins[k] if t > cutoff]
            if not self.failed_logins[k]:
                del self.failed_logins[k]

        for k in list(self.file_modifications.keys()):
            self.file_modifications[k] = [t for t in self.file_modifications[k] if t > cutoff]
            if not self.file_modifications[k]:
                del self.file_modifications[k]

        for k in list(self.outbound_connections.keys()):
            self.outbound_connections[k] = [t for t in self.outbound_connections[k] if t > cutoff]
            if not self.outbound_connections[k]:
                del self.outbound_connections[k]

    def process_event(self, event: NormalizedSecurityEvent) -> List[SecurityAlert]:
        """Process a single normalized event through correlation heuristics and rule engines."""
        current_time = time.time()
        self.clean_old_entries(current_time)
        alerts: List[SecurityAlert] = []

        # 1. Threat Intel IOC Matching
        if event.source_ip:
            ioc = ThreatIntelligenceEngine.lookup_ioc(event.source_ip)
            if ioc:
                alerts.append(SecurityAlert(
                    alert_id=f"alert-ioc-{uuid.uuid4()}",
                    title=f"Adversary Network Hit: {event.source_ip}",
                    description=f"Inbound traffic matched known malicious threat actor IOC: {ioc.description}",
                    severity=EventSeverity.CRITICAL if ioc.confidence >= 90 else EventSeverity.HIGH,
                    rule_id="AEGIS-IOC-001",
                    rule_source="ThreatIntel",
                    mitre_tactics=["TA0011"],
                    mitre_techniques=["T1071.001"],
                    source_event_ids=[event.event_id],
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip
                ))

        if event.destination_ip:
            ioc = ThreatIntelligenceEngine.lookup_ioc(event.destination_ip)
            if ioc:
                alerts.append(SecurityAlert(
                    alert_id=f"alert-ioc-{uuid.uuid4()}",
                    title=f"Outbound C2 Destination Match: {event.destination_ip}",
                    description=f"Host initiated connection to known malicious adversary node: {ioc.description}",
                    severity=EventSeverity.CRITICAL,
                    rule_id="AEGIS-IOC-002",
                    rule_source="ThreatIntel",
                    mitre_tactics=["TA0011"],
                    mitre_techniques=["T1071"],
                    source_event_ids=[event.event_id],
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip
                ))

        # 2. Sigma Rule Execution
        event_dict = {
            "Image": event.process_name or "",
            "CommandLine": event.command_line or "",
            "EventID": event.metadata.get("EventID") or (4625 if event.action == "FAILURE" else 4624),
            "DestinationPort": event.destination_port,
            "DestinationIp": event.destination_ip,
            "eventName": event.command_line.split(":")[-1] if event.command_line and ":" in event.command_line else "",
            "Request": event.command_line or ""
        }
        sigma_matches = SigmaRuleCompiler.scan_event(event_dict)
        for s_rule in sigma_matches:
            sev_map = {
                "critical": EventSeverity.CRITICAL,
                "high": EventSeverity.HIGH,
                "medium": EventSeverity.MEDIUM,
                "low": EventSeverity.LOW
            }
            alerts.append(SecurityAlert(
                alert_id=f"alert-sigma-{uuid.uuid4()}",
                title=s_rule.title,
                description=s_rule.description,
                severity=sev_map.get(s_rule.level.value, EventSeverity.HIGH),
                rule_id=s_rule.id,
                rule_source="Sigma",
                mitre_techniques=[t.replace("attack.", "").upper() for t in s_rule.tags if "t1" in t.lower()],
                source_event_ids=[event.event_id],
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                user_id=event.user_name
            ))

        # 3. Behavioral Heuristic 1: Authentication Failure Threshold (> 5 failures in 300s)
        if event.event_type == "logon" and event.action == "FAILURE" and event.user_name:
            key = (event.hostname or "unknown", event.user_name)
            self.failed_logins[key].append(current_time)
            if len(self.failed_logins[key]) >= 5:
                alerts.append(SecurityAlert(
                    alert_id=f"alert-auth-abuse-{uuid.uuid4()}",
                    title=f"Repeated Logon Failures Detected on {key[0]} (User: {key[1]})",
                    description=f"Observed {len(self.failed_logins[key])} failed logon attempts within {self.time_window} seconds.",
                    severity=EventSeverity.HIGH,
                    rule_id="AEGIS-CORR-001",
                    rule_source="CorrelationEngine",
                    mitre_tactics=["TA0006"],
                    mitre_techniques=["T1110.001"],
                    source_event_ids=[event.event_id],
                    asset_id=event.hostname,
                    user_id=event.user_name,
                    source_ip=event.source_ip
                ))
                self.failed_logins[key] = []

        # 4. Behavioral Heuristic 2: Rapid File Modification Burst (> 20 modifications in 60s)
        if event.event_type == "file_event" and event.hostname:
            self.file_modifications[event.hostname].append(current_time)
            if len(self.file_modifications[event.hostname]) >= 20:
                alerts.append(SecurityAlert(
                    alert_id=f"alert-file-spike-{uuid.uuid4()}",
                    title=f"High-Volume File Modification Spike on Host: {event.hostname}",
                    description=f"Rapid file modification burst of {len(self.file_modifications[event.hostname])} operations detected in under 60 seconds.",
                    severity=EventSeverity.CRITICAL,
                    rule_id="AEGIS-CORR-002",
                    rule_source="CorrelationEngine",
                    mitre_tactics=["TA0040"],
                    mitre_techniques=["T1486"],
                    source_event_ids=[event.event_id],
                    asset_id=event.hostname
                ))
                self.file_modifications[event.hostname] = []

        # 5. Behavioral Heuristic 3: Periodic Network Outbound Signal
        if event.source_ip and event.destination_ip and event.event_type == "network_connection":
            flow_key = (event.source_ip, event.destination_ip)
            self.outbound_connections[flow_key].append(current_time)
            if len(self.outbound_connections[flow_key]) >= 10:
                timestamps = self.outbound_connections[flow_key]
                deltas = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
                avg_delta = sum(deltas) / len(deltas)
                variance = sum((d - avg_delta) ** 2 for d in deltas) / len(deltas)
                if variance < 2.0 and avg_delta > 1.0:
                    alerts.append(SecurityAlert(
                        alert_id=f"alert-beaconing-{uuid.uuid4()}",
                        title=f"Periodic Network Heartbeat Pattern ({flow_key[0]} -> {flow_key[1]})",
                        description=f"Regular network heartbeats detected with average interval {round(avg_delta, 1)}s and variance {round(variance, 3)}.",
                        severity=EventSeverity.HIGH,
                        rule_id="AEGIS-CORR-003",
                        rule_source="CorrelationEngine",
                        mitre_tactics=["TA0011"],
                        mitre_techniques=["T1071"],
                        source_event_ids=[event.event_id],
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip
                    ))
                    self.outbound_connections[flow_key] = []

        # 6. Behavioral Heuristic 4: Data Exfiltration Volume Spike (> 50MB outbound)
        bytes_out = event.metadata.get("bytes_out", 0)
        if bytes_out and event.source_ip and event.destination_ip:
            flow_key = (event.source_ip, event.destination_ip)
            self.outbound_bandwidth_bytes[flow_key] += bytes_out
            if self.outbound_bandwidth_bytes[flow_key] > (50 * 1024 * 1024):
                mb_transferred = round(self.outbound_bandwidth_bytes[flow_key] / (1024 * 1024), 2)
                alerts.append(SecurityAlert(
                    alert_id=f"alert-exfil-{uuid.uuid4()}",
                    title=f"Anomalous High-Volume Data Exfiltration: {mb_transferred} MB transferred",
                    description=f"Host {flow_key[0]} transmitted {mb_transferred} MB to external target {flow_key[1]} within monitoring window.",
                    severity=EventSeverity.CRITICAL,
                    rule_id="AEGIS-CORR-004",
                    rule_source="CorrelationEngine",
                    mitre_tactics=["TA0010"],
                    mitre_techniques=["T1048"],
                    source_event_ids=[event.event_id],
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip
                ))
                self.outbound_bandwidth_bytes[flow_key] = 0

        self.generated_alerts.extend(alerts)
        return alerts
