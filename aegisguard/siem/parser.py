"""
Multi-Format Security Telemetry Ingestion and Normalization Engine.
Parses Syslog (RFC 3164/5424), Windows EVTX JSON, AWS CloudTrail,
Suricata EVE JSON, and Web Access logs into NormalizedSecurityEvent schemas.
"""

import re
import json
import uuid
import datetime
from typing import Dict, Any, Optional, List
from aegisguard.core.models import NormalizedSecurityEvent


class LogParser:
    """Multi-source telemetry normalizer."""

    @classmethod
    def parse_syslog(cls, raw_line: str) -> NormalizedSecurityEvent:
        """Parse standard RFC 3164 / 5424 Syslog strings."""
        event_id = f"syslog-{uuid.uuid4()}"
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        hostname = "unknown-host"
        proc_name = "syslog"
        pid = None
        cmd = raw_line

        m = re.match(r"^<(\d+)>(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+([^\s]+)\s+([^:\[]+)(?:\[(\d+)\])?:\s+(.*)$", raw_line)
        if m:
            hostname = m.group(2)
            proc_name = m.group(3)
            pid = int(m.group(4)) if m.group(4) else None
            cmd = m.group(5)

        return NormalizedSecurityEvent(
            event_id=event_id,
            timestamp=ts,
            source_type="syslog",
            event_type="system_log",
            hostname=hostname,
            process_name=proc_name,
            process_id=pid,
            command_line=cmd,
            raw_payload=raw_line
        )

    @classmethod
    def parse_windows_event(cls, event_data: Dict[str, Any]) -> NormalizedSecurityEvent:
        """Parse Windows Security Event Log JSON."""
        system = event_data.get("Event", {}).get("System", {})
        event_data_fields = event_data.get("Event", {}).get("EventData", {})
        if isinstance(event_data_fields, list):
            event_data_fields = {d.get("@Name", f"Field_{idx}"): d.get("#text", "") for idx, d in enumerate(event_data_fields)}

        event_id_num = system.get("EventID", "0")
        event_id = f"winevt-{event_id_num}-{uuid.uuid4()}"
        ts = system.get("TimeCreated", {}).get("@SystemTime", datetime.datetime.utcnow().isoformat() + "Z")
        hostname = system.get("Computer", "WINDOWS-HOST")

        event_type = "windows_security"
        action = None
        user_name = event_data_fields.get("TargetUserName") or event_data_fields.get("SubjectUserName")
        cmd_line = event_data_fields.get("CommandLine")
        image = event_data_fields.get("NewProcessName") or event_data_fields.get("ProcessName")
        proc_id = None
        if "ProcessId" in event_data_fields:
            try:
                proc_id = int(str(event_data_fields["ProcessId"]), 16 if "0x" in str(event_data_fields["ProcessId"]) else 10)
            except ValueError:
                pass

        if event_id_num == "4624":
            event_type = "logon"
            action = "SUCCESS"
        elif event_id_num == "4625":
            event_type = "logon"
            action = "FAILURE"
        elif event_id_num == "4688":
            event_type = "process_creation"
            action = "EXECUTE"

        return NormalizedSecurityEvent(
            event_id=event_id,
            timestamp=ts,
            source_type="evtx",
            event_type=event_type,
            hostname=hostname,
            user_name=user_name,
            process_name=image,
            process_id=proc_id,
            command_line=cmd_line,
            action=action,
            source_ip=event_data_fields.get("IpAddress"),
            source_port=int(event_data_fields["IpPort"]) if event_data_fields.get("IpPort") and str(event_data_fields["IpPort"]).isdigit() else None,
            raw_payload=json.dumps(event_data)
        )

    @classmethod
    def parse_cloudtrail(cls, record: Dict[str, Any]) -> NormalizedSecurityEvent:
        """Parse AWS CloudTrail audit event records."""
        event_id = record.get("eventID", str(uuid.uuid4()))
        ts = record.get("eventTime", datetime.datetime.utcnow().isoformat() + "Z")
        event_name = record.get("eventName", "UnknownApiCall")
        user_identity = record.get("userIdentity", {})
        user_name = user_identity.get("userName") or user_identity.get("principalId", "aws-principal")
        src_ip = record.get("sourceIPAddress")

        return NormalizedSecurityEvent(
            event_id=f"cloudtrail-{event_id}",
            timestamp=ts,
            source_type="cloudtrail",
            event_type="cloud_api",
            action=record.get("errorCode", "SUCCESS"),
            source_ip=src_ip,
            user_name=user_name,
            command_line=f"{record.get('eventSource')}:{event_name}",
            metadata=record,
            raw_payload=json.dumps(record)
        )

    @classmethod
    def parse_suricata(cls, record: Dict[str, Any]) -> NormalizedSecurityEvent:
        """Parse Suricata EVE JSON network intrusion alerts."""
        event_id = f"suricata-{uuid.uuid4()}"
        ts = record.get("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
        alert = record.get("alert", {})
        action = alert.get("action", "ALERT")

        return NormalizedSecurityEvent(
            event_id=event_id,
            timestamp=ts,
            source_type="suricata",
            event_type="network_ids_alert",
            source_ip=record.get("src_ip"),
            source_port=record.get("src_port"),
            destination_ip=record.get("dest_ip"),
            destination_port=record.get("dest_port"),
            protocol=record.get("proto"),
            action=action,
            command_line=alert.get("signature", "Suricata Alert"),
            metadata=record,
            raw_payload=json.dumps(record)
        )

    @classmethod
    def parse_nginx_access(cls, log_line: str) -> NormalizedSecurityEvent:
        """Parse standard Nginx / Apache combined access log lines."""
        event_id = f"nginx-{uuid.uuid4()}"
        ts = datetime.datetime.utcnow().isoformat() + "Z"

        m = re.match(r"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+\"(\S+)\s+(\S+)\s*([^\"]*)\"\s+(\d+)\s+(\d+)", log_line)
        if m:
            src_ip = m.group(1)
            user = m.group(2) if m.group(2) != "-" else None
            method = m.group(4)
            path = m.group(5)
            status_code = m.group(7)
            action = "SUCCESS" if status_code.startswith("2") or status_code.startswith("3") else "FAILURE"

            return NormalizedSecurityEvent(
                event_id=event_id,
                timestamp=ts,
                source_type="nginx",
                event_type="web_access",
                source_ip=src_ip,
                user_name=user,
                action=action,
                command_line=f"{method} {path} HTTP/1.1",
                metadata={"status_code": status_code, "method": method, "path": path},
                raw_payload=log_line
            )

        return NormalizedSecurityEvent(
            event_id=event_id,
            timestamp=ts,
            source_type="nginx",
            event_type="web_access",
            command_line=log_line,
            raw_payload=log_line
        )
