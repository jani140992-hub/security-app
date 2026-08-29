"""
AegisGuard Enterprise Security Platform CLI Utility.
Command-line interface for SecOps operators, SOC analysts, and DevSecOps engineers.
"""

import sys
import argparse
import json
from aegisguard.api.app import get_system_overview
from aegisguard.catalogs.cve_cwe_database import CveDatabaseEngine
from aegisguard.catalogs.stix_threat_intel import ThreatIntelligenceEngine
from aegisguard.catalogs.nist_sp800_53 import NistSp80053Engine, BaselineImpact
from aegisguard.catalogs.cis_benchmarks import CisBenchmarkEngine
from aegisguard.siem.parser import LogParser
from aegisguard.siem.engine import CorrelationEngine
from aegisguard.soar.playbooks import SoarPlaybookEngine


def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AegisGuard Enterprise Cyber Defense & SecOps CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational Subcommands")

    # Command: overview
    subparsers.add_parser("overview", help="Display platform health and taxonomy overview")

    # Command: scan-log
    p_scan = subparsers.add_parser("scan-log", help="Scan raw security event log through detection engine")
    p_scan.add_argument("--log", type=str, help="Raw syslog, nginx, or event string", default="<34>Oct 11 22:14:15 srv01 sshd[1234]: Failed password for invalid user root from 198.51.100.42 port 50232 ssh2")
    p_scan.add_argument("--type", type=str, choices=["syslog", "nginx"], default="syslog")

    # Command: check-cve
    p_cve = subparsers.add_parser("check-cve", help="Query CVE database by ID or keyword")
    p_cve.add_argument("query", type=str, help="CVE ID or component keyword")

    # Command: threat-lookup
    p_threat = subparsers.add_parser("threat-lookup", help="Look up IP, domain, or hash in Threat Intel feeds")
    p_threat.add_argument("ioc", type=str, help="Indicator value (IP, FQDN, or SHA256)")

    # Command: audit-compliance
    p_comp = subparsers.add_parser("audit-compliance", help="Evaluate NIST SP 800-53 or CIS compliance baseline")
    p_comp.add_argument("--framework", type=str, choices=["NIST-800-53", "CIS"], default="NIST-800-53")
    p_comp.add_argument("--baseline", type=str, choices=["LOW", "MODERATE", "HIGH"], default="MODERATE")

    # Command: run-playbook
    p_soar = subparsers.add_parser("run-playbook", help="Trigger automated SOAR containment playbook")
    p_soar.add_argument("--action", type=str, choices=["ISOLATE_HOST", "BLOCK_FIREWALL", "REVOKE_IAM"], required=True)
    p_soar.add_argument("--target", type=str, required=True, help="Target IP, hostname, or IAM ARN")

    args = parser.parse_args()

    if not args.command or args.command == "overview":
        data = get_system_overview()
        print("=" * 70)
        print("  AEGISGUARD ENTERPRISE CYBER DEFENSE PLATFORM")
        print("=" * 70)
        print(f"Status:             {data['status']}")
        print(f"MITRE Tactics:      {data['mitre_matrix']['total_tactics']} tactics, {data['mitre_matrix']['total_techniques']} techniques")
        print(f"CVE Vulnerabilities:{data['cve_database']['total_cves']} records ({data['cve_database']['critical_count']} CRITICAL)")
        print(f"NIST Controls:      {data['nist_framework']['total_controls']} controls across {data['nist_framework']['total_families']} families")
        print(f"CIS Benchmarks:     {data['cis_benchmarks']['total_recommendations']} rules across {data['cis_benchmarks']['total_benchmarks']} profiles")
        print(f"Sigma Rules:        {data['sigma_rules']['total_rules']} detection rules")
        print(f"Threat Intelligence:{data['threat_intel']['total_iocs_tracked']} IOCs tracked across {data['threat_intel']['threat_actors_count']} APT actors")
        print("=" * 70)

    elif args.command == "scan-log":
        print(f"[*] Ingesting {args.type} event...")
        if args.type == "syslog":
            evt = LogParser.parse_syslog(args.log)
        else:
            evt = LogParser.parse_nginx_access(args.log)

        engine = CorrelationEngine()
        alerts = engine.process_event(evt)
        print(f"[+] Event parsed: ID={evt.event_id}, Type={evt.event_type}, Action={evt.action}")
        print(f"[+] Alerts triggered: {len(alerts)}")
        for a in alerts:
            print(f"    - [{a.severity.value}] {a.title} ({a.rule_id})")

    elif args.command == "check-cve":
        results = CveDatabaseEngine.search(args.query)[:5]
        if not results:
            print(f"[-] No CVE matching '{args.query}' found.")
        else:
            print(f"[+] Found {len(results)} matching vulnerabilities:")
            for c in results:
                print(f"    [{c.severity.value}] {c.cve_id} (CVSS {c.base_score}) - {c.title}")
                print(f"        Remediation: {c.remediation_guidance[:100]}...")

    elif args.command == "threat-lookup":
        ioc = ThreatIntelligenceEngine.lookup_ioc(args.ioc)
        if not ioc:
            print(f"[-] Indicator '{args.ioc}' not found in active threat intelligence feeds.")
        else:
            print(f"[+] THREAT HIT: {ioc.value}")
            print(f"    Type:        {ioc.ioc_type.value}")
            print(f"    Confidence:  {ioc.confidence}%")
            print(f"    Actor:       {ioc.associated_actor}")
            print(f"    Malware:     {ioc.associated_malware}")
            print(f"    Description: {ioc.description}")

    elif args.command == "audit-compliance":
        if args.framework == "NIST-800-53":
            base_enum = getattr(BaselineImpact, args.baseline)
            res = NistSp80053Engine.evaluate_compliance({"AC-1", "AC-2", "AU-2", "AU-3", "SI-4", "SC-7"}, base_enum)
            print(f"[+] NIST SP 800-53 Rev 5 Audit ({args.baseline} Baseline):")
            print(f"    Required Controls: {res['total_required']}")
            print(f"    Passing Controls:  {res['passed_count']}")
            print(f"    Score:             {res['compliance_score_percent']}%")
        else:
            res = CisBenchmarkEngine.audit_system_posture("CIS-UBUNTU-22.04", {"CIS-UBUNTU-22.04-1.1.1", "CIS-UBUNTU-22.04-1.1.2"})
            print(f"[+] CIS Benchmark Audit (CIS-UBUNTU-22.04):")
            print(f"    Total Rules:       {res['total_rules']}")
            print(f"    Score:             {res['compliance_score_percent']}%")

    elif args.command == "run-playbook":
        print(f"[*] Executing SOAR Playbook '{args.action}' on target '{args.target}'...")
        if args.action == "ISOLATE_HOST":
            rec = SoarPlaybookEngine.execute_host_isolation_playbook(args.target, args.target, "cli-trigger")
        elif args.action == "BLOCK_FIREWALL":
            rec = SoarPlaybookEngine.execute_firewall_ip_block_playbook(args.target, "cli-trigger")
        else:
            rec = SoarPlaybookEngine.execute_revoke_cloud_credentials_playbook(args.target, "cli-trigger")

        print(f"[+] Playbook Execution {rec.execution_id}: {rec.status.value}")
        for s in rec.step_results:
            print(f"    [{s.status}] {s.step_name}: {s.details} ({s.execution_time_ms}ms)")


if __name__ == "__main__":
    main()
