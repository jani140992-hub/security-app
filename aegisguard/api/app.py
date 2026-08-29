"""
AegisGuard REST API Server and Management Service.
Provides RESTful endpoints for alerts, incident triage, CVE searches,
MITRE matrix navigation, NIST/CIS compliance audits, and live event telemetry.
Includes standalone HTTP server capability and optional FastAPI support.
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any, List

from aegisguard.catalogs.mitre_attack_enterprise import MitreAttackEngine
from aegisguard.catalogs.cve_cwe_database import CveDatabaseEngine, CvssV31Calculator
from aegisguard.catalogs.nist_sp800_53 import NistSp80053Engine, BaselineImpact
from aegisguard.catalogs.cis_benchmarks import CisBenchmarkEngine
from aegisguard.catalogs.sigma_detection_rules import SigmaRuleCompiler
from aegisguard.catalogs.stix_threat_intel import ThreatIntelligenceEngine
from aegisguard.catalogs.owasp_top10 import OwaspEngine, OwaspCategory
from aegisguard.siem.parser import LogParser
from aegisguard.siem.engine import CorrelationEngine
from aegisguard.cspm.auditor import CspmAuditor
from aegisguard.soar.playbooks import SoarPlaybookEngine
from aegisguard.threat_intel.feed import ThreatIntelEnricher


correlation_engine = CorrelationEngine()


def get_system_overview() -> Dict[str, Any]:
    """Aggregate high-level SecOps telemetry overview."""
    return {
        "platform": "AegisGuard Enterprise Cyber Defense & SecOps",
        "status": "OPERATIONAL",
        "version": "1.0.0",
        "mitre_matrix": MitreAttackEngine.get_matrix_coverage_summary(),
        "cve_database": CveDatabaseEngine.get_database_summary(),
        "nist_framework": NistSp80053Engine.get_framework_summary(),
        "cis_benchmarks": CisBenchmarkEngine.get_catalog_summary(),
        "sigma_rules": SigmaRuleCompiler.get_catalog_summary(),
        "threat_intel": ThreatIntelligenceEngine.get_threat_landscape_summary(),
        "owasp_top10": OwaspEngine.get_summary()
    }


class AegisApiHandler(BaseHTTPRequestHandler):
    """Standard HTTP request handler for AegisGuard REST API."""

    def _set_json_headers(self, status_code: int = 200):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_OPTIONS(self):
        self._set_json_headers(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api/v1/health":
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"status": "HEALTHY", "code": 200}).encode("utf-8"))

        elif path == "/api/v1/overview":
            self._set_json_headers(200)
            self.wfile.write(json.dumps(get_system_overview()).encode("utf-8"))

        elif path == "/api/v1/mitre/tactics":
            self._set_json_headers(200)
            tactics = [
                {"id": t.id, "name": t.name, "description": t.description, "order": t.phase_order}
                for t in MitreAttackEngine.get_matrix_coverage_summary().get("tactics", {}).values()
            ]
            self.wfile.write(json.dumps({"tactics": tactics}).encode("utf-8"))

        elif path == "/api/v1/cve/search":
            query = params.get("q", [""])[0]
            results = CveDatabaseEngine.search(query)[:25]
            data = [{
                "cve_id": c.cve_id,
                "title": c.title,
                "score": c.base_score,
                "severity": c.severity.value,
                "cwe": c.cwe_id,
                "is_kev": c.is_known_exploited
            } for c in results]
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"results": data, "count": len(data)}).encode("utf-8"))

        elif path == "/api/v1/threat-intel/lookup":
            indicator = params.get("ioc", [""])[0]
            enrichment = ThreatIntelEnricher.enrich_ip(indicator)
            self._set_json_headers(200)
            self.wfile.write(json.dumps(enrichment).encode("utf-8"))

        elif path == "/api/v1/threat-intel/stix":
            bundle = ThreatIntelligenceEngine.export_stix_bundle()
            self._set_json_headers(200)
            self.wfile.write(json.dumps(bundle).encode("utf-8"))

        elif path == "/api/v1/compliance/nist":
            summary = NistSp80053Engine.get_framework_summary()
            self._set_json_headers(200)
            self.wfile.write(json.dumps(summary).encode("utf-8"))

        elif path == "/api/v1/compliance/cis":
            summary = CisBenchmarkEngine.get_catalog_summary()
            self._set_json_headers(200)
            self.wfile.write(json.dumps(summary).encode("utf-8"))

        else:
            self._set_json_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found", "path": path}).encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/v1/siem/ingest":
            raw_log = payload.get("log", "")
            source_type = payload.get("source_type", "syslog")

            if source_type == "syslog":
                evt = LogParser.parse_syslog(raw_log)
            elif source_type == "nginx":
                evt = LogParser.parse_nginx_access(raw_log)
            elif source_type == "cloudtrail":
                evt = LogParser.parse_cloudtrail(payload.get("data", {}))
            else:
                evt = LogParser.parse_syslog(raw_log)

            alerts = correlation_engine.process_event(evt)
            self._set_json_headers(200)
            self.wfile.write(json.dumps({
                "event_id": evt.event_id,
                "parsed_type": evt.event_type,
                "alerts_triggered": len(alerts),
                "alerts": [{"id": a.alert_id, "title": a.title, "severity": a.severity.value} for a in alerts]
            }).encode("utf-8"))

        elif path == "/api/v1/soar/playbook/run":
            playbook_type = payload.get("playbook")
            target = payload.get("target", "")
            alert_id = payload.get("alert_id", "manual-trigger")

            if playbook_type == "ISOLATE_HOST":
                rec = SoarPlaybookEngine.execute_host_isolation_playbook(target, target, alert_id)
            elif playbook_type == "BLOCK_FIREWALL":
                rec = SoarPlaybookEngine.execute_firewall_ip_block_playbook(target, alert_id)
            elif playbook_type == "REVOKE_IAM":
                rec = SoarPlaybookEngine.execute_revoke_cloud_credentials_playbook(target, alert_id)
            else:
                rec = SoarPlaybookEngine.execute_firewall_ip_block_playbook(target, alert_id)

            self._set_json_headers(200)
            self.wfile.write(json.dumps({
                "execution_id": rec.execution_id,
                "playbook": rec.playbook_name,
                "status": rec.status.value,
                "steps_count": len(rec.step_results)
            }).encode("utf-8"))

        else:
            self._set_json_headers(404)
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode("utf-8"))


def run_server(host: str = "0.0.0.0", port: int = 8443):
    server = HTTPServer((host, port), AegisApiHandler)
    print(f"AegisGuard API Server running on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping server...")
        server.server_close()


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
    run_server(port=p)
