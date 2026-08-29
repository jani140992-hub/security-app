import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.siem.parser import LogParser
from aegisguard.siem.engine import CorrelationEngine
from aegisguard.core.models import NormalizedSecurityEvent


class TestSiemSubsystem(unittest.TestCase):
    def test_syslog_parsing(self):
        line = "<34>Oct 11 22:14:15 srv-db01 sshd[4321]: Accepted publickey for ubuntu from 10.0.1.5 port 55432"
        evt = LogParser.parse_syslog(line)
        self.assertEqual(evt.hostname, "srv-db01")
        self.assertEqual(evt.process_name, "sshd")
        self.assertEqual(evt.process_id, 4321)

    def test_nginx_access_parsing(self):
        line = '192.168.1.50 - admin [11/Oct/2024:14:32:10 +0000] "GET /api/v1/users HTTP/1.1" 200 4520 "-" "Mozilla/5.0"'
        evt = LogParser.parse_nginx_access(line)
        self.assertEqual(evt.source_ip, "192.168.1.50")
        self.assertEqual(evt.action, "SUCCESS")

    def test_correlation_engine_alerting(self):
        engine = CorrelationEngine()
        # Feed 6 failed login events for the same host & user
        alerts = []
        for i in range(6):
            evt = NormalizedSecurityEvent(
                event_id=f"evt-{i}",
                timestamp="2024-01-01T00:00:00Z",
                source_type="evtx",
                event_type="logon",
                action="FAILURE",
                hostname="SRV-DC01",
                user_name="Administrator"
            )
            alerts.extend(engine.process_event(evt))

        # Must trigger brute-force threshold alert
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "AEGIS-CORR-001")


if __name__ == "__main__":
    unittest.main()
