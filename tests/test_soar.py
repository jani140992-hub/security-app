import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.soar.playbooks import SoarPlaybookEngine, PlaybookStatus


class TestSoarPlaybooks(unittest.TestCase):
    def test_host_isolation_playbook(self):
        rec = SoarPlaybookEngine.execute_host_isolation_playbook("10.0.10.25", "srv-workstation-09", "alert-999")
        self.assertEqual(rec.status, PlaybookStatus.SUCCESS)
        self.assertEqual(len(rec.step_results), 3)

    def test_firewall_ip_block_playbook(self):
        rec = SoarPlaybookEngine.execute_firewall_ip_block_playbook("198.51.100.42", "alert-999")
        self.assertEqual(rec.status, PlaybookStatus.SUCCESS)
        self.assertEqual(len(rec.step_results), 2)

    def test_revoke_credentials_playbook(self):
        rec = SoarPlaybookEngine.execute_revoke_cloud_credentials_playbook("arn:aws:iam::123456789012:user/dev", "alert-999")
        self.assertEqual(rec.status, PlaybookStatus.SUCCESS)
        self.assertEqual(len(rec.step_results), 3)


if __name__ == "__main__":
    unittest.main()
