import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.cspm.auditor import CspmAuditor, PostureSeverity


class TestCspmSubsystem(unittest.TestCase):
    def test_aws_audit_detection(self):
        sample_account = {
            "iam_summary": {"AccountMFAEnabled": 0},
            "s3_buckets": [
                {"name": "finance-data-backup", "block_public_access": False, "server_side_encryption": False}
            ],
            "security_groups": [
                {"group_id": "sg-12345", "ingress_rules": [{"cidr": "0.0.0.0/0", "port": 22}]}
            ],
            "cloudtrail": {"is_multi_region": False}
        }
        findings = CspmAuditor.audit_aws_account(sample_account)
        self.assertGreaterEqual(len(findings), 4)

        score_data = CspmAuditor.calculate_posture_score(findings)
        self.assertLess(score_data["posture_score"], 60)
        self.assertEqual(score_data["rating"], "CRITICAL_DEFICIT")


if __name__ == "__main__":
    unittest.main()
