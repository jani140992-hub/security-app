import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.cspm.auto_remediation import (
    CspmAutoRemediator,
    RemediationStatus,
    DriftRemediationTask
)


class TestCspmAutoRemediation(unittest.TestCase):
    def test_s3_public_access_remediation_dry_run(self):
        task = CspmAutoRemediator.remediate_s3_public_access("finance-reports-backup", dry_run=True)
        self.assertEqual(task.status, RemediationStatus.PLANNED)
        self.assertTrue(task.dry_run)

    def test_s3_public_access_remediation_live(self):
        task = CspmAutoRemediator.remediate_s3_public_access("finance-reports-backup", dry_run=False)
        self.assertEqual(task.status, RemediationStatus.SUCCESS)
        self.assertIn("PublicAccessBlockConfiguration", task.details)

    def test_security_group_ingress_remediation(self):
        task = CspmAutoRemediator.remediate_open_security_group("sg-0a1b2c3d", 22)
        self.assertEqual(task.status, RemediationStatus.SUCCESS)
        self.assertIn("port 22", task.details)

    def test_storage_encryption_remediation(self):
        task = CspmAutoRemediator.remediate_unencrypted_storage("customer-logs-store")
        self.assertEqual(task.status, RemediationStatus.SUCCESS)
        self.assertIn("SSE-KMS", task.details)


if __name__ == "__main__":
    unittest.main()
