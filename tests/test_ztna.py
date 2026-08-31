import unittest
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.crypto.ztna_policy import (
    ZtnaPolicyEngine,
    ZtnaSubjectContext,
    ZtnaAccessRequest,
    ZtnaDecisionType,
    DataSensitivity
)


class TestZtnaPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.valid_subject = ZtnaSubjectContext(
            user_id="analyst.secops@enterprise.local",
            user_roles=["SecOps_Analyst", "Cloud_Auditor"],
            device_id="DEV-LAPTOP-1042",
            device_is_managed=True,
            device_edr_healthy=True,
            device_disk_encrypted=True,
            source_ip="10.10.4.15",
            mfa_authenticated_at_epoch=time.time() - 300,
            identity_risk_score=10.0
        )

    def test_permit_healthy_request(self):
        req = ZtnaAccessRequest(
            request_id="req-001",
            subject=self.valid_subject,
            target_resource_id="srv-k8s-control-plane",
            target_protocol="HTTPS",
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            requested_action="READ"
        )
        res = ZtnaPolicyEngine.evaluate_request(req)
        self.assertEqual(res.decision, ZtnaDecisionType.PERMIT)
        self.assertGreater(res.session_ttl_seconds, 0)

    def test_deny_unmanaged_device(self):
        self.valid_subject.device_is_managed = False
        req = ZtnaAccessRequest(
            request_id="req-002",
            subject=self.valid_subject,
            target_resource_id="srv-db-prod",
            target_protocol="TLS",
            data_sensitivity=DataSensitivity.INTERNAL,
            requested_action="READ"
        )
        res = ZtnaPolicyEngine.evaluate_request(req)
        self.assertEqual(res.decision, ZtnaDecisionType.DENY)

    def test_isolate_compromised_edr(self):
        self.valid_subject.device_edr_healthy = False
        req = ZtnaAccessRequest(
            request_id="req-003",
            subject=self.valid_subject,
            target_resource_id="srv-db-prod",
            target_protocol="TLS",
            data_sensitivity=DataSensitivity.INTERNAL,
            requested_action="READ"
        )
        res = ZtnaPolicyEngine.evaluate_request(req)
        self.assertEqual(res.decision, ZtnaDecisionType.ISOLATE)

    def test_step_up_mfa_stale_authentication(self):
        self.valid_subject.mfa_authenticated_at_epoch = time.time() - 7200  # 2 hours old
        req = ZtnaAccessRequest(
            request_id="req-004",
            subject=self.valid_subject,
            target_resource_id="srv-vault-secrets",
            target_protocol="HTTPS",
            data_sensitivity=DataSensitivity.RESTRICTED_MISSION_CRITICAL,
            requested_action="ADMIN"
        )
        res = ZtnaPolicyEngine.evaluate_request(req)
        self.assertEqual(res.decision, ZtnaDecisionType.STEP_UP_MFA)


if __name__ == "__main__":
    unittest.main()
