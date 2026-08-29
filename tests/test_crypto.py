import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegisguard.crypto.pki import ZeroTrustCryptoEngine


class TestZeroTrustCrypto(unittest.TestCase):
    def test_password_hashing_and_verification(self):
        pwd = "P@ssw0rdSecureEnterprise2026!"
        h_data = ZeroTrustCryptoEngine.hash_password(pwd)
        self.assertTrue(ZeroTrustCryptoEngine.verify_password(pwd, h_data["salt_hex"], h_data["hash_hex"]))
        self.assertFalse(ZeroTrustCryptoEngine.verify_password("WrongPassword!", h_data["salt_hex"], h_data["hash_hex"]))

    def test_x509_certificate_issuance_and_validation(self):
        cert = ZeroTrustCryptoEngine.issue_certificate("internal.api.aegisguard.local", validity_days=30)
        val = ZeroTrustCryptoEngine.validate_certificate(cert)
        self.assertTrue(val["is_valid"])
        self.assertEqual(val["status"], "VALID")
        self.assertGreaterEqual(val["remaining_days"], 29)


if __name__ == "__main__":
    unittest.main()
