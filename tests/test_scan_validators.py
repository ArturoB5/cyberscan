import unittest

from fastapi import HTTPException

from backend.routes.scan import (
    _validate_domain,
    _validate_hash,
    _validate_public_ip,
    _validate_public_url,
)
from backend.services.analyzer import classify_risk


class ScanValidatorTests(unittest.TestCase):
    def test_valid_public_url(self):
        self.assertEqual(
            _validate_public_url("https://example.com/path"),
            "https://example.com/path",
        )

    def test_reject_localhost_url(self):
        with self.assertRaises(HTTPException):
            _validate_public_url("http://localhost/admin")

    def test_reject_private_ip(self):
        with self.assertRaises(HTTPException):
            _validate_public_ip("192.168.1.10")

    def test_accept_public_ip(self):
        self.assertEqual(_validate_public_ip("8.8.8.8"), "8.8.8.8")

    def test_valid_domain(self):
        self.assertEqual(_validate_domain("example.com"), "example.com")

    def test_invalid_hash(self):
        with self.assertRaises(HTTPException):
            _validate_hash("123")

    def test_sha256_hash_normalized(self):
        sample = "A" * 64
        self.assertEqual(_validate_hash(sample), sample.lower())

    def test_classify_risk(self):
        self.assertEqual(classify_risk({"malicious": 0, "suspicious": 0}), "SAFE")
        self.assertEqual(classify_risk({"malicious": 1, "suspicious": 0}), "MEDIUM RISK")
        self.assertEqual(classify_risk({"malicious": 6, "suspicious": 0}), "HIGH RISK")


if __name__ == "__main__":
    unittest.main()
