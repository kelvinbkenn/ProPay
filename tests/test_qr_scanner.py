"""
Unit and Security Test Suite for ProPay Signed Dynamic QR Code Engine (qr_scanner.py)

Tests:
- Key generation and retrieval (KeyManager)
- Dynamic payload construction with CSPRNG nonce and timestamp
- Cryptographic signature generation and verification (HMAC-SHA256)
- Anti-tampering defense (Amount tampering, VPA tampering, nonce tampering)
- Replay attack defense (Nonce consumption and duplicate rejection)
- Expiry window defense (Expired QR rejection)
- UTF-8 Half-Block ASCII terminal QR rendering
- Image export (PNG) and OpenCV detection & decoding roundtrip
"""

import os
import sys
import time
import json
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qr_scanner import KeyManager, NonceManager, SignedQREngine


class TestSignedQREngine(unittest.TestCase):
    """Test suite for ProPay attack-resilient QR code subsystem."""

    def setUp(self):
        # Create temporary isolated directory for keys and nonces
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.key_file = self.temp_path / "test_key.key"
        self.nonce_file = self.temp_path / "test_nonces.json"

        self.key_mgr = KeyManager(key_path=self.key_file)
        self.nonce_mgr = NonceManager(cache_file=self.nonce_file)
        self.engine = SignedQREngine(
            key_manager=self.key_mgr,
            nonce_manager=self.nonce_mgr,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_key_manager_generation_and_persistence(self):
        """Validates key generation produces 32+ bytes and persists across instances."""
        key1 = self.key_mgr.get_or_create_hmac_key()
        self.assertGreaterEqual(len(key1), 32)
        self.assertTrue(self.key_file.exists())

        # Second instance loads the same persisted key
        key_mgr2 = KeyManager(key_path=self.key_file)
        key2 = key_mgr2.get_or_create_hmac_key()
        self.assertEqual(key1, key2)

    def test_02_payload_structure_and_signature(self):
        """Validates generated payload contains all required fields and a 64-char HMAC-SHA256 hex signature."""
        payload = self.engine.generate_payload(
            vpa="alice@propay",
            amount=150.75,
            name="Alice Store",
            ttl_seconds=60,
        )

        required_keys = [
            "version", "vpa", "name", "amount", "currency",
            "txn_nonce", "timestamp", "expires_at", "sig_alg", "sig"
        ]
        for k in required_keys:
            self.assertIn(k, payload, f"Missing key in payload: {k}")

        self.assertEqual(payload["version"], SignedQREngine.PROTOCOL_VERSION)
        self.assertEqual(payload["vpa"], "alice@propay")
        self.assertEqual(payload["amount"], 150.75)
        self.assertEqual(payload["currency"], "INR")
        self.assertEqual(payload["sig_alg"], "HMAC-SHA256")
        self.assertEqual(len(payload["sig"]), 64)  # 256 bits = 64 hex chars
        self.assertEqual(len(payload["txn_nonce"]), 32)  # 16 bytes = 32 hex chars

    def test_03_verification_genuine_payload(self):
        """Validates that a genuine, unmodified payload passes verification."""
        payload = self.engine.generate_payload(
            vpa="bob@propay",
            amount=99.00,
            name="Bob Merchant",
            ttl_seconds=300,
        )

        is_valid, msg, verified_data = self.engine.verify_payload(payload)
        self.assertTrue(is_valid, f"Expected valid payload, got failure: {msg}")
        self.assertIsNotNone(verified_data)
        self.assertEqual(verified_data["vpa"], "bob@propay")
        self.assertEqual(verified_data["amount"], 99.00)

    def test_04_tamper_defense_amount_modification(self):
        """Validates that modifying transaction amount by even $0.01 triggers signature rejection."""
        payload = self.engine.generate_payload(
            vpa="store@propay",
            amount=100.00,
        )

        # Attacker reduces amount from 100.00 to 1.00
        tampered_payload = dict(payload)
        tampered_payload["amount"] = 1.00

        is_valid, msg, _ = self.engine.verify_payload(tampered_payload)
        self.assertFalse(is_valid, "Tampered amount should be rejected!")
        self.assertIn("Signature Mismatch", msg)

    def test_05_tamper_defense_vpa_redirection(self):
        """Validates that changing the recipient VPA triggers signature rejection."""
        payload = self.engine.generate_payload(
            vpa="charity@propay",
            amount=50.00,
        )

        # Attacker redirects recipient to attacker's VPA
        tampered_payload = dict(payload)
        tampered_payload["vpa"] = "attacker@evil"

        is_valid, msg, _ = self.engine.verify_payload(tampered_payload)
        self.assertFalse(is_valid, "Redirected VPA should be rejected!")
        self.assertIn("Signature Mismatch", msg)

    def test_06_tamper_defense_nonce_alteration(self):
        """Validates that modifying nonce triggers signature rejection."""
        payload = self.engine.generate_payload(
            vpa="merchant@propay",
            amount=20.00,
        )

        tampered_payload = dict(payload)
        tampered_payload["txn_nonce"] = "0" * 32

        is_valid, msg, _ = self.engine.verify_payload(tampered_payload)
        self.assertFalse(is_valid, "Modified nonce should be rejected!")
        self.assertIn("Signature Mismatch", msg)

    def test_07_replay_attack_prevention(self):
        """Validates that submitting the same valid nonce a second time is rejected."""
        payload = self.engine.generate_payload(
            vpa="cafe@propay",
            amount=45.50,
            ttl_seconds=120,
        )

        # First verification succeeds and consumes nonce
        is_valid1, msg1, _ = self.engine.verify_payload(payload, consume_nonce=True)
        self.assertTrue(is_valid1, f"First redemption failed: {msg1}")

        # Second verification with same payload is caught as replay attack
        is_valid2, msg2, _ = self.engine.verify_payload(payload, consume_nonce=True)
        self.assertFalse(is_valid2, "Replayed QR code was not caught!")
        self.assertIn("Replay Attack Detected", msg2)

    def test_08_expiration_defense(self):
        """Validates that expired dynamic QR codes are rejected."""
        payload = self.engine.generate_payload(
            vpa="taxi@propay",
            amount=15.00,
            ttl_seconds=-10,  # Expired 10 seconds ago
        )

        is_valid, msg, _ = self.engine.verify_payload(payload, check_expiry=True)
        self.assertFalse(is_valid, "Expired QR should be rejected!")
        self.assertIn("Expired QR Code", msg)

    def test_09_ascii_qr_rendering(self):
        """Validates that ASCII rendering produces high-contrast half-block output."""
        payload = self.engine.generate_payload(
            vpa="test@propay",
            amount=10.00,
        )
        ascii_art = self.engine.render_ascii_qr(payload)
        self.assertIsInstance(ascii_art, str)
        self.assertGreater(len(ascii_art), 100)
        # Should contain half-block unicode characters
        has_block_chars = any(c in ascii_art for c in ["█", "▀", "▄", " "])
        self.assertTrue(has_block_chars, "Rendered QR must contain block characters")

    def test_10_image_export_and_opencv_decode_roundtrip(self):
        """Validates exporting to PNG image and decoding via OpenCV QRCodeDetector."""
        payload = self.engine.generate_payload(
            vpa="kiosk@propay",
            amount=88.50,
            name="ProPay Kiosk",
            ttl_seconds=180,
        )

        output_png = self.temp_path / "kiosk_qr.png"
        saved_path = self.engine.export_qr_image(payload, output_png)
        self.assertTrue(saved_path.exists())
        self.assertGreater(saved_path.stat().st_size, 100)

        # Decode image using OpenCV
        decoded_text, _ = self.engine.decode_qr_image(saved_path)
        self.assertIsNotNone(decoded_text, "Failed to decode exported QR image via OpenCV!")

        # Verify decoded payload
        is_valid, msg, decoded_payload = self.engine.verify_payload(decoded_text)
        self.assertTrue(is_valid, f"Decoded QR payload failed verification: {msg}")
        self.assertEqual(decoded_payload["vpa"], "kiosk@propay")
        self.assertEqual(decoded_payload["amount"], 88.50)


if __name__ == "__main__":
    unittest.main()
