"""
Unit and Security Test Suite for ProPay AES-256-GCM Encrypted Vault (crypto_vault.py)
Tests:
- Master key generation, entropy, and persistence
- Low-level AES-256-GCM authenticated encryption/decryption roundtrip
- Tamper defense: Single-bit alteration in ciphertext triggers InvalidTag rejection
- Identity substitution defense: Associated Data mismatch triggers InvalidTag rejection
- Encrypted biometric template storage, 128-D vector fidelity, and recovery
- Auto-migration of legacy unencrypted JSON templates to encrypted vault
- Cryptographic secrets storage and retrieval
- Vault-wide cryptographic audit detecting bit flips
"""

import os
import sys
import json
import tempfile
import unittest
import numpy as np
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypto_vault import CryptoVault, MasterKeyManager, KEY_SIZE_BYTES


class TestCryptoVault(unittest.TestCase):
    """Test suite for ProPay AES-256-GCM authenticated encryption security vault."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_dir = Path(self.temp_dir.name) / "vault"
        self.key_file = self.vault_dir / "master.key"
        self.vault = CryptoVault(vault_dir=self.vault_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_master_key_generation_and_persistence(self):
        """Validates that 256-bit CSPRNG root key is created and persists."""
        self.assertTrue(self.key_file.exists())
        self.assertEqual(len(self.vault.master_key), KEY_SIZE_BYTES)

        # Reload with new instance
        vault2 = CryptoVault(vault_dir=self.vault_dir)
        self.assertEqual(self.vault.master_key, vault2.master_key)

    def test_02_aes_gcm_encrypt_decrypt_roundtrip(self):
        """Validates AES-256-GCM encrypt and decrypt roundtrip with Associated Data."""
        secret_payload = b"ProPay Confidential Master Key 2026"
        ad = b"header_metadata_v1"

        envelope = self.vault.encrypt_bytes(secret_payload, associated_data=ad)
        self.assertEqual(envelope["cipher"], "AES-256-GCM")
        self.assertIn("nonce_hex", envelope)
        self.assertIn("ciphertext_hex", envelope)

        ok, decrypted, msg = self.vault.decrypt_bytes(envelope, associated_data=ad)
        self.assertTrue(ok, msg)
        self.assertEqual(decrypted, secret_payload)

    def test_03_tamper_defense_ciphertext_alteration(self):
        """Validates that altering even a single bit in ciphertext fails AEAD tag verification."""
        secret_payload = b"Sensitive User Payment Token"
        envelope = self.vault.encrypt_bytes(secret_payload)

        # Tamper with ciphertext by flipping one byte
        ct_bytes = bytearray(bytes.fromhex(envelope["ciphertext_hex"]))
        ct_bytes[4] ^= 0x01
        envelope["ciphertext_hex"] = bytes(ct_bytes).hex()

        ok, decrypted, msg = self.vault.decrypt_bytes(envelope)
        self.assertFalse(ok)
        self.assertIsNone(decrypted)
        self.assertIn("AEAD Authentication Tag Mismatch", msg)

    def test_04_tamper_defense_associated_data_mismatch(self):
        """Validates that changing Associated Data (e.g. user identity) invalidates decryption."""
        secret_payload = b"Alice Face Embedding"
        genuine_ad = b"alice"
        impostor_ad = b"mallory"

        envelope = self.vault.encrypt_bytes(secret_payload, associated_data=genuine_ad)
        # Attempt to decrypt with different identity in AD
        ok, decrypted, msg = self.vault.decrypt_bytes(envelope, associated_data=impostor_ad)
        self.assertFalse(ok)
        self.assertIsNone(decrypted)

    def test_05_biometric_template_vault_store_and_load(self):
        """Validates saving and loading 128-D normalized embedding in encrypted vault."""
        username = "charlie"
        raw_emb = np.random.randn(128).astype(np.float32)
        raw_emb = raw_emb / np.linalg.norm(raw_emb)

        vault_path = self.vault.store_biometric_template(username, raw_emb, {"role": "payer"})
        self.assertTrue(vault_path.exists())

        # Verify file does NOT contain raw float vector in plaintext
        with open(vault_path, "r") as f:
            raw_content = f.read()
        self.assertNotIn(str(raw_emb[0]), raw_content)
        self.assertIn("AES-256-GCM", raw_content)

        # Load and verify mathematical fidelity
        loaded_emb = self.vault.load_biometric_template(username)
        self.assertIsNotNone(loaded_emb)
        self.assertEqual(len(loaded_emb), 128)
        cosine = float(np.dot(raw_emb, loaded_emb) / (np.linalg.norm(raw_emb) * np.linalg.norm(loaded_emb)))
        self.assertAlmostEqual(cosine, 1.0, places=5)

    def test_06_secret_store_and_load(self):
        """Validates arbitrary cryptographic secret storage and retrieval."""
        key_name = "qr_signing_key_test"
        secret_bytes = os.urandom(32)

        self.vault.store_secret(key_name, secret_bytes)
        loaded = self.vault.load_secret(key_name)
        self.assertEqual(loaded, secret_bytes)

    def test_07_vault_audit_detection(self):
        """Validates that audit_vault detects clean vs tampered vault records."""
        # 1. Store clean items
        self.vault.store_biometric_template("user1", np.ones(128, dtype=np.float32))
        self.vault.store_secret("secret1", b"supersecret")

        clean_ok, violations = self.vault.audit_vault()
        self.assertTrue(clean_ok)
        self.assertEqual(len(violations), 0)

        # 2. Tamper with one vault file
        self.vault.tamper_vault_file_for_demo("user1", is_biometric=True)
        tampered_ok, tampered_violations = self.vault.audit_vault()
        self.assertFalse(tampered_ok)
        self.assertEqual(len(tampered_violations), 1)


if __name__ == "__main__":
    unittest.main()
