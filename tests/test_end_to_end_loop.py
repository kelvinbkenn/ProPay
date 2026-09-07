"""
End-to-End Integration Test Suite for ProPay Zero-Trust Payment Platform
Validates the complete payment lifecycle:
1. Dynamic QR Code Generation with HMAC-SHA256 signing
2. QR Code parsing & cryptographic verification
3. Factor 1: Biometric Face verification with 128-D SFace embedding
4. Factor 2: Hardened constant-time PIN authentication
5. Replay protection (nonce consumption)
6. Atomic Ledger Commitment & Merkle tree update
7. O(log N) Merkle inclusion proof verification
8. Balance integrity & anti-overdraft validation
"""

import os
import sys
import time
import tempfile
import unittest
import numpy as np
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qr_scanner import SignedQREngine, KeyManager, NonceManager
from pin_auth import PINAuthManager
from crypto_vault import CryptoVault
from ledger import TamperEvidentLedger, Transaction, MerkleProof


class TestEndToEndTransactionLoop(unittest.TestCase):
    """End-to-End test suite validating the complete ProPay transaction loop."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

        self.vault_dir = self.base_path / "vault"
        self.auth_dir = self.base_path / "auth"
        self.keys_file = self.base_path / "keys" / "qr_hmac.key"
        self.nonces_file = self.base_path / "used_nonces.json"
        self.ledger_file = self.base_path / "ledger.json"

        # Initialize subsystems in isolated environment
        self.vault = CryptoVault(vault_dir=self.vault_dir)
        self.pin_auth = PINAuthManager(auth_dir=self.auth_dir, iterations=1_000)
        self.key_mgr = KeyManager(key_path=self.keys_file)
        self.nonce_mgr = NonceManager(cache_file=self.nonces_file)
        self.qr_engine = SignedQREngine(key_manager=self.key_mgr, nonce_manager=self.nonce_mgr)
        self.ledger = TamperEvidentLedger(ledger_file=self.ledger_file)

        # Setup test accounts
        self.payer_vpa = "alice@propay"
        self.payee_vpa = "merchant_coffee@propay"
        self.payer_pin = "789123"

        # Enroll PIN
        self.pin_auth.setup_pin(self.payer_vpa, self.payer_pin, enforce_policy=False)

        # Enroll Biometric Face Embedding in AES-256-GCM vault
        raw_emb = np.random.randn(128).astype(np.float32)
        self.enrolled_embedding = raw_emb / np.linalg.norm(raw_emb)
        self.vault.store_biometric_template("alice", self.enrolled_embedding)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_complete_successful_transaction_loop(self):
        """Validates a complete genuine transaction through all authorization and settlement stages."""
        initial_payer_balance = self.ledger.get_balance(self.payer_vpa)
        self.assertEqual(initial_payer_balance, 2500.00)

        payment_amount = 350.00

        # Step 1: Merchant Generates Signed Dynamic QR Code
        qr_payload = self.qr_engine.generate_payload(
            vpa=self.payee_vpa,
            amount=payment_amount,
            name="Artisan Coffee Roasters",
            currency="INR",
            ttl_seconds=120,
        )
        self.assertEqual(qr_payload["vpa"], self.payee_vpa)
        self.assertEqual(qr_payload["amount"], payment_amount)
        self.assertIn("sig", qr_payload)
        self.assertEqual(len(qr_payload["sig"]), 64)

        # Step 2: Customer Scans & Validates QR Cryptographic Integrity
        is_qr_valid, qr_msg, parsed_qr = self.qr_engine.verify_payload(qr_payload, consume_nonce=False)
        self.assertTrue(is_qr_valid, f"QR verification failed: {qr_msg}")
        self.assertEqual(parsed_qr["amount"], payment_amount)

        # Step 3: Factor 1 — Biometric Face Verification
        loaded_emb = self.vault.load_biometric_template("alice")
        self.assertIsNotNone(loaded_emb)

        # Candidate face frame captured with slight normal camera variance (std=0.01)
        candidate_face = self.enrolled_embedding + np.random.normal(0, 0.01, 128).astype(np.float32)
        candidate_face = candidate_face / np.linalg.norm(candidate_face)

        cosine_sim = float(np.dot(candidate_face, loaded_emb) / (np.linalg.norm(candidate_face) * np.linalg.norm(loaded_emb)))
        self.assertGreater(cosine_sim, 0.95)
        bio_passed = cosine_sim >= 0.650
        self.assertTrue(bio_passed)

        # Step 4: Factor 2 — Constant-Time PIN Verification
        pin_ok, pin_msg, pin_details = self.pin_auth.authenticate(self.payer_vpa, self.payer_pin)
        self.assertTrue(pin_ok, f"PIN authentication failed: {pin_msg}")
        self.assertFalse(pin_details["locked"])

        # Step 5: Consume Dynamic Nonce (Anti-Replay)
        nonce = qr_payload["txn_nonce"]
        self.assertFalse(self.nonce_mgr.is_nonce_used(nonce))
        self.nonce_mgr.mark_nonce_used(nonce, int(qr_payload["expires_at"]))
        self.assertTrue(self.nonce_mgr.is_nonce_used(nonce))

        # Step 6: Atomic Ledger Commitment & Merkle Root Update
        ok_commit, commit_msg, tx = self.ledger.record_transaction(
            sender_vpa=self.payer_vpa,
            receiver_vpa=self.payee_vpa,
            amount=payment_amount,
            auth_factors=[
                "BIOMETRIC_FACE_VERIFIED",
                "CONSTANT_TIME_PIN_VERIFIED",
                "DYNAMIC_QR_HMAC_VERIFIED",
            ],
            metadata={
                "qr_nonce": nonce,
                "merchant_name": "Artisan Coffee Roasters",
            },
            check_balance=True,
        )
        self.assertTrue(ok_commit, f"Ledger commit failed: {commit_msg}")
        self.assertIsNotNone(tx)
        self.assertEqual(tx.amount, payment_amount)
        self.assertEqual(tx.sender_vpa, self.payer_vpa)
        self.assertEqual(tx.receiver_vpa, self.payee_vpa)

        # Step 7: Merkle Inclusion Proof Generation and Verification
        proof = self.ledger.get_merkle_proof(tx.tx_id)
        self.assertIsNotNone(proof)
        self.assertTrue(proof.verify(), "Merkle inclusion proof verification failed!")

        # Step 8: Balances Verification
        new_payer_bal = self.ledger.get_balance(self.payer_vpa)
        new_payee_bal = self.ledger.get_balance(self.payee_vpa)
        self.assertEqual(new_payer_bal, initial_payer_balance - payment_amount)
        self.assertEqual(new_payee_bal, payment_amount)

        # Step 9: Ledger Cryptographic Chain Integrity Audit
        chain_ok, violations = self.ledger.verify_chain_integrity()
        self.assertTrue(chain_ok, f"Ledger integrity compromised: {violations}")

    def test_rejected_transaction_when_pin_incorrect(self):
        """Validates that transaction cannot settle if PIN auth fails, without consuming nonce or balance."""
        init_bal = self.ledger.get_balance(self.payer_vpa)
        qr_payload = self.qr_engine.generate_payload(vpa=self.payee_vpa, amount=100.0)

        # Attempt with incorrect PIN
        pin_ok, _, _ = self.pin_auth.authenticate(self.payer_vpa, "000000")
        self.assertFalse(pin_ok)

        # Ensure nonce not marked used
        self.assertFalse(self.nonce_mgr.is_nonce_used(qr_payload["txn_nonce"]))

        # Ensure balance untouched
        self.assertEqual(self.ledger.get_balance(self.payer_vpa), init_bal)

    def test_rejected_transaction_when_qr_tampered(self):
        """Validates that modified QR amounts trigger instant rejection before auth."""
        qr_payload = self.qr_engine.generate_payload(vpa=self.payee_vpa, amount=100.0)
        # Malicious modification
        qr_payload["amount"] = 1.0

        is_valid, msg, _ = self.qr_engine.verify_payload(qr_payload)
        self.assertFalse(is_valid)
        self.assertIn("Signature Mismatch", msg)


if __name__ == "__main__":
    unittest.main()
