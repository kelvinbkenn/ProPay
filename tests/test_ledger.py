"""
Unit and Security Test Suite for ProPay Tamper-Evident Transaction Ledger (ledger.py)
Part 5 of the ProPay Secure CLI Payment Platform.

Tests:
- Genesis block generation and anchor hashing
- Sequential append-only SHA-256 hash chaining
- Canonical hash calculation and tamper detection
- Broken link detection in block sequence
- Merkle Tree construction, odd-node handling, and deterministic root
- Merkle inclusion proof generation and cryptographic verification
- Counterfeit/tampered Merkle proof rejection
- Dynamic balance tracking across debits and credits
- Overdraft / insufficient funds enforcement
- Atomic disk persistence and state reload integrity
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

from ledger import (
    Transaction,
    MerkleTree,
    MerkleProof,
    TamperEvidentLedger,
    GENESIS_PREV_HASH,
)


class TestTamperEvidentLedger(unittest.TestCase):
    """Test suite for ProPay attack-resilient cryptographic transaction ledger."""

    def setUp(self):
        # Create isolated temporary ledger file for each test
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)
        self.ledger_file = self.temp_path / "test_ledger.json"
        self.ledger = TamperEvidentLedger(ledger_file=self.ledger_file)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_genesis_block_initialization(self):
        """Validates genesis block structure, deterministic zero-hash anchor, and initial state."""
        self.assertGreaterEqual(len(self.ledger.transactions), 1)
        genesis = self.ledger.transactions[0]

        self.assertEqual(genesis.tx_id, "TXN-GENESIS-00000000")
        self.assertEqual(genesis.prev_hash, GENESIS_PREV_HASH)
        self.assertEqual(genesis.sender_vpa, "system_genesis")
        self.assertEqual(genesis.amount, 0.0)
        self.assertEqual(len(genesis.tx_hash), 64)
        self.assertEqual(genesis.tx_hash, genesis.calculate_hash())

    def test_02_sequential_append_and_hash_chaining(self):
        """Validates sequential blocks correctly chain prev_hash to previous block's tx_hash."""
        ok, msg, tx1 = self.ledger.record_transaction(
            sender_vpa="kelvin@propay",
            receiver_vpa="merchant@propay",
            amount=100.0,
            auth_factors=["BIOMETRIC_FACE_VERIFIED", "PIN_CONSTANT_TIME"],
        )
        self.assertTrue(ok, f"Tx 1 recording failed: {msg}")
        self.assertIsNotNone(tx1)

        ok2, msg2, tx2 = self.ledger.record_transaction(
            sender_vpa="merchant@propay",
            receiver_vpa="supplier@propay",
            amount=50.0,
            auth_factors=["DYNAMIC_QR_HMAC"],
        )
        self.assertTrue(ok2, f"Tx 2 recording failed: {msg2}")
        self.assertIsNotNone(tx2)

        # Check chain link
        self.assertEqual(tx2.prev_hash, tx1.tx_hash)

        # Full chain integrity check passes
        is_valid, violations = self.ledger.verify_chain_integrity()
        self.assertTrue(is_valid, f"Chain validation failed with: {violations}")

    def test_03_tamper_defense_amount_alteration(self):
        """Validates that altering a transaction amount invalidates canonical hash and triggers alert."""
        ok, _, tx = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="store@propay",
            amount=200.00,
            auth_factors=["BIOMETRIC_FACE_VERIFIED"],
        )
        self.assertTrue(ok)

        # Attacker modifies amount
        target_idx = len(self.ledger.transactions) - 1
        self.ledger.transactions[target_idx].amount = 200000.00

        is_valid, violations = self.ledger.verify_chain_integrity()
        self.assertFalse(is_valid, "Tampered amount should break integrity check!")
        self.assertTrue(any("Tamper Alert" in v for v in violations))

    def test_04_tamper_defense_vpa_alteration(self):
        """Validates that modifying recipient or sender VPA is caught immediately."""
        ok, _, tx = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="bob@propay",
            amount=75.00,
            auth_factors=["PIN_CONSTANT_TIME"],
        )
        self.assertTrue(ok)

        # Attacker reroutes funds to attacker@propay
        target_idx = len(self.ledger.transactions) - 1
        self.ledger.transactions[target_idx].receiver_vpa = "attacker@evil"

        is_valid, violations = self.ledger.verify_chain_integrity()
        self.assertFalse(is_valid, "Tampered recipient VPA should break integrity!")
        self.assertTrue(any("Tamper Alert" in v for v in violations))

    def test_05_tamper_defense_broken_hash_link(self):
        """Validates that forging or corrupting prev_hash breaks chain continuity."""
        ok, _, tx = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="bob@propay",
            amount=25.00,
            auth_factors=["PIN_CONSTANT_TIME"],
        )
        self.assertTrue(ok)

        # Corrupt prev_hash of the new block
        target_idx = len(self.ledger.transactions) - 1
        self.ledger.transactions[target_idx].prev_hash = "f" * 64
        # Even if attacker reseals tx_hash to cover up content hash mismatch:
        self.ledger.transactions[target_idx].seal()

        is_valid, violations = self.ledger.verify_chain_integrity()
        self.assertFalse(is_valid, "Broken prev_hash chain link must be caught!")
        self.assertTrue(any("Chain Broken" in v for v in violations))

    def test_06_merkle_tree_root_deterministic(self):
        """Validates Merkle tree builds deterministically and handles odd leaf count."""
        leaves = [
            "a" * 64,
            "b" * 64,
            "c" * 64,
        ]
        tree1 = MerkleTree(leaves)
        tree2 = MerkleTree(leaves)

        self.assertEqual(tree1.root, tree2.root)
        self.assertEqual(len(tree1.root), 64)

        # Empty tree has well-defined root
        empty_tree = MerkleTree([])
        self.assertEqual(len(empty_tree.root), 64)

    def test_07_merkle_inclusion_proof_generation_and_verification(self):
        """Validates generating and verifying Merkle inclusion proof for a valid transaction."""
        ok, _, tx = self.ledger.record_transaction(
            sender_vpa="kelvin@propay",
            receiver_vpa="charlie@propay",
            amount=350.00,
            auth_factors=["BIOMETRIC_FACE_VERIFIED", "PIN_CONSTANT_TIME"],
        )
        self.assertTrue(ok)

        proof = self.ledger.get_merkle_proof(tx.tx_id)
        self.assertIsNotNone(proof, "Should find Merkle proof for recorded tx")
        self.assertEqual(proof.tx_id, tx.tx_id)
        self.assertEqual(proof.merkle_root, self.ledger.merkle_root)

        # Verify proof against current root
        self.assertTrue(proof.verify(), "Merkle proof verification must succeed for genuine leaf")

    def test_08_merkle_proof_counterfeit_rejection(self):
        """Validates that a modified leaf hash or sibling path fails Merkle verification."""
        ok, _, tx = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="dave@propay",
            amount=80.00,
            auth_factors=["DYNAMIC_QR_HMAC"],
        )
        self.assertTrue(ok)

        proof = self.ledger.get_merkle_proof(tx.tx_id)
        self.assertIsNotNone(proof)

        # Case 1: Corrupted leaf hash
        fake_leaf = "0" * 64
        self.assertFalse(
            MerkleTree.verify_proof(fake_leaf, proof.proof_path, proof.merkle_root),
            "Proof verification must fail with forged leaf hash",
        )

        # Case 2: Wrong Merkle root
        fake_root = "1" * 64
        self.assertFalse(
            MerkleTree.verify_proof(proof.leaf_hash, proof.proof_path, fake_root),
            "Proof verification must fail with wrong root",
        )

    def test_09_balance_tracking_and_overdraft_prevention(self):
        """Validates accurate balance calculations and rejection of transactions exceeding balance."""
        # Initial seeded balance for alice@propay is 2500.00
        init_bal = self.ledger.get_balance("alice@propay")
        self.assertEqual(init_bal, 2500.00)

        # Valid spend of ₹500
        ok1, _, _ = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="groceries@propay",
            amount=500.00,
            auth_factors=["PIN_CONSTANT_TIME"],
        )
        self.assertTrue(ok1)
        self.assertEqual(self.ledger.get_balance("alice@propay"), 2000.00)
        self.assertEqual(self.ledger.get_balance("groceries@propay"), 500.00)

        # Overdraft attempt of ₹99,999.00
        ok2, msg2, _ = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="luxury@propay",
            amount=99999.00,
            auth_factors=["PIN_CONSTANT_TIME"],
            check_balance=True,
        )
        self.assertFalse(ok2, "Overdraft transaction should be rejected!")
        self.assertIn("Insufficient funds", msg2)

    def test_10_persistence_and_reload_integrity(self):
        """Validates that saving to disk and re-instantiating ledger preserves chain integrity and Merkle root."""
        self.ledger.record_transaction(
            sender_vpa="kelvin@propay",
            receiver_vpa="cafe@propay",
            amount=120.00,
            auth_factors=["BIOMETRIC_FACE_VERIFIED"],
        )
        original_root = self.ledger.merkle_root
        original_count = len(self.ledger.transactions)

        # Reload from the same file in a brand new instance
        reloaded_ledger = TamperEvidentLedger(ledger_file=self.ledger_file)
        self.assertEqual(len(reloaded_ledger.transactions), original_count)
        self.assertEqual(reloaded_ledger.merkle_root, original_root)

        is_valid, violations = reloaded_ledger.verify_chain_integrity()
        self.assertTrue(is_valid, f"Reloaded ledger should pass integrity check: {violations}")


if __name__ == "__main__":
    unittest.main()
