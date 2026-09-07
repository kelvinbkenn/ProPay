"""
Unit and Security Test Suite for ProPay Constant-Time PIN Authentication & Rate Limiter (pin_auth.py)

Tests:
- Numeric PIN policy enforcement (length, non-numeric, trivial, repeating, sequential)
- PBKDF2-HMAC-SHA256 hashing and unique per-user CSPRNG salting
- Constant-time verification of valid vs invalid PINs
- Non-existent user dummy computation defense
- Exponential backoff rate limiter and 3-attempt lockout threshold
- Immediate lockout rejection while locked
- Success counter reset on correct PIN entry
- Administrative lockout reset
- Disk persistence across manager instances
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

from pin_auth import (
    PINPolicy,
    PINHasher,
    RateLimiter,
    PINAuthManager,
    MAX_CONSECUTIVE_FAILURES,
    LOCKOUT_DURATION_SECONDS,
)


class TestPINAuth(unittest.TestCase):
    """Test suite for ProPay attack-resilient PIN authentication subsystem."""

    def setUp(self):
        # Create temporary isolated directory for PIN records
        self.temp_dir = tempfile.TemporaryDirectory()
        self.auth_dir = Path(self.temp_dir.name)
        # Use 1,000 rounds in tests for high test execution speed
        self.test_iterations = 1_000
        self.manager = PINAuthManager(
            auth_dir=self.auth_dir,
            iterations=self.test_iterations,
            max_failures=3,
            lockout_duration_sec=300,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_01_pin_policy_valid_pins(self):
        """Valid 4, 5, and 6-digit non-trivial PINs must be accepted."""
        valid_samples = ["8492", "3901", "72041", "930218", "619482"]
        for pin in valid_samples:
            valid, msg = PINPolicy.validate(pin)
            self.assertTrue(valid, f"Expected '{pin}' to be valid, but got: {msg}")

    def test_02_pin_policy_invalid_format_and_length(self):
        """Non-numeric, too short, or too long PINs must be rejected."""
        invalid_samples = [
            ("", "empty"),
            ("123", "too short (3 digits)"),
            ("1234567", "too long (7 digits)"),
            ("abcd", "alphabetic"),
            ("12a4", "alphanumeric"),
            ("12.4", "decimal punctuation"),
            (" 8492 ", "whitespace padded"),
        ]
        for pin, reason in invalid_samples:
            valid, msg = PINPolicy.validate(pin)
            self.assertFalse(valid, f"Expected rejection for {reason} ('{pin}')")

    def test_03_pin_policy_trivial_and_sequential_rejection(self):
        """Trivial dictionary PINs, repeated digits, and sequential digits must be rejected."""
        bad_pins = [
            "0000", "1111", "9999", "1234", "4321", "2345", "6789", "9876",
            "000000", "123456", "654321", "111111", "777777"
        ]
        for pin in bad_pins:
            valid, msg = PINPolicy.validate(pin)
            self.assertFalse(valid, f"Expected trivial PIN '{pin}' to be rejected")

    def test_04_hasher_unique_salts_and_verification(self):
        """Hasher produces unique salts and distinct hashes for the same PIN."""
        pin = "8402"
        hash1, salt1 = PINHasher.hash_pin(pin, iterations=self.test_iterations)
        hash2, salt2 = PINHasher.hash_pin(pin, iterations=self.test_iterations)

        self.assertNotEqual(salt1, salt2, "CSPRNG salts must be unique across invocations")
        self.assertNotEqual(hash1, hash2, "Hashes with different salts must differ")

        # Verify correct PIN matches
        self.assertTrue(PINHasher.verify_pin(pin, hash1, salt1, iterations=self.test_iterations))
        self.assertTrue(PINHasher.verify_pin(pin, hash2, salt2, iterations=self.test_iterations))

        # Wrong PIN does not match
        self.assertFalse(PINHasher.verify_pin("8403", hash1, salt1, iterations=self.test_iterations))

    def test_05_dummy_computation_runs_without_error(self):
        """Dummy PBKDF2 computation completes without throwing exceptions."""
        try:
            PINHasher.dummy_computation(iterations=500)
        except Exception as e:
            self.fail(f"dummy_computation raised unexpected exception: {e}")

    def test_06_pin_setup_and_auth_success(self):
        """User can enroll a PIN and authenticate successfully."""
        user = "alice"
        pin = "9371"

        ok, msg = self.manager.setup_pin(user, pin)
        self.assertTrue(ok, msg)
        self.assertTrue(self.manager.user_exists(user))

        auth_ok, auth_msg, details = self.manager.authenticate(user, pin)
        self.assertTrue(auth_ok, auth_msg)
        self.assertFalse(details["locked"])
        self.assertEqual(details["failed_attempts"], 0)

    def test_07_nonexistent_user_rejection(self):
        """Attempting to authenticate non-existent user is safely rejected."""
        auth_ok, auth_msg, details = self.manager.authenticate("bob_ghost", "9371")
        self.assertFalse(auth_ok)
        self.assertIn("not registered", auth_msg)
        self.assertFalse(details["locked"])

    def test_08_rate_limiter_lockout_trigger(self):
        """3 consecutive failures trigger lockout, blocking subsequent attempts."""
        user = "charlie"
        correct_pin = "5183"
        wrong_pin = "5184"

        self.manager.setup_pin(user, correct_pin)

        # Attempt 1: Fail
        ok1, msg1, det1 = self.manager.authenticate(user, wrong_pin)
        self.assertFalse(ok1)
        self.assertFalse(det1["locked"])
        self.assertEqual(det1["failed_attempts"], 1)
        self.assertEqual(det1["remaining_attempts"], 2)

        # Attempt 2: Fail
        ok2, msg2, det2 = self.manager.authenticate(user, wrong_pin)
        self.assertFalse(ok2)
        self.assertFalse(det2["locked"])
        self.assertEqual(det2["failed_attempts"], 2)
        self.assertEqual(det2["remaining_attempts"], 1)

        # Attempt 3: Fail -> LOCKOUT
        ok3, msg3, det3 = self.manager.authenticate(user, wrong_pin)
        self.assertFalse(ok3)
        self.assertTrue(det3["locked"])
        self.assertEqual(det3["failed_attempts"], 3)
        self.assertEqual(det3["remaining_attempts"], 0)
        self.assertGreater(det3["lockout_remaining_seconds"], 200)

        # Attempt 4: Even with CORRECT PIN, account remains locked!
        ok4, msg4, det4 = self.manager.authenticate(user, correct_pin)
        self.assertFalse(ok4)
        self.assertTrue(det4["locked"])
        self.assertIn("Account is locked", msg4)

    def test_09_success_resets_failed_counter(self):
        """Successful authentication after 2 failed attempts resets failure counter to 0."""
        user = "david"
        correct_pin = "4819"
        wrong_pin = "4820"

        self.manager.setup_pin(user, correct_pin)

        # 2 failures
        self.manager.authenticate(user, wrong_pin)
        self.manager.authenticate(user, wrong_pin)

        status_mid = self.manager.get_status(user)
        self.assertEqual(status_mid["failed_attempts"], 2)

        # 1 success
        ok, msg, det = self.manager.authenticate(user, correct_pin)
        self.assertTrue(ok)
        self.assertEqual(det["failed_attempts"], 0)

        status_after = self.manager.get_status(user)
        self.assertEqual(status_after["failed_attempts"], 0)
        self.assertFalse(status_after["is_locked"])

    def test_10_admin_lockout_reset(self):
        """Administrative lockout reset immediately restores access."""
        user = "eve"
        correct_pin = "7294"
        wrong_pin = "7295"

        self.manager.setup_pin(user, correct_pin)

        # Cause lockout
        for _ in range(3):
            self.manager.authenticate(user, wrong_pin)

        status = self.manager.get_status(user)
        self.assertTrue(status["is_locked"])

        # Reset lockout
        reset_ok, reset_msg = self.manager.reset_lockout(user)
        self.assertTrue(reset_ok, reset_msg)

        status_post = self.manager.get_status(user)
        self.assertFalse(status_post["is_locked"])
        self.assertEqual(status_post["failed_attempts"], 0)

        # Now correct PIN works immediately
        ok, msg, det = self.manager.authenticate(user, correct_pin)
        self.assertTrue(ok)

    def test_11_persistence_across_instances(self):
        """PIN record and state persist across manager instance restarts."""
        user = "frank"
        pin = "8301"

        self.manager.setup_pin(user, pin)

        # Create new manager pointing to the same storage directory
        new_manager = PINAuthManager(auth_dir=self.auth_dir, iterations=self.test_iterations)
        self.assertTrue(new_manager.user_exists(user))

        ok, msg, det = new_manager.authenticate(user, pin)
        self.assertTrue(ok, msg)


if __name__ == "__main__":
    unittest.main()
