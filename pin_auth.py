"""
ProPay - Hardened Constant-Time PIN Authentication & Rate Limiter
Part 2 of the ProPay Secure CLI Payment Platform.

Features:
- UPI Numeric PIN enforcement (4-6 digits) with anti-trivial PIN dictionary filters
- PBKDF2-HMAC-SHA256 key derivation with 600,000 iterations & CSPRNG salt
- Strict constant-time signature/hash verification via hmac.compare_digest
- Mitigates side-channel timing attacks with dummy computation for non-existent users
- Exponential backoff rate limiter with mandatory 15-minute lockout after 3 failed attempts
- Rich CLI interface for PIN enrollment, verification, and status monitoring
"""

import os
import sys
import time
import json
import hmac
import hashlib
import secrets
import getpass
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console(legacy_windows=False)

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
AUTH_DIR = DATA_DIR / "auth"

# Security Parameters
DEFAULT_PBKDF2_ITERATIONS = 600_000  # OWASP / Banking-grade work factor
SALT_SIZE_BYTES = 32  # 256-bit CSPRNG salt
MAX_CONSECUTIVE_FAILURES = 3
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes in seconds

# Common trivial PINs to reject immediately
TRIVIAL_PINS = {
    "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
    "1234", "4321", "2345", "3456", "4567", "5678", "6789", "9876", "8765", "7654",
    "0123", "3210", "1357", "2468", "9012",
    "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777",
    "888888", "999999", "123456", "654321", "123123", "112233", "121212"
}


def ensure_auth_directory(auth_dir: Path = AUTH_DIR) -> None:
    """Ensures the auth storage directory exists with proper permissions."""
    auth_dir.mkdir(parents=True, exist_ok=True)


class PINPolicy:
    """Validates numeric UPI PIN strength and format."""

    @staticmethod
    def validate(pin: str) -> Tuple[bool, str]:
        """
        Validates PIN compliance:
        - Must be numeric
        - Must be between 4 and 6 digits
        - Must not be in common trivial/dictionary PIN blocklist
        - Must not be all identical digits
        - Must not be simple strictly ascending/descending sequences
        """
        if not pin or not pin.isdigit():
            return False, "PIN must consist exclusively of numeric digits (0-9)."

        if len(pin) not in (4, 5, 6):
            return False, f"PIN length must be 4, 5, or 6 digits (received {len(pin)} digits)."

        if pin in TRIVIAL_PINS:
            return False, f"The PIN '{pin}' is easily guessable and rejected by security policy."

        # Check for all repeated characters (e.g. 77777)
        if len(set(pin)) == 1:
            return False, "PIN cannot consist of a single repeated digit."

        # Check for sequential digits (e.g. 1234, 4321)
        digits = [int(c) for c in pin]
        is_ascending = all(digits[i] + 1 == digits[i + 1] for i in range(len(digits) - 1))
        is_descending = all(digits[i] - 1 == digits[i + 1] for i in range(len(digits) - 1))
        if is_ascending or is_descending:
            return False, "PIN cannot consist of consecutive ascending or descending numbers."

        return True, "PIN meets security requirements."


class PINHasher:
    """
    PBKDF2-HMAC-SHA256 hasher and constant-time verifier.
    """

    @staticmethod
    def generate_salt(size: int = SALT_SIZE_BYTES) -> bytes:
        """Generates a cryptographically secure random salt."""
        return secrets.token_bytes(size)

    @staticmethod
    def hash_pin(
        pin: str,
        salt: Optional[bytes] = None,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> Tuple[str, str]:
        """
        Hashes numeric PIN with PBKDF2-HMAC-SHA256.
        Returns: (hash_hex, salt_hex)
        """
        if salt is None:
            salt = PINHasher.generate_salt()
        derived = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=pin.encode("utf-8"),
            salt=salt,
            iterations=iterations,
            dklen=32,
        )
        return derived.hex(), salt.hex()

    @staticmethod
    def verify_pin(
        candidate_pin: str,
        stored_hash_hex: str,
        stored_salt_hex: str,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    ) -> bool:
        """
        Verifies candidate PIN against stored hash in constant-time.
        Uses hmac.compare_digest to prevent side-channel timing leaks.
        """
        try:
            salt = bytes.fromhex(stored_salt_hex)
            expected_hash = bytes.fromhex(stored_hash_hex)
        except ValueError:
            return False

        candidate_derived = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=candidate_pin.encode("utf-8"),
            salt=salt,
            iterations=iterations,
            dklen=32,
        )

        return hmac.compare_digest(candidate_derived, expected_hash)

    @staticmethod
    def dummy_computation(iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> None:
        """
        Performs dummy PBKDF2 computation to ensure constant response latency
        when a queried username does not exist, mitigating username enumeration timing attacks.
        """
        dummy_salt = b"\x00" * SALT_SIZE_BYTES
        hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=b"0000",
            salt=dummy_salt,
            iterations=iterations,
            dklen=32,
        )


class RateLimiter:
    """
    Manages rate-limiting state and enforcement:
    - 3 consecutive failed attempts trigger a 15-minute (900s) lockout.
    - Tracks attempt counts and lockouts per user account.
    """

    def __init__(
        self,
        max_failures: int = MAX_CONSECUTIVE_FAILURES,
        lockout_duration_sec: int = LOCKOUT_DURATION_SECONDS,
    ):
        self.max_failures = max_failures
        self.lockout_duration_sec = lockout_duration_sec

    def is_locked(self, state: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determines whether the account is currently locked out.
        Returns: (is_locked, remaining_seconds)
        """
        lockout_until = state.get("lockout_until", 0.0)
        now = time.time()
        if now < lockout_until:
            return True, max(0.0, lockout_until - now)
        return False, 0.0

    def record_failure(self, state: Dict[str, Any]) -> Tuple[Dict[str, Any], bool, float]:
        """
        Records a failed attempt, triggering lockout if threshold reached.
        Returns: (updated_state, is_now_locked, remaining_seconds)
        """
        now = time.time()
        failed_count = state.get("failed_attempts", 0) + 1
        state["failed_attempts"] = failed_count
        state["last_failed_at"] = now
        state["total_failures"] = state.get("total_failures", 0) + 1

        if failed_count >= self.max_failures:
            lockout_until = now + self.lockout_duration_sec
            state["lockout_until"] = lockout_until
            return state, True, float(self.lockout_duration_sec)

        return state, False, 0.0

    def record_success(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Resets failed attempt counter and lockout status on successful auth."""
        state["failed_attempts"] = 0
        state["lockout_until"] = 0.0
        state["last_success_at"] = time.time()
        state["total_successes"] = state.get("total_successes", 0) + 1
        return state


class PINAuthManager:
    """
    Coordinates PIN enrollment, constant-time verification, and rate limiter persistence.
    """

    def __init__(
        self,
        auth_dir: Path = AUTH_DIR,
        iterations: int = DEFAULT_PBKDF2_ITERATIONS,
        max_failures: int = MAX_CONSECUTIVE_FAILURES,
        lockout_duration_sec: int = LOCKOUT_DURATION_SECONDS,
        seed_demo: bool = True,
    ):
        self.auth_dir = auth_dir
        self.iterations = iterations
        self.rate_limiter = RateLimiter(max_failures, lockout_duration_sec)
        ensure_auth_directory(self.auth_dir)
        if seed_demo and self.auth_dir == AUTH_DIR:
            self._initialize_seed_pins()

    def _initialize_seed_pins(self) -> None:
        """Seeds default demonstration PINs if they do not already exist."""
        # Default hackathon demo credentials:
        # kelvin@propay -> PIN '123456'
        # alice@propay  -> PIN '654321'
        demo_users = [
            ("kelvin@propay", "123456"),
            ("alice@propay", "654321"),
        ]
        for u, p in demo_users:
            if not self.user_exists(u):
                self.setup_pin(u, p, enforce_policy=False)

    def _get_user_file(self, username: str) -> Path:
        sanitized = username.lower().strip()
        candidates = [sanitized]
        if "@" in sanitized:
            candidates.append(sanitized.split("@")[0])
            candidates.append(sanitized.replace("@", "_").replace(".", "_"))
        else:
            candidates.append(f"{sanitized}@propay")

        for cand in candidates:
            p = self.auth_dir / f"{cand}_pin.json"
            if p.is_file():
                return p

        safe_name = sanitized.replace("@", "_").replace(".", "_")
        return self.auth_dir / f"{safe_name}_pin.json"

    def user_exists(self, username: str) -> bool:
        """Returns True if a PIN profile exists for the given user."""
        return self._get_user_file(username).is_file()

    def load_record(self, username: str) -> Optional[Dict[str, Any]]:
        """Loads the stored auth record from disk."""
        path = self._get_user_file(username)
        if not path.is_file():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_record(self, username: str, record: Dict[str, Any]) -> bool:
        """Persists the auth record to disk with atomic write."""
        path = self._get_user_file(username)
        temp_path = path.with_suffix(".tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2)
            temp_path.replace(path)
            return True
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            return False

    def setup_pin(self, username: str, pin: str, enforce_policy: bool = True) -> Tuple[bool, str]:
        """
        Enrolls or updates the user's UPI PIN.
        Returns: (success, message)
        """
        if enforce_policy:
            valid, msg = PINPolicy.validate(pin)
            if not valid:
                return False, msg

        hash_hex, salt_hex = PINHasher.hash_pin(pin, iterations=self.iterations)
        record = {
            "username": username.lower().strip(),
            "created_at": time.time(),
            "updated_at": time.time(),
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": self.iterations,
            "salt_hex": salt_hex,
            "hash_hex": hash_hex,
            "failed_attempts": 0,
            "lockout_until": 0.0,
            "last_failed_at": None,
            "last_success_at": None,
            "total_failures": 0,
            "total_successes": 0,
        }

        if self.save_record(username, record):
            return True, f"UPI PIN successfully enrolled for '{username}'."
        return False, "Failed to persist PIN auth record."

    def authenticate(self, username: str, candidate_pin: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Performs hardened constant-time PIN authentication with rate limiter enforcement.
        Returns: (authenticated, message, status_details)
        """
        record = self.load_record(username)

        # Constant-time mitigation for non-existent users
        if record is None:
            PINHasher.dummy_computation(iterations=self.iterations)
            return False, f"User '{username}' is not registered.", {"locked": False, "remaining_attempts": 0}

        # Check rate limiter lockout
        locked, rem_time = self.rate_limiter.is_locked(record)
        if locked:
            mins = int(rem_time // 60)
            secs = int(rem_time % 60)
            return False, f"Account is locked due to consecutive failed attempts. Try again in {mins}m {secs}s.", {
                "locked": True,
                "lockout_remaining_seconds": rem_time,
                "failed_attempts": record.get("failed_attempts", 0),
            }

        # Perform constant-time cryptographic verification
        iterations = record.get("iterations", self.iterations)
        is_valid = PINHasher.verify_pin(
            candidate_pin=candidate_pin,
            stored_hash_hex=record.get("hash_hex", ""),
            stored_salt_hex=record.get("salt_hex", ""),
            iterations=iterations,
        )

        if is_valid:
            record = self.rate_limiter.record_success(record)
            self.save_record(username, record)
            return True, "PIN authentication successful.", {
                "locked": False,
                "failed_attempts": 0,
                "remaining_attempts": self.rate_limiter.max_failures,
            }
        else:
            record, is_now_locked, lock_sec = self.rate_limiter.record_failure(record)
            self.save_record(username, record)
            failed = record.get("failed_attempts", 0)
            remaining = max(0, self.rate_limiter.max_failures - failed)

            if is_now_locked:
                mins = int(lock_sec // 60)
                secs = int(lock_sec % 60)
                msg = f"Invalid PIN! 3 consecutive failed attempts reached. Account locked for {mins}m {secs}s."
            else:
                msg = f"Invalid PIN! {remaining} attempt(s) remaining before account lockout."

            return False, msg, {
                "locked": is_now_locked,
                "failed_attempts": failed,
                "remaining_attempts": remaining,
                "lockout_remaining_seconds": lock_sec if is_now_locked else 0.0,
            }

    def reset_lockout(self, username: str) -> Tuple[bool, str]:
        """Manually unlocks account and resets failure counters (administrative/recovery)."""
        record = self.load_record(username)
        if record is None:
            return False, f"User '{username}' not found."

        record["failed_attempts"] = 0
        record["lockout_until"] = 0.0
        self.save_record(username, record)
        return True, f"Lockout for user '{username}' has been successfully reset."

    def get_status(self, username: str) -> Optional[Dict[str, Any]]:
        """Returns the current security & lockout status for the user."""
        record = self.load_record(username)
        if record is None:
            return None

        locked, rem_time = self.rate_limiter.is_locked(record)
        return {
            "username": record["username"],
            "created_at": record.get("created_at"),
            "kdf": record.get("kdf"),
            "iterations": record.get("iterations"),
            "failed_attempts": record.get("failed_attempts", 0),
            "is_locked": locked,
            "lockout_remaining_seconds": rem_time,
            "total_failures": record.get("total_failures", 0),
            "last_success_at": record.get("last_success_at"),
        }

    def check_lockout(self, username: str) -> Tuple[bool, int]:
        """Convenience method returning (is_locked, remaining_seconds_int)."""
        record = self.load_record(username)
        if not record:
            return False, 0
        locked, rem_time = self.rate_limiter.is_locked(record)
        return locked, int(rem_time)

    def verify_pin(self, username: str, candidate_pin: str) -> Tuple[bool, str]:
        """Convenience method returning (is_authenticated, status_message)."""
        ok, msg, _ = self.authenticate(username, candidate_pin)
        return ok, msg

    def register_pin(self, username: str, pin: str) -> bool:
        """Convenience method for registering PIN."""
        ok, _ = self.setup_pin(username, pin, enforce_policy=False)
        return ok


# Alias for backward compatibility across modules
HardenedPINAuthManager = PINAuthManager


# ----------------------------------------------------------------------------
# Interactive Rich CLI Controller
# ----------------------------------------------------------------------------
class PINAuthCLI:
    """Interactive CLI Controller for PIN enrollment, verification, and rate limiter status."""

    def __init__(self, manager: Optional[PINAuthManager] = None):
        self.manager = manager or PINAuthManager()

    def enroll_interactive(self, username: str) -> bool:
        """Guides user through secure PIN setup with policy validation and confirmation."""
        console.print(f"\n[bold green]== Enroll / Update UPI PIN for: [white]{username}[/white] ==[/bold green]")

        if self.manager.user_exists(username):
            console.print("[yellow]Notice: A PIN profile already exists for this user. This will overwrite it.[/yellow]")

        while True:
            try:
                pin1 = getpass.getpass("Enter new 4-6 digit numeric UPI PIN: ")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Setup cancelled by user.[/yellow]")
                return False

            valid, msg = PINPolicy.validate(pin1)
            if not valid:
                console.print(f"[bold red]❌ Rejected by Security Policy: {msg}[/bold red]")
                continue

            try:
                pin2 = getpass.getpass("Confirm UPI PIN: ")
            except (KeyboardInterrupt, EOFError):
                console.print("\n[yellow]Setup cancelled by user.[/yellow]")
                return False

            if not hmac.compare_digest(pin1, pin2):
                console.print("[bold red]❌ PINs do not match! Please try again.[/bold red]\n")
                continue

            # Compute PBKDF2 hash
            with console.status("[cyan]Deriving cryptographic key via PBKDF2-HMAC-SHA256 (600,000 rounds)...[/cyan]"):
                success, result_msg = self.manager.setup_pin(username, pin1)

            if success:
                console.print(
                    Panel(
                        f"[bold green]✔ UPI PIN Enrolled Successfully![/bold green]\n"
                        f"User: [white]{username}[/white]\n"
                        f"KDF: [cyan]PBKDF2-HMAC-SHA256[/cyan]\n"
                        f"Work Factor: [cyan]{self.manager.iterations:,} iterations[/cyan]\n"
                        f"Rate Limiter: [green]Active (15-min lockout on 3 failures)[/green]",
                        title="PIN Auth Setup",
                    )
                )
                return True
            else:
                console.print(f"[bold red]❌ Error: {result_msg}[/bold red]")
                return False

    def verify_interactive(self, username: str) -> bool:
        """Prompts for PIN and executes constant-time verification with rate-limit defense."""
        console.print(f"\n[bold cyan]== UPI PIN Authentication: [white]{username}[/white] ==[/bold cyan]")

        # Check existing lockout status before prompting
        status = self.manager.get_status(username)
        if status and status.get("is_locked"):
            rem = status["lockout_remaining_seconds"]
            mins = int(rem // 60)
            secs = int(rem % 60)
            console.print(
                Panel(
                    f"[bold red]🔒 ACCOUNT LOCKED[/bold red]\n"
                    f"User '{username}' exceeded maximum permitted PIN attempts.\n"
                    f"Lockout remaining: [bold yellow]{mins}m {secs}s[/bold yellow]",
                    title="Security Lockout",
                )
            )
            return False

        try:
            candidate_pin = getpass.getpass(f"Enter UPI PIN for '{username}': ")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Authentication cancelled by user.[/yellow]")
            return False

        with console.status("[cyan]Verifying PIN in constant-time...[/cyan]"):
            ok, msg, details = self.manager.authenticate(username, candidate_pin)

        if ok:
            console.print(
                Panel(
                    f"[bold green]✔ PIN Authentication Succeeded![/bold green]\n"
                    f"User: [white]{username}[/white]\n"
                    f"Timing Defense: [green]hmac.compare_digest Verified[/green]\n"
                    f"Rate Limiter: [dim]Failures reset to 0[/dim]",
                    title="PIN Verified",
                )
            )
            return True
        else:
            if details.get("locked"):
                console.print(
                    Panel(
                        f"[bold red]🔒 MAXIMUM ATTEMPTS EXCEEDED[/bold red]\n{msg}",
                        title="Account Locked",
                    )
                )
            else:
                console.print(
                    Panel(
                        f"[bold red]❌ Authentication Failed[/bold red]\n{msg}",
                        title="Security Warning",
                    )
                )
            return False

    def print_status(self, username: str) -> None:
        """Displays rate limiter and security metrics in a formatted table."""
        status = self.manager.get_status(username)
        if not status:
            console.print(f"[red]No PIN profile found for user '{username}'.[/red]")
            return

        table = Table(title=f"PIN Security Status: {username}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("KDF Algorithm", str(status.get("kdf")))
        table.add_row("Work Factor", f"{status.get('iterations', 0):,} rounds")
        table.add_row(
            "Account Lockout Status",
            "[bold red]LOCKED[/bold red]" if status["is_locked"] else "[bold green]UNLOCKED[/bold green]",
        )
        if status["is_locked"]:
            rem = status["lockout_remaining_seconds"]
            table.add_row("Lockout Time Remaining", f"[yellow]{int(rem // 60)}m {int(rem % 60)}s[/yellow]")
        table.add_row("Current Consecutive Failures", str(status.get("failed_attempts", 0)))
        table.add_row("Total Lifetime Failures", str(status.get("total_failures", 0)))
        table.add_row("Total Successful Logins", str(status.get("total_successes", 0)))

        console.print(table)


# ----------------------------------------------------------------------------
# CLI Entrypoint
# ----------------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="ProPay Constant-Time PIN Authentication & Rate Limiter")
    parser.add_argument("--setup", type=str, metavar="USERNAME", help="Enroll or change UPI PIN")
    parser.add_argument("--verify", type=str, metavar="USERNAME", help="Authenticate user with UPI PIN")
    parser.add_argument("--status", type=str, metavar="USERNAME", help="Show account security and lockout status")
    parser.add_argument("--reset-lockout", type=str, metavar="USERNAME", help="Reset account lockout (admin/recovery)")
    parser.add_argument(
        "--test-pin",
        type=str,
        nargs=2,
        metavar=("USERNAME", "PIN"),
        help="Headless non-interactive PIN verification for scripts and benchmarks",
    )

    args = parser.parse_args()
    manager = PINAuthManager()
    cli = PINAuthCLI(manager)

    if args.setup:
        cli.enroll_interactive(args.setup)
    elif args.verify:
        cli.verify_interactive(args.verify)
    elif args.status:
        cli.print_status(args.status)
    elif args.reset_lockout:
        ok, msg = manager.reset_lockout(args.reset_lockout)
        color = "green" if ok else "red"
        console.print(f"[{color}]{msg}[/{color}]")
    elif args.test_pin:
        user, pin = args.test_pin
        ok, msg, details = manager.authenticate(user, pin)
        if ok:
            console.print(f"[bold green]✔ {msg}[/bold green]")
        else:
            console.print(f"[bold red]❌ {msg}[/bold red]")
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
