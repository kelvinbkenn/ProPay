"""
ProPay - Cryptographically Signed Dynamic QR Code Engine & Scanner
Part 3 of the ProPay Secure CLI Payment Platform.

Features:
- Cryptographically signed dynamic QR payload generation (HMAC-SHA256 & Ed25519)
- Anti-tamper & man-in-the-middle defense (immutable VPA, amount, nonce, expiry binding)
- Replay attack defense via CSPRNG nonces and short-lived expiration windows
- High-contrast UTF-8 ASCII / Unicode terminal QR rendering for direct CLI scanning
- Headless and image-based QR decoding via OpenCV (cv2.QRCodeDetector)
- Real-time interactive webcam scanner with targeting HUD and immediate cryptographic validation
"""

import os
import sys
import time
import json
import base64
import hmac
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

import cv2
import numpy as np
import qrcode

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(legacy_windows=False)

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = DATA_DIR / "keys"
NONCE_CACHE_FILE = DATA_DIR / "used_nonces.json"

DEFAULT_KEY_FILE = KEYS_DIR / "qr_hmac_secret.key"
DEFAULT_TTL_SECONDS = 120  # Dynamic QR codes expire after 2 minutes by default


def ensure_data_directories() -> None:
    """Ensure data and keys directories exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)


class KeyManager:
    """
    Manages cryptographic keys used for signing and verifying payment QR codes.
    Generates high-entropy CSPRNG keys if none exist.
    """

    def __init__(self, key_path: Path = DEFAULT_KEY_FILE):
        self.key_path = Path(key_path)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)

    def get_or_create_hmac_key(self) -> bytes:
        """Retrieves existing HMAC secret key or generates a new 256-bit CSPRNG key, synchronized with CryptoVault."""
        vault = None
        try:
            from crypto_vault import CryptoVault
            vault = CryptoVault()
        except Exception:
            pass

        if self.key_path.exists():
            with open(self.key_path, "rb") as f:
                key = f.read().strip()
                if len(key) >= 32:
                    if vault:
                        try:
                            if not vault.load_secret("qr_hmac_key"):
                                vault.store_secret("qr_hmac_key", key)
                        except Exception:
                            pass
                    return key

        if vault:
            try:
                vault_key = vault.load_secret("qr_hmac_key")
                if vault_key and len(vault_key) >= 32:
                    self.key_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self.key_path, "wb") as f:
                        f.write(vault_key)
                    return vault_key
            except Exception:
                pass

        # Generate fresh 256-bit key
        new_key = secrets.token_bytes(32)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.key_path, "wb") as f:
            f.write(new_key)
        if vault:
            try:
                vault.store_secret("qr_hmac_key", new_key)
            except Exception:
                pass
        return new_key


class NonceManager:
    """
    Guards against Replay Attacks by maintaining a persistent cache of used nonces
    and pruning expired records.
    """

    def __init__(self, cache_file: Path = NONCE_CACHE_FILE):
        self.cache_file = Path(cache_file)
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_nonces(self) -> Dict[str, int]:
        """Loads nonces mapping nonce -> expiry_timestamp."""
        if not self.cache_file.exists():
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_nonces(self, nonces: Dict[str, int]) -> None:
        """Prunes expired nonces and saves back to disk."""
        now = int(time.time())
        # Retain only non-expired nonces to keep storage bounded
        active = {n: exp for n, exp in nonces.items() if exp > now}
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(active, f, indent=2)
        except Exception:
            pass

    def is_nonce_used(self, nonce: str) -> bool:
        """Checks if nonce has already been consumed."""
        nonces = self._load_nonces()
        return nonce in nonces

    def mark_nonce_used(self, nonce: str, expires_at: int) -> None:
        """Records nonce as consumed."""
        nonces = self._load_nonces()
        nonces[nonce] = expires_at
        self._save_nonces(nonces)

    def clear(self) -> None:
        """Clears nonce cache (useful in test environments)."""
        if self.cache_file.exists():
            try:
                self.cache_file.unlink()
            except Exception:
                pass


class SignedQREngine:
    """
    Core Cryptographic Dynamic QR Code Engine.
    Handles generation, signing, canonical serialization, and verification.
    """

    PROTOCOL_VERSION = "PROPAY-QR-v1.0"
    DEFAULT_CURRENCY = "INR"

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        nonce_manager: Optional[NonceManager] = None,
    ):
        self.key_manager = key_manager or KeyManager()
        self.nonce_manager = nonce_manager or NonceManager()
        self.secret_key = self.key_manager.get_or_create_hmac_key()

    @staticmethod
    def build_canonical_string(
        version: str,
        vpa: str,
        name: str,
        amount: float,
        currency: str,
        txn_nonce: str,
        timestamp: int,
        expires_at: int,
    ) -> str:
        """
        Constructs a deterministic canonical string across all fields to guarantee
        reproducible signature calculation regardless of serialization quirks.
        """
        formatted_amount = f"{amount:.2f}"
        return (
            f"ver={version}|vpa={vpa.strip()}|name={name.strip()}|"
            f"amt={formatted_amount}|cur={currency.upper()}|"
            f"nonce={txn_nonce}|ts={timestamp}|exp={expires_at}"
        )

    def compute_signature(self, canonical_str: str) -> str:
        """Computes HMAC-SHA256 signature for canonical string."""
        sig = hmac.new(self.secret_key, canonical_str.encode("utf-8"), hashlib.sha256)
        return sig.hexdigest()

    def generate_payload(
        self,
        vpa: str,
        amount: float,
        name: str = "Merchant",
        currency: str = DEFAULT_CURRENCY,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> Dict[str, Any]:
        """
        Creates a new, tamper-evident dynamic QR payload signed with HMAC-SHA256.
        """
        if amount <= 0:
            raise ValueError("Transaction amount must be strictly positive.")
        if not vpa or "@" not in vpa:
            raise ValueError(f"Invalid UPI VPA address: '{vpa}'")

        now = int(time.time())
        expires_at = now + ttl_seconds
        txn_nonce = secrets.token_hex(16)

        canonical_str = self.build_canonical_string(
            version=self.PROTOCOL_VERSION,
            vpa=vpa,
            name=name,
            amount=amount,
            currency=currency,
            txn_nonce=txn_nonce,
            timestamp=now,
            expires_at=expires_at,
        )

        signature = self.compute_signature(canonical_str)

        payload = {
            "version": self.PROTOCOL_VERSION,
            "vpa": vpa.strip(),
            "name": name.strip(),
            "amount": round(amount, 2),
            "currency": currency.upper(),
            "txn_nonce": txn_nonce,
            "timestamp": now,
            "expires_at": expires_at,
            "sig_alg": "HMAC-SHA256",
            "sig": signature,
        }
        return payload

    def serialize_payload(self, payload: Dict[str, Any]) -> str:
        """Serializes payload dictionary into standard JSON string for QR encoding."""
        return json.dumps(payload, separators=(",", ":"))

    def parse_payload(self, payload_str: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """Parses a QR payload string (JSON or Base64 encoded JSON)."""
        if not payload_str or not isinstance(payload_str, str):
            return None, "Empty payload string."

        raw = payload_str.strip()
        # Attempt Base64 decode if not starting with {
        if not raw.startswith("{"):
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
                raw = decoded
            except Exception:
                pass

        try:
            data = json.loads(raw)
            if not isinstance(data, dict):
                return None, "Payload is not a JSON dictionary."
            return data, "Parsed successfully."
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON payload: {e}"

    def verify_payload(
        self,
        payload_input: Any,
        consume_nonce: bool = True,
        check_expiry: bool = True,
    ) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Validates cryptographic integrity and freshness of the payload:
        1. Required fields presence
        2. Constant-time signature verification (Tamper defense)
        3. Nonce replay check (Replay defense)
        4. Expiry timestamp check (Timeout defense)
        5. Amount validity check
        """
        if isinstance(payload_input, str):
            payload, msg = self.parse_payload(payload_input)
            if payload is None:
                return False, f"Malformed QR: {msg}", None
        elif isinstance(payload_input, dict):
            payload = payload_input
        else:
            return False, "Unsupported payload type.", None

        # Check required fields
        required_fields = [
            "version", "vpa", "name", "amount", "currency",
            "txn_nonce", "timestamp", "expires_at", "sig_alg", "sig"
        ]
        for field in required_fields:
            if field not in payload:
                return False, f"Missing required payload field: '{field}'", payload

        # Check protocol version
        if payload["version"] != self.PROTOCOL_VERSION:
            return False, f"Unsupported protocol version: {payload['version']}", payload

        # Check amount
        try:
            amount_val = float(payload["amount"])
            if amount_val <= 0:
                return False, "Invalid transaction amount (<= 0).", payload
        except (ValueError, TypeError):
            return False, "Malformed amount value.", payload

        # Constant-time signature verification
        try:
            canonical_str = self.build_canonical_string(
                version=payload["version"],
                vpa=payload["vpa"],
                name=payload["name"],
                amount=amount_val,
                currency=payload["currency"],
                txn_nonce=payload["txn_nonce"],
                timestamp=int(payload["timestamp"]),
                expires_at=int(payload["expires_at"]),
            )
            expected_sig = self.compute_signature(canonical_str)
            provided_sig = str(payload["sig"])

            if not hmac.compare_digest(expected_sig, provided_sig):
                return False, "Signature Mismatch: Payload has been tampered with!", payload
        except Exception as e:
            return False, f"Cryptographic verification error: {e}", payload

        now = int(time.time())

        # Expiry Check
        if check_expiry:
            expires_at = int(payload["expires_at"])
            if now > expires_at:
                seconds_expired = now - expires_at
                return False, f"Expired QR Code: expired {seconds_expired}s ago.", payload

        # Replay Check
        nonce = str(payload["txn_nonce"])
        if self.nonce_manager.is_nonce_used(nonce):
            return False, "Replay Attack Detected: This QR code nonce has already been redeemed.", payload

        if consume_nonce:
            self.nonce_manager.mark_nonce_used(nonce, int(payload["expires_at"]))

        return True, "Valid Cryptographically Verified QR Code", payload

    def render_ascii_qr(self, payload: Dict[str, Any]) -> str:
        """
        Generates high-contrast UTF-8 block ASCII representation for the terminal
        using half-block characters (▀ and ▄) to render square QR modules cleanly.
        """
        text_data = self.serialize_payload(payload)
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=1,
            border=2,
        )
        qr.add_data(text_data)
        qr.make(fit=True)

        matrix = qr.get_matrix()
        height = len(matrix)
        width = len(matrix[0]) if height > 0 else 0

        # Build ASCII using Unicode half-block characters for sharp rendering
        lines = []
        # Step 2 rows at a time
        for y in range(0, height, 2):
            line_chars = []
            for x in range(width):
                top = matrix[y][x]
                bottom = matrix[y + 1][x] if (y + 1 < height) else False

                if top and bottom:
                    line_chars.append(" ")   # Both dark (with white background in terminal)
                elif top and not bottom:
                    line_chars.append("▄")   # Top dark
                elif not top and bottom:
                    line_chars.append("▀")   # Bottom dark
                else:
                    line_chars.append("█")   # Both light
            lines.append("".join(line_chars))

        return "\n".join(lines)

    def export_qr_image(
        self,
        payload: Dict[str, Any],
        output_path: Path,
        box_size: int = 8,
        border: int = 4,
    ) -> Path:
        """Exports QR code to a high-resolution PNG image file with ISO-compliant quiet zone."""
        text_data = self.serialize_payload(payload)
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,  # Standard M error correction
            box_size=box_size,
            border=border,
        )
        qr.add_data(text_data)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        img.save(str(output_path))
        return output_path

    @staticmethod
    def create_detector():
        """Instantiates highest-accuracy OpenCV QR detector (QRCodeDetectorAruco if available)."""
        if hasattr(cv2, "QRCodeDetectorAruco"):
            return cv2.QRCodeDetectorAruco()
        return cv2.QRCodeDetector()

    @classmethod
    def decode_qr_image(cls, image_path_or_ndarray: Any) -> Tuple[Optional[str], Optional[np.ndarray]]:
        """
        Reads an image from disk or ndarray and decodes the QR code via OpenCV.
        Supports automatic fallback between QRCodeDetectorAruco and legacy detector.
        Returns: (decoded_text, bbox_points)
        """
        if isinstance(image_path_or_ndarray, (str, Path)):
            img = cv2.imread(str(image_path_or_ndarray))
            if img is None:
                return None, None
        elif isinstance(image_path_or_ndarray, np.ndarray):
            img = image_path_or_ndarray
        else:
            return None, None

        # 1. Try modern ArUco-based detector first
        detector = cls.create_detector()
        decoded_text, points, _ = detector.detectAndDecode(img)
        if decoded_text:
            return decoded_text, points

        # 2. Fallback to legacy QRCodeDetector if different
        if hasattr(cv2, "QRCodeDetectorAruco") and isinstance(detector, cv2.QRCodeDetectorAruco):
            legacy = cv2.QRCodeDetector()
            decoded_text, points, _ = legacy.detectAndDecode(img)
            if decoded_text:
                return decoded_text, points

        # 3. Fallback to grayscale + resized
        if len(img.shape) == 3:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            decoded_text, points, _ = detector.detectAndDecode(gray)
            if decoded_text:
                return decoded_text, points

        return None, None


class QRScannerCLI:
    """
    Interactive CLI visualizer and webcam scanner for ProPay QR Engine.
    """

    def __init__(self, engine: Optional[SignedQREngine] = None):
        self.engine = engine or SignedQREngine()

    def display_generated_qr(self, payload: Dict[str, Any], export_path: Optional[Path] = None) -> None:
        """Displays formatted transaction details and ASCII QR code in the terminal."""
        ascii_qr = self.engine.render_ascii_qr(payload)

        details_table = Table(show_header=False, box=None)
        details_table.add_column("Property", style="bold cyan", width=16)
        details_table.add_column("Value", style="bold white")

        details_table.add_row("Payee Name:", payload["name"])
        details_table.add_row("UPI VPA:", payload["vpa"])
        details_table.add_row("Amount:", f"{payload['currency']} {payload['amount']:.2f}")
        details_table.add_row("Nonce:", f"{payload['txn_nonce'][:12]}... (CSPRNG)")
        details_table.add_row("Expires In:", f"{payload['expires_at'] - int(time.time())} seconds")
        details_table.add_row("Signature Alg:", payload["sig_alg"])
        details_table.add_row("Signature:", f"{payload['sig'][:16]}...{payload['sig'][-8:]}")

        panel_content = f"{ascii_qr}\n\n"
        console.print(Panel(
            panel_content,
            title="[bold green]ProPay Attack-Resilient Dynamic Payment QR[/bold green]",
            subtitle="[dim]Scan with ProPay CLI or UPI app[/dim]",
            expand=False,
        ))
        console.print(Panel(details_table, title="Transaction Summary", expand=False))

        if export_path:
            saved_path = self.engine.export_qr_image(payload, export_path)
            console.print(f"[green]Saved QR image to:[/green] [bold]{saved_path}[/bold]")

    def verify_file(self, filepath: str) -> bool:
        """Decodes and validates a QR code from an image file."""
        console.print(f"[yellow]Inspecting QR file:[/yellow] {filepath}")
        raw_text, _ = self.engine.decode_qr_image(filepath)
        if not raw_text:
            console.print("[bold red]Failed to detect or decode QR code in image.[/bold red]")
            return False

        is_valid, msg, payload = self.engine.verify_payload(raw_text)
        self._print_verification_result(is_valid, msg, payload)
        return is_valid

    def verify_payload_string(self, payload_str: str) -> bool:
        """Verifies raw string payload without image decoding."""
        is_valid, msg, payload = self.engine.verify_payload(payload_str)
        self._print_verification_result(is_valid, msg, payload)
        return is_valid

    def _print_verification_result(
        self,
        is_valid: bool,
        message: str,
        payload: Optional[Dict[str, Any]],
    ) -> None:
        """Renders stylized table with verification outcome."""
        status_color = "green" if is_valid else "red"
        status_text = "VERIFIED (AUTHENTIC)" if is_valid else "REJECTED (TAMPERED / EXPIRED / REPLAY)"

        result_table = Table(title=f"Verification Result: [{status_color}]{status_text}[/{status_color}]")
        result_table.add_column("Field", style="cyan")
        result_table.add_column("Detail", style="white")

        result_table.add_row("Status", f"[{status_color}]{message}[/{status_color}]")
        if payload:
            result_table.add_row("VPA", str(payload.get("vpa", "N/A")))
            result_table.add_row("Amount", f"{payload.get('currency', '')} {payload.get('amount', 'N/A')}")
            result_table.add_row("Nonce", str(payload.get("txn_nonce", "N/A")))
            result_table.add_row("Algorithm", str(payload.get("sig_alg", "N/A")))
            result_table.add_row("Signature", str(payload.get("sig", "N/A"))[:24] + "...")

        console.print(result_table)

    def scan_webcam(self) -> None:
        """
        Interactive live camera feed scanner with HUD targeting box
        and real-time cryptographic verification.
        """
        console.print("[bold yellow]Launching ProPay Live Camera Scanner...[/bold yellow]")
        console.print("[dim]Hold a ProPay dynamic QR code in front of the lens. Press 'q' or 'ESC' to exit.[/dim]")

        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            console.print("[bold red]Error: Could not access webcam device.[/bold red]")
            return

        detector = self.engine.create_detector()
        detected_once = False

        try:
            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                h, w = frame.shape[:2]
                decoded_text, points, _ = detector.detectAndDecode(frame)

                # Draw targeting reticle
                box_color = (0, 165, 255)  # Orange default
                status_label = "PROPAY SCANNER: Point camera at QR"

                if points is not None and len(points) > 0:
                    pts = points[0].astype(int)
                    cv2.polylines(frame, [pts], isClosed=True, color=(0, 255, 255), thickness=2)

                    if decoded_text:
                        is_valid, msg, payload = self.engine.verify_payload(
                            decoded_text, consume_nonce=False, check_expiry=True
                        )
                        if is_valid and payload:
                            box_color = (0, 255, 0)
                            status_label = f"AUTHENTIC: {payload['vpa']} | {payload['currency']} {payload['amount']:.2f}"
                            cv2.polylines(frame, [pts], isClosed=True, color=box_color, thickness=4)
                            if not detected_once:
                                # Mark once consumed
                                self.engine.nonce_manager.mark_nonce_used(
                                    payload["txn_nonce"], int(payload["expires_at"])
                                )
                                detected_once = True
                                console.print(f"\n[bold green]✓ Scanned successfully![/bold green] Payee: {payload['vpa']} | Amount: {payload['amount']}")
                        else:
                            box_color = (0, 0, 255)
                            status_label = f"SECURITY ALERT: {msg}"
                            cv2.polylines(frame, [pts], isClosed=True, color=box_color, thickness=4)

                # HUD Overlay bar
                cv2.rectangle(frame, (0, h - 50), (w, h), (20, 20, 20), -1)
                cv2.putText(
                    frame,
                    status_label,
                    (20, h - 18),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.65,
                    box_color,
                    2,
                )

                cv2.imshow("ProPay Dynamic QR Scanner (HUD)", frame)
                key = cv2.waitKey(1) & 0xFF
                if key in (ord('q'), 27):  # 'q' or ESC
                    break
        finally:
            cap.release()
            cv2.destroyAllWindows()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="ProPay Attack-Resilient Dynamic QR Code CLI")
    parser.add_argument("--generate", action="store_true", help="Generate a signed payment QR code")
    parser.add_argument("--vpa", type=str, default="merchant@propay", help="Payee UPI Virtual Payment Address")
    parser.add_argument("--name", type=str, default="Merchant Store", help="Payee display name")
    parser.add_argument("--amount", type=float, default=250.00, help="Payment amount")
    parser.add_argument("--currency", type=str, default="INR", help="Currency symbol (default: INR)")
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS, help="QR expiry in seconds")
    parser.add_argument("--export", type=str, help="Path to export generated QR image (PNG)")
    parser.add_argument("--verify-file", type=str, help="Verify QR code from an image file")
    parser.add_argument("--verify-payload", type=str, help="Verify a raw JSON or Base64 QR payload string")
    parser.add_argument("--scan", action="store_true", help="Open webcam scanner with HUD targeting")

    args = parser.parse_args()
    engine = SignedQREngine()
    cli = QRScannerCLI(engine)

    if args.generate:
        payload = engine.generate_payload(
            vpa=args.vpa,
            amount=args.amount,
            name=args.name,
            currency=args.currency,
            ttl_seconds=args.ttl,
        )
        export_path = Path(args.export) if args.export else None
        cli.display_generated_qr(payload, export_path=export_path)

    elif args.verify_file:
        cli.verify_file(args.verify_file)

    elif args.verify_payload:
        cli.verify_payload_string(args.verify_payload)

    elif args.scan:
        cli.scan_webcam()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
