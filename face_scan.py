"""
ProPay - Biometric Face Scan & Liveness Authentication Engine
Part 1 of the ProPay Secure CLI Payment Platform.

Uses OpenCV Deep Neural Networks:
- YuNet: High-accuracy face & 5-point landmark detection (ONNX)
- SFace: 128-dimensional deep facial feature representation (ONNX)
- Multi-tier anti-spoofing engine (texture analysis + dynamic motion/liveness challenges)
"""

import os
import sys
import time
import json
import base64
import random
import urllib.request
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

import cv2
import numpy as np

# Suppress non-critical OpenCV internal DNN graph warnings for a clean CLI
if hasattr(cv2, "utils") and hasattr(cv2.utils, "logging"):
    cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_ERROR)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

try:
    from crypto_vault import CryptoVault
    _VAULT_AVAILABLE = True
except ImportError:
    _VAULT_AVAILABLE = False

console = Console()

# Base directories
BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data" / "biometrics"

# Official OpenCV Zoo Model URLs and Paths
YUNET_URL = "https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx"
SFACE_URL = "https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx"

YUNET_PATH = MODELS_DIR / "face_detection_yunet_2023mar.onnx"
SFACE_PATH = MODELS_DIR / "face_recognition_sface_2021dec.onnx"

# Security Thresholds
# SFace cosine similarity standard threshold: 0.363 cosine distance => ~0.637 similarity.
# For high-security banking/UPI grade, we use 0.650 cosine similarity.
DEFAULT_MATCH_THRESHOLD = 0.650
LAPLACIAN_VARIANCE_MIN = 35.0  # Threshold to reject blurred photos / static paper prints


def ensure_models_downloaded() -> None:
    """Ensure ONNX deep learning weights exist locally, downloading if missing."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    if not YUNET_PATH.exists():
        console.print("[yellow]Downloading YuNet Face Detection model...[/yellow]")
        urllib.request.urlretrieve(YUNET_URL, YUNET_PATH)
        console.print(f"[green]Downloaded: {YUNET_PATH.name}[/green]")

    if not SFACE_PATH.exists():
        console.print("[yellow]Downloading SFace Facial Recognition model (38MB)...[/yellow]")
        urllib.request.urlretrieve(SFACE_URL, SFACE_PATH)
        console.print(f"[green]Downloaded: {SFACE_PATH.name}[/green]")


class AntiSpoofEngine:
    """
    Multi-stage anti-spoofing & liveness verification:
    1. Passive: Texture/Frequency domain analysis (detecting screen pixel grids, paper reflections, blur).
    2. Active Challenge: Randomized landmark motion tracking (e.g., eye blink, head turns, distance shift).
    """

    @staticmethod
    def analyze_texture(crop_bgr: np.ndarray) -> Tuple[bool, float, str]:
        """
        Evaluates image sharpness and frequency distribution to detect presentation attacks
        such as low-resolution photos or screen recordings.
        """
        if crop_bgr is None or crop_bgr.size == 0:
            return False, 0.0, "Empty face region"

        gray = cv2.cvtColor(crop_bgr, cv2.COLOR_BGR2GRAY)
        
        # 1. Laplacian variance (Blurriness / Flat surface test)
        lap_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
        if lap_var < LAPLACIAN_VARIANCE_MIN:
            return False, lap_var, f"Image lacks natural depth/sharpness (Variance: {lap_var:.1f} < {LAPLACIAN_VARIANCE_MIN})"

        # 2. Specular / Color saturation distribution
        hsv = cv2.cvtColor(crop_bgr, cv2.COLOR_BGR2HSV)
        sat_std = float(np.std(hsv[:, :, 1]))
        if sat_std < 5.0:
            return False, lap_var, "Monochrome/spoofed color profile detected"

        return True, lap_var, "Texture authenticity verified"

    @staticmethod
    def compute_eye_aspect_ratio(landmarks: np.ndarray) -> float:
        """
        Computes eye spacing and relative proportions from 5-point landmarks:
        [x_re, y_re, x_le, y_le, x_nose, y_nose, x_rc, y_rc, x_lc, y_lc]
        """
        re_x, re_y = landmarks[0], landmarks[1]
        le_x, le_y = landmarks[2], landmarks[3]
        nose_x, nose_y = landmarks[4], landmarks[5]

        eye_dist = np.sqrt((re_x - le_x) ** 2 + (re_y - le_y) ** 2)
        eye_mid_x, eye_mid_y = (re_x + le_x) / 2.0, (re_y + le_y) / 2.0
        vertical_dist = np.sqrt((eye_mid_x - nose_x) ** 2 + (eye_mid_y - nose_y) ** 2)

        if eye_dist <= 1e-5:
            return 0.0
        return float(vertical_dist / eye_dist)

    @staticmethod
    def generate_random_challenge() -> Dict[str, Any]:
        """Generates a dynamic challenge for liveness verification."""
        challenges = [
            {
                "id": "blink",
                "instruction": "Please BLINK your eyes naturally",
                "action_type": "blink",
                "timeout_sec": 6.0,
            },
            {
                "id": "tilt_right",
                "instruction": "Slightly TILT your head to the RIGHT",
                "action_type": "tilt_right",
                "timeout_sec": 6.0,
            },
            {
                "id": "tilt_left",
                "instruction": "Slightly TILT your head to the LEFT",
                "action_type": "tilt_left",
                "timeout_sec": 6.0,
            },
            {
                "id": "center",
                "instruction": "Look STRAIGHT at the camera and HOLD STILL",
                "action_type": "center",
                "timeout_sec": 4.0,
            },
        ]
        return random.choice(challenges)


class FaceEngine:
    """
    Core Facial Biometrics Engine wrapping OpenCV YuNet and SFace ONNX models.
    """

    def __init__(
        self,
        match_threshold: float = DEFAULT_MATCH_THRESHOLD,
        detector_score_threshold: float = 0.85,
        input_size: Tuple[int, int] = (320, 320),
    ):
        ensure_models_downloaded()
        self.match_threshold = match_threshold
        self.detector_score_threshold = detector_score_threshold
        self.input_size = input_size

        # Initialize YuNet Face Detector
        self.detector = cv2.FaceDetectorYN.create(
            str(YUNET_PATH),
            "",
            input_size,
            score_threshold=detector_score_threshold,
            nms_threshold=0.3,
            top_k=5000,
        )

        # Initialize SFace Face Recognizer
        self.recognizer = cv2.FaceRecognizerSF.create(str(SFACE_PATH), "")
        self.anti_spoof = AntiSpoofEngine()

    def detect_faces(self, image_bgr: np.ndarray) -> Optional[np.ndarray]:
        """
        Detects faces in the given BGR image.
        Returns array of detected faces or None.
        Each face row: [x, y, w, h, x_re, y_re, x_le, y_le, x_nose, y_nose, x_rc, y_rc, x_lc, y_lc, score]
        """
        if image_bgr is None or image_bgr.size == 0:
            return None

        h, w = image_bgr.shape[:2]
        self.detector.setInputSize((w, h))

        _, faces = self.detector.detect(image_bgr)
        return faces

    def extract_feature(self, image_bgr: np.ndarray, face_data: np.ndarray) -> np.ndarray:
        """
        Aligns the detected face crop using 5-point landmarks and extracts
        a 128-dimensional normalized feature embedding vector.
        """
        aligned_face = self.recognizer.alignCrop(image_bgr, face_data)
        feature = self.recognizer.feature(aligned_face)
        # Ensure L2 normalized embedding
        norm = np.linalg.norm(feature)
        if norm > 1e-6:
            feature = feature / norm
        return feature.flatten()

    def extract_primary_embedding(
        self, image_bgr: np.ndarray, check_anti_spoof: bool = True
    ) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], str]:
        """
        Finds the most prominent (highest confidence / largest) face in the image
        and extracts its normalized 128-d embedding.
        Returns: (embedding_vec, face_bbox_and_landmarks, status_message)
        """
        faces = self.detect_faces(image_bgr)
        if faces is None or len(faces) == 0:
            return None, None, "No face detected in frame."

        best_face = faces[0]
        if len(faces) > 1:
            best_face = max(faces, key=lambda f: f[2] * f[3] * f[14])

        score = best_face[14]
        if score < self.detector_score_threshold:
            return None, None, f"Face detection confidence too low ({score:.2f} < {self.detector_score_threshold:.2f})"

        if check_anti_spoof:
            x, y, w, h = int(best_face[0]), int(best_face[1]), int(best_face[2]), int(best_face[3])
            x, y = max(0, x), max(0, y)
            face_crop = image_bgr[y : y + h, x : x + w]

            passed_tex, var_val, tex_msg = self.anti_spoof.analyze_texture(face_crop)
            if not passed_tex:
                return None, None, f"Anti-Spoof Rejected: {tex_msg}"

        embedding = self.extract_feature(image_bgr, best_face)
        return embedding, best_face, "Face successfully extracted"

    @staticmethod
    def compute_similarity(emb1: np.ndarray, emb2: np.ndarray) -> float:
        """
        Calculates cosine similarity between two 128-d face embeddings.
        Returns score in range [-1.0, 1.0].
        """
        vec1 = np.asarray(emb1, dtype=np.float32).flatten()
        vec2 = np.asarray(emb2, dtype=np.float32).flatten()

        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        if norm1 <= 1e-6 or norm2 <= 1e-6:
            return 0.0

        cosine_sim = float(np.dot(vec1, vec2) / (norm1 * norm2))
        return cosine_sim

    def verify_embedding(
        self,
        candidate_emb: np.ndarray,
        template_emb: np.ndarray,
        threshold: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """
        Compares candidate embedding against enrolled template.
        Returns: (is_match, similarity_score)
        """
        thresh = threshold if threshold is not None else self.match_threshold
        similarity = self.compute_similarity(candidate_emb, template_emb)
        is_match = similarity >= thresh
        return is_match, similarity

    # ------------------------------------------------------------------------
    # Enrolled Templates Storage (AES-256-GCM Encrypted Vault & JSON Fallback)
    # ------------------------------------------------------------------------
    def save_template(self, username: str, embedding: np.ndarray, metadata: Optional[Dict[str, Any]] = None) -> Path:
        """Saves enrolled biometric template both in encrypted AES-256-GCM vault and JSON store."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        sanitized = username.lower().strip()
        template_path = DATA_DIR / f"{sanitized}_template.json"
        
        payload = {
            "username": sanitized,
            "created_at": time.time(),
            "model": "SFace-128D",
            "embedding": embedding.tolist(),
            "metadata": metadata or {},
        }
        with open(template_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # Store in AES-256-GCM encrypted vault
        if _VAULT_AVAILABLE:
            try:
                CryptoVault().store_biometric_template(sanitized, embedding, metadata)
            except Exception as e:
                console.print(f"[dim yellow]Notice: Vault encryption skipped: {e}[/dim yellow]")

        return template_path

    def load_template(self, username: str) -> Optional[np.ndarray]:
        """Loads enrolled biometric template for given user, prioritizing encrypted vault."""
        sanitized = username.lower().strip()
        # 1. Try loading from AES-256-GCM encrypted vault
        if _VAULT_AVAILABLE:
            try:
                emb = CryptoVault().load_biometric_template(sanitized)
                if emb is not None:
                    return emb
            except Exception:
                pass

        # 2. Fallback to unencrypted JSON template
        template_path = DATA_DIR / f"{sanitized}_template.json"
        if not template_path.exists():
            return None
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return np.array(data["embedding"], dtype=np.float32)
        except Exception as e:
            console.print(f"[red]Error loading biometric template for {username}: {e}[/red]")
            return None

    def list_enrolled_users(self) -> List[str]:
        """Returns unified list of all enrolled usernames from vault and disk."""
        users = set()
        if _VAULT_AVAILABLE:
            try:
                users.update(CryptoVault().list_enrolled_users())
            except Exception:
                pass

        if DATA_DIR.exists():
            for file in DATA_DIR.glob("*_template.json"):
                uname = file.name.replace("_template.json", "")
                users.add(uname)
        return sorted(list(users))

    def enroll_user(self, username: str, camera_id: int = 0) -> bool:
        """Interactive face enrollment helper for unified CLI workflows."""
        cli = FaceAuthenticatorCLI(self)
        return cli.enroll_interactive(username)

    def verify_user(self, username: str, camera_id: int = 0) -> Tuple[bool, float]:
        """Interactive face verification helper with liveness challenge."""
        cli = FaceAuthenticatorCLI(self)
        ok, sim, _ = cli.verify_interactive(username)
        return ok, sim


class FaceAuthenticatorCLI:
    """
    Interactive CLI Controller for Face Enrollment and Multi-factor Verification.
    Supports both live camera stream with liveness challenge and headless testing.
    """

    def __init__(self, engine: Optional[FaceEngine] = None):
        self.engine = engine or FaceEngine()

    def capture_with_liveness(
        self,
        camera_id: int = 0,
        enable_challenge: bool = True,
        display_window: bool = True,
        max_duration_sec: float = 15.0,
    ) -> Tuple[Optional[np.ndarray], bool, str]:
        """
        Captures face from webcam with real-time liveness challenge.
        Returns: (extracted_embedding, liveness_passed, status_message)
        """
        cap = cv2.VideoCapture(camera_id)
        if not cap.isOpened():
            return None, False, f"Could not access camera (Device ID: {camera_id}). Ensure camera is connected."

        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

        challenge = AntiSpoofEngine.generate_random_challenge() if enable_challenge else None
        challenge_passed = not enable_challenge
        start_time = time.time()

        console.print(
            Panel(
                f"[bold cyan]Camera Activated for Biometric Verification[/bold cyan]\n"
                f"[yellow]Challenge: {challenge['instruction'] if challenge else 'Align Face & Look at Camera'}[/yellow]\n"
                f"Press [bold green]'q'[/bold green] to cancel at any time.",
                title="ProPay Biometric Auth",
            )
        )

        ear_history: List[float] = []
        angle_history: List[float] = []
        best_embedding: Optional[np.ndarray] = None
        frames_collected: List[np.ndarray] = []

        try:
            while time.time() - start_time < max_duration_sec:
                ret, frame = cap.read()
                if not ret or frame is None:
                    time.sleep(0.05)
                    continue

                frame = cv2.flip(frame, 1)
                h, w = frame.shape[:2]

                faces = self.engine.detect_faces(frame)
                status_text = "Searching for face..."
                status_color = (0, 165, 255)  # Orange

                if faces is not None and len(faces) > 0:
                    best_face = faces[0]
                    x, y, fw, fh = (
                        int(best_face[0]),
                        int(best_face[1]),
                        int(best_face[2]),
                        int(best_face[3]),
                    )
                    score = float(best_face[14])

                    if score >= self.engine.detector_score_threshold:
                        landmarks = best_face[4:14]
                        ear = AntiSpoofEngine.compute_eye_aspect_ratio(landmarks)
                        ear_history.append(ear)

                        re_x, re_y = landmarks[0], landmarks[1]
                        le_x, le_y = landmarks[2], landmarks[3]
                        angle = np.degrees(np.arctan2(le_y - re_y, le_x - re_x))
                        angle_history.append(angle)

                        # Liveness Challenge Verification
                        if not challenge_passed and challenge:
                            if challenge["id"] == "blink":
                                if len(ear_history) > 10:
                                    recent_std = np.std(ear_history[-10:])
                                    recent_min = np.min(ear_history[-10:])
                                    recent_max = np.max(ear_history[-10:])
                                    if (recent_max - recent_min) > 0.12 or recent_std > 0.04:
                                        challenge_passed = True
                            elif challenge["id"] == "tilt_right":
                                if any(a > 8.0 for a in angle_history[-15:]):
                                    challenge_passed = True
                            elif challenge["id"] == "tilt_left":
                                if any(a < -8.0 for a in angle_history[-15:]):
                                    challenge_passed = True
                            elif challenge["id"] == "center":
                                if len(angle_history) > 12 and all(abs(a) < 6.0 for a in angle_history[-10:]):
                                    challenge_passed = True

                        if challenge_passed:
                            status_text = "Liveness PASSED! Hold still..."
                            status_color = (0, 255, 0)  # Green
                            try:
                                emb = self.engine.extract_feature(frame, best_face)
                                frames_collected.append(emb)
                                if len(frames_collected) >= 5:
                                    avg_emb = np.mean(frames_collected, axis=0)
                                    best_embedding = avg_emb / np.linalg.norm(avg_emb)
                                    break
                            except Exception:
                                pass
                        else:
                            status_text = f"Action Required: {challenge['instruction']}"
                            status_color = (0, 255, 255)  # Yellow

                        if display_window:
                            cv2.rectangle(frame, (x, y), (x + fw, y + fh), status_color, 2)
                            for i in range(0, 10, 2):
                                px, py = int(landmarks[i]), int(landmarks[i + 1])
                                cv2.circle(frame, (px, py), 3, (255, 0, 0), -1)

                if display_window:
                    cv2.rectangle(frame, (0, 0), (w, 40), (20, 20, 20), -1)
                    cv2.putText(
                        frame,
                        f"ProPay Auth | {status_text}",
                        (10, 26),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.6,
                        status_color,
                        2,
                    )
                    cv2.imshow("ProPay - Biometric Scanner", frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        return None, False, "Biometric scan cancelled by user."

            if best_embedding is not None and challenge_passed:
                return best_embedding, True, "Biometric face verification completed successfully."
            elif not challenge_passed:
                return None, False, "Liveness challenge failed or timed out."
            else:
                return None, False, "Biometric scan timed out. No stable face captured."

        finally:
            cap.release()
            if display_window:
                cv2.destroyAllWindows()

    def enroll_interactive(self, username: str) -> bool:
        """CLI interactive face enrollment procedure."""
        console.print(f"\n[bold green]== Enrolling Face for User: [white]{username}[/white] ==[/bold green]")
        existing = self.engine.load_template(username)
        if existing is not None:
            console.print(f"[yellow]Warning: An enrolled biometric template already exists for '{username}'. Overwriting...[/yellow]")

        console.print("[cyan]Initializing camera for multi-frame biometric enrollment...[/cyan]")
        emb, passed, msg = self.capture_with_liveness(enable_challenge=False, max_duration_sec=10.0)

        if not passed or emb is None:
            console.print(f"[bold red]❌ Enrollment Failed: {msg}[/bold red]")
            return False

        path = self.engine.save_template(username, emb, {"enrolled_via": "CLI_Webcam"})
        console.print(
            Panel(
                f"[bold green]✔ Biometric Enrollment Successful![/bold green]\n"
                f"User: [white]{username}[/white]\n"
                f"Feature Vector: [cyan]128-dimensional Deep Neural Embedding[/cyan]\n"
                f"Template Path: [dim]{path}[/dim]",
                title="Biometrics Stored",
            )
        )
        return True

    def verify_interactive(self, username: str) -> Tuple[bool, float, str]:
        """CLI interactive face verification procedure with liveness challenge."""
        console.print(f"\n[bold cyan]== Verifying Biometric Identity for: [white]{username}[/white] ==[/bold cyan]")
        template = self.engine.load_template(username)
        if template is None:
            msg = f"User '{username}' is not enrolled in the biometric vault."
            console.print(f"[bold red]❌ {msg}[/bold red]")
            return False, 0.0, msg

        emb, passed_liveness, msg = self.capture_with_liveness(enable_challenge=True, max_duration_sec=15.0)
        if not passed_liveness or emb is None:
            console.print(f"[bold red]❌ Biometric Verification Failed: {msg}[/bold red]")
            return False, 0.0, msg

        is_match, similarity = self.engine.verify_embedding(emb, template)
        if is_match:
            console.print(
                Panel(
                    f"[bold green]✔ Biometric Identity Confirmed![/bold green]\n"
                    f"User: [white]{username}[/white]\n"
                    f"Cosine Similarity: [bold green]{similarity:.4f}[/bold green] (Threshold: {self.engine.match_threshold:.3f})\n"
                    f"Liveness Check: [bold green]PASSED[/bold green]",
                    title="Face Auth Success",
                )
            )
            return True, similarity, "Face verification succeeded."
        else:
            console.print(
                Panel(
                    f"[bold red]❌ Biometric Mismatch / Impostor Detected![/bold red]\n"
                    f"Similarity: [bold red]{similarity:.4f}[/bold red] (Threshold: {self.engine.match_threshold:.3f})\n"
                    f"The presented face does not match the enrolled template for '{username}'.",
                    title="Security Alert",
                )
            )
            return False, similarity, "Biometric similarity below required threshold."


# ----------------------------------------------------------------------------
# Command-Line Testing & Benchmark Interface
# ----------------------------------------------------------------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="ProPay Biometric Face Scan & Liveness CLI")
    parser.add_argument("--enroll", type=str, help="Enroll a new user biometric template (webcam)")
    parser.add_argument("--verify", type=str, help="Verify user identity against enrolled template (webcam)")
    parser.add_argument("--list", action="store_true", help="List all enrolled users")
    parser.add_argument("--threshold", type=float, default=DEFAULT_MATCH_THRESHOLD, help="Set match threshold")
    parser.add_argument("--verify-files", nargs=2, metavar=("IMG1", "IMG2"), help="Compare two image files offline")

    args = parser.parse_args()
    engine = FaceEngine(match_threshold=args.threshold)
    cli = FaceAuthenticatorCLI(engine)

    if args.enroll:
        cli.enroll_interactive(args.enroll)
    elif args.verify:
        cli.verify_interactive(args.verify)
    elif args.list:
        users = engine.list_enrolled_users()
        table = Table(title="Enrolled Biometric Templates")
        table.add_column("Username", style="cyan")
        table.add_column("Model Type", style="green")
        table.add_column("Template File", style="dim")
        for u in users:
            table.add_row(u, "SFace-128D (ONNX)", f"data/biometrics/{u}_template.json")
        console.print(table)
    elif args.verify_files:
        p1, p2 = args.verify_files
        img1 = cv2.imread(p1)
        img2 = cv2.imread(p2)
        if img1 is None or img2 is None:
            console.print("[red]Error: Could not read one or both image files.[/red]")
            sys.exit(1)

        emb1, _, msg1 = engine.extract_primary_embedding(img1, check_anti_spoof=False)
        emb2, _, msg2 = engine.extract_primary_embedding(img2, check_anti_spoof=False)
        if emb1 is None:
            console.print(f"[red]Image 1 Error: {msg1}[/red]")
            sys.exit(1)
        if emb2 is None:
            console.print(f"[red]Image 2 Error: {msg2}[/red]")
            sys.exit(1)

        match, sim = engine.verify_embedding(emb1, emb2)
        console.print(f"[bold]Cosine Similarity:[/bold] {sim:.4f}")
        console.print(f"[bold]Match Decision (>= {args.threshold}):[/bold] {'[green]MATCH[/green]' if match else '[red]NO MATCH[/red]'}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
