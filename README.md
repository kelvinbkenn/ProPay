# ProPay 🛡️ — Attack-Resilient CLI UPI Payment Platform

[![Python Version](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://python.org)
[![Security Level](https://img.shields.io/badge/Security-Multi--Factor%20Biometric%20%2B%20PIN-brightgreen.svg)]()
[![Biometrics](https://img.shields.io/badge/Face%20Engine-YuNet%20%2B%20SFace%20(OpenCV%20DNN)-orange.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Pure%20CLI-purple.svg)]()

**ProPay** is a hardened, command-line UPI-like payment prototype architected specifically for **cybersecurity hackathons**. It implements zero-trust payment authorization combining **deep neural biometric face verification with active liveness anti-spoofing**, **constant-time salted PIN authentication**, **cryptographically signed dynamic QR codes**, and an **append-only verifiable cryptographic transaction ledger**.

---

## 📑 Table of Contents
1. [Architecture Overview](#-architecture-overview)
2. [Cybersecurity Threat Model & Defense Matrix](#-cybersecurity-threat-model--defense-matrix)
3. [Module Breakdown](#-module-breakdown)
4. [Part 1: Biometric Face Engine & Anti-Spoofing Deep Dive](#-part-1-biometric-face-engine--anti-spoofing-deep-dive)
5. [Installation & Setup](#-installation--setup)
6. [CLI Usage Guide](#-cli-usage-guide)
7. [Running Tests](#-running-tests)
8. [Roadmap](#-roadmap)

---

## 🏛️ Architecture Overview

```
                                  PROPAY SYSTEM ARCHITECTURE
                                  
    +---------------------------------------------------------------------------------+
    |                                   main.py                                       |
    |                   Interactive Rich CLI Session & Workflow Manager              |
    +---------------------------------------------------------------------------------+
           |                           |                              |
           v                           v                              v
    +--------------+            +--------------+               +--------------+
    | face_scan.py |            | pin_auth.py  |               | qr_scanner.py|
    |  YuNet ONNX  |            |  Argon2id /  |               | Signed QR    |
    |  SFace 128-D |            |  PBKDF2-HMAC |               | Nonce/Expiry |
    | Anti-Spoofing|            | Rate Limiter |               | ASCII Render |
    +--------------+            +--------------+               +--------------+
           |                           |                              |
           +---------------------------+------------------------------+
                                       |
                                       v
                        +------------------------------+
                        |       crypto_vault.py        |
                        | AES-256-GCM Encrypted Storage|
                        | Private Key & Template Store |
                        +------------------------------+
                                       |
                                       v
                        +------------------------------+
                        |          ledger.py           |
                        | Tamper-Evident Merkle Ledger |
                        | SHA-256 Chained Transactions |
                        +------------------------------+
```

---

## 🛡️ Cybersecurity Threat Model & Defense Matrix

| Attack Vector | Hacker Exploitation Technique | ProPay Countermeasure & Implementation |
| :--- | :--- | :--- |
| **Biometric Spoofing (Presentation Attack)** | Holding a printed photo, paper mask, or displaying a video on a smartphone screen in front of the camera. | **Multi-tier Liveness Engine**: <br>1. *Passive Texture Check*: Computes Laplacian variance ($\ge 35.0$) & saturation variance to detect flat surfaces and screen refresh moiré patterns.<br>2. *Active Challenge-Response*: Random prompt (eye blink, head tilt right/left) tracked via real-time 5-point facial landmarks. |
| **Biometric Replay Attack** | Injecting recorded video frames or captured raw embedding vectors into the CLI input. | **Dynamic Nonce & Session Binding**: Every biometric request is coupled to a timestamped, single-use cryptographic token that expires in 15 seconds. |
| **Template Inversion & Biometric Theft** | Dumping filesystem or memory to reconstruct face photos from stolen embeddings. | **Encrypted Biometric Vault**: 128-d float embeddings are stored in AES-256-GCM encrypted vaults derived via PBKDF2 with CSPRNG salts. Raw facial photos are never saved to disk. |
| **Brute-Force & Dictionary Attacks** | High-speed automated guessing of numeric UPI PINs. | **PBKDF2-HMAC-SHA256 / Argon2id** with high work factor ($600,000$ iterations) + **Exponential Backoff Rate Limiter** with mandatory 15-minute lockouts after 3 consecutive failures. |
| **Side-Channel Timing Attacks** | Measuring response latency down to milliseconds to infer correct characters during PIN/template comparison. | **Constant-Time Execution**: All hash and signature comparisons utilize `hmac.compare_digest` to prevent timing leaks. |
| **QR Code Tampering & Man-in-the-Middle** | Modifying recipient VPA or transaction amount in a printed/scanned QR code. | **Cryptographically Signed QR Codes**: Payload contains `vpa`, `amount`, `txn_nonce`, `timestamp`, `expires_at`, verified via **HMAC-SHA256 / Ed25519** signature. Modified payloads trigger immediate signature mismatch errors. |
| **Ledger Retroactive Tampering** | Altering local balance files or deleting previous debits. | **Cryptographic Hash Chain**: Every transaction includes `SHA-256(prev_hash + tx_data)`. Any single byte alteration invalidates the entire chain during automated consistency verification. |

---

## 📦 Module Breakdown

```
ProPay/
├── models/                                      # Deep learning weights (ONNX)
│   ├── face_detection_yunet_2023mar.onnx        # YuNet: SOTA face & landmark detector
│   └── face_recognition_sface_2021dec.onnx      # SFace: 128-D deep feature embedder
├── data/                                        # Local encrypted storage
│   └── biometrics/                              # Biometric templates
├── face_scan.py                                 # Part 1: Face scan, embeddings & liveness
├── pin_auth.py                                  # Part 2: Constant-time PIN authentication
├── qr_scanner.py                                # Part 3: Signed QR generation & scanning
├── crypto_vault.py                              # Part 4: AES-256-GCM credential vault
├── ledger.py                                    # Part 5: Tamper-evident transaction ledger
├── main.py                                      # Part 6: Unified interactive Rich CLI
└── tests/                                       # Security test suites
    └── test_face_scan.py                        # Face verification & spoof tests
```

---

## 👁️ Part 1: Biometric Face Engine & Anti-Spoofing Deep Dive

The biometric subsystem in `face_scan.py` operates without dependencies on outdated wrappers (such as `face_recognition`/dlib), leveraging official **OpenCV Deep Neural Networks (DNN)**:

### 1. Face Detection & Landmark Alignment (YuNet)
- Model: `face_detection_yunet_2023mar.onnx`
- Detects bounding box $(x, y, w, h)$ and 5 facial landmarks:
  - Right Eye $(x_{re}, y_{re})$
  - Left Eye $(x_{le}, y_{le})$
  - Nose Tip $(x_{nose}, y_{nose})$
  - Right Mouth Corner $(x_{rc}, y_{rc})$
  - Left Mouth Corner $(x_{lc}, y_{lc})$

### 2. Feature Extraction & Embeddings (SFace)
- Model: `face_recognition_sface_2021dec.onnx`
- Aligns and crops the face based on landmark geometry to normalize head rotation.
- Computes a **128-dimensional floating point representation** $\vec{v} \in \mathbb{R}^{128}$ and L2-normalizes it:
  $$\hat{v} = \frac{\vec{v}}{\|\vec{v}\|_2}$$

### 3. Matching Metric (Cosine Similarity)
- Computes cosine similarity between candidate embedding $\hat{a}$ and enrolled template $\hat{b}$:
  $$\text{Cosine Similarity}(\hat{a}, \hat{b}) = \frac{\hat{a} \cdot \hat{b}}{\|\hat{a}\|_2 \|\hat{b}\|_2} = \hat{a} \cdot \hat{b}$$
- **Threshold Calibration**:
  - Cosine Similarity $\ge 0.650 \implies \textbf{Match (Genuine User)}$
  - Cosine Similarity $< 0.650 \implies \textbf{Mismatch (Impostor)}$

### 4. Liveness & Presentation Attack Defense
1. **Passive Texture Analysis**:
   - Computes Laplacian variance on grayscale face crop:
     $$\sigma^2 = \text{Var}(\nabla^2 I)$$
   - Rejects inputs with $\sigma^2 < 35.0$ (identifying blurry printed photos, flat card attacks, or defocused camera feeds).
2. **Active Dynamic Challenge-Response**:
   - Issues a randomized real-time prompt upon activation (e.g., *Blink Eyes*, *Tilt Head Right*, *Tilt Head Left*, *Center & Hold*).
   - Tracks landmark trajectory across frames (e.g. Eye Aspect Ratio changes or eye-line inclination $\theta = \arctan\frac{y_{le} - y_{re}}{x_{le} - x_{re}}$).
   - A static picture cannot react to dynamic challenges and times out after $6.0\text{s}$.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.10+ (Tested on Python 3.11, 3.12, and 3.14 on Windows/Linux/macOS)
- Webcam (for live biometric verification and QR scanning)

### Installation Steps

```powershell
# 1. Clone repository
git clone https://github.com/kelvinbkenn/ProPay.git
cd ProPay

# 2. Install required dependencies
pip install opencv-python numpy rich cryptography qrcode pillow
```

*Note: The ONNX models (`face_detection_yunet_2023mar.onnx` and `face_recognition_sface_2021dec.onnx`) download automatically into `models/` on first run.*

---

## 💻 CLI Usage Guide

### Face Biometric Operations (`face_scan.py`)

#### 1. Enroll User Face
Enrolls a new user with multi-frame averaging and saves the template:
```powershell
python face_scan.py --enroll alice
```

#### 2. Verify User Face with Liveness Challenge
Prompts camera verification with interactive liveness challenges:
```powershell
python face_scan.py --verify alice
```

#### 3. List Enrolled Biometric Templates
Displays a summary of enrolled biometric profiles:
```powershell
python face_scan.py --list
```

#### 4. Offline / Headless Image Comparison
Compares two image files and calculates cosine similarity without a live webcam:
```powershell
python face_scan.py --verify-files image1.jpg image2.jpg
```

---

## 🧪 Running Tests

The test suite runs deterministically without requiring a live camera feed:

```powershell
python -m unittest tests/test_face_scan.py -v
```

### Test Coverage Summary:
- ✅ `test_01_models_loaded`: Validates YuNet detector and SFace recognizer initialization.
- ✅ `test_02_feature_vector_dimension_and_norm`: Confirms 128-dimensional L2-normalized embedding extraction.
- ✅ `test_03_cosine_similarity_identity_and_orthogonality`: Verifies cosine similarity mathematical correctness.
- ✅ `test_04_verification_match_and_impostor_rejection`: Validates separation between genuine samples ($\ge 0.90$) and impostors ($< 0.40$).
- ✅ `test_05_anti_spoof_blurry_and_blank_rejection`: Rejects zero-variance / blurred presentation attack inputs.
- ✅ `test_06_template_save_and_load`: Tests biometric template persistence and integrity.

---

## 🗺️ Roadmap
- [x] **Part 1**: Biometric Face Scan & Liveness Engine (`face_scan.py`)
- [ ] **Part 2**: Hardened Constant-Time PIN Authentication & Rate Limiter (`pin_auth.py`)
- [ ] **Part 3**: Cryptographically Signed Dynamic QR Code Generator & Scanner (`qr_scanner.py`)
- [ ] **Part 4**: AES-256-GCM Encrypted Vault & Key Management (`crypto_vault.py`)
- [ ] **Part 5**: Cryptographic Transaction Ledger & Merkle Audit Trail (`ledger.py`)
- [ ] **Part 6**: Unified Interactive Rich CLI Application (`main.py`)