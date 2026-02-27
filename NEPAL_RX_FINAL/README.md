# Nepal E-Prescription System v3.7
### ST6051CEM Practical Cryptography — Open-Source Cryptographic Tool

A PKI-based secure electronic prescription system for Nepal's healthcare sector.  
Implements **digital signatures, hybrid encryption, X.509 certificates, PKCS#12 keystores, HSM simulation, and Certificate Revocation**.

---

## 🔐 Cryptographic Features

| Feature | Algorithm | Standard |
|---------|-----------|----------|
| Password Hashing | PBKDF2-SHA256 | NIST SP 800-132 |
| Symmetric Encryption | AES-256-GCM | NIST FIPS 197 |
| Key Wrapping | RSA-OAEP + MGF1-SHA256 | PKCS#1 v2.2 |
| Digital Signatures | RSA-PSS + SHA-256 | PKCS#1 v2.2 |
| Certificates | X.509 v3 Self-Signed | RFC 5280 |
| Key Storage | PKCS#12 Password-Protected | RFC 7292 |
| HSM | Software Simulation | FIPS 140-2 |
| Key Size | RSA-2048 | NIST SP 800-57 |

---

## 🛡️ Security Features

- **Replay Attack Prevention** — Unique UUID + timestamp per prescription; duplicate IDs rejected
- **MITM Prevention** — RSA-PSS digital signature covers all prescription fields; tampering detected
- **Forward Secrecy** — Fresh 256-bit AES session key generated per prescription
- **Brute Force Protection** — Account lockout after 5 failed attempts (30 minutes)
- **Key Revocation (CRL)** — Certificate Revocation List; revoked keys rejected on verification
- **Confidentiality** — AES-256-GCM encryption; only pharmacist private key can decrypt

---

## 🚀 Installation

### Requirements
- Python 3.10+
- pip

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/nepal-rx-system.git
cd nepal-rx-system

# 2. Install dependencies
pip install -r requirements.txt

# 3. Delete any existing database (fresh install)
del nepal_rx_process_logs.db    # Windows
rm -f nepal_rx_process_logs.db  # Linux/Mac

# 4. Run the application
python App.py
```

### Access
- **Web Interface:** http://127.0.0.1:5000
- **Admin Panel:** http://127.0.0.1:5000/admin

---

## 👥 Default Users

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin@2024!` |
| Doctor | `doctor1` | `Doctor@123` |
| Doctor | `doctor2` | `Doctor@456` |
| Pharmacist | `pharmacist1` | `Pharm@123` |
| Patient | `patient1` | `Patient@123` |

---

## 📋 Key URLs

| URL | Description |
|-----|-------------|
| `/dashboard` | Role-specific dashboard |
| `/create-prescription` | Doctor: create & sign prescription |
| `/prescriptions` | View all prescriptions |
| `/certificate/<username>` | View X.509 certificate |
| `/download-keystore` | Download PKCS#12 keystore |
| `/revoke-key` | Admin/Doctor: revoke certificate |
| `/revoked-keys` | Certificate Revocation List (CRL) |
| `/attack-demo` | Attack prevention demonstrations |
| `/use-cases` | Three real-world use cases |
| `/admin/process-logs` | 9-step encryption process logs |
| `/admin/algorithm-usage` | Algorithm usage statistics |

---

## 🧪 Running Tests

```bash
# Run all unit tests + attack simulation tests
python3 -m unittest tests/test_nepal_rx.py -v
```

**Test coverage (24 tests):**
- RSA-2048 key generation
- Digital signature sign/verify
- MITM tampered-data rejection
- Unauthorized signing rejection
- Multi-user independent signatures
- Hybrid AES-256-GCM encryption/decryption
- GCM authentication tag tampering detection
- X.509 certificate generation & validation
- PKCS#12 keystore export + wrong-password rejection
- Certificate Revocation List simulation
- Replay attack prevention (UUID uniqueness)
- PBKDF2 brute-force cost verification
- Forward secrecy (unique ciphertext per encryption)

---

## 📁 Project Structure

```
nepal-rx-system/
├── App.py                     # Main Flask application (1900+ lines)
├── requirements.txt           # Python dependencies
├── LICENSE                    # MIT License
├── README.md                  # This file
├── example_usage.py           # Standalone usage examples
├── CREDENTIALS_AND_INFO.txt   # Full user credentials + crypto docs
├── tests/
│   └── test_nepal_rx.py       # 24 unit + attack simulation tests
├── .github/
│   └── workflows/
│       └── tests.yml          # CI/CD pipeline
└── templates/                 # Jinja2 HTML templates
    ├── base.html
    ├── dashboard.html
    ├── certificate.html        # X.509 certificate viewer
    ├── download_keystore.html  # PKCS#12 keystore download
    ├── revoke_key.html         # Certificate revocation
    ├── revoked_keys.html       # CRL viewer
    ├── attack_demo.html        # Attack prevention demos
    ├── use_cases.html          # 3 real-world use cases
    └── admin/
        ├── dashboard.html
        ├── process_logs.html   # 9-step crypto process logs
        ├── algorithm_usage.html
        └── change_logs.html
```

---

## 🔑 How It Works

### Prescription Encryption (9 Steps)
1. Generate 256-bit AES session key (random)
2. Generate 96-bit GCM nonce (random)
3. Serialize prescription data to JSON
4. Encrypt with AES-256-GCM → ciphertext + auth tag
5. Load pharmacist X.509 certificate / public key
6. Wrap AES key with RSA-OAEP (pharmacist public key)
7. Hash prescription data with SHA-256
8. Sign hash with doctor RSA-PSS private key
9. Store: encrypted_data, nonce, tag, encrypted_key, signature

### Prescription Decryption (5 Steps)
1. Load pharmacist RSA private key (from HSM/DB)
2. Unwrap AES key with RSA-OAEP (pharmacist private key)
3. Decrypt ciphertext with AES-256-GCM (verifies auth tag)
4. Parse decrypted JSON
5. Verify doctor RSA-PSS signature

---

## 🌍 Community Contributions

Contributions are welcome! Areas for extension:

- **ECC Support** — Add ECDSA/ECDH (secp256r1) as alternative to RSA
- **OCSP** — Replace CRL with Online Certificate Status Protocol
- **True HSM** — Integrate with PKCS#11 hardware tokens (YubiKey, etc.)
- **Certificate Chain** — Implement proper CA hierarchy (Root CA → Intermediate → User)
- **Timestamping** — Add RFC 3161 trusted timestamps to prescriptions

Please follow these contribution steps:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/ECC-support`)
3. Add tests for new functionality
4. Ensure all 24 existing tests pass
5. Submit a Pull Request with description

---

## 📝 Log Files

Generated automatically in the project folder on first run:

| File | Contents |
|------|----------|
| `password_save_process.log` | 5-step PBKDF2 hashing process per user |
| `prescription_encrypt_process.log` | 9-step encryption process per prescription |
| `prescription_decrypt_process.log` | 5-step decryption process per view |
| `complete_process_logs.log` | Combined log of all operations |

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for ST6051CEM Practical Cryptography, Softwarica College of IT & E-Commerce / Coventry University*
