"""
============================================================================
NEPAL E-PRESCRIPTION SYSTEM - Example Usage Scripts
ST6051CEM Practical Cryptography — Open-Source Tool
============================================================================
This script demonstrates all core cryptographic features as standalone
examples WITHOUT needing to run the Flask web server.

Run: python3 example_usage.py
============================================================================
"""
import os, json, base64, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_ser
from datetime import datetime, timedelta, timezone

DIVIDER = "=" * 70

# ─── EXAMPLE 1: RSA Key Generation ──────────────────────────────────────────
def example_key_generation():
    print(f"\n{DIVIDER}")
    print("EXAMPLE 1: RSA-2048 Key Pair Generation")
    print(DIVIDER)

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()

    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    print(f"Key Size:       {private_key.key_size} bits")
    print(f"Algorithm:      RSA")
    print(f"Private Key:    {private_pem[:64]}...")
    print(f"Public Key:     {public_pem[:64]}...")
    print("✅ Unique RSA-2048 key pair generated for user")
    return private_key, public_key


# ─── EXAMPLE 2: X.509 Certificate Generation ────────────────────────────────
def example_certificate_generation(private_key, public_key, username="doctor1", role="doctor"):
    print(f"\n{DIVIDER}")
    print("EXAMPLE 2: X.509 v3 Certificate Generation")
    print(DIVIDER)

    now = datetime.now(timezone.utc)
    serial = int.from_bytes(os.urandom(16), 'big')
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nepal E-Prescription System"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role.capitalize()),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    cert = (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(public_key).serial_number(serial)
        .not_valid_before(now).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(private_key, hashes.SHA256(), default_backend()))

    print(f"Subject CN:     {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"Serial Number:  {format(cert.serial_number, 'x')}")
    print(f"Valid From:     {cert.not_valid_before_utc.strftime('%Y-%m-%d')}")
    print(f"Valid Until:    {cert.not_valid_after_utc.strftime('%Y-%m-%d')}")
    print(f"Algorithm:      RSA-2048 with SHA-256")
    print(f"Key Usage:      Digital Signature, Non-Repudiation, Key Encipherment")
    print("✅ X.509 v3 certificate issued successfully")
    return cert


# ─── EXAMPLE 3: PKCS#12 Keystore Export ─────────────────────────────────────
def example_pkcs12_export(private_key, cert, username="doctor1"):
    print(f"\n{DIVIDER}")
    print("EXAMPLE 3: PKCS#12 Password-Protected Keystore (HSM Simulation)")
    print(DIVIDER)

    password = b"SecureKeystorePass@2026"
    p12_bytes = pkcs12_ser.serialize_key_and_certificates(
        name=username.encode(), key=private_key, cert=cert, cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password))

    print(f"Keystore Size:  {len(p12_bytes)} bytes")
    print(f"Format:         PKCS#12 (.p12)")
    print(f"Encryption:     AES-256-CBC (Best Available)")
    print(f"Password:       [PROTECTED]")
    print(f"Contents:       Private Key + X.509 Certificate")

    # Verify we can re-load it with correct password
    loaded_key, loaded_cert, _ = pkcs12_ser.load_key_and_certificates(
        p12_bytes, password, default_backend())
    print(f"Verification:   Loaded CN = {loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print("✅ PKCS#12 keystore exported and verified")
    return p12_bytes


# ─── EXAMPLE 4: Digital Signatures ──────────────────────────────────────────
def example_digital_signatures(private_key, public_key):
    print(f"\n{DIVIDER}")
    print("EXAMPLE 4: RSA-PSS Digital Signatures")
    print(DIVIDER)

    prescription = json.dumps({
        "prescription_id": "RX-20260222-0001",
        "doctor": "Dr. Rajesh Sharma",
        "patient": "Ram Thapa",
        "medication": "Amoxicillin",
        "dosage": "500mg",
        "created_at": datetime.utcnow().isoformat()
    }, sort_keys=True).encode('utf-8')

    # Sign
    signature = private_key.sign(prescription,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

    print(f"Data Size:      {len(prescription)} bytes")
    print(f"Signature:      {base64.b64encode(signature).decode()[:48]}... ({len(signature)} bytes)")
    print(f"Algorithm:      RSA-PSS with SHA-256, MGF1")

    # Verify — valid
    try:
        public_key.verify(signature, prescription,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        print("✅ Signature VALID — prescription is authentic")
    except Exception as e:
        print(f"❌ Signature invalid: {e}")

    # Simulate MITM: tamper with data
    tampered = prescription.replace(b"Amoxicillin", b"Morphine")
    try:
        public_key.verify(signature, tampered,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        print("❌ SECURITY FAILURE: tampered data accepted")
    except Exception:
        print("✅ MITM ATTACK PREVENTED — tampered prescription rejected")


# ─── EXAMPLE 5: Hybrid Encryption ───────────────────────────────────────────
def example_hybrid_encryption(pharmacist_private_key, pharmacist_public_key):
    print(f"\n{DIVIDER}")
    print("EXAMPLE 5: Hybrid Encryption (AES-256-GCM + RSA-OAEP)")
    print(DIVIDER)

    # Prescription data to encrypt
    plaintext_data = {
        "prescription_id": "RX-20260222-0001",
        "medication": "Amoxicillin 500mg",
        "dosage_instructions": "Take 1 capsule 3x daily for 7 days",
        "doctor": "Dr. Rajesh Sharma",
        "patient": "Ram Thapa"
    }

    # STEP 1: Generate fresh AES-256 session key
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    print(f"AES Session Key: {base64.b64encode(aes_key).decode()[:32]}... (256 bits, fresh per prescription)")

    # STEP 2: Encrypt with AES-256-GCM
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), default_backend()).encryptor()
    ciphertext = encryptor.update(json.dumps(plaintext_data).encode()) + encryptor.finalize()
    tag = encryptor.tag

    # STEP 3: Wrap AES key with pharmacist RSA public key
    encrypted_key = pharmacist_public_key.encrypt(aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    print(f"Encrypted Data: {base64.b64encode(ciphertext).decode()[:48]}... ({len(ciphertext)} bytes)")
    print(f"Encrypted Key:  {base64.b64encode(encrypted_key).decode()[:48]}... ({len(encrypted_key)} bytes)")
    print(f"GCM Auth Tag:   {base64.b64encode(tag).decode()} (16 bytes)")

    # DECRYPT (pharmacist side)
    decrypted_key = pharmacist_private_key.decrypt(encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    decryptor = Cipher(algorithms.AES(decrypted_key), modes.GCM(nonce, tag), default_backend()).decryptor()
    decrypted_data = json.loads(decryptor.update(ciphertext) + decryptor.finalize())

    print(f"Decrypted Med:  {decrypted_data['medication']}")
    print("✅ Hybrid encryption/decryption successful")

    # Demonstrate wrong-key fails
    attacker_key, _ = rsa.generate_private_key(65537, 2048, default_backend()), None
    attacker_priv = attacker_key
    try:
        attacker_priv.decrypt(encrypted_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print("❌ SECURITY FAILURE")
    except Exception:
        print("✅ CONFIDENTIALITY ENFORCED — wrong key cannot decrypt")


# ─── EXAMPLE 6: PBKDF2 Password Hashing ─────────────────────────────────────
def example_password_hashing():
    print(f"\n{DIVIDER}")
    print("EXAMPLE 6: PBKDF2-SHA256 Password Hashing (260,000 iterations)")
    print(DIVIDER)

    import time
    password = "Doctor@123"
    salt = os.urandom(16)

    start = time.time()
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
    key = kdf.derive(password.encode())
    elapsed = time.time() - start

    salt_b64 = base64.b64encode(salt).decode()
    key_b64 = base64.b64encode(key).decode()
    stored_hash = f"pbkdf2:sha256:260000${salt_b64}${key_b64}"

    print(f"Algorithm:      PBKDF2-HMAC-SHA256")
    print(f"Iterations:     260,000 (NIST SP 800-132 recommended)")
    print(f"Salt:           {salt_b64} (16 random bytes)")
    print(f"Derived Key:    {key_b64[:32]}... (256 bits)")
    print(f"Compute Time:   {elapsed:.3f}s (makes brute force expensive)")
    print(f"Stored Format:  pbkdf2:sha256:260000$[salt]$[key]")
    print("✅ Password hashed securely — plain text never stored")


# ─── EXAMPLE 7: Certificate Revocation ──────────────────────────────────────
def example_certificate_revocation(cert):
    print(f"\n{DIVIDER}")
    print("EXAMPLE 7: Certificate Revocation List (CRL) Simulation")
    print(DIVIDER)

    # Simulate CRL as a set of revoked serial numbers
    revoked_serials = set()
    serial_hex = format(cert.serial_number, 'x')

    # Before revocation
    is_revoked_before = serial_hex in revoked_serials
    print(f"Certificate Serial:  {serial_hex}")
    print(f"Before Revocation:   {'REVOKED' if is_revoked_before else 'VALID'}")

    # Revoke (e.g., key compromised)
    revoked_serials.add(serial_hex)
    is_revoked_after = serial_hex in revoked_serials
    print(f"After Revocation:    {'REVOKED' if is_revoked_after else 'VALID'}")
    print(f"CRL Entries:         {len(revoked_serials)}")
    print("✅ Certificate revocation prevents use of compromised keys")


# ─── Main ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(DIVIDER)
    print("  NEPAL E-PRESCRIPTION SYSTEM — CRYPTOGRAPHIC EXAMPLES")
    print("  ST6051CEM Practical Cryptography")
    print(DIVIDER)

    # Generate keys for doctor and pharmacist
    print("\n[SETUP] Generating RSA-2048 key pairs for Doctor and Pharmacist...")
    doctor_priv, doctor_pub = example_key_generation()
    pharmacist_priv, pharmacist_pub = rsa.generate_private_key(65537, 2048, default_backend()), None
    pharmacist_pub = pharmacist_priv.public_key()

    # Generate certificate for doctor
    cert = example_certificate_generation(doctor_priv, doctor_pub, "doctor1", "doctor")

    # PKCS#12 keystore
    example_pkcs12_export(doctor_priv, cert, "doctor1")

    # Digital signatures
    example_digital_signatures(doctor_priv, doctor_pub)

    # Hybrid encryption
    example_hybrid_encryption(pharmacist_priv, pharmacist_pub)

    # Password hashing
    example_password_hashing()

    # Certificate revocation
    example_certificate_revocation(cert)

    print(f"\n{DIVIDER}")
    print("  ALL EXAMPLES COMPLETED SUCCESSFULLY")
    print(f"  Algorithms Demonstrated:")
    print("    RSA-2048, AES-256-GCM, RSA-PSS/SHA-256, RSA-OAEP/MGF1-SHA256")
    print("    X.509 v3, PKCS#12, PBKDF2-SHA256 (260,000 iter), CRL")
    print(DIVIDER)
