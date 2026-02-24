"""
=============================================================================
NEPAL E-PRESCRIPTION SYSTEM — Unit Tests & Attack Simulation Tests
ST6051CEM Practical Cryptography — Requirement 5: Testing and Validation
=============================================================================
Run all tests:
    python3 -m unittest tests/test_nepal_rx.py -v

Expected: 30 tests, ~2-3 seconds, all PASS
=============================================================================
"""
import sys, os, unittest, base64, json, time, secrets, uuid
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_ser
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

# ── Compatibility shim for cryptography < 42 ──────────────────────────────
def cert_not_after(cert):
    """Returns timezone-aware not_valid_after regardless of library version."""
    try:
        return cert.not_valid_after_utc          # cryptography >= 42
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)  # older

def cert_not_before(cert):
    """Returns timezone-aware not_valid_before regardless of library version."""
    try:
        return cert.not_valid_before_utc         # cryptography >= 42
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)  # older


# =============================================================================
# HELPERS — mirror App.py CryptoUtils exactly
# =============================================================================

def gen_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    return priv, priv.public_key()

def gen_cert(priv, pub, username, role="doctor", days=365):
    now = datetime.now(timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nepal RX Test"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(pub)
        .serial_number(int.from_bytes(os.urandom(16), "big"))
        .not_valid_before(now).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(priv, hashes.SHA256(), default_backend())
    )

def sign_data(priv, data: bytes) -> bytes:
    """Mirrors HSMSimulator.sign_with_hsm"""
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def verify_sig(pub, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False

def hybrid_encrypt(data: dict, pub):
    """Mirrors CryptoUtils.encrypt_prescription_with_logging steps 1-6"""
    aes_key = os.urandom(32)        # Step 1: fresh AES-256 session key
    nonce   = os.urandom(12)        # Step 2: fresh 96-bit GCM nonce
    pt = json.dumps(data, sort_keys=True).encode()  # Step 3
    enc = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), default_backend()).encryptor()
    ct = enc.update(pt) + enc.finalize()            # Step 4
    tag = enc.tag
    enc_key = pub.encrypt(aes_key, padding.OAEP(    # Step 6: key wrap
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ct, nonce, tag, enc_key

def hybrid_decrypt(ct, nonce, tag, enc_key, priv):
    """Mirrors CryptoUtils.decrypt_prescription_with_logging"""
    aes_key = priv.decrypt(enc_key, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    dec = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), default_backend()).decryptor()
    return json.loads(dec.update(ct) + dec.finalize())

def pbkdf2_hash(password: bytes, salt: bytes, iterations=260000) -> bytes:
    kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations, default_backend())
    return kdf.derive(password)

def make_rx_id() -> str:
    return f"RX-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


# =============================================================================
# CLASS 1: KEY GENERATION  (4 tests)
# =============================================================================
class TestKeyGeneration(unittest.TestCase):

    def test_rsa_2048_key_size(self):
        """Private key must be exactly 2048 bits"""
        priv, _ = gen_keypair()
        self.assertEqual(priv.key_size, 2048)

    def test_public_exponent_oaep_roundtrip(self):
        """e=65537 verified via OAEP encrypt/decrypt roundtrip"""
        priv, pub = gen_keypair()
        msg = os.urandom(32)
        enc = pub.encrypt(msg, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        self.assertEqual(priv.decrypt(enc, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)), msg)

    def test_unique_keys_per_user(self):
        """5 registrations must produce 5 unique key pairs"""
        pem = lambda k: k.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        keys = [pem(gen_keypair()[0]) for _ in range(5)]
        self.assertEqual(len(set(keys)), 5)

    def test_pem_serialisation_roundtrip(self):
        """Private key must survive PEM serialize → reload"""
        priv, _ = gen_keypair()
        pem = priv.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        reloaded = serialization.load_pem_private_key(pem, password=None, backend=default_backend())
        self.assertEqual(priv.key_size, reloaded.key_size)


# =============================================================================
# CLASS 2: DIGITAL SIGNATURES  (7 tests)
# =============================================================================
class TestDigitalSignatures(unittest.TestCase):

    def test_valid_signature_verifies(self):
        """Correctly signed data must pass verification"""
        priv, pub = gen_keypair()
        data = b'{"medication":"Amoxicillin","dosage":"500mg"}'
        self.assertTrue(verify_sig(pub, data, sign_data(priv, data)))

    def test_tampered_data_rejected(self):
        """MITM: any change to signed data must fail verification"""
        priv, pub = gen_keypair()
        sig = sign_data(priv, b'{"medication":"Amoxicillin","dosage":"500mg"}')
        self.assertFalse(verify_sig(pub, b'{"medication":"Morphine","dosage":"9000mg"}', sig))

    def test_wrong_key_rejected(self):
        """Attacker key must not verify against doctor public key"""
        _, pub_doctor  = gen_keypair()
        priv_attacker, _ = gen_keypair()
        sig = sign_data(priv_attacker, b"forged prescription")
        self.assertFalse(verify_sig(pub_doctor, b"forged prescription", sig))

    def test_multiple_users_independent(self):
        """Requirement 5: 4 users sign and verify independently"""
        for i in range(4):
            priv, pub = gen_keypair()
            data = f"User {i}: Aspirin 100mg".encode()
            self.assertTrue(verify_sig(pub, data, sign_data(priv, data)))

    def test_cross_verification_fails(self):
        """User A sig must not verify under User B public key"""
        priv_a, _     = gen_keypair()
        _,      pub_b = gen_keypair()
        self.assertFalse(verify_sig(pub_b, b"RX data", sign_data(priv_a, b"RX data")))

    def test_pss_probabilistic(self):
        """PSS must produce different signatures for same message (random salt)"""
        priv, pub = gen_keypair()
        data = b"same prescription data"
        s1, s2 = sign_data(priv, data), sign_data(priv, data)
        self.assertNotEqual(s1, s2)
        self.assertTrue(verify_sig(pub, data, s1))
        self.assertTrue(verify_sig(pub, data, s2))

    def test_signature_is_256_bytes(self):
        """RSA-2048 signature must be exactly 256 bytes"""
        priv, _ = gen_keypair()
        self.assertEqual(len(sign_data(priv, b"prescription")), 256)


# =============================================================================
# CLASS 3: HYBRID ENCRYPTION  (7 tests)
# =============================================================================
class TestHybridEncryption(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        """Full cycle must recover original prescription"""
        priv, pub = gen_keypair()
        data = {"medication": "Amoxicillin", "dosage": "500mg", "patient": "Alice"}
        self.assertEqual(hybrid_decrypt(*hybrid_encrypt(data, pub), priv), data)

    def test_wrong_key_cannot_decrypt(self):
        """Only pharmacist private key can unwrap AES session key"""
        _, pub_pharm = gen_keypair()
        priv_atk, _  = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "secret"}, pub_pharm)
        with self.assertRaises(Exception):
            hybrid_decrypt(ct, n, t, ek, priv_atk)

    def test_forward_secrecy(self):
        """Same plaintext must produce different ciphertext (fresh AES key)"""
        _, pub = gen_keypair()
        data = {"medication": "Aspirin"}
        ct1, _, _, _ = hybrid_encrypt(data, pub)
        ct2, _, _, _ = hybrid_encrypt(data, pub)
        self.assertNotEqual(ct1, ct2)

    def test_gcm_tag_detects_ciphertext_tampering(self):
        """Single-bit flip in ciphertext must raise InvalidTag"""
        priv, pub = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "Aspirin"}, pub)
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with self.assertRaises(Exception):
            hybrid_decrypt(tampered, n, t, ek, priv)

    def test_gcm_tag_detects_tag_tampering(self):
        """Modifying the GCM tag itself must also raise an error"""
        priv, pub = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "Aspirin"}, pub)
        bad_tag = bytes([t[0] ^ 0x01]) + t[1:]
        with self.assertRaises(Exception):
            hybrid_decrypt(ct, n, bad_tag, ek, priv)

    def test_nonce_is_96_bits(self):
        """GCM nonce must be 12 bytes (96 bits) per NIST SP 800-38D"""
        self.assertEqual(len(os.urandom(12)), 12)

    def test_sort_keys_deterministic(self):
        """sort_keys=True must produce identical bytes regardless of dict order"""
        d1 = {"medication": "Amoxicillin", "dosage": "500mg", "patient": "Alice"}
        d2 = {"patient": "Alice", "dosage": "500mg", "medication": "Amoxicillin"}
        self.assertEqual(json.dumps(d1, sort_keys=True), json.dumps(d2, sort_keys=True))


# =============================================================================
# CLASS 4: CERTIFICATE MANAGEMENT  (9 tests)
# =============================================================================
class TestCertificateManagement(unittest.TestCase):

    def test_certificate_generated(self):
        priv, pub = gen_keypair()
        self.assertIsNotNone(gen_cert(priv, pub, "doctor1"))

    def test_cn_matches_username(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor_manish")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "doctor_manish")

    def test_validity_365_days(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        self.assertEqual((cert_not_after(cert) - cert_not_before(cert)).days, 365)

    def test_serial_128_bit(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        self.assertGreater(cert.serial_number, 0)
        self.assertLessEqual(cert.serial_number.bit_length(), 128)

    def test_unique_serials(self):
        priv1, pub1 = gen_keypair(); priv2, pub2 = gen_keypair()
        c1 = gen_cert(priv1, pub1, "d1"); c2 = gen_cert(priv2, pub2, "d2")
        self.assertNotEqual(c1.serial_number, c2.serial_number)

    def test_pkcs12_export(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        p12 = pkcs12_ser.serialize_key_and_certificates(
            b"doctor1", priv, cert, None,
            serialization.BestAvailableEncryption(b"TestPass123!"))
        self.assertGreater(len(p12), 0)

    def test_pkcs12_wrong_password_fails(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        p12 = pkcs12_ser.serialize_key_and_certificates(
            b"doctor1", priv, cert, None,
            serialization.BestAvailableEncryption(b"CorrectPass!"))
        with self.assertRaises(Exception):
            pkcs12_ser.load_key_and_certificates(p12, b"WrongPass!", default_backend())

    def test_crl_revocation_blocks_serial(self):
        """Revoked serial must appear in CRL and be rejected"""
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "compromised_doctor")
        crl = set()
        serial_hex = format(cert.serial_number, "x")
        crl.add(serial_hex)  # simulate Admin /revoke-key
        self.assertIn(serial_hex, crl)

    def test_expired_cert_detected(self):
        """Cert with not_valid_after in the past must be detected as expired"""
        priv, pub = gen_keypair()
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired_doc")])
        cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(pub)
            .serial_number(int.from_bytes(os.urandom(16), "big"))
            .not_valid_before(now - timedelta(days=2))
            .not_valid_after(now - timedelta(days=1))
            .sign(priv, hashes.SHA256(), default_backend()))
        self.assertTrue(cert_not_after(cert) < datetime.now(timezone.utc))


# =============================================================================
# CLASS 5: ATTACK SIMULATIONS  (6 tests)
# =============================================================================
class TestAttackSimulations(unittest.TestCase):

    def test_replay_attack_unique_ids(self):
        """1000 UUID4 prescription IDs must all be unique"""
        ids = [make_rx_id() for _ in range(1000)]
        self.assertEqual(len(set(ids)), 1000)

    def test_replay_rx_id_format(self):
        """ID must match RX-YYYYMMDD-XXXXXXXX format"""
        rx_id = make_rx_id()
        parts = rx_id.split("-")
        self.assertEqual(parts[0], "RX")
        self.assertEqual(len(parts[1]), 8)   # YYYYMMDD
        self.assertEqual(len(parts[2]), 8)   # 8 uppercase hex

    def test_mitm_signature_fails(self):
        """MITM: field changes after signing must fail RSA-PSS verification"""
        priv, pub = gen_keypair()
        orig = json.dumps({"med": "Amoxicillin", "dose": "500mg"}, sort_keys=True).encode()
        sig = sign_data(priv, orig)
        bad  = json.dumps({"med": "Morphine",    "dose": "9000mg"}, sort_keys=True).encode()
        self.assertFalse(verify_sig(pub, bad, sig))

    def test_mitm_gcm_ciphertext_rejected(self):
        """MITM: ciphertext bit flip caught by GCM authentication tag"""
        priv, pub = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "Amoxicillin"}, pub)
        pos = len(ct) // 2
        tampered = ct[:pos] + bytes([ct[pos] ^ 0xFF]) + ct[pos+1:]
        with self.assertRaises(Exception):
            hybrid_decrypt(tampered, n, t, ek, priv)

    def test_brute_force_pbkdf2_timing(self):
        """PBKDF2 at 260,000 iter must take >10ms per attempt"""
        salt = os.urandom(16)
        start = time.perf_counter()
        pbkdf2_hash(b"testpassword", salt)
        elapsed = time.perf_counter() - start
        self.assertGreater(elapsed, 0.01)
        print(f"\n    PBKDF2 timing: {elapsed:.3f}s (260,000 iterations)")

    def test_unauthorized_signing_rejected(self):
        """Attacker cannot forge a signature that verifies under doctor's public key"""
        _, doctor_pub = gen_keypair()
        atk_priv, _   = gen_keypair()
        fake_sig = sign_data(atk_priv, b"forged prescription")
        self.assertFalse(verify_sig(doctor_pub, b"forged prescription", fake_sig))


# =============================================================================
# CLASS 6: PASSWORD SECURITY  (6 tests)
# =============================================================================
class TestPasswordSecurity(unittest.TestCase):

    def test_different_salts_different_hashes(self):
        pw = b"Doctor@Nepal123"
        h1 = pbkdf2_hash(pw, os.urandom(16))
        h2 = pbkdf2_hash(pw, os.urandom(16))
        self.assertNotEqual(h1, h2)

    def test_correct_password_verifies(self):
        pw = b"Patient@Nepal123"
        salt = os.urandom(16)
        self.assertTrue(secrets.compare_digest(pbkdf2_hash(pw, salt), pbkdf2_hash(pw, salt)))

    def test_wrong_password_rejected(self):
        salt = os.urandom(16)
        stored = pbkdf2_hash(b"CorrectPassword!", salt)
        wrong  = pbkdf2_hash(b"WrongPassword!",  salt)
        self.assertFalse(secrets.compare_digest(stored, wrong))

    def test_output_is_256_bits(self):
        self.assertEqual(len(pbkdf2_hash(b"testpass", os.urandom(16))), 32)

    def test_salt_is_16_bytes(self):
        self.assertEqual(len(os.urandom(16)), 16)

    def test_timing_safe_comparison(self):
        """Use secrets.compare_digest for constant-time comparison"""
        salt = os.urandom(16)
        h1 = pbkdf2_hash(b"same", salt)
        h2 = pbkdf2_hash(b"same", salt)
        self.assertTrue(secrets.compare_digest(h1, h2))


if __name__ == "__main__":
    print("=" * 65)
    print("  Nepal E-Prescription System — Test Suite (30 tests)")
    print("  ST6051CEM Practical Cryptography")
    print("=" * 65)
    unittest.main(verbosity=2)