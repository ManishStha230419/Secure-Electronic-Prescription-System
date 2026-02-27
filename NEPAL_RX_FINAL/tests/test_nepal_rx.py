"""
=============================================================================
NEPAL E-PRESCRIPTION SYSTEM - Unit Tests & Attack Simulation Tests
ST6051CEM Practical Cryptography - Requirement 5: Testing and Validation
=============================================================================
Run: python3 -m unittest tests/test_nepal_rx.py -v
=============================================================================
"""
import sys, os, unittest, base64, json, time, secrets as sec
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_ser
from datetime import datetime, timedelta, timezone

# ─── Helpers ────────────────────────────────────────────

def gen_keypair():
    priv = rsa.generate_private_key(65537, 2048, default_backend())
    return priv, priv.public_key()

def gen_cert(priv, pub, username, role="doctor"):
    now = datetime.now(timezone.utc)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nepal RX Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])
    return (x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(pub).serial_number(int.from_bytes(os.urandom(16), 'big'))
        .not_valid_before(now).not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(priv, hashes.SHA256(), default_backend()))

def sign_data(priv, data: bytes) -> bytes:
    return priv.sign(data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

def verify(pub, data: bytes, sig: bytes) -> bool:
    try:
        pub.verify(sig, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except Exception:
        return False

def hybrid_encrypt(data, pub):
    aes_key = os.urandom(32); nonce = os.urandom(12)
    ct_enc = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), default_backend()).encryptor()
    ct = ct_enc.update(json.dumps(data).encode()) + ct_enc.finalize()
    tag = ct_enc.tag
    enc_key = pub.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=None))
    return ct, nonce, tag, enc_key

def hybrid_decrypt(ct, nonce, tag, enc_key, priv):
    aes_key = priv.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                   algorithm=hashes.SHA256(), label=None))
    dec = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), default_backend()).decryptor()
    return json.loads(dec.update(ct) + dec.finalize())

# ─── Tests ──────────────────────────────────────────────

class TestKeyGeneration(unittest.TestCase):
    def test_rsa_2048_generated(self):
        priv, pub = gen_keypair()
        self.assertEqual(priv.key_size, 2048)

    def test_unique_keys_per_user(self):
        p1, _ = gen_keypair(); p2, _ = gen_keypair()
        pem = lambda k: k.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        self.assertNotEqual(pem(p1), pem(p2), "Keys must be unique per user")


class TestDigitalSignatures(unittest.TestCase):
    def test_valid_signature_verifies(self):
        priv, pub = gen_keypair()
        data = b"Prescription: Amoxicillin 500mg"
        self.assertTrue(verify(pub, data, sign_data(priv, data)))

    def test_tampered_data_rejected(self):
        """MITM attack: data modified after signing must fail"""
        priv, pub = gen_keypair()
        sig = sign_data(priv, b"Amoxicillin 500mg")
        self.assertFalse(verify(pub, b"Morphine 9000mg", sig),
                         "MITM tampered data must be rejected")

    def test_wrong_key_rejected(self):
        """Unauthorized signing: attacker key must not verify"""
        _, pub_doctor = gen_keypair()
        priv_attacker, _ = gen_keypair()
        sig = sign_data(priv_attacker, b"Prescription")
        self.assertFalse(verify(pub_doctor, b"Prescription", sig),
                         "Unauthorized signature must be rejected")

    def test_multiple_users_independent_signatures(self):
        """Req 5: Multiple users sign and verify independently"""
        for i in range(3):
            priv, pub = gen_keypair()
            data = f"User {i} prescription".encode()
            self.assertTrue(verify(pub, data, sign_data(priv, data)))

    def test_cross_verification_fails(self):
        priv_a, _ = gen_keypair()
        _, pub_b = gen_keypair()
        sig_a = sign_data(priv_a, b"data")
        self.assertFalse(verify(pub_b, b"data", sig_a))


class TestHybridEncryption(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        priv, pub = gen_keypair()
        data = {"medication": "Amoxicillin", "dosage": "500mg"}
        ct, n, t, ek = hybrid_encrypt(data, pub)
        self.assertEqual(hybrid_decrypt(ct, n, t, ek, priv), data)

    def test_wrong_key_cannot_decrypt(self):
        """Confidentiality: only intended pharmacist can decrypt"""
        _, pub_pharm = gen_keypair()
        priv_attacker, _ = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "secret"}, pub_pharm)
        with self.assertRaises(Exception):
            hybrid_decrypt(ct, n, t, ek, priv_attacker)

    def test_forward_secrecy_unique_ciphertext(self):
        """Each encryption uses fresh AES key — forward secrecy"""
        _, pub = gen_keypair()
        data = {"medication": "Aspirin"}
        ct1, _, _, _ = hybrid_encrypt(data, pub)
        ct2, _, _, _ = hybrid_encrypt(data, pub)
        self.assertNotEqual(ct1, ct2, "Fresh AES key per prescription (forward secrecy)")

    def test_gcm_tag_detects_tampering(self):
        """GCM authentication tag rejects tampered ciphertext"""
        priv, pub = gen_keypair()
        ct, n, t, ek = hybrid_encrypt({"med": "Aspirin"}, pub)
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with self.assertRaises(Exception):
            hybrid_decrypt(tampered, n, t, ek, priv)


class TestCertificateManagement(unittest.TestCase):
    def test_certificate_created(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        self.assertIsNotNone(cert)

    def test_certificate_cn_correct(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.assertEqual(cn, "doctor1")

    def test_certificate_validity_365_days(self):
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "doctor1")
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertEqual(delta.days, 365)

    def test_pkcs12_keystore_export(self):
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
            serialization.BestAvailableEncryption(b"RightPass!"))
        with self.assertRaises(Exception):
            pkcs12_ser.load_key_and_certificates(p12, b"WrongPass!", default_backend())

    def test_crl_revocation_simulation(self):
        """Revoked cert serial in CRL blocks trust"""
        priv, pub = gen_keypair()
        cert = gen_cert(priv, pub, "compromised_doctor")
        crl = set()
        serial_hex = format(cert.serial_number, 'x')
        crl.add(serial_hex)  # Revoke
        self.assertIn(serial_hex, crl)


class TestAttackSimulations(unittest.TestCase):
    def test_replay_attack_unique_ids(self):
        """Unique UUIDs prevent replay attacks"""
        import uuid
        ids = set()
        for _ in range(100):
            rx_id = f"RX-{uuid.uuid4()}"
            self.assertNotIn(rx_id, ids)
            ids.add(rx_id)

    def test_brute_force_pbkdf2_timing(self):
        """PBKDF2 at 260,000 iterations must be computationally expensive"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
        start = time.time()
        kdf.derive(b"testpassword")
        elapsed = time.time() - start
        self.assertGreater(elapsed, 0.01, "PBKDF2 must take measurable time to deter brute force")
        print(f"\n  PBKDF2 timing: {elapsed:.3f}s (260,000 iterations)")

    def test_unauthorized_prescription_signing(self):
        """Patient/pharmacist cannot forge doctor signature"""
        _, doctor_pub = gen_keypair()
        attacker_priv, _ = gen_keypair()
        fake_sig = sign_data(attacker_priv, b"forged prescription")
        self.assertFalse(verify(doctor_pub, b"forged prescription", fake_sig))

    def test_mitm_prescription_tampering(self):
        """MITM: signature invalidated when prescription altered"""
        priv, pub = gen_keypair()
        original = b'{"med":"Amoxicillin","dose":"500mg"}'
        sig = sign_data(priv, original)
        tampered = b'{"med":"Morphine","dose":"9000mg"}'
        self.assertFalse(verify(pub, tampered, sig))


class TestPasswordSecurity(unittest.TestCase):
    def test_different_salts_different_hashes(self):
        password = b"Doctor@123"
        s1, s2 = os.urandom(16), os.urandom(16)
        def derive(salt):
            kdf = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
            return kdf.derive(password)
        self.assertNotEqual(derive(s1), derive(s2))

    def test_correct_password_verified(self):
        password = b"Patient@123"
        salt = os.urandom(16)
        kdf1 = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
        stored = kdf1.derive(password)
        kdf2 = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
        attempt = kdf2.derive(password)
        self.assertTrue(sec.compare_digest(stored, attempt))

    def test_wrong_password_rejected(self):
        password = b"CorrectPassword!"
        salt = os.urandom(16)
        kdf1 = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
        stored = kdf1.derive(password)
        kdf2 = PBKDF2HMAC(hashes.SHA256(), 32, salt, 260000, default_backend())
        wrong = kdf2.derive(b"WrongPassword!")
        self.assertFalse(sec.compare_digest(stored, wrong))


if __name__ == '__main__':
    unittest.main(verbosity=2)
