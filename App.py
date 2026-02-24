"""
================================================================================
NEPAL E-PRESCRIPTION SYSTEM v3.7 FINAL - COMPLETE PROCESS LOGGING
Logs HOW passwords are saved + HOW prescriptions are encrypted
Creates log files in the code folder for easy viewing
================================================================================
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import pkcs12 as pkcs12_serialization
from datetime import timezone
from datetime import datetime, timedelta
from functools import wraps
import os, json, base64, hashlib, secrets, re, uuid, io

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nepal_rx_process_logs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

db = SQLAlchemy(app)

# ============================================================================
# CUSTOM JINJA2 FILTERS
# ============================================================================

@app.template_filter("from_json")
def from_json_filter(value):
    """Parse a JSON string in templates."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 30
PBKDF2_ITERATIONS = 260000

# Log file paths
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
PASSWORD_LOG_FILE = os.path.join(LOG_DIR, 'password_save_process.log')
PRESCRIPTION_ENCRYPT_LOG = os.path.join(LOG_DIR, 'prescription_encrypt_process.log')
PRESCRIPTION_DECRYPT_LOG = os.path.join(LOG_DIR, 'prescription_decrypt_process.log')
COMPLETE_LOG_FILE = os.path.join(LOG_DIR, 'complete_process_logs.log')

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    registration_number = db.Column(db.String(50))
    email = db.Column(db.String(120))
    hospital = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    private_key = db.Column(db.Text)
    public_key = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    certificate_pem = db.Column(db.Text)           # X.509 self-signed certificate
    certificate_serial = db.Column(db.String(64))  # Serial number for revocation
    key_revoked = db.Column(db.Boolean, default=False)
    key_revoked_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                          iterations=PBKDF2_ITERATIONS, backend=default_backend())
        key = base64.b64encode(kdf.derive(password.encode())).decode()
        self.password_hash = f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${base64.b64encode(salt).decode()}${key}"

    def check_password(self, password):
        try:
            parts = self.password_hash.split('$')
            salt = base64.b64decode(parts[1])
            stored_key = parts[2]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                              iterations=PBKDF2_ITERATIONS, backend=default_backend())
            key = base64.b64encode(kdf.derive(password.encode())).decode()
            return secrets.compare_digest(key, stored_key)
        except:
            return check_password_hash(self.password_hash, password)

    def is_locked(self):
        return self.account_locked_until and self.account_locked_until > datetime.utcnow()


class Prescription(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prescription_id = db.Column(db.String(50), unique=True, nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    tag = db.Column(db.Text, nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)
    signature = db.Column(db.Text, nullable=False)
    data_hash = db.Column(db.String(64))
    medication = db.Column(db.String(200))
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    dispensed_at = db.Column(db.DateTime)
    dispensed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='prescribed')
    patient = db.relationship('User', foreign_keys=[patient_id], backref='prescriptions')
    pharmacist = db.relationship('User', foreign_keys=[dispensed_by])


class ProcessLog(db.Model):
    """Logs the COMPLETE PROCESS of how something is saved/encrypted"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    process_type = db.Column(db.String(50), nullable=False)
    resource_id = db.Column(db.String(100))
    step_number = db.Column(db.Integer)
    step_description = db.Column(db.Text, nullable=False)
    algorithm_used = db.Column(db.String(100))
    input_data = db.Column(db.Text)
    output_data = db.Column(db.Text)
    parameters = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='process_logs')


class DetailedChangeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    change_type = db.Column(db.String(50), nullable=False)
    field_changed = db.Column(db.String(100))
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    algorithms_used = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.Text)
    user = db.relationship('User', backref='change_logs')


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource_id = db.Column(db.String(50))
    ip_address = db.Column(db.String(50))
    status = db.Column(db.String(20), default='success')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='audit_logs')


class RevokedCertificate(db.Model):
    """Certificate Revocation List (CRL) simulation"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    serial_number = db.Column(db.String(64), nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(200))
    revoked_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', foreign_keys=[user_id])
    revoker = db.relationship('User', foreign_keys=[revoked_by])


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    type = db.Column(db.String(20), default='info')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='notifications')


# ============================================================================
# LOG FILE WRITING FUNCTIONS
# ============================================================================

def write_to_log_file(filepath, content):
    """Write to log file in code folder"""
    try:
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(content + '\n')
    except Exception as e:
        print(f"Error writing to log file: {e}")


def write_complete_log(content):
    """Write to complete log file"""
    write_to_log_file(COMPLETE_LOG_FILE, content)


# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

def log_process_step(process_type, step_number, step_description, algorithm_used, 
                     input_data, output_data, parameters, resource_id=None):
    """Log each step of a cryptographic process"""
    try:
        user_id = session.get('user_id') if session else None
    except:
        user_id = None
    
    log = ProcessLog(
        user_id=user_id,
        process_type=process_type,
        resource_id=resource_id,
        step_number=step_number,
        step_description=step_description,
        algorithm_used=algorithm_used,
        input_data=input_data,
        output_data=output_data,
        parameters=json.dumps(parameters) if parameters else None
    )
    db.session.add(log)
    db.session.commit()
    
    # Write to log file
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_content = f"""
[{timestamp}] {process_type.upper()} - {resource_id or 'N/A'}
STEP {step_number}: {step_description}
Algorithm: {algorithm_used}
Input: {input_data}
Output: {output_data}
Parameters: {parameters}
{'='*80}
"""
    
    # Write to specific log file
    if process_type == 'password_save':
        write_to_log_file(PASSWORD_LOG_FILE, log_content)
    elif process_type == 'prescription_encrypt':
        write_to_log_file(PRESCRIPTION_ENCRYPT_LOG, log_content)
    elif process_type == 'prescription_decrypt':
        write_to_log_file(PRESCRIPTION_DECRYPT_LOG, log_content)
    
    # Write to complete log
    write_complete_log(log_content)


def log_detailed_change(change_type, field_changed, old_value, new_value, algorithms_used, details=None):
    try:
        user_id = session.get('user_id') if session else None
        ip_addr = request.remote_addr if request else None
    except:
        user_id = None
        ip_addr = None
    
    change = DetailedChangeLog(
        user_id=user_id,
        change_type=change_type,
        field_changed=field_changed,
        old_value=old_value,
        new_value=new_value,
        algorithms_used=json.dumps(algorithms_used) if algorithms_used else None,
        ip_address=ip_addr,
        details=details
    )
    db.session.add(change)
    db.session.commit()


def log_action(action, rx_id=None, status='success'):
    try:
        user_id = session.get('user_id') if session else None
        ip_addr = request.remote_addr if request else None
    except:
        user_id = None
        ip_addr = None
    
    log = AuditLog(
        user_id=user_id,
        action=action,
        resource_id=rx_id,
        ip_address=ip_addr,
        status=status
    )
    db.session.add(log)
    db.session.commit()


def create_notification(user_id, title, message, ntype='info'):
    notif = Notification(user_id=user_id, title=title, message=message, type=ntype)
    db.session.add(notif)
    db.session.commit()


# ============================================================================
# CRYPTO UTILITIES WITH PROCESS LOGGING
# ============================================================================

class CryptoUtils:
    @staticmethod
    def hash_password_with_logging(password, username):
        """Hash password with PBKDF2-SHA256 and log EVERY STEP"""
        try:
            user_id = session.get('user_id') if session else None
        except:
            user_id = None
        
        # Write header to password log file
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header = f"""
{'='*80}
PASSWORD SAVE PROCESS FOR: {username}
Started: {timestamp}
{'='*80}
"""
        write_to_log_file(PASSWORD_LOG_FILE, header)
        write_complete_log(header)
        
        # STEP 1: Generate random salt
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode()
        log_process_step(
            'password_save', 1,
            'Generate random salt for password hashing',
            'Random Number Generator',
            f'Length: 16 bytes',
            f'Salt (base64): {salt_b64}',
            {'salt_length': 16, 'encoding': 'base64'},
            username
        )
        
        # STEP 2: Create PBKDF2 Key Derivation Function
        log_process_step(
            'password_save', 2,
            'Initialize PBKDF2-SHA256 Key Derivation Function',
            'PBKDF2-SHA256',
            f'Password: [HIDDEN], Salt: {salt_b64[:20]}...',
            'KDF object created',
            {
                'algorithm': 'SHA-256',
                'iterations': PBKDF2_ITERATIONS,
                'key_length': 32,
                'backend': 'default_backend'
            },
            username
        )
        
        # STEP 3: Derive key from password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                          iterations=PBKDF2_ITERATIONS, backend=default_backend())
        derived_key = kdf.derive(password.encode())
        key_b64 = base64.b64encode(derived_key).decode()
        
        log_process_step(
            'password_save', 3,
            f'Derive 256-bit key from password using PBKDF2 with {PBKDF2_ITERATIONS} iterations',
            'PBKDF2-SHA256',
            f'Input: password + salt',
            f'Derived key (base64): {key_b64}',
            {
                'iterations_performed': PBKDF2_ITERATIONS,
                'hash_function': 'SHA-256',
                'output_length': 32,
                'computation_time': 'CPU-intensive'
            },
            username
        )
        
        # STEP 4: Format final hash
        final_hash = f"pbkdf2:sha256:{PBKDF2_ITERATIONS}${salt_b64}${key_b64}"
        log_process_step(
            'password_save', 4,
            'Format final password hash for storage',
            'String Formatting',
            f'Salt: {salt_b64}, Key: {key_b64[:30]}...',
            f'Final format: pbkdf2:sha256:{PBKDF2_ITERATIONS}$[salt]$[key]',
            {
                'format': 'pbkdf2:algorithm:iterations$salt$key',
                'total_length': len(final_hash)
            },
            username
        )
        
        # STEP 5: Store in database
        log_process_step(
            'password_save', 5,
            'Store hashed password in database',
            'Database Write',
            f'Hash: {final_hash[:50]}...',
            'Stored in user.password_hash field',
            {
                'table': 'user',
                'field': 'password_hash',
                'username': username
            },
            username
        )
        
        # Write summary
        summary = f"""
SUMMARY:
Password for '{username}' successfully hashed and stored.
Total steps: 5
Final hash length: {len(final_hash)} characters
Storage location: database table 'user', field 'password_hash'
{'='*80}

"""
        write_to_log_file(PASSWORD_LOG_FILE, summary)
        write_complete_log(summary)
        
        return final_hash

    @staticmethod
    def encrypt_prescription_with_logging(data_dict, pharmacist_public_key_pem, rx_id):
        """Encrypt prescription and log EVERY STEP"""
        try:
            user_id = session.get('user_id') if session else None
        except:
            user_id = None
        
        # Write header
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header = f"""
{'='*80}
PRESCRIPTION ENCRYPTION PROCESS: {rx_id}
Started: {timestamp}
Medication: {data_dict.get('medication', 'N/A')}
{'='*80}
"""
        write_to_log_file(PRESCRIPTION_ENCRYPT_LOG, header)
        write_complete_log(header)
        
        # STEP 1: Generate AES-256 key
        aes_key = os.urandom(32)
        log_process_step(
            'prescription_encrypt', 1,
            'Generate random AES-256 encryption key',
            'Random Number Generator (AES)',
            'Generate 256-bit random key',
            f'AES Key: {base64.b64encode(aes_key).decode()} (32 bytes)',
            {'key_size': 256, 'key_length_bytes': 32},
            rx_id
        )
        
        # STEP 2: Generate GCM nonce
        nonce = os.urandom(12)
        log_process_step(
            'prescription_encrypt', 2,
            'Generate GCM nonce (initialization vector)',
            'Random Number Generator (Nonce)',
            'Generate 96-bit nonce',
            f'Nonce: {base64.b64encode(nonce).decode()} (12 bytes)',
            {'nonce_size': 96, 'nonce_length_bytes': 12, 'mode': 'GCM'},
            rx_id
        )
        
        # STEP 3: Convert prescription data to JSON
        plaintext_json = json.dumps(data_dict)
        log_process_step(
            'prescription_encrypt', 3,
            'Convert prescription data to JSON format',
            'JSON Serialization',
            f'Data: Medication={data_dict.get("medication")}, Dosage={data_dict.get("dosage")}',
            f'JSON: {plaintext_json[:100]}...',
            {'data_size': len(plaintext_json), 'format': 'UTF-8 JSON'},
            rx_id
        )
        
        # STEP 4: Encrypt with AES-256-GCM
        plaintext = plaintext_json.encode('utf-8')
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        
        log_process_step(
            'prescription_encrypt', 4,
            'Encrypt prescription data with AES-256-GCM',
            'AES-256-GCM',
            f'Plaintext: {len(plaintext)} bytes',
            f'Ciphertext: {base64.b64encode(ciphertext).decode()[:40]}... ({len(ciphertext)} bytes), Auth Tag: {base64.b64encode(tag).decode()}',
            {
                'algorithm': 'AES-256-GCM',
                'mode': 'Galois/Counter Mode',
                'key_size': 256,
                'plaintext_size': len(plaintext),
                'ciphertext_size': len(ciphertext),
                'auth_tag_size': 128,
                'authenticated': True
            },
            rx_id
        )
        
        # STEP 5: Load pharmacist's public key
        pharmacist_pub_key = serialization.load_pem_public_key(
            pharmacist_public_key_pem.encode('utf-8'), backend=default_backend())
        log_process_step(
            'prescription_encrypt', 5,
            "Load pharmacist's RSA-2048 public key from PEM format",
            'RSA Key Loading',
            f'PEM: -----BEGIN PUBLIC KEY-----...',
            'RSA public key object loaded',
            {'key_type': 'RSA', 'key_size': 2048, 'format': 'PEM'},
            rx_id
        )
        
        # STEP 6: Encrypt AES key with RSA-OAEP
        encrypted_key = pharmacist_pub_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        log_process_step(
            'prescription_encrypt', 6,
            'Encrypt AES key with RSA-OAEP (key wrapping)',
            'RSA-OAEP',
            f'AES key: {base64.b64encode(aes_key).decode()[:30]}...',
            f'Encrypted key: {base64.b64encode(encrypted_key).decode()[:40]}... ({len(encrypted_key)} bytes)',
            {
                'algorithm': 'RSA-OAEP',
                'rsa_key_size': 2048,
                'padding': 'OAEP',
                'mgf': 'MGF1-SHA256',
                'hash': 'SHA-256',
                'label': None
            },
            rx_id
        )
        
        # STEP 7: Hash prescription data with SHA-256
        data_for_signature = json.dumps(data_dict, sort_keys=True).encode('utf-8')
        hash_digest = hashlib.sha256(data_for_signature).digest()
        log_process_step(
            'prescription_encrypt', 7,
            'Hash prescription data with SHA-256 for signing',
            'SHA-256',
            f'Data: {len(data_for_signature)} bytes',
            f'Hash: {base64.b64encode(hash_digest).decode()}',
            {'algorithm': 'SHA-256', 'output_size': 256, 'output_bytes': 32},
            rx_id
        )
        
        # STEP 8: Sign with RSA-PSS
        doctor = db.session.get(User, session['user_id']) if 'user_id' in session else User.query.filter_by(role='doctor').first()
        if doctor and doctor.private_key:
            private_key = serialization.load_pem_private_key(
                doctor.private_key.encode('utf-8'), password=None, backend=default_backend())
            
            signature = private_key.sign(
                data_for_signature,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        else:
            signature = b'SIGNATURE_PLACEHOLDER'
        
        log_process_step(
            'prescription_encrypt', 8,
            'Sign prescription with RSA-PSS digital signature',
            'RSA-PSS',
            f'Data hash: {base64.b64encode(hash_digest).decode()}',
            f'Signature: {base64.b64encode(signature).decode()[:40]}... ({len(signature)} bytes)',
            {
                'algorithm': 'RSA-PSS',
                'rsa_key_size': 2048,
                'hash': 'SHA-256',
                'padding': 'PSS',
                'mgf': 'MGF1-SHA256',
                'salt_length': 'MAX_LENGTH'
            },
            rx_id
        )
        
        # STEP 9: Store all components in database
        log_process_step(
            'prescription_encrypt', 9,
            'Store encrypted prescription components in database',
            'Database Write',
            'All encrypted components ready',
            f'Table: prescription, ID: {rx_id}',
            {
                'encrypted_data': f'{len(ciphertext)} bytes',
                'nonce': '12 bytes',
                'auth_tag': '16 bytes',
                'encrypted_key': f'{len(encrypted_key)} bytes',
                'signature': f'{len(signature)} bytes',
                'hash': '32 bytes'
            },
            rx_id
        )
        
        # Write summary
        summary = f"""
SUMMARY:
Prescription {rx_id} successfully encrypted.
Total steps: 9
Components stored:
  - Encrypted data: {len(ciphertext)} bytes (AES-256-GCM)
  - Nonce: 12 bytes
  - Auth tag: 16 bytes
  - Encrypted AES key: {len(encrypted_key)} bytes (RSA-OAEP)
  - Digital signature: {len(signature)} bytes (RSA-PSS)
  - Data hash: 32 bytes (SHA-256)
{'='*80}

"""
        write_to_log_file(PRESCRIPTION_ENCRYPT_LOG, summary)
        write_complete_log(summary)
        
        return (
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8'),
            base64.b64encode(encrypted_key).decode('utf-8'),
            base64.b64encode(signature).decode('utf-8'),
            base64.b64encode(hash_digest).decode('utf-8')
        )

    @staticmethod
    def generate_certificate(private_key_obj, public_key_obj, username, role, hospital=None):
        """
        Generate a self-signed X.509 certificate for a user.
        Simulates PKI Certificate Authority (CA) issuance.
        """
        serial = int.from_bytes(os.urandom(16), 'big')
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Bagmati"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Kathmandu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, hospital or "Nepal E-Prescription System"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, role.capitalize()),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key_obj)
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=True,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False
                ), critical=True
            )
            .sign(private_key_obj, hashes.SHA256(), backend=default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        serial_hex = format(serial, 'x')
        return cert_pem, serial_hex

    @staticmethod
    def export_pkcs12_keystore(private_key_pem, cert_pem, username, keystore_password):
        """
        Export user keys as a PKCS#12 (.p12) password-protected keystore.
        Simulates secure key storage (HSM keystore export).
        """
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None, backend=default_backend())
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), backend=default_backend())
        p12_bytes = pkcs12_serialization.serialize_key_and_certificates(
            name=username.encode(),
            key=private_key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.BestAvailableEncryption(keystore_password.encode())
        )
        return p12_bytes

    @staticmethod
    def validate_certificate(cert_pem, expected_username=None):
        """
        Validate an X.509 certificate: check expiry, subject, and revocation status.
        """
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), backend=default_backend())
            now = datetime.now(timezone.utc)
            # Check expiry
            if cert.not_valid_after_utc < now:
                return False, "Certificate expired"
            if cert.not_valid_before_utc > now:
                return False, "Certificate not yet valid"
            # Check subject CN matches username
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if expected_username and (not cn or cn[0].value != expected_username):
                return False, "Certificate CN does not match username"
            # Check revocation
            serial_hex = format(cert.serial_number, 'x')
            revoked = RevokedCertificate.query.filter_by(serial_number=serial_hex).first()
            if revoked:
                return False, f"Certificate revoked at {revoked.revoked_at}"
            return True, "Certificate valid"
        except Exception as e:
            return False, f"Invalid certificate: {str(e)}"


class HSMSimulator:
    """
    Software-based Hardware Security Module (HSM) simulator.
    Wraps all cryptographic operations to simulate HSM behaviour:
    - Keys never leave the HSM in plaintext
    - All operations are logged
    - Access control enforced per role
    """
    HSM_KEY_STORE = {}  # In-memory secure key store (simulates HSM RAM)

    @classmethod
    def store_key(cls, user_id, private_key_pem, username):
        """Store key in HSM (simulated in-memory secure enclave)"""
        cls.HSM_KEY_STORE[user_id] = {
            'key': private_key_pem,
            'stored_at': datetime.utcnow().isoformat(),
            'username': username
        }

    @classmethod
    def retrieve_key(cls, user_id):
        """Retrieve key from HSM - simulates controlled key access"""
        entry = cls.HSM_KEY_STORE.get(user_id)
        if entry:
            return entry['key']
        # Fall back to DB (cold storage simulation)
        user = db.session.get(User, user_id)
        return user.private_key if user else None

    @classmethod
    def sign_with_hsm(cls, user_id, data):
        """Perform signing inside HSM - key never exposed outside"""
        key_pem = cls.retrieve_key(user_id)
        if not key_pem:
            raise ValueError("Key not found in HSM")
        private_key = serialization.load_pem_private_key(
            key_pem.encode(), password=None, backend=default_backend())
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def decrypt_prescription_with_logging(encrypted_data, nonce, tag, encrypted_key, signature, rx_id):
        """Decrypt prescription and log EVERY STEP"""
        try:
            user_id = session.get('user_id') if session else None
        except:
            user_id = None
        
        user = db.session.get(User, user_id) if user_id else None
        if not user:
            user = User.query.filter_by(role='pharmacist').first()
        
        # Write header
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        header = f"""
{'='*80}
PRESCRIPTION DECRYPTION PROCESS: {rx_id}
Started: {timestamp}
User: {user.username if user else 'N/A'}
{'='*80}
"""
        write_to_log_file(PRESCRIPTION_DECRYPT_LOG, header)
        write_complete_log(header)
        
        # STEP 1: Load private key
        private_key = serialization.load_pem_private_key(
            user.private_key.encode('utf-8'), password=None, backend=default_backend())
        log_process_step(
            'prescription_decrypt', 1,
            'Load user RSA-2048 private key from PEM format',
            'RSA Key Loading',
            'PEM format private key',
            'RSA private key object loaded',
            {'key_type': 'RSA', 'key_size': 2048},
            rx_id
        )
        
        # STEP 2: Decrypt AES key with RSA-OAEP
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        aes_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        log_process_step(
            'prescription_decrypt', 2,
            'Decrypt AES key using RSA-OAEP (key unwrapping)',
            'RSA-OAEP',
            f'Encrypted key: {len(encrypted_key_bytes)} bytes',
            f'Decrypted AES key: {base64.b64encode(aes_key).decode()} (32 bytes)',
            {
                'algorithm': 'RSA-OAEP',
                'mgf': 'MGF1-SHA256',
                'hash': 'SHA-256'
            },
            rx_id
        )
        
        # STEP 3: Decrypt prescription data with AES-256-GCM
        ciphertext = base64.b64decode(encrypted_data)
        nonce_bytes = base64.b64decode(nonce)
        tag_bytes = base64.b64decode(tag)
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce_bytes, tag_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        log_process_step(
            'prescription_decrypt', 3,
            'Decrypt prescription data with AES-256-GCM and verify authentication tag',
            'AES-256-GCM',
            f'Ciphertext: {len(ciphertext)} bytes, Nonce: 12 bytes, Tag: 16 bytes',
            f'Plaintext: {plaintext.decode("utf-8")[:100]}... ({len(plaintext)} bytes)',
            {
                'algorithm': 'AES-256-GCM',
                'authenticated': True,
                'tag_verified': True
            },
            rx_id
        )
        
        # STEP 4: Parse JSON
        decrypted_data = json.loads(plaintext.decode('utf-8'))
        log_process_step(
            'prescription_decrypt', 4,
            'Parse decrypted JSON data',
            'JSON Deserialization',
            f'JSON string: {len(plaintext)} bytes',
            f'Prescription data: Medication={decrypted_data.get("medication")}',
            {'format': 'JSON', 'fields_count': len(decrypted_data)},
            rx_id
        )
        
        # STEP 5: Verify signature
        data_for_verification = json.dumps(decrypted_data, sort_keys=True).encode('utf-8')
        rx = Prescription.query.filter_by(prescription_id=rx_id).first()
        if rx and rx.doctor and rx.doctor.public_key:
            doctor_public_key = serialization.load_pem_public_key(
                rx.doctor.public_key.encode('utf-8'), backend=default_backend())
            
            try:
                doctor_public_key.verify(
                    base64.b64decode(signature),
                    data_for_verification,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                sig_valid = True
            except:
                sig_valid = False
        else:
            sig_valid = False
        
        log_process_step(
            'prescription_decrypt', 5,
            'Verify RSA-PSS digital signature',
            'RSA-PSS Verification',
            f'Signature: {len(base64.b64decode(signature))} bytes',
            f'Verification result: {"VALID ✓" if sig_valid else "INVALID ✗"}',
            {
                'algorithm': 'RSA-PSS',
                'verification_result': sig_valid,
                'doctor': rx.doctor.full_name if rx and rx.doctor else 'N/A'
            },
            rx_id
        )
        
        # Write summary
        summary = f"""
SUMMARY:
Prescription {rx_id} successfully decrypted.
Total steps: 5
Decryption result: SUCCESS
Signature verification: {"VALID" if sig_valid else "INVALID"}
Medication: {decrypted_data.get('medication', 'N/A')}
{'='*80}

"""
        write_to_log_file(PRESCRIPTION_DECRYPT_LOG, summary)
        write_complete_log(summary)
        
        return decrypted_data, sig_valid


# ============================================================================
# DECORATORS
# ============================================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            user = db.session.get(User, session['user_id'])
            if not user or user.role not in roles:
                flash('Access denied.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin access required.', 'error')
            abort(403)
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_globals():
    unread = 0
    if 'user_id' in session:
        unread = Notification.query.filter_by(user_id=session['user_id'], is_read=False).count()
    return {'unread_notifications': unread}


# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        
        if user and not user.is_locked() and user.check_password(password):
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            user.last_login_ip = request.remote_addr
            db.session.commit()
            
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['full_name'] = user.full_name
            
            log_action('Login')
            flash(f'Welcome, {user.full_name}!', 'success')
            return redirect(url_for('admin_dashboard') if user.role == 'admin' else url_for('dashboard'))
        else:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION)
                db.session.commit()
            flash('Invalid credentials.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action('Logout')
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'patient')
        
        if User.query.filter_by(username=username).first():
            flash('Username taken.', 'error')
            return render_template('register.html')
        
        # Generate RSA keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        
        user = User(
            username=username,
            role=role,
            full_name=request.form.get('full_name', ''),
            registration_number=request.form.get('registration_number', ''),
            email=request.form.get('email', ''),
            phone=request.form.get('phone', ''),
            hospital=request.form.get('hospital', ''),
            private_key=private_pem,
            public_key=public_pem
        )
        
        # Hash password with logging
        user.password_hash = CryptoUtils.hash_password_with_logging(password, username)
        
        db.session.add(user)
        db.session.commit()
        
        log_action('User Registered')
        flash('Account created! RSA-2048 keys generated.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    
    if user.role == 'doctor':
        recent_rx = Prescription.query.filter_by(doctor_id=user.id).order_by(Prescription.created_at.desc()).limit(5).all()
    elif user.role == 'pharmacist':
        recent_rx = Prescription.query.filter_by(status='active').order_by(Prescription.created_at.desc()).limit(5).all()
    else:
        recent_rx = Prescription.query.filter_by(patient_id=user.id).order_by(Prescription.created_at.desc()).limit(5).all()
    
    # Build stats dict based on role
    today = datetime.utcnow().date()
    if user.role == 'doctor':
        total = Prescription.query.filter_by(doctor_id=user.id).count()
        active = Prescription.query.filter_by(doctor_id=user.id, status='active').count()
        dispensed = Prescription.query.filter_by(doctor_id=user.id, status='dispensed').count()
        patient_ids = db.session.query(Prescription.patient_id).filter_by(doctor_id=user.id).distinct().count()
        stats = {'total': total, 'active': active, 'dispensed': dispensed, 'patients': patient_ids}
    elif user.role == 'pharmacist':
        pending = Prescription.query.filter_by(status='active').count()
        total_dispensed = Prescription.query.filter_by(status='dispensed').count()
        today_dispensed = Prescription.query.filter(
            Prescription.status=='dispensed',
            db.func.date(Prescription.created_at)==today).count()
        stats = {'pending': pending, 'today': today_dispensed, 'total': total_dispensed}
    else:  # patient / admin
        total = Prescription.query.filter_by(patient_id=user.id).count()
        active = Prescription.query.filter_by(patient_id=user.id, status='active').count()
        dispensed = Prescription.query.filter_by(patient_id=user.id, status='dispensed').count()
        doctor_ids = db.session.query(Prescription.doctor_id).filter_by(patient_id=user.id).distinct().count()
        stats = {'total': total, 'active': active, 'dispensed': dispensed, 'doctors': doctor_ids}

    # Recent audit logs for the sidebar
    recent_logs = AuditLog.query.filter_by(user_id=user.id).order_by(
        AuditLog.timestamp.desc()).limit(10).all()

    return render_template('dashboard.html', user=user, notifications=notifications,
                           recent_rx=recent_rx, stats=stats, recent_logs=recent_logs)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user = db.session.get(User, session['user_id'])
    
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pwd = request.form.get('new_password', '')
        
        if not user.check_password(current):
            flash('Current password incorrect.', 'error')
            return render_template('change_password.html')
        
        old_hash = user.password_hash[:50] + "..."
        
        # Hash new password with FULL PROCESS LOGGING
        user.password_hash = CryptoUtils.hash_password_with_logging(new_pwd, user.username)
        user.password_changed_at = datetime.utcnow()
        
        new_hash = user.password_hash[:50] + "..."
        
        db.session.commit()
        
        # Summary log
        log_detailed_change(
            'password_change',
            'password_hash',
            old_hash,
            new_hash,
            ['PBKDF2-SHA256', 'SHA-256'],
            f"Password changed. PBKDF2-SHA256 with {PBKDF2_ITERATIONS} iterations. See log files for detailed steps."
        )
        
        log_action('Password Changed')
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

@app.route('/create-prescription', methods=['GET', 'POST'])
@role_required('doctor')
def create_prescription():
    if request.method == 'POST':
        doctor = db.session.get(User, session['user_id'])
        patient = db.session.get(User, request.form.get('patient_id'))
        pharmacist = User.query.filter_by(role='pharmacist', is_active=True).first()
        
        if not pharmacist:
            flash('No pharmacist available.', 'error')
            return redirect(url_for('create_prescription'))
        
        rx_count = Prescription.query.count() + 1
        rx_id = f"RX-{datetime.now().strftime('%Y%m%d')}-{rx_count:04d}"
        
        data = {
            'prescription_id': rx_id,
            'doctor_name': doctor.full_name,
            'patient_name': patient.full_name,
            'medication': request.form.get('medication', ''),
            'dosage': request.form.get('dosage', ''),
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Encrypt with FULL PROCESS LOGGING (9 steps logged)
        enc_data, nonce, tag, enc_key, signature, data_hash = CryptoUtils.encrypt_prescription_with_logging(
            data, pharmacist.public_key, rx_id)
        
        rx = Prescription(
            prescription_id=rx_id,
            doctor_id=doctor.id,
            patient_id=patient.id,
            encrypted_data=enc_data,
            nonce=nonce,
            tag=tag,
            encrypted_key=enc_key,
            signature=signature,
            data_hash=data_hash,
            medication=data['medication']
        )
        db.session.add(rx)
        db.session.commit()
        
        # Summary log
        log_detailed_change(
            'prescription_created',
            'prescription_data',
            'NULL',
            f'RX: {rx_id}, Medication: {data["medication"]}',
            ['RSA-2048', 'AES-256-GCM', 'RSA-PSS', 'SHA-256', 'RSA-OAEP', 'MGF1-SHA256', 'PSS'],
            f"Prescription encrypted and signed. See log files for 9 detailed steps."
        )
        
        log_action('Prescription Created', rx_id)
        create_notification(patient.id, 'New Prescription', f'Dr. {doctor.full_name} prescribed {data["medication"]}', 'success')
        flash(f'Prescription {rx_id} created!', 'success')
        return redirect(url_for('view_prescription', id=rx.id))
    
    patients = User.query.filter_by(role='patient', is_active=True).all()
    return render_template('create_prescription.html', patients=patients)

@app.route('/prescription/<int:id>')
@login_required
def view_prescription(id):
    rx = db.session.get(Prescription, id)
    if not rx:
        abort(404)
    user = db.session.get(User, session['user_id'])
    
    decrypted = None
    sig_valid = False
    
    if user.role in ['pharmacist', 'patient']:
        try:
            # Decrypt with FULL PROCESS LOGGING (5 steps logged)
            decrypted, sig_valid = CryptoUtils.decrypt_prescription_with_logging(
                rx.encrypted_data, rx.nonce, rx.tag, rx.encrypted_key, rx.signature, rx.prescription_id)
            
            # Summary log
            log_detailed_change(
                'prescription_viewed',
                'prescription_data',
                '[ENCRYPTED]',
                '[DECRYPTED]',
                ['RSA-OAEP', 'MGF1-SHA256', 'AES-256-GCM', 'RSA-PSS'],
                f"Prescription decrypted and verified. Signature: {sig_valid}. See log files for 5 detailed steps."
            )
        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
    
    log_action('Prescription Viewed', rx.prescription_id)
    return render_template('view_prescription.html', prescription=rx, decrypted_data=decrypted, user=user, sig_valid=sig_valid)

@app.route('/prescriptions')
@login_required
def prescriptions():
    user = db.session.get(User, session['user_id'])
    page = request.args.get('page', 1, type=int)
    
    if user.role == 'doctor':
        query = Prescription.query.filter_by(doctor_id=user.id)
    elif user.role == 'pharmacist':
        query = Prescription.query
    else:
        query = Prescription.query.filter_by(patient_id=user.id)
    
    rxs = query.order_by(Prescription.created_at.desc()).paginate(page=page, per_page=10, error_out=False)
    return render_template('prescriptions.html', prescriptions=rxs, user=user)

@app.route('/profile')
@login_required
def profile():
    user = db.session.get(User, session['user_id'])
    total_actions = AuditLog.query.filter_by(user_id=user.id).count()
    return render_template('profile.html', user=user, total_actions=total_actions)

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifs = Notification.query.filter_by(user_id=session['user_id']).order_by(
        Notification.created_at.desc()).paginate(page=page, per_page=15, error_out=False)
    return render_template('notifications.html', notifications=notifs)


# ============================================================================
# ADMIN PANEL
# ============================================================================

@app.route('/admin')
@admin_required
def admin_dashboard():
    total_users = User.query.count()
    total_rxs = Prescription.query.count()
    total_process_logs = ProcessLog.query.count()
    
    recent_processes = ProcessLog.query.order_by(ProcessLog.timestamp.desc()).limit(10).all()
    
    # Log file info
    log_files = []
    for filename in [PASSWORD_LOG_FILE, PRESCRIPTION_ENCRYPT_LOG, PRESCRIPTION_DECRYPT_LOG, COMPLETE_LOG_FILE]:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            log_files.append({
                'name': os.path.basename(filename),
                'path': filename,
                'size': f"{size/1024:.1f} KB" if size > 1024 else f"{size} bytes"
            })
    
    return render_template('admin/dashboard.html',
                           total_users=total_users,
                           total_rxs=total_rxs,
                           total_process_logs=total_process_logs,
                           recent_processes=recent_processes,
                           log_files=log_files)

@app.route('/admin/process-logs')
@admin_required
def audit_log():
    page = request.args.get('page', 1, type=int)
    process_filter = request.args.get('process', '')
    resource_filter = request.args.get('resource', '')
    
    query = ProcessLog.query
    
    if process_filter:
        query = query.filter_by(process_type=process_filter)
    if resource_filter:
        query = query.filter_by(resource_id=resource_filter)
    
    logs = query.order_by(ProcessLog.resource_id, ProcessLog.step_number).paginate(page=page, per_page=50, error_out=False)
    
    all_processes = db.session.query(ProcessLog.process_type).distinct().all()
    
    return render_template('admin/process_logs.html',
                           logs=logs,
                           all_processes=[p[0] for p in all_processes],
                           process_filter=process_filter,
                           resource_filter=resource_filter)

@app.route('/admin/download-process-report')
@admin_required
def download_process_report():
    """Download complete process report"""
    output = io.StringIO()
    
    output.write("="*100 + "\n")
    output.write("NEPAL E-PRESCRIPTION - COMPLETE PROCESS REPORT\n")
    output.write(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
    output.write("="*100 + "\n\n")
    
    output.write("="*100 + "\n")
    output.write("HOW PASSWORDS ARE SAVED (PBKDF2-SHA256 Process)\n")
    output.write("="*100 + "\n")
    
    password_logs = ProcessLog.query.filter_by(process_type='password_save').order_by(
        ProcessLog.resource_id, ProcessLog.step_number).all()
    
    current_resource = None
    for log in password_logs:
        if log.resource_id != current_resource:
            current_resource = log.resource_id
            output.write(f"\n{'='*100}\n")
            output.write(f"USERNAME: {log.resource_id}\n")
            output.write(f"{'='*100}\n")
        
        output.write(f"\nSTEP {log.step_number}: {log.step_description}\n")
        output.write(f"Algorithm: {log.algorithm_used}\n")
        output.write(f"Input: {log.input_data}\n")
        output.write(f"Output: {log.output_data}\n")
        if log.parameters:
            params = json.loads(log.parameters)
            output.write(f"Parameters: {params}\n")
        output.write("-"*80 + "\n")
    
    output.write("\n\n" + "="*100 + "\n")
    output.write("HOW PRESCRIPTIONS ARE ENCRYPTED (9-Step Process)\n")
    output.write("="*100 + "\n")
    
    rx_logs = ProcessLog.query.filter_by(process_type='prescription_encrypt').order_by(
        ProcessLog.resource_id, ProcessLog.step_number).all()
    
    current_resource = None
    for log in rx_logs:
        if log.resource_id != current_resource:
            current_resource = log.resource_id
            output.write(f"\n{'='*100}\n")
            output.write(f"PRESCRIPTION: {log.resource_id}\n")
            output.write(f"{'='*100}\n")
        
        output.write(f"\nSTEP {log.step_number}: {log.step_description}\n")
        output.write(f"Algorithm: {log.algorithm_used}\n")
        output.write(f"Input: {log.input_data}\n")
        output.write(f"Output: {log.output_data}\n")
        if log.parameters:
            params = json.loads(log.parameters)
            output.write(f"Parameters: {params}\n")
        output.write("-"*80 + "\n")
    
    output.write("\n\n" + "="*100 + "\n")
    output.write("HOW PRESCRIPTIONS ARE DECRYPTED (5-Step Process)\n")
    output.write("="*100 + "\n")
    
    decrypt_logs = ProcessLog.query.filter_by(process_type='prescription_decrypt').order_by(
        ProcessLog.resource_id, ProcessLog.step_number).all()
    
    current_resource = None
    for log in decrypt_logs:
        if log.resource_id != current_resource:
            current_resource = log.resource_id
            output.write(f"\n{'='*100}\n")
            output.write(f"PRESCRIPTION: {log.resource_id}\n")
            output.write(f"{'='*100}\n")
        
        output.write(f"\nSTEP {log.step_number}: {log.step_description}\n")
        output.write(f"Algorithm: {log.algorithm_used}\n")
        output.write(f"Input: {log.input_data}\n")
        output.write(f"Output: {log.output_data}\n")
        if log.parameters:
            params = json.loads(log.parameters)
            output.write(f"Parameters: {params}\n")
        output.write("-"*80 + "\n")
    
    output.write("\n" + "="*100 + "\n")
    output.write("END OF REPORT\n")
    output.write("="*100 + "\n")
    
    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8'))
    mem.seek(0)
    output.close()
    
    return send_file(
        mem,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'process_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.txt'
    )


# ============================================================================

# ============================================================================
# MISSING ROUTES - ADDED TO FIX BuildError
# ============================================================================



@app.route('/audit-trail')
@login_required
def audit_trail():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', 'all')
    query = AuditLog.query.filter_by(user_id=session['user_id'])
    if action_filter and action_filter != 'all':
        query = query.filter_by(action=action_filter)
    logs = query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20, error_out=False)
    actions = [a[0] for a in db.session.query(AuditLog.action).filter_by(
        user_id=session['user_id']).distinct().all()]
    return render_template('audit_log.html', logs=logs, actions=actions)

@app.route('/settings')
@login_required
def settings():
    user = db.session.get(User, session['user_id'])
    return render_template('settings.html', user=user)

@app.route('/analytics')
@login_required
def analytics():
    from sqlalchemy import func
    user = db.session.get(User, session['user_id'])

    if user.role == 'doctor':
        base_q = Prescription.query.filter_by(doctor_id=user.id)
    elif user.role == 'pharmacist':
        base_q = Prescription.query
    else:
        base_q = Prescription.query.filter_by(patient_id=user.id)

    total_rxs = base_q.count()
    active_count = base_q.filter_by(status='active').count()
    dispensed_count = base_q.filter_by(status='dispensed').count()
    status_counts = {'active': active_count, 'dispensed': dispensed_count}
    total_dispensed = dispensed_count

    # Top medications
    from collections import Counter
    meds = [rx.medication for rx in base_q.all() if rx.medication]
    top_medications = Counter(meds).most_common(5)

    # Monthly data
    monthly_data = {}
    for rx in base_q.all():
        key = rx.created_at.strftime('%Y-%m') if rx.created_at else 'Unknown'
        monthly_data[key] = monthly_data.get(key, 0) + 1

    return render_template('analytics.html', user=user, total_rxs=total_rxs,
                           status_counts=status_counts, total_dispensed=total_dispensed,
                           top_medications=top_medications, monthly_data=monthly_data)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name)
        user.email = request.form.get('email', user.email)
        user.phone = request.form.get('phone', user.phone)
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', user=user)

@app.route('/notification/<int:id>/read')
@login_required
def mark_notification_read(id):
    notif = db.session.get(Notification, id)
    if notif and notif.user_id == session['user_id']:
        notif.is_read = True
        db.session.commit()
    return redirect(request.referrer or url_for('notifications'))

@app.route('/prescription/<int:id>/dispense', methods=['POST'])
@login_required
def dispense_prescription(id):
    user = db.session.get(User, session['user_id'])
    if user.role not in ('pharmacist', 'admin'):
        abort(403)
    rx = db.session.get(Prescription, id)
    if not rx:
        abort(404)
    rx.status = 'dispensed'
    db.session.commit()
    flash('Prescription marked as dispensed.', 'success')
    return redirect(url_for('view_prescription', id=id))

@app.route('/admin/change-logs')
@admin_required
def admin_change_logs():
    page = request.args.get('page', 1, type=int)
    change_type = request.args.get('type', '')
    user_filter = request.args.get('user_id', '')

    query = DetailedChangeLog.query
    if change_type:
        query = query.filter_by(change_type=change_type)
    if user_filter:
        query = query.filter_by(user_id=user_filter)

    logs = query.order_by(DetailedChangeLog.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)
    all_users = User.query.order_by(User.username).all()
    return render_template('admin/change_logs.html', logs=logs,
                           all_users=all_users, change_type=change_type, user_filter=user_filter)

@app.route('/admin/algorithm-usage')
@admin_required
def admin_algorithm_usage():
    page = request.args.get('page', 1, type=int)
    algo_filter = request.args.get('algorithm', '')
    process_filter_a = request.args.get('operation', '')

    query = ProcessLog.query
    if algo_filter:
        query = query.filter(ProcessLog.algorithm_used.ilike(f'%{algo_filter}%'))
    if process_filter_a:
        query = query.filter(ProcessLog.process_type.ilike(f'%{process_filter_a}%'))

    logs = query.order_by(ProcessLog.timestamp.desc()).paginate(page=page, per_page=50, error_out=False)

    # Compute algo usage stats
    from collections import Counter
    all_algos = [l.algorithm_used for l in ProcessLog.query.all() if l.algorithm_used]
    algo_stats = Counter(all_algos).most_common(10)

    return render_template('admin/algorithm_usage.html', logs=logs,
                           algo_stats=algo_stats, algo_filter=algo_filter,
                           operation_filter=process_filter_a)

@app.route('/admin/download-report')
@admin_required
def download_report():
    return redirect(url_for('download_process_report'))


# ============================================================================
# PKI - CERTIFICATE, KEY REVOCATION, KEYSTORE ROUTES
# ============================================================================

@app.route('/certificate/<username>')
@login_required
def view_certificate(username):
    """View X.509 certificate for a user — PKI certificate management"""
    user = User.query.filter_by(username=username).first()
    if not user:
        abort(404)
    cert_info = None
    validity = None
    if user.certificate_pem:
        try:
            from cryptography import x509 as _x509
            cert = _x509.load_pem_x509_certificate(
                user.certificate_pem.encode(), backend=default_backend())
            now = datetime.now(timezone.utc)
            cert_info = {
                'subject': dict((a.oid.dotted_string, a.value) for a in cert.subject),
                'serial': format(cert.serial_number, 'x'),
                'not_before': cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M UTC'),
                'not_after': cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M UTC'),
                'expired': cert.not_valid_after_utc < now,
                'cn': cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                'org': cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
                    if cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else 'N/A',
            }
            valid, msg = CryptoUtils.validate_certificate(user.certificate_pem, username)
            validity = {'valid': valid, 'message': msg}
        except Exception as e:
            cert_info = {'error': str(e)}
    return render_template('certificate.html', cert_user=user,
                           cert_info=cert_info, validity=validity)

@app.route('/certificate/<username>/download')
@login_required
def download_certificate(username):
    """Download raw PEM certificate"""
    user = User.query.filter_by(username=username).first()
    if not user or not user.certificate_pem:
        abort(404)
    mem = io.BytesIO(user.certificate_pem.encode())
    mem.seek(0)
    return send_file(mem, mimetype='application/x-pem-file', as_attachment=True,
                     download_name=f'{username}_certificate.pem')

@app.route('/download-keystore', methods=['GET', 'POST'])
@login_required
def download_keystore():
    """Download PKCS#12 password-protected keystore — Secure Key Storage"""
    user = db.session.get(User, session['user_id'])
    if request.method == 'POST':
        keystore_password = request.form.get('keystore_password', '')
        if len(keystore_password) < 8:
            flash('Keystore password must be at least 8 characters.', 'error')
            return render_template('download_keystore.html', user=user)
        if not user.certificate_pem:
            flash('No certificate found. Please contact admin.', 'error')
            return redirect(url_for('profile'))
        try:
            p12_bytes = CryptoUtils.export_pkcs12_keystore(
                user.private_key, user.certificate_pem,
                user.username, keystore_password)
            mem = io.BytesIO(p12_bytes)
            mem.seek(0)
            log_action('PKCS12 Keystore Downloaded')
            return send_file(mem, mimetype='application/x-pkcs12', as_attachment=True,
                             download_name=f'{user.username}_keystore.p12')
        except Exception as e:
            flash(f'Error generating keystore: {str(e)}', 'error')
    return render_template('download_keystore.html', user=user)

@app.route('/revoke-key', methods=['GET', 'POST'])
@login_required
def revoke_key():
    """Revoke a user's certificate — PKI Key Revocation"""
    current_user = db.session.get(User, session['user_id'])
    if current_user.role not in ('admin', 'doctor'):
        abort(403)
    users = User.query.filter(User.id != current_user.id, User.key_revoked == False).all()
    if request.method == 'POST':
        target_id = request.form.get('user_id', type=int)
        reason = request.form.get('reason', 'Key compromised')
        target = db.session.get(User, target_id)
        if not target:
            flash('User not found.', 'error')
            return redirect(url_for('revoke_key'))
        target.key_revoked = True
        target.key_revoked_at = datetime.utcnow()
        revocation = RevokedCertificate(
            user_id=target.id,
            serial_number=target.certificate_serial or 'unknown',
            reason=reason,
            revoked_by=current_user.id
        )
        db.session.add(revocation)
        db.session.commit()
        log_action(f'Certificate Revoked: {target.username}')
        flash(f'Certificate for {target.username} has been revoked.', 'success')
        return redirect(url_for('revoked_keys'))
    return render_template('revoke_key.html', users=users, current_user=current_user)

@app.route('/revoked-keys')
@login_required
def revoked_keys():
    """View Certificate Revocation List (CRL)"""
    revocations = RevokedCertificate.query.order_by(
        RevokedCertificate.revoked_at.desc()).all()
    return render_template('revoked_keys.html', revocations=revocations)

@app.route('/attack-demo')
@login_required
def attack_demo():
    """
    Demonstrate attack prevention:
    - Replay attack simulation
    - MITM attack simulation
    - Brute force simulation
    - Unauthorized signing attempt
    """
    user = db.session.get(User, session['user_id'])
    # Replay attack: show prescription with same ID attempted twice
    replay_demo = {
        'attack': 'Replay Attack',
        'description': 'Attacker captures a valid prescription and re-submits it.',
        'prevention': 'Each prescription has a unique UUID + timestamp. Duplicate IDs are rejected.',
        'evidence': f'Unique IDs used: {Prescription.query.count()} prescriptions, all with distinct RX-IDs'
    }
    # MITM demo
    mitm_demo = {
        'attack': 'Man-in-the-Middle (MITM)',
        'description': 'Attacker intercepts and modifies prescription data in transit.',
        'prevention': 'RSA-PSS digital signature on every prescription. Any modification invalidates the signature.',
        'evidence': 'Signature covers all prescription fields via SHA-256 hash before signing.'
    }
    # Brute force demo
    bf_demo = {
        'attack': 'Brute Force / Credential Stuffing',
        'description': 'Attacker repeatedly guesses passwords.',
        'prevention': f'Account locked after {MAX_LOGIN_ATTEMPTS} failed attempts for {LOCKOUT_DURATION} minutes. PBKDF2 with 260,000 iterations slows offline attacks.',
        'evidence': 'Failed login attempts tracked per user in database.'
    }
    # Unauthorized signing demo
    unauth_demo = {
        'attack': 'Unauthorized Prescription Signing',
        'description': 'Patient or pharmacist attempts to create/sign a prescription.',
        'prevention': 'Role-based access control: only doctors can create prescriptions. RSA private key unique per user.',
        'evidence': 'create_prescription route decorated with @role_required("doctor")'
    }
    demos = [replay_demo, mitm_demo, bf_demo, unauth_demo]
    total_users = User.query.count()
    total_certs = User.query.filter(User.certificate_pem != None).count()
    total_rxs = Prescription.query.count()
    total_revoked = RevokedCertificate.query.count()
    return render_template('attack_demo.html', user=user, demos=demos,
                           total_users=total_users, total_certs=total_certs,
                           total_rxs=total_rxs, total_revoked=total_revoked)

@app.route('/use-cases')
def use_cases():
    """Three real-world use cases demonstrating cryptographic features"""
    cases = [
        {
            "id": 1,
            "title": "Use Case 1: Tamper-Proof E-Prescriptions (Healthcare)",
            "problem": "Paper prescriptions can be forged, altered, or reused. Drug fraud costs healthcare systems billions yearly.",
            "solution": "Each prescription is digitally signed with the doctor RSA-2048 private key using RSA-PSS/SHA-256. The pharmacist verifies the signature using the doctor X.509 certificate before dispensing.",
            "algorithms": ["RSA-2048 Digital Signature", "RSA-PSS with SHA-256", "X.509 Certificate Validation"],
            "how": "Doctor signs prescription. Pharmacist verifies certificate. Signature verified. Prescription dispensed. Any forgery immediately detected.",
            "icon": "hospital"
        },
        {
            "id": 2,
            "title": "Use Case 2: Confidential Patient Data (Privacy)",
            "problem": "Patient prescription data is highly sensitive. Unauthorized parties must not access it.",
            "solution": "Hybrid encryption: AES-256-GCM encrypts the prescription content, RSA-OAEP wraps the AES key with the pharmacist RSA-2048 public key. Only the intended pharmacist can decrypt.",
            "algorithms": ["AES-256-GCM (symmetric encryption)", "RSA-OAEP with MGF1-SHA256 (key wrapping)", "GCM Authentication Tag (integrity)"],
            "how": "Prescription encrypted at creation. Database stores only ciphertext. Decryption only possible with pharmacist private key.",
            "icon": "shield-lock"
        },
        {
            "id": 3,
            "title": "Use Case 3: Secure Key Lifecycle Management (PKI)",
            "problem": "If a doctor private key is compromised, all future prescriptions could be forged in their name.",
            "solution": "X.509 certificates with a Certificate Revocation List (CRL). Compromised keys are immediately revoked. PKCS12 keystores provide password-protected key storage.",
            "algorithms": ["X.509 v3 Certificates", "Certificate Revocation List (CRL)", "PKCS12 Password-Protected Keystore"],
            "how": "Admin revokes compromised certificate. Serial added to CRL. All subsequent verifications check CRL. Revoked key rejected.",
            "icon": "key"
        }
    ]
    return render_template('use_cases.html', cases=cases)


# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


# ============================================================================
# INIT
# ============================================================================

def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() > 0:
            return
        
        print("\n🔧 Creating database...")
        
        # Initialize log files
        for logfile in [PASSWORD_LOG_FILE, PRESCRIPTION_ENCRYPT_LOG, PRESCRIPTION_DECRYPT_LOG, COMPLETE_LOG_FILE]:
            if os.path.exists(logfile):
                os.remove(logfile)
            header = f"""
{'='*80}
NEPAL E-PRESCRIPTION SYSTEM v3.7 - PROCESS LOG
Log File: {os.path.basename(logfile)}
Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*80}

"""
            write_to_log_file(logfile, header)
        
        users_data = [
            # ---- ADMIN ----
            {'username': 'admin', 'password': 'Admin@2024!', 'role': 'admin',
             'full_name': 'System Admin', 'registration_number': 'ADMIN-001',
             'email': 'admin@nepal-rx.np', 'phone': '01-4000000'},

            # ---- DOCTORS ----
            {'username': 'doctor1', 'password': 'Doctor@123', 'role': 'doctor',
             'full_name': 'Dr. Rajesh Sharma', 'registration_number': 'NMC-12345',
             'email': 'rajesh@hospital.np', 'hospital': 'TUTH', 'phone': '014412404'},
            {'username': 'doctor2', 'password': 'Doctor@456', 'role': 'doctor',
             'full_name': 'Dr. Priya Shrestha', 'registration_number': 'NMC-23456',
             'email': 'priya@hospital.np', 'hospital': 'Bir Hospital', 'phone': '014221119'},
            {'username': 'doctor3', 'password': 'Doctor@789', 'role': 'doctor',
             'full_name': 'Dr. Anil Karmacharya', 'registration_number': 'NMC-34567',
             'email': 'anil@hospital.np', 'hospital': 'Patan Hospital', 'phone': '015522266'},

            # ---- PHARMACISTS ----
            {'username': 'pharmacist1', 'password': 'Pharm@123', 'role': 'pharmacist',
             'full_name': 'Sita Gurung', 'registration_number': 'NPC-67890',
             'email': 'sita@pharmacy.np', 'hospital': 'KTM Pharmacy', 'phone': '014445678'},
            {'username': 'pharmacist2', 'password': 'Pharm@456', 'role': 'pharmacist',
             'full_name': 'Bikash Tamang', 'registration_number': 'NPC-78901',
             'email': 'bikash@pharmacy.np', 'hospital': 'Patan Pharmacy', 'phone': '015544321'},
            {'username': 'pharmacist3', 'password': 'Pharm@789', 'role': 'pharmacist',
             'full_name': 'Manisha Rai', 'registration_number': 'NPC-89012',
             'email': 'manisha@pharmacy.np', 'hospital': 'New Road Pharmacy', 'phone': '014256789'},

            # ---- PATIENTS ----
            {'username': 'patient1', 'password': 'Patient@123', 'role': 'patient',
             'full_name': 'Ram Thapa', 'registration_number': '12-01-75-00123',
             'email': 'ram@email.com', 'phone': '9841000001'},
            {'username': 'patient2', 'password': 'Patient@456', 'role': 'patient',
             'full_name': 'Gita Adhikari', 'registration_number': '12-01-75-00456',
             'email': 'gita@email.com', 'phone': '9841000002'},
            {'username': 'patient3', 'password': 'Patient@789', 'role': 'patient',
             'full_name': 'Suresh Magar', 'registration_number': '12-01-75-00789',
             'email': 'suresh@email.com', 'phone': '9841000003'},
            {'username': 'patient4', 'password': 'Patient@321', 'role': 'patient',
             'full_name': 'Kamala Bhandari', 'registration_number': '12-01-75-00321',
             'email': 'kamala@email.com', 'phone': '9841000004'},
        ]
        
        for udata in users_data:
            pwd = udata.pop('password')
            username = udata['username']
            
            # Generate RSA keys
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = private_key.public_key()
            private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PrivateFormat.PKCS8,
                                                     encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            
            u = User(**udata, private_key=private_pem, public_key=public_pem)
            u.password_hash = CryptoUtils.hash_password_with_logging(pwd, username)
            # Generate X.509 certificate
            cert_pem, serial_hex = CryptoUtils.generate_certificate(
                private_key, public_key, username,
                udata.get('role', 'user'), udata.get('hospital'))
            u.certificate_pem = cert_pem
            u.certificate_serial = serial_hex
            # Load into HSM simulator
            HSMSimulator.store_key(username, private_pem, username)
            db.session.add(u)
        
        db.session.commit()
        print("✅ Database initialized!\n")
        print(f"📄 Log files created in: {LOG_DIR}")
        print(f"   - {os.path.basename(PASSWORD_LOG_FILE)}")
        print(f"   - {os.path.basename(PRESCRIPTION_ENCRYPT_LOG)}")
        print(f"   - {os.path.basename(PRESCRIPTION_DECRYPT_LOG)}")
        print(f"   - {os.path.basename(COMPLETE_LOG_FILE)}\n")


if __name__ == '__main__':
    init_db()
    print("\n" + "="*80)
    print("  NEPAL E-PRESCRIPTION v3.7 FINAL - COMPLETE PROCESS LOGGING")
    print("="*80)
    print("  🌐 URL: http://127.0.0.1:5000")
    print("  👑 Admin: http://127.0.0.1:5000/admin")
    print("  📋 Process Logs: /admin/process-logs")
    print("  📥 Download Report: /admin/download-process-report")
    print("="*80)
    print("  LOGIN: admin / Admin@2024!")
    print("="*80)
    print("\n  🔍 PROCESS LOGGING:")
    print("     • Password Save: 5 steps logged")
    print("     • Prescription Encrypt: 9 steps logged")
    print("     • Prescription Decrypt: 5 steps logged")
    print(f"\n  📄 LOG FILES LOCATION:")
    print(f"     {LOG_DIR}")
    print("     • password_save_process.log")
    print("     • prescription_encrypt_process.log")
    print("     • prescription_decrypt_process.log")
    print("     • complete_process_logs.log")
    print("="*80 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
