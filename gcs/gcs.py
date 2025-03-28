from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import logging, os
from pathlib import Path
from crypto_utils import CryptoUtils
from crl_manager import CRLManager
from config import PKIConfig
from flask import Flask, request, jsonify
from pki_gen import PKISetup

class GCS:
    def __init__(self, base_dir: str = "certs"):
        self.logger = logging.getLogger('GCS_SERVER')
        self.logger.setLevel(logging.INFO)
        self.base_dir = Path(base_dir)
        self.config = PKIConfig()
        self.crypto_utils = CryptoUtils()
        self.app = Flask(__name__)
        self.cert_validity_minutes = int(os.getenv('CERT_VALIDITY_MINUTES', '59'))
        self.skip_verification = os.getenv('SKIP_VERIFICATION', 'false').lower() == 'true' # Skips hardware verification for each node
        self.setup_routes()
        self.private_key, self.public_key = self.crypto_utils.generate_key_pair()
        self._ensure_pki_infrastructure()
        self._load_pki_materials()
        self.allowed_drones = set()
        self._start_bootstrap_phase()
        self.issued_certificates = {}
        self.leader_drones = set() # Note: No included implementation for updating a leader note

    def _start_bootstrap_phase(self):
        """Start the bootstrap phase for certificate enrollment"""
        self.config.BOOTSTRAP_START_TIME = datetime.now(timezone.utc)
        self.logger.info(f"Bootstrap phase started at {self.config.BOOTSTRAP_START_TIME}")
        self.logger.info(f"Bootstrap phase will end at {self.config.BOOTSTRAP_START_TIME + self.config.BOOTSTRAP_DURATION}")

    def setup_routes(self):
            @self.app.route('/request_certificate', methods=['POST'])
            def handle_cert_request():
                try:
                    data = request.get_json()
                    drone_id, manufacturer_id, csr_pem = data.get('drone_id'), data.get('manufacturer_id'), data.get('csr')
                    
                    if not all([drone_id, manufacturer_id, csr_pem]):
                        return jsonify({'status': 'error', 'message': 'Missing fields'}), 400
                        
                    csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
                    
                    if not self.skip_verification:
                        try:
                            csr.public_key().verify(csr.signature, csr.tbs_certrequest_bytes, ec.ECDSA(hashes.SHA256()))
                            if not self.verify_drone_identity(drone_id, manufacturer_id):
                                return jsonify({'status': 'error', 'message': 'Identity verification failed'}), 403
                        except Exception:
                            return jsonify({'status': 'error', 'message': 'Invalid CSR'}), 400
                    
                    cert = self.generate_certificate(csr, drone_id, manufacturer_id)
                    return jsonify({'status': 'success', 'certificate': self.format_certificate_response(cert, drone_id, manufacturer_id)}), 200
                    
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 500
                        
            @self.app.route('/get_network_nodes', methods=['POST'])
            def get_network_nodes():
                try:
                    data = request.get_json()
                    requesting_drone_id = data.get('drone_id')
                    auth_token = data.get('auth_token')  # This could be signed with the drone's private key
                    
                    # Verify the drone is a leader
                    if not self.is_leader_drone(requesting_drone_id, auth_token):
                        return jsonify({'status': 'error', 'message': 'Unauthorized - not a leader drone'}), 403
                    
                    # Return the list of nodes and their certificates
                    return jsonify({
                        'status': 'success',
                        'nodes': self.get_network_node_list()
                    }), 200
                    
                except Exception as e:
                    return jsonify({'status': 'error', 'message': str(e)}), 500
                
    def is_leader_drone(self, drone_id: str, auth_token: str) -> bool:
        """Verify if the requesting drone is a leader"""
        # For basic implementation, just check if the drone ID is in our leader set
        # In a more secure implementation, validate the auth_token cryptographically
        return drone_id in self.leader_drones

    def get_network_node_list(self) -> dict:
        """Get the list of all nodes and their certificates"""
        return self.issued_certificates

    def _get_name_attribute(self, name: x509.Name, oid: NameOID) -> Optional[str]:
        """Safely extract name attribute from certificate subject/issuer"""
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except (IndexError, ValueError):
            return None

    def _ensure_pki_infrastructure(self):
        """Ensure PKI infrastructure exists, create if it doesn't"""
        ca_cert_path = self.base_dir / "ca" / "ca_cert.pem"
        ca_key_path = self.base_dir / "private" / "ca_key.pem"
        password_path = self.base_dir / ".secure" / "ca_password.bin"

        # Check if any required files are missing
        if not all([ca_cert_path.exists(), ca_key_path.exists(), password_path.exists()]):
            self.logger.info("PKI infrastructure not complete. Initializing...")
            pki_setup = PKISetup(output_dir=str(self.base_dir))
            pki_setup.setup_pki()
            self.logger.info("PKI infrastructure initialized successfully")
        else:
            self.logger.info("Using existing PKI infrastructure")

    def _load_pki_materials(self):
        """Load PKI materials from files"""
        try:
            # Load CA certificate
            ca_cert_path = self.base_dir / "ca" / "ca_cert.pem"
            with open(ca_cert_path, 'rb') as f:
                ca_cert_data = f.read()
                self.ca_cert = x509.load_pem_x509_certificate(ca_cert_data)
                self.ca_public_key = self.ca_cert.public_key()

            # Load CA private key
            ca_key_path = self.base_dir / "private" / "ca_key.pem"
            password_path = self.base_dir / ".secure" / "ca_password.bin"
            
            # Read password
            password = PKISetup.read_password_file(password_path)
            
            # Load private key
            with open(ca_key_path, 'rb') as f:
                self.ca_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password
                )

            # Initialize CRL Manager
            crl_path = self.base_dir / "crl" / "drone_crl.json"
            self.crl_manager = CRLManager(self.config)
            if crl_path.exists():
                self.crl_manager.load_crl_from_file(str(crl_path))
            else:
                self.logger.warning("CRL file not found, initializing empty CRL")
                self.crl_manager.initialize_empty_crl(str(crl_path))

        except Exception as e:
            self.logger.error(f"Failed to load PKI materials: {str(e)}")
            raise

    def _initialize_test_drones(self):
        """Initialize test drones for development and testing"""
        test_drones = [
            ("TEST001", "TESTMFG"),
            ("TESTDRONE", "TESTMANUF"),
        ]
        
        for drone_id, manufacturer_id in test_drones:
            self.add_allowed_drone(drone_id, manufacturer_id)
            self.logger.info(f"Added test drone {drone_id}/{manufacturer_id} to allowed drones")

    def verify_drone_identity(self, drone_id: str, manufacturer_id: str) -> bool:
        """Verify the drone's identity against allowed drones"""
        return (drone_id, manufacturer_id) in self.allowed_drones

    def add_allowed_drone(self, drone_id: str, manufacturer_id: str):
        """Add a drone to the allowed drones list"""
        self.allowed_drones.add((drone_id, manufacturer_id))

    def remove_allowed_drone(self, drone_id: str, manufacturer_id: str):
        """Remove a drone from the allowed drones list"""
        self.allowed_drones.discard((drone_id, manufacturer_id))

    def verify_drone_certificate(self, cert_data: bytes) -> bool:
        """Verify a drone's certificate"""
        try:
            # First verify the signature
            if not self.crypto_utils.verify_certificate_signature(cert_data, self.ca_public_key):
                self.logger.warning("Certificate signature verification failed")
                return False
                
            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Check if revoked
            if self.crl_manager.is_cert_revoked(str(cert.serial_number)):
                self.logger.warning("Certificate is revoked")
                return False
                
            # Check validity period
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
                self.logger.warning("Certificate is not within its validity period")
                return False
                
            # Check key usage extension
            try:
                key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                if key_usage:
                    key_usage_value = key_usage.value
                    required_usages = {
                        'digital_signature': True,
                        'key_encipherment': True
                    }
                    
                    for usage, required in required_usages.items():
                        if getattr(key_usage_value, usage) != required:
                            self.logger.warning(f"Certificate missing required key usage: {usage}")
                            return False
            except x509.ExtensionNotFound:
                self.logger.warning("Certificate missing key usage extension")
                return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate verification failed: {str(e)}")
            return False

    def format_certificate_response(self, cert: x509.Certificate, drone_id: str, manufacturer_id: str) -> Dict[str, Any]:
        key_usage = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        return {
            'certificate_data': {
                'pem': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                'serial_number': str(cert.serial_number),
                'public_key': cert.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                'ca_public_key': self.ca_cert.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
            },
            'validity': {
                'not_before': cert.not_valid_before_utc.isoformat(),
                'not_after': cert.not_valid_after_utc.isoformat()
            },
            'subject': {
                'drone_id': drone_id,
                'manufacturer_id': manufacturer_id,
                'common_name': self._get_name_attribute(cert.subject, NameOID.COMMON_NAME)
            },
            'issuer': {
                'common_name': self._get_name_attribute(cert.issuer, NameOID.COMMON_NAME),
                'organization': self._get_name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME)
            },
            'key_usage': {
                'digital_signature': key_usage.digital_signature,
                'key_encipherment': key_usage.key_encipherment
            },
            'metadata': {
                'issued_at': datetime.now(timezone.utc).isoformat(),
                'version': cert.version.name
            }
        }
    
    def register_leader(self, drone_id: str):
        self.leader_drones.add(drone_id)
        self.logger.info(f"Registered {drone_id} as a leader drone")

    def generate_certificate(self, csr: x509.CertificateSigningRequest, drone_id: str, manufacturer_id: str) -> x509.Certificate:
        builder = x509.CertificateBuilder()
        now = datetime.now(timezone.utc)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(minutes=self.cert_validity_minutes))
        builder = builder.public_key(csr.public_key())
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False,
                decipher_only=False
            ), critical=True)
        cert = builder.sign(private_key=self.ca_private_key, algorithm=hashes.SHA256())
        cert_data = {
            'certificate': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            'drone_id': drone_id,
            'manufacturer_id': manufacturer_id,
            'issued_at': datetime.now(timezone.utc).isoformat(),
            'valid_until': (now + timedelta(minutes=self.cert_validity_minutes)).isoformat()
        }
        self.issued_certificates[drone_id] = cert_data
        
        # Check if the drone should be a leader
        if os.getenv('LEADER_DRONES', '').split(','):
            leader_ids = [id.strip() for id in os.getenv('LEADER_DRONES', '').split(',')]
            if drone_id in leader_ids:
                self.register_leader(drone_id)
        
        return cert

    def run(self, host='0.0.0.0', port=5000):
        self.app.run(host=host, port=port)