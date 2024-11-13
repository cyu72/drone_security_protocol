from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timedelta, timezone
import logging
from typing import Optional, Set
from pathlib import Path
from crypto_utils import CryptoUtils
from crl_manager import CRLManager
from config import PKIConfig
from flask import Flask, request, jsonify
from pki_gen import PKISetup

class GCS:
    def __init__(self, base_dir: str = "certs"):
        """Initialize the Ground Control Station with auto-setup of PKI if needed"""
        # Set up logging
        self.logger = logging.getLogger('GCS_SERVER')
        self.logger.setLevel(logging.INFO)
        
        self.base_dir = Path(base_dir)
        self.config = PKIConfig()
        self.crypto_utils = CryptoUtils()
        self.app = Flask(__name__)
        self.setup_routes()
        
        # Initialize key pair
        self.private_key, self.public_key = self.crypto_utils.generate_key_pair()
        
        # Check if PKI infrastructure exists, if not create it
        self._ensure_pki_infrastructure()
        
        # Load PKI materials
        self._load_pki_materials()
        
        # Initialize allowed drones set
        self.allowed_drones: Set[tuple] = set()
        
        # Start bootstrap phase
        self._start_bootstrap_phase()
            
        self.logger.info("GCS initialized successfully")
        self.logger.info(f"Bootstrap phase will last for: {self.config.BOOTSTRAP_DURATION}")

    def _start_bootstrap_phase(self):
        """Start the bootstrap phase for certificate enrollment"""
        self.config.BOOTSTRAP_START_TIME = datetime.now(timezone.utc)
        self.logger.info(f"Bootstrap phase started at {self.config.BOOTSTRAP_START_TIME}")
        self.logger.info(f"Bootstrap phase will end at {self.config.BOOTSTRAP_START_TIME + self.config.BOOTSTRAP_DURATION}")

    def setup_routes(self):
        @self.app.route('/request_certificate', methods=['POST'])
        def handle_cert_request():
            try:
                # Check if we're in bootstrap phase
                if not self.config.is_in_bootstrap_phase():
                    remaining_time = self.config.get_bootstrap_remaining_time()
                    if remaining_time and remaining_time.total_seconds() <= 0:
                        return jsonify({
                            'error': 'Bootstrap phase has ended. Certificate requests are no longer accepted.',
                            'bootstrap_ended_at': (self.config.BOOTSTRAP_START_TIME + 
                                                 self.config.BOOTSTRAP_DURATION).isoformat()
                        }), 403
                    return jsonify({
                        'error': 'Bootstrap phase has not started yet',
                        'current_time': datetime.now(timezone.utc).isoformat()
                    }), 403

                data = request.get_json()
                
                # Extract request data
                drone_id = data.get('drone_id')
                manufacturer_id = data.get('manufacturer_id')
                csr_pem = data.get('csr')
                
                if not all([drone_id, manufacturer_id, csr_pem]):
                    return jsonify({'error': 'Missing required fields'}), 400
                
                # Load CSR
                csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
                
                # Verify CSR signature
                try:
                    csr.public_key().verify(
                        csr.signature,
                        csr.tbs_certrequest_bytes,
                        ec.ECDSA(hashes.SHA256())
                    )
                except Exception:
                    return jsonify({'error': 'Invalid CSR signature'}), 400
                
                # During bootstrap phase, automatically add to allowed drones
                self.add_allowed_drone(drone_id, manufacturer_id)
                self.logger.info(f"Added drone {drone_id}/{manufacturer_id} during bootstrap phase")
                
                # Generate certificate
                cert = self.generate_certificate(csr, drone_id, manufacturer_id)
                
                # Return the certificate with bootstrap phase info
                response_data = {
                    'certificate': cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                    'bootstrap_remaining': self.config.get_bootstrap_remaining_time().total_seconds()
                }
                
                return jsonify(response_data), 200
                
            except Exception as e:
                self.logger.error(f"Certificate request handling failed: {str(e)}")
                return jsonify({'error': 'Internal server error'}), 500

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

    def generate_certificate(self, csr: x509.CertificateSigningRequest, 
                           drone_id: str, manufacturer_id: str) -> x509.Certificate:
        """Generate a certificate from a CSR"""
        # Create certificate builder
        builder = x509.CertificateBuilder()
        
        # Set serial number
        builder = builder.serial_number(x509.random_serial_number())
        
        # Set subject from CSR
        builder = builder.subject_name(csr.subject)
        
        # Set issuer (the CA's information)
        builder = builder.issuer_name(self.ca_cert.subject)
        
        # Set validity period
        now = datetime.now(timezone.utc)
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=self.config.MAX_CERT_VALIDITY_DAYS))
        
        # Set public key from CSR
        builder = builder.public_key(csr.public_key())
        
        # Add basic constraints extension
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Add key usage extension
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        
        # Sign certificate
        certificate = builder.sign(
            private_key=self.ca_private_key,
            algorithm=hashes.SHA256()
        )
        
        return certificate

    def run(self, host='0.0.0.0', port=5000):
        """Run the GCS server"""
        self.app.run(host=host, port=port)