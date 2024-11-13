#!/usr/bin/env python3
import argparse
import requests
import json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import logging
from pathlib import Path

class DronePKITester:
    def __init__(self):
        """Initialize the PKI tester"""
        self.private_key = None
        self.public_key = None
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('DronePKITester')

    def generate_keypair(self):
        """Generate ECDSA key pair for the test drone"""
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.logger.info("Generated ECDSA key pair")

    def generate_csr(self, drone_id: str, manufacturer_id: str) -> bytes:
        """Generate a Certificate Signing Request"""
        if not self.private_key:
            self.generate_keypair()

        # Create CSR builder
        builder = x509.CertificateSigningRequestBuilder()

        # Add Subject
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Drone-{drone_id}"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, manufacturer_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Drone Fleet")
        ]))

        # Add Extensions
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )

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

        # Generate CSR
        csr = builder.sign(self.private_key, hashes.SHA256())
        return csr.public_bytes(serialization.Encoding.PEM)

    def request_certificate(self, drone_id: str, manufacturer_id: str) -> None:
        """Request a certificate from the local GCS instance"""
        try:
            # Generate CSR
            csr_pem = self.generate_csr(drone_id, manufacturer_id)
            
            # Prepare request data
            request_data = {
                'drone_id': drone_id,
                'manufacturer_id': manufacturer_id,
                'csr': csr_pem.decode('utf-8')
            }

            # Connect to local GCS Flask server
            url = "http://localhost:5000/request_certificate"
            self.logger.info(f"Sending certificate request to local GCS")
            self.logger.debug(f"Request data: {request_data}")
            
            response = requests.post(url, json=request_data)
            self.logger.debug(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                # Save the certificate
                with open(f"drone_{drone_id}_cert.pem", 'wb') as f:
                    f.write(response.content)
                self.logger.info(f"Certificate received and saved to drone_{drone_id}_cert.pem")
                
                # Save the private key
                with open(f"drone_{drone_id}_key.pem", 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
                self.logger.info(f"Private key saved to drone_{drone_id}_key.pem")
                
                # Verify the received certificate
                self.verify_received_certificate(response.content)
                
            else:
                self.logger.error(f"Certificate request failed: {response.status_code}")
                self.logger.error(f"Response: {response.text}")
                
        except Exception as e:
            self.logger.error(f"Error requesting certificate: {str(e)}")
            raise

    def verify_received_certificate(self, cert_data: bytes) -> bool:
        """Verify the received certificate"""
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Verify certificate fields
            self.logger.info("Certificate details:")
            self.logger.info(f"Subject: {cert.subject}")
            self.logger.info(f"Issuer: {cert.issuer}")
            self.logger.info(f"Valid from: {cert.not_valid_before}")
            self.logger.info(f"Valid until: {cert.not_valid_after}")
            
            # Verify extensions
            for extension in cert.extensions:
                self.logger.info(f"Extension: {extension.oid._name}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Certificate verification failed: {str(e)}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Test Drone PKI Certificate Request')
    parser.add_argument('--drone-id', default='TEST001', help='Drone ID')
    parser.add_argument('--manufacturer-id', default='TESTMFG', help='Manufacturer ID')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger('DronePKITester').setLevel(logging.DEBUG)
    
    tester = DronePKITester()
    try:
        tester.request_certificate(args.drone_id, args.manufacturer_id)
    except Exception as e:
        logging.error(f"Test failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()