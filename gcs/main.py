import logging
import os
from pathlib import Path
from messages import MESSAGE_TYPE, GCS_MESSAGE, RREQ, RREP
from gcs import GCS
import sys

PORT_NUMBER = 65456
BRDCST_PORT = 65467
ADHOC_IFACE = "wlan0"
FLASK_PORT = int(os.getenv('FLASK_PORT', '5000'))
FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')

class GCS_SERVER:
    def __init__(self):
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('GCS_SERVER')
        
        self.gcs = GCS()
        self.socket = None
        
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        self.logger.info(f"New connection from {client_address}")
        try:
            while True:
                # Receive data
                data = client_socket.recv(4096)
                if not data:
                    break
                    
                # Process message
                try:
                    message = GCS_MESSAGE()
                    message.deserialize(data.decode())
                    
                    # Handle different message types
                    if message.type == MESSAGE_TYPE.ROUTE_REQUEST:
                        # Verify client certificate before processing route request
                        if not self._verify_client_certificate(client_socket):
                            self.logger.warning(f"Failed certificate verification for {client_address}")
                            break
                        # Handle route request
                        self._handle_route_request(message, client_socket)
                    elif message.type == MESSAGE_TYPE.INIT_AUTO_DISCOVERY:
                        # Handle auto discovery
                        self._handle_auto_discovery(message, client_socket)
                    elif message.type == MESSAGE_TYPE.EXIT:
                        self.logger.info(f"Client {client_address} requested disconnection")
                        break
                    
                except Exception as e:
                    self.logger.error(f"Error processing message: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error handling client {client_address}: {str(e)}")
        finally:
            client_socket.close()
            self.logger.info(f"Connection closed for {client_address}")

    def _verify_client_certificate(self, client_socket):
        """Verify client's certificate"""
        try:
            # Request client certificate
            client_socket.send(b"SEND_CERT")
            cert_data = client_socket.recv(4096)
            
            # Verify certificate using GCS
            return self.gcs.verify_drone_certificate(cert_data)
        except Exception as e:
            self.logger.error(f"Certificate verification error: {str(e)}")
            return False

    def _handle_route_request(self, message, client_socket):
        """Handle route request messages"""
        try:
            # Process RREQ message
            rreq = RREQ()
            rreq.deserialize(message.serialize())
            
            # Create and send route reply
            rrep = RREP(
                src_addr=rreq.dest_addr,
                dest_addr=rreq.src_addr,
                src_seq_num=rreq.src_seq_num,
                dest_seq_num=rreq.dest_seq_num,
                hash_value=rreq.hash,
                hop_count=0
            )
            
            client_socket.send(rrep.serialize().encode())
            
        except Exception as e:
            self.logger.error(f"Error handling route request: {str(e)}")

    def _handle_auto_discovery(self, message, client_socket):
        """Handle auto discovery messages"""
        try:
            # Extract drone information from message
            drone_id = message.src_addr
            manufacturer_id = "UNKNOWN"  # Would normally extract from message
            
            # Add to allowed drones if not already present
            self.gcs.add_allowed_drone(drone_id, manufacturer_id)
            
            # Send acknowledgment
            response = GCS_MESSAGE(
                src_addr="GCS",
                dest_addr=drone_id,
                message_type=MESSAGE_TYPE.DATA
            )
            client_socket.send(response.serialize().encode())
            
        except Exception as e:
            self.logger.error(f"Error handling auto discovery: {str(e)}")
            
    def start(self):
        """Start the server"""
        try:
            # Start GCS Flask server in a separate thread
            gcs_thread = threading.Thread(
                target=self.gcs.run,
                kwargs={'host': FLASK_HOST, 'port': FLASK_PORT}
            )
            gcs_thread.daemon = True
            gcs_thread.start()
            self.logger.info(f"GCS REST API server started on {FLASK_HOST}:{FLASK_PORT}")
            
            # Create main socket server
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind and listen
            server_address = ('', PORT_NUMBER)
            self.socket.bind(server_address)
            self.socket.listen(5)
            self.logger.info(f"Socket server listening on port {PORT_NUMBER}")
            
            # Main server loop
            while True:
                client_socket, client_address = self.socket.accept()
                # Start new thread for each client
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            self.logger.error(f"Server error: {str(e)}")
            if self.socket:
                self.socket.close()
            raise
            
    def stop(self):
        """Stop the server"""
        if self.socket:
            self.socket.close()
            self.logger.info("Server stopped")

def main():
    ADHOC_IP = "192.168.1.99"
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('PKI_SERVER')
    
    try:
        gcs = GCS(base_dir="certs")
        logger.info("PKI server initialized")
        
        logger.info("Starting PKI server...")
        gcs.run(host='0.0.0.0', port=5000)
        
    except KeyboardInterrupt:
        logger.info("Shutting down PKI server...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()