import socket
import json
import struct
import time
import logging
from typing import Dict, Any, Optional, Tuple
from contextlib import contextmanager
import threading
from queue import Queue, Empty

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TCPDataForwarder:
    """
    A class to handle secure forwarding of encrypted data over TCP connections.
    Supports both client (sender) and server (receiver) functionality.
    """

    def __init__(self, timeout: int = 30, max_retries: int = 3, retry_delay: int = 5):
        """
        Initialize the TCP data forwarder.

        Args:
            timeout: Socket timeout in seconds
            max_retries: Maximum connection retry attempts
            retry_delay: Delay between retry attempts in seconds
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'connection_errors': 0,
            'bytes_sent': 0,
            'bytes_received': 0
        }

    @contextmanager
    def tcp_connection(self, host: str, port: int):
        """
        Context manager for TCP socket connections with proper cleanup.

        Args:
            host: Destination IP address or hostname
            port: Destination port number
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            # Enable TCP keepalive for long-running connections
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            logger.info(f"Connecting to {host}:{port}")
            sock.connect((host, port))
            logger.info(f"Successfully connected to {host}:{port}")

            yield sock

        except socket.timeout:
            logger.error(f"Connection timeout to {host}:{port}")
            self.stats['connection_errors'] += 1
            raise
        except socket.error as e:
            logger.error(f"Socket error connecting to {host}:{port}: {e}")
            self.stats['connection_errors'] += 1
            raise
        finally:
            if sock:
                try:
                    sock.close()
                    logger.info(f"Connection to {host}:{port} closed")
                except:
                    pass

    def _send_message(self, sock: socket.socket, data: bytes) -> bool:
        """
        Send data with length prefix over TCP socket.

        Args:
            sock: Connected socket
            data: Data to send

        Returns:
            True if successful, False otherwise
        """
        try:
            # Send length prefix (4 bytes, big-endian)
            message_length = len(data)
            length_prefix = struct.pack('>I', message_length)

            # Send length prefix
            sock.sendall(length_prefix)

            # Send actual data
            sock.sendall(data)

            self.stats['messages_sent'] += 1
            self.stats['bytes_sent'] += len(data) + 4

            logger.debug(f"Sent {message_length} bytes of data")
            return True

        except socket.error as e:
            logger.error(f"Error sending data: {e}")
            return False

    def _receive_message(self, sock: socket.socket) -> Optional[bytes]:
        """
        Receive data with length prefix from TCP socket.

        Args:
            sock: Connected socket

        Returns:
            Received data or None if error
        """
        try:
            # Receive length prefix (4 bytes)
            length_data = self._receive_exact(sock, 4)
            if not length_data:
                return None

            message_length = struct.unpack('>I', length_data)[0]

            # Validate message length (prevent DoS)
            if message_length > 10 * 1024 * 1024:  # 10MB limit
                logger.error(f"Message too large: {message_length} bytes")
                return None

            # Receive actual message
            data = self._receive_exact(sock, message_length)
            if data:
                self.stats['messages_received'] += 1
                self.stats['bytes_received'] += len(data) + 4
                logger.debug(f"Received {message_length} bytes of data")

            return data

        except socket.error as e:
            logger.error(f"Error receiving data: {e}")
            return None

    def _receive_exact(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
        """
        Receive exact number of bytes from socket.

        Args:
            sock: Connected socket
            num_bytes: Number of bytes to receive

        Returns:
            Received data or None if error
        """
        data = b''
        while len(data) < num_bytes:
            try:
                chunk = sock.recv(num_bytes - len(data))
                if not chunk:
                    logger.error("Connection closed by remote host")
                    return None
                data += chunk
            except socket.error as e:
                logger.error(f"Error receiving data: {e}")
                return None
        return data

    def forward_encrypted_data(self, host: str, port: int, encrypted_package: Dict[str, Any],
                               metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Forward encrypted data to destination server.

        Args:
            host: Destination IP address or hostname
            port: Destination port number
            encrypted_package: Encrypted data package from DataEncryption class
            metadata: Additional metadata to include

        Returns:
            True if successful, False otherwise
        """
        # Prepare the message
        message = {
            'timestamp': time.time(),
            'encrypted_data': encrypted_package,
            'type': 'encrypted_data_forward'
        }

        if metadata:
            message['metadata'] = metadata

        # Serialize message
        try:
            json_data = json.dumps(message, separators=(',', ':'))
            data_bytes = json_data.encode('utf-8')
        except Exception as e:
            logger.error(f"Error serializing message: {e}")
            return False

        # Attempt to send with retries
        for attempt in range(self.max_retries):
            try:
                with self.tcp_connection(host, port) as sock:
                    success = self._send_message(sock, data_bytes)
                    if success:
                        logger.info(f"Successfully forwarded {len(data_bytes)} bytes to {host}:{port}")
                        return True

            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)

        logger.error(f"Failed to forward data after {self.max_retries} attempts")
        return False

    def start_receiver_server(self, host: str, port: int, message_handler,
                              max_connections: int = 10) -> None:
        """
        Start TCP server to receive forwarded encrypted data.

        Args:
            host: Server bind address
            port: Server bind port
            message_handler: Function to handle received messages
            max_connections: Maximum concurrent connections
        """
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_sock.bind((host, port))
            server_sock.listen(max_connections)
            logger.info(f"Server listening on {host}:{port}")

            while True:
                try:
                    client_sock, client_addr = server_sock.accept()
                    logger.info(f"New connection from {client_addr}")

                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr, message_handler)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                except KeyboardInterrupt:
                    logger.info("Server shutdown requested")
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")

        finally:
            server_sock.close()
            logger.info("Server stopped")

    def _handle_client(self, client_sock: socket.socket, client_addr: Tuple[str, int],
                       message_handler) -> None:
        """
        Handle individual client connection.

        Args:
            client_sock: Client socket
            client_addr: Client address tuple
            message_handler: Function to process received messages
        """
        try:
            client_sock.settimeout(self.timeout)

            while True:
                data = self._receive_message(client_sock)
                if not data:
                    break

                try:
                    message = json.loads(data.decode('utf-8'))
                    logger.info(f"Received message from {client_addr}: {len(data)} bytes")

                    # Call the message handler
                    response = message_handler(message, client_addr)

                    # Send response if handler returns one
                    if response:
                        response_data = json.dumps(response).encode('utf-8')
                        self._send_message(client_sock, response_data)

                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON from {client_addr}: {e}")
                except Exception as e:
                    logger.error(f"Error handling message from {client_addr}: {e}")

        except Exception as e:
            logger.error(f"Error in client handler for {client_addr}: {e}")
        finally:
            client_sock.close()
            logger.info(f"Connection with {client_addr} closed")

    def get_stats(self) -> Dict[str, int]:
        """Get connection and transfer statistics."""
        return self.stats.copy()

# Example usage and demonstration
def example_message_handler(message: Dict[str, Any], client_addr: Tuple[str, int]) -> Optional[Dict]:
    """
    Example handler for received encrypted messages.

    Args:
        message: Received message dictionary
        client_addr: Client address tuple

    Returns:
        Optional response dictionary
    """
    logger.info(f"Processing message from {client_addr[0]}:{client_addr[1]}")

    if message.get('type') == 'encrypted_data_forward':
        encrypted_data = message.get('encrypted_data', {})
        timestamp = message.get('timestamp')

        logger.info(f"Received encrypted data package:")
        logger.info(f"  - Timestamp: {time.ctime(timestamp) if timestamp else 'Unknown'}")
        logger.info(f"  - Encryption method: {encrypted_data.get('encryption_method', 'Unknown')}")
        logger.info(f"  - Data size: {len(encrypted_data.get('encrypted_data', ''))} chars")

        # Here you would typically decrypt the data using your DataEncryption class
        # and process the original captured prefixes and metadata

        return {
            'status': 'received',
            'timestamp': time.time(),
            'message': 'Encrypted data received successfully'
        }

    return None

def demonstrate_tcp_forwarding():
    """Demonstrate TCP data forwarding functionality."""

    # Example encrypted package (would come from DataEncryption class)
    sample_encrypted_package = {
        'encrypted_data': 'gAAAAABh1234567890abcdef...',  # Base64 encrypted data
        'encryption_method': 'Fernet (AES-128-CBC + HMAC-SHA256)',
        'data_format': 'base64',
        'salt': 'MTIzNDU2Nzg5MGFiY2RlZg==',
        'key_derivation': 'PBKDF2-SHA256'
    }

    # Initialize forwarder
    forwarder = TCPDataForwarder(timeout=10, max_retries=2, retry_delay=3)

    print("=== TCP Data Forwarding Demonstration ===\n")

    # Example 1: Forward data (this would fail without a server running)
    print("1. Attempting to forward encrypted data...")

    success = forwarder.forward_encrypted_data(
        host='127.0.0.1',
        port=8888,
        encrypted_package=sample_encrypted_package,
        metadata={
            'source_system': 'capture-node-01',
            'data_type': 'network_prefixes',
            'urgency': 'normal'
        }
    )

    print(f"Forward attempt result: {'Success' if success else 'Failed (expected without server)'}")

    # Show statistics
    stats = forwarder.get_stats()
    print(f"\nForwarder Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print("\n" + "="*50)
    print("2. To run a receiver server, use:")
    print("""
# Start receiver server
forwarder = TCPDataForwarder()
forwarder.start_receiver_server('0.0.0.0', 8888, example_message_handler)
    """)

    return forwarder

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'server':
        # Run as server
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
        forwarder = TCPDataForwarder()
        print(f"Starting receiver server on port {port}...")
        try:
            forwarder.start_receiver_server('0.0.0.0', port, example_message_handler)
        except KeyboardInterrupt:
            print("\nServer stopped by user")
    else:
        # Run demonstration
        demonstrate_tcp_forwarding()