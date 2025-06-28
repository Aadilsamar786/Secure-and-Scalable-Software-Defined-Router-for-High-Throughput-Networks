import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Dict, Any, Union

class DataEncryption:
    """
    A class to handle symmetric encryption of captured data using AES via Fernet.
    Fernet provides AES 128 encryption in CBC mode with PKCS7 padding and HMAC SHA256 for authentication.
    """

    def __init__(self, password: str = None, salt: bytes = None):
        """
        Initialize the encryption handler.

        Args:
            password: Password for key derivation. If None, generates a random key.
            salt: Salt for key derivation. If None, generates random salt.
        """
        if password:
            if salt is None:
                salt = os.urandom(16)  # Generate random 16-byte salt
            self.salt = salt
            self.key = self._derive_key_from_password(password, salt)
        else:
            self.key = Fernet.generate_key()
            self.salt = None

        self.cipher = Fernet(self.key)

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Recommended minimum iterations
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    def encrypt_data(self, data: Union[Dict[Any, Any], str, bytes]) -> Dict[str, str]:
        """
        Encrypt structured data (typically JSON serializable data).

        Args:
            data: Data to encrypt (dict, string, or bytes)

        Returns:
            Dictionary containing encrypted data and metadata
        """
        # Convert data to JSON string if it's a dictionary
        if isinstance(data, dict):
            json_data = json.dumps(data, separators=(',', ':'))
        elif isinstance(data, str):
            json_data = data
        elif isinstance(data, bytes):
            json_data = data.decode('utf-8')
        else:
            json_data = json.dumps(data)

        # Encrypt the data
        encrypted_data = self.cipher.encrypt(json_data.encode())

        # Prepare result with metadata
        result = {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'encryption_method': 'Fernet (AES-128-CBC + HMAC-SHA256)',
            'data_format': 'base64'
        }

        # Include salt if password-based encryption was used
        if self.salt:
            result['salt'] = base64.b64encode(self.salt).decode('utf-8')
            result['key_derivation'] = 'PBKDF2-SHA256'

        return result

    def decrypt_data(self, encrypted_package: Dict[str, str]) -> Union[Dict[Any, Any], str]:
        """
        Decrypt data from encrypted package.

        Args:
            encrypted_package: Dictionary containing encrypted data and metadata

        Returns:
            Decrypted data (parsed as JSON if possible, otherwise as string)
        """
        # Decode base64 encrypted data
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])

        # Decrypt the data
        decrypted_bytes = self.cipher.decrypt(encrypted_data)
        decrypted_string = decrypted_bytes.decode('utf-8')

        # Try to parse as JSON, return as string if parsing fails
        try:
            return json.loads(decrypted_string)
        except json.JSONDecodeError:
            return decrypted_string

    def get_key_info(self) -> Dict[str, str]:
        """Get information about the encryption key."""
        info = {
            'key_length': f"{len(self.key)} bytes",
            'key_base64': base64.b64encode(self.key).decode('utf-8')
        }

        if self.salt:
            info['uses_password'] = 'Yes'
            info['salt'] = base64.b64encode(self.salt).decode('utf-8')
        else:
            info['uses_password'] = 'No'

        return info

# Example usage and demonstration
def demonstrate_encryption():
    """Demonstrate the encryption functionality with sample data."""

    # Sample captured data structure
    captured_data = {
        'prefixes': [
            {'prefix': '192.168.1.0/24', 'source': 'BGP', 'timestamp': '2024-01-15T10:30:00Z'},
            {'prefix': '10.0.0.0/8', 'source': 'OSPF', 'timestamp': '2024-01-15T10:31:00Z'}
        ],
        'metadata': {
            'capture_time': '2024-01-15T10:30:00Z',
            'source_system': 'router-01',
            'data_type': 'routing_table'
        },
        'statistics': {
            'total_prefixes': 2,
            'unique_sources': 2
        }
    }

    print("=== Data Encryption Demonstration ===\n")

    # Method 1: Random key generation
    print("1. Using randomly generated key:")
    encryptor1 = DataEncryption()
    encrypted_package1 = encryptor1.encrypt_data(captured_data)

    print("Key Info:")
    key_info = encryptor1.get_key_info()
    for k, v in key_info.items():
        if k != 'key_base64':  # Don't print the actual key for security
            print(f"  {k}: {v}")

    print(f"\nEncrypted Package Size: {len(json.dumps(encrypted_package1))} bytes")
    print("Encrypted package keys:", list(encrypted_package1.keys()))

    # Decrypt and verify
    decrypted_data1 = encryptor1.decrypt_data(encrypted_package1)
    print("Decryption successful:", decrypted_data1 == captured_data)

    print("\n" + "="*50 + "\n")

    # Method 2: Password-based encryption
    print("2. Using password-based encryption:")
    password = "SecurePassword123!"
    encryptor2 = DataEncryption(password=password)
    encrypted_package2 = encryptor2.encrypt_data(captured_data)

    print("Key Info:")
    key_info2 = encryptor2.get_key_info()
    for k, v in key_info2.items():
        if k != 'key_base64':
            print(f"  {k}: {v}")

    print(f"\nEncrypted Package Size: {len(json.dumps(encrypted_package2))} bytes")
    print("Encrypted package keys:", list(encrypted_package2.keys()))

    # Demonstrate decryption with same password
    encryptor2_new = DataEncryption(
        password=password,
        salt=base64.b64decode(encrypted_package2['salt'])
    )
    decrypted_data2 = encryptor2_new.decrypt_data(encrypted_package2)
    print("Decryption successful:", decrypted_data2 == captured_data)

    return encrypted_package1, encrypted_package2

if __name__ == "__main__":
    # Run demonstration
    demonstrate_encryption()

    # Example of encrypting simple string data
    print("\n" + "="*50)
    print("3. Encrypting simple string data:")

    simple_encryptor = DataEncryption()
    simple_data = "Sensitive routing information: AS65001 -> 203.0.113.0/24"
    encrypted_simple = simple_encryptor.encrypt_data(simple_data)
    decrypted_simple = simple_encryptor.decrypt_data(encrypted_simple)

    print(f"Original: {simple_data}")
    print(f"Encrypted size: {len(encrypted_simple['encrypted_data'])} characters")
    print(f"Decrypted: {decrypted_simple}")
    print("Match:", simple_data == decrypted_simple)