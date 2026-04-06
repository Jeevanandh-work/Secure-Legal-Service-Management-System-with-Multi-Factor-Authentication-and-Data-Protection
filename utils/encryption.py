"""
Encryption Module
Handles AES encryption and decryption of sensitive data (case descriptions)
Uses AES-256 in CBC mode for symmetric encryption
SECURITY: All case descriptions are encrypted before storage in MongoDB
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class EncryptionManager:
    """Manages AES-256 encryption and decryption of sensitive data"""
    
    def __init__(self, encryption_key):
        """
        Initialize encryption manager
        Args:
            encryption_key (bytes): 32-byte key for AES-256 encryption
        """
        if len(encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes (256 bits)")
        self.key = encryption_key
    
    def encrypt(self, plaintext):
        """
        Encrypt plaintext using AES-256-CBC
        
        Security Notes:
        - Each encryption uses a random IV (Initialization Vector)
        - IV is prepended to ciphertext (no need to store separately)
        - Returns base64-encoded ciphertext for safe storage
        
        Args:
            plaintext (str): Text to encrypt (e.g., case description)
        
        Returns:
            str: Base64-encoded encrypted data (IV + ciphertext)
        """
        try:
            # Convert plaintext to bytes if string
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate random 16-byte IV for CBC mode
            iv = os.urandom(16)
            
            # Create cipher object
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Apply PKCS7 padding manually (cryptography library requires this)
            plaintext = self._pad(plaintext)
            
            # Encrypt the plaintext
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            # Prepend IV to ciphertext and encode to base64
            encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
            
            return encrypted_data
        
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data):
        """
        Decrypt AES-256-CBC encrypted data
        
        Security Notes:
        - Extracts IV from the first 16 bytes of decrypted data
        - Validates and removes PKCS7 padding
        - Returns plaintext as string
        
        Args:
            encrypted_data (str): Base64-encoded encrypted data
        
        Returns:
            str: Decrypted plaintext
        """
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract IV (first 16 bytes) and ciphertext (remaining)
            iv = encrypted_bytes[:16]
            ciphertext = encrypted_bytes[16:]
            
            # Create cipher object
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt the ciphertext
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            plaintext = self._unpad(plaintext)
            
            # Return as string
            return plaintext.decode('utf-8')
        
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def _pad(data):
        """
        Apply PKCS7 padding
        Pads data so length is multiple of 16 (AES block size)
        """
        padding_length = 16 - (len(data) % 16)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    @staticmethod
    def _unpad(data):
        """
        Remove PKCS7 padding
        Reads padding length from last byte and validates
        """
        padding_length = data[-1]
        if padding_length > 16 or padding_length == 0:
            raise ValueError("Invalid padding")
        return data[:-padding_length]

# Global encryption manager instance
def get_encryption_manager(key):
    """Factory function to create encryption manager instance"""
    return EncryptionManager(key)
