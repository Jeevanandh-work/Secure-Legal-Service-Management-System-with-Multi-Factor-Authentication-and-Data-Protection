"""
RSA and Hybrid Encryption Module
Provides RSA key management and hybrid encryption (AES data key encrypted by RSA).
"""

import os
import json
import base64
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class RSACryptoManager:
    """Manage RSA key-pairs and hybrid encryption/decryption for request data."""

    def __init__(self, private_key_path: str, public_key_path: str, key_size: int = 2048):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self.key_size = key_size

        self._ensure_keypair_exists()
        self.private_key = self._load_private_key()
        self.public_key = self._load_public_key()

    def _ensure_keypair_exists(self):
        """Create an RSA key pair on first run and store as PEM files."""
        key_dir = os.path.dirname(self.private_key_path)
        if key_dir:
            os.makedirs(key_dir, exist_ok=True)

        if os.path.exists(self.private_key_path) and os.path.exists(self.public_key_path):
            return

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=self.key_size)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(self.private_key_path, "wb") as f:
            f.write(private_pem)
        with open(self.public_key_path, "wb") as f:
            f.write(public_pem)

    def _load_private_key(self):
        with open(self.private_key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _load_public_key(self):
        with open(self.public_key_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def hybrid_encrypt_text(self, plaintext: str) -> Dict[str, Any]:
        """
        Hybrid encryption:
        1) Encrypt plaintext using random AES-256-GCM data key.
        2) Encrypt AES data key with RSA public key.
        """
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext

        data_key = os.urandom(32)
        nonce = os.urandom(12)
        aesgcm = AESGCM(data_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)

        encrypted_data_key = self.public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return {
            "scheme": "RSA-OAEP+AES-256-GCM",
            "encrypted_key": base64.b64encode(encrypted_data_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        }

    def hybrid_decrypt_text(self, payload: Dict[str, Any]) -> str:
        """Decrypt hybrid payload created by hybrid_encrypt_text."""
        encrypted_data_key = base64.b64decode(payload["encrypted_key"])
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])

        data_key = self.private_key.decrypt(
            encrypted_data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        aesgcm = AESGCM(data_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    @staticmethod
    def to_json(payload: Dict[str, Any]) -> str:
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_json(payload_str: str) -> Dict[str, Any]:
        return json.loads(payload_str)
