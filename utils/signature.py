"""
Digital Signature Module
Provides request signing and signature verification for tamper detection.
"""

import os
import json
import base64
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


class SignatureManager:
    """Manage per-user RSA signing keys for academic demo."""

    def __init__(self, key_dir: str):
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)

    def _safe_id(self, user_id: str) -> str:
        return "".join(ch for ch in str(user_id) if ch.isalnum() or ch in ("-", "_"))

    def _paths(self, user_id: str) -> Tuple[str, str]:
        safe_id = self._safe_id(user_id)
        private_path = os.path.join(self.key_dir, f"{safe_id}_private.pem")
        public_path = os.path.join(self.key_dir, f"{safe_id}_public.pem")
        return private_path, public_path

    def ensure_user_keypair(self, user_id: str):
        """Create per-user keypair if it does not already exist."""
        private_path, public_path = self._paths(user_id)
        if os.path.exists(private_path) and os.path.exists(public_path):
            return

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        with open(private_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        with open(public_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    def _load_private(self, user_id: str):
        private_path, _ = self._paths(user_id)
        with open(private_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def _load_public(self, user_id: str):
        _, public_path = self._paths(user_id)
        with open(public_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def canonical_payload(payload: Dict[str, Any]) -> bytes:
        """Deterministic JSON serialization to keep signatures stable."""
        canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return canonical_json.encode("utf-8")

    def payload_hash(self, payload: Dict[str, Any]) -> str:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.canonical_payload(payload))
        return base64.b64encode(digest.finalize()).decode("utf-8")

    def sign_payload(self, user_id: str, payload: Dict[str, Any]) -> str:
        """Sign payload using the submitter's private key."""
        self.ensure_user_keypair(user_id)
        private_key = self._load_private(user_id)
        signature = private_key.sign(
            self.canonical_payload(payload),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode("utf-8")

    def verify_payload(self, user_id: str, payload: Dict[str, Any], signature_b64: str) -> bool:
        """Verify payload signature using the submitter's public key."""
        try:
            self.ensure_user_keypair(user_id)
            public_key = self._load_public(user_id)
            signature = base64.b64decode(signature_b64.encode("utf-8"))
            public_key.verify(
                signature,
                self.canonical_payload(payload),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False
