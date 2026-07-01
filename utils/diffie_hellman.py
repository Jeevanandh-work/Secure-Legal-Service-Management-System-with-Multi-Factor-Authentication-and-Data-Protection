"""
Diffie-Hellman Demo Module
Simulates DH key exchange and derives a shared AES key for demonstration.
"""

import base64
from typing import Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh


class DiffieHellmanDemo:
    """Educational DH key exchange helper (not a full production key agreement stack)."""

    _parameters = None

    @classmethod
    def _get_parameters(cls):
        if cls._parameters is None:
            # 2048-bit params are suitable for demo but should be centrally managed in production.
            cls._parameters = dh.generate_parameters(generator=2, key_size=2048)
        return cls._parameters

    def perform_key_exchange(self) -> Dict[str, str]:
        """
        Simulate client-server DH exchange and derive a 32-byte symmetric key.
        Returns base64 strings for easy logging/demo display.
        """
        params = self._get_parameters()

        client_private = params.generate_private_key()
        server_private = params.generate_private_key()

        client_public = client_private.public_key()
        server_public = server_private.public_key()

        shared_client = client_private.exchange(server_public)
        shared_server = server_private.exchange(client_public)

        if shared_client != shared_server:
            raise ValueError("Diffie-Hellman shared secrets do not match")

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"legal-service-dh-demo",
        ).derive(shared_client)

        return {
            "shared_secret_b64": base64.b64encode(shared_client).decode("utf-8"),
            "derived_aes_key_b64": base64.b64encode(derived_key).decode("utf-8"),
            "note": "Demo DH key exchange completed successfully",
        }
