"""
AIRC Identity Management

Handles Ed25519 key generation, storage, and request signing.
Developers never touch crypto directly.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
except ImportError:
    raise ImportError("Install cryptography: pip install cryptography")


DEFAULT_KEY_DIR = Path.home() / ".airc" / "keys"


class Identity:
    """
    Manages AIRC identity: keypair generation, storage, and signing.

    Usage:
        identity = Identity("my_agent")
        identity.ensure_keypair()  # Generates if missing, loads if exists
        signature = identity.sign(payload_dict)
    """

    def __init__(self, name: str, key_dir: Optional[Path] = None):
        self.name = name
        self.key_dir = key_dir or DEFAULT_KEY_DIR
        self._private_key: Optional[Ed25519PrivateKey] = None
        self._public_key: Optional[Ed25519PublicKey] = None

    @property
    def key_path(self) -> Path:
        return self.key_dir / f"{self.name}.key"

    @property
    def public_key_path(self) -> Path:
        return self.key_dir / f"{self.name}.pub"

    @property
    def public_key_base64(self) -> str:
        """Public key as base64 string (for registration)."""
        if not self._public_key:
            raise ValueError("No keypair loaded. Call ensure_keypair() first.")
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode()

    def ensure_keypair(self) -> "Identity":
        """Load existing keypair or generate new one."""
        if self.key_path.exists():
            self._load_keypair()
        else:
            self._generate_keypair()
        return self

    def _generate_keypair(self) -> None:
        """Generate new Ed25519 keypair and save to disk."""
        self.key_dir.mkdir(parents=True, exist_ok=True)

        self._private_key = Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        # Save private key (PEM format)
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.key_path.write_bytes(private_pem)
        os.chmod(self.key_path, 0o600)  # Secure permissions

        # Save public key (PEM format)
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_path.write_bytes(public_pem)

    def _load_keypair(self) -> None:
        """Load existing keypair from disk."""
        private_pem = self.key_path.read_bytes()
        self._private_key = serialization.load_pem_private_key(
            private_pem, password=None
        )
        self._public_key = self._private_key.public_key()

    def sign(self, payload: dict) -> str:
        """
        Sign a payload dict using Ed25519.

        Args:
            payload: The request body as a dict

        Returns:
            Base64-encoded signature string
        """
        if not self._private_key:
            raise ValueError("No keypair loaded. Call ensure_keypair() first.")

        # Canonical JSON (sorted keys, no whitespace)
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        message = canonical.encode('utf-8')

        signature = self._private_key.sign(message)
        return base64.b64encode(signature).decode()

    def fingerprint(self) -> str:
        """SHA-256 fingerprint of public key (for verification)."""
        raw = self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()[:16]
