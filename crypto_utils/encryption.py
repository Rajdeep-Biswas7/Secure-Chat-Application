"""
crypto_utils/encryption.py
--------------------------
Message-level encryption utilities.

Design goals
────────────
1. The server NEVER sees plaintext. Only the sender encrypts; only the
   intended recipient can decrypt.
2. Modular: the CryptoEngine abstract base class defines the interface so
   the Fernet implementation can be swapped for AES-GCM + ECDH without
   changing any call-site code.
3. Anti-replay: every ciphertext carries a unique nonce / token ID;
   callers supply a seen-ID set to reject replays.

Fernet (symmetric, authenticated encryption)
─────────────────────────────────────────────
• Key derivation  : PBKDF2-HMAC-SHA256  (password → Fernet key)
• Encryption      : AES-128-CBC + HMAC-SHA256  (built into Fernet)
• Nonce / IV      : embedded in the Fernet token (128-bit, CSPRNG)
• Authentication  : HMAC-SHA256 (tamper detection built in)

The "nonce" we expose in the packet is a separate UUID4 (replay-guard ID)
stored alongside the Fernet token. The Fernet token itself already encodes
its own IV, so the combination gives both replay-resistance and AE.

Advanced upgrade path
─────────────────────
Replace FernetEngine with an AesGcmEngine that performs an ECDH key-exchange
on login, derives per-session AES-256-GCM keys, and uses 96-bit random nonces.
The rest of the codebase needs no changes.
"""

from __future__ import annotations

import base64
import os
import uuid
from abc import ABC, abstractmethod
from typing import NamedTuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# ── Data container ────────────────────────────────────────────────────────────

class EncryptedMessage(NamedTuple):
    """
    Wire representation of an encrypted payload.

    ciphertext : base64-encoded Fernet token (already contains IV + HMAC)
    nonce      : UUID4 string used as a replay-guard identifier
    key_hint   : optional label to help the recipient locate the correct key
                 (e.g. session ID or key version tag); never a key itself
    """
    ciphertext: str   # base64url string
    nonce:      str   # UUID4 replay-guard
    key_hint:   str   # opaque label (empty string = no hint)


# ── Abstract interface ────────────────────────────────────────────────────────

class CryptoEngine(ABC):
    """
    Abstract base for all message-level crypto implementations.
    Implementors must be stateless; key material is passed per call.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedMessage:
        """Encrypt *plaintext* under *key*; return an EncryptedMessage."""

    @abstractmethod
    def decrypt(
        self,
        message: EncryptedMessage,
        key: bytes,
        seen_nonces: set[str],
    ) -> bytes:
        """
        Decrypt *message* using *key*.

        Parameters
        ----------
        message      : the EncryptedMessage to decrypt
        key          : symmetric key bytes
        seen_nonces  : mutable set; nonce is added after successful decryption.
                       Raises ReplayError if the nonce is already present.
        """

    @abstractmethod
    def generate_key(self) -> bytes:
        """Generate a fresh random key suitable for this engine."""

    @abstractmethod
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive a deterministic key from a password + salt."""

    @staticmethod
    def generate_salt(length: int = 16) -> bytes:
        """Return *length* cryptographically random bytes."""
        return os.urandom(length)


# ── Exceptions ────────────────────────────────────────────────────────────────

class DecryptionError(Exception):
    """Raised when decryption fails (wrong key, tampered ciphertext, etc.)."""


class ReplayError(Exception):
    """Raised when a nonce has already been seen (replay attack detected)."""


# ── Fernet implementation ─────────────────────────────────────────────────────

class FernetEngine(CryptoEngine):
    """
    Production-ready symmetric AE using the Fernet construction.

    Fernet guarantees:
      - Confidentiality : AES-128-CBC
      - Integrity       : HMAC-SHA256
      - Freshness       : timestamp embedded in token (optional TTL check)
    """

    # PBKDF2 parameters – deliberately expensive to slow brute-force
    _KDF_ITERATIONS = 480_000
    _KEY_LENGTH     = 32  # bytes (256 bits → base64-encoded to 44 chars for Fernet)

    def generate_key(self) -> bytes:
        """Return 32 raw random bytes (use derive_key_from_password for passwords)."""
        return Fernet.generate_key()  # returns URL-safe base64 (32 bytes of entropy)

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive a Fernet-compatible key from *password* + *salt* via PBKDF2-HMAC-SHA256.
        The result is base64url-encoded (Fernet requires this encoding).
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._KEY_LENGTH,
            salt=salt,
            iterations=self._KDF_ITERATIONS,
            backend=default_backend(),
        )
        raw = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw)   # Fernet-ready

    def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedMessage:
        """
        Encrypt *plaintext* under *key*.
        Returns an EncryptedMessage whose ciphertext is the Fernet token
        (base64url string) and nonce is a fresh UUID4 replay-guard.
        """
        try:
            f = Fernet(key)
        except Exception as exc:
            raise ValueError(f"Invalid encryption key: {exc}") from exc

        token    = f.encrypt(plaintext)                     # bytes
        nonce    = str(uuid.uuid4())
        return EncryptedMessage(
            ciphertext=token.decode("utf-8"),
            nonce=nonce,
            key_hint="fernet-v1",
        )

    def decrypt(
        self,
        message: EncryptedMessage,
        key: bytes,
        seen_nonces: set[str],
    ) -> bytes:
        """
        Decrypt *message*.

        Raises
        ------
        ReplayError     if the nonce was already used
        DecryptionError if decryption or MAC verification fails
        """
        if message.nonce in seen_nonces:
            raise ReplayError(f"Replay detected: nonce {message.nonce!r} already used")

        try:
            f         = Fernet(key)
            plaintext = f.decrypt(message.ciphertext.encode("utf-8"))
        except InvalidToken as exc:
            raise DecryptionError("Decryption failed – invalid token or wrong key") from exc
        except Exception as exc:
            raise DecryptionError(f"Unexpected decryption error: {exc}") from exc

        seen_nonces.add(message.nonce)
        return plaintext


# ── Convenience helpers ───────────────────────────────────────────────────────

# Module-level default engine (Fernet). Import this symbol elsewhere.
default_engine: CryptoEngine = FernetEngine()


def encrypt_message(plaintext: str, key: bytes) -> EncryptedMessage:
    """Encrypt a UTF-8 string with the default engine."""
    return default_engine.encrypt(plaintext.encode("utf-8"), key)


def decrypt_message(
    message: EncryptedMessage,
    key: bytes,
    seen_nonces: set[str],
) -> str:
    """Decrypt an EncryptedMessage to a UTF-8 string with the default engine."""
    raw = default_engine.decrypt(message, key, seen_nonces)
    return raw.decode("utf-8")


def generate_session_key() -> bytes:
    """Return a fresh random Fernet key for a new session."""
    return default_engine.generate_key()


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password + salt."""
    return default_engine.derive_key_from_password(password, salt)
