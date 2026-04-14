"""
auth/auth.py
------------
Authentication and authorisation helpers.

Password hashing
----------------
  Primary:  bcrypt (cost 12) when the `bcrypt` package is installed.
  Fallback: PBKDF2-HMAC-SHA256 (480 000 iterations) for minimal environments.
  Both schemes embed the algorithm tag in the stored string.
  Raw passwords are NEVER stored, logged, or forwarded.

Key derivation salt
-------------------
  A separate 16-byte random salt is stored per user; the CLIENT uses it with
  PBKDF2 to derive its Fernet key.  Server never derives or stores the key.

Session
-------
  On successful login the server returns a session_id (UUID4).
"""

from __future__ import annotations

import hashlib
import hmac
import os

try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

from database.db import (
    create_user, get_user_by_username,
    create_session, invalidate_session, update_last_seen,
)
from shared.config import SESSION_TIMEOUT
from shared.logger import get_logger

log = get_logger(__name__)

_BCRYPT_ROUNDS     = 12
_PBKDF2_ITERATIONS = 480_000
_PBKDF2_DKLEN      = 32


def _hash_password(plaintext: str) -> str:
    if _BCRYPT_AVAILABLE:
        raw = _bcrypt.hashpw(plaintext.encode("utf-8"), _bcrypt.gensalt(rounds=_BCRYPT_ROUNDS))
        return "bcrypt$" + raw.decode("utf-8")
    salt   = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, _PBKDF2_ITERATIONS, dklen=_PBKDF2_DKLEN)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(plaintext: str, stored: str) -> bool:
    if stored.startswith("bcrypt$") and _BCRYPT_AVAILABLE:
        raw = stored[len("bcrypt$"):].encode("utf-8")
        return _bcrypt.checkpw(plaintext.encode("utf-8"), raw)
    if stored.startswith("pbkdf2$"):
        parts = stored.split("$")
        if len(parts) != 4:
            return False
        _, iters_s, salt_hex, digest_hex = parts
        salt     = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual   = hashlib.pbkdf2_hmac("sha256", plaintext.encode("utf-8"), salt, int(iters_s), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    return False


class RegistrationError(Exception):
    pass

class AuthenticationError(Exception):
    pass


def register_user(username: str, plaintext_password: str) -> dict:
    _validate_credentials(username, plaintext_password)
    if get_user_by_username(username) is not None:
        raise RegistrationError(f"Username '{username}' already exists")
    pwd_hash = _hash_password(plaintext_password)
    kdf_salt = os.urandom(16).hex()
    user_id  = create_user(username, pwd_hash, kdf_salt)
    log.info("Registration successful: username=%s", username)
    return {"user_id": user_id, "kdf_salt": kdf_salt}


def login_user(username: str, plaintext_password: str) -> dict:
    _validate_credentials(username, plaintext_password)
    row = get_user_by_username(username)
    if row is None:
        log.warning("Login attempt for unknown user: %s", username)
        raise AuthenticationError("Invalid username or password")
    if not _verify_password(plaintext_password, row["pwd_hash"]):
        log.warning("Failed login attempt: username=%s", username)
        raise AuthenticationError("Invalid username or password")
    session_id = create_session(row["user_id"], ttl_seconds=SESSION_TIMEOUT)
    update_last_seen(row["user_id"])
    log.info("Login successful: username=%s session=%s", username, session_id)
    return {"session_id": session_id, "user_id": row["user_id"], "kdf_salt": row["kdf_salt"]}


def logout_user(session_id: str) -> None:
    invalidate_session(session_id)
    log.info("Session invalidated: session_id=%s", session_id)


def _validate_credentials(username: str, password: str) -> None:
    if not username or not isinstance(username, str):
        raise RegistrationError("Username must be a non-empty string")
    if len(username) > 64:
        raise RegistrationError("Username too long (max 64 characters)")
    if not all(c.isalnum() or c in "-_." for c in username):
        raise RegistrationError("Username may only contain letters, digits, hyphens, underscores, dots")
    if not password or len(password) < 8:
        raise RegistrationError("Password must be at least 8 characters")
    if len(password) > 128:
        raise RegistrationError("Password too long (max 128 characters)")
