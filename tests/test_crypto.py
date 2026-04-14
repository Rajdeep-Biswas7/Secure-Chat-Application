"""
tests/test_crypto.py
--------------------
Unit tests for crypto_utils/encryption.py

Coverage
────────
  • Key generation and derivation
  • Encrypt → decrypt round-trip
  • Replay detection (nonce reuse)
  • Tampered ciphertext detection
  • Wrong key rejection
  • EncryptedMessage field presence
"""

import os
import pytest

from crypto_utils.encryption import (
    FernetEngine,
    EncryptedMessage,
    DecryptionError,
    ReplayError,
    encrypt_message,
    decrypt_message,
    generate_session_key,
    derive_key,
)


@pytest.fixture
def engine() -> FernetEngine:
    return FernetEngine()


@pytest.fixture
def key(engine) -> bytes:
    return engine.generate_key()


# ── Key generation ────────────────────────────────────────────────────────────

class TestKeyGeneration:
    def test_generate_key_returns_bytes(self, engine):
        k = engine.generate_key()
        assert isinstance(k, bytes)
        assert len(k) == 44  # URL-safe base64 of 32 bytes

    def test_generate_key_uniqueness(self, engine):
        keys = {engine.generate_key() for _ in range(50)}
        assert len(keys) == 50, "Keys should be unique"

    def test_derive_key_from_password(self, engine):
        salt = os.urandom(16)
        k1   = engine.derive_key_from_password("s3cr3tPass!", salt)
        k2   = engine.derive_key_from_password("s3cr3tPass!", salt)
        assert k1 == k2, "Same password+salt must yield identical key"

    def test_derive_key_different_salts(self, engine):
        s1, s2 = os.urandom(16), os.urandom(16)
        k1 = engine.derive_key_from_password("password", s1)
        k2 = engine.derive_key_from_password("password", s2)
        assert k1 != k2, "Different salts must produce different keys"

    def test_derive_key_different_passwords(self, engine):
        salt = os.urandom(16)
        k1   = engine.derive_key_from_password("PasswordA", salt)
        k2   = engine.derive_key_from_password("PasswordB", salt)
        assert k1 != k2

    def test_generate_salt(self, engine):
        s = engine.generate_salt()
        assert len(s) == 16
        assert engine.generate_salt() != engine.generate_salt()


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

class TestEncryptDecrypt:
    def test_round_trip_bytes(self, engine, key):
        plaintext = b"Hello, secure world!"
        enc       = engine.encrypt(plaintext, key)
        dec       = engine.decrypt(enc, key, set())
        assert dec == plaintext

    def test_round_trip_unicode(self, engine, key):
        text      = "こんにちは世界 – 🔐"
        enc       = engine.encrypt(text.encode("utf-8"), key)
        dec       = engine.decrypt(enc, key, set()).decode("utf-8")
        assert dec == text

    def test_round_trip_empty(self, engine, key):
        enc = engine.encrypt(b"", key)
        dec = engine.decrypt(enc, key, set())
        assert dec == b""

    def test_round_trip_large_payload(self, engine, key):
        payload = os.urandom(32_768)  # 32 KiB
        enc     = engine.encrypt(payload, key)
        dec     = engine.decrypt(enc, key, set())
        assert dec == payload

    def test_encrypted_message_fields(self, engine, key):
        enc = engine.encrypt(b"test", key)
        assert isinstance(enc, EncryptedMessage)
        assert enc.ciphertext
        assert enc.nonce
        assert enc.key_hint == "fernet-v1"

    def test_ciphertexts_are_unique(self, engine, key):
        enc1 = engine.encrypt(b"same plaintext", key)
        enc2 = engine.encrypt(b"same plaintext", key)
        # Fernet includes a random IV so ciphertexts must differ
        assert enc1.ciphertext != enc2.ciphertext
        assert enc1.nonce      != enc2.nonce

    def test_wrong_key_raises(self, engine, key):
        enc     = engine.encrypt(b"secret", key)
        bad_key = engine.generate_key()
        with pytest.raises(DecryptionError):
            engine.decrypt(enc, bad_key, set())

    def test_tampered_ciphertext_raises(self, engine, key):
        enc     = engine.encrypt(b"secret", key)
        # Flip a character in the ciphertext
        bad_ct  = enc.ciphertext[:-4] + "XXXX"
        bad_enc = EncryptedMessage(bad_ct, enc.nonce, enc.key_hint)
        with pytest.raises(DecryptionError):
            engine.decrypt(bad_enc, key, set())

    def test_empty_ciphertext_raises(self, engine, key):
        bad_enc = EncryptedMessage("", "some-nonce", "fernet-v1")
        with pytest.raises(DecryptionError):
            engine.decrypt(bad_enc, key, set())


# ── Replay detection ─────────────────────────────────────────────────────────

class TestReplayDetection:
    def test_replay_raises_on_second_use(self, engine, key):
        enc  = engine.encrypt(b"msg", key)
        seen = set()
        engine.decrypt(enc, key, seen)          # first use: OK
        with pytest.raises(ReplayError):
            engine.decrypt(enc, key, seen)      # second use: replay

    def test_nonce_added_to_seen_set(self, engine, key):
        enc  = engine.encrypt(b"msg", key)
        seen = set()
        engine.decrypt(enc, key, seen)
        assert enc.nonce in seen

    def test_different_nonces_accepted(self, engine, key):
        enc1 = engine.encrypt(b"msg1", key)
        enc2 = engine.encrypt(b"msg2", key)
        seen = set()
        r1   = engine.decrypt(enc1, key, seen)
        r2   = engine.decrypt(enc2, key, seen)
        assert r1 == b"msg1"
        assert r2 == b"msg2"


# ── Module-level helpers ──────────────────────────────────────────────────────

class TestHelpers:
    def test_encrypt_decrypt_helpers(self):
        key   = generate_session_key()
        seen  = set()
        enc   = encrypt_message("hello world", key)
        plain = decrypt_message(enc, key, seen)
        assert plain == "hello world"

    def test_derive_key_helper(self):
        salt  = os.urandom(16)
        k1    = derive_key("mypass", salt)
        k2    = derive_key("mypass", salt)
        assert k1 == k2
