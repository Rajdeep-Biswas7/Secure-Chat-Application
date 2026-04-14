#!/usr/bin/env python3
"""
run_tests.py
------------
Lightweight test runner — no external test framework required.
Uses Python's built-in unittest module.

All tests mirror the pytest test files but are expressed as unittest.TestCase
subclasses so they run with zero extra dependencies.

Run:
    python run_tests.py              # all suites
    python run_tests.py crypto       # crypto suite only
    python run_tests.py protocol     # protocol suite
    python run_tests.py auth         # auth suite
    python run_tests.py database     # database suite
"""

import hashlib
import os
import struct
import sys
import tempfile
import time
import unittest
import uuid

# ── Ensure project root is on the path ────────────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# ── Shared temp DB for auth / database tests ──────────────────────────────────
_TMP_DB = tempfile.mktemp(suffix="_test.db")
os.environ.setdefault("DATABASE_PATH", _TMP_DB)
os.environ.setdefault("SERVER_CERT",   "certs/server.crt")
os.environ.setdefault("SERVER_KEY",    "certs/server.key")
os.environ.setdefault("CA_CERT",       "certs/server.crt")
os.environ.setdefault("LOG_FILE",      "")   # suppress file logging during tests

# ──────────────────────────────────────────────────────────────────────────────
#  CRYPTO TESTS
# ──────────────────────────────────────────────────────────────────────────────

class TestKeyGeneration(unittest.TestCase):
    def setUp(self):
        from crypto_utils.encryption import FernetEngine
        self.engine = FernetEngine()

    def test_generate_key_returns_bytes(self):
        k = self.engine.generate_key()
        self.assertIsInstance(k, bytes)
        self.assertEqual(len(k), 44)

    def test_generate_key_uniqueness(self):
        keys = {self.engine.generate_key() for _ in range(20)}
        self.assertEqual(len(keys), 20)

    def test_derive_key_deterministic(self):
        salt = os.urandom(16)
        k1   = self.engine.derive_key_from_password("pass123", salt)
        k2   = self.engine.derive_key_from_password("pass123", salt)
        self.assertEqual(k1, k2)

    def test_derive_key_different_salts(self):
        s1, s2 = os.urandom(16), os.urandom(16)
        k1     = self.engine.derive_key_from_password("password", s1)
        k2     = self.engine.derive_key_from_password("password", s2)
        self.assertNotEqual(k1, k2)

    def test_generate_salt_randomness(self):
        s1 = self.engine.generate_salt()
        s2 = self.engine.generate_salt()
        self.assertNotEqual(s1, s2)
        self.assertEqual(len(s1), 16)


class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        from crypto_utils.encryption import FernetEngine
        self.engine = FernetEngine()
        self.key    = self.engine.generate_key()

    def test_round_trip_bytes(self):
        plaintext = b"Hello, secure world!"
        enc       = self.engine.encrypt(plaintext, self.key)
        dec       = self.engine.decrypt(enc, self.key, set())
        self.assertEqual(dec, plaintext)

    def test_round_trip_unicode(self):
        text = "こんにちは世界"
        enc  = self.engine.encrypt(text.encode("utf-8"), self.key)
        dec  = self.engine.decrypt(enc, self.key, set()).decode("utf-8")
        self.assertEqual(dec, text)

    def test_round_trip_empty(self):
        enc = self.engine.encrypt(b"", self.key)
        dec = self.engine.decrypt(enc, self.key, set())
        self.assertEqual(dec, b"")

    def test_round_trip_large_payload(self):
        payload = os.urandom(16_384)
        enc     = self.engine.encrypt(payload, self.key)
        dec     = self.engine.decrypt(enc, self.key, set())
        self.assertEqual(dec, payload)

    def test_ciphertexts_are_unique(self):
        enc1 = self.engine.encrypt(b"same", self.key)
        enc2 = self.engine.encrypt(b"same", self.key)
        self.assertNotEqual(enc1.ciphertext, enc2.ciphertext)
        self.assertNotEqual(enc1.nonce,      enc2.nonce)

    def test_wrong_key_raises(self):
        from crypto_utils.encryption import DecryptionError
        enc     = self.engine.encrypt(b"secret", self.key)
        bad_key = self.engine.generate_key()
        with self.assertRaises(DecryptionError):
            self.engine.decrypt(enc, bad_key, set())

    def test_tampered_ciphertext_raises(self):
        from crypto_utils.encryption import DecryptionError, EncryptedMessage
        enc     = self.engine.encrypt(b"secret", self.key)
        bad_enc = EncryptedMessage(enc.ciphertext[:-4] + "XXXX", enc.nonce, enc.key_hint)
        with self.assertRaises(DecryptionError):
            self.engine.decrypt(bad_enc, self.key, set())


class TestReplayDetection(unittest.TestCase):
    def setUp(self):
        from crypto_utils.encryption import FernetEngine
        self.engine = FernetEngine()
        self.key    = self.engine.generate_key()

    def test_replay_raises_on_second_use(self):
        from crypto_utils.encryption import ReplayError
        enc  = self.engine.encrypt(b"msg", self.key)
        seen = set()
        self.engine.decrypt(enc, self.key, seen)
        with self.assertRaises(ReplayError):
            self.engine.decrypt(enc, self.key, seen)

    def test_nonce_added_to_seen_set(self):
        enc  = self.engine.encrypt(b"msg", self.key)
        seen = set()
        self.engine.decrypt(enc, self.key, seen)
        self.assertIn(enc.nonce, seen)

    def test_different_nonces_accepted(self):
        enc1 = self.engine.encrypt(b"msg1", self.key)
        enc2 = self.engine.encrypt(b"msg2", self.key)
        seen = set()
        r1   = self.engine.decrypt(enc1, self.key, seen)
        r2   = self.engine.decrypt(enc2, self.key, seen)
        self.assertEqual(r1, b"msg1")
        self.assertEqual(r2, b"msg2")


class TestCryptoHelpers(unittest.TestCase):
    def test_encrypt_decrypt_helpers(self):
        from crypto_utils.encryption import (
            encrypt_message, decrypt_message, generate_session_key
        )
        key   = generate_session_key()
        seen  = set()
        enc   = encrypt_message("hello world", key)
        plain = decrypt_message(enc, key, seen)
        self.assertEqual(plain, "hello world")

    def test_derive_key_helper(self):
        from crypto_utils.encryption import derive_key
        salt = os.urandom(16)
        k1   = derive_key("mypass", salt)
        k2   = derive_key("mypass", salt)
        self.assertEqual(k1, k2)


# ──────────────────────────────────────────────────────────────────────────────
#  PROTOCOL TESTS
# ──────────────────────────────────────────────────────────────────────────────

class TestMakePacket(unittest.TestCase):
    def setUp(self):
        from protocol.messages import MessageType, make_packet
        self.make   = make_packet
        self.MT     = MessageType

    def test_has_required_fields(self):
        p = self.make(self.MT.PING, {})
        for f in ("type", "msg_id", "timestamp", "payload"):
            self.assertIn(f, p)

    def test_type_is_string(self):
        p = self.make(self.MT.LOGIN, {"username": "x", "password_hash": "y"})
        self.assertEqual(p["type"], "login")

    def test_msg_id_is_uuid4(self):
        p = self.make(self.MT.PING, {})
        uid = uuid.UUID(p["msg_id"], version=4)
        self.assertEqual(uid.version, 4)

    def test_timestamp_is_recent(self):
        p   = self.make(self.MT.PING, {})
        now = time.time()
        self.assertLess(abs(p["timestamp"] - now), 2.0)

    def test_payload_preserved(self):
        payload = {"username": "alice", "password_hash": "abc"}
        p       = self.make(self.MT.LOGIN, payload)
        self.assertEqual(p["payload"], payload)


class TestEncodeDecodePacket(unittest.TestCase):
    def setUp(self):
        from protocol.messages import MessageType, make_packet, encode_packet, decode_packet
        self.make   = make_packet
        self.encode = encode_packet
        self.decode = decode_packet
        self.MT     = MessageType

    def test_round_trip(self):
        original = self.make(self.MT.PING, {})
        encoded  = self.encode(original)
        body     = encoded[4:]
        decoded  = self.decode(body)
        self.assertEqual(decoded, original)

    def test_length_header_correct(self):
        p   = self.make(self.MT.PING, {})
        enc = self.encode(p)
        declared_len = struct.unpack(">I", enc[:4])[0]
        self.assertEqual(declared_len, len(enc) - 4)

    def test_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            self.decode(b"not valid json {{{{")


class TestValidatePacket(unittest.TestCase):
    def setUp(self):
        from protocol.messages import (
            MessageType, ErrorCode, ProtocolError,
            make_packet, validate_packet,
        )
        self.make     = make_packet
        self.validate = validate_packet
        self.MT       = MessageType
        self.EC       = ErrorCode
        self.PE       = ProtocolError

    def test_valid_ping(self):
        p = self.make(self.MT.PING, {})
        self.validate(p)  # no exception

    def test_valid_login(self):
        p = self.make(self.MT.LOGIN, {"username": "alice", "password_hash": "pw"})
        self.validate(p)

    def test_valid_direct_message(self):
        p = self.make(self.MT.DIRECT_MESSAGE, {"to": "bob", "ciphertext": "ct", "nonce": "n"})
        self.validate(p)

    def test_missing_envelope_field_type(self):
        p = self.make(self.MT.PING, {})
        del p["type"]
        with self.assertRaises(self.PE) as cm:
            self.validate(p)
        self.assertEqual(cm.exception.code, self.EC.MALFORMED_PACKET)

    def test_unknown_message_type(self):
        p         = self.make(self.MT.PING, {})
        p["type"] = "nonexistent_type"
        with self.assertRaises(self.PE) as cm:
            self.validate(p)
        self.assertEqual(cm.exception.code, self.EC.MALFORMED_PACKET)

    def test_missing_login_username(self):
        p = self.make(self.MT.LOGIN, {"password_hash": "pw"})
        with self.assertRaises(self.PE) as cm:
            self.validate(p)
        self.assertEqual(cm.exception.code, self.EC.INVALID_PAYLOAD)

    def test_timestamp_too_old(self):
        p              = self.make(self.MT.PING, {})
        p["timestamp"] = time.time() - 90_000
        with self.assertRaises(self.PE) as cm:
            self.validate(p)
        self.assertEqual(cm.exception.code, self.EC.MALFORMED_PACKET)

    def test_payload_not_dict(self):
        p            = self.make(self.MT.PING, {})
        p["payload"] = ["not", "a", "dict"]
        with self.assertRaises(self.PE) as cm:
            self.validate(p)
        self.assertEqual(cm.exception.code, self.EC.MALFORMED_PACKET)


# ──────────────────────────────────────────────────────────────────────────────
#  AUTH TESTS
# ──────────────────────────────────────────────────────────────────────────────

def _init_test_db():
    from database.db import init_db
    init_db(_TMP_DB)

_init_test_db()


class TestRegistration(unittest.TestCase):
    def test_register_returns_user_id_and_salt(self):
        from auth.auth import register_user
        result = register_user(f"reg_{os.urandom(3).hex()}", "StrongPass1!")
        self.assertIn("user_id",  result)
        self.assertIn("kdf_salt", result)
        self.assertEqual(len(result["kdf_salt"]), 32)  # 16-byte hex = 32 chars

    def test_register_duplicate_raises(self):
        from auth.auth import register_user, RegistrationError
        uname = f"dup_{os.urandom(3).hex()}"
        register_user(uname, "StrongPass1!")
        with self.assertRaises(RegistrationError):
            register_user(uname, "AnotherPass2!")

    def test_register_short_password_raises(self):
        from auth.auth import register_user, RegistrationError
        with self.assertRaises(RegistrationError):
            register_user(f"u_{os.urandom(3).hex()}", "short")

    def test_register_empty_username_raises(self):
        from auth.auth import register_user, RegistrationError
        with self.assertRaises(RegistrationError):
            register_user("", "ValidPassword1!")

    def test_register_special_chars_raises(self):
        from auth.auth import register_user, RegistrationError
        with self.assertRaises(RegistrationError):
            register_user("user name!", "ValidPassword1!")


class TestLogin(unittest.TestCase):
    def setUp(self):
        from auth.auth import register_user, RegistrationError
        self.uname = f"login_{os.urandom(3).hex()}"
        self.pwd   = "CorrectHorse1!"
        try:
            register_user(self.uname, self.pwd)
        except RegistrationError:
            pass

    def test_login_success(self):
        from auth.auth import login_user
        result = login_user(self.uname, self.pwd)
        self.assertIn("session_id", result)
        self.assertIn("user_id",    result)
        self.assertIn("kdf_salt",   result)

    def test_login_wrong_password_raises(self):
        from auth.auth import login_user, AuthenticationError
        with self.assertRaises(AuthenticationError):
            login_user(self.uname, "WrongPassword!")

    def test_login_nonexistent_user_raises(self):
        from auth.auth import login_user, AuthenticationError
        with self.assertRaises(AuthenticationError):
            login_user("nobody_here_xyz", "SomePassword1!")

    def test_kdf_salt_consistent(self):
        from auth.auth import login_user
        r1 = login_user(self.uname, self.pwd)
        r2 = login_user(self.uname, self.pwd)
        self.assertEqual(r1["kdf_salt"], r2["kdf_salt"])


class TestLogout(unittest.TestCase):
    def test_logout_does_not_raise(self):
        from auth.auth import register_user, login_user, logout_user, RegistrationError
        uname = f"lo_{os.urandom(3).hex()}"
        register_user(uname, "LogoutPass1!")
        result = login_user(uname, "LogoutPass1!")
        logout_user(result["session_id"])  # must not raise

    def test_logout_invalid_session_does_not_raise(self):
        from auth.auth import logout_user
        logout_user("00000000-0000-0000-0000-000000000000")


# ──────────────────────────────────────────────────────────────────────────────
#  DATABASE TESTS
# ──────────────────────────────────────────────────────────────────────────────

class TestUsers(unittest.TestCase):
    def test_create_and_fetch_user(self):
        from database.db import create_user, get_user_by_username
        uname = f"dbuser_{os.urandom(3).hex()}"
        uid   = create_user(uname, "hash1", "salt1", _TMP_DB)
        row   = get_user_by_username(uname, _TMP_DB)
        self.assertIsNotNone(row)
        self.assertEqual(row["user_id"],  uid)
        self.assertEqual(row["pwd_hash"], "hash1")

    def test_get_nonexistent_user_returns_none(self):
        from database.db import get_user_by_username
        row = get_user_by_username("ghost_xyz_1234", _TMP_DB)
        self.assertIsNone(row)

    def test_create_duplicate_user_raises(self):
        from database.db import create_user
        uname = f"dupdb_{os.urandom(3).hex()}"
        create_user(uname, "h", "s", _TMP_DB)
        with self.assertRaises(Exception):
            create_user(uname, "h2", "s2", _TMP_DB)


class TestMessages(unittest.TestCase):
    def setUp(self):
        from database.db import create_user
        self.uname1 = f"msgu_{os.urandom(3).hex()}"
        self.uname2 = f"msgt_{os.urandom(3).hex()}"
        self.uid1   = create_user(self.uname1, "h", "s", _TMP_DB)
        self.uid2   = create_user(self.uname2, "h", "s", _TMP_DB)

    def test_store_and_retrieve_pending(self):
        from database.db import store_message, get_pending_messages
        mid = f"msg-{os.urandom(4).hex()}"
        store_message(mid, self.uid1, self.uname2, "direct", "ciphertxt", "nonce1", db_path=_TMP_DB)
        pending = get_pending_messages(self.uname2, _TMP_DB)
        ids     = [r["msg_id"] for r in pending]
        self.assertIn(mid, ids)

    def test_mark_delivered_removes_from_pending(self):
        from database.db import store_message, get_pending_messages, mark_delivered
        mid = f"msg-{os.urandom(4).hex()}"
        store_message(mid, self.uid1, self.uname2, "direct", "ct", "nonce2", db_path=_TMP_DB)
        mark_delivered(mid, _TMP_DB)
        pending = get_pending_messages(self.uname2, _TMP_DB)
        self.assertNotIn(mid, [r["msg_id"] for r in pending])


class TestGroups(unittest.TestCase):
    def setUp(self):
        from database.db import create_user
        self.uname = f"grpu_{os.urandom(3).hex()}"
        self.uid   = create_user(self.uname, "h", "s", _TMP_DB)

    def test_create_and_fetch_group(self):
        from database.db import create_group, get_group_by_name
        gname = f"grp_{os.urandom(3).hex()}"
        gid   = create_group(gname, self.uid, _TMP_DB)
        row   = get_group_by_name(gname, _TMP_DB)
        self.assertIsNotNone(row)
        self.assertEqual(row["group_id"], gid)

    def test_creator_is_member(self):
        from database.db import create_group, get_group_members
        gname = f"grp_{os.urandom(3).hex()}"
        create_group(gname, self.uid, _TMP_DB)
        members = get_group_members(gname, _TMP_DB)
        self.assertIn(self.uname, members)

    def test_add_member(self):
        from database.db import create_group, create_user, add_group_member, get_group_members
        gname  = f"grp_{os.urandom(3).hex()}"
        create_group(gname, self.uid, _TMP_DB)
        uname2 = f"mem_{os.urandom(3).hex()}"
        create_user(uname2, "h", "s", _TMP_DB)
        add_group_member(gname, uname2, _TMP_DB)
        members = get_group_members(gname, _TMP_DB)
        self.assertIn(uname2, members)

    def test_nonexistent_group_returns_none(self):
        from database.db import get_group_by_name
        row = get_group_by_name("no_such_group_xyz_abc", _TMP_DB)
        self.assertIsNone(row)


# ──────────────────────────────────────────────────────────────────────────────
#  Suite builder + runner
# ──────────────────────────────────────────────────────────────────────────────

SUITES = {
    "crypto": [
        TestKeyGeneration,
        TestEncryptDecrypt,
        TestReplayDetection,
        TestCryptoHelpers,
    ],
    "protocol": [
        TestMakePacket,
        TestEncodeDecodePacket,
        TestValidatePacket,
    ],
    "auth": [
        TestRegistration,
        TestLogin,
        TestLogout,
    ],
    "database": [
        TestUsers,
        TestMessages,
        TestGroups,
    ],
}


def build_suite(names: list[str]) -> unittest.TestSuite:
    suite = unittest.TestSuite()
    for name in names:
        for cls in SUITES[name]:
            suite.addTests(unittest.TestLoader().loadTestsFromTestCase(cls))
    return suite


def main():
    filter_arg = sys.argv[1] if len(sys.argv) > 1 else None
    if filter_arg and filter_arg not in SUITES:
        print(f"Unknown suite '{filter_arg}'. Available: {list(SUITES)}")
        sys.exit(1)

    suite_names = [filter_arg] if filter_arg else list(SUITES)
    suite       = build_suite(suite_names)

    print(f"\nRunning suites: {', '.join(suite_names)}\n{'─'*50}")
    runner  = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result  = runner.run(suite)

    # Cleanup temp DB
    try:
        os.unlink(_TMP_DB)
    except FileNotFoundError:
        pass

    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
