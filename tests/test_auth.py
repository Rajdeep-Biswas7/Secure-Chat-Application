"""
tests/test_auth.py
------------------
Unit tests for auth/auth.py

Uses a temporary SQLite database isolated per test session.
"""

import os
import tempfile
import pytest

# Point all DB calls at a temp file before importing auth
_TMP_DB = tempfile.mktemp(suffix=".db")
os.environ["DATABASE_PATH"] = _TMP_DB

from database.db import init_db
from auth.auth import (
    register_user,
    login_user,
    logout_user,
    RegistrationError,
    AuthenticationError,
)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    """Initialise the temp database once for the whole module."""
    init_db(_TMP_DB)
    yield
    try:
        os.unlink(_TMP_DB)
    except FileNotFoundError:
        pass


# ── Registration ──────────────────────────────────────────────────────────────

class TestRegistration:
    def test_register_returns_user_id_and_salt(self):
        result = register_user("alice", "StrongPass1!")
        assert "user_id"  in result
        assert "kdf_salt" in result
        assert len(result["kdf_salt"]) == 32   # 16-byte hex

    def test_register_duplicate_raises(self):
        register_user("bob", "StrongPass2!")
        with pytest.raises(RegistrationError):
            register_user("bob", "AnotherPass3!")

    def test_register_short_password_raises(self):
        with pytest.raises(RegistrationError):
            register_user("charlie", "short")

    def test_register_empty_username_raises(self):
        with pytest.raises(RegistrationError):
            register_user("", "ValidPassword1!")

    def test_register_special_username_chars_raises(self):
        with pytest.raises(RegistrationError):
            register_user("user name!", "ValidPassword1!")

    def test_register_long_username_raises(self):
        with pytest.raises(RegistrationError):
            register_user("a" * 65, "ValidPassword1!")

    def test_register_long_password_raises(self):
        with pytest.raises(RegistrationError):
            register_user("dave", "x" * 200)


# ── Login ─────────────────────────────────────────────────────────────────────

class TestLogin:
    def setup_method(self):
        # Register a fresh user for each test
        try:
            register_user("loginuser", "CorrectHorse1!")
        except RegistrationError:
            pass  # already exists from a prior test

    def test_login_success(self):
        result = login_user("loginuser", "CorrectHorse1!")
        assert "session_id" in result
        assert "user_id"    in result
        assert "kdf_salt"   in result

    def test_login_wrong_password_raises(self):
        with pytest.raises(AuthenticationError):
            login_user("loginuser", "WrongPassword!")

    def test_login_nonexistent_user_raises(self):
        with pytest.raises(AuthenticationError):
            login_user("nobody_here", "SomePassword1!")

    def test_login_empty_password_raises(self):
        with pytest.raises((AuthenticationError, RegistrationError)):
            login_user("loginuser", "")

    def test_kdf_salt_consistent(self):
        r1 = login_user("loginuser", "CorrectHorse1!")
        r2 = login_user("loginuser", "CorrectHorse1!")
        assert r1["kdf_salt"] == r2["kdf_salt"]


# ── Logout ────────────────────────────────────────────────────────────────────

class TestLogout:
    def test_logout_does_not_raise(self):
        register_user("logoutuser", "LogoutPass1!")
        result     = login_user("logoutuser", "LogoutPass1!")
        session_id = result["session_id"]
        logout_user(session_id)   # should not raise

    def test_logout_invalid_session_does_not_raise(self):
        logout_user("00000000-0000-0000-0000-000000000000")
