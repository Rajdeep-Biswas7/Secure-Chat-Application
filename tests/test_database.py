"""
tests/test_database.py
----------------------
Unit tests for database/db.py

Uses an in-memory SQLite database (:memory: path is not used because
multiple connections are needed; instead a temp file is created).
"""

import os
import tempfile
import time
import pytest

_TMP_DB = tempfile.mktemp(suffix=".db")
os.environ["DATABASE_PATH"] = _TMP_DB

from database.db import (
    init_db,
    create_user,
    get_user_by_username,
    update_last_seen,
    create_session,
    invalidate_session,
    store_message,
    get_pending_messages,
    mark_delivered,
    get_message_history,
    create_group,
    get_group_by_name,
    get_group_members,
    add_group_member,
)


@pytest.fixture(scope="module", autouse=True)
def db():
    init_db(_TMP_DB)
    yield
    try:
        os.unlink(_TMP_DB)
    except FileNotFoundError:
        pass


# ── Users ─────────────────────────────────────────────────────────────────────

class TestUsers:
    def test_create_and_fetch_user(self):
        uid = create_user("testuser1", "hash1", "salt1", _TMP_DB)
        row = get_user_by_username("testuser1", _TMP_DB)
        assert row is not None
        assert row["user_id"]  == uid
        assert row["pwd_hash"] == "hash1"
        assert row["kdf_salt"] == "salt1"

    def test_get_nonexistent_user_returns_none(self):
        row = get_user_by_username("ghost", _TMP_DB)
        assert row is None

    def test_create_duplicate_user_raises(self):
        create_user("uniqueuser", "h", "s", _TMP_DB)
        with pytest.raises(Exception):   # sqlite3.IntegrityError
            create_user("uniqueuser", "h2", "s2", _TMP_DB)

    def test_update_last_seen(self):
        uid = create_user("seenuser", "h", "s", _TMP_DB)
        before = get_user_by_username("seenuser", _TMP_DB)["last_seen"]
        time.sleep(0.05)
        update_last_seen(uid, _TMP_DB)
        after  = get_user_by_username("seenuser", _TMP_DB)["last_seen"]
        assert after is not None
        if before is not None:
            assert after > before


# ── Sessions ──────────────────────────────────────────────────────────────────

class TestSessions:
    def test_create_session(self):
        uid = create_user("sessuser", "h", "s", _TMP_DB)
        sid = create_session(uid, ttl_seconds=3600, db_path=_TMP_DB)
        assert sid and len(sid) == 36    # UUID4

    def test_invalidate_session_no_error(self):
        uid = create_user("sessuser2", "h", "s", _TMP_DB)
        sid = create_session(uid, db_path=_TMP_DB)
        invalidate_session(sid, _TMP_DB)  # should not raise


# ── Messages ──────────────────────────────────────────────────────────────────

class TestMessages:
    def setup_method(self):
        self.uname1 = f"msguser_{os.urandom(4).hex()}"
        self.uname2 = f"msgpeer_{os.urandom(4).hex()}"
        self.uid_a  = create_user(self.uname1, "h", "s", _TMP_DB)
        self.uid_b  = create_user(self.uname2, "h", "s", _TMP_DB)

    def test_store_and_retrieve_pending(self):
        mid = f"msg-{os.urandom(4).hex()}"
        store_message(mid, self.uid_a, self.uname2, "direct", "ciphertxt", "nonce1", db_path=_TMP_DB)
        pending = get_pending_messages(self.uname2, _TMP_DB)
        ids     = [r["msg_id"] for r in pending]
        assert mid in ids

    def test_mark_delivered_removes_from_pending(self):
        mid = f"msg-{os.urandom(4).hex()}"
        store_message(mid, self.uid_a, self.uname2, "direct", "ct", "nonce2", db_path=_TMP_DB)
        mark_delivered(mid, _TMP_DB)
        pending = get_pending_messages(self.uname2, _TMP_DB)
        assert mid not in [r["msg_id"] for r in pending]

    def test_no_duplicate_on_reinsert(self):
        mid = f"msg-{os.urandom(4).hex()}"
        store_message(mid, self.uid_a, self.uname2, "direct", "ct", "n3", db_path=_TMP_DB)
        store_message(mid, self.uid_a, self.uname2, "direct", "ct", "n3", db_path=_TMP_DB)
        pending = get_pending_messages(self.uname2, _TMP_DB)
        assert [r for r in pending if r["msg_id"] == mid].__len__() == 1


# ── Groups ────────────────────────────────────────────────────────────────────

class TestGroups:
    def setup_method(self):
        self.uname = f"grpuser_{os.urandom(4).hex()}"
        self.uid   = create_user(self.uname, "h", "s", _TMP_DB)

    def test_create_and_fetch_group(self):
        gname = f"group_{os.urandom(4).hex()}"
        gid   = create_group(gname, self.uid, _TMP_DB)
        row   = get_group_by_name(gname, _TMP_DB)
        assert row is not None
        assert row["group_id"] == gid

    def test_creator_is_member(self):
        gname   = f"group_{os.urandom(4).hex()}"
        create_group(gname, self.uid, _TMP_DB)
        members = get_group_members(gname, _TMP_DB)
        assert self.uname in members

    def test_add_member(self):
        gname   = f"group_{os.urandom(4).hex()}"
        create_group(gname, self.uid, _TMP_DB)
        uname2  = f"mem_{os.urandom(4).hex()}"
        create_user(uname2, "h", "s", _TMP_DB)
        add_group_member(gname, uname2, _TMP_DB)
        members = get_group_members(gname, _TMP_DB)
        assert uname2 in members

    def test_nonexistent_group_returns_none(self):
        row = get_group_by_name("no_such_group_xyz", _TMP_DB)
        assert row is None
