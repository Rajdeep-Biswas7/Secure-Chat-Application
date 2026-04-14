"""
database/db.py
--------------
SQLite persistence layer.

Schema overview
───────────────
  users          – credentials and key material
  sessions       – active login sessions
  messages       – stored ciphertext (server never sees plaintext)
  group_members  – group membership
  groups         – chat group registry

Security notes
──────────────
• Passwords are stored as bcrypt hashes; the raw password never touches this layer.
• Message content is stored as opaque ciphertext; this module treats it as a
  plain string blob and never interprets it.
• Parameterised queries are used throughout to prevent SQL injection.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from shared.config import DATABASE_PATH
from shared.logger import get_logger

log = get_logger(__name__)


# ── Schema DDL ────────────────────────────────────────────────────────────────

_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id     TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    pwd_hash    TEXT NOT NULL,        -- bcrypt hash
    kdf_salt    TEXT NOT NULL,        -- hex-encoded salt for key derivation
    created_at  REAL NOT NULL,
    last_seen   REAL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS messages (
    msg_id      TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES users(user_id),
    recipient   TEXT NOT NULL,   -- username (DM) or group name
    msg_type    TEXT NOT NULL,   -- 'direct' | 'group'
    ciphertext  TEXT NOT NULL,   -- opaque encrypted blob
    nonce       TEXT NOT NULL,   -- replay-guard UUID
    key_hint    TEXT NOT NULL DEFAULT '',
    timestamp   REAL NOT NULL,
    delivered   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS groups (
    group_id    TEXT PRIMARY KEY,
    group_name  TEXT UNIQUE NOT NULL,
    created_by  TEXT NOT NULL REFERENCES users(user_id),
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id    TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(user_id)  ON DELETE CASCADE,
    joined_at   REAL NOT NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient);
CREATE INDEX IF NOT EXISTS idx_messages_delivered ON messages(delivered);
CREATE INDEX IF NOT EXISTS idx_sessions_user      ON sessions(user_id);
"""


# ── Connection helpers ────────────────────────────────────────────────────────

def _connect(path: str = DATABASE_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
    return conn


@contextmanager
def get_db(path: str = DATABASE_PATH) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that yields a connection and commits/rolls-back cleanly."""
    conn = _connect(path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: str = DATABASE_PATH) -> None:
    """Create all tables if they do not already exist."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with get_db(path) as conn:
        conn.executescript(_SCHEMA)
    log.info("Database initialised at %s", path)


# ── User CRUD ─────────────────────────────────────────────────────────────────

def create_user(
    username: str,
    pwd_hash: str,
    kdf_salt: str,
    db_path: str = DATABASE_PATH,
) -> str:
    """Insert a new user; return the new user_id. Raises if username exists."""
    user_id = str(uuid.uuid4())
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO users (user_id, username, pwd_hash, kdf_salt, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, username, pwd_hash, kdf_salt, time.time()),
        )
    log.info("User created: username=%s", username)
    return user_id


def get_user_by_username(username: str, db_path: str = DATABASE_PATH) -> sqlite3.Row | None:
    """Return the user row or None."""
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row


def update_last_seen(user_id: str, db_path: str = DATABASE_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE users SET last_seen = ? WHERE user_id = ?",
            (time.time(), user_id),
        )


# ── Session CRUD ──────────────────────────────────────────────────────────────

def create_session(
    user_id: str,
    ttl_seconds: int = 3600,
    db_path: str = DATABASE_PATH,
) -> str:
    """Create an active session; return session_id."""
    session_id = str(uuid.uuid4())
    now        = time.time()
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions (session_id, user_id, created_at, expires_at, active)
            VALUES (?, ?, ?, ?, 1)
            """,
            (session_id, user_id, now, now + ttl_seconds),
        )
    return session_id


def invalidate_session(session_id: str, db_path: str = DATABASE_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE sessions SET active = 0 WHERE session_id = ?",
            (session_id,),
        )


# ── Message CRUD ──────────────────────────────────────────────────────────────

def store_message(
    msg_id:     str,
    sender_id:  str,
    recipient:  str,
    msg_type:   str,
    ciphertext: str,
    nonce:      str,
    key_hint:   str = "",
    db_path:    str = DATABASE_PATH,
) -> None:
    """Persist an encrypted message (ciphertext only)."""
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO messages
              (msg_id, sender_id, recipient, msg_type, ciphertext, nonce, key_hint, timestamp, delivered)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (msg_id, sender_id, recipient, msg_type, ciphertext, nonce, key_hint, time.time()),
        )


def get_pending_messages(
    username: str,
    db_path: str = DATABASE_PATH,
) -> list[sqlite3.Row]:
    """Return undelivered messages addressed to *username*."""
    with get_db(db_path) as conn:
        rows = conn.execute(
            """
            SELECT m.*, u.username AS sender_username
            FROM   messages m
            JOIN   users    u ON m.sender_id = u.user_id
            WHERE  m.recipient = ? AND m.delivered = 0
            ORDER  BY m.timestamp ASC
            """,
            (username,),
        ).fetchall()
    return rows


def mark_delivered(msg_id: str, db_path: str = DATABASE_PATH) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            "UPDATE messages SET delivered = 1 WHERE msg_id = ?",
            (msg_id,),
        )


def get_message_history(
    username: str,
    peer_or_group: str,
    limit: int = 50,
    db_path: str = DATABASE_PATH,
) -> list[sqlite3.Row]:
    """
    Return the most recent *limit* messages between *username* and *peer_or_group*.
    Works for both DMs and groups.
    """
    with get_db(db_path) as conn:
        rows = conn.execute(
            """
            SELECT m.*, u.username AS sender_username
            FROM   messages m
            JOIN   users    u ON m.sender_id = u.user_id
            WHERE  (m.recipient = ? AND u.username = ?)
                OR (m.recipient = ? AND u.username = ?)
                OR  m.recipient = ?
            ORDER  BY m.timestamp DESC
            LIMIT  ?
            """,
            (peer_or_group, username, username, peer_or_group, peer_or_group, limit),
        ).fetchall()
    return list(reversed(rows))


# ── Group CRUD ────────────────────────────────────────────────────────────────

def create_group(
    group_name: str,
    created_by: str,
    db_path: str = DATABASE_PATH,
) -> str:
    """Create a group and add the creator as first member."""
    group_id = str(uuid.uuid4())
    now      = time.time()
    with get_db(db_path) as conn:
        conn.execute(
            "INSERT INTO groups (group_id, group_name, created_by, created_at) VALUES (?,?,?,?)",
            (group_id, group_name, created_by, now),
        )
        conn.execute(
            "INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?,?,?)",
            (group_id, created_by, now),
        )
    log.info("Group created: name=%s by user_id=%s", group_name, created_by)
    return group_id


def get_group_by_name(group_name: str, db_path: str = DATABASE_PATH) -> sqlite3.Row | None:
    with get_db(db_path) as conn:
        return conn.execute(
            "SELECT * FROM groups WHERE group_name = ?", (group_name,)
        ).fetchone()


def get_group_members(group_name: str, db_path: str = DATABASE_PATH) -> list[str]:
    """Return list of usernames in *group_name*."""
    with get_db(db_path) as conn:
        rows = conn.execute(
            """
            SELECT u.username
            FROM   group_members gm
            JOIN   groups g ON gm.group_id = g.group_id
            JOIN   users  u ON gm.user_id  = u.user_id
            WHERE  g.group_name = ?
            """,
            (group_name,),
        ).fetchall()
    return [r["username"] for r in rows]


def add_group_member(
    group_name: str,
    username: str,
    db_path: str = DATABASE_PATH,
) -> None:
    with get_db(db_path) as conn:
        group = conn.execute(
            "SELECT group_id FROM groups WHERE group_name = ?", (group_name,)
        ).fetchone()
        user = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if group and user:
            conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id, joined_at) VALUES (?,?,?)",
                (group["group_id"], user["user_id"], time.time()),
            )
