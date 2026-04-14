# Secure Chat Application with End-to-End Encryption

A production-style, multi-client encrypted chat system built in Python.  
All message content is encrypted **on the client** before transmission; the server relays and stores **only ciphertext**.

---

## Table of Contents

1. [Feature List](#feature-list)
2. [Architecture](#architecture)
3. [Module Layout](#module-layout)
4. [SQLite Schema](#sqlite-schema)
5. [Security Design & Threat Model](#security-design--threat-model)
6. [Setup Instructions](#setup-instructions)
7. [Running the Application](#running-the-application)
8. [Running Tests](#running-tests)
9. [Configuration Reference](#configuration-reference)
10. [Future Improvements](#future-improvements)

---

## Feature List

| Category | Feature |
|---|---|
| Transport | TLS 1.2+ via Python `ssl`; weak ciphers disabled |
| Auth | bcrypt password hashing (cost 12); per-user KDF salt |
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256); client-side only |
| Key derivation | PBKDF2-HMAC-SHA256, 480 000 iterations |
| Anti-replay | Per-message UUID4 nonce tracked in client memory |
| Messaging | One-to-one DM + named group chat |
| Offline delivery | Encrypted messages queued in SQLite; delivered on reconnect |
| Presence | Real-time online/offline broadcast |
| History | Encrypted message history retrieval |
| Rate limiting | Token-bucket per connection (configurable) |
| Logging | Structured rotating logs — **no plaintext content ever logged** |
| Protocol | Length-prefixed JSON with type, msg_id, timestamp, payload |
| Tests | pytest suite: crypto, protocol, auth, database |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                        CLIENT                        │
│                                                      │
│  Terminal UI  ──►  SecureChatClient                  │
│                         │                            │
│           ┌─────────────┴──────────────┐             │
│           │  FernetEngine (encrypt /   │             │
│           │  decrypt locally)          │             │
│           └─────────────┬──────────────┘             │
│                         │  TLS socket                │
└─────────────────────────┼────────────────────────────┘
                          │  (ciphertext only on wire)
┌─────────────────────────┼────────────────────────────┐
│                       SERVER                         │
│                         │                            │
│              ChatServer (accept loop)                │
│                         │                            │
│            ClientHandler thread (per user)           │
│           ┌─────────────┴──────────────┐             │
│           │  auth/auth.py              │             │
│           │  database/db.py            │             │
│           │  protocol/messages.py      │             │
│           └─────────────┬──────────────┘             │
│                    SQLite DB                         │
│         (users · sessions · messages · groups)       │
└─────────────────────────────────────────────────────┘
```

**Key principle:** The server is a *blind relay*. It validates packet envelopes,
routes encrypted payloads to recipients, and stores ciphertext. It has no access
to any decryption key at any point.

---

## Module Layout

```
secure_chat/
│
├── server/
│   └── server.py          # ChatServer + ClientHandler; accept loop; routing
│
├── client/
│   └── client.py          # SecureChatClient; terminal UI; local encrypt/decrypt
│
├── auth/
│   └── auth.py            # register_user / login_user / logout_user
│
├── database/
│   └── db.py              # SQLite schema; CRUD for users/sessions/messages/groups
│
├── crypto_utils/
│   └── encryption.py      # CryptoEngine ABC; FernetEngine; helpers
│
├── protocol/
│   └── messages.py        # MessageType enum; make/encode/decode/validate packet
│
├── shared/
│   ├── config.py          # Env-var configuration loader
│   └── logger.py          # Rotating-file logger factory
│
├── certs/
│   └── generate_certs.py  # Self-signed TLS cert generator
│
├── tests/
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_auth.py
│   └── test_database.py
│
├── logs/                  # Created automatically at runtime
├── .env.example           # Template — copy to .env and edit
├── pytest.ini
└── requirements.txt
```

---

## SQLite Schema

```sql
users (
    user_id     TEXT PK,
    username    TEXT UNIQUE,
    pwd_hash    TEXT,        -- bcrypt hash; raw password never stored
    kdf_salt    TEXT,        -- hex; used by CLIENT to derive Fernet key
    created_at  REAL,
    last_seen   REAL
)

sessions (
    session_id  TEXT PK,
    user_id     TEXT FK→users,
    created_at  REAL,
    expires_at  REAL,
    active      INTEGER
)

messages (
    msg_id      TEXT PK,
    sender_id   TEXT FK→users,
    recipient   TEXT,        -- username (DM) or group name
    msg_type    TEXT,        -- 'direct' | 'group'
    ciphertext  TEXT,        -- opaque encrypted blob; server cannot read
    nonce       TEXT,        -- UUID4 replay-guard
    key_hint    TEXT,
    timestamp   REAL,
    delivered   INTEGER
)

groups (
    group_id    TEXT PK,
    group_name  TEXT UNIQUE,
    created_by  TEXT FK→users,
    created_at  REAL
)

group_members (
    group_id    TEXT FK→groups,
    user_id     TEXT FK→users,
    joined_at   REAL,
    PK (group_id, user_id)
)
```

---

## Security Design & Threat Model

### What is protected

| Threat | Mitigation |
|---|---|
| Network eavesdropping | TLS 1.2+ with ECDHE + AES-GCM ciphers |
| Plaintext on server | Fernet encryption client-side; server stores ciphertext only |
| Weak passwords | bcrypt cost-12 + PBKDF2 key derivation (480 k iterations) |
| Password DB breach | bcrypt hashes; KDF salts; no raw passwords ever stored |
| Message tampering | Fernet HMAC-SHA256 authentication tag |
| Replay attacks | Per-message UUID4 nonce tracked in client seen-set |
| SQL injection | Parameterised queries throughout |
| Username enumeration | Uniform error message for bad credentials |
| Spam / flood | Per-connection token-bucket rate limiter |
| Log data leakage | Logging code never receives message content |

### Assumptions / out-of-scope

- **Key distribution:** Both parties currently share the same Fernet key derived
  from their own password. True E2E requires a key-exchange (ECDH) so each
  pair of users shares a unique session key. See *Future Improvements*.
- **Server trust:** The server is trusted not to swap ciphertexts. A
  fully zero-trust design would use signed messages (e.g. Ed25519).
- **Client device:** The client process and its memory are assumed to be
  uncompromised.
- **Certificate pinning:** Not implemented. Production deployment should use
  CA-signed certs and enable `check_hostname = True`.

---

## Setup Instructions

### 1. Prerequisites

```
Python 3.11+
pip
```

### 2. Clone and install

```bash
git clone <repo-url>
cd secure_chat
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env if you need non-default ports, paths, etc.
```

### 4. Generate TLS certificates (development only)

```bash
python certs/generate_certs.py
```

This writes `certs/server.key` and `certs/server.crt`.  
**For production**, replace these with certificates from a trusted CA and set
`SERVER_CERT`, `SERVER_KEY`, and `CA_CERT` in `.env` accordingly.

---

## Running the Application

### Start the server

```bash
python -m server.server
```

Expected output:
```
2024-01-15 10:00:00 [INFO    ] server.server — Database initialised
2024-01-15 10:00:00 [INFO    ] server.server — Server listening on 127.0.0.1:65432 (TLS)
```

### Start a client (in a separate terminal)

```bash
python -m client.client
```

You will be prompted to register or login, then enter the chat loop.

#### Client commands

```
/msg  <user>  <text>         Send an encrypted direct message
/group <n> <text>         Send an encrypted group message
/history <peer> [limit]      Fetch encrypted message history (decrypted locally)
/online                      Show currently online users
/help                        Print command list
/quit                        Logout and exit
```

#### Create a group (database script — no UI command yet)

```python
from database.db import create_group, get_user_by_username
user = get_user_by_username("alice")
create_group("general", user["user_id"])
```

---

## Running Tests

```bash
pytest                        # all tests
pytest tests/test_crypto.py   # crypto suite only
pytest -v --tb=long           # verbose with full tracebacks
pytest --cov=. --cov-report=term-missing   # with coverage
```

---

## Configuration Reference

All settings can be overridden in `.env`:

| Variable | Default | Description |
|---|---|---|
| `SERVER_HOST` | `127.0.0.1` | Bind address |
| `SERVER_PORT` | `65432` | TCP port |
| `SERVER_CERT` | `certs/server.crt` | TLS certificate path |
| `SERVER_KEY` | `certs/server.key` | TLS private key path |
| `CA_CERT` | `certs/server.crt` | CA cert for client verification |
| `DATABASE_PATH` | `secure_chat.db` | SQLite file path |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FILE` | `logs/server.log` | Rotating log file |
| `RATE_LIMIT_MESSAGES` | `20` | Max messages per window |
| `RATE_LIMIT_WINDOW` | `60` | Rate-limit window (seconds) |
| `MAX_CONNECTIONS` | `100` | Max simultaneous clients |
| `SESSION_TIMEOUT` | `3600` | Session TTL (seconds) |
| `MAX_MESSAGE_SIZE` | `65536` | Max packet size (bytes) |

---

## Future Improvements

### Security upgrades
- **ECDH key exchange** — Perform an X25519 key exchange at login so each
  sender-recipient pair derives a unique shared secret. Replace FernetEngine
  with AesGcmEngine (the CryptoEngine ABC already supports this swap).
- **Message signing** — Sign each message with the sender's Ed25519 private key
  so recipients can verify authenticity even if the server is compromised.
- **Certificate pinning** — Pin the server's public key on the client to defeat
  MITM attacks using rogue CA certs.
- **Forward secrecy** — Rotate session keys periodically (double-ratchet style).
- **Argon2id** — Replace bcrypt with Argon2id for better resistance to
  GPU/ASIC attacks.

### Feature additions
- **Group key management** — Distribute a symmetric group key via sender-to-member
  encrypted envelopes so only members can decrypt group messages.
- **File transfer** — Stream encrypted file chunks over the existing protocol.
- **Read receipts** — Add a `read_receipt` message type and delivery status UI.
- **Push notifications** — WebSocket or APNS/FCM bridge for mobile.
- **Tkinter / web UI** — A GUI front-end using the same client library.
- **Admin console** — Server-side CLI to list users, groups, ban/unban.

### Operational improvements
- **Async I/O** — Replace `threading` with `asyncio` + `asyncio.streams` for
  better scalability beyond ~1 000 concurrent users.
- **Connection pooling** — Use a SQLite connection pool or migrate to PostgreSQL
  for high-load deployments.
- **Metrics** — Prometheus exporter for connection count, message throughput,
  error rate.
- **Docker** — Multi-stage `Dockerfile` + `docker-compose.yml` for one-command
  deployment.
- **CI/CD** — GitHub Actions workflow running `pytest`, `mypy`, `bandit`.
#   S e c u r e - C h a t - A p p l i c a t i o n  
 