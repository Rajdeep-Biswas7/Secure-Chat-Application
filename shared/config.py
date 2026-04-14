"""
shared/config.py
----------------
Central configuration loader using environment variables via python-dotenv.
All tunable parameters live here; no secrets or paths are hardcoded elsewhere.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from the project root (two levels up from this file)
_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_ROOT / ".env", override=False)


def _get(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _get_int(key: str, default: int) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


# ── Network ──────────────────────────────────────────────────────────────────
SERVER_HOST: str = _get("SERVER_HOST", "127.0.0.1")
SERVER_PORT: int = _get_int("SERVER_PORT", 65432)

# ── TLS ──────────────────────────────────────────────────────────────────────
SERVER_CERT: str = str(_ROOT / _get("SERVER_CERT", "certs/server.crt"))
SERVER_KEY: str  = str(_ROOT / _get("SERVER_KEY",  "certs/server.key"))
CA_CERT: str     = str(_ROOT / _get("CA_CERT",     "certs/server.crt"))

# ── Persistence ───────────────────────────────────────────────────────────────
DATABASE_PATH: str = str(_ROOT / _get("DATABASE_PATH", "secure_chat.db"))

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_LEVEL: str = _get("LOG_LEVEL", "INFO")
LOG_FILE: str  = str(_ROOT / _get("LOG_FILE", "logs/server.log"))

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_MESSAGES: int = _get_int("RATE_LIMIT_MESSAGES", 20)   # msgs per window
RATE_LIMIT_WINDOW:   int = _get_int("RATE_LIMIT_WINDOW",   60)   # seconds
MAX_CONNECTIONS:     int = _get_int("MAX_CONNECTIONS",     100)

# ── Application limits ────────────────────────────────────────────────────────
SESSION_TIMEOUT:    int = _get_int("SESSION_TIMEOUT",   3600)   # seconds
MAX_MESSAGE_SIZE:   int = _get_int("MAX_MESSAGE_SIZE",  65536)  # bytes
