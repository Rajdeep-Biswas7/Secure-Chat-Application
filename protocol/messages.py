"""
protocol/messages.py
--------------------
Defines the JSON-based application protocol.

Every packet on the wire is a UTF-8 encoded JSON object prefixed with a
4-byte big-endian length header so framing is unambiguous.

Packet schema
─────────────
{
  "type"       : <MessageType>,   # required
  "msg_id"     : <str UUID4>,     # required – used for ACK / dedup
  "timestamp"  : <float>,         # required – Unix epoch, set by sender
  "payload"    : { ... }          # type-specific body
}

Payload schemas per type
  register        → {username, password_hash}
  login           → {username, password_hash}
  logout          → {}
  direct_message  → {to, ciphertext, nonce, key_hint}
  group_message   → {group, ciphertext, nonce, key_hint}
  ack             → {ref_msg_id, status}
  error           → {code, detail}
  presence        → {username, online}
  history_request → {peer_or_group, limit}
  history_response→ {messages: [...]}
  ping / pong     → {}
"""

import json
import struct
import uuid
import time
from enum import Enum
from typing import Any

from shared.config import MAX_MESSAGE_SIZE


# ── Message types ─────────────────────────────────────────────────────────────

class MessageType(str, Enum):
    REGISTER         = "register"
    LOGIN            = "login"
    LOGOUT           = "logout"
    DIRECT_MESSAGE   = "direct_message"
    GROUP_MESSAGE    = "group_message"
    ACK              = "ack"
    ERROR            = "error"
    PRESENCE         = "presence"
    HISTORY_REQUEST  = "history_request"
    HISTORY_RESPONSE = "history_response"
    PING             = "ping"
    PONG             = "pong"


# ── Error codes ───────────────────────────────────────────────────────────────

class ErrorCode(str, Enum):
    AUTH_FAILED       = "AUTH_FAILED"
    USER_EXISTS       = "USER_EXISTS"
    USER_NOT_FOUND    = "USER_NOT_FOUND"
    MALFORMED_PACKET  = "MALFORMED_PACKET"
    RATE_LIMITED      = "RATE_LIMITED"
    INTERNAL_ERROR    = "INTERNAL_ERROR"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    INVALID_PAYLOAD   = "INVALID_PAYLOAD"
    MESSAGE_TOO_LARGE = "MESSAGE_TOO_LARGE"


# ── Required payload fields per message type ──────────────────────────────────

_REQUIRED_FIELDS: dict[str, list[str]] = {
    MessageType.REGISTER:         ["username", "password_hash"],
    MessageType.LOGIN:            ["username", "password_hash"],
    MessageType.LOGOUT:           [],
    MessageType.DIRECT_MESSAGE:   ["to", "ciphertext", "nonce"],
    MessageType.GROUP_MESSAGE:    ["group", "ciphertext", "nonce"],
    MessageType.ACK:              ["ref_msg_id", "status"],
    MessageType.ERROR:            ["code", "detail"],
    MessageType.PRESENCE:         ["username", "online"],
    MessageType.HISTORY_REQUEST:  ["peer_or_group"],
    MessageType.HISTORY_RESPONSE: ["messages"],
    MessageType.PING:             [],
    MessageType.PONG:             [],
}


# ── Packet factory ────────────────────────────────────────────────────────────

def make_packet(msg_type: MessageType, payload: dict[str, Any]) -> dict[str, Any]:
    """Create a well-formed packet dict (not yet serialised)."""
    return {
        "type":      msg_type.value,
        "msg_id":    str(uuid.uuid4()),
        "timestamp": time.time(),
        "payload":   payload,
    }


# ── Serialisation / deserialisation ──────────────────────────────────────────

HEADER_SIZE = 4  # bytes for length prefix


def encode_packet(packet: dict[str, Any]) -> bytes:
    """
    Serialise a packet to length-prefixed bytes.
    Raises ValueError if the resulting message exceeds MAX_MESSAGE_SIZE.
    """
    body = json.dumps(packet, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Packet too large: {len(body)} bytes")
    return struct.pack(">I", len(body)) + body


def decode_packet(data: bytes) -> dict[str, Any]:
    """
    Deserialise raw bytes (WITHOUT the 4-byte length prefix) to a packet dict.
    Raises ValueError on malformed JSON.
    """
    try:
        return json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Malformed packet body: {exc}") from exc


def read_packet(sock) -> dict[str, Any] | None:
    """
    Block-read one framed packet from *sock*.
    Returns None if the connection was closed cleanly.
    Raises ConnectionError or ValueError on protocol violations.
    """
    # Read 4-byte length header
    header = _recv_exact(sock, HEADER_SIZE)
    if header is None:
        return None

    length = struct.unpack(">I", header)[0]
    if length == 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Invalid declared packet length: {length}")

    body = _recv_exact(sock, length)
    if body is None:
        raise ConnectionError("Connection closed mid-packet")

    return decode_packet(body)


def _recv_exact(sock, n: int) -> bytes | None:
    """Read exactly *n* bytes from *sock*; return None on clean EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None if not buf else (_ for _ in ()).throw(
                ConnectionError("Partial read – connection lost")
            )
        buf += chunk
    return buf


def send_packet(sock, msg_type: MessageType, payload: dict[str, Any]) -> None:
    """Convenience: build, encode, and send a packet in one call."""
    packet = make_packet(msg_type, payload)
    sock.sendall(encode_packet(packet))


# ── Validation ────────────────────────────────────────────────────────────────

class ProtocolError(Exception):
    """Raised when an incoming packet fails structural validation."""
    def __init__(self, code: ErrorCode, detail: str):
        super().__init__(detail)
        self.code   = code
        self.detail = detail


def validate_packet(packet: dict[str, Any]) -> None:
    """
    Validate the top-level envelope and required payload fields.
    Raises ProtocolError with an appropriate ErrorCode on failure.
    """
    # Top-level envelope fields
    for field in ("type", "msg_id", "timestamp", "payload"):
        if field not in packet:
            raise ProtocolError(
                ErrorCode.MALFORMED_PACKET,
                f"Missing top-level field: '{field}'"
            )

    msg_type_str = packet["type"]
    valid_types  = {mt.value for mt in MessageType}
    if msg_type_str not in valid_types:
        raise ProtocolError(
            ErrorCode.MALFORMED_PACKET,
            f"Unknown message type: '{msg_type_str}'"
        )

    if not isinstance(packet["payload"], dict):
        raise ProtocolError(
            ErrorCode.MALFORMED_PACKET,
            "Field 'payload' must be a JSON object"
        )

    # Payload fields
    required = _REQUIRED_FIELDS.get(msg_type_str, [])
    payload  = packet["payload"]
    missing  = [f for f in required if f not in payload]
    if missing:
        raise ProtocolError(
            ErrorCode.INVALID_PAYLOAD,
            f"Missing payload fields for '{msg_type_str}': {missing}"
        )

    # Timestamp sanity (reject packets from the far future or past 24 h)
    now = time.time()
    ts  = packet["timestamp"]
    if not isinstance(ts, (int, float)) or abs(now - ts) > 86_400:
        raise ProtocolError(
            ErrorCode.MALFORMED_PACKET,
            "Packet timestamp out of acceptable range"
        )
