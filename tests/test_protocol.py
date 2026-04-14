"""
tests/test_protocol.py
----------------------
Unit tests for protocol/messages.py

Coverage
────────
  • Packet creation (make_packet)
  • Encode / decode round-trip
  • Length-prefix framing (encode_packet)
  • Validation: good packets, missing fields, bad types, bad timestamps
  • ProtocolError attributes
"""

import struct
import time
import uuid

import pytest

from protocol.messages import (
    MessageType, ErrorCode, ProtocolError,
    make_packet, encode_packet, decode_packet,
    validate_packet,
)


# ── make_packet ───────────────────────────────────────────────────────────────

class TestMakePacket:
    def test_has_required_fields(self):
        p = make_packet(MessageType.PING, {})
        assert "type"      in p
        assert "msg_id"    in p
        assert "timestamp" in p
        assert "payload"   in p

    def test_type_is_string(self):
        p = make_packet(MessageType.LOGIN, {"username": "x", "password_hash": "y"})
        assert p["type"] == "login"

    def test_msg_id_is_uuid4(self):
        p = make_packet(MessageType.PING, {})
        # Should not raise
        uuid.UUID(p["msg_id"], version=4)

    def test_timestamp_is_recent(self):
        p   = make_packet(MessageType.PING, {})
        now = time.time()
        assert abs(p["timestamp"] - now) < 2.0

    def test_payload_preserved(self):
        payload = {"username": "alice", "password_hash": "abc"}
        p       = make_packet(MessageType.LOGIN, payload)
        assert p["payload"] == payload


# ── encode / decode ───────────────────────────────────────────────────────────

class TestEncodeDecodePacket:
    def test_round_trip(self):
        original = make_packet(MessageType.PING, {})
        encoded  = encode_packet(original)
        # Strip 4-byte length header
        body     = encoded[4:]
        decoded  = decode_packet(body)
        assert decoded == original

    def test_length_header_correct(self):
        p    = make_packet(MessageType.PING, {})
        enc  = encode_packet(p)
        declared_len = struct.unpack(">I", enc[:4])[0]
        assert declared_len == len(enc) - 4

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError):
            decode_packet(b"not json at all !!!{")

    def test_unicode_payload(self):
        p    = make_packet(MessageType.DIRECT_MESSAGE, {
            "to":         "bob",
            "ciphertext": "こんにちは",
            "nonce":      "nonce-1",
        })
        enc  = encode_packet(p)
        body = enc[4:]
        dec  = decode_packet(body)
        assert dec["payload"]["ciphertext"] == "こんにちは"


# ── validate_packet ───────────────────────────────────────────────────────────

class TestValidatePacket:
    # ── Good packets ──────────────────────────────────────────────────────────

    def test_valid_ping(self):
        p = make_packet(MessageType.PING, {})
        validate_packet(p)   # should not raise

    def test_valid_login(self):
        p = make_packet(MessageType.LOGIN, {"username": "alice", "password_hash": "pass"})
        validate_packet(p)

    def test_valid_direct_message(self):
        p = make_packet(MessageType.DIRECT_MESSAGE, {
            "to":         "bob",
            "ciphertext": "cipherbytes",
            "nonce":      str(uuid.uuid4()),
        })
        validate_packet(p)

    # ── Missing top-level fields ──────────────────────────────────────────────

    @pytest.mark.parametrize("field", ["type", "msg_id", "timestamp", "payload"])
    def test_missing_envelope_field(self, field):
        p = make_packet(MessageType.PING, {})
        del p[field]
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    def test_unknown_message_type(self):
        p         = make_packet(MessageType.PING, {})
        p["type"] = "nonexistent_type"
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    def test_payload_not_dict(self):
        p            = make_packet(MessageType.PING, {})
        p["payload"] = ["not", "a", "dict"]
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    # ── Missing payload fields ────────────────────────────────────────────────

    def test_missing_login_username(self):
        p = make_packet(MessageType.LOGIN, {"password_hash": "pw"})
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.INVALID_PAYLOAD

    def test_missing_dm_ciphertext(self):
        p = make_packet(MessageType.DIRECT_MESSAGE, {"to": "bob", "nonce": "n"})
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.INVALID_PAYLOAD

    # ── Timestamp checks ──────────────────────────────────────────────────────

    def test_timestamp_too_old(self):
        p               = make_packet(MessageType.PING, {})
        p["timestamp"]  = time.time() - 90_000   # 25 hours ago
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    def test_timestamp_far_future(self):
        p               = make_packet(MessageType.PING, {})
        p["timestamp"]  = time.time() + 90_000
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    def test_timestamp_non_numeric(self):
        p               = make_packet(MessageType.PING, {})
        p["timestamp"]  = "not-a-number"
        with pytest.raises(ProtocolError) as exc_info:
            validate_packet(p)
        assert exc_info.value.code == ErrorCode.MALFORMED_PACKET

    # ── ProtocolError attributes ──────────────────────────────────────────────

    def test_protocol_error_has_code_and_detail(self):
        try:
            p         = make_packet(MessageType.PING, {})
            p["type"] = "garbage"
            validate_packet(p)
        except ProtocolError as exc:
            assert exc.code   == ErrorCode.MALFORMED_PACKET
            assert isinstance(exc.detail, str)
            assert exc.detail
