"""
server/server.py
----------------
Multi-client TLS/TCP server with threaded client handlers.

Architecture
────────────
  main()                   – parse config, create TLS context, bind socket
  ChatServer               – manages the accept loop and the online-user registry
  ClientHandler            – one thread per connected client; owns the full
                             request→dispatch→response lifecycle

Thread safety
─────────────
  The online-user registry (_online) is protected by a re-entrant lock.
  All SQLite operations are serialised by SQLite's WAL mode + per-call
  context managers in database/db.py (each call opens/closes its own
  connection).

Security notes
──────────────
  • TLS 1.2+ is enforced; legacy protocols and weak ciphers are disabled.
  • The server stores and forwards only ciphertext; it never touches plaintext.
  • Rate limiting is enforced per-connection: token-bucket style.
  • All authentication errors use constant-time responses (bcrypt ensures this).
  • Exceptions in handlers are caught; internal details are NOT sent to clients.
"""

from __future__ import annotations

import os
import ssl
import socket
import threading
import time
from typing import Optional

from auth.auth import (
    register_user, login_user, logout_user,
    RegistrationError, AuthenticationError,
)
from database.db import (
    init_db, store_message, get_pending_messages,
    mark_delivered, get_message_history,
    get_group_members, get_group_by_name,
    get_user_by_username,
)
from protocol.messages import (
    MessageType, ErrorCode, ProtocolError,
    read_packet, send_packet, validate_packet,
)
from shared.config import (
    SERVER_HOST, SERVER_PORT, SERVER_CERT, SERVER_KEY,
    MAX_CONNECTIONS, RATE_LIMIT_MESSAGES, RATE_LIMIT_WINDOW,
    LOG_FILE, LOG_LEVEL, DATABASE_PATH,
)
from shared.logger import get_logger

log = get_logger(__name__, log_file=LOG_FILE, level=LOG_LEVEL)


# ── Rate limiter (token bucket) ───────────────────────────────────────────────

class RateLimiter:
    """
    Simple per-connection rate limiter.
    Allows at most *limit* messages per *window* seconds.
    """
    def __init__(self, limit: int = RATE_LIMIT_MESSAGES, window: float = RATE_LIMIT_WINDOW):
        self._limit  = limit
        self._window = window
        self._tokens: list[float] = []
        self._lock   = threading.Lock()

    def is_allowed(self) -> bool:
        now = time.time()
        with self._lock:
            # Purge tokens outside the current window
            self._tokens = [t for t in self._tokens if now - t < self._window]
            if len(self._tokens) >= self._limit:
                return False
            self._tokens.append(now)
            return True


# ── Client handler ────────────────────────────────────────────────────────────

class ClientHandler(threading.Thread):
    """
    Handles one client connection for its entire lifetime.
    Runs in its own daemon thread.
    """

    def __init__(self, conn: ssl.SSLSocket, addr: tuple, server: "ChatServer"):
        super().__init__(daemon=True)
        self._conn        = conn
        self._addr        = addr
        self._server      = server
        self._username:   Optional[str]  = None
        self._user_id:    Optional[str]  = None
        self._session_id: Optional[str]  = None
        self._rate        = RateLimiter()
        self._active      = True

    # ── Main loop ─────────────────────────────────────────────────────────────

    def run(self) -> None:
        log.info("Connection accepted from %s:%s", *self._addr)
        try:
            while self._active:
                packet = read_packet(self._conn)
                if packet is None:
                    break
                self._dispatch(packet)
        except ConnectionError as exc:
            log.info("Client disconnected (%s:%s): %s", *self._addr, exc)
        except Exception as exc:
            log.error("Unhandled error for %s:%s – %s", *self._addr, exc, exc_info=True)
        finally:
            self._cleanup()

    # ── Dispatcher ────────────────────────────────────────────────────────────

    def _dispatch(self, packet: dict) -> None:
        try:
            validate_packet(packet)
        except ProtocolError as exc:
            self._send_error(exc.code, exc.detail)
            return

        if not self._rate.is_allowed():
            self._send_error(ErrorCode.RATE_LIMITED, "Too many requests – slow down")
            return

        msg_type = packet["type"]
        payload  = packet["payload"]
        msg_id   = packet["msg_id"]

        # Pre-auth routes
        if msg_type == MessageType.REGISTER:
            self._handle_register(payload)
        elif msg_type == MessageType.LOGIN:
            self._handle_login(payload)
        elif msg_type == MessageType.PING:
            send_packet(self._conn, MessageType.PONG, {})

        # Auth-required routes
        elif msg_type in (
            MessageType.DIRECT_MESSAGE,
            MessageType.GROUP_MESSAGE,
            MessageType.LOGOUT,
            MessageType.HISTORY_REQUEST,
        ):
            if not self._username:
                self._send_error(ErrorCode.NOT_AUTHENTICATED, "Please log in first")
                return
            if msg_type == MessageType.DIRECT_MESSAGE:
                self._handle_direct(payload, msg_id)
            elif msg_type == MessageType.GROUP_MESSAGE:
                self._handle_group(payload, msg_id)
            elif msg_type == MessageType.LOGOUT:
                self._handle_logout()
            elif msg_type == MessageType.HISTORY_REQUEST:
                self._handle_history(payload)
        else:
            self._send_error(ErrorCode.MALFORMED_PACKET, f"Unhandled type: {msg_type}")

    # ── Handlers ──────────────────────────────────────────────────────────────

    def _handle_register(self, payload: dict) -> None:
        try:
            result = register_user(payload["username"], payload["password_hash"])
            send_packet(self._conn, MessageType.ACK, {
                "ref_msg_id": "register",
                "status":     "ok",
                "kdf_salt":   result["kdf_salt"],
            })
        except RegistrationError as exc:
            self._send_error(ErrorCode.USER_EXISTS, str(exc))
        except Exception as exc:
            log.error("Registration error: %s", exc, exc_info=True)
            self._send_error(ErrorCode.INTERNAL_ERROR, "Registration failed")

    def _handle_login(self, payload: dict) -> None:
        try:
            result = login_user(payload["username"], payload["password_hash"])
            self._username   = payload["username"]
            self._user_id    = result["user_id"]
            self._session_id = result["session_id"]
            self._server.set_online(self._username, self)

            # Announce presence
            self._server.broadcast_presence(self._username, online=True)

            # Deliver any pending offline messages
            self._deliver_pending()

            send_packet(self._conn, MessageType.ACK, {
                "ref_msg_id": "login",
                "status":     "ok",
                "kdf_salt":   result["kdf_salt"],
                "session_id": result["session_id"],
            })
            log.info("User logged in: username=%s addr=%s:%s", self._username, *self._addr)
        except AuthenticationError as exc:
            self._send_error(ErrorCode.AUTH_FAILED, str(exc))
        except Exception as exc:
            log.error("Login error: %s", exc, exc_info=True)
            self._send_error(ErrorCode.INTERNAL_ERROR, "Login failed")

    def _handle_direct(self, payload: dict, msg_id: str) -> None:
        to         = payload["to"]
        ciphertext = payload["ciphertext"]
        nonce      = payload["nonce"]
        key_hint   = payload.get("key_hint", "")

        # Validate recipient exists
        if get_user_by_username(to) is None:
            self._send_error(ErrorCode.USER_NOT_FOUND, f"User '{to}' not found")
            return

        # Persist (ciphertext only)
        store_message(
            msg_id=msg_id,
            sender_id=self._user_id,
            recipient=to,
            msg_type="direct",
            ciphertext=ciphertext,
            nonce=nonce,
            key_hint=key_hint,
        )

        # Attempt real-time relay
        handler = self._server.get_handler(to)
        if handler:
            try:
                send_packet(handler._conn, MessageType.DIRECT_MESSAGE, {
                    "from":       self._username,
                    "to":         to,
                    "ciphertext": ciphertext,
                    "nonce":      nonce,
                    "key_hint":   key_hint,
                    "msg_id":     msg_id,
                })
                mark_delivered(msg_id)
                log.info("DM relayed: from=%s to=%s msg_id=%s", self._username, to, msg_id)
            except Exception as exc:
                log.warning("Failed to relay DM to %s: %s", to, exc)
        else:
            log.info("DM queued (offline): from=%s to=%s msg_id=%s", self._username, to, msg_id)

        send_packet(self._conn, MessageType.ACK, {"ref_msg_id": msg_id, "status": "queued"})

    def _handle_group(self, payload: dict, msg_id: str) -> None:
        group_name = payload["group"]
        ciphertext = payload["ciphertext"]
        nonce      = payload["nonce"]
        key_hint   = payload.get("key_hint", "")

        members = get_group_members(group_name)
        if not members:
            self._send_error(ErrorCode.USER_NOT_FOUND, f"Group '{group_name}' not found or empty")
            return

        # Persist once (addressed to the group name)
        store_message(
            msg_id=msg_id,
            sender_id=self._user_id,
            recipient=group_name,
            msg_type="group",
            ciphertext=ciphertext,
            nonce=nonce,
            key_hint=key_hint,
        )

        # Relay to all online members (except sender)
        for member in members:
            if member == self._username:
                continue
            handler = self._server.get_handler(member)
            if handler:
                try:
                    send_packet(handler._conn, MessageType.GROUP_MESSAGE, {
                        "from":       self._username,
                        "group":      group_name,
                        "ciphertext": ciphertext,
                        "nonce":      nonce,
                        "key_hint":   key_hint,
                        "msg_id":     msg_id,
                    })
                except Exception as exc:
                    log.warning("Failed to relay group msg to %s: %s", member, exc)

        mark_delivered(msg_id)
        send_packet(self._conn, MessageType.ACK, {"ref_msg_id": msg_id, "status": "sent"})
        log.info("Group msg relayed: from=%s group=%s", self._username, group_name)

    def _handle_logout(self) -> None:
        if self._session_id:
            logout_user(self._session_id)
        send_packet(self._conn, MessageType.ACK, {"ref_msg_id": "logout", "status": "ok"})
        self._active = False

    def _handle_history(self, payload: dict) -> None:
        peer  = payload["peer_or_group"]
        limit = min(int(payload.get("limit", 50)), 200)
        rows  = get_message_history(self._username, peer, limit)
        messages = [
            {
                "msg_id":          r["msg_id"],
                "from":            r["sender_username"],
                "ciphertext":      r["ciphertext"],
                "nonce":           r["nonce"],
                "key_hint":        r["key_hint"],
                "timestamp":       r["timestamp"],
            }
            for r in rows
        ]
        send_packet(self._conn, MessageType.HISTORY_RESPONSE, {"messages": messages})

    # ── Offline message delivery ───────────────────────────────────────────────

    def _deliver_pending(self) -> None:
        rows = get_pending_messages(self._username)
        for row in rows:
            try:
                send_packet(self._conn, MessageType.DIRECT_MESSAGE, {
                    "from":       row["sender_username"],
                    "to":         self._username,
                    "ciphertext": row["ciphertext"],
                    "nonce":      row["nonce"],
                    "key_hint":   row["key_hint"],
                    "msg_id":     row["msg_id"],
                    "offline":    True,
                })
                mark_delivered(row["msg_id"])
            except Exception as exc:
                log.warning("Failed to deliver pending msg %s: %s", row["msg_id"], exc)
        if rows:
            log.info("Delivered %d pending messages to %s", len(rows), self._username)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _send_error(self, code: ErrorCode, detail: str) -> None:
        try:
            send_packet(self._conn, MessageType.ERROR, {
                "code":   code.value if hasattr(code, "value") else code,
                "detail": detail,
            })
        except Exception:
            pass  # connection may already be dead

    def _cleanup(self) -> None:
        if self._username:
            self._server.set_offline(self._username)
            self._server.broadcast_presence(self._username, online=False)
            log.info("User disconnected: username=%s", self._username)
        try:
            self._conn.close()
        except Exception:
            pass


# ── Chat server ───────────────────────────────────────────────────────────────

class ChatServer:
    """
    Manages the server socket, TLS context, and the online-user registry.
    """

    def __init__(self):
        self._online:  dict[str, ClientHandler] = {}
        self._lock     = threading.RLock()

    # ── Online registry ───────────────────────────────────────────────────────

    def set_online(self, username: str, handler: ClientHandler) -> None:
        with self._lock:
            self._online[username] = handler

    def set_offline(self, username: str) -> None:
        with self._lock:
            self._online.pop(username, None)

    def get_handler(self, username: str) -> Optional[ClientHandler]:
        with self._lock:
            return self._online.get(username)

    def online_users(self) -> list[str]:
        with self._lock:
            return list(self._online.keys())

    def broadcast_presence(self, username: str, online: bool) -> None:
        with self._lock:
            handlers = list(self._online.values())
        for h in handlers:
            if h._username != username:
                try:
                    send_packet(h._conn, MessageType.PRESENCE, {
                        "username": username,
                        "online":   online,
                    })
                except Exception:
                    pass

    # ── TLS context ───────────────────────────────────────────────────────────

    @staticmethod
    def _build_tls_context() -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version     = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
        # Disable weak ciphers; prefer ECDHE + AES-GCM
        ctx.set_ciphers(
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "!aNULL:!MD5:!RC4"
        )
        return ctx

    # ── Accept loop ───────────────────────────────────────────────────────────

    def serve_forever(self) -> None:
        init_db()
        tls_ctx = self._build_tls_context()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((SERVER_HOST, SERVER_PORT))
            raw_sock.listen(MAX_CONNECTIONS)
            log.info("Server listening on %s:%d (TLS)", SERVER_HOST, SERVER_PORT)

            with tls_ctx.wrap_socket(raw_sock, server_side=True) as tls_sock:
                while True:
                    try:
                        conn, addr = tls_sock.accept()
                        handler    = ClientHandler(conn, addr, self)
                        handler.start()
                    except ssl.SSLError as exc:
                        log.warning("TLS handshake failed: %s", exc)
                    except OSError:
                        break


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    server = ChatServer()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Server shutting down")


if __name__ == "__main__":
    main()
