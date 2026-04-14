"""
client/client.py
----------------
Terminal-based chat client.

Responsibilities
────────────────
  • Establish a TLS connection to the server
  • Register / login interactively
  • Derive a Fernet key from password + KDF salt (client-side only)
  • Encrypt outgoing messages with the Fernet engine BEFORE sending
  • Decrypt incoming messages locally (server never sees plaintext)
  • Run a background thread for incoming messages
  • Provide a simple readline-based command loop

Commands (at the chat prompt)
──────────────────────────────
  /msg  <user>  <text>      – send a direct encrypted message
  /group <name> <text>      – send to a group
  /history <peer> [limit]   – fetch message history
  /online                   – list online users  (via presence map)
  /quit                     – logout and exit

Key derivation
──────────────
  On login the server sends back the kdf_salt for that account.
  The client calls PBKDF2-HMAC-SHA256(password, kdf_salt) → Fernet key.
  This key is held in memory only for the lifetime of the session.
  The server stores the salt but never the key or any derived value.
"""

from __future__ import annotations

import os
import ssl
import socket
import sys
import threading
import time
from typing import Optional

from crypto_utils.encryption import (
    FernetEngine, EncryptedMessage,
    encrypt_message, decrypt_message, derive_key,
)
from protocol.messages import (
    MessageType, read_packet, send_packet,
)
from shared.config import (
    SERVER_HOST, SERVER_PORT, CA_CERT,
    LOG_LEVEL,
)
from shared.logger import get_logger

log = get_logger(__name__, level=LOG_LEVEL)


class SecureChatClient:
    """
    Handles the full client lifecycle: connect → auth → chat → disconnect.
    """

    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        self._host        = host
        self._port        = port
        self._sock:       Optional[ssl.SSLSocket] = None
        self._username:   Optional[str]  = None
        self._session_id: Optional[str]  = None
        self._fernet_key: Optional[bytes] = None     # derived locally; never sent
        self._seen_nonces: set[str]       = set()
        self._online_users: set[str]      = set()
        self._recv_thread: Optional[threading.Thread] = None
        self._running     = False
        self._engine      = FernetEngine()

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # For self-signed dev certs: load the CA cert and verify hostname=False
        if os.path.exists(CA_CERT):
            tls_ctx.load_verify_locations(CA_CERT)
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode    = ssl.CERT_REQUIRED
        else:
            # Fallback: no verification (dev without certs)
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode    = ssl.CERT_NONE
            log.warning("CA cert not found – TLS certificate verification disabled")

        raw_sock = socket.create_connection((self._host, self._port), timeout=10)
        self._sock = tls_ctx.wrap_socket(raw_sock, server_hostname=self._host)
        log.info("Connected to %s:%d (TLS %s)", self._host, self._port,
                 self._sock.version())

    def disconnect(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    # ── Registration / Login ──────────────────────────────────────────────────

    def register(self, username: str, password: str) -> bool:
        """
        Register a new account.
        NOTE: We send the raw password as 'password_hash' here.
        The SERVER hashes it with bcrypt.  This is intentional for simplicity;
        in a production system you would hash client-side too (SRP or similar).
        """
        send_packet(self._sock, MessageType.REGISTER, {
            "username":      username,
            "password_hash": password,   # server will bcrypt this
        })
        response = read_packet(self._sock)
        if response and response["type"] == MessageType.ACK:
            kdf_salt = response["payload"].get("kdf_salt", "")
            # Derive and cache the Fernet key
            self._fernet_key = self._derive_key(password, kdf_salt)
            self._username   = username
            print(f"[✓] Registered as '{username}'")
            return True
        else:
            detail = response["payload"].get("detail", "Unknown error") if response else "No response"
            print(f"[✗] Registration failed: {detail}")
            return False

    def login(self, username: str, password: str) -> bool:
        send_packet(self._sock, MessageType.LOGIN, {
            "username":      username,
            "password_hash": password,
        })
        response = read_packet(self._sock)
        if response and response["type"] == MessageType.ACK:
            pl               = response["payload"]
            self._session_id = pl.get("session_id")
            kdf_salt         = pl.get("kdf_salt", "")
            self._fernet_key = self._derive_key(password, kdf_salt)
            self._username   = username
            print(f"[✓] Logged in as '{username}'")
            return True
        else:
            detail = response["payload"].get("detail", "Bad credentials") if response else "No response"
            print(f"[✗] Login failed: {detail}")
            return False

    # ── Messaging ─────────────────────────────────────────────────────────────

    def send_direct(self, to: str, text: str) -> None:
        if not self._fernet_key:
            print("[!] Not authenticated")
            return
        enc = encrypt_message(text, self._fernet_key)
        send_packet(self._sock, MessageType.DIRECT_MESSAGE, {
            "to":         to,
            "ciphertext": enc.ciphertext,
            "nonce":      enc.nonce,
            "key_hint":   enc.key_hint,
        })

    def send_group(self, group: str, text: str) -> None:
        if not self._fernet_key:
            print("[!] Not authenticated")
            return
        enc = encrypt_message(text, self._fernet_key)
        send_packet(self._sock, MessageType.GROUP_MESSAGE, {
            "group":      group,
            "ciphertext": enc.ciphertext,
            "nonce":      enc.nonce,
            "key_hint":   enc.key_hint,
        })

    def request_history(self, peer: str, limit: int = 20) -> None:
        send_packet(self._sock, MessageType.HISTORY_REQUEST, {
            "peer_or_group": peer,
            "limit":         limit,
        })

    # ── Receive loop (background thread) ─────────────────────────────────────

    def _start_recv_thread(self) -> None:
        self._running      = True
        self._recv_thread  = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def _recv_loop(self) -> None:
        while self._running:
            try:
                packet = read_packet(self._sock)
                if packet is None:
                    print("\n[!] Server closed the connection")
                    self._running = False
                    break
                self._handle_incoming(packet)
            except ConnectionError:
                if self._running:
                    print("\n[!] Connection lost")
                self._running = False
                break
            except Exception as exc:
                log.error("Recv error: %s", exc, exc_info=False)

    def _handle_incoming(self, packet: dict) -> None:
        msg_type = packet["type"]
        payload  = packet["payload"]

        if msg_type == MessageType.DIRECT_MESSAGE:
            self._print_direct(payload)
        elif msg_type == MessageType.GROUP_MESSAGE:
            self._print_group(payload)
        elif msg_type == MessageType.PRESENCE:
            username = payload.get("username", "?")
            online   = payload.get("online", False)
            if online:
                self._online_users.add(username)
                print(f"\n  ● {username} is now online")
            else:
                self._online_users.discard(username)
                print(f"\n  ○ {username} went offline")
        elif msg_type == MessageType.HISTORY_RESPONSE:
            self._print_history(payload.get("messages", []))
        elif msg_type == MessageType.ACK:
            pass  # silent ACKs
        elif msg_type == MessageType.ERROR:
            print(f"\n[✗] Server error [{payload.get('code')}]: {payload.get('detail')}")
        elif msg_type == MessageType.PONG:
            pass

    def _print_direct(self, payload: dict) -> None:
        sender     = payload.get("from", "?")
        ciphertext = payload.get("ciphertext", "")
        nonce      = payload.get("nonce", "")
        key_hint   = payload.get("key_hint", "")
        offline    = payload.get("offline", False)
        tag        = " [offline]" if offline else ""

        plaintext  = self._try_decrypt(ciphertext, nonce, key_hint)
        timestamp  = time.strftime("%H:%M:%S")
        print(f"\n  [{timestamp}] {sender}{tag} → you: {plaintext}")

    def _print_group(self, payload: dict) -> None:
        sender     = payload.get("from", "?")
        group      = payload.get("group", "?")
        ciphertext = payload.get("ciphertext", "")
        nonce      = payload.get("nonce", "")
        key_hint   = payload.get("key_hint", "")
        plaintext  = self._try_decrypt(ciphertext, nonce, key_hint)
        timestamp  = time.strftime("%H:%M:%S")
        print(f"\n  [{timestamp}] [{group}] {sender}: {plaintext}")

    def _print_history(self, messages: list) -> None:
        print("\n── History ─────────────────────────────")
        for m in messages:
            sender    = m.get("from", "?")
            ts_raw    = m.get("timestamp", 0)
            ts        = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_raw))
            plaintext = self._try_decrypt(
                m.get("ciphertext", ""),
                m.get("nonce", ""),
                m.get("key_hint", ""),
            )
            print(f"  [{ts}] {sender}: {plaintext}")
        print("────────────────────────────────────────")

    def _try_decrypt(self, ciphertext: str, nonce: str, key_hint: str) -> str:
        if not self._fernet_key or not ciphertext:
            return "<encrypted>"
        try:
            msg = EncryptedMessage(ciphertext=ciphertext, nonce=nonce, key_hint=key_hint)
            return decrypt_message(msg, self._fernet_key, self._seen_nonces)
        except Exception:
            return "<unable to decrypt>"

    # ── Key derivation ────────────────────────────────────────────────────────

    @staticmethod
    def _derive_key(password: str, kdf_salt_hex: str) -> bytes:
        try:
            salt = bytes.fromhex(kdf_salt_hex)
        except ValueError:
            salt = os.urandom(16)
        return derive_key(password, salt)

    # ── Terminal UI ───────────────────────────────────────────────────────────

    def run_interactive(self) -> None:
        """Main command-line loop."""
        self.connect()

        print("\n╔══════════════════════════════════════╗")
        print("║     Secure Chat — E2E Encrypted      ║")
        print("╚══════════════════════════════════════╝\n")

        # Auth flow
        while not self._username:
            choice = input("  (r) Register   (l) Login   (q) Quit > ").strip().lower()
            if choice == "q":
                self.disconnect()
                return
            username = input("  Username: ").strip()
            password = self._get_password("  Password: ")
            if choice == "r":
                if not self.register(username, password):
                    continue
            elif choice == "l":
                if not self.login(username, password):
                    continue
            else:
                print("  Unknown option")
                continue

        self._start_recv_thread()
        self._print_help()

        # Chat loop
        while self._running:
            try:
                line = input("").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not line:
                continue

            if line.startswith("/msg "):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    self.send_direct(parts[1], parts[2])
                else:
                    print("  Usage: /msg <user> <text>")

            elif line.startswith("/group "):
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    self.send_group(parts[1], parts[2])
                else:
                    print("  Usage: /group <name> <text>")

            elif line.startswith("/history "):
                parts = line.split()
                peer  = parts[1] if len(parts) > 1 else ""
                limit = int(parts[2]) if len(parts) > 2 else 20
                if peer:
                    self.request_history(peer, limit)
                else:
                    print("  Usage: /history <peer_or_group> [limit]")

            elif line == "/online":
                users = list(self._online_users)
                print(f"  Online: {', '.join(users) if users else '(none)'}")

            elif line == "/help":
                self._print_help()

            elif line == "/quit":
                break

            else:
                print("  Unknown command. Type /help for commands.")

        # Logout
        if self._username:
            try:
                send_packet(self._sock, MessageType.LOGOUT, {})
                read_packet(self._sock)
            except Exception:
                pass
        self.disconnect()
        print("\n  Goodbye.")

    @staticmethod
    def _print_help() -> None:
        print("\n  Commands:")
        print("    /msg  <user>  <text>         Send a direct message")
        print("    /group <name> <text>         Send to a group")
        print("    /history <peer> [n]          Fetch message history")
        print("    /online                      List online users")
        print("    /quit                        Logout and exit\n")

    @staticmethod
    def _get_password(prompt: str) -> str:
        import getpass
        return getpass.getpass(prompt)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("--host", default=SERVER_HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    args   = parser.parse_args()

    client = SecureChatClient(host=args.host, port=args.port)
    client.run_interactive()


if __name__ == "__main__":
    main()
