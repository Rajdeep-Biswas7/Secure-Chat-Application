#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup_project.py
----------------
One-shot project bootstrapper.

Run once after cloning:
    python setup_project.py

What it does
────────────
  1. Creates the logs/ directory
  2. Copies .env.example → .env (if not already present)
  3. Generates a self-signed TLS certificate + key in certs/
  4. Initialises the SQLite database (creates all tables)
  5. Creates two demo users and a demo group for quick testing
  6. Prints a usage summary
"""

import os
import sys
import shutil
from pathlib import Path

# Fix Windows console encoding for Unicode characters
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ── Step 1: directories ───────────────────────────────────────────────────────
print("\n[1/5] Creating runtime directories...")
(ROOT / "logs").mkdir(exist_ok=True)
(ROOT / "certs").mkdir(exist_ok=True)
print("      logs/  ✓")
print("      certs/ ✓")

# ── Step 2: .env file ─────────────────────────────────────────────────────────
print("\n[2/5] Setting up environment file...")
env_example = ROOT / ".env.example"
env_file    = ROOT / ".env"
if not env_file.exists():
    shutil.copy(env_example, env_file)
    print(f"      Created .env from .env.example ✓")
else:
    print(f"      .env already exists – skipping ✓")

# ── Step 3: TLS certificates ──────────────────────────────────────────────────
print("\n[3/5] Generating self-signed TLS certificate...")
cert_path = ROOT / "certs" / "server.crt"
key_path  = ROOT / "certs" / "server.key"
if cert_path.exists() and key_path.exists():
    print("      Certificates already exist – skipping ✓")
else:
    from certs.generate_certs import generate_self_signed_cert
    generate_self_signed_cert()

# ── Step 4: Database ──────────────────────────────────────────────────────────
print("\n[4/5] Initialising SQLite database...")
from database.db import init_db
init_db()
print("      Database initialised ✓")

# ── Step 5: Demo data ─────────────────────────────────────────────────────────
print("\n[5/5] Creating demo users and group...")
from auth.auth import register_user, RegistrationError
from database.db import create_group, get_user_by_username

demo_accounts = [
    ("alice", "AlicePass1!"),
    ("bob",   "BobPass123!"),
]

user_ids = {}
for username, password in demo_accounts:
    try:
        result = register_user(username, password)
        user_ids[username] = result["user_id"]
        print(f"      User '{username}' created ✓")
    except RegistrationError:
        row = get_user_by_username(username)
        if row:
            user_ids[username] = row["user_id"]
        print(f"      User '{username}' already exists – skipping ✓")

# Create demo group
if "alice" in user_ids:
    from database.db import get_group_by_name, add_group_member
    if get_group_by_name("general") is None:
        gid = create_group("general", user_ids["alice"])
        # Add bob if he exists
        if "bob" in user_ids:
            add_group_member("general", "bob")
        print("      Group 'general' created with alice + bob ✓")
    else:
        print("      Group 'general' already exists – skipping ✓")

# ── Summary ───────────────────────────────────────────────────────────────────
print("""
╔══════════════════════════════════════════════════════════════╗
║           Secure Chat — Setup Complete                       ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Start the server:                                           ║
║    python -m server.server                                   ║
║                                                              ║
║  Start a client (new terminal):                              ║
║    python -m client.client                                   ║
║                                                              ║
║  Demo accounts:                                              ║
║    alice / AlicePass1!                                       ║
║    bob   / BobPass123!                                       ║
║                                                              ║
║  Demo group: 'general'                                       ║
║                                                              ║
║  Run tests:                                                  ║
║    pytest                                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")
