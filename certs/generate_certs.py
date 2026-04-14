#!/usr/bin/env python3
"""
certs/generate_certs.py
-----------------------
Generate a self-signed TLS certificate and private key for development.

Usage
-----
    python certs/generate_certs.py

Files created
-------------
    certs/server.key   – 4096-bit RSA private key (PEM)
    certs/server.crt   – self-signed X.509 certificate (PEM, 365 days)

Production note
---------------
Replace these with certificates from a trusted CA (Let's Encrypt, etc.).
The server will automatically pick them up via the SERVER_CERT / SERVER_KEY
environment variables.
"""

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

_OUT = Path(__file__).resolve().parent


def generate_self_signed_cert(
    common_name: str = "localhost",
    days_valid:  int = 365,
) -> None:
    print(f"Generating 4096-bit RSA key pair...")

    # Private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend(),
    )

    # Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   "Dev"),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "SecureChat Dev"),
        x509.NameAttribute(NameOID.COMMON_NAME,              common_name),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=days_valid))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )

    key_path  = _OUT / "server.key"
    cert_path = _OUT / "server.crt"

    # Write private key (600 permissions)
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(key_path, 0o600)

    # Write certificate
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[✓] Private key : {key_path}")
    print(f"[✓] Certificate : {cert_path}")
    print(f"    Valid for   : {days_valid} days (CN={common_name})")
    print("\n  NOTE: This is a SELF-SIGNED cert for development only.")
    print("        Replace with a CA-signed cert for production.\n")


if __name__ == "__main__":
    generate_self_signed_cert()
