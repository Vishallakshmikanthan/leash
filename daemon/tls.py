"""
daemon/tls.py - TLS certificate generation and SSLContext helpers for Leash.
"""
from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from daemon.paths import tls_cert_path, tls_key_path


def get_cert_fingerprint(cert_der: bytes) -> str:
    """Calculate SHA-256 fingerprint in lowercase hex."""
    return hashlib.sha256(cert_der).hexdigest()


def generate_self_signed_cert(
    cert_file: Path | str | None = None,
    key_file: Path | str | None = None,
    valid_days: int = 365,
    common_name: str = "leash.local",
) -> Tuple[Path, Path, str]:
    """
    Generates a self-signed ECDSA P-256 certificate and private key.
    Returns: (cert_path, key_path, sha256_fingerprint)
    """
    cert_p = Path(cert_file) if cert_file else tls_cert_path()
    key_p = Path(key_file) if key_file else tls_key_path()

    if cert_p.exists() and key_p.exists():
        cert_data = cert_p.read_bytes()
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
            der = cert.public_bytes(serialization.Encoding.DER)
            return cert_p, key_p, get_cert_fingerprint(der)
        except Exception:
            pass  # regenerate if corrupt

    # Generate EC key
    key = ec.generate_private_key(ec.SECP256R1())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Leash"),
    ])

    alt_names = [
        x509.DNSName("localhost"),
        x509.DNSName("leash.local"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
    ]

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_p.parent.mkdir(parents=True, exist_ok=True)
    key_p.parent.mkdir(parents=True, exist_ok=True)

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_p.write_bytes(cert_bytes)
    key_p.write_bytes(key_bytes)
    try:
        key_p.chmod(0o600)
    except (AttributeError, OSError):
        pass

    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = get_cert_fingerprint(der)
    return cert_p, key_p, fingerprint


def create_server_ssl_context(
    cert_file: Path | str | None = None,
    key_file: Path | str | None = None,
) -> Tuple[ssl.SSLContext, str]:
    """
    Creates an SSLContext configured for TLS 1.2+ server.
    Returns (ssl_context, sha256_fingerprint).
    """
    cert_p, key_p, fingerprint = generate_self_signed_cert(cert_file, key_file)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_p), str(key_p))
    return ctx, fingerprint
