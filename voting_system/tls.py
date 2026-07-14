"""
TLS configuration shared by nodes, clients and integration tests.

The prototype uses a small local certificate authority instead of disabling
certificate verification. The generated CA signs one development server
certificate that is valid for localhost and 127.0.0.1. Every local HTTPS
server uses that certificate, while Python peer clients trust only the local
CA file.

Production deployments must replace these generated files with certificates
and private keys managed by the actual deployment infrastructure.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TLS_DIR = PROJECT_ROOT / ".node-data" / "tls"


@dataclass(frozen=True)
class TLSPaths:
    """Filesystem locations needed by HTTPS servers and verified clients."""

    ca_cert: Path
    server_cert: Path
    server_key: Path

    def apply_to_environment(self, environment: dict[str, str]) -> None:
        """Expose canonical absolute TLS paths to a child process."""
        environment["TLS_CA_CERT"] = str(self.ca_cert)
        environment["TLS_CERT_FILE"] = str(self.server_cert)
        environment["TLS_KEY_FILE"] = str(self.server_key)


def _write_private_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    """Persist one unencrypted development key with owner-only permissions."""
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


def _subject(common_name: str) -> x509.Name:
    """Create the compact X.509 subject used by local demo certificates."""
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Voting Blockchain Development"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def _material_is_current(paths: TLSPaths) -> bool:
    """Return whether existing certificates contain the required TLS metadata."""
    try:
        ca_cert = x509.load_pem_x509_certificate(paths.ca_cert.read_bytes())
        server_cert = x509.load_pem_x509_certificate(paths.server_cert.read_bytes())
        ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        ca_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        server_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        server_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        server_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return True
    except (ValueError, x509.ExtensionNotFound):
        return False


def ensure_development_tls_material(
    tls_dir: Path | None = None,
    *,
    force: bool = False,
    extra_hosts: list[str] | None = None,
) -> TLSPaths:
    """
    Create a local CA and localhost server certificate when they do not exist.

    ``extra_hosts`` allows a LAN address or DNS name to be included for a
    presentation on multiple computers. Regeneration is explicit because
    silently replacing the CA would break trust and any already running node.
    """
    directory = (tls_dir or DEFAULT_TLS_DIR).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    paths = TLSPaths(
        ca_cert=directory / "development-ca.pem",
        server_cert=directory / "server-cert.pem",
        server_key=directory / "server-key.pem",
    )
    ca_key_path = directory / "development-ca-key.pem"
    required = [paths.ca_cert, paths.server_cert, paths.server_key, ca_key_path]
    if not force and all(path.exists() for path in required) and _material_is_current(paths):
        return paths

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _subject("Voting Blockchain Development CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    san_names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    for host in extra_hosts or []:
        value = host.strip()
        if not value:
            continue
        try:
            san_names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            san_names.append(x509.DNSName(value))

    server_cert = (
        x509.CertificateBuilder()
        .subject_name(_subject("localhost"))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    _write_private_key(ca_key_path, ca_key)
    _write_private_key(paths.server_key, server_key)
    paths.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    paths.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    return paths


def configured_tls_paths() -> TLSPaths:
    """
    Resolve custom TLS files or create the default local development material.

    Custom deployments must provide certificate and key together. A dedicated
    CA file is recommended; when omitted, the certificate itself is used as
    trust anchor to support deliberately self-signed development certificates.
    """
    cert_value = os.environ.get("TLS_CERT_FILE")
    key_value = os.environ.get("TLS_KEY_FILE")
    ca_value = os.environ.get("TLS_CA_CERT")
    if cert_value or key_value:
        if not cert_value or not key_value:
            raise ValueError("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
        cert = Path(cert_value).expanduser().resolve()
        key = Path(key_value).expanduser().resolve()
        ca = Path(ca_value).expanduser().resolve() if ca_value else cert
        for path in [cert, key, ca]:
            if not path.exists():
                raise FileNotFoundError(f"TLS file does not exist: {path}")
        return TLSPaths(ca_cert=ca, server_cert=cert, server_key=key)

    extra_hosts = [
        host.strip()
        for host in os.environ.get("TLS_EXTRA_HOSTS", "").split(",")
        if host.strip()
    ]
    return ensure_development_tls_material(extra_hosts=extra_hosts)


def create_client_ssl_context(ca_cert: Path | str | None = None) -> ssl.SSLContext:
    """Create a verifying TLS client context for node and CLI HTTPS calls."""
    configured_ca = ca_cert or os.environ.get("TLS_CA_CERT")
    if not configured_ca and (DEFAULT_TLS_DIR / "development-ca.pem").exists():
        configured_ca = DEFAULT_TLS_DIR / "development-ca.pem"
    if configured_ca:
        return ssl.create_default_context(cafile=str(configured_ca))
    return ssl.create_default_context()
