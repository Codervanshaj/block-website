from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import AppConfig


ROOT_CA_NAME = "Prevent Visit Local Root CA"
LEAF_COMMON_NAME = "Prevent Visit Intercept Certificate"


class CertificateManager:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.base_dir = Path(config.certs_dir)
        self.root_key_path = self.base_dir / "root_ca_key.pem"
        self.root_cert_pem_path = self.base_dir / "root_ca_cert.pem"
        self.root_cert_der_path = self.base_dir / "root_ca_cert.cer"
        self.leaf_key_path = self.base_dir / "leaf_key.pem"
        self.leaf_dir = self.base_dir / "leaf"

    def ensure_root_ca(self) -> tuple[Path, Path]:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if self.root_key_path.exists() and self.root_cert_pem_path.exists() and self.root_cert_der_path.exists():
            return self.root_key_path, self.root_cert_pem_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Prevent Visit"),
                x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CA_NAME),
            ]
        )
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
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
            .sign(key, hashes.SHA256())
        )

        self.root_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.root_cert_pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.root_cert_der_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
        return self.root_key_path, self.root_cert_pem_path

    def ensure_leaf_key(self) -> Path:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if self.leaf_key_path.exists():
            return self.leaf_key_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.leaf_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        return self.leaf_key_path

    def get_or_create_leaf_cert(self, host: str) -> Path:
        self.ensure_root_ca()
        self.ensure_leaf_key()
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        safe_name = host.replace("*", "_wildcard_").replace(":", "_")
        cert_path = self.leaf_dir / f"{safe_name}.pem"
        if cert_path.exists():
            return cert_path

        root_key = serialization.load_pem_private_key(self.root_key_path.read_bytes(), password=None)
        root_cert = x509.load_pem_x509_certificate(self.root_cert_pem_path.read_bytes())
        leaf_key = serialization.load_pem_private_key(self.leaf_key_path.read_bytes(), password=None)

        now = datetime.now(timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Prevent Visit"),
                        x509.NameAttribute(NameOID.COMMON_NAME, LEAF_COMMON_NAME),
                    ]
                )
            )
            .issuer_name(root_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(
                x509.SubjectAlternativeName([self._build_name(host)]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )
        cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256())
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path

    @staticmethod
    def _build_name(host: str) -> x509.GeneralName:
        try:
            return x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            return x509.DNSName(host)
