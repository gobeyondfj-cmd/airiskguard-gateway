from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime
from datetime import UTC

from airiskguard_gateway.config import CONFIG_DIR

CERT_DIR = CONFIG_DIR
CA_KEY_FILE = CERT_DIR / "ca.key"
CA_CERT_FILE = CERT_DIR / "ca.pem"


class CertManager:
    def ensure_cert(self) -> Path:
        """Generate CA if it doesn't exist. Return the mitmproxy confdir (cert_dir)."""
        CERT_DIR.mkdir(parents=True, exist_ok=True)

        # mitmproxy looks for mitmproxy-ca.pem in the confdir
        mitm_ca = CERT_DIR / "mitmproxy-ca.pem"
        if not mitm_ca.exists():
            self._generate_ca()

        return CERT_DIR

    def install_to_system(self) -> str:
        """Install CA to OS trust store. Returns status message."""
        self.ensure_cert()
        os_name = platform.system()

        if os_name == "Darwin":
            return self._install_macos()
        elif os_name == "Linux":
            return self._install_linux()
        elif os_name == "Windows":
            return self._install_windows()
        else:
            return f"Unsupported OS: {os_name}. Manually trust: {CERT_DIR / 'mitmproxy-ca-cert.pem'}"

    def cert_pem_path(self) -> Path:
        return CERT_DIR / "mitmproxy-ca-cert.pem"

    def _generate_ca(self) -> None:
        """Generate a CA key + cert and write mitmproxy-compatible files."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "AIRiskGuard Gateway CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIRiskGuard"),
        ])

        now = datetime.datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)

        # mitmproxy expects mitmproxy-ca.pem = cert + key combined
        (CERT_DIR / "mitmproxy-ca.pem").write_bytes(cert_pem + key_pem)
        # Public cert only (for OS trust store installation)
        (CERT_DIR / "mitmproxy-ca-cert.pem").write_bytes(cert_pem)
        (CERT_DIR / "mitmproxy-ca-cert.cer").write_bytes(cert_pem)

    def _install_macos(self) -> str:
        cert_path = str(self.cert_pem_path())
        result = subprocess.run(
            ["security", "add-trusted-cert", "-d", "-r", "trustRoot",
             "-k", "/Library/Keychains/System.keychain", cert_path],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return f"CA installed to macOS System keychain. Path: {cert_path}"
        return f"Failed (may need sudo): {result.stderr.strip()}\n\nRun manually:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {cert_path}"

    def _install_linux(self) -> str:
        cert_path = self.cert_pem_path()
        dest = Path("/usr/local/share/ca-certificates/airiskguard-gateway.crt")
        try:
            shutil.copy(cert_path, dest)
            subprocess.run(["update-ca-certificates"], check=True)
            return f"CA installed to {dest}"
        except (PermissionError, subprocess.CalledProcessError) as e:
            return (
                f"Failed (may need sudo): {e}\n\nRun manually:\n"
                f"  sudo cp {cert_path} {dest}\n"
                f"  sudo update-ca-certificates"
            )

    def _install_windows(self) -> str:
        cert_path = str(self.cert_pem_path())
        result = subprocess.run(
            ["certutil", "-addstore", "Root", cert_path],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return f"CA installed to Windows Root store. Path: {cert_path}"
        return f"Failed: {result.stderr.strip()}\n\nRun manually (as admin):\n  certutil -addstore Root {cert_path}"
