"""Test SSH-inside-TLS: assembly client does TLS handshake then SSH kex+auth through TLS tunnel.

Architecture:
  [ASM client] --TLS 1.3--> [Python TLS server (mock SSH kex+auth on decrypted stream)]

The Python test creates a single TLS server socket. When the assembly client
connects and completes the TLS handshake, the mock SSH server (do_kex_as_server
+ do_auth_as_server from test_ssh_multichan.py) runs directly on the ssl-wrapped
socket — TLS is transparent at that layer.
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

import pytest

# Import the proven mock SSH server helpers
sys.path.insert(0, os.path.dirname(__file__))
from test_ssh_multichan import (
    do_kex_as_server,
    do_auth_as_server,
    build_kexinit_payload,
    build_plain_packet,
    recv_plain_packet,
    encode_string,
    encode_mpint,
    recv_exact,
    python_ssh_aead_encrypt,
    recv_encrypted_packet,
    send_encrypted_packet,
    derive_key_64,
)

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_tls_ssh")
SSH_PASSWORD = b"changeme"


def _generate_tls_cert():
    """Generate self-signed ECDSA cert for the TLS server."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from datetime import datetime, timedelta, timezone

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "tls-ssh-test.local"),
    ])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=1))
            .sign(key, hashes.SHA256()))

    certfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    certfile.write(cert.public_bytes(serialization.Encoding.PEM))
    certfile.close()

    keyfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyfile.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    keyfile.close()

    return certfile.name, keyfile.name


def _start_tls_ssh_server(certfile, keyfile, password=SSH_PASSWORD):
    """Start a TLS server that runs mock SSH kex+auth directly on the decrypted stream.

    Returns (port, thread, results_dict).
    The results_dict is populated by the handler thread:
      - results['success'] = True on success
      - results['error']   = str on failure
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    results = {}

    def handler():
        conn = None
        try:
            srv.settimeout(30)
            raw, _ = srv.accept()
            raw.settimeout(15)
            conn = ctx.wrap_socket(raw, server_side=True)
            # Run mock SSH server directly on the TLS-decrypted stream.
            # ssl.SSLSocket.recv/sendall are transparent — no changes needed.
            keys = do_kex_as_server(conn)
            do_auth_as_server(conn, keys, password)
            results['success'] = True
        except Exception as e:
            results['error'] = str(e)
            import traceback
            traceback.print_exc()
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            try:
                srv.close()
            except Exception:
                pass

    t = threading.Thread(target=handler, daemon=True)
    t.start()
    return port, t, results


def _run_tls_ssh_client(port, timeout=30):
    """Run the assembly TLS+SSH client binary."""
    inp = struct.pack("<H", port)
    result = subprocess.run(
        [BINARY],
        input=inp,
        capture_output=True,
        timeout=timeout,
    )
    return result


@pytest.fixture(scope="module")
def tls_cert_files():
    certfile, keyfile = _generate_tls_cert()
    yield certfile, keyfile
    os.unlink(certfile)
    os.unlink(keyfile)


class TestTLSSSHIntegration:
    """Test SSH-inside-TLS: TLS handshake then SSH kex+auth through TLS tunnel."""

    def test_tls_ssh_handshake_and_auth(self, tls_cert_files):
        """Assembly client: TLS connect -> SSH kex -> SSH password auth -> success."""
        certfile, keyfile = tls_cert_files

        port, thread, results = _start_tls_ssh_server(certfile, keyfile)
        time.sleep(0.1)

        result = _run_tls_ssh_client(port)
        thread.join(timeout=10)

        assert results.get('success'), (
            f"Server failed: {results.get('error')}"
        )
        assert result.returncode == 0, (
            f"TLS+SSH client failed (exit {result.returncode})\n"
            f"stdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}"
        )
        assert result.stdout == b"OK", (
            f"Expected b'OK', got {result.stdout!r}"
        )

    def test_tls_ssh_multiple_connections(self, tls_cert_files):
        """Verify multiple sequential TLS+SSH connections succeed."""
        certfile, keyfile = tls_cert_files

        for i in range(3):
            port, thread, results = _start_tls_ssh_server(certfile, keyfile)
            time.sleep(0.1)

            result = _run_tls_ssh_client(port)
            thread.join(timeout=10)

            assert results.get('success'), (
                f"Connection {i} server failed: {results.get('error')}"
            )
            assert result.returncode == 0, (
                f"Connection {i} failed: exit {result.returncode}\n"
                f"stdout: {result.stdout!r}\n"
                f"stderr: {result.stderr!r}"
            )
            assert result.stdout == b"OK", (
                f"Connection {i}: expected b'OK', got {result.stdout!r}"
            )

    def test_tls_ssh_wrong_password_fails(self, tls_cert_files):
        """Verify auth failure when SSH server rejects the password."""
        certfile, keyfile = tls_cert_files

        # Start server expecting a different password — client sends SSH_PASSWORD
        wrong_expected = b"not_the_right_password"
        port, thread, results = _start_tls_ssh_server(
            certfile, keyfile, password=wrong_expected
        )
        time.sleep(0.1)

        result = _run_tls_ssh_client(port, timeout=10)
        thread.join(timeout=10)

        # Client should fail (non-zero exit) since password is rejected
        assert result.returncode != 0, (
            f"Expected auth failure but client succeeded\n"
            f"stdout: {result.stdout!r}\n"
            f"stderr: {result.stderr!r}"
        )
