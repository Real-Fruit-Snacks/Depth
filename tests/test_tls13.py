"""Test TLS 1.3 handshake and encrypted record layer against Python ssl module."""
import subprocess, struct, os, socket, ssl, threading, time, tempfile, pytest

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_tls13")


def _generate_cert_files():
    """Generate a self-signed ECDSA cert + key in temp files."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.local"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    )

    certfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    certfile.write(cert_pem)
    certfile.close()

    keyfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    keyfile.write(key_pem)
    keyfile.close()

    return certfile.name, keyfile.name


def _start_tls_echo_server(certfile, keyfile):
    """Start a TLS 1.3 echo server. Returns (port, server_thread, stop_event)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    # Try to set ChaCha20-Poly1305 cipher; fall back if not available
    try:
        ctx.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
    except Exception:
        pass  # Let OpenSSL pick; it should still work if ChaCha20 is supported
    ctx.load_cert_chain(certfile, keyfile)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    stop_event = threading.Event()

    def run():
        srv.settimeout(30)
        try:
            raw_conn, _ = srv.accept()
        except socket.timeout:
            srv.close()
            return
        try:
            tls_conn = ctx.wrap_socket(raw_conn, server_side=True)
            tls_conn.settimeout(10)
            while not stop_event.is_set():
                try:
                    data = tls_conn.recv(16384)
                    if not data:
                        break
                    tls_conn.sendall(data)
                except (ssl.SSLError, socket.timeout, ConnectionResetError, BrokenPipeError):
                    break
            tls_conn.close()
        except (ssl.SSLError, OSError):
            try:
                raw_conn.close()
            except Exception:
                pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, t, stop_event


def _run_tls_client(port, timeout=30):
    """Run the assembly TLS client, sending the port on stdin."""
    inp = struct.pack("<H", port)
    result = subprocess.run(
        [BINARY],
        input=inp,
        capture_output=True,
        timeout=timeout
    )
    return result


@pytest.fixture(scope="module")
def cert_files():
    """Module-scoped cert files."""
    certfile, keyfile = _generate_cert_files()
    yield certfile, keyfile
    os.unlink(certfile)
    os.unlink(keyfile)


class TestTLS13Handshake:
    """Test TLS 1.3 handshake completes successfully."""

    def test_handshake_completes(self, cert_files):
        """Assembly client connects, completes TLS 1.3 handshake, exchanges data."""
        certfile, keyfile = cert_files
        port, server_thread, stop_event = _start_tls_echo_server(certfile, keyfile)
        time.sleep(0.1)  # Let server bind

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0, (
                f"TLS client failed with exit code {result.returncode}\n"
                f"stderr: {result.stderr!r}"
            )
            # Should have received "HELLO_TLS" echo
            assert result.stdout == b"HELLO_TLS", (
                f"Expected b'HELLO_TLS', got {result.stdout!r}"
            )
        finally:
            stop_event.set()
            server_thread.join(timeout=5)

    def test_handshake_multiple_connections(self, cert_files):
        """Verify handshake works across multiple independent connections."""
        certfile, keyfile = cert_files
        for i in range(3):
            port, server_thread, stop_event = _start_tls_echo_server(certfile, keyfile)
            time.sleep(0.1)
            try:
                result = _run_tls_client(port)
                assert result.returncode == 0, f"Connection {i} failed: {result.stderr!r}"
                assert result.stdout == b"HELLO_TLS"
            finally:
                stop_event.set()
                server_thread.join(timeout=5)


class TestTLS13DataRoundtrip:
    """Test encrypted data exchange after handshake."""

    def test_echo_roundtrip(self, cert_files):
        """Basic echo test — send HELLO_TLS, receive it back."""
        certfile, keyfile = cert_files
        port, server_thread, stop_event = _start_tls_echo_server(certfile, keyfile)
        time.sleep(0.1)

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0
            assert result.stdout == b"HELLO_TLS"
        finally:
            stop_event.set()
            server_thread.join(timeout=5)
