"""Test TLS 1.3 ClientHello contains SNI and ALPN extensions.

Uses a Python TLS server with SNI callback and ALPN settings to verify
the assembly TLS client sends proper SNI hostname and ALPN protocols.
"""
import subprocess
import struct
import os
import socket
import ssl
import threading
import time
import tempfile
import pytest

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


@pytest.fixture(scope="module")
def cert_files():
    """Module-scoped cert files."""
    certfile, keyfile = _generate_cert_files()
    yield certfile, keyfile
    os.unlink(certfile)
    os.unlink(keyfile)


def _run_tls_client(port, timeout=30):
    """Run the assembly TLS client binary."""
    inp = struct.pack("<H", port)
    result = subprocess.run(
        [BINARY],
        input=inp,
        capture_output=True,
        timeout=timeout
    )
    return result


class TestSNI:
    """Verify SNI hostname is present in TLS ClientHello."""

    def test_sni_hostname_in_clienthello(self, cert_files):
        """Python TLS server with SNI callback captures the hostname."""
        certfile, keyfile = cert_files
        sni_received = []

        def sni_callback(ssl_sock, server_name, ssl_ctx):
            sni_received.append(server_name)
            return None  # continue with default context

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass
        ctx.load_cert_chain(certfile, keyfile)
        ctx.sni_callback = sni_callback

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
        time.sleep(0.1)

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0, (
                f"TLS client failed: exit={result.returncode}, stderr={result.stderr!r}"
            )
            assert result.stdout == b"HELLO_TLS", (
                f"Expected echo, got: {result.stdout!r}"
            )
            assert len(sni_received) >= 1, "No SNI callback received"
            assert sni_received[0] == "www.microsoft.com", (
                f"Expected SNI 'www.microsoft.com', got '{sni_received[0]}'"
            )
        finally:
            stop_event.set()
            t.join(timeout=5)


class TestALPN:
    """Verify ALPN protocols are present in TLS ClientHello."""

    def test_alpn_protocols_in_clienthello(self, cert_files):
        """Python TLS server with ALPN settings verifies negotiated protocol."""
        certfile, keyfile = cert_files
        negotiated_protocol = []

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass
        ctx.load_cert_chain(certfile, keyfile)
        # Server advertises h2 — should match client's ALPN
        ctx.set_alpn_protocols(["h2", "http/1.1"])

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
                proto = tls_conn.selected_alpn_protocol()
                negotiated_protocol.append(proto)
                while not stop_event.is_set():
                    try:
                        data = tls_conn.recv(16384)
                        if not data:
                            break
                        tls_conn.sendall(data)
                    except (ssl.SSLError, socket.timeout, ConnectionResetError, BrokenPipeError):
                        break
                tls_conn.close()
            except (ssl.SSLError, OSError) as e:
                negotiated_protocol.append(f"error: {e}")
                try:
                    raw_conn.close()
                except Exception:
                    pass
            finally:
                srv.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0, (
                f"TLS client failed: exit={result.returncode}, stderr={result.stderr!r}"
            )
            assert len(negotiated_protocol) >= 1, "No ALPN negotiation happened"
            assert negotiated_protocol[0] == "h2", (
                f"Expected ALPN 'h2', got '{negotiated_protocol[0]}'"
            )
        finally:
            stop_event.set()
            t.join(timeout=5)

    def test_alpn_http11_fallback(self, cert_files):
        """Server only offers http/1.1 — should negotiate http/1.1."""
        certfile, keyfile = cert_files
        negotiated_protocol = []

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass
        ctx.load_cert_chain(certfile, keyfile)
        ctx.set_alpn_protocols(["http/1.1"])

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
                proto = tls_conn.selected_alpn_protocol()
                negotiated_protocol.append(proto)
                while not stop_event.is_set():
                    try:
                        data = tls_conn.recv(16384)
                        if not data:
                            break
                        tls_conn.sendall(data)
                    except (ssl.SSLError, socket.timeout, ConnectionResetError, BrokenPipeError):
                        break
                tls_conn.close()
            except (ssl.SSLError, OSError) as e:
                negotiated_protocol.append(f"error: {e}")
                try:
                    raw_conn.close()
                except Exception:
                    pass
            finally:
                srv.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0, (
                f"TLS client failed: exit={result.returncode}, stderr={result.stderr!r}"
            )
            assert len(negotiated_protocol) >= 1, "No ALPN negotiation happened"
            assert negotiated_protocol[0] == "http/1.1", (
                f"Expected ALPN 'http/1.1', got '{negotiated_protocol[0]}'"
            )
        finally:
            stop_event.set()
            t.join(timeout=5)


class TestSNIALPNCombined:
    """Test SNI + ALPN work together and TLS handshake completes."""

    def test_tls_with_sni_alpn_succeeds(self, cert_files):
        """Full TLS handshake with SNI + ALPN, then data exchange."""
        certfile, keyfile = cert_files
        sni_received = []
        negotiated_protocol = []

        def sni_callback(ssl_sock, server_name, ssl_ctx):
            sni_received.append(server_name)
            return None

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            ctx.set_ciphersuites("TLS_CHACHA20_POLY1305_SHA256")
        except Exception:
            pass
        ctx.load_cert_chain(certfile, keyfile)
        ctx.sni_callback = sni_callback
        ctx.set_alpn_protocols(["h2", "http/1.1"])

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
                proto = tls_conn.selected_alpn_protocol()
                negotiated_protocol.append(proto)
                while not stop_event.is_set():
                    try:
                        data = tls_conn.recv(16384)
                        if not data:
                            break
                        tls_conn.sendall(data)
                    except (ssl.SSLError, socket.timeout, ConnectionResetError, BrokenPipeError):
                        break
                tls_conn.close()
            except (ssl.SSLError, OSError) as e:
                negotiated_protocol.append(f"error: {e}")
                try:
                    raw_conn.close()
                except Exception:
                    pass
            finally:
                srv.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            result = _run_tls_client(port)
            assert result.returncode == 0, (
                f"TLS client failed: exit={result.returncode}, stderr={result.stderr!r}"
            )
            assert result.stdout == b"HELLO_TLS"
            assert sni_received[0] == "www.microsoft.com"
            assert negotiated_protocol[0] == "h2"
        finally:
            stop_event.set()
            t.join(timeout=5)


class TestSNIRawCapture:
    """Capture raw ClientHello bytes to verify SNI and ALPN are present."""

    def test_sni_bytes_in_raw_clienthello(self, cert_files):
        """Read raw ClientHello, verify 'www.microsoft.com' bytes are present."""
        certfile, keyfile = cert_files
        captured_data = []

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        port = srv.getsockname()[1]

        def run():
            srv.settimeout(30)
            try:
                raw_conn, _ = srv.accept()
            except socket.timeout:
                srv.close()
                return
            try:
                # Read the first TLS record (ClientHello)
                raw_conn.settimeout(10)
                # TLS record header: type(1) + version(2) + length(2) = 5 bytes
                header = b""
                while len(header) < 5:
                    header += raw_conn.recv(5 - len(header))

                record_len = struct.unpack(">H", header[3:5])[0]
                record_body = b""
                while len(record_body) < record_len:
                    record_body += raw_conn.recv(record_len - len(record_body))

                captured_data.append(header + record_body)

                # Now wrap in TLS to let handshake complete (best effort)
                # Actually, we already consumed the ClientHello, so we can't
                # easily hand off to ssl. Just close.
                raw_conn.close()
            except Exception:
                try:
                    raw_conn.close()
                except Exception:
                    pass
            finally:
                srv.close()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        time.sleep(0.1)

        try:
            # Client will fail (server closes after capture), that's fine
            _run_tls_client(port, timeout=10)
        except Exception:
            pass

        t.join(timeout=5)

        assert len(captured_data) >= 1, "No ClientHello captured"
        raw = captured_data[0]

        # Verify SNI hostname bytes are in the record
        assert b"www.microsoft.com" in raw, (
            f"SNI hostname 'www.microsoft.com' not found in raw ClientHello "
            f"({len(raw)} bytes)"
        )

        # Verify ALPN protocol identifiers
        assert b"h2" in raw, "ALPN protocol 'h2' not found in raw ClientHello"
        assert b"http/1.1" in raw, "ALPN protocol 'http/1.1' not found in raw ClientHello"
