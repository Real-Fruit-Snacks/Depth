"""Integration test: SSH password authentication — assembly client/server vs Python mock.

Tests ssh_auth_client_password and ssh_auth_server_password by running
the full kex handshake first, then the auth protocol over encrypted packets.
"""
import subprocess, struct, os, socket, threading, hashlib, time, pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

AUTH_BINARY = "./build/test_ssh_auth"


# ---- Wire helpers ----

def encode_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def encode_mpint(value_be: bytes) -> bytes:
    be = value_be  # X25519 output treated as BE per OpenSSH convention
    while len(be) > 1 and be[0] == 0:
        be = be[1:]
    if not be:
        return struct.pack(">I", 0)
    if be[0] & 0x80:
        be = b'\x00' + be
    return struct.pack(">I", len(be)) + be


def build_kexinit_payload():
    payload = bytes([20])  # SSH_MSG_KEXINIT
    payload += os.urandom(16)  # cookie
    name_lists = [
        b"curve25519-sha256",
        b"ssh-ed25519",
        b"chacha20-poly1305@openssh.com",
        b"chacha20-poly1305@openssh.com",
        b"hmac-sha2-256",  # mac c2s
        b"hmac-sha2-256",  # mac s2c
        b"none",
        b"none",
        b"",  # languages c2s
        b"",  # languages s2c
    ]
    for nl in name_lists:
        payload += encode_string(nl)
    payload += bytes([0])  # first_kex_packet_follows = FALSE
    payload += struct.pack(">I", 0)  # reserved
    return payload


def build_plain_packet(payload: bytes) -> bytes:
    payload_len = len(payload)
    unpadded = 5 + payload_len
    padding = (8 - (unpadded % 8)) % 8
    if padding < 4:
        padding += 8
    pkt_len = 1 + payload_len + padding
    return struct.pack(">I", pkt_len) + bytes([padding]) + payload + (b'\x00' * padding)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def recv_plain_packet(sock) -> bytes:
    header = recv_exact(sock, 4)
    pkt_len = struct.unpack(">I", header)[0]
    data = recv_exact(sock, pkt_len)
    pad_len = data[0]
    payload_len = pkt_len - 1 - pad_len
    return data[1:1 + payload_len]


# ---- Crypto helpers ----

def python_chacha20_block(key, counter, nonce_12):
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    full_nonce = struct.pack("<I", counter) + nonce_12
    cipher = Cipher(ChaCha20(key, full_nonce), None).encryptor()
    return cipher.update(b'\x00' * 64)


def python_chacha20_encrypt(key, counter, nonce_12, plaintext):
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    full_nonce = struct.pack("<I", counter) + nonce_12
    cipher = Cipher(ChaCha20(key, full_nonce), None).encryptor()
    return cipher.update(plaintext)


def python_ssh_aead_encrypt(payload_bytes, k1, k2, seq):
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    # Pad the payload (SSH binary packet format)
    payload_len = len(payload_bytes)
    unpadded = 5 + payload_len
    padding = (8 - (unpadded % 8)) % 8
    if padding < 4:
        padding += 8
    padded = bytes([padding]) + payload_bytes + (b'\x00' * padding)
    pkt_len = len(padded)

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)

    # Encrypt length with K2
    plain_len = struct.pack(">I", pkt_len)
    ks = python_chacha20_block(k2, 0, nonce)
    enc_len = bytes(a ^ b for a, b in zip(plain_len, ks[:4]))

    # Encrypt payload with K1 (counter=1)
    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    enc_payload = python_chacha20_encrypt(k1, 1, nonce, padded)
    mac = Poly1305.generate_tag(poly_key, enc_len + enc_payload)

    return enc_len + enc_payload + mac


def python_ssh_aead_decrypt(data, k1, k2, seq):
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    from cryptography.exceptions import InvalidSignature

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    enc_len = data[:4]
    mac = data[-16:]
    enc_payload = data[4:-16]

    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    try:
        Poly1305.verify_tag(poly_key, enc_len + enc_payload, mac)
    except InvalidSignature:
        return None

    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]

    payload = python_chacha20_encrypt(k1, 1, nonce, enc_payload)
    pad_len = payload[0]
    actual_payload = payload[1:pkt_len - pad_len]
    return actual_payload


def recv_encrypted_packet(sock, k1, k2, seq):
    """Receive one encrypted SSH packet from socket."""
    # Read encrypted length (4 bytes)
    enc_len = recv_exact(sock, 4)

    # Decrypt length to know how much more to read
    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]

    # Read rest: encrypted payload (pkt_len bytes) + MAC (16 bytes)
    rest = recv_exact(sock, pkt_len + 16)
    full_data = enc_len + rest

    return python_ssh_aead_decrypt(full_data, k1, k2, seq)


def derive_key_64(K_mpint, H, letter_byte, session_id):
    h1_input = K_mpint + H + bytes([letter_byte]) + session_id
    first_32 = hashlib.sha256(h1_input).digest()
    h2_input = K_mpint + H + first_32
    second_32 = hashlib.sha256(h2_input).digest()
    return first_32 + second_32


def generate_ed25519_keypair():
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    priv_bytes = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes, priv_key, pub_key


# ---- Mock server for testing assembly client auth ----

class MockSSHServerWithAuth:
    """SSH server that does kex + auth protocol for testing the assembly client."""

    def __init__(self, expected_password: bytes, accept: bool = True):
        self.host_key = Ed25519PrivateKey.generate()
        self.host_pubkey = self.host_key.public_key()
        self.server_version = b"SSH-2.0-MockServer_1.0"
        self.expected_password = expected_password
        self.accept = accept  # Whether to accept correct passwords
        self.success = False
        self.error = None
        self.received_username = None
        self.received_password = None
        # Keys derived after kex
        self.k1_c2s = None
        self.k2_c2s = None
        self.k1_s2c = None
        self.k2_s2c = None
        self.session_id = None

    def handle(self, sock):
        try:
            self._do_handshake(sock)
            self._do_auth(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()

    def _do_handshake(self, sock):
        # Version exchange
        sock.sendall(self.server_version + b"\r\n")
        client_version_line = b""
        while not client_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            client_version_line += b
        self.client_version = client_version_line.rstrip(b"\r\n")

        # KEXINIT exchange
        self.server_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.server_kexinit))
        self.client_kexinit = recv_plain_packet(sock)
        assert self.client_kexinit[0] == 20

        # ECDH
        ecdh_init = recv_plain_packet(sock)
        assert ecdh_init[0] == 30
        client_ephem_pub = ecdh_init[5:37]

        server_ephem_priv = X25519PrivateKey.generate()
        server_ephem_pub = server_ephem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        client_x25519_pub = X25519PublicKey.from_public_bytes(client_ephem_pub)
        shared_secret = server_ephem_priv.exchange(client_x25519_pub)

        host_pub_bytes = self.host_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        host_key_blob = encode_string(b"ssh-ed25519") + encode_string(host_pub_bytes)

        K_mpint = encode_mpint(shared_secret)
        hash_input = (
            encode_string(self.client_version)
            + encode_string(self.server_version)
            + encode_string(self.client_kexinit)
            + encode_string(self.server_kexinit)
            + encode_string(host_key_blob)
            + encode_string(client_ephem_pub)
            + encode_string(server_ephem_pub)
            + K_mpint
        )
        H = hashlib.sha256(hash_input).digest()
        self.session_id = H

        signature_raw = self.host_key.sign(H)
        sig_blob = encode_string(b"ssh-ed25519") + encode_string(signature_raw)

        reply = bytes([31])
        reply += encode_string(host_key_blob)
        reply += encode_string(server_ephem_pub)
        reply += encode_string(sig_blob)
        sock.sendall(build_plain_packet(reply))

        # Derive keys
        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        # NEWKEYS exchange
        sock.sendall(build_plain_packet(bytes([21])))
        client_newkeys = recv_plain_packet(sock)
        assert client_newkeys == bytes([21])

    def _do_auth(self, sock):
        """Handle auth protocol over encrypted transport."""
        seq_recv = 3  # c2s (after 3 plaintext kex packets) (encrypted packets start at 0)
        seq_send = 3  # s2c (after 3 plaintext kex packets)

        # Step 1: Recv SSH_MSG_SERVICE_REQUEST (encrypted)
        payload = recv_encrypted_packet(sock, self.k1_c2s, self.k2_c2s, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for SERVICE_REQUEST"
        assert payload[0] == 5, f"Expected SERVICE_REQUEST(5), got {payload[0]}"
        # Verify service name
        svc_len = struct.unpack(">I", payload[1:5])[0]
        svc_name = payload[5:5 + svc_len]
        assert svc_name == b"ssh-userauth", f"Expected 'ssh-userauth', got {svc_name!r}"

        # Step 2: Send SSH_MSG_SERVICE_ACCEPT (encrypted)
        accept_payload = bytes([6]) + encode_string(b"ssh-userauth")
        enc_pkt = python_ssh_aead_encrypt(accept_payload, self.k1_s2c, self.k2_s2c, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        # Step 3: Recv SSH_MSG_USERAUTH_REQUEST (encrypted)
        payload = recv_encrypted_packet(sock, self.k1_c2s, self.k2_c2s, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for USERAUTH_REQUEST"
        assert payload[0] == 50, f"Expected USERAUTH_REQUEST(50), got {payload[0]}"

        # Parse: [byte 50][string user][string service][string method][byte FALSE][string password]
        offset = 1
        user_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        self.received_username = payload[offset:offset + user_len]
        offset += user_len
        svc_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4 + svc_len
        method_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        method = payload[offset:offset + method_len]
        offset += method_len
        assert method == b"password", f"Expected 'password', got {method!r}"
        offset += 1  # skip FALSE byte
        pass_len = struct.unpack(">I", payload[offset:offset + 4])[0]
        offset += 4
        self.received_password = payload[offset:offset + pass_len]

        # Step 4: Send SUCCESS or FAILURE
        if self.accept and self.received_password == self.expected_password:
            success_payload = bytes([52])  # SSH_MSG_USERAUTH_SUCCESS
            enc_pkt = python_ssh_aead_encrypt(success_payload, self.k1_s2c, self.k2_s2c, seq_send)
            sock.sendall(enc_pkt)
        else:
            # FAILURE: [byte 51][string name-list][byte partial-success]
            failure_payload = bytes([51]) + encode_string(b"password") + bytes([0])
            enc_pkt = python_ssh_aead_encrypt(failure_payload, self.k1_s2c, self.k2_s2c, seq_send)
            sock.sendall(enc_pkt)
        seq_send += 1


# ---- Mock client for testing assembly server auth ----

class MockSSHClientWithAuth:
    """SSH client that does kex + auth protocol for testing the assembly server."""

    def __init__(self, host_pub_key_obj, username: bytes, password: bytes):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.host_pub_key_obj = host_pub_key_obj
        self.username = username
        self.password = password
        self.success = False
        self.error = None
        self.auth_result = None  # 'success' or 'failure'
        # Keys derived after kex
        self.k1_c2s = None
        self.k2_c2s = None
        self.k1_s2c = None
        self.k2_s2c = None

    def handle(self, sock):
        try:
            self._do_handshake(sock)
            self._do_auth(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()

    def _do_handshake(self, sock):
        # Version exchange (client sends first for server-side kex)
        sock.sendall(self.client_version + b"\r\n")

        server_version_line = b""
        while not server_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            server_version_line += b
        self.server_version = server_version_line.rstrip(b"\r\n")

        # KEXINIT exchange
        self.client_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.client_kexinit))
        self.server_kexinit = recv_plain_packet(sock)
        assert self.server_kexinit[0] == 20

        # ECDH_INIT
        client_ephem_priv = X25519PrivateKey.generate()
        client_ephem_pub = client_ephem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
        sock.sendall(build_plain_packet(ecdh_init))

        # ECDH_REPLY
        ecdh_reply = recv_plain_packet(sock)
        assert ecdh_reply[0] == 31

        offset = 1
        ks_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        host_key_blob = ecdh_reply[offset:offset + ks_len]
        offset += ks_len
        f_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        server_ephem_pub = ecdh_reply[offset:offset + 32]
        offset += 32
        sig_blob_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        sig_blob = ecdh_reply[offset:offset + sig_blob_len]

        server_x25519_pub = X25519PublicKey.from_public_bytes(server_ephem_pub)
        shared_secret = client_ephem_priv.exchange(server_x25519_pub)

        K_mpint = encode_mpint(shared_secret)
        hash_input = (
            encode_string(self.client_version)
            + encode_string(self.server_version)
            + encode_string(self.client_kexinit)
            + encode_string(self.server_kexinit)
            + encode_string(host_key_blob)
            + encode_string(client_ephem_pub)
            + encode_string(server_ephem_pub)
            + K_mpint
        )
        H = hashlib.sha256(hash_input).digest()
        self.session_id = H

        # Derive keys
        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        # NEWKEYS: server sends first, client receives first
        server_newkeys = recv_plain_packet(sock)
        assert server_newkeys == bytes([21])
        sock.sendall(build_plain_packet(bytes([21])))

    def _do_auth(self, sock):
        """Run auth protocol as client over encrypted transport."""
        seq_send = 3  # c2s (after 3 plaintext kex packets)
        seq_recv = 3  # s2c (after 3 plaintext kex packets)

        # Step 1: Send SSH_MSG_SERVICE_REQUEST (encrypted)
        svc_request = bytes([5]) + encode_string(b"ssh-userauth")
        enc_pkt = python_ssh_aead_encrypt(svc_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        # Step 2: Recv SSH_MSG_SERVICE_ACCEPT (encrypted)
        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for SERVICE_ACCEPT"
        assert payload[0] == 6, f"Expected SERVICE_ACCEPT(6), got {payload[0]}"

        # Step 3: Send SSH_MSG_USERAUTH_REQUEST
        auth_request = bytes([50])
        auth_request += encode_string(self.username)
        auth_request += encode_string(b"ssh-connection")
        auth_request += encode_string(b"password")
        auth_request += bytes([0])  # FALSE
        auth_request += encode_string(self.password)
        enc_pkt = python_ssh_aead_encrypt(auth_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        # Step 4: Recv response
        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for auth response"
        if payload[0] == 52:
            self.auth_result = 'success'
        elif payload[0] == 51:
            self.auth_result = 'failure'
        else:
            raise ValueError(f"Unexpected auth response: {payload[0]}")


# ============================================================================
# Tests
# ============================================================================

class TestSSHAuthClient:
    """Test assembly SSH auth client against Python mock server."""

    def _run_client_auth(self, username: bytes, password: bytes,
                         server_password: bytes, server_accept: bool = True):
        """Run kex+auth and return (server, subprocess result)."""
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server = MockSSHServerWithAuth(server_password, accept=server_accept)
        server_thread = threading.Thread(target=server.handle, args=(s_server,))
        server_thread.start()

        client_fd = s_client.fileno()
        # Input: sock_fd(4 LE) + mode('c') + user_len(4 LE) + username + pass_len(4 LE) + password
        inp = struct.pack("<i", client_fd) + b'c'
        inp += struct.pack("<I", len(username)) + username
        inp += struct.pack("<I", len(password)) + password

        try:
            r = subprocess.run(
                [AUTH_BINARY],
                input=inp,
                capture_output=True,
                timeout=15,
                pass_fds=(client_fd,),
            )
        finally:
            s_client.close()

        server_thread.join(timeout=10)
        return server, r

    def test_client_auth_success(self):
        """Client authenticates with correct password."""
        server, r = self._run_client_auth(
            username=b"testuser",
            password=b"correctpassword",
            server_password=b"correctpassword",
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert len(r.stdout) >= 1
        assert r.stdout[0] == 0, f"Expected success byte 0, got {r.stdout[0]}"
        assert server.received_username == b"testuser"
        assert server.received_password == b"correctpassword"

    def test_client_auth_failure(self):
        """Client gets rejected with wrong password."""
        server, r = self._run_client_auth(
            username=b"testuser",
            password=b"wrongpassword",
            server_password=b"correctpassword",
            server_accept=True,  # server checks password, will reject
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 1, f"Expected failure (rc=1), got rc={r.returncode}"
        assert len(r.stdout) >= 1
        assert r.stdout[0] == 1, f"Expected failure byte 1, got {r.stdout[0]}"

    def test_client_auth_empty_password(self):
        """Client authenticates with empty password."""
        server, r = self._run_client_auth(
            username=b"admin",
            password=b"",
            server_password=b"",
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert r.stdout[0] == 0

    def test_client_auth_long_password(self):
        """Client authenticates with a longer password."""
        password = b"a_somewhat_longer_password_12345!"
        server, r = self._run_client_auth(
            username=b"longuser",
            password=password,
            server_password=password,
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0
        assert r.stdout[0] == 0


class TestSSHAuthServer:
    """Test assembly SSH auth server against Python mock client."""

    def _run_server_auth(self, expected_password: bytes, client_username: bytes,
                         client_password: bytes):
        """Run kex+auth with assembly server and return (client, subprocess result)."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockSSHClientWithAuth(host_pub_key, client_username, client_password)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        # Input: sock_fd(4 LE) + mode('s') + host_key(64) + pass_len(4 LE) + password
        inp = struct.pack("<i", server_fd) + b's'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(expected_password)) + expected_password

        try:
            r = subprocess.run(
                [AUTH_BINARY],
                input=inp,
                capture_output=True,
                timeout=15,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=10)
        return client, r

    def test_server_auth_success(self):
        """Server accepts correct password."""
        client, r = self._run_server_auth(
            expected_password=b"secretpass",
            client_username=b"admin",
            client_password=b"secretpass",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert len(r.stdout) >= 1
        assert r.stdout[0] == 0, f"Expected success byte 0, got {r.stdout[0]}"
        assert client.auth_result == 'success'

    def test_server_auth_failure(self):
        """Server rejects wrong password."""
        client, r = self._run_server_auth(
            expected_password=b"secretpass",
            client_username=b"admin",
            client_password=b"wrongpass",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 1, f"Expected server failure (rc=1), got rc={r.returncode}"
        assert len(r.stdout) >= 1
        assert r.stdout[0] == 1, f"Expected failure byte 1, got {r.stdout[0]}"
        assert client.auth_result == 'failure'

    def test_server_auth_empty_password(self):
        """Server accepts empty password when expected."""
        client, r = self._run_server_auth(
            expected_password=b"",
            client_username=b"root",
            client_password=b"",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0
        assert r.stdout[0] == 0
        assert client.auth_result == 'success'

    def test_server_auth_long_password(self):
        """Server handles longer passwords correctly."""
        password = b"this_is_a_longer_test_password!!"
        client, r = self._run_server_auth(
            expected_password=password,
            client_username=b"user123",
            client_password=password,
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0
        assert r.stdout[0] == 0
        assert client.auth_result == 'success'
