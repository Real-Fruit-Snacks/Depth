"""Integration test: SSH Ed25519 public key authentication.

Tests ssh_auth_server_pubkey and ssh_auth_server_any by running
the full kex handshake first, then the pubkey auth protocol over encrypted packets.
Python acts as the SSH client, assembly as the server.
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

PUBKEY_BINARY = "./build/test_ssh_pubkey"


# ---- Wire helpers (shared with test_ssh_auth.py) ----

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
        b"hmac-sha2-256", b"hmac-sha2-256",  # mac c2s, mac s2c
        b"none", b"none",
        b"", b"",  # languages
    ]
    for nl in name_lists:
        payload += encode_string(nl)
    payload += bytes([0])  # first_kex_packet_follows
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
    payload_len = len(payload_bytes)
    unpadded = 5 + payload_len
    padding = (8 - (unpadded % 8)) % 8
    if padding < 4:
        padding += 8
    padded = bytes([padding]) + payload_bytes + (b'\x00' * padding)
    pkt_len = len(padded)
    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    plain_len = struct.pack(">I", pkt_len)
    ks = python_chacha20_block(k2, 0, nonce)
    enc_len = bytes(a ^ b for a, b in zip(plain_len, ks[:4]))
    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    enc_payload = python_chacha20_encrypt(k1, 1, nonce, padded)
    mac = Poly1305.generate_tag(poly_key, enc_len + enc_payload)
    return enc_len + enc_payload + mac


def recv_encrypted_packet(sock, k1, k2, seq):
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    from cryptography.exceptions import InvalidSignature
    enc_len = recv_exact(sock, 4)
    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]
    rest = recv_exact(sock, pkt_len + 16)
    full_data = enc_len + rest
    # Decrypt
    enc_payload = full_data[4:-16]
    mac = full_data[-16:]
    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    try:
        Poly1305.verify_tag(poly_key, enc_len + enc_payload, mac)
    except InvalidSignature:
        return None
    payload = python_chacha20_encrypt(k1, 1, nonce, enc_payload)
    pad_len = payload[0]
    actual_payload = payload[1:pkt_len - pad_len]
    return actual_payload


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


# ---- Mock SSH client for pubkey auth ----

class MockSSHClientPubkeyAuth:
    """Python SSH client that does kex + pubkey auth against assembly server."""

    def __init__(self, host_pub_key_obj, operator_priv_key, operator_pub_bytes,
                 username=b"operator", do_probe=True, bad_signature=False):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.host_pub_key_obj = host_pub_key_obj
        self.operator_priv_key = operator_priv_key  # Ed25519PrivateKey object
        self.operator_pub_bytes = operator_pub_bytes  # 32-byte raw pubkey
        self.username = username
        self.do_probe = do_probe
        self.bad_signature = bad_signature
        self.success = False
        self.error = None
        self.auth_result = None
        self.probe_result = None  # 'pk_ok' or 'failure'
        self.k1_c2s = None
        self.k2_c2s = None
        self.k1_s2c = None
        self.k2_s2c = None
        self.session_id = None

    def handle(self, sock):
        try:
            self._do_handshake(sock)
            self._do_pubkey_auth(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()

    def _do_handshake(self, sock):
        # Version exchange (client sends first)
        sock.sendall(self.client_version + b"\r\n")
        server_version_line = b""
        while not server_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            server_version_line += b
        self.server_version = server_version_line.rstrip(b"\r\n")

        # KEXINIT
        self.client_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.client_kexinit))
        self.server_kexinit = recv_plain_packet(sock)
        assert self.server_kexinit[0] == 20

        # ECDH
        client_ephem_priv = X25519PrivateKey.generate()
        client_ephem_pub = client_ephem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
        sock.sendall(build_plain_packet(ecdh_init))

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

        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        # NEWKEYS
        server_newkeys = recv_plain_packet(sock)
        assert server_newkeys == bytes([21])
        sock.sendall(build_plain_packet(bytes([21])))

    def _do_pubkey_auth(self, sock):
        seq_send = 3
        seq_recv = 3

        # Build public_key_blob
        pubkey_blob = encode_string(b"ssh-ed25519") + encode_string(self.operator_pub_bytes)

        # Step 1: Send SERVICE_REQUEST
        svc_request = bytes([5]) + encode_string(b"ssh-userauth")
        enc_pkt = python_ssh_aead_encrypt(svc_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        # Step 2: Recv SERVICE_ACCEPT
        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for SERVICE_ACCEPT"
        assert payload[0] == 6, f"Expected SERVICE_ACCEPT(6), got {payload[0]}"

        if self.do_probe:
            # Phase 1: Probe (boolean FALSE)
            auth_req = bytes([50])
            auth_req += encode_string(self.username)
            auth_req += encode_string(b"ssh-connection")
            auth_req += encode_string(b"publickey")
            auth_req += bytes([0])  # FALSE
            auth_req += encode_string(b"ssh-ed25519")
            auth_req += encode_string(pubkey_blob)

            enc_pkt = python_ssh_aead_encrypt(auth_req, self.k1_c2s, self.k2_c2s, seq_send)
            sock.sendall(enc_pkt)
            seq_send += 1

            # Recv PK_OK (60) or FAILURE (51)
            payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
            seq_recv += 1
            assert payload is not None, "Decrypt failed for PK_OK/FAILURE"

            if payload[0] == 60:
                self.probe_result = 'pk_ok'
            elif payload[0] == 51:
                self.probe_result = 'failure'
                self.auth_result = 'failure'
                return
            else:
                raise ValueError(f"Unexpected probe response: {payload[0]}")

        # Phase 2: Sign and send (boolean TRUE)
        # Build signed data
        signed_data = encode_string(self.session_id)
        signed_data += bytes([50])
        signed_data += encode_string(self.username)
        signed_data += encode_string(b"ssh-connection")
        signed_data += encode_string(b"publickey")
        signed_data += bytes([1])  # TRUE
        signed_data += encode_string(b"ssh-ed25519")
        signed_data += encode_string(pubkey_blob)

        # Sign
        if self.bad_signature:
            # Use a different key to produce a bad signature
            bad_key = Ed25519PrivateKey.generate()
            signature_raw = bad_key.sign(signed_data)
        else:
            signature_raw = self.operator_priv_key.sign(signed_data)

        sig_blob = encode_string(b"ssh-ed25519") + encode_string(signature_raw)

        auth_req2 = bytes([50])
        auth_req2 += encode_string(self.username)
        auth_req2 += encode_string(b"ssh-connection")
        auth_req2 += encode_string(b"publickey")
        auth_req2 += bytes([1])  # TRUE
        auth_req2 += encode_string(b"ssh-ed25519")
        auth_req2 += encode_string(pubkey_blob)
        auth_req2 += encode_string(sig_blob)

        enc_pkt = python_ssh_aead_encrypt(auth_req2, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        # Recv SUCCESS (52) or FAILURE (51)
        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None, "Decrypt failed for auth response"
        if payload[0] == 52:
            self.auth_result = 'success'
        elif payload[0] == 51:
            self.auth_result = 'failure'
        else:
            raise ValueError(f"Unexpected auth response: {payload[0]}")


class MockSSHClientPasswordAuth:
    """Python SSH client that does kex + password auth (for testing ssh_auth_server_any)."""

    def __init__(self, host_pub_key_obj, username: bytes, password: bytes):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.host_pub_key_obj = host_pub_key_obj
        self.username = username
        self.password = password
        self.success = False
        self.error = None
        self.auth_result = None
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
        sock.sendall(self.client_version + b"\r\n")
        server_version_line = b""
        while not server_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            server_version_line += b
        self.server_version = server_version_line.rstrip(b"\r\n")

        self.client_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.client_kexinit))
        self.server_kexinit = recv_plain_packet(sock)
        assert self.server_kexinit[0] == 20

        client_ephem_priv = X25519PrivateKey.generate()
        client_ephem_pub = client_ephem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
        sock.sendall(build_plain_packet(ecdh_init))

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

        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        server_newkeys = recv_plain_packet(sock)
        assert server_newkeys == bytes([21])
        sock.sendall(build_plain_packet(bytes([21])))

    def _do_auth(self, sock):
        seq_send = 3
        seq_recv = 3

        svc_request = bytes([5]) + encode_string(b"ssh-userauth")
        enc_pkt = python_ssh_aead_encrypt(svc_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None
        assert payload[0] == 6

        auth_request = bytes([50])
        auth_request += encode_string(self.username)
        auth_request += encode_string(b"ssh-connection")
        auth_request += encode_string(b"password")
        auth_request += bytes([0])
        auth_request += encode_string(self.password)
        enc_pkt = python_ssh_aead_encrypt(auth_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None
        if payload[0] == 52:
            self.auth_result = 'success'
        elif payload[0] == 51:
            self.auth_result = 'failure'
        else:
            raise ValueError(f"Unexpected auth response: {payload[0]}")


# ============================================================================
# Tests
# ============================================================================

class TestSSHPubkeyAuth:
    """Test assembly SSH pubkey auth server against Python mock clients."""

    def _run_pubkey_server(self, operator_priv_key, operator_pub_bytes,
                           authorized_keys_list, do_probe=True, bad_signature=False,
                           mode='k'):
        """Run kex + pubkey auth with assembly server."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockSSHClientPubkeyAuth(
            host_pub_key, operator_priv_key, operator_pub_bytes,
            do_probe=do_probe, bad_signature=bad_signature,
        )
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        num_keys = len(authorized_keys_list)

        if mode == 'k':
            # Pubkey-only mode
            inp = struct.pack("<i", server_fd) + b'k'
            inp += host_priv_bytes + host_pub_bytes
            inp += struct.pack("<I", num_keys)
            for key in authorized_keys_list:
                inp += key  # each is 32 bytes
        else:
            # 'a' mode (any auth) - still doing pubkey
            inp = struct.pack("<i", server_fd) + b'a'
            inp += host_priv_bytes + host_pub_bytes
            inp += struct.pack("<I", num_keys)
            for key in authorized_keys_list:
                inp += key
            inp += struct.pack("<I", 0) + b""  # empty password

        try:
            r = subprocess.run(
                [PUBKEY_BINARY],
                input=inp,
                capture_output=True,
                timeout=30,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=15)
        return client, r

    def _run_password_server_any(self, expected_password, client_username,
                                  client_password, authorized_keys_list=None):
        """Run kex + password auth through ssh_auth_server_any."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockSSHClientPasswordAuth(host_pub_key, client_username, client_password)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        keys = authorized_keys_list or []
        num_keys = len(keys)

        inp = struct.pack("<i", server_fd) + b'a'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", num_keys)
        for key in keys:
            inp += key
        inp += struct.pack("<I", len(expected_password)) + expected_password

        try:
            r = subprocess.run(
                [PUBKEY_BINARY],
                input=inp,
                capture_output=True,
                timeout=30,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=15)
        return client, r

    # ---- Pubkey-only tests ----

    def test_pubkey_probe_known_key(self):
        """Server responds with PK_OK for an authorized key."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[op_pub],
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.probe_result == 'pk_ok', f"Expected pk_ok, got {client.probe_result}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert r.stdout[0] == 0

    def test_pubkey_probe_unknown_key(self):
        """Server responds with FAILURE for an unauthorized key."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Authorized list has a different key
        other_pub = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[other_pub],
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.probe_result == 'failure', f"Expected failure, got {client.probe_result}"
        assert client.auth_result == 'failure'
        assert r.returncode == 1

    def test_pubkey_auth_success(self):
        """Full two-phase pubkey auth: probe -> PK_OK -> sign -> SUCCESS."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[op_pub],
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.probe_result == 'pk_ok'
        assert client.auth_result == 'success'
        assert r.returncode == 0
        assert r.stdout[0] == 0

    def test_pubkey_auth_bad_signature(self):
        """Probe -> PK_OK -> wrong signature -> FAILURE."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[op_pub],
            bad_signature=True,
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.probe_result == 'pk_ok'
        assert client.auth_result == 'failure'
        assert r.returncode == 1
        assert r.stdout[0] == 1

    def test_pubkey_auth_unknown_key_no_probe(self):
        """Probe with unknown key -> FAILURE (no second phase)."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[],  # empty list
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.probe_result == 'failure'
        assert client.auth_result == 'failure'
        assert r.returncode == 1

    def test_pubkey_auth_multiple_authorized_keys(self):
        """Server accepts a key from a list of multiple authorized keys."""
        # Generate 3 keys, use the second one
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        pubs = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for k in keys]

        client, r = self._run_pubkey_server(
            operator_priv_key=keys[1],
            operator_pub_bytes=pubs[1],
            authorized_keys_list=pubs,
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.auth_result == 'success'
        assert r.returncode == 0

    # ---- ssh_auth_server_any tests ----

    def test_any_auth_pubkey_success(self):
        """ssh_auth_server_any accepts pubkey auth."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client, r = self._run_pubkey_server(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[op_pub],
            mode='a',
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.auth_result == 'success'
        assert r.returncode == 0

    def test_any_auth_password_success(self):
        """ssh_auth_server_any accepts password auth."""
        client, r = self._run_password_server_any(
            expected_password=b"secretpass",
            client_username=b"admin",
            client_password=b"secretpass",
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.auth_result == 'success'
        assert r.returncode == 0

    def test_any_auth_password_failure(self):
        """ssh_auth_server_any rejects wrong password."""
        client, r = self._run_password_server_any(
            expected_password=b"secretpass",
            client_username=b"admin",
            client_password=b"wrongpass",
        )
        assert client.success, f"Client failed: {client.error}"
        assert client.auth_result == 'failure'
        assert r.returncode == 1
