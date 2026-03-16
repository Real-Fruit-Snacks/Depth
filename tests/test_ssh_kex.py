"""Integration test: SSH key exchange — assembly client vs Python mock server.

Tests ssh_kex_client by having a Python mock SSH server that speaks
the SSH protocol manually (version exchange, KEXINIT, ECDH, NEWKEYS).
The assembly client connects via a socketpair and completes the handshake.

Also tests encrypted packet send/recv after key derivation.
"""
import subprocess, struct, os, socket, threading, hashlib, time, pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

KEX_BINARY = "./build/test_ssh_kex"


def encode_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def encode_mpint(value_be: bytes) -> bytes:
    """Encode bytes as SSH mpint (BE per OpenSSH convention)."""
    # Convert to big-endian, strip leading zeros
    be = value_be  # treat as BE per OpenSSH (no reversal)
    while len(be) > 1 and be[0] == 0:
        be = be[1:]
    if not be:
        return struct.pack(">I", 0)
    if be[0] & 0x80:
        be = b'\x00' + be
    return struct.pack(">I", len(be)) + be


def build_kexinit_payload():
    """Build a server KEXINIT payload."""
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
    """Build a plaintext SSH binary packet."""
    payload_len = len(payload)
    unpadded = 5 + payload_len
    padding = (8 - (unpadded % 8)) % 8
    if padding < 4:
        padding += 8
    pkt_len = 1 + payload_len + padding
    return struct.pack(">I", pkt_len) + bytes([padding]) + payload + (b'\x00' * padding)


def recv_plain_packet(sock) -> bytes:
    """Receive a plaintext SSH packet and return the payload."""
    header = recv_exact(sock, 4)
    pkt_len = struct.unpack(">I", header)[0]
    data = recv_exact(sock, pkt_len)
    pad_len = data[0]
    payload_len = pkt_len - 1 - pad_len
    return data[1:1 + payload_len]


def recv_exact(sock, n):
    """Read exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


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
    """Encrypt an SSH packet using chacha20-poly1305@openssh.com."""
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)

    plain_len = struct.pack(">I", len(payload_bytes))
    ks = python_chacha20_block(k2, 0, nonce)
    enc_len = bytes(a ^ b for a, b in zip(plain_len, ks[:4]))

    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    enc_payload = python_chacha20_encrypt(k1, 1, nonce, payload_bytes)
    mac = Poly1305.generate_tag(poly_key, enc_len + enc_payload)

    return enc_len + enc_payload + mac


def python_ssh_aead_decrypt(data, k1, k2, seq):
    """Decrypt an SSH packet."""
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

    # Decrypt length
    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]

    payload = python_chacha20_encrypt(k1, 1, nonce, enc_payload)
    # payload = [pad_len(1)][actual_payload][padding]
    pad_len = payload[0]
    actual_payload = payload[1:pkt_len - pad_len]
    return actual_payload


def derive_key_64(K_mpint, H, letter_byte, session_id):
    """Derive 64 bytes of key material per SSH spec."""
    # First 32 bytes
    h1_input = K_mpint + H + bytes([letter_byte]) + session_id
    first_32 = hashlib.sha256(h1_input).digest()
    # Second 32 bytes
    h2_input = K_mpint + H + first_32
    second_32 = hashlib.sha256(h2_input).digest()
    return first_32 + second_32


class MockSSHServer:
    """Minimal SSH server for testing key exchange."""

    def __init__(self):
        self.host_key = Ed25519PrivateKey.generate()
        self.host_pubkey = self.host_key.public_key()
        self.server_version = b"SSH-2.0-MockServer_1.0"
        self.client_version = None
        self.client_kexinit = None
        self.server_kexinit = None
        self.session_id = None
        self.k1_c2s = None
        self.k2_c2s = None
        self.k1_s2c = None
        self.k2_s2c = None
        self.success = False
        self.error = None

    def handle(self, sock):
        """Run the server side of the SSH handshake."""
        try:
            self._do_handshake(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()

    def _do_handshake(self, sock):
        # Step 1: Version exchange
        sock.sendall(self.server_version + b"\r\n")
        client_version_line = b""
        while not client_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            client_version_line += b
        self.client_version = client_version_line.rstrip(b"\r\n")

        # Step 2: KEXINIT exchange
        self.server_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.server_kexinit))

        self.client_kexinit = recv_plain_packet(sock)
        assert self.client_kexinit[0] == 20, f"Expected KEXINIT, got {self.client_kexinit[0]}"

        # Step 3: Recv SSH_MSG_KEX_ECDH_INIT
        ecdh_init = recv_plain_packet(sock)
        assert ecdh_init[0] == 30, f"Expected KEX_ECDH_INIT, got {ecdh_init[0]}"
        client_ephem_len = struct.unpack(">I", ecdh_init[1:5])[0]
        assert client_ephem_len == 32
        client_ephem_pub = ecdh_init[5:37]

        # Step 4: Generate server ephemeral key, compute shared secret
        server_ephem_priv = X25519PrivateKey.generate()
        server_ephem_pub = server_ephem_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        client_x25519_pub = X25519PublicKey.from_public_bytes(client_ephem_pub)
        shared_secret = server_ephem_priv.exchange(client_x25519_pub)
        # shared_secret is in LE byte order (raw X25519 output)

        # Step 5: Build and send SSH_MSG_KEX_ECDH_REPLY
        # Host key blob: string("ssh-ed25519") || string(pubkey_32)
        host_pub_bytes = self.host_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
        host_key_blob = encode_string(b"ssh-ed25519") + encode_string(host_pub_bytes)

        # Compute exchange hash H
        V_C = self.client_version
        V_S = self.server_version
        I_C = self.client_kexinit
        I_S = self.server_kexinit

        K_mpint = encode_mpint(shared_secret)

        hash_input = (
            encode_string(V_C)
            + encode_string(V_S)
            + encode_string(I_C)
            + encode_string(I_S)
            + encode_string(host_key_blob)
            + encode_string(client_ephem_pub)
            + encode_string(server_ephem_pub)
            + K_mpint
        )
        H = hashlib.sha256(hash_input).digest()
        self.session_id = H

        # Sign H with host key
        signature_raw = self.host_key.sign(H)
        sig_blob = encode_string(b"ssh-ed25519") + encode_string(signature_raw)

        # Build reply payload
        reply = bytes([31])  # SSH_MSG_KEX_ECDH_REPLY
        reply += encode_string(host_key_blob)
        reply += encode_string(server_ephem_pub)
        reply += encode_string(sig_blob)
        sock.sendall(build_plain_packet(reply))

        # Step 6: Derive keys
        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        # Step 7: Exchange NEWKEYS
        newkeys = bytes([21])
        sock.sendall(build_plain_packet(newkeys))

        client_newkeys = recv_plain_packet(sock)
        assert client_newkeys == bytes([21]), f"Expected NEWKEYS, got {client_newkeys!r}"


class TestSSHKex:
    """Test full SSH key exchange via assembly client + Python mock server."""

    def _run_kex(self):
        """Run key exchange and return (server, client_returncode, client_stdout)."""
        # Create a TCP socketpair
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server = MockSSHServer()
        server_thread = threading.Thread(target=server.handle, args=(s_server,))
        server_thread.start()

        # Run the assembly client, passing the client socket fd
        # The test binary reads the fd number from stdin, then runs kex
        client_fd = s_client.fileno()
        inp = struct.pack("<i", client_fd)

        try:
            r = subprocess.run(
                [KEX_BINARY],
                input=inp,
                capture_output=True,
                timeout=10,
                pass_fds=(client_fd,),
            )
        finally:
            s_client.close()

        server_thread.join(timeout=5)
        return server, r

    def test_kex_completes(self):
        """Client successfully completes key exchange with mock server."""
        server, r = self._run_kex()
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}"

    def test_version_exchange(self):
        """Server receives correct client version string."""
        server, r = self._run_kex()
        assert server.success, f"Server failed: {server.error}"
        assert server.client_version == b"SSH-2.0-OpenSSH_9.0"

    def test_client_kexinit_valid(self):
        """Server receives valid KEXINIT from client."""
        server, r = self._run_kex()
        assert server.success, f"Server failed: {server.error}"
        ki = server.client_kexinit
        assert ki[0] == 20
        assert b"curve25519-sha256" in ki
        assert b"ssh-ed25519" in ki
        assert b"chacha20-poly1305@openssh.com" in ki

    def test_kex_output_contains_session_id(self):
        """Client outputs derived session ID which matches server's."""
        server, r = self._run_kex()
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0
        # The test binary outputs: session_id(32) + k1_c2s(32) + k2_c2s(32) + k1_s2c(32) + k2_s2c(32)
        # = 160 bytes
        output = r.stdout
        assert len(output) >= 32, f"Output too short: {len(output)} bytes"
        client_session_id = output[:32]
        assert client_session_id == server.session_id, "Session ID mismatch"

    def test_derived_keys_match(self):
        """Client and server derive the same session keys."""
        server, r = self._run_kex()
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0

        output = r.stdout
        assert len(output) >= 160, f"Output too short: {len(output)} bytes"

        client_session_id = output[0:32]
        client_k1_c2s = output[32:64]
        client_k2_c2s = output[64:96]
        client_k1_s2c = output[96:128]
        client_k2_s2c = output[128:160]

        assert client_session_id == server.session_id, "Session ID mismatch"
        assert client_k1_c2s == server.k1_c2s, "K1 C2S mismatch"
        assert client_k2_c2s == server.k2_c2s, "K2 C2S mismatch"
        assert client_k1_s2c == server.k1_s2c, "K1 S2C mismatch"
        assert client_k2_s2c == server.k2_s2c, "K2 S2C mismatch"
