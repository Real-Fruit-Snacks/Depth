"""Integration test: SSH key exchange -- assembly server vs Python mock client.

Tests ssh_kex_server by having a Python mock SSH client that speaks
the SSH protocol manually (version exchange, KEXINIT, ECDH_INIT).
The assembly server responds with version, KEXINIT, ECDH_REPLY, NEWKEYS.
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

KEX_SERVER_BINARY = "./build/test_ssh_kex_server"


def encode_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def encode_mpint(value_be: bytes) -> bytes:
    """Encode bytes as SSH mpint (BE per OpenSSH convention)."""
    be = value_be  # treat as BE per OpenSSH (no reversal)
    while len(be) > 1 and be[0] == 0:
        be = be[1:]
    if not be:
        return struct.pack(">I", 0)
    if be[0] & 0x80:
        be = b'\x00' + be
    return struct.pack(">I", len(be)) + be


def build_kexinit_payload():
    """Build a client KEXINIT payload."""
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


def derive_key_64(K_mpint, H, letter_byte, session_id):
    """Derive 64 bytes of key material per SSH spec."""
    h1_input = K_mpint + H + bytes([letter_byte]) + session_id
    first_32 = hashlib.sha256(h1_input).digest()
    h2_input = K_mpint + H + first_32
    second_32 = hashlib.sha256(h2_input).digest()
    return first_32 + second_32


def generate_ed25519_keypair():
    """Generate an Ed25519 keypair and return (private_32, public_32, keypair_64)."""
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    # Get raw private key bytes (seed)
    priv_bytes = priv_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    pub_bytes = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return priv_bytes, pub_bytes, priv_key, pub_key


class MockSSHClient:
    """Minimal SSH client for testing the assembly server's key exchange."""

    def __init__(self, host_pub_key_obj):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.server_version = None
        self.client_kexinit = None
        self.server_kexinit = None
        self.session_id = None
        self.k1_c2s = None
        self.k2_c2s = None
        self.k1_s2c = None
        self.k2_s2c = None
        self.host_pub_key_obj = host_pub_key_obj
        self.host_key_blob_received = None
        self.server_ephem_pub = None
        self.signature_blob = None
        self.signature_valid = None
        self.success = False
        self.error = None

    def handle(self, sock):
        """Run the client side of the SSH handshake."""
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
        # Step 1: Version exchange (client sends first in normal SSH,
        # but our server reads first, so we send first)
        sock.sendall(self.client_version + b"\r\n")

        # Read server version
        server_version_line = b""
        while not server_version_line.endswith(b"\n"):
            b = sock.recv(1)
            if not b:
                raise ConnectionError("EOF during version")
            server_version_line += b
        self.server_version = server_version_line.rstrip(b"\r\n")

        # Step 2: KEXINIT exchange (client sends first, server receives first)
        self.client_kexinit = build_kexinit_payload()
        sock.sendall(build_plain_packet(self.client_kexinit))

        self.server_kexinit = recv_plain_packet(sock)
        assert self.server_kexinit[0] == 20, f"Expected KEXINIT, got {self.server_kexinit[0]}"

        # Step 3: Generate client ephemeral keypair and send ECDH_INIT
        client_ephem_priv = X25519PrivateKey.generate()
        client_ephem_pub = client_ephem_priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

        # Send SSH_MSG_KEX_ECDH_INIT
        ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
        sock.sendall(build_plain_packet(ecdh_init))

        # Step 4: Receive SSH_MSG_KEX_ECDH_REPLY
        ecdh_reply = recv_plain_packet(sock)
        assert ecdh_reply[0] == 31, f"Expected KEX_ECDH_REPLY, got {ecdh_reply[0]}"

        # Parse K_S (host key blob)
        offset = 1
        ks_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        host_key_blob = ecdh_reply[offset:offset + ks_len]
        self.host_key_blob_received = host_key_blob
        offset += ks_len

        # Parse server ephemeral public key
        f_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        assert f_len == 32, f"Expected 32-byte server ephem, got {f_len}"
        self.server_ephem_pub = ecdh_reply[offset:offset + 32]
        offset += 32

        # Parse signature blob
        sig_blob_len = struct.unpack(">I", ecdh_reply[offset:offset + 4])[0]
        offset += 4
        self.signature_blob = ecdh_reply[offset:offset + sig_blob_len]
        offset += sig_blob_len

        # Step 5: Compute shared secret
        server_x25519_pub = X25519PublicKey.from_public_bytes(self.server_ephem_pub)
        shared_secret = client_ephem_priv.exchange(server_x25519_pub)

        # Step 6: Compute exchange hash H
        K_mpint = encode_mpint(shared_secret)

        hash_input = (
            encode_string(self.client_version)
            + encode_string(self.server_version)
            + encode_string(self.client_kexinit)
            + encode_string(self.server_kexinit)
            + encode_string(host_key_blob)
            + encode_string(client_ephem_pub)
            + encode_string(self.server_ephem_pub)
            + K_mpint
        )
        H = hashlib.sha256(hash_input).digest()
        self.session_id = H

        # Step 7: Verify the signature on H
        # Parse sig_blob: string("ssh-ed25519") + string(raw_sig_64)
        sig_offset = 0
        sig_algo_len = struct.unpack(">I", self.signature_blob[sig_offset:sig_offset + 4])[0]
        sig_offset += 4
        sig_algo = self.signature_blob[sig_offset:sig_offset + sig_algo_len]
        sig_offset += sig_algo_len
        raw_sig_len = struct.unpack(">I", self.signature_blob[sig_offset:sig_offset + 4])[0]
        sig_offset += 4
        raw_sig = self.signature_blob[sig_offset:sig_offset + raw_sig_len]

        try:
            self.host_pub_key_obj.verify(raw_sig, H)
            self.signature_valid = True
        except Exception:
            self.signature_valid = False

        # Step 8: Derive keys
        self.k1_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[:32]
        self.k2_c2s = derive_key_64(K_mpint, H, 0x43, self.session_id)[32:]
        self.k1_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[:32]
        self.k2_s2c = derive_key_64(K_mpint, H, 0x44, self.session_id)[32:]

        # Step 9: Exchange NEWKEYS (server sends first, client receives first)
        server_newkeys = recv_plain_packet(sock)
        assert server_newkeys == bytes([21]), f"Expected NEWKEYS, got {server_newkeys!r}"

        # Send our NEWKEYS
        sock.sendall(build_plain_packet(bytes([21])))


class TestSSHKexServer:
    """Test full SSH key exchange via assembly server + Python mock client."""

    def _run_kex(self):
        """Run key exchange and return (client, server_returncode, server_stdout)."""
        # Generate host keypair
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        # Create socketpair
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockSSHClient(host_pub_key)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        # Run the assembly server, passing fd + host keypair via stdin
        server_fd = s_server.fileno()
        inp = struct.pack("<i", server_fd) + host_priv_bytes + host_pub_bytes

        try:
            r = subprocess.run(
                [KEX_SERVER_BINARY],
                input=inp,
                capture_output=True,
                timeout=10,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=5)
        return client, r

    def test_server_kex_completes(self):
        """Assembly server successfully completes key exchange with Python mock client."""
        client, r = self._run_kex()
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert client.success, f"Client failed: {client.error}"

    def test_server_version_exchange(self):
        """Client receives correct server version string."""
        client, r = self._run_kex()
        assert r.returncode == 0, f"Server failed (rc={r.returncode})"
        assert client.success, f"Client failed: {client.error}"
        assert client.server_version == b"SSH-2.0-OpenSSH_9.0"

    def test_server_kexinit_valid(self):
        """Server KEXINIT contains correct algorithms."""
        client, r = self._run_kex()
        assert r.returncode == 0
        assert client.success, f"Client failed: {client.error}"
        ki = client.server_kexinit
        assert ki[0] == 20
        assert b"curve25519-sha256" in ki
        assert b"ssh-ed25519" in ki
        assert b"chacha20-poly1305@openssh.com" in ki

    def test_server_host_key_signature_valid(self):
        """Ed25519 signature in ECDH_REPLY is valid."""
        client, r = self._run_kex()
        assert r.returncode == 0
        assert client.success, f"Client failed: {client.error}"
        assert client.signature_valid is True, "Ed25519 signature verification failed"

    def test_server_derived_keys_match(self):
        """Client and server derive the same session keys."""
        client, r = self._run_kex()
        assert r.returncode == 0, f"Server failed (rc={r.returncode})"
        assert client.success, f"Client failed: {client.error}"

        output = r.stdout
        assert len(output) >= 160, f"Server output too short: {len(output)} bytes"

        server_session_id = output[0:32]
        server_k1_c2s = output[32:64]
        server_k2_c2s = output[64:96]
        server_k1_s2c = output[96:128]
        server_k2_s2c = output[128:160]

        assert server_session_id == client.session_id, "Session ID mismatch"
        assert server_k1_c2s == client.k1_c2s, "K1 C2S mismatch"
        assert server_k2_c2s == client.k2_c2s, "K2 C2S mismatch"
        assert server_k1_s2c == client.k1_s2c, "K1 S2C mismatch"
        assert server_k2_s2c == client.k2_s2c, "K2 S2C mismatch"
