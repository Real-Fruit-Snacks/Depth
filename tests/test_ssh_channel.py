"""Integration test: SSH channel multiplexing — assembly client/server vs Python mock.

Tests ssh_channel_open_session, ssh_channel_accept, ssh_channel_send_data,
ssh_channel_recv, ssh_channel_send_eof_close by running full kex + auth first,
then channel operations over encrypted packets.
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

CHANNEL_BINARY = "./build/test_ssh_channel"


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
    enc_len = recv_exact(sock, 4)
    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]
    rest = recv_exact(sock, pkt_len + 16)
    full_data = enc_len + rest
    return python_ssh_aead_decrypt(full_data, k1, k2, seq)


def send_encrypted_packet(sock, payload, k1, k2, seq):
    """Send one encrypted SSH packet."""
    enc_pkt = python_ssh_aead_encrypt(payload, k1, k2, seq)
    sock.sendall(enc_pkt)


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


# ---- Kex + Auth helpers for mock sides ----

def do_kex_as_server(sock):
    """Run full kex handshake as Python server. Returns keys dict."""
    host_key = Ed25519PrivateKey.generate()
    host_pubkey = host_key.public_key()
    server_version = b"SSH-2.0-MockServer_1.0"

    # Version exchange
    sock.sendall(server_version + b"\r\n")
    client_version_line = b""
    while not client_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        client_version_line += b
    client_version = client_version_line.rstrip(b"\r\n")

    # KEXINIT exchange
    server_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(server_kexinit))
    client_kexinit = recv_plain_packet(sock)
    assert client_kexinit[0] == 20

    # ECDH
    ecdh_init = recv_plain_packet(sock)
    assert ecdh_init[0] == 30
    client_ephem_pub = ecdh_init[5:37]

    server_ephem_priv = X25519PrivateKey.generate()
    server_ephem_pub = server_ephem_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_x25519_pub = X25519PublicKey.from_public_bytes(client_ephem_pub)
    shared_secret = server_ephem_priv.exchange(client_x25519_pub)

    host_pub_bytes = host_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
    host_key_blob = encode_string(b"ssh-ed25519") + encode_string(host_pub_bytes)

    K_mpint = encode_mpint(shared_secret)
    hash_input = (
        encode_string(client_version)
        + encode_string(server_version)
        + encode_string(client_kexinit)
        + encode_string(server_kexinit)
        + encode_string(host_key_blob)
        + encode_string(client_ephem_pub)
        + encode_string(server_ephem_pub)
        + K_mpint
    )
    H = hashlib.sha256(hash_input).digest()
    session_id = H

    signature_raw = host_key.sign(H)
    sig_blob = encode_string(b"ssh-ed25519") + encode_string(signature_raw)

    reply = bytes([31])
    reply += encode_string(host_key_blob)
    reply += encode_string(server_ephem_pub)
    reply += encode_string(sig_blob)
    sock.sendall(build_plain_packet(reply))

    # Derive keys
    k1_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[:32]
    k2_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[32:]
    k1_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[:32]
    k2_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[32:]

    # NEWKEYS
    sock.sendall(build_plain_packet(bytes([21])))
    client_newkeys = recv_plain_packet(sock)
    assert client_newkeys == bytes([21])

    return {
        'k1_c2s': k1_c2s, 'k2_c2s': k2_c2s,
        'k1_s2c': k1_s2c, 'k2_s2c': k2_s2c,
        'session_id': session_id,
    }


def do_auth_as_server(sock, keys, expected_password: bytes):
    """Run auth protocol as Python server. Returns seq numbers (seq_recv, seq_send)."""
    seq_recv = 3  # c2s (after 3 plaintext kex packets)
    seq_send = 3  # s2c (after 3 plaintext kex packets)

    # Recv SERVICE_REQUEST
    payload = recv_encrypted_packet(sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
    seq_recv += 1
    assert payload[0] == 5

    # Send SERVICE_ACCEPT
    send_encrypted_packet(sock, bytes([6]) + encode_string(b"ssh-userauth"),
                          keys['k1_s2c'], keys['k2_s2c'], seq_send)
    seq_send += 1

    # Recv USERAUTH_REQUEST
    payload = recv_encrypted_packet(sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
    seq_recv += 1
    assert payload[0] == 50

    # Parse password from auth request
    offset = 1
    user_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + user_len
    svc_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + svc_len
    method_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + method_len + 1  # +1 for FALSE byte
    pass_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4
    received_password = payload[offset:offset + pass_len]

    if received_password == expected_password:
        send_encrypted_packet(sock, bytes([52]), keys['k1_s2c'], keys['k2_s2c'], seq_send)
    else:
        send_encrypted_packet(sock, bytes([51]) + encode_string(b"password") + bytes([0]),
                              keys['k1_s2c'], keys['k2_s2c'], seq_send)
        raise ValueError("Auth failed - wrong password")
    seq_send += 1

    return seq_recv, seq_send


def do_kex_as_client(sock, host_pub_key_obj):
    """Run full kex as Python client. Returns keys dict."""
    client_version = b"SSH-2.0-TestClient_1.0"

    sock.sendall(client_version + b"\r\n")

    server_version_line = b""
    while not server_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        server_version_line += b
    server_version = server_version_line.rstrip(b"\r\n")

    # KEXINIT
    client_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(client_kexinit))
    server_kexinit = recv_plain_packet(sock)
    assert server_kexinit[0] == 20

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
        encode_string(client_version)
        + encode_string(server_version)
        + encode_string(client_kexinit)
        + encode_string(server_kexinit)
        + encode_string(host_key_blob)
        + encode_string(client_ephem_pub)
        + encode_string(server_ephem_pub)
        + K_mpint
    )
    H = hashlib.sha256(hash_input).digest()
    session_id = H

    k1_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[:32]
    k2_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[32:]
    k1_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[:32]
    k2_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[32:]

    # NEWKEYS: server sends first
    server_newkeys = recv_plain_packet(sock)
    assert server_newkeys == bytes([21])
    sock.sendall(build_plain_packet(bytes([21])))

    return {
        'k1_c2s': k1_c2s, 'k2_c2s': k2_c2s,
        'k1_s2c': k1_s2c, 'k2_s2c': k2_s2c,
        'session_id': session_id,
    }


def do_auth_as_client(sock, keys, username: bytes, password: bytes):
    """Run auth as Python client. Returns seq numbers (seq_send, seq_recv)."""
    seq_send = 3  # c2s (after 3 plaintext kex packets)
    seq_recv = 3  # s2c (after 3 plaintext kex packets)

    # Send SERVICE_REQUEST
    send_encrypted_packet(sock, bytes([5]) + encode_string(b"ssh-userauth"),
                          keys['k1_c2s'], keys['k2_c2s'], seq_send)
    seq_send += 1

    # Recv SERVICE_ACCEPT
    payload = recv_encrypted_packet(sock, keys['k1_s2c'], keys['k2_s2c'], seq_recv)
    seq_recv += 1
    assert payload[0] == 6

    # Send USERAUTH_REQUEST
    auth_request = bytes([50])
    auth_request += encode_string(username)
    auth_request += encode_string(b"ssh-connection")
    auth_request += encode_string(b"password")
    auth_request += bytes([0])
    auth_request += encode_string(password)
    send_encrypted_packet(sock, auth_request, keys['k1_c2s'], keys['k2_c2s'], seq_send)
    seq_send += 1

    # Recv response
    payload = recv_encrypted_packet(sock, keys['k1_s2c'], keys['k2_s2c'], seq_recv)
    seq_recv += 1
    assert payload[0] == 52, f"Auth failed, got msg type {payload[0]}"

    return seq_send, seq_recv


# ---- Mock server with channel support ----

class MockSSHServerWithChannels:
    """Python server: kex + auth + accept channel + recv data + echo back + close."""

    def __init__(self, expected_password: bytes):
        self.expected_password = expected_password
        self.success = False
        self.error = None
        self.received_data = None
        self.received_channel_type = None
        self.received_sender_channel = None

    def handle(self, sock):
        try:
            keys = do_kex_as_server(sock)
            seq_recv, seq_send = do_auth_as_server(sock, keys, self.expected_password)
            # After auth: seq_recv=2 (c2s), seq_send=2 (s2c)

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Recv CHANNEL_OPEN
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 90, f"Expected CHANNEL_OPEN(90), got {payload[0]}"

            # Parse: [byte 90][string channel_type][uint32 sender][uint32 window][uint32 maxpkt]
            offset = 1
            ct_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            self.received_channel_type = payload[offset:offset + ct_len]
            offset += ct_len
            self.received_sender_channel = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            client_window = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            client_maxpkt = struct.unpack(">I", payload[offset:offset + 4])[0]

            # Send CHANNEL_OPEN_CONFIRMATION
            # [byte 91][uint32 recipient=sender_channel][uint32 sender=42]
            # [uint32 window=2MB][uint32 maxpkt=32KB]
            confirm = bytes([91])
            confirm += struct.pack(">I", self.received_sender_channel)
            confirm += struct.pack(">I", 42)  # our channel id
            confirm += struct.pack(">I", 0x200000)  # 2MB window
            confirm += struct.pack(">I", 0x8000)  # 32KB max packet
            send_encrypted_packet(sock, confirm, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Recv CHANNEL_DATA
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 94, f"Expected CHANNEL_DATA(94), got {payload[0]}"

            # Parse: [byte 94][uint32 recipient][string data]
            offset = 1
            recipient = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            self.received_data = payload[offset:offset + data_len]

            # Echo data back as CHANNEL_DATA
            echo = bytes([94])
            echo += struct.pack(">I", self.received_sender_channel)  # recipient = client's channel
            echo += encode_string(self.received_data)
            send_encrypted_packet(sock, echo, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Send EOF + CLOSE
            eof = bytes([96]) + struct.pack(">I", self.received_sender_channel)
            send_encrypted_packet(sock, eof, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            close = bytes([97]) + struct.pack(">I", self.received_sender_channel)
            send_encrypted_packet(sock, close, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()


# ---- Mock client with channel support ----

class MockSSHClientWithChannels:
    """Python client: kex + auth + open channel + send data + recv echo."""

    def __init__(self, host_pub_key_obj, username: bytes, password: bytes, data_to_send: bytes):
        self.host_pub_key_obj = host_pub_key_obj
        self.username = username
        self.password = password
        self.data_to_send = data_to_send
        self.success = False
        self.error = None
        self.received_data = None
        self.received_eof = False
        self.received_close = False

    def handle(self, sock):
        try:
            keys = do_kex_as_client(sock, self.host_pub_key_obj)
            seq_send, seq_recv = do_auth_as_client(sock, keys, self.username, self.password)
            # After auth: seq_send=2 (c2s), seq_recv=2 (s2c) -- actually seq_recv=3 (svc_accept + auth_success + ...)
            # Wait -- let me recount:
            # c2s: SERVICE_REQUEST(seq=0), USERAUTH_REQUEST(seq=1) -> seq_send=2
            # s2c: SERVICE_ACCEPT(seq=0), USERAUTH_SUCCESS(seq=1) -> seq_recv=2
            # Correct: after auth, seq_send=2, seq_recv=2

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Send CHANNEL_OPEN
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)  # sender channel
            chan_open += struct.pack(">I", 0x200000)  # window
            chan_open += struct.pack(">I", 0x8000)  # max packet
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Recv CHANNEL_OPEN_CONFIRMATION
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"
            remote_channel = struct.unpack(">I", payload[5:9])[0]

            # Send CHANNEL_DATA
            data_pkt = bytes([94])
            data_pkt += struct.pack(">I", remote_channel)
            data_pkt += encode_string(self.data_to_send)
            send_encrypted_packet(sock, data_pkt, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Recv echoed CHANNEL_DATA
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 94, f"Expected CHANNEL_DATA(94), got {payload[0]}"
            offset = 5  # skip msg_type + recipient_channel
            data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            self.received_data = payload[offset:offset + data_len]

            # Recv EOF + CLOSE from server
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            if payload[0] == 96:
                self.received_eof = True

            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            if payload[0] == 97:
                self.received_close = True

            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()


# ============================================================================
# Tests
# ============================================================================

class TestSSHChannelClient:
    """Test assembly client opening channels against Python mock server."""

    def _run_client_channel(self, username: bytes, password: bytes):
        """Run kex+auth+channel with assembly client, Python server."""
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server = MockSSHServerWithChannels(password)
        server_thread = threading.Thread(target=server.handle, args=(s_server,))
        server_thread.start()

        client_fd = s_client.fileno()
        # Input: sock_fd(4 LE) + mode('o') + user_len(4 LE) + username + pass_len(4 LE) + password
        inp = struct.pack("<i", client_fd) + b'o'
        inp += struct.pack("<I", len(username)) + username
        inp += struct.pack("<I", len(password)) + password

        try:
            r = subprocess.run(
                [CHANNEL_BINARY],
                input=inp,
                capture_output=True,
                timeout=15,
                pass_fds=(client_fd,),
            )
        finally:
            s_client.close()

        server_thread.join(timeout=10)
        return server, r

    def test_channel_open_success(self):
        """Client successfully opens a session channel."""
        server, r = self._run_client_channel(
            username=b"testuser",
            password=b"pass123",
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}, stdout={r.stdout!r}"
        assert server.received_channel_type == b"session"
        assert server.received_sender_channel == 0

    def test_channel_data_send(self):
        """Client sends data through channel, server receives it."""
        server, r = self._run_client_channel(
            username=b"admin",
            password=b"secret",
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert server.received_data == b"hello"

    def test_channel_data_roundtrip(self):
        """Client sends data, server echoes back, client receives echo."""
        server, r = self._run_client_channel(
            username=b"user",
            password=b"pw",
        )
        assert server.success, f"Server failed: {server.error}"
        assert r.returncode == 0, f"Client failed (rc={r.returncode}), stderr={r.stderr!r}"
        # Client should output the echoed data
        assert r.stdout == b"hello", f"Expected echoed 'hello', got {r.stdout!r}"


class TestSSHChannelServer:
    """Test assembly server accepting channels from Python mock client."""

    def _run_server_channel(self, expected_password: bytes, client_username: bytes,
                            client_password: bytes, data_to_send: bytes = b"hello"):
        """Run kex+auth+channel with assembly server, Python client."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockSSHClientWithChannels(host_pub_key, client_username, client_password, data_to_send)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        # Input: sock_fd(4 LE) + mode('a') + host_key(64) + pass_len(4 LE) + password
        inp = struct.pack("<i", server_fd) + b'a'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(expected_password)) + expected_password

        try:
            r = subprocess.run(
                [CHANNEL_BINARY],
                input=inp,
                capture_output=True,
                timeout=15,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=10)
        return client, r

    def test_channel_accept_success(self):
        """Server accepts channel open from client."""
        client, r = self._run_server_channel(
            expected_password=b"testpass",
            client_username=b"admin",
            client_password=b"testpass",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}, stdout={r.stdout!r}"

    def test_channel_recv_data(self):
        """Server receives channel data from client."""
        client, r = self._run_server_channel(
            expected_password=b"pw",
            client_username=b"user",
            client_password=b"pw",
            data_to_send=b"hello",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        # Server outputs the received data
        assert r.stdout == b"hello", f"Expected 'hello', got {r.stdout!r}"

    def test_channel_echo_roundtrip(self):
        """Server receives data, echoes back, client gets echo."""
        client, r = self._run_server_channel(
            expected_password=b"pass",
            client_username=b"root",
            client_password=b"pass",
            data_to_send=b"world!",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert client.received_data == b"world!"
        assert r.stdout == b"world!"

    def test_channel_eof_close(self):
        """Server sends EOF and CLOSE after echo, client receives them."""
        client, r = self._run_server_channel(
            expected_password=b"secret",
            client_username=b"admin",
            client_password=b"secret",
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0
        assert client.received_eof, "Client did not receive EOF"
        assert client.received_close, "Client did not receive CLOSE"

    def test_channel_larger_data(self):
        """Channel handles larger data payload."""
        data = b"A" * 500
        client, r = self._run_server_channel(
            expected_password=b"pw",
            client_username=b"user",
            client_password=b"pw",
            data_to_send=data,
        )
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert client.received_data == data
        assert r.stdout == data
