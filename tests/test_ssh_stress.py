"""Comprehensive stress tests for SSH program assembly modules.

Tests large data transfers, rapid messaging, AEAD edge cases, repeated key exchange,
auth brute force resistance, binary safety, PTY stress, and connection teardown.

These tests exercise the assembly SSH implementation beyond normal operational
parameters to find edge cases, performance regressions, and robustness issues.
"""
import subprocess
import struct
import os
import socket
import threading
import hashlib
import time
import pytest
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

# Binary paths (relative to project root)
AEAD_BINARY = "./build/test_ssh_aead"
CHANNEL_BINARY = "./build/test_ssh_channel"
PTY_BINARY = "./build/test_ssh_pty"
KEX_BINARY = "./build/test_ssh_kex"
KEX_SERVER_BINARY = "./build/test_ssh_kex_server"
AUTH_BINARY = "./build/test_ssh_auth"
E2E_BINARY = "./build/test_ssh_e2e"


# ============================================================================
# Wire helpers (same as existing tests)
# ============================================================================

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


# ============================================================================
# Crypto helpers
# ============================================================================

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
    """SSH-framed AEAD encrypt (adds padding). Used for channel/transport tests."""
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
    """SSH-framed AEAD decrypt (strips padding). Used for channel/transport tests."""
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


def python_raw_aead_encrypt(payload, k1, k2, seq):
    """Raw AEAD encrypt (no SSH padding). Matches the AEAD test harness directly."""
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)

    plain_len = struct.pack(">I", len(payload))
    ks = python_chacha20_block(k2, 0, nonce)
    enc_len = bytes(a ^ b for a, b in zip(plain_len, ks[:4]))

    poly_key = python_chacha20_block(k1, 0, nonce)[:32]
    enc_payload = python_chacha20_encrypt(k1, 1, nonce, payload)
    mac = Poly1305.generate_tag(poly_key, enc_len + enc_payload)

    return enc_len + enc_payload + mac


def python_raw_aead_decrypt(data, k1, k2, seq):
    """Raw AEAD decrypt (no SSH unframing). Matches the AEAD test harness directly."""
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

    payload = python_chacha20_encrypt(k1, 1, nonce, enc_payload)
    return payload


def recv_encrypted_packet(sock, k1, k2, seq):
    enc_len = recv_exact(sock, 4)
    nonce = b'\x00' * 4 + struct.pack(">Q", seq)
    ks = python_chacha20_block(k2, 0, nonce)
    pkt_len_bytes = bytes(a ^ b for a, b in zip(enc_len, ks[:4]))
    pkt_len = struct.unpack(">I", pkt_len_bytes)[0]
    rest = recv_exact(sock, pkt_len + 16)
    full_data = enc_len + rest
    return python_ssh_aead_decrypt(full_data, k1, k2, seq)


def send_encrypted_packet(sock, payload, k1, k2, seq):
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


# ============================================================================
# Kex + Auth helpers
# ============================================================================

def do_kex_as_server(sock):
    """Run full kex handshake as Python server. Returns keys dict."""
    host_key = Ed25519PrivateKey.generate()
    host_pubkey = host_key.public_key()
    server_version = b"SSH-2.0-StressServer_1.0"

    sock.sendall(server_version + b"\r\n")
    client_version_line = b""
    while not client_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        client_version_line += b
    client_version = client_version_line.rstrip(b"\r\n")

    server_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(server_kexinit))
    client_kexinit = recv_plain_packet(sock)
    assert client_kexinit[0] == 20

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

    k1_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[:32]
    k2_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[32:]
    k1_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[:32]
    k2_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[32:]

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
    seq_recv = 3
    seq_send = 3

    payload = recv_encrypted_packet(sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
    seq_recv += 1
    assert payload[0] == 5

    send_encrypted_packet(sock, bytes([6]) + encode_string(b"ssh-userauth"),
                          keys['k1_s2c'], keys['k2_s2c'], seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
    seq_recv += 1
    assert payload[0] == 50

    offset = 1
    user_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + user_len
    svc_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + svc_len
    method_len = struct.unpack(">I", payload[offset:offset + 4])[0]
    offset += 4 + method_len + 1
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


def do_kex_as_client(sock, host_pub_key_obj=None):
    """Run full kex as Python client. Returns keys dict."""
    client_version = b"SSH-2.0-StressClient_1.0"

    sock.sendall(client_version + b"\r\n")
    server_version_line = b""
    while not server_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        server_version_line += b
    server_version = server_version_line.rstrip(b"\r\n")

    client_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(client_kexinit))
    server_kexinit = recv_plain_packet(sock)
    assert server_kexinit[0] == 20

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
    seq_send = 3
    seq_recv = 3

    send_encrypted_packet(sock, bytes([5]) + encode_string(b"ssh-userauth"),
                          keys['k1_c2s'], keys['k2_c2s'], seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, keys['k1_s2c'], keys['k2_s2c'], seq_recv)
    seq_recv += 1
    assert payload[0] == 6

    auth_request = bytes([50])
    auth_request += encode_string(username)
    auth_request += encode_string(b"ssh-connection")
    auth_request += encode_string(b"password")
    auth_request += bytes([0])
    auth_request += encode_string(password)
    send_encrypted_packet(sock, auth_request, keys['k1_c2s'], keys['k2_c2s'], seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, keys['k1_s2c'], keys['k2_s2c'], seq_recv)
    seq_recv += 1

    return seq_send, seq_recv, payload[0]


# ============================================================================
# AEAD helpers (direct binary interface)
# ============================================================================

def encrypt_asm(k1, k2, seq, payload):
    inp = b'e' + k1 + k2 + struct.pack("<I", seq) + struct.pack("<I", len(payload)) + payload
    r = subprocess.run([AEAD_BINARY], input=inp, capture_output=True, timeout=10)
    assert r.returncode == 0, f"AEAD encrypt failed (rc={r.returncode})"
    return r.stdout


def decrypt_asm(k1, k2, seq, data):
    inp = b'd' + k1 + k2 + struct.pack("<I", seq) + struct.pack("<I", len(data)) + data
    return subprocess.run([AEAD_BINARY], input=inp, capture_output=True, timeout=10)


# ============================================================================
# Mock server/client for channel stress tests
# ============================================================================

class MockChannelServerMultiRecv:
    """Python server that does kex+auth+channel, receives multiple data packets
    and echoes each one back, then sends EOF+CLOSE."""

    def __init__(self, expected_password: bytes, expected_messages: int):
        self.expected_password = expected_password
        self.expected_messages = expected_messages
        self.success = False
        self.error = None
        self.received_data = []

    def handle(self, sock):
        try:
            keys = do_kex_as_server(sock)
            seq_recv, seq_send = do_auth_as_server(sock, keys, self.expected_password)

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Recv CHANNEL_OPEN
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 90

            offset = 1
            ct_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4 + ct_len
            sender_channel = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            client_window = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4

            # Send CHANNEL_OPEN_CONFIRMATION
            confirm = bytes([91])
            confirm += struct.pack(">I", sender_channel)
            confirm += struct.pack(">I", 42)
            confirm += struct.pack(">I", 0x200000)  # 2MB window
            confirm += struct.pack(">I", 0x8000)    # 32KB max packet
            send_encrypted_packet(sock, confirm, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Recv CHANNEL_DATA — the channel harness sends "hello"
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 94

            offset = 5
            data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            self.received_data.append(payload[offset:offset + data_len])

            # Echo back
            echo = bytes([94])
            echo += struct.pack(">I", sender_channel)
            echo += encode_string(self.received_data[-1])
            send_encrypted_packet(sock, echo, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Send EOF + CLOSE
            eof = bytes([96]) + struct.pack(">I", sender_channel)
            send_encrypted_packet(sock, eof, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            close = bytes([97]) + struct.pack(">I", sender_channel)
            send_encrypted_packet(sock, close, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            self.success = True
        except Exception as e:
            self.error = str(e)
            import traceback
            traceback.print_exc()
        finally:
            sock.close()


class MockChannelClientLargeData:
    """Python client: kex + auth + open channel + send large data + recv echo."""

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
            seq_send, seq_recv, auth_result = do_auth_as_client(
                sock, keys, self.username, self.password)
            assert auth_result == 52, f"Auth failed: {auth_result}"

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Send CHANNEL_OPEN
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)
            chan_open += struct.pack(">I", 0x200000)  # 2MB window
            chan_open += struct.pack(">I", 0x8000)    # 32KB max packet
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Recv CHANNEL_OPEN_CONFIRMATION
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 91
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
            assert payload[0] == 94
            offset = 5
            data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            offset += 4
            self.received_data = payload[offset:offset + data_len]

            # Recv EOF
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            if payload[0] == 96:
                self.received_eof = True

            # Recv CLOSE
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
# Test 1: AEAD Edge Cases
# ============================================================================

class TestAEADEdgeCases:
    """Stress test AEAD encrypt/decrypt with edge case parameters."""

    def test_seq_max_uint32_encrypt_decrypt(self):
        """Encrypt/decrypt with sequence number at uint32 max (0xFFFFFFFF)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"max seq stress"
        seq = 0xFFFFFFFF

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0, f"Decrypt failed at seq=0xFFFFFFFF"
        assert r.stdout == payload

    def test_seq_max_cross_validate(self):
        """Cross-validate max seq between assembly and Python."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"cross-max-seq"
        seq = 0xFFFFFFFF

        # ASM encrypt -> Python decrypt (raw, no SSH framing)
        enc = encrypt_asm(k1, k2, seq, payload)
        dec = python_raw_aead_decrypt(enc, k1, k2, seq)
        assert dec == payload, "ASM->Python failed at max seq"

        # Python encrypt -> ASM decrypt (raw, no SSH framing)
        enc = python_raw_aead_encrypt(payload, k1, k2, seq)
        r = decrypt_asm(k1, k2, seq, enc)
        assert r.returncode == 0, "Python->ASM failed at max seq"
        assert r.stdout == payload

    def test_empty_payload(self):
        """Encrypt/decrypt empty payload."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b""
        seq = 0

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == b""

    def test_single_byte_payload(self):
        """Encrypt/decrypt payload of exactly 1 byte."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for byte_val in [0x00, 0x01, 0x7F, 0x80, 0xFF]:
            payload = bytes([byte_val])
            seq = byte_val

            encrypted = encrypt_asm(k1, k2, seq, payload)
            r = decrypt_asm(k1, k2, seq, encrypted)
            assert r.returncode == 0, f"Failed for byte 0x{byte_val:02x}"
            assert r.stdout == payload, f"Data mismatch for byte 0x{byte_val:02x}"

    def test_32kb_payload(self):
        """Encrypt/decrypt payload of exactly 32KB (SSH_MAX_PACKET_SIZE typical)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(32768)
        seq = 100

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0, "Failed for 32KB payload"
        assert r.stdout == payload, "Data mismatch for 32KB payload"

    @pytest.mark.slow
    def test_large_payload_sizes(self):
        """Test various large payload sizes up to 64KB (harness buffer limit is 65536)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        # Max safe payload for AEAD harness: output_buf(65536) - 20 (header+mac) = 65516
        for size in [4096, 8192, 16384, 32768, 65516]:
            payload = os.urandom(size)
            seq = size % 0xFFFFFFFF

            encrypted = encrypt_asm(k1, k2, seq, payload)
            dec = python_raw_aead_decrypt(encrypted, k1, k2, seq)
            assert dec == payload, f"Cross-validation failed at size {size}"

    def test_sequential_seq_numbers(self):
        """Encrypt/decrypt with sequential sequence numbers (0 through 99)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for seq in range(100):
            payload = f"seq-{seq}".encode()
            encrypted = encrypt_asm(k1, k2, seq, payload)
            r = decrypt_asm(k1, k2, seq, encrypted)
            assert r.returncode == 0, f"Failed at seq={seq}"
            assert r.stdout == payload, f"Data mismatch at seq={seq}"

    def test_all_zero_key(self):
        """Encrypt/decrypt with all-zero keys (edge case for key schedule)."""
        k1 = b'\x00' * 32
        k2 = b'\x00' * 32
        payload = b"zero key test"
        seq = 0

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_all_ff_key(self):
        """Encrypt/decrypt with all-0xFF keys."""
        k1 = b'\xff' * 32
        k2 = b'\xff' * 32
        payload = b"ff key test"
        seq = 0xFFFFFFFF

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload


# ============================================================================
# Test 2: Binary Safety
# ============================================================================

class TestBinarySafety:
    """Verify all 256 byte values survive encrypt/decrypt."""

    def test_all_byte_values(self):
        """Send all 256 byte values (0x00-0xFF) through AEAD."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = bytes(range(256))
        seq = 42

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload, "Binary data corrupted through AEAD"

    def test_all_byte_values_repeated(self):
        """Send all 256 byte values repeated 4x (1KB) through AEAD."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = bytes(range(256)) * 4
        seq = 7

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_null_bytes_in_strings(self):
        """Send payloads with embedded null bytes."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        test_payloads = [
            b"\x00",
            b"\x00\x00\x00\x00",
            b"hello\x00world",
            b"\x00" * 100,
            b"A\x00B\x00C\x00D\x00",
        ]

        for i, payload in enumerate(test_payloads):
            seq = i
            encrypted = encrypt_asm(k1, k2, seq, payload)
            r = decrypt_asm(k1, k2, seq, encrypted)
            assert r.returncode == 0, f"Failed for test payload #{i}"
            assert r.stdout == payload, f"Data mismatch for test payload #{i}"

    def test_max_harness_binary_data(self):
        """Send max-size binary data through AEAD harness (65516 bytes)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        # Max safe: output_buf(65536) - 20 (4 enc_len + 16 mac) = 65516
        payload = bytes(range(256)) * 255 + bytes(range(236))  # = 65516 bytes
        assert len(payload) == 65516
        seq = 999

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0, "Max harness binary transfer failed"
        assert len(r.stdout) == len(payload), (
            f"Length mismatch: expected {len(payload)}, got {len(r.stdout)}"
        )
        assert r.stdout == payload, "Max harness binary data corrupted"

    def test_max_harness_sha256_integrity(self):
        """Verify SHA-256 hash matches for max-size binary transfer."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = bytes(range(256)) * 255 + bytes(range(236))  # 65516 bytes
        seq = 1234

        expected_hash = hashlib.sha256(payload).hexdigest()

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0

        actual_hash = hashlib.sha256(r.stdout).hexdigest()
        assert actual_hash == expected_hash, (
            f"SHA-256 mismatch: expected {expected_hash}, got {actual_hash}"
        )

    def test_large_payload_above_64kb(self):
        """Verify AEAD handles payloads above 64KB after buffer fix."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(69569)
        inp = (b'e' + k1 + k2 + struct.pack("<I", 0)
               + struct.pack("<I", len(payload)) + payload)
        r = subprocess.run([AEAD_BINARY], input=inp, capture_output=True, timeout=10)
        assert r.returncode == 0, f"Expected success, got rc={r.returncode}"
        assert len(r.stdout) > 0, "No output from encrypt"


# ============================================================================
# Test 3: Large Data Transfer via Channel
# ============================================================================

class TestChannelLargeData:
    """Stress test channel with larger payloads via assembly server mode."""

    def _run_server_channel(self, password: bytes, data_to_send: bytes):
        """Run assembly server, Python client sends data."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        client = MockChannelClientLargeData(
            host_pub_key, b"stressuser", password, data_to_send)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        inp = struct.pack("<i", server_fd) + b'a'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(password)) + password

        try:
            r = subprocess.run(
                [CHANNEL_BINARY],
                input=inp,
                capture_output=True,
                timeout=30,
                pass_fds=(server_fd,),
            )
        finally:
            s_server.close()

        client_thread.join(timeout=15)
        return client, r

    def test_500_bytes(self):
        """Channel handles 500-byte payload (baseline)."""
        data = b"X" * 500
        client, r = self._run_server_channel(b"pw", data)
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed: rc={r.returncode}, stderr={r.stderr!r}"
        assert client.received_data == data
        assert r.stdout == data

    def test_500_bytes_at_recv_buffer_limit(self):
        """Channel handles 500-byte payload (at ssh_channel_recv 512-byte buffer limit).

        BUG FOUND: ssh_channel_recv uses a 512-byte stack buffer for decrypted
        packets. CHANNEL_DATA framing adds 9 bytes (msg_type + recipient_channel
        + string_len), so max safe data is 512 - 9 = 503 bytes. This severely
        limits channel throughput for a real SSH implementation that should
        support up to 32KB packets per SSH_MAX_PACKET_DATA.
        """
        data = os.urandom(500)
        client, r = self._run_server_channel(b"pw", data)
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed: rc={r.returncode}, stderr={r.stderr!r}"
        assert client.received_data == data
        assert r.stdout == data

    def test_binary_data_all_bytes(self):
        """Channel handles all 256 byte values."""
        data = bytes(range(256))
        client, r = self._run_server_channel(b"pw", data)
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed: rc={r.returncode}, stderr={r.stderr!r}"
        assert client.received_data == data

    def test_data_sha256_integrity(self):
        """Verify SHA-256 integrity through encrypted channel."""
        data = os.urandom(400)  # Well within 503-byte recv buffer limit
        expected_hash = hashlib.sha256(data).hexdigest()

        client, r = self._run_server_channel(b"pw", data)
        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0

        actual_hash = hashlib.sha256(r.stdout).hexdigest()
        assert actual_hash == expected_hash, (
            f"SHA-256 mismatch through channel: {expected_hash} != {actual_hash}"
        )


# ============================================================================
# Test 4: Repeated Key Exchange
# ============================================================================

class TestRepeatedKex:
    """Verify no state leaks by running multiple consecutive kex handshakes."""

    @pytest.mark.slow
    def test_10_consecutive_client_kex(self):
        """Run 10 consecutive kex handshakes in client mode."""
        results = []
        for i in range(10):
            s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

            # Simple mock server
            server_result = {}

            def server_handler(sock, res):
                try:
                    host_key = Ed25519PrivateKey.generate()
                    host_pubkey = host_key.public_key()
                    version = b"SSH-2.0-KexStress_1.0"

                    sock.sendall(version + b"\r\n")
                    vline = b""
                    while not vline.endswith(b"\n"):
                        b = sock.recv(1)
                        if not b:
                            raise ConnectionError("EOF")
                        vline += b

                    server_kexinit = build_kexinit_payload()
                    sock.sendall(build_plain_packet(server_kexinit))
                    client_kexinit = recv_plain_packet(sock)
                    assert client_kexinit[0] == 20

                    ecdh_init = recv_plain_packet(sock)
                    assert ecdh_init[0] == 30
                    client_ephem_pub = ecdh_init[5:37]

                    server_ephem_priv = X25519PrivateKey.generate()
                    server_ephem_pub = server_ephem_priv.public_key().public_bytes(
                        Encoding.Raw, PublicFormat.Raw)
                    client_x25519 = X25519PublicKey.from_public_bytes(client_ephem_pub)
                    shared = server_ephem_priv.exchange(client_x25519)

                    host_pub_bytes = host_pubkey.public_bytes(Encoding.Raw, PublicFormat.Raw)
                    host_key_blob = encode_string(b"ssh-ed25519") + encode_string(host_pub_bytes)
                    K_mpint = encode_mpint(shared)
                    hash_input = (
                        encode_string(vline.rstrip(b"\r\n"))
                        + encode_string(version)
                        + encode_string(client_kexinit)
                        + encode_string(server_kexinit)
                        + encode_string(host_key_blob)
                        + encode_string(client_ephem_pub)
                        + encode_string(server_ephem_pub)
                        + K_mpint
                    )
                    H = hashlib.sha256(hash_input).digest()
                    sig = host_key.sign(H)
                    sig_blob = encode_string(b"ssh-ed25519") + encode_string(sig)

                    reply = bytes([31])
                    reply += encode_string(host_key_blob)
                    reply += encode_string(server_ephem_pub)
                    reply += encode_string(sig_blob)
                    sock.sendall(build_plain_packet(reply))

                    sock.sendall(build_plain_packet(bytes([21])))
                    nk = recv_plain_packet(sock)
                    assert nk == bytes([21])
                    res['ok'] = True
                except Exception as e:
                    res['error'] = str(e)
                finally:
                    sock.close()

            t = threading.Thread(target=server_handler, args=(s_server, server_result))
            t.start()

            client_fd = s_client.fileno()
            inp = struct.pack("<i", client_fd)
            try:
                r = subprocess.run(
                    [KEX_BINARY], input=inp, capture_output=True,
                    timeout=10, pass_fds=(client_fd,))
            finally:
                s_client.close()
            t.join(timeout=5)

            results.append({
                'iteration': i,
                'client_rc': r.returncode,
                'server_ok': server_result.get('ok', False),
                'server_error': server_result.get('error'),
            })

        # Verify all 10 succeeded
        for res in results:
            assert res['server_ok'], (
                f"Iteration {res['iteration']} server failed: {res['server_error']}")
            assert res['client_rc'] == 0, (
                f"Iteration {res['iteration']} client failed: rc={res['client_rc']}")

    @pytest.mark.slow
    def test_10_consecutive_server_kex(self):
        """Run 10 consecutive kex handshakes in server mode."""
        for i in range(10):
            host_priv_bytes, host_pub_bytes, _, host_pub_key = generate_ed25519_keypair()

            s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

            client_result = {}

            def client_handler(sock, pub_key, res):
                try:
                    keys = do_kex_as_client(sock, pub_key)
                    res['ok'] = True
                    res['session_id'] = keys['session_id']
                except Exception as e:
                    res['error'] = str(e)
                finally:
                    sock.close()

            t = threading.Thread(target=client_handler,
                                 args=(s_client, host_pub_key, client_result))
            t.start()

            server_fd = s_server.fileno()
            inp = struct.pack("<i", server_fd) + host_priv_bytes + host_pub_bytes
            try:
                r = subprocess.run(
                    [KEX_SERVER_BINARY], input=inp, capture_output=True,
                    timeout=10, pass_fds=(server_fd,))
            finally:
                s_server.close()
            t.join(timeout=5)

            assert client_result.get('ok'), (
                f"Iteration {i} client failed: {client_result.get('error')}")
            assert r.returncode == 0, (
                f"Iteration {i} server failed: rc={r.returncode}")


# ============================================================================
# Test 5: Auth Brute Force Simulation
# ============================================================================

class TestAuthBruteForce:
    """Test authentication handles rapid wrong password attempts."""

    @pytest.mark.slow
    def test_20_wrong_then_correct(self):
        """Send 20 wrong passwords then 1 correct — verify it still works."""
        correct_password = b"the_real_password"

        # Test 20 wrong attempts
        for i in range(20):
            wrong_password = f"wrong_pass_{i}".encode()

            s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

            server_result = {'done': False}

            def mock_server(sock, res, pwd):
                try:
                    keys = do_kex_as_server(sock)
                    seq_recv = 3
                    seq_send = 3

                    payload = recv_encrypted_packet(
                        sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
                    seq_recv += 1
                    assert payload[0] == 5

                    send_encrypted_packet(
                        sock, bytes([6]) + encode_string(b"ssh-userauth"),
                        keys['k1_s2c'], keys['k2_s2c'], seq_send)
                    seq_send += 1

                    payload = recv_encrypted_packet(
                        sock, keys['k1_c2s'], keys['k2_c2s'], seq_recv)
                    seq_recv += 1
                    assert payload[0] == 50

                    # Parse password
                    offset = 1
                    user_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                    offset += 4 + user_len
                    svc_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                    offset += 4 + svc_len
                    method_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                    offset += 4 + method_len + 1
                    pass_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                    offset += 4
                    received_password = payload[offset:offset + pass_len]

                    if received_password == pwd:
                        send_encrypted_packet(
                            sock, bytes([52]),
                            keys['k1_s2c'], keys['k2_s2c'], seq_send)
                        res['accepted'] = True
                    else:
                        send_encrypted_packet(
                            sock, bytes([51]) + encode_string(b"password") + bytes([0]),
                            keys['k1_s2c'], keys['k2_s2c'], seq_send)
                        res['accepted'] = False
                    res['done'] = True
                except Exception as e:
                    res['error'] = str(e)
                finally:
                    sock.close()

            t = threading.Thread(target=mock_server,
                                 args=(s_server, server_result, correct_password))
            t.start()

            client_fd = s_client.fileno()
            inp = struct.pack("<i", client_fd) + b'c'
            inp += struct.pack("<I", 4) + b"user"
            inp += struct.pack("<I", len(wrong_password)) + wrong_password

            try:
                r = subprocess.run(
                    [AUTH_BINARY], input=inp, capture_output=True,
                    timeout=10, pass_fds=(client_fd,))
            finally:
                s_client.close()
            t.join(timeout=5)

            assert server_result.get('done'), (
                f"Wrong attempt {i} server didn't finish: {server_result.get('error')}")
            assert not server_result.get('accepted'), (
                f"Wrong attempt {i} should have been rejected")
            assert r.returncode == 1, (
                f"Wrong attempt {i} client should fail: rc={r.returncode}")

        # Now test correct password
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server_result = {'done': False}
        t = threading.Thread(target=mock_server,
                             args=(s_server, server_result, correct_password))
        t.start()

        client_fd = s_client.fileno()
        inp = struct.pack("<i", client_fd) + b'c'
        inp += struct.pack("<I", 4) + b"user"
        inp += struct.pack("<I", len(correct_password)) + correct_password

        try:
            r = subprocess.run(
                [AUTH_BINARY], input=inp, capture_output=True,
                timeout=10, pass_fds=(client_fd,))
        finally:
            s_client.close()
        t.join(timeout=5)

        assert server_result.get('done'), (
            f"Correct attempt server didn't finish: {server_result.get('error')}")
        assert server_result.get('accepted'), "Correct password should be accepted"
        assert r.returncode == 0, (
            f"Correct password should succeed: rc={r.returncode}")


# ============================================================================
# Test 6: Max-Size Packets
# ============================================================================

class TestMaxSizePackets:
    """Test encryption/decryption of packets near SSH_MAX_PACKET_SIZE (32KB)."""

    def test_exactly_32kb(self):
        """Encrypt/decrypt exactly 32768 bytes."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(32768)
        seq = 0

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_32kb_minus_1(self):
        """Encrypt/decrypt 32767 bytes."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(32767)
        seq = 1

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_32kb_plus_1(self):
        """Encrypt/decrypt 32769 bytes (just over typical max packet)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(32769)
        seq = 2

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_power_of_two_sizes(self):
        """Encrypt/decrypt at various power-of-2 boundary sizes."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for exp in range(0, 16):
            size = 2 ** exp
            payload = os.urandom(size)
            seq = exp

            encrypted = encrypt_asm(k1, k2, seq, payload)
            r = decrypt_asm(k1, k2, seq, encrypted)
            assert r.returncode == 0, f"Failed at size 2^{exp} = {size}"
            assert r.stdout == payload, f"Data mismatch at size 2^{exp} = {size}"


# ============================================================================
# Test 7: PTY Stress
# ============================================================================

class TestPTYStress:
    """Stress test PTY allocation and relay."""

    def _run_relay_test(self, password: bytes, command: str, marker: str,
                        timeout_sec: float = 8.0):
        """Run full SSH session: Python client -> asm server with PTY relay."""
        host_priv_bytes, host_pub_bytes, _, _ = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server_fd = s_server.fileno()
        inp = b'r'
        inp += struct.pack("<i", server_fd)
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(password)) + password

        proc = subprocess.Popen(
            [PTY_BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(server_fd,),
        )
        proc.stdin.write(inp)
        proc.stdin.flush()
        s_server.close()

        try:
            sock = s_client
            keys = do_kex_as_client(sock)
            seq_send, seq_recv, auth_result = do_auth_as_client(
                sock, keys, b"testuser", password)
            assert auth_result == 52

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Open channel
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)
            chan_open += struct.pack(">I", 0x200000)
            chan_open += struct.pack(">I", 0x8000)
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 91
            remote_channel = struct.unpack(">I", payload[5:9])[0]

            # PTY request
            pty_req = bytes([98])
            pty_req += struct.pack(">I", remote_channel)
            pty_req += encode_string(b"pty-req")
            pty_req += bytes([0])
            pty_req += encode_string(b"xterm-256color")
            pty_req += struct.pack(">I", 80)
            pty_req += struct.pack(">I", 24)
            pty_req += struct.pack(">I", 640)
            pty_req += struct.pack(">I", 480)
            pty_req += encode_string(b"")
            send_encrypted_packet(sock, pty_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Shell request
            shell_req = bytes([98])
            shell_req += struct.pack(">I", remote_channel)
            shell_req += encode_string(b"shell")
            shell_req += bytes([0])
            send_encrypted_packet(sock, shell_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            time.sleep(0.5)

            # Send command
            cmd_bytes = (command + "\n").encode()
            data_pkt = bytes([94])
            data_pkt += struct.pack(">I", remote_channel)
            data_pkt += encode_string(cmd_bytes)
            send_encrypted_packet(sock, data_pkt, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Read responses
            collected = b""
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
                    seq_recv += 1

                    if payload[0] == 94:
                        offset = 5
                        data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                        offset += 4
                        collected += payload[offset:offset + data_len]
                        if marker.encode() in collected:
                            break
                    elif payload[0] == 93:
                        continue
                    elif payload[0] in (96, 97):
                        break
                except (socket.timeout, ConnectionError):
                    break

            # Clean exit
            exit_pkt = bytes([94])
            exit_pkt += struct.pack(">I", remote_channel)
            exit_pkt += encode_string(b"exit\n")
            try:
                send_encrypted_packet(sock, exit_pkt, k1_c2s, k2_c2s, seq_send)
            except (BrokenPipeError, ConnectionError):
                pass

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            return collected

        finally:
            s_client.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_sequential_commands(self):
        """Run multiple commands sequentially through PTY."""
        host_priv_bytes, host_pub_bytes, _, _ = generate_ed25519_keypair()
        password = b"pty_stress"

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server_fd = s_server.fileno()
        inp = b'r'
        inp += struct.pack("<i", server_fd)
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(password)) + password

        proc = subprocess.Popen(
            [PTY_BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(server_fd,),
        )
        proc.stdin.write(inp)
        proc.stdin.flush()
        s_server.close()

        try:
            sock = s_client
            keys = do_kex_as_client(sock)
            seq_send, seq_recv, auth_result = do_auth_as_client(
                sock, keys, b"testuser", password)
            assert auth_result == 52

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Open channel
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)
            chan_open += struct.pack(">I", 0x200000)
            chan_open += struct.pack(">I", 0x8000)
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 91
            remote_channel = struct.unpack(">I", payload[5:9])[0]

            # PTY + shell
            pty_req = bytes([98])
            pty_req += struct.pack(">I", remote_channel)
            pty_req += encode_string(b"pty-req")
            pty_req += bytes([0])
            pty_req += encode_string(b"xterm-256color")
            pty_req += struct.pack(">I", 80)
            pty_req += struct.pack(">I", 24)
            pty_req += struct.pack(">I", 640)
            pty_req += struct.pack(">I", 480)
            pty_req += encode_string(b"")
            send_encrypted_packet(sock, pty_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            shell_req = bytes([98])
            shell_req += struct.pack(">I", remote_channel)
            shell_req += encode_string(b"shell")
            shell_req += bytes([0])
            send_encrypted_packet(sock, shell_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            time.sleep(0.5)

            # Send multiple commands with unique markers
            commands = [
                ("echo MARKER_WHOAMI_$(whoami)", "MARKER_WHOAMI_"),
                ("echo MARKER_PWD_$(pwd)", "MARKER_PWD_"),
                ("echo MARKER_LS_$(ls / | head -1)", "MARKER_LS_"),
                ("echo MARKER_ECHO_test", "MARKER_ECHO_test"),
                ("echo MARKER_HOST_$(cat /etc/hostname 2>/dev/null || echo none)",
                 "MARKER_HOST_"),
            ]

            collected = b""
            for cmd, _ in commands:
                cmd_bytes = (cmd + "\n").encode()
                data_pkt = bytes([94])
                data_pkt += struct.pack(">I", remote_channel)
                data_pkt += encode_string(cmd_bytes)
                send_encrypted_packet(sock, data_pkt, k1_c2s, k2_c2s, seq_send)
                seq_send += 1
                time.sleep(0.3)

            # Collect output
            deadline = time.time() + 10.0
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
                    seq_recv += 1
                    if payload[0] == 94:
                        offset = 5
                        data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                        offset += 4
                        collected += payload[offset:offset + data_len]
                        # Check if we have the last marker
                        if b"MARKER_HOST_" in collected:
                            # Give a little more time for all output
                            time.sleep(0.5)
                            # Read any remaining
                            try:
                                sock.settimeout(0.5)
                                while True:
                                    p = recv_encrypted_packet(
                                        sock, k1_s2c, k2_s2c, seq_recv)
                                    seq_recv += 1
                                    if p[0] == 94:
                                        off = 5
                                        dl = struct.unpack(">I", p[off:off + 4])[0]
                                        off += 4
                                        collected += p[off:off + dl]
                                    elif p[0] in (96, 97):
                                        break
                            except (socket.timeout, ConnectionError):
                                pass
                            break
                    elif payload[0] == 93:
                        continue
                    elif payload[0] in (96, 97):
                        break
                except (socket.timeout, ConnectionError):
                    break

            # Cleanup
            exit_pkt = bytes([94])
            exit_pkt += struct.pack(">I", remote_channel)
            exit_pkt += encode_string(b"exit\n")
            try:
                send_encrypted_packet(sock, exit_pkt, k1_c2s, k2_c2s, seq_send)
            except (BrokenPipeError, ConnectionError):
                pass

            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            output = collected.decode('utf-8', errors='replace')

            # Verify all markers present
            for _, marker in commands:
                assert marker in output, (
                    f"Missing marker '{marker}' in PTY output. Got: {output!r}"
                )

        finally:
            s_client.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_large_output_command(self):
        """Run a command that produces large output through PTY."""
        collected = self._run_relay_test(
            password=b"ptypass",
            command="seq 1 50 && echo SEQDONE",
            marker="SEQDONE",
            timeout_sec=12.0,
        )
        output = collected.decode('utf-8', errors='replace')
        assert 'SEQDONE' in output, (
            f"Expected 'SEQDONE' in seq output, got: {output[:500]!r}..."
        )
        # Verify at least some values are present
        assert '1' in output
        assert '50' in output

    def test_binary_output_command(self):
        """Run a command with base64-encoded random output through PTY."""
        collected = self._run_relay_test(
            password=b"ptypass",
            command="dd if=/dev/urandom bs=256 count=1 2>/dev/null | base64",
            marker="=",  # base64 typically ends with =
            timeout_sec=8.0,
        )
        # We just verify we got some output back (base64 chars)
        output = collected.decode('utf-8', errors='replace')
        assert len(output) > 50, (
            f"Expected substantial base64 output, got {len(output)} chars"
        )


# ============================================================================
# Test 8: Connection Teardown
# ============================================================================

class TestConnectionTeardown:
    """Test clean channel teardown (EOF + CLOSE)."""

    def test_clean_eof_close(self):
        """Open channel, send data, verify clean EOF + CLOSE sequence."""
        host_priv_bytes, host_pub_bytes, _, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        data = b"teardown_test"
        client = MockChannelClientLargeData(
            host_pub_key, b"user", b"pass", data)
        client_thread = threading.Thread(target=client.handle, args=(s_client,))
        client_thread.start()

        server_fd = s_server.fileno()
        inp = struct.pack("<i", server_fd) + b'a'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", 4) + b"pass"

        try:
            r = subprocess.run(
                [CHANNEL_BINARY], input=inp, capture_output=True,
                timeout=15, pass_fds=(server_fd,))
        finally:
            s_server.close()

        client_thread.join(timeout=10)

        assert client.success, f"Client failed: {client.error}"
        assert r.returncode == 0, f"Server failed: rc={r.returncode}"
        assert client.received_data == data, "Data mismatch"
        assert client.received_eof, "Did not receive EOF"
        assert client.received_close, "Did not receive CLOSE"

    def test_multiple_teardown_cycles(self):
        """Run 5 connect/data/teardown cycles to check for resource leaks."""
        for i in range(5):
            host_priv_bytes, host_pub_bytes, _, host_pub_key = generate_ed25519_keypair()

            s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

            data = f"cycle_{i}".encode()
            client = MockChannelClientLargeData(
                host_pub_key, b"user", b"pass", data)
            client_thread = threading.Thread(target=client.handle, args=(s_client,))
            client_thread.start()

            server_fd = s_server.fileno()
            inp = struct.pack("<i", server_fd) + b'a'
            inp += host_priv_bytes + host_pub_bytes
            inp += struct.pack("<I", 4) + b"pass"

            try:
                r = subprocess.run(
                    [CHANNEL_BINARY], input=inp, capture_output=True,
                    timeout=15, pass_fds=(server_fd,))
            finally:
                s_server.close()

            client_thread.join(timeout=10)

            assert client.success, f"Cycle {i} client failed: {client.error}"
            assert r.returncode == 0, f"Cycle {i} server failed: rc={r.returncode}"
            assert client.received_data == data, f"Cycle {i} data mismatch"
            assert client.received_eof, f"Cycle {i} missing EOF"
            assert client.received_close, f"Cycle {i} missing CLOSE"


# ============================================================================
# Test 9: AEAD Rapid Fire (simulating rapid small messages)
# ============================================================================

class TestAEADRapidFire:
    """Simulate rapid small message encrypt/decrypt sequences."""

    @pytest.mark.slow
    def test_500_small_messages(self):
        """Encrypt/decrypt 500 small messages (10-100 bytes) with sequential seqs."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for seq in range(500):
            size = 10 + (seq % 91)  # 10 to 100 bytes
            payload = os.urandom(size)

            encrypted = encrypt_asm(k1, k2, seq, payload)
            r = decrypt_asm(k1, k2, seq, encrypted)
            assert r.returncode == 0, f"Failed at message {seq}"
            assert r.stdout == payload, f"Data mismatch at message {seq}"

    def test_100_messages_cross_validated(self):
        """Cross-validate 100 messages between ASM and Python (raw AEAD)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for seq in range(100):
            size = 10 + (seq % 91)
            payload = os.urandom(size)

            # ASM encrypt -> Python decrypt (raw, no SSH framing)
            enc = encrypt_asm(k1, k2, seq, payload)
            dec = python_raw_aead_decrypt(enc, k1, k2, seq)
            assert dec == payload, f"ASM->Python mismatch at msg {seq}"

            # Python encrypt -> ASM decrypt (raw, no SSH framing)
            enc = python_raw_aead_encrypt(payload, k1, k2, seq)
            r = decrypt_asm(k1, k2, seq, enc)
            assert r.returncode == 0, f"Python->ASM failed at msg {seq}"
            assert r.stdout == payload, f"Python->ASM mismatch at msg {seq}"


# ============================================================================
# Test 10: Large Data via AEAD (1MB stress)
# ============================================================================

class TestLargeDataTransfer:
    """Stress test with very large payloads through AEAD directly."""

    @pytest.mark.slow
    def test_max_harness_aead_roundtrip(self):
        """Encrypt/decrypt max harness payload (65516 bytes) through AEAD assembly."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(65516)  # Max safe: 65536 - 20
        seq = 0

        t0 = time.time()
        encrypted = encrypt_asm(k1, k2, seq, payload)
        t1 = time.time()
        r = decrypt_asm(k1, k2, seq, encrypted)
        t2 = time.time()

        assert r.returncode == 0, "Max harness decrypt failed"
        assert len(r.stdout) == len(payload), (
            f"Length mismatch: {len(r.stdout)} != {len(payload)}")
        assert r.stdout == payload, "Max harness data corrupted"

        encrypt_ms = (t1 - t0) * 1000
        decrypt_ms = (t2 - t1) * 1000
        print(f"\n  65516B encrypt: {encrypt_ms:.1f}ms, decrypt: {decrypt_ms:.1f}ms")

    @pytest.mark.slow
    def test_max_harness_sha256_integrity(self):
        """Verify SHA-256 for max-harness-size transfer."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(65516)
        expected_hash = hashlib.sha256(payload).hexdigest()
        seq = 42

        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0

        actual_hash = hashlib.sha256(r.stdout).hexdigest()
        assert actual_hash == expected_hash

    @pytest.mark.slow
    def test_max_harness_cross_validation(self):
        """Cross-validate max harness payload between ASM and Python (raw AEAD)."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(65516)
        seq = 7

        # ASM encrypt -> Python decrypt (raw)
        enc = encrypt_asm(k1, k2, seq, payload)
        dec = python_raw_aead_decrypt(enc, k1, k2, seq)
        assert dec == payload, "Max harness ASM->Python mismatch"

    def test_64kb_binary_all_bytes(self):
        """Send 64KB of binary data with all byte values through AEAD."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        # All byte values repeated: 256 * 255 = 65280 bytes (fits in harness)
        payload = bytes(range(256)) * 255
        expected_hash = hashlib.sha256(payload).hexdigest()
        seq = 99

        t0 = time.time()
        encrypted = encrypt_asm(k1, k2, seq, payload)
        r = decrypt_asm(k1, k2, seq, encrypted)
        t1 = time.time()

        assert r.returncode == 0
        actual_hash = hashlib.sha256(r.stdout).hexdigest()
        assert actual_hash == expected_hash
        elapsed_ms = (t1 - t0) * 1000
        print(f"\n  64KB binary roundtrip: {elapsed_ms:.1f}ms")

    def test_70kb_payload_roundtrip(self):
        """Verify 70KB payload encrypts and decrypts correctly after buffer fix."""
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = os.urandom(70000)
        # Encrypt
        inp = (b'e' + k1 + k2 + struct.pack("<I", 0)
               + struct.pack("<I", len(payload)) + payload)
        r = subprocess.run([AEAD_BINARY], input=inp, capture_output=True, timeout=10)
        assert r.returncode == 0, f"Encrypt failed rc={r.returncode}"
        ciphertext = r.stdout
        # Decrypt
        inp2 = (b'd' + k1 + k2 + struct.pack("<I", 0)
                + struct.pack("<I", len(ciphertext)) + ciphertext)
        r2 = subprocess.run([AEAD_BINARY], input=inp2, capture_output=True, timeout=10)
        assert r2.returncode == 0, f"Decrypt failed rc={r2.returncode}"
        assert r2.stdout == payload, "70KB roundtrip data mismatch"


# ============================================================================
# Test 11: PTY Multiple Allocations
# ============================================================================

class TestPTYMultipleAlloc:
    """Verify PTY allocation works repeatedly without leaking fds."""

    def test_10_consecutive_pty_allocs(self):
        """Allocate 10 PTYs consecutively."""
        for i in range(10):
            r = subprocess.run(
                [PTY_BINARY], input=b'p', capture_output=True, timeout=10)
            assert r.returncode == 0, f"PTY alloc {i} failed: rc={r.returncode}"
            assert len(r.stdout) == 8, f"PTY alloc {i} wrong output size: {len(r.stdout)}"
            master_fd = struct.unpack("<i", r.stdout[:4])[0]
            slave_fd = struct.unpack("<i", r.stdout[4:8])[0]
            assert master_fd > 0, f"PTY alloc {i} bad master: {master_fd}"
            assert slave_fd > 0, f"PTY alloc {i} bad slave: {slave_fd}"
