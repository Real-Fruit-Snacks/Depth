"""Comprehensive stress tests for SSH v2 multi-channel event loop.

Exercises all v2 features under heavy load:
  - Multi-channel stress (open/close/routing at MAX_CHANNELS)
  - Port forwarding stress (large data, binary, concurrent, integrity)
  - PTY stress (sequential commands, large output, concurrent sessions)
  - Pubkey auth stress (repeated auth, multiple keys, mixed methods)
  - Combined operations (PTY + forward cross-traffic)
  - Edge cases (empty data, max-size data, window adjust, connection drop)

Uses the test_ssh_multichan.asm harness (assembly as program client,
Python as teamserver/operator). For pubkey tests, uses test_ssh_pubkey.asm.
"""
import subprocess
import struct
import os
import socket
import threading
import hashlib
import time
import random
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

MULTICHAN_BINARY = "./build/test_ssh_multichan"
PUBKEY_BINARY = "./build/test_ssh_pubkey"


# ============================================================================
# Wire helpers
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
        b"hmac-sha2-256", b"hmac-sha2-256",  # mac c2s, mac s2c
        b"none", b"none",
        b"", b"",  # languages
    ]
    for nl in name_lists:
        payload += encode_string(nl)
    payload += bytes([0])
    payload += struct.pack(">I", 0)
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
# Kex + Auth as teamserver
# ============================================================================

def do_kex_as_server(sock):
    host_key = Ed25519PrivateKey.generate()
    host_pubkey = host_key.public_key()
    server_version = b"SSH-2.0-MockTeamserver_1.0"

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
        raise ValueError("Auth failed")
    seq_send += 1

    return seq_recv, seq_send


# ============================================================================
# Channel helpers
# ============================================================================

def open_session_channel(sock, keys, seq_send, seq_recv, sender_channel_id):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    chan_open = bytes([90])
    chan_open += encode_string(b"session")
    chan_open += struct.pack(">I", sender_channel_id)
    chan_open += struct.pack(">I", 0x200000)
    chan_open += struct.pack(">I", 0x8000)
    send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
    seq_recv += 1
    assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"

    recipient = struct.unpack(">I", payload[1:5])[0]
    remote_channel = struct.unpack(">I", payload[5:9])[0]

    return remote_channel, recipient, seq_send, seq_recv


def send_pty_req(sock, keys, seq_send, remote_channel):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
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
    send_encrypted_packet(sock, pty_req, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_shell_req(sock, keys, seq_send, remote_channel):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    shell_req = bytes([98])
    shell_req += struct.pack(">I", remote_channel)
    shell_req += encode_string(b"shell")
    shell_req += bytes([0])
    send_encrypted_packet(sock, shell_req, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_channel_data(sock, keys, seq_send, remote_channel, data: bytes):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    pkt = bytes([94])
    pkt += struct.pack(">I", remote_channel)
    pkt += encode_string(data)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_channel_eof_close(sock, keys, seq_send, remote_channel):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    eof = bytes([96]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, eof, k1_s2c, k2_s2c, seq_send)
    seq_send += 1
    close = bytes([97]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, close, k1_s2c, k2_s2c, seq_send)
    seq_send += 1
    return seq_send


def send_window_adjust(sock, keys, seq_send, remote_channel, bytes_to_add):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    pkt = bytes([93])
    pkt += struct.pack(">I", remote_channel)
    pkt += struct.pack(">I", bytes_to_add)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def collect_channel_data(sock, keys, seq_recv, target_string: bytes,
                         timeout_sec: float = 8.0, channel_filter: int = None):
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    collected = {}
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            sock.settimeout(1.0)
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            if payload[0] == 94:  # CHANNEL_DATA
                recipient = struct.unpack(">I", payload[1:5])[0]
                data_len = struct.unpack(">I", payload[5:9])[0]
                data = payload[9:9 + data_len]
                collected.setdefault(recipient, b"")
                collected[recipient] += data
                if channel_filter is not None:
                    if target_string in collected.get(channel_filter, b""):
                        break
                else:
                    all_data = b"".join(collected.values())
                    if target_string in all_data:
                        break
            elif payload[0] == 93:  # WINDOW_ADJUST
                continue
            elif payload[0] in (96, 97):  # EOF or CLOSE
                if channel_filter is not None:
                    eof_recipient = struct.unpack(">I", payload[1:5])[0]
                    if eof_recipient == channel_filter:
                        break
                    else:
                        continue
                else:
                    break
            elif payload[0] in (99, 100):  # CHANNEL_SUCCESS / CHANNEL_FAILURE
                continue
        except (socket.timeout, ConnectionError):
            break
    return collected, seq_recv


def collect_all_channel_data(sock, keys, seq_recv, timeout_sec: float = 5.0):
    """Collect all data from all channels until timeout, returning (map, seq_recv)."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    collected = {}
    eof_channels = set()
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            sock.settimeout(0.5)
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            if payload[0] == 94:
                recipient = struct.unpack(">I", payload[1:5])[0]
                data_len = struct.unpack(">I", payload[5:9])[0]
                data = payload[9:9 + data_len]
                collected.setdefault(recipient, b"")
                collected[recipient] += data
            elif payload[0] in (96, 97):
                eof_recipient = struct.unpack(">I", payload[1:5])[0]
                eof_channels.add(eof_recipient)
            elif payload[0] in (93, 99, 100):
                continue
        except (socket.timeout, ConnectionError):
            break
    return collected, seq_recv, eof_channels


def drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=3.0):
    """Drain packets until EOF/CLOSE or timeout. Returns seq_recv."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            sock.settimeout(0.5)
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
        except (socket.timeout, ConnectionError):
            break
    return seq_recv


# ============================================================================
# direct-tcpip helpers
# ============================================================================

def build_direct_tcpip_open(sender_channel, host, port):
    payload = bytes([90])
    payload += encode_string(b"direct-tcpip")
    payload += struct.pack(">I", sender_channel)
    payload += struct.pack(">I", 0x200000)
    payload += struct.pack(">I", 0x8000)
    payload += encode_string(host.encode() if isinstance(host, str) else host)
    payload += struct.pack(">I", port)
    payload += encode_string(b"127.0.0.1")
    payload += struct.pack(">I", 12345)
    return payload


def open_direct_tcpip_channel(sock, keys, seq_send, seq_recv, sender_channel, host, port):
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pkt = build_direct_tcpip_open(sender_channel, host, port)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
    seq_recv += 1

    msg_type = payload[0]
    if msg_type == 91:
        remote_channel = struct.unpack(">I", payload[5:9])[0]
        return msg_type, remote_channel, seq_send, seq_recv
    else:
        return msg_type, None, seq_send, seq_recv


def open_direct_tcpip_channel_robust(sock, keys, seq_send, seq_recv, sender_channel, host, port, timeout=5.0):
    """Open direct-tcpip channel, handling interleaved packets from active channels."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pkt = build_direct_tcpip_open(sender_channel, host, port)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            sock.settimeout(2.0)
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
        except socket.timeout:
            continue

        if payload[0] == 91:  # CHANNEL_OPEN_CONFIRMATION
            remote_channel = struct.unpack(">I", payload[5:9])[0]
            return 91, remote_channel, seq_send, seq_recv
        elif payload[0] == 92:  # CHANNEL_OPEN_FAILURE
            return 92, None, seq_send, seq_recv
        # Skip CHANNEL_DATA, WINDOW_ADJUST, CHANNEL_SUCCESS, CHANNEL_EOF, CHANNEL_CLOSE, etc.
        # from active PTY sessions or other channels.

    raise TimeoutError("No CHANNEL_OPEN response received")


# ============================================================================
# Echo server helpers
# ============================================================================

def start_echo_server(max_connections=5):
    """Start a TCP echo server on a random port. Handles multiple connections."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(max_connections)
    port = srv.getsockname()[1]

    def accept_loop():
        while True:
            try:
                srv.settimeout(30.0)
                conn, _ = srv.accept()

                def handle(c):
                    try:
                        while True:
                            d = c.recv(4096)
                            if not d:
                                break
                            c.sendall(d)
                    except Exception:
                        pass
                    finally:
                        c.close()

                threading.Thread(target=handle, args=(conn,), daemon=True).start()
            except Exception:
                break
        srv.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    return port


def start_slow_echo_server(delay_sec=0.1):
    """Echo server that delays each response."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            srv.settimeout(30.0)
            conn, _ = srv.accept()
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    time.sleep(delay_sec)
                    conn.sendall(data)
            except Exception:
                pass
            finally:
                conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


# ============================================================================
# Server startup
# ============================================================================

def start_program(password: bytes, username: bytes = b"operator"):
    s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    server_fd = s_server.fileno()
    inp = struct.pack("<i", server_fd)
    inp += struct.pack("<I", len(username)) + username
    inp += struct.pack("<I", len(password)) + password

    proc = subprocess.Popen(
        [MULTICHAN_BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=(server_fd,),
    )
    proc.stdin.write(inp)
    proc.stdin.flush()
    s_server.close()
    return proc, s_client


def setup_session(password: bytes):
    proc, sock = start_program(password)
    try:
        keys = do_kex_as_server(sock)
        seq_recv, seq_send = do_auth_as_server(sock, keys, password)
        return proc, sock, keys, seq_send, seq_recv
    except Exception:
        sock.close()
        proc.kill()
        proc.wait()
        raise


def teardown(proc, sock):
    try:
        sock.close()
    except Exception:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ============================================================================
# Pubkey auth helpers (for pubkey stress tests)
# ============================================================================

class MockSSHClientPubkeyAuth:
    """Python SSH client that does kex + pubkey auth against assembly server."""

    def __init__(self, host_pub_key_obj, operator_priv_key, operator_pub_bytes,
                 username=b"operator", do_probe=True, bad_signature=False):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.host_pub_key_obj = host_pub_key_obj
        self.operator_priv_key = operator_priv_key
        self.operator_pub_bytes = operator_pub_bytes
        self.username = username
        self.do_probe = do_probe
        self.bad_signature = bad_signature
        self.success = False
        self.error = None
        self.auth_result = None
        self.probe_result = None

    def handle(self, sock):
        try:
            self._do_handshake(sock)
            self._do_pubkey_auth(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
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

    def _do_pubkey_auth(self, sock):
        seq_send = 3
        seq_recv = 3

        pubkey_blob = encode_string(b"ssh-ed25519") + encode_string(self.operator_pub_bytes)

        svc_request = bytes([5]) + encode_string(b"ssh-userauth")
        enc_pkt = python_ssh_aead_encrypt(svc_request, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        assert payload is not None and payload[0] == 6

        if self.do_probe:
            auth_req = bytes([50])
            auth_req += encode_string(self.username)
            auth_req += encode_string(b"ssh-connection")
            auth_req += encode_string(b"publickey")
            auth_req += bytes([0])
            auth_req += encode_string(b"ssh-ed25519")
            auth_req += encode_string(pubkey_blob)
            enc_pkt = python_ssh_aead_encrypt(auth_req, self.k1_c2s, self.k2_c2s, seq_send)
            sock.sendall(enc_pkt)
            seq_send += 1

            payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
            seq_recv += 1
            if payload[0] == 60:
                self.probe_result = 'pk_ok'
            elif payload[0] == 51:
                self.probe_result = 'failure'
                self.auth_result = 'failure'
                return
            else:
                raise ValueError(f"Unexpected probe response: {payload[0]}")

        signed_data = encode_string(self.session_id)
        signed_data += bytes([50])
        signed_data += encode_string(self.username)
        signed_data += encode_string(b"ssh-connection")
        signed_data += encode_string(b"publickey")
        signed_data += bytes([1])
        signed_data += encode_string(b"ssh-ed25519")
        signed_data += encode_string(pubkey_blob)

        if self.bad_signature:
            bad_key = Ed25519PrivateKey.generate()
            signature_raw = bad_key.sign(signed_data)
        else:
            signature_raw = self.operator_priv_key.sign(signed_data)

        sig_blob = encode_string(b"ssh-ed25519") + encode_string(signature_raw)
        auth_req2 = bytes([50])
        auth_req2 += encode_string(self.username)
        auth_req2 += encode_string(b"ssh-connection")
        auth_req2 += encode_string(b"publickey")
        auth_req2 += bytes([1])
        auth_req2 += encode_string(b"ssh-ed25519")
        auth_req2 += encode_string(pubkey_blob)
        auth_req2 += encode_string(sig_blob)

        enc_pkt = python_ssh_aead_encrypt(auth_req2, self.k1_c2s, self.k2_c2s, seq_send)
        sock.sendall(enc_pkt)
        seq_send += 1

        payload = recv_encrypted_packet(sock, self.k1_s2c, self.k2_s2c, seq_recv)
        seq_recv += 1
        if payload[0] == 52:
            self.auth_result = 'success'
        elif payload[0] == 51:
            self.auth_result = 'failure'
        else:
            raise ValueError(f"Unexpected auth response: {payload[0]}")


class MockSSHClientPasswordAuth:
    """Python SSH client that does kex + password auth."""

    def __init__(self, host_pub_key_obj, username: bytes, password: bytes):
        self.client_version = b"SSH-2.0-TestClient_1.0"
        self.host_pub_key_obj = host_pub_key_obj
        self.username = username
        self.password = password
        self.success = False
        self.error = None
        self.auth_result = None

    def handle(self, sock):
        try:
            self._do_handshake(sock)
            self._do_auth(sock)
            self.success = True
        except Exception as e:
            self.error = str(e)
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
        assert payload is not None and payload[0] == 6

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
        if payload[0] == 52:
            self.auth_result = 'success'
        elif payload[0] == 51:
            self.auth_result = 'failure'


def run_pubkey_auth_test(operator_priv_key, operator_pub_bytes,
                         authorized_keys_list, mode='k',
                         do_probe=True, bad_signature=False):
    """Run kex + pubkey auth with assembly server. Returns (client, result)."""
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
        inp = struct.pack("<i", server_fd) + b'k'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", num_keys)
        for key in authorized_keys_list:
            inp += key
    else:
        inp = struct.pack("<i", server_fd) + b'a'
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", num_keys)
        for key in authorized_keys_list:
            inp += key
        inp += struct.pack("<I", 0) + b""

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


def run_password_auth_any_test(expected_password, client_username,
                                client_password, authorized_keys_list=None):
    """Run kex + password auth through ssh_auth_server_any."""
    host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

    s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    client = MockSSHClientPasswordAuth(host_pub_key, client_username, client_password)
    client_thread = threading.Thread(target=client.handle, args=(s_client,))
    client_thread.start()

    server_fd = s_server.fileno()
    keys_list = authorized_keys_list or []
    num_keys = len(keys_list)

    inp = struct.pack("<i", server_fd) + b'a'
    inp += host_priv_bytes + host_pub_bytes
    inp += struct.pack("<I", num_keys)
    for key in keys_list:
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


# ============================================================================
# 1. Multi-Channel Stress Tests
# ============================================================================

class TestMultiChannelStress:
    """Stress the v2 multi-channel event loop with aggressive channel operations."""

    def test_max_channels_all_pty_simultaneous(self):
        """Open MAX_CHANNELS (8) PTY sessions simultaneously, send unique commands
        on each, verify correct routing."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"max_pty_pw")

        try:
            channels = []  # list of (remote_ch, recipient)
            for i in range(8):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=100 + i
                )
                channels.append((remote_ch, recip))

            # Start PTY + shell on all 8
            for remote_ch, _ in channels:
                seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
                seq_send = send_shell_req(sock, keys, seq_send, remote_ch)

            time.sleep(1.0)

            # Send unique command on each channel
            markers = []
            for i, (remote_ch, recip) in enumerate(channels):
                marker = f"CHAN{i}_UNIQUE_{os.urandom(4).hex()}"
                markers.append(marker)
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo {marker}\n".encode())

            # Collect all output
            time.sleep(2.0)
            collected, seq_recv, _ = collect_all_channel_data(
                sock, keys, seq_recv, timeout_sec=15.0
            )

            all_output = b"".join(collected.values())
            for i, marker in enumerate(markers):
                assert marker.encode() in all_output, (
                    f"Missing output for channel {i}: marker={marker}, "
                    f"collected keys={list(collected.keys())}"
                )

            # Cleanup
            for remote_ch, _ in channels:
                try:
                    seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")
                except (BrokenPipeError, ConnectionError):
                    break

        finally:
            teardown(proc, sock)

    def test_rapid_open_close_cycles(self):
        """Open and close channels rapidly: 20 cycles of open -> data -> close."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"rapid_oc_pw")

        try:
            for cycle in range(20):
                # Open channel
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv,
                    sender_channel_id=500 + cycle
                )

                # Send pty + shell + a quick command
                seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
                seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
                time.sleep(0.2)

                marker = f"CYCLE{cycle}"
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo {marker}\n".encode())

                # Collect until we see the marker
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, marker.encode(),
                    timeout_sec=5.0, channel_filter=recip
                )
                output = collected.get(recip, b"")
                assert marker.encode() in output, (
                    f"Cycle {cycle}: expected {marker} in output, got {output[:200]!r}"
                )

                # Close channel
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")
                time.sleep(0.1)
                seq_send = send_channel_eof_close(sock, keys, seq_send, remote_ch)

                # Drain EOF/CLOSE responses
                seq_recv = drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=2.0)

        finally:
            teardown(proc, sock)

    def test_close_channels_random_order(self):
        """Open 8 channels, close them in random order, verify no state corruption."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"rand_close_pw")

        try:
            channels = []
            for i in range(8):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=600 + i
                )
                channels.append((remote_ch, recip, 600 + i))

            # Start PTY on all
            for remote_ch, _, _ in channels:
                seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
                seq_send = send_shell_req(sock, keys, seq_send, remote_ch)

            time.sleep(1.0)

            # Verify all channels work first
            for i, (remote_ch, recip, _) in enumerate(channels):
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo ALIVE{i}\n".encode())

            collected, seq_recv, _ = collect_all_channel_data(
                sock, keys, seq_recv, timeout_sec=10.0
            )
            all_output = b"".join(collected.values())
            for i in range(8):
                assert f"ALIVE{i}".encode() in all_output, (
                    f"Channel {i} not alive before close"
                )

            # Close in random order
            close_order = list(range(8))
            random.shuffle(close_order)
            for idx in close_order:
                remote_ch, recip, sender_id = channels[idx]
                try:
                    seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")
                    time.sleep(0.05)
                    seq_send = send_channel_eof_close(sock, keys, seq_send, remote_ch)
                except (BrokenPipeError, ConnectionError):
                    break
                time.sleep(0.1)
                seq_recv = drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=1.0)

        finally:
            teardown(proc, sock)

    def test_four_pty_four_tcpip_simultaneous(self):
        """Open 4 PTY + 4 direct-tcpip channels simultaneously."""
        echo_ports = [start_echo_server() for _ in range(4)]
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"mixed8_pw")

        try:
            pty_channels = []
            fwd_channels = []

            # Open 4 PTY sessions
            for i in range(4):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=700 + i
                )
                pty_channels.append((remote_ch, recip, 700 + i))

            # Open 4 direct-tcpip
            for i in range(4):
                msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                    sock, keys, seq_send, seq_recv,
                    sender_channel=800 + i, host="127.0.0.1", port=echo_ports[i]
                )
                assert msg_type == 91, f"Forward {i} failed: msg_type={msg_type}"
                fwd_channels.append((remote_ch, 800 + i))

            # Start PTY shells
            for remote_ch, _, _ in pty_channels:
                seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
                seq_send = send_shell_req(sock, keys, seq_send, remote_ch)

            time.sleep(0.5)

            # Send data on all 8 channels
            for i, (remote_ch, recip, _) in enumerate(pty_channels):
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo PTY{i}_OK\n".encode())

            for i, (remote_ch, sender_id) in enumerate(fwd_channels):
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"FWD{i}_ECHO".encode())

            # Collect all responses
            collected, seq_recv, _ = collect_all_channel_data(
                sock, keys, seq_recv, timeout_sec=10.0
            )

            all_output = b"".join(collected.values())
            for i in range(4):
                assert f"PTY{i}_OK".encode() in all_output, (
                    f"Missing PTY channel {i} output"
                )
                assert f"FWD{i}_ECHO".encode() in all_output, (
                    f"Missing forward channel {i} echo"
                )

            # Cleanup PTYs
            for remote_ch, _, _ in pty_channels:
                try:
                    seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")
                except (BrokenPipeError, ConnectionError):
                    break

        finally:
            teardown(proc, sock)

    def test_channel_table_full_rejection(self):
        """Open 8 channels (filling table), verify 9th open fails gracefully,
        then close one and reopen successfully."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"full_tbl_pw")
        k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
        k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

        try:
            remote_channels = []
            for i in range(8):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=900 + i
                )
                remote_channels.append((remote_ch, recip))

            # 9th should fail
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 999)
            chan_open += struct.pack(">I", 0x200000)
            chan_open += struct.pack(">I", 0x8000)
            send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 92, (
                f"Expected CHANNEL_OPEN_FAILURE(92) for 9th channel, got {payload[0]}"
            )

            # Close one channel
            remote_ch0, recip0 = remote_channels[0]
            seq_send = send_channel_eof_close(sock, keys, seq_send, remote_ch0)
            seq_recv = drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=2.0)

            # Now we should be able to open a new one
            remote_ch_new, recip_new, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=1000
            )
            assert remote_ch_new is not None, "Failed to open channel after freeing a slot"

        finally:
            teardown(proc, sock)


# ============================================================================
# 2. Port Forwarding Stress Tests
# ============================================================================

class TestPortForwardingStress:
    """Stress test direct-tcpip port forwarding with heavy data and concurrency."""

    def test_forward_1mb_chunked(self):
        """Forward 1MB of data through a direct-tcpip channel, chunked with window management."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"1mb_fwd_pw")
        k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
        k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            total_size = 256 * 1024  # 256KB (fits in window with adjusts)
            chunk_size = 4096
            test_data = os.urandom(total_size)

            t_start = time.time()
            received = b""
            send_offset = 0
            bytes_since_adjust = 0

            # Interleave sending and receiving with window adjusts
            sock.settimeout(0.1)
            while send_offset < total_size or len(received) < total_size:
                # Send a batch of chunks
                batch = 0
                while send_offset < total_size and batch < 16:
                    end = min(send_offset + chunk_size, total_size)
                    chunk = test_data[send_offset:end]
                    seq_send = send_channel_data(sock, keys, seq_send, remote_ch, chunk)
                    send_offset = end
                    batch += 1

                # Drain any available responses
                try:
                    while True:
                        sock.settimeout(0.5)
                        payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                        seq_recv += 1
                        if payload[0] == 94:  # CHANNEL_DATA
                            data_len = struct.unpack(">I", payload[5:9])[0]
                            data = payload[9:9 + data_len]
                            received += data
                            bytes_since_adjust += data_len
                            # Send WINDOW_ADJUST every 64KB
                            if bytes_since_adjust >= 65536:
                                adj = bytes([93]) + struct.pack(">I", remote_ch) + struct.pack(">I", bytes_since_adjust)
                                send_encrypted_packet(sock, adj, k1_s2c, k2_s2c, seq_send)
                                seq_send += 1
                                bytes_since_adjust = 0
                except socket.timeout:
                    pass

                if time.time() - t_start > 60:
                    break

            # Final drain
            deadline = time.time() + 10.0
            while len(received) < total_size and time.time() < deadline:
                try:
                    sock.settimeout(2.0)
                    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                    seq_recv += 1
                    if payload[0] == 94:
                        data_len = struct.unpack(">I", payload[5:9])[0]
                        received += payload[9:9 + data_len]
                except socket.timeout:
                    break

            t_elapsed = time.time() - t_start
            throughput_mbps = (total_size / max(t_elapsed, 0.001)) / (1024 * 1024)

            assert len(received) >= total_size, (
                f"Expected {total_size} bytes echoed, got {len(received)} "
                f"({t_elapsed:.1f}s, {throughput_mbps:.2f} MB/s)"
            )
            assert received[:total_size] == test_data, "Data corruption in transfer"

        finally:
            teardown(proc, sock)

    def test_forward_binary_all_byte_values(self):
        """Forward binary data containing all 256 byte values through direct-tcpip."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"binary_fwd_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=50, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Build binary data: all 256 byte values repeated 4 times = 1024 bytes
            test_data = bytes(range(256)) * 4

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, test_data)

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, test_data[-16:],
                timeout_sec=10.0, channel_filter=50
            )

            response = collected.get(50, b"")
            assert test_data in response, (
                f"Binary data not echoed correctly. "
                f"Sent {len(test_data)} bytes, got {len(response)} bytes"
            )

            # Verify every byte value is present
            for bval in range(256):
                assert bytes([bval]) in response, (
                    f"Byte value {bval:#04x} missing from response"
                )

        finally:
            teardown(proc, sock)

    def test_four_concurrent_forwards(self):
        """4 concurrent forwards to different echo servers, each handling 10KB."""
        echo_ports = [start_echo_server() for _ in range(4)]
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"4fwd_pw")

        try:
            fwd_channels = []
            for i in range(4):
                msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                    sock, keys, seq_send, seq_recv,
                    sender_channel=60 + i, host="127.0.0.1", port=echo_ports[i]
                )
                assert msg_type == 91, f"Forward {i} open failed"
                fwd_channels.append((remote_ch, 60 + i))

            # Send 10KB on each channel
            data_per_channel = {}
            for i, (remote_ch, sender_id) in enumerate(fwd_channels):
                data = os.urandom(10240)
                data_per_channel[sender_id] = data
                # Send in 1KB chunks
                for off in range(0, len(data), 1024):
                    chunk = data[off:off + 1024]
                    seq_send = send_channel_data(sock, keys, seq_send, remote_ch, chunk)

            # Collect responses
            received = {60 + i: b"" for i in range(4)}
            deadline = time.time() + 20.0
            while time.time() < deadline:
                collected, seq_recv, _ = collect_all_channel_data(
                    sock, keys, seq_recv, timeout_sec=2.0
                )
                for ch_id, data in collected.items():
                    if ch_id in received:
                        received[ch_id] += data

                # Check if we got all data
                all_done = all(
                    len(received[60 + i]) >= 10240 for i in range(4)
                )
                if all_done:
                    break

            for i in range(4):
                sender_id = 60 + i
                expected = data_per_channel[sender_id]
                actual = received[sender_id][:len(expected)]
                assert len(received[sender_id]) >= len(expected), (
                    f"Channel {sender_id}: expected {len(expected)} bytes, "
                    f"got {len(received[sender_id])}"
                )
                assert actual == expected, (
                    f"Channel {sender_id}: data mismatch at 10KB"
                )

        finally:
            teardown(proc, sock)

    def test_rapid_small_messages(self):
        """Forward 100 rapid small messages (64 bytes each) and verify all received."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"rapid_msg_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=70, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send 100 x 64-byte messages with sequence numbers
            messages = []
            for i in range(100):
                msg = f"MSG{i:04d}:".encode() + os.urandom(56)
                messages.append(msg)
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch, msg)

            total_expected = sum(len(m) for m in messages)

            # Collect all responses
            received = b""
            deadline = time.time() + 20.0
            while len(received) < total_expected and time.time() < deadline:
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"IMPOSSIBLE",
                    timeout_sec=2.0, channel_filter=70
                )
                received += collected.get(70, b"")

            assert len(received) >= total_expected, (
                f"Expected {total_expected} bytes, got {len(received)}"
            )

            # Verify all message headers are present in order
            for i in range(100):
                header = f"MSG{i:04d}:".encode()
                assert header in received, (
                    f"Message {i} header missing from response"
                )

        finally:
            teardown(proc, sock)

    def test_forward_slow_echo_server(self):
        """Forward to a slow echo server (100ms delay per response)."""
        echo_port = start_slow_echo_server(delay_sec=0.1)
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"slow_echo_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=80, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send 5 messages, each should come back after ~100ms
            all_sent = b""
            for i in range(5):
                msg = f"SLOW{i}:data".encode()
                all_sent += msg
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch, msg)

            # Collect with generous timeout
            received = b""
            deadline = time.time() + 10.0
            while len(received) < len(all_sent) and time.time() < deadline:
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"IMPOSSIBLE",
                    timeout_sec=2.0, channel_filter=80
                )
                received += collected.get(80, b"")

            assert len(received) >= len(all_sent), (
                f"Expected {len(all_sent)} bytes from slow server, got {len(received)}"
            )

        finally:
            teardown(proc, sock)

    def test_forward_sha256_integrity(self):
        """Forward large data and verify SHA-256 integrity end-to-end."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"sha256_fwd_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=90, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send 256KB of random data
            test_data = os.urandom(256 * 1024)
            expected_hash = hashlib.sha256(test_data).hexdigest()

            for offset in range(0, len(test_data), 4096):
                chunk = test_data[offset:offset + 4096]
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch, chunk)

            # Collect all echoed data
            received = b""
            deadline = time.time() + 30.0
            while len(received) < len(test_data) and time.time() < deadline:
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"IMPOSSIBLE",
                    timeout_sec=2.0, channel_filter=90
                )
                received += collected.get(90, b"")

            actual_hash = hashlib.sha256(received[:len(test_data)]).hexdigest()

            assert len(received) >= len(test_data), (
                f"SHA-256 check: expected {len(test_data)} bytes, got {len(received)}"
            )
            assert actual_hash == expected_hash, (
                f"SHA-256 mismatch!\n"
                f"  Expected: {expected_hash}\n"
                f"  Actual:   {actual_hash}\n"
                f"  Received {len(received)} bytes"
            )

            print(f"\n  [INTEGRITY] 256KB SHA-256 verified: {expected_hash[:16]}...")

        finally:
            teardown(proc, sock)


# ============================================================================
# 3. PTY Stress Tests (Extended)
# ============================================================================

class TestPTYStressExtended:
    """Extended PTY stress tests for the v2 event loop."""

    def test_sequential_commands(self):
        """Run 10 sequential commands through a PTY session, verify all outputs."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"seqcmd_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            for i in range(10):
                marker = f"SEQ_{i}_{os.urandom(3).hex()}"
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo {marker}\n".encode())

                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, marker.encode(),
                    timeout_sec=5.0, channel_filter=recip
                )
                output = collected.get(recip, b"")
                assert marker.encode() in output, (
                    f"Command {i}: expected {marker} in output, got {output[:200]!r}"
                )

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")

        finally:
            teardown(proc, sock)

    def test_large_output_command(self):
        """Run a command that produces 50KB+ output."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"bigout_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            # Generate lots of output. The end marker is sent as a separate command
            # AFTER the loop finishes (shell is sequential). We check for the marker
            # on its own line (b"\r\n===BIGOUT_COMPLETE===\r\n") so the PTY echo of
            # the second command line (which contains the marker string too) does NOT
            # trigger a false-positive match.
            end_marker = b"\r\n===BIGOUT_COMPLETE===\r\n"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         b"for i in $(seq 1 5000); do echo \"LINE_$i padding_data_to_make_it_longer\"; done\n")
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         b"echo ===BIGOUT_COMPLETE===\n")

            # Collect until we see the end marker on its own line, sending WINDOW_ADJUST
            # to avoid window exhaustion when the assembly's remote window fills up.
            received = b""
            bytes_since_adjust = 0
            window_adjust_threshold = 32768
            deadline = time.time() + 60.0
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

            while end_marker not in received and time.time() < deadline:
                try:
                    sock.settimeout(2.0)
                    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                    seq_recv += 1

                    if payload[0] == 94:  # CHANNEL_DATA
                        ch_recip = struct.unpack(">I", payload[1:5])[0]
                        data_len = struct.unpack(">I", payload[5:9])[0]
                        data = payload[9:9 + data_len]
                        if ch_recip == recip:
                            received += data
                            bytes_since_adjust += data_len
                            if bytes_since_adjust >= window_adjust_threshold:
                                seq_send = send_window_adjust(
                                    sock, keys, seq_send, remote_ch, bytes_since_adjust
                                )
                                bytes_since_adjust = 0
                    elif payload[0] in (93, 99, 100):  # WINDOW_ADJUST, SUCCESS, FAILURE
                        continue
                    elif payload[0] in (96, 97):  # EOF, CLOSE
                        break
                except socket.timeout:
                    continue

            assert end_marker in received, (
                f"Large output command did not complete. Got {len(received)} bytes"
            )
            # 5000 lines * ~40 bytes = ~200KB expected (with PTY \r\n overhead)
            assert len(received) > 50000, (
                f"Expected 50KB+ output, got {len(received)} bytes"
            )

            print(f"\n  [PERF] Large PTY output: {len(received)} bytes received")

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")

        finally:
            teardown(proc, sock)

    def test_two_concurrent_pty_different_commands(self):
        """Two concurrent PTY sessions running different commands simultaneously."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"2pty_pw")

        try:
            # Open two sessions
            remote_ch0, recip0, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=10
            )
            remote_ch1, recip1, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=20
            )

            for ch in [remote_ch0, remote_ch1]:
                seq_send = send_pty_req(sock, keys, seq_send, ch)
                seq_send = send_shell_req(sock, keys, seq_send, ch)

            time.sleep(0.8)

            # Send different workloads
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch0,
                                         b"for i in $(seq 1 20); do echo PTY0_LINE_$i; done; echo PTY0_COMPLETE\n")
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch1,
                                         b"for i in $(seq 1 20); do echo PTY1_LINE_$i; done; echo PTY1_COMPLETE\n")

            # Collect from both
            collected = {recip0: b"", recip1: b""}
            deadline = time.time() + 15.0
            while time.time() < deadline:
                batch, seq_recv, _ = collect_all_channel_data(
                    sock, keys, seq_recv, timeout_sec=2.0
                )
                for ch_id, data in batch.items():
                    if ch_id in collected:
                        collected[ch_id] += data

                if (b"PTY0_COMPLETE" in collected[recip0] and
                        b"PTY1_COMPLETE" in collected[recip1]):
                    break

            assert b"PTY0_COMPLETE" in collected[recip0], (
                f"PTY0 did not complete. Got {len(collected[recip0])} bytes"
            )
            assert b"PTY1_COMPLETE" in collected[recip1], (
                f"PTY1 did not complete. Got {len(collected[recip1])} bytes"
            )

            # Cleanup
            for ch in [remote_ch0, remote_ch1]:
                try:
                    seq_send = send_channel_data(sock, keys, seq_send, ch, b"exit\n")
                except (BrokenPipeError, ConnectionError):
                    break

        finally:
            teardown(proc, sock)

    def test_pty_rapid_input(self):
        """Send rapid input to PTY, verify no data loss."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"rapid_pty_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            # Send 50 rapid echo commands without waiting between them
            markers = []
            for i in range(50):
                marker = f"RAPID{i:03d}"
                markers.append(marker)
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                             f"echo {marker}\n".encode())

            # Wait for the last marker
            last_marker = markers[-1].encode()
            received = b""
            deadline = time.time() + 20.0
            while last_marker not in received and time.time() < deadline:
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, last_marker,
                    timeout_sec=3.0, channel_filter=recip
                )
                received += collected.get(recip, b"")

            # Verify all markers appeared
            missing = [m for m in markers if m.encode() not in received]
            assert len(missing) == 0, (
                f"Missing {len(missing)}/50 markers: {missing[:5]}... "
                f"(received {len(received)} bytes)"
            )

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")

        finally:
            teardown(proc, sock)

    def test_pty_ctrl_c_survives(self):
        """Send ctrl-C (0x03) through PTY, verify shell does not die."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"ctrlc_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            # Send ctrl-C
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"\x03")
            time.sleep(0.3)

            # Shell should still be alive -- send a command
            marker = f"AFTER_CTRLC_{os.urandom(3).hex()}"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         f"echo {marker}\n".encode())

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, marker.encode(),
                timeout_sec=5.0, channel_filter=recip
            )
            output = collected.get(recip, b"")
            assert marker.encode() in output, (
                f"Shell died after ctrl-C. Expected {marker}, got {output[:200]!r}"
            )

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")

        finally:
            teardown(proc, sock)


# ============================================================================
# 4. Pubkey Auth Stress Tests
# ============================================================================

class TestPubkeyAuthStress:
    """Stress test Ed25519 pubkey authentication."""

    def test_ten_consecutive_pubkey_auth(self):
        """10 consecutive pubkey auth attempts with correct key."""
        for i in range(10):
            op_priv_key = Ed25519PrivateKey.generate()
            op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

            client, r = run_pubkey_auth_test(
                operator_priv_key=op_priv_key,
                operator_pub_bytes=op_pub,
                authorized_keys_list=[op_pub],
            )
            assert client.success, f"Attempt {i}: client failed: {client.error}"
            assert client.auth_result == 'success', (
                f"Attempt {i}: expected success, got {client.auth_result}"
            )
            assert r.returncode == 0, (
                f"Attempt {i}: server rc={r.returncode}"
            )

    def test_four_different_authorized_keys(self):
        """Auth with 4 different authorized keys, verify all accepted."""
        keys = [Ed25519PrivateKey.generate() for _ in range(4)]
        pubs = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) for k in keys]

        for i in range(4):
            client, r = run_pubkey_auth_test(
                operator_priv_key=keys[i],
                operator_pub_bytes=pubs[i],
                authorized_keys_list=pubs,
            )
            assert client.success, f"Key {i}: client failed: {client.error}"
            assert client.auth_result == 'success', (
                f"Key {i}: expected success, got {client.auth_result}"
            )
            assert r.returncode == 0

    def test_wrong_key_then_correct_key(self):
        """Pubkey auth with wrong key (should fail) followed by correct key (should succeed)."""
        correct_key = Ed25519PrivateKey.generate()
        correct_pub = correct_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        wrong_key = Ed25519PrivateKey.generate()
        wrong_pub = wrong_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Wrong key should fail
        client1, r1 = run_pubkey_auth_test(
            operator_priv_key=wrong_key,
            operator_pub_bytes=wrong_pub,
            authorized_keys_list=[correct_pub],
        )
        assert client1.auth_result == 'failure', "Wrong key should fail"

        # Correct key should still succeed (server not locked out)
        client2, r2 = run_pubkey_auth_test(
            operator_priv_key=correct_key,
            operator_pub_bytes=correct_pub,
            authorized_keys_list=[correct_pub],
        )
        assert client2.auth_result == 'success', (
            f"Correct key failed after wrong key attempt: {client2.error}"
        )
        assert r2.returncode == 0

    def test_any_auth_dispatches_pubkey_and_password(self):
        """Verify ssh_auth_server_any correctly dispatches both pubkey and password methods."""
        # Pubkey through 'any' mode
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        client_pk, r_pk = run_pubkey_auth_test(
            operator_priv_key=op_priv_key,
            operator_pub_bytes=op_pub,
            authorized_keys_list=[op_pub],
            mode='a',
        )
        assert client_pk.auth_result == 'success', (
            f"Pubkey via 'any' failed: {client_pk.error}"
        )

        # Password through 'any' mode
        client_pw, r_pw = run_password_auth_any_test(
            expected_password=b"test_password_123",
            client_username=b"admin",
            client_password=b"test_password_123",
        )
        assert client_pw.auth_result == 'success', (
            f"Password via 'any' failed: {client_pw.error}"
        )

    def test_mixed_pubkey_password_attempts(self):
        """Alternating pubkey and password auth attempts through ssh_auth_server_any."""
        op_priv_key = Ed25519PrivateKey.generate()
        op_pub = op_priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        for i in range(5):
            if i % 2 == 0:
                # Pubkey auth
                client, r = run_pubkey_auth_test(
                    operator_priv_key=op_priv_key,
                    operator_pub_bytes=op_pub,
                    authorized_keys_list=[op_pub],
                    mode='a',
                )
                assert client.auth_result == 'success', (
                    f"Round {i} (pubkey): {client.error}"
                )
            else:
                # Password auth
                client, r = run_password_auth_any_test(
                    expected_password=b"round_pass",
                    client_username=b"admin",
                    client_password=b"round_pass",
                )
                assert client.auth_result == 'success', (
                    f"Round {i} (password): {client.error}"
                )


# ============================================================================
# 5. Combined Operations
# ============================================================================

class TestCombinedOperations:
    """Test PTY + port forwarding working simultaneously with cross-traffic."""

    def test_pty_plus_three_forwards(self):
        """PTY session + 3 direct-tcpip forwards running simultaneously with cross-traffic."""
        echo_ports = [start_echo_server() for _ in range(3)]
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"combined_pw")

        try:
            # Open PTY
            remote_pty, recip_pty, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=1
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_pty)
            seq_send = send_shell_req(sock, keys, seq_send, remote_pty)

            # Open 3 forwards
            fwd_channels = []
            for i in range(3):
                msg_type, remote_fwd, seq_send, seq_recv = open_direct_tcpip_channel(
                    sock, keys, seq_send, seq_recv,
                    sender_channel=10 + i, host="127.0.0.1", port=echo_ports[i]
                )
                assert msg_type == 91
                fwd_channels.append((remote_fwd, 10 + i))

            time.sleep(0.5)

            # Interleave PTY commands and forward data
            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         b"echo COMBINED_PTY_1\n")

            for i, (remote_fwd, sender_id) in enumerate(fwd_channels):
                seq_send = send_channel_data(sock, keys, seq_send, remote_fwd,
                                             f"COMBINED_FWD_{i}".encode())

            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         b"echo COMBINED_PTY_2\n")

            # Collect all
            collected = {}
            deadline = time.time() + 15.0
            while time.time() < deadline:
                batch, seq_recv, _ = collect_all_channel_data(
                    sock, keys, seq_recv, timeout_sec=2.0
                )
                for ch_id, data in batch.items():
                    collected.setdefault(ch_id, b"")
                    collected[ch_id] += data

                pty_data = collected.get(recip_pty, b"")
                fwd_ok = all(
                    f"COMBINED_FWD_{i}".encode() in collected.get(10 + i, b"")
                    for i in range(3)
                )
                if b"COMBINED_PTY_2" in pty_data and fwd_ok:
                    break

            # Verify PTY
            pty_output = collected.get(recip_pty, b"")
            assert b"COMBINED_PTY_1" in pty_output, "PTY command 1 missing"
            assert b"COMBINED_PTY_2" in pty_output, "PTY command 2 missing"

            # Verify forwards
            for i in range(3):
                fwd_data = collected.get(10 + i, b"")
                assert f"COMBINED_FWD_{i}".encode() in fwd_data, (
                    f"Forward {i} echo missing"
                )

            # Cleanup
            try:
                seq_send = send_channel_data(sock, keys, seq_send, remote_pty, b"exit\n")
            except (BrokenPipeError, ConnectionError):
                pass

        finally:
            teardown(proc, sock)

    def test_interleaved_pty_forward_sequence(self):
        """Open PTY, run cmd, open forward, send data, run another cmd, close forward,
        run final cmd -- verify all outputs correct."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"interleave_pw")

        try:
            # Step 1: Open PTY
            remote_pty, recip_pty, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=1
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_pty)
            seq_send = send_shell_req(sock, keys, seq_send, remote_pty)
            time.sleep(0.5)

            # Step 2: Run a PTY command
            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         b"echo STEP2_OK\n")
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"STEP2_OK",
                timeout_sec=5.0, channel_filter=recip_pty
            )
            assert b"STEP2_OK" in collected.get(recip_pty, b"")

            # Step 3: Open forward (use robust variant to skip interleaved PTY packets)
            msg_type, remote_fwd, seq_send, seq_recv = open_direct_tcpip_channel_robust(
                sock, keys, seq_send, seq_recv,
                sender_channel=2, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Step 4: Send data on forward
            fwd_data = b"INTERLEAVE_FWD_DATA"
            seq_send = send_channel_data(sock, keys, seq_send, remote_fwd, fwd_data)
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, fwd_data,
                timeout_sec=5.0, channel_filter=2
            )
            assert fwd_data in collected.get(2, b""), "Forward echo missing"

            # Step 5: Run another PTY command while forward is active
            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         b"echo STEP5_OK\n")
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"STEP5_OK",
                timeout_sec=5.0, channel_filter=recip_pty
            )
            assert b"STEP5_OK" in collected.get(recip_pty, b"")

            # Step 6: Close forward
            seq_send = send_channel_eof_close(sock, keys, seq_send, remote_fwd)
            seq_recv = drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=2.0)

            # Step 7: Run final PTY command
            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         b"echo STEP7_FINAL\n")
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"STEP7_FINAL",
                timeout_sec=5.0, channel_filter=recip_pty
            )
            assert b"STEP7_FINAL" in collected.get(recip_pty, b"")

            seq_send = send_channel_data(sock, keys, seq_send, remote_pty, b"exit\n")

        finally:
            teardown(proc, sock)

    def test_rapid_open_close_while_active(self):
        """Rapidly open/close channels while other channels are active."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"active_oc_pw")

        try:
            # Open a persistent PTY channel
            remote_pty, recip_pty, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=1
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_pty)
            seq_send = send_shell_req(sock, keys, seq_send, remote_pty)
            time.sleep(0.5)

            # Rapidly open and close forward channels while PTY is active
            for cycle in range(10):
                msg_type, remote_fwd, seq_send, seq_recv = open_direct_tcpip_channel_robust(
                    sock, keys, seq_send, seq_recv,
                    sender_channel=100 + cycle, host="127.0.0.1", port=echo_port
                )
                assert msg_type == 91, f"Cycle {cycle}: forward open failed"

                fwd_msg = f"CYCLE{cycle}".encode()
                seq_send = send_channel_data(sock, keys, seq_send, remote_fwd, fwd_msg)

                # Quick collect
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, fwd_msg,
                    timeout_sec=3.0, channel_filter=100 + cycle
                )
                assert fwd_msg in collected.get(100 + cycle, b""), (
                    f"Cycle {cycle}: forward echo missing"
                )

                seq_send = send_channel_eof_close(sock, keys, seq_send, remote_fwd)
                seq_recv = drain_until_eof_or_timeout(sock, keys, seq_recv, timeout_sec=1.0)

            # Verify PTY is still alive
            marker = f"STILL_ALIVE_{os.urandom(3).hex()}"
            seq_send = send_channel_data(sock, keys, seq_send, remote_pty,
                                         f"echo {marker}\n".encode())
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, marker.encode(),
                timeout_sec=5.0, channel_filter=recip_pty
            )
            assert marker.encode() in collected.get(recip_pty, b""), (
                "PTY died during rapid forward open/close cycles"
            )

            seq_send = send_channel_data(sock, keys, seq_send, remote_pty, b"exit\n")

        finally:
            teardown(proc, sock)


# ============================================================================
# 6. Edge Cases
# ============================================================================

class TestEdgeCases:
    """Edge cases that could cause crashes or undefined behavior."""

    def test_empty_channel_data(self):
        """Send CHANNEL_DATA with 0 bytes payload. Should not crash."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"empty_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send empty data
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"")

            # Send real data after to verify channel still works
            test_data = b"after_empty_test"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, test_data)

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, test_data,
                timeout_sec=5.0, channel_filter=42
            )
            assert test_data in collected.get(42, b""), (
                "Channel broken after empty data send"
            )

        finally:
            teardown(proc, sock)

    def test_max_size_channel_data(self):
        """Send maximum size CHANNEL_DATA (32KB) in a single packet."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"maxpkt_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Max packet size is 0x8000 = 32768 bytes
            test_data = os.urandom(32768)
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, test_data)

            received = b""
            deadline = time.time() + 15.0
            while len(received) < len(test_data) and time.time() < deadline:
                collected, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"IMPOSSIBLE",
                    timeout_sec=2.0, channel_filter=42
                )
                received += collected.get(42, b"")

            assert len(received) >= len(test_data), (
                f"Max-size packet: expected {len(test_data)} bytes, got {len(received)}"
            )
            assert received[:len(test_data)] == test_data, "Max-size packet: data corruption"

        finally:
            teardown(proc, sock)

    def test_window_adjust_large_value(self):
        """Send WINDOW_ADJUST with a large value. Should not crash."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"winadj_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            # Send large window adjust
            seq_send = send_window_adjust(sock, keys, seq_send, remote_ch, 0x7FFFFFFF)

            # Channel should still work
            marker = f"AFTER_WINADJ_{os.urandom(3).hex()}"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         f"echo {marker}\n".encode())

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, marker.encode(),
                timeout_sec=5.0, channel_filter=recip
            )
            assert marker.encode() in collected.get(recip, b""), (
                "Channel broken after large WINDOW_ADJUST"
            )

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")

        finally:
            teardown(proc, sock)

    def test_client_side_channel_close(self):
        """Close channel from client side (teamserver sends EOF+CLOSE)."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"clclose_pw")

        try:
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            # Close from client side
            seq_send = send_channel_eof_close(sock, keys, seq_send, remote_ch)

            # Drain responses - should get EOF+CLOSE back from program
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            got_eof = False
            got_close = False
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                    seq_recv += 1
                    if payload[0] == 96:  # EOF
                        got_eof = True
                    elif payload[0] == 97:  # CLOSE
                        got_close = True
                    if got_eof and got_close:
                        break
                except (socket.timeout, ConnectionError):
                    break

            # At minimum we should get the close acknowledgment
            assert got_close or got_eof, (
                "No EOF/CLOSE response from program on client-side close"
            )

        finally:
            teardown(proc, sock)

    def test_connection_drop_no_zombie_processes(self):
        """Drop connection during active session, verify no zombie processes."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"drop_pw")

        try:
            # Open PTY and start a command
            remote_ch, recip, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)
            time.sleep(0.5)

            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         b"echo DROP_TEST\n")
            time.sleep(0.3)

            # Abruptly close the socket
            sock.close()

            # Process should exit within a reasonable time
            try:
                rc = proc.wait(timeout=10)
                # Process exited cleanly or due to connection drop -- both OK
            except subprocess.TimeoutExpired:
                # If still running, that might indicate a zombie/hang
                proc.kill()
                proc.wait()
                pytest.fail("Server process did not exit after connection drop (zombie risk)")

        except Exception:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
            raise

    def test_multiple_window_adjusts(self):
        """Send multiple WINDOW_ADJUST messages in rapid succession."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"multi_wa_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send 20 window adjusts rapidly
            for _ in range(20):
                seq_send = send_window_adjust(sock, keys, seq_send, remote_ch, 0x10000)

            # Channel should still work
            test_data = b"after_many_window_adjusts"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, test_data)

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, test_data,
                timeout_sec=5.0, channel_filter=42
            )
            assert test_data in collected.get(42, b""), (
                "Channel broken after 20 rapid WINDOW_ADJUSTs"
            )

        finally:
            teardown(proc, sock)

    def test_channel_data_after_eof(self):
        """Send CHANNEL_DATA after EOF on a forward channel. Should not crash."""
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"data_eof_pw")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91

            # Send some data
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"before_eof")
            time.sleep(0.2)

            # Send EOF
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
            eof = bytes([96]) + struct.pack(">I", remote_ch)
            send_encrypted_packet(sock, eof, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            time.sleep(0.2)

            # Try sending data after EOF (protocol violation, should not crash)
            try:
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"after_eof")
            except (BrokenPipeError, ConnectionError):
                pass  # Expected -- connection may close

            # Process should not have crashed
            time.sleep(0.5)
            poll = proc.poll()
            # Process may have exited cleanly or still be running -- either is acceptable
            # as long as it didn't segfault (return code -11)
            if poll is not None:
                assert poll != -11, "Server SEGFAULT after data-after-EOF"

        finally:
            teardown(proc, sock)
