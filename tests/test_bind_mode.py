"""Integration tests: Bind mode (assembly acts as SSH server).

Python connects TO the assembly binary's listen port as an SSH client.
The assembly side runs kex_server + auth_server_any + event_loop_v2.

Test flow:
  1. Start assembly bind-mode harness (listens on a port)
  2. Python connects as SSH client
  3. Python does kex as client + auth as client
  4. Python sends CHANNEL_OPEN, pty-req, shell, commands
  5. Verify responses
"""
import subprocess
import struct
import os
import socket
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

BIND_BINARY = "./build/test_bind_mode"


# ---- Wire helpers (same as test_ssh_multichan.py) ----

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


# ---- Kex as CLIENT (Python connects to assembly server) ----

def do_kex_as_client(sock, host_pub_bytes):
    """
    Run full SSH kex as Python CLIENT against assembly SSH SERVER.
    The assembly server sends its version first, then we exchange kexinit, etc.

    In the assembly server (ssh_kex_server):
      - Server sends version
      - Client (us) sends version
      - Server sends KEXINIT
      - Client sends KEXINIT
      - Client sends ECDH_INIT
      - Server sends ECDH_REPLY
      - Server sends NEWKEYS
      - Client sends NEWKEYS

    Returns keys dict with c2s/s2c keys from the CLIENT's perspective.
    """
    client_version = b"SSH-2.0-TestClient_1.0"

    # Version exchange: server sends first
    server_version_line = b""
    while not server_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        server_version_line += b
    server_version = server_version_line.rstrip(b"\r\n")

    # Client sends version
    sock.sendall(client_version + b"\r\n")

    # Server sends KEXINIT first
    server_kexinit = recv_plain_packet(sock)
    assert server_kexinit[0] == 20, f"Expected KEXINIT(20), got {server_kexinit[0]}"

    # Client sends KEXINIT
    client_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(client_kexinit))

    # Client sends ECDH_INIT
    client_ephem_priv = X25519PrivateKey.generate()
    client_ephem_pub = client_ephem_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
    sock.sendall(build_plain_packet(ecdh_init))

    # Server sends ECDH_REPLY
    ecdh_reply = recv_plain_packet(sock)
    assert ecdh_reply[0] == 31, f"Expected ECDH_REPLY(31), got {ecdh_reply[0]}"

    # Parse ECDH_REPLY: [byte 31][string host_key_blob][string server_ephem_pub][string sig_blob]
    offset = 1
    host_key_blob_len = struct.unpack(">I", ecdh_reply[offset:offset+4])[0]
    offset += 4
    host_key_blob = ecdh_reply[offset:offset+host_key_blob_len]
    offset += host_key_blob_len

    server_ephem_pub_len = struct.unpack(">I", ecdh_reply[offset:offset+4])[0]
    offset += 4
    server_ephem_pub = ecdh_reply[offset:offset+server_ephem_pub_len]
    offset += server_ephem_pub_len

    sig_blob_len = struct.unpack(">I", ecdh_reply[offset:offset+4])[0]
    offset += 4
    sig_blob = ecdh_reply[offset:offset+sig_blob_len]

    # Compute shared secret
    server_x25519_pub = X25519PublicKey.from_public_bytes(server_ephem_pub)
    shared_secret = client_ephem_priv.exchange(server_x25519_pub)

    # Compute exchange hash H
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

    # Verify host key signature
    # Parse host_key_blob to get the raw public key
    # host_key_blob = string("ssh-ed25519") + string(pubkey_32)
    hk_offset = 0
    hk_type_len = struct.unpack(">I", host_key_blob[hk_offset:hk_offset+4])[0]
    hk_offset += 4 + hk_type_len
    hk_pub_len = struct.unpack(">I", host_key_blob[hk_offset:hk_offset+4])[0]
    hk_offset += 4
    host_raw_pub = host_key_blob[hk_offset:hk_offset+hk_pub_len]

    # Verify it matches expected host key
    assert host_raw_pub == host_pub_bytes, "Host key mismatch"

    # Parse sig_blob = string("ssh-ed25519") + string(signature_64)
    sig_offset = 0
    sig_type_len = struct.unpack(">I", sig_blob[sig_offset:sig_offset+4])[0]
    sig_offset += 4 + sig_type_len
    sig_raw_len = struct.unpack(">I", sig_blob[sig_offset:sig_offset+4])[0]
    sig_offset += 4
    sig_raw = sig_blob[sig_offset:sig_offset+sig_raw_len]

    # Verify signature
    host_pub_key = Ed25519PublicKey.from_public_bytes(host_pub_bytes)
    host_pub_key.verify(sig_raw, H)  # raises on failure

    # Derive keys
    # From client perspective:
    #   c2s keys = letter 'C' (0x43) — what WE send
    #   s2c keys = letter 'D' (0x44) — what SERVER sends
    k1_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[:32]
    k2_c2s = derive_key_64(K_mpint, H, 0x43, session_id)[32:]
    k1_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[:32]
    k2_s2c = derive_key_64(K_mpint, H, 0x44, session_id)[32:]

    # Server sends NEWKEYS first
    server_newkeys = recv_plain_packet(sock)
    assert server_newkeys == bytes([21]), f"Expected NEWKEYS, got {server_newkeys!r}"

    # Client sends NEWKEYS
    sock.sendall(build_plain_packet(bytes([21])))

    return {
        'k1_c2s': k1_c2s, 'k2_c2s': k2_c2s,
        'k1_s2c': k1_s2c, 'k2_s2c': k2_s2c,
        'session_id': session_id,
    }


def do_auth_as_client(sock, keys, username: bytes, password: bytes):
    """
    Run password auth as Python CLIENT against assembly SSH SERVER.
    Returns (seq_send, seq_recv) after auth completes.

    Note: In bind mode, assembly is SERVER. So:
      - We SEND with c2s keys (client-to-server)
      - We RECEIVE with s2c keys (server-to-client)
    """
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    seq_send = 3  # our send seq (c2s, after 3 plaintext pkts)
    seq_recv = 3  # our recv seq (s2c, after 3 plaintext pkts)

    # Send SSH_MSG_SERVICE_REQUEST for "ssh-userauth"
    svc_req = bytes([5]) + encode_string(b"ssh-userauth")
    send_encrypted_packet(sock, svc_req, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    # Receive SSH_MSG_SERVICE_ACCEPT
    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
    seq_recv += 1
    assert payload[0] == 6, f"Expected SERVICE_ACCEPT(6), got {payload[0]}"

    # Send USERAUTH_REQUEST with password
    auth_req = bytes([50])
    auth_req += encode_string(username)
    auth_req += encode_string(b"ssh-connection")
    auth_req += encode_string(b"password")
    auth_req += bytes([0])  # FALSE (no old password)
    auth_req += encode_string(password)
    send_encrypted_packet(sock, auth_req, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    # Receive USERAUTH_SUCCESS or FAILURE
    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
    seq_recv += 1
    assert payload[0] == 52, f"Expected USERAUTH_SUCCESS(52), got {payload[0]}"

    return seq_send, seq_recv


# ---- Channel helpers (we are the client sending to server) ----

def open_session_channel_as_client(sock, keys, seq_send, seq_recv, sender_channel_id):
    """Open a session channel. We send with c2s, receive with s2c."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

    chan_open = bytes([90])
    chan_open += encode_string(b"session")
    chan_open += struct.pack(">I", sender_channel_id)
    chan_open += struct.pack(">I", 0x200000)  # window = 2MB
    chan_open += struct.pack(">I", 0x8000)    # max packet = 32KB
    send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    # Receive CHANNEL_OPEN_CONFIRMATION
    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
    seq_recv += 1
    assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"

    recipient = struct.unpack(">I", payload[1:5])[0]
    remote_channel = struct.unpack(">I", payload[5:9])[0]

    return remote_channel, recipient, seq_send, seq_recv


def send_pty_req_as_client(sock, keys, seq_send, remote_channel):
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pty_req = bytes([98])
    pty_req += struct.pack(">I", remote_channel)
    pty_req += encode_string(b"pty-req")
    pty_req += bytes([0])  # want_reply = false
    pty_req += encode_string(b"xterm-256color")
    pty_req += struct.pack(">I", 80)
    pty_req += struct.pack(">I", 24)
    pty_req += struct.pack(">I", 640)
    pty_req += struct.pack(">I", 480)
    pty_req += encode_string(b"")
    send_encrypted_packet(sock, pty_req, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def send_shell_req_as_client(sock, keys, seq_send, remote_channel):
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    shell_req = bytes([98])
    shell_req += struct.pack(">I", remote_channel)
    shell_req += encode_string(b"shell")
    shell_req += bytes([0])  # want_reply = false
    send_encrypted_packet(sock, shell_req, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def send_channel_data_as_client(sock, keys, seq_send, remote_channel, data: bytes):
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pkt = bytes([94])
    pkt += struct.pack(">I", remote_channel)
    pkt += encode_string(data)
    send_encrypted_packet(sock, pkt, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def send_channel_eof_close_as_client(sock, keys, seq_send, remote_channel):
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    eof = bytes([96]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, eof, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    close = bytes([97]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, close, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    return seq_send


def collect_channel_data_as_client(sock, keys, seq_recv, target_string: bytes,
                                    timeout_sec: float = 8.0, channel_filter: int = None):
    """Read encrypted packets (s2c direction), collecting CHANNEL_DATA."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

    collected = {}
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            sock.settimeout(1.0)
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
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
                    continue
                break
            elif payload[0] in (99, 100):  # SUCCESS/FAILURE
                continue
        except (socket.timeout, ConnectionError):
            break

    return collected, seq_recv


# ---- Start assembly bind-mode harness ----

def find_free_port():
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_bind_server(password: bytes, port: int = None):
    """
    Start the assembly bind-mode harness.
    Returns (proc, port, host_pub_bytes).
    """
    if port is None:
        port = find_free_port()

    # Generate Ed25519 host keypair
    host_priv_key = Ed25519PrivateKey.generate()
    host_pub_key = host_priv_key.public_key()
    host_priv_bytes = host_priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    host_pub_bytes = host_pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Input: port(2 LE) + host_private(32) + host_public(32) + pass_len(4 LE) + password
    inp = struct.pack("<H", port)
    inp += host_priv_bytes + host_pub_bytes
    inp += struct.pack("<I", len(password)) + password

    proc = subprocess.Popen(
        [BIND_BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.stdin.write(inp)
    proc.stdin.flush()

    # Wait for "LISTENING\n" on stdout
    ready = b""
    deadline = time.time() + 10
    while time.time() < deadline:
        proc.stdout.flush()
        try:
            ch = proc.stdout.read(1)
            if not ch:
                break
            ready += ch
            if ready.endswith(b"\n"):
                break
        except Exception:
            break

    assert b"LISTENING" in ready, (
        f"Server didn't become ready. Got: {ready!r}, "
        f"stderr: server may still be starting"
    )

    return proc, port, host_pub_bytes


def connect_and_setup(port, host_pub_bytes, password: bytes, username: bytes = b"operator"):
    """Connect to the bind server, do kex + auth. Returns (sock, keys, seq_send, seq_recv)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(('127.0.0.1', port))

    keys = do_kex_as_client(sock, host_pub_bytes)
    seq_send, seq_recv = do_auth_as_client(sock, keys, username, password)

    return sock, keys, seq_send, seq_recv


# ============================================================================
# Tests
# ============================================================================

class TestBindMode:
    """Test bind mode: assembly listens, Python connects."""

    def test_bind_connect_kex_auth(self):
        """Connect to bind server, complete kex + auth, then disconnect."""
        proc, port, host_pub = start_bind_server(b"bind_pw_1")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"bind_pw_1"
            )
            # Auth succeeded — just close
            sock.close()
        finally:
            proc.kill()
            proc.wait()

    def test_bind_pty_session(self):
        """Connect, kex, auth, open channel, pty-req, shell, echo command."""
        proc, port, host_pub = start_bind_server(b"bind_pw_2")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"bind_pw_2"
            )

            # Open session channel
            remote_ch, recipient, seq_send, seq_recv = open_session_channel_as_client(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )

            # pty-req + shell
            seq_send = send_pty_req_as_client(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req_as_client(sock, keys, seq_send, remote_ch)

            time.sleep(0.5)

            # Send command
            seq_send = send_channel_data_as_client(
                sock, keys, seq_send, remote_ch, b"echo bind_mode_works\n"
            )

            # Collect output
            collected, seq_recv = collect_channel_data_as_client(
                sock, keys, seq_recv, b"bind_mode_works", timeout_sec=8.0,
                channel_filter=recipient
            )

            output = collected.get(recipient, b"").decode('utf-8', errors='replace')
            assert 'bind_mode_works' in output, (
                f"Expected 'bind_mode_works' in output, got: {output!r}"
            )

            # Exit shell
            try:
                seq_send = send_channel_data_as_client(
                    sock, keys, seq_send, remote_ch, b"exit\n"
                )
            except (BrokenPipeError, ConnectionError):
                pass
            time.sleep(0.5)

            sock.close()
        finally:
            proc.kill()
            proc.wait()

    def test_bind_sequential_connections(self):
        """Three sequential connect/session/disconnect cycles to same server."""
        proc, port, host_pub = start_bind_server(b"bind_pw_3")

        try:
            for i in range(3):
                sock, keys, seq_send, seq_recv = connect_and_setup(
                    port, host_pub, b"bind_pw_3"
                )

                # Open channel
                remote_ch, recipient, seq_send, seq_recv = open_session_channel_as_client(
                    sock, keys, seq_send, seq_recv, sender_channel_id=i
                )

                # pty-req + shell
                seq_send = send_pty_req_as_client(sock, keys, seq_send, remote_ch)
                seq_send = send_shell_req_as_client(sock, keys, seq_send, remote_ch)

                time.sleep(0.5)

                # Send a unique command for this iteration
                marker = f"seq_conn_{i}_ok"
                seq_send = send_channel_data_as_client(
                    sock, keys, seq_send, remote_ch,
                    f"echo {marker}\n".encode()
                )

                collected, seq_recv = collect_channel_data_as_client(
                    sock, keys, seq_recv, marker.encode(), timeout_sec=8.0,
                    channel_filter=recipient
                )

                output = collected.get(recipient, b"").decode('utf-8', errors='replace')
                assert marker in output, (
                    f"Connection {i}: Expected '{marker}' in output, got: {output!r}"
                )

                # Exit and disconnect
                try:
                    seq_send = send_channel_data_as_client(
                        sock, keys, seq_send, remote_ch, b"exit\n"
                    )
                except (BrokenPipeError, ConnectionError):
                    pass
                time.sleep(0.3)
                sock.close()

                # Small delay before next connection
                time.sleep(0.3)

        finally:
            proc.kill()
            proc.wait()

    def test_bind_wrong_password_rejected(self):
        """Connect with wrong password, verify auth is rejected."""
        proc, port, host_pub = start_bind_server(b"correct_pw")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('127.0.0.1', port))

            keys = do_kex_as_client(sock, host_pub)

            # Try auth with wrong password
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
            seq_send = 3
            seq_recv = 3

            svc_req = bytes([5]) + encode_string(b"ssh-userauth")
            send_encrypted_packet(sock, svc_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 6  # SERVICE_ACCEPT

            auth_req = bytes([50])
            auth_req += encode_string(b"operator")
            auth_req += encode_string(b"ssh-connection")
            auth_req += encode_string(b"password")
            auth_req += bytes([0])
            auth_req += encode_string(b"wrong_password")
            send_encrypted_packet(sock, auth_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            # Should be USERAUTH_FAILURE (51), not SUCCESS (52)
            assert payload[0] == 51, (
                f"Expected USERAUTH_FAILURE(51), got {payload[0]}"
            )

            sock.close()
        finally:
            proc.kill()
            proc.wait()
