"""Integration tests: Multi-channel SSH event loop (v2).

Tests ssh_client_event_loop_v2 with multiple concurrent session channels.
Python side acts as the operator (SSH client/teamserver), assembly binary
acts as the program server with the v2 event loop.

Test flow:
  1. Python does kex_as_server + auth_as_server (from the program's perspective,
     the teamserver is the SSH server during kex/auth)
  2. Python sends CHANNEL_OPEN for session channels
  3. Python sends pty-req + shell channel requests
  4. Python sends commands as CHANNEL_DATA
  5. Python reads back PTY output through CHANNEL_DATA
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

MULTICHAN_BINARY = "./build/test_ssh_multichan"


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


# ---- Kex + Auth as teamserver (server side) ----

def do_kex_as_server(sock):
    """Run full kex handshake as Python server. Returns keys dict."""
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
        raise ValueError("Auth failed")
    seq_send += 1

    return seq_recv, seq_send


# ---- Helper: open a session channel on the program ----

def open_session_channel(sock, keys, seq_send, seq_recv, sender_channel_id):
    """
    Open a session channel on the program.
    The Python side acts as the teamserver sending CHANNEL_OPEN.
    The program's v2 event loop responds with CHANNEL_OPEN_CONFIRMATION.

    NOTE: In this architecture the program is the CLIENT connecting to the teamserver.
    The teamserver (Python) sends CHANNEL_OPEN to the program.
    From the SSH protocol perspective:
      - Python sends with s2c keys (server-to-client)
      - Python receives with c2s keys (client-to-server)
    """
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    chan_open = bytes([90])
    chan_open += encode_string(b"session")
    chan_open += struct.pack(">I", sender_channel_id)
    chan_open += struct.pack(">I", 0x200000)  # window = 2MB
    chan_open += struct.pack(">I", 0x8000)    # max packet = 32KB
    send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    # Receive CHANNEL_OPEN_CONFIRMATION
    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
    seq_recv += 1
    assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"

    # Parse: [byte 91][uint32 recipient][uint32 sender][uint32 window][uint32 maxpkt]
    recipient = struct.unpack(">I", payload[1:5])[0]
    remote_channel = struct.unpack(">I", payload[5:9])[0]

    return remote_channel, recipient, seq_send, seq_recv


def send_pty_req(sock, keys, seq_send, remote_channel):
    """Send pty-req channel request (want_reply=false)."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

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
    send_encrypted_packet(sock, pty_req, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_shell_req(sock, keys, seq_send, remote_channel):
    """Send shell channel request (want_reply=false)."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

    shell_req = bytes([98])
    shell_req += struct.pack(">I", remote_channel)
    shell_req += encode_string(b"shell")
    shell_req += bytes([0])  # want_reply = false
    send_encrypted_packet(sock, shell_req, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_channel_data(sock, keys, seq_send, remote_channel, data: bytes):
    """Send CHANNEL_DATA."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

    pkt = bytes([94])
    pkt += struct.pack(">I", remote_channel)
    pkt += encode_string(data)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    return seq_send + 1


def send_channel_eof_close(sock, keys, seq_send, remote_channel):
    """Send CHANNEL_EOF + CHANNEL_CLOSE."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

    eof = bytes([96]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, eof, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    close = bytes([97]) + struct.pack(">I", remote_channel)
    send_encrypted_packet(sock, close, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    return seq_send


def collect_channel_data(sock, keys, seq_recv, target_string: bytes,
                         timeout_sec: float = 8.0, channel_filter: int = None):
    """
    Read encrypted packets, collecting CHANNEL_DATA payloads.
    Returns (collected_bytes, seq_recv, channel_data_map) where
    channel_data_map is {recipient_channel: bytes}.
    Stops when target_string is found or timeout.
    """
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

                # Check if target found
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
                # Only break if it's for our filtered channel
                if channel_filter is not None:
                    eof_recipient = struct.unpack(">I", payload[1:5])[0]
                    if eof_recipient == channel_filter:
                        break
                    else:
                        continue  # EOF/CLOSE for a different channel
                else:
                    break
            elif payload[0] == 99:  # CHANNEL_SUCCESS
                continue
            elif payload[0] == 100:  # CHANNEL_FAILURE
                continue
        except (socket.timeout, ConnectionError):
            break

    return collected, seq_recv


# ---- Start assembly program harness ----

def start_program(password: bytes, username: bytes = b"operator"):
    """
    Start the assembly multichan test harness.
    The harness acts as the program CLIENT (kex_client + auth_client + event_loop_v2).
    Returns (proc, sock) where sock is the Python (teamserver) side.
    Input format: sock_fd(4 LE) + user_len(4 LE) + username + pass_len(4 LE) + password
    """
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
    """
    Start program, do kex + auth. Returns (proc, sock, keys, seq_send, seq_recv).
    """
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


# ============================================================================
# Tests
# ============================================================================

class TestMultiChannelV2:
    """Test the multi-channel v2 event loop."""

    def test_single_session_still_works(self):
        """Backward compatibility: one PTY session works through v2 event loop."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"secret123")

        try:
            # Open one session channel
            remote_ch, recipient, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=0
            )

            # Send pty-req + shell
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch)

            time.sleep(0.5)

            # Send command
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch,
                                         b"echo single_ok\n")

            # Collect output
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"single_ok", timeout_sec=8.0,
                channel_filter=recipient
            )

            output = collected.get(recipient, b"").decode('utf-8', errors='replace')
            assert 'single_ok' in output, (
                f"Expected 'single_ok' in output, got: {output!r}"
            )

            # Send exit
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, b"exit\n")
            time.sleep(0.5)

        finally:
            sock.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_two_sessions_concurrent(self):
        """Open two session channels, send different commands, verify routing."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"multi_pw")

        try:
            # Open channel 0
            remote_ch0, recip0, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=100
            )

            # Open channel 1
            remote_ch1, recip1, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=200
            )

            # pty-req + shell on channel 0
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch0)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch0)

            # pty-req + shell on channel 1
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch1)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch1)

            time.sleep(0.8)

            # Send different commands
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch0,
                                         b"echo chan0_alpha\n")
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch1,
                                         b"echo chan1_beta\n")

            # Collect output — look for both markers
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"chan1_beta", timeout_sec=10.0
            )

            # If we haven't seen chan0_alpha yet, keep collecting
            all_data = b"".join(collected.values())
            if b"chan0_alpha" not in all_data:
                more, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"chan0_alpha", timeout_sec=5.0
                )
                for k, v in more.items():
                    collected.setdefault(k, b"")
                    collected[k] += v

            # Verify both channels got their output
            chan0_data = collected.get(recip0, b"").decode('utf-8', errors='replace')
            chan1_data = collected.get(recip1, b"").decode('utf-8', errors='replace')

            # The output should appear on the correct channels
            all_output = chan0_data + chan1_data
            assert 'chan0_alpha' in all_output, (
                f"Expected 'chan0_alpha' somewhere, got ch0={chan0_data!r}, ch1={chan1_data!r}"
            )
            assert 'chan1_beta' in all_output, (
                f"Expected 'chan1_beta' somewhere, got ch0={chan0_data!r}, ch1={chan1_data!r}"
            )

            # Cleanup: exit both shells
            try:
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch0, b"exit\n")
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch1, b"exit\n")
            except (BrokenPipeError, ConnectionError):
                pass
            time.sleep(0.5)

        finally:
            sock.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_channel_alloc_uses_unique_ids(self):
        """Open 3 channels, verify each has a different local_id (sender channel)."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"unique_pw")

        try:
            remote_channels = []
            for i in range(3):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=50 + i
                )
                remote_channels.append(remote_ch)

            # Each remote_ch (the program's local_id) should be unique
            assert len(set(remote_channels)) == 3, (
                f"Expected 3 unique channel IDs, got {remote_channels}"
            )

            # They should be 0, 1, 2 (sequential allocation)
            assert sorted(remote_channels) == [0, 1, 2], (
                f"Expected [0, 1, 2], got {sorted(remote_channels)}"
            )

        finally:
            sock.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_close_one_keeps_other(self):
        """Open two channels, close one, verify the other still works."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"close_pw")

        try:
            # Open channel 0
            remote_ch0, recip0, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=10
            )

            # Open channel 1
            remote_ch1, recip1, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=20
            )

            # Start shells on both
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch0)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch0)
            seq_send = send_pty_req(sock, keys, seq_send, remote_ch1)
            seq_send = send_shell_req(sock, keys, seq_send, remote_ch1)

            time.sleep(0.8)

            # Send a command on channel 0 to verify it works
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch0,
                                         b"echo ZZZ1\n")

            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"ZZZ1", timeout_sec=5.0,
                channel_filter=recip0,
            )

            ch0_data = collected.get(recip0, b"")
            assert b"ZZZ1" in ch0_data, f"Expected ZZZ1 in channel 0 data: {ch0_data!r}"

            # Close channel 0
            seq_send = send_channel_eof_close(sock, keys, seq_send, remote_ch0)

            # Drain EOF/CLOSE responses from the program for channel 0
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                    seq_recv += 1
                    if payload[0] in (96, 97):  # EOF or CLOSE for ch0
                        continue
                    elif payload[0] == 94:  # Data (maybe from ch1 PTY prompt)
                        break
                    elif payload[0] == 93:  # WINDOW_ADJUST
                        continue
                    else:
                        break
                except (socket.timeout, ConnectionError):
                    break

            time.sleep(0.3)

            # Channel 1 should still work
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch1,
                                         b"echo after_close_ok\n")

            collected2, seq_recv = collect_channel_data(
                sock, keys, seq_recv, b"after_close_ok", timeout_sec=8.0,
                channel_filter=recip1
            )

            chan1_data = collected2.get(recip1, b"").decode('utf-8', errors='replace')
            assert 'after_close_ok' in chan1_data, (
                f"Expected 'after_close_ok' on chan1, got: {chan1_data!r}"
            )

            # Cleanup
            try:
                seq_send = send_channel_data(sock, keys, seq_send, remote_ch1, b"exit\n")
            except (BrokenPipeError, ConnectionError):
                pass
            time.sleep(0.5)

        finally:
            sock.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_max_channels_rejection(self):
        """Open MAX_CHANNELS (8) channels, verify next open is rejected."""
        proc, sock, keys, seq_send, seq_recv = setup_session(b"max_pw")
        k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
        k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

        try:
            # Open 8 channels
            for i in range(8):
                remote_ch, recip, seq_send, seq_recv = open_session_channel(
                    sock, keys, seq_send, seq_recv, sender_channel_id=300 + i
                )

            # Try to open a 9th — should get CHANNEL_OPEN_FAILURE (92)
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 999)       # sender channel
            chan_open += struct.pack(">I", 0x200000)   # window
            chan_open += struct.pack(">I", 0x8000)     # max packet
            send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Receive response — should be CHANNEL_OPEN_FAILURE (92)
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 92, (
                f"Expected CHANNEL_OPEN_FAILURE(92), got msg type {payload[0]}"
            )

        finally:
            sock.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
