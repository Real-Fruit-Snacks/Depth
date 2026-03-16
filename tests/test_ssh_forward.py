"""Integration tests: SSH direct-tcpip port forwarding.

Tests ssh_client_event_loop_v2 handling of direct-tcpip CHANNEL_OPEN requests.
Python side acts as the operator (SSH teamserver), assembly binary acts as the
program with the v2 event loop.

Test flow:
  1. Python does kex_as_server + auth_as_server
  2. Python sends CHANNEL_OPEN for "direct-tcpip" channels
  3. Assembly connects to target TCP host:port
  4. Data is relayed bidirectionally through SSH channel data messages
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
    """Run auth protocol as Python server. Returns (seq_recv, seq_send)."""
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


# ---- Session channel helpers (copied from test_ssh_multichan.py) ----

def open_session_channel(sock, keys, seq_send, seq_recv, sender_channel_id):
    """Open a session channel. Returns (remote_channel, recipient, seq_send, seq_recv)."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    chan_open = bytes([90])
    chan_open += encode_string(b"session")
    chan_open += struct.pack(">I", sender_channel_id)
    chan_open += struct.pack(">I", 0x200000)  # window = 2MB
    chan_open += struct.pack(">I", 0x8000)    # max packet = 32KB
    send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
    seq_recv += 1
    assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"

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


def collect_channel_data(sock, keys, seq_recv, target_string: bytes,
                         timeout_sec: float = 8.0, channel_filter: int = None):
    """
    Read encrypted packets, collecting CHANNEL_DATA payloads.
    Returns (channel_data_map, seq_recv) where channel_data_map is {recipient: bytes}.
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


# ---- direct-tcpip helpers ----

def build_direct_tcpip_open(sender_channel, host, port):
    """Build SSH_MSG_CHANNEL_OPEN for direct-tcpip."""
    payload = bytes([90])  # SSH_MSG_CHANNEL_OPEN
    payload += encode_string(b"direct-tcpip")
    payload += struct.pack(">I", sender_channel)
    payload += struct.pack(">I", 0x200000)   # initial window 2MB
    payload += struct.pack(">I", 0x8000)     # max packet 32KB
    payload += encode_string(host.encode() if isinstance(host, str) else host)
    payload += struct.pack(">I", port)
    payload += encode_string(b"127.0.0.1")   # originator IP
    payload += struct.pack(">I", 12345)      # originator port
    return payload


def open_direct_tcpip_channel(sock, keys, seq_send, seq_recv, sender_channel, host, port):
    """
    Send direct-tcpip CHANNEL_OPEN and read response.
    Returns (msg_type, remote_channel_or_none, seq_send, seq_recv).
    msg_type is 91 (CONFIRMATION) or 92 (FAILURE).
    remote_channel is the assembly's local channel id (sender field in CONFIRMATION).
    """
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pkt = build_direct_tcpip_open(sender_channel, host, port)
    send_encrypted_packet(sock, pkt, k1_s2c, k2_s2c, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
    seq_recv += 1

    msg_type = payload[0]
    if msg_type == 91:  # CHANNEL_OPEN_CONFIRMATION
        # [byte 91][uint32 recipient=sender_channel][uint32 sender][uint32 window][uint32 maxpkt]
        remote_channel = struct.unpack(">I", payload[5:9])[0]
        return msg_type, remote_channel, seq_send, seq_recv
    else:
        # CHANNEL_OPEN_FAILURE (92) or unexpected
        return msg_type, None, seq_send, seq_recv


# ---- Echo server helper ----

def start_echo_server():
    """Start a TCP echo server on a random port. Returns port number."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run():
        try:
            srv.settimeout(10.0)
            conn, _ = srv.accept()
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    conn.sendall(data)
            except Exception:
                pass
            finally:
                conn.close()
        except Exception:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port


def find_closed_port():
    """Find a port with nothing listening."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    # Port is now free — nothing listening on it
    return port


# ---- Server startup ----

def start_program(password: bytes, username: bytes = b"operator"):
    """
    Start the assembly multichan test harness.
    Input format: sock_fd(4 LE) + user_len(4 LE) + username + pass_len(4 LE) + password
    Returns (proc, sock).
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
    """Start program, do kex + auth. Returns (proc, sock, keys, seq_send, seq_recv)."""
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
    """Clean up process and socket."""
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
# Tests
# ============================================================================

class TestDirectTcpip:
    """Integration tests for direct-tcpip port forwarding via ssh_forward_open."""

    def test_direct_tcpip_connect_and_echo(self):
        """
        Open a direct-tcpip channel to a local echo server.
        Send data through the channel, verify the echo comes back.
        """
        echo_port = start_echo_server()
        time.sleep(0.1)  # let echo server settle

        proc, sock, keys, seq_send, seq_recv = setup_session(b"fwd_pw1")
        k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=42, host="127.0.0.1", port=echo_port
            )
            assert msg_type == 91, (
                f"Expected CHANNEL_OPEN_CONFIRMATION(91), got {msg_type}"
            )
            assert remote_ch is not None

            # Send data through the forward channel
            test_data = b"hello_echo_test_12345"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch, test_data)

            # Collect echo response
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, test_data, timeout_sec=8.0,
                channel_filter=42
            )

            response = collected.get(42, b"")
            assert test_data in response, (
                f"Expected echo of {test_data!r}, got {response!r}"
            )

        finally:
            teardown(proc, sock)

    def test_forward_connection_refused(self):
        """
        Open direct-tcpip to a port with nothing listening.
        Verify the assembly server sends SSH_MSG_CHANNEL_OPEN_FAILURE (92).
        """
        closed_port = find_closed_port()

        proc, sock, keys, seq_send, seq_recv = setup_session(b"fwd_pw2")

        try:
            msg_type, remote_ch, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=77, host="127.0.0.1", port=closed_port
            )
            assert msg_type == 92, (
                f"Expected CHANNEL_OPEN_FAILURE(92) for refused connection, got {msg_type}"
            )
            assert remote_ch is None

        finally:
            teardown(proc, sock)

    def test_multiple_forwards(self):
        """
        Open 2 direct-tcpip channels to different echo servers.
        Send different data on each, verify correct routing.
        """
        echo_port1 = start_echo_server()
        echo_port2 = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"fwd_pw3")

        try:
            # Open channel to echo server 1
            msg1, remote_ch1, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=10, host="127.0.0.1", port=echo_port1
            )
            assert msg1 == 91, f"Channel 1 open failed: got msg type {msg1}"

            # Open channel to echo server 2
            msg2, remote_ch2, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=20, host="127.0.0.1", port=echo_port2
            )
            assert msg2 == 91, f"Channel 2 open failed: got msg type {msg2}"

            # Verify distinct assembly-side channel IDs
            assert remote_ch1 != remote_ch2, (
                f"Expected different remote channel IDs, got {remote_ch1} and {remote_ch2}"
            )

            # Send distinct data on each channel
            data1 = b"channel_one_data_ALPHA"
            data2 = b"channel_two_data_BETA"
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch1, data1)
            seq_send = send_channel_data(sock, keys, seq_send, remote_ch2, data2)

            # Collect from both channels
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, data1, timeout_sec=8.0,
                channel_filter=10
            )
            if data2 not in collected.get(20, b""):
                more, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, data2, timeout_sec=5.0,
                    channel_filter=20
                )
                for k, v in more.items():
                    collected.setdefault(k, b"")
                    collected[k] += v

            resp1 = collected.get(10, b"")
            resp2 = collected.get(20, b"")

            assert data1 in resp1, (
                f"Expected {data1!r} echoed on channel 10, got {resp1!r}"
            )
            assert data2 in resp2, (
                f"Expected {data2!r} echoed on channel 20, got {resp2!r}"
            )

        finally:
            teardown(proc, sock)

    def test_forward_and_session_concurrent(self):
        """
        Open one PTY session channel + one direct-tcpip forward simultaneously.
        Verify both work concurrently.
        """
        echo_port = start_echo_server()
        time.sleep(0.1)

        proc, sock, keys, seq_send, seq_recv = setup_session(b"fwd_pw4")

        try:
            # Open a PTY session channel
            remote_sess, recip_sess, seq_send, seq_recv = open_session_channel(
                sock, keys, seq_send, seq_recv, sender_channel_id=1
            )
            seq_send = send_pty_req(sock, keys, seq_send, remote_sess)
            seq_send = send_shell_req(sock, keys, seq_send, remote_sess)

            # Open a direct-tcpip channel
            msg, remote_fwd, seq_send, seq_recv = open_direct_tcpip_channel(
                sock, keys, seq_send, seq_recv,
                sender_channel=2, host="127.0.0.1", port=echo_port
            )
            assert msg == 91, (
                f"Expected CHANNEL_OPEN_CONFIRMATION(91) for forward, got {msg}"
            )

            time.sleep(0.5)  # let PTY shell settle

            # Send a command on the session channel
            seq_send = send_channel_data(sock, keys, seq_send, remote_sess,
                                         b"echo session_alive\n")

            # Send data on the forward channel
            fwd_data = b"forward_alive_XYZ"
            seq_send = send_channel_data(sock, keys, seq_send, remote_fwd, fwd_data)

            # Collect: wait for echo server response on channel 2
            collected, seq_recv = collect_channel_data(
                sock, keys, seq_recv, fwd_data, timeout_sec=8.0,
                channel_filter=2
            )
            fwd_resp = collected.get(2, b"")
            assert fwd_data in fwd_resp, (
                f"Expected forward echo {fwd_data!r} on channel 2, got {fwd_resp!r}"
            )

            # Also collect session output (may already be buffered)
            if b"session_alive" not in collected.get(recip_sess, b""):
                more, seq_recv = collect_channel_data(
                    sock, keys, seq_recv, b"session_alive", timeout_sec=5.0,
                    channel_filter=recip_sess
                )
                for k, v in more.items():
                    collected.setdefault(k, b"")
                    collected[k] += v

            sess_resp = collected.get(recip_sess, b"").decode('utf-8', errors='replace')
            assert 'session_alive' in sess_resp, (
                f"Expected 'session_alive' in PTY output, got: {sess_resp!r}"
            )

            # Cleanup session shell
            try:
                seq_send = send_channel_data(sock, keys, seq_send, remote_sess, b"exit\n")
            except (BrokenPipeError, ConnectionError):
                pass
            time.sleep(0.3)

        finally:
            teardown(proc, sock)
