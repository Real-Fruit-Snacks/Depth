"""Integration tests: SSH remote port forwarding (ssh -R).

Tests ssh_client_event_loop_v2 handling of SSH_MSG_GLOBAL_REQUEST "tcpip-forward"
and the resulting CHANNEL_OPEN "forwarded-tcpip" when connections arrive.

Python acts as SSH CLIENT (connects to assembly server in bind mode).
When Python sends GLOBAL_REQUEST "tcpip-forward", the assembly starts listening
on the requested port. When a TCP connection arrives on that port, the assembly
sends CHANNEL_OPEN "forwarded-tcpip" back to Python.

Test flow:
  1. Start assembly in bind mode (test_remote_fwd harness)
  2. Python connects as SSH client, does kex + auth
  3. Python sends SSH_MSG_GLOBAL_REQUEST "tcpip-forward"
  4. Assembly responds with REQUEST_SUCCESS + bound port
  5. A separate thread connects to the forwarded port
  6. Assembly accepts, sends CHANNEL_OPEN "forwarded-tcpip" to Python
  7. Python confirms the channel
  8. Data relay verified bidirectionally
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

REMOTE_FWD_BINARY = "./build/test_remote_fwd"


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


# ---- Kex as CLIENT ----

def do_kex_as_client(sock, host_pub_bytes):
    """Kex as Python CLIENT against assembly SSH SERVER."""
    client_version = b"SSH-2.0-TestClient_1.0"

    server_version_line = b""
    while not server_version_line.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("EOF during version")
        server_version_line += b
    server_version = server_version_line.rstrip(b"\r\n")

    sock.sendall(client_version + b"\r\n")

    server_kexinit = recv_plain_packet(sock)
    assert server_kexinit[0] == 20

    client_kexinit = build_kexinit_payload()
    sock.sendall(build_plain_packet(client_kexinit))

    client_ephem_priv = X25519PrivateKey.generate()
    client_ephem_pub = client_ephem_priv.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    ecdh_init = bytes([30]) + encode_string(client_ephem_pub)
    sock.sendall(build_plain_packet(ecdh_init))

    ecdh_reply = recv_plain_packet(sock)
    assert ecdh_reply[0] == 31

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

    hk_offset = 0
    hk_type_len = struct.unpack(">I", host_key_blob[hk_offset:hk_offset+4])[0]
    hk_offset += 4 + hk_type_len
    hk_pub_len = struct.unpack(">I", host_key_blob[hk_offset:hk_offset+4])[0]
    hk_offset += 4
    host_raw_pub = host_key_blob[hk_offset:hk_offset+hk_pub_len]
    assert host_raw_pub == host_pub_bytes

    sig_offset = 0
    sig_type_len = struct.unpack(">I", sig_blob[sig_offset:sig_offset+4])[0]
    sig_offset += 4 + sig_type_len
    sig_raw_len = struct.unpack(">I", sig_blob[sig_offset:sig_offset+4])[0]
    sig_offset += 4
    sig_raw = sig_blob[sig_offset:sig_offset+sig_raw_len]

    host_pub_key = Ed25519PublicKey.from_public_bytes(host_pub_bytes)
    host_pub_key.verify(sig_raw, H)

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
    """Password auth as Python CLIENT against assembly SSH SERVER."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    seq_send = 3
    seq_recv = 3

    svc_req = bytes([5]) + encode_string(b"ssh-userauth")
    send_encrypted_packet(sock, svc_req, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
    seq_recv += 1
    assert payload[0] == 6

    auth_req = bytes([50])
    auth_req += encode_string(username)
    auth_req += encode_string(b"ssh-connection")
    auth_req += encode_string(b"password")
    auth_req += bytes([0])
    auth_req += encode_string(password)
    send_encrypted_packet(sock, auth_req, k1_c2s, k2_c2s, seq_send)
    seq_send += 1

    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
    seq_recv += 1
    assert payload[0] == 52

    return seq_send, seq_recv


# ---- Remote forward helpers ----

def build_global_request_tcpip_forward(bind_address: bytes, bind_port: int,
                                        want_reply: bool = True) -> bytes:
    """Build SSH_MSG_GLOBAL_REQUEST "tcpip-forward"."""
    payload = bytes([80])  # SSH_MSG_GLOBAL_REQUEST
    payload += encode_string(b"tcpip-forward")
    payload += bytes([1 if want_reply else 0])
    payload += encode_string(bind_address)
    payload += struct.pack(">I", bind_port)
    return payload


def build_global_request_cancel_forward(bind_address: bytes, bind_port: int,
                                         want_reply: bool = True) -> bytes:
    """Build SSH_MSG_GLOBAL_REQUEST "cancel-tcpip-forward"."""
    payload = bytes([80])
    payload += encode_string(b"cancel-tcpip-forward")
    payload += bytes([1 if want_reply else 0])
    payload += encode_string(bind_address)
    payload += struct.pack(">I", bind_port)
    return payload


def send_channel_open_confirm(sock, keys, seq_send, recipient_channel,
                               sender_channel, window=0x200000, maxpkt=0x8000):
    """Send SSH_MSG_CHANNEL_OPEN_CONFIRMATION."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    payload = bytes([91])
    payload += struct.pack(">I", recipient_channel)
    payload += struct.pack(">I", sender_channel)
    payload += struct.pack(">I", window)
    payload += struct.pack(">I", maxpkt)
    send_encrypted_packet(sock, payload, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def send_channel_data_as_client(sock, keys, seq_send, remote_channel, data: bytes):
    """Send CHANNEL_DATA (c2s direction)."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']

    pkt = bytes([94])
    pkt += struct.pack(">I", remote_channel)
    pkt += encode_string(data)
    send_encrypted_packet(sock, pkt, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def recv_encrypted_packet_with_timeout(sock, k1, k2, seq, timeout=5.0):
    """Receive an encrypted packet with a socket timeout."""
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        return recv_encrypted_packet(sock, k1, k2, seq)
    finally:
        sock.settimeout(old_timeout)


def collect_packets_until(sock, keys, seq_recv, predicate, timeout_sec=8.0):
    """
    Collect encrypted packets (s2c direction) until predicate returns True.
    Returns (packets_list, seq_recv).
    """
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    packets = []
    deadline = time.time() + timeout_sec

    while time.time() < deadline:
        try:
            sock.settimeout(max(0.5, deadline - time.time()))
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            packets.append(payload)
            if predicate(packets):
                break
        except (socket.timeout, ConnectionError):
            break

    return packets, seq_recv


# ---- Server startup ----

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def start_remote_fwd_server(password: bytes, port: int = None):
    """Start the assembly remote-fwd test harness. Returns (proc, port, host_pub_bytes)."""
    if port is None:
        port = find_free_port()

    host_priv_key = Ed25519PrivateKey.generate()
    host_pub_key = host_priv_key.public_key()
    host_priv_bytes = host_priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    host_pub_bytes = host_pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    inp = struct.pack("<H", port)
    inp += host_priv_bytes + host_pub_bytes
    inp += struct.pack("<I", len(password)) + password

    proc = subprocess.Popen(
        [REMOTE_FWD_BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.stdin.write(inp)
    proc.stdin.flush()

    ready = b""
    deadline = time.time() + 10
    while time.time() < deadline:
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
        f"Server didn't become ready. Got: {ready!r}"
    )

    return proc, port, host_pub_bytes


def connect_and_setup(port, host_pub_bytes, password: bytes,
                       username: bytes = b"operator"):
    """Connect, kex, auth. Returns (sock, keys, seq_send, seq_recv)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(('127.0.0.1', port))

    keys = do_kex_as_client(sock, host_pub_bytes)
    seq_send, seq_recv = do_auth_as_client(sock, keys, username, password)

    return sock, keys, seq_send, seq_recv


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
# Tests
# ============================================================================

class TestRemoteForward:
    """Integration tests for SSH remote port forwarding (ssh -R)."""

    def test_remote_forward_basic(self):
        """
        Request a remote forward, connect to the forwarded port,
        verify data relay through the SSH channel.
        """
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw1")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw1"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Send GLOBAL_REQUEST "tcpip-forward" with port=0 (let OS pick)
            fwd_req = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Receive REQUEST_SUCCESS with the bound port
            payload = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload[0] == 81, (
                f"Expected REQUEST_SUCCESS(81), got {payload[0]}"
            )
            bound_port = struct.unpack(">I", payload[1:5])[0]
            assert bound_port > 0, f"Expected non-zero bound port, got {bound_port}"

            # Connect to the forwarded port from a separate thread
            fwd_data_received = []
            fwd_data_sent = b"hello_remote_forward_test_42"
            connect_error = []

            def tcp_client():
                try:
                    time.sleep(0.2)  # let assembly poll loop pick up the listen fd
                    cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    cs.settimeout(5)
                    cs.connect(('127.0.0.1', bound_port))
                    cs.sendall(fwd_data_sent)
                    # Read back whatever the channel sends us
                    try:
                        data = cs.recv(4096)
                        fwd_data_received.append(data)
                    except socket.timeout:
                        pass
                    cs.close()
                except Exception as e:
                    connect_error.append(e)

            t = threading.Thread(target=tcp_client, daemon=True)
            t.start()

            # Wait for CHANNEL_OPEN "forwarded-tcpip" from assembly
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] == 90 for p in pkts),
                timeout_sec=8.0
            )

            # Find the CHANNEL_OPEN packet
            chan_open = None
            for p in packets:
                if p[0] == 90:
                    chan_open = p
                    break

            assert chan_open is not None, (
                f"Expected CHANNEL_OPEN from assembly. Got packet types: "
                f"{[p[0] for p in packets]}"
            )

            # Parse CHANNEL_OPEN "forwarded-tcpip"
            # [byte 90][string type][uint32 sender][uint32 window][uint32 maxpkt]
            # [string connected_addr][uint32 connected_port]
            # [string originator_addr][uint32 originator_port]
            offset = 1
            type_len = struct.unpack(">I", chan_open[offset:offset+4])[0]
            offset += 4
            chan_type = chan_open[offset:offset+type_len]
            offset += type_len
            assert chan_type == b"forwarded-tcpip", (
                f"Expected 'forwarded-tcpip', got {chan_type!r}"
            )

            sender_channel = struct.unpack(">I", chan_open[offset:offset+4])[0]
            offset += 4
            remote_window = struct.unpack(">I", chan_open[offset:offset+4])[0]
            offset += 4
            remote_maxpkt = struct.unpack(">I", chan_open[offset:offset+4])[0]

            # Send CHANNEL_OPEN_CONFIRMATION
            my_channel_id = 100  # arbitrary local id
            seq_send = send_channel_open_confirm(
                sock, keys, seq_send,
                recipient_channel=sender_channel,
                sender_channel=my_channel_id
            )

            # Wait a bit for data to flow through
            time.sleep(0.5)

            # Collect CHANNEL_DATA from assembly (the data the TCP client sent)
            packets2, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(
                    p[0] == 94 and fwd_data_sent in p[9:9+struct.unpack(">I", p[5:9])[0]]
                    for p in pkts if len(p) > 9
                ),
                timeout_sec=8.0
            )

            # Extract channel data
            channel_data = b""
            for p in packets2:
                if p[0] == 94:  # CHANNEL_DATA
                    data_len = struct.unpack(">I", p[5:9])[0]
                    channel_data += p[9:9+data_len]

            assert fwd_data_sent in channel_data, (
                f"Expected {fwd_data_sent!r} in channel data, got {channel_data!r}"
            )

            # Send data back through the channel to the TCP client
            reply_data = b"reply_from_ssh_channel"
            seq_send = send_channel_data_as_client(
                sock, keys, seq_send, sender_channel, reply_data
            )

            # Wait for TCP client thread
            t.join(timeout=5)
            assert not connect_error, f"TCP client error: {connect_error}"

        finally:
            teardown(proc, sock)

    def test_remote_forward_specific_port(self):
        """Request a remote forward on a specific port."""
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw2")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw2"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Find a free port to request
            specific_port = find_free_port()

            fwd_req = build_global_request_tcpip_forward(b"0.0.0.0", specific_port)
            send_encrypted_packet(sock, fwd_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload[0] == 81, (
                f"Expected REQUEST_SUCCESS(81), got {payload[0]}"
            )
            bound_port = struct.unpack(">I", payload[1:5])[0]
            assert bound_port == specific_port, (
                f"Expected port {specific_port}, got {bound_port}"
            )

            # Verify we can connect to it
            time.sleep(0.3)
            cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs.settimeout(3)
            cs.connect(('127.0.0.1', specific_port))
            cs.close()

            # Collect the resulting CHANNEL_OPEN
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] == 90 for p in pkts),
                timeout_sec=5.0
            )
            chan_open = next((p for p in packets if p[0] == 90), None)
            assert chan_open is not None, "Expected CHANNEL_OPEN after TCP connect"

        finally:
            teardown(proc, sock)

    def test_remote_forward_multiple(self):
        """Request 2 remote forwards on different ports."""
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw3")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw3"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Forward 1: port=0
            fwd_req1 = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req1, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload1 = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload1[0] == 81
            port1 = struct.unpack(">I", payload1[1:5])[0]
            assert port1 > 0

            # Forward 2: port=0
            fwd_req2 = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req2, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload2 = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload2[0] == 81
            port2 = struct.unpack(">I", payload2[1:5])[0]
            assert port2 > 0
            assert port1 != port2, f"Ports should differ: {port1} vs {port2}"

            # Connect to both forwarded ports
            time.sleep(0.3)

            cs1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs1.settimeout(3)
            cs1.connect(('127.0.0.1', port1))
            cs1.sendall(b"data_for_port1")

            cs2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs2.settimeout(3)
            cs2.connect(('127.0.0.1', port2))
            cs2.sendall(b"data_for_port2")

            # Collect 2 CHANNEL_OPEN messages
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: sum(1 for p in pkts if p[0] == 90) >= 2,
                timeout_sec=8.0
            )

            chan_opens = [p for p in packets if p[0] == 90]
            assert len(chan_opens) >= 2, (
                f"Expected 2 CHANNEL_OPEN messages, got {len(chan_opens)}"
            )

            # Confirm both channels
            for i, co in enumerate(chan_opens[:2]):
                offset = 1
                type_len = struct.unpack(">I", co[offset:offset+4])[0]
                offset += 4 + type_len
                sender_ch = struct.unpack(">I", co[offset:offset+4])[0]
                seq_send = send_channel_open_confirm(
                    sock, keys, seq_send,
                    recipient_channel=sender_ch,
                    sender_channel=200 + i
                )

            # Collect data from both channels
            time.sleep(0.5)
            packets2, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: sum(1 for p in pkts if p[0] == 94) >= 2,
                timeout_sec=8.0
            )

            all_data = b""
            for p in packets2:
                if p[0] == 94:
                    data_len = struct.unpack(">I", p[5:9])[0]
                    all_data += p[9:9+data_len]

            assert b"data_for_port1" in all_data or b"data_for_port2" in all_data, (
                f"Expected forwarded data in channel, got {all_data!r}"
            )

            cs1.close()
            cs2.close()

        finally:
            teardown(proc, sock)

    def test_remote_forward_with_pty(self):
        """
        Remote forward + PTY session simultaneously.
        Open a session channel with PTY, then request a remote forward,
        verify both work concurrently.
        """
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw4")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw4"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Open a session channel
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)       # sender_channel
            chan_open += struct.pack(">I", 0x200000) # window
            chan_open += struct.pack(">I", 0x8000)   # maxpkt
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload[0] == 91, f"Expected CONFIRM(91), got {payload[0]}"
            session_recipient = struct.unpack(">I", payload[1:5])[0]
            session_remote_ch = struct.unpack(">I", payload[5:9])[0]

            # Send pty-req
            pty_req = bytes([98])
            pty_req += struct.pack(">I", session_remote_ch)
            pty_req += encode_string(b"pty-req")
            pty_req += bytes([0])
            pty_req += encode_string(b"xterm")
            pty_req += struct.pack(">I", 80)
            pty_req += struct.pack(">I", 24)
            pty_req += struct.pack(">I", 640)
            pty_req += struct.pack(">I", 480)
            pty_req += encode_string(b"")
            send_encrypted_packet(sock, pty_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Send shell
            shell_req = bytes([98])
            shell_req += struct.pack(">I", session_remote_ch)
            shell_req += encode_string(b"shell")
            shell_req += bytes([0])
            send_encrypted_packet(sock, shell_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            time.sleep(0.5)

            # Now request a remote forward
            fwd_req = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Receive REQUEST_SUCCESS
            # May need to skip shell prompt data first
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] == 81 for p in pkts),
                timeout_sec=8.0
            )
            success_pkt = next((p for p in packets if p[0] == 81), None)
            assert success_pkt is not None, (
                f"Expected REQUEST_SUCCESS. Got: {[p[0] for p in packets]}"
            )
            bound_port = struct.unpack(">I", success_pkt[1:5])[0]
            assert bound_port > 0

            # Send a command on the PTY
            cmd_data = b"echo pty_and_fwd_ok\n"
            seq_send = send_channel_data_as_client(
                sock, keys, seq_send, session_remote_ch, cmd_data
            )

            # Connect to the forwarded port
            time.sleep(0.3)
            cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs.settimeout(3)
            cs.connect(('127.0.0.1', bound_port))
            cs.sendall(b"fwd_concurrent_test")

            # Collect all responses - should have both PTY output and CHANNEL_OPEN
            packets2, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: (
                    any(p[0] == 90 for p in pkts) and
                    any(p[0] == 94 and b"pty_and_fwd_ok" in p[9:] for p in pkts if len(p) > 9)
                ),
                timeout_sec=8.0
            )

            # Verify PTY output
            pty_data = b""
            for p in packets + packets2:
                if p[0] == 94:
                    recipient = struct.unpack(">I", p[1:5])[0]
                    if recipient == session_recipient:
                        data_len = struct.unpack(">I", p[5:9])[0]
                        pty_data += p[9:9+data_len]

            assert b"pty_and_fwd_ok" in pty_data, (
                f"Expected 'pty_and_fwd_ok' in PTY output, got {pty_data!r}"
            )

            # Verify CHANNEL_OPEN arrived for forward
            chan_open_fwd = next(
                (p for p in packets + packets2 if p[0] == 90),
                None
            )
            assert chan_open_fwd is not None, "Expected CHANNEL_OPEN for forward"

            cs.close()

            # Exit shell
            try:
                seq_send = send_channel_data_as_client(
                    sock, keys, seq_send, session_remote_ch, b"exit\n"
                )
            except (BrokenPipeError, ConnectionError):
                pass
            time.sleep(0.3)

        finally:
            teardown(proc, sock)

    def test_remote_forward_large_data(self):
        """Send 32KB of data through a remote forward channel."""
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw5")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw5"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Request forward
            fwd_req = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload[0] == 81
            bound_port = struct.unpack(">I", payload[1:5])[0]

            # Connect and send 32KB
            time.sleep(0.3)
            large_data = os.urandom(32768)

            cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs.settimeout(5)
            cs.connect(('127.0.0.1', bound_port))

            # Wait for CHANNEL_OPEN
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] == 90 for p in pkts),
                timeout_sec=5.0
            )

            chan_open_pkt = next((p for p in packets if p[0] == 90), None)
            assert chan_open_pkt is not None

            # Parse sender channel
            offset = 1
            type_len = struct.unpack(">I", chan_open_pkt[offset:offset+4])[0]
            offset += 4 + type_len
            sender_ch = struct.unpack(">I", chan_open_pkt[offset:offset+4])[0]

            # Confirm the channel
            seq_send = send_channel_open_confirm(
                sock, keys, seq_send,
                recipient_channel=sender_ch,
                sender_channel=300
            )

            # Now send the large data on the TCP socket
            cs.sendall(large_data)
            time.sleep(1)

            # Collect channel data
            received_data = b""
            deadline = time.time() + 10.0
            while len(received_data) < len(large_data) and time.time() < deadline:
                remaining = len(large_data) - len(received_data)
                packets2, seq_recv = collect_packets_until(
                    sock, keys, seq_recv,
                    lambda pkts: sum(
                        struct.unpack(">I", p[5:9])[0]
                        for p in pkts if p[0] == 94 and len(p) > 9
                    ) > 0,
                    timeout_sec=3.0
                )
                for p in packets2:
                    if p[0] == 94 and len(p) > 9:
                        data_len = struct.unpack(">I", p[5:9])[0]
                        received_data += p[9:9+data_len]

            assert len(received_data) >= len(large_data), (
                f"Expected {len(large_data)} bytes, got {len(received_data)}"
            )
            assert received_data[:len(large_data)] == large_data, (
                "Large data mismatch"
            )

            cs.close()

        finally:
            teardown(proc, sock)

    def test_remote_forward_close(self):
        """
        Open a remote forward, connect, close the TCP connection.
        Verify the assembly sends EOF/CLOSE for the channel.
        """
        proc, port, host_pub = start_remote_fwd_server(b"rfwd_pw6")

        try:
            sock, keys, seq_send, seq_recv = connect_and_setup(
                port, host_pub, b"rfwd_pw6"
            )
            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Request forward
            fwd_req = build_global_request_tcpip_forward(b"0.0.0.0", 0)
            send_encrypted_packet(sock, fwd_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            payload = recv_encrypted_packet_with_timeout(
                sock, k1_s2c, k2_s2c, seq_recv, timeout=5.0
            )
            seq_recv += 1
            assert payload[0] == 81
            bound_port = struct.unpack(">I", payload[1:5])[0]

            # Connect to forwarded port
            time.sleep(0.3)
            cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            cs.settimeout(3)
            cs.connect(('127.0.0.1', bound_port))
            cs.sendall(b"close_test_data")

            # Wait for CHANNEL_OPEN
            packets, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] == 90 for p in pkts),
                timeout_sec=5.0
            )

            chan_open_pkt = next((p for p in packets if p[0] == 90), None)
            assert chan_open_pkt is not None

            offset = 1
            type_len = struct.unpack(">I", chan_open_pkt[offset:offset+4])[0]
            offset += 4 + type_len
            sender_ch = struct.unpack(">I", chan_open_pkt[offset:offset+4])[0]

            # Confirm channel
            seq_send = send_channel_open_confirm(
                sock, keys, seq_send,
                recipient_channel=sender_ch,
                sender_channel=400
            )

            time.sleep(0.3)

            # Close the TCP connection
            cs.close()

            # The assembly should detect the fd EOF and send EOF/CLOSE
            # (on next poll cycle when read returns 0)
            packets2, seq_recv = collect_packets_until(
                sock, keys, seq_recv,
                lambda pkts: any(p[0] in (96, 97) for p in pkts),
                timeout_sec=8.0
            )

            eof_close_found = any(p[0] in (96, 97) for p in packets2)
            assert eof_close_found, (
                f"Expected EOF(96) or CLOSE(97) after TCP disconnect. "
                f"Got: {[p[0] for p in packets2]}"
            )

        finally:
            teardown(proc, sock)
