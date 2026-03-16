"""End-to-end integration tests for the SSH program.

Test 1: Build verification -- the depth binary builds and is reasonable size.
Test 2: Full e2e session -- Python mock teamserver -> assembly program client ->
        kex + auth + channel_open + pty-req + shell + send command + read output.

The Python side acts as the teamserver:
  - Runs kex as SERVER
  - Runs auth as SERVER (accepts password)
  - Sends CHANNEL_OPEN to program (teamserver opens a channel for the operator)
  - Sends pty-req and shell channel requests
  - Sends a command as CHANNEL_DATA
  - Reads back PTY output through CHANNEL_DATA
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

E2E_BINARY = "./build/test_ssh_e2e"
BINARY = "./build/depth"


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


# ---- Mock teamserver: kex + auth + channel orchestration ----

def do_kex_as_server(sock):
    """Run full kex handshake as Python server. Returns keys dict."""
    host_key = Ed25519PrivateKey.generate()
    host_pubkey = host_key.public_key()
    server_version = b"SSH-2.0-DepthSSH_1.0"

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
        raise ValueError(f"Auth failed - wrong password: {received_password!r} != {expected_password!r}")
    seq_send += 1

    return seq_recv, seq_send


# ============================================================================
# Tests
# ============================================================================

class TestBuild:
    """Verify the program binary builds correctly."""

    def test_binary_exists(self):
        """depth binary exists after build."""
        assert os.path.exists(BINARY), (
            f"Binary not found at {BINARY}. Run 'make' first."
        )

    def test_binary_size(self):
        """depth binary is a reasonable size (8KB - 200KB)."""
        if not os.path.exists(BINARY):
            pytest.skip("Binary not built")
        size = os.path.getsize(BINARY)
        assert 8000 < size < 200000, (
            f"Binary size {size} bytes is outside expected range 8KB-200KB"
        )

    def test_binary_is_elf(self):
        """depth binary is a valid ELF."""
        if not os.path.exists(BINARY):
            pytest.skip("Binary not built")
        with open(BINARY, "rb") as f:
            magic = f.read(4)
        assert magic == b'\x7fELF', f"Not an ELF binary, magic={magic!r}"

    def test_is_statically_linked(self):
        """depth binary has no dynamic dependencies."""
        if not os.path.exists(BINARY):
            pytest.skip("Binary not built")
        r = subprocess.run(["file", BINARY], capture_output=True, text=True)
        assert "statically linked" in r.stdout, (
            f"Binary should be statically linked: {r.stdout}"
        )


class TestKeygen:
    """Test the keygen tool."""

    def test_keygen_nasm_format(self):
        """keygen.py generates valid NASM output."""
        r = subprocess.run(
            ["python3", "./tools/keygen.py", "--format", "nasm"],
            capture_output=True, text=True, timeout=10,
        )
        assert r.returncode == 0, f"keygen failed: {r.stderr}"
        assert "host_keypair:" in r.stdout
        assert "db " in r.stdout
        assert "private key" in r.stdout
        assert "public key" in r.stdout

    def test_keygen_bin_format(self):
        """keygen.py generates 64-byte binary output (32 priv + 32 pub)."""
        r = subprocess.run(
            ["python3", "./tools/keygen.py", "--format", "bin"],
            capture_output=True, timeout=10,
        )
        assert r.returncode == 0, f"keygen failed: {r.stderr}"
        assert len(r.stdout) == 64, f"Expected 64 bytes, got {len(r.stdout)}"


class TestE2ESession:
    """Full end-to-end test: Python mock teamserver -> assembly program."""

    def _run_e2e_test(self, username: bytes, password: bytes, command: str = "echo e2e_ok"):
        """
        Run full e2e session:
        1. Assembly program does kex_client + auth_client + event_loop
        2. Python acts as teamserver: kex_server + auth_server
        3. Python sends CHANNEL_OPEN to program
        4. Python sends pty-req + shell channel requests
        5. Python sends command as CHANNEL_DATA
        6. Python reads back PTY output
        """
        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        server_fd = s_server.fileno()

        # Build input for assembly e2e harness
        # Format: sock_fd(4 LE) + user_len(4 LE) + username + pass_len(4 LE) + password
        inp = struct.pack("<i", server_fd)
        inp += struct.pack("<I", len(username)) + username
        inp += struct.pack("<I", len(password)) + password

        # Start assembly program harness
        proc = subprocess.Popen(
            [E2E_BINARY],
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

            # Python teamserver: kex + auth
            keys = do_kex_as_server(sock)
            seq_recv, seq_send = do_auth_as_server(sock, keys, password)

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Teamserver sends CHANNEL_OPEN "session" to program
            # (In the real system, this represents an operator connection being forwarded)
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)       # sender channel = 0
            chan_open += struct.pack(">I", 0x200000) # window = 2MB
            chan_open += struct.pack(">I", 0x8000)   # max packet = 32KB
            send_encrypted_packet(sock, chan_open, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Receive CHANNEL_OPEN_CONFIRMATION from program
            payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
            seq_recv += 1
            assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"
            remote_channel = struct.unpack(">I", payload[5:9])[0]

            # Send pty-req (want_reply=false)
            pty_req = bytes([98])  # SSH_MSG_CHANNEL_REQUEST
            pty_req += struct.pack(">I", remote_channel)
            pty_req += encode_string(b"pty-req")
            pty_req += bytes([0])  # want_reply = false
            pty_req += encode_string(b"xterm-256color")
            pty_req += struct.pack(">I", 80)   # cols
            pty_req += struct.pack(">I", 24)   # rows
            pty_req += struct.pack(">I", 640)  # width px
            pty_req += struct.pack(">I", 480)  # height px
            pty_req += encode_string(b"")       # terminal modes
            send_encrypted_packet(sock, pty_req, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Send shell request (want_reply=false)
            shell_req = bytes([98])
            shell_req += struct.pack(">I", remote_channel)
            shell_req += encode_string(b"shell")
            shell_req += bytes([0])  # want_reply = false
            send_encrypted_packet(sock, shell_req, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Wait for PTY + shell to initialize
            time.sleep(0.5)

            # Send command through CHANNEL_DATA
            cmd_bytes = (command + "\n").encode()
            data_pkt = bytes([94])
            data_pkt += struct.pack(">I", remote_channel)
            data_pkt += encode_string(cmd_bytes)
            send_encrypted_packet(sock, data_pkt, k1_s2c, k2_s2c, seq_send)
            seq_send += 1

            # Read responses -- collect channel data
            collected = b""
            deadline = time.time() + 8.0
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_c2s, k2_c2s, seq_recv)
                    seq_recv += 1

                    if payload[0] == 94:  # CHANNEL_DATA
                        offset = 5
                        data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                        offset += 4
                        collected += payload[offset:offset + data_len]
                        if b"e2e_ok" in collected:
                            break
                    elif payload[0] == 93:  # WINDOW_ADJUST
                        continue
                    elif payload[0] in (96, 97):  # EOF or CLOSE
                        break
                except (socket.timeout, ConnectionError):
                    break

            # Send exit to shell, then close channel
            exit_pkt = bytes([94])
            exit_pkt += struct.pack(">I", remote_channel)
            exit_pkt += encode_string(b"exit\n")
            try:
                send_encrypted_packet(sock, exit_pkt, k1_s2c, k2_s2c, seq_send)
                seq_send += 1
            except (BrokenPipeError, ConnectionError):
                pass

            # Wait for process to finish
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

            return collected, proc.returncode

        finally:
            s_client.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait()

    def test_full_e2e_session(self):
        """Full e2e: Python teamserver -> assembly program -> PTY shell -> echo command."""
        collected, rc = self._run_e2e_test(
            username=b"operator",
            password=b"e2e_secret",
            command="echo e2e_ok",
        )
        output = collected.decode('utf-8', errors='replace')
        assert 'e2e_ok' in output, (
            f"Expected 'e2e_ok' in PTY output, got: {output!r}"
        )

    def test_e2e_exec_command(self):
        """E2e with a different command to verify PTY relay works."""
        collected, rc = self._run_e2e_test(
            username=b"admin",
            password=b"pass123",
            command="echo ssh_asm_works",
        )
        output = collected.decode('utf-8', errors='replace')
        assert 'ssh_asm_works' in output, (
            f"Expected 'ssh_asm_works' in PTY output, got: {output!r}"
        )
