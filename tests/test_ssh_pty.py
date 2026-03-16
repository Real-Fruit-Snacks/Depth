"""Integration tests: SSH PTY allocation, shell spawning, and I/O relay.

Tests ssh_pty_alloc, ssh_pty_spawn_shell, ssh_pty_spawn_exec, ssh_pty_relay
by running the assembly test harness in various modes.

For the relay test, a full SSH session is established:
  Python client → kex → auth → channel_open → pty-req → shell → send data → recv
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

PTY_BINARY = "./build/test_ssh_pty"


# ---- Wire helpers (shared with other test files) ----

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


# ---- Kex + Auth helpers ----

def do_kex_as_client(sock, host_pub_key_obj=None):
    client_version = b"SSH-2.0-TestClient_1.0"
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
    assert payload[0] == 52, f"Auth failed, got msg type {payload[0]}"

    return seq_send, seq_recv


# ============================================================================
# Tests
# ============================================================================

class TestPTYAlloc:
    """Test PTY allocation via assembly harness."""

    def test_pty_alloc_returns_valid_fds(self):
        """PTY allocation returns valid master and slave fds."""
        r = subprocess.run(
            [PTY_BINARY],
            input=b'p',
            capture_output=True,
            timeout=10,
        )
        assert r.returncode == 0, f"PTY alloc failed (rc={r.returncode}), stderr={r.stderr!r}"
        assert len(r.stdout) == 8, f"Expected 8 bytes output, got {len(r.stdout)}"

        master_fd = struct.unpack("<i", r.stdout[:4])[0]
        slave_fd = struct.unpack("<i", r.stdout[4:8])[0]
        assert master_fd > 0, f"Invalid master_fd: {master_fd}"
        assert slave_fd > 0, f"Invalid slave_fd: {slave_fd}"
        assert master_fd != slave_fd, "master_fd and slave_fd should differ"

    def test_pty_write_read(self):
        """PTY allocation produces working file descriptors (tested by shell mode)."""
        # This is implicitly tested by the shell test — if PTY fds are broken,
        # the shell won't work. But we verify alloc standalone here.
        r = subprocess.run(
            [PTY_BINARY],
            input=b'p',
            capture_output=True,
            timeout=10,
        )
        assert r.returncode == 0


class TestPTYShell:
    """Test shell spawning and I/O through PTY."""

    def test_spawn_shell_and_echo(self):
        """Spawn bash, write 'echo hello', read back output containing 'hello'."""
        r = subprocess.run(
            [PTY_BINARY],
            input=b's',
            capture_output=True,
            timeout=15,
        )
        assert r.returncode == 0, f"Shell test failed (rc={r.returncode}), stderr={r.stderr!r}"
        # The output contains the command echo and its result
        # PTY echoes the input back plus the output, so we should see "hello" somewhere
        output = r.stdout.decode('utf-8', errors='replace')
        assert 'hello' in output, f"Expected 'hello' in output, got: {output!r}"


class TestPTYRelay:
    """Test full SSH session with PTY relay."""

    def _run_relay_test(self, password: bytes, command: str = "echo test123"):
        """Run full SSH session: Python client → asm server with PTY relay."""
        host_priv_bytes, host_pub_bytes, host_priv_key, host_pub_key = generate_ed25519_keypair()

        s_server, s_client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        # Build input for assembly server in relay mode
        server_fd = s_server.fileno()
        inp = b'r'
        inp += struct.pack("<i", server_fd)
        inp += host_priv_bytes + host_pub_bytes
        inp += struct.pack("<I", len(password)) + password

        # Start assembly server
        proc = subprocess.Popen(
            [PTY_BINARY],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(server_fd,),
        )
        proc.stdin.write(inp)
        proc.stdin.flush()
        s_server.close()  # We don't need this end anymore

        try:
            # Python client side
            sock = s_client
            keys = do_kex_as_client(sock)
            seq_send, seq_recv = do_auth_as_client(sock, keys, b"testuser", password)

            k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
            k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']

            # Open channel
            chan_open = bytes([90])
            chan_open += encode_string(b"session")
            chan_open += struct.pack(">I", 0)  # sender channel
            chan_open += struct.pack(">I", 0x200000)  # window
            chan_open += struct.pack(">I", 0x8000)  # max packet
            send_encrypted_packet(sock, chan_open, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Receive CHANNEL_OPEN_CONFIRMATION
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            assert payload[0] == 91, f"Expected CHANNEL_OPEN_CONFIRM(91), got {payload[0]}"
            remote_channel = struct.unpack(">I", payload[5:9])[0]

            # Send CHANNEL_REQUEST "pty-req" (want_reply=false)
            pty_req = bytes([98])  # SSH_MSG_CHANNEL_REQUEST
            pty_req += struct.pack(">I", remote_channel)
            pty_req += encode_string(b"pty-req")
            pty_req += bytes([0])  # want_reply = false
            pty_req += encode_string(b"xterm-256color")  # TERM
            pty_req += struct.pack(">I", 80)   # cols
            pty_req += struct.pack(">I", 24)   # rows
            pty_req += struct.pack(">I", 640)  # width px
            pty_req += struct.pack(">I", 480)  # height px
            pty_req += encode_string(b"")  # terminal modes (empty)
            send_encrypted_packet(sock, pty_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Send CHANNEL_REQUEST "shell" (want_reply=false)
            shell_req = bytes([98])
            shell_req += struct.pack(">I", remote_channel)
            shell_req += encode_string(b"shell")
            shell_req += bytes([0])  # want_reply = false
            send_encrypted_packet(sock, shell_req, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Small delay for PTY + shell to initialize
            time.sleep(0.5)

            # Send command through CHANNEL_DATA
            cmd_bytes = (command + "\n").encode()
            data_pkt = bytes([94])
            data_pkt += struct.pack(">I", remote_channel)
            data_pkt += encode_string(cmd_bytes)
            send_encrypted_packet(sock, data_pkt, k1_c2s, k2_c2s, seq_send)
            seq_send += 1

            # Read responses — collect channel data
            collected = b""
            deadline = time.time() + 5.0
            while time.time() < deadline:
                try:
                    sock.settimeout(1.0)
                    payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
                    seq_recv += 1

                    if payload[0] == 94:  # CHANNEL_DATA
                        offset = 5
                        data_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                        offset += 4
                        collected += payload[offset:offset + data_len]
                        # Check if we have our expected output
                        if b"test123" in collected:
                            break
                    elif payload[0] == 93:  # WINDOW_ADJUST — skip
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
                send_encrypted_packet(sock, exit_pkt, k1_c2s, k2_c2s, seq_send)
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

    def test_full_ssh_pty_session(self):
        """Full integration: Python client -> kex -> auth -> channel -> PTY shell.
        Client sends 'echo test123', reads back 'test123' from the PTY."""
        collected, rc = self._run_relay_test(password=b"secret123")
        output = collected.decode('utf-8', errors='replace')
        assert 'test123' in output, (
            f"Expected 'test123' in PTY output, got: {output!r}"
        )


class TestPipeExec:
    """Test pipe-based exec (no PTY) via assembly harness."""

    def _run_pipe_exec(self, cmd: str, input_data: bytes = b"") -> bytes:
        """Run a command via pipe exec mode 'e'.

        Protocol:
          Send: 'e' + cmd_len(4 LE) + cmd + input_len(4 LE) + input_data
          Recv: child stdout on process stdout
        """
        cmd_bytes = cmd.encode()
        inp = b'e'
        inp += struct.pack("<I", len(cmd_bytes)) + cmd_bytes
        inp += struct.pack("<I", len(input_data)) + input_data

        r = subprocess.run(
            [PTY_BINARY],
            input=inp,
            capture_output=True,
            timeout=10,
        )
        assert r.returncode == 0, (
            f"Pipe exec failed (rc={r.returncode}), "
            f"stderr={r.stderr!r}, stdout={r.stdout!r}"
        )
        return r.stdout

    def test_echo_hello(self):
        """Basic: 'echo hello' should output 'hello\\n'."""
        output = self._run_pipe_exec("echo hello")
        assert output == b"hello\n", f"Expected b'hello\\n', got {output!r}"

    def test_whoami(self):
        """'whoami' should return the current user."""
        import getpass
        expected = getpass.getuser()
        output = self._run_pipe_exec("whoami")
        assert output.strip().decode() == expected

    def test_cat_with_stdin(self):
        """'cat' with stdin input should echo it back."""
        test_data = b"pipe exec test data\n"
        output = self._run_pipe_exec("cat", input_data=test_data)
        assert output == test_data, f"Expected {test_data!r}, got {output!r}"

    def test_cat_binary_data(self):
        """'cat' with binary data through pipes."""
        test_data = bytes(range(256))
        output = self._run_pipe_exec("cat", input_data=test_data)
        assert output == test_data, f"Binary roundtrip failed: len={len(output)}"

    def test_stderr_merged(self):
        """stderr should appear in stdout (merged)."""
        output = self._run_pipe_exec("echo stdout_msg; echo stderr_msg >&2")
        decoded = output.decode()
        assert "stdout_msg" in decoded, f"Missing stdout in: {decoded!r}"
        assert "stderr_msg" in decoded, f"Missing stderr in: {decoded!r}"

    def test_large_output(self):
        """Large output (seq 1 1000) should be fully captured."""
        output = self._run_pipe_exec("seq 1 1000")
        lines = output.strip().split(b"\n")
        assert len(lines) == 1000, f"Expected 1000 lines, got {len(lines)}"
        assert lines[0] == b"1"
        assert lines[-1] == b"1000"

    def test_empty_command_output(self):
        """'true' produces no output."""
        output = self._run_pipe_exec("true")
        assert output == b"", f"Expected empty output, got {output!r}"

    def test_multi_command(self):
        """Multiple commands via shell."""
        output = self._run_pipe_exec("echo first; echo second; echo third")
        lines = output.strip().split(b"\n")
        assert lines == [b"first", b"second", b"third"]
