"""Integration tests: SFTP v3 subsystem over SSH channel.

Python connects TO the assembly bind-mode binary as an SSH client,
opens a channel, requests the "sftp" subsystem, then exercises
SFTP protocol operations.

Reuses the bind-mode test harness (test_bind_mode binary).
"""
import struct
import os
import tempfile
import shutil
import time
import pytest

# Import helpers from test_bind_mode
from test_bind_mode import (
    start_bind_server,
    connect_and_setup,
    open_session_channel_as_client,
    send_encrypted_packet,
    recv_encrypted_packet,
    encode_string,
)

SFTP_BINARY = "./build/test_sftp"

# Override the bind binary path for SFTP tests
import test_bind_mode
test_bind_mode.BIND_BINARY = SFTP_BINARY

# SFTP packet types
SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2
SSH_FXP_OPEN = 3
SSH_FXP_CLOSE = 4
SSH_FXP_READ = 5
SSH_FXP_WRITE = 6
SSH_FXP_LSTAT = 7
SSH_FXP_FSTAT = 8
SSH_FXP_SETSTAT = 9
SSH_FXP_OPENDIR = 11
SSH_FXP_READDIR = 12
SSH_FXP_REMOVE = 13
SSH_FXP_MKDIR = 14
SSH_FXP_RMDIR = 15
SSH_FXP_REALPATH = 16
SSH_FXP_STAT = 17
SSH_FXP_RENAME = 18
SSH_FXP_STATUS = 101
SSH_FXP_HANDLE = 102
SSH_FXP_DATA = 103
SSH_FXP_NAME = 104
SSH_FXP_ATTRS = 105

# SFTP status codes
SSH_FX_OK = 0
SSH_FX_EOF = 1
SSH_FX_NO_SUCH_FILE = 2
SSH_FX_PERMISSION_DENIED = 3
SSH_FX_FAILURE = 4

# SFTP open flags
SSH_FXF_READ = 0x01
SSH_FXF_WRITE = 0x02
SSH_FXF_CREAT = 0x08
SSH_FXF_TRUNC = 0x10

# SFTP attr flags
SSH_FILEXFER_ATTR_SIZE = 0x01
SSH_FILEXFER_ATTR_UIDGID = 0x02
SSH_FILEXFER_ATTR_PERMISSIONS = 0x04
SSH_FILEXFER_ATTR_ACMODTIME = 0x08


# ---- SFTP packet helpers ----

def sftp_make_packet(pkt_type, request_id, payload=b""):
    """Build a complete SFTP packet with length prefix."""
    if pkt_type == SSH_FXP_INIT:
        # INIT has no request_id, payload is version
        inner = struct.pack(">BI", pkt_type, request_id)  # type + version
    else:
        inner = struct.pack(">BI", pkt_type, request_id) + payload
    return struct.pack(">I", len(inner)) + inner


def sftp_make_attrs(permissions=None):
    """Build minimal SFTP attrs."""
    flags = 0
    data = b""
    if permissions is not None:
        flags |= SSH_FILEXFER_ATTR_PERMISSIONS
        data += struct.pack(">I", permissions)
    return struct.pack(">I", flags) + data


def send_sftp_packet(sock, keys, seq_send, remote_ch, sftp_pkt):
    """Send an SFTP packet as SSH channel data."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    pkt = bytes([94])  # SSH_MSG_CHANNEL_DATA
    pkt += struct.pack(">I", remote_ch)
    pkt += encode_string(sftp_pkt)
    send_encrypted_packet(sock, pkt, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def recv_sftp_response(sock, keys, seq_recv, timeout_sec=10.0):
    """Receive channel data containing an SFTP response.
    Returns (sftp_type, request_id_or_version, payload, seq_recv).
    """
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    deadline = time.time() + timeout_sec

    while time.time() < deadline:
        try:
            sock.settimeout(min(2.0, deadline - time.time()))
            ssh_payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1

            if ssh_payload is None:
                continue

            msg_type = ssh_payload[0]

            if msg_type == 94:  # CHANNEL_DATA
                # Parse: [byte 94][uint32 recipient][string data]
                data_len = struct.unpack(">I", ssh_payload[5:9])[0]
                data = ssh_payload[9:9 + data_len]

                if len(data) < 5:
                    continue

                sftp_pkt_len = struct.unpack(">I", data[:4])[0]
                sftp_type = data[4]

                if sftp_type == SSH_FXP_VERSION:
                    # VERSION: [uint32 version] (no request_id)
                    version = struct.unpack(">I", data[5:9])[0]
                    return (sftp_type, version, data[9:4+sftp_pkt_len], seq_recv)
                else:
                    if len(data) < 9:
                        continue
                    request_id = struct.unpack(">I", data[5:9])[0]
                    payload = data[9:4+sftp_pkt_len]
                    return (sftp_type, request_id, payload, seq_recv)

            elif msg_type == 93:  # WINDOW_ADJUST
                continue
            elif msg_type in (99, 100):  # SUCCESS/FAILURE
                continue
            elif msg_type in (96, 97):  # EOF/CLOSE
                return (None, 0, b"", seq_recv)
        except Exception:
            if time.time() >= deadline:
                break
            continue

    raise TimeoutError("No SFTP response received")


def send_subsystem_request(sock, keys, seq_send, remote_ch, subsystem_name, want_reply=True):
    """Send SSH_MSG_CHANNEL_REQUEST for subsystem."""
    k1_c2s, k2_c2s = keys['k1_c2s'], keys['k2_c2s']
    pkt = bytes([98])  # SSH_MSG_CHANNEL_REQUEST
    pkt += struct.pack(">I", remote_ch)
    pkt += encode_string(b"subsystem")
    pkt += bytes([1 if want_reply else 0])
    pkt += encode_string(subsystem_name.encode() if isinstance(subsystem_name, str) else subsystem_name)
    send_encrypted_packet(sock, pkt, k1_c2s, k2_c2s, seq_send)
    return seq_send + 1


def wait_for_channel_success(sock, keys, seq_recv, timeout_sec=5.0):
    """Wait for CHANNEL_SUCCESS (99) response."""
    k1_s2c, k2_s2c = keys['k1_s2c'], keys['k2_s2c']
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            sock.settimeout(min(2.0, deadline - time.time()))
            payload = recv_encrypted_packet(sock, k1_s2c, k2_s2c, seq_recv)
            seq_recv += 1
            if payload[0] == 99:  # CHANNEL_SUCCESS
                return True, seq_recv
            elif payload[0] == 100:  # CHANNEL_FAILURE
                return False, seq_recv
            elif payload[0] == 93:  # WINDOW_ADJUST
                continue
        except Exception:
            break
    return False, seq_recv


def parse_sftp_status(payload):
    """Parse SSH_FXP_STATUS payload -> status_code."""
    if len(payload) < 4:
        return -1
    return struct.unpack(">I", payload[:4])[0]


def parse_sftp_handle(payload):
    """Parse SSH_FXP_HANDLE payload -> handle bytes."""
    if len(payload) < 4:
        return None
    handle_len = struct.unpack(">I", payload[:4])[0]
    return payload[4:4 + handle_len]


def parse_sftp_data(payload):
    """Parse SSH_FXP_DATA payload -> data bytes."""
    if len(payload) < 4:
        return b""
    data_len = struct.unpack(">I", payload[:4])[0]
    return payload[4:4 + data_len]


def parse_sftp_name(payload):
    """Parse SSH_FXP_NAME payload -> list of (filename, longname, attrs_raw)."""
    if len(payload) < 4:
        return []
    count = struct.unpack(">I", payload[:4])[0]
    offset = 4
    entries = []
    for _ in range(count):
        if offset + 4 > len(payload):
            break
        fname_len = struct.unpack(">I", payload[offset:offset+4])[0]
        offset += 4
        fname = payload[offset:offset+fname_len]
        offset += fname_len

        if offset + 4 > len(payload):
            break
        lname_len = struct.unpack(">I", payload[offset:offset+4])[0]
        offset += 4
        lname = payload[offset:offset+lname_len]
        offset += lname_len

        # Parse attrs (at least flags)
        if offset + 4 > len(payload):
            break
        attr_flags = struct.unpack(">I", payload[offset:offset+4])[0]
        attr_start = offset
        offset += 4
        if attr_flags & SSH_FILEXFER_ATTR_SIZE:
            offset += 8
        if attr_flags & SSH_FILEXFER_ATTR_UIDGID:
            offset += 8
        if attr_flags & SSH_FILEXFER_ATTR_PERMISSIONS:
            offset += 4
        if attr_flags & SSH_FILEXFER_ATTR_ACMODTIME:
            offset += 8

        entries.append((fname, lname, payload[attr_start:offset]))
    return entries


def parse_sftp_attrs(payload):
    """Parse SSH_FXP_ATTRS payload -> dict."""
    if len(payload) < 4:
        return {}
    flags = struct.unpack(">I", payload[:4])[0]
    offset = 4
    attrs = {'flags': flags}
    if flags & SSH_FILEXFER_ATTR_SIZE:
        attrs['size'] = struct.unpack(">Q", payload[offset:offset+8])[0]
        offset += 8
    if flags & SSH_FILEXFER_ATTR_UIDGID:
        attrs['uid'] = struct.unpack(">I", payload[offset:offset+4])[0]
        attrs['gid'] = struct.unpack(">I", payload[offset+4:offset+8])[0]
        offset += 8
    if flags & SSH_FILEXFER_ATTR_PERMISSIONS:
        attrs['permissions'] = struct.unpack(">I", payload[offset:offset+4])[0]
        offset += 4
    if flags & SSH_FILEXFER_ATTR_ACMODTIME:
        attrs['atime'] = struct.unpack(">I", payload[offset:offset+4])[0]
        attrs['mtime'] = struct.unpack(">I", payload[offset+4:offset+8])[0]
        offset += 8
    return attrs


# ---- SFTP high-level operations ----

def sftp_init(sock, keys, seq_send, seq_recv, remote_ch):
    """Send SFTP INIT, receive VERSION."""
    pkt = sftp_make_packet(SSH_FXP_INIT, 3)  # version=3
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, version, payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_VERSION, f"Expected VERSION, got type {resp_type}"
    assert version == 3, f"Expected version 3, got {version}"
    return seq_send, seq_recv


def sftp_open(sock, keys, seq_send, seq_recv, remote_ch, path, pflags, req_id=1):
    """Open a file, return handle."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    payload += struct.pack(">I", pflags)
    payload += sftp_make_attrs()
    pkt = sftp_make_packet(SSH_FXP_OPEN, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_HANDLE, (
        f"Expected HANDLE(102), got type {resp_type}"
        + (f" status={parse_sftp_status(resp_payload)}" if resp_type == SSH_FXP_STATUS else "")
    )
    assert rid == req_id
    handle = parse_sftp_handle(resp_payload)
    return handle, seq_send, seq_recv


def sftp_close(sock, keys, seq_send, seq_recv, remote_ch, handle, req_id=2):
    """Close a handle."""
    payload = encode_string(handle)
    pkt = sftp_make_packet(SSH_FXP_CLOSE, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_read(sock, keys, seq_send, seq_recv, remote_ch, handle, offset, length, req_id=3):
    """Read from file handle. Returns data or raises on EOF/error."""
    payload = encode_string(handle)
    payload += struct.pack(">Q", offset)
    payload += struct.pack(">I", length)
    pkt = sftp_make_packet(SSH_FXP_READ, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert rid == req_id
    if resp_type == SSH_FXP_DATA:
        return parse_sftp_data(resp_payload), seq_send, seq_recv
    elif resp_type == SSH_FXP_STATUS:
        status = parse_sftp_status(resp_payload)
        if status == SSH_FX_EOF:
            return None, seq_send, seq_recv
        raise RuntimeError(f"SFTP read error: status {status}")
    raise RuntimeError(f"Unexpected response type {resp_type}")


def sftp_write(sock, keys, seq_send, seq_recv, remote_ch, handle, offset, data, req_id=4):
    """Write to file handle."""
    payload = encode_string(handle)
    payload += struct.pack(">Q", offset)
    payload += encode_string(data)
    pkt = sftp_make_packet(SSH_FXP_WRITE, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_stat(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=5):
    """Stat a path."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    pkt = sftp_make_packet(SSH_FXP_STAT, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert rid == req_id
    if resp_type == SSH_FXP_ATTRS:
        return parse_sftp_attrs(resp_payload), seq_send, seq_recv
    elif resp_type == SSH_FXP_STATUS:
        status = parse_sftp_status(resp_payload)
        raise RuntimeError(f"SFTP stat error: status {status}")
    raise RuntimeError(f"Unexpected response type {resp_type}")


def sftp_realpath(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=6):
    """Resolve a path."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    pkt = sftp_make_packet(SSH_FXP_REALPATH, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_NAME, f"Expected NAME, got type {resp_type}"
    assert rid == req_id
    entries = parse_sftp_name(resp_payload)
    assert len(entries) == 1
    return entries[0][0].decode(), seq_send, seq_recv


def sftp_mkdir(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=7):
    """Create a directory."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    payload += sftp_make_attrs(permissions=0o755)
    pkt = sftp_make_packet(SSH_FXP_MKDIR, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_rmdir(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=8):
    """Remove a directory."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    pkt = sftp_make_packet(SSH_FXP_RMDIR, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_remove(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=9):
    """Remove a file."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    pkt = sftp_make_packet(SSH_FXP_REMOVE, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_rename(sock, keys, seq_send, seq_recv, remote_ch, oldpath, newpath, req_id=10):
    """Rename a file."""
    payload = encode_string(oldpath.encode() if isinstance(oldpath, str) else oldpath)
    payload += encode_string(newpath.encode() if isinstance(newpath, str) else newpath)
    pkt = sftp_make_packet(SSH_FXP_RENAME, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_STATUS, f"Expected STATUS, got type {resp_type}"
    assert rid == req_id
    status = parse_sftp_status(resp_payload)
    assert status == SSH_FX_OK, f"Expected OK, got status {status}"
    return seq_send, seq_recv


def sftp_opendir(sock, keys, seq_send, seq_recv, remote_ch, path, req_id=11):
    """Open directory, return handle."""
    payload = encode_string(path.encode() if isinstance(path, str) else path)
    pkt = sftp_make_packet(SSH_FXP_OPENDIR, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert resp_type == SSH_FXP_HANDLE, f"Expected HANDLE, got type {resp_type}"
    assert rid == req_id
    handle = parse_sftp_handle(resp_payload)
    return handle, seq_send, seq_recv


def sftp_readdir(sock, keys, seq_send, seq_recv, remote_ch, handle, req_id=12):
    """Read directory entries. Returns list of entries or None on EOF."""
    payload = encode_string(handle)
    pkt = sftp_make_packet(SSH_FXP_READDIR, req_id, payload)
    seq_send = send_sftp_packet(sock, keys, seq_send, remote_ch, pkt)
    resp_type, rid, resp_payload, seq_recv = recv_sftp_response(sock, keys, seq_recv)
    assert rid == req_id
    if resp_type == SSH_FXP_NAME:
        return parse_sftp_name(resp_payload), seq_send, seq_recv
    elif resp_type == SSH_FXP_STATUS:
        status = parse_sftp_status(resp_payload)
        if status == SSH_FX_EOF:
            return None, seq_send, seq_recv
        raise RuntimeError(f"readdir error: status {status}")
    raise RuntimeError(f"Unexpected response type {resp_type}")


# ---- Fixture for SFTP session ----

class SFTPSession:
    """Manages an SFTP session for tests."""

    def __init__(self):
        self.proc = None
        self.sock = None
        self.keys = None
        self.seq_send = 3
        self.seq_recv = 3
        self.remote_ch = 0
        self.recipient = 0
        self.req_counter = 100

    def next_id(self):
        self.req_counter += 1
        return self.req_counter

    def setup(self):
        self.proc, port, host_pub = start_bind_server(b"sftp_test_pw")
        self.sock, self.keys, self.seq_send, self.seq_recv = connect_and_setup(
            port, host_pub, b"sftp_test_pw"
        )
        # Open session channel
        self.remote_ch, self.recipient, self.seq_send, self.seq_recv = (
            open_session_channel_as_client(
                self.sock, self.keys, self.seq_send, self.seq_recv,
                sender_channel_id=0
            )
        )
        # Request sftp subsystem
        self.seq_send = send_subsystem_request(
            self.sock, self.keys, self.seq_send, self.remote_ch, "sftp"
        )
        success, self.seq_recv = wait_for_channel_success(
            self.sock, self.keys, self.seq_recv
        )
        assert success, "Subsystem request failed"

        # SFTP init/version exchange
        self.seq_send, self.seq_recv = sftp_init(
            self.sock, self.keys, self.seq_send, self.seq_recv, self.remote_ch
        )

    def teardown(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.proc:
            try:
                self.proc.kill()
                self.proc.wait()
            except Exception:
                pass


@pytest.fixture
def sftp_session():
    sess = SFTPSession()
    sess.setup()
    yield sess
    sess.teardown()


@pytest.fixture
def tmp_dir():
    """Create a temporary directory for file operations."""
    d = tempfile.mkdtemp(prefix="sftp_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


# ============================================================================
# Tests
# ============================================================================

class TestSFTP:
    """SFTP subsystem integration tests."""

    def test_sftp_version_exchange(self):
        """INIT -> VERSION(3) exchange."""
        sess = SFTPSession()
        sess.proc, port, host_pub = start_bind_server(b"sftp_ver_pw")
        try:
            sess.sock, sess.keys, sess.seq_send, sess.seq_recv = connect_and_setup(
                port, host_pub, b"sftp_ver_pw"
            )
            sess.remote_ch, sess.recipient, sess.seq_send, sess.seq_recv = (
                open_session_channel_as_client(
                    sess.sock, sess.keys, sess.seq_send, sess.seq_recv,
                    sender_channel_id=0
                )
            )
            sess.seq_send = send_subsystem_request(
                sess.sock, sess.keys, sess.seq_send, sess.remote_ch, "sftp"
            )
            success, sess.seq_recv = wait_for_channel_success(
                sess.sock, sess.keys, sess.seq_recv
            )
            assert success, "Subsystem request should succeed"

            # Send INIT
            pkt = sftp_make_packet(SSH_FXP_INIT, 3)
            sess.seq_send = send_sftp_packet(
                sess.sock, sess.keys, sess.seq_send, sess.remote_ch, pkt
            )

            # Receive VERSION
            resp_type, version, payload, sess.seq_recv = recv_sftp_response(
                sess.sock, sess.keys, sess.seq_recv
            )
            assert resp_type == SSH_FXP_VERSION
            assert version == 3
        finally:
            sess.teardown()

    def test_sftp_open_read_close(self, sftp_session, tmp_dir):
        """Open a file, read its contents, close."""
        s = sftp_session
        # Create a test file on disk
        test_file = os.path.join(tmp_dir, "readtest.txt")
        test_content = b"Hello from SFTP read test!\n"
        with open(test_file, "wb") as f:
            f.write(test_content)

        # Open
        rid = s.next_id()
        handle, s.seq_send, s.seq_recv = sftp_open(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, SSH_FXF_READ, req_id=rid
        )
        assert handle is not None

        # Read
        rid = s.next_id()
        data, s.seq_send, s.seq_recv = sftp_read(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, 0, 4096, req_id=rid
        )
        assert data == test_content, f"Expected {test_content!r}, got {data!r}"

        # Close
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_close(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, req_id=rid
        )

    def test_sftp_write_file(self, sftp_session, tmp_dir):
        """Open for write+create, write data, close, verify on disk."""
        s = sftp_session
        test_file = os.path.join(tmp_dir, "writetest.txt")
        write_data = b"Written via SFTP subsystem!\n"

        # Open for write+create+trunc
        rid = s.next_id()
        handle, s.seq_send, s.seq_recv = sftp_open(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
            req_id=rid
        )

        # Write
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_write(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, 0, write_data, req_id=rid
        )

        # Close
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_close(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, req_id=rid
        )

        # Verify on disk
        with open(test_file, "rb") as f:
            assert f.read() == write_data

    def test_sftp_stat(self, sftp_session, tmp_dir):
        """Stat a file, verify size and permissions."""
        s = sftp_session
        test_file = os.path.join(tmp_dir, "stattest.txt")
        test_content = b"stat test content 12345"
        with open(test_file, "wb") as f:
            f.write(test_content)
        os.chmod(test_file, 0o644)

        rid = s.next_id()
        attrs, s.seq_send, s.seq_recv = sftp_stat(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, req_id=rid
        )

        assert 'size' in attrs
        assert attrs['size'] == len(test_content), (
            f"Expected size {len(test_content)}, got {attrs['size']}"
        )
        assert 'permissions' in attrs
        # Check file type bits (regular file = 0o100000) + permission bits
        assert (attrs['permissions'] & 0o777) == 0o644, (
            f"Expected 0644, got {oct(attrs['permissions'] & 0o777)}"
        )

    def test_sftp_mkdir_rmdir(self, sftp_session, tmp_dir):
        """Create directory, verify, remove."""
        s = sftp_session
        test_dir = os.path.join(tmp_dir, "testdir")

        # mkdir
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_mkdir(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_dir, req_id=rid
        )
        assert os.path.isdir(test_dir)

        # rmdir
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_rmdir(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_dir, req_id=rid
        )
        assert not os.path.exists(test_dir)

    def test_sftp_readdir(self, sftp_session, tmp_dir):
        """Create files in temp dir, opendir, readdir, verify listing."""
        s = sftp_session
        # Create some test files
        test_files = ["file_a.txt", "file_b.txt", "file_c.txt"]
        for fname in test_files:
            with open(os.path.join(tmp_dir, fname), "w") as f:
                f.write("test")

        # opendir
        rid = s.next_id()
        handle, s.seq_send, s.seq_recv = sftp_opendir(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            tmp_dir, req_id=rid
        )

        # readdir (collect all entries)
        all_names = []
        for _ in range(10):  # max iterations
            rid = s.next_id()
            entries, s.seq_send, s.seq_recv = sftp_readdir(
                s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
                handle, req_id=rid
            )
            if entries is None:  # EOF
                break
            for fname, lname, attrs in entries:
                all_names.append(fname.decode())

        # Close
        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_close(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, req_id=rid
        )

        # Verify all test files are listed (plus . and ..)
        for fname in test_files:
            assert fname in all_names, (
                f"Expected {fname} in listing, got: {all_names}"
            )
        assert "." in all_names
        assert ".." in all_names

    def test_sftp_remove(self, sftp_session, tmp_dir):
        """Create file, remove via SFTP, verify gone."""
        s = sftp_session
        test_file = os.path.join(tmp_dir, "to_remove.txt")
        with open(test_file, "w") as f:
            f.write("delete me")

        assert os.path.exists(test_file)

        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_remove(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, req_id=rid
        )
        assert not os.path.exists(test_file)

    def test_sftp_rename(self, sftp_session, tmp_dir):
        """Create file, rename via SFTP, verify."""
        s = sftp_session
        old_path = os.path.join(tmp_dir, "old_name.txt")
        new_path = os.path.join(tmp_dir, "new_name.txt")
        with open(old_path, "w") as f:
            f.write("rename me")

        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_rename(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            old_path, new_path, req_id=rid
        )
        assert not os.path.exists(old_path)
        assert os.path.exists(new_path)
        with open(new_path) as f:
            assert f.read() == "rename me"

    def test_sftp_realpath(self, sftp_session):
        """Resolve '.' to current working directory."""
        s = sftp_session
        rid = s.next_id()
        path, s.seq_send, s.seq_recv = sftp_realpath(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            ".", req_id=rid
        )
        # Should return an absolute path
        assert path.startswith("/"), f"Expected absolute path, got {path!r}"
        # Should match cwd
        assert path == os.getcwd(), f"Expected {os.getcwd()!r}, got {path!r}"

    def test_sftp_binary_file(self, sftp_session, tmp_dir):
        """Write/read binary data containing all 256 byte values."""
        s = sftp_session
        test_file = os.path.join(tmp_dir, "binary_test.bin")

        # All 256 byte values
        binary_data = bytes(range(256))

        # Write
        rid = s.next_id()
        handle, s.seq_send, s.seq_recv = sftp_open(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
            req_id=rid
        )

        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_write(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, 0, binary_data, req_id=rid
        )

        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_close(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, req_id=rid
        )

        # Read back
        rid = s.next_id()
        handle, s.seq_send, s.seq_recv = sftp_open(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            test_file, SSH_FXF_READ, req_id=rid
        )

        rid = s.next_id()
        data, s.seq_send, s.seq_recv = sftp_read(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, 0, 4096, req_id=rid
        )

        assert data == binary_data, (
            f"Binary data mismatch: got {len(data)} bytes, expected {len(binary_data)}"
        )

        rid = s.next_id()
        s.seq_send, s.seq_recv = sftp_close(
            s.sock, s.keys, s.seq_send, s.seq_recv, s.remote_ch,
            handle, req_id=rid
        )
