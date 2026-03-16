"""Test SSH transport layer: packet framing, KEXINIT building, net I/O."""
import subprocess, struct, os, pytest

BINARY = "./build/test_ssh_transport"


def _run(inp, expect_success=True):
    r = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    if expect_success:
        assert r.returncode == 0, f"Binary exited with {r.returncode}, stderr={r.stderr!r}"
    return r


def build_kexinit_asm():
    """Get KEXINIT payload from assembly."""
    r = _run(b'v')
    return r.stdout


def build_packet_asm(payload):
    """Build plaintext SSH packet from payload, return raw wire bytes."""
    inp = b'p' + struct.pack("<I", len(payload)) + payload
    r = _run(inp)
    return r.stdout


def parse_packet_asm(raw_packet):
    """Parse raw plaintext SSH packet, return extracted payload."""
    inp = b'r' + struct.pack("<I", len(raw_packet)) + raw_packet
    r = _run(inp)
    return r.stdout


def net_roundtrip_asm(data):
    """Send data through net_write_all -> net_read_exact via pipe."""
    inp = b'n' + struct.pack("<I", len(data)) + data
    r = _run(inp)
    return r.stdout


def python_build_plain_packet(payload):
    """Reference implementation of plaintext SSH packet building."""
    payload_len = len(payload)
    # unpadded = 4 + 1 + payload_len
    unpadded = 5 + payload_len
    remainder = unpadded % 8
    padding = (8 - remainder) % 8
    if padding < 4:
        padding += 8
    pkt_len = 1 + payload_len + padding
    packet = struct.pack(">I", pkt_len) + bytes([padding]) + payload + (b'\x00' * padding)
    return packet


def python_parse_plain_packet(raw):
    """Reference parser for plaintext SSH packet."""
    pkt_len = struct.unpack(">I", raw[:4])[0]
    pad_len = raw[4]
    payload_len = pkt_len - 1 - pad_len
    payload = raw[5:5 + payload_len]
    return payload


class TestNetIO:
    """Test net_read_exact and net_write_all via pipe roundtrip."""

    def test_small_data(self):
        data = b"Hello, world!"
        assert net_roundtrip_asm(data) == data

    def test_empty_data(self):
        data = b""
        result = net_roundtrip_asm(data)
        assert result == data

    def test_binary_data(self):
        data = bytes(range(256))
        assert net_roundtrip_asm(data) == data

    def test_large_data(self):
        data = os.urandom(8192)
        assert net_roundtrip_asm(data) == data

    def test_exact_page_size(self):
        data = os.urandom(4096)
        assert net_roundtrip_asm(data) == data


class TestPlaintextPacketBuild:
    """Test ssh_send_packet_plain builds correct wire format."""

    def test_hello_packet(self):
        payload = b"Hello SSH"
        raw = build_packet_asm(payload)

        # Decode the packet
        pkt_len = struct.unpack(">I", raw[:4])[0]
        pad_len = raw[4]
        extracted_payload = raw[5:5 + len(payload)]
        total = 4 + pkt_len

        assert len(raw) == total
        assert extracted_payload == payload
        assert pad_len >= 4
        assert (4 + 1 + len(payload) + pad_len) % 8 == 0

    def test_empty_payload(self):
        payload = b""
        raw = build_packet_asm(payload)

        pkt_len = struct.unpack(">I", raw[:4])[0]
        pad_len = raw[4]

        assert pkt_len == 1 + 0 + pad_len
        assert pad_len >= 4
        assert (4 + 1 + pad_len) % 8 == 0

    def test_single_byte(self):
        payload = b"\x15"  # SSH_MSG_NEWKEYS
        raw = build_packet_asm(payload)

        pkt_len = struct.unpack(">I", raw[:4])[0]
        pad_len = raw[4]
        assert raw[5] == 0x15
        assert pad_len >= 4
        assert (4 + 1 + 1 + pad_len) % 8 == 0

    def test_alignment_various_sizes(self):
        """Test that padding is correct for various payload sizes."""
        for size in [0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 17, 31, 32, 100, 255]:
            payload = bytes([0x42]) * size
            raw = build_packet_asm(payload)

            pkt_len = struct.unpack(">I", raw[:4])[0]
            pad_len = raw[4]

            assert pkt_len == 1 + size + pad_len, f"Failed at size {size}"
            assert pad_len >= 4, f"Padding too small at size {size}: {pad_len}"
            assert (4 + 1 + size + pad_len) % 8 == 0, f"Alignment failed at size {size}"
            assert len(raw) == 4 + pkt_len, f"Length mismatch at size {size}"

    def test_kexinit_message_type(self):
        """Build packet with KEXINIT-like payload."""
        payload = bytes([20]) + os.urandom(100)  # MSG_KEXINIT
        raw = build_packet_asm(payload)

        pkt_len = struct.unpack(">I", raw[:4])[0]
        pad_len = raw[4]
        assert raw[5] == 20
        assert pad_len >= 4


class TestPlaintextPacketParse:
    """Test ssh_recv_packet_plain correctly extracts payloads."""

    def test_roundtrip(self):
        """Build a packet then parse it, should get original payload."""
        payload = b"roundtrip test data"
        raw = build_packet_asm(payload)
        extracted = parse_packet_asm(raw)
        assert extracted == payload

    def test_roundtrip_empty(self):
        payload = b""
        raw = build_packet_asm(payload)
        extracted = parse_packet_asm(raw)
        assert extracted == payload

    def test_roundtrip_binary(self):
        payload = bytes(range(256))
        raw = build_packet_asm(payload)
        extracted = parse_packet_asm(raw)
        assert extracted == payload

    def test_roundtrip_various_sizes(self):
        for size in [1, 7, 8, 15, 16, 63, 64, 127, 128, 255, 256, 512, 1024]:
            payload = os.urandom(size)
            raw = build_packet_asm(payload)
            extracted = parse_packet_asm(raw)
            assert extracted == payload, f"Roundtrip failed at size {size}"

    def test_parse_python_built_packet(self):
        """Parse a packet built by Python reference implementation."""
        payload = b"python-built packet"
        raw = python_build_plain_packet(payload)
        extracted = parse_packet_asm(raw)
        assert extracted == payload

    def test_python_parse_asm_built_packet(self):
        """Python parses a packet built by assembly."""
        payload = b"asm-built packet"
        raw = build_packet_asm(payload)
        extracted = python_parse_plain_packet(raw)
        assert extracted == payload


class TestKEXINIT:
    """Test ssh_build_kexinit produces valid KEXINIT payload."""

    def test_message_type(self):
        payload = build_kexinit_asm()
        assert payload[0] == 20  # SSH_MSG_KEXINIT

    def test_cookie_is_16_bytes(self):
        payload = build_kexinit_asm()
        # Bytes 1-16 are the cookie (random, just check they exist)
        assert len(payload) > 17

    def test_cookie_is_random(self):
        """Two KEXINIT payloads should have different cookies."""
        p1 = build_kexinit_asm()
        p2 = build_kexinit_asm()
        assert p1[1:17] != p2[1:17]

    def test_contains_algorithms(self):
        payload = build_kexinit_asm()
        # The payload should contain our algorithm strings
        assert b"curve25519-sha256" in payload
        assert b"ssh-ed25519" in payload
        assert b"chacha20-poly1305@openssh.com" in payload
        assert b"none" in payload  # compression

    def test_parse_name_lists(self):
        """Parse the KEXINIT and verify each name-list."""
        payload = build_kexinit_asm()
        offset = 17  # skip type(1) + cookie(16)

        expected_lists = [
            b"curve25519-sha256",           # kex_algorithms
            b"ssh-ed25519",                 # server_host_key_algorithms
            b"chacha20-poly1305@openssh.com",  # encryption_c2s
            b"chacha20-poly1305@openssh.com",  # encryption_s2c
            b"hmac-sha2-256",               # mac_c2s (compat, unused with AEAD)
            b"hmac-sha2-256",               # mac_s2c
            b"none",                        # compression_c2s
            b"none",                        # compression_s2c
            b"",                            # languages_c2s
            b"",                            # languages_s2c
        ]

        for i, expected in enumerate(expected_lists):
            assert offset + 4 <= len(payload), f"Truncated at name-list {i}"
            str_len = struct.unpack(">I", payload[offset:offset+4])[0]
            offset += 4
            actual = payload[offset:offset+str_len]
            offset += str_len
            assert actual == expected, f"Name-list {i}: expected {expected!r}, got {actual!r}"

        # After name-lists: boolean(1) + uint32(4)
        assert offset + 5 <= len(payload)
        assert payload[offset] == 0  # first_kex_packet_follows = FALSE
        reserved = struct.unpack(">I", payload[offset+1:offset+5])[0]
        assert reserved == 0

    def test_total_length_reasonable(self):
        payload = build_kexinit_asm()
        # Should be: 1 + 16 + 10 name-lists + 1 + 4 = reasonable size
        # Each name-list has 4-byte length prefix
        # Total should be roughly 150-250 bytes
        assert 100 < len(payload) < 500


class TestKEXINITAsPacket:
    """Test KEXINIT sent as an SSH packet."""

    def test_kexinit_packet_roundtrip(self):
        """Build KEXINIT, wrap in packet, parse back."""
        kexinit_payload = build_kexinit_asm()
        raw_packet = build_packet_asm(kexinit_payload)
        extracted = parse_packet_asm(raw_packet)
        # Cookie is random so we can't compare byte-for-byte with another build
        # But the extracted payload should match what we built
        assert extracted == kexinit_payload
