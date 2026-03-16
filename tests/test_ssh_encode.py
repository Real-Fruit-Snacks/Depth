"""Test SSH wire encoding."""
import subprocess, struct, os, pytest

BINARY = "./build/test_ssh_encode"

def encode_uint32_asm(value):
    inp = b'u' + struct.pack("<I", value)
    r = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    assert r.returncode == 0
    return r.stdout

def encode_string_asm(data):
    inp = b's' + struct.pack("<I", len(data)) + data
    r = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    assert r.returncode == 0
    return r.stdout

def encode_mpint_asm(data_le):
    inp = b'm' + struct.pack("<I", len(data_le)) + data_le
    r = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    assert r.returncode == 0
    return r.stdout

class TestEncodeUint32:
    def test_zero(self):
        assert encode_uint32_asm(0) == b'\x00\x00\x00\x00'
    def test_443(self):
        assert encode_uint32_asm(443) == b'\x00\x00\x01\xbb'
    def test_max(self):
        assert encode_uint32_asm(0xFFFFFFFF) == b'\xff\xff\xff\xff'

class TestEncodeString:
    def test_empty(self):
        assert encode_string_asm(b"") == b'\x00\x00\x00\x00'
    def test_ssh_ed25519(self):
        assert encode_string_asm(b"ssh-ed25519") == b'\x00\x00\x00\x0bssh-ed25519'
    def test_algorithm_list(self):
        data = b"curve25519-sha256"
        result = encode_string_asm(data)
        assert result == struct.pack(">I", len(data)) + data

class TestEncodeMpint:
    def test_zero(self):
        # mpint 0 = length 0, no bytes
        assert encode_mpint_asm(b'\x00') == b'\x00\x00\x00\x00'
    def test_small(self):
        # value 9 in LE = 0x09, in mpint = [len=1][0x09]
        assert encode_mpint_asm(b'\x09') == b'\x00\x00\x00\x01\x09'
    def test_high_bit(self):
        # value 0x80 in LE = 0x80, needs sign byte: [len=2][0x00][0x80]
        assert encode_mpint_asm(b'\x80') == b'\x00\x00\x00\x02\x00\x80'
    def test_x25519_output(self):
        # 32 bytes LE, typical X25519 output
        data = os.urandom(32)
        result = encode_mpint_asm(data)
        # Verify: reverse to BE, strip leading zeros, add sign byte if needed
        be = data[::-1]
        while len(be) > 1 and be[0] == 0:
            be = be[1:]
        if be[0] & 0x80:
            be = b'\x00' + be
        expected = struct.pack(">I", len(be)) + be
        assert result == expected
