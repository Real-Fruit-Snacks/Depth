"""Test SHA-256 against RFC 6234 test vectors and hashlib."""
import subprocess, hashlib, os, struct, pytest

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_sha256")


def sha256_asm(msg: bytes) -> bytes:
    inp = struct.pack("<I", len(msg)) + msg
    result = subprocess.run(
        [BINARY], input=inp, capture_output=True, timeout=30
    )
    assert result.returncode == 0, f"Binary exited with {result.returncode}"
    assert len(result.stdout) == 32, f"Expected 32 bytes, got {len(result.stdout)}"
    return result.stdout


class TestSHA256:
    def test_empty(self):
        expected = hashlib.sha256(b"").digest()
        assert sha256_asm(b"") == expected

    def test_abc(self):
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        )
        assert sha256_asm(b"abc") == expected

    def test_448bit(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = bytes.fromhex(
            "248d6a61d20638b8e5c026930c3e6039"
            "a33ce45964ff2167f6ecedd419db06c1"
        )
        assert sha256_asm(msg) == expected

    def test_million_a(self):
        msg = b"a" * 1000000
        expected = bytes.fromhex(
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0"
        )
        assert sha256_asm(msg) == expected

    def test_crosscheck_random(self):
        for size in [0, 1, 55, 56, 64, 100, 1000, 65536]:
            msg = os.urandom(size)
            assert sha256_asm(msg) == hashlib.sha256(msg).digest(), \
                f"Failed at size {size}"
