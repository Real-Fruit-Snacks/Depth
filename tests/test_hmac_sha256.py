"""Test HMAC-SHA256 against RFC 4231 test vectors and Python's hmac module."""
import subprocess, hmac, hashlib, os, struct, pytest

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_hmac_sha256")


def hmac_sha256_asm(key: bytes, msg: bytes) -> bytes:
    """Call the assembly HMAC-SHA256 via the test harness binary."""
    inp = struct.pack("<I", len(key)) + key + struct.pack("<I", len(msg)) + msg
    result = subprocess.run(
        [BINARY], input=inp, capture_output=True, timeout=30
    )
    assert result.returncode == 0, f"Binary exited with {result.returncode}"
    assert len(result.stdout) == 32, f"Expected 32 bytes, got {len(result.stdout)}"
    return result.stdout


def python_hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """Reference implementation using Python's hmac module."""
    return hmac.new(key, msg, hashlib.sha256).digest()


class TestHMACSHA256:
    """RFC 4231 test vectors for HMAC-SHA256."""

    def test_rfc4231_case1(self):
        """Test Case 1: Short key, short data."""
        key = b"\x0b" * 20
        data = b"Hi There"
        expected = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case2(self):
        """Test Case 2: Key = 'Jefe'."""
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case3(self):
        """Test Case 3: Key and data are 0xaa/0xdd patterns."""
        key = b"\xaa" * 20
        data = b"\xdd" * 50
        expected = bytes.fromhex(
            "773ea91e36800e46854db8ebd09181a7"
            "2959098b3ef8c122d9635514ced565fe"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case4(self):
        """Test Case 4: Combined key and data."""
        key = bytes(range(0x01, 0x1a))  # 0x01..0x19 = 25 bytes
        data = b"\xcd" * 50
        expected = bytes.fromhex(
            "82558a389a443c0ea4cc819899f2083a"
            "85f0faa3e578f8077a2e3ff46729665b"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case5(self):
        """Test Case 5: Truncated HMAC (we check full 32 bytes)."""
        key = b"\x0c" * 20
        data = b"Test With Truncation"
        # Full HMAC-SHA256 (not truncated)
        expected = python_hmac_sha256(key, data)
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case6(self):
        """Test Case 6: Key longer than block size (131 > 64 bytes)."""
        key = b"\xaa" * 131
        data = b"Test Using Larger Than Block-Size Key - Hash Key First"
        expected = bytes.fromhex(
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_rfc4231_case7(self):
        """Test Case 7: Key and data both longer than block size."""
        key = b"\xaa" * 131
        data = (
            b"This is a test using a larger than block-size key "
            b"and a larger than block-size data. The key needs to "
            b"be hashed before being used by the HMAC algorithm."
        )
        expected = bytes.fromhex(
            "9b09ffa71b942fcb27635fbcd5b0e944"
            "bfdc63644f0713938a7f51535c3a35e2"
        )
        assert hmac_sha256_asm(key, data) == expected

    def test_empty_message(self):
        """HMAC with empty message."""
        key = b"key"
        msg = b""
        expected = python_hmac_sha256(key, msg)
        assert hmac_sha256_asm(key, msg) == expected

    def test_empty_key(self):
        """HMAC with empty key (zero-length key, padded to 64 zero bytes)."""
        key = b""
        msg = b"message"
        expected = python_hmac_sha256(key, msg)
        assert hmac_sha256_asm(key, msg) == expected

    def test_exact_block_size_key(self):
        """HMAC with key exactly 64 bytes (block size)."""
        key = os.urandom(64)
        msg = b"test message with exact block size key"
        expected = python_hmac_sha256(key, msg)
        assert hmac_sha256_asm(key, msg) == expected

    def test_key_65_bytes(self):
        """HMAC with key one byte over block size (triggers hashing)."""
        key = os.urandom(65)
        msg = b"test with 65-byte key"
        expected = python_hmac_sha256(key, msg)
        assert hmac_sha256_asm(key, msg) == expected

    def test_crosscheck_random(self):
        """Cross-check with Python hmac for various sizes."""
        for key_size in [1, 16, 32, 64, 65, 128, 256]:
            for msg_size in [0, 1, 55, 56, 64, 100, 512]:
                key = os.urandom(key_size)
                msg = os.urandom(msg_size)
                expected = python_hmac_sha256(key, msg)
                result = hmac_sha256_asm(key, msg)
                assert result == expected, (
                    f"Failed: key_size={key_size}, msg_size={msg_size}"
                )
