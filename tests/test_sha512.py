"""Test SHA-512 against FIPS 180-4 test vectors and hashlib."""
import subprocess, hashlib, os, struct, pytest

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_sha512")


def sha512_asm(msg: bytes) -> bytes:
    inp = struct.pack("<I", len(msg)) + msg
    result = subprocess.run(
        [BINARY], input=inp, capture_output=True, timeout=30
    )
    assert result.returncode == 0, f"Binary exited with {result.returncode}"
    assert len(result.stdout) == 64, f"Expected 64 bytes, got {len(result.stdout)}"
    return result.stdout


class TestSHA512:
    def test_empty(self):
        assert sha512_asm(b"") == hashlib.sha512(b"").digest()

    def test_abc(self):
        expected = bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        assert sha512_asm(b"abc") == expected

    def test_two_block(self):
        msg = (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        )
        expected = bytes.fromhex(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )
        assert sha512_asm(msg) == expected

    def test_crosscheck_random(self):
        for size in [0, 1, 55, 64, 100, 111, 112, 127, 128, 256, 1000]:
            msg = os.urandom(size)
            assert sha512_asm(msg) == hashlib.sha512(msg).digest(), \
                f"Failed at size {size}"
