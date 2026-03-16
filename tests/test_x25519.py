"""Test X25519 against RFC 7748 test vectors."""
import subprocess, os, pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_x25519")


def x25519_asm(scalar: bytes, point: bytes) -> bytes:
    inp = scalar + point
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    assert result.returncode == 0, f"Exit {result.returncode}, stderr: {result.stderr}"
    assert len(result.stdout) == 32, f"Expected 32 bytes, got {len(result.stdout)}"
    return result.stdout


class TestX25519:
    def test_rfc7748_vector1(self):
        scalar = bytes.fromhex(
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
        )
        point = bytes.fromhex(
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
        )
        expected = bytes.fromhex(
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        )
        assert x25519_asm(scalar, point) == expected

    def test_rfc7748_vector2(self):
        scalar = bytes.fromhex(
            "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
        )
        point = bytes.fromhex(
            "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
        )
        expected = bytes.fromhex(
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        )
        assert x25519_asm(scalar, point) == expected

    def test_basepoint_rfc7748(self):
        scalar = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        basepoint = b"\x09" + b"\x00" * 31
        expected = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )
        assert x25519_asm(scalar, basepoint) == expected

    def test_crosscheck_random(self):
        for _ in range(5):
            priv = X25519PrivateKey.generate()
            pub = X25519PrivateKey.generate().public_key()
            priv_bytes = priv.private_bytes_raw()
            pub_bytes = pub.public_bytes_raw()
            expected = priv.exchange(pub)
            assert x25519_asm(priv_bytes, pub_bytes) == expected
