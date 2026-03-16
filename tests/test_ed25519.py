"""Test Ed25519 against RFC 8032 test vectors."""
import subprocess, struct, os, pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BINARY = "./build/test_ed25519"

def ed25519_pubkey_asm(secret: bytes) -> bytes:
    inp = b'p' + secret
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=10)
    assert result.returncode == 0, f"Exit {result.returncode}, stderr={result.stderr}"
    assert len(result.stdout) == 32, f"Got {len(result.stdout)} bytes"
    return result.stdout

def ed25519_sign_asm(keypair: bytes, msg: bytes) -> bytes:
    inp = b's' + keypair + struct.pack("<I", len(msg)) + msg
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=10)
    assert result.returncode == 0, f"Exit {result.returncode}, stderr={result.stderr}"
    assert len(result.stdout) == 64, f"Got {len(result.stdout)} bytes"
    return result.stdout

def ed25519_verify_asm(pubkey: bytes, sig: bytes, msg: bytes) -> bool:
    inp = b'v' + pubkey + sig + struct.pack("<I", len(msg)) + msg
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=10)
    return result.returncode == 0

class TestEd25519:
    def test_rfc8032_vector1_pubkey(self):
        """RFC 8032 Section 7.1 Test Vector 1 - pubkey derivation."""
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        priv = Ed25519PrivateKey.from_private_bytes(secret)
        expected_pub = priv.public_key().public_bytes_raw()
        assert ed25519_pubkey_asm(secret) == expected_pub

    def test_rfc8032_vector1_sign(self):
        """RFC 8032 Section 7.1 Test Vector 1 - signing empty message."""
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        priv = Ed25519PrivateKey.from_private_bytes(secret)
        pubkey = priv.public_key().public_bytes_raw()
        msg = b""
        expected_sig = priv.sign(msg)
        sig = ed25519_sign_asm(secret + pubkey, msg)
        assert sig == expected_sig

    def test_rfc8032_vector1_verify(self):
        """RFC 8032 Section 7.1 Test Vector 1 - verify."""
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        priv = Ed25519PrivateKey.from_private_bytes(secret)
        pubkey = priv.public_key().public_bytes_raw()
        sig = priv.sign(b"")
        assert ed25519_verify_asm(pubkey, sig, b"")

    def test_verify_rejects_bad_sig(self):
        secret = bytes.fromhex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        priv = Ed25519PrivateKey.from_private_bytes(secret)
        pubkey = priv.public_key().public_bytes_raw()
        sig = priv.sign(b"")
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert not ed25519_verify_asm(pubkey, bytes(bad_sig), b"")

    def test_crosscheck_random(self):
        for _ in range(3):
            priv = Ed25519PrivateKey.generate()
            secret = priv.private_bytes_raw()
            pub = priv.public_key().public_bytes_raw()
            msg = os.urandom(100)
            python_sig = priv.sign(msg)
            asm_sig = ed25519_sign_asm(secret + pub, msg)
            assert asm_sig == python_sig, "Signature mismatch"
            assert ed25519_verify_asm(pub, asm_sig, msg)
