"""Test chacha20-poly1305@openssh.com against Python reference implementation."""
import subprocess, struct, os, pytest

BINARY = "./build/test_ssh_aead"


def _run(inp, expect_success=True):
    r = subprocess.run([BINARY], input=inp, capture_output=True, timeout=5)
    if expect_success:
        assert r.returncode == 0, f"Binary exited with {r.returncode}"
    return r


def encrypt_asm(k1, k2, seq, payload):
    inp = b'e' + k1 + k2 + struct.pack("<I", seq) + struct.pack("<I", len(payload)) + payload
    r = _run(inp)
    return r.stdout


def decrypt_asm(k1, k2, seq, data):
    inp = b'd' + k1 + k2 + struct.pack("<I", seq) + struct.pack("<I", len(data)) + data
    return _run(inp, expect_success=False)


def decrypt_length_asm(k2, seq, enc_len_bytes):
    inp = b'l' + k2 + struct.pack("<I", seq) + enc_len_bytes
    r = _run(inp)
    return struct.unpack("<I", r.stdout)[0]


def python_chacha20_block(key, counter, nonce_12):
    """Generate 64-byte ChaCha20 keystream block."""
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    # ChaCha20 from cryptography uses 16-byte nonce = counter(4 LE) + nonce(12)
    full_nonce = struct.pack("<I", counter) + nonce_12
    cipher = Cipher(ChaCha20(key, full_nonce), None).encryptor()
    return cipher.update(b'\x00' * 64)


def python_chacha20_encrypt(key, counter, nonce_12, plaintext):
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
    full_nonce = struct.pack("<I", counter) + nonce_12
    cipher = Cipher(ChaCha20(key, full_nonce), None).encryptor()
    return cipher.update(plaintext)


def python_ssh_aead_encrypt(payload, k1, k2, seq):
    """Reference implementation of SSH chacha20-poly1305 AEAD."""
    from cryptography.hazmat.primitives.poly1305 import Poly1305

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)

    # Encrypt length with K2, counter=0
    plain_len = struct.pack(">I", len(payload))
    ks = python_chacha20_block(k2, 0, nonce)
    enc_len = bytes(a ^ b for a, b in zip(plain_len, ks[:4]))

    # Generate Poly1305 key with K1, counter=0
    poly_key = python_chacha20_block(k1, 0, nonce)[:32]

    # Encrypt payload with K1, counter=1
    enc_payload = python_chacha20_encrypt(k1, 1, nonce, payload)

    # MAC over enc_length || enc_payload
    mac = Poly1305.generate_tag(poly_key, enc_len + enc_payload)

    return enc_len + enc_payload + mac


def python_ssh_aead_decrypt(data, k1, k2, seq):
    """Reference decrypt. Returns payload or None on MAC failure."""
    from cryptography.hazmat.primitives.poly1305 import Poly1305
    from cryptography.exceptions import InvalidSignature

    nonce = b'\x00' * 4 + struct.pack(">Q", seq)

    enc_len = data[:4]
    mac = data[-16:]
    enc_payload = data[4:-16]

    # Generate Poly1305 key
    poly_key = python_chacha20_block(k1, 0, nonce)[:32]

    # Verify MAC
    try:
        Poly1305.verify_tag(poly_key, enc_len + enc_payload, mac)
    except InvalidSignature:
        return None

    # Decrypt payload
    payload = python_chacha20_encrypt(k1, 1, nonce, enc_payload)
    return payload


class TestSSHAEAD:
    """Test encrypt/decrypt roundtrip through assembly."""

    def test_encrypt_decrypt_roundtrip(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"Hello SSH!"
        seq = 42

        encrypted = encrypt_asm(k1, k2, seq, payload)
        assert len(encrypted) == 4 + len(payload) + 16

        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_empty_payload(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b""
        seq = 0

        encrypted = encrypt_asm(k1, k2, seq, payload)
        assert len(encrypted) == 4 + 0 + 16

        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == b""

    def test_wrong_key_fails(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"secret data"
        seq = 0

        encrypted = encrypt_asm(k1, k2, seq, payload)

        wrong_k1 = os.urandom(32)
        r = decrypt_asm(wrong_k1, k2, seq, encrypted)
        assert r.returncode != 0

    def test_wrong_seq_fails(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"secret data"
        seq = 5

        encrypted = encrypt_asm(k1, k2, seq, payload)

        r = decrypt_asm(k1, k2, seq + 1, encrypted)
        assert r.returncode != 0

    def test_tampered_ciphertext_fails(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"don't tamper"
        seq = 99

        encrypted = encrypt_asm(k1, k2, seq, payload)
        # Flip a bit in the encrypted payload
        tampered = bytearray(encrypted)
        tampered[5] ^= 0x01
        tampered = bytes(tampered)

        r = decrypt_asm(k1, k2, seq, tampered)
        assert r.returncode != 0

    def test_tampered_mac_fails(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"verify me"
        seq = 1

        encrypted = encrypt_asm(k1, k2, seq, payload)
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        tampered = bytes(tampered)

        r = decrypt_asm(k1, k2, seq, tampered)
        assert r.returncode != 0


class TestDecryptLength:
    """Test length decryption."""

    def test_decrypt_length(self):
        k2 = os.urandom(32)
        seq = 7
        plain_len = 100

        nonce = b'\x00' * 4 + struct.pack(">Q", seq)
        ks = python_chacha20_block(k2, 0, nonce)
        enc_len = bytes(a ^ b for a, b in zip(struct.pack(">I", plain_len), ks[:4]))

        result = decrypt_length_asm(k2, seq, enc_len)
        assert result == plain_len

    def test_decrypt_length_zero(self):
        k2 = os.urandom(32)
        seq = 0
        plain_len = 0

        nonce = b'\x00' * 4 + struct.pack(">Q", seq)
        ks = python_chacha20_block(k2, 0, nonce)
        enc_len = bytes(a ^ b for a, b in zip(struct.pack(">I", plain_len), ks[:4]))

        result = decrypt_length_asm(k2, seq, enc_len)
        assert result == plain_len

    def test_decrypt_length_large(self):
        k2 = os.urandom(32)
        seq = 1000
        plain_len = 35000

        nonce = b'\x00' * 4 + struct.pack(">Q", seq)
        ks = python_chacha20_block(k2, 0, nonce)
        enc_len = bytes(a ^ b for a, b in zip(struct.pack(">I", plain_len), ks[:4]))

        result = decrypt_length_asm(k2, seq, enc_len)
        assert result == plain_len


class TestCrossValidation:
    """Cross-validate assembly against Python reference implementation."""

    def test_asm_encrypt_python_decrypt(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"cross-validate this payload"
        seq = 12345

        encrypted = encrypt_asm(k1, k2, seq, payload)
        decrypted = python_ssh_aead_decrypt(encrypted, k1, k2, seq)
        assert decrypted == payload

    def test_python_encrypt_asm_decrypt(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"reverse cross-validation"
        seq = 77

        encrypted = python_ssh_aead_encrypt(payload, k1, k2, seq)
        r = decrypt_asm(k1, k2, seq, encrypted)
        assert r.returncode == 0
        assert r.stdout == payload

    def test_various_sizes(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)

        for size in [1, 15, 16, 17, 32, 63, 64, 65, 128, 255, 256, 512, 1024]:
            payload = os.urandom(size)
            seq = size  # use size as seq for variety

            # ASM encrypt -> Python decrypt
            enc = encrypt_asm(k1, k2, seq, payload)
            dec = python_ssh_aead_decrypt(enc, k1, k2, seq)
            assert dec == payload, f"ASM->Python failed at size {size}"

            # Python encrypt -> ASM decrypt
            enc = python_ssh_aead_encrypt(payload, k1, k2, seq)
            r = decrypt_asm(k1, k2, seq, enc)
            assert r.returncode == 0, f"Python->ASM failed at size {size}"
            assert r.stdout == payload, f"Python->ASM data mismatch at size {size}"

    def test_seq_zero(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"seq zero test"
        seq = 0

        enc = encrypt_asm(k1, k2, seq, payload)
        dec = python_ssh_aead_decrypt(enc, k1, k2, seq)
        assert dec == payload

    def test_seq_max_uint32(self):
        k1 = os.urandom(32)
        k2 = os.urandom(32)
        payload = b"max seq"
        seq = 0xFFFFFFFF

        enc = encrypt_asm(k1, k2, seq, payload)
        dec = python_ssh_aead_decrypt(enc, k1, k2, seq)
        assert dec == payload
