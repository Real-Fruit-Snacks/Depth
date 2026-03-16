"""Test HKDF (extract, expand, expand_label, derive_secret) against RFC 5869 vectors and Python reference."""
import subprocess, hmac, hashlib, struct, os, pytest

BINARY = os.path.join(os.path.dirname(__file__), "..", "build", "test_hkdf")


# --- Python reference implementations ---

def py_hkdf_extract(salt, ikm):
    if salt is None or len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def py_hkdf_expand(prk, info, length):
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def py_hkdf_expand_label(secret, label, context, length):
    hkdf_label = struct.pack(">H", length)
    hkdf_label += bytes([6 + len(label)]) + b"tls13 " + label
    hkdf_label += bytes([len(context)]) + context
    return py_hkdf_expand(secret, hkdf_label, length)


def py_derive_secret(secret, label, messages):
    transcript_hash = hashlib.sha256(messages).digest()
    return py_hkdf_expand_label(secret, label, transcript_hash, 32)


# --- Assembly wrappers ---

def asm_hkdf_extract(salt, ikm):
    """Mode 'e': salt_len(4) + salt + ikm_len(4) + ikm -> 32 bytes PRK."""
    if salt is None:
        inp = b"e" + struct.pack("<I", 0) + struct.pack("<I", len(ikm)) + ikm
    else:
        inp = b"e" + struct.pack("<I", len(salt)) + salt + struct.pack("<I", len(ikm)) + ikm
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=30)
    assert result.returncode == 0, f"Binary exited with {result.returncode}\nstderr: {result.stderr}"
    assert len(result.stdout) == 32, f"Expected 32 bytes, got {len(result.stdout)}"
    return result.stdout


def asm_hkdf_expand(prk, info, length):
    """Mode 'x': prk(32) + info_len(4) + info + output_len(4) -> length bytes."""
    inp = b"x" + prk + struct.pack("<I", len(info)) + info + struct.pack("<I", length)
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=30)
    assert result.returncode == 0, f"Binary exited with {result.returncode}\nstderr: {result.stderr}"
    assert len(result.stdout) == length, f"Expected {length} bytes, got {len(result.stdout)}"
    return result.stdout


def asm_hkdf_expand_label(secret, label, context, length):
    """Mode 'l': secret(32) + label_len(4) + label + ctx_len(4) + ctx + out_len(4) -> length bytes."""
    inp = (b"l" + secret +
           struct.pack("<I", len(label)) + label +
           struct.pack("<I", len(context)) + context +
           struct.pack("<I", length))
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=30)
    assert result.returncode == 0, f"Binary exited with {result.returncode}\nstderr: {result.stderr}"
    assert len(result.stdout) == length, f"Expected {length} bytes, got {len(result.stdout)}"
    return result.stdout


def asm_derive_secret(secret, label, messages):
    """Mode 'd': secret(32) + label_len(4) + label + msgs_len(4) + msgs -> 32 bytes."""
    inp = (b"d" + secret +
           struct.pack("<I", len(label)) + label +
           struct.pack("<I", len(messages)) + messages)
    result = subprocess.run([BINARY], input=inp, capture_output=True, timeout=30)
    assert result.returncode == 0, f"Binary exited with {result.returncode}\nstderr: {result.stderr}"
    assert len(result.stdout) == 32, f"Expected 32 bytes, got {len(result.stdout)}"
    return result.stdout


# --- Test cases ---

class TestHKDFExtract:
    """HKDF-Extract tests."""

    def test_hkdf_extract_rfc5869_case1(self):
        """RFC 5869 Test Case 1 - Extract."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = bytes.fromhex("000102030405060708090a0b0c")
        expected_prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        assert asm_hkdf_extract(salt, ikm) == expected_prk

    def test_hkdf_extract_rfc5869_case2(self):
        """RFC 5869 Test Case 2 - Extract (longer inputs)."""
        ikm = bytes(range(0x00, 0x50))   # 80 bytes: 0x00..0x4f
        salt = bytes(range(0x60, 0xb0))  # 80 bytes: 0x60..0xaf
        expected_prk = bytes.fromhex(
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244"
        )
        assert asm_hkdf_extract(salt, ikm) == expected_prk

    def test_hkdf_extract_null_salt(self):
        """Extract with NULL salt should use 32 zero bytes."""
        ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        # Our asm uses 32-byte zero salt when salt_len=0
        expected = py_hkdf_extract(None, ikm)
        assert asm_hkdf_extract(None, ikm) == expected

    def test_hkdf_extract_crosscheck_random(self):
        """Cross-check extract with Python for random inputs."""
        for salt_len in [1, 13, 32, 64, 80]:
            for ikm_len in [1, 22, 32, 64, 80]:
                salt = os.urandom(salt_len)
                ikm = os.urandom(ikm_len)
                expected = py_hkdf_extract(salt, ikm)
                assert asm_hkdf_extract(salt, ikm) == expected, (
                    f"Failed: salt_len={salt_len}, ikm_len={ikm_len}"
                )


class TestHKDFExpand:
    """HKDF-Expand tests."""

    def test_hkdf_expand_rfc5869_case1(self):
        """RFC 5869 Test Case 1 - Expand."""
        prk = bytes.fromhex(
            "077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5"
        )
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        expected_okm = bytes.fromhex(
            "3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865"
        )
        assert asm_hkdf_expand(prk, info, 42) == expected_okm

    def test_hkdf_expand_rfc5869_case2(self):
        """RFC 5869 Test Case 2 - Expand (longer output)."""
        prk = bytes.fromhex(
            "06a6b88c5853361a06104c9ceb35b45c"
            "ef760014904671014a193f40c15fc244"
        )
        info = bytes(range(0xb0, 0x100))  # 80 bytes: 0xb0..0xff
        expected_okm = bytes.fromhex(
            "b11e398dc80327a1c8e7f78c596a4934"
            "4f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09"
            "da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f"
            "1d87"
        )
        assert asm_hkdf_expand(prk, info, 82) == expected_okm

    def test_hkdf_expand_single_block(self):
        """Expand exactly 32 bytes (single HMAC block)."""
        prk = os.urandom(32)
        info = b"test info"
        expected = py_hkdf_expand(prk, info, 32)
        assert asm_hkdf_expand(prk, info, 32) == expected

    def test_hkdf_expand_empty_info(self):
        """Expand with empty info field."""
        prk = os.urandom(32)
        info = b""
        expected = py_hkdf_expand(prk, info, 64)
        assert asm_hkdf_expand(prk, info, 64) == expected

    def test_hkdf_expand_partial_last_block(self):
        """Expand to non-multiple of 32 (partial last block)."""
        prk = os.urandom(32)
        info = b"partial"
        for length in [1, 15, 31, 33, 48, 63, 65, 100]:
            expected = py_hkdf_expand(prk, info, length)
            assert asm_hkdf_expand(prk, info, length) == expected, (
                f"Failed for length={length}"
            )


class TestHKDFExpandLabel:
    """HKDF-Expand-Label (TLS 1.3) tests."""

    def test_hkdf_expand_label_basic(self):
        """Basic expand_label with known label and context."""
        secret = os.urandom(32)
        label = b"derived"
        context = os.urandom(32)
        expected = py_hkdf_expand_label(secret, label, context, 32)
        assert asm_hkdf_expand_label(secret, label, context, 32) == expected

    def test_hkdf_expand_label_empty_context(self):
        """Expand-Label with empty context (common in TLS 1.3)."""
        secret = os.urandom(32)
        label = b"finished"
        context = b""
        expected = py_hkdf_expand_label(secret, label, context, 32)
        assert asm_hkdf_expand_label(secret, label, context, 32) == expected

    def test_hkdf_expand_label_various_lengths(self):
        """Expand-Label with various output lengths."""
        secret = os.urandom(32)
        label = b"key"
        context = os.urandom(32)
        for length in [16, 32, 48, 64]:
            expected = py_hkdf_expand_label(secret, label, context, length)
            assert asm_hkdf_expand_label(secret, label, context, length) == expected, (
                f"Failed for length={length}"
            )

    def test_hkdf_expand_label_tls13_c_hs_traffic(self):
        """Simulate TLS 1.3 client handshake traffic secret derivation label."""
        secret = bytes.fromhex(
            "33ad0a1c607ec03b09e6cd9893680ce2"
            "10adf300aa1f2660e1b22e10f170f92a"
        )
        label = b"c hs traffic"
        context = hashlib.sha256(b"client_hello + server_hello").digest()
        expected = py_hkdf_expand_label(secret, label, context, 32)
        assert asm_hkdf_expand_label(secret, label, context, 32) == expected

    def test_hkdf_expand_label_short_label(self):
        """Expand-Label with single-character label."""
        secret = os.urandom(32)
        label = b"k"
        context = b""
        expected = py_hkdf_expand_label(secret, label, context, 32)
        assert asm_hkdf_expand_label(secret, label, context, 32) == expected


class TestDeriveSecret:
    """derive_secret tests."""

    def test_derive_secret_basic(self):
        """Basic derive_secret with known inputs."""
        secret = os.urandom(32)
        label = b"derived"
        messages = b"hello world"
        expected = py_derive_secret(secret, label, messages)
        assert asm_derive_secret(secret, label, messages) == expected

    def test_derive_secret_empty_messages(self):
        """Derive-Secret with empty transcript."""
        secret = os.urandom(32)
        label = b"ext binder"
        messages = b""
        expected = py_derive_secret(secret, label, messages)
        assert asm_derive_secret(secret, label, messages) == expected

    def test_derive_secret_long_messages(self):
        """Derive-Secret with longer transcript messages."""
        secret = os.urandom(32)
        label = b"c hs traffic"
        messages = os.urandom(512)
        expected = py_derive_secret(secret, label, messages)
        assert asm_derive_secret(secret, label, messages) == expected


class TestTLS13KeySchedule:
    """TLS 1.3 key schedule integration tests."""

    def test_tls13_early_secret(self):
        """Compute TLS 1.3 early secret: HKDF-Extract(0, 0).
        Salt = 32 zero bytes, IKM = 32 zero bytes."""
        ikm = b"\x00" * 32
        expected = py_hkdf_extract(None, ikm)
        assert asm_hkdf_extract(None, ikm) == expected

    def test_tls13_derived_secret(self):
        """Compute TLS 1.3 'derived' secret from early secret.
        Derive-Secret(early_secret, "derived", "")."""
        early_secret = py_hkdf_extract(None, b"\x00" * 32)
        label = b"derived"
        messages = b""
        expected = py_derive_secret(early_secret, label, messages)
        assert asm_derive_secret(early_secret, label, messages) == expected

    def test_tls13_handshake_secret(self):
        """Compute TLS 1.3 handshake secret:
        HKDF-Extract(derived_secret, shared_secret)."""
        early_secret = py_hkdf_extract(None, b"\x00" * 32)
        derived = py_derive_secret(early_secret, b"derived", b"")
        shared_secret = os.urandom(32)  # simulated ECDHE shared secret
        expected = py_hkdf_extract(derived, shared_secret)
        assert asm_hkdf_extract(derived, shared_secret) == expected

    def test_tls13_full_key_derivation(self):
        """Full TLS 1.3 key derivation chain:
        early_secret -> derived -> handshake_secret -> client/server keys."""
        # Early secret
        early_secret = py_hkdf_extract(None, b"\x00" * 32)
        asm_early = asm_hkdf_extract(None, b"\x00" * 32)
        assert asm_early == early_secret

        # Derived secret
        derived = py_derive_secret(early_secret, b"derived", b"")
        asm_derived = asm_derive_secret(early_secret, b"derived", b"")
        assert asm_derived == derived

        # Handshake secret (with fake shared secret)
        shared = b"\xab" * 32
        hs_secret = py_hkdf_extract(derived, shared)
        asm_hs = asm_hkdf_extract(derived, shared)
        assert asm_hs == hs_secret

        # Client handshake traffic secret
        transcript = b"fake_client_hello||fake_server_hello"
        c_hs = py_derive_secret(hs_secret, b"c hs traffic", transcript)
        asm_c_hs = asm_derive_secret(hs_secret, b"c hs traffic", transcript)
        assert asm_c_hs == c_hs

        # Server handshake traffic secret
        s_hs = py_derive_secret(hs_secret, b"s hs traffic", transcript)
        asm_s_hs = asm_derive_secret(hs_secret, b"s hs traffic", transcript)
        assert asm_s_hs == s_hs

        # Derive actual keys from traffic secrets
        c_key = py_hkdf_expand_label(c_hs, b"key", b"", 32)
        asm_c_key = asm_hkdf_expand_label(c_hs, b"key", b"", 32)
        assert asm_c_key == c_key

        c_iv = py_hkdf_expand_label(c_hs, b"iv", b"", 12)
        asm_c_iv = asm_hkdf_expand_label(c_hs, b"iv", b"", 12)
        assert asm_c_iv == c_iv
