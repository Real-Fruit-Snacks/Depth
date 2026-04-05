# Changelog

All notable changes to Depth will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- Complete SSH-2.0 protocol implementation in x86_64 NASM assembly
- ChaCha20-Poly1305 AEAD transport encryption (`chacha20-poly1305@openssh.com`)
- X25519 Diffie-Hellman key exchange (`curve25519-sha256`)
- Ed25519 host key signatures (`ssh-ed25519`)
- SHA-256 and SHA-512 hash implementations (FIPS 180-4)
- HMAC-SHA256 and HKDF key derivation (RFC 5869)
- Full SSH packet framing with encrypted and plaintext modes
- Password and public key authentication
- Channel multiplexing (up to 8 concurrent channels)
- Interactive PTY shell via `/dev/ptmx` with poll-based I/O relay
- Pipe-based non-interactive command execution (`bash -c`)
- SFTPv3 file transfer (16 opcodes, 16 handle slots)
- Local TCP port forwarding (direct-tcpip channels)
- Remote TCP port forwarding (tcpip-forward global requests)
- Optional TLS 1.3 wrapping with SNI/ALPN support
- Bind mode (server) and reverse mode (client) operation
- Function-pointer I/O dispatch for transparent TLS/raw switching
- 268-test suite with NASM harnesses and Python runners
- Ed25519 keypair generator tool (`tools/keygen.py`)
- ~94 KB statically-linked ELF binary, zero libc dependency
