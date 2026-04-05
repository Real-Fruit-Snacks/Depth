<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-light.svg">
  <img alt="Depth" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-6E4C13.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Complete SSH-2.0 protocol implementation in pure x86_64 NASM assembly.**

~94 KB static ELF binary. Key exchange (X25519), host authentication (Ed25519), encrypted transport (ChaCha20-Poly1305), interactive shells (PTY), SFTP, port forwarding. Zero libc. Zero dependencies.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

</div>

---

## Quick Start

**Prerequisites:** NASM, GNU ld, GCC

```bash
git clone https://github.com/Real-Fruit-Snacks/Depth.git
cd Depth
make
```

**Verify:**

```bash
file build/depth
# ELF 64-bit LSB executable, x86-64, statically linked

./build/depth                          # bind mode, port 7777
ssh -p 7777 svc@target                 # connect with OpenSSH
```

---

## Features

### ChaCha20-Poly1305 AEAD

Full `chacha20-poly1305@openssh.com` transport encryption. Two-key scheme: K1 encrypts payload, K2 encrypts packet length. Sequence-number nonce. Every packet authenticated.

### Ed25519 + X25519

Complete elliptic curve cryptography from scratch. X25519 Diffie-Hellman for key exchange, Ed25519 for host key signatures. SHA-512 internals, SHA-256 exchange hash. All field arithmetic in pure assembly.

### Full SSH Protocol Stack

RFC 4253/4254 compliant: version exchange, algorithm negotiation (KEXINIT), ECDH key exchange, NEWKEYS, service request, password authentication, channel multiplexing (up to 8 concurrent), PTY allocation, shell/exec requests, window management.

### Interactive Shell (PTY)

Full pseudoterminal support via `/dev/ptmx`. Fork, setsid, set controlling terminal, dup2 stdio, execve `/bin/bash`. Poll-based I/O relay between PTY master and SSH channel with child lifecycle management.

### SFTP

SFTPv3 implementation: open, read, write, close, stat, fstat, lstat, setstat, opendir, readdir, remove, mkdir, rmdir, rename, realpath. Concurrent shell + SFTP sessions through event-loop integration.

### Port Forwarding

Local (`ssh -L`) and remote (`ssh -R`) TCP forwarding. Direct-tcpip channels for local forward, global request handling for remote forward. Multiplexed alongside shell/SFTP channels.

---

## Architecture

```
Depth/
├── Makefile                # Build targets for binary + 22 test harnesses
├── src/
│   ├── main.asm            # Entry point: bind/reverse mode dispatch
│   ├── ssh_transport.asm   # Version exchange, KEXINIT, ECDH, key derivation
│   ├── ssh_auth.asm        # Password + pubkey authentication
│   ├── ssh_channel.asm     # Channel multiplexing, window management
│   ├── ssh_client.asm      # v2 event loop: poll, dispatch, PTY/pipe relay
│   ├── ssh_pty.asm         # PTY allocation, shell/exec spawn
│   ├── ssh_sftp.asm        # SFTPv3 dispatch: 16 opcodes
│   ├── ssh_forward.asm     # Local port forwarding (direct-tcpip)
│   ├── ssh_remote_forward.asm  # Remote port forwarding (tcpip-forward)
│   ├── ssh_encode.asm      # SSH wire encoding: mpint, string, uint32
│   ├── ssh_aead.asm        # ChaCha20-Poly1305 AEAD
│   ├── sha256.asm          # SHA-256 (FIPS 180-4)
│   ├── sha512.asm          # SHA-512 (for Ed25519)
│   ├── curve25519.asm      # X25519 scalar multiplication
│   ├── ed25519.asm         # Ed25519 sign + verify
│   ├── hmac_sha256.asm     # HMAC-SHA256
│   ├── hkdf.asm            # HKDF extract + expand
│   ├── net.asm             # TCP socket operations
│   ├── io_dispatch.asm     # Function pointer I/O abstraction
│   ├── tls13.asm           # TLS 1.3 handshake + record I/O
│   └── sc_reduce_c.c       # Ed25519 scalar reduction (C helper)
├── include/
│   ├── ssh.inc             # SSH constants, channel struct, SFTP types
│   ├── syscall.inc         # Linux syscall numbers
│   ├── config.inc          # IP, port, credentials, mode settings
│   └── *.inc               # AEAD, ChaCha20, Poly1305, TLS constants
└── tests/                  # 25 NASM harnesses + 28 Python test runners
```

---

## Platform

Linux x86_64 only. ~94 KB statically-linked ELF binary. Uses raw `syscall` instructions and NASM-specific syntax. No libc, no dynamic linking, no runtime dependencies. No portability to other architectures or operating systems.

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Depth/security/advisories). 90-day responsible disclosure.

**Depth is not** a C2 framework, vulnerability scanner, exploit framework, or anti-forensics tool. It is an SSH protocol implementation for authorized security testing.

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
