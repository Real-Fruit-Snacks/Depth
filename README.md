<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-light.svg">
  <img alt="Depth" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Depth/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-6E4C13.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Complete SSH-2.0 protocol implementation in pure x86_64 NASM assembly**

~94 KB statically-linked ELF binary. Key exchange (X25519), host authentication (Ed25519), encrypted transport (ChaCha20-Poly1305), interactive shells (PTY), SFTP file transfers, TCP port forwarding. Zero libc. Zero dependencies. Pure Linux syscalls.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Wire Protocol](#wire-protocol) • [Internals](#internals) • [Architecture](#architecture) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**ChaCha20-Poly1305 AEAD**
Full `chacha20-poly1305@openssh.com` transport encryption. Two-key scheme: K1 encrypts payload (counter=1), K2 encrypts packet length (counter=0). Sequence-number nonce. Every packet authenticated — tampered data rejected before decryption.

**Ed25519 + X25519**
Complete elliptic curve cryptography from scratch. X25519 Diffie-Hellman for key exchange, Ed25519 for host key signatures. SHA-512 for Ed25519 internals, SHA-256 for exchange hash. All field arithmetic in pure assembly.

**Full SSH Protocol Stack**
RFC 4253/4254 compliant: version exchange, algorithm negotiation (KEXINIT), ECDH key exchange, NEWKEYS, service request, password authentication, channel multiplexing (up to 8 concurrent), PTY allocation, shell/exec requests, window management.

**~94 KB Static Binary**
The entire implementation — crypto primitives, SSH protocol, PTY handling, SFTP, port forwarding, TLS 1.3 — compiles to a ~94 KB statically-linked ELF. No libc, no dynamic linking, no runtime dependencies. Pure Linux syscalls via `syscall` instruction.

</td>
<td width="50%">

**SFTP File Transfers**
Full SFTPv3 implementation: open, read, write, close, stat, fstat, lstat, setstat, opendir, readdir, remove, mkdir, rmdir, rename, realpath. Handles concurrent shell + SFTP sessions through event-loop integration.

**TCP Port Forwarding**
Both local (`ssh -L`) and remote (`ssh -R`) forwarding. Direct-tcpip channels for local forward, global request handling for remote forward with accept loop and forwarded-tcpip channel opens. Multiplexed alongside shell/SFTP channels.

**Interactive PTY Shell**
Full pseudoterminal support via `/dev/ptmx`: allocate master/slave pair, fork, setsid, set controlling terminal, dup2 stdio, execve `/bin/bash`. Poll-based I/O relay between PTY master and SSH channel with child process lifecycle management.

**Pipe-Based Command Execution**
Non-interactive `ssh target 'cmd'` without PTY. Creates stdin/stdout pipes, forks, executes via `bash -c`. Graceful EOF handling: close stdin pipe to signal child, drain buffered output, wait for natural exit with SIGKILL fallback.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>NASM</td>
<td>Latest</td>
<td>x86_64 assembler</td>
</tr>
<tr>
<td>GNU ld</td>
<td>Any</td>
<td>Static ELF linking</td>
</tr>
<tr>
<td>GCC</td>
<td>Any</td>
<td>Ed25519 scalar reduction helper (<code>sc_reduce_c.c</code>)</td>
</tr>
<tr>
<td>Python</td>
<td>>= 3.8</td>
<td>Test runner</td>
</tr>
<tr>
<td>pytest</td>
<td>Latest</td>
<td><code>pip install pytest</code></td>
</tr>
<tr>
<td>cryptography</td>
<td>Latest</td>
<td><code>pip install cryptography</code></td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Depth.git
cd Depth

# Build everything (binary + all test harnesses)
make

# Run tests (268 tests)
make test

# Verify binary
file build/depth
# build/depth: ELF 64-bit LSB executable, x86-64, statically linked
```

### Verification

```bash
# Run the binary (bind mode, port 7777)
./build/depth

# Connect with OpenSSH
ssh -p 7777 svc@target

# Non-interactive command execution
ssh -p 7777 svc@target 'whoami'

# SFTP file transfer
sftp -P 7777 svc@target

# Local port forwarding
ssh -L 8080:internal:80 -p 7777 svc@target
```

### Configuration

Edit `include/config.inc` before building:

```nasm
server_ip:      dd 0x0100007F      ; 127.0.0.1 (network byte order)
server_port:    dw 0xBB01          ; port 443 (big-endian)
ssh_username:   db "svc"
ssh_password:   db "changeme"
bind_mode:      db 1               ; 0=reverse, 1=bind
bind_port:      dw 7777
```

---

## Wire Protocol

### SSH Packet (Plaintext, Pre-NEWKEYS)

```
┌──────────────┬──────────┬───────────┬──────────┐
│ pkt_len (4B) │ pad (1B) │ payload   │ padding  │
│ big-endian   │          │           │ >= 4B    │
└──────────────┴──────────┴───────────┴──────────┘
   total = 4 + pkt_len, aligned to 8 bytes
```

### SSH Packet (Encrypted, Post-NEWKEYS)

```
┌──────────────────┬────────────────────────┬──────────┐
│ enc_length (4B)  │ enc_payload (N)        │ MAC (16B)│
│ K2 stream cipher │ K1 ChaCha20 ctr=1      │ Poly1305 │
└──────────────────┴────────────────────────┴──────────┘
  K2 encrypts length field (counter=0, seq as nonce)
  K1 encrypts padded payload (counter=1)
  Poly1305 key from K1 block 0
  MAC covers enc_length + enc_payload
```

### ECDH Key Exchange

```
Client                              Server
  │── SSH_MSG_KEX_ECDH_INIT ──────>│  (client ephemeral X25519 pub)
  │                                 │  compute shared secret
  │                                 │  compute exchange hash H
  │                                 │  sign H with Ed25519 host key
  │<── SSH_MSG_KEX_ECDH_REPLY ────│  (host pub + server ephem + signature)
  │  verify Ed25519 signature       │
  │  derive 6 session keys (A-F)    │  derive 6 session keys (A-F)
```

---

## Internals

### Crypto Primitives

All cryptography implemented from scratch in x86_64 assembly:

<table>
<tr>
<th>Primitive</th>
<th>File</th>
<th>Description</th>
</tr>
<tr>
<td>SHA-256</td>
<td><code>sha256.asm</code></td>
<td>FIPS 180-4, used for exchange hash and key derivation</td>
</tr>
<tr>
<td>SHA-512</td>
<td><code>sha512.asm</code></td>
<td>Used internally by Ed25519</td>
</tr>
<tr>
<td>X25519</td>
<td><code>curve25519.asm</code></td>
<td>Curve25519 scalar multiplication for ECDH</td>
</tr>
<tr>
<td>Ed25519</td>
<td><code>ed25519.asm</code></td>
<td>Edwards-curve signatures (sign + verify)</td>
</tr>
<tr>
<td>ChaCha20</td>
<td><code>ssh_aead.asm</code></td>
<td>20-round stream cipher, 256-bit key</td>
</tr>
<tr>
<td>Poly1305</td>
<td><code>ssh_aead.asm</code></td>
<td>One-time MAC, mod 2^130-5 arithmetic</td>
</tr>
<tr>
<td>HMAC-SHA256</td>
<td><code>hmac_sha256.asm</code></td>
<td>Used by HKDF for key derivation</td>
</tr>
<tr>
<td>HKDF</td>
<td><code>hkdf.asm</code></td>
<td>RFC 5869 extract-and-expand</td>
</tr>
</table>

### Channel Multiplexing

Each channel occupies a 48-byte state structure:

<table>
<tr>
<th>Offset</th>
<th>Field</th>
<th>Description</th>
</tr>
<tr><td>0</td><td><code>LOCAL_ID</code></td><td>Our channel number (0-7)</td></tr>
<tr><td>4</td><td><code>REMOTE_ID</code></td><td>Peer's channel number</td></tr>
<tr><td>8</td><td><code>LOCAL_WINDOW</code></td><td>Bytes we can still receive</td></tr>
<tr><td>12</td><td><code>REMOTE_WINDOW</code></td><td>Bytes we can still send</td></tr>
<tr><td>16</td><td><code>LOCAL_MAXPKT</code></td><td>Our max packet size</td></tr>
<tr><td>20</td><td><code>REMOTE_MAXPKT</code></td><td>Peer's max packet size</td></tr>
<tr><td>24</td><td><code>WRITE_FD</code></td><td>Write fd (PTY master or stdin pipe)</td></tr>
<tr><td>28</td><td><code>CHILD_PID</code></td><td>Shell/exec child process ID</td></tr>
<tr><td>32</td><td><code>FLAGS</code></td><td>Channel state flags</td></tr>
<tr><td>36</td><td><code>TYPE</code></td><td>0=unused, 1=session, 2=direct-tcp, 3=sftp</td></tr>
<tr><td>40</td><td><code>FD</code></td><td>Read fd (PTY master or stdout pipe)</td></tr>
</table>

### I/O Dispatch

Platform-agnostic I/O through function pointers:

```
io_read_fn  → net_read_exact  (raw TCP)
              tls_read_exact  (TLS 1.3 wrapped)

io_write_fn → net_write_all   (raw TCP)
              tls_write_all   (TLS 1.3 wrapped)
```

All SSH protocol code calls through `io_read_fn` / `io_write_fn`, enabling transparent TLS wrapping without modifying any protocol logic.

### Memory Layout

The v2 event loop allocates ~38 KB on the stack:

<table>
<tr>
<th>Offset</th>
<th>Size</th>
<th>Purpose</th>
</tr>
<tr><td><code>+0</code></td><td>32 KB</td><td>Receive/send buffer (encrypted packets)</td></tr>
<tr><td><code>+32896</code></td><td>1 KB</td><td>Packet construction workspace</td></tr>
<tr><td><code>+33920</code></td><td>104 B</td><td>pollfd array (13 entries: 1 ssh + 8 channels + 4 forwards)</td></tr>
<tr><td><code>+34024</code></td><td>4 KB</td><td>I/O relay buffer</td></tr>
<tr><td><code>+38128</code></td><td>16 B</td><td>PTY fd storage</td></tr>
</table>

---

## Testing

### Test Suite (268 Tests)

<table>
<tr>
<th>Category</th>
<th>Tests</th>
<th>Description</th>
</tr>
<tr><td>SHA-256</td><td>8</td><td>NIST vectors, empty input, streaming, large data</td></tr>
<tr><td>SHA-512</td><td>6</td><td>NIST vectors, empty input, large data</td></tr>
<tr><td>X25519</td><td>7</td><td>RFC 7748 vectors, all-zero rejection, identity</td></tr>
<tr><td>Ed25519</td><td>9</td><td>RFC 8032 vectors, sign/verify roundtrip, invalid signatures</td></tr>
<tr><td>HMAC-SHA256</td><td>6</td><td>RFC 4231 vectors, key lengths</td></tr>
<tr><td>HKDF</td><td>6</td><td>RFC 5869 vectors, extract/expand</td></tr>
<tr><td>SSH Encode</td><td>14</td><td>mpint, string, uint32 encoding/decoding</td></tr>
<tr><td>SSH AEAD</td><td>15</td><td>Encrypt/decrypt roundtrip, MAC verification, tamper detection</td></tr>
<tr><td>SSH Transport</td><td>24</td><td>Packet framing, KEXINIT building, name-list parsing</td></tr>
<tr><td>SSH KEX</td><td>8</td><td>Client/server key exchange, shared secret derivation</td></tr>
<tr><td>SSH Auth</td><td>10</td><td>Password auth, none probe, multi-attempt</td></tr>
<tr><td>SSH Channel</td><td>14</td><td>Open/confirm, data transfer, window management, EOF/close</td></tr>
<tr><td>SSH PTY</td><td>12</td><td>PTY allocation, shell spawn, pipe exec, relay</td></tr>
<tr><td>SSH E2E</td><td>4</td><td>Build verification, ELF validation, full session</td></tr>
<tr><td>SSH Multi-channel</td><td>6</td><td>Concurrent channels, independent data streams</td></tr>
<tr><td>SSH Forwarding</td><td>10</td><td>Local forward, direct-tcpip channels</td></tr>
<tr><td>Remote Forward</td><td>5</td><td>Remote forward setup, forwarded-tcpip</td></tr>
<tr><td>SFTP</td><td>12</td><td>File operations, directory listing, read/write</td></tr>
<tr><td>Bind Mode</td><td>8</td><td>Server-mode operation, accept loop</td></tr>
<tr><td>Master Socket</td><td>5</td><td>Connection multiplexing</td></tr>
<tr><td>TLS 1.3</td><td>4</td><td>Handshake, encrypted SSH over TLS</td></tr>
<tr><td>SNI/ALPN</td><td>2</td><td>TLS server name indication</td></tr>
<tr><td>Stress</td><td>53</td><td>Rapid I/O, large transfers, concurrent operations</td></tr>
<tr><td>Pubkey Auth</td><td>5</td><td>Ed25519 public key authentication flow</td></tr>
</table>

```bash
# All tests
make test

# Specific category
python3 -m pytest tests/test_sha256.py -v
python3 -m pytest tests/test_ssh_pty.py::TestPipeExec -v

# Stress tests only
python3 -m pytest tests/test_ssh_stress.py -v
```

Each test category has a NASM test harness (`.asm`) that exposes assembly functions to a Python test runner (`.py`) via stdin/stdout binary protocol.

---

## Architecture

```
[Operator]                              [Target]
 OpenSSH  ──────── TCP ──────────>   depth (bind mode)
          <── SSH-2.0 banner ────
          ── KEXINIT ───────────>
          <── KEXINIT ──────────
          ── ECDH_INIT ─────────>
          <── ECDH_REPLY ───────    (Ed25519 signed)
          ── NEWKEYS ───────────>
          <── NEWKEYS ──────────
          ══ encrypted channel ══>
          <══ encrypted channel ══
```

```
Depth/
├── Makefile                # Build targets for binary + 22 test harnesses
├── src/
│   ├── main.asm            # Entry point: mode dispatch (bind/reverse)
│   ├── ssh_transport.asm   # Version exchange, KEXINIT, ECDH, key derivation
│   ├── ssh_auth.asm        # Password + pubkey authentication (client + server)
│   ├── ssh_channel.asm     # Channel multiplexing, window management
│   ├── ssh_client.asm      # v2 event loop: poll, dispatch, PTY/pipe relay
│   ├── ssh_pty.asm         # PTY allocation, shell/exec spawn, pipe exec
│   ├── ssh_sftp.asm        # SFTPv3 dispatch: 16 opcodes, handle table
│   ├── ssh_forward.asm     # Local port forwarding (direct-tcpip)
│   ├── ssh_remote_forward.asm  # Remote port forwarding (tcpip-forward)
│   ├── ssh_encode.asm      # SSH wire encoding: mpint, string, uint32
│   ├── ssh_aead.asm        # ChaCha20-Poly1305 AEAD encrypt/decrypt
│   ├── sha256.asm          # SHA-256 (FIPS 180-4)
│   ├── sha512.asm          # SHA-512 (for Ed25519)
│   ├── curve25519.asm      # X25519 scalar multiplication
│   ├── ed25519.asm         # Ed25519 sign + verify
│   ├── hmac_sha256.asm     # HMAC-SHA256
│   ├── hkdf.asm            # HKDF extract + expand
│   ├── net.asm             # TCP networking (socket, connect, bind, accept)
│   ├── io_dispatch.asm     # Function pointer I/O abstraction
│   ├── tls13.asm           # TLS 1.3 handshake
│   ├── tls_io.asm          # TLS record I/O
│   ├── tls_record.asm      # TLS record framing
│   └── sc_reduce_c.c       # Ed25519 scalar reduction (C helper)
├── include/
│   ├── ssh.inc             # SSH constants, channel state struct, SFTP types
│   ├── syscall.inc         # Linux syscall numbers
│   ├── config.inc          # IP, port, credentials, mode settings
│   ├── tls.inc             # TLS constants
│   ├── aead.inc            # AEAD constants
│   ├── chacha20.inc        # ChaCha20 constants
│   └── poly1305.inc        # Poly1305 constants
├── tests/                  # 25 NASM harnesses + 28 Python test runners
├── tools/
│   └── keygen.py           # Ed25519 keypair generator
└── docs/
    ├── index.html          # GitHub Pages landing page
    └── banner.svg          # Repository banner
```

### Protocol Layer Stack

<table>
<tr>
<th>Layer</th>
<th>Implementation</th>
</tr>
<tr><td><strong>Transport</strong></td><td>Raw TCP via Linux syscalls (<code>socket</code>, <code>connect</code>, <code>bind</code>, <code>listen</code>, <code>accept</code>)</td></tr>
<tr><td><strong>Encryption</strong></td><td><code>chacha20-poly1305@openssh.com</code> — two-key AEAD, sequence-number nonce</td></tr>
<tr><td><strong>Key Exchange</strong></td><td>Curve25519 ECDH (<code>curve25519-sha256</code>), SHA-256 exchange hash</td></tr>
<tr><td><strong>Host Auth</strong></td><td>Ed25519 signatures (<code>ssh-ed25519</code>), SHA-512 internals</td></tr>
<tr><td><strong>User Auth</strong></td><td>Password authentication (<code>ssh-userauth</code> service)</td></tr>
<tr><td><strong>Channels</strong></td><td>Up to 8 multiplexed channels with independent window management</td></tr>
<tr><td><strong>Shell</strong></td><td>PTY via <code>/dev/ptmx</code>, poll-based I/O relay, child lifecycle management</td></tr>
<tr><td><strong>Exec</strong></td><td>Pipe-based <code>bash -c</code> for non-interactive commands, stdout/stderr merged</td></tr>
<tr><td><strong>SFTP</strong></td><td>SFTPv3 with 16 file handle slots, event-loop integrated</td></tr>
<tr><td><strong>Forwarding</strong></td><td>Local (<code>direct-tcpip</code>) and remote (<code>tcpip-forward</code>) TCP forwarding</td></tr>
<tr><td><strong>TLS</strong></td><td>Optional TLS 1.3 wrapping (X25519 + ChaCha20-Poly1305) via I/O dispatch</td></tr>
<tr><td><strong>Key Derivation</strong></td><td>HKDF-SHA256 with RFC 4253 key derivation (A-F letters)</td></tr>
<tr><td><strong>MAC</strong></td><td><code>hmac-sha2-256</code> advertised for compatibility (implicit with AEAD cipher)</td></tr>
</table>

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux x86_64</th>
</tr>
<tr><td>Bind mode (SSH server)</td><td>Full</td></tr>
<tr><td>Reverse mode (SSH client)</td><td>Full</td></tr>
<tr><td>ChaCha20-Poly1305 AEAD</td><td>Full</td></tr>
<tr><td>X25519 key exchange</td><td>Full</td></tr>
<tr><td>Ed25519 host keys</td><td>Full</td></tr>
<tr><td>Interactive PTY shell</td><td>Full</td></tr>
<tr><td>Pipe command execution</td><td>Full</td></tr>
<tr><td>SFTP file transfer</td><td>Full</td></tr>
<tr><td>Local port forwarding</td><td>Full</td></tr>
<tr><td>Remote port forwarding</td><td>Full</td></tr>
<tr><td>TLS 1.3 wrapping</td><td>Full</td></tr>
<tr><td>Channel multiplexing (8)</td><td>Full</td></tr>
<tr><td>Password authentication</td><td>Full</td></tr>
<tr><td>Public key authentication</td><td>Full</td></tr>
</table>

Linux x86_64 only. Uses raw `syscall` instructions and NASM-specific syntax. No portability to other architectures or operating systems.

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Encrypted SSH transport between operator and target
- Host key verification via Ed25519 signatures
- Authenticated key exchange with forward secrecy (ephemeral X25519)
- Authorized testing with known monitoring

**Out of scope:**
- Evading advanced EDR/XDR systems
- Anti-forensics or evidence destruction
- Defeating kernel security modules
- Sophisticated traffic analysis evasion

### What Depth Does NOT Do

Depth is an **SSH protocol implementation**, not an offensive framework:

- **Not a C2 framework** — No implant management, tasking queues, or beaconing
- **Not a vulnerability scanner** — No scanning or enumeration capabilities
- **Not an exploit framework** — No payload generation or exploit modules
- **Not anti-forensics** — Does not destroy evidence or tamper with logs

---

## Future Work

- Exit status channel message (return real exit codes)
- Sequential bind-mode connections (accept loop after session ends)
- Terminal resize (SIGWINCH / window-change request)
- Rekey after data volume threshold
- Window adjust for large transfers
- Environment variable requests

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Depth](https://github.com/Real-Fruit-Snacks/Depth)
- **Releases**: [Latest Release](https://github.com/Real-Fruit-Snacks/Depth/releases/latest)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Depth/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Deadwater](https://github.com/Real-Fruit-Snacks/Deadwater) • [Deluge](https://github.com/Real-Fruit-Snacks/Deluge) • [Depth](https://github.com/Real-Fruit-Snacks/Depth) • [Dew](https://github.com/Real-Fruit-Snacks/Dew) • [Droplet](https://github.com/Real-Fruit-Snacks/Droplet) • [Fathom](https://github.com/Real-Fruit-Snacks/Fathom) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [Grotto](https://github.com/Real-Fruit-Snacks/Grotto) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Maelstrom](https://github.com/Real-Fruit-Snacks/Maelstrom) • [Rapids](https://github.com/Real-Fruit-Snacks/Rapids) • [Ripple](https://github.com/Real-Fruit-Snacks/Ripple) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • [Seep](https://github.com/Real-Fruit-Snacks/Seep) • [Shallows](https://github.com/Real-Fruit-Snacks/Shallows) • [Siphon](https://github.com/Real-Fruit-Snacks/Siphon) • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Spillway](https://github.com/Real-Fruit-Snacks/Spillway) • [Surge](https://github.com/Real-Fruit-Snacks/Surge) • [Tidemark](https://github.com/Real-Fruit-Snacks/Tidemark) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undercurrent](https://github.com/Real-Fruit-Snacks/Undercurrent) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Vapor](https://github.com/Real-Fruit-Snacks/Vapor) • [Wellspring](https://github.com/Real-Fruit-Snacks/Wellspring) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
