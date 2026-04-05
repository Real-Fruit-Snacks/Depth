# Security Policy

## Supported Versions

Only the latest release of Depth is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Depth, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Depth/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Depth is an SSH-2.0 implementation designed for authorized security assessments. The following behaviors are **features, not bugs**:

- Reverse and bind mode SSH server operation
- Encrypted communications (ChaCha20-Poly1305, TLS 1.3)
- Key exchange and host authentication (X25519, Ed25519)
- Interactive PTY shell access
- SFTP file transfer
- TCP port forwarding (local and remote)
- Small static binary with no dependencies

These capabilities exist by design for legitimate security testing. Reports that simply describe Depth working as intended will be closed.

## Responsible Use

Depth is intended for authorized penetration testing, security research, and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
