# Contributing to Depth

Thank you for your interest in contributing to Depth! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **NASM:** Latest version (assembler)
- **GNU ld:** Any version (static linking)
- **GCC:** Any version (for `sc_reduce_c.c` helper)
- **Python:** >= 3.8 (for test suite)
- **pytest:** `pip install pytest`
- **cryptography:** `pip install cryptography`
- **Git:** For version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Depth.git
cd Depth

# Build everything (binary + all test harnesses)
make

# Run the full test suite (268 tests)
make test
```

## Code Style

All assembly code should follow these conventions:

- **Indentation:** Tabs for instructions, spaces for alignment within operands
- **Labels:** Lowercase with underscores (`send_kexinit`, `handle_channel_open`)
- **Constants:** Uppercase with underscores (`SSH_MSG_KEXINIT`, `CHANNEL_MAX`)
- **Comments:** Explain *why*, not *what* — the instruction set is the what
- **Section ordering:** `.data`, `.bss`, `.text` within each source file

## Testing Requirements

- All existing tests must continue to pass: `make test`
- New features must include corresponding test harnesses (NASM `.asm` + Python `.py`)
- Test harnesses communicate with Python runners via stdin/stdout binary protocol

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   make clean
   make
   make test
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(sftp): add rename operation support
fix(aead): correct Poly1305 tag verification on short packets
docs: update build instructions for Debian
test: add RFC 7748 X25519 edge-case vectors
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
