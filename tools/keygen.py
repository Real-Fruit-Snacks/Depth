#!/usr/bin/env python3
"""Generate Ed25519 host keypair for SSH program."""
import sys
import argparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


def main():
    parser = argparse.ArgumentParser(description="Generate Ed25519 keypair")
    parser.add_argument("--format", choices=["nasm", "bin"], default="nasm")
    parser.add_argument("--output", default="-")
    args = parser.parse_args()

    key = Ed25519PrivateKey.generate()
    priv = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    if args.format == "bin":
        data = priv + pub
        if args.output == "-":
            sys.stdout.buffer.write(data)
        else:
            with open(args.output, "wb") as f:
                f.write(data)
    else:
        lines = ["; Auto-generated Ed25519 host keypair", "host_keypair:"]
        for label, data in [("private", priv), ("public", pub)]:
            lines.append(f"    ; {label} key (32 bytes)")
            for i in range(0, 32, 16):
                chunk = data[i:i + 16]
                lines.append("    db " + ",".join(f"0x{b:02x}" for b in chunk))
        text = "\n".join(lines) + "\n"
        if args.output == "-":
            print(text)
        else:
            with open(args.output, "w") as f:
                f.write(text)


if __name__ == "__main__":
    main()
