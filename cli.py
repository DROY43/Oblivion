from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core import (
    DEFAULT_MASTER_BITS, DEFAULT_OTP_BITS, OblivionError,
    decrypt_file, encrypt_file, generate_random_key, otp_decrypt, otp_encrypt,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oblivion",
        description="OBLIVION-65536 experimental encryption toolkit.",
        epilog=(
            "Security note: a 65,536-bit master secret does NOT provide "
            "65,536-bit computational security. AES mode uses AES-256-GCM. "
            "OTP mode provides perfect secrecy only if the pad is truly random, "
            "kept secret, exactly as long as the message, and NEVER reused."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="Generate a cryptographically random key file.")
    keygen.add_argument("--bits", type=int, default=DEFAULT_MASTER_BITS)
    keygen.add_argument("--output", required=True)
    keygen.add_argument("--force", action="store_true")

    enc = sub.add_parser("encrypt", help="Encrypt a file with AES-256-GCM.")
    enc.add_argument("input")
    enc.add_argument("output")
    enc.add_argument("--key", required=True)
    enc.add_argument("--force", action="store_true")

    dec = sub.add_parser("decrypt", help="Authenticate and decrypt an OBLIVION file.")
    dec.add_argument("input")
    dec.add_argument("output")
    dec.add_argument("--key", required=True)
    dec.add_argument("--force", action="store_true")

    padgen = sub.add_parser("padgen", help="Generate a random one-time pad of a given size.")
    padgen.add_argument("--bytes", type=int, required=True)
    padgen.add_argument("--output", required=True)
    padgen.add_argument("--force", action="store_true")

    otpenc = sub.add_parser("otp-encrypt", help="Encrypt with a one-time pad (exact size required).")
    otpenc.add_argument("input")
    otpenc.add_argument("output")
    otpenc.add_argument("--pad", required=True)
    otpenc.add_argument("--force", action="store_true")

    otpdec = sub.add_parser("otp-decrypt", help="Decrypt a one-time-pad file.")
    otpdec.add_argument("input")
    otpdec.add_argument("output")
    otpdec.add_argument("--pad", required=True)
    otpdec.add_argument("--force", action="store_true")

    info = sub.add_parser("info", help="Explain security levels and supported modes.")
    return p


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "keygen":
            generate_random_key(args.output, args.bits, args.force)
            print(f"Generated {args.bits}-bit ({args.bits // 8}-byte) random key: {args.output}")
            print("Keep it secret, back it up securely, and never expose it in logs.")
        elif args.command == "encrypt":
            encrypt_file(args.input, args.output, args.key, args.force)
            print(f"Encrypted: {args.output}")
        elif args.command == "decrypt":
            decrypt_file(args.input, args.output, args.key, args.force)
            print(f"Authenticated and decrypted: {args.output}")
        elif args.command == "padgen":
            if args.bytes <= 0:
                parser.error("--bytes must be positive")
            generate_random_key(args.output, args.bytes * 8, args.force)
            print(f"Generated {args.bytes}-byte one-time pad: {args.output}")
            print("WARNING: use this pad for exactly one message, then securely manage/destroy it.")
        elif args.command == "otp-encrypt":
            otp_encrypt(args.input, args.output, args.pad, args.force)
            print(f"One-time-pad ciphertext written: {args.output}")
            print("CRITICAL: never reuse any portion of this pad.")
        elif args.command == "otp-decrypt":
            otp_decrypt(args.input, args.output, args.pad, args.force)
            print(f"One-time-pad plaintext written: {args.output}")
        elif args.command == "info":
            print(f"""OBLIVION-65536 {__version__}

AES mode:
  - AES-256-GCM with HKDF-SHA-512 key derivation.
  - Accepts master-key files of 256 bits or larger.
  - A 122,880-bit master secret is supported, but AES-256 still has a 256-bit key.
  - Chunk authentication detects tampering and truncation.

One-time-pad mode:
  - XORs plaintext with a truly random pad of exactly the same length.
  - Perfect secrecy requires fresh, secret, uniformly random pad material that is NEVER reused.
  - OTP mode does not authenticate ciphertext; active tampering is not detected.
  - Securely distributing and storing the pad is a major practical challenge.

This is an experimental project, not independently audited. Do not rely on it
as the sole protection for high-value data until it has been reviewed.
""")
    except (OblivionError, OSError, ValueError, FileExistsError) as exc:
        print(f"oblivion: error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
