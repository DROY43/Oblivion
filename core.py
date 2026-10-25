from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"OBLIVION1"
VERSION = 1
CHUNK_SIZE = 1024 * 1024
MAX_HEADER = 1024 * 1024
DEFAULT_MASTER_BITS = 122_880  # 15 KiB of random master-key material
DEFAULT_OTP_BITS = 16_384
OTP_MAGIC = b"OBLIPAD1"


class OblivionError(Exception):
    """Base exception for expected OBLIVION errors."""


class FormatError(OblivionError):
    pass


class KeyErrorOblivion(OblivionError):
    pass


def generate_random_key(path: str | Path, bits: int = DEFAULT_MASTER_BITS,
                        force: bool = False) -> None:
    """Write uniformly random key material to a new file, mode 0600 on POSIX."""
    path = Path(path)
    if bits <= 0 or bits % 8:
        raise ValueError("Key size must be a positive multiple of 8 bits.")
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists; use --force to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            remaining = bits // 8
            while remaining:
                block = secrets.token_bytes(min(1024 * 1024, remaining))
                f.write(block)
                remaining -= len(block)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_key(path: str | Path, minimum_bytes: int = 32) -> bytes:
    data = Path(path).read_bytes()
    if len(data) < minimum_bytes:
        raise KeyErrorOblivion(
            f"Key file is too short: need at least {minimum_bytes} bytes."
        )
    return data


def _derive_aes_key(master: bytes, salt: bytes) -> bytes:
    # HKDF-SHA-512 produces a 256-bit AES key. Large master-key input does
    # not increase AES-256's 256-bit key length or its security ceiling.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        info=b"OBLIVION-65536/v1/file-encryption",
    ).derive(master)


def encrypt_file(source: str | Path, destination: str | Path,
                 key_path: str | Path, force: bool = False) -> None:
    """Encrypt a file as independently authenticated AES-256-GCM chunks."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; use --force to overwrite.")

    master = _read_key(key_path)
    salt = secrets.token_bytes(32)
    prefix = secrets.token_bytes(8)  # per-file random nonce prefix
    aes_key = _derive_aes_key(master, salt)
    base = {
        "version": VERSION,
        "algorithm": "AES-256-GCM",
        "kdf": "HKDF-SHA-512",
        "chunk_size": CHUNK_SIZE,
        "salt": salt.hex(),
        "nonce_prefix": prefix.hex(),
        "source_name": source.name,
    }
    header = json.dumps(base, sort_keys=True, separators=(",", ":")).encode()
    if len(header) > MAX_HEADER:
        raise ValueError("Header too large.")
    aad_header = MAGIC + struct.pack(">I", len(header)) + header

    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".oblivion-", dir=str(destination.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with source.open("rb") as inp, temp_path.open("wb") as out:
            out.write(aad_header)
            index = 0
            while True:
                chunk = inp.read(CHUNK_SIZE)
                if not chunk:
                    break
                if index >= 2**32:
                    raise ValueError("File exceeds supported chunk count.")
                nonce = prefix + struct.pack(">I", index)
                aad = aad_header + struct.pack(">I", index)
                ciphertext = AESGCM(aes_key).encrypt(nonce, chunk, aad)
                out.write(struct.pack(">I", len(ciphertext)))
                out.write(ciphertext)
                index += 1
            # Authenticated terminal record binds chunk count and end-of-file.
            nonce = prefix + struct.pack(">I", index)
            aad = aad_header + b"END" + struct.pack(">I", index)
            terminal = AESGCM(aes_key).encrypt(nonce, b"", aad)
            out.write(struct.pack(">I", len(terminal)))
            out.write(terminal)
            out.flush()
            os.fsync(out.fileno())
        if destination.exists() and force:
            destination.unlink()
        os.replace(temp_path, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def decrypt_file(source: str | Path, destination: str | Path,
                 key_path: str | Path, force: bool = False) -> None:
    """Decrypt to a temporary file and publish it only after all checks pass."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; use --force to overwrite.")

    master = _read_key(key_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".oblivion-dec-", dir=str(destination.parent))
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        with source.open("rb") as inp, temp_path.open("wb") as out:
            magic = inp.read(len(MAGIC))
            if magic != MAGIC:
                raise FormatError("Not an OBLIVION encrypted file.")
            raw_len = inp.read(4)
            if len(raw_len) != 4:
                raise FormatError("Truncated header.")
            header_len = struct.unpack(">I", raw_len)[0]
            if header_len <= 0 or header_len > MAX_HEADER:
                raise FormatError("Invalid header length.")
            header_bytes = inp.read(header_len)
            if len(header_bytes) != header_len:
                raise FormatError("Truncated header.")
            try:
                header = json.loads(header_bytes)
                if header["version"] != VERSION or header["algorithm"] != "AES-256-GCM":
                    raise FormatError("Unsupported version or algorithm.")
                salt = bytes.fromhex(header["salt"])
                prefix = bytes.fromhex(header["nonce_prefix"])
                chunk_size = int(header["chunk_size"])
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as e:
                raise FormatError("Malformed header.") from e
            if len(salt) != 32 or len(prefix) != 8 or chunk_size != CHUNK_SIZE:
                raise FormatError("Invalid cryptographic parameters.")
            aes_key = _derive_aes_key(master, salt)
            aad_header = MAGIC + raw_len + header_bytes
            index = 0
            while True:
                raw_clen = inp.read(4)
                if len(raw_clen) != 4:
                    raise FormatError("Missing terminal record or truncated ciphertext.")
                clen = struct.unpack(">I", raw_clen)[0]
                if clen < 16 or clen > CHUNK_SIZE + 16:
                    raise FormatError("Invalid ciphertext record length.")
                ciphertext = inp.read(clen)
                if len(ciphertext) != clen:
                    raise FormatError("Truncated ciphertext record.")
                if index >= 2**32:
                    raise FormatError("Too many chunks.")
                nonce = prefix + struct.pack(">I", index)
                try:
                    plaintext = AESGCM(aes_key).decrypt(
                        nonce, ciphertext, aad_header + struct.pack(">I", index)
                    )
                    is_terminal = False
                except Exception:
                    # The terminal record uses a distinct AAD label with the
                    # same nonce index. Try it only as the final record.
                    try:
                        plaintext = AESGCM(aes_key).decrypt(
                            nonce, ciphertext, aad_header + b"END" + struct.pack(">I", index)
                        )
                        is_terminal = True
                    except Exception as e:
                        raise FormatError(
                            "Authentication failed: wrong key, damaged file, or tampering."
                        ) from e
                if is_terminal:
                    if plaintext != b"":
                        raise FormatError("Invalid terminal record.")
                    if inp.read(1):
                        raise FormatError("Unexpected trailing data.")
                    break
                if len(plaintext) > chunk_size:
                    raise FormatError("Plaintext chunk exceeds configured size.")
                out.write(plaintext)
                index += 1
            out.flush()
            os.fsync(out.fileno())
        if destination.exists() and force:
            destination.unlink()
        os.replace(temp_path, destination)
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def otp_encrypt(source: str | Path, destination: str | Path,
                pad_path: str | Path, force: bool = False) -> None:
    """One-time-pad encryption for a single message/file; pad must be fresh and same size."""
    source, destination, pad_path = Path(source), Path(destination), Path(pad_path)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; use --force to overwrite.")
    if pad_path.resolve() in (source.resolve(), destination.resolve()):
        raise ValueError("Pad, input, and output must be three different files.")
    plaintext = source.read_bytes()
    pad = pad_path.read_bytes()
    if len(pad) != len(plaintext):
        raise KeyErrorOblivion(
            f"One-time pad must be exactly the file size ({len(plaintext)} bytes); "
            f"got {len(pad)} bytes."
        )
    # This tool cannot reliably enforce non-reuse across copies/backups. It
    # therefore does not delete or mark the pad consumed automatically.
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, pad))
    header = OTP_MAGIC + struct.pack(">Q", len(ciphertext))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and force:
        destination.unlink()
    with destination.open("xb" if not force else "wb") as f:
        f.write(header)
        f.write(ciphertext)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass


def otp_decrypt(source: str | Path, destination: str | Path,
                pad_path: str | Path, force: bool = False) -> None:
    """Reverse OTP XOR; reusing a pad destroys perfect-secrecy guarantees."""
    source, destination, pad_path = Path(source), Path(destination), Path(pad_path)
    if source.resolve() == destination.resolve():
        raise ValueError("Source and destination must be different files.")
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; use --force to overwrite.")
    if pad_path.resolve() in (source.resolve(), destination.resolve()):
        raise ValueError("Pad, input, and output must be three different files.")
    data = source.read_bytes()
    if len(data) < len(OTP_MAGIC) + 8 or data[:len(OTP_MAGIC)] != OTP_MAGIC:
        raise FormatError("Not an OBLIVION one-time-pad file.")
    expected = struct.unpack(">Q", data[len(OTP_MAGIC):len(OTP_MAGIC) + 8])[0]
    ciphertext = data[len(OTP_MAGIC) + 8:]
    if len(ciphertext) != expected:
        raise FormatError("Truncated or malformed one-time-pad file.")
    pad = pad_path.read_bytes()
    if len(pad) != len(ciphertext):
        raise KeyErrorOblivion("Pad must be exactly the ciphertext length.")
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, pad))
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and force:
        destination.unlink()
    with destination.open("xb" if not force else "wb") as f:
        f.write(plaintext)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass
