# OBLIVION-65536

An experimental open-source cryptography toolkit exploring very large master-key material and one-time-pad encryption.

**Status:** prototype; not independently audited. Do not use as the sole protection for high-value data.

## Important terminology

OBLIVION supports 65,536-bit (8,192-byte) and larger random master-key files. Its practical file-vault mode uses AES-256-GCM, so it does **not** provide 65,536-bit computational security. A larger master key does not increase the key size of AES-256.

The separate one-time-pad (OTP) mode can provide information-theoretic perfect secrecy only when all of the following are true:

- The pad is uniformly random and kept secret.
- The pad is at least as long as the plaintext.
- No pad byte is ever reused, including across backups or copies.
- The pad is securely delivered to the recipient.
- The threat model concerns confidentiality. This prototype's OTP mode does **not** authenticate messages, so tampering is not detected.

OTP mode is impractical for large files because it requires key material equal in size to the data. A 16,384-bit pad covers 2 KiB; a 122,880-bit pad covers 15 KiB.

## Install

Python 3.10+:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

## AES-256-GCM vault

Generate a 122,880-bit random master key (15 KiB):

```bash
oblivion keygen --bits 122880 --output master.key
chmod 600 master.key
```

Encrypt and decrypt:

```bash
oblivion encrypt report.pdf report.pdf.obl --key master.key
oblivion decrypt report.pdf.obl report-restored.pdf --key master.key
```

Use `--force` only when you intentionally want to replace an existing output.

## One-time pad

Generate a pad exactly as long as the input. Example for a 2 KiB message:

```bash
oblivion padgen --bytes 2048 --output message.pad
oblivion otp-encrypt message.txt message.txt.otp --pad message.pad
oblivion otp-decrypt message.txt.otp recovered.txt --pad message.pad
```

The example pad above is 2 KiB, so it only works with an input exactly 2 KiB long. To encrypt another file, generate a new pad matching that file's exact byte length. Never reuse a pad or any portion of it. Do not assume deleting a pad file guarantees all copies are gone.

## Commands

```text
oblivion keygen --bits N --output FILE
oblivion encrypt INPUT OUTPUT --key KEYFILE
oblivion decrypt INPUT OUTPUT --key KEYFILE
oblivion padgen --bytes N --output PADFILE
oblivion otp-encrypt INPUT OUTPUT --pad PADFILE
oblivion otp-decrypt INPUT OUTPUT --pad PADFILE
oblivion info
```

## Security notes and limitations

- The prototype has not been independently audited.
- AES mode authenticates each chunk and an explicit end marker, but the file format needs expert review before production use.
- OTP mode does not provide authenticity/integrity.
- Python cannot guarantee complete erasure of key bytes from process memory.
- The application does not manage OTP consumption across copies, backups, or machines. Reuse prevention must be enforced operationally.
- Passwords are not accepted as raw key material by default. Do not turn a memorable password into a huge key file and assume it has equivalent entropy.
- Use a well-reviewed, established product for critical data until this project has been audited.
