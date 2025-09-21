#!/usr/bin/env python3
# tools/keygen.py
"""Generate an Ed25519 keypair for a gateway.

Prints the public key (base64) for registration with the backend, and writes the private
key to a path you choose. The private key never leaves the gateway and must never be
committed; this tool refuses to write one inside a git working tree unless you force it.
"""

from __future__ import annotations

import argparse
import base64
import os
import stat
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def in_git_worktree(path: Path) -> Path | None:
    """Return the repo root if path sits inside a git working tree."""
    probe = path if path.is_dir() else path.parent
    probe = probe.resolve()

    # Walk up looking for .git. Cheaper and more predictable than shelling out, and it
    # still works when git is not installed on the gateway.
    for candidate in [probe, *probe.parents]:
        if (candidate / ".git").exists():
            return candidate

    try:
        out = subprocess.run(
            ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def write_private_key(key: Ed25519PrivateKey, dest: Path) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Create 0600 from the start; do not write then chmod, that leaves a readable window.
    fd = os.open(str(dest), os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True,
                    help="path to write the private key PEM, e.g. /etc/ble-meter/gateway.key")
    ap.add_argument("--force", action="store_true",
                    help="write even if the path is inside a git working tree")
    args = ap.parse_args(argv)

    dest: Path = args.out.expanduser()
    if dest.exists():
        print(f"refusing to overwrite existing key: {dest}", file=sys.stderr)
        return 2

    repo = in_git_worktree(dest)
    if repo is not None:
        print("=" * 72, file=sys.stderr)
        print(f"WARNING: {dest}", file=sys.stderr)
        print(f"is inside a git working tree ({repo}).", file=sys.stderr)
        print("A private key committed to a repo is a compromised key: anyone with the", file=sys.stderr)
        print("history can sign usage reports as this gateway. Write it outside the repo,", file=sys.stderr)
        print("for example /etc/ble-meter/gateway.key.", file=sys.stderr)
        print("=" * 72, file=sys.stderr)
        if not args.force:
            print("refusing. Re-run with --force only if you are certain.", file=sys.stderr)
            return 2
        print("--force given, writing anyway. Check .gitignore now.", file=sys.stderr)

    dest.parent.mkdir(parents=True, exist_ok=True)

    key = Ed25519PrivateKey.generate()
    write_private_key(key, dest)

    raw_pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_b64 = base64.b64encode(raw_pub).decode("ascii")

    print(f"private key written: {dest} (mode 0600)")
    print(f"public key (base64): {pub_b64}")
    print()
    print("Register it with the backend:")
    print('  curl -X POST "$BACKEND/devices" -H "Content-Type: application/json" \\')
    print(f'       -d \'{{"device_id": "<your-device-id>", "public_key": "{pub_b64}"}}\'')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
