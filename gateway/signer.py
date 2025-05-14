"""gateway/signer.py

Ed25519 signing over the same canonical byte serialisation the firmware uses, so either
the ESP32 or this gateway can produce a report the backend verifies with one code path.

Why bytes and not a dict:
  - A Python dict has no guaranteed order across producers, and JSON encoders differ on
    whitespace, key order, integer and float formatting, and escaping. Two encoders give
    two signatures for the same data, so verification becomes luck.
  - A C struct is worse: padding and endianness are platform-dependent.
So the tuple is flattened to one explicit byte string, matching signer.cpp exactly: domain
tag, format version, then each field length-prefixed or big-endian fixed width. Any change
here must be mirrored in firmware/esp32/signer.cpp and must bump FORMAT_VERSION.

The private key is read from a file path at runtime. It is never inline in this repo and
never committed. Config ships REPLACE_ME placeholders only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAIN = b"ble-usage-meter/report/v1"
FORMAT_VERSION = 1


@dataclass(frozen=True)
class ReportTuple:
    device_id: str
    count: int
    sequence: int
    window_start: int
    window_end: int


def canonical_bytes(r: ReportTuple) -> bytes:
    """Byte-for-byte identical to canonical_bytes() in firmware/esp32/signer.cpp."""
    dev = r.device_id.encode("utf-8")
    if len(dev) > 0xFFFF:
        raise ValueError("device_id too long")
    return b"".join(
        (
            DOMAIN,
            bytes([FORMAT_VERSION]),
            # 2-byte big-endian length prefix stops ("ab","c") and ("a","bc") colliding.
            struct.pack(">H", len(dev)),
            dev,
            struct.pack(">QQQQ", r.count, r.sequence, r.window_start, r.window_end),
        )
    )


class Signer:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def from_file(cls, path: str | Path, password: bytes | None = None) -> "Signer":
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"no signing key at {p}, generate one with tools/keygen.py")
        data = p.read_bytes()
        if b"REPLACE_ME" in data:
            raise ValueError(f"{p} is still a placeholder, provision a real key")
        key = serialization.load_pem_private_key(data, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("signing key must be Ed25519")
        return cls(key)

    def public_key_bytes(self) -> bytes:
        return self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, r: ReportTuple) -> bytes:
        """64-byte detached signature over canonical_bytes(r)."""
        return self._key.sign(canonical_bytes(r))


def verify(public_key: bytes | Ed25519PublicKey, r: ReportTuple, signature: bytes) -> bool:
    """Local self-check. The backend runs the authoritative check in backend/verify.py."""
    pk = (
        public_key
        if isinstance(public_key, Ed25519PublicKey)
        else Ed25519PublicKey.from_public_bytes(public_key)
    )
    try:
        pk.verify(signature, canonical_bytes(r))
    except Exception:
        return False
    return True
