# backend/verify.py
# Signature verification for incoming usage reports.

from __future__ import annotations

import base64
import sqlite3
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .models import UsageReport


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    code: str = "ok"
    detail: str = ""


def load_public_key(b64_key: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64_key, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def check_signature(report: UsageReport, public_key_b64: str) -> VerifyResult:
    """Ed25519 check over the same canonical bytes the gateway signed.

    The message is built by models.canonical_message(), never from a re-serialised dict:
    if the backend and the gateway disagree by one byte the check fails for the wrong reason.
    """
    try:
        pub = load_public_key(public_key_b64)
    except Exception as exc:
        return VerifyResult(False, "bad_registered_key", f"stored key unusable: {exc}")

    try:
        sig = base64.b64decode(report.signature, validate=True)
    except Exception:
        return VerifyResult(False, "bad_signature_encoding", "signature is not valid base64")

    try:
        pub.verify(sig, report.canonical_bytes())
    except InvalidSignature:
        return VerifyResult(False, "bad_signature", "signature does not match the registered key")

    return VerifyResult(True)


def fetch_device(conn: sqlite3.Connection, device_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT device_id, public_key, last_accepted_sequence, last_accepted_count"
        " FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()


def verify_report(conn: sqlite3.Connection, report: UsageReport) -> VerifyResult:
    device = fetch_device(conn, report.device_id)
    if device is None:
        return VerifyResult(False, "unknown_device", "device is not registered")
    return check_signature(report, device["public_key"])
