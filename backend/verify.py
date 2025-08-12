# backend/verify.py
# Verification for incoming usage reports: signature, then freshness, then monotonicity.
#
# v1 checked only the signature. That was not enough. A signature proves a report was
# authentic when it was made; it says nothing about *when* it arrived or whether it is the
# latest. Two attacks got through:
#
#   1. Replay. An old report is still perfectly signed. Anyone who captured one (or the
#      device holder, who has all of them) could resubmit it forever and freeze their usage.
#   2. Rollback. A gateway holding its own key can honestly sign a report with a *lower*
#      count than one already accepted, and a signature-only backend would take it and
#      revise the bill downwards.
#
# The fixes below are the whole point of this module. Neither is optional.

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


# Structured rejection codes. Callers and tests match on these, not on message text.
CODE_OK = "ok"
CODE_UNKNOWN_DEVICE = "unknown_device"
CODE_BAD_SIGNATURE = "bad_signature"
CODE_BAD_SIGNATURE_ENCODING = "bad_signature_encoding"
CODE_BAD_REGISTERED_KEY = "bad_registered_key"
CODE_REPLAY = "replay_or_rollback_sequence"
CODE_COUNT_ROLLBACK = "count_rollback"


def load_public_key(b64_key: str) -> Ed25519PublicKey:
    raw = base64.b64decode(b64_key, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def check_signature(report: UsageReport, public_key_b64: str) -> VerifyResult:
    """Ed25519 check over the same canonical bytes the gateway signed.

    The message comes from models.canonical_message(), never from a re-serialised dict.
    """
    try:
        pub = load_public_key(public_key_b64)
    except Exception as exc:
        return VerifyResult(False, CODE_BAD_REGISTERED_KEY, f"stored key unusable: {exc}")

    try:
        sig = base64.b64decode(report.signature, validate=True)
    except Exception:
        return VerifyResult(False, CODE_BAD_SIGNATURE_ENCODING, "signature is not valid base64")

    try:
        pub.verify(sig, report.canonical_bytes())
    except InvalidSignature:
        return VerifyResult(False, CODE_BAD_SIGNATURE, "signature does not match the registered key")

    return VerifyResult(True)


def check_sequence(report: UsageReport, last_accepted_sequence: int) -> VerifyResult:
    """FIX 1, anti-replay.

    Reject any sequence at or below the last one accepted for this device. Equality is a
    rejection, not an idempotent no-op: resubmitting the identical signed report is exactly
    what a replay looks like, and treating it as harmless is what let the attack work.
    The stored high-water mark starts at -1 so a first report at sequence 0 is accepted once.
    """
    if report.sequence <= last_accepted_sequence:
        return VerifyResult(
            False,
            CODE_REPLAY,
            f"sequence {report.sequence} <= last accepted {last_accepted_sequence}",
        )
    return VerifyResult(True)


def check_count_monotonic(report: UsageReport, last_accepted_count: int) -> VerifyResult:
    """FIX 2, anti-rollback.

    The counter is monotonic by construction on the gateway, so a fresh sequence carrying a
    count *below* the stored one means the counter was reset, restored from an old backup, or
    edited. A correctly signed report is not a truthful one; the key only proves origin.
    Reject rather than clamp, so the operator sees the anomaly instead of silently losing it.
    """
    if report.count < last_accepted_count:
        return VerifyResult(
            False,
            CODE_COUNT_ROLLBACK,
            f"count {report.count} below last accepted {last_accepted_count}",
        )
    return VerifyResult(True)


def fetch_device(conn: sqlite3.Connection, device_id: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT device_id, public_key, last_accepted_sequence, last_accepted_count"
        " FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()


def verify_report(conn: sqlite3.Connection, report: UsageReport) -> VerifyResult:
    """Full gate. Order matters: authenticate first, then judge freshness."""
    device = fetch_device(conn, report.device_id)
    if device is None:
        return VerifyResult(False, CODE_UNKNOWN_DEVICE, "device is not registered")

    sig = check_signature(report, device["public_key"])
    if not sig.ok:
        return sig

    seq = check_sequence(report, int(device["last_accepted_sequence"]))
    if not seq.ok:
        return seq

    return check_count_monotonic(report, int(device["last_accepted_count"]))
