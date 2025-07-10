# backend/models.py
# Wire and storage shapes for the usage meter backend.
# Scope: this meters hardware the operator owns. Nothing here bypasses or unlocks anything.

from __future__ import annotations

from datetime import datetime, date, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_validator


# Canonical serialisation. Byte-for-byte identical to firmware/esp32/signer.cpp
# canonical_bytes() and gateway/signer.py. Changing anything here breaks every existing
# signature, so bump CANONICAL_FORMAT_VERSION if you do.
#
# Sign bytes, not a dict. A JSON object has no inherent key order and encoders differ on
# whitespace, integer formatting and escaping, so two encoders give two signatures for the
# same data. A C struct is worse: padding and endianness are implementation defined.
#
# Layout:
#   domain string (ASCII, no terminator, no length prefix)
#   1 byte  format version
#   2 bytes big-endian length of device_id, then its UTF-8 bytes
#   8 bytes big-endian count
#   8 bytes big-endian sequence
#   8 bytes big-endian window_start, unix seconds
#   8 bytes big-endian window_end,   unix seconds
#
# device_id is length-prefixed so ("ab","c") and ("a","bc") cannot serialise alike.
# The domain string is separation: a report signature can never be reused as a signature
# over some other message the same key signs.
CANONICAL_DOMAIN = b"ble-usage-meter/report/v1"
CANONICAL_FORMAT_VERSION = 1


def canonical_unix_seconds(value: datetime) -> int:
    """Whole unix seconds UTC. A naive datetime is treated as UTC, not local time."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return int(value.astimezone(timezone.utc).timestamp())


def canonical_message(
    device_id: str,
    count: int,
    sequence: int,
    window_start: datetime,
    window_end: datetime,
) -> bytes:
    """The exact bytes that are signed and verified. Do not reorder these fields."""
    did = device_id.encode("utf-8")
    if len(did) > 0xFFFF:
        raise ValueError("device_id too long for the 2-byte length prefix")

    out = bytearray(CANONICAL_DOMAIN)
    out.append(CANONICAL_FORMAT_VERSION)
    out += len(did).to_bytes(2, "big")
    out += did
    out += int(count).to_bytes(8, "big")
    out += int(sequence).to_bytes(8, "big")
    out += canonical_unix_seconds(window_start).to_bytes(8, "big")
    out += canonical_unix_seconds(window_end).to_bytes(8, "big")
    return bytes(out)


class UsageReport(BaseModel):
    """A signed count for one reporting window."""

    device_id: str = Field(min_length=1, max_length=128)
    count: int = Field(ge=0)
    sequence: int = Field(ge=0)
    window_start: datetime
    window_end: datetime
    signature: str = Field(min_length=1, description="base64 Ed25519 signature over canonical_message()")

    @field_validator("window_end")
    @classmethod
    def _window_ordered(cls, v: datetime, info):
        start = info.data.get("window_start")
        if start is not None and v < start:
            raise ValueError("window_end precedes window_start")
        return v

    def canonical_bytes(self) -> bytes:
        return canonical_message(
            self.device_id, self.count, self.sequence, self.window_start, self.window_end
        )


class DeviceRecord(BaseModel):
    """A registered gateway/device and the high-water marks used to reject rollback."""

    device_id: str
    public_key: str = Field(description="base64 raw Ed25519 public key, 32 bytes")
    label: Optional[str] = None
    registered_at: Optional[datetime] = None
    last_accepted_sequence: int = -1  # -1 means nothing accepted yet, so sequence 0 is valid
    last_accepted_count: int = 0


class PolicyRecord(BaseModel):
    """Licence terms for one device. Absent or unparseable means deny (see policy.py)."""

    device_id: str
    active: bool = False
    quota_units: Optional[int] = None       # units allowed per period; None means unlimited
    period_days: Optional[int] = None       # rolling period length for the quota
    expires_on: Optional[date] = None       # hard stop regardless of quota
    notes: Optional[str] = None


class RegisterDeviceRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=128)
    public_key: str = Field(min_length=1)
    label: Optional[str] = None


class RejectionReason(BaseModel):
    """Structured rejection so a caller can tell a replay from a bad signature."""

    code: str
    detail: str


class ReportAccepted(BaseModel):
    accepted: bool = True
    device_id: str
    sequence: int
    count: int


class UsageResponse(BaseModel):
    device_id: str
    total_count: int
    last_accepted_sequence: int
    reports: int


class LicenseDecision(BaseModel):
    device_id: str
    allowed: bool
    reason: str
    used_in_period: Optional[int] = None
    quota_units: Optional[int] = None
    expires_on: Optional[date] = None
