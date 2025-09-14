# backend/app.py
# Usage meter backend.
# Scope: meters hardware the operator owns. It accepts signed counts, stores them, and
# answers a licence question about them. It sends nothing to any appliance, drives no
# device behaviour, and holds no vendor credentials.

from __future__ import annotations

import base64
import sqlite3

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse

from . import policy as policy_mod
from .db import get_conn, utcnow_iso
from .models import (
    LicenseDecision,
    RegisterDeviceRequest,
    ReportAccepted,
    UsageReport,
    UsageResponse,
)
from .verify import (
    CODE_BAD_SIGNATURE,
    CODE_BAD_SIGNATURE_ENCODING,
    CODE_COUNT_ROLLBACK,
    CODE_REPLAY,
    CODE_UNKNOWN_DEVICE,
    verify_report,
)

app = FastAPI(title="ble-usage-meter backend", version="0.2.0")

# Rejection code -> HTTP status. Replay and rollback are 409: the request was authentic and
# well formed, it just conflicts with history the backend already has. A client that cannot
# tell those apart from a bad signature will retry the wrong things.
STATUS_FOR_CODE = {
    CODE_UNKNOWN_DEVICE: 404,
    CODE_BAD_SIGNATURE: 401,
    CODE_BAD_SIGNATURE_ENCODING: 400,
    CODE_REPLAY: 409,
    CODE_COUNT_ROLLBACK: 409,
}


def _rejection(code: str, detail: str) -> JSONResponse:
    """Structured rejection body. Callers branch on `code`, humans read `detail`."""
    return JSONResponse(
        status_code=STATUS_FOR_CODE.get(code, 400),
        content={"accepted": False, "code": code, "detail": detail},
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/devices", status_code=201)
def register_device(req: RegisterDeviceRequest, conn: sqlite3.Connection = Depends(get_conn)):
    """Register a gateway's public key. Registration is out of band and operator-driven.

    Re-registering an existing device_id is refused: silently swapping a public key would
    let anyone with API access re-key a device and then sign whatever count they liked.
    Rotation is a deliberate operation, see docs/deployment.md.
    """
    try:
        raw = base64.b64decode(req.public_key, validate=True)
    except Exception:
        return _rejection("bad_public_key", "public_key is not valid base64")
    if len(raw) != 32:
        return _rejection("bad_public_key", "Ed25519 public key must decode to 32 bytes")

    existing = conn.execute(
        "SELECT device_id FROM devices WHERE device_id = ?", (req.device_id,)
    ).fetchone()
    if existing is not None:
        return _rejection("device_exists", "device already registered; rotate explicitly")

    conn.execute(
        "INSERT INTO devices (device_id, public_key, label, registered_at,"
        " last_accepted_sequence, last_accepted_count) VALUES (?, ?, ?, ?, -1, 0)",
        (req.device_id, req.public_key, req.label, utcnow_iso()),
    )
    return {"device_id": req.device_id, "registered": True}


@app.post("/reports")
def post_report(report: UsageReport, conn: sqlite3.Connection = Depends(get_conn)):
    result = verify_report(conn, report)
    if not result.ok:
        return _rejection(result.code, result.detail)

    # Append the report, then advance the high-water marks. Both in one transaction: a
    # stored report whose marks did not move would let the same sequence in again.
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO usage_reports"
            " (device_id, count, sequence, window_start, window_end, signature, received_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                report.device_id,
                report.count,
                report.sequence,
                report.window_start.isoformat(),
                report.window_end.isoformat(),
                report.signature,
                utcnow_iso(),
            ),
        )
        conn.execute(
            "UPDATE devices SET last_accepted_sequence = ?, last_accepted_count = ?"
            " WHERE device_id = ?",
            (report.sequence, report.count, report.device_id),
        )
        conn.execute("COMMIT")
    except sqlite3.IntegrityError:
        # UNIQUE(device_id, sequence). Reached only if two identical reports race past the
        # sequence check concurrently; same meaning as a replay.
        conn.execute("ROLLBACK")
        return _rejection(CODE_REPLAY, "a report with this sequence is already stored")

    return ReportAccepted(
        device_id=report.device_id, sequence=report.sequence, count=report.count
    )


@app.get("/devices/{device_id}/usage", response_model=UsageResponse)
def get_usage(device_id: str, conn: sqlite3.Connection = Depends(get_conn)):
    device = conn.execute(
        "SELECT last_accepted_sequence, last_accepted_count FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if device is None:
        return _rejection(CODE_UNKNOWN_DEVICE, "device is not registered")

    n = conn.execute(
        "SELECT COUNT(*) AS n FROM usage_reports WHERE device_id = ?", (device_id,)
    ).fetchone()["n"]

    return UsageResponse(
        device_id=device_id,
        total_count=int(device["last_accepted_count"]),
        last_accepted_sequence=int(device["last_accepted_sequence"]),
        reports=int(n),
    )


@app.get("/devices/{device_id}/license", response_model=LicenseDecision)
def get_license(device_id: str, conn: sqlite3.Connection = Depends(get_conn)):
    """Policy decision for this device. Unknown or unevaluable resolves to deny."""
    device = conn.execute(
        "SELECT device_id FROM devices WHERE device_id = ?", (device_id,)
    ).fetchone()
    if device is None:
        return LicenseDecision(
            device_id=device_id, allowed=False, reason=policy_mod.REASON_NO_POLICY
        )
    return policy_mod.decide(conn, device_id)
