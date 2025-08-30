# backend/app.py
# Usage meter backend.
# Scope: meters hardware the operator owns. It accepts signed counts and stores them.
# It sends nothing to any appliance and holds no vendor credentials.

from __future__ import annotations

import sqlite3

from fastapi import Depends, FastAPI, HTTPException

from .db import get_conn, utcnow_iso
from .models import ReportAccepted, UsageReport, UsageResponse
from .verify import verify_report

app = FastAPI(title="ble-usage-meter backend", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/reports", response_model=ReportAccepted)
def post_report(report: UsageReport, conn: sqlite3.Connection = Depends(get_conn)) -> ReportAccepted:
    result = verify_report(conn, report)
    if not result.ok:
        raise HTTPException(status_code=400, detail=result.detail)

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
    return ReportAccepted(device_id=report.device_id, sequence=report.sequence, count=report.count)


@app.get("/devices/{device_id}/usage", response_model=UsageResponse)
def get_usage(device_id: str, conn: sqlite3.Connection = Depends(get_conn)) -> UsageResponse:
    device = conn.execute(
        "SELECT last_accepted_sequence, last_accepted_count FROM devices WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if device is None:
        raise HTTPException(status_code=404, detail="unknown device")

    n = conn.execute(
        "SELECT COUNT(*) AS n FROM usage_reports WHERE device_id = ?", (device_id,)
    ).fetchone()["n"]

    return UsageResponse(
        device_id=device_id,
        total_count=int(device["last_accepted_count"]),
        last_accepted_sequence=int(device["last_accepted_sequence"]),
        reports=int(n),
    )
