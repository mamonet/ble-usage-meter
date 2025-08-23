# backend/policy.py
# Licence policy evaluation: activation, N units per period, expiry date.
#
# FAIL CLOSED. Every path that cannot reach a confident "allow" returns deny: no policy row,
# a malformed row, an unparseable date, a quota with no period to measure it over, an
# unreadable usage total. The alternative (allow on error) means a corrupt row or a dropped
# column silently grants unlimited use, and nobody notices until the billing period closes.
# Deny is visible and recoverable; a silent allow is neither.

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from .models import LicenseDecision, PolicyRecord

REASON_OK = "within_policy"
REASON_NO_POLICY = "no_policy_on_record"
REASON_INACTIVE = "not_activated"
REASON_EXPIRED = "expired"
REASON_OVER_QUOTA = "quota_exceeded"
REASON_UNEVALUABLE = "policy_unevaluable"


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    used_in_period: Optional[int] = None
    quota_units: Optional[int] = None
    expires_on: Optional[date] = None


def load_policy(conn: sqlite3.Connection, device_id: str) -> Optional[PolicyRecord]:
    row = conn.execute(
        "SELECT device_id, active, quota_units, period_days, expires_on, notes"
        " FROM policies WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        expires = date.fromisoformat(row["expires_on"]) if row["expires_on"] else None
    except (ValueError, TypeError):
        # Unparseable date. Do not treat as "no expiry"; let evaluate() deny.
        raise PolicyUnevaluable(f"expires_on is not an ISO date: {row['expires_on']!r}")
    return PolicyRecord(
        device_id=row["device_id"],
        active=bool(row["active"]),
        quota_units=row["quota_units"],
        period_days=row["period_days"],
        expires_on=expires,
        notes=row["notes"],
    )


class PolicyUnevaluable(Exception):
    """Raised when a policy row exists but cannot be turned into a decision."""


def usage_in_period(conn: sqlite3.Connection, device_id: str, period_days: int,
                    now: Optional[datetime] = None) -> int:
    """Units consumed in the rolling period.

    Counts are cumulative high-water marks, so usage in a window is (latest count in window)
    minus (latest count strictly before the window), not a sum of report counts.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=period_days)).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    latest = conn.execute(
        "SELECT count FROM usage_reports WHERE device_id = ?"
        " ORDER BY sequence DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    if latest is None:
        return 0

    baseline = conn.execute(
        "SELECT count FROM usage_reports WHERE device_id = ? AND window_end < ?"
        " ORDER BY sequence DESC LIMIT 1",
        (device_id, cutoff),
    ).fetchone()

    start = int(baseline["count"]) if baseline is not None else 0
    return max(0, int(latest["count"]) - start)


def evaluate(policy: Optional[PolicyRecord], used: Optional[int],
             today: Optional[date] = None) -> Decision:
    """Pure decision function. Any uncertainty resolves to deny."""
    today = today or datetime.now(timezone.utc).date()

    if policy is None:
        return Decision(False, REASON_NO_POLICY)

    if not policy.active:
        return Decision(False, REASON_INACTIVE, expires_on=policy.expires_on)

    if policy.expires_on is not None and today > policy.expires_on:
        return Decision(False, REASON_EXPIRED, expires_on=policy.expires_on)

    if policy.quota_units is not None:
        # A unit cap with no period is meaningless: "20 units per what?". Deny rather than
        # guess a period, because guessing generous is a free grant.
        if policy.period_days is None or policy.period_days <= 0:
            return Decision(False, REASON_UNEVALUABLE, quota_units=policy.quota_units)
        if used is None:
            return Decision(False, REASON_UNEVALUABLE, quota_units=policy.quota_units)
        if used >= policy.quota_units:
            return Decision(False, REASON_OVER_QUOTA, used_in_period=used,
                            quota_units=policy.quota_units, expires_on=policy.expires_on)
        return Decision(True, REASON_OK, used_in_period=used,
                        quota_units=policy.quota_units, expires_on=policy.expires_on)

    return Decision(True, REASON_OK, expires_on=policy.expires_on)


def decide(conn: sqlite3.Connection, device_id: str,
           today: Optional[date] = None) -> LicenseDecision:
    """DB-backed entry point. Every failure mode lands on deny."""
    try:
        policy = load_policy(conn, device_id)
    except (PolicyUnevaluable, sqlite3.Error, ValueError, TypeError):
        return LicenseDecision(device_id=device_id, allowed=False, reason=REASON_UNEVALUABLE)

    used: Optional[int] = None
    if policy is not None and policy.quota_units is not None and policy.period_days:
        try:
            used = usage_in_period(conn, device_id, policy.period_days)
        except sqlite3.Error:
            used = None  # evaluate() denies on an unknown usage total

    d = evaluate(policy, used, today=today)
    return LicenseDecision(
        device_id=device_id,
        allowed=d.allowed,
        reason=d.reason,
        used_in_period=d.used_in_period,
        quota_units=d.quota_units,
        expires_on=d.expires_on,
    )
