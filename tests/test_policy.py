# tests/test_policy.py
# Policy evaluation, with the fail-closed behaviour tested as hard as the happy path.

from datetime import date

import pytest

from backend import policy as pol
from backend.db import init_db, utcnow_iso
from backend.models import PolicyRecord

DEV = "dev-1"
TODAY = date(2026, 6, 1)


def record(**kw) -> PolicyRecord:
    base = dict(device_id=DEV, active=True, quota_units=None, period_days=None,
                expires_on=None)
    base.update(kw)
    return PolicyRecord(**base)


# -- pure evaluation ---------------------------------------------------------

def test_within_quota_allows():
    d = pol.evaluate(record(quota_units=100, period_days=30), used=40, today=TODAY)
    assert d.allowed
    assert d.reason == pol.REASON_OK
    assert d.used_in_period == 40


def test_over_quota_denies():
    d = pol.evaluate(record(quota_units=100, period_days=30), used=100, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_OVER_QUOTA


def test_quota_boundary_is_exclusive():
    # 100 units of a 100-unit quota means the quota is spent.
    assert pol.evaluate(record(quota_units=100, period_days=30), 99, TODAY).allowed
    assert not pol.evaluate(record(quota_units=100, period_days=30), 100, TODAY).allowed


def test_no_quota_means_unlimited_units():
    assert pol.evaluate(record(quota_units=None), used=10_000, today=TODAY).allowed


def test_expired_denies():
    d = pol.evaluate(record(expires_on=date(2026, 5, 31)), used=0, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_EXPIRED


def test_expiry_on_the_day_itself_still_allows():
    assert pol.evaluate(record(expires_on=TODAY), used=0, today=TODAY).allowed


def test_expiry_beats_an_unused_quota():
    d = pol.evaluate(
        record(quota_units=100, period_days=30, expires_on=date(2025, 1, 1)), 0, TODAY
    )
    assert not d.allowed
    assert d.reason == pol.REASON_EXPIRED


def test_inactive_denies():
    d = pol.evaluate(record(active=False), used=0, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_INACTIVE


# -- fail closed -------------------------------------------------------------

def test_missing_policy_denies_by_default():
    d = pol.evaluate(None, used=0, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_NO_POLICY


def test_quota_without_a_period_is_unevaluable_and_denies():
    # "20 units per what?" Guessing a period generously would be a free grant.
    d = pol.evaluate(record(quota_units=20, period_days=None), used=0, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_UNEVALUABLE


def test_nonsense_period_denies():
    d = pol.evaluate(record(quota_units=20, period_days=0), used=0, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_UNEVALUABLE


def test_unknown_usage_denies_rather_than_assuming_zero():
    d = pol.evaluate(record(quota_units=20, period_days=30), used=None, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_UNEVALUABLE


# -- DB-backed ---------------------------------------------------------------

@pytest.fixture
def conn(tmp_path):
    c = init_db(tmp_path / "backend.db")
    c.execute(
        "INSERT INTO devices (device_id, public_key, label, registered_at,"
        " last_accepted_sequence, last_accepted_count)"
        " VALUES (?, 'REPLACE_ME', NULL, ?, -1, 0)",
        (DEV, utcnow_iso()),
    )
    yield c
    c.close()


def test_device_with_no_policy_row_denies(conn):
    d = pol.decide(conn, DEV, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_NO_POLICY


def test_corrupt_expiry_date_denies(conn):
    conn.execute(
        "INSERT INTO policies (device_id, active, quota_units, period_days, expires_on)"
        " VALUES (?, 1, NULL, NULL, 'not-a-date')",
        (DEV,),
    )
    d = pol.decide(conn, DEV, today=TODAY)
    assert not d.allowed
    assert d.reason == pol.REASON_UNEVALUABLE


def test_active_unlimited_policy_allows(conn):
    conn.execute(
        "INSERT INTO policies (device_id, active, quota_units, period_days, expires_on)"
        " VALUES (?, 1, NULL, NULL, NULL)",
        (DEV,),
    )
    assert pol.decide(conn, DEV, today=TODAY).allowed


def test_usage_in_period_uses_high_water_marks_not_a_sum(conn):
    # Counts are cumulative, so period usage is a difference between two marks.
    for seq, count, end in [
        (1, 100, "2026-01-01T00:00:00Z"),   # long before the window
        (2, 140, "2026-05-20T00:00:00Z"),
        (3, 175, "2026-05-30T00:00:00Z"),
    ]:
        conn.execute(
            "INSERT INTO usage_reports (device_id, count, sequence, window_start,"
            " window_end, signature, received_at) VALUES (?, ?, ?, ?, ?, 'x', ?)",
            (DEV, count, seq, end, end, utcnow_iso()),
        )

    from datetime import datetime, timezone

    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    used = pol.usage_in_period(conn, DEV, period_days=30, now=now)
    # Baseline is the last report ending before 2026-05-02, which is count 100.
    assert used == 75
