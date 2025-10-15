# tests/test_replay.py
#
# THE security test. Everything else in this repo is bookkeeping; this is the part that
# stops a device holder from paying less than they owe.
#
# A valid signature proves origin, not freshness. Each case below is correctly signed with
# the device's real key and must still be rejected:
#   - the same report submitted twice (replay)
#   - a report carrying a sequence at or below the last accepted one (rollback of position)
#   - a report carrying a count below the last accepted one (rollback of the meter)
#
# Each assertion checks the structured reason code, not just the failure, so a future
# refactor cannot make these pass for the wrong reason.

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend import verify as bverify
from backend.db import init_db, utcnow_iso
from backend.models import UsageReport
from gateway.signer import ReportTuple, Signer

DEV = "dev-1"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())   # generated at test time


@pytest.fixture
def conn(tmp_path, signer):
    c = init_db(tmp_path / "backend.db")
    c.execute(
        "INSERT INTO devices (device_id, public_key, label, registered_at,"
        " last_accepted_sequence, last_accepted_count) VALUES (?, ?, NULL, ?, -1, 0)",
        (DEV, base64.b64encode(signer.public_key_bytes()).decode("ascii"), utcnow_iso()),
    )
    yield c
    c.close()


def sign_report(signer: Signer, count: int, sequence: int) -> UsageReport:
    start = BASE + timedelta(minutes=5 * sequence)
    end = start + timedelta(minutes=5)
    tup = ReportTuple(DEV, count, sequence, int(start.timestamp()), int(end.timestamp()))
    return UsageReport(
        device_id=DEV,
        count=count,
        sequence=sequence,
        window_start=start,
        window_end=end,
        signature=base64.b64encode(signer.sign(tup)).decode("ascii"),
    )


def accept(conn, report: UsageReport) -> None:
    """Record a report as accepted, advancing both high-water marks."""
    conn.execute(
        "INSERT INTO usage_reports (device_id, count, sequence, window_start, window_end,"
        " signature, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (report.device_id, report.count, report.sequence, report.window_start.isoformat(),
         report.window_end.isoformat(), report.signature, utcnow_iso()),
    )
    conn.execute(
        "UPDATE devices SET last_accepted_sequence = ?, last_accepted_count = ?"
        " WHERE device_id = ?",
        (report.sequence, report.count, report.device_id),
    )


def test_first_report_is_accepted(conn, signer):
    # Sanity: the marks start at -1/0 so an honest first report gets through once.
    assert bverify.verify_report(conn, sign_report(signer, count=10, sequence=0)).ok


def test_same_report_twice_is_rejected_the_second_time(conn, signer):
    report = sign_report(signer, count=10, sequence=1)

    first = bverify.verify_report(conn, report)
    assert first.ok, first.detail
    accept(conn, report)

    # Byte-identical resubmission. The signature is still perfectly valid, and that is
    # exactly the point: only the sequence high-water mark catches this.
    second = bverify.verify_report(conn, report)
    assert not second.ok
    assert second.code == bverify.CODE_REPLAY


def test_lower_sequence_is_rejected(conn, signer):
    current = sign_report(signer, count=50, sequence=5)
    assert bverify.verify_report(conn, current).ok
    accept(conn, current)

    stale = sign_report(signer, count=50, sequence=3)
    result = bverify.verify_report(conn, stale)
    assert not result.ok
    assert result.code == bverify.CODE_REPLAY


def test_equal_sequence_is_rejected_not_treated_as_idempotent(conn, signer):
    accepted = sign_report(signer, count=50, sequence=5)
    accept(conn, accepted)

    # Same sequence, different (higher) count. Treating equality as a harmless duplicate
    # would let a device reuse a sequence slot; equality must be a rejection.
    result = bverify.verify_report(conn, sign_report(signer, count=60, sequence=5))
    assert not result.ok
    assert result.code == bverify.CODE_REPLAY


def test_lower_count_is_rejected(conn, signer):
    accept(conn, sign_report(signer, count=100, sequence=5))

    # Fresh sequence, so the replay check passes, but the meter went backwards. The
    # gateway signed it honestly with its own key; the key proves origin, not truth.
    rolled_back = sign_report(signer, count=40, sequence=6)
    result = bverify.verify_report(conn, rolled_back)
    assert not result.ok
    assert result.code == bverify.CODE_COUNT_ROLLBACK


def test_equal_count_on_a_new_sequence_is_allowed(conn, signer):
    # A quiet window with no work done is legitimate: count stays put, sequence advances.
    accept(conn, sign_report(signer, count=100, sequence=5))
    assert bverify.verify_report(conn, sign_report(signer, count=100, sequence=6)).ok


def test_progress_after_a_rejection_still_works(conn, signer):
    # A rejection must not wedge the device: the next honest report is accepted.
    accept(conn, sign_report(signer, count=100, sequence=5))
    assert not bverify.verify_report(conn, sign_report(signer, count=40, sequence=6)).ok

    good = sign_report(signer, count=115, sequence=6)
    assert bverify.verify_report(conn, good).ok
    accept(conn, good)
    assert bverify.verify_report(conn, sign_report(signer, count=130, sequence=7)).ok


def test_replay_of_a_captured_report_from_the_wire(conn, signer):
    # Models an eavesdropper resubmitting a report they captured verbatim.
    original = sign_report(signer, count=10, sequence=1)
    accept(conn, original)

    captured = UsageReport(**original.model_dump())
    result = bverify.verify_report(conn, captured)
    assert not result.ok
    assert result.code == bverify.CODE_REPLAY


def test_signature_is_checked_before_sequence(conn, signer):
    # Order matters: an unauthenticated request should not learn the device's sequence
    # position from the error it gets back.
    accept(conn, sign_report(signer, count=100, sequence=5))

    attacker = Signer(Ed25519PrivateKey.generate())
    stale_and_forged = sign_report(attacker, count=1, sequence=1)
    result = bverify.verify_report(conn, stale_and_forged)
    assert result.code == bverify.CODE_BAD_SIGNATURE


def test_stored_reports_cannot_be_edited_to_hide_a_replay(conn, signer):
    import sqlite3

    accept(conn, sign_report(signer, count=100, sequence=5))
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE usage_reports SET count = 1 WHERE sequence = 5")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM usage_reports WHERE sequence = 5")
