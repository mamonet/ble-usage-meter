# tests/test_sign_verify.py
# A report signed by the gateway must verify in the backend, and any edit to it must not.
#
# Every key here is generated at runtime. No key material is committed to this repo, not
# even a test key: a literal private key in a test file is still a private key in git.

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from backend import verify as bverify
from backend.db import init_db, utcnow_iso
from backend.models import UsageReport, canonical_message
from gateway.signer import ReportTuple, Signer
from gateway.signer import canonical_bytes as gw_canonical_bytes

DEV = "dev-1"
WINDOW_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(minutes=5)


@pytest.fixture
def signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())  # generated per test, never a literal


@pytest.fixture
def conn(tmp_path):
    c = init_db(tmp_path / "backend.db")
    yield c
    c.close()


def register(conn, signer: Signer, device_id: str = DEV) -> str:
    pub_b64 = base64.b64encode(signer.public_key_bytes()).decode("ascii")
    conn.execute(
        "INSERT INTO devices (device_id, public_key, label, registered_at,"
        " last_accepted_sequence, last_accepted_count) VALUES (?, ?, NULL, ?, -1, 0)",
        (device_id, pub_b64, utcnow_iso()),
    )
    return pub_b64


def make_report(signer: Signer, count: int = 42, sequence: int = 1,
                device_id: str = DEV) -> UsageReport:
    tup = ReportTuple(
        device_id=device_id,
        count=count,
        sequence=sequence,
        window_start=int(WINDOW_START.timestamp()),
        window_end=int(WINDOW_END.timestamp()),
    )
    sig = signer.sign(tup)
    return UsageReport(
        device_id=device_id,
        count=count,
        sequence=sequence,
        window_start=WINDOW_START,
        window_end=WINDOW_END,
        signature=base64.b64encode(sig).decode("ascii"),
    )


def test_canonical_serialisation_agrees_across_sides():
    # If these two ever diverge, every signature silently stops verifying. Pin it.
    tup = ReportTuple(DEV, 42, 1, int(WINDOW_START.timestamp()), int(WINDOW_END.timestamp()))
    assert gw_canonical_bytes(tup) == canonical_message(
        DEV, 42, 1, WINDOW_START, WINDOW_END
    )


def test_canonical_bytes_are_domain_separated():
    msg = canonical_message(DEV, 1, 1, WINDOW_START, WINDOW_END)
    assert msg.startswith(b"ble-usage-meter/report/v1")


def test_length_prefix_stops_field_run_together():
    # ("ab","c") and ("a","bc") style collisions must be impossible.
    a = canonical_message("ab", 1, 2, WINDOW_START, WINDOW_END)
    b = canonical_message("a", 1, 2, WINDOW_START, WINDOW_END)
    assert a != b


def test_gateway_signed_report_verifies_in_backend(conn, signer):
    register(conn, signer)
    result = bverify.verify_report(conn, make_report(signer))
    assert result.ok, result.detail


def test_tampered_count_fails(conn, signer):
    register(conn, signer)
    report = make_report(signer, count=42)

    # The device holder edits the count downward but keeps the original signature.
    forged = report.model_copy(update={"count": 7})
    result = bverify.check_signature(forged, base64.b64encode(signer.public_key_bytes()).decode())
    assert not result.ok
    assert result.code == bverify.CODE_BAD_SIGNATURE


@pytest.mark.parametrize("field,value", [
    ("sequence", 99),
    ("device_id", "dev-2"),
    ("window_end", WINDOW_END + timedelta(hours=1)),
])
def test_tampering_with_any_signed_field_fails(conn, signer, field, value):
    pub = register(conn, signer)
    report = make_report(signer)
    forged = report.model_copy(update={field: value})
    assert not bverify.check_signature(forged, pub).ok


def test_signature_from_a_different_key_fails(conn, signer):
    register(conn, signer)
    attacker = Signer(Ed25519PrivateKey.generate())
    report = make_report(attacker)          # correctly signed, wrong key
    result = bverify.verify_report(conn, report)
    assert not result.ok
    assert result.code == bverify.CODE_BAD_SIGNATURE


def test_unregistered_device_is_rejected(conn, signer):
    result = bverify.verify_report(conn, make_report(signer))
    assert not result.ok
    assert result.code == bverify.CODE_UNKNOWN_DEVICE


def test_malformed_signature_encoding_is_reported_distinctly(conn, signer):
    pub = register(conn, signer)
    report = make_report(signer).model_copy(update={"signature": "not base64 !!"})
    result = bverify.check_signature(report, pub)
    assert not result.ok
    assert result.code == bverify.CODE_BAD_SIGNATURE_ENCODING
