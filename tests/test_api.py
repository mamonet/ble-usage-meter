# tests/test_api.py
# End to end over the HTTP surface with TestClient. No hardware, no network.
# Keys are generated per test; nothing in this file is a committed key.

import base64
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from backend.app import app
from backend.db import get_conn, init_db
from gateway.signer import ReportTuple, Signer

DEV = "dev-1"
BASE = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "backend.db"
    init_db(db_path).close()

    def override():
        conn = init_db(db_path)
        try:
            yield conn
        finally:
            conn.close()

    app.dependency_overrides[get_conn] = override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def signer() -> Signer:
    return Signer(Ed25519PrivateKey.generate())


def pub_b64(signer: Signer) -> str:
    return base64.b64encode(signer.public_key_bytes()).decode("ascii")


def report_body(signer: Signer, count: int, sequence: int, device_id: str = DEV) -> dict:
    start = BASE + timedelta(minutes=5 * sequence)
    end = start + timedelta(minutes=5)
    tup = ReportTuple(device_id, count, sequence, int(start.timestamp()), int(end.timestamp()))
    return {
        "device_id": device_id,
        "count": count,
        "sequence": sequence,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "signature": base64.b64encode(signer.sign(tup)).decode("ascii"),
    }


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_register_post_report_read_usage(client, signer):
    r = client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    assert r.status_code == 201, r.text

    r = client.post("/reports", json=report_body(signer, count=25, sequence=1))
    assert r.status_code == 200, r.text
    assert r.json()["accepted"] is True

    r = client.get(f"/devices/{DEV}/usage")
    assert r.status_code == 200
    body = r.json()
    assert body["total_count"] == 25
    assert body["last_accepted_sequence"] == 1
    assert body["reports"] == 1


def test_successive_reports_accumulate(client, signer):
    client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    for seq, count in [(1, 10), (2, 22), (3, 30)]:
        assert client.post("/reports", json=report_body(signer, count, seq)).status_code == 200

    body = client.get(f"/devices/{DEV}/usage").json()
    assert body["total_count"] == 30
    assert body["reports"] == 3


def test_unregistered_device_is_rejected(client, signer):
    r = client.post("/reports", json=report_body(signer, count=1, sequence=1))
    assert r.status_code == 404
    assert r.json()["code"] == "unknown_device"


def test_usage_for_unknown_device_is_404(client):
    assert client.get("/devices/nope/usage").status_code == 404


def test_bad_signature_is_401(client, signer):
    client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    body = report_body(signer, count=25, sequence=1)
    body["count"] = 5          # edited after signing
    r = client.post("/reports", json=body)
    assert r.status_code == 401
    assert r.json()["code"] == "bad_signature"


def test_replay_over_http_is_409(client, signer):
    client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    body = report_body(signer, count=25, sequence=1)
    assert client.post("/reports", json=body).status_code == 200

    r = client.post("/reports", json=body)
    assert r.status_code == 409
    assert r.json()["code"] == "replay_or_rollback_sequence"


def test_count_rollback_over_http_is_409(client, signer):
    client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    client.post("/reports", json=report_body(signer, count=100, sequence=1))

    r = client.post("/reports", json=report_body(signer, count=40, sequence=2))
    assert r.status_code == 409
    assert r.json()["code"] == "count_rollback"


def test_registering_twice_is_refused(client, signer):
    payload = {"device_id": DEV, "public_key": pub_b64(signer)}
    assert client.post("/devices", json=payload).status_code == 201

    # Re-keying via a plain re-register would let anyone with API access sign as this
    # device. Rotation has to be deliberate.
    attacker = Signer(Ed25519PrivateKey.generate())
    r = client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(attacker)})
    assert r.status_code == 400
    assert r.json()["code"] == "device_exists"


def test_malformed_public_key_is_refused(client):
    r = client.post("/devices", json={"device_id": DEV, "public_key": "not-base64!!"})
    assert r.status_code == 400
    assert r.json()["code"] == "bad_public_key"

    short = base64.b64encode(b"\x00" * 16).decode("ascii")
    r = client.post("/devices", json={"device_id": DEV, "public_key": short})
    assert r.status_code == 400


def test_license_denies_when_no_policy_is_set(client, signer):
    client.post("/devices", json={"device_id": DEV, "public_key": pub_b64(signer)})
    r = client.get(f"/devices/{DEV}/license")
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is False
    assert body["reason"] == "no_policy_on_record"


def test_license_for_unknown_device_denies(client):
    body = client.get("/devices/nope/license").json()
    assert body["allowed"] is False
