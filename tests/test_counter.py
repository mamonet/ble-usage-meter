# tests/test_counter.py
# The counter is the source of truth for billing, so monotonicity and durability are
# tested directly rather than assumed.

import sqlite3

import pytest

from gateway.counter import Counter
from gateway.store import Store

DEV = "dev-1"


def test_counter_starts_at_zero():
    assert Counter().get(DEV) == 0


def test_increment_is_monotonic():
    c = Counter()
    seen = [c.increment(DEV) for _ in range(10)]
    assert seen == list(range(1, 11))
    assert all(b > a for a, b in zip(seen, seen[1:]))


def test_no_decrement_api():
    # There is deliberately no decrement/reset/set. Absence is the control.
    c = Counter()
    for name in ("decrement", "reset", "set", "set_count", "clear"):
        assert not hasattr(c, name), f"Counter grew a {name}() method"


def test_increment_rejects_non_positive():
    c = Counter()
    with pytest.raises(ValueError):
        c.increment(DEV, 0)
    with pytest.raises(ValueError):
        c.increment(DEV, -5)


def test_restore_will_not_lower_a_live_value():
    c = Counter()
    for _ in range(7):
        c.increment(DEV)
    c.restore(DEV, 3)          # stale persisted value, must be ignored
    assert c.get(DEV) == 7
    c.restore(DEV, 12)         # newer value, applied
    assert c.get(DEV) == 12


def test_sequence_never_repeats():
    c = Counter()
    seqs = [c.next_sequence() for _ in range(5)]
    assert seqs == [1, 2, 3, 4, 5]
    assert len(set(seqs)) == len(seqs)


def test_restart_resumes_from_persisted_value(tmp_path):
    db = tmp_path / "meter.sqlite3"

    with Store(db) as store:
        c = Counter()
        for _ in range(4):
            store.save_counter(DEV, c.increment(DEV))
        store.save_sequence(c.next_sequence())

    # Process restart: new Counter, state comes back from disk.
    with Store(db) as store:
        c2 = Counter()
        for device_id, count in store.load_counters().items():
            c2.restore(device_id, count)
        c2.restore_sequence(store.load_sequence())

        assert c2.get(DEV) == 4
        assert c2.sequence == 1
        # It continues upward rather than restarting at 1.
        assert c2.increment(DEV) == 5
        assert c2.next_sequence() == 2


def test_store_rejects_a_lowered_counter(tmp_path):
    with Store(tmp_path / "meter.sqlite3") as store:
        store.save_counter(DEV, 10)
        with pytest.raises(sqlite3.IntegrityError):
            store.save_counter(DEV, 9)
        assert store.load_counters()[DEV] == 10


def test_store_rejects_a_lowered_sequence(tmp_path):
    with Store(tmp_path / "meter.sqlite3") as store:
        store.save_sequence(5)
        with pytest.raises(ValueError):
            store.save_sequence(4)
        assert store.load_sequence() == 5


def test_event_log_is_append_only(tmp_path):
    with Store(tmp_path / "meter.sqlite3") as store:
        store.append_event(DEV, "work_unit", 1)
        store.append_event(DEV, "unknown", 1)
        assert store.event_count(DEV) == 2

        # No UPDATE or DELETE is exposed on the Store API.
        for name in ("update_event", "delete_event", "purge_events", "clear_events"):
            assert not hasattr(store, name), f"Store grew a {name}() method"

        # And the database refuses even a direct attempt.
        conn = sqlite3.connect(tmp_path / "meter.sqlite3")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE events SET event='nothing' WHERE id=1")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM events WHERE id=1")
        conn.close()

        assert store.event_count(DEV) == 2


def test_appended_events_keep_insertion_order(tmp_path):
    with Store(tmp_path / "meter.sqlite3") as store:
        for i in range(3):
            store.append_event(DEV, f"e{i}", sequence=i)
        rows = list(store.recent_events(limit=10))
        assert [r["event"] for r in rows] == ["e2", "e1", "e0"]
