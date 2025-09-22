# tests/test_matcher.py
# Matching must be exact. A near-miss that quietly counts is a billing error.

import pytest

from gateway.config import EventRule
from gateway.matcher import UNKNOWN, GattWrite, Matcher

SVC = "0000fff0-0000-1000-8000-00805f9b34fb"
CHR = "0000fff1-0000-1000-8000-00805f9b34fb"
OTHER_CHR = "0000fff2-0000-1000-8000-00805f9b34fb"


@pytest.fixture
def matcher() -> Matcher:
    return Matcher([EventRule(SVC, CHR, bytes.fromhex("a001"), "work_unit")])


def write(payload: bytes, characteristic: str = CHR) -> GattWrite:
    return GattWrite(peer_addr="AA:BB:CC:DD:EE:FF", service=SVC,
                     characteristic=characteristic, payload=payload)


def test_exact_prefix_matches(matcher):
    assert matcher.match(write(bytes.fromhex("a001"))) == "work_unit"


def test_prefix_matches_with_trailing_payload(matcher):
    # The prefix is a prefix, not the whole value: real commands carry arguments after it.
    assert matcher.match(write(bytes.fromhex("a001deadbeef"))) == "work_unit"


def test_uuid_case_is_normalised(matcher):
    w = GattWrite("AA:BB:CC:DD:EE:FF", SVC.upper(), CHR.upper(), bytes.fromhex("a001"))
    assert matcher.match(w) == "work_unit"


@pytest.mark.parametrize(
    "payload_hex",
    [
        "a002",      # last byte differs
        "a101",      # first byte differs
        "a0",        # truncated: shorter than the prefix, must not match
        "00a001",    # prefix present but not at offset 0
        "",          # empty payload
    ],
)
def test_near_miss_does_not_match(matcher, payload_hex):
    assert matcher.match(write(bytes.fromhex(payload_hex))) is None


def test_right_prefix_on_wrong_characteristic_does_not_match(matcher):
    assert matcher.match(write(bytes.fromhex("a001"), characteristic=OTHER_CHR)) is None


def test_unmatched_write_classifies_as_unknown(matcher):
    # An unrecognised write is recorded, not guessed into a count.
    assert matcher.classify(write(bytes.fromhex("ffff"))) == UNKNOWN


def test_unknown_write_does_not_increment_counter(matcher):
    from gateway.counter import Counter

    counter = Counter()
    device = "dev-1"
    for payload in ["ffff", "a002", "a0"]:
        event = matcher.match(write(bytes.fromhex(payload)))
        if event == "work_unit":
            counter.increment(device)

    assert counter.get(device) == 0

    # A genuine match does increment, so the test above is not passing vacuously.
    if matcher.match(write(bytes.fromhex("a001"))) == "work_unit":
        counter.increment(device)
    assert counter.get(device) == 1


def test_empty_prefix_matches_any_payload():
    m = Matcher([EventRule(SVC, CHR, b"", "session_start")])
    assert m.match(write(b"")) == "session_start"
    assert m.match(write(bytes.fromhex("deadbeef"))) == "session_start"


def test_payload_compared_as_bytes_not_text():
    # "a001" as ASCII text is not the same as the two bytes 0xa0 0x01.
    m = Matcher([EventRule(SVC, CHR, bytes.fromhex("a001"), "work_unit")])
    assert m.match(write(b"a001")) is None
