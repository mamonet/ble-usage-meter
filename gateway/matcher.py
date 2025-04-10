"""gateway/matcher.py

Map an observed GATT write to a named event. Same semantics as
firmware/esp32/event_matcher.cpp, deliberately: both sides must agree on what counts, or
a gateway report and a firmware report for the same activity would disagree.

Rules, identical to the firmware:
  - UUIDs compared in normalised lowercase full-128-bit form.
  - Payload prefix compared as exact bytes, not as text. Payloads are binary.
  - An empty prefix matches any payload on that characteristic.
  - First matching rule wins; config rejects duplicate triples so order cannot matter.
  - An unmatched write returns None and is recorded as unknown. It is never guessed into
    a count.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import EventRule

UNKNOWN = "unknown"


@dataclass(frozen=True)
class GattWrite:
    """One complete, reassembled ATT value. Not a fragment."""

    peer_addr: str
    service: str
    characteristic: str
    payload: bytes


class Matcher:
    def __init__(self, rules: list[EventRule]) -> None:
        # Index by (service, characteristic) so a busy link does not scan every rule.
        self._by_char: dict[tuple[str, str], list[EventRule]] = {}
        for r in rules:
            self._by_char.setdefault((r.service.lower(), r.characteristic.lower()), []).append(r)

    @property
    def rule_count(self) -> int:
        return sum(len(v) for v in self._by_char.values())

    def match(self, write: GattWrite) -> str | None:
        """Return the event name, or None when the write is not recognised."""
        candidates = self._by_char.get(
            (write.service.lower(), write.characteristic.lower())
        )
        if not candidates:
            return None

        payload = write.payload
        for rule in candidates:
            if not rule.prefix:
                return rule.event
            # Exact byte compare over the leading len(prefix) bytes.
            if len(payload) >= len(rule.prefix) and payload[: len(rule.prefix)] == rule.prefix:
                return rule.event
        return None

    def classify(self, write: GattWrite) -> str:
        """Event name, or the literal 'unknown' for the append-only log."""
        return self.match(write) or UNKNOWN
