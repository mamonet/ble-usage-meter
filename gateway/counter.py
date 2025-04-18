"""gateway/counter.py

Per-device monotonic usage counter plus a report sequence number. Mirrors
firmware/esp32/counter.cpp.

The count only ever goes up. A decrease is a bug, not a feature: the backend treats a
count below the last accepted one as a rollback and rejects the report, so a silent drop
here would break verification downstream. There is no decrement, reset or set API, and
restore() refuses to lower a live value.
"""

from __future__ import annotations


class Counter:
    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self._sequence: int = 0

    def restore(self, device_id: str, count: int) -> None:
        """Load a persisted value. A value below the live one is ignored, not applied."""
        if count < 0:
            raise ValueError("count cannot be negative")
        if count >= self._counts.get(device_id, 0):
            self._counts[device_id] = count

    def restore_sequence(self, sequence: int) -> None:
        if sequence > self._sequence:
            self._sequence = sequence

    def increment(self, device_id: str, n: int = 1) -> int:
        if n < 1:
            raise ValueError("increment must be positive")
        new = self._counts.get(device_id, 0) + n
        self._counts[device_id] = new
        return new

    def get(self, device_id: str) -> int:
        return self._counts.get(device_id, 0)

    def snapshot(self) -> dict[str, int]:
        return dict(self._counts)

    @property
    def sequence(self) -> int:
        return self._sequence

    def next_sequence(self) -> int:
        """Advance once per report batch. Never reused, so a replay is detectable."""
        self._sequence += 1
        return self._sequence
