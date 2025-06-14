"""gateway/reporter.py

Post signed usage reports with backoff.

Delivery is at-least-once and that is fine, because the counter in SQLite is the source of
truth and the report is a derived snapshot of it:
  - A failed post loses nothing. The count is already durable; the next window carries the
    same or a higher cumulative value.
  - A duplicate post double-counts nothing. Reports carry an absolute cumulative count, not
    a delta, so the backend takes the higher value and a replayed report is a no-op. The
    sequence number lets the backend reject a stale or rolled-back one outright.
Nothing in this module mutates the counter. Delivery state must never feed measurement.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass

import httpx

from .signer import ReportTuple, Signer

log = logging.getLogger(__name__)


@dataclass
class PostResult:
    delivered: bool
    status: int | None
    attempts: int


class Reporter:
    def __init__(
        self,
        endpoint: str,
        signer: Signer,
        base_delay: float = 5.0,
        max_delay: float = 600.0,
        max_attempts: int = 8,
        timeout: float = 10.0,
    ) -> None:
        self._endpoint = endpoint
        self._signer = signer
        self._base = base_delay
        self._max = max_delay
        self._attempts = max_attempts
        self._timeout = timeout

    def build_payload(self, r: ReportTuple) -> dict[str, object]:
        # JSON is transport only. The signature covers canonical_bytes(r), not this dict,
        # so key order and encoder quirks here cannot affect verification.
        sig = self._signer.sign(r)
        return {
            "device_id": r.device_id,
            "count": r.count,
            "sequence": r.sequence,
            "window_start": r.window_start,
            "window_end": r.window_end,
            "sig": base64.b64encode(sig).decode("ascii"),
        }

    async def post(self, r: ReportTuple) -> PostResult:
        payload = self.build_payload(r)
        delay = self._base

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for attempt in range(1, self._attempts + 1):
                try:
                    resp = await client.post(self._endpoint, json=payload)
                except httpx.HTTPError as exc:
                    log.warning("post attempt %d failed: %s", attempt, exc)
                else:
                    if 200 <= resp.status_code < 300:
                        return PostResult(True, resp.status_code, attempt)
                    if 400 <= resp.status_code < 500:
                        # Rejected on content. Resending identical bytes will not help.
                        # The count stays in SQLite; the operator investigates.
                        log.error(
                            "report rejected %d: %s", resp.status_code, resp.text[:200]
                        )
                        return PostResult(False, resp.status_code, attempt)
                    log.warning("server error %d, will retry", resp.status_code)

                if attempt < self._attempts:
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, self._max)

        # Give up for this window. Nothing lost: the next window re-sends the cumulative
        # count under a fresh sequence number.
        return PostResult(False, None, self._attempts)
