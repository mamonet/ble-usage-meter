"""gateway/proxy.py

Transparent BLE proxy: peripheral facing the operator's phone app, central facing the
operator's own appliance. It exists because an encrypted link defeats passive capture, so
counting on hardware you own needs a position on the path rather than beside it.

What this module does and does not do, plainly:
  - It is used ONLY on hardware the operator owns. It is not a tool for interposing on
    someone else's device or link.
  - It forwards every byte UNCHANGED, in both directions, and counts the writes that match
    the operator's configured event rules. Forward first, count second.
  - It NEVER originates a command. It never injects, replays, drops, delays for effect,
    reorders, rewrites or synthesises traffic. There is no send-arbitrary-bytes entry
    point and no code path that constructs an ATT payload of its own. If a byte was not
    received from one side, it is never written to the other.
  - It uses no vendor credentials. Pairing, if any, is the operator's own between their
    own devices.
Any change that lets this file emit traffic the peer did not send breaks the scope of the
project and must be rejected in review.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from bleak import BleakClient

from .matcher import GattWrite, Matcher

log = logging.getLogger(__name__)

WriteHandler = Callable[[GattWrite], Awaitable[None] | None]


class TransparentProxy:
    """Relay between the app-facing peripheral and the operator's own appliance.

    The peripheral side is registered with BlueZ over D-Bus by the caller; this class
    owns the central side and the forward-then-count rule.
    """

    def __init__(
        self,
        appliance_address: str,
        matcher: Matcher,
        on_write: WriteHandler,
    ) -> None:
        self._address = appliance_address
        self._matcher = matcher
        self._on_write = on_write
        self._client: BleakClient | None = None
        self._stop = asyncio.Event()

    async def connect(self) -> None:
        self._client = BleakClient(self._address)
        await self._client.connect()
        log.info("proxy central attached to %s", self._address)

    async def forward_from_app(
        self,
        service_uuid: str,
        char_uuid: str,
        data: bytes,
        response: bool,
    ) -> None:
        """Relay one complete ATT value app -> appliance, verbatim, then count it.

        `data` is passed to the appliance exactly as received. There is no filtering,
        substitution or normalisation step, by design: the meter must not change what the
        operator's own app asked their own appliance to do.
        """
        if self._client is None:
            raise RuntimeError("proxy not connected")

        await self._client.write_gatt_char(char_uuid, data, response=response)

        # Counting happens after the forward and cannot affect it. A matcher error must
        # never turn into a dropped or altered command.
        try:
            write = GattWrite(
                peer_addr=self._address,
                service=service_uuid,
                characteristic=char_uuid,
                payload=bytes(data),
            )
            result = self._on_write(write)
            if asyncio.iscoroutine(result):
                await result
        except Exception:
            log.exception("metering failed for a forwarded write; traffic was unaffected")

    async def forward_from_appliance(self, char_uuid: str, data: bytes) -> bytes:
        """Relay one notification appliance -> app, verbatim. Observed, not counted."""
        log.debug("notify %s %d bytes", char_uuid, len(data))
        return bytes(data)

    async def run(self) -> None:
        await self.connect()
        try:
            await self._stop.wait()
        finally:
            if self._client is not None:
                await self._client.disconnect()

    def stop(self) -> None:
        self._stop.set()
