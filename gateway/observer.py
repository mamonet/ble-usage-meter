"""gateway/observer.py

Passive BLE observation on the Pi via BlueZ/bleak.

Scope: this observes a link between hardware the operator owns and their own phone app.
It reads and counts. It contains no write, no command construction and no pairing-bypass
path; the only bleak calls used are discovery and notification subscription on the
operator's own device. Nothing here originates traffic to an appliance.

Passive capture works when the link is unencrypted. When it is not, use proxy.py, which
is the same counting logic on a forwarding path.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice

from .matcher import GattWrite, Matcher

log = logging.getLogger(__name__)

WriteHandler = Callable[[GattWrite], Awaitable[None] | None]


class PassiveObserver:
    def __init__(
        self,
        matcher: Matcher,
        on_write: WriteHandler,
        address: str | None = None,
    ) -> None:
        self._matcher = matcher
        self._on_write = on_write
        self._address = address
        self._stop = asyncio.Event()

    async def discover(self, timeout: float = 10.0) -> list[BLEDevice]:
        """Passive scan. BlueZ sends no scan requests in passive mode."""
        devices = await BleakScanner.discover(timeout=timeout, scanning_mode="passive")
        for d in devices:
            log.debug("adv %s rssi=%s", d.address, getattr(d, "rssi", None))
        return list(devices)

    async def run(self) -> None:
        if self._address is None:
            raise ValueError("no target address, pass the operator's own device address")

        async with BleakClient(self._address) as client:
            log.info("attached to %s, observing", self._address)
            for service in client.services:
                for char in service.characteristics:
                    if "notify" not in char.properties and "indicate" not in char.properties:
                        continue
                    await client.start_notify(
                        char, self._make_handler(service.uuid, char.uuid)
                    )
            await self._stop.wait()

    def _make_handler(self, service_uuid: str, char_uuid: str):
        # bleak delivers one assembled value per notification, but a vendor app may still
        # split a logical command across several. Fragments are joined by length: a value
        # exactly at the negotiated MTU payload size is treated as continued.
        buf = bytearray()

        def handler(sender: BleakGATTCharacteristic, data: bytearray) -> None:
            nonlocal buf
            buf.extend(data)
            mtu_payload = getattr(sender, "max_write_without_response_size", 0) or 0
            if mtu_payload and len(data) == mtu_payload:
                return  # probably continued, wait for the tail before matching
            payload = bytes(buf)
            buf = bytearray()
            write = GattWrite(
                peer_addr=str(self._address),
                service=service_uuid,
                characteristic=char_uuid,
                payload=payload,
            )
            result = self._on_write(write)
            if asyncio.iscoroutine(result):
                asyncio.get_running_loop().create_task(result)

        return handler

    def stop(self) -> None:
        self._stop.set()
