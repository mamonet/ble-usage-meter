#!/usr/bin/env python3
# tools/parse_snoop.py
"""List candidate GATT writes in an Android HCI snoop log.

This reads a capture FILE that the operator took from their OWN phone, using the developer
option "Enable Bluetooth HCI snoop log". It opens no sockets, scans for no devices, and
connects to nothing. There is no code path in this tool that talks to a device.

Purpose: after driving a few real work cycles on hardware you own, one write tends to repeat
once per cycle. Grouping writes by (handle, uuid, payload prefix) and sorting by count makes
that one stand out, so you can put it in config/events.yaml as your event signature.

Usage:
    python tools/parse_snoop.py btsnoop_hci.log
    python tools/parse_snoop.py btsnoop_hci.log --prefix-len 3 --min-count 2
"""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# btsnoop file header: 8-byte magic, 4-byte version, 4-byte datalink.
BTSNOOP_MAGIC = b"btsnoop\x00"
RECORD_HEADER = struct.Struct(">IIIIq")  # orig_len, incl_len, flags, drops, ts

# HCI packet types (first byte of an H4-framed record).
H4_ACL = 0x02

# ATT opcodes that carry a client-initiated write.
ATT_WRITE_REQ = 0x12
ATT_WRITE_CMD = 0x52
ATT_PREPARE_WRITE_REQ = 0x16
ATT_SIGNED_WRITE_CMD = 0xD2
WRITE_OPCODES = {
    ATT_WRITE_REQ: "write_req",
    ATT_WRITE_CMD: "write_cmd",
    ATT_PREPARE_WRITE_REQ: "prepare_write_req",
    ATT_SIGNED_WRITE_CMD: "signed_write_cmd",
}

ATT_CID = 0x0004


@dataclass(frozen=True)
class GattWrite:
    opcode_name: str
    handle: int
    payload: bytes


def iter_records(data: bytes):
    """Yield (flags, packet_bytes) from a btsnoop file."""
    if not data.startswith(BTSNOOP_MAGIC):
        raise ValueError("not a btsnoop file (bad magic)")
    off = 16
    n = len(data)
    while off + RECORD_HEADER.size <= n:
        orig_len, incl_len, flags, _drops, _ts = RECORD_HEADER.unpack_from(data, off)
        off += RECORD_HEADER.size
        if incl_len < 0 or off + incl_len > n:
            break
        yield flags, data[off : off + incl_len]
        off += incl_len


def parse_acl_att(pkt: bytes) -> GattWrite | None:
    """Pull an ATT write out of one H4 ACL record.

    Only complete first fragments (PB=0b10) are handled. A continuation fragment has no
    L2CAP header, and stitching them needs connection state this tool deliberately avoids.
    Fragmented writes are simply skipped rather than half-parsed into a wrong prefix.
    """
    if len(pkt) < 9 or pkt[0] != H4_ACL:
        return None

    handle_flags = int.from_bytes(pkt[1:3], "little")
    pb = (handle_flags >> 12) & 0x03
    if pb != 0x02:  # not a first, non-flushable fragment
        return None

    acl_len = int.from_bytes(pkt[3:5], "little")
    body = pkt[5 : 5 + acl_len]
    if len(body) < 4:
        return None

    l2cap_len = int.from_bytes(body[0:2], "little")
    cid = int.from_bytes(body[2:4], "little")
    if cid != ATT_CID:
        return None

    att = body[4 : 4 + l2cap_len]
    if len(att) < 3:
        return None

    opcode = att[0]
    name = WRITE_OPCODES.get(opcode)
    if name is None:
        return None

    handle = int.from_bytes(att[1:3], "little")
    payload = att[3:]
    if opcode == ATT_PREPARE_WRITE_REQ and len(payload) >= 2:
        payload = payload[2:]  # strip the value offset
    return GattWrite(name, handle, payload)


def collect(path: Path, prefix_len: int) -> Counter:
    data = path.read_bytes()
    groups: Counter = Counter()
    for _flags, pkt in iter_records(data):
        w = parse_acl_att(pkt)
        if w is None:
            continue
        # UUID is not in the ATT write itself, only the handle. Resolving handle -> UUID
        # needs the discovery exchange from the same capture; where that is absent the
        # handle is reported alone and you resolve it in Wireshark.
        key = (w.opcode_name, w.handle, w.payload[:prefix_len].hex())
        groups[key] += 1
    return groups


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("logfile", type=Path, help="btsnoop_hci.log captured from your own phone")
    ap.add_argument("--prefix-len", type=int, default=2,
                    help="bytes of payload to group on (default 2)")
    ap.add_argument("--min-count", type=int, default=1,
                    help="hide groups seen fewer than this many times")
    ap.add_argument("--top", type=int, default=40, help="max rows to print")
    args = ap.parse_args(argv)

    if not args.logfile.is_file():
        print(f"no such file: {args.logfile}", file=sys.stderr)
        return 2

    try:
        groups = collect(args.logfile, args.prefix_len)
    except ValueError as exc:
        print(f"cannot parse: {exc}", file=sys.stderr)
        return 2

    rows = [(c, k) for k, c in groups.items() if c >= args.min_count]
    rows.sort(reverse=True)
    if not rows:
        print("no ATT writes found. Check the log covers the period you drove the device.")
        return 0

    print(f"{'count':>6}  {'opcode':<18} {'handle':<8} prefix")
    for count, (opname, handle, prefix) in rows[: args.top]:
        print(f"{count:>6}  {opname:<18} 0x{handle:04x}   {prefix or '(empty)'}")

    print()
    print("The write that tracks your action should appear once per cycle you drove.")
    print("Resolve the handle to a characteristic UUID in Wireshark, then put the")
    print("service UUID, characteristic UUID and prefix into config/events.yaml.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
