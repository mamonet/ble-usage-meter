"""gateway/cli.py

Command line entry point for the Pi gateway.

Scope: ble-usage-meter is an independent usage meter for BLE hardware the operator owns.
It observes the operator's own link, counts the writes matching event rules the operator
supplies, and posts a signed cumulative report. It is read-only with respect to device
behaviour: no subcommand here sends, injects, replays or forges a command to an appliance,
and none uses vendor credentials. The proxy subcommand forwards traffic unchanged on
hardware the operator owns; it does not originate traffic.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time

from .config import ConfigError, GatewayConfig, load_gateway
from .counter import Counter
from .matcher import UNKNOWN, GattWrite, Matcher
from .observer import PassiveObserver
from .proxy import TransparentProxy
from .reporter import Reporter
from .signer import ReportTuple, Signer
from .store import Store

SCOPE_NOTE = __doc__.split("Scope:", 1)[1].strip()

log = logging.getLogger("ble-usage-meter")


class Pipeline:
    """Shared match -> log -> count -> persist path for observe and proxy."""

    def __init__(self, cfg: GatewayConfig, store: Store, counter: Counter) -> None:
        self.matcher = Matcher(cfg.rules)
        self.store = store
        self.counter = counter

    def handle(self, write: GattWrite) -> None:
        event = self.matcher.classify(write)
        self.store.append_event(
            device_id=write.peer_addr,
            event=event,
            sequence=self.counter.sequence,
            service=write.service,
            characteristic=write.characteristic,
            payload_head=write.payload[:16],
        )
        if event == UNKNOWN:
            # Logged for the operator to inspect. Not counted, never guessed.
            log.info("unknown write on %s, %d bytes", write.characteristic, len(write.payload))
            return
        count = self.counter.increment(write.peer_addr)
        self.store.save_counter(write.peer_addr, count)
        log.info("%s %s -> %d", write.peer_addr, event, count)


def _load(args: argparse.Namespace) -> tuple[GatewayConfig, Store, Counter]:
    cfg = load_gateway(args.config, args.events)
    store = Store(cfg.db_path)
    counter = Counter()
    for dev, n in store.load_counters().items():
        counter.restore(dev, n)
    counter.restore_sequence(store.load_sequence())
    return cfg, store, counter


def cmd_observe(args: argparse.Namespace) -> int:
    cfg, store, counter = _load(args)
    pipeline = Pipeline(cfg, store, counter)
    obs = PassiveObserver(pipeline.matcher, pipeline.handle, address=args.address)
    log.info("observing %s with %d rules", args.address, pipeline.matcher.rule_count)
    try:
        asyncio.run(obs.run())
    except KeyboardInterrupt:
        obs.stop()
    finally:
        store.close()
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    cfg, store, counter = _load(args)
    pipeline = Pipeline(cfg, store, counter)
    proxy = TransparentProxy(args.address, pipeline.matcher, pipeline.handle)
    log.info("proxying %s, traffic forwarded unchanged", args.address)
    try:
        asyncio.run(proxy.run())
    except KeyboardInterrupt:
        proxy.stop()
    finally:
        store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    cfg, store, counter = _load(args)
    try:
        signer = Signer.from_file(cfg.private_key_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"cannot sign: {exc}", file=sys.stderr)
        store.close()
        return 2

    reporter = Reporter(
        cfg.report_endpoint,
        signer,
        base_delay=cfg.retry_base_sec,
        max_delay=cfg.retry_max_sec,
        max_attempts=cfg.retry_max_attempts,
    )
    seq = counter.next_sequence()
    store.save_sequence(seq)
    now = int(time.time())
    window_start = now - cfg.report_interval_sec

    async def run_all() -> int:
        failures = 0
        for device_id, count in counter.snapshot().items():
            r = ReportTuple(device_id, count, seq, window_start, now)
            res = await reporter.post(r)
            status = "ok" if res.delivered else "undelivered"
            print(f"{device_id} count={count} seq={seq} {status} ({res.attempts} attempts)")
            if not res.delivered:
                # Nothing to unwind; the count is already durable in SQLite.
                failures += 1
        return failures

    failures = asyncio.run(run_all())
    store.close()
    return 1 if failures else 0


def cmd_status(args: argparse.Namespace) -> int:
    cfg, store, counter = _load(args)
    print(f"meter_id      {cfg.meter_id}")
    print(f"db            {cfg.db_path}")
    print(f"rules         {len(cfg.rules)}")
    print(f"sequence      {counter.sequence}")
    print(f"events logged {store.event_count()}")
    print("counters:")
    snap = counter.snapshot()
    if not snap:
        print("  (none yet)")
    for dev, n in sorted(snap.items()):
        print(f"  {dev}  {n}")
    if args.events_tail:
        print("recent events:")
        for row in store.recent_events(args.events_tail):
            print(f"  {row['ts']:.0f}  {row['device_id']}  {row['event']}")
    store.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ble-usage-meter",
        description=SCOPE_NOTE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use only on hardware you own. This tool counts; it never commands.",
    )
    p.add_argument("-c", "--config", default="config/gateway.yaml")
    p.add_argument("-e", "--events", default=None, help="override events file")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    o = sub.add_parser("observe", help="passively watch an unencrypted link and count")
    o.add_argument("address", help="BLE address of your own device")
    o.set_defaults(func=cmd_observe)

    x = sub.add_parser(
        "proxy", help="forward traffic unchanged on your own hardware and count"
    )
    x.add_argument("address", help="BLE address of your own appliance")
    x.set_defaults(func=cmd_proxy)

    r = sub.add_parser("report", help="sign and post the current cumulative counts")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("status", help="show counters, sequence and log size")
    s.add_argument("--events-tail", type=int, default=0)
    s.set_defaults(func=cmd_status)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
