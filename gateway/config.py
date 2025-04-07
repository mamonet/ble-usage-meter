"""gateway/config.py

Load and validate gateway.yaml and events.yaml.

Scope: configuration for a meter that observes and counts activity on hardware the
operator owns. Nothing here configures sending anything to an appliance. All UUIDs and
key paths shipped in examples are placeholders.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

UUID_LEN = 36
_HEX = set("0123456789abcdef")


class ConfigError(ValueError):
    """Raised on any malformed or missing configuration value."""


def _normalise_uuid(raw: str) -> str:
    """Expand a 16-bit UUID to full form and lowercase it, so comparison is unambiguous."""
    s = str(raw).strip().lower()
    if len(s) == 4 and all(c in _HEX for c in s):
        return f"0000{s}-0000-1000-8000-00805f9b34fb"
    if len(s) == 8 and all(c in _HEX for c in s):
        return f"{s}-0000-1000-8000-00805f9b34fb"
    if len(s) != UUID_LEN or s.count("-") != 4:
        raise ConfigError(f"not a UUID: {raw!r}")
    if not all(c in _HEX or c == "-" for c in s):
        raise ConfigError(f"not a UUID: {raw!r}")
    return s


def _parse_prefix(raw: object) -> bytes:
    """Payload prefix as hex, e.g. 'aa01'. Empty or absent means match any payload."""
    if raw is None or raw == "":
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    s = str(raw).replace(" ", "").replace(":", "").lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 or not all(c in _HEX for c in s):
        raise ConfigError(f"prefix is not even-length hex: {raw!r}")
    return bytes.fromhex(s)


@dataclass(frozen=True)
class EventRule:
    service: str
    characteristic: str
    prefix: bytes
    event: str


@dataclass
class GatewayConfig:
    meter_id: str
    report_endpoint: str
    report_interval_sec: int
    db_path: Path
    private_key_path: Path
    retry_base_sec: int = 5
    retry_max_sec: int = 600
    retry_max_attempts: int = 8
    rules: list[EventRule] = field(default_factory=list)


def load_events(path: str | Path) -> list[EventRule]:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw_rules = doc.get("events")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ConfigError("events.yaml must contain a non-empty 'events' list")

    rules: list[EventRule] = []
    seen: set[tuple[str, str, bytes]] = set()
    for i, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            raise ConfigError(f"events[{i}] is not a mapping")
        try:
            service = _normalise_uuid(item["service"])
            characteristic = _normalise_uuid(item["characteristic"])
            name = str(item["event"]).strip()
        except KeyError as exc:
            raise ConfigError(f"events[{i}] missing {exc.args[0]}") from exc
        if not name:
            raise ConfigError(f"events[{i}] has an empty event name")
        prefix = _parse_prefix(item.get("prefix"))

        key = (service, characteristic, prefix)
        if key in seen:
            # Two rules on the same triple would make the count depend on list order.
            raise ConfigError(f"events[{i}] duplicates an earlier rule")
        seen.add(key)
        rules.append(EventRule(service, characteristic, prefix, name))
    return rules


def load_gateway(path: str | Path, events_path: str | Path | None = None) -> GatewayConfig:
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}

    def req(key: str) -> object:
        if key not in doc:
            raise ConfigError(f"gateway.yaml missing required key {key!r}")
        return doc[key]

    interval = int(doc.get("report_interval_sec", 300))
    if interval < 10:
        raise ConfigError("report_interval_sec must be >= 10")

    key_path = Path(str(req("private_key_path"))).expanduser()
    endpoint = str(req("report_endpoint"))
    if not endpoint.startswith(("http://", "https://")):
        raise ConfigError("report_endpoint must be an http(s) URL")

    events_file = events_path or doc.get("events_file")
    if events_file is None:
        raise ConfigError("no events file given, set events_file or pass one")

    return GatewayConfig(
        meter_id=str(req("meter_id")),
        report_endpoint=endpoint,
        report_interval_sec=interval,
        db_path=Path(str(doc.get("db_path", "meter.sqlite3"))).expanduser(),
        private_key_path=key_path,
        retry_base_sec=int(doc.get("retry_base_sec", 5)),
        retry_max_sec=int(doc.get("retry_max_sec", 600)),
        retry_max_attempts=int(doc.get("retry_max_attempts", 8)),
        rules=load_events(events_file),
    )
