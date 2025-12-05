# docs/deployment.md
<!-- final path: docs/deployment.md -->

# Deployment

Running the backend, registering devices, rotating keys, and replacing a gateway.

Scope: this meters hardware the operator owns. The backend accepts signed counts from your
own gateways and answers a licence question about them.

---

## Running the backend

### Development

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app:app --reload --port 8000
```

The SQLite file is created and migrated on first request. Override the path with
`METER_DB`:

```
METER_DB=/var/lib/ble-meter/backend.db uvicorn backend.app:app --port 8000
```

Check it:

```
curl http://localhost:8000/health
```

### Production

Run behind a reverse proxy that terminates TLS. Reports are **signed, not encrypted**: over
plain HTTP nobody can forge a count, but anyone on the path can read your usage figures.

```
uvicorn backend.app:app --host 127.0.0.1 --port 8000 --workers 4
```

A systemd unit:

```ini
[Unit]
Description=ble-usage-meter backend
After=network.target

[Service]
User=ble-meter
Group=ble-meter
WorkingDirectory=/opt/ble-usage-meter
Environment=METER_DB=/var/lib/ble-meter/backend.db
ExecStart=/opt/ble-usage-meter/.venv/bin/uvicorn backend.app:app \
          --host 127.0.0.1 --port 8000 --workers 4
Restart=on-failure

# The DB is the billing record. Nothing else needs write access.
ProtectSystem=strict
ReadWritePaths=/var/lib/ble-meter
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Note on workers: the backend uses SQLite with WAL and one connection per request, which is
fine for the write rate a meter fleet produces (one report per device per interval). If you
outgrow it, the schema ports to Postgres with only `backend/db.py` changing.

### Backups

`usage_reports` is append-only and is your billing evidence. Back it up like an accounting
record, not like a cache:

```
sqlite3 /var/lib/ble-meter/backend.db ".backup '/backups/meter-$(date +%F).db'"
```

Use `.backup`, not a file copy: a copy taken mid-write against a WAL database can be
inconsistent. Keep backups off the machine, and test a restore before you need one.

**Restoring an old backup rolls the high-water marks backwards**, which re-opens the replay
window for every sequence between the backup and now. If you ever restore, treat the gap as
suspect and reconcile against the gateways' own logs.

---

## Registering a device

Registration is deliberate and out of band. A gateway cannot register itself.

**1. Generate the key on the gateway**, not on your laptop. The private key should never
travel.

```
python tools/keygen.py --out /etc/ble-meter/gateway.key
```

The tool writes the PEM at mode 0600, refuses to overwrite an existing file, and refuses to
write inside a git working tree without `--force`. It prints the public key.

**2. Register the public key with the backend.**

```
curl -X POST "$BACKEND/devices" \
  -H "Content-Type: application/json" \
  -d '{"device_id": "<device-id>", "public_key": "<base64 from keygen>", "label": "<optional>"}'
```

The `device_id` must match `meter_id` in the gateway's `gateway.yaml`. A mismatch produces
`unknown_device` on every report, which is the most common bring-up failure.

**3. Set a policy** if you are enforcing quotas. There is no policy endpoint; policies are
operator data, set directly:

```
sqlite3 /var/lib/ble-meter/backend.db \
  "INSERT INTO policies (device_id, active, quota_units, period_days, expires_on)
   VALUES ('<device-id>', 1, 1000, 30, '2027-01-01');"
```

Fields: `active` gates everything; `quota_units` with `period_days` gives N units per
rolling period; `expires_on` is a hard stop. A `quota_units` with no `period_days` is
**unevaluable and denies**, deliberately. With no policy row at all the device still reports
usage normally, but `/devices/{id}/license` denies.

**4. Verify end to end.** Start the gateway, drive one cycle, and check:

```
curl "$BACKEND/devices/<device-id>/usage"
curl "$BACKEND/devices/<device-id>/license"
```

---

## Registration is not re-keyable

`POST /devices` **refuses an existing device id**. This is intentional: if re-registration
silently replaced the public key, anyone who reached the API could point a device at their
own key and sign any count they liked. Changing a key is the rotation procedure below.

---

## Key rotation

Rotate when a key may have been exposed, when a gateway changes hands, and on whatever
schedule your policy sets.

The constraint that shapes the procedure: **the device's high-water marks must not go
backwards**. They are what stops replay and rollback, and resetting them re-opens the
window for every report ever issued for that device.

### Rotating in place (preferred)

Keeps the id, the history, and the marks.

1. **Generate the new key on the gateway**, to a new path.

   ```
   python tools/keygen.py --out /etc/ble-meter/gateway.key.new
   ```

2. **Stop the gateway.** Its counter and sequence are persisted in SQLite, so nothing is
   lost. Note the last sequence it reported:

   ```
   curl "$BACKEND/devices/<device-id>/usage"
   ```

3. **Swap the registered public key.** There is no endpoint for this by design; it is a
   deliberate operator action:

   ```
   sqlite3 /var/lib/ble-meter/backend.db \
     "UPDATE devices SET public_key = '<new base64 public key>'
      WHERE device_id = '<device-id>';"
   ```

   Note what this does **not** touch: `last_accepted_sequence` and `last_accepted_count`
   stay exactly where they were. The new key picks up the sequence where the old one left
   off, so no historical report can be replayed against the new key either.

4. **Install the new key on the gateway** and restart.

   ```
   mv /etc/ble-meter/gateway.key.new /etc/ble-meter/gateway.key
   systemctl restart ble-meter-gateway
   ```

5. **Verify** the next report is accepted, then destroy the old key:

   ```
   shred -u /etc/ble-meter/gateway.key.old
   ```

There is a short window between steps 3 and 4 where the gateway signs with the old key and
the backend expects the new one. Reports in that window are rejected with `bad_signature`;
the gateway retries and the counter is unaffected, so nothing is lost. Keep the window
short anyway.

### If a key was actually compromised

Rotate as above, then treat the reports since the suspected compromise as unverified.
Cryptography cannot tell you which of them were genuine, because a stolen key produces
authentic signatures. Reconcile against the gateway's own append-only event log and against
whatever independent record of the work exists.

### What never to do

- **Do not delete and recreate the device** to change its key. That resets the marks to
  -1/0 and makes every historical report replayable.
- **Do not reuse a key across devices.** One compromise would then be a fleet compromise.
- **Do not commit a key.** A key in git history is compromised permanently; rewriting
  history does not un-leak it. Rotate instead.

---

## Replacing a gateway

The failure mode to avoid: the new gateway starts its counter at zero, reports a count
below the stored high-water mark, and every report is rejected as `count_rollback`. That
rejection is correct, and working around it by resetting the backend would defeat the
protection.

### The gateway hardware failed but the storage survived

Easiest case. Move the SQLite file (`db_path`) and the key to the new unit, keep the same
`meter_id`, and start it. The counter and sequence resume from the persisted values and the
backend sees an uninterrupted series.

### The storage is gone

The new gateway must not restart from zero. Seed it from the backend's own record, which is
the authoritative high-water mark:

1. Read where the device stands:

   ```
   curl "$BACKEND/devices/<device-id>/usage"
   # -> total_count, last_accepted_sequence
   ```

2. Register the new gateway's key (rotation procedure above; keep the device id).

3. Seed the new gateway's store so it continues rather than restarts:

   ```
   sqlite3 /var/lib/ble-meter/meter.sqlite3 \
     "INSERT INTO counters(device_id, count, updated_at)
      VALUES ('<device-id>', <total_count>, strftime('%s','now'));
      INSERT INTO meta(key, value) VALUES ('sequence', '<last_accepted_sequence>')
      ON CONFLICT(key) DO UPDATE SET value=excluded.value;"
   ```

4. Start the gateway. Its first report carries `sequence = last_accepted_sequence + 1` and a
   count at or above the stored one, so it is accepted normally.

Work performed while the gateway was down was never observed and is not recoverable. Record
the outage; a silent meter is not zero usage, and `docs/trust-model.md` covers why that gap
is an operational problem rather than a cryptographic one.

### Retiring a device

Set `active = 0` in `policies` so the licence check denies. Leave the `devices` row and its
reports in place: they are the billing record, and deleting the row would let its history be
replayed if the id were ever reused.

```
sqlite3 /var/lib/ble-meter/backend.db \
  "UPDATE policies SET active = 0 WHERE device_id = '<device-id>';"
```

Do not reuse a retired device id for new hardware.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `unknown_device` (404) | `meter_id` does not match the registered `device_id` | Align them; ids are case-sensitive |
| `bad_signature` (401) | Wrong key installed, or mid-rotation | Confirm the registered public key matches the gateway's |
| `bad_signature` on every report after an upgrade | Canonical serialisation changed on one side | Gateway, firmware and backend must agree; the format version must match |
| `replay_or_rollback_sequence` (409) | Gateway lost its sequence and restarted low | Seed the sequence from the backend, above |
| `count_rollback` (409) | Gateway lost its counter and restarted at zero | Seed the counter from the backend, above |
| Licence denies with `policy_unevaluable` | Quota with no period, or a malformed expiry date | Fix the policy row; deny-by-default is working as designed |
| Licence denies with `no_policy_on_record` | No policy row exists | Insert one, or ignore if you are not enforcing quotas |
| Reports stop arriving | Meter down, out of range, or network | Investigate; do not treat silence as zero usage |
