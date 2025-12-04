# docs/trust-model.md
<!-- final path: docs/trust-model.md -->

# Trust model

What the signature and the sequence number actually buy you, and what they do not. Read the
second list as carefully as the first; a metering system oversold is worse than one whose
limits are written down.

---

## The setting

The operator owns a fleet of appliances. Each has a meter (an ESP32 or a Pi) watching its
BLE link and counting units of work. The meter signs a periodic report and posts it to a
backend that the operator controls. The count may drive a bill or a quota.

The interesting adversary is therefore **the person holding the device**, not a remote
attacker. They have physical access, time, and a direct financial incentive to make the
number smaller.

---

## What the mechanisms guarantee

### The Ed25519 signature guarantees origin and integrity

A report that verifies against a device's registered public key was produced by something
holding that device's private key, and has not been altered by so much as a bit since.

The signature covers a **canonical byte serialisation**: a domain tag, a format version,
then the length-prefixed device id and four big-endian 64-bit integers (count, sequence,
window start, window end). Not a JSON object, not a struct. JSON encoders disagree on key
order, whitespace, and number formatting; struct layout is padding- and endianness-
dependent. Either would make verification depend on which implementation produced the
bytes. The serialisation is defined once and implemented identically in
`firmware/esp32/signer.cpp`, `gateway/signer.py`, and `backend/models.py`, and a test pins
the three together.

Concretely, the signature stops:

- editing the count in transit or in a proxy;
- forging a report for a device you do not have the key for;
- reusing a report signature on any other message the key might sign, because of the
  domain tag.

### The sequence number guarantees freshness

A signature says nothing about *when*. An old report stays perfectly valid forever, so a
signature-only backend can be fed one repeatedly and will keep accepting it.

The backend therefore stores a `last_accepted_sequence` per device and rejects any report
whose sequence is **at or below** it. Equality is a rejection, not an idempotent no-op:
resubmitting the identical signed report is precisely what a replay looks like.

### The count high-water mark guarantees no rollback

A device holds its own key, so it can *honestly* sign a report with a lower count after
resetting its counter or restoring an old backup. The signature would verify. So the
backend also stores `last_accepted_count` and rejects any report whose count falls below
it. The key proves origin, not truth, and this is where that distinction is enforced.

### Append-only storage guarantees the history stands

`usage_reports` has no UPDATE or DELETE path in the backend, and SQLite triggers abort
either operation. The gateway's event log is the same. An accepted report is evidence;
corrections are appended, never edited.

### Deny-by-default guarantees a failure is not a free grant

`backend/policy.py` returns deny for a missing policy, an unparseable date, a quota with no
period, or an unreadable usage total. A corrupt row therefore blocks rather than silently
authorising unlimited use.

---

## What they do not guarantee

**They do not prove that a counted event was real.** The meter counts GATT writes that
match a configured signature. If the vendor app sends that write for something other than
work, the meter counts it. Signature and sequence protect the number's integrity in
transit and over time; they say nothing about whether the number was right when it was
made. Validate the mapping by counting cycles by hand, and re-validate after app updates.

**They do not prove that unreported work did not happen.** The meter only counts what it
observes. Powering it down, unplugging it, jamming it, or moving the appliance out of range
produces *no* reports, not wrong ones. Detecting that is an availability problem, not a
cryptographic one: alert on a gateway that stops reporting, and treat a silent meter as
suspicious rather than as zero usage.

**They do not protect the key from the device holder.** The private key lives on hardware
the counterparty physically controls. A determined holder can extract it from flash. See
below for what that costs and how to limit it.

**They do not make counts confidential.** Reports are signed, not encrypted. Use HTTPS or
the usage figures are readable by anyone on the path.

**They do not prove the report window is honest.** Timestamps come from the gateway's
clock. A device with a skewed or manipulated clock can misattribute work between periods.
The count itself stays monotonic and cannot shrink, so this shifts usage between billing
periods rather than erasing it. Compare `received_at` against the claimed window if this
matters to you.

---

## Threat model

### 1. A device holder who wants a lower bill

*Their capabilities:* physical access, unlimited time, an incentive.

| Attempt | Result | Why |
|---|---|---|
| Edit the count in the report body | Rejected, `bad_signature` | Any edit breaks the signature |
| Resubmit an old signed report | Rejected, `replay_or_rollback_sequence` | Sequence at or below the mark |
| Reset the meter and sign a low count | Rejected, `count_rollback` | Count below the stored mark |
| Delete stored reports at the backend | Blocked | Append-only triggers |
| Unplug the meter | **Succeeds at suppressing counts** | Detected only as silence |
| Move the appliance out of range | **Succeeds at suppressing counts** | Same |
| Extract the private key from flash | **Succeeds**, see case 4 | Physical access wins eventually |

The pattern: **tampering with numbers fails, denial of observation works.** Design your
operations around that. The gap is monitored, not cryptographic. Alert on a gateway whose
reports stop, and make an absent report a contractual problem rather than a free period.

### 2. A replayed report

*Capability:* an eavesdropper on the network path, or the holder resubmitting their own
traffic.

*Cost if it worked:* usage frozen at whatever the replayed report said. The most attractive
attack available, since it needs no key and no reverse engineering.

*Defence:* the sequence high-water mark, plus `UNIQUE(device_id, sequence)` as a second
layer. Rejected with `replay_or_rollback_sequence` and covered by `tests/test_replay.py`.

*Residual:* a replay across a **re-registration** would work if you deleted and recreated a
device, resetting its marks to -1/0. Rotate keys in place instead; `POST /devices` refuses
to re-register an existing id for exactly this reason.

### 3. A rolled-back counter

*Capability:* the device holder, using the device's own legitimate key.

*Cost if it worked:* arbitrary reduction of the bill while every report verifies. This is
the attack a naive "just check the signature" backend is wide open to, and it is why
`backend/verify.py` has two checks and not one.

*Defence:* count monotonicity in three places. The gateway `Counter` exposes no decrement
or reset. A SQLite trigger on the gateway aborts any write lowering a stored count. The
backend rejects any report whose count is below `last_accepted_count`.

*Residual:* a rollback **between** two reports is invisible if the count recovers past the
old high-water mark before the next report. Work done in that gap is lost. Shorter report
intervals shrink the window.

### 4. A stolen gateway key

*Capability:* anyone who extracts the key from flash, or finds one committed to a repo.

*Cost:* total, for that one device. The holder can sign any count they like. Every backend
check still passes because the reports are genuinely authentic. Monotonicity still applies,
so they cannot go *backwards*, but they can simply stop counting real work and report a
flat or slowly rising number.

*What limits the damage:*

- **One key per device.** A compromise is contained to that device's billing.
- **The key is never in the repo.** `tools/keygen.py` refuses to write inside a git working
  tree without `--force`; `.gitignore` catches `*.pem` and `*.key` as a backstop. A key in
  git history is compromised permanently, and rewriting history does not un-leak it.
- **Reports are only ever compared against the *registered* public key.** Re-registration
  of an existing device id is refused, so an attacker with API access cannot simply swap in
  their own public key.
- **Rotation is cheap.** Generate a new key, re-register, keep the old reports. See
  `docs/deployment.md`.

*What does not help:* nothing cryptographic detects a stolen key being used correctly. The
signal is behavioural, a device whose reported rate diverges from its expected duty cycle.
Compare across the fleet.

### 5. A malicious or compromised backend operator

Out of scope by construction: the backend belongs to the operator, who is the party the
meter reports *to*. Nothing here protects a device holder from the operator's own records.
If both sides need to trust the same number, the reports would have to be countersigned or
anchored somewhere neither side controls, which this system does not do.

### 6. A network attacker

*Capability:* intercept and modify traffic between gateway and backend.

They cannot forge or alter a report. They can drop reports (denial of observation again),
delay them, or read the usage figures if you deployed over plain HTTP. Use TLS. Dropped
reports are recoverable because the gateway retries and the counter, not the report, is the
source of truth.

---

## Summary

| Property | Guaranteed? | By what |
|---|---|---|
| Report authorship | Yes | Ed25519 over canonical bytes |
| Report integrity | Yes | Same |
| Not a replay | Yes | Sequence high-water mark |
| Count never decreases | Yes | Count high-water mark + gateway triggers |
| History not rewritten | Yes | Append-only tables and triggers |
| Failure does not grant access | Yes | Deny-by-default policy |
| Counted event was real work | **No** | Depends on your event mapping |
| All real work was counted | **No** | A powered-off meter reports nothing |
| Key safe from the holder | **No** | Physical access; rotate and monitor |
| Usage figures confidential | **No** | Signed, not encrypted; use TLS |
| Report window honest | **Partly** | Gateway clock; count stays monotonic |
