# docs/protocol-discovery.md
<!-- final path: docs/protocol-discovery.md -->

# Finding the event signature

## Scope

**This procedure applies to hardware you own.** It is interoperability work: you are
identifying which command your own appliance receives when it performs one unit of work, so
you can count that work independently.

It is not a way to bypass a paywall, unlock a paid feature, or defeat any protection. The
meter never sends a command to an appliance, and nothing here involves vendor-cloud
credentials. If a step would only make sense as an attack on someone else's device, it is
not part of this procedure.

Everything below is a **method**. No capture output, UUID, or opcode in this repo was
observed on any real device; the examples in `config/events.example.yaml` are invented
placeholders. You produce the real values yourself, from your own hardware.

---

## What you are looking for

One GATT write that happens exactly once per unit of work. Concretely, a triple:

    (service UUID, characteristic UUID, payload prefix)

That triple goes into `config/events.yaml`. Everything else in the system is already built.

---

## Step 1: capture the link

On an Android phone that drives the appliance:

1. Enable **Developer options** (tap Build number seven times in Settings > About phone).
2. Turn on **Enable Bluetooth HCI snoop log**.
3. Toggle Bluetooth off and on. The log only starts on a fresh stack init on most builds.
4. Open the vendor app and **drive a known number of real work cycles** on your device.
   Count them out loud and write the number down. Ten is plenty and twenty is better; the
   exact number is the thing you will match against later.
5. Leave a deliberate gap of thirty seconds or so between cycles. It makes the pattern
   obvious in the timeline.
6. Pull the log:

   ```
   adb bugreport bugreport.zip        # snoop log is inside, path varies by vendor
   # or, where the path is exposed directly:
   adb pull /sdcard/btsnoop_hci.log
   ```

Some builds only flush the log on bug report generation, so use `adb bugreport` if a direct
pull gives you a stale or empty file.

## Step 2: narrow it down mechanically

```
python tools/parse_snoop.py btsnoop_hci.log --prefix-len 2
```

This groups every ATT write by `(opcode, handle, payload prefix)` and sorts by frequency. It
reads the file only; it does not connect to anything.

You are looking for a group whose count equals the number of cycles you drove. That
correspondence is the whole signal. Watch out for:

- **A count that is a clean multiple of your cycles** (2x, 3x). The app may send the command
  more than once per action, or the write may be fragmented. Check the payloads before
  assuming; if it is genuinely repeated, the debounce setting in `events.yaml` handles it.
- **High-frequency groups on a regular interval.** Those are keepalives, status polls, or
  notification acks. They will not track your cycle count.
- **Nothing matching at all.** Either the log did not cover your session, or the link is
  encrypted. Go to step 5.

Re-run with a longer `--prefix-len` if one handle carries several different commands. The
prefix has to be long enough to separate "do one unit of work" from "report status".

## Step 3: confirm in Wireshark

`parse_snoop.py` reports ATT **handles**, because that is all a write carries. To get the
UUIDs you need the discovery exchange from the same capture.

1. Open the log in Wireshark. It reads btsnoop natively.
2. Filter with `btatt` to see the ATT layer.
3. Find the `Read By Group Type Response` and `Read By Type Response` frames near the start
   of the connection. These map handles to service and characteristic UUIDs.
4. Locate your candidate handle in that mapping. Wireshark will then annotate later writes
   to that handle with the characteristic UUID.
5. Cross-check the timeline: select each write to your candidate handle and confirm the
   timestamps line up with the gaps you left between cycles.

Useful filters:

```
btatt.opcode == 0x12 || btatt.opcode == 0x52     # write request / write command
btatt.handle == 0x00XX                            # your candidate
```

If the discovery exchange is missing because the phone had already bonded and cached the
handles, clear the app's Bluetooth cache or forget the device and re-pair before capturing.

## Step 4: cross-check against the app

The capture tells you *what* is written; the app tells you *what it means*. Decompile the
vendor APK you already have installed:

```
jadx-gui app.apk
```

Search the decompiled source for:

- the UUID string you found, which usually lands on a constant with a descriptive name;
- `writeCharacteristic`, `BluetoothGattCharacteristic`, `setValue` call sites;
- the byte constants that make up your payload prefix.

The goal here is narrow: confirm that the characteristic you picked is the one associated
with performing work, and not a status or configuration channel that happens to correlate.
That is all you need from the app. You are not looking for keys, licence checks, or
server endpoints, and you should not use any you stumble across.

If the app is obfuscated, the UUID constants usually survive even when method names do not,
which is normally enough for the confirmation.

## Step 5: when the link is encrypted

With LE Secure Connections, passive capture gives you ciphertext and step 2 finds nothing.
Two supported paths, both on your own hardware:

**Path A: capture the pairing.** The link key is derivable only if you record the pairing
exchange itself. Forget the device on the phone, start the capture, then pair fresh. With
the pairing in the capture, Wireshark (or a sniffer like an nRF52 dongle with
`nrf_sniffer_ble`) can decrypt the session that follows. This is the lower-effort path and
it needs no extra hardware beyond the sniffer, but you must redo it whenever the bond is
re-established with a new key.

**Path B: run the meter as a proxy.** The gateway presents itself as a peripheral that the
app pairs with, and connects onward to your appliance as a central, relaying traffic. It
sees the plaintext because it is a legitimate endpoint of both encrypted links rather than
an eavesdropper on one.

Path B is an observation path on hardware you own. It still originates no command of its
own: every byte it forwards came from the app, and the meter counts rather than injects.
Setting it up is covered in `docs/hardware-setup.md`. Prefer Path A when it works, because
the proxy adds a hop that can affect timing on latency-sensitive devices.

## Step 6: write the config and verify by counting

Put the triple into `config/events.yaml`:

```yaml
events:
  - event: work_unit
    service: "<the service UUID you found>"
    characteristic: "<the characteristic UUID you found>"
    prefix: "<the payload prefix, hex>"
```

Then do the only test that matters: run the meter, drive a known number of cycles, and
compare. If the meter says 20 and you did 20, you are done. If it says 40, the command is
sent twice and you need a debounce. If it says 12, your prefix is too specific and is
missing a variant, or some cycles use a different opcode.

Record the result in the Results table in the README. Do not fill that table in from
anything except a run you actually performed.

---

## Notes

- Vendor app updates can change the protocol. Keep unknown-write logging on: a sudden rise
  in unknown writes alongside a drop in counted events is the signal that something moved.
- Some devices send the work command over a proprietary service and a status update over a
  standard one. Count the command, not the status: status can be resent, suppressed, or
  arrive out of order.
- Record which of these paths you used in the Results table. Passive and proxy have
  different reliability characteristics and it matters when reading the numbers back later.
