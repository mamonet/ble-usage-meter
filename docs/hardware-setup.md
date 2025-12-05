# docs/hardware-setup.md
<!-- final path: docs/hardware-setup.md -->

# Hardware setup

Scope: everything here runs against appliances the operator owns. The meter observes and
counts; it never sends a command to an appliance.

---

## Choosing between ESP32 and Raspberry Pi

| | ESP32 | Raspberry Pi |
|---|---|---|
| Cost per unit | Low | Higher |
| Power | Runs off the appliance's USB, negligible draw | Needs a proper supply |
| Deploy model | One per machine, permanent | One per bench, or per small cluster |
| Passive observe | Yes | Yes |
| Proxy mode | Awkward; NimBLE can do both roles but resources are tight | Straightforward with BlueZ |
| Debugging | Serial console, reflash to change anything | Full Linux, `btmon`, Python REPL |
| Storage | NVS, a few hundred KB | SQLite on an SD card or SSD |
| Clock | No RTC; needs SNTP or it timestamps from boot | NTP as usual |

**Rule of thumb:** develop on the Pi, deploy on the ESP32. The Pi gives you `btmon`, live
Python, and easy proxying while you are still figuring out the event signature. Once the
mapping is settled and passive capture is known to work, the ESP32 is what you bolt to each
machine and forget about.

Stay on the Pi permanently if you need proxy mode, if the appliance is somewhere with power
and network anyway, or if one gateway can cover several machines in range.

---

## ESP32

### Requirements

- ESP-IDF v5.x. The firmware is C++17 and uses NimBLE, which ships with IDF.
- Any ESP32 with BLE. Plain ESP32, C3, and S3 all work; the C3 is the cheapest that is not
  end-of-life.
- USB serial for flashing.

### Build and flash

```
. $IDF_PATH/export.sh
cd firmware/esp32
idf.py set-target esp32c3          # or esp32, esp32s3
idf.py menuconfig                  # WiFi credentials, see below
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

`sdkconfig.defaults` sets the NimBLE options the firmware needs. If you regenerate
`sdkconfig`, check that NimBLE is still the selected host and that the observer role is
enabled.

### Configuration

`config.h` holds build-time values, all placeholders. Set at minimum:

- `kReportEndpoint` — your backend's `/reports` URL.
- `kMeterDeviceId` — must match the id you register with the backend.
- `kReportIntervalSec` — 300 is a reasonable default.

Event rules are compiled in for the ESP32 build. Change them, rebuild, reflash.

### Provisioning the signing key

**The key is not compiled into the image.** It is written to NVS at setup time, so the
firmware binary is not secret and can be built in CI.

```
python tools/keygen.py --out /secure/path/dev-0001.key
```

Print the public key from that output, register it with the backend, and write the private
seed into NVS under the key named in `config.h` (`kNvsKeySignKey`) using your provisioning
step or `esp_partition` tooling. Never commit the key, and never put it in `config.h`.

### Clock

The ESP32 has no RTC. Report windows come from SNTP; without it, timestamps run from boot
and the backend cannot attribute usage to a period. Enable SNTP and give the device network
before you trust any window.

---

## Raspberry Pi

### Requirements

- Pi 3B+ or newer. A Pi Zero 2 W works for observe mode and is tight for proxy mode.
- Raspberry Pi OS Bookworm or similar, with BlueZ 5.66+.
- Python 3.11.

An external USB Bluetooth adapter is worth having. The built-in radio is fine for observe
mode, but proxy mode wants two adapters so the central and peripheral roles do not contend.

### BlueZ setup

```
sudo apt install bluez bluez-tools python3-dbus
sudo systemctl enable --now bluetooth
bluetoothctl show                  # confirm the adapter is up
```

For proxy mode, BlueZ needs experimental features for some advertising and pairing
controls:

```
sudo systemctl edit bluetooth
# add:
#   [Service]
#   ExecStart=
#   ExecStart=/usr/libexec/bluetooth/bluetoothd --experimental
sudo systemctl restart bluetooth
```

Give the meter process access to the adapter without running it as root:

```
sudo usermod -aG bluetooth ble-meter
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python3))
```

The `setcap` line applies to the interpreter, so prefer a dedicated virtualenv interpreter
over the system one.

### Install and run

```
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp config/gateway.example.yaml config/gateway.yaml
cp config/events.example.yaml config/events.yaml
# edit both: they ship placeholders only
python -m gateway.cli --config config/gateway.yaml
```

### Useful during bring-up

```
sudo btmon                                  # live HCI, the Pi equivalent of the snoop log
sudo btmon -w capture.snoop                 # write a btsnoop file
bluetoothctl devices                        # what is bonded
```

`btmon -w` output feeds straight into `tools/parse_snoop.py`, so you can iterate on the
event mapping on the Pi without going back to the phone.

---

## Observe mode versus proxy mode

### When passive observe works

- The link is unencrypted, or
- you captured the pairing exchange and can decrypt the session, and
- your adapter reliably follows the connection.

Observe mode is always preferable when it works. It is invisible to both endpoints, it
cannot affect the appliance's behaviour, and it fails safe: a missed packet is an
undercount, never a disruption.

The catch is reliability. A passive listener has to follow the connection's frequency
hopping. Consumer adapters were not built for this and will drop packets, especially at
range or in an RF-noisy environment. **Dropped packets mean undercounts.** Validate against
a hand count before you bill anything, and re-validate after moving anything.

A dedicated sniffer (an nRF52840 dongle running the Nordic BLE sniffer firmware) is far
more reliable than a general-purpose adapter and costs little. Use one if observe mode is
your production path.

### When you need the proxy

Passive capture fails outright when the link uses LE Secure Connections and you did not
capture the pairing. You get ciphertext and no amount of listening helps.

Proxy mode puts the gateway between the phone and your own appliance:

```
phone app  <--BLE-->  gateway (peripheral role)
                      gateway (central role)  <--BLE-->  your appliance
```

The gateway advertises the same service profile, the app pairs with it, and it relays every
operation onward to the real device. It sees plaintext because it is a genuine endpoint of
both encrypted links, not an eavesdropper on one.

**This is an observation path on hardware you own.** The proxy originates no command of its
own: every byte forwarded came from the app, and the meter counts rather than injects.
There is no code path that generates or replays an appliance command.

Practical consequences:

- The app must pair with the gateway instead of the appliance. That is a one-time step the
  operator performs on their own equipment.
- The extra hop adds latency, typically one connection interval. Devices with tight timing
  may notice. Test before committing.
- Two adapters is strongly preferred. One adapter juggling both roles works but connection
  scheduling gets unreliable under load.
- If the gateway dies mid-session, the app loses the appliance. Passive observe has no such
  failure mode, which is another reason to prefer it.

Set the mode in `config/gateway.yaml`:

```yaml
mode: observe      # or: proxy
```

---

## Physical placement

Placement decides your accuracy more than anything else in this document. A dropped packet
is a lost unit of work.

- **Put the meter within a metre or two of the appliance**, closer if you can. It is
  listening to a link that was engineered for a phone in someone's hand, not for a third
  party in the corner of the room.
- **Line of sight to the appliance's antenna.** 2.4 GHz does not go through metal. An
  appliance in a metal enclosure will need the meter inside it or right at an opening.
- **Away from the appliance's own power electronics.** Motors, heaters, and switching
  supplies generate broadband noise. If the meter sits on the same chassis, move it as far
  from the supply as the cable allows.
- **Away from WiFi access points and USB 3 ports.** Both stamp all over 2.4 GHz. A USB 3
  hard drive enclosure next to the meter is a genuine cause of packet loss.
- **Consider where the operator stands.** They hold the phone. A human body between the
  phone and the meter attenuates significantly. Place the meter on the side the operator
  works from, not behind the machine.
- **Fix it in place.** Accuracy validated with the meter taped to a bench does not survive
  someone moving it. Mount it.

For proxy mode the placement constraint applies twice, since the gateway now needs a good
link to both the phone and the appliance. Between them, not behind either.

### Validating placement

Run the meter, drive a known number of cycles from the position the operator actually
works from, and compare counts. Then repeat at the far end of the intended working area.
If the two disagree, the meter is too far away or something is in the path. Record the
result in the Results table in the README; do not fill that table from anything but a run
you performed.
