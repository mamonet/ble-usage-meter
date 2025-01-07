# ble-usage-meter

An independent usage meter for BLE appliances that are driven by a phone app. Early scaffold.

Many Bluetooth appliances are controlled from a vendor Android/iOS app and expose no usage counter of
their own, or keep it locked inside a vendor cloud. If you own a fleet of these devices and need to
meter, bill, or license their use, you have no trustworthy number to work from.

This watches the BLE link itself, recognises the command that corresponds to one unit of work, counts
those events per device, and posts a signed, tamper-evident usage report to a small backend.

> Scope note: this is for **hardware you own**. It is an interoperability and metering tool, not a way
> to bypass a vendor's paywall or unlock paid features.

ESP32 (NimBLE) or Raspberry Pi (BlueZ), with a small FastAPI backend. Ed25519-signed reports.
