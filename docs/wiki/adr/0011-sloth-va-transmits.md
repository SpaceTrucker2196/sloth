---
title: sloth-va, a Victron reader that transmits, beside a sloth that does not
date: 2026-11-15
status: Accepted
authority: owner request and rulings of 2026-11-15 ("I want to make a sloth-va that will connect to victron hardware and gather the data stream from it"; share hci0 / then a dedicated controller; both Instant Readout and scheduled GATT sessions)
---

# ADR 0011 — sloth-va: the first sloth-family component that transmits

## Context

The owner's camper carries three Victron Energy devices: a BMV-712 Smart
battery monitor, an Orion-Tr Smart 12/12-18A isolated DC-DC charger and
a VE.Direct Bluetooth Smart dongle. sloth's BLE capture already hears
them: two send Victron Instant Readout (manufacturer data, company
0x02E1, record 0x10), the dongle sends a different record. Their values
are encrypted (AES-CTR, a per-device key, [research](../../../research/victron/instant-readout-and-gatt.md))
and the richer data is behind an LE connection that requires pairing
with the device's PIN.

MISSION.md §2 holds sloth to receiving: on Bluetooth "no inquiry, no
active scanning (no SCAN_REQ), no connection, pairing or GATT read, no
advertising", and rule 2: sloth "never decrypts a frame it captured".
Reading the owner's own Victron gear the way the owner asked needs a
connection, pairing and decryption. The charter is not the agent's to
change (agents/dark-factory.md §4.3), and this decision does not change
it.

## Decision

**A separate helper, `sloth-va`, does the transmitting and the
decrypting; sloth stays as it is.**

- **Separate binary, separate account, opt-in.** `src/va/`, built only
  where libsystemd (sd-bus) is found, linked into neither `sloth` nor
  `slothweb` (tests/test_va.c fails if `src/va/` reaches their source
  lists or a file under `src/` or `web/src/` includes it). It runs as
  `sloth-va` under `packaging/systemd/sloth-va.service`, which `make
  install-service` installs and never enables. The owner enables it.
- **What sloth sees is a file.** sloth-va appends one JSONL record per
  reading to `/var/lib/sloth-va/victron.jsonl`. sloth reads it as a
  passive file source (`--victron PATH`), the same shape as `--rtl433`
  and `--aprs`. sloth decrypts nothing and connects to nothing; rule 2
  and the Bluetooth paragraph of §2 still describe sloth exactly.
- **Scope: the owner's listed devices, nothing else.** sloth-va's
  peers are exactly the addresses in `/etc/sloth/victron.keys` and the
  addresses given in `/etc/sloth/victron-va.conf`. Every other
  advertisement is ignored unread; no other device is ever connected
  to, paired, or written. A device is reached only once BlueZ has heard
  it; sloth-va never starts discovery (which scans actively) to find
  one. A key-file device whose serial is unknown gets one unpaired
  connection to read its name (Victron's default names carry the
  serial); a name without a configured serial is not tried again for
  six hours.
- **What goes on the air.**
  - Instant Readout transmits nothing: sloth-va registers a BlueZ
    AdvertisementMonitor, which makes the kernel hold a passive
    background scan (no SCAN_REQ) with duplicate filtering off
    (net/bluetooth/hci_sync.c).
  - GATT sessions: per configured device, every `--interval` seconds
    (default 300), one at a time, at most 60 s each: LE connect, pair
    with the PIN when not bonded, write the documented keep-alive, read
    the documented values, disconnect. A device that does not offer the
    one GATT service Victron documented (65970000…) gets one connection
    per interval in which its service list is read and recorded; it is
    not paired and nothing is written to it. Between sessions the link
    is down, so the owner's phone app can connect.
- **Secrets.** PINs and keys stay in root-only files the owner writes;
  the unit hands private copies to the service with `LoadCredential=`.
  sloth-va never logs, records or exports a PIN or a key (a text scan
  of its log calls is a test), refuses a world-readable secret file,
  and its pairing agent answers only for the device it is pairing at
  that moment, never as BlueZ's default agent.
- **Announced.** The unit's description says it transmits; every GATT
  session is logged as transmitting; `make install-service` prints that
  it transmits; this ADR and docs/wiki/victron.md say what and when.
- **The own-transmit alert is left to tell the truth.** sloth's
  `BT_OWN_TRANSMIT` fires when the monitor channel shows the host's
  controller told to transmit. sloth-va's LE connections are exactly
  that (`le_connect`), so the alert fires, WARN, naming the controller,
  for `BT_TX_RECENT_SECS` (120 s) after each connection and resolves
  after the quiet period. With three devices at the default interval it
  is effectively standing while sloth-va runs. It is **not** silenced,
  filtered by address or taught sloth-va's name: sloth cannot tell
  sloth-va's connection from anyone else's on that controller, and an
  alert that went quiet for "known" connections would go quiet for a
  compromised host too. The operator reads it as "sloth-va is running";
  its absence while sloth-va runs means the sessions are not happening.
  `ble_scan_mode` reads `passive` from the kernel's background scan.
- **Its own controller.** sloth-va uses one named controller
  (`SLOTH_VA_ADAPTER`, by address, which is stable; hciN follows probe
  order). sloth's own passive scan (`sloth-ble-scan`) belongs on a
  different controller. Until the second adapter is fitted, enabling
  sloth-va stops `sloth-ble-scan` (it `Conflicts=bluetooth.service`,
  which sloth-va requires); sloth's `--bt-monitor` still sees every
  advertising report the kernel's passive scan on sloth-va's controller
  receives.

## Consequences

- The Victron values reach sloth's sensor health and stream from a file,
  with provenance `readout` (decrypted broadcast) or `gatt` (a session).
- bluetoothd must run (it was masked for `sloth-ble-scan`), with
  `Experimental = true` for the AdvertisementMonitor API and, to keep a
  dual-mode controller from page scanning, `ControllerMode = le`
  (docs/wiki/deployment.md §10).
- The BlueZ bond with each paired device persists in `/var/lib/bluetooth`;
  undoing the deployment removes it (`bluetoothctl remove`).
- GATT support for these three devices is unverified: Victron documented
  the 65970000 service for the SmartShunt only. If none of them has it,
  the GATT half degrades to a service inventory once per interval, and
  the owner may lengthen `--interval` or run `--no-gatt`.
- A later change that wants sloth itself to connect, pair or decrypt is
  still a charter change, for the owner.

## Related pages

- [Victron (sloth-va)](../victron.md)
- [Deployment §10](../deployment.md)
- [BLE](../ble.md) — `BT_OWN_TRANSMIT`, `ble_scan_mode`, `sloth-ble-scan`
- [ADR index](README.md)
