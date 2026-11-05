---
name: non-ip-sensors
description: Passive RF / non-IP sensor-family roadmap (BLE, Zigbee, SDR, GPS, ADS-B, Meshtastic, CAN) — issue #26
type: project
---

# Passive non-IP sensor roadmap (#26)

**Summary**: The direction beyond 802.11 — the passive signal families sloth
*may* grow to observe, and the bar each must clear before it lands. This is a
decision framework, not a commitment: it exists so future "add BLE" / "add
ADS-B" requests are judged consistently instead of arriving as unrelated
one-offs.

**Depends on**: [[architecture]] and the sensor abstraction (issue #28). No
family below should be bolted directly onto the Wi-Fi or IP capture paths —
each is a typed producer of observations copied into `sloth_state_t`, exactly
like the 802.11 path. Until the sensor seam exists, treat everything here as
design, not implementation.

**Last updated**: 2026-11-05 (ADS-B in slothweb: the ADS-B tab, [[adsb]]); 2026-11-05 (ADS-B slice 1 shipped: the `--adsb` feed, the aircraft table and the `adsb_aircraft` record, [[adsb]]); 2026-11-02 (the GPS family is shipped: [[location]] for the position, [[gnss]] for the sky; the sketch below replaced by what exists); 2026-10-14.

---

## The non-negotiable filter

Every family is judged against MISSION §2 first. A sensor may **only** land if
it is:

- **Passive.** It reads a local device / socket / file / capture stream. It
  never transmits, never associates, never probes, never injects. (The
  charter's one absolute is no injection onto a monitored network —
  `MISSION.md` §2; retuning sloth's *own* monitor radio's channel with
  `--hop`, #22, is a receiver change and never a transmission.)
- **Local.** The operator owns the receiver and is authorised to observe the
  signal in their environment.
- **Flag-not-exploit.** It surfaces what it hears; it never acts on it.

A family that can't be done within those bounds does not land — it belongs in a
different tool.

## The seven questions every family must answer

Before any sensor family is accepted, its proposal issue must answer:

1. **What is observable passively?** The concrete records, not the aspiration.
2. **What hardware / interface is required?** And is it something an operator
   plausibly already owns?
3. **What enters `sloth_state_t`?** The typed observation struct.
4. **What view, if any?** Reuse an existing pattern or justify a new one.
5. **What JSONL record type, if any?** Additive to the schema, never a rename.
6. **What is explicitly out of scope?** The active behaviours we are *not*
   building (pairing, polling, transmitting, decoding encrypted payloads).
7. **How is it tested without live hardware?** Hand-crafted byte arrays from
   the spec, a fake sensor feed — never a parser fed its own output.

---

## Candidate families

Ordered roughly by how cleanly they fit the passive filter (easiest first).

### BLE / Bluetooth advertisements
- **Observe**: advertising packets — device address (public vs random),
  advertised name, service UUIDs, TX power, RSSI, appearance; iBeacon /
  Eddystone frames; address-rotation correlation (the BLE analog of the
  802.11 MAC-randomisation / seqnum work).
- **Hardware**: an HCI adapter in passive-scan mode (`hci0`) via the Linux
  Bluetooth stack, or an nRF/Ubertooth sniffer.
- **State**: a `ble_device_t` (addr, addr_type, name, top service UUID,
  rssi, first/last-seen, adv count).
- **View**: mirror the probe/roaming panel — one row per device, vendor via a
  BLE company-ID table, RSSI history.
- **JSONL**: `ble_device`.
- **Out of scope**: connecting, pairing, GATT enumeration, active scan
  (which transmits SCAN_REQ).
- **Test**: hand-built HCI LE Advertising Report byte arrays.
- **Status**: in progress under #144. The host source shipped in slice 2
  — the Linux HCI monitor channel via `--bt-monitor`, with the
  `ble_device_t` table above, and an own-transmission check on the host.
  See [[ble]]. Slice 3 added the over-the-air source: `--bt-capture`
  reads an Ubertooth's pcap file or FIFO (BLE link layer and BR/EDR,
  LAP only) into the same table as a second `ble` sensor. See
  [[ubertooth]].

### Zigbee / 802.15.4
- **Observe**: MAC-layer frame metadata — PAN ID, short/extended addresses,
  frame type, channel, LQI/RSSI; network churn (new devices joining a PAN).
- **Hardware**: an 802.15.4 radio in promiscuous/sniffer mode (e.g. a
  CC2531/CC2652 running a sniffer firmware) exposed as a capture interface.
- **State**: `zigbee_frame_t` / `zigbee_device_t` keyed by PAN + address.
- **View**: a frame list like the monitor-frames band; a device inventory.
- **JSONL**: `zigbee_device`.
- **Out of scope**: joining a network, decrypting NWK/APS payloads,
  transmitting beacons.
- **Test**: crafted 802.15.4 MAC headers.

### SDR-derived metadata
- **Observe**: not raw IQ — *decoded metadata* from a local SDR pipeline
  (rtl_433-style): sensor IDs, protocol names, channel/frequency, signal
  level for ISM-band devices (weather stations, TPMS, remotes).
- **Hardware**: an RTL-SDR / HackRF feeding a local decoder whose JSON output
  sloth tails.
- **State**: `sdr_event_t` (protocol, id, freq, rssi, first/last-seen).
- **View**: an event list grouped by protocol.
- **JSONL**: `sdr_event`.
- **Out of scope**: transmitting, demodulating protected/encrypted signals,
  bundling a full SDR stack (sloth *consumes* a decoder's output).
- **Test**: sample decoder-JSON lines.

### GPS / GNSS — shipped
- **Observe**: the operator's own position and time from a local
  receiver (`--gps gpsd://` or `--gps /dev/tty…`), used to *stamp*
  findings with where the sensor was ([[location]], 2026-10-27), and the
  receiver's own sky — satellites in view with C/N0, elevation, azimuth,
  used and health, the DOPs, the receiver's clock against the host's
  ([[gnss]], 2026-11-02). Self-location and the sensor's own antenna
  only; nothing about a third party.
- **Hardware**: any gpsd-served receiver (the reference host: a USB
  u-blox 7 under gpsd), or an NMEA 0183 serial device for the position.
- **State**: `gps_health_t` and the `loc_stamp_t` arbitration in
  `src/gps.c`; `gnss_sky_t` / `gnss_fix_t` on `sloth_state_t`.
- **View**: the `gps` token in the Interfaces health strip, the location
  line in an alert's detail, and the `[#]` GNSS view.
- **JSONL**: `loc` on stamped alerts, the `gps_*` and `gnss_*` members of
  `sensor_health`, `gnss_fix` / `gnss_sky` / `gnss_sat`, and the `sensor`
  record of kind `gps`.
- **Out of scope**: tracking third parties; writing to the receiver
  (sloth sends gpsd one `?WATCH` line and a serial device nothing).
- **Test**: hand-built gpsd JSON and NMEA sentences
  (`tests/test_gps.c`); no fixtures.

### ADS-B aircraft — slice 1 shipped
- **Observe**: decoded Mode-S / ADS-B messages from a local decoder
  (readsb / dump1090-fa): address (ICAO, or `~` non-ICAO / TIS-B),
  callsign, squawk, emergency, category, altitude, position, velocity,
  RSSI.
- **Hardware**: an RTL-SDR on 1090 MHz feeding readsb or dump1090-fa,
  whose `aircraft.json` sloth re-reads (`--adsb PATH`). sloth never
  opens or tunes the SDR and uses no network.
- **State**: `adsb_aircraft_t` keyed by address, `adsb_health_t`
  (`include/sloth.h`, `src/adsb.c`).
- **View**: slothweb's ADS-B tab (aircraft table, position plot, 2026-11-05); a TUI view pending.
- **JSONL**: `adsb_aircraft`, change-only on held altitude bands and
  position cells; `adsb_*` in `sensor_health`; the `sensor` record of
  kind `adsb`.
- **Out of scope**: transmitting, interrogating (that's active radar),
  driving the SDR. SBS / Beast sockets are refused as not yet
  supported.
- **Test**: hand-written `aircraft.json` documents from readsb's
  README-json.md (`tests/test_adsb.c`), a fuzz harness; no captures.
- **Status**: slice 1 (2026-11-05) is the core — feed, state, JSONL.
  The view, slothweb, `--db` and the emergency-squawk alert (with its
  research citation) are pending. See [[adsb]].

### Meshtastic / LoRa
- **Observe**: packet metadata from a local Meshtastic node in a
  listen/monitor role — node IDs, channel, hop limit, RSSI/SNR, port; message
  *metadata* (not decrypted content).
- **Hardware**: a Meshtastic node exposing its packet stream over serial/BLE.
- **State**: `mesh_packet_t` / `mesh_node_t`.
- **View**: a node inventory + packet list.
- **JSONL**: `mesh_node`.
- **Out of scope**: transmitting into the mesh, decrypting channel payloads.
- **Test**: crafted protobuf packet metadata.

### CAN bus (lab / vehicle)
- **Observe**: frame metadata on a SocketCAN interface in a lab/vehicle the
  operator owns — arbitration ID, DLC, periodicity, new-ID appearance.
- **Hardware**: a SocketCAN adapter (`can0`), listen-only mode.
- **State**: `can_frame_meta_t` keyed by arbitration ID.
- **View**: an ID-frequency table (which IDs, how often).
- **JSONL**: `can_id`.
- **Out of scope**: transmitting frames, UDS/diagnostic requests, actuation.
- **Test**: crafted `struct can_frame` records.

---

## Sequencing

1. **Sensor abstraction (#28)** must land first — the typed-observation seam.
2. **BLE** is the natural first family: closest to the existing Wi-Fi model
   (advertisements ≈ beacons/probes, address randomisation ≈ MAC rotation),
   commonly-owned hardware, and a clean passive scan mode.
3. **GPS** next — small, and it multiplies the value of every other family and
   the site snapshots (#27) by adding where/when.
4. The rest are demand-driven: land a family when an operator has the hardware
   and a real use case, judged against the seven questions above.

## Related pages

- [[architecture]] — where the platform/sensor seam lives.
- [[wifi-sigint]] — the 802.11 family whose patterns these mirror.
- [[jsonl-schema]] — the record-type contract new families extend.
- [[adsb]] — the ADS-B family's first slice.
