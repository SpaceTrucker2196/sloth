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

**Last updated**: 2026-07-04.

---

## The non-negotiable filter

Every family is judged against MISSION §2 first. A sensor may **only** land if
it is:

- **Passive.** It reads a local device / socket / file / capture stream. It
  never transmits, never associates, never probes, never injects. (The one
  charter carve-out — retuning sloth's *own* monitor radio's channel, #22 —
  does not extend to transmitting on any band.)
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

### GPS / location context
- **Observe**: the operator's own position/time from a local GPS (gpsd) — used
  to *stamp* other observations with where/when they were seen, not as a
  target. Enables geo-tagged site snapshots (#27) and wardrive-style maps.
- **Hardware**: any gpsd-served receiver.
- **State**: a single `gps_fix_t` (lat, lon, alt, fix quality, sat count, ts)
  on the state, plus optional per-observation location stamping.
- **View**: a status line; lat/lon in the snapshot header.
- **JSONL**: a `gps` field on existing records, or a `gps_fix` record.
- **Out of scope**: tracking third parties; this is *self*-location only.
- **Test**: crafted gpsd JSON / NMEA sentences.

### ADS-B aircraft
- **Observe**: decoded Mode-S / ADS-B messages from a local decoder
  (dump1090): ICAO address, callsign, altitude, position, velocity.
- **Hardware**: an RTL-SDR on 1090 MHz feeding dump1090, whose feed sloth tails.
- **State**: `adsb_aircraft_t` keyed by ICAO.
- **View**: an aircraft table.
- **JSONL**: `adsb_aircraft`.
- **Out of scope**: transmitting, interrogating (that's active radar).
- **Test**: sample dump1090 SBS/JSON lines.

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
