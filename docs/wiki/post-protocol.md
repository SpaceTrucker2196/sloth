---
name: post-protocol
description: The sloth-ios sensor-post protocol, vendored from sloth-ios and pinned to ver=1.0 - the one-way JSONL stream a phone serves and slothweb's --post reads, its six record types, and which of them may travel to a peer
type: reference
---

# sloth sensor-post protocol (vendored, `ver=1.0`)

**Summary**: the contract a sloth-ios **post** (a phone serving its own
sensors) meets a **hub** at. In this repo the hub is slothweb: `--post
HOST:PORT` opens one read-only reader per post and keeps a roster at
`/api/posts` (#205 slice 1). Vendored so a cold start needs nothing out
of tree (MISSION §5); this copy is the one slothweb's tests are written
against.

**Sources**: `sloth-ios/docs/wiki/post-protocol.md` at sloth-ios commit
`6774bb7` (app `CFBundleShortVersionString` 1.0, the TXT record's
`ver=1.0`), copied 2026-11-19; owner rulings on sloth#205
(2026-11-13: consume in slothweb, not the sensor; 2026-11-19: what
travels, `--strict`, vendoring). slothweb side: `web/src/web_posts.c`,
`web/src/web_posts.h`, `web/tests/test_posts.c`.

**Last updated**: 2026-11-19 (vendored at `ver=1.0`; slothweb's reader
and the fleet-share classification).

**Pin.** The text below the line is sloth-ios's, unchanged but for this
header and the "In sloth" section at the end. A post whose `ver=` is not
`1.0` may add fields or types: slothweb counts an unknown type as
`other` and drops nothing else silently. When sloth-ios changes the
protocol, copy it again and move the pin.

---

The contract a sloth-ios **post** meets a **hub** at. A hub is a sloth
instance or another sloth-ios acting as the fleet viewer. This is the
mirror image of sloth's own `--data-socket`: a one-way, newline-
delimited JSON stream, pulled by the consumer, authored by the
producer. Here the producer is the phone.

## Discovery

A post publishes a Bonjour service:

| Field   | Value                                             |
|---------|---------------------------------------------------|
| type    | `_sloth-post._tcp.`                               |
| name    | the operator-chosen post name                     |
| port    | OS-assigned (read from the resolved service)      |
| TXT     | `post=<uuid>` `role=mobile\|roaming\|fixed` `ver=<app>` `plat=ios\|ipados` |

A hub browses `_sloth-post._tcp.`, resolves each service to host +
port, and opens a TCP connection. A sloth instance should treat each
resolved post as a passive sensor family (see sloth issues #26 / #28);
sloth-ios's `FleetCoordinator` opens a `PostClient` per post.

## Transport

- TCP, newline-delimited UTF-8 JSON, one record per line (`\n`).
- One-way: the post **never reads** from the hub. No handshake, no
  auth, no verbs. Access control is the operator's (tailnet bind,
  Tailscale ACLs) — identical to sloth's data socket.
- On connect, the post bursts a **snapshot** (current identity + one
  of each latching record + every live BLE contact), then streams the
  live tail.
- Foreground only. Backgrounding the app closes the listener.

## Envelope

Every record shares sloth's envelope and adds `post`:

```json
{ "type": "<tag>", "ts": <unix-seconds>, "post": "<uuid>", ... }
```

## Record types

| type           | meaning                          | key fields |
|----------------|----------------------------------|------------|
| `ios_post`     | heartbeat + identity (every 5 s) | `name` `role` `platform` `app_ver` `battery` `charging` `uptime_s` |
| `ble_contact`  | one BLE advertiser heard         | `addr` (opaque id, not a MAC) `addr_type` `name` `rssi` `tx_power` `services[]` `count` |
| `imu_sample`   | compass + magnetometer + attitude| `heading_deg` `field_mag_uT` `field_x/y/z` `pitch_deg` `roll_deg` `yaw_deg` |
| `wifi_self`    | the one joined WiFi network      | `ssid` `bssid` `rssi` `band` (null unless entitled) |
| `geo_fix`      | coarse position (opt-in)         | `lat` `lon` `alt_m` `h_acc_m` `course_deg` `speed_mps` |
| `radio_scan`   | best-effort nearby-AP scan       | `available` `reason` `aps[]` |

### iOS reality

The sandbox gates what a post can actually observe:

- **`ble_contact`** — works. `addr` is iOS's opaque
  `CBPeripheral.identifier`, not a hardware MAC. Scan-only; the post
  never connects to a peer.
- **`imu_sample`** — works via CoreMotion / CoreLocation.
- **`wifi_self`** — only the joined network, and only with the "Access
  WiFi Information" entitlement + location permission. Otherwise the
  fields are null (honest "don't know").
- **`geo_fix`** — opt-in; off by default.
- **`radio_scan`** — a full nearby-AP scan needs the private
  `com.apple.wifi.manager-access` entitlement, which a dev / ad-hoc /
  TestFlight signature cannot carry. On a stock device this comes back
  `available: false` with the blocking reason. A jailbroken or
  Apple-internal-signed build could fill it; the field shape is ready.

## Privacy

Both sides are in-memory only (MISSION §2(6)). The only persisted
producer state is the post identity (`PostIdentity`): a random UUID
and a name in `UserDefaults`, rotatable to shed history.

## Reference

Producer: `Sources/SlothCore/SensorRecord.swift`,
`SensorBuffer.swift`, `PostService.swift`, `PostIdentity.swift`,
`App/Sensors/`. Consumer / fleet: `PostClient.swift`,
`FleetStore.swift`, `FleetRadar.swift`, `App/Sensors/FleetCoordinator.swift`.

## In sloth: slothweb's reader and what travels

- **Consumer**: slothweb, never sloth (the sensor stays silent; MISSION
  §2). `--post HOST:PORT`, repeatable (at most 8), a literal address in
  the tailnet (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) unless
  `--post-allow-outside-tailnet`; `--strict` refuses any. No mDNS browse
  in slice 1: Bonjour does not cross the tailnet, which is the roaming
  case, so the address and port are given. → [[cli-reference]]
- **Read only**: the reader never writes a byte, not even a shutdown.
  Back-off 1 s doubling to 30 s when the post goes away.
- **Kept**: per post, the `ios_post` identity and a count of each type.
  No other record's contents in slice 1.
- **Fleet sharing** (owner rulings 2026-11-19, ADR 0009, [[fleet]]):

  | type | travels to a peer | why |
  |---|---|---|
  | `ble_contact` | yes | a passive BLE receive: monitor provenance |
  | `wifi_self` | never | the phone's joined, authenticated network: managed provenance |
  | `geo_fix` | never | the operator's own position |
  | `imu_sample` | never | the operator's own movement |
  | `radio_scan` | never | the phone's ordinary Wi-Fi card scanning (Hotspot Helper, sloth-ios#17), treated as the managed card's scan |
  | `ios_post` | never | the post's own state |
  | anything else | never | fail closed |

  `web_post_type_travels()` holds this; `web/tests/test_posts.c` pins it.

## Related pages

- [[slothweb]] — the service that reads posts.
- [[fleet]] — the fleet export and the monitor-only rule.
- [[ble]] — sloth's own BLE receivers, the closest kin of `ble_contact`.
- [[rf-distance]] — why an RSSI range is an estimate, not a position.
- [[cli-reference]] — `--post`.
