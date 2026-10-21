# Camera detection

**Summary**: How sloth recognises IP cameras passively (#106): the camera
rules, each reading traffic a camera or its setup SoftAP already put on
the wire, and the device-record join that gathers their evidence onto
the `[g]` Devices view as a `CAMERA` row with a signal trail. Nothing
here sends a frame, and nothing here reads, stores or compares a
credential.

**Sources**: `src/camera_join.c`, `src/camera_join.h`,
`src/camera_vendor.c`, `src/alerts/rules_camera.c`,
`src/alerts/rules_wired.c` (`rule_cam_ws_discovery`,
`rule_cam_rtsp_unauth`), `src/alerts/rules_twin.c`
(`rule_cam_setup_ssid`), `src/onvif_discovery.c`, `src/rtsp_snoop.c`,
`src/mdns_snoop.c`, `src/ssdp_snoop.c`, `src/views/devices.c`,
`src/db_schema.c`, `research/papers/ws-discovery-onvif.md`,
`research/papers/camera-setup-softap.md`,
`research/papers/camera-vendor-identity.md`,
`research/rfc/2326-7826-rtsp.md`, issue #106, issue #145.

**Last updated**: 2026-10-20 (#106 round 2: device-record join, CAMERA
row, schema v6).

## The signals

Every one is a WARN on first sighting, one alert per identity with a
rising count, and on the empty-technique list: what it reports is a
camera's own exposure, not an adversary's step, so an ATT&CK technique
such as T1046 would claim an enumeration sloth did not perform
([[alerts]], "exposure, not adversary technique"). Each corroborates and
none confirms (#145 ruling 2).

| Rule | Reads | Key | What it says | Source |
|---|---|---|---|---|
| `CAM_WS_DISCOVERY` | UDP/3702 Hello / Bye / ProbeMatches / ResolveMatches whose `Types` name a `NetworkVideoTransmitter` | `EndpointReference` UUID | the device announced itself as an ONVIF camera | `research/papers/ws-discovery-onvif.md` |
| `CAM_SETUP_SSID` | a beacon SSID with a camera vendor's documented setup-SoftAP prefix (`HAP_`, `DAP-`, `EZVIZ_`, `Tapo_Cam_`) | BSSID | the BSSID advertises a setup SSID; provisioning state not observed | `research/papers/camera-setup-softap.md` |
| `CAM_MDNS_SERVICE` | a DNS-SD service type IANA registers for camera video (`axis-video`, `cctv`), or `rtsp` reported as a protocol | service instance | the host advertises a camera service (or RTSP) | `research/papers/camera-vendor-identity.md` |
| `CAM_SSDP_DEVICE` | an SSDP NOTIFY for UPnP `DigitalSecurityCamera:1`, or `Basic:1` only when SERVER names a camera vendor | USN device UUID | the device called itself a camera, or named a camera maker | `research/papers/camera-vendor-identity.md` |
| `CAM_SETUP_OUI` | a beaconing BSSID in a camera vendor's IEEE MA-L block, U/L bit masked | BSSID | the address block belongs to a camera maker; device class not observed | `research/papers/camera-vendor-identity.md` |
| `CAM_RTSP_UNAUTH` | RTSP `DESCRIBE` answered `200` with no `Authorization` and no earlier `401` on that connection (TCP 554 / 8554) | server IP | a stream description was handed out with no authentication step on the wire | `research/rfc/2326-7826-rtsp.md` |

Full rows, thresholds and the false-positive notes: [[alerts]] and
[`docs/views/alerts.md`](../views/alerts.md).

## What sloth never does here

- **Transmit.** No M-SEARCH, no WS-Discovery Probe, no mDNS query, no
  RTSP or HTTP request, no association to a setup SoftAP. Every input is
  a frame someone else sent ([[sloth]], MISSION §2).
- **Touch a credential.** `src/rtsp_snoop.c` reduces an `Authorization`
  header to the fact that it was present and does not track a
  Request-URI carrying userinfo or a credential-shaped parameter — the
  `src/cleartext_creds.h` guardrail, unchanged. **Default-credential
  matching is struck by owner ruling (#145)**: no table of vendor
  passwords ships, and no observed credential is compared with one.
- **Claim more than it saw.** The INFO → WARN → CRIT escalation the
  issue first proposed would need a join across signals that the wire
  does not provide; it is not attempted (#145).

## The device record (#106 round 2)

`camera_join()` runs inside `devices_update()`, after the MAC-keyed
merges (ARP, beacons, probes, stations) and before the DHCP hostname
bridge. It reads the same snapshot tables as the camera rules, through the
same predicates — `cam_setup_ssid()`, `cam_ssdp_row()`,
`cam_mdns_service()`, `cam_vendor_oui()` in `src/camera_vendor.c`, and
the open-hotspot guardrail `ssid_is_public_hotspot()` — so a device is
never marked on an input its rule stays quiet on.

### Join keys: only what sloth observes

| Side | Signals | Joined on |
|---|---|---|
| LAN | WS-Discovery, mDNS, SSDP, RTSP | the row's source IP == the record's IP |
| Radio | setup SSID, camera-vendor OUI | the BSSID == the record's MAC |

A setup SoftAP's BSSID is **never** joined to a LAN IP. Nothing on the
air ties the AP a camera raises before provisioning to the address it
has on the LAN afterwards, so the two are two records. Pinned by
`tests/test_camera_join.c :: test_setup_softap_never_joins_lan_ip`.

A camera heard announcing itself by a class-bearing LAN signal
(WS-Discovery, a camera mDNS type, SSDP) with no record holding its IP —
the usual case on a mirror port, where the sensor's own neighbour table
never learns it — gets a record of its own: all-zero MAC, `Src` flag
`C`, keyed by IP alone. RTSP and an mDNS `_rtsp` service only ever
attach to an existing record: neither says the host is a camera.

### Fields

| Field | Values | From |
|---|---|---|
| `device_class` | `camera` / `camera-vendor` / unknown | `camera`: the device named its own class (ONVIF NVT, `DigitalSecurityCamera:1`, `axis-video` / `cctv`, a camera setup SSID). `camera-vendor`: only an OUI block or a SERVER token names a camera maker. RTSP sets no class. |
| `camera_vendor` | short brand | SERVER product token, then setup-SSID brand, then the OUI row — in that order of precedence, by source rather than table order |
| `camera_model` | text | the ONVIF `onvif://www.onvif.org/name/` and `/hardware/` scopes, percent-decoded, printable ASCII only (the camera chose every byte) |
| `setup_mode` | 0 / 1 | 1 on a BSSID record advertising a camera setup SSID — the advertisement, not the provisioning state |
| `cam_signal_mask` | `CAM_SIG_*` bits | which camera rules' inputs were seen: 1 WS-Discovery, 2 setup SSID, 4 mDNS, 8 SSDP, 16 OUI, 32 RTSP |

### Where it goes

- **Devices view** `[g]`: a `Class` column (`CAMERA`, or `CAM?` for
  camera-vendor) and an `Enter` detail with the signal trail — which
  rule saw what, and how long ago — plus the ONVIF scopes, mDNS
  instances, SSDP `SERVER` headers and the RTSP exposure table for that
  IP. See [`docs/views/devices.md`](../views/devices.md).
- **JSONL** `device` record: `device_class`, `camera_vendor`,
  `camera_model`, `setup_mode`, `cam_signals` (additive); an IP-only
  record has `"mac":""`. See [[jsonl-schema]].
- **`--db`** `devices` table: the same five columns, schema v6. The
  evidence is history, not a reading: the mask ORs and the class and
  setup flag only rise across ticks. An IP-only record has no MAC to key
  a row on and is not written. v5 files migrate in place by adding the
  columns; see [[sqlite-schema]].

## Limits

- **A camera on the LAN with no camera announcement is invisible here.**
  The join can only mark what a rule could fire on.
- **IP equality is the whole LAN key.** A DHCP lease that moves to
  another host moves the evidence with it until the source rows age out.
- **No fingerprinting by traffic shape.** Bitrate, RTP payload type and
  cloud SNI are not used for the class; `SURV_CLOUD_SNI` (#105) is a
  separate rule about the destination, not the device.

## Related pages

- [[alerts]] — the rule rows and the exposure-list reasoning
- [[jsonl-schema]] — the `device` record fields
- [[sqlite-schema]] — schema v6 and the v5 migration
- [[views-catalog]] — the `[g]` Devices view
- [[research-corpus]] — how the cited documents are indexed
- [[threat-model]] — the passive-only boundary
