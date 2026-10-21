# Devices  `[g]`

Synthesised device profile per MAC — joins ARP, DHCP, beacons,
probes, and WiFi-station state into a single record.

## Source

[`src/devices.c`](../../src/devices.c) runs each poll and builds an
in-memory device table by upserting one row per MAC across five
sources:

1. **ARP** — kernel ARP table → IP + MAC + interface.
2. **DHCP** — assigned IP and hostname (bridged to MAC via the
   matching ARP entry).
3. **Beacons** — 802.11 beacons identify access points by BSSID
   (which is a MAC).
4. **Probes** — 802.11 probe requests show unassociated clients
   by their source MAC.
5. **Stations** — currently-associated WiFi clients via nl80211.

Then [`src/camera_join.c`](../../src/camera_join.c) (#106 round 2)
folds the camera rules' inputs onto those records — WS-Discovery,
mDNS, SSDP and RTSP by **the same IP**, a camera setup SSID and a
camera-vendor OUI by **the same MAC** (the BSSID). A setup SoftAP's
BSSID is never joined to a LAN IP: nothing on the air ties the two. A
camera heard announcing itself on the LAN with no record for its IP
gets one keyed by IP alone, with no MAC. Full rules and keys:
[camera-detection](../wiki/camera-detection.md).

Each source contributes a bit in the `Src` flag column.

## View

Two rows of chrome, then one row per device, newest first. IP, Vendor
and the name column flex with the terminal width; at the 100-column
minimum they get 15, 9 and 15 cells and nothing reaches the last column.

```
 Devices: 6  cameras: 4  [up/dn] navigate  [Enter] detail  (newest first)
 MAC                IP               Class   Vendor     Hostname / SSID  Src      RSI   Risk  Hits
 3c:22:fb:10:20:30  10.0.0.64        CAMERA  Hikvision  HIKVISION DS-2C  A-----C  -     HIGH  0
 -                  10.0.0.65        CAMERA  ?          AXIS P1435-LE    ------C  -     HIGH  0
 9e:11:22:33:44:55  -                CAMERA  Hikvision  (camera setup A  ---B---  -55   MED   0
 00:40:8c:01:02:03  -                CAM?    Axis Comm  (access point)   ---B---  -61   MED   0
 b8:27:eb:11:22:33  192.168.1.100    -       Raspberry  raspberrypi      AD-----  -     LOW   0
 de:ad:be:ef:00:01  -                -       ?          ssid:Starbucks   ----P--  -55   MED   127
                                                                         │││││││
                                                                         ││││││└─ Camera row joined by IP
                                                                         │││││└── Station
                                                                         ││││└─── Probe
                                                                         │││└──── Beacon
                                                                         ││└───── mDNS (reserved)
                                                                         │└────── DHCP
                                                                         └─────── ARP
```

### The CAMERA row

`Class` is the row type:

| Cell | `device_class` | Rests on |
|---|---|---|
| `CAMERA` | `camera` | the device named its own class: an ONVIF `NetworkVideoTransmitter`, UPnP `DigitalSecurityCamera:1`, an `axis-video` / `cctv` DNS-SD service, or a camera vendor's documented setup SSID |
| `CAM?` | `camera-vendor` | only an IEEE OUI block or an SSDP `SERVER` product token names a camera maker; the device class was not observed |
| `-` | — | no class-bearing signal. RTSP, and an mDNS `_rtsp` service, never set a class: RTSP is a protocol NVRs and media servers serve too |

Both forms corroborate; neither confirms. The name column falls back to
the camera vendor and model (ONVIF `name` + `hardware` scopes) when there
is no hostname, and to `(camera setup AP)` for a BSSID advertising a
camera setup SSID.

### Enter: device detail

`Enter` opens the selected device; `Enter` or `Esc` returns. The detail
follows the device, not the row, so the newest-first re-sort under it
does not move it to another device. It does not scroll: a section that
does not fit is counted on the last line instead of drawn, and each line
is cut at the terminal width rather than wrapped. Shown at 100 columns
with the screen tall enough for every section:

```
 ── DEVICE DETAIL ──  [Enter/Esc] back
  MAC 3c:22:fb:10:20:30   IP 10.0.0.64   OUI vendor ?   Src A-----C
  Class    camera - the device named its own class; corroborated, not confirmed
  Camera   vendor Hikvision   model HIKVISION DS-2CD2042WD-I
  Signals  WSD - MDNS SSDP - RTSP
 ── SIGNAL TRAIL ──
  RULE              SEEN      WHAT
  CAM_MDNS_SERVICE  10s ago   mDNS _axis-video._tcp instance Garage Cam._axis-video._tcp.local (Axi
  CAM_SSDP_DEVICE   15s ago   SSDP NOTIFY alive Basic:1, SERVER names camera vendor Hikvision (the
  CAM_RTSP_UNAUTH   20s ago   RTSP DESCRIBE answered with no challenge on port 554 path /Streaming/
  CAM_WS_DISCOVERY  30s ago   ONVIF Hello, Types dn:NetworkVideoTransmitter, XAddrs http://10.0.0.6
 ── ONVIF SCOPES ──
  onvif://www.onvif.org/type/video_encoder
  onvif://www.onvif.org/name/HIKVISION
  onvif://www.onvif.org/hardware/DS-2CD2042WD-I
  onvif://www.onvif.org/location/city/hangzhou
  XAddrs http://10.0.0.64/onvif/device_service
 ── mDNS ──
  instance Garage Cam._axis-video._tcp.local   _axis-video._tcp   host cam.local:554
 ── SSDP ──
  SERVER Linux/3.0 UPnP/1.0 Hikvision-Webs/1.0
 ── RTSP EXPOSURE ──
  PORT   ANON  AUTH   401  SCHEME   PATH
  554       4     0     0  -        /Streaming/Channels/101
  8554      0     0     1  Digest   /sub
```

The trail is one line per source row, newest first, each named by the
rule that reads it. RTSP exposure lists every stream sloth saw answered
for the IP, authenticated ones included, so an anonymous path reads
against its neighbours. No credential appears anywhere on this screen:
sloth never stores one (the `cleartext_creds` guardrail), and
default-credential matching is struck by owner ruling (#145).

## Risk bucket

The `Risk` column shows a bucket derived from independently observable
signals — no ML, no black box. Bucket = weighted sum of signals:

| Signal | Weight | Meaning |
|--------|-------:|---------|
| `RANDOM_MAC`     | 1 | Locally-administered bit set (Apple/Android privacy MAC, monlib randomization) |
| `UNKNOWN_VENDOR` | 1 | OUI not in the embedded table |
| `NO_HOSTNAME`    | 1 | No DHCP/mDNS/NBNS hostname resolution |
| `PROBE_ONLY`     | 1 | Probe frames observed, no beacon/STA association |
| `CLEARTEXT_CRED` | 3 | This device leaked a credential in the clear (see `[v]` Alerts, `CLEARTEXT_CRED`) |
| `ALERT_TAGGED`   | 3 | An active alert names this device's IP as its target |

Score → bucket:

| Score | Bucket | Colour |
|-------|--------|--------|
| 0     | LOW    | dim |
| 1–2   | MED    | phosphor-heat 0.4 |
| 3–4   | HIGH   | phosphor-heat 0.7 |
| 5+    | CRIT   | phosphor-heat 1.0 |

The signal bitmask is exported in the JSONL `risk_signals` field so
external consumers can reproduce the score and show a per-signal
breakdown.

## What's normal

- Each known device shows multiple source flags — e.g. `AD-----` for
  a wired host (ARP + DHCP) or `A----S-` for a wireless client.
- Vendor column matches your inventory.
- Your own cameras show as `CAMERA` rows: ONVIF and vendor SSDP
  announcements are what they do by default. The operator's job is to
  recognise their inventory, not to treat each row as an incident.

## What's suspicious

- **Unknown vendor `?`** on a device with an IP — randomised MAC or
  an OUI not in the embedded table. Worth a manual whois.
- **`---B--` only**: a beacon-only entry is just an AP. **`----P-`
  only**: someone in radio range probing but not connecting (could
  be passing through, could be casing the place — see
  [`probe.md`](probe.md)).
- **New device** appearing in the list without DHCP — probably
  manually-configured. Rogue hosts often skip DHCP to avoid the audit
  trail.
- **One IP, two MACs** within a few minutes — MAC spoofing or
  legitimate failover. Reconcile with `[8] ARP` and `[d] DHCP`.
- **A `CAMERA` row you do not own**, or one with `RTSP` in its signals:
  a stream description was handed out with no authentication step on
  the wire. Check the RTSP exposure table in the detail.
- **`(camera setup AP)`**: a BSSID advertising a camera vendor's setup
  SSID. Whether the camera is unprovisioned is not observed — a reset or
  a re-pair raises the same AP — but the SoftAP is reachable while it is
  up.
- **A `CAM?` row**: only the address block or a SERVER string names a
  camera maker; an NVR from the same vendor reads the same.

## See also

- [`arp.md`](arp.md), [`dhcp.md`](dhcp.md), [`beacons.md`](beacons.md),
  [`probe.md`](probe.md), [`wifi.md`](wifi.md) — the five upstream
  sources.
- [`alerts.md`](alerts.md) — the `CAM_*` rule rows;
  [camera-detection](../wiki/camera-detection.md) — how their evidence
  reaches this view.
