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
`src/db_schema.c`, `src/lan_role.c`, `src/dhcp_snoop.c`,
`src/ndp_snoop.c`, `research/papers/camera-router-role.md`,
`research/papers/ws-discovery-onvif.md`,
`research/papers/camera-setup-softap.md`,
`research/papers/camera-vendor-identity.md`,
`research/rfc/2326-7826-rtsp.md`, issue #106, issue #145, issue #155.

**Last updated**: 2026-10-21 (#155 review: forged-veto limit, the
mixed-vendor name is not a camera claim, the implied score floor, the
uplink statements). 2026-10-21 (#155: mixed-vendor OUI rows for Ubiquiti,
TP-Link and Wyze; behavioural score with RTSP_SDP as the one deciding
signal; router-role vetoes and `not-camera`; conflicts shown; DHCP
options 55 / 60 as display-only evidence; schema v7). 2026-10-20 (#106
round 2: device-record join, CAMERA row, schema v6; join recency window,
ambiguous-IP refusal, per-family ONVIF / SSDP addresses, MAC-keyed-only
DB stickiness).

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
| `CAM_SETUP_OUI` | a beaconing BSSID in a camera vendor's IEEE MA-L block, U/L bit masked; a mixed-vendor block (Ubiquiti, TP-Link, Wyze; #155) only beside a camera setup SSID on the same BSSID, and never on a locally administered address | BSSID | the address block belongs to a camera maker; device class not observed | `research/papers/camera-vendor-identity.md` |
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
| LAN | WS-Discovery, SSDP | the row's packet source address == the record's IP; one address kept per family (below) |
| LAN | RTSP | the responder's address on the TCP connection == the record's IP |
| LAN | mDNS | the address in the A / AAAA record whose owner name is the SRV target == the record's IP — the **advertised** address, not an observed packet source |
| Radio | setup SSID, camera-vendor OUI | the BSSID == the record's MAC |

The mDNS key is what an answer *claims*, sent by whoever answered: a
Bonjour Sleep Proxy answers for a sleeping host (with that host's
address, which is the point), an mDNS reflector re-sends another
segment's answers from its own source, and anyone on the link can send
a spoofed answer. Requiring the packet source to equal the A-record
address would break the first two and not stop the third — a host that
can spoof an mDNS answer can as easily spoof the UDP source of a
WS-Discovery Hello — so sloth does not, and says here that the mDNS
evidence on a record is the network's claim about that address.

### When an IP is not a key

An IP identifies a host only while the address has not changed hands,
and a passive sensor cannot see a lease move. A join has to pass both
of these:

- **Recency.** A LAN row joins only when its `last_seen` is within
  `camera.join_fresh_secs` of now (`--tune`, default 3600 s: SSDP
  re-advertises inside its `max-age` >= 1800 s, mDNS refreshes service
  records at 80 % of their TTL, and a lease turning over inside an hour
  is the exception). The ONVIF, SSDP and RTSP tables only evict when
  full, never by age, so a stale row is still there; it is listed on the
  record's signal trail as *history, not joined* and adds nothing to the
  record. A WS-Discovery Hello is sent once, on joining the network, so
  a camera nobody probes drops back to unclassified after the window —
  the knob trades that against the reuse risk.
- **One record per address.** Two records holding the same IP — two
  LANs on the same subnet, a stale neighbour entry beside a fresh one —
  is a key that names no one: neither is marked, no IP-only record is
  made, and the trail says *not joined (more than one device record
  holds this IP)*. The rows do not carry the capture interface, so
  sloth refuses rather than picks.

**Dual stack.** WS-Discovery and SSDP run on both 239.255.255.250 and
ff02::c, and their rows are keyed by `EndpointReference` / USN, so one
camera's announcements arrive from an IPv4 and an IPv6 source. Each row
keeps the last address of each family with its own time. The IPv4
address joins first; when it joined or created a record, the IPv6 one
only attaches to a record that already holds it, so a dual-stack camera
is one record rather than one per family flipping with whichever
family spoke last. A camera heard only over IPv6 still gets its record.
Pinned by `test_dual_stack_onvif_is_one_record`.

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
| `device_class` | `camera` / `camera-vendor` / `not-camera` / unknown | `camera`: the device named its own class (ONVIF NVT, `DigitalSecurityCamera:1`, `axis-video` / `cctv`, a camera setup SSID). `camera-vendor`: only an OUI block or a SERVER token names a camera maker, or (#155) a mixed-vendor block served an RTSP SDP. `not-camera` (#155): a mixed-vendor block in a router role. RTSP alone sets no class. |
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
- **`--db`** `devices` table: the same five columns (schema v6; v7 adds
  the #155 classifier columns, below), keyed
  by MAC. Evidence is sticky only where it was keyed on that MAC: the
  setup-SSID (2) and OUI (16) bits OR across ticks, the class they imply
  and `setup_mode` only rise, and the vendor is kept while one of those
  bits stands. The LAN bits were joined by IP, so they, the class they
  alone gave, and `camera_model` are the latest tick's — a lease that
  moves to another host does not leave a camera on that host's MAC for
  good. What each rule saw stays in the `alerts` table, keyed by what it
  had. An IP-only record has no MAC to key a row on and is not written.
  v5 files migrate in place by adding the columns; see [[sqlite-schema]].

## Telling a camera from a router on a mixed-vendor block (#155)

Owner ruling 2026-10-21 on #106: Ubiquiti, TP-Link and Wyze go in the
OUI table. They sell cameras, but the same assignee's blocks are on
their routers, APs, plugs and bulbs — the UNSW IoT device list has a
TP-Link camera (`f4:f2:6d`) and a TP-Link smart plug (`50:c7:bf`), both
in one assignee's blocks — so an OUI cannot separate the product classes
inside one vendor, and the class has to come from traffic. The design
below is the issue's fact-checked one; its sources are in
`research/papers/camera-router-role.md`.

**The table.** 314 rows, every MA-L assignment the registry snapshot
lists under "TP-LINK TECHNOLOGIES CO.,LTD.", "TP-Link Systems Inc",
"TP-Link Systems Inc.", "Ubiquiti Inc" and "Wyze Labs Inc", verbatim,
flagged `mixed`. A mixed match names the vendor (`camera_vendor`) and is
a **+1 prior, nothing more**: it never sets `device_class` on its own and
never fires `CAM_SETUP_OUI` on its own. It also never matches a locally
administered address: the U/L mask the camera-vendor rows apply is not
applied to them, because a weak prior resting on 22 coinciding bits is
no prior. The registry digest in `tests/test_camera_vendor.c` covers the
new rows and does not read the host's `oui.csv`.

**The vendor name is not a camera claim.** The issue's design has a
mixed match set the vendor, and it does: `camera_vendor` reads
`TP-Link` on a TP-Link plug and `Ubiquiti` on a UniFi AP. The field
keeps its name for the JSONL and `--db` contract, but on a mixed block
it names the maker, not a camera, so it is read beside `device_class`
and `cam_evidence`: a record whose class is not `camera` /
`camera-vendor` and whose evidence holds `mixed_oui` is a vendor guess
and nothing more. The Devices detail prints that case as
`Vendor   TP-Link (mixed-vendor block; not a camera claim)` instead of
the `Camera   vendor` line, so the presentation does not recreate the
"every UniFi AP is a camera" reading #106 kept out of the class.

**The rule.**

| Input | Effect |
|---|---|
| a self-declaration (ONVIF NVT, `DigitalSecurityCamera:1`, a camera mDNS type, a camera setup SSID) | `camera`, as before — it still decides |
| mixed OUI | +1 (`mixed_oui`) |
| RTSP `DESCRIBE` answered `200` with `Content-Type: application/sdp` at the record's IP (RFC 2326 §10.2) | +2 (`rtsp_sdp`) — the one cited class-deciding signal |
| RTSP `DESCRIBE` answered with no SDP body seen | +1 (`rtsp_server`), shown only |
| DNS-SD `_rtsp` advertised for the record's IP | +1 (`mdns_rtsp`), shown only |
| mixed OUI with score >= 3 **including** `rtsp_sdp` | `camera-vendor` |
| DHCP server: a BOOTREPLY (op 2) sent from UDP 67, or the address named in an option 54 Server Identifier (RFC 2131 §4.1, RFC 2132 §9.7) | veto `dhcp_server` |
| Router Advertisement with Router Lifetime > 0 (RFC 4861 §4.2), keyed on the SLLA option's MAC or else the source address | veto `sends_ra`, labelled "sends RAs" |
| DNS responses from UDP 53 to >= 2 distinct LAN clients | veto `dns_responder` |
| a veto on a mixed-vendor record with no camera evidence | `not-camera` |
| camera evidence (a self-declaration, or the scored rule) **and** a veto | **conflict**: `cam_conflict` 1, shown as `CONFL!` in the list and a `CONFLICT` line in the detail. A scored-only record stays unclassified; a self-declared one keeps `camera`. Never resolved silently. |

The two weaker signals cannot decide: the rule requires `rtsp_sdp`, and
the prior plus `rtsp_sdp` already reaches 3 — so the score floor
(`CAM_CLASS_MIN_SCORE`) is implied by the two required bits and never
binds on its own; it is a stated floor kept against a weight change,
not a tunable gate. A veto on a record with no
mixed OUI is listed and decides nothing — only the mixed block made the
class an open question. Every IP-keyed evidence and veto row (RTSP, mDNS, the
DHCP and DNS roles, an RA without SLLA) is held to the join's own
key rule (fresh within `camera.join_fresh_secs`, one record at the IP);
an RA carrying a Source Link-Layer Address option is keyed on that MAC.

**Where the vetoes come from.** `src/lan_role.c` keeps one row per LAN
address seen in a DHCP-server or DNS-responder role (32 rows,
`STAB_OLDEST`, counted as `evict_lan_role`). `dhcp_snoop()` now takes the
datagram's IP source and UDP source port so a BOOTREPLY can be tied to
the host that sent it; option 54 is taken from either side, because a
client's REQUEST naming the server that offered is, on a switched port,
often all sloth sees of that server. The RA rows are `ndp_snoop.c`'s,
unchanged. A DNS answer counts only when both ends are LAN addresses
(RFC 1918, RFC 6598, RFC 3927; RFC 4193, RFC 4291 link-local) and the
source is not the destination.

**DHCP options 55 and 60** (Parameter Request List, Vendor Class
Identifier; RFC 2132 §9.8, §9.13) are kept from the client's own
BOOTREQUESTs and shown on the Devices detail and in JSONL as
`dhcp_prl` / `dhcp_vci`. They are evidence to read, not inputs: no table
maps them to a class, because no licence-clean source cites one per row,
and sloth never sends observed values to Fingerbank or any other lookup
service.

**Dropped by the fact-check, and not built.** An RTP-source signal (an
RTP v2 header test matches about a quarter of arbitrary UDP, and WebRTC
and VoIP genuinely send RTP); an uplink-ratio score (no citable basis
for a threshold — sloth also keeps no per-device byte counters for hosts
other than itself, so there is nothing to display either); and an "acts
as an AP" veto, which would need a BSSID-to-LAN-MAC join that sloth
forbids (above). The issue says the uplink ratio is "displayed only,
never scored" in its design and "stays a +1 corroborator flagged as
uncited" in its Must-not list; the two disagree, and with no
per-device byte counters this build does neither — uplink is neither
scored nor displayed, pending the owner's confirmation on #155.

**Nothing is solicited.** No RTSP OPTIONS or DESCRIBE, no ONVIF probe,
no SSDP M-SEARCH, no mDNS query, no DHCP request, no scan of 554, 2020
or 7447, no monitor-mode switch or retune: every input is traffic
already on the segment (MISSION §2.1). No RTSP credential,
`Authorization` value or URL userinfo enters an evidence row — the RTSP
lines carry the port, the path and counts (`src/cleartext_creds.h`).

**What a switched LAN shows, honestly.** On an ordinary switch port
sloth sees broadcast and multicast and its own exchanges, not other
hosts' unicast. A DHCP reply is broadcast only when the client asks for
it, a DNS answer and an RTSP session are unicast, and a camera's cloud
uplink never crosses the sensor's port. So on a switched LAN most
mixed-vendor devices will read unclassified: a self-declaration (ONVIF
Hello, SSDP NOTIFY, mDNS) or a broadcast-visible veto (an RA, a
broadcast OFFER, a client REQUEST naming its server) is what moves
them. On a mirror port or on the gateway itself the unicast signals
appear and the rule has its inputs.

### Classifier fields

| Field | Values |
|---|---|
| `device_class` | adds `not-camera` (3) |
| `cam_score` | sum of the evidence weights |
| `cam_evidence` | `CAM_EV_*`: 1 `mixed_oui`, 2 `rtsp_sdp`, 4 `rtsp_server`, 8 `mdns_rtsp` |
| `cam_vetoes` | `CAM_VETO_*`: 1 `dhcp_server`, 2 `sends_ra`, 4 `dns_responder` |
| `cam_conflict` | 1 when camera evidence and a veto both stand |
| `dhcp_prl` / `dhcp_vci` | the client's options 55 / 60, display-only |

JSONL carries the masks as comma-joined slugs (`"cam_evidence":
"mixed_oui,rtsp_sdp"`). `--db` schema v7 adds the six columns, with a
v6 -> v7 migration in the same change; `not-camera` never overrides a
class the row's MAC-keyed beacon bits imply, and such a meeting is
stored as `cam_conflict` 1. See [[sqlite-schema]].

## Limits

- **A camera on the LAN with no camera announcement is invisible here.**
  The join can only mark what a rule could fire on.
- **IP equality, bounded by recency, is the whole LAN key.** A lease
  that moves to another host inside `camera.join_fresh_secs` moves the
  evidence with it for the rest of that window; after it, the old rows
  are history on the trail and mark nothing. The source tables never
  age a row out on their own — only a full table evicts — so it is the
  window, not the table, that ends the join.
- **No interface on the LAN rows.** Two segments using one subnet make
  the address ambiguous, and the join refuses it rather than guessing.
- **No fingerprinting by traffic shape.** Bitrate, RTP payload type,
  uplink ratio and cloud SNI are not used for the class; the one
  behavioural signal that decides is an RTSP SDP answer (#155).
  `SURV_CLOUD_SNI` (#105) is a separate rule about the destination, not
  the device.
- **`not-camera` is not evidence of absence.** The router-role vetoes
  rest on frames any host on the segment can forge: one broadcast
  DHCPREQUEST naming a camera's IP in option 54, a BOOTREPLY sent from
  UDP 67 with that source, or an RA whose SLLA option is the camera's
  MAC. That makes a mixed-vendor record with no camera evidence read
  `not-camera`, and turns a scored `camera-vendor` record into a
  conflict with the class left unknown, for the whole
  `camera.join_fresh_secs` window — enough to hide a TP-Link or Wyze
  camera from this view. Option 54 from a client REQUEST and a
  BOOTREPLY from UDP 67 weigh the same today. Read `not-camera` as "a
  router role was claimed at this address", the same caution the mDNS
  and A-record paragraph above applies to camera claims.
- **Mixed-vendor blocks mostly read unclassified on a switched port**
  (#155, above): the deciding signal and two of the three vetoes are
  unicast.

## Related pages

- [[alerts]] — the rule rows and the exposure-list reasoning
- [[jsonl-schema]] — the `device` record fields
- [[sqlite-schema]] — schema v7 and the v5 -> v6 -> v7 migrations
- [[views-catalog]] — the `[g]` Devices view
- [[research-corpus]] — how the cited documents are indexed
- [[threat-model]] — the passive-only boundary
