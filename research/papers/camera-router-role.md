---
source_url: https://www.rfc-editor.org/rfc/rfc2131
retrieved: 2026-10-21
topics: [camera, router, device-classification, oui, mixed-vendor, dhcp, router-advertisement, dns, rtsp, sdp, iot-fingerprinting]
alert_kinds: [ALERT_TYPE_CAM_SETUP_OUI]
citation: RFC 2131 (DHCP) §2, §4.1; RFC 2132 (DHCP Options) §3.5, §9.7, §9.8, §9.13; RFC 4861 (IPv6 Neighbor Discovery) §4.2, §6.2.1; RFC 1035 §4.1.1; RFC 2326 §10.2 and RFC 7826 §13.2 (RTSP DESCRIBE); RFC 3550 (RTP); UNSW IoT Analytics List_Of_Devices.txt; Miettinen et al., IoT Sentinel, ICDCS 2017 (arXiv:1611.04880); Sivanathan et al., IEEE TMC 2019 (DOI 10.1109/TMC.2018.2866249); Meidan et al., arXiv:1709.04647; Satori (github.com/xnih/satori); TP-Link FAQ 2680
---
# Telling a camera from a router by passive traffic (#155)

What the device classifier at the end of `src/camera_join.c` decides
from, for the mixed-vendor OUI rows in `src/camera_vendor.c` (Ubiquiti,
TP-Link, Wyze; owner ruling 2026-10-21 on #106). Research and
fact-check were done on #155 on 2026-10-21; this records the verified
design with the fact-checker's corrections applied, including what was
dropped. Nothing here is an alert of its own: the output is the device
record's class, score, evidence and vetoes, and the one rule it touches
is `ALERT_TYPE_CAM_SETUP_OUI`, which a mixed-vendor block fires only
beside a camera setup SSID.

## 1. Why an OUI cannot decide the class here

- **UNSW IoT Analytics, `List_Of_Devices.txt`** (fetched 2026-10-20; the
  entries and MACs match verbatim): a TP-Link Day Night Cloud camera
  (`f4:f2:6d:93:51:f1`), a TP-Link smart plug (`50:c7:bf:00:56:39`) and a
  TP-Link router in the same lab. Both of the first two are blocks the
  IEEE registry assigns to "TP-LINK TECHNOLOGIES CO.,LTD.". One assignee,
  three product classes: the block names the maker, never the box.
  `tests/test_camera_vendor.c` and `tests/test_camera_class.c` use those
  two MACs.
- **Sivanathan et al.**, "Classifying IoT Devices in Smart Environments
  Using Network Traffic Characteristics", IEEE TMC 2019, DOI
  10.1109/TMC.2018.2866249 (abstract via the Semantic Scholar API,
  verified): 28 IoT devices including cameras, plugs and lights,
  instrumented for six months, characterised by activity cycles, port
  numbers and signalling: traffic, not the vendor, is what the
  classification rests on.
- **Miettinen et al.**, "IoT Sentinel", ICDCS 2017, arXiv:1611.04880,
  §V and Table III (PDF text): a fixed fingerprint of the first 12 unique
  packet vectors x 23 features (276 dimensions); over 27 device types the
  global correct-identification ratio was 0.815. A learned fingerprint is not
  what sloth ships — there is no per-row source for its decisions — but
  it is the measured reason not to expect a vendor to be one class.
- **Meidan et al.**, "Detection of Unauthorized IoT Devices Using Machine
  Learning Techniques", arXiv:1709.04647 (abstract verified): Random
  Forest over TCP-session features, 17 devices of 9 types. Same
  conclusion, same reason it is not shipped (ProfilIoT, ACM SAC 2017, DOI
  10.1145/3019612.3019878, was not opened).

## 2. The one class-deciding behaviour: an RTSP media description

RFC 2326 §10.2 (DESCRIBE) and RFC 7826 §13.2: the reply to DESCRIBE
carries the presentation description, and its Content-Type for a
session description is `application/sdp`. A host answering `200` with
that body is serving a media stream description — what a camera or an
NVR does, and not what a router does. `src/rtsp_snoop.c` already records
it per stream row (`sdp`), with no credential copied (the
`cleartext_creds.h` guardrail). Weight +2 (`rtsp_sdp`). A mixed-vendor
record reads `camera-vendor` only at score >= 3 with `rtsp_sdp` part of
it, i.e. the +1 prior and the SDP answer together.

TP-Link FAQ 2680 (fetched, quotes match): the Tapo RTSP port is 554 with
paths `/stream1` (high quality) and `/stream2` (standard), and
`/stream6` / `/stream7` for the telephoto lens on dual-lens models — the
exchange the rule reads, on the port `try_rtsp()` already dispatches.
Interleaved binary data on the RTSP connection is framed `$` (0x24), a
1-byte channel and a 2-byte length (RFC 2326, RFC 7826); RTP itself is
RFC 3550. Neither is read for the class (§5).

Weaker signals are shown and scored +1 but cannot decide: a DESCRIBE
answered with no SDP body seen (`rtsp_server`) and a DNS-SD `_rtsp`
advertisement (`mdns_rtsp`, IANA `rtsp`, a protocol rather than a
class — `research/papers/camera-vendor-identity.md` §1).

## 3. Router-role vetoes

- **DHCP server.** RFC 2131 §4.1: "DHCP messages from a client to a
  server are sent to the 'DHCP server' port (67), and DHCP messages from
  a server to a client are sent to the 'DHCP client' port (68)"; a
  BOOTREPLY is `op` 2 (§2). RFC 2132 §9.7: option 54, Server Identifier,
  names the server, and a client's DHCPREQUEST in SELECTING state carries
  it to name the server whose offer it took (RFC 2131 §4.3.2). Option 3
  (§3.5) lists the routers. So `dhcp_snoop()` now takes the datagram's IP
  source and UDP source port: a BOOTREPLY from port 67 marks its source,
  and option 54 from either side marks the address it names. A relay
  agent also sends BOOTREPLYs from 67 (§4.1); it is a router too.
- **Router Advertisement sender.** RFC 4861 §4.2: Router Lifetime is
  "the lifetime associated with the default router in units of seconds";
  "a Lifetime of 0 indicates that the router is not a default router and
  SHOULD NOT appear on the default router list". So only lifetime > 0
  vetoes, and the label is "sends RAs". §6.2.1: MaxRtrAdvInterval is at
  most 1800 s, inside the join window the veto is held to. The SLLA
  option (§4.6.1) keys the RA to a MAC without an IP lease.
- **DNS responder to >= 2 LAN clients.** RFC 1035 §4.1.1: QR is the top
  bit of the third header octet, 1 for a response. A LAN host answering
  more than one other LAN host from port 53 is running a resolver or a
  forwarder; a camera does not. The threshold is "more than one" so a
  single answer — a host's own reply to the sensor, a stray — does not
  count as a service.

A veto on a mixed-vendor record with no camera evidence makes it
`not-camera`; camera evidence that meets a veto is a conflict, shown and
never resolved silently.

## 4. Display-only: DHCP options 55 and 60

RFC 2132 §9.8 (Parameter Request List) and §9.13 (Vendor Class
Identifier) are what a client asks for and says it is, and they differ
by OS and firmware. **Satori** (GPL-2.0, `github.com/xnih/satori`,
README verified) fingerprints DHCP among other protocols, but its tables
are not licence-clean for an embedded table here and do not carry a
per-row source, and no other licence-clean, per-row-cited mapping from
an option list to a device class was found (Fingerbank was not fetched,
and is never queried with observed data). So sloth stores and shows both
options and scores neither.

## 5. Dropped by the fact-check

- **An RTP-source signal.** An RTP v2 header test (version bits 2, a
  payload type in range) matches roughly a quarter of arbitrary UDP
  payloads, and WebRTC and VoIP clients genuinely send RTP. It would
  score phones and laptops as cameras.
- **An uplink-ratio threshold.** Cameras upload more than they download,
  but no source gives a threshold that separates them; an uncited
  number would decide a class on a guess. It is neither scored nor, since
  sloth keeps no per-device byte counters for hosts other than itself,
  displayed.
- **An "acts as an AP" veto.** It would need a BSSID joined to a LAN MAC,
  which the device join forbids (nothing on the air ties the two;
  `docs/wiki/camera-detection.md`).

## 6. Visibility, honestly

On a switched port the sensor sees broadcast and multicast and its own
exchanges, not other hosts' unicast. A DHCP reply is broadcast only when
the client sets the BROADCAST bit (RFC 2131 §4.1), a DNS answer and an
RTSP session are unicast, and a camera's cloud uplink never reaches the
sensor's port. So on a switched LAN most mixed-vendor devices read
unclassified unless a self-declaration (ONVIF Hello, SSDP NOTIFY, mDNS)
or a broadcast-visible veto (an RA, a broadcast OFFER, a client REQUEST
naming its server) appears. On a mirror port or on the gateway the
unicast signals are visible.

## 7. What is never done to get any of this

No RTSP OPTIONS or DESCRIBE, ONVIF probe, SSDP M-SEARCH, mDNS query,
DHCP request or scan of 554 / 2020 / 7447; no monitor-mode switch or
retune; no web lookup of an OUI or fingerprint (MISSION.md §2.1).

## Related

- `research/papers/camera-vendor-identity.md` — the OUI table and its
  registry snapshot.
- `research/rfc/2326-7826-rtsp.md` — the RTSP exchange `rtsp_snoop.c`
  reads.
- `docs/wiki/camera-detection.md` — the rule as built.
