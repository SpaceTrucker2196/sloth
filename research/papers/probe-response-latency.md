---
source_url: https://cs.uwaterloo.ca/~brecht/courses/856/readings/handoff/empirical-analysis-of-handoff.pdf
retrieved: 2026-11-12
topics: [karma, probe-response, latency, timing, rogue-ap, hostapd-mana, airbase-ng, radiotap, tsft, data-point]
citation: Mishra, Shin & Arbaugh, "An Empirical Analysis of the IEEE 802.11 MAC Layer Handoff Process", ACM SIGCOMM CCR 33(2), 2003, §3.2, §5.1-5.3; hostapd-mana src/ap/beacon.c handle_probe_req() at d8d9e212; aircrack-ng src/airbase-ng/airbase-ng.c at 7e2256f3; Han, Sheng, Tan, Li & Lu, "A Timing-Based Scheme for Rogue AP Detection", IEEE TPDS 22(11), 2011, §3-4; radiotap.org TSFT field definition
---
# Probe-response latency: no source gives a lure a direction

The basis for `src/probe_latency.c` (#187 S3), and the reason it is a
**data point and not a detector**. #187 proposed that a KARMA lure's
probe-response latency — the time from a station's Probe Request to the
Probe Response a BSSID addresses back to it — differs measurably from a
real AP's, and suggested a median under 2 ms as a confirmer. This
document records what was read first-hand to test that, and what it
does and does not support. The short answer: a legitimate-AP baseline
exists, a lure measurement does not, and the tools' own source code
argues against a clean direction.

## What a legitimate AP's latency looks like (2003 hardware)

Mishra, Shin & Arbaugh, ACM SIGCOMM CCR 33(2), 2003, read 2026-11-12
from the PDF.

- **Method (§3.2).** Prism 2.5 NICs in monitor mode, one per channel,
  on Linux laptops; captures from two machines merged by timestamp with
  NTP over a point-to-point link, "a clock accuracy of 80 µs or better
  between the machines". Three networks (umd, cswireless, nist), three
  client NICs (Cisco 340, Lucent, ZoomAir).
- **Definition (§5.3).** "the probe response time from ap_i to be the
  time between the probe request message sent by C on L and the
  corresponding probe response sent by the AP ap_i" — the quantity
  sloth measures.
- **Figures (§5.3).** On umd, "all probe responses are received by a
  station within (approx.) 11ms … in 90% of the cases all probe
  responses are received within (approx.) 6.5ms". On nist "all
  responses are received within 9ms", on cswireless "around 15ms".
  These are figures for the **last** response on a channel, not per AP.
- **The station's side (§5.1-5.2).** The paper restates the standard's
  active scan: probe request with "broadcast destination, desired SSID,
  and broadcast BSSID", a ProbeTimer, MinChannelTime if the medium stays
  idle, MaxChannelTime otherwise. Measured probe-wait: Cisco ~17 ms
  (Min) and ~38 ms (Max); ZoomAir ~63 ms and ~73 ms.

What this supports: a response well inside 15 ms is ordinary for a real
AP, and a station is not listening much past ~73 ms. It is the basis
for `PLAT_PAIR_MAX_US` (200 ms, an engineering bound well past the
longest probe-wait above), **not** for any threshold. It is also 2003
hardware answering wildcard probes; it says nothing about a lure, and
nothing about modern APs, many of which answer probes in firmware.

## What the lure tools actually do

**hostapd-mana** (`src/ap/beacon.c`, `handle_probe_req()`, read at
GitHub HEAD `d8d9e2127e88957302ccf4dd89d90842b8251fc7`, 2026-11-12):

- With `enable_mana`, a directed probe for any SSID sets
  `params.mana_ssid = elems.ssid` — the requested name — and calls
  `hostapd_send_probe_resp_from_params()`, which builds the frame with
  `hostapd_gen_probe_resp(hapd, params)` and sends it with
  `hostapd_drv_send_mlme()`. Without mana the same function runs with
  `mana_ssid` unset, so the configured SSID is used. **It is the same
  userspace path, through the same driver call, that stock hostapd uses
  to answer probes on any driver without probe-response offload.** What
  MANA adds in front of it in this file is a call to
  `mana_probe_process_request()` (in MANA's own `mana/probe.c`, not
  read: the raw path at that commit did not resolve) and debug logging;
  nothing in `beacon.c` is measured or claimed to be measurable.
- For a **wildcard** probe, when `mana_probe_process_request()` sets
  `iterate`, it walks the station's remembered SSIDs
  (`mana_probe_iter_hash()`, "MANA: Generating broadcast response for
  SSID") and sends one response per name, back to back. Only the first
  of those is a latency; the rest are serialisation.
- `hostapd_send_probe_resp_from_params()` sets the no-ack policy when
  the request was a wildcard sent to the broadcast address ("to avoid
  excessive retries"), so those answers are never retransmitted.
- The file also contains `hostapd_probe_resp_offloads()`, which applies
  only when the driver advertises `WPA_DRIVER_FLAGS_PROBE_RESP_OFFLOAD`.
  A firmware that answers probes itself answers for the configured
  SSID; answering for *any* SSID requires the userspace path. So a lure
  is always on the userspace path, and a real AP may be on either.

**airbase-ng** (`src/airbase-ng/airbase-ng.c`, read at GitHub HEAD
`7e2256f38f3590af4c19a6ae14ed79bab02242e6`, 2026-11-12):

- A Probe Request read from the monitor interface is rewritten in place
  ("transform into probe response", `packet[0] = 0x50`) and injected
  with `my_send_packet()` → `send_packet(…, kRewriteSequenceNumber)`.
  Userspace, through monitor-mode injection.
- A directed probe gets one `my_send_packet()`; a **broadcast** probe
  gets three consecutive calls with the same buffer.

What this supports: a direction only in the weak form "a lure answers
from userspace". A real AP answering from userspace (hostapd on a
mac80211 driver without offload — the common OpenWrt case) takes the
same path, so the population a threshold would have to separate a lure
from is not distinguished by the mechanism. The 2 ms figure in #187 has
no basis here, and the plausible sign of the offload difference
(firmware faster than userspace) is the opposite of "a lure answers
fast".

## The one timing-based rogue-AP scheme that was read

Han, Sheng, Tan, Li & Lu, IEEE TPDS 22(11), 2011, read 2026-11-12 from
the PDF. It times **DNS round trips** through an associated AP (§4),
relying on the extra wireless hop a relaying rogue adds. §3 states why
simple timing fails: "the rogue AP can simply forge a response to the
user, thus avoiding the time penalty of the additional wireless link".
A probe response is always generated locally — by a real AP and a lure
alike — so the asymmetry this paper measures does not exist for it. It
is cited here for that negative, not as a source for S3.

## The clock sloth uses

radiotap.org, TSFT field, read 2026-11-12: `u64 mactime`, alignment 8,
microseconds, "Value in microseconds of the MAC's 64-bit 802.11 Time
Synchronization Function timer when the first bit of the MPDU arrived at
the MAC. For received frames only." One hardware counter on the
receiving radio, so a request/response difference is free of host
jitter; it runs start-of-frame to start-of-frame, so the request's
airtime is inside the figure. Without TSFT sloth falls back to the pcap
header stamp (host receive time, nominally µs, carrying driver and USB
batching delay) and never mixes the two in one pair or one BSSID.

## What could not be read

- **IEEE 802.11-2020** MLME-SCAN.request parameters (ProbeDelay,
  MinChannelTime, MaxChannelTime) — not retrieved (paywalled); the
  procedure above is Mishra et al.'s restatement of the 1999 text. No
  clause number is asserted in sloth for them. Note the standard bounds
  the *station's* wait, not the AP's answer; nothing read sets a
  deadline on a probe response.
- **Jana & Kasera**, clock-skew rogue-AP detection from TSF timestamps
  in beacons and probe responses — seen only as a search-result summary;
  not read. It measures the AP's clock drift, not response latency.
- **Hak5 PineAP** — closed source; no timing documentation found.
  `research/tools/wifi-pineapple-mk7.md` covers its documented
  behaviour.
- No measurement study of KARMA, MANA, airbase-ng or PineAP response
  latency was found.

## Decision

Observation only. `src/probe_latency.c` measures per-BSSID latency
(count, min, p10, median, p90 over the last 32 pairs, directed and
wildcard separately) and feeds **no** verdict: no alert, no KARMA score,
no confidence. A threshold needs either a primary source giving a
direction and a magnitude, or sloth's own captures of a known lure and
known APs on the same radio — the second is the realistic route, and
the measurement exists so that it can be taken.
