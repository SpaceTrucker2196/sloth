# ROADMAP.md — where sloth is going

This file is the **planning ledger**: open, not-yet-owned work, grouped
by theme and prioritised. It sits between the two documents that bound
it:

- [`MISSION.md`](MISSION.md) §4 is the *direction* — slow-moving gravity,
  and the non-negotiable scope rules (§2). Nothing here overrides those.
  Every item below is passive-only: no injection, no active scan, no
  cracking, no control surface.
- [`PROGRESS.md`](PROGRESS.md) is the *rear-view mirror* — what landed,
  what's in flight. When an item here is picked up it becomes an
  "In progress" block there; when it lands it moves to "Recently landed".

GitHub issues are the canonical tracker; this file is the synthesis that
keeps them from arriving as unrelated one-offs. Each item cites its issue
where one exists.

Status legend: **▲ next** (clear, scoped, high value) · **◆ planned**
(agreed direction, needs design) · **◇ exploratory** (worth doing, shape
still open).

---

## A. Open GitHub issues, grouped

### A1. Data-integrity bug (fix before feature work)

- **✅ LANDED (2026-07-04, `83f2897`)** — **Packet/telemetry
  de-duplication** — `#20`. Fixed via a monotonic once-only high-water
  mark; each captured frame now emits exactly once. Original analysis
  follows. The JSONL emit loop
  (`src/jsonl.c` `jsonl_emit_all`, lines ~1057-1076) re-emits the entire
  snapshot state every refresh cycle, not just newly-observed records.
  Measured at ~90.8% duplicate packet records (42,304 emitted /
  ~3,902 unique). This is **not** packets-only: every snapshot emitter it
  calls — `jsonl_emit_beacons`, `_deauths`, `_probe_clients`,
  `_pnl_clients`, `_seqnum_*`, `_assocs`, `_eapol_events`, `_wifi_aps`,
  `_wifi_stas`, `_mdns_services` — has the same shape and almost
  certainly the same defect. Fix: track a per-record "last emitted"
  watermark (monotonic seq or last-seen cursor per ring) so each record
  is serialised exactly once. Downstream SIEM consumers currently
  count one event as many. This corrupts every drift/baseline feature
  below, so it is the true blocker.

### A2. Multi-radio & channel coverage

- **✅ LANDED (2026-07-04)** — **Multi-radio Wi-Fi sensor merge** —
  `#21`. Shipped as `src/wifi_merge.c`: an entity-keyed merge table
  (AP BSSID / STA MAC) that folds observations from >1 monitor adapter
  into one world model, tagging each with a source sensor id and
  retaining `seen_by` / `sensor_mask` / `best_rssi` / `best_sensor`
  observer metadata. Additive `wifi_merged` JSONL record; built on the
  #28 sensor registry. Merge/dedup/error-handling covered in
  `tests/test_wifi_merge.c`; live N-radio concurrent capture is
  hardware-gated (needs two monitor adapters + `CAP_NET_ADMIN`).
- **✅ LANDED (2026-07-04)** — **Adaptive passive channel scheduler** —
  `#22`. Shipped as `src/wifi_chanhop.c` + a `set_channel` platform op
  (nl80211), driven by `--hop` (opt-in, off by default). Required the
  first amendment to MISSION §2 (narrow carve-out for retuning sloth's
  own monitor interface). nl80211 path needs on-hardware Linux
  verification. Original note follows for context: sloth previously did
  **not** control the radio at all — it passively reads whatever channel
  the card is externally tuned to (the Channel view literally instructs
  the operator to "hop the adapter to other channels"). A conservative,
  explainable dwell-weighting scheduler (busy channels get more dwell,
  quiet channels keep a guaranteed minimum revisit, per-channel dwell
  cap) would dramatically raise capture yield from a single radio. This
  is the single biggest passive-coverage win available.

### A3. Synthesis / assessment layer

- **◆ RF baseline + drift detection** — `#23`. Learn "normal" for a
  location/session (BSSID inventory, SSID↔BSSID map, OUI mix, channel
  histogram, RSN/AKM/MFP posture, beacon behaviour, probe volume,
  deauth rate, RSSI ranges) and flag meaningful drift. Additive, passive,
  reads existing state. **Depends on #20** being fixed first.
- **◆ Wireless assessment / compliance-evidence view** — `#24`. Translate
  observed facts into conservative, evidence-anchored findings (MFP
  optional, legacy cipher present, WPA2/WPA3 transition-mode exposure,
  duplicate-SSID-different-vendor, hidden-SSID revealed, PMKID/EAPOL
  captured, excessive/sensitive PNL). Not a policy engine — each finding
  traces to a specific observation.
- **◆ Site snapshot export/import** — `#27`. `--snapshot-out FILE` writes
  a normalised passive summary on exit; `--baseline-in FILE` compares
  current observations against a prior visit. Normalised observations,
  not raw pcap. Pairs with #23.

### A4. Ergonomics

- **▲ First-launch prefers wireless monitor** — `#25`. When a
  monitor-mode interface exists at startup, default the visible view to
  the relevant Wi-Fi view/dashboard and start non-monitor interfaces
  (loopback, docker, VPN, virtual) present-but-collapsed. Capture
  behaviour unchanged; purely UI defaulting. Small, high-ergonomics win.

### A5. Architecture / long-horizon

- **◇ Passive sensor abstraction layer** — `#28`. A small, boring typed
  "sensor" model (type, state, name, interface, observed count,
  first/last-seen) so non-802.11 sources normalise into `sloth_state_t`
  and JSONL the same way Wi-Fi does — **without** becoming a plugin ABI
  or control surface. Enables #21 and everything in #26.
- **✅ LANDED (2026-07-04)** — **Non-IP RF coverage roadmap** — `#26`.
  Written up as `docs/wiki/non-ip-sensors.md`: the passive filter, the
  seven questions every family must answer, and per-family sketches for
  BLE, Zigbee, SDR metadata, GPS, ADS-B, Meshtastic, and CAN — sequenced
  behind the #28 sensor abstraction. Original note follows. Parent
  roadmap for future
  passive sensor families: BLE advertisements, Zigbee/802.15.4, SDR
  metadata, GPS context, ADS-B, Meshtastic/LoRa, CAN bus. Each new family
  must answer: what's observable passively, what hardware, what enters
  state, what view, what JSONL record, what's explicitly out of scope,
  how it's tested without live hardware. Sequenced **after** #28 lands.

---

## B. Wi-Fi SIGINT deep-dive: gaps to best-in-class

Per MISSION §4(4), 802.11 is where sloth's unique value lives. This is a
gap analysis of the passive 802.11 surface as it stands, and the work
that would make sloth the strongest passive Wi-Fi spectrum-analysis tool
available. **All items are strictly passive** — read-only monitor
capture, no injection, no active probing, no online cracking.

### B0. What sloth already does well (the baseline)

So the gaps below are read against a real feature set, current 802.11
capability includes: monitor-mode beacon/probe/deauth capture; full RSN
parse (ciphers, AKM incl. SAE/OWE/FT/Suite-B, MFP/RSN-caps); WPA1 vendor
IE; HT/VHT presence + HE/EHT/Multi-Link **PHY-tier classification**
(so Wi-Fi 4/5/6/7 is *labelled*); WPS state incl. zero-UUID; 802.11k
neighbour reports + RNR (6 GHz-capable neighbour extraction); vendor-IE
fingerprint hash; PNL aggregation + OS fingerprint; EAPOL/PMKID/4-way
capture with hashcat-22000 + replayable pcap; sequence-number MAC-
randomisation correlation; association inventory with graded evidence;
KARMA / evil-twin / evil-twin-proximity / Pineapple detection; deauth/
disassoc flood + probe flood alerts. `freq_to_channel` already maps
2.4/5/6 GHz. That is a strong base — the gaps are about **breadth of
frame/IE coverage, PHY telemetry, and attack detection**, not starting
from zero.

### B1. Frame-type coverage holes  ▲ highest-leverage

The monitor dispatch (`src/capture/probe.c` `on_probe_frame`) decodes
only a subset of 802.11. Confirmed **not** parsed today:

- **▲ Authentication frames (subtype 11).** The SAE (WPA3) and OWE
  exchanges, plus shared-key/open auth, are invisible. Passive value:
  auth-flood detection, SAE anti-clogging / downgrade observation,
  detecting auth from MACs never seen probing. Also the front half of
  every association is currently unobserved.
- **▲ Association/Reassociation *requests* (subtypes 0/2).** Only the
  *responses* are parsed. The request carries the client's supported
  rates, HT/VHT/HE caps, requested SSID, RSN choice, and power-cap — a
  rich client fingerprint and the "what did the client ask for vs what
  the AP granted" delta.
- **▲ Action frames (subtype 13).** Entirely unhandled. This is a large
  passive surface: 802.11v BSS-Transition-Management (roaming steering,
  and BTM-based deauth-equivalent abuse), Radio Measurement (802.11k)
  requests/reports, FT action (fast roaming), and spoofed/malformed
  action frames used by modern WIDS-evasion tooling.
- **◆ Control frames (type 1: RTS/CTS/ACK/BlockAck).** Not decoded.
  These are what you need for **airtime/channel-utilisation** accounting,
  RTS/CTS-flood (airtime-DoS) detection, and hidden-node inference. Even
  just counting them by type per channel yields a real utilisation
  metric.
- **◆ Data-frame telemetry beyond EAPOL.** Data frames are inspected
  only to pull EAPOL-Key. Retry-bit rate, QoS TID distribution, frame
  size histograms, and per-BSSID data volume are all cheap passive
  signals (interference, jamming, exfil-shaped flows) left on the floor.

### B2. Information-element depth

- **▲ QBSS Load IE (tag 11).** Not parsed. This is the AP *self-reported*
  station count + channel utilisation + admission capacity — a free,
  no-math congestion/occupancy metric. Cheapest high-value IE to add.
- **◆ HT/VHT/HE/EHT operation + capability decode.** Today these are
  presence flags feeding PHY-tier labelling. Decoding the operation
  elements yields channel width (20/40/80/160/320 MHz), primary/secondary
  channel, and the actual spatial-stream/MCS ceiling — needed for a real
  spectrum-occupancy picture and for spotting mis-width / overlap.
- **◆ Country / operating-class / power-constraint / TPC / DFS / CSA.**
  Not parsed. Enables regulatory-domain cross-checks (AP advertising a
  country/channel it shouldn't), DFS/radar-event observation, and
  Channel-Switch-Announcement (tag 37) tracking — CSA is both a normal
  roaming signal and a known passive-attack lever.
- **▲ 6 GHz channel derivation on the monitor path.** Two coupled gaps
  make 6 GHz effectively invisible to the SIGINT engine even though the
  neighbour-report path already handles 6 GHz: (a) the radiotap parser's
  freq→channel map stops at 5885 MHz (`src/capture/probe.c`), so 6 GHz
  monitor frames get channel 0 — the `freq_to_channel` in
  `src/platform/linux_wifi.c` already maps 5955-7115 and should be shared;
  and (b) beacon channel is read only from the DS Param IE (tag 3), which
  many 6 GHz/HE APs omit, so decoding the HE Operation element (B2 above)
  is the durable fix. Cheap, concrete, and unblocks all 6E work.
- **◆ Extended Capabilities, RM Enabled Capabilities, Mesh (11s), FT
  (MDE/FTE).** Round out roaming (11r/k/v) telemetry and mesh visibility.
- **◇ Multi-Link Element full decode (Wi-Fi 7 / MLO).** Today the
  Multi-Link IE only flips the "Wi-Fi 7" tier. Decoding it gives the MLD
  MAC ↔ per-link (affiliated) MAC mapping — the modern analogue of the
  seqnum correlation trick, and essential for tracking Wi-Fi 7 devices
  that present different MACs per link.

### B3. PHY / signal-layer analysis

- **◆ Channel-utilisation / airtime view.** Combine B1 control-frame
  counts + B2 QBSS Load + per-channel frame rate into a live occupancy
  panel. This is the "spectrum analyser" the tool is currently missing —
  the thing that turns "here are APs" into "here is how busy each channel
  actually is."
- **◆ Retry-rate / FCS-error tracking.** Radiotap already exposes FCS and
  flags. Rising retries / FCS errors on a channel is the passive
  signature of interference, a hidden node, or a jammer. No new capture
  needed — just count what's already arriving.
- **◇ Per-BSSID / per-STA RSSI history + movement.** evil-twin-proximity
  already uses RSSI; generalise it to a signal-history sparkline per
  device with an approaching/leaving indicator. Coarse presence/ranging,
  no triangulation claims.
- **◇ Fuller radiotap decode.** The monitor parser reads only RSSI +
  (2.4/5 GHz) channel today. Rate/MCS (radiotap bit 19), VHT/HE/EHT
  radiotap, bandwidth, and antenna fields are stepped over — decoding
  them feeds the airtime/utilisation view and MIMO/PHY-rate telemetry.

### B3b. Parser-consistency debt

- **◆ Unify the two Wi-Fi paths.** sloth has *two* Wi-Fi code paths with
  very different depth: the monitor-mode engine (`src/capture/probe.c` +
  `beacon_snoop.c`) with the rich RSN/WPS/RNR/11k/vendor parser, and the
  managed-mode nl80211 scan path (`src/platform/linux_wifi.c`) whose IE
  parser only yields SSID + RSN/WPA/WEP booleans. So the exact same AP
  reports far less detail depending on which interface mode saw it. The
  beacon IE parser should be the single source of truth both paths call,
  so capability depth doesn't depend on interface mode.

### B4. Attack / anomaly detection breadth

Deauth-flood, probe-flood, evil-twin, KARMA, Pineapple exist. Gaps:

- **▲ Beacon-flood / rogue-beacon (mdk3/mdk4 signature).** Sudden bloom
  of many distinct SSIDs/BSSIDs from one radio neighbourhood, or beacons
  whose sequence numbers don't advance monotonically for a known BSSID
  (spoofed). High-signal, purely passive.
- **◆ PMF/WPA3 downgrade + transition-mode exposure.** Flag APs
  advertising WPA2/WPA3 mixed mode, MFP optional-not-required, or an OWE
  transition BSS — the practical downgrade surfaces. Overlaps #24's
  assessment view.
- **◆ Authentication/association flood** (needs B1 auth+assoc-req).
- **◆ CTS/RTS airtime-DoS** (needs B1 control frames).
- **◇ Karma/known-beacon responder heuristics v2** and PMKID-harvest
  tool fingerprints (AP or client behaviour that matches known passive-
  harvest tooling), staying observation-only.

### B5. Coverage & correlation (ties back to §A)

- The channel scheduler (**#22**) and multi-radio merge (**#21**) are the
  force-multipliers for everything in B1–B4: more of the spectrum seen,
  more of the time, without transmitting. They belong to both sections.
- Baseline/drift (**#23**) is what converts the richer per-frame/IE data
  above into "what *changed*" — the question operators actually ask.

### Suggested sequencing

1. **#20** duplicate-emission fix (unblocks all baseline/export work).
2. **B2 QBSS Load** + **B1 auth / assoc-req / action** parsing
   (cheap, large detection breadth per MISSION §4(1) "coverage first").
3. **#22 channel scheduler** (biggest single passive-coverage gain).
4. **B3 channel-utilisation view** + **#24 assessment view**
   (turn the new data into operator answers).
5. **#21 multi-radio** → **#28 sensor abstraction** → **#23 baseline**
   → **#26 non-IP families** (the architectural long haul).
