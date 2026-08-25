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
still open) · **✅** landed.

> **Verified 2026-07-28** against the tree at `e7ddd7a`. Every status
> below was checked against the source, not carried forward — the
> previous revision had drifted badly enough to be misleading (it listed
> QBSS Load, auth-frame parsing, beacon-flood detection, the 6 GHz
> frequency map and per-device RSSI history as open work when all five
> had shipped). Re-verify before trusting a status older than a few
> weeks; the checks are cheap greps and are named inline.

---

## Where things stand

> **Re-verified 2026-08-24** against the tree at `f2fe12f`, as a triage
> sweep over every open issue. The line below ("no open GitHub issues")
> was true when written on 2026-07-28 and stopped being true on 08-03.
> It is the same drift this file warns about at the top, four weeks
> later — worth leaving visible rather than quietly overwriting.

~~**No open GitHub issues.**~~ **Eleven are open** (`#61`, `#63`–`#72`),
all of it section-B work now filed rather than merely listed here.
Section A — the original issue backlog — remains fully landed.

Both of the half-landed issues are now closed:

- ~~**`#59` BTM abuse**~~ — ✅ closed 2026-08-24 across four slices.
- ~~**`#60` Assoc requests**~~ — ✅ closed 2026-08-24 across five.

---

## A. Original issue backlog — ✅ complete

Kept as a record of what the sequencing above delivered, not as work.

| Issue | What | Landed |
|---|---|---|
| `#20` | Packet/telemetry de-duplication (monotonic high-water mark) | `83f2897` |
| `#21` | Multi-radio Wi-Fi sensor merge (`src/wifi_merge.c`) | 2026-07-04 |
| `#22` | Adaptive passive channel scheduler (`--hop`, MISSION §2 carve-out) | 2026-07-04 |
| `#23` | RF baseline + drift detection (`src/wifi_baseline.c`) | — |
| `#24` | Wireless assessment / compliance evidence (`src/wifi_assess.c`) | — |
| `#25` | First-launch prefers wireless monitor | — |
| `#26` | Non-IP RF coverage roadmap (`docs/wiki/non-ip-sensors.md`) | 2026-07-04 |
| `#27` | Site snapshot export/import (`src/wifi_snapshot.c`) | — |
| `#28` | Passive sensor abstraction (`src/sensors.c`) | — |

### A6. The 2026-07-28 arc — ✅ complete

A day of field-reported fixes followed by a persona-driven feature run.
Recorded here because none of it existed in the previous revision and it
closes several section-B items by side effect.

**Field reports (bugs).** `#46` `pcap_activate` positive warnings treated
as fatal, silently disabling `--iface`/`--monitor-only` scoping
(`4b1b577`). `#47` data-socket clients never received a change-cache
baseline (`f5c848d`). `#48` `WITH_NCURSES=0` did not compile, plus a CI
guard so build configurations are actually built (`a6af13d`, `e2effaa`).

**Operator experience.** `docs/personas/wifi-surveyor.md` (`6e58de0`) —
an operator persona scored against eleven executable scenarios. It is a
test fixture, not marketing: `make test` proves the parsers do what they
say, and this is the inspection step for whether what they say is what
the operator needed. It found `#51` within an hour of being written.

**Findings it drove.** `#51` evil-twin rule reporting cross-vendor range
extenders as CRIT rogue APs, fixed via 802.11k neighbour advertisement
(`52cf47a`). `#52` operator-designated networks — `--my-ssid` /
`--my-bssid` and `MY_NET_RECON` (`fc1d9d3`). `#53` presence
classification from RSSI trajectory (`c1f616c`). `#54` recurring-transit
detection (`85ae491`). `#55` known-device roster and `UNKNOWN_DEVICE`
(`c4e7467`). `#50` `--headless` / `--no-color`, and a poll-loop spin that
burned a core whenever stdin was not a terminal (`e7ddd7a`).

**Storage.** `#42` embedded SQLite sink across six commits (`247731c`
through `bf10952`, plus `43a95a6`): 40 tables, tiered retention, a size
ceiling that never drops findings, schema-level MISSION §2 guardrails,
and survey sessions. See [`docs/wiki/sqlite-schema.md`](docs/wiki/sqlite-schema.md).

> **Unverified in the field.** `#42` was motivated by a measured
> 12.6 GB / 8 h on a production node. Nothing here has confirmed what
> `--db` does to that number on real traffic — only the reporting node
> can. That measurement is the highest-value outstanding *validation*,
> as distinct from outstanding work.

---

## B. Wi-Fi SIGINT deep-dive: gaps to best-in-class

Per MISSION §4(4), 802.11 is where sloth's unique value lives. **All
items are strictly passive** — read-only monitor capture, no injection,
no active probing, no online cracking.

### B0. Baseline — what already works

Monitor-mode beacon/probe/deauth/auth capture; full RSN parse (ciphers,
AKM incl. SAE/OWE/FT/Suite-B, MFP/RSN-caps); WPA1 vendor IE; HT/VHT/HE/
EHT/Multi-Link **PHY-tier classification**; WPS state incl. zero-UUID;
802.11k neighbour reports + RNR; QBSS Load; vendor-IE fingerprint hash;
PNL aggregation + OS fingerprint; EAPOL/PMKID/4-way capture with
hashcat-22000 + replayable pcap; sequence-number MAC-randomisation
correlation; association inventory with graded evidence; presence
classification and recurring-transit detection; KARMA / evil-twin /
evil-twin-proximity / Pineapple / rogue-RADIUS / SSID-confusion /
mgmt-fuzz detection; deauth, probe, beacon and auth flood alerts.
2.4/5/**6 GHz** frequency mapping on both the monitor and nl80211 paths.

The gaps below are about **breadth of frame/IE coverage, PHY telemetry,
and parser consistency** — not starting from zero.

### B1. Frame-type coverage holes ▲ highest-leverage

`src/capture/probe.c` decodes management subtypes it names but does not
dispatch on all of them. Verified absent:

- **▲ Association / Reassociation *requests* (subtypes 0 / 2).** Only
  responses are parsed (`src/assoc_track.c`). The request carries the
  client's supported rates, HT/VHT/HE capabilities, requested SSID, RSN
  choice and power capability — a rich client fingerprint, plus the
  *"what the client asked for versus what the AP granted"* delta, which
  is where downgrade and misconfiguration show up. Also unblocks
  association-flood detection (B4).
  *Was: `grep -c assoc_req src/capture/probe.c` → 0.* ✅ **Landed**
  (`#60`): `probe.c:347` dispatches subtypes 0 and 2, the ask-vs-ask
  downgrade delta is in (`487b617`), `ALERT_TYPE_ASSOC_FLOOD` fires
  (`123a6e8`), and the data layer and surfaces followed. Note the delta
  is measured across *successive requests*, not request-versus-grant:
  an assoc response carries no RSNE outside FT/OWE (§9.3.3.7), so
  "granted AKM" is not a value the protocol supplies.
- **▲ Action frames (subtype 13).** Entirely unhandled, and a large
  passive surface: 802.11v BSS-Transition-Management (roaming steering,
  and BTM abuse as a deauth-equivalent), 802.11k Radio Measurement
  request/report, FT action, and the spoofed/malformed action frames
  modern WIDS-evasion tooling relies on.
  *Was: `grep -cE 'subtype == 13|ACTION' src/capture/probe.c` → 0.*
  ✅ **Landed** (`#59`): dispatcher and BTM Request parser (`5432574`),
  `ALERT_TYPE_BTM_ABUSE` (`2cf45d9`), persistence and surfaces
  (`3aceecf`). Categories 5 / 6 / 127 are counted as stubs — RRM
  (`#61`) and CSA (`#63`) extend the same dispatcher and are unblocked
  by it. See [`docs/wiki/btm-abuse.md`](docs/wiki/btm-abuse.md).
- **◆ Control frames (type 1: RTS/CTS/ACK/BlockAck).** Recognised by
  name in `frame_type_label()` but never counted or analysed. Counting
  them by type per channel is what airtime / channel-utilisation
  accounting needs, plus RTS/CTS-flood (airtime DoS) and hidden-node
  inference. Filed as `#64` (counters + RTS flood) and `#70` (Bl0ck /
  Block-Ack paralysis), split because they share a frame type and
  nothing else. Note CTS and ACK carry only a Receiver Address — they
  attribute to a channel, not to an AP.
- **◆ Data-frame telemetry beyond EAPOL.** Data frames are inspected
  only to pull EAPOL-Key (`probe.c:262`). Retry-bit rate, QoS TID
  distribution, frame size histograms and per-BSSID data volume are
  cheap passive signals (interference, jamming, exfil-shaped flows)
  currently discarded. The larger miss found during the 08-24 sweep is
  that there is **no LLC/SNAP → IP bridge at all**: a data frame on the
  monitor radio never reaches `decode_ipv4()`, so the monitor path and
  the IP capture see disjoint worlds even on an open network. Filed as
  `#72`; it blocks `#69`.

### B2. Information-element depth

- **▲ HT / VHT / HE / EHT *operation* element decode.** Today these are
  presence flags feeding PHY-tier labelling; the operation elements are
  not decoded. They yield channel width (20/40/80/160/320 MHz),
  primary/secondary channel and the real MCS ceiling — needed for a
  spectrum-occupancy picture, for spotting mis-width and overlap, and as
  the **durable fix for 6 GHz beacon channel**: the frequency map is now
  correct, but beacon channel still comes from the DS Param IE (tag 3),
  which many 6 GHz/HE APs omit.
  *Check: `grep -cE 'he_oper|vht_oper|chan_width' src/beacon_snoop.c` → 0.*
- **◆ Country / operating-class / power-constraint / TPC / DFS / CSA.**
  Not parsed. Enables regulatory cross-checks (an AP advertising a
  country or channel it should not), DFS/radar observation, and
  Channel-Switch-Announcement tracking — CSA is both a normal roaming
  signal and a known passive-attack lever.
  *Check: `grep -cE 'tag == 7|tag == 37|country' src/beacon_snoop.c` → 0.*
- **◆ Extended Capabilities (127), RM Enabled Capabilities (70), Mesh
  (113), FT MDE/FTE (54/55).** Round out 11r/k/v roaming telemetry and
  mesh visibility. Note 11k *neighbour reports* (tag 52) and RNR are
  already parsed — this is the rest of the family.
- **◇ Multi-Link Element full decode (Wi-Fi 7 / MLO).** Today it only
  flips the "Wi-Fi 7" tier. Decoding it gives the MLD MAC ↔ per-link
  affiliated MAC mapping — the modern analogue of the seqnum correlation
  trick, and the only way to track Wi-Fi 7 devices that present a
  different MAC per link. Composes directly with `transit_canonical_mac()`
  (`#54`), which already resolves identity through seqnum correlations.

### B3. PHY / signal-layer analysis

- **✅ LANDED — Retry-rate / FCS-error tracking.** Radiotap decoding
  extracted to `src/radiotap.c` (and thereby unit-tested for the first
  time — `probe.c` is not in the test build), widened to read FLAGS and
  RATE. Per-channel accounting in `src/rf_quality.c`, a retry column in
  `[m] Channel`, and the `RF_DEGRADED` alert. The extraction also fixed
  a latent bug: the extended-present-bitmap loop re-tested the *first*
  word's continuation bit and never advanced, so any capture from a
  driver emitting extended bitmaps yielded **no signal and no channel at
  all**.
- **◆ Channel-utilisation / airtime view.** Combine B1 control-frame
  counts with the existing QBSS Load and per-channel frame rate into a
  live occupancy panel. This is the "spectrum analyser" the tool still
  lacks — what turns *"here are the APs"* into *"here is how busy each
  channel actually is"*.
- **◇ Fuller radiotap decode.** Beyond FLAGS/RATE above: MCS
  (radiotap bit 19), VHT/HE/EHT fields, bandwidth and antenna. Feeds the
  airtime view and MIMO/PHY-rate telemetry.
- ~~Per-BSSID / per-STA RSSI history + movement~~ — **✅ landed** as
  `#53` / `#54`: `rssi_ring_t` on `probe_client_t`, trajectory-shape
  classification in `src/presence.c`, recurring-transit accumulation in
  `src/transit.c`.

### B3b. Parser-consistency debt

- **✅ LANDED — Unify the two Wi-Fi paths.** `beacon_parse_ies()` is now
  the single IE parser both paths call; the nl80211 scan path reports
  the same RSN/WPS/QBSS/vendor/PHY depth as monitor mode, surfaced as
  AKM/MFP and PHY columns in `[3] WiFi`. Two output spellings
  (`<hidden>`/`Open` vs `""`/`OPEN`) are preserved on purpose — they
  reach the JSONL `wifi_ap` record, so unifying them is a schema
  decision, not a refactor. Original note follows.
- **~~▲ Unify the two Wi-Fi paths.~~** sloth has *two* Wi-Fi code paths of
  very different depth: the monitor-mode engine
  (`src/capture/probe.c` + `src/beacon_snoop.c`) with the rich
  RSN/WPS/RNR/11k/QBSS/vendor parser, and the managed-mode nl80211 scan
  path (`src/platform/linux_wifi.c`) whose IE parser yields SSID plus
  RSN/WPA/WEP booleans and nothing more. **The same AP reports far less
  detail depending on which interface mode saw it.**

  That is a correctness inconsistency rather than a missing feature,
  which is why it ranks above most of B2 despite being less glamorous.
  The beacon IE parser should be the single source of truth both paths
  call.
  *Check: `grep -cE 'akm|pairwise|mfp' src/platform/linux_wifi.c` → 0,
  against 39 neighbour/RNR references in `beacon_snoop.c` alone.*

### B4. Attack / anomaly detection breadth

Deauth, probe, beacon and auth floods, evil-twin (+ proximity, + attack
chain), KARMA/Pineapple, rogue-RADIUS, SSID-confusion and mgmt-fuzz all
exist. Gaps:

- ~~**◆ Association flood.**~~ ✅ landed (`#60`, `123a6e8`). The
  issue's "≤ 3 distinct STAs" gate was dropped deliberately: flood
  tooling randomises source MACs, so a real flood is *many* distinct
  STAs and the gate would have suppressed the common shape.
- **◆ CTS/RTS airtime DoS.** Needs B1 control frames — `#64`.
- ~~**◆ PMF/WPA3 downgrade + transition-mode exposure.**~~ ✅ landed
  (`#62`). `ALERT_TYPE_WPA_DOWNGRADE` fires on four lanes — SAE+PSK
  transition, OWE-with-open-companion, MFP-optional-on-SAE, and WPA1
  beside RSN — after a 30 s observation floor, one alert per
  (BSSID, kind). The `[b]` MFP column became a `posture` column. CRIT
  when the BSSID is designated or when `#60`'s assoc delta shows a
  client actually took the lane.
- **◇ KARMA / known-beacon responder heuristics v2**, and PMKID-harvest
  tool fingerprints — AP or client behaviour matching known passive
  harvesting tooling. Observation-only. Filed as `#68`, and the one
  issue genuinely gated on captures: a frame layout can be built from a
  spec, a tool's fingerprint cannot be invented. Ship the table format
  and matcher; leave the signature rows empty until captures exist.
- **◆ Enterprise client accepting no server cert (CVE-2023-52160).**
  `#65`. The AP-side rule (`ROGUE_RADIUS`, `#31`) warns about attacker
  infrastructure; this is the client-side mirror — a PEAP session
  reaching EAP-Success with no TLS ServerHello or Certificate observed,
  which is your own devices demonstrating they would fall for it.
  Viable, with one seam to widen first: `eap_track_observe()` receives
  only the BSSID (`eapol_log.c:310`), and this rule needs the STA and
  the frame direction — both already computed at that call site, just
  not passed.

### B5. Coverage & correlation

The channel scheduler (`#22`) and multi-radio merge (`#21`) are the
force-multipliers for everything in B1–B4: more spectrum seen, more of
the time, without transmitting. Baseline/drift (`#23`) is what converts
richer per-frame data into *"what changed"* — the question operators
actually ask.

---

## C. Smaller outstanding items

- **◆ Evil-twin suppression for APs without 802.11k.** `#51` uses
  neighbour advertisement to recognise co-operating infrastructure, which
  modern mesh kit emits and budget single-box repeaters generally do not.
  Those still trip the rule. The obvious second signal — *"both BSSIDs
  present since early in the session"* — is weak under `--hop`, where an
  AP's first observation is confounded by when the radio first visited
  its channel. Scenario S2.1 in the persona suite is `PARTIAL` for this
  reason and is the only scenario short of `PASS`.
- **◇ Mutation-testing campaign, rounds 10+.** Paused at ~51 % kill rate
  (938 / 1844 considered). Non-blocking and stateless; see `PROGRESS.md`.
- **◇ Headless log hygiene, part two.** `--headless` (`#50`) silences the
  draw path but deliberately keeps sloth's own stderr diagnostics — those
  are what tell an operator the database opened or the monitor interface
  was missing. If journal volume becomes a problem, the shape would be
  log levels, not suppression.

---

## Suggested sequencing

The previous sequencing is fully delivered. Current order, weighting
MISSION §4(1) ("coverage beats precision until coverage exists") against
effort:

1. ~~**B3b — unify the two Wi-Fi parsers.**~~ ✅ landed.
2. ~~**B3 retry / FCS tracking.**~~ ✅ landed.
3. ~~**`#59` slices 2–4** — the `BTM_ABUSE` rule, surfaces, docs.~~
   ✅ landed 2026-08-24.
4. ~~**`#60` slice 5b** — `[w]` Assoc columns, `[k]` PNL PHY tier,
   `--report`, docs.~~ ✅ landed 2026-08-24.
5. ~~**`#62` PMF/WPA3 downgrade.**~~ ✅ landed 2026-08-25.
6. **`#65` PEAP no-server-cert.** Small, and the only issue open that
   catches evidence of a *shipping* CVE (CVE-2023-52160) against
   handsets already on the network. Widen the `eap_track_observe()` seam
   first — it needs the STA and the direction.
7. **`#63` CSA abuse.** Extends `#59`'s dispatcher; composes with
   `#62`'s posture flags.
8. **`#66` HT/VHT/HE/EHT operation decode.** Unlocks real channel width,
   completes the durable 6 GHz beacon-channel fix, and is the data model
   the airtime view needs.
9. **`#61` RRM**, then **`#64`** control-frame counters → the B3
   channel-utilisation view.

Backlog after that: `#70` (Bl0ck), `#67` (Wi-Fi 7 MLO — a real
correctness bug, since seqnum correlation misreports one MLO device as
three, but future-weighted), `#68` (tool fingerprints, capture-gated),
`#71`/`#72` (the `#69` prerequisites) and `#69` itself.
