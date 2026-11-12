# Attack-hardware fingerprints (#77, #151)

**Summary**: What sloth measures about the radio stack behind an AP, and
what it concludes from it. Issue #77 asked sloth to name the attack
hardware (Pineapple, ESP32 Marauder, eaphammer rigs) from passive 802.11
observables. The spec-derivable half shipped as measurements: the beacon
IE-order hash, beacon TBTT jitter, and the WPS/WSC vendor strings. #151
then built what could be built from public sources: a known-stack
IE-order table (the mechanism and its capture guard; **no rows**, because
no row can be sourced without a capture), the Pineapple setup-AP pairing
(from Hak5's own documentation), and a verdict layer that turns the
inputs into `none` / `suspected-<device>` / `corroborated-<device>` on the
`KARMA_AP` detail and as two JSONL fields. Nothing here raises an alert
or moves a severity.

**Sources**: `src/attack_hw.c`, `src/attack_hw.h`,
`src/alerts/rules_twin.c` (`rule_karma_ap`), `src/alerts/engine.c`
(`fire_stage_hw_verdict`), `src/jsonl.c` (`emit_hw_verdict`),
`src/beacon_snoop.c`, `src/views/beacon.c`
(`draw_detail_stack_measures`), `src/eap_parse.c` (`wsc_take_vendor_str`),
`src/eap_parse.h`, `src/tool_fingerprint.c`, `include/sloth.h`
(`ap_fingerprint_t`, `ap_beacon_timing_t`), `docs/views/beacons.md`,
`docs/wiki/jsonl-schema.md`, `research/tools/wifi-pineapple-mk7.md`,
`tests/test_attack_hw.c`, `src/probe_latency.c`, `src/probe_latency.h`,
`tests/test_probe_latency.c`, `research/papers/probe-response-latency.md`,
issues #77, #151 and #187, plan #145 (rulings 1-3).
IEEE 802.11-2020 §9.3.3.2, §9.4.1.3, §9.4.1.10, §11.1.3; Wi-Fi Simple
Configuration Technical Specification v2.0 §7.7, §12.

**Last updated**: 2026-11-12 (#187 S3: probe-response latency, measured
only), 2026-11-12 (#151: the stack table mechanism, the
Pineapple setup-AP pairing, the verdict layer), 2026-10-20

## What #151 built (2026-11-12)

### 1. The known-stack IE-order table: mechanism, guard, no rows

`HW_STACKS[]` in `src/attack_hw.c` maps an (`ie_order_hash`,
`ie_order_count`) pair to the stack that emitted it, and to an attack
device or `SLOTH_TOOL_UNKNOWN` for a production stack. It ships empty.

A row's values are the order hash of one firmware build's beacons. No
specification or vendor document states that order, and #151's standard
is a capture per row: named hardware, named firmware, band, the
capture's SHA-256 in the row. `hw_stack_row_valid()` enforces it: a
non-zero hash and count, a label, an id, an evidence string that is not
`UNVERIFIED` (this table, unlike `TOOL_SIGNATURES`, admits no research
rows), and a 64-character lowercase-hex `capture_sha256`. A test holds
every shipped row to it, and the validator is proven on synthetic rows
so the first real row meets a guard already seen to refuse.

The matcher pins hash **and** count. A hash of 0 ("not decoded") never
matches. When two rows match one observation, which is a collision #151
says must arrive as a second row, the answer is no match plus an
`ambiguous` flag, never whichever row comes first. Transient elements
(CSA, Quiet, ECSA, Channel Switch Wrapper, Quiet Channel) are already
outside the hash (`beacon_snoop.c`), so a beacon taken mid-channel-switch
reaches the same row as a steady one; a test drives the real parser
with both.

**Rows wanted, none sourced.** One capture each, with firmware version
and band, ideally from two units:

| Stack | Device | Why it is not in the table |
|---|---|---|
| Cisco IOS-XE (Catalyst 9800 APs) | production | no public capture or document gives the element order |
| Aruba OS | production | same |
| Ubiquiti UniFi | production | same |
| MikroTik RouterOS | production | same |
| OpenWrt / hostapd defaults | production | the element set, and so the hash, depends on configuration (HT/VHT/HE, WMM, RSN, 11k/v); a row read off source would be a guess about the configuration and a research row, which this table refuses |
| Pineapple MK7 PineAP | `pineapple-mk7` | needs a capture (#151 item 1) |
| ESP32 Marauder | `esp32-marauder` | the firmware's source is public, but which frames each lure mode emits, and in what element order on the air, is not documented; a row read off source would be a research row, which this table refuses. Needs a capture |

### 2. The Pineapple setup-AP pairing

Hak5's Mark VII documentation says that during setup the device "serves
an Open AP" whose "SSID ... is `Pineapple_XXXX`, where the 'XXXX' is the
last 4 characters of the devices MAC address", and that the network
"will disappear after setup is complete"
(`research/tools/wifi-pineapple-mk7.md`).

`hw_pineapple_pair()` pairs a `KARMA_AP` BSSID with a **different** BSSID
in the beacon table, seen within `BEACON_AGE_SECS`, whose SSID is exactly
`Pineapple_` plus four hex digits (`Pineapple_Guest` and
`Pineapple_12345` do not pair). Whether the suffix equals either
BSSID's low 16 bits is recorded and not required: the docs do not say
which interface's MAC "the devices MAC address" is. The KARMA BSSID never
pairs with itself. A legitimate dual-band enterprise AP (two adjacent
BSSIDs, one SSID) does not pair; that is #151's negative acceptance test,
`test_dual_band_enterprise_ap_does_not_pair`.

This is narrower than the "two-radio pattern" #151 asks for, and
deliberately so. Adjacent MACs, a shared IE-order hash, the channel
relation, and timing between PineAP's echoes and the second radio's
traffic are not documented anywhere public, so none of them is required
or scored. By the vendor's own account the setup network exists only
until setup completes, so this will rarely fire in the field. The full
two-radio pattern still waits on a capture of a configured MK7 with
PineAP and the management AP both up.

The pairing enriches a `KARMA_AP` that already fired: the detail gains
`+setup-AP Pineapple_1a2b@<bssid>`. It never raises an alert and never
moves severity or confidence.

### 3. The verdict layer

`hw_verdict_eval()` combines up to four signal classes for one BSSID:

| Class | Input | Capture-backed? |
|---|---|---|
| `tool` | a `TOOL_SIGNATURES` row match | only if the row is not `unverified`; **none is** today |
| `stack` | a known-stack table hit | yes, by the validator; **the table is empty** |
| `pair` | the Pineapple setup-AP pairing | no (vendor docs) |
| `oui` | a Hak5 OUI on the BSSID, read as Pineapple | no (registry). Not counted when the tool row itself requires an OUI flag: the Pineapple row *is* the Hak5 OUI, and counting both would corroborate a device from one observation. An Espressif OUI names no device and is not an input |

Tiers:

- `none`: nothing names a device, or two devices tie.
- `suspected-<device>`: at least one class names it.
- `corroborated-<device>`: two or more classes name it, at least one of
  them capture-backed, and nothing names another device or a production
  stack (a production-stack hit means the IE emitter is not attack
  hardware, so it caps the tier).

So `corroborated` is **unreachable on live data today**: no input is
capture-backed. That is plan #145's standard applied, not a gap: the
honest ceiling is `suspected` until a capture backs a row. Tests reach
`corroborated` with synthetic capture-backed rows.

The tier lands in two places. In the `KARMA_AP` detail as
`hw:suspected-pineapple-mk7`, after the tool attribution. In JSONL as
`hw_verdict` and `hw_signals` (`"oui+pair"`) on `alert` and every
`alert.*` record, omitted when there is none (`jsonl_version` 1.4.0,
[[jsonl-schema]]). The alert stores three bytes (`hw_tier`, `hw_device`,
`hw_signals`) that sat in padding; both surfaces render through
`hw_verdict_format()`, so the detail and the record cannot spell a
verdict two ways.

Not inputs, though #151 lists them: **WPS/WSC vendor strings** and
**TBTT jitter**. No public source maps a string or a jitter figure to an
attack device, so they stay measurements. The `[b]` detail does not show
the tier yet (see below).

### The hook in `rules_twin.c`

Four lines in `rule_karma_ap()`: one call to `hw_karma_context()` (in
`src/attack_hw.c`, which does the stack lookup, pairing, verdict and note),
the `hw_note` buffer in the detail format, and
`fire_stage_hw_verdict()` before `fire_inv()`. The stage is a one-shot
the next `fire_inv()` stamps and clears, so the other fourteen
`fire_inv()` callers are untouched and nothing else inherits a verdict.

### Owner rulings still needed

- **Two vocabularies.** `tool_fingerprint.c` reports `low/med/high`, and
  the verdict reports `suspected/corroborated`. #151 asks whether `high`
  maps to `corroborated` or is renamed. Unchanged here: both still reach
  the operator.
- **Severity policy.** The verdict moves neither severity nor
  confidence. Whether a `corroborated` verdict should escalate
  `KARMA_AP` (as `tool_verified` already does) is an owner call; it can
  only matter once a capture-backed row exists.
- **Surfaces.** The tier is on the Alerts view through the detail. The
  `[b]` detail and the `[A]` view #77 proposed are not built (plan #145
  ruling 3: no new views by default).
- **TBTT threshold** (#151 item 4): still needs the jitter captures.

## What ships: measurements

Each of these is derived from a published specification and tested with
hand-built frames. None is a verdict and none raises an alert.

| Measurement | Basis | Where it surfaces | Zero / empty means |
|---|---|---|---|
| `ie_order_hash`, `ie_order_count` | element identity in beacon order, bodies excluded (802.11-2020 §9.3.3.2 element order) | JSONL `beacon`; `[b]` detail `IE order:` | **not decoded** (no elements, or the frame overran). Never a hash value |
| `tbtt_jitter_us`, `_samples`, `_resets` | TSF delta vs whole Beacon Intervals (§11.1.3, §9.4.1.3, §9.4.1.10) | JSONL `beacon`; `[b]` detail `TBTT jitter:` | with fewer than `TBTT_JITTER_MIN_SAMPLES` (2) residuals, **not measured**. With 2 or more, 0 µs is a real reading |
| WPS beacon strings (Manufacturer, Model Name, Model Number, Serial) | WPS IE attributes 0x1021/0x1023/0x1024/0x1042 (WSC 2.0 §12) | JSONL `beacon`; `[b]` detail `WPS ID:` | absent, or nothing printable |
| WSC M1/M2 strings (same four IDs) | WSC 2.0 §7.7 EAP-WSC body, §12 attributes | `eap_wsc_info_t` only (parse layer) | absent, or nothing printable |

### On the `[b]` detail screen

The `STACK MEASUREMENTS` block sits below `CAPTURED HANDSHAKES`, just
above the back hint. The screen does not scroll, so the block is drawn
only when it and the footer both fit; on a shorter terminal it is
dropped and the footer says `(taller terminal shows stack
measurements)`, rather than the block pushing the handshake counts off
the bottom. It never prints a bare `0` for either field, because a zero
means a different thing for each:

```
 ── STACK MEASUREMENTS (no threshold until a capture backs one) ──
  IE order:    0x1a2b3c4d  (14 elements; JSONL ie_order_hash 439041101)
  TBTT jitter: 312 us stddev over 48 samples
  TBTT basis:  2 baseline resets (TSF back / BI change / gap)
```

and for an AP heard twice on the monitor radio (the first beacon only
sets the baseline, so an AP heard once reads `0/2`). An AP seen only
through the managed-mode scan always reads `0/2`: that path is handed an
IE blob with no frame and so no Timestamp, and nothing is sampled:

```
  IE order:    not decoded (no elements, or the frame overran)
  TBTT jitter: not measured (1/2 samples; monitor mode only, needs consecutive beacons)
```

The hash is shown in hex and in the decimal form the JSONL record uses,
so an operator can grep a log for the value on screen. The reset clause
only appears when a baseline has been discarded, and it counts every
cause, on its own row so the worst-case line still fits 100 columns: a TSF that ran backwards, a changed Beacon Interval, or a gap
past `BEACON_AGE_SECS`. A hopping capture radio or an AP at the edge of
range builds up gap rebases on its own, so the count says nothing about
the AP by itself and carries no verdict.

### WSC M1/M2 vendor strings

An Enrollee's M1 carries its own Manufacturer, Model Name, Model Number
and Serial Number. A Registrar's M2 carries the Registrar's. The beacon
WPS IE only describes the AP. The registration exchange describes both
ends, including a registrar that is really an attack tool driving a
PIN or Pixie-Dust session. `eap_wsc_parse()` now fills
`manufacturer`, `model_name`, `model_number` and `serial_number`:

- **Printable ASCII only.** Every byte comes from the transmitter, and
  §12 defines all four attributes as ASCII. Bytes outside 0x20..0x7e
  are dropped, not mapped, so the stored form can be shorter than the
  attribute.
- **Clamped at the §12 maximum.** That is 64 octets for Manufacturer
  and 32 for each of the others. A longer attribute is malformed: the
  first `max` octets are kept and `vendor_str_clamped` is set. The walk
  continues past it to the attributes that follow.
- **Latest occurrence wins** when a message repeats an attribute, the
  same rule as Device Password ID.
- **Not read from bytes that were not walked.** That covers middle
  fragments (MF set, LF clear), bytes past the declared EAP length, and
  an attribute whose length runs past the frame.

These fields are measurement only. No rule reads them, and this slice
adds no JSONL or TUI output for them. The #82 session timeline is
where they would naturally be shown.

## Probe-response latency (#187 S3): measured, no verdict

`src/probe_latency.c` pairs a station's Probe Request with the Probe
Response a BSSID addresses back to it and keeps, per BSSID, the count,
minimum, p10, median and p90 over its last 32 pairs, directed and
wildcard probes separately. It is fed once per monitor frame from
`src/capture/probe.c`.

- **Clock.** Radiotap TSFT on both frames when the radio supplies it
  (the receiver's own TSF at each MPDU's first bit, 1 µs, no host
  jitter); otherwise the pcap stamp on both (host receive time, driver
  and USB batching inside it). Never one of each, and one clock per
  BSSID row.
- **A pair counts only** inside one dwell (dwells are numbered from the
  radiotap frequency, so a `--hop` retune between the two frames voids
  it); against a request heard once under its sequence number; from a
  first transmission (Retry clear); as the BSSID's first answer to that
  request (hostapd-mana answers a wildcard probe once per remembered
  SSID, airbase-ng sends a broadcast-probe answer three times); naming
  the requested SSID; within 200 ms. Each refusal is tallied.
- **Bounds.** 64 pending requests and 128 BSSID rows, oldest evicted and
  counted. The tally is module-local (`probe_latency_counters()`): an
  `SH_EVICT_*` kind would add a sensor-health JSONL member, which waits
  for the next JSONL version.
- **Not exported or shown yet.** No JSONL member, no sloth.db column, no
  TUI column; the accessor is `probe_latency_get()` /
  `probe_latency_snapshot()`. The `[y]` view has no room for a column
  at 100x33 without dropping the tool attribution's minimum.

**Observation only: no cited threshold, not used in any verdict.** #187
proposed a median under 2 ms as a KARMA confirmer.
`research/papers/probe-response-latency.md` records what was read: a
2003 legitimate-AP baseline (Mishra, Shin & Arbaugh: every response
within 9-15 ms per network) and the lure tools' source, which answers
through the same userspace path stock hostapd uses on a driver without
probe-response offload. No source gives a lure a direction or a
magnitude, and the plausible offload difference runs the other way
(firmware faster). `rule_karma_ap()` and `KARMA_PROBE_FORGE` do not read
it. A threshold needs a source or sloth's own captures of a known lure
beside known APs on one radio.

## What does not ship, and why

The issue quotes numbers ("real APs hold ±2 TU, Marauder-class firmware
jitters 8-40 TU") and names stacks (Cisco IOS-XE, Aruba, Ubiquiti,
MikroTik, OpenWrt) whose IE order would form a lookup table. No primary
source for any of them was found. They are facts about particular
firmware builds, so they can only come from capturing that firmware.
Plan #145's evidence standard (its second ruling) forbids shipping a
fingerprint row without a primary source. The same reasoning is set out
at length in [[tool-fingerprints]], where the two existing rows are
flagged `UNVERIFIED` and capped at `med`.

## Waiting on captures

The text below was filed as #151 (2026-10-20). What #151 could build
without captures is above; the rest of it still waits on them.

---

**Title:** Attack-hardware fingerprints: known-stack table, two-radio
Pineapple pattern, verdict layer (waiting on owner rig captures)

**Body:**

Split out of #77 per plan #145. Everything #77 could build from a
specification has shipped as measurements: `ie_order_hash` (874f6b9),
TBTT jitter (a56903a), the WPS beacon vendor strings, the `[b]` detail
`STACK MEASUREMENTS` block, and the WSC M1/M2 vendor-string parse.
What is left needs numbers that come only from capturing real
firmware. This issue waits on owner-supplied rig captures. Nothing here
starts before a capture exists for the item it needs.

**Evidence standard (plan #145, ruling 2).** A passive sensor
corroborates, it never confirms. The top tier of any output here is
named `corroborated-<device>`. Never `identified-<device>`, never
`CONFIRMED_*`. No table row ships without a primary source: a capture
from named hardware at a named firmware version, with the capture's
SHA-256 and the rig recorded in the row's `evidence` string. The
captures stay off-repo. `tests/` keeps zero `.pcap` files (AGENTS.md).
Each row's test is a hand-built `uint8_t` frame reproducing what the
capture showed, per the clause that defines the field. The capture is
the integration check behind it, not the fixture.

**1. Known-stack IE-order table.**
- *Needs:* one capture per stack (Cisco IOS-XE, Aruba OS, Ubiquiti
  UniFi, MikroTik RouterOS, OpenWrt/hostapd defaults, Pineapple MK7
  PineAP, ESP32 Marauder). Each needs firmware version and band, and
  ideally two units, to show the hash is per-stack and not per-unit or
  per-configuration.
- *Builds:* an embedded table `ie_order_hash` → stack label, matched in
  the same place `tool_fingerprint_match()` runs. A hash collision or a
  configuration-dependent order must show up as a second row with its
  own capture, not as a wildcard.
- *Acceptance:* every row carries its capture provenance. A test
  asserts that no row has an empty `evidence`, the same guard
  `TOOL_SIGNATURES` already has. A hash taken while an element is
  transient (CSA, Quiet) does not match.

**2. Two-radio Pineapple pattern.**
- *Needs:* a capture of a Pineapple MK7 running PineAP with both radios
  up. The capture defines the pattern; it is not just a check on it.
  Which BSSIDs relate (adjacent MACs, shared OUI, same IE-order hash),
  on which channels, and with what timing between the PineAP radio's
  SSID echoes and the second radio's traffic are all unverified today.
- *Builds:* a correlation over the beacon table that pairs the two
  radios and adds that pairing to a `KARMA_AP` detail as corroboration.
  It enriches an alert that already fired. It never raises one on its
  own, which is the gate the existing UNVERIFIED rows use.
- *Acceptance:* a negative test from a capture of a legitimate
  dual-radio AP (any enterprise AP with one BSSID per band) that does
  not pair.

**3. Verdict layer.**
- *Needs:* items 1 and 2, or at least two independently sourced signals
  per device. A scorer over the two `UNVERIFIED` rows that exist today
  would be apparatus with nothing real behind it.
- *Builds:* one function that combines a `tool_fingerprint` row match,
  an IE-order table hit, the two-radio pairing, OUI, and WPS/WSC
  vendor strings into tiers `none` → `suspected-<device>` →
  `corroborated-<device>`. The tier lands in the alert detail and as
  additive JSONL fields on the alert record. Owner decision needed
  here: `tool_fingerprint.c` reports `low/med/high` today. Its `high`
  should map to `corroborated` or be renamed, so two vocabularies do
  not reach the operator.
- *Surface:* the Alerts view and the `[b]` detail. Plan #145 ruling 3
  says no new views for single rule families, so the `[A]` view #77
  proposed needs its own owner ruling before it is built. The default
  is no new view.

**4. TBTT jitter threshold.**
- *Needs:* jitter figures (`tbtt_jitter_us` over at least 100 samples,
  idle channel and loaded channel) from at least three production APs
  and from each attack device in item 1.
- *Builds:* only if the captures separate the populations. In that case
  the jitter becomes one more corroborating input to item 3, with the
  measured distributions cited. It never becomes a standalone alert.
  Until then it stays a measurement, as plan #145 records.

**Out of scope here:** EAP outer-identity + server-certificate CN
sniffing. That is a new decode path over EAP-TLS/PEAP certificates and
needs its own design issue. Its CN-pattern corpus has the same
provenance question as the stack table.

---

## Related pages

- [[tool-fingerprints]]: the signature-row mechanism, its two
  UNVERIFIED rows, and why the table does not grow without captures.
- [[jsonl-schema]]: the `beacon` record fields named above, and the
  `hw_verdict` / `hw_signals` alert fields.
- [[enterprise-rogue]]: the WPA-Enterprise detectors the deferred CN
  sniff would join.
- [[alerts]]: `KARMA_AP`, the alert the verdict tier lands on.
