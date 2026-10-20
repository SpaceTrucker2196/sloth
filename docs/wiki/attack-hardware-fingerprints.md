# Attack-hardware fingerprints (#77)

**Summary**: What sloth measures about the radio stack behind an AP, and
what it does not yet conclude from it. Issue #77 asked sloth to name the
attack hardware (Pineapple, ESP32 Marauder, eaphammer rigs) from passive
802.11 observables. The spec-derivable half shipped as measurements:
the beacon IE-order hash, beacon TBTT jitter, and the WPS/WSC vendor
strings from beacons and from the M1/M2 registration exchange. The half
that needs real numbers off real firmware (a known-stack table, the
two-radio Pineapple pattern, a verdict layer) has no primary source in
this tree. It is written up below, ready to file as one issue that waits
on owner-supplied rig captures.

**Sources**: `src/beacon_snoop.c`, `src/views/beacon.c`
(`draw_detail_stack_measures`), `src/eap_parse.c` (`wsc_take_vendor_str`),
`src/eap_parse.h`, `src/tool_fingerprint.c`, `include/sloth.h`
(`ap_fingerprint_t`, `ap_beacon_timing_t`), `docs/views/beacons.md`,
`docs/wiki/jsonl-schema.md`, issue #77, plan #145 (rulings 1-3).
IEEE 802.11-2020 §9.3.3.2, §9.4.1.3, §9.4.1.10, §11.1.3; Wi-Fi Simple
Configuration Technical Specification v2.0 §7.7, §12.

**Last updated**: 2026-10-20

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
  TBTT jitter: 312 us stddev over 48 samples  2 baseline resets (TSF back / BI change / gap)
```

and for an AP heard twice (the first beacon only sets the baseline, so
an AP heard once reads `0/2`), or seen only through the managed-mode
scan, which is handed an IE blob with no frame and so no Timestamp:

```
  IE order:    not decoded (no elements, or the frame overran)
  TBTT jitter: not measured (1/2 samples; monitor mode only, needs consecutive beacons)
```

The hash is shown in hex and in the decimal form the JSONL record uses,
so an operator can grep a log for the value on screen. The reset clause
only appears when a baseline has been discarded, and it counts every
cause: a TSF that ran backwards, a changed Beacon Interval, or a gap
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

The text below is the refile for the capture-gated remainder of #77,
written to be filed as one issue as-is. The labels to use are
`needs-pcap-fixture`, `detector` and `enhancement`.

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
- [[jsonl-schema]]: the `beacon` record fields named above.
- [[enterprise-rogue]]: the WPA-Enterprise detectors the deferred CN
  sniff would join.
- [[alerts]]: the surface any verdict tier would land on.
