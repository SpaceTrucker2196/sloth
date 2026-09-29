---
name: wifi-sigint
description: The v1.1 WiFi SIGINT feature set — PNL, EAPOL/PMKID, seqnum correlation, assoc inventory
type: project
---

# WiFi SIGINT (v1.1)

**Summary**: Four views added in v1.1 turn sloth from "what's on the wire" into "who is in the room and what do they remember". Built around passive 802.11 monitor-mode capture.

**Sources**: `docs/views/pnl.md`, `docs/views/eapol.md`, `docs/views/seqnum.md`, `docs/views/assoc.md`, `docs/views/probe.md`, `docs/views/beacons.md`.

**Last updated**: 2026-05-25.

---

## The four views

| Key | View | Primitive |
|-----|------|-----------|
| `k` | PNL    | Per-MAC Preferred-Network-List aggregation + OS fingerprint via vendor IE |
| `e` | EAPOL  | PMKID + 4-way handshake capture; hashcat 22000 + replayable per-handshake pcap |
| `j` | Seqnum | MAC-randomisation deanonymisation via 802.11 sequence-control correlation |
| `w` | Assoc  | Confirmed STA ↔ AP associations (EAPOL > Reassoc ≥ Assoc evidence) |

## What each enables

- **PNL (k)** — fingerprints a device by the SSIDs it remembers.
  Survives MAC rotation because the OS vendor IE in probe requests is
  the same across rotations.
- **EAPOL (e)** — exports `eapol.22000` in hashcat mixed format plus
  per-handshake pcaps replayable in aircrack-ng / Wireshark. PMKID
  rows are offline-crackable with no client interaction.
- **Seqnum (j)** — reports address pairs whose frames fall on the same
  forward-running 12-bit sequence counter, with a calibrated score and
  the evidence window. A hypothesis about a radio, never an
  identification of a person, and not on its own grounds for personnel
  action or physical identification (#94). `--no-correlate` switches the
  linkage off. See [[mac-randomisation]] for the full explanation and the
  limits on use.
- **Assoc (w)** — answers "who is on which AP, right now" with
  graded evidence (EAPOL is definitive, AssocResp / ReassocResp are
  strong).

## Cross-view correlation chains

The four views compose:

```
Probe (raw) ──► PNL (k)     ──► fingerprint by SSID list
                Seqnum (j)  ──► fingerprint by chipset counter
                                    │
                                    ▼
                              same physical device across MACs
                                    │
                                    ▼
                              Assoc (w) tells you which AP it landed on
                                    │
                                    ▼
                              EAPOL (e) lets you crack the PSK against it
```

## Hardware requirements

Monitor mode on a card / driver that supports
`ARPHRD_IEEE80211_RADIOTAP`. The project README cites rtl88XXau as a
tested chipset. Set the probe-capture interface from `[1] Interfaces`
(`m` key).

## Storage caps

- `MAX_PNL_CLIENTS = 128` × 16 SSIDs per client, LRU evicted by `last_seen`.
- `MAX_ASSOC_ENTRIES = 128`, LRU evicted by `last_seen`.

## Multiple monitor-mode radios (issue #21)

A single monitor adapter hears one channel at a time. Channel hopping
covers the band over time, but a short management frame — a lone
deauth, a probe response — slips past while the radio is tuned
elsewhere. A second adapter parked on another channel closes that gap.

sloth merges observations from every monitor radio into one coherent
world model. Each adapter is a `SENSOR_WIFI` sensor with its own id
(see the [[non-ip-sensors]] registry); every 802.11 observation is
tagged with the radio that heard it and folded into an entity-keyed
merge table (AP BSSID / STA MAC). The existing Wi-Fi views still
aggregate **by observed entity, not by adapter** — you see one row per
AP no matter how many radios saw it — but the merge layer retains
enough observer metadata to answer *which radio saw this, on what
channel, at what signal, and when*:

- `seen_by` — how many distinct radios heard the entity.
- `sensor_mask` — which radios (bit *i* = sensor id *i*).
- `best_rssi` / `best_sensor` — strongest signal and the radio closest
  to the entity (useful for coarse direction-finding across a spread of
  adapters).

This metadata is emitted on the additive `wifi_merged` JSONL record
(see [[jsonl-schema]]) so downstream consumers can reason about
coverage and per-radio provenance. With a single adapter the merge is
an identity map — one row per AP, `seen_by == 1` — so nothing changes
for the common case.

### Setup expectations

sloth is **passive**. It does **not** put any adapter into monitor
mode and does **not** change channel assignments except the operator's
own `--hop` scheduler on sloth's own monitor interface (see
[[wifi-sigint]] channel hopping). Prepare each radio externally before
launch, exactly as for a single adapter:

```
airmon-ng start wlan0        # → wlan0mon
airmon-ng start wlan1        # → wlan1mon, park on another channel with iw
```

Each prepared monitor interface registers as its own Wi-Fi sensor and
contributes to the merged view. sloth never transmits, associates, or
reconfigures an adapter it did not create.

> **Hardware note.** Concurrent capture across two physical radios is
> validated only on Linux with two monitor-capable adapters and
> `CAP_NET_ADMIN`. The merge, dedup, and JSONL layers are exercised in
> CI against seeded multi-sensor state (`tests/test_wifi_merge.c`); the
> live N-thread capture path is hardware-gated like the nl80211
> channel-set path.

## Regulatory elements (issue #101, slice 1)

`src/reg_ie.c` parses the three elements that carry the regulatory
envelope an AP *claims* to operate in. Until #101 sloth read none of
them, so the cheapest non-compliance signal there is — a 5 GHz AP that
names no country at all, the hostapd / OpenWrt stripped-build default —
was invisible.

| Element | Tag | Clause | Fields taken |
|---|---|---|---|
| Country          | 7  | IEEE 802.11-2020 §9.4.2.8 (802.11d-2016) | ISO 3166-1 alpha-2 code, environment octet, triplets |
| Power Constraint | 32 | §9.4.2.13 | Local Power Constraint, unsigned dB |
| TPC Report       | 35 | §9.4.2.16 (802.11h) | Transmit Power, signed dBm; Link Margin, signed dB |

Two details in the Country element are where a naive parser goes wrong.

**The third octet of the Country String is not always an environment.**
§9.4.2.8 gives it five forms: ASCII `' '` (all environments), `'I'`
(indoor only), `'O'` (outdoor only), `'X'` (non-country entity, with the
code itself `"XX"`), or the *binary* Annex E Operating Class table
number — which is what hostapd emits as `0x04` when it advertises global
operating classes. Anything outside those five is recorded as
`REG_ENV_UNKNOWN` rather than folded into "any": an AP that emits an
undefined octet has made no environment claim, and inventing one would
put a regulatory assertion in the record that never went over the air.

**The triplets are two different structures sharing one shape.** Each is
three octets, and which three fields they are is decided by the first
octet, per triplet, not per element: at 201 or above it is an Operating
Extension Identifier and the triplet is (ext id, operating class,
coverage class); below it, (first channel, number of channels, maximum
transmit power). Read the wrong way, an operating triplet for global
class 81 reports "channel 201, 81 channels, 3 dBm" — plausible enough to
pass unnoticed. Maximum transmit power is **signed** dBm; sub-1 mW caps
are real, and an unsigned read turns −2 dBm into 254 dBm.

Both TPC Report fields are signed too. Link Margin is reserved (0) in a
beacon or probe response and only carries a value in a TPC Report action
frame; it is parsed regardless, since the element layout is the same.

The parser reaches frames through `beacon_parse_ies()` — the one seam
both the monitor path and the nl80211 managed path use, so the two
cannot diverge on regulatory depth the way they once did on RSN depth.
Its `reg_out` parameter is optional and NULL-safe.

**Slice 1 is inert by design.** It parses and stops: no regulatory
table, no channel-legality decision, no alert type, no field on
`probe_ap_t`, no view, no JSONL record, no SQLite column. Reading a
claim is not the same as judging it, and the judging half needs a
versioned regulatory table that this half must not pre-empt. Every
caller passes NULL today.

Malformed elements are counted (`malformed_country`,
`malformed_power_constraint`, `malformed_tpc`) in the same spirit as
`beacon_rsn_t`'s `ie_overruns`: a truncated or crafted regulatory
element is itself a signal, so it is recorded rather than silently
skipped.

Tests are hand-built byte arrays in `tests/test_reg_ie.c`, per
`agents/AGENTS.md` — the issue's pcap-fixture test plan is deferred to
the `needs-pcap-fixture` follow-up layer it belongs to.

## Related pages

- [[mac-randomisation]] — the seqnum deanonymisation primitive in
  depth.
- [[non-ip-sensors]] — the passive sensor registry each radio joins.
- [[attack-map]] — entries for evil-twin, PMKID harvest, PNL leakage,
  hidden-SSID disclosure all live here.
- [[views-catalog]] — full view index.
