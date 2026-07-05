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
- **Seqnum (j)** — pairs randomised MACs that emit frames on the same
  monotonic 12-bit sequence counter. See [[mac-randomisation]] for the
  full explanation.
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

## Related pages

- [[mac-randomisation]] — the seqnum deanonymisation primitive in
  depth.
- [[non-ip-sensors]] — the passive sensor registry each radio joins.
- [[attack-map]] — entries for evil-twin, PMKID harvest, PNL leakage,
  hidden-SSID disclosure all live here.
- [[views-catalog]] — full view index.
