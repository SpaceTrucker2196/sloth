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

## Related pages

- [[mac-randomisation]] — the seqnum deanonymisation primitive in
  depth.
- [[attack-map]] — entries for evil-twin, PMKID harvest, PNL leakage,
  hidden-SSID disclosure all live here.
- [[views-catalog]] — full view index.
