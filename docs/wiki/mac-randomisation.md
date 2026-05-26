---
name: mac-randomisation
description: The 802.11 sequence-number deanonymisation primitive — why MAC randomisation isn't enough
type: reference
---

# MAC randomisation

**Summary**: Modern OSes randomise the MAC address of unassociated 802.11 frames (probe requests). The 12-bit sequence counter in every 802.11 header doesn't get randomised — it lives at the chipset level. Sloth uses that to pair "different" MACs that are really the same radio.

**Sources**: `docs/views/seqnum.md`, `docs/views/pnl.md`, `docs/views/probe.md`.

**Last updated**: 2026-05-25.

---

## The leak

Every 802.11 frame carries a 16-bit **Sequence Control** field. The
upper 12 bits are a per-station sequence number that increments on
each transmitted frame. The counter lives at the chipset level, below
the OS's MAC-randomisation logic.

Every popular stack (iOS, Android, macOS, Windows, Linux) emits a
**monotonic** sequence counter across MAC rotations. Two "different"
MACs whose seqnum trails fall on the same counter (within a small
drift window) are almost certainly the same physical radio.

## Recognising a randomised MAC

The IEEE locally-administered bit is bit 1 of the first octet (0x02
mask). Common randomised first bytes: `02:`, `06:`, `0a:`, `0e:`.
Sloth flags these as `rnd=Y` everywhere it surfaces MACs.

## Sloth's correlation

Implementation: `src/views/seqnum.c`. Per source MAC:

- Most recent 8 sequence numbers + their timestamps (newest-first ring).
- Total frame count, first/last seen, randomised flag.

On snapshot, every pair of clients is scanned against every other; a
pair is reported when their trails contain at least one entry within
**64 seqnums** and **30 seconds** of each other. Pairs sort by
ascending gap (smallest gap = strongest match).

"LIKELY SAME DEVICE" rows render heat-red when at least one MAC is
randomised and the gap ≤ 8 — the SIGINT prizes.

## What this misses

- Devices that explicitly randomise the seqnum (rare; mostly custom
  firmware, research builds, certain patched Linux drivers).
- Devices that go quiet between MAC rotations long enough for the
  30 s window to expire.
- Cross-channel correlations when the sniffer is on one channel at a
  time.

## How it pairs with other views

- **PNL match** in addition to a seqnum match — see [[wifi-sigint]] —
  is essentially a forensic certainty: two randomised MACs share both
  the chipset counter trail and the SSID-list fingerprint.
- A **randomised MAC ↔ burned-in MAC** correlation identifies the
  device that's randomising. Doubly useful when the burned-in MAC's
  OUI maps to a known vendor (Apple, Intel, Samsung).
- A **chain of randomised MACs** (A→B→C→D over time) traces the
  rotation cadence of a single device.

## Reference

"Why MAC Address Randomization is not Enough" — Vanhoef et al. The
paper that originally exposed the seqnum leak.

## Related pages

- [[wifi-sigint]]
- [[attack-map]] — "MAC-randomisation deanonymisation" entry.
