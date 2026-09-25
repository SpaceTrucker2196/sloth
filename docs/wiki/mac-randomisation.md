---
name: mac-randomisation
description: The 802.11 sequence-number deanonymisation primitive — why MAC randomisation isn't enough
type: reference
---

# MAC randomisation

**Summary**: Modern OSes randomise the MAC address of unassociated 802.11 frames (probe requests). The 12-bit sequence counter in every 802.11 header doesn't get randomised — it lives at the chipset level. Sloth uses that to report pairs of addresses that **may** be one radio, with a calibrated score and the evidence window behind it.

**Sources**: `docs/views/seqnum.md`, `docs/views/pnl.md`, `docs/views/probe.md`, `include/seqnum_track.h`, `src/seqnum_track.c`, `tests/test_seqnum_track.c`, issue #94.

**Last updated**: 2026-09-25 (#94 — correlation honesty).

---

## Limits on use — read first

A correlation is evidence about a **radio**. It is not an identification
of a **person**, and nothing in sloth may be read as one.

- A MAC address can qualify as **personal data**. UK ICO guidance on
  Wi-Fi location analytics treats it that way. **Hashing a MAC does not
  make longitudinal tracking anonymous** — a stable pseudonym followed
  over time is tracking of an individual under another name.
- These records, **alone, must not be used** for personnel action,
  physical identification of an individual, or automated containment.
  Corroborate with an independent source first: an association, a DHCP
  lease, a PNL overlap, an inventory entry.
- The score ranks evidence strength. It is **not a posterior
  probability**: how often a reported pair is really one radio depends on
  the base rate of rotations in that environment, which sloth cannot
  observe.

This section is the charter for the whole primitive, not a footnote to
it. The capability is genuinely useful for its stated purpose — stopping
one handset being counted as four devices — and genuinely misusable for
building a movement history of a named individual. The wording, the
score, the retention default and the `--no-correlate` switch all exist to
keep the first without enabling the second.

## The leak

Every 802.11 frame carries a 16-bit **Sequence Control** field. The
upper 12 bits are a per-station sequence number that increments on
each transmitted frame. The counter lives at the chipset level, below
the OS's MAC-randomisation logic.

Every popular stack (iOS, Android, macOS, Windows, Linux) emits a
**monotonic** sequence counter across MAC rotations. Two "different"
MACs whose trails fall on the same forward-running counter are
**consistent with** one physical radio.

The counter is also only 12 bits — 4096 positions — and that is the half
of the primitive that used to go unsaid. Independent radios in a busy
room land near each other on it routinely, so an any-pair match across
many trails needs a calibrated score, not the phrase "same device". See
[Calibration](#calibration).

## Recognising a randomised MAC

The IEEE locally-administered bit is bit 1 of the first octet (0x02
mask). Common randomised first bytes: `02:`, `06:`, `0a:`, `0e:`.
Sloth flags these as `rnd=Y` everywhere it surfaces MACs.

## Sloth's correlation

Implementation: `src/seqnum_track.c`, contract in
`include/seqnum_track.h`, rendering in `src/views/seqnum.c`. Per source
MAC: the most recent 8 sequence numbers + timestamps (newest-first ring),
frame count, last seen, randomised flag. Records are dropped once stale
past `SEQNUM_CLIENT_RETAIN_S` (3600 s) — they are no longer kept until
the table fills.

On snapshot every pair is tested, and a pair is reported only if **all**
of these hold — freshness inside `--correlate-retain`, temporal ordering,
no concurrent activity, a **forward** counter advance of 1…64, at most
30 s at the seam, each trail internally forward-running, and a score at
or above 20 %. Full table with the reasoning per requirement:
[`docs/views/seqnum.md`](../views/seqnum.md). Pairs sort by descending
confidence.

The heat-red row means **possible rotation** and requires a high score
*and* exactly one randomised address. The structural half is the point:
coincidences reach the same numeric band, and only the *shape* — one
rotating address beside one anchor identity — distinguishes a rotation.

### What #94 changed, and why

The pre-#94 rule minimised **absolute** modular distance over the cross
product of two trails and accepted any pair inside a flat 64-seqnum,
30-second window, with no expiry anywhere. It then labelled the result
`LIKELY SAME DEVICE`. Four defects, each now closed:

1. **No expiry.** Nothing aged out except on table fill, so two trails
   that were once close kept producing *current* "same device"
   suggestions for the life of the process.
2. **No direction.** Absolute distance cannot separate a counter that
   advanced 5 from one that went back 5. Only the first is a rotation.
3. **No exclusivity.** Two addresses transmitting through the same
   seconds are two radios; the rule paired them anyway.
4. **A categorical claim from circumstantial evidence.** The output
   named a conclusion instead of scoring a hypothesis, and these records
   are the kind that end up quoted in a personnel file.

## Calibration

`tests/test_seqnum_track.c :: test_dense_environment_false_pair_rate`
builds 64 independent radios, each running its own monotonic 8-frame
trail from a random one of only 512 counter positions, each active in its
own non-overlapping slot — every pair false by construction. It prints
the rate on every `make test`:

| Rule | Accepted | Rate |
|---|---|---|
| pre-#94 | 472 / 2016 | **23.413 %** |
| current | 59 / 2016 | **2.927 %** (top score 80 %) |

The issue's arithmetic (129/4096 differences inside modular distance 64,
≈ 3.15 % per comparison for two independent uniform 12-bit values) is an
estimate about a *model*. Real trails are dependent, so the table above
is a measurement of this code and the estimate is not quoted in its
place.

## Configuration and retention

Longitudinal correlation is switched and retained separately from
capture, because linking addresses over time is a different purpose from
watching the air:

- `--no-correlate` — no pair is linked, scored, exported or stored.
  Per-MAC trails still render; those are observation.
- `--correlate-retain SECS` (default **300**) — both addresses must have
  been heard inside this window, counted from now.

Stated purpose: keep device counts, alert dedup and transit passes from
being inflated by MAC rotation. The five-minute default is set for that
purpose. See [[retention]].

## What this misses

- Devices that explicitly randomise the seqnum (rare; mostly custom
  firmware, research builds, certain patched Linux drivers).
- Devices that go quiet across the rotation for longer than the 30 s
  seam.
- Cross-channel correlations when the sniffer is on one channel at a
  time — and this now cuts both ways: hopping makes trails look
  interleaved, which the exclusivity test rejects.
- Wi-Fi 7 MLDs structurally — independent sequence spaces per link.

## How it pairs with other views

- **PNL match in addition to a seqnum match** — see [[wifi-sigint]] — is
  the strongest combination available, because it is a *second
  independent* observable rather than more of the same one. It is still
  corroboration, not certainty: PNL lists are not unique, and a shared
  home SSID is common.
- A **randomised MAC ↔ burned-in MAC** correlation is the anchored
  shape, and the only one the view will call possible rotation. Most
  useful when the burned-in OUI maps to a known vendor.
- A **chain of correlations** (A→B→C→D) is consistent with one device's
  rotation cadence. Each hop carries its own score; the chain is no
  stronger than its weakest hop and the scores do not compound.
- `MY_NET_RECON` consumes correlations as an **exoneration** — a
  rotating probe address correlated with an associated real one means
  the device is on the network, not reconnoitring it (see [[alerts]]).

## Reference

"Why MAC Address Randomization is not Enough" — Vanhoef et al. The
paper that originally exposed the seqnum leak.

## Related pages

- [[wifi-sigint]]
- [[attack-map]] — "MAC-randomisation deanonymisation" entry.
- [[alerts]] — severity vs confidence, and the corroboration doctrine
  this primitive now follows.
- [[retention]] — what sloth deletes and when.
- [[jsonl-schema]] — the `seqnum_correlation` record's evidence fields.
