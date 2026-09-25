# Seqnum  `[j]`

Sequence-number correlation across MAC rotations. Reports pairs of
addresses whose counters are **consistent with** one physical radio
rotating its MAC, with a score and the evidence window behind it.

> **Read this before acting on a row.** A correlation is evidence about a
> **radio**, not an identification of a **person**. A MAC address is not a
> person; in some jurisdictions it is personal data in its own right (UK
> ICO guidance on Wi-Fi location analytics), and hashing it does not make
> longitudinal tracking anonymous — a stable pseudonym tracked over time
> is still tracking. These records **must not be used on their own** for
> personnel action, physical identification of an individual, or
> automated containment. See [Limits on use](#limits-on-use).

## Protocol

Every 802.11 frame carries a 16-bit **Sequence Control** field; the
upper 12 bits are a per-station sequence number that increments on each
transmitted frame. The counter lives at the chipset level — below the
OS's MAC-randomisation logic. Most popular stacks (iOS, Android, macOS,
Windows, Linux) do **not** reset or randomise the seqnum across a MAC
rotation; they emit a monotonic counter across "different" MACs.

That is the leak. It is also only 12 bits — 4096 positions — which is
the part that matters for how the finding is phrased. Two independent
radios in a busy room land near each other on that counter often enough
that an any-pair match across many histories is a *candidate*, not a
conclusion. See [Calibration](#calibration) for the measured rate.

## What sloth captures

Per source MAC observed in any 802.11 frame the monitor radio decodes:

- The most recent 8 sequence numbers + their timestamps (newest-first
  ring).
- Total frame count, last seen, randomised-MAC flag.

Records are dropped once nothing has been heard from the address for
`SEQNUM_CLIENT_RETAIN_S` (3600 s, or the correlation window if that is
longer). Before #94 the only way out of the table was eviction on fill,
so a quiet sensor kept every address it had ever heard for the life of
the process.

## What makes a pair

A pair is reported only when **every** one of these holds. Each removes
a class of false pair the pre-#94 rule accepted:

| Requirement | Why |
|---|---|
| **Freshness** — both addresses heard within `--correlate-retain` (default 300 s) of *now* | A claim about the present must rest on present evidence. Two stale trails that were once close described nothing current, and used to keep producing live suggestions indefinitely. |
| **Ordering** — the earlier address's last frame is at or before the later address's first | A rotation has a before and an after. |
| **Exclusivity** — the two addresses are not concurrently active | One radio holds one address at a time. Interleaved transmissions are two radios however close their counters sit. |
| **Direction** — the counter advanced **forward** by 1…64 across the seam | Absolute modular distance cannot tell a counter that advanced 5 from one that went back 5, and only the first is one radio's counter continuing. Zero is excluded: a repeated value is a duplicate, not a continuation, and duplicates are the commonest coincidence in a dense room. |
| **Immediacy** — at most 30 s between the two frames at the seam | A rotation is a seam in one stream. |
| **Continuity** — each trail runs forward on its own | A trail that does not is not a counter that can be extrapolated across an address change. |
| **Score** — confidence at or above 20 % | Below the floor the evidence is at the coincidence rate the fixture measures. |

Reported pairs sort by **descending confidence**. Gap alone used to
order them, which put a one-frame-each coincidence above a full trail
whenever its gap happened to be smaller.

## Confidence

A percentage, capped at **90** — there is no passive observation that
closes the gap to certainty, so the scale does not reach 100. Terms:

| Term | Weight |
|---|---:|
| forward gap 1–4 / 5–16 / 17–32 / 33–64 | +40 / +28 / +16 / +8 |
| seam ≤ 2 s / ≤ 8 s / ≤ 16 s / longer | +20 / +12 / +6 / 0 |
| trail depth (thinner side) ≥ 6 / ≥ 4 / ≥ 2 / 1 | +20 / +12 / +6 / 0 |
| exactly one randomised address | +14 |
| both randomised | 0 |
| neither randomised | −10 |

**It is a ranking of evidence strength, not a posterior probability.**
How often a reported pair is actually one radio depends on the base rate
of rotations in the environment, which sloth cannot observe. In a room
of sixty randomising handsets and no rotations, every accepted pair is
wrong no matter what it scores.

The strongest reading — the heat-red row — requires a high score **and**
exactly one randomised address (`seqnum_corr_is_strong()`). That is
structural on purpose: coincidences reach the same numeric band, and the
only thing that separates a rotation is its *shape*, one rotating address
beside one anchor identity. A both-randomised pair is a real case too
(one phone across two rotations), so it is still reported with its
score — it is just not presented as the strongest evidence there is.

## Calibration

`tests/test_seqnum_track.c :: test_dense_environment_false_pair_rate`
builds 64 independent radios, each with a monotonic 8-frame trail
starting at a random one of only 512 counter positions, each active in
its own non-overlapping four-second slot — so every pair is false by
construction and the thing being measured is counter coincidence alone.

It prints the rate on every `make test`:

```
dense fixture: 59/2016 candidate pairs accepted = 2.927% false-pair rate,
top score 80% (64 independent radios, 512 sequence positions)
```

The same fixture against the pre-#94 rule accepted **472/2016 =
23.413 %**. The issue's arithmetic — 129/4096 differences inside modular
distance 64, ≈ 3.15 % per comparison for two independent uniform values
— is an estimate about a *model*; real trails are dependent, so the
number above is a measurement of this code and the estimate is not
quoted as if it were one.

## Configuration

Correlating addresses across a rotation is longitudinal tracking of a
device. That is a different purpose from observing what is on the air
now, so it is switched and retained separately:

| Flag | Default | Effect |
|---|---|---|
| `--no-correlate` | correlation **on** | No pair is linked, scored, exported or stored. Per-MAC trails still render — those are observation. |
| `--correlate-retain SECS` | 300 | Evidence window. A pair is reported only while **both** addresses have been heard inside it, counted from now. Also raises the per-MAC record horizon when set above 3600. |

**Stated purpose**: to tell an operator that two addresses on their own
segment may be one device, so that device counts, alert dedup and
transit passes are not inflated by MAC rotation. It is not there to
build a movement history of an individual, and the retention default is
set for that purpose — five minutes of evidence, not a day of it.

Sloth announces the setting at startup so an operator does not have to
read the source to find out it is on:

```
sloth: device correlation ON (seqnum trails across MAC rotations,
evidence retained 300s; hypothesis only — not identification)
```

## View

```
 Seqnum tracker: 6 clients, 2 correlations  [up/dn] navigate correlations  [c] clear
 Possible device correlation — same-radio hypothesis, not identification (retain 300s)
 MAC A             rnd   MAC B             rnd    fwd      dt  window       support
 ----------------- ---   ----------------- ---   ----  ------  -----------  --------------------
 a0:b1:c2:d3:e4:f5 -     02:aa:bb:cc:dd:ee Y        1      2s   8v6/6s      80% possible rotation
 02:aa:bb:cc:dd:ee Y     02:11:22:33:44:55 Y       12     11s   4v3/14s     46% moderate
  A correlation is evidence about a radio. Not an identification of a person, and not
  grounds on its own for personnel action, physical location, or automated containment.

 Per-MAC seqnum history (newest left)
 MAC                vendor          rnd   age   recent seqnums
 -----------------  --------------  ----  ----  -----------------------------------
 a0:b1:c2:d3:e4:f5  Apple           -     5s    1247 1246 1245 1244 1243 1242
 02:aa:bb:cc:dd:ee  (random)        Y     9s    1252 1251 1250 1249 1248
 02:11:22:33:44:55  (random)        Y     19s   1260 1259 1258
```

`window` is `<A depth>v<B depth>/<span>s` — the trail depth each side
and the wall-clock span the pair was decided over.

## What's normal

- A handful of clients in radio range, each with their own trail and no
  correlation at all.
- Real (burned-in) MACs that correlate with nobody.
- Weak rows in a busy environment. That is the measured coincidence rate
  being shown honestly rather than hidden.

## What's interesting (SIGINT-wise)

- **A randomised MAC correlating tightly with a burned-in MAC**: the
  anchored shape, and the only one that reaches the top band. Strongest
  when the burned-in MAC's OUI maps to a known vendor.
- **Two randomised MACs correlating**: possibly one device across two
  rotations. Corroborate it before relying on it — [PNL](pnl.md) overlap
  is the usual second source.
- **A chain of correlations** (A→B→C→D over time): consistent with one
  device's rotation cadence. Each hop carries its own score; a chain is
  no stronger than its weakest link and the scores do not add.

## What this misses

- Devices that randomise the seqnum (rare; custom firmware, research
  builds, some patched Linux drivers).
- Devices quiet across the rotation for longer than the 30 s seam.
- Cross-channel correlations when the sniffer sees one channel at a time
  — and this cuts both ways: channel hopping makes trails look
  interleaved, which the exclusivity test rejects.
- Wi-Fi 7 MLDs structurally: an MLD's radios have independent sequence
  spaces. See `wifi_mld` in [[jsonl-schema]].

## Limits on use

1. A correlation identifies a **radio**, at best. Not a person, not an
   account, not an employee.
2. A MAC address can be **personal data**. UK ICO guidance on Wi-Fi
   location analytics treats it that way, and hashing it does not change
   the analysis: a stable pseudonym followed over time is longitudinal
   tracking of an individual by another name.
3. **Not sufficient for personnel action**, physical identification, or
   automated containment. The score is a ranking, the base rate is
   unobserved, and every row has innocent explanations.
4. Corroborate with an independent source before acting — an
   association, a DHCP lease, a PNL overlap, an inventory entry.
5. Retention is a decision, not a default to inherit. See
   `--correlate-retain` and [[retention]].

## See also

- [pnl.md](pnl.md) — confirm a correlation with shared PNL contents
- [probe.md](probe.md) — raw probe stream that feeds the tracker
- [alerts.md](alerts.md) — `MY_NET_RECON`, which consumes correlations
  as an *exoneration*
- `docs/wiki/mac-randomisation.md` — the concept page
- "Why MAC Address Randomisation is not Enough" (Vanhoef et al.) — the
  paper that originally exposed the seqnum leak
