# `[c]` FragAttacks

**Issue:** [#75](https://github.com/SpaceTrucker2196/sloth/issues/75) ·
**Code:** [`src/views/fragattack.c`](../../src/views/fragattack.c),
[`src/fragattack.c`](../../src/fragattack.c) ·
**See also:** [`alerts.md`](alerts.md),
[the FragAttacks notes](../wiki/fragattacks.md)

## Protocol

None new. This view reads no packets — it mirrors the per-BSS counters
`src/fragattack.c` already maintains for the seven FragAttacks
detectors (Vanhoef, USENIX Security 2021) that have been shipping
since #75 slice 1.

## What sloth captures

Nothing new. `frag_snapshot()` runs once per poll, after `alerts_update()`,
and copies the per-BSS table into `frag_bss_row_t` rows sorted by
`last_hit` descending — the BSS that just produced a finding is at the
top. One row per BSSID; a detail pane below shows the seven-CVE
breakdown for the selected row.

No new SQLite table and no per-event evidence blob. `src/alert_pcap.c`
already writes a per-alert pcap with the triggering frames, which is a
better fixture seed than truncated bytes in a database row and needs
no schema change — this view is a counter table, not an event log.

## Mockup

```
 FragAttacks (#75): 2 BSSIDs tracked, 4 findings across 7 CVEs
 BSSID                FINDINGS  LAST SA -> DA                           AGE
 ------------------  --------  --------------------------------------  ----
>02:aa:bb:00:00:01           3  02:aa:bb:00:00:10 -> 02:aa:bb:00:00:20  12s
 02:aa:bb:00:00:02           1  02:aa:bb:00:00:30 -> 02:aa:bb:00:00:40  3m

 ── FragAttacks findings for 02:aa:bb:00:00:01 ──
  FRAG_PLAINTEXT     CVE-2020-26140/-26143        2
  FRAG_BCAST         CVE-2020-26145               0
  FRAG_CACHE         CVE-2020-24586               0
  FRAG_MIXED         CVE-2020-26147               0
  FRAG_AMSDU         CVE-2020-24588               1
  FRAG_AMSDU_EAPOL   CVE-2020-26144               0
  FRAG_MIXKEY        CVE-2020-24587               0
  1 protected frame witnessed on this BSSID (key-install gate)
```

`↑`/`↓` move the selection; the pane below shows that BSSID's
breakdown.

## Normal

Zero rows. Every FragAttacks CVE is either a design flaw in the 802.11
aggregation/fragmentation path or an implementation bug — a conforming
stack producing any of the seven findings has essentially no benign
explanation (see [`alerts.md`](alerts.md) for each rule's stated benign
trigger, mostly "a driver bug").

Zero **findings** with a nonzero **protected frame** count is also
normal, and is the common case on any encrypted network sloth
monitors: `protected_frames` is the key-install gate's own evidence
counter (a station was witnessed sending an encrypted frame), not a
finding. Summing it into the findings total would make an ordinary
encrypted BSS with no attacks read as hundreds of hits — the view
deliberately keeps it a separate line under the detail pane instead.

## Suspicious

Any nonzero row. Each of the seven counters maps to one CVE with its
own detection logic — see [`alerts.md`](alerts.md) for what each rule
actually watches for and its false-positive gates, and
[the FragAttacks notes](../wiki/fragattacks.md) for the full mechanism,
including the two CVEs (-26139, -26146) not built and why.

The `LAST SA -> DA` pair and `AGE` column are for triage: which station
pair produced the most recent hit, and how long ago. The per-alert
pcap (`--pcap-dir`) carries the actual offending frames — this view is
a live counter, not the forensic record.

## See also

- [`alerts.md`](alerts.md) — the seven `FRAG_*` rules this view
  summarises, with their CVEs, gates, and benign triggers
- [the FragAttacks notes](../wiki/fragattacks.md) — full detector
  writeup, including what is not built and why
- [`research.md`](research.md) — `[f]`, the sources behind each alert
  kind, including the FragAttacks paper citation
