---
source_url: https://www.ecfr.gov/current/title-47/chapter-I/subchapter-A/part-15/subpart-E/section-15.407
retrieved: 2026-10-20
topics: [dfs, radar, regulatory, fcc, etsi, unii, 5ghz, cac, heuristic]
alert_kinds: [ALERT_TYPE_DFS_MASKING]
citation: 47 CFR §15.407 (a)(1)-(3), (h)(2) (U-NII bands, radar detection); FCC KDB 905462 D02 (DFS compliance procedures, 60 s channel availability check); ETSI EN 301 893 V2.1.1 (2017-05) §4.2.6 (DFS, incl. 10 min CAC on 5600-5650 MHz) under Directive 2014/53/EU and Commission Decision 2005/513/EC as amended by 2007/90/EC
---
# DFS — why a BSS rarely starts cold on a radar channel

Clause-annotated summary of the two sources the compiled-in channel
table (`src/reg_table.c`, `docs/wiki/regulatory-table.md`) is built
from, and of the inference `ALERT_TYPE_DFS_MASKING` draws from them.
Our own description, not an excerpt.

## The rule both regulators impose

- **FCC, 47 CFR §15.407.** U-NII-1 (5150-5250 MHz, channels 36-48) and
  U-NII-3 (5725-5850 MHz, 149-165) carry no radar-detection duty.
  U-NII-2A (5250-5350, 52-64) and U-NII-2C (5470-5725, 100-144) do:
  §15.407(h)(2) requires dynamic frequency selection there. The test
  procedure that sets the channel availability check (CAC) at 60 s
  before first transmission is the FCC's DFS guidance, KDB 905462 D02,
  not the section itself.
- **ETSI, EN 301 893 V2.1.1.** The harmonised standard for 5 GHz RLAN
  under the Radio Equipment Directive 2014/53/EU, with the band plan of
  Commission Decision 2005/513/EC (amended 2007/90/EC). It covers
  5150-5350 and 5470-5725 MHz only; DFS applies on 5250-5350 and
  5470-5725, with a 60 s CAC, extended to 10 minutes on channels
  touching 5600-5650 MHz (weather radar: 120, 124, 128 at 20 MHz).
  Channel 144 is not in it (5710-5730 MHz runs past 5725), and nor are
  149-165, which other ETSI documents and national rules address.

So on 52-64 and 100-144 a transmitter must listen, silent, before it
may beacon — and must leave the channel when it detects radar, which is
what a Channel Switch Announcement (sloth #63) is for.

## The inference, and why it is only a heuristic

A BSS normally reaches a DFS channel in one of two ways: it was there
before the monitor started, or it moved there by announcing a switch.
A BSSID that appears for the first time on a DFS channel *after* the
RF picture settled, with no CSA leading there, came up cold on a
channel most clients scan only passively and many WIDS cover lightly.
The issue names that as an evasion: an evil twin on hostapd with
`ieee80211h=0`, hiding where the defenders look least.

**No public advisory names DFS-masking as a WIDS-evasion pattern.** The
issue says so, and the alert text carries the caveat. A legitimate AP
that reboots onto a DFS channel after its CAC produces exactly the same
observation, as does an AP whose channel a hopping radio first reached
late. That is why sloth reports it at LOW, raises it to WARN only on
corroboration from outside the rule (a designated SSID from a BSSID
that is not designated, or a BSSID already in an evil-twin episode),
and assigns no ATT&CK technique: the finding is a shape, not an
observed adversary action. `tests/test_research_corpus.c ::
test_uncitable_kinds_with_a_real_basis_are_still_cited` holds this
document as its source.

## What the table is not

It is a heuristic aid dated 2026-10-20, not a statement of law. It
answers "does this source list the channel, and does it require radar
detection there" for two jurisdictions — the two whose primary sources
were read. It says nothing about licences, indoor-only conditions,
national deviations or power limits, and it will go stale when either
rule is amended. See `docs/wiki/regulatory-table.md`.

## Related sloth alert kinds

`ALERT_TYPE_DFS_MASKING` — LOW/WARN, keyed per BSSID.
