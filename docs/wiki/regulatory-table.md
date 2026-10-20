---
name: regulatory-table
description: The compiled-in 5 GHz channel table (src/reg_table.c) — cited to 47 CFR 15.407 and ETSI EN 301 893, dated, and heuristic
type: reference
---

# Regulatory channel table

**Summary**: sloth carries a small compiled-in table of 5 GHz channels for two jurisdictions — the FCC (47 CFR §15.407) and ETSI (EN 301 893, applied in the EU member states) — recording which 20 MHz channels each source lists and which of them require radar detection (DFS). It is **cited, dated 2026-10-20, and heuristic**: an aid to reading what an AP does, never a statement of what is lawful where the AP stands. Today one rule reads it, `DFS_MASKING`.

**Sources**: `src/reg_table.c`, `src/reg_table.h`, `research/regulatory/dfs-15.407-en301893.md`, 47 CFR §15.407 (eCFR, read 2026-10-20), FCC KDB 905462 D02, ETSI EN 301 893 V2.1.1 (2017-05), Directive 2014/53/EU, Commission Decision 2005/513/EC as amended by 2007/90/EC, the EU member-state list on europa.eu. Issue #101 slice A; owner rulings on #145.

**Last updated**: 2026-10-20 (#101 slice A: table created).

---

## What it is for, and what it is not

A compiled-in claim about law goes stale the day the rule it encodes is
amended, and an operator reading an alert has to know whether it rests
on a regulation or on a guess. So three framings hold everywhere the
table surfaces — in the code, in alert detail, here:

- **Cited.** Every row names the clause it was read from. A row with no
  primary source is not added (owner ruling 2 on #145: no table row
  without one). That is why there are two jurisdictions and not the
  eight the issue lists: JP, CN, IN, GB, CA and AU each need their own
  source read before they get rows.
- **Dated.** `REG_TABLE_AS_OF` (`2026-10-20`) is when the rows were last
  checked against the sources. `DFS_MASKING`'s detail prints it.
- **Heuristic.** It answers "does this source list the channel, and does
  it require radar detection there". It does not model licences,
  indoor-only conditions, national deviations, transmit-power limits,
  U-NII-4 or 6 GHz. A channel missing from a table means "not in this
  source", not "unlawful": EN 301 893 does not cover 5725-5850 MHz at
  all, and other ETSI documents and national rules do.

Embedded in-tree (owner ruling 8), not loaded from a runtime file, so
the table a binary used is the table its source tree shows.

## Country → table

The AP's own Country element (tag 7, [[wifi-sigint]]) chooses the table:

| Country element | Table |
|---|---|
| `US` | FCC |
| `AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE` (EU-27, ISO 3166-1 — Greece is `GR`) | ETSI |
| anything else, absent, malformed, or lower case | none — the **union** of both tables |

The union is the conservative reading for a passive monitor: a channel
is DFS if any source here requires it, and the CAC is the longest any
of them imposes. In practice the two agree everywhere except 144, which
only the FCC lists. EEA states and the UK apply the same or a derived
standard by their own instruments, which were not read, so they are not
mapped.

## FCC — 47 CFR §15.407

| Channels | MHz (20 MHz centres) | DFS | CAC | Clause |
|---|---|---|---|---|
| 36, 40, 44, 48 | 5180-5240 | no | — | §15.407(a)(1), U-NII-1 |
| 52, 56, 60, 64 | 5260-5320 | yes | 60 s | §15.407(a)(2), (h)(2), U-NII-2A |
| 100-144 (step 4) | 5500-5720 | yes | 60 s | §15.407(a)(2), (h)(2), U-NII-2C |
| 149, 153, 157, 161, 165 | 5745-5825 | no | — | §15.407(a)(3), U-NII-3 |

The 60 s channel availability check comes from the FCC's DFS test
procedure, KDB 905462 D02, not from §15.407 itself. Channel 144 straddles
the U-NII-2C/U-NII-3 edge at 5725 MHz; its 5470-5725 part is what makes
it DFS. U-NII-4 (5850-5895) is absent because it was not verified for
this table.

## ETSI — EN 301 893 V2.1.1

| Channels | MHz (20 MHz centres) | DFS | CAC | Clause |
|---|---|---|---|---|
| 36, 40, 44, 48 | 5180-5240 | no | — | 5150-5250 MHz |
| 52, 56, 60, 64 | 5260-5320 | yes | 60 s | 5250-5350 MHz, §4.2.6 |
| 100, 104, 108, 112, 116 | 5500-5580 | yes | 60 s | 5470-5725 MHz, §4.2.6 |
| 120, 124, 128 | 5600-5640 | yes, weather radar | 600 s | 5600-5650 MHz, §4.2.6 |
| 132, 136, 140 | 5660-5700 | yes | 60 s | 5470-5725 MHz, §4.2.6 |

Not listed: 144 (5710-5730 MHz runs past 5725) and 149-165 (outside the
standard's scope).

## Who reads it

- **`DFS_MASKING`** (`src/alerts/rules_regulatory.c`): does the channel
  a BSSID was first heard on require radar detection? The detail names the table
  that answered ("FCC", "ETSI", or "FCC+ETSI" for the union), the date,
  and the CAC. See [[alerts]] and `docs/views/alerts.md`.

`COUNTRY_ABSENT` does not read it: a missing Country element is judged
against IEEE 802.11d, not against a regulator's channel plan.

Channel-in-country validation (an AP naming `DE` on channel 149, say) is
what the table makes possible next; it is not built in this slice.

## Changing it

Edit `src/reg_table.c` and this page in the same change, bump
`REG_TABLE_AS_OF`, and cite the clause for every row added.
`tests/test_reg_table.c` pins the row sets, the DFS flags, the CACs and
the country mapping to the values in the tables above, so an edit to
the code that this page does not also describe goes red.

## Related pages

- [[alerts]] — `DFS_MASKING`, `COUNTRY_ABSENT`, `TPC_ABSENT_HIGH_BAND`.
- [[wifi-sigint]] — the regulatory envelope sloth parses (Country, Power Constraint, TPC Report).
- [[research-corpus]] — where the citing documents live.
