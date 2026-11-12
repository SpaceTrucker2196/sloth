# KARMA  `[y]`

Materialised view of KARMA / PineAP candidate APs — one row per BSSID
beaconing an abnormal number of distinct SSIDs, the "answer every
network a client probes for" lure (#30), or answering stations'
directed probes for SSIDs it never beaconed (#187 S2).

## Protocol / data source

Built passively each poll by `karma_update()` from `s->beacon_aps[]`
(distinct-SSID history per BSSID), the client PNLs in
`s->pnl_clients[]`, and the deauth impact aggregates
`s->deauth_victims[]`, and since #187 S2 the directed-probe answers
in `s->karma_forge` (`karma_forge_snapshot()`). No new
radio traffic — every input is already captured by the beacon snooper,
the probe/PNL tracker, and the deauth tracker. The view reads only
`s->karma_aps[]`.

## What sloth captures

Per candidate:

- **SSIDs** — count of distinct SSIDs this BSSID has beaconed
  (`beacon_ap_t.ssid_history_n`). Legit multi-VAP APs sit at 1–4; a
  PineAP / `mdk4 b` / `airbase-ng -P` lure climbs past the
  `KARMA_SSID_THRESH` of 3.
- **PNL** — how many of those SSIDs appear in the union of nearby
  clients' preferred-network lists. **Reported, not scored** (#90): the
  union says somebody around here remembers one of these names, which
  common SSIDs guarantee. The column goes bright, and the score picks
  up its `+2`, only when a *single* station's list asks for at least
  `KARMA_PNL_CORROB_MIN` = 2 of them — PineAP Beacon Response answers
  one station's probes for its whole remembered list, and that shape is
  what separates an active lure from a benign SSID-cycling AP. The
  union still feeds the J% denominator below.
- **J%** — Jaccard similarity between the advertised SSID set and the
  client-PNL union (`|A∩B| / |A∪B|`), shown as a percentage. Trends
  toward 100% as the AP mirrors the entire union of probed networks —
  the sharpest PineAP tell. Rendered bright at ≥70%.
- **IE** — how many **distinct** IE fingerprints (encryption / cipher /
  AKM / MFP + vendor-IE hash) this BSSID's advertised SSIDs came back
  with, or `-` when any of them has none recorded. `1` against an SSIDs
  column of 4 is the *IE-fingerprint collapse* (#187): four names, one
  security posture. It is rendered bright, and adds `+1` to the score.
  The cell printed `Y`/`-` before #187 and spent the same `-` on
  "postures differ" and "nothing observed", which are opposite
  readings.

  **What the collapse is and is not worth.** A collapse is weak,
  same-direction corroboration, which is why the `KARMA_AP` alert pays
  it only `KARMA_W_IE_COLLAPSE` = 10 confidence and never escalates
  severity on it. The contrast usually claimed for this signal — one
  spoofing radio versus multi-VAP gear that varies RSN and vendor IEs
  per VAP — is **not** the contrast sloth can draw here: a BSSID
  belongs to exactly one BSS, and the VAPs of real multi-SSID gear each
  get their own BSSID, so each of them carries one SSID and never
  becomes a candidate at all. The one shape that does put several SSIDs
  behind a single transmitted BSSID is the 802.11ax Multiple BSSID set,
  and sloth does not decode its nontransmitted profiles
  ([[fragattacks]]). What is left crossing the threshold benignly is a
  BSS renamed over a long session, or hotspot gear cycling SSIDs — and
  those keep one posture, so they collapse exactly as a lure does.

  The sharper reading is the **converse**: a count that tracks the SSID
  count is the AP showing genuinely different security postures per
  name, which a single spoofing radio does not do. That is why the
  count is printed in both directions rather than only when it
  incriminates. Since 2026-11-12 (#187, owner decision) it costs the
  `KARMA_AP` alert 15 confidence (`KARMA_W_IE_VARIETY`, named
  `+IE variety` in the detail) whenever two or more distinct, all-known
  fingerprints are present; this view's score is unchanged.
  Basis: `research/papers/mbssid-per-bss-ie-variation.md`.
- **chain** — a **shared-victim** deauth-then-lure chain (#90): a
  station deauthed off a *different* BSSID within the 60 s window
  (measured from when the flood's threshold was last *met*, not the
  last deauth frame, so a trickle after a flood ends doesn't keep it
  "concurrent" — #88) that this candidate can independently be shown
  to be luring — either the victim's PNL already asks for one of the
  candidate's advertised SSIDs (*one* is enough here, unlike the
  standalone PNL signal above: the flood has already tied this station
  to this candidate, so the PNL entry only has to name a network the
  candidate is answering), or the victim has since associated with the
  candidate. An unrelated flood elsewhere in range, with no
  link to this candidate's own victims, no longer counts
  (`karma_deauth_lure_victim()`, `src/karma_detect.c`) — crediting
  every candidate in range with any concurrent flood was the false
  positive issue #90 reported.
- **FR** — forged answers (#187 S2): how many distinct SSIDs this
  BSSID answered a station's **directed** probe request for while never
  beaconing them (`karma_forged_ssids()`, shared with the
  `KARMA_PROBE_FORGE` alert, so the cell and the alert state one
  number). `-` is none. A BSSID reaches this table on FR alone, at
  `karma.forge_ssids` (2): the classic KARMA radio — `airbase-ng -P`,
  the 2005 paper's access point "that responded to any Probe Request" —
  beacons one name and answers the rest, so it never crosses the SSIDs
  threshold and the beacon-only view could not list it. Bright at the
  threshold. An AP answering for its own name, hidden or not, never
  counts; nor does an answer to a wildcard probe; nor a name the BSSID
  beaconed at any point this session. With no beacon heard from the
  BSSID, or its 8-SSID beacon history full, the count is 0 rather than
  a guess. Basis: `research/papers/daizovi-macaulay-2005-karma.md`,
  `research/tools/airbase-ng.md`.
- **score** —
  `1 + (>=2 PNL hits on one station ? 2 : 0) + (IE uniform ? 1 : 0) + (chain ? 3 : 0) + (FR >= 2 ? 3 : 0)`,
  ranked strongest-first. The PNL term uses the single-station count,
  not the PNL column's union, so the ranking and the `KARMA_AP` alert's
  CRIT gate cannot disagree about one BSSID (#90).
- **tool** — a trailing `[label]` when the tool-signature table
  names the candidate ([[tool-fingerprints]]). A row with no capture
  behind it renders as `[ESP32 Marauder? provisional]` (#90): a
  hypothesis sloth is willing to state, not an identification. Same
  text as the `KARMA_AP` alert detail — both come from
  `tool_attribution_format()`. Display only: it does not move the
  score, because an UNVERIFIED guess is not corroboration, and every
  row shipped today is UNVERIFIED.

The same signals drive the `KARMA_AP` alert in `[v] Alerts`, which adds
a `confidence` percentage and escalates WARN→CRIT only when a
single-station PNL match, the deauth chain, a verified tool match or a
`corroborated` attack-hardware verdict (#151, 2026-11-12) corroborates
the bare SSID count (#90) — this view is the ranked, browsable surface for
the same underlying signals, not a mirror of the alert's severity. The
IE count and the collapse judgement come from `karma_ie_distinct_fp()`
and `karma_ie_collapsed()` (`src/karma_detect.h`), which this view and
the alert rule both call, so the two surfaces cannot state different
numbers about one BSSID — the same reason the PNL measures are shared.

## Open

- **#187 S3, probe-response latency, is not built.** The issue proposes
  a median answer under 2 ms as a confirmer; no primary source for that
  figure, or for the direction of the difference (a user-space soft AP
  answering through hostapd is plausibly *slower* than firmware, not
  faster), was found. Without one the threshold would be a guess.

- IE **variety** in the `[y]` score. The alert spends it as negative
  confidence since 2026-11-12; the ranking score here does not, so a
  varied candidate ranks where it did.
- Collapse is reported per BSSID over the whole SSID history, with no
  time dimension: an AP renamed twice a year ago and a radio cycling
  three names this minute produce the same cell.

## View

```
 ── KARMA ─────────────────────────────────────────────────────────
 KARMA/PineAP candidates: 1 / max 64  deauth-then-lure: 1
 BSSID              SSIDs  PNL   J%    IE  chain  FR  score  Top SSID / last
 -----------------  -----  ----  ----  --  -----  --  -----  ---------------
 00:11:22:33:44:55      7     4  80%   1   YES    -       7  Starbucks (2s)
 02:13:37:00:00:01      1     0  0%    1   -      2       4  default (1s)
 24:6f:28:33:44:55      3     0  0%    3   -      -       1  ACME-Cor (4s)  [ESP32 M~? provisional]
 PNL = SSIDs probed, >=2 on one station; chain = deauth-then-lure on shared victim; FR = forged
 [tool? provisional] = UNVERIFIED signature, no capture: a hypothesis, not an identification
```

The BSSID is bright; PNL and chain go bright when non-zero to draw the
operator's eye.

**Fit at the 100x33 minimum** (#90). The page is sized from the row the
view starts on (under however many rows the tab bar wrapped onto) less
five lines: the status line, the two header lines and the two-line
legend. The legend used to be left out of that budget, so a full table
pushed it off the bottom — the line saying a tool name is a hypothesis.
Each row's tail is fitted to the terminal width so it never reaches the
last column and wraps: the top SSID gives way first, down to 8
characters, then the tool *label*; the `? provisional` part of the
attribution is kept whole while any of the label fits, because that is
the part that says the name is unverified. A clipped label ends in `~`
so a stub is never read as the name of some other tool, and below three
kept characters only the `~` is left. The mockup above is drawn at 100
columns, so its third row (`ACME-Corp`, `ESP32 Marauder`) shows the fit.
With a long SSID and an old age a row can read
`ABCDEFGH (14d)  [Twenty~? provisional]` (an age of a day or more prints in
whole days since #187 S2 took four cells for FR; the attribution has had
no `/conf` word since #151's 2026-11-12 mapping, so the label keeps the
four cells that freed); the full attribution is
in the `KARMA_AP` alert detail and on a wider terminal. Pinned by
`tests/test_karma.c :: test_view_full_page_fits_a_100x33_terminal`,
which draws through `tui_draw()` on a 100x33 offscreen screen.

## What's normal

- Zero rows. Most APs advertise one SSID (or a small fixed set of
  VAPs) and never trip the threshold.
- A single row at score 1 (≥3 SSIDs, no PNL overlap, no deauth):
  worth a glance — some captive-portal gear cycles SSIDs — but not by
  itself an attack. That holds with a `provisional` tool attribution
  on it too: the signature has never been checked against a capture of
  the tool it names.
- **The benign range straddles the threshold.** The SSID count above
  puts legitimate multi-VAP gear at 1–4, and `KARMA_SSID_THRESH` is 3,
  so a lawful 3- or 4-SSID AP trips the count by design. Other
  readings that reach ≥3 without an attacker: a single-radio AP
  carrying several SSIDs on one BSSID, an AP renamed a few times over
  a long session, and a repeater or mesh node rebroadcasting the
  networks behind it. This overlap is why the count alone is a
  candidate signal and why CRIT needs one of the corroborators
  below — not a defect in the threshold.

## What's suspicious

- **FR ≥ 2** — this BSSID told stations it was networks they asked for
  by name, and it has never beaconed those names. That is the KARMA
  mechanism itself, not a property of the beacons; `KARMA_PROBE_FORGE`
  fires WARN on it, and is CRIT once a station that was sent a forged
  name associated under it and was let in (#187, 2026-11-12).

- **Two or more PNL hits on one station** — the AP is beaconing
  several of the networks *one* nearby device is looking for. That is
  the PineAP / KARMA beacon-response fingerprint: the lure answers a
  station's probes for its whole remembered list. A single hit, or
  hits spread one-each across several strangers' devices, is the
  coincidence that used to escalate and no longer does (#90) — the
  count is still shown, so judge it with the J% column beside it.
- **chain = YES** — a station this candidate can be tied to was
  deauthed off a different AP moments ago: the classic
  deauth-then-lure sequence
  ([T1557.004](https://attack.mitre.org/techniques/T1557/004/)), not
  just a flood happening somewhere nearby.
- **score ≥ 5** — multiple signals stacked; treat as an active lure. A
  BSSID at this score is also badged deep-red with a `!` on the
  dashboard's Beacons panel, the same way `THREAT_IP` flags a hostile
  host — so an active lure is visible without leaving the dashboard.
  (Until #116 the `!` was drawn in the panel's first cell, which the
  separator to its left overwrote, so only the red SSID showed.)

## See also

- [beacons.md](beacons.md) — the raw per-BSSID beacon table this is
  synthesised from.
- [pnl.md](pnl.md) — the client preferred-network lists used for the
  overlap signal.
- [twins.md](twins.md) — the evil-twin episode table; a KARMA AP and an
  evil twin can both fire on the same rogue.
- [alerts.md](alerts.md) — the `KARMA_AP` rule.
