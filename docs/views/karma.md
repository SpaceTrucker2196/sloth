# KARMA  `[y]`

Materialised view of KARMA / PineAP candidate APs — one row per BSSID
beaconing an abnormal number of distinct SSIDs, the "answer every
network a client probes for" lure. See issue #30.

## Protocol / data source

Built passively each poll by `karma_update()` from `s->beacon_aps[]`
(distinct-SSID history per BSSID), the client PNLs in
`s->pnl_clients[]`, and the deauth impact aggregates
`s->deauth_victims[]`. No new
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
- **IE** — `Y` when every SSID this BSSID beacons carries an identical
  IE fingerprint (encryption / cipher / AKM / MFP + vendor-IE hash). A
  legit multi-VAP AP varies these per VAP; a single spoofing radio does
  not, so uniformity is a KARMA signal (adds +1 to the score).
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
- **score** —
  `1 + (>=2 PNL hits on one station ? 2 : 0) + (IE uniform ? 1 : 0) + (chain ? 3 : 0)`,
  ranked strongest-first. The PNL term uses the single-station count,
  not the PNL column's union, so the ranking and the `KARMA_AP` alert's
  CRIT gate cannot disagree about one BSSID (#90).
- **tool** — a trailing `[label/conf]` when the tool-signature table
  names the candidate ([[tool-fingerprints]]). A row with no capture
  behind it renders as `[ESP32 Marauder/med? provisional]` (#90): a
  hypothesis sloth is willing to state, not an identification. Same
  text as the `KARMA_AP` alert detail — both come from
  `tool_attribution_format()`. Display only: it does not move the
  score, because an UNVERIFIED guess is not corroboration, and every
  row shipped today is UNVERIFIED.

The same signals drive the `KARMA_AP` alert in `[v] Alerts`, which adds
a `confidence` percentage and escalates WARN→CRIT only when a
single-station PNL match, the deauth chain, or a verified tool match
corroborates the bare SSID count (#90) — this view is the ranked, browsable surface for
the same underlying signals, not a mirror of the alert's severity.

## View

```
 ── KARMA ─────────────────────────────────────────────────────────
 KARMA/PineAP candidates: 1 / max 64  deauth-then-lure: 1
 BSSID              SSIDs  PNL   J%    IE  chain  score  Top SSID / last
 -----------------  -----  ----  ----  --  -----  -----  ---------------
 00:11:22:33:44:55      7     4  80%   Y   YES        7  Starbucks (2s)
 24:6f:28:33:44:55      3     0  0%    -   -          1  ACME-Corp (4s)  [ESP32 Marauder/med? provisional]
 PNL = SSIDs in client probe lists, >=2 on one station; chain = deauth-then-lure on shared victim
 [tool/conf? provisional] = UNVERIFIED signature, no capture: a hypothesis, not an identification
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
characters, then the tool *label*; the `/conf? provisional` part of the
attribution is kept whole while any of the label fits, because that is
the part that says the name is unverified. At 100 columns with a long
SSID and an old age that can leave a row reading
`ABCDEFGH (1234567s)  [ES/med? provisional]`; the full attribution is
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
