# KARMA  `[y]`

Materialised view of KARMA / PineAP candidate APs — one row per BSSID
beaconing an abnormal number of distinct SSIDs, the "answer every
network a client probes for" lure. See issue #30.

## Protocol / data source

Built passively each poll by `karma_update()` from `s->beacon_aps[]`
(distinct-SSID history per BSSID), the client PNLs in
`s->pnl_clients[]`, and the deauth ring `s->deauth_events[]`. No new
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
  clients' preferred-network lists. PineAP Beacon Response answers
  exactly what clients probe for, so a high overlap separates an active
  lure from a benign SSID-cycling AP.
- **J%** — Jaccard similarity between the advertised SSID set and the
  client-PNL union (`|A∩B| / |A∪B|`), shown as a percentage. Trends
  toward 100% as the AP mirrors the entire union of probed networks —
  the sharpest PineAP tell. Rendered bright at ≥70%.
- **IE** — `Y` when every SSID this BSSID beacons carries an identical
  IE fingerprint (encryption / cipher / AKM / MFP + vendor-IE hash). A
  legit multi-VAP AP varies these per VAP; a single spoofing radio does
  not, so uniformity is a KARMA signal (adds +1 to the score).
- **chain** — a deauth flood is active within 60 s (`deauth-then-lure`:
  knock clients off, then answer their reconnection probes).
- **score** — `1 + (PNL>0 ? 2 : 0) + (chain ? 3 : 0)`, ranked
  strongest-first.

The same signals drive the `KARMA_AP` CRIT alert in `[v] Alerts`; this
view is the ranked, browsable surface for them.

## View

```
 ── KARMA ─────────────────────────────────────────────────────────
 KARMA/PineAP candidates: 1 / max 64  deauth-then-lure: 1
 BSSID              SSIDs  PNL   J%    IE  chain  score  Top SSID / last
 -----------------  -----  ----  ----  --  -----  -----  ---------------
 00:11:22:33:44:55      7     4  80%   Y   YES        7  Starbucks (2s)
 PNL = advertised SSIDs matching nearby client probe lists; chain = concurrent deauth flood
```

The BSSID is bright; PNL and chain go bright when non-zero to draw the
operator's eye.

## What's normal

- Zero rows. Most APs advertise one SSID (or a small fixed set of
  VAPs) and never trip the threshold.
- A single row at score 1 (≥3 SSIDs, no PNL overlap, no deauth):
  worth a glance — some captive-portal gear cycles SSIDs — but not by
  itself an attack.

## What's suspicious

- **PNL overlap > 0** — the AP is beaconing the exact networks nearby
  clients are looking for. That is the PineAP / KARMA beacon-response
  fingerprint.
- **chain = YES** — a deauth flood is running alongside the lure: the
  classic deauth-then-lure sequence
  ([T1557.004](https://attack.mitre.org/techniques/T1557/004/)).
- **score ≥ 5** — multiple signals stacked; treat as an active lure.

## See also

- [beacons.md](beacons.md) — the raw per-BSSID beacon table this is
  synthesised from.
- [pnl.md](pnl.md) — the client preferred-network lists used for the
  overlap signal.
- [twins.md](twins.md) — the evil-twin episode table; a KARMA AP and an
  evil twin can both fire on the same rogue.
- [alerts.md](alerts.md) — the `KARMA_AP` rule.
