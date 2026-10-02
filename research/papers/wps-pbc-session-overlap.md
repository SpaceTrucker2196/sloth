---
source_url: https://w1.fi/cgit/hostap/plain/src/wps/wps_defs.h
retrieved: 2026-10-02
topics: [wps, pbc, push-button, session-overlap, walk-time, mdk4]
alert_kinds: [ALERT_TYPE_WPS_PBC_RACE]
citation: WSC 2.0 Push-Button Configuration walk time and session overlap, as implemented in hostap src/wps/wps_defs.h (WPS_PBC_WALK_TIME, WPS_CFG_MULTIPLE_PBC_DETECTED)
---
# WPS Push-Button Configuration — walk time and session overlap

Push-Button Configuration authenticates by physical proximity and
nothing else. Pressing the button on the AP opens a window in which any
enrollee in RF range can register; there is no secret involved, so the
only thing standing between an attacker and the network is that they
have to be present during the window and that the owner is expected to
notice a second device enrolling.

WSC bounds the window and names the failure. Both constants are in the
Wi-Fi Alliance's reference implementation (`hostap`, `src/wps/wps_defs.h`):

```
/* Walk Time for push button configuration (in seconds) */
#define WPS_PBC_WALK_TIME 120
```

and, in `enum wps_config_error`, the Configuration Error a registrar
returns when it sees enrollees from more than one device inside that
window:

```
WPS_CFG_MULTIPLE_PBC_DETECTED = 12,
```

matched by the event `WPS_EV_PBC_OVERLAP — PBC session overlap
detected` in `src/wps/wps.h`. Overlap is not a warning in WSC: the
registrar is required to abort, precisely because it cannot tell which
of the two enrollees belongs to the person who pressed the button.

`mdk4`'s `w` mode is the tool that manufactures the condition on
purpose, holding the window open and racing legitimate enrollees.

## Why sloth cites this

`ALERT_TYPE_WPS_PBC_RACE` reports the overlap condition from outside
the exchange. Two observables, both already parsed:

- the AP's own beacon carrying **Device Password ID 0x0004** (Push
  Button) in its WPS IE, which hostapd-class firmware advertises only
  while the walk-time window is actually open — the wave-5 slice of
  issue #82 made that value deliberately non-sticky for this reason;
- the count of distinct stations with a live, unfinished WSC
  registration against that BSSID inside the last **120 s**, from the
  session table wave 7 built.

More than two concurrent enrollees fires (owner-accepted threshold,
2026-09-30; configurable via `--wps-pbc-concurrent`, the walk time is
not, because it is the protocol's number and not the operator's). The
spec's own abort rule is why this earns CRIT rather than a posture
note: the registrar is supposed to treat it as unresolvable, so sloth
reporting it is reporting a protocol error condition, not inferring an
intent.

## What it does not say

Nothing here distinguishes an attacker from two household members
pressing WPS at the same moment. Neither does the protocol — that
indistinguishability is the whole reason the abort rule exists — and
sloth does not claim otherwise: the finding is "session overlap", not
"attack confirmed". The threshold of *more than two* is what keeps the
ordinary two-party case quiet.

## Provenance note

The canonical home of these files is the upstream `hostap` cgit at the
`source_url` above. That server returned an anti-bot interstitial to an
automated fetch on the retrieval date, so the quoted lines were read
from a public mirror of the same file
(`raw.githubusercontent.com/latelee/hostapd/master/src/wps/wps_defs.h`)
and are reproduced verbatim. The underlying WSC 2.0 specification text
is behind Wi-Fi Alliance membership and is not quoted here.

## Related

- `research/cert/vu-723755.md` — the PIN path, the other WPS attack
  surface with rules in this tree
- `research/mitre/T1557.md` — the ATT&CK technique this rule maps to
