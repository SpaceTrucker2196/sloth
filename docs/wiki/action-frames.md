# Action frames and the MFP era

**Issue:** [#76](https://github.com/SpaceTrucker2196/sloth/issues/76) ·
**Code:** [`src/action_snoop.c`](../../src/action_snoop.c) ·
**Surfaces in:** `SA_QUERY_FLOOD`, `MFP_UNPROTECTED`, and the four
action-frame detectors that came before them

## Why this surface matters

Management-frame protection killed the raw deauthentication flood. An
adversary who wants a client off its network — to move it onto a rogue
AP, or simply to break it — cannot send a spoofed deauth to an
MFP-protected BSS and have it work.

So the attacks moved. The modern shape is unauthenticated *action*
frames: BTM Requests that ask a client to roam, RRM Beacon Requests that
make it survey the air on the attacker's behalf, CSAs that move it to
another channel, and SA-Query floods that attack the protection
mechanism itself. Hak5's Pineapple ships "BTM-assisted steering" as an
MFP-friendly alternative to deauth for exactly this reason.

## What sloth detects here

| alert | CVE / clause | shipped |
|---|---|---|
| `BTM_ABUSE` | 802.11v §9.6.14 | #59 |
| `RRM_SURVEY_ABUSE` | 802.11k §9.6.7 | #61 |
| `CSA_ABUSE` | 802.11h §9.6.2.4 | #63 |
| `SA_QUERY_FLOOD` | 802.11w §11.13 | #76 |
| `MFP_UNPROTECTED` | CVE-2019-16275 | #76 |

## `SA_QUERY_FLOOD` — detecting the answer, not the question

This is the one worth understanding, because what it detects is not what
it looks like.

SA Query is MFP's own mechanism. When an AP receives an **unprotected**
disassociation or deauthentication claiming to be from an associated
station, it does not act on it. It sends an SA Query Request to that
station and waits: a station that is really still there answers, the
spoofed frame is discarded, and nothing happens.

So a storm of SA Queries is not an attack on the client. It is the
**visible symptom** of someone spraying spoofed disassociations at an
MFP-protected network.

That distinction has an operational consequence. The attacker's frames
are aimed at the AP, and sloth may be on another channel or simply out
of range of the transmitter — a directional antenna from across a car
park is not going to reach a monitor radio sitting next to the AP. The
AP's **response** goes out on the BSS's own channel at ordinary power
and is heard.

Detecting the answer rather than the question is why this rule earns a
place beside the deauth-flood rule rather than duplicating it.

**Thresholds.** §11.13 describes a short retry sequence — a handful of
frames over a few hundred milliseconds — after which the AP gives up.
Twelve in ten seconds is comfortably above that and comfortably below
anything an attacker generating a flood would produce.

**Counted per `(BSSID, station)`.** Two stations being queried are two
exchanges. Merging them lets ordinary traffic on a busy BSS reach the
threshold without anything being wrong.

**A sliding window, not a counter.** A network that saw a legitimate
burst an hour ago would otherwise carry it forever and the threshold
would stop meaning anything.

## `MFP_UNPROTECTED` — CVE-2019-16275

An individually addressed robust Action frame with the Protected bit
clear, on a BSS whose own beacon advertises MFP **required**.

Either the stack is non-conforming or the frame was injected.
CVE-2019-16275 is hostapd's version of the first being exploitable as
the second. Sloth cannot tell them apart and does not claim to — what it
says is that the frame arrived and the BSS said it should not have.

### Three distinctions the rule depends on

**Robust is an exclusion list, not an allow-list.** Every Action
category is robust except the three the standard defines as never
protected: Public (4), Unprotected WNM (11), Vendor Specific (127).

Written as an allow-list, the detector goes quiet on every category
assigned after it was written — and nothing fails when it does. The
category space grows; the exclusions do not.

**MFP capable is not MFP required.** Capable-but-not-required is the
ordinary WPA2 posture and an unprotected action frame there is legal.
Firing on it would mean an alert on essentially every network in range.
(It is separately a *downgrade lane*, which is `WPA_DOWNGRADE`'s
finding — see [`alerts.md`](../views/alerts.md).)

**A BSSID with no beacon on file is not "MFP off".** `beacon_find_mfp()`
returns **-1** for a BSSID never heard beacon, distinct from 0. On a
hopping radio most BSSIDs are unheard most of the time, and a detector
that reads "no beacon" as "no MFP" fires on every network it has not
tuned to yet. The three states are kept apart deliberately.

**Individually addressed only.** Group-addressed management frames are
protected by BIP, which appends a Management MIC element rather than
setting the Protected bit. Reading that bit on a broadcast answers a
question it was never asked.

## The chain, as a marker

#76 also proposed `EVIL_TWIN_BTM_CHAIN`: action → deauth → new-BSSID
beacon within 3 s with an RSSI delta. It shipped as a **marker on the
existing `EVIL_TWIN` alert**, not as a new one, and the reasoning is
worth keeping.

Every link in that chain already fires. A BTM burst raises `BTM_ABUSE`,
a deauth flood raises `DEAUTH_FLOOD`, a new same-SSID BSSID raises
`EVIL_TWIN`, a sudden RSSI jump raises `EVIL_TWIN_PROXIMITY`. A chain
detector on top would be a **fifth row describing the same seconds of
air** — and five alerts for one event teaches an operator to ignore all
five. `KARMA_AP` had already settled this shape with its
`+deauth-then-lure` marker rather than a separate alert.

So `EVIL_TWIN` gains `+btm-steered by <AP>`.

**The link is tighter than the issue proposed.** Not "a steer happened
and a twin appeared" — that is two things in the same minute, and
treating co-occurrence as causation is how a correlator becomes noise.
The marker requires that the BTM Request **named that exact BSSID as its
destination**, in the candidate list, while carrying Disassociation
Imminent. That is the AP telling a client to associate to the rogue: the
whole attack in one field.

**It escalates as well as annotates.** A same-cipher-different-OUI twin
is normally WARN, because a cross-vendor deployment is a real
possibility. A twin with traffic actively being pushed at it is not
ambiguous, so the marker raises it to CRIT. That escalation is the value
of the chain, delivered without a separate alert to triage.

**Bounded to 300 s.** The steering table is durable by design — it
survives the rate window so the `[a]` view can show every steer — so an
unbounded lookup would mark every twin seen for the rest of a long
session against one steer from its start.

**Imminent-only**, for the same reason `BTM_ABUSE` counts only those: a
Request without B2 set cannot force anything, and a load-balancing
controller emits exactly those all day.

## What #76 proposed that was already built

Worth recording, because the issue was filed from a stale grep and the
same trap has now caught three issues in this repo.

`grep -cE 'subtype == 13|ACTION' src/capture/probe.c` returned 0 when
#59 was filed. It returns 2 today: `probe.c:398` dispatches subtype 13
and `:404` calls `action_observe()`.

`BTM_ROGUE_STEERING` and `BTM_COERCED_ROAM` are both `BTM_ABUSE`, which
already cross-checks candidate BSSIDs two ways — against the evil-twin
table and against whether the candidate has *ever been heard beacon*,
the latter catching a fabricated destination the issue does not mention.
`BTM_FLOOD` is `BTM_ABUSE`'s own threshold over its own window; a second
rate rule on the same frames would produce two alerts for one event.

## Testing

Hand-built frames per IEEE 802.11-2020 §9.6, no captures — see
`agents/AGENTS.md` § Discipline. The cases that decide whether these are
usable are the negative ones: MFP capable rather than required, a BSSID
never heard beacon, a Public Action frame, a group-addressed frame, and
a legitimate three-frame SA-Query exchange. A capture from a lab rig
running `mdk4` would exercise none of them.

## See also

- [[btm-abuse]] — the 802.11v steering detector this sits beside
- [[fragattacks]] — the other family that lives on this surface
- `docs/views/alerts.md` — the rule table rows
