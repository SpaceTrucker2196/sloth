# BTM abuse — the forced roam that leaves no deauth

**Issue:** [#59](https://github.com/SpaceTrucker2196/sloth/issues/59) ·
**Alert:** `ALERT_TYPE_BTM_ABUSE` · **View:** `[a]` Deauth ·
**MITRE:** [T1498](https://attack.mitre.org/techniques/T1498/)

## The gap this closes

sloth has caught deauthentication floods since its first release. The
rule is simple and it works: five or more deauth frames at one target in
five seconds, and `DEAUTH_FLOOD` fires. That covers `aireplay-ng`,
`mdk4 -d`, and every tool built on the same primitive.

It covers none of what follows.

An attacker who wants a client on *their* AP has a second option that
the 802.11 standard hands them: **BSS Transition Management**. It is
part of 802.11v, added so a controller could balance load across access
points, and it is a polite mechanism — the AP suggests, the client
decides. Except for one bit.

Set **B2** in the Request Mode field and the message changes from "you
might like it better over there" to **Disassociation Imminent**: you are
about to be dropped, here is where to go. Clients honour it. That is the
entire point of the bit.

So a rogue AP can move a client without transmitting a single deauth
frame. `DEAUTH_FLOOD` sees nothing, because nothing it watches for
happened. The operator sees a clean deauth table and a client that
somehow ended up somewhere else.

## Why it is worse than deauth, not merely different

[Ali & Kulkarni (2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823001712)
lay out the properties that make this attractive to an attacker:

- **No proximity requirement.** A deauth-and-lure attack needs the rogue
  AP to out-signal the real one at the victim, which puts a physical
  constraint on where the attacker can stand. A BTM Request *names* the
  destination. The client goes looking for the BSSID it was given.
- **It works on clients that ignore deauth.** Some IoT and embedded
  firmware treats unsolicited deauth as noise and reconnects to the same
  AP. Those same stacks implement 802.11v steering, because roaming
  support is a certification checkbox.
- **It looks like management traffic**, because it is management
  traffic. A WIDS tuned for floods sees a handful of well-formed Action
  frames.

The frames are protocol-legitimate. The abuse is behavioural — which
means this detector is a threshold with context, not a signature, and
its false positives come from real networks doing real steering.

## What sloth measures

Parsing lives in [`src/action_snoop.c`](../../src/action_snoop.c),
dispatched from `probe.c` on management subtype 13. The rule is
`rule_btm_abuse` in [`src/alerts.c`](../../src/alerts.c).

Two structures, because the operator and the rule ask different
questions:

| | holds | answers |
|---|---|---|
| the table | one durable row per `(BSSID, STA)` | "how much has this AP steered this client, ever" |
| the ring | timestamped events | "how much in the last 60 seconds" |

### The threshold, and what it is measured against

**Four BTM Requests carrying Disassociation Imminent, at one
`(BSSID, STA)` pair, within 60 seconds.**

Three choices in that sentence are load-bearing:

**Gated on the Disassociation-Imminent bit, not on rate alone.** Issue
#59 specifies the rate. Taken literally it fires on any AP that steers
one client four times a minute — which is what a controller-managed
enterprise network does all day. A Request without B2 cannot force
anything; the client may decline and often does. Both counts appear in
the alert detail (`4/7 req 60s`) and both columns appear in the view, so
a high-rate non-forcing AP stays visible without alerting.

**Per pair, not per BSSID.** An AP steering many clients is load
balancing. An AP steering *one* client four times in a minute is not
taking no for an answer. Keying on the BSSID alone would let the first
masquerade as the second.

**One steer is not an attack.** A single Disassociation Imminent is what
"this radio is going down for maintenance" looks like, and that is what
the BSS Termination fields exist to say.

### Severity

WARN by default. **CRIT** when any of:

- a candidate BSSID is the **rogue half of a detected twin pair**
  (`s->twin_episodes`) — the forcing has an identified landing site,
  which is the difference between a denial of service and a completed
  adversary-in-the-middle setup;
- the BSSID matches `--my-bssid` — this is happening on the operator's
  own network;
- the target STA is on the `--known-macs` roster — one of the
  operator's own devices is being moved.

Only the *twin* half of a pair matches. Being steered toward the
legitimate AP of a known pair is recovery, not attack.

### Attacker tells

Two are reported in the alert detail:

- **`source never beaconed`** — the transmitter has never been heard
  advertising a BSS. A legitimate AP steering its own clients has, by
  definition, been beaconing the network it is moving them off.
- **`candidate never beaconed`** — the destination may not exist. Real
  steering points at real APs; a fabricated candidate list aims a forced
  roam somewhere the client cannot verify.

Both are **reported, not escalated on**, and the reason is worth stating
plainly: on a channel-hopping sensor, "never beaconed" means "not while
we were listening". With `--hop` the AP inventory is a sample. Treating
a sampling gap as evidence of forgery would make the detector noisy in
exactly the configuration most operators run.

## Why T1498 and not T1557

What sloth observes is a client being forced off its access point. That
is [network denial of service](https://attack.mitre.org/techniques/T1498/).

Whether the client then lands on an attacker's AP — the
[adversary-in-the-middle](https://attack.mitre.org/techniques/T1557/)
that the forcing exists to set up — is a *separate observation*, and
sloth may or may not make it. When the chain does complete, the
`ATTACK_PATH` machinery carries T1557 for it.

Tagging this alert T1557 would claim the second half of the attack on
the evidence of the first.

## What it looks like when it is nothing

The honest failure mode. All of these are real:

- **Aggressive band steering.** A controller moving a dual-band client
  between 2.4 and 5 GHz, repeatedly, because the client keeps coming
  back. Some vendors set Disassociation Imminent to make it stick.
- **A dying radio.** An AP that is genuinely about to go down and says
  so to each associated client in turn — though this usually spreads
  across many pairs rather than concentrating on one.
- **A client that will not leave.** The AP asks, the client declines,
  the AP asks harder. The `Reqs` versus `Force` columns are how you tell
  this from an attack: a stubborn-client case usually shows a high total
  with a low forcing count.

Check the candidate BSSID first. If it is an AP you know, and it beacons
the same SSID, this is your own network being a network.

## Defences

802.11w (Protected Management Frames) authenticates Action frames, so a
PMF-required network rejects a forged BTM Request from an outsider. It
does **not** help when:

- the BSS is in **transition mode or PMF-optional** — check the `MFP`
  column in `[b]`, and see `ALERT_TYPE_SSID_CONFUSION`;
- the client has genuinely associated to a **rogue AP**, which can then
  steer it legitimately.

## Export

- **JSONL**: `btm_request` records, one per pair, with `req_count`,
  `imminent_count`, the candidate BSSIDs, and the disassociation timer.
- **SQLite**: `btm_requests`, in the 12x *finding* retention tier —
  evidence must outlive the alert it justifies. Counters upsert with
  `MAX` so LRU eviction of the in-memory table cannot erase steering
  that a live alert depends on.
- **`--report`**: an *802.11v BSS-Transition steering* section, listing
  every steered client and flagging the forcing ones.

## Known limits

- **Fixture coverage is spec-derived, not capture-derived.** Frames are
  hand-built from IEEE 802.11-2020 §9.6.14 per
  [`agents/AGENTS.md`](../../agents/AGENTS.md) § Discipline. That proves
  the parser against the standard, not against what `mdk4` or a
  modified `hostapd` actually emits. A real capture is wanted as a later
  integration layer.
- **One pair reported per tick.** The rule surfaces the busiest forcing
  pair each poll, so a simultaneous multi-client forcing campaign
  produces its alerts across several ticks rather than all at once.
- **The third attacker tell from #59 is not implemented.** "Beacon-
  interval mismatch between the claimed source BSSID's steady-state
  beacon and the action-frame source" is not computable: an Action frame
  carries no beacon interval. Comparing addr2 against addr3 would be the
  meaningful forged-TA check and is proposed as a follow-up.

## See also

- [`docs/views/deauth.md`](../views/deauth.md) — the view.
- [`docs/views/alerts.md`](../views/alerts.md) — the rule table.
- [`docs/wiki/evil-twin-reproducer.md`](evil-twin-reproducer.md) — the
  twin detection this rule escalates against.
- IEEE 802.11-2020 §9.6.14 (BSS Transition Management), Figure 9-924
  (Request Mode bitfield — Disassociation Imminent is **B2**, `0x04`).
