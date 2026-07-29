---
name: wifi-surveyor
description: UX persona + scenario suite — independent RF security researcher running WiFi site surveys and surveillance-detection sweeps
type: reference
---

# Persona: the WiFi surveyor

**Summary**: An independent security researcher who walks into a space
and asks *what is transmitting here, what belongs, and what is watching
me*. He is sloth's most demanding operator: he already owns Kismet,
airodump-ng and Wireshark, so sloth earns its slot only by answering
questions those tools make him assemble by hand.

**Sources**: `docs/views/*.md`, `docs/wiki/wifi-sigint.md`,
`src/alerts.c`, `src/twins.c`, `src/karma_detect.c`, `include/sloth.h`.

**Last updated**: 2026-07-28 (rescored after #51–#55).

> Pronouns for this persona (he/him) are taken from the brief that
> commissioned it; they describe this fixture, not sloth's operators
> generally.

---

## 1. Who he is

**Ilya Novak**, 41. Runs a two-person consultancy doing RF security
assessments: retail sites worried about skimmers, small offices after
an incident, a residential client who thinks someone is sitting outside
the house. Twelve years in wireless, four of them building the tooling
he now sells surveys with.

He is not learning 802.11 from sloth. He knows what a 4-way handshake
is, he can read a radiotap header, and he will notice immediately if a
detector is lying to him. What he does not have is time: a survey is a
**three-hour window on site** plus an unattended overnight run, and the
deliverable is a report someone non-technical will read on Monday.

### Environment

| | |
|---|---|
| Primary rig | Linux laptop, 2× monitor-capable adapters (rtl88XXau), one hopping, one parked |
| Unattended sensor | Raspberry Pi 4, single adapter, headless, systemd, left overnight |
| Typical scene | Mixed 2.4/5 GHz, 15–60 APs in range, 100–400 client MACs over a session, a street or car park within RF range |
| Deliverable | Markdown/PDF report: inventory, findings, evidence, recommendation |

### What "good" means to him

- **Every claim is defensible.** He will be asked "how do you know?" in
  front of a client. A finding he can't trace to an observation is worse
  than no finding.
- **False positives cost him money.** Reporting a neighbour's WiFi
  extender as a rogue access point is the kind of mistake that ends a
  client relationship.
- **The tool holds state he can't.** He cannot personally remember which
  of 300 MACs was here last Tuesday. That is the job he is outsourcing.

---

## 2. The five questions

Everything he does on site reduces to five questions. The scenario suite
is organised around them.

| # | Question | In his words |
|---|---|---|
| Q1 | **What is emitting here?** | "Give me the inventory — every AP and every client, with security and signal." |
| Q2 | **What is infrastructure vs. impostor?** | "Three BSSIDs are shouting the same SSID. Which are the client's own repeaters, and which is someone's Pineapple?" |
| Q3 | **What is just passing through?** | "Half these MACs are cars on the road. Show me who is *staying*." |
| Q4 | **Is anyone probing my network?** | "Somebody out there is asking for my SSID by name. Who, and since when?" |
| Q5 | **Which clients don't belong?** | "I know my devices. Tell me about the ones I don't know." |

Q1 and Q2 are survey work. Q3, Q4 and Q5 are **surveillance detection**
— and they are the reason he is on site at the residential job.

---

## 3. Scenario suite

Requirements notation: **L** = Linux + monitor mode + `CAP_NET_ADMIN`;
**A** = any platform.

### Q1 — Inventory

#### S1.1 Enumerate every AP in range (L)

1. Prepare the radio externally (`airmon-ng start wlan0`), launch
   `sudo ./sloth --hop --snapshot-out site-a.txt --site-label "Site A"`.
2. Open `[b] Beacons`. Let the hop cycle complete twice.
3. Read SSID, BSSID, channel, encryption, RSN cipher/AKM, MFP, WPS
   state, vendor, PHY tier.

**Pass**: every AP audible on the hop list appears with its security
posture resolved, not just its name.
**Result: PASS.** `beacon_ap_t` carries pairwise/group/AKM/MFP, WPS
state and lock, vendor-IE guess, PHY tier, QBSS occupancy, and reveals
hidden SSIDs out-of-band. This is richer than an `airodump-ng` CSV.

#### S1.2 Enumerate clients, associated and not (L)

1. `[7] Probe` for unassociated devices emitting probe requests.
2. `[w] Assoc` for confirmed STA↔AP bindings with graded evidence.
3. `[k] PNL` for each client's remembered network list.

**Pass**: he can tell, per MAC, whether it is associated, to what, and
on what evidence.
**Result: PASS.** Evidence grading (EAPOL > ReassocResp ≥ AssocResp) is
exactly the defensibility he needs for S1.2's "how do you know?".

#### S1.3 Leave a sensor overnight, collect in the morning (L)

1. `sloth --hop --monitor-only -o /var/log/sloth/events.jsonl
   --report site-a.md` under systemd on the Pi.
2. Return, read the report.

**Pass**: an unattended run yields a reviewable artifact without a TTY.
**Result: PASS**, with a caveat — the run is now buildable without
ncurses (#48) but still paints a screen; see #50. The `--report` /
`--report-json` posture rollup is the artifact he wants.

---

### Q2 — Infrastructure vs. impostor

#### S2.1 Three BSSIDs, one SSID — classify them (L)

Scene: client's Asus router, a TP-Link range extender the office
manager bought, and (in the adversarial variant) an ESP32 running an
evil twin. All three beacon `CorpWiFi`, all WPA2-CCMP-PSK.

1. `[b] Beacons`, group by SSID.
2. `[x] Twins` for pairing episodes.
3. `[v] Alerts` for `EVIL_TWIN`.

**Pass**: the extender is identified as infrastructure; only the ESP32
is flagged.
**Result: PARTIAL** (was `WRONG`; rescored 2026-07-28 after #51).

`ap_infrastructure_peers()` now consults the parsed **802.11k Neighbor
Reports** in `beacon_ap_t.neighbors[]`: if either AP advertises the
other, the pair is co-operating infrastructure and neither the alert
nor the `[x] Twins` view treats it as a twin. Membership is asserted by
the deployment itself, which beats the OUI heuristic — an impostor
cannot appear in the real AP's list and cannot make itself listed.

**Residual limitation, and it is the common case at the low end.** The
suppression needs at least one side to emit tag 52. Modern mesh kit
(AiMesh, Deco, eero) generally does; a £25 single-box repeater
generally does not. For those, sloth still has no evidence of a
relationship and the cross-vendor heuristic still fires — so Ilya can
still get a CRIT on a client's cheap extender. `PARTIAL`, not `PASS`,
until a second infrastructure signal exists.

The obvious candidate — "both BSSIDs present since early in the
session" — is weak under `--hop`, which is his default: an AP's
`first_seen` is confounded by when the radio first visited its channel,
so a legitimate extender discovered on hop cycle three looks new.
`beacon_ap_t` has no `first_seen` field today, so this is not a
cheap addition either. Left open deliberately rather than shipped as a
guess.

#### S2.2 Catch an actual Pineapple (L)

1. `[y] KARMA` — BSSIDs beaconing an abnormal count of distinct SSIDs.
2. `[z] RADIUS` — weak EAP methods offered, identity leaks.
3. `[a] Deauth` — deauth-then-lure chains.

**Pass**: a PineAP-style lure is distinguished from a busy multi-VAP AP.
**Result: PASS.** `karma_ap_t` scores SSID count, PNL overlap, Jaccard
in ppm, IE uniformity across SSIDs, and deauth chaining. IE uniformity
is the right discriminator and it is already implemented.

---

### Q3 — Transient vs. resident

#### S3.1 Separate the road from the room (L)

Scene: the survey position is 20 m from a road. Over three hours, ~200
client MACs are observed; perhaps 25 belong to the site.

1. Observe for three hours.
2. Ask: which MACs were *present* rather than *passing*?

**Pass**: a view or column separates devices by dwell — resident
(hours), visitor (minutes), transient (seconds, RSSI rising then
falling as it passes).
**Result: PASS** (was `FAIL`; rescored 2026-07-28 after #53).
`probe_client_t` now carries an `rssi_ring_t`, pushed from
`record_probe()`, and `[7] Probe` has a **Presence** column reading
resident / visitor / passing / ?, with "passing" rendered hot so it
stands out from the resident population.

The classifier (`src/presence.c`) keys on **trajectory shape**, not
dwell — dwell alone is confounded by channel hopping, since a resident
device the radio happened to hear once looks brief. A vehicle leaves a
rise-peak-fall signature; a device that arrived and stayed rises and
plateaus; a stationary one wobbles a few dB.

Note the asymmetry, which is what makes the column trustworthy: dwell
alone may promote an emitter to visitor or resident, but calling
something *passing* asserts that it moved, so it requires trajectory
evidence. A device heard once is `?`, never `passing`. Ilya can defend
the column in front of a client.

The class is also persisted to `probe_clients.presence` at its
strongest-ever verdict, so a pass survives in the record after the
trajectory ages out of the 60-second ring.

#### S3.2 Spot the car that came back (L)

**Pass**: a transient device seen on three separate passes over two
hours is surfaced as recurring — the signature of someone circling.
**Result: PASS** (was `FAIL`; rescored 2026-07-28 after #54).
`src/transit.c` accumulates the transit verdicts from #53 across a
horizon longer than the probe table's 120-second eviction, and
`RECURRING_TRANSIT` fires at three passes inside two hours. It reaches
Ilya on the overnight run, which was the point — this is the
observation he cannot make unaided, since nobody remembers which of two
hundred MACs they saw forty minutes ago.

Two design points that decide whether he can trust it:

- **Observations within 5 minutes coalesce into one pass.** A slow
  drive-by, or a vehicle stopped at a light inside RF range, produces a
  run of transit verdicts; counting each as an approach would
  manufacture a circuit out of a single event.
- **MAC randomisation does not defeat it.** A rotating device would
  otherwise accumulate several half-counts and never reach the
  threshold. `transit_canonical_mac()` resolves through the existing
  `seqnum_correlations` table — the deanonymisation primitive `[j]`
  already provides — so both addresses of a correlated pair land on one
  key.

Severity is WARN, not CRIT: a delivery round produces this honestly. It
is a lead with the pass count and closest approach attached, not a
conclusion.

---

### Q4 — Recon against his own network

#### S4.1 Someone is probing my SSID (L)

1. Designate the client's network.
2. Ask: which unknown clients have `CorpWiFi` in their PNL, or have
   sent directed probes for it?

**Pass**: an alert or view scoped to *his* SSID.
**Result: PASS** (was `FAIL`; rescored 2026-07-28 after #52).
`--my-ssid` / `--my-bssid` designate a network as his, and
`MY_NET_RECON` fires on any client whose PNL names a designated SSID
while it is not associated to that network. Association is the
exoneration and is checked by designated BSSID *or* SSID, so his
client's own staff do not each raise an alert and he does not have to
enumerate every BSSID of a multi-AP site.

It fires unattended, which was the actual requirement — the overnight
Pi run now answers this question without him awake for it. Note the
benign trigger, which he will need to explain in the report: a former
guest's phone honestly remembers the network. The alert is WARN, not
CRIT, for exactly that reason.

#### S4.2 Someone is attacking my AP specifically (L)

**Pass**: deauth floods, auth floods and probe floods aimed at his
BSSID rank above the same activity aimed elsewhere.
**Result: PASS** (was `PARTIAL`; rescored 2026-07-28 after #52).
`DEAUTH_FLOOD` and `AUTH_FLOOD` escalate WARN → CRIT when the target
BSSID is designated, and the detail line says `- YOUR network` so the
distinction survives into `--report`. Floods aimed elsewhere keep their
original severity: the scoping raises his case rather than lowering
everyone else's.

`PROBE_FLOOD` is deliberately not scoped. It keys on the *probing
client*, which has no target BSSID to compare against — the
"someone is probing me specifically" case is what `MY_NET_RECON`
answers, and duplicating it here would double-report one event.

---

### Q5 — Known vs. unknown

#### S5.1 Flag devices that aren't on the roster (L)

**Pass**: a supplied roster of known MACs marks everything else as
unknown.
**Result: PASS** (was `FAIL`; rescored 2026-07-28 after #55).
`--known-mac` / `--known-macs FILE` extend `src/ownership.c`, and a
device associated to a designated network but absent from the roster
raises `UNKNOWN_DEVICE`. Both inputs are required, so it is silent
unless Ilya supplied each — which also means it cannot fire noise at a
site where he only did half the setup.

This is the distinction he needed: *unfamiliar*, not *intrinsically
odd*. `device_risk_signals` still scores properties, and with
randomisation default on every handset `RANDOM_MAC` fires on the
client's own staff — the population he wanted filtered out.

**Roster reliability, which he needs to understand before using it**:
per-*probe* randomisation rotates constantly, so a roster cannot follow
a device that is only probing. Per-SSID randomisation used for
*association* is stable — one MAC per network, kept across reconnects —
so a device rostered while on the network keeps that address. He rosters
associated devices; passers-by are S3.1/S3.2's job.

#### S5.2 New since last week's survey (L)

1. `--baseline-in site-a.txt` from the prior visit.

**Pass**: new/gone/changed emitters since the last survey.
**Result: PARTIAL.** `--snapshot-out` / `--baseline-in` (#27) does
exactly this — **for APs only**. The client population, which is where
Q3/Q4/Q5 all live, has no cross-session *diff*, though as of #42
`--db` now persists the client state a diff would run over. `[k] PNL` and
`[j] Seqnum` even survive MAC rotation *within* a session, so the
fingerprint that would make cross-session client diffing work already
exists; it just isn't persisted. Issue #42's SQLite sink is the natural
home for it.

---

## 4. Scorecard

| Scenario | Question | Verdict |
|----------|----------|---------|
| S1.1 AP inventory | Q1 | PASS |
| S1.2 Client inventory | Q1 | PASS |
| S1.3 Unattended run | Q1 | PASS (see #50) |
| S2.1 Repeater vs. rogue | Q2 | PARTIAL (was WRONG; #51) |
| S2.2 Pineapple detection | Q2 | PASS |
| S3.1 Transient vs. resident | Q3 | PASS (was FAIL; #53) |
| S3.2 Recurring transient | Q3 | PASS (was FAIL; #54) |
| S4.1 Probes for my SSID | Q4 | PASS (was FAIL; #52) |
| S4.2 Attacks on my AP | Q4 | PASS (was PARTIAL; #52) |
| S5.1 Unknown clients | Q5 | PASS (was FAIL; #55) |
| S5.2 New since last survey | Q5 | PARTIAL |

**Reading (original, 2026-07-28 morning)**: sloth was already excellent
at Q1 and at the adversarial half of Q2, and every failure clustered in
the half of the job that is *not* about attacks — **establishing what is
normal**. Residency, ownership and familiarity were the three axes Ilya
reasons on, and sloth modelled none of them.

**Reading (after #51–#55)**: all three axes are closed. Residency came
from trajectory shape (#53) plus episode accumulation (#54); ownership
from network designation (#52); familiarity from the device roster
(#55). The last two are the same mechanism — operator-supplied context,
which sloth did not accept as an input class at all this morning.

What remains is not an axis but a join: **S5.2**, cross-session client
diffing, which needs the persisted state from #42 rather than any new
capture capability.

---

## 5. Gaps, ranked

Ranked by value to this persona per unit of work, with the existing
in-tree material each would build on.

| # | Gap | Builds on | Notes |
|---|-----|-----------|-------|
| ~~G1~~ | ~~**No "my network" designation**~~ | — | **Landed (#52).** `--my-ssid` / `--my-bssid`, the `MY_NET_RECON` rule, flood severity scoping, and twin-side pinning. Q4 fully answered. |
| ~~G2~~ | ~~**Repeater/infrastructure classification**~~ | — | **Landed (#51).** 802.11k mutual/one-way neighbor advertisement now suppresses the twin verdict in both the alert and the view. Residual: APs that emit no Neighbor Reports, which is most budget extenders — see S2.1. |
| ~~G3~~ | ~~**Client RSSI history + dwell classification**~~ | — | **Landed (#53).** Client `rssi_ring_t`, `src/presence.c`, Presence column in `[7] Probe`, persisted class. S3.1 closed; S3.2 (recurring transients) now has its primitive and needs episode tracking. |
| ~~G4~~ | ~~**Known-device roster**~~ | — | **Landed (#55).** `--known-mac` / `--known-macs`, `UNKNOWN_DEVICE` alert requiring both roster and designation. Q5 closed. |
| G5 | **Cross-session client baseline** | `--snapshot-out` (#27), SQLite sink (#42) | Extend the survey diff from APs to clients. Cheapest once #42 lands — it is a query over persisted state, not new capture. |

### Sequencing note

G1 (#52) and G2 (#51) have both landed, which closes Q4 and softens Q2.
What remains is Q3 and Q5 — residency and familiarity. G3 is the big
one and the highest remaining value: it is the only unmet ask that is
about *surveillance detection* rather than inventory hygiene. G4 is
small and now cheap, because #52 established how operator-supplied
context enters the system — a known-MAC roster is the same shape as a
designated SSID and should reuse the ownership module rather than
inventing a second one. G5 should wait for #42's state tables rather
than growing a second persistence path.

None of the five requires transmitting anything, so all five sit inside
MISSION §2. G1 introduced operator-supplied context as a new *input*
class — sloth previously took only observations and display preferences
— and that decision is now made and implemented in `src/ownership.c`.
G4 is the same shape and should extend that module rather than start a
parallel one.

---

## 6. Related pages

- [[wifi-sigint]] — the view set this persona lives in.
- [[mac-randomisation]] — why `[j] Seqnum` is what makes G5 tractable.
- [[alerts]] — the rule catalogue scored above.
- [[evil-twin-reproducer]] — scapy harness for re-running S2.1 on real
  hardware, including the budget-extender case #51 still misses.
