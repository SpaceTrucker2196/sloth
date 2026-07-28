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

**Last updated**: 2026-07-28.

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
**Result: WRONG.** `rule_evil_twin`'s WARN branch fires on *same SSID,
same cipher, different vendor OUI* — which is precisely a store-bought
extender behind a different-vendor router. Worse, the Phase-2
escalation promotes WARN to **CRIT** when the two APs' vendor-IE
fingerprint hashes differ, and a TP-Link extender's IEs will never
match an Asus router's. The code comment reasons that "legit
dual-vendor mesh is rare" — true in enterprise, false in exactly the
SOHO and residential scenes Ilya surveys. He gets a CRIT rogue-AP
finding on the client's own hardware, which is the specific mistake
that costs him the account.

**What is already in the tree to fix it**: `beacon_ap_t.neighbors[]`
holds parsed **802.11k Neighbor Reports** (tag 52), and
`src/views/beacon.c` already answers "is this neighbor a BSSID we've
also seen directly?" Co-operating infrastructure advertises its
siblings; an impostor does not know they exist. That is a positive
infrastructure signal sitting one wire away from the twin logic.

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
**Result: FAIL.** No dwell or mobility classification exists anywhere.
`probe_client_t` carries `first_seen`/`last_seen` and a *single*
`signal_dbm` — no RSSI history at all. The only RSSI ring in the tree
(`rssi_ring_t`, 16 samples / 60 s) is attached to `beacon_ap_t`, i.e.
to **APs, not clients**, and feeds exactly one consumer: the
`EVIL_TWIN_PROXIMITY` rule. That rule's own comment names "mobile
devices roaming past" as the noise it must tolerate.

So the single richest signal for Ilya's surveillance-detection work —
*this emitter approached, peaked and receded in 40 seconds* — is
currently modelled as an error term. He is left sorting 200 MACs by
`last_seen − first_seen` in the JSONL by hand, which discards the
trajectory shape that distinguishes a car from someone who parked.

#### S3.2 Spot the car that came back (L)

**Pass**: a transient device seen on three separate passes over two
hours is surfaced as recurring — the signature of someone circling.
**Result: FAIL.** Follows from S3.1; without transit episodes there is
nothing to count recurrences of. This is the highest-value unmet ask in
the whole suite: a recurring transient is the single most actionable
observation in a surveillance-detection engagement.

---

### Q4 — Recon against his own network

#### S4.1 Someone is probing my SSID (L)

1. Designate the client's network.
2. Ask: which unknown clients have `CorpWiFi` in their PNL, or have
   sent directed probes for it?

**Pass**: an alert or view scoped to *his* SSID.
**Result: FAIL.** The observation exists — `pnl_client_t.ssids[]` is
exactly "which networks does this device remember" — but **sloth has no
concept of "mine"**. There is no `--my-ssid` / `--my-bssid`, so the
question cannot be posed. Ilya can eyeball `[k] PNL` for the SSID, but
not be *told*, and not overnight while he is asleep.

#### S4.2 Someone is attacking my AP specifically (L)

**Pass**: deauth floods, auth floods and probe floods aimed at his
BSSID rank above the same activity aimed elsewhere.
**Result: PARTIAL.** `DEAUTH_FLOOD`, `AUTH_FLOOD` and `PROBE_FLOOD`
all exist and fire correctly, but on volume alone, unscoped. In a busy
RF scene he must correlate BSSIDs by hand to learn whether the flood
was aimed at his client or at the coffee shop next door — and severity
does not reflect the difference.

---

### Q5 — Known vs. unknown

#### S5.1 Flag devices that aren't on the roster (L)

**Pass**: a supplied roster of known MACs marks everything else as
unknown.
**Result: FAIL.** No roster import exists. `device_risk_signals`
(`RANDOM_MAC`, `UNKNOWN_VENDOR`, `NO_HOSTNAME`, `PROBE_ONLY`) is a
usable *proxy* for suspiciousness, but it scores intrinsic properties,
not membership. With MAC randomisation now default on every phone,
`RANDOM_MAC` fires on the client's own staff.

#### S5.2 New since last week's survey (L)

1. `--baseline-in site-a.txt` from the prior visit.

**Pass**: new/gone/changed emitters since the last survey.
**Result: PARTIAL.** `--snapshot-out` / `--baseline-in` (#27) does
exactly this — **for APs only**. The client population, which is where
Q3/Q4/Q5 all live, has no cross-session baseline. `[k] PNL` and
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
| S2.1 Repeater vs. rogue | Q2 | **WRONG** |
| S2.2 Pineapple detection | Q2 | PASS |
| S3.1 Transient vs. resident | Q3 | **FAIL** |
| S3.2 Recurring transient | Q3 | **FAIL** |
| S4.1 Probes for my SSID | Q4 | **FAIL** |
| S4.2 Attacks on my AP | Q4 | PARTIAL |
| S5.1 Unknown clients | Q5 | **FAIL** |
| S5.2 New since last survey | Q5 | PARTIAL |

**Reading**: sloth is already excellent at Q1 and at the adversarial
half of Q2 — the inventory and the exotic-attack detectors are genuinely
ahead of the field tools Ilya carries. Every failure clusters in the
half of his job that is *not* about attacks at all: **establishing what
is normal**. Residency, ownership, and familiarity are the three axes he
reasons on, and sloth models none of them.

That is a coherent gap, not five unrelated ones. Q3 needs *time*, Q4
needs *ownership*, Q5 needs *familiarity* — and all three are cheap,
because the underlying observations are already captured. What is
missing is the operator's context: a way to tell sloth which network is
his and which devices he already knows, and a memory of how long things
stayed.

---

## 5. Gaps, ranked

Ranked by value to this persona per unit of work, with the existing
in-tree material each would build on.

| # | Gap | Builds on | Notes |
|---|-----|-----------|-------|
| G1 | **No "my network" designation** | `pnl_client_t.ssids[]`, deauth/auth/probe flood rules | `--my-ssid` / `--my-bssid` (repeatable). Unlocks S4.1 outright and re-ranks S4.2. Also lets the twin logic never nominate his own AP as the impostor. Smallest change, largest unlock. |
| G2 | **Repeater/infrastructure classification** | `beacon_ap_t.neighbors[]` (802.11k, already parsed and rendered) | Positively identify co-operating infrastructure and downgrade the evil-twin alert for it. Fixes a `WRONG`, which outranks fixing a `FAIL`. |
| G3 | **Client RSSI history + dwell classification** | `rssi_ring_t` (exists, AP-only) | Attach a ring to client records; classify RESIDENT / VISITOR / TRANSIENT from dwell plus trajectory shape. Unlocks S3.1 and makes S3.2 possible. Largest of the five. |
| G4 | **Known-device roster** | `device_t`, device-risk scoring | `--known-macs FILE`; an unknown-device signal that means *unfamiliar* rather than *intrinsically odd*. |
| G5 | **Cross-session client baseline** | `--snapshot-out` (#27), SQLite sink (#42) | Extend the survey diff from APs to clients. Cheapest once #42 lands — it is a query over persisted state, not new capture. |

### Sequencing note

G1 and G2 are independent and small. G3 is the big one and should not
block them. G5 should wait for #42's state tables rather than growing a
second persistence path.

None of the five requires transmitting anything, so all five sit inside
MISSION §2. G1 and G4 add operator-supplied context, which is a new
*input* class for sloth (today it takes only observations and display
preferences) — worth noting as a design decision rather than assuming.

---

## 6. Related pages

- [[wifi-sigint]] — the view set this persona lives in.
- [[mac-randomisation]] — why `[j] Seqnum` is what makes G5 tractable.
- [[alerts]] — the rule catalogue scored above.
- [[evil-twin-reproducer]] — scapy harness for re-testing S2.1 after G2.
