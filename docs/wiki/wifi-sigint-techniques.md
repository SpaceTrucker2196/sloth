---
name: wifi-sigint-techniques
description: Common passive Wi-Fi SIGINT techniques an analyst uses, each mapped to the sloth view that performs it and the tradecraft limits that keep it honest
type: reference
---

# Wi-Fi SIGINT techniques

**Summary**: The passive-collection techniques a signals analyst applies
to 802.11, and how sloth performs each one. "SIGINT" here means
**signals intelligence** — deriving information from the radio emissions
themselves, without joining, transmitting, or decrypting. Everything on
this page is receive-only; it is the discipline sloth was built around.

**Sources**: `docs/views/{probe,pnl,beacons,seqnum,assoc,eapol,channel,devices}.md`,
`docs/wiki/{wifi-sigint,mac-randomisation,ja3-fingerprinting}.md`.

**Last updated**: 2026-09-30.

---

## The premise

A Wi-Fi device is a beacon of information whether or not it is connected
to anything. It probes, it associates, it emits sequence numbers, it
carries vendor quirks. Passive SIGINT reads that emission stream and
builds knowledge from it — presence, identity, relationships, history —
with zero interaction. Passive means **undetectable and non-disruptive**:
nothing on the target network can tell it is being observed, and nothing
sloth does can break it.

## Technique 1 — Presence & inventory (site survey)

*Who and what is here?* Enumerate every AP and every client in RF range.

- **APs**: SSID, BSSID, channel, security posture (cipher/AKM/PMF),
  vendor (from OUI), hidden-SSID reveal. → Beacons `[b]`.
- **Clients**: MAC (often randomised), signal strength, activity. →
  Probe `[7]`, WiFi `[3]`, Devices `[g]`.
- **Channel occupancy**: where the activity is across the band. → Channel `[m]`.
- **Repeatable survey**: `--snapshot-out` writes a normalised AP
  inventory; `--baseline-in` diffs a later run against it (new/gone/
  changed APs). → [[posture-report]].

**Tradecraft limit**: one channel at a time ([[monitor-mode]]). A true
survey hops the band and dwells; a single-channel snapshot is partial.

## Technique 2 — Device fingerprinting

*Which device is this, beyond its (randomised) address?*

- **PNL fingerprint** — the set of SSIDs a device remembers is close to
  unique and stable across MAC rotations. → PNL `[k]`.
- **OS / chipset fingerprint** — vendor information elements in probe
  requests reveal the OS family and often the chipset, and they too
  survive rotation. → PNL `[k]` (OS column).
- **TLS client fingerprint (JA3)** — once a device passes TLS traffic,
  the ClientHello shape identifies the client stack. → TLS `[t]`,
  [[ja3-fingerprinting]].

## Technique 3 — Deanonymisation of randomised MACs

*Are these two random addresses the same physical radio?*

The 802.11 sequence-control counter runs forward per-radio and does not
reset on a MAC change. Frames from one radio fall on one monotonic
12-bit counter trail, so two addresses sharing a trail (within an
evidence window) are a candidate for the same device. → Seqnum `[j]`,
[[mac-randomisation]].

**Tradecraft limit — stated as policy, not caveat**: this is a
*hypothesis about a radio*, never an identification of a person. sloth
reports a calibrated score and the evidence window, and the finding is
**not on its own grounds for personnel action or physical
identification** (#94). `--no-correlate` disables the linkage entirely.

## Technique 4 — Relationship mapping

*Who is talking to whom?*

- **STA ↔ AP association** — confirmed pairings with graded evidence
  (EAPOL definitive; (Re)Assoc responses strong). → Assoc `[w]`.
- **Cross-view correlation** — chain the primitives: a probe (raw) →
  PNL fingerprint + seqnum identity → the AP it associated to → the
  handshake against it. This chain is the heart of [[wifi-sigint]].

## Technique 5 — Passphrase-strength testing (your own network)

*Is our WPA2 passphrase guessable?*

The 4-way handshake and PMKID are passively capturable and let an offline
guess verify itself. sloth captures them and exports hashcat 22000 format
plus a replayable per-handshake pcap, so an operator can test the
strength of a passphrase **they own**. → EAPOL `[e]`, [[wifi-sigint]],
[[pcap-export]].

**Tradecraft limit**: this is crackable material. Files are `0600` in a
`0700` dir, validated not repaired (`README.md` #87). The legitimate use
is auditing your own network; the [wifi-surveyor persona](https://github.com/SpaceTrucker2196/sloth/blob/main/docs/personas/wifi-surveyor.md)
scenario is scoped to authorised assessment.

## Technique 6 — Attack detection (counter-SIGINT)

*Is someone else running the techniques above, against us?*

The same passive stream that collects also detects collection and
attack: evil twins, KARMA, deauth floods, BTM steering, FragAttacks,
rogue RADIUS. Full map: [[where-exploits-happen]]. This is the defensive
face of the same radio discipline.

## The discipline, in one rule

Every technique here is **receive-only**. No probe injection, no deauth,
no association, no decryption of others' traffic. That is what separates
passive SIGINT from active attack tooling, and it is the line
`MISSION.md` draws and enforces. See [[what-sloth-does]] "What it never
does".

## Related pages

- [[wifi-sigint]] — the v1.1 primitive set and correlation chain.
- [[how-wifi-works]] · [[monitor-mode]] — the substrate.
- [[mac-randomisation]] — technique 3 in full, with the score.
- [[where-exploits-happen]] — the counter-SIGINT map.
- [[wifi-state-of-the-art]] — how these techniques shift with Wi-Fi 7/8.
