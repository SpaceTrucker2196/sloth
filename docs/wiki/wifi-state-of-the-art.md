---
name: wifi-state-of-the-art
description: Living overview of the state of the art in Wi-Fi technology and Wi-Fi security research, and what each shift means for a passive monitor like sloth
type: reference
---

# Wi-Fi state of the art

**Summary**: A living snapshot of where 802.11 technology and Wi-Fi
security research stand, and — the reason it lives in this repo — what
each shift means for a **passive** monitor. Update this page when a
generation ships, a major vulnerability class lands, or a defence changes
what is visible on the air. This is the "keep an overview of the state of
the art in WiFi tech in this repo" page.

**Sources**: IEEE 802.11 task-group schedules, Wi-Fi Alliance, and the
research corpus under `research/` (`research/papers/`, `research/cve/`).
Web-sourced items carry a date and a link.

**Last updated**: 2026-09-30.

---

## Generations at a glance

| Marketing | Amendment | Bands | Headline | Status (2026) |
|-----------|-----------|-------|----------|---------------|
| Wi-Fi 4 | 802.11n | 2.4/5 | MIMO | legacy, ubiquitous |
| Wi-Fi 5 | 802.11ac | 5 | wider channels, MU-MIMO | legacy |
| Wi-Fi 6 | 802.11ax | 2.4/5 | OFDMA, efficiency | mainstream |
| **Wi-Fi 6E** | 802.11ax | +6 GHz | clean 6 GHz spectrum | widely shipping |
| **Wi-Fi 7** | 802.11be | 2.4/5/6 | 320 MHz, 4K-QAM, **MLO** (multi-link operation) | shipping, current high end |
| **Wi-Fi 8** | 802.11bn (UHR) | 2.4/5/6 | **reliability** over raw speed | in draft — see below |

### Wi-Fi 7 (802.11be) — the current frontier

The defining feature is **Multi-Link Operation (MLO)**: one logical link
spread across two or three bands at once. For a passive monitor this is a
structural challenge — a single device's traffic is now split across
channels *and bands simultaneously*, so single-radio, single-channel
capture ([[monitor-mode]]) sees only a fraction of a Wi-Fi 7 conversation.
Full visibility increasingly needs multiple synchronised monitor radios.
This is the biggest capture-side shift since 6 GHz and is worth tracking
in sloth's roadmap.

### Wi-Fi 8 (802.11bn / UHR) — in draft

802.11bn is branded **Ultra High Reliability**; it targets reliability,
latency and seamless roaming rather than a new peak rate. Per the IEEE
P802.11 TGbn schedule as of 2026: draft D2.0 letter ballot **May 2026**,
D3.0 **Jan 2027**, final WG approval **March 2028**, RevCom/SASB **May
2028**. Wi-Fi Alliance certification is planned around **early 2028**, so
first "Wi-Fi 8" market devices are expected **2027–2028** (pre-cert
silicon may appear sooner). Because the focus is reliability, expect more
coordination and steering machinery (the 802.11k/v/r family) — which is
exactly the management-frame surface [[action-frames]] and [[btm-abuse]]
already watch. ([Wi-Fi 8 overview](https://en.wikipedia.org/wiki/Wi-Fi_8),
[TGbn schedule](https://grouper.ieee.org/groups/802/11/Reports/tgbn_update.htm),
[completion 1H2028 / cert Jan 2028](https://wifinowglobal.com/news-blog/wi-fi-8-standard-on-track-for-completion-in-1h2028-with-certification-scheduled-for-january-2028/))

## Security: where the research is

sloth's detectors are built on named research; the corpus under
`research/` is the machine-readable index ([[research-corpus]]). The live
landscape:

- **WPA3 / SAE — Dragonblood (Vanhoef & Ronen, 2019).** Five flaws: a
  DoS, two **downgrade** attacks (force WPA2's capturable handshake), and
  two **side-channel** leaks of the SAE password element. Mitigated by
  patches, but the *transition mode* (WPA3 that also accepts WPA2) keeps
  the downgrade lane open in practice. sloth watches this with
  `SAE_PSK_SPLIT`, `SAE_PSK_REGRESSION`, `WPA_DOWNGRADE`.
  ([Dragonblood follow-up](https://www.hackread.com/future-of-wi-fi-security-assessing-vulnerabilities-in-wpa3/))
- **FragAttacks (Vanhoef, 2021).** Twelve CVEs in 802.11 fragmentation
  and aggregation — design flaws present since 1997, plus common
  implementation bugs. sloth ships seven `FRAG_*` detectors covering eight
  of the twelve; see [[fragattacks]] for which, and why the A-MSDU
  detector as usually described cannot work.
- **SSID Confusion (CVE-2023-52424, 2024).** A client can be made to
  connect to a trusted network under the wrong SSID because the SSID is
  not authenticated in the 4-way handshake. → `SSID_CONFUSION`.
- **PEAP without server-cert validation (CVE-2023-52160).** A
  misconfigured *client* in your own fleet accepts a rogue enterprise
  server. → `PEAP_NO_SERVER_CERT`, [[enterprise-rogue]].
- **The perennial: unprotected management frames.** Every deauth/evil-
  twin/KARMA attack still works wherever **PMF (802.11w)** is not
  enforced. WPA3 mandates PMF, which is the single biggest defensive
  improvement in the stack — and the reason `MFP_UNPROTECTED` matters.

## Defences that change what is visible

The arms race is two-sided; these defences shrink the passive-collection
surface, and sloth adapts to each:

- **MAC randomisation** (all modern OSes) — defeats address-based
  tracking. Countered by PNL + sequence-number analysis
  ([[mac-randomisation]]), themselves imperfect and policy-bounded.
- **Mandatory PMF (WPA3)** — signs management frames, blunting forged-
  deauth attacks. Shifts detection toward SA-Query storms as the
  *symptom* ([[action-frames]]).
- **6 GHz-only enhancements** — some management frames are protected or
  changed on 6 GHz, and beacon protection is arriving. Ongoing.
- **RCM / randomised & changing MAC** and per-network MACs continue to
  tighten across OS releases.

## How to keep this page current

This is the repo's Wi-Fi radar. When any of the below happens, update the
relevant section here **and** add a `research/` document if it backs a
detector (that is enforced — [[research-corpus]]):

1. A Wi-Fi generation ships or its schedule moves → the generations table.
2. A significant vulnerability class is disclosed → the security section
   (with date + link), and open an issue if it implies a new detector.
3. A defence changes what is observable → the defences section, and note
   the capture-side impact for [[monitor-mode]] / roadmap.

## Related pages

- [[how-wifi-works]] — the protocol these generations extend.
- [[where-exploits-happen]] — the attack surface, mapped to detectors.
- [[wifi-sigint-techniques]] — collection techniques, and how defences bend them.
- [[research-corpus]] — the cited basis behind each detector.
- [[non-ip-sensors]] — the passive-RF roadmap.
