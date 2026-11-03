---
type: OPEN_SETUP_AP
technique: ""
rule_file: src/alerts/rules_twin.c:1192 of rule_open_setup_ap()
count_semantics: per poll tick (POLL_MS 250 ms default, include/sloth.h:28) on which an OPEN beacon_ap row with a matching setup-prefix SSID is still in the beacon table; fire() bumps `evaluations` (= `count`) once per alerts_update() call under the key, not per beacon frame (src/alerts/engine.c:478-479). Rows age out after BEACON_AGE_SECS (300 s, include/sloth.h:1297), so count ~ 4 x seconds the device stayed in setup mode and in range.
severity_assessment: agree - WARN is right for an exposure that nobody has yet been seen to use; the harm needs a second party to join the SoftAP, which sloth cannot see from the beacon.
false_positive_risk: medium - every hit is a real open AP with a setup-shaped name, but "mid-setup for two minutes" and "abandoned in setup mode for a year" fire identically, and the prefix table has four rows (SETUP-, roborock-vacuum-, NETGEAR_EXT, HP-Print-) whose provenance is field observation rather than a vendor document.
noise_verdict: not seen on the reference host - host data is null for this type. Expected shape if it does fire: one key per BSSID (`opensetup:<bssid>`), count rising ~4/s while the device is visible, resolving after the beacon row ages; no fan-out, so even a crowded apartment block yields one row per unconfigured device. No tuning knob exists and none is needed at that shape.
prevalence: common as a posture, unquantified - NIST SP 1800-36 (Nov 2025) names open-network credential delivery as a standing onboarding practice [1][4]; no survey counting open setup SoftAPs in the wild was found or fetched. No fetched source reports an attack campaign built on it.
tuning: []
researched: 2026-10-27
---
## What the rule checks

Inputs: the beacon table `s->beacon_aps[]` (`beacon_ap_t`, filled by `src/beacon_snoop.c` from monitor-mode Beacons and by the managed-scan path in `src/platform/linux_wifi.c`). The walk is `src/alerts/rules_twin.c:1166-1207`; the rule sits at line 48 of `src/alerts/rules_table.c`, which is 22nd in run order (the table's first row, `rule_port_scan`, is line 27).

Per row, four gates in order:

1. `!a->ssid[0]` -> skip (hidden SSID; rules_twin.c:1172).
2. `a->enc[0] && !ascii_ieq(a->enc, "OPEN")` -> skip. An empty `enc` (a row from a path that never decided) is treated as open, matching what `rule_evil_twin` and `twins.c` do; compared case-insensitively because the managed-scan path renders `Open` (rules_twin.c:1180).
3. `ssid_is_public_hotspot(a->ssid)` -> skip. The guardrail runs **before** the pattern table (rules_twin.c:1183). It is a case-insensitive prefix match on `g_open_hotspot_ssids[]` (`xfinitywifi`, `XFINITY`, `attwifi`, `CoxWiFi`, `Cox Mobile`, `CableWiFi`, `optimumwifi`, `SpectrumWiFi`, `Google Starbucks`, `Boingo`, `@Reyee`; rules_twin.c:1112-1124) plus a substring match on `guest` anywhere in the SSID (rules_twin.c:1131-1134).
4. Case-insensitive prefix match against `g_setup_ssid_pats[]` (rules_twin.c:1145-1164): `SETUP-` ("device setup SSID"), `HP-Setup` ("HP printer setup"), `HP-Print-` ("HP print SoftAP"), `DIRECT-` ("Wi-Fi Direct group, unprotected"), `roborock-vacuum-` ("robot vacuum provisioning"), `NETGEAR_EXT` ("range extender unconfigured"). First match wins.

Key: `opensetup:<bssid>` via plain `snprintf` (rules_twin.c:1202) - one incident per device, rising count, not one per poll. Detail: `open <what>: SSID <ssid,32> BSSID <bssid> ch <channel>, unauthenticated setup surface` (rules_twin.c:1203-1205). Fires `ALERT_SEV_WARN` with `match_ip = NULL`, so there is no per-alert pcap (src/alert_pcap.c:105 returns 0 on an empty `match_ip`) and no evidence-ring citation (`fire()`, not `fire_ev()`). Technique is `""` by design - `include/sloth_alerts.def:153` with the comment "exposure, not adversary technique (#80)"; `src/jsonl.c` omits the `technique` field for such kinds (docs/wiki/jsonl-schema.md:298).

There is no escalation path. The alert resolves when no rule re-asserts the key for `ALERT_RESOLVE_AFTER_S` (300 s, include/sloth.h:860; the engine contract is stated at src/alerts/engine.c:44), which in practice means the beacon row aged out or the AP stopped being OPEN / stopped matching. Thresholds: none; the rule is a pure predicate.

## The attack

A headless device - a printer, a robot vacuum, a range extender, a camera - has to be told which WLAN to join and its passphrase. The cheapest way to do that without a screen is for the device to bring up its own Wi-Fi network, usually **open** (no encryption), so a phone can join it and post the credentials over HTTP or a vendor app [4]. NIST's practice guide on onboarding states the problem directly: "Wi-Fi is sometimes used to provide credentials over an open (i.e., unencrypted) network, but this onboarding method risks credential disclosure" [1][4]. While the device is in that state, anyone in radio range can join its SoftAP and drive the same provisioning flow - point the device at a network they control, rewrite its configuration, or stand up a copy of the setup SSID and collect the home passphrase the owner types in [1][4]. NIST's second observation is the mirror of the first: "many IoT devices onboard to networks without verifying the network's identity" [1].

What an attacker gains is bounded by the device: configuration control of that device (and, for a camera or extender, a foothold that bridges onto the WLAN once the owner finishes setup), or the WLAN passphrase if the owner can be induced to type it into the attacker's clone. No specific exploitation tooling is needed - a laptop and the vendor's own app or web page suffice, which is also why no tool is named here.

Two of the six prefixes have a normative basis rather than a field one:

- `DIRECT-`: Wi-Fi P2P Technical Specification v1.5 §3.2.1 requires "Each SSID shall begin with the ASCII characters 'DIRECT-'" and, in the same clause, that the Group's Credentials "Use WPA2-PSK as Authentication Type" and "Use AES as Encryption Type" [6]. An **open** `DIRECT-` network is therefore a device operating outside its own specification; that is the finding, not merely "a P2P group exists".
- `HP-Setup`: HP printers advertise `HP-Setup>xx-<model>` until joined to a WLAN; the repo's source for "listed as unsecured" is an HP support-forum thread [1][7]. That URL returned HTTP 403 to today's fetch, so the claim rests on the repo's 2026-09-17 retrieval, not on a re-read.

The remaining four (`SETUP-`, `HP-Print-`, `roborock-vacuum-`, `NETGEAR_EXT`) are recorded in the research doc as observed on open SoftAPs during the passive run behind #80, with the explicit caveat that this provenance "is weaker than a spec clause and is recorded as such" [1]. A NETGEAR knowledge-base URL tried today returned 404; no vendor document for those four was confirmed.

## Evidence that proves it

What sloth records:

- The `alert` / `alert.create` JSONL records with `title OPEN_SETUP_AP`, `key opensetup:<bssid>`, `sev 1`, no `technique` field (docs/wiki/jsonl-schema.md:287-298), `count` = evaluations.
- The `beacon` JSONL record for the same `bssid`: `ssid`, `enc` (must read `OPEN` or be empty), `channel`, `signal_dbm`, `has_wps`/`wps_state`, `vendor`, `wps_manufacturer`/`wps_model_name`/`wps_serial` when the WPS IE leaks them, `frame_count`, `last_seen` (docs/wiki/jsonl-schema.md:700). The WPS vendor strings are the single most useful corroboration: a device in factory setup mode usually carries a WPS IE naming its make and model.
- No pcap and no evidence-ring frames: `match_ip` is NULL and the rule uses `fire()`.
- sensor_health: nothing specific moves; `evict_beacon_ap` matters only if the table is thrashing.

To call it real, a reader should see: an `enc:"OPEN"` beacon whose SSID carries the setup prefix **and** whose WPS IE / vendor OUI agrees with the device class the detail named (`HP-Setup...` with an HP OUI or `wps_manufacturer:"HP"`; `roborock-vacuum-...` with a Roborock/Espressif-class OUI). The exposure is proven by the beacon alone - no second party is required - so the question is not "is this real" but "is this still in setup, or abandoned there". A `first_seen`/`last_seen` span of minutes with the SSID then disappearing is a normal onboarding; a span of days is an abandoned surface.

What would refute it (as an *exposure*): an `enc` that is not `OPEN` on a fresh look (the rule would stop firing); a hidden-SSID twin of the same BSSID (not applicable - hidden never fires); or a SoftAP that, on inspection, accepts no provisioning (a captive splash with nothing behind it). sloth cannot see the last of these - joining the SoftAP is active and outside MISSION §2.

What sloth does **not** have: whether anyone joined the SoftAP. A station associating to the open setup BSSID would appear in the association tracker if the frames were heard, but the rule does not correlate that and the alert does not claim it.

## Benign causes

- **A device legitimately mid-setup.** The owner has just unboxed the printer. This is the common case and the research doc is explicit that it still fires on purpose, "because the window is exactly when the exposure exists" [1]. Fingerprint: short lifetime, then the SSID vanishes and a new client appears on the WLAN with the same vendor OUI.
- **A permanently-open Wi-Fi Direct or print SoftAP.** `HP-Print-` and `DIRECT-` are long-lived SoftAPs on printers. Per the P2P spec they must be WPA2-PSK [6], and HP's Wi-Fi Direct SoftAP ships with a password, so an open one is a misconfiguration - still correctly reported, but the operator should expect it to persist rather than age out.
- **A hotspot the guardrail did not anticipate.** The allowlist is a short list of US carrier/venue names plus the token `guest`. A European carrier SSID beginning with `SETUP-` would not be excused - but nothing fetched suggests such an SSID exists, and the table is prefix-anchored, which keeps the exposure narrow.
- **Guardrail false negative, not false positive:** any setup SSID containing `guest` is suppressed before the pattern table (rules_twin.c:1131-1134; the same logic `rule_cam_setup_ssid` inherits and documents as a live false-negative path at rules_twin.c:1250+). Mentioned so a reader does not conclude silence means absence.

## Assessment

**Severity.** WARN is right. The rule observes a third party's exposure, not an adversary's action; nothing in a beacon says anyone has used the surface. CRIT would claim more than was seen, and the research doc's reasoning for an empty technique (T1557 is what comes *after* joining; T1600 needs crypto weakened rather than absent) [1] applies equally to severity.

**Prevalence.** Open-SoftAP onboarding is widespread enough that NIST wrote a practice guide to replace it, keyed on Wi-Fi Easy Connect / DPP [4][5][8]; that is the only quantification available - "common practice", not a percentage. No fetched source describes an attack campaign against unconfigured setup APs, so the real-world *attack* prevalence is undocumented rather than known-low.

**Noise on the reference host.** Not seen (host data null). If it fires: one key per BSSID, count ~4 per second of visibility (250 ms tick), no fan-out. Worst plausible case - a printer left in setup mode for a day in range - is one row with count ~350,000 and one `alert.create` plus throttled `alert.update` events whose detail only changes if the channel changes. That is a quiet type by construction; no dedupe or knob is warranted.

**Is the evidence sufficient to act on?** Yes for the exposure (the beacon *is* the finding), no for any claim of compromise. The right first move is physical: the detail gives SSID, BSSID and channel; the `beacon` record gives RSSI and, often, make/model from the WPS IE. Find the device. If it is the operator's, finish or abort its setup (docs/wiki/alert-remediation.md:1242-1263). If it is not, inform whoever owns it; do not join its SoftAP or provision it - that is active and is theirs to fix. For the operator's own future devices, prefer Easy Connect / DPP onboarding, which authenticates with public-key cryptography via QR/NFC rather than an open network [1][8] (the Alliance page says "public key cryptography" and QR/NFC; the DPP name comes from [1]).

**Gaps worth stating.** Four of six prefixes lack a vendor document; the HP source could not be re-read today (403). The rule does not correlate stations joining the setup BSSID, which would be the one passive observation that upgrades "exposed" to "being used". No `technique`, by design, so consumers filtering on ATT&CK will not see this type.

## Bibliography

1. research/papers/nist-sp1800-36-onboarding.md - repo document citing this type (retrieved 2026-09-17); source of the HP-Setup forum claim and the field-observation provenance note (accessed 2026-10-27)
2. research/papers/camera-setup-softap.md - sibling rule CAM_SETUP_SSID; documents why that rule is not gated on OPEN and the shared `guest` guardrail (accessed 2026-10-27)
3. docs/views/alerts.md row `OPEN_SETUP_AP` (line 147); docs/wiki/alert-remediation.md §`OPEN_SETUP_AP` (lines 1242-1263); docs/wiki/where-exploits-happen.md:48 (accessed 2026-10-27)
4. NIST SP 1800-36, Trusted IoT Device Network-Layer Onboarding and Lifecycle Management, final, November 2025 - https://csrc.nist.gov/pubs/sp/1800/36/final (accessed 2026-10-27; the Vol. A sentence on open-network credential disclosure is quoted via [1])
5. NCCoE project page, Trusted IoT Device Network-Layer Onboarding and Lifecycle Management - https://www.nccoe.nist.gov/projects/trusted-iot-device-network-layer-onboarding-and-lifecycle-management (accessed 2026-10-27; returned 403 to the automated fetch - listed as the project's home, confirmed via [4])
6. Wi-Fi Alliance, Wi-Fi Peer-to-Peer (P2P) Technical Specification v1.5, §3.2.1 P2P Group ID ("Each SSID shall begin with the ASCII characters 'DIRECT-'"; Credentials shall "Use WPA2-PSK as Authentication Type" and "Use AES as Encryption Type") - https://cse.iitkgp.ac.in/~bivasm/sp_notes/wifi_direct_2.pdf (accessed 2026-10-27; 2.7 MB PDF, text extracted locally with pdftotext; both sentences confirmed in §3.2.1)
7. HP Support Community, "HP-setup network doesn't appear" - https://h30434.www3.hp.com/t5/Printers-Archive-Read-Only/HP-setup-network-doesn-t-appear/td-p/7909443 (accessed 2026-10-27: HTTP 403 to a plain fetch; with a browser User-Agent the URL returns HTTP 200, but the 5.8 KB body is a Cloudflare challenge interstitial, not the thread - still unread; claim rests on the repo's 2026-09-17 retrieval in [1])
8. Wi-Fi Alliance, Wi-Fi Easy Connect - https://www.wi-fi.org/discover-wi-fi/wi-fi-easy-connect (accessed 2026-10-27; confirmed "Public key cryptography for secure authentication" and onboarding by "scanning a product quick response (QR) code, NFC tag"; the page does not use the name "Device Provisioning Protocol")

## Verification notes

Verified 2026-10-27 against the working tree at c5650a3.

Code (re-read `src/alerts/rules_twin.c:1100-1210`, `src/alerts/rules_table.c`, `src/alerts/engine.c`, `src/beacon_snoop.c`, `src/alert_pcap.c`, `src/jsonl.c`):

- `rule_file`, the four gates and their order, the hotspot allowlist (1112-1124), the `guest` substring (1134), the six-row prefix table (1145-1164), first-match-wins, WARN, `match_ip` NULL, plain `fire()` - all confirmed as written.
- Corrected the key/detail line numbers: key `snprintf` is at 1202 (was 1200), detail at 1203-1205 (was 1201-1204).
- Corrected `fire()`'s evaluation bump to engine.c:478-479 (was 476-478); `a->count` is the compat alias of `evaluations` at 479.
- `ALERT_RESOLVE_AFTER_S` is a define at include/sloth.h:860 (300 s); engine.c:44 is the contract comment. Added the value and the define location.
- Beacon rows do age out at `BEACON_AGE_SECS` (beacon_snoop.c:1522), so the resolve path described holds.
- `alerts_update()` runs once per `poll_tick()` (src/poll.c:296), so count = ticks. POLL_MS's own comment (sloth.h:28) notes the loop also wakes early on alert fires, so "~4/s" is the default-cadence figure, not a guarantee.
- Slot 48 in `rules_table.c` is line 48 of the file; the table starts at line 26, so it is the 22nd rule in run order. The text says "slot 48" meaning the file line; left as is since the file line is what a reader greps for.
- Noise arithmetic: 4 ticks/s x 86,400 s = 345,600, matching "~350,000".

Sources:

- [4] csrc.nist.gov: confirmed Final, November 2025, "Wi-Fi Easy Connect" in keywords. The page does not itself carry the open-network credential-disclosure sentence (that is in Vol. A, quoted via [1]); the bibliography already said so. Moved the frontmatter prevalence citation from [4][5] to [1][4] because [5] could not be read.
- [5] nccoe.nist.gov: HTTP 403 again on re-fetch. Left as the project's home with the 403 recorded; nothing in the body rests on it alone.
- [6] P2P spec v1.5: fetched (2.7 MB PDF), extracted with pdftotext. §3.2.1 "P2P Group ID" confirmed to contain both "Each SSID shall begin with the ASCII characters 'DIRECT-'" and the Credentials list "Use WPA2-PSK as Authentication Type. / Use AES as Encryption Type." Bibliography entry expanded with the exact wording.
- [7] HP forum: HTTP 403 again. Unchanged; the claim remains attributed to the repo's 2026-09-17 retrieval.
- [8] wi-fi.org Easy Connect: confirmed "Public key cryptography for secure authentication" and QR/NFC onboarding. The page does not use the name "Device Provisioning Protocol"; the Assessment sentence now cites [1][8] and says where the DPP name comes from.
- research paths: `research/papers/nist-sp1800-36-onboarding.md` (names OPEN_SETUP_AP, 3 hits) and `research/papers/camera-setup-softap.md` (names OPEN_SETUP_AP, 4 hits) both exist. docs/views/alerts.md:147, alert-remediation.md:1242, where-exploits-happen.md:48 confirmed.

Second pass, 2026-10-27, against 0d60387 (HEAD). `git diff --stat c5650a3..HEAD` touches only `web/`, `docs/assets/slothweb/`, `docs/wiki/log.md` and `docs/wiki/slothweb.md`, so every source line cited above was re-read on the current tree and is unchanged: `src/alerts/rules_twin.c:1112-1134` (hotspot allowlist and `guest` substring), `1145-1164` (six-row prefix table), `1166-1207` (gates at 1172/1180/1183, key `snprintf` at 1202, detail 1203-1205, WARN, NULL `match_ip`), `src/alerts/rules_table.c:48`, `include/sloth.h:28/860/1297`, `src/alerts/engine.c:478-479`, `src/poll.c:296`.

Sources re-fetched this pass: [4] csrc.nist.gov (Final, November 2025, "Wi-Fi Easy Connect" in keywords; the open-network credential-disclosure sentence is not on the landing page, as already stated), [5] nccoe.nist.gov (HTTP 403 again), [6] P2P spec PDF (HEAD 200, application/pdf), [7] HP forum (see change below), [8] wi-fi.org Easy Connect ("Public key cryptography for secure authentication", QR/NFC, no "DPP"). All consistent with the text.

Change in this pass: bibliography [7] now records that the HP URL answers 200 to a browser User-Agent but serves a Cloudflare challenge page, so the thread remains unread either way. No other text changed.

Third pass, 2026-10-27, against d70d394 (HEAD; `git diff --stat 0d60387..HEAD` is `LEDGER.md` only, so the tree is the one the second pass read). Code re-read independently rather than from the earlier notes; every external source re-fetched with curl (browser User-Agent) and grepped for the quoted text.

Code: `rule_open_setup_ap()` (rules_twin.c:1166-1207), the hotspot allowlist and `guest` substring (1111-1134), the six-row prefix table (1145-1164), `fire()`'s evaluation bump (engine.c:478-479; a new incident starts at `count = 1`), `POLL_MS` 250, `ALERT_RESOLVE_AFTER_S` 300 and `BEACON_AGE_SECS` 300 all re-confirmed. The gates, key, detail, WARN, NULL `match_ip` and the noise arithmetic (4/s x 86,400 s = 345,600) hold.

Change: "run order slot 48" was wrong - 48 is the file line, and the rule is 22nd in run order. The first pass noticed and left it; corrected now, and the walk's end line tightened from 1210 to 1207 (the closing brace).

Sources: [4] csrc.nist.gov (200; "Date Published: November 2025", Final, "Wi-Fi Easy Connect"), [6] P2P spec PDF (200, 2.85 MB; pdftotext finds "Each SSID shall begin with the ASCII characters "DIRECT-"", "Use WPA2-PSK as Authentication Type." and "Use AES as Encryption Type."), [8] wi-fi.org (200; "Public key cryptography for secure authentication", "quick response (QR) code, NFC tag", no "Device Provisioning Protocol"). [5] nccoe.nist.gov and [7] HP forum both 403 again with a browser UA. Nothing struck. research paths: `nist-sp1800-36-onboarding.md` (3 hits) and `camera-setup-softap.md` (4 hits) exist and name the type.
