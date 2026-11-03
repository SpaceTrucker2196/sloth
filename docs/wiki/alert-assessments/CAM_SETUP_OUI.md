---
type: CAM_SETUP_OUI
technique: ""
rule_file: src/alerts/rules_camera.c:223 of rule_cam_setup_oui()
count_semantics: per poll tick (POLL_MS 250 ms) in which the matching BSSID is still in the beacon table; `count` is the engine's `evaluations` alias, not a frame or incident count. One incident per BSSID (`camoui:<mac>`); it re-asserts every tick for as long as the AP's last beacon is under BEACON_AGE_SECS (300 s) old, and resolves 300 s after the rule stops re-asserting it.
severity_assessment: agree - WARN for an exposure (a camera-vendor box acting as an AP) that corroborates but cannot confirm a camera; CRIT would claim a device class the rule itself says it did not observe.
false_positive_risk: medium - the registry assignment names the maker, never the product (a Hikvision NVR or an Arlo base station match as readily as a camera), and the `randomized-local` form rests on 22 free bits coinciding.
noise_verdict: quiet in incidents, very noisy in the `count` metric on the reference host - 7,557,910 fires on 2 keys, max_sev WARN: two BSSIDs, each re-evaluated ~3.78M times, which at one evaluation per tick, with ticks at most 250 ms apart, is at most ~10.9 days of continuous presence per BSSID (an upper bound). This is two resident camera-vendor APs, not 7.5M events; the metric is the artefact. slothweb's alert page leads with `observations` (detail-change count) and shows `count` as evaluations since #179 (2026-11-03); still recommend an inventory/known-BSSID suppression for a camera base station the operator owns (no `--tune` knob exists for this rule today). Since #173: re-checked by test (tests/test_alert_tick_rate.c): a standing camera-vendor BSSID whose signal, frame count and last_seen move every pass is 600 evaluations and 1 observation over 600 passes, and a channel change adds one - the detail reads only channel, SSID, encryption and the OUI match, so no rule change was needed; `count` is the engine's per-tick evaluations
prevalence: common as an exposure, not as an attack - consumer and SMB cameras from the vendors in the table ship with a setup SoftAP by design [8][9], and two of the vendors have authentication-bypass / command-injection CVEs in CISA's Known Exploited Vulnerabilities catalogue [10][11], which is why a camera-vendor box on the air is worth a row.
tuning: [none - the rule reads no registry knob; `camera.join_fresh_secs` affects the Devices join (src/camera_join.c), not whether this rule fires]
researched: 2026-10-27
---
## What the rule checks

`rule_cam_setup_oui()` (src/alerts/rules_camera.c:223-260) walks `s->beacon_aps[]`, the table `src/beacon_snoop.c` fills from 802.11 beacon frames (MAX_BEACON_APS 256, include/sloth.h:1295; an AP is dropped once its last beacon is older than BEACON_AGE_SECS = 300 s, include/sloth.h:1297, src/beacon_snoop.c:1522). For each AP it calls `cam_setup_oui_counts()` (src/camera_join.c:207-224), which in turn calls `cam_vendor_oui()` (src/camera_vendor.c:525-547; contract in src/camera_vendor.h:31-48):

- the first three octets of the BSSID are compared with the embedded `g_cam_oui[]` table (src/camera_vendor.c:9-33 and the rows that follow) with **bit 1 of octet 0 - the IEEE 802 universal/local bit - masked off**; the I/G bit is not masked because a group address never transmits a beacon (src/camera_vendor.h:31-36). The mask exists for #106's field case, a UniFi setup AP beaconing `B6:FB:E4` for the registered `B4:FB:E4` [1];
- a **camera-vendor row** (Hikvision, EZVIZ, Dahua, Amcrest, Axis, Reolink, Mobotix, Lorex, Arlo) matches on the OUI alone; when the observed address had the U/L bit set, `*local` is 1 and the detail says `randomized-local` (src/camera_vendor.h:37-41);
- a **mixed-vendor row** (Ubiquiti, TP-Link, Wyze; #155) matches only when the same BSSID also beacons a camera setup SSID that is not a public hotspot name - `cam_setup_oui_counts()` returns 0 otherwise (src/camera_join.c:213-217) - and never on a locally administered address (src/camera_vendor.h:43-48).

Key: `akey_begin(..., "camoui")` + `akey_mac(bssid)` (src/alerts/rules_camera.c:236-238) - one incident per BSSID. Detail (src/alerts/rules_camera.c:241-256): `BSSID <mac> ch <n> SSID <ssid|<hidden>>, enc <enc|unknown>: OUI XX:XX:XX is IEEE MA-L "<assignee verbatim>" (<brand>, camera vendor|mixed vendor; device class not observed)` followed by `; counted only beside its camera setup SSID` (mixed) or `; randomized-local: U/L bit set, matched with it masked - not itself a registry assignment` (local). The OUI in the detail is printed with the U/L bit cleared (`a->bssid[0] & ~0x02u`, line 248). `fire()` is called with `match_ip` NULL and port 0 (line 257-258): no per-alert pcap can be written for it (src/alert_pcap.c:20-22 requires a `match_ip`).

Severity is fixed WARN; there is no escalation. The engine (src/alerts/engine.c:474-489) increments `evaluations` (aliased to `count`) on every tick the rule re-fires the key and `observations` only when the rendered detail changes - here, when the channel, SSID or encryption string changes. The incident resolves when the key has not been asserted for ALERT_RESOLVE_AFTER_S = 300 s (include/sloth.h:860; `expire_incidents()`, src/alerts/engine.c:919-927), i.e. ~300 s after the AP leaves the beacon table, which is itself 300 s after its last beacon: roughly ten minutes after the AP goes silent.

## The attack

There is no attack in the sense of an adversary acting; this is an exposure. A network camera that is beaconing is operating as an access point: either its own setup SoftAP, the mode consumer cameras boot into so that a phone app can hand them the home Wi-Fi credentials [8], or a base station that cameras of the same brand attach to [1]. While it is in that state anyone in radio range can join the open or default-passphrase network the camera offers, and the vendor onboarding documents on file describe exactly that window [8][9]. sloth already reports it by SSID (`CAM_SETUP_SSID`); this rule reports it by **address**, so a setup AP whose SSID was renamed or hidden still shows [1].

Why a camera-vendor box on the air is worth knowing about: two of the vendors in the table have critical, actively exploited vulnerabilities. CVE-2021-36260 is a command injection in the web server of "some Hikvision product", CVSS 9.8, added to CISA's Known Exploited Vulnerabilities catalogue on 2022-01-10 [10]. CVE-2021-33044 is an "identity authentication bypass vulnerability found in some Dahua products during the login process", CVSS 9.8, added to the KEV catalogue on 2024-08-21 [11]. A camera that is reachable because it is still in setup mode, or because its base station is an AP, is the position those exploits start from.

The identifier the rule reads is defined by IEEE Std 802-2014 clause 8.2: the first three octets of a 48-bit MAC address carry the OUI the IEEE Registration Authority assigned, with bit 0 of octet 0 the individual/group bit and bit 1 the universal/local bit (1 = locally administered) [6][7]. Every row in `g_cam_oui[]` is one MA-L (24-bit) assignment from the public `oui.csv` listing with the assignee string verbatim, so each row is its own citation [1][7].

## Evidence that proves it

What sloth records for this type:

- the alert detail: BSSID, channel, SSID (or `<hidden>`), encryption string, the masked OUI, the registry assignee verbatim, the brand, `camera vendor` or `mixed vendor`, and the `randomized-local` / `counted only beside its camera setup SSID` tail (src/alerts/rules_camera.c:241-256);
- JSONL `alert.create` / `alert.update` / `alert.resolve` events on key `camoui:<mac>`, each carrying `incident_id`, `count` (= evaluations), `observations`, `first_seen`, `last_seen` (src/alerts/engine.c:20-50; docs/wiki/jsonl-schema.md);
- the `beacon` record for the same BSSID (signal, channel, capabilities, SSID), and the `device` record whose `mac` equals the BSSID: `cam_signals` bit 16 (`CAM_SIG_SETUP_OUI`), `device_class` `camera-vendor` (OUI only) or `camera` (a setup SSID too), `camera_vendor`, `setup_mode` (src/camera_join.c:596-614; docs/wiki/jsonl-schema.md:699);
- **no pcap**: `fire()` gets no `match_ip` (line 257), and 802.11 frames are in any case only exported as evidence pcaps under `--collect-handshakes` (docs/wiki/cli-reference.md:56);
- sensor_health: `evict_beacon_ap` rising means the 256-row beacon table is churning, so a BSSID can drop out and re-enter, producing resolve/create pairs for one AP.

To call it real, a reader should see: a BSSID whose first three octets, with the U/L bit cleared, equal a row the IEEE listing assigns to a camera vendor [7]; the same BSSID in the `beacon` record for more than a few minutes (a setup AP that is being provisioned normally disappears once the camera joins the home network [8]); ideally a `CAM_SETUP_SSID` incident or a `device.setup_mode = 1` on the same BSSID, which is the camera naming itself [8][9]. For the mixed-vendor form, the setup SSID is required by construction [1].

What refutes it, or weakens it: `randomized-local` in the detail - the address was locally administered and is by definition not a registry assignment, so the match rests on 22 free bits coinciding [1][6]; a `device_class` of `camera-vendor` with no other camera signal and an SSID that is the operator's own infrastructure name (a Hikvision or Dahua **NVR** serving its own Wi-Fi hotspot matches identically [1]); a BSSID that comes and goes exactly with a known device (an Arlo base station is an AP for its cameras for its whole life [1], so an incident that never resolves is normal for it).

## Benign causes

- **The operator's own camera base station or NVR.** Arlo base stations, and Hikvision/Dahua NVRs with a Wi-Fi hotspot, beacon continuously on a camera-vendor OUI; the rule says "device class not observed" for exactly this reason [1]. This is the most likely explanation of a never-resolving incident, and of the reference host's two keys.
- **A camera being provisioned right now.** The vendor setup SoftAP (`HAP_`, `DAP-`, `EZVIZ_`, `Tapo_Cam_`) is on the air for the minutes the onboarding takes [8][9]. Expected, short-lived, and the `CAM_SETUP_SSID` incident on the same BSSID names the brand.
- **A locally administered address that happens to land in a camera block.** Flagged `randomized-local`; weigh it accordingly [1][6].
- **A non-camera product of a camera vendor.** The registry names assignees, not product lines [7]; the `Why these vendors are camera vendors` section of the corpus document explains that the second leg is the vendor's own self-description, which does not exclude their NVRs, doorbells or hubs [1].
- **A mixed-vendor false negative is more likely than a false positive**: a TP-Link, Ubiquiti or Wyze camera with no setup SSID does not fire at all (#155) [1][2].

## Assessment

**Severity.** WARN is right. The rule corroborates a camera vendor's box operating as an AP and explicitly does not establish the device class [1]; escalating would assert what the evidence does not carry. The one case that deserves more attention - an open setup AP with a default passphrase - is already `OPEN_SETUP_AP` / `CAM_SETUP_SSID`'s job, and those fire alongside.

**Prevalence.** Setup SoftAPs are a design feature of the whole consumer camera segment [8][9], so the exposure is common; the vendors concerned carry actively exploited critical CVEs [10][11]. No independent count of camera-vendor APs in the wild was confirmed for this document.

**Noise on the reference host.** 7,557,910 fires on 2 keys. The rule re-asserts a key once per `alerts_update()` tick, and `count` is the evaluation counter (src/alerts/engine.c:478-479; src/poll.c:296; POLL_MS 250 ms, include/sloth.h:28). 7,557,910 / 2 = 3,778,955 evaluations per key; at 4 per second that is ~944,700 s = ~10.9 days of a BSSID being continuously present in the beacon table (less wall time if event wakes added ticks; more if the host ran slower). Two camera-vendor BSSIDs beaconing for the life of the run - a base station or NVR hotspot - is the picture, and max_sev 1 (WARN) agrees. In incident terms this is quiet: two incidents. The number that is noisy is `count`, and the fix is presentational: show `observations`, which only moves when channel/SSID/encryption changes, and label `count` as evaluations. A second improvement is an inventory check - the rule consults none today - so a base station the operator owns can be acknowledged without silencing a new camera-vendor BSSID.

**Sufficient to act on?** As a prompt to look, yes; as proof of a camera, no. The detail says so.

**First response.** Read the BSSID and the assignee string, check whether it is a device the operator owns (the wiki section, docs/wiki/alert-remediation.md:1703). If it is being provisioned, finish provisioning; if it is a base station or NVR, record it and expect the incident to persist; if it is nobody's, locate it physically - do not join or configure it (MISSION §2) [5].

**Since #173.** Pinned rather than changed: `observations` holds at one over a standing AP and moves on a channel change (`tests/test_alert_tick_rate.c`). The inventory suppression recommended above is not done.

## Bibliography

1. research/papers/camera-vendor-identity.md - Camera identity from what the device announces (IANA, UPnP Forum, IEEE RA); the OUI table's provenance, the U/L mask and the mixed-vendor ruling (repo research corpus, accessed 2026-10-27)
2. research/papers/camera-router-role.md - Telling a camera from a router by passive traffic (#155); why a mixed-vendor OUI cannot decide the class (repo research corpus, accessed 2026-10-27)
3. docs/views/alerts.md:152 - the `CAM_SETUP_OUI` rule-table row (accessed 2026-10-27)
4. docs/wiki/alert-remediation.md:1703 - `CAM_SETUP_OUI` investigate / fix (accessed 2026-10-27)
5. docs/wiki/camera-detection.md - the camera-detection design, the device join and what is never done (accessed 2026-10-27)
6. IEEE Std 802-2014, IEEE Standard for Local and Metropolitan Area Networks: Overview and Architecture, clause 8.2 (MAC address structure: I/G bit and U/L bit) - https://doi.org/10.1109/IEEESTD.2014.6847097 (title confirmed via the Crossref record for that DOI, 2026-10-27; clause text cited via [1], which quotes it; the standard itself is paywalled)
7. IEEE Registration Authority, MA-L public listing (`oui.csv`) - https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries (the registry every `g_cam_oui[]` row is checked against; snapshot used is Debian `ieee-data` 2024-07-22 per src/camera_vendor.c:9-13; accessed 2026-10-27)
8. research/papers/camera-setup-softap.md - Camera setup-mode SoftAP SSIDs, vendor onboarding documentation (Hikvision HAP_, Dahua/Amcrest DAP-, EZVIZ_, Tapo_Cam_) with the Hikvision how-to PDF as primary source - https://www.hikvision.com/content/dam/hikvision/en/support/how-to/how-to-document/network-cameras/How-to-Set-Wi-Fi-Connection-of-Wi-Fi-Camera-via-Mobile-Phone-Web-Broswer.pdf (accessed 2026-10-27 via the corpus document; a direct fetch of the PDF returns a bot-challenge page, so the PDF itself was not read in this pass). Background source: this document names `CAM_SETUP_SSID` and `OPEN_SETUP_AP`, not `CAM_SETUP_OUI`
9. research/papers/nist-sp1800-36-onboarding.md - NIST SP 1800-36 (NCCoE), the onboarding-window exposure (repo research corpus, accessed 2026-10-27). Background source: names `OPEN_SETUP_AP`, `BTM_ABUSE`, `NO_MONITOR_MODE`, not `CAM_SETUP_OUI`
10. NVD, CVE-2021-36260 - Hikvision web server command injection, CVSS 3.1 9.8, CISA KEV added 2022-01-10, action due 2022-01-24 - https://nvd.nist.gov/vuln/detail/CVE-2021-36260 (confirmed via the NVD 2.0 API, accessed 2026-10-27)
11. NVD, CVE-2021-33044 - Dahua identity authentication bypass, CVSS 3.1 9.8, CISA KEV added 2024-08-21; vendor advisory https://www.dahuasecurity.com/support/cybersecurity/details/957 (listed in NVD's references, but returned HTTP 404 on 2026-10-27) - https://nvd.nist.gov/vuln/detail/CVE-2021-33044 (confirmed via the NVD 2.0 API, accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD d70d394) and by fetching every external source.

- Code: the rule is `src/alerts/rules_camera.c:223-260`, not 224 (rule_file and body corrected). The OUI comparison is implemented in `src/camera_vendor.c:525-547` (U/L masked with `MAC_UL_BIT`, I/G unmasked, mixed row refused on a local address); the draft cited only the header contract, now both. Key anchor `:236-238`, detail `:241-256`, resolve path `expire_incidents()` `src/alerts/engine.c:919-927` - corrected. Confirmed exactly as stated: `cam_setup_oui_counts()` `src/camera_join.c:207-226` (mixed row needs a non-hotspot camera setup SSID), detail format and the U/L-cleared OUI (`:248`), fixed WARN, `match_ip` NULL, BEACON_AGE_SECS 300 (`include/sloth.h:1297`, aged in `src/beacon_snoop.c:1522`), MAX_BEACON_APS 256, ALERT_RESOLVE_AFTER_S 300, `evaluations`/`count` alias `src/alerts/engine.c:478-479`. One nuance: `observations` also moves on a severity change (`engine.c:487-488`), which cannot happen here (fixed WARN).
- Noise arithmetic re-done: 7,557,910 / 2 = 3,778,955 per key; / 4 per s = 944,739 s = 10.93 days. Follows.
- Sources: [10] and [11] re-confirmed through the NVD 2.0 API (descriptions, CVSS 3.1 9.8, `cisaExploitAdd` 2022-01-10 / 2024-08-21, action due 2022-01-24). [6] the URL was wrong: `standards.ieee.org/ieee/802/5461/` is IEEE/ISO/IEC 80005-1-2012, not 802-2014; replaced with the DOI 10.1109/IEEESTD.2014.6847097, whose Crossref title matches. [7] the IEEE RA public listing page resolves ("Public Listing For IEEE Standards Registration Authority"); the MA-L rows are as quoted in the corpus. [8] the Hikvision PDF returns a JS bot challenge and could not be read; kept, as it is cited via the corpus document. The Dahua advisory URL inside [11] now 404s; noted, NVD still carries it.
- research/ paths: all four exist. `camera-vendor-identity.md` and `camera-router-role.md` name `ALERT_TYPE_CAM_SETUP_OUI`. `camera-setup-softap.md` and `nist-sp1800-36-onboarding.md` do not name this type (they back the setup-SoftAP facts, not the rule); labelled as background sources in the bibliography.

Review pass (2026-11-01). Per-key duration relabelled as an upper bound: POLL_MS 250 is the longest wait between ticks (include/sloth.h:28) and the loop wakes early, so ticks run at 4/s or more.
