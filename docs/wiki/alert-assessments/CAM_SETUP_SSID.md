---
type: CAM_SETUP_SSID
technique: ""
rule_file: src/alerts/rules_twin.c:1522 of rule_cam_setup_ssid(); prefix table src/camera_vendor.c:665 (g_camera_setup_ssid_pats); matcher cam_setup_ssid() at :694
count_semantics: per rule tick (one alerts_update() pass, POLL_MS=250 ms default) on which a beacon_ap row whose SSID matches a camera-vendor setup prefix is still in the beacon table. Keyed per BSSID, so one incident with a rising count per camera, not one per beacon frame. `fire()` bumps `evaluations` (= `count`) once per alerts_update() under the key (engine.c:478).
severity_assessment: agree - WARN. It reports a camera's own provisioning exposure (its first-boot password likely still unchanged), not an adversary; higher would overclaim, lower would bury a genuine exposure window.
false_positive_risk: low-medium - every hit is a real beacon carrying a vendor-documented setup-SoftAP prefix, so the match is precise; the "false" part is only that a configured camera can re-advertise this name after a factory reset, a re-pair, or because an installer left the AP on. The rule says "provisioning state not observed" for exactly this reason.
noise_verdict: not seen on the reference host - host data is null. Expected shape if it fires: one key per camera (`camsetup:<bssid>`), count rising ~4/s while the beacon is visible, resolving when the camera joins a WLAN and stops beaconing its setup AP or the row ages. No fan-out; at most one row per camera in range.
prevalence: Wi-Fi setup SoftAPs are the standard onboarding path for the four covered vendors (Hikvision, Dahua/Amcrest, EZVIZ, TP-Link Tapo) per their own documentation [1][5][6]; the broader exposure (an unprovisioned camera with an unchanged default credential) is a well-documented IoT risk class (NIST SP 1800-36) [4][7]. No count of cameras caught mid-setup in the wild was located.
tuning: []
researched: 2026-10-27
---
## What the rule checks

Input: the beacon table `s->beacon_aps[]` (`beacon_ap_t`). Run order: `src/alerts/rules_table.c:49` (0-based table index 22; immediately after the generic OPEN_SETUP_AP, and additive to it).

Gates, in order (rules_twin.c:1244-1314):

1. `!a->ssid[0]` -> skip (hidden/broadcast SSID; 1249).
2. `ssid_is_public_hotspot(a->ssid)` -> skip (1271). The hotspot guardrail runs BEFORE the prefix match, matching `rule_open_setup_ap`'s ordering. The rule's own comment (1251-1270) is explicit that this suppresses real matches today, not just future ones: `ssid_is_public_hotspot()` matches the substring `guest`, so a vendor shipping `HAP_guest...` would be invisible - a live false negative accepted because an SSID a human called "guest" is a network someone meant to be open, and a camera WARN on it is the noise that gets a type muted.
3. `!cam_setup_ssid(a->ssid, &vendor, NULL)` -> skip (1274). This is a case-insensitive prefix match (`ssid_ascii_iprefix`, camera_vendor.c:684) against `g_camera_setup_ssid_pats[]` (camera_vendor.c:665-681): `HAP_` (Hikvision), `DAP-` (Dahua/Amcrest OEM), `EZVIZ_` (EZVIZ), `Tapo_Cam_` (TP-Link Tapo - trailing underscore deliberate so Tapo plugs/bulbs cannot match).

Not gated on OPEN, unlike OPEN_SETUP_AP (header 1211-1242): Hikvision's and EZVIZ's setup APs are WPA-protected with a key printed on the device label, so an OPEN gate would make the headline case undetectable. Encryption is reported in the detail, not used as a gate: `enc unknown` when `a->enc` is empty (not read as open), `OPEN, unauthenticated` when OPEN, else `enc <cipher>` (1285-1291).

Key `camsetup:<bssid>` via plain snprintf (1297) - one row per camera. Detail (1308-1312): `<vendor> advertising its documented setup SSID: <ssid,32> BSSID <bssid> ch <channel>, <encdesc> (provisioning state not observed)`. Fires `ALERT_SEV_WARN`, `match_ip = NULL`.

## The attack

This is not an attack; the technique is empty on purpose. A headless Wi-Fi camera has no screen to type a passphrase into, so it brings up its own access point and the installer's phone joins it to hand over the WLAN credentials. The four covered vendors document this and the SSID shape each uses [1][5]. Hikvision's setup PDF confirms the shape directly: "Select the HAP_xxxxxx from the Wi-Fi list... xxxxxx stands for the verification code, which you can find on the device label," and "password is the last 8 charters [sic] of serial number on the label" [6]. Dahua uses `DAP-` ("Dahua Access Point") plus a serial fragment, inherited by its OEM Amcrest as `DAP-AMC...`; EZVIZ (Hikvision's consumer brand) uses `EZVIZ_<9-digit serial>` keyed on the label verification code; TP-Link Tapo uses `Tapo_Cam_<last 4 of MAC>` [1].

The exposure the alert names is not the SoftAP itself but what it implies: a camera that is still advertising its setup network has, in the normal case, never been through its first-boot wizard, so its admin password is whatever shipped - and the SoftAP is the surface that reaches that unchanged account. Where the setup AP is WPA-protected, the "key" is printed on the chassis the camera is mounted on, which is not a secret from anyone who can see the camera and therefore reach its RF [5][6]. The repo (#106) rejected both T1669 (Wi-Fi Networks) and T1046 (Network Service Discovery): each would claim an attacker acting on the SoftAP, which is the step after the one sloth can see. Nobody has to be present for the beacon to be on the air. The nearest adversary interest is the same IoT-onboarding risk NIST SP 1800-36 documents: an unconfigured device in setup state is a management surface reachable by anyone in range [4][7]. The rule never tries the label-derived key and has no path that could - it is not a credential check.

## Evidence that proves it

The detail carries everything the match rests on: the vendor label, the SSID (so the reader can see the prefix), the BSSID, channel, and the encryption state (`OPEN, unauthenticated` / `enc WPA2` / `enc unknown`). No pcap is written (no IP flow; `match_ip` NULL) and no evidence-ring IDs are cited - the finding is a beacon SSID prefix, re-observed each tick, not a single frame. JSONL emits the alert with no `technique` field. The Devices view reads the same `g_camera_setup_ssid_pats[]` rows (via `src/camera_join.c`) so a camera's setup-SSID signal can join to its device record (docs/wiki/camera-detection.md).

What a reader should confirm to act: that the SSID prefix genuinely matches the vendor named (the prefix is in the detail), and whether the camera is theirs. If it is, the exposure is real while the AP is up - the camera's default credential likely stands. What refutes it as a problem: the camera is legitimately mid-installation right now (still worth knowing - that window is exactly when the exposure exists), or it was factory-reset and is being re-paired. The rule deliberately does not assert "in setup mode" or "not yet joined to a WLAN" - only "advertising its documented setup SSID (provisioning state not observed)."

## Benign causes

- **Genuine installation in progress.** The camera is being onboarded as the operator watches. Correct to fire - the exposure exists during that window.
- **Factory reset / re-pair.** A configured camera reset to defaults re-advertises the setup SSID; its password may since have been changed, which the beacon cannot show.
- **Installer left the setup AP enabled** after onboarding. The provisioning state is the operator's to check; the beacon alone cannot distinguish these.

There is no vendor-side "fix": this is the vendors' documented onboarding, working as designed.

## Assessment

WARN is right - the finding is a third party's device exposing its own provisioning posture, and the repo makes the same call it made for OPEN_SETUP_AP and CAM_WS_DISCOVERY: cite the basis, assign no technique, report the observable and let the operator draw the inference. False-positive risk is low for the match (every hit is a real vendor setup prefix) but the inference "password unchanged" can be stale after a reset, which the detail's "provisioning state not observed" is written to cover. Eight prefixes that could not be sourced to a vendor document (`Reolink-`, `WyzeCam`, `Arlo_`, `Verkada-`, `UVC-`, `Lorex_`, `Swann-`, `Blink-`) and substring matches on `CCTV`/`surveil` were deliberately left out as guesses - the bar is a citable vendor document [1]. On the reference host it is not seen (null data). A responder should determine whether the camera is theirs: if so, finish provisioning and change the account password (not the label-printed setup key), or power it off if it is not being installed; if not, tell whoever controls it and do not join its setup network (docs/wiki/alert-remediation.md §CAM_SETUP_SSID).

## Bibliography

1. sloth, research/papers/camera-setup-softap.md (repo corpus; cites ALERT_TYPE_CAM_SETUP_SSID; per-vendor SSID shapes and the "considered and not shipped" list)
2. sloth, docs/views/alerts.md CAM_SETUP_SSID row; docs/wiki/alerts.md §"Exposure rules"; docs/wiki/camera-detection.md; docs/wiki/alert-remediation.md §CAM_SETUP_SSID (repo)
3. sloth, src/camera_vendor.c:665 (g_camera_setup_ssid_pats) and src/alerts/rules_twin.c:1244 (rule) (repo)
4. sloth, research/papers/nist-sp1800-36-onboarding.md (repo corpus; the onboarding-window exposure, cited by OPEN_SETUP_AP)
5. Hikvision, "How to Set Wi-Fi Connection of Wi-Fi Camera via Mobile Phone Web Browser" - https://www.hikvision.com/content/dam/hikvision/en/support/how-to/how-to-document/network-cameras/How-to-Set-Wi-Fi-Connection-of-Wi-Fi-Camera-via-Mobile-Phone-Web-Broswer.pdf (accessed 2026-10-27)
6. Hikvision setup PDF, verbatim: "Select the HAP_xxxxxx from the Wi-Fi list... xxxxxx stands for the verification code, which you can find on the device label"; "Enter access point password, password is the last 8 charters [sic] of serial number on the label, for example, if the device serial number is D12345678, then the access point password is 12345678" (same URL; PDF downloaded and text-extracted 2026-10-27, 4 pages)
7. NIST SP 1800-36 (NCCoE), "Trusted IoT Device Network-Layer Onboarding and Lifecycle Management," November 2025 - https://csrc.nist.gov/pubs/sp/1800/36/final (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree and the live sources.

- Code: rule re-read at rules_twin.c:1244-1315 and the prefix table at camera_vendor.c:665-681 (`HAP_`, `DAP-`, `EZVIZ_`, `Tapo_Cam_`, case-insensitive prefix via ssid_ascii_iprefix at :684). Gate order (empty SSID, public-hotspot guard, prefix match), no OPEN gate, encdesc wording, key `camsetup:<bssid>`, WARN and NULL match_ip all match. Nine line references were stale by 2-13 lines and were corrected; `slot 49` was a file line, now stated as line 49 / index 22.
- Count semantics confirmed: plain `fire()` -> `evaluations++` at engine.c:478, per tick per BSSID.
- Text fix: the 'considered and not shipped' list names eight prefixes, not four (research/papers/camera-setup-softap.md:91-105); the Hikvision quote now reproduces the PDF's actual wording ('charters') rather than a silent correction.
- Sources: [5]/[6] the Hikvision PDF was not readable through WebFetch but downloaded directly (HTTP 200, application/pdf, 4 pages) and text-extracted; both quoted sentences are present verbatim at its lines 31-34. [7] NIST SP 1800-36 final page confirmed (November 2025). [1] research/papers/camera-setup-softap.md exists and names ALERT_TYPE_CAM_SETUP_SSID; [4] research/papers/nist-sp1800-36-onboarding.md exists and, as the entry already says, names OPEN_SETUP_AP rather than this type. docs/wiki/alert-remediation.md §CAM_SETUP_SSID exists (line 1499).
- Second pass (2026-10-27, later the same day): rule re-read at rules_twin.c:1244-1315 and the table at camera_vendor.c:665-681; gate order (1249, 1271, 1274), encdesc (1285-1291), key (1297), detail (1308-1312), WARN, NULL match_ip and table position (line 49, index 22) all match. Note: the `<vendor>` in the detail is the row's label ("Hikvision camera", "Dahua/Amcrest camera", ...), not the bare brand. No text change needed.
- Sources re-opened: [7] NIST SP 1800-36 final page confirmed (November 2025; full title "Trusted Internet of Things (IoT) Device Network-Layer Onboarding and Lifecycle Management: Enhancing Internet Protocol-Based IoT Device and Network Security"). [5]/[6] the Hikvision PDF returned HTTP 403 to this pass's automated fetch and was not re-read; the two quoted sentences rest on the first pass's download and text extraction, and should be re-checked by hand if the entry is published. research/papers/camera-setup-softap.md names ALERT_TYPE_CAM_SETUP_SSID; research/papers/nist-sp1800-36-onboarding.md names ALERT_TYPE_OPEN_SETUP_AP only (as [4] already says).
