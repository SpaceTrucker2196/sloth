---
type: TPC_ABSENT_HIGH_BAND
technique: ""
rule_file: src/alerts/rules_wifi_mgmt.c:703 of rule_tpc_absent_high_band()
count_semantics: per rule tick (one alerts_update() pass, POLL_MS=250 ms default) on which a designated 5 GHz beacon_ap row still has neither Power Constraint (tag 32) nor TPC Report (tag 35) retained. Keyed per BSSID, so one incident with a rising count per designated AP, not one per beacon frame. `fire()` bumps `evaluations` (= `count`) once per alerts_update() under the key (engine.c:478).
severity_assessment: agree - WARN, never CRIT. It reports the operator's own equipment being misconfigured against IEEE 802.11-2020 §11.8, not an adversary; the header is explicit that nothing was transmitted at sloth to produce it.
false_positive_risk: low (as scoped) - it fires only on a BSS the operator designated with --my-bssid/--my-ssid, and only after an observation floor; the residual benign cause is a 6 GHz BSS misread as 5 GHz (guarded by ap_band_label) or a legacy 802.11a AP (suppressed). Ungated it would be high.
noise_verdict: not seen on the reference host - host data is null. The rule is inert unless --my-bssid/--my-ssid is set (ownership_any() guard at rules_wifi_mgmt.c:683), so a host with no designated network never fires it. Where it does fire: one key per designated 5 GHz AP, count rising ~4/s while the AP is visible, resolving when a beacon finally carries either element or the row ages. No fan-out; a handful of designated APs at most.
prevalence: this is a compliance posture, not an attack, so "prevalence" is how often APs ship without TPC/DFS elements - common on stripped hostapd (ieee80211h=0) and minimal OpenWrt images [1][6]; no survey quantifying it was located. The adjacent threat the issue imagined (an evil twin from a stripped build) is covered by the EVIL_TWIN family, not this rule.
tuning: [TPC_ABSENT_MIN_OBSERVED_S (60 s, compile-time, sloth.h:2473), TPC_ABSENT_MIN_BEACONS (3, compile-time, sloth.h:2481), --my-bssid, --my-ssid (the ownership gate that arms the rule), --hop (affects whether enough beacons are heard to clear the floor)]
researched: 2026-10-27
---
## What the rule checks

Input: the beacon table `s->beacon_aps[]` (`beacon_ap_t`), with regulatory elements merged into the sticky `a->reg` envelope (`include/reg_ie.h`; `reg_ie_merge()` never clears a `_present` flag, so "absent" means "no beacon from this BSSID ever carried it"). Run order: `src/alerts/rules_table.c:79` (0-based table index 52).

Gates, in order (rules_wifi_mgmt.c:682-748):

1. `!ownership_any()` -> return. The rule is inert until the operator designates a network (683).
2. Per row: skip unless `ownership_is_my_bssid(a->bssid)` or `ownership_is_my_ssid(a->ssid)` (688-689).
3. `ap_band_label(a->channel, a->channel_source) != "5 GHz"` -> skip (691-692). The band comes from the label, not the bare channel number, because 5 and 6 GHz numbers overlap (#66, #91).
4. `a->phy == "legacy"` -> skip (693). Pre-802.11h 802.11a gear was never required to send these elements.
5. Observation floor: `!a->first_seen` OR `now - a->first_seen < TPC_ABSENT_MIN_OBSERVED_S` (60 s) OR `a->frame_count < TPC_ABSENT_MIN_BEACONS` (3) -> skip (704-706). Both time and beacon count, because a hopping radio that heard one beacon and left would otherwise fire on a single reading.
6. `a->reg.power_constraint_present || a->reg.tpc_present` -> skip (708). The finding is the absence of BOTH.

Key `tpcabsent:<bssid>` via plain snprintf (718) - per BSSID, not per SSID, so two designated APs on one ESS are two rows. Detail (736-747): the BSSID, SSID, channel, how long/over how many beacons it was observed, whether the Country element was also absent, and an ownership clause - `- YOUR network` only when the BSSID matched, or `- matched on SSID only, so this BSSID is not confirmed yours` when only the SSID matched (because an SSID is attacker-writable; #89). Fires `ALERT_SEV_WARN`, `match_ip = NULL` (748).

The rule reads the retained envelope (`a->reg.power_constraint_present`, `a->reg.tpc_present`; reg_ie.h:82-86). It deliberately does not read the Spectrum Management bit in Capability Information (sloth does not retain it) nor the 6 GHz Transmit Power Envelope (tag 195), which carries the limit on 6 GHz instead and would be the wrong element to flag as missing.

## The attack

This is not an attack; the technique is empty on purpose, and the rule's own header and docs/views/alerts.md say so. IEEE 802.11h-2003 folded Transmit Power Control and Dynamic Frequency Selection into 802.11 so the 5 GHz band could be shared with radar and satellite services, originally to meet European regulation [8]. Those mechanisms are now in IEEE 802.11-2020 §11.8 [7]. An AP publishes its power ceiling across three elements: the Country element (tag 7, §9.4.2.8) gives the regulatory maximum, the Power Constraint element (tag 32, §9.4.2.13) the local reduction below it, and the TPC Report element (tag 35, §9.4.2.16) the power the AP is actually using [7]. A station subtracts the constraint from the regulatory maximum to cap itself; the TPC Report lets it close the loop. A 5 GHz AP that sends neither tag 32 nor tag 35 has published no ceiling at all.

The overwhelmingly likely cause is a build with the feature off, not an adversary: hostapd with `ieee80211d=0` / `ieee80211h=0`, and the stripped OpenWrt images that rogue kits are assembled from, emit no Country element, no Power Constraint and no TPC Report, while keeping the default transmit power wherever the device is carried [1][6]. The issue (#101) originally proposed tagging this T1557.004 (Evil Twin), but the repo rejected that: claiming impersonation from a missing element would assert an adversary from a configuration gap. A lab-built rogue AP will often show this shape, but so will a legitimately stripped build, so the rule reports only the non-compliance and leaves attribution to the EVIL_TWIN rules that actually compare a clone against a real AP.

## Evidence that proves it

The detail is self-contained: BSSID, SSID, channel, the observation window (`<secs>s observed over <N> beacons`), and whether the Country element was also absent. There is no pcap (no IP flow; the finding is the absence of elements across many beacons, not a single frame to cite), and the rule passes no evidence-ring IDs - absence cannot be cited to one frame. JSONL emits the alert with no `technique` field (dropped because `alert_technique()` is empty; docs/wiki/jsonl-schema.md).

What a reader should confirm: the BSSID is genuinely the operator's designated 5 GHz AP (the detail says whether the match was by BSSID or only by SSID), the observation count is well past the floor (so "absent" is not "heard once"), and - if acting - that the AP's build has 802.11d/h disabled. What refutes the finding as a problem: a legacy 802.11a radio (the rule already suppresses `phy == "legacy"`), a 6 GHz BSS misidentified as 5 GHz (the rule guards against this with `ap_band_label`), or a channel-hopping receiver that simply never caught the beacon carrying the element - but the two-part floor (time AND beacons) is designed to exclude that last case, and one beacon with either element settles it permanently because the envelope is sticky.

## Benign causes

- **Stripped or minimal AP firmware.** The common case: a deliberately pared build (minimal OpenWrt, hostapd with `ieee80211d=0`/`ieee80211h=0`) omits the elements and is not hostile - it is simply non-compliant with §11.8 in a domain that expects spectrum management [1][6].
- **Legacy 802.11a equipment** predating 802.11h-2003 - suppressed by the `phy == "legacy"` gate.
- **6 GHz BSS** where the power limit rides tag 195 - excluded by the band gate.
- **Receiver that was elsewhere** - excluded by the observation floor.

## Assessment

WARN is the correct and deliberate ceiling: the finding is the operator's own gear being misconfigured, and the repo's reasoning (header comment at rules_wifi_mgmt.c:642-646, and docs/views/alerts.md) is that promoting a configuration gap to CRIT, or claiming an ATT&CK technique, would overstate what was observed. The ownership gate is load-bearing: ungated, the rule would fire on every third-party 5 GHz AP in RF range, where sloth has no standing to call a posture wrong and the operator has nothing to fix - so false-positive risk is low only because the gate narrows the population to the operator's declared estate. On the reference host it is not seen, consistent with no designated network. A responder should verify the AP is theirs, then enable 802.11d/h with a country code on it (hostapd `ieee80211d=1`, `ieee80211h=1`, `country_code=...`) per docs/wiki/alert-remediation.md §TPC_ABSENT_HIGH_BAND; the rule makes no claim about whether the power actually in use is legal where the AP stands - that needs the regulatory table, a later slice.

## Bibliography

1. sloth, research/ieee/802.11-2020-11.8-spectrum-management.md (repo corpus; cites ALERT_TYPE_TPC_ABSENT_HIGH_BAND)
2. sloth, docs/views/alerts.md TPC_ABSENT_HIGH_BAND row; docs/wiki/alerts.md §"Exposure rules"; docs/wiki/alert-remediation.md §TPC_ABSENT_HIGH_BAND (repo)
3. sloth, include/reg_ie.h (retained regulatory envelope; power_constraint_present/tpc_present fields) and include/sloth.h:2473,2481 (observation floor constants) (repo)
4. sloth, src/alerts/rules_regulatory.c (sibling COUNTRY_ABSENT, same observation-floor reasoning) (repo)
5. IEEE Std 802.11-2020, Part 11: Wireless LAN MAC and PHY Specifications (approved 2020-12-03, published 2021-02-26) - https://standards.ieee.org/ieee/802.11/7028/ (accessed 2026-10-27)
6. hostapd configuration (ieee80211d, ieee80211h, country_code, local_pwr_constraint, spectrum_mgmt_required) - hostapd.conf, https://w1.fi/hostapd/ (w1.fi/hostapd/ reached 2026-10-27 and links hostapd.conf; w1.fi's cgit served a bot-check page to the automated fetch, so hostapd.conf itself was confirmed the same day through the AOSP mirror of hostap, https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/hostapd/hostapd.conf, which documents `country_code`, `ieee80211d`, `ieee80211h`, `local_pwr_constraint` and `spectrum_mgmt_required`)
7. IEEE Std 802.11-2020 §11.8 (Spectrum management), §9.4.2.8 (Country), §9.4.2.13 (Power Constraint), §9.4.2.16 (TPC Report), §9.4.1.4 (Capability Information) - standard clauses (paywalled)
8. IEEE Std 802.11h-2003, "Spectrum and Transmit Power Management Extensions in the 5 GHz band in Europe" (TPC + DFS; the standard itself is paywalled and no standards.ieee.org landing page for it was verified) - summarized at https://en.wikipedia.org/wiki/IEEE_802.11h-2003 (accessed 2026-10-27: DFS + TPC added to the 802.11a PHY for radar/satellite coexistence, originally for European regulation, published 2003, rolled into 802.11-2007). The URL this entry previously carried, standards.ieee.org/ieee/802.11h/1137/, resolves to IEEE 802.6h-1993 (DQDB isochronous service) and was struck.

## Verification notes

Verified 2026-10-27 against the working tree and the live sources.

- Code: rule re-read at rules_wifi_mgmt.c:682-750. Gate order, both constants (TPC_ABSENT_MIN_OBSERVED_S=60 at sloth.h:2473, TPC_ABSENT_MIN_BEACONS=3 at :2481), key `tpcabsent:<bssid>`, WARN, NULL match_ip and the SSID-only wording all match. Six line references inside the function were off by one to two lines and were corrected; `slot 79` was a file line, not a table index, and is now stated as both (line 79, index 52).
- Count semantics confirmed: plain `fire()` -> `evaluations++` / `count` at engine.c:478 once per alerts_update() per key; no evidence ids, no match_ip.
- Sources: [1] research/ieee/802.11-2020-11.8-spectrum-management.md exists and names ALERT_TYPE_TPC_ABSENT_HIGH_BAND (the hostapd ieee80211d=0/ieee80211h=0 sentence is at its line 49). [5] IEEE 802.11-2020 page confirmed. [6] hostapd: w1.fi/hostapd/ reachable; hostapd.conf options confirmed through the AOSP mirror (w1.fi cgit is behind a bot check for automated fetches). [8] was wrong: the cited standards.ieee.org URL is IEEE 802.6h-1993, not 802.11h-2003; re-sourced to the Wikipedia summary, which supports the TPC/DFS/Europe/2003 sentence. docs/wiki/alert-remediation.md §TPC_ABSENT_HIGH_BAND exists (line 1474).
- Second pass (2026-10-27, later the same day): rule re-read at rules_wifi_mgmt.c:682-750. Corrected the key line (snprintf of `tpcabsent:%.17s` is at 718, not 716) and the detail range (736-747, not 735-746); added the `!a->first_seen` half of gate 5, which the text omitted. Constants (sloth.h:2473/2481), table position (line 79, index 52), WARN and NULL match_ip re-confirmed.
- Sources re-opened: [5] IEEE 802.11-2020 page (approved 2020-12-03, published 2021-02-26; now marked superseded by 802.11-2024, which does not change the clause citations); [6] w1.fi/hostapd/ links hostapd.conf, and the AOSP mirror's hostapd.conf documents country_code (102), ieee80211d (124), ieee80211h (130), local_pwr_constraint (137), spectrum_mgmt_required (144); [8] Wikipedia 802.11h-2003 supports DFS+TPC for the 802.11a PHY, satellite/radar coexistence at 5 GHz, European-regulation origin, integration into 802.11-2007. research/ieee/802.11-2020-11.8-spectrum-management.md names the type. Nothing struck.
