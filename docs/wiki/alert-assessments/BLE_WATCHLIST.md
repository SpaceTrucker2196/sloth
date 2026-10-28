---
type: BLE_WATCHLIST
technique: ""
rule_file: src/alerts/rules_ble.c:156 of rule_ble_watchlist() (detail in fire_finding(), src/alerts/rules_ble.c:126-135; grouping in src/ble_detect.c:221-277)
count_semantics: per poll tick (POLL_MS 250 ms) in which at least one `ble_device_t` row with a non-empty `watch_cat` was heard in the last BLE_WATCH_RECENT_SECS (120 s); one incident per (category, sensor iface) (`blewl:<category>:<iface>`). The detail's address count is of addresses heard in the window - which rotate - so it is explicitly not a device count.
severity_assessment: agree - WARN, provisionally; with the shipped table empty the rule cannot fire, and the deferred CRIT ("stalk-grade" category from a "non-resident" source) is correctly deferred because "non-resident" has no definition yet.
false_positive_risk: not assessable - no row ships; for the candidate rows (finder tags) the structural risk is high by nature, because the same tag rides in its owner's own bag.
noise_verdict: not seen on the reference host - no fires, and cannot fire on any host today: `ble_watchlist_count()` is 0 (src/ble_watchlist.c:8-9, 48). When rows land: one incident per (category, sensor), `observations` moving as the address count changes within the 120 s window; `count` at 4/s while asserted.
prevalence: finder-tag misuse (stalking with AirTags, SmartTags, Tiles) is documented in the academic literature [3][4]; no incidence figure is quoted here because none was confirmed and the shipped rule detects nothing yet.
tuning: [none - BLE_WATCH_RECENT_SECS is a compile-time constant (src/ble_detect.h:108); the table is replaced only by ble_watchlist_set_table() (tests, or a future operator list), each row requiring a source]
researched: 2026-10-27
---
## What the rule checks

Input is `s->ble_devices[]` (MAX_BLE_DEVICES 256). When an advertisement is decoded, `ble_watchlist_match()` (src/ble_watchlist.c:41-46) tests it against the rows in force and stores the first matching row's `category` on the device row's `watch_cat[16]` (include/sloth.h, `ble_device_t`). A row matches when every field it constrains matches (src/ble_watchlist.h:27-53): `BLE_WL_MFR` (Manufacturer Specific Data, `id` = company ID), `BLE_WL_SVC_DATA` (Service Data 16-bit, `id` = UUID) or `BLE_WL_UUID16` (a listed 16-bit Service UUID); optionally `subtype` (first payload octet after the id, -1 any) and `min_len`/`max_len` payload bounds; and a `source` string, which `ble_watchlist_set_table()` refuses to accept empty (src/ble_watchlist.c:50-62). Nothing is decrypted, resolved or linked across addresses (src/ble_watchlist.h:21-25).

**The shipped table is empty**: `g_rows` is NULL and `g_n` is 0 (src/ble_watchlist.c:5-9), so `watch_cat` is never set and the rule never fires outside the tests, which install an in-test table (src/ble_watchlist.h:11-19) [1].

`watch_findings()` (src/ble_detect.c:221-277) groups rows with a non-empty `watch_cat` and `last_seen >= now - BLE_WATCH_RECENT_SECS` (120 s, src/ble_detect.h:108) by (sensor iface, category), counting addresses per group. Key: `blewl` + category + iface (lines 271-275). Detail (src/alerts/rules_ble.c:127-132): `<n> address(es) matching watched category <category> heard via <iface> in the last 120s - addresses rotate, so this is not a count of devices; a category, never an identity`. WARN, `match_ip` NULL (no pcap). The finding stops being asserted 120 s after the last matching advertisement and the engine resolves it 300 s later.

Empty technique: on the cited-basis exemption list, not the own-state list (include/sloth_alerts.def:318; tests/test_research_corpus.c:240-294, the list entry at line 294) - a tag in range is a third party's device being present, and T1430 (Location Tracking) would claim an intent the advertisement cannot carry [1].

## The attack

The category the rule exists for is the crowd-sourced finder tag - Apple AirTag / Find My, Samsung SmartTag, Tile, Chipolo. Such a tag broadcasts a BLE advertisement that nearby phones of the same ecosystem pick up and forward, with the finder's location, to the vendor's server [4]. Yu et al. (USENIX Security 2024) describe Samsung's Offline Finding: a beacon "picked up by nearby Samsung phones or tablets (the finder devices), which then forward the unique beacon, along with the location it was detected at, to a Samsung managed server" [4]. Heinrich, Bittner and Hollick (AirGuard) open with the misuse case: "Finder networks in general, and Apple's Find My network in particular, can pose a grave threat to users' privacy and even health if these networks are abused for stalking" [3]. The misuse is to plant a tag on a person or vehicle and read its reported location; the countermeasure both ecosystems and the AirGuard app implement is to detect a tag that travels with you but is not yours [3].

What a passive sensor can honestly say about this is narrow, and the repo's design says it in so many words: a tag's address is random and rotates by design, so a match says "an advertiser of this kind is in range", never "this tag" and never "this person"; linking a rotated address back to a tag needs the tag's keys, which sloth does not have and does not seek [1][5]. The rows that would make the rule fire are candidates only, each waiting on a primary source for its payload shape: Samsung SmartTag on Service Data 0xFD59/0xFD5A (Yu et al. §3 is cited by the owner's fact-check but was not read beyond the abstract), Tile on 0xFEED/0xFEEC, Chipolo on 0xFE33/0xFE65, Apple Find My offline-finding on Manufacturer 0x004C with a first octet the issue gives as 0x12 (AirGuard reverse-engineered the protocol; only its abstract was read) [1][2]. The Bluetooth SIG `member_uuids.yaml` says only who was *assigned* each UUID, not what advertises it [2].

## Evidence that proves it

What sloth records when a row is installed:

- the alert detail: the category slug, the address count in the last 120 s, the sensor iface (src/alerts/rules_ble.c:127-132);
- `ble_alert` JSONL, `kind: watchlist`, with `category`, `addrs` (addresses, not devices), `window_s`, change-only on `addrs` by powers of two (docs/wiki/jsonl-schema.md:732);
- the matching `ble_device` records (address type, the manufacturer/service-data fields the row matched, RSSI, first/last seen, `sensor_iface`), also in the `[*]` view's Enter detail (docs/wiki/cli-reference.md:373);
- sensor_health `evict_ble_device`, `btcap_sampling`;
- **no pcap**, and nothing from the HCI channel verbatim.

To call a (future) finding real, in the only sense it supports - "a tag of this category is in range, and may be staying" - a reader should see: the `ble_device` rows for the category with the payload fields the installed row constrains (for example Service Data under the vendor's UUID with the length and first octet the primary source specifies [2]); a presence that **persists across address rotations** at roughly constant RSSI, which a sensor cannot establish from one address but can from the category's continuous occupancy of the 120 s window over hours; and the repo's own caution that this is still not a count of devices and not a person [1][5]. The step that turns presence into a stalking finding - that the tag is not resident and travels with a target - is exactly the CRIT the repo deferred because "non-resident" is undefined (src/ble_detect.h:13-24) [1].

What refutes it: the tag is the operator's own, or belongs to someone who lives or works there (a tag rides in its owner's bag too) (docs/wiki/alert-remediation.md:1798); the "category" row matched a phone - for Find My, every iPhone participates in the network and some Apple payloads under 0x004C are not tags at all, which is why no row ships without a source saying what the shape distinguishes [1][2].

## Benign causes

- **Residents' and co-workers' own tags** - keys, bags, pets, bikes. The most common case by far, and indistinguishable from a planted tag by presence alone [1].
- **Phones and laptops of the same ecosystem**, if a row is drawn too wide (a company ID alone matches every Apple device; the schema's `subtype` and length bounds exist to narrow it) [2].
- **Lost-mode tags on a neighbouring property or passing vehicle** entering the 120 s window briefly.
- **A row installed from memory rather than a primary source** - the project's stated reason for shipping no rows: "a row invented from memory passes every test written against it while matching nothing real, and a row that is wrong is worse than none" (src/ble_watchlist.h:11-15) [1].

## Assessment

**Severity.** WARN is right for the posture the rule describes - an observation of a category - and the repo's refusal to grade it higher without a definition of "non-resident" is the correct discipline [1]. Should rows land, the operator should treat a WARN here as "something of this kind is present", nothing more.

**Prevalence.** Finder-tag stalking is an established, studied misuse [3][4]; the candidate categories are among the most widely sold BLE devices. No incidence number is quoted because none was confirmed for this document, and because the shipped rule detects nothing yet.

**Noise on the reference host.** Not seen, and it could not have been: the table is empty (src/ble_watchlist.c:7-9). When rows land, expect one incident per (category, sensor) with `observations` moving as the 120 s address count changes - with a busy Find My population that could be constant churn, which is another reason the Apple row needs a shape narrower than the company ID [2]. `count` climbs at 4/s while asserted; show `observations`.

**Sufficient to act on?** No, and the detail says so: "a category, never an identity". It is sufficient to prompt a physical search when the operator has independent reason to suspect a planted tag, which the ecosystems' own unwanted-tracking alerts and AirGuard address far more directly [3].

**First response.** Read the category and the address count; recall who is present and whether their tags explain it; if a planted tag is suspected, use the platform's own detection (Apple's unwanted-tracking alerts, Android's, AirGuard) to find and identify it - sloth cannot (docs/wiki/alert-remediation.md:1798) [3].

## Bibliography

1. research/bluetooth/ble-watchlist-categories.md - BLE watchlist categories: the schema, the candidate rows and why the table ships empty (repo research corpus, accessed 2026-10-27)
2. Bluetooth SIG Assigned Numbers, `uuids/member_uuids.yaml` - Tile (0xFEED, 0xFEEC, 0xFD84), CHIPOLO (0xFE65, 0xFE33), Samsung (0xFD59, 0xFD5A, ...), V2SOFT (0xFD5B), Apple member UUIDs - https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/member_uuids.yaml (as read and quoted in [1]; accessed 2026-10-27)
3. Alexander Heinrich, Niklas Bittner, Matthias Hollick, "AirGuard - Protecting Android Users From Stalking Attacks By Apple Find My Devices", arXiv:2202.11813 - https://arxiv.org/abs/2202.11813 (abstract fetched and confirmed 2026-10-27; the "grave threat to users' privacy and even health" sentence is the abstract's opening)
4. Tingfeng Yu, James Henderson, Alwen Tiu, Thomas Haines, "Privacy Analysis of Samsung's Crowd-Sourced Bluetooth Location Tracking System", 33rd USENIX Security Symposium 2024, arXiv:2210.14702 - https://arxiv.org/abs/2210.14702 (abstract fetched and confirmed 2026-10-27; the finder-device / Samsung-managed-server sentence is quoted from it verbatim)
5. research/bluetooth/ble-address-rotation.md - why private addresses cannot be linked to a device or person by a passive sensor; the spec's 15-minute recommended rotation (repo research corpus, accessed 2026-10-27). Background source: it does not name `BLE_WATCHLIST`; the "a category, never an identity" wording is the rule's own detail (src/alerts/rules_ble.c:130) and src/ble_detect.h:94-97
6. docs/views/alerts.md:146 - the `BLE_WATCHLIST` rule-table row (accessed 2026-10-27); docs/wiki/alert-remediation.md:1798 - investigate / fix

## Verification notes

Verified 2026-10-27 against the working tree (HEAD 0d60387) and by fetching every external source.

- Code: `rule_ble_watchlist()` is at `src/alerts/rules_ble.c:156` (draft: 139), its detail case `:126-135`. `watch_findings()` is `src/ble_detect.c:221-277` (key `:271-275`), `BLE_WATCH_RECENT_SECS` 120 at `src/ble_detect.h:108` - anchors corrected. The grouping is (sensor iface, category) with `last_seen >= now - 120`, counting rows (addresses) per group, as stated. `src/ble_watchlist.c`: `g_rows`/`g_n` `:8-9`, `row_matches()` `:22-39`, `ble_watchlist_match()` `:41-46`, `ble_watchlist_set_table()` `:50-62` refusing an empty `source` at `:57`; the row schema is `src/ble_watchlist.h:27-53` - anchors corrected; the empty shipped table confirmed. `include/sloth_alerts.def:318` has the empty technique; `tests/test_research_corpus.c:294` lists `ALERT_TYPE_BLE_WATCHLIST` in `test_uncitable_kinds_with_a_real_basis_are_still_cited` (anchor widened to 240-294). WARN, `match_ip` NULL.
- Count semantics: correct as written; the rule cannot fire with the shipped table.
- Sources: [3] arXiv:2202.11813 and [4] arXiv:2210.14702 abstracts fetched; both quotes confirmed verbatim and the USENIX Security '24 venue confirmed. [2] `member_uuids.yaml` fetched: Tile 0xFEED/0xFEEC/0xFD84, CHIPOLO 0xFE65/0xFE33, Samsung 0xFD59/0xFD5A, V2SOFT 0xFD5B confirmed. [1] `research/bluetooth/ble-watchlist-categories.md` and [5] `research/bluetooth/ble-address-rotation.md` exist; the first names `ALERT_TYPE_BLE_WATCHLIST` and holds the candidate-row table (0xFD59/0xFD5A, 0xFEED/0xFEEC, 0xFE33/0xFE65, Apple 0x004C first octet 0x12) the entry describes.

Second pass, 2026-10-27 (re-read against HEAD d70d394; every external source re-fetched):

- Code re-read: grouping, key (`blewl` + category + iface), 120 s recency, detail and WARN/no-pcap all as stated; `watch_cat` is set from the first matching row at decode (`src/ble_hci.c:369-370`). Front-matter anchor for the zero count corrected to `src/ble_watchlist.c:8-9, 48`.
- Source attribution corrected: `research/bluetooth/ble-address-rotation.md` exists but neither names `BLE_WATCHLIST` nor contains the "category, never identity" wording the bibliography credited to it; that wording is in the rule detail and `ble_detect.h`. [5] relabelled as background. The type's citing document is `research/bluetooth/ble-watchlist-categories.md`, which names it.
- Sources re-fetched: [2] member_uuids.yaml (0xFEED, 0xFEEC, 0xFD84, 0xFE65, 0xFE33, 0xFD59, 0xFD5A, 0xFD5B present); [3] arXiv:2202.11813 abstract ("grave threat to users' privacy and even health if these networks are abused for stalking"); [4] arXiv:2210.14702 abstract ("forward the unique beacon", USENIX).
