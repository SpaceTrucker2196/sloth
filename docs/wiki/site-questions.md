---
name: site-questions
description: The operator's site questions, each tied to the alert kinds that are its indicators, with a status for each question (finding, no finding, not observable, not assessed)
type: reference
---

# Site questions

**Summary**: sloth raises about a hundred alert kinds and had no list of what the operator wants to know. A site question is one question in plain words, the decision it supports, a priority, and the alert kinds that are its indicators. sloth ships seven default questions; each alert kind is an indicator of one or more of them, or is marked "no question" with a reason. Receive-only: a question's answer is derived from findings and coverage figures sloth already holds.

**Sources**: issue #244 (from #241 item 1) and its owner rulings of 2026-11-25; FM 2-0 (2004) figure 1-2 (priority question, specific questions, indicators, collection tasks), 1-34 (a priority question asks only one question and supports a decision) and 4-6 (clear requirements preclude being overwhelmed by too much information), as quoted in the issue; `include/sloth_questions.def` (the questions), `include/sloth_question_map.def` (the indicators); `src/questions.h`, `src/questions.c` (the tables, the file, the status), `src/questions_live.h`, `src/questions_live.c` (the record and the report section); `tests/test_questions.c`; [[coverage-assessment]] (the status every answer carries).

**Last updated**: 2026-11-25 (#244: the page, § 4 the status, § 5 the file format, § 6 the record, the table, the `[!]` view and the report section)

## 1. The default questions

`include/sloth_questions.def`. Priority 1 is the most urgent.

| Id | Priority | Question | Decision it supports |
|---|---|---|---|
| Q1 | 1 | Is a device impersonating one of my networks? | Warn users off the network and find the transmitter. |
| Q2 | 1 | Is a device that I do not know on my network? | Remove the device and change the network key. |
| Q3 | 1 | Is a device collecting key material near my site? | Change the network key or the credentials now. |
| Q4 | 2 | Is a device or a person surveying my site again and again? | Raise the watch on the site and keep the evidence. |
| Q5 | 3 | Is my site revealing information? | Change the settings or devices that disclose the site. |
| Q6 | 2 | Is the radio environment being denied or degraded? | Move channel or band, or find the source. |
| Q7 | 1 | Is the sensor able to see what it must see? | Trust the other answers, or fix the sensor first. |

Q7 is priority 1 because every other answer depends on it: a `no_finding` from a sensor that cannot see is not an answer.

## 2. Which kind answers which question

`include/sloth_question_map.def` has one row per alert kind, in `include/sloth_alerts.def` order. It is a sibling of that file, like `sloth_exposure.def` and `sloth_alert_inputs.def`, because `sloth_alerts.def` is in the contract with a two-argument `X`. `tests/test_questions.c` holds it to `sloth_alerts.def` row for row and holds this table to it: change both together.

| Kind | Questions | No question because |
|---|---|---|
| `PORT_SCAN` | Q4 |  |
| `DEAUTH_FLOOD` | Q6 |  |
| `NXDOMAIN_BURST` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `THREAT_DOMAIN` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `THREAT_IP` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `BEACONING` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `DGA_DOMAIN` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `ARP_SPOOF` | Q1 |  |
| `ROGUE_DHCP` | Q1 |  |
| `ROGUE_RA` | Q1 |  |
| `SMB1_USE` | — | a weak protocol or setting in use on the LAN, not something an observer near the site learns |
| `KERB_PREAUTH_BURST` | Q3 |  |
| `LDAP_SEARCH_FLOOD` | Q4 |  |
| `BGP_NOTIFICATION_BURST` | — | a routing session failing: about the site's upstream, not an observer near it |
| `SSH_BRUTE_FORCE` | — | an attack on a LAN service from inside the LAN: no default question is about the site's own services |
| `RDP_BRUTE_FORCE` | — | an attack on a LAN service from inside the LAN: no default question is about the site's own services |
| `SNMP_COMMUNITY_BRUTE` | — | an attack on a LAN service from inside the LAN: no default question is about the site's own services |
| `MQTT_BROKER_BRUTE` | — | an attack on a LAN service from inside the LAN: no default question is about the site's own services |
| `EVIL_TWIN` | Q1 |  |
| `EVIL_TWIN_PROXIMITY` | Q1 |  |
| `KARMA_AP` | Q1 |  |
| `DNS_TUNNEL` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `PROBE_FLOOD` | Q4 |  |
| `ATTACK_TOOL_UA` | Q4 |  |
| `ATTACK_PATH` | — | an attack on a LAN service from inside the LAN: no default question is about the site's own services |
| `WEAK_TLS` | — | a weak protocol or setting in use on the LAN, not something an observer near the site learns |
| `NO_MONITOR_MODE` | Q7 |  |
| `CLEARTEXT_CRED` | Q3, Q5 |  |
| `BEACON_FLOOD` | Q6 |  |
| `AUTH_FLOOD` | Q6 |  |
| `SSID_CONFUSION` | Q1, Q5 |  |
| `MGMT_FUZZ` | Q6 |  |
| `ROGUE_RADIUS` | Q1, Q3 |  |
| `ICMP_TUNNEL` | — | a host on the LAN behaving like a compromised one: no default question is about the site's own hosts |
| `MY_NETWORK_RECON` | Q4, Q5 |  |
| `RECURRING_TRANSIT` | Q4, Q5 |  |
| `UNKNOWN_DEVICE` | Q2 |  |
| `RF_DEGRADED` | Q6 |  |
| `ASSOC_FLOOD` | Q6 |  |
| `BTM_ABUSE` | Q1 |  |
| `WPA_DOWNGRADE` | Q1, Q5 |  |
| `PEAP_NO_SERVER_CERT` | Q3, Q5 |  |
| `CSA_ABUSE` | Q1, Q6 |  |
| `RRM_SURVEY_ABUSE` | Q4 |  |
| `RTS_FLOOD` | Q6 |  |
| `CAPTIVE_PORTAL` | Q1 |  |
| `BLOCKACK_ATTACK` | Q6 |  |
| `FRAG_PLAINTEXT` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_BCAST` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_CACHE` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_MIXED` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `SAE_PSK_SPLIT` | Q5 |  |
| `SAE_PSK_REGRESSION` | Q5 |  |
| `FRAG_AMSDU` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_AMSDU_EAPOL` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_MIXKEY` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_PN_GAP` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `FRAG_EAPOL_RELAY` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `SA_QUERY_FLOOD` | Q6 |  |
| `MFP_UNPROTECTED` | Q6 |  |
| `OPEN_SETUP_AP` | Q5 |  |
| `WPS_PIN_BRUTE` | Q3 |  |
| `WPS_LOCKOUT_CYCLING` | Q3 |  |
| `WPS_PBC_RACE` | Q2 |  |
| `MLE_INVALID_LINK_ID` | Q6 |  |
| `MLE_COMMON_INFO_LEN_BAD` | Q6 |  |
| `MLE_SUBELEM_OVERRUN` | Q6 |  |
| `MLD_MAC_COLLISION` | Q1 |  |
| `MLE_CROSS_LINK_CIPHER_DOWNGRADE` | Q5 |  |
| `CAM_WS_DISCOVERY` | Q5 |  |
| `PM_FORGE` | Q1 |  |
| `SURV_CLOUD_SNI` | Q5 |  |
| `TPC_ABSENT_HIGH_BAND` | Q5 |  |
| `CAM_SETUP_SSID` | Q5 |  |
| `QUEUE_EVICT` | — | an attack on one client's traffic in flight (FragAttacks, Framing Frames): no default question is about traffic |
| `MLE_RECONFIG_NO_MLO` | Q6 |  |
| `MLE_PR_BEACON_DIFF` | Q1 |  |
| `SURV_DNS` | Q5 |  |
| `WPS_PIXIE_PROBE` | Q3 |  |
| `WPS_PIXIE_LIKELY_SUCCESS` | Q3 |  |
| `COUNTRY_ABSENT` | Q5 |  |
| `DFS_MASKING` | — | a new transmitter first heard on a DFS channel: its purpose is unknown, and no default question is about transmitters in general |
| `CAM_MDNS_SERVICE` | Q5 |  |
| `CAM_SSDP_DEVICE` | Q5 |  |
| `CAM_SETUP_OUI` | Q5 |  |
| `CAM_RTSP_UNAUTH` | Q5 |  |
| `BT_OWN_TRANSMIT` | — | the host's own Bluetooth controller transmitting: a check on sloth's receive-only promise, not on what the sensor can see |
| `BLE_ADV_FLOOD` | Q6 |  |
| `BLE_HID_UNEXPECTED` | Q2 |  |
| `BLE_WATCHLIST` | Q4 |  |
| `GNSS_JAMMING` | Q6 |  |
| `GNSS_SPOOF_SUSPECT` | Q6 |  |
| `GNSS_TIME_JUMP` | Q6 |  |
| `GNSS_POSITION_JUMP` | Q6 |  |
| `ADSB_EMERGENCY` | — | an aircraft's emergency squawk: about the aircraft, not the site |
| `KARMA_PROBE_FORGE` | Q1 |  |
| `PMKID_HARVEST` | Q3 |  |
| `HANDSHAKE_HARVEST` | Q3 |  |
| `SENSOR_UNDERVOLT` | Q7 |  |
| `SENSOR_SOURCE_DOWN` | Q7 |  |
| `SENSOR_SUPPRESSED` | Q7 |  |

## 3. The judgement behind the table

The table is a judgement about what a finding answers, not a fact about the code.

- **Q1, impersonation**: a transmitter or host that claims to be part of the operator's network or steers clients to one that does: the twin and KARMA kinds, rogue DHCP, RA, RADIUS and ARP, the forged Channel Switch and BSS Transition frames, a forged captive portal, a probe response or MLD address that contradicts the BSS's own beacon, and `PM_FORGE` (a frame sent under a station's address). `SSID_CONFUSION` and `WPA_DOWNGRADE` are here as well as in Q5: the network the client is moved to is someone else's.
- **Q2, unknown device**: `UNKNOWN_DEVICE` (the roster rule), a Push-Button enrolment race (`WPS_PBC_RACE`: anyone in range can join for the walk time) and an unexpected BLE keyboard (`BLE_HID_UNEXPECTED`).
- **Q3, key material**: PMKID and handshake harvesting, the WPS PIN and Pixie Dust attacks, a rogue RADIUS server or a PEAP client that does not check the server (inner credentials), clear-text credentials, and a Kerberos pre-authentication burst (the replies are crackable offline).
- **Q4, surveying**: what reads as reconnaissance repeated over time: port scans, directory searches, probe floods, attack tools' user agents, RRM radio measurement requests, a device probing for the site's own network names, a device passing again and again, and a BLE watch-list category.
- **Q5, revealing**: exactly the kinds `include/sloth_exposure.def` puts in a group ([[exposure-report]]); the test holds the two sets equal, so they cannot drift.
- **Q6, denial and degradation**: floods of deauthentication, authentication, association, beacons, RTS, SA Query and BLE advertising, management frame fuzzing and malformed multi-link elements, forged Block Ack and Reconfiguration elements, unprotected robust action frames on an MFP-required BSS, RF degradation and the GNSS jamming and spoofing kinds.
- **Q7, the sensor**: no monitor mode, a source down, collection suppressed, under-voltage.
- **No question**: the kinds about a compromised host or a service on the LAN, weak protocols in use, attacks on one client's traffic (FragAttacks, Framing Frames' queue eviction), a routing session failing, an aircraft's emergency, a new transmitter on a DFS channel, and the host's own Bluetooth transmitting (a check on sloth's own receive-only promise). None of the seven defaults asks about them; an operator's own questions may.

## 4. A question's status

`q_derive()` (`src/questions.c`) gives each question one word from the alerts the daemon holds and the coverage status of the question's indicators ([[coverage-assessment]]):

| Status | When |
|---|---|
| `finding` | an indicator has an open finding: preliminary, confirmed or lapsed ([[alerts]] § Finding lifecycle); a withdrawn or resolved one does not count |
| `no_finding` | no finding, and every indicator is observable |
| `no_finding_partly` | no finding, and some indicator is partly observable or blind |
| `not_observable` | no finding, and every indicator is blind |
| `not_assessed` | no finding, and there is no coverage status: before the first status sample, and in a `--replay` run, which reads files and has no radios to assess |

A finding is reported whatever the coverage: a replayed evil twin gives Q1 `finding` beside coverage that was never assessed, and with no monitor radio and no IP capture Q1 reads `not_observable` (`tests/test_questions.c :: test_acceptance`, the issue's acceptance as the owner ruled it on 2026-11-25). The reason beside a status that is not `no_finding` is the first blind indicator's reason, else the first partly one's, in `sloth_alerts.def` order.

Each daemon answers only for the kinds its rule table raises (`cov_daemon_raises()`). `sloth-rf` raises the GNSS and ADS-B kinds and `SENSOR_SOURCE_DOWN`, so it answers Q6 and Q7 of the defaults; a question none of whose indicators a daemon raises has no answer there and is not reported by it.

The status is about the sensor and the findings it holds, never a claim about the site: `no_finding` is "looked and found nothing", not "nothing is there" ([[coverage-assessment]] § 5).

## 5. The operator's own questions: the file format

The operator's own file, read with `--questions PATH` (owner ruling 2026-11-25: the sensor reads the file; sloth-mesh may write it later). With no `--questions`, the seven defaults are used; with it, the file's questions replace them. One question per line:

```
# id|priority|question|decision|KIND,KIND,...
TWIN|1|Is someone copying HomeNet?|Tell the household.|EVIL_TWIN,KARMA_AP,KARMA_PROBE_FORGE
KEYS|1|Is anyone after the Wi-Fi key?|Rotate the key.|PMKID_HARVEST,HANDSHAKE_HARVEST
EYES|1|Can the sensor see?|Fix the sensor first.|NO_MONITOR_MODE,SENSOR_SOURCE_DOWN,SENSOR_SUPPRESSED
```

- `#` starts a comment line; blank lines are skipped; spaces around a field are dropped; CRLF reads as LF.
- `id`: 1 to 15 of `A-Z a-z 0-9 _ -`, unique in the file.
- `priority`: 1 (most urgent) to 9.
- `question`, `decision`: non-empty, under 160 bytes each. Ask one question (FM 2-0 1-34).
- the kinds: `include/sloth_alerts.def` names (with or without `ALERT_TYPE_`, as `--value-period` takes them), comma-separated, at least one. A kind named twice counts once.

The file is refused, and sloth exits 2 naming the line, for an unknown kind, a duplicate id, a field missing or out of range, more than 32 questions, no question at all, a line of 2048 bytes or more, a file over 64 KiB or one that is not text (`q_set_load()`, `q_set_parse()`; `tests/test_questions.c :: test_parse_refusals`).

## 6. Where the answers go

`src/questions_live.c` reads the daemon's alert snapshot and the coverage status it keeps ([[coverage-assessment]] § 4) each time it is asked:

- **The `question_status` record** (JSONL 2.17.0, both daemons, [[jsonl-schema]]): one row per question the daemon answers, change-only with the 300 s heartbeat, keyed by the question's id. More observations of a finding already counted write nothing; a new finding, a changed status, reason or coverage count does.
- **The `question_status` table** of `--db` (schema v22, [[sqlite-schema]]; owner ruling 2026-11-25): one row each time an answer changes, and one per question after the file opens, so the history of an answer is a query. On the observation tier.
- **The `[!]` Questions view** of sloth-wifi's terminal ([views/questions.md](../views/questions.md)): the same answers, most urgent first, the selected question's decision, coverage and incident ids below.
- **`--report` and `--report-json`** ([[posture-report]]): a "Site questions" section after "What this site reveals", the questions most urgent first (priority 1 first, then the set's order), each with its status, reason, indicator counts and decision, then the two limits of [[coverage-assessment]] § 5; `questions` in the JSON, after `exposure`.

Both carry kinds, counts, status words and incident ids beside the operator's own question and decision text: never an address, a name, an SSID or an alert key, whichever capture a finding came from. sloth-mesh's fleet export writes only its own fixed line types, so neither travels ([ADR 0009](adr/0009-fleet-monitor-only.md)).

The answer is derived each time from what the daemon holds now: a finding counts while its incident is open (300 s after its last evaluation it resolves), so `finding` turns back into a `no_finding` word when the incident closes.

## Related pages

- [[collection-cycle]] — the Plan and Analyze steps this page builds
- [[coverage-assessment]] — the observable / partly / blind status every answer carries
- [[exposure-report]] — the groups Q5 is made of
- [[alerts]] — the kinds
- [[posture-report]] — the Site questions section
- [[jsonl-schema]] — the `question_status` record
