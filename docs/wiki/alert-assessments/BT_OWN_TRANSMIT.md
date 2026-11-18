---
type: BT_OWN_TRANSMIT
technique: ""
rule_file: src/alerts/rules_ble.c:34 of rule_bt_own_transmit()
count_semantics: per poll tick (POLL_MS 250 ms) in which a transmission kind is asserted - ON on any controller (advertising, inquiry/page scan, periodic inquiry, an enabled active scan), or its newest host command is within BT_TX_RECENT_SECS (120 s). One incident per kind (`bttx:<kind>`), never per command; `observations` moves when the detail's "last command N s ago" string changes, which is every second while asserted.
severity_assessment: agree - WARN; it is the sensor host violating its own passive posture (MISSION §2), not an adversary. It should not be CRIT (no one is attacked) and not INFO (a non-passive sensor undermines every other Bluetooth finding's provenance).
false_positive_risk: low - the rule reads the host's own HCI commands off the kernel monitor channel; the only way to "false positive" is a command the controller then rejected, which still counts by design.
noise_verdict: not seen on the reference host - no fires. By construction one incident per kind, resolved 300 s after the kind is neither on nor recent; `count` is an evaluation counter and `observations` ticks every second via the age string in the detail, so a steady active scan produces ~1 observation/s - the detail should quantise its age (see Assessment).
prevalence: not an attack - it is a configuration state of the operator's host; on a stock Linux desktop with bluetoothd running it is the normal state (bluetoothd scans actively and advertises when asked), so without the `sloth-ble-scan` helper it is expected to fire [5][6].
tuning: [none - BT_TX_RECENT_SECS is a compile-time constant (src/ble_hci.h:118); the operator-side controls are `--bt-monitor` to enable the source and `sloth-ble-scan.service` / stopping bluetoothd to keep the controller passive]
researched: 2026-10-27
---
## What the rule checks

The input is `s->ble_host`, filled by `src/ble_hci.c` from libpcap's `bluetooth-monitor` device (Linux HCI monitor channel, DLT 254) when `--bt-monitor` is on, or from a DLT 254 savefile under `--replay` (docs/wiki/cli-reference.md:182,320). The decoder reads an allow-list only (src/ble_hci.h:30-51): monitor opcodes NEW_INDEX (0), DEL_INDEX (1), COMMAND_PKT (2) and EVENT_PKT (3) [7] (events only LE Meta 0x3E subevents 0x02 and 0x0D, the advertising reports); within commands, the host's own scan, advertise and connect opcodes - LE Set Scan Parameters 0x200B / Extended 0x2041, LE Set Scan Enable 0x200C / Extended 0x2042, LE Set Advertising Enable 0x200A / Extended 0x2039 / Periodic 0x2040, LE Create Connection 0x200D / Extended 0x2043, Inquiry 0x0401, Periodic Inquiry Mode 0x0403 and Exit 0x0404, Create Connection 0x0405, Remote Name Request 0x0419, Write Scan Enable 0x0C1A, and Reset 0x0C03 [3]. Everything else is counted as ignored without copying its bytes, because the same channel carries link keys and LTKs (src/ble_hci.h:32-36).

Each controller holds the persistent kinds as on/off: an enable sets the bit, the matching disable, Exit Periodic Inquiry, Reset or DEL_INDEX clears it (src/ble_hci.h:53-57). A scan counts as a transmission only when `Scan_Type` is **active** (an active scanner sends SCAN_REQ PDUs; a passive one sends nothing) [3][5] (docs/views/alerts.md:143): an LE Set (Extended) Scan Parameters with active type stamps `active_scan` by itself, as does an enable under active parameters, while ON needs both (src/ble_hci.c:174-175, 683-722). `bt_tx_asserted_mask()` (src/ble_hci.c:251-259) returns the kinds that are either ON on any controller or whose newest command arrived within BT_TX_RECENT_SECS = 120 s (src/ble_hci.h:118; src/ble_hci.c:247) - the one-shot kinds (a Create Connection, a Remote Name Request) are reported by recency only.

The rule (src/alerts/rules_ble.c:34-65) fires one alert per asserted kind. Key: `akey_begin(..., "bttx")` + `akey_tok(kind)` (lines 42-46). Detail (lines 48-61): `host controller hci<N> told to transmit (<kind>, still on|recent, last command <s> s ago|no command seen); scan mode <passive|active|...>, filter <policy> - sloth sent nothing, the host stack did: this sensor's host is not passive`. `match_ip` is NULL: no pcap. The alert is **bucketed, not latched**: once a kind is neither on nor recent it stops being re-asserted and the engine resolves it after 300 s of silence (include/sloth.h:860), Recency runs from the newest *enabling* command of the kind - `note_tx()` (src/ble_hci.c:535-541) is called on enables only, never on a disable - so a persistent kind stops being asserted at the later of its disable and its last enable + 120 s, and resolves 300 s after that: a scan enabled for one minute closes ~7 minutes after its enable (~6 minutes after its disable); one left on for an hour closes ~5 minutes after its disable.

A controller already transmitting before sloth opened the channel is not seen until the host commands or resets it; sensor_health's `ble_own_tx_baseline` says so (src/jsonl.c:2519; docs/views/alerts.md:143).

## The attack

None. This type is one of the two own-operational-state kinds (`NO_MONITOR_MODE` is the other) pinned by `tests/test_research_corpus.c :: test_own_state_kinds_are_named` (lines 329-332) and given an empty technique in include/sloth_alerts.def:296. What it reports is that the Bluetooth controller sloth listens through has been put on the air by the operator's own host stack - bluetoothd, the kernel, a desktop settings panel - which breaks the passive guarantee MISSION §2 makes for every network sloth monitors [1][5].

Why that matters: in Bluetooth LE, an **active** scan transmits SCAN_REQ PDUs to each advertiser it hears and so announces the scanner's presence and address; a **passive** scan only listens (Core Specification Vol 6 Part B §4.4.3.1, as cited by the repo's wiki, docs/wiki/ble.md:35) [3][5]. Inquiry and page scan make the host discoverable/connectable over BR/EDR, advertising makes it an LE advertiser, and Create Connection initiates a link [3]. Any of these turns the sensor from an observer into a participant: it can be enumerated, fingerprinted and, in the case of the keystroke-injection class CVE-2023-45866 describes, targeted - that CVE is precisely a host accepting an unauthenticated peripheral [4]. A sensor that is itself an attackable Bluetooth host is a liability, and a non-passive sensor also contaminates its own evidence (its SCAN_REQs elicit scan responses other devices would not otherwise have sent).

The procedure the wiki gives to avoid it: run `sloth-ble-scan.service`, which holds a **passive** LE scan over the HCI user channel for the life of the sensor on a host where nothing else uses Bluetooth, or `hcitool -i hci0 lescan --passive --duplicates`; the `[*]` view's `ble_scan_mode` should read `passive` (docs/wiki/ble.md:513-554) [5].

## Evidence that proves it

What sloth records:

- the alert detail: adapter index, the kind (`bt_tx_kind_name()`, src/ble_hci.c:195-209: `active_scan`, `inquiry`, `periodic_inquiry`, `advertising`, `ext_advertising`, `periodic_advertising`, `le_connect`, `bredr_connect`, `remote_name_request`, `inquiry_page_scan`), `still on` or `recent`, seconds since the last command, and the current scan mode and filter policy (src/alerts/rules_ble.c:55-61);
- sensor_health's Bluetooth host block: `btmon_*` stream health, `ble_scan_mode`, filter policy, own-transmission recency and `ble_own_tx_baseline` (docs/wiki/jsonl-schema.md:840-850; src/jsonl.c:2519);
- JSONL `alert.create` / `alert.update` / `alert.resolve` on `bttx:<kind>`;
- **no pcap**, and nothing read from the monitor channel is written verbatim anywhere (src/ble_hci.h:59-63; docs/wiki/cli-reference.md:182).

To confirm it independently the operator runs `btmon` on the sensor host and looks for the same HCI command: `LE Set Scan Parameters` with `Type: Active`, `LE Set Scan Enable` with `Scanning: Enabled`, `LE Set Advertising Enable: Enabled`, `Inquiry`, `Write Scan Enable: Inquiry Scan + Page Scan`, etc. [3][7]; and `ps`/`systemctl` for the process that issued it (bluetoothd, a settings daemon, a user's `bluetoothctl scan on`). The kernel's monitor channel shows every command whatever process sent it, so the HCI record is authoritative [7].

What refutes it: nothing in the rule's own terms - a command the controller rejected still counts, by design, because the host *tried* (docs/views/alerts.md:143). What does *not* fire it and should not be mistaken for it: a controller transmitting under firmware or a pre-existing state with no host command (`ble_own_tx_baseline`), and a passive scan (`Scan_Type` passive), which is the intended configuration.

## Benign causes

Every cause is "benign" in the sense that nobody is attacking, but none is acceptable for a passive sensor:

- **bluetoothd running with default settings.** BlueZ's daemon performs active discovery when asked by a client and may advertise; the wiki's helper exists because, on a host where anything else uses Bluetooth, the operator's own stack is the usual cause (docs/wiki/ble.md:14-18, 576-580) [5].
- **A desktop Bluetooth settings panel open**, a phone-pairing attempt, or `bluetoothctl scan on` - all active scans [3][5].
- **Auto-connect to a previously paired peripheral** (Create Connection / LE Create Connection) at boot.
- **`hcitool lescan` without `--passive`** - active by default [5].
- **A DLT 254 replay** of someone else's btmon capture: the "host" is whoever recorded it, reported as `btmon_iface: replay` (docs/wiki/cli-reference.md:320).

## Assessment

**Severity.** WARN is right. It is the correct level for "the sensor is not what it claims to be": important enough to show on every view, not an attack. The repo's own-state form is the right classification and the empty technique is honest [1].

**Prevalence.** As a state, near-universal on a general-purpose Linux host with Bluetooth enabled; as an attack, not applicable. The `sloth-ble-scan` helper is the remedy the project ships [5].

**Noise on the reference host.** Not seen - the host either ran without `--bt-monitor` or with a passive scan held, which is the intended outcome. If it does fire: one incident per kind, so at most a handful of keys. `count` is evaluations (4/s). `observations` is the one to watch: the detail embeds `last command N s ago`, which changes every second, so while a kind is asserted the detail signature changes once a second and `observations` climbs with it; the JSONL `alert.update` is throttled to one per ALERT_UPDATE_MIN_S = 60 s (include/sloth.h:867; src/alerts/engine.c:527-538) so the stream is fine, but the counter is inflated. Recommendation: bucket the age in the detail (`<2 min`, `2-10 min`, ...) the way `stale_state()` buckets `stale_secs` for `sensor_health` (AGENTS.md, "Change-only emission must bucket its continuous values") - the same principle, applied to an alert detail.

**Sufficient to act on?** Yes - it is fully observable and reproducible on the host itself with `btmon`.

**First response.** Find the process that issued the command; stop it or reconfigure it; start the passive scan with `sloth-ble-scan.service` (or `hcitool lescan --passive --duplicates`); confirm `ble_scan_mode = passive` and watch the incident resolve 300 s after the kind stops being asserted - ~5 minutes after the disable, or up to ~7 minutes after the last enabling command (docs/wiki/alert-remediation.md:1741; docs/wiki/ble.md:513-554).

## Bibliography

1. docs/views/alerts.md:143 - the `BT_OWN_TRANSMIT` rule-table row, with the full opcode list and Core Specification clauses (accessed 2026-10-27)
2. docs/wiki/alert-remediation.md:1741 - `BT_OWN_TRANSMIT` investigate / fix (accessed 2026-10-27)
3. Bluetooth Core Specification v5.4 (Bluetooth SIG), Vol 4 Part E §7.1 (Link Control commands: Inquiry 0x0401, Periodic Inquiry 0x0403, Create Connection 0x0405, Remote Name Request 0x0419), §7.3.2 (Reset), §7.3.18 (Write Scan Enable), §7.8 (LE Controller commands: Set Scan Parameters, Set Scan Enable, Set Advertising Enable, Create Connection and their Extended forms); Vol 6 Part B §4.4.3.1 (passive scanning) - https://www.bluetooth.com/specifications/specs/core-specification-5-4/ (page fetched 2026-10-27; it marks Core Specification 5.4 "Withdrawn", with Errata Correction 18552 mandatory for compliance claims, and names no successor on that page; the clause text itself was not read - clause numbers are as cited by src/ble_hci.h and docs/wiki/ble.md:35)
4. NVD, CVE-2023-45866 - "Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral role HID Device to initiate and establish an encrypted connection ...", CVSS 3.1 6.3, CWE-287 - https://nvd.nist.gov/vuln/detail/CVE-2023-45866 (confirmed via the NVD 2.0 API, accessed 2026-10-27) - cited for why a non-passive Bluetooth host is itself a target
5. docs/wiki/ble.md - the Bluetooth host source: the passive-scan procedure (§"Passive-scan procedure"), `Filter_Duplicates`, `sloth-ble-scan`, what the source refuses and never writes (accessed 2026-10-27)
6. docs/wiki/cli-reference.md:182-184,320 - `--bt-monitor`, `--bt-capture`, `--ble-rotation-hints`, the DLT 254 replay route (accessed 2026-10-27)
7. Linux kernel, include/net/bluetooth/hci_mon.h - HCI monitor channel opcodes (`HCI_MON_NEW_INDEX 0`, `HCI_MON_DEL_INDEX 1`, `HCI_MON_COMMAND_PKT 2`, `HCI_MON_EVENT_PKT 3`, ...) - https://github.com/torvalds/linux/blob/master/include/net/bluetooth/hci_mon.h (raw file fetched and confirmed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD 0d60387) and by fetching every external source.

- Code: `rule_bt_own_transmit()` is `src/alerts/rules_ble.c:34-65` (draft: 33-64): `bt_tx_asserted_mask()` at `:36`, key `:42-46`, detail `:48-61`, WARN with NULL `match_ip` `:62-63` - anchors corrected. `bt_tx_asserted_mask()` is `src/ble_hci.c:251-259` and ORs "on" with `bt_tx_recency() == BT_TX_RECENT` (`:243-249`, `<= BT_TX_RECENT_SECS` at `:247`); `BT_TX_RECENT_SECS 120` at `src/ble_hci.h:118`. The allow-list block is `src/ble_hci.h:30-51`, the on/off paragraph `:53-57`, the never-written paragraph `:59-63` - corrected. The active-only scan rule is stated in `docs/views/alerts.md:143` (Scan_Type **active**), not in the rule file, and the entry now says where. `src/jsonl.c:2519` (`ble_own_tx_baseline`), `include/sloth.h:860/867`, `src/alerts/engine.c:527-538` (the 60 s update throttle; draft said 524-535), `tests/test_research_corpus.c:329-333`, `include/sloth_alerts.def:296`, `docs/wiki/ble.md:14-18, 35, 513, 576-580`, `docs/wiki/cli-reference.md:182-184, 320` all confirmed.
- Count semantics: correct - one `fire()` per asserted kind per tick; the detail's `last command %ld s ago` does change every second, so the `observations` inflation noted in the Assessment is real.
- Sources: [3] bluetooth.com page fetched - it says "Withdrawn", not "superseded", and the entry now says so and admits the clause text was not read; the wiki cites §4.4.3.1 (passive scanning), so the §4.4.3 reference was tightened. [4] NVD confirmed via the NVD 2.0 API (description, CVSS 6.3, CWE-287). [7] raw `hci_mon.h` fetched; the four opcodes confirmed. [1], [2], [5], [6] are repo files at the cited lines. This kind is on the own-state list by design and needs no `research/` document (`tests/test_research_corpus.c:329-333`).

Second pass, 2026-10-27 (re-read against HEAD d70d394; every external source re-fetched):

- Kind names were wrong: the detail and key carry `bt_tx_kind_name()` tokens with underscores (`active_scan`, `le_connect`, `bredr_connect`, `inquiry_page_scan`, ...); there is no `active-scan` or `create-connection`. Corrected to the full list from `src/ble_hci.c:195-209`.
- Resolve timing corrected: `note_tx()` stamps `tx_wall[kind]` on enabling commands only (`src/ble_hci.c:535-541`, call sites `:584-720`), so recency counts from the last enable, not from the disable; the "~7 minutes later" sentence and the First response were reworded to say from what.
- Added that an active-type Set Scan Parameters alone stamps `active_scan` (recency), while ON needs `scan_enabled == 1` with active mode (`src/ble_hci.c:174-175, 683-722`), and that the event allow-list is limited to LE Meta subevents 0x02/0x0D (`src/ble_hci.h:40-41`).
- Confirmed: the detail signature is a raw FNV-1a of the rendered string (`src/alerts/engine.c:74-76`), so the per-second `last command N s ago` does bump `observations` every second; the Assessment's recommendation stands.
- Sources re-fetched: [4] via the NVD 2.0 API (2023-12-08, CVSS 6.3, CWE-287); [7] raw `hci_mon.h` (`HCI_MON_NEW_INDEX 0` .. `HCI_MON_EVENT_PKT 3`); [3] the bluetooth.com 5.4 page still carries "Withdrawn".
