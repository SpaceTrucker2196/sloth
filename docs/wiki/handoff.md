---
name: handoff
description: sloth --handoff (the site handoff packet) and sloth --interference-report (one section per RF_DEGRADED, RTS_FLOOD or GNSS_JAMMING episode), both read from sloth.db read-only
type: reference
---

# Site handoff packet and interference report

**Summary**: `sloth --handoff DIR [the normal options]` writes what a site's next operator needs into one new or empty directory and exits, starting nothing: the command line and radios, `--preflight` for that command line with the rule status counts, the designated networks and roster, the `--baseline-in` file, a site snapshot that `--baseline-in` reads, open findings with their state, 30 days of closed findings counted by kind, 30 days of interference, and a README. `sloth --interference-report FILE --db DB [--from T] [--to T]` writes one Markdown section per `RF_DEGRADED`, `RTS_FLOOD` or `GNSS_JAMMING` episode, for a reader outside the site. Both read `sloth.db` read-only. Neither writes a credential's user name, an RDP cookie, an MQTT user name or an EAP identity, though `sloth.db` holds them.

**Sources**: issue #250 (from #241 items 11 and 17); FM 2-0 (2004) 4-16 (what a unit taking over receives) and 8-25 (direction finding locates interference sources); FM 6-02.43 (2009) Appendix A-7 (resolve harmful interference at the lowest level, report what cannot be); `src/handoff.h`, `src/handoff.c`, `src/interference.h`, `src/interference.c`, `src/site_db.h`, `src/site_db.c`; `src/wifi_snapshot.c` (`wifi_snapshot_row()`, `wifi_snapshot_diff()`); `src/alerts/rules_wifi_mgmt.c` (`rule_rf_degraded()`, `rule_rts_flood()`), `src/alerts/rules_gnss.c` (`rule_gnss_jamming()`); sloth-mesh's `src/web_secret.h` (the withheld columns); `tests/test_handoff.c`, `tests/replay/handoff_cli.sh`.

**Last updated**: 2026-11-24 (#250 review: `--to` includes the whole day, minute or second it names; FILE naming `--db` or its `-wal`, `-shm`, `-journal` is refused; the "before" window takes only intervals that closed before the episode opened; the detail is parsed, never copied; the retry figures count frames of every type; access points overlap, not span; a channel number heard on two bands is said to be; at most 200 episodes, the latest; GNSS_JAMMING is reported from sloth-rf's own database; `--handoff` announces no opt-in), 2026-11-24 (#250: the page).

---

## 1. How they run

Both are commands: one of `--preflight`, `--handoff` and `--interference-report` per command line (two exit `2`).

`--handoff` runs where `--preflight` runs, after every whole-command-line check, so a refused combination exits `2` with its usual line. It then opens `--db` (when named), creates DIR, runs the preflight's gather and checks, writes the files and exits `0`, or `2` if a file could not be written. A database that does not open, or a DIR that exists and is not empty, exits `2` before anything is created.

`--interference-report` runs as soon as the command line is read: it needs only `--db`, so no capture-side check concerns it. FILE is created `0600` (an existing one is held to the secure-file rule and truncated); `-` is stdout. A FILE that is the `--db` file or its `-wal`, `-shm` or `-journal`, by device and inode (another spelling or a link is caught), exits `2` with nothing truncated: one mistyped path would otherwise empty the live sensor's store.

`--from` and `--to` take epoch seconds or UTC `YYYY-MM-DD[THH:MM[:SS]][Z]`. `--to` includes what it names: `2026-11-24` is up to 23:59:59 that day and `T10:15` up to 10:15:59, so `--from D --to D` is the day D (`site_db_parse_time_end()`).

Neither prints an opt-in as enabled: `--allow-active` and `--ble-rotation-hints` say nothing under `--handoff`, as under `--preflight`, because nothing starts (`tests/replay/handoff_cli.sh`).

Neither opens a capture handle, a radio or a socket. The preflight's own reads are those of [[preflight]].

## 2. sloth.db, read-only

`src/site_db.c` opens the file `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW`, DEFENSIVE, inside one read transaction so every file of a packet sees the same state of the database.

- When `<db>-wal` holds frames (a daemon has the file open, or stopped uncleanly), the URI is `?mode=ro`: the frames are read, as any reader reads them, and SQLite may leave a `-shm` beside the file if none is there. The daemon's last minutes are in the `-wal` until a checkpoint, so the main file alone would miss them.
- Otherwise it is `?mode=ro&immutable=1`, as `--preflight` reads it: no lock, nothing created.

A file whose schema is newer than the build's is refused; one older than v11 (the first with `alert_incidents`) is refused with the version it holds. `coverage_intervals` (v18) and the quality columns (v19) are read only when present; their absence is stated.

## 3. The packet

| File | What it holds |
|---|---|
| `README.txt` | Host, time, sloth version, site label, database, the rule counts, and one line per file: what it holds, or `[absent]` and why. |
| `config.json` | `argv`; `radios` (`--iface`, `--monitor-iface`, `--monitor-only`, `--df-iface` with positions); `hop` (enabled, the plan's frequencies and bands); `positions` (`--location`, `--df-origin`); `designations` (counts); `inventory` (version, site, hash, counts, path); `intel_pack` (version, hash, date); `database` (path, schema, whether a `-wal` was read). |
| `preflight.txt`, `preflight.json` | `--preflight` for this command line, as `sloth --preflight` and `--preflight --json` print it; the JSON's `rules` holds the observable / partly / blind counts and each kind not observable. |
| `networks.tsv` | `my-ssid` (escaped as the snapshot escapes an SSID), `my-bssid`, `known-mac` rows, and the inventory's identity. |
| `baseline.tsv` | The `--baseline-in` file, copied when its first line is `# sloth-snapshot v1`; otherwise not copied, and README says why without quoting it. |
| `snapshot.tsv` | A `# sloth-snapshot v1` file from `beacon_aps`: the APs last heard within a day (`HANDOFF_SNAPSHOT_WINDOW_S`) of the newest one, most recent first, at most 256 (the `--baseline-in` reader's limit, `MAX_BEACON_APS`). Without `--db`, the `--snapshot-out` file when it is a snapshot. |
| `findings_open.tsv` | Each `alert_incidents` row with no `closed_at`: kind, severity, peak, state, opened, last evaluated, evaluations, `complete` (v19), incident id. State `open` when it was evaluated within 300 s (`ALERT_RESOLVE_AFTER_S`) of the file's newest write; `unclosed` when older, because a running engine would have closed it and the daemon stopped first. |
| `findings_closed_30d.tsv` | Incidents closed in the 30 days to the packet's time, by kind, with how many peaked CRIT, WARN and INFO. |
| `interference.md` | `--interference-report` for the same 30 days (§ 5). |
| `false_positives.txt` | Empty, saying so: triage notes are kept by sloth-mesh, not in `sloth.db`. |

### Importing it

`snapshot.tsv` and `baseline.tsv` are what `--snapshot-out` writes. On the next run, `--baseline-in DIR/snapshot.tsv` diffs the site against it at exit and prints the new, gone and changed access points (`tests/replay/handoff_cli.sh` runs a replay against a packet built from the replay's own database and reads `0 change(s)`). There is no import for the other files: `config.json`'s `argv` is the command line, and the findings stay in `sloth.db`.

## 4. Withheld

sloth-mesh's `web_secret.h` lists the columns its readers of `sloth.db` withhold: `alerts.key` and `alerts.detail` (a clear-text credential's user name, an RDP `mstshash` cookie, an MQTT user name in the text), `cleartext_creds.username`, `mqtt_flows.last_username`, `rogue_radius.last_identity` and `rdp_flows.last_cookie`. `alert_incidents.key` is the same key. sloth's own rule is the schema guardrail (`tests/test_db.c`, no column can hold a password, PMKID, nonce or MIC): what `sloth.db` does hold of these is names, and the packet holds none of them.

- A finding is written as its kind, severity, times and incident id; no key, title or detail.
- `interference.md` reads `key` and `detail` only for `RF_DEGRADED`, `RTS_FLOOD` and `GNSS_JAMMING`, and writes what it parses out of them, never their text: the channel number, the RTS transmitter's address (heard over the air, and what the report's reader looks for) and the rule's figures. `test_interference_report` puts a word in each of the three details and asserts it is not written; seen red with the detail copied.
- The `--inventory` file is named, not copied: it is the operator's JSON, and sloth parses keys it does not read, so it could hold anything.

`tests/test_handoff.c :: test_handoff_packet` puts a distinct word in each of those columns and in an alert title and asserts that no file of the packet holds any of them, while `findings_open.tsv` does list the finding they belong to. Seen red with `findings_open.tsv` writing `alert_incidents.key`, and with the interference report reading `CLEARTEXT_CRED`.

The packet is a local file for the site's own operator; the roster travels in it because the next operator needs it to run the sensor as it was run. It is not a fleet export ([ADR 0009](adr/0009-fleet-monitor-only.md) governs those), and it names its host all the same.

## 5. The interference report

One document; a header with the sensor's host and version, the database and schema, the window and the time written; a paragraph on what the figures are; the episode counts by kind; which daemons' rows the file holds. Then one section per episode overlapping the window, in time order:

- **Times**: opened, last evaluated, the length; closed (with the reason) or "no close recorded in this file".
- **Severity**, peak, evaluations and evidence changes.
- **Figures** the rule recorded at its last evaluation, parsed out of the finding's stored detail when the row's incident is this episode (§ 4: the text is not copied): `RF_DEGRADED`'s retry ratio, bad-FCS share and frame count, where the count is every frame type heard on the channel, control and management included (`rf_quality_observe()` in `src/capture/probe.c`), not data frames; `RTS_FLOOD`'s RTS count, span and longest NAV; `GNSS_JAMMING`'s fall in tracked median C/N0, the u-blox jamming indicator's level and hold, and a lost fix. `sloth.db` keeps a finding's latest detail only, so an earlier episode of the same key reads "not stored for this episode"; a detail in a form the build does not parse says so.
- **Coverage**, from the `coverage_interval` rows overlapping the episode ([[coverage-assessment]]): how many, each radio's share of that time on the episode's channel, frames heard on the channel and control frames per minute, during and before. "Before" is the rows that closed in the same length before the episode opened (at most 10 minutes, `IFR_BEFORE_MAX_S`): a row still open when it opened holds its first frames and is counted as during only, so an episode shorter than a minute usually has no "before" and says so rather than repeating the during rate. An `RTS_FLOOD` records no channel, so its section gives the radios' time by channel instead. The channel is a number (`RF_DEGRADED`'s key carries no band, and neither does `beacon_aps`): when the rows hold it on two bands, 2.4 GHz and 6 GHz channel 1 say, the section says the figures and the APs are those bands together. With no row overlapping, it says so; nothing is zeroed. Each scan is a range of the `last_seen` index ending `IFR_IV_SPAN_MAX_S` (an hour) after the window.
- **Channel utilisation**: not stored as a history. `beacon_aps` holds each AP's latest QBSS load, which the AP list shows and labels as the latest.
- **Access points** on `RF_DEGRADED`'s channel number whose first-to-last sighting overlaps the episode (heard at some time in it by that measure; `beacon_aps` keeps no history), with the clients whose association overlaps it as a count (client addresses are not written: the reader is outside the site), at most 20 listed (`IFR_MAX_APS`). An `RTS_FLOOD` names its transmitter; the stations whose medium it reserved are not stored.
- **Location**: "not located". One sensor measures what reaches it; an estimate needs several (sloth-mesh#19).

At most 200 episodes (`IFR_MAX_EPISODES`) are written, the latest, and the header gives the total and asks for a narrower window for the rest. A transmitter that changes its address opens a new `RTS_FLOOD` incident each time, and the report runs inside the read transaction that holds back the daemon's checkpoint (§ 2), so its length and run time are bounded.

GNSS_JAMMING is sloth-rf's alert, and sloth-rf keeps its own database since the cutover ([ADR 0010](adr/0010-wifi-rf-daemons.md); `/var/lib/sloth-rf/sloth-rf.db` in the shipped unit). Its episodes are reported by the same command with `--db` that file; the `--handoff` packet reads `sloth.db` only, so its `interference.md` holds no post-cutover GNSS jamming. The report says so, and gives the Wi-Fi rows and the GNSS fixes the file holds (their count and newest time) without naming which daemon wrote them: a `sloth.db` from before the cutover keeps sloth-wifi's own GNSS rows ([[sqlite-schema]]).

The wording is about the observable. The retry ratio a jammer causes is the one a microwave oven, a hidden node and a client at the edge of range cause (`rule_rf_degraded()`'s comment), and a GNSS receiver cannot tell interference from jamming (DHS 2017, `rule_gnss_jamming()`); the report says what was received and when, not why.

## Related pages

- [[preflight]] — the checks the packet carries.
- [[coverage-assessment]] — the `coverage_interval` rows and the rule statuses.
- [[sqlite-schema]] — the tables read.
- [[posture-report]] — `--snapshot-out` and `--baseline-in`.
- [[cli-reference]] — the flags.
