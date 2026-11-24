---
name: handoff
description: sloth --handoff (the site handoff packet) and sloth --interference-report (one section per RF_DEGRADED, RTS_FLOOD or GNSS_JAMMING episode), both read from sloth.db read-only
type: reference
---

# Site handoff packet and interference report

**Summary**: `sloth --handoff DIR [the normal options]` writes what a site's next operator needs into one new or empty directory and exits, starting nothing: the command line and radios, `--preflight` for that command line with the rule status counts, the designated networks and roster, the `--baseline-in` file, a site snapshot that `--baseline-in` reads, open findings with their state, 30 days of closed findings counted by kind, 30 days of interference, and a README. `sloth --interference-report FILE --db DB [--from T] [--to T]` writes one Markdown section per `RF_DEGRADED`, `RTS_FLOOD` or `GNSS_JAMMING` episode, for a reader outside the site. Both read `sloth.db` read-only. Neither writes a credential's user name, an RDP cookie, an MQTT user name or an EAP identity, though `sloth.db` holds them.

**Sources**: issue #250 (from #241 items 11 and 17); FM 2-0 (2004) 4-16 (what a unit taking over receives) and 8-25 (direction finding locates interference sources); FM 6-02.43 (2009) Appendix A-7 (resolve harmful interference at the lowest level, report what cannot be); `src/handoff.h`, `src/handoff.c`, `src/interference.h`, `src/interference.c`, `src/site_db.h`, `src/site_db.c`; `src/wifi_snapshot.c` (`wifi_snapshot_row()`, `wifi_snapshot_diff()`); `src/alerts/rules_wifi_mgmt.c` (`rule_rf_degraded()`, `rule_rts_flood()`), `src/alerts/rules_gnss.c` (`rule_gnss_jamming()`); sloth-mesh's `src/web_secret.h` (the withheld columns); `tests/test_handoff.c`, `tests/replay/handoff_cli.sh`.

**Last updated**: 2026-11-24 (#250: the page).

---

## 1. How they run

Both are commands: one of `--preflight`, `--handoff` and `--interference-report` per command line (two exit `2`).

`--handoff` runs where `--preflight` runs, after every whole-command-line check, so a refused combination exits `2` with its usual line. It then opens `--db` (when named), creates DIR, runs the preflight's gather and checks, writes the files and exits `0`, or `2` if a file could not be written. A database that does not open, or a DIR that exists and is not empty, exits `2` before anything is created.

`--interference-report` runs as soon as the command line is read: it needs only `--db`, so no capture-side check concerns it. FILE is created `0600` (an existing one is held to the secure-file rule and truncated); `-` is stdout.

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
- `interference.md` reads `key` and `detail` only for `RF_DEGRADED`, `RTS_FLOOD` and `GNSS_JAMMING`, whose text is the rule's own figures.
- The `--inventory` file is named, not copied: it is the operator's JSON, and sloth parses keys it does not read, so it could hold anything.

`tests/test_handoff.c :: test_handoff_packet` puts a distinct word in each of those columns and in an alert title and asserts that no file of the packet holds any of them, while `findings_open.tsv` does list the finding they belong to. Seen red with `findings_open.tsv` writing `alert_incidents.key`, and with the interference report reading `CLEARTEXT_CRED`.

The packet is a local file for the site's own operator; the roster travels in it because the next operator needs it to run the sensor as it was run. It is not a fleet export ([ADR 0009](adr/0009-fleet-monitor-only.md) governs those), and it names its host all the same.

## 5. The interference report

One document; a header with the sensor's host and version, the database and schema, the window and the time written; a paragraph on what the figures are; the episode counts by kind; which daemons' rows the file holds. Then one section per episode overlapping the window, in time order:

- **Times**: opened, last evaluated, the length; closed (with the reason) or "no close recorded in this file".
- **Severity**, peak, evaluations and evidence changes.
- **Figures** the rule recorded: the finding's stored detail, when the row's incident is this episode. `sloth.db` keeps a finding's latest detail only, so an earlier episode of the same key reads "not stored for this episode". `RF_DEGRADED`'s retry ratio, bad-FCS share and frame count and `RTS_FLOOD`'s RTS count, span and longest NAV are also given as a sentence each.
- **Coverage**, from the `coverage_interval` rows overlapping the episode ([[coverage-assessment]]): how many, each radio's share of that time on the episode's channel, frames heard on the channel and control frames per minute, during and in the same length before (at most 10 minutes, `IFR_BEFORE_MAX_S`). An `RTS_FLOOD` records no channel, so its section gives the radios' time by channel instead. With no row overlapping, it says so; nothing is zeroed.
- **Channel utilisation**: not stored as a history. `beacon_aps` holds each AP's latest QBSS load, which the AP list shows and labels as the latest.
- **Access points** on `RF_DEGRADED`'s channel whose first and last sighting span the episode, with the clients associated in it as a count (client addresses are not written: the reader is outside the site), at most 20 listed (`IFR_MAX_APS`). An `RTS_FLOOD` names its transmitter; the stations whose medium it reserved are not stored.
- **Location**: "not located". One sensor measures what reaches it; an estimate needs several (sloth-mesh#19).

GNSS_JAMMING is sloth-rf's alert, written to `sloth.db` only when sloth-rf runs with `--db` the same path. The report says whether the file holds Wi-Fi rows, GNSS rows or both, and with no GNSS rows that GNSS jamming is not reported from it.

The wording is about the observable. The retry ratio a jammer causes is the one a microwave oven, a hidden node and a client at the edge of range cause (`rule_rf_degraded()`'s comment), and a GNSS receiver cannot tell interference from jamming (DHS 2017, `rule_gnss_jamming()`); the report says what was received and when, not why.

## Related pages

- [[preflight]] — the checks the packet carries.
- [[coverage-assessment]] — the `coverage_interval` rows and the rule statuses.
- [[sqlite-schema]] — the tables read.
- [[posture-report]] — `--snapshot-out` and `--baseline-in`.
- [[cli-reference]] — the flags.
