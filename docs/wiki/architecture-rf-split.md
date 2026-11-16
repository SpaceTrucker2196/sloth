# Architecture: the sloth-wifi / sloth-rf coupling inventory

**Summary**: Every place today's single `sloth` process ties the SDR and
GNSS modules (ADS-B, APRS, rtl_433, GNSS) to the Wi-Fi monitor, produced
by grep rather than from #211's prose, with the command beside each list
so a reviewer can re-run it. It covers the RF files and what each
`*_health_poll()` writes, the services that exist once per process, the
places GNSS reaches into Wi-Fi-side code, the run flag that lives in
`src/capture/capture.c`, slothweb's one-socket and one-database
assumptions, the packaging, the slice table S0 to S6, and a section
naming every place the tree and #211 disagree.

**Sources**: `include/sloth.h`, `include/sloth_alerts.def`,
`include/sloth_views.def`, `src/poll.c`, `src/main.c`, `src/gps.c`,
`src/adsb.c`, `src/aprs.c`, `src/rtl433.c`, `src/capture/capture.c`,
`src/capture/capture.h`, `src/capture/{gps,adsb,aprs,rtl433}_reader.c`,
`src/alerts/engine.c`, `src/alerts/rules_table.c`,
`src/alerts/rules_twin.c`, `src/alerts/rules_sensor.c`,
`src/evidence_manifest.c`, `src/position_track.c`, `src/sys_status.c`,
`src/sys_status.h`, `src/jsonl.c`, `src/data_socket.c`, `src/db.c`,
`src/db.h`, `src/db_schema.c`, `src/views/alerts.c`, `src/views/iface.c`,
`src/views/adsb.c`, `Makefile`, `web/src/main.c`, `web/src/web_config.h`,
`web/src/web_devices.h`, `web/src/web_fleet.h`, `web/src/web_ingest.c`,
`web/src/web_ingest.h`, `web/src/web_live.c`, `web/src/web_gnss.c`,
`web/src/web_rtl433.c`, `web/src/web_slothdb.c`, `packaging/systemd/`,
`packaging/bin/sloth-migrate-sensor`, `tests/test_unit_file.c`,
`tests/deploy/`, issues #211 to #217.

**Last updated**: 2026-11-15 (#216, S5 landed, the cutover: §12, what left sloth-wifi, what stayed, the seams it cut and what of §§2 to 7 and 10 it made stale), 2026-11-15 (#214, S3 landed: §11, what it did about each row of §6.2, and what it left), 2026-11-15 ([[victron]]: sloth-rf's fifth `source_status` row, `victron`), 2026-11-15 (#213 review: §10's member count measured at 49, and what the `nm` gate missed and now holds); 2026-11-15 (#213, S2 landed: §10, the seams it cut, and what of §§2 to 4 it made stale); 2026-11-15 (S0, and the notes on S1)

This page is a measurement, not a plan. It is slice S0's deliverable
(#211) and it exists so that S1 to S6 cut along lines someone has
looked at. The decision it serves is
[ADR 0010](adr/0010-wifi-rf-daemons.md). Where it contradicts #211, the
tree is the authority and §9 says so.

It measures the tree as it stood before any slice. S1 (#212) has since
landed, so these describe the parent of that commit and not the tree:

- **§5.** The run flag is `src/run_flag.c` now, and the four readers
  include `run_flag.h`.
- **Every `src/poll.c` line number, and the stage-table row of §3.**
  The table is data: `g_poll_sloth`, `g_poll_wifi`, `g_poll_rf`.
- **Every sentence that names `st_health()` or `st_sensors()` as the
  one function** (§2.2, §3.1, §4.1's `src/poll.c` row, §4.2, §9 item
  1). `st_health()` is five stages: `health_capture` in `src/poll.c`,
  `health_gnss` (`poll_st_health_gnss()`, `src/poll_gnss.c`),
  `health_rf` (`poll_st_health_rf()`, `src/poll_rf.c`), `health_host`
  (`poll_st_health_host()`, `src/poll_core.c`) and `capture_scope`.
  `st_sensors()` is three: `st_sensors_wifi()` in `src/poll.c`,
  `poll_st_sensors_gnss()` and `poll_st_sensors_rf()`. The calls and
  their order are the ones written below; `aprs_health_poll()` still
  runs after `gps_health_poll()`.
- **§2.1's "There is one list" and its `Makefile` line numbers.**
  `CORE_COMMON_SRCS` is the union of `CORE_BASE_SRCS`, `GNSS_SRCS` and
  `RF_SRCS`; every RF file is still in `sloth` and in `sloth_test`.
- **`alerts_update()`** is called from `poll_st_alerts()` in
  `src/poll_core.c`, not from `src/poll.c`.

S2 (#213) has landed as well: `sloth-rf` exists, beside `sloth`, which
keeps every flag. §10 is what it cut and why. It made these stale too:

- **§2.3's flags and §4.1's `src/main.c` row.** The checks for
  `--location`, `--gps`, `--gps-allow-remote`, `--gps-baud` are
  `src/gnss_flags.c`, those for `--adsb`, `--aprs`, `--aprs-freq`,
  `--aprs-silent-hours`, `--rtl433` are `src/rf_flags.c`, and the
  privilege drop, `--tune`, `--ticks` and the three sinks' start-up are
  `src/daemon_start.c`; `src/main.c` and `src/rf/main.c` call them.
- **§3's JSONL and `sensor_health` rows, §4.1's `src/jsonl.c` rows,
  and the `src/jsonl.c` count in §4.3.** The sink, the cache
  (`g_dedup[]`), `any_sink()`, the builders and the alert and `sensor`
  records are `src/jsonl_core.c`; `jsonl_emit_gnss()`, `_adsb()`,
  `_aprs()`, `_rtl433()` and `g_aprs_cursor` are `src/jsonl_rf.c`.
  `sensor_health` is assembled from blocks (`src/jsonl_internal.h`):
  `sloth`'s assembly is still `jsonl_emit_sensor_health()` in
  `src/jsonl.c`, sloth-rf's is `jsonl_emit_sensor_health_rf()`.
- **§3's rule-table row and §2.3's rule rows.** `g_alert_rules[]` is
  the rows of whichever table the daemon selected; the 93 are
  `g_alert_table_sloth`.
- **§3.1's `SYS_SRC_*` paragraph and §4.1's `src/sys_status.c` row.**
  `sys_status_poll()` fills the GNSS, ADS-B, APRS and rtl_433 rows
  itself; the other four are `sys_status_capture_fill()` in
  `src/sys_status_capture.c`, registered by the daemon that has a
  capture.
- **§3's poll-loop row and the note above on `poll_st_alerts()`.**
  `g_poll_rf` has nine stages; `poll_st_jsonl()` is in `src/poll.c`.
- **§9 item 4 is no longer only a question for 2.0.0.** sloth-rf
  writes its own five `source_status` rows (`victron` the fifth since
  JSONL 1.10.0) and its own sensors from
  slot 0 today; the numbering is the shared enum's.

S5 (#216), the cutover, has landed: §12. It made these stale:

- **Every "`sloth`" that means the Wi-Fi daemon.** The binary is
  `sloth-wifi`; `sloth` is a symlink to it.
- **§2.1's view column and §2.3's view and flag rows.** `src/views/adsb.c`
  is deleted and `include/sloth_views.def` has no ADS-B row; `--adsb`,
  `--aprs`, `--aprs-freq`, `--aprs-silent-hours`, `--rtl433` and
  `--victron` are not parsed by `src/main.c` but refused
  (`src/rf_moved.c`), and it starts and stops no decoder reader.
- **§2.3's rule rows, §3's rule-table row and §10's first table row.**
  The Wi-Fi table is `g_alert_table_wifi`, 88 rows; the four GNSS
  rules and `rule_adsb_emergency` are in `g_alert_table_rf` only.
- **§3's poll-loop row.** Two tables, `g_poll_wifi` and `g_poll_rf`;
  `g_poll_sloth` is gone.
- **§3.1 and §4.1's `src/sys_status.c` row.** `sys_status_poll()` fills
  the GNSS row itself; the `adsb`, `aprs`, `rtl433` and `victron` rows
  are `src/sys_status_rf.c`, registered by sloth-rf.
- **§3's database row and §4.1's last paragraph.** `write_gnss()`,
  `write_adsb()`, `write_aprs()` and `write_victron()` run only where
  `db_set_rf_side()` was called; `jsonl_emit_gnss()` is not called by
  `src/jsonl.c`.
- **§4.3.** Nothing outside the RF group names `adsb_*`, `aprs_*`,
  `rtl433_*` or `victron_*` functions any more; `src/views/iface.c`
  has no `adsb` token.
- **§7.** `ExecStart=/usr/local/bin/sloth-wifi`; the migrate tool
  accepts `sloth` and `sloth-wifi` and reads `$ROOT$PREFIX/bin/sloth-wifi`;
  `make install` places `sloth-wifi` and the `sloth` link.
- **§8.** S5's row: landed.

[[architecture]] has the current layout.

Line numbers are those of commit `3148c553`. They move; the commands do
not.

---

## 1. How each list was produced

Run from the repository root. Each command is the authority for the
section named beside it.

```sh
# (a1) files named for an RF module
git ls-files src include |
  grep -i -E 'adsb|aprs|rtl433|gnss|gps|nmea|ubx|sdr|meshtastic'

# (a2) every file that mentions one (the superset: owners and users)
grep -rlE 'adsb|aprs|rtl433|gnss|gps_|[^a-z]gps[^a-z]|GNSS|ADSB|APRS|RTL433' \
  src include --include=*.c --include=*.h --include=*.def | sort

# (a3) the health polls, and the state members each one touches
grep -rnE '^(void|int) +[a-z0-9_]*_health_poll *\(' src
grep -nE '_health_poll *\(' src/poll.c
sed -n '<first>,<closing brace>p' <file> | grep -oE 's->[a-z0-9_]+' | sort | uniq -c

# (a4) the RF members of sloth_state_t, the alert kinds and the views
grep -nE '(gps|gnss|adsb|aprs|rtl433)[a-z0-9_]*(\[[A-Z0-9_]+\])?;' include/sloth.h
grep -nE 'GNSS|ADSB|APRS|RTL433|SENSOR_' include/sloth_alerts.def | grep 'X('
grep -nE 'GNSS|ADSB|APRS|RTL' include/sloth_views.def
grep -nE 'gnss|adsb|aprs|rtl433|sensor' src/alerts/rules_table.c

# (b) the once-per-process services
grep -n 'g_poll_stages' src/poll.c ; sed -n '470,506p' src/poll.c
grep -nE '^static [a-zA-Z_0-9 \*]+ g_[a-z_0-9]+' \
  src/alerts/engine.c src/db.c src/jsonl.c src/data_socket.c
grep -rnE 'sensor_register *\(' src --include=*.c
grep -nE 'SENSOR_[A-Z0-9_]+|MAX_SENSORS' include/sloth.h
grep -nE 'SYS_SRC_[A-Z0-9_]+' src/sys_status.h
grep -nE 'CREATE TABLE IF NOT EXISTS (gnss|adsb|aprs|rtl433|device_positions|sensor)[a-z_]*' \
  src/db_schema.c

# (c) GNSS outside the GNSS module
grep -rnE '(s|st|state)->(gps|gnss_[a-z_]+)\b' src --include=*.c --include=*.h |
  grep -vE '^src/(gps\.[ch]|capture/gps_reader\.[ch]|alerts/rules_gnss\.c|views/gnss\.[ch])'
grep -rnE '\b(gps|gnss)_[a-z0-9_]+ *\(' src --include=*.c |
  grep -vE '^src/(gps\.c|capture/gps_reader\.c|alerts/rules_gnss\.c|views/gnss\.c)'
grep -rnE 's->(adsb|aprs|rtl433)(_[a-z_]+)?\b' src --include=*.c |
  grep -vE '^src/(adsb|aprs|rtl433)\.c' | awk -F: '{print $1}' | sort | uniq -c

# (d) the run flag
grep -rnE 'capture_run_flag' src --include=*.c --include=*.h

# (e) slothweb
grep -nE '\b(sock|sloth_db)\b' web/src/web_config.h
grep -nE '^static [A-Za-z_0-9 \*]+ \**g_[a-z_0-9]+' web/src/main.c
grep -nE '&g_sdb|cfg\.(sock|sloth_db)' web/src/main.c
grep -rnE 'web_slothdb[a-z_]* *\*sdb' web/src/*.h
grep -rnE '"sensor_health"' web/src/*.c
grep -nE 'web_live_sock_connected|web_feed_reset|web_metrics_stream' web/src/web_ingest.c
grep -nE '"devices"|FROM devices' web/src/web_slothdb.c

# (f) packaging
git ls-files packaging
grep -nE '^(ExecStart|RuntimeDirectory|StateDirectory|User|After|Wants|BindsTo|ReadOnlyPaths|RestrictAddressFamilies)' \
  packaging/systemd/sloth-sensor.service packaging/systemd/slothweb.service
sed -n '250,309p' packaging/bin/sloth-migrate-sensor
grep -rnE '/usr/local/s?bin/sloth\b' tests packaging Makefile

# (g) the slices
gh issue list --state all --limit 12 --json number,title
```

---

## 2. What belongs to the RF side (a)

### 2.1 Files

From (a1). Lines are `wc -l` at this commit.

| Module | Pure half | Reader thread | Rule file | Terminal view |
|---|---|---|---|---|
| GNSS | `src/gps.c` (1607), `src/gps.h` (388) | `src/capture/gps_reader.c` (266), `.h` (43) | `src/alerts/rules_gnss.c` (954) | `src/views/gnss.c` (336), `.h` (13) |
| ADS-B | `src/adsb.c` (1094), `src/adsb.h` (279), `src/adsb_beast.c` (542), `src/adsb_beast.h` (201) | `src/capture/adsb_reader.c` (288), `.h` (54) | `src/alerts/rules_adsb.c` (169) | `src/views/adsb.c` (318), `.h` (15) |
| APRS | `src/aprs.c` (670), `src/aprs.h` (226) | `src/capture/aprs_reader.c` (187), `.h` (46) | none | none |
| rtl_433 | `src/rtl433.c` (673), `src/rtl433.h` (200) | `src/capture/rtl433_reader.c` (187), `.h` (48) | none | none |

`include/` holds no RF file of its own; the RF types
(`gps_health_t`, `gnss_sky_t`, `gnss_fix_t`, `adsb_health_t`,
`aprs_health_t`, `rtl433_health_t` and their row types) are declared in
`include/sloth.h`, and the kinds and views in
`include/sloth_alerts.def` and `include/sloth_views.def`.

Not on the list, and why:

- **Meshtastic has no code.** `grep -rniE meshtastic src include web/src`
  finds only the registry kind: `SENSOR_MESHTASTIC` in the
  `sensor_kind_t` enum (`include/sloth.h:2818`), its name string in
  `src/sensors.c:6`, and a comment.
- **`sloth-sdrsweep` is already a separate binary.** `src/sdrsweep/`
  (`main.c`, `sdrsweep_dsp.c`, `sdrsweep_dsp.h`) is built by its own
  Makefile section (`Makefile:558` on) from `SDRSWEEP_SRCS`
  (`Makefile:574`), has its own unit and account
  (`packaging/systemd/sloth-sdrsweep.{service,path,sysusers.conf}`), and
  `tests/test_sdrsweep.c` holds that it is not linked into `sloth`. This
  programme does not move it.

The sources reach the build through `CORE_COMMON_SRCS`
(`Makefile:226`, `241`, `254`, `258`, `262`, `266`; `src/views/gnss.c`
and `src/alerts/rules_gnss.c` are in the same list). There is one list,
so every RF file is in `sloth` and in `sloth_test`.

Tests named for these modules: `tests/test_gps.c`,
`test_gnss_rules.c`, `test_gnss_view.c`, `test_adsb.c`,
`test_adsb_beast.c`, `test_adsb_rules.c`, `test_adsb_view.c`,
`test_aprs.c`, `test_rtl433.c`, and for the shared services
`test_sensor_health.c`, `test_sensor_rules.c`, `test_sensors.c`,
`test_sys_status.c`.

### 2.2 What each health poll writes

From (a3). All are called from one stage, `st_health()` in `src/poll.c`,
in this order (lines 129, 132, 135, 140), after the capture, monitor and
Bluetooth polls (124 to 126) and before `sys_status_poll()`.

| Poll | Defined | Writes on `sloth_state_t` | Reads on it |
|---|---|---|---|
| `gps_health_poll(s, wall)` | `src/gps.c:1280` | `gps`, `gnss_sky`, `gnss_fix`, `gnss_hist` | — |
| `adsb_health_poll(s, wall, mono_ms)` | `src/adsb.c:1025` | `adsb`, `adsb_rows`, `adsb_count`, `adsb_gone`, `adsb_gone_count` | — |
| `aprs_health_poll(s, wall, mono_ms)` | `src/aprs.c:488` | `aprs`, `aprs_rows`, `aprs_count`, `aprs_gone`, `aprs_gone_count`, `aprs_pkts`, `aprs_pkt_count` | `gps` (§4.2) |
| `rtl433_health_poll(s, wall)` | `src/rtl433.c:624` | `rtl433`, `rtl433_rows`, `rtl433_count` | — |

The members are declared at `include/sloth.h:4213` to `4260`, beside the
terminal selections that belong to the two RF views (`gnss_sel`,
`gnss_sel_key`, `gnss_detail`, `adsb_sel`, `adsb_sel_key`).

### 2.3 Alert kinds, rule rows, views, flags, knobs

- **Kinds** (`include/sloth_alerts.def`): `GNSS_JAMMING` (330),
  `GNSS_SPOOF_SUSPECT` (338), `GNSS_TIME_JUMP` (343),
  `GNSS_POSITION_JUMP` (346), `ADSB_EMERGENCY` (358),
  `SENSOR_UNDERVOLT` (381), `SENSOR_SOURCE_DOWN` (383). APRS and rtl_433
  have no alert kind.
- **Rule rows** (`src/alerts/rules_table.c`): `rule_gnss_jamming`,
  `rule_gnss_time_jump`, `rule_gnss_position_jump`,
  `rule_gnss_spoof_suspect` (116 to 119), `rule_adsb_emergency` (121),
  `rule_sensor_undervolt`, `rule_sensor_source_down` (124, 125). The
  last pair is defined in `src/alerts/rules_sensor.c` (87, 157) and
  reads only `sys_status_get()`.
- **Views** (`include/sloth_views.def`): `GNSS`, key `#` (65); `ADSB`,
  key `^` (71). Both are included from `src/tui.c` (71, 72).
- **Flags** (`src/main.c`): `--location` (1030), `--gps` (1032),
  `--adsb` (1034), `--aprs` (1036), `--rtl433` (1038), `--aprs-freq`
  (1040), `--aprs-silent-hours` (1047), `--gps-allow-remote` (1056),
  `--gps-baud` (1058). The readers are configured at 1373 (ADS-B), 1402
  (APRS), 1427 (rtl_433) and 1754 (GNSS), started together after the
  privilege drop (2017 to 2020) and stopped together (2114 to 2117).
- **Knobs** (`grep -oE 'TUNE_(GPS|GNSS|ADSB|APRS|RTL433)[A-Z0-9_]*'
  src/tune.h | sort -u`): `TUNE_ADSB_EMERG_HOLD_S`, the twelve
  `TUNE_GNSS_*`, and `TUNE_GPS_MAX_FIX_AGE_S`, `TUNE_GPS_MIN_MOVE_M`,
  `TUNE_GPS_SAMPLE_S`. The three `TUNE_GPS_*` are read by Wi-Fi-side
  code too (the location stamp's age, `position_track.c`).

---

## 3. What exists once per process (b)

Each of these is one instance that both halves use today. A second
daemon needs its own.

| Service | Where | What is single |
|---|---|---|
| The state | `sloth_state_t`, `include/sloth.h` | One struct; the RF members of §2.2 sit in it beside the Wi-Fi tables. Every rule, view, emitter and writer takes it whole. |
| The poll loop | `g_poll_stages[]`, `src/poll.c:470` | One table of stages (`platform_net`, `health`, … `alerts`, … `positions`, `jsonl`, `db`), run in order every tick at `src/poll.c:519`. The four RF polls are lines inside the `health` stage; the RF sensor registrations are lines inside `st_sensors()` (§3.1). There is no per-application table. |
| The alert engine | `src/alerts/engine.c` | File-scope state: `g_incident_seq` (59), `g_incident_hook` (99), the twin taint table (130 to 132), `g_key_hash_mask` (209), the side table (279 to 281), the hardware verdict (463). One alert table on the state. |
| The rule table | `src/alerts/rules_table.c` | One array, 93 `R(rule_…)` rows; seven of them are the RF rows of §2.3. Table order is run order. |
| The JSONL writer | `src/jsonl.c` | One file sink `g_fp` and one mutex (50 to 53), one change-only cache `g_dedup[]` (107), one APRS cursor `g_aprs_cursor` (3430). `jsonl_emit_state_snapshots()` (3883) calls `jsonl_emit_gnss`, `_adsb`, `_aprs`, `_rtl433` (3930 to 3933) and then `jsonl_emit_sensor_health` (3943) in one pass. |
| The data socket | `src/data_socket.c` | One listener `g_listen_fd`, one client table, one unix path (73 to 81). `any_sink()` (`src/jsonl.c:59`) is "the file or this socket". |
| The database handle | `src/db.c` | `static sqlite3 *g_db` (44), with the session id (58), the tick clocks (55, 56) and `g_aprs_seq` (180) beside it. `db_tick()` (2766) writes every table from the one state; the RF writers are `write_gnss()` (1983), `write_adsb()` (2059), `write_aprs()` (2140), and `write_positions()` (1939). `DB_SCHEMA_VERSION` is 14 (`src/db.h:114`). |
| The `sensor_health` record | `jsonl_emit_sensor_health()`, `src/jsonl.c:2181` | One record per process. Its change signature takes the GNSS state and the position cell (2430 to 2444); its body carries the `gps_*`, `gnss_*` and `loc_*` members (from 2768) and the `adsb_*`, `aprs_*` and `rtl433_*` blocks, each only while its flag is set. |

The RF tables in the schema (`src/db_schema.c`): `device_positions`
(784), `sensor_positions` (796), `gnss_fixes` (814), `gnss_sightings`
(838), `adsb_aircraft` (861), `adsb_sightings` (883), `aprs_stations`
(921), `aprs_packets` (942), `sensors` (963). rtl_433 has no table.

### 3.1 The two registries

- **`s->sensors[]`** (`include/sloth.h:3930`, `MAX_SENSORS` 16 at 2815).
  `sensor_register()` (`src/sensors.c:24`) is called from one function,
  `st_sensors()` in `src/poll.c`: the Wi-Fi monitor (299), the BLE HCI
  monitor (318), the Ubertooth capture (328), the GNSS receiver (338),
  the ADS-B decoder (348), the APRS decoder (363), the rtl_433 decoder
  (378). The kind numbers (`SENSOR_WIFI` … `SENSOR_RTL433`,
  `include/sloth.h:2817` to 2820) are persisted, in the `sensors` table
  and the `sensor` record.
- **`SYS_SRC_*`** (`src/sys_status.h:114` to 119): `SYS_SRC_CAPTURE`,
  `_MONITOR`, `_BTMON`, `_BTCAP`, `_GNSS`, `_ADSB`, `_APRS`, `_RTL433`,
  then `SYS_SRC_COUNT`. A source's slot is its id in the stream.
  `sys_status_poll()` fills one `sys_source_t src[SYS_SRC_COUNT]`
  (`src/sys_status.h:172`) from the state: `s->gps` at
  `src/sys_status.c:984` to 1006, `s->adsb` at 1014, `s->aprs` at 1029,
  `s->rtl433` at 1046. `rule_sensor_source_down` and
  `rule_sensor_undervolt` read that one snapshot.

Both registries hold Wi-Fi and RF rows in one array with one numbering.

---

## 4. GNSS in Wi-Fi-side code, and APRS reading the position (c)

### 4.1 Wi-Fi-side code that uses GNSS

From (c). "Wi-Fi-side" here is everything outside `src/gps.c`,
`src/capture/gps_reader.c`, `src/alerts/rules_gnss.c` and
`src/views/gnss.c`.

| Where | What it uses | Why |
|---|---|---|
| `src/alerts/engine.c:626` | `gps_location_current(&a->loc, now)` | The location stamp: where the sensor was as an incident opened, once per open. Every alert kind gets it. Downstream: `gps_loc_json()` on the alert record (`src/jsonl.c:544`), the `loc_src` column (`src/db.c:2230`). |
| `src/alerts/rules_twin.c:2062` | `s->gnss_hist` in `twin_sensor_moving()` | Motion suppression: a twin proximity swing measured while the sensor moved is not evidence. Called at 243 and 2115. |
| `src/evidence_manifest.c:388` | `gps_loc_json(meta->loc, …)` | The incident's location in the evidence manifest. |
| `src/views/alerts.c:154`, `156` | `s->gps.configured`, `gps_loc_text()` | The alert detail's location line. |
| `src/views/iface.c:531` to 533 | `s->gps`, `gps_state_name()` | The `gps` token on the interface strip. |
| `src/position_track.c:106`, `119`, `120` | `gps_location_current()`, `s->gps.sats`, `s->gps.hdop`, `gps_distance_m()` (32) | `postrack_tick()`, the `positions` stage (`src/poll.c:437`): samples for `device_positions` **and** `sensor_positions`, written by `write_positions()`. |
| `src/jsonl.c:2430` to 2444, 2768 to 2815 | `s->gps` | `sensor_health`'s `gps_*`, `gnss_*` and `loc_*` members and their part of the change signature. |
| `src/sys_status.c:984` to 1006 | `s->gps`, `gps_state_name()` | The `SYS_SRC_GNSS` row of `source_status`. |
| `src/poll.c:337` to 340 | `s->gps.has_gps`, `.src`, `.sentences` | The GNSS row of `s->sensors[]`. |
| `src/main.c:1061`, 1317 to 1348, 1754 to 1794 | `gps_reader_baud_ok()` (1061, the `--gps-baud` parse), `gps_location_parse_fixed()` (1317), `gps_spec_parse()` (1332, 1768), `gps_reader_configure()` (1754) | Flag parsing and start-up. |

The GNSS records and tables themselves are written from
`src/jsonl.c:3236` (`jsonl_emit_gnss`) and `src/db.c:1983`
(`write_gnss`), both reading `s->gps`, `s->gnss_fix` and `s->gnss_sky`.

Headers: `gps.h` is included by `src/alerts/engine.c`, `src/db.c`,
`src/evidence_manifest.c`, `src/jsonl.c`, `src/main.c`, `src/poll.c`,
`src/position_track.c`, `src/reset_all.c`, `src/sys_status.c`,
`src/views/adsb.c`, `src/views/alerts.c`, `src/views/iface.c`, besides
the GNSS module's own files.

### 4.2 The place APRS reads the position

`aprs_health_poll()` at `src/aprs.c:529`:

```c
int rg = aprs_region_of(s->gps.has_loc, s->gps.loc_lat, s->gps.loc_lon);
```

It is why `aprs_health_poll()` runs after `gps_health_poll()` in
`st_health()` (`src/aprs.h:117` says so), and why sloth-rf needs its own
`--gps` / `--location`. Only the region and its channel are kept, never
the position.

### 4.3 The other RF modules on the Wi-Fi side

Where code outside a module's own `.c` reads its state, by file and
count of `s->adsb*`, `s->aprs*` and `s->rtl433*` references:
`src/jsonl.c` 58, `src/views/adsb.c` 22, `src/poll.c` 15,
`src/alerts/rules_adsb.c` 7, `src/db.c` 7, `src/sys_status.c` 6,
`src/views/iface.c` 2. The last is the `adsb` token on the interface
strip (`src/views/iface.c:548` to 550), a Wi-Fi-side view reading
`s->adsb`. `src/views/adsb.c` in turn calls `gps_location_current()`
(164) for range and bearing. `src/reset_all.c` includes `adsb.h`,
`aprs.h`, `rtl433.h` and `gps.h` to clear every module on a reset.

---

## 5. The run flag lives in `src/capture/capture.c` (d)

`capture_run_flag_t` is declared in `src/capture/capture.h` (347, with
`capture_run_flag_get`, `_set`, `_take` at 350 to 352) and defined in
`src/capture/capture.c` (478, 485, 491), the libpcap capture's own file.

Every reader thread uses it for its `g_running`:

| File | `#include "capture/capture.h"` | `g_running` |
|---|---|---|
| `src/capture/gps_reader.c` | 15 | 32 |
| `src/capture/adsb_reader.c` | 15 | 31 |
| `src/capture/aprs_reader.c` | 10 | 22 |
| `src/capture/rtl433_reader.c` | 10 | 22 |
| `src/capture/bt_capture.c` | 15 | 27 |
| `src/capture/bt_monitor.c` | 15 | 29 |
| `src/capture/probe.c` | 13 | 145 |
| `src/capture/capture.c` | 3 | 548 |

So the four RF readers, which need nothing else from the capture, link
against the capture's translation unit for three small functions. A
sloth-rf that does not open a pcap handle cannot be linked until the
flag moves to a file of its own (S1, #212).

---

## 6. slothweb assumes one socket and one database (e)

### 6.1 Configuration and globals

- `web_config_t` (`web/src/web_config.h`, closes at 93) has one
  `web_sockspec_t sock` (42, `--socket`) and one `char sloth_db[4096]`
  (52, `--sloth-db`).
- `web/src/main.c` holds one of each consumer as a file-scope global
  (42 to 74): `g_live` (43), `g_ingest` (44), `g_rollup`, `g_metrics`,
  `g_store`, `g_tsdb`, `g_sdb` (53), `g_m4` (54), `g_sql`, `g_frrs`,
  `g_ble`, `g_gnss`, `g_adsb`, `g_aprs`, `g_rtl433`, `g_sys`, `g_lure`,
  `g_chain`, `g_fleet`.
- One ingest thread: `web_ingest_start(&g_ingest, &cfg.sock, …)`
  (`web/src/main.c:323`). `web_ingest_t` (`web/src/web_ingest.h:102`)
  has one `spec`, one `feed` and one `live`.
- One database reader: `web_slothdb_init(&g_sdb, cfg.sloth_db, &fns)`
  (129). `&g_sdb` is handed to the anomaly config (126), `g_m4.sdb`
  (183) and `web_sqlbox_init()` (287); `web_sys_set_dbs()` (175) takes
  the one path for the store-size figures.
- The structs that carry it: `web_m4_t.sdb` (`web/src/web_devices.h:70`,
  struct closes at 102), `web_fleet_src_t.sdb` (`web/src/web_fleet.h:436`,
  closes at 450), and the same member in `web_anomaly.h:300`,
  `web_fleetview.h:125` and `web_sqlbox.h:110`. Each is a single
  pointer: a route reads "the" sloth.db.

### 6.2 What a second stream into today's pipeline would break

From `grep -rnE '"sensor_health"' web/src/*.c` and the connect path in
`web/src/web_ingest.c`, each read at this commit.

| Consumer | Behaviour | Effect of sloth-rf's records arriving on the same feed |
|---|---|---|
| `web/src/web_rtl433.c`, `sh_apply()` (187) | A `sensor_health` without `rtl433_state` **clears** the block (`memset(&a->sh, 0, …)`). | sloth-wifi's `sensor_health` blanks the rtl_433 tab's health every tick. |
| `web/src/web_gnss.c`, `loc_apply()` (242) | A `sensor_health` without `loc_lat` / `loc_lon` / `loc_src` **clears** the sensor position. | A daemon with no position clears the one the other reported. |
| `web/src/web_live.c`, `sensor_record()` (735) | Overwrites `cap_open`, `cap_running`, `mon_open`, `mon_running`, the interface names and the scope from every `sensor_health`; absent members read as 0 or `""`. | sloth-rf's record says "no capture, no monitor radio" for the host. |
| `web/src/web_live.c`, `web_live_sock_connected()` (92) | On every connect: `ninc = 0` (open incidents dropped), the monitor-radio set cleared, `conn_gen++`. | Each daemon's reconnect resets the other's open incidents and scope. |
| `web/src/web_ingest.c`, `ingest_main()` | On connect: `web_feed_reset()` and `web_metrics_stream()`. | The same, for the feed's line state and the metrics' per-stream tables. |
| `web/src/web_ingest.h:117` to 118 | "Call before `web_ingest_start()`; the metrics are then the ingest thread's alone." `web_metrics_t` has no lock of its own; `web/src/web_rollup.h:68` names one ingest thread adding samples. | A second ingest thread feeding `g_metrics` breaks the single-writer contract. |
| `web/src/web_lure.c` (296), `web/src/web_sysstat.c` `health_apply()` | Take `jsonl_version` and `db_max_mb` from whichever `sensor_health` came last. | The version and the store limit flip between the two daemons' values. |
| `web/src/web_frrs.c` (579) | Takes `monitor_iface` / `capture_iface` from every `sensor_health`. | As for `web_live.c`. |

Consumers that already keep what they had when their block is absent,
and so are safe on a shared feed: `web/src/web_adsb.c` `sh_apply()`
(202), `web/src/web_aprs.c` `sh_apply()` (263), `web/src/web_gnss.c`
`sh_apply()` (207), `web/src/web_ble.c` `sh_apply()` (501).

### 6.3 The devices-table probe

`web/src/web_slothdb.c` refuses a file whose `devices` table lacks
sloth's required columns: the probe builds the column list from
`web_sdb_allow[]` rows for `"devices"` (1169 to 1177), checks them with
`table_cols(c->db, "devices", …)` (1180), and a failure is
`"no devices table with sloth's columns"` (1387). The row count it
reports is `SELECT count(*) FROM devices` (1425).

`sloth-rf.db` has the same DDL, so it passes the probe; its `devices`
table is empty, so "rows" reads 0 for a healthy file. The reader's
allow-list already names the RF tables (`adsb_aircraft`,
`adsb_sightings`, `aprs_stations`, `aprs_packets`, `gnss_fixes`,
`gnss_sightings`, `device_positions`, `sensor_positions`), all read
through the one handle today.

### 6.4 The fleet

`web/src/web_fleetshare.c` already classifies the RF alert kinds:
`ADSB_EMERGENCY` and the `GNSS_*` kinds are on the travel list (44, 45),
`SENSOR_UNDERVOLT` and `SENSOR_SOURCE_DOWN` on the withheld list (60).
The export reads through `web_fleet_src_t.sdb`, one database. rtl_433
has no export writer and the importer refuses its record. Nothing here
changes with the split (ADR 0009); what changes is that the rows the
export reads will sit in a second file.

---

## 7. Packaging (f)

- **Units** (`git ls-files packaging`): `sloth-sensor.service` with its
  drop-ins `sloth-sensor.service.d/bt-monitor.conf` and `gps.conf`,
  `slothweb.service`, `sloth-ble-scan.service`,
  `sloth-sdrsweep.{service,path,sysusers.conf}`, `sloth.sysusers.conf`;
  defaults `packaging/default/sloth`, `slothweb`, `sloth-sdrsweep`;
  tools `packaging/bin/sloth-migrate-sensor`, `sloth-monitor-up`. There
  is no `sloth-rf.service`.
- **`sloth-sensor.service`**: `User=sloth` (34),
  `EnvironmentFile=-/etc/default/sloth` (42), `StateDirectory=sloth`
  (47), `RuntimeDirectory=sloth` (49, mode 0750),
  `ExecStart=/usr/local/bin/sloth` (88) with
  `--db /var/lib/sloth/sloth.db` and
  `--data-socket unix:/run/sloth/sloth.sock`, then `$SLOTH_ARGS`;
  `RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET` (138). It is
  bound to the monitor radio's device unit (25, 26), so the whole
  process, RF readers included, stops when the radio is unplugged. The
  `gps.conf` drop-in carries the serial device and the `AF_INET` that
  gpsd needs, commented out.
- **`slothweb.service`**: `After=` and `Wants=sloth-sensor.service`
  (31, 32), `RuntimeDirectory=slothweb` (61),
  `ExecStart=/usr/local/bin/slothweb --socket unix:/run/sloth/sloth.sock
  --sloth-db /var/lib/sloth/sloth.db` (71 to 73),
  `ReadOnlyPaths=-/var/lib/sloth` (92). One socket, one database, one
  sensor unit, one read-only state directory.
- **The migrate tool's flag allow-list**
  (`packaging/bin/sloth-migrate-sensor`, the `case "$f"` at 260 to 309).
  The binary must be named `sloth` (`case "$(basename "$1")"`, 252 to
  255). Absorbed: `--headless`, `--no-discovery`, `--hop`; dropped:
  `--no-privdrop`; relocated: `--db`, `--pcap-dir`, `--report`,
  `--report-json`, `--snapshot-out`, `--baseline-in`, `--with-research`;
  `--data-socket` (unix, or tcp with `--data-socket-unix`); carried:
  `--bt-monitor`, `--my-ssid`, `--my-bssid`, `--site-label`, `--site`,
  `--known-mac`, `--iface`, `--db-interval-secs`, `--db-retain-days`,
  `--db-max-mb`, `--correlate-retain`. Anything else is refused (307 to 308).
  No RF flag is on the list: `grep -nE 'adsb|aprs|rtl433|--gps|--location'`
  on the script finds nothing. It reads the binary at
  `$ROOT$PREFIX/bin/sloth` (86) and the socket at
  `$ROOT/run/sloth/sloth.sock` (84).
- **Install** (`Makefile`): `TARGET = sloth` (425);
  `install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)` (1598).
- **Tests that pin `/usr/local/bin/sloth`**: `tests/test_unit_file.c`
  (221, 236, 334, 335; 607 asserts its absence from another unit),
  `tests/deploy/test_migrate_sensor.sh` (101, 104, a stub binary at that
  path), `tests/deploy/test_lab_tools.sh` (97, a fake `cmdline`). A
  rename without the symlink turns each of these red.

---

## 8. The slices (g)

From `gh issue list`, titles as filed.

| Slice | Issue | What |
|---|---|---|
| S0 | #211 | The tracking issue, [ADR 0010](adr/0010-wifi-rf-daemons.md), this page. |
| S1 | #212 | Build seam: source groups, run flag out of `capture.c`, poll stage table per app. No behaviour change. |
| S2 | #213 | The `sloth-rf` binary: readers, RF rules, own JSONL socket and database. Additive. **Landed 2026-11-15; §10.** |
| S3 | #214 | slothweb reads two daemons: `--rf-socket` and `--rf-db`. **Landed 2026-11-15; §11.** |
| S4 | #215 | Packaging: `sloth-rf.service` and `sloth-migrate-rf`. |
| S5 | #216 | Cutover: `sloth-wifi` rename, RF leaves the Wi-Fi daemon, JSONL 2.0.0. **Landed 2026-11-15; §12.** |
| S6 | #217 | Deploy both daemons: W9FJC, then beta-site. |

Which section each slice cuts: S1 is §5 and the stage table and source
list of §3 and §2.1; S2 is §2 and the rest of §3; S3 is §6; S4 is §7;
S5 is §4.3, the `sloth` name in §7 and the contract version.

---

## 9. Where the tree and #211 disagree

#211's "What the code looks like today" holds on every point it makes.
These are the places the grep found more than it says, or something it
does not decide.

1. **GNSS reaches Wi-Fi-side code in more than five places.** #211
   lists the location stamp, twin motion suppression, the evidence
   manifest, a pair of views and `device_positions`. The views are
   `src/views/alerts.c` and `src/views/iface.c`. Also there (§4.1): the
   `SYS_SRC_GNSS` row in `src/sys_status.c`, the GNSS row of
   `s->sensors[]` in `src/poll.c`, and `sensor_health`'s `gps_*` and
   `gnss_*` members beside the `loc_*` ones #211's table does name.
   Whether sloth-wifi keeps reporting a GNSS source row and the `gps_*`
   / `gnss_*` health members, or only `loc_*`, is not stated.
   Ruled 2026-11-15: sloth-wifi keeps the source row, the sensor row
   and the `gps_*` / `gnss_*` members (ADR 0010).
2. **`sensor_positions` is in neither column.** `position_track.c`
   writes it with `device_positions` from one fix; #211 assigns
   `device_positions` to sloth-wifi and the `gnss_*` tables to sloth-rf.
   Ruled 2026-11-15: both daemons write it, each to its own database
   (ADR 0010).
3. **`SENSOR_UNDERVOLT` is host state.** `rule_sensor_undervolt` reads
   the host's supply flags from `sys_status_get()`, not a source. #211
   gives sloth-rf both `SENSOR_*` kinds "for its own sources" and
   sloth-wifi "everything else"; on a host running both, whether one or
   both report an undervolt is not stated. Ruled 2026-11-15: sloth-wifi
   only (ADR 0010).
4. **The registries are shared numbering, not only shared storage.**
   `sensor_kind_t` and `SYS_SRC_*` are persisted ids (§3.1). Two
   daemons each emitting `sensor` and `source_status` records with
   their own subset is a contract question for the 2.0.0 stream that
   #211 does not spell out.
5. **slothweb breaks in more places than the four named.** #211 names
   the rtl_433 tab, the sensor position, the metrics writer and open
   incidents; all four are confirmed (§6.2). `web_live.c`'s capture and
   monitor state, `web_frrs.c`'s interface names, `web_lure.c`'s stream
   version and `web_sysstat.c`'s store limit are overwritten the same
   way.
6. **A Wi-Fi-side view reads ADS-B.** The interface strip's `adsb`
   token (`src/views/iface.c:548`) is not the ADS-B view and is not
   mentioned; it has to go at cutover with the view.
7. **The migrate tool refuses every RF flag today.** A legacy unit with
   `--gps`, `--location`, `--adsb`, `--aprs` or `--rtl433` in its
   `ExecStart` is refused by `sloth-migrate-sensor` (§7). #211's S4
   names a new `sloth-migrate-rf`; it does not say the existing tool
   has this gap.
8. **`sloth-sensor.service` is bound to the monitor radio.** The RF
   readers stop with it today (§7). Not a disagreement, but the
   strongest packaging argument for the split and absent from #211.

---

## 10. What S2 cut (#213)

`sloth-rf` is three objects of its own and `libsloth_core.a`. Linking
the roots it needs - the three poll files, the four readers, the data
socket, the privilege drop, `tune` - against the archive as it stood
after S1 pulled 159 members and libpcap, because the services §3 calls
"once per process" each named the capture. The table is every
dependency that had to go, with the symbol that carried it (from `nm`
on the archive), in the order the link showed them. After: 49 members
in the default configuration (measured on the committed link: the
archive members that define a global symbol the binary defines), and
`DT_NEEDED` of libm, libsqlite3 and libc. The first count published
here, 46, was taken before `gnss_flags.o`, `rf_flags.o` and
`daemon_start.o` joined the link. With `--victron` (which reached
`main` while this slice was in review, and is wired into sloth-rf
through `rf_flags.o` and `jsonl_rf.o`) the link is 51: `victron.o` and
`victron_reader.o`, a parser and a file tailer that name no capture
module, so the gate below passes unchanged.

| Shared object | Pulled, through | Cut |
|---|---|---|
| `engine.o` | `rules_table.o` (`g_alert_rules`, `g_alert_rule_count`), and through its 93 rows every rule file and every module a rule reads | The table is data the daemon selects: `alert_rule_table_t`, `alerts_set_table()` (`src/alerts/rules.h`). `g_alert_rules` / `g_alert_rule_count` are now the selected table's rows, defined in `engine.c`. `sloth`: `g_alert_table_sloth`, the same 93 rows in the same order. sloth-rf: `g_alert_table_rf` (`src/alerts/rules_table_rf.c`). |
| `engine.o` | `rules_wired.o`, `rules_twin.o` (`rules_wired_forget`, `rules_twin_forget`, called from `alerts_clear()`) | The `*_forget()` list is the table's. |
| `engine.o` | `alert_pcap.o`, `evidence_export.o` (`alert_pcap_dump`, `evidence_export_pcap_unique`, …), and through them `eapol_log.o` and the evidence ring | The two exporters are the table's (`alert_exporter_t`); sloth-rf's table names none. |
| `jsonl_core.o` (the alert record) | `rules_twin.o` (`twin_class_label`) | The four-word label moved to `engine.c`, beside `alert_type_name()`. This shifted `rules_twin.c` by ten lines; the 20 assessments citing it were repointed. |
| `jsonl.o` | nearly every capture module: `capture.o`, `probe.o`, `ble_hci.o`, `bt_stream.o`, `beacon_snoop.o`, `eapol_log.o`, `alert_pcap.o`, `procs.o`, … (any reference to `jsonl.o` linked all of it) | Three files (`src/jsonl_internal.h`): `jsonl_core.c`, `jsonl_rf.c`, and `jsonl.c` for the capture's records. `sensor_health` is written in blocks so both daemons' records come from the same functions. |
| `poll_core.o` | `jsonl.o` (`jsonl_emit_connections`, `jsonl_emit_twin_episodes`, `jsonl_emit_state_snapshots` in `poll_st_jsonl()`) | `poll_st_jsonl()` moved to `src/poll.c`; sloth-rf's stage is `poll_st_jsonl_rf()`. |
| `poll_core.o` | `persist_health.o`, and through it `alert_pcap.o` and `eapol_log.o` (`alert_pcap_failures`, `eapol_export_failures`) | `persist_health_poll()` moved from `health_host` to `src/poll.c`'s `health_capture`. Same phase; the counts move later in the tick. |
| `sys_status.o` | `capture.o` (`capture_exit_name`), `bt_stream.o` (`bt_cap_state_name`), `beacon_snoop.o` (`beacon_recall_stat`) | The four capture rows are `src/sys_status_capture.c` and the recall sample a function pointer, both handed over by `sys_status_set_capture_side()`. Unregistered, the rows are unnamed: not written, not counted, not judged. |
| `sys_status.o` | `g_platform`, defined in `src/platform/linux.c` with the nl80211 backend | sloth-rf defines its own vtable, `src/rf/platform_rf.c`: `sys_read` and `sys_list`, every other slot NULL. |
| `sensor_health.o` | `dns.o` (`dns_resolver_stats` in `sh_mem_sample()`), the resolver | `sh_set_resolver_calls_fn()`; unregistered, `resolver_calls` is -1. |
| `db.o` | `libver.o`, and through `libver_pcap()` libpcap itself (`pcap_lib_version`) | `libver_pcap()` and `libver_format()` are `src/libver_pcap.c`; `libver_format_libs()` takes the libpcap word. |

`sloth` hands the first, third and the two `sys_status` / `sensor_health`
parts over in one call, `capture_side_install()` (`src/capture_side.c`).

What was **not** cut, and is linked into sloth-rf: `wifi_assess.o`
(`alerts_update()` still calls `wifi_downgrade_update()`, a pass over
`s->beacon_aps` that calls nothing; `tests/test_alert_rules.c` pins the
call's place in the function), `attack_hw.o` and `wifi_oui_attacker.o`
(the alert record formats the hardware verdict), `wired_attach.o` (a
label), `ownership.o` and `presence.o` (`db.o`). None opens, parses or
captures anything; they are tables and labels over state this daemon
never fills. `rules_sensor.o` carries `rule_sensor_undervolt()` beside
`rule_sensor_source_down()`; it is linked and not in sloth-rf's table.

The Makefile's `check_rf_no_capture` holds the result on every link
([[architecture]], Build layout), and was seen to fail both ways: with a
call into `bt_stream.c` added to `src/jsonl_rf.c` (the definitions
list), and with `libver_format()` used there and `-lpcap` put back on
the link line (the imports list).

The gate works per archive member, so a name guards only the member
that defines it. The first list named `linux_wifi_*` and `linux_get_*`
for the platform backend and five decoders for 802.11; review found
that `linux_tcpdiag.o` (the INET_DIAG socket), `linux_neigh.o`
(rtnetlink), `discovery.o` (the mDNS advertisement) and seven frame
decoders in files of their own define none of those names and need
none of them, so a call from a shared file would have linked each with
the gate green. The lists now name those members, a third list holds
whole families by pattern (`linux_*`, `dot11_*`, `*_observe_frame`,
`*_parse_frame`, `bt_*`, `ble_*`, `btle_*`, `evidence_*`, `eapol_*`,
`discovery_*`, `view_*`, `tui_*`), and the imports list refuses the
forward resolver and the calls a netlink or raw-socket module is made
of (`sendto`, `sendmsg`, `recv*`, `ioctl`, `if_nametoindex`). Seen red,
each with one reference added to `src/rf/platform_rf.c`:
`linux_tcpdiag_fill` and `linux_neigh_parse` (imports: `recv`,
`if_indextoname`), `discovery_unpublish` and `ctrl_observe_frame`
(definitions), `radiotap_parse` (definitions), `getaddrinfo` and
`sendto` (imports). The gate does not say no file about 802.11 is
linked: the members in the paragraph above are.

Rulings applied: both daemons write `sensor_positions` (the
`positions` stage is in `g_poll_rf`; `device_positions` stays empty
there because no stage of that table builds a device);
`SENSOR_UNDERVOLT` is not in `g_alert_table_rf`.

Left for later slices: slothweb does not read sloth-rf (S3, since
landed: §11); nothing is
installed and there is no unit (S4); `sloth` still takes the RF flags,
so a host must not point both at one serial GPS (S5). Two things S2
found that no slice names yet: `agents/risk_score.sh` scores deletions
in `src/jsonl.c` and names it as the forensic-output path, and does
not know `src/jsonl_core.c` or `src/jsonl_rf.c`; and the readers'
messages and the shared flag checks say `sloth:` in sloth-rf, which is
right while they are one copy and wants a decision at cutover.

---

## 11. What S3 cut (#214)

slothweb reads sloth-rf beside sloth, behind `--rf-socket` and
`--rf-db`; with neither it is §6's single-source program, unchanged.
The design is [[slothweb]] § Two daemons. Against §6.2's table, row by
row:

| §6.2 hazard | What S3 did |
|---|---|
| `web_rtl433.c` `sh_apply()` clears on a `sensor_health` without the block | With `--rf-socket` sloth's stream never reaches it (`split_line()`); the function is unchanged, so one stream still clears it as before. |
| `web_gnss.c` `loc_apply()` clears the position | sloth-rf's stream writes the served slot; sloth's `sensor_health` writes a fallback slot (`web_gnss_record_fallback()`), read only while the served one is empty. |
| `web_live.c` `sensor_record()` overwrites capture and monitor state | Each stream has its own `web_live_t`; the RF one keeps liveness, version and daemon word only (`WEB_LIVE_RF`). |
| `web_live_sock_connected()` drops open incidents and the radio set | Per state: a reconnect clears its own. The incident readers and the open counts read both (`web_live_set_peer()`). |
| `ingest_main()` resets the feed and `web_metrics_stream()` | Per feed; the RF feed has no metrics. |
| `web_metrics_t` single writer | Kept: the RF thread calls `web_metrics_rf_sample()`, which touches only the rollup (its own mutex). |
| `web_lure.c`, `web_sysstat.c` take `jsonl_version` / `db_max_mb` from the last `sensor_health` | The lures are sloth's stream's alone; `web_sys_record_from()` gives each daemon's `db_max_mb` to its own store. |
| `web_frrs.c` takes the interface names | sloth's stream's alone. |

And two it did not name: `sys_status` and the `source_status` rows,
which both daemons write (`web_sys_record_from()`: the host batch is
sloth's once sloth has reported, the rows are owned by name), and
`sensor_health`'s `daemon`, used as a second guard on each socket.

§6.1's single pointers gained a sibling where an RF table is read:
`web_m4_t.sdb_rf`, `web_fleet_src_t.rf`. `web_anomaly.h`'s and
`web_sqlbox.h`'s stay sloth.db's. §6.3 holds: sloth-rf.db passes the
`devices` probe with an empty table, and `/api/health` `rf_db`
therefore reports no row count. §6.4 holds: the allow-list and the
writers are untouched; the export's aircraft and GNSS incidents are
read from the second file, its device, AP and alert lines from the
first.

Left for later: the alert history's merge across two databases (the
`alerts` table readers in `web_alertdb.c`, `web_slothdb.c`'s
`web_sdb_alerts_*`, the export's `alert` lines) and sloth-rf's records
on the ticker. Nothing is installed: the unit that passes the two
flags is S4.

---

## 12. What S5 cut (#216), the cutover

One binary's worth of RF left the Wi-Fi daemon. By the owner's rulings
of 2026-11-15:

| | Left `sloth-wifi` (now `sloth-rf`'s alone) | Stayed in `sloth-wifi` |
|---|---|---|
| Flags | `--adsb`, `--aprs`, `--aprs-freq`, `--aprs-silent-hours`, `--rtl433`, `--victron`: refused, exit 2 | `--gps`, `--gps-allow-remote`, `--gps-baud`, `--location`, and every capture flag |
| Threads | the ADS-B, APRS, rtl_433 and Victron readers | the GNSS reader |
| Poll stages | `health_rf`, `sensors_rf` | `health_gnss`, `sensors_gnss`, `positions`, every capture stage |
| Records | `gnss_fix`, `gnss_sky`, `gnss_sat`, `adsb_aircraft`, `aprs_station`, `aprs_packet`, `rtl433_device`, `victron_device` | every capture record; `sensor`, `sensor_health`, `sys_status`, `source_status` about itself |
| `sensor_health` | the `adsb_*`, `aprs_*`, `rtl433_*`, `victron_*` blocks and their part of the change signature | `gps_*`, `gnss_*`, `loc_*`, and all of the capture's |
| `source_status` rows | `adsb`, `aprs`, `rtl433`, `victron` | `capture`, `monitor`, `btmon`, `btcap`, `gnss` |
| Sensor registry rows | ADS-B, APRS, rtl_433, Victron | the radios, the receiver |
| Rules | `GNSS_JAMMING`, `GNSS_SPOOF_SUSPECT`, `GNSS_TIME_JUMP`, `GNSS_POSITION_JUMP`, `ADSB_EMERGENCY` | everything else, `SENSOR_UNDERVOLT`, and `SENSOR_SOURCE_DOWN` for its five rows |
| Tables written | `gnss_fixes`, `gnss_sightings`, `adsb_*`, `aprs_*`, `victron_*` | `device_positions`, `sensor_positions`, every capture table |
| Terminal | the ADS-B view (`^`), the interface strip's `adsb` token: deleted | the GNSS view (`#`), the strip's `gps` token |
| Location | | the `loc` stamp on alerts and devices, the twin motion suppression |

`sloth-rf` did not change, apart from the version string: its poll
table, its rule table, its records and its messages are what they
were. The same canned decoder files through the parent's `sloth-rf`
and this one gave the same set of records (types, members and
identities) and the same database rows, `jsonl_version` apart.

**The seams.** `g_poll_wifi` and `g_alert_table_wifi` existed or
followed directly; three shared files still named the decoders, found
by `nm` on the archive (the members of the base group with an
undefined symbol an RF member defines), and each takes that part as
data now, the way §10's capture side does:

| Shared object | Pulled, through | Cut |
|---|---|---|
| `sys_status.o` | `adsb.o`, `aprs.o`, `rtl433.o`, `victron.o` (`*_state_name()` in `fill_sources()`) | the four rows are `src/sys_status_rf.c`, registered by `sys_status_set_rf_side()`. Unregistered, unnamed: not written, not counted, not judged. `track_age()` became `sys_status_track_age()` for it |
| `db.o` | `adsb.o` (`adsb_row_sig()`, `adsb_emergency_name()` in `write_adsb()`) | `db_set_rf_side()` hands over both functions and is also the switch for `write_gnss()`, `write_adsb()`, `write_aprs()`, `write_victron()`: sloth-wifi holds a fix and a sky and must still write no `gnss_*` row |
| `jsonl.o` | `jsonl_rf.o` (five `jsonl_emit_*`, five `jsonl_sh_*`, `jsonl_sh_rf_sig`) | the calls are gone from `jsonl_emit_state_snapshots()` and `jsonl_emit_sensor_health()` |
| `poll.o` | `poll_rf.o` (`poll_st_health_rf`, `poll_st_sensors_rf`) | `g_poll_sloth` deleted; `src/main.c` passes `g_poll_wifi` |
| `rules_table.o` | `rules_gnss.o`, `rules_adsb.o` (`rule_gnss_*` and `rule_adsb_emergency`, and their `*_forget()`) | the rows are out of `g_alert_table_wifi` |
| `iface.o`, `tui.o`, `main.o` | `adsb.o`, the ADS-B view, the readers, `rf_flags.o` | the token, the view and the flags are gone; the refusal is `src/rf_moved.c`, which names no decoder |

sloth-rf hands its side over in `rf_side_install()` (`src/rf_side.c`),
the mirror of `capture_side_install()`.

**The gate.** `check_wifi_no_rf` (`Makefile`) runs `nm` on `sloth-wifi`
and refuses any definition, file-local included, of the decoders'
families, their rules and the receiver's, the RF records and blocks,
and sloth-rf's stages, tables and side. Seen to fail with a call to
`adsb_state_name()` added to `src/main.c` (it named `adsb_alt_band`,
`adsb_doc_parse`, …: the whole member came in), and with a call to
`rules_gnss_forget()` (it named the four `rule_gnss_*`).
`tests/test_rf_build.c` holds each pattern to a definition and to not
matching what sloth-wifi keeps.

**Numbering.** `alert_type_t`, `sensor_kind_t` and `sys_src_id_t` did
not change. Both daemons use one of each, the numbers are persisted,
and a row a daemon does not have is absent. The views list lost its
last row, so `view_t` did not move either.

**Per-binary counts.** `make docs-counts` writes `views` (sloth-wifi's),
`rules` (the kinds in the list), `rules-wifi` and `rules-rf`;
`tests/test_docs_consistency.c :: test_counts_say_which_binary` holds
them to the build.

**Packaging.** `TARGET` is `sloth-wifi`; `sloth` is a symlink target of
`all` and is installed beside the binary. `sloth-sensor.service` runs
`/usr/local/bin/sloth-wifi`. `make install-service` warns when the
host's `/etc/default/sloth` still passes a decoder flag
([[deployment]] §11.4).

**slothweb.** It reads 1.x and 2.x and says which; `rf_stream` on
`/api/health` and the four RF tabs' answers ([[slothweb]] § The RF
stream's state).

**The stream.** `SLOTH_JSONL_VERSION` is `2.0.0` in both daemons;
[[jsonl-schema]] § 1.x to 2.0.0 is the migration table. The replay
golden changed by the four `not_configured` rows, `sources` 9 to 5 and
the version.

Left: S6 (#217), deploying both daemons. Two things S5 found that no
slice names: the shared flag checks and the readers still say `sloth:`
in sloth-rf (§10's note; held unchanged here, wants a ruling); and
`sloth-migrate-sensor` still refuses a legacy unit that carries `--gps`
or `--location`, which are sloth-wifi's flags (§9 item 7's gap, for
those two).

---

## Related pages

- [ADR 0010 — two daemons, one repository](adr/0010-wifi-rf-daemons.md) — the decision this page measures for.
- [[architecture-split]] — the other inventory: the sensor, the dashboard and the intelligence tables (#184).
- [[architecture]] — the system map.
- [ADR index](adr/README.md)
- [[jsonl-schema]] — the stream whose contract version moves at cutover.
- [[sqlite-schema]] — the DDL both stores will share.
- [[deployment]] — the units and the migrate tool.
- [[gnss]], [[adsb]], [[aprs]], [[rtl433]], [[sdr-sweep]] — the modules.
