# sloth v1.8.6 — where the sensor is, and three non-IP sensor families

Two weeks in one patch: no release was cut on 2026-11-02, so this tag
carries **223 commits** (163 of them substantive) since v1.8.5 and
**15 closed issues**. Alert types go **90 → 95**; `VIEW_COUNT` goes
**36 → 38** (the `[#]` GNSS and `[^]` ADS-B views). Suite went
**33398 → 44132 assertions**.

Two things carry it. The first is **position**: sloth now knows where it
is, from `--location` or a `--gps` receiver, and stamps every alert
incident, capture manifest and `--db` row with it. The second is the
widening of the `#26` roadmap into **three non-IP sensor families that
sloth reads but never drives** — a GNSS receiver (`--gps`), a local
ADS-B decoder's `aircraft.json` (`--adsb`), and a local Dire Wolf APRS
packet log (`--aprs`). Each is a file or a socket an already-running
decoder writes; sloth opens no SDR, tunes no radio and sends no network
traffic for any of them.

Alongside those: slothweb's visual system reached V0–V4 with a Radar
dome (#171), the live sensor moved off the build tree (#153), the
sensor stopped accusing its own radio (#183), alert pcaps gained
retention (#166), and the `alerts` table stopped growing a row per
evict-and-refire (#170).

---

## ⚠️ Upgrade notes — read before upgrading

This is a patch tag by the owner's scheme, but five operator-visible
things changed. **The schema bump and the pcap sweep are the two that
can change what a working v1.8.5 invocation does.**

**1. `DB_SCHEMA_VERSION` 7 → 13, and the upgrade is one-way.** An
existing v1–v12 `--db` file is migrated forward automatically inside
`db_open()`, one version at a time, each step in its own transaction;
no step rewrites a recorded value. **But a file this build has migrated
to v13 is refused by v1.8.5 and older**, which refuse any file from a
newer build. If you may roll back, copy the `--db` file before the
first v1.8.6 run. The six steps:

| Step | Change |
|---|---|
| v7 → v8 | `alerts` gained `reopens`, `incident_id`, `incident_count`, `incident_first_seen` (#170) |
| v8 → v9 | `alerts` gained the location stamp (`lat`, `lon`, `alt_m`, `acc_m`, `loc_src`, `loc_ts`) |
| v9 → v10 | `gnss_fixes`, `gnss_sightings` |
| v10 → v11 | `alert_incidents` (#175) |
| v11 → v12 | `adsb_aircraft`, `adsb_sightings` (#26) |
| v12 → v13 | `aprs_stations`, `aprs_packets` |

The last four steps add their tables through the unconditional schema,
so the migration itself only stamps the version.

**2. `--pcap-dir` now deletes old alert pcaps (#166).**
`pcap.retain_days` defaults to **14**: files sloth wrote under
`--pcap-dir` are deleted once older than that, swept at startup and
hourly in bounded steps. Only names sloth wrote are touched, regular
files only, nothing followed. Set `--tune pcap.retain_days=0` to keep
them forever — the pre-v1.8.6 behaviour. `sensor_health` reports
`pcap_retain_days`, `pcap_swept` and `pcap_sweep_errors`.
`--pcap-dir` and `--eapol-dir` naming one directory now **exits 2**
(checked by dev/ino).

**3. slothweb withholds evidence pcaps by default.** The alert page
lists the packets behind a finding but will not serve them unless
slothweb is given `--web-serve-evidence-pcap`; with
`--web-allow-remote` that flag exits `2` unless written
`--web-serve-evidence-pcap=remote`. `--eapol-dir` can hold PMKID and
handshake material, which is why the default is withheld rather than
listed-and-served.

**4. The live sensor belongs outside the build tree (#153).** A bare
`--data-socket` is a Unix socket, `slothweb` runs as its own unit, and
`packaging/bin/sloth-migrate-sensor` moves an old build-tree unit
across (`--dry-run`, `--data-socket-unix`, `--with-slothweb`).
`make install-service` now writes `/etc/default/sloth` **only where
absent**, so a reinstall no longer overwrites operator settings.

**5. Alert counts changed meaning for eight rules (#173).** The shape
is unchanged, but `ATTACK_TOOL_UA`, `DGA_DOMAIN`, `WPA_DOWNGRADE`,
`MGMT_FUZZ`, `FRAG_PLAINTEXT`, `SMB1_USE`, `PM_FORGE` and
`CAM_SETUP_OUI` no longer count an observation per poll tick, so a
count from a v1.8.5 log and one from this build are not comparable for
those types. The engine's observation semantics are unchanged — each
rule stopped moving a detail value that the evidence had not moved:
`ATTACK_TOOL_UA` measured 3.1e9 fires on two keys. Details that were
running counters are now bands (`WPA_DOWNGRADE` 30s+/5m+/1h+/1d+,
`MGMT_FUZZ` defects per 100 frames, `FRAG_PLAINTEXT` and `SMB1_USE` by
decade), and `PM_FORGE` gained the 900 s recency bound `QUEUE_EVICT`
already had. Every assessment's `count_semantics` line says which a
rule has.

**JSONL remains additive only.** Every field named below is new; no
record changed shape, and a consumer ignoring them sees what it saw
before. No CLI flag was renamed — the flags below are additions.

---

## Where the sensor is

**`--location LAT,LON[,ALT]`** — a fixed position, WGS84 decimal
degrees and metres AMSL. Out-of-range latitude, longitude or altitude
exits 2. Allowed with `--replay`: the files were captured somewhere.

**`--gps SPEC`** — a receiver. `/dev/ttyXXX` is NMEA 0183 GGA/RMC/GSA,
checksum verified, opened `O_RDONLY` **before** the privilege drop
(the drop clears supplementary groups and the device is usually group
`dialout`) and read on a worker after it; `gpsd://[HOST[:PORT]]` is
gpsd's JSON stream, dialled after the drop, and sloth sends it exactly
one line (`?WATCH`) and then only reads. A fix younger than
`gps.max_fix_age_s` (30 s) wins over `--location`; fix qualities 6
(dead reckoning), 7 (manual) and 8 (simulation) never stamp. Numeric
addresses only — no resolver — and a non-loopback gpsd needs
`--gps-allow-remote`, which `--strict` refuses regardless: a lock
another flag can override is not a lock. `--gps-baud` takes the six
standard speeds.

**The stamp.** Every new alert incident carries `loc` on the `alert`
and `alert.*` JSONL records, `lat`/`lon`/`alt_m`/`loc_src`/`loc_ts` on
the `--db` `alerts` row, and `loc` in the evidence manifests. `acc_m`
is an estimate (HDOP × 5 m, or gpsd's `eph`) and is omitted when the
source gave none. A moving sensor with `--db` also records
`device_positions` and `sensor_positions`. slothweb shows it with
GeoJSON and GPX export.

**The `[#]` GNSS view** and the `gnss_fix` / `gnss_sky` / `gnss_sat`
change-only records: satellites in view and used, C/N0 mean/max/SD,
the five DOPs, clock offset against the host wall clock (coarse, no
PPS), the u-blox jamming indicator, and a per-satellite trail across
the sky. The used count is signed as a band and the offset band has
hysteresis, so a flapping receiver does not flap the record.

## Four GNSS rules

Each threshold is argued from `research/gnss/`; where the research says
no published threshold exists, the default is the conservative one and
the assessment's `tuning` row says so. Twelve `gnss.*` knobs,
`src/alerts/rules_gnss.c`.

**`GNSS_JAMMING`** (T1464) — two paths. Path (a) is a collapse: the
tracked-satellite median C/N0 falls `gnss.jam_cn0_drop_db` (10 dB)
under a 60 s baseline while the sky still lists satellites and the used
set falls by two. **Tracked only, and a median**, because gpsd lists
untracked satellites at ss 0 and attenuation by an obstruction is
direction-dependent: the first version averaged the ss-0 rows in, and
four of ten satellites lost behind a building read as a 12 dB collapse.
Path (b) is a held `jamInd` run. CRIT when the fix is lost, else WARN.
Sources: DHS 2017 (*interference and jamming differ only in intent*,
Development Strategies 7 and 8), `research/gnss/jamming-detection.md`
on what a u-blox 7 behind gpsd 3.27 actually exposes (`jamInd` only;
`agcCnt` and ITFM `jammingState` are logged and dropped), Mobile
ATT&CK T1464. The detail says *"interference or jamming: the receiver
cannot tell which (DHS 2017), nor locate the source"* — the mapping is
the observable, not a claim of intent.

**`GNSS_SPOOF_SUSPECT`** (no technique) — LOW on two heuristics, WARN
on three, never CRIT. `research/gnss/spoofing-detection.md` calls every
heuristic weak alone and says nothing short of cryptographic
authentication stops a careful spoofer, so the rule reports a
suspicion.

**`GNSS_TIME_JUMP`** and **`GNSS_POSITION_JUMP`** (no technique) — WARN
each: a confirmed multi-second step of the receiver's clock (leap and
rollover tolerated) and an unphysical move measured against the
receiver's own TPV speed and its error. Not CRIT, because faults and
multipath produce both. Basis
`research/gnss/time-and-position-integrity.md`.

All three empty techniques are the second exemption form: a real basis
with no ATT&CK technique that names the behaviour.

## ADS-B (#26, #186)

**`--adsb SPEC`** tails the `aircraft.json` a local, already-running
decoder (readsb, dump1090-fa) writes. Absolute path or `file:///path`,
reopened about once a second because the decoder replaces it by rename,
read-only on a worker started after the privilege drop, a regular file
of at most 2 MiB. A missing file is a **state, not a refusal**: the
`adsb` sensor and `sensor_health.adsb_state` read `error` until it
appears. `sbs://` and `beast://` exit 2 ("not yet supported"). Rows
already stale at startup are dropped rather than presented as current.

**The `[^]` ADS-B view** and slothweb's aircraft page draw the table
with history; satellites and aircraft seen are kept across runs.

**`ADSB_EMERGENCY`** (no technique, flag only) — squawk exactly 7500,
7600 or 7700, or an emergency/priority status present and not `none`.
LOW on first sight, WARN once the condition has held
`adsb.emerg_hold_s` (10 s) of the aircraft's own messages, **never
CRIT**. A pass where the source is not `live` keeps every listed row's
hold, so a one-poll read error cannot drop an open WARN back to LOW.
Sources: SERA.13005 (7700 emergency, 7600 radio failure, 7500 unlawful
interference), readsb's `README-json.md` status words,
`research/adsb/emergency-squawks.md`; ADS-B has no entity
authentication, and Schafer et al. 2013 §3.2 demonstrate the False
Alarm Attack with commodity SDRs. The detail says so: *"flag only:
ADS-B is unauthenticated and a false alarm can be injected; sloth
cannot verify it and takes no action."*

## APRS (#26)

**`--aprs SPEC`** tails the CSV packet log Dire Wolf writes
(`direwolf -L FILE`), one line per decoded packet. The first look
starts at the file's **end** — its history is not replayed, because
`sloth.db` already holds what an earlier run read — a new file at the
path (rotation) is read from its start and a shrunken one (logrotate
`copytruncate`) from 0; at most 256 KiB a poll. A missing file is the
`waiting` state, since Dire Wolf creates it with its first packet.
Emits `aprs_packet` (one per packet), the change-only `aprs_station`,
`aprs_*` in `sensor_health`, and with `--db` the `aprs_stations` and
`aprs_packets` tables. sloth never touches the radio, the SDR or Dire
Wolf.

## slothweb

**The visual system, V0–V4 (#171).** A glyph layer — G1/G5/G6 as mark
lists plus painters — then four views built on it: every Overview
number against its own series and band (V1), how near each emitter is
in sloth's own words (V2), the air picture against each channel's own
normal (V3), and the attack chain as one event with flows as a matrix
(V4). Backed by new `live.*`, `records.rate` and `sensor.drops` rollup
series.

**The Radar tab** — every radio heard on one manipulable half-dome,
full-screen as its own page: Wi-Fi and BLE on the north axis with
labels that never overlap, the 10 most recent devices labelled and the
rest on hover, APRS objects as their own marks with a window setting
and 24 h trails.

**Pages and plumbing** — the Alerts page, an alert's own page with its
capture, evidence and assessment, and tile drill-downs; the BLE view at
parity with the TUI's `[*]`; alert triage with history folding, the
FRRS emitter record and the TACDB tab; a vendor research KB of 277
cited entries with FCC grantee codes, held to read-only and to cited
sources; `/api/bundle` copy-JSON on every detail view, scoped to the
page and the click; sortable tables with resizable columns that move;
settings kept in the browser between launches; a Monitor / Hybrid /
Local capture-path switch; a system map on the architecture page; and
the event stream closed when the page is left.

## Detectors and data

- **The sensor's own radio (#183).** Every MAC the `iface` records
  carry — Ethernet, the managed card, the monitor radio — is rostered
  automatically as the sensor's own, needs no `--known-mac`, and
  exonerates the same way; the exoneration ages like the claim.
  `PM_FORGE`, `RECURRING_TRANSIT` and `BLOCKACK_ATTACK` are tagged and
  demoted when the party is the sensor's own radio. The issue is still
  open: `MY_NETWORK_RECON` and `ATTACK_PATH` are its remaining items.
- **`KARMA_SPAM` (#187)** — the IE-fingerprint collapse is judged in
  the alert, not only in the score.
- **Bad-FCS frames (#178)** — per-type parsers are gated on the
  monitor stream's FCS result, so a corrupted SSID is no longer
  recorded as a real name on a legitimate BSSID.
- **`FRAG_EAPOL_RELAY` on Wi-Fi 7 MLO (#180)** — the FragAttacks rules
  treat the AP MLD MAC as the AP; the EAPOL SA is not the link BSSID.
- **Captive-portal grading (#169)** — findings are graded, evil-twin
  kit pages fingerprinted, and grades tied to the event's client.
- **Distance from RSSI (#169)** — a data point on Wi-Fi and BLE rows,
  held against noise, with the receive antenna's gain
  (`rf.rx_gain_db_wifi`) subtracted before the estimate and a
  `--my-bssid` calibration superseding it.
- **IPv6 neighbours (#176)** — the kernel's neighbour table is read
  into the sensor's table; `rf.rssi.ble` got a key class of its own
  (#177).
- **Alert incidents (#170, #175)** — one `sloth.db` row per incident
  beside the finding row, one `alerts` row per finding across reopens,
  old files compacted on a copy by the new offline
  `--db-compact-alerts SRC DST` (immutable read of `SRC`, refuses a
  non-empty `SRC-wal`). History reads a finding's peak severity and
  count across incidents.
- **Alert pages and notes (#179, #181)** — the alert page leads with
  observations rather than a count, and an over-long triage note is
  refused visibly instead of dropped silently.
- **Alert assessments (#174)** — the last 18 alert types assessed, with
  the MLO literature search recorded; `rule_file` lines repointed after
  wave 1 met wave 2. Every one of the 95 types now has an assessment.
- **BLE rotation hints (#156)** — the flood lane is held to per-address
  hints, three rotations linked, and `BLE_ADV_FLOOD` /
  `BLE_WATCHLIST` pinned unchanged by rotation.

## Architecture, build and repo

- **#185, contract freeze S0** — the coupling inventory, ADRs 1–7 and
  the pack schema v1 draft.
- **Test isolation** — a private run directory per test run and a leak
  guard, cleanup after an interrupted run and under a long `TMPDIR`.
- **`make gate` is one script** (`tools/gate.sh`), rebuilding
  generators per flag set.
- **`update-oui` no longer fetches** — the IEEE registry CSVs are
  committed and copied from `ieee-data` or a given directory.
- **`sloth-ble-scan`** is a passive-scan helper unit for
  `--bt-monitor`, with `--down`, `--delay` and a bounded bind wait;
  every HCI write routes through the gate and `AF_BLUETOOTH` stays
  opt-in.
- **Fixed** — the release-digit bound read (cppcheck), SSDP keyword
  compares bounded in slothweb's pcap decoder, every libpcap setter's
  result checked with a refused BPF filter reported, device names never
  joined on an empty address, `--bt-monitor` able to stop (non-blocking
  poll of the monitor channel), the Bluetooth SIG generator's tables
  freed and `qsort` skipped on a table no CSV filled, and the
  freq-to-channel disagreement (#167).
- **List views (#150)** — pages sized from the cursor to fit 100×33,
  clipping on list-view tables only, clip width counted per glyph and
  Twins' flags kept whole.
- **Docs** — `[[gnss]]`, `[[adsb]]`, `[[aprs]]`, `[[location]]` and
  `docs/views/adsb.md` added; wiki subdirectories publish to the flat
  GitHub wiki; antenna designs live under
  `docs/hardware/antenna`, one directory per revision; the Rev N
  fixture build guide is in the wiki.

## Known gaps

- **`ADSB_EMERGENCY` and the four GNSS rules have no firing data.**
  All five are `noise_verdict: not measured` — new rules, and the
  reference host has a clean 3D fix on 13 satellites and no emergency
  traffic in coverage.
- **The GNSS C/N0 path cannot tell jamming from attenuation.** An
  antenna fault, a cable, a tunnel or a garage reads the same; the
  slow-decline, keeps-its-solution, shrinking-list, partial-obstruction
  and empty-sky cases are excluded and tested, but the ambiguity is
  stated in the alert rather than hidden.
- **`jamInd` is uncalibrated** — the vendor says calibrate in place, so
  a receiver whose ordinary indicator sits high will fire path (b).
- **The clock offset is coarse.** No PPS, so it is the receiver's
  reported time minus the host wall clock at receipt.
- **#171 is open** — V0–V4 landed; the visual system is not finished.
- **`sbs://` and `beast://` are unimplemented** for `--adsb`, and
  refused rather than silently ignored.

---

Passive throughout. The GNSS receiver is opened read-only, the ADS-B
and APRS readers tail files another process writes, and nothing here
transmits, scans, or modifies kernel state — see
[`MISSION.md`](MISSION.md) §2.
