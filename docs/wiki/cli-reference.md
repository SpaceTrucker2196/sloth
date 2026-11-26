---
name: cli-reference
description: Complete command, flag, argument, keybinding and environment reference for the two sensor daemons, sloth-wifi (alias sloth) and sloth-rf, and for slothweb — the authoritative CLI page
type: reference
---

# CLI reference

**Summary**: Every command-line flag, its argument, default, and effect;
every runtime keybinding; the tab-bar status badges; the environment
variables; and exit codes. Two sensor binaries since the cutover (#216,
[ADR 0010](adr/0010-wifi-rf-daemons.md)): **`sloth-wifi`** (IP, 802.11,
BLE; `sloth` is a symlink to it and is the same program) and
**`sloth-rf`** (ADS-B, APRS, rtl_433, Victron, the GNSS records). Every
section down to "Exit codes" is `sloth-wifi`'s; `sloth-rf` has its own
section after it. Where this page says `sloth` it means `sloth-wifi`
under either name.
Source of truth is `print_usage()` and the argv loop in `src/main.c`, and
`include/sloth_views.def` / `handle_key()` for the keys. If this page and the
binary disagree, the binary is right — and this page is out of sync, which
is a bug ([[docs-drift-judge]], and the wiki-sync duty in `agents/AGENTS.md`).
The flag *list* and the view-key table are gated by `make test`
(`tests/test_docs_consistency.c`, suite "CLI surface vs. wiki reference"):
a long option the argv loop parses and this page does not backtick is a
red suite, and so is the reverse. The flag *descriptions* are not gated —
only that each flag and key is here.

**Sources**: `src/main.c` (`print_usage`, `main` argv loop, `handle_key`),
`src/rf/rf_args.c` and `src/rf/main.c` (sloth-rf), `src/gnss_flags.c`,
`src/daemon_start.c` (the flag checks both daemons call),
`src/rf_flags.c` (the decoder flags' checks, sloth-rf's),
`src/rf_moved.c` (sloth-wifi's refusal of them),
`tests/replay/rf_refusals.sh`,
`include/sloth_views.def` (expanded by `src/view_labels.c`),
`include/sloth.h`; `src/persist_health.c`
(`persist_badge`), `src/tui.c` (`draw_tabbar`, both front ends) and
`src/views/dashboard_bands.c` (`draw_persist_badge`) for the status
badges.

**Last updated**: 2026-11-25 (#244: `--questions PATH` in both daemons, the operator's site questions; `--report` and `--report-json` carry each question's answer, `questions` in the JSON, [[site-questions]]), 2026-11-25 (#249 review: `--sweep` refuses an unreadable baseline with exit `2` before the preflight, and exits `1` when the run did not start or a file was not written), 2026-11-25 (#249: `--sweep LABEL`, `--sweep-minutes N`, `--sweep-dir DIR`, a time-limited sweep of a room against the label's baseline, [[sweep-session]]), 2026-11-25 (#245 review ruling: `--value-period` refuses a standing condition, which never lapses), 2026-11-25 (#245: `--no-preliminary` and `--value-period KIND=SECS` in both daemons, the finding lifecycle: preliminary, confirmed, withdrawn, lapsed, [[alerts]] § Finding lifecycle), 2026-11-24 (#248: `--cue`, passive cueing: a finding of six fixed kinds lengthens the `--hop` dwell on its channel 4x for 120 s within limits, refused under `--strict`, ignored without `--hop`, [[passive-cueing]]; `suppress.cue_refused_per_min`, `SENSOR_SUPPRESSED`'s fourth signal), 2026-11-24 (#251 review: `--verify` lists each segment's head and calls `N` or more unchained lines after a segment's last chain record a break; the `--preflight` row names the evidence-directory at-rest check), 2026-11-24 (#251: `--jsonl-chain N`, a hash chain over the `-o` file in both daemons, and `--verify PATH`, which checks a chained file or an evidence directory and names the first break, exit 0 / 1 / 2, [[record-integrity]]; `--preflight` warns when `--pcap-dir` or `--eapol-dir` keeps captures past 7 days on a disk with no dm-crypt under it), 2026-11-24 (#250 review: `--to` includes the day or minute it names; `--interference-report` refuses a FILE that is `--db` or its `-wal` / `-shm` / `-journal`; `--handoff` prints no `--allow-active` or `--ble-rotation-hints` notice, as `--preflight` does not), 2026-11-24 (#250: `--handoff DIR`, the site handoff packet, and `--interference-report FILE` with `--from` / `--to`, one section per `RF_DEGRADED`, `RTS_FLOOD` or `GNSS_JAMMING` episode, both reading `--db` read-only, [[handoff]]), 2026-11-24 (#243: `--report` and `--report-json` carry what the designated site reveals, `exposure` in the JSON, [[exposure-report]]), 2026-11-23 (#246 review: `--report` and `--report-json` name the finding quality, `findings`, as `--help` does), 2026-11-23 (#247 review: the Synopsis names `--preflight [--json]`; under `--preflight` the `--allow-active` and `--ble-rotation-hints` notices are not printed, since nothing starts), 2026-11-23 (`--preflight` and `--json`, #247: check the set-up and exit 0 / 1 / 2, [[preflight]]), 2026-11-23 (`--report` / `--report-json` carry the collection coverage, #242 item 3), 2026-11-23 (`suppress.evict_per_min`, `suppress.drop_pct`, `suppress.drop_min`, `suppress.silent_intervals`, #242 item 4: `SENSOR_SUPPRESSED`'s thresholds), 2026-11-20 (`retention.random_repeat_s`, #239: the `--db` purge of random addresses that did not repeat, [[retention]] § 2b), 2026-11-18 (the startup trim keeps a decoder whose file was written within 10 min (`--adsb`) or 24 h (`--aprs`, `--rtl433`), or is dated ahead of the clock), 2026-11-18 (sloth-rf `--no-sdr-trim` and the startup trim it turns off: with no SDR on USB, a file `--adsb`, `--aprs` and `--rtl433` are not started and read `not_installed`; nothing left to read runs on idle so its rows say why), 2026-11-17 (`--df-iface NAME@X,Y`, `--df-origin X,Y`: [[direction-finding]] § Radios off the line), 2026-11-16 (`--monitor-iface` is repeatable: each further one, up to three, is another sensor radio, [[multi-radio-sensing]]), 2026-11-16 (`--df-iface`, `--df-origin`: [[direction-finding]]), 2026-11-16 (#185 item 4: `--print-schema` in both daemons, the `--db` DDL and `DB_SCHEMA_VERSION` as SQL, which `make contract` publishes as `schema.sql`), 2026-11-15 (#216, the cutover: the Wi-Fi binary is `sloth-wifi` with `sloth` a symlink to it; it refuses `--adsb`, `--aprs`, `--aprs-freq`, `--aprs-silent-hours`, `--rtl433` and `--victron` with exit 2 and one line naming `sloth-rf` and `sloth-migrate-rf`; the six rows moved to the sloth-rf table; the `^` ADS-B view key is gone), 2026-11-15 (#214: slothweb's `--rf-socket SPEC` and `--rf-db PATH`, sloth-rf's socket and database read beside sloth's; no sensor flag changed), 2026-11-15 ([[victron]]: sloth-rf's `source_status` gains the `victron` row, five not four; no flag changed), 2026-11-15 (#213, owner ruling: sloth-rf no longer takes `--jsonl`; its JSONL flag is `-o` / `--out` only, so both daemons take the same flags); 2026-11-15 (#213 review: sloth-rf's JSONL flag is documented as `-o` / `--out`, `sloth`'s spelling, with `--jsonl` as its own extra one; the bare `--data-socket` remedy names no port, since 8765 is `sloth`'s); 2026-11-15 (#213: the `sloth-rf` section, the second daemon's flags, `--victron` among them; the receiver's and decoders' flag checks are one copy both mains call); 2026-11-15 (`--victron SPEC`: tail the JSONL the `sloth-va` helper writes, the owner's Victron readings; file-only, sloth connects to nothing); 2026-11-14 (`--rtl433 SPEC`, #208: tail the JSON event log a local rtl_433 already writes, as a passive sub-GHz sensor; file-only, no SDR and no network); 2026-11-13 (`--aprs-freq HZ` and `--aprs-silent-hours N`, #204: the decoder's declared frequency against the GNSS-derived region, and the silent-decoder threshold); 2026-11-12 (`--monitor-iface NAME` pins the monitor radio); 2026-11-12 (`--gps gpsd://`: the one line sent is `?WATCH={"enable":true,"json":true,"pps":true}`, #182; `report.retain_days`; `--report-interval` also keeps `snapshot.live.txt` and is accepted with only `--snapshot-out`; `--report-history` records are pruned, #190); 2026-11-12 (`karma.forge_assoc_s`, #187); 2026-11-12 (`report.retain_days`; `--report-interval` also keeps `snapshot.live.txt` and is accepted with only `--snapshot-out`; `--report-history` records are pruned, #190); ---

## Synopsis

```
sloth-wifi [output] [handshakes] [stream] [wifi] [bluetooth] [location]
           [correlation] [db] [inventory] [posture] [replay] [runtime]
           [--help] [--version] [--print-schema] [--preflight [--json]]
           [--handoff DIR] [--interference-report FILE [--from T] [--to T]]
           [--sweep LABEL --sweep-minutes N [--sweep-dir DIR]]
sloth      ...    the same program: a symlink to sloth-wifi (build tree
                  and /usr/local/bin), kept with no end date
sloth-rf   [decoders] [receiver] [output] [db] [stream] [runtime]   (see "sloth-rf")
```

Run as root (or with `CAP_NET_ADMIN` + `CAP_NET_RAW`) for capture. A
root run **drops privileges by default** once the capture handles are
open (#140) — see [Privilege](#privilege--dropping-root-after-capture-opens). The
test binary `sloth_test` takes no flags. No subcommands — sloth is a
single mode driven by flags.

## Flags, by group

### Output — forensic log & format

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `-o`, `--out` | `FILE` | off | Append a JSONL forensic log of all observed events. Created `0600`; an existing file must be private, owned by you, not a symlink. → [[jsonl-schema]] |
| `--jsonl-chain` | `N` | off | A hash chain over the `-o` file (#251): a `chain` record after every `N` records (`1..100000`) holding the SHA-256 of the block and of the previous chain record, a genesis record when the file is opened, and a seal (a shorter block) at exit and whenever a report is written; an alert record that names a capture (`pcap_path`) then also carries its `pcap_sha256`. The data socket gets no chain record. Off, the file is byte for byte what it was. Needs `-o` and `--out-format jsonl`, else **exit `2`**. No signing key. → [[record-integrity]] |
| `--out-format` | `FORMAT` | `jsonl` | Format for `-o` **and** `--data-socket`. One of `jsonl`, `cef` (ArcSight CEF), `syslog` (RFC 5424, PRI 134). |
| `--pcap-dir` | `DIR` | off | On a critical alert with a known flow, write the matching packets to a fresh pcap under `DIR`. Dir `0700`, files `0600`. Files sloth wrote there are deleted once older than `pcap.retain_days` (default **14**, `0` = keep forever), swept at startup and hourly in bounded steps (#166). Must not be the same directory as `--eapol-dir` (checked by dev/ino; exits `2`). → [[pcap-export]], [[retention]] §2d |
| `--eapol-dir` | `DIR` | off | Append captured PMKIDs / 4-way handshakes to `DIR/eapol.22000` (hashcat 22000) **and** a per-handshake `DIR/<bssid>_<sta>.pcap`. **Crackable material** — strict perms, refused not repaired. **Requires `--collect-handshakes`**: without it this flag exits `2` and no directory is created. → [[wifi-sigint]] |
| `--collect-handshakes` | — | **off** | Opt in to writing crackable material to disk. A PMKID or a paired M1+M2 supports offline password guessing, so exporting one is a separate decision from observing one. Gates the `.22000` lines, the per-handshake pcaps and (#92) the per-alert **evidence** pcaps — the raw 802.11 frames a deauth-flood alert cites, written to `--eapol-dir` as `<incident_id>-<event_id>-<RULE>.pcap` under `pcap.min_severity` and `pcap.key_cooldown_secs` — **only**: detection, alerting, the `[e]` view and the JSONL/DB records are unaffected. The flag is named for handshakes but also gates that frame-level evidence, because a raw frame carries the same EAPOL/PMKID material (owner ruling 2026-10-08); `--pcap-dir` alone never writes 802.11 frames. sloth never cracks anything itself (MISSION §2.2). → [[retention]] |
| `--handshake-retention` | `DAYS` | `7` | Age-out window for the artifacts above. Swept at startup and once a day while running; artifacts last written before the window are deleted. `0` = keep forever. Alias for `--tune handshake.retention_days` (#120). Whole-file granularity by mtime, so `eapol.22000` goes only once nothing has been appended for the whole window. A failed delete is counted and shown in the `[e]` header, never silent. → [[retention]] |
| `--report` | `FILE.md` | off | On exit, write a Markdown posture report (alerts by severity + MITRE technique, collection coverage: which rules could fire and why not, #242 item 3; finding quality: one line per finding, how its evidence was observed, #246; what this site reveals: the designated site's exposure findings by group, each with its rules' coverage, #243; site questions: each question's answer in priority order, #244; cleartext creds, high-risk devices). → [[posture-report]], [[coverage-assessment]] § 8, § 9, [[exposure-report]], [[site-questions]] |
| `--report-json` | `FILE.json` | off | Same rollup, structured for SIEM diff; the site's exposure is `exposure`, the site questions' answers `questions`, the finding quality is `findings` and the coverage its last member, `coverage`. |
| `--report-interval` | `SECS` | `0` (off) | Also write the report **while running**, every `SECS` seconds (`0..86400`; anything else exits `2`), to a *live* file beside each report path: `report.md` → `report.live.md`, `report.json` → `report.live.json` (#190). The live file is the same rollup with `Session end: (running)` and an `As of` stamp (JSON: `"session_end": null`, `"running": true`, `"as_of"`), so it cannot be read as a signed-off record. It is rendered to a hidden temporary (`.report.live.md.tmp`, `0600`, `O_EXCL`), synced, and renamed over the live name, so a reader sees the previous complete report or the new one. A failed write leaves the previous live file as it was and no temporary, is announced once on stderr (`live report export failed: …`), and is retried at the next interval; it never stops the sensor. **`SIGUSR1`** writes the live report at once, with or without an interval (`systemctl kill -s USR1 sloth-sensor`). The live file is removed when the session's shutdown report is written. One found by a later session (at its first live write, or at its shutdown if it wrote none) was left by a session that never signed off (OOM kill, power loss): it is kept as `report.<UTC mtime>.unclean.md` (`_2`…`_99` if taken) before the name is reused or removed, and if it cannot be kept it is left where it is and the live write is refused rather than replace it. With `--snapshot-out FILE`, the same interval and `SIGUSR1` also keep `FILE.live.txt` (`snapshot.txt` → `snapshot.live.txt`), written the same way, marked `# session<TAB>running`, removed when the shutdown snapshot is written; it never touches the `--snapshot-out` file, so a `--baseline-in` naming that file still moves only at a clean stop. A live snapshot left by a killed session is replaced, not kept: it is an inventory, not a record. The shutdown `--report` and `--snapshot-out` writes are unchanged. Refused (exit 2) without `--report`, `--report-json` or `--snapshot-out`. → [[posture-report]] |
| `--report-history` | — | off | On exit, also keep this session's report as `report.<UTC session start>.md` (and `.json`), e.g. `report.20261109T101500Z.md`, beside the `--report` path (#190). Created `0600` with `O_EXCL`; a name already taken gets `_2`…`_99`, so no run can replace an earlier session's record. Written whether or not the plain `--report` write succeeded. Deleted once last modified `report.retain_days` (default **90**, `0` = keep forever) or more days ago, with the `.unclean` files, at start and at shutdown, on a run using `--report-interval` or `--report-history`; only names of exactly that shape, regular files owned by sloth's user, nothing followed. Refused (exit 2) without `--report` or `--report-json`. |

### Stream — the read-only data socket

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--data-socket` | `[SPEC]` | off | Stream the same records over a **read-only** socket. `SPEC` = `unix:/path` or `tcp:HOST:PORT`. Bare flag → `unix:/run/sloth/sloth.sock` (#136, owner ruling 2026-10-15). If `/run/sloth` is absent, a symlink, owned by neither root nor sloth's effective user, or group/other-writable, the bare flag **exits `2`** and prints the remedy (`RuntimeDirectory=sloth`, or `install -d -m 0750 -o <uid> /run/sloth`) — there is **no fallback to TCP**, so a flag that named no transport never becomes one every local account can read. Loopback TCP must be typed: `--data-socket tcp:127.0.0.1:8765`. Explicit specs are unchanged. Nothing is ever read from the socket. A loopback `tcp:` spec prints a one-line notice at start-up that the stream is readable by every local account and names the `unix:` alternative (#135). Slots are capped per peer and reaped when idle: `--tune socket.max_per_peer`, `socket.idle_secs`. → [[data-socket-exposure]] |
| `--data-socket-allow-remote` | — | off | Permit a non-loopback bind (incl. `0.0.0.0`). Every observation becomes readable by anyone who can reach the port. Prefer an SSH tunnel. |
| `--no-discovery` | — | advertises | Suppress the mDNS advert of a routable data socket. Loopback/unix never advertise regardless. |

### Wi-Fi — capture scope & active behaviour

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--iface` | `NAME` | all | Restrict the stream to `NAME` (repeatable, max `MAX_IFACES`). Logical only — OS iface state untouched. |
| `--monitor-only` | — | off | Restrict capture to the auto-discovered monitor interface. **Fail-closed**: exits non-zero if none found or it can't be enforced. |
| `--monitor-iface` | `NAME` | discovery | Open exactly `NAME` as the 802.11 monitor radio instead of the first type-803 (`ARPHRD_IEEE80211_RADIOTAP`) netdev in `/sys/class/net` readdir order, which a second radio in monitor mode on the same host can win. If `NAME` is missing or its `type` is not 803 there is **no fallback** to discovery: the run continues without 802.11 capture, one stderr line says so, and `sensor_health.monitor_err` carries `monitor iface NAME not found` or `… is not in monitor mode (type N)`. When it opens, one stderr line names it. The `[m]` retarget refuses any other interface (`X refused: --monitor-iface pins NAME`). **Repeatable** ([[multi-radio-sensing]]): the first names this radio, radio 0; each further `--monitor-iface`, at most three, opens another **sensor radio** whose frames reach the same parsers, detectors, tables and alerts. A frame two radios hear is delivered once (`mon_rK_dup_dropped` in `sensor_health` counts the copies); under `--hop` the channel list is dealt out between the radios so they sit on different channels; without `--hop` nothing retunes them. A further radio that is absent or not type 803 at start is named on stderr and left out, and one that leaves the bus mid-run stops alone and is not reopened. Each name 1..15 characters, no `/`; a raw HCI device `bluetoothN` and `--replay` are refused (exit 2), as are a `WITH_PCAP=0` build, a name given twice, a fifth radio, and a further radio that is also a `--df-iface` radio. **Not `--iface`**: the allow-list scopes the IP stream and, by the owner's 2026-10-04 ruling, does not reach the monitor radio; this flag names the radio and scopes nothing. With `--monitor-only` the pinned radio is the one the stream is restricted to. The shipped unit passes `--monitor-iface ${SLOTH_IFACE}` ([[deployment]]). |
| `--df-iface` | `NAME[@METRES\|@X,Y]` | off | Direction finding: also listen on `NAME`, a second monitor-mode radio, prepared by the operator like the sensor radio. Repeatable, up to 3. Only the transmitter address and signal level of its frames are read, into a per-radio table; no frame from it reaches a parser, detector, count or alert. `@METRES` (within ±1000) is the radio's place along a straight baseline; `@X,Y` its place in two dimensions (metres east, metres north, each within ±1000), which with three or more radios not on one line adds a compass bearing to `wifi_df` for a transmitter close to them. One command line uses one form. Under `--hop` these radios are retuned with the sensor radio; without it nothing retunes them and a stderr line says to park them on its channel. A radio that cannot be opened is announced and left out; with no sensor radio none is opened. Receive-only. **Exit `2`** on a malformed spec, positions in both forms, a raw HCI device, a fourth radio, with `--replay`, or in a `WITH_PCAP=0` build. Output: the `wifi_df` and `df_radio` records. → [[direction-finding]] |
| `--df-origin` | `METRES\|X,Y` | `0` or `0,0` | The sensor radio's own place, in the form the `--df-iface` positions use. |
| `--hop` | — | off | Passive channel-hopping: retune sloth's own monitor interface across a 2.4/5 GHz list, dwelling on activity. A kernel-state write on sloth's own radio; allowed under `--strict` (owner ruling 2026-09-30, #84). Needs monitor mode + `CAP_NET_ADMIN`. No frame transmitted. → [[monitor-mode]] |
| `--cue` | — | off | Passive cueing (#248, owner rulings 2026-11-23): a new `EVIL_TWIN`, `KARMA_AP`, `KARMA_PROBE_FORGE`, `DEAUTH_FLOOD`, `PMKID_HARVEST` or `HANDSHAKE_HARVEST` incident makes the `--hop` scheduler dwell **4x** its normal plan on the channel the finding was heard on (its first cited frame's radiotap frequency) for **120 s**. Limits: at most 4 cues at once and 8 started per 10 min; cues at most **50 %** of the sensor radios' time together, and on each radio the rotation with its cues at most twice as long (every other channel keeps at least half its normal share and is visited every rotation; owner ruling 2026-11-24). A cue over a limit is refused and counted (`cue_refused_limit`), feeding `SENSOR_SUPPRESSED` (`suppressed:cue`). One stderr line at start names the kinds and the limits. Only sloth's own monitor radio is retuned, nothing is transmitted, no other receiver is started and no cue leaves the sensor. **Refused under `--strict`** (exit 2); **ignored with a notice without `--hop`** (and in a `WITH_PCAP=0` build). Output: the `cue` record and `sensor_health`'s `cue_*` fields. → [[passive-cueing]] |
| `--tune NAME=VALUE` | name=value | — | Move one knob in the registry — a detector threshold, one of the three storage floors, one of the two per-alert-pcap export policy knobs (#96), or one of the two data-socket hygiene knobs (#135). **`socket.max_per_peer`** (default 4, 1..16) caps how many of the data socket's 16 client slots one peer may hold at once — a uid on `unix:` (`SO_PEERCRED`), an address on `tcp:`, and one shared capped bucket for any peer the kernel cannot identify; over the cap the connection is closed at accept and counted in `sensor_health.socket_peer_refused`. **`socket.idle_secs`** (default 900 = three JSONL heartbeats, 0 = never) closes a client that has made no progress for that long whatever its queue holds; the old 30 s stall rule only ran while bytes were queued. See [[data-socket-exposure]] §4.1. **`pcap.min_severity`** defaults to `2` (CRIT only), which is what `--help` has always claimed and the export never checked; `0` keeps every alert carrying a `match_ip`, the pre-#96 behaviour. **`pcap.key_cooldown_secs`** defaults to `3600`: the same alert key exports at most once an hour, because an alert evicted from the engine and re-fired is the same finding, not new evidence. `0` disables it. Together those two are the "full capture" escape — set both to 0 and nothing is filtered. **`pcap.retain_days`** (default `14`, `0..3650`, owner ruling 2026-10-26 on #166) is how long an alert pcap is kept in `--pcap-dir`; `0` keeps them forever. Only names sloth writes are deleted, regular files only, nothing followed; `sensor_health` reports `pcap_retain_days`, `pcap_swept` and `pcap_sweep_errors`. See [[retention]] §2d. `storage.min_free_pct` defaults to **5 and is ON**: sloth refuses a new `--pcap-dir` write when free inodes or free bytes fall under that share of the filesystem. `storage.min_free_mb` and `storage.min_free_inodes` are absolute overrides, `0` = none. The default is relative because an absolute one cannot suit two filesystems of different size — the floor that protects a 30M-inode host would refuse every write on a small one. Set `storage.min_free_pct=0` and leave the others at 0 for the pre-guard behaviour. See [[retention]]. **Repeatable.** An unknown name, a non-integer, or a value outside the knob's range **exits 2** — a threshold the operator believes they set but did not is worse than no knob, so a bad `--tune` never falls back to the default. Any knob off its default is reported in `sensor_health` (`tuned`, `tuned_count`) and as a fault-only `tuned N/M` token on the Interfaces health strip, so a detuned sensor and a quiet segment do not read alike (#82). Since #120 the registry also holds the detector thresholds that were still compile-time `#define`s — `scan.port_thresh`, `deauth.flood_thresh`/`flood_window_s`, `beacon.flood_*`, `auth.flood_*`, `assoc.flood_*`, `probe.flood_frames`/`flood_window_s`, `btm.abuse_*`, `saq.flood_*`, `rts.flood_rate`/`flood_sustain_s`, `bd.*` (beaconing; the two ratios as whole percent; `bd.max_findings`, added by #148, caps open findings rather than setting a threshold), `queue_evict.*`, `transit.*`, `presence.*`, `seqnum.corr_seq_window`/`corr_dt_max_s` — each defaulting to the value it had as a `#define`; where a count lives in a fixed ring, the knob's upper bound is the ring size, so a threshold cannot be raised past what the detector can hold. The table below lists them. |
| `--no-preliminary` | — | lifecycle on | Turn the finding lifecycle off (#245, [[alerts]] § Finding lifecycle). On (the default, owner ruling 2026-11-25): a kind on the preliminary list (`include/sloth_alert_value.def`; `PMKID_HARVEST`, `HANDSHAKE_HARVEST` and sloth-rf's `GNSS_JAMMING` today) reports its first qualifying evidence at once as `alert.preliminary`, detail "not evaluated: first evidence only", then is confirmed (`alert` + `alert.create`, same `incident_id`) or withdrawn (`alert.resolve`, reason `withdrawn`); a confirmed finding with no new observation for its value period is `lapsed` (one `alert.update`, reason `lapsed`; the incident stays open and the 300 s resolve is unchanged); every `alert` / `alert.*` record carries `state` and `value_period_s`, and the `alert_lifecycle` record the per-kind counts. Off: none of that, and the stream is the one before #245 (`make replay-check` holds it byte for byte against the golden with those fields taken out). |
| `--value-period` | `KIND=SECS` | 300 for every kind | The value period of one alert kind (#245): seconds after a confirmed finding's last observation at which it lapses. `KIND` as in `sloth_alerts.def`, with or without `ALERT_TYPE_`; `SECS` `1`..`2592000` (30 days). **Repeatable.** An unknown kind, `0`, a non-integer or more than 30 days **exits 2**. Moves the lapse only: the 300 s resolve and the preliminary window are unchanged. No effect under `--no-preliminary`. A standing condition (sloth's own state, or an 802.11 kind of SHAPE `STATE`) never lapses and is refused here too, exit 2 ([[alerts]] § Finding lifecycle). |
| `--questions` | `PATH` | the seven defaults | The operator's site questions (#244, owner ruling 2026-11-25: the operator's own file; sloth-mesh may write it later). One per line, `id|priority|question|decision|KIND,KIND`; it replaces the seven defaults of `include/sloth_questions.def`. An unknown kind, a duplicate id, a field out of range, more than 32 questions or none **exits 2** naming the line ([[site-questions]] § 5). Each question's answer is a `question_status` record and a `--report` section. |
| `--tune-list` | — | — | Print every knob with its default, current value and unit, then exit 0. The registry is the contract: adding a tunable adds a row there, not a new flag — which is why the storage floors are knobs and not `--min-free-mb`. |
| `--allow-active` | — | off | Opt in to the two active behaviours: (1) reverse-DNS PTR queries on cache miss; (2) nl80211 **passive** scan triggers (no SSID list, no probe transmitted). Prints one stderr line naming what it enabled; never silent. |
| `--strict` | — | off | Lock: refuses any later attempt to enable active behaviour this run (`--strict --allow-active` exits non-zero). Suppresses the mDNS advert. **Refuses a routable `--data-socket` (exit 2), even with `--data-socket-allow-remote`** — loopback and `unix:` are unaffected (#84, 2026-10-06). Does **not** refuse `--hop`. **Refuses `--cue`** (exit 2, #248). Records operator intent where `ps(1)`/audit can see it. |

#### Knobs added by #120

Defaults are the shipped values; ranges are inclusive and a value outside one exits 2. `--tune-list` is authoritative.

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `correlate.retain_secs` | 300 | 1..604800 | `--correlate-retain` |
| `handshake.retention_days` | 7 | 0..36500 | `--handshake-retention` (0 = forever) |
| `db.interval_secs` | 1 | 1..86400 | `--db-interval-secs` |
| `db.retain_days` | 30 | 1..36500 | `--db-retain-days` |
| `db.max_mb` | 512 | 0..4194304 | `--db-max-mb` (0 = unlimited) |
| `scan.port_thresh` | 8 | 2..64 | distinct local service ports from one IP → `PORT_SCAN` |
| `deauth.flood_thresh` / `deauth.flood_window_s` | 5 / 5 | 2..32 / 1..600 | distinct deauth/disassoc frames per sliding window |
| `beacon.flood_thresh` / `beacon.flood_window_s` | 40 / 10 | 2..256 / 1..3600 | new BSSIDs per window |
| `auth.flood_thresh` / `auth.flood_window_s` | 30 / 5 | 2..512 / 1..3600 | auth frames to one BSSID per window |
| `assoc.flood_thresh` / `assoc.flood_window_s` | 21 / 60 | 2..256 / 1..3600 | (re)assoc requests to one BSSID per window |
| `probe.flood_frames` / `probe.flood_window_s` | 30 / 5 | 2..32 / 1..600 | probe requests from one TA per sliding window |
| `btm.abuse_thresh` / `btm.abuse_window_s` | 4 / 60 | 2..256 / 1..3600 | disassoc-imminent BTM requests per (BSSID, STA) |
| `saq.flood_thresh` / `saq.flood_window_s` | 12 / 10 | 2..48 / 1..3600 | SA Query frames per (BSSID, STA) |
| `rts.flood_rate` / `rts.flood_sustain_s` | 500 / 5 | 1..100000 / 1..3600 | RTS/s from one TA, held for N s |
| `bd.min_samples` / `bd.min_interval_s` / `bd.max_jitter_pct` | 5 / 10 / 25 | 3..16 / 1..86400 / 1..100 | beaconing v1 (low jitter) |
| `bd.min_samples_v2` / `bd.min_concentration_pct` | 12 / 60 | 3..16 / 1..100 | beaconing v2 (gap concentration) |
| `bd.max_findings` | 16 | 1..64 | open per-destination `BEACONING` findings at most; strong tracks past them are one `beacon-overflow` finding (#148, owner ruling 2026-10-23). A cap, not a threshold: it never decides whether a track is strong. 16 is an eighth of the engine's 128 slots; the ceiling 64 keeps one detector from claiming more than half of them by configuration. See [[alerts]] § BEACONING cap |
| `queue_evict.window_ms` / `queue_evict.min_frames` / `queue_evict.report_secs` | 100 / 3 / 900 | 1..10000 / 2..1000 / 1..86400 | queue-release detection (#107) |
| `transit.gap_secs` / `transit.window_secs` / `transit.recur_thresh` | 300 / 7200 / 3 | 1..86400 / 60..604800 / 2..16 | recurring transit (#54) |
| `presence.swing_dbm` / `presence.min_samples` | 8 / 3 | 1..100 / 3..16 | transit-shaped RSSI trajectory |
| `presence.transient_max_s` / `presence.visitor_min_s` / `presence.resident_min_s` | 120 / 120 / 900 | 1..86400 / 1..86400 / 1..604800 | presence dwell classes |
| `seqnum.corr_seq_window` / `seqnum.corr_dt_max_s` | 64 / 30 | 1..4095 / 1..3600 | seqnum correlation seam |

#### Knobs added by #82 (Pixie Dust)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `wps.pixie_silence_s` | 60 | 1..3600 | seconds a WPS run must stay quiet after M3, with no M4, before `WPS_PIXIE_PROBE` calls it abandoned |
| `wps.pixie_success_window_s` | 86400 | 3600..604800 | seconds `WPS_PIXIE_LIKELY_SUCCESS` looks back from a completed registration for an abandoned-after-M3 run at the same AP |

#### Knob added by #106 round 2 (camera identity)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `camera.join_fresh_secs` | 3600 | 900..604800 | seconds a LAN camera row (WS-Discovery, mDNS, SSDP, RTSP) stays joinable to the device record holding its IP; older rows are trail history only. Longer holds a quiet ONVIF camera's class; shorter narrows the window in which a reused DHCP lease carries it to another host. See [[camera-detection]] |

#### Knob added by #190 (report retention)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `report.retain_days` | 90 | 0..3650 | days a per-session report record (`report.<UTC>.md`, `report.<UTC>.unclean.md`, `_N` variants, and the `.json` ones) is kept beside `--report`; `0` = forever. Swept at start and shutdown, only with `--report-interval` or `--report-history`. Retention, not a detector threshold; off its default it still counts in `tuned`. See [[posture-report]] |

#### Knob added by #239 (random-address retention)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `retention.random_repeat_s` | 600 | 0..86400 | `--db` only: seconds a locally administered address may have been heard for (`last_seen - first_seen`) and still count as one that did not repeat. Such a row, last heard more than 7 days ago and grouped with no SSID, is purged from `devices` and counted into `random_devices_daily` (owner ruling 2026-11-20). `0` purges only rows heard in one tick; a larger value purges more. Retention, not a detector threshold; off its default it still counts in `tuned`. See [[retention]] § 2b |

#### Knobs added by #144 slice 4 (BLE detectors)

None of these has a cited basis for where legitimate traffic stops. The
BLE-spam tool's source is the basis for the *shape* (a fresh address per
payload, which is why gate 1 counts addresses new to the key rather than
addresses present, an advertising interval of 20–500 ms — [[ble]]), not for a
number, so `BLE_ADV_FLOOD` requires all three of its gates together and
none can be switched off: the third gate, a documented spam payload key,
is not a knob.

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `ble.flood_window_s` | 10 | 1..600 | seconds per `BLE_ADV_FLOOD` window (tumbling, monotonic clock); a changed value restarts every window |
| `ble.flood_distinct_addrs` | 20 | 2..128 | gate 1: **fresh** advertiser addresses on one spam-listed key in a window — not heard on the key in the two windows before, and only in a window whose predecessor held advertisements on it (a crowd of stable genuine advertisers counts 0); the ceiling is the exact per-window set the table keeps, the fresh count past it is Bloom-backed and under-counts |
| `ble.flood_rate` | 10 | 1..10000 | gate 2: advertisements per second on that key, counted over the whole window (a window in progress is never extrapolated upward) |
| `ble.hid_rotate_addrs` | 3 | 2..256 | `BLE_HID_UNEXPECTED` rotation form: new random addresses advertising a HID appearance on one sensor inside the window |
| `ble.hid_rotate_window_s` | 900 | 60..86400 | seconds in the `BLE_HID_UNEXPECTED` rotation window; the form cannot fire on a sensor until that sensor's first advertisement is more than one window old (per sensor: a `--bt-capture` started later has its own first window) |

#### Knobs added 2026-10-26 (RSSI distance data point)

Model coefficients and a calibration distance for [[rf-distance]], not
detector thresholds: no alert rule reads the estimate. `N` values are
ITU-R P.1238-10 Table 2's residential column, ×10 because the registry
is integer-only; the bounds bracket its corridor (~18) and its worst
rows (~44).

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `rf.path_loss_n_2g` | 28 | 16..60 | distance power loss coefficient N ×10 for 2.4 GHz Wi-Fi **and BLE** |
| `rf.path_loss_n_5g` | 30 | 16..60 | N ×10 for 5 GHz |
| `rf.path_loss_n_6g` | 30 | 16..60 | N ×10 for 6 GHz (P.1238 has no row; the 5 GHz value) |
| `rf.median_k` | 8 | 1..16 | RSSI samples the distance median takes (the newest, within 60 s) |
| `rf.ref_dist_dm` | 0 | 0..1000 | decimetres from the sensor to the `--my-bssid` AP; non-zero turns on calibration from that AP's measured path loss, per Wi-Fi band, bounded ±20 dB, never applied to BLE. 0 = no calibration |
| `rf.rx_gain_db_wifi` | 0 | -20..30 | receive antenna gain, dBi, of the Wi-Fi monitor radio (2026-11-06): subtracted from every RSSI before the distance is solved; 9 dB moves an estimate out ×2.1 at N 2.8. A `--my-bssid` calibration in force supersedes it (its offset already holds the gain) |
| `rf.rx_gain_db_ble` | 0 | -20..30 | the same for the BLE receiver |

#### Knobs added 2026-10-27 (sensor position, `--gps`)

Sampling and freshness for the position stamp; no rule reads the position stamp. `GNSS_POSITION_JUMP` and `GNSS_SPOOF_SUSPECT` read the receiver's fix history instead: see the `gnss.*` knobs below. → [[location]]

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `gps.min_move_m` | 5 | 0..100000 | metres the GPS fix must move before a device's position sample (and the sensor's track) is taken again |
| `gps.sample_s` | 60 | 1..86400 | at rest: the sensor's track interval, the least gap before a device's RSSI band change is sampled, and /10 of a device's keep-alive interval ([[location]]) |
| `gps.max_fix_age_s` | 30 | 1..3600 | a GPS fix older than this stamps nothing; `--location`, when given, stands in |

#### Knobs added 2026-11-03 (the GNSS rules)

Thresholds of the four `--gps` rules ([[alerts]] § The GNSS receiver, `src/alerts/rules_gnss.c`). Each default is argued from `research/gnss/`; where the research says no published threshold exists, the default is the conservative one and the row says so. Every window runs on the monotonic clock. → [[gnss]]

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `gnss.jam_cn0_drop_db` | 10 | 1..60 | `GNSS_JAMMING`: dB the median C/N0 of the tracked satellites (ss > 0) must fall, newest point against the 60 s before the window. "No read source puts a number on 'simultaneous' or on the drop; any value is a judgement" (`research/gnss/jamming-detection.md`): 10 dB is the bottom of the nominal "~ 37 to 45dB-Hz" band down to the 27 dB-Hz Kriezis et al. define as signal loss |
| `gnss.jam_window_s` | 10 | 2..120 | seconds the collapse must happen within: the research's "within one or two epochs", stretched over gpsd's SKY cadence. A sky falling over minutes stays inside its own baseline |
| `gnss.jam_ind` | 128 | 1..255 | u-blox `jamInd` (TPV `jam`, CW only) at or above which the indicator path counts. The vendor: "It is necessary to run the receiver in the application and then calibrate the 'not jammed' case" — no published level, so the top half of the scale, erring quiet |
| `gnss.jam_hold_s` | 30 | 2..299 | seconds `jamInd` must hold there: gpsd attaches `jam` about one TPV in four (MON-HW "every 4" epochs), so one report cannot fire |
| `gnss.spoof_cn0_high_db` | 53 | 30..99 | `GNSS_SPOOF_SUSPECT` heuristic 1: dB-Hz at or above which a used satellite counts. Kriezis et al.'s F9P + ANN-MB spoofing threshold, 8 dB over the nominal band's top; "Neither number transfers to a u-blox 7 with an unknown antenna" (`research/gnss/spoofing-detection.md`), so conservative, not calibrated |
| `gnss.spoof_high_sats` | 4 | 1..48 | used satellites that must be that high at once: four is what a spoofer must supply to steer a fix |
| `gnss.spoof_cn0_mean_db` | 45 | 20..99 | heuristic 2: the used set's mean C/N0 must be at least this (the nominal band's top), which keeps the indoor case — uniform but weak — out |
| `gnss.spoof_cn0_sd_db` | 1 | 1..20 | heuristic 2: the spread must be under this. "No peer-reviewed source read for this document states a uniformity (low-spread) threshold" — 1 dB is below what a sky across elevations shows |
| `gnss.spoof_min_sats` | 6 | 3..48 | heuristic 2: used satellites with a C/N0 the spread is taken over ("Few satellites (spread undefined)") |
| `gnss.spoof_window_s` | 300 | 10..3600 | seconds in which two heuristics must both have been seen; spans a jam-then-reacquire sequence (DHS 2017 advises delaying reacquisition "for many minutes or hours") |
| `gnss.time_jump_ms` | 1000 | 200..3600000 | `GNSS_TIME_JUMP` (and heuristic 3): ms the receiver's time must step against the host's monotonic clock between fixes. The gpsd time HOWTO: the in-band delay "may be stable to 10 mSec for hours and then jump by 200mSec", so 200 ms is the floor, and "anything below roughly a second is noise on its own terms" (`research/gnss/time-and-position-integrity.md`) |
| `gnss.pos_jump_k` | 3 | 1..100 | `GNSS_POSITION_JUMP` (and heuristic 3): the multiplier on eph₁ + eph₂ in the bound `(speed + eps) × Δt + k × (eph₁ + eph₂)`. "Because the confidence level of eph is unknown, a multiplier on it is a judgement, not a cited value": 3 covers eph read as one sigma to three sigma per fix |

Threshold of the `--adsb` rule ([[alerts]] § ADS-B, `src/alerts/rules_adsb.c`; basis `research/adsb/emergency-squawks.md`). The rule and the twelve `gnss.*` rule knobs above are read by `sloth-rf` only since the cutover (#216); the registry is one, so `sloth-wifi --tune-list` still prints them and `--tune` still accepts them, to no effect there.

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `adsb.emerg_hold_s` | 10 | 2..59 | `ADSB_EMERGENCY`: seconds an aircraft's emergency squawk (7500 / 7600 / 7700) or status must hold, measured on its own messages (the row's `last_mono_ms`), before LOW becomes WARN. No source read gives a figure for how long a decode error or a code dialled through in passing lasts; 10 s is a judgement - ten of readsb's one-second documents. Below 60 because the table retires an aircraft unheard for 60 s |

#### Knob added 2026-11-11 (`EVIL_TWIN` late arrival, #188)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `twin.late_arrival_s` | 120 | 30..86400 | `EVIL_TWIN`: seconds the later-heard half of a same-SSID pair must be first heard after the earlier half before `+late-arrival` (+20 confidence, only on a pair with a locally administered half) counts, and the wait after the sensor was last moving (GNSS, 1 m/s or more) before any arrival counts. 120 is five worst passes of the default 11-channel hop list (22 s each); the floor keeps it above one such pass and above the 10 s in which one device's two radios are first heard. An AP that drops out and returns is not an arrival whatever this is set to ([[alerts]], `docs/wiki/alert-assessments/EVIL_TWIN.md`) |

#### Knob added 2026-11-12 (`EVIL_TWIN` faint half, #188)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `twin.crit_min_beacons` | 5 | 1..1000 | `EVIL_TWIN`: beacons the beacon table must have heard from a twin half before a reading taken off that half may carry CRIT. On a **same-security** pair, from each half, before a row resting only on soft signals may be CRIT; fewer, or a strongest reading at or under -92 dBm, is `+faint` and WARN. On the **weak/strong** branch since #232, from the weak half, before its `OPEN`/`WEP` label may be CRIT — that label is what sloth writes when the Privacy bit is set and no RSN or WPA IE parsed, so below the floor it has not been read twice and the row is WARN `single weak beacon, enc unconfirmed` at -65 confidence (a truncated RSN IE or an IE overrun ever counted for that BSSID is WARN at the same deduction whatever the count). Five is five passes of the hop list for an AP in steady earshot (a dwell is 100 ms or more, APs beacon every 102.4 ms), under two minutes at the default list's worst 22 s. Hard signals are not gated ([[alerts]], `docs/wiki/alert-assessments/EVIL_TWIN.md`) |

#### Knobs added 2026-11-11 (`KARMA_PROBE_FORGE`, #187 S2)

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `karma.forge_ssids` | 2 | 2..8 | `KARMA_PROBE_FORGE`: distinct SSIDs one BSSID must have answered stations' directed probes for, without ever beaconing them, before the rule fires. 2 is the smallest count one BSS cannot produce by being itself (its own name, hidden or not, is never counted); the ceiling is the per-BSSID answer set, so a value the table cannot hold is refused. The basis (Dai Zovi & Macaulay 2005, airbase-ng `-P`) describes the mechanism, not a count, so the number is sloth's judgement ([[alerts]], `src/karma_detect.h`) |
| `karma.forge_window_s` | 600 | 10..86400 | `KARMA_PROBE_FORGE`: seconds an answered SSID stays on its BSSID's forge row. Long enough to see two passing phones' preferred networks answered by one radio when unassociated phones probe a few times a minute; a judgement, not a cited value |
| `karma.forge_assoc_s` | 60 | 5..600 | `KARMA_PROBE_FORGE` CRIT (#187, 2026-11-12): seconds after the newest forged answer to a station in which that station's association request to the BSSID, under the forged name, still counts as the lure having worked (the BSSID must also have granted it, and the request must be no earlier than the first forged answer). A station that took the bait joins within seconds of the probe exchange; a judgement, not a cited value. The ceiling is the forge window's default |

#### Knobs added 2026-11-11 (`PMKID_HARVEST`, `HANDSHAKE_HARVEST`, #172)

None of these numbers comes from a source: hcxdumptool's README and Steube's 2018 post describe the mechanism, not counts or timing (`research/tools/hcxdumptool.md`, `research/papers/steube-2018-pmkid.md`). Each is argued in `src/harvest_track.h`.

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `harvest.window_s` | 900 | 600..86400 | Both rules: seconds a soliciting station's targets, and a BSSID's harvest victims, stay counted. Long enough to hold three targets reached one every five minutes, the slow harvest the flood rules miss; the floor stays above `harvest.reconnect_s`'s ceiling |
| `harvest.min_bssids` | 3 | 2..16 | `PMKID_HARVEST`: distinct BSSIDs that answered one station's association request with an M1 the station left without an M2 (and, for CRIT, that carried a PMKID). The ceiling is the per-station target table |
| `harvest.unanswered_pct` | 50 | 1..100 | `PMKID_HARVEST`: share of a station's M1-answering BSSIDs that must be unanswered. A roaming phone sits near 0, a harvester at 100 |
| `harvest.deauth_min` | 2 | 1..1000 | `HANDSHAKE_HARVEST`: distinct deauth/disassoc frames claimed from the BSSID to a station (or broadcast) before its fresh M1/M2 counts. Under `DEAUTH_FLOOD`'s 5 on purpose; one is an AP doing its job |
| `harvest.reconnect_s` | 30 | 1..600 | `HANDSHAKE_HARVEST`: seconds from the last such frame to the fresh M1/M2 pair |

#### Knobs added 2026-11-23 (`SENSOR_SUPPRESSED`, #242 item 4)

No source gives any of these: each is set well above what the reference sensor measured on its live stream (115 s of `sensor_health`, 2026-11-23), and the measurement is written beside the defaults in `src/alerts.h` and in [[coverage-assessment]] § 7. The minute is the coverage record's interval and is not a knob.

| Knob | Default | Range | Meaning |
|------|---------|-------|---------|
| `suppress.evict_per_min` | 600 | 1..10000000 | `SENSOR_SUPPRESSED`: evictions from one synthesis table in one minute (the flow rings, `evidence_frame`, `alert`, `pcap_cooldown` not judged). No source; the reference sensor's busiest table, `frag_sta`, ran 42 a minute (2026-11-23) |
| `suppress.drop_pct` | 1 | 1..100 | `SENSOR_SUPPRESSED`: percent of a capture handle's `ps_recv` dropped (`ps_drop + ps_ifdrop`) in one minute. The reference sensor dropped none |
| `suppress.drop_min` | 100 | 1..10000000 | `SENSOR_SUPPRESSED`: drops the handle must also have in that minute, so a trickle on a quiet link is not a share |
| `suppress.silent_intervals` | 3 | 2..60 | `SENSOR_SUPPRESSED`: coverage intervals in a row a visited channel that was heard earlier hears nothing while another channel of its band is heard. One quiet minute on a hopped channel is a lull |
| `suppress.cue_refused_per_min` | 5 | 1..100000 | `SENSOR_SUPPRESSED`: `--cue` refusals at a limit (active, rate or share) in one minute (#248). Unmeasured: `--cue` is new. Two cues fit an 11-channel radio, so a third finding in a busy minute is one refusal; a trigger flood refuses one per finding |

`--refresh-ms` is deliberately not a knob: it is UI cadence, not a detector or retention decision.


**Startup diagnostic — unresolved allow-list names (#85).** An
`--iface`/`--monitor-only` name that does not resolve at launch is not
pinned, so every frame arriving on it is refused for the rest of the
run. Immediately after the capture thread starts, sloth names those
interfaces once on stderr: `none of the requested interfaces could be
resolved (<names>)` when nothing pinned, `requested interfaces not
resolved (<names>)` when only part of the list did. This is a
diagnostic, **not** a refusal — it does not change the exit code, and a
run that prints it still collects on whatever did pin. That is an owner
decision (2026-10-19, #85 close-out), as is a replugged adapter staying
failed closed until restart. Nothing is
printed when capture could not be opened at all; that case already has
its own warning, and no name could have pinned either way. The claim is
scoped to the IP capture stream: the monitor radio sits outside the
`--iface` allow-list. An interactive run's line is wiped by ncurses
init, so the audience is journald / `--headless`. →
[[views-catalog]], `docs/views/interfaces.md`

### Bluetooth — the HCI monitor channel (#144)

| Flag | Argument | Default | Effect |
|---|---|---|---|
| `--bt-monitor` | — | off | Also open libpcap's `bluetooth-monitor` device (Linux HCI monitor channel, DLT 254) and decode an allow-list of it: controller announcements (NEW_INDEX), LE Advertising Reports and LE Extended Advertising Reports (every report of each), and the host's own scan, advertise and connect commands. **Receive-only**: the kernel gives the monitor socket no transmit path, and sloth sends no HCI or MGMT command — the operator starts a *passive* scan with their own stack, or with `sloth-ble-scan.service` ([[ble]], [[deployment]] §7). Opened before the privilege drop beside the IP handle (binding the channel needs `CAP_NET_RAW`); a failure to open is announced on stderr and in `sensor_health.btmon_err`, and the run continues. Registers sensor kind `ble`. Nothing read off the channel is written verbatim anywhere — link keys and LTKs cross it. Refused (exit 2) with `--replay` and in a `WITH_PCAP=0` build. |
| `--bt-capture` | `PATH` | off | Read an Ubertooth capture the operator produces: a **classic pcap** file or FIFO written by `ubertooth-btle -q` (link type 256, BLE LL with pseudo-header), `ubertooth-btle -c` (192, PPI around 251) or `ubertooth-rx -q` (255, BR/EDR baseband). **sloth never drives the dongle** — no libubertooth, no USB request, no child process; the operator runs the tool, with the receive-only flags [[ubertooth]] lists. `PATH` is checked with `stat()` at startup (missing, a directory, a device node or a socket exits 2) and opened **once**, on its own worker after the privilege drop, so a FIFO with no writer yet never holds startup and is never reopened; the account sloth runs as must be able to read it. Any other link type, and pcapng, is refused with a message in `sensor_health.btcap_err`. A regular file is read to its end; a FIFO until its writer closes it (`btcap_state` `eof`). Advertisers land in the BLE device table as `sensor_iface` `ubertooth`, a separate row from the same address heard by `--bt-monitor`; BR/EDR is kept as LAP only. **Counts are a sample of one channel** (`btcap_sampling`). Registers a second sensor of kind `ble`. Refused (exit 2) with `--replay` and in a `WITH_PCAP=0` build. |
| `--ble-rotation-hints` | — | off | **Internal use only** (owner ruling 2026-10-23, #156). Link private BLE addresses (resolvable or non-resolvable, by Address[47:46]; never static, public or resolved-identity addresses) that may be one advertiser rotating: a documented token carried across the change (MS-CDP Salt + Device_Hash; Apple Handoff, unverified; Fast Pair account data with an unchanged salt), or a clean seam and the same advertising shape alone. Used only to de-duplicate the `[*]` view's total, an estimate line over the recent window only (a link lasts while both addresses are in the seam table). **No detector reads a hint**: tokens are attacker-supplied, so `BLE_HID_UNEXPECTED` counts addresses with the flag on exactly as with it off. **No link is shown per row, no JSONL field names a link or a token, nothing reaches the database**: what leaves the process is three `sensor_health` decade bands (`"0"`, `"1-9"`, ...), `ble_rot_hints`, `ble_rot_poisoned` and `ble_rot_seam_evictions`, present only while the flag is on and in no change-only signature. Tokens are held only as SipHash-2-4 digests under a key drawn from `getrandom()` per run, never written; tables are bounded (64 recent addresses per sensor and adapter) and expire without frames. Timing-only links carry their caveat on the estimate line. **Silent on an HCI adapter whose scan filters duplicates** (`Filter_Duplicates` on, or no scan enable seen): use `hcitool lescan --passive --duplicates` as [[ble]]'s procedure says. Without the flag nothing is allocated and no field appears; `make replay-check` holds the output to the golden from before the feature. **Ignored, with a stderr notice, without `--bt-monitor` or `--bt-capture`** (so also under `--replay`, which takes neither) — chosen over a refusal because the flag adds no output a run without a BLE source could miss. A hint corroborates; it does not confirm, and identifies no device or person ([[ble]]). |

The raw per-controller devices libpcap also lists — `bluetooth0`,
`bluetooth1`, ... (`HCI_CHANNEL_RAW`) — accept injected packets, and no
path opens one: `--iface bluetooth0` exits 2, the `[m]` retarget
refuses it, and the IP capture's first-device fallback skips every
`bluetooth*` name rather than taking the head of the device list.

If `sensor_health.ble_scan_mode` reads `active`, or
`ble_own_tx_asserted` is not empty, the host is transmitting and
`BT_OWN_TRANSMIT` fires; stop the scan and start a passive one.
`ble_own_tx` = `never` means only that no transmit command has crossed
the channel since sloth opened it — a controller already advertising or
page-scanning before then is not in it until `ble_own_tx_baseline`
reads `1` (power-cycle the adapter with sloth running). `ble_scan_mode` is `unknown` until a
scan-parameter command has actually been seen — start sloth before the
scan, or restart the scan, to have it recorded. → [[ble]]

### Location — where the sensor is (2026-10-27)

Both opt-in; neither is a network the sensor monitors, and neither puts
a frame on one. Each is announced on stderr at startup. → [[location]]

`sloth-wifi` keeps the receiver (owner ruling 2026-11-15): the position
stamp on alerts and devices, `device_positions`, `sensor_positions`,
the twin rules' motion suppression, the `[#]` view, the `gnss` row of
`source_status` and `sensor_health`'s `gps_*`, `gnss_*` and `loc_*`
members. It does not write the `gnss_fix` / `gnss_sky` / `gnss_sat`
records or the `gnss_fixes` / `gnss_sightings` tables and runs no
`GNSS_*` rule: those are `sloth-rf`'s, from its own copy of the same
reader. A serial receiver opens once, so a host that gives `--gps` to
both daemons uses gpsd.

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--location` | `LAT,LON[,ALT]` | off | The sensor's fixed position, WGS84 decimal degrees and metres above mean sea level (`51.50074,-0.12469,12`). Every new alert incident is stamped with it: the JSONL `alert` / `alert.*` records' `loc` object, the `--db` alerts row's `lat`/`lon`/`alt_m`/`loc_src`/`loc_ts`, the evidence manifests' `loc`. A latitude outside -90..90, a longitude outside -180..180, an altitude outside -1000..20000 or anything that is not a decimal number exits 2. Allowed with `--replay` (the files were captured somewhere; say where). |
| `--gps` | `SPEC` | off | Read the sensor's position from a receiver. `SPEC` is `/dev/ttyXXX` — NMEA 0183 GGA, RMC and GSA off a serial device, checksum verified, opened read-only (`O_RDONLY`; sloth never writes a byte to the receiver) **before** the privilege drop, because the drop clears supplementary groups and the device is usually group `dialout`, and read on a worker after it — or `gpsd://[HOST[:PORT]]`, gpsd's JSON stream over TCP (default `127.0.0.1:2947`), dialled after the drop; sloth sends gpsd exactly one line, `?WATCH={"enable":true,"json":true,"pps":true}` (`"pps"` since 2026-11-12, #182: gpsd then also sends `TOFF`, which `GNSS_TIME_JUMP` judges on, [[gnss]]), then only reads. There is no `gpsd://PATH`: gpsd has no Unix-socket data transport (its `-F` socket takes device add/remove commands only). A fix younger than `gps.max_fix_age_s` stamps as `loc_src` `gps` and wins over `--location`; an older one, or a receiver reporting no fix, stamps nothing (or the `--location` value). Fix quality 6 (dead reckoning), 7 (manual) and 8 (simulation) never stamp. With `--db`, a moving sensor also records `device_positions` and `sensor_positions`. `sensor_health` carries `gps_*`; the interface view's health strip carries `gps <state>`. Refused (exit 2) with `--replay`, for a malformed SPEC, a host name (numeric addresses only: no resolver), a device that cannot be opened, and a non-loopback gpsd without `--gps-allow-remote`. |
| `--gps-allow-remote` | — | off | Permit `--gps gpsd://HOST` outside 127.0.0.0/8 and `::1`. The stream is unauthenticated and unencrypted. `--strict` refuses a remote gpsd regardless: a lock another flag can override is not a lock. Ignored, with a notice, without `--gps`. |
| `--gps-baud` | `N` | 9600 | Serial speed for `--gps /dev/...`: 4800, 9600, 19200, 38400, 57600 or 115200. Anything else, or the flag with a gpsd SPEC or without `--gps`, exits 2. |

### Refused — the SDR decoders' flags (#216)

| Flag | Effect |
|------|--------|
| `--adsb`, `--aprs`, `--aprs-freq`, `--aprs-silent-hours`, `--rtl433`, `--victron` | **Exit `2`**, with or without a value, before anything is opened, printing one line: `sloth-wifi: --adsb is sloth-rf's flag since the split (JSONL 2.0.0): this daemon reads no SDR decoder. Run 'sloth-migrate-rf --apply' to move it from /etc/default/sloth to /etc/default/sloth-rf, then start sloth-rf (docs/wiki/deployment.md section 11.4)` (the flag named is the one given; `src/rf_moved.c`). |

Until the cutover the one binary took these six. They are `sloth-rf`'s
(§ sloth-rf, below), and `sloth-wifi` links none of the decoders: the
`Makefile`'s `check_wifi_no_rf` fails the link if a decoder symbol is
in it. A refusal and not "unknown argument", because a sensor whose
`/etc/default/sloth` still names one must say what to do, not print a
usage text into the journal; [[deployment]] §11.4 is the upgrade.
`tests/test_rf_moved.c` holds the line and `tests/replay/rf_refusals.sh`
the exit code, on the linked binary and on the `sloth` symlink.

### Privilege — dropping root after capture opens

Owner ruling 2026-10-15, "only use root when necessary" (#140). sloth
needs `CAP_NET_RAW` once, to open the capture handles, and
`CAP_NET_ADMIN` for the whole run only when it writes nl80211 (`--hop`
retunes, `--allow-active` scan triggers — each opens a fresh netlink
socket). So after `capture_open`/`probe_open` and the scope check, and
before any sink or thread exists, a root run switches account and sheds
everything else. Every sink (`-o`, `--db`, `--pcap-dir`, `--eapol-dir`,
`--data-socket`, the exit-time `--report`/`--snapshot-out`) is then
created **as the target account**, so its path must be owned by that
account — the existing "validated, never repaired" refusal fires
otherwise.

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--user` | `NAME` | `sloth` when that account exists | Account a root run drops to (`setgroups(0)` → `setresgid` → `setresuid`, then raw `capset`; no libcap). Keeps `CAP_NET_ADMIN` only for `--hop`/`--allow-active`, never `CAP_NET_RAW`. An unknown `NAME` exits `2` before anything opens. Without `--user` and with no `sloth` account a root run **keeps uid 0 but drops every capability it does not need**, and says so on stderr. Needs root (`CAP_SETUID`+`CAP_SETGID`); a non-root `--user` exits `2`. |
| `--no-privdrop` | — | off | Keep every privilege for the whole run — the explicit escape for dev boxes (e.g. a root-owned `data/`). Announced on stderr; `no_new_privs` is still set. `--user` with `--no-privdrop` exits `2`. |

What every run does regardless of flags: `PR_SET_NO_NEW_PRIVS`, ambient
set cleared, inheritable set cleared. A non-root run (the shipped
systemd unit runs as `sloth` with ambient caps) keeps its uid and sheds
`CAP_NET_RAW` the same way. Every step is read back (`getresuid`,
`capget`, `PR_CAPBSET_READ`, `PR_GET_NO_NEW_PRIVS`); a mismatch is a
startup failure, exit `2`, never a half-dropped run. The stderr line is
one of:

```
sloth: dropped to uid 998 (sloth) after capture opened; caps kept: CAP_NET_ADMIN for --hop; no_new_privs on
sloth: no 'sloth' account to drop to — staying uid 0 with every capability dropped; caps kept: none; no_new_privs on. Create the account (packaging/systemd/sloth.sysusers.conf) or pass --user NAME
sloth: --no-privdrop: privileges NOT dropped — this run keeps uid 0 and every capability for its whole life
```

Consequences of a dropped run, by design: the `[m]` monitor retarget
cannot open a new radio (`CAP_NET_RAW` is gone; the current radio keeps
capturing and the pcap error is shown — restart with the new interface
instead); the process views lose the pid map for other users'
sockets (`/proc/<pid>/fd` is unreadable); the mDNS service file cannot
be written to `/etc/avahi/services` (the existing "use --no-discovery"
notice). → [[deployment]], [[monitor-mode]]

### Correlation — MAC deanonymisation

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--no-correlate` | — | on (correlation enabled) | Disable longitudinal device correlation. Seqnum `[j]` still shows each MAC's own trail, but no pair is linked and no `seqnum_correlation` record is exported/stored. → [[mac-randomisation]] |
| `--correlate-retain` | `SECS` | `300` | Evidence window: a pair is reported only while **both** addresses were heard inside this window, counted from now. Alias for `--tune correlate.retain_secs` (1..604800); a non-integer such as `30s` exits 2 (#120). Clearing the `[j]` table no longer resets it. |

### WPS alert thresholds (#82)

The only rule thresholds sloth exposes on the command line. Every other
one in the engine is a `#define`; these three are knobbed because the
owner asked for the issue's proposed numbers to be tunable per site
(decision of 2026-09-30). Each is a **floor** — raising it only quiets
the rule, it can never invent a finding — and a value of zero or less is
**rejected with exit 2** rather than read as "disabled", because a floor
of zero fires on every observation. → [[alerts]]

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--wps-pin-brute-cycles` | `N` | `5` | WPS PIN attempts (M1→M3→EAP-NACK restart cycles) from one station, or from one UUID-E behind rotating MACs, within **60 s** before `WPS_PIN_BRUTE` fires. [CERT/CC VU#723755](https://kb.cert.org/vuls/id/723755). |
| `--wps-lockout-cycles` | `N` | `2` | Completed AP-Setup-Locked lock→unlock cycles on one BSSID within **1 h** before `WPS_LOCKOUT_CYCLING` fires. An AP that locks once and stays locked never fires. |
| `--wps-pbc-concurrent` | `N` | `2` | Concurrent WPS Push-Button enrollees on one BSSID inside the **120 s** walk time that `WPS_PBC_RACE` fires *above* — the default means the third concurrent enrollee alerts. |

The three `--wps-*` flags above are **aliases** for the `wps.pin_brute_cycles`, `wps.lockout_cycles` and `wps.pbc_concurrent` knobs in the `--tune` registry; they shipped first and still work unchanged. Either spelling sets one value, `--tune-list` shows it, and — the part that was broken until 2026-10-05 — either spelling is recorded in `sensor_health`'s `tuned` and in the health strip, so a WPS threshold raised by flag can no longer silence a detector without appearing in the export. Since #120 they parse through the registry too: `--wps-pin-brute-cycles 5x` exits 2 instead of being read as 5.


The windows are deliberately **not** flags: 60 s is the rate the
brute-force threshold is defined over, one hour is the period the
lockout sawtooth is stated in, and 120 s is the PBC walk time the WSC
protocol fixes (`WPS_PBC_WALK_TIME`). A knob that moved the walk time
would be measuring something the protocol does not do.

### Persistent state — SQLite

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--db` | `FILE` | off | Persist entity state to SQLite. Bounded by fixed tables, not uptime (upsert per entity, not append per tick). Read with `sqlite3`; sloth exposes no query surface. → [[sqlite-schema]] |
| `--db-interval-secs` | `N` | `1` | Seconds between DB write ticks. Raise on slow storage. |
| `--db-retain-days` | `N` | `30` | Age-out window for observation rows. Tiered: entities keep 3×, alerts/credential exposures keep 12×. A random address heard once leaves `devices` after 7 days for a count in `random_devices_daily` (`--tune retention.random_repeat_s`, #239). → [[retention]] |
| `--db-compact-alerts` | `SRC DST` | — | Offline, then exits: write a copy of the database `SRC` to `DST` with `alerts` folded to one row per key (the duplicates a pre-#170 build wrote per evict-and-refire). `SRC` is opened immutable and nothing is written to it or beside it; a non-empty `SRC-wal` or `SRC-journal` (a sensor killed, not stopped) is refused until checkpointed. `DST` (and its `-wal`/`-shm`/`-journal`) must not exist; run as root, `DST` is handed to `SRC`'s owner. Prints the row counts and the time; exit 0, or 1 with the reason. Built without SQLite: exit 2. Swapping `DST` in is the operator's decision: sensor stopped, `SRC-wal`/`-shm` absent.  → [[sqlite-schema]] *Compacting an older file* |
| `--db-max-mb` | `N` | `512` | Size target (MiB), a pruning trigger not a hard cap. `0` = unlimited. Oldest observation rows go first; entity/alert/credential rows never dropped. |

The three `--db-*` flags are aliases for `db.interval_secs`, `db.retain_days` and `db.max_mb` in the `--tune` registry (#120). Until then they were read with `atoi()`: `--db-retain-days abc` became 0, which silently meant "default", and `--db-max-mb 5x` became 5. Each is now validated like `--tune` — a non-integer or an out-of-range value exits 2 naming the knob — and a moved value appears in `sensor_health.tuned`. `--db-interval-secs 0` and `--db-retain-days 0`, which used to fall back to the default, are now refused (ranges start at 1); `--db-max-mb 0` still means unlimited.

### Inventory & ownership — trust anchors

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--inventory` | `FILE` | off | Load approved-inventory JSON (which BSSIDs are authorised for which SSID, #89). The only evil-twin trust input not from the air. All-or-nothing: a malformed file exits. → [[inventory]] |
| `--site` | `TEXT` | off | Operator label for this sensor's location; part of the evil-twin dedup key. Overrides the inventory file's `site`. Config only — never derived from RF. |
| `--my-ssid` | `SSID` | off | Designate your own network (repeatable, max 16). Label only; unlocks `MY_NET_RECON`. Exported on the stream as the `ownership` record (JSONL 1.2.0), which slothweb uses to mark the network "yours". |
| `--my-bssid` | `BSSID` | off | Designate your own AP (repeatable, max 16). Floods at it escalate WARN→CRIT; never named the impostor half of a twin. Exported on the `ownership` record like `--my-ssid`; the `--known-mac` roster travels there as a count only. |
| `--known-mac` | `MAC` | off | Add a MAC to the known-device roster (repeatable, max 512). The host's **own** interface addresses need no flag: every MAC the `iface` records carry - Ethernet, the managed card, the monitor radio - is rostered automatically and exonerates the same way (#183), and on Linux so are each interface's permanent address, each Wi-Fi phy's address pool and wireless devices with no netdev such as a P2P device ([[alerts]], "The sensor's own addresses"). |
| `--known-macs` | `FILE` | off | Load a roster (one MAC/line, `#` comments). With a roster **and** a `--my-ssid`/`--my-bssid`, an associated device not on the roster raises `UNKNOWN_DEVICE`. A bad line is echoed as at most 48 bytes with C0/DEL shown as `?` (#137). |

### Posture — snapshots & research

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--snapshot-out` | `FILE` | off | On exit, write a passive AP-inventory snapshot (BSSID/SSID/security/channel/vendor) for repeat site assessments. Normalised text, no pcap. Created `0600`; an existing file must be private, owned by you, not a symlink — one that is not is refused and left unchanged. SSIDs are escaped (`\t` `\n` `\\` `\xHH`), so an on-air tab or newline cannot add a field or row (#137). Format → [[wifi-sigint-techniques]]; also [[posture-report]] |
| `--baseline-in` | `FILE` | off | On exit, diff the current AP inventory against a prior `--snapshot-out` (new/gone/changed APs). A row whose channel is not 0–255 or mfp not 0–2 is skipped; SSIDs print escaped (#137). |
| `--site-label` | `TEXT` | off | Operator label stamped into `--snapshot-out`, escaped the same way as an SSID. Distinct from `--site`. |
| `--with-research` | `research.db` | off | Load the research corpus so `--report` cites the source behind each fired alert. Opened as an untrusted database: `DEFENSIVE`, `TRUSTED_SCHEMA=0`, no extensions; a file whose `research` is not the FTS5 table, or that holds a view or trigger, is refused (#137). Additive: unreadable or refused corpus warns and continues. → [[research-corpus]] |
| `--check-manifest` | `FILE` | off | Read a locally-populated release manifest (JSON); show "update available" in Help when `latest` > `SLOTH_VERSION`. sloth never fetches — populate `FILE` via cron/systemd. A control byte in `latest` or `url` fails the manifest (#137). → [[manifest-format]] |

### Replay — savefiles instead of interfaces (#119)

Owner ruling 2026-10-15. A **regression and CI harness**: the whole
pipeline (decoders, alert engine, every sink) runs on libpcap
savefiles, with no interface opened. It is not a forensic replay of a
long capture: detection windows run on wall-clock arrival, so every
record in the files arrives at replay time and rate/flood/scan alerts
from a capture spanning hours are not evidence. Decoding, parsing and
per-frame detectors behave as live. → [[replay-integration]]

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--replay` | `FILE[,FILE]` | off | Read up to 8 savefiles instead of opening any interface. Routed by datalink the way the live handles split: Ethernet (1), Linux cooked v1/v2 (113/276) → the IP path; radiotap (127) → the 802.11 monitor path; Bluetooth Linux monitor (254, a tcpdump/Wireshark capture of `bluetooth-monitor`) → the Bluetooth host source, reported as `btmon_iface: replay`; anything else is refused at startup, before a sink opens. Each record keeps its own capture time and wire length in what is exported; detection windows use arrival time (see above). Decoded synchronously before the first tick. **No host state is read**: interfaces, sockets, ARP, DHCP and the Wi-Fi scan come back empty, so the output describes the files and not the machine. `sensor_health` reports `capture_iface`/`monitor_iface` as `replay`. Refused (exit 2) with `--iface`, `--monitor-only`, `--monitor-iface`, `--hop`, `--bt-monitor` or `--bt-capture`, which name live capture, and with `--allow-active`, which would resolve addresses read from the files, and in a `WITH_PCAP=0` build. An unreadable, undecodable or damaged file exits 1 — a replay that stopped part-way is not reported as a replay of the file. |
| `--ticks` | `N` | off (run until quit) | Exit `0` after `N` poll ticks, `1..1000000`; anything else exits 2. The last tick still emits; only the wait after it is skipped. With `--replay --headless` this makes a batch job: replay, tick, flush the sinks and reports, exit. |

### Runtime & meta

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--refresh-ms` | `N` | `250` (~4 Hz) | Dashboard refresh interval, ms. Floor 50. The loop also wakes early on alert fires, so it is an upper bound. |
| `--headless` | — | off | Draw nothing, never touch the terminal (no clears, no escape sequences, no raw-mode termios). For appliance/systemd. Capture, alerting and every sink run normally. |
| `--no-color`, `--no-colour` | — | color on | Suppress colour escapes, keep drawing. Also honoured via `NO_COLOR` env. |
| `--version`, `-V` | — | — | Print version to stdout and exit `0`. Line 1 is `sloth <SLOTH_VERSION>`, unchanged for scripts that read it alone; lines 2–3 (#142) are `pcap: <pcap_lib_version()>` and `sqlite: <sqlite3_libversion()>` — the libraries the dynamic linker **loaded**, `none` in a build without one. → [[release-checklist]] |
| `--print-schema` | — | — | Print the `--db` schema as one SQL script to stdout and exit `0` (#185 item 4): a comment naming `DB_SCHEMA_VERSION`, the DDL of `src/db_schema.c` (`db_schema_sql()`), and the `INSERT` of the `meta` row `schema_version` that a new file is stamped with. Loading it into an empty database gives the tables, indexes and version row `--db` would create; the PRAGMAs a daemon also sets (`auto_vacuum`, `journal_mode=WAL`, `synchronous`, `foreign_keys`) are storage settings and are named in the comment, not emitted. Opens no device, file or database and needs no privilege. The same text in a `WITH_SQLITE=0` build, and byte for byte the same as `sloth-rf --print-schema` (`make contract-check`). It is the contract artifact's `schema.sql` ([[contract]]). |
| `--preflight` | — | off | Check this command line's set-up and exit, starting nothing (#247): each interface named and its monitor mode (whether its phy supports monitor mode, by a read-only nl80211 `GET_WIPHY`), the regulatory domain (`GET_REG`), the clock against the intel pack's date and the kernel's sync flag, `--gps` (a loopback gpsd is connected to and its greeting read; nothing is sent), free space under every output path against `db.max_mb`, the `--db` file's schema (opened `immutable=1`, read-only, never migrated), the intel pack's version, hash and age (warn past 90 days), `pcap-dir-at-rest` / `eapol-dir-at-rest` for each evidence directory (warn when captures are kept over 7 days, which `--pcap-dir`'s default 14 is, on a filesystem with no dm-crypt in its block-device stack; btrfs, ZFS and tmpfs read `not checked`; [[sensor-compromise]]), the `--bt-monitor` / `--bt-capture` / `--replay` / `--baseline-in` sources, the under-voltage alarm and hottest temperature, the passive contract, the `--data-socket` directory, the notification path (none in sloth: `n/a`), and the rule statuses this configuration would have (an expectation, not a measurement). One line per item: `ok`, `warn`, `fail`, `n/a` or `not checked`, and the reason. **Exit `0`** ready, **`1`** ready with warnings, **`2`** not ready. Opens no capture handle, retunes no radio, sets no mode, writes no file, binds no socket, starts no thread; runs without root (a path closed to the account running it reads `not checked`). The whole-command-line checks run first, so a refused combination exits `2` with its usual line and no preflight page. → [[preflight]] |
| `--json` | — | off | With `--preflight`: print the same as one JSON object on one line (`exit`, `verdict`, `checks[]` of `check` / `item` / `level` / `reason`, and `rules` with the counts and every kind that is not observable). Alone it exits `2`. → [[preflight]] |
| `--handoff` | DIR | off | Write a site handoff packet into DIR and exit, starting nothing (#250): `config.json` (the command line, radios, hop plan, positions, designation counts, inventory identity, intel pack, database), `preflight.txt` / `preflight.json` (`--preflight` for this command line, with the rule status counts), `networks.tsv` (designated SSIDs and BSSIDs, the roster), `baseline.tsv` (the `--baseline-in` file), `snapshot.tsv` (the APs `--db` heard in the day before its newest, as a `--baseline-in` file; without `--db`, the `--snapshot-out` file), `findings_open.tsv`, `findings_closed_30d.tsv`, `interference.md` (the last 30 days), `false_positives.txt` (empty: triage is sloth-mesh's) and `README.txt`. DIR is created `0700` or must be an empty private directory; every file is `0600`. `--db` is read-only. No file holds a credential's user name, an RDP cookie, an MQTT user name or an EAP identity, though sloth.db holds them. **Exit `0`** written, **`2`** not (a database that does not open or a refused DIR creates nothing). Not with `--preflight` or `--interference-report`. → [[handoff]] |
| `--verify` | PATH | — | Check and exit (#251), reading only PATH. A file: the `--jsonl-chain` chain, every block against its record, every record against the one before, and the first break named by segment, block and line range (`N` or more unchained lines after a segment's last chain record is one: chain records removed, or a run without the flag appending to the file); each segment's head (one per run, for a report from that run to be compared with), the file's head (the last chain record and its SHA-256), the lines after it not yet chained, and lines no segment covers. A directory: every `sloth-manifest-*.jsonl` in it, `seq` without a gap, and each listed file's SHA-256 against its lines; files listed and missing, and files listed nowhere, are reported, not breaks. **Exit `0`** intact, **`1`** a break, **`2`** cannot verify (unreadable, no chain record, no manifest). Not with `--preflight`, `--handoff` or `--interference-report`. → [[record-integrity]] |
| `--sweep` | LABEL | off | A time-limited sweep of a room or site (#249). Runs the `--preflight` checks in process first (the page on stderr; a `fail` exits `2` before anything opens), then the sweep plan: every 20 MHz channel of 2.4 GHz (1-13) and 5 GHz (36-165, DFS included) once, each for an equal share of `--sweep-minutes` (rounded down to the poll interval, at least 1024 ms), and stops after the one pass or at the time given, whichever first. Then the label's report: every emitter heard (access points, Wi-Fi clients, BLE advertisers) as new, known or missing against the label's accepted baseline, unknown strongest first, cameras / setup mode / hidden names, the coverage statement (each channel's measured time, refusals, channels and bands not swept: 6 GHz and sub-GHz always) and the limits. Files in the sweep directory (0600): `sweep-LABEL.<UTC>.tsv` (this sweep's inventory, a snapshot v2), `.md`, `.json`; the baseline `sweep-LABEL.baseline.tsv` is read, never written (accepting is slothweb's). One `sweep_report` JSONL record. The `--db` session is labelled `sweep:LABEL`. Needs `--hop` and `--sweep-minutes`; refuses `--cue` and `--replay`; not with `--preflight`, `--handoff`, `--verify` or `--interference-report`. LABEL is 1-48 of `A-Z a-z 0-9 . _ -`, not starting with `.` or `-`. Receive-only. → [[sweep-session]] |
| `--sweep-minutes` | N | — | The sweep's time, `1..1440` minutes. Only with `--sweep`. |
| `--sweep-dir` | DIR | the `--db` file's directory | Where the label's baseline is read and the sweep's inventory and reports are written. An existing directory; without it `--sweep` needs `--db`. Only with `--sweep`. |
| `--interference-report` | FILE | off | Write one Markdown section per `RF_DEGRADED`, `RTS_FLOOD` or `GNSS_JAMMING` episode in `--db` (read-only) to FILE (`-` for stdout; else created `0600`) and exit (#250): the times, the channel or transmitter, the retry ratio and control-frame figures the rule recorded (parsed; the alert's detail text is not copied), the radios' time on the channel from `coverage_interval` rows, frames and control frames per minute during and before, the access points on the channel with a client count, and "not located"; at most 200 episodes, the latest. Needs `--db`; `GNSS_JAMMING` after the cutover is in sloth-rf's own database, so name that file to report it. A FILE that is `--db` or its `-wal`, `-shm` or `-journal` is refused. **Exit `0`** written, **`2`** not. → [[handoff]] |
| `--from` | T | — | With `--interference-report`: the window's start, epoch seconds or UTC `YYYY-MM-DD[THH:MM[:SS]][Z]`. Alone it exits `2`. |
| `--to` | T | — | With `--interference-report`: the window's end, as `--from`, including what it names: `2026-11-24` runs to 23:59:59 that day and `THH:MM` to the minute's last second, so `--from D --to D` is the day D. Before `--from`, or alone, it exits `2`. |
| `--help`, `-h` | — | — | Print usage and exit `0`. |

## Keybindings (runtime TUI)

### View selection

| Key | View | Key | View | Key | View |
|-----|------|-----|------|-----|------|
| `1` Interfaces | `d` DHCP | `u` QUIC | `l` OSI stack |
| `2` Connections | `s` SSDP | `r` DNS | `x` Twins |
| `3` WiFi | `b` Beacons | `p` NTP | `y` KARMA |
| `4` Packets | `a` Deauth | `i` ICMP | `z` Rogue RADIUS |
| `5` Processes | `h` HTTP | `v` Alerts | `c` FragAttacks |
| `6` Stats | `t` TLS | `g` Devices | `f` Research |
| `7` Probe | `k` PNL | `o` Dashboard | `?` Help |
| `8` ARP | `e` EAPOL | `m` Channel | |
| `9` mDNS | `j` Seqnum | `w` Assoc | `*` BLE |
| `0` NBNS | | | `#` GNSS |

`*` is BLE and `#` is GNSS because every letter and digit already
selects a view or is a global (`b` is Beacons). `^` selected the ADS-B
view until the cutover (#216); the aircraft table is `sloth-rf`'s, which
is headless, and is read in slothweb, so the key selects nothing now.
Full map with descriptions: [[views-catalog]].

### Global keys

| Key | Action |
|-----|--------|
| `Tab` | Cycle views forward |
| `n` | Toggle DNS hostname resolution (conn/proc/stats views) |
| `/` | Filter current log view — type to refine, `Enter` commit, `Esc` cancel |
| `\` | Clear filter |
| `q` / `Q` | Quit |
| `?` | Toggle Help |

### Per-view keys

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate rows |
| `c` | Clear the current log view's ring buffer |
| `t` | (Interfaces) toggle iface visibility (display-only) |
| `y` | (Interfaces) toggle iface data-stream selection — drops its packets pre-decode |
| `m` | (Interfaces) retarget the 802.11 monitor radio onto the selected iface; refused, leaving a running radio alone, when a non-empty `--iface` allow-list excludes it — the reason shows as the probe error |
| `Enter` | (Interfaces / Packets) open detail panel; (Devices) open the device detail — camera signal trail, ONVIF scopes, mDNS, SSDP `SERVER`, RTSP exposure; `Enter` / `Esc` returns ([[camera-detection]]); (BLE) open every decoded field of the selected advertiser, `Enter` / `Esc` returns ([[ble]]) |
| `f` | (Conns / Packets) cycle filter |
| `s` | (Conns) cycle sort |
| `g` | (EAPOL) show the selected row's harvest cluster alone, with a one-line summary; again for every row. Claimed over the global Devices switch (#172, `docs/views/eapol.md`) |

A view can *claim* a key the global switch also uses; see
`src/view_route.c` and the "add a view" checklist in `AGENTS.md`.

## Status badges

The tab bar carries one status badge today, drawn immediately after the
` sloth v<version>` banner at full alert heat (`tui_heat(1.0)`):

| Badge | Meaning |
|-------|---------|
| `!persist jsonl:N pcap:N eapol:N` | An on-disk export sink has failed a write, **or was refused one**. Each `N` is that sink's **lifetime** failure count for this run of sloth: it never resets, and there is no rate or recent-window form of it. The refusal case is `pcap:N` only, and only when a `storage.min_free_mb` / `storage.min_free_inodes` floor is set: `src/alert_pcap.c` routes a pre-write capacity refusal through the same `sfile_fail()` counter, so that `N` can count dumps that were never attempted rather than dumps that failed. Both are "evidence you do not have", which is why they share a counter. |

How `persist_badge()` (`src/persist_health.c`) formats it:

- **Only failing sinks appear.** A healthy sink is omitted entirely, so
  `!persist pcap:2` says the JSONL log and the EAPOL exports are fine
  and two per-alert pcap dumps failed. With all three healthy the whole
  badge is absent rather than zeroed, so the bar is quiet when there is
  nothing to say.
- **The sink order is fixed** — `jsonl`, then `pcap`, then `eapol` —
  independent of which failed first or which count is larger.
- **Worked example.** Three JSONL write failures, one failed per-alert
  pcap and two failed EAPOL exports render as
  `!persist jsonl:3 pcap:1 eapol:2`.
- **It cannot disagree with the log.** The badge reads the same
  accessors that `sensor_health.storage_failures` sums in the JSONL
  stream, per sink as `storage_jsonl_failures`,
  `storage_pcap_failures` and `storage_eapol_failures`
  ([[jsonl-schema]]).
- **Where it is drawn.** On the tab bar of every view that has one,
  in both front ends. Under ncurses the dashboard (`[o]`, the startup
  view) has no tab bar — `tui_draw()` gives it the whole screen — so
  it draws the same badge right-aligned on its **Interfaces** title
  rule, and under its "terminal too small" notice when the terminal
  cannot hold the tile (`draw_persist_badge`,
  `src/views/dashboard_bands.c`). Until 2026-10-19 it did not, and the
  badge was seen only after a switch to a detail view. The ANSI
  fallback (`WITH_NCURSES=0`) draws the bar on every view.
- **Truncated by whole sinks on the dashboard.** When the Interfaces
  title is too short for every failing sink, the dashboard drops
  whole `sink:N` tokens from the right and ends the badge with `+`
  (`!persist jsonl:3 pcap:1+` means at least one more sink failed),
  never cutting a count to its leading digits. If not even one token
  fits, it shows the bare `!persist`.

The badge is the only signal **on the tab bar**, but not the only one
anywhere — three others carry the same fact, and an integrator should
prefer whichever suits their consumer:

- one stderr line per sink on its first failure, `sloth: <sink> export
  failed: <reason>`, behind a `reported` latch (`src/secure_file.c`);
- `storage_failures` plus the per-sink `storage_jsonl_failures` /
  `storage_pcap_failures` / `storage_eapol_failures` on every
  `sensor_health` record (`src/jsonl.c`, `src/jsonl_core.c`), and
  `pcap_write_failures` on an alert record (`src/jsonl_core.c`);
- `pcap_dir_free_mb` and `pcap_dir_free_inodes` on `sensor_health`,
  which is the only one that says anything *before* a write fails.

What the badge genuinely is alone in doing is being visible to an
operator watching a terminal. And in every one of these, a failing sink
is still not disabled, not throttled and not retried any differently —
only a configured `storage.*` floor refuses anything in advance. See
[[retention]] § 6.

## Environment variables

| Var | Effect |
|-----|--------|
| `NO_COLOR` | Any non-empty value disables colour (read before flags). |
| `RISK_THRESHOLD` | Converge-loop risk gate threshold (default 50) — tooling, not the binary. See `agents/FACTORY.md`. |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean exit (incl. `--version`, `--print-schema`, `--help`, and the end of a `--ticks N` run). `--preflight`: ready. `--handoff`, `--interference-report`: written. `--verify`: intact. |
| `1` | `--preflight`: ready with warnings. `--verify`: a break. `--sweep`: the run did not start, or its inventory or a report was not written (stderr names which). A `--replay` file that cannot be opened, is not a savefile, has a datalink with no route, or is damaged part-way (#119). |
| `2` | `--preflight`: not ready (a `fail` line). `--handoff`, `--interference-report`: not written. `--verify`: cannot verify. `--sweep`: the preflight failed. Bad argument, or a fail-closed refusal (`--json` without `--preflight`; `--sweep` without `--hop`, `--sweep-minutes` or a sweep directory, with `--cue`, `--replay` or an offline command, a bad LABEL or N, the label's baseline there but not readable (checked before the preflight), `--sweep-minutes` or `--sweep-dir` without `--sweep`; two of `--preflight`, `--handoff`, `--verify` and `--interference-report`; `--jsonl-chain` without `-o`, outside `1..100000`, or with `--out-format cef` or `syslog`; `--from` or `--to` without `--interference-report`, or not a time; `--interference-report` without `--db`, or with a FILE that is `--db` or its `-wal`, `-shm` or `-journal`; one of the six decoder flags, which are `sloth-rf`'s since #216: § Refused; `--monitor-only` with no monitor iface, malformed `--inventory`/`--known-macs`, a refused output path, `--strict --allow-active`, `--strict` with a routable `--data-socket`, `--eapol-dir` without `--collect-handshakes`, `--pcap-dir` and `--eapol-dir` naming one directory (#166), a `--handshake-retention` value outside `0..36500`, a `--correlate-retain`/`--db-*`/`--wps-*` value that is not an integer inside its knob's range (#120), a `--user` naming no account or needing root it does not have, `--user` with `--no-privdrop`, a privilege drop that failed or did not read back, `--iface` naming a raw HCI device `bluetoothN`, a `--monitor-iface` naming a radio twice, given more than four times, not an interface name, naming `bluetoothN`, with `--replay` or in a `WITH_PCAP=0` build, or naming a further radio that `--df-iface` also names, `--bt-monitor` with `--replay` or in a `WITH_PCAP=0` build, a `--location` outside its ranges, a malformed `--gps` SPEC, `--gps` with `--replay`, a `--gps` device that cannot be opened, a non-loopback gpsd without `--gps-allow-remote` or under `--strict`, a `--gps-baud` outside its list, a malformed or unsupported `--adsb` SPEC (a non-loopback `sbs://` or `beast://` host), `--adsb` with `--replay`, a malformed `--aprs` SPEC, `--aprs` with `--replay`, a malformed `--rtl433` SPEC, `--rtl433` with `--replay`, a malformed `--victron` SPEC, `--victron` with `--replay`). |

## sloth-rf

`sloth-rf` is the RF half of the sensor as a daemon of its own (#213,
[ADR 0010](adr/0010-wifi-rf-daemons.md), [[architecture-rf-split]]): it
reads a GNSS receiver, the files or loopback sockets that readsb,
Dire Wolf and rtl_433 write and the file `sloth-va` writes, and makes the JSONL records, database rows
and alerts for them. Since the cutover (#216) it is the only daemon
that does: `sloth-wifi` refuses the six decoder flags. It opens no radio, tunes
no SDR and transmits nothing (`MISSION.md` §2); the one line it writes
to a peer is gpsd's `?WATCH`, announced. It has no terminal interface:
slothweb is its interface: `slothweb --rf-socket SPEC --rf-db PATH`
reads it beside `sloth` (#214, § slothweb).

It is built by a plain `make` beside `sloth-wifi`, installed by `make
install` and run by `sloth-rf.service` ([[deployment]] §11). Both
daemons take `--gps`, so the two must not be pointed at one serial GPS
(a serial device opens once; both can read gpsd).

Every flag `sloth-rf` shares with `sloth-wifi` (the receiver's, `-o`,
`--db`, `--data-socket`, `--strict`, `--tune`, `--user`,
`--no-privdrop`, `--ticks`) is read and refused by the same function
(`src/gnss_flags.c`, `src/daemon_start.c`), so the meaning, the refusal
text and the exit code are those of the `sloth-wifi` rows above. The
messages say `sloth:` in both daemons, the decoder flags' included
(`src/rf_flags.c`): it is the prefix every shared module already
prints, and it is what makes the shared refusals the same bytes.
`make replay-check` runs both binaries on the command lines both
refuse and compares stderr, runs the six decoder flags through both
(`sloth-wifi` refuses each, `sloth-rf` takes each), and holds `sloth`
to being a symlink that answers as `sloth-wifi` does
(`tests/replay/rf_refusals.sh`); `--jsonl` both refuse as an unknown
argument.

| Flag | Arg | Default | Effect |
|------|-----|---------|--------|
| `--adsb` | `SPEC` | off | Read a local, already-running ADS-B decoder (readsb, dump1090-fa) ([[adsb]]). `SPEC` is an absolute path or `file:///path` to its `aircraft.json`, or `sbs://[HOST[:PORT]]` for its SBS / BaseStation TCP output, or `beast://[HOST[:PORT]]` for its Beast binary output. **File**: opened afresh about once a second (`ADSB_POLL_MS`; the decoder replaces it by rename), read-only, by a worker started after the privilege drop; a regular file of at most 2 MiB, else counted as a read error; no network. **`sbs://`** (2026-11-09): `HOST` a numeric loopback address (`127.0.0.0/8` or `[::1]`), default `127.0.0.1:30003` (readsb's SBS port); a TCP client started after the privilege drop that **never writes a byte to the socket**, announced on stderr; a refused connect or a closed session is a read error, retried after 2 s (doubling to 30 s while the connect keeps failing); lines over 512 bytes and malformed lines are parse errors, not fatal; `live` while any line, readsb's 60 s heartbeat included, arrived in the last 130 s. Under `sloth-sensor.service` it needs `AF_INET` (`AF_INET6` for `[::1]`) added to `RestrictAddressFamilies=` by a drop-in. **`beast://`** (2026-11-09): the same rules, default `127.0.0.1:30005` (readsb's `--net-bo-port`); sloth frames the stream and decodes the Mode S frames itself (CRC-24 with no bit correction; DF17/18 only intact; DF4/5/20/21 only for an address a clean DF17 or DF11 confirmed in the last 60 s; CPR from an even/odd pair within 10 s, then locally against the aircraft's own last fix); garbage, unknown frame types and cut frames are parse errors, CRC failures `bad`, never fatal; `live` while any frame, readsb's 60 s Mode A/C heartbeat included, arrived in the last 130 s. sloth never opens or tunes the SDR. A missing file or an unreachable port is not a refusal: the `adsb` sensor and `sensor_health`'s `adsb_state` read `error` until it appears. Emits `adsb_aircraft` (change-only) and `adsb_*` in `sensor_health`. Refused (exit 2) with `--replay`, for a relative path, a directory path, `file://HOST/`, any other scheme, an `sbs://` or `beast://` host that is a name or not loopback, or a port outside 1..65535. |
| `--aprs` | `SPEC` | off | Tail the packet log a local, already-running Dire Wolf APRS decoder writes (`direwolf -L FILE`, one CSV line per decoded packet; [[aprs]]). `SPEC` is an absolute path or `file:///path`. Checked about once a second (`APRS_POLL_MS`) by a worker started after the privilege drop, read-only: the first look starts at the file's end (its history is not replayed; sloth.db already holds what an earlier run read), a file that appears later or a new file at the path (rotation) is read from its start, a file that shrank (logrotate `copytruncate`) from 0; at most 256 KiB a poll, lines over 1024 bytes counted bad. sloth never touches the radio, the SDR or Dire Wolf and uses no network. A missing file is a state, not a refusal (`aprs_state` `waiting`; Dire Wolf creates the file with its first packet); an unreadable one reads `error`. Emits `aprs_packet` (one per packet), `aprs_station` (change-only) and `aprs_*` in `sensor_health`; with `--db`, `aprs_stations` and `aprs_packets`. Refused (exit 2) with `--replay`, for a relative path, a directory path, `file://HOST/` and any other scheme. |
| `--aprs-freq` | `HZ` | not declared | The frequency the Dire Wolf decoder is **configured** for, in Hz, `144000000`..`148000000` (#204; [[aprs]] § The channel). On the reference host that is `APRS_FREQ` in `/etc/default/aprs`, not `rx_fm`'s reported hardware tune, which sits fs/4 above it (about 144.894 MHz for 144.390) and is normal. sloth compares it with the APRS channel of the region its GNSS position falls in and sets `aprs_freq_mismatch` 1 in `sensor_health` when they are more than 6.25 kHz apart; it never changes the decoder. Decimal Hz only (`144.39` is refused). Needs `--aprs` (exit 2 without it, or out of range). |
| `--aprs-silent-hours` | `N` | `6` | Report the decoder **silent** (`aprs_silent` 1 in `sensor_health`, a notice on slothweb's APRS tab) when its log is readable (`aprs_state` `live`) but no packet arrived for `N` hours, counted from the newest packet or this run's first read, whichever is later. `0` turns it off; `1`..`168`. Six hours is six times the quiet hour the state already tolerates and catches a dead receive chain the same day ([[aprs]] § Silent). Needs `--aprs`. |
| `--rtl433` | `SPEC` | off | Tail the JSON event log a local, already-running `rtl_433` writes (`rtl_433 -F json`, one JSON object per decode; [[rtl433]]). `SPEC` is an absolute path or `file:///path`. Checked about once a second (`RTL433_POLL_MS`) by a worker started after the privilege drop, read-only: the first look starts at the file's end (its history is not replayed), a file that appears later or a new file at the path (rotation) is read from its start, a file that shrank (logrotate `copytruncate`) from 0; at most 256 KiB a poll, lines over 1024 bytes counted bad. **sloth never opens, tunes, hops or runs the SDR** - `rtl_433` owns it - and uses no network. A missing file is a state, not a refusal (`rtl433_state` `waiting`; `rtl_433` creates the file with its first decode); an unreadable one, or anything that is not a regular file, reads `error`. Each line is keyed `(model, id)` into a table of 256 rows that drops the least recently heard on full (`evict_rtl433`); a line that is not one JSON object, or that carries no usable `model` or `id`, is a bad line with its own `rtl433_rej_*` counter. Emits `rtl433_device` (change-only) and `rtl433_*` in `sensor_health`. Refused (exit 2) with `--replay`, for a relative path, a directory path, `file://HOST/` and any other scheme. |
| `--victron` | `SPEC` | off | Tail the JSONL the `sloth-va` helper appends to (`/var/lib/sloth-va/victron.jsonl`; [[victron]]): the owner's Victron readings, decrypted Instant Readout (`source` `readout`) and GATT sessions (`gatt`). `SPEC` is an absolute path or `file:///path`. The same tail as `--rtl433` (once a second, from the end at startup, rotation and truncation followed, at most 64 KiB a poll, lines over 2048 bytes bad). **sloth only reads the file**: sloth-va is the separate component that connects to the devices ([ADR 0011](adr/0011-sloth-va-transmits.md)); sloth opens no Bluetooth socket for this and decrypts nothing. A missing file is `waiting`. One row per device address, at most 16 (a 17th is counted, `victron_table_full`, never evicting); values only from an allow-list with bounds, out of range absent (`victron_bad_values`), other names counted (`victron_other_keys`); the device's own name (`label`) is not kept. Emits `victron_device` (change-only, values banded) and `victron_*` in `sensor_health`. Refused (exit 2) with `--replay` and for a malformed SPEC. |
| `--no-sdr-trim` | — | off (trim on) | Turn off the **startup trim** (2026-11-18, owner: "have sloth-rf trim itself depending on what sensors are installed at startup"; `src/rf_trim.h`). By default, once at startup and before any reader is configured, sloth-rf reads `idVendor` / `idProduct` of every device under `/sys/bus/usb/devices` (regular files through the receiver inventory's guard; no libusb, no device opened) and looks for one `sys_usb_table[]` calls an SDR (RTL2832U `0bda:2832` / `0bda:2838` and the RTL2832U sticks sold under their makers' IDs that osmocom librtlsdr drives, Airspy, HackRF, SDRplay, LimeSDR / XTRX, bladeRF, USRP, PlutoSDR, FUNcube, Perseus, HydraSDR; every `ID_SOFTWARE_RADIO` row of systemd's `hwdb.d/70-software-radio.hwdb`, plus usb.ids, `src/sys_status.c`). With none, a **file** `--adsb`, `--aprs` (with its `--aprs-freq` and `--aprs-silent-hours`) and `--rtl433` are not started: one stderr line names each and why, and its `source_status` row reads `not_installed` with the SPEC as `endpoint`, which `SENSOR_SOURCE_DOWN` never judges. Never trimmed: `--adsb sbs://` and `beast://` (what feeds the socket may take its samples from an SDR on another machine), `--gps`, `--location`, `--victron`. **Kept although no SDR is found** (fail open, owner 2026-11-18): a trim candidate whose file was modified within its window of startup — 10 minutes for `--adsb` (readsb rewrites `aircraft.json` about once a second while it runs), 24 hours for `--aprs` and `--rtl433` (Dire Wolf and rtl_433 write only on a decode; a quiet channel can be silent overnight) — or whose mtime is ahead of the clock (skew). Something other than a local USB SDR may be writing it: Dire Wolf on a sound-card TNC, readsb net-only, rtl_433 on `rtl_tcp` or SoapyRemote. It is `stat()`ed only, and the run says `sloth-rf: --aprs PATH kept: no SDR on USB but its file was written N s ago (another feed writes it; trimmed when unwritten for 86400 s)`. A file `stat()` fails on for a reason other than absence (`EACCES`: an unsearchable directory, a `/home` path under the unit's `ProtectHome=true`) is kept as well, with `… could not be checked (…); its reader reports it`, so its row shows the real cause rather than "no SDR". A missing file (`ENOENT`, `ENOTDIR`), or one older than its window, is trimmed (`RF_TRIM_FRESH_ADSB_S`, `RF_TRIM_FRESH_EVENTS_S` in `src/rf_trim.h`). A sysfs that cannot be listed (or lists 256 entries or more), or a device whose ID cannot be read when no SDR is found, trims nothing; a SPEC that does not parse is not trimmed, so it is refused as on any host. With an SDR present the run says which (`sloth-rf: SDR attached: …; decoder inputs kept`). If the trim removed an input and nothing is left to read (no decoder, no `--victron`, no `--gps`), sloth-rf prints why and runs on idle, as a run given no input does, so its socket serves the `not_installed` rows (an exit would leave slothweb's `--rf-socket` retrying, its sensor tile bad and the rows unread). **Startup only**: an SDR plugged in later needs `systemctl restart sloth-rf`. Give this flag on a host whose SDR has an ID the table lacks. |
| `--gps` | `SPEC` | off | As `sloth`'s ([[gnss]], [[location]]). Here it also feeds the `gnss_fix` / `gnss_sky` / `gnss_sat` records and the four `GNSS_*` rules, which are sloth-rf's after cutover. A serial device is opened before the privilege drop, as in `sloth`. |
| `--gps-allow-remote` | — | off | As `sloth`'s. `--strict` refuses a remote gpsd regardless. |
| `--gps-baud` | `N` | 9600 | As `sloth`'s. |
| `--location` | `LAT,LON[,ALT]` | off | As `sloth`'s. Stamps this daemon's alerts and gives the APRS region check a position without a receiver. |
| `-o`, `--out` | `FILE` | off | As `sloth`'s: append the JSONL record stream to `FILE`. Created 0600; an existing file must be private and the run's own. There is no `--jsonl` spelling: it is `unknown argument`, exit 2, in both daemons. |
| `--jsonl-chain` | `N` | off | As `sloth`'s: a hash chain over the `-o` file, `N` records a block (#251); without `-o`, exit 2. `sloth --verify FILE` checks it. → [[record-integrity]] |
| `--db` | `FILE` | off | A SQLite database with sloth's own DDL and `DB_SCHEMA_VERSION` ([[sqlite-schema]]). The `gnss_*`, `adsb_*`, `aprs_*`, `sensors`, `alerts` / `alert_incidents`, `sessions` and `sensor_positions` tables fill; every capture table (`devices`, `device_positions`, `beacon_aps`, …) stays empty, because no stage of this daemon builds a device. The `--db-*` alias flags are not taken: use `--tune db.max_mb=N`, `db.retain_days=N`, `db.interval_secs=N`. |
| `--site-label` | `TEXT` | — | Label for the `--db` session row. |
| `--data-socket` | `[SPEC]` | off | As `sloth`'s, with its own default: bare, it is `unix:/run/sloth-rf/sloth-rf.sock`, refused (exit 2, with the remedy naming `RuntimeDirectory=sloth-rf`) when `/run/sloth-rf` is absent or not owned by root or this user. The remedy's explicit transport is `tcp:127.0.0.1:PORT`, a port of its own: 8765 is `sloth`'s. Never TCP by default, and never advertised over mDNS. |
| `--data-socket-allow-remote` | — | off | As `sloth`'s. |
| `--strict` | — | off | Refuses a remote gpsd and a routable `--data-socket`, as in `sloth`. The rest of what `--strict` locks in `sloth` (the resolver, the scan trigger) does not exist here. |
| `--tune` | `NAME=VALUE` | — | As `sloth`'s; the registry is shared, so `--tune-list` prints every knob, of which this daemon reads the `gps.*`, `gnss.*`, `adsb.*`, `db.*` and `socket.*` ones. |
| `--no-preliminary` | — | lifecycle on | As `sloth`'s (#245): here it turns off `GNSS_JAMMING`'s preliminary (the indicator before its hold), the lapse and the `state` / `value_period_s` fields. |
| `--value-period` | `KIND=SECS` | 300 | As `sloth`'s. |
| `--questions` | `PATH` | the seven defaults | As `sloth`'s (#244). This daemon answers only the questions one of whose kinds it raises (with the defaults, Q6 and Q7). |
| `--tune-list` | — | — | Print every knob, then exit 0. |
| `--user` | `NAME` | `sloth` | As `sloth`'s. Nothing here keeps a capability after the drop. |
| `--no-privdrop` | — | off | As `sloth`'s. |
| `--ticks` | `N` | run until a signal | Exit 0 after `N` poll ticks. |
| `--version`, `-V` | — | — | `sloth-rf <version>` and the loaded sqlite. No `pcap:` line: it loads no libpcap. |
| `--print-schema` | — | — | As `sloth-wifi`'s, and the same bytes: both daemons' databases are created from one DDL (`src/db_schema.c`) at one `DB_SCHEMA_VERSION`. Exit 0. |
| `--help`, `-h` | — | — | Usage, on stderr; exit 0. |

The six decoder rows were written when the one binary took those
flags and are unchanged: where a row says `sloth` reads, sends or
refuses something, the daemon is `sloth-rf`.

Anything else is `unknown argument:` and exit 2, including every flag
of `sloth-wifi`'s capture (`--iface`, `--hop`, `--allow-active`,
`--bt-monitor`, `--replay`, `--pcap-dir`, `--headless`, …): a daemon
that accepted `--hop` and did nothing would read as one that can retune
a radio.

What it writes, and how that differs from `sloth`'s stream:

- **Records**: `gnss_fix`, `gnss_sky`, `gnss_sat`, `adsb_aircraft`,
  `aprs_packet`, `aprs_station`, `rtl433_device`, `victron_device`
  (with `--victron`), `sensor`, `alert` and the `alert.*` lifecycle,
  `sys_status`, `sys_sensor`, `receiver_hw`, `source_status` and
  `sensor_health`. The first eight are this daemon's alone since JSONL
  2.0.0: `sloth-wifi`, given the same inputs, writes none of them
  (`tests/test_rf_loop.c`).
- **`sensor_health`** says `"daemon":"rf"` and carries the process,
  receiver and decoder blocks only ([[jsonl-schema]]).
- **`source_status`** has five rows (`gnss`, `adsb`, `aprs`, `rtl433`,
  `victron`; `adsb`, `aprs` and `rtl433` read `not_installed` when the
  startup trim took them, JSONL 2.5.0); `sloth-wifi`'s has five too (`capture`, `monitor`,
  `btmon`, `btcap`, `gnss`). `gnss` is in both, and the other four of
  each are in that daemon's stream only. `sys_status`'s `sources`
  counts the daemon's own.
- **Alerts**: `GNSS_JAMMING`, `GNSS_TIME_JUMP`, `GNSS_POSITION_JUMP`,
  `GNSS_SPOOF_SUSPECT`, `ADSB_EMERGENCY` and `SENSOR_SOURCE_DOWN` for
  its five sources. Not `SENSOR_UNDERVOLT` (owner ruling 2026-11-15:
  the host has one supply and the daemon with the capture reports it).
- **Signals**: SIGINT and SIGTERM stop it cleanly (readers, then the
  sinks, in `sloth`'s order). SIGUSR1 is ignored; `sloth` writes its
  report on it and this daemon has none.

Exit codes are `sloth-wifi`'s: `0` clean (and `--help`, `--version`,
`--print-schema`, `--tune-list`, the end of `--ticks N`, and a start
whose inputs the startup trim left empty: see `--no-sdr-trim`), `1` a sink that could not be
opened, `2` a bad argument or a fail-closed refusal.

## slothweb

slothweb, the browser dashboard, is a separate binary with its own
flags, listed with every start-up message in sloth-mesh's `README.md`
("Command line", "Troubleshooting"); it is sloth-mesh's since #235. Since 2026-10-27 it takes
`--pcap-dir DIR` (repeatable once): the sensor's `--pcap-dir` (and,
optionally, its `--eapol-dir`), read-only, for the alert page's packet
capture ([[pcap-export]] §6, [[slothweb]]). An evidence pcap from the
`--eapol-dir` may hold EAPOL/PMKID handshake material, so it is listed
but withheld unless slothweb also gets `--web-serve-evidence-pcap`
(announced on stderr); with `--web-allow-remote` that flag exits `2`
unless given as `--web-serve-evidence-pcap=remote` (2026-11-02).
Since 2026-11-10 (#192 F1, [[fleet]]) slothweb serves
`/api/fleet/export` to its allow list and, with `--peer NAME=URL`
(repeatable, at most 8, a tailnet `100.64.0.0/10` address unless
`--peer-allow-outside-tailnet`, which is announced), pulls the
operator's other slothwebs every `--peer-interval-secs` (default 60)
into its own store; a peer outside the tailnet, or any under
`--strict`, exits `2`. Since 2026-11-11 (#192 I6) `--peer-gnss-region-km N`
(1..20000, default 50) is how far apart two sites may be for a GNSS
event seen at both within 120 s to be called regional; a value outside
the range exits `2`.
Since 2026-11-19 (#205, [[post-protocol]]) `--post HOST:PORT`
(repeatable, at most 8, a tailnet address unless
`--post-allow-outside-tailnet`, which is announced) reads a sloth-ios
sensor post's one-way stream, never writing to it, into the roster at
`/api/posts`; any `--post` under `--strict` exits `2`.
Since 2026-11-15 (#214, [ADR 0010](adr/0010-wifi-rf-daemons.md))
`--rf-socket SPEC` and `--rf-db PATH` name sloth-rf's data socket and
database, read beside `--socket` and `--sloth-db` and never written.
Neither has a default: without them slothweb reads one stream and one
database, as before. With `--rf-socket` the GNSS, ADS-B, APRS, rtl_433
and Victron tabs are fed from sloth-rf's stream only; with `--rf-db`
their history and the fleet's aircraft and GNSS incidents are read
from its file. A socket or a file that is not there is retried or
reported, not fatal. `--strict` refuses a non-loopback `--rf-socket`;
`--rf-socket` naming `--socket`'s socket (its default included), or
`--rf-db` naming `--sloth-db`'s or `--store`'s file, exits `2`. The SQL
box stays on `--sloth-db` ([[slothweb]] § Two daemons).
Since 2026-11-11 `--web-agent-secret PATH` lets an agent on the same
machine write through `slothweb-mcp`: slothweb writes a per-run secret
to `PATH` (`0600`, replaced every start, removed at exit; a path
holding anything but its own private file exits `1`), and a loopback
POST carrying it may write triage, notes and links, recorded `via:
agent` ([[slothweb-mcp]] section 4). `--web-agent-group NAME` (needs
`--web-agent-secret`) writes it `0640` in group `NAME` instead, so
`slothweb-mcp` can run as a member of `NAME` with no sudo rule;
slothweb's own user must be a member too, and an unknown group or one
it cannot give exits `1` ([[slothweb-mcp]] section 7).

### slothweb-mcp

sloth-mesh's `make mcp` builds `slothweb-mcp`, an MCP server (stdio,
newline-delimited JSON-RPC) that is a client of slothweb's HTTP API
on loopback ([[slothweb-mcp]]). Not in its `make` or its install.

Its flags, in prose because this page's tables are `sloth`'s own flags
(a test holds every table row to `src/main.c`):

- **`--url URL`**: slothweb's address, `http://` and a literal IPv4 or
  `[IPv6]` address with an optional port; default
  `http://127.0.0.1:8770`. No name is resolved. Not loopback: exit `2`
  unless `--allow-remote`.
- **`--allow-remote`**: read a slothweb on another host (in the clear:
  slothweb has no TLS). Writes still fail: the agent secret is taken
  from loopback peers only.
- **`--from-loopback`**: connect from `127.0.0.1` (`::1` for a V6
  address), for a slothweb bound to this host's own address (a
  Tailscale `--web-bind`): slothweb then sees a loopback peer and takes
  the agent secret. A loopback source reaches this host only, so a
  non-loopback `--url` needs no `--allow-remote` with it.
- **`--agent NAME`**: the name writes are recorded under, 1..32 bytes
  of UTF-8 with no control characters (exit `2` otherwise). Without it
  the write tools refuse.
- **`--secret-file PATH`**: the file `slothweb --web-agent-secret PATH`
  wrote; read at each write; must be `0600` and the running user's own,
  or `0640` in a group the running user is in (`slothweb
  --web-agent-group`). Without it the write tools refuse; a file the
  user may not open is `secret_no_access`, "check group membership".
- **`--read-only`**: no write tools: not listed, not callable.
- **`--help`**, **`-h`**: usage, on stderr.

An unknown or incomplete argument exits `2`.
Since 2026-11-11 (#192 I2, I3) slothweb takes `--my-ssid SSID` and
`--my-bssid MAC` too (repeatable, at most 16 of each, as sloth), the same values as
sloth's flags of those names, which `sloth.db` and the stream do not
carry: this site's own networks, named to a peer that asks with
`ident=1` (they travel under the owner's monitor-only rule, ADR 0009)
and the baseline of the fleet's identity findings
(`/api/fleet/findings`). An SSID of 0 or more than 32 octets or with a
control character, a BSSID that is not six hex octets, or a seventeenth of
either exits `2`; any given is announced on stderr. Set both: slothweb
does not read sloth's flags, so a network named to one and not the other
is the sensor's own to sloth and a stranger's to the fleet, or the
reverse.

## Build variants (Makefile)

Not runtime flags, but part of the command surface:

```sh
make                 # full: ncurses + pcap + nl80211
make WITH_NCURSES=0  # headless / embedded (ANSI fallback)
make WITH_PCAP=0     # no capture, no probe view
make WITH_WIFI=0     # no nl80211
make WITH_SQLITE=0   # no --db
make embedded        # shortcut: no ncurses, no pcap
make test            # sloth_test — no root/tty/net; built WITH_NCURSES + WITH_PCAP,
                     #   views drawn offscreen, capture path included (#116)
make test-capture-path  # alias for `make test`, kept one release (#116)
make sloth_test_noflags # the suite without ncurses/pcap — link-only, never run
make mutate          # mutation-test the suite (opt-in, offline)
make replay-check    # run `sloth --replay` on generated savefiles, diff
                     #   the normalised JSONL against tests/replay/golden.jsonl (#119)
make replay-golden   # rewrite the golden from the current tree (review the diff)
make bench           # time seqnum correlation + PNL union at full table
                     #   occupancy, -O2 (#91; BENCH_ITERS=n, figures in [[ring-buffers]])
make deploy-test     # packaging/bin/sloth-migrate-sensor against a scratch root
                     #   with stub systemctl etc.; unprivileged (#153, [[deployment]] §4)
make install         # sloth, the monitor-mode helper, sloth-ble-scan, research.db and
                     #   the alert assessments under $(PREFIX) (#139, #153)
make install-service # sloth-sensor.service, sloth-ble-scan.service (installed, not
                     #   enabled), the sysusers fragment, /etc/default/sloth (only if
                     #   absent); slothweb's binary and unit install from sloth-mesh (#235)
```

`make` on Linux also builds `sloth-ble-scan`, the operator's
passive-scan helper for `--bt-monitor` ([[ble]], [[deployment]] §7). It
is not part of `sloth` and sloth never runs it:

```sh
sloth-ble-scan [--delay SECS] [hciN]  # take hciN's HCI user channel and hold a PASSIVE
                                      #   LE scan until SIGTERM/SIGINT/SIGHUP (default hci0;
                                      #   --delay 0..60 waits before taking the channel)
sloth-ble-scan --down [hciN]          # bring hciN down (HCIDEVDOWN), so the channel can be taken
```

Needs `CAP_NET_ADMIN`. A bind refused with `ENODEV` (hciN not
registered yet) or `EBUSY` (still in setup, or bluetoothd holding it) is
retried once a second for up to 30 s, then fails; `--down` on an
unregistered hciN succeeds with nothing to do. `hciN` is one argument:
an empty one is a usage error, not hci0. Exit 0 stopped by a signal, 1
failure (the channel could not be taken, a refused command, the
controller went away, a Hardware Error five times in a minute), 2
usage.

`packaging/bin/sloth-migrate-sensor` takes `--dry-run`,
`--data-socket-unix` (move an old unit's `tcp:` data socket to
`unix:/run/sloth/sloth.sock`; without it a `tcp:` socket is refused) and
`--with-slothweb` (install, start and verify `slothweb.service` after the
sensor verifies); exit 0, 1 (rolled back), 2 (refused), 3 (sensor done,
slothweb rolled back). [[deployment]] §4.2-§4.4.

All six build variants must be warning-clean; CI enforces `-Werror`
across the matrix (`AGENTS.md` Discipline).

## Related pages

- [[what-sloth-does]] — what each output actually contains.
- [[monitor-mode]] — the `--hop` / `--monitor-only` substrate.
- [[preflight]] — `--preflight`: every check, what it reads and what it never does.
- [[handoff]] — `--handoff` and `--interference-report`: the packet's files, what is withheld, the report's sections.
- [[sweep-session]] — `--sweep`: the plan, the report, the baseline and its accept.
- [[record-integrity]] — `--jsonl-chain` and `--verify`: what is hashed, when, and what a verifier can show.
- [[ble]] — `--bt-monitor`, the passive-scan procedure and its warnings.
- [[jsonl-schema]] · [[data-socket-exposure]] · [[sqlite-schema]] · [[pcap-export]].
- [[views-catalog]] — the keys, with per-view detail.
