---
name: preflight
description: sloth --preflight, the set-up check before a session - every check, what it reads, what it never does, the exit codes and the JSON form
type: reference
---

# Preflight: check the set-up before a session

**Summary**: `sloth --preflight [the normal options]` checks what this command line would use (interfaces and monitor mode, the regulatory domain, the clock and `--gps`, storage and the `--db` schema, the intel pack, the sources, the host, the passive contract, the output path and the rule statuses) and exits, starting nothing. One line per item, `ok` / `warn` / `fail` / `n/a` / `not checked` and the reason; exit `0` ready, `1` ready with warnings, `2` not ready. `--preflight --json` prints the same as one JSON object. It opens no capture handle, retunes no radio, sets no interface mode, writes no file, binds no socket, starts no thread and sends nothing on a monitored segment.

**Sources**: issue #247 (from #241 item 10); FM 2-0 (2004) 4-9 to 4-11 and 8-18 (verify the equipment, the databases and the reporting channels before the mission); `src/preflight.h`, `src/preflight.c` (the checks, pure), `src/preflight_gather.c` (what is read); `src/platform/linux_wifi.c` (`linux_wifi_get_reg()`, `linux_wifi_phy_iftypes()`); `src/sys_status.c` (`sys_status_read()`, `sys_status_list()`, `sys_status_sample_host()`); `src/db.c` (`db_probe_version()`); `src/intel_pack.c` (`intel_pack_date()`); `src/secure_file.c` (`sfile_validate_stat()`, the rule the run holds an existing output path to); `src/capture/capture.c` (`capture_scope_verdict()`); `tests/test_preflight.c`, `tests/replay/preflight_cli.sh`.

**Last updated**: 2026-11-25 (#244: the `notify` row is `ok` with `--notify-priority`, sloth's local notification lane), 2026-11-25 (#249: `--sweep` runs the checks in process and stops on a `fail`, [[sweep-session]]), 2026-11-24 (#251: `pcap-dir-at-rest` and `eapol-dir-at-rest` in `storage`, captures kept past 7 days on a disk with no dm-crypt, [[sensor-compromise]]), 2026-11-23 (#247 review: `--monitor-only` with no monitor radio fails; a radio left out is not a passive failure; a phy-sharing interface that is down is not a warning, and the active monitor flag is named as not checked; output paths the run refuses fail; a version row that holds no version fails; the netdev listing's cut is reported and named interfaces are looked up by their own path; the `gnss` row says what counts as up; the service-unit note, since `SuccessExitStatus=` does not cover `ExecStartPre=`), 2026-11-23 (#247: the page, with the eight checks).

---

## 1. Why

Before #247 a set-up problem showed itself only once a session had started: as `NO_MONITOR_MODE`, `SENSOR_SOURCE_DOWN` or `SENSOR_UNDERVOLT`, as a stderr line, or as an empty alert list that could equally be a quiet site. FM 2-0 4-10 asks the analyst to "check to verify that procedures, personnel, equipment, and services are in place" before the work starts; this is that check for one sensor, run with the command line the session will use.

## 2. How it runs

`--preflight` is read with the rest of the command line, and every whole-command-line check runs first: a refused combination (`--strict --allow-active`, a malformed `--gps`, `--eapol-dir` without `--collect-handshakes`, a `--user` naming no account, ...) exits `2` with its usual line and prints no preflight page. Then, before any handle is opened, sloth gathers the facts below, runs the eight checks over them and exits with their code. A flag that loads a file at parse time (`--inventory`, `--known-macs`, `--with-research`) has already read it; nothing else happens.

It needs no root. Where the account running it cannot see a path (a directory on the way is closed to it, as `/run/sloth-ubt` is to an ordinary user) the line reads `not checked`, never "missing": the run itself is another account. Writability is tested with `access(2)` as the account running the preflight, and the reason says so, because the daemon writes its sinks as the account it drops to.

## 3. The checks

| Check | # | Item | What is read | `fail` | `warn` |
|---|---|---|---|---|---|
| `radios` | 1 | each `--iface`, `--monitor-iface`, `--df-iface`; with no `--monitor-iface`, the radio discovery would take; `monitor-only`; `netdevs` | `/sys/class/net` listed (the first 128 entries, `PF_MAX_NETDEV`) and, for each, `.../type` (803 is monitor mode), `.../phy80211/name` and `index` and `.../flags` (up or down), through `sys_status`'s guarded readers; a named interface the listing does not hold is read by its own path; the phy's supported modes by nl80211 `GET_WIPHY` (one phy, not a dump) | an `--iface` not on the host (sloth exits 1: the scope cannot be enforced); a `--monitor-iface` missing, or not in monitor mode (sloth sets no mode, so it would not be opened); the reason says whether its phy supports monitor mode, does not, or was not checked; `--monitor-only` with no radio in monitor mode to open (`capture_scope_verdict()` refuses: the run exits 1) | a `--df-iface` missing or not in monitor mode (that radio is left out); no interface in monitor mode at all (every 802.11 rule blind), naming the interfaces whose phy supports it. `netdevs` is `not checked` when the listing holds more than 128 entries (discovery saw only those) |
| `radios` | 1 | `regdom` | nl80211 `GET_REG` | | world domain `00` (not set), or no domain reported; `not checked` without nl80211 |
| `clock` | 2 | `time` | the wall clock; `adjtimex(2)` with `modes` 0, which reads | the clock is before the intel pack's date, the newest date the binary carries (no build date is compiled in: the build is reproducible) | the kernel reports the clock unsynchronised |
| `clock` | 2 | `gps` | a loopback gpsd: one connect and one read of the `VERSION` line gpsd sends unasked, within 1.5 s; nothing is written (the `?WATCH` line is the reader's, after start). A serial receiver: `stat(2)` only (opening a tty raises DTR). A gpsd off loopback is not dialled (`not checked`) | a serial device that is missing or not a character device (sloth exits 2) | gpsd did not answer (the reader would keep retrying, the position reads searching) |
| `storage` | 3 | `db`, `jsonl`, `pcap-dir`, `eapol-dir`, `report`, `report-json`, `snapshot`; `pcap-eapol` | `stat(2)` and `lstat(2)` of the path, its directory, `access(2)`, `statvfs` on the directory opened `O_RDONLY`; an existing path held to the rule the run holds it to (`src/secure_file.h`, by `sfile_validate_stat()` over the `lstat`, nothing opened) | the directory does not exist; under 1 % free; an existing path the run refuses whatever account it runs as: a symbolic link, the wrong type, a group or other permission bit, a file with more than one link; `--pcap-dir` and `--eapol-dir` the same directory (same device and inode, or the same spelling when neither exists yet: sloth exits 2) | not writable by this account; owned by an account other than the one running the preflight (the run refuses it unless it writes as that account); under 10 % free (the bands of `fs_capacity_band()`) |
| `storage` | 3 | `db-schema` | the file opened `immutable=1`, read-only (`db_probe_version()`, the way `--db-compact-alerts` reads its source): no lock, no `-wal` or `-shm` created, nothing migrated | written by a newer sloth; older than this build migrates; a `schema_version` row that holds no version (read as `db_open()` reads it, so `0` or `x` is refused at start, where a missing row is stamped); not a sloth database; `--db` in a `WITH_SQLITE=0` build | (`ok` for a current file, a new file, or one `db_open()` will migrate at start, which the line says) |
| `storage` | 3 | `pcap-dir-at-rest`, `eapol-dir-at-rest` (#251) | the directory's `st_dev`, then `/sys/dev/block/MAJ:MIN/dev`, `dm/uuid`, `dm/name` and `slaves/` walked down through `/sys/class/block/NAME` (`pf_block_crypt()`), through sys_status's guarded readers | | captures kept more than `PF_PLAIN_RETAIN_DAYS` (7) days, or forever, by `pcap.retain_days` / `handshake.retention_days`, on a filesystem with no dm-crypt (`CRYPT-` uuid) in its device stack; `not checked` when the device is not a block device in `/sys` (tmpfs, btrfs, ZFS, overlayfs, NFS). fscrypt and self-encrypting drives are not seen ([[sensor-compromise]] § 4) |
| `storage` | 3 | `db.max_mb` | the file's size and the free space | | the filesystem fills before the database reaches `db.max_mb` |
| `intel` | 4 | `pack` | `intel_pack_version()`, `intel_pack_hash()`, `intel_pack_date()` (intel/LOCK's `date`, compiled in) | | older than 90 days (`PF_INTEL_MAX_AGE_DAYS`, the issue's proposal: the packs change on the scale of months), or its age unknown because the clock is before it |
| `sources` | 5 | `btmon`, `btcap`, `replay`, `baseline` | `/sys/class/bluetooth` (the controllers); `stat(2)` of the `--bt-capture` path (a FIFO is not opened: the open waits for its writer), of each `--replay` file and of `--baseline-in` | a `--bt-capture` path missing or neither FIFO nor regular file (sloth exits 2); a `--replay` file missing | no Bluetooth controller for `--bt-monitor`; `--baseline-in` missing |
| `host` | 6 | `undervolt`, `temperature` | `sys_status`'s thermal-zone and hwmon readers (`sys_status_sample_host()`) | | the firmware's under-voltage alarm is set now; the hottest reading is 80 C or more (`sys_status`'s critical band) |
| `host` | 6 | `passive` | the same interface facts as check 1 | | another, non-monitor interface that is up (or whose up/down state cannot be read) shares the phy of a monitor radio sloth would open: it can transmit through that radio. `not checked` when the netdev listing was cut |
| `output` | 7 | `socket` | a `unix:` socket's directory, by `stat(2)` and `access(2)` | the directory does not exist | not writable by this account; a `tcp:` listener is `not checked` (only binding it would test it) |
| `output` | 7 | `notify` | the source: no file under `src/` sends a message (mail, webhook, push); `--notify-priority` (#244) | | `n/a` without `--notify-priority` ("no --notify-priority: no notification path in sloth"); `ok` with it, naming the priority and that the lane is a line on stderr, local only, so no test message is sent. A lane that leaves the host, and its test message, are sloth-mesh#18's |
| `rules` | 8 | | `cov_rule_status()` over the environment this configuration would have (§ 4) | | a kind is blind because a configured source would not deliver (`source_down`) |

What `passive` checks, precisely: the radios the run would open are the first `--monitor-iface` when it is in monitor mode (or, with none named, the one discovery takes), then each further `--monitor-iface` and `--df-iface` that is in monitor mode; with no first radio none is opened (`src/main.c`). An interface named and not in monitor mode is not opened, because sloth sets no mode: check 1 says what that costs, and it is not a passive failure. For each radio that would be opened, no other interface on its phy may be up and in a mode other than monitor, because that interface can transmit through the radio (as a client or an access point); one that is administratively down (`IFF_UP` clear in `/sys/class/net/NAME/flags`) transmits nothing and is listed as down. sloth itself injects no frame (`MISSION.md` § 2), which no configuration can show. The opt-ins on the command line that send something are named on the line and are not a failure: `--allow-active` (PTR queries and nl80211 scan triggers) and a routable `--data-socket` with `--data-socket-allow-remote` (it serves whoever connects). Not checked, and said on the line: a monitor interface created with the `active` flag (`iw ... type monitor flags active`, `MONITOR_FLAG_ACTIVE`) ACKs unicast frames sent to its own address, and no read-only path the preflight uses reports that flag. Also not checked: whether an interface given to `--iface` is opened promiscuous (libpcap does that on every capture open; it changes what the host receives, not what it sends).

## 4. The last check: the rule statuses, an expectation

The `rules` check builds the `cov_env_t` this configuration would have and runs [[coverage-assessment]]'s `cov_rule_status()` over every kind `sloth-wifi` raises. It is what the configuration leads one to expect, not a measurement; the running daemon's `rule_status` records are the measurement. The environment:

| Field | From |
|---|---|
| `dot11` | `up` when the first `--monitor-iface` is in monitor mode (plus each further one that is) or, with none named, when discovery would find a radio; `down` when one is named and is not; else none |
| `ip` | `up` unless `--monitor-only`; `down` when an `--iface` is not on the host |
| `host`, `sys` | `up` |
| `ble_hci`, `ble_adv` | `--bt-monitor`: `up` with a controller, else `down`; `--bt-capture`: `up` when the path is there (or not visible to this account), else `down` |
| `gnss` | `--gps` with a serial path: `up` when it is a character device, or when it is not visible to the account running the preflight (not taken for down); `down` when it is missing or another type. `--gps gpsd://`: `down` only when the probe found it down (gpsd did not answer, or the spec did not parse); `up` when it answered and also when it was not checked (a gpsd off loopback is not dialled), so an unchecked receiver counts as delivering |
| bands, channels, hopping | under `--hop`, the plan's channels and their bands; without it one channel per radio and the band unknown (no band check), as the running daemon has before a frame arrives |
| config | `--my-ssid` / `--my-bssid` (`own_net`), a roster (`roster`), `--db` (`db`) |

The line gives the three counts; the page lists every kind that is not observable, grouped as the report groups them (blind first, then partly, by reason). A `--replay` run is not assessed (`n/a`), as in the daemon.

## 5. Output

The page:

```
sloth --preflight: sloth-wifi 1.8.7, this command line; nothing started
  ok           radios alfa0             in monitor mode on phy6 (--monitor-iface)
  ok           radios regdom            regulatory domain US
  ok           clock gps                gpsd at 127.0.0.1:2947 answered, release 3.25 (connect and one read; nothing sent)
  not checked  sources btcap            /run/sloth-ubt/ubt.fifo: not visible to the account running --preflight (...)
  ...
  ok           rules                    expected for this configuration, not measured: 55 observable, 37 partly, 4 blind
                         blind no_own_net (3): MY_NETWORK_RECON UNKNOWN_DEVICE TPC_ABSENT_HIGH_BAND
                         ...
ready (exit 0)
```

`--json`, one line:

```
{"preflight":{"daemon":"sloth-wifi","version":"1.8.7"},"exit":1,"verdict":"ready_with_warnings",
 "checks":[{"check":"radios","item":"alfa0","level":"ok","reason":"..."},...],
 "rules":{"assessed":true,"expectation":true,"observable":55,"partly":37,"blind":4,
          "kinds":[{"kind":"DFS_MASKING","status":"blind","reason":"band"},...]}}
```

`level` is `ok`, `warn`, `fail`, `na` or `not_checked`; `verdict` is `ready`, `ready_with_warnings` or `not_ready`. A command-line path is bytes, not text: a byte that does not start well-formed UTF-8 is written `\ufffd`, so the object is valid JSON whatever the path. The words of the `rules` kinds are those of the `rule_status` record ([[jsonl-schema]]).

## 6. Exit codes

| Code | Meaning |
|---|---|
| `0` | ready: no line is `warn` or `fail` |
| `1` | ready with warnings: a `warn` line, no `fail` |
| `2` | not ready: a `fail` line; also any command line the argv checks refuse (no page then) |

`n/a` and `not checked` do not change the code. `tests/test_preflight.c` drives each check with a failing fixture and holds the codes; `tests/test_docs_consistency.c` holds `--help` to them.

## 7. What it never does, and the test for it

`tests/test_preflight.c :: test_preflight_writes_nothing` gives every output path (`--db` with a real WAL-mode database already in place, `-o`, `--pcap-dir`, `--eapol-dir`, both reports, `--snapshot-out`, a `unix:` socket) one fresh directory, runs the gatherer, the checks and both printers, and asserts the directory holds the database alone, its size and modification time unchanged. Seen red with the database opened `mode=ro` without `immutable=1` (a `-shm` and a `-wal` appear) and with `--pcap-dir` created. `test_gpsd_probe_reads_and_sends_nothing` runs the real gpsd probe against a loopback stand-in that counts the bytes it receives; seen red with the `?WATCH` line sent. The nl80211 queries are `GET`s, one reply each, parsed by pure functions tested on hand-built replies. `tests/replay/preflight_cli.sh` (run by `make replay-check`) drives the linked binary: `--json` alone exits 2, the 32nd `--iface` reaches the page, `--monitor-only` with no radio fails, and `--allow-active` under `--preflight` prints no "enabled" notice (seen red with each of the last two fixes reverted).

## 8. Daemons and the service unit

`sloth-wifi` (and `sloth`) has `--preflight`. **sloth-rf does not yet**: its inputs are the decoders' files and sockets and the GNSS receiver, which this page's checks do not cover (sloth-rf's startup trim, `src/rf_trim.h`, already reads whether an SDR is attached); it is a follow-up with its own source checks, not a flag to copy.

A service unit could run it before the daemon, `ExecStartPre=/usr/local/bin/sloth --preflight <the same options>`, so that a `fail` (exit 2) stops the start with the reason in the journal. A `warn` (exit 1) stops it too: `SuccessExitStatus=` applies to the main service process only (systemd.service(5)), not to `ExecStartPre=`, and the `-` prefix ignores every failure, `2` included. To start on a warning and not on a failure, wrap it: `ExecStartPre=/bin/sh -c '/usr/local/bin/sloth --preflight <options>; [ $? -le 1 ]'`. It is not installed by `make install-service`: the unit runs it as root before the drop, where `access(2)` answers for root, and a check that fails on a transient (gpsd starting after sloth) would hold the sensor down. That decision is the owner's.

## Related pages

- [[cli-reference]] — `--preflight`, `--json` and the exit codes.
- [[coverage-assessment]] — the rule statuses the `rules` check derives, and the running daemon's measurement of them.
- [[sweep-session]] — `--sweep` runs these checks in process first and does not start on a `fail`.
- [[monitor-mode]] — preparing a radio, which the preflight checks and never does.
- [[jsonl-schema]] — `sensor_health`, `source_status` and `sys_status`: what a running sensor reports about the same things.
- [[capture-scope]] — the `--iface` scope an absent interface cannot enforce.
- [[sqlite-schema]] — the schema versions and the migration the `db-schema` line names.
