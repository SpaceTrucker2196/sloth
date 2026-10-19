# Threat model: assets, adversaries, trust boundaries

What sloth protects, who it protects it from, and where the lines are
that an attacker has to cross. Every security issue cites this page by
ID (`A1`–`A5`, `ADV-1`–`ADV-4`, `TB-1`–`TB-7`) instead of restating the
model; the IDs are stable and are not renumbered when the list grows.

**Summary**: sloth is a root-adjacent process that spends its whole life
parsing bytes an adversary chose, then writes what it saw to disk, to a
socket and to a terminal. The assets are the captured third-party data,
the sensor host, the operator's decision surface, downstream parsers
and the build. The adversaries are whoever is on the air or wire
(unauthenticated, unlimited frames), a local unprivileged account on the
sensor, operator-supplied files whose intent is trusted but whose bytes
are not, and an upstream compromise. Seven boundaries separate them from
the assets; the table in §5 maps every finding of the 2026-10
architecture review to the boundary it crosses, the CWE it instantiates,
whether it is closed today, and the Track X slice that owns it.

**Sources**: `src/capture/capture.c` (`on_packet`, `decode_frame`,
`decode_ipv4`), `src/capture/probe.c` (`on_probe_frame`),
`src/secure_file.c`, `src/privdrop.c`, `src/discovery.c`, `src/eapol_log.c`,
`src/alert_pcap.c`, `src/db.c`, `research/query.c`, `src/data_socket.c`,
`src/jsonl.c` (`json_escape`), `src/formatter.c` (`cef_escape_field`,
`cef_escape_ext`, `syslog_sd_escape`), `src/inventory.c`, `src/posture.c`,
`src/wifi_snapshot.c`, `src/views/dashboard_bands.c`,
`packaging/systemd/sloth-sensor.service`, `Makefile`,
`.github/workflows/ci.yml`, `SECURITY.md`, `MISSION.md` §2, issues #133,
#134, #139 and the #143 tracking index.

**Last updated**: 2026-10-19 (#142 CI half)

---

## 1. How to use this page

- A security issue's **first section** names the boundary and the
  adversary it is about (`TB-3 / ADV-2`), then describes the finding.
  It does not re-derive why a local user matters or what the pcap edge
  is; that is what this page is for.
- A finding that fits no boundary here is a finding about this page:
  add the boundary, do not force the fit.
- The IDs are stable. A boundary that is retired keeps its number with
  a "retired" note rather than being reused.
- The Track X slices (#134–#142) and anything filed after them cite
  these IDs. The slices that shipped before this page existed (#134,
  #139) are mapped in §5 instead.

## 2. Assets

| ID | Asset | Where it lives | Why it matters |
|---|---|---|---|
| **A1** | **Captured third-party data.** SSIDs and probed network lists, hostnames, DNS names and TLS SNI, cleartext credentials, EAPOL handshakes and PMKIDs. | At rest: `--db`, `-o`, `--pcap-dir`, `--eapol-dir`, `--report`, `--report-json`, `--snapshot-out`. In motion: `--data-socket`. | None of it is the operator's. It was observed from devices that did not consent, and some of it (`--eapol-dir`) is directly crackable. Leaking it is the harm sloth exists to detect, done by sloth. See [[retention]] for what is ever deleted. |
| **A2** | **Sensor host integrity.** The process, its privileges, and the host filesystem it can write. | Wherever sloth runs. The shipped unit runs as `sloth` with `CAP_NET_RAW` + `CAP_NET_ADMIN` ([[deployment]]); a run from a checkout under `sudo` is uid 0 for its whole life. | A parser fault in a privileged process that reads hostile bytes forever is a host compromise, not a crash. A root file write to an attacker-chosen path is the same thing by a shorter route. |
| **A3** | **The operator's decision surface.** The terminal, the journal, `report.md`, whatever SIEM consumes the stream. | `src/tui.c` and `src/views/*.c`; `-o`; `--report*`; syslog/CEF via `--out-format`. | The operator acts on what the screen says. An adversary who can write to the screen — a terminal escape inside an SSID, a forged line in the report — steers the response. |
| **A4** | **Downstream consumers' parsers.** Anything that reads the JSONL, CEF or RFC 5424 output. | `src/jsonl.c`, `src/formatter.c`, the `examples/` consumers, the operator's SIEM. | sloth promises well-formed records ([[jsonl-schema]]). A record that is not — invalid UTF-8, an unescaped control byte, a CEF field with a smuggled delimiter — breaks or misleads a parser sloth does not control. |
| **A5** | **Build and provenance.** The binary the service executes and the libraries it links. | `Makefile`, `.github/workflows/ci.yml`, the release tag, `/usr/local/bin/sloth` after `make install`. | Everything above assumes the binary is the one the source describes. Without dependency floors, an image pin or an SBOM, nothing says so. |

## 3. Adversaries

| ID | Adversary | Can | Cannot |
|---|---|---|---|
| **ADV-1** | **On-air / on-wire.** Any station in radio range or any host on the monitored segment. | Send unlimited frames, unauthenticated. Choose every byte of 802.11 management, control and data payload, and every byte of the IP, L4 and application payload sloth parses. Repeat at line rate. | Touch the sensor's filesystem, sockets or process. Read any sloth output. ADV-1 reaches sloth only through TB-1 and, by way of what sloth stores and later renders or re-reads, through TB-5 and TB-6. |
| **ADV-2** | **Local unprivileged account on the sensor.** A shell on the host without root. | Connect to the loopback TCP data socket (the bare `--data-socket` default), hold connection slots, plant symlinks and hardlinks in world-writable directories, read anything not `0600`/`0700`, and on a host still running the pre-#139 hand-written unit, edit the build tree that root executes. | Read `0600` output owned by the sloth user or root. Attach to the process. Bind the socket path first when it is under a root-owned `0700` directory. |
| **ADV-3** | **Operator-supplied files.** `--with-research`, `--check-manifest`, `--known-macs`, `--inventory`, `--baseline-in`. | Be anything. The operator's *intent* is trusted; the *bytes* are produced by cron or external tooling, copied between hosts, or — for `--baseline-in` — written by sloth itself a run earlier from ADV-1 data, so an SSID an attacker beaconed last week is now in an "operator" file. | Arrive without the operator naming the path. ADV-3 is a channel, not a person; a malformed file is as likely to be an accident as an attack and the response is the same: fail closed, name the line, exit 2. |
| **ADV-4** | **Upstream compromise.** libpcap, sqlite3, ncursesw, GitHub Actions, the CI image. | Change what the binary does without changing the source. | Be detected by anything in the tree today. ADV-4 is scoped here so #142 has something to cite, not because sloth has a defence. |

## 4. Trust boundaries

Each boundary names what crosses it, where the check lives, and what is
known to be unchecked. "Enforced" means there is a test that goes red
when the check is removed; the slice issues record the mutation.

### TB-1 — the pcap edge

**Crosses**: `struct pcap_pkthdr` + bytes from libpcap into the parsers.
Two entry points: `on_packet()` in `src/capture/capture.c` (the IP
capture) and `on_probe_frame()` in `src/capture/probe.c` (the monitor
radio). Everything downstream of these two functions is ADV-1's data.

**Enforced today**: `decode_frame()` bounds every link-layer header
against `caplen`; `decode_ipv4()` refuses a header shorter than 20 or an
IHL that overruns `caplen`; the probe path refuses a radiotap length
`>=` the frame.

**Known unchecked**: `caplen` is cast from `bpf_u_int32` to `int` at both
entry points (CWE-1284 — the parsers compare signed lengths); `probe.c`
reads the radiotap length itself instead of through `radiotap_parse()`,
so the two paths can disagree about where the frame starts; IPv4 Total
Length is never read, so padding past the IP datagram is parsed as L4
payload (CWE-125 territory once a parser trusts it). Owner: #141 (one
checked frame view for both paths), #132 (Total Length and fragments).

### TB-2 — process privilege

**Crosses**: nothing should. The process starts with the privileges it
needs to open the capture and keeps them.

**Enforced today**: the shipped unit (`packaging/systemd/sloth-sensor.service`,
#139) runs as `sloth`, not root, with exactly `CAP_NET_RAW` and
`CAP_NET_ADMIN`, `NoNewPrivileges`, from `/usr/local/bin`;
`tests/test_unit_file.c` pins each of those. See [[deployment]].

**Enforced since #140** (owner ruling 2026-10-15, default on): once
the capture handles are open and before any sink or thread exists,
`src/privdrop.c` drops a root run to the `sloth` account (or `--user
NAME`), or — with no such account — keeps uid 0 and sheds every
capability it does not need. `CAP_NET_ADMIN` stays only for
`--hop`/`--allow-active`; `CAP_NET_RAW` never does. `no_new_privs` and
an empty ambient/inheritable set on every run, the unit's included.
Each step is read back and a mismatch exits 2. The plan is pinned by
`tests/test_privdrop.c`; the unit's `capset` re-allow by
`tests/test_unit_file.c`.

**Known unchecked**: `--no-privdrop` keeps uid 0 and every capability
for the run — announced on stderr, never the default. A root run with no
`sloth` account is still uid 0, so it still owns root's files, though
without `CAP_DAC_OVERRIDE` it no longer reads everyone else's. The
root half of `privdrop_apply()` (`setresuid`, `PR_CAPBSET_DROP`) cannot
run in CI and is a hand check on the host. A fully unprivileged start
stays ruled out: `--hop` needs `CAP_NET_ADMIN` on every retune.

### TB-3 — filesystem write

**Crosses**: every byte sloth writes to disk. `src/secure_file.c` is
the choke point: `sfile_private_dir()` pins a `0700` directory owned by
the caller, `sfile_system_dir()` pins a root-owned one, `sfile_open()`
opens `O_NOFOLLOW|O_CLOEXEC` inside the pinned fd, `sfile_check_existing()`
refuses a path that is a symlink, group/other-readable or not the
caller's ("validated, never repaired").

**Enforced today**: `-o`, `--pcap-dir`, `--eapol-dir`, `--db`,
`--snapshot-out`, `--report`, `--report-json` (`sfile_fopen` in
`src/main.c`), the avahi service file and the manual `w` export all go
through it (`grep -l sfile_ src/*.c`). #134 closed the two writers
that did not: `discovery_publish()`'s `fopen(out, "w")` and
`eapol_export_create()` passing a name with `/` into `sfile_open()`.
`SQLITE_OPEN_NOFOLLOW` is a compile-time requirement (`#error` below
sqlite 3.31.0 in `src/db.c` and `research/query.c`). `tests/test_secure_file.c`
holds the red-then-green record.

**Known unchecked**: the `-wal`/`-shm`/`-journal` side-file checks in
`db_prepare_private()` are advisory — sqlite creates those files itself,
after the check, so a planted name there is a TOCTOU `NOFOLLOW` narrows
but does not close. The Packets view's `w` export writes to the working directory,
which the shipped unit pins with `WorkingDirectory=`; a checkout run
does not.

### TB-4 — the data socket

**Crosses**: every record, to every connected peer. Reachability is the
access control; there is no authentication and, by owner decision
(2026-09-25, #100), there will be no TLS. See [[data-socket-exposure]].

**Enforced today**: a routable bind needs `--data-socket-allow-remote`
and `--strict` refuses it even then; `unix:` paths rely on directory
permissions and `SO_PEERCRED` is the kernel's authentication; the socket
is write-only (nothing is ever read from a peer); a peer with queued
bytes that has not drained them for `DATA_SOCKET_STALL_SECS` is closed.

**Enforced since #136**: the bare flag means
`unix:/run/sloth/sloth.sock`; when `/run/sloth` is absent or not ours it
exits 2 with the remedy and never falls back to TCP, so loopback TCP —
readable by any ADV-2 account (CWE-306) — is only ever typed.

**Known unchecked**: `MAX_CLIENTS` is 16 **global**
slots with no per-peer cap, so one local account can hold all of them
(CWE-770); the stall timer runs only while `c->off < c->len`, so an
idle peer with nothing queued is held indefinitely. Owner: #135
(per-peer cap, idle timeout independent of queued bytes, loopback-TCP
notice).

### TB-5 — render and export

**Crosses**: stored network bytes (ADV-1's, days old) into the terminal,
JSON, CEF, syslog, Markdown and the snapshot file. This is the boundary
where A1 data becomes A3 and A4 risk.

**Enforced today**: per-field ingest filters where the field was
noticed — SSID (`src/beacon_snoop.c`, C0 and DEL dropped), cleartext
credentials, MQTT and SSH identifiers, inventory SSIDs; `json_escape()`
escapes `"`, `\`, and every byte below `0x20`; the CEF and syslog
escapers quote their own delimiters.

**Known unchecked**: there is no choke point — a new field reaches the
terminal unfiltered until someone notices (CWE-150; #77 found four WPS
strings doing exactly that in the ANSI build). `json_escape()` passes
every byte `>= 0x80` through, so a non-UTF-8 SSID produces a record that
is not valid JSON text (CWE-838, CWE-116). `cef_escape_*()` and
`syslog_sd_escape()` map CR and LF to space and pass every other C0
byte, including ESC, into a line a SIEM will display (CWE-117).
Owner: #138 (`netstr` choke point, valid-UTF-8 `json_escape`); the
manifest/roster/baseline raw prints are #137's.

### TB-6 — operator-file parsers

**Crosses**: ADV-3 bytes into the process, by the operator's hand.

**Enforced today**: `--inventory` is all-or-nothing with a printable
check per octet (`src/inventory.c`); `--known-macs` and `--inventory`
exit 2 on a malformed line; `research.db` is opened
`SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW` with `DEFENSIVE` on,
`TRUSTED_SCHEMA` off, extension loading off and a 1 MiB length limit,
each read back, and is refused unless `research` is the FTS5 virtual
table and the file holds no view or trigger (#137, [[research-corpus]]).
`--db` has `DEFENSIVE` on (#137). The manifest reader refuses a C0/DEL
byte in `latest` or `url` ([[manifest-format]]); a bad roster line is
echoed as a bounded copy with C0/DEL replaced by `?`; the snapshot
writer escapes the SSID and label columns so `--baseline-in` reads back
exactly the octets heard, and the drift report prints them escaped
([[wifi-sigint-techniques]]).

**Known unchecked**: the research view still prints corpus titles as
stored (`src/views/research.c`); that is the TB-5 choke point's job
(#138), not a parser's. `--baseline-in` remains the loop that turns
ADV-1 into ADV-3 — the escaping makes it lossless and inert, it does not
make the SSIDs trustworthy.

### TB-7 — build and CI

**Crosses**: source into the binary the unit executes; third-party
code into the link.

**Enforced today**: CI builds all six configurations with `-Werror`
(`.github/workflows/ci.yml`); the install path is root-owned and the
unit executes only `/usr/local/bin/sloth` (#139); cppcheck is pinned
to one version; sqlite has a compile-time floor and, since #142, a
runtime one — `db_open()` and `rq_open()` refuse a loaded library
below 3.31.0, which the compile check cannot see; `make check-deps`
(run by `all`) refuses sqlite below 3.31.0 and libpcap below 1.9.0
when pkg-config can say; `make sbom` writes a CycloneDX SBOM of the
link dependencies; `sloth --version` and `sensor_health.libs` report
the libraries actually loaded.

Since #142's CI half: every workflow runs on a pinned image
(`ubuntu-24.04`), refused otherwise by
`tests/test_ci_pins.c :: test_no_workflow_runs_on_a_moving_image`; CI
produces a CycloneDX SBOM; `v*` tags get GitHub build-provenance
attestation.

**Known unchecked**: no floor for ncursesw (CWE-1104). Tag signing stays
a manual owner step ([[release-checklist]]) — CI holds no key, by
design.

## 5. Finding → boundary map

One row per finding from the 2026-10 review. "Status" is what the tree
does on the date above, not what the issue said when it was filed —
#134 and #139 shipped before this page and closed five of these rows.

| Finding | Boundary | Adversary | CWE | Status (2026-10-14) | Slice |
|---|---|---|---|---|---|
| Root for the life of the process | TB-2 | ADV-1 via TB-1 | 250, 269 | **Closed** by #140 (narrowed by #139): a root run drops to `sloth` (or keeps uid 0 with capabilities shed) after capture opens; `--no-privdrop` is the announced exception. | #140 (X7) |
| systemd unit executes the build tree | TB-2 / TB-7 | ADV-2 | 426, 732 | **Closed** by #139: unit runs `/usr/local/bin/sloth`, `tests/test_unit_file.c` scans for a `/home/` path. Migration recipe on [[deployment]]. | #139 (X6) |
| `discovery.c` `fopen(out, "w")` followed symlinks as root | TB-3 | ADV-2 | 59, 367 | **Closed** by #134: `sfile_system_dir()` + `O_EXCL` temp + `renameat`; sentinel test. | #134 (X1) |
| `eapol_log.c` passed an export name with `/` into `openat` | TB-3 | ADV-1 (name from the air) | 22 | **Closed** by #134: `sfile_open()` refuses `/`, `.`, `..` and empty on a real dirfd. | #134 (X1) |
| `db.c` side-file TOCTOU; `SQLITE_OPEN_NOFOLLOW` behind `#ifdef` | TB-3 | ADV-2 | 367 | **Narrowed** by #134: `NOFOLLOW` is now a compile-time requirement. The side-file check remains advisory by nature (sqlite creates the files). | #134 (X1) |
| `alert_pcap.c` used non-reentrant `localtime()` from the capture thread | A1 | — (correctness) | 663 | **Closed** by #134: `localtime_r`. Three `localtime()` calls remain in `src/views/dashboard_bands.c`, all on the UI thread, which is now the only caller. | #134 (X1) |
| Loopback TCP by default; 16 global slots; idle peers held forever | TB-4 | ADV-2 | 306, 770 | **Open.** `MAX_CLIENTS 16`, no per-peer cap; stall timer only while bytes are queued. | #135 (X2), #136 (X3) |
| Terminal escapes in stored strings; `json_escape` passes `>= 0x80`; CEF/syslog strip CR/LF only | TB-5 | ADV-1 (stored) | 150, 116, 117, 838 | **Open.** Per-field filters exist where someone looked; no choke point. | #138 (X5) |
| `caplen` cast to `int`; `probe.c` private radiotap length; no IPv4 Total-Length clamp | TB-1 | ADV-1 | 1284, 125 | **Open.** Both entry points cast; `decode_ipv4()` never reads Total Length. | #141 (X8), #132 (P10b) |
| `research.db` opened without `DEFENSIVE` / `TRUSTED_SCHEMA` off | TB-6 | ADV-3 | 20 | **Closed** by #137: `DEFENSIVE`, `TRUSTED_SCHEMA=0`, no extensions, `SQLITE_LIMIT_LENGTH` 1 MiB, each read back; catalogue probe refuses a `research` VIEW and any trigger. `--db` gets `DEFENSIVE`. | #137 (X4) |
| Manifest / roster / baseline fields printed raw | TB-6 → TB-5 | ADV-3 (and ADV-1 via baseline) | 117 | **Closed** by #137: manifest C0/DEL → `err=1`; roster echo bounded and sanitised; snapshot SSID/label escaped, `strtol` with range on read. | #137 (X4) |
| No dependency minimums, `ubuntu-latest`, no SBOM | TB-7 | ADV-4 | 1104, 1357 | **Partly closed** by #142: sqlite 3.31.0 floor at compile (#134) and run time, `make check-deps` floors, `make sbom`, loaded versions in `--version` / `sensor_health.libs`. **Open**: `ubuntu-latest` runners, the CI SBOM and attestation jobs. | #142 (X9) |

## 6. What this model deliberately leaves out

These are owner decisions recorded on the Track X issues, repeated here
so a reader does not file them as gaps:

- **No TLS on the data socket** (2026-09-25, #100). Reachability is the
  control; `unix:` and an SSH tunnel are the answers.
- **No bearer tokens over TCP** as a substitute for `unix:`.
  `SO_PEERCRED` is the kernel's authentication; a shared secret on a
  loopback port is weaker and looks stronger.
- **No fully unprivileged start and no privsep helper now.** `--hop`
  retunes through `CAP_NET_ADMIN` on every dwell. #140 drops what it
  can and keeps that one capability.
- **No SSID sanitisation beyond C0/DEL at ingest.** Anything stronger
  changes what the operator sees, and the operator needs to see what was
  on the air. Escaping belongs at the render boundary (TB-5), not the
  capture boundary.
- **No libcap.** Capability handling is done with the raw syscalls.
- **sloth never chmods or chowns an operator path.** A directory with
  the wrong mode is refused with the mode named; it is not repaired
  ("validated, never repaired", `src/secure_file.c`).
- **Active behaviour of any kind** is outside the model entirely; see
  [`MISSION.md`](../../MISSION.md) §2. The model assumes sloth transmits
  nothing, so there is no boundary for what sloth sends.

## 7. Keeping this page true

- A new output path is a new A1 location and a new TB-3 writer. It goes
  through `src/secure_file.c` or it is a finding.
- A new input file is a new ADV-3 channel and a new TB-6 parser. It
  fails closed on the first bad byte and exits 2, or it is a finding.
- A new record field is a new TB-5 crossing. Until #138 lands, that
  means an ingest filter in the same change.
- A new capability or a new place the binary is executed from moves
  TB-2 or TB-7. The unit file test (`tests/test_unit_file.c`) is where
  that is pinned.
- When a slice closes a row in §5, change the row's status in the same
  commit, with the issue number. The row stays; the map is the record.

## Related pages

- [[deployment]] — the shipped unit: the current state of TB-2.
- [[data-socket-exposure]] — TB-4 in full, and the three supported ways
  to reach the stream from another host.
- [[pcap-export]] and [[sqlite-schema]] — the two largest A1 stores and
  how `secure_file.c` guards them.
- [[jsonl-schema]] — the A4 contract.
- [[inventory]], [[manifest-format]], [[research-corpus]],
  [[posture-report]] — the ADV-3 channels, one page each.
- [[retention]] — what A1 data is ever deleted.
- [[where-exploits-happen]] — the other threat map: what ADV-1 does to
  the *network*, as opposed to what it does to sloth.
- [`SECURITY.md`](../../SECURITY.md) — how to report a finding against
  any of these boundaries.
