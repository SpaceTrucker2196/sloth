# Deployment: `make install` and the shipped systemd unit

**Summary**: Since #139 sloth ships a hardened systemd unit and the
install targets that place everything it references. `sudo make
install` puts the binary, the monitor-mode helper and the research
corpus under `/usr/local`; `sudo make install-service` installs the
unit, a `sysusers.d` fragment for the `sloth` account and a site
defaults file. The service runs as `sloth`, not root, with exactly
`CAP_NET_RAW` and `CAP_NET_ADMIN`, from paths only root can write, with
its state under `/var/lib/sloth`. This page explains why each piece is
the way it is and how to migrate a sensor that is still running out of a
build tree: `packaging/bin/sloth-migrate-sensor` (#153) copies its data,
switches the unit, verifies the result and rolls back on failure. Since
the owner's ruling of 2026-10-26 it also moves a `tcp:` data socket to
the unit's unix socket when told to (`--data-socket-unix`, §4.2), and
installs `slothweb.service` (§6), the web UI as the same `sloth` account
with no capability at all, once the sensor verifies
(`--with-slothweb`, §4.3).

**Sources**: `packaging/systemd/sloth-sensor.service`,
`packaging/systemd/sloth.sysusers.conf`, `packaging/bin/sloth-monitor-up`,
`packaging/default/sloth`, `packaging/systemd/slothweb.service`,
`packaging/default/slothweb`, `packaging/bin/sloth-migrate-sensor`,
`Makefile` (`install`, `install-service`, `deploy-test`),
`tests/test_unit_file.c`, `tests/deploy/test_migrate_sensor.sh`,
`src/secure_file.c`, `src/data_socket.c`, `src/privdrop.c`, `tests/test_privdrop.c`, `MISSION.md` §2.

**Last updated**: 2026-10-26 (#153 third review: the shared uid's signal exposure stated and the signal syscalls denied, `ReadOnlyPaths=-`, `make install` refuses a stale slothweb, a failed backup is not an incomplete rollback); 2026-10-26 (#153 owner ruling: `--data-socket-unix`, `slothweb.service`, `--with-slothweb`); 2026-10-26 (#153, second review fixes: EPERM/EACCES verify, `/run/sloth` on rollback, radio and dropped-key checks); 2026-10-23 (#153, review fixes)

---

## 1. Why a shipped unit

Until #139 the repo shipped no unit (`agents/FACTORY.md` §7 said "keep
deployment under operator control") and the one actually running on the
reference sensor had grown by hand into this shape:

```ini
User=root
WorkingDirectory=/home/<uid 1000>/Projects/sloth
ConditionPathExists=/home/<uid 1000>/Projects/sloth/sloth
ExecStart=/home/<uid 1000>/Projects/sloth/sloth --headless --hop ...
```

Three consequences, each observed rather than hypothetical:

- **`make clean` takes the sensor down.** `ConditionPathExists` on the
  build artefact means a rebuild is an outage; on 2026-10-14 the sensor
  sat for about an hour with no binary on disk, and because a failed
  *condition* is not a failed *start*, `Restart=always` did nothing.
- **uid 1000 can replace the binary root executes.** Anything able to
  write the checkout — an agent worktree, a compromised editor plugin,
  the user's own shell — writes a file that the next restart runs as
  uid 0. That is CWE-426 (untrusted search path), CWE-732 (incorrect
  permission assignment for a critical resource) and CWE-250 (execution
  with unnecessary privileges) in one unit.
- **Root for the whole process lifetime.** sloth needs two capabilities
  for about a second at startup (opening the capture handle) and one
  more each time `--hop` retunes. It never needs uid 0, and running the
  parser surface — radiotap, 802.11, EAPOL, DNS, TLS, QUIC, all fed by
  the air — as root turns any parser bug into a root bug.

The shipped unit removes uid 0 from the process **with no code change**:
`User=sloth` plus `AmbientCapabilities=` gives an unprivileged account
the two capabilities at `exec`, and the bounding set keeps it from ever
getting more. The in-process privilege drop (#140, §3.3) is defence in
depth on top of this, not a prerequisite for it.

## 2. What gets installed

| Target | File | Installed as | Mode | Why there |
|---|---|---|---|---|
| `install` | `sloth` | `/usr/local/bin/sloth` | 0755 | root-owned, so the running binary cannot be swapped by the build user |
| `install` | `packaging/bin/sloth-monitor-up` | `/usr/local/sbin/sloth-monitor-up` | 0755 | the only thing that touches link state; runs as root from `ExecStartPre=+` |
| `install` | `research.db` | `/usr/local/share/sloth/research.db` | 0644 | `--with-research` opens it `SQLITE_OPEN_READONLY`; read-only data, so `secure_file.c`'s ownership rule does not apply |
| `install` | `slothweb` (`make web` first, as yourself) | `/usr/local/bin/slothweb` | 0755 | what `slothweb.service` runs (§6); `install` refuses without it rather than relink it as root, and refuses one older than any file under `web/src`, `web/ui`, `web/tools`, `web/data`, the recipes page or the `Makefile`, so a pull followed by `make` alone does not install the old slothweb beside the new unit and UI |
| `install-service` | `packaging/systemd/sloth-sensor.service` | `/etc/systemd/system/sloth-sensor.service` | 0644 | the unit below, with `/usr/local/` rewritten to `$(PREFIX)/` if you changed it |
| `install-service` | `packaging/systemd/sloth.sysusers.conf` | `/usr/lib/sysusers.d/sloth.conf` | 0644 | declares the `sloth` account; `systemd-sysusers` creates it, make never does |
| `install-service` | `packaging/default/sloth` | `/etc/default/sloth` | 0644, `install -b` | site settings; an existing copy is kept as `/etc/default/sloth~` |
| `install-service` | `packaging/systemd/slothweb.service` | `/etc/systemd/system/slothweb.service` | 0644 | §6, with `/usr/local/` rewritten as for the sensor's |
| `install-service` | `packaging/default/slothweb` | `/etc/default/slothweb` | 0644, only if absent | slothweb's bind and allowed peers; never replaced, so it has no backup either |

Both targets honour `DESTDIR`, so `make install install-service
DESTDIR=/tmp/stage` lays the whole tree out under a scratch root for
inspection or `systemd-analyze verify`. `PREFIX`, `UNITDIR`,
`SYSUSERSDIR` and `DEFAULTDIR` are overridable the same way.

**Make never runs `useradd`.** The account is declared in a
`sysusers.d(5)` fragment and created by `systemd-sysusers`, which is
idempotent, assigns a system-range uid, and is the same mechanism every
distribution package uses. A Makefile creating accounts is how two
installs on one host end up with two different uids owning the state
directory. `tests/test_unit_file.c` fails if `useradd`, `adduser` or
`groupadd` appears in either install recipe.

The account:

```
u sloth - "sloth passive sensor" /var/lib/sloth /usr/sbin/nologin
```

System user, kernel-assigned id, home is the state directory, no shell.

## 3. The unit, key by key

The full file is `packaging/systemd/sloth-sensor.service`; every key
below is asserted by `tests/test_unit_file.c`, so the page and the file
cannot drift apart silently.

### 3.1 Identity and state

| Key | Value | Why |
|---|---|---|
| `User=` / `Group=` | `sloth` | the point of the slice; given once, so a later `User=` line cannot override it |
| `StateDirectory=` | `sloth` (mode `0700`) | systemd creates `/var/lib/sloth` owned by `sloth`; nothing depends on a checkout existing |
| `RuntimeDirectory=` | `sloth` (mode `0750`) | `/run/sloth` for the data socket; cleaned up on stop |
| `WorkingDirectory=` | `/var/lib/sloth` | every relative path, should one slip in, lands in the private state dir |
| `UMask=` | `0077` | belt and braces: `secure_file.c` already refuses group/other-accessible outputs, this makes sure it never has to |
| `Environment=` / `EnvironmentFile=-/etc/default/sloth` | defaults, then the site file | `SLOTH_IFACE` and `SLOTH_ARGS`; the `-` means a missing file is not an error, and the `Environment=` defaults apply then |

`secure_file.c` is what makes a missed `chown` during migration a loud
failure rather than silent degradation: `--db`, `--pcap-dir`,
`--report`, `--report-json` and `--snapshot-out` all go through it, and
it refuses any file or directory not owned by the effective uid with
`owned by another user — refusing`. A state directory still root-owned
from the old unit stops the service at its first write, with that
message in the journal.

### 3.2 Starting

```ini
ExecStartPre=+/usr/local/sbin/sloth-monitor-up ${SLOTH_IFACE}
ExecStart=/usr/local/bin/sloth \
    --headless \
    --hop \
    --db /var/lib/sloth/sloth.db --db-interval-secs 1 \
    --pcap-dir /var/lib/sloth/pcap \
    --data-socket unix:/run/sloth/sloth.sock --no-discovery \
    --with-research /usr/local/share/sloth/research.db \
    --report /var/lib/sloth/report.md \
    --report-json /var/lib/sloth/report.json \
    --snapshot-out /var/lib/sloth/snapshot.txt \
    --baseline-in /var/lib/sloth/snapshot.txt \
    $SLOTH_ARGS
```

- **`ExecStartPre=+…`** The `+` runs the helper with full privileges and
  outside the sandbox: putting a radio into monitor mode needs
  `CAP_NET_ADMIN` as root and writes through `iw`, which the service's
  own filter would refuse. sloth never does this itself — the operator
  prepares the radio ([[monitor-mode]], `MISSION.md` §2) — which is
  exactly why it is a separate script and a separate privilege level.
  The helper is idempotent: if `/sys/class/net/$IF/type` is already
  `803` it exits 0 without touching the link, so a restart does not flap
  the radio.
- **`--headless --hop`** No TUI; retune the receiver across channels
  (needs `CAP_NET_ADMIN` per retune, which is why the capability stays
  for the lifetime of the process rather than being dropped after
  startup).
- **`--db … --db-interval-secs 1`** The retained artefact
  ([[sqlite-schema]], [[retention]]). This is the *db-only profile*: no
  `-o` JSONL sink, because the JSONL emitters re-dump every table every
  poll and filled a disk once (148 GiB, 2026-09-26).
- **`--pcap-dir`** Per-alert pcaps ([[pcap-export]]). `secure_file.c`
  creates it `0700` if absent.
- **`--data-socket unix:/run/sloth/sloth.sock --no-discovery`** A
  `unix:` socket, created `0600` inside the `0750` runtime directory, so
  `SO_PEERCRED` is the authentication and nothing listens on a port
  ([[data-socket-exposure]]). `--no-discovery` because a unix socket has
  nothing to advertise.
- **`--with-research`** The embedded corpus ([[research-corpus]]),
  read-only.
- **`--report`, `--report-json`** Written on `SIGTERM`
  ([[posture-report]]) — which is why `KillSignal=SIGTERM` and
  `TimeoutStopSec=60`.
- **`--snapshot-out` / `--baseline-in`** The same path: each run writes
  the site snapshot it will compare against next time.
- **`$SLOTH_ARGS`** Unquoted, so it word-splits. The site's `--my-ssid`,
  `--my-bssid` and `--site-label` live in `/etc/default/sloth`
  ([[inventory]] explains why the own-AP identity is configuration and
  never learned over the air), as does any `--inventory FILE`.

Not present, deliberately: **`--eapol-dir`**. Since #87 it is refused
without `--collect-handshakes`, and a refused start under
`Restart=always` is a restart loop. The test asserts that if one appears
the other does too.

### 3.3 Privilege

| Key | Value |
|---|---|
| `AmbientCapabilities=` | `CAP_NET_RAW CAP_NET_ADMIN` |
| `CapabilityBoundingSet=` | `CAP_NET_RAW CAP_NET_ADMIN` |
| `NoNewPrivileges=` | `true` |

`CAP_NET_RAW` opens the `AF_PACKET` capture handle; `CAP_NET_ADMIN` is
what `--hop`'s nl80211 retunes need. Ambient capabilities are the
mechanism that lets an unprivileged `User=` receive them at `exec`
without a setcap'd binary; the bounding set means no child or
`execve` can regain anything else. The test asserts the bounding set is
a subset of `{CAP_NET_RAW, CAP_NET_ADMIN}`, that ambient is a subset of
bounding, and that each is given exactly once (a second
`CapabilityBoundingSet=` line *merges*, it does not replace).

**Inside the process (#140).** The unit hands sloth both capabilities
at `exec`; sloth gives back what it no longer needs once the capture
handles are open. `CAP_NET_RAW` is used once — `pcap_activate()`
creates the `AF_PACKET` sockets and reading them needs nothing — so it
is shed with `capset` before any sink or thread exists. `CAP_NET_ADMIN`
is kept only when the run writes nl80211 for its whole life: `--hop`
(every retune opens a fresh netlink socket) or `--allow-active` (scan
triggers, likewise). The shipped `ExecStart=` has `--hop`, so the
steady state is `CapEff: 0000000000001000`. The ambient and inheritable
sets are cleared and `no_new_privs` is set on every run, and each step
is read back; a mismatch is exit `2`, never a half-dropped run.

The same code runs for a hand start outside systemd. `sudo sloth ...`
**drops by default** (owner ruling 2026-10-15, "only use root when
necessary"): to the `sloth` account the sysusers fragment creates, or
`--user NAME`; with no such account it keeps uid 0 and sheds every
capability it does not need, and says so. `--no-privdrop` is the
announced escape for a dev box. Because the drop happens *before* the
sinks open, `--db`, `--pcap-dir`, `-o`, `--eapol-dir` and the
`--data-socket` path are created as the target account, and
`secure_file.c`'s ownership check holds against that account — a
`data/` owned by your login user is refused when the run drops to
`sloth`. Either `chown` it (as the migration below already does for
`/var/lib/sloth`), point the run at `/var/lib/sloth`, pass `--user
<you>`, or pass `--no-privdrop`. → [[cli-reference]] "Privilege".

### 3.4 Filesystem

`ProtectSystem=strict` makes the entire filesystem read-only except the
two directories systemd created; `ProtectHome=true` removes `/home`
entirely, which is the direct answer to "it ran from a checkout".
`PrivateTmp`, `PrivateDevices`, `ProtectKernelTunables/Modules/Logs`,
`ProtectControlGroups`, `ProtectClock`, `ProtectHostname` are all `true`
and all free: sloth touches none of those. `ProtectProc=invisible`
hides other users' processes, which disables the root-only pid map in
the process views — fine headless, where no view is drawn.

### 3.5 Kernel surface

| Key | Value | Why |
|---|---|---|
| `RestrictAddressFamilies=` | `AF_UNIX AF_NETLINK AF_PACKET` | capture, rtnetlink/nl80211/INET_DIAG, the data socket. **No `AF_INET`**: the db-only profile opens no Internet socket. Add `AF_INET AF_INET6` only for a `tcp:` `--data-socket` or `--allow-active`; the test enforces that pairing in both directions |
| `SystemCallFilter=` | `@system-service`, then `~@privileged @resources`, then `capset` | the standard service allow-list minus privilege changes and resource-limit calls, with `capset` alone re-allowed for the in-process drop (#140). A later allow line adds back to the filter. `capset` can only shed here: it never grows the permitted set, and growing the inheritable set needs `CAP_SETPCAP`, which the bounding set excludes. The test asserts the re-allow sits after the deny |
| `SystemCallErrorNumber=` | `EPERM` | a blocked call fails with an error sloth already handles, instead of `SIGSYS` |
| `SystemCallArchitectures=` | `native` | no 32-bit syscall table |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute` | `true` | none needed; SQLite does not JIT |

`capset` is in `@privileged`, so without that third line every start
fails closed at the drop with `capset: Operation not permitted` and
exit `2`. Measured on systemd 261 (2026-10-15) with a probe that only
calls `capset` to lower its sets, run via `systemd-run --user` under the
unit's three filter lines: `EPERM` with the first two alone, `0` with
the third added. **Upgrade the binary and the unit together** (`sudo
make install install-service`): a #140 binary under a pre-#140 unit
will not start. `setresuid`/`setgroups` stay denied — the unit already
starts as `sloth`, so the account switch never runs under it.

### 3.6 Resources and lifecycle

`MemoryMax=1G` / `MemoryHigh=768M` is a ceiling until the memory-growth
item (M0) closes: an OOM kill plus `Restart=always RestartSec=10` bounds
a leak to one restart instead of a host OOM. `TasksMax=16` is generous
for a process with a capture thread and a poll loop.
`StartLimitIntervalSec=300` / `StartLimitBurst=5` stop a hot loop when
the radio is present but unusable.

`BindsTo=` / `After=sys-subsystem-net-devices-alfa0.device` wait for
the radio rather than racing it, and stop the service when it is
unplugged. A dependency stop is not a failure, so `Restart=` does not
re-arm it — hence the second `WantedBy=` on the device unit in
`[Install]`, which starts the service again when the device returns
(the reference sensor's Realtek 8812AU re-enumerates under USB load;
one such event left it dead for 19 h before that line existed). The
device name is spelled out because systemd cannot read an
`EnvironmentFile` in `[Unit]`; pin it by MAC in a `.link` file so probe
order cannot swap it with the uplink:

```ini
# /etc/systemd/network/10-alfa-monitor.link
[Match]
MACAddress=00:c0:ca:xx:xx:xx
[Link]
Name=alfa0
```

### 3.7 Score

`systemd-analyze security --offline=true packaging/systemd/sloth-sensor.service`
reports **1.6 OK** on systemd 261 (2026-10-14). The number is recorded,
not gated: it moves with the systemd version's checklist, and the
remaining exposure is the two capabilities and the `AF_PACKET` family,
which are the job. `systemd-analyze verify` on the file passes; on a
host without `/usr/local/bin/sloth` installed yet it warns that the
command is not executable, which is the expected state before `make
install`.

## 4. Migrating a build-tree sensor

For a sensor still running the hand-written unit (root, out of a
checkout, state under `data/`), `packaging/bin/sloth-migrate-sensor`
(#153) does the whole move and can undo it. The owner runs it, as root,
on the sensor host; nothing in the repo runs it, and its downtime is the
owner's to schedule. Dry run first, always, and inside `tmux` or
`screen`: verification can take seven minutes, and although a HUP, INT
or TERM after the stop rolls back rather than leaving the hardened unit
half-checked, a session that survives is still better than a rollback.

```sh
cd /path/to/checkout
make                                                # as yourself
sudo make install                                   # binary, helper, research.db
tmux new -s migrate                                 # or screen
sudo packaging/bin/sloth-migrate-sensor --dry-run   # prints every action, changes nothing
sudo packaging/bin/sloth-migrate-sensor             # does them, verifies, or rolls back
journalctl -u sloth-sensor -f
```

Two options, each opt-in and each printed by the dry run:
`--data-socket-unix` (§4.2) moves an old `tcp:` data socket to the
unit's unix socket, and `--with-slothweb` (§4.3) installs, starts and
verifies `slothweb.service` after the sensor. Exit status: 0 migrated
(or already migrated), 1 failed and rolled back, 2 refused with nothing
changed, 3 the sensor migrated and verified but slothweb failed and was
rolled back alone. The reference host's exact sequence is §4.4.

**Do not run `make install-service` first.** It overwrites
`/etc/systemd/system/sloth-sensor.service` with no backup, which leaves
the tool nothing to roll back to; the tool installs the unit, the
sysusers fragment and `/etc/default/sloth` itself. Run against a unit
that is already the hardened one (byte-identical to
`packaging/systemd/sloth-sensor.service` after the `PREFIX`
substitution), it only re-verifies — so a second run is safe and is
how to re-check a migrated host. A matching unit is not proof the data
moved, though (`install-service` places the same bytes, and the sensor
then starts on an empty `/var/lib/sloth` and verifies fine with a fresh
db), so the re-verify also needs a
`sloth-sensor.service.bak-migrate-<stamp>` backup (a rollback renames
its backup to `.rolled-back-<stamp>`, so a remaining `.bak-migrate-`
means a migration that stood) and `/var/lib/sloth/sloth.db`. Without
both it refuses, exit 2, and says the data was never copied, naming
the old `--db` from the backup when there is one. If `install-service`
already ran, put the build-tree unit back and rerun, or follow §4.1.

What it does, in order:

1. **Preflight**, which changes nothing and must pass whole: the
   installed `sloth`, `sloth-monitor-up` and `research.db` from `make
   install`; the current unit's single `ExecStart=` and its flags (below);
   the source data dir, derived from `--db` (override `SRC_DATA=`), holds
   only regular files and directories (`db.c` refuses symlinks); no
   drop-ins under `sloth-sensor.service.d/`; `/var/lib/sloth` absent or
   empty, and neither it nor `/var/lib` a symlink (the copy would land
   in whatever it names); free space for the copy plus 10 % and 64 MiB.
   The monitor radio: the device the hardened unit's `BindsTo=` names
   (`alfa0`) becomes `SLOTH_IFACE`, and the old unit's
   `ExecStartPre=… sloth-monitor-up <if>` (every one), a `MON_IFACE=`
   override and a carried `--iface` allow-list must all agree with it —
   a different radio, an argument that is not a plain name, or an
   allow-list leaving the radio out is refused, because systemd cannot
   take the `BindsTo=` device from `/etc/default/sloth` and the defaults
   file would contradict the unit. Every other `[Service]` key of the
   old unit (`Environment=`, another `ExecStartPre=`, `Nice=`,
   `LimitNOFILE=`, …; all but `ExecStart`, `WorkingDirectory`, `User`,
   `Group`, `Restart` and the monitor-up line) is printed as
   `not carried`, in the dry run too, since the hardened unit's own
   replace them. When the old socket is under `/run/sloth`, that
   directory's mode and owner are recorded for the rollback (below); a
   socket in a subdirectory of it, or a symlinked `/run/sloth`, is
   refused.
   Entries with group/other bits are listed as a note: the copy drops
   them (below), the source keeps them.
2. **Account**: installs `/usr/lib/sysusers.d/sloth.conf` and runs
   `systemd-sysusers` before anything is stopped.
3. **Data**: backs up the unit (and `/etc/default/sloth`, if present) as
   `*.bak-migrate-<stamp>`, stops the service, **copies** (`cp -pR`,
   never `mv`) the data dir into `/var/lib/sloth`, `chown -R
   sloth:sloth`, `chmod -R go-rwx`, `chmod 0700`, and compares every
   file's SHA-256 and the directory list against the source. A mismatch
   rolls back before the unit is touched. The `go-rwx` is not tidiness:
   `cp -p` carries the source modes, and `src/secure_file.c` refuses any
   file or private directory with group/other bits, so a 0644 report or
   a 0755 `pcap/` would stop the hardened sensor from starting.
4. **Unit**: writes `/etc/default/sloth` from `packaging/default/sloth`
   with the carried `SLOTH_ARGS`, installs the hardened unit,
   `daemon-reload`, `reenable` (so the device `WantedBy=` link exists),
   and starts it.
5. **Verify**: the service is active; `/proc/<MainPID>/status` shows
   `CapEff: 0000000000001000` (CAP_NET_ADMIN only, because the unit has
   `--hop`; 0 without) and `NoNewPrivs: 1`; `sensor_health` records on
   `unix:/run/sloth/sloth.sock` over a further `SETTLE_SECS` (default
   90) show no retune failure whose `chan_retune_reason` is `EPERM` or
   `EACCES` (or is absent, from a binary that cannot say), and at least
   one has a non-zero `chan_confirmed`; and the MainPID is unchanged at the end,
   so it did not restart-loop. One record is not enough: connecting
   changes `socket_clients`, which is in the record's signature
   (`src/jsonl.c`), so the first record is emitted the moment the
   reader connects, usually before any retune has been tried, and the
   failure this migration risks (no CAP_NET_ADMIN, every retune EPERM)
   shows only later. The window covers one hop rotation (11 channels
   (`DEFAULT_CHANNELS`) at the 2 s maximum dwell, about 22 s,
   `src/wifi_chanhop.c`), and the first failure, each new failure
   reason and the first confirmed channel each emit a record of their
   own (`retune_fail_any`, `retune_reason_mask` and
   `chan_ever_confirmed` are in the signature), so none can hide
   between heartbeats. Why only `EPERM`/`EACCES`: they are what a
   missing CAP_NET_ADMIN returns, and nl80211 checks the capability
   before the channel, so without it every retune fails that way. A
   channel the regdomain or driver will not take fails with `EINVAL`
   (`src/jsonl.c` calls it the normal case, #91), under the root unit
   just the same; the default hop list includes 149–161, which some
   regdomains refuse, so failing on any non-zero count would roll a
   healthy sensor back on every attempt. Those reasons are printed as
   a note and do not fail verify; the confirmed-channel check still
   catches a radio that never retunes at all. The socket
   reader starts before the service does, because `sensor_health` is
   change-only with a 300 s heartbeat, and reconnects until its
   deadline, because a stale socket left by the old unit refuses the
   first connect; the budget for the first record (`HEALTH_SECS`,
   default 330) covers a full heartbeat besides.

**Any failure after the stop rolls back**, and so does a HUP, INT or
TERM from just before the stop onwards (a dropped SSH session is the
likely one; the trap is set before the stop so that a signal during it
is acted on once it returns, rather than leaving the sensor stopped,
and further signals are ignored while the rollback runs): the previous
unit and defaults file are restored (a defaults file that did not exist
is removed), the unit backup is renamed `.rolled-back-<stamp>`,
`daemon-reload` and `reenable`, the copy is renamed to
`/var/lib/sloth.rolled-back-<stamp>` (not deleted — the new sensor may
have written to it), and the old service is started on its old data
path. It is reported as rolled back only if it is still active on the
same MainPID after `ROLLBACK_SETTLE_SECS` (default 15, past the
hardened unit's `RestartSec=10`): with `Restart=always` a unit that
dies on startup reads active between attempts. Otherwise the tool
prints `ROLLBACK INCOMPLETE`. One way that would happen is handled:
the hardened unit's `RuntimeDirectory=sloth` removes `/run/sloth` when
it stops, and `src/data_socket.c` never creates a socket's directory,
so an old unit whose socket lived there (the bare `--data-socket`
default since #136) with nothing of its own to make the directory
could not bind and would restart-loop. The rollback therefore
recreates `/run/sloth` with the mode and owner preflight recorded
(`install -d -m <mode> -o <uid> -g <gid>`) before it starts the old
unit, when the directory existed then and is gone now. **The old data is never
modified, in either outcome**; delete
`data/` by hand once the migrated sensor has run long enough to
satisfy you. Exit status: 0 migrated or already migrated, 1 failed and
rolled back, 2 refused by preflight with nothing changed.

How the old flags are carried. The rule is "refuse rather than guess":
the hardened unit sandboxes the process (`ProtectHome`,
`ProtectSystem=strict`, `RestrictAddressFamilies=AF_UNIX AF_NETLINK
AF_PACKET`), so a flag naming a path under `/home` or a `tcp:` socket
would fail there, and a silently dropped flag changes what the sensor
does.

| Old flag | What happens |
|---|---|
| `--my-ssid`, `--my-bssid`, `--site-label`, `--site`, `--known-mac`, `--iface`, `--db-interval-secs`, `--db-retain-days`, `--db-max-mb`, `--correlate-retain` | carried verbatim into `SLOTH_ARGS` |
| `--db`, `--pcap-dir`, `--report`, `--report-json`, `--snapshot-out`, `--baseline-in` | already in the hardened `ExecStart` under `/var/lib/sloth`; accepted only when the old path is the same name under the data dir (`sloth.db`, `pcap`, `report.md`, `report.json`, `snapshot.txt`), so the copy lands where the new unit looks; any other name is refused |
| `--with-research` | replaced by `$(PREFIX)/share/sloth/research.db` from `make install` |
| `--data-socket unix:…` (or bare) | replaced by `unix:/run/sloth/sloth.sock`; a different old path is reported so its readers can be repointed |
| `--headless`, `--hop`, `--no-discovery` | already in the hardened `ExecStart` |
| `--no-privdrop` | dropped — removing it is the point of #153 |
| `--data-socket tcp:…`, `-o`/`--out`, `--eapol-dir`, `--collect-handshakes`, `--inventory`, `--allow-active`, anything else | refused, exit 2: each is an owner decision in the hardened profile (§3), not a migration step |

Relative paths resolve against the old unit's `WorkingDirectory=`; a
path containing `..` is refused.
Quoting, `$VAR`, `%` specifiers and `;` in the old `ExecStart` are
refused too: `SLOTH_ARGS` is split on whitespace, so a value with a
space cannot survive the move, and the tool says so instead of
mangling it.

Every path and command is an environment variable (`ROOT` prefixes
every host path; `SYSTEMCTL`, `SYSUSERS`, `GETENT`, `CHOWN`, `CP`,
`SOCAT`, `TIMEOUT`, `PREFIX`, `SRC_DATA`, `MON_IFACE` (must equal the
`BindsTo=` device), `VERIFY_SECS`,
`HEALTH_SECS`, `SETTLE_SECS`, `ROLLBACK_SETTLE_SECS`), which is how `make deploy-test` runs it unprivileged:
`tests/deploy/test_migrate_sensor.sh` builds a scratch root holding a
fake build-tree unit (written by the test, never read from `/etc`), a
data dir, a `/proc/<pid>/status`, and stub `systemctl`,
`systemd-sysusers`, `getent`, `chown` and `socat` that log every call.
It covers: a dry run leaves the scratch root's tree hash and the call
log untouched; the flags above carried exactly, `--no-privdrop` and
every `/home` path absent; the copy's files 0600 and directories 0700
even where the source had 0644/0755, with the source's modes left
alone; a corrupted copy caught by checksum before the unit switches; a
failed verify rolled back to the old unit, defaults and data path, the
old unit re-enabled and its backup renamed, for each check in turn
(`chan_retune_failures` 3 `EPERM`; CapEff `0000000000003000`;
`NoNewPrivs` 0; a MainPID that changes; a unit never active; a 0 record
followed 2 s later by a 5 `EPERM`; `EACCES`; a count with no reason
field; `EINVAL` followed by `EPERM`; no confirmed channel), with no
defaults file left where there was none; `EINVAL` refusals alone
passing verify with a note; a rollback recreating a `/run/sloth`
(0750) the hardened unit's stop removed, so an old unit with its
socket there comes back; an old unit that restart-loops after a
rollback reported as `ROLLBACK INCOMPLETE`; old `[Service]` keys
named as not carried; an `--iface` list including `alfa0` carried; a HUP mid-verify, then a second HUP
during the rollback, rolling back exactly once with the socket reader
gone; a socket reader that reconnects after a refused first connect; a
second run that only verifies; a rerun after a rollback; and refusals
(unknown flag, `-o`, `tcp:` socket, quoting, a renamed `--db`, a `..`
path, `--eapol-dir`, low space, a non-empty target, a missing `make
install`, a drop-in, two `ExecStart=`, a non-sloth binary, a symlink in
the data dir, a symlinked target or `/var/lib`, the hardened unit
placed by `install-service` with no backup, a backup but no copied
db, another radio in `sloth-monitor-up` (in the only or a second
`ExecStartPre=`), a `${SLOTH_IFACE}` argument, a `MON_IFACE=` override,
an `--iface` list without `alfa0`, a socket below `/run/sloth/`), each
changing nothing; a dry run on a migrated host makes no mutating call. Each absence check was seen to fail under
a mutation of the tool (`docs/wiki/log.md`, #153 entries).
`TOOL_SH="busybox sh"` or `"bash --posix"` runs the tool under another
shell. `shellcheck -s sh` runs first when it is installed and is clean
on all three scripts (0.11.0, 2026-10-26); CI does not run `make
deploy-test` yet.

### 4.1 By hand

The same move without the tool, for a host it refuses. It follows the
same rules: back up before changing, stop before copying, **copy, never
move**, verify the copy before switching, and leave the old data where
it is.

```sh
cd /path/to/checkout
sudo make install                                    # binary, helper, research.db
stamp=$(date +%Y%m%d-%H%M%S)
u=/etc/systemd/system/sloth-sensor.service
sudo cp -p "$u" "$u.bak-migrate-$stamp"              # the way back
[ -f /etc/default/sloth ] && sudo cp -p /etc/default/sloth /etc/default/sloth.bak-migrate-$stamp
sudo install -D -m 644 packaging/systemd/sloth.sysusers.conf /usr/lib/sysusers.d/sloth.conf
sudo systemd-sysusers                                # creates the sloth account
sudo systemctl stop sloth-sensor
sudo install -d -m 0700 /var/lib/sloth
sudo cp -pR data/. /var/lib/sloth/                   # the whole dir: db + -wal/-shm, pcap/, report.*, snapshot, v5 backup
sudo chown -R sloth:sloth /var/lib/sloth
sudo chmod -R go-rwx /var/lib/sloth                  # secure_file.c refuses group/other bits
sudo chmod 0700 /var/lib/sloth
sudo sh -c 'cd data && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2' > /tmp/src.sums
sudo sh -c 'cd /var/lib/sloth && find . -type f -exec sha256sum {} + | LC_ALL=C sort -k2' \
    | diff /tmp/src.sums - && echo "copy verified"   # stop here unless this prints
sudo install -m 644 packaging/systemd/sloth-sensor.service "$u"   # PREFIX=/usr/local; else sed it as install-service does
sudo install -m 644 packaging/default/sloth /etc/default/sloth
sudoedit /etc/default/sloth                          # SLOTH_IFACE, SLOTH_ARGS=--my-ssid/--my-bssid/--site-label
sudo systemctl daemon-reload
sudo systemctl reenable sloth-sensor
sudo systemctl start sloth-sensor
journalctl -u sloth-sensor -f
```

Then check it as §5 describes. To go back: `sudo systemctl stop
sloth-sensor`, copy `$u.bak-migrate-$stamp` (and the defaults backup)
back, `daemon-reload`, `start`; `data/` was never touched.

Notes:

- `make install-service` is not used here: it overwrites the unit with
  no backup. Naming the backup `.bak-migrate-<stamp>` is deliberate —
  it is what lets a later `sloth-migrate-sensor` run recognise the host
  as migrated and only re-verify it.
- Copy with the service stopped, so the db and its `-wal`/`-shm` side
  files are consistent; copying the whole directory keeps them together.
  SQLite gives the side files the main file's mode and `db.c` refuses a
  permissive or symlinked one rather than repairing it (#87, "validated,
  never repaired"), which is what the `go-rwx` is for.
- A missed `chown` is loud: the first write fails with `owned by another
  user — refusing` and the unit restarts until you fix it. It does not
  degrade quietly.
- The old unit's `ConditionPathExists=` is gone on purpose. If the
  binary is missing the unit now fails and says so, instead of being
  silently skipped.
- `make clean` in the checkout no longer affects the service. `make
  install` is the deploy step.
- `data/` stays in place as the fallback. Delete it by hand once the
  migrated sensor has run long enough to satisfy you.

### 4.2 A `tcp:` data socket: `--data-socket-unix`

The hardened unit streams on `--data-socket unix:/run/sloth/sloth.sock
--no-discovery` only (`RestrictAddressFamilies=AF_UNIX AF_NETLINK
AF_PACKET`; the socket is `0600 sloth` in the `0750 sloth`
`RuntimeDirectory`, and `SO_PEERCRED` is the authentication). An old
unit that streams on `tcp:` — the reference host's
`--data-socket tcp:127.0.0.1:8765`, which every local account could
read — is therefore refused by default, with the message it has always
had:

```
sloth-migrate-sensor: REFUSED: --data-socket tcp:127.0.0.1:8765: the hardened unit allows AF_UNIX only (RestrictAddressFamilies); a tcp: socket is an owner decision, not a migration
```

The owner made that decision on 2026-10-26 (#153): the live sensor
moves to the unix socket. `--data-socket-unix` is how it is made on the
command line, not guessed by the tool:

- the `tcp:` spec is not carried anywhere: the hardened `ExecStart`
  already names `unix:/run/sloth/sloth.sock` and keeps `--no-discovery`
  (the bare `--data-socket` default, spelled out), and nothing of it
  reaches `SLOTH_ARGS`;
- the dry run prints the conversion (`data socket: --data-socket
  tcp:127.0.0.1:8765 becomes --data-socket unix:/run/sloth/sloth.sock
  --no-discovery`) and the summary line (`socket: tcp:127.0.0.1:8765 ->
  unix:/run/sloth/sloth.sock`);
- verify reads `sensor_health` from the new unix socket, as the user
  running the tool — root, or `sloth`, the only two the `0600` socket
  admits — never from `tcp:`;
- a rollback restores the old unit byte for byte, `tcp:` socket and
  all, from `sloth-sensor.service.bak-migrate-<stamp>`;
- a second run on the migrated host, with or without the flag, only
  re-verifies.

Every reader of the old stream has to move with it: `slothweb --socket
tcp:127.0.0.1:8765` loses its stream, and a slothweb running as another
account cannot read the new socket at all. `--with-slothweb` (§4.3)
installs one that can.

### 4.3 slothweb: `--with-slothweb`

`--with-slothweb` adds a sixth step, run only once the sensor has
verified: install `slothweb.service` (§6), start it and verify it. Its
preflight runs with the sensor's, before anything changes, and refuses
(exit 2) when `make install` did not place `/usr/local/bin/slothweb`,
when `curl` is missing, when `slothweb.service.d/` holds drop-ins, when
`SLOTHWEB_ARGS` uses quoting or variables or names `--socket`,
`--sloth-db` or `--store` (the unit fixes those three; a second one
would win, and the sandbox admits no other path), or when something
already listens on the port and `slothweb.service` is not running — a
slothweb started by hand, which reads the old socket; stop it first.
That last one is the only refusal a dry run does not make: the dry run
comes before the hand-started slothweb is stopped (§4.4), so it prints
`note: a real run would REFUSE: port … already has a listener` and
carries on, and the real run refuses if it is still there.

The step:

1. back up an existing `slothweb.service` that differs from the shipped
   one (`.bak-migrate-<stamp>`), install the shipped one;
2. install `/etc/default/slothweb` from `packaging/default/slothweb`
   **only if there is none** — an existing one, with the operator's
   bind and allowed peers, is used as it is and never replaced;
3. `daemon-reload`, `enable`, `restart`;
4. verify: active; `/api/health` on the bound address answers within
   60 s with `"db":"open"`, `db_mode` `wal` or `immutable` (slothweb, as
   `sloth`, opened the sensor's `sloth.db` read-only — `wal` with the
   sensor running) and `"socket":"connected"` (it reads the unix
   socket); the same MainPID at the end. The request is made from
   `127.0.0.1` (`curl --interface 127.0.0.1`, or `::1` for a v6 bind):
   a connection from loopback to one of the host's own addresses is a
   loopback peer, which slothweb's allow-list always admits, so a
   Tailscale bind with a single `/32` in `--web-allow` verifies with no
   extra entry.

A failure in step 6 rolls back **slothweb only**: it is stopped, its
previous unit is put back (or the one installed is removed), a defaults
file this run wrote is removed, and its enabled and active state are
restored. The sensor, verified already, is not stopped, restored or
restarted. Exit status 3 says exactly that: the sensor migrated, slothweb
did not. A second run with `--with-slothweb` verifies an installed,
enabled, active slothweb and changes nothing.

`make deploy-test` covers both flags against the scratch root: the
`tcp:` refusal without the flag, word for word; the dry run printing the
conversion and changing nothing; the conversion (unit, `SLOTH_ARGS`
without `tcp:`, verify on the unix socket and never `TCP`); a rollback
restoring the `tcp:` unit verbatim; the idempotent second run; the
slothweb dry run; the install with its order after the sensor's start
and the health request from loopback; the idempotent slothweb rerun;
five slothweb failures (db not open, stream not connected, a
`rollback` db_mode, never active, no answer) each rolled back alone
with the sensor untouched after its verify; an operator's unit and
defaults put back and kept, the Tailscale bind asked on its own
address; and four refusals (no binary, the port busy, a fixed path in
`SLOTHWEB_ARGS`, quoting), the busy port said but not refused by a
dry run.

### 4.4 The reference host, command by command

The live sensor today runs the build-tree unit with
`--data-socket tcp:127.0.0.1:8765`, and slothweb runs by hand as the
login user, reading that socket and a `sloth-snap.db` copy (#168). The
owner's commands, on that host, in order — every `sudo` step is the
owner's, and nothing in the repo runs them:

```sh
cd /path/to/checkout
make && make web                                    # as yourself
sudo make install                                   # sloth, slothweb, helper, research.db
tmux new -s migrate

# Only for the Tailscale bind (otherwise slothweb is loopback-only and
# the tool installs the template): write the site file first, from the
# template, and fill in the two addresses.
sudo install -m 644 packaging/default/slothweb /etc/default/slothweb
sudoedit /etc/default/slothweb
#   SLOTHWEB_ARGS=--web-bind <this host's tailscale ip>:8770 --web-allow-remote --web-allow <the viewer's tailscale ip>/32

# 1. Dry run. Read every line: the socket conversion, the copy, the
#    unit, the slothweb unit and the URL its health is read on. With
#    the slothweb started by hand still up, it also says the real run
#    would refuse until that one is stopped (it holds the port).
sudo packaging/bin/sloth-migrate-sensor --dry-run --data-socket-unix --with-slothweb

# 2. Stop the slothweb started by hand (its stream goes away with the
#    tcp: socket, and it holds the port the unit binds).
pkill -x slothweb

# 3. The migration.
sudo packaging/bin/sloth-migrate-sensor --data-socket-unix --with-slothweb
echo "exit $?"     # 0 done; 1 sensor rolled back; 2 refused; 3 sensor done, slothweb rolled back

journalctl -u sloth-sensor -u slothweb -f
```

Afterwards the snapshot is not needed: slothweb reads
`/var/lib/sloth/sloth.db` in place as a WAL reader, and its DB-backed
views say "database as of HH:MM" from the file's own mtime, with the
date in front when it is not today's (#168).
`~/sloth-snap.db` and the old `slothweb.db` in the home directory can be
deleted by hand once the new one has filled; the old `data/` stays
until you delete it, as §4 says.

## 5. Verifying a deployment

```sh
systemctl show -p User,AmbientCapabilities,CapabilityBoundingSet sloth-sensor
# User=sloth
# AmbientCapabilities=cap_net_admin cap_net_raw
# CapabilityBoundingSet=cap_net_admin cap_net_raw
ps -o user,cap_eff -C sloth                 # not root
grep -E 'CapEff|CapAmb|NoNewPrivs' /proc/$(pidof sloth)/status
# CapEff: 0000000000001000   (CAP_NET_ADMIN only, for --hop; 0 without)
# CapAmb: 0000000000000000
# NoNewPrivs: 1
journalctl -u sloth-sensor -b | grep 'capabilities dropped'
ls -la /var/lib/sloth /run/sloth            # sloth:sloth, 0700 / 0750
systemd-analyze security sloth-sensor
```

And for the repo side, `make test` runs `tests/test_unit_file.c`, which
scans the shipped files: `User=sloth`, the two capabilities and nothing
else, `ProtectSystem=strict`, `ExecStart=/usr/local/bin/sloth`, no
`/home/` anywhere in the unit, no `--eapol-dir` without
`--collect-handshakes`, no `AF_INET` on a `unix:` profile, the sysusers
record, the helper's idempotency check preceding its `iw` call, and the
Makefile never calling `useradd`. Each absence check was seen to fail
under a mutation before it shipped (`docs/wiki/log.md`, #139 entry).

## 6. slothweb.service

`packaging/systemd/slothweb.service` runs the web UI beside the sensor.
`make install-service` installs it with the sensor's unit;
`sloth-migrate-sensor --with-slothweb` (§4.3) installs, starts and
verifies it on a migrated host.

```ini
User=sloth
Group=sloth
Environment=SLOTHWEB_ARGS=
EnvironmentFile=-/etc/default/slothweb
StateDirectory=slothweb             # /var/lib/slothweb, 0700
ExecStart=/usr/local/bin/slothweb \
    --socket unix:/run/sloth/sloth.sock \
    --sloth-db /var/lib/sloth/sloth.db \
    --store /var/lib/slothweb/slothweb.db \
    $SLOTHWEB_ARGS
CapabilityBoundingSet=
AmbientCapabilities=
ReadOnlyPaths=-/var/lib/sloth
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=~kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo pidfd_send_signal
```

| Key | Why |
|---|---|
| `User=sloth`, `Group=sloth` | The sensor's state is `/var/lib/sloth`, `0700 sloth`, and its stream `/run/sloth/sloth.sock`, `0600 sloth`. slothweb reads both, so it is that account rather than a second one granted access to them; the sensor's files keep their modes. |
| What the shared uid costs | A process may signal any process of its own uid, so a compromised slothweb — it serves HTTP, and may be reachable over Tailscale — could `SIGSTOP` or `SIGKILL` the sensor and end capture. Accepted for now because the `0600` socket and the `0700` state directory admit only that account, and a second account needs both widened. It is narrowed rather than left open: the signal syscalls are denied (`SystemCallFilter=~kill …`, below); ptrace is already refused, because the sensor keeps `CAP_NET_ADMIN` in its permitted set; and the read-only mounts keep slothweb from writing `sloth.db` or `/run/sloth`. The lasting fix is a `slothweb` account in group `sloth`, the socket `0660` and a group-readable view of `sloth.db`. |
| `After=`, `Wants=sloth-sensor.service` | Starting slothweb starts the sensor; `Wants=`, not `Requires=`, so a sensor restart (or its radio unplugged) leaves the UI serving history and saying the stream is retrying. |
| `--socket unix:/run/sloth/sloth.sock` | The sensor's unix socket (§4.2). `connect()` on a socket in a read-only mount works: the read-only check covers files, directories and links, not sockets. |
| `--sloth-db /var/lib/sloth/sloth.db` | Read in place, never copied. With the sensor running both `-wal` and `-shm` exist, so slothweb opens it as a WAL reader with `readonly_shm=1` and never creates a file beside it (`web/src/web_slothdb.h`); `/api/health` says `"db_mode":"wal"`. `web/tests/test_slothdb.c :: test_same_uid_reader_beside_a_writing_sloth` holds the deployment's shape: a `0700` directory and `0600` files, made `0500` and `0400` for the reads (the read-only mount, by mode), a writer of the same uid committing between them, each commit seen. It does not pin `readonly_shm`: with the `-shm` unwritable SQLite opens it read-only either way, as under the mount; `test_crashed_sloth_restarts_beside_a_reader` goes red without it. |
| `--store /var/lib/slothweb/slothweb.db` | slothweb's own file, in its own `StateDirectory`, never inside the sensor's. |
| `$SLOTHWEB_ARGS` | From `/etc/default/slothweb`: the bind and the allowed peers. Empty (the shipped file), slothweb listens on `127.0.0.1:8770` and admits loopback only. The three paths above are not overridable there: the sandbox admits no others. |
| `CapabilityBoundingSet=`, `AmbientCapabilities=` (empty) | No capability at all: it binds a port above 1024 and never captures. An absent `CapabilityBoundingSet=` would be the full set, so the empty one is written out. |
| `NoNewPrivileges=true` | Nothing it executes can gain privilege. |
| `ProtectSystem=strict`, `ReadOnlyPaths=-/var/lib/sloth`, `ProtectHome=yes` | Everything read-only but `/var/lib/slothweb`. `/var/lib/sloth` is read-only under `strict` already; `ReadOnlyPaths=` says so, so a later `ReadWritePaths=` cannot widen it by accident. The `-`: where the sensor has never started, `/var/lib/sloth` is not there, and without it the start fails with `226/NAMESPACE` instead of slothweb serving its own history and saying `sloth.db` is missing. No `/home` at all. |
| `PrivateTmp`, `PrivateDevices`, `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible` | As for the sensor (§3.4). |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | The data socket and HTTP; no packet or netlink socket. |
| `SystemCallFilter=@system-service`, `~@privileged @resources`, `MemoryDenyWriteExecute`, `LockPersonality` | As for the sensor, without the sensor's `capset` exception: slothweb holds nothing to shed. |
| `SystemCallFilter=~kill tkill tgkill rt_sigqueueinfo rt_tgsigqueueinfo pidfd_send_signal` | No signal to any process (the shared uid, above). `tgkill` is denied with the rest because `tgkill(pid, pid, sig)` reaches any process, not only a thread of slothweb; slothweb sends no signal, not even to itself (its shutdown is a write to a pipe from the handler), and `abort()` still ends the process when its `raise()` is refused. A future `pthread_kill()` or `raise()` would get `EPERM`. |
| `MemoryMax=512M`, `TasksMax=32` | Four threads, two SQLite page caches and the HTTP buffers; the store is capped on disk by `--web-max-mb` (256 MB by default). |
| `Restart=on-failure` | A refused start (a bad `SLOTHWEB_ARGS`) stops, and says why in the journal, instead of looping. |

`/etc/default/slothweb` (`packaging/default/slothweb`) documents the
Tailscale bind with its example values commented out and placeholder
addresses from `100.64.0.0/24`, never a real host's:

```sh
SLOTHWEB_ARGS=--web-bind 100.64.0.10:8770 --web-allow-remote --web-allow 100.64.0.20/32
```

Each of the three is needed and each is refused alone: a non-loopback
`--web-bind` needs `--web-allow-remote`, and `--web-allow-remote` admits
no peer that `--web-allow` does not name. Name one viewer, as a `/32`.
No `tailscale serve`, no funnel. `make install-service` installs the
file only where there is none (`[ -e … ] || install`), so an edited one
is never replaced and needs no backup; `tests/test_unit_file.c` holds
both the guard and the absence of `install -b` on that line.

Checking it:

```sh
systemctl show -p User,CapabilityBoundingSet,AmbientCapabilities slothweb
# User=sloth
# CapabilityBoundingSet=
# AmbientCapabilities=
grep -E 'CapEff|NoNewPrivs' /proc/$(systemctl show -p MainPID --value slothweb)/status
# CapEff: 0000000000000000
# NoNewPrivs: 1
curl -s --interface 127.0.0.1 http://127.0.0.1:8770/api/health | grep -o '"db_mode":"[a-z]*"\|"socket":"[a-z]*"\|"sloth_db_age_s":[0-9]*'
systemd-analyze security slothweb
```

`tests/test_unit_file.c` scans the shipped unit: `User=sloth` and
`Group=sloth` once each, both capability sets present and empty, no
`CAP_` anywhere, no `/home/` anywhere, the sandbox keys, the address
families exactly within `AF_UNIX AF_INET AF_INET6`, the six signal
syscalls denied, `ReadOnlyPaths=` naming `-/var/lib/sloth`, no
`ReadWritePaths=` token at or under `/var/lib/sloth` and
`StateDirectory=` not naming it, the
`ExecStart` paths and no `--web-bind`, `--web-allow`,
`--web-allow-remote` or `--web-allow-sql` in it; and the defaults file:
`SLOTHWEB_ARGS` once and empty, no live `--web-allow-remote`, the
commented recipe present with a `/32`, every IPv4 literal loopback or a
`100.64.0.0/24` placeholder.

## 7. What this does not do

- It does not shed `CAP_NET_ADMIN` while `--hop` is on. Every retune
  opens a fresh nl80211 socket, so the capability is needed for the
  whole run; sloth drops everything else (#140, §3.3).
- It does not run fully unprivileged or through a privsep helper (track
  X "do not" list: not now).
- It does not put TLS or bearer tokens on the data socket; the `unix:`
  path and `SO_PEERCRED` are the authentication (owner decision
  2026-09-25, #100).
- It does not chmod or chown anything the operator owns. The migration
  (§4) does that, once, run by the owner — and to a copy, never to the
  original `data/`.

## Related pages

- [[data-socket-exposure]] — the `unix:` trust boundary the unit relies on
- [[monitor-mode]] — what `sloth-monitor-up` prepares and why sloth never does
- [[sqlite-schema]], [[retention]] — the `--db` artefact under `/var/lib/sloth`
- [[pcap-export]] — the `--pcap-dir` contents
- [[posture-report]] — what `SIGTERM` writes before exit
- [[inventory]] — why `--my-ssid`/`--my-bssid` are configuration
- [[cli-reference]] — every flag in the `ExecStart`
- [[slothweb]], `web/README.md` — the web UI `slothweb.service` runs, and the sloth.db freshness its DB-backed views show (#168)
