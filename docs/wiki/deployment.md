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
build tree.

**Sources**: `packaging/systemd/sloth-sensor.service`,
`packaging/systemd/sloth.sysusers.conf`, `packaging/bin/sloth-monitor-up`,
`packaging/default/sloth`, `Makefile` (`install`, `install-service`),
`tests/test_unit_file.c`, `src/secure_file.c`, `src/data_socket.c`,
`MISSION.md` §2.

**Last updated**: 2026-10-14 (#139)

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
getting more. An in-process privilege drop (track X7) is defence in
depth on top of this, not a prerequisite for it.

## 2. What gets installed

| Target | File | Installed as | Mode | Why there |
|---|---|---|---|---|
| `install` | `sloth` | `/usr/local/bin/sloth` | 0755 | root-owned, so the running binary cannot be swapped by the build user |
| `install` | `packaging/bin/sloth-monitor-up` | `/usr/local/sbin/sloth-monitor-up` | 0755 | the only thing that touches link state; runs as root from `ExecStartPre=+` |
| `install` | `research.db` | `/usr/local/share/sloth/research.db` | 0644 | `--with-research` opens it `SQLITE_OPEN_READONLY`; read-only data, so `secure_file.c`'s ownership rule does not apply |
| `install-service` | `packaging/systemd/sloth-sensor.service` | `/etc/systemd/system/sloth-sensor.service` | 0644 | the unit below, with `/usr/local/` rewritten to `$(PREFIX)/` if you changed it |
| `install-service` | `packaging/systemd/sloth.sysusers.conf` | `/usr/lib/sysusers.d/sloth.conf` | 0644 | declares the `sloth` account; `systemd-sysusers` creates it, make never does |
| `install-service` | `packaging/default/sloth` | `/etc/default/sloth` | 0644, `install -b` | site settings; an existing copy is kept as `/etc/default/sloth~` |

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
| `SystemCallFilter=` | `@system-service`, then `~@privileged @resources` | the standard service allow-list minus privilege changes and resource-limit calls; sloth uses neither |
| `SystemCallErrorNumber=` | `EPERM` | a blocked call fails with an error sloth already handles, instead of `SIGSYS` |
| `SystemCallArchitectures=` | `native` | no 32-bit syscall table |
| `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute` | `true` | none needed; SQLite does not JIT |

If X7 (an in-process `setresuid`/`capset` drop) lands, verify on the
target host that those calls pass `@system-service` minus
`@privileged` — `capset` is in `@privileged` — or the drop fails with
`EPERM` at startup. The unit carries the same note.

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

## 4. Migration from a build-tree unit

For a sensor still running the hand-written unit (root, out of a
checkout, state under `data/`):

```sh
cd /path/to/checkout
sudo systemctl stop sloth-sensor
sudo make install install-service
sudo systemd-sysusers                       # creates the sloth account
sudo install -d -m0700 -o sloth -g sloth /var/lib/sloth /var/lib/sloth/pcap
sudo mv data/sloth.db* data/snapshot.txt /var/lib/sloth/   # keep history + baseline
sudo chown -R sloth:sloth /var/lib/sloth
sudoedit /etc/default/sloth                 # SLOTH_IFACE, --my-ssid/--my-bssid/--site-label
sudo systemctl daemon-reload
sudo systemctl enable --now sloth-sensor
journalctl -u sloth-sensor -f
```

Notes:

- `mv` the db **and its `-wal`/`-shm` side files** together (the glob
  does that); SQLite gives the side files the main file's mode and
  `db.c` refuses a permissive or symlinked one rather than repairing it
  (#87, "validated, never repaired").
- A missed `chown` is loud: the first write fails with `owned by another
  user — refusing` and the unit restarts until you fix it. It does not
  degrade quietly.
- `/etc/default/sloth` is installed with `install -b`; if you had one,
  the previous copy is at `/etc/default/sloth~`.
- The old unit's `ConditionPathExists=` is gone on purpose. If the
  binary is missing the unit now fails and says so, instead of being
  silently skipped.
- `make clean` in the checkout no longer affects the service. `make
  install` is the deploy step.

## 5. Verifying a deployment

```sh
systemctl show -p User,AmbientCapabilities,CapabilityBoundingSet sloth-sensor
# User=sloth
# AmbientCapabilities=cap_net_admin cap_net_raw
# CapabilityBoundingSet=cap_net_admin cap_net_raw
ps -o user,cap_eff -C sloth                 # not root
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

## 6. What this does not do

- It does not drop privileges *inside* sloth. The process holds
  `CAP_NET_ADMIN` for its lifetime because `--hop` needs it per retune.
  X7 is that work.
- It does not run fully unprivileged or through a privsep helper (track
  X "do not" list: not now).
- It does not put TLS or bearer tokens on the data socket; the `unix:`
  path and `SO_PEERCRED` are the authentication (owner decision
  2026-09-25, #100).
- It does not chmod or chown anything the operator owns. The migration
  recipe does that, once, by hand.

## Related pages

- [[data-socket-exposure]] — the `unix:` trust boundary the unit relies on
- [[monitor-mode]] — what `sloth-monitor-up` prepares and why sloth never does
- [[sqlite-schema]], [[retention]] — the `--db` artefact under `/var/lib/sloth`
- [[pcap-export]] — the `--pcap-dir` contents
- [[posture-report]] — what `SIGTERM` writes before exit
- [[inventory]] — why `--my-ssid`/`--my-bssid` are configuration
- [[cli-reference]] — every flag in the `ExecStart`
