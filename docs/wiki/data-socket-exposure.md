# Data-socket exposure and the trust boundary

How `--data-socket` is reachable, who is allowed to read it, and how to
get the stream to another host without putting it on the network
yourself.

Wire format: [[jsonl-schema]]. Reference consumers:
[`examples/consumer/`](../../examples/consumer/) and
[`examples/forwarder/`](../../examples/forwarder/).

**Summary**: What the read-only data socket exposes, which transport
authenticates (`unix:` via the kernel; `tcp:` does not), the
remote-bind guard, the per-peer slot cap and idle timeout, and how to
carry the stream off-host without putting it on the wire yourself.

**Sources**: `src/data_socket.c`, `src/data_socket.h`, `src/main.c`,
`src/tune.c`, `src/jsonl.c`, `src/discovery.c`, `src/secure_file.c`,
`packaging/`.

**Last updated**: 2026-10-15.

---

## 1. The short version

**The data socket has no authentication and no encryption, and it is
never going to have any** (owner decision, 2026-09-25, issue #86).
Reachability *is* the access control. So:

| Deployment | Who can read the stream | Verdict |
|---|---|---|
| `unix:/run/sloth/sloth.sock` (0600) — **the bare-flag default** | only uid 0 and the socket's owner | **recommended** |
| `tcp:127.0.0.1:8765` (must be typed) | any local user on the host | fine on a single-purpose sensor |
| `tcp:<routable>:8765` | anyone who can reach the port | needs `--data-socket-allow-remote`, and you should not |

Nothing is exposed off-host unless an operator explicitly types a
routable address *and* passes the opt-in flag. That is the whole
guard — see §4.

### 1.1 The bare flag (#136)

Bare `--data-socket` means `unix:/run/sloth/sloth.sock` (owner ruling
2026-10-15). Before #136 it meant `tcp:127.0.0.1:8765` — a listener
every local account can read, chosen for an operator who never asked
for TCP (CWE-1188). The directory is checked before anything is bound,
by the same rule sloth applies to every system directory it writes into
without creating (`sfile_system_dir`): a real directory, not a symlink,
owned by root or sloth's effective uid, not group/other-writable.
sloth never creates or chmods it. If the check fails, sloth exits `2`:

```
$ sloth --headless --data-socket
sloth: --data-socket default unix:/run/sloth/sloth.sock: /run/sloth: No such file or directory.
  Create it (RuntimeDirectory=sloth, or: install -d -m 0750 -o 1000 /run/sloth)
  or name a transport explicitly: --data-socket tcp:127.0.0.1:8765
```

The uid in the `install` line is sloth's own effective uid, so the
directory it creates is one the check accepts. There is **no fallback
to TCP**: a bare flag that silently became a loopback listener would
widen exposure in exactly the case the operator chose nothing. Explicit
`unix:` and `tcp:` specs are unchanged. The shipped unit already passes
the `unix:` spec explicitly and provisions the directory with
`RuntimeDirectory=sloth` (`packaging/systemd/sloth-sensor.service`),
so it is unaffected.

---

## 2. What is actually on the wire

This matters because "read-only" is a statement about *commands*, not
about *data*. Read-only means nothing flows back into sloth
([`MISSION.md`](../../MISSION.md) §4). It does not make the stream
harmless to disclose.

A consumer of the data socket sees everything sloth sees:

- SSIDs and BSSIDs in range, including the preferred-network lists
  (PNLs) that bystander devices broadcast — a location history for
  every phone that walks past the sensor.
- MAC addresses, hostnames, DHCP names, mDNS service names.
- DNS queries, TLS SNI, HTTP hosts and user-agents — who is talking to
  what.
- Captured credential material: cleartext creds from FTP/POP3/IMAP/SMTP,
  SNMP community strings, EAPOL/PMKID handshake material, Kerberos and
  LDAP observations.

That is the disclosure a routable bind creates. It is not sloth's own
telemetry; it is third-party data about everyone in radio range, which
is why the default refuses to publish it.

---

## 3. The recommended deployment: `unix:` mode

```sh
sloth --headless --data-socket unix:/run/sloth/sloth.sock
# or, identically since #136:
sloth --headless --data-socket
```

The socket file is created **0600, owned by the uid sloth runs as**.
sloth forces the mode via `umask` across the `bind()` rather than
inheriting the process umask (which on a default `0022` host would
produce a world-connectable `0755` socket) and rather than `chmod()`ing
afterwards (which leaves a window where the socket is already
listening at the looser mode).

**This is real authentication, not a convention.** When a client calls
`connect()`, the kernel checks the caller's credentials against the
socket file's permissions before the connection is ever established.
An unauthorised local user does not get a refused handshake — they get
`EACCES` and never reach sloth's code at all.

What that buys, compared with any token or TLS scheme:

- **Nothing to rotate.** No key, no certificate, no shared secret.
- **Nothing to expire.** No renewal job, no outage at 03:00 when a cert
  lapses.
- **Nothing to leak.** There is no credential to put in a config file,
  an environment variable, or `ps` output.
- **Nothing to brute-force.** There is no auth exchange to attack.

The path is also protected on startup: sloth `lstat()`s it without
following symlinks, refuses to replace anything that is not a socket it
owns, and probes for a live instance before unlinking a stale one
(issue #86, commit `f2bf0b5`).

Grant access by group instead of uid if a collector runs as its own
user — put the socket in a directory owned by a shared group, or run
the reader as the same uid. sloth does not chown the socket for you.

---

## 4. The remote-bind guard

`--data-socket` accepts a literal IPv4 `tcp:HOST:PORT`. Since #86:

- **`127.0.0.0/8` binds freely.** The whole loopback `/8`, not just
  `127.0.0.1` — `127.0.0.2` is equally unreachable from off-host, and
  an operator already using one does not need a new flag.
- **Everything else is refused** unless `--data-socket-allow-remote` is
  also passed. That includes the `0.0.0.0` wildcard, which is the worst
  case rather than an exception: it binds every interface the host has.
- The refusal happens **before `socket()` is called**, so a bind you did
  not opt into never reaches the kernel.
- `unix:` paths are unaffected in both directions — a filesystem socket
  has no address to be reachable at.

Refused, with the remedy named:

```console
$ sloth --data-socket tcp:192.168.1.50:8765
data-socket: refusing to bind 192.168.1.50:8765 — not a loopback address.
  The JSONL stream is unauthenticated and unencrypted: anyone who
  can reach that port reads every observation sloth makes.
  Keep it local (--data-socket unix:/run/sloth/sloth.sock, or the default
  tcp:127.0.0.1:8765) and forward it yourself:
      ssh -L 8765:127.0.0.1:8765 user@this-host
  To expose it anyway, add --data-socket-allow-remote.
```

Allowed, with the exposure named:

```console
$ sloth --data-socket tcp:192.168.1.50:8765 --data-socket-allow-remote
sloth: WARNING: data-socket is bound to 192.168.1.50:8765, which is not a
  loopback address. The stream is UNAUTHENTICATED and UNENCRYPTED —
  every host that can reach 192.168.1.50:8765 can read every observation,
  including SSIDs, MAC addresses, hostnames and captured credentials.
  Authorised by --data-socket-allow-remote.
```

The flag is a speed bump on a deliberate choice, not a veto. It exists
so that exposure is something an operator *typed*, not something they
inherited from a default.

> **Note.** A routable bind is also what enables the mDNS
> advertisement carve-out ([`MISSION.md`](../../MISSION.md) §2): sloth
> drops an Avahi service file so the sloth-ios client can find the
> socket. Loopback and `unix:` sockets never advertise. Suppress it
> entirely with `--no-discovery` — or with `--strict`, which refuses it
> for the whole run (#84).
>
> **How the file is written** (#134). `/etc/avahi/services/sloth.service`
> is written as root into a directory sloth does not own, and until #134
> it was a plain `fopen(path, "w")`: a symlink planted at that name was
> followed and its target truncated (CWE-59/CWE-367). It now goes through
> `secure_file.c` like every other write: the directory is pinned with
> `sfile_system_dir()` (root- or euid-owned, not group/other-writable —
> `0755` is accepted, a `1777` `/tmp` is refused), the XML lands in an
> `O_EXCL` temp inside that pin, is `fsync`ed, and takes the final name
> by `renameat()`, which *replaces* a planted link rather than following
> it. The file is `fchmod`ed to **0644 on purpose**: avahi-daemon runs as
> `avahi` and has to read it, and the content — hostname and port — is
> what the announcement broadcasts anyway. That is the one place sloth
> loosens a mode, by descriptor on a file it created a moment earlier;
> operator paths are still validated, never repaired. `discovery_unpublish()`
> removes the file through the held directory descriptor. Nothing here is
> on the shipped unit's path, which passes `--no-discovery`.
>
## 4.1 Slots and idle (#135)

The listener holds **16 client slots** (`MAX_CLIENTS` in
`src/data_socket.c`), and until #135 nothing said who could fill them:
one local account on the loopback TCP default — or, behind
`--data-socket-allow-remote`, one host — could open sixteen connections
and every other consumer got nothing (CWE-770). Two knobs in the
`--tune` registry now govern the slots. Neither changes a transport, an
address or a default.

| Knob | Default | Range | What it does |
|------|---------|-------|--------------|
| `socket.max_per_peer` | 4 | 1..16 | Concurrent clients one peer may hold. 16 = no per-peer cap. |
| `socket.idle_secs` | 900 | 0..86400 | Seconds without progress before a client is closed, whatever its queue holds. 0 = never. |

**Who counts as a peer.** Decided at `accept()`, from what the kernel
vouches for and nothing else. On `unix:` it is the connecting **uid**,
read with `SO_PEERCRED` — the same credential the 0600 mode relies on.
On `tcp:` it is the peer's **IPv4 address** from `getpeername()`. A
connection the kernel cannot identify (an address family this module
never binds, a failed `getsockopt`) falls into one shared **"unknown"
bucket** that is capped like any single peer. That is the fail-closed
direction: an exemption for the unidentifiable would be the one every
flood took.

**Over the cap.** The connection is `close()`d at accept — the peer
sees EOF, not a hang — `socket_peer_refused` in `sensor_health` goes up
by one ([[jsonl-schema]]), and one line reaches stderr at most once per
60 s so a reconnect loop arrives in the journal as a rate, not a flood:

```
data-socket: refused a connection from uid 1000: it already holds 4 client slots (socket.max_per_peer); 7 refused since start
```

The accept drain continues past a refusal, because the next queued
connection may be another peer's and it is owed its slot. The cap is on
*concurrent* holdings, not a lifetime quota: close one and the same
peer's next connection is served.

**Idle.** Each client carries a progress mark that moves on accept, on a
record queued onto an empty queue, and on every byte the kernel takes.
The 30 s stall rule (`DATA_SOCKET_STALL_SECS`) only ever ran while
bytes were queued, so a client sloth never needed to write to — or one
whose queue drained and then went quiet — held its slot for the life of
the process. `socket.idle_secs` closes a client whose mark is older than
the knob **regardless of queue state**. The default, 900 s, is three
JSONL heartbeats (`JSONL_HEARTBEAT_SECS` = 300): a live consumer is
offered a record at least every 300 s and never reaches it; one that has
seen nothing for three beats is not a consumer any more. A client
dropped this way that reconnects receives the full baseline again
(#47), so the cost of a false positive is one reconnect, not lost data.

**What this does not do.** It authenticates nobody — a peer under the
cap on loopback TCP is still any local account. And a per-peer cap is
not a reservation: with 16 slots and 4 per peer, four peers fill the
listener and a fifth is turned away by the global guard, not by this
one. The guarantee is that no single peer can hold the listener against
the others indefinitely, never that any peer has a slot kept for it.

**The loopback-TCP notice.** Since #135 sloth says at start-up what a
loopback `tcp:` spec means. (Until #136 that was also the bare-flag
default; the bare flag is now `unix:`, §1.1, so loopback TCP is only
ever something an operator typed.)

```
sloth: data-socket tcp:127.0.0.1:8765 is readable by every local account; prefer unix:/run/sloth/sloth.sock (0600, kernel-checked peer)
```

Printed for any loopback `tcp:` spec.
`unix:` paths do not get it, and a routable bind has its own warning
(§4). Announced rather than changed, per `MISSION.md` §2.

## Where the socket lives, and who may read it

**`/run/sloth/sloth.sock`, created by `RuntimeDirectory=`** (owner
decision, 2026-10-06). The path matters more than it looks:

- **Not `/tmp`.** A world-traversable, sticky-bit directory is the wrong
  home for a daemon socket, and it invites the symlink races
  `secure_file.c` already has to defend against elsewhere.
- **Not `/run/sloth.sock` either**, even though that reads cleaner.
  `/run` is root-owned, so a sloth running as a dedicated unprivileged
  uid — which is the posture worth recommending — cannot create a node
  there. A bare `/run` path and an unprivileged uid are two
  recommendations that contradict each other, which is why this section
  names one path and one mechanism.
- **`RuntimeDirectory=sloth`** makes systemd create `/run/sloth/` owned
  by the unit's `User=` before `ExecStart`, and remove it on stop. That
  is what lets an unprivileged sloth bind inside it:

```ini
[Service]
User=sloth
Group=sloth
RuntimeDirectory=sloth
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/sloth --data-socket unix:/run/sloth/sloth.sock -o /var/log/sloth/sloth.jsonl
```

### Who can read it

sloth creates the socket `0600`, owned by its own euid. So a consumer
running as a **different** user gets `EACCES` from the kernel at
`connect()`, before any sloth code runs. Three ways out, in the order
worth preferring:

1. **Run the consumer as the same user** (`sudo -u sloth …`). Nothing to
   configure, nothing widened.
2. **Share by directory group**, not by socket mode.
   `RuntimeDirectoryMode=0750` with `Group=sloth` lets anyone in that
   group traverse `/run/sloth/` — then the `0600` socket still only
   admits its owner, so this alone is not enough; pair it with (1).
3. **Widen the socket by hand** (`chgrp`/`chmod g+rw` after start). Note
   what sloth does and does not check: `unix_path_removable()` inspects
   the node's **type and owner** at startup and never its **mode**, and
   it runs *before* the bind — so a widened mode is not rejected,
   because by then sloth has stopped looking. That is a deliberate
   ceiling on what sloth can promise, not an invitation; the operator
   who widens it owns the consequence.

A `root` reader is the usual exception, and the mechanism is
`CAP_DAC_OVERRIDE` rather than uid 0 as such — a root process in a unit
or container that dropped that capability is refused like anyone else.

> **Settled 2026-10-06 (#84): `--strict` refuses a routable bind.**
> `--strict --data-socket tcp:<routable>:PORT` exits 2, and
> `--data-socket-allow-remote` does not change that — the opt-in is how
> an operator says "expose this", `--strict` is how they say "not on
> this run", and a lock any other flag can override is not a lock. The
> refusal happens before any sink opens, so a refused run binds nothing.
>
> A loopback bind (`tcp:127.0.0.1:PORT`) and a `unix:` path are
> unaffected: neither leaves the host, and bare `--strict --data-socket`
> is a documented pairing. An unparseable spec is left to the binder,
> which names the actual typo rather than blaming `--strict`.
>
> So under `--strict` the remaining paths by which a run touches the
> network are the ones MISSION.md §2 accounts for, not this one.

---

## 5. Getting the stream to another host

All three supported paths keep sloth listening on loopback or a UNIX
socket. The tunnel or the forwarder owns the authentication and the
encryption, because those are solved problems outside sloth and a
crypto stack inside a C99 binary is not (#86, #100).

### 5.1 SSH port-forward — the default answer

Run sloth with a loopback socket on the sensor — typed, since the bare
flag means `unix:` (§1.1):

```sh
sloth --headless --data-socket tcp:127.0.0.1:8765
```

From the management host, pull the port across:

```sh
ssh -N -L 8765:127.0.0.1:8765 user@sensor
```

Then read it locally as if it were on your own machine:

```sh
nc 127.0.0.1 8765 | jq -c 'select(.type == "alert")'
python3 examples/consumer/sloth-consume.py tcp:127.0.0.1:8765
```

`-N` means "no remote command, just the tunnel". Authentication is your
existing SSH key; encryption is the SSH transport. Nothing new to
manage. Keep it up across drops with `autossh -M 0 -N -L ...` or a
systemd unit (§5.4).

To go the other way — sensor pushes to a fixed collector, useful when
the sensor is behind NAT — use a remote forward from the sensor:

```sh
ssh -N -R 8765:127.0.0.1:8765 user@collector
```

### 5.2 stunnel — when the reader cannot speak SSH

Use this when the consumer is an appliance or a SIEM that takes a TCP
stream and you need TLS on the path but cannot wrap it in SSH.

Ready-to-edit configs ship in
[`examples/stunnel/`](../../examples/stunnel/) — read that README
before deploying, because getting `accept` and `connect` backwards is
the one mistake that silently exposes the plaintext side.

The shape: on the sensor, stunnel accepts TLS on a routable port and
connects to sloth's loopback socket; on the reader, stunnel accepts on
loopback and connects to the sensor over TLS. sloth itself still binds
only `127.0.0.1`, so the guard in §4 never has to be overridden.

Use `verify = 2` with a real peer certificate. Without it you have
encryption against a passive listener and nothing against an active
one, which for this data is not the threat you care about.

### 5.3 The shipped forwarder — push to a SIEM

[`examples/forwarder/sloth-forward.py`](../../examples/forwarder/) is a
stdlib-only Python 3.7+ program that **connects to sloth as a local
client and pushes outbound** to a collector. It inverts the direction:
nothing listens remotely on the sensor at all.

```sh
python3 examples/forwarder/sloth-forward.py unix:/run/sloth/sloth.sock \
    --sink hec \
    --hec-url https://splunk.example.com:8088/services/collector \
    --hec-token-env SLOTH_HEC_TOKEN
```

Sinks that ship: `hec` (Splunk HTTP Event Collector), `syslog`
(RFC 5424 over UDP or TCP), `elastic` (Bulk API, also OpenSearch),
`loki`, `datadog`, and a generic `webhook`. `--sink a,b` fans out to
several at once. Records can be filtered before they leave
(`--type alert`, `--src IP`) and are batched (`--batch-size`,
`--batch-ms`).

The TLS and the credentials live in the forwarder's outbound
connection — HTTPS to the collector, tokens read from the environment
so they stay out of `ps`. Delivery is non-durable by design: a batch
the sink refuses after `--max-retries` is dropped and counted. If you
need durability, also write `-o /var/log/sloth.jsonl` and ship the file
with filebeat/vector/fluent-bit on a separate path.

**This is the pattern the architecture already assumes:** sloth emits
locally, a separate process does the talking. See
[`examples/compose/`](../../examples/compose/) for a one-command Loki +
Grafana stack wired to this sink.

### 5.4 Keeping the tunnel up

The sensor side ships a unit since #139 ([[deployment]]); the tunnel on
the management host is still the operator's, and the unit you want is
small:

```ini
# /etc/systemd/system/sloth-tunnel.service  (on the management host)
[Unit]
Description=SSH tunnel to the sloth sensor data socket
After=network-online.target

[Service]
Type=simple
User=sloth
ExecStart=/usr/bin/ssh -N -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
    -L 8765:127.0.0.1:8765 user@sensor
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`ExitOnForwardFailure=yes` matters: without it a failed forward leaves
a live SSH session and a tunnel that silently carries nothing.

---

## 6. What was deliberately not built

In-process TLS/mTLS and bearer tokens were considered and **rejected**
(owner decision, 2026-09-25). The design is recorded in issue #100 and
is not scheduled.

The reasoning, so it does not get re-argued:

- A crypto dependency (OpenSSL, mbedTLS) in a C99 tool that must keep
  an `embedded` build variant and six warning-clean builds buys a
  certificate lifecycle and a CVE treadmill.
- It would be protecting a socket that should not be reachable in the
  first place. The fix for "this port is exposed" is to not expose the
  port.
- It points the opposite way from
  [`MISSION.md`](../../MISSION.md) §4, which already says a SOC
  aggregating across hosts uses a local consumer that ships upstream —
  and that consumer is not part of sloth.

What this slice does and does not claim: it makes "no remote exposure
by default" *technically true* and puts a guard in front of the
foot-gun. Whether that closes an external reviewer's "remotely exposed"
finding is the reviewer's call, not something sloth asserts about
itself.

---

## See also

- [[jsonl-schema]] — the record format on the socket.
- [[retention]] — what `--db` keeps, and for how long.
- [`MISSION.md`](../../MISSION.md) §2, §4 — passivity rules and the
  read-only-socket scope.
- [`agents/FACTORY.md`](../../agents/FACTORY.md) §6.2 — invocation forms.
- [[cli-reference]] — `--tune socket.max_per_peer` / `socket.idle_secs`.
