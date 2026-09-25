# Data-socket exposure and the trust boundary

How `--data-socket` is reachable, who is allowed to read it, and how to
get the stream to another host without putting it on the network
yourself.

Wire format: [[jsonl-schema]]. Reference consumers:
[`examples/consumer/`](../../examples/consumer/) and
[`examples/forwarder/`](../../examples/forwarder/).

---

## 1. The short version

**The data socket has no authentication and no encryption, and it is
never going to have any** (owner decision, 2026-09-25, issue #86).
Reachability *is* the access control. So:

| Deployment | Who can read the stream | Verdict |
|---|---|---|
| `unix:/run/sloth.sock` (0600) | only uid 0 and the socket's owner | **recommended** |
| `tcp:127.0.0.1:8765` (the default) | any local user on the host | fine on a single-purpose sensor |
| `tcp:<routable>:8765` | anyone who can reach the port | needs `--data-socket-allow-remote`, and you should not |

Nothing is exposed off-host unless an operator explicitly types a
routable address *and* passes the opt-in flag. That is the whole
guard — see §4.

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
sloth --headless --data-socket unix:/run/sloth.sock
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
  Keep it local (--data-socket unix:/run/sloth.sock, or the default
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
> entirely with `--no-discovery`.

---

## 5. Getting the stream to another host

All three supported paths keep sloth listening on loopback or a UNIX
socket. The tunnel or the forwarder owns the authentication and the
encryption, because those are solved problems outside sloth and a
crypto stack inside a C99 binary is not (#86, #100).

### 5.1 SSH port-forward — the default answer

Run sloth with the default loopback socket on the sensor:

```sh
sloth --headless --data-socket          # tcp:127.0.0.1:8765
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
python3 examples/forwarder/sloth-forward.py unix:/run/sloth.sock \
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

No systemd unit ships in-tree — deployment stays under operator control
([`FACTORY.md`](../../agents/FACTORY.md) §7). The unit you want is
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
