# slothweb

A browser dashboard for [sloth](../README.md), the passive network
monitor. It runs beside sloth on the same host, reads sloth's live
record stream (the data socket) and, if you point it there, sloth's
SQLite file, and serves one page on `http://127.0.0.1:8770/`: live
counts and a record ticker, time series with hour-of-week baselines,
anomaly episodes, the device table, WiFi, a time-travel History view,
and the protocol flows. It never sends anything onto a network and
never writes to sloth or to `sloth.db`.

![Overview](../docs/assets/slothweb/overview.png)

The spec is [`docs/web-ui-spec.md`](../docs/web-ui-spec.md) (the
rulings table at its top overrides the body); the wiki page is
[`docs/wiki/slothweb.md`](../docs/wiki/slothweb.md). Everything below
the Security section is reference: the command line, every route, and
how each part works.

## Five minutes

### Prerequisites

- Linux, a C99 compiler (`cc`),
  `make`, and the SQLite 3 headers and library: `libsqlite3-dev` on
  Debian and Ubuntu, `sqlite-devel` on Fedora.
  SQLite 3.31 or newer; nothing else is linked but libc, pthreads and
  libm.
- A browser on the same host, or an SSH tunnel to it.
- `curl`, only for the checks in this section.
- For real data: sloth, built from this tree (`make`) and run with
  `--data-socket` (below). Not needed for the demo.

### Build

From the top of this tree:

```sh
make web            # ./slothweb (with SQLite, the default)
make web-demo       # build/web/slothweb-demo, the synthetic data for the demo below
```

`make web WITH_SQLITE=0` builds a slothweb with no SQLite at all: no
`--sloth-db`, no `--store`, history in memory only.

**The vendor table.** The IEEE registry CSVs (MA-L, MA-M, MA-S and
IAB) are committed in `web/data/` (owner ruling 2026-10-26), so `make
web` builds the full table and rule A4 (vendor unknown) is on by
default; `/api/health` says `"vendor_table":"ieee"`. Neither the build
nor slothweb ever fetches anything. `web/data/SOURCE.md` names where
the files come from, their package version and SHA-256 (`make
web-test` checks the hashes). `make update-oui` refreshes them by hand,
from `/usr/share/ieee-data` when Debian's `ieee-data` package is
installed and otherwise from the IEEE; review and commit the result.
`make web WEB_OUI_DIR=DIR` builds from another directory, and one
without the CSVs gives sloth's own small table (about 120 vendors) with
A4 off. The Bluetooth SIG assigned numbers the BLE view names (company
identifiers, 16-bit service UUIDs, appearance values) are the same
shape: three CSVs committed in `web/data/btsig/`
([`SOURCE.md`](data/btsig/SOURCE.md)), compiled in by
`web/tools/btsig_gen.c`, refreshed by hand with `make update-btsig
SRC=DIR` from a directory of the SIG's YAML (never a fetch), and
`make web WEB_BTSIG_DIR=DIR` without them builds an empty table
(`"sig":"none"` in `/api/health`'s `ble` member; the page shows the
numbers alone).

**Vendor research.** Under the OUI card the drawer and the Lookup card
show what `web/data/vendors/` documents about the block's holder (owner
request 2026-10-27): kind, country, parent, founded, the device classes
a MAC in its blocks usually is, products found carrying it, radios,
the silicon documented in its modules and products, FCC grantee codes,
randomisation, security notes, a summary and numbered sources, each
field with a confidence word and every claim with a `[n]`. One Markdown
file per vendor, compiled in at build time by `web/tools/vendorkb.c`
(`make web-vendorkb` checks the files alone); a file with a dangling
`[n]`, a source no `[n]` cites, a missing field or a name not its
file's fails the build naming the file. A vendor with no file shows "no
research yet for <name>". A registrant that is a separate company in
an entry's group (an affiliate: a subsidiary, branch or parent with
blocks of its own) finds that entry, marked as another company's, with
country, parent and founded left unknown.
Sources are plain text, never links. There are
<!-- count:vendors -->276<!-- /count --> entries. Most of the
reference host's vendor names find one; those that do not (SJI
Industry Company, Reliance Communications LLC, SJIT Co., Ltd. today)
are pending because no public documentation ties them to a company;
[`web/data/vendors/COVERAGE.md`](data/vendors/COVERAGE.md) lists both
and carries the totals, and `test_vendorkb.c` holds it to the entries
and to `web/data/vendors/REFERENCE_HOST.txt` (names only, no device
counts). Format, coverage and rules:
[`docs/wiki/vendor-research.md`](../docs/wiki/vendor-research.md).

The full table costs the binary about 2.8 MB: slothweb is 3.3 MB with
it and 0.5 MB without (x86-64, `-O2`, measured 2026-10-26); the
generator itself runs in under 0.1 s, and a clean `make web` takes
about the same either way (7 to 8 s here).

### Try it on synthetic data

No sensor needed. `slothweb-demo` writes a made-up `sloth.db` from
sloth's own schema and serves a generated record stream on a unix
socket, the way sloth's `--data-socket` does. Everything in it is
invented: documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), locally administered MACs, `example` names.

<!-- quickstart:begin -->
```sh
make web web-demo
SRC=$PWD; cd "$(mktemp -d)"
"$SRC/build/web/slothweb-demo" db sloth.db
"$SRC/build/web/slothweb-demo" pcaps pcap
"$SRC/build/web/slothweb-demo" feed unix:sloth.sock &
"$SRC/slothweb" --socket unix:sloth.sock --sloth-db sloth.db --store slothweb.db --pcap-dir pcap
```
<!-- quickstart:end -->

Open `http://127.0.0.1:8770/`. The status strip should say `live`, the
footer `sock connected`, `db open`, `store open`. Stop with Ctrl-C,
then `kill %1` for the demo stream. `make web-quickstart-check` runs
exactly these steps in a temporary copy of the tree and checks the
answer (`web/tools/quickstart_check.sh`).

`pcap` is a made-up `--pcap-dir`: the capture sloth would save for the
demo's SMB1 alert once it escalates to CRIT (a few minutes in) and the
802.11 evidence of its first deauth flood, with their manifest, so an
alert's page shows its capture decoded and hash-checked ([An alert's
proof](#an-alerts-proof)). The deauth flood's file is an evidence pcap,
so it is listed but withheld; add `--web-serve-evidence-pcap` to the
last line to see it decoded too.

The time series start empty and fill at 10 s a bucket; baselines need
three weeks of a given hour before they draw a band, so a fresh store
says "no baseline yet". The demo's sloth.db already holds a month of
devices, alerts, sessions and flows for the Devices, WiFi, History and
Flows views.

Every MAC in the demo is locally administered, so the full vendor table
has nothing to name there: no device gets an IEEE vendor and A4 (vendor
unknown) never fires, though `/api/health` says `"a4":"on"`. That is the
rule working, not the table missing. To see the table, type a globally
administered MAC into Lookup (`00:1b:63:00:00:01` is an Apple block), or
run beside sloth on real traffic. The same goes for the vendor research
section under the OUI card: the stock demo never shows it, and Lookup
does for a researched vendor's block (`24:0a:c4:00:00:01`, Espressif,
with its FCC grantee code and the sources each line cites). The demo
stays locally administered, because everything in it is invented.

### Run it beside sloth

Start sloth with its data socket, and, for the Devices, WiFi, History
and Flows views, its database:

```sh
sudo ./sloth --headless --data-socket unix:/run/sloth/sloth.sock --db /var/lib/sloth/sloth.db
```

(`docs/wiki/deployment.md` has the systemd unit, which creates
`/run/sloth` with `RuntimeDirectory=sloth`; by hand,
`sudo install -d -m 0750 -o sloth /run/sloth`.) Then run slothweb as
the user sloth runs as: the `sloth` account after its privilege drop
(`docs/wiki/deployment.md`), or the `--user NAME` you gave it (put that
name in place of `sloth`). That account usually cannot reach a
checkout in your home directory, so install the binary first, and give
it a store in a directory it owns (`/var/lib/sloth` is `sloth`'s, mode
`0700`):

```sh
sudo install -m 0755 slothweb /usr/local/bin/slothweb
sudo -u sloth /usr/local/bin/slothweb --sloth-db /var/lib/sloth/sloth.db --store /var/lib/sloth/slothweb.db
```

- **The data socket.** `--socket` defaults to sloth's own default,
  `unix:/run/sloth/sloth.sock`; `--socket tcp:127.0.0.1:8765` reads a
  loopback TCP stream instead (`sloth --data-socket
  tcp:127.0.0.1:8765`). sloth creates its unix socket `0600` inside a
  `0750` directory, so the kernel's permission check is the stream's
  only authentication: slothweb must run as the same user as sloth, or
  as one the directory and socket admit. slothweb only ever reads the
  socket and reconnects on its own if sloth restarts.
- **`--sloth-db PATH`** is sloth's `--db` file, opened read-only. It
  may not exist yet: slothweb retries on every request.
- **`--store PATH`** is slothweb's own file (time series, baselines,
  anomaly episodes), default `./slothweb.db` in the directory you start
  it from, which must be one the user slothweb runs as can write. It is created `0600`; never point it at `sloth.db` (refused).

**As a service.** `packaging/systemd/slothweb.service` is all of the
above as a unit: `User=sloth`, `--socket unix:/run/sloth/sloth.sock
--sloth-db /var/lib/sloth/sloth.db --store /var/lib/slothweb/slothweb.db`,
no capability, `/var/lib/sloth` read-only, loopback unless
`/etc/default/slothweb` says otherwise (a Tailscale bind is documented
there, commented, with a single `/32` in `--web-allow`). `make install`
places the binary (after `make web`), `make install-service` the unit
and, only where there is none, the defaults file;
`sudo packaging/bin/sloth-migrate-sensor --dry-run --with-slothweb`
shows what installing it beside a migrated sensor would do, and the
same without `--dry-run` installs, starts and verifies it, rolling back
only slothweb if it fails. `docs/wiki/deployment.md` §4.3, §4.4 and §6.

### Open the page

`http://127.0.0.1:8770/` on the same host. From another machine,
forward the port rather than exposing it:

```sh
ssh -L 8770:127.0.0.1:8770 user@sensor     # then open http://127.0.0.1:8770/ locally
```

Keys: `1`..`9` switch views (`6` is the Alerts page), `/` searches
devices, `[` hides the view list and the footer, `Esc` closes the device drawer; the
view is also in the address (`#flows`, `#alerts?state=open`,
`#alert?id=d42`), so a reload stays on it and Back returns from a
drill-down. Every Overview tile is a link to the view of what it
counts ([Alerts](#alerts)).
The button at the right of the top bar switches to the light theme;
the choice is kept in this browser only (`localStorage`, key
`slothweb.v1.theme`), dark is the default, and a browser that keeps
nothing just gets dark ([Design](#design)). So is every other setting
a viewer can change, from each table's columns to the view the page
opens on ([Kept settings](#kept-settings)).

| | |
|---|---|
| ![Activity](../docs/assets/slothweb/activity.png) | ![Devices](../docs/assets/slothweb/devices.png) |
| ![Anomalies](../docs/assets/slothweb/anomalies.png) | ![WiFi](../docs/assets/slothweb/wifi.png) |
| ![Flows](../docs/assets/slothweb/flows.png) | ![History](../docs/assets/slothweb/history.png) |
| ![Lookup](../docs/assets/slothweb/lookup.png) | ![Flows at 360 px](../docs/assets/slothweb/flows-narrow.png) |
| ![Overview, light theme](../docs/assets/slothweb/overview-light.png) | ![Devices, light theme](../docs/assets/slothweb/devices-light.png) |
| ![Flows, light theme](../docs/assets/slothweb/flows-light.png) | ![Alerts](../docs/assets/slothweb/alerts.png) |
| ![An alert's page](../docs/assets/slothweb/alert.png) | ![An alert's page, light theme](../docs/assets/slothweb/alert-light.png) |

All screenshots are of the synthetic demo above, taken by headless
Chromium; none shows anything captured from a real network.

## Troubleshooting

Every message slothweb can print as it starts, from the source (a test,
`web/tests/test_readme.c`, fails when one is missing here). `PATH`,
`ADDR`, `N` and `ERR` stand for the values printed. Exit status: `2` for
a usage error or a policy refusal, `1` when the bind, the store or a
thread fails; slothweb is not running after either.

**Command line and policy** (exit 2):

| Message | Remedy |
|---|---|
| `slothweb: unknown option OPT (see --help)` | `./slothweb --help` lists the flags. |
| `slothweb: --flag needs an argument` | Give the flag its value. |
| `slothweb: --web-max-keys V: want a whole number from N to N` (also `--web-max-mb`, `--web-retain-days`) | Use a whole number in the range printed. |
| `slothweb: empty --web-bind` | `--web-bind 127.0.0.1:8770`. |
| `slothweb: bad --web-bind ADDR (want A.B.C.D:PORT or [V6]:PORT)`, `bad --web-bind ADDR (want [V6]:PORT)`, `bad --web-bind address in ADDR`, `--web-bind ADDR: bad port` | A literal address and a port: `127.0.0.1:8770`, `[::1]:8770`. |
| `slothweb: --web-bind ADDR: not a literal IPv4 address (names are not resolved)` | slothweb never resolves a name, its own bind included: `localhost:8770` is refused, write `127.0.0.1:8770`. |
| `slothweb: refusing to bind ADDR: not a loopback address.` | Keep it on loopback and use `ssh -L` (above), or, deliberately, add `--web-allow-remote` and name the peers with `--web-allow` (Security). |
| `slothweb: --strict refuses a non-loopback --web-bind (ADDR).`, `--strict refuses a non-loopback --web-allow (CIDR).`, `--strict refuses a non-loopback --socket (SPEC).` | `--strict` means loopback only, whatever else is given; drop one of the two. |
| `slothweb: --web-allow CIDR admits non-loopback peers; that needs --web-allow-remote.` | Add `--web-allow-remote` if you mean it. |
| `slothweb: --web-allow CIDR: empty address`, `bad address`, `not a literal IPv4 or IPv6 address`, `bad prefix`, `prefix too long`, `host bits set past the prefix` | A CIDR with its host bits zero: `10.0.0.0/8`, not `10.0.0.1/8`; no names. |
| `slothweb: too many --web-allow entries (max N)` | Use fewer, wider prefixes. |
| `slothweb: --socket SPEC: want unix:PATH or tcp:ADDR:PORT`, `want tcp:A.B.C.D:PORT or tcp:[V6]:PORT`, `want tcp:[V6]:PORT`, `bad address`, `bad port` | `--socket unix:/run/sloth/sloth.sock` or `--socket tcp:127.0.0.1:8765`. |
| `slothweb: --socket SPEC: not a literal IPv4 address (names are not resolved)` | A literal address, never a name. |
| `slothweb: --socket SPEC: the path must be 1..N bytes` | A unix socket path is limited to 107 bytes by the kernel: use a shorter path, or a relative one from the directory you start in. |
| `slothweb: --sloth-db: empty or too long a path`, `--store: empty or too long a path`, `--pcap-dir: empty or too long a path` | Give a path, shorter than 4,080 bytes. |
| `slothweb: --pcap-dir: at most N (the sensor's --pcap-dir and its --eapol-dir)` | Two directories at most: the sensor's `--pcap-dir`, and its `--eapol-dir` when it runs `--collect-handshakes`. |
| `slothweb: --pcap-dir PATH given twice` | Name each directory once. |
| `slothweb: --web-serve-evidence-pcap with --web-allow-remote would hand remote peers evidence pcaps` | An evidence pcap (`<incident>-<event>-<RULE>.pcap`, from the sensor's `--eapol-dir`) may hold EAPOL/PMKID handshake material, so serving it to remote peers takes its own spelling: `--web-serve-evidence-pcap=remote`. Or drop one of the two flags. Exit 2. |
| `slothweb: --sloth-db needs SQLite; this slothweb was built with WITH_SQLITE=0`, `--store needs SQLite; this slothweb was built with WITH_SQLITE=0`, `--web-allow-sql needs SQLite; this slothweb was built with WITH_SQLITE=0` | Rebuild with `make web` (SQLite is the default), or drop the flag. |
| `slothweb: --sloth-db and --store name the same file (PATH): sloth.db is sloth's, the store is slothweb's own` | Point `--store` somewhere else. |
| `slothweb: --web-allow-sql needs --sloth-db PATH: the box reads sloth.db and nothing else.` | Add `--sloth-db`, or drop `--web-allow-sql`. |
| `slothweb: --strict refuses --web-allow-sql.` | The SQL box is a query surface; `--strict` refuses it. Drop one. |
| `slothweb: --peer SPEC: want NAME=http://A.B.C.D[:PORT]`, `the name must be 1 to 32 of A-Z a-z 0-9 . _ -`, `the URL must start http:// (no TLS: the tailnet encrypts the link)`, `the URL is longer than 64 bytes`, `not a literal IPv4 address (names are not resolved)`, `bad port`, `the URL is the peer's address only, with no path` | `--peer w9fjc=http://100.101.102.103:8770`: a name of your own, then the peer slothweb's tailnet address and port, nothing after it ([Fleet](#fleet)). |
| `slothweb: --peer NAME: http://ADDR:PORT is outside the tailnet (100.64.0.0/10); refused without --peer-allow-outside-tailnet` | Use the peer's `100.x` tailnet address (`tailscale ip -4` on the peer). Only if the link is one you trust some other way, add `--peer-allow-outside-tailnet`; that is announced. |
| `slothweb: --peer SPEC: that name or address is given twice` | One `--peer` per peer, each with its own name. |
| `slothweb: --peer: at most N peers` | Eight peers at most. |
| `slothweb: --peer-interval-secs V: want a whole number from N to N` | 10 to 3600 seconds; the default is 60. |
| `slothweb: --peer-gnss-region-km V: want a whole number from 1 to N` | 1 to 20000 km; the default is 50. |
| `slothweb: --my-ssid: at most N`, `--my-bssid: at most N` | At most 16 of each, as sloth: name the networks a peer could meet. |
| `slothweb: --my-ssid: want 1 to N octets with no control character` | The SSID as sloth's `--my-ssid` takes it, 1 to 32 octets. |
| `slothweb: --my-bssid V: want aa:bb:cc:dd:ee:ff` | A MAC address, six octets in hex separated by colons. |
| `slothweb: --strict refuses --peer.` | Pulling a peer is a network service, which `--strict` refuses; drop one of the two. |
| `slothweb: --peer needs SQLite; this slothweb was built with WITH_SQLITE=0` | The pulled rows live in the store: rebuild with `make web`. |
| `slothweb: --web-max-mb N is below what --web-max-keys N needs: the baselines and episodes can take about N MB and the ceiling keeps N MB of history beside them (a week of hour rows for each of N series).` | Use the `--web-max-mb` it names, or a lower `--web-max-keys`. |

**Warnings** (slothweb runs; each names an exposure you asked for):

| Message | Meaning |
|---|---|
| `slothweb: WARNING: listening on ADDR, which is not a loopback address.` | `--web-allow-remote` and a routable `--web-bind`: every admitted peer reads everything, with no authentication and no TLS. |
| `slothweb: WARNING: admitting non-loopback peers in CIDR (--web-allow, authorised by --web-allow-remote).` | As it says. |
| `slothweb: WARNING: --web-allow-sql with --web-allow-remote: the SQL box (/api/query) ...` | Every admitted peer can run read-only SQL over sloth.db. |
| `slothweb: WARNING: reading the data stream from SPEC, which is not loopback.` | The stream crosses a network unencrypted; read it on the sensor instead, or tunnel it. |
| `slothweb: WARNING: --peer NAME at URL is outside the tailnet (--peer-allow-outside-tailnet).` | The pull and the export it reads travel as plain HTTP over whatever path reaches that address; only that path protects them ([Fleet](#fleet)). |

**Starting up** (exit 1 unless said):

| Message | Remedy |
|---|---|
| `slothweb: bind: Address already in use` (or another `bind: ERR`), `socket: ERR`, `IPV6_V6ONLY: ERR` | Another program (often another slothweb) holds the port: stop it, or `--web-bind 127.0.0.1:8771`. |
| `slothweb: store: PATH: not a slothweb store (another program's database, sloth.db perhaps); refused, left as it is. Use a separate --store` | `--store` names a file that is not slothweb's: give a new path. |
| `slothweb: store: PATH: application_id N is another program's database; refused, left as it is. Use a separate --store` | The same. |
| `slothweb: store: PATH: not a readable SQLite database (ERR); refused, left as it is` | The same, or the file is damaged: move it aside. |
| `slothweb: store: PATH: written by a newer slothweb (schema vN; this build writes vN); refused, left as it is. Use a separate --store` | Run the newer slothweb, or a separate `--store`. |
| `slothweb: store: PATH: slothweb store with no readable schema version; refused, left as it is` | Move the file aside; slothweb makes a new one. |
| `slothweb: store: PATH: schema vN could not be migrated to vN (ERR); the file is unchanged from vN` | Usually a full disk or a read-only directory; fix that and start again. |
| `slothweb: store: PATH: mode 0644 gives group or other access; it must be 0600 (not repaired)` | `chmod 600 PATH`. |
| `slothweb: store: PATH: owned by uid N, not this user` | Run as the file's owner, or use another `--store`. |
| `slothweb: store: PATH: a symlink is refused`, `not a regular file`, `has N links; it must have one`, `PATH: fstat: ERR`, `PATH: ERR` | Name the real file, in a directory you own. |
| `slothweb: store: PATH: changed while it was being opened; refused` | Something else is writing that path; give slothweb its own. |
| `slothweb: store: PATH: SQLITE_DBCONFIG_DEFENSIVE refused`, `libsqlite3 VERSION is older than 3.31.0`, `PATH: prepare: ERR` | The SQLite library is too old or built without what slothweb needs: install 3.31 or newer. |
| `slothweb: store: PATH: slothweb was built without SQLite (WITH_SQLITE=0); no store` | Not printed by a normal start (a memory-only build has no store); rebuild with `make web` for one. |
| `slothweb: store: the saved baselines or anomaly episodes could not all be read; starting from what was` | Runs on (no exit): the rows that could not be read are skipped. |
| `slothweb: store: the saved BLE advertisers could not all be read; starting from what was` | Runs on (no exit): the BLE view starts from the stream alone; the v7 tables are read again at the next start. |
| `slothweb: time series: out of memory` | Lower `--web-max-keys`. |
| `slothweb: --pcap-dir: out of memory` | The manifest index (4,096 entries, about 1.3 MB) could not be allocated; free memory and start again. |
| `slothweb: SQL box: cannot start its thread`, `slothweb: pipe: ERR`, `slothweb: pthread_create failed` | Out of threads or descriptors: check `ulimit -u` and `ulimit -n`. |
| `slothweb: fleet: ERR`: `--peer needs the store (slothweb.db), and there is none`, the store's own refusals for a third connection (`the store is not open`, `PATH: changed while it was being opened; refused`), `pthread_create failed` | The pull thread (a connection to the store of its own, [Fleet](#fleet)) could not start. Start again; exit 1. |

**sloth.db** (not fatal; slothweb runs and retries on every request,
and the page says why in each view that needs it):

| Message | Remedy |
|---|---|
| `slothweb: no --sloth-db: the Devices view and the drawer's sloth.db record are off; Lookup answers from the stream and the vendor table` | Add `--sloth-db PATH` for the Devices, WiFi AP table, History and Flows views. |
| `slothweb: sloth.db PATH: missing (PATH: not there (yet): sloth makes it with --db); Devices and A2's durable first_seen wait for it, retried on every request` | Start sloth with `--db PATH`, or fix the path. The same line carries each reason below. |
| `PATH: written by a newer sloth (schema vN): not read; update slothweb` | Build slothweb from the same tree as sloth. |
| `PATH: schema vN is older than any sloth.db`, `PATH: no schema_version in its meta: not a sloth.db`, `PATH: no devices table with sloth's columns`, `PATH: not a sloth.db (ERR)` | `--sloth-db` names something that is not sloth's database. |
| `PATH: a symlink is refused`, `PATH: not a regular file` | Name the real file. |
| `PATH: needs recovery by sloth, which it does when it next opens it (ERR)` | sloth stopped mid-write; start sloth and it recovers the file. |
| `PATH: SQLITE_DBCONFIG_DEFENSIVE refused`, `PATH: query_only: ERR` | The SQLite library lacks what slothweb needs: 3.31 or newer. |
| `no --sloth-db`, `slothweb was built without SQLite; no sloth.db` | The reason `/api/health` gives (`db_error`) when there is no sloth.db to read. |
| `--web-assessments: empty or too long a path`, `--web-assessments PATH: not a directory` | Give the directory holding the research assessments (`<TYPE>.md` with front matter), or leave the flag out: "follow recommended" then says "no recommendation yet". A path that is not there is accepted and means the same (`slothweb: follow recommended: PATH: no such directory, no recommendation yet`); `make install` puts them in `$(PREFIX)/share/sloth/alert-assessments`. |
| `--web-agent-secret: empty or too long a path`, `--web-agent-secret PATH: exists and is not a private regular file of this user (mode 0600, one link); refused, left as it is`, `--web-agent-secret: no random bytes from /dev/urandom`, `--web-agent-secret PATH: ERR` | The file slothweb writes the run's agent secret to ([Writes by an agent](#writes-by-an-agent)). Name a path in a directory slothweb's user can write (under the shipped unit `/run/slothweb`); slothweb replaces its own earlier file there and will not write over anything else (with `--web-agent-group`, its own file may also be `0640` in that group: `... (mode 0600, or 0640 with the --web-agent-group group, one link) ...`). Exit `1` for all but the first. |
| `--web-agent-group needs --web-agent-secret`, `--web-agent-group: empty or too long a name`, `--web-agent-group NAME: no such group`, `--web-agent-group: cannot give PATH.new the group (ERR); slothweb's user must be a member of the group` | The group the agent secret is given ([Writes by an agent](#writes-by-an-agent)). Create the group and add slothweb's user to it (`usermod -aG NAME sloth`; it takes effect at the next start of the service), or leave the flag out for a `0600` file. Exit `2` for the first two, `1` for the others. |
| `triage: ERR`, `the store is not open`, `PATH: changed while it was being opened; refused` | The triage and TACDB writer (a third connection to the store, [Triage and the FRRS record](#triage-and-the-frrs-record)) could not open what the store thread had just opened: the file was replaced or locked in between. Start again; exit 1. |

**The alert pcaps** (not fatal; each directory is opened afresh per
request, so one the sensor creates later is read once it exists):

| Message | Meaning |
|---|---|
| `slothweb: alert pcaps from PATH (read-only, opened per request; sloth's alert pcap names only, never a handshake pcap or eapol.22000; evidence pcaps listed and withheld)` (or `served`) | One line per `--pcap-dir`. Why a capture is missing is on the alert's page (`captures_note`, `why_no_capture`), not here. `served` only under `--web-serve-evidence-pcap`. |
| `slothweb: WARNING: --web-serve-evidence-pcap: evidence pcaps (<incident>-<event>-<RULE>.pcap from the sensor's --eapol-dir) are decoded and downloadable; they may hold EAPOL/PMKID handshake material, crackable offline.` | Printed whenever `--web-serve-evidence-pcap` is given: the alert page now decodes and offers those files. Drop the flag to withhold them again. |
| `slothweb: WARNING: --web-serve-evidence-pcap=remote with --web-allow-remote: every peer the allow list admits can download them, with no authentication and no TLS.` | The same files, to every admitted remote peer. Narrow `--web-allow`, or drop `=remote`. |
| `slothweb: no --pcap-dir: the alert page's packet capture is off` | Add `--pcap-dir /var/lib/sloth/pcap` (the sensor's own `--pcap-dir`) to see and download an alert's capture. |

**Normal start notices** (not problems): `listening on`, `vendor
table: ieee (...)`, or `vendor table: sloth (...); A4 off: built
without the IEEE CSVs in web/data/` for a `WEB_OUI_DIR` build without
them (see Build), `sloth.db ...: schema vN, N devices, read-only`, `reading
SPEC`, `BLE: N advertisers and M findings restored from the store;
assigned numbers: sig (...)` (or `none (...); names off: built without
the SIG CSVs in web/data/btsig/` for a `WEB_BTSIG_DIR` build without
them), `time series in`, `baselines (N restored)`, `store schema vN
migrated to vN`, `triage and TACDB writes on` (or `off (no store)`),
`--web-read-only: no write route; every POST is 405`, `follow
recommended: ...`, `agent writes: a loopback POST carrying the secret in
PATH writes triage, notes and links, recorded via agent` (with
`--web-agent-secret`), `fleet: /api/fleet/export served to the allow list;
no --peer, nothing pulled` or one `fleet: pulling NAME from
URL/api/fleet/export every N s into PATH (tailnet)` per `--peer`,
`fleet: this site's own networks (N SSIDs, N BSSIDs,
--my-ssid/--my-bssid) named in /api/fleet/export to the allow list for
ident=1` when any is given, and in
a `WITH_SQLITE=0` build:

| Message | Meaning |
|---|---|
| `slothweb: built without SQLite: time series in memory only (10 s buckets, no minute or hour tier to read back); baselines and anomaly episodes in memory, lost at exit; rules A1 (z only, no MAD), A2, A3, A5-A8 and A10 active (A4 with the IEEE table), A9 needs the store` | What a memory-only build keeps; `make web` (with SQLite) keeps the rest. |

**After start**, the stream's state is in `/api/health`
(`socket`, `socket_last_error`) and in the footer: `sock retrying`
with `connect: No such file or directory` means sloth is not running or
not with `--data-socket`; `Permission denied` means slothweb runs as
another user than sloth (above).

## Security

Read this before exposing slothweb to anything but your own loopback.

- **Loopback by default.** slothweb binds `127.0.0.1:8770` and admits
  only loopback peers (`127.0.0.0/8`, `::1`); any other peer is closed
  at `accept()` before a byte is read. Two separate opt-ins widen that:
  `--web-allow-remote` permits a non-loopback `--web-bind`, and each
  `--web-allow CIDR` admits that prefix (it needs `--web-allow-remote`
  too). Each is announced on stderr at start. Loopback stays admitted
  whatever is added. Prefer `ssh -L` to either.
- **GET and HEAD, and POST to slothweb's own state only.** Every other
  method is `405` on every path, and POST is `405` everywhere but the
  seven triage, link and TACDB write routes ([Triage and the FRRS
  record](#triage-and-the-frrs-record)), which write slothweb's own
  store and nothing else: no endpoint changes anything in sloth,
  sloth.db, the host or the network. A write must carry an `Origin`
  equal to the `Host` it was sent to (slothweb sets no cookie, so this
  is its whole cross-site defence: a browser sends `Origin` on every
  cross-site POST and no page can forge it), `Content-Type:
  application/json` and a `Content-Length` within the bound (4 KiB; the
  import 8 MiB), refused before a body byte is read otherwise; and each
  peer is rate limited. `--web-read-only` removes the write routes
  whole, restoring GET and HEAD only. `--strict` does not imply it:
  strict is about where the bind and the peers are, read-only about
  what an admitted peer may do.
- **No authentication.** Whoever can reach the port reads everything
  slothweb serves: every device, name, SSID, flow and alert, and,
  unless `--web-read-only`, can triage alerts and anomalies, link
  them and edit the TACDB. There
  are no accounts and no token; the allow list is the only gate. A
  triage row records the peer's address and whatever name the operator
  typed ("by"): neither is an identity. The one credential slothweb
  has is the agent secret of `--web-agent-secret`
  ([Writes by an agent](#writes-by-an-agent)): a file only slothweb's
  user reads, accepted from loopback only, which marks a write as an
  agent's and opens nothing the page cannot already do.
- **No TLS.** Use an SSH tunnel (or a VPN you already trust) for
  another host.
- **The Host check.** A request is answered only when its `Host` is
  `localhost` or a literal IP address (with an optional port); anything
  else is `421` before any route. This stops a web page that points its
  own name at `127.0.0.1` (DNS rebinding) from reading slothweb through
  your browser.
- **CSP and no external requests.** The page is one embedded file
  served with `Content-Security-Policy: default-src 'none'` plus the
  hashes of its own one script and one style, and `connect-src 'self'`:
  it loads no font, script, image or anything else from anywhere, and
  can talk only to slothweb. No CORS headers are sent.
- **Read-only towards sloth.db.** `--sloth-db` is opened
  `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW` per request, through a
  file layer that never creates a file. In WAL mode that means:
  slothweb never checkpoints and never writes the WAL into the main
  file; when sloth is running it reads sloth's `-shm` index read-only;
  when sloth is not running it reads the file as of sloth's last
  checkpoint (`"db_mode":"immutable"` in `/api/health`) rather than
  create a `-wal` or `-shm` beside it; and every statement is its own
  short read transaction with a time budget, so slothweb cannot hold
  sloth's WAL from being reset or stall a sloth write. A file that
  needs recovery is left for sloth to recover.
- **Secret columns withheld everywhere.** sloth.db holds some
  credential material by design (a cleartext-credential username, an
  RDP cookie, an MQTT username, an EAP identity, the alert key and
  detail that name them). slothweb reads sloth.db only through a
  column allow-list enforced by an SQLite authorizer, so those columns
  cannot be read by any route, and the same withheld list is refused
  inside the SQL box. `mqtt_flows` is not read at all; Kerberos'
  preauth counts are left out because the allow-list refuses any
  column named for a credential word.
- **`--web-allow-sql`.** Off by default. With it, `/api/query` runs one
  read-only `SELECT` at a time over sloth.db (5 s, 10,000 rows, the
  withheld columns refused) for every admitted peer. Combined with
  `--web-allow-remote` that is announced as a warning.
- **The fleet** ([Fleet](#fleet), ADR 0008). `/api/fleet/export` is a
  read like any other route, so it answers only what the allow list
  admits; it reads sloth.db through the same allow-list and its member
  names are one list held to the withheld words, so no credential,
  username, alert key or detail, EAPOL row or RADIUS identity is in it.
  It does carry SSIDs and client MACs: admit only your own sensors, one
  address each. `--peer` pulls nothing unless given, refuses an address
  outside the tailnet unless `--peer-allow-outside-tailnet` (announced),
  and refuses a peer's answer whole if it is oversize or carries
  anything not on the list. A peer's `slothweb.db` then holds this
  site's device history: protect every sensor as the most sensitive.
- **`--strict`** refuses every non-loopback bind, allow entry and
  `--socket tcp:` address, the SQL box and `--peer`, even when the
  opt-in flags are given.
- **No name resolution, ever.** slothweb resolves nothing: not its bind
  address, not `--socket`, no reverse DNS, no WHOIS. Every name it
  shows was already in sloth's stream or database.
- **Third-party data.** The page shows other people's data: MAC
  addresses, device and host names, SSIDs and probe lists, flows
  between hosts. Treat the page, screenshots of it, and `slothweb.db`
  as you would the capture itself, under whatever authorisation and
  retention rules apply to the network you monitor.

## Reference

The rest of this file describes each part in detail, milestone by
milestone (W0, M0 to M6; tracker #102).

## Command line

| Flag | Effect |
|---|---|
| `--socket SPEC` | sloth's data socket to read. `unix:PATH`, or `tcp:A.B.C.D:PORT` / `tcp:[V6]:PORT` with a literal address; default `unix:/run/sloth/sloth.sock`, sloth's own default since #136. Names are never resolved (`tcp:localhost:8765` is an error). A non-loopback `tcp:` address is announced on stderr; `--strict` refuses it. |
| `--web-bind ADDR:PORT` | Listen address. A literal `A.B.C.D:PORT` or `[V6]:PORT`; default `127.0.0.1:8770`. Names are never resolved, so `localhost:8770` is an error. A non-loopback address is refused unless `--web-allow-remote` is given. `[::]` is IPv6 only (`IPV6_V6ONLY`). |
| `--web-allow CIDR` | Admit peers in `CIDR` as well as loopback. Repeatable, up to 30 entries. Host bits past the prefix must be zero (`10.0.0.1/8` is refused, write `10.0.0.0/8`). A non-loopback entry needs `--web-allow-remote`. |
| `--web-allow-remote` | Authorise a non-loopback bind and non-loopback `--web-allow` entries. Each one is announced on stderr at startup. It authorises the bind, not the peers: with no `--web-allow`, a remote bind still admits loopback only. |
| `--strict` | Refuse any non-loopback bind or allow entry, even with `--web-allow-remote`, and a non-loopback `--socket tcp:` address. Same shape as sloth's `--strict` refusing a routable `--data-socket`. |
| `--store PATH` | slothweb's own SQLite file for the time series (M2) and the baselines and anomaly episodes (M3); default `./slothweb.db`. Never `sloth.db`: a file that is not a slothweb store is refused untouched (below). Needs a `WITH_SQLITE` build; in one without, the flag is a usage error. |
| `--web-max-keys N` | Device keys tracked by keyed metrics, 16..8192, default 512; host keys get N/2 (256) and BLE advertiser addresses (`rf.rssi.ble`) a class of their own at N (#177), so rotating BLE addresses evict each other and never a Wi-Fi key. Least recently seen out first. It also sizes M3's tables: the baseline cap (`web_baseline_cap_for()`), the identity tables (N MACs, N/2 IPs) and A7's hosts (N/2). |
| `--web-max-mb N` | Ceiling on the store's used size, in MB, default 256. Checked after every 10 s write and at each compaction; over it, the oldest 10 s rows go first, then the 1 min and 1 h rows of keyed series, and the global series' rows last. The baselines and episodes (M3) count towards it but are never dropped, and the time series always keeps a history allowance beside them: a week of hour rows for every series the baselines can hold, at 64 bytes a row (measured), about 51 MB at the default 512 keys and 760 MB at 8,192. So the bound is `used <= max(ceiling, analysis state + allowance)`: when the analysis state (its pages measured with SQLite's `dbstat`, `store_analysis_bytes`) leaves less than the allowance under the ceiling, the time series is trimmed to the allowance, not erased and not left to grow, and the pass is counted in `store_ceiling_raised`. A library without `dbstat` cannot measure the analysis state (`store_analysis_bytes` `-1`) and drops until under the ceiling or out of rows. With a store, a ceiling below the analysis state's estimate plus the allowance is refused at start (exit 2), naming the least that would do: 96 at the default 512 keys, 1,437 at 8,192 (MB here are 2^20 bytes). |
| `--web-retain-days N` | Days of 1 min buckets kept, 1..400, default 30. |
| `--sloth-db PATH` | sloth's own database (`sloth --db`), read-only (below). Absent: `/api/devices` is a `503` `no_sloth_db`, the drawer and Lookup answer from the stream and the vendor table, A2 runs on the stream alone, and the page says so. A path that is not there yet, or a file refused, is not fatal: every request opens it afresh. Needs a `WITH_SQLITE` build; the same path as `--store` is refused. |
| `--web-allow-sql` | The SQL box (M5, below): `/api/query` and `/api/recipes`, and the box on the History view. Off by default; without it both paths are `404` and the page never draws the box. Needs `--sloth-db` and a `WITH_SQLITE` build. `--strict` refuses it (exit 2). With `--web-allow-remote` it is announced on stderr, naming what every admitted peer can then read. |
| `--web-agent-group NAME` | With `--web-agent-secret`, the secret file is `0640` in group `NAME` instead of `0600` ([Writes by an agent](#writes-by-an-agent)), so `slothweb-mcp` runs as the operator's own user, a member of `NAME`, with no sudo rule (owner ruling 2026-11-11). Looked up at start; slothweb's own user must be a member of `NAME` (only then may it give a file that group). An unknown group, or one it cannot give, exits `1` before serving; without `--web-agent-secret` it exits `2`. |
| `--web-agent-secret PATH` | Let an agent on this machine write through `slothweb-mcp` ([Writes by an agent](#writes-by-an-agent)): a secret drawn at start is written to `PATH` (`0600`, or `0640` in the `--web-agent-group` group; a new one every run, removed at exit), and a loopback POST carrying it in `X-Slothweb-Agent`, with no `Origin`, may write triage, notes and links, recorded `via: agent` under the name it gives. A `PATH` that is empty or too long is `slothweb: --web-agent-secret: empty or too long a path`; one holding something that is not a private regular file of this user is `--web-agent-secret PATH: exists and is not a private regular file of this user (mode 0600, one link); refused, left as it is`; no random bytes is `--web-agent-secret: no random bytes from /dev/urandom`; each exits before serving. Unset: no agent path, and a request with the header is `403 agent_off`. |
| `--web-read-only` | No write route: every POST is `405` `Allow: GET, HEAD` before a header is checked, the surface before triage existed. The triage states and the TACDB still read; the page draws no button and says why. Default off: an admitted peer may write (the owner's open question Q10 asks whether `--web-allow-remote` should imply it). |
| `--web-assessments DIR` | Where "follow recommended" reads each alert type's research assessment, `DIR/<TYPE>.md` (front matter `false_positive_risk`, `noise_verdict`, `severity_assessment`; [Triage](#triage-and-the-frrs-record)). The type name comes from the alert table, never from a request; each file read until its front matter closes, at most 32 KiB. Unset, or a path not there: every type says "no recommendation yet". Something there that is not a directory is refused (exit 2). `slothweb.service` passes `/usr/local/share/sloth/alert-assessments`, where `make install` copies `docs/wiki/alert-assessments/*.md`. |
| `--pcap-dir DIR` | The sensor's `--pcap-dir`, read-only, for the alert page's packet capture ([An alert's proof](#an-alerts-proof)). Repeatable once more for its `--eapol-dir` (at most two; the same path twice is refused). Only a file named as sloth names an alert pcap is ever opened (`alert_YYYYMMDD_HHMMSS_<slug>.pcap`, or `<incident_id>-<event>-<RULE>[-N].pcap`), through the directory's descriptor, not following a symlink, a regular file of at most 16 MiB; never a handshake pcap or `eapol.22000`, whatever directory they sit in. Absent: the page says "slothweb was not given --pcap-dir". An evidence pcap is listed but withheld unless `--web-serve-evidence-pcap` is given (below). |
| `--web-serve-evidence-pcap[=remote]` | Serve evidence pcaps (`<incident_id>-<event>-<RULE>[-N].pcap`, the sensor's `--eapol-dir`): decoded on the alert page and downloadable. Off by default, because they are raw 802.11 frames from sloth's evidence ring and may hold EAPOL/PMKID handshake material ([What is never served](#an-alerts-proof)). Announced on stderr whenever given. With `--web-allow-remote` the bare flag is refused (exit 2); `--web-serve-evidence-pcap=remote` serves them to the admitted remote peers too, with a second announcement. |
| `--peer NAME=URL` | Pull another of the operator's own slothwebs ([Fleet](#fleet), ADR 0008): its `/api/fleet/export`, into this store's `peer_sites` and `peer_sightings`. Repeatable, at most 8. `URL` is `http://A.B.C.D[:PORT]` (port 80 when absent), a literal address in the tailnet, `100.64.0.0/10`; a name is never resolved, and an address outside the tailnet is refused (exit 2) unless `--peer-allow-outside-tailnet` is given. Off by default; each peer is named on stderr at start. Needs a `WITH_SQLITE` build; `--strict` refuses it. |
| `--peer-interval-secs N` | Seconds between pulls, 10..3600, default 60. |
| `--peer-gnss-region-km N` | A GNSS event at two sites at most this far apart is regional ([Fleet](#fleet), #192 I6), 1..20000, default 50. A choice, not a sourced figure: how far a ground-level source reaches is not in the corpus. |
| `--my-ssid SSID`, `--my-bssid MAC` | This site's own networks, the values its sloth is given with the same flags (repeatable, at most 16 of each, as sloth; [Fleet](#fleet), #192 I2, I3). Named in `/api/fleet/export` to a peer that asks with `ident=1`, and the baseline of the identity findings: a client elsewhere probing for them, this network's BSSID or SSID heard where it cannot reach. None by default; named on stderr at start. |
| `--peer-allow-outside-tailnet` | Allow a `--peer` address outside `100.64.0.0/10` (a LAN peer, a loopback test). There is no TLS: the link you chose is the only protection, and each such peer is announced as a warning. |
| `--help` | Usage. |

Exit status: `0` after `SIGINT`/`SIGTERM`, `1` when the bind fails or
the store is refused, `2` on a usage error or a policy refusal (a
`--web-max-mb` too small for `--web-max-keys` among them).

## What a peer gets

1. **At accept().** The peer address is checked against the allowed-peer
   list before anything else. The default list is `127.0.0.0/8` and
   `::1`; a v4-mapped peer (`::ffff:a.b.c.d`) is matched as IPv4. A peer
   outside the list is closed without a byte read or written, and
   counted. Loopback is always on the list; `--web-allow` extends it and
   never replaces it.
2. **The header block** must arrive complete, request line through the
   empty line, within 8 KB, or the answer is `431`. A body is never read.
3. **One answer**, then the connection closes (no keep-alive), except
   for an event stream:

   | Request | Answer |
   |---|---|
   | `GET`/`HEAD` with no `Host`, or two | `400` |
   | `GET`/`HEAD` whose `Host` is not `localhost` or an IP literal | `421`, before any route (below) |
   | `GET /` | the page, `200`, `ETag`, `Cache-Control: no-cache` |
   | `GET /` with a matching `If-None-Match` | `304`, no body |
   | `GET /api/health` | `200` JSON, `Cache-Control: no-store` |
   | `GET /api/live` | `200` JSON, `Cache-Control: no-store` |
   | `GET /api/series?...`, `/api/keys?...`, `/api/metrics` | `200` JSON, `Cache-Control: no-store`; `400` with `{"error":"reason"}` for a parameter that does not pass (below); `503` with no time series attached |
   | `GET /api/series/all?metric=&tier=&from=&to=&cols=&after=` | `200` JSON, every key of one metric, each in at most `cols` cells, a page of keys to an answer ([below](#apiseriesall)); `400` / `503` as `/api/series` |
   | `GET /api/anomalies?since=&kind=` | `200` JSON, `Cache-Control: no-store`, open episodes and those closed since `since` (below); `400` for a parameter that does not pass; `503` with no anomaly engine |
   | `GET /api/baseline?metric=&key=` | `200` JSON, one series' 168 hour-of-week cells; `400` / `503` as above |
   | `GET /api/devices?q=&sort=&dir=&limit=&offset=&fleet=` | `200` JSON, a page of sloth.db's devices (M4, below), with the peers' rows unless `fleet=0` ([Fleet](#fleet)); `400` for a parameter or a query term that does not pass; `503` with no `--sloth-db`, or sloth.db missing, refused, busy or past its budget |
   | `GET /api/device/{mac}` | `200` JSON, one device, with what each peer reported of it ([Fleet](#fleet)); `400` for a MAC that does not pass or any query but `fleet=` |
   | `GET /api/lookup?q=` | `200` JSON, the Lookup card for a MAC or an IP; `400` otherwise |
   | `GET /api/wifi/channels?metric=&from=&to=&cols=`, `/api/wifi/deauth?from=&to=&cols=` | `200` JSON, the channel waterfall and the deauth timeline (M5, below); `400` for a parameter that does not pass; `503` with no time series |
   | `GET /api/wifi/chain?from=&to=&cols=&bssid=` | `200` JSON, G8's attack chain per BSSID: the deauth timeline's rows (or the one `bssid`) with the EVIL_TWIN, KARMA_AP and association stages sloth.db holds against each and the links the stream's `twin_episode` made (#171 V4, below); out of scope under Local; `400` for a parameter that does not pass (`bad_bssid`); `503` with no time series |
   | `GET /api/wifi/aps?sort=&dir=&limit=&offset=&fleet=` | `200` JSON, a page of sloth.db's beacon_aps, with the peers' rows unless `fleet=0` ([Fleet](#fleet)); `400`; `503` with no `--sloth-db` or sloth.db unreadable |
   | `GET /api/wifi/local?limit=` | `200` JSON, the managed Wi-Fi card's own scan (sloth.db `wifi_aps`, newest first, at most 100) and link (`wifi_stas`, at most 32); out of scope under Monitor; `400`; `503` as above |
   | `GET /api/wifi/ssid?ssid=` | `200` JSON, one SSID's detail ([An SSID's detail](#an-ssids-detail)): its access points now and once, the stations associated to it and asking for it, its 24 h presence, its KARMA and twin findings and the alerts naming it; `ssid` is the base64url of its octets, or `-` for the hidden (empty) SSID; out of scope under Local; `400` `missing_ssid`, `bad_ssid`; `503` as above |
   | `GET /api/probes/clients?days=&sort=&limit=&offset=&fleet=`, `/api/probes/ssids?days=&sort=&limit=&offset=&fleet=` | `200` JSON, the Probes tab ([Probes](#probes)): the stations heard probing with the networks each asked for by name, and the networks asked for with how many stations ask; `days` 0 (all sloth.db retains) or 1..400, default 30; `limit` 1..100; each with `total` beside `count`; with the peers' rows unless `fleet=0` ([Fleet](#fleet)); out of scope under Local; `400` `bad_days`, `bad_sort`, `bad_limit`, `bad_offset`; `503` as above |
   | `GET /api/probes/shared?mac=&days=&min=`, `/api/probes/groups?days=&min=` | `200` JSON, the stations probing for the same networks as `mac`, ranked by the similarity, and the groups of stations linked by shared uncommon networks; `min` 1..8, default 2; out of scope under Local; `400` `missing_mac`, `bad_mac`, `bad_min`, `bad_days`; `503` as above |
   | `GET /api/history/overview`, `/api/history/devices`, `/api/history/alerts`, `/api/history/flows` (`?from=&to=` and their own) | `200` JSON, the History view's reads of sloth.db; `400`; `503` as above |
   | `GET /api/sessions`, `/api/sessions/new?id=` | `200` JSON, the survey sessions and one's "new since the previous session"; `404` for a session sloth.db does not have |
   | `GET /api/flows?proto=&from=&to=&ip=&sort=&dir=&limit=&offset=` | `200` JSON, one protocol table of sloth.db (M6, below); `400` for a parameter that does not pass, `proto=mqtt` included (`proto_withheld`); `503` as above |
   | `GET /api/flows/graph?from=&to=&nodes=&edges=&form=` | `200` JSON, the pairs with the fold stated: the chord diagram's (`form=chord`, the default) or the source by destination matrix's (`form=matrix`, #171 V4); `400` (`bad_form`, `nodes_not_in_matrix`); `503` as above |
   | `GET /api/alerts?state=&sev=&type=&q=&window=&limit=&offset=` | `200` JSON, the Alerts page: the stream's open incidents, then the closed ones and sloth.db's rows, one row per alert key ([Alerts](#alerts)); `400` for a parameter that does not pass; sloth.db missing or refused leaves the stream's rows and says so (`"db"`) |
   | `GET /api/alert?id=` | `200` JSON, everything an alert's page shows; `400` for an id that is not `s<handle>` or `d<rowid>`; `404` for one neither source has; `503` with no `--sloth-db` for a `d` id, or sloth.db unreadable |
   | `GET /api/pcap/frames?id=&n=&offset=` | `200` JSON: capture `n` of alert `id` (an index into `/api/alert`'s `captures`; a name or path is never taken), its SHA-256 recomputed against the manifest (`hash.says`: `hash verified`, `HASH MISMATCH` or `no manifest entry`), its file header, and 24 decoded frames from `offset` (0..4095) with each one's hex dump; `400` for a parameter that does not pass; `404` `no_such_alert`, `no_such_capture`, `no_pcap_dir`, `not_found`; `403` `not_regular`, `withheld_evidence_pcap` (an evidence pcap without `--web-serve-evidence-pcap`); `413` `too_large` (over 16 MiB); `415` `pcapng_not_supported` or `not_pcap` with a `message` |
   | `GET /api/pcap?id=&n=` | `200` the same file's bytes, `Content-Type: application/vnd.tcpdump.pcap`, `Content-Disposition: attachment; filename="<its name>"`, `X-Sloth-SHA256: verified`, `mismatch` or `no_manifest_entry` (the check of the bytes served), `Cache-Control: no-store`; the errors as above, as JSON |
   | `GET /api/bundle?kind=device\|alert\|lookup\|ble\|platform&id=` | `200` JSON, a detail view's whole answer for its "copy JSON" button ([Copy JSON: the analysis bundle](#copy-json-the-analysis-bundle)); `400` for a kind, an id or a parameter that does not pass; `404` and `503` as the route it splices (`not_found` for a BLE address no sensor heard, `no_such_platform`, `no_store`); `413` `bundle_too_large` |
   | `GET /api/lures` | `200` JSON, the WiFi view's KARMA and key-harvest card ([Lures and key harvesting](#lures-and-key-harvesting)): `karma` (sloth's `karma_suspect` rows, highest score first), `stations` (`harvest_station`, most unanswered M1s first), `chains` (`harvest_chain`, most victims first), each row's counts with `ts` and `age_s`; `reported` (`true` from a JSONL 1.3.0 stream, `false` before it, `null` before any `sensor_health`), `jsonl_version`, `stale` (rows not refreshed for 660 s, left out), `records`, `rejected`, `overflow`. Monitor's and Hybrid's; under Local `{"out_of_scope":true,...}`. No parameter: any is `400` |
   | `GET /api/sys` | `200` JSON, the Sensor health view's host status ([Sensor health](#sensor-health)): the newest `sys_status` (CPU, load, memory, uptime, sloth's RSS, the output filesystem, the hottest temperature, the under-voltage alarm; `null` for a figure the host does not have), its `sys_sensor` rows, every `source_status` (all of sloth's sources, configured or not) and every `receiver_hw` (the attached receivers); `"seen":false` before the first batch or with no live stream; `"stale":true` past three of the sensor's own intervals. The same answer under every scope. No parameter: any is `400` |
   | `GET /api/gnss?limit=` | `200` JSON, the GNSS tab ([GNSS](#gnss)): the `sensor_health` gnss block, the newest `gnss_fix` and `gnss_sky`, every satellite row with its last 16 `(ts, C/N0)` points sorted by C/N0, and the panel's counts; `scope_note` says the receiver is the host's own, so the answer is the same under every scope; `400` for an unknown parameter or a `limit` outside 1..64; `503` with no panel |
   | `GET /api/adsb?limit=&fleet=` | `200` JSON, the ADS-B tab ([ADS-B](#ads-b)): the `sensor_health` adsb block, every aircraft row with its kept track (its last 32 positions, `[ts, lat, lon, alt]`), an emergency first, then live before gone, then the most recently heard, each row's `alert` (the open `ADSB_EMERGENCY` incident naming its address, `{"id","sev"}`, else `null`), and the panel's counts (`total`, `live`, `with_pos`, `emergency`); with the peers' aircraft unless `fleet=0` ([Fleet](#fleet)); Monitor's and Hybrid's, Local answers `out_of_scope` with the query still checked; `400` for an unknown parameter or a `limit` outside 1..512; `503` with no panel |
   | `GET /api/gnss/seen?days=&limit=` | `200` JSON from sloth.db's `gnss_sightings` (needs `--sloth-db`): one row per satellite seen in the last `days` (1..400, default 1), most recently seen first, at most `limit` (1..160): first and last seen, records, `used_pct`, `cn0_max`, `cn0_mean`, `el_max`; `"have":false` from a file older than v10; every scope's; `503` `no_sloth_db` without one |
   | `GET /api/gnss/tracks?hours=` | `200` JSON from `gnss_sightings`: every satellite's `[ts, el, az]` over the last `hours` (1..24, default 6), at most 32 a satellite (the newest record of each `bucket_s`) and 2400 in all (`cut`), each track with its RINEX `id`; the sky plot's trails; every scope's |
   | `GET /api/gnss/sat?gnssid=&prn=&days=` | `200` JSON, one satellite's `gnss_sightings` over the window, oldest first, at most 400, as `[ts, el, az, cn0, used, health]`; `400` `bad_gnssid` / `bad_prn` / `bad_days` |
   | `GET /api/adsb/seen?days=&limit=&offset=&q=&fleet=` | `200` JSON from sloth.db's `adsb_aircraft`: the aircraft last seen in the last `days` (default 7), newest first, `limit` (1..100) from `offset`, `more` when there are others; with the peers' aircraft unless `fleet=0` ([Fleet](#fleet)); `q` a hex or callsign prefix (letters and digits, a leading `~`; anything else `400` `bad_q`); `"have":false` from a file older than v12; Monitor's and Hybrid's (Local `out_of_scope`, the query checked) |
   | `GET /api/adsb/aircraft?hex=&days=&fleet=` | `200` JSON, one aircraft's inventory row (`null` when not in the file) and its `adsb_sightings` over the window, oldest first, at most 400, as compact rows named in `cols`; with `fleet` naming the other hosts that heard it unless `fleet=0` ([Fleet](#fleet)); `400` `bad_hex` for anything but sloth's six lower-case hex digits (optionally `~`) |
   | `GET /api/aprs?limit=&call=` | `200` JSON, the APRS tab ([APRS](#aprs)): the `sensor_health` aprs block and the stations (live before gone, the most recently heard first, without tracks; `limit` 1..1024; as many as fit the 64 KB answer, `"cut":true` when the buffer stopped the list, `shown` how many); with `call=` (an AX.25 callsign) that one station with `track_pts` (`[ts, lat, lon]`, its last 32 positions) and `packets_recent` (its last 16 packets as rows named by `packet_cols`), `"station":null` when not kept. Under Local the query is checked, then `out_of_scope`. `400` names an unknown parameter, `bad_limit`, `bad_call` |
   | `GET /api/aprs/tracks?hours=` | `200` JSON, the Radar tab's APRS entities from sloth.db's `aprs_packets` (needs `--sloth-db`) over the last `hours` (1..24, default 24): stations by source call and, as entities of their own, objects and items by their name with the station that reported them as `via`; newest first, each a compact row named by `cols` (`key`, `object`, `via`, `symbol`, `last_seen` its newest packet of any kind, the newest position's `lat`, `lon`, `alt_m`, `speed_kt`, `course`, `pos_ts`, `moving`, the newest non-empty `status` and `comment` cut to 64, and `pts`, a moving entity's trail `[ts, lat, lon]` of at most 48 points, `[]` when stationary); at most 300, while a worst-case row still fits the 64 KB answer, `cut` when more; `bucket_s`; `"have":false` from a file older than v13; `400` `bad_hours` or an unknown parameter; Monitor's and Hybrid's (Local `out_of_scope`, the query checked) |
   | `GET /api/aprs/seen?days=&limit=&offset=&q=` | `200` JSON from sloth.db's `aprs_stations` (needs `--sloth-db`): the stations last heard in the last `days` (1..400, default 7), newest first, `limit` (1..100) a page from `offset`, `more` when another page follows; `q` a callsign prefix of `[0-9A-Za-z-]` (at most 9, upper-cased; anything else `400 bad_q`); the comment cut to 48. A file older than v13 answers `"have":false` and an empty list. Monitor's and Hybrid's |
   | `GET /api/aprs/station?call=&days=` | `200` JSON, one station's `aprs_stations` row (`null` when not in the file) and its `aprs_packets` over the window, oldest first, the newest 400 that fit the 64 KB answer (`"cut":true` when older ones were left out), compact rows named by `cols`. `400 bad_call` for anything but an AX.25 callsign. Monitor's and Hybrid's |
   | `GET /api/radar` | `200` JSON, the Radar tab's band census ([Radar](#radar)): for BLE and for Wi-Fi the row total, the rows with one of sloth's five distance bands, the rows with a reading and no estimate (`none`), and per band (`immediate`, `near`, `room`, `building`, `far`) its count and up to eight strongest-signal rows (BLE `addr`, `addr_type`, `iface`, `name`, `rssi`, `last_seen`; Wi-Fi `mac`, `kind` `ap`\|`sta`, `ssid`, `rssi`, `ts`); `devs.ble` and `devs.wifi`, each family's 50 most recently heard rows with an estimate, newest first, the same members plus `m` (metres, `null` when the record carried none), `band` and `trend` (sloth's word or `""`); a half with no table attached is `null`; Monitor's and Hybrid's, Local answers `out_of_scope` with the query checked; `400` for any parameter |
   | `GET /api/gnss/fixes?since=&limit=` | `200` JSON, the kept `gnss_fix` records (512 in memory) oldest first after `since` (unix seconds), at most `limit` (default and most 128); the page walks the ring (`gnss.js fixes()`: from `since=0`, then from the last row's `ts` while a page comes back full, at most eight pages), so the strip reaches the newest record once the ring holds more than a page; `400` for `bad_since` / `bad_limit` |
   | `HEAD /api/alerts`, `HEAD /api/alert`, `HEAD /api/pcap`, `HEAD /api/pcap/frames`, `HEAD /api/bundle` | `405`, `Allow: GET`, as `/api/query` |
   | `GET /api/positions?mac=&format=json\|geojson\|gpx&since=&until=` | `200`, sloth.db v9's `device_positions` for one MAC (where the sensor was when it heard it, not the device's position) and the sensor's track over the same span, newest first, at most 200 of each (the track the newest 200 points within the samples' span, so the oldest samples of a full answer may have no track under them), `"more"` when there were more; the GeoJSON carries the same `"more"` and `"limit"` as foreign members of its FeatureCollection (RFC 7946 §6.1) and a cut GPX says `truncated` in its `<metadata><desc>` ([Sensor location](#sensor-location)); `json` is `application/json`, `geojson` (RFC 7946) `application/geo+json` and `gpx` (GPX 1.1) `application/gpx+xml`, both as attachments; `400` for a parameter that does not pass (`bad_mac`, `bad_format`, `bad_range`); `503` with no `--sloth-db` or sloth.db unreadable. A file before v9 answers empty lists. `HEAD` is `405` |
   | `GET /api/query?sql=` | only with `--web-allow-sql` (otherwise `404`): `200` JSON, the statement's result; `400` with `{"error":"reason"}` for a refused statement; `503` `busy` while another runs, or sloth.db unreadable |
   | `HEAD /api/query` | `405`, `Allow: GET`: nothing to describe without running it |
   | `GET /api/recipes` | only with `--web-allow-sql`: `200` JSON, the box's recipes |
   | `GET /events` | `200` `text/event-stream`, held open (below) |
   | `GET /events` with 24 streams already open | `503` |
   | `GET` any other path | `404` |
   | `HEAD` of any of these | the same status and headers, no body |
   | any other method (`POST`, `PUT`, `DELETE`, `PATCH`, ...), any path | `405`, `Allow: GET, HEAD` |
   | header block over 8 KB | `431` |
   | malformed request line or header | `400` |
   | HTTP major version other than 1 | `505` |
   | no complete header block within 10 s of accept() | `408`, best effort |

   Methods are case-sensitive (RFC 9110 §9.1): `get` is `405`.

   **Host.** The allow list judges the TCP peer, and the operator's
   browser is a loopback peer whatever page it shows. A site that
   points its own name at `127.0.0.1` (DNS rebinding) is same-origin
   with slothweb in that browser, so its script could read
   `/api/health` and `/events`; sending no CORS headers does not stop
   that. Its requests carry its name in `Host`, so a routed request is
   answered only when `Host` (or an absolute-form target's authority)
   is `localhost`, a literal IPv4 address or a bracketed IPv6 literal,
   each with an optional `:port`. An IP literal cannot be rebound, so
   any literal is accepted, which keeps `ssh -L` forwards and a
   `0.0.0.0` bind reached by the host's address working; no name is
   resolved to decide. A remote bind reached by DNS name is refused:
   use the address. Writing methods are `405` before this check.
4. **Timeouts are absolute from accept()**, not reset per byte: a client
   trickling one byte at a time is cut off on the same schedule as one
   that sends nothing. The response has its own 10 s budget. After it, a
   client may keep sending (a body nobody reads) for 1 s before the
   socket closes. The half-close and drain make those unread bytes end the
   connection with a FIN instead of a reset; this is defensive (some
   stacks discard an unread response on reset) and the loopback tests
   check the FIN, not a rescued response, because Linux delivers the
   queued response either way.
5. At most 32 connections are held. A 33rd admitted peer is closed and
   counted as busy. If `accept()` runs out of descriptors or memory, the
   listener is left unpolled for 100 ms rather than spinning.

On shutdown slothweb prints the counters to stderr: admitted, refused at
accept, busy, served, timed out, accept back-offs.

## Routes

Paths match exactly, and an absolute-form target (`GET
http://127.0.0.1:8770/ HTTP/1.1`) routes by its path. The query string
is ignored except by the routes that take parameters, which validate it
whole; each of them but `/api/query` refuses a query string of 512
bytes or more as `query_too_long`. Every `/api` route but
`/api/health` and `/api/query` also takes `scope=monitor|hybrid|local`
([Capture scope](#capture-scope)).

**`/`** is the one page: `web/ui/index.html` with `theme.css`,
`page.css` and `app.js` inline. The `ETag` is the first 128 bits of the
page's SHA-256, so it changes exactly when the page does; the browser
revalidates on every load and gets `304` until a rebuild. The page's
policy is

```
default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…';
img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

so the browser itself refuses any request the page did not hash, other
than same-origin `fetch` and `EventSource`. The two images, the sloth
in the header and the favicon, are `data:` PNGs inline in the page
(`web/ui/icon-64.b64`, `web/ui/icon-32.b64`; the owner's art at every
size in `docs/assets/slothweb/icon/`): bytes, not requests, which
`img-src data:` admits and nothing else. The fonts are the system
monospace stack (`ui-monospace, "SF Mono", Menlo, Consolas, "DejaVu Sans
Mono", "Liberation Mono", monospace`); no font file exists. Colours are
the `docs/web-ui-spec.md` §8.1 tokens in `web/ui/theme.css`.

**`/api/health`** answers

```json
{"service":"slothweb","milestone":"M6","uptime_s":12,
 "socket":"connected","socket_spec":"unix:/run/sloth/sloth.sock",
 "last_record_age_s":0,"socket_attempts":1,"socket_connects":1,
 "socket_reconnects":0,"socket_failures":0,"socket_closes":0,
 "socket_retry_ms":0,"socket_last_error":null,"socket_last_error_age_s":null,
 "socket_bytes":48113,"socket_lines":92,"socket_records":92,
 "socket_decode_errors":0,
 "socket_decode_by":{"syntax":0,"utf8":0,"depth":0,"fields":0,
   "not_object":0,"duplicate_key":0,"no_type":0,"overlong":0,"truncated":0},
 "socket_gaps":0,"socket_gap_dropped":0,
 "db":"open","db_schema":7,"db_rows":42,"db_path":"/var/lib/sloth/sloth.db",
 "db_mode":"wal","sloth_db_mtime":1792627199,"sloth_db_age_s":1,
 "db_error":null,"db_opens":118,"db_timeouts":0,
 "db_supported":[1,7],"vendor_table":"ieee",
 "vendor_counts":{"ma_l":39627,"ma_m":6451,"ma_s":11639},"a4":"on",
 "passive_ptr":{"entries":0,"cap":4096,"seen":31,"stored":0,"empty":31,
   "refused":0,"evictions":0,"db_evictions":0,"persist_errors":0},
 "sloth_db_stale_after_s":600,"sloth_db_stale":false,"sql":false,
 "store":"open","store_path":"./slothweb.db","store_schema":5,
 "store_rows":{"fine":42120,"minute":7020,"hour":117},
 "store_bytes":1765376,"store_max_bytes":268435456,"store_batches":360,
 "store_write_errors":0,"store_last_error":null,"store_compactions":2,
 "store_dropped_expired":0,"store_dropped_ceiling":0,"store_ceiling_runs":0,
 "store_ceiling_raised":0,"store_analysis_bytes":-1,
 "store_baseline_rows_reused":0,
 "chmix":{"channels":7,"samples":5210,"ring_rows":1680,"ring_overwritten":0,
   "queue_dropped":0,"folded":0,"channel_evictions":0,"store_rows":2210,
   "store_dropped_expired":0,"store_dropped_cap":0},
 "retain_days":30,
 "series_keys":{"global":1,"device":30,"host":20,"iface":2,"channel":3,"alert":0,"rectype":9,"sys":12,"bleclass":3,"ble":40},
 "series_key_caps":{"global":1,"device":512,"host":256,"iface":32,"channel":64,"alert":128,"rectype":80,"sys":64,"bleclass":8,"ble":512},
 "key_evictions":{"global":0,"device":0,"host":0,"iface":0,"channel":0,"alert":0,"rectype":0,"sys":0,"bleclass":0,"ble":0},
 "key_returns":{"global":0,"device":0,"host":0,"iface":0,"channel":0,"alert":0,"rectype":0,"sys":0,"bleclass":0,"ble":0},
 "series":117,"samples":221385,"ring_rows":42120,"queue_rows":0,
 "queue_cap":32768,"queue_dropped":0,"churn_dropped":0,"highwater_evictions":0,
 "values_clamped":0,
 "anomaly":{"open":1,"building":0,"closed_kept":2,"cap":512,"opened":3,
   "closed":2,"dropped":0,"evicted_closed":0,"candidates_dropped":0,
   "rows_dropped":0,"late_rows":4,"hours_fed":31,"hours_unobserved":1,
   "minutes_unobserved":3,"hours_merged":1,"mad":true,"mad_queries":2,"mad_skipped":0,
   "a9":true,"a9_queries":5,"fanout_hosts":20,"fanout_evictions":0,
   "reported":1,"reported_evicted":0,"known_evictions":0,
   "persist_errors":0,"persisted":true},
 "baseline":{"entries":212,"cap":4930,"evictions":0,"aged_out":0,
   "fed":6020,"zero_fed":1311,"deletes_lost":0},
 "ident":{"macs":30,"mac_cap":512,"mac_evictions":0,"ips":24,"ip_cap":256,
   "ip_evictions":0,"dns_matched":12,"dns_unmatched":3,"query_overwrites":0},
 "sse_clients":1,"tick_seq":12,"hostname":"W9FJC"}
```

`socket` is `connecting`, `connected` or `retrying` (waiting out a
back-off of `socket_retry_ms`). `socket_last_error` is slothweb's own
text (`connect: No such file or directory`, `peer closed the stream`),
never anything the peer sent. `socket_gaps` counts sloth's `socket_gap`
markers and `socket_gap_dropped` the records they say were dropped
(jsonl-schema, #93). The `db` fields are `sloth.db`'s (M4, below):
`db` is `none` (no `--sloth-db`; then only `db_schema`, `db_rows` and
`db_supported` follow, as `null`, `null` and the range), `open`,
`missing`, `refused`, `error` or `unbuilt`, checked afresh for each
`/api/health`; `db_rows` counts `devices`, `db_mode` is how it was
opened (`wal`, `immutable`, `rollback`) and `db_error` slothweb's own
sentence for the last refusal. `sloth_db_mtime` is what the DB-backed
views are as of (unix seconds; `null` when the file is not open) and
`sloth_db_age_s` how long ago that is; `sloth_db_stale` is `true` when
that age is over `sloth_db_stale_after_s` (600) while the stream is
current, `null` without an open file (below, "How old the database
is"). `vendor_table` and `vendor_counts` are
the generated table's (`ieee`, `sloth` or `none`), `a4` is `on` or why
it is off, and `passive_ptr` the cache's size and counters. The
`store` fields are M2's (below): `store` is
`open`, or `memory` in a build without SQLite (`store_path`,
`store_schema` and `store_rows` are then `null`); `store_rows` is the
rows stored, kept by the writer (a bucket merged into one already on
disk is not counted again) and recounted at each compaction;
`key_evictions` counts keys pushed out of each class by its cap,
`key_returns` evicted device and host keys that came back and were given
their earlier life (below), `queue_cap` the store queue's size and
`queue_dropped` the closed buckets it had no room for, and
`highwater_evictions` rows pushed out of the running-total table. The
`anomaly`, `baseline` and `ident` members are M3's: every table the
engine keeps, its bound, and what it has had to drop or evict (below);
`persisted` is `false` in a build without SQLite.

**`/api/live`** is the live state:

```json
{"socket":"connected","devices":42,"devices_stale":false,"devices_ts":1792629211,
 "device_passes":118,"device_passes_unpublished":0,
 "alerts_open":{"low":0,"warn":1,"crit":0,"overflow":false},
 "records":9120,"records_s":61.4,"last_record_age_s":0,
 "types":{"iface":236,"device":4956,"dns":310,"...":0},
 "types_other":0,"types_invalid":0,
 "sensor":{"state":"ok","age_s":40,"ts":1792629171,"capture_iface":"any",
   "capture_open":1,"capture_running":1,"capture_exit":"none",
   "monitor_iface":"","monitor_open":0,"monitor_running":0,"monitor_exit":"",
   "scope":"none","scope_not_enforced":0},
 "alerts":[{"ts":1792629100,"type":"alert.create","sev":1,"title":"…",
   "detail":"…","alert_id":"s3fa9c2d11a","match_ip":"192.0.2.20"}],
 "recent":[{"seq":9071,"type":"dns","ts":1792629210,"text":"example.com  10.0.0.5"}]}
```

| Member | Meaning |
|---|---|
| `devices` | the number of `device` records in sloth's latest snapshot pass: the TUI's device count (below). `null` until a pass has been seen. `devices_stale` is `true` while the socket is down and until the current connection delivers a pass |
| `alerts_open` | incidents open now, by severity (0 LOW, 1 WARN, 2 CRIT), from the `alert.create` / `.update` / `.escalate` / `.resolve` records. Starts empty on each connection (below). `overflow` once more than 256 are open |
| `alerts` | the latest eight lifecycle records, newest first; `alert_id` is the link to the incident's page (`/api/alert?id=`), slothweb's own handle, never sloth's `incident_id` (below, [Alerts](#alerts)); `null` for a record of an incident slothweb is not tracking |
| `records`, `records_s` | records decoded since start, and the mean over the five whole seconds before now |
| `types` | records by `type`, for up to 48 names; the rest are `types_other`. A `type` that is not 1..32 bytes of `[a-z0-9_.]` is `types_invalid` and is not shown |
| `sensor` | the latest `sensor_health` record and `state`: `unknown` (none yet), `ok`, `degraded` (a capture or monitor handle open with its thread not running, or the launch scope not enforced), `not_observing` (neither handle open), or `stale` (none for 330 s; it is change-only with a 300 s heartbeat) |
| `alerts` | the last 8 alert lifecycle records, newest first. `match_ip` is the record's address (the page's alert-hot colour, [Design](#design)), or `""` when it has none or what it has is not 1..45 bytes of `[0-9A-Fa-f:.]` |
| `recent` | the last 50 records of any type, oldest first, each as its `type`, `ts` and a short `text` built from the members a reader looks for first (`qname`, `host`, `ssid`, `mac`, `ip`, `src`, ...), at most 80 bytes |

**`/api/ble?sort=&dir=&limit=&offset=&q=`**, **`/api/ble/alerts?limit=`**
and **`/api/ble/{addr}?type=&iface=`** are the BLE view's ([BLE](#ble)):
the advertisers and findings slothweb keeps from sloth's `ble_device`
and `ble_alert` records (sloth.db has no BLE table). `sort` is `last`
(default, newest first), `first`, `rssi`, `dist`, `adv`, `addr`, `type`,
`iface`, `name`, `kind` (the address in words), `best` (the strongest
RSSI), `rate`, `hws` (the three flags), `pdus`, `watch` or `mfr` (the
company's SIG name; in either direction the named companies first, then
the ids the table does not name, by number, then none), one word a
column of the page's table, with `dir=asc|desc`; an empty value sorts
last either way; `limit` 1..1024 (default 100)
from `offset`; `q` matches an address prefix, the local name or the
watch category, ASCII case folded. A row carries the record's fields
with absent ones `null` (`tx_power` -128, the ids -1, `rssi` without
`has_rssi`), `addr_kind` (the address in words: `public`, `random
static`, `random RPA`, `random NRPA`, `random reserved`, `resolved
public`, `resolved random`, `anonymous`), the PDU names of `pdu_mask`, the Bluetooth SIG names of the
company, service and appearance (`mfr_name`, `uuid16_name`,
`svc_data_name`, `appearance_name`; `null` when the table has none),
the row's advertising rate between its records (`adv_rate`, `null`
with fewer than two), and `est` (sloth's distance estimate as it came:
`m`, `band`, `trend`, `ptx`, plus `cell`, the TUI's `~5m room ↘`, and
`describe`; `null` for no estimate). Beside the rows, `total` is the
rows slothweb keeps, `sensor.ble_devices` sloth's own live count (the
TUI's header number; `null` before a `sensor_health` said it), and
`standing_floods` the `adv_flood` findings standing now: not the TUI's
`flood keys` (the flood detector's tracked windows), which no record
carries. `/api/ble/alerts` lists the
findings standing first, then those resolved in the last day; the
finding's key is never in an answer. `/api/ble/{addr}` is every row of
the address (the asked-for sensor's first) with its rate points and its
presence strip (`presence`: `bucket_s` 900, `n` 96, `newest`, the start
of the newest quarter hour a record was heard in, and `bits`, 24 hex
digits most significant first, bit i the quarter hour i before
`newest`), and the `hid_oui` findings naming it; 404 when none. Since
2026-11-02 a row also carries `class` and `class_label` (its device
class, [BLE](#ble)) and, on `/api/ble/{addr}`, `channels` (the LL
channels its records named since slothweb started, an Ubertooth row's;
absent for none). Under `scope=local`
each answers `out_of_scope` (the receivers are passive radio), the
query still checked.

**`/api/ble/classes?from=&to=&cols=&metric=advertisers|adv`**,
**`/api/ble/classes?from=&to=&cols=&mix=1`** and
**`/api/ble/proximity?from=&to=&cols=&n=12|24|48`** are the BLE Devices
waterfall's ([BLE](#ble), `web/src/web_bledev.h`), on the WiFi channel
grid's `from`, `to` and `cols` (the same tiers and bounds, the same
refusals). The first is the class x time grid of `ble.class.advertisers`
(default; a gauge, each cell the mean) or `ble.class.adv` (`adv`; a
counter, each cell the sum): `rows` of `{key, label, glyph, cells}` in
display order, Trackers always one; `metric` other than those two is a
400 `unknown_metric`. With `mix=1` it is `/api/wifi/channels?mix=1`'s
answer (`metric` `ble.mix`, `unit` `reports`, `top`, `source`,
`ring_from`, `folded`, `read_cut`; no `db`) with `rows` for `channels`,
each row `{key, label, glyph, total, cells}`, and each `tx` entry an
advertiser: `{id, kind: "ble", name, name_np, class, addr_type, iface}`
from the newest row the BLE tables hold of the address, the last four
`null` when they no longer hold it. Anonymous advertising (`addr_type`
255, an extended advertisement with no AdvA) is one entry,
`{"id":"anonymous","kind":"anon","name":null,"name_np":false,"class":"b:unk","addr_type":255,"iface":null}`,
in Unknown alone (no `iface`: it has no row to open). The third lists the advertisers
with a row heard in the window (`last_seen >= from`), every row of an
address merged (`rf.rssi.ble` is keyed by address), at most 256 read
(`read_cut`): every address whose newest row is a tracker first,
whatever its age, then the newest, so a cut drops the oldest
non-trackers and `candidates` is then the number read, not the window's
total. Anonymous advertising is never a candidate and takes none of
the 256 (`candidates` does not count it, and a cut still reads 256
addresses); `anonymous_heard` says whether any was heard: there is no
address to key `rf.rssi.ble` by, and sloth's one anonymous row per
sensor carries whichever anonymous advertiser it heard last. The top `n` (default 24; anything else a 400 `bad_n`) are
trackers first, then the nearest (the strongest signal in the window
less the row's P_tx), then by reports: `rows` of `{addr, addr_type,
addr_kind, iface, name, name_np, class, best, samples, adv_count,
last_seen, rows, ptx, ptx_source, edges, cells}`, each cell the mean of
the series' buckets in it to one decimal or `null`. `ptx` is the power
the row is graded with, in `rf_ctx_ble()`'s order (`ptx_source`
`ble_ext_tx_power`, `ble_ad_tx_power` or `assumed` 0 dBm), and `edges`
its four dBm edges; the answer's own `edges` and `candidates` are the
0 dBm ones and the count read. Each answer ends with `now`: `window_s`
60, `advertisers` (addresses with a row heard in it, anonymous advertising one between them), `trackers`,
`nearest` (by current RSSI less P_tx, the grade's estimate rather than
raw signal: address, name, class, `rssi`, sloth's `band` when it has an
estimate, the grade, `ptx`, `ptx_source`; never an anonymous row, whose
signal is no one device's), `adv_rate` (sloth's
`ble.adv_rate` over the last minute, reports a second) and `sensor`
(`seen`, `btmon_iface`, `btcap_iface` from sloth's latest
`sensor_health`; `seen` false before one). Monitor's and Hybrid's;
`out_of_scope` under Local after the query is checked. With no time
series either route is a `503` `no_time_series` in any scope, Local
included, because the grid's bounds need the tiers before the Local
answer; the class mix with no mix wired is a `503` `no_ble_mix`.

**`/events`** is a Server-Sent Events stream. It starts with
`retry: 3000` and the current tick, then:

| Event | Cadence | Payload |
|---|---|---|
| `tick` (with `id:`) | 1 s | `{"seq":N,"ts":UNIX,"uptime_s":U,"sse_clients":K,"socket":"connected","devices":42,"devices_stale":false,"alerts_open":[low,warn,crit],"records_s":61.4,"records":9120,"sensor":"ok","anomalies_open":1}` |
| `record` | with each tick | `{"seq":N,"type":"dns","ts":UNIX,"text":"..."}`, the records added since the previous tick, the newest 20 at most (spec §7.1: coalesced to 20 a second); a gap in `seq` says some were skipped |
| `anomaly` | with each tick, on change | one episode as `/api/anomalies` renders it, each time it opens, advances (an open episode's minute) or closes; the newest 16 changes a tick at most, an episode that changed twice sent once as it is now |
| `: ping` comment | 15 s | none; keeps proxies and idle timers from closing it |

`seq` counts up by one per second from start-up; a late wake-up sends
one tick, not a burst. Anything the client sends on the stream is read
and discarded, which is also how its departure is noticed. A client
that stops reading is dropped once 64 KB is waiting for it (its socket
send buffer is capped at 16 KB as well), and its browser reconnects on
its own after the `retry` delay. Every accepted socket has
`TCP_NODELAY` (spec §10.2): events are small and should not wait for
the previous one's ACK. At most 24 streams are held, so 8 of
the 32 connection slots stay free for the page and the API.

## Sensor location

sloth stamps each new alert incident with where the sensor was
(`--location`, `--gps`; [location](../docs/wiki/location.md)). slothweb
reads the stamp from two places and shows the same object either way:
the stream's alert records carry it as `"loc":{...}`, the one nested
object `web_jl_parse()` keeps (as `loc.lat`, `loc.src`, ... fields: a
composite key and its NUL are never longer than the member's source,
so the record's text still fits the line, and the duplicate check
covers them), and a schema-v9 sloth.db carries it in six alerts
columns on the allow-list. A value outside -90..90 / -180..180, or a
source other than `gps` or `fixed`, is no location, never a clamped
one. `/api/alert` answers `"loc"`, the stream's stamp first, then the
row's, `null` when neither has one.

`/api/positions` reads `device_positions` and `sensor_positions` (v9,
allow-listed; a file before v9 answers empty lists). The page draws
them in the device drawer as a Canvas 2D scatter on a local
equirectangular projection centred on the samples' mean, coloured by
RSSI in the palette's heat, the sensor's track as a line, and offers
GeoJSON and GPX as attachments of the same route. No tiles and no
third-party map: the page still asks its own server and nothing else.
`web/ui/location.js` is the whole of it, behind two hooks app.js calls
(`window.SlothLocation.alert(j)` on an alert's page, `.drawer(mac)`
when the drawer opens) and two containers, `#loc-alert` and
`#loc-drawer`.

## GNSS

The GNSS tab (its button reads `GPS Sat` since 2026-11-02, the owner's
name for it; the id and the view are unchanged) is the host's own receiver as sloth reports it
([gnss](../docs/wiki/gnss.md)): with `--gps`, sloth writes three
change-only records off the gpsd stream it already reads for its
position — `gnss_fix` (the newest TPV: mode, status, DOPs, position,
speed, the receiver's time against the host's clock), `gnss_sky` (the
pass's counts, DOPs and C/N0 statistics) and one `gnss_sat` per
satellite in view — plus five `gnss_*` members of `sensor_health`.
`web/src/web_gnss.c` keeps them in memory: 64 satellite rows keyed
(gnssid, PRN), the least recently reported evicted and a row quiet for
660 s (two heartbeats and a margin) dropped as set, each with its last
16 `(ts, C/N0)` points; 512 fixes in a ring; the newest sky and sensor
block. Nothing is persisted — sloth.db's `gnss_fixes` and
`gnss_sightings` (schema v10, both allow-listed) hold the history, and
`WEB_SDB_SCHEMA_MAX` moved to 10 with them.

The page (`web/ui/gnss.js`, `window.SlothGnss`, containers `gnss-*`,
one hook in `app.js`) draws the TUI's `[#]` view: its two header
lines, the satellite table sorted by C/N0 (a header sorts client-side;
rows bright when in the solution and dim when unhealthy; the C/N0
number heat-graded over 50 dB-Hz with the TUI's thresholds; the signal
cell [the meter](#the-s-meter-2026-11-11) on 0 to 50 dB-Hz, lit to the
row's C/N0 with ticks at the least and greatest of its points, which
took the per-row C/N0 trail's place), a polar sky plot (azimuth around,
elevation inward, north up, dots heat-graded and larger when used),
and a fix-history strip (mode, satellites used, HDOP, clock offset
over the kept records). Satellites are coloured by constellation (the key palette, one colour per `gnssid`) in the sky plot, its trails and both tables' GNSS column, with a key under the sky; C/N0 keeps its heat in the signal cells. Clicking a row opens the TUI's detail rows.
The receiver is neither the monitor radio's nor the IP capture's, so
its records are META like `sensor_health`, the tab is served under
every scope, and the scope chip says so.

Every string is hostile: the constellation is named from gpsd's
`gnssid` through sloth's own table (`other` past 7, counted), the
source label is kept only when printable ASCII, every number is range
checked and anything outside is `null`, never clamped. The clock
offset is the receiver's stamp against the host's `CLOCK_REALTIME` as
the line arrived — coarse (serial and gpsd latency, no PPS), enough to
see a multi-second step and nothing finer; the page labels it so.
Observation only: no row is a finding, and the detectors are a later
slice.

Every satellite row (live and seen) names the satellite: `id`, the
RINEX identifier (`G05`, `R09`, `E11`, `C23`, `J02`, `I10`, `S31`), and
`veh`, the vehicle on that PRN at the row's time from the IGS satellite
metadata compiled in (`web/data/gnss/SOURCE.md`; `web/tools/gnssmeta_gen.c`
makes `build/web/web_gnssmeta_table.c`): name, NORAD catalogue number,
COSPAR designator, SVN, block, launch date, orbital plane and slot;
`null` for SBAS and IMES, which the file does not hold. `/api/gnss`
says the release in `meta`. With `--sloth-db` the sky plot draws each
satellite's trail over a chosen window (`/api/gnss/tracks`).

With `--sloth-db`, the tab's "satellites seen" table reads sloth.db's
`gnss_sightings` (`/api/gnss/seen`): every satellite listed in the
window (24 h, 7 or 30 days, kept per browser), first and last seen,
records, the share in the solution, C/N0 maximum and mean, the highest
elevation. Clicking a row there or in the live table draws that
satellite's C/N0 (heat-graded, larger dots in the solution) and
elevation over the window (`/api/gnss/sat`).

## ADS-B

The ADS-B tab (2026-11-05, #26) is the aircraft a local decoder lists,
as sloth reports them ([adsb](../docs/wiki/adsb.md)): with `--adsb`,
sloth tails readsb's or dump1090-fa's `aircraft.json` and writes one
change-only `adsb_aircraft` record per aircraft (first sight, a change
of held altitude band, position cell, squawk, emergency, callsign or
category, the 300 s heartbeat, and one `"gone"` on expiry), plus the
`adsb_*` members of `sensor_health`. `web/src/web_adsb.c` keeps them in
memory: 512 rows keyed by `hex` (`~`-prefixed non-ICAO addresses are a
separate key), the least recently reported evicted; a gone row kept,
dimmed, for 600 s; a live row quiet for 660 s (two heartbeats and a
margin: its `gone` was lost or sloth stopped) dropped and counted as
aged; each row's last 32 positions, one per record whose position
moved, reset when the address comes back with a new `first_seen`.
Nothing is persisted; sloth.db has no ADS-B table yet.

A row's figures are as of its last record, not the decoder's last
second: altitude within its band, position within its cell. The page
says so. The page (`web/ui/adsb.js`, `window.SlothAdsb`, containers
`adsb-*`, one hook in `app.js`) draws a header from the decoder's
health (state, aircraft live and with a position, the decoder's clock
age, message, read and error counts), the aircraft table (app.js's
DataTable; rows bright with a position, dim once gone; altitude
heat-graded over 45,000 ft, RSSI over -50..0 dBFS with
[the meter](#the-s-meter-2026-11-11) on that range beside it; an
emergency status and the reserved squawks 7500 / 7600 / 7700 in the
peak colour as the decoder reports them, text only), a position plot
(north up, no map tiles and nothing fetched: each aircraft at its last
position with a heading tick and its kept track coloured by altitude,
a km scale bar) and a detail panel on click. The decoder's SDR is a
passive radio, so `adsb_aircraft` is Monitor's like `ble_device`; under
Local the view shows its scope note.

**History** (2026-11-05): with `--sloth-db`, the tab also reads
sloth.db's `adsb_aircraft` and `adsb_sightings` (schema v12, written by
sloth's `--db` with `--adsb`): an "aircraft seen" table over a window
(24 h to a year, 100 a page, a hex or callsign search, the window and
search kept per browser) with first and last seen, visits, recorded
sightings, the last callsign, squawk and category, the altitude range,
top speed, strongest RSSI and whether an emergency was ever reported;
and, for a row clicked there or in the live table, the detail panel's
history: those figures, every callsign and squawk it used, an altitude
profile (emergencies ringed) and its recorded track dashed on the
positions plot, also for an aircraft no longer listed. The GNSS tab
has the same for satellites (see [GNSS](#gnss)).

Every string is hostile: `hex` must be sloth's `~`? and six lower-case
hex digits (else rejected and counted), the callsign printable ASCII of
at most 8, the squawk four octal digits, the category `A0`..`D7`, the
emergency one of sloth's eight words; every number is range checked
and anything outside is `null`, never clamped. Observation only: no
row is a finding. The finding is sloth's flag-only `ADSB_EMERGENCY`
(#186, an emergency squawk or status; [adsb](../docs/wiki/adsb.md)),
and the tab links to it: a row whose address an **open**
`ADSB_EMERGENCY` incident names (sloth's key
`adsbemerg:<hex>:<icao|nonicao>:...`) carries `alert` (`{"id","sev"}`,
the alert page's handle), shown as an ALERT column (`ALERT` for WARN,
`alert` for LOW) and an alert line in the detail panel, each opening
the alert's page. A closed incident, or one of another type, links
nothing. The incident is Monitor's, as the records are.

## APRS

The APRS tab (2026-11-05) is the stations a local Dire Wolf decodes on
144.390 MHz, as sloth reports them ([aprs](../docs/wiki/aprs.md)): with
`--aprs`, sloth tails Dire Wolf's `-L` packet log (one CSV line per
packet; it never talks to the radio or to Dire Wolf) and writes one
`aprs_packet` record per packet and one change-only `aprs_station`
record per station (first heard, a new held 0.01° position cell, a new
symbol, the first packet heard direct, the 300 s heartbeat, and one
`"gone"` after an hour unheard), plus the `aprs_*` members of
`sensor_health`. `web/src/web_aprs.c` keeps them in memory: 1024
stations keyed by callsign, the least recently reported evicted; a gone
station kept, dimmed, for 30 minutes; a live one quiet for 660 s aged
out and counted; each with its last 32 positions and its last 16
packets (time, type, via, level, the comment cut to 48). A station's
last heard, via, level, comment and position follow its packets; an
object's or item's position belongs to the object, never to its sender.

The page (`web/ui/aprs.js`, `window.SlothAprs`, containers `aprs-*`,
one hook in `app.js`) draws a header from the decoder's health (the log
file's state, stations live / with a position / heard direct, the last
packet's age, line, packet, bad-line, rotation and truncation counts),
the station table (app.js's DataTable: CALL, SYM, LAST HEARD, PACKETS,
VIA - `direct` or the digipeater -, POSITION, SPD, CRS, ALT, LEVEL
heat-graded over 0..100, COMMENT, SYSTEM), a position plot (north up,
no map tiles and nothing fetched: each station at its last position,
brighter when heard direct, the selected one with its kept track solid
and its recorded positions dashed, a km scale bar) and a detail panel
on click with its figures, its recent packets and its history. Every
comment, status and system string is a transmitter's free text, shown
with `textContent` only. Dire Wolf's receiver is a passive radio, so
`aprs_packet` and `aprs_station` are Monitor's; under Local the view
shows its scope note and the routes answer `out_of_scope`.

**History**: with `--sloth-db`, the tab reads sloth.db's
`aprs_stations` and `aprs_packets` (schema v13, written by sloth's
`--db` with `--aprs`; `web/src/web_aprshist.c`): a "stations seen"
table over a window (24 h to a year, 100 a page, a callsign search, the
window and search kept per browser) with first and last heard, visits,
packets, ever heard direct, best level, last via, position and comment;
and, for a station clicked there or live, its recorded packets (the
newest 400 that fit the answer) in the detail panel and its recorded
positions on the plot.

Every string is hostile: a call must be an AX.25 callsign (else the
record is rejected and counted), the symbol two printable bytes, the
type one, text printable ASCII within sloth's caps; every number is
range checked and anything outside is `null`, never clamped. Answers
are budgeted in bytes as well as rows, since an escaped comment can
cost six bytes a character. Observation only: no row is a finding, and
APRS authenticates nothing - a position is what a station claimed.

## Radar

The Radar tab (2026-11-06; owner request, "a master radar / CIC view of
every radio heard") is one half-dome centred on the sensor that places
every radio sloth observes, drawn as vector graphics on a plain canvas
and turned, tilted and zoomed by the viewer (`web/ui/radar.js`,
`window.SlothRadar`, containers `radar-*`, one hook in `app.js`; its
spec is `docs/web-ui-spec.md` §8.14). Each family contributes what it
honestly has:

| Family | Position data | Drawn as |
|---|---|---|
| GNSS satellites (`/api/gnss`) | azimuth, elevation | ◇ on the rim shell at its az/el; filled when in the solution, C/N0 on the heat ramp, an unhealthy one ringed; the `/api/gnss/tracks` trail behind it |
| ADS-B aircraft (`/api/adsb`) | lat, lon, altitude, track, kept track | ▲ rotated to its track at its true bearing and elevation angle, a drop line to its ground foot, the kept track through the same mapping; altitude on the heat ramp, an emergency or a reserved squawk ringed and worded |
| APRS stations (`/api/aprs`) | lat, lon, altitude as broadcast | ○ at its true bearing, `--heat-2` when heard direct; the selected station's kept track |
| Wi-Fi APs and stations (`/api/radar`) | sloth's distance estimate (metres, band, trend), no bearing | the 50 most recently heard with an estimate as ■ on the **north axis** at their own distance, each with its own faint solid ring; and one fainter solid ring per band on the ground, labelled `Wi-Fi room 7` |
| BLE advertisers (`/api/radar`) | sloth's distance estimate, no bearing | the 50 most recently heard with an estimate as ● on the north axis, each with its own faint dashed ring; and one fainter dashed ring per band, labelled `BLE room 12` |

The dome is the page (owner request, 2026-11-06): on the Radar tab the
canvas fills the window below the tab bar, and the header, the camera
line and buttons, the picked panel and the caption float over it as
small panels; the explanation folds under "about this view". Other tabs
are unchanged. **full screen** (or `f` on the focused dome) puts the
dome alone into the browser's full screen, every panel hidden; Esc
leaves. The button is hidden where the browser has no Fullscreen API.

A single passive sensor has no bearing for a terrestrial emitter
(`web/src/web_frrs_report.c`, `src/position_track.h`), so rings are the
honest form, and the caption says what a ring is: where the device may
be, not where it is. **True direction, compressed distance**: every
object sits at its true (azimuth, elevation) with its slant range on a
log scale, 0.3 m at the centre (so the "immediate" ring is not the
centre point) to 300 km at the rim, labelled rings at 1 m, 10 m, 100 m,
1 km, 10 km and 100 km; a satellite is the rim-shell case of the same
rule, so a 10 km-away aircraft 10 km up sits at 45° as it does in the
sky, and an airliner 100 km out sits near the horizon. Beyond 300 km an
object is on the rim, dimmed, its true range in the label. The ground
range is the haversine on R 6371008.8 m with the forward azimuth. The
camera is orthographic (yaw, pitch 10° to 90° where 90° is the plan /
PPI view, zoom 0.5 to 4): equal ranges stay equal on screen, so picking
is two-dimensional and the depth only dims a mark on the dome's far
side. Drag turns and tilts (0.5°/px, pointer capture), the wheel zooms,
the focused canvas takes the arrows (Shift ×3), `+` `-`, `0` reset, `n`
north up, `t` plan view and `Escape`; five buttons mirror them for
touch. The dome is drawn only when something changed, through one
`requestAnimationFrame`, never on an idle loop.

**Devices on the north axis** (owner request 2026-11-06: "add
Bluetooth and Wi-Fi devices; since we have no azimuth or location for
them, plot them along the north axis as a dot and label, with a light
transparent ring showing the distance"). Of each family, the 50 most
recently heard rows that carry a distance estimate (`/api/radar`
`devs`, newest first) sit at azimuth 0 on the ground at their own
estimated metres through the same log range (the band's nominal radius
when the record carried no metres): ■ Wi-Fi, ● BLE, each with its own
ring at that distance (`globalAlpha` 0.15, `lineWidth` 1, Wi-Fi solid,
BLE `[6, 4]` dashed, no fill); the per-band rings stay, fainter
(0.09). The axis is a convention, not a bearing, and the side panel
says so ("distance from signal strength; no bearing: drawn on the north
axis"). Only the 10 most recently heard of each family carry a label
(owner ruling after seeing 100 labels cover the dome); any other dot
shows its label while the pointer is over it or it is selected. A label
is compact: the name or SSID cut to 12 characters, else the address's
last three octets, its `~metres` and sloth's trend as its glyph (↘
approaching, → steady, ↗ leaving): the only motion a Wi-Fi or BLE
emitter has. No label is placed under a panel floating over the dome. The caption
counts them ("devices: 50 of 1012 BLE, 50 of 61 Wi-Fi shown (most
recent)"). A dot, or its stacked label, is picked before a ring; the
panel opens it in BLE Devices or Devices (the drawers).

**Labels never overlap.** One layout pass a frame (`drawLabels()`):
every label is a request with an anchor and a priority (selected,
aircraft, APRS, devices, used satellites, other satellites, band
labels, range labels); N E S W are placed first, then the selected,
aircraft and APRS labels greedily (eight directions around the anchor
at two radii, then, for those three, a third radius with a `--rule`
leader), then the north-axis devices in two stacked columns with
leaders (Wi-Fi right of the axis, BLE left; one-dimensional stacking by
anchor height, relaxed upward when a column overflows the canvas),
then everything else greedily. Every label reaches the canvas through
one function that refuses a box off the canvas or touching any box
already placed, so the rule holds whatever a placer proposes; a label
with no room is left out and its mark is still drawn.

**APRS: the window, objects, trails** (owner request 2026-11-06: "a
setting that defaults to one hour for APRS objects and show trails if
they are moving for the last 24 hours"; "objects will update status
regularly but remain up to one hour before clearing after no
transmission"). The top-left panel's one control, `APRS for`
(`radar-aprs-win`: 15 min, **1 h**, 3 h, 6 h, 24 h, kept per browser),
is how long an APRS entity stays on the dome after its **newest packet
of any kind**: every packet resets it, a status-only one included, and
an entity whose newest packet has no position stays at its last known
one. The entities are stations (by source call, ○) and, of their own,
objects and items (by their name, a ✕, labelled `NAME (obj via CALL)`),
read from sloth.db over 24 h once a minute (`/api/aprs/tracks`, so the
live table's 660 s age-out does not clear them) and merged with the
live `/api/aprs` stations, the live row winning for the latest
position. Each carries its newest status and comment: the side panel
shows both, the label adds the status (else the comment) cut to 16
characters when there is room and drops it when there is not. A
**moving** entity (two distinct 0.001° cells, or a speed above 0, in
the 24 h) draws its trail on the ground through the same log mapping,
at most 48 points (the newest of each 30 min bucket), fading toward
its oldest point and broken across a gap of more than two buckets; the
caption says "APRS: N in the last 1 h (M moving, trails 24 h), K
objects". Without `--sloth-db` the live stations still draw, without
trails or objects, and the caption says why.

**Speed and heading.** An aircraft with a ground speed and a track, or
an APRS station with a speed and a course, gets a velocity tick from
its mark along its heading, drawn on the ground-projected direction
(its ground point and a point a small world step along the heading,
each through the same mapping, so the tick bends as the map does), of
screen length `6 + 14·log10(1 + kt/10)` px, at most 30, in the mark's
colour; the ▲ points the same way, and the label adds `250 kt 090°`.
A speed of 0 or none draws no tick.

**Fleet areas** (owner request 2026-11-11: "when multiple sloths exist
on the network use that for better location in the radar view. just
make light transparent overlays for best guesses of the area the signal
may be coming from"). With a `--peer`, the module reads
`/api/fleet/locate` for `wifi`, `ap` and `ble` every 30 s (100 rows a
kind; "Locating emitters" in `docs/wiki/fleet.md`) and draws
each located emitter as a light translucent area on the ground, the
shape its figures honestly give: with three or more sites and a
least-squares fix, the disc of the fix's radius; else, when every pair
of the sites' one-sigma range bands meet, the region where all the
bands (each an annulus `lo_m`..`hi_m` about its site) overlap; else,
when the nearer site is outside the difference's sigma
(`within_band: false`), a fainter wash (half the alpha) over that
site's half of the plane, out to its band's outer edge; else nothing,
counted. Every shape is in metres from this sensor and goes through the
dome's own `place()` and `project()`, so a circle is drawn in 72 steps
and bends on the log range as the rings do. Each area is one `--data`
fill through its clip, the alpha shared out (0.4 over the areas drawn,
at most 0.08) so overlaps read darker and however many stack on one
spot stay under a third of `--data` (1 - e^-0.4), the faint device
rings still readable over them; they are drawn after the dome and
before every mark. The nearer-side wash is that site's disc cut by the
perpendicular bisector, the cut reaching past the disc's far edge.
The other sites are hollow □ with their name. Hover an area, or tap it
with nothing picked, for its label (key, `bands of 2 sites` / `may be
within r` / `nearer SITE`, the band, `coarse`) and, picked, the side
panel; a tap is not taken by an area while something is picked, so
tapping off the marks still clears the panel where a hundred areas
cover the centre. The panel: each site's RSSI, range
and band, the nearer site by dB, the method, the area's form and the
baseline, "open in Fleet". A device dot on the north axis and its area
are linked: hover or pick one and the other is outlined (the dot
ringed). The **fleet areas** button (`radar-fleet`) hides them, kept as
`radar.fleet` only when off. `/api/health` is read once a page for
`fleet.peers`: with none the button is hidden and nothing of the fleet
is fetched, nor with the button off, the tab hidden or under Local
(three requests per 30 s otherwise).
At W9FJC and beta-site (10.5 m apart on 2026-11-11) 133 of 141 located
rows drew: 55 as overlapping bands (outer radius median 40 m), 78 as a
side (median 12 m), 8 with no side; at that baseline they are where an
emitter may be, not where it is, and the caption says so.

**The centre** is the GPS fix when `gnss.fix` is a 2D/3D fix within 60
s, else the position `sensor_health` carries (`/api/gnss` `loc`: the
last fix or `--location`), else the header says "no sensor position:
aircraft and APRS not placed" and draws the satellites and the rings
anyway. **Scope**: the satellites are the host's own receiver's, every
scope's, so the view has no `scoped-out` state; under Local the module
skips `/api/adsb`, `/api/aprs` and `/api/radar` and the header says
"Local: only the host's own receiver (satellites). Aircraft, APRS,
Wi-Fi monitor and BLE are the passive radios' — switch to Monitor or
Hybrid". Every fetch is the page's scoped `getJSON`; `/api/gnss` and
the two decoders every 5 s, `/api/radar` every 10 s (the devices are
current), `/api/fleet/locate` every 30 s (only with a peer, the fleet
areas on), the trails every 60 s. **Picking**: a tap (under 4 px of travel) takes the nearest mark
within 8 px, else the nearest ring by its ellipse distance, else, with
nothing picked, the fleet area under it; with something picked, a tap
off every mark and ring clears it; the side
panel (textContent only) gives the identity, the exact bearing, ground
range, altitude and elevation angle, the signal, lat/lon for an aircraft
or a station, last seen, and for a ring the family, the band's metre
edges (`src/rf_distance.h`), the count and up to eight devices ("8 of
31"), each a way into its drawer; "open in GPS Sat / ADS-B / APRS / BLE
Devices / Devices" shows the tab and hands the family's module the
selection (`SlothGnss.select`, `SlothAdsb.select`, `SlothAprs.select`,
`openBleDrawer`, `openDrawer`). The caption (R9) names the sources and
their windows, the position's source and age, the range and height
rule, each family's placed and unplaced counts, how many Wi-Fi and BLE
rows have no distance estimate, and the estimate sentence. The visual
spec's R12 (no glyph without a TUI form) is waived for this view by
owner ruling (`docs/web-ui-spec.md`): the dome has no character-cell
form; its marks still carry shape and word (R10), it uses no gradient,
shadow or fill on the chrome (R8), and the selection is the one accent.

`/api/radar` (`web/src/web_radar.c`) is the band census the rings
need: one answer with, for BLE (the tables of [BLE](#ble), a row per
advertiser as one sensor heard it) and Wi-Fi (the FRRS ledger's beacons
and probe_clients through `web_frrs_rf_census()`), the row total, the
rows with one of sloth's five band words, the rows with a reading and
no estimate (`none`), and per band the count and its eight
strongest-signal rows (a name cut to 24 octets on a code-point
boundary); and `devs`, each family's 50 most recently heard rows with
an estimate (metres, band, trend word). `/api/ble?limit=1024` answers 62.8 KB with `more:true` and
`/api/wifi/aps` 57 KB, so counting on the page would be a dozen pages
every 10 s; the bands are under 6 KB with every BLE row held, and the
whole answer at its worst (every BLE row and a full ledger, every name
and SSID escaped to six bytes a character) is 43.8 KB, held under 48 KB
by `test_radar.c`. It takes
no parameter (any is `400`), Local answers `out_of_scope` with the query
checked, and a half whose table is not attached is `null`.

## Lures and key harvesting

The WiFi view's "lures and key harvesting" card shows the tables sloth's
KARMA and key-harvest rules read (#187, #172), from three stream
records (JSONL 1.3.0, `docs/wiki/jsonl-schema.md` *Credential lures*):

- **KARMA suspects** (`karma_suspect`, sloth's `[y]` rows): the BSSID,
  its latest SSID, the SSIDs it beaconed, the distinct security
  postures behind them, the names it answered directed probes for and
  never beaconed and how many stations those answers reached, the most
  of its names one station asks for, the deauth-then-lure flag, the
  `[y]` score and the tool attribution.
- **Stations leaving M1s unanswered** (`harvest_station`): BSSIDs asked
  to associate, how many answered with an M1, the M1s left with no M2,
  those carrying a PMKID KDE, the BSSIDs it did answer.
- **Deauth-then-handshake chains** (`harvest_chain`): stations knocked
  off and captured reconnecting, and the deauths before them.

Counts, not verdicts: the alerts (`KARMA_AP`, `KARMA_PROBE_FORGE`,
`PMKID_HARVEST`, `HANDSHAKE_HARVEST`) say whether a row crossed its
threshold. sloth writes a row when its counts move and every 300 s,
and a `gone` record when it leaves sloth's table; slothweb drops a row
on `gone` and leaves out one not refreshed for 660 s. sloth writes
nothing while its tables are empty, so the card reads "none" only from
a 1.3.0 stream; from an older sloth it says the stream does not carry
these, and before the first `sensor_health` that it does not know.

The card is the monitor radio's: hidden under Local, as the rest of the
WiFi view's radio panels are.

## Sensor health

The `#health` view (the sensor health tile's) leads with three panels
about the sensor's own machine, fed by four record types sloth writes
once a minute since JSONL 1.1.0 (`sys_status`, `sys_sensor`,
`source_status`, `receiver_hw`;
[`docs/wiki/jsonl-schema.md`](../docs/wiki/jsonl-schema.md), *Host
status and the source inventory*). `web/src/web_sysstat.c` keeps the
newest batch in memory and answers `/api/sys`; the page is
`web/ui/syshealth.js` (`window.SlothSysHealth`, containers `sy-*`), two
hooks in `app.js`. The older panel (capture, monitor, Bluetooth, the
stream, sloth.db, slothweb.db) is unchanged below them.

**Sources and receivers.** Two tables, each the page's one DataTable.
*Sources* lists every source sloth can read, configured or not: the
IP capture, the monitor radio, the HCI monitor channel, an Ubertooth
stream, the GNSS receiver, the ADS-B and APRS decoders. Each row is its
state, as a mark **and** a word (`● ok`, `◐ stale`, `✕ down`,
`· not configured`; R10: never colour alone), its kind, its endpoint
(or `not configured (--flag)`), the receiver it runs on, when it last
delivered, its rate in its own unit, its errors and the reader's own
word for what is wrong. *Attached receivers* lists the hardware sloth
found in sysfs: the SDRs, GNSS receivers, serial bridges, Wi-Fi
adapters and Bluetooth controllers, each with its USB or PCI ID, the
port it is on, its driver, the interfaces under it, which of sloth's
sources uses it, and what the device says it is.

Two things the tables do not claim. A source is tied to a receiver
**only where sysfs ties them** (an interface or a tty under the
device): an RTL-SDR with `--adsb beast:127.0.0.1:30005` configured
reads `no source of sloth's` on one row and `not tied to a receiver` on
the other, because the dongle is readsb's and sloth sees a TCP
endpoint. And **no serial number** is shown, because sloth does not
read one.

**The sensor host.** A tile per figure: CPU (with iowait and its band),
load, memory, sloth's own RSS, the free space under the output path,
uptime, the hottest temperature, the under-voltage alarm, then one per
temperature sensor, voltage rail and power supply. A reading the host
does not have is `-` and the words `not reported by this host`: a VM
has no hwmon and a desktop no under-voltage alarm, and neither is a
zero. A band is its word (`band: warm`), not a colour.

**Trends.** One row per series, G1 over its hour-of-week band with the
last value, the band's words and a trend word; a source's up/down and
the under-voltage alarm are G5 strips, 96 cells over the window
(`glyph.g5()`, called; the glyph is unchanged). Rows: CPU and memory
(0 to 100 %, one fixed scale, so the two compare), sloth's RSS, the
hottest temperature and each sensor (one shared scale, R3), each
voltage and the alarm, capture drops (`sensor.drops`) and records per
second (`records.total`), and for each configured source its up/down
strip and its rate (each on its own scale: the units differ, and the
caption says so). The window is the `sy-win` control: 1 h, 6 h, **24 h**
(default), 7 d, 30 d, kept per browser. Up to 24 h reads the minute tier
(the fine tier with no store); 7 d and 30 d read the hour tier and need
the store, and say so without one.

The trend word follows one stated rule (`trendOf()`): the median of the
last third of the samples against the median of the first third,
`rising` or `falling` when they differ by more than the series' own
spread (1.4826 × the median absolute deviation, a robust standard
deviation) **and** by more than the smallest change worth a word in
that unit (1 °C, 5 % CPU, 2 % memory, 0.05 V, 1 MB of RSS), `steady`
otherwise. Medians, so one spike moves nothing. With fewer than 12
samples, or samples covering under half the window, the word is
`warming`, as a baseline's is: no trend is claimed. A strip's cell is
*up* only when every bucket in it was up throughout (the bucket's
minimum), so an outage is never averaged away; the alarm's cell is
*set* when it was set at any time (the maximum); a cell with no report
is a gap, not a "down".

**The beacon memory.** Since JSONL 1.2.0 `sys_status` carries the
state of sloth's memory of BSSIDs its beacon table dropped, which
`EVIL_TWIN`'s late-arrival signal reads to tell a returning AP from a
new one. When that memory overflows, an AP it does not know is stamped
unsure and the signal goes quiet until the memory again reaches back
24 h; nothing said so before. One line under the sources table
(`sy-recall`) now does: `evil-twin late-arrival: on (beacon memory N of
4096)`, or `evil-twin late-arrival: quiet until <time>: the beacon
memory overflowed (4096 of 4096, reaches back 6 h)`, or `not reported by
this sensor` from an older sloth. `/api/sys`'s `beacon_recall` is
`{slots, max, overflowed, reach_s, quiet, quiet_s, quiet_until}` or
`null`; `quiet_until` is the batch's `ts` plus `quiet_s`, the sensor's
clock, never compared with slothweb's. Ingest is range-checked like its
neighbours: `slots` within `0..max`, the flags 0 or 1, quiet only with an
overflow, `quiet_s` at most a day; a batch failing any of the first
drops the block and keeps the rest.

**Honest states.** Before the first `sys_status`, the panel says the
sensor has not reported its host status and why that can be: a sloth
older than JSONL 1.1.0, or **slothweb reading a copied sloth.db with no
live stream** — sloth.db holds none of this, so there is nothing to
show (the trends still draw whatever the store kept from an earlier
stream). A sensor that stopped reporting shows its age, and `STALE`
past three of its own intervals, with the last figures marked stale
rather than removed. The view is every scope's, as the health view
always was: `/api/sys` answers the same under Local and Monitor, and
the series are read as Hybrid's whatever the page's scope is (they are
tagged to no radio), so this module fetches them itself rather than
through the page's scoped `getJSON`.

**`/api/sys`** takes no parameter:

```
{"now":1800000065,"scope_note":"every scope: sloth's own state","seen":true,
 "ts":1800000060,"age_s":4,"seq":2,"interval_s":60,"stale":false,
 "system":{"cpu_pct":15.0,"cpu_iowait_pct":10.0,"cpu_band":"low","load1":0.20,...,
           "temp_max_c":51.0,"temp_max_id":"hwmon3/temp1","temp_band":"ok","undervolt":0},
 "sensors":[{"class":"temp","id":"thermal_zone0","key":"thermal_zone0","label":"cpu-thermal",
             "c":48.3,"alarm":null,"capacity":null,"status":null},...],
 "sources":[{"name":"monitor","kind":"wifi-monitor","state":"ok","endpoint":"wlan1mon",
             "hw":"usb:1-1.4","desc":"Realtek RTL8812AU 802.11ac","driver":"rtl88XXau",
             "age_s":0,"age_band":"fresh","unit":"frames","count":184220,"rate":51.30,...},...],
 "receivers":[{"key":"usb:1-1.2","kind":"sdr","bus":"usb","id":"0bda:2838","known":1,...},...],
 "records":11,"rejected":0,"overflow":0}
```

A figure the sensor did not send is `null`; an empty string is `null`
too. `age_s` is slothweb's monotonic clock against itself (when the
batch arrived), never the record's `ts` against this host's wall clock.
`key` is the sensor's series key. Bounds: 36 sensors, 8 sources, 16
receivers (sloth sends at most 36, 7 and 16; more are counted in
`overflow`), a record that does not pass its checks is counted in
`rejected`, and every string is kept only up to what it costs to write
(a byte the JSON writer escapes to six costs six), so the answer at its
worst — every slot full of `<` — is 17.8 KB of the 63 KB the buffer
holds (`test_sysstat.c` builds it and prints the figure).

**Series and cost.** Eight metrics ([Metrics](#metrics)): `sys.cpu`,
`sys.mem_used`, `sys.rss`, `sys.undervolt` (global) and `sys.temp`,
`sys.volt`, `source.rate`, `source.up` (keyed, the `sys` class, 64
keys). One sample a minute each. They are rows in the store's existing
`series` / `fine` / `minute` / `hour` tables under their metric names:
**no table, no column and no store version change**. A Raspberry Pi
with two temperature sensors, the under-voltage alarm and four
configured sources is 15 series, each a row a minute in the fine tier
(24 h) and the minute tier (30 d) and one an hour for 400 days. None of the eight is scored by the
anomaly engine (the global ones as every global series, the keyed ones
by class): a board warming up is not an intrusion. In memory, each
metric adds its open buckets to every key slot of every class (204
bytes a slot, measured): eight metrics are 2.58 MB over the 1,657 slots
of the default `--web-max-keys 512`, and the new class's own 64 slots
0.61 MB; at `--web-max-keys 8192` the eight are 32.5 MB. The record-type
class went from 64 to 80 keys with the four new types (0.15 MB). That is the
rollup's existing cost per metric, not a new one.

## The data socket (M1)

One thread (`web/src/web_ingest.c`) connects to `--socket`, reads, and
hands each line to the decoder. It never writes a byte to the socket
(the stream is one-way; sloth never reads from a client) and never
resolves a name. When the connection fails or the peer closes it, the
thread waits and tries again: 250 ms, doubling, capped at 4 s, so a
restarted sloth is back on the page within the spec's 5 s. A
connection that delivered at least one whole line resets the wait; one
that is accepted and closed at once (sloth refusing a client over its
per-peer cap does that) does not, so it is never redialled in a tight
loop. A TCP connect gives up after 3 s.

**Every byte from the socket is untrusted.** Lines are framed on `\n`
and capped at 16 KB (sloth's own line buffer is 8 KB); a longer line is
discarded through its newline and counted once, however the reads split
it. Each line is decoded by a strict reader written for this
(`web/src/web_jsonl.c`), not by `research/mcp/json.c`, which decodes
`\u` only to Latin-1 and does not check raw UTF-8. A line is refused
whole, and counted by reason, unless it is one JSON object (RFC 8259)
with nothing after it, at most 384 top-level members and 8 levels deep,
every string well-formed UTF-8 (RFC 3629) both raw and after `\u`
decoding (no lone surrogate, no overlong form, no raw control byte, no
`\u0000`), no member name twice (which `type` would win is what a
hostile line would like to choose), and a string `type`. A line the
connection ended in the middle of is counted as `truncated`.

Strings are kept cut to a fixed size on a code-point boundary and leave
slothweb only through one JSON writer (`web/src/web_json.c`), which
escapes per RFC 8259 and also writes `<`, `>`, `&`, `'`, DEL, C1 and
U+2028/U+2029 as `\uXXXX`. So a hostname or SSID holding markup is never
markup in any byte slothweb sends, and the page shows every stream value
with `textContent` only: the script contains no `innerHTML` or other
HTML or code sink, and a record type picks its colour from a fixed
table rather than becoming a class name.

**The device count.** sloth's poll thread rebuilds `s->devices` every
poll and writes one `device` record per row (`jsonl_emit_devices()`),
so the number of `device` records in one pass is exactly the TUI's
`device_count`. slothweb counts rows, not distinct MACs, for the same
reason. The pass is not one unbroken run on the wire: the capture
thread writes `dns`, `tls`, `quic`, `http`, `ntp`, `icmp` and
`cleartext_cred` records through the same writer at the same time, and
no lock spans the pass, so a DNS answer can land between two device
rows. Only the poll thread's own record types (`POLL_TYPES` in
`web/src/web_live.c`) steer the count; every other type, alerts and
types sloth adds later included, is passed over. A pass ends at the
first poll-thread record of another type and is then published. A pass that a `socket_gap`, an undecodable line or an
implausible `type` may have cut short is not published, and the
previous count stands (`device_passes_unpublished`). sloth's snapshot
batch starts with the `iface` records, so a batch that reaches the next
batch's start with no `device` record at all publishes `0`, unless
something was lost in it. A new connection is a new stream: a pass begun
on the old one is never finished by the new one.

**Open alerts** are counted from the lifecycle records since this
connection. sloth replays nothing on connect, so an incident opened
earlier is counted once it is updated or escalated, and a resolve missed
while disconnected cannot leave one open forever: the set starts empty
on every connection. An under-count heals itself; an over-count would
not.

## The time series (M2)

### Metrics

The ingest thread hands each decoded record to `web/src/web_metrics.c`
after the live state, which turns it into samples. The set is
docs/web-ui-spec.md §5.1, and every one of its metrics has a source
`src/jsonl.c` writes today, so none is left out:

| Metric | Kind | Key | From |
|---|---|---|---|
| `iface.rx_rate`, `iface.tx_rate` | gauge | interface | `iface` `rx_rate`, `tx_rate` |
| `host.rx_rate`, `host.tx_rate`, `host.conns` | gauge | IP | `top_host` `rx_rate`, `tx_rate`, `conn_count` |
| `dev.frames` | counter | MAC | `frame_count` deltas of `probe_client` (`mac`) and `assoc` (`sta_mac`). Not `seqnum_client`: sloth counts the same probe requests in both tables (`src/capture/probe.c` feeds each to `seqnum_track_observe()` and then `record_probe()`), so the two summed would count every probe twice. The probes it leaves out are those whose body was cut short of its information elements |
| `dev.present` | presence | MAC | any record with `mac` or `sta_mac` whose `last_seen`, if it has one, is within 10 s of its `ts` |
| `dns.queries` | counter | IP | `dns` with `is_resp` 0, by `src` |
| `dns.nxdomain` | counter | IP | `dns` with `answer` `NXDOMAIN`, by `src`, which on a response is the resolver: sloth's record names no client for an answer |
| `tls.handshakes` | counter | IP | `tls`, by `src` |
| `http.requests` | counter | IP | `http` without `status` (a response has one), by `src` |
| `alerts.fired` | counter | alert type | `alert` (one per new alert key), by `ty`; the lifecycle records are not counted again |
| `wifi.ap_count` | gauge | channel | `channel_summary` `ap_count` |
| `wifi.ctrl_total` | counter | channel | `channel_summary` `ctrl_total` deltas: sloth's figure is a running total, so this is a counter, not the spec's gauge |
| `wifi.deauth` | counter | MAC (BSSID) | `deauth` `count` deltas per (src, dst, bssid, subtype), by `bssid` |
| `wifi.probe_clients` | gauge | none | `probe_client` rows per snapshot pass |
| `conns.total` | gauge | none | `connections` rows per snapshot pass |
| `flow.ssh`, `flow.rdp`, `flow.smb`, `flow.snmp`, `flow.mqtt` | counter | IP | deltas of `ssh_flow` `banner_count`, `rdp_flow` `connect_req_count`, `smb_session` `count` (by `client_ip`), `snmp_flow` get+getnext+getbulk+set+response+trap, `mqtt_flow` connect+subscribe+publish, per flow, by source |
| `live.devices`, `live.alerts_open`, `live.anomalies_open` | gauge | none | docs/web-visual-spec.md §7 (V1, F1): sampled once a batch (below), from `web_live_summary()`'s device count and open incident severities (low+warn+crit summed) and from `web_anomaly_open_count()`. Each needs its source wired first (`web_metrics_set_live()`, `web_metrics_set_anomaly()`); unwired, neither is sampled at all, not sampled at 0 |
| `records.rate` | counter | record type | every decoded record but `socket_gap`, one per line, keyed by its own `type` |
| `records.total` | counter | none | the same records, unkeyed (#171 V1): the records/s tile's G1, one read rather than one per type, and exactly the sum of `records.rate`'s keys (a type `records.rate` refuses is in neither) |
| `gnss.sats_used`, `gnss.hdop`, `gnss.time_off_ms`, `gnss.cn0_mean` | gauge | none | the host's own GNSS receiver ([GNSS](#gnss)): `gnss_fix` `usat` (when ≥ 0), `hdop` (when > 0) and `time_off_ms` (when present), `gnss_sky` `cn0_mean` (when > 0). The records are change-only (a band change or the 300 s heartbeat), so each series is as sparse as its record; every scope's, as `sensor.drops` is; not scored by the anomaly engine |
| `ble.class.advertisers` | gauge | BLE class | the BLE Devices view's class rows ([BLE](#ble), `web/src/web_bledev.h`): once a snapshot pass (at the batch's first `iface` record), the distinct addresses whose rows in the BLE tables were heard in the last 20 s, per device class (`b:phone`, `b:wear`, `b:tag`, `b:hid`, `b:bcn`, `b:iot`, `b:unk`), anonymous rows (`addr_type` 255) one advertiser between them in `b:unk`, as the class mix draws them; a class with none is not sampled |
| `ble.class.adv` | counter, reports | BLE class | `ble_device` `adv_count` deltas per (address, address type, sensor), by the record's class, an anonymous row's (`addr_type` 255) included, always under `b:unk`; a one-channel sample (`sampled` 1) left out. HCI advertising reports, one a scan rather than a frame when the controller filters duplicates |
| `sys.cpu`, `sys.mem_used`, `sys.rss`, `sys.undervolt` | gauge; %, %, kB, 0/1 | none | the sensor host's own state ([Sensor health](#sensor-health)), one sample a minute: `sys_status` `cpu_pct`; `mem_total_kb` less `mem_avail_kb` as a share of the total; `rss_kb`; `undervolt`, whose bucket maximum says whether the alarm was set in it. A member the record does not carry, or one out of range, is not sampled: an absent reading is a gap, never a 0. Every scope's; not scored |
| `sys.temp`, `sys.volt` | gauge; C, V | sensor (`sys`) | `sys_sensor` `c` by `id` (class `temp`) and `v` by `id` (classes `volt` and `power`); key `hottest` of `sys.temp` is `sys_status` `temp_max_c`. An alarm-only rail has no `sys.volt` series |
| `source.rate`, `source.up` | gauge; /s, 0/1 | source (`sys`) | `source_status` `rate` and `state` by `name`: 1 for `ok`, 0 for `stale` or `down`, nothing while `not_configured`. A bucket's minimum says whether the source was up throughout it, which is what the page's strip reads |
| `sensor.drops` | counter | none | §7: `sensor_health` `capture_drop_delta` + `capture_ifdrop_delta` + `monitor_drop_delta` + `monitor_ifdrop_delta`, every tick, including the 0 of a healthy one -- a flat line, not a gap |
| `rf.rssi.sta`, `rf.rssi.bssid`, `rf.rssi.ble` | gauge, dBm | MAC | the signal sloth last heard from the emitter, one sample per record that carries one: `probe_client` `signal_dbm` by `mac`; `beacon` and `assoc` `signal_dbm` by `bssid` (an assoc row's signal is the AP's frames, the (re)association response and EAPOL M1/M3, never the station's); `ble_device` `rssi` by `addr` with `has_rssi` 1, every receiver and address type of that address in one series. Sampled only when the record's `last_seen` is within 10 s of its `ts`, so a row sloth re-sends after the emitter went quiet adds nothing; a Wi-Fi 0 (sloth's "no signal") and anything outside -127..-1 dBm (BLE -127..+20) is not a reading. Since 2026-11-02 sloth re-sends `ble_device` once a 10 s slot while it keeps hearing the advertiser (otherwise on a change or the 300 s heartbeat), so a heard advertiser's series has a point a fine bucket. Owner ruling 2026-11-02 on [`docs/web-frrs-spec.md`](../docs/web-frrs-spec.md) Q7. Each bucket is the mean of what one receiver's driver reported, with min and max: a sloth gauge, not a calibrated measurement. The Wi-Fi pair are the device class's keys, so `--web-max-keys` bounds them with the same eviction; `rf.rssi.ble` is the BLE class's (#177), its own cap at the same N, so rotating advertiser addresses evict each other and never a Wi-Fi key; Monitor's scope; not scored by the anomaly engine |

A key is a canonical form checked by type: a MAC is lower-case
`xx:xx:xx:xx:xx:xx` (all zeros, sloth's "no MAC", is not one), an IP is
what `inet_ntop()` writes back for what `inet_pton()` accepted, an
interface name is 1..15 bytes of `[A-Za-z0-9_.:@-]`, a channel is
1..233 with `6g` in front on 6 GHz (5 and 6 GHz share numbers), an alert
type is `ty` 0..9999, a record type is 1..32 bytes of `[a-z0-9_.]` (the
same charset `web_live.c`'s own `type_ok()` holds it to), a BLE class one
of the seven slugs (`bleclass`, at most 8 keys, never evicted by the
others, not scored by the anomaly engine), a sensor or source name
1..47 bytes of `[a-z0-9_.-]` after lower-casing and `/` to `.`, so
`hwmon1/temp2` is `hwmon1.temp2` (`sys`, at most 64 keys: sloth sends
36 sensors and 7 sources at most; a class of its own, established from
the first sample as the interface class is, not scored). A record whose
key does not pass is not counted, so no string a peer wrote is ever a
key as it was sent. Gauges take sloth's `%.2f` reals.

**Running totals.** `frame_count`, `count` and the flow counts are
high-water marks. Each is turned into a delta against the last value
seen for the same row, floored at zero, so a row sloth evicted and made
again does not read as a negative burst. On a new connection sloth
re-sends every row at its full total, so the first sight of a row is a
baseline (no delta) unless the row's own `first_seen` is no earlier than
the connection's first record, i.e. it was born while slothweb was
listening; rows with no `first_seen` (`channel_summary`) are always a
baseline on first sight. Every connection starts a new
table. The table holds 4,096 rows, least recently used out first,
counted as `highwater_evictions`. An evicted row's id goes into a small
two-hash filter, so a row born while listening, evicted and then seen
again on the same connection is a baseline the second time rather than
counting its whole total twice; a filter collision can only turn a born
row into a baseline. The filter is two generations of 4,096 ids, 8 KB
each, cleared with the table: when the newer fills, the older is
cleared and takes the next ids, so a long connection never saturates
it. That bounds both sides. A lookup is wrongly positive at most about
2.7% of the time (a born row's first total taken as a baseline), and an
evicted id is remembered across at least 4,096 later evictions and
fewer than 8,192; a row evicted and seen again only after more than that
counts its total a second time.

**Rows per pass** (`conns.total`, `wifi.probe_clients`) use the same
batch start as the device count: the first `iface` record after another
poll-thread record. `connections` is written just before its tick's
`iface` records, so the window that closes at a batch start holds that
tick's connections and the previous tick's probe clients. The partial
window a connection opens in is not sampled, nor is one that a
`socket_gap` or an undecodable line may have cut.

`live.devices` and `live.alerts_open` sample at the same batch start,
but unlike `conns.total` they are not gated on the batch being untainted:
`web_live_t`'s own device count already holds its last *published*
value through a taint (`web_live.c`'s `devices_step()`), so the sample
is the same figure `/api/live` would answer, not a stale reread of a
half-built pass. `live.anomalies_open` samples on the same tick, from
whichever `web_anomaly_t` was wired in, independent of `web_live_t`.

Bucketing uses slothweb's clock, never a record's `ts`: a hostile `ts`
could otherwise write anywhere in history.

### Tiers

| Tier | Bucket | Kept | `tier=` |
|---|---|---|---|
| fine | 10 s | 24 h | `fine` |
| minute | 1 min | `--web-retain-days` (30 d) | `minute` |
| hour | 1 h | 400 d | `hour` |

Every series keeps one open bucket per tier with sum, count, min and
max. A bucket closes when a sample lands in a later one, or when the
store thread finds its interval over, whichever is first. A gauge's
value is sum/count, a counter's sum, presence's max. Keys are bounded
per class: device MACs (`--web-max-keys`, 512), host IPs (half, 256),
BLE advertiser addresses (`rf.rssi.ble`, the same N, a class of their
own since #177), interfaces (32, sloth's `MAX_IFACES`), channels (64,
sloth's `MAX_CHAN_ENTRIES`) and alert types (128: sloth has 90 kinds); a new key
in a full class evicts the one seen least recently, after writing out
its open buckets, and is counted in `key_evictions`. The one global key
is never evicted.

Interfaces, channels and alert types come from catalogues sloth itself
bounds, which no peer can churn, so their keys are *established*, as
the global key is, from their first sample: an alert type that fires
twice in a few seconds gets its minute row when the minute ends and its
hour row when the hour does, and an evicted channel's rows are written,
not dropped. Each has its own class, so a busy channel list cannot
evict a quiet alert type.

Device and host keys are whatever a frame or a packet claims, and what
an eviction writes for them is decided on the key's whole life, not on
how many samples it took. One is established once its samples span a
minute (the last 60 s or more after the first). Until then its 10 s
buckets are written as usual, but its 1 min and 1 h buckets are held in
memory (at most two per tier, since samples within a minute cross at
most one boundary of each). When it becomes established they are
written. When it is evicted first they are dropped, counted as
`churn_dropped`, whether it took one sample or a hundred. A key neither
established nor evicted has them written at shutdown, so until then its
minute and hour rows are not in the store. The life outlasts a stay in
the class: an evicted key's first sighting, and whether it was
established, are kept in a small table (four entries per key slot) and
given back when it returns (`key_returns`). So a real host that recurs
under LRU pressure, evicted between each two of its samples, is
established a minute after it was first seen and from then on writes
its minute and hour buckets, partial at each eviction and merged by the
store; it loses only its first minute's. The table prefers established
keys: an unestablished one never displaces an established one, so a
scan can only push out the entries of keys still in their first minute.
What holds, then: a scan or a spoofed-source flood whose keys are each
seen for under a minute writes 10 s rows only, which the ceiling drops
first and which expire in 24 h; at shutdown at most the keys then
resident (one class cap) write what they held. Keys seen across a
minute or more do reach the 30-day and 400-day tiers, one row per
metric per bucket each, under churn too: that is bounded by the
ceiling, not by this rule. A key evicted and seen
again is a new series in memory: `/api/series` finds its earlier rows in
the store, and without one they are gone from the answer.

Closed buckets wait for the store thread in a queue sized from the
class caps: six rows for every series the classes can hold, and at
least 32,768 (about 3 MB at the default `--web-max-keys`, 41 MB at
8,192; allocated zeroed, so only what is used is resident). Six covers
what one series can close between two writes: two 10 s rows, a minute
and an hour row, and the two held rows of a key becoming established.
So the hour boundary, which closes a 10 s, a minute and an hour bucket
of every series in one pass, and the shutdown, which writes what is
queued and then closes everything still open, fit at 8,192 keys. The
store thread also writes early once 16,384 rows are queued. Only
eviction churn can outrun the queue; then a 10 s row is dropped before
a minute or hour row (one arriving at a full queue takes the newest
queued 10 s row's place), and every drop is `queue_dropped`.

Closed 10 s buckets also go to a ring of 131,072 rows in memory (about
5 MB); `/api/series` reads it for what the store has not written yet,
and in a build without SQLite it is all there is.

### slothweb.db

`--store` (default `./slothweb.db`) is slothweb's file. It holds the
closed buckets, `series(id, metric, key)` and one table per tier,
`(series, t, sum, n, min, max)`, and since v3 the anomaly engine's
state (`baseline`, `baseline_cell`, `episode`, `fanout`, `reported`;
[below](#baselines-and-anomalies-m3)). It is never `sloth.db`.

- **Opening** follows sloth's rules for its own database (`src/db.c`,
  `src/secure_file.c`, re-implemented because no `src/` file is linked):
  the path is opened by descriptor with `O_NOFOLLOW` and created `0600`;
  an existing file must be a regular file owned by the effective uid
  with no group or other bits and one link, and the `-wal`, `-shm` and
  `-journal` files, when present, the same; anything else is refused,
  never repaired. SQLite then opens it with `SQLITE_OPEN_NOFOLLOW` and
  `SQLITE_DBCONFIG_DEFENSIVE`, and needs 3.31.0 or later.
- **Identification** happens before anything is written, on a
  read-only connection: the last read-write connection to close on a
  WAL database checkpoints the WAL into it and deletes the WAL, so
  identifying a WAL-mode sloth.db on one would rewrite the file it
  refused. A read-only connection does make an absent `-wal` (empty)
  and `-shm` (32 KB), so a WAL-mode file with no `-wal` (cleanly
  closed: all it holds is in the main file) is read as an immutable
  URI instead, which opens no side file; a refused, cleanly closed
  sloth.db leaves its directory exactly as it was. They are not made
  and deleted, because deleting would race sloth opening its own file.
  A `-wal` with no `-shm` beside it still gets one made. Only once the
  file is ours or empty is it opened read-write (and identified again
  there, so a file swapped between the two opens is refused). An empty
  file is new: no schema object, and `application_id` and
  `user_version` both 0, so a file another program has set up but given
  no table yet is not taken for one. A new store is stamped with
  slothweb's own `application_id` (`0x534c5745`, "SLWE"), and a file
  carrying any other non-zero one is refused. A file whose `meta` table
  says `store = slothweb` is ours, at its `schema_version`. Anything
  else (sloth.db, whose `meta` is differently shaped, any other
  database, a file that is not SQLite) is refused and left byte for
  byte as it was. So is a store whose version is newer than this
  build's.
- **Migration** follows the 2026-10-21 owner rule: a chain of steps from
  v0, each additive, each in one `BEGIN IMMEDIATE` transaction with its
  own version stamp, so a failed step leaves the file at the version it
  last reached, with the step's own changes rolled back. A new file is
  stamped v0 first and takes the same chain, so the chain runs on every
  first start. Today the chain is nine steps: v0 to v1 creates the four
  tables, v1 to v2 indexes each tier on `t`, v2 to v3 creates the five
  analysis tables, v3 to v4 creates `passive_ptr` and its index (M4),
  v4 to v5 creates `chmix` and its index (the WiFi view's channel mix,
  [below](#the-channel-mix-slothwebdb-v5)), v5 to v6 the triage and
  TACDB tables ([Triage](#triage-and-the-frrs-record)), v6 to v7 the BLE
  tables ([below](#the-ble-tables-slothwebdb-v7)), v7 to v8 the
  fleet's `peer_sites` and `peer_sightings`
  ([Fleet](#the-fleet-tables-slothwebdb-v8)) and v8 to v9 the anomaly
  subjects and the operator's links
  ([below](#anomaly-triage-and-links-slothwebdb-v9)); plain `CREATE TABLE` and
  `CREATE INDEX`: a name already taken fails the step rather than being
  adopted.
- **No column can hold a credential**: `web/tests/test_store.c` keeps
  sloth's `test_db.c` guardrail (no column named for a password, a
  community, a nonce, a key or a token may be TEXT or BLOB), and scans
  the file for an SNMP community, an MQTT user name and a cleartext
  credential fed through the stream. Keys are canonical addresses and
  names only.
- **Writes** come only from the store thread (`web/src/web_tsdb.c`),
  never the HTTP thread: once a second it closes due buckets, every
  10 s (or as soon as 16,384 are queued) it writes the closed ones, up
  to 4,096 to a transaction. A bucket already on
  disk (one an eviction or a restart closed early) is merged: sums and
  counts added, min and max widened, and not counted again in
  `store_rows`. On shutdown what is queued is written, then every open
  bucket is closed and written, so a restart picks up where it stopped. One
  bucket is briefly short after a restart: the one the restart split.
  Until this run's part of it is written (within two flush intervals),
  `/api/series` has the last run's part in the store and this run's in
  memory, and shows the fuller of the two rather than their sum.
- **The ceiling** (`--web-max-mb`) is checked after every 10 s write,
  not only at compaction, so it bounds the file within one flush
  interval: key churn can otherwise write millions of rows in an hour.
  The check is three PRAGMAs (4 µs). Over it, slices go until it is
  under, each its own transaction: the oldest 2,048 fine rows (any
  series) until none is left, then the oldest 2,048 keyed minute rows,
  then keyed hour rows, and only then the same for the global series,
  which are one per metric whatever the traffic; series rows left with
  no bucket are swept once after the slices, and free pages are
  returned, 256 at a time. Passes that dropped rows are
  `store_ceiling_runs`, rows `store_dropped_ceiling`. A pass over the
  ceiling first measures the analysis state's pages (`dbstat`,
  `store_analysis_bytes`: the baseline tables kept until the next
  baseline write, the episode, fanout and reported tables, a few hundred
  KB at most, measured on every pass, so the figure is never stale past
  the next one). When they leave less than the history allowance under
  the ceiling, the pass trims the time series to the allowance instead
  (`store_ceiling_raised`). Every slice reads
  the head of the v2 index on `t`; without it each was a full scan of
  the tier. Measured on a store filled to the ceiling (2,048 host keys,
  then flushes of 2,000 new fine rows each followed by the ceiling, as
  the store thread does): at 256 MB a trim took 4,767 ms before the
  index, 215 ms with it and 5-minute slices, and a median 74 ms with
  2,048-row slices; at 64 MB a median 209 ms with 5-minute slices and
  59 ms with 2,048-row ones. The index costs space: the ceiling holds
  about 36% fewer fine rows (6.1 M rather than 9.6 M at 256 MB).
- **Compaction** runs at start and then once an hour, after the write:
  rows past each tier's retention go, a tile at a time (256 series of
  consecutive id by 256 buckets of `t`, one transaction each); then the
  ceiling as above; then free pages are returned
  (`auto_vacuum=INCREMENTAL`, 256 pages to a transaction) and the WAL is
  truncated. A tier is keyed `(series, t)` and indexed on `t`, so a
  delete in `t` order scatters over the key's pages and one in series
  order over the index's; a tile is a run of both, about 2,000 pages
  whatever the size of the store.
- **The WAL** is not counted in `--web-max-mb`, which bounds the main
  file; what bounds the WAL is that no transaction is large. It is
  checkpointed once it passes 1 MB (`wal_autocheckpoint`) and cut back
  to 1 MB at the next write after a checkpoint (`journal_size_limit`),
  so between transactions it holds at most about 1 MB, and during one
  it grows by the pages that transaction changes: at most a leaf of the
  key and one of the index per row. The largest transactions are a write
  of 4,096 queued rows and a ceiling slice of 2,048, so at 4 KB pages
  the worst case is about 32 MB above the file, whatever the ceiling;
  an expiry tile changes about 8 MB at most. Before, the start-up
  compaction deleted everything expired in one transaction, and after a
  long stop the WAL grew to the size of the file. Measured on a store
  of 1.5 M fine rows (44 to 49 MB) expired at once, for 100, 1,000,
  5,000 and 20,000 series: the WAL peaked at 45 to 49 MB in one
  transaction and at 2.0 to 7.1 MB by tiles, and the compaction took 1.7
  to 4.8 s before and 1.7 to 2.4 s after. On the ceiling measurement
  above (256 MB) the WAL's largest was 11.0 MB, from the 2,000-row
  writes, not the trims.
- **Reads** come from the HTTP thread over a second, read-only
  connection (WAL lets it read beside the writer), with every value
  bound as a parameter; a table name is chosen from three constant
  statements, never from the request.

An hour of a small home network's records (2 interfaces, 20 hosts, 30
devices, 10 probe clients, 3 channels, 15 connections, a DNS query
every 2 s; 117 series) is 42,120 fine rows: 1.8 MB on disk, the file
and its truncated WAL, after the hour's compaction (1.1 MB before the
v2 index), and at most 3.4 MB during the hour, the WAL between
checkpoints included.

**Without SQLite** (`make web WITH_SQLITE=0`), there is no store:
`--store` is a usage error, the minute and hour tiers are not kept, and
`/api/series` serves the fine tier from the in-memory ring only, which
covers about 131,072 / (number of series) buckets of 10 s: about 3 h at
117 series, about 7 minutes at 3,000. The ring is shared: the closed
rows of keys since evicted stay in it until they are written over, so
under key churn the live series get less than that. `/api/metrics` says `"store":false`
and marks the two tiers unavailable; asking for one is a `400`
`tier_unavailable`. `/api/health` says `"store":"memory"`.

### /api/series, /api/keys, /api/metrics

```
GET /api/series?metric=iface.rx_rate&key=eth0&tier=fine&from=1792540800&to=1792627200
{"metric":"iface.rx_rate","key":"eth0","tier":"fine","step":10,"kind":"gauge",
 "unit":"B/s","from":1792540800,"to":1792627200,"source":"store+memory",
 "more":false,"next_to":null,
 "points":[[1792623600,1002.5,1000.5,1004.5,5],...]}
```

`points` are `[t, value, min, max, n]`, oldest first, for buckets with
`from <= t < to`; `value` is the mean for a gauge, the sum for a
counter, the max for presence. Buckets with no sample are absent. At
most 900 come back, the newest; `"more":true` and `next_to` say to ask
again with `to=next_to` for the older ones (the page does, up to twelve
times). The bucket still filling is included. `source` is
`store+memory`, `store` (minute and hour) or `memory`.

The parameters are validated before anything reads a series, and every
refusal is a `400` with a reason word of slothweb's own, never the
value back:

| Rule | Reason |
|---|---|
| the query is `name=value` pairs joined by `&`, nothing else | `bad_query` |
| a name is one of `metric`, `key`, `tier`, `from`, `to` (`/api/keys`: `metric`; `/api/metrics`: none) | `unknown_parameter` |
| each at most once | `repeated_parameter` |
| a value is percent-decoded (RFC 3986 §2.1), then 1..63 bytes of printable ASCII | `bad_escape`, `bad_value`, `empty_value`, `value_too_long` |
| the whole query is under 512 bytes | `query_too_long` |
| `metric` is one of the table above | `missing_metric`, `unknown_metric` |
| `key` passes the metric's canonicaliser; a global metric takes none | `bad_key` |
| `tier` is `fine` (default), `minute` or `hour`, the last two only with a store | `unknown_tier`, `tier_unavailable` |
| `from` and `to` are 1..11 decimal digits; `to` defaults to the end of the current bucket, `from` to 1 h, 1 d or 30 d before it | `bad_from`, `bad_to` |
| `from < to`, `to` at most a day ahead, the span no longer than the tier keeps plus one bucket | `empty_range`, `to_in_future`, `range_too_long` |

A point is at most 69 bytes, so 900 fit the 64 KB answer buffer with its
header; `test_series.c` builds that worst case. `/api/keys?metric=M`
lists the keys holding a series of `M`, most recently seen first (256 at
most, with `total`). `/api/metrics` lists the metric table, each with
its key count, and the tiers with their steps, retention and whether
this build serves them.

### /api/series/all

```
GET /api/series/all?metric=host.rx_rate&tier=fine&from=1792540800&to=1792627200&cols=480
{"metric":"host.rx_rate","tier":"fine","step":10,"cell":180,"cells":480,
 "kind":"gauge","unit":"B/s","keykind":"ip","from":1792540800,"to":1792627200,
 "total":300,
 "keys":[{"key":"192.0.2.10","p":[0,1002.5,1,998.25,7,1010]},...],
 "more":true,"next":"192.0.2.31","source":"store+memory"}
```

Every key of one metric over one window, for the Activity graph's
`keys: all` (`web/src/web_allkeys.c`). One `/api/series` read a key
would be 2,560 requests for 256 keys over 24 h at 10 s (ten pages of 900
each), and 81,920 for 8,192; this is one read a key on the server, 128
keys to an answer.

- **Cells.** A key's buckets are merged into at most `cols` cells
  (8..480, 240 when absent). A cell is `cell` seconds, a whole number of
  the tier's buckets, the least that fits; cell `i` starts at
  `from + i * cell`. `p` is sparse and flat, `[i, v, i, v, ...]`, the
  cells that hold a bucket, oldest first; an empty cell is absent, never
  a 0. A cell's value is its buckets' merge read as `/api/series` reads
  one bucket: a gauge's mean, a counter's **sum** (per `cell` seconds,
  not per bucket), presence's max. Six significant digits.
- **Keys: every one.** Not `/api/keys`' 256 most recently seen (owner
  ruling of 2026-11-11, "lift the cap"): the union of the keys the
  rollup holds a series of now (at most `--web-max-keys`, 8,192 at its
  maximum) and the keys the store holds a bucket of in the window
  (`web_store_keys_after()`: one seek of the `(metric, key)` index a
  series and one of the tier's primary key, no scan of the window), so
  a key the rollup has since evicted is still answered from its rows.
  The first answer (no `after`) carries `total`, how many there are;
  the others `"total":null`. A store holding more than the 65,536 keys
  one answer counts says `"total_min":true`, and the page writes
  `65536+`.
- **Paging.** Keys are answered in byte order, at most 128 to an
  answer, and fewer when the 64 KB answer is full (a key is never cut:
  the one that did not fit is the next answer's first) or when the
  answer has taken keys for 100 ms (`WEB_ALLKEYS_ANSWER_MS`; it always
  answers one), which is what keeps an answer inside the request's
  250 ms whatever the keys hold. `more` and `next` say to ask again
  with `after=next`. The lists are read afresh for each answer, so a
  key that appeared or was evicted between two pages is the one
  inconsistency a paged read can show; none is answered twice.
- **Bounds.** `after` is a key of the metric, canonicalised as `key`
  is (`bad_after`; a global metric takes none); `cols` out of range is
  `bad_cols`; a window of more than 10,080 of the tier's buckets is
  `range_too_long` (7 d of minutes; 24 h at 10 s is 8,640, 400 d of
  hours 9,600). The other rules and reason words are `/api/series`'.
  Under a scope the keys are the scope's, and a metric the scope does
  not hold answers no key and `"out_of_scope":true`.
- **Cost.** Rows, not cells: a key is one read of at most 10,081
  buckets (the store's and the ring's, merged as `/api/series` merges
  them) and one pass over the fine ring. Measured by `test_allkeys.c`
  on the build host, unsanitized, on a busy machine:

  | what | answers | bytes | in all | the slowest answer |
  |---|---|---|---|---|
  | the fullest answer from memory: 19 keys of 4,096 buckets each in 480 cells | 1 | 62,372 | 15 to 16 ms | |
  | the fullest from the store: 14 keys of 24 h at 10 s, 8,640 rows each | 1 | 62,647 | 32 to 37 ms | |
  | 8,192 keys walked from the store (8 rows each, none in the rollup), 64 cells | 64 | 604,978 | 89 to 100 ms | 4.5 to 5.4 ms (the first, which counts the keys: 6 to 8 ms) |
  | 8,192 keys walked from memory (16 buckets each: the ring's 131,072 rows full), 64 cells | 64 to 65 | 416,178 | 3.8 to 4.0 s | 71 to 100 ms (100 is the answer's own time bound stopping it) |

  The last is the ring's worst: `web_rollup_fine()` passes over all
  131,072 rows for each key, 0.47 ms a key, so a full ring and the most
  keys a rollup can hold is 3.8 s of answers, each inside the budget.
  A dense key is some 4.5 KB, so dense keys go 14 to an answer.

### The Activity view

`2` (or the top bar) opens it; `1` goes back to the Overview. It picks a
metric (from `/api/metrics`), a key (from `/api/keys`) and a window
(1 h, 6 h and 24 h from the 10 s tier; 7 d and 30 d from 1 min; 400 d
from 1 h), and draws the series on Canvas 2D: the bucket value as a
line over the baseline band, `mean ± k sd` of each bucket's hour of the
week with `k` the sensitivity slider's (2 by default), a segment out of
the band in the heat ramp, and the baseline mean and z in the hover. A
series with no baseline yet is drawn over its min..max spread instead.
The ratio-to-baseline toggle is not here yet. Below it, a small
multiple per key (the 24 most recently seen), each the last hour at
10 s as G1 over its band on one shared y-scale (or each its own, by the
`scale` button), sorted by |z| when a key has a baseline and by current
value otherwise (#171 V1, F6; the glyph layer, below), with the key in
the TUI's colour for it: the
eight hues of `src/tui_palette.c` picked by `src/ip_color.c`'s hash
(djb2; the spec says FNV-1a, but the TUI's own hash is the one that
keeps the colours equal). Colours come from `theme.css` tokens read back
at run time. Keys are shown with `textContent` and `fillText` only and
leave the page only as an `encodeURIComponent()`'d parameter of a
same-origin `fetch`.

#### Every key on one graph

Owner request and ruling of 2026-11-11 (`web/ui/allkeys.js`, its own
module; `/api/series/all`, above). The graph draws one key (the key
picker's) over its band, and the other keys are only the small
multiples below it, 24 of them, each in its own cell. The button in the
graph's label row, `keys: one`, turns to `keys: all` (kept per browser,
`act.allkeys`; one key is the default, as before), and the graph then
draws **every key of the metric** on one y-scale, one line a key, each
in the key's colour, with a legend.

- **Colour.** A key's colour is the TUI's hash of the key
  (`ipColorIndex()`, `src/ip_color.c`'s djb2 over its bytes, modulo
  eight): the same `--k-0..7` the key takes as an address, a device
  swatch or a drawer header, so the same key is the same colour on
  every load and in every view. Nothing but the key's bytes goes in:
  not its rank, not how many keys there are. `eth0` is `--k-6`,
  `wlan0mon` `--k-1` (pinned in `test_allkeys.c`).
- **More keys than colours.** Eight hues and up to 8,192 keys: colours
  repeat, and colour is never the only carrier (R10). The legend is
  ranked and numbered; the top five lines carry `rank key` at their
  right end, pushed apart so no two overlap; hovering or focusing a
  legend entry, or hovering a line, draws that line last in its colour
  and every other line in `--faint`. (`--rule` at first; the owner
  asked for the dimmed lines "a little more visible" on 2026-11-11.
  `--faint` is 2.84:1 on `--bg` and 2.72:1 on `--panel` in the dark
  theme, 3.03 and 3.39 in the light, where `--rule` is 1.65 and 1.58,
  1.34 and 1.51: `make web-contrast`. `--tui-dim`, 4.55:1, is a
  phosphor green and would read as a ninth key colour; the picked
  line's hue against a grey is what makes it dominate.)
- **The legend** lists every key drawn: rank, swatch, the key (through
  `keySpan()`, so an address is an address), and its latest value in
  the window (`-` when it has none). The order is stated beside it:
  latest value, largest first; equal values by key; a key with nothing
  in the window last. A click (or Enter or Space) on an entry **picks**
  it: its line alone in colour, the rest grey, until the same entry
  again, `show every key`, or Esc. A click on a line does the same.
  Up and Down move between entries. A pick also sets the key picker, so
  `keys: one` opens on that key, and moving the key picker picks that
  key here; the key picker keeps its 256, so a picked key it does not
  hold is said in the caption: `; 02:5e:ed:00:1f:fc is not one of the
  key picker's 256`. A device's entry carries a `device` button, the
  drawer. (A host has no detail view of its own to open by address, so
  an address's entry has none.) **At 8,192 keys** the legend is not
  8,192 buttons: 200 entries are in the page at once, `show 200 more`
  adds as many, and a **filter** box over it (`#ak-filter`, the page's
  own search input, not kept: it is a look at one metric's keys)
  narrows the entries to the keys whose text holds what is typed,
  ASCII case aside. An entry keeps the rank it has among every key,
  and the line beside the box says `Listed: 16 of 16 matching, of
  8192`. The filter narrows the list, not the graph.
- **"Every key" is every key** (owner ruling of 2026-11-11, "lift the
  cap"): the route walks them all, 128 to an answer, and the page
  draws what has arrived while the rest is read, the caption saying
  `loading 3968 of 8212 keys`, each answer handled in its own turn so
  the page stays responsive, the graph drawn again every 300 ms. What
  bounds it is said in the caption, never silent:
  - the graph holds **8,192 keys**, `--web-max-keys`' own maximum, so
    every key a rollup can hold is drawn; a store with more in the
    window reads `8192 of 8212 keys, the first by key (the graph holds
    8192)`;
  - a read that has run **60 s** stops: `3072 of 8192 keys (the read
    was stopped at 60 s)`;
  - a read the server ended: `(the read stopped)`.

  A read is dropped without a word when the metric, the scope, the
  window or the mode changes, and stops when the Activity view is no
  longer the one shown; coming back starts it afresh. A later read of
  the same window (a cell's time on, 60 s at most, and never sooner
  than ten times what the last read took) lands whole, so the graph
  does not flicker each minute.
- **What 8,192 lines are.** A line costs its length in pixels to
  draw, so 8,192 of them are 8,192 plot widths however few cells each
  has (measured: 88 ms). So the **256 largest** by the legend's order
  are lines, and the focus row whatever its rank; the rest are drawn as
  one thing, **the range they span in each cell** (least to most, one
  `--faint` rectangle a cell at 35 percent, under the lines), which is
  what a mass of lines shows. The caption says `lines for the 256
  largest, the other 7936 as their range a cell`. Pick or hover any
  key, from the legend or its filter, and its line is drawn.
- **One scale, stated.** Every line is on one y-scale, grown and never
  shrunk on a refresh (R11), its top in the caption: `shared scale,
  top 86.6k B/s`.
- **The band is one key's.** With every key drawn there is none, and
  the caption says `no band: it is one key's, pick a key for its`.
  With a key picked its band (mean ± k sd at the slider's k) is drawn
  under the lines and the caption says `band ±2.0 sd for eth0`, or
  `no band for eth0 yet` and `warming`.
- **Cells, tier, cost.** Each key is read as at most 480 cells, one for
  every two pixels of the plot; the caption names them: `fine in 3 min
  cells (mean)`, `(sum)` for a counter, whose values are then per cell
  and not per bucket. The cells the graph holds across all its keys
  are bounded (524,288; 131,072 for a presence metric, whose every
  cell can be a mark of its own), so past 1,092 keys each is read at
  fewer: 128 cells at 4,096 keys, 64 at 8,192 (the first answer says
  how many keys there are, and the walk starts again at the cells that
  fit). The tier is the finest whose buckets over the window number at
  most 10,080: fine for 1 h, 6 h and 24 h, minute for 7 d, hour for
  30 d and 400 d (the one-key graph reads 30 d at the minute tier; the
  caption says which; kept by owner ruling of 2026-11-11). A hover or
  a pick repaints from what was read. Measured in headless Chrome on
  the build host (software raster, 1200 px, device ratio 1), the
  graph's build and paint, with no focus and with a key picked:

  | keys | cells a key | marks | build | paint |
  |---|---|---|---|---|
  | 256 | 480 | 122,893 | 5 to 21 ms | 24 to 28 ms (16 ms on a quieter host, the first measurement) |
  | 1,024 | 480 | 123,373 | 12 to 23 ms | 23 to 27 ms |
  | 4,096 | 128 | 32,909 | 8 to 12 ms | 6 to 7 ms |
  | 8,192 | 64 | 16,461 | 7 to 8 ms | 4 to 5 ms |

  (ranking 8,192 rows: 2 to 3 ms). 256 and 1,024 keys are the same 256
  lines of 480 cells, the worst the graph draws; more keys are fewer
  cells a line. Without the fold, 8,192 lines of 16 cells painted in
  86 to 94 ms. The lines of one row are one path: through
  `glyph.paint()`, which strokes each segment, the 256-key list took
  116 ms, which is why the module has its own painter (`paintMarks()`,
  the same rules). **End to end**, in headless Chrome against a
  slothweb whose store held 8,192 synthetic devices (24 rows each in
  the hour): 8,192 of 8,212 keys read, ranked and drawn in 0.65 to
  0.71 s over 65 requests, the first 128 keys on the graph at 86 to
  142 ms; two tasks over 50 ms on the page's thread in that time (50
  and 58 ms, each a redraw of the legend and the graph).
- **Presence.** A presence metric has no line. Its keys are stacked
  strips on one canvas: a row a key, 8 px, in the legend's order (most
  cells present first; the legend's value is `n/480 cells`), each
  run of present cells in the key's colour, the rank beside the first
  row and every fifth, three time labels under the last row, the same
  hover and pick. Past 512 keys a row is 4 px, past 1,024 2 px, past
  4,096 1 px, so 8,192 keys are a canvas of 8,192 px (a browser makes
  no taller one reliably); measured, 8,192 rows of 16 cells (46,506
  marks) paint in 26 to 28 ms, 1,024 of 128 cells in 25 ms. Stacked and not disabled, because "who was here when,
  across every device" is what a presence metric is for.
- **Scopes and empty states.** Every scope the view has: the keys are
  the scope's (an interface by its radio), and a metric the scope does
  not hold collapses to its caption, `not in the Local scope` (R5); a
  metric with no key yet, `no ip seen yet`; keys with nothing in the
  window, the dash and `no data`; data covering under a tenth of the
  window, the window shrunk to it and `40 s of 1 h` (R4); a key with
  fewer than five points, dots (R6); a hole of more than two and a half
  cells, a break (R5), and a point no line reaches, a dot.

Keys are untrusted text here as everywhere: `textContent`, `fillText`
and `encodeURIComponent()` only; `test_allkeys.c` holds the module to
no `innerHTML` and no `setAttribute`.

## Baselines and anomalies (M3)

### Where the numbers come from

The engine reads the buckets that close, not the store. The store
thread hands it every minute and hour row as the row leaves the
rollup's queue (`web_tsdb_set_rows_hook`), after writing it, and a
store-thread step that crosses a minute boundary flushes first whatever
the 10 s flush cadence says, so the minute pass that runs at the first
step of minute `m+1` has every row the boundary closed for minute `m`.
Rows are merged per `(tier, metric, key, t)`: an eviction and a return
can close one bucket in two parts. The previous slice instead asked the
store for "the newest minute row in the last two minutes" and "the hour
row that just closed"; whether either had been flushed yet depended on
the flush phase, so a bucket was scored twice or not at all, and the
hour feed ran for about one hour in ten.

Without SQLite the rollup still queues its minute and hour rows (and
not its 10 s rows) for the engine, so the baselines and every rule but
A9 run in memory, and are lost at exit.

**Observed time.** A minute is observed when the socket was connected
and a record had arrived within 60 s at every store-thread step in it,
and slothweb was running at its start. A minute that was not is not
scored at all: neither a hit nor a quiet minute for any episode. An
hour is fed to the baselines only when at least 45 of its minutes were
observed; otherwise it is skipped and counted (`hours_unobserved`): a
counter that did not see half its hour would read as a quiet hour.

**A slothweb restart** (owner ruling 2026-11-11) no longer costs an
hour by itself. Coverage used to live in memory and count only minutes
after the process started, so every restart lost the clock hour it
started in and the hour it stopped in. Now each run writes the minutes
it observed to the store ([slothweb.db v11](#restarts-inside-an-hour-slothwebdb-v11))
at every minute boundary, after that minute's rows are in the minute
tier, and an hour that began before this run is judged on every run's
minutes together: 45 or more and it is fed (`hours_merged`), from the
minute tier's rows of the hour, both runs' parts. A run killed without
a clean exit loses only the minute in progress (at most 60 s and one
store-thread step); every completed minute's bits are already written.
An hour the previous run observed but never passed (it stopped before
the hour ended, and this run started after) is passed at this run's
first step, if it is within the last day. Without a store, the old rule
stands.

### The baseline (§5.3)

- **Cells** are the local hour of the week, `((tm_wday + 6) % 7) * 24 +
  tm_hour` from `localtime_r()`, Monday 00:00 first, so a routine keeps
  its cells across a daylight-saving change (a UTC index moved every
  edge hour of a routine by one cell twice a year). A closed hour starts
  on a UTC hour and is filed under the local hour its start falls in,
  and a minute is scored against the cell its own UTC hour bucket was
  filed under, not the cell of the minute: in a zone with a half-hour
  offset the two differ for half of every hour, and 14:10 IST scored
  against cell 14 was compared with the bucket 14:30-15:30, so a device
  present every day from 13:30 to 14:30 fired A3 on a regular routine.
  `/api/baseline` reports `now_cell` and the current `utc_offset_s` so
  the page maps a time to the same cell (by its hour bucket's start).
- **Scale.** A gauge's mean, a presence metric's max (0 or 1), and a
  counter's count **per minute**, so a minute bucket and an hour bucket
  of a counter compare directly.
- **An hour with no row** is 0 for a counter and for presence (a counter
  that counted nothing, a device that was not there), fed to every
  counter and presence entry the hour did not feed. For a gauge it is
  not a sample: sloth not reporting a host, a channel or an interface is
  not a measurement of zero. Only an entry that exists is zero-fed; an
  entry is made by a key's first real hour row.
- **Two spreads.** A cell is fed once an hour, so its variance is how
  much the hour's value moves from week to week. A1 scores a minute,
  and the minutes of one hour spread far more than their hour's mean
  moves: a host whose connection count is 2 to 8 every minute of every
  hour has hour means within a few tenths of 5, and with the cell's
  variance alone (in practice the floor below) a minute of 8 was z = 3
  and the quiet stream fired A1 all week. So a cell also learns `wvar`,
  the variance of the hour's minute values about their own mean: the
  engine sums the minute rows it scores per series per hour (a counter's
  minutes without a row count 0) and hands the hour's within-variance
  over when it feeds the hour, an EWMA on the same half-life. A minute
  is scored with `sd = sqrt(var + wvar)`; for a counter the within term
  is at least its mean, the Poisson variance of a count, so a counter
  whose minutes were all alike, or a cell with no `wvar` yet, does not
  call one more event out of band. An hour bucket is compared with
  `sqrt(var)` alone, which is what the page's band uses for buckets of
  an hour or more.
- **The sd floor.** A score divides by at least `max(10% of |mean|, one
  unit)`, one unit being one count a minute, one connection, one AP, or
  1 KiB/s for a byte rate. A cell whose samples were all equal has
  variance 0; with the previous `sqrt(var + 1e-9)` one more AP on a
  channel scored z = 31,623.
- **The MAD ratio.** For an A1 candidate on a counter, the last 28 hour
  rows of the same local hour of the week are read from the hour tier
  (28 primary-key lookups; a DST change moves the target hour by one),
  and the candidate stands only if Iglewicz and Hoaglin's modified z is
  at least 3.5. The rows are hour values, so their MAD is the week to
  week spread; the minute's own spread is added as for z: `|x - median|
  / sqrt((MAD / 0.6745)^2 + within)`, floored like the sd (with no
  within term this is `0.6745 |x - median| / MAD`). Without it the ratio
  was as blind to the minutes' spread as z, and confirmed whatever z
  flagged. With fewer than 6 rows there is no claim and z alone decides. An
  hour with no row is not in the sample: the file cannot tell an hour
  that counted nothing from one slothweb did not see. Computed once per
  series per hour, at most 32 series a minute (past that z alone
  decides, counted as `mad_skipped`). A memory-only build has no hour
  tier and skips it.
- **The table** holds `web_baseline_cap_for(--web-max-keys)` entries
  (4,930 at the default) but allocates them 256 at a time as they are
  made; a cell is 16 bytes (float mean, variance and within-hour
  variance, two 16-bit counts), an entry about 2.8 KB. A free list and an LRU list ordered by the last
  hour with a real row make every insert, touch and eviction O(1); an
  entry idle longer than the hour tier keeps (400 days) is aged out.

### The rules (§6)

| Rule | Kind | What it measures |
|---|---|---|
| A1 | `rate` | a keyed, non-presence metric's minute value (a counter's count, a gauge's mean) with `|z| >= 3` against its cell, in 3 consecutive observed minutes; a counter with a baseline and no row this minute is scored as 0, a gauge with no row breaks the streak; a counter must also pass the MAD ratio |
| A2 | `new` | a MAC whose own `first_seen` (the `probe_client`, `pnl_client` or `assoc` row's, from sloth) is within 24 h and of which slothweb holds nothing older (no `dev.present` or `dev.frames` baseline entry first fed before then, no minute or hour row of either in the store before then), reported once per MAC across restarts while slothweb remembers it (a full reported set forgets its oldest, `reported_evicted`); more than 8 such MACs in one minute, or more than 16 in a rolling hour, are one episode keyed `""`; randomised MACs are left out (each rotation is new by construction; A5 is about them) |
| A3 | `hours` | a MAC present this minute in a cell whose presence mean is below 0.1 over 4 or more weeks |
| A5 | `ident` | a randomised MAC (the locally administered bit, which is how sloth sets `mac_random`) whose DHCP or mDNS hostname is also the name of another MAC |
| A6 | `ident` | an IP whose current DHCP hostname, mDNS host and NBNS name (two or more of them) disagree in normal form |
| A7 | `fanout` | the largest `host.conns` sample of each 10-minute window against the host's own p95 of that value; fires above both 2 x p95 and p95 + 5, after 144 windows |
| A8 | `dns` | a client with 20 or more queries in 10 min and more than 30% of them answered NXDOMAIN |
| A9 | `proto` | a host's `flow.{ssh,rdp,smb,snmp,mqtt}` minute row with no row of that series before it in the minute or hour tier, a row the rollup released late included |
| A10 | `sensor` | the socket connected and nothing received for 60 s, counted from the later of the last record and the connection |

Where this departs from the spec's body, and why:

- **A2** reads `first_seen` from the stream, not `sloth.db` (M3 reads no
  `sloth.db`; M4 does). Only stations sloth heard over the air carry
  one (`arp` and `device` do not). sloth sets it to now whenever it
  makes a client entry (`src/capture/probe.c`): at its own restart, and
  when it evicts and re-learns a station. So `first_seen` alone reported
  a device with weeks of history as new after sloth restarted; A2 now
  also asks slothweb's own memory: a `dev.present` or `dev.frames`
  baseline entry first fed before the 24 h window, or a minute or hour
  row of either in the store before it, and the MAC is not new (the
  answer is remembered for the window; at most 256 store lookups a
  minute, the rest wait, `a2_deferred`). `sloth.db`'s
  `devices.first_seen` is the durable answer, in M4. The reported set
  is keyed by `first_seen`, holds `--web-max-keys` MACs and outlives a
  restart. Full, it forgets the MAC with the oldest `first_seen`
  (`reported_evicted`), which moves to the set of MACs not to report
  one by one; a MAC both sets have let go may be reported a second
  time. That is the accepted cost, and it is bounded: a duplicate "new
  device" is better than a hidden one, and the re-reports are at most
  the evictions. A MAC is judged new
  once: the scan puts it in one set or the other as it counts it, so no
  MAC is offered twice. It is marked reported only once its episode
  exists, so one whose episode the table cannot take is counted
  (`dropped`) and judged afresh the next minute: a full table delays a
  report, never loses it. A burst (more than 8 new MACs
  in one minute, which is what spoofed probe requests look like) or a
  trickle (more than 16 in a rolling hour: 8 a minute is never a burst)
  is one episode keyed `""`, held while the hour is over its limit, and
  its MACs are not put in the reported set, so a flood can neither take
  the episode table from the other rules nor churn the reported set.
  Its evidence counts the MACs judged new in that minute (a burst) or
  that hour (a trickle), exactly, and names at most two, whole. The
  stated cost of the fold: a real device that arrives inside a spoofed
  trickle or burst is one of the MACs folded into the `""` episode and
  is not reported on its own. The rolling hour is kept in memory and
  starts at 0 after a restart.
- **A4** (vendor unknown) arrived with M4 (#162); see
  [Devices and lookup](#devices-and-lookup-m4).
- **A5 and A6** use the names the stream carries: `device.hostname`
  (sloth's copy of the DHCP lease hostname), `dhcp_lease`, `mdns_service`
  and `nbns_name` (suffixes 0x00 and 0x20 only: the others name a group).
  A name reached through an IP counts for a MAC only while that IP's own
  ARP binding is that MAC, so a lease handed to another device does not
  name both. Names compare as ASCII lower case, first label only, and an
  NBNS name against the first 15 bytes of the other.
- **A7.** The spec asks for distinct peers in 10 minutes. The stream has
  no per-host peer list: `top_host` is a remote IP the sensor host talks
  to, and its `conn_count` is the number of distinct flows between the
  two in one poll (`src/top_hosts.c`). A7 measures that. And "above its
  own p95" alone is true of one window in twenty by construction; the
  margin is what keeps a quiet stream quiet.
- **A8.** sloth's `dns` record names its sender only, so an NXDOMAIN
  answer's `src` is the resolver, and `dns.nxdomain` is keyed by it. The
  previous slice divided a host's NXDOMAIN answers *sent* by its queries
  and could not fire for a client. A8 now joins an answer to the client
  that asked the same qname (held as a 64-bit hash, never the text) in
  the 10 s before, once.
- **A9** "first ever" is the store's: any earlier row of that series in
  the minute (30 d) or hour (400 d) tier. The previous slice used "no
  baseline entry", which every restart and every LRU eviction made true
  again. A host new to the stream whose first activity is the protocol
  has its first minute row held by the rollup until its key is
  established, and released after that minute's pass: that row is
  checked as it arrives (at its own `t`; it is already written, and the
  lookup asks for rows strictly before it). Skipped as late, it was in
  the store by the next minute and A9 never fired for exactly the host
  it is for. A memory-only build has no history to ask and skips A9.

### Episodes

An episode is one row per (rule, metric, key) that advances: building
until its rule has held for 3 consecutive evaluated buckets (A1) or 1
(the rest), then open, then closed after 2 evaluated buckets in which it
did not hold. One bucket advances an episode once, however often it is
scored. A building episode that misses a bucket is dropped. A closed
episode is kept for 24 h; if its rule holds again a new episode starts
and has to earn its streak afresh (the previous slice deleted a closed
episode a minute after it closed, and a recurrence in that minute
reopened it at once with its old streak). The table holds 512: a new
episode takes a free slot; else its own rule's oldest closed episode;
else, while its rule holds fewer than a ninth of the table, the oldest
closed episode of a rule holding more than that. Never another rule's
closed episode otherwise: with one oldest-closed pool for every rule, a
flood of one kind pushed every other rule's closed episodes out well
inside their 24 h. An open or building one is never pushed out, and
the newcomer is dropped and counted.

The rules run without the episode lock, which is taken only to apply a
minute's candidates, so a request never waits on a rule's SQLite.

### What outlives a restart

Schema v3 adds five tables; the store thread writes them, and they are
read back before any thread starts:

| Table | Holds | Written |
|---|---|---|
| `baseline (id, metric, key, last_active, last_fed, first_fed)` | one row per entry | after each hour's feed, with its cells |
| `baseline_cell (cell, id, mean, var, n, wvar, wn)` | the cells fed, keyed `(cell, id)` so that the hourly write, the same cell of every entry, is a run of adjacent rows | after each hour's feed |
| `episode (id, kind, metric, key, state, score, peak, evidence, ...)` | open and closed episodes; `kind` holds the rule (`A1`..`A10`) | each minute an episode changes |
| `fanout (key, windows, hist)` | A7's per-host histogram, 16 weights as text | at each 10-minute window |
| `reported (kind, key, t)` | the MACs A2 has reported, `t` the MAC's `first_seen`, for 24 h from it | as they are reported |
| `anom_cover (hour, mask, done)` (v11) | which minutes of each hour a run observed, every run's bits ORed; `done` once a run passed the hour; two days kept | at each minute boundary and at a clean exit; `done` at the hour pass |

At start the most recently active entries up to the cap are loaded and
any other row is deleted, so the file never holds a row the table does
not; the deletes go a few rows (and their cells) to a transaction, so a
restore after `--web-max-keys` shrank keeps the WAL small. Every value
read back is checked as if it came off the wire: a mean or variance a
float cannot hold is refused (cast, it would be an infinity, printed as
a bare `inf`), an episode's scores are clamped to 0..100 and an episode
with an id of 0 or a time outside 1970..3000 is not restored.

Each hour the evicted entries' rows are deleted first and the changed
cells written after, so a pair evicted and fed again in the same hour
finds its old row gone (written first, its insert hit `UNIQUE (metric,
key)` and rolled its whole batch back). The delete queue grows rather
than forget an id (it used to drop all but the newest 4,096, and a
forgotten row made its pair's insert fail every hour until restart). A
new entry whose pair still has a row anyway takes it over, cells
cleared (`store_baseline_rows_reused`). A batch the store refuses is
marked dirty again and written the hour after; the batches after it
still go. Episodes older than 24 h are dropped. A memory-only build keeps all
of it in memory, says so at start and on `/api/health`
(`"persisted":false`), and loses it at exit.

### /api/anomalies and /api/baseline

`/api/anomalies?since=S&kind=K` answers

```json
{"now":1792684660,"since":1792681060,"anomalies":[
  {"id":2,"rule":"A1","kind":"rate","metric":"host.conns","key":"10.0.0.5",
   "score":100,"peak":100,"evidence":"host.conns[10.0.0.5] z=195.0 value=200 baseline=5±1",
   "first_seen":1792684620,"last_seen":1792684800,"tid":"add57a348de83bda4",
   "state":"open","open":true}],
 "more":false,"omitted":0}
```

(`tid` is the id the episode's triage and links are filed under, the
same for every episode of that rule, metric and key:
[Anomaly triage and links](#anomaly-triage-and-links).)

open episodes first, highest score first, then those closed at or after
`since` (default an hour ago, never earlier than the 24 h kept), newest
first; `kind` is one of `rate`, `new`, `hours`, `ident`, `fanout`,
`dns`, `proto`, `sensor`. The list stops before an episode that might
not fit (the worst case is 159 bytes of evidence and a 47-byte key, each
byte escaped six-fold) with `"more":true` and `omitted`, so it always
fits; the previous slice answered `503` past 276 episodes. Evidence is
slothweb's own sentence; names in it came off the stream, cut on a
code-point boundary and escaped like every other string.

`/api/baseline?metric=M&key=K` answers the 168 cells of one series as
`[mean, sd, n, sd_hour]` (`sd` a minute's spread, the one A1 scores
with; `sd_hour` an hour bucket's, week to week alone; both floored as a
score floors them), Monday 00:00 local
first, with `now_cell`, `utc_offset_s`, `warm_n` and `scale`
(`per_minute`, `mean` or `share_of_weeks`); `"cells":null` for a pair
never fed.

### The Anomalies view and the Overview

`4` (or the top bar) opens the Anomalies view (§8.7): one card per
episode, open first, each with its kind's glyph (`~` rate, `+` new, `@`
hours, `=` ident, `<` fanout, `?` dns, `^` proto, `!` sensor) and word,
the key in its hash colour, a score bar in the heat ramp, the evidence,
the last hour of the metric that fired (from `/api/series`), and first
and last seen; chips filter by kind, and a window picks how far back
closed episodes are listed. It re-reads `/api/anomalies` on each
`anomaly` event, at most once a second. A card whose key is a MAC opens
that device's drawer (M4); a host drawer waits for its milestone.

The Overview (§8.4) gains a throughput tile (the `iface.rx_rate` of the
interface sloth reported most recently) with its 24 h sparkline over the
baseline band, an open-anomalies tile, "now vs normal" (the same series,
larger), the hour-of-week heatmap of that series (7 x 24, the heat ramp
by mean, warming cells plain grey (no hatch, #171 V1; since the ruling
of 2026-11-11 every cell is drawn and a warming cell with a sample
carries a `--tui-dim` bar for its value so far, [below](#the-glyph-layer)),
the current cell outlined in
`--signal`), and the five highest-scoring open episodes. Since #171
V1 every tile has its own series and band (the glyph layer, below):
the hour-of-week grid's warming cells are plain grey, counted in its
caption, with no hatch.

The **sensitivity** slider (1.5 to 4 sd, kept in this browser only)
changes the band drawn and hides `rate` episodes whose |z| is under it.
It changes nothing stored, and the server fires A1 at 3 sd whatever it
says, so a setting under 3 shows what 3 shows.

## Devices and lookup (M4)

### sloth.db, read-only

`--sloth-db PATH` is sloth's file, never slothweb's (`web_slothdb.h`).
Every use opens its own connection and closes it after: a request, or
the minute pass that asks it for A2. So no read snapshot outlives a
request and none can pin sloth's WAL past one statement (each runs in
its own implicit read transaction, ended by its reset), and a sloth
that starts, stops or checkpoints between two requests is simply seen
by the next one.

- **Open.** `lstat()` first: a symlink, a directory or a device is
  refused, and a path with nothing there is `"db":"missing"` (sloth has
  not made it yet), retried on every request. Then
  `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW`, never `READWRITE` or
  `CREATE` (a test asserts the flags passed). The lessons of the
  store's identify hold here, harder, since this file is never ours: a
  read-only connection never checkpoints, so sloth's unflushed WAL is
  never written into the file; a WAL-mode file with no `-wal`, or with a
  `-wal` and no `-shm` (no sloth running, nothing checkpointing), is
  opened as an immutable URI (`mode=ro&immutable=1`), because an
  ordinary read-only open makes an empty `-wal` and a 32 KB `-shm`
  beside it; such a read sees the file as of sloth's last checkpoint,
  and `/api/health` says `"db_mode":"immutable"`. With both present it
  is a WAL reader (`"wal"`) opened `mode=ro&readonly_shm=1`: sloth's
  `-shm` is opened read-only and never initialised by slothweb. With
  sloth running that is an ordinary reader on sloth's index; with
  sloth crashed (both files left, no process holding the `-shm`)
  SQLite reads the WAL into a private index instead of running WAL
  recovery on the shared one, which would make a sloth starting at
  that moment fail its first statement with `SQLITE_BUSY_RECOVERY`.
  Every open goes through a VFS that never creates a named file, so a
  sloth closing cleanly between the choice of open and the first read
  (its `-wal` and `-shm` gone) fails that read (`"db":"error"`) rather
  than leaving an empty `-wal` beside sloth.db; the next request reads
  it immutable. A rollback-journal file is read with a shared lock per
  statement (`"rollback"`); one with a hot journal (sloth crashed
  mid-write) cannot be read until sloth rolls it back, and is
  `"db":"error"` ("needs recovery by sloth"), never "not a sloth.db",
  which is kept for a file whose shape is wrong.
- **sloth's side.** `db_open()` sets a 1 s busy timeout
  (`DB_BUSY_MS`), so a lock another reader holds at sloth's start is
  waited out rather than failing the open, which stops sloth.
- **Each connection** gets `SQLITE_DBCONFIG_DEFENSIVE`,
  `PRAGMA query_only`, a 100 ms busy timeout and a progress handler that
  interrupts any statement past the caller's budget (250 ms for a
  request, 1500 ms for `/api/history/overview`, 200 ms for a minute
  pass), so a slow read costs slothweb a
  `503` `sloth_db_timeout`, never sloth a stall
  (`db_timeouts` on `/api/health`).
- **Identify.** sloth's `meta` is `(key, value)`; a `schema_version`
  of 1 to 12 is read (`"db_supported":[1,12]`). The upper bound is held
  to sloth's `DB_SCHEMA_VERSION` by a test, so a schema bump cannot
  ship with slothweb still refusing the new files. A newer one is refused
  with "written by a newer sloth (schema v13; this slothweb reads
  v1..v12)": this build does not know its columns. An older one is read
  by probing its columns with `PRAGMA table_info`: a column the version
  lacks (`device_class`, `camera_*` before v6, `dhcp_vci` before v7,
  `alerts.reopens` before v8) reads as `0` or `NULL`, and a table that is missing reads as no rows,
  its query conditions as false. A file with no `devices` table of
  sloth's shape, a `slothweb.db` (its `meta` is `(name, value)`) or
  anything else is refused.
- **The column allow-list.** Every statement names its columns, and an
  authorizer on every connection denies a read of any `(table,
  column)` not on `web_sdb_allow[]`, any function but `like`,
  `coalesce`, `substr`, `instr`, `min`, `max`, `count` and slothweb's
  four, any pragma but `table_info`, and every statement that is not a
  `SELECT` (an `ATTACH`, a recursive CTE, a write). A statement naming
  another column fails to prepare. The list holds `devices` (the
  §8.6 columns), `pnl_clients`, `pnl_ssids`, `probe_clients` and
  `assocs` (first seen and the drawer's lists), `arp`, `dhcp_leases`,
  `mdns_services`, `nbns_names`, `alerts` (key, type, severity,
  title, match IP, count, times: not `detail`, which can carry a user
  name) and `meta`. So no credential-bearing column
  (`cleartext_creds.username`, `rogue_radius.last_identity`,
  `mqtt_flows.last_username`, anything in `eapol_events`) can be served
  whatever a later statement says. `alerts.key` carries a remote
  string too (a cleartext credential's key names its username), so it
  is predicate-only: denied in a result column and a `WHERE` alike to
  every statement but the device query and the drawer's alerts read,
  whose result columns are constant and which match it against a
  canonical MAC. The test seed keys an alert as sloth keys a
  credential and holds its username out of every result column and
  every body. `test_slothdb.c` reads the guardrail
  word list out of `tests/test_db.c` itself, plus credential words
  (`user`, `identity`, `pass`, `token`, `key_material`, ...), and fails
  if a listed column matches one or is not a column of sloth's live
  schema.

### The query language (§9.1)

`web_query.h`. Terms are separated by spaces and combine with AND; `-`
negates one; `"double quotes"` hold a space. `vendor:` (the OUI
table's name or sloth's own label, substring), `mac:` (prefix, `-` read
as `:`), `ip:` (prefix, the device's or an ARP binding's), `ssid:`
(last SSID or a PNL SSID), `name:` (sloth's hostname, DHCP, mDNS host
or instance, NBNS, a PTR answer seen), `random:yes|no` (the locally
administered bit), `seen:` and `first:` (`<24h` less than 24 h ago,
`>7d` more than, `>2026-09-29` at or after that day UTC, `<...` before
it, `<=...` on or before it, a bare date that day; units `s m h d w`), `risk:` (0..3 with
`= < > <= >=`, the level slothweb scores from `risk_signals`, below), `z:` (`|z|` now, below), `src:` (`arp dhcp mdns beacon
probe sta camera`, sloth's `DEV_SRC_*` bits), `has:` (`pnl alert
anomaly name ip ssid`) and `anomaly:` (a kind, keyed by the MAC). A
word before `:` that is no prefix (`b8:27:eb`) is free text, which
matches the MAC, IP, hostname, either vendor and the last SSID.

Bounded before anything is read: at most 256 bytes, 12 terms, 64 bytes
a term; text is well-formed UTF-8 with no C0, DEL or C1 byte; every
other value is checked against its prefix's form; a refusal is a `400`
naming the reason (`bad_mac`, `bad_time`, `term_too_long`, ...),
never the value. It compiles to **one** statement whose text is
assembled only from constant fragments: every value is a bound
parameter, a LIKE pattern with `\`, `%` and `_` escaped (`ESCAPE '\'`),
and the statement's shape is the same whatever the values. The vendor
of the OUI table, `|z|` now, the anomaly count and the passive PTR name
are SQL functions slothweb registers on the connection, reading its
own memory. `tests/fuzz/fuzz_web_query.c` fuzzes the parser and the
compiler (`make fuzz`) and aborts if a statement names a parameter it
does not bind or holds a byte the constant fragments do not. Results
are capped (`limit` 1..200, default 100; `offset` 0..100,000), sorted
by `last` seen (default), `first` seen, `mac`, `risk`, `vendor`, `ip`,
`ssid` (the last SSID), `signal` or `sources`, each a constant column of
the statement's own list; `dir=asc` or `dir=desc` sets that column's
direction, an empty value last either way, then the MAC (without it,
each sort keeps its own order, and the answer has no `dir` member);
anything else is a `400` `bad_sort` or `bad_dir` that never echoes it.
SQLite compares text by its bytes, so the order is locale-free. `ip`
orders by `web_ipkey(d.ip)`, a function slothweb registers on its
sloth.db connections (IPv4 before IPv6, each by its bytes, an address
`inet_pton()` cannot read last with the empty ones), so a page of rows
is the start of the same numeric order the page shows
([Tables](#tables-sort-and-resize)); `/api/flows` orders `src` and
`dst` the same way.

### The vendor table (§9.2)

`web_oui.h`, generated by `web/tools/oui_gen.c` (Build and run, above).
An entry is one assignment: a 24-bit MA-L, 28-bit MA-M or 36-bit MA-S
(or IAB) prefix, the table sorted by `prefix36 << 2 | class`, so each
class is one exact binary search, most specific first (MA-M and MA-S
blocks sit inside MA-L assignments registered to the IEEE itself). A
lookup always reports the locally administered bit (a randomised or
software MAC) and the group bit, and for a hit its block, registry,
bits and whether the IEEE lists it as "Private". Names are trimmed,
cleaned of control bytes and invalid UTF-8, cut to 63 bytes on a
code-point boundary, and emitted into the generated C as string
literals with every byte but `[A-Za-z0-9 .,-]` an octal escape, so no
registry name can end a literal, open a comment or splice a line.

### Passive names (§9.3, without its active half)

The drawer and Lookup list every name already seen, with its source
and time: `dhcp_leases`, `mdns_services` (host and instance) and
`nbns_names` (suffixes 0x00 and 0x20) from sloth.db; the same three
from the stream (`web_ident.h`, current for 15 minutes); and the
passive PTR cache. A row's name is the best of these, with its glyph:
`D` DHCP, `m` mDNS, `N` NBNS, `h` sloth's own `devices.hostname` (as
sloth graded it), `p` a PTR answer seen on the wire.

**The passive PTR cache** (`web_ptr.h`) records a `dns` record with
`qtype` `PTR`, `is_resp` 1, a reverse name that decodes to an address
(`in-addr.arpa`, or the 32 nibbles of `ip6.arpa`) and an `answer` that
is a host name; NXDOMAIN, an address and anything with a byte outside
`[A-Za-z0-9._-]` are refused (counted). It holds 4,096 addresses, the
least recently seen out first (counted), and is kept in `slothweb.db`
(schema v4, `passive_ptr`, below). Sloth decodes a PTR response's
RDATA into the `dns` record's `answer` (#165; `src/dns_log.c`, RFC
1035 §3.3.12); before that it filled `answer` only from the first A
or AAAA record, so every PTR answer arrived empty, counted as
`passive_ptr.empty`, and the cache never filled. slothweb does not
parse packets itself — it only reads what sloth's `answer` field now
carries.

### A4, and A2 made durable

- **A4** `vendor`: a MAC present this minute (`dev.present`), globally
  administered and unicast, whose OUI is in none of the full table's
  MA-L, MA-M or MA-S blocks. Only with a table built from the IEEE MA-L
  registry: sloth's 117-entry fallback misses most vendors by design,
  so with it A4 is off and `/api/health` gives the reason
  (`"a4":"the vendor table is not the IEEE registry ..."`, or `"on"`).
  The episode is held while the MAC stays present and closes two
  observed minutes after it leaves, as A3's do. More than eight such
  MACs in one minute are one episode keyed `""`: spoofed addresses with
  made-up OUIs would otherwise take the table. The stated cost: a real
  unknown-vendor device inside such a burst is folded into it.
- **A2** with `--sloth-db`: sloth.db's earliest `first_seen` for the
  MAC (`devices`, `probe_clients`, `pnl_clients`, `assocs`), which sloth
  keeps as `MIN()` across its own restarts (`src/db.c`), is asked first.
  Older than 24 h, the MAC is not new whatever the stream's
  `first_seen` says (`a2_sdb_old`); within it, the M3 judgement stands
  (slothweb's own baselines and store still have a say). sloth.db also
  names candidates the stream cannot: a MAC whose `devices.first_seen`
  is within the window, a wired device learnt from ARP among them (no
  stream record carries a first_seen for it), at most 64 a minute
  (`a2_sdb_new`). A MAC sloth.db does not hold, or no sloth.db, is the
  M3 stream path unchanged. The lookups share A2's 256 a minute, on one
  connection for the pass.

`|z|` now (the `z` column and `z:` term) is the largest `|z|` A1 scored
for any metric of the device key in its latest minute, kept for 3
minutes; a device with no warm baseline has none (`null`).

### slothweb.db v4

`v3 -> v4` adds `passive_ptr (ip, name, first_seen, last_seen)` and its
index on `last_seen`, in one additive `BEGIN IMMEDIATE` step like the
others (a name already taken fails the step and leaves the file at v3).
Each upsert keeps the first sight of the current name; the table is
kept to the 4,096 most recently seen in the same transaction and what
the bound drops is counted (`passive_ptr.db_evictions`). It counts
towards `--web-max-mb` and is measured with the analysis state; at
about 120 bytes a row it is at most about 0.5 MB, inside the estimate's
slack, and is not added to the estimate.

### The channel mix: slothweb.db v5

`v4 -> v5` adds `chmix (tier, channel, t, tx, kind, frames)`, keyed
`(tier, channel, t, tx, kind)` (a MAC that beacons and probes is two
transmitters, as in memory), and its index on `(tier, t)`, in one additive
`BEGIN IMMEDIATE` step like the others (a name already taken fails the
step and leaves the file at v4). A row is one named transmitter of a
closed minute (`tier` 1) or hour (`tier` 2) bucket of a channel (`tx` a
canonical MAC, `kind` 1 an AP, 2 a client) or the rest (`tx` `''`,
`kind` 0). Nothing in it is text a peer chose: no SSID is stored, the
page's names come from sloth.db or the stream at read time. A bucket
closed early (a shutdown) and finished later is merged. It is bounded
three ways: minute rows are kept three days (the grid reads the minute
tier only for a window of at most three days) and hour rows 400, at
every compaction (`chmix.store_dropped_expired`); the table holds at
most 524,288 rows, the oldest minute rows and then the oldest hour rows
dropped after a write that passes that (`chmix.store_dropped_cap`); and
under `--web-max-mb` its rows are the second class the ceiling drops,
after the fine tier and before any keyed minute or hour row. Both cuts
delete whole buckets, every row of each `(channel, t)` the oldest rows
fall in, never part of one, which would be drawn as the whole cell with
its shares wrong. A row is
about 60 bytes with its index, so the cap is about 32 MB.

The BLE Devices view's class mix ([BLE](#ble)) shares the table without
a step (2026-11-02): `channel` a class slug (`b:phone` .. `b:unk`, which
no channel key can be), `tx` an advertiser's address, `kind` 3, `frames`
its advertising reports; since 2026-11-03 also anonymous advertising,
`channel` `b:unk`, `tx` `00:00:00:00:00:00` and `kind` 4, one row a
bucket (a b801ab7 slothweb skips kind 4 on read, so on a downgrade those
reports are missing from the minute and hour cells, never drawn as an
address). The values are of kinds the columns already
hold, so a v7 file is read as it is and an older slothweb never draws a
`b:` row (its reader keeps canonical channel keys and kinds 1 and 2).
Each view reads its own namespace (`b:*` or everything else) under its
own read cap, and the retention, the row cap and the ceiling treat both
alike, at most seven classes x six rows a bucket for BLE.

### The BLE tables: slothweb.db v7

`v6 -> v7` adds `ble_device` and `ble_alert` with an index each on
their last-seen column, in one additive `BEGIN IMMEDIATE` step like the
others (a name already taken fails the step and leaves the file at
v6; `web/tests/test_store.c` builds a v6 file as the triage slice
writes it, a triage row and a TACDB platform in it, and holds both the
migration, which leaves those rows as they were, and that failure; a
v5 file is taken through v6 and v7 in turn). sloth.db keeps no BLE table, so these are
slothweb's own record of what the stream said ([BLE](#ble)).
`ble_device` is one advertiser as one sensor heard it, keyed
`(addr, addr_type, iface)` exactly as sloth keys its table: every
column but one is a number or one of sloth's words; `name` is the
advertiser's local name in its display form (`web/src/web_ssid.h`, as
`passive_ptr.name` holds a peer-chosen name), flagged by `name_np`,
never a key; the distance estimate is kept as decimetres, band, trend
and P_tx source, -1 for none; the drawer's presence strip as
`pres_bucket` and its 96 bits in `pres_lo` / `pres_hi`; no raw AD byte exists on the stream and
none is stored. `ble_alert` is one finding by the FNV-1a hash of its
key (the key itself, which in other alert families can carry remote
text, is never stored), its per-kind integers in eight generic columns
`n0..n7` (a flood's id, subtype, window, distinct, total, fresh count,
rate in tenths and its cap and window flags; a `hid_oui` finding's
address type, HID bits, appearance and its address as a 48-bit
number), its one word of the kind (`mfr/ADV_IND`, `Hak5`, the watch
category) in `label` and a flood's citation line (sloth's own text,
`src/ble_flood.c`) in `detail`, so a seeded finding renders as the live
one did and a resolve on its live key updates the same row. The store thread upserts every row dirtied
since the last flush each 10 s (a row already there takes the new
values; `pdu_mask` and `hid` are OR-ed, the earlier `first_seen` kept),
and at start the newest 1024 rows and the findings standing or changed
in the last day seed the in-memory tables, so a restart keeps the
history. Bounded: rows last seen before `--web-retain-days` go at every
compaction (`ble_store.dropped_expired`), and the tables hold at most
8,192 (eight times the in-memory table, whose seed reads the newest
1,024) and 4,096 rows, the oldest by last seen dropped after a write
that passes that, an advertiser no flag marks before a HID or
watchlisted one (`ble_store.dropped_cap`). A row is at most about 330
bytes with its index and a name at its cut, so the cap is under 3 MB.
They are inside `--web-max-mb` as well: an address flood mints a row a
random address, so the ceiling takes the unflagged advertisers right
after the channel mix and before any keyed history, and the flagged
ones and the findings after the keyed history and before the global
series; a flood trims its own rows, not the Wi-Fi and host series. A
write that fails (the transaction rolled back, `write_errors` counted)
leaves its batch dirty for the next flush (`ble.redirtied`). The BLE
Devices view's class mix is not in these tables: it is `chmix` rows of
kind 3 under `b:` keys ([The channel mix](#the-channel-mix-slothwebdb-v5)),
and a row's class is derived from its fields when asked, never stored.

### Anomaly triage and links: slothweb.db v9

`v8 -> v9` (owner request 2026-11-11; sequenced after the fleet's v8,
which reached main first) adds `anom_subject` and
`relation` with the links' two indexes (`relation_pair`, unique on both
ends; `relation_to`), in one additive `BEGIN IMMEDIATE` step like the
others: plain `CREATE`, so a name already taken fails the step and
leaves the file at v8. `web/tests/test_store.c` builds a v8 file as the
fleet slice writes it (a pulled peer in `peer_sites` and two of its
sightings in `peer_sightings`, two triage rows, a TACDB platform and a
BLE advertiser in it) and holds both the migration, which leaves the
fleet's tables and rows, every other row and the `triage` table's
columns as they were, and that failure (a v8 file already holding the
name `relation_to`: still v8, none of the step's three other objects
left behind; seen red with the migration's `ROLLBACK` made `COMMIT`).
A v7 file goes v7, v8, v9 (and on to v10) in one open
(`test_v7_file_reaches_v10_in_one_open`). The `triage` table is not touched: an
anomaly's decisions are rows in it beside the alerts', under a subject
of their own (`a` and sixteen hex digits, type `-1`), so the cap, the
folding and the history are one mechanism
([Anomaly triage and links](#anomaly-triage-and-links)).

| Table | Columns | Holds |
|---|---|---|
| `anom_subject` | `subject` (PK), `rule`, `metric`, `key`, `ts` | what an anomaly's id names: the rule's name (`A3`), the metric's catalogue name (or `''`) and the canonical key, exactly what `episode` already stores of it. Written once, when the anomaly is first triaged or linked; at most 8,192 (`507 anomaly_subjects_full` past it). The engine forgets an episode after a day; this is why a note still says what it was written on, and how a hash collision is caught |
| `relation` | `id` (PK), `a_kind`, `a_id`, `a_label`, `b_kind`, `b_id`, `b_label`, `note`, `who`, `peer`, `ts` | one link the operator made, from `a` to `b`: kind 0 an alert (id its triage subject, `d<rowid>` of the finding's first sloth.db row or the stream handle), 1 an anomaly (its id), 2 a device (a canonical MAC), 3 a BLE advertiser (`addr/type`; a kind is a number, so adding it was no schema step); each label slothweb's own words (`PORT_SCAN 203.0.113.50`, `A7 fanout 203.0.113.50`), kept so a link whose end is gone still says what it pointed at; `note` (240 bytes) and `who` (32) operator text from the validated POST body, `peer` the connection's address. At most 8,192 rows and 32 naming one finding. A candidate is never a row |

No column can hold a credential and nothing in either is a stream
string: an alert's label is its type's name and the address its
descriptor names, never its key's text (`test_notes.c` links a
cleartext-credential alert and scans the file for the username).

### Notes: slothweb.db v10

`v9 -> v10` (owner request 2026-11-11: "an openclaw agent will need to
... add notes to anomalies, devices, and other observations") adds the
`note` table with its index `note_subject` and one column, `via`, to
`relation`, in one `BEGIN IMMEDIATE` step. It is the one step that is
not `CREATE` alone: `ALTER TABLE relation ADD COLUMN via INTEGER NOT
NULL DEFAULT 0` is additive in the 2026-10-21 rule's own words
("columns or tables with defaults"), rewrites no stored value, and
rolls back with the rest; `test_schema_text_guardrail` holds the chain
to exactly that one `ALTER`. Every link made before the step reads
`via` 0, the page's, which is what it was. `web/tests/test_store.c`
builds a v9 file (the fleet's peer and sightings, three triage rows of
which one is an anomaly's, the anomaly's `anom_subject` row, two
links) and holds the migration, which leaves every one of those rows
and columns as written, and the failure (a v9 file already holding the
name `note_subject`: still v9, no `note` table, `relation` with the
eleven columns it had; seen red with the migration's `ROLLBACK` made
`COMMIT`, and the default seen red as `DEFAULT 3`). A v7 file goes v7,
v8, v9, v10 (and on to v11) in one open (`test_v7_file_reaches_v11_in_one_open`). The
`triage` table is not touched: its `via` column already takes the new
value.

| Table | Columns | Holds |
|---|---|---|
| `note` | `id` (PK), `kind`, `subject`, `text`, `who`, `peer`, `via`, `retracts`, `folded`, `ts` | one plain note or one retraction ([Notes on devices and the rest](#notes-on-devices-and-the-rest)): `kind` 0 a device, 1 a BLE advertiser, 2 an SSID, 3 a GNSS satellite, 4 an aircraft, 5 an APRS station; `subject` the id the routes name it by (a canonical MAC, `addr/type`, the base64url of an SSID's octets and never its display form, `gnssid.prn`, an ICAO address, a callsign); `text` (240 bytes) and `who` (32) from the validated POST body, `peer` the connection's address; `via` 0 the page, 3 an agent; `retracts` 0 on a note, the note's `id` on the row that takes it back; `folded` the retracted rows of the subject folded away. At most 20,000 rows and 64 a subject |
| `relation` | gains `via` | how the link was written: 0 the page, 3 an agent through `slothweb-mcp` |

`via` is one set of numbers in `triage`, `relation` and `note`:
0 manual, 1 recommended, 2 import (triage only), 3 agent. No request
can set it: a body naming `via` is refused as an unknown member, and 3
is written only for a request the gate authenticated as the agent's
([[slothweb-mcp]]).


### Restarts inside an hour: slothweb.db v11

`v10 -> v11` (owner ruling 2026-11-11: schedule the restart-loss fix as
its own slice) adds one table in one `BEGIN IMMEDIATE` step:

| Table | Columns | Holds |
|---|---|---|
| `anom_cover` | `hour` (PK, an hour start), `mask` (bit i the hour's minute i), `done` | which minutes of the hour slothweb observed, across its runs: each run ORs its own bits in (`INSERT ... ON CONFLICT DO UPDATE SET mask = mask \| excluded.mask`), never puts its bits in place of another's; `done` is 1 once a run passed the hour. Rows older than two days are deleted at each hour pass |

What it is for and what each metric kind gets
([Where the numbers come from](#where-the-numbers-come-from), "Observed time"): the bits of minute m are
written by the store thread at the step that crosses into m+1, after
that step has flushed the rollup's queue, so a persisted bit always
names a minute whose rows are in the minute tier; if a store write
failed while an hour was open, no more of that hour's bits are written,
and it may be judged short but is never fed from rows that are not
there. An hour that began before the running process is fed only when
the runs together observed 45 minutes, and then from the minute tier's
rows of the hour (every run's, with whatever a killed run had flushed),
in place of this run's own hour row, which holds only its part: a
presence metric's value is the max of those rows (present if present
in either part), a counter's the sum of their sums (both parts; its
minutes with no row count 0, as in any hour), a gauge's the sum of
sums over the sum of counts; the within-hour spread is rebuilt from
the same rows, a value a minute. A pair with a baseline and no row in
either part is fed 0 (presence and counters only, as in any fed hour);
an hour not fed is never zero-filled. A late hour row from this run for
such an hour is dropped, as before, since it is a part. No metric kind
is left out: the minute tier carries sum, count, min and max for all
three. What is still lost: a killed run's minute in progress (its rows
and its bit), a minute row the rollup's queue dropped when full
(`queue_dropped`), and any minute rows the `--web-max-mb` ceiling has
already trimmed (it trims the oldest first; an hour is merged within
the hour after it).

Cost, measured in the test build (`-O0`, this host): rebuilding an hour
of 2,050 series, 60 minute rows each, took 199.9 ms on the store
thread; one coverage write 0.012 ms. Both run on the store thread
(web_tsdb's step hook) over the writer connection, never on a request,
and the store is in WAL mode, so a request's read on the reader
connection is not held by either.

`web/tests/test_store.c` builds a v10 file (the v9 file, two notes and
a retraction, an agent's link, episodes and minute rows) and holds the
migration, which leaves every one of those rows as written and the new
table's own statements working (`test_v10_file_is_migrated`), and the
failure (a v10 file already holding the name `anom_cover`: still v10,
its rows as they were; `test_v10_failed_step_leaves_file_unchanged`).
A v7 file goes v7 to v11 in one open
(`test_v7_file_reaches_v11_in_one_open`). `web/tests/test_anomaly.c`'s
`test_restart_*` and `test_killed_run_loses_only_the_minute_in_progress`
hold the engine's side.

### /api/devices, /api/device/{mac}, /api/lookup

```
GET /api/devices?q=vendor%3Aapple%20random%3Ayes%20seen%3A%3C24h
{"now":1792627200,"q":"vendor:apple random:yes seen:<24h","sort":"last",
 "limit":100,"offset":0,"db_schema":7,"vendor_table":"ieee",
 "presence_from":1792541400,"presence_cell_s":600,"utc_offset_s":0,
 "rows":[{"mac":"da:a1:19:00:00:01","random":true,"vendor":"Apple",
   "vendor_src":"sloth","ip":"10.0.1.11","name":null,"name_src":null,
   "ssid":"HomeNet","signal":-48,"sources":48,"is_ap":false,"risk":1,
   "risk_signals":1,"first_seen":1791763200,"last_seen":1792623600,
   "z":null,"anomalies":0,"presence":"000000000000000000000000000000000000"}],
 "count":1,"more":false,"next_offset":null}
```

`risk` is scored from `risk_signals` on every read, in every scope, and
the level sloth stored in `devices.risk_level` is not read at all
(#191). The bits: 1 random MAC, 2 unknown vendor, 4 no hostname, 8
probe-only, 16 a cleartext credential, 32 an alert, 64 self (one of the
sensor host's own interfaces, or a device on the operator's roster; the
drawer writes `(self)` beside the level). Bits 1, 2, 4 and 8 are one
anonymity family worth one point in total, and nothing beside bit 64;
bits 16 and 32 are three points each; 1 is MED, 3 HIGH, 5 CRIT. A phone
walking past (random MAC, no hostname, probe-only) is MED, where the
three bits used to sum to HIGH, and a database written before the
change reads the new levels without being rewritten: its rows for
devices never seen again would otherwise stay HIGH for good.

A row is the §8.6 columns that have a source: the MAC, randomised or
not, the vendor (`vendor_src` `oui` from the table, `sloth` sloth's own
label), IP, the best passive name and its glyph, last SSID, signal,
sloth's `sources` bits, risk level and signals, first and last seen,
`|z|` now, the device's anomaly episodes (open and kept), and the 24 h
presence strip: 144 cells of 10 minutes ending with the cell `now` is
in, as 36 hex digits, cell 0 the oldest and the high bit of the first
digit, set when a minute row of `dev.present` in slothweb.db, or a 10 s
bucket still in memory, had the device present. A page stops early,
with `"more":true` and `next_offset`, when the next row might not fit
its 64 KB (a row is at most 2,600 bytes with every text member at its
cut length escaped six-fold, and `WEB_RF_JSON_MAX`, 560, for its
`"rf"`; `test_devices.c` builds that case); nothing is ever a `503`
for size.

**`"rf"`, the signal meter's data (#171 V2, `web/src/web_rf.h`).** Each `/api/devices`
and `/api/wifi/aps` row, and `/api/device/{mac}` and `/api/lookup` (for
the MAC looked up, or the IP's) at the top level, carry the emitter's
signal over the last hour:

```
"rf":{"metric":"rf.rssi.sta","from":1792623660,"cell_s":60,
      "cells":[null,...,-71,-64,-60,null],"n":3,
      "whisker":[-60,-60],"whisker_src":"samples",
      "band":"room","trend":"approaching","est_src":"probe_client",
      "radio":"2.4 GHz"}
```

`cells` are 60 minute means of the `rf.rssi.*` fine buckets in memory
(the ring and the open bucket, `web_rollup_trail()`), integer dBm,
oldest first, the last the minute `now` is in, `null` where none fell,
`[]` when none at all. The series are §7's `ap.rssi` and `sta.rssi`
under the names they already had: `rf.rssi.bssid` (a beacon's
`signal_dbm`, and an assoc's, which is the AP's frames) for a row
sloth calls an AP and every `/api/wifi/aps` row, `rf.rssi.sta` (a
probe_client's) otherwise, and the other when the first has nothing in
the hour. The spec's other two `sta.rssi` sources are the AP's signal,
not the station's (assoc's `signal_dbm` is set from frames the AP
sent; `wifi_sta`'s is the managed card's link), so no new metric and
no slothweb.db step. `whisker` is the range at the last value: the
beacon's own `rssi_min_60s`..`rssi_max_60s` for a BSSID whose latest
beacon is in the minute of the last value (`"beacon"`; an assoc, the
AP's frames too, can be the later sample), else the last cell's sample
range, which spans the same minute (`"samples"`). `band` and `trend`
are **sloth's** distance estimate (`src/rf_distance.c`, the
`est_dist_band` and `est_dist_trend` of the latest beacon or
probe_client record, held in the FRRS ledger), passed on only as one
of sloth's own words, so the page bolds an approaching emitter by
sloth's trend and names sloth's band: G2 never fits a nearness of its
own that could disagree with the TUI's distance cell. `radio` (2026-11-11)
is the band that latest record was heard on, `"2.4 GHz"`, `"5 GHz"` or
`"6 GHz"` in `ap_band_label()`'s words from its `channel` and, for a
beacon, its `channel_source`, or `null` when the ledger has no record or
the channel is in no band: [the S-meter](#the-s-meter-2026-11-11) reads
the signal on that band's scale, and `null` is "band unknown", never a
guess. A probe_client record has no `channel_source`, so a 6 GHz channel
number in one reads as the 2.4 or 5 GHz number it shares. The page no
longer draws `whisker` (the meter's ticks are the hour's least and
greatest of `cells`); it stays in the member. Under Local,
which shows nothing of the monitor radio, `"rf":null`.

`/api/device/{mac}` (the MAC percent-decoded, case and `-` folded)
answers the drawer: the OUI card, the vendor research section
(`"vendor_research"`: the `web/data/vendors/` entry for the OUI's
holder as fields, summary and sources, or `{"found":false}`; see
Vendor research, above), the allow-listed record and its v6/v7
detail (sloth's hostname, device class, camera vendor and model, DHCP
vendor class), what the stream knows (IP binding, first seen), every
passive name, PNL SSIDs (24), associations (12), ARP addresses (8),
alerts that name it (12, by MAC in their key or its IP as `match_ip`),
each with a `_more` flag when cut, the presence strip, the 168
hour-of-week cells of `dev.present` from the baseline (`[share of
weeks present, n]`, Monday 00:00 local first, with `now_cell` and
`warm_n`; `null` before any feed) and its anomaly episodes (8, open
first). `/api/lookup?q=` takes a MAC or an IP: for a MAC the OUI card
(found, vendor, block, bits, registry, private, local, multicast, the
table and whether it is the full one), the same vendor research section
and its ARP addresses; for an IP
its ARP MACs; for both every passive name and sloth.db's record (an
IP's through its ARP MAC, or the stream's binding), and for that MAC
`"mac"`, the presence strip and `"rf"` (F20). `"active":false`
always: there is no active lookup.

### The Devices view, the drawer, Lookup

`3` (or the top bar) opens Devices: the search box (§9.1; `/` focuses
it from anywhere; the query is sent 300 ms after typing stops, or on
Enter), the sort, and the table: the first 512 rows of the answer,
paged in 200 at a time, drawn virtualised (only the rows in view
exist, recycled as it scrolls, one fixed row height). Each row: the
MAC with its hash colour on the swatch only and a muted `~` prefix when
randomised, vendor, IP, name with its glyph, SSID, signal, source
glyphs (`A`RP `D`HCP `P`robe `B`eacon `S`TA, `.` absent), risk, first
and last seen, `z`, anomaly count and the 144-cell strip on Canvas 2D
(present in the sun's phase at the sensor, or `--tui-normal` with no
sensor position; `--bg` absent; *G5 by the sun*, below). A risk level above 0 is a left
border in its severity colour; text stays `--ink` and `--muted`. A row
click opens the drawer, as does an Anomalies card keyed by a MAC; Esc
closes it. The drawer lists everything `/api/device/{mac}` gives, the
strip, the week heatmap (the Overview's heatmap drawing, by share of
weeks) and the episodes as cards. The vendor research is the drawer's
last block (owner request 2026-11-11, "move the vendor research to the
bottom on the wifi detail view"): its own container, `#dr-vendor`,
after the FRRS record and the sensor's positions, so a device's own
record, lists, presence, signal and anomalies come before what is
documented about its OUI's holder. The drawer is one view whatever
opened it (a WiFi client or access point, a Devices row, an anomaly
card), so it moved for all of them; the Lookup card keeps the section
under its OUI card. `9` opens Lookup: one input, a MAC or
an IP, and the card, which ends with the drawer's strip and G2 (F20).
Slice V2 (#171) puts G2 in the signal column, G6 in risk and anom, the
`new` mark before the swatch and the first-seen `◆` on the strip; see
The glyph layer, below. Every value is set with `textContent`; the page
gained no HTML or code sink (`test_routes.c` scans for them) and makes
no request but its own server's (the CSP's hashes are recomputed by
the build).

### How old the database is (#168)

The stream is current to the second; `sloth.db` is as current as the
file `--sloth-db` names. Read in place beside a running sloth (the
shipped unit, `"db_mode":"wal"`) that is a second or so, since sloth
commits every `--db-interval-secs`. Read from a copy, it is as old as
the copy, and nothing else on the page would say so: the Overview and
the Activity view keep moving while a Devices table frozen at the copy
looks live.

So every DB-backed view says how old its data is. Devices, the WiFi
view's access-point table, Flows, History and Lookup each carry a line
`database as of HH:MM` (local time; `YYYY-MM-DD HH:MM` when that is not
today, so a snapshot days old never reads as this afternoon even with
the stream down, when "stale" is not said), from `/api/health`'s
`sloth_db_mtime`: the file's mtime, or, for a WAL reader, the newer of
the file's and its `-wal`'s (sloth's commits sit in the `-wal` until a
checkpoint; an immutable or rollback read is the main file alone). It
is read at load, each time one of those views is shown, and every 30 s
while one is. When the data is older than `sloth_db_stale_after_s`
(10 minutes) **and** the stream is current (connected, a record in the
last 60 s), the line turns to the warning colour and says so: `database
as of 21:06 - stale: 1h52m old while the live stream is current; these
rows are as old as it is`. The server decides (`sloth_db_stale`), so
the rule is tested once, in `web/tests/test_devices.c`; with the stream
down as well, the socket state is the message and the line only gives
the time.

slothweb opens `--sloth-db` afresh for every request, so a copy
replaced by `rename(2)` is read from the next request on, without a
restart. A deployment that reads a copy (because slothweb cannot read
sloth's own file) has to refresh it, and with a checkpoint-safe copy:
`cp` of a WAL database can tear. SQLite's online backup, into a
temporary name in the same directory, then a rename over the old copy:

```sh
sqlite3 "file:/var/lib/sloth/sloth.db?mode=ro" ".backup /srv/slothweb/sloth-snap.db.tmp" &&
    mv /srv/slothweb/sloth-snap.db.tmp /srv/slothweb/sloth-snap.db
```

run as an account that can read sloth's file, every 15 to 30 minutes
from a systemd timer or cron. The shipped unit needs none of this: it
runs as `sloth` and reads the live file read-only.

## WiFi, History and the SQL box (M5)

#163. Spec §8.8, §8.10, §7's `/api/query` and the rulings header's SQL
box ruling (behind `--web-allow-sql`, default off, `sqlite3_set_authorizer`
read-only, 5 s, 10,000 rows). Every sloth.db read goes through the M4
reader (`web_slothdb.h`): the same opener, the same allow-list for the
views' statements, no second opener. Acceptance (§12): the
`sqlite-schema.md` recipes run from the SQL box and match the `sqlite3`
output; a write statement is refused.

### The WiFi view (§8.8)

```
GET /api/wifi/channels?metric=ap_count&from=1792623600&to=1792627200&cols=90
{"metric":"wifi.ap_count","kind":"gauge","unit":"APs","tier":"fine","step":10,
 "from":1792623600,"to":1792627200,"cols":90,"col_s":40,"total_keys":5,
 "channels":[{"key":"1","band":"2.4","cells":[3,null,...]},...,
             {"key":"6g37","band":"6","cells":[...],
              "scale":{"kind":"absolute","max":3}}],"shown":5,"more":false,
 "scale_s":86400}
```

- **The waterfall** is slothweb.db's `wifi.ap_count` (a gauge: a cell is
  the mean of its buckets) or `wifi.ctrl_total` (a counter: their sum),
  the toggle on the view. Rows are channels, 2.4 GHz, then 5, then 6
  (`6gN` keys, since 5 and 6 GHz share numbers), then any channel sloth
  could not place (`"band":"?"`: a number outside 1-14 and 32-177 with
  no HE 6 GHz element, which sloth labels `?`), each band by channel
  number, with a rule drawn between bands; at most 40 rows, then
  `"more":true`. Columns are `cols` (1..96) cells of `col_s`, a
  whole number of the tier's step. The tier is the finest that covers
  the range: 10 s for up to 6 h inside the last 24 h, 1 min for up to
  3 d inside `--web-retain-days`, 1 h beyond; the keys are the
  rollup's and the store's for that tier and range, so a channel the
  rollup evicted or a restart forgot keeps its history. Without a store
  a range reaching past 24 h is a `400` `tier_unavailable`. Drawn on
  Canvas 2D as G3's horizon strips by default (slice V3, the Design
  section's "Slice V3"), or as the stacked grid below.
- **G3's scale** (slice V3, F8). Each row carries `"scale"`, and the
  answer `"scale_s"`, the span an absolute scale was read over
  (2,592,000 with a store, 86,400 without):

  ```
  {"key":"6","band":"2.4","cells":[...],"scale":{"kind":"absolute","max":9}}
  {"key":"6","band":"2.4","cells":[...],"scale":{"kind":"z"},
   "z":[null,...,6.32,...],"z_warming":12}
  ```

  `absolute`'s `max` is the channel's own largest over the last 30 days
  at the hour tier (the fine ring's day without a store), widened to
  every cell of the answer so no drawn value is above it: a gauge's
  largest sample (each bucket's max); a counter's as a count per
  minute: with a store its busiest hour's mean (an hour bucket's sum
  over 60), without one its busiest minute (the fine buckets of one
  minute summed). Never the busiest cell in view (F8). `z` is
  `ctrl_total`'s when the channel's hour-of-week baseline has an entry:
  each cell's count per minute (its sum × 60 / `col_s`) scored against
  the cell its UTC hour bucket was filed under, with the minute spread
  as A1 scores it, or the hour's (`sd_hour`) for a cell of an hour or
  more; `null` for an empty cell and for a warming one, which
  `z_warming` counts. `ap_count` is always absolute. Rows are every
  channel the store holds an hour row for in the last 30 days besides
  the range's own keys, so a quiet channel keeps its row with every
  cell `null`.
- **The channel mix** (owner request 2026-10-26) is who made a cell
  busy. With `mix=1` (and no `metric`), `/api/wifi/channels` answers on
  the same grid and tiers with, per channel and cell, the five
  transmitters that sent the most frames and one count for the rest:

  ```
  GET /api/wifi/channels?mix=1&from=1792623600&to=1792627200&cols=90
  {"metric":"wifi.mix","kind":"counter","unit":"frames","tier":"fine",
   "step":10,"from":1792623600,"to":1792627200,"cols":90,"col_s":40,
   "top":5,"source":"memory","ring_from":1792623610,"db":"open",
   "total_keys":7,
   "tx":[{"id":"02:de:00:00:00:a7","kind":"ap","vendor":null,
          "ssid":"demo-\\xff\\xfe-legacy","ssid_k":6,"ssid_np":true,
          "ssid_src":"sloth.db"},
         {"id":"0a:de:00:00:02:05","kind":"client","vendor":null},...],
   "channels":[{"key":"11","band":"2.4","total":41260,
                "cells":[null,...,[308,11,0,176,3,121],...]},...],
   "shown":7,"more":false,"folded":false,"read_cut":false}
  ```

  A cell is `null` or `[total, other, i, frames, i, frames, ...]`, `i`
  an index into `tx`, the busiest first; `total` is everything heard in
  the cell, so `other` plus the named frames. The samples are the
  frame-count deltas of the stream records that carry a channel and one
  transmitter: `beacon` (the AP by its bssid; on `6gN` when its
  `channel_source` says the HE 6 GHz element gave the channel) and
  `probe_client` (the station by its mac). A `probe_client` record has
  no band and only the channel of the station's latest probe, so its
  whole delta since the last snapshot is credited to that channel, read
  in the 2.4 or 5 GHz band its number is in (a station probing on
  6 GHz lands on the 2.4 or 5 GHz channel of that number). `assoc` is
  not in the mix: its `frame_count` counts both ends together, the AP's
  (re)association responses and EAPOL M1/M3 with the station's M2/M4.
  sloth emits no per-transmitter record for data frames, and control
  frames carry no transmitter address, so neither is in the mix
  (`web_chmix.h`). Each channel's open bucket in each tier tracks 32
  transmitters by name; a further one's frames go to the rest and are
  counted against it in a table of 32 candidates, and once a candidate
  has sent more in the bucket than the quietest tracked one the two
  change places with their own frames, so a heavy transmitter first
  heard late in an hour still enters on all it sent, every named count
  is exact, and a scan of one-frame MACs cannot push the busy ones out. Closed 10 s buckets live in a ring of 49,152
  rows (about 4.7 MB; `ring_from` says how far back it reaches, and a
  cell before it is drawn from the heat grid, dimmed); closed minute and
  hour buckets go to slothweb.db's `chmix` (v5, below). An answer names
  at most 160 transmitters in 20 KB, the busiest over the range first;
  a cell's five are its busiest among those, the rest's frames in its
  `other` (`"folded":true`), and the rows stop at a whole row
  (`"more":true`) before the answer would pass its buffer. An AP's name
  is sloth.db's `beacon_aps.ssid`, the octets sloth stored, or, where
  sloth.db has no row, the SSID the stream's last beacon carried, whole
  (`ssid_src`; a slot holds the stream's longest form, 32 octets each
  U+FFFD); `vendor` is the vendor table's. `mix` other than `1`
  is a `400` `bad_mix`, with `metric` a `400` `mix_takes_no_metric`.
- **The grid** draws each cell as a stacked bar of those five, each
  band's height its share of the cell's frames, the busiest at the
  bottom and the rest grey on top: an AP in its SSID's hash colour (the
  server's `ssid_k`), a client in its MAC's, as the TUI colours them,
  on CP_MON_ROW's ground (`--mon-bg`), since the monitor radio heard all
  of it. A 6 px strip at each row's left is the row's busyness in the
  metric the toggle shows, in the heat ramp against the busiest row.
  Pointing at a cell, tapping it or moving to it with the arrow keys
  (the grid takes the focus) lists its five under the grid with name,
  frames and share; each is a button that opens the device drawer (a
  client) or brings its row of the AP table into view (an AP); Enter
  moves into the list.
- **SSIDs are never sent raw.** An SSID is octets an AP chose, not
  text: sloth keeps the high ones as they came (`src/dot11_ie.c`), so
  sloth.db can hold one that is not UTF-8, and the stream carries U+FFFD
  where one was. Every SSID slothweb sends (the AP table and its
  history, the channel mix, the drawer's last SSID, PNL SSIDs and
  associations, the Devices row, History's new APs and probe clients,
  the ticker, and any SQL box column whose name holds `ssid` or
  `title`) is in a display form (`web_ssid.h`): printable UTF-8 as it
  is, every octet of anything else as `\xNN` (C0, DEL, C1, U+FFFD,
  Unicode's whole Default_Ignorable_Code_Point set (the bidi and
  zero-width controls, Hangul fillers, variation selectors, tags), the
  blanks other than U+0020 that draw as a space (U+00A0, U+2000..U+200A
  and the like), private use, noncharacters, and any octet that starts
  no well-formed sequence), a backslash doubled. sloth writes an SSID
  into an alert's title and detail as it came, so those go out in the
  same form, on `/api/live`'s alerts, on the ticker and on
  `/api/history/alerts`. Beside it go `<name>_k`,
  the colour hashed over the octets themselves (`src/ip_color.c`'s djb2
  mod 8, what `tui_ssid_addstr()` colours by), and `<name>_np`, true when
  anything was escaped, which the page shows as a "non-printable"
  marker. For an SSID from sloth.db the colour is the TUI's exactly
  (`test_tui_colors.c`); one from the stream has lost the octets U+FFFD
  replaced, and its colour is that of what the stream carried.
- **The AP table** is sloth.db's `beacon_aps` (100 rows, `sort=` last,
  ssids, karma, bssid, ssid, channel, signal, enc, mfp, downgrade or
  first, `dir=asc|desc` as `/api/devices` takes it, `limit`, `offset`,
  `"more"`): SSID, channel,
  signal, sloth's `enc` and `akm` text, the AKM bits decoded to the
  802.11 suite names (`src/rsn_ie.c`'s `rsn_akm_name()`, copied and
  held to it by `test_parity.c`; a bit it does not name reads
  `AKM-n`), MFP as off / capable / required, the downgrade flags by
  name (`include/sloth.h` `WPA_DG_*`: SAE/PSK transition, OWE
  transition, MFP optional, WPA1 alongside RSN), WPS, vendor, PHY, the
  SSID history from `beacon_ap_ssids` (8, newest first, its count, and
  `ssids_more`) and the KARMA score from `karma_candidates` where the
  AP is one. An SSID count above 1 is drawn in `--sev-warn` with its
  history under the row. A page stops early, with `"more"`, before a row
  that might not fit (a row is at most 7,400 bytes; `test_wifi.c`
  builds the worst case, about 6,200).
- **The deauth timeline** is `wifi.deauth` per bssid on the same grid,
  the 40 bssids with the most frames in the range first, each with the
  `DEAUTH_FLOOD` episodes sloth.db's `alerts` holds against it in the
  range (`[first_seen, last_seen, sev, count]`, 8, oldest first), drawn
  as the chains panel's G7 rug since slice V3, the episodes underlined
  in `--sev-crit`. The episode is matched by
  `alerts.key` (`deauth:<victim>@<bssid>`, `rule_deauth_flood()`),
  which is predicate-only: the key is in the WHERE, bound to the
  canonical BSSID, and never in a result column or a body.
- **Probe clients** is `/api/series` and `/api/baseline` for
  `wifi.probe_clients`, drawn as every time chart is, over its M3 band.

### An SSID's detail

Owner request 2026-11-11: "on the wifi tab we should be able to select
any ssid and get a detail view just like we do for a client"
(`web/src/web_ssidview.h`, `web/ui/ssid.js`).

**Every SSID the page writes is selectable.** `ssidSpan()` is the one
function a name is written through, and it hands its span to
`SlothSsid.link()`: a dotted rule under the name, `tabIndex` 0, a click
or Enter or Space (the page's one keydown handler) opens the detail. On
the WiFi view that is the AP table's SSID and each name of its SSID
history, the `(hidden)` word of a BSSID that beacons no name, the
card's scan, and the channel mix's list, where the row is already a
button that brings the AP into view, so the detail is a small `ssid`
button after it. The device drawer's last SSID, PNL SSIDs and
associations are the same span, so a client's probed networks open
from there; so are the Devices table's SSID column and History's
lists. The WiFi view's clients table has no SSID column, and the
chains, the deauth rug and the channel strips draw BSSIDs and
channels, not names.

**How a name travels.** An SSID is 0 to 32 octets, not text, and a
route parameter is 1 to 63 bytes of printable ASCII. The page has each
name in its display form (printable UTF-8 as it is, any other octet as
`\xNN`, a backslash doubled), which reads back to one octet string
only; `octets()` reads it back and `param()` spells the octets as
base64url without padding (RFC 4648 section 5), 1 to 43 characters, or
`-` for none. The server takes exactly one spelling of an octet string
(`web_ssid_param()`: leftover bits must be zero, no padding, no NUL, at
most 32 octets), binds it as a parameter and compares it with `=`. It
is never a LIKE pattern and never part of a statement's text, so
`Home%` and `Home_et` are their own networks and not `HomeNet`'s
(`test_ssidview.c`). A name the stream carried with lost octets
(U+FFFD, three octets where one was) can be more than 32 octets: the
drawer then says it is not an SSID sloth.db can hold, and asks nothing.

```
GET /api/wifi/ssid?ssid=SG9tZU5ldA
{"ssid":"HomeNet","ssid_k":3,"ssid_np":false,"hidden":false,"octets":7,
 "now":1792627200,"db":"open","db_schema":13,"designated":true,
 "designated_count":2,"first_seen":1791849600,"last_seen":1792627140,
 "bssids":[{"bssid":"0a:00:00:00:00:01","current":true,"designated":true,"vendor":"Acme",
   "channel":6,"enc":"WPA3","akm":"PSK,SAE","akm_names":["PSK","SAE"],
   "mfp_word":"capable","signal":-50,"first_seen":1791849600,
   "last_seen":1792627140,"karma":null,
   "twins":[{"real":"0a:00:00:00:00:01","twin":"0a:00:00:00:00:02",
     "attributed":true,"tainted":true,"confidence":80,
     "first_seen":1792626300,"last_seen":1792626300}]}],
 "bssids_total":2,"bssids_more":false,
 "assocs":[{"mac":"00:03:93:00:00:03","random":false,"vendor":"Apple",
   "bssid":"0a:00:00:00:00:01","channel":6,"signal":-52,
   "first_seen":1792454400,"last_seen":1792626900}],"assocs_total":2,
 "probers":[{"mac":"da:a1:19:00:00:01","random":true,"vendor":null,
   "first_seen":1791763200,"last_seen":1792623600}],"probers_total":1,
 "alerts":[{"title":"Deauth flood","type":7,"sev":2,"count":40,
   "incidents":1,"id":"d12","first_seen":1792623600,
   "last_seen":1792626600}],"alerts_more":false,"alerts_read":true,
 "alerts_reached":null,"alerts_days":30,
 "presence":"000000000000000000000000000000000002",
 "presence_from":1792541400,"presence_bssids":2}
```

- **`bssids`**: sloth.db's `beacon_aps` rows whose SSID is exactly this
  one (`current`), the 48 last seen, then the BSSIDs `beacon_ap_ssids`
  says beaconed it once and beacon another name now (`current` false,
  their times those of this name). Each with sloth's vendor, channel
  (`beacon_aps.channel` carries no band, so a 6 GHz channel is its
  number alone, as in the AP table), `enc`, `akm` and the AKM bits by
  name, MFP as a word, the last signal, its KARMA score from
  `karma_candidates`, and the twin pairs the stream's `twin_episode`
  made with it since slothweb started (`web_chain.h`; sloth.db keeps
  none the page may read). The hidden SSID is the rows whose SSID is
  NULL or empty.
- **`assocs`**: `assocs` rows that carried this SSID or are to one of
  its current BSSIDs, the 24 newest with the whole count. **`probers`**:
  `pnl_ssids` rows of this name, the same; none for the hidden SSID,
  since a wildcard probe names no network.
- **`presence`**: G5's 144 cells of 10 minutes: a cell is set when any
  current BSSID was present in it (`dev.present`, as a Devices row's
  strip).
- **`alerts`**: the 12 newest findings whose key names a current BSSID
  or the SSID itself (the component `src/alert_key.c` `akey_remote()`
  writes for an SSID: its sanitised first 32 octets and the FNV-1a of
  all of it), by the alert page's opaque id. The key is in the WHERE
  and the GROUP BY only, never in the answer. `instr()` over every
  recent key once a BSSID is the cost and no index helps it, so the
  walk is bounded by work, not by a clock: at most 320,000 / (8 +
  BSSIDs) alert rows, the newest of the last 30 days, found through
  `idx_alerts_last_seen` before the walk begins; `alerts_reached` says
  how far back that was, `null` for the whole window.
- **`designated`** is `true` or `false` once sloth's `ownership`
  record (JSONL 1.2.0) has arrived, with `designated_count` the number
  of SSIDs sloth designates (`--my-ssid`), and `null` for both before
  it: the page then says `not known: sloth has not reported its
  designated networks`, never a guess. Each BSSID carries its own
  `designated` (`--my-bssid`), marked `yours` in the drawer. The record
  is kept in memory by `web/src/web_own.c`, the newest replacing the
  last whole, a malformed one refused; SSIDs compare octet for octet,
  as sloth's own `ownership_is_my_ssid()` does.

**The drawer** (`#sdrawer`) is built as the device drawer is: the name
with its non-printable marker, a key and value list (octets, first and
last seen, the designated line), the strip with its caption, then the
lists, each with its count (`24 of 340` when cut) and R5's one line
when empty: access points (the new mark on one first seen in the last
24 h, the BSSID a button that opens the device drawer), clients
associated, clients probing, twin and karma findings in sloth's words,
alerts (each row opens the alert's page). Opening a device or an alert
from it closes it; Esc closes it; a scope change asks again. Under
Local the route answers `out_of_scope` and the drawer says so: all of
it is the monitor radio's. No vendor research is drawn here: an SSID
has no one vendor. The detail is not in the address, as the device
drawer is not.

### The History view (§8.10)

- **The strip** (`/api/history/overview`) is the last 30 days in 180
  cells (`from`, `to`, `cols` 1..360; at most 400 days): devices first
  seen and alert episodes begun per cell, and the survey sessions in
  the range as white ticks and as chips under it. Dragging on it sets
  the range; a click on a tick, or its chip, opens that session's
  "new since".
  It counts every row begun in the range, not a page of them, so it has
  its own budget, 1500 ms (`WEB_SDB_OVERVIEW_MS`; every other route
  keeps 250 ms): on the owner's 254 MB snapshot (867,748 alert
  episodes) the old single `GROUP BY` took 253 ms, past 250, and the
  page said "sloth.db was too slow to answer". Each table is now counted
  the cheapest way the file allows: with sloth's `idx_<t>_first_seen`
  one count per cell over the index (32–320 ms on that snapshot); without
  it (a file sloth has not opened since), the `first_seen` of the rows in
  range, bucketed in C rather than through `GROUP BY`'s sorter, found
  through `idx_<t>_last_seen` when `min`/`max(last_seen)` say under 2/5
  of the table is in range, and by a scan otherwise: on a table mostly
  in range the index read costs twice the scan's per row (measured,
  254 ms against 123 ms on the snapshot). The bound loses no row because
  sloth stores `first_seen <= last_seen`: the device upsert binds both
  from one time, and `write_events()` clamps an alert episode the engine
  stamped across a backward wall-clock step (a file an older sloth wrote
  across such a step can hold an episode the bound leaves out). The
  snapshot itself is the scan case, every row in the last 30 days:
  123–246 ms on an idle desktop core with the file in the page cache,
  0.3–1.1 s on the same host at load average 17. Those are best-case
  figures, so 1500 ms is 6–12 times the idle scan but only 1.3–5 times
  the loaded one; a sensor-class host was not measured. The answer is
  cached for at most 60 s per sloth.db state (device, inode, mtime and
  size of the file and its `-wal`), per cell size and per `from` cell,
  4 entries; a cached answer carries the `from` and `to` it was counted
  for. An immutable snapshot is counted once a minute at most; a running
  sloth changes its `-wal` every tick and is in effect not cached. A
  failure says which read stopped and how far it got:
  `{"error":"sloth_db_timeout","detail":...,"query":"alerts","rows_read":N,"plan":"scan","budget_ms":1500}`
  (`plan` is how that table was being read: `index`, `bound`, `scan`,
  or null between them, so a slow scan of a file sloth has not
  reindexed is told apart from a slow index count), and the page keeps
  "try again" and appends the query, the rows read, the plan and the
  budget.
- **Who was here** (`/api/history/devices?from=&to=&limit=&offset=`) is
  the wiki's recipe as a route: devices whose `[first_seen, last_seen]`
  overlaps `[from, to]`, edges included, rendered as `/api/devices`
  renders a row, with the presence strip over the range itself and
  nothing past it: `presence_cells` (at most 144) cells of
  `presence_cell_s` from `from`, the last ending at `to` (and
  `utc_offset_s`, the host's UTC offset at `to`, the zone of the
  strip's ruler), from
  slothweb.db's `dev.present`. A cell is a whole number of the steps of
  `presence_tier`: `minute` while the range lies inside
  `--web-retain-days`, `hour` (the hour tier, kept 400 d, with whatever
  minute rows remain) for a range reaching further back, so the older
  part of a long range is not drawn blank. The hex still carries 144
  cells; those past `presence_cells` are 0, and the page spreads
  `presence_cells` across the strip. A row opens the drawer.
- **Alerts, anomalies and flows in the range**: `/api/history/alerts`
  (title, the IP it names, type, the highest severity, the summed count,
  first and last seen, one row per alert key with its `incidents` in
  the range and the `id` of its page; never the key or the detail). The
  keys listed come from the range's newest 20,000 rows; each listed
  key's figures are then its own over every row of it in the range,
  read through the primary key, so a key whose older rows fall past
  that bound is not undercounted, and `"scan"` says whether the bound
  was reached and the oldest last seen it covered (the page names it).
  `incidents` counts the key's rows in the range, each at least one
  incident there: a lower bound on a v8 file, whose row may hold
  earlier incidents too. On a v8 sloth.db a row is a finding that may
  span several incidents, and the range test reads the latest
  incident's start, so a range inside the gap between two incidents
  does not list it. On a v11 sloth.db (#175) a key with rows in
  `alert_incidents` is read from those instead: listed when one of its
  incidents overlaps the range, its `sev` the highest peak, `count` the
  sum and `incidents` the number of the incidents there (exact), so a
  finding CRIT once and LOW since reads LOW in a range holding only the
  LOW incident; a key with none is read from its row as above, and the
  20,000 rows are over both sources together; the anomaly episodes slothweb still
  holds (`/api/anomalies?since=from`, those begun by `to`; episodes are
  kept a week), and `/api/history/flows` (`ssh_flows`, `rdp_flows`,
  `smb_sessions`, `snmp_flows`: protocol, src, dst, the count each keeps,
  the SMB port or SNMP version). `mqtt_flows` is not read: it holds a
  username and M4's allow-list keeps the table off whole.
- **New since the previous session** (`/api/sessions/new?id=`) is
  `--report`'s section (`src/posture.c`, `src/db.c`) in the browser.
  `since` is the previous session's `COALESCE(ended, started)` (a crash
  falls back to its start, as sloth's does), the previous being what
  `db_session_begin()` read when this one began: of the sessions
  recorded before it, the latest started. Then the access points,
  devices and probe clients first seen at or after it, each newest first
  with `--report`'s identity and label (`COALESCE(NULLIF(hostname,''),
  NULLIF(vendor,''), '')` for a device, the SSID otherwise) and its
  total, 32 listed as `--report` lists them. A first visit has no
  previous session and, like `--report`, no list. For the latest
  session that is `--report`'s window exactly; for an older one the
  window also closes where that visit did (its `ended`, or the next
  session's start when it never recorded one), so it says what
  `--report` said at the end of that visit rather than everything
  since. `test_history.c` holds the latest one to the wiki's own
  "between the last two visits" recipe.

### The SQL box

`--web-allow-sql` adds `/api/query?sql=` and `/api/recipes`, and the
box on the History view; without it both are a `404` like any unknown
path, `/api/health` says `"sql":false`, and the page never draws the box
or asks for its recipes.

```
GET /api/query?sql=SELECT%20bssid%2C%20COUNT(*)%20n%20FROM%20beacon_ap_ssids%20GROUP%20BY%20bssid%20HAVING%20n%20%3E%201
{"columns":["bssid","n"],"rows":[["0a:00:00:00:00:01",3]],"row_count":1,
 "truncated":false,"truncated_by":null,"row_cap":10000,"timeout_ms":5000,
 "elapsed_ms":1}
```

What a statement goes through (`web_sqlbox.h` has the detail):

1. **The text**, on the server's thread before anything is queued:
   exactly one `sql=` parameter, percent-decoded (`+` a space), at most
   4,096 bytes, valid UTF-8 with no control byte but tab, CR and LF, and
   `SELECT` or `WITH` as its first keyword after blanks and comments.
   `EXPLAIN`, `PRAGMA`, `ATTACH` and every write fail here.
2. **The opener**: M4's, unchanged (read-only, no-follow, no side file,
   `DEFENSIVE`, `query_only`).
3. **One statement**: the prepare's tail must be blanks and comments.
   `SELECT 1; DROP TABLE devices` is refused whole; nothing of it runs.
4. **The authorizer** answers `SQLITE_OK` to `SQLITE_SELECT`,
   `SQLITE_READ` and `SQLITE_FUNCTION` for the functions the recipes
   and plain queries use (`count`, `sum`, `avg`, `min`, `max`,
   `coalesce`, `datetime`, `strftime`, `substr`, `like`, ...), and
   denies everything else: every write and DDL (a temporary table
   included), `PRAGMA`, `ATTACH`, a transaction, a recursive CTE, and a
   CTE with a DML tail, which is an `INSERT`, `UPDATE` or `DELETE`.
   `SQLITE_READ` is itself denied for the withheld columns (below),
   `sqlite_dbpage` (raw pages would carry their bytes),
   `sqlite_stat3`/`4` (sampled index keys), `dbstat` (and the recovery
   extension's `sqlite_dbdata`/`sqlite_dbptr`: a table's or an index's
   payload less its readable siblings is a withheld value's length),
   every `pragma_*` table-valued function and anything outside `main`. The refusal names
   what was denied (`{"error":"denied","detail":"withheld:
   cleartext_creds.username"}`).
5. `sqlite3_stmt_readonly()` must also hold, a second, independent
   check.
6. **Limits**: `SQLITE_LIMIT_ATTACHED` 0, values at most 64 KB, bounded
   expression depth, compound select, columns and function arguments, no
   bound parameters, `trusted_schema` and extension loading off.
7. **5 s**, by a progress handler: what came back by then is the answer,
   `"truncated_by":"timeout"`. **10,000 rows** (`"rows"`) and **4 MB of
   answer** (`"bytes"`) likewise. **No temporary file**: the box's
   connection goes through a VFS that opens sloth.db, its journal and
   its `-wal` and nothing else, with `temp_store` FILE and a 2 MB page
   cache, so a sort or temporary b-tree that outgrows the cache is a
   `400` `temp_space` at its first spill instead of gigabytes written
   to the temporary directory (the filesystem sloth.db is on, on a
   sensor) for the whole 5 s. A library built to keep temporary tables
   in memory regardless (`TEMP_STORE=3`, unbounded) has no box: every
   statement is a `503`. Every value is JSON (the writer every
   string here goes through), a BLOB as `{"blob":"<hex>"}`, a REAL
   always with its point.
8. **One at a time.** The statement runs on the box's own thread, so
   the page, the stream and every other route keep being served for the
   seconds it may take. From the submit until its answer has been
   written (or its client is gone) the box is busy, and every other
   `/api/query` is a `503` `{"error":"busy"}`. The answer is sent from
   the box's one buffer, which is what bounds the memory it costs.
9. **The rest.** A statement that kept sloth.db open for *t* ms (at most
   the timeout) is followed by *t* ms with no box connection to it; one
   submitted then is queued (the box is busy) and runs after. A reader
   holds a WAL read mark while it runs and sloth restarts its WAL only
   when none is held, so without the rest a client looping the box kept
   sloth.db-wal growing at sloth's whole write rate (14.7 MB in 40 s
   against 4.2 MB with no reader) and left it that size. The server's
   deadline for a box answer is its own timeout plus twice the box's.

**The withheld columns** (`web_secret.h`) are the same list M4's reader
is held to: the columns `tests/test_db.c`'s guardrail words name when
the column can hold text (TEXT, BLOB, or no declared type), the
credential words M4's allow-list test uses, and the credential-bearing
columns the words miss: `alerts.key` and `alerts.detail` (a cleartext
credential's username, `rule_cleartext_cred()`; an RDP cookie and an
MQTT username in the text), `cleartext_creds.username`,
`mqtt_flows.last_username`, `rogue_radius.last_identity` and
`rdp_flows.last_cookie`. The box reads the file's own schema at each
statement, so a TEXT column a later sloth adds with such a name is
withheld the day it appears. Withholding them in the box too is
deliberate: the box is the operator's own `sqlite3`, but in a browser
tab, served to whoever the allow list admits; a username that crossed
the wire in the clear is the finding, and the terminal is where to read
it. The integer flags and counts that carry the same words
(`pw_observed`, `has_pmkid`, `community_count`, `deauth_chain`) are read.

**The recipes** are `docs/wiki/sqlite-schema.md`'s own:
`web/tools/recipes.c` extracts every `sqlite3 sloth.db "..."` in a
` ```sh ` block at build time into `build/web/web_recipes.c` (never
committed), the SQL byte for byte and the `#` line before it as the
title; `/api/recipes` serves them and the box offers them in a list.
Five of the eight run from the box. Three are refused, naming what
they read: "Findings by severity" (`alerts.detail`), "Cleartext
credential exposures" (`cleartext_creds.username`) and "What is
actually taking the space?" (`dbstat`). The extractor stops the build
on a `sqlite3` line in a ` ```sh ` block written any other way, and on
a ` ```sql ` block, so the page cannot offer a recipe the box drops.

**The acceptance** (`test_sqlbox.c`): a sloth.db generated from
`src/db_schema.c` in a fresh directory, seeded so every recipe returns
rows; each recipe through `/api/query` over a real loopback socket and
through the sqlite3 C API directly on the same file, the result
identical; through the `sqlite3` shell too when one is on `PATH` (CI
may have none; the library it would run is the honest stand-in); the
three refused recipes refused, naming what they read; every write in every
disguise refused (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ATTACH`,
`PRAGMA writable_schema`, a temporary table, a CTE with a DML tail,
two statements) and the file byte for byte and its directory unchanged.

**Exposure.** `--strict` refuses `--web-allow-sql` (exit 2). With
`--web-allow-remote` slothweb prints a warning at start naming the
exposure: every peer the allow list admits can then run any read-only
`SELECT` over sloth.db.

### Where this departs from the spec's body

- The spec's `/api/query` denies "everything except `SQLITE_READ` and
  `SQLITE_SELECT`". A recipe calls `strftime()`, `datetime()`,
  `COALESCE()` and `COUNT()`, which are `SQLITE_FUNCTION`s: those and a
  few plain functions are allowed, nothing that reads a file, loads
  code or makes a blob of a chosen size.
- The spec's acceptance says the recipes "match the sqlite3 CLI
  output". Two recipes read a column withheld from every reader and
  one reads `dbstat`, so they are refused instead; the other five
  match.
- `HEAD /api/query` is a `405` (`Allow: GET`), the one route that is not
  GET and HEAD: a `HEAD` would have to run the statement to describe its
  answer.
- §8.8 names `/api/wifi/channels` and `/api/wifi/aps`; the timeline's
  `/api/wifi/deauth`, the History routes and `/api/sessions` are this
  milestone's own, in the same shape.
- "New since" for an older session closes its window at that visit's
  end (above); for the latest it is `--report`'s.

## Flows (M6)

#164. Spec §8.9 and §8.12, the rulings header. `web_flows.h`, the
Flows view (`7`).

![Flows](../docs/assets/slothweb/flows.png)

**What is read.** sloth.db's protocol tables, one tab each:
`ssh_flows`, `rdp_flows`, `smb_sessions`, `snmp_flows`, `ldap_events`,
`kerb_events` and `bgp_sessions`, through the M4 reader and its column
allow-list (`web_sdb_ftab[]` in `web_slothdb.c` names each tab's
columns; `test_flows.c` holds every one to the allow-list). Three are
left out, and the tab says which and why (`"withheld"`):
`ssh_flows.server_banner` (M5 kept it off), `rdp_flows.last_cookie`
(an `mstshash` account name) and `snmp_flows.community_count`;
`kerb_events.preauth_required_count` and `preauth_failed_count` are
integer counts, but named for a credential word, and the allow-list's
name guard is deliberately not type-aware, so they stay off it rather
than weaken the guard. **`mqtt_flows` is not read at all**: it holds
MQTT usernames, M4's allow-list keeps the table whole off, and
`/api/flows?proto=mqtt` is a `400` `proto_withheld`; its tab is shown
disabled with the reason.

**`/api/flows?proto=&from=&to=&ip=&sort=&limit=&offset=`.** One tab's
rows overlapping `[from, to)` (History's range rules: the last 30 days
by default, at most 400): `src`, `dst` (`null` for the per-source
`ldap` and `kerb` tables), `counts` in the order of `columns`, their
`total`, the SMB `server_port` and `dialect` with `smb1`, the RDP
`proto_mask`, the SNMP `version`, `first_seen` and `last_seen`.
`proto` is required. `ip` is a literal address, canonicalised, matched
against either end. `sort` is `last` (default), `total`, `src`, `dst`
or `first`, with `dir=asc|desc` as `/api/devices` takes it;
`limit` 1..200 (default 50) and `offset` 0..1,000,000. `total` counts
every matching row; a page that would not fit its 64 KB answer stops
early with `"more":true`, and the next page starts at `offset +
count`. Each parameter passes whole or the answer is a `400` with its
reason (`missing_proto`, `unknown_proto`, `proto_withheld`, `bad_ip`,
`bad_sort`, `bad_limit`, `bad_offset`, and History's range reasons).

**`/api/flows/graph?from=&to=&nodes=&edges=&form=`.** The chord diagram's
data (`form=chord`, the default, and the answer as it was before
`form` existed): the source -> destination pairs of the pair tables (`ssh`, `rdp`,
`smb`, `snmp`, `bgp`; `ldap` and `kerb` record a source only), the
`edges` largest by total (1..200, default 80), and of their endpoints
the `nodes` busiest (2..64, default 24; the page asks for 12 below
520 px). A pair with an end outside the kept nodes is folded, as is
every pair past the largest `edges`. `"fold"` states it in numbers:
pairs, flows (the sum of totals) and addresses, each as total, shown
and folded, so the page can say "16 of 40 pairs, 24 of 61 addresses;
folded: 24 pairs, 310 of 2,104 counted". `"tabs"` gives each tab's rows
and total in the range for the tab strip (`null` for a table the file
lacks, `"mqtt":"withheld"`). Bounded on both sides: at most 200 pairs
read, 64 nodes drawn, whatever sloth.db holds.

**`form=matrix`** (#171 V4, F11; `docs/web-visual-spec.md` §7's route
change). The same `edges` largest pairs, and no endpoint folded by
rank: every end of a pair read is a row or a column, so `nodes` is
refused with it (`400 nodes_not_in_matrix`) rather than quietly
ignored. `"srcs"` and `"dsts"` are the sources and the destinations,
each `{id, group, total}` and each in address order (IPv4 by its
bytes, then IPv6 by its bytes, then anything else by its text, so
`10.0.0.11` follows `10.0.0.8` as the address plan has it); `"groups"`
are the subnets over both axes in that order (an IPv4 address's /24,
an IPv6 address's /64, anything else its own), computed here so the
page draws what it is given; `"cells"` are the pairs merged by
(source, destination), `{s, d, total, protos, smb1}`, `protos` every
pair table that has the pair (`ssh`, `rdp`, `smb`, `snmp`, `bgp`) and
`smb1` when one was an SMB1 session; `"max"` is the largest cell, the
matrix's one scale. `"fold"` keeps its members: `pairs_folded` counts
only the pairs past `edges`, `nodes_folded` the ends of those. `"tabs"`
as the chord's.

**The view: the matrix first** (owner ruling 4 of 2026-10-26, F11;
#171 V4, `web/ui/flowmx.js`). The panel's `draw` control (kept, as
`ctl.f-mode`) is `who talks to whom (matrix)` by default and `chord`
second. The matrix: a row per source and a column per destination
(`form=matrix`, 80 pairs, 40 below 520 px), the source addresses in a
gutter at the left and the destinations reading up the column headers,
each in its hash colour and bold once cross-panel, an alert-hot one in
its `CP_ALERT_HOT_*` colour, as the chord's nodes are; a `--rule` line
where the subnet changes on either axis; each cell G6's count bar on
the matrix's one scale (R3: the largest cell a full cell, printed in
the caption) behind the pair's count in words (`64`, `2.0k`), and the
pair's protocols as letters in its corner (`S` ssh, `R` rdp, `M` smb,
`N` snmp, `B` bgp) rather than a hue, so it needs no legend; an SMB1
cell in `--sev-crit`, bar and number (R10: the note under it says what
red is). A cell is 30 to 56 px wide, so a matrix wider than the panel
scrolls inside its own box and the page never does. R11: the scale
grows and never shrinks until the window or the scope changes. R9: the
caption `sloth.db's pair tables, 7 d, one scale, largest 64; 2
subnets, n=6`; no pair collapses the panel to it (R5). Clicking a
source, a cell (its source) or a destination's header filters the
table by that address. **The chord, the second mode**, is the drawing
below, unchanged.

A Canvas 2D chord diagram: the kept addresses on a
circle, busiest first from twelve o'clock, each with its hash colour
(§8.12) and its address as text (cut to 22 characters, 11 below
520 px, from the left and only after a `.` or `:`, behind `…`: so
198.51.100.1 is `….51.100.1`, never a whole address it is not); each pair a curve through the middle
from its source to an arrowhead at its destination, its width by the
log of its total, its colour the protocol's hue (`--f-ssh` and the
rest in `theme.css`), and an SMB1 session in `--sev-crit`. The legend
names every hue in text, and the fold line above says what was left
out, so the drawing never stands on colour alone. Clicking an address
filters the table by it. Under it, the tab strip (each tab with its
row count) and the table: source, destination, the counters by name,
total, the protocol's extra (port and dialect, version, protocol mask),
first and last seen; newest first, paged with "more". The address
columns grow from 16 to 40 characters with the width, enough for a
whole IPv6 address, and a cut one has the whole address as its
tooltip. **An SMB1 row is
`--sev-crit`**, by a fixed class (`frow sev2`) and with `SMB1` in its
own column. Without `--sloth-db`, or in a `WITH_SQLITE=0` build, both
panels say why instead.

**The polish pass** (#164's second half), each found by driving the
page in headless Chromium against the demo data in four states (full,
no `--sloth-db`, no stream, `WITH_SQLITE=0`) at 1280 x 900 and 360 x
740: the view list is buttons, so `Tab` reaches every view in order
(with `aria-current` on the open one), and device, history and flow
rows and anomaly cards take focus and open with `Enter`; the device
drawer takes the focus when it opens and gives it back when it closes;
wide row tables scroll sideways inside their own box at a narrow width,
so the page itself never does (it did at 360 px); the table headers'
columns line up with their rows (an 11 px header against 12 px rows in
`ch` units drifted left a column per screen); the MAC column fits a
randomised MAC; the History strip takes pointer events, so a finger
can drag a range; `color-scheme: dark`, so a browser that prefers a
light scheme still draws dark controls on the dark page; the address
names the view (`#flows`), so a reload stays on it; and a
`WITH_SQLITE=0` build's pages say it cannot read sloth.db rather than
suggesting a flag it does not have.

## Alerts

Owner requests 2026-10-23..26. The Alerts page (`6`), an alert's own
page, and the Overview's tiles as links to the views of what they
count. `web_alerts.h` (the routes), `web_alertdb.h` (the sloth.db
reads), `web_alertfmt.h` (whose detail is shown), `web_alertkb.h` (what
each type is, why it matters, how to fix it).

### The Alerts page

`/api/alerts` merges two sources. The stream's lifecycle records
(`alert.create`, `.update`, `.escalate`, `.resolve`, docs/wiki/jsonl-schema.md)
are kept per incident in `web_live.c`: the open ones (256 at most, as
before: the open-alerts tile counts exactly these) and the 64 most
recently resolved, each with its severity history, counts, first and
last seen, and whether sloth wrote a pcap of it. Before schema v8
sloth.db's `alerts` table held one row per `(key, first_seen)`: a
finding that comes and goes is many rows of one key, about 114 on the
owner's host (#170, 868k rows); a v8 file keeps one row per finding,
its `reopens` counting the incidents after the first, and the rows
recorded before the upgrade stay as they were. The page has one row per
alert key, from either source: sloth.db's rows of a key grouped, the
stream's incidents of a key shown as its open one (else its newest
closed one) with the others counted in, and a key the stream has shown
once, as the stream's (`"source":"both"`). A row's `"incidents"` and
`"count"` are the key's, all time: sloth.db's totals over every row of
the key (`1 + reopens` a v8 row, one an older row) or the stream's,
whichever is larger, since either can lag the other; the alert's page
shows the same two (and `"latest_count"`, the one incident's; on a
v11 sloth.db, #175, also `"db_incident"`, one incident's own
`first_seen`, `last_seen`, `sev`, `peak_sev`, `count`, `observations`,
`closed_at` and `reason` from `alert_incidents`: the stream incident the
page opened on, `"which":"opened"`, else the key's newest,
`"latest"`, and its `"history"` runs built from those rows,
`"source":"incidents"`). A
stream row also carries `"observations"` (the incident's detail
changes) and `"confidence"` (the rule's percent, `null` when it reports
none); a sloth.db row has neither, so both are `null`. Open incidents
come first, highest severity, then most observations, then newest
change, and never by `count` (#179: for a per-tick rule `count` is how
long the condition stood, 44.8M on an EVIL_TWIN pair of one detail
change); then the closed ones, newest last seen first. A row at or under 20%
confidence (owner ruling 2026-11-03) is drawn muted, display only, its order and severity
unchanged; a CRIT row never is (EVIL_TWIN keeps CRIT on a hard
signal that a forged 802.11k claim and a copied OUI take to 5%).

Filters: state (open, closed, all), severity, type (by name or
number; the dropdown is the facets, groups per type in the window),
`q` (one word: a substring of the title, the address or the type's
name), and the window (default 7 d; open incidents are listed whatever
their age). 50 a page, `more` for the next.

**alerts.key stays predicate-only.** Its text can carry a remote string
(for a cleartext credential, the username), so the reads match on it
and group by it with `pred_ok` set, and no result column carries it.
A sloth.db group is named by the rowid of its newest row (`d<rowid>`,
which sloth's upsert keeps and its incremental vacuum does not
renumber), a stream incident by slothweb's handle for it (`s<handle>`);
a stream key is kept in memory to bind as a predicate and is never
rendered. `test_alerts.c` walks every route with a username in both
sources' keys and details and finds it in no body.

**sloth's `incident_id` is not served either.** sloth derives it by
FNV-1a64 over the key, then the creation time, then a small counter
(`src/alerts/engine.c`, `incident_id_make()`), and every FNV step
inverts: undo the time (the incident's first seen) and the counter (a
few thousand guesses) and what remains is the key's unsalted hash,
which a dictionary of usernames turns back into a `CLEARTEXT_CRED`
username. slothweb names a stream incident by a handle of its own, 8
hex digits drawn from `/dev/urandom` at startup and a counter of the
incidents this process has seen, in `/api/alerts`, `/api/alert` (`id`,
`stream_id`), the page's `#alert?id=` links and `/api/live`'s
`alert_id`. The handle says nothing of the key; the nonce only keeps a
link saved before a restart from naming another incident after it.
`test_alerts.c` feeds incident_ids in sloth's shape and finds none in
any body.

**Bounded.** Every list reads at most 20,000 rows of its window, newest
last seen first through `idx_alerts_last_seen`, with its filters
applied inside that read: the bound counts rows that match, so an old
alert of a rare type, title or address is found by asking for it, and
its type is among the facets. One walk answers the page, the facets
(with no type filter; a type filter costs a second walk for the
facets, which leave it out) and the `"scan"` member: how many matching
rows were read, whether the read stopped at the bound, and `"oldest"`,
how far back it reached when it did (the page says so). A filter that
matches little walks the window to find what there is, under the
request's 250 ms budget, and a `503 sloth_db_timeout` says when the
window was too wide for it. A key's own reads go through the primary
key's index, at most 2,000 incidents. Measured: on a generated table of
500,000 rows on 4,386 keys of 114 rows (`SLOTHWEB_ALERTS_BENCH=1
WT_ONLY=alerts ./slothweb_test`, the `-O0` test build), `/api/alerts`
33 to 114 ms for every filter and page tried, `/api/alert` 1.2 ms,
History's 30-day list 33 ms. On the owner's 868k-row (schema v6)
sloth.db, read through an immutable URI with the sqlite3 shell: the
default list's statement 55 ms and its page's key totals 70 ms; a
search word matching nothing over the default 7 days 115 ms; a rare
type over the whole 400-day window 370 ms, past the budget (a 503,
where the parent answered from the newest 20,000 rows and missed the
row); History's 30-day list 240 ms. `--db-compact-alerts` (#170) folds
that file to 7,598 rows, where every one of these is a few
milliseconds.

### An alert's page

Opened from any alert anywhere: the Alerts page, the Overview's latest
alerts, History's alerts in the range, the device drawer's alerts
naming it. `/api/alert?id=` answers all six sections:

- **What it is**: the first sentence of the rule table's trigger
  (`docs/views/alerts.md`), its issue references dropped and at most
  280 bytes, with the whole cell, its engineering history included,
  folded under "details" and its code spans set as code; the rule's
  severity and the alert's now, the ATT&CK technique, what `match_ip`
  names, and the paragraphs of `docs/wiki/alerts.md` about it.
- **Why it matters**: every research corpus document whose
  `alert_kinds` list the type, with its citation, source URL (as text:
  the page links nowhere), lead paragraph and the paragraphs that name
  the type.
- **How to investigate and fix**: the type's section of
  [`docs/wiki/alert-remediation.md`](../docs/wiki/alert-remediation.md),
  written for all 90 types, each step resting on a corpus document
  that cites the type, "none; mitigate by ..." where no vendor fix
  exists.
- **The header** (#179), under the title (type, severity, technique),
  in reading order: the detail changes (`observations`), the times
  opened (`incidents`), first and last seen and the span between, the
  rule's `confidence` and `rule_reason`, and only then `count`, as
  evaluations with a tooltip saying what they are. The answer's own
  member order follows: `observations`, `incidents`, `sev_history`,
  `confidence`, `rule_reason`, then `count` and `latest_count`, so the
  copy-JSON bundle's `alert.page` reads the same way; no member is
  renamed. `confidence` is the stream record's own field; `rule_reason`
  is EVIL_TWIN's or KARMA_AP's verdict phrase ("vendor OUI differs",
  "candidate, uncorroborated", ...), matched at ingest against a table
  of the rule's literals (`web_alertfmt.h`) in the text after the
  detail's last quote, so what is served is the table's word, never
  the detail's bytes, and it is served even where the detail is
  withheld. sloth.db keeps neither: both are `null` for a row the
  stream does not hold. `reason` is unchanged: why an incident closed.
- **Evidence**: severity history, when and why it closed, whether sloth
  saved a pcap (only the stream says), and the detail text, for an
  audited type only (below).
- **History of this alert**: every incident of the key, newest first,
  incidents less than 30 minutes apart folded into one run, each run a
  link to its newest incident.
- **The device**: the device the key names by MAC, or the one holding
  the address, with its presence strip, its other alerts and anomalies,
  and the drawer a click away. The drawer's alerts naming a device are
  read with the device test inside the read, walking `last_seen` newest
  first a slice at a time (a day, then twice as far back each time)
  while the request's budget has 80 ms left, so a device's month-old
  alert is reached however much newer traffic other devices made;
  `"alerts_reached"` is the last seen it got back to when the budget
  stopped it first (the drawer says so), `null` when it read the table
  to its end.
- **The attack chain** (#171 V4, `web/ui/chain.js`), above the device:
  G8 for the BSSID the alert names. `"device"` carries `"bssid"`, the
  AP sloth heard beacon whose BSSID the key names (`web_adb_emitter()`
  over `beacon_aps`, the key a predicate, never read out), `null`
  otherwise, and the page asks `/api/wifi/chain` for that BSSID around
  the alert's span ([The glyph layer](#the-glyph-layer), slice V4). No
  BSSID: no section.

- **The proof** (the page's last section, `web/ui/evidence.js`):
  observed against threshold, the type's assessment and bibliography,
  and the packet capture with every frame decoded and its bytes. Its
  own section below.

The first three are built in at compile time: `web/tools/alertkb.c`
reads `include/sloth_alerts.def`, `docs/views/alerts.md`,
`docs/wiki/alerts.md`, every `research/` document and
`docs/wiki/alert-remediation.md` into `build/web/web_alertkb.c`
(generated, never committed), so an edit to any of them is what the
page shows after the next build. `test_alertkb.c` fails when a type has
no entry, no trigger, no source or no steps, or when a remediation
section cites a document whose `alert_kinds` do not list the type.

**The detail is withheld unless audited.** An alert's detail is the
text its rule wrote, and for several rules it carries what the wire said:
CLEARTEXT_CRED's username, SNMP_COMMUNITY_BRUTE's community,
RDP_BRUTE_FORCE's cookie, MQTT_BROKER_BRUTE's username, a banner, a
host or query name. `web_alertfmt.c` lists the 50 types whose every
`snprintf()` into the detail formats only numbers, literals,
addresses, MACs, BSSIDs and SSIDs; `test_alertfmt.c` reads
`src/alerts/` on every run and fails if a listed type's format gains
any other string field, and refuses the credential-bearing types.
Every path asks the list: the stream's detail is not even kept for an
unlisted type (so `/api/live` and the ticker show the title alone), and
sloth.db's `alerts.detail` is read by one statement only, as
`CASE WHEN web_detail_ok(type) THEN detail END`, so a withheld detail
never leaves SQLite.

### An alert's proof

Owner requests of 2026-10-27: "show the full packet capture in alerts
at the bottom as well", and the drawer's alert rows tapped for "full
verbose details of the alert, include bibliography, when possible prove
the alert with evidence". `/api/alert` carries four more members and
the page draws them last, the capture last of all:

- **`evidence`**: what was observed (`count (evaluations)`, the
  observations, the span, and the `name=value` numerals of the detail,
  only for a type whose detail is audited, above) beside the threshold
  where it is known: the assessment's front matter keys naming a
  threshold, a window or a count, and its `tuning` list. Neither
  counter counts frames or requests, and `reading the counts` says so
  on every answer: `count` is one per poll (at least 4 a second) while
  the condition stands, and `observations` follows it once the detail
  moves, because the engine re-takes the detail only on a severity
  change or past its 60 s update floor (`src/alerts/engine.c`,
  `fire_inv()`). The assessment's own `count_semantics` follows as
  `count_semantics (assessment)`. With no capture, `why_no_capture` says why in
  sloth's own terms, first match wins: no `--pcap-dir`; a rule that
  names no target address (the rule table's `match_ip` cell is `—`), so
  sloth's `--pcap-dir` export can never hold one; below
  `pcap.min_severity` (default CRIT); sloth's record says it wrote none
  (the key inside `pcap.key_cooldown_secs`, default an hour, of its
  last capture, or no packet in the 256-packet ring to or from the
  address); the record names a file the directory no longer holds
  (`pcap.retain_days`, default 14). So "none saved" never reads as
  "nothing happened".
- **`assessment`**: `docs/wiki/alert-assessments/<TYPE>.md`, built in
  by `web/tools/alertasm.c` into `build/web/web_alertasm_table.c`
  (generated, never committed; lookup `web/src/web_alertasm.h`): its
  front matter as written, its sections in order (words, code spans
  and `[n]` marks kept), its Bibliography as text entries, and the
  Bibliography's own prose as `bibliography_note` (or `null`): a line
  there is an entry's continuation only when indented straight under
  it, so a note such as MY_NETWORK_RECON.md's "(5. and 6. intentionally
  unused ...)" or a "no public advisory was found" paragraph is never
  shown as a source's words. Wiki header
  lines (`**Summary**`, `**Sources**`, `**Last updated**`) before the
  first `---` are read past; `## Related pages` is not shown; a
  numbered entry `7. text` is entry `[7]` (the assessments number with
  gaps). The build stops on a file whose stem is not an alert type, or
  on a `[n]` with no Bibliography entry outside `## Verification
  notes` (which names the sources' own reference numbers). 72 of the
  90 types have one; for the rest (the `pending` list of
  `tests/test_alert_assessments.c`) the answer is `null` and the page
  says "no assessment yet". A document too long for what is left of
  the answer's 64 KiB (8 KiB kept for the history behind it), measured
  by writing it, is sent as `{"path":...,"too_large":true}`, never cut.
- **`captures`**: the alert's files, newest first, at most 8, each
  `n` (what the routes take), `file`, `sink`, `size`, `sha256`,
  `written_at`, `rule` and `matched_by`: `incident` (the manifest's
  `incident_id` is the stream incident's), `record` (the file the
  alert's own lifecycle record names in `pcap_path`, which may have no
  manifest line), or, only when neither found one, `rule_time` (the
  same rule written between `first_seen - 60 s` and `last_seen + 1 h`:
  the manifest names no address, so the page says to check it is this
  alert's). A sloth.db row (`d` id) has only `rule_time`. Never the
  `incident_id` (it inverts to the key's hash, [Alerts](#alerts)), the
  manifest's session or a directory path. `captures_note` says why the
  list may be short: `no --pcap-dir`, `directory unreadable: ENOENT`
  (or `EACCES`, ...), `index partial`. Each entry also carries
  `withheld` (`"withheld: may hold EAPOL/PMKID handshake material"` for
  an evidence pcap without `--web-serve-evidence-pcap`, else `null`),
  `unreadable` (`"unreadable: not a regular file"` when what sits under
  the name is a symlink, a FIFO or anything else not regular, by
  `fstatat` with `AT_SYMLINK_NOFOLLOW`, else `null`),
  `manifest_lines` (how many manifest lines name the file) and
  `conflict` (`"conflicting manifest lines (N)"` when those lines
  disagree on hash or size, else `null`). A withheld or unreadable
  entry is shown with its reason and cannot be opened: both routes
  answer it with `403`.
- **The capture** (`/api/pcap/frames`): the file read whole through
  the directory's descriptor (`openat`, `O_NOFOLLOW`, a regular file,
  at most 16 MiB), its SHA-256 (FIPS 180-4) recomputed over the bytes
  read and compared with the manifest's: `hash verified` says these
  are the bytes sloth hashed when it wrote the line, and no more
  (`docs/wiki/pcap-export.md` says what a hash does not establish).
  When several lines name the file, every one is tried: any line
  whose hash and size match makes it `hash verified` (and
  `manifest_sha256` is that line's), none makes it `HASH MISMATCH`,
  and lines that disagree add `conflict`. Which line is newest decides
  nothing: a line's `written_at_epoch` is only what the line claims, so
  an appended line with a later stamp cannot turn an authentic file
  into a mismatch.
  The reader is libpcap-free (`web/src/web_pcap.c`): classic pcap in
  either byte order, microsecond or nanosecond magic, per
  draft-ietf-opsawg-pcap; pcapng is refused with "convert it with
  `editcap -F pcap`" (sloth never writes it). 802.11 frames (link types
  105 and 127) are read by sloth's own parsers, linked in from `src/`
  (`radiotap.c`, `dot11_frame.c`, `dot11_ie.c`, `wifi_freq.c`,
  `dns_wire.c`, `netstr.c`): radiotap channel, signal and flags; the
  type and subtype by IEEE Std 802.11-2020 Table 9-1; the four
  addresses with their roles (RA, TA, DA, SA, BSSID, Table 9-26);
  sequence and fragment; a deauthentication's or disassociation's
  reason (Table 9-49), an authentication's algorithm and status, an
  association response's status (Table 9-50); a beacon's or probe's
  SSID (an over-long element said to be invalid), DS channel, RSN and
  PHY tier. Ethernet, Linux SLL and SLL2 go through slothweb's own
  bounded summary decoder (sloth's are static inside the capture path):
  VLAN tags, ARP, IPv4 and IPv6 (one extension-header chain), TCP flags,
  UDP, ICMP and ICMPv6, DNS (the name walk is sloth's `dns_wire.c`),
  HTTP request line, `Host` and `User-Agent`, TLS record and handshake
  type and a ClientHello's SNI, QUIC, NTP, DHCP, SSDP and WS-Discovery.
  sloth's `--pcap-dir` files keep 64 bytes of a packet (snaplen 64), so
  most frames end inside their payload: every such frame says
  `truncated at snaplen 64` and its decode stops where the bytes do,
  never reporting an uncaptured field as absent. The snaplen is named
  as the cause only when the record's captured length equals it; a
  record cut shorter than its file's snaplen says `N of M bytes
  captured` instead. 24 frames a page,
  each with its hex dump (256 bytes at most inline, the rest in the
  download), a filter over the page's frames, "next frames" for the
  rest (the first 4,096 records of a file are indexed). The frame index
  is one of the page's tables (`DataTable` in `app.js`, reached as
  `window.SlothTables.make`, table id `evframes`): `#`, time, bytes,
  kind, summary and cut sort over the frames held and resize, both
  kept in this browser with "reset columns", and the filter is kept
  like the page's other controls; a row opens (click, Enter or Space)
  into its fields and hex dump, and stays open across a sort.
- **The download** (`/api/pcap`): the file's bytes, as an attachment.
  It is a second read of the file, so those bytes are hashed again and
  the answer says what they are in `X-Sloth-SHA256` (`verified`,
  `mismatch`, `no_manifest_entry`): a file replaced after the page said
  "hash verified" does not download under that word.
  The page starts it with `window.location.assign("/api/pcap?id=...")`,
  every value encoded: the one place it leaves its own view, and to its
  own server.

**What is never served.** The per-handshake pcaps (`<bssid>_<sta>.pcap`)
and `eapol.22000` that share an `--eapol-dir` are crackable material.
Their names pass neither alert-pcap grammar and their manifest sinks
(`handshake_pcap`, `hashcat_22000`) are not indexed, so neither route
can open them, by index, by record or by rule. A request never carries
a file name: `n` indexes the alert's own list, so a file the alert's
lookup does not return is a `404` whatever the directory holds.

**What is withheld unless asked for.** An evidence pcap
(`<incident_id>-<event>-<RULE>[-N].pcap`, sink `evidence_pcap`, in the
`--eapol-dir`) is raw 802.11 frames from sloth's evidence ring, and the
ring notes every monitor frame: a `FRAG_EAPOL_RELAY` or
`FRAG_AMSDU_EAPOL` incident's file can carry the same EAPOL/PMKID
material sloth itself writes only under `--collect-handshakes`
(`docs/wiki/pcap-export.md` §4, owner ruling 2026-10-08). So it is
listed in the alert's `captures` with `withheld` and its size and hash,
and neither decoded nor downloadable (`403 withheld_evidence_pcap`),
until slothweb is started with `--web-serve-evidence-pcap`, which is
announced on stderr. With `--web-allow-remote` the bare flag is refused
at start; `--web-serve-evidence-pcap=remote` is the explicit way to
hand those files to remote peers, and is announced as such.

**The index.** Manifests are `sloth-manifest-*.jsonl` in the directory,
read newest session first, at most 32 of 1 MiB each, every
newline-terminated line parsed and an unterminated tail dropped (sloth
truncates a failed append, so a tail is a crash's, never a committed
line); at most 4,096 entries from at most 8,192 directory entries.
Rescanned on a request when the directory's mtime or the newest
manifest's size moved, at most every 2 s.

**The drawer's alert rows** (the list `app.js` marks
`data-ev="drawer-alerts"`, found by that mark and not by its label's
words) are tap targets that say so: a `›` at the
row's end, a 44 px row on a touch screen (`pointer: coarse`), and a
tap (or Enter) opens the alert's page and closes the drawer, which at
phone width covers the page it opens. Checked at 360 px with touch
emulation by `web/tools/tap_check.py` (Chromium's DevTools protocol;
not run by CI, loopback only).

### Copy JSON: the analysis bundle

Owner request 2026-10-27: every detail view (the device drawer, an
alert's page, the Lookup card, the BLE drawer, a TACDB platform)
carries a **copy JSON** button and a **download .json** button, so the
view's data can be pasted into Claude (or anything else) for analysis.
Both fetch one document,
`/api/bundle?kind=device|alert|lookup|ble|platform&id=`, the id as the
view's own route takes it (a MAC; `s<handle>` or `d<rowid>`; a MAC or
an IP; a BLE address; a platform's number).

**It re-renders nothing.** Every detail route writes its JSON straight
into a buffer and keeps no struct, and what it withholds (an unaudited
alert detail, the alert key, sloth's `incident_id`, the lists a capture
scope empties) lives in that rendering. So `web_bundle.c` calls the
route functions themselves and splices their bodies in verbatim:
`device.drawer` is `/api/device/{mac}`, `alert.page` is
`/api/alert?id=`, `lookup.card` is `/api/lookup?q=`, `ble.drawer` is
`/api/ble/{addr}` (every sensor's row of the address; under Local the
router's out-of-scope note, and no row), `platform.view` is
`/api/frrs/tacdb/view?id=`, and `alert.device` / `lookup.device` the
drawer of the device they name (an alert naming an address and no MAC
carries the address's Lookup card as `alert.lookup` instead). The
sections later slices brought data for are routes' bytes too: `frrs` is
`web_frrs_route()`'s answer to the GET the page's FRRS panel makes
(`/api/frrs/report?kind=sta|bssid&addr=` for a device, the kind the
drawer's panel picks; `?kind=ble&addr=<addr>/<type>` for a BLE address,
its first row's type; `/api/frrs/report/alert?id=` for an alert),
`alert.triage` is `/api/frrs/history?id=` (the state and every
decision), and `device.vendor_research`, `alert.assessment` and
`alert.evidence` (`captures`, `captures_note`, `evidence`: the capture
files listed with their manifest hashes, never a pcap's bytes) are
members of the primary answer lifted out whole. `location` is the
location slice's own answers: a device's is `/api/positions?mac=` in
its JSON form, as the drawer's scatter reads it (where the sensor was
each time it heard the device, and its track, newest first, at most
200 of each), and an alert's is the alert page's `loc` member, the
stamp as the incident opened (`no_data` when the page's is null). A bundle can carry
nothing the page would not show. `test_bundle.c` compares the spliced bytes with the routes' own
answers and reruns the alert routes' credential and incident-id checks
against every kind.

Around the splices:

- **envelope**: `bundle_schema` (semver; fields only added within a
  major), `kind`, `id`, `generated_at` (`iso`, `unix`), `server`
  (time zone and UTC offset, `slothweb.build_version`: the sloth
  source tree slothweb was built from, not the sensor's running sloth,
  which the stream does not say; the page's ETag,
  uptime; no host name: no page shows it, and a bundle is made to be
  pasted into someone else's service), `sensor` (the socket, sensor
  health and its age, the capture and monitor handles, sloth's launch
  scope, and records/s, the device count and the open alerts by
  severity under the scope in effect, as `/api/live` counts them),
  `sloth_db` (as `/api/health`), `scope_in_effect` with a
  sentence saying what it excludes, `page` (`url` and `view`, filled
  by the browser before copying; the server never echoes an address),
  and `withheld`, naming what was left out and why.
- **optional sections**, one registry row each in `web_bundle.c`:
  `records_recent` / `records_around` (the ticker ring's newest 50
  records that name the device or address: a stopgap, said so; only
  the records the scope in effect holds, each line as the page's ticker
  shows it under that scope, a device row's under Monitor without its
  address or name; matched on the record's address members (`mac`,
  `bssid`, `sta_mac`, `addr`, `ip`, `src`, `src_ip`, `dst`, `dst_ip`,
  `match_ip`, an endpoint's `:port` dropped), kept beside the line in
  the ring, never on the line itself: it is cut at 80 bytes, so a long
  query name could leave `192.0.2.123` as `192.0.2.12` at its end, and
  an SSID can read as an address; an alert that names the device only
  in its detail text is therefore not listed),
  `observed_vs_thresholds`, `records_by_type_global` (the stream's
  per-type mix; a summary that did not render is `too_large`, never an
  empty `{}` that would read as "no records"), `vendor_research`,
  `frrs`, `triage` (an alert's), `assessment`, `evidence`, `location`,
  and for what no build has yet `comint_report`, a device's `triage`
  (triage is per finding), `signal_history`, `distance`. A section without
  data is
  `{"available": false, "reason": ...}`, the reason one of `not_built`
  (this build has no such feature), `no_data`, `too_large`,
  `withheld`, `budget` (a sloth.db read timed out), `no_sloth_db`,
  `not_kept` (the stream carries it, slothweb does not keep it),
  `read_error` (a read failed), `no_store` (an FRRS route needs
  slothweb.db and it is not open). A nested drawer, card or FRRS answer
  that did not answer says which in its route's own words: a 400 or 404
  is `no_data`, a body over the route's cap (or the record's own
  `record_too_large`) `too_large`. A BLE address's FRRS record under
  Local is `withheld` with the drawer it belongs to. A slice adds its row and a fill
  function; the page needs no change.
- **analysis aids**: `glossary` (every field and unit), `prompt` (a
  suggested prompt that tells the reader the sensor is passive and one
  vantage point, and asks for observed versus inferred), `limits`
  (every cap, whether it cut, each sloth.db read's time). The glossary
  and the prompt say what an alert's `count` and `observations` are:
  evaluations of a standing condition, not frames or requests. `count`
  rises once per evaluation pass that fired; `observations` once per
  evaluation whose detail or severity differs from the last emitted
  one, and since the engine refreshes that baseline only on a severity
  change or past its 60 s update floor (`src/alerts/engine.c`), it
  follows the evaluations while the detail keeps changing. A large
  figure is how long the rule kept matching.

Bounds: the body is the route's own heap buffer (`web_resp_t
.body_owned`, freed with the connection) of at most 512 KB. The
envelope, the primary splice and the aids are required; the optional
sections are measured against what is left and rolled back to
`too_large`, named in `limits.truncated_sections`, when they would
cross it; a required part that cannot fit is `413 bundle_too_large`.
The room held back for the required part counts every optional row's
name and its longest marker, so a cap the required part fits never
overflows on the markers.
Each sloth.db read keeps its own 250 ms budget, at most four serial
reads a bundle (an alert's: the page, its device or address, its FRRS
record, its triage). A `scope=` rides along as on every route.

The page: `web/ui/bundle.js` (`window.SlothBundle`, included before
`app.js` into the one hashed script) with one `SlothBundle.mount()`
call per view; the copy buttons are `#bundle-btn-drawer`,
`#bundle-btn-alert` and `#bundle-btn-lookup`. The BLE drawer and the
TACDB platform view mount it through their own hooks, the spans
`#bundle-btn-ble` (app.js, with the scope) and `#bundle-btn-tacdb`
(`SlothFrrs.mountBundle()`); a span that carries the slot's id already
gives its button none, so no id is on the page twice. It copies with
`navigator.clipboard` where the page is a secure context (localhost,
https) and otherwise, on plain http over a tunnel or Tailscale where
`navigator.clipboard` does not exist, through a selected hidden
`<textarea>` and `document.execCommand("copy")`; when both fail it says
so and focuses the download. A browser takes the clipboard write only
inside the click (Firefox's `execCommand`, Safari's `writeText`), not
after an awaited fetch, so the bundle is fetched when the pointer or
focus reaches the button and a click that finds it ready copies at
once; one that does not hands `ClipboardItem` the fetch as a promise
where it exists (a secure context), and otherwise fetches and says
"ready: click copy again". What is kept is keyed on the scoped request
(a scope switch on the same id fetches again), expires after 60 s, and
is dropped whenever the view mounts the control again. A fetch that
failed (a closed alert's 404, a 503 from sloth.db, a 413) holds the
pointer off that request for 10 s, so a moving pointer does not build
one bundle per round trip; a click still retries, saying the kept
error meanwhile. In the drawer the control is mounted before the close
button, which stays at the right and follows it in the tab order. The minute is
for plain http, where a first click copies only text already kept: a
pointer resting past it re-arms the fetch on its next move, and a touch
tap, whose `pointerenter` and click arrive together, starts it on
`pointerdown`. `generated_at` dates the copy either way. The alert
page's control lives inside its heading, which loading and an error
rewrite, so it never names the alert before. The download is a Blob URL of the
document's own bytes: the one `.href =` on the page, and the only
`url(` forms the no-external-reference test admits
(`createObjectURL(` and `revokeObjectURL(`). The policy is unchanged.

### The tiles' views

| Tile | Opens | The number it shows is |
|---|---|---|
| throughput | `#activity?focus=throughput`: each interface's rx (over its band) and tx, 24 h, and the top hosts | the first interface's last rx bucket, drawn first |
| open anomalies | `#anomalies?state=open`: every open episode, the sensitivity and the kind chip not applied | the count of the cards |
| devices | `#devices?q=pass:latest`: sloth.db's devices whose MAC was in sloth's latest pass on the stream (`pass:latest`, a query term) | the stream's pass; the note says how many of them sloth.db holds |
| open alerts | `#alerts?state=open` | the rows |
| records/s | `#records`: records by type over the same five seconds, and the ticker of one type or all | the sum of the per-type rates (`/api/live`'s `types_rate`) |
| sensor health | `#health`: every source and attached receiver, the sensor host's status and its trends ([Sensor health](#sensor-health)), then capture, monitor, the stream, sloth.db and its freshness | the state word of the older panel |

Each opens with the filter it applies named in a bar above it, and a
way back. `test_alerts.c` asserts the counts on the demo's own data
(`web/tools/demo.c`, linked into the test binary): 23 devices and 23
rows, the open alerts and the Alerts page's open rows, the open
episodes and the open cards, the records/s and the rates' sum.

## Triage and the FRRS record

Owner request 2026-10-27; the model, the field-by-field mapping and the
owner's open questions are in
[`docs/web-frrs-spec.md`](../docs/web-frrs-spec.md). Two things:

- **Triage.** Every alert row, wherever it is drawn (the Overview's
  latest alerts, the Alerts page, History, the drawer's "alerts naming
  it", an alert's page), carries its state chip and the buttons
  *false*, *noise*, *incident*, *known*, *follow recommended* and, once triaged,
  *clear*: on hover or focus in a list (always on a device with no
  hover), always on an alert's page, which adds the optional note, the
  "by" name (kept in this browser) and every change as a table. States:
  `untriaged` (no row, or a *clear*), `false` (the rule fired on
  something it does not detect), `noise` (what it detects, expected
  here), `incident`, `known` (known good — expected traffic from a
  friendly or neutral emitter, the FRRS/EW affiliation sense: friend,
  or neutral per MIL-STD-2525's green; drawn green, `--tri-known`;
  triaged out like false/noise, never an incident; owner request
  2026-11-03, stored as 4, no schema step since nothing in slothweb.db
  rejects it). Triaged-out rows (`false`, `noise`, `known`) are dimmed,
  never removed; the open-alerts tile keeps the open count and says how
  many of them are triaged out beside it. Every change is a new row in
  slothweb.db's `triage` table (append-only: a change is undone by
  another), with when, the peer's address, the typed name and note, and
  for *follow recommended* the assessment's own words. Nothing goes back
  to sloth: triage changes no rule.
- **The FRRS emitter record.** For a Wi-Fi station, a BSSID or a BLE
  address, the Joint Spectrum Center's groups as sloth can fill them
  passively: **BEI** (the RF environment: channel, occupancy measured
  and advertised, co-channel networks, the regulatory domain seen,
  `RF_DEGRADED` and deauth floods, presence, anomaly episodes, which
  radios could hear), **SCS** (certification: the registrant's FCC
  grantee codes from the vendor research KB, `web/data/vendors/`, each
  with its source; compliance: Country, TPC,
  DFS, cipher, AKM, MFP, transition mode, WPS, the posture findings),
  **EC/S** (the parametrics: bands, width, PHY generation, beacon
  interval and its jitter, suites, MFP, TX power, vendor-IE hashes, WPS
  model, Multi-Link links, steering; a client's requested suites, rates
  and listen interval, its probe cadence and sequence-counter trail; a
  BLE advertiser's address type, PHYs, TX power, appearance, Company
  ID), **TACDB** (the operator's filing) and the **Report**: the COMINT
  seven (who, signal and radio, function, timing, technical, protection,
  peers). Every field is `{"v": value, "src": "where sloth keeps it"}`,
  `v` `null` meaning *not observed*, with `since` when the value came
  from the stream's latest record. Two sentences travel with every
  record: a single passive sensor has **no location axis** (`est_dist_*`
  is a distance from signal strength, not a position; the location
  slice's elements `loc-alert` and `loc-drawer` are another's), and
  **sloth decrypts nothing** ("language" is the protocols observed and
  whether they were in the clear). Shown on an alert's page (the
  emitter the alert names), in the device drawer and per emitter on the
  TACDB tab. The Report's signal item carries the emitter's RSSI
  against time (`series_rssi`): the last 24 h of its `rf.rssi.*` series
  ([Metrics](#metrics)) from the fine tier, in 48 cells of 30 min each
  the mean of its samples, with the window's min and max, the last
  value, the sample count and the `/api/series` query for the 30 days
  the minute tier keeps; `v` `null` and "no samples" when there is
  none. The page draws it as a text
  [S-meter](#the-s-meter-2026-11-11) (it was a sparkline of the cells
  until 2026-11-11): a full block for each lit segment and `▁` for an
  unlit one, a space at S9, for the last value on the emitter's band's
  scale (the BEI's `band`; 2.4 GHz for BLE), then the S reading, the
  last value and the window's min and max in dBm and in S, and which
  scale it used (`band unknown: 2.4 GHz scale` when the BEI names
  none). It is characters, so the report still copies as text.
- **The TACDB tab.** Units (site, area, room, vehicle, person, other;
  four deep) with their subordinate units; platforms listed by
  nomenclature, each with its equipment complement (the emitters it
  owns, each opening its EC/S and Report); suggestions from sloth's own
  correlations (S1 a sequence-counter trail at confidence 60 or more and
  a forward gap of 64 or less, S2 Multi-Link affiliation, S3 adjacent
  BSSIDs of one block on one channel, S6 a station both the host's card
  and the air heard), each saying "may be one platform", confirmed or
  dismissed by the operator; export and import as JSON Lines so another
  sensor shares it. Operator data: not captured and not scoped; a
  platform spans every capture scope, and each emitter row says which
  scopes heard it.

### The write surface

slothweb's first. Eight paths take POST, and nothing else does:

| Path | Body | Effect |
|---|---|---|
| `/api/frrs/triage` | `{"id":"d1234","state":"noise","note":"…","by":"…"}`; `id` an alert's or an anomaly's (`a` and sixteen hex digits, the `tid` of `/api/anomalies`); `state` one of `untriaged`, `false`, `noise`, `incident`, `known`, `recommended` | appends a row; `recommended` takes the assessment's state, `409 no_recommendation` when it names none (always, for an anomaly: no assessment judges an anomaly rule) |
| `/api/frrs/relate` | `{"op":"add","from":"a…","to":"d1234"\|"a…"\|"aa:bb:cc:dd:ee:ff"\|"aa:bb:cc:dd:ee:ff/1","note":"…","by":"…"}`, `{"op":"remove","from":"<either end>","link":7}` | a link between an anomaly and anything, or an alert and a device ([Anomaly triage and links](#anomaly-triage-and-links)); answers the `from` end's `/api/frrs/related` |
| `/api/frrs/triage/bulk` | `{"ids":"d1,s2,a…","state":"noise","note":"…","by":"…"}` | one state on up to 100 ids at one token, each written as `/api/frrs/triage` writes it, each id's outcome in `results` ([Incidents and bulk triage](#incidents-and-bulk-triage)) |
| `/api/frrs/incident` | `{"op":"add"\|"member"\|"close",…}` | an incident opened, its members changed, or it closed ([Incidents and bulk triage](#incidents-and-bulk-triage)) |
| `/api/frrs/note` | `{"op":"add","kind":"device"\|"ble"\|"ssid"\|"gnss"\|"aircraft"\|"aprs","id":"…","text":"…","by":"…"}`, `{"op":"retract","kind":…,"id":…,"note":7,"text":"<why>","by":"…"}` | a plain note on a subject held now, or the row that takes one back ([Notes on devices and the rest](#notes-on-devices-and-the-rest)); answers the subject's `/api/frrs/notes` |
| `/api/frrs/tacdb/unit` | `{"op":"create","name":"home","kind":"site","parent":null,"note":"…"}`, `{"op":"update","id":1,…}`, `{"op":"delete"\|"restore","id":1}` | |
| `/api/frrs/tacdb/platform` | `{"op":"create","nomenclature":"work laptop","class":"laptop","unit":1,"vendor":"…","note":"…","emitter_kind":"sta","emitter_addr":"…"}`, `update`, `delete`, `restore`, `{"op":"confirm","suggest":"<token>","unit":1}` | |
| `/api/frrs/tacdb/emitter` | `{"op":"add"\|"move"\|"remove"\|"restore","platform":1,"kind":"sta"\|"bssid"\|"ble","addr":"aa:bb:cc:dd:ee:ff[/type]","role":"primary","label":"…"}` | a live `(kind, addr)` belongs to one platform: `409 emitter_owned` |
| `/api/frrs/tacdb/dismiss` | `{"suggest":"<token>"}` | the pair is not offered again until either address shows newer evidence |
| `/api/frrs/import?mode=check\|merge` | an export (JSON Lines, below) | `check` (the default) validates every line and reports; `merge` writes the whole file in one transaction, or nothing |

Every write answers `200` with the stored row as the read routes render
it; the page redraws from that. A write passes, in order: the method
(`405`; a GET to a write path is `405` `Allow: POST`, a POST anywhere
else `405` `Allow: GET, HEAD`; under `--web-read-only` every POST is the
latter), the allow list (at `accept()`), the Host check (`421`),
**Origin** (exactly one, `http://` and the request's own Host, the port
defaulted to 80 on both sides: else `403 bad_origin`; a
`Sec-Fetch-Site` other than `same-origin` or `none` is `403
bad_fetch_site`), the **rate** (a token bucket per peer address, a
burst of 10 and 30 a minute, the import costing 5: `429 rate_limited`
with `Retry-After`), the **Content-Type** (`application/json`, an
optional `; charset=utf-8`: else `415 bad_content_type`), the
**length** (`Content-Length` required, `411`; any `Transfer-Encoding`
`400`; over 4,096 bytes, 8 MiB for the import, `413` before a body byte
is read, and the socket closed rather than drained), the **body** (the
stream's own JSON decoder: one flat object, `400 bad_body`; a member
the route does not take `400 unknown_member` naming it), and each
member to its bound (`note` 240 bytes, `by` 32, a name 64, a label 32;
an over-long value is `400 too_long`, never cut, and on
`/api/frrs/triage` the refusal carries the member, the bytes sent and
the bound, `{"error":"too_long","member":"note","length":242,"limit":240}`,
never the text (#181); the page says "note too long: 242 of 240 bytes"
beside the buttons, counts the note in bytes as it is typed (the
field's `maxlength` is the same 240, but counts UTF-16 units, so 121
accented letters fit the field and not the server), sends no note over
the bound, marks a change pending until the server answers and draws
the history from the server's rows only; a control byte, or a
bidirectional embedding or isolate control (U+202A to U+202E, U+2066
to U+2069), `400 bad_text`; addresses canonical). Then `404 no_such_alert`,
`404 no_such_platform`, `409 duplicate_name`, `409 unit_depth` (a
restore is checked again), `409 parent_deleted` and `409 unit_deleted`
(nothing comes back into a deleted unit), `409 emitter_owned`, `507
tacdb_full` (512 units, 2,048 platforms, 8,192 emitters live, and twice
each counting deleted rows, which a delete keeps), `507 triage_full`
(only with all 20,000 rows current, nothing superseded to fold, and a
decided state: a clear is always taken), `503 no_store` (no
slothweb.db), `503 store_busy`. A triage write that changes nothing
(the state it has, no new note) answers `200` `"unchanged":true` and
adds no row. An operator's change is never refused for room: past 64
changes of one alert its history folds (the first row and the newest
kept, the folded counted, "N older folded" on the alert's page), and at
20,000 rows the oldest superseded rows fold, imported ones first, then
those of alerts aged out (newest row over 7 days old), never an alert's
current row; `/api/health` `frrs` says `triage_rows`, `triage_cap`,
`triage_folded`, and the open-alerts tile warns from 90 % of the cap. From a shell the Origin has to be said:

```sh
curl -H 'Origin: http://127.0.0.1:8770' -H 'Content-Type: application/json' \
     -d '{"id":"d1234","state":"noise","note":"the NAS"}' \
     http://127.0.0.1:8770/api/frrs/triage
```

The writes go over a third connection to slothweb.db, the HTTP
thread's own, one short `BEGIN IMMEDIATE` transaction per request,
beside the store thread's writer and the read-only reader (WAL; a 250 ms
busy timeout either side). Nothing written is a stream string: the
tables hold addresses, slothweb's own words and operator text that came
only through a validated POST body.

**The import.** The body is an export: JSON Lines, the header first,
the `end` line last.

```
{"type":"slothweb-tacdb","format":"slothweb-tacdb","version":1,"exported":1792627199,"note":"…"}
{"type":"unit","id":2,"parent":null,"name":"home","kind":"site","note":""}
{"type":"unit","id":1,"parent":2,"name":"office","kind":"room","note":""}
{"type":"platform","id":7,"unit":1,"nomenclature":"work laptop","class":"laptop","vendor":"","note":"","confirmed":true,"origin":"operator"}
{"type":"emitter","platform":7,"kind":"sta","addr":"02:de:00:00:00:12","role":"primary","label":""}
{"type":"dismiss","rule":"S3","a":"02:de:00:00:00:a1","b":"02:de:00:00:00:a9","ts":1792627000}
{"type":"triage","alert_type":"PORT_SCAN","addr":"198.51.100.7","port":0,"first_seen":1792000000,"state":"noise","prev_state":"untriaged","via":"manual","basis":"","note":"the scanner","by":"jeff","peer":"127.0.0.1","ts":1792627000}
{"type":"end","lines":8,"complete":true}
```

It answers `{"mode":"check"|"merge","skipped":[{"line":n,"why":"…"}],
"skipped_n":n,"lines":n,"ok":true|false,"why":null|"…","merged":{"units",
"platforms","emitters","dismissed","triage"}}` (`skipped` lists 50 at
most; `merged` is what `merge` committed, or for a `check` what it
would: the check runs the same merge in its transaction and rolls it
back, so it reports every skip a merge would), `200` when the file
checked whole, `413` `too_many_triage` for more than 1,000 triage lines
(nothing merged, the rest of the file not read) and `400` otherwise. The check refuses the file
(nothing merged, `why` the first reason) when its first line is not the
header (`no_header`) or the version is not 1, a line is not one flat
object or names a member its type does not take, a value is past its
bound, two lines share an id, the `end` line is missing, not last, or
counts other than the file's lines (`truncated`) or says
`complete:false` (`export_incomplete`: the export stopped at its bound),
or the file holds more than the TACDB's caps, or a triage line's `ts`
is more than 300 s ahead of this clock (`future_ts`).
A merge then skips, each reported by line: a unit or platform already
here by name under the same parent (`already_here`; ids are never
carried across), one whose parent or unit did not merge
(`parent_not_merged`, `unit_not_merged`: never re-filed elsewhere), a
platform whose nomenclature a live one here has but none of whose
emitters is filed on it (`duplicate_name`: a name is not a device), an
emitter on another platform here (`emitter_owned`), a triage line no
newer than its alert's newest row here (`already_here` when identical,
else `older_than_here`: a file never puts an older decision over a later
one, and the same file twice merges nothing), one once imported rows
fill half the table (`import_share_full`), and anything at a cap
(`tacdb_full`). An alert keeps at most 8 imported rows, its oldest
imported folded, so a file never fills an operator's history. An
imported row records the importer as its `peer`, no `by`, and the
file's `by` and `peer` as `claimed_by` / `claimed_peer`, shown
"imported, claimed …" (and exported as those claims). A 1,000-line
import is one transaction with every statement prepared once; the
figures are in `test_import_time_over_socket`'s line of `make web-test`.
Units merge parent first whatever the file's order. A store error
mid-merge rolls the whole file back.

### The reads

| Path | Parameters | Answer |
|---|---|---|
| `/api/frrs/states` | `ids=` 1..16 alert or anomaly ids, comma-separated | `{"store":"open","triage":{"<id>":{"state","ts","via","history_n","prev_state","note","by","basis","peer","finding"}},"types":{"<id>":"PORT_SCAN"},"untriaged":[…],"missing":[…],"writes":true}` |
| `/api/frrs/history` | `id=` | the subject (`d<rowid>` of the finding's first sloth.db row, or the stream handle until sloth has written it), its descriptor (`type`, `addr`, `port`, `first_seen`: what an export re-attaches by), `current`, `recommend` and every row newest first |
| `/api/frrs/summary` | none | `{"store","writes","read_only","recommendations":"dir"\|"none","open":{"total","untriaged","false","noise","incident","known","out"},"rows","cap","near_cap"}`: the open incidents the tile counts, by their triage, in the request's scope, and how full the triage table is |
| `/api/frrs/recommend` | `type=` a name or number | `{"type","state":"noise"\|null,"basis","source","why_none":null\|"no_automatic_triage"\|"no_assessment","file","front_matter":{…}\|null}` |
| `/api/frrs/report` | `kind=sta\|bssid\|ble`, `addr=` (BLE `aa:…:ff/N`, N the address type) | the record: `emitter`, `sources`, `position_limit`, `content_limit`, `bei`, `scs`, `ecs`, `tacdb`, `report`, `alerts` |
| `/api/frrs/report/alert` | `id=` | `{"alert":{"id","type","emitter_from"},"record":…}`; the emitter is a MAC in the alert's key, else the device holding its `match_ip`; `record` `null` with a `reason` when it names none |
| `/api/frrs/tacdb` | `unit=`, `q=`, `deleted=0\|1`, `limit=` 1..200, `offset=` | `{"note","writes","units":[{id,parent,name,kind,note,depth,platforms,deleted}],"platforms":[{id,nomenclature,class,vendor,note,unit,unit_path,confirmed,origin,updated,deleted,emitters:[{kind,addr,role,label,origin,deleted,last_seen,scopes}]}],"matched","more","counts":{…,"caps":{…}}}` |
| `/api/frrs/tacdb/view` | `id=` | one platform, deleted emitters included |
| `/api/frrs/suggest` | `limit=` | `{"note","suggestions":[{token,rule,rule_name,kind,a,b,role_b,class,confidence,last_seen,nomenclature,evidence}]}` |
| `/api/frrs/related` | `id=` an alert's id, an anomaly's, a MAC or a BLE address `/` type (a held BLE end of a link also carries `"iface"`, the sensor its drawer opens by) | `{"id","kind":"alert"\|"anomaly"\|"device"\|"ble","label","held","store","writes","window_s":600,"links_cap":32,"links":[{"link","dir":"to"\|"from","kind","id","label","held","note","by","peer","ts","triage":{…}\|null}],"links_more","suggest":[{"kind","id","label","basis","first_seen","last_seen"}],"suggest_note","alerts_reached"}` and, for a device, `"anomalies":[{"id","label","anomaly":{…},"triage"}]` ([Anomaly triage and links](#anomaly-triage-and-links)) |
| `/api/frrs/notes` | `kind=`, `id=`, `before=` a note's number | `{"kind","id","held":true\|false\|null,"store","writes","cap":64,"text_max":240,"rows","live","folded","notes":[{"note","ts","text","by","peer","via":"manual"\|"agent","retracted":null\|{"ts","reason","by","peer","via"}}],"more","next"}`; an SSID's also `"ssid"`, `"ssid_k"`, `"ssid_np"`, its display form ([Notes on devices and the rest](#notes-on-devices-and-the-rest)) |
| `/api/frrs/incidents` | `state=open\|closed\|all`, or `id=N` | the incidents newest first, or one with its members ([Incidents and bulk triage](#incidents-and-bulk-triage)) |
| `/api/frrs/notes/marks` | `kind=`, `ids=` up to 24, comma-separated, not percent-encoded | `{"kind","store","marks":{"<id>":{"n","agent","ts"}}}`: the ids holding a standing note |
| `/api/frrs/export` | none | `slothweb-tacdb.jsonl` (attachment, the import's format above): a header line, every live unit (parents first), platform and emitter, every dismissal, every alert's triage row by its descriptor (an anomaly's rows and the links stay on this sensor), an `end` line counting the lines and saying `complete`; deleted rows stay on this sensor; `507 export_too_large` past 8 MiB |

`/api/alerts` takes `triage=any|untriaged|triaged|out|false|noise|incident|known`
(`out` is `false`, `noise` or `known`)
(the Alerts page always sends it): every row then carries
`"triage":{"state","via","ts"}` and the answer `triage_counts`, counted
before the filter, so a row the filter leaves out is counted, never
silently gone. Without the parameter the answer is byte for byte as
before. `/api/health` gains `frrs` (writes, rows, the TACDB's counts,
the ledger's sizes and evictions, refusals by kind).

The stream facts (the latest beacon, `wifi_regulatory`, `wifi_mld`,
`wifi_assoc_req`, `pnl_client`, `seqnum_correlation`, `ble_device`, TLS
server names and the cleartext protocols per address) are held in
memory only, bounded and least-recently-seen out, and lost at exit:
after a restart "not observed" means "not in the stream since". sloth.db
is read through the same column allow-list as every route, extended
with the parametric columns the record names (suite identifiers, rates,
counts, hashes; no secret among them).

"Follow recommended" reads `--web-assessments DIR/<TYPE>.md` front
matter until the other session's compiled table
(`web/src/web_alertasm.{c,h}`) lands: `noise` only where
`false_positive_risk` begins `high` **and** `noise_verdict` begins
`noisy` or `very noisy` (eight of the 72 types), because `noise_verdict`
describes how the rule counts, not whether an alert is real
(FRAG_PLAINTEXT is "very noisy" with a `low` false-positive risk). An
assessment below that bar draws the button "no automatic triage:
<risk>", which does nothing; no assessment, "no recommendation yet".
At 480 px and under the button carries its short label. The
assessments judge a rule, not an alert, so
`false_positive_risk: high` never marks an alert `false` and
`severity_assessment` (`agree`, `too high`) never makes one an
`incident`; the page shows both beside the buttons (open question Q3).
Under `--web-read-only` a page loaded before the restart says
"read-only" for the server's plain `405`.

### Anomaly triage and links

Owner request 2026-11-11: "add ability to add triage notes like we have
on alerts for anomalies. allow them to be related where possible".

**One mechanism.** An anomaly (slothweb's own finding,
[Baselines and anomalies](#baselines-and-anomalies-m3)) is triaged by
the alert's route, states, note bound, history, folding and cap: the
same `POST /api/frrs/triage`, the same rows in `triage`, read by the
same `/api/frrs/states` and `/api/frrs/history`. What differs is the
subject. Every episode's JSON carries `tid`, `a` and sixteen hex
digits, the FNV-1a 64 of the rule's name, the metric's name and the
key. It names the **finding**, every episode of that rule, metric and
key, exactly as an alert's triage names every incident of its key
(`d<rowid>` is the finding, reopens included): a device marked
`known` for being present at an unusual hour stays known when it does
it again, as a triaged-out alert stays triaged out when it reopens. An
episode's own `id` could not do this (it restarts at 1 once every saved
episode has aged out). What an anomaly adds, because its episodes are
further apart than an alert's incidents: every row records the episode
it was written on (`"episode"`, that episode's `first_seen`), and when
the episode held now is another one the state is shown as
`"carried":true` ("earlier episode" beside the chip, "decided on an
earlier episode, not on this one" in the panel). A triaged-out state
(`false`, `noise`, `known`) dims the card whether it is this episode's
or carried, the "earlier episode" mark still on the dimmed card (owner
ruling 2026-11-11: the point of marking a nightly recurrence known is
that it stays quiet); a carried `incident` is never dimmed. Saying the
state again makes it this episode's (a row, even with no new note). So a note never reads as if it had been written about a
later episode.

The id is a hash of values the answer already shows, so it discloses
nothing, but FNV is not collision-proof against a chosen key (a MAC is
chosen by its sender). The store therefore keeps the rule, metric and
key beside the id (`anom_subject`), and an id whose episode in the
engine is not that descriptor is refused on every route, `409
id_collision`, never joined to the other's notes. An id neither the
engine nor the store holds is `404 no_such_anomaly`: a note cannot be
written on an anomaly that does not exist. Once the engine lets an
episode go (a day after it closes) the id still resolves from the
store: `/api/frrs/history` answers its notes with
`"anomaly":{…,"held":false}`.

Nothing is ever recommended for an anomaly (`"recommend":null`,
`409 no_recommendation`): the assessments judge sloth's alert rules.
The TACDB export carries alerts' triage only; an anomaly is this
sensor's own baseline's finding and its rows stay here. `/api/health`
`frrs.triage_rows` counts both kinds (they share the cap), and gains
`anomaly_subjects` and `links`.

**The page.** Every anomaly card (the Overview's top five, the
Anomalies view, the drawer's, an alert page's) carries its state chip
and a *triage* (or *notes*) button, which opens the anomaly's panel:
the four state buttons and *clear*, the note (counted in bytes against
the same 240), every change newest first with the episode it was made
on, the links, the candidates, and "link to" (an alert id, an anomaly
id, a MAC or a BLE address with its type). The "by" name is the one
kept for alert triage (`frrs.by`). The table form of the Anomalies view
carries the same chip and button on every row, so every place an
anomaly is listed can be triaged; the presence strip's episode marks
do not. An alert's page gains *linked anomalies and devices* under its
triage panel, the device drawer *anomalies and alerts linked to this
device* and the BLE drawer the same for the advertiser, each with a
"link to" field. One module, `web/ui/notes.js` (`SlothNotes`), six
guarded calls in `app.js`; its writes go through `frrs.js`'s own
`post()`.

**Links.** `POST /api/frrs/relate` `add` makes a link between two
things, in either order: an anomaly to an alert, another anomaly, a
device (a MAC) or a BLE advertiser; or an alert to a device or a BLE
advertiser with no anomaly in it (owner ruling 2026-11-11). Alert to
alert and device to device stay refused (an alert's page already lists
its other alerts by the device they name, and no view lists a device's
devices), as does a thing to itself: `400 bad_pair`. A BLE advertiser
is named as the TACDB names one, `aa:bb:cc:dd:ee:ff/N`, its address and
address type (0 to 3; the anonymous address, type 255, is every
anonymous advertiser and is `400 bad_id`): the BLE view's row is that
plus the sensor that heard it, and one advertiser two sensors hear is
one end. That is all the identity an advertiser has: a private address
rotates, and its link then reads "no longer held". No name of it is
stored; its label is empty and the id is what is shown. Both ends are
resolved against what exists first (`404 no_such_alert`,
`no_such_anomaly`, `no_such_device`, `no_such_ble`: a device is one
sloth.db, sloth's latest pass, the ledger or an anomaly's key holds; a
BLE advertiser one the ledger holds, which is memory refilled from the
stream, so after a restart it is not held until heard again; `400
bad_id`), the same pair again in either
direction answers the link that is there (`"unchanged":true`), and a
finding past 32 links or the table past 8,192 is `507 links_full` (a
link is never dropped to make room). `remove` names the link's number
and one of its ends (`404 no_such_link` otherwise). A link is listed
from both ends by `/api/frrs/related`, with the other end's label, its
current triage, and `"held"`: `false` when the alert is no longer in
sloth.db (retention, `--db-compact-alerts`, a rebuilt file) or the
anomaly no longer in the engine, when what is left is the label the
link kept and the page says "no longer held" with no *open* button;
such a link can still be removed, and a new link to something gone is
refused.

**Candidates** ("possibly related"). Never automatic and never stored:
`/api/frrs/related` offers, for a finding held now, the findings on the
**same MAC or the same IP address** whose `[first_seen, last_seen]`
span overlaps its own or lies within **600 s** of it, both edges
inclusive. Ten minutes is the longest any anomaly rule looks back
before it can fire (A7's window and A8's DNS window; A1 needs three
minutes), so an episode's `first_seen` can trail its cause by that much
and no more. An anomaly is offered the other anomalies on its key, the
stream's incidents and sloth.db's alerts naming it (the newest 32 read,
inside the request's 250 ms budget; `alerts_reached` says how far back
when the budget stopped the walk); an alert is offered the anomalies on
the address it names. At most eight. A finding's span is the
finding's: an alert reopened over a week overlaps everything on its
address in that week. No anomaly rule is keyed by an SSID and a BSSID
is a MAC, so those two subjects are the ones there are; A10 (the
sensor) and A2's or A4's burst episode have no key and get no
candidates. The words are a fact about the two rows, "same device,
overlapping in time", "same address, within 10 minutes", with the
sentence "possibly related, not established: these share a subject and
a time; a passive sensor corroborates, it does not confirm"; never a
cause. One press of *link* accepts one (the same `add`); until then
nothing is written. On the suite's 30,000-row alerts table the read
took 9.5 to 14.5 ms over six runs on the reference host, loaded
(`test_suggestions_stay_inside_the_budget` prints it).

**The same guards.** Both writes are paths of `web_http.c`'s one POST
list and pass `web_frrs_gate()` before a body byte is read, as the
alert's does: Origin, `Sec-Fetch-Site`, the rate bucket, Content-Type,
the 4,096-byte body, `--web-read-only`. A note is at most 240 bytes of
valid UTF-8 with no control byte and no bidirectional control, refused
whole when it is not, stored as typed, served through the JSON writer's
escape and drawn with `textContent`; nothing in the page turns text
into markup or a link.

**The evidence bundle** ([Copy JSON](#copy-json-the-analysis-bundle))
gains `alert.related` and `device.related`, `/api/frrs/related`'s
answer: the links, each linked anomaly's triage, a device's own
anomalies' triage, and the candidates marked in the glossary as not
stored.

`web/tests/test_notes.c` holds it, the alert triage tests of
`test_frrs.c` again on an anomaly's id (the round trip and its escape,
the states, the cross-origin, body, over-limit and GET refusals, the
credential scan, the unchanged write, the folding history, the cap),
then what is new: the decision across a closed store and a re-detected
episode, carried on a later one, kept with none held; the collision
refused; alert and anomaly rows apart and the export alerts-only; links
from both ends, their guards and bound, a dangling end; the
candidates' subject and both edges of the window to the second, nothing
stored until accepted; the read on the large table; the bundle; the
link's write over a socket; and `notes.js` with its drawing and writing
functions pinned whole. `test_store.c` holds the v8 to v9 migration and
its failure.

`web/tests/test_frrs.c` holds it: hand-built requests through the
router and over loopback sockets (a cross-origin, doubled-Origin,
`Sec-Fetch-Site` and missing-Origin write refused; `text/plain`, an
unknown member, a 241-byte note, a control byte refused; an oversize
body answered `413` before it is read; a GET to a write path `405`;
`--web-read-only`; the rate limit), the credential and stream-string
scans of the store file, the finding set once, triaged-out rows counted
and never dropped, the record's two limits and every source it names
checked against sloth.db's DDL and `src/jsonl.c`, the TACDB's rules and
an export merged into a fresh store (a reparented unit kept in place,
a headerless or cut-short file merging nothing and leaving no
transaction behind, no platform merged on its name alone), the bounds
on deleted rows and imported triage, an alert's history folding past
64 and its imported share past 8, a write that changes nothing adding
no row, the table at a lowered cap folding superseded rows (imported
first) and always taking a clear, a check reporting the merge's own
skips (a unit cycle), the bidirectional controls refused, a body's
deadline scaling with its length (a slow import answered, a drip cut
off), the 1,000-line import timed, the suggestion rules against
hand-built rows, the recommendation against the assessments' own
front-matter lines and against the shipped files by name
(FRAG_PLAINTEXT and SMB1_USE get none), the Report's `series_rssi` from
hand-built beacon, probe and `ble_device` lines (the cells, min, max and
history query; each kind its own metric; a day's window; "no samples";
the device cap's eviction counted on `/api/health`) and the page's
sparkline pinned as served; `test_store.c` the v5 to v6
migration and its failure. Each absence assertion names the mutation it
was seen red under.

### Writes by an agent

Owner request 2026-11-11: an agent on the same machine reads slothweb
through `slothweb-mcp` (`web/mcp/`, `make web-mcp`;
[docs/wiki/slothweb-mcp.md](../docs/wiki/slothweb-mcp.md) has its tools,
its flags and how to register it) and writes triage, notes and links.
Its rows are marked `via: agent`, and the mark is decided by slothweb
from what the request proves, never from what it says: a page could
otherwise label its writes as it liked, and an agent could pass as the
operator. `web/src/web_agent.c`.

`--web-agent-secret PATH`: at start slothweb reads 32 bytes from
`/dev/urandom`, writes them as 64 hex digits to `PATH` (created `0600`
by descriptor, never through a link, put in place by `rename`; a file
already there that is not a private regular file of this user is
refused and left as it is) and keeps them in memory: a new secret every
run, the file removed at a clean exit. slothweb says `agent writes: a
loopback POST carrying the secret in PATH (0600) writes triage, notes
and links, recorded via agent`. Without the flag there is no agent path.

`--web-agent-group NAME` (owner ruling 2026-11-11: `slothweb-mcp` reads
the secret through group permission, with no sudo rule): the group is
looked up at start (`getgrnam_r`); the file is created `0600` under its
temporary name, given `(this user, NAME)` with `fchown` and made `0640`
with `fchmod` there, and only then renamed into place, so it is never
readable by anyone else at any instant. The kernel lets slothweb give a
file only a group its user is a member of, so slothweb's user must be
in `NAME`; otherwise, or with no such group, it refuses to start. A file
already at `PATH` is then accepted as its own when it is `0600`, or
`0640` with that group; another group or any other bit is refused and
left as it is. The shipped unit puts it in `/run/slothweb`
(`RuntimeDirectory=slothweb`, `0711`), because its state directory is
`0700`; [docs/wiki/slothweb-mcp.md](../docs/wiki/slothweb-mcp.md)
section 7 has the group, the flags and the re-login the operator's new
group needs.

`web_agent_check()` is the rule, run by `web_frrs_gate()` before a body
byte is read and again by the router:

| The POST has | It is | Recorded |
|---|---|---|
| no `X-Slothweb-Agent` header | the browser's, held to `Origin` and `Sec-Fetch-Site` exactly as before | `via: manual` or `recommended`; never `agent` |
| the header once, equal to the secret (constant-time), from a loopback peer, with no `Origin` and no `Sec-Fetch-Site` | the agent's | `via: agent` |
| the header, otherwise | `403`: `agent_off` (no secret configured), `bad_agent_secret`, `agent_not_local`, `agent_with_origin` | nothing; never tried again as a browser's |

The secret stands in for the `Origin` check on that one path only.
`Origin` is a CSRF defence, and CSRF needs a browser: a page cannot
read the file, cannot send the header across origins without a
preflight slothweb never answers, and cannot strip its own `Origin`, so
a request carrying both is refused as a page's. The browser's path is
unchanged. The agent's path is narrower than the page's: triage, notes
and links only (`403 agent_path` on the TACDB routes and the import), a
name required (`400 missing_by`), no "follow recommended" (`400
bad_state`), it removes only links an agent made (`403
not_agent_link`), and it takes back only notes an agent wrote (`403
not_agent_note`, owner ruling 2026-11-11; any agent's, never the
operator's, while the page takes back any). The token bucket applies, in a bucket of the agent's
own per peer (`a/` and the address), so it can neither spend the
operator's allowance nor write unbounded; limited, it gets the same
`429` and `Retry-After`. `/api/health`'s `frrs.agent` is
`{"enabled","writes","refused"}`, never the secret. What this does not
stop: another process of slothweb's own user, or root, can read the
file; `by` is a label, as the operator's is.

`web/tests/test_mcp.c` holds it (`test_whose_write`,
`test_write_refusals`, `test_rate_limit`, `test_secret_file_rules`,
`test_secret_file_group`: the file's mode and group with one of the
test's own supplementary groups configured, an unknown group, a group
the user is not in, a `0640` file of the group accepted and one of
another group or with other bits refused, and `secret_no_access`):
each line of the table, a browser's write never marked agent, a wrong
secret refused by the gate and by the router each on its own, a
near-miss and a prefix of the secret, the three routes and no other,
the bucket apart from the operator's, the file's mode and what it will
not overwrite, and the same over a loopback socket.

### Notes on devices and the rest

Owner request 2026-11-11: notes on devices and on the other things the
page lists, readable and writable by an agent as well as the operator.
An alert's or an anomaly's note stays its triage note, above; this is
the plain note for what is not a finding. `web/src/web_notes.c`,
`web/ui/subnotes.js` (`SlothSubNotes`).

**Subjects.** Six kinds, each with an id validated whole to its own
format, and a note is added only to a subject slothweb holds now:

| `kind` | `id` | Held when |
|---|---|---|
| `device` | a MAC, canonical | an anomaly is keyed by it, the stream's latest pass, the ledger or sloth.db has it (as a link's device end) |
| `ble` | `aa:bb:cc:dd:ee:ff/N`, N the address type 0..3 | the ledger holds that address and type. The anonymous address (255) is every anonymous advertiser and is refused |
| `ssid` | the base64url of its 1..32 octets, as `/api/wifi/ssid`'s parameter | sloth.db's `beacon_aps`, `beacon_ap_ssids` or `pnl_ssids` names those octets (`503 no_sloth_db` without `--sloth-db`). Never the display form: two SSIDs can share one. The empty SSID (`-`) is every hidden network and is refused |
| `gnss` | `gnssid.prn` in decimal, 0..127 and 0..32767 | the GPS Sat table holds that satellite |
| `aircraft` | six lower-case hex digits, `~` before a non-ICAO address | the ADS-B table holds it, live or gone |
| `aprs` | a callsign with its optional `-SSID` | the APRS table holds it, live or gone |

Left out, each because the page has no identity for it that survives a
reload: a flow (a pair of addresses and a port, re-keyed every
window), a host with no MAC (an address a DHCP lease reassigns; the
Lookup card answers by address and names the MAC when there is one), a
fleet peer's sighting (its key is the peer's, and the peer has its own
notes), and a TACDB unit or platform (they carry their own `note`
field). Alerts and anomalies are not kinds here on purpose.

**A note** is text (240 bytes, the triage note's rules: UTF-8, no
control or bidirectional-control character, over-long refused with
`{"error":"too_long","member":"text","length":N,"limit":240}` and
never cut), who (`by`, 32 bytes, optional from the page), the peer's
address, the time, and `via`. It is never changed and never deleted:
`retract` writes a row naming it, with who and an optional reason, and
the note stays listed, struck, with who took it back. The page may take
back any note; an agent (`via: agent`, [Writes by an agent](#writes-by-an-agent))
only one an agent wrote: the operator's is `403 not_agent_note` and
nothing is written, whether or not it was already taken back. Reading and
retracting need no holder, so a note outlives what it was written on
and its listing says `"held":false`.

**Bounds.** A subject holds 64 rows and the table 20,000. At either,
the oldest retracted notes fold with their retractions (the count kept
as `folded` on the subject's oldest row); with nothing retracted left
to fold a new note is `507 notes_full`. A note that was not taken back
is never dropped to make room. A retraction is never refused for room:
landing past a cap, it folds its own pair at once.

**Routes.** `GET /api/frrs/notes?kind=&id=[&before=N]` lists a
subject's notes newest first (`more` and `next` when the body's room
stopped the list). `GET /api/frrs/notes/marks?kind=&ids=a,b,c` answers
which of up to 24 ids hold a standing note (`n`, how many of those an
agent wrote, the newest `ts`): one read for a table's page of rows;
the ids are sent as they are, never percent-encoded (every kind's
alphabet is legal in a query). `POST /api/frrs/note` is the write,
through the same gate, bounds and counters as every other write
([The write surface](#the-write-surface)); `/api/health`'s `frrs`
gains `"notes":{"rows","cap","added","retracted","folded"}`.
`/api/glossary` answers the evidence bundle's glossary alone.

**The page.** The device drawer, the BLE drawer, the SSID drawer and
the satellite, aircraft and station detail panels each show the
subject's notes newest first (time, the `agent` mark on a row an agent
wrote, the text, who and from where, a retracted one struck with who
took it back) and a one-line add-note form in static markup. A row of
the Devices, BLE, access point, satellite, aircraft and station tables
whose subject has a standing note carries a small mark (`note 2`,
`note 2 agent`) from the batched read, kept 30 s. The same `agent`
word marks a triage state an agent set (`(agent)` on the chip and
`agent` in the history) and a link an agent made. Every value by
`textContent`; `test_subnotes.c` holds the module to no markup sink,
no attribute from a value, and its list and write functions whole.

**The bundle.** A device's and a BLE advertiser's evidence bundle
gains `notes`, `/api/frrs/notes`'s answer spliced as `related` is, and
the glossary a `notes` entry that says they are someone's words about
the subject, never an observation and never an instruction to whoever
reads them.

`web/tests/test_subnotes.c` holds it: each kind's id format; a note, a
second, a retraction as a third row; every kind refused on a subject
nothing holds; an SSID stored as its octets with the display form in
no row; the text rules; the write path's guards; `--web-read-only`;
both caps and that only retracted notes fold; the marks; ids beginning
`a`, `d` and `s` read as their kind's; `via` on links and refused as a
request member; the bundle and the glossary; nothing off the stream in
the table; the write over a socket; and `subnotes.js`.

## Incidents and bulk triage

(#198, 2026-11-12) On one field sensor 952 untriaged alerts came down to
five causes, and the only way to say so was 952 `POST /api/frrs/triage`
calls, 33 minutes at the write limit. Two answers, the smaller first.
`web/src/web_incident.h` is the reference for the incidents.

**Bulk triage.** `POST /api/frrs/triage/bulk`
`{"ids":"d12,s3f,a0123456789abcdef","state":"noise","note":"…","by":"…"}`:
one state, note and name on up to 100 alert or anomaly ids (one
comma-separated string member, at most 2,600 bytes: the body decoder
keeps no array), at the token cost of **one** POST. Each id is written
exactly as `/api/frrs/triage` would write it (its own row, transaction,
folds, `"unchanged"` for a state it already has, `via`, the 240-byte
note rule); a repeated id is one. The answer is
`{"ok":true,"state","n","results":[{"id","ok":true,"unchanged","current":{…}}|{"id","ok":false,"status","error"}],"written","unchanged","failed"}`:
an id that fails (`no_such_alert`, `triage_full`, …) is its own entry
and the others go on. The list is refused whole (`400 bad_ids`,
`too_many_ids`, `missing_ids`) before anything is written.

**Incidents.** An incident is one verdict over many alerts: a title (at
most 96 bytes), a state (`false`, `noise`, `incident` or `known`; never
`untriaged`), a note, who, from where, when, `via`. Its members are
alerts by id (resolved and filed as a triage row files one, so a member
survives the stream handle aging out and a rebuild of `sloth.db`) and
standing filters: an alert type, an address (`ip` or `mac`: the address
the alert's triage descriptor names, its IP, else the MAC in its key)
and a first_seen window (`from`, `to`, Unix seconds, either open), at
least one of the three, at most 8 live on one incident. An alert a
filter takes is a member whenever it began, until the incident is
closed; one that began after the filter was set is **auto-joined**, and
after the close a filter takes no alert that began later. Membership is
read, never written: an alert joining costs no write.

**What a member reads as** (decided for #198): its own newest triage row
when that row is a decision (not a clear) at or after the incident's
decision (its open, or its close when it has one), else the incident's
state, note, who and `via`. The newer statement wins; on the same second
the alert's own, the more specific one. Clearing its own row returns it
to the incident. An alert in two incidents reads the one decided last.
Anomalies are not members (an anomaly's id already names every episode
of it). The fleet export's verdicts are the triage rows alone.

**Where it shows.** A member's triage (on `/api/frrs/states`,
`/api/frrs/history`'s `current`, `POST /api/frrs/triage`'s and the bulk
route's `current`) gains `"incident":{"id","title","state","governs","joined":"member"|"filter","auto"}`,
and an `/api/alerts?triage=` row's `triage` gains
`"incident":{"id","governs","auto"}`; `governs` false means its own
later verdict stands. Only a member carries it: every answer about an
alert in no incident is byte for byte what it was before
(`test_incident.c :: test_untouched_without_an_incident`).
`/api/alerts` takes `incident=none|any|<id>` (the rows in no incident,
in one, in that one), which runs the triage join; the triage counts are
then over those rows. `/api/frrs/summary`'s open counts and the
`triage=` filter count a member as its incident's state.

**Routes.**

| Route | Body or parameters | Answer |
|---|---|---|
| `POST /api/frrs/incident` | `{"op":"add","title","state","note","by"[,"ids":"d1,s2"][,"type"][,"ip"\|"mac"][,"from"][,"to"]}` | the incident and, with ids, each id's entry in `results` |
| `POST /api/frrs/incident` | `{"op":"member","incident":N,"ids":"…"}`, `{"op":"member","incident":N,"type":…,…}` or `{"op":"member","incident":N,"remove":M}`, one change a call | `unchanged` for a member already there or already removed; `409 incident_closed` |
| `POST /api/frrs/incident` | `{"op":"close","incident":N[,"state"][,"note"],"by"}` | the close is a row (one per incident); a second close is `unchanged` |
| `GET /api/frrs/incidents` | `state=open\|closed\|all` | `{"store","writes","cap","title_max","ids_max","incidents":[{"id","title","state","open","decided","ts","opened_state","note","by","peer","via","closed":null\|{"ts","state","note","by","peer","via"},"alerts","filters"}],"more"}`, newest first, at most 200 |
| `GET /api/frrs/incidents` | `id=N` | `{"store","writes","incident":{…},"members":[{"member","kind":"alert","id","type","addr","port","first_seen",…}\|{"member","kind":"filter","type","addr","from","to",…}],"more","removed"}` |

A close takes the next id of the `incident` table, so incident numbers
have gaps after a close. Each write is one token, `/api/health`'s
`frrs` gains `bulk_posts` and `incidents` (`rows`, `opened`, `closed`).
Append-only: nothing is deleted or rewritten; a removal is a row naming
the member (`removes`), a close a row naming the incident (`closes`).
Bounds: 1,024 incidents, 20,000 member rows, 4,096 on one incident, 8
live filters on one; past any of them a write is `507` (these rows are
the operator's and never fold).

**The agent's path.** `slothweb-mcp` writes all of it (`via: agent`).
An agent opens incidents, adds members to any open one, removes only
members an agent added (`403 not_agent_member`) and closes only
incidents an agent opened (`403 not_agent_incident`): a judgement call
for #198, mirroring the notes and links rule, so an agent never ends
the operator's statement.

**slothweb.db v12.** Two tables, `incident` (`id`, `closes`, `title`,
`state`, `note`, `who`, `peer`, `via`, `ts`; a partial unique index keeps
one close per incident) and `incident_member` (`id`, `incident`, `kind`
0 an alert or 1 a filter, `subject`, `finding`, `type`, `addr`, `port`,
`first_seen`, `t_from`, `t_to`, `who`, `peer`, `via`, `removes`, `ts`)
with five indexes. Additive, one transaction; a v11 file is migrated in
place and a failed step leaves it at v11 (`test_store.c ::
test_v11_file_is_migrated`, `test_v11_failed_step_leaves_file_unchanged`).

**The page.** The Alerts page's incidents panel (`web/ui/incident.js`,
`incident.css`): one row per incident (state chip, number, title, its
alert count by id and filter, who, when, `close`), opened to its filters
and its alerts drawn as the list draws them, each removable when added
by id. "Group the list by incident" (on by default, kept as
`inc.group`) asks the list for `incident=none`, so the list holds only
the alerts in no incident. A toggle box on every alert row selects it;
the selection takes a bulk verdict (100 ids a POST), opens an incident,
or joins an open one. "From the list's type or address" opens one whose
filter is the type picked and an address typed in the search, the
window as when they began; what a filter cannot hold (severity, state,
other words) is said, not dropped. A member's chip says `(inc. #N)`,
`, own` when its own later verdict stands, `, auto` when auto-joined;
the alert page says which incident it is in and links to it
(`#alerts?incident=N`). Every value by `textContent`; the theme's
tokens only, so light and dark follow.

## BLE

Owner request 2026-10-27 ("add bluetooth to the web ui"). The tab after
Lookup (key `0`: every other digit was taken, and the TUI's `*` is no
browser hotkey; TACDB, after it, carries no digit, since its `0` was a
label and never a binding) is the TUI's `[*]` BLE view (`src/views/ble.c`,
`docs/views/ble.md`, [docs/wiki/ble.md](../docs/wiki/ble.md)) at data
and colour parity, served from `/api/ble`, `/api/ble/alerts` and
`/api/ble/{addr}` ([Routes](#routes)). Everything in it comes off the
stream: the `ble_device` record (one row per advertiser as one sensor
heard it: the host controller under `--bt-monitor` and an Ubertooth
under `--bt-capture` hearing the same address are two rows, and their
counts are never summed), the `ble_alert` record (the structured
companion of a `BLE_ADV_FLOOD`, `BLE_HID_UNEXPECTED` or `BLE_WATCHLIST`
finding, standing until the `alert.resolve` of the same key) and the
Bluetooth members of `sensor_health` (`btmon_*`, `ble_*`, `btcap_*`,
the banded `ble_rot_*`). sloth.db has no BLE table, so slothweb keeps
the rows itself (`web/src/web_ble.h`): 1024 advertisers in memory, the
least recently heard row with neither a HID flag nor a watch category
evicted and counted (an address flood turns over its own rows, never
the keyboard or the tracker; the oldest of all only when every row is
flagged), a row's `adv_count` and `last_seen` only moving up as the
store's upsert keeps them; 128 findings; the latest
sensor_health's block; and the v7 tables of slothweb.db
([slothweb.db v7](#the-ble-tables-slothwebdb-v7)) so a restart keeps
the history. Nothing is sent: sloth never scans, connects or reads
GATT, and neither does slothweb.

The table is the TUI's, column for column (its cells are the TUI's
strings), then the columns the owner asked for that the TUI's detail
shows and its table does not, with every column sortable and resizable
through the one `DataTable()`. The `kind` column, the `T` letter's
tooltip and the drawer's address line say the address in words: a random address's
two top bits (Core v5.4 Vol 6 Part B §1.3.2) make it `random static`,
`random RPA` (a resolvable private address, the rotating kind) or
`random NRPA` (`addr_kind` in the row; `public`, `resolved public`,
`resolved random`, `anonymous`):

| Column | TUI cell | Source |
|---|---|---|
| address | `xx:xx:xx:xx:xx:xx` | `addr` |
| T | `P` public, `R` random, `p`/`r` resolved identity, `?` anonymous | `addr_type` (0, 1, 2, 3, 255) |
| kind | the address in words (above); a column the TUI lacks | `addr_kind`, from `addr_type` and the address's top two bits |
| sensor | the iface | `iface` (`bluetooth-monitor`, `ubertooth`; anything else `other`) |
| rssi | the dBm, `-` without one | `has_rssi`, `rssi` |
| dist (est) | `rf_dist_cell()`'s full form: `~5m room ↘` (`<1m`, `Nm`, `>1km`; `imm`/`near`/`room`/`bldg`/`far`; ↘ approaching, → steady, ↗ leaving); `-` for no estimate | `est_dist_m`, `est_dist_band`, `est_dist_trend` (sloth's own estimate, `src/rf_distance.c`, `research/papers/rssi-distance-estimation.md`; never re-derived, absent means no estimate) |
| adv | `count_cell()`: whole below 100000, then `Nk`, `NM` | `adv_count` |
| age | `age_cell()`: `Ns`/`Nm`/`Nh`/`Nd` since last heard | `last_seen` |
| hws | `H`/`-` HID, `W`/`-` watchlist, `~`/`-` a one-channel sample | `hid`, `watch_category`, `sampled` |
| advertises | `summary_cell()`: `"name" mfr 004c/10 svc 180f sd 181c app 03c1`, most specific first, `-` when empty; the name in its display form with the non-printable marker when anything was escaped | `name`, `mfr_id`/`mfr_subtype`, `uuid16`, `svc_data_uuid16`, `appearance` |
| sig names | the Bluetooth SIG's names for the company, service and appearance (`web/data/btsig/`, below); a column the TUI lacks | `mfr_name`, `uuid16_name`, `svc_data_name`, `appearance_name` |
| best | the strongest RSSI seen (the TUI's detail shows it) | `rssi_best` |
| adv/s | the rate between this row's records, coarse (below) | `adv_rate` |
| first | first heard, as a stamp | `first_seen` |
| pdus | the PDU types heard, from the sticky mask | `pdu_mask` |
| watch | the `BLE_WATCHLIST` category, a category and never an identity | `watch_category` |

A row is one colour, as the TUI draws it: `--tui-bright` (`d-bright`)
for a HID or watchlisted advertiser, `--tui-normal` otherwise. The
address takes no `--tui-dim`, the name no hash hue, the RSSI no heat,
and no row the monitor radio's ground: the TUI's BLE view and its
packets band put no BLE row on `CP_MON_ROW`, so `MON_TYPES` is
unchanged and `web/tests/test_tui_colors.c`'s pin of it against
`src/jsonl.c` stands. Above the table is the TUI's header line (`BLE
advertisers: N` bright, with N sloth's own count as the TUI has it,
`sensor_health`'s `ble_devices`, and `(R rows kept here)` dim beside
it, `HID: n` and `watchlist: n` at `tui_heat(0.5)` when above zero else
dim, then `standing floods: n` dim: the TUI's `flood keys` is
`ble_flood_count`, the flood detector's tracked windows, which no
record carries, so the web counts what it has under its own name) and, with `--ble-rotation-hints` on, its
rotation-hints block with the TUI's sentences verbatim; the estimate
itself (`ble_rot_distinct()`) is not on the stream, only the hint
count as a decade band, and the block says so; its address count is
sloth's live `ble_devices`, the window the estimate covers, not the
rows kept here. The empty state is the TUI's three lines. Under the
table the TUI's legend, dim. The caption is R9's: `ble_device, N of M
rows, S standing alerts, sensor IFACE, scan MODE/FILTER`. The table
refreshes every 5 s, asking for as many rows as are shown (up to
1024), so rows a `more` brought in stay.

A click opens the BLE drawer: every decoded field in the TUI detail's
order and wording (address, sensor, LL channel, last PDU, local name
with `(shortened)`, manufacturer as `company 0x004c, first octet 0x10`
with the SIG's name, service, service data, appearance with `(HID)`,
HID, TX power, AD flags, RSSI with its best, `distance (est)` as
`~4.5m room steady, Ptx ad` or `no estimate`, advertisements, first
heard), then what the record carries that the TUI's detail does not
(the PDUs heard, the PHYs and SID of an extended advertiser, the
stamps, a 24 h presence strip (G5, 96 quarter-hour cells ending
now, the first-seen cell marked) and the row's advertising rate between
its records with a G1 of it), and the `hid_oui` findings naming the
address. The strip is 96 bits a row (two words and the newest bucket)
kept and stored with the row, a quarter hour set when a record's
`last_seen` fell in it; it costs no series and survives a restart, and
it is coarse in the other direction: a heard advertiser's record comes
once a 10 s slot, one that went quiet only on the 300 s heartbeat, so a
quiet quarter can be an unchanged advertiser whose heartbeat fell in the
next one. The rate is kept
per row inside `web_ble` (the last 16 `(ts, adv_count)` points, 256
bytes a row) rather than as a per-address series in the rollup: the
rollup's device class is 512 keys shared with the Wi-Fi tables, and a
resident random-address BLE device is a new key every fifteen minutes,
which would churn that class and evict the Wi-Fi devices' history. The
rate is coarse (the points are kept at least 300 s apart, the newest
following each record until it is, so sixteen cover about eighty minutes
now that a heard advertiser is re-sent once a 10 s slot) and the drawer
says so. The two
series the rollup does get are global and never evicted:
`ble.devices` (a gauge, sloth's advertiser-table size from
`sensor_health.ble_devices`) and `ble.adv_rate` (a counter, the delta
of `ble_adv_reports`), both Monitor's and both sampled only while
`btmon_iface` says sloth is listening. The one per-address BLE series
is `rf.rssi.ble` ([Metrics](#metrics)), kept for the FRRS Report's
signal against time by the owner's Q7 ruling of 2026-11-02, in a key
class of its own since #177 (`ble`, the same `--web-max-keys` N as the
device class): the class evicts its least recently seen advertiser, so
rotating addresses push out the quiet advertisers first and never a
Wi-Fi key, every eviction counted on `/api/health`
(`key_evictions.ble`). An advertiser is
sampled only when its record arrives fresh (once a 10 s slot while it is
heard), and it takes a key only once it has a reading.

Below the table the findings: kind, alert, sensor, the finding in
words (`mfr 004c/07 ADV_IND: 44 addrs (40 fresh), 812 adv at 81.2/s in
10 s (previous window)`; `00:13:37:00:00:01 (0) Hak5 OUI, HID
appearance, service 0x1812`; `3 random addresses in 900 s`; `CATEGORY -
a category, never an identity: N addresses in 120 s`), median RSSI,
first, last, and `standing` (the alert name at the warning colour) or
`resolved`. A finding quiet for more than 660 s (two heartbeats and a
margin) is no longer standing whatever resolve was missed. The same
incidents are on the Alerts page as `alert.*` records, typed and
Monitor's; the Health view's `bluetooth` block shows the
`sensor_health` members (source, stream, controllers, advertisers,
reports, scan mode and filter, own transmission, Ubertooth, rotation
bands, findings standing), the sensor tile's sub-line names the
`btmon` stream, the Overview's `ble advertisers` tile (a link to the
view) is the advertisers held with the HID, watchlisted and standing
counts and a 24 h G1 of `ble.devices`, and the status strip's `ble`
pill is the advertisers held (a dash under Local or with no Bluetooth
source; the tile says why). Under Local the
view shows why it is empty.

**The BLE Devices waterfall** (owner request 2026-11-02: "show a
waterfall similar to wifi for bluetooth devices"; "visualize in the best
way to convey ble in a similar style"). The tab reads `BLE Devices` (id,
view and key unchanged), and above the table sit a header strip and two
panels in the WiFi view's idiom (`web/ui/bledev.js`, `window.SlothBleDev`,
`bledev-*` containers; four guarded calls in `app.js`). Its rows are not
channels: an HCI LE Advertising Report carries no channel (Core v5.4 Vol
4 Part E §7.7.65.2), so every host-controller row is channel -1, and an
Ubertooth's hop 37/38/39 on every advertising event; channel rows would
be one row of -1. What BLE does carry is what kind of device is around
and how close it is.

The strip: `BLE now (last 60 s): N advertisers, trackers T, nearest
"name" -48 dBm near (grade), R reports/s`. With no BLE sensor at all
(sloth's `sensor_health` names neither `--bt-monitor` nor
`--bt-capture`) the strip says so and both panels are hidden, rather
than a lone Trackers row and "trackers 0" reading as a listening sensor
that heard none. With `--bt-capture` alone the reports/s is the host
stream's and says none, and the class panel's note says the Ubertooth's
one-channel samples are not credited, so its cells are advertiser
counts only and "advertising reports" stays empty.

**Who is around** (`/api/ble/classes`): one row per device class,
columns the window's 96 cells. A cell is the class's five busiest
advertisers by advertising reports as stacked bands, each its share, a
named device in its name's hash colour (as an AP is by its SSID's) and
an unnamed one in its address's, grey for the rest; a cell the class mix
no longer holds keeps the series' heat, dimmed (the cells select:
advertisers, a gauge of distinct addresses, or advertising reports). The
strip at a row's left is its busyness, the heat ramp against the busiest
row. Past 30% of the canvas (a phone) a row's label is its class letter
alone, which the footnote's list explains.

Anonymous advertising (2026-11-03) is in the class rows too. An LE
Extended Advertising Report with Address_Type 0xFF carries no AdvA;
sloth zeroes the address, so one row per sensor holds every anonymous
advertiser that sensor hears ([ble](../docs/wiki/ble.md), "Anonymous trains collide").
Its reports are Unknown's, whatever the row's fields would read as,
because those fields are no one advertiser's: sloth keeps the first
manufacturer pair the row heard for good, ORs in the HID bits and only
ever sets a watch category (`src/ble_hci.c` `observe_locked()`), so the
first anonymous advertiser fixes the Continuity pair for the life of
the row and a later one's Appearance or HID bit would move every
anonymous report after it. Classing it per record would have credited
them to a class decided by whichever devices happened to leave fields
on the row. So `web_ble_class_of_rec()` and `web_ble_dev_class()` both
answer Unknown for `addr_type` 255, and its reports are one band there:
the mix's `WEB_TX_BLE_ANON` (kind 4) with the zero address, drawn in `--muted` (neither a device's hash colour nor the
rest's grey), listed as "anonymous" in the cell's list and not a button,
since there is no row to open. It cannot be taken for an advertiser:
the kind is in every key (the open buckets, the answer's table, the
`chmix` primary key), and no kind-3 entry can carry the zero address,
because an address reaches the mix only through `web_key_mac()`, which
refuses all zeros. `ble.class.advertisers` counts anonymous advertising
as one advertiser in Unknown, so for it a row's advertiser count, its
`ble.class.adv` reports and its drawn bands name one set and never move
class (before, the anonymous row was in the advertiser count of
whichever class its fields read as, and in neither of the other two).
A named advertiser whose fields change class still moves: its earlier
bands stay where they were drawn, so the bucket in which it moves can
show it in both rows while the gauge, a snapshot, counts it in one. The ground is the page's own (`--bg`): the TUI puts no BLE row on
the monitor ground. The mix is the WiFi channel mix's engine
(`web/src/web_chmix.h`), a second instance keyed by class slug with a
16,384-row fine ring (seven classes over the fine tier's six hours),
its minute and hour rows in slothweb.db's `chmix` as kind 3
([The channel mix](#the-channel-mix-slothwebdb-v5)); its frames are a
row's `adv_count` deltas per (address, address type, sensor), a
one-channel Ubertooth sample left out. Those running totals' high-water
marks are a table of their own (`WEB_BLE_HW_ROWS`, 2048, in
`web_metrics.h`), apart from the 4096 the Wi-Fi, flow and channel
counters share: one mark per address means a transmitter rotating random
addresses (a spam tool, the case `BLE_ADV_FLOOD` is for) mints them at
its own rate, and in the shared table it would evict the Wi-Fi rows
between their records and make them count whole totals again.

The classes are one closed list (`web_bledev.c` `web_ble_classes[]`, its
copy in `bledev.js` held equal by `web/tests/test_bledev.c`), each
device in exactly one, the first rule that holds in this order winning
(display order differs: Phones, Wearables, Trackers, Input, Beacons,
Vehicles & IoT, Unknown). Each rule reads only what `ble_device` carries
and rests on a source quoted in
[research/bluetooth/ble-device-classes.md](../research/bluetooth/ble-device-classes.md):

| Order | Class | Rule |
|---|---|---|
| 1 | Trackers (`b:tag`) | a watch category; an Appearance of category Tag or Keyring; a 16-bit UUID listed or carried as Service Data that the SIG registry assigns to Tile (0xFEED, 0xFEEC, 0xFD84) or CHIPOLO (0xFE33, 0xFE65) - the assignment, not a verified payload shape |
| 2 | Input (`b:hid`) | sloth's HID bits (Appearance 0x03C0..0x03CA, or the HID service 0x1812 listed) |
| 3 | Beacons (`b:bcn`) | Eddystone: Service Data or a listed UUID 0xFEAA |
| 4 | Wearables & audio (`b:wear`) | Apple 0x004C Continuity 0x07 Proximity Pairing or 0x0B Magic Switch; Fast Pair Service Data 0xFE2C (the Provider, the accessory side); Samsung 0x0075 first octet 0x42 or 0x01; an Appearance of a worn, audio or personal-health category (Watch, Eye-glasses, Heart Rate, Blood Pressure, Glucose, Running Walking, Cycling, Audio Sink and Source, Wearable Audio, Hearing aid, Pulse Oximeter, CGM, Insulin Pump, Medication Delivery, Spirometer, Outdoor Sports) |
| 5 | Phones & computers (`b:phone`) | Apple Continuity 0x05 AirDrop, 0x0C Handoff, 0x0D / 0x0E Instant Hotspot, 0x0F Nearby Action, 0x10 Nearby Info; Microsoft 0x0006 first octet 0x01 (the MS-CDP beacon); Appearance Phone or Computer |
| 6 | Vehicles & IoT (`b:iot`) | Apple Continuity 0x06 HomeKit; an Appearance of a fixed, home, vehicle or industrial category |
| 7 | Unknown (`b:unk`) | none of the above; and all anonymous advertising (`addr_type` 255), whatever its row's fields, which are several advertisers' (below) |

Left out, said so rather than guessed: iBeacon (Apple type 0x02; no
primary text was read for it), AltBeacon (its 0xBEAC code is two octets
and the stream carries only the first), Apple Find My (0x12) and Samsung
SmartTag (0xFD59, 0xFD5A), whose shapes the watchlist page lists as
unverified, and Swift Pair peripherals (0x0006 / 0x03), which fall to
their Appearance or Unknown. `mfr_id` and `mfr_subtype` are the first
pair sloth heard on the row, so an Apple device that rotates Continuity
types is classed by its first, and an Apple Watch that sends Nearby
Info and no Appearance reads as a phone. A row's other fields are its
last report's, so a class is decided per record. Trackers is always a
row: the shipped watchlist is empty and the Find My and SmartTag shapes
are unverified, so an empty Trackers row is information, not "no
trackers here", and the panel says so.

**How close** (`/api/ble/proximity`): one row per advertiser heard in
the window (12, 24 or 48: trackers first, then the nearest by the
strongest signal in the window less its announced power, then reports;
at most 256 read, every tracker in the window first, and the note says
"of the 256 read" under a cut), the label its class letter, its name and the
address's last three octets; a cell the mean of `rf.rssi.ble` in it
graded hot-is-near by the band sloth's estimator (`src/rf_distance.c`)
gives that signal at the row's own P_tx: the extended report header's
TxPower (`ble_device` `ext_tx_power`, memory only, never stored), else
the TX Power Level AD, else 0 dBm, `rf_ctx_ble()`'s order, so the cell
and the table's `dist (est)` name one band for one reading. For an
advertiser announcing nothing (P_tx
0 dBm, L(1 m) = 20 log10(2440) - 28 dB, N 2.8): immediate above -39.75
dBm (`--heat-3`), near above -53.11 (`--heat-2`), room above -67.75
(`--heat-1`), building above -81.11 (`--heat-0`), far `--faint`, not
heard the ground. The edges are computed from those constants in C and
in the page, and the test reads `src/rf_distance.h` and `.c` for them.
A row announcing P dBm has each edge moved by P (TX Power Level 10 dBm
at -60 is about 12 m, building). The legend shows the 0 dBm edges and a
picked cell names its row's P_tx. The footnote says what the grade is
not: a tuned path-loss exponent (`--tune rf.path_loss_n_2g`, which
slothweb cannot see) and the band's hysteresis and hold can put sloth's
own band (the table's `dist (est)`) elsewhere, and signal strength is not a
location. A rotating random address is its own row: rotations are not
linked (the rotation hints, above, are sloth's, banded, and identify
nothing). Anonymous advertising has no row here and is never the
strip's nearest: with no address there is no `rf.rssi.ble` series to
key, and the one row per sensor carries whichever anonymous advertiser
was heard last, so its line would be several devices' signals drawn as
one. The note says when some was heard and left out
(`anonymous_heard`), and points at the class panel, which counts it;
it takes none of the 256 read, so under a cut "of the 256 read" stays
256.
Pointer, tap or arrow keys pick a cell in either panel and the
list under it names it (an advertiser the BLE tables still hold is a
button that opens its drawer); a click (a primary press and release,
never the start of a touch scroll) on a row's name opens the drawer.
Both panels redraw on a resize and reload every 30 s while the view is
visible.

The drawer gains the address's signal over the waterfall's window
(`/api/series` `rf.rssi.ble`, the fine tier up to a day, the minute tier
past it) as [the S-meter](#the-s-meter-2026-11-11) on the 2.4 GHz row
(BLE is 2.4 GHz): lit to the window's last sample, ticks at its least
and greatest, the S reading and dBm in the note (until 2026-11-11 a
line over the window in the grade's colour; the waterfall and the
table's dist column still say the grade), the row's class, and for an
Ubertooth row the LL channels slothweb has seen it on since it started.
Opening the drawer on another address clears all three first and drops
the last address's series answer if it is still on its way; a theme
change redraws an open BLE drawer.

Both panels rest on sloth's side of the change: `ble_device` is re-sent
once a 10 s slot while sloth keeps hearing the advertiser
([jsonl-schema](../docs/wiki/jsonl-schema.md)), so a heard advertiser
has a signal point and an `adv_count` delta a fine bucket. Before it
the record came once per 300 s heartbeat for a steady advertiser, and a
1 h waterfall would have filled about one cell in seven.

**The Bluetooth SIG assigned numbers.** The company behind a
Manufacturer Specific Data block, the service a 16-bit UUID lists and
the device class an Appearance value states come from the SIG's public
Assigned Numbers, committed as three CSVs in `web/data/btsig/`
([its SOURCE.md](data/btsig/SOURCE.md): URLs, date, SHA-256 of the
YAML fetched once and of the CSVs, the licence note) and compiled in
at build time by `web/tools/btsig_gen.c`, exactly as the IEEE registry
is. `make update-btsig SRC=DIR` (`web/tools/update_btsig.sh`) converts
the three YAML files found in a given directory and rewrites the
hashes; it never fetches (the ab5fcb2 ruling), and nothing in the
build, the tests or CI runs it. A `WEB_BTSIG_DIR` without the CSVs
builds an empty table (`sig: none` in `/api/health` and the start
notice) and the page shows the numbers alone, as the TUI does.
`web/tests/test_btsig.c` holds the committed files to the hashes and
the lookups to the SIG's names.

## Probes

Owner request 2026-11-11: "i want a separate probes tab that shows
clients searching for ssid's. associating these with clients or other
devices where possible keep track of ssid's and look for devices
probing for the same ssids" (`web/src/web_probes.h`,
`web/ui/probes.js`). A tab of its own, after BLE Devices in the bar;
no digit is left for it.

**What sloth records about a probe request**, which is all this view
has:

| Where | What |
|---|---|
| sloth.db `probe_clients` | one row a station heard probing: its latest directed SSID, signal, channel, first and last seen, sloth's presence class, and `frame_count`, every probe request sloth counted for it, directed and wildcard together (`src/capture/probe.c` `record_probe()`; the live table is 128 entries, aged out after 120 s, sloth.db keeps the row) |
| sloth.db `pnl_clients` | one row a station that sent a directed probe: `probe_count` (directed probes only), sloth's OS label from the probe's vendor elements and its PHY tier, first and last seen (`src/probe_pnl.c`; 128 clients live) |
| sloth.db `pnl_ssids` | one row per (station, SSID) asked for by name, 16 names a station live; a wildcard probe names none and has no row (`probe_pnl_observe()` returns on an empty SSID) |
| sloth.db `seqnum_correlations` | two MACs whose 802.11 sequence counters ran on from one another (`src/seqnum_track.c`): `gap`, `dt_ms`, each side's frame count. sloth's hypothesis that one radio sent both across a MAC rotation, capped below certainty in sloth's own record |
| sloth.db `assocs`, `devices` | an association seen for the MAC; a device row for it |
| the stream | `probe_client` (the flood window and sloth's distance estimate besides), `pnl_client` (its `ssids` array), `seqnum_client`, `seqnum_correlation` (with `confidence`, `fwd_gap` and the window, which sloth.db does not keep) |
| the TUI | the PNL view: a client, its names, its OS and PHY labels; the WiFi tab's clients panel here is the `wifi.probe_clients` count and the nearest probing devices |

The view reads sloth.db only, through the M4 reader and its column
allow-list: no column was added, nothing is written, and nothing is
kept in slothweb.db, so what it shows is what sloth.db retains, across
restarts of either process. sloth keeps **no count of wildcard
probes**: `frame_count` and `probe_count` are two tables' counters
with their own lifetimes, so their difference is not one. Each row
gives both, named; a station with no named network says `wildcard
probes only`, and an empty name is never listed as an SSID (the reads
refuse one even from a file something else wrote).

**The window** is the view's first control: 24 h, 7 d, 30 d (the
default) or everything sloth.db retains, by each row's last seen. It is
in every caption.

**Clients heard probing** (`/api/probes/clients`): every station of
`probe_clients` or `pnl_clients` last seen in the window, 50 a page
with `more`, in the order the control picks (last heard, first heard,
networks asked for, frames, signal, address). A row: the MAC (`~` and
`randomised` for a locally administered one, else the OUI table's
vendor), the networks it asked for by name (the 16 newest and `+n
more`; each opens that [SSID's detail](#an-ssids-detail)), their
count, frames and directed probes, signal, the 24 h presence strip
(G5, as a Devices row's), last seen, and what it is **tied to**, only
where sloth already has a basis:

- `device`: sloth.db holds a `devices` row for the same MAC; the button
  opens the device drawer.
- `associated to <bssid> <ssid>`: the newest `assocs` row for the MAC;
  the BSSID opens its drawer, the SSID its detail.
- `may be one radio with <mac>`: a `seqnum_correlations` row naming the
  MAC, the three newest. The tooltip gives its basis (gap, milliseconds
  apart, frames) and the words: consistent with one radio; a hypothesis
  a passive sensor corroborates and never confirms. The correlations
  are read newest first, at most 20,000 rows of the table.

A click or Enter on a row picks the station for the next panel.

**Probing for the same networks** (`/api/probes/shared`): the picked
station's named networks, each with how many stations ask for it and
its weight, then the other stations sharing its uncommon ones, the
most similar first. The similarity, over the window's rows:

```
N        the stations that sent a directed probe (pnl_clients)
df(s)    the stations asking for SSID s (pnl_ssids)
w(s)     ln(N / df(s)): a network every station asks for weighs 0
uncommon 2 <= df(s) <= U, U = N / 20 kept within 2..16
sim(A,B) = sum of w(s) over the SSIDs both ask for
           / sum of w(s) over the SSIDs either asks for
```

and a pair is ranked only when it shares at least `min` uncommon SSIDs
(the second control: 1 to 4 on the page, default 2). A carrier or
hotspot name weighs next to nothing and never makes a candidate: only
an uncommon name of the picked station does, so the candidates are at
most 64 names x 15 stations, each read by `idx_pnl_ssids_ssid`. The
caption carries the formula with the answer's own N and U. `sim` is
symmetric and in 0..1; `test_probes.c` works one set by hand (six
stations: 0.319 and 0.216). It says two stations probe for the same
networks: they have been in the same places or share a configuration.
It does not say whose they are, and the page never words it so.

**Networks searched for** (`/api/probes/ssids`): every SSID asked for
by name in the window: the stations asking (distinct MACs: `pnl_ssids`'
key is the pair) and how many of those MACs are randomised, whether an
access point in sloth.db beacons exactly that name (how many, and the
strongest), first and last asked for; the name opens its detail. The
operator's designated networks (`--my-ssid`, from sloth's `ownership`
record) carry `"designated": true` and a `yours` mark: a designated
network being searched for is the row an operator most wants to see.
Before that record arrives every row's `designated` is `null`, the
answer's `designated_count` is `null`, and the caption says the
designated networks are not known. The WiFi AP table's rows carry the
same member, `true` by BSSID (`--my-bssid`) or SSID, and the same mark.

**Groups** (`/api/probes/groups`): the stations linked, directly or
through one another, by at least `min` shared uncommon networks, each
group with its stations and the uncommon names at least two of them
ask for; the group sharing most first. One pass over the window's
`pnl_ssids` in SSID order, so only an uncommon name's stations are ever
held.

**Bounds.** Every read runs under the request's 250 ms budget and
answers `503` `sloth_db_timeout` past it. What is capped, each shown
as `N of M` in its caption when met:

| What | Cap |
|---|---|
| a page of stations or networks | 100 rows (`total` is every row in the window) |
| a station's names in its row | the 16 newest (`ssid_count` is all) |
| the picked station's names, and each candidate's | the 64 newest |
| candidates ranked, and shown | 1,024; 50 |
| groups: stations held, uncommon names, pairs counted | 4,096; 8,192; 65,536 (`capped`, with `ssids_read` of `ssids_uncommon`) |
| groups shown, and a group's stations and names | 40; 12; 8 |
| correlations read | 20,000 |

On the suite's large file (50,000 stations, 200,000 `pnl_ssids` rows,
600,000 alerts) every route answers inside the budget
(`test_probes.c` prints each time).

**Scope.** Probe requests are the monitor radio's: Monitor's and
Hybrid's; under Local the tab says so, as the BLE tab does, and the
four routes answer `out_of_scope`.

**Privacy.** A list of the networks a device asks for can name a home
or a workplace, and across MAC rotations the list itself can single a
device out. The view shows what sloth.db already holds, to whoever the
peer list already admits; it adds no export: the copy-JSON bundle
gains no kind and no member for it, so the bundle's glossary needed no
entry, and a device's bundle carries its PNL as it did before.

## Fleet

Issue #192 slices F1, F2, I5 and I6, under [ADR 0008](../docs/wiki/adr/0008-own-fleet.md)
(the owner's own sensors share at full fidelity over the tailnet) and
[docs/wiki/fleet.md](../docs/wiki/fleet.md). Each slothweb serves what
its sensor has seen to the addresses its allow list admits, and pulls
the same from the peers `--peer` names, into its own `slothweb.db`. The
sensor and `sloth.db` are not touched; slothweb still never writes
`sloth.db`. The code is `web/src/web_fleet.c`.

**`/api/fleet/export?since=EPOCH`** (GET only, `application/x-ndjson`)
is read-only and on the existing listener, so it answers exactly the
peers `--web-allow` admits: on the operator's other sensor that is this
host's tailnet address, as one address, never a subnet (ADR 0008). It is
JSON Lines, one flat object a line, so the puller reads it with the
stream's own strict decoder (`web_jsonl.h`) and nothing new:

| Line | Members |
|---|---|
| `fleet_export` (first) | `fleet_export_version` (1), `generated` (the peer's clock), `since`, `site_label` (sloth.db's newest session label), `slothweb_version`, `sloth_version` (null: not kept), `sloth_db` (`open`, `none`, `unavailable`), `lat`, `lon`, `alt_m`, `pos_source` (`gps`/`fixed`), `pos_ts`, `pos_age_s` (all null without a position; from `sensor_health`'s `loc_*`) |
| `gnss` | `sensor_health`'s receiver summary: `gps_state`, `sats_in_view`, `sats_used`, `cn0_mean`, `time_offset_ms`, `jam`, `ts`; with `gnss=1` (#192 I6) also the newest fix (`fix_ts`, `mode`, `fix_lat`, `fix_lon`, `eph`, `hdop`) and the tracked satellites' median C/N0 (`cn0_med`, `tracked`) |
| `gnss_event` | with `gnss=1` only (#192 I6): sloth.db's `alert_incidents` of the four GNSS rules' keys, the last week's changed since `since`, newest first: `alert_type`, `ty`, `first_seen`, `last_seen`, `count`, `sev`; at most 256 |
| `wifi` | sloth.db `devices` last seen at or after `since`: `mac`, `vendor`, `ssid` (its last), `rssi`, `bssid` (its newest association), `is_ap`, `first_seen`, `last_seen`; at most 2,000 |
| `ap` | `beacon_aps`: `bssid`, `ssid`, `channel`, `enc`, `vendor`, `rssi`, times; at most 1,000 |
| `probe` | each exported client's probe list (`pnl_ssids`), one line per SSID: `mac`, `ssid`, times; 32 a client, 4,000 in all |
| `ble` | slothweb's BLE advertisers heard since: `addr`, `addr_type`, `name`, `class`, `rssi`, times; at most 1,024 |
| `alert` | the alert keys whose latest incident is in the window: `alert_type`, `ty`, `fingerprint` (FNV-1a of type and title), `title`, `ip`, `sev`, `count`, times; at most 1,000 |
| `verdict` | each triaged finding's current state decided since: `alert_type`, `addr`, `port`, `alert_first_seen`, `state`, `ts`; at most 1,000 |
| `fleet_end` (last) | `rows`, the count of each kind, `truncated_<kind>` for each, with `next=1` or a page `next_wifi`, `next_ap`, `next_alert`, `next_verdict` (null, or the cursor after the last row sent of a kind that was cut), with `gnss=1` `gnss_event` (the incident lines sent) and `gnss_complete` (true only when the week's incidents were read to the end: false on a sloth.db before v11, a read error or timeout, or the cap; the importer then takes no `ev` coverage from the answer), `complete: true` |

Every member of every line is listed once, in `web_fleet_members[]`:
the writer names nothing else (an unlisted name fails the answer, 503)
and the reader refuses a line holding anything else; the suite holds
each name to `web_sdb_is_secret()` ([Security](#security)). The
`sloth.db` rows come through the M4 reader and its column allow-list,
so no credential, username, alert key, alert detail, EAPOL row, RADIUS
identity, MQTT username or RDP cookie can be read, whatever a later edit
says; `web/tests/test_fleet.c` seeds each one and holds it out of the
body. A triage verdict travels without its note, author or address of
origin. A kind cut at its cap, or by sloth.db's read budget (1.5 s),
says so in `truncated_<kind>`; the body is never cut, and a row that
would pass 8 MB is not written. So does a kind with a row the importer
below would refuse (a stored signal of +60 dBm, a first seen after the
last): every line is held to the importer's own checks before it is
sent, and such a row is left out, because one would refuse the peer's
whole answer at every pull while it stayed in the window.

Parameters, each at most once: `since=EPOCH`; `next=1` (the end line
carries the cursors); `kind=wifi|ap|alert|verdict` with `after=CURSOR`
(`<last_seen>~<key>`, 1..12 digits, `~`, up to 24 of `[0-9A-Za-z:]`), a
page of that kind only after the cursor, in the reader's own order
(keyset on last_seen and the key). Anything else is a 400 (`bad_since`,
`bad_next`, `bad_kind`, `bad_after`, `after_needs_kind`,
`unknown_parameter`).

**The pull** runs on a thread of its own, every `--peer-interval-secs`:
one HTTP/1.1 `GET /api/fleet/export?since=N&next=1` to each peer over plain TCP,
5 s to connect and 30 s for the whole answer (not each read: a peer
that trickles bytes is cut off), which is held to 10 MB and refused
whole past it (never cut to fit); a `Transfer-Encoding` or a second
`Content-Length` is refused. `since` is the peer's own
`generated` at its last good pull less 120 s, so a clock difference
between the sites loses nothing, and a first pull asks from 0 (the newest
rows of each kind, at their caps). An answer is checked whole before a
row is written: every line decoded, every member known, every value in
range (MACs canonical, times 0..2100, RSSI -150..30, strings at most 255
bytes, altitude -1,000..100,000 m, state one of triage's words), the header version 1 and the end
line's counts equal to the rows sent. Anything else is refused with a
reason in slothweb's own words (`line 4: a wifi line with a member it
may not carry: refused`, `HTTP status 503`, `response over 10485760
bytes: refused`), kept in memory, in `/api/health` and in `peer_sites`,
and no sighting is written.

**The backfill** (F2). A kind cut at its cap comes back with a cursor;
the puller keeps the cut answer's `since` (the floor) and the cursor for
it and, after each good pull, asks for up to 4 pages a kind
(`since=FLOOR&kind=K&after=CURSOR`) until a page is not cut, so the rows
a first pull cut are fetched over the next pulls and nothing already
held is asked for again. A probe list rides its client's wifi row; BLE
is never cut. The state is in slothweb.db's `meta` table
(`fleet.backfill.NAME.KIND`, the floor and the cursor), written in the
transaction that stores the rows, and read back at start. A page's
refusal is `backfill KIND: ...` in `last_error` and leaves the
backfill to the next pull, as does a page that did not move its cursor.
An alert answer whose reader's 20,000-row scan did not reach the floor
is cut too, its cursor the scan's oldest `last_seen` (`<ts>~`), and a
page scans only the rows at or before its cursor. A peer whose export
answers `next=1` with a 400 `unknown_parameter` (an F1 build) is asked
again with `since=` alone and pulled so for an hour, nothing paged from
it (`pages_refused` in `/api/fleet/overview`), so a fleet can be
upgraded a host at a time. [docs/wiki/fleet.md](../docs/wiki/fleet.md)
has why it is a keyset and not an offset.

### The fleet tables: slothweb.db v8

`v7 -> v8` adds `peer_sites`, `peer_sightings` and one index, in one
additive `BEGIN IMMEDIATE` step like the others (a name already taken
fails it and leaves the file at v7; `web/tests/test_store.c` holds the
migration of a v7 file with a BLE advertiser, a triage row and a TACDB
platform in it, which come through unchanged, and that failure).

- `peer_sites`: one row per `--peer` name: `url`, `label`,
  `last_attempt`, `last_ok` (slothweb's clock), `last_error`, the
  site's `lat`, `lon`, `alt`, `pos_source`, `pos_ts`, the peer's
  `remote_version`, `remote_ts` (its clock at the last good answer, the
  next pull's `since`) and `rows_last`.
- `peer_sightings`: one row per `(peer, kind, key)`: `kind` is `wifi`,
  `ble`, `ap`, `probe`, `alert`, `verdict` or `gnss`; `key` the
  canonical MAC (a probe: `mac|ssid`; an alert: its fingerprint; a
  verdict: `type|addr|port|alert_first_seen`); `label` the SSID, name,
  title or state; `vendor` (a BLE row's class); `rssi`; `first_seen`
  and `last_seen`, widened by every pull (the earlier first, the later
  last); and `extra`, JSON slothweb writes itself from validated
  members.

The pull thread writes over a store connection of its own (as triage
does, a busy timeout of 5 s), one transaction a pull; the HTTP thread
reads over the read-only one. Bounded twice per peer at every pull: no
sighting older than 90 days by the peer's own clock, and at most 20,000
sightings, the least recently seen dropped first. A row is a few hundred
bytes, so eight peers at the cap are some 50 MB, inside `--web-max-mb`'s
accounting but not dropped by its ceiling.

**`/api/health`** gains `fleet`: `{"export":true,"export_version":1,
"interval_s":60,"outside_tailnet":false,"peers":[{"name","url",
"last_ok_age_s","last_attempt_age_s","last_error","rows","pulls",
"failures"}]}`. **`/api/fleet/peers`** answers each `peer_sites` row
(`configured` false for a name no longer given) with its sightings
counted by kind.

**`/api/fleet/overview`** (the Fleet tab): `local` (this site's label,
`sloth_db`, the position the export sends), `interval_s`, `store`,
`configured`, `peers` (each `peer_sites` row or configured peer: its
position, `last_ok_age_s`, `last_attempt_age_s`, `last_error`, `skew_s`
= the peer's clock at its last good answer less this one's then,
`remote_version`, `rows_last`, `counts` by kind, `backfill` per running
kind with `floor` and `cursor`, `pages`, `page_failures`, `pages_refused`, `distance_m`),
`calibration` (#192 I5: each site with a position, its count of own
radios, and its receiver's `state`, `offset_db` and links, as below)
and `distances` (every pair of sites with a position, haversine metres,
this site `self`). **`/api/fleet/shared?kind=wifi|ble|ap|probe&limit=N`**
(GET only, limit 50, 1..200): the keys of the kind a peer sent that this
site holds too (`sloth.db`'s `devices`, `beacon_aps` or `pnl_ssids`
through the M4 reader, read-only, in the 1.5 s overview budget; a BLE
address from slothweb's table), the newest activity at any site first,
each with `sites` (`self` and each peer: `first_seen`, `last_seen`,
`rssi`) and `verdict` (this site's triage at the address, else a
peer's); `partial` when the 5,000-row scan or the budget stopped short.
A signal is a radio reading or `null`: sloth's stored 0 ("never heard on
the air", an ARP- or DHCP-only device) is none, and a device row without
a reading takes `probe_clients`' reading of the same MAC (#192 I5); the
export's `rssi` follows the same rule, except that a probe reading
travels only when it is within 120 s of the row's `last_seen` and not on
5 or 6 GHz (the importer reads a row's `rssi` as of its `last_seen`, at
2.4 GHz).

**`/api/fleet/locate?kind=wifi|ap|ble&limit=N`** (#192 I5; GET only,
limit 50, 1..200; `web/src/web_locate.h`): each emitter two or more
sites heard within 120 s of each other (a peer's time less its measured
skew; the newest within 15 minutes), each site's range by sloth's own
path-loss model (`src/rf_model.h`, ITU-R P.1238-10; power assumed) with
a one-sigma band, and the location: the two range circles' crossings
(`two_circles`, 0 to 2 `candidates`) or a weighted least-squares fix
(`least_squares`, three or more sites, with `residual_m`), each
candidate as `lat`/`lon`, plane `e`/`n` metres around the sites'
centroid and `radius_m`; always `nearest` (the site with the least path
loss, by how many dB, the difference's one-sigma `sigma_db` and
`within_band`, true when the difference is inside it and says nothing
about which site is nearer), `baseline_m`, `band_m` and `coarse` (the
band wider than the baseline: a side, not a point). A least-squares fix
that has not settled within 500 damped steps is no candidate. `sites` lists each site
with a position, `too_far` (none other within 2 km) and its receiver's
`calibration`: from another site's own radio heard at a known distance
(`own=1` on the export names a site's radios, read from
`/sys/class/net` at start), an offset bounded at +/-20 dB applied to
2.4 GHz Wi-Fi rows only. Then `scanned`, `keys`, `looked_up`,
`unpaired`, `stale`, `partial`. The model, the band and what it is worth
at a 17 m baseline: [docs/wiki/fleet.md](../docs/wiki/fleet.md).

The export's `own=1` adds `own_macs` to its header (this site's physical
interfaces' addresses, comma-separated, or `null`); an F2 puller never
asks for it, and an F2 export refuses it as an unknown parameter, which
the puller answers by asking with `next=1` alone and not asking with
`own=1` for an hour. `gnss=1` (#192 I6) the same way, in front of it:
an I5 export refuses it, and the puller asks again with
`next=1&own=1` and not with `gnss=1` for the hour.

**`/api/fleet/gnss?limit=N`** (#192 I6; GET only, limit 50, 1..200;
`web/src/web_fleetgnss.h`): GNSS across the sites. `local`: this site's
sloth.db (`open`, `none`, `unavailable`, or `no_incidents` for a file
before v11, which never reads as quiet). `sites`: each
receiver as its last sample said (`fresh`, `incidents` offered,
`state`, satellites, `cn0_mean`, `cn0_med` over `tracked`, `jam`,
`time_offset_ms`, `skew_s`, the `fix` with `eph` and `hdop`), its
`reference` (the coordinate-wise median of up to a week of fixes, one a
600 s, from 6 on: `n`, `lat`, `lon`, `displacement_m` of the fix now,
`bound_m` = 3 x eph, `outside`) and `time` (the offset now against the
median of the hour before, `step_ms`, `stepped` at 1000 ms or more; a
peer's skew the same way, `skew_step_s`, `skew_moved` at 2 s or more).
`baseline`: each pair, `ref_m` between the references, `now_m` between
the fixes now, `delta_m`, `bound_m` = 3 x (eph + eph), `verdict`
(`within`, `outside`, `undetermined` with `why`) and `moved` (each site
past its own bound). `position` and `time`: `consistent`, `one_site`
(and `site`), `several` or `undetermined` (fewer than two sites
evaluated). `events`, newest first: each GNSS incident of this site
(sloth.db) and of each peer (its `gnss_event` lines, in this site's
clock), and each `JAM_IND` (indicator 128 or more) and `CN0_DROP` (the
tracked median 10 dB under the site's own hour) a site's samples show:
`site`, `type`, `class` (interference, spoof, time, position),
`source`, times, `verdict` (`regional`, `local`, `undetermined`) and the
sites `with` the same class within 120 s, `quiet` (observed from 120 s
before it to a pull at least 120 s after its end, nothing), `stale`
(not observed so: an event still running, or not yet pulled past its
window, has no quiet site) and `far` (outside
`--peer-gnss-region-km` or with no position). `counts` by verdict over
the week, and `basis`: each class's sources and which numbers are a
choice. `/api/fleet/overview` gains `gnss`: the `position` and `time`
verdicts and the last day's `events_24h` by verdict.

**`/api/fleet/aircraft?limit=N`** (#192 I7; GET only, limit 100,
1..500; `web/src/web_fleetadsb.h`): aircraft across the sites. `sites`:
each ADS-B receiver (this one from the stream's `adsb_*` summary and
sloth.db, a peer from its `adsb_rx` line): the decoder's `source` kind
and `state`, `aircraft_now`, `msg_rate`, `through_age_s` (how old its
data is), `cut_age_s`, and its coverage over 24 h from its own position,
`positions`, `range_max_m` and twelve 30-degree `sectors`
(`{from, max_m, n}`, `max_m` the sector's reach: the median of its
hourly farthest). `aircraft` over the last two hours, unconfirmed
first: the address, callsign, squawk, category, emergency, altitude,
speed, track, the tested position (`ref`, `lat`, `lon`, `pos_ts`),
`seen` per site, `verdict` (`confirmed`: two receivers heard it at
overlapping times; `unconfirmed`: within 0.8 of another receiver's
reach in that sector and of the 4/3-earth radio horizon from its ground
(no antenna height credited, its own altitude known) while that
receiver answered past the window, was not cut and heard two other
aircraft at each end of the span the position's time may lie in, and
did not hear it; `out_of_peer_coverage`; `undetermined`
with `why`, `single_receiver` while the fleet has one receiver), `peers`
(each other receiver's `state`, `dist_m`, `sector_max_m`, `horizon_m`),
and `inconsistent` (two receivers' positions further apart than it could
fly). `counts`, `total`, `partial` and `basis` (the survey it cites and
the thresholds that are choices). `/api/fleet/overview` gains
`aircraft`: `receivers`, `single_receiver`, `aircraft`, `counts`.

The export's `adsb=1` (#192 I7) adds one `adsb_rx` line (the receiver's
summary and coverage, `r000`..`r330` metres, `n000`..`n330` positions)
and an `aircraft` line per sloth.db `adsb_aircraft` row changed since
`since` within 6 h (at most 1,000, newest first, each position with
`pos_prev` and `pos_ts` bounding its time; the end line's `aircraft`
and `truncated_aircraft`, true whenever the aircraft were not all read,
including not read at all). An I6 export refuses it; the
puller asks again with `gnss=1` and not with `adsb=1` for the hour.

**`/api/fleet/findings?kind=I2|I3|I4|I8&limit=N`** (#192 I2, I3, I4, I8;
GET only, limit 100, 1..500; `web/src/web_fleetid.h`): identity across
the sites. `I2` a client at one site probing for an SSID another site
names as its own (a lead: an SSID is only as unique as its name; not
applicable at co-located sites; randomised probe addresses left out and
counted, a client triaged known exonerated); `I3` a site's own BSSID, or its own
SSID from a BSSID it does not name, heard where its network cannot
reach, and one BSSID heard at two sites within 600 s further apart than
both reach together; `I4` one beacon fingerprint (IE-order and vendor-IE
hash) on an AP sloth names the attacker (`KARMA_AP`, or the impostor half
of an `EVIL_TWIN` pair the stream's `twin_episode` attributed), at two
sites, in order: a lead, never a detection; `I8` one address triaged known at one site and incident at
another. A site's reach is an AP at 20 dBm heard down to its weakest AP
signal less 20 dB (`src/rf_model.h`); a check that needs distance says
`co_located` within it (the owner's sites are 16.8 m apart) or
`no_position`. Answers `local`, `store`, `configure` (how to name the
own networks when no site does), `sites` (each one's own networks,
`offered`, floor, reach, counts), `pairs` (distance, reaches,
`co_located`), `counts` (each class that applies, `not_applicable`,
`exonerated`), `findings` (each `id`, `class`, `kind`, `key`, `ssid`,
`sites`, times, `applicable`, `lead` (I2 and I4: an inference to
confirm), `reason`, `note`, `exonerated`,
`distance_m`, `bound_m`, `evidence` per site and `basis`), `total`,
`partial`, `verdicts` (every address a peer sent a verdict on, each
site's state beside it: shown, never written into this site's triage)
and `basis`. `/api/fleet/overview` gains `findings`: the counts,
`total`, `own_named`, `partial`.

The export's `ident=1` (#192 I4) adds an `own_net` line per network
`--my-ssid` and `--my-bssid` name (the end line's `own_net` counts
them, and an answer that does replaces what the peer named before), and
to every `ap` line `ie_fp`, `vie_fp` (the beacon's IE-order and
vendor-IE hashes from the FRRS ledger), `wps_manuf`, `wps_model`,
`wps_num`, and `attacks`, `attack_first`, `attack_last` (the
`EVIL_TWIN` and `KARMA_AP` alerts of the last 30 days naming that BSSID
at a key field: `KARMA_AP`; `EVIL_TWIN` only for the impostor half of a
pair the stream's `twin_episode` attributed, `web_chain.h`;
`TWIN_UNATTRIBUTED` for either half of a pair it did not; the real half
of an attributed pair neither). An I7 export refuses it; the puller asks again with
`adsb=1` and not with `ident=1` for the hour.

**The Fleet tab** (after TACDB, `web/ui/fleet.js`): the sites on an SVG
map with the distance between each pair, a health card per peer, and
"seen at more than one site" with each site's first-to-last-seen bar on
one time axis, the key a link to the device drawer. The map also draws
the located emitters (I5): each candidate a translucent circle of its
radius (the key on hover or tap), the picked row's range circles dashed,
and a metre scale; it fits the sites and the candidates, so at a 17 m
baseline it is drawn in metres. A "located emitters" table follows the
map. "GNSS across the sites" (I6) follows: a card per receiver (C/N0,
satellites, fix, distance from its reference, clock offset), a gauge
per pair of sites (the band is the bound around the reference distance,
the mark the distance now) and the classified events. "Identity across
the sites" (I2, I3, I4, I8; `web/ui/fleetid.js`, its own module) lists
each finding with its class (its basis on hover), its subject (a MAC
opens the device drawer), each site's part and whether it applies at the
sites' spacing, then every verdict a peer sent beside this site's. The
follower (I1) is still to come.

**The merged views** (owner request 2026-11-11;
`web/src/web_fleetview.h`). `/api/devices`, `/api/wifi/aps`,
`/api/ble`, `/api/probes/clients` and `/api/probes/ssids` carry the
peers' rows, and `/api/device/{mac}` and `/api/ble/{addr}` answer for an
address only a peer heard; `/api/adsb` and `/api/adsb/seen` carry the
peers' aircraft and `/api/adsb/aircraft` names the hosts that heard one.
Each takes
`fleet=0|1`, taken out of the query before the route's own parser as
`scope=` is: `fleet=0` is the route's own answer byte for byte; `fleet=1`
or none merges when a `--peer` is configured and the request is Hybrid
(a peer row carries no capture path, so Monitor and Local never merge);
anything else is a `400` `bad_fleet`. Without a peer the answers are as
they were.

- A local row a peer also reported gains `sites`: `[{site, label,
  first_seen, last_seen}]`, one a peer (`label` the name its export
  sent, `null` for none).
- The peers' other keys follow the local rows on the first page (no
  `offset`, or `offset=0`; on 2026-11-12 the page that ended the local
  list, which a field sensor's deep offsets time out before), at most 100 (`WEB_FV_REMOTE_MAX`), as
  rows with `"remote": true`, `site` (the peer that heard it last),
  `site_label` and `sites`, in the route's own sort (a column a peer
  sends nothing for reads as empty, then by last seen). They hold only
  what `peer_sightings` holds, under the route's names: a device's
  `mac`, `random` (the MAC's own bit), `vendor`, `ssid`, `signal`,
  `is_ap`, `first_seen`, `last_seen`; an AP's `bssid`, `ssid`,
  `signal`, `channel`, `enc`, `vendor` and the times; an advertiser's
  `addr`, `addr_type`, `type`, `name`, `rssi`, `class` (when it is one
  of the closed list) and the times. Every other member is absent. A
  peer's 0 dBm is no reading (`null`), as everywhere in the fleet.
- A key this site holds anywhere (`sloth.db`'s `devices` or
  `beacon_aps`, the BLE table), whatever the page or the filter shows,
  is never a remote row. `/api/devices`' `q` applies to the remote rows
  when every term is one they can answer (free text, `vendor:`, `mac:`,
  `ssid:`, `random:`, `seen:`, `first:`); any other term leaves them out.
  `/api/ble`'s `q` is the address prefix or the name.
- The Probes tab's two lists read the peers' `probe` rows (a client's
  MAC and the SSID it asked for by name; one naming none is passed
  over) last seen in the route's `days` window, and sort the remote rows
  by the route's `sort` (`frames`, `signal` and `clients` read as empty,
  so by last seen). A remote **station** (`/api/probes/clients`) is one
  with no `probe_clients` or `pnl_clients` row here at any time: `mac`,
  `random`, `vendor` (this site's OUI table, as a local row's),
  `first_seen` and `last_seen` (the earliest and latest over the peers'
  rows), `ssid_count` and `ssids` (the distinct SSIDs the peers heard it
  ask for, the newest 16, each with its times) and `ssids_more`;
  `frames`, `directed`, `signal`, `channel`, `os`, `phy`, `device` and
  `assoc` are `null`, `siblings`, `siblings_total` and `presence`
  absent. A remote **network** (`/api/probes/ssids`) is an SSID no
  `pnl_ssids` row here names at any time: `ssid` (and its display
  members) and the times; `clients`, `random`, `aps`, `ap_signal`,
  `uncommon` and `designated` are `null`. A row's `sites` has one entry
  a peer however many of its rows match (the earliest `first_seen`, the
  latest `last_seen`). `/api/probes/shared` and `/api/probes/groups`
  are never merged and take no `fleet=`: the similarity, `N`, `df` and
  the groups are this site's `pnl_ssids` alone.
- The ADS-B tab's two lists read the peers' `aircraft` rows (#192 I7,
  keyed by the address). `/api/adsb`, the decoder's table now, takes
  those last seen within `WEB_ADSB_TTL_S` (660 s) plus one
  `--peer-interval-secs`; `/api/adsb/seen` those last seen in its `days`
  window, its `q` (a hex or callsign prefix, any case) applied. Both
  order them by last seen. An address the panel's table lists (live or
  gone) is never a remote row; in `/api/adsb/seen` neither is one
  `sloth.db`'s `adsb_aircraft` holds at any time. `/api/adsb` takes no
  `limit=`-cut answer as the end of its list (`total` must equal the
  rows). A remote `/api/adsb` row: `hex`, `non_icao` (the leading `~`),
  `flight`, `squawk`, `category`, `emergency`, `on_ground`, `alt` (the
  peer's newest altitude, barometric else geometric: the line does not
  say which, so `alt_baro` and `alt_geom` are absent), `gs`, `track`,
  `lat`, `lon`, `pos_ts`, `rssi`, `messages` (each `null` when the line
  had none), `first_seen`, `last_seen`; `state`, `source_type`,
  `alt_band`, the rates, `ts`, `records`, `alert` and `track_pts` absent.
  A remote `/api/adsb/seen` row: `hex`, `non_icao`, the times, `flight`,
  `squawk`, `category`, `alt`, `messages`; `visits`, `sightings`,
  `source_type`, `emergency_seen`, the ranges and maxima and `pos_seen`
  absent. The panel's `total`, `live`, `with_pos` and `emergency` stay
  its own.
- `fleet`, the answer's last member: `peers` (`site`, `label`), `remote`
  (the rows added), `remote_cap`, `remote_more` (more were cut by the cap
  or the room), `partial` (the 4,000 newest peer rows were read, or the
  budget stopped the check against `sloth.db`), `remote_off` (`null`,
  `not_first_page`, `query` or `sloth_db`). `count`, `total` and every
  other figure stay this site's own.
- `/api/device/{mac}` gains `fleet` where a peer reported the MAC (as a
  client, `rows`, or as an AP, `ap_rows`: each `site`, `label`, the
  times, `ssid`, `vendor`, `signal`, `is_ap` and `bssid` or `channel`
  and `enc`), with `remote` true when `sloth.db` has no record of it and
  `note` naming each host that saw it, `"seen at beta-site, gamma"` (its
  label, else its `--peer` name). Its `fleet` also carries
  `probe_rows`, each peer's probe rows of the MAC (`site`, `label`,
  `kind` `"probe"`, the times and the `ssid` asked for; at most 64,
  newest first), so a station only a peer heard probing opens a drawer
  too. `/api/ble/{addr}` the same; an address only a peer reported is a
  `200` with no local row in place of the `404`.
- `/api/adsb/aircraft?hex=` gains `fleet` where a peer reported the
  address: `rows`, each `site`, `label`, `kind` `"aircraft"`, the times,
  `visit_first`, `flight`, `squawk`, `category`, `emergency`,
  `on_ground`, `alt`, `gs`, `track`, `rssi`, `messages`, `lat`, `lon`,
  `pos_ts`, `pos_prev`, `pos_alt` (`null` for what the line did not
  carry), with `remote` true and `note` naming the hosts when neither
  `sloth.db` (`aircraft` `null`) nor the panel's table holds it. The
  answer stays a `200`; `sightings` stay this site's own, so a peer's
  position is never drawn as a recorded track.

The remote rows are display only: no risk, alert, anomaly, baseline,
series, triage, tile count or detail audit reads them, and
`/api/fleet/export` reads `sloth.db` and the BLE table, never
`peer_sightings`, so a peer's rows never echo back to it
(`web/tests/test_fleetview.c`). The page draws them in the grey state
(`--tui-dim`, no hash hue) with the host's name beside the address, a
local row another host heard with a small `+name`; each view has a
"This site / All sites" choice kept in the browser (`fleet.devices`,
`fleet.aps`, `fleet.ble`, `fleet.probes`, `fleet.adsb`), All sites by
default and hidden with no peer. In the Probes tab a grey station opens its device
drawer and a grey network lists, under its row, each host that heard it
asked for and when. In the ADS-B tab a grey aircraft has no altitude colour or
signal meter; the positions plot draws it as a grey ring at the last
position its host sent, labelled with the host, with no track or
heading tick; its detail lists each host's figures and takes no notes.
The Radar dome asks `/api/adsb?fleet=0`: another host's aircraft has no
bearing or elevation from this site.

## Capture scope

Owner request 2026-10-26. The top bar's **Monitor | Hybrid | Local**
switch filters every view by how the data was captured
(`web/src/web_scope.h`; the whole of it, view by view, is
[docs/wiki/capture-scope.md](../docs/wiki/capture-scope.md)):

| Scope | Shows |
|---|---|
| Hybrid | everything: the default, and every view as it was before the switch |
| Monitor | what the passive monitor-mode radio heard over the air (beacons, probes, associations, EAPOL, deauths, the channel mix, the 802.11 detectors) and the BLE receivers (`--bt-monitor`, `--bt-capture`), which are receive-only radio too; nothing the connected Wi-Fi or Ethernet carried |
| Local | what the host's own interfaces carried: the IP capture on Ethernet and the associated Wi-Fi card, ARP, DHCP, DNS, mDNS, NBNS, the flows, `/proc`, the interfaces' throughput, and the managed card's own station dump and scan (the WiFi view under Local, `/api/wifi/local`); never the monitor radio |

sloth's records carry no capture path, so each datum is placed by what
it is: its record type, its alert type (the rule's input, whatever file
the rule is in), its metric, an interface's name (Monitor when sloth
has named it a monitor radio), a device's `DEV_SRC_*` bits and camera
signals. sloth's own state, and its two own-state alerts, are in every
scope. A device seen both ways appears in both, and in each shows only
what that scope captured: under Monitor no address or name behind it,
under Local no SSID, AP bit or PNL; its signal, first and last seen and
risk (sloth's score over the scope's signals) are the scope's own.
While sloth says its IP capture is itself a monitor radio
(`sensor_health.capture_linktype`, or `capture_iface == monitor_iface`
from an older sloth) the stream's IP-capture records count as
Monitor's; the host's own ARP table, DHCP leases and scan entries
(`/proc`, the lease files) never do, nor `PORT_SCAN` and `ARP_SPOOF`,
which read them. sloth.db's IP tables keep no capture path and stay
Local's. Under Local the WiFi view is the managed card's own scan and
link; Flows are empty under Monitor, saying why; the BLE view is empty
under Local, saying why (the receivers are passive radio, so `/api/ble*`
answers `out_of_scope` there and `/api/live`'s `ble` member is `null`);
so are the Probes view and an SSID's detail, the monitor radio's.
The SQL box is unscoped and says so. A device row's anomaly count and z, the
open-anomalies tile and the Records view are counted in the scope.

Every `/api` route but `/api/health` and `/api/query` takes
`scope=monitor|hybrid|local` beside its own parameters; the router
takes it out (`web_scope_take()`) before the route's parser runs.
Anything else is a 400 `bad_scope`. Without it the answer is
Hybrid's, byte for byte as before (the `/events` stream is not an
`/api` answer: its records gained `sc`, and a device row's `text_m`);
with it the answer's first member is `"scope"`, and a view the scope
holds nothing of answers `{"out_of_scope":true,"reason":...}`, its
query checked but nothing read. The page sends the scope on every
fetch, keeps it in the address (`#devices?scope=monitor`, Hybrid left
out) and in this browser (`slothweb.v1.scope`), and a chip at the top of
every view, the status strip and a bar under it say which scope is
shown; `?` beside the switch is the legend. A tile's drill-down opens
in the scope in force, the one its count was taken in.

## Kept settings

Owner request 2026-10-27: "the whole UI should keep settings between
launches where it is changeable". Every control a viewer can change is
kept per browser, in `localStorage`, one JSON value per setting under
one versioned namespace, `slothweb.v1.<name>`. Nothing reaches the
server and there is no endpoint for it: a second browser, or a second
viewer, starts from the defaults. A private window, blocked or full
storage, or a value that does not parse is the default, never an error
(every read and write is in a `try`, and the page was driven with
storage that throws on every touch). A later change of shape takes a
`v2` namespace; the keys of the build before this one
(`slothweb.theme`, `slothweb.scope`, `slothweb.sensitivity`,
`slothweb.cols.<table>`) are moved into `v1` on the first load and
removed, and no other key is touched, so opening this build after a
newer one on the same host:port leaves the newer one's `slothweb.v2.*`
as it was (`reset settings` clears `slothweb.v1.*` only, for the same
reason).

**The address wins.** A link that names a view, a filter or a scope
(`#alerts?state=open`, `#devices?q=pass:latest`, `?scope=monitor`)
opens on what it names, and a filter or a scope the address sets is not
kept. An Alerts address that names any filter sets every other one to
its default, the search and the window included, so
`#alerts?state=open` lists what the open-alerts tile counts and not
that with a search word kept from last week. The kept values are what
the page opens on at the bare address, or when a tab is clicked: an
Alerts or Devices address with no filter opens on the kept filters,
and leaving a drill-down puts the kept search back. A kept filter is
the viewer's own, not a drill-down, so it never raises the drill-down
bar; that bar's `show all` sets the view's filters to their defaults
and forgets the kept ones, so it does show all.

| Setting | Kept as | Notes |
|---|---|---|
| the view | `view` | a tab's view only (Overview to Lookup, Alerts), however it was reached, a link included (the link's filters and scope are not kept); an alert's page, the records and the health need the link they came from |
| theme | `theme` | applied before the first paint, as before |
| capture scope | `scope` | a pick in the switch (click or arrows); an address's scope wins for that view and is not kept |
| sensitivity | `sens` | 1.5 to 4 sd, checked as read |
| each table's column widths and sort | `table.<id>` | every table, by the one `DataTable()`: a width for a column the table no longer has is ignored and dropped at the next save (the SQL box's one `sql` id keeps only the current result's), one under the column's floor drawn at it, one over 4000 px (no drag makes one) ignored, a sort on a column that is gone or no longer sorts left off |
| the ticker's pause | `paused` | it opens paused and says so |
| the hidden view list and footer (`[`) | `collapsed` | |
| Anomalies: kind chip, cards or table | `anom.kind`, `anom.table` | the chip narrows the Anomalies list only: the Overview's open top five and the open-anomalies tile's drill-down are every kind |
| Anomalies: closed-in window | `ctl.n-win` | |
| Activity: metric, its key, window | `act.metric`, `act.keys`, `ctl.a-win` | the metric by name, each metric's key by itself |
| Activity: the small multiples' scale | `act.scale` | `own`, or absent for the shared default (#171 V1, F6) |
| Activity: one key or every key on the graph | `act.allkeys` | `true`, or absent for the default, one key; by `allkeys.js`. The key picked in the legend is not kept (it is a look, not a setting), but it sets the key picker, which is |
| Devices: search, sort | `ctl.d-q`, `ctl.d-sort` | |
| Lookup: the query box | `ctl.l-q` | kept, not run |
| WiFi: cells, window, AP sort | `ctl.w-metric`, `ctl.w-win`, `ctl.w-sort` | |
| Alerts: state, severity, type, search, window | `ctl.al-*` | the type put back once the server's list of types is in; a kept type the server answers `bad_type` for (renamed, corrupt) is dropped and the list reloaded without it |
| Flows: protocol tab, window, sort, address, the pairs' drawing | `flows.proto`, `ctl.f-win`, `ctl.f-sort`, `ctl.f-ip`, `ctl.f-mode` | an address picked from a row, the matrix or the chord is kept as if typed; the drawing is the matrix until the chord is chosen (ruling 4) |
| BLE: search, sort | `ctl.b-q`, `ctl.b-sort` | an address naming a search (`#ble?q=`) opens on it, not kept |
| BLE Devices: cells, window, devices | `ctl.bledev-metric`, `ctl.bledev-win`, `ctl.bledev-n` | the waterfall's three selects |
| Radar: the APRS window | `ctl.radar-aprs-win` | by `keepCtl()`; one of its five options (15 min to 24 h), else 1 h |
| Radar: the camera | `radar.yaw`, `radar.pitch`, `radar.zoom` | by `radar.js`; a number in range (yaw 0..360, pitch 10..90, zoom 0.5..4) else the default; `reset view` removes all three; the selection is not kept |
| Probes: window, minimum shared, the two orders | `probes.pr-days`, `probes.pr-min`, `probes.pr-cl-sort`, `probes.pr-ss-sort` | by `probes.js`; put back only as one of the control's own options; the picked station is not kept |
| the SQL box's text | `ctl.q-sql` | the draft; the first recipe no longer replaces it |
| Alerts: triage filter | `ctl.al-triage` | by `frrs.js`; `#alerts?triage=out` wins, and an address naming any other filter opens on `any` |
| triage: the "by" name | `frrs.by` | typed once, sent with every triage change from this browser |
| the FRRS record's open groups | `frrs.open` | a bit per group; Report and BEI open by default |
| TACDB: the selected unit, the search | `frrs.tacdb.unit`, `frrs.tacdb.q` | |
| the triage history and TACDB tables | `table.frrs.triage`, `table.tacdb-*` | through `DataTable()` as every table |

A select's kept value is put back only when it is one of its options,
a text only within the box's `maxlength`.

**Not kept, by decision:** the triage note and the TACDB tab's forms
(each the fields of one change, emptied once written: `frrs-note`,
`tc-u-*`, `tc-p-*`, `tc-pv-*`, `tc-e-*`, the import file); the recipe picker (it fills the SQL box,
whose text is kept); the History range (absolute times, stale on the
next launch) and its session markers; the Records view's type pick (a
row of a list that changes every 2 s: kept, a type that stopped
arriving would hide every record with no row left to unpick); the
device drawer, the scope legend, the WiFi grid's and the BLE waterfall's picked cells, an alert's
page's id (each a moment, or the address's); the frame filter of an
alert's capture (`ev-filter`: one file's frames, not a view's); the `more` pages (no page
size is a control: the pages are fixed). `web/tests/test_prefs.c`
fails on any new `select`, `input` or `textarea` (its attributes in
any order; one with no id fails too) that is neither kept nor listed
here, and on any toggle button, radio or tab set carrying ARIA state,
in the page or set by the script, that is not listed as kept.

**Reset.** Each table's `reset columns` forgets its widths and sort.
`reset settings` at the right of the footer (a second click within 4 s
does it) forgets every kept setting and loads the page again at the
bare address, on the defaults.

## Design

### The glyph layer

The page's data graphics are a small, fixed set of glyphs, specified in
[`docs/web-visual-spec.md`](../docs/web-visual-spec.md) (its rulings
table of 2026-10-26 overrides its body). All eight are built:
**G1** the band sparkline, **G5** the binary presence strip, **G6** the
bullet and count bar (slice V0), **G4** the hour-of-week grid (slice
V1, F3), **G2** the range sparkline (slice V2, F9; replaced on the page
by [the S-meter](#the-s-meter-2026-11-11) on 2026-11-11), **G3** the horizon
strip and **G7** the event rug (slice V3, F8, F12), and **G8** the
chain timeline (slice V4, F14). Slice V4 also lays G6's count bar out
as the Flows matrix (`glyph.mx()`, F11).

**Two halves.** Each glyph is a *pure function* from data and a size to
a list of marks, plus a *painter* that draws the list. A mark is
`[kind, x, y, w, h, token]`: a kind (`shade`, `band`, `line`, `gap`,
`dot`, `max`, `min`, `last`, `cell`, `warm`, `outline`, `first`,
`tick`, `now`, `range`, `bar`, `ref`, `whisker`, `dash`, the S-meter's
`seg`, `off`, `pklo`, `pkhi`, V3's
`hz1`, `hz2`, `base`, `clip`, `span`, `session`, V4's `axis`,
`link`, `grp`, and the ruler's `sun`), a rectangle in CSS pixels, and a colour **token** name — never
a colour. A word a glyph writes (V4's `label`, `word`, `num`, `proto`)
is a mark with a seventh member, its text, which the painter writes in
the token's colour at the mark's height in pixels, at most its width
wide; so a severity word or a count is in the mark list a test reads,
not added after it. Nothing in the pure half reads the DOM, the canvas or the
theme, so what a glyph *says* can be read without a browser, which is
what `web/tests/test_glyph.c` does: the C there is a port of
`web/ui/glyph.js` line for line, and the JS it ports is pinned verbatim
out of the served page, so a change on either side fails `make
web-test`. That keeps the suite free of node and of any other
dependency (owner ruling 2 of 2026-10-26), by the same mechanism
`test_tui_colors.c` already uses for the TUI's colours.
`web/tools/palette.c` is the other shape in this tree and does not fit
here: a palette is static data a tool can emit into `palette.js`, while
a glyph's geometry is a function of data the page only has at run time.

**The rules.** Every glyph and every panel follows these; a review of a
slothweb change checks the change against the list
(`docs/web-visual-spec.md` §8).

- **R1. One ink.** A line is `--tui-normal`. The band is `--data` at 12
  percent. Grey (`--rule`, `--faint`, `--muted`) carries structure.
  Colour carries only out of band (the heat ramp), severity (the
  `--sev-*` tokens, on alerts and chain bars only), identity (the hash
  hues on addresses and SSIDs) and the one accent (`--signal`, once per
  panel). **The exception is G1's line** (owner ruling 1 of
  2026-10-26): it keeps the level grading of the TUI's
  `draw_sparkline_at()`, so a web sparkline and a TUI sparkline of the
  same data are the same picture. Out of band is still said by the
  band and by the last-value dot, which is where a reader looks for it.
  **The second exception is G5's present cell** (owner ruling of
  2026-11-11, "color the 24 hour presence based on night sunrise day
  sunset"): it takes the sun's phase at the sensor, one of
  `--sun-night`, `--sun-rise`, `--sun-day`, `--sun-set`, and is
  `--tui-normal` only where there is no sensor position or the cell is
  longer than an hour. G5 only; see *G5 by the sun*, below.
  **And one graph mode** (owner ruling of 2026-11-11, recorded at the
  head of `docs/web-visual-spec.md`): the Activity graph's `keys: all`
  draws every key of the metric as its own line in that key's identity
  hue ([below](#every-key-on-one-graph)). It is the identity colour R1
  already grants, on a line; colour is never the only carrier there
  (R10), and the default (`keys: one`) and every other glyph keep one
  ink.
- **R2. Fixed heights, data-driven widths.** A glyph's height is set by
  the text line it sits in (14 px in a table, 18 px in a tile); its
  width follows the container. Never the other way round.
- **R3. Shared scales inside a set.** Small multiples share a y-scale
  by default and say so. `own scale` is a toggle and prints each cell's
  maximum. RSSI is always on the fixed −95 to −20 dBm scale. *Amended
  by the owner on 2026-11-11 for [the S-meter](#the-s-meter-2026-11-11):
  a signal is read on the scale of the band it was heard on (−95 to
  −20 dBm is the 2.4 GHz row), each table says so once, and the dBm
  number beside the meter is the raw value on every band.*
- **R4. Honest windows.** When the data covers less than a tenth of the
  window, the glyph shrinks the window to the data and the caption says
  `6 min of 24 h` (`glyph.win()`). A band chart carries at least three
  time labels and a now mark.
- **R5. Three empty states.** `no data` (a `--faint` dash across the
  middle, and nothing else, so it cannot be read as a flat line at
  zero), `warming` (the line with no band drawn, the word in the
  caption) and a gap (a break in the line, its own `gap` mark, which
  the painter draws as absence of ink). They never look alike. An
  empty panel collapses to its caption.
- **R6. Fewer than five points draw dots.** A line through three
  buckets claims a shape the data does not have.
- **R7. The last value is marked and written.** A `last` mark on the
  line and the number beside it, always. Min and max dots only where
  there is no band, because then the range is the only reference.
- **R8. No hatching, no gradients, no shadows, no rounded bars.** The
  chrome's radius applies to panels, not to data. "Not known yet" is
  never a texture either: G4's warming cell is a plain `--rule` tile,
  and where it has a sample its value so far is a solid `--tui-dim` bar
  on that tile (owner ruling of 2026-11-11, recorded at the head of
  `docs/web-visual-spec.md`; it amends the earlier rule that a warming
  cell makes no claim), never a hatch and never a heat token.
- **R9. The caption line.** Every panel ends with one `--muted` line:
  source, window, tier, scale, n, in that order, and then the state
  when there is one (`glyph.caption()`). Example: `ap.rssi
  02:de:00:00:00:a1, 1 h, fine, -95 to -20 dBm, n=360`.
- **R10. Greyscale must still read.** Every colour meaning is also a
  position, a shape or a word. A heat-coloured segment is also above
  the band; a severity bar also carries its word; the last value is its
  own kind of mark, not a dot like any other.
- **R11. Scales do not jump.** A glyph that refreshes every tick keeps
  its y-range until the data leaves it, and then grows it; it never
  shrinks on a refresh (`glyph.scale()` takes the previous range). A
  reader must be able to look away and back.
- **R12. The TUI form exists.** A glyph with no character-cell form is
  not added — parity is the test that keeps the web honest. The eight
  built here:

| Glyph | What it answers | TUI form |
|---|---|---|
| G1 band sparkline | what is the value now, and is it normal | the `▁▂▃▄▅▆▇█` sparkline of `draw_sparkline_at()` in `CP_NORMAL`, graded by level, with the last cell in `CP_HEAT_*` when out of band; the band is the `±` number after it |
| G2 S-meter (signal strength) | how near is this emitter, and how much has it moved | the character cells the emitter report prints: a full block a lit segment, `▁` an unlit one, a space at S9, then the S reading and the dBm (`███████▁▁ ▁▁  S7 -58`), with sloth's own distance cell (`rf_dist_cell()`: `~4.5m room ↘`) for the words. **Not built in the TUI** (R12 owed): the Devices view's Enter signal trail is still a trail on its own range |
| G2 as first built: the range sparkline (superseded 2026-11-11; `glyph.g2()` kept, no caller) | how near is this emitter, and is it moving | the same `▁▂▃▄▅▆▇█` glyphs on the fixed −95 to −20 dBm scale with the dBm number, and sloth's own distance cell (`rf_dist_cell()`: `~4.5m room ↘`) for the words. The Devices view's Enter signal trail draws a trail today but on its own range; adopting the fixed scale there is the TUI's half of R12 for G2, **not done in this slice** |
| G4 hour-of-week grid | when is this usually here, and is now usual | **not built in the TUI yet.** The spec's form is the Devices Enter detail's 7 by 24 grid of `▪` at `tui_heat`'s four levels. The web grid predates the glyph layer (M3); V1 moved it into `glyph.js` and took its hatch out, it did not add it, so R12 is owed here rather than met: the TUI form is a follow-up |
| G5 binary presence strip | when was it here | the Devices view's 24 cells, one an hour, as `▮` and `·`, with `◆` at a first-seen cell inside the window and the anomaly episode's cells underlined |
| G6 bullet and count bar | how big is this score or count, against its range | `▐████▌░░░` in `CP_NORMAL`, eight cells, the measure filled and the rest dotted |
| G3 horizon strip | which channels are busy against their norm, and when | the Channel view's histogram is the bar form of it; the spec's two-level row per channel, `▄` for the first band in `CP_NORMAL` and `█` for the second in `CP_HEAT_MID`, is **not built in the TUI in this slice** (R12 owed, as G4's is) |
| G7 event rug | when did things happen, and how many | the same `▁▂▃▄▅▆▇█` row per lane on one scale for every lane, a space for none; **not built in the TUI in this slice** (no TUI view has the 30 d strip or the deauth lanes yet) |
| G8 chain timeline | which stage of an attack is in progress, and what came before it | the spec's form: the Twins view's episode table carrying one 24-cell lane per stage, `━` for an incident's span and `●` where it began and closed, in the alert's severity colour, the deauth lane as G7's row; **not built in the TUI in this slice** (R12 owed, as G3's and G7's are) |

**Where they are drawn.** G1 paints every Overview tile, a 40 px G1
after each network fact in the status strip and after the footer's
`drops`, every anomaly card, and the Activity view's small multiples;
G4 paints the Overview's hour-of-week heatmap and the drawer's weekly
presence; the presence strips go through G5 (`drawStrip()`, `paintStrip()`),
their cells coloured by the sun at the sensor (below); the
S-meter (G2's sparkline until 2026-11-11) paints
the signal column of Devices and of the AP table, the drawer and the
Lookup card; G6 the risk, karma, anomaly-score and count columns (both
slice V2, `web/ui/rf.js`); G3 the WiFi view's channels and G7 its
chains and the History strip (slice V3, `web/ui/air.js` and app.js);
G8 the WiFi view's chains, the alert page and the drawer, and G6's
count bar the Flows matrix (slice V4, `web/ui/chain.js` and
`web/ui/flowmx.js`).

**G5 by the sun (owner ruling 2026-11-11).** A present cell of the
presence strip is coloured by where the sun was at the sensor at the
cell's midpoint: `--sun-night` under -6 degrees of elevation,
`--sun-day` over +6, and between them `--sun-rise` while the elevation
rises across the cell and `--sun-set` while it falls. Six degrees both
ways on purpose: -6 is civil twilight, the almanac's own line between
dusk and night; +6 is about where the low warm light ends; and at mid
latitudes the band between them is six or more ten-minute cells, where
the instant of sunrise would be one cell or none. Rising or setting is
the sign of the change across the cell, so a polar day (all day), a
polar night (all night) and a summer night that never leaves twilight
(sunset turning to sunrise at the sun's lowest) need no case of their
own.

- **The sun** is `web/ui/sun.js` (`SlothSun`, one namespace object, no
  DOM): NOAA's low-precision solar position, the declination and the
  equation of time from the fractional year, the hour angle from UTC
  and the longitude. No request, no library, no table. Geometric (no
  refraction), good to a minute or two; `test_glyph.c` holds it within
  three minutes of the U.S. Naval Observatory's rise, set, transit and
  civil twilight at five places.
- **The position is the sensor's.** `/api/gnss` (served under every
  scope): the newest fix when it is 2D or 3D, else `loc`, the position
  `sensor_health` carries (the last fix, or `--location`). Asked at
  load and every five minutes; the last valid one is held, so every
  strip on the page is coloured from the same place, and when it comes
  or moves (by a hundredth of a degree, about a kilometre) the strips,
  rulers and words drawn are drawn again. No new route. **Never the
  viewer's**: the page does not call the browser's geolocation and does
  not read its zone to guess, because the sensor may be a continent
  from whoever is looking, and the page asks the browser for no
  permission (`test_glyph.c` holds the page to both).
- **No position: no phase.** Every present cell is `--tui-normal`, the
  mark list the one it was before the ruling, and the words beside the
  strip say `no sensor position: presence in one ink`. The same for a
  cell longer than an hour, which spans a sunrise too often to be one
  phase: `cells over 1 h: presence in one ink` (History's ranges past
  six days; its 144 cells are then over 3600 s each).
- **Once per window.** `SlothSun.phases(from, cellS, n, pos)` is kept
  by position (to 0.01 degree), window start, cell length and count, 16
  windows at most, so a table's repaint is a lookup: the Devices rows
  share one window and the 144 positions are worked out once, not once
  a row.
- **The ruler (F10)** is drawn at last, in the presence column's header
  of the Devices, WiFi clients and History tables (`drawRuler()`, a
  144 by 6 px canvas over the rows' strips): a `--faint` tick at each
  midnight **of the sensor's zone** (below), `--signal` at
  now where it falls (none when a History range ended before now), and
  under them the phases as one `sun` mark a run, night 1 px, sunrise
  and sunset 2, day 3, from the bottom, so a row with three present
  cells still reads against day and night, and a phase is a height as
  well as a colour (R10). No position: the ticks alone.
- **In words (R10).** Each strip's label, and a line over each of the
  three tables, names the phases and when each begins in the window:
  `coloured by the sun at the sensor (gps fix), sensor time (slothweb's
  host), UTC-5: night, sunrise 06:10, day 07:20, sunset 16:00, night
  17:10` (`last gps fix` or `--location` for `loc`; past eight runs,
  the four words alone). `SlothSun.says()`, pure, ported and tested.
- **Sensor time (owner ruling 2026-11-11, the second).** The ruler's
  midnight ticks and the words' sunrise and sunset times are in the
  sensor's zone, not the viewer's, so the ticks and the sun's band
  agree whoever is looking: a sensor at UTC-7 seen from UTC+1 has its
  midnight ticks at 07:00 UTC. It is the one exception to the page's
  clock, every other time label staying the viewer's, and it is said
  where it applies: each table's line ends `midnight ticks in sensor
  time (slothweb's host), UTC-7; every other time on the page is your
  clock`, the ruler's title says the same, and each strip's words name
  the zone before their times.
  - **Where the zone comes from.** `utc_offset_s`, a number of seconds
    the server reports beside the strips: `/api/devices` (the offset
    now) and `/api/history/devices` (the offset at the range's end)
    gained it for this; `/api/device/{mac}` already had it in `week`,
    which the drawer and the alert page use. The Lookup card and the
    BLE drawer, whose answers carry none, use the last one any answer
    gave. No zone name is read and the browser's zone database is not
    asked (`SlothSun.zone()` takes two numbers).
  - **Whose zone it is.** `web_utc_offset()` is slothweb's own host's.
    Beside sloth that is the sensor's, which is why it is taken as
    such; a slothweb reading a copied sloth.db on another machine
    reports that machine's zone, and the words say `slothweb's host`
    so the reader can tell.
  - **Summer time.** One offset serves the whole ruler, the one at the
    window's end. A 24 h window is right but for the day of a change;
    a History range over a day that crosses one has its earlier ticks
    an hour out, and the line says `the offset at the range's end
    throughout` for every range over a day rather than hide it. An
    offset per midnight would need the server to answer one per day of
    the range; not built.
  - **No offset** (an older server, an error, a value past 18 h): the
    viewer's clock, as before the ruling, and the words say `your clock
    (the server gave no sensor offset), UTC+1`.
- **Every strip.** `paintStrip()` is the one caller of `glyph.g5()`;
  `drawStrip()` (the server's hex) and the BLE drawer's own cells go
  through it with the window's start and the cell's seconds: Devices,
  the drawer, Lookup, the WiFi clients and the alert page 600 s from
  `presence_from`; History `presence_cell_s` from `presence_from`; the
  BLE drawer its 900 s buckets from the bucket 95 before now's.
- **The colours** are in `web/ui/theme.css`, both themes written out
  (the light theme's data rule would turn the yellow into a brown
  beside `--heat-2`'s); night is the least contrast of the four in
  both, the quiet one, and day is `--tui-normal` by reference, the
  plain one. `web/tools/palette.c` fails the build when one is under
  3:1 on `--bg` or `--panel` (a graphic, WCAG 1.4.11) or within 20
  (CIEDE2000) of another phase or of a mark that shares the strip:
  `--signal` (the first-seen cell, the now tick), `--heat-2` (the
  anomaly underline), `--faint` (the midnight ticks). The figures are
  under *Contrast*, below.
- **TUI form (R12): owed.** The Devices view's 24 cells are not
  coloured by phase; sloth has the position (`--gps`, `--location`),
  so the form exists to be built.

**Slice V1 (#171), what each placement draws.**

- **Tiles and strip (F1, `web/ui/facts.js`).** The tiles are in the
  owner's urgency order (ruling 5): open alerts, open anomalies, sensor
  health, throughput, devices, records/s, then BLE advertisers. Each
  draws the 24 h series behind its number over the band for each
  bucket's hour — `live.alerts_open`, `live.anomalies_open`,
  `sensor.drops`, `iface.rx_rate` (app.js's own, as before),
  `live.devices`, `records.total` (shown per second, as the tile's
  number is) and `ble.devices` — and under the glyph G1's words:
  `band lo to hi` for the last bucket's hour (or `warming`, or `no
  data`) and `↑`, `↓` or `→` since the bucket before (`glyph.trend()`).
  The strip's `devs`, `ble`, `alerts`, `anomalies` and `rec/s` carry
  the same series at 40 by 12 px, and the footer's `drops` the
  sensor's (§6.9), with the last bucket's count beside it (R7: the
  footer has no `/api/live` figure of its own). A drop count is a
  bucket's sum, so its words name the bucket (`band 0 to 3 drops per
  10 s`, or `per 1 min` from the minute tier). The tile's number stays
  `/api/live`'s; the glyph is the stored series, read once a minute (the
  Overview's own minute, or facts.js's on every other view), its scale
  grown across refreshes and started again on a scope change. The five V1 series are Hybrid's
  (`web_scope_metric()` tag 0), so under Monitor or Local their glyphs
  are R5's dash and the words say `a Hybrid series: none under
  Monitor`; `ble.devices` is Monitor's too and a dash only under Local.
- **Anomaly cards (F13).** The metric that fired, as G1 over its band,
  with the episode's first-to-last window as a `shade` mark in
  `--signal` at 12 percent under everything else, clipped to the
  window. The window is the last hour, or back to ten minutes before
  the episode began, up to a day, read from the minute tier when it is
  over an hour and there is a store (a day at 10 s is ten pages a
  card). Each card's y-range is kept by episode and scope (R11), since
  the Overview rebuilds its cards every minute. A presence series keeps
  its strip.
  A failed read hides the canvas and says `series unavailable`, never a
  blank; the card's caption follows R9 and ends `shaded: the episode`.
- **Hour-of-week grid (F3, G4; owner ruling of 2026-11-11).** Every
  one of the 168 cells is drawn whenever there are cells: a grid that
  is all warming is 168 tiles under the now `outline`, which is always
  the last mark. (Until the ruling an all-warming grid drew the outline
  alone, which for the first three weeks of a store, and for any device
  under three weeks old, was one tile on an empty canvas.) A fed cell
  (n >= `warm_n`, 3) is one `cell` mark on the heat ramp by its mean
  against the largest fed mean, as before, and only a fed cell takes
  the ramp. A warming cell is one plain `--rule` `warm` mark, no hatch
  (R8). A warming cell with a sample (1 <= n < `warm_n`; a cell gets
  one sample a week) is **provisional**: on its tile it carries a
  `prov` bar in one ink, `--tui-dim`, the tile's width, rising from
  the tile's floor: 1 px for a mean of 0 (observed, absent so far), a
  quarter, a half or three quarters of the tile for a mean in the
  first, second or last third of the provisional scale (under 0.34,
  under 0.67, the rest). The bar never fills the tile, so in one grey
  a provisional cell is a part-inked tile and a fed cell a whole one
  (R10). **The provisional scale** is fixed at 0 to 1 for a map of
  shares (the drawer's presence map passes `share`; `/api/baseline`'s
  `"scale":"share_of_weeks"` says the same), where n = 1 gives the
  floor or three quarters and n = 2 the floor, the half or three
  quarters; for a mean of a gauge or a counter (the Overview's
  `iface.rx_rate`) it is 0 to the largest mean of any sampled cell,
  fed or provisional. A cell with n = 0 is the tile alone, so
  "observed, absent so far" and "not yet observed" are different
  marks. No cells at all (`"cells":null`, a pair never fed) is R5's
  `no data`: the `--faint` dash alone, no outline, no day or hour
  labels. The caption (`heatCaption()`) is R9's: the source, `hour of
  week`, the scale (`ramp 0 to 1.2k B/s`, the largest fed mean, while
  a cell is fed; `provisional bar in thirds of 0 to 1`, or `... of 0
  to 25.0k B/s`, while a cell is provisional), n (the samples behind
  the fed and the provisional cells), and while any cell is warming
  `warming: 156 of 168 cells, fed: 12, provisional: 84 (under 3
  weeks), not yet observed: 72`; with no cells, `no data`. The
  meanings are those words (R10): the bar on its tile reads 2.75:1 in
  the dark theme and 3.37:1 in the light, and against the panel beside
  it 4.35:1 and 5.07:1 (the graphics table under
  [Design](#design)).
- **Small multiples (F6).** One G1 per key over the last hour, every
  cell on one y-scale (`glyph.shared()`, grown and never shrunk on a
  refresh, R11, started again for a new metric, a scope or the toggle)
  whose top the caption prints once; the `scale: shared`
  button turns to `scale: own`, kept in this browser (`act.scale`),
  where each cell prints its own top in `--faint` at its top left.
  Sorted by |z| — the last bucket against its hour's band, a key with
  no baseline after every key with one, by value — or by value when no
  key has a baseline (`glyph.order()`); the caption says `sorted by
  |z|` or `sorted by value`. Each cell's line under its number carries
  its `z`. A presence metric keeps its strips.

#### The S-meter (2026-11-11)

Owner rulings of 2026-11-11, recorded in the header of
[`docs/web-visual-spec.md`](../docs/web-visual-spec.md): "make all
signal graphs a s-meter style bar", "yes add S+ numbers for wifi",
"make the s-meter appropriate for the band". Every place the page drew
a signal's strength as a graphic now draws `glyph.sm()`, a receiver's
S-meter, and G2's sparkline has no caller (`glyph.g2()` and its tests
stay).

- **The face.** Nine segments S1 to S9, 6 dB apart, then `+10` and
  `+20`, 10 dB apart, to 27 dB over S9. A segment is lit when the value
  has reached its edge: exactly -47 dBm at 2.4 GHz is S9, -47.01 is S8.
  The lit run is `--tui-normal` to S9 and `--heat-3` past it; an unlit
  segment is a 2 px `--rule` line, so lit against unlit is a shape as
  well as a tone, and the S9 boundary is a 3 px gap where the others
  are 1 px (R10). Segments are whole pixels. No new colour.
- **The scale is the band's.** One table, `SM_BANDS` in
  `web/ui/glyph.js`, with the reasoning in the comment over it; the
  step and the face are the constants beside it (`SM_DB`, `SM_UNITS`,
  `SM_OVER_DB`, `SM_OVER_TOP`). To move a band's reference, change its
  `s9`.

| Band | Middle used | S9 | S1 | Top of the face | Reasoning |
|---|---|---|---|---|---|
| 2.4 GHz (and BLE) | 2442 MHz | -47 dBm | -95 dBm | -20 dBm | S1 is the floor of the range R3 gave every RSSI glyph, eight 6 dB units under S9; the top is that range's top |
| 5 GHz | 5500 MHz | -54 dBm | -102 dBm | -27 dBm | 20 log10(5500 / 2442) = 7.05 dB more free-space path loss than 2.4 GHz, so the whole scale is 7 dB lower |
| 6 GHz | 6535 MHz | -56 dBm | -104 dBm | -29 dBm | 20 log10(6535 / 2442) = 8.55 dB, rounded to 9 |
| unknown | - | the 2.4 GHz row | | | a reading whose row names no band reads on the 2.4 GHz row and its label says `band unknown: 2.4 GHz scale`; a band is never guessed |

  It is a display scale, not the IARU reference (S9 = -93 dBm above
  30 MHz, -73 below), which would pin nearly every 802.11 reading past
  S9. The band comes from the row's own record: the `"rf"` member's
  `radio` (under `/api/devices`, above), else the AP row's
  `channel` as `ap_band_label()` reads a number (1 to 14 is 2.4 GHz,
  32 to 177 is 5 GHz), and for the report the BEI's `band`. BLE is the
  2.4 GHz row. Sloth reports no dBm for a ham or aviation band, so no
  view uses the IARU reference.
- **What the sparkline carried.** The lit run is the latest value; two
  `--ink` ticks, full height, are the window's least and greatest
  reading on the same band's row, drawn only where the window moved
  (one reading is the run alone). The 60 s whisker and the −67 dBm rule
  are not drawn: a third tick beside the two does not read at 72 px
  (−67 dBm is S5 at 2.4 GHz). No reading is R5's dash and no segment.
  A reading past either end is drawn at the end and counted
  (`glyph.smClamped()`, as `g2Clamped()` counted).
- **The words.** Beside every dBm meter its S reading and the dBm
  number, both: `S7 -58`, `S9+10 -35`. Past S9 the reading steps in
  tens as the face does (-46 dBm is `S9`, -37 is `S9+10`, -27 and above
  `S9+20`); the exact figure is the dBm. A reading under S1 is `S1`.
  The canvas has `role="img"` and a label that says the reading, the
  hour's range and the scale in words. Each table's caption line draws
  the face once, as text, with its labels and every band's S9
  (`SlothRf.legend()`, into the `.smkey` placeholder): `S █1 █2 … █9
  █+10 █+20 S9 = -47 dBm at 2.4 GHz, -54 at 5 GHz, -56 at 6 GHz, 6 dB
  per S-unit, by the band heard on; a display scale, not the IARU
  reference`. A cell's title names the scale it used, and `band
  unknown: 2.4 GHz scale` when the row names no band.
- **Where.** The Devices, AP and probing-clients `dBm` columns
  (`SlothRf.cell()`, the canvas 72 by 14 px as G2's was; the column is
  196 px where it was 150, for the S reading); the drawer and the
  Lookup card (`SlothRf.block()`, 18 px tall at the panel's width, the
  legend under it, R9's caption with the hour's range in S and dBm);
  the emitter report's `series_rssi` as character cells
  (Triage and the FRRS record, above); the BLE
  drawer on the 2.4 GHz row.
- **Other units.** A strength that is not dBm has no S-units and no
  band row: the GPS Sat table's signal cell is the same face over 0 to
  50 dB-Hz in ten 5 dB-Hz segments (`SPAN_DBHZ`), lit to the row's C/N0
  with ticks at the least and greatest of its points (a satellite not
  tracked is the dash), and the per-row C/N0 trail column is gone; the
  ADS-B table's signal cell is the face over -50 to 0 dBFS in ten.
- **Not the meter.** The BLE waterfall, the satellite history plot's
  C/N0 lane, the Radar and sky marks and the map's dots grade signal by
  colour over time or place; they are not level graphics and are as
  they were. Plain numbers stay numbers.

**Slice V2 (#171), what each placement draws (`web/ui/rf.js`).** The
two G2 bullets below are as V2 built them; the S-meter above replaced
G2 in both places on 2026-11-11.

- **G2 in the signal column (F9).** The Devices table's and the AP
  table's `dBm` cell: the row's `"rf"` (above, under `/api/devices`) as
  G2 at 72 by 14 px on the fixed −95 to −20 dBm scale (R3), a `--faint`
  rule at −67 dBm (owner ruling 3: a field rule of thumb for good
  coverage, not a standard), the whisker at the last value, the last
  value marked (R7) and written beside it, then **sloth's** band and
  trend glyph as the TUI's distance cell prints them (`room ↘`). The
  number is bold when sloth's trend says `approaching`, never by a
  slope the page fits (`glyph.g2Words()`), and each table's caption
  counts `n approaching (sloth's estimate)`. One ink (R1). Every row
  draws the same hour, so the rows compare (P4): R4's shrink is the
  full-width glyph's, not a table cell's. A row with no trail (Local,
  or nothing heard in the hour) is R5's dash beside sloth.db's number.
  A reading off the scale is drawn at its edge and counted
  (`glyph.g2Clamped()`).
- **G2 at full width (F20, §6.8).** The drawer, under the strip, and
  the end of the Lookup card (after the card's own copy of the
  drawer's strip): the same glyph across the panel, its window's three
  time labels under it, and R9's caption — `rf.rssi.sta
  da:a1:19:00:00:01, 1 h, fine, -95 to -20 dBm, n=42`, the clamped
  count, the −67 dBm rule named for what it is, where the whisker came
  from, and sloth's estimate in words. A trail under a tenth of the
  hour draws its own span and says `6 min of 1 h` (R4); with nothing
  to draw the block is its caption (R5).
- **The new mark (F15).** A `--signal` dot before the swatch of any
  row first seen in the last 24 h (the Devices view's strip window; the
  AP table's the same day), the row's one accent (P6), `new` in its
  title (R10); each table's caption counts `n new in 24 h`. G5's `◆`
  marks the first-seen cell on the Devices strip, the drawer's and the
  card's (`glyph.firstCell()`).
- **G6 (F17, §6.5).** A bullet on the bounded scores, the number kept
  beside it: risk on sloth's levels 0 to 3 (`DEV_RISK_*`), the tick at
  HIGH (2), the number in the TUI's heat grade; karma on
  `karma_candidates.score`, the TUI's `[y]` score of 1 to 7 (1, plus 2
  for a station's PNL, 1 for uniform IEs, 3 for a deauth chain;
  `src/karma_detect.c`), not the KARMA_AP alert's 0 to 100 confidence:
  the tick at 3, the least a candidate scores once the PNL or a deauth
  chain corroborates it (the alert's CRIT gate; the uncorroborated reach
  2); the anomaly score on every card
  and in the table, ranges at the heat ramp's 40 and 70, the tick at 60
  for A1 (`WEB_ANOM_Z_THRESHOLD` 3 sd, score z × 20) and none for the
  rules that score a fixed figure. The bar takes `--sev-warn` only at
  or past the tick, so a column is grey while all is well. A bar on the
  counts: the Devices `anom` column and the Flows `total` column, each
  on its own column's largest value (R3), which the Devices caption
  prints (`anom bars to 3`). The card's old rounded score bar is gone
  (R8). The Flows `counts` column, several numbers to a cell, is since
  #195 a name and a narrower G6 count bar per number, each on that
  count's largest in the rows shown (R3, one scale a count), so one
  count's bars read down the table beside the next.
- **G4's 56 by 28 form (§6.8, #195).** On the Lookup card of a MAC
  with a sloth.db record, between the strip and G2: the device's week
  (`/api/device/MAC`'s `week`, shares of past weeks present, as the
  drawer reads it) at a little over 2 px a cell, no labels, no tile
  inset (`glyph.g4()`'s `pad: 0`), and R9's caption. Drawn only when a
  cell has a sample; a failed read says `hour of week: unavailable`.

**#195, the V-slices' smaller leftovers.**

- **F4: tile prose as hover notes.** What a tile's number is, in words
  (`open alerts by severity ...`, the anomaly rules and A4's state, the
  throughput's `rx, 24 h, band = mean ± k sd`, what the device count
  counts), is the tile's `title`; the line under a tile's glyph is G1's
  words and, at most, a state (`in memory only: lost at a restart`,
  `waiting for a device pass`, `last known; stream not live`).
- **The Records panel's per-type G1 (§6.1).** Under the ticker's label,
  `records.rate` by type: the first 8 keys `/api/keys` lists (most
  recently seen first), each read for the last hour at the fine tier
  with its band, ranked by the hour's sum, the busiest 4 shown as the
  type, a 40 px G1 on its own scale (R11) and its last bucket's rate
  (R7); the caption `records.rate by type, 1 h, fine, own, rec/s, 4 of
  N types, busiest first`. A type with nothing in the hour is not
  shown. `web/ui/facts.js`, refreshed with the strip.

**Slice V3 (#171), the WiFi view's air picture (§6.3) and History's
rug (`web/ui/air.js`).** The WiFi view is four panels, top to bottom:
channels, emitters, chains, clients.

- **Channels: G3 (F8).** One horizon strip per channel, 18 px a row,
  the key in a gutter at its left and, right-aligned in `--faint`
  beside it, the strip's own top (R3: each strip is on its own scale,
  so each prints its maximum), or `z` for a z strip: two bands laid
  over one another
  (`hz1` in `--data` at 35 percent, `hz2` at 70 percent over it; Heer,
  Kong and Agrawala 2009). The scale is absolute and the server's
  (`/api/wifi/channels`' row `"scale"`, below): `ap_count` from 0 to
  the channel's own largest over 30 days, the second band its upper
  half; `ctrl_total` as z against the channel's hour-of-week baseline
  (`"z"`), the first band 0 to the slider's k sd and the second k to
  2k in `--heat-2`, the only colour on the panel, so the strip is flat
  while a channel is normal and the horizon and the band sparkline
  agree on what out of band means; a `ctrl_total` channel with no
  baseline yet is drawn from 0 to its own 30 d busiest, per minute,
  and its top is printed where a z strip's `z` is. R5's three states differ: nothing
  observed is no ink (a row with none is the dash), observed and quiet
  a 1 px `--rule` `base`, warming a `--rule` cell (`warm`, as G4's); a
  value past the top is drawn to it and marked by a 1 px `clip` along
  it (R10), counted in the caption. R11 per channel: a top grows and
  never shrinks until the metric or the scope changes. The caption:
  `wifi.ctrl_total, 1 h, fine, 5 as z against hour-of-week, band 2
  above 2.0 sd; 7 channels, 40 s cells, n=90`, then `warming: n cells`
  while any is. R4: when the columns any channel was observed in span
  less than a tenth of the window, every strip draws those columns
  only (one window for every row, so they still compare) and the
  caption says `6 min of 1 h` (`glyph.win()`). Rows are every channel seen in 30 days, so a channel
  that went quiet keeps its row. The `channels` control (kept, as
  `ctl.w-grid`) turns the panel back to **the stacked grid** below,
  unchanged; both answers are fetched whichever is shown.
- **The drill-in (ruling: both).** Pointing at, tapping or arrowing to
  a column outlines it in `--signal` and draws, in a 112 px column
  (56 px on a phone) beside the strips at their row height, that column's five busiest
  transmitters on each channel, stacked by share of its frames in their
  TUI colours on the monitor radio's ground (the stacking work of
  2026-10-23); the list under the panel names the picked cell's five,
  each a button, as the grid's does.
- **Emitters.** The AP table, nearest first by default (`sort=signal`,
  sloth.db's last signal, strongest first), with V2's G2, karma bullet
  and new mark; the SSID count is a row of `▪`, one per SSID (eight,
  then `+`), in `--sev-warn` above one, its count in words in the
  title, not `+3 ssids`.
- **Chains: G7 (§6.3, F16).** The deauth frames per bssid as an event
  rug (since V4, of the bssids with one stage; G8 draws the rest,
  below), a 12 px lane per bssid (the busiest 12) on
  one scale for every lane (R3; the timeline drew each row against its
  own busiest), the tallest printed in the caption, sloth.db's
  `DEAUTH_FLOOD` episodes as a 1 px `--sev-crit` underline across the
  cells they cover. A lane only for a bssid with a frame or a flood in
  the window (the route lists every key the rollup holds, so one that
  deauthed hours before the window comes with every cell empty); with
  none the canvas collapses and the caption says `0 deauth in the
  window`. Probe floods as a second rug are not
  drawn: `alerts.fired` is keyed by type number and the page does not
  hold that table yet; with G8 in V4.
- **Clients (F16).** The probe-client chart over its band (with no
  points the canvas is hidden and the caption says `no data`), and under it
  the devices sloth.db holds a `probe_clients` row for, last seen in
  the window, nearest first (`/api/devices?sort=signal&q=src:probe
  seen:<1h`, 50), each with the new mark, V2's G2 in its dBm column and
  G5 for its 24 h, so a probing client that is near and new is found by
  eye; a row opens the drawer. Its own table (`wclients`), held whole,
  sorted in place.
- **History: G7 (F12).** The 30 d strip is a rug of two lanes, devices
  first seen (`--tui-normal`) and alerts begun (`--sev-warn`), each
  tick as tall as its cell's count on one scale for both lanes (at
  least 1 px for one event), none drawing nothing, and survey sessions
  full height in `--ink`. The lanes span the canvas so a drag's x is
  still a time; the range picked is the `--signal` outline. The caption
  (`h-strip-note`) prints the tallest count, the cell size and the two
  totals. The overview already answered counts per cell (§7's route
  change was already true), so nothing changed on the server. The
  alert lane is one severity colour: per-severity counts would need
  the overview's read to group by severity, not done here.
- **The TUI's half (R12)** is not done for G3 or G7: no TUI view draws
  the forms in the table above yet.

**Slice V4 (#171), the attack chain and the Flows matrix
(`web/ui/chain.js`, `web/ui/flowmx.js`).**

- **G8, the chain timeline (F14).** sloth's rules know that a deauth
  flood, then an evil twin, then a client association to the twin is
  one event in three parts; the page showed them in three places. G8
  draws them as one: four 18 px lanes on one time axis, in the order
  the chain runs (`deauth`, `twin`, `assoc`, `karma`), every lane its
  `--rule` axis whether or not it has anything, so a stage not yet
  seen is an empty lane and the next stage is where to look. Deauth
  frames and associations are ticks on one scale for both lanes (R3,
  the tallest in the caption; R11 per BSSID until the window or the
  scope changes); each DEAUTH_FLOOD, EVIL_TWIN and KARMA_AP incident
  is a 4 px bar from its first to its last observation in the
  severity colour it reached (R1: severity on chain bars only), with a
  dot where it began and where it closed when that is inside the
  window and it has closed. A lane's words in the gutter carry its
  highest severity (`twin CRIT 70%`, R10) or `none`. Under the lanes,
  the links sloth made, each a `--faint` connector with its reason in
  words: `tainted ↑ 5 s` from the deauth lane at the first
  `twin_episode` that carried `attack_in_progress` (the twin tainted
  by a deauth flood on the other half within `DEAUTH_TWIN_WIN_SECS`),
  `attributed ↑` on the twin lane at the first that carried
  `attributed`; the twin's newest `confidence` follows its label.
  Three time labels under it (R4). The data is
  **`/api/wifi/chain`**: the deauth rows of `/api/wifi/deauth`, and
  since #195 every BSSID sloth.db holds an EVIL_TWIN or KARMA_AP row
  for in the window (`web_sdb_ap_attacks()`: beacon_aps' BSSID, the
  key matched at its fields), those an alert names first and the
  deauth-only ones after them, each part busiest first, at most 16; or
  the one BSSID `bssid=` names whether or not it has a deauth key; each
  with `"twin"` and `"karma"`
  (sloth.db's EVIL_TWIN and KARMA_AP rows whose key names the BSSID,
  matched as a predicate and never read out, `[first, last, sev,
  count]`, at most 8 each; the key matched at its fields, the pair's
  two BSSIDs after `twin:` or `twin-fp:` and the one after `karma:`,
  never as a substring, which would take the text across a pair's two
  halves or an attack-chain key's SSID), `"assoc"` (sloth.db's
  associations to it first seen in each cell; the station is never
  read), `"links"` (the stream's pairs naming it: `real`, `twin`, the
  first and newest record, `tainted` and `attributed` as those first
  times, the newest `confidence`), `"stages"` (deauth, twin, assoc and
  karma; an association counts only beside a twin or karma row, since
  on any other AP it is a station joining) and `"read"` (false when a
  sloth.db read failed). sloth.db keeps none of the links in a form G8
  can draw: its `twin_episodes` latches `attack_in_progress` with no
  time it was set and keeps neither `attributed` nor `confidence`, and
  EVIL_TWIN's attack-chain row is keyed by the SSID, not the BSSIDs,
  with its detail withheld on the web, so the links are the stream's
  `twin_episode`
  kept in memory (`web_chain.c`: 64 pairs keyed by the unordered pair,
  the least recently reported evicted and counted, every address
  through `web_key_mac()`, the SSID not kept), and the answer says
  since when (`"links_since"`, the first one kept). No slothweb.db
  step.
- **Where G8 goes.** On the WiFi view's chains panel (§6.3): one G8 per
  bssid with more than one stage, its address in its hash colour above
  it, and a bssid with one stage a lane of the G7 rug under it (§5:
  "a BSSID with one stage gets a G7 rug, not a G8"); with no chain the
  block collapses to its caption (`no bssid with more than one stage
  in the window`, F16). A BSSID with no deauth key in the window is a
  candidate there too since #195 when sloth.db holds an EVIL_TWIN or
  KARMA_AP row naming it (a twin raised with no deauth flood), and the
  BSSIDs an alert names are read before the deauth-only ones, so the
  16 a page reads are not all merely busy APs. **On the alert page**, in an
  `attack chain` section above the device's: the chain of the BSSID
  the alert names (`/api/alert`'s `device.bssid`: an AP sloth heard
  beacon that the key names, matched as a predicate, `null` for
  anything else, in which case the section is hidden), from a quarter
  of an hour before its first observation to five minutes after its
  last (at least half an hour, never past now); one stage is the
  caption alone (`one stage in the window: a chain draws from two`).
  **In the drawer** (§6.8), when the device is a BSSID with more than
  one stage in the last 24 h, and nothing otherwise. Under Local none
  of the three asks.
- **The Flows matrix (F11)**, above under Flows: the matrix first, the
  chord second, by ruling 4.
- **The TUI's half (R12)**: the Twins view's chain lanes for the
  selected pair (#195; `docs/views/twins.md`).
- **The probe-flood rug** (#195, V3's leftover): under the deauth rug,
  `PROBE_FLOOD` from `/api/alerts?state=all&type=PROBE_FLOOD` (the type
  by name, which is what the page lacked), a G7 lane per severity that
  has any in that severity's colour, the worst on top: a tick where a
  finding (one alert key) was first seen, its height the findings begun
  in the cell on one scale for every lane, and an underline from its
  first to its last sighting, which is the finding's span (quiet gaps
  between its incidents included, as the caption says). None in the
  window collapses it to its caption (`SlothAir.floodRug()`).

### Tables: sort and resize

Every table on the page (owner request 2026-10-26: the Devices table,
the AP table, each Flows tab, History's who was here, alerts, flows
and new-since lists, the drawer's and Lookup's lists, the Anomalies
view as a table (its `table` button), the Overview's latest alerts,
the record ticker, the Alerts page's list, an alert's history of runs
and its device's other alerts, the records view's types and records,
and the SQL box's result) is one implementation,
`DataTable()` in `web/ui/app.js`, with one rule set in `page.css`:

- **Sort.** A sortable column's header is a button: a click or Enter
  cycles ascending, descending and off, the header cell's `aria-sort`
  says which and a triangle shows it. A table whose rows the page
  holds sorts them in place, stably, by the column's type: an address
  numerically (IPv4 before IPv6, each by its bytes, `::` expanded), a
  MAC by its six octets, a time, a count, a dBm, a score or a severity
  by number, text by its UTF-8 bytes (no locale), an empty value last
  in either direction. A server-paged table (Devices, the AP table,
  Flows) asks the server again with the column's sort word and
  `dir=asc|desc`, which the server checks against its list (above); a
  column the server has no word for (a name slothweb computes, z, the
  anomaly count, a presence strip) is not sortable there. The server
  orders an address numerically too (`web_ipkey()`), so the rows it
  sends are the start of the order the page shows; the page sorts them
  again only when it holds them all, never a prefix (a page of Flows
  loaded by `more` lands after the rows above it). The SQL box types
  each result column from its values: numbers, addresses and MACs sort
  as such, anything else as text. The view's own `sort` select still
  works; choosing from it clears the header's sort. The Alerts page's
  list has no server sort: a header sorts the rows loaded so far (open
  first, then the newest change, until one does), `more` adding to them.
- **Resize.** A column's right edge is a separator: drag it (a mouse,
  a pen or a finger), or focus it with Tab and use the arrow keys (8
  px, 40 px with Shift; Home for the minimum), or double-click it (or
  Enter) to fit the column to its widest drawn cell. No column goes
  below its minimum (4 ch unless the column says otherwise) or below
  its header's label and sort triangle, so no header is cut to an
  ellipsis. A wide column that shares the row's free space (a name, a
  record, an alert) does so until its width is set; from then it is
  that width, the drag and the arrows start from the width drawn, and
  the separator's `aria-valuenow` (with `aria-valuetext` "N px",
  `aria-valuemax` 4000) is the width on the screen. The list tables'
  headers carry their `li` rows' padding, so each edge sits over its
  column.
- **Read as tables.** The box is `role="table"`, the header a row of
  `columnheader`s, every body row `role="row"` of `cell`s, and what
  holds the rows a `rowgroup`, set as rows are drawn.
- **Kept.** The widths and the sort are kept per table in this
  browser (`slothweb.v1.table.<table>`, [Kept settings](#kept-settings);
  the SQL box's widths by column name, so one query's widths reach only
  the same-named column of the next), read and written inside a `try`:
  a private window or blocked storage just means the defaults. A kept
  width under the column's floor is drawn at it, one over 4000 px is
  ignored as corrupt; a kept sort
  whose column is gone, or no longer sorts, is left off. Each table's
  `reset columns` forgets its widths and its sort.
- **Narrow windows.** A table is at least its columns' width and sits
  in its own `.hscroll` box, so at 360 px it scrolls inside the box and
  the page never scrolls sideways. Both themes use the chrome tokens:
  the separator is `--rule` until pointed at, dragged or focused, then
  `--signal`.


The page is two layers, coloured from two places (owner ruling
2026-10-23: "color code all data the same as the sloth cli").

**The chrome** (backgrounds, panels, the top bar, type, labels,
controls) is the owner's Spacetrucker design system
([www.river.io/jeff](https://www.river.io/jeff/)). `web/ui/theme.css`
carries its tokens (`--void`, `--void-2`, `--panel`, `--ink`, `--dim`,
`--dimmer`, `--phosphor` and its `-hi`, `-mid` and `-dim`, `--rule`,
`--ice`, `--violet`, `--brass`, `--amber`, `--dusk-teal`,
`--dusk-magenta`, `--paper`, the glows) and maps the page's semantic
names onto them, so the code still reads `--bg`, `--panel`, `--rule`,
`--ink`, `--muted`, `--faint`, `--signal`, `--data`, `--phosphor`:

| semantic | Spacetrucker | use |
|---|---|---|
| `--bg` | `--void` | the page ground |
| `--panel`, `--panel-2` | the site's panel, `--void-2` | cards, tiles; cells, chips |
| `--rule` | the site's rule | dotted row rules |
| `--ink`, `--muted`, `--faint` | `--ink`, `--dim`, `--dimmer` | text, secondary, disabled |
| `--signal`, `--data` | `--amber`, `--ice` | selection edge, canvas accent |
| `--hover` | `--phosphor` (light: `--phosphor-hi`) | hover text, the live pill |

The components are the site's: a sticky top bar on a brass edge with
the title, the views and the theme toggle; the pill status strip
(`live`, scope, devs, alerts, anomalies, rec/s — the network's facts
only, F5: every fact about slothweb itself is in the footer, `sock db
store tick up clients`, and the two rows are never mixed; the dot stays
in the strip because it is the page's own liveness, which is what the
strip's `aria-label` names);
eyebrow labels (brass small caps behind a short rule) as panel titles;
panels as brass-bordered cards (radius 14 px); the site's buttons and
chips for view controls; dotted row rules in tables; HUD corner
brackets and a dot grid on the Overview's tiles. Glows only on the title
and the live pill. The type is `"Fira Code", ui-monospace, "SF Mono",
Menlo, "DejaVu Sans Mono", monospace`: Fira Code is used where it is
installed and is never fetched; the page holds no font file and makes
no request of any kind (the rulings, and the CSP).

There is no motion layer: no boot-in, scramble, typing or beam, which a
page that updates every second would retrigger. The one animation is
the blinking cursor after the title, off under
`prefers-reduced-motion`. The site's CRT layer is kept very faint:
scanlines at alpha 0.07 and a vignette at 0.16 (the site's are 0.28 and
0.40), painted on the page ground under every panel, so they never
cross a chart; both are off in the light theme and under reduced
motion.

**The data** (every address, SSID, host name, info string, severity,
heat level and sparkline) is coloured exactly as sloth's TUI colours
it, in the dark theme byte for byte. Nothing is copied by hand:
`web/tools/palette.c` links `src/tui_palette.c`, asks
`tui_pair_colors()` for each pair the page mirrors, turns each xterm-256
index into hex by the standard formula (16 system colours, the 6x6x6
cube on 0/95/135/175/215/255, the 24 greys from 8 in steps of 10),
reads `find_brand()`'s table and the Google letter sequence out of
`src/tui.c` as text (a table it cannot read fails the build), and
writes `build/web/palette.css` and `build/web/palette.js`, which the
embedder takes as `@include`s. `app.js` ports the TUI's choices:

| data | TUI | page |
|---|---|---|
| an IP address, everywhere one appears (tables, cards, chord labels and nodes, the drawer, Lookup, alerts, flows, records) | `tui_ip_addstr()`: `ip_color_index()` (djb2 over the bytes, mod 8) into `tui_ip_fg` | `ipColorIndex()` over the UTF-8 bytes into `--k-0`..`--k-7` |
| an address an alert names | `tui_alert_hot_check()`, before anything else: for `ALERT_HOT_TTL_S` (3600 s) after the alert was last seen, its `match_ip` is `CP_ALERT_HOT_LOW` / `WARN` / `CRIT` by the alert's severity, bold from WARN; promotion only, 256 slots, the oldest replaced | `hotSet()` from each alert's `match_ip` (`/api/live`, the drawer's alerts), `hotCheck()` before the hash in `ipSpan()` and the chord's nodes: `--hot-0`..`--hot-2`, bold from WARN |
| an address seen in two or more sources | bold (`ip_index_is_cross_panel()`: more than one `IP_SRC_*` bit) | bold, by the same bits: the page keeps one index for its life (the TUI rebuilds its per frame), at the TUI's 512 addresses, and an address that turns cross-panel turns bold where it is already drawn. An alert counts toward `IP_SRC_ALERT` with its `match_ip` alone, as `ip_index_build()` adds it; the other addresses in an alert's text are coloured and counted toward no source |
| an SSID | `tui_ssid_addstr()`: the same hash and palette | `ssidSpan()` |
| a host name, a device name | `tui_brand_addstr()`: the earliest match of any brand, ASCII case-insensitive, a tie to the first entry; Google's letters in the logo's sequence | `brandRuns()` over the generated table into `--br-0`..`--br-15`, the rest in the row's pair |
| a record's info text | `tui_info_color()`: the hash into `tui_info_fg`, `CP_NORMAL` when empty | `infoClass()`, `--info-0`..`--info-7`, with every address in it in its own colour |
| MACs, labels, stamps | `CP_DIM` | `--tui-dim` |
| values, names | `CP_NORMAL`, `CP_BRIGHT` | `--tui-normal`, `--tui-bright` |
| severity | `tui_heat(0.3 / 0.5 / 1.0)` for LOW / WARN / CRIT | `--sev-*` on `--heat-1`..`--heat-3` |
| heat | `tui_heat()`'s 0.15 / 0.40 / 0.70 | `heatClass()`, `heat()` |
| sparklines | `draw_sparkline_at()`: level round(v / max x 8), 0 dim, 1-2 normal, 3-4 heat mid, 5-6 heat hi, 7-8 peak | `sparkLevel()`, `sparkColor()` |
| monitor-radio rows | `CP_MON_ROW` on xterm 236, stamp included (`draw_mon_row()`, `draw_mon_band_row()`) | `.ticker li.mon` on `--mon-bg`, the whole row in `--mon-fg`: every record type `src/jsonl.c` emits from the monitor radio's state (`MON_TYPES`: beacons to EAPOL, fifteen; not `wifi_ap` / `wifi_sta`, which are the managed interface's scan, nor the captive-portal events) |

The Flows view's protocol hues (`--f-*`) have no TUI counterpart (the
TUI has no flow chart); they stay chart colours named beside their
lines. `--f-kerb` is `var(--tui-normal)`, not a copy of its value. The
generator fails the build if two of the hues, or one and `--sev-crit`,
come within 15 (CIEDE2000) of each other in either theme, and prints
every pair under 30 below. An SMB1 row's protocol and counts are
`--sev-crit`; its addresses are coloured as every other address, so
they are alert-hot while `SMB1_USE` names one.

`web/tests/test_tui_colors.c` holds the two together: it links
`src/tui.c` (the ANSI backend), captures what the TUI writes for 18
addresses (half of them cross-panel), 8 alert-hot ones (`tui_alert_hot_set()`
by severity, at and past the TTL, a promotion, a full table), 15 SSIDs
(five not ASCII: 2-, 3- and 4-byte sequences and a surrogate pair), 32
host names (5 upper- or mixed-case) and 7 info strings, and compares
the colour of every byte with the colour the page gives it: the page's
functions pinned as served (`utf8()`, `ipColorIndex()`, `lowerAscii()`,
`brandRuns()`, `hotSet()`, `hotCheck()` among them), a C port of them
over the served `SLOTH_PALETTE`, and the served custom properties. The
port of `utf8()` encodes each SSID from the UTF-16 units a JS string
holds, so a non-ASCII SSID is hashed through the page's encoder and not
through the C string's bytes. The page's `MON_TYPES` is compared with
the record types `src/jsonl.c` emits from the monitor radio. It was
seen red with the generator's cube formula changed, with `app.js`'s
`IP_SRC` and tie rule changed, with its own port's tie rule changed,
with `utf8()`'s 2-byte lead changed from `0xc0` to `0xc1` (in the page,
and in the port), with `lowerAscii()`'s `+ 32` made `+ 0` (in both),
with the page's alert-hot bold moved to CRIT and its TTL made 3599, with
an alert's free text counted toward `IP_SRC_ALERT`, and with `"eapol"`
taken out of `MON_TYPES`.

**The light theme** is the site's cream (`--void` `#f4f0e6`), behind
the toggle in the top bar. Dark is the default whatever the browser
prefers. The script sits in `<head>` and sets `data-theme="light"` on
`:root` from `localStorage` before the body is parsed, so there is no
flash, and the rest waits for the DOM; the read and the write are in
`try`, and a page that cannot store just stays dark. It is the same
single `<script>`, so the CSP hash the embedder computes covers it as
before. The DOM's colours are `var()` references and follow by
themselves; canvases read their colours from the custom properties
(`theme()`), so the toggle clears that cache and redraws the open view
and the drawer.

The data keep their hue mapping in the light theme. The rule, in
`light_variant()`: keep the TUI colour's HSL hue and saturation, and
lower its lightness in steps of 0.005 until it reads at 4.5:1 (WCAG AA,
body text) on both the light `--bg` and the light `--panel`; a colour
that already does is kept. The monitor rows' ground is the light `--bg`
scaled toward black until it stands off `--bg` by the same ratio as
xterm 236 stands off the dark `--bg`, and their text follows the same
rule against that ground.

Contrast, computed by `make web-contrast` (WCAG 2.x relative luminance;
`*` marks a ratio under 4.5:1). The dark column is the TUI's own value,
kept byte for byte even where the TUI's choice reads under 4.5:1 on
this ground (`--br-8`, `--br-13`, `--info-0`, `--heat-0`, `--tui-dim`
on `--panel`). `--faint` colours disabled controls only (a disabled
chip); a placeholder that is not a control, such as the nav's
`Alerts`, is `--muted`. `--phosphor`,
`--data` and `--signal` colour no text in the light theme (edges,
brackets, canvas strokes), and the light theme's hover text and live
pill use `--hover` instead. Chip text (`--phosphor-mid`) sits on
`--panel-2` (4.69:1 light). The graphics table holds a mark that
carries meaning to 3:1 (WCAG 1.4.11). The hour-of-week heatmap's
warming cell is plain `--rule` since #171 V1 (F3: no hatch, R8): its
meaning is carried in words, the caption's `warming: n of 168 cells`
(R10), so the fill is structure, and a fed cell's lowest heat
(`--heat-0`) is measured against it below: 2.05:1 in the dark theme,
under 3:1, which is why the count in words is the carrier and not the
grey. A provisional cell's bar (owner ruling of 2026-11-11) is
`--tui-dim` on that tile: 2.75:1 in the dark theme, 3.37:1 in the
light, and 4.35:1 and 5.07:1 against the panel at the tile's edge; it
is told from a fed cell by shape (it never fills the tile) and by the
caption's count, not by hue alone. `--tui-dim` was chosen over `--data`
because `--data` at full strength reads 8.70:1 on the tile in the dark
theme, louder than every fed cell beside it, and the painter has no
reduced strength for a G4 mark. The dotted row
rules are under 3:1 on purpose; they separate rows that read without
them. A closed anomaly card is marked by a dashed edge and the word
`closed`, never by dimming, so its data keep these ratios.

| token | use | dark | on --bg | on --panel | light | on --bg | on --panel |
|---|---|---|---|---|---|---|---|
| `--ink` | body text | `#e8e2f2` | 16.29 | 15.57 | `#29212f` | 13.64 | 15.27 |
| `--muted` | secondary text | `#8a82a0` | 5.68 | 5.42 | `#6b6176` | 5.13 | 5.74 |
| `--faint` | disabled controls only | `#5a536e` | 2.84 * | 2.72 * | `#8f8799` | 3.03 * | 3.39 * |
| `--brass` | eyebrow labels | `#b88c40` | 6.74 | 6.44 | `#8a5f18` | 4.95 | 5.54 |
| `--phosphor` | chrome accent, no text | `#6bffcc` | 16.49 | 15.76 | `#0b8c6a` | 3.71 * | 4.15 * |
| `--phosphor-hi` | title | `#d9fff3` | 19.19 | 18.34 | `#06563f` | 7.65 | 8.57 |
| `--phosphor-mid` | chip text | `#43d6a8` | 11.21 | 10.72 | `#1a7d61` | 4.45 * | 4.98 |
| `--hover` | hover text, live pill | `#6bffcc` | 16.49 | 15.76 | `#06563f` | 7.65 | 8.57 |
| `--data` | canvas accent, no text | `#4cebff` | 14.37 | 13.73 | `#1a7ea1` | 4.06 * | 4.55 |
| `--signal` | selection edge, no text | `#ff8c26` | 8.87 | 8.47 | `#c25f0a` | 3.74 * | 4.19 * |
| `--k-0` | IP / SSID hash | `#00ffd7` | 15.99 | 15.28 | `#007a67` | 4.64 | 5.19 |
| `--k-1` | IP / SSID hash | `#5fd7d7` | 11.96 | 11.44 | `#1e7777` | 4.66 | 5.22 |
| `--k-2` | IP / SSID hash | `#87ffaf` | 16.64 | 15.91 | `#007f2a` | 4.53 | 5.08 |
| `--k-3` | IP / SSID hash | `#afff87` | 17.16 | 16.40 | `#2a7d00` | 4.58 | 5.12 |
| `--k-4` | IP / SSID hash | `#d7af00` | 9.84 | 9.40 | `#836b00` | 4.54 | 5.08 |
| `--k-5` | IP / SSID hash | `#ffaf5f` | 11.34 | 10.84 | `#ab5600` | 4.54 | 5.08 |
| `--k-6` | IP / SSID hash | `#d78787` | 7.56 | 7.23 | `#c04242` | 4.50 | 5.04 |
| `--k-7` | IP / SSID hash | `#87afd7` | 8.98 | 8.58 | `#386fa7` | 4.61 | 5.16 |
| `--br-0` | brand | `#0087ff` | 5.80 | 5.54 | `#006dcf` | 4.51 | 5.05 |
| `--br-1` | brand | `#d75f5f` | 5.59 | 5.34 | `#cb3333` | 4.54 | 5.09 |
| `--br-2` | brand | `#ffd700` | 14.70 | 14.05 | `#7f6b00` | 4.61 | 5.16 |
| `--br-3` | brand | `#00af5f` | 7.16 | 6.85 | `#007c43` | 4.66 | 5.21 |
| `--br-4` | brand | `#ff8700` | 8.56 | 8.18 | `#a85900` | 4.51 | 5.05 |
| `--br-5` | brand | `#ff0000` | 5.16 | 4.93 | `#db0000` | 4.60 | 5.15 |
| `--br-6` | brand | `#808080` | 5.22 | 4.99 | `#6d6d6d` | 4.55 | 5.09 |
| `--br-7` | brand | `#875fff` | 5.02 | 4.80 | `#7445ff` | 4.57 | 5.12 |
| `--br-8` | brand | `#005fff` | 4.01 * | 3.83 * | `#005fff` | 4.52 | 5.06 |
| `--br-9` | brand | `#00d75f` | 10.69 | 10.21 | `#007e38` | 4.57 | 5.11 |
| `--br-10` | brand | `#af5fff` | 5.80 | 5.54 | `#952cff` | 4.52 | 5.06 |
| `--br-11` | brand | `#ffaf00` | 11.18 | 10.68 | `#916400` | 4.58 | 5.13 |
| `--br-12` | brand | `#0087af` | 4.99 | 4.77 | `#007598` | 4.62 | 5.17 |
| `--br-13` | brand | `#af0000` | 2.77 * | 2.65 * | `#af0000` | 6.54 | 7.32 |
| `--br-14` | brand | `#ff5f00` | 6.76 | 6.46 | `#bd4600` | 4.57 | 5.11 |
| `--br-15` | brand | `#d75faf` | 6.03 | 5.77 | `#c13091` | 4.50 | 5.04 |
| `--info-0` | record info | `#875f5f` | 3.76 * | 3.60 * | `#875f5f` | 4.82 | 5.39 |
| `--info-1` | record info | `#87875f` | 5.56 | 5.31 | `#6f6f4e` | 4.55 | 5.09 |
| `--info-2` | record info | `#af875f` | 6.34 | 6.06 | `#896745` | 4.51 | 5.05 |
| `--info-3` | record info | `#afaf87` | 9.13 | 8.73 | `#6f6f4a` | 4.56 | 5.10 |
| `--info-4` | record info | `#d7875f` | 7.38 | 7.06 | `#aa552b` | 4.56 | 5.11 |
| `--info-5` | record info | `#d7af5f` | 10.00 | 9.56 | `#8a6722` | 4.56 | 5.11 |
| `--info-6` | record info | `#af8787` | 6.52 | 6.23 | `#916060` | 4.56 | 5.11 |
| `--info-7` | record info | `#878787` | 5.74 | 5.48 | `#6d6d6d` | 4.55 | 5.09 |
| `--tui-bright` | TUI phosphor | `#00ffaf` | 15.63 | 14.94 | `#007d56` | 4.54 | 5.08 |
| `--tui-normal` | TUI phosphor | `#00d7af` | 11.13 | 10.64 | `#007b64` | 4.59 | 5.14 |
| `--tui-dim` | TUI phosphor | `#00875f` | 4.55 | 4.35 * | `#007d58` | 4.53 | 5.07 |
| `--heat-0` | heat, severity | `#626262` | 3.38 * | 3.23 * | `#626262` | 5.36 | 6.00 |
| `--heat-1` | heat, severity | `#d7af00` | 9.84 | 9.40 | `#836b00` | 4.54 | 5.08 |
| `--heat-2` | heat, severity | `#ff8700` | 8.56 | 8.18 | `#a85900` | 4.51 | 5.05 |
| `--heat-3` | heat, severity | `#ff0000` | 5.16 | 4.93 | `#db0000` | 4.60 | 5.15 |
| `--hot-0` | alert-hot address | `#ffd700` | 14.70 | 14.05 | `#7f6b00` | 4.61 | 5.16 |
| `--hot-1` | alert-hot address | `#ff8700` | 8.56 | 8.18 | `#a85900` | 4.51 | 5.05 |
| `--hot-2` | alert-hot address | `#ff0000` | 5.16 | 4.93 | `#db0000` | 4.60 | 5.15 |
| `--f-ssh` | chart hue | `#7fd1ff` | 12.24 | 11.70 | `#0072b2` | 4.56 | 5.10 |
| `--f-rdp` | chart hue | `#b48cff` | 7.99 | 7.63 | `#803dff` | 4.58 | 5.13 |
| `--f-smb` | chart hue | `#ffd166` | 14.30 | 13.67 | `#8f6400` | 4.62 | 5.18 |
| `--f-snmp` | chart hue | `#9be564` | 13.53 | 12.93 | `#407a15` | 4.60 | 5.15 |
| `--f-bgp` | chart hue | `#ff9ecb` | 10.80 | 10.33 | `#d60063` | 4.57 | 5.11 |
| `--f-ldap` | chart hue | `#c0c0c0` | 11.33 | 10.83 | `#6d6d6d` | 4.55 | 5.09 |
| `--f-kerb` | chart hue | `#00d7af` | 11.13 | 10.64 | `#007b64` | 4.59 | 5.14 |

Graphics (`*` under 3:1):

| graphic | on | use | dark | light |
|---|---|---|---|---|
| `--rule` | `--bg` | row rules | 1.65 * | 1.34 * |
| `--rule` | `--panel` | row rules, the warming cell | 1.58 * | 1.51 * |
| `--heat-0` | `--rule` | a fed cell's lowest heat, beside a warming one | 2.05 * | 3.99 |
| `--tui-dim` | `--rule` | a provisional cell's bar, on its warming tile | 2.75 * | 3.37 |
| `--tui-dim` | `--panel` | a provisional cell's bar, against the panel beside the tile | 4.35 | 5.07 |

Chart hues closer than 30 (CIEDE2000) in either theme; under 15 fails the build:

| hues | dark | light |
|---|---|---|
| `--f-ssh`, `--f-rdp` | 27.2 | 25.6 |
| `--f-ssh`, `--f-ldap` | 19.8 | 21.6 |
| `--f-ssh`, `--f-kerb` | 29.7 | 30.8 |
| `--f-rdp`, `--f-bgp` | 21.8 | 30.3 |
| `--f-rdp`, `--f-ldap` | 27.8 | 31.6 |
| `--f-smb`, `--f-snmp` | 26.4 | 28.4 |
| `--f-smb`, `--f-ldap` | 25.8 | 24.4 |
| `--f-smb`, `--sev-crit` | 44.2 | 29.8 |
| `--f-snmp`, `--f-ldap` | 27.7 | 25.5 |
| `--f-snmp`, `--f-kerb` | 20.9 | 18.8 |
| `--f-bgp`, `--f-ldap` | 24.2 | 27.9 |
| `--f-bgp`, `--sev-crit` | 35.5 | 23.0 |
| `--f-ldap`, `--f-kerb` | 25.5 | 23.1 |

The sun's phases on the presence strip (G5), graphics (`*` under 3:1), and how far apart (CIEDE2000) they and the strip's other marks are; under 20 fails the build:

| token | dark | on --bg | on --panel | light | on --bg | on --panel |
|---|---|---|---|---|---|---|
| `--sun-night` | `#4a72c4` | 4.41 | 4.22 | `#5b84d6` | 3.23 | 3.61 |
| `--sun-rise` | `#ffe07a` | 15.90 | 15.20 | `#8a7a00` | 3.79 | 4.25 |
| `--sun-day` | `#00d7af` | 11.13 | 10.64 | `#007b64` | 4.59 | 5.14 |
| `--sun-set` | `#e0569b` | 5.86 | 5.61 | `#c2247a` | 4.82 | 5.40 |

| marks | dark | light |
|---|---|---|
| `--sun-night`, `--sun-rise` | 62.1 | 54.5 |
| `--sun-night`, `--sun-day` | 45.7 | 35.9 |
| `--sun-night`, `--sun-set` | 35.0 | 37.8 |
| `--sun-night`, `--signal` | 52.8 | 47.6 |
| `--sun-night`, `--heat-2` | 53.5 | 48.4 |
| `--sun-night`, `--faint` | 21.1 | 21.2 |
| `--sun-rise`, `--sun-day` | 34.9 | 30.7 |
| `--sun-rise`, `--sun-set` | 60.2 | 59.1 |
| `--sun-rise`, `--signal` | 26.6 | 25.3 |
| `--sun-rise`, `--heat-2` | 27.2 | 21.8 |
| `--sun-rise`, `--faint` | 60.2 | 37.7 |
| `--sun-day`, `--sun-set` | 62.2 | 49.3 |
| `--sun-day`, `--signal` | 53.7 | 47.8 |
| `--sun-day`, `--heat-2` | 54.2 | 44.0 |
| `--sun-day`, `--faint` | 50.7 | 33.4 |
| `--sun-set`, `--signal` | 43.3 | 39.8 |
| `--sun-set`, `--heat-2` | 44.8 | 41.4 |
| `--sun-set`, `--faint` | 29.7 | 26.9 |

Monitor rows, on `--mon-bg` (`#303030` dark, `#c5c2ba` light):

| token | dark | on --mon-bg | light | on --mon-bg |
|---|---|---|---|---|
| `--mon-fg` | `#00d7af` | 7.13 | `#005a49` | 4.61 |

## What it never does

The [Security](#security) section above is the summary; this is the
same list as code facts.

- No write but to slothweb's own store: POST only on the seven triage, link and
  TACDB routes, same-origin, bounded, rate limited; none under
  `--web-read-only`, where every other method stays `405` as before.
- No name resolution of any kind, including its own bind address.
- No write to `sloth.db`, ever, and no migration of it and no file beside
  it: `--sloth-db` opens it `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW`
  (an immutable URI when that is what makes no side file), and
  `--store` pointed at it is refused untouched. The SQL box opens it
  the same way and adds its own read-only authorizer on top.
- No credential column served, the SQL box included: the withheld
  columns (`web_secret.h`) are refused to every statement.
- No active lookup of any kind: no PTR query, no `getnameinfo()`, no
  WHOIS or GeoIP (the 2026-10-21 rulings). Every name slothweb shows was
  already on the wire.
- No write to the data socket, ever: slothweb only reads it.
- No request off the host from the page: no URL, no font, no script
  from anywhere but the page itself, enforced by the CSP above and
  checked by `test_routes.c`.
- No TLS and no authentication. For access from another host, forward
  the loopback port (`ssh -L 8770:127.0.0.1:8770 user@sensor`) rather
  than binding a routable address.

## Tests

`make web-test` builds `slothweb_test` from `web/tests/*.c` and the
`web/src/` modules (not `main.c`). It needs no host file and no running
sloth, opens only loopback ephemeral ports (`127.0.0.1` and `::1`, port
0), and unix sockets and SQLite files in fresh `mkdtemp()` directories
under `/tmp`, and never leaves the host. Its sloth.db files are made
from sloth's own DDL (`src/db_schema.c`, linked into the test binary
only) and its OUI tables from CSVs it writes itself: nothing is a
committed fixture. The one committed input it reads is the registry in
`web/data/`, which it holds to `SOURCE.md`'s hashes and builds under a
time bound in a forked child (a generator that never finishes fails
the test instead of hanging the suite). Every M2 to M6 test runs on a pinned clock, and the suite pins the zone (`TZ=UTC0`) too, since a
baseline cell is a local hour. `make web-test WITH_SQLITE=0` builds and runs the same suite
against the memory-only build. It is clean under
`EXTRA_CFLAGS="-Werror -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"`
and under `EXTRA_CFLAGS="-Werror -fsanitize=thread"` with
`TSAN_OPTIONS=halt_on_error=1`.

| File | Covers |
|---|---|
| `test_acl.c` | the list on hand-built sockaddrs: loopback default, non-loopback v4/v6 refused, prefix boundaries, v4-mapped folding, CIDR parse errors |
| `test_config.c` | `--web-serve-evidence-pcap` off by default, announced when given, refused with `--web-allow-remote` unless `=remote` (then announced for remote peers), any other `=value` an unknown option; `--web-allow-sql` off by default, refused by `--strict` and without `--sloth-db` (and without SQLite), announced with `--web-allow-remote` and silent without it; default bind, remote bind refused without the flag and announced with it, remote `--web-allow` needs the flag, `--strict`; `--socket` default, parsing, the announcement of a non-loopback `tcp:` and its `--strict` refusal; a `--web-max-mb` below the analysis state's estimate plus the history allowance refused naming the minimum (one MB less refused, the minimum and the defaults accepted, 8,192 keys at the default ceiling refused; nothing refused without SQLite) |
| `test_http.c` | hand-written request bytes: GET/HEAD routed, 405 for every other method, split reads, 400/505, the 8 KB boundary, path and query, `If-None-Match` collection and weak comparison, `Host` collection and which values are accepted |
| `test_routes.c` | the route table without a socket: page `200`/`304`/`HEAD`, no external reference in the served page, no HTML or code sink in its script (stream values are `textContent` only), the font stack (Fira Code named once, no font file), the chrome tokens, the CSP hashes recomputed (SHA-256 checked against FIPS 180-4 vectors), health JSON, stream headers, `503`, event formats, `404`, `405` on every route, `421` for a foreign `Host` on every route and `400` for none or two; `/api/anomalies` (`503` without an engine, the JSON byte for byte, `HEAD`, every `400`, the filters, the worst case a `200` with `more`), `/api/baseline` (`503`, every `400`, never fed, a fed cell at its index), the `anomaly` event as one data line, `anomalies_open` in the tick, the M3 health members; the page's M3 element ids and their lookups and the two fetches' literal prefixes, with those query shapes answered `200`; a non-finite cell answered as `null`; the page's `cellOf()` pinned as served and checked against `/api/baseline`'s `now_cell` for every 10 minutes of a week in IST |
| `test_json.c` | the writer's escaping byte for byte: markup, quotes, controls, C1, U+2028/9, invalid UTF-8 as U+FFFD, the code-point-boundary cut |
| `test_jsonl.c` | hand-written lines: sloth's shapes, escapes and surrogate pairs, member text inside a string, every truncation of a record, syntax errors, invalid UTF-8 raw and escaped, duplicate members, the depth, member and integer limits |
| `test_live.c` | the live state and the framer without a socket: the device count per pass, passes cut by a gap, a bad line or a bad type not published, an empty table publishing 0, a reconnect as a new stream, the alert lifecycle counts, an alert's `match_ip` (an address or `""`), type names, records per second, sensor-health states, the recent ring, hostile strings escaped in `/api/live` and in `record` events, the worst-case `/api/live` fitting its buffer, split reads, truncated and overlong lines |
| `test_ingest.c` | the client over a real unix socket and loopback TCP, the test playing sloth: `--socket` parsing and its refusals, the back-off bound, **the device count `/api/live` reports matching what the fake sent within 5 s** for 3, 12, 300, 0 and 7 devices (spec §12, M1), markup escaped over HTTP and over `/events`, reconnect after the peer closes, retrying with no peer at the capped interval, no tight loop on a peer that closes at once, a mixed stream of truncated, overlong, invalid-UTF-8 and hostile lines, and that the client never writes to the socket |
| `test_rollup.c` | bucket boundaries in all three tiers, sum/count/min/max, value by kind, non-finite and huge values, the per-class key caps and LRU eviction with its flush and counters, churn decided on a key's whole life (keys of two and three samples crossing minute and hour boundaries keep only their 10 s rows, a key spanning a minute keeps all), held rows released when a key is established and at shutdown, a host recurring under LRU pressure keeping its minute and hour rows, interface, channel and alert keys established from their first sample and in classes of their own, the ring query's merge and bounds, the full store queue dropping 10 s rows before minute and hour rows and counting them, and every class full at `--web-max-keys` 8192 across an hour boundary and a shutdown with nothing dropped |
| `test_metrics.c` | hand-written lines through the decoder on a pinned clock: the key canonicalisers, gauges from `%.2f` reals, hostile keys refused, event counters, running totals as deltas floored at zero and first-sight baselines, flows, channels, presence, a probe request counted once though both `probe_client` and `seqnum_client` carry it, rows per pass with gaps and bad lines, the bounded high-water table, an evicted row seen again not counted twice, the evicted-id filter's two generations remembering an id across 8,191 evictions and forgetting it at the next rotation; `rf.rssi.*` from `probe_client`, `beacon` (no channel mix wired), `assoc` (the BSSID's, never the station's) and `ble_device`, a stale row, a Wi-Fi 0 and `has_rssi` 0 adding nothing, and the device cap's eviction at `--web-max-keys 16` |
| `test_store.c` | the DDL guardrail in every build; with SQLite: a fresh store, `test_db.c`'s secret-column sweep, secrets fed through the stream absent from the file, a v0, a v1, a v2, a v3 and a v4 file migrated, a v0, a v1, a v2, a v3 and a v4 file whose step fails left where they were, `chmix`'s merge, tiers and bounded reads, its retention (minute rows three days, hour rows 400) and its row cap (minute rows first, counted), the cap and the ceiling deleting whole buckets, the kind in the key, `passive_ptr`'s upsert, bound and read-back, the presence cells of the minute tier, the v3 tables through their own calls (a baseline restored into a smaller table with the rest and an invalid row deleted, episodes expired at load, histograms, the reported set pruned, the A9 and MAD reads), a newer file and foreign files (a sloth.db shape, other databases, a file with another program's `application_id` and `user_version` but no table yet, our own `meta` under a foreign `application_id`, not SQLite) refused byte for byte, a WAL-mode sloth.db with an unflushed WAL refused with the file and its WAL byte for byte, a cleanly closed WAL-mode sloth.db refused with its directory listing unchanged, the file rules (symlink, mode, links, side files, a directory; the owner rule is not tested, see below), `DEFENSIVE` refusing a `sqlite_master` write on the store's handle and a library that leaves it off failing the open, a file swapped between the identifying and the writing open refused byte for byte, merged writes counted once in `store_rows` and bound queries, retention, the WAL left empty by the compaction, a start after a long stop expiring everything with the WAL never past one slice, the ceiling dropping the oldest fine rows first and sparing global series, keeping the time series within the history allowance (and rows left) while 80,000 rows arrive with the analysis state alone over it (with `dbstat`; without it, the fallback asserted), re-measuring the baseline tables after `web_store_bl_del()` and the episode table on the next pass, and holding under 200 new keys a second within one flush interval; a new baseline entry taking over its pair's stale row, a restore of 4,000 entries into ten keeping the WAL under 3 MB, the analysis estimate against the default ceiling; churn of two and three samples per key writing no minute or hour row while slothweb runs; the ceiling taking a flood's 8,192 unflagged advertisers before any keyed minute row, the HID rows and the findings kept |
| `test_series.c` | every parameter rule and its reason, the answer's shape and paging, the routes (`HEAD`, `400` without echo, `query_too_long`, `421` and `405` on all three, `503` without a time series, the health members), the 900-point worst case fitting, the 900-point cap on a store+memory answer of 1,800 buckets and its next page, the store thread running beside reads and writes, and spec §12's M2 acceptance: an hour of records through the framer on a pinned clock, the 24 h request answered with 360 points 10 s apart (from memory, from the store's fine tier, and through `/api/series` again after a restart over the same store), the store under 5 MB on disk with its WAL after every step of the hour |
| `test_server.c` | real loopback sockets: default bind address, a refused peer over v4 and v6, 405 for POST/PUT/DELETE/PATCH, 431, idle and slow clients timed out, slot exhaustion; the page byte for byte and its `304`, health, a stream's ticks and pings and the client leaving, the first tick at once, a departing client noticed on the read path with no event due, the stream socket's `TCP_NODELAY` and `SO_SNDBUF`, a non-reading stream client dropped at the 64 KB backlog and not past it, the stream cap, `421` for `Host: attacker.example`; an episode that opens reaching a stream client as one `anomaly` event, counted once |
| `test_baseline.c` | the cell as the local hour of the week, Monday first, and the same cell for the same local hour across a DST change (167 UTC hours apart), a never-fed pair scoring absent and a zero feed making no entry, warming forcing z to 0, an established cell's z, the sd floor (a constant history and one AP more scores 1, not 31,623; 10% of the mean; 1 KiB/s for a byte rate), an hour fed once, zero feeds for counters and presence and none for gauges and not counted as activity, cells independent, the full table evicting the least recently active entry by real feeds only, ageing out with the row id queued for deletion, allocation following the entries, dirty cells out once and back through a restore, the cap at the default and the extremes, NaN and both infinities ignored, the value scale per kind, a minute's sd carrying the within-hour spread (and Poisson for a counter), the delete queue returning 5,000 ids with none lost, refused records held to the next pass, restore refusing values a float cannot hold and keeping `first_fed` |
| `test_ident.c` | records on a pinned clock: the earliest `first_seen` kept and randomised MACs left out, names cut to 63 bytes on a code-point boundary and NBNS to 15, group NBNS suffixes ignored and names current for their TTL, both tables evicting and counting, the DNS join (an NXDOMAIN answer counted once against the client that asked that qname within 10 s, a late or unknown one unmatched), the normal form |
| `test_anomaly.c` | every rule from seeded state, rows given to the engine as web_tsdb gives them and the clock moved only through its step: A1 opening on three burst minutes with the evidence `metric[key]` closed, never on two, a gauge gap breaking the streak, a constant history with ±1 jitter firing nothing, a silent counter scored as 0, unobserved minutes not scored, a bucket closed in two parts scored as one, 300 keys all scored (the previous cap was 256); the lifecycle (open after one quiet minute, closed after two, a closed episode listed 59 minutes on and not 61, a recurrence starting a new episode that must earn three minutes, a full table keeping its open episodes, the worst-case listing fitting with `more`, the kind and since filters, the change feed); A2 once per MAC across a restart and never for an old or randomised MAC; A3 at four weeks and not three, and not in normal hours; A5 for the randomised MAC only and not through a reassigned lease; A6's normal form and escaped evidence; A7 far above its p95 and not without history or margin; A8 for the client the answers were joined to, not under 20 queries or at exactly 30%; A9 on first use and not for a host with history across a restart; MAD refuting a return to an old level and confirming a real burst, once per hour per series; baselines and an open episode surviving a restart; A10 for a connection that never sends, not just after a reconnect, not while disconnected, not before the limit; the engine without a store; the newest changes when there are more than asked for; the hour pass learning the within-hour spread; A2 not new after sloth restarts (by the baseline, and by the store's rows), a flood of new MACs as one episode that keeps another rule's history, the slot policy, the reported set evicting its oldest with the new MAC still given its episode and the evicted one not reported again while remembered, re-reports (8) bounded by evictions (32), a burst's and a trickle's evidence counting exactly what was judged new and naming two MACs, a trickle of eight a minute folded into one episode once the hour's sixteen are reported, a scan past 4,096 identity slots; MAD refuted by the within-hour term alone; A3 in a half-hour zone; A7 below its minimum excess and across a restart; a baseline pair evicted and back in one hour, a refused batch written later, restored episode values checked (the episode's own score, and a metric below -1); a slothweb restart inside an hour fed once from both runs' minute rows (presence present in either part, Z zero-filled, the counter's 30 x 2 + 30 x 4), a counter not fed when the first run's rows could not be written, 20 + 20 minutes feeding nothing, a killed run losing only its minute in progress, a restart across the hour boundary feeding both hours, and the merge's cost (SQLite) |
| `test_oui.c` | the vendor table from registry CSVs the test writes into its own directory (MA-L, MA-M, MA-S, IAB; a BOM, CRLF, quoted fields with commas, quotes and a line break; CID skipped; a duplicate keeps the first): the most specific block first, 28- and 36-bit blocks inside the IEEE's MA-L, the local and group bits on a miss, the generated C (octal escapes, no name ending a literal or a comment), every malformed CSV failing with its row, names cleaned and cut on a code-point boundary, sloth's own `src/oui.c` read as text (every initialiser line, Apple found, an MA-S vendor not), the built-in table's source (the one `make web-test` says the build should have: `ieee` by default, `sloth` from an empty `WEB_OUI_DIR`) and order; the committed `web/data/` held to `SOURCE.md`'s hashes and built in a forked child under a time bound, its counts `SOURCE.md`'s rows, and a first file of 6,000 names then a second built under one too (the generator hung there until 2026-10-26); `update-oui` named in the Makefile only by comments, `.PHONY` and its own rule, and by no workflow or script under `.github/`; `update_oui.sh` run on a copy of `web/data/` with the same four files leaving `SOURCE.md` unchanged, and rewriting it once a CSV differs |
| `test_query.c` | the query language: the acceptance terms, every §9.1 prefix, free text, negation, quotes and MAC fragments as text, every refusal and its reason, the length, term and term-length bounds, the compiled statement holding no byte of the query (an injection attempt and LIKE metacharacters bound and escaped, the text the same whatever the values), the day range, missing tables reading as false, the worst case fitting, the anomaly kinds and `src:` bits held to the engine's and to `include/sloth.h`'s `DEV_SRC_*` |
| `test_ptr.c` | the passive PTR cache: reverse names per RFC 1035 §3.5 and RFC 3596 §2.5 (and what is not one), what a dns record must be to be recorded (an empty answer, sloth's today, counted), the bound and its eviction, a rename, changed rows out once and back on a failed write, a row read back checked; the identity tables' M4 readers |
| `test_slothdb.c` | sloth.db generated from `src/db_schema.c`: the open flags (read-only, no-follow, never write or create; a write refused); the file byte for byte and its directory listing after every read, for a rollback-journal file, a cleanly closed WAL file (immutable, no `-wal` or `-shm` made), a WAL file sloth holds open with unflushed frames (read, main file and WAL prefix unchanged, sloth still writing) and a `-wal` with no `-shm`; the refusals (missing, symlink, directory, newer, a slothweb store, no devices table, a bad version, not SQLite, not configured); a v5 file read by probing and a minimal v1 file; the allow-list against `tests/test_db.c`'s guardrail, credential words and the live schema; the authorizer denying every statement off the list; the budget interrupting a slow statement; the acceptance query returning exactly D1 and D6; every other term against the file; the drawer's, Lookup's and A2's reads |
| `test_devices.c` | the three routes through the route table: no sloth.db (`503`, the drawer and Lookup from the stream), `405` and `421` on the new paths; the acceptance query over HTTP (encoded both ways, `HEAD`); a row's members, the vendor's and name's sources, markup never markup; paging and every `400`; sloth.db missing; the drawer (path forms, lists, the detail, alerts, no credential, a MAC sloth.db lacks, bad MACs); the strip from the store's minute tier and the ring, the week from the baseline, an episode and the `anomaly:` and `has:` terms; Lookup (an MA-S MAC resolved, and not with sloth's own table; an IP's MAC, names and record; refusals); the health members; the worst case stopping with `more` |
| `test_chmix.c` | the WiFi view's channel mix and the SSID display form: the escaper on printable UTF-8, a backslash, octets that start no sequence, C0, DEL, C1, U+FFFD, a bidi override, a zero width space, Default_Ignorable code points (a Hangul filler, the grapheme joiner, variation selectors) and blank lookalikes (NBSP, an em space), private use, a noncharacter, a truncated and an overlong sequence, and its cut; the colour against `src/ip_color.c` over the octets (a case where hashing the display form would differ); a bucket's top five by frames then MAC and the rest, closed when due and not before; the tracking bound (a scan of one-frame MACs cannot push out a busy one, a heavy late one still gets in, and one first heard half way through an hour behind 32 others far ahead enters with exactly its frames); the channel bound and the ring's overwrite counted; `beacon` and `probe_client` through the decoder and the metric derivation (deltas, a first sight a baseline, 6 GHz from `channel_source`, the beacon's name, kept whole at the stream's longest form), an `assoc` line in sloth's shape adding nothing; `?mix=1` from memory (band order, a cell merged and cut to five, the tx table, an AP's escaped stream name, empty cells null, the refusals, the plain grid unchanged), the worst case stopping at a whole row with `more` and `folded`, the `chmix` health member, the ticker's SSID escaped, an alert's title and detail escaped on `/api/live` and the ticker; with SQLite, the minute tier from slothweb.db with the AP's octets from sloth.db (escaped, the TUI's colour) and a stream name only where sloth.db has none, and every sloth.db SSID (AP table and history, the drawer's last SSID, PNL SSIDs and associations, the Devices row, `/api/sessions/new`'s APs and probe clients, the SQL box's ssid and title columns) and `/api/history/alerts`' titles escaped, never U+FFFD |
| `test_prefs.c` | the kept settings, by the page's text (the suite runs no script; the behaviour was driven in headless Chromium): no `localStorage` outside the store's functions, each in a `try`, one `slothweb.v1.` namespace, the old keys moved; every table's widths and sort read through `DataTable()`, a width clamped to the column's floor, a sort only on a column that still sorts, written on each change and forgotten by `reset columns`; every `select`, `input` and `textarea` on the page kept or listed as not kept; the address over a kept view, scope and filters; `reset settings`. Each absence seen red under a named mutation |
| `test_tables.c` | sortable, resizable columns: the devices statement with a direction compiled from constant columns only (and unchanged without one), every sort word and the `dir` words accepted and nothing else; over a generated sloth.db the order `/api/devices`, `/api/wifi/aps` and `/api/flows` give for each new word in both directions (text by bytes, an address by number, an empty value last), `bad_dir` without the value echoed; the page's one `DataTable()` used by every table, its headers no longer `aria-hidden`, its storage in a `try`, the reset control, the direction on every server-paged fetch; the review's fixes pinned (a set flex column drawn fixed and seeded from its drawn width, the label floor, the separator's maximum and text, ARIA rows, cells and rowgroups, a server-paged prefix not sorted again, the SQL box's widths by name and typed columns, the list headers' padding) |
| `test_wifi.c` | the WiFi routes through the route table: the waterfall's band order and channel order, a gauge cell as the mean of its buckets and a counter's as their sum, null for empty, the defaults, 40 channels and `more`, every `400` (`tier_unavailable` past 24 h without a store), `503` without a time series or sloth.db; a channel only the store holds, at the minute and hour tiers; the deauth timeline by frames with its DEAUTH_FLOOD episodes in the range matched on the alert key that no body names, and without sloth.db; the AP table (AKM bits and downgrade flags by name, MFP as a word, the SSID history and count, KARMA, a markup SSID escaped, sorts, paging, refusals) and its worst-case row fitting `WEB_WIFI_AP_ROW_MAX`; the page's WiFi view, its ids and fetches. Both builds |
| `test_history.c` | the History routes over a generated sloth.db: the strip's cells and session markers, the defaults and refusals; the strip on 600,000 alert episodes and 60,000 devices without the first_seen indexes inside its budget (the time asserted under 250 ms, 4x that under ASan or TSan), its work (progress-handler ticks) under a quarter of a scan's by the last_seen bound, every plan's counts held to a `GROUP BY`'s; the snapshot's shape (867,748 episodes and 31,821 devices, all in the last 30 days, no index: the scan plan) inside the overview's 1500 ms through the route, and a direct count inside 4x that under the sanitizers; the cache served without an open, invalidated by an mtime, a minute, a write, and a write into the `-wal` that leaves the main file's stat unchanged; a timeout naming its read, rows and plan; who was here at the edges of the overlap, the presence strip over the range, paging; the alerts and flows in a range with no key, detail, cookie or MQTT username and no `mqtt_flows`; the sessions; "new since the previous session" for a first visit, a visit after a crash (its window closed at the next start), one whose previous never ended (since its start), and the latest, whose devices are the ones the wiki's own recipe names; the page's History view. Both builds |
| `test_sqlbox.c` | the SQL box: the parameter and text rules; `404` without `--web-allow-sql` and the page's box hidden; spec §12's M5 acceptance (above) over a real socket against the C API and the sqlite3 shell; every write, DDL, PRAGMA, ATTACH, DML-tail CTE and second statement refused with the file byte for byte; every withheld column refused, the guardrail's words on the list, the integer flags read; the row, byte, time and value limits; one at a time (`503` `busy`, free again once answered or once the client leaves), `HEAD` `405`, `/api/recipes`. Both builds |
| `test_flows.c` | the Flows routes over a generated sloth.db: every tab's row byte for byte, an SMB1 session marked, the columns each tab reads held to the allow-list and the withheld ones held off it, no cookie, banner, MQTT username, community count or preauth count in any body, every `400`, paging, sorting, the `ip` filter, a page that stops early with `more` and the next one, the chord pairs with their fold at three sizes, a table the file lacks; the page's Flows view. Both builds |
| `test_alertfmt.c` | the detail audit read from `src/alerts/`: every listed type's every `fire()` site found and its formats' string fields approved; the credential-bearing types off the list and refused by the checker |
| `test_vendorkb.c` | the vendor research table against `web/data/vendors/` and the registry: every `.md` an entry and every entry a file named for its name, every `[n]` resolving and every cited field carrying one, the name, each alias and each affiliate exact `Organization Name` strings of the committed CSVs (a dead entry is red), the lookup folding case, white space and punctuation, matching no prefix and flagging an affiliate, the drawer and Lookup carrying `"vendor_research"` for a researched vendor (without the entry's country, parent and founded for an affiliate) and `{found:false}` for one without and for an IP, the page drawing it through one function with no `href` and no markup sink, the generator refusing each defect the format names (fixtures run through the built `vendorkb`), and `data/vendors/COVERAGE.md` against `REFERENCE_HOST.txt`, the registry and the entries, its count line included |
| `test_alertkb.c` | the alert knowledge table against its sources: an entry per `.def` row in order with its technique, a trigger, sources and steps for each, plain text, and every remediation source a corpus document that cites the type |
| `test_alerts.c` | the Alerts page and an alert's page over a generated sloth.db and a fed stream: the collapse (sloth.db's rows and the stream's incidents, a key once), the order, every filter, paging, every `400`/`404`/`405`, the six sections, runs, the device by MAC and by address, no key, username, community or sloth `incident_id` in any body, every type's page within the buffer, the 20,000-row bound on 30,000 rows (500,000 with `SLOTHWEB_ALERTS_BENCH`), filters, History's figures and the drawer reaching past it, and the tiles against their views on the demo's data; the page's views and links |
| `test_mcp.c` | `slothweb-mcp` and the agent's write path ([Writes by an agent](#writes-by-an-agent), [docs/wiki/slothweb-mcp.md](../docs/wiki/slothweb-mcp.md)): the protocol as the research server's tests hold it, the JSON reader and the copier, the address, name and secret-file rules, every read tool against the real routes, every write tool end to end with its refusals, whose write it is, hostile SSIDs, hostnames, comments and notes held to their fields, the size caps, and the same calls over a loopback socket |
| `test_subnotes.c` | the plain notes ([Notes on devices and the rest](#notes-on-devices-and-the-rest)): each kind's id, a subject nothing holds refused, the retraction as a row, both caps and that only retracted notes fold, the text rules and the write path's guards, the batched marks, ids beginning `a`, `d` and `s`, `via` on links, the bundle's `notes` and `/api/glossary`, the stream held out of the table, the write over a socket, and `subnotes.js` with its list and write pinned whole |
| `test_notes.c` | anomaly triage and the links ([Anomaly triage and links](#anomaly-triage-and-links)): `test_frrs.c`'s alert triage tests again on an anomaly's id, the decision across a reopened store and a re-detected, a later and a forgotten episode, an id collision refused, alert and anomaly rows apart, links from both ends with their guards, a dangling end, the candidates' subject and both window edges, the candidate read on a 30,000-row alerts table, the bundle's `related` sections, the link's write over a socket, and `notes.js` with its functions pinned whole |
| `test_readme.c` | this file: every message the start-up path can print, scraped from `web/src/`, quoted in Troubleshooting; the Security section's points; every screenshot this file shows present under `docs/assets/slothweb/` and under the size bound |
| `test_tui_colors.c` | the data colours against the TUI itself ([Design](#design)): `src/tui.c`'s ANSI backend linked in and captured, every byte of an address, an SSID, a host name and an info string compared with the page's colour for it (its functions pinned as served, a C port of them over the served `SLOTH_PALETTE`, the served custom properties); the cross-panel bold and the page's `IP_SRC` bits held to `IP_SRC_*`, an alert counted by its `match_ip` alone; the alert-hot override against `tui_alert_hot_set()` (severity, bold from WARN, the TTL's edge, promotion, the full table) and its TTL and cap against `src/tui.c`; the phosphor, heat, alert-hot and monitor-row pairs; `MON_TYPES` against the record types `src/jsonl.c` emits from the monitor radio |
| `test_glyph.c` | the glyph layer's geometry ([the glyph layer](#the-glyph-layer)): a C port of `web/ui/glyph.js` with the JS pinned verbatim out of the served page, so a change on either side fails. The S-meter (2026-11-11): the band table against the path-loss formula, every S boundary on the edge and a hundredth either side, the reading past S9 stepped in tens, both clamps and their count, one reading on three bands, the unknown band's row and label, no reading (the dash and no segment), one reading, the peak-hold ticks and their band, the geometry at 72 by 14, greyscale, the dB-Hz and dBFS faces, the legend's labels and words, the report's character cells, every sm function and every call site pinned whole, and what it replaced gone from the page. For G1, G5 and G6: empty, warming, one point, four points as dots (R6), a gap (R5), in band, out of band (and in again once the band is widened), G1's line graded as `draw_sparkline_at()` grades it (ruling 1), min and max dots only without a band (R7), a scale that grows and never shrinks (R11), the window rule and its words (R4), the caption grammar and the three states in it (R9), the presence cells from the server's hex, the ruler's midnight and now ticks in a shifted zone (F10), the first-seen mark (F15), an anomaly episode's underline clipped to the strip, the bullet's ranges, threshold tick and severity, the count bar's shared scale, and each glyph's list read with every token flattened to one grey (R10); each glyph's TUI form named in the README (R12). Nineteen mutations, each naming the test it reddened. V2: G2's states (the dash, one sample as its dot alone, dots under five, a gap), its fixed −95 to −20 dBm scale and the −67 dBm rule, a reading off the scale clamped and counted, the whisker only when there is one and in order, the four kinds in one grey (R10); G2's words bold only by sloth's `approaching` and naming sloth's band and trend glyph, never a slope of their own; the new mark and G5's first-seen cell (F15); every placement of G2 and G6 and the card's rounded bar gone (R8). The sun (ruling 2026-11-11): a C port of `web/ui/sun.js`, pinned whole as served; rise, set, transit and both civil twilights at five places within 3 min of the U.S. Naval Observatory (London and Sydney at the June solstice, New York in November, the equator at the equinox, Fiji a tenth of a degree off the antimeridian); noon elevations from latitude and declination; polar night and midnight sun at Longyearbyen, twilight all night at Reykjavik, no day at Tromso; a strip present all day at London giving the four tokens in order with counts within a cell of the almanac; no position, a bad one or no window giving the plain strip mark for mark; cells over an hour one ink; the ruler's band under its ticks, its heights in one grey (R10); every G5 caller, the tokens, and the page naming neither geolocation nor a zone. 31 mutations (14 in the port, 15 in the JS and CSS, 2 the build's colour check), each seen red. Sensor time (the second ruling): the ruler's ticks at a UTC-7 sensor's midnights seen from UTC+1, the fallback to the viewer's clock and its words, the words' sunrise and sunset in sensor time against the almanac at New York, the zone's name for whole and part-hour offsets, the page reading the viewer's offset in one place only; 12 more mutations seen red, among them the ticks put back on the viewer's offset. G4 by the ruling of 2026-11-11: an all-warming grid is 168 plain tiles and the outline last (red with the `st.fed` loop guard put back), no cells is the dash alone, a cell with n = 1 or 2 is a `--tui-dim` bar on its tile and never a heat token (red with the ramp given to it), the bar never the tile's height, a never-sampled cell no bar, the share scale against the largest-mean scale, fed cells as they were, the caption's scales and counts through a port of `heatCaption()` and `fmt()`, and `g4()`, `g4Stats()`, `heatmap()`, `heatCaption()` and both callers pinned whole. 18 mutations (12 in the port, 3 in `glyph.js`, 3 in `app.js`), each seen red |
| `test_rf.c` | the signal meter's data (`web_rf.h`): `radio`, the band the latest record was heard on, for every channel edge, a 6 GHz channel only by its `channel_source`, `null` with no channel; the hour's window; `web_rollup_trail()` merging closed and open fine buckets per cell, another key's and an earlier bucket left out; an AP's series first, a station's otherwise, the other when the first is empty, and no trail under Local or without a rollup; the member with the beacon's 60 s range or the last cell's samples as the whisker (the beacon's only when it is in the last value's minute) and sloth's band and trend from the FRRS ledger's latest beacon or probe_client; a record's word that is not sloth's, and a range out of order, refused; `WEB_RF_JSON_MAX` holding the longest member |
| `test_parity.c` | the AKM names (src/rsn_ie.c, linked into the test alone), the downgrade bits (`WPA_DG_*`) and DEAUTH_FLOOD's type held to sloth's own; the BLE view's vocabularies (the PDU, band, trend, glyph and P_tx-source words, the finding kinds, the alert names, the TUI's address-type letters and its legend line) held to `src/` as text |
| `test_ble.c` | the BLE view ([BLE](#ble)) from hand-built `ble_device`, `ble_alert`, `alert.resolve` and `sensor_health` lines in the emitter's exact shape: two rows for one address heard by two sensors, a heartbeat updating in place (the sticky masks OR-ed, the earlier first_seen kept, the rate from two points), the hostile strings (a control byte escaped and flagged, an over-long name cut back to a code-point boundary, a category that is not sloth's slug dropped and counted, an unknown iface `other`, a bad record kept nowhere), the record's absent values null and an anonymous all-zero address a row, the estimate's four fields with the TUI's cell and description, the LRU at 1025 rows evicting the oldest, the findings (standing, the resolve of the key, the time-out, the day's listing, the key never rendered, a `hid_oui` finding under its address), the `sensor_health` block and its rotation bands; the two metrics only while a Bluetooth source is configured; every route through the table (the sort words and both directions, each refusal a word never echoing the value, the search, paging, HEAD, Monitor and Hybrid serving, Local `out_of_scope` with the query still checked, `/api/live`'s `ble` member and `/api/health`'s counters, the M0 shape without the tables, the BLE incident typed and Monitor's on the Alerts page); the page's lines pinned as served; with SQLite the store round trip through the store thread's flush, a changed row upserted once, the seed on reopen with the name's display form and the estimate, every field of a seeded finding (a flood's fresh count, rate, window and citation, a `hid_oui` finding's address and the drawer's match on it), a resolve on a seeded finding updating its stored row in place, a seeded row's presence strip shifting on with fresh traffic, retention at compaction, a failed write (a trigger aborting it mid-transaction) rolled back whole and its batch written by the next flush, the row caps (the oldest gone, a flagged row kept past newer unflagged ones, counted) and a non-canonical stored address not seeded; every sort word in both directions with an empty key last (`mfr`'s three tiers fixed in either direction); a name cut back to a code-point boundary; `ble.devices` with an Ubertooth alone and `ble.adv_rate` only with the host stream; `/api/live`'s `ble` member with every string at its cut and escaped six-fold; without a store the tables still ingest and serve. Each absence seen red under a named mutation |
| `test_lure.c` | the KARMA and key-harvest card ([Lures and key harvesting](#lures-and-key-harvesting)): sloth's three records in the emitter's exact shape through `/api/lures` (every member, the SSID through the writer), a newer record replacing its row and `gone` removing it, refusals of malformed and out-of-range members, the stale bound and a full table reclaiming a stale slot, the worst-case answer inside the buffer, `reported` from `sensor_health`'s `jsonl_version`, the Local answer; and the page's module, containers, hooks and words pinned out of the served page, with no markup sink. Each absence assertion seen red under a named mutation |
| `test_sysstat.c` | the Sensor health view's host status ([Sensor health](#sensor-health)): sloth's four records in the emitter's exact shape through `/api/sys` (a figure the host lacks `null`, a not-configured source listed, a batch replacing the last, the age on the monotonic clock, the same answer under every scope with one `scope` member), refusals and ranges on hostile lines, the worst-case answer inside the buffer, the eight series through `web_metrics_record()` (absent or out of range not sampled, an outage in a bucket's minimum), the `sys` key kind; and the page's words as a C port of `syshealth.js`'s `trendOf()` and `stripOf()` with the JS pinned out of the served page. Each absence assertion seen red under a named mutation |
| `test_bledev.c` | the BLE Devices waterfall ([BLE](#ble)): each class rule on hand-built fields (SIG Appearance values, Continuity types, the registry's UUIDs) and each left-out shape landing in Unknown, the first-match order and the table's match numbers, the slugs (never a channel key, the only `bleclass` keys), a class from a record line; the proximity edges against `src/rf_distance.h` and `.c` read in the test; the page's class table and grade pinned against the C ones, the panels inside `v-ble`, no `innerHTML` in the module; the mix engine taking kinds 3 and 4 (an advertiser, anonymous advertising) apart and refusing 5, a sized ring; the class mix fed from `ble_device` lines (a baseline, deltas, a reconnect, a row born while listening, a sampled row, one address on two sensors kept apart); the advertisers gauge once a pass, an address on two sensors once; the one anonymous row sloth can send (the host stream's, its first mfr pair kept, a keyboard's HID bit OR-ed in) credited to Unknown alone as one entry and one advertiser while its fields read Phones then Input, named rows and an Ubertooth's uncredited samples beside it, each class's advertisers, drawn transmitters, reports and drawn frames agreeing, no series under the zero address; the anonymous entry through both routes (one `anonymous` tx entry in `b:unk`, its kind word the one `bledev.js` tests, no proximity row, never nearest, `anonymous_heard`, the strip counting it once) and under a read cut (no slot taken: 256 read); five thousand fresh BLE addresses leaving a Wi-Fi row's high-water mark (and its true delta) in place; both routes from memory (display order, the tx entries named from the tables or by address alone, the strip's facts, every refusal), the proximity rows' order, means and window, a tracker heard before three hundred newer addresses still read and first, each row graded with its announced power (extended header, TX Power Level, else 0 dBm) and nearest by the margin; `now`'s sensor facts; both routes 503 `no_time_series` in either scope and the mix 503 `no_ble_mix`; Local `out_of_scope` with the query checked and a long query a 400; with SQLite the WiFi and BLE mixes in one `chmix` at the same tier and t, each namespace reading only its own, each route drawing only its own, a kind-4 anonymous row read back and drawn, and the file still v7. Each absence seen red under a named mutation |
| `test_radar.c` | the Radar tab ([Radar](#radar)): `/api/radar` from seeded `ble_device`, `beacon` and `probe_client` lines (every row in total, the banded rows nearest-RSSI first, a reading without an estimate in `none` and nowhere else, a word that is not sloth's no band, both halves `null` without their tables), the eight-per-band cap on twelve scrambled rows, rows without a reading sorting last, Monitor and Hybrid against Local's `out_of_scope` with the query checked, `400` for any parameter, the body under 8 KB with every BLE row held and under 10 KB with both censuses full, the name cut on a code-point boundary; the page: the tab between APRS and TACDB, the hook and init lines, every container id looked up, no `scoped-out` toggle and the comment saying why, no control in the view, the projection functions whole (`rn`, `geo`, `place`, `project`, `ringDist`) with no divide by depth, the painters whole, the ring dash and alpha, no gradient or shadow, the kept camera's three prefs validated and cleared, no kept selection, one `requestAnimationFrame`, the Local and estimate sentences verbatim, the centre rule, every fetch through the lent scoped `getJSON`, the three `select()` exports whole. Each absence seen red under a named mutation |
| `test_allkeys.c` | the Activity graph's `keys: all`: `/api/series/all` (every parameter and reason word, the cell arithmetic, the answer's shape for a gauge, a counter, presence and a global metric, an empty cell absent, keys in byte order, 128 to an answer and `after` paging with no key twice, `total` on the first answer only, a full answer stopping whole, the scopes by metric and by key, the route's `400` and `503`), every key walked (300 where `/api/keys` lists 256, the oldest among them; the rollup's and the store's, a store key with no bucket in the window left out), an answer stopping at its time and still answering one key, the fullest answer and a walk of 8,192 keys from memory and from the store timed against the 250 ms request budget and printed; and `web/ui/allkeys.js`: its pure half ported to C line for line and pinned verbatim (the legend's order, the `N of M keys` and `loading N of M keys` words, the tier per window, the cells a key is read in, the legend's filter, the multi-key mark list: one token a key, the shared scale, gaps, dots under five points, the focus row last and the rest `--faint` (never `--rule`), the rows past 256 folded into one range a cell, the band only for a picked key, the top five end labels pushed apart, greyscale; the frame; the presence strips), the key colours pinned against `ip_color_index()`, and the other half by whole functions, with no `innerHTML`, no `setAttribute` and one `--signal`. Each absence seen red under a named mutation |
| `test_ssidview.c` | an SSID's detail ([An SSID's detail](#an-ssids-detail)): the `ssid=` parameter both ways on the empty name, one that is not UTF-8, a zero-width space, 32 octets and two that look like SQL wildcards, and its refusals (one character, leftover bits, a NUL, padding, `+` and `/`, 33 octets); `/api/wifi/ssid` over a generated sloth.db: the BSSIDs now and once, KARMA, the stream's twin link, the associations by name and by BSSID, the askers, the strip, the alerts by BSSID and by the SSID's own key component; `Home%` and `Home_et` each their own; the hidden SSID; a name nothing beacons; Monitor's answer and Local's `out_of_scope`; 600,000 alerts with 40 BSSIDs, 5,000 associations and 50,000 askers inside the request's budget, the alert walk's reach printed; and the page's half, `octets()`, `param()`, `link()`, `more()`, `ssidSpan()` and `ssidHidden()` whole and each hook where the WiFi view writes a name. Each absence assertion seen red under the mutation its comment names |
| `test_probes.c` | the Probes tab ([Probes](#probes)): `/api/probes/clients` over the acceptance scenario with a wildcard-only station, an old one and a correlation (frames and directed, the names, the device row, the association, the sibling, the strip, each order, a page as N of M, the window); `/api/probes/ssids` (stations, randomised, the APs beaconing it); the similarity on six stations worked by hand (0.319, 0.216, nothing at the minimum, nobody by the common name) and the groups at a minimum of 2 and of 1; each refusal; Local's `out_of_scope`; 50,000 stations, 200,000 `pnl_ssids` rows and 600,000 alerts with each route inside the request's budget and the groups saying they are capped; and the page's half, `tied()`, `formula()`, `select()` and `show()` whole, the tab's place in the bar, the views, the scope switch and the kept controls, the wording. Each absence assertion seen red under the mutation its comment names |
| `test_btsig.c` | the Bluetooth SIG table this binary was built with (`WEB_BTSIG_EXPECT`): sorted, the names printable and within the cut, the lookups answering the SIG's names for Apple, Microsoft, Google, Ericsson, Battery, Human Interface Device, the keyboard appearance and the generic forms, a miss and the bounds null; the committed CSVs byte for byte the ones `web/data/btsig/SOURCE.md` hashes, with its row counts; `update_btsig.sh` run by the `update-btsig` target alone and named by no workflow; the generator run on a name holding every trigraph's opening, a quote and a backslash, its literal decoded back byte-identical and no `??` left in its output |
| `test_replay.c` | spec §12's M3 acceptance: a six-week JSONL stream generated in the test (never a fixture) through the framer, decoder, live state, metric derivation, identity tables, rollup, `web_tsdb_step()` and the engine as `main.c` wires them, on pinned clocks: four weeks of routine (noisy gauges, Poisson counts, and an input for every rule: names that agree, a randomised MAC with its own name, a month-old probe client, a steady ssh host), then a quiet 7 d week in which nothing at all fires, slothweb and sloth restarting in the middle of it in an SQLite build, then a 7 d week in which A1 fires for a burst of connections and A3 for a daytime device that appears only at night, while a device that is only ever present at night never fires; and the hour that just closed reaching the baseline at flush phases 0, 3 and 7 (the previous slice fed it only at phase 0); A9 for a new host whose first row the rollup released late, at sloth's real cadence (SQLite); five weeks of a 13:30-14:30 routine in IST firing nothing. Both builds |
| `test_evidence.c` | an alert's proof, every pcap written at run time from byte arrays built per their clause (no capture is committed): the file header in both byte orders and both resolutions, pcapng and junk refused by name, the record walk (orig_len raised to incl_len, a caplen past the snaplen, a file cut inside a record); the decoders on Ethernet/IPv4/TCP with a ClientHello cut at 64 bytes (no SNI claimed), a DNS query whole and cut, a compression pointer to itself, SLL2/ICMP, SLL/ARP, radiotap deauthentication (reason 7, Table 9-26 roles, channel and signal), a beacon (SSID, DS channel, RSN, a 33-octet SSID called invalid), an authentication status 0; the hex dump; a page of 24 frames, the next page, the worst case stopping with `more` inside its buffer, a cut file, a record cut below a 0xffffffff snaplen said as `40 of 270 bytes captured` and never as the snaplen; both alert-pcap name grammars and what they refuse (a handshake pcap's name, `eapol.22000`, a path, a near miss of each); the manifest line in `src/evidence_manifest.c`'s shape and every sink and shape it refuses; a directory: newest first, a handshake line and an unterminated tail not indexed, an 18-digit `written_at_epoch` sorted first and returned as written (no arithmetic on a stamp; the sanitized build would stop on an overflow) and equal stamps in read order, the three joins and the fallback only when they find nothing, hash verified, mismatched by a byte and by a length, no entry; a symlink, a FIFO, a name off the gate and a 16 MiB + 1 file refused; a missing directory; the routes: `captures` with no `incident_id`, session or path in the answer, `hash verified`, `no manifest entry`, `HASH MISMATCH` after a byte changed, `404` past the list, `400` for a file name or a bad `n`, `405` on `HEAD`, the download's headers and bytes, its `X-Sloth-SHA256` of the bytes served (`verified`, then `mismatch` after a byte changed, `no_manifest_entry`), `415` for pcapng, `why_no_capture` for an L2-only rule and with no `--pcap-dir`; an evidence pcap listed `withheld` and refused `403` by both routes with no frame or byte, then decoded and served under `serve_evidence`; a symlink and a FIFO with manifest lines listed `unreadable: not a regular file` and refused `403`; a file with sloth's line and a forged later-stamped line `hash verified` (by sloth's line) with `conflicting manifest lines (2)`, and a file with only a forged line `HASH MISMATCH`; the assessment generator run on documents it writes (header lines, front matter, sections, bibliography, Related pages left out, an indented continuation kept with its entry and other prose kept apart as the note, MY_NETWORK_RECON.md's note never in an entry) and its two build stops; the page's hooks (the drawer's list by its `data-ev` mark, the frame index through `DataTable`, a withheld or unreadable capture never opened), the download's one form and the section's place, last |

A test cannot originate from a non-loopback address, so the refused-peer
socket tests narrow the list instead (only `127.0.0.2`, or only IPv4)
and connect from `127.0.0.1` and `::1`; `test_acl.c` covers the
non-loopback addresses against the same function the accept path calls.
Every absence assertion was seen to fail under a mutant of the guard it
covers before it was trusted. One rule has none: the store's owner rule
(a file owned by another uid is refused) cannot be exercised without
privilege a test must not ask for, and removing it leaves the suite
green; it is held by code reading. M5 adds two guards that are depth
behind others and cannot be isolated either: the SQL box's
`sqlite3_stmt_readonly()` check (every write is refused first by the
precheck or the authorizer, and the opener is read-only) and the M4
authorizer's own withheld-column test (no withheld column is on the
allow-list to begin with); removing either leaves the suite green. The
absences two guards hold together (a column neither selected nor on the
allow-list; the file left byte for byte) were seen red with both
changed at once, or with a write added to the test; the tests' comments
say which. Two guards are reached only through
test seams in `web_store.c` (`web_store_test_no_defensive`,
`web_store_test_between_opens`, NULL and 0 outside the tests): the
`DEFENSIVE` read-back, by a seam that reads it back as off, and the
writer's second identify, by a seam that swaps the file between the two
opens.

`make cppcheck` analyses `web/` with the rest of the tree. `make fuzz`
runs `tests/fuzz/fuzz_web_query.c` (M4's query language) and
`tests/fuzz/fuzz_web_sqlbox.c` (the SQL box's guard over sloth's schema
in memory: nothing written, no withheld column read by an accepted
statement, an accepted statement one SELECT or WITH).

## Layout

```
web/
  README.md        this file
  src/
    main.c         argv, signals, the run
    web_config.c   command line, the remote-exposure policy, announcements
    web_acl.c      the allowed-peer list
    web_http.c     request parsing and the fixed error responses
    web_routes.c   the route table, health and live JSON, event formats
    web_server.c   listener, poll loop, timeouts, event streams, counters
    web_ingest.c   --socket, the data-socket thread, back-off, line framing
    web_jsonl.c    the strict JSONL record decoder
    web_live.c     the live state: counts, devices, alerts, sensor, ring
    web_metrics.c  records to samples: keys, deltas, rows per pass (M2)
    web_rollup.c   the metric table, the three tiers, key bounds, the ring
    web_rf.c       G2's "rf" member: a row's rf.rssi.* trail and sloth's
                   distance words from the FRRS ledger (#171 V2)
    web_store.c    slothweb.db: open rules, identification, migration, I/O
    web_tsdb.c     the store thread: close, write, compact
    web_series.c   /api/series, /api/keys, /api/metrics, /api/baseline
    web_allkeys.c  /api/series/all: every key of a metric in at most cols
                   cells, a page of keys to an answer (Activity's keys: all)
    web_baseline.c 168 local hour-of-week cells per (metric, key) (M3)
    web_ident.c    names, MAC/IP bindings, first_seen, the DNS join (M3)
    web_anomaly.c  rows in, the rules, episodes, persistence (M3)
    web_slothdb.c  sloth.db read-only: open, identify, allow-list, reads (M4)
    web_query.c    the device query language, compiled to one statement (M4)
    web_oui.c      the vendor lookup over the generated table (M4)
    web_vendorkb.c the vendor research lookup over the generated table, spelling folded
    web_vendorkb.h its symbols and the key normaliser the generator and tests share
    web_ptr.c      the passive PTR cache (M4)
    web_devices.c  /api/devices, /api/device/{mac}, /api/lookup (M4),
                   /api/history/devices (M5)
    web_wifi.c     /api/wifi/channels, /api/wifi/deauth, /api/wifi/aps, /api/wifi/local (M5),
                   /api/wifi/chain (#171 V4); the grid and the mix answer the BLE
                   waterfall shares
    web_chain.c    G8's links: the stream's twin_episode pairs, in memory (#171 V4)
    web_bledev.c   the BLE device classes, the proximity grade, /api/ble/classes,
                   /api/ble/proximity (the BLE Devices waterfall)
    web_radar.c    /api/radar: the Wi-Fi and BLE distance-band census the Radar
                   tab's rings draw (the BLE tables, the FRRS ledger)
    web_ssidview.c /api/wifi/ssid: one SSID's detail, and the ssid= parameter
    web_probeq.h   the few lines each of its sloth.db reads repeats (the
                   Probes view's reads too)
    web_probes.c   /api/probes/*: the stations heard probing, the networks
                   asked for, the similarity and the groups
    web_history.c  /api/history/*, /api/sessions, /api/sessions/new (M5)
    web_flows.c    /api/flows, /api/flows/graph and its matrix form (M6, #171 V4)
    web_alerts.c   /api/alerts, /api/alert: the Alerts page, an alert's page
    web_bundle.c   /api/bundle: a detail view's answers spliced into one document
    web_alertdb.c  sloth.db's alerts: groups by key, a key's incidents, its device
    web_relate.c   an anomaly's triage subject; /api/frrs/related, /api/frrs/relate
    web_notes.c    plain notes on devices and the rest: /api/frrs/notes, /notes/marks, /note
    web_agent.c    --web-agent-secret: the run's secret, and whose write a POST is
    web_alertfmt.c the types whose alert detail is shown, audited
    web_loc.c      sloth's location stamp: range-checked, from the stream or sloth.db
    web_positions.c /api/positions: JSON, GeoJSON, GPX
    web_alertkb.h  the generated alert knowledge table's symbols
    web_alertasm.c the assessments by type, over the generated table
    web_evidence.c /api/alert's proof members, /api/pcap/frames, /api/pcap
    web_pcap.c     the libpcap-free pcap reader and the frame decoders
    web_pcapdir.c  --pcap-dir: the name gate, the manifest index, the hash check
    web_dot11_names.c  IEEE 802.11-2020 subtype, reason and status names
    web_sh_stub.c  the one sensor-health call dot11_ie.c makes, answered
    web_secret.c   the withheld columns both sloth.db readers refuse (M5)
    web_sqlguard.c the SQL box's text rules, authorizer, limits, runner (M5)
    web_sqlbox.c   the SQL box's thread, its one answer, busy (M5)
    web_recipes.h  the generated recipes' symbols (M5)
    web_json.c     the JSON writer every outgoing string goes through
    web_assets.h   the generated page's symbols
  ui/              the page sources (index.html, theme.css, page.css, app.js,
                   glyph.js, sun.js: the sun's phase for the presence strip,
                   facts.js, rf.js and air.js: the glyphs' placements,
                   allkeys.js and allkeys.css: every key on the Activity graph,
                   evidence.js, bundle.js the copy-JSON
                   control, notes.js and notes.css: anomaly triage and
                   the links, subnotes.js and subnotes.css: plain notes on
                   devices and the rest, location.js and location.css: where
                   the sensor was, gnss.js and gnss.css: the GPS Sat
                   tab, bledev.js and bledev.css: the BLE Devices
                   waterfall, radar.js and radar.css: the Radar tab's
                   dome, ssid.js and ssid.css: an SSID's detail,
                   probes.js and probes.css: the Probes tab, and
                   syshealth.js and syshealth.css: the Sensor
                   health view's host status)
  tools/
    embed.c        ui/ -> build/web/web_assets.c (build time only)
    oui_gen.c      web/data/*.csv -> build/web/web_oui_table.c (build time only)
    oui_csv.c      the registry CSV reader the generator and the tests share
    update_oui.sh  make update-oui: refresh web/data/ by hand (never in a build or CI)
    recipes.c      docs/wiki/sqlite-schema.md -> build/web/web_recipes.c (build time only)
    alertkb.c      the .def, the rule table, the wiki, research/ and
                   docs/wiki/alert-remediation.md -> build/web/web_alertkb.c (build time only)
    vendorkb.c     web/data/vendors/*.md -> build/web/web_vendorkb_table.c (build time only);
                   refuses a file with a dangling [n] or a missing field, naming it
    alertasm.c     docs/wiki/alert-assessments/*.md -> build/web/web_alertasm_table.c
                   (build time only)
    tap_check.py   the drawer's alert rows tapped at 360 px under touch emulation
                   (Chromium's DevTools protocol; by hand, loopback only)
    palette.c      src/tui_palette.c + src/tui.c -> build/web/palette.css, palette.js;
                   make web-contrast (build time only)
    sha256.c       SHA-256 and base64 for embed.c and the tests
    demo.c         build/web/slothweb-demo: the synthetic sloth.db and stream (M6);
                   linked into slothweb_test too (-DSLOTHWEB_DEMO_LIB)
    quickstart_check.sh  the five-minute check, make web-quickstart-check (M6)
  mcp/             slothweb-mcp (make web-mcp): an MCP server for an agent on this
                   machine, a client of the routes above; main.c the pipe, mcp.c the
                   tools, mcp_json.c the reader and the copier, mcp_http.c the request
  data/            the IEEE registry CSVs, committed (SOURCE.md: origin, hashes, refresh);
                   vendors/ the vendor research, one .md per OUI holder (docs/wiki/vendor-research.md),
                   COVERAGE.md and REFERENCE_HOST.txt: which reference-host vendors have one
  tests/           slothweb_test (make web-test); sdb_gen.c builds the tests'
                   sloth.db from src/db_schema.c; src/rsn_ie.c is linked for
                   test_parity.c, src/tui.c, tui_palette.c, ip_color.c,
                   netstr.c and view_labels.c for test_tui_colors.c
```

Wiki page: [`docs/wiki/slothweb.md`](../docs/wiki/slothweb.md).
