# Interfaces  `[1]`

Per-interface stats: RX/TX rates, errors/drops, MTU, link speed,
NIC vendor (via OUI lookup), link-layer mode (ETH / WIFI / MON),
and rolling history sparklines.

## Source

`/sys/class/net/<iface>/statistics/*` for the byte/packet/error counters,
`/sys/class/net/<iface>/{mtu,speed}` for capacity,
`/sys/class/net/<iface>/address` for the MAC address (fed to
`src/oui.c` for vendor), and `/sys/class/net/<iface>/type` for the
ARPHRD_* value that classifies mode (`803`/`804` = monitor mode).
BSD/macOS reads MAC via `AF_LINK` `sockaddr_dl` and probes monitor
mode via `SIOCGIFMEDIA` (`IFM_IEEE80211_MONITOR` mediaopt). The
Linux and BSD paths produce identical `IFACE_MODE_*` classifications
so `NO_MONITOR_MODE` fires the same way on both.

Rates are computed by diffing poll-to-poll. The 30-sample (= 30
seconds at 1 Hz) history feeds the sparkline graphs.

## View

```
 ── Interfaces ─────────────────────────────────────────────────
 iface      Mode Vendor        rx/s        tx/s      rx history        rx total   tx total
 eth0       ETH  Intel Corp    1.0 MB/s    200 KB/s  ▂▃▄▅▆▇█▇▆▅▃▂▂▁_   5.0 GB     1.0 GB
 wlan0      WIFI Apple         500 KB/s    50 KB/s   __▁_▁▁▂▂▁__▁_▁    200 MB     50 MB    ssid: HomeNet
 wlan0mon   MON  Alfa Networks 2.0 MB/s    0 B/s     _▁▂▃▄▅▆▇█▆▄▂▁_    600 MB     0 B     [monitor]
 lo         ETH  -             0 B/s       0 B/s     ________________  0 B        0 B
                 ^                                   ^
                 OUI-derived NIC vendor              heat-graded: cool→peak red
```

Monitor-mode rows render bright and carry a trailing `[monitor]`
marker — the operator can see at a glance whether at least one
radio is available for WiFi SIGINT. A managed Wi-Fi station carries a
trailing `ssid: <network>` while associated, so the joined network is
visible without opening the WiFi view.

With a monitor radio present, the first poll hides the wired /
loopback / virtual noise (issue #25) but keeps **every Wi-Fi netdev**
visible — the monitor radio and the managed station sit side by side
by default. `t` un-hides anything.

Each sparkline stretches across the available row width (`HIST_LEN`
samples mapped to as many cells as fit). Heat colours scale per
interface: a quiet wlan still shows usable shape next to a saturated
eth.

## Keybindings

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate |
| `Enter` | Open detail panel (sparkline graph, errors, drops) |
| `m`     | Mark this iface as the probe-capture iface |
| `t`     | Toggle iface **visibility** (display-only; data still flows) |
| `y`     | Toggle iface **data-stream selection** (drops packets pre-decode) |

## What's normal

- One or two interfaces with real traffic; loopback usually idle.
- Errors / drops counters at 0 or growing very slowly.

## What's suspicious

- **Sudden saturation** of an iface that's normally quiet — could be
  legitimate (backup running), or exfiltration / DDoS amplifier.
- **High drop count** — link issues OR pcap can't keep up (overflow
  in the capture ring).
- **Promiscuous mode unexpectedly set** on an iface — something
  external put your card into capture mode. Check with `ip link
  show`. Common after misconfigured Docker bridges; less common,
  meaningful indicator of a sniffer running locally.
- **MTU mismatch** between paired interfaces in the same VLAN —
  performance hit, also a misconfig that's easy to miss.
- **No monitor-mode radio at startup** — the `NO_MONITOR_MODE` alert
  fires once at first-poll if no iface reports ARPHRD_IEEE80211_RADIOTAP
  (Linux type 803). Doesn't mean an attack; means WiFi SIGINT views
  (Probe, Beacons, EAPOL, Deauth) will stay empty this session. See
  [`alerts.md`](alerts.md).

## Data-stream selection (`y`) — issue #17

Independent of the hide election, `y` toggles whether the interface's
packets contribute to the capture pipeline. A deselected iface's
frames are dropped in the pcap callback *before* any decode / log /
alert runs — Connections, Packets, DNS, TLS, HTTP, QUIC, ICMP, NTP,
the JSONL log, and the alert engine all lose that iface's traffic
until it's toggled back.

Rows carry a `d` prefix and a trailing `(deselected)` marker so the
election is visible at a glance.

**How the filter works.** Ingress interface attribution requires
`DLT_LINUX_SLL2` (cooked capture v2) — its header carries an
`sll2_if_index` at offset 4. sloth opens `any` with `pcap_create` +
`pcap_activate`, then calls `pcap_set_datalink(handle,
DLT_LINUX_SLL2)`. libpcap ≥ 1.10 accepts this; ≥ 1.11 defaults to it
for `any`.

`pcap_activate` reports failure with a *negative* return; positive
returns are warnings on an otherwise usable handle. The `any` device
has no promiscuous mode, so it routinely activates with
`PCAP_WARNING_PROMISC_NOTSUP`. Only negative returns close the handle
— treating warnings as fatal silently downgraded every capture to
SLL v1 and disabled the filters below (issue #46).

If the datalink call fails (older libpcap, kernel refuses), sloth
falls back to `DLT_LINUX_SLL` v1 or `DLT_EN10MB` — capture still
works, but the header doesn't identify an ingress iface, so the
data-stream toggle becomes a UI-only marker with no filter effect.
The iface view still shows the marker for consistency across
platforms. A launch-time `--iface` / `--monitor-only` scope on such a
datalink is refused at startup instead (#85, below).

**Scope.** Applies to the IP/TCP capture path only. The 802.11
monitor capture is a separate pcap handle bound to a specific
monitor interface — WiFi SIGINT views are already governed by the
`m` (monitor-iface) selection.

## Channel scan bar retune confirmation — issue #91

With `--hop`, the monitor radio's row carries a scan bar — `ch: 1 6
[11] 36 44` — showing the hop list and the channel currently dwelt on.
Advancing that bracket used to mean only "sloth asked the radio to
retune here", not "the radio is actually here": `chanhop_drive()` threw
away `set_channel()`'s return code, so a retune that failed (no
`CAP_NET_ADMIN`, `EBUSY`, an unsupported frequency) left the UI
indistinguishable from a healthy, quiet channel.

The bracket now distinguishes the two: `[11]` means the platform
acknowledged the retune to channel 11; `[11?]` means sloth requested 11
but the last `set_channel()` call failed, so the radio may still be
parked on whatever channel was last confirmed. `chan_requested`,
`chan_confirmed`, and a lifetime `chan_retune_failures` count live on
`sloth_state_t` for anything else that wants to consume the same
signal (see `src/wifi_chanhop.c :: chanhop_record_retune()` for the
pure bookkeeping, kept hardware-free and unit-tested the same way as
the rest of the scheduler).

## Sensor health strip — issue #91 slices 2-3

Under the interface rows, above the key hints, sits one line describing
the *capture behind* every row rather than any single interface:

```
  health: cap up  mon down (iface_gone)  mon drop 12  retune-fail 2  evict 5
```

A fully healthy sensor renders exactly:

```
  health: cap up  mon up
```

**Everything after the two liveness words is a fault**, and appears only
when its counter is non-zero. That is deliberate: a strip that prints
`drop 0  ifdrop 0  evict 0` every second trains the operator to stop
reading it, and then it is worse than nothing. The line is structural
rather than colour-coded, so it reads the same on an inverted row and in
the ANSI build — the same choice the scan bar's `?` marker made.

### The two streams

`cap` is the IP data-stream handle (the `any` device); `mon` is the
802.11 monitor radio. Each reads one of three ways:

| Word | Meaning |
|------|---------|
| `off` | no pcap handle — capture was never opened, or the build has no libpcap |
| `up` | the handle exists and its worker thread is dispatching |
| `down (<reason>)` | the handle exists but the worker has ended |

`off` and `down` are different words on purpose. Capture that was never
opened and capture that *died* need different operator responses, and
issue #91 exists because they looked identical from outside.

### Why "down" was previously invisible

Both workers loop on `pcap_dispatch()` and `break` on a negative return.
Until this slice they then simply returned: the handle stayed open,
`capture_is_open()` kept saying yes, and the tables stopped growing. On a
channel-hopping radio an empty dwell is *normal*, so a dead monitor
thread and a quiet channel produced the same picture indefinitely.

Each worker now classifies why it stopped and publishes the verdict plus
libpcap's own error text. The classification
(`src/capture/capture.c :: capture_classify_exit()`) is pure — no handle,
no radio — so it is unit-tested from hand-written return codes and error
strings, the same treatment `capture_activate_failed()` gets:

| `<reason>` | Cause |
|------------|-------|
| `stopped` | shutdown was requested — a clean exit, not a fault |
| `iface_gone` | the adapter went away (unplug, `ip link set down`) |
| `perm_lost` | `CAP_NET_RAW` / `CAP_NET_ADMIN` revoked under a running capture |
| `not_activated` | dispatch on a handle that was never activated |
| `error` | any other `PCAP_ERROR` — the raw libpcap text still travels in the JSONL record |

`error` is the honest fallback, not a gap: libpcap's wording is not a
kernel contract, so an unrecognised message is reported as-is rather
than guessed into a specific bucket.

### Drops and evictions

`cap drop` / `mon drop` are libpcap's buffer drops and `cap ifdrop` /
`mon ifdrop` the NIC's, polled with `pcap_stats()` once per tick. The
strip shows lifetime totals; the JSONL record carries per-tick deltas
beside them, because "am I dropping *now*" is the operator question and a
lifetime total only answers it by differencing two samples. Sloth
accumulates its own totals from those deltas rather than echoing
libpcap's 32-bit counters, so a counter that resets cannot make the
exported total run backwards.

`retune-fail` is the lifetime `chan_retune_failures` from slice 1 above.

`evict` is the total over every instrumented bounded table — an
observation that did not make it in because the table was full. The
counted tables are **alerts, top hosts, PNL clients, per-client PNL
SSIDs, DHCP events, 802.1X EAP sessions, and the device table**; the
device table refuses a *new* entry rather than evicting an old one,
which is a different mechanism with the same meaning. Listing them is
the point: the probe-client, beacon, seqnum, assoc and per-protocol flow
rings are **not** instrumented yet, and a tally that silently omitted a
table would read as "no loss" when it means "not measured". The JSONL
record breaks the total out per table.

The same state feeds the `sensor_health` JSONL record — see
[`../wiki/jsonl-schema.md`](../wiki/jsonl-schema.md).

**Still hardware-dependent, still open on #91:** the measured
adapter/driver/kernel/band/width support matrix, and comparing hopping
against an independent reference receiver. Neither can be produced from
a dev box with no radio, and neither is faked here.

## Headless scoping (`--iface` / `--monitor-only`) — issue #35

The launch-time complement to `y`, for deployments where no operator
is present to work the interactive controls (systemd units, `script`
ptys, appliance sensors):

```sh
sloth --iface wlan1 --hop --data-socket tcp:100.64.0.5:8765 --data-socket-allow-remote
sloth --monitor-only --hop --data-socket unix:/var/run/sloth.sock
```

- `--iface NAME` (repeatable) — allow-list: only the named
  interfaces feed the capture pipeline; every other iface's frames
  are dropped in the pcap callback before decode, exactly like a
  `y`-deselect set at launch.
- `--monitor-only` — sugar for `--iface <monitor radio>`: resolves
  the monitor-mode Wi-Fi interface sloth discovers at startup and
  allow-lists it.

**Fail-closed (#85).** Capture scope is an authorisation boundary, so
a scope sloth cannot enforce is a startup error, not a warning. sloth
prints the reason to stderr and exits 1 — before opening any JSONL,
DB, data socket or mDNS record — when:

- `--monitor-only` is given and no monitor-mode interface is present
  (e.g. the radio lost the boot race; `Restart=` re-resolves on the
  next start);
- `--iface` was given but no usable name was installed (`--iface ""`);
- the data-stream datalink cannot attribute frames to an interface
  (anything but SLL2/276 — older libpcap, the `open_live` fallback).

If packet capture could not be opened at all (no root, no devices)
the run continues with a warning: no data stream means nothing out of
scope is collected. There is no unrestricted fallback flag — omit
`--iface`/`--monitor-only` to capture everything.

The policy is installed before the capture thread is created and
never written afterwards. In the callback, with an allow-list active,
a frame whose ingress index does not resolve to a name
(`if_indextoname()` failed, interface gone) is dropped before decode,
and the failure is not cached.

**Excluded marker.** Interfaces present on the box but absent from a
non-empty allow-list carry an `x` prefix and a dim `(excluded)`
annotation in the interface view, mirroring the `d` / `(deselected)`
treatment — a row marker always means "this iface's frames are being
dropped". Prefix precedence is `h` (hidden) > `d` (deselected) > `x`
(excluded) > `s` (scanning). There is no key to clear it: the
allow-list is launch-time immutable, so `x` rows change only on
restart. An empty allow-list (the default) marks nothing.

The allow-list and the runtime deselect list are independent
elections; the callback drops a frame when *either* rejects its
ingress iface. Both are purely logical — OS interface state
(up/down, monitor mode, addresses) is never touched — and both
require SLL2 ingress attribution (see above). Without it the `y`
deselect is a marker with no filter effect, while a launch-time
allow-list refuses to start (fail-closed, above). The 802.11 monitor
handle is unaffected.

## See also

- Backend: [`src/platform/linux_parse.c`](../../src/platform/linux_parse.c).
- Stats baseline: [`src/views/stats.c`](../../src/views/stats.c).
