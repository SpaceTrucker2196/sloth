<p align="center">
  <img src="slothwifi.png" alt="sloth" width="640">
</p>

<p align="center">
  <a href="https://github.com/SpaceTrucker2196/sloth/actions/workflows/ci.yml"><img src="https://github.com/SpaceTrucker2196/sloth/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/SpaceTrucker2196/sloth/actions/workflows/code-review.yml"><img src="https://github.com/SpaceTrucker2196/sloth/actions/workflows/code-review.yml/badge.svg" alt="Code Review"></a>
  <img src="https://img.shields.io/badge/code%20review-GPT--5.2%20Codex-blueviolet?logo=openai" alt="Reviewed by GPT-5.2 Codex">
</p>

# sloth

A terminal-based passive network monitor for Linux, written in C99. Sloth never
injects packets, never scans, and never modifies kernel state — it observes what
your host already sees and turns it into 27 views, six alert rules, an embedded
WiFi-SIGINT toolkit (PNL aggregation, RSN/cipher/MFP inventory, EAPOL/PMKID
capture, hidden-SSID reveal, seqnum-based MAC-randomisation deanonymisation),
and an optional JSONL forensic log.

📖 **Per-view deep dives live under [`docs/views/`](docs/views/)** — each
file explains the protocol, shows a text mockup, and lists what to watch
for in normal vs anomalous traffic.

> **v1.1 — WiFi SIGINT** — sloth gained six new wireless capabilities
> on top of the v1.0 monitor: [PNL aggregation](docs/views/pnl.md) per
> client MAC, RSN / cipher / AKM / MFP inventory from beacons,
> [EAPOL / PMKID / 4-way handshake capture](docs/views/eapol.md) with
> hashcat-22000 export, hidden-SSID reveal, MAC-randomisation
> [sequence-number deanonymisation](docs/views/seqnum.md), and a
> dashboard alert-hot IP override that paints any IP appearing in a
> CRIT alert deep-red across every panel for 1 h. See the v1.1
> [release notes](https://github.com/SpaceTrucker2196/sloth/releases/tag/v1.1.0)
> for the full diff.

```
[1] Interfaces  [2] Connections  [3] WiFi      [4] Packets   [5] Processes
[6] Stats       [7] Probe        [8] ARP       [9] mDNS      [0] NBNS
[d] DHCP        [s] SSDP         [b] Beacons   [a] Deauth    [h] HTTP
[t] TLS         [u] QUIC         [r] DNS       [p] NTP       [i] ICMP
[v] Alerts      [g] Devices      [o] Dashboard [?] Help
[k] PNL         [e] EAPOL        [j] Seqnum    [w] Assoc     ← WiFi SIGINT
```

## What you get

### Observation

| View | What it shows |
|------|---------------|
| [**Interfaces**](docs/views/interfaces.md) | Per-interface RX/TX rates, errors/drops, MTU, link speed; sparkline history |
| [**Connections**](docs/views/connections.md) | Active TCP/UDP sockets with PID, RTT, retransmits, per-conn bandwidth |
| [**WiFi**](docs/views/wifi.md)             | Nearby APs from `nl80211` scan: signal, channel, encryption |
| [**Packets**](docs/views/packets.md)       | Live pcap capture with BPF filter, hex detail panel, pcap export |
| [**Processes**](docs/views/processes.md)   | Process tree with fold/unfold |
| [**Stats**](docs/views/stats.md)           | Session totals — bytes, packets, rates per interface since reset |
| [**Probe**](docs/views/probe.md)           | 802.11 probe-request sniffer — unassociated clients and the SSIDs they're looking for |
| [**ARP**](docs/views/arp.md)               | Layer-2 neighbour table with OUI vendor lookup |
| [**mDNS**](docs/views/mdns.md)             | Bonjour/Zeroconf service table from passive UDP/5353 |
| [**NBNS**](docs/views/nbns.md)             | NetBIOS Name Service table from UDP/137 |
| [**DHCP**](docs/views/dhcp.md)             | Live DHCP event log: DISCOVER/REQUEST/ACK |
| [**SSDP**](docs/views/ssdp.md)             | UPnP device table from UDP/1900 NOTIFY / M-SEARCH |
| [**Beacons**](docs/views/beacons.md)       | Passive 802.11 beacon sniffer — APs visible to a monitor-mode iface, with pairwise cipher / AKM / MFP status from the RSN IE, and hidden-SSID reveal from probe-responses |
| [**Deauth**](docs/views/deauth.md)         | 802.11 deauth/disassoc frames; flood detection per target MAC |
| [**HTTP**](docs/views/http.md)             | Plaintext HTTP requests: method, host, path |
| [**TLS**](docs/views/tls.md)               | TLS ClientHello log: SNI host, version, and **JA3 fingerprint** |
| [**QUIC**](docs/views/quic.md)             | QUIC Initial packets: version + DNS-resolved host |
| [**DNS**](docs/views/dns.md)               | DNS query/response log: qname, qtype, answer, NXDOMAIN |
| [**NTP**](docs/views/ntp.md)               | NTP traffic: mode, stratum, reference ID |
| [**ICMP**](docs/views/icmp.md)             | ICMPv4 + ICMPv6 with named types (Echo, Unreachable, Neigh Sol, …) |

### Synthesis

| View | What it shows |
|------|---------------|
| [**Alerts**](docs/views/alerts.md)       | Rule-derived events: port scans, deauth floods, NXDOMAIN bursts, threat-intel domain hits, threat-intel IP hits, periodic beaconing |
| [**Devices**](docs/views/devices.md)     | One record per MAC, joined from ARP/DHCP/Beacons/Probe/Stations with OUI vendor |
| [**Dashboard**](docs/views/dashboard.md) | Composite at-a-glance view: interfaces, conns + top hosts, packets, and seven side-panel categories all tiled to fill the terminal |

### WiFi SIGINT (v1.1)

| View | What it shows |
|------|---------------|
| [**PNL**](docs/views/pnl.md)         | Per-MAC Preferred Network List — every directed probe-request's source MAC aggregated with the unique set of SSIDs it has probed for. Randomised MACs are flagged so randomised vs burned-in is one glance. A device's PNL fingerprints its owner. |
| [**EAPOL**](docs/views/eapol.md)     | Captured EAPOL-Key frames + 4-way handshake state machine. M1 with a PMKID KDE = one-frame offline-crack vector. M1+M2 together = full handshake. `--eapol-dir DIR` writes captures in hashcat 22000 format. |
| [**Seqnum**](docs/views/seqnum.md)   | Sequence-number-based MAC-randomisation deanonymisation. Pairs of MACs whose seqnum trails overlap within 64 seqnums / 30 s are the same physical radio across a MAC rotation. |
| [**Assoc**](docs/views/assoc.md)     | Client ↔ AP association inventory. Each row is a (BSSID, STA) pair we've observed confirmation for: EAPOL handshake completed, assoc-response status=0, or reassoc-response status=0. Disassoc / deauth removes the entry. |

### Output

- **`sloth -o FILE`** — append a JSONL line for every DNS/TLS/QUIC/HTTP/NTP/ICMP record and every newly-fired alert. See [JSONL schema](#jsonl-schema) below.
- **`sloth --pcap-dir DIR`** — when a rule fires with a known flow identifier (THREAT_IP, BEACONING, PORT_SCAN, NXDOMAIN_BURST, THREAT_DOMAIN), the matching packets are written to a per-alert pcap file under `DIR`.
- **`sloth --eapol-dir DIR`** — append each captured PMKID and 4-way handshake to `DIR/eapol.22000` in [hashcat mixed format](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2). Crack directly with `hashcat -m 22000 eapol.22000 wordlist.txt`. Sloth also writes a per-handshake `DIR/<bssid>_<sta>.pcap` (raw 802.11, DLT 105) so each capture can be replayed through `aircrack-ng -w wordlist.txt -e <SSID> <file>.pcap` or opened in Wireshark.

## WiFi SIGINT usage

Sloth is fully passive — it never injects probe requests, never sends
deauth frames, never associates with anything. All wireless data is
sniffed by a monitor-mode interface that's been put into monitor mode
by an external tool (`iw`, `airmon-ng`, etc.) before sloth starts.

```sh
# 1. Set an adapter to monitor mode (external — sloth never touches link state).
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up

# 2. Run sloth. It auto-discovers the monitor iface; --eapol-dir
#    streams captured PMKIDs + 4-way handshakes to hashcat format.
sudo ./sloth --eapol-dir /tmp/sloth-eapol -o /tmp/sloth.jsonl

# 3. While sloth runs:
#    [k] PNL    — devices and the SSIDs they're probing for
#    [b] Beacons — APs + cipher / AKM / MFP inventory + hidden-SSID reveal
#    [e] EAPOL  — captured handshakes (PMKID = single-frame crack)
#    [j] Seqnum — randomised MACs correlated to the same physical radio
#    [7] Probe  — raw probe-request feed (Roaming clients)

# 4a. Offline crack against the streamed handshake / PMKID file.
hashcat -m 22000 /tmp/sloth-eapol/eapol.22000 rockyou.txt

# 4b. OR replay an individual handshake through aircrack-ng.
aircrack-ng -w rockyou.txt -e "SSID" \
    /tmp/sloth-eapol/<bssid>_<sta>.pcap
```

## Build

```sh
make                          # full build (ncurses + pcap + nl80211)
make WITH_PCAP=0              # no capture, no probe view
make WITH_NCURSES=0           # headless / embedded
make embedded                 # shortcut: no ncurses, no pcap
make test                     # 1856 unit tests (no root, no terminal, no network)
```

Requires `libpcap-dev` and `libncursesw-dev` for the full build. The test build needs neither.

## Keybindings

Use `[?]` inside sloth for an up-to-date reference card.

### View selection

| Key | View | Key | View | Key | View |
|-----|------|-----|------|-----|------|
| `1` | Interfaces  | `d` | DHCP    | `u` | QUIC    |
| `2` | Connections | `s` | SSDP    | `r` | DNS     |
| `3` | WiFi        | `b` | Beacons | `p` | NTP     |
| `4` | Packets     | `a` | Deauth  | `i` | ICMP    |
| `5` | Processes   | `h` | HTTP    | `v` | Alerts  |
| `6` | Stats       | `t` | TLS     | `g` | Devices |
| `7` | Probe       | `?` | Help    | `o` | Dash    |
| `8` | ARP         | `k` | PNL     | `e` | EAPOL   |
| `9` | mDNS        | `j` | Seqnum  | `w` | Assoc   |
| `0` | NBNS        |     |         |     |         |

### Global

| Key      | Action |
|----------|--------|
| `Tab`    | Cycle views forward |
| `n`      | Toggle DNS hostname resolution (in conn/proc/stats views) |
| `/`      | Filter current log view — type to refine, `Enter` to commit, `Esc` to cancel |
| `\`      | Clear filter |
| `q`/`Q`  | Quit |

### Per-view

| Key      | Action |
|----------|--------|
| `↑`/`↓`  | Navigate rows |
| `c`      | Clear the current log view's ring buffer |
| `t`      | (Interfaces) Toggle iface visibility |
| `Enter`  | (Interfaces/Packets) Open detail panel |
| `f`      | (Conns/Packets) Cycle filter |
| `s`      | (Conns) Cycle sort |

## Alerts

Six rules feed `VIEW_ALERTS`. New keys also append to the JSONL stream and (if `--pcap-dir` is set) trigger a per-alert pcap dump.

| Rule | Severity | Trigger | match_ip / port |
|------|----------|---------|-----------------|
| `PORT_SCAN`      | CRIT | scanner's IP touched ≥ 8 distinct local ports | scanner IP / 0  |
| `DEAUTH_FLOOD`   | WARN | ≥ 5 deauth/disassoc frames in 5 s to one target | — (L2 only)    |
| `NXDOMAIN_BURST` | WARN | ≥ 10 NXDOMAIN replies to one src in 60 s        | src / 53        |
| `THREAT_DOMAIN`  | CRIT | DNS qname matches embedded IOC list             | src / 53        |
| `THREAT_IP`      | CRIT | conn remote IP matches embedded IOC list        | remote IP / port |
| `BEACONING`      | WARN | flow with ≥ 5 samples, mean ≥ 10 s, jitter/mean ≤ 0.25 | remote IP / port |

The IOC lists in `src/threat_intel.c` are intentionally synthetic (RFC 5737 doc IPs, `.testing` / `.example` sentinel domains). They exist so the alerts pipeline can be exercised in tests — replace them with your own feed for production use.

## JSONL schema

Each line is one JSON object. `ts` is a Unix timestamp; strings are RFC 8259 escaped.

```json
{"type":"dns","ts":1700000000,"src":"192.168.1.5","qname":"example.com","qtype":"A","answer":"93.184.216.34","is_resp":1}
{"type":"tls","ts":1700000001,"src":"10.0.0.5","dst":"93.184.216.34","host":"example.com","ver":"TLS 1.3","ja3":"deadbeefcafef00d00112233445566ff"}
{"type":"quic","ts":1700000002,"src":"10.0.0.5","dst":"1.1.1.1","host":"cloudflare.com","ver":"v1"}
{"type":"http","ts":1700000003,"src":"10.0.0.5","host":"example.com","method":"GET","path":"/index.html"}
{"type":"ntp","ts":1700000004,"src":"10.0.0.1","dst":"192.168.1.5","mode":"server","version":4,"stratum":1,"ref":"GPS"}
{"type":"icmp","ts":1700000005,"src":"192.168.1.5","dst":"8.8.8.8","desc":"Echo Req","ty":8,"code":0,"seq":42,"v6":0}
{"type":"alert","ts":1700000006,"title":"THREAT_DOMAIN","detail":"192.168.1.5 queried malware.testing.com (IOC malware.testing.com)","key":"threat-d:malware.testing.com","sev":2,"ty":3,"count":1}
```

## Architecture

The codebase is built around a **platform vtable** (`platform_ops_t` in `include/sloth.h`):

```c
typedef struct {
    int  (*get_ifaces)(iface_stat_t *out, int max);
    int  (*get_conns)(conn_t *out, int max);
    int  (*wifi_scan)(wifi_ap_t *out, int max);
    int  (*get_wifi_stations)(wifi_sta_t *out, int max);
    int  (*get_arp)(arp_entry_t *out, int max);
    int  (*get_dhcp)(dhcp_lease_t *out, int max);
    void (*init)(void);
    void (*cleanup)(void);
} platform_ops_t;
```

Adding a new data source means adding one function pointer here and implementing it in each backend (`src/platform/linux.c`, `bsd.c`, `stub.c`, `win32.c`) and the test fake (`tests/fake_platform.c`). Views read from `sloth_state_t`; they never call platform ops directly.

### Data flow

```
   capture thread                main loop (poll_data, 1 Hz)
   ──────────────                ───────────────────────────
   pcap_loop()                   g_platform.get_ifaces()
       │                         g_platform.get_conns()
       ▼                         g_platform.get_arp()
   dns_log_parse / record        … other platform reads
   tls_log_parse / record               │
   quic_log_parse / record              ▼
   http_log_parse / record       *_snapshot()   ◄── ring buffer copy
   ntp_log_parse / record               │
   icmp_log_parse / record              ▼
       │                         alerts_update()
       ├─► jsonl_emit_*()        beacon_update()
       │     (if -o set)         devices_update()
       └─► ring buffer                  │
                                        ▼
                                 tui_draw()
```

Packet decode runs in a dedicated pcap thread. The eight log modules each have an independent ring buffer behind a `pthread_mutex_t`; `*_snapshot()` helpers copy the latest entries into `sloth_state_t` once per poll. Synthesis modules (alerts, devices, beacon-detect) read snapshot state and produce derived views.

### Code layout

```
include/sloth.h            shared types: state, packet, conn, alert, device, ...
src/main.c                 CLI, signal handlers, main loop
src/tui.c                  ncurses / ANSI rendering, key polling
src/platform/linux*.c      Linux backends (rtnetlink, nl80211, /proc, INET_DIAG)
src/capture/capture.c      libpcap thread; per-protocol parser dispatch
src/{dns,tls,quic,http,
     ntp,icmp,dns,...}_log.c     ring buffers + per-record snapshot
src/{alerts,beacon_detect,
     devices,threat_intel,
     filter,jsonl,alert_pcap}.c  synthesis + export
src/views/*.c              one file per VIEW_*
src/md5.c                  RFC 1321 implementation used for JA3
tests/                     unit tests, fake platform, scenarios
```

## Testing

```sh
make test    # 1856 assertions, no root, no terminal, no network
```

Every real-data path is replaced by a controllable fake:

- **`tests/fake_platform.c`** — implements `g_platform` with deterministic in-memory data. All vtable functions read from a global `fake_net_t`.
- **`tests/null_tui.c`** — stubs ncurses functions as no-ops; `TPRINT` falls back to `printf`, so view draw functions execute their full rendering logic.
- **`tests/scenarios.c`** — named configurations (empty, idle, busy, many_conns, wifi_crowded, monitor_env) used by render smoke tests.

Protocol parsers (DNS, TLS, JA3, QUIC, HTTP, NTP, ICMP, mDNS, NBNS, DHCP, SSDP) are tested with **raw byte arrays** constructed by hand from the relevant RFCs. Each test computes byte values from first principles so the tests are not circular.

```
0x00,0x00, 0x84,0x00,          // DNS hdr: ID=0, QR=1 AA=1
0x00,0x00, 0x00,0x01,          //          QDCOUNT=0, ANCOUNT=1
…
```

The MD5 implementation used for JA3 is independently validated against all RFC 1321 test vectors (`tests/test_md5.c`).

## Status

Code: 14k+ lines across ~80 files. Tests: 1856 assertions. License: see project root.

Sloth was built as a passive monitor. It will not scan, fuzz, attack, or attempt to deauth or de-associate anything. If that's what you need, use a different tool.
