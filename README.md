# sloth

A terminal-based network monitor for Linux, written in C99. Passive-only — no packets are injected and no kernel state is modified.

```
[1] Interfaces  [2] Connections  [3] WiFi     [4] Packets  [5] Processes
[6] Stats       [7] Probe        [8] ARP      [9] mDNS
[0] NBNS        [d] DHCP         [s] SSDP     [b] Beacons
```

## Features

| View | What it shows |
|------|--------------|
| **Interfaces** | Per-interface RX/TX rates, errors/drops, MTU, link speed; sparkline history graph (Enter) |
| **Connections** | Active TCP/UDP sockets with PID, RTT, retransmits, per-connection bandwidth; sort/filter |
| **WiFi** | Nearby APs (nl80211 scan) with signal, channel, encryption; associated-station detail (Enter) |
| **Packets** | Live pcap capture with BPF filter, detail panel, pcap export; DNS/TLS-SNI/mDNS decoding |
| **Processes** | Process tree (DFS pre-order) with fold/unfold |
| **Stats** | Session totals: bytes, packets, rates per interface since last reset |
| **Probe** | 802.11 probe-request sniffer — unassociated devices, SSIDs being searched, signal |
| **ARP** | Layer-2 neighbor table with OUI vendor lookup and DHCP hostname/lease expiry |
| **mDNS** | Bonjour/Zeroconf service table built from passive UDP/5353 observation |
| **NBNS** | NetBIOS Name Service table — Windows/Samba hostnames from UDP/137 |
| **DHCP** | Live DHCP event log — DISCOVER/REQUEST/ACK with hostname and IP |
| **SSDP** | UPnP device table from passive UDP/1900 NOTIFY/M-SEARCH traffic |
| **Beacons** | Passive 802.11 beacon sniffer — APs observed on monitor iface with SSID, BSSID, signal, channel, encryption, beacon interval |

Passive snooping features active when pcap capture is running:

- **DNS snooping** — UDP/53 answers populate the hostname cache (used by Connections view `n` key)
- **TLS SNI snooping** — ClientHello hostname extracted and added to the cache
- **mDNS snooping** — PTR/SRV/A/AAAA records from UDP/5353 multicast traffic

## Requirements

```
libpcap-dev   (packet capture + probe view)
libncursesw-dev
```

For the Probe view (802.11 monitor mode): a wireless adapter capable of `ARPHRD_IEEE80211_RADIOTAP` (type 803) and a driver that supports monitor mode (tested with 88XXau DKMS on kernel 6.19+).

## Build

```sh
make                          # full build (ncurses + pcap + nl80211)
make WITH_PCAP=0              # no capture, no probe view
make WITH_NCURSES=0           # headless / embedded
make embedded                 # shortcut: no ncurses, no pcap
make test                     # unit test suite (no root, no terminal needed)
```

## Key bindings

### Global

| Key | Action |
|-----|--------|
| `1`–`9` | Switch to view |
| `Tab` | Cycle views forward |
| `n` | Toggle DNS hostname resolution |
| `q` / `Q` | Quit |

### Interfaces (1)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Open/close detail panel (speed, MTU, errors, bar graphs) |
| `m` | Set this interface as probe-capture interface |
| `t` | Toggle interface visibility |

### Connections (2)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `s` | Cycle sort: State → Proto → Port → PID → Bandwidth → RTT |
| `f` | Cycle filter: All → TCP → UDP |

### Packets (4)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `Enter` | Open/close hex detail panel |
| `f` / `/` | Open BPF filter input |
| `p` / `Space` | Pause / resume auto-scroll |
| `w` | Export visible packets to pcap file |
| `x` | Clear packet buffer |

### Probe (7) / mDNS (9)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate |
| `c` | Clear table |

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

Packet decode runs in a dedicated pcap thread. DNS, TLS-SNI, and mDNS parsers are called inline from the capture callback (all three are thread-safe) and inject into shared caches protected by their own mutexes. The main loop calls `*_snapshot()` helpers each poll cycle to pull the latest data without blocking.

---

## Testing

### Philosophy

The test suite runs with a plain `make test` — no root, no terminal, no network, no kernel interfaces. Every real-data path is replaced by a controllable fake.

### The fake environment

Three files provide the complete test substrate:

**`tests/fake_platform.c`** — implements `g_platform` with deterministic in-memory data. All vtable functions (`get_ifaces`, `get_conns`, `wifi_scan`, `get_wifi_stations`, `get_arp`, `get_dhcp`) read from a global `fake_net_t` struct:

```c
typedef struct {
    iface_stat_t   ifaces[MAX_IFACES];
    int            iface_count;
    conn_t         conns[MAX_CONNS];
    int            conn_count;
    wifi_ap_t      aps[MAX_WIFI_APS];
    int            ap_count;
    wifi_sta_t     wifi_stas[MAX_WIFI_STAS];
    int            wifi_sta_count;
    probe_client_t probe_clients[MAX_PROBE_CLIENTS];
    int            probe_count;
    char           probe_iface[16];
    int            tick;
} fake_net_t;
```

`fake_net_apply_probe()` copies probe state into a running `sloth_state_t`, allowing probe-view tests to drive specific client counts, signals, ages, and SSIDs without touching a real radio.

**`tests/null_tui.c`** — stubs all terminal/ncurses functions as no-ops. The `TPRINT` macro falls back to `printf`, so view draw functions execute their full rendering logic and print to stdout. Tests redirect stdout to `/dev/null` to suppress output while still exercising every branch.

**`tests/scenarios.c`** — named configurations of `fake_net_t`:

| Scenario | Description |
|----------|-------------|
| `scenario_empty()` | Zero interfaces, zero connections — exercises empty-state branches |
| `scenario_idle()` | Two interfaces, one established TCP connection, two APs |
| `scenario_busy()` | Saturated gigabit interface (exercises rate formatting) |
| `scenario_many_conns()` | 200 connections, mixed TCP/UDP (exercises sort/filter limits) |
| `scenario_wifi_crowded()` | 30 APs across full signal range (exercises viewport pagination) |
| `scenario_monitor_env()` | wlan0 (managed) + wlan1mon (monitor), associated station, 8 probe clients with varied ages/signals/SSIDs |

### What is tested

| Test file | Module | Focus |
|-----------|--------|-------|
| `test_parse.c` | `linux_parse.c` | `/proc/net/if_inet6`, `/proc/net/tcp6`, hex address parsing |
| `test_rates.c` | `history.c` / `bandwidth.c` | Rate calculation, counter rollover, sparkline ring |
| `test_state.c` | core | View tab cycling, packet ring buffer, VIEW_COUNT sync |
| `test_scenario.c` | all views | Render smoke tests (idle + empty state) against every draw function |
| `test_conns.c` | `views/conns.c` | Sort/filter/navigation key handlers |
| `test_wifi.c` | `views/wifi.c` | AP navigation, viewport, detail panel |
| `test_packets.c` | `views/packets.c` | Ring buffer, filter mode, key handlers |
| `test_procs.c` | `views/procs.c` | Process tree DFS, fold/unfold |
| `test_bw.c` | `bandwidth.c` | Per-connection bandwidth attribution |
| `test_dns.c` | `dns.c` | Cache injection, lookup, format helpers |
| `test_stats.c` | `views/stats.c` | Baseline capture, delta calculation |
| `test_probe.c` | probe view | Age buckets, signal extremes, viewport, named/wildcard SSIDs, monitor scenario |
| `test_oui.c` | `oui.c` | OUI vendor lookup, randomized/multicast bits |
| `test_services.c` | `services.c` | Port-to-name mapping |
| `test_arp.c` | `views/arp.c` | ARP table rendering, DHCP hostname lookup |
| `test_pcap_write.c` | `pcap_write.c` | pcap file header + packet record serialization |
| `test_iface_graph.c` | `views/iface.c` | Sparkline bar graph, history ring |
| `test_geo.c` | `geo.c` | RFC1918 / loopback / link-local classification |
| `test_dhcp.c` | `linux_dhcp.c` | isc-dhcpd and systemd lease file parsing |
| `test_rtt.c` | `linux_tcpdiag.c` | INET_DIAG RTT/retransmit parsing |
| `test_tree.c` | `views/procs.c` | Process tree construction from /proc |
| `test_scan.c` | `scan.c` | Port-sweep detection, RFC1918 filter, alert flag |
| `test_dns_snoop.c` | `dns_snoop.c` | DNS wire format A/AAAA/CNAME parsing, compression pointer loops |
| `test_sni_snoop.c` | `sni_snoop.c` | TLS ClientHello parsing, extension walking, rejection of non-ClientHello records |
| `test_mdns_snoop.c` | `mdns_snoop.c` + `views/mdns.c` | PTR/SRV/A/AAAA parsing, service table, snapshot, cache-flush bit, combined packets, view draw/nav |

### Hand-crafted protocol packets

Protocol parsers (`dns_snoop`, `sni_snoop`, `mdns_snoop`) are tested with **raw byte arrays** constructed by hand from RFC specifications. Each byte is calculated from first principles so tests are not circular. For example, a DNS PTR packet at the byte level:

```
0x00,0x00, 0x84,0x00,          // ID=0, QR=1 AA=1
0x00,0x00, 0x00,0x01,          // QDCOUNT=0, ANCOUNT=1
0x00,0x00, 0x00,0x00,          // NSCOUNT=0, ARCOUNT=0
0x05,'_','h','t','t','p',      // owner: _http (label)
0x04,'_','t','c','p',          //        _tcp
0x05,'l','o','c','a','l',0x00, //        local (root)
0x00,0x0C, 0x00,0x01,          // TYPE=PTR, CLASS=IN
0x00,0x00,0x11,0x94,           // TTL=4500
0x00,0x0B,                     // RDLENGTH=11
0x08,'m','y','d','e','v','i','c','e', // rdata: mydevice
0xC0,0x0C                      //         + compression ptr to offset 12
```

---

## Code coverage

Generated with `gcc --coverage` on the test build (no pcap, no ncurses). Run `make test` to reproduce.

```
src/sni_snoop.c           100.0%   52 /  52  lines
src/scan.c                100.0%   50 /  50
src/pcap_write.c          100.0%   41 /  41
src/history.c             100.0%   23 /  23
src/geo.c                 100.0%   21 /  21
src/oui.c                 100.0%   19 /  19
src/services.c            100.0%   14 /  14
src/mdns_snoop.c          100.0%  129 / 129
src/bandwidth.c            97.8%   87 /  89
src/platform/linux_parse.c 97.7%   84 /  86
src/dns_snoop.c            96.5%   82 /  85
src/views/arp.c            96.2%   75 /  78
src/views/wifi.c           95.4%  144 / 151
src/views/procs.c          95.0%  267 / 281
src/views/probe.c          94.1%  111 / 118
src/views/packets.c        93.8%   61 /  65
src/views/mdns.c           93.2%   68 /  73
src/views/stats.c          84.2%  144 / 171
src/views/conns.c          83.6%  163 / 195
src/views/iface.c          77.6%  184 / 237
src/dns.c                  52.4%   66 / 126  ¹
src/platform/linux_dhcp.c   0.0%    0 /  96  ²
src/platform/linux_pid.c    0.0%    0 /  47  ²
src/platform/linux_tcpdiag.c 0.0%  0 /  39  ²
src/platform/linux_wifi.c   0.0%    0 / 283  ²
```

**Overall (tested modules only):** ~90%  
**Overall (all source):** ~73%

¹ `dns.c` — the background resolver thread (`dns_init`, worker, `getnameinfo`, `enqueue`) is not exercised.
  Unit tests use `dns_reset()` + `dns_set_resolved()` to inject entries directly, bypassing the thread.
  This is intentional: the async path is tested at integration level, not unit level.

² Linux platform backends require root and live kernel interfaces (nl80211 for WiFi, INET_DIAG for RTT,
  /proc files for PID/DHCP). They are replaced in tests by `tests/fake_platform.c`.
  These files have zero unit coverage by design.
