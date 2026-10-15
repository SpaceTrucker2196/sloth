---
name: architecture
description: Code-tree layout, key modules, and the seams (platform vtable, capture pipeline, view layer)
type: reference
---

# Architecture

**Summary**: How sloth's source is organised: header → CLI → platform vtable → capture pipeline → per-protocol parsers → state → views.

**Sources**: `CLAUDE.md`, `src/sloth_clock.h`, `src/dot11_frame.h`, `src/capture/probe.c`, `docs/views/connections.md`, `docs/views/packets.md`, `docs/views/dashboard.md`, `docs/views/devices.md`.

**Last updated**: 2026-10-14 (#122: the one-decode 802.11 frame view).

---

## Tree

```
include/sloth.h            -- central header: shared structs, view_t enum, VIEW_COUNT
src/main.c                 -- CLI, signal handlers, poll loop
src/tui.c / tui.h          -- ncurses rendering, colour init, key polling (ANSI fallback)
src/platform/linux*.c      -- rtnetlink, nl80211, /proc readers, INET_DIAG
src/capture/capture.c      -- libpcap thread; dispatches to per-protocol parsers
src/{dns,tls,quic,http,ntp,icmp}_log.c  -- ring buffers + snapshot ([[ring-buffers]])
src/{alerts,beacon_detect,devices,threat_intel,filter,jsonl,alert_pcap,
     top_hosts,ip_color,ip_owner}.c     -- synthesis + export
src/views/*.c              -- one file per VIEW_*
src/md5.c                  -- embedded MD5 for JA3 (RFC 1321 vectors verified)
src/sloth_clock.c          -- the one clock seam: sloth_wall() / sloth_mono_ms()
tests/                     -- unit tests, fake platform, scenarios
docs/views/*.md            -- per-view deep dives
```

## Seams

- **Platform vtable** (`platform_ops_t` in `sloth.h`) — see [[platform-vtable]].
  Views never call platform ops directly; they read `sloth_state_t`.
- **Capture pipeline** — `src/capture/capture.c` runs a libpcap thread,
  decodes Ethernet → IPv4/v6 → TCP/UDP, then dispatches to
  `dns_log`, `tls_log`, `quic_log`, `http_log`, `ntp_log`, `icmp_log`.
  ARP, LLC, and unknown ethertypes are filtered before the ring buffer.
  The packet ring itself is private to the capture thread and reaches
  `sloth_state_t` only as a per-poll copy (`capture_ring_snapshot()`,
  first thing in `poll_data()`, #111) — see [[ring-buffers]]. The
  802.11 side (`src/capture/probe.c`) follows the same rule, and every
  module it feeds, `src/fragattack.c` included since #111, holds its
  tables behind its own mutex.
- **802.11 frame view** (`src/dot11_frame.h`, #122) — each monitor frame
  is decoded **once**: `probe.c :: on_probe_frame()` and the
  `DLT_IEEE802_11_RADIO` arm of `capture.c :: decode_frame()` strip the
  FCS radiotap announces (`dot11_fcs_strip_len()`, truncation-aware),
  hand radiotap's FCS/DATAPAD/BADFCS flags to `dot11_frame_decode()`
  as hints, and read type, subtype, flags, header length, body offset
  and the Table 9-26 address roles out of the resulting `dot11_frame_t`.
  The §9.2.4.1.10 rule (Order means HT Control only in management and
  QoS data frames) lives in that one function. The byte-pointer helpers
  in `src/dot11_data.h` are wrappers over it, kept because the
  observers (`eapol_log.c`, `fragattack.c`, `pm_forge.c`,
  `queue_evict.c`, `deauth_snoop.c`, `action_snoop.c`, `assoc_track.c`,
  `ctrl_frames.c`) still take `(dot11, len)` and their tests and fuzz
  harnesses are written against that. Tests build frames with
  `tests/frame_build.h`, which appends optional fields only when the
  test states them. Two consequences an operator can see: the monitor
  packets band's per-frame length excludes the FCS when radiotap says
  one is present (it used to include the four trailer octets), and a
  (re)association response of 30–35 octets now reaches the assoc
  tracker (a stale 36-octet floor dropped them).
- **Alert engine** — `src/alerts.c` runs each rule every poll, dedupes by
  stable key, fires JSONL + per-alert pcap. See [[alerts]].
- **Clock seam** (`src/sloth_clock.h`, #109) — `sloth_wall()` for
  evidence (timestamps, export) and `sloth_mono_ms()` for durations
  (windows, TTLs, cooldowns); `sloth_clock_test_set()` swaps either for
  tests, `NULL` restores the real one. Stamping through the seam and
  checking against libc is a bug no test can see while both read real
  clocks: the evil-twin taint did exactly that, so under an injected
  clock it never matched and in production an NTP step mis-aged its
  TTL. Modules migrate off direct `time(NULL)` / `clock_gettime()` one
  at a time; `tests/test_clock_seam.c` lists the migrated files and
  fails on a regression. The #88 `flood_wall()` / `flood_mono_ms()` /
  `flood_test_set_clock()` names in `flood_window.h` are `static
  inline` forwards to it until their last caller moves.
- **Correlation seams** — modules that answer a question sloth's own
  sensors cannot. `src/inventory.c` reads the operator's approved-BSSID
  file ([[inventory]]); `src/wired_attach.c` is a one-slot in-process
  registration point for a future switch/controller/DHCP correlator, so
  the twin surfaces can render "is this AP on the wire" without any of
  them pretending RF answers it (#89 slice 3). Both are read-only,
  in-process, and neither is a control surface or a plugin loader.

## State

`sloth_state_t` is the single shared structure. Each view declares ring
buffers + counters + selection index on it. Views read; platform code
and the main-thread `*_snapshot()` copies write. Nothing on a capture
thread writes `sloth_state_t` directly: each capture-fed module keeps
its own table behind its own mutex and main copies it out once per
poll.

## Test discipline

- `make test` returns 0. Never commit a red test.
- `make` is warning-clean.
- `VIEW_COUNT` must stay in sync across `include/sloth.h`,
  `tests/test_state.c`, and `tests/test_arp.c` when adding / removing a view.
- Parser tests use raw byte arrays built from RFCs — no parser-feeds-itself
  circular tests.

## Related pages

- [[platform-vtable]]
- [[views-catalog]]
- [[alerts]]
- [[pcap-export]]
