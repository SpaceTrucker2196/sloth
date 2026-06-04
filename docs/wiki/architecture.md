---
name: architecture
description: Code-tree layout, key modules, and the seams (platform vtable, capture pipeline, view layer)
type: reference
---

# Architecture

**Summary**: How sloth's source is organised: header → CLI → platform vtable → capture pipeline → per-protocol parsers → state → views.

**Sources**: `CLAUDE.md`, `docs/views/connections.md`, `docs/views/packets.md`, `docs/views/dashboard.md`, `docs/views/devices.md`.

**Last updated**: 2026-05-25.

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
tests/                     -- unit tests, fake platform, scenarios (~1664 assertions)
docs/views/*.md            -- per-view deep dives
```

## Seams

- **Platform vtable** (`platform_ops_t` in `sloth.h`) — see [[platform-vtable]].
  Views never call platform ops directly; they read `sloth_state_t`.
- **Capture pipeline** — `src/capture/capture.c` runs a libpcap thread,
  decodes Ethernet → IPv4/v6 → TCP/UDP, then dispatches to
  `dns_log`, `tls_log`, `quic_log`, `http_log`, `ntp_log`, `icmp_log`.
  ARP, LLC, and unknown ethertypes are filtered before the ring buffer.
- **Alert engine** — `src/alerts.c` runs each rule every poll, dedupes by
  stable key, fires JSONL + per-alert pcap. See [[alerts]].

## State

`sloth_state_t` is the single shared structure. Each view declares ring
buffers + counters + selection index on it. Views read; capture and
platform code write.

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
