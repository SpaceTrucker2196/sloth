---
name: architecture
description: Code-tree layout, key modules, and the seams (platform vtable, capture pipeline, view layer)
type: reference
---

# Architecture

**Summary**: How sloth's source is organised: header → CLI → platform vtable → capture pipeline → per-protocol parsers → state → views.

**Sources**: `CLAUDE.md`, `Makefile`, `tests/test_build_recipe.c`, `src/sloth_clock.h`, `src/dot11_frame.h`, `src/capture/probe.c`, `docs/views/connections.md`, `docs/views/packets.md`, `docs/views/dashboard.md`, `docs/views/devices.md`.

**Last updated**: 2026-10-15 (#115: derived source lists, `libsloth_core.a`, per-config object directories).

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
tests/fuzz/fuzz_*.c        -- libFuzzer harnesses; one Makefile rule builds them all
build/<cfg>/               -- objects + libsloth_core.a per configuration (ignored)
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

## Build layout

Since #115 every binary is derived from one set of source lists in the
`Makefile`; nothing keeps a list of its own.

- `APP_SRCS` = `src/main.c`, `src/tui.c` and the real platform vtable
  (`src/platform/linux.c` on Linux) — what only the shipped `sloth`
  links.
- `CORE_SRCS` = everything else the current `WITH_*` configuration
  compiles: `CORE_COMMON_SRCS` plus whichever feature groups
  (`LINUX_PLATFORM_SRCS`, `LINUX_WIFI_SRCS`, `PCAP_CORE_SRCS`,
  `SQLITE_CORE_SRCS`) the flags leave on. It is archived as
  `build/<cfg>/libsloth_core.a` and linked after the app objects.
- `sloth_test` links every `tests/*.c` except the capture-path pair
  against a core archive built from `CORE_SRCS_ALL` minus
  `src/capture/probe.c`, plus `src/reset_all.c` and the library halves
  of the research tools (`TEST_ONLY_SRCS`). `sloth_test_pcap` links the
  same with `-DWITH_PCAP`, its own `main`, and probe.c back in.
- `make fuzz` builds every `tests/fuzz/fuzz_<name>.c` with one rule
  against a clang-built core archive (plus the null renderer and fake
  platform). The archive keeps each target narrow: the linker pulls only
  the members the harness reaches, so `fuzz_radiotap_parse` still links
  no snooper and no alert code. A new module or harness needs no
  Makefile edit — the hand-kept inline lists this replaced failed CI on
  2026-10-14 when a module they named gained a dependency.
- Objects live in `build/n<NCURSES>p<PCAP>w<WIFI>s<SQLITE>/` (`embedded`
  is `n0p0w1s0`), `build/test/`, `build/test-pcap/` and `build/fuzz/`.
  Each directory carries a flags stamp, so changing `EXTRA_CFLAGS`
  recompiles instead of reusing objects built without, say, `-Werror`;
  `sloth` relinks when the configuration changes even if no object is
  newer. Header dependencies come from `-MMD`.
- `make cppcheck` still scans the `src` and `research` directories — the
  exact command CI runs. `tests/test_build_recipe.c ::
  test_cppcheck_target_matches_ci` holds the two argument lists equal
  until CI calls the target itself (#119).

The "`make clean` between configs" rule in `agents/AGENTS.md` stays in
force until the per-config directories have a week of green CI behind
them; relaxing it belongs to the batched `agents/` change (#119).

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
