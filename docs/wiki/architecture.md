---
name: architecture
description: Code-tree layout, key modules, and the seams (platform vtable, capture pipeline, view layer)
type: reference
---

# Architecture

**Summary**: How sloth's source is organised: header → CLI → platform vtable → capture pipeline → per-protocol parsers → state → views.

**Sources**: `CLAUDE.md`, `Makefile`, `tests/test_build_recipe.c`, `src/sloth_clock.h`, `src/poll.h`, `tests/test_poll.c`, `src/dot11_frame.h`, `src/capture/frame_edge.h`, `src/capture/probe.c`, `docs/views/connections.md`, `docs/views/packets.md`, `docs/views/dashboard.md`, `docs/views/devices.md`.

**Last updated**: 2026-10-19 (#118, #141)

---

## Tree

```
include/sloth.h            -- central header: shared structs; re-includes the two below
include/sloth_view.h       -- view_t, VIEW_COUNT, view_label(), view_for_key()
include/sloth_views.def    -- the view list: one X(ID, label, key, slug) row per view
include/sloth_alert.h      -- alert_type_t, ALERT_TYPE_COUNT, alert_type_name(), alert_technique()
include/sloth_alerts.def   -- the alert-type list: one X(ID, technique) row per rule
include/sloth_compat.h     -- SLOTH_STATIC_ASSERT, the C99 compile-time assertion
tools/docs_counts.sh       -- `make docs-counts`: rewrites the prose counts from the .defs
src/main.c                 -- CLI, signal handlers, poll loop
src/tui.c / tui.h          -- ncurses rendering, colour init, key polling (ANSI fallback)
src/platform/linux*.c      -- rtnetlink, nl80211, /proc readers, INET_DIAG
src/capture/capture.c      -- libpcap thread; dispatches to per-protocol parsers
src/capture/frame_edge.c   -- the pcap-edge gate both capture callbacks call first (#141)
src/{dns,tls,quic,http,ntp,icmp}_log.c  -- ring buffers + snapshot ([[ring-buffers]])
src/{alerts,beacon_detect,devices,threat_intel,filter,jsonl,alert_pcap,
     top_hosts,ip_color,ip_owner}.c     -- synthesis + export
src/views/*.c              -- one file per VIEW_*
src/md5.c                  -- embedded MD5 for JA3 (RFC 1321 vectors verified)
src/sloth_clock.c          -- the one clock seam: sloth_wall() / sloth_mono_ms()
tests/                     -- unit tests, fake platform, scenarios
tests/fuzz/fuzz_*.c        -- libFuzzer harnesses; one rule per archive builds them all
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
  the first SNAPSHOT stage of `poll_tick()`, #111/#113) — see [[ring-buffers]]. The
  802.11 side (`src/capture/probe.c`) follows the same rule, and every
  module it feeds, `src/fragattack.c` included since #111, holds its
  tables behind its own mutex.
- **Pcap-edge gate** (`src/capture/frame_edge.h`, #141) — the first
  thing both capture callbacks do. `frame_view_init()` turns a libpcap
  record header into a `frame_view_t` or refuses the frame before a byte
  of it is read: capture length 0, above the 65535-octet snaplen both
  handles open with, or above the record's own wire length, or a
  timestamp whose microseconds are out of range. Everything after it
  reads the view, never `hdr`; the unchecked `(int)hdr->caplen` casts
  in `on_packet()` and `on_probe_frame()` are gone (CWE-1284). Refusals
  count as `parse_fault_frame_edge` ([[jsonl-schema]]).
  `frame_view_radiotap()` is the monitor DLT's half — radiotap
  verdict, FCS strip, 802.11 minimum — and is the one call both
  `on_probe_frame()` and `decode_frame()`'s `DLT_IEEE802_11_RADIO` arm
  make, so the two radio entry points cannot disagree on what a valid
  header is. libpcap-free, so it is unit-tested and fuzzed
  (`fuzz_frame_edge`) without `WITH_PCAP`. The IPv4 Total Length clamp
  is not here; it belongs to the IP rework (#132).
- **802.11 frame view** (`src/dot11_frame.h`, #122) — each monitor frame
  is decoded **once**: `probe.c :: on_probe_frame()` and the
  `DLT_IEEE802_11_RADIO` arm of `capture.c :: decode_frame()` strip the
  FCS radiotap announces (`dot11_fcs_strip_len()`, truncation-aware,
  called from `frame_view_radiotap()` since #141),
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
- **Alert engine** — `src/alerts/engine.c` runs every rule each poll in
  the order of `src/alerts/rules_table.c`, dedupes by stable key, fires
  JSONL + per-alert pcap. The rules live in `src/alerts/rules_<domain>.c`
  (#118). See [[alerts]].
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
- `sloth_test` links every `tests/*.c` against a core archive built
  from `CORE_SRCS_ALL` plus `src/tui.c`, `src/reset_all.c` and the
  library halves of the research tools (`TEST_ONLY_SRCS`), compiled
  with `-DWITH_NCURSES -DWITH_PCAP` — the configuration `sloth` ships
  in, since #116. Every view draws through the real renderer into an offscreen
  ncurses screen (`tui_init_offscreen()`, output to `/dev/null`) and
  tests read the cells back (`tui_test_line()`, `ASSERT_LINE_HAS`,
  `ASSERT_SCREEN_HAS`). Only the platform is a stand-in
  (`tests/fake_platform.c`); `src/main.c` is not linked.
  `tests/test_views_render.c` walks `sloth_views.def` through
  `tui_draw()`: each view's tab is the one reverse-video label, its body
  is what its own draw renders, and the dashboard draws no tab bar. It
  also ratchets the remaining `ASSERT(1)` smoke asserts — a ceiling that
  only moves down, and a list of converted files that must hold none.
- `sloth_test_noflags` is the same suite without the two flags,
  against the ANSI renderer and probe.h's stubs: built, never run, so
  the `#ifndef` halves keep compiling. Before #116 that was the
  configuration the suite *ran* in, with a no-op renderer
  (`tests/null_tui.c`) and the capture path in a second binary,
  `sloth_test_pcap`.
- `make fuzz` builds every `tests/fuzz/fuzz_<name>.c` with one rule
  against a clang-built core archive (plus the ANSI half of `src/tui.c`
  and the fake platform; no fuzz binary links ncurses). The archive keeps each target narrow: the linker pulls only
  the members the harness reaches, so `fuzz_radiotap_parse` still links
  no snooper and no alert code. A new module or harness needs no
  Makefile edit — the hand-kept inline lists this replaced failed CI on
  2026-10-14 when a module they named gained a dependency.
- The exception is a harness whose seam exists only under `WITH_PCAP`
  (`fuzz_decode_frame`, over `capture_test_decode_frame()`, #125). Those
  are named in `FUZZ_PCAP_TARGETS` and link a second archive,
  `build/fuzz-pcap/`, compiled with `-DWITH_PCAP` and linked with
  `-lpcap`. `make fuzz` runs them after the plain targets; `FUZZ_PCAP`
  says what a missing `<pcap.h>` means — `auto` (default) prints a
  `SKIPPED` line naming each target, `1` fails, `0` never runs them.
  `make fuzz-pcap` runs only that half.
  `tests/test_docs_consistency.c :: test_every_fuzz_harness_is_built`
  holds the list to the directory: no name without a harness, no
  WITH_PCAP-seam harness off the list, no plain harness outside
  `FUZZ_SRCS`.
- Objects live in `build/n<NCURSES>p<PCAP>w<WIFI>s<SQLITE>/` (`embedded`
  is `n0p0w1s0`), `build/test/`, `build/test-pcap/`, `build/fuzz/` and
  `build/fuzz-pcap/`.
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

## Tick

One pass of the main loop is `poll_tick()` (`src/poll.c`, #113): a
table of named stages, each tagged with a phase, run in table order.
`main.c :: poll_data()` only builds the `poll_ctx_t` — one wall and one
monotonic reading through the clock seam, the research handle, and two
hooks for consumers that live in the app rather than the core library
(the tui alert-hot list, the channel-hop scheduler).

| Phase | What runs | Reads |
|---|---|---|
| PLATFORM | `g_platform` ifaces / conns / Wi-Fi / ARP / DHCP, capture + probe + persist health, scope pins, first-tick stats baseline | the kernel |
| SNAPSHOT | `capture_ring_snapshot()` first, then every capture-fed `*_snapshot(s)` | module tables, under their locks |
| DERIVE | history + bandwidth, channel summary + control-frame annotation, RF quality, scan, beacon detection, recurring transit, sensor registration + merged Wi-Fi model, twins | this tick's snapshots |
| ALERTS | `alerts_update()` | everything above |
| POST | research coverage, KARMA, alert-hot, devices, top hosts, channel hop | this tick's alerts |
| EMIT | JSONL connections, twin episodes, state snapshots | all of it |
| DURABLE | `db_tick()` on its own cadence | all of it |

`test_phases_are_monotonic` pins that no stage precedes a stage of an
earlier phase; the end-to-end tests in `tests/test_poll.c` run the real
table on the fake platform. The hand-sequenced `poll_data()` it replaced
had six stale reads, each one tick late: JSONL state before the
snapshots, twins before beacons, the channel summary before beacons,
sensor and `wifi_merged` records before registration, recurring transit
after the alert pass, and RF quality / beacon detection on the raw wall
clock while the alert engine read the seam. Stages gated on `WITH_PCAP`
keep that gate; the suite is built `WITH_PCAP` since #116, so they run
in `sloth_test` with the rest.

Not in the table: the `(out, max)` copies (`pm_forge`, `wps_track`,
`queue_evict`) that a rule takes under the module's own lock at the
point it reads them. They have no `sloth_state_t` field for a stage to
fill.

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
- Views and alert types are each one list, not several kept in step
  (see *Generated lists* below). Adding a row is the whole registration;
  `make docs-counts` then updates the prose counts, and
  `tests/test_docs_consistency.c` fails until it has.
- Parser tests use raw byte arrays built from RFCs — no parser-feeds-itself
  circular tests.

## Generated lists (#117)

Two enums used to be hand-synced across five places each. `VIEW_COUNT`
was hardcoded as `35` in two tests, the label table, the `tui.c` draw
switch and the `main.c` key switches all listed every view again, and
`alert_type_name()` / `alert_technique()` were two 75-arm switches held
total only by `-Wswitch` under CI's `-Werror`. Every slice adding a view
or a rule edited all of them, plus about six prose counts in the docs —
the collision point when slices land in parallel.

Each list is now an X-macro `.def` file, and everything else is expanded
from it:

| List | Row | Expanded into |
|---|---|---|
| `include/sloth_views.def` | `X(ID, "label", "key", slug)` | `view_t` + `VIEW_COUNT`; `view_label()` (`"[key] label"`, assembled at compile time) and `view_for_key()` in `src/view_labels.c`; the draw dispatch in `src/tui.c` (`view_<slug>_draw`); the per-view key dispatch (`view_<slug>_key`) and the global view-select in `src/main.c` |
| `include/sloth_alerts.def` | `X(ID, "T1xxx" or "")` | `alert_type_t` + `ALERT_TYPE_COUNT`; the `alert_type_name()` and `alert_technique()` tables in `src/alerts/engine.c` |

Row order is the enum order. For views that is the Tab cycle and the
help card's order; for alert types the values are carried by the JSONL
`ty` field and the SQLite store, so rows are appended, never inserted or
reordered. `alert_type_name()` is the enum spelling stringized, so it
cannot drift from the enum. The dispatch switches have no `default:`, so
`-Wswitch` still names a missed value if one is ever hand-written back.

`SLOTH_STATIC_ASSERT` (`include/sloth_compat.h`) is the C99 form — a
negative-size array typedef, since `_Static_assert` is C11 — and pins
each table's length to its count and each view key to one character.

`sloth.h` re-includes both headers, so none of its includers changed.
They came first because neither depends on anything else in `sloth.h`.

**Prose counts.** The docs that state how many views or rules there are
carry the number inside a marker, `<!-- count:views -->N<!-- /count -->`
or `<!-- count:rules -->…`. `make docs-counts` (`tools/docs_counts.sh`)
counts the `X(` rows at column 0 of each `.def` and rewrites every
marker; `tests/test_docs_consistency.c` asserts each marker against the
compiled count, asserts the row count the script uses agrees with the
compiler's, and still runs the free-prose scanner over every page, which
now reads through the comments. `log.md` carries no markers: it is
history. `agents/` is outside this change (its edits are batched in #119)
and keeps its unmarked counts, still checked by the prose scanner.

## Related pages

- [[platform-vtable]]
- [[jsonl-schema]]
- [[ring-buffers]]
- [[views-catalog]]
- [[alerts]]
- [[pcap-export]]

## Rule: do not add arrays to `sloth_state_t`

`sloth_state_t` is 2.2 MB and is copied into from 43 snapshot functions.
New modules expose an accessor (`const T *mod_rows(int *n)`, or the
`frag_bss_copy` / `stab_snapshot` style) instead of adding a ring to the
struct. Existing members move out one header at a time, never in a flag
day (#117, #143).
