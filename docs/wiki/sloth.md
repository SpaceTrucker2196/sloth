---
name: sloth
description: Top-level project overview — what sloth is, what it does, what it explicitly never does
type: reference
---

# Sloth

**Summary**: Terminal-based **passive** network monitor for Linux, written in C99. Reads `/proc`, `/sys`, netlink, and a pcap stream. Never injects a frame onto a network it monitors; every other network-using behaviour is opt-in and announced (`MISSION.md` §2).

**Sources**: `CLAUDE.md`, `docs/views/README.md`, all `docs/views/*.md`.

**Last updated**: 2026-10-19.

---

## What sloth surfaces

- **<!-- count:views -->36<!-- /count --> ncurses views** (`VIEW_COUNT`, one per row of `include/sloth_views.def`) organised into observation, synthesis, and WiFi-SIGINT groups — see [[views-catalog]].
- **<!-- count:rules -->90<!-- /count --> alert rules** (one per `ALERT_TYPE_*`, one per row of `include/sloth_alerts.def`) — see [[alerts]]. The threat-intel matcher among them ships a **synthetic demo IOC list**, not a feed — see [[threat-intel]].
- **Per-alert pcap dumps** when `--pcap-dir` is set — see [[pcap-export]].
- **Optional JSONL forensic log** for downstream tooling.
- **Composite dashboard** that tiles seven bands into one terminal — see [[dashboard]].

## What sloth never does

- No packet injection. No active scanning. No kernel-state modification.
- No mocks of real-data interfaces in tests; the fake platform in `tests/fake_platform.c` lives there for a reason.
- No coloured row backgrounds in the TUI — see [[ip-palette]].

## Binaries

- `sloth` — main binary.
- `sloth_test` — test binary, must always be green. Built the way
  `sloth` ships (#116): `WITH_NCURSES` + `WITH_PCAP`, the real renderer
  drawing into an offscreen ncurses screen, and the capture-path suite
  (#95) in the same run, so the sanitizers see frames arrive through
  libpcap's own reader and the real `on_packet()` callback.
- `sloth_test_noflags` — the same suite without ncurses or pcap.
  Link-only: it proves the `#ifndef` halves still build, and is never
  run. (`sloth_test_pcap`, the separate capture-path binary, is gone;
  `make test-capture-path` is an alias for `make test` for one release.)

## Architecture entry points

- `include/sloth.h` — central header with shared structs and the `view_t` enum.
- `src/main.c` — CLI, signal handlers, poll loop.
- `src/platform/linux*.c` — kernel-facing backends behind a vtable; see [[platform-vtable]].
- `src/capture/capture.c` — libpcap thread that dispatches to per-protocol parsers.
- `src/views/*.c` — one file per view; see [[views-catalog]].

## Threat coverage in one glance

See [[attack-map]] for the full protocol-to-threat map, [[wifi-sigint]] for the
802.11-specific SIGINT primitives (PMKID, 4-way handshake, PNL, seqnum),
[[mac-randomisation]] for the deanonymisation primitives, [[ja3-fingerprinting]]
for the TLS client-fingerprint primitive, and [[beacon-detection]] for the C2
periodicity detector.

## Related pages

- [[architecture]] — code-tree layout and seams.
- [[views-catalog]] — full keybinding-to-view map.
- [[alerts]] — alert engine and its rules (one per `ALERT_TYPE_*`).
- [[dashboard]] — composite view layout.
