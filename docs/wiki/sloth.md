---
name: sloth
description: Top-level project overview — what sloth is, what it does, what it explicitly never does
type: reference
---

# Sloth

**Summary**: Terminal-based **passive** network monitor for Linux, written in C99. Reads `/proc`, `/sys`, netlink, and a pcap stream — never injects, scans, or modifies kernel state.

**Sources**: `CLAUDE.md`, `docs/views/README.md`, all `docs/views/*.md`.

**Last updated**: 2026-05-25.

---

## What sloth surfaces

- **24 ncurses views** organised into observation, synthesis, and WiFi-SIGINT groups — see [[views-catalog]].
- **Six alert rules** with embedded threat-intel matching — see [[alerts]].
- **Per-alert pcap dumps** when `--pcap-dir` is set — see [[pcap-export]].
- **Optional JSONL forensic log** for downstream tooling.
- **Composite dashboard** that tiles seven bands into one terminal — see [[dashboard]].

## What sloth never does

- No packet injection. No active scanning. No kernel-state modification.
- No mocks of real-data interfaces in tests; the fake platform in `tests/fake_platform.c` lives there for a reason.
- No coloured row backgrounds in the TUI — see [[ip-palette]].

## Binaries

- `sloth` — main binary.
- `sloth_test` — test binary, ~1664 assertions, must always be green.

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
- [[alerts]] — alert engine + the six rules.
- [[dashboard]] — composite view layout.
