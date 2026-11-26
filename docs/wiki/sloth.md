---
name: sloth
description: Top-level project overview — what sloth is (Citizen SIGINT), what it does, what it explicitly never does
type: reference
---

# Sloth

**Summary**: Sloth is an open intelligence tool for RF signals intelligence: **Citizen Signals Intelligence (Citizen SIGINT)**. It is receive-only. It lets a private citizen see and understand the radio spectrum around them — Wi-Fi, Bluetooth and BLE, ADS-B, APRS, GNSS, SDR sweeps — and the host network the sensor sits on. It runs on Linux and is written in C99. It never injects a frame onto a network it monitors, and it reports radios, not people (`MISSION.md` §2).

**Sources**: `MISSION.md`, `CLAUDE.md`, `include/sloth_views.def`, `include/sloth_alerts.def`, `packaging/systemd/`, `Makefile`.

**Last updated**: 2026-11-26 (the Citizen SIGINT mission, operator 2026-11-26: summary, binaries and the never-does list rewritten from the tree at v1.8.7); 2026-10-19.

---

## What sloth surfaces

- **<!-- count:views -->38<!-- /count --> ncurses views** (`VIEW_COUNT`, one per row of `include/sloth_views.def`) organised into observation, synthesis, Wi-Fi SIGINT and other-radio groups — see [[views-catalog]]. They are `sloth-wifi`'s (`sloth` is a symlink to it); the second daemon, `sloth-rf`, is headless ([ADR 0010](adr/0010-wifi-rf-daemons.md)) and is read in [[slothweb]].
- **<!-- count:rules -->101<!-- /count --> alert rules** (one per `ALERT_TYPE_*`, one per row of `include/sloth_alerts.def`) — see [[alerts]]. Each has a written, cited assessment ([Alert assessments](alert-assessments/README.md)). The threat-intel matcher among them ships a **synthetic demo IOC list**, not a feed — see [[threat-intel]].
- **Finding quality and coverage** — completeness, latency, corroboration and source state on each finding, and which rules can see anything in the present configuration — see [[coverage-assessment]].
- **Per-alert pcap dumps** when `--pcap-dir` is set — see [[pcap-export]].
- **JSONL stream and SQLite stores** for downstream tooling — see [[jsonl-schema]], [[sqlite-schema]].
- **Written products**: the posture report, the exposure report, preflight, the handoff packet — see [[posture-report]], [[exposure-report]], [[preflight]], [[handoff]].
- **Composite dashboard** that tiles seven bands into one terminal — see [[dashboard]].

## What sloth never does

- **No injection.** No frame onto a monitored network, under any flag. Optional network-using services (`--allow-active`, a routable data socket) are off by default and announced; `--hop` retunes only sloth's own receiver. See [[what-sloth-does]] for the full list.
- **No decryption and no key recovery** of anything it captured.
- **No statement about a person.** Sloth reports a device's presence, its technical behaviour and its position or movement relative to the sensor, never who uses it or what they do.
- No mocks of real-data interfaces in tests; the fake platform in `tests/fake_platform.c` lives there for a reason.
- No coloured row backgrounds in the TUI — see [[ip-palette]].

The one sloth-family program that transmits is `sloth-va`, which connects only to the operator's own listed Victron devices and is kept out of the sensor ([ADR 0011](adr/0011-sloth-va-transmits.md), [[victron]]).

## Binaries

- `sloth-wifi` (and `sloth`, a symlink to it) — Wi-Fi monitor, IP capture, BLE, the views.
- `sloth-rf` — headless reader for ADS-B, APRS, rtl_433, Victron and GNSS.
- `sloth-ble-scan`, `sloth-sdrsweep`, `sloth-va` — Linux helpers with their own units ([[deployment]]).
- `sloth_test` — test binary, must always be green. Built the way
  `sloth` ships (#116): `WITH_NCURSES` + `WITH_PCAP`, the real renderer
  drawing into an offscreen ncurses screen, and the capture-path suite
  (#95) in the same run, so the sanitizers see frames arrive through
  libpcap's own reader and the real `on_packet()` callback.
- `sloth_test_noflags` — the same suite without ncurses or pcap.
  Link-only: it proves the `#ifndef` halves still build, and is never
  run. (`sloth_test_pcap`, the separate capture-path binary, is gone;
  `make test-capture-path` is an alias for `make test` for one release.)

`slothweb` and `slothweb-mcp` are sloth-mesh's; `sloth-comintd` is
sloth-comint's ([ADR 0001](adr/0001-three-repos.md)).

## Architecture entry points

- `include/sloth.h` — central header with shared structs and the `view_t` enum.
- `src/main.c` — `sloth-wifi`'s CLI, signal handlers, poll loop; `src/rf/` — `sloth-rf`'s.
- `src/platform/linux*.c` — kernel-facing backends behind a vtable; see [[platform-vtable]].
- `src/capture/capture.c` — libpcap thread that dispatches to per-protocol parsers.
- `src/views/*.c` — one file per view; see [[views-catalog]].

## Threat coverage in one glance

See [[attack-map]] for the full protocol-to-threat map, [[wifi-sigint]] for the
802.11-specific SIGINT primitives (PMKID, 4-way handshake, PNL, seqnum),
[[mac-randomisation]] for correlation across MAC rotations and its limits,
[[ja3-fingerprinting]] for the TLS client-fingerprint primitive, and
[[beacon-detection]] for the C2 periodicity detector.

## Related pages

- [[what-sloth-does]] — the whole tool on one screen.
- [[architecture]] — code-tree layout and seams.
- [[views-catalog]] — full keybinding-to-view map.
- [[alerts]] — alert engine and its rules (one per `ALERT_TYPE_*`).
- [[dashboard]] — composite view layout.
