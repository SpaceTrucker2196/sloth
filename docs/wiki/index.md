# Wiki index

Table of contents for the sloth wiki. Pages are concept-oriented; raw
per-view documentation lives in `../views/` and is treated as immutable
source material.

## Start here

- [[sloth]] — what sloth is, what it explicitly never does.
- [[architecture]] — code-tree layout and the seams between layers.
- [[views-catalog]] — keybinding-to-view map for all 24 views.
- [[dashboard]] — the seven-band composite view.

## Engines

- [[alerts]] — alert engine internals and the six rules.
- [[beacon-detection]] — periodicity detector for C2 / implants.
- [[threat-intel]] — embedded IOC matcher.
- [[ja3-fingerprinting]] — TLS ClientHello fingerprinting.

## WiFi SIGINT

- [[wifi-sigint]] — overview of the v1.1 SIGINT view set.
- [[mac-randomisation]] — the 802.11 seqnum deanonymisation primitive.

## UI and infrastructure

- [[ip-palette]] — colour conventions and TUI rules.
- [[platform-vtable]] — the kernel seam (`platform_ops_t`).
- [[pcap-export]] — per-alert, manual, and per-EAPOL-handshake pcap.
- [[jsonl-schema]] — wire format for `-o FILE` and `--data-socket SPEC`.

## Reference

- [[attack-map]] — threat class → entry-point view.

## Source material

Raw source documents (treat as immutable):

- `../views/*.md` — per-view deep dives (24 files).
- `../views/README.md` — index of per-view docs.
- `../../CLAUDE.md` — project conventions and discipline rules.

## Maintenance

- [log.md](log.md) — append-only record of wiki operations.
- All page names are lowercase with hyphens (e.g. `mac-randomisation.md`).
- Cross-link with `[[page-name]]` wherever a concept is referenced.
