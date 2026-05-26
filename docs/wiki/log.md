# Wiki log

Append-only record of wiki operations. Newest entries at the bottom.

---

## 2026-05-25 — Initial ingest (priming the wiki)

**Source**: `docs/views/*.md` (24 per-view docs) + `docs/views/README.md` + repo-root `CLAUDE.md`.

**Created pages**:

- [sloth.md](sloth.md) — top-level project overview.
- [architecture.md](architecture.md) — code-tree layout and seams.
- [views-catalog.md](views-catalog.md) — keybinding map for all 24 views.
- [dashboard.md](dashboard.md) — seven-band composite layout.
- [alerts.md](alerts.md) — alert engine + the six rules.
- [ja3-fingerprinting.md](ja3-fingerprinting.md) — TLS ClientHello fingerprinting primitive.
- [threat-intel.md](threat-intel.md) — embedded IOC matcher.
- [beacon-detection.md](beacon-detection.md) — periodicity detector for C2.
- [wifi-sigint.md](wifi-sigint.md) — overview of the v1.1 SIGINT view set.
- [mac-randomisation.md](mac-randomisation.md) — 802.11 seqnum deanonymisation.
- [ip-palette.md](ip-palette.md) — colour conventions and TUI rules.
- [platform-vtable.md](platform-vtable.md) — the kernel seam.
- [pcap-export.md](pcap-export.md) — three pcap-export paths.
- [attack-map.md](attack-map.md) — threat-to-view map.
- [index.md](index.md) — table of contents.

**Notes**:

- Source view docs in `docs/views/` left untouched (treated as
  immutable per `docs/CLAUDE.md`).
- Wiki pages cross-link concept-to-concept with `[[wiki-link]]` and
  point back to source docs with normal relative links
  (`../views/foo.md`).
- No per-view 1:1 mirror page — `views-catalog.md` plus the concept
  pages cover the synthesis-level material; the per-view docs remain
  the source of truth for protocol-level detail.
