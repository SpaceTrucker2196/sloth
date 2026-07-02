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

---

## 2026-05-25 — Mission §4 amendment: read-only local data socket

**Source**: `MISSION.md` §4 ("out of scope" list).

**Change**: replaced the blanket "no REST API or remote-control
surface" bullet with a stricter two-paragraph rule. The hard ban now
targets **control** surfaces specifically (no command channel, no RPC,
no remote configuration, no plugin loader, no shell-out). A
**read-only local data socket** (UNIX domain or `127.0.0.1`) that
mirrors the JSONL stream is now explicitly **in scope** as a
`tail -f`-style consumer hook for local SIEM forwarders.

**Why**: JSONL files are clunky for in-process tooling and force
filesystem polling. A read-only socket gives downstream tools a clean
hookup without ever giving sloth the ability to be told what to do.
The mission's passive-only spirit is preserved — there are no verbs
on the socket; you can only read.

**Not implemented yet**: this amendment opens the door. The socket
itself is future work — needs a `--data-socket PATH` flag, a writer
loop in `src/jsonl.c` (or a new `src/data_socket.c`), and a connection
test in the test suite.

---

## 2026-05-26 — Mutation-testing wiki page

**Source**: GitHub issue #4 ("Add a mutation-testing harness to
validate the test oracle"), `.github/scripts/mutate.py`,
`docs/dark-factory.md` §3.3.

**Created pages**:

- [mutation-testing.md](mutation-testing.md) — operator reference,
  how to read the report, what to do with each surviving mutant
  (real gap / equivalent mutant / dead code), implementation notes
  (force-rebuild, sandbox isolation), target priorities.

**Index updates**: added a "Factory infrastructure" section under
[[index]] holding the new page.

**Why**: closes the loop the dark-factory pattern doc opens — §3.3
states "if the test suite is 'yeah it mostly catches things,' you
are still at Level 3 — the human is the actual oracle." `make mutate`
is the mechanical check that the suite is stronger than that.
Baseline kill-rate for `src/alerts.c` lives in `PROGRESS.md`.

---

## 2026-07-02 — Version check-in architecture page

**Source**: issue #18 request for an automated version check-in and update
plan; `include/sloth.h`, `src/main.c`, `src/event_wake.c`,
`src/data_socket.c`, `README.md`, `RELEASE_v1.4.0.md`, `SECURITY.md`.

**Created pages**:

- [version-checkin.md](version-checkin.md) — architecture recommendation
  for periodic release checks, a separate staged self-update path, safety
  boundaries, implementation phases, and open questions.

**Index updates**: added [[version-checkin]] under "UI and infrastructure"
in [[index]].

**Why**: the issue explicitly asked for plan and architecture rather than
product code. The new page records a concrete design that fits sloth's
existing non-blocking main loop and passive-tool constraints, while still
laying out how a future source-download/build/install workflow could be
added with minimal interruption.
