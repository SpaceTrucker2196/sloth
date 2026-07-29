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
`agents/dark-factory.md` §3.3.

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

---

## 2026-07-02 — Version check-in phases 1-3 landed

**Source**: [[version-checkin]] recommendation; commits landing
`src/version.{c,h}`, `src/updater.{c,h}`, `examples/updater/`,
`SECURITY.md` rewrite.

**Created pages**:

- [manifest-format.md](manifest-format.md) — JSON schema for the
  manifest file that `--check-manifest` consumes.

**Index updates**: added [[manifest-format]] under "UI and infrastructure"
in [[index]].

**Doc updates**: [[version-checkin]] rewrote its "Recommended
implementation phases" section to mark phases 1–3 as landed and
phases 4–5 as deferred. `SECURITY.md` replaced its GitHub template with
a real supported-version policy, vulnerability reporting instructions,
and a pointer to `MISSION.md` for the passive-only guarantee.

**Why**: the design was already logged as an architecture proposal; this
entry records the first-code landing so a future reader can see when the
policy → module → checker sequence actually shipped and where the
follow-up phases are still open.

---

## 2026-07-14 — ICMP-tunnel detector (#40) JSONL field

**Source**: issue #40; commit adding `ALERT_TYPE_ICMP_TUNNEL` and the
`icmp_log_entry_t.payload_len` field.

**Doc updates**: [[jsonl-schema]] `icmp` record gained the additive
`plen` integer (payload bytes past the ICMP header) — the signal the new
`ICMP_TUNNEL` rule keys on. Additive per the schema-stability contract;
older records simply omit it.

**Index updates**: none (no new page).

**Why**: the JSONL schema is a downstream contract (MISSION §3), so a new
emitted field is logged even though it rode in on a detector change
rather than a dedicated schema revision.

## 2026-07-18 — Change-only snapshot emission (#42)

**Source**: issue #42 (log volume); commit adding a change cache to
`src/jsonl.c` that suppresses re-emission of unchanged snapshot rows.

**Doc updates**: [[jsonl-schema]] "State snapshot record types" gained a
**Change-only emission** paragraph. Rows are now written only when new,
changed, or `JSONL_HEARTBEAT_SECS` (300 s) stale — no schema/field change,
purely an emission-cadence change. `pnl_client` and `seqnum_client` are
converted first (≈45 % of production volume was unchanged rows); other
snapshot types follow the same pattern later.

**Index updates**: none (no new page).

**Why**: the emission cadence is part of the downstream JSONL contract —
consumers that assumed one row per entity per tick need to know the stream
is now change-driven with a 5-minute heartbeat floor, even though the
per-row fields are unchanged.

## 2026-07-28 — Data-socket clients get a change-cache baseline (#47)

**Source**: issue #47 (field report from a production appliance);
commit resetting the #42 change cache when `data_socket_tick()` accepts
a client.

**Doc updates**: [[jsonl-schema]] "Change-only emission" gained a
paragraph covering the data-socket case. Before this, the cache reset on
file-sink (re)open only, so a socket client connecting mid-run saw only
entities that changed *after* it connected — steady-state rows stayed
invisible to it until their next 5-minute heartbeat. The reset now also
fires per accept.

**Index updates**: none (no new page).

**Why**: same reason as the #42 entry — emission cadence is part of the
downstream contract. A consumer that reconnects needs to know it will be
re-synced with a full baseline rather than having to wait out a
heartbeat, since that determines whether reconnect is a viable re-sync
strategy at all.

## 2026-07-28 — UX personas + wifi-surveyor suite (and its first fix, #51)

**Source**: a request for a UX test persona simulating a WiFi security
survey; commit adding `docs/personas/`, and #51 which the suite's own
scoring turned up.

**Doc updates**: new `docs/personas/` tree — a README defining the
verdict scheme and `wifi-surveyor.md`, an eleven-scenario suite scored
against the tree. [[index]] gained a Reference entry pointing at it.
No wiki page was modified; the suite cites `docs/views/*` and `src/*`
as sources the same way a wiki page does, but it carries *results*, so
it is a fixture rather than a concept page.

**Index updates**: [[index]] § Reference.

**Why**: `make test` proves the parsers do what they say; it cannot say
whether what they say is what the operator needed. The suite is the
inspection step for that second question, and it earned its keep
immediately — scoring S2.1 surfaced that the evil-twin rule reports a
cross-vendor range extender as a CRIT rogue AP, which shipped as #51.
S2.1 is rescored `WRONG` → `PARTIAL`; the residual case (APs that emit
no 802.11k Neighbor Reports) is documented in the scenario rather than
closed.

## 2026-07-28 — Operator-designated networks (#52)

**Source**: issue #52, itself raised by scoring the [wifi-surveyor
persona suite](../personas/wifi-surveyor.md) scenarios S4.1 / S4.2;
commit adding `src/ownership.c` and the `MY_NET_RECON` rule.

**Doc updates**: `docs/views/alerts.md` gained a `MY_NET_RECON` row and
severity-scoping notes on `DEAUTH_FLOOD` / `AUTH_FLOOD`. README gained a
"Designating your own network" section. The persona suite rescored S4.1
`FAIL` → `PASS` and S4.2 `PARTIAL` → `PASS`, closing Q4.

**Index updates**: none (no new page).

**Why**: this is sloth's first **operator-supplied context** input —
previously the tool took observations and display preferences only,
never an assertion about the world. Worth recording as an architectural
first: the known-device roster (G4 in the persona doc) is the same shape
and should extend `ownership.c` rather than introduce a second
mechanism. The passive guarantee is untouched — a designation is a
label, and nothing is transmitted.

## 2026-07-28 — SQLite sink (#42) schema reference

**Source**: issue #42; commits 61700b5 (schema v1 + state bucket),
01dc317 (protocol flows), ec4a9b7 (event bucket), 78305dc (retention +
size ceiling), 376ab88 (KARMA / rogue-RADIUS evidence).

**Doc updates**: new [[sqlite-schema]] page — why the sink exists
against the measured 38 GB/day, the 38-table layout by tier, the upsert
semantics that make the file trustworthy, retention tiers, the MISSION
§2 guardrails and what "identifier versus secret" means in practice,
plus query recipes. README gained `--db` sections covering the flags.

**Index updates**: [[index]] § Reference, next to [[jsonl-schema]].

**Why**: the sink is a second durable contract alongside the JSONL
schema, and the parts a reader most needs are the ones not visible in
the DDL — that `assocs.source` is strongest-first so a naive MAX
silently downgrades confirmed handshakes; that detector evidence sits in
the finding tier so it cannot expire before the alert it justifies; that
SNMP community strings are deliberately absent even though the wire
format emits them; and the `auto_vacuum` caveat for files created before
that pragma landed.

## 2026-07-28 — Survey sessions and schema v2 (#56)

**Source**: issue #56 (persona S5.2); commit adding the `sessions`
table, `db_new_since()`, and a *New since last survey* report section.

**Doc updates**: [[sqlite-schema]] gained a **Survey sessions** section
and a rewritten schema-version note; the page is retitled schema v2 /
40 tables. README gained the repeat-survey paragraph. The persona suite
rescored S5.2 `PARTIAL` → `PASS`.

**Index updates**: none.

**Why**: the version note is the part worth recording. v2 exists
because `probe_clients.presence` (#53) added a *column* to an existing
table without a bump — and `CREATE TABLE IF NOT EXISTS` cannot apply
that, so v1 files failed on a confusing SQL error instead of the clear
version message. The rule is now written down: new tables are safe
without a bump, new columns on existing tables are not. The version
check also moved ahead of schema application so the clear message wins.
