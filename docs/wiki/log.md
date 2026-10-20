# Wiki log

Append-only record of wiki operations. Newest entries at the bottom.

---

## 2026-05-25 — Initial ingest (priming the wiki)

**Source**: `docs/views/*.md` (24 per-view docs) + `docs/views/README.md` + repo-root `CLAUDE.md`.

**Created pages**:

- [sloth.md](sloth.md) — top-level project overview.
- [architecture.md](architecture.md) — code-tree layout and seams.
- [views-catalog.md](views-catalog.md) — keybinding map for all 35 views.
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

## 2026-07-28 — Headless operation and the poll-loop spin (#50)

**Source**: issue #50; commit adding `--headless`, `--no-color` /
`NO_COLOR`, and the `tui_poll_key` tty guard.

**Doc updates**: [[ip-palette]] gained a **Colour policy and headless
operation** section covering the split between "no colour" and "no
drawing". README gained a Headless operation section including the
spin-fix note. The persona suite's S1.3 caveat is removed.

**Index updates**: none.

**Why**: the issue as filed was about escape sequences in the journal,
and the fix for that is `--headless`. But measuring it turned up a
larger defect behind the same symptom: with stdin at EOF (systemd,
`< /dev/null`) `select()` reported stdin readable every time, so the
refresh interval never applied and the loop spun — ~76 000 redraws in
two seconds against an intended ~10, burning a core as well as flooding
the journal. Recorded here because the fix (`isatty` guard in
`tui_poll_key`) benefits interactive and `--no-color` runs too, not
only `--headless`, and a future reader tracing the flag will otherwise
miss why the guard exists.

## 2026-09-07 — FragAttacks tracker view (#75 slice 5)

**Source**: issue #75; commit adding `VIEW_FRAGATTACK` / `[c]`,
`src/views/fragattack.c`, `frag_snapshot()`.

**Doc updates**: [[fragattacks]] gained a **The view** section and its
intro/CVE-count corrected from "six" to "eight of twelve, seven
detectors" — stale since slice 4 landed and only now noticed while
touching the page. New per-view doc
[`docs/views/fragattack.md`](../views/fragattack.md).

**Index updates**: [[fragattacks]] bullet updated to mention the view
and the corrected count.

**Why**: seven detectors had been shipping since slice 1 with no
operator-visible surface short of grepping alert history. The view adds
no new data source — it mirrors `src/fragattack.c`'s existing per-BSS
counters — and deliberately adds no SQLite table or evidence blob,
since `src/alert_pcap.c` already carries better forensic evidence than
a truncated blob would. `[c]` is the key because `[f]` went to #73's
Research view first and was, by the time slice 5 landed, the only
letter still free in the global switch.

---

## 2026-09-15 — WPS vendor-string leakage (#77 slice)

**Source**: issue #77 ("Attack-hardware fingerprint layer"); the
buildable-without-hardware slice of it. `src/beacon_snoop.c`,
`src/beacon_snoop.h`, `include/sloth.h`, `src/jsonl.c`,
`src/views/beacon.c`.

**Doc updates**: [`docs/views/beacons.md`](../views/beacons.md) gained a
"WPS vendor-string leakage (#77)" section. [[jsonl-schema]]'s `beacon`
row gained the four new additive fields.

**Why**: #77 asked for a curated attack-hardware fingerprint corpus
(specific Cisco/Aruba/Ubiquiti/MikroTik stacks, Pineapple/Marauder/
eaphammer captures) and a pcap-fixture test plan — both blocked, the
first on "empirical fact about a binary" grounds `tool_fingerprint.c`
already documents, the second on `agents/AGENTS.md`'s no-pcap-fixtures
rule. The one bullet in the issue that needed neither — WPS Manufacturer/
Model Name/Model Number/Serial Number attribute parsing — is spec-defined
(WFA WPS 2.0 §12) and hand-testable from TLV bytes like every other
parser in this file. Shipped that slice only; see the issue-77 triage
comment for the rest.

---

## 2026-09-15 — Beacon IE-ordering fingerprint (#77 slice)

**Source**: issue #77, bullet 1 ("Beacon IE ordering fingerprint") — the
observable half. `src/beacon_snoop.c`, `include/sloth.h`, `src/jsonl.c`.

**Doc updates**: [`docs/views/beacons.md`](../views/beacons.md) gained an
"IE-ordering fingerprint (#77)" section. [[jsonl-schema]]'s `beacon` row
gained `ie_order_hash` / `ie_order_count`. [[tool-fingerprints]]'
"Adding a tool" asks captures to record the new hash.

**Why**: the bullet asks for an IE-order hash per BSSID matched against a
curated table of vendor stacks. The hash is spec-shaped (IEEE 802.11-2020
§9.3.3.2 fixes element order; Vanhoef et al., AsiaCCS 2016, established
presence/order as a device fingerprint) and hand-testable; the table is
not — it needs captures from each stack, the same wall
`tool_fingerprint.c` documents. Shipped the hash as a plain observable;
no signature field, no verdict. It also gives the "vendor-IE consistency
drift" follow-up something to compare.

---

## 2026-09-18 — Beacon TBTT jitter observable (#77 slice)

**Source**: issue #77, bullet 2 ("Beacon interval jitter") — the
observable half. `src/beacon_snoop.{c,h}`, `include/sloth.h`,
`src/jsonl.c`.

**Doc updates**: [`docs/views/beacons.md`](../views/beacons.md) gained a
"Beacon TBTT jitter (#77)" section. [[jsonl-schema]]'s `beacon` row
gained `tbtt_jitter_us` / `tbtt_jitter_samples` / `tbtt_jitter_resets`.

**Why**: the bullet asks for a rolling stddev of beacon inter-arrival
per BSSID. Measured from the receiver it would be worthless here — no
radiotap TSFT is guaranteed, the radio hops, and frames are lost. The
beacon body already carries the answer: IEEE 802.11-2020 §11.1.3
schedules TBTTs at whole multiples of the Beacon Interval and
§9.3.3.2 order 1 / §9.4.1.10 puts the transmitter's own TSF in every
beacon, so the residual against the nearest multiple is the AP's own
medium-access deferral on the AP's clock. The timestamp field was
previously not parsed at all — `beacon_parse` skipped bytes 24-31.

Shipped as measurement only. The issue's "8-40 TU = Marauder" figure
has no source that could be verified here, and `agents/AGENTS.md`
requires detectors to cite theirs; the measurement is spec-grounded,
the attribution is not. No alert rule, no TUI row, no signature row in
`tool_fingerprint.c`, and no `--db` column (a schema bump invalidates
every prior database file — the `phy_confirmed`/#60f precedent).

## 2026-09-21 — Data-socket record framing under backpressure (#93)

**Source**: issue #93 (external CISO/GRC review, finding F11).
`src/data_socket.{c,h}`, `tests/test_data_socket.c`.

**Doc updates**: [[jsonl-schema]] "Backpressure" became "Delivery:
whole records or none", with the overflow / stall / error table, the
loss-detection rule, and the EOF-fragment rule under "Framing"; new
`socket_gap` (socket-only) record section. README `--data-socket`
bullet, `docs/streaming.html`, `examples/consumer/README.md` and the
`sloth-stream.py` docstring said a slow client "loses lines"; they now
describe the queue.

**Index updates**: none (no new page).

**Why**: the writer sent the payload and its `\n` as two `send()`
calls and kept no state between them. An `EAGAIN` on the delimiter
left the client connected with no record of the missing byte, so the
next record was glued on — `{"a":1}{"b":2}\n`, which no JSONL parser
accepts. It also read `errno` after a *positive* short write, where
errno is stale, and could keep a client with half a record on the wire.
Each client now owns a queue of complete `payload\n` spans written from
a byte offset; short writes and `EINTR` retry, `EAGAIN` waits for the
next emit or tick, anything else closes. Overflow (512 KiB) drops only
whole records not yet started, and a client that accepts no bytes for
30 s is closed — a reader that stops can hold a TCP window shut without
ever producing `EPIPE`, so waiting for one is not a policy.

The loss signal is a new record type rather than a field on every
record: a per-connection `seq` on each line would give each client a
different byte stream and add a field that has no meaning in `-o FILE`.
`socket_gap` appears only after an actual drop, only on that
connection, so the schema change is additive and a healthy consumer
never sees it.

## 2026-09-22 — Private export files and reported write failures (#87)

**Source**: issue #87 (external CISO/GRC review, finding F05).
`src/secure_file.{c,h}` (new), `src/eapol_log.c`, `src/alert_pcap.c`,
`src/jsonl.c`, `src/db.c`, `src/pcap_write.c`, `src/main.c`,
`src/views/eapol.c`; tests in `test_eapol_log.c`, `test_alert_pcap.c`,
`test_jsonl.c`, `test_db.c`, `test_pcap_write.c`.

**Doc updates**: [[pcap-export]] gained "Permissions and failures" and
lost two stale claims (per-alert hits never appended to one file, and
`pcap_write.c` never handled all three paths). [[jsonl-schema]],
[[sqlite-schema]] and [[posture-report]] state the 0600 rule and the
refusal behaviour. `docs/views/eapol.md` gained "Export handling"; the
README Output section a file-permissions paragraph, and the `--db`
example now reads the 0600 file with `sudo`.

**Index updates**: none (no new page).

**Why**: the EAPOL directory was `mkdir(…, 0755)` and every file a plain
`fopen()`, so under the usual 022 umask a fresh PMKID export was
world-readable; SQLite likewise creates `0644 & ~umask` and copies that
to the WAL. Directory creation and most write errors were ignored. Now
dirs are 0700 and files 0600 by descriptor (`O_NOFOLLOW|O_CLOEXEC`,
relative to a directory fd validated once at startup), and an existing
path is validated and refused — never `chmod`ed — when it is a symlink,
foreign-owned, multiply linked, or group/other accessible. Each artifact
has a deliberate create mode: `eapol.22000` and `-o` append; handshake
pcaps are atomically replaced; alert and Packets-view pcaps are
exclusive with a numeric suffix; reports are validated then truncated.
Failures print once to stderr and are counted (EAPOL view shows it).

**Not done here** (owner decision): a separate opt-in for collecting
crackable material with a short default retention, and an explicit
group-sharing policy. Today a group bit is simply refused.

## 2026-09-23 — EAPOL handshake attempts and the 22000 message pair (#97)

**Source**: issue #97 (external CISO/GRC review, technical appendix T12
and T13). `include/eapol_log.h`, `include/sloth.h`,
`include/assoc_track.h`, `src/eapol_log.c`, `src/jsonl.c`; tests in
`test_eapol_log.c`.

**Doc updates**: [[jsonl-schema]] `eapol` record gained three additive
fields — `handshake_progress`, `replay_counter_ok`, `assoc_evidence` —
and the row now says what `handshake_complete` does and does not mean.
`docs/views/eapol.md` gained "Attempts, not flags" and "Message-pair
byte"; `docs/views/assoc.md`'s evidence table now names M3 rather than
"M2 with prior M1" as the EAPOL source.

**Index updates**: none (no new page).

**Why**: the pending record was keyed `(BSSID, STA)` with `m1_seen` /
`m2_seen`, no replay counter and no age bound, so a cached M1 paired
with any later M2 — across associations and across rekeys — and a new
M1 left the previous attempt's M2 and PMKID underneath it. That pair
was then handed to `assoc_observe(ASSOC_SRC_EAPOL, …)`, calling a
half-exchange an association. The record now holds one bounded
*attempt*: M1 and M2 pair only on equal Key Replay Counters
(802.11-2020 §12.7.2) within `EAPOL_PAIR_WINDOW_S`, a new M1 discards
everything that depended on the old ANonce, message role must agree
with frame direction, and association promotion moved to M3 — the AP
installing a key, which is the first point the authenticator commits.

The export's trailing message-pair byte was the literal `02`, which is
hashcat's M2+M3 category; sloth builds M1+M2 with the EAPOL blob from
M2, which is `00`. It is now derived by `eapol_message_pair()` from the
pair kind plus whether the replay counters were actually compared, so
bit 7 ("not replaycount checked") reflects what the tool did.

**Not done here**: validating the export against `hcxpcapngtool` and
confirming a known-key fixture cracks. There is no owned capture on the
build host and MISSION §2.2 forbids sloth running a cracker, so the
bit values are asserted against hashcat's published table and the
offline lab validation stays open on #97.

## 2026-09-23 — Alert incident lifecycle (#98)

**Source**: issue #98 (external CISO/GRC review, technical appendix
T14). `src/alerts.c`, `src/jsonl.{c,h}`, `include/sloth.h`; tests in
`test_alerts.c` and `test_data_socket.c`.

**Doc updates**: [[jsonl-schema]] gained the `alert.create` /
`alert.update` / `alert.escalate` / `alert.resolve` section (field
table, the material-change predicate, the resolve rule and its
reasons), `incident_id` on the `alert` record, and a plain statement of
what `count` measures; the common-envelope `type` row and the
versioning section were updated. `docs/views/alerts.md` gained an
"Incident lifecycle" section and a counter/timestamp table, and the
lines describing the engine, the `n` column and the `c` key were
corrected — they described emit-on-new-key-only behaviour.
`docs/streaming.html` gained an `alert.escalate` card and the "the
`alert` record is written only when the key is new" note.
`examples/consumer/README.md` and `sloth-stream.py` gained a lifecycle
section, a formatter for the four new types, and the warning that
`--type alert` alone never sees an escalation.

**Index updates**: none (no new page).

**Why**: `fire()` bumped `count`, refreshed the timestamp, replaced
detail and severity, then returned early when the key already existed —
and `jsonl_emit_alert()` ran only for new keys. A WARN→CRIT escalation
therefore changed sloth's engine and emitted nothing, so a consumer
paging on CRIT only ever held the WARN record written when the key was
created. `count` had the matching problem in the other direction: it
incremented on every evaluation tick of a retained condition, measuring
rule polls while being presented as an occurrence count.

An incident — one continuous run of a dedup key — now opens with
`alert.create`, carries one `incident_id` through every escalate and
update, and closes with exactly one `alert.resolve`. What is emitted is
a *material* change: any severity move (never throttled, in either
direction), or a changed `detail` at most once per 60 s. An evaluation
that re-renders identical evidence emits nothing, so a condition held
across 100 polls is one create and silence — and `observations` counts
only the evaluations whose evidence moved, beside `evaluations` (and
the unchanged `count`) for the rule ticks.

Resolve keys on `last_evaluated`, not `last_observed`, after 300 s: a
rule that stops firing is one whose evidence aged out of the source
ring, whereas a standing condition re-renders the same detail forever
and keying on observation would resolve and immediately re-create it
every five minutes. 300 s matches `JSONL_HEARTBEAT_SECS`. Durations run
on `CLOCK_MONOTONIC` through the #88 seam in `src/flood_window.c`;
every exported timestamp stays wall clock, because those are evidence.
A resolved incident stays in the TUI — the operator's history is not
the stream's business — but is evicted first under `MAX_ALERTS`
pressure, and an evicted live incident is resolved on the way out.

Everything is additive: four new record types, one new field on
`alert`, no field removed or repurposed. The `--db` `alerts` table is
untouched and `DB_SCHEMA_VERSION` stays 4.

**Not done here**: the issue's fourth Fix bullet ("revisit dedup keys
per F06/F07") and its third regression ("two distinct twin pairs under
one SSID: two incidents"). F06 was already done in #88; F07 is issue
#89 and still open, and `rule_evil_twin` still keys on `twin:<ssid>`,
so the two pairs merge before the lifecycle layer sees them. The layer
never merges across keys and will report two incidents the moment the
key distinguishes them; `test_lifecycle_two_twin_pairs_one_ssid_still_merge_see_89`
pins the current behaviour so #89 flips it deliberately.

## 2026-09-23 — Sensor health: capture-worker exits, pcap drops, table evictions (#91 slices 2-3)

**Source**: issue #91 (external CISO/GRC review, F09), slices 2 and 3 of
a 4-slice plan; slice 1 (requested-vs-confirmed channel) shipped in
`509fa71`. `src/capture/capture.{c,h}`, `src/capture/probe.{c,h}`,
`src/sensor_health.{c,h}` (new), `src/jsonl.{c,h}`, `src/views/iface.c`,
`src/main.c`, `include/sloth.h`; tests in `test_capture.c`,
`test_sensor_health.c` (new), `test_state.c` and `test_jsonl.c`.

**Doc updates**: [[jsonl-schema]] gained the `sensor_health` record —
table row, full field list, the per-stream block, the monotonic-total
rule, the change-only signature and an explicit statement of which
tables the eviction tally does and does not cover.
`docs/views/interfaces.md` gained a "Sensor health strip" section with
the three liveness words, the exit-reason table, and the same coverage
caveat; the slice-1 section's forward reference to slices 2-4 was
replaced by it. `examples/consumer/README.md` and `sloth-stream.py`
gained a `sensor_health` section, a formatter, and the note that it is
the one record type a *silent* sensor still emits.

**Index updates**: none (no new page).

**Why**: "healthy with no detections" and "not observing" were the same
observation. Three separate paths produced it. Both capture workers loop
on `pcap_dispatch()` and `break` on a negative return, then simply
returned — the pcap handle stayed open, `capture_is_open()` kept saying
yes, and the tables stopped growing. On a channel-hopping radio an empty
dwell is *normal*, so a dead monitor thread was indistinguishable from a
quiet channel indefinitely. `pcap_stats()` was never called at all, so
NIC and libpcap buffer drops were invisible. And every bounded table
discards observations when full, silently, so a sensor at max occupancy
and a sensor on an empty segment produced the same empty delta.

Each worker now classifies why it stopped — `stopped` (requested),
`iface_gone`, `perm_lost`, `not_activated`, `error` — and publishes the
verdict with libpcap's raw text beside it. The classification is pure
(`capture_classify_exit()`, above the `WITH_PCAP` guard like
`capture_activate_failed()` before it), so it is unit-tested from
hand-written return codes and error strings with no handle and no radio.
A requested stop wins over any error text, because `pcap_breakloop()`
makes the pending dispatch fail and reporting that as a fault would cry
wolf on every clean shutdown. `PCAP_ERROR` is split by case-insensitive
substring on libpcap's wording, which is not a kernel contract — an
unrecognised message degrades to `error` rather than being guessed into
a bucket, and `_exit_detail` carries the raw string so a consumer is
never left with only sloth's classification.

Liveness is `run_flag && exit_reason == none`, deliberately a
conjunction: a dead worker leaves the run flag *set*, because it broke
out of its loop rather than being asked to stop. `_open` 1 with
`_running` 0 is exactly the failure that used to be invisible.

`pcap_stats()` is polled once per tick. Sloth accumulates its own
lifetime totals from the per-tick deltas rather than echoing libpcap's
32-bit counters: a sample below the previous one is read as a counter
reset (the new value becomes the delta), so the exported total is
monotonic and a consumer differencing two samples never sees a negative
rate. A true 2^32 wrap would under-count by one wrap period — the
deliberate trade for keeping the common case exact. The first sample is
taken as both total and first delta rather than discarded as a baseline,
because the startup window is where an undersized buffer drops hardest.

`sensor_health` is the stream's only singleton record: one line per tick
about the collector, not one per table row. It has to be, since the
whole point is to say something when no other record exists. It is
change-only on the shared snapshot cache, but the signature covers
liveness, exit reasons, the channel pair, retune failures, the
cumulative drop counters and the eviction total — and deliberately not
`recv` or any delta. `recv` climbs every tick on a working sensor, so
signing over it would mean a line per second forever and the suppression
would be decorative. A drop counter moving is news; a packet counter
moving is not. Healthy sensors emit one line per 300 s heartbeat.

The TUI strip in the interface view follows the same rule in the other
direction: everything after the two liveness words is a fault and
appears only when non-zero, so a healthy sensor renders exactly
`health: cap up  mon up`. A strip that printed `drop 0  evict 0` every
second would train the operator to stop reading it.

Everything is additive — one new record type, no existing record, field
or name touched, `DB_SCHEMA_VERSION` unchanged (MISSION §4.3).

**Scope decision, flagged**: the eviction tally covers alerts, top
hosts, PNL clients, per-client PNL SSIDs, DHCP events, 802.1X EAP
sessions and the device table (which refuses a new entry rather than
evicting an old one — different mechanism, same meaning). It does
**not** cover the probe-client, beacon, seqnum, assoc or per-protocol
flow rings. The counted set is the one whose modules are in `TEST_SRCS`,
so every wired call site has a test that drives the real table past its
cap; the probe-client ring's eviction site lives in `src/capture/probe.c`,
which is compiled only under `WITH_PCAP` and is not in the test build, so
instrumenting it would have shipped untested wiring. Which tables are
covered is stated in both docs rather than left implicit, because a
tally that silently omits a table reads as "no loss" when it means "not
measured".

**Not done here**: slice 4 (benchmarking sequence correlation and
PNL-union at max occupancy) is out of scope for this change. The
issue's remaining hardware-dependent items stay open and are not
faked — the measured adapter/driver/kernel/band/width support matrix,
and comparing hopping against an independent reference receiver, both
need a radio this build host does not have. The dwell-servicing gap
(configured dwell != measured dwell, since dwell is only serviced when
the poll loop runs) and the monitor-specific frame counter tied to the
confirmed frequency are also untouched; the RF dwell heuristic still
attributes activity via `s->pkt_total`, the general capture counter.

---

## 2026-09-24 — #89 slice 1: evil-twin trust anchors removed

**Source**: issue #89 (external CISO/GRC review, F07), slice 1 of 3 per
the Captain's answers recorded on the issue 2026-09-24. Code:
`src/alerts.{c,h}`, `src/twins.c`, `src/views/{twins,beacon}.c`,
`src/jsonl.c`, `include/sloth.h`.

**Updated pages**:

- [alerts.md](alerts.md) — new "Severity vs confidence (#89)" section:
  the two axes, why most rules omit confidence, the two removed trust
  anchors, and the canonical pair-key shape.
- [jsonl-schema.md](jsonl-schema.md) — additive `confidence` on `alert`
  and the `alert.*` lifecycle records; additive `attributed` +
  `confidence` on `twin_episode`; the `real_bssid` / `twin_bssid`
  meanings now depend on `attributed`; canonical dedup-key note.
- [../views/alerts.md](../views/alerts.md) — `EVIL_TWIN` rule-table row.
- [../views/twins.md](../views/twins.md) — "Which half is the impostor"
  ranking, `?` glyph, Conf column, A/B headings.

**What changed in the detector**:

Three things, all removals of something the code treated as proof:

1. **An 802.11k neighbour report is no longer a suppressor.** It was an
   unauthenticated frame with veto power: an attacker advertising the AP
   it impersonated erased the finding. Now a confidence deduction that
   can demote a soft-signal severity and nothing more — a hard signal
   (attacker-tool OUI, BTM steer) is immune, so the attacker gets no
   severity lever.
2. **A matching vendor OUI is no longer a suppressor.** Three bytes the
   attacker writes. A same-OUI pair whose vendor-IE fingerprints
   contradict each other now fires; a same-OUI pair with no other signal
   stays quiet because it carries no evidence, which is a different fact
   from being trusted.
3. **RSSI no longer names the impostor.** It is a fact about distance,
   and in the commonest case it is backwards — the operator's own AP is
   the closest radio in the room. Unattributed pairs are ordered
   canonically and flagged `?`.

Plus: severity split from confidence (5..95 %, never 100), and the
canonical pair key so two candidate pairs under one SSID both survive.
The key shares #98's dedup/incident machinery rather than forking a
second scheme — it flips #98's own
`test_lifecycle_two_twin_pairs_one_ssid_*` assertion, which that issue
left pinned to the broken count with a note naming #89.

**Out of scope, deliberately**: the JSON inventory file, the
`--my-ssid`/`--my-bssid` flag merge and the inventory content hash are
slice 2; the UI separation of over-the-air impersonator vs neighbouring
AP vs wired-attached rogue is slice 3. `site` is left empty rather than
derived from an observed SSID or BSSID — the Captain's constraint on the
issue, and the exact defect class this slice removes.

**Not done here**: `attributed` and `confidence` are not persisted to the
`--db` `twin_episodes` table. That needs a `DB_SCHEMA_VERSION` bump and
a migration, which is more than this slice warrants; the canonical
BSSID ordering does however fix a real defect in that table's primary
key `(ssid, real_bssid, twin_bssid)`, which previously swapped — and so
inserted a duplicate row — whenever the pair's two RSSIs crossed.

---

## 2026-09-25 — `KARMA_AP` severity/confidence split (#90)

**Updated pages**: [alerts.md](alerts.md), [tool-fingerprints.md](tool-fingerprints.md).

`KARMA_AP` fired CRIT unconditionally once one BSSID beaconed ≥3
distinct SSIDs — a long-lived AP that legitimately renamed itself a
few times over a session scored the same as an active PineAP lure.
Applied the same severity/confidence split #89 gave `EVIL_TWIN`:

- Bare SSID count is now a WARN candidate (`- candidate,
  uncorroborated` in the detail); CRIT requires PNL overlap (the
  actual PineAP Beacon-Response mechanism), a shared-victim
  deauth-then-lure chain, or a verified tool signature match.
- **Deauth-then-lure now requires a shared victim.** The prior check
  (`karma_deauth_active()`, both in `src/alerts.c` and duplicated in
  `src/karma_detect.c`) fired on *any* recent flood anywhere in range,
  crediting every KARMA candidate with an unrelated victim's bad luck.
  `karma_deauth_lure_victim()` (`src/karma_detect.c`, shared by both
  callers) now requires a station deauthed off a *different* BSSID
  whose PNL asks for one of this candidate's SSIDs, or who has since
  associated with it.
- `tool_fingerprint_match()` gained an `unverified` out-param so a
  caller can tell a genuinely thin match from one the existing
  confidence cap was silently capping. The alert detail marks an
  UNVERIFIED match with a trailing `?`, matching the `[11?]`
  unconfirmed-retune convention #91 introduced in the interface view.
- PMKID observation stays informational only — it never escalated
  severity, and the fix makes that explicit in code comments: a
  legitimate 802.11r/PMK-caching exchange also produces one.

Additive-only: `confidence` reuses #89's `fire_conf()` engine plumbing
and JSONL field; no alert type id renamed, no `DB_SCHEMA_VERSION` bump
(`karma_candidates.score` keeps its column, just a corrected input to
the same formula).

---

## 2026-09-25 — approved-inventory trust anchor (#89 slice 2)

**Created page**: [inventory.md](inventory.md).
**Updated pages**: [index.md](index.md), [alerts.md](alerts.md),
[jsonl-schema.md](jsonl-schema.md),
[../views/alerts.md](../views/alerts.md),
[../views/twins.md](../views/twins.md).

Slice 1 removed three false trust anchors from the evil-twin rules and
left the detector with none at all: it could say "these two radios
disagree" and never "that one is not mine". This slice adds the anchor —
the operator's own `--inventory` JSON, the only trust input in the
family that does not arrive over the air.

- **Loader** (`src/inventory.c`): hand-rolled recursive descent, no new
  dependency. The tree had no JSON *parser* — `jsonl.c`/`formatter.c`
  only write and `updater.c`'s `scan_str_field` is a flat key scanner
  that cannot express `networks[].bssids[]` and would match `"ssid"`
  inside a string value. **All-or-nothing**: malformed JSON, wrong
  types, over-size, duplicate SSIDs/BSSIDs, bad MACs, control bytes,
  a NUL, deep nesting and `\u` each fail with a reason and a byte
  offset, loading nothing; a failed load leaves a previously valid
  inventory in force. `--inventory` exits non-zero rather than starting
  without the anchor the operator asked for.
- **Detection**: `INV_MISMATCH` is `+50` positive evidence and **hard**,
  so a spoofed 802.11k neighbour claim cannot erase it and a same-OUI
  clone becomes visible. `INV_APPROVED` on both halves makes the pair a
  non-candidate — a sole suppressor, deliberately: what #89 removed were
  suppressors sourced from frames the attacker writes, and the test is
  whether the adversary can reach the input. The weak/strong branch
  demotes an approved pair to WARN instead of silencing it, because a
  downgrade lane under one SSID is a finding whoever owns the radios.
- **Unconfigured is unchanged.** Pinned by
  `test_no_inventory_keeps_slice1_behaviour` — an operator who never
  writes a file must not silently lose detection.
- **Flag merge**: `--my-ssid` / `--my-bssid` (#52) are **unioned** with
  the file, never intersected. Adding a flag must not be able to
  manufacture a rogue out of the operator's own AP.
- **`site` is configuration only** (owner decision, 2026-09-25): `--site`
  or the file's `site` field, nothing else, flag wins, order-independent.
  No `site_source` field — there is no second source. A site derived
  from the uplink would re-key the canonical pair key on every roam and
  fragment one impersonator into several incidents.
- **Identity is the content hash**: 16 hex chars of SHA-256 over the
  file's bytes, stamped into every alert and export that consulted it as
  the additive `inventory` JSONL field. Emitted only by rules that
  actually read it. The `version` string is a label — two files may both
  claim one.
- `security_profile` is parsed, validated and displayed but **not**
  matched against the observed cipher: that needs a normalisation table
  between operator vocabulary and beacon-derived `enc` strings, and a
  wrong row in it alerts on the operator's own APs.

Additive JSONL only; no `DB_SCHEMA_VERSION` bump. Slice 3 (UI separation
of impersonator / neighbour / wired-attached, plus the controller
correlation hook) remains open.

---

## 2026-09-25 — Strict observation becomes the default (#84 slice 2)

**Updated pages**: [dashboard.md](dashboard.md), plus
[`docs/views/dns.md`](../views/dns.md),
[`docs/views/dashboard.md`](../views/dashboard.md) and the README.

Slice 1 built the seam — `dns_lookup_cached()` for names sloth already
observed, `dns_resolve()` as the single choke point for active reverse
resolution — and deliberately changed nothing that flowed through it.
This slice decides the policy, on the Captain's written instruction
recorded on the issue: **strict observation is the default.**

- `dns_resolver_set_enabled()` defaults **off**
  (`DNS_RESOLVER_DEFAULT_ENABLED`). `test_resolver_enabled_by_default`
  inverted to `test_resolver_disabled_by_default`; that assertion
  existed precisely to make this flip arrive as a deliberate edit
  rather than as drift, and this is that edit.
- **The worker thread is gated.** `dns_init()` no longer creates the
  resolver thread unconditionally. Since the worker owns the only
  `getnameinfo(3)` call in the tree, a strict run cannot resolve even by
  accident — "the DNS worker is never started" is now a property of the
  process, not a branch taken per lookup. It also no longer starts a
  *second* worker when called twice, which two test suites do.
- **The two remaining ungated callers are routed.** The UDP/443 QUIC
  decoder (v4 and v6) called `dns_resolve()` on the capture thread for
  every packet, consulting no toggle — a cold cache turned capture
  itself into a reverse-DNS generator. It now calls
  `capture_quic_hostname()`, which is passive unconditionally.
  `top_hosts_update()` resolved on every poll regardless of the `[n]`
  names/numeric toggle; it now follows it, so the two gates compose.
- **Flags.** `--allow-active` opts in and prints exactly one stderr line
  naming what it enabled. `--strict` is an accepted no-op that *locks*
  the guarantee for the run; the lock lives in `src/dns.c`, not in the
  argv parser, so it is a cross-module invariant. A command line
  carrying both is refused in either order rather than silently
  resolved in favour of one.

**Not done here**: the nl80211 scan-trigger limiter and the
telemetry/Avahi profile are slice 3, and the README positioning rewrite
is sequenced after the profile is verified on real hardware. Both halves
of the DNS lookup API still return a shared static buffer documented
main-thread-only while the capture thread reaches the decoder path —
that race predates #84 and was not touched inside a behaviour flip.

---

## 2026-09-25 — data-socket exposure guard (#86, transport half)

**Created page**: [data-socket-exposure.md](data-socket-exposure.md).
**Updated pages**: [index.md](index.md), [../streaming.html](../streaming.html),
[../../README.md](../../README.md), [../../examples/README.md](../../examples/README.md).

The Captain's decision on #86 (2026-09-25) was **no crypto in sloth** —
in-process TLS/mTLS and bearer tokens are rejected, the design is parked
in #100, and the transport stays local. This slice makes "no remote
exposure by default" technically true rather than merely conventional,
and writes down the boundary that replaces the crypto.

- **Remote-bind guard.** A `tcp:` spec outside `127.0.0.0/8` — including
  the `0.0.0.0` wildcard — is refused unless
  `--data-socket-allow-remote` is passed; the refusal names the flag and
  offers the `ssh -L` one-liner. With the flag, the bind proceeds and
  warns, naming address, port, and the fact that the stream is
  unauthenticated and unencrypted. The check runs **before `socket()`**,
  so a bind nobody opted into never reaches the kernel.
- **Loopback is the whole `/8`, not `127.0.0.1`.** `127.0.0.2` is
  equally unreachable off-host and an operator using one must not start
  needing a flag. Classification is done on the address `inet_pton()`
  parsed, not on the string, and `unix:` is unaffected in both
  directions. No working configuration changed.
- **`unix:` sockets are now created 0600.** They were created at the
  process umask — `0755` on a default `0022` host, i.e.
  world-connectable. The page states that 0600 plus the uid-ownership
  check from `f2bf0b5` is kernel-enforced peer authentication, which was
  not true until this commit: the mode is now forced with `umask` across
  the `bind()` (not `chmod()` after it, which leaves the socket
  listening at the looser mode first). This is the recommended
  deployment and the page says so plainly rather than burying it.
- **The three supported remote paths, with commands that run**:
  `ssh -N -L 8765:127.0.0.1:8765 user@sensor`; the new mutual-TLS
  stunnel templates; and `examples/forwarder/sloth-forward.py`, which
  connects as a *local* client and pushes outbound to HEC / syslog /
  Elasticsearch / Loki / Datadog / webhook — so nothing listens remotely
  on the sensor at all.
- **`examples/stunnel/`** ships sensor- and reader-side configs with
  `verify = 2` on both ends, because one-sided TLS protects this stream
  from a passive listener and not at all from an active one. The README
  leads with the `accept`/`connect` swap, the one error that fails open.
  **No systemd unit ships** — `FACTORY.md` §7 keeps deployment under
  operator control, so the unit is an inline example on the wiki page
  instead, matching the forwarder README's precedent.

The page is explicit about the one thing sloth cannot assert about
itself: whether this closes an external reviewer's "remotely exposed"
finding is the reviewer's sign-off. The auth/TLS half of #86 stays open.

---

## 2026-09-25 — Correlation honesty: what the evidence supports (#94)

**Source**: external CISO/GRC review (Todd Luther, 2026-09), issue #94.
The finding is not a missing feature — it is that two outputs stated
conclusions their evidence does not support, and both produce records
that could be quoted in a personnel investigation or used to point at a
person in a room.

**Doc updates**: [mac-randomisation.md](mac-randomisation.md) rewritten
around the limits on use, the seven acceptance requirements, the measured
false-pair rate, and the configuration; `alerts.md` gained
*Corroboration before intent* and *Records are not conclusions about
people*; `jsonl-schema.md` documents the seven additive
`seqnum_correlation` fields; `retention.md` gained §3b for the two
in-memory correlation horizons; `docs/views/seqnum.md` and the
`MY_NET_RECON` row in `docs/views/alerts.md` rewritten.

**Sequence correlation.** The pre-#94 rule minimised **absolute** modular
distance over the cross product of two 8-entry trails and accepted any
pair inside a flat 64-seqnum / 30-second window, with nothing expiring
anywhere, then labelled the result `LIKELY SAME DEVICE`. Five checks now
gate a pair, and each removes a class of false pair rather than tuning a
threshold:

- **freshness** — both addresses heard within `--correlate-retain`
  (default 300 s) of *now*. Without it two trails that were once close
  kept producing current suggestions for the life of the process.
- **ordering + exclusivity** — the earlier address must be finished
  before the later one starts. One radio holds one address at a time, so
  interleaved transmissions are two radios however close their counters
  sit. This is the check that does most of the work in a dense room.
- **direction** — the counter advanced *forward* by 1…64. Absolute
  distance cannot separate +5 from −5, and only one of those is a
  rotation. Zero is excluded: a repeated value is a duplicate, and
  duplicates are the commonest coincidence there is.
- **continuity** — each trail runs forward on its own before it is
  extrapolated across the seam.
- **a score above the floor**, replacing the categorical verdict.

**Measured, not estimated.** The issue offered scale intuition —
129/4096 differences inside modular distance 64, ≈ 3.15 % per comparison
for two independent uniform 12-bit values. That is an estimate about a
model; real trails are dependent. `test_dense_environment_false_pair_rate`
builds 64 independent radios over only 512 counter positions, each in its
own non-overlapping slot, and prints the rate on every `make test`:
**472/2016 = 23.413 % before, 59/2016 = 2.927 % after**, top score 80 %.
The test asserts a bound set *from* the measurement (< 4 %), so it fails
if the rule is ever loosened, and does not encode the estimate.

**The score is a ranking, not a probability.** Stated plainly in the
docs because it is the one thing a reader will get wrong: how often a
reported pair is really one radio depends on the base rate of rotations,
which sloth cannot observe. In a room of sixty randomising handsets and
no rotations, every accepted pair is wrong whatever it scores. This is
also why the heat-red "possible rotation" row is **structural** as well
as numeric — it requires exactly one randomised address, the shape
rotation actually produces, because coincidences reach the same numeric
band and no number derived from the same evidence can separate them.

**`MY_NET_RECON`.** Uncorroborated it is now LOW at 25 % confidence and
says `probed for designated network … uncorroborated`; the word
*reconnaissance* requires positive corroboration (sustained probing, or a
PNL naming two or more designated networks). A randomised MAC does not
corroborate — it describes the handset population — and neither does the
*absence* of an observed association, because an incomplete capture is
the benign case the rule exists to respect. Three exonerations:
designated association, the `--known-mac` roster, and association by a
seqnum-correlated sibling address — which closes the randomised-probe /
real-association case where exact-MAC matching accused a device that was
on the network the whole time.

**Deliberate test change.** `test_my_net_recon_fires_for_unassociated_client`
pinned `ALERT_SEV_WARN` for the bare observation while the rule's own
comment conceded "a former guest's phone produces it honestly". That
assertion was pinning the over-claim, not guarding a regression, so it
was rewritten as
`test_my_net_recon_uncorroborated_is_low_and_unqualified` rather than
worked around.

**Configurable, with a stated purpose.** `--no-correlate` and
`--correlate-retain SECS`, announced at startup so an operator does not
have to read the source to learn the capability is on. Purpose: keep
device counts, alert dedup and transit passes from being inflated by MAC
rotation — not to build a movement history.

**Flagged decision (taken on a default, not an answer).** Triage asked
whether "rename outputs" meant display text only or also the JSONL alert
type ids, and the question was never answered. Proceeded on the stated
default: **human-readable text changed, type ids kept**. `MY_NET_RECON`
and every other id is untouched, because renaming one is a non-additive
schema break under MISSION §4.3 and would reach the sloth-ios consumer.
Everything new is an added field. No `DB_SCHEMA_VERSION` bump.

---

## 2026-09-25 — #84 slice 3: scan trigger, discovery and the positioning rewrite

**Source**: issue #84 (external CISO/GRC review, Todd Luther, 2026-09),
slice 3 of 3. Slices 1–2 built the passive/active split in the resolver
and made strict observation the default.

**What changed.**

- **`src/observe.{c,h}`** is new and small: one owner for the run's
  observation policy. The strict lock moved out of `src/dns.c`, which
  held it in slice 2 when the resolver was the only active path worth
  gating. The nl80211 scan trigger and the Avahi carve-out both have to
  honour the same lock and neither can depend on the DNS module, so the
  policy is now its own object every subsystem asks. `dns.c` keeps only
  the resolver's own enable bit and delegates the lock.
- **The nl80211 scan trigger is gated and instrumented.**
  `trigger_scan_async()` used to fire `NL80211_CMD_TRIGGER_SCAN` from the
  ordinary poll loop, unconditionally. The decision, the rate limiter and
  the message construction are now split into
  `linux_wifi_prepare_scan_trigger()`, which returns 0 when policy or the
  limiter refuses. Under the default profile — and, locked, under
  `--strict` — **zero requests are built**, and no socket is opened
  either. Counting at the builder rather than at `sendto(2)` is the
  point: a request that was built and then dropped is still a request the
  code was willing to make.
- **The scan-trigger rate limiter is genuinely per-interface.** It was a
  single function-static `time_t` shared by every interface behind a
  comment claiming per-interface limiting, so the first radio
  `find_wlan_ifaces()` enumerated consumed the whole budget and the rest
  were triggered only when it happened to be quiet. Fixed rather than
  documented as global: the enumeration order is fixed, so "global" does
  not mean fair, it means one radio is preferred and the others starve —
  and a monitor radio alongside an uplink is the deployment sloth
  targets. `find_wlan_ifaces()` caps at 8, so an 8-slot table gives every
  enumerated radio its own slot with no allocation.
- **`--strict` suppresses mDNS discovery**, enforced inside
  `discovery_publish()` rather than at the call site. sloth still
  transmits nothing itself, but avahi-daemon announcing on its behalf is
  the host's presence on the wire.
- **README positioning rewritten**, which the issue sequences last. The
  old headline claim — "never injects packets, never scans, never
  modifies kernel state" — was the thing under review and is gone. What
  replaces it says only what the code enforces, names the two active
  behaviours in a table, and states plainly what has *not* been proven
  (over-the-air validation with an independent receiver).

**Deliberate asymmetry, flagged.** The scan trigger is off by *default*;
discovery is suppressed only under the explicit `--strict` lock. The
Captain's written decision of 2026-09-25 names the resolver and the scan
trigger, not discovery, and the carve-out already requires a routable
`--data-socket` bind plus `--data-socket-allow-remote` — two explicit
operator acts — so it cannot fire on a default run at all. Silently
dropping it would break sloth-ios discovery for a deployment that asked
for it.

**Not touched.** `MISSION.md` §2/§3 and `agents/AGENTS.md` still carry
the older "never scans, never modifies kernel state" phrasing. The
charter is the Captain's to author (§4.3) and `agents/` is a high-signal
surface, so the inconsistency is surfaced on the issue rather than
edited here.

---

## 2026-09-26 — #89 slice 3: impersonator / neighbour / wired separation

**Source**: issue #89 fix list, final bullet — *"Distinguish in the UI:
over-the-air impersonator vs. neighboring AP vs. unauthorized AP
attached to the wired network. RF alone cannot establish wired
attachment; leave a hook for controller/switch/DHCP correlation."*

**Updated pages**:

- [jsonl-schema.md](jsonl-schema.md) — additive `ap_class` and
  `wired_attachment` on the `alert`, `alert.*` and `twin_episode`
  records, plus a note on why they are two axes and why a missing
  `wired_attachment` must be rendered as unknown rather than as "not
  attached".
- [../views/twins.md](../views/twins.md) — the category table, the new
  `Class` / `Wired` columns and legend, and the reasoning for keeping
  wired attachment off the class enum entirely.

**Notes**:

- **Two of the three categories are decidable, one is not, and that
  asymmetry is the whole slice.** `ap_class` (`impostor` / `neighbor` /
  `declared` / unknown) comes from RF plus the approved inventory,
  because impersonation is an over-the-air behaviour. Wired attachment
  is not observable from any frame — a Pineapple on an LTE uplink and a
  rogue bridged onto the access VLAN beacon identically — so it is a
  separate field that no rule in `src/alerts.c` can set, defaulting to
  unknown and rendering as `?`.
- **The hook** is `src/wired_attach.h`: one in-process registration
  slot for a future switch CAM / controller / DHCP correlator. Not a
  plugin loader (no dlopen, no path), not a control surface (nothing
  reaches it from the network or the CLI), and registering a correlator
  grants it no permission to transmit — MISSION §2 applies to it like
  anything else. One slot, no stacking: two correlators disagreeing is
  an unresolved question, not a vote.
- **Classification is a label, never a gate.** No class suppresses an
  episode, moves a severity or changes a confidence; with no inventory
  configured an operator sees exactly what they saw before, plus two
  columns reading `?`. A classifier that could silence a finding would
  be a new sole suppressor — the bug class #89 exists to remove.
- **`ALERT_DETAIL_LEN` 256 → 320.** The same-security twin detail was
  calibrated to land at exactly 255 bytes worst case, so appending
  ` [class=… wired=…]` pushed it over and `-Wformat-truncation` caught
  it. Grown rather than trading a field away, because the field that
  would have been truncated is `wired=?` — the one statement that stops
  a reader assuming sloth checked the wire.

## 2026-09-26 — #86 slice 3: data-socket examples use /run

**Source**: issue #86 — the documented `unix:` socket examples should
model the deployment `data-socket-exposure.md` recommends, not a path
another local user controls.

**Updated pages**:

- [../quickstart.html](../quickstart.html),
  [../index.html](../index.html) and
  [../views/interfaces.md](../views/interfaces.md) — `unix:` examples
  now spell `/run/sloth.sock` (was `/tmp/sloth.sock`, and `/var/run`
  in the interfaces doc).

**Notes**:

- **Why `/run`.** `/tmp` is world-writable, so anyone can create the
  path before sloth starts. `init_unix()` already refuses a non-socket
  or foreign-owned path (f2bf0b5), which turns a plant into a denial
  of service rather than a hijack, but examples are what people copy.
  `/run` is root-owned and is what the refusal hint names.
- **Not done yet.** `README.md`, `docs/streaming.html`,
  [jsonl-schema.md](jsonl-schema.md) and the `examples/consumer` and
  `examples/forwarder` READMEs still show `/tmp/sloth.sock`. They are
  the next sweep. The `RELEASE_v1.*.md` notes are historical and stay.
- **Known rough edge.** The forwarder examples connect without `sudo`,
  and a 0600 socket that root creates refuses any other uid. This was
  true before with `/tmp` too, and `data-socket-exposure.md` §5 has the
  same shape. It needs a sudo or group note in a later pass.

---

## 2026-09-26 — #96: docs-consistency test for version and counts

**Source**: issue #96 — README, SECURITY and help text state the
version, view count and alert-rule count, and each has drifted from the
build before.

**Updated pages**:

- `../../SECURITY.md` — the archived row of the supported-versions
  table reads "every tag before the newest" (was "v1.8.0 and below",
  which left v1.8.1 in no row once it was tagged).
- `tests/test_docs_consistency.c` (new) — compares claims in
  `README.md`, `SECURITY.md`, the help card and `print_usage()` with
  `SLOTH_VERSION`, `VIEW_COUNT` and `ALERT_TYPE_COUNT`.

**Notes**:

- **Fixed grammar, no model.** Counts come from a closed word pattern:
  `<N> [live|passive|ncurses|alert]* views|rules`. README must yield
  its known claims, so a reword that slips past the grammar fails
  instead of passing silently.
- **Coupling.** SECURITY.md may name only `SLOTH_VERSION`. The commit
  that bumps the version must edit SECURITY.md in the same commit.
- **Limits.** Counts written as words ("six alert rules") are not
  read. The help-card check only catches a count or version later
  hard-coded into `help.c`.
- **Out of scope.** `MISSION.md` and `agents/` are not checked. The
  "9304 assertions" figure in `agents/AGENTS.md` and README is stale
  (10712 now) and is left for the owner.

## 2026-09-26 — #95: test suite under ASan and UBSan in CI

**Source**: issue #95 — parsers read bytes off the air and the wire; a
unit test that passes while reading past its buffer is a false green.
#83's EAPOL-Key over-read was only confirmed by a manual ASan run.

**Updated pages**:

- `.github/workflows/ci.yml` — new blocking `sanitize` job runs
  `make test` with `-fsanitize=address,undefined
  -fno-sanitize-recover=all` and leak detection on.
- `tests/test_tls_log.c` — the JA4 extension-reorder test swapped two
  extensions with an overlapping `memcpy`; both copies now read from
  the pristine fixture. Same bytes, same assertions.

**Notes**:

- **One finding, in a test.** The overlapping `memcpy` was the only
  sanitizer report across 10712 assertions; nothing in `src/`.
- **Fix, don't suppress.** Zero leaks, so no `tests/lsan.supp`. A
  future third-party entry needs a reason per line and never covers
  sloth's own allocations.
- **Coverage limit.** Only `sloth_test` is instrumented, and it is
  built without `WITH_PCAP`/`WITH_NCURSES`: pcap capture paths, ncurses
  rendering and the `sloth` binary are not sanitized.
- **Out of scope.** `agents/AGENTS.md` still describes CI as the
  six-variant `-Werror` build only; left for the owner.

## 2026-09-26 — #86: mDNS discovery uses the data-socket exposure classifier

**Source**: issue #86 — `discovery_routable_tcp_port()` kept its own
copy of "is this spec routable" and had drifted from the bind guard in
`src/data_socket.c`.

**Updated pages**:

- `src/discovery.c` — routable now means
  `data_socket_spec_is_remote() == 1`; the port comes from the new
  `data_socket_spec_tcp_port()`.
- `src/data_socket.{c,h}` — `data_socket_spec_tcp_port()` exported,
  built on the binder's strict `parse_host_port()`.
- `src/discovery.h` — comment no longer describes a 127.0.0.1-only rule.
- `tests/test_discovery.c` — 5 tests, 20 assertions.

**Notes**:

- **The bug.** Only 127.0.0.1 counted as loopback, so
  `tcp:127.0.0.2:8765` bound without `--data-socket-allow-remote` and
  was then advertised over mDNS as a LAN service. `atoi()` read
  `8765x` as 8765 where the binder rejects the spec.
- **One classifier.** The advertisement can now only describe what the
  exposure guard allowed. #84's `--strict` gate in `discovery_publish()`
  is unchanged.
- **Still advertised.** `0.0.0.0` binds every interface and needs
  `--data-socket-allow-remote`; now pinned by a test.
- **Limits.** `data_socket_spec_tcp_port()` has no direct tests in
  `tests/test_data_socket.c`, and duplicates the parse sequence in
  `data_socket_spec_is_remote()`. Both are follow-ups.

## 2026-09-26 — #95: evil-twin taint table locked against the probe thread

**Source**: issue #95 — `g_taint` in `src/alerts.c` was written on the
main loop and read from the probe thread (via `eapol_log.c` writing a
.22000 line) with nothing ordering the accesses.

**Updated pages**:

- `src/alerts.c` — `g_taint_mu` guards mark, query and clear; eviction
  body is `taint_mark_locked()`.
- `src/alerts.h` — thread-safety contract documented;
  `EVIL_TWIN_TAINT_MAX` exported.
- `tests/test_alerts.c` — concurrent mark/query test, 16 assertions.

**Notes**:

- **Leaf lock.** Nothing but memcmp/memcpy runs under `g_taint_mu` and
  `time()` is read before locking, so taking it under `eapol_log.c`'s
  `g_mu` cannot deadlock.
- **Red signal is TSan.** With the locks stubbed a TSan run reports 2
  races; without TSan the new test only catches the race by chance.
  CI gains a reliable signal when the #95 TSan slice lands.
- **Limits.** The post-join capacity check runs on a cleared table, and
  the leaf-lock invariant is documented, not mechanically enforced.

## 2026-09-26 — #84: --strict doc claims corrected to match code

**Source**: issue #84 — README and the data-socket exposure page
claimed `--strict` blocks `--hop` and closes every on-wire path. The
code gates only `--allow-active` and the mDNS advertisement.

**Updated pages**:

- `README.md` — WiFi SIGINT usage: `--strict` refuses `--allow-active`
  only; `--hop` is the separate MISSION §2 carve-out. `--strict` and
  `--data-socket` bullets name a routable data socket as a remaining
  path.
- `docs/wiki/data-socket-exposure.md` — `--strict` suppresses the
  advertisement, not an opted-in routable listener.

**Notes**:

- **Owner decision open.** Whether `--strict` should also refuse
  `--hop` or a routable socket is left to the owner; the docs describe
  today's behaviour.
- **Limits.** `sloth --help` in `src/main.c` still over-claims and
  needs a code slice. The README "exactly two behaviours" paragraph
  predates this change and omits `--hop` and the routable socket.

## 2026-09-26 — #87: export permission contract documented

**Source**: issue #87 — the permission hardening shipped a fixed
on-disk contract, but only the EAPOL page described it and its closing
line read like guidance on group access while triage Q3 is still open.

**Updated pages**:

- `docs/wiki/retention.md` — new §4.1: per-artifact creation mode
  (0600 files, 0700 directories, independent of umask), write strategy
  and refusal behaviour. `--snapshot-out` added to §4 and to §6 known
  gaps as not covered (plain fopen).
- `docs/views/eapol.md` — sudo/group line replaced with current
  behaviour: no group mode, gid not checked, a group-accessible
  existing path is refused and left unchanged.

**Notes**:

- **Behaviour, not policy.** Both pages say what the code does and
  point to #87 Q3; SECURITY.md is untouched.
- **Scoped claims.** SQLite side files are lstat-checked by path, not
  pinned to a descriptor. "Refused, not repaired" covers append and
  truncate targets and directories only; EXCL artifacts step to `_N`
  and the per-handshake pcap is replaced by rename.
- **Limits.** The main `--db` is reopened by path after its check.
  `--snapshot-out` ignores write errors after open. §6 still says a
  failed write disables the sink, which #87/#92 changed to
  count-and-retry.

## 2026-09-26 — #95: RF quality counters locked against the probe thread

**Source**: issue #95 — `g_ch`/`g_n` in `src/rf_quality.c` were written
by `rf_quality_observe()` on the probe thread for every monitor-mode
frame and read by the poll loop's snapshot with nothing ordering the
accesses.

**Updated pages**:

- `src/rf_quality.c` — `g_mu` guards observe, retry/badFCS pct,
  is_degraded, snapshot and clear; `roll_if_stale()` runs only under
  it; pct body is `pct_locked()`.
- `src/rf_quality.h` — thread-safety contract documented.
- `tests/test_rf_quality.c` — concurrent observe/snapshot test, 13
  assertions.

**Notes**:

- **Leaf lock, table-wide.** Eviction rewrites a slot's identity, so
  per-slot locks would still need a table lock; critical sections are
  at most a 64-entry scan. Snapshot holds the lock for the whole pass
  so each row is self-consistent.
- **Red signal is TSan.** With the locks stubbed TSan reports races
  (exit 66); a plain build caught the tear 1 of 3 runs. CI gains a
  reliable signal when the #95 TSan slice lands.
- **Limits.** The reader checks `is_degraded` only for false positives
  on clean channels. `rf_quality_snapshot()` still writes
  `s->channels[]` unlocked, so callers must own `sloth_state_t` (true
  today: poll loop only).

## 2026-09-26 — #82: EAP-WSC decoder (WPS M1–M8 inside EAP Expanded Type)

**Source**: issue #82. Its PIN-brute and Pixie-Dust asks were declined in
triage because sloth had no EAP-WSC decode path. This slice adds that
path as a stateless parser.

**Updated pages**:

- `src/eap_parse.c`, `src/eap_parse.h` — `eap_wsc_parse()` and
  `wsc_msg_name()`: RFC 3748 §5.7 Expanded Type 254 gated on WFA SMI
  0x00372A / vendor-type 1 (WSC 2.0 §7.7); Op-Code, MF/LF flags,
  Message Length; §12 TLV walk for Message Type 0x1022, UUID-E 0x1047,
  MAC 0x1020, bounded by EAP Length. `eap_type_name(254)` now returns
  "Expanded".
- `tests/test_eap_parse.c` — 9 hand-built-frame tests (+155
  assertions).

**Notes**:

- **Fragments.** Middle fragments are skipped because their body starts
  mid-value. A final fragment (MF and LF clear) looks the same as an
  unfragmented message, so it is walked. Its msg_type is untrusted
  until the session layer reassembles.
- **Tolerance.** Fixed-size attributes with the wrong length are
  ignored. Duplicate TLVs resolve last-wins. Op-Code and Message Type
  are not cross-checked. Each is a job for the session layer.
- **Naming.** 0x1020 is the generic MAC Address attribute and is the
  Enrollee MAC only in M1, so the field is `mac`.
- **Not yet wired.** Nothing calls it at runtime. The wave-7 WPS session
  table is the first caller, and wave-11 fuzzing targets it.

## 2026-09-26 — #92: EAPOL handshake pcap carries original capture timestamps

**Source**: issue #92. The per-handshake pcap stamped every record with
the processing time (`time(NULL)`) and a zero `ts_usec`, so a capture
backlog shifted it and M1..M4 of one exchange collapsed into the same
second.

**Updated pages**:

- `include/eapol_log.h`, `src/eapol_log.c` — `eapol_observe_dot11()`
  takes `(ts_sec, ts_usec)` from the pcap header; `pending_t` stores
  per-message usec; `write_handshake_pcap()` writes both. The
  `eapol_observe_dot11_at()` seam from #97 is folded in and removed.
- `src/capture/probe.c` — `on_probe_frame` passes `hdr->ts` through.
- `tests/test_eapol_log.c` — 3 hand-built-frame tests that read back the
  written record headers (+19 assertions). `tests/test_alerts.c` and
  `tests/test_fragattack.c` get one-line signature updates.

**Notes**:

- **One clock for EAPOL.** The pairing window, event ts, LRU
  `last_seen` and the `eap_track` rogue-RADIUS session stamps now use
  capture time. Live capture is the same wall-clock domain, so no
  comparison crosses domains.
- **Clamp.** A `ts_usec` outside 0..999999 is stored as 0. Probe never
  enables nanosecond precision; if it ever does, the pcap magic must
  change to 0xa1b23c4d and the clamp revisited.
- **Open.** `frag_observe()` still takes `time(NULL)` for the same
  frame. That is left for a later #92 slice or the wave-4 stop-flags
  edit of probe.c.

---

## 2026-09-26 — #95: DNS lookups return into a caller-owned buffer

**Source**: issue #95. `dns_lookup_cached()` and `dns_resolve()`
returned a pointer into one static `g_result`. The capture thread
(`capture_quic_hostname()`) read it while the main thread
(`dns_resolve()` for top_hosts and the packet detail pane) could be
overwriting it, so a QUIC log record could carry a torn hostname. This
closes the race the #84 entry above left under "Not done here".

**Updated pages**:

- `src/dns.c`, `src/dns.h` — all three lookups take `(ip, buf, sz)`;
  the name, or a copy of ip on a miss, is copied under `g_mu`,
  truncated and NUL-terminated. `g_result` removed. `DNS_NAME_MAX`
  (256) added and used for the cache host field.
- `src/top_hosts.c`, `src/views/packets.c`, `src/capture/capture.[ch]`
  — callers pass their own buffer; `capture_quic_hostname()` gains
  `(buf, sz)`.
- `tests/test_dns.c` — held-at-once, miss, truncation, NULL/0 buffer
  and a two-thread lookup-vs-resolve test (+35 assertions with
  `tests/test_top_hosts.c`). Snoop and capture tests moved to the new
  signature.

**Notes**:

- **Contract.** NULL buf or `sz == 0` returns ip and writes nothing;
  every other path returns buf. `dns_lookup()` is kept on the same
  signature so the compatibility spelling cannot bring back a static
  buffer.
- **top_hosts** resolves into a `hostname[64]`-sized temporary, keeping
  the old 63-character truncation.
- **Race gate.** The two-thread test is probabilistic; the
  held-at-once test is the deterministic proof. Reliable detection of
  a regression depends on the TSan CI slice.
- **Open.** `dns_fmt_addr` is not covered by the "any thread" note in
  `dns.h`; it is main-thread only today.

## 2026-09-27 — #86: data-socket listener and client fds are close-on-exec

**Source**: commit `d3170da`, issue #86 (last item on the fix list).

sloth keeps the data socket open for its whole life. Without
`FD_CLOEXEC`, any child it exec()s inherits the listener and every live
client, so that child can `accept()` on, or read, the unauthenticated
JSONL stream.

**Updated pages**:

- `src/data_socket.c`: on Linux the listener comes from
  `ds_socket()` with `SOCK_CLOEXEC|SOCK_NONBLOCK`, and clients come
  from `accept_cloexec()` (`accept4()` with the same flags), so the
  flag is set atomically. `_GNU_SOURCE` is defined for this file only,
  and only under `__linux__`. Other targets set `fcntl(F_SETFD,
  FD_CLOEXEC)` after the call, check it, and close the fd if it fails.
- `src/data_socket.h`: one test-hook comment. Passing NULL to
  `data_socket_test_set_accept_fn()` now restores the close-on-exec
  wrapper, not plain `accept`.
- `tests/test_data_socket.c`: three tests (+12 assertions) check
  `fcntl(F_GETFD) & FD_CLOEXEC` on the UNIX listener, the loopback TCP
  listener and two accepted clients.

**Notes**:

- **Coverage gap.** Reverting only the static `g_accept_fn` initializer
  to `accept` stays green, because earlier tests pass NULL first. The
  initial default has no coverage that is independent of test order.
- ~~**Open.** The liveness-probe socket in `unix_path_removable()` is
  still not close-on-exec.~~ **Closed 2026-10-05**: it is created
  close-on-exec with the module's other sockets, and the "every fd this
  module owns" comment is now true rather than aspirational. The entry
  is struck rather than deleted — a changelog that quietly loses its own
  open items stops being a record of what was outstanding when.
- **Open.** A docs sweep for `unix:/tmp/sloth.sock` is outstanding in
  README.md, docs/streaming.html, docs/wiki/jsonl-schema.md and
  examples/{consumer,forwarder}/README.md. Authenticated remote
  delivery is tracked in #100.

## 2026-09-27 — #95: worker stop flags behind a mutex (C99)

**Source**: commit `9bfb808`, issue #95.

The capture, probe and DNS workers were stopped through a plain `int`
flag. It was written on one thread and read on another with no
synchronisation, which is a data race in C99. Stop paths also checked
the flag and cleared it in two separate steps, so two stoppers running
at once could both `pthread_join` the same thread, which is undefined
behaviour.

**Changes**:

- `src/capture/capture.{c,h}`: new `capture_run_flag_t` (a mutex plus
  an int) with `get`, `set` and `take`. `take()` clears the flag and
  returns its old value atomically. It is defined outside `WITH_PCAP`
  so the tests can run it under TSan without libpcap.
- `src/capture/probe.c`: uses the same helper. `probe_set_iface()` now
  clears the flag when `pthread_create` fails.
- `src/dns.c`: the flag stays under `g_mu`, because the condvar needs
  it. The worker reads it only while holding the lock, and
  `dns_cleanup` checks and clears it in one step.
- `src/main.c`: `g_quit` is `volatile sig_atomic_t`.
- Tests (+16 assertions): the flag contract, a polling worker stopped
  mid-loop, concurrent `take()`, and concurrent `dns_cleanup()`.

**Notes**:

- **Open.** SIGINT and SIGTERM can be delivered to worker threads, so
  the C99 guarantee for `g_quit` formally covers only a handler on the
  same thread. Blocking them with `pthread_sigmask` is a follow-up.
- **Open.** Start and stop are not safe to run concurrently, because
  the flag is set before `pthread_create`. Only the main thread starts
  and stops workers today.
- **Coverage gap.** The exclusivity test catches a `take()` written as
  a get followed by a set only by chance. The new spin loops have no
  timeout. The pcap worker loops themselves are not tested.

## 2026-09-27 — #90: tool-signature provenance exported per alert

**Source**: commit `ef7db0d`, issue #90.

A KARMA_AP alert that named a tool (ESP32 Marauder, WiFi Pineapple)
said so only in free-text detail. A JSONL consumer could not tell which
signature row matched, which revision of it, or that every shipped row
is research-derived and has never been validated against a capture.

**Changes**:

- `src/tool_fingerprint.{c,h}`: each row has a stable `id` and a
  `version`. The shipped rows are `esp32-marauder-01` and
  `pineapple-mk7-01`, version `research-2026-09-04`. Ids are never
  reused or renamed; a capture that replaces a row keeps its id and
  moves its version. `tool_fingerprint_match_row()` returns the
  winning row, and the older matchers wrap it.
- `include/sloth.h`, `src/alerts.c`: `alert_t` carries `sig_id`,
  `sig_version`, `sig_evidence` and `sig_validated`. They are stamped
  in `fire_inv` and refreshed on every evaluation, so a match that
  disappears mid-incident stops being exported.
- `src/jsonl.c`: alert and lifecycle records emit `signature_id`,
  `signature_version`, `validated` (JSON boolean) and
  `signature_evidence`, and omit all four when nothing matched.
  Additive: no schema-version bump, no CLI change.
- `src/karma_detect.{c,h}`, `src/views/karma.c`: `karma_tool_match()`
  builds the observation for both the rule and the [y] view, and
  `tool_attribution_format()` renders it. An unverified match reads
  `[ESP32 Marauder/med? provisional]` in both places.
- Docs: `jsonl-schema.md` (new fields; `confidence` is also emitted by
  KARMA_AP and MY_NET_RECON), `alerts.md`, `karma.md`,
  `tool-fingerprints.md`.
- Tests (+95 assertions), including a data-socket test that pushes
  every unverified row through the real rule, engine and socket.

**Notes**:

- **Owner questions.** `research-2026-09-04` or the literal
  `unversioned` for unverified rows? Is a JSON boolean right for
  `validated`, given the rest of the schema uses 0/1 ints?
- **Open.** A matched [y] row runs to about 122 columns and wraps on
  the 100-column minimum terminal; the attribution should be truncated
  to the remaining width. The second legend line is not counted in the
  page budget (`LINES - 5`), so a full list clips it.
- **Open.** The explicit PMKID_OBSERVED /
  BEHAVIOR_CONSISTENT_WITH_ACTIVE_COLLECTION / CONFIRMED_ATTACK states.

## 2026-09-27 — #85: capture allow-list pinned by ifindex, scope state reported

**Source**: commit `7da4b15`, issue #85.

`--iface` and `--monitor-only` were enforced by matching interface
names through a cache. A rename, delete or ifindex reuse could make a
stale name authorise traffic from the wrong interface, and nothing told
the operator when the requested scope was no longer being observed.

**Changes**:

- `src/capture/capture.{c,h}`: `capture_policy_pin()` pins the
  allow-list to (ifindex, name) pairs before the worker starts. A frame
  is admitted only when its SLL2 ingress index matches a valid pin.
  `capture_scope_poll()` revalidates each pin every tick. On delete,
  rename, reuse or lookup failure it clears the pin (sticky) and bumps
  a generation counter under `g_mu`. `capture_scope_state()` returns
  none, enforced, no_capture or degraded.
- `src/jsonl.c`: sensor_health appends `scope`, `scope_not_enforced`,
  `scope_requested`, `scope_enforced` and `scope_generation`, all in
  the change-only signature. Additive.
- `src/views/iface.c`: the health strip shows `scope degraded N/M` or
  `scope no-capture` only when something is wrong.
- Docs: `jsonl-schema.md`, `docs/views/interfaces.md`;
  `examples/consumer/sloth-stream.py`.
- Tests (+101 assertions), using a seeded interface table that changes
  between ticks and hand-built SLL2 headers.

**Notes**:

- **Owner question.** When an adapter is unplugged and returns under
  the same name with a new ifindex, should it stay failed closed until
  restart (what ships), or be re-pinned by name mid-run?
- **Open.** A transient `if_indextoname()` failure also fails a pin
  closed for the rest of the run. It shows as `scope degraded`.
- **Open.** An ifindex reused between two ticks is admitted until the
  next revalidation (documented). A dead worker with a live handle
  reads `enforced`. [m] can still retarget the probe radio under
  `--monitor-only`.
- **Deferred.** The `out_of_scope_dropped` counter (wave 8).

## 2026-09-27 — #95: blocking cppcheck job, and the bug its first pass found

**Source**: commit `154079c`, issue #95.

The sanitizer jobs only see code the suite executes. A static pass over
all of `src/` and `research/` catches defects on paths no test drives.

**Changes**:

- `.github/workflows/ci.yml`: new `cppcheck` job on ubuntu-24.04. A
  guard step fails unless the binary is exactly 2.13.0. Default Linux
  configuration only (the -D set mirrors `make`); warning, portability,
  performance and information classes plus errors; any unlisted finding
  fails the run.
- `tests/cppcheck.supp`: 23 `id:file` entries, each with its reason.
  An entry that stops matching an analysed file fails the job
  (unmatchedSuppression).
- `src/views/alerts.c`: the alert detail panel printed last_seen as
  "First seen": two `localtime()` results shared one static struct tm.
  Now `localtime_r` into stack storage. New test in
  `tests/test_alerts.c` (+6 assertions), red before the fix.
- `src/capture/capture.c`: `%u` → `%d` for an int protocol number.
- `src/http_log.c`: dropped a redundant `e &&` guard that the next
  statement contradicted.

**Notes**:

- **Owner question.** Convert the 10 main-thread `localtime()`/`gmtime()`
  sites to `localtime_r()` and drop their suppressions?
- **Owner question.** Add a second cppcheck pass for the embedded
  configuration, so WITH_*=0 paths are analysed?
- **Open.** An `id:file` entry hides a new same-id finding in the same
  file; an entry for a renamed or deleted file is not reported stale.
  Both are stated in the list header.
- **Open.** `src/pcap_write.c:30` dereferences a `localtime()` result
  without a NULL check (pre-existing; cppcheck does not flag it).
- **Not done.** clang-tidy.

## 2026-09-28 — #85 wave 8: out-of-scope drop counter

**Source**: issue #85, deferred from the wave-5 slice above.

The scope boundary could fail an individual frame silently: a pin
rejection or an unattributable frame under an active allow-list left no
trace beyond the drop itself. `scope`/`scope_enforced`/`scope_generation`
say whether the boundary is intact, not whether it is being tested.

**Changes**:

- `src/capture/capture.{c,h}`: `capture_frame_in_scope()` now bumps a
  module-local lifetime counter whenever an active allow-list refuses a
  frame — an unattributable ifindex, a non-SLL2/short frame that can't
  carry one, or an ifindex with no valid pin. The unrelated runtime `[y]`
  deselect (unrestricted stream) does not touch it — that's an operator
  toggle, not an authorization failure. New accessor
  `capture_out_of_scope_dropped()` plus a test-only reset.
- `src/jsonl.c`: sensor_health appends `scope_dropped`, in the
  change-only signature alongside the other `scope*` fields — a scope
  boundary starting to refuse frames is exactly the kind of news that
  heartbeat already treats as urgent. Additive.
- Docs: `jsonl-schema.md` (field table, sample record, cadence note);
  `examples/consumer/sloth-stream.py` surfaces it as a fault-only line.
- Tests (+9 assertions): counts distinct rejection reasons, stays at
  zero for admitted frames, for unrestricted "can't-tell" frames, and
  for the runtime deselect; reset zeroes it; the JSONL field reflects
  the accessor. Three mutations (drop the `restricted` guard on each of
  the two capture.c increment sites; hardcode the emitted field to 0)
  each turned one test red, reverted.

**Notes**:

- **Open**, same as the parent slice: the residual window where an
  ifindex reused between ticks is admitted until the next
  revalidation — those frames are not scope-boundary refusals and
  correctly don't count here.

## 2026-09-30 — Complete-reference build + GitHub wiki sync (#103)

Seven new concept pages turn the wiki into the complete information
source for sloth:

- `what-sloth-does.md` — one-screen map: surfaces, 35 views, 61 alerts,
  outputs, the passive line.
- `how-wifi-works.md` — 802.11 reference: bands/channels, the three frame
  classes, discover→auth→assoc→key, security generations, roaming, MAC
  randomisation, each tied to the sloth view that sees it.
- `monitor-mode.md` — the four NIC modes, what monitor mode gathers that
  managed/promiscuous cannot, how to enable it (external), the limits.
- `where-exploits-happen.md` — attack surface mapped to the join sequence
  and to each `ALERT_TYPE_*` detector.
- `wifi-sigint-techniques.md` — six passive collection techniques, each
  mapped to a view, with the tradecraft/policy limits (incl. #94).
- `cli-reference.md` — authoritative flags/args/keybindings/env/exit
  codes from `src/main.c` and `src/view_labels.c`.
- `wifi-state-of-the-art.md` — living Wi-Fi radar (Wi-Fi 7 MLO, Wi-Fi 8 /
  802.11bn schedule, WPA3/Dragonblood, FragAttacks, SSID confusion),
  web-sourced items dated and linked.
- `wiki-maintenance.md` — source-of-truth + sync mechanism + the standing
  agent duty.

Sync infrastructure so agents keep the wiki updated automatically:
`.github/scripts/wiki_sync.sh` renders `docs/wiki/` into `sloth.wiki.git`
(index→Home, strips front matter, rewrites relative links, generates
`_Sidebar`/`_Footer`, deletes removed pages); `.github/workflows/
wiki-sync.yml` runs it on every push to main touching `docs/wiki/**`.

Repo instructions updated: `docs/CLAUDE.md`, `agents/AGENTS.md` (new
"Wiki" duty section), `README.md` (wiki = complete reference). `index.md`
gained a "Read this first" section linking all seven.

---

## 2026-10-01 — `--collect-handshakes` + `--handshake-retention` (#87)

**Source**: the owner's written decision on issue #87 (2026-09-30):
crackable material is gated behind an opt-in, off by default, with a
7-day default retention sweep at startup and daily.

**Updated pages**:

- `cli-reference.md` — the two new flags in the output group,
  `--eapol-dir` marked as requiring the opt-in, the synopsis group list,
  and exit code `2` extended with both new refusals.
- `retention.md` — new **§2c** "Handshake exports: the opt-in and its
  sweep": what is swept, when, the whole-file-by-mtime granularity limit
  on `eapol.22000`, the never-follow-a-symlink rule, and the limit that
  retention needs a live opted-in collection. §4's "no retention"
  table rows for the EAPOL artifacts corrected to 7 days, §4.1's
  directory row noting the gate is checked before the directory is
  created, and two new entries in §6 Known gaps.
- `what-sloth-does.md`, `pcap-export.md`, `monitor-mode.md`,
  `evil-twin-reproducer.md` — `--eapol-dir` now names the opt-in, and
  every runnable command line that would have exited `2` was corrected.

Also outside `docs/wiki/`: `README.md` (output section, DB retention
paragraph, the quickstart command, the EAPOL view row) and
`docs/views/eapol.md` (§ Export handling).

**Not changed**: `MISSION.md` §2.2 already frames the 22000 export as
material the *operator* cracks, never sloth; the gate narrows what
reaches disk and needed no mission change.

## 2026-10-04 — operator-tunable detector thresholds (#82)

The owner accepted #82's WPS rate thresholds "each behind a config
knob" on 2026-09-30, and nothing could satisfy it: every behavioural
threshold in `src/alerts.c` was a `#define`, and sloth had exactly one
`getenv` (`NO_COLOR`). Owner decision 2026-10-04 settled the surface as
one repeatable flag over a named registry rather than ~20 flags.

- `src/tune.{c,h}` — 23-row registry, indexed by a `tune_id_t` so the
  detector hot path is an array index and not a string compare. Each row
  carries a name, the shipped default, a range and a unit. Bounds
  exclude only values that make a rule meaningless (a count under 1, a
  zero-length window), not values an operator might legitimately want.
- `--tune NAME=VALUE` (repeatable) and `--tune-list`. An unknown name, a
  non-integer, a missing value or an out-of-range number **exits 2**.
  That is the design point, not strictness for its own sake: a knob the
  operator believes they set but did not is worse than no knob, because
  the run looks tuned and behaves stock.
- `src/alerts.c` and `src/karma_detect.h` — the 22 `#define`s and
  `KARMA_SSID_THRESH` now expand to `tune_val(...)`. Every use site is
  unchanged, so any site that needed a compile-time constant would have
  failed the build rather than silently changing meaning.
- `sensor_health` gains `tuned_count` and `tuned` (additive), and the
  Interfaces health strip gains a fault-only `tuned N/M` token. A raised
  threshold can silence a detector, so a quiet sensor and a detuned one
  must not look alike — to a consumer or to the operator at the
  terminal.
- `tests/test_tune.c` — 15 cases. The weight is on the rejections:
  unknown name, prefix-of-a-real-name (`ssh.brute` must not match
  `ssh.brute_force`), out-of-range at both ends, every malformed spec
  shape, and that nothing moves on any rejection. Also that the spec
  array still matches the enum order, since a reordering would remap one
  rule's threshold onto another's value with every test still green.

**Deliberately not tunable**: the `RECON_CONF_*` confidence weights.
Those decide what a corroborator is *worth*, not when a rule fires;
retuning them rewrites what a confidence percentage means in the export,
which is #89/#90 territory and not an operator dial.

**Not changed**: `MISSION.md`. A threshold is an observation parameter,
not a rule of engagement — nothing here lets sloth transmit, scan or
write kernel state.

## 2026-10-05 — #86: finish the `/run/sloth.sock` docs sweep

**Source**: the open item recorded under the 2026-09-27 `#86` entry above.

**Changed pages**: [jsonl-schema.md](jsonl-schema.md) (2 lines). The rest
of the sweep is outside `docs/wiki/`: `README.md`, `docs/streaming.html`,
`examples/consumer/README.md`, `examples/consumer/sloth-stream.py`,
`examples/forwarder/README.md`, `examples/forwarder/sloth-forward.py` —
45 lines in all, every one a `unix:/tmp/sloth.sock` in a copyable example.

**Why**: `/tmp` is world-writable, so any local user can pre-plant the
socket path. Since `f2bf0b5` `init_unix()` refuses a path that is not a
socket or is owned by another uid, which makes a plant a denial of
service rather than a hijack — but an example an operator copies should
not model a path somebody else controls. Slice 3 (`6d5b024`) moved
`docs/quickstart.html`, `docs/index.html` and `docs/views/interfaces.md`
and deferred these; four of the files carried both spellings at once.

**Closes the open item** from the 2026-09-27 entry. `git grep
"tmp/sloth.sock"` now matches only `RELEASE_v1.*.md`, `METRICS.md` and
the historical lines in this log, all of which are records of what was
true at the time and stay as they are.

**Notes**:

- Docs only — no code, CLI, JSONL or schema change. `/run/` and `/tmp/`
  are the same width, so no example's column alignment moved.
- **Open.** The consumer and forwarder examples still run without
  `sudo`, and a root-created 0600 socket refuses a different uid, so
  they likely fail with EACCES as written. Unchanged by this sweep and
  pre-existing with `/tmp`; same shape as data-socket-exposure.md §5.

## 2026-10-05 — the two threshold mechanisms reconciled (#82)

Two sessions answered the same owner decision ("each behind a config
knob") in parallel and both landed: `d652502` added three explicit flags
with module statics behind them, `4206fe7` added the generic `--tune`
registry. `main` carried two idioms for one job.

- `src/tune.{c,h}` gains `wps.pin_brute_cycles`, `wps.lockout_cycles`
  and `wps.pbc_concurrent`, plus `tune_set_id()` for setting a knob by
  id. Their `lo` is 1, not the 2 used by the other counts, because these
  three inherit the validation `alerts_set_wps_*` already published —
  widening a shipped CLI contract is the break this reconciliation
  exists to avoid.
- `src/alerts.c` drops the three statics; the setters and accessors now
  read and write the registry. Signatures and the documented 1/0 return
  are unchanged, so `--wps-pin-brute-cycles` and friends behave exactly
  as shipped.

**The bug this closed, which was not merely tidiness.** A threshold
moved through the old statics reached no export: `--wps-pin-brute-cycles
900` silenced `WPS_PIN_BRUTE` while `sensor_health` still read
`tuned_count` 0 and the health strip showed nothing. That is precisely
the "a detuned sensor must not look like a quiet one" confusion `tuned`
was added to resolve, and the flags bypassed it. Either spelling is now
recorded.

5 new cases (+35 assertions): defaults agree with the `WPS_*` macros and
the accessors; both spellings reach one value with last-writer-wins; the
flag path reaches `tuned`; the published 1/0 and reject-zero-or-less
contract still holds at the boundary; `tune_set_id()` rejects a bad id
and an out-of-range value without moving anything. Verified by mutation:
making `tune_set_id()` accept without recording turns all five red, plus
`test_wps_pbc_threshold_is_configurable` from the original slice — so the
reroute is load-bearing for the earlier coverage too.

## 2026-10-06 — `CAM_WS_DISCOVERY`: ONVIF cameras over WS-Discovery (#106 slice 1)

New passive parser `src/onvif_discovery.c` reads UDP/3702 (multicast
239.255.255.250 / ff02::c) — the OASIS WS-Discovery 1.1 multicast
protocol an ONVIF camera uses to announce itself (Hello on join, Bye on
leave, ProbeMatches/ResolveMatches answering a Probe/Resolve sloth
merely overheard). Nothing here is transmitted by sloth: every field
read (`EndpointReference`, `Types`, `Scopes`, `XAddrs`) was already put
on the wire, unauthenticated, by the device itself.

New `ALERT_TYPE_CAM_WS_DISCOVERY` (WARN, alert count 65 → 66), fired
once per distinct camera (`Types` naming a `NetworkVideoTransmitter`),
keyed by its `EndpointReference` UUID so a DHCP lease change doesn't
split one camera into two alerts. `alert_technique()` returns `""` —
same reasoning as `ALERT_TYPE_OPEN_SETUP_AP` (#80): this is the
camera's own exposure, not an adversary enumerating it, so ATT&CK T1046
(Network Service Discovery) would claim an active step sloth did not
take. Cited in `research/papers/ws-discovery-onvif.md`.

This is slice 1 of #106 — the signal picked first because it needs no
watchlist, no OUI table and no owner decision: the ONVIF scope grammar
is fully specified, so the frames are hand-buildable without a capture.
The remaining signals (mDNS/SSDP camera service types, default-credential
RTSP/HTTP, setup-mode SoftAP) are later slices on the same issue, gated
on open questions recorded there.

---

## 2026-10-07 — bounded raw 802.11 evidence ring (#92)

**Updated**: [ring-buffers.md](ring-buffers.md) — new "The evidence ring
is bounded by bytes, not by rows" variation;
[jsonl-schema.md](jsonl-schema.md) — `evict_evidence_frame` added to the
`sensor_health` eviction tally (the field list, the counted-set prose
that `tests/test_sensor_health.c ::
test_schema_doc_lists_every_counted_table` holds to the enum, and the
worked example line).

`src/evidence_ring.c` retains whole captured frames — radiotap included
— addressed by a monotonic event ID rather than by a flow. The gap it
closes: `alert_pcap_dump()` selects supporting packets by `match_ip`, so
the detections with no IP (evil twin, deauth flood, KARMA) shipped with
zero frames behind them, and the general packet ring could not stand in
because it keeps `min(caplen, 64)` bytes.

Documented as a ring-buffer *variation* rather than a page of its own:
it is the same bounded-history idea with four deviations (byte arena
plus metadata ring, RAM-scaled sizing, ID-keyed lookup, counted
eviction), and the per-record fidelity contract belongs beside the code
in `src/evidence_ring.h` where a future reader of the struct will be.

Memory-only, which is what lets it land while the question of what the
on-disk exporter may write is still open on #92: full frames include
EAPOL/PMKID material, and #87 gates *writing* that to disk. Evidence
filenames, exclusive creation, the hashed manifest and the
`storage_error` event remain unshipped — later slices, all of which
touch a file.

---

## 2026-10-08 — MLD MAC collision detector (#104 slice 4)

New `ALERT_TYPE_MLD_MAC_COLLISION` (CRIT, T1669): the same (MLD MAC,
link_id) pair reported with two different affiliated addresses.
IEEE 802.11be §9.4.2.312 ties one `link_id` to one stable hardware
address for the association's life; `mle_observe()` now counts a
later conflicting binding rather than merging it into the roster.
New research page
[802.11be-9.4.2.312-mld-identity.md](../../research/ieee/802.11be-9.4.2.312-mld-identity.md).
Alert count 68 → 69, synced across `MISSION.md`, `README.md`,
`agents/AGENTS.md`, `index.md`, `sloth.md`, `what-sloth-does.md`,
`attack-map.md`.

## 2026-10-10 — `[m]` Channel: 6 GHz no longer reads as 5 GHz (#91)

5 GHz and 6 GHz channel numbers overlap (37, 149, …), so the two
`band_for()` copies in `src/views/beacon.c` and `src/views/channel.c`
could not tell them apart — both guessed purely from the channel
*number*, and a 6 GHz AP on a number inside the 32-177 range (most of
the common ones) was labelled `5 GHz`. `docs/views/channel.md`'s own
mockup already showed channel 37 as `6GHz`, which the code could not
actually produce.

New shared `ap_band_label(channel, channel_source)` (`src/beacon_snoop.c`,
declared in `sloth.h`) checks `channel_source == CH_SRC_HE_6GHZ` first —
that subfield of the HE Operation element exists only on a 6 GHz BSS, so
it settles the question regardless of the number — and only falls back
to the numeric 2.4/5 GHz ranges otherwise. The old, unreachable 181-233
"6 GHz" branch (no real channel number is ever that) is dropped rather
than carried forward. `channel_summary_t` gained a `channel_source`
field, promoted to `CH_SRC_HE_6GHZ` and never un-set once any
contributing AP reports it, so the `[m]` Channel view's aggregated rows
get the same fix. New additive JSONL field `channel_summary.band`
(`docs/wiki/jsonl-schema.md`), so a log consumer and the TUI read the
same band for the same row.

Known, accepted gap left for a later slice: `channel_summary_t` is
still keyed by channel number alone, so a 5 GHz and a 6 GHz AP sharing
a number are still one row, not two — correctly labelled now, but still
one row's worth of `ap_count`/`Top SSID` for two different frequencies.

## 2026-10-13 — #87: --snapshot-out routed through the private-file helper

**Source**: issue #87 — `--snapshot-out` was the one created artifact
still written with a plain `fopen(path, "w")`: mode `0666 & ~umask`
(0644 under the usual 022), a symlink at the final component followed,
whatever already sat at the path neither validated nor left alone. Its
eight `fprintf`s and its `fclose` were unchecked and the function
returned 0 unconditionally, so `src/main.c` announced a truncated or
failed write as "site snapshot -> FILE". This is what retires the
"ignores write errors after open" limit recorded in the 2026-09-26
#87 entry above.

`src/wifi_snapshot.c` now opens through `sfile_fopen(AT_FDCWD, path,
SFILE_TRUNC, …)` — the same treatment `--report` already gets, because
a snapshot is an inventory of every AP in range with its security
posture. `SFILE_TRUNC` validates before it truncates, so a refused file
is left byte-for-byte intact. `sfile_fclose` folds in `ferror`, the
flush and the close, which is why the individual `fprintf`s stay
unchecked. A new `wifi_snapshot_error()` accessor carries the reason to
the caller, copying `jsonl`'s shape; no mutex, since the snapshot is
written once at shutdown on the main thread. `EXCL` was deliberately
not used: re-pointing `--snapshot-out` at last visit's file is the
documented repeat-survey workflow.

**Updated pages**:

- `docs/wiki/retention.md` — §4.1 table row for `--snapshot-out`
  rewritten to the real behaviour (0600, validated then truncated,
  snapshot skipped and the old file left as it was); the §4.1 preamble
  clause claiming one export bypasses the checks removed; the §6
  known-gap bullet deleted; "as of 1.8.2" and **Last updated** brought
  to 1.8.4.
- `docs/wiki/cli-reference.md` — the `--snapshot-out` row now states the
  on-disk contract, in the same words as the `-o` row, because the
  flag's behaviour on an existing file changed.

**Notes**:

- **User-visible on upgrade.** A `site-a.txt` written 0644 by an earlier
  sloth is now refused and left alone until the operator `chmod 600`s
  it — the same migration step c588ba9 imposed for `--db` and
  `--report`. Belongs in release notes.
- **Scope.** `wifi_snapshot_diff()` is untouched: a baseline the
  operator names is read, not created, and cd4d4c0 scoped #87's fix
  list to created artifacts. The §4 retention column is untouched —
  `--snapshot-out` still has no retention; permissions and retention
  are different axes.
- **Still open on #87, owner-only.** Q3, whether a group mode should
  exist for these artifacts (retention.md §4.1 still answers it with
  "nothing here answers it", deliberately), and the f8fd5e8 decision-4
  gap: retention for material left by a run that is no longer
  collecting.

---

## 2026-10-13 — #96: the `!persist` badge documented, and its blind spot

**Source**: issue #96 (docs that mislead an evaluator). The wave-6 slice
shipped `src/persist_health.c` and both tab-bar renderers but paid none
of the wiki duty `agents/AGENTS.md` attaches to a behaviour change: the
literal `!persist` appeared nowhere under `docs/`, `README.md`,
`MISSION.md`, `SECURITY.md` or `agents/`, and `retention.md` §6 still
told the reader the opposite of what the code now does.

**Updated pages**:

- `docs/wiki/cli-reference.md` — new top-level `## Status badges`
  section (placed after the keybinding block, before the environment
  variables, because a tab-bar indicator is not a keybinding): the
  literal badge form, failing-sinks-only, the fixed sink order, a
  worked example, the shared accessors that stop it disagreeing with
  `sensor_health.storage_failures`, and where it is not drawn.
  `**Summary**` and `**Sources**` widened to match — the page used to
  promise only flags, keys, environment variables and exit codes.
- `docs/wiki/retention.md` — §6's first known-gap bullet split in two.
  The visible cannot-persist state is now described as shipped; the
  capacity half is restated against the code: no free-space precheck,
  nothing ENOSPC-specific, and no sink that disables itself. The old
  wording ("the sink disables itself with one stderr line", "not
  implemented as of 1.8.2") was false on both counts.

**Notes**:

- **Found while verifying, not briefed.** Under ncurses the badge is
  *not* visible on the startup view: `tui_draw()` returns early for
  `VIEW_DASH` so the dashboard owns the whole screen and no tab bar is
  drawn, and `src/main.c` starts there. The ANSI fallback draws the bar
  everywhere. The wave-6 claim that a failing export is visible from
  every view holds only for the fallback front end. Documented as a
  caveat on both pages rather than implied away; the fix is a layout
  decision inside the dashboard tile and belongs in its own slice.
- **No sink disables itself** — checked all three. `sfile_fail()`
  increments a counter and latches one stderr line; JSONL `clearerr()`s
  deliberately, and the pcap and EAPOL paths open a fresh file per
  export, so there is no disabled state to enter.
- **Pinned by the build.** `test_persist_badge_documented` in
  `tests/test_docs_consistency.c` renders a badge from a seeded
  `persist_health_t` and requires `cli-reference.md` to contain the
  prefix and every sink token the formatter emits, so renaming a token
  in `src/persist_health.c` fails the suite and names the page.
## 2026-10-13 — the WPS lockout sawtooth is inspectable (#82)

**Pages touched:** `alerts.md` (a paragraph under *Tunable thresholds*
naming where `WPS_LOCKOUT_CYCLING`'s evidence is readable, and the
`Last updated` bump). `docs/views/beacons.md` is source material under
`docs/CLAUDE.md`, but the same change adds its
`## WPS lockout sawtooth (#82)` section, because the block is a
behaviour change to that view.

**Why.** `WPS_LOCKOUT_CYCLING` has fired since `d652502` and names a
cycle count in its detail string, but nothing in the TUI read the
transition ring — the only consumer of lock state outside `src/alerts.c`
was the scalar `wps_locked`. The WARN was a number the operator could
not inspect anywhere. The detail screen now renders the ring, and it
calls the rule's own `wps_lock_cycles_in_window()` rather than counting
the ring a second time, so the two figures are one number by
construction and not by review.

**Also corrected:** the `beacons.md` paragraph that still listed the
lockout-cycling and PBC thresholds as "left open for want of a citable
basis". They shipped in `d652502`; the weak-RNG vendor watchlist is what
is actually still open.

**Not done.** No new alert kind, no new view, no `VIEW_COUNT` change, no
JSONL or schema change. The WPS session table is still not
state-resident, so no session/opcode timeline is on screen; the
probe-response path still parses only the SSID tag.
## 2026-10-13 — #91: eviction tally covers rf_channel and http_flow

**Source**: issue #91. Two more bounded synthesis tables reach the
`sensor_health` tally: `src/rf_quality.c`'s per-channel RF-quality rows
(`MAX_RF_CHANNELS` 64, LRU on stalest `last_seen`) and
`src/http_log.c`'s request/response pairing slots (`HTTP_FLOW_MAX` 64,
LRU on oldest `ts`). Both LRU-evicted silently, so an operator could
not tell a channel sloth had stopped measuring, or a response that
shipped without its host and path, from an absence of either.

**Updated pages**:

- `docs/wiki/jsonl-schema.md` — `evict_rf_channel` and
  `evict_http_flow` added to the counted list and the sample record
  (appended, so no earlier field moves). The "**Not** counted"
  paragraph rewritten: it claimed the HTTP pairing table was "the one
  bounded table left without a field", which was wrong by more than
  twenty tables, and it is replaced with a named sample of those plus
  the mechanical rule (a field or it is not measured).
- `docs/views/interfaces.md` — same two corrections to the `evict`
  strip section.

**Notes**:

- `src/sensor_health.h`'s coverage paragraph carried the same false
  completeness claim ("every bounded synthesis table in sloth") and is
  corrected in the same change. Only the *counted* list is pinned to
  the build by a test; the uncounted side is prose and had drifted.
## 2026-10-13 — CLI surface gated against the reference (#103)

**Source**: `src/main.c` (argv loop, `handle_key`), `src/view_labels.c`,
`docs/wiki/cli-reference.md`.

**Changed pages**:

- [cli-reference.md](cli-reference.md) — Summary now says the flag list
  and the view-key table are checked by `make test`, and names what the
  check does not cover.
- [wiki-maintenance.md](wiki-maintenance.md) — the enforcement bullet now
  lists what `make test` actually fails on, and what is still rule-only.

**Notes**:

- The new guard is `tests/test_docs_consistency.c`, suite "CLI surface
  vs. wiki reference (#103)": five walks, each with a measured floor so a
  broken scanner cannot pass vacuously. Long options both directions
  (parser → page, page → parser), view keys page-ward, and the switch's
  key set against `view_labels[]`.
- **Nothing was out of sync when it landed.** All 44 long options and all
  34 view keys already matched. The guard exists because the hand check
  that found that does not run again — and the number the #103 triage
  comment quoted for it ("37 of them") was stale by seven options within
  two weeks.
- **What it does not catch**, stated so nobody over-trusts it: whether a
  documented flag's *description* is right (that is the advisory
  [[docs-drift-judge]]); which view a key is documented against, since
  the page's names are longer than the `view_labels[]` ones; short
  options; and the `print_usage()`/parser gap — `--no-colour` and
  `--help` are parsed and have no usage line.
## 2026-10-13 — #85: unresolved allow-list names are announced at launch

**Source**: issue #85. An `--iface`/`--monitor-only` name that does not
resolve at launch is not pinned, so `capture_frame_in_scope()` refuses
every frame arriving on it. That is the fail-closed behaviour the issue
asked for, but the startup verdict is computed from the *requested*
names (`capture_scope_verdict()` over `iface_allowed_count`), so it
returned `ENFORCED` and printed nothing even when zero names resolved.
The only reports of the real state were the Interfaces view's `scope
degraded e/r` strip and `sensor_health`'s `scope` fields — so a
headless sensor, or an interactive one sitting on the dashboard,
collected no IP traffic and said nothing about why.
`docs/views/interfaces.md` already claimed "Neither case is silent";
this makes that sentence true.

`capture_policy_unpinned()` is the pure part: allow-listed names with
no valid pin, counted and named. Matched by name rather than by pin
index so the operator reads back what they typed, and read from the
live `valid` bits, so it stays honest after a mid-run fail-closed
instead of describing only launch. `capture_scope_notice()` is the
gate, and it is the reason this is not two counts compared inline in
`main.c`: with no pcap handle `capture_run()` returns before it pins
anything, so every requested name reads unpinned and an ungated notice
would print "none of the requested interfaces could be resolved" under
the truthful `capture unavailable` line, blaming the resolver for the
handle's absence. `capture_open == 0` is therefore silent
unconditionally. Both sit above the `WITH_PCAP` guard so the test build
drives them without libpcap; `main.c` only prints.

**Not a refusal.** The exit code is unchanged. Not pinning a name
already suspends that interface's collection, and continuing on a
degraded scope is the decision already taken in `cda85c5` for a
capture that could not be opened at all. Changing that default is the
owner's call.

**Scoped to the IP capture stream**, not "no traffic": the 802.11
monitor radio is outside the `--iface` allow-list per the 2026-10-04
ruling (`bc316f5`), and a broader claim would reintroduce the false
boundary statement that ruling removed.

**Still open on #85** — unchanged: the replug policy question (a
replugged adapter stays failed closed until restart), the
`scope_dropped`-vs-`[y]`-deselect contract discrepancy, and the
`cli-reference.md` exit-code mismatch for the scope refusal (doc says
`2`, `src/main.c` returns `1`). All three are owner decisions.
## 2026-10-13 — `SURV_CLOUD_SNI`: surveillance-vendor cloud endpoints (#105 family B)

New `src/vendor_watchlist.{c,h}` — an embedded table of surveillance
platform service domains (`evidence.com`, `axon.com`, `flocksafety.com`)
with a label-boundary suffix matcher, the same semantics
`src/threat_intel.c` uses for IOC domains. Embedded rather than the
`data/surveillance_vendors.csv` with SIGHUP reload that #105 specifies:
that is an architecture-contract decision (MISSION.md §3 embeds the IOC
list on purpose) with no owner answer in the thread, so this ships the
table the way `src/wifi_oui_attacker.c` ships its OUI tables and leaves
the question open.

New `ALERT_TYPE_SURV_CLOUD_SNI` (WARN, alert count 70 → 71), fired when
a TLS SNI already in `s->tls_log` matches the table. Keyed
`surv-sni:<vendor>:<endpoint-ip>` — on the peer address rather than the
hostname, so a per-session upload host does not split one dock into an
alert per connection. `alert_technique()` returns `""`, third after
`OPEN_SETUP_AP` (#80) and `CAM_WS_DISCOVERY` (#106): T1041 and
T1567.002 describe an attacker moving data out, and a body camera
uploading to its own vendor is the system working as designed. Cited in
`research/papers/surveillance-vendor-endpoints.md`.

**Pages changed**:

- `docs/wiki/alerts.md` — `SURV_CLOUD_SNI` in the WARN tier list plus a
  new "Surveillance-vendor endpoints (#105)" section stating what a hit
  does not establish.
- `docs/wiki/sloth.md`, `docs/wiki/what-sloth-does.md`,
  `docs/wiki/attack-map.md`, `docs/wiki/index.md` — alert count 70 → 71
  (gated by `tests/test_docs_consistency.c`).

**Notes**:

- **The rule claims less than the issue asks for.** #105's success
  criterion is "is there a Flock on my street right now". A TLS SNI
  cannot answer that: a Flock camera uplinks over cellular and never
  touches a monitored LAN, so a `flocksafety.com` hit is a host on this
  network *using* the platform. The detector also cannot separate a
  docked camera uploading from a browser tab on the vendor's portal,
  and the alert detail says so rather than implying a device was found.
- **`axon.com` is a known broad row.** It is Axon's marketing site as
  well as the evidence platform's migration destination, so reading a
  product page fires the rule. Narrowing it would mean guessing at
  upload subdomains Axon has not published — a row that matches nothing
  real while still labelling whatever it does hit.
- **Still open on #105, owner-only.** Signal family A (OUI and SSID
  watchlists) is gated on the MISSION.md §2.4 reading for a
  third-party street-side device, and on whether the medium/low
  confidence tiers fire at all. The CSV/SIGHUP storage question, the
  surveillance inventory/JSONL fields, `VIEW_SURVEILLANCE`, the
  cross-signal CRIT and `SURV_DHCP_VENDOR` (which also needs DHCP
  option 60/61 parsing that does not exist) are all untouched.
## 2026-10-13 — evidence-ring citations reach the alert (#92)

**Pages touched**: [pcap-export.md](pcap-export.md) (new §4).

The 2026-10-07 entry landed the ring; the code comment at the retain
site said the event ID was dropped because "nothing records IDs on an
alert yet". That is now wired for one detector family: `on_probe_frame()`
keeps the event ID `evidence_ring_note()` returns, stamps it on the
parsed deauth frame, `deauth_victim_t` carries up to 8 per (BSSID,
victim) aggregate, and `rule_deauth_flood()` hands them to the alert
engine as `alert_t.evidence_ids[]`. A deauth flood has no IP to export
on, so this is the first route from a wireless alert back to its frames.

**Wiki debt cleared.** The ring reached `ring-buffers.md` (as a
bounded-by-bytes variation) and `jsonl-schema.md` (the eviction tally)
on 2026-10-07, but `pcap-export.md` — the page an operator reads to find
out how sloth keeps frames — had zero evidence content, and the exporter
had none anywhere. §4 now covers the ring, the RAM-scaled budget, the
ID-keyed retrieval contract, which alerts cite frames, why the *newest*
IDs rather than the first, and what is still unwired.

**Notes**:

- §4 states what is still unwired rather than implying completeness:
  nothing writes evidence frames to disk (`evidence_export.c` has no
  production caller), the IDs appear in no JSONL record and no `--db`
  column, and there is no evidence namer, manifest or `storage_error`
  event.
- It also records a defect the page's own "partial files are removed"
  claim would otherwise paper over: `evidence_export.c`'s three failure
  paths only `close(fd)`, leaving a zero-length or truncated file under
  its final name, contrary to the promise in `evidence_export.h`.
- No new `ALERT_TYPE_*`, so no `research/` citation and no rule-count
  change; `alerts.md` and the count gates are untouched.
## 2026-10-13 — `TPC_ABSENT_HIGH_BAND`: the regulatory envelope stops being inert (#101 slice 3)

**Updated**: [wifi-sigint.md](wifi-sigint.md) — the "Regulatory elements"
section is now slices 1-3, its "Still inert past storage" paragraph is
corrected (it claimed no alert type, which is no longer true), and a new
"The first finding drawn from it (slice 3)" subsection states the rule,
its four deliberate scope limits and the one corroborator that is not
available yet.

New `ALERT_TYPE_TPC_ABSENT_HIGH_BAND` (WARN, alert count 70 → 71), the
first rule to read the per-BSSID regulatory envelope slices 1-2
retained. It fires when a BSS the operator designated (`--my-bssid` /
`--my-ssid`), operating in 5 GHz, has advertised neither a Power
Constraint element (tag 32) nor a TPC Report element (tag 35) in any
beacon heard from it — IEEE 802.11-2020 §11.8 makes those two how an AP
publishes a local transmit-power ceiling, so an AP sending neither has
published none. Cited in
`research/ieee/802.11-2020-11.8-spectrum-management.md`.

`alert_technique()` returns `""`, the third rule in that position after
`OPEN_SETUP_AP` (#80) and `CAM_WS_DISCOVERY` (#106): this reports
non-compliance by the operator's own equipment, and T1557.004 — the
technique #101 proposed — would assert impersonation from a
configuration gap whose likeliest cause is a stripped hostapd build.
`agents/AGENTS.md` had described that `""` exemption as covering
`NO_MONITOR_MODE` alone, which has been false since #80; the sentence
now names both forms and the three kinds in the second one.

Chosen as the slice because it is the only one of #101's five rules that
needs neither the regulatory table (owner question 3, still open) nor a
path-loss model (owner question 2, still open) nor a new field on
`beacon_ap_t`. 6 GHz is excluded on purpose: there the power limit rides
the Transmit Power Envelope element (tag 195), which sloth does not
parse, so the absence of 32/35 would be the wrong element missing.

---
## 2026-10-13 — `CAM_SETUP_SSID`: camera setup-mode SoftAP (#106 slice 2)

New `ALERT_TYPE_CAM_SETUP_SSID` (WARN, alert count 70 → 71). `#80`'s
`OPEN_SETUP_AP` answers "an open SoftAP exists", which is equally true
of a printer, a vacuum and a camera. This answers the sentence `#106`
asks for — *a Hikvision camera is still in setup mode* — because the
device class changes what the operator does next: a camera never joined
to a WLAN was also never taken through the password change its
first-boot wizard performs.

Four prefixes, each sourced to the vendor's own onboarding
documentation: `HAP_` (Hikvision), `DAP-` (Dahua, and Amcrest as its
OEM), `EZVIZ_` (Hikvision's consumer brand), `Tapo_Cam_` (TP-Link).
`Reolink-`, `WyzeCam`, `Arlo_`, `Verkada-`, `UVC-`, `Lorex_`, `Swann-`,
`Blink-` and substring matches on `CCTV`/`surveil` were **left out
rather than guessed** — the reasons are in
`research/papers/camera-setup-softap.md`.

The design decision worth recording: the rule is **not gated on OPEN**,
unlike `OPEN_SETUP_AP`. Hikvision's `HAP_` AP and EZVIZ's AP-mode
network are WPA-protected, and the key is printed on the device label —
the last 8 characters of the serial, or the verification code. An OPEN
gate would therefore have made the issue's own headline case
undetectable. The rule reports provisioning *state* and puts the
encryption in the detail (`OPEN, unauthenticated`, `enc WPA2`, or
`enc unknown` when the beacon row never filled `enc`, which is not read
as open) rather than deciding for the operator.

`alert_technique()` returns `""`, the third rule in that position after
`OPEN_SETUP_AP` and `CAM_WS_DISCOVERY`: nobody has to be present for
this to fire. Whether `agents/AGENTS.md` should widen its `""` exemption
from "sloth's own operational state" to cover observed-device exposure
is still the owner's open question, recorded at `src/alerts.c`'s
`OPEN_SETUP_AP` case and untouched here.

Pages touched: [alerts.md](alerts.md) (new "Exposure rules" subsection),
plus the 70 → 71 count in [index.md](index.md), [sloth.md](sloth.md),
[what-sloth-does.md](what-sloth-does.md) and
[attack-map.md](attack-map.md).
## 2026-10-13 — #90: the PNL escalator wants one station, not the union

**Source**: issue #90, next slice. `src/karma_detect.{c,h}`,
`src/alerts.{c,h}`, `src/views/karma.c`, `include/sloth.h`.

**Updated pages**: [alerts.md](alerts.md), `docs/views/alerts.md`,
`docs/views/karma.md`.

The issue's third problem bullet was the one statement in the body that
was never stale: PNL overlap was measured against the **union** of
every nearby client's preferred-network list, and `KARMA_AP` escalated
to CRIT on `overlap > 0`. One SSID of a benign multi-VAP AP landing in
one passer-by's remembered list produced a CRIT — and common names
("Starbucks", a carrier hotspot) land there constantly.

**Changes**:

- `karma_pnl_client_hits()` is the new corroborating measure: the
  largest number of a candidate's advertised SSIDs found in a *single*
  station's PNL, plus that station's MAC. PineAP Beacon Response
  answers one station's probes for its whole remembered list, so that
  shape — not a union hit — is the attack's own signature.
- `KARMA_PNL_CORROB_MIN` = 2 gates the `KARMA_AP` CRIT, the
  `KARMA_W_PNL_OVERLAP` confidence weight, and the `[y]` view's `+2`
  score bonus. One rule, both surfaces, stated once in the helper's
  contract — the alert and the ranked table cannot disagree about one
  BSSID.
- The union count is now **reported only**: it stays in the detail
  (`, N in client PNLs`), stays in the `[y]` PNL column, and still
  feeds the J% denominator. When a station does corroborate, the detail
  names it (`, 3 in client PNLs (2 on 02:aa:bb:cc:dd:ee)`) so the
  operator can open `[k]` instead of trusting a count.
- The duplicate union loop is gone. `karma_pnl_union_hits()` replaces
  both the `static pnl_overlap` in `src/karma_detect.c` and the
  behaviourally identical `static karma_pnl_overlap` in `src/alerts.c`
  — the consolidation slice 1 did for the deauth helper, finally done
  for this one.
- The deauth-then-lure chain still accepts **one** PNL hit, and both
  the code comment and `docs/views/karma.md` now say why: the flood has
  already tied that station to the candidate, so the PNL entry only has
  to name a network the candidate is answering. `tests/test_karma.c ::
  test_deauth_chain` pins the asymmetry.

No new alert type, no `ALERT_TYPE_*` count change, no JSONL field, no
CLI change, no `DB_SCHEMA_VERSION` bump — `karma_candidates.score`
keeps its column with a corrected input, and `pnl_overlap` keeps its
column with its existing meaning.

**Notes**:

- **Flagged (§4.2).** `KARMA_PNL_CORROB_MIN` = 2 is a judgement call,
  same shape as the `KARMA_W_*` weights: it is the smallest count that
  cannot be a single coincidence. Deliberately not tunable —
  `KARMA_SSID_THRESH` is the knob that moves candidate volume.
- **Not done.** The three explicit states (`PMKID_OBSERVED` /
  `BEHAVIOR_CONSISTENT_WITH_ACTIVE_COLLECTION` / `CONFIRMED_ATTACK`)
  as a first-class exported field, which still waits on the owner's
  ruling about whether a never-transmitting passive sensor may claim
  `CONFIRMED_ATTACK`. The `[y]` row overflowing the documented
  100-column minimum when it carries a tool attribution, and the
  legend clipped by the `LINES - 5` page budget, are also still open;
  this change kept the rewritten legend line at 97 columns and added a
  test asserting it fits 100, but did not fix the budget itself.
- **Not done.** The J% column is still computed, rendered, persisted
  and then ignored by the severity gate. A Jaccard-based escalator is
  the obvious next narrowing and is deliberately out of this slice.
## 2026-10-13 — Queued-frame release detector (#107 shape B)

**Pages touched**:

- `docs/wiki/wifi-state-of-the-art.md` — Framing Frames
  (CVE-2022-47522) gains an entry. The class had shipped a detector
  (`PM_FORGE`, shape A) with no entry on the radar page, which
  `CLAUDE.md` requires per vulnerability class; this is the change that
  makes it a two-shape detector, so the entry covers both and states
  which third shape is structurally undetectable passively.
- `docs/wiki/alerts.md` — `QUEUE_EVICT` added to the
  "corroboration before intent" section. It is the first rule where the
  *observable itself* is indistinguishable from ordinary behaviour, so
  the doctrine decides the whole severity ladder rather than just the
  wording.
- `docs/wiki/jsonl-schema.md` — `evict_queue_evict` joins the
  per-table eviction tally (additive; gated by
  `tests/test_sensor_health.c :: test_schema_doc_lists_every_counted_table`).
- `docs/wiki/index.md`, `docs/wiki/attack-map.md`,
  `docs/wiki/what-sloth-does.md`, `docs/wiki/sloth.md` — 70 → 71 alert
  rules, gated by `tests/test_docs_consistency.c`.

**Notes**:

- **Ownership deliberately does not escalate this rule on its own**,
  which is a departure from `PM_FORGE` and is written down in both the
  rule comment and the `docs/views/alerts.md` row. A downlink burst
  after a roam is the most common event on an operator's own network.
- **Shape C is not coming**, barring an owner decision to ship an
  open-network-only detector: the A-MSDU inner-subframe headers the
  comparison needs are inside the encrypted body on any protected BSS.

## 2026-10-14 — alert-engine eviction is fair between rules (#96)

`evict_oldest()` kept preferring resolved incidents, but among live ones
it now evicts the oldest entry of whichever `ALERT_TYPE_*` holds the
**most** slots instead of the oldest entry overall.

Written because the same defect was found and fixed three separate times
in one session, each time inside the rule that happened to trip it:

- **#105** — `SURV_CLOUD_SNI` keyed on an endpoint address *the remote
  side chooses*, so ordinary CDN rotation turned 200 rows from one
  benign host into 127 incidents and filled the ring.
- **#107** — `QUEUE_EVICT`'s `release_count` was unbounded in time, so
  one roam fired forever and 128 roams saturated the ring.
- **#96** — 128 `BEACONING` tracks re-firing every tick churned the ring
  continuously, and because a reused slot is memset (clearing
  `pcap_dumped`), that churn is what wrote 16.1M duplicate pcaps.

Each fix bounded one rule's cardinality. None stopped the *next* rule
doing the same thing, because the engine had no notion of fairness at
all — a grep for a per-type budget across ~200 `ALERT_TYPE_*` references
found nothing. The shared resource is 128 slots; the policy belonged
there, not in each of 75 detectors.

Deliberately not a quota. With ~75 types and 128 slots an equal share is
one or two each, and most types hold nothing most of the time, so a hard
cap would idle most of the ring. Evicting the greediest type is
work-conserving: one rule may hold all 128 slots unopposed and gives one
back the moment another rule fires, so a quiet rule that keeps firing
converges on a fair share. The guarantee is not a reserved slot per
rule — it is that no rule can hold the ring against another
indefinitely.

Three tests in `tests/test_alerts.c`, each mutation-proved against a
distinct mutation: reverting to globally-oldest reddens the two
starvation tests, and introducing a real per-type cap reddens all three
(the third exists to pin the *absence* of a cap).

The change also broke two pcap-cooldown tests, in the way a correct
change should: their harness flooded `PORT_SCAN` until the lone
`THREAT_IP` entry was evicted, and under fairness a rule holding one
slot is the last thing evicted, so the flood can no longer reach it.
The harness moved to the other route to the same slot reuse — let the
incident **expire**, since `fire()` only treats a key as seen while its
entry is live — rather than the policy bending to the test. Expiry is
also the more faithful route: it is what actually recycled slots in the
field, 300 s at a time.

Pages: [[alerts]], [[retention]], `docs/views/alerts.md`.

## 2026-10-14 — +HTC/Order misread as HT Control on non-QoS data frames (#95)

`dot11_data_header_len()` added four bytes for an HT Control field
whenever the +HTC/Order bit was set in a data frame's Frame Control.
That bit has two unrelated meanings (IEEE 802.11-2020 §9.2.4.1.10), and
HT Control is present only in **QoS Data and Management** frames
(§9.2.4.6). In a non-QoS data frame the bit is the StrictlyOrdered
service class and no field follows it, so the header is the plain 24.

Four bytes of skew on one attacker-chosen bit, with three consequences,
all of them the "invents data" failure `src/dot11_data.c` is written to
avoid:

- **Detector evasion.** `first_frag_ethertype()` found no `AA AA 03` at
  the shifted offset and returned −1; its caller reads −1 as nothing to
  see (`if (et < 0 || et == ETHERTYPE_EAPOL) return;`), so a plaintext
  unicast frame with that bit set walked past `FRAG_PLAINTEXT`
  (CVE-2020-26140 / -26143) unrecorded.
- **Invented evidence.** `dot11_ccmp_pn()` read the CCMP header four
  bytes late and returned a PN assembled from payload bytes — precisely
  what that function already refuses to do for a WEP/TKIP IV.
- **Invented EtherType.** `dot11_data_payload()` read LLC/SNAP from
  mid-payload: usually `NOT_SNAP` and a dropped frame, but `AA AA 03`
  occurring there yields an EtherType and payload offset invented from
  the middle of the packet.

**Why the existing gates could not have caught it.** Every offset stayed
in bounds, so there is no memory error for ASan/UBSan or the four fuzz
targets to find — this is a semantic misparse, and #95's own fuzzing
work would not have reached it. A pcap fixture would not have either:
`fragattacks.py` does not set that bit, so its frames parse correctly
under the bug. It was found by reading the clause against the code,
which is the one method none of the automated gates implement.

`tests/test_dot11_data.c` had asserted 28 for this case since #72 and
the code agreed, so the suite was green on a shared wrong belief — the
test was the thing that had to change, with the IEEE clause as the
authority. Mutation-proved in both directions: restoring `if (order)`
reddens the two parser tests and the detector test; removing the
HT Control addition entirely reddens the QoS tests.

Also consolidated the A-MSDU presence check. It existed in three copies
with **two different bounds** — `dot11_data_payload()` guarded with
`qos_off + 1 < len`, `dot11_amsdu_present()` with `qos_off >= len` — so
a frame carrying exactly one byte of QoS Control was "A-MSDU present" to
one and uninspected by the other. Both refused the frame, so nothing was
misparsed, but two bounds for one field is how a divergence arrives. All
three sites now call the helper.

Pages: [[fragattacks]].

## 2026-10-14 — three more management parsers read their bodies at a fixed 24 (#95)

Follow-on to the +HTC/Order entry above, and the reason that one was
worth generalising: the same clause was being got wrong in three more
parsers, and each had its own hardcoded offset.

A management frame with the +HTC/Order bit set carries a 4-octet HT
Control field between Sequence Control and the body (IEEE 802.11-2020
§9.2.4.1.10, §9.3.3.2), so the body starts at 28, not 24.
`src/deauth_snoop.c` handled that correctly and cited the clause while
doing it. The other three did not:

| parser | hardcoded | what the skew did |
|---|---|---|
| `src/action_snoop.c` | 24 | Category read out of HT Control, matching no `ACTION_CAT_*` — so **CSA, RRM and BTM all declined the frame silently**. Spoofed channel-switch and forced-roam detection, evaded by one bit. |
| `src/assoc_track.c` | 24 | Capability, Listen Interval and the whole IE list read 4 octets early, so the SSID and the RSN "ask" that feed the WPA-downgrade delta and the PNL/KARMA correlation came from the wrong place. |
| `src/beacon_snoop.c` | 36 (24 + 12 fixed) | Beacon interval out of HT Control, Privacy bit out of the Timestamp, IE walk started inside the Timestamp — SSID, channel, RSN, TSF and the vendor / IE-order fingerprints all wrong. |

The offset now lives in one place, `dot11_mgmt_hdr_len()`, and all four
parsers call it — including `deauth_snoop.c`, which gave up its correct
local copy so that there is nothing left to diverge from. Note the
contrast with the data-frame function beside it: for a management frame
the bit means +HTC outright, with none of the QoS-subtype condition the
data case needs, which is exactly the kind of difference that invites
four hand-rolled copies.

**Why nothing caught this.** `action_parse_category()` rejects a frame
whose Frame Control byte 0 is not `0xD0`, but the +HTC bit is in byte
**1**, so the guard never excluded the frames being mis-read. Every
offset stayed in bounds, so the sanitiser and fuzz jobs were blind to it
for the same reason as the data-frame case. And `deauth_snoop.c` had a
test for exactly this (`test_parse_htc_shifts_body`) — it just never
generalised to its three siblings. Mutating the shared helper back to a
fixed 24 reddens all six new tests *and* that pre-existing deauth test,
which is the cleanest statement of the asymmetry: one parser had both
the code and the test, three had neither.

Pages: [[fragattacks]] for the data-frame half.

### Addendum, same day — two more sites, and the gate that caught it

`src/capture/probe.c` had the same hardcoded offset twice, and it is the
file where it matters most for the Wi-Fi detectors:

- **Probe requests** walked the IEs from 24, so a probe request with
  +HTC set contributed **no SSID to the preferred-network list** — and
  the PNL is what the KARMA correlation is built on.
- **Probe / (Re)Association responses** read the status code and the IE
  list from 24, so `beacon_reveal_hidden_ssid()`, `assoc_observe()` and
  the queue-eviction session note all received the wrong bytes.

Both now call `dot11_mgmt_hdr_len()`. Covered by
`test_probe_request_pnl_survives_the_htc_bit` in the capture-path suite,
driven through the real `pcap_dispatch` seam, and mutation-proved.

**The gate gap this exposed is worth more than the fix.** The first
version of the management-header change passed `make test`,
`make test-capture-path` and all six `-Werror` configs locally, and then
**failed CI** — `make fuzz` could not link `fuzz_deauth_parse` or
`fuzz_beacon_parse_ies`, because each fuzz target keeps a hand-written
source list and `deauth_snoop.c` and `beacon_snoop.c` had just gained a
dependency on `dot11_data.c`. The narrow link is deliberate (it is what
puts the fuzzer's redzoned buffer directly under the parser), so the
hand-kept list is the price, and it rots silently.

Separately, `src/capture/probe.c` is in `CAPTURE_PATH_SRCS` but **not**
in `TEST_SRCS`, so `make test` cannot report even a compile error in it
— a `hdr` name collision there was visible only to
`make test-capture-path`.

`agents/AGENTS.md` now says both: six configs are not the whole build
surface, and `make fuzz FUZZ_SECONDS=1` plus `make test-capture-path`
belong in the local gate run after touching any module they link.

## 2026-10-14 — MISSION.md §2 rule 1 rewritten: one absolute, not four exceptions (#84, unblocks #102)

Applied today under the operator's explicit authorisation; the text is
the final draft posted on #84 on 2026-10-06, unchanged except for the
attribution line. The charter is never the agent's to change on its own
(`agents/dark-factory.md` §4.3), and the permission layer had refused
the edit twice before — correctly.

Rule 1 used to say sloth never injects, never scans, never resolves a
host it had not already seen, and never modifies network or host state,
then listed two "narrow exceptions". Those absolutes were not kept:
`--hop` (#22) retunes the receiver, a routable `--data-socket` (#29)
publishes an mDNS service file, `--allow-active` (#84) sends a
reverse-DNS query and asks the kernel to scan, and opening a capture
handle sets **promiscuous mode behind no flag at all** — the fourth was
never in the document. Four is where exceptions have become the rule.

The owner's ruling, verbatim: *"as long as sloth's sensors are not
injecting it's fine to have optional services that use the network."*
So the line is drawn where it can be held. **No injection** — never
crafting and sending a frame onto a network sloth is monitoring — is the
one absolute, with no flag, build option or mode that turns it off.
Optional services may use the network from the host over paths the
operator configured. Two properties still hold and are what "passive"
is now worth: sloth never puts an interface into monitor mode, and every
network-using service is opt-in and announced (`--allow-active` prints
what it enabled; `--strict` locks it all off). Promiscuous mode is
stated as the one write that is neither, because it is inherent to
capturing. Rule 2 (no active key recovery) is untouched.

Shipped behaviour does **not** change: `--hop`, `--allow-active` and
discovery stay off by default. What changes is that keeping them off is
now convention rather than charter.

Moved in lockstep, since each restated the retired wording:
`agents/AGENTS.md` (the one-line summary), [[what-sloth-does]] (summary
and "What it never does"), [[sloth]], [[non-ip-sensors]], and
`.github/scripts/docs_drift_prompt.md` — which would otherwise have
instructed the drift reviewer to enforce a sentence the charter no
longer contains. `README.md` and [[monitor-mode]] claim only that sloth
never injects over the air, which remains true, and stand.

#102 (slothweb) was held against the old text, which forbade a local
HTTP surface; it is no longer charter-blocked.

## 2026-10-14 — `make mutate` had been aborting since #73 (#108)

The sandbox copied a hand-kept tuple of directories; `TEST_SRCS` outgrew it
at #73 and every run since aborted at "baseline not green". Fixed by
deriving the sandbox from `git ls-files`, pinned by a recipe test. First
real run: baseline green, 1,392 sites, one sampled mutant survived at
`alerts.c:2201` (`g_arp_hist`, → #110). Details: [[mutation-testing]].

## 2026-10-14 — fragattack gets its mutex; the packet ring becomes a snapshot (#111)

Architecture slice S3, the one the 2026-10 review called "the one known
data race". `src/fragattack.c` had zero `pthread_mutex` calls while
`frag_observe()` / `frag_note_association()` ran on the probe thread
and `frag_snapshot()` / `rule_fragattack()` on main. Separately, the
wired packet ring on `sloth_state_t` was written by the capture thread
under `capture.c`'s *private* `g_mu` and read lock-free by seven
main-thread modules — a lock no reader could take.

Shipped: one module mutex in `fragattack.c` (every entry point takes
it and calls a `*_locked()` body) plus `frag_bss_copy()`, which
`rule_fragattack()` now uses instead of a pointer into the live table;
a private ring in `capture.c` with `capture_ring_snapshot()` called
first in `poll_data()`, head/count/total semantics unchanged so no
reader moved. `capture_test_dispatch()` seeds the ring from the
caller's state and snapshots back, so the capture-path suite's
`sloth_state_t` stays premise and result.

Proof is ThreadSanitizer, as the issue specified: the two concurrent
tests pass with the locks deleted (single writer, no lost update) and
the TSan build of each binary goes red on the same mutation.

Pages: [[ring-buffers]] (new variation section), [[architecture]]
(capture-pipeline seam, state paragraph), [[fragattacks]] (new
Threading section, Testing addendum). `README.md`'s data-flow
paragraph gained one sentence.

---

## 2026-10-14 — One clock seam; taint TTL read the wrong clock (#109)

**Source**: `src/sloth_clock.{h,c}`, `src/flood_window.h`, `src/alerts.c`,
`tests/test_clock_seam.c`, `tests/test_alerts.c`.

**Change**: `sloth_wall()` / `sloth_mono_ms()` / `sloth_clock_test_set()`
are now the single clock seam; the #88 `flood_*` names in
`flood_window.h` forward to it until their last caller migrates.
`evil_twin_bssid_is_tainted()` read `time(NULL)` while the mark was
stamped through the seam, so under a test clock the taint never matched
and an NTP step mis-aged the TTL in production; both sites now read
`sloth_wall()`. `alert_pcap`, `dns`, `cleartext_creds`, `top_hosts`,
`seqnum_track` and `assoc_track` moved off `time(NULL)` in the same
commit; `tests/test_clock_seam.c` scrapes the migrated files and fails
on a regression. Remaining direct sites (snoopers, jsonl, main, views,
capture, probe, beacon/deauth snoop) migrate in later slices.

**Pages**: [[architecture]] (new "Clock seam" bullet), [[alerts]],
[[jsonl-schema]] (seam location).

---

## 2026-10-14 — File-write hardening: the two secure_file bypasses, NOFOLLOW pinned, reentrant clock (#134)

`src/secure_file.c` (#87) is where every root write is meant to go, and
a sweep in the 2026-10 architecture review found the writes that did
not. Closed in one slice, each with a test seen red under the mutation
the issue named before it was committed green.

- **`discovery_publish()` followed symlinks.** `fopen(out, "w")` on
  `/etc/avahi/services/sloth.service` as root, no owner check, truncated
  whatever a planted link pointed at (CWE-59, CWE-367). Now:
  `sfile_system_dir()` pins the directory (new; root- *or* euid-owned,
  not group/other-writable, `O_DIRECTORY|O_NOFOLLOW`, never created),
  `O_EXCL` temp inside it, `fsync`, `fchmod 0644` (deliberate: avahi
  reads it; content is hostname + port), `renameat` over the final
  name, `unlinkat` through the held fd on unpublish. Test plants the
  name as a symlink to a sentinel; sentinel survives, link replaced by
  a regular 0644 file. Mutation: fopen writer restored → sentinel
  overwritten → red. The existing publish tests moved from `mkstemp` in
  `/tmp` to a private `mkdtemp`, because a `1777` directory is now
  refused by design and a test asserting that was added.
- **`sfile_open(dirfd, name)` took any name.** `eapol_export_create()`
  passed the evidence-export name straight through, so `"../x"` would
  have left the pinned directory the day a TUI prompt or the socket
  supplied one (CWE-22). A real dirfd now refuses empty, `.`, `..` and
  any `/` with `EINVAL`; `AT_FDCWD` operator paths keep their slashes.
  Mutation: guard disabled → `../escape` created in the parent → red,
  through both `sfile_open()` and `evidence_export_pcap()`.
- **`SQLITE_OPEN_NOFOLLOW` was `#ifdef`-optional.** On sqlite < 3.31 it
  compiled away silently and the advisory side-file checks in
  `db_prepare_private()` stood alone against a TOCTOU they cannot win.
  `src/db.c` and `research/query.c` now `#error` below 3.31.0 and pass
  the flag unconditionally; `rq_open()` gained it.
- **`alert_pcap.c` used `localtime()`**, the last writer still on the
  non-reentrant clock (CWE-663); `localtime_r`, as `pcap_write.c` has
  since #95.
- **`w` in Packets writes to the working directory**, documented rather
  than changed: no flag, no directory check; the shipped unit should pin
  `WorkingDirectory=` (X6).

Pages: [[pcap-export]] (CWD note, bare-name rule, `localtime_r`),
[[data-socket-exposure]] (how the service file is written),
[[sqlite-schema]] (the compile-time pin). New `tests/test_secure_file.c`.

One correction to the issue text: the manual packet export is bound to
`w` in the Packets view (`src/views/packets.c`), not `[p]`, which is the
NTP view switch; `src/pcap_write.c` is the right file either way.

## 2026-10-14 — one bounded keyed table (`stab_t`) replaces eight copied evictors and three refuse-forever tables (#110)

**Source**: `src/stab.{h,c}`, `src/{bgp,ldap,kerb,smb,ssh,rdp,snmp,mqtt,mdns,nbns}_snoop.c`,
`src/alerts.c` (ARP-spoof history), `src/sensor_health.{h,c}`, `tests/test_stab.c`.

**Updated pages**:

- [ring-buffers.md](ring-buffers.md) — new section *Keyed tables: `stab_t`*: the three
  policies, which table uses which, and why the tie-break is not an equivalent mutant.
- [jsonl-schema.md](jsonl-schema.md) — eleven `evict_*` fields appended
  (`bgp_session` … `arp_hist`); the uncounted list loses the eight snoopers plus mDNS and
  NBNS; two new paragraphs on what `mdns_service`/`nbns_name` count (refusals, not
  reclaims) and on the `arp_hist` baseline consequence.

**Notes**:

- Before this, `g_arp_hist`, the mDNS service table and the NBNS name table refused every
  new key for the life of the process once full. mDNS/NBNS are now `STAB_REFUSE_AGING`
  (3600 s) and the ARP baseline is `STAB_OLDEST`; all eleven tables reach the tally.
- `test_arp_spoof_history_overflow_safe` had encoded the refuse-forever rule as its
  premise, and its "overflow" IP carried MAC `01:…` — multicast bit set — so the rule
  skipped it before the guard it claimed to kill. Replaced by
  `test_arp_spoof_history_full_evicts_oldest_and_tallies` with a unicast MAC.
- mDNS `instance[64]` was looked up with a full-length `strcmp` against a truncated copy, so
  a >63-char instance name created a new row per packet; `key_eq` now compares on the
  stored width.
- The FragAttacks tables stay on their own idiom until the locking slice (S3) lands.

## 2026-10-14 — `make install` + a shipped hardened systemd unit (#139)

New page [[deployment]]; linked from the index under "UI and
infrastructure". [[data-socket-exposure]] §5.4 no longer says "no
systemd unit ships in-tree", because one now does. `agents/FACTORY.md`
§7 still says "no template shipped" — that file is batched in another
slice and was not edited here, so until that lands §7 is the stale one
and this page is the authority.

What shipped, all under `packaging/` (AGENTS.md forbids new files at the
repo root only): `systemd/sloth-sensor.service`,
`systemd/sloth.sysusers.conf`, `bin/sloth-monitor-up` (copied verbatim
from `/usr/local/sbin` on the reference sensor, where it had lived
outside the repo since 2026-09-26) and `default/sloth`. `make install`
now also places the helper and `research.db`, honours `DESTDIR`, and a
new `make install-service` puts the unit, the sysusers fragment and the
defaults file (with `install -b`) in place. Make never calls `useradd`;
`systemd-sysusers` does.

The unit runs as `User=sloth` with `AmbientCapabilities=CAP_NET_RAW
CAP_NET_ADMIN` and an equal bounding set, `ProtectSystem=strict`, state
in `StateDirectory=sloth`, the data socket on a `unix:` path under
`RuntimeDirectory=sloth`, and a `@system-service` syscall filter minus
`@privileged @resources`. `systemd-analyze security --offline` scores it
1.6 (systemd 261); recorded on the page, not gated. This removes uid 0
from the process with no code change; the in-process drop (X7) is
defence in depth on top.

`tests/test_unit_file.c` scans the shipped files. Each assertion of
absence was mutated red before it was claimed, with the inverse edit
restoring green each time (`grep -c` proved presence both ways):

- `User=sloth` → `User=root` (the mutation the issue names):
  `test_unit_runs_as_the_sloth_account` red.
- `AF_INET` appended to `RestrictAddressFamilies=` on the `unix:`
  profile: `test_unit_flag_pairs_are_consistent` red.
- `--eapol-dir /var/lib/sloth/eapol` added to `ExecStart` without
  `--collect-handshakes`: `test_unit_flag_pairs_are_consistent` red.
- `CAP_SYS_ADMIN` appended to `CapabilityBoundingSet=`:
  `test_unit_capabilities_are_exactly_the_two` red.
- `ExecStart` pointed back at `/home/<user>/Projects/sloth/sloth`:
  `test_unit_executes_installed_paths_only` red (two assertions: the
  raw `/home/` scan and the `/usr/local/bin/sloth` prefix).
- `useradd -r sloth` inserted as the first `install-service` recipe:
  `test_makefile_install_targets` red.

One deviation from the issue text: `packaging/default/sloth` ships
`SLOTH_ARGS=--site-label sloth-sensor` with `--my-ssid`/`--my-bssid`
shown as a commented example, not the reference site's real SSID and
BSSID. Those are operator data; the migration recipe on the page tells
the operator to edit the file, and the test asserts the real SSID is
not in the shipped copy.

## 2026-10-14 — Action frames honour the Protected bit; Beacon Request mode read from octet 9 (#124)

[[action-frames]] gains a section on what the Protected Frame bit
means for every detector on that page, and [[jsonl-schema]] carries a
contract note on `rrm_beacon_request.measurement_mode`.

Two defects in `src/action_snoop.c`. **B:** `action_parse_category()`
never checked FC B14, so on a PMF link it read PN0 of the CCMP header
as the category: `SA_QUERY_FLOOD` was nearly blind where SA Query
exists and could fire from a 1/256 PN0 coincidence; the CSA, RRM and
BTM parsers ran on ciphertext when PN0/PN1 lined up. The parser now
returns `ACTION_PARSE_PROTECTED` (-2) before reading the body,
`action_observe()` tallies the frame under `action_protected_count()`
and stops, and the `[a]` deauth view shows the tally as `protected
action: N` beside the BTM count (`docs/views/deauth.md`). **C:** the
Beacon Request Measurement Mode was read from element octet 11 (BSSID
octet 1, `0xff` on every wildcard request) instead of octet 9
(§9.4.2.20.7); `measurement_mode` values before this date are not
modes.

The tests had not caught B because `build_action(..., protect=1, ...)`
wrote a plaintext category into a Protected frame. That flag is gone
from both `tests/test_action_snoop.c` and `tests/test_alerts.c`; the
protected form is now built by a CCMP-header helper that cannot be
given a category, with PN0 chosen to look like SA Query or WNM. Six
protected-frame tests and one mode test, each mutation-proved. The
`docs/views/alerts.md` `SA_QUERY_FLOOD` row carries the scope note:
unprotected SA Query only, which on a non-PMF BSS is itself a finding.
No length heuristic for protected SA Query in this slice.

## 2026-10-14 — Threat model page: assets, adversaries, trust boundaries (#133)

New page [threat-model.md](threat-model.md): the five assets
(A1 captured third-party data, A2 sensor host, A3 operator decision
surface, A4 downstream parsers, A5 build/provenance), the four
adversaries (ADV-1 on-air/on-wire, ADV-2 local unprivileged account,
ADV-3 operator-supplied files, ADV-4 upstream compromise), the seven
trust boundaries (TB-1 pcap edge through TB-7 build/CI) with what is
enforced and what is known unchecked at each, and the finding → boundary
map for the 2026-10 architecture review with a CWE, a status and an
owning Track X slice per row. Every security issue from here on cites
the IDs instead of restating the model. Linked from `index.md` under
"Start here".

Re-verifying the issue body against the tree moved five map rows from
"finding" to "closed" or "narrowed" before the page was written: the
`discovery.c` `fopen` and the `eapol_log.c` name passthrough (#134), the
`NOFOLLOW` `#ifdef` (#134, now a compile-time floor), `alert_pcap.c`'s
`localtime()` (#134, `localtime_r`), and the unit executing the build
tree (#139). The page records the tree as it is dated, not as the issue
described it; cited line numbers in the issue (`capture.c:1115`,
`probe.c:268`) had drifted by a few lines and the page names the
functions instead. Two facts the issue did not state were checked and
added: no `sqlite3_db_config()` call exists anywhere in `src/` or
`research/`, and the data-socket stall timer runs only while bytes are
queued, so an idle peer is held indefinitely.

No code in this slice; `test_docs_consistency` is the gate (wikilinks,
relative links, index reachability, counts).

---

## 2026-10-14 — Data-socket hygiene: per-peer slot cap, idle timeout, loopback-TCP notice (#135)

**Source**: `src/data_socket.c`, `src/data_socket.h`, `src/tune.c`,
`src/tune.h`, `src/jsonl.c`, `src/main.c`, `tests/test_data_socket.c`,
`tests/test_tune.c`.

**Updated pages**:

- [data-socket-exposure.md](data-socket-exposure.md) — new §4.1 "Slots
  and idle": who counts as a peer (`SO_PEERCRED` uid on `unix:`,
  `getpeername` address on `tcp:`, one shared capped bucket for the
  unidentifiable), what happens over the cap, the idle rule and why 900 s
  is three heartbeats, what the cap does **not** guarantee, and the new
  loopback-TCP start-up notice. The page also gained the
  Summary / Sources / Last-updated header it had been missing.
- [cli-reference.md](cli-reference.md) — the `--tune` row names
  `socket.max_per_peer` (4, 1..16) and `socket.idle_secs` (900, 0 =
  never); the `--data-socket` row names the notice.
- [jsonl-schema.md](jsonl-schema.md) — `sensor_health` gains
  `socket_peer_refused` and `socket_clients`, appended after `tuned`;
  example line updated.

**Notes**:

Before this slice `MAX_CLIENTS 16` was the only limit on the data
socket, and the 30 s stall timer ran only while a client held queued
bytes, so one peer could take every slot and a client sloth never wrote
to kept its slot for the life of the process (CWE-770). The cap is
decided at `accept()` from what the kernel vouches for; an
unidentifiable peer is capped, never exempt. No default changed: the
bare-flag `tcp:127.0.0.1:8765` is announced as readable by every local
account (CWE-306) and left for #136's ruling.

Four mutations, each applied with `sed`, proven present with `grep -c`,
run red, reverted with the inverse `sed`, proven absent, run green:

- `peer_slots(&peer) >= cap` → `>`: `test_per_peer_cap_refuses_the_extra_connection`,
  `test_per_peer_cap_default_is_four`, `test_per_peer_cap_frees_with_the_slot`,
  `test_unknown_peers_share_one_capped_bucket` red (12 assertions).
- `c->off < c->len &&` re-added to the idle condition:
  `test_idle_client_is_closed_with_nothing_queued`,
  `test_idle_clock_restarts_on_delivery` red.
- `peer.kind != DS_PEER_UNKNOWN &&` gating the cap (unknown = unlimited):
  `test_unknown_peers_share_one_capped_bucket` red, and only it.
- `idle > 0 &&` removed (no off switch): `test_idle_zero_disables_the_rule` red.

One existing test's premise expired: `test_tick_caps_at_max_clients`
feeds dup'd listener fds through the accept seam, which are all
"unknown" and so now stop at the per-peer cap of 4. It pins the
*global* guard, so it opens `socket.max_per_peer` to 16 and its claim
stands; the unknown-bucket cap has its own test. The two clock-seam
stall tests now install the injected clock *before* the accept, because
with an idle rule a client stamped from the real monotonic clock on a
seconds-old CI host would read as idle on the first injected tick
(#109's lesson).

## 2026-10-14 — Decode each 802.11 frame once: `dot11_frame_t` view, `tests/frame_build.h`, EAPOL +HTC fix (#122)

**Why.** ~12 observers re-derived type/subtype/flags/header length/
Protected/addresses from the raw `(dot11, len)` pair, and
`src/dot11_data.c` was an opt-in helper rather than a choke point. The
three +HTC fixes of 2026-10-14 (#95) were one instance of the class;
`src/eapol_log.c` still carried a seventh copy of the header formula
that added HT Control for every data frame with the Order bit set, so a
non-QoS StrictlyOrdered EAPOL frame (§9.2.4.1.10) had its LLC header
read four bytes late and the handshake was silently missed. Every
offset stayed in bounds; ASan/UBSan and the fuzz targets are
structurally blind to this class.

**What landed.**

- `src/dot11_frame.{h,c}` — `dot11_frame_decode()` fills a
  `dot11_frame_t`: type/subtype/flags, `has_qos` / `has_htc` /
  `has_addr4` (the §9.2.4.1.10 rule lives here and nowhere else),
  `hdr_len`, datapad-aware `body_off` / `body_len`, positional `a1..a4`
  and Table 9-26 roles (`bssid`/`sa`/`da`/`ta`/`ra`, NULL when the
  clause defines none — control frames are RA/TA only, a WDS frame has
  no single BSSID), `seq_num` / `frag_num` / `tid` / `amsdu` (−1 when
  absent), and the radiotap `fcs_stripped` / `bad_fcs` record.
  `dot11_frame_body()` refuses a Protected body; `dot11_frame_payload()`
  locates LLC/SNAP with the `dot11_data` status codes;
  `dot11_fcs_strip_len()` is the FCS arithmetic for a possibly
  truncated capture. Runt → 0 with `hdr_len == -1`; type-3 Extension
  frames are reported, not decoded.
- `src/dot11_data.c` — every entry point is now a wrapper over the view;
  the formula body is deleted. `tests/test_dot11_data.c` was the
  regression net for that commit (unchanged, 17666 before and after).
  One narrowing: `dot11_data_header_len()` / `dot11_mgmt_hdr_len()`
  return −1 for a frame of the other type instead of computing a header
  the frame does not have.
- `src/radiotap.c` — `radiotap_info_t` gains `fcs_present` and
  `datapad`, the two FLAGS bits the view consumes (both were stepped
  over before).
- `tests/frame_build.h` — spec-derived builder: `fb_dot11_hdr()` appends
  FC, Duration, A1–A3, SeqCtl, then A4 / QoS / HTC **iff the test says
  so** — presence is stated, never inferred from the flags, which is
  the difference between a builder that checks the parser and one that
  copies it. `fb_fcs()` is the real 802.3 CRC-32 (check value pinned);
  `fb_ciphertext()` never starts `AA AA 03`; `fb_radiotap()` builds a
  header with FLAGS / CHANNEL / DBM_ANTSIGNAL in bit order.
- **Fix A** — `src/eapol_log.c :: eapol_observe_dot11()` takes
  `dot11_data_header_len()` and `dot11_data_addrs()`; its own formula
  and address switch are deleted. Own commit, because `eapol_log.c` is
  +20 on the risk gate. See [[pcap-export]] §3.

**Mutation (A).** `has_htc` rule in `src/dot11_frame.c` changed from
`order && (type == 0 || has_qos)` to `order` (`grep -c` = 1 applied,
0 after the inverse edit): 33 assertions red across
`test_m1_non_qos_strictly_ordered_is_recorded` (eapol),
`test_header_length_table` (frame view),
`test_order_bit_adds_nothing_without_qos`,
`test_order_bit_composes_with_four_address` (dot11_data) and
`test_order_bit_does_not_hide_a_plaintext_frame` (fragattack).
`test_m1_qos_with_htc_is_recorded` stayed green, as it should — the two
cases are separable. Restored green.

- **Decode once in `probe.c` / `capture.c`.** `on_probe_frame()` strips
  the FCS radiotap announces (`dot11_fcs_strip_len(caplen, origlen,
  fcs_present)`, so a snaplen-truncated capture strips only the trailer
  octets it still holds), builds one `dot11_frame_t` with the
  FCS/DATAPAD/BADFCS hints, and reads `type`/`subtype`/`retry`/`a1`/
  `a2`/`bssid`/`sa`/`da`/`seq_num` and the body from it; every inline
  `dot11[...]` read and `dot11_mgmt_hdr_len()` call in that function is
  gone. The observers keep their `(dot11, len)` signatures this slice.
  `capture.c :: decode_frame()` gained `origlen` and its
  `DLT_IEEE802_11_RADIO` arm goes `radiotap_parse` → hints →
  `dot11_frame_decode` → `dot11_frame_payload`, with the FCS taken off
  the length handed to the IP decoder and DATAPAD honoured (a 26-octet
  QoS header puts LLC/SNAP at 28; before, such a frame was dropped as
  bare LLC).
- **Fix I** — the stale `if (dot11_len < 36) return;` ahead of the
  assoc/reassoc/probe-response arm is deleted; the floor is the view's
  header plus the subtype's fixed part (`mhdr + 6`, or `+ 12` for a
  probe response). A 30–35-octet (re)association response is legal and
  now reaches `assoc_observe()`. A Protected (ciphertext) body in that
  arm is refused by `dot11_frame_body()` instead of parsed.
- Operator-visible: the monitor packets band's per-frame length now
  excludes the FCS when radiotap says one is present; a CTS/ACK that
  arrives with trailing octets no longer shows a TA made from them;
  short association grants appear in the assoc view. No JSONL value
  changes.
- Builders converted to `frame_build.h`: `test_eapol_log.c ::
  build_frame` (now `build_frame_opt`, capped at exactly 24 + 8 + n
  because `feed_exact()` mallocs that many — the first draft capped at
  a round 256 and ASan-less `free()` caught the heap overrun instead),
  `test_capture_path.c :: mon_frame`, and `test_dot11_data.c ::
  build_data` in its own commit — that one computed the header length
  with the production formula, so it was a tautology.

**Mutation (I).** `if (dot11_len < 36) return;` reinserted at the top
of the assoc/probe-response arm in `src/capture/probe.c` (`grep -c` =
1 applied, 0 after the inverse `sed '/.../d'`): 10 assertions red in
`tests/test_capture_path.c :: test_a_short_assoc_response_records_the_grant`
(both the 30- and the 33-octet response), driven through
`probe_test_dispatch()`. Restored green, 431/0 in `sloth_test_pcap`.

**Not claimed.** Observers other than `eapol_log.c` still re-derive
header fields from `(dot11, len)` through the `dot11_data` wrappers;
their migration to taking the view directly is the next slice. The
`src/action_snoop.c` copy is owned by a parallel slice this round and
was not touched here.

## 2026-10-15 — Derived source lists, `libsloth_core.a`, per-config object directories (#115)

**Why.** The Makefile kept seven source lists by hand — `SRCS`,
`TEST_SRCS`, `CAPTURE_PATH_SRCS`, `FUZZ_EAPOL_SRCS` and three inline
lists in the `fuzz` recipe — and the inline ones rotted first: on
2026-10-14 two fuzz targets failed to link in CI because a module they
named gained a dependency they did not. The six build configs also
shared one object directory, which is why `make clean` between configs
was a rule rather than a habit.

**What landed** ([[architecture]] "Build layout").
- `APP_SRCS` (`main.c`, `tui.c`, the real platform vtable) and
  `CORE_SRCS` (everything else the current `WITH_*` config compiles,
  filtered from `CORE_SRCS_ALL` by feature group). `sloth` links the app
  objects plus `build/<cfg>/libsloth_core.a`.
- `sloth_test` takes `$(wildcard tests/*.c)` minus the capture-path
  pair; its core is `CORE_SRCS_ALL` minus `probe.c` plus
  `src/reset_all.c` and the research tools' library halves, derived from
  `RESEARCH_SRCS`/`MCP_SRCS`. `sloth_test_pcap` is the same with
  `-DWITH_PCAP` and probe.c back in.
- `make fuzz`: one rule, `build/fuzz/bin/fuzz_%` from
  `tests/fuzz/fuzz_%.c` and a clang-built core archive (plus the null
  renderer and fake platform). The archive keeps targets narrow —
  `fuzz_radiotap_parse` still links no snooper or alert code. Binaries
  moved from `/tmp/sloth_fuzz_*` to `build/fuzz/bin/`.
- Object directories `build/n?p?w?s?/`, `build/test/`,
  `build/test-pcap/`, `build/fuzz/`, each with a flags stamp so a changed
  `EXTRA_CFLAGS` recompiles, and a member stamp so a dropped source
  leaves the archive. `sloth` relinks on a config switch. `-MMD`
  replaces the `TEST_HDRS` wildcard. `build/` is ignored.
- `make cppcheck` is unchanged: it still scans `src research`, the exact
  command CI runs. A new test holds the two argument lists equal until
  #119 makes CI call the target.

**Tests** (`tests/test_build_recipe.c`): no `$(CC)`/`$(FUZZ_CC)`
command names a literal `.c`; no variable spells out a `tests/` source
other than as a `filter-out` exclusion, and `TEST_SRCS` is the
wildcard; `CFG_TAG` names all four feature flags and the bare
`%.o: %.c` rule is gone; the cppcheck target's arguments equal ci.yml's.
`BR_MAX_LINES` raised to 4096.

**Mutations.** (a) `src/radiotap.c` added to the fuzz link recipe →
`test_no_compile_or_link_command_names_a_source` red; (b) a
`TEST_EXTRA = tests/null_tui.c` line → `test_no_variable_spells_out_a_test_file`
red; (c) `$(WITH_PCAP)` dropped from `CFG_TAG` →
`test_object_dir_is_per_config` red; (d) cppcheck scan args replaced by
`$(CORE_SRCS) $(APP_SRCS) research` → `test_cppcheck_target_matches_ci`
red; (e) `src/dot11_frame.c` deleted from `CORE_COMMON_SRCS` → `sloth`,
`sloth_test`, `sloth_test_pcap` and three of four fuzz targets fail to
link (`fuzz_radiotap_parse` does not reach it and still links — the
narrow property). Each restored by an inverse edit, green again.

**Not done here.** `agents/AGENTS.md` still says "Update the Makefile
SRCS and TEST_SRCS" and keeps the `make clean` between configs rule;
ci.yml keeps its own cppcheck command. Both are `agents/`/`.github/`
edits, batched into #119.

## 2026-10-15 — Bare `--data-socket` defaults to `unix:/run/sloth/sloth.sock` (#136)

Owner ruling 2026-10-15 on #136: the bare flag stops meaning loopback
TCP. A `tcp:127.0.0.1:8765` listener is readable by every local account
(CWE-1188, threat model TB-4), and it was what an operator got for
naming no transport at all.

- Bare `--data-socket` → `unix:/run/sloth/sloth.sock`. `/run/sloth` is
  validated by `sfile_system_dir()` — real directory, not a symlink,
  owned by root or the effective uid, not group/other-writable — and
  never created or chmod'ed.
- Failure exits `2` with the remedy (`RuntimeDirectory=sloth`, or
  `install -d -m 0750 -o <euid> /run/sloth`, or the explicit
  `tcp:127.0.0.1:8765`). **No silent TCP fallback.**
- Explicit `unix:`/`tcp:` specs unchanged. The shipped unit already
  passes the `unix:` spec explicitly, so production is unaffected.
- Code: `data_socket_default_spec(run_dir_ok)` (pure),
  `data_socket_default_dir_ok()`, `data_socket_default_refusal()` in
  `src/data_socket.c`; `src/main.c` argv parsing and `--help` text.
- Pages: [[cli-reference]], [[data-socket-exposure]] (§1 table, new
  §1.1, §4.1 notice, §5.1 typed spec), [[jsonl-schema]] transports,
  [[threat-model]] TB-4. README and `examples/stunnel/README.md` now
  type the loopback spec.
- Guards: `tests/test_docs_consistency.c ::
  test_data_socket_default_documented` pins `--help`, the
  cli-reference row and README to `DATA_SOCKET_DEFAULT_SPEC`;
  `test_main_assigns_no_tcp_default` reads `src/main.c` for a TCP
  literal assigned to the spec.

## 2026-10-15 — Radiotap applied before parsing: one gate, DATAPAD out, FCS false positives pinned (#123)

**Why.** #122 gave `radiotap_info_t` `fcs_present` / `datapad` and taught
both monitor entry points to strip the FCS and decode with the hints.
Three things in #123 were still open: `on_probe_frame()` read `it_len`
itself and discarded `radiotap_parse()`'s verdict, so an `it_len` below
the 8-octet fixed header (which the parser rejects) was accepted and the
"802.11 frame" began inside the present bitmap (defect H); the
data-frame observers in `probe.c` take a bare `(dot11, len)` and put
LLC at the end of the MAC header, so with DATAPAD an EAPOL handshake
was read two octets early and missed; and nothing in the capture-path
suite pinned what the FCS strip buys a beacon — `fuzz_ie_overruns`
climbing on every healthy beacon on ath9k/rt2800 (`MGMT_FUZZ` on clean
air) and `ie_order_hash` suppressed (defect G).

**What landed.**

- `src/capture/probe.c` — `if (!radiotap_parse(...)) { tally; return; }`
  is the gate, and `rt.hdr_len` the offset; the private `it_len` read is
  gone. Refusals are counted in `mon_radiotap_reject_total()` and
  published as `capture_health_t.parse_rejects` by
  `probe_health_poll()`.
- `src/capture/probe.c` — for data frames, when the view's `body_off`
  exceeds `hdr_len` the pad is removed into a static buffer before
  `eapol_observe_dot11()`, `frag_observe()`, `pm_forge_observe()` and
  `queue_evict_observe_downlink()` run. Removing it once, rather than
  teaching four observers the hint, also keeps the EAPOL collector's
  verbatim `DLT_IEEE802_11` handshake export free of pad octets. The
  evidence ring still keeps the capture exactly as delivered.
- `src/views/iface.c` — `mon rt-reject N` on the health strip, only when
  non-zero. Not in JSONL.
- Docs: [[monitor-mode]] Limits, [[jsonl-schema]] `beacon` row
  (semantics corrected, no field change), `docs/views/beacons.md`,
  `docs/views/interfaces.md`.

**Tests** (`tests/test_capture_path.c`, through `probe_test_dispatch()` /
`capture_test_dispatch()`): FCS beacon with a `DD 7F 00 00` trailer →
`fuzz_ie_overruns == 0`, `ie_order_hash != 0`, and the same octets with
the flag clear → 1 overrun, hash 0 (the control); DATAPAD QoS EAPOL M1
→ one event, flag clear → none; DATAPAD+FCS UDP/53 query →
`dns_log` record; `it_len = 4` → no frame, reject tally +1, health poll
agrees; 100 bad-FCS frames still reach the monitor ring, the evidence
ring and `rf_quality` (100 % bad-FCS). `tests/test_state.c`: the strip
entry.

**Mutations** (each `grep -c` = 1 applied, 0 after the inverse edit,
green restored):

- `rt.fcs_present` → `0` in `on_probe_frame()`'s
  `dot11_fcs_strip_len()` call: red in
  `test_an_fcs_beacon_walks_no_phantom_element` and
  `test_fcs_is_stripped_before_the_frame_is_recorded`.
- `out->body_off = need;` in `dot11_frame_decode()`: red in
  `test_a_datapad_eapol_m1_reaches_the_collector`,
  `test_a_datapad_dns_query_reaches_the_dns_log`,
  `test_radiotap_datapad_frame_reaches_the_ip_decoder`.
- depad block disabled (`if (0 && ...)`) in `probe.c`: red in
  `test_a_datapad_eapol_m1_reaches_the_collector` only.
- `radiotap_parse()` return discarded: red in
  `test_a_short_radiotap_length_is_refused_and_counted` and the
  oversized-`it_len` case of
  `test_monitor_seam_rejects_frames_below_the_guards`.
- `mon rt-reject` printed unconditionally: red across the
  `test_health_strip_*` quiet cases and
  `test_health_strip_reports_radiotap_rejects`.

**Not claimed / deferred.** Bad-FCS frames are still parsed by every
per-type observer — pinned, not decided; that policy is open. The IP
stream's `cap_health.parse_rejects` stays 0: `capture.c`'s radio arm
already gates on `radiotap_parse()` but does not tally (it returns one
"not decodable" for many reasons, and splitting them is the sensor-health
tally work, `SH_PF_RADIOTAP_BAD`, P5). `radiotap_parse()` still does not
check `it_version == 0`.

## 2026-10-15 — Privilege drop after capture opens, default on for root runs (#140)

**Source**: `src/privdrop.c`, `src/privdrop.h`, `src/main.c`,
`src/capture/probe.c` (`probe_set_iface`),
`packaging/systemd/sloth-sensor.service`, `tests/test_privdrop.c`,
`tests/test_unit_file.c`, `tests/test_capture_path.c`.

**Updated pages**:

- [cli-reference.md](cli-reference.md) — new "Privilege" group:
  `--user NAME` (default `sloth` when the account exists) and
  `--no-privdrop`; the three stderr announcements; what a dropped run
  can no longer do (`[m]` onto a new radio, the other-user pid map,
  writing `/etc/avahi/services`); exit-code `2` row gains the four
  privdrop refusals.
- [deployment.md](deployment.md) — §3.3 "Inside the process": what is
  shed and when, the steady-state `CapEff: 0000000000001000` under the
  shipped `--hop` unit, and the hand-run default; §3.5 the new
  `SystemCallFilter=capset` re-allow and why it is safe; §5 the
  `/proc/<pid>/status` check; §6 no longer says there is no in-process
  drop.
- [monitor-mode.md](monitor-mode.md) — new section: why `CAP_NET_RAW`
  is needed only to open the radio and `CAP_NET_ADMIN` for every
  `--hop` retune.
- [threat-model.md](threat-model.md) — TB-2 "Enforced since #140" and
  its remaining unchecked cases; the §5 row for "Root for the life of
  the process" moves to **Closed**.

**Notes**:

Owner ruling 2026-10-15, "only use root when necessary", made this a
default rather than the opt-in the issue body first proposed. The split
follows `observe_resolve_profile()` (#84): `privdrop_resolve()` is a
pure plan, `privdrop_apply()` performs it with raw `capget`/`capset`/
`prctl`/`setres[ug]id` (no libcap) and reads every step back, failing
closed with exit `2`.

Placement in `main()`: after `capture_open()`/`probe_open()` and the
scope verdict, before `--pcap-dir`/`--eapol-dir`/`-o`/`--db`/socket/
discovery open — so every sink is created as the account the run lives
as and `secure_file.c`'s ownership check holds against that account.
`dns_init()` moved below the drop because it starts the `--allow-active`
resolver thread, and `capset`/`no_new_privs` are per-thread: a worker
created earlier would have kept root's set.

Deviations from the issue body, each forced by the kernel or the
ruling: the apply order runs `PR_CAPBSET_DROP` **first**, while
`CAP_SETPCAP` is still effective (after `capset` or a `setresuid` away
from 0 it is gone and the drop would `EPERM`); the bounding drop is
skipped when `CAP_SETPCAP` is not held (the shipped unit, whose own
`CapabilityBoundingSet=` already does that job); `keep_net_admin` is
`(hop || allow_active) && held`, because `capset` cannot grant a
capability the permitted set lacks; `PRIVDROP_NONE_ROOT_ANNOUNCED`
became `PRIVDROP_ROOT_KEEP_UID` (uid 0 kept, capabilities shed) plus
`PRIVDROP_DISABLED` (`--no-privdrop`), since the ruling forbids a root
run that silently stays fully root.

`capset` is in systemd's `@privileged`, which the shipped unit denies.
Measured with `systemd-run --user` under the unit's filter lines: the
binary exits `2` at the drop ("capset: Operation not permitted")
without the new `SystemCallFilter=capset` line, and runs with it. The
binary and the unit therefore have to be upgraded together.

`probe_set_iface()` now opens the new handle before stopping the old
one. A dropped run has no `CAP_NET_RAW`, so `[m]` onto a new radio
fails at the open; stopping first would have turned that refusal into
a lost radio.

**Mutations (each applied, `grep -c` = 1, red, inverse edit, `grep -c`
= 0, green).**

1. `keep_net_raw = 1` in `privdrop_resolve()` — 6 tests red, including
   `test_net_raw_is_never_kept_by_a_shedding_plan` (24 shedding plans
   checked) and the forked apply test (the child cannot `capset` a cap
   it does not hold).
2. `want_admin = req->hop` (the `allow_active` term dropped) —
   `test_allow_active_alone_keeps_net_admin` and
   `test_describe_names_uid_account_and_kept_cap` red.
3. `exit_code = 0` on `REFUSE_NO_SUCH_USER` —
   `test_unknown_user_is_refused_with_exit_2` red.
4. The `PR_SET_NO_NEW_PRIVS` call removed from `privdrop_apply()` —
   `test_apply_unprivileged_plan_sets_nnp_and_sheds` red (child exit 10,
   the readback refuses).
5. `ROOT_KEEP_UID` with `shed_caps = 0` (the "silently stays fully
   root" case) — 4 tests red.
6. `SystemCallFilter=capset` commented out of the unit, and separately
   moved onto the `@system-service` line *before* the deny —
   `test_unit_sandbox_keys_present` red both times.
7. The pre-#140 `probe_iface` clear put back in the failed-open branch
   of `probe_set_iface()` —
   `test_a_failed_retarget_open_keeps_the_current_radio` red in
   `sloth_test_pcap`.

**Not claimed.** The root half of `privdrop_apply()` — `setresuid`,
`setgroups`, `PR_CAPBSET_DROP`, ambient clear under real caps — cannot
run in CI (non-root) and is the hand checklist on the issue:
`CapEff: 0000000000001000` with `--hop`, `0` without, `NoNewPrivs: 1`,
`chan_retune_failures` staying 0. That a live probe worker survives a
refused `[m]` needs a real radio and is argued from the code.

## 2026-10-15 — Alert identity: hash-first lookup and incident side state (#112)

`find_by_key()` compares a 64-bit FNV-1a per slot before `strcmp`
(which still decides — a forced-collision test proves it), and looks a
key up as it will be stored, so an over-long key no longer opens a new
incident every tick. `pcap_cool[]` became a per-key side table that
also carries `pcap_path`, `pcap_write_failures`, `reopen_count` and,
after an eviction only, `first_seen`. `alert.*` records gain the
additive `reopen_count`. Pages: [[jsonl-schema]], [[alerts]].

## 2026-10-15 — Typed alert-key builder (#112)

`src/alert_key.h`: MAC / IP / number / token / hex / remote-string /
set components, each with a fixed shape. A remote string is a
sanitised readable prefix plus the FNV-1a of the full string, so two
values sharing a prefix can no longer merge into one incident the way
`%.30s` merged them. Overflow yields `""` and `fire()` now refuses an
empty key. The nine rules that put remote-chosen text in a key migrate
one per commit; [[alerts]] → *Dedup key shapes* carries the
before/after table, [[jsonl-schema]] the `key` note.

## 2026-10-15 — View and alert-type lists generated; prose counts markered (#117)

`include/sloth_views.def` and `include/sloth_alerts.def` are X-macro
lists; `sloth_view.h` / `sloth_alert.h` (re-included by `sloth.h`)
expand the enums, and the label table, `view_for_key()`, the `tui.c`
draw dispatch, the `main.c` view dispatch and view-select, and the
`alert_type_name()` / `alert_technique()` tables are expanded from the
same rows, length-pinned by `SLOTH_STATIC_ASSERT`. The hardcoded
`VIEW_COUNT == 35` tests are gone. View and rule counts on [[sloth]],
[[what-sloth-does]], [[views-catalog]], [[index]], [[attack-map]],
README and MISSION.md sit in count markers (HTML comments) that
`make docs-counts` rewrites and `make test` checks. No behaviour change:
same keys, same order, same enum values. Pages: [[architecture]] →
*Generated lists*, [[alerts]], [[views-catalog]], [[cli-reference]],
[[wiki-maintenance]], [[jsonl-schema]].

## 2026-10-15 — The poll tick becomes a declared phase table (#113)

Architecture slice S5. `main.c :: poll_data()` sequenced ~45 calls by
hand, sat in a file no test binary links, and had drifted into five
verified stale reads plus a sixth found while moving them (channel
summary before `beacon_snapshot()`). `src/poll.{h,c}` replaces the body
with `poll_tick()` over `g_poll_stages[]` — PLATFORM, SNAPSHOT, DERIVE,
ALERTS, POST, EMIT, DURABLE — and one `poll_ctx_t` clock reading per
tick through the seam. `tests/test_poll.c` pins the table invariant and
runs the real table end to end on the fake platform; every reorder was
mutation-proved (move the stage back, watch its test go red).

Contract: JSONL record **order within a tick** changed — state records
now follow the tick's alerts and describe this tick, not the previous
one. Shapes and fields unchanged.

Pages: [[architecture]] (new *Tick* section, capture seam),
[[jsonl-schema]] (*Order within a tick*, cadence), [[ring-buffers]],
[[sqlite-schema]] (write path).

## 2026-10-15 — Fuzz the parsers about to be refactored (#125)

Six libFuzzer targets ahead of the Track P rewrites, so each rewrite
has a sanitizer baseline to keep: `fuzz_action_observe`,
`fuzz_assoc_request_parse` (which also hands a parsed request's MLE body
to `mle_parse()` — one parser's bounds trusted by another),
`fuzz_mle_parse`, `fuzz_dns_read_name` (over `dns_log_parse()` until
P10a lifts name decoding out), `fuzz_tls_log_parse` and
`fuzz_decode_frame`. The last reaches the static `decode_frame()`
through a new seam, `capture_test_decode_frame()`, and not through
`capture_test_dispatch()`: libpcap's offline buffer runs past each
record's caplen, so only a direct call puts the fuzzer's redzoned
buffer under the decoders.

#115 had already made the plain targets a wildcard, so those five
needed no Makefile edit. `decode_frame` lives inside `WITH_PCAP`, so it
gets `FUZZ_PCAP_TARGETS` and a second archive (`build/fuzz-pcap/`,
`-DWITH_PCAP`, `-lpcap`); `make fuzz` runs it after the plain targets.
The CI fuzz job's runner has no `libpcap-dev`, so `FUZZ_PCAP=auto`
(default) prints a `SKIPPED` line there instead of failing;
`FUZZ_PCAP=1` makes it fatal once that job installs the package.
[[architecture]] → build section carries the mechanism.
`test_every_fuzz_harness_is_built` holds the list to `tests/fuzz/`.

## 2026-10-15 — One bounded reader, one TLV iterator, a parse-fault tally (#126)

`src/bytes.h`: `be16/be32/le16/le32/le48`, a bounded cursor (`rd_t`,
short read → 0 + sticky fault, never past the end) and one TLV iterator
(`tlv_next`, 1+1 and 2+2) with one overrun policy — stop and report.
`sensor_health` gains `parse_faults` and nine `parse_fault_<kind>`
fields from a sibling enum (`sh_parse_fault_t`), kept out of both the
`evictions` sum and the change-only signature. Some kinds are reserved
for later slices and reported as unmeasured, not as zero faults.
Page: [[jsonl-schema]] → *Parse faults*.

## 2026-10-15 — Operator-supplied files are untrusted bytes (#137)

`rq_open()` sets `DEFENSIVE`, `TRUSTED_SCHEMA=0`, no extension loading
and a 1 MiB `SQLITE_LIMIT_LENGTH`, reads each back, and refuses a corpus
whose `research` is not the FTS5 table or that holds a view or trigger;
`MATCH` still works. `db_open()` sets `DEFENSIVE`. The manifest reader
fails on a C0/DEL byte in `latest`/`url`; a bad roster line is echoed
bounded and sanitised; the snapshot writer escapes SSID and label
(`\t` `\n` `\\` `\xHH`, `\x2d` for a literal `-`) and the reader
unescapes and range-checks channel/mfp with `strtol`. Pages:
[[research-corpus]], [[sqlite-schema]], [[manifest-format]],
[[wifi-sigint-techniques]] (snapshot format), [[cli-reference]],
[[threat-model]] (TB-6, two risk rows closed).

## 2026-10-15 — the batched `.github` / `agents` edit (#119)

One commit instead of four +40s. CI's fuzz job installs libpcap-dev and
runs `FUZZ_PCAP=1`, so `fuzz_decode_frame` (#125) runs in CI instead of
being skipped. CI's cppcheck job is now `make cppcheck` - the duplicated
command and the test that pinned the two copies together are gone, a
test asserting there is one copy replaces it. `agents/AGENTS.md`: the
view/alert recipes describe the `.def` X-macro lists (#117) and the
derived source lists (#115); the gate list includes both test binaries
under ASan+UBSan; the "make clean between configs" rule is downgraded
now objects are per config. `agents/converge.md` gains the sibling-grep
rule. [[architecture]] gains "do not add arrays to `sloth_state_t`".

## 2026-10-18 — the suite is built the way the program ships (#116)

`sloth_test` is compiled `WITH_NCURSES` + `WITH_PCAP` and links
`src/tui.c` and `src/capture/probe.c`. Views draw into an offscreen
ncurses screen (`tui_init_offscreen()`, `newterm()` over `/dev/null`);
`tui_test_line()` / `tui_test_screen()` read the cells back through the
wide-char API, and `tests/runner.h` gains `ASSERT_LINE_HAS`,
`ASSERT_SCREEN_HAS` and `ASSERT_SCREEN_LACKS`. The capture-path suite
runs inside `make test`; `sloth_test_pcap`, `tests/null_tui.c` and
`tests/test_capture_path_main.c` are deleted, and `make
test-capture-path` is an alias for one release. `make
sloth_test_noflags` builds the suite without either flag, link-only.
`probe_clear` joins `SLOTH_RESETS` (its exclusion existed only because
probe.c was not linked). First compile of `dashboard_bands.c` in the
test build found the packets-band bargraph comparing a truncated slot
against the untruncated info string, so a long info took a new slot per
packet; it now matches on the stored form, and `dashboard_info_clear()`
resets the table. The `[m]` key tests in `test_iface_graph.c` would now
have opened the host's interfaces; they go through the `--iface`
allow-list refusal instead. Pages: [[architecture]], [[sloth]],
[[cli-reference]].

## 2026-10-19 — #116 continued: view tests assert what they draw

`tests/test_views_render.c` drives every `sloth_views.def` entry
through `tui_draw()` (tab selection by reverse video, body equals the
view's own draw, dashboard has no tab bar, wrapped tab bar, a seeded
row for the two draws nothing called) and ratchets `ASSERT(1)`: 98 at
the start of the slice, 10 left, none of them a render test. The ones
left are sanitizer-only no-crash checks with nothing observable to
assert: `test_action_snoop.c`, `test_chanhop.c`, `test_capture.c`,
`test_dns_snoop.c`, `test_fragattack.c`, `test_fragattack_view.c`
(NULL snapshot), `test_jsonl.c` (two), `test_karma.c` (NULL key
buffer), `test_pcap_format.c`. Reading the screens back found five
display defects, each fixed with the assertion that found it: the
dashboard's KARMA `!` badge was drawn into the cell the panel separator
then overwrote and had never shown; the DNS log's Answer column sat two
cells right of its header on unselected rows; the WiFi detail pane
padded the signal value and printed `dBm` under the next column; the
packet detail pane said "build with WITH_PCAP=1" from code compiled only
WITH_PCAP; the process tree's fold set had no reset, so one test's fold
leaked into the next (`view_procs_fold_clear()` joins `SLOTH_RESETS`).
`test_procs.c`'s detail case used PID 99 and printed the host's process;
it uses a PID above any `pid_max` now. Pages: [[mutation-testing]].

## 2026-10-18 — process memory on `sensor_health` (#121)

The production sensor reached 7.7 GB RSS over twelve days on the
pre-2026-10-14 binary and the stream never said so. `sensor_health`
now carries `rss_kb`, `rss_hwm_kb`, `sqlite_mem_kb`,
`sqlite_mem_hwm_kb`, `malloc_kb`, `fd_count` and `resolver_calls`,
appended after the parse-fault breakout, `-1` for "not measured", and
outside the change-only signature (sampled only after a line is already
going out). Read-only samples of the new binary on the issue showed
RSS flat (+720 kB over 2 h 18 m, `[heap]` +8 kB, no NSS mapped), so
the growth lived in code the 2026-10-14 fixes removed; these fields are
what would show a recurrence. [[jsonl-schema]].

## 2026-10-18 — the remaining thresholds into the `--tune` registry (#120)

Forty rows appended to `src/tune.c`. Five are the flags that parsed
with `atoi()` or a private `strtol` — `--correlate-retain`,
`--handshake-retention`, `--db-interval-secs`, `--db-retain-days`,
`--db-max-mb` — now aliases through `tune_set_value()`, so `5x` and
`abc` exit 2 naming the knob instead of becoming 5 and "default"; the
`--wps-*` aliases lost their `atoi()` the same way. The other
thirty-five are the detector thresholds that were still `#define`s
(`scan.*`, `deauth.flood_*`, `beacon.flood_*`, `auth.flood_*`,
`assoc.flood_*`, `probe.flood_*`, `btm.abuse_*`, `saq.flood_*`,
`rts.flood_*`, `bd.*`, `queue_evict.*`, `transit.*`, `presence.*`,
`seqnum.corr_*`). The `#define` stays as the default and the row reads
it; the use site reads the knob. Ring-backed counts cap at the ring.
`sensor_health.tuned` reports them with no schema change. Clearing the
`[j]` seqnum table no longer resets `--correlate-retain`. Pages:
[[cli-reference]], [[jsonl-schema]], [[retention]].


## 2026-10-18 — element helpers once: SSID, PHY tier, OUI vendor (#127)

`src/dot11_ie.{h,c}` holds the SSID copy, the PHY-tier classifier and
the vendor-IE OUI table that were each written two or three times.
Defect F fixed: probe_pnl.c read Element ID Extension 81 as Multi-Link
and ignored 106/107, so `pnl_client.phy` disagreed with `beacon.phy`;
both now use 106/107/108 and ext 81 alone reads `legacy` on both (and in
`wifi_assoc_req.phy`, which shares the beacon parser). The WPS
attribute walk in `beacon_parse_ies` and the WSC walk in `eap_parse.c`
moved onto the shared iterator and now count in `ie_overrun`.
Page: [[jsonl-schema]] → *Parse faults*.

## 2026-10-18 — Supply-chain basics, first slice (#142)

`db_open()` and `rq_open()` refuse a **loaded** sqlite below 3.31.0
(`src/libver.c`); the compile-time `#error` (#134) cannot see the
library the dynamic linker picks. `sloth --version` gains two lines
naming the loaded libpcap and sqlite, and `sensor_health` gains `libs`
with the same two, appended and outside the change-only signature.
`make check-deps` (run by `all`) applies pkg-config floors — sqlite
3.31.0, libpcap 1.9.0 — fatal when unmet, a one-line notice when
pkg-config or a `.pc` file is absent. `make sbom` writes a CycloneDX
1.5 SBOM of the five link deps (`tools/sbom.sh`). `tests/test_ci_pins.c`
gains a `runs-on: *-latest` classifier; the workflow half of the slice
(runners to `ubuntu-24.04`, the `sbom` and `release-attestation` CI
jobs) did not land and is the open remainder. New page
[[release-checklist]], including the manual `git tag -s` step. Pages:
[[jsonl-schema]], [[cli-reference]], [[version-checkin]],
[[threat-model]] (TB-7 and its risk row, partly closed).

## 2026-10-19 — #142's CI half: pinned runners, SBOM job, release attestation

The builder's workflow edit was refused by the permission classifier;
this one came from the main session. All nine `runs-on: ubuntu-latest`
are now `ubuntu-24.04`, and `test_no_workflow_runs_on_a_moving_image`
scans every workflow (putting `-latest` back in one turns it red). CI
gains an `sbom` job (`anchore/sbom-action` v0.24.3 by full digest), and
`.github/workflows/release-attest.yml` attests the binary and writes
`SHA256SUMS` on `v*` tags (`actions/attest-build-provenance` v4.2.2 by
full digest). Tag signing remains manual. [[release-checklist]],
[[threat-model]].

## 2026-10-19 — `src/alerts.c` split by domain behind an ordered rule table (#118)

The 5,370-line `src/alerts.c` is now `src/alerts/`: `engine.c` (the
incident ring, `fire()` and its variants, eviction, side table, taint
tracker, snapshot, pcap export, `alerts_update()`), `rules_table.c`
(the rule order and nothing else), and five rule files — `rules_wired.c`
(25 rules), `rules_wifi_mgmt.c` (21), `rules_twin.c` (12),
`rules_enterprise.c` (5), `rules_mle.c` (5). `alerts_update()`'s
hand-written sequence of 68 calls became a loop over
`g_alert_rules[]`, copied verbatim; rule bodies moved unchanged.
`src/alerts.h` did not change. New `tests/test_alert_rules.c` holds the
table to the rule definitions (every rule run exactly once) and pins
the order dependencies by name: `rule_deauth_flood` and
`rule_evil_twin` before `rule_evil_twin_attack_chain`, and
`wifi_downgrade_update()` before the loop. `make mutate` defaults to
the engine and the five rule files. Not moved, because this slice could
not edit them: `.github/scripts/mutate-equivalents.txt` and
`docs_drift.py` / `docs-drift.yml` still name `src/alerts.c`, and so
does `agents/AGENTS.md`'s "How to add an alert rule". Pages:
[[alerts]], [[mutation-testing]], [[architecture]], [[threat-intel]],
[[jsonl-schema]], [[where-exploits-happen]], [[btm-abuse]].

## 2026-10-19 — RSN element parsed once; SAE-EXT-KEY is WPA3 (#128)

`src/rsn_ie.c` is the one RSNE (§9.4.2.24) parser: every field
including PMKIDs and the Group Management Cipher, a Version check, and
`truncated` set when a declared count or a fixed field runs past the
element (the suites that fit are kept). `beacon_parse_ies()` and mle.c's
per-STA-profile reader both use it; mle.c's private cipher-rank table is
gone. **Contract change**: `enc` on `beacon`, `wifi_ap` and
`twin_episode` is now `WPA3` for a BSS offering only SAE-EXT-KEY (AKM
24/25), which logged `WPA2` before — the label now uses the same
`RSN_AKM_FAMILY_SAE` predicate as `akm_bits`. The reserved
`parse_fault_rsn_malformed` is wired, and `fuzz_truncated_rsn` also
counts an overrunning count. Pages: [[jsonl-schema]]; per-view doc
`docs/views/beacons.md`.

## 2026-10-19 — Pcap-edge input gate (#141)

New `src/capture/frame_edge.{c,h}`: `frame_view_init()` is the first
call in both `on_packet()` and `on_probe_frame()` and refuses a record
whose caplen is 0, above 65535, or above its own origlen, or whose
`ts_usec` is outside 0–999999; the callbacks read the resulting
`frame_view_t`, never `hdr`. `frame_view_radiotap()` is the one radiotap
gate (verdict, FCS strip, 10-octet 802.11 minimum) for both radio entry
points — #123 had already made `probe.c` honour `radiotap_parse()`'s
return; this removes the second copy of the rule in `capture.c`.
Refusals land in the #126 parse-fault tally as a new appended kind,
`frame_edge` (`sensor_health.parse_fault_frame_edge`, additive). Tests:
`tests/test_frame_edge.c`, three capture-path cases, and
`tests/fuzz/fuzz_frame_edge.c`. The IPv4 Total Length clamp the issue
also named is #132's. Pages: [[architecture]], [[jsonl-schema]].

## 2026-10-19 — one render/export sanitisation choke point (#138)

`src/netstr.{c,h}`: `display_sanitize()` (UTF-8 aware; invalid octet,
C0 except `\n`, DEL, C1 and the bidi controls → `?`) runs on every
string `TPRINT` (now `tui_printf()`), `t_puts`/`t_putn` and the views'
former direct `printw`/`addstr` emit, in both backends.
`netstr_copy()` (C0/DEL → `?`, high octets kept) is the ingest copy for
name-class fields — the SSID once, in `dot11_ie_ssid_copy()`, plus
qname, NBNS, DHCP hostname, SNI, QUIC host, HTTP Host/UA and mDNS
names. `json_escape()` output is always valid UTF-8 (`�` for an
invalid octet; DEL, C1, U+2028/9 `\u`-escaped) — informational, not a
break: every value that parsed before parses the same. CEF and syslog
map C0/DEL/C1 to a space. Pages: [[jsonl-schema]] (common envelope,
versioning note), [[threat-model]] (TB-5 closed, residual stated).

## 2026-10-19 — #119: `--replay` / `--ticks` and the `replay-check` gate

The remaining half of #119 (owner ruling 2026-10-15). New flags
`--replay FILE[,FILE]` and `--ticks N`; `make replay-check` runs the
shipped `sloth` on savefiles that `tests/replay/gen_replay.c` builds at
run time from `tests/frame_build.h` arrays, normalises the JSONL and
diffs it against the committed `tests/replay/golden.jsonl`. CI gains a
`replay` job and a sanitized replay step in `sanitize`; `mutate.py`
gains `--target {test,replay-check,all}`. Created [[replay-integration]]
(linked from [[index]]); updated [[cli-reference]] (Replay group, exit
code 1, build targets), [[jsonl-schema]] (`capture_iface` /
`monitor_iface` = `replay`), [[mutation-testing]] (`--target`).

## 2026-10-19 — #132: one transport dispatch; IP length, fragments, IPv6 extension headers

`src/capture/capture.c`: `l4_from_ipv4()` / `l4_from_ipv6()` reduce an
IP packet to its transport segment, `decode_l4()` is the one
TCP/UDP/ICMP dispatch for both versions (IPv6 gains the Kerberos/88 and
SNMP/161-162 arms its copy had lost), and `decode_tcp()` reads the data
offset once for the thirteen `try_*` observers. IPv4 Total Length and
IPv6 Payload Length clamp the segment, so Ethernet padding no longer
reaches the payload parsers; a non-first fragment is labelled
`IPv4 frag` / `IPv6 frag` and not parsed; IPv6 Hop-by-Hop, Routing,
Destination Options, AH and Fragment headers are walked, and
`packet.proto` is the protocol the walk ends on. The reserved
parse-fault kinds `ip_truncated` and `ip_fragment` are now measured.
Pages: [[jsonl-schema]] (`packet.info` values, the two kinds),
[[architecture]], [[kerberos-snoop]], [[snmp-snoop]];
`docs/views/packets.md`.

## 2026-10-19 — one DNS name reader; the shipped TLS/HTTP parsers under test (#131)

`src/dns_wire.{c,h}`: `dns_read_name()` / `dns_skip_name()` (RFC 1035
§4.1.4) replace the three verbatim `read_name()` copies in
`dns_snoop`, `dns_log` and `mdns_snoop` and `nbns_snoop`'s
`skip_name()`. The shared reader refuses the reserved label types
`01`/`10`; the copies refused only `10`, and NBNS refused neither. The
compression bound is unchanged: 20 pointers followed, the 21st refused.
The reader copies raw; marking stays at the stores (#138), and the
passive DNS cache (`dns_set_resolved`) joins them. `sni_snoop()` and
`http_snoop()` are now wrappers over `tls_log_parse()` /
`http_log_parse()`, and `src/sni_snoop.c` / `src/http_snoop.c` are gone
(the credential scanner moved to `http_log.c`). Running their suites
through the shipped parsers found three divergences, each resolved
toward the spec: session_id > 32 and empty cipher_suites (RFC 8446
§4.1.2) and a lowercase method (RFC 9110 §9.1). All `u16be` statics →
`be16` from `src/bytes.h`. `fuzz_dns_read_name` drives the reader
directly. Pages: [[jsonl-schema]] (versioning note),
[[ja3-fingerprinting]].

## 2026-10-19 — #130: observers consume the frame view

Every 802.11 observer gained a view entry (`*_frame(const dot11_frame_t
*f, ...)`) and `on_probe_frame()` calls only those, so a monitor frame
is decoded once end to end — the byte entry points are wrappers kept
for tests and fuzzing. The per-file Frame Control decoders in
`fragattack.c`, `pm_forge.c`, `queue_evict.c`, `deauth_snoop.c`,
`assoc_track.c`, `action_snoop.c`, `beacon_snoop.c`, `ctrl_frames.c`
and `eapol_log.c` are gone. View gains `proto`, `dot11_frame_depad()`,
`dot11_frame_tid/amsdu/ccmp_pn()` and a test-only decode counter. No
behaviour change: the suite and `make replay-check` are unchanged.
Page: [[architecture]] (802.11 frame view).

## 2026-10-19 — #129: Multi-Link Element Presence Bitmap read per 802.11be

`mle_parse()` read Multi-Link Control bit 4 as "MLD MAC Address
Present" and refused a Basic MLE with it clear. In the Basic variant
bit 4 is **Link ID Info Present** and the MLD MAC is unconditional, so
every client (non-AP) MLD in a (Re)Association Request was dropped.
Verified against hostapd `ieee802_11_defs.h` and Wireshark
`packet-ieee80211.c` (the IEEE 802.11be-2024 text itself was not read).
Updated [[jsonl-schema]] (`wifi_mld` semantics: client MLDs now
appear) and [[mac-randomisation]] (MLD bullet).

## 2026-10-19 — #109: clock migration finished; flood_* forwards deleted

Every remaining direct `time(NULL)` / `clock_gettime()` in `src/` moved
onto the seam: the wired snoopers, the protocol logs, `jsonl.c`,
`main.c`, nineteen views, the platform rate code, and last the Track P
files (`beacon_snoop.c`, `capture/capture.c`, `capture/probe.c`,
`deauth_snoop.c`). Wall stayed wall. What moved clock: the channel-hop
dwell and the 30 s settle before the Wi-Fi baseline is frozen (was a
difference of two wall readings, so an NTP step could fire it early or
never) are now monotonic; the bandwidth and interface-rate deltas read
the new `sloth_mono_ts()`. `tests/test_clock_seam.c` no longer keeps a
hand list: it walks all of `src/` (`.c` and `.h`), exempts only
`src/sloth_clock.c`, and asserts it found that file and the calls in
it. The #88 `flood_wall()` / `flood_mono_ms()` /
`flood_test_set_clock()` forwards in `flood_window.h` are gone. JSONL
output unchanged; `make replay-check` golden unchanged. Pages:
[[architecture]] (clock seam bullet), [[alerts]].

## 2026-10-19 — #110 (second half): fragattack and the last find_or_alloc tables onto `stab_t`

The five FragAttacks tables (BSS, key-install witness, open
reassemblies, association times, A-MSDU-flip PNs) and six more
hand-written find-or-allocate tables (NDP router advertisements, SSDP,
ONVIF, SMTP AUTH LOGIN flows, per-BSSID EAP posture, EAPOL in-flight
handshakes) are `stab_t STAB_OLDEST`; DHCP, already counted, moved too.
Eleven `evict_*` fields appended to `sensor_health`. `stab_del()` and
`stab_expire()` added so a completed reassembly and an expired PN are
retired without being counted as loss. Updated [[jsonl-schema]] (field
list, sample, semantics, uncounted list) and [[ring-buffers]] (users,
the two retire calls, and the three bodies left hand-written with the
reason for each).

## 2026-10-19 — Wi-Fi SIGINT guide for non-specialists

Added [[wifi-sigint-guide]]: the radio environment around an ordinary
person — beacons, probe requests and what randomisation does and does
not hide, cars (factory hotspots, wireless CarPlay/Android Auto, TPMS
and fobs as sub-GHz, Tesla phone-key BLE), Axon body cameras (what the
user guides and FCC grants document, what is not published, why sloth
ships no radio fingerprint), Flock plate readers (vendor LTE documents
vs. community Wi-Fi/BLE observations, with their dates and measured
false-positive rates), Bluetooth LE around a person, the inference
ladder from presence to Wi-Fi sensing, and the legal frame by
jurisdiction. Every claim was researched and then independently
fact-checked against its source before being written; 21 candidate
claims were dropped for lacking an openable source and are not on the
page. Linked from [[index]] (read-first list and WiFi SIGINT section),
[[how-wifi-works]] and [[wifi-sigint-techniques]].

## 2026-10-19 — Wi-Fi SIGINT guide: every phone radio

Added §3 to [[wifi-sigint-guide]] ("What your phone itself transmits:
iOS and Android", 3.1–3.4): Wi-Fi scanning, joined, hotspot, AWDL,
Aware/Direct/RTT and the Control Center "off" semantics; Bluetooth LE
Continuity frames, address rotation and its leaks, action-triggered
frames, Quick Share / Fast Pair / Find Hub / Android Information
Service; cellular, Wi-Fi Calling, UWB, NFC, satellite, Thread, Airplane
Mode and power-off; a summary table of identifier, rotation and switch.
Sources 87–117 added. Later sections renumbered 4–8. Recorded that
sequence-number randomisation is now the common case on current phones
(iOS 16.1+, Android 12-compliant handsets) in [[mac-randomisation]] and
`docs/views/seqnum.md`, replacing the "rare; custom firmware" wording.
Five researcher/fact-checker pairs (99 claims kept, 36 dropped) and five
review lenses (51 findings, all applied) preceded the commit.

## 2026-10-19 — deauth tables on `stab_t`; two evict fields (#143)

`src/deauth_snoop.c`'s observation and (BSSID, victim) tables, the
last hand-written find-or-add pair that the #110 close-out grep
missed, are now `stab_t` STAB_OLDEST. `sensor_health` gains two
appended fields, `evict_deauth_obs` and `evict_deauth_victim`; rows
aged out after 60 s of silence are retired, not counted. Recency stays
monotonic milliseconds, held in the row's `time_t` stamp. Detector
behaviour, eviction victim and snapshot order are unchanged; the replay
golden differs only by the two keys. Updated [[jsonl-schema]] (field
list, example, counted list, meaning) and [[ring-buffers]] (the
"still hand-written" list).

## 2026-10-19 — recorded mutation run: views, probe.c, main.c (#143)

[[mutation-testing]] gains "Recorded run: views, probe, main": one
`make mutate` run at `6542fd1` per area, sampled with `--seed 143` —
`src/views/*.c` 8/55 killed (14.5%), `src/capture/probe.c` 12/25
(48.0%), `src/main.c` under `--target replay-check` 5/60 (8.3%) — with
the exact commands, the confidence interval for each sample, and where
the survivors cluster. The "don't waste cycles" note on `main.c` now
names its replay-check oracle.

## 2026-10-19 — deauth stamp fits a 32-bit `time_t` again; review fixes (#143)

Review of the `stab_t` move found that its build-time check
(`sizeof(time_t) >= sizeof(uint64_t)`) dropped every 32-bit-`time_t`
target — i386, and armhf without `_TIME_BITS=64` such as Raspberry Pi
OS bookworm 32-bit — with no owner ruling and no deployment note. The
check is gone. `src/deauth_snoop.c` rows keep the `uint64_t` monotonic
`last_ms` for ageing and give `stab_t` an epoch-relative `time_t stamp`,
rebased to now − 60 s and restamped at every snapshot, so a stamp stays
under about a minute and fits any `time_t`. 32-bit targets build as
they did before the slice; the eviction order is unchanged, since a
rebase shifts every stamp by the same amount. Two tests pin what was
only claimed: the age-out's upward walk leaves `[E,D,C]` where
`stab_expire()` would leave `[D,E,C]`, and eviction order survives the
epoch move. Updated [[ring-buffers]], `docs/views/deauth.md` (128-row
tables, the two evict counters) and [[mutation-testing]] (`LC_ALL=C`
on the views command, since the sample depends on glob order, and 43
min as the cost of a re-run).

## 2026-10-19 — #85 close-out: dead-worker scope, `scope_dropped` contract

`capture_scope_poll()` derived `no_capture` from "a handle is open", so
a capture thread that died (`perm_lost`, `iface_gone`, any exit) kept
its handle and the scope read `enforced` while nothing was collected.
The scope state now uses the same liveness as `capture_running`
(`capture_worker_live()`), so a dead worker reads `no_capture`.
`scope_dropped` no longer counts a `[y]` deselect of a pinned,
still-valid interface under an allow-list — authorization failures
only, as [[jsonl-schema]] already said (owner decision 2026-10-19: the
code follows the doc). Owner decisions of the same date recorded in
[[jsonl-schema]], [[cli-reference]] and `docs/views/interfaces.md`:
a replugged adapter stays failed closed until restart, and an
unresolvable `--iface` name stays a stderr notice plus `degraded`. The
consumer example's comment no longer claims fail-closed means nothing
out of scope was collected.

## 2026-10-19 — README and site pages follow the applied MISSION §2 (#84)

README's "Strict observation" table said sloth had "exactly two"
behaviours beyond observation; MISSION §2 rule 1 (rewritten 2026-10-14)
lists five. The table now carries reverse DNS, the scan trigger,
`--hop`, a routable `--data-socket` and promiscuous mode, each with its
default, opt-in and what `--strict` does to it. The WiFi SIGINT section
no longer calls `--strict --hop` an open owner decision (ruled
2026-09-30: `--hop` stays allowed under `--strict`), and the stale
"§2.1", "first carve-out" and "sole carve-out" references are gone.
`docs/index.html` and `docs/philosophy.html` dropped "never scans, never
modifies kernel state". The `--strict` help text stopped saying a
routable socket still binds under it (refused since 2026-10-06), and
[[cli-reference]]'s `--hop` row stopped counting kernel-state writes.
`tests/test_docs_consistency.c` now pins MISSION §2's flags to the ones
`src/main.c` parses, both ways, for `--allow-active`, `--strict` and
`--hop`.

## 2026-10-19 — data-socket exposure drops the "carve-out" framing (#84)

[[data-socket-exposure]]'s mDNS note called the Avahi advertisement a
"carve-out (MISSION.md §2)". The charter rewrite retired that framing;
§2 rule 1 covers the advertisement as an opt-in, announced
network-using service, and the note now says so. The site hero's "Every
exception opt-in and announced" was narrowed to every network-using
option, since §2 names promiscuous mode as the one write that is
neither.

## 2026-10-19 — #90: `[y]` KARMA view fits 100x33

The `[y]` view's page budget now counts its two-line legend and starts
from the row the view begins on, so a full table no longer pushes the
legend (the "a hypothesis, not an identification" line) off a 100x33
screen. Rows fit the width instead of wrapping: the top SSID shrinks
first, then the tool label, keeping the `/conf? provisional` tail whole.
The second legend line was 108 columns and is shortened to 97. Detail in
`docs/views/karma.md` (*Fit at the 100x33 minimum*); see [[alerts]] for
the `KARMA_AP` rule it mirrors.

## 2026-10-19 — #90: sloth corroborates, never confirms

Recorded the owner ruling of 2026-10-19 (#145 ruling 2) in
[[jsonl-schema]] and the `KARMA_AP` row of `docs/views/alerts.md`: there is no
`CONFIRMED_ATTACK` state and no tier above CRIT, which for `KARMA_AP`
means *corroborated*. `signature_version` and the boolean `validated`
stay as shipped. `tests/test_alerts.c ::
test_karma_pmkid_harvest_noted` now pins that a PMKID alone leaves the
candidate at WARN.

## 2026-10-19 — #90: a clipped `[y]` tool label is marked

A tool label the `[y]` KARMA view had to shorten to fit 100 columns now
ends in `~` (`[ESP32 M~/med? provisional]`), and below three kept
characters only the marker is left (`[~/med? provisional]`), so a stub
like `ES` is never read as the whole name of some other tool. The
`docs/views/karma.md` mockup is redrawn as the row renders at 100
columns. The same top-of-screen page budget in the other list views is
tracked in #150.

## 2026-10-19 — #95 close-out: reentrant time calls

The last eight non-reentrant time call sites in `src/` (`posture.c`
`gmtime`, six protocol views and three dashboard bands `localtime`)
now use `gmtime_r`/`localtime_r` into a local `struct tm`, and their
`tests/cppcheck.supp` entries are gone. [[threat-model]] X1 row
updated: no non-reentrant time call remains.

## 2026-10-19 — #95 close-out: worker signal masks and the lock table

Every worker thread (capture, probe, DNS) is now created through
`worker_thread_create()` (`src/worker_thread.c`), which starts it with
SIGINT and SIGTERM blocked so `on_signal()` only ever runs on the main
thread; `tests/test_worker_thread.c` checks the helper, a live DNS
worker's kernel-reported mask, and that no other `src/` file calls
`pthread_create()`. [[architecture]] gains *Threads, signals and locks*:
the thread list and a table of every module mutex, what it guards and
what it takes while held. The issue's proposed rule (no module takes
another's lock while holding its own) was checked and does not hold —
43 cross-module edges, all acyclic — so the page records the measured
order and an acquire-downward rule instead, and corrects the
`src/fragattack.c` comment that called `eapol_log`'s mutex a leaf.

## 2026-10-19 — #95 close-out: compiler and architecture coverage

Added [[compiler-coverage]]: CI builds on gcc (Ubuntu 24.04's default)
and clang for fuzzing, x86-64 only, with no 32-bit, big-endian, musl or
BSD job. Records that wire parsing goes through `src/bytes.h` byte
assembly and `memcpy`, never casts, and lists the host assumptions that
do exist — in-place netlink attribute casts (4-octet aligned, including
64-bit reads), `long` timestamps, no `time_t` width assertion, `int`
lengths, unaudited `char` signedness in the text-protocol scanners.
Linked from [[index]].

## 2026-10-19 — #95 close-out: rollback instructions

[[release-checklist]] gains section 5, *Rolling back to the previous
tag*: fetching and verifying a release (signed tag, `SHA256SUMS` against
the release notes, `gh attestation verify`), the finding that v1.8.4 and
earlier have none of the three (unsigned tag, no checksums in the notes,
no attestation workflow yet) and so can only be rebuilt from the tagged
commit, and a table of what on-disk state survives a downgrade: the
`--db` file is refused across a schema change (v5 here, v4 at v1.8.4)
and must be moved aside; JSONL is appended to in the older, additive
shape; snapshot, research DB, pcaps and reports carry over; the shipped
unit's flags all exist at v1.8.4. Step 10 no longer calls the
attestation workflow pending — it landed in `9131b8e`.

## 2026-10-19 — #96 close-out: word-form counts, dashboard `!persist` badge

Removed the last spelled-out counts that described the build: "the six
rules" in the [[alerts]] frontmatter and in [[sloth]], and "Three rules
return `""`" in [[alerts]] § Exposure rules, which named three of the
five cited-but-techniqueless kinds; the two-rule note in
[[threat-intel]]'s Last-updated line now names the rules.
`tests/test_docs_consistency.c :: test_no_word_form_counts` fails on a
number word (two..twenty) directly before "rules" or "views" in any wiki
page but this log, README.md or MISSION.md; two subset counts that are
not the build's shape ([[wifi-sigint]]'s v1.1 "four views",
[[tool-fingerprints]]' "three rules" of matching) are allowed by exact
page, phrase and occurrence count.

The `!persist` storage-failure badge now shows on the ncurses dashboard,
the startup view, which has no tab bar: right-aligned on the Interfaces
title rule, and under the "terminal too small" notice. [[retention]] §6
no longer records the gap; [[cli-reference]] § Status badges and
[[dashboard]] describe where it is drawn. The dashboard minimum size in
[[dashboard]] and [[ip-palette]] is corrected from 100×33 to the 102×41
`view_dashboard_draw()` computes.

## 2026-10-19 — #96 review: dashboard `!persist` badge edge cases

Review fixes on the dashboard badge. A badge too long for the
Interfaces title is now cut between whole `sink:N` tokens and marked
`+`, never mid-number (a raw character cut had turned `eapol:2147483647`
into `eapol:2147`). On a terminal too small for the tile the badge goes
on the row after the "too small" notice, which wraps below ~76 columns,
instead of overprinting it on row 1. The layout-unchanged test's
comment now names the mutation that actually made its row diff fail.
The sanitised run of the new truncation test found `persist_badge()`
summing the three counters in an `int`; the total is now summed wide
and saturated at `INT_MAX`.
[[cli-reference]] § Status badges, [[dashboard]] and [[retention]] §6
updated.

## 2026-10-20 — Alert evidence reaches disk; no partial evidence files (#92 slices 1+2)

`dump_new_alert_pcaps()` now exports an incident's cited evidence-ring
frames through `evidence_export_pcap()` — gated on `--collect-handshakes`
and `--eapol-dir` per the 2026-10-08 ruling, under the same
`pcap.min_severity` floor and per-key cooldown as IP alert pcaps — as
`<incident_id>-<event_id>-<RULE>.pcap`. A DEAUTH_FLOOD CRIT used to
write zero frames because the loop skipped every alert without a
`match_ip`. `pcap_path` / `pcap_write_failures` on `alert.*` events now
also appear for evidence-citing alerts (additive), and `alert_t.pcap_path`
grew from 80 to 256 bytes so a real directory no longer truncates it.
The exporter writes temp → fsync → no-clobber `renameat`, unlinking the
temp on every failure path, so nothing zero-length or truncated is left
under a final name. The ring and exporter moved to `CORE_COMMON_SRCS`
because the engine, which every build links, now calls them. Pages:
[[pcap-export]], [[jsonl-schema]], [[cli-reference]].

## 2026-10-20 — Evidence export review fixes (#92 slices 1+2)

An evidence pcap name is unique within one process only, so a restart
that re-fires a key in the same wall second can rebuild a name an
earlier run left on disk. The commit refused it and the engine retried
every tick, forever: a write, fsync, unlink and counted failure per
tick, and a `sensor_health` record per tick through `storage_failures`.
The engine now exports through `evidence_export_pcap_unique()`, which
commits under `-2` … `-99` and reports the name used; all 99 taken is
counted once and ends the incident. An alert citing evidence that has
all aged out now falls back to `--pcap-dir` when it also has a
`match_ip`, instead of being marked done with nothing written. The
bare-name fallback for a path over 255 bytes is now tested in both
exporters. Pages: [[pcap-export]], [[jsonl-schema]].

## 2026-10-20 — #92 slice 4: PM_FORGE and QUEUE_EVICT cite their frames

#107's last slice. `PM_FORGE` now cites the contradicting pair (the
PM=1 Null/QoS-Null and the PM=0 data frame on another TID), and
`QUEUE_EVICT` the session-change frame plus the released burst, as
`evidence_count` / `evidence_id_N` on the `alert` and `alert.*`
records. `on_probe_frame()` stamps the evidence-ring ID on the decoded
frame view (`dot11_frame_t.event_id`) so every frame observer can read
it; the bounded per-row ring is `src/ev_cite.h`. A later session change
with one stray frame keeps the reported release's citations, and a
repeated sequence number cites nothing. [[pcap-export]] § Which alerts
cite frames, [[jsonl-schema]] and [[alerts]] updated.

## 2026-10-20 — #92 slice 4: flood and Action-frame rules cite their frames

`AUTH_FLOOD`, `ASSOC_FLOOD`, `BTM_ABUSE` and `SA_QUERY_FLOOD` now cite
the evidence-ring IDs of the frames they counted. Each tracker already
kept one entry per frame; it now keeps that frame's id beside the
timestamp, and the citation query walks the same window the count used.
`BTM_ABUSE` cites only the Disassociation-Imminent Requests, the ones
its threshold counts. [[pcap-export]] § Which alerts cite frames and
[[alerts]] § Engine updated.
