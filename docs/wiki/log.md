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
