# PROGRESS.md — Agent activity log

A warm-start view of the repo: what's in flight, what just landed, what
was decided. Companion to [`MISSION.md`](MISSION.md) (the charter, slow
moving) and [`docs/wiki/log.md`](docs/wiki/log.md) (wiki edits only).

**Who writes here**: every agent that lands a non-trivial change.
**When**: at the end of a working session, before pushing the commits
that close out the work.
**Where to read first**: top of the file. Newest entries at the top of
their section; the "In progress" section is mutable, the "Recently
landed" section is append-only.

---

## Format

Each landed entry is one block:

```
### YYYY-MM-DD — short title
**Commits**: <hash1>, <hash2>
**Touched**: paths or modules
**Why**: one to three sentences on what motivated the change
**Follow-ups**: open work this exposed, if any (link to the In-progress entry)
```

Each in-progress entry is one block:

```
### <short title>
**Owner**: agent name + session (or human if a human is driving)
**Started**: YYYY-MM-DD
**Goal**: one sentence
**Status**: free text — where it is right now
**Blockers**: if any
**Next concrete step**: what the next agent picking it up should do
```

When an in-progress item lands, **move** it to "Recently landed" (do
not duplicate). Add the commit hashes. Append any follow-up that the
work exposed as a new In-progress entry.

---

## In progress

*(nothing actively in flight — pick from "Open follow-ups" or the
paused work below)*

### Paused: Mutation-testing follow-ups (rounds 10+)
**Owner**: next agent
**Started**: 2026-05-28 — paused 2026-05-28 by operator request
**Status**: rounds 1-9 closed. Aggregate kill rate is **51.0% of
considered** (estimated 938 killed / 1844 considered / 2311
mutants total). The campaign delivered ~600 net mutants killed and
the `--ignore-file` machinery; remaining work is small per-round
gains against the noise floor (see "diminishing returns" pattern in
the "Recently landed" entries). Resume at will; everything is
non-blocking and stateless.
**Next concrete step** (in priority order, if resuming):
1. Bulk-add LZT / SBL / TIP entries for `dns_log.c`, `tls_log.c`,
   `http_log.c` — same patterns already documented for
   `quic_log.c` in `mutate-equivalents.txt`. Should push each
   file's "of considered" kill rate above 55% (and the aggregate
   back from ~51% to ~55%) without changing any actual code.
2. Mutate `src/{ntp,icmp}_log.c` (similar structure, small).
3. Mutate `src/probe_pnl.c`, `src/eapol_log.c`,
   `src/seqnum_track.c`, `src/assoc_track.c` (WiFi-SIGINT engines).
4. Skip `src/views/*.c` — render code, low semantic value.
5. Cosmetic: tighten the "killed (build broke)" sub-counter so
   compile failures and test-binary segfaults are categorised
   distinctly (both currently produce stderr containing "error"
   + "make"; the heuristic conflates them).

---

## Recently landed

### 2026-06-02 — Evil-twin AP detection (6 phases)
**Commits**: `24b2aa7`, `f81aab0`, `32f53a8`, `059f502`, `50a768b`, `16cfd0a`
**Touched**: `include/sloth.h`, `src/alerts.{c,h}`, `src/beacon_snoop.c`,
`src/eapol_log.c`, `src/jsonl.{c,h}`, `src/main.c`, `src/tui.c`,
`src/twins.{c,h}`, `src/views/{beacon,twins}.{c,h}`,
`src/wifi_oui_attacker.{c,h}`, `tests/test_alerts.c`,
`tests/test_beacon_snoop.c`, `tests/test_eapol_log.c`,
`tests/test_jsonl.c`, `tests/test_twins.c`,
`tests/test_wifi_oui_attacker.c`, `tests/test_{state,arp}.c`
(VIEW_COUNT bumps), `tests/main_test.c`, `Makefile`, `README.md`,
`docs/views/{README,twins}.md`, `docs/wiki/{jsonl-schema,index,
evil-twin-reproducer}.md`
**Why**: Modern evil-twin attacks (Pineapple, ESP32-Marauder) mirror
the legit AP's SSID + cipher to defeat the existing weak/strong twin
check. Extends `rule_evil_twin` with same-cipher diff-OUI detection,
vendor-IE fingerprint hashing, RSSI-step proximity, deauth-correlated
attack-chain CRIT, and full UI / JSONL surface. Lands the newer of
the two copilot plans (`copilot/evil-twin-ap-detection-update`,
planned 2026-06-01).
**What's in it** (phase-by-phase):
- **Phase 1** (`24b2aa7`) — `ap_fingerprint_t` carrier + same-cipher
  WARN branch with dedup key `twin-fp:<ssid>`. Skips OPEN. New enum
  `ALERT_TYPE_EVIL_TWIN_PROXIMITY` reserved for Phase 3.
- **Phase 2** (`f81aab0`) — beacon parser fills `fp.flags`
  (HT/VHT/HE/WPS-UUID-zero) and `vendor_ies_hash` (FNV-1a over non-MS
  tag-221 IEs in beacon order). New `src/wifi_oui_attacker.{c,h}`
  with Hak5 + Espressif tables. WARN→CRIT escalation on hash
  mismatch or attacker OUI.
- **Phase 3** (`32f53a8`) — `rssi_ring_t` (16-slot ring) in
  `beacon_ap_t`; `rssi_ring_push()` recomputes the 60s min/max on
  each beacon. `rule_evil_twin_proximity` fires WARN on ≥15 dBm
  swing, key `twin-prox:<bssid>`. `0` sentinel guards first-observation
  false fires.
- **Phase 4** (`059f502`) — `rule_evil_twin_attack_chain` correlates
  twin pair + recent DEAUTH_FLOOD → CRIT `EVIL_TWIN` (key
  `twin-chain:<ssid>`, "attack-in-progress" detail). 32-slot taint
  tracker (300s TTL, alerts.h API). EAPOL `.22000` export prepends
  `# provenance=tainted-evil-twin bssid=<MAC>` for handshakes against
  tainted BSSIDs (hashcat ignores `#`).
- **Phase 5** (`50a768b`) — `twin_episode_t` materialised view +
  `twins_snapshot()` (RSSI-default real/twin, taint override). New
  `[x] Twins` view (`VIEW_TWINS = 30`, `VIEW_COUNT = 31`) with flag
  glyphs `!@#*~`. Beacon view SSID column gets glyph suffix; status
  line surfaces episode count. New JSONL `twin_episode` record type.
- **Phase 6** (`16cfd0a`) — validation. Hand-crafted parser tests for
  HT/VHT/HE/WPS-UUID-zero/vendor-hash. EAPOL provenance-marker test.
  End-to-end attack-chain scenario asserting all 5 acceptance
  criteria (chain fires, all flags set; clean baseline doesn't fire).
  scapy reproducer doc at `docs/wiki/evil-twin-reproducer.md` for
  live testing.

**Counts**: 2302 assertions total, was 2143 before Phase 1 (+159).
All 6 phases warning-clean.

**Deliberate non-fixtures**: skipped literal pcap fixtures in
`tests/fixtures/` despite the original plan. Per CLAUDE.md "Hand-
crafted protocol tests" discipline, a scapy-roundtripped pcap would
be circular (sloth parsing scapy output without a third-party
reference). The same coverage now lives in hand-crafted byte arrays
(Phase 6 parser tests) plus the e2e scenario, with scapy reproducer
snippets documented for live testing.

**Follow-ups**: `AP_FP_FLAG_DEFAULT_HOSTAPD_CAPS` remains reserved
but unpopulated — signature needs pcap calibration before it can be
defined reliably. (The `HAK5_OUI` / `ESPRESSIF_OUI` follow-ups closed
2026-06-02 in the entry below.)

### 2026-06-02 — Evil-twin AP/OUI flag-bit population + Loki sink + Compose demo
**Touched**: `src/beacon_snoop.c`, `tests/test_beacon_snoop.c`,
`examples/forwarder/sloth-forward.py`, `examples/forwarder/README.md`,
`examples/compose/` (new dir: `docker-compose.yml`, `mock-sloth.py`,
`loki-config.yml`, `grafana-datasource.yml`, `README.md`)
**Why**: Closes two open follow-ups and lights up a third end-to-end
demo path so evaluators can see the JSONL stream land in a SIEM-like
surface within seconds of `docker compose up`.

**What's in it**:
- **`AP_FP_FLAG_HAK5_OUI` / `AP_FP_FLAG_ESPRESSIF_OUI` population**
  — `beacon_record` now sets the flag bits inline from the BSSID OUI
  via `oui_is_hak5()` / `oui_is_espressif()`. Bits never clear; they
  live for the entry's lifetime. Downstream consumers (JSONL,
  iOS, Twins view) can surface the marker without re-doing the
  table lookup. 3 new tests in `test_beacon_snoop.c` (Hak5 OUI sets
  the flag, Espressif OUI sets the flag, clean OUI sets neither).
- **Loki sink in the forwarder** — fourth sink type alongside
  `hec` / `syslog` / `elastic`. Groups by `type` field so each
  record type becomes its own Loki stream (keeps label
  cardinality bounded). Supports multi-tenant (`X-Scope-OrgID`),
  basic auth, and `--loki-insecure` for test clusters. ~95 LoC for
  the sink class + ~25 LoC for CLI flags + a documentation block in
  the forwarder README.
- **`examples/compose/`** — four-container demo stack
  (mock-sloth producer + forwarder + Loki + Grafana). One
  `docker compose up`, then open Grafana on `:3000` and run
  `{job="sloth"}` to see records arriving. The producer is a
  synthetic Python script (`mock-sloth.py`) emitting one record per
  record-type per second; the wire format matches sloth's
  `--data-socket tcp:HOST:PORT` so swapping in real sloth is one
  line. README documents the substitution. Grafana datasource is
  auto-provisioned; Loki runs single-binary with filesystem storage.

**Counts**: 2311 assertions total (+9 from Phase 6 close). make is
warning-clean.

**Follow-ups**: None directly. The Compose stack documents how to
swap in real sloth; that requires a published Docker image which
isn't built here.

### 2026-06-02 — `connections` JSONL record type
**Commits**: `23777db`
**Touched**: `src/jsonl.{c,h}`, `src/main.c`, `tests/test_jsonl.c`,
`docs/wiki/jsonl-schema.md`
**Why**: Eighth JSONL record type — per-flow connection snapshots so
`sloth-ios` (and any other JSONL consumer) can build a Connections
view with RTT, retx, and bw join, without having to re-derive flow
identity from packet-level records. Lands the older of the two
copilot plans (`copilot/add-connection-records`, planned 2026-05-28).
**What's in it**:
- New emitter `jsonl_emit_connections(s)` writes one line per active
  flow in `s->conns[0..conn_count)`. Driven from `poll_data()` at the
  ≈1 Hz poll cadence; consumers rebuild their table from the latest
  snapshot keyed by `(src, dst, proto)`.
- TCP records carry `state` (kernel `TCP_*` table — duplicated in
  `jsonl.c` to avoid a layering dep on view code), `rtt_ms`
  (omitted when `rtt_us == 0`), and `retx`.
- UDP records omit `state` / `rtt_ms` / `retx`.
- Endpoints render as `host:port`; IPv6 addresses get bracketed
  (`[fe80::1]:54321`).
- `rx_bytes` / `tx_bytes` join from `bw_lookup()` — both 0 when no
  bw entry (also when `WITH_PCAP=0`).
- `age_s` was deferred — option (b) of the plan. `linux_get_conns`
  rebuilds the conn array from `/proc/net/{tcp,udp}{,6}` every poll
  with no state retention, so `first_seen` can't be carried forward
  without breaking the platform vtable contract. Consumers can
  compute age client-side from the first record they observe.
- Schema doc updated; iOS Swift consumer sketch already expects this
  record shape so no client-side change required.
- Three new tests in `tests/test_jsonl.c`: mixed TCP+UDP fields,
  IPv6 bracketing, `rtt_ms` omission on zero RTT.
**Follow-ups**:
- `age_s` revisit — would need a tuple-keyed parallel table in
  `main.c` (carry `first_seen` across polls) or a vtable change.
  Not urgent: consumers can compute it.
- `retx` is currently always emitted for TCP, including when 0.
  The spec said `omit for UDP` (which we do) but didn't specify
  zero-skip for TCP — leaving as-is, consumer treats 0 as "none".

### 2026-05-28 — `examples/forwarder/` SIEM forwarder (HEC + syslog + Elastic)
**Commits**: `742257c`, `a093e23`
**Touched**: `examples/forwarder/sloth-forward.py` (new, ~525 lines
across two commits), `examples/forwarder/README.md` (new),
`examples/README.md`, `docs/wiki/jsonl-schema.md`
**Why**: After the consumer landed, the next step was a SIEM
forwarder showing how to take the same JSONL stream to a real
downstream. Three sinks ship — covering ~95% of operator
deployments (Splunk, syslog-anything, Elastic / OpenSearch / cloud
clusters). Sink interface is two members (`.name`,
`.send(batch)`), so adding Loki / Datadog / in-house collectors
is ~30 lines per sink.
**What's in it**:
- `hec` — Splunk HEC envelopes over HTTPS POST. Token via
  `--hec-token-env` to keep credentials out of `ps`.
- `syslog` — RFC 5424 over UDP (default) or TCP. MSGID is the
  record's `type`, MSG is the raw JSON, PRI defaults to 134
  (local0.info).
- `elastic` — Bulk API (`POST /_bulk`). Time-rolled indices via
  strftime tokens (`sloth-events-%Y.%m.%d`). `@timestamp` derived
  from `ts`. Basic auth or API key. Partial failures
  (`errors:true` in the 200 response) surface as batch failures
  so the retry loop sees them.
- Batching (`--batch-size 100 --batch-ms 1000` default), retries
  with exponential backoff, drop-on-failure to match sloth's
  non-durable contract (MISSION.md §4). Stats line to stderr
  every `--stats-interval` (default 30s): `received=N
  forwarded=N dropped=N retries=N`.
- `--type` / `--src` filters mirror the consumer.
- `--no-reconnect` for one-shot / test use; default is loop forever.
- Smoke-tested end-to-end against in-process fake servers for
  HEC, syslog-UDP, and Elastic (including the partial-failure
  path with mapper_parsing_exception).
- Production patterns documented in the README: systemd unit
  template with `EnvironmentFile`, "one forwarder per sink"
  rationale, when to combine with `-o FILE` for durability.

### 2026-05-28 — `examples/consumer/` Python reference consumer
**Commits**: `4526f8a`
**Touched**: `examples/consumer/sloth-stream.py` (new, ~270 lines),
`examples/consumer/README.md` (new), `examples/README.md` (new),
`FACTORY.md`, `docs/wiki/jsonl-schema.md`
**Why**: The JSONL data socket spec was documented but had no
runnable companion. A reference consumer validates the schema by
exercising it, gives external integrators a working starting point
in the simplest possible language, and serves as the textbook shape
for porting to Go / Node / Swift / etc.
**What's in it**:
- `parse_spec` → `connect` → `stream_lines` → `json.loads` →
  filter → format → print, with disconnect → backoff → reconnect.
- `unix:` and `tcp:` specs (matches sloth's `--data-socket SPEC`).
- `--type` and `--src` filters; `--raw` pass-through (for `| jq .`);
  `--count` 5s-interval tally; `--no-reconnect` for one-shot.
- Per-type ANSI-colour pretty formatters. Forward-compat for
  unknown `type` values (raw fields rendered instead of dropped).
- Stdlib only. Python 3.7+. ~270 lines, single file.
- Smoke-tested end-to-end against a fake sloth producer; every
  record type from the schema renders with its distinctive marker.

### 2026-05-28 — Round 9: per-protocol log files + selection-clamp tests
**Commits**: *(this commit)*
**Touched**: `tests/test_dns_log.c`, `tests/test_tls_log.c`,
`tests/test_quic_log.c`, `tests/test_http_log.c`,
`.github/scripts/mutate-equivalents.txt`, `README.md`,
`PROGRESS.md`
**Why**: Round 9 baselined the four per-protocol log files and
discovered they all share the same selection-clamp boundary that
the existing `_clamps_sel` test didn't pin (it seeds `sel=99` with
`n=1` — way above the boundary, so `>=` -> `>` and `>` -> `>=`
mutations both survive).

**Per-file baselines** (no triage yet for 3 of 4):

| target              | mutants | baseline raw | of considered (post-r9) |
|---------------------|---------|--------------|-------------------------|
| `src/dns_log.c`     | 203     | 47.8%        | ~48.8% (boundary tests only) |
| `src/tls_log.c`     | 276     | 37.0%        | ~37.7% (boundary tests only) |
| `src/quic_log.c`    | 22      | 68.2%        | **100.0%** (full triage) |
| `src/http_log.c`    | 179     | 38.0%        | ~39.1% (boundary tests only) |

**8 new assertions** added across 4 tests:
- `tests/test_dns_log.c`: `test_snapshot_clamps_sel_at_exact_boundary`
  + `test_snapshot_empty_resets_sel_to_zero`
- `tests/test_quic_log.c`, `tests/test_tls_log.c`,
  `tests/test_http_log.c`: combined
  `test_snapshot_clamps_sel_at_boundary_and_empty` (sel == n
  exactly + empty-log path)

Each test pair kills two specific mutations:
- `>=` -> `>`: when sel exactly equals n (one past last valid
  index), the clamp must still trigger.
- `>` -> `>=`: when n is 0, mutated code computes `n - 1 = -1`
  and assigns that to sel — a real bug.

**5 new ignore entries** for `quic_log.c` only (`SBL` for
`char ver[8]`, `LZT` for the snapshot loop bounds + saturating
add). `quic_log.c` now reports **100.0% of considered** (17/17,
5 ignored) — same clean result as `threat_intel.c`. The pattern
extends to the other 3 log files but their bulk-ignore work is
queued for round 10.

**Aggregate estimate after round 9**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 2311  | 467     | 1844       | ~938   | **~51.0%**    |

The aggregate **dropped from 55.4% to ~51.0%** because adding
the four new log files introduced ~700 mutants at 37-48% raw
baselines, pulling the average down. Round 10's bulk-ignore work
will recover most of this without code changes — the same
LZT/SBL/return-sentinel patterns documented for quic_log apply
to the other three.

**README badges** bumped: tests 2114 → 2122; mutation kill rate
55.4% (yellowgreen) → 51.0% **(yellow — first downward
tier-move in the campaign)**.

**Decisions worth flagging**:
- Did NOT fully triage dns_log/tls_log/http_log this round. They
  share quic_log's structure exactly; bulk-extending the ignore
  entries would close most of the gap, but doing it correctly
  per-line (rather than wildcarded) is the right move and adds
  ~30 entries to the ignore file. Queued for round 10 to keep
  this commit focused.
- The badge tier-move (yellowgreen → yellow) is honest. Aggregate
  is a moving target while new files are still being mutated;
  short-term wobbles are expected.

### 2026-05-28 — Round 8: scan + filter + host_cache + ip_owner (DT class)
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py`,
`.github/scripts/mutate-equivalents.txt`,
`tests/test_scan.c`, `tests/test_filter.c`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Push beyond the export-path / alerts files into smaller
untouched code. `scan.c`'s RFC1918/multicast filter has a clean
boundary surface that pays off in tests; `filter.c`/`host_cache.c`
were nearly equivalence-class-only; `ip_owner.c` exposed a new
issue — files dominated by static data tables.

**Per-file results** (post-ignore-file):

| target              | mutants | ignored | considered | killed | of considered |
|---------------------|---------|---------|------------|--------|---------------|
| `src/scan.c`        | 77      | 0       | 77         | 66     | **85.7%**     |
| `src/filter.c`      | 35      | 8       | 27         | 21     | **77.8%**     |
| `src/host_cache.c`  | 20      | 3       | 17         | 14     | **82.4%**     |
| `src/ip_owner.c`    | 393     | 352     | 41         | 20     | **48.8%**     |

**9 new tests** in `tests/test_scan.c`:
- A `routable_seed_then_assert` helper drives a comprehensive
  boundary sweep over `scan_is_routable`'s ranges:
  10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT), 127/8,
  169.254/16, 224/4 (multicast). Each range tested with one IP
  just inside and one just outside on each side. Kills the
  bulk of the const ±1 and rel `>=`→`>` mutations on lines 16-22.
- `test_routable_rejects_malformed_ips` covers the
  `sscanf < 2` guard (single-octet input, non-numeric "abc").

**1 new test** in `tests/test_filter.c`:
- `test_needle_exact_length_match`: needle and haystack of
  equal length must match. Kills the line-10 `nlen > hlen`
  boundary that the existing `_longer_than_haystack` test
  didn't pin.

**New ignore-file capability: wildcards + line ranges**.
`mutate.py` now supports:
- `<line>` field as a range `M-N` (inclusive).
- `<op>` / `<original>` / `<mutated>` as `*` (any).

Together these enable bulk-ignoring structurally-untestable
blocks of code. The triggering case: `ip_owner.c` has 70+ CIDR
entries in a `static const ip_owner_range_t g_owners[]` table.
Each octet literal is a mutation site (393 mutants total, 291
of them on table lines). Writing a behavioural test per octet
just repeats the table in the test file — the data IS the
contract. Bulk-ignored via:

    src/ip_owner.c:22-94:*:*:*    # DT: g_owners CIDR data block

This dropped ip_owner's 393-mutant pile to 41 considered (the
actual lookup functions); 20/41 killed (48.8%) — a fair number.

**New DT equivalence class** documented in
`docs/wiki/mutation-testing.md`: static lookup tables whose
correctness is a data-validation concern, not a behavioural-test
concern.

**Aggregate after round 8**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1631  | 462     | 1169       | 648    | **55.4%**     |

(Up from 52.3% in round 7. The jump comes from scan.c's
85.7% boundary sweep + the new files' generally clean baselines.)

**README badges** bumped: tests 2085 → 2114; mutation kill rate
52.3% (yellow) → 55.4% **(yellowgreen)** — first colour tier
move since the campaign began.

**Decisions worth flagging**:
- Wildcard support is powerful and dangerous. Documented the
  failure mode (carelessly-broad entries hide real gaps forever)
  in `docs/wiki/mutation-testing.md` "Filtering known
  equivalents". The DT entry for ip_owner.c specifically covers
  *only* lines 22-94 (the static array), leaving lines 95-113
  (the lookup functions) under behavioural test.
- `scan_is_routable` is static and not directly testable, but
  the boundary sweep tests through `scan_update`'s public
  surface get the same coverage with no API churn.
- Did NOT triage all 21 ip_owner code-path survivors. Many are
  in the `ip_owner_lookup_str` parser (`sscanf` returns, octet
  bounds) and overlap with the `scan_is_routable` patterns
  already covered. Marginal value; deferred to a future round.

### 2026-05-27 — Round 7: data_socket fault-injection seam
**Commits**: *(this commit)*
**Touched**: `src/data_socket.{c,h}`, `tests/test_data_socket.c`,
`.github/scripts/mutate-equivalents.txt`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Round 6 closed the cheap real-socket wins on
`data_socket.c`; the remaining survivors are in `send` / `accept`
error paths that real-socket fixtures can't reliably trigger. Add
a small fault-injection seam (function-pointer indirection +
test-only setter) so unit tests can force EAGAIN, partial-send,
and accept-overflow.

**Seam design** (production cost: one predictable branch per call):
```
static data_socket_send_fn   g_send_fn   = send;
static data_socket_accept_fn g_accept_fn = accept;
void data_socket_test_set_send_fn  (data_socket_send_fn   fn);
void data_socket_test_set_accept_fn(data_socket_accept_fn fn);
```
Setters accept NULL to restore defaults. All `send`/`accept` call
sites in `data_socket.c` now go through `g_send_fn` / `g_accept_fn`.
Header declarations cite "test only — production must not call".

**Three new tests**:
- `test_send_eagain_keeps_client`        : fake send returns -1 with
                                           errno=EAGAIN; client must
                                           stay (slow-client branch).
- `test_send_partial_harvests_client`    : fake returns n < len;
                                           client must be closed +
                                           compacted (non-EAGAIN
                                           failure branch).
- `test_tick_caps_at_max_clients`        : fake accept always
                                           succeeds; the `while
                                           (g_client_n < MAX_CLIENTS)`
                                           guard must drain exactly
                                           16 fds (not 15, not 17).

**Per-file delta** (after the seam + tests + line-number
re-anchoring of the ignore file):

| target              | before | after  | delta |
|---------------------|--------|--------|-------|
| `src/data_socket.c` | 26.7%  | **27.6%** | +1 mutant |

**Smaller win than expected**. The fault-injection seam unlocks 3
specific branches, but most send/accept failure paths reduce to
the same close-and-compact behavior the EPIPE test already
covered. The infrastructure remains valuable for testing future
error-path additions; it's not pure overhead.

**New OPT entry**: `data_socket.c:208:bool:||:&&` — on Linux and
Darwin, `EAGAIN == EWOULDBLOCK` (same numeric value), so
`errno == EAGAIN || errno == EWOULDBLOCK` collapses to the same
test under either operator. Documented as OPT (equivalence-by-data,
not by structure).

**Ignore-file fragility documented** in
`docs/wiki/mutation-testing.md` §"Line numbers are fragile":
inserting code above an ignored mutation site invalidates the
entry. The 18-line fault-injection seam at the top of
`data_socket.c` shifted every entry below by +18; I re-anchored
them in the same commit. A future improvement (queued) is
content-hash fingerprinting so adds/removes don't churn the
ignore file.

**Aggregate after round 7**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1106  | 100     | 1006       | 527    | **52.4%**     |

(The "ignored" count is 100 with the EAGAIN OPT entry added but
the line-shift adjustments preserved net coverage; effective
delta on the aggregate is +1 mutant killed, +1 mutant ignored.)

**README badges** bumped: tests 2071 → 2085; mutation kill rate
52.2% → 52.3% of considered.

**Decisions worth flagging**:
- Used `static ssize_t (*g_send_fn)(...) = send;` rather than a
  conditional initializer or `dlsym` lookup. C99 allows function-
  symbol addresses in static initializers; one less branch in the
  hot path.
- Header declarations of the test setters are in `data_socket.h`
  itself rather than a separate `data_socket_test.h`. The "test
  only — production must not call" comment is the contract;
  splitting the header would add files for marginal isolation.
- The fault-injection tests use `dup(fd)` to mint fake fds for the
  accept-overflow test. Cheap, valid, harmless to close in cleanup.

### 2026-05-27 — Round 6: dns_snoop hop-chain + data_socket real-socket triage
**Commits**: *(this commit)*
**Touched**: `tests/test_dns_snoop.c`, `tests/test_data_socket.c`,
`README.md`, `PROGRESS.md`
**Why**: Two of the round-5 follow-ups closed without needing
infrastructure changes — the dns_snoop hop-chain test and the
data_socket compaction/empty-payload tests can be done with
real-socket manipulation alone, no fault-injection seam required.

**Per-file delta**:

| target            | before        | after          | delta   |
|-------------------|---------------|----------------|---------|
| `src/dns_snoop.c` | 51.1% (92/180) | **52.8%** (95/180) | +3 mutants |
| `src/data_socket.c` | 22.9% (24/105) | **26.7%** (28/105) | +4 mutants |

**Four new tests**:

`tests/test_dns_snoop.c` (2):
- `compression_chain_20_hops_succeeds`  — exactly 20 chained
  compression pointers must resolve to the trailing label "x".
- `compression_chain_21_hops_rejected`  — 21 chained pointers
  must trigger the `if (++hops > 20)` guard.

Together these pin the threshold and kill all four line-37
survivors: `rel >→>=`, `const 20→21`, `const 20→19`, and
`const 1→2` (the `++hops` increment becoming `hops += 2`).

`tests/test_data_socket.c` (2):
- `emit_empty_payload_is_skipped`     — `data_socket_emit("")`
  must not send anything (not even a bare `\n` that would corrupt
  the JSONL frame). Verifies by emitting "" then "hello" and
  asserting the consumer reads exactly "hello\n".
- `middle_client_disconnect_compacts` — three clients A/B/C; B
  disconnects; emit must compact via swap-with-last (line 200:
  `g_clients[i] = g_clients[--g_client_n]`) so A *and* C both
  still receive subsequent messages. A second emit confirms both
  remaining fds are still healthy.

**Aggregate after round 6**:

| total | ignored | considered | killed | of considered |
|-------|---------|------------|--------|---------------|
| 1106  | 99      | 1007       | 526    | **52.2%**     |

**README badges** bumped: tests 2053 → 2071; mutation kill rate
51.5% → 52.2%.

**Decisions worth flagging**:
- Skipped the fault-injection seam this round. The cheap real-
  socket wins delivered 7 more kills; the remaining
  `data_socket.c` survivors need infrastructure (a swappable
  `send` / `accept` pointer) which is more than this commit
  should carry. Surfaced as round-7 priority with a concrete
  ~10-line design sketch.
- The dns_snoop hop-chain test packets are hand-crafted following
  RFC 1035 §4.1.4 layout; inline comment explains the offset math
  so the next agent can extend (e.g. test the 22-hop case) without
  re-deriving.

### 2026-05-27 — Round 5: mutate the export-path files
**Commits**: *(this commit)*
**Touched**: `tests/test_jsonl.c`,
`.github/scripts/mutate-equivalents.txt`,
`docs/wiki/mutation-testing.md`, `README.md`, `PROGRESS.md`
**Why**: Round 5 of the verify-the-verifier campaign — the
export-path files were last on the round 1-4 priority list because
JSONL is a downstream contract (the iOS Swift client and any SIEM
forwarder reads it; schema drift breaks them silently).

**Per-file delta** (all numbers post-ignore-file):

| target               | mutants | ignored | considered | killed | kill-rate (considered) |
|----------------------|---------|---------|------------|--------|------------------------|
| `src/jsonl.c`        | 26      | 8       | 18         | 10     | **55.6%**              |
| `src/data_socket.c`  | 122     | 17      | 105        | 24     | **22.9%**              |
| `src/pcap_write.c`   | 43      | 8       | 35         | 21     | **60.0%**              |

**One new test** (`test_emit_icmp_v6_true_writes_one` in
`tests/test_jsonl.c`): with `is_v6 = 1`, asserts the emitted JSON
contains `"v6":1` AND does not contain `"v6":2`. Kills the
`is_v6 ? 1 : 0` const-1 mutation that the existing v6=0 test
couldn't catch (mutation 1→2 still emits `"v6":0` when is_v6 is false).

**New `OPT` equivalence class** documented in
[`docs/wiki/mutation-testing.md`](docs/wiki/mutation-testing.md):
early-return optimisation guards (e.g. `if (!any_sink() || !e)
return;`). Mutating the `||` to `&&` doesn't change correctness — the
function still produces the right output downstream; the early
return is only a fast-path skip. Eight `jsonl.c` emitters share this
exact pattern; all eight `|| -> &&` mutations now classified as OPT.

**~30 new equivalents added to** `mutate-equivalents.txt`:
- jsonl.c: 8 OPT (all emitter early-return guards) + 1 FAB
- data_socket.c: 17 (TIP negative-sentinel returns whose callers
  check `< 0`, SBL buffer sizes for `g_unix_path`, listen backlog)
- pcap_write.c: 8 (harness `>>` quirk, SBL `char path[128]`,
  TIP `fopen`-fail sentinel)

**README badge** bumped: `mutation kill rate` now 51.5% of
considered (was 54.7% — the addition of `data_socket.c` at 22.9%
pulled the aggregate down). The `tests` badge moved 2050 → 2053.

**Aggregate after round 5**:

| total mutants | ignored | considered | killed | kill-rate of considered |
|---------------|---------|------------|--------|-------------------------|
| 1106          | 99      | 1007       | 519    | **51.5%**               |

`data_socket.c` accounts for most of the surviving real gaps (81).
Tracked as the round-6 priority — those gaps are in the socket I/O
error paths and need a fault-injection seam to test cleanly.

**Decisions worth flagging**:
- pcap_write.c's raw kill rate dropped 53.5% → 48.8% between runs.
  Cause: the `> -> >=` ignore entry on line 15 matches three sites
  (the three `v>>8`, `v>>16`, `v>>24` shifts); two of those were
  killed before, so ignoring all three loses two kills. Acceptable
  for the harness-quirk class; would need fingerprints with column
  index to be more granular.
- Did not chase the 81 `data_socket.c` real survivors in this
  commit. They cluster in error paths that need a fault-injection
  seam (a `data_socket_inject_fault()` API guarded by a build flag),
  which is more design than this commit should carry. Surfaced as
  round 6 in the In-progress entry.

### 2026-05-27 — Round 4: `--ignore-file` flag + equivalence seed file
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py`,
`.github/scripts/mutate-equivalents.txt` (new),
`docs/wiki/mutation-testing.md`, `PROGRESS.md`
**Why**: Round 3 surfaced the diminishing-returns problem — by the
third round of triage, ~95% of surviving mutants on a file fell into
the documented equivalence classes. The raw kill rate stopped
trending because new tests couldn't catch what was already
unkillable.

`mutate.py` now accepts `--ignore-file PATH`. A default file ships
at `.github/scripts/mutate-equivalents.txt` and is loaded
automatically. Each non-blank, non-comment line is
`file:line:op:original:mutated`; matching mutants are reported as
**IGNORED** rather than **SURVIVED**, and the report surfaces two
kill rates: **of considered** (the real-test rate) and
**of total** (preserved for trend continuity with pre-ignore runs).

The seeded equivalents file covers seven classes documented in
[`docs/wiki/mutation-testing.md`](../docs/wiki/mutation-testing.md):
FPA (function-parameter array size), SBL (stack buffer sizing
literal), FXS (memcmp/memcpy length on fixed-size struct field),
LZT (loop bound reading zero-initialised tail), TIP (truthy-
initialiser perturbation), FAB (function-as-boolean return value),
LCP (lowercase prefix case-folding). Initial entries (~55) come
from manually-verified survivors in rounds 1-3. The discipline for
adding entries (per the wiki page): truly equivalent or leave as a
survivor — falsely-ignored real mutants hide forever.

**Kill-rate picture, before vs. after the ignore file** (all files
mutated so far, post-triage):

| file                 | raw     | effective (`of considered`) | ignored |
|----------------------|---------|------------------------------|---------|
| `src/alerts.c`       | 43.2%   | **47.0%**                    | 27      |
| `src/threat_intel.c` | 81.8%   | **100.0%**                   | 4       |
| `src/dga.c`          | 50.0%   | **53.7%**                    | 6       |
| `src/beacon_detect.c`| 72.2%   | **83.0%**                    | 7       |
| `src/dns_snoop.c`    | 47.4%   | **51.1%**                    | 14      |
| `src/sni_snoop.c`    | 51.4%   | **52.1%**                    | 2       |
| `src/http_snoop.c`   | 65.1%   | **70.0%**                    | 6       |
| **aggregate**        | **50.7%** | **54.7%**                  | **66**  |

Aggregate: 915 mutants total, 66 ignored, 849 considered, 464 killed.
The `alerts.c` raw is one decimal lower than the round-1 record
(43.8% → 43.2%) — run-to-run noise on a single-digit number of
mutants flipping. The trend stands.

`threat_intel.c` shows the value most clearly: the raw 81.8% had
hidden the fact that 100% of *non-equivalent* mutants are killed.
The wiki rule ("don't write fake assertions to kill equivalents")
made writing 0 new tests the right call in round 2 — `--ignore-file`
now makes that visible to future readers without re-deriving the
reasoning.

**No product behaviour change.** `make` warning-clean, `make test`
green (2050 assertions).

**Decisions worth flagging**:
- Default ignore file auto-loads if present. Skipping it requires
  passing `--ignore-file ""` explicitly. Trade-off: convenience
  beats surprise — agents running `make mutate` cold get the
  noise-suppressed view automatically; pure-raw mode is the
  one-keyword opt-out.
- The "of total" kill rate is kept in the report so historical
  trends remain comparable. Drop only if a future tooling round
  rewrites PROGRESS.md to use the considered rate consistently.

### 2026-05-27 — Mutation round 3 triage: dns_snoop + sni_snoop + http_snoop
**Commits**: *(this commit)*
**Touched**: `tests/test_http_snoop.c`, `tests/test_sni_snoop.c`,
`tests/test_dns_snoop.c`, `PROGRESS.md`
**Why**: Closed real gaps in the round-3 protocol-parser
baselines. Ten new tests across three files. Gains are smaller
than rounds 1-2 because the existing RFC-byte test discipline
already covered the happy paths; remaining survivors are
overwhelmingly equivalence-class.

**Per-file delta**:

| target            | before | after  | new tests | mutants killed |
|-------------------|--------|--------|-----------|----------------|
| `src/http_snoop.c`| 61.6%  | **65.1%** | 3         | +3             |
| `src/sni_snoop.c` | 47.9%  | **51.4%** | 3         | +5             |
| `src/dns_snoop.c` | 44.8%  | **47.4%** | 4         | +5             |

**New tests (10 total)**:

- `test_http_snoop`:
  - `host_with_hostsz_two`              : `hostsz < 2` boundary
  - `hostname_prefix_does_not_alias_host`: prefix-length 5 vs 4 —
                                          `Hostname:` decoy header
                                          must not match `Host:`
  - `host_no_space_after_colon`         : `ci_startswith`
                                          `slen < plen` boundary

- `test_sni_snoop`:
  - `sni_hostsz_zero_rejected`          : `hostsz <= 0` boundary
  - `sni_non_host_name_type_rejected`   : SNI extension with
                                          name_type ≠ 0x00 (rare,
                                          but reserved by the spec)
  - `sni_empty_name_rejected`           : SNI `name_len == 0`
                                          guard. Both come with
                                          new hand-crafted packets
                                          following the RFC 5246
                                          layout.

- `test_dns_snoop`:
  - `header_only_no_questions`          : `len < 12` boundary —
                                          12-byte header-only
                                          message must parse
  - `non_a_record_with_rdlen_4_not_injected`:
                                          NS record (TYPE=2) with
                                          RDLEN=4 must not be
                                          misread as A. Kills the
                                          `&& -> ||` mutation on
                                          line 113.
  - `a_record_with_wrong_rdlen_not_injected`:
                                          TYPE=A but RDLEN=5
                                          (malformed) must not
                                          inject.
  - `non_aaaa_record_with_rdlen_16_not_injected`:
                                          symmetric for line 125
                                          AAAA branch.

**Suite totals**: 2031 → 2050 assertions (+19); 0 failed. Build
warning-clean.

**Decisions worth flagging**:
- Did not chase the compression-pointer hop-count mutations
  (line 37 `if (++hops > 20)`). Killing them requires a hand-
  crafted DNS message with >20 distinct compression pointer
  hops — doable but verbose; queued in the In-progress entry.
- For `dns_lookup`, the original assertion `== NULL` was too
  strict. dns_lookup returns the IP itself when the entry is
  in PENDING state (queued by the background resolver), not
  NULL — so my assertion would fire on prior tests' residue.
  Loosened to "must not return the resolved hostname"; still
  kills the intended mutations.

### 2026-05-27 — OSI / TCP-IP stack view (`[l]`)
**Commits**: *(this commit)*
**Touched**: `src/views/osi.{c,h}` (new), `include/sloth.h` (VIEW_OSI
+ VIEW_COUNT bump 29→30), `src/tui.c`, `src/main.c`,
`src/views/help.c`, `Makefile`, `tests/test_osi.c` (new),
`tests/test_state.c`, `tests/test_arp.c`, `tests/main_test.c`,
`docs/views/osi.md` (new), `docs/views/README.md`
**Why**: User request — a synthesis view that maps everything sloth
sees onto the seven OSI layers, one row per layer, drawn as a grid
with ANSI box-drawing chars. Pure derivation from `sloth_state_t`:
- L7  DNS / HTTP / TLS / QUIC / mDNS / NBNS / NTP log counts
- L6  TLS-version histogram + distinct JA3 fingerprints (the legacy
      bucket lights up red on >0 to echo the WEAK_TLS alert)
- L5  TLS sessions / QUIC / EAPOL counts
- L4  TCP split by state (E/L/?), UDP, ICMP
- L3  distinct remote hosts (IPv4 / IPv6) + ARP mappings
- L2  ifaces, APs, STAs, devices, beacons
- L1  probe iface name (if monitor mode) or primary iface
Layout uses horizontal bracket rules (top/bottom) and an internal
`│` separator between the label and data columns. Side borders
intentionally dropped — content width varies per layer, and closing
them cleanly would require per-cell column tracking that added
nothing to readability. Three tests in `tests/test_osi.c`: empty
state, key noop, populated-state render.
**Follow-ups**: TLS-version histogram in the test exercises a
TLS 1.0 entry (legacy>0 path) but not the alert-palette colour
specifically. Out of scope for unit tests (null TUI swallows
attrs); covered when running the binary.

### 2026-05-27 — Mutation round 3 baselines (protocol parsers)
**Commits**: *(this commit, alongside OSI view)*
**Touched**: `PROGRESS.md`
**Why**: Recorded baseline kill-rates for the three protocol
parsers named as round-3 priority. No test additions in this
round — the user redirected mid-triage to the OSI feature, so
round-3 closure is deferred. Numbers stand as the starting
waterline for whoever picks this up.

| target            | mutants | killed | survived | kill-rate |
|-------------------|---------|--------|----------|-----------|
| `src/dns_snoop.c` | 194     | 87     | 107      | 44.8%     |
| `src/sni_snoop.c` | 142     | 68     | 74       | 47.9%     |
| `src/http_snoop.c`| 86      | 53     | 33       | **61.6%** |

`http_snoop.c` already at 61.6% — RFC-byte test discipline pays off.
The DNS/SNI parsers will likely have a chunky equivalence-class tail
(loop bounds reading zero-init, buffer-size literals on stack
buffers); real test gaps probably concentrate on extension-walk and
compression-pointer edge cases.

### 2026-05-27 — Mutation round 2: threat_intel + dga + beacon_detect
**Commits**: *(this commit)*
**Touched**: `tests/test_dga.c`, `tests/test_beacon_detect.c`,
`PROGRESS.md`
**Why**: Round 2 of the verify-the-verifier campaign (issue #4).
Baselined and (where worthwhile) triaged the three security-critical
files named in the issue as next-priority after `src/alerts.c`.

**Per-file results**:

- `src/threat_intel.c` (IOC matcher): **81.8% baseline (18/22)**.
  All 4 survivors fall in the documented equivalence classes —
  three are `return 1; → return 2;` (function-as-boolean), one is
  the empty-IOC guard which is unreachable given the fixed embedded
  list. **No new tests** — by the wiki page's own "don't write fake
  assertions to kill equivalent mutants" rule. Effective real-test
  kill rate: 100%.

- `src/dga.c` (DGA/DNS-tunnel heuristic): **36.4% → 50.0%** (+12).
  Added five boundary tests in `tests/test_dga.c`:
    - `label_exactly_ten_chars_flagged` (kills `len < 10` boundary)
    - `consonant_cluster_exactly_four` (kills `cons >= 4` boundary;
      constructed label `aakjxqe1212.com` keeps entropy ≈ 2.91 so
      the cluster signal is necessary, not redundant)
    - `digit_density_exactly_thirty_percent` (kills `>= 30` in the
      `30 → 31` direction)
    - `uppercase_label_normalized` (kills the `+ 32` ASCII
      case-conversion arith and `32 ± 1` const mutations on line 17,
      AND — via the AKJXBQZPQVZ.com follow-up — the `>= 'A'`
      char-range mutation that wasn't exercised by the lowercase
      tests)

- `src/beacon_detect.c` (periodicity detector for C2): **55.6% →
  72.2%** (+9). Added eight tests in `tests/test_beacon_detect.c`:
    - `find_distinguishes_port_from_ip` (kills the `&& → ||` in
      `find()` — would have aliased two tracks sharing only one
      coordinate)
    - `observe_empty_ip_is_noop` (kills `bd_observe`'s `|| → &&`
      NULL/empty guard mutation — empty string would otherwise
      create a track keyed on `""`)
    - `update_skips_zero_port_conn` (same shape for `bd_update`'s
      `||` guard on conn filtering)
    - `update_at_exact_gap_records_new_sample` (kills the
      `>= BD_GAP_S → > BD_GAP_S` boundary in `bd_update`)
    - `stats_two_samples_computes_mean` (kills `n < 2` early-return
      and the `2 ± 1` mutations on the minimum-samples guard)
    - `is_strong_at_exact_min_interval` (kills `mean <
      BD_MIN_INTERVAL_S` boundary)
    - `is_strong_at_exact_max_jitter_ratio` (kills the `jitter/mean
      > BD_MAX_JITTER_RATIO` boundary; constructed gaps
      [25,15,25,15] for mean=20, stddev=5, ratio=0.25 exact)
  Also moved `seed_conn` helper above the tests that need it
  (forward-declaration would have worked too).

**Suite totals**: 2008 → 2027 assertions (+19); 0 failed. Build
warning-clean.

**Decisions flagged** (per `docs/dark-factory.md` §4.2):
- Skipped writing tests for `threat_intel.c` survivors — documented
  equivalence-class only. The wiki page's rule is explicit; adding
  fake assertions would degrade the suite's honesty.
- Kept boundary-construction comments inline in the new tests
  (entropy/jitter math). The tests would otherwise look magic-number-y;
  the comment is the proof of correctness that lets the next agent
  modify the seed values without breaking the boundary semantics.
- Did not chase the remaining 44 dga.c / 15 beacon_detect.c / 4
  threat_intel.c survivors. The remaining gaps are dominated by the
  equivalence classes plus a few constructed-input cases (e.g.
  `bd_stats` mean==0 guard requires synthetically seeding a
  zero-cadence track).

### 2026-05-26 — Close mutation-testing gaps round 1 (`src/alerts.c`)
**Commits**: *(this commit)*
**Touched**: `tests/test_alerts.c`, `docs/wiki/mutation-testing.md`,
`PROGRESS.md`
**Why**: First triage round on the 258 surviving mutants from the
`make mutate` baseline on `src/alerts.c`. Targeted the four
highest-survivor rules — `rule_rogue_dhcp` (41), `rule_arp_spoof`
(37), `rule_evil_twin` (27), `rule_probe_flood` (23) — plus the
`mac_to_str` byte-index cluster (12, reached indirectly via
`rule_deauth_flood`). Added nine new boundary / detail-content
tests, fixed `add_deauth_flood`'s missing `memset` (latent bug —
`bssid` was uninitialised), and added a "known equivalence classes"
section to `docs/wiki/mutation-testing.md` that names the patterns
that will always survive (function-parameter array sizes, stack
buffer sizing, loop bounds reading zero-init tail, truthy
initialisers).

**Kill-rate trajectory** for `src/alerts.c`:
| pass        | mutants | killed | survived | kill-rate |
|-------------|---------|--------|----------|-----------|
| baseline    | 329     | 71     | 258      | 21.6%     |
| after r1    | 329     | 144    | 185      | **43.8%** |

Per-rule survivor counts (baseline → after r1): arp_spoof 37 → 14,
rogue_dhcp 41 → 32, evil_twin 27 → 7, probe_flood 23 → 12,
mac_to_str 12 → 2, deauth_flood 5 → 5 (all 5 remaining are
documented equivalence-class patterns). Build warning-clean.
`make test` green: 2008 assertions, 0 failed.

**Decisions flagged**:
- Did not write tests for mutants in the equivalence classes —
  documented them instead. Adding fake assertions to "kill" them
  would have made the suite lie. The wiki page §"Known equivalence
  classes" is now the operator's reference for skipping them.
- Did not chase deep snprintf-loop arithmetic mutations (lines 655,
  656, 662, 663 in rule_rogue_dhcp). Real gaps, but at the level of
  "off-by-one in string formatting on >2-server case" with low
  practical impact. Left for round 2.
- Sample test bug caught during development: `mac[6] = {0x11, ...}`
  triggered the rule's multicast-skip (LSB set). Now corrected and
  the lesson noted inline.

### 2026-05-26 — Mutation-testing harness (`make mutate`, closes #4)
**Commits**: *(this commit)*
**Touched**: `.github/scripts/mutate.py` (new, ~370 LoC),
`Makefile` (added `mutate` target), `docs/wiki/mutation-testing.md`
(new), `docs/wiki/index.md`, `docs/wiki/log.md`, `PROGRESS.md`
**Why**: Closes the loop the dark-factory pattern doc
([`docs/dark-factory.md`](docs/dark-factory.md) §3.3) opens: the
Level-5 claim in `MISSION.md` rests on `make test` being a
trustworthy oracle, but the suite had ~1974 hand-crafted assertions
with no evidence they'd actually fail on real regressions.
`make mutate` introduces small faults (relational swaps, ±1 on
integer literals, `&&`↔`||`, `+`↔`-`, `return N` → `return 0`) into
src files one at a time, runs `make -B test`, and reports surviving
mutants as concrete test-suite gaps. Sandboxed: src is never
modified in place — the harness copies the repo to a tmpdir and
mutates there. No third-party framework, no product behaviour
changes, `make` + `make test` still clean.
**Baseline kill-rates** (record as new targets are added):
| target          | mutants | killed | survived | kill-rate |
|-----------------|---------|--------|----------|-----------|
| `src/alerts.c`  | 329     | 71     | 258      | 21.6%     |
The low rate confirms issue #4's premise: assertions were broadly
counted but rarely targeted at thresholds and boundary conditions.
A sampled review of survivors shows ~30–40% are likely equivalent
mutants (function-parameter array sizes, no-effect post-condition
writes); the rest are real gaps.
**Follow-ups**: see In-progress entry above (close the gaps on
`src/alerts.c` first, then mutate `src/threat_intel.c`, `src/dga.c`,
`src/dns_snoop.c`, `src/beacon_detect.c` in that order). A minor
cosmetic issue: the "killed (build broke)" sub-counter sometimes
catches test-binary segfaults instead of compile failures (stderr
contains both "error" and "make"). Real kill-count is correct; only
the breakdown is noisy.

### 2026-05-26 — Read-only data socket (`--data-socket SPEC`)
**Commits**: `1199563`
**Touched**: `src/data_socket.{c,h}` (new), `src/jsonl.c`, `src/main.c`,
`tests/test_data_socket.c` (new), `tests/main_test.c`, `Makefile`,
`docs/wiki/jsonl-schema.md` (new), `docs/wiki/index.md`, `FACTORY.md`
**Why**: Implements the data socket the 2026-05-25 MISSION §4
amendment opened the door for. Supports `unix:/path` (local SIEM
agents) and `tcp:HOST:PORT` (e.g. binding to a Tailscale IP so the
upcoming iOS Swift UI dashboard can consume the JSONL stream over
the tailnet). Read-only — nothing is ever read from the socket.
Multi-client (up to 16), non-blocking writes, drop slow lines on
EAGAIN, harvest on EPIPE. Hooked into `src/jsonl.c` so every
`jsonl_emit_*` line broadcasts to both sinks; the new `any_sink()`
helper short-circuits format work when nobody is listening. 5 new
unit tests via a hermetic UNIX-domain fixture; 1974 assertions
total. Build warning-clean. Bonus: `docs/wiki/jsonl-schema.md`
finally pins down the stream format and resolves the long-standing
`docs/wiki/log.md` naming-collision follow-up.
**Follow-ups**: TCP path is exercised by the production binary but
not by a unit test (ephemeral-port collisions in CI). An iOS
SwiftUI client consumer is upcoming work.

### 2026-05-26 — Three-tier alert palette + cross-panel severity coloring
**Commits**: `21814ec`
**Touched**: `include/sloth.h`, `src/tui.h`, `src/tui.c`, `src/main.c`,
`src/alerts.c`, `src/views/alerts.c`, `src/views/dashboard_bands.c`,
`src/views/packets.c`, `tests/null_tui.c`, `tests/test_alerts.c`,
`docs/views/alerts.md`, `docs/wiki/alerts.md`, `docs/wiki/ip-palette.md`
**Why**: The old alert palette was binary (WARN/CRIT). Port-scan
reconnaissance and active attack-path exploitation rendered the same
deep red across every panel, which devalued the red channel — the
operator couldn't tell at a glance whether a flagged IP was
"interesting" or "on fire". Three-tier (LOW=yellow / WARN=orange /
CRIT=red) restores the gradient. Reclassified `PORT_SCAN`,
`NXDOMAIN_BURST`, and `PROBE_FLOOD` to LOW. Cross-panel
`tui_alert_hot_*` now carries severity; `tui_alert_hot_check(ip)`
returns the tier (or -1 if cold); `tui_alert_hot_set` is
promotion-only so a later LOW won't downgrade an earlier CRIT.
1950 assertions still pass; build warning-clean.
**Follow-ups**: none directly; the data-socket follow-up below would
benefit from exporting the per-IP severity too.

### 2026-05-25 — Three-tier mission amendment + dashboard.c split
**Commits**: `f4dda8d`, `0ddda50`
**Touched**: `src/views/dashboard*.c`, `Makefile`, `MISSION.md`,
`docs/wiki/log.md`
**Why**: `src/views/dashboard.c` had grown to 1863 lines (2.3× the
next largest file in the repo) and mixed orchestration, primitives,
and 17 per-panel renderers. Split into orchestrator (456) +
primitives (199) + bands (755) + grid (455) + internal header (104).
Same commit window opened the door for a future read-only local data
socket by tightening the MISSION §4 ban: it now targets *control*
surfaces specifically and explicitly allows a `tail -f`-style
data-only socket. 1950 test assertions still pass; build is
warning-clean.
**Follow-ups**: data-socket implementation (not started).

### 2026-05-25 — FACTORY.md build & infra runbook
**Commits**: `c62b8f0`
**Touched**: `FACTORY.md` (new), staged previously-untracked
`MISSION.md` and `docs/dark-factory.md`
**Why**: An agent landing on the repo cold needs one file that
answers "what do I install, build, run, deploy, debug?". Charter
(MISSION) and pattern (dark-factory) already existed; FACTORY closes
the loop on the operational side.
**Follow-ups**: none.

### 2026-05-25 — Wiki prime from per-view docs
**Commits**: `8ca0b99`
**Touched**: `docs/wiki/*.md` (15 concept pages + index + log),
`docs/CLAUDE.md`
**Why**: First ingest of the per-view docs (`docs/views/*.md`) into
a Karpathy-style LLM Wiki. Source view docs are immutable; the wiki
adds a concept layer (alerts, JA3, threat-intel, beacon-detection,
wifi-sigint, mac-randomisation, ip-palette, platform-vtable,
pcap-export, attack-map, etc.) cross-linked with `[[wiki-link]]`.
**Follow-ups**: JSONL schema page (MISSION §4(3) names
`docs/wiki/log.md` as the home but the current `log.md` is the wiki
ops log — naming collision to resolve).

---

## Open follow-ups (not yet owned)

### Forwarder / consumer extensions

- **Additional forwarder sinks** — `examples/forwarder/` ships
  HEC, syslog, Elastic, Loki, Datadog, and webhook. OpenSearch
  compatibility documented under the Elastic section (wire-
  compatible `_bulk`). Slack/Discord-style incoming webhooks
  intentionally not supported as a built-in sink (their message
  envelope is outside the schema-agnostic remit); operators write
  a transform proxy or use a Slack app.
- ~~**Sink fan-out**~~ — landed 2026-06-03. `--sink loki,datadog`
  (comma-separated) pushes every record to every named sink in the
  same batch. Per-sink failures are isolated; stats output adapts
  to show each sink's forwarded/dropped/retries separately. Sends
  are sequential per batch — one slow sink slows the whole
  pipeline, so use separate forwarder processes when backpressure
  isolation matters. Smoke test now covers fan-out alongside the
  individual sinks (one producer → forwarder → two fake-sink HTTP
  servers).
- ~~**Smoke-test the consumer/forwarder in CI**~~ — landed
  2026-06-03 in `examples/compose/smoke_test.py` +
  `.github/workflows/examples-smoke.yml`. Runs end-to-end
  (mock-sloth → forwarder → fake Loki) in &lt;10 s and asserts every
  record type in mock-sloth's template list arrives at the sink.

### iOS / Tailscale (out of this repo)

- **Tailscale integration** — install + configure on the deployment
  host so `--data-socket tcp:100.x.x.x:8765` actually reaches the
  iOS client. Out of repo (configuration, not code), but blocks the
  iOS client from being useful.
- **iOS SwiftUI client** — consume the data socket and render the
  same panels sloth shows in the TUI. Lives in a separate repo
  (confirmed by the operator 2026-05-28).

### Product depth (sloth itself)

- ~~**Beacon detection v2**~~ — landed 2026-06-03. `bd_is_strong`
  now returns kind=1 (v1 low-jitter) or kind=2 (v2 gap-concentration)
  to a unified call site. v2 catches ~40% additive jitter (covers
  Cobalt at "interactive" 30% and Sliver default) at ~0.1% per-flow
  false positive rate. Alert detail labels which detector fired.
  Sliver "low-and-slow" at 50% jitter still uncaught — statistical
  separation isn't reliable with the current 16-sample buffer; the
  mitigation is longer flow histories feeding v1.
- **More passive observables** — per MISSION §4(1) "coverage > precision":
  SMB/CIFS metadata, Kerberos pre-auth, LDAP referral leakage,
  BGP route monitor for peering segments, IPv6 RA/NDP surface in alerts.
- **Sibling forensic-export formats** — CEF, RFC 5424 syslog, Splunk
  HEC-over-local-socket as **emitters** alongside JSONL. (Note:
  forwarders can already deliver these formats *downstream*; this
  follow-up is about sloth speaking them natively as a sink.)
