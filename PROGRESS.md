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

### Add `connections` record type to JSONL stream
**Owner**: next agent
**Started**: 2026-05-28
**Goal**: Emit per-flow connection records on the JSONL stream so
`sloth-ios` (and any other consumer) can build a Connections view with
RTT sparklines.
**Status**: not started — all data structures already exist in-tree.
**Blockers**: none.
**Next concrete step**:

Implement a `jsonl_emit_connections(const sloth_state_t *s)` function
that iterates `s->conns[0..conn_count)`, joins each entry with its
`conn_bw_t` via `bw_lookup()`, and emits one JSONL line per flow.

**Required record shape** (one JSON object per line, per flow):

```jsonc
{
  "type":     "connections",
  "ts":       <unix seconds — use time(NULL)>,
  "src":      "<local_addr>:<local_port>",   // host:port or [v6]:port
  "dst":      "<remote_addr>:<remote_port>",
  "proto":    "tcp",             // "tcp" | "udp"
  "state":    "ESTABLISHED",     // tcp_state_name(); omit for UDP
  "rtt_ms":   12.4,              // conn_t.rtt_us / 1000.0; omit if 0 or UDP
  "retx":     0,                 // conn_t.retrans; omit for UDP
  "rx_bytes": 12345,             // conn_bw_t.rx_bytes (0 if no bw entry)
  "tx_bytes": 6789,              // conn_bw_t.tx_bytes (0 if no bw entry)
  "age_s":    47                 // seconds since first observation — requires tracking first_seen per flow
}
```

**Implementation plan** (files to touch):

1. **`src/jsonl.h`** — declare `void jsonl_emit_connections(const sloth_state_t *s);`
2. **`src/jsonl.c`** — implement the emitter:
   - Loop `s->conns[0..conn_count)`.
   - Format `src` as `addr:port` (use `[%s]:%u` for IPv6).
   - For TCP: include `state`, `rtt_ms` (if non-zero), `retx`.
   - For UDP: omit those three fields.
   - Join with `bw_lookup(s, &s->conns[i])` for `rx_bytes`/`tx_bytes`.
   - `age_s` requires a per-flow first-seen timestamp. Options:
     (a) add a `time_t first_seen` field to `conn_t` in `include/sloth.h`
         and populate it in `src/platform/linux_conns.c` (use current time
         on first appearance, carry forward on subsequent polls); or
     (b) omit `age_s` in the first pass — `sloth-ios` can compute it
         client-side from the first record it receives for a tuple.
     Prefer (a) if feasible without breaking the platform vtable contract.
3. **`src/main.c`** — call `jsonl_emit_connections(&g_state)` from
   `poll_data()` (or from the redraw tick), after `conn_rebuild_idx`
   and `bw_update` have run.
4. **`docs/wiki/jsonl-schema.md`** — add a `### connections` section
   documenting the new record type, following the existing format.
5. **`tests/test_jsonl.c`** — add a test that:
   - Seeds `sloth_state_t` with 2–3 fake connections (TCP + UDP).
   - Calls `jsonl_emit_connections`.
   - Captures output and asserts correct JSON field presence and types.
6. **`include/sloth.h`** — if adding `first_seen`, add it to `conn_t`.

**Existing code to follow as a pattern**:
- `jsonl_emit_dns()` in `src/jsonl.c` — shows the `start_obj` /
  `kv_str` / `kv_int` / `end_obj` / `emit_line` pattern.
- `bw_lookup()` in `src/bandwidth.c` — joins `conn_t` → `conn_bw_t`.
- `tcp_state_name()` in `src/views/conns.c` — maps int state → string.
- `tests/test_jsonl.c` — existing emit tests show how to capture output.

**Cadence**: emit once per `poll_data()` tick (≈1 Hz). Every active
flow gets a record each tick. No dedup / state-change filtering needed;
the consumer rebuilds the table from the latest snapshot keyed by
`(src, dst, proto)`.

**What NOT to do**:
- Don't add a separate flow-id field.
- Don't emit individual RTT samples or congestion-window data.
- Don't retro-fill `rtt_ms` for closed flows.
- Don't break the existing 7 record types.

**Acceptance criteria**:
- `make test` passes (including the new test).
- `make` is warning-clean.
- Running `sloth -o /tmp/test.jsonl` on a machine with active TCP/UDP
  connections produces `{"type":"connections",...}` lines in the file.
- The record shape matches the spec above (verified by the test).

---

### Evil-twin AP — same-cipher, vendor-IE, and Pineapple/ESP32 fingerprint detection
**Owner**: next agent
**Started**: 2026-06-01
**Goal**: Extend `rule_evil_twin` to detect modern same-cipher evil-twin attacks with attack-chain correlation.
**Status**: planned — design documented, implementation not started.
**Blockers**: none (pcap fixtures needed for test suite — can be synthesised with scapy)
**Next concrete step**: implement phase 1 (data model + same-cipher detection)

#### Plan (phases)

**Phase 1 — Data model & same-cipher twin detection (~3 days)**
1. Add `ap_fingerprint_t` struct to `include/sloth.h`:
   - `uint8_t oui[3]; uint16_t beacon_interval_ms; uint32_t vendor_ies_hash; uint8_t flags;`
   - Flags: `WPS_UUID_ZERO | HT_PRESENT | VHT_PRESENT | HE_PRESENT | DEFAULT_HOSTAPD_CAPS | HAK5_OUI | ESPRESSIF_OUI`
2. Extend `beacon_ap_t` with `ap_fingerprint_t fp` and `int8_t rssi_max_60s, rssi_min_60s`.
3. Add `ALERT_TYPE_EVIL_TWIN_PROXIMITY` enum value.
4. Modify `rule_evil_twin()` in `src/alerts.c`: fire WARN when same SSID + different BSSID + **same** `enc` string + different OUI vendor (instead of requiring weak-vs-strong mismatch).
5. Add test cases to `tests/test_alerts.c` for same-cipher twin detection.

**Phase 2 — Vendor-IE mismatch & attacker OUI tables (~2 days)**
1. Create `src/wifi_oui_attacker.c` with embedded OUI tables (Hak5, Espressif).
2. Hash tagged vendor IEs (tag 221) per BSSID in beacon_snoop; store in `ap_fingerprint_t.vendor_ies_hash`.
3. On same-SSID/same-cipher pair, if vendor-IE hashes differ → escalate to CRIT.
4. Populate `ap_fingerprint_t.flags` from beacon parsing (HT/VHT/HE caps, WPS UUID, hostapd defaults).
5. Match against attacker OUI list to raise severity one tier.

**Phase 3 — RSSI-step proximity detection (~1 day)**
1. Track per-BSSID RSSI min/max in a 60 s sliding window.
2. If RSSI delta ≥ 15 dBm within window (no roam) → fire `EVIL_TWIN_PROXIMITY`.

**Phase 4 — Attack-chain correlation (~2 days)**
1. If `DEAUTH_FLOOD` target BSSID matches the "real" half of a same-cipher twin pair within 5 s → fire `EVIL_TWIN` at CRIT with detail `attack-in-progress`.
2. Tag any subsequent EAPOL capture against the twin BSSID with `provenance=tainted-evil-twin` in .22000 export.

**Phase 5 — UI surface (~2 days)**
1. Beacon view `[b]`: twin-cluster pairs share a color, suspicious vendor IEs marked `⚑`, RSSI step inline.
2. New `[x] Twins` view: one row per twin cluster (real BSSID, twin BSSID, cipher, OUI diff, rssi delta, attack-chain indicator).
3. JSONL output: add "Evil-twin episodes" section.

**Phase 6 — Test fixtures & integration tests (~2 days)**
1. Create `tests/fixtures/evil-twin-*.pcap` with scapy (same-cipher twin, vendor-IE delta, RSSI step, deauth-then-twin).
2. Assertions per test plan in issue (5 acceptance criteria).
3. Mark tests `needs-pcap-fixture`.

#### References
- MITRE ATT&CK T1557.004 — Evil Twin
- CISA — Securing Enterprise Wireless Networks (2024)
- CERT/CC VU#871675 — hostapd/wpa_supplicant WPA3/SAE
- CVE-2022-23303 / CVE-2022-23304

---

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
  HEC, syslog, and Elastic. Natural next additions, in rough
  popularity order: Loki (`/loki/api/v1/push`), Datadog Logs
  intake, OpenSearch (works against the Elastic sink already with
  `--es-url` repointed; document or add a thin alias), generic
  webhook (POST raw JSON to any URL — useful for Discord/Slack
  alerting integrations). Sink interface is two members per the
  README's "Adding a sink" recipe; ~30 lines each.
- **Sink fan-out** — currently one forwarder process per sink.
  A multi-sink mode would let one process push to both Splunk and
  Elastic from the same source connection. Worth it only if
  backpressure isolation isn't important to the operator.
- **Docker Compose demo stack** — `examples/compose/` with sloth +
  forwarder + a SIEM (Elastic + Kibana, or Grafana + Loki) so the
  whole pipeline can be brought up with one `docker compose up`.
  Good for evaluators and as a CI integration test.
- **Smoke-test the consumer/forwarder in CI** — currently
  hand-run; could be a `.github/workflows/examples.yml` that spins
  up a fake sloth producer, runs each script for ~5s, asserts the
  expected records arrive at a fake sink. Catches regression on
  schema additions.

### iOS / Tailscale (out of this repo)

- **Tailscale integration** — install + configure on the deployment
  host so `--data-socket tcp:100.x.x.x:8765` actually reaches the
  iOS client. Out of repo (configuration, not code), but blocks the
  iOS client from being useful.
- **iOS SwiftUI client** — consume the data socket and render the
  same panels sloth shows in the TUI. Lives in a separate repo
  (confirmed by the operator 2026-05-28).

### Product depth (sloth itself)

- **Beacon detection v2** — current `BEACONING` detector
  blind-spots aggressive (>25%) jitter. An autocorrelation-based
  variant would catch modern C2 frameworks (Sliver, Cobalt) that
  deliberately defeat the current heuristic.
- **More passive observables** — per MISSION §4(1) "coverage > precision":
  SMB/CIFS metadata, Kerberos pre-auth, LDAP referral leakage,
  BGP route monitor for peering segments, IPv6 RA/NDP surface in alerts.
- **Sibling forensic-export formats** — CEF, RFC 5424 syslog, Splunk
  HEC-over-local-socket as **emitters** alongside JSONL. (Note:
  forwarders can already deliver these formats *downstream*; this
  follow-up is about sloth speaking them natively as a sink.)
