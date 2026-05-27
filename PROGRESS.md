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

### Mutation-testing follow-ups (rounds 8+)
**Owner**: next agent
**Started**: 2026-05-27
**Goal**: `data_socket.c` remains the biggest open pile at 27.6%
(76 real survivors). The fault-injection seam is in place; the
remaining survivors cluster in `init_tcp` / `init_unix` error
paths (DNS resolution, getaddrinfo failures, port-parse edge
cases) that need test packets with malformed specs we haven't
covered.
**Status**: rounds 1-7 closed. Aggregate kill rate is 52.3% of
considered (527 killed / 1007 considered / 1106 mutants total).
The fault-injection seam (round 7) delivered fewer kills than
hoped (+1) because most send/accept failure paths reduce to the
same close-and-compact behavior the EPIPE test already covered.
The infrastructure remains valuable for testing future
error-path additions.
**Blockers**: none.
**Next concrete step** (in priority order):
1. Triage `init_tcp` / `init_unix` survivors. Lots of return-`-1`
   paths with different `fprintf` messages — most are TIP-class
   negative-sentinel equivalents. Add targeted tests for the
   ones that have observable behaviour differences (e.g. bad
   port, missing colon).
2. Consider a content-based fingerprint for the ignore file so
   adding code to a file doesn't invalidate all entries below.
   E.g. include a 16-byte hash of the surrounding 3 lines in
   the fingerprint. Cost: re-derive on every line that moves.
3. As new equivalents emerge from future runs, append to
   `.github/scripts/mutate-equivalents.txt` (conservatively).
4. Cosmetic: tighten the "killed (build broke)" sub-counter.

---

## Recently landed

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

- **Tailscale integration** — install + configure on the deployment
  host so `--data-socket tcp:100.x.x.x:8765` actually reaches the
  iOS client. Out of repo (configuration, not code), but blocks the
  iOS client from being useful.
- **iOS SwiftUI client** — consume the data socket and render the
  same panels sloth shows in the TUI. Out of this repo.
- **Beacon detection v2** — current `BEACONING` detector
  blind-spots aggressive (>25%) jitter. An autocorrelation-based
  variant would catch modern C2 frameworks (Sliver, Cobalt) that
  deliberately defeat the current heuristic.
- **More passive observables** — per MISSION §4(1) "coverage > precision":
  SMB/CIFS metadata, Kerberos pre-auth, LDAP referral leakage,
  BGP route monitor for peering segments, IPv6 RA/NDP surface in alerts.
- **Sibling forensic-export formats** — CEF, RFC 5424 syslog, Splunk
  HEC-over-local-socket as emitters alongside JSONL.
