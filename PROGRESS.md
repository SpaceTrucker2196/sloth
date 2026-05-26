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

### Mutation-testing follow-ups (round 2)
**Owner**: next agent
**Started**: 2026-05-26
**Goal**: Pick up where round 1 stopped — the remaining 185
survivors on `src/alerts.c` cluster in the documented equivalence
classes (buffer sizes, loop bounds reading zero-init tail, truthy
init values). Decide per-cluster whether to add tests, refactor the
code to eliminate the equivalence, or accept the noise floor.
**Status**: round 1 closed (see "Recently landed" below) — kill rate
21.6% → 43.8% in a single pass against `src/alerts.c`.
**Blockers**: none.
**Next concrete step** (in priority order):
1. Mutate the high-value files we haven't touched: `src/threat_intel.c`,
   `src/dga.c`, `src/dns_snoop.c`, `src/beacon_detect.c`. These are
   security-critical and have well-defined input shapes.
2. Consider an `--ignore-file` flag on `mutate.py` so known equivalence
   classes (function-parameter array sizes, loop-bound `<→<=`) can be
   filtered from the survivor list, making the kill rate trend more
   informative as the suite improves.
3. Cosmetic: the "killed (build broke)" sub-counter mis-categorises
   test-binary segfaults as build failures (stderr contains both
   "error" and "make"). Tighten the heuristic to look for the actual
   "make: *** [...] Error 1" pattern.

---

## Recently landed

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
