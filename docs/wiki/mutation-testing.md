---
name: mutation-testing
description: In-tree harness that mutates src/*.c, reruns `make test`, and reports surviving mutants as concrete test-suite gaps.
type: reference
---

# Mutation testing

**Summary**: `make mutate` introduces small, well-defined faults into
`src/*.c`, rebuilds the test binary, and reruns `make test`. Every
mutant should be killed (at least one assertion flips red). Surviving
mutants are concrete gaps in the test suite — either a missing
assertion or genuinely dead/equivalent code. This is how sloth checks
that its **test suite itself** is trustworthy enough to back the
[[sloth|Level-5]] autonomy claim in [`MISSION.md`](../../MISSION.md).

**Sources**: GitHub issue #4, [`docs/dark-factory.md`](../dark-factory.md) §3.3,
`.github/scripts/mutate.py`.

**Last updated**: 2026-05-26.

---

## Why

`make test` is the oracle. If the assertions don't actually fail when
the code regresses, the oracle is lying and the dark-factory loop
([[sloth]]) is shipping unchecked work. Coverage (gcov) measures
*execution* — what lines ran. Mutation testing measures *fault
detection* — whether your tests would notice if those lines broke.
The two are only weakly correlated: 100% line coverage can pair with
0% mutation kill-rate.

The point is not a green score. The point is: every surviving mutant
is either a real test gap (write the assertion that would have caught
it) or a known-equivalent mutant (document and move on). Either way
the suite gets stronger.

---

## How to run

```sh
# Default: mutate src/alerts.c with all five operator families.
make mutate

# Pass-through flags via MUTATE_FLAGS.
make mutate MUTATE_FLAGS="--files src/alerts.c src/threat_intel.c"
make mutate MUTATE_FLAGS="--operators rel const"
make mutate MUTATE_FLAGS="--files src/dga.c --limit 50 --seed 7"
make mutate MUTATE_FLAGS="--report /tmp/mutate.txt"
make mutate MUTATE_FLAGS="--keep-sandbox"   # leaves tmpdir for inspection
```

Direct invocation:

```sh
python3 .github/scripts/mutate.py --files src/alerts.c
```

The harness:

1. Copies `Makefile`, `src/`, `include/`, `tests/` into a tmpdir.
2. Runs `make test` once in the sandbox to confirm the baseline is
   green. Aborts if it isn't.
3. For each mutation site: applies the mutation in the sandbox, runs
   `make -B test` (force-rebuild — see "Implementation notes" below),
   records kill vs. survive, restores the file from the saved
   baseline copy.
4. Prints a summary plus a list of surviving mutants
   (`file:line:operator:note`).

Product source under `/Users/.../sloth/src/*.c` is **never modified**.

Runtime estimate: one full `make -B test` cycle takes ~3 s; one source
file's worth of mutation sites typically runs in 200–400 mutants,
so plan ~10–20 min for a full file. Use `--limit` for a quick poke;
use the bare default for a baseline run.

---

## Mutation operators

Five operator families, all text-level. No C parser dependency — a
small state machine masks strings, character literals, comments, and
preprocessor lines so mutations only land on executable code.

| op       | What changes | Example | Why it matters |
|----------|--------------|---------|----------------|
| `rel`    | Relational / equality swaps: `>` ↔ `>=`, `<` ↔ `<=`, `==` ↔ `!=`. | `if (count > THRESH)` → `if (count >= THRESH)` | Off-by-one detector. Catches threshold tests that fire one step too early or too late. |
| `arith`  | `+` ↔ `-` on binary infix integer arithmetic (skips `++`, `--`, `+=`, unary, `->`). | `i + 1` → `i - 1` | Index/threshold computation errors. |
| `bool`   | `&&` ↔ `\|\|`. | `a && b` → `a \|\| b` | Logic-shape regressions in rule predicates and validators. |
| `const`  | Integer literals ±1. Skips `0`, values ≥ 1024 (buffer sizes), hex/binary literals. | `MAX_TRIES = 5` → `4` or `6` | Threshold drift in alert rules — the highest-value class on `src/alerts.c`. |
| `return` | `return N;` (N ≠ 0) → `return 0;`. | `return 1;` → `return 0;` | Boolean / error-code return-path regressions. |

Operators were chosen for high signal-per-mutant: each one tests a
property an experienced reviewer would actively look for in a code
review, made mechanical.

What's **not** mutated (yet):

- Statement deletion — high uncompilable-mutant rate; revisit when the
  harness is more mature.
- Pointer-arithmetic changes — too easy to produce equivalent or
  trivially-segfaulting mutants.
- Floating-point operators — sloth's `src/` has very few of these.
- String-literal mutations — the BPF filter, format strings, etc. are
  not where bugs hide.

---

## Reading the report

```
== Mutation summary ==
Files:     src/alerts.c
Operators: rel, arith, bool, const, return
Mutants:   329
Killed:    231 (70.2%)
           ├─ by build break: 0
           └─ by timeout:     0
Survived:  98

Surviving mutants (test-suite gaps):
  src/alerts.c:  114  const    20 -> 21
  src/alerts.c:  515  rel      < -> <=
  ...
```

- **Killed** — at least one assertion flipped red. The test suite
  caught the regression. Good.
- **Killed by build break** — the mutated code failed to compile.
  Counts as killed because no surviving binary could pass tests, but a
  high rate here suggests an operator is producing low-quality
  mutants. Not informative.
- **Killed by timeout** — the mutant introduced an infinite loop or
  pathologically slow path. Counts as killed (the suite did notice
  *something* was wrong).
- **Survived** — the test suite returned green. This is the to-do
  list.

---

## What to do with a surviving mutant

Each survivor is one of three things. Decide which, then act.

**1. A real test gap.** The mutation introduces a behaviour change
that no assertion notices. Write the assertion. Example: a `const`
mutation flips an alert threshold from 5 to 6; the existing test
seeds the rule with exactly 10 hits, so both thresholds fire — add a
test that seeds 5 hits and asserts the alert *does* fire at 5 but
*does not* fire at 4.

**2. An equivalent mutant.** The mutation is semantically identical
to the original. Common patterns:

- A variable assignment that's only ever truth-checked (`x = 1` vs.
  `x = 2` — both truthy, no test can distinguish).
- A loop bound mutation where the extra iteration reads a
  zero-initialised slot and continues immediately on a guard check.
- An arithmetic operator change on values that are always 0 in tested
  paths.

Equivalent mutants are noise. Document them in the test for the
relevant function (`/* equivalent: mutation analysis 2026-05-26 */`)
so the next mutation run isn't a surprise, but don't write a fake
assertion to "kill" them — that just makes the test suite lie.

**3. Genuinely dead code.** The mutation lands on code that no test
exercises *at all*. Either add coverage or delete the dead code per
the CLAUDE.md "no dead code" rule.

---

## Filtering known equivalents

After a few triage rounds the survivor list starts to plateau at the
documented-equivalence-class noise floor. `make mutate` supports a
`--ignore-file PATH` flag that suppresses these from the survivor
count so the kill rate trend stays informative.

A default file ships in-tree at
[`.github/scripts/mutate-equivalents.txt`](../../.github/scripts/mutate-equivalents.txt)
and is loaded automatically. To use a custom file:

```sh
make mutate MUTATE_FLAGS="--files src/alerts.c \
                          --ignore-file path/to/custom.txt"
```

### Format

One entry per non-blank, non-comment line:

```
<file>:<line>:<op>:<original>:<mutated>    # optional comment
```

Match is exact on all five fields. When a mutant's fingerprint
appears here, it's reported as **IGNORED** rather than **SURVIVED**,
and the effective kill rate becomes `killed / (total - ignored)`.

### Line numbers are fragile

The fingerprint includes the line number, so inserting code above an
ignored mutation site invalidates the entry — the mutation
resurfaces as a survivor at its new line. When you add or remove
significant lines in a file, run `make mutate` against that file
and re-anchor the affected ignore entries.

(A future improvement, queued in `PROGRESS.md`, is fingerprinting by
content + nearby context instead of line number. For now, the
trade-off is fingerprint precision vs. churn — line numbers won.)

### When to add an entry

A deliberate act, not a workaround:

1. The mutation must be **truly** equivalent — no observable
   behaviour change for any reasonable input the function sees. Not
   "hard to test"; not "I don't want to write the test"; equivalent.
2. The trailing comment should cite the class shorthand from the
   ignore file's header (FPA, SBL, FXS, LZT, TIP, FAB, LCP) so the
   next reviewer can re-verify the call without re-tracing the
   logic.
3. If you're not certain, **leave it as a survivor**. A survivor
   that turns out to be equivalent is a one-line PR; a falsely-
   ignored real mutant is a defect that hides forever.

### Reading the report with `--ignore-file`

```
== Mutation summary ==
Files:     src/threat_intel.c
Operators: rel, arith, bool, const, return
Mutants:   22
Ignored:   4 (documented equivalence-class)
Considered:18
Killed:    18 (100.0% of considered, 81.8% of total)
Survived:  0
```

Two kill rates surface: **of considered** is the new headline
(real-test kill rate); **of total** is the raw number, kept so
historical trends remain comparable to runs that pre-date the
ignore file.

---

## Known equivalence classes

These patterns recur across `src/*.c` and produce mutants that *will*
survive any reasonable test suite. Recognise them in the survivor
list so you don't chase phantom gaps. The harness has no automatic
filter; this list is the manual one.

**Function-parameter array sizes.** C ignores the size declared in a
function-parameter array (`void f(uint8_t mac[6])` is identical to
`void f(uint8_t *mac)`). `const 6 → 7` on such a parameter is a
no-op. Examples in `src/alerts.c`:
`mac_to_str` line 23, `rule_arp_spoof` line 193.

**Stack-buffer sizing literals.** Mutations like `char buf[20]` →
`char buf[19]` or `char buf[21]` rarely change behaviour: snprintf
truncates to fit either size, and the formatted output uses far
fewer bytes than the buffer holds. Example: the `20` on
`char a_bssid[20]` and similar (`rule_evil_twin`, `rule_probe_flood`).

**`memcmp`/`memcpy` length mutations on fixed-size struct fields.**
Reading one byte past a 6-byte MAC reads into the next field of the
struct, whose value is usually a stable byte that doesn't cause a
visible difference. `const 6 → 7` on `memcmp(a->bssid, b->bssid, 6)`
typically survives unless the adjacent field varies between callers.

**Loop bounds reading zero-initialised tail.** `for (i = 0; i < n; i++)`
mutated to `<= n` reads `arr[n]`, which is zero-initialised for
sloth's bounded state arrays. The rules' first check is usually
`if (!arr[i].ip[0]) continue;` (or analogous), so the extra
iteration is silently skipped. Survives every reasonable test.

**Truthy-initialiser perturbation.** `int found = -1; ... if (found <
0)` mutated to `found = -2` is equivalent — the sentinel test still
sees a negative value. Similarly `int all_zero = 1` → `2` (both
truthy). These survive unless a test seeds the exact rare path where
the initial value escapes through unmodified.

**Sub-snprintf field-width mutations on `%xx:` pattern strings.**
The format-string literals like `"%02x:..."` are mutated indirectly
when an integer in surrounding code shifts, but a mutation on the
field width itself is rare to spot and almost never tested.

**Early-return optimisation guards.** Patterns like
`if (!any_sink() || !e) return;` mutate the `||` to `&&` and
survive — because the early-return is a *fast-path optimisation*,
not a correctness gate. The function still produces the right
output downstream; the mutation only causes wasted format work.
No test can or should distinguish this. New shorthand: **OPT**.

For everything outside these classes, treat the survivor as a real
gap and write the test.

---

## Implementation notes

A few things to know before extending the harness:

- **Force-rebuild is mandatory.** `make test` checks mtimes; on APFS
  (and ext4 in some configurations) a mutation can land in the same
  filesystem second as the freshly built test binary, and make will
  skip the rebuild. The harness invokes `make -B test` to force
  unconditional rebuild. Removing this is a footgun — every "mutant"
  would silently run the unmutated binary.

- **Sandbox isolation.** Each run gets a fresh tmpdir under `/tmp`.
  The repo is copied with `shutil.copytree` (preserves mtimes — fine
  because `-B` overrides anyway). Sandbox is deleted on exit unless
  `--keep-sandbox` is set.

- **Restoration is per-file, not per-mutation site.** After each
  mutation, the harness overwrites the file with the saved baseline
  copy — even though only one byte range changed. This is robust
  against partial-mutation bugs at the cost of a few ms of I/O.

- **Equivalent-mutant filtering is not automatic.** Tools like
  pitest/Mull have some heuristic detection; this harness does not.
  The signal-to-noise ratio is currently good enough that human
  review of survivors is the right cost.

- **`#ifdef PLATFORM_LINUX` blocks.** Mutations inside Linux-only
  blocks will always survive on Darwin (the test build doesn't set
  `PLATFORM_LINUX`). Run the harness on Linux for full coverage; on
  Darwin, target files that aren't platform-gated (`src/alerts.c`,
  `src/threat_intel.c`, the snoop/log files).

---

## Targets and priorities

Highest-value files to mutate, in order:

1. `src/alerts.c` — alert rule thresholds. Off-by-one in `>` vs `>=`
   is exactly the kind of bug that would silently mis-classify
   traffic. Test gaps here directly degrade the [[alerts]] guarantee.
2. `src/threat_intel.c` — IOC matcher. Wrong-result mutants are
   security-critical.
3. `src/dga.c`, `src/dns_snoop.c`, etc. — protocol parsers built from
   RFC bytes. Existing test discipline is strong but the kill-rate
   here measures how strong.
4. `src/beacon_detect.c` — periodicity detector. Threshold-sensitive.
5. `src/filter.c` — BPF-style filter logic.

Don't waste cycles mutating:

- `src/views/*.c` — render code. Low semantic value, lots of
  formatting noise; tests use [[platform-vtable|the fake platform]] +
  null TUI but assert mostly on "did it not crash".
- `src/tui.c`, `src/main.c` — orchestration glue.
- `src/platform/*.c` — kernel-facing, not run by tests.

---

## Baseline kill-rates

See [`../../PROGRESS.md`](../../PROGRESS.md) for the running record.
Each baseline run records: target file, mutant count, killed count,
survived count, and the date.

A baseline is only meaningful if `make` and `make test` are clean at
the SHA recorded next to it. Don't trust a kill-rate from a tree
where the suite already had failures.

---

## Related pages

- [[alerts]] — the alert engine, the first mutation target.
- [[architecture]] — code-tree layout for picking the next target.
- [[platform-vtable]] — why some files won't mutate cleanly on macOS.
- [`../dark-factory.md`](../dark-factory.md) §3.3 — why "tests are
  the ground truth" requires this harness.
