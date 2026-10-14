---
description: Run one production order through the factory - issue to green tests to pushed commit
---

Run the dark-factory converge loop on GitHub issue #$ARGUMENTS.

## Loop

1. **Read the order.** `gh issue view $ARGUMENTS` — parse goal,
   acceptance criteria, test requirements, autonomy level, out-of-scope.
   If the issue lacks acceptance criteria, comment asking for them and
   stop.

   **Then re-verify the body against the tree.** Issue bodies here are
   written once and age for months while the code moves under them, so
   an unchecked body is a description of a tree that no longer exists.
   Re-run every grep the body quotes and open every `file:line` it
   cites, *before* planning. On 2026-10-13 a triage pass found #96
   asserting `SECURITY.md` still said 1.4.x when it had been reconciled
   to 1.8.4, and #101 quoting `grep -cE 'country_ie|…' src/` → 0 when
   `src/reg_ie.c` already existed. Either one would have produced a
   slice that re-did landed work. Record the contradictions in the
   step-9 report so the next reader does not re-derive them.

   **Ask the second question too.** "What does this issue still need?"
   and "what is wrong with the code this issue touches?" have different
   answers, and the second one pays better. #77 was labelled
   `needs-pcap-fixture` and read as hardware-blocked; reading the code
   it pointed at instead found `wps_attr_str()` clamping length but not
   content, so four attacker-controlled WPS strings reached the
   terminal verbatim through `printf` in non-ncurses builds (CWE-150).
   A planning pass over the issue text alone would have marked it
   blocked and moved on. Read the code the issue touches, not only the
   work the issue asked for.

   **Ask the third question when the bug has a sibling: does the shared
   resource have a policy?** A fix that bounds one caller's demand on a
   shared resource leaves every other caller free to do the same thing.
   Three defects shipped separately on 2026-10-13/14 before anyone
   looked at the resource they shared: #105 keyed an alert on an
   endpoint address the *remote side* chooses, #107 left a counter
   unbounded in time, and #96's beaconing rule re-fired 128 tracks
   every tick. All three filled the 128-slot alert ring, and because
   eviction took the globally oldest entry, each starved every other
   rule. Each was fixed inside the offending rule, and each fix was
   correct — which is exactly why there kept being a next one.
   A `grep` for a per-type budget across ~200 `ALERT_TYPE_*` references
   found none: the engine had no fairness policy at all, and the slots
   are shared by all 75 detectors.

   The trigger to look is **the second instance, not the third**: two
   bugs with the same shape against one shared resource means the
   resource is missing a rule, and the cheap check is to grep for
   whether any policy exists before writing the third local fix. Fixing
   the class retires the instances; fixing instances does not retire
   the class.

   When you do add such a policy, say what it does **not** guarantee.
   Per-type fairness here is work-conserving, not a quota — a rule may
   still hold every slot unopposed — so the guarantee is only that no
   rule can hold the resource against another indefinitely, never that
   any rule has a reserved share. The stronger claim is the one a
   reader will assume, and it would be false.
2. **Plan.** Map the change against agents/AGENTS.md (architecture, invariants,
   recipes). If the plan requires anything under "stops-and-asks" in
   agents/dark-factory.md §4.3, or touches out-of-scope items, stop and
   surface the plan on the issue instead of coding.
3. **Generate.** Implement per the repo recipes (add-a-view,
   add-an-alert, etc.). New behavior gets new assertions; bug fixes get
   the test that would have caught the bug.
4. **Converge.** Run `make test` and `make` (warning-clean). While red:
   fix, re-run, count the iteration. Never weaken an assertion to get
   green — if a test looks wrong, that's a decides-and-flags item.

   **`make clean` between build configs.** The six configs share one
   object directory, so objects built under one set of `WITH_*` flags
   are silently reused by the next config and the link fails on symbols
   that are present in the source. Twice on 2026-10-13 that cost a
   debugging detour over a build that was never broken — once for
   `capture_test_savefile`, once for `capture_open`/`capture_run`. A
   missing symbol you can see in the file is a stale object, not a bug:
   `make clean` first, then believe the error.
5. **Self-review.** Diff against agents/AGENTS.md invariants and hard don'ts
   (VIEW_COUNT sync, no circular parser tests, no repo-root files, never
   stage `wifi-sigint/`, `sloth`, or `sloth_test`).

   **Mutation-prove every assertion of absence.** A test that asserts
   something does *not* happen passes just as happily when it exercises
   nothing at all, so it is worthless until you have seen it fail:
   revert the fix (or mutate the guard), run the suite, confirm the new
   assertion goes red, restore. Do this before writing the comment that
   claims coverage. On 2026-10-13 three such tests were green for the
   wrong reason and each was caught only by mutating — the `[m]`
   ordering test (`probe_stop()` never writes `probe_iface`, so the
   assertion held either way), the `rt_len >= len` guard (`>=`→`>`
   leaves the suite green, because `dot11_len < 10` already catches
   equality — that case cannot be isolated and the comment now says
   so), and a duplicate-MAC invariant whose first two scenarios passed
   under the pre-fix code because the eviction scan compares with `<`
   and so needs *staggered* survivor timestamps to expose the bug.
   If the mutation does not reproduce, the honest move is to write down
   what the test does not cover, not to widen the claim.

   **Undo the mutation with the inverse edit, never `git checkout
   <file>`.** That command restores the file from HEAD, so it discards
   every *other* uncommitted change in it, not just the mutation — on
   2026-10-13 it silently threw away a whole new test plus a scanner fix
   that had taken a dozen minutes to get right, and the loss was visible
   only because the next `grep` came back empty. Mutate with `sed`, undo
   with the opposite `sed`, or `cp` the file aside first and copy it
   back. Choose a mutation that removes the call site or flips the
   operator you are testing: a tweak the test inputs cannot distinguish
   proves nothing, and the first mutation tried that day was exactly
   that — it left the suite green while changing real behaviour.

   **One mutation per claim, and the mutation must model the claim.** A
   mutation that merely breaks the code proves only that the suite
   notices breakage. On 2026-10-14 the engine-fairness work shipped
   three tests making two different claims — *a flood must not starve
   another rule* and *one rule may still hold every slot* — and they
   needed two different mutations. Reverting to globally-oldest
   eviction reddened the two starvation tests but left the third green,
   correctly: that test pins the **absence** of a per-type cap, which
   globally-oldest also has. The first attempt at a cap mutation
   clamped the internal `most` variable, which did not model a quota at
   all — it broke victim selection, failed the starvation tests for the
   wrong reason, and left the one test it was aimed at green. Only a
   real budget at the allocation site reddened it. If one mutation
   reddens every test in a group, suspect the mutation rather than
   celebrating the coverage; tests asserting different properties
   should be separable.

   **When a fix reddens an existing test, decide which one is wrong
   before touching either.** The default assumption should be that the
   fix is wrong, but not the conclusion. Same day: per-rule eviction
   fairness reddened two pcap-cooldown tests whose harness flooded
   `PORT_SCAN` until a lone `THREAT_IP` entry was evicted. That harness
   had encoded the *old* policy as its premise, and fairness makes a
   rule holding one slot the last thing evicted — by design, and the
   whole point of the change. The test's premise had expired, so the
   harness moved to another route to the same state (let the incident
   expire, since `fire()` treats a key as seen only while its entry is
   live) and the policy did not bend. Write down which way you decided
   and why, in the test's own comment: the next reader otherwise cannot
   tell a premise that expired from a regression that was explained
   away. The tell that it was really the premise: the replacement route
   was also the more faithful one — expiry is what recycled engine
   slots in the field, 300s at a time, while a `PORT_SCAN` flood never
   did.
6. **Risk gate.** Run `sh agents/risk_score.sh --selftest && sh
   agents/risk_score.sh` (scores the working tree against
   `origin/main`; weights + threshold in the script header, docs in
   FACTORY.md §10.3). Record the `RISK <n>/<threshold>` line in the
   step-9 report comment. Advisory mode (default): proceed, flag the
   score (§4.2). Enforcing mode (`agents/risk_enforce` present)
   at/above threshold: stop — do not ship — and surface the breakdown
   on the issue for human review.
7. **Ship.** Commit with an imperative subject ending in
   `(closes #$ARGUMENTS)`, Co-Authored-By trailer, `git add` specific
   files only, push to `main`. CI + the AI code-review and docs-drift
   workflows act as post-hoc judges.

   **Confirm CI by commit SHA, never by workflow name.** `gh run list
   --workflow CI` returns the newest run of that workflow, which is
   routinely an older commit's, and the repo has several workflows whose
   run IDs are easy to conflate. On 2026-10-13 that produced three
   separate public misreports of CI status in one session — a stale run
   read as this commit's, a Code Review run read as CI, and a watcher
   that exited without saying anything. Query the pushed SHA:
   `gh run list --commit "$(git rev-parse HEAD)" --json
   workflowName,conclusion,databaseId`, and report per job. "CI is
   green" with no SHA behind it is not a result.

   Two traps in that command, both hit the same day it was written here:

   - **`--commit` filters a page, it does not query.** `gh` fetches its
     default ~20 most recent runs and filters locally, so the same
     command that printed a green result an hour ago returns `[]` once
     enough runs have happened since. An empty result means "not in the
     window", NOT "never ran" — pass `--limit 300` and filter, or use
     `gh api .../actions/runs?head_sha=<sha>`, before concluding
     anything from silence.
   - **Actions runs on the pushed HEAD, not on each commit.** Two
     commits in one push give one run, against the second. So an
     intermediate commit legitimately has no run of its own and is
     covered by the next one. Check per PUSH, not per commit, or the
     tally looks short for no reason.

   **Omitting CI from the report is not neutral — it reads as green.**
   On 2026-10-14 a slice was pushed, the step-9 comment was posted with
   the local gates listed and no mention of CI, and CI then failed: a
   `make fuzz` link error, in a target no local gate ran. Nothing in the
   report was false, and that is the problem — a gate list with CI
   missing from it looks complete, so the red push read as a finished
   slice until the next check. Either wait for the verdict and name it
   with its SHA, or say in the report that CI is still running and post
   the result when it lands. The step is "confirm CI by SHA", and
   leaving the line out does not satisfy it.
8. **Instrument.** Append a row to `METRICS.md` (issue, converge
   iterations, tests passing at ship, notes). **Get the assertion count
   by building, not from memory** — run `make test` on the parent commit
   and on the shipped tree, and report both. A recalled "was N" figure
   is worth nothing: on 2026-10-05 a slice reported `+35 assertions` from
   a parent of 12741 when the parent was 12776, so its real delta was
   about zero, and once that number was wrong every other figure in the
   report became unverifiable. Two other sources had the parent right,
   which is the only reason it was caught. Then run the ledger per
   agents/AGENTS.md Token/Cost Ledger and commit it as its own
   `chore(ledger):` commit — the ledger row is the token-cost record
   for this order.
9. **Report.** Comment on the issue: what shipped, flagged decisions,
   risk score, metrics row.

Escalate (stop, do not push) on: any MISSION.md conflict, any
autonomy-contract §4.3 trigger, or three consecutive converge
iterations with no progress.
