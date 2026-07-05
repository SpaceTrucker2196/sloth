---
description: Run one production order through the factory - issue to green tests to pushed commit
---

Run the dark-factory converge loop on GitHub issue #$ARGUMENTS.

## Loop

1. **Read the order.** `gh issue view $ARGUMENTS` — parse goal,
   acceptance criteria, test requirements, autonomy level, out-of-scope.
   If the issue lacks acceptance criteria, comment asking for them and
   stop.
2. **Plan.** Map the change against AGENTS.md (architecture, invariants,
   recipes). If the plan requires anything under "stops-and-asks" in
   docs/dark-factory.md §4.3, or touches out-of-scope items, stop and
   surface the plan on the issue instead of coding.
3. **Generate.** Implement per the repo recipes (add-a-view,
   add-an-alert, etc.). New behavior gets new assertions; bug fixes get
   the test that would have caught the bug.
4. **Converge.** Run `make test` and `make` (warning-clean). While red:
   fix, re-run, count the iteration. Never weaken an assertion to get
   green — if a test looks wrong, that's a decides-and-flags item.
5. **Self-review.** Diff against AGENTS.md invariants and hard don'ts
   (VIEW_COUNT sync, no circular parser tests, no repo-root files, never
   stage `wifi-sigint/`, `sloth`, or `sloth_test`).
6. **Ship.** Commit with an imperative subject ending in
   `(closes #$ARGUMENTS)`, Co-Authored-By trailer, `git add` specific
   files only, push to `main`. CI + the AI code-review and docs-drift
   workflows act as post-hoc judges.
7. **Instrument.** Append a row to `METRICS.md` (issue, converge
   iterations, tests passing at ship, notes). Then run the ledger per
   AGENTS.md Token/Cost Ledger and commit it as its own
   `chore(ledger):` commit — the ledger row is the token-cost record
   for this order.
8. **Report.** Comment on the issue: what shipped, flagged decisions,
   metrics row.

Escalate (stop, do not push) on: any MISSION.md conflict, any
autonomy-contract §4.3 trigger, or three consecutive converge
iterations with no progress.
