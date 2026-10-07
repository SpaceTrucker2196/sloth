---
description: Run one production order through the factory - issue to green tests to pushed commit
---

Run the dark-factory converge loop on GitHub issue #$ARGUMENTS.

## Loop

1. **Read the order.** `gh issue view $ARGUMENTS` — parse goal,
   acceptance criteria, test requirements, autonomy level, out-of-scope.
   If the issue lacks acceptance criteria, comment asking for them and
   stop.
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
5. **Self-review.** Diff against agents/AGENTS.md invariants and hard don'ts
   (VIEW_COUNT sync, no circular parser tests, no repo-root files, never
   stage `wifi-sigint/`, `sloth`, or `sloth_test`).
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
