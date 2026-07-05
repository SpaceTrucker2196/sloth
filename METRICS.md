# Factory metrics

One row per production order run through the converge loop
(`.claude/commands/converge.md`). Token cost lives in `LEDGER.md`
(script-generated, append-only) — join on the commit sha. Append-only;
never rewrite rows.

| issue | commit | date | converge_iters | tests_at_ship | shipped | notes |
|------:|--------|------|---------------:|--------------:|:-------:|-------|
| 34 | 8714467 | 2026-07-05 | 1 | 3572 | yes | factory standup; docs/tooling only, suite green on first converge |
