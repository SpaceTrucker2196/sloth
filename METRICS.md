# Factory metrics

One row per production order run through the converge loop
(`.claude/commands/converge.md`). Token cost lives in `LEDGER.md`
(script-generated, append-only) — join on the commit sha. Append-only;
never rewrite rows.

| issue | commit | date | converge_iters | tests_at_ship | shipped | notes |
|------:|--------|------|---------------:|--------------:|:-------:|-------|
| 34 | 8714467 | 2026-07-05 | 1 | 3572 | yes | factory standup; docs/tooling only, suite green on first converge |
| 35 | 7d21d42 | 2026-07-14 | 1 | 3672 | yes | allow-list rode #17 SLL2 machinery; suite green on first converge |
| 37 | 08bc4a7 | 2026-07-14 | 1 | 3689 | yes | display-only marker over #35 predicates; prefix election extracted for direct test |
| 38 | 3cdb7cf | 2026-07-14 | 1 | 3710 | yes | add-a-view recipe over existing #31 data layer; green on first converge |
| 39 | 2ca5f4b | 2026-07-14 | 1 | 3778 | yes | docs-drift; extracted view_labels to shared file + capture-based drift guard |
| 40 | 2dbf143 | 2026-07-14 | 1 | 3796 | yes | ICMP-tunnel detector; additive payload_len field + ring-scan rule, green on first converge |
| 45 | a688b25 | 2026-07-20 | 2 | 3813 | yes | factory-infra: risk gate scorer, advisory until owner enables agents/risk_enforce; selftest red once (md-under-agents precedence), green on iter 2 |
