---
title: The research corpus and the alert assessments stay with the rules
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 2) and §1; owner ruling on #184 §5 item 2 of 2026-11-04 ("ADR 2 confirmed")
---

# ADR 0002 — The research corpus and the alert assessments stay with the rules

## Context

ADR 3 moves intelligence — facts about the world's devices and adversary
tooling — into packs owned by `sloth-comint`. `research/` and
`docs/wiki/alert-assessments/` look like intelligence from a distance:
they are cited documents about the outside world, they are the same for
every installation, and a generator already compiles them into slothweb's
build (`web/tools/alertkb.c` and `web/tools/alertasm.c`).

They are not intelligence in that sense (#184 §1). They are **citations
for the rules**:

- `tests/test_research_corpus.c` holds every citable `ALERT_TYPE_*` to a
  document in `research/**.md` that names it. Adding a detector means
  adding its source in the same change, or the suite goes red and names
  the kind (`agents/AGENTS.md`, "Detectors cite their sources").
- The assessments name `rule_file` line numbers. Any edit to
  `src/alerts/rules_*.c` shifts them, and each has to be repointed at
  its rule function's definition line before pushing
  (`agents/AGENTS.md`, 8caf61e).

Both of those are couplings to the rules, in the same tree, enforced by
the same test run.

## Decision

`research/`, `research.db` and `docs/wiki/alert-assessments/` stay in
`sloth`, with the rules (#184 §2, decision 2). They move with the rules
or the discipline breaks.

The vendor research workflow does **not** stay: the vendor entries in
`web/data/vendors/` and their generator move to `sloth-comint` (#184 §5
item 2, confirmed by the owner on 2026-11-04). The two are different
things — a vendor entry is a fact about a registrant, an assessment is an
argument about one of sloth's own rules.

`sloth` ships the corpus and the assessments outward as the **alert
knowledge bundle** inside the contract artifact (#184 §2 C4); the
generator that reads them moves to `sloth-dash` and reads the bundle
instead of the tree.

## Consequences

Accepted:

- The research-corpus test and the assessment line-number discipline
  stay exactly as they are. Nothing in `agents/AGENTS.md` about citing
  sources changes.
- `sloth` keeps a documentation-shaped dependency in its release
  artifact: the bundle is part of the contract, so a corpus edit is a
  contract change and `sloth-dash` sees it at a pinned version rather
  than on the next build.
- Two generators read the bundle, not one — `alertkb.c` takes
  `include/sloth_alerts.def`, `docs/views/alerts.md`,
  `docs/wiki/alerts.md`, `docs/wiki/alert-remediation.md` and
  `research/`; `alertasm.c` takes the `.def` and
  `docs/wiki/alert-assessments/`. #184 §2 C4 describes them as one; see
  [architecture-split.md](../architecture-split.md) §5.
- The split runs down the middle of `web/data/`: the IEEE and SIG
  registries and the vendor entries go to `sloth-comint`, while the
  corpus and assessments they sit beside in the same build stay in
  `sloth`.

Paid for by:

- The corpus is large and changes often, and every change is now a
  contract bump for `sloth-dash` to pick up. ADR 7's versions make that
  visible; they do not make it free.

## Related pages

- [ADR index](README.md)
- [ADR 0003 — intelligence is files](0003-intelligence-is-files.md) — what does move.
- [Research corpus](../research-corpus.md)
- [Alert assessments](../alert-assessments/README.md)
- [Architecture split inventory](../architecture-split.md)
