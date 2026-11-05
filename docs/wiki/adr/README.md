# Architecture decision records

**Summary**: One file per architectural decision, in the order it was
taken, with the context that forced it and the consequences accepted
with it. These seven record the decisions listed at the end of #184 §2
and the owner's rulings on #184 §5 of 2026-11-04. They are a record, not
a proposal: nothing here is a decision an agent made.

**Sources**: issue #184 §2 and §5, the owner's comment on #184 of
2026-11-04, issue #185 (Stage 0).

**Last updated**: 2026-11-05

A record says what was decided and why, and stays as written once the
decision is taken. Superseding one means a new record that names it, not
an edit to the old one.

Where a record cannot be written without inventing a decision #184 does
not contain, the gap is marked `OPEN — needs owner ruling` in place
rather than filled in. Those marks are the point of reading these pages
before Stage 1 starts.

| # | Decision | Status |
|---|---|---|
| [0001](0001-three-repos.md) | Three repositories, contracts first, history preserved | Accepted |
| [0002](0002-research-corpus-stays.md) | The research corpus and the alert assessments stay with the rules | Accepted |
| [0003](0003-intelligence-is-files.md) | Intelligence is files; compiled snapshots guarantee offline operation | Accepted |
| [0004](0004-libsloth-wire.md) | Shared parsers ship as `libsloth-wire`; no cross-repo source includes | Accepted |
| [0005](0005-no-runtime-dependency.md) | No component depends on another at run time | Accepted |
| [0006](0006-sharing-is-opt-in.md) | Cross-installation sharing is opt-in and sanitised | Accepted |
| [0007](0007-versioning.md) | Semantic versions per repository, contract versions per seam | Accepted |

## Related pages

- [Architecture split inventory](../architecture-split.md) — the measured coupling these decisions cut.
- [Pack schema v1](../pack-schema.md) — ADR 3's artifact.
- [Architecture](../architecture.md) — the system map.
