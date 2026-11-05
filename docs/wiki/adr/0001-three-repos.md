---
title: Three repositories, contracts first, history preserved
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 1), §1 and §3; owner ruling on #184 §5 of 2026-11-04 (names, visibility, artifact home)
---

# ADR 0001 — Three repositories, contracts first, history preserved

## Context

Sloth is one tree with three concerns in it, and the system map in
[architecture.md](../architecture.md) already draws them as three boxes
(#184 §1):

1. **Sensing and judgement** — capture, decode once, state, rules, the
   incident engine, JSONL, `sloth.db`, evidence pcaps, the TUI and the
   CLI. This must run on one host with no network, no browser and no
   other service, and it must never put a frame on the monitored segment
   (`MISSION.md` §2).
2. **Presentation and the operator's workflow** — slothweb: the stream
   client, the read-only `sloth.db` reader, rollups and baselines,
   anomalies, BLE, triage, FRRS, TACDB, `slothweb.db`, the HTTP API and
   the page. It is useful on a host with no sensor, reading a copied
   `sloth.db`, and it is the part that will change fastest.
3. **Knowledge about the world's devices and adversary tooling** —
   today scattered across `src/` tables and `web/data/`. Every one of
   these is a fact about the world, not about a frame or about an
   operator, and every one is the same for every sloth installation.

The three change at different rates, are useful to different people on
different hosts, and are tested by one suite and one CI matrix that has
to be green for all of it before any of it ships.

## Decision

Split the tree into three repositories (#184 §2, decision 1):

| Repository | Owns | Knows about |
|---|---|---|
| `sloth` | sensor, rules, engine, TUI, CLI, JSONL, `sloth.db`, research corpus, alert assessments, the wire parsers | frames and rules |
| `sloth-dash` | slothweb, `slothweb.db`, triage, FRRS, TACDB, the page, the bundle | the operator |
| `sloth-comint` | intelligence packs, their sources and generators, `comint.db`, `sloth-comintd`, cross-installation sharing | the world's devices and adversary tooling |

Three properties of the split are part of the decision:

- **Contracts first.** Every seam is written down and made buildable
  before anything is cut. That is Stage 0 (#185), and nothing moves
  until it lands.
- **History is preserved.** Each carve-out is a `git filter-repo` with a
  path list, so blame survives, verified by `git log --follow` on three
  moved files in each new repository before its first push (#184 §3,
  §6).
- **Nothing regresses.** Every view, rule, route, flag, record and test
  that exists today keeps working, and all three install on one host
  (#184 preamble).

The owner's rulings of 2026-11-04 fix the remaining names and homes:

- The repository names are `sloth`, `sloth-dash` and `sloth-comint` as
  proposed (#184 §5 item 1). The binary name `slothweb` stays as a
  compatibility symlink for one release.
- Both new repositories are **private** (#184 §5 item 3). They exist as
  of 2026-11-04 with a README only; the history moves in Stages 1 and 3.
- The contract artifact lives on **`sloth`'s GitHub releases** (#184 §5
  item 4).

`OPEN — needs owner ruling`: the **licence** for the two new
repositories. #184 §5 item 3 asked about licence and visibility
together; the ruling of 2026-11-04 answered visibility (private) and did
not name a licence.

## Consequences

Accepted:

- Three CI matrices instead of one. Each repository tests only itself;
  the integration job that installs all three runs on a schedule and on
  release tags, not on every push (#184 §2 C9, §6).
- Every seam becomes a versioned contract that can be broken by a
  release rather than caught by a shared test run. ADR 7 is the answer
  to that, and C1–C10 are the list of seams.
- A change that spans two repositories becomes two changes in a fixed
  order, with a pinned version between them.
- Parallelism comes from the repositories, not from agent fan-out: once
  Stage 1 lands, Stage 2 (in `sloth`) and Stage 3 (in `sloth-dash`) run
  side by side with separate builder and reviewer pairs (#184 §3).

Paid for by:

- The measured coupling in
  [architecture-split.md](../architecture-split.md), which is the work
  Stages 1 to 4 consist of.
- A migration for existing hosts: paths, the `slothweb` symlink, the
  unit rename (#184 §3, Stage 5).

## Related pages

- [ADR index](README.md)
- [ADR 0004 — libsloth-wire](0004-libsloth-wire.md) — the parser seam this split creates.
- [ADR 0005 — no runtime dependency](0005-no-runtime-dependency.md) — what each component must still do alone.
- [Architecture split inventory](../architecture-split.md)
