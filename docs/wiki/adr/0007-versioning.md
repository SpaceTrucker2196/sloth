---
title: Semantic versions per repository, contract versions per seam
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 7), C1, C2, C6, C7 and C10; issue #185 items 3 and 4
---

# ADR 0007 — Semantic versions per repository, contract versions per seam

## Context

One tree has one version. `include/sloth.h`'s `SLOTH_VERSION` is the
source of truth for it (`MISSION.md` §3), and slothweb has no version of
its own: the `Makefile` `sed`s `SLOTH_VERSION` out of the header into
`-DSLOTHWEB_BUILD_VERSION` (`Makefile:726`) and the bundle envelope
reports the sloth tree it was built from (#184 §2 C7).

That works because everything is built together. Once the components ship
separately, a reader of any output has to be able to answer "which code,
against which contract?" from the output itself. The record stream has no
version field at all today, and the only versioned seam is
`DB_SCHEMA_VERSION`, which is 11 (`src/db.h:103`).

## Decision

Two kinds of version, named separately (#184 §2, decision 7):

**Semantic versions per repository.** `sloth` keeps `SLOTH_VERSION`.
`sloth-dash` gets `SLOTH_DASH_VERSION` (#184 §2 C7). `sloth-comint` gets
its own.

**Contract versions per seam**, each owned by the repository that
publishes the seam:

| Contract | Version | Owner |
|---|---|---|
| JSONL records | `SLOTH_JSONL_VERSION`, reported in `sensor_health` (#184 C1, #185 item 3) | `sloth` |
| `sloth.db` schema | `DB_SCHEMA_VERSION`, 11 today (#184 C2) | `sloth` |
| pack schema | the manifest's schema version (#184 C6, [pack-schema.md](../pack-schema.md)) | `sloth-comint` |
| the comint API | v1, in the route prefix (#184 C10) | `sloth-comint` |

**Every bundle names all of them.** The bundle envelope gains a
`contract` block reporting the dash, sensor, JSONL, db-schema and pack
versions; `bundle_schema` goes to 1.1.0, additive (#184 §2 C7, §3 Stage 3
item 3). `/api/health` reports the three component versions (#184 §3
Stage 3, reviewer criteria), and `sloth-comintd`'s `/v1/health` names the
pack version and its hash (#184 §3 Stage 1 item 5).

Pins are files, not conventions: `sloth-dash` names the contract it
builds against in `contract.lock` and the pack in `pack.lock` (#184 §3
Stage 3 item 2).

The existing migration discipline is unchanged and is the model for the
new contracts: every schema bump ships its migration in the same commit,
additive, never rewriting a recorded value in place (owner ruling
2026-10-21, `agents/AGENTS.md`). JSONL stays additive — add fields, do
not rename them (`MISSION.md` §4 item 3).

## Consequences

Accepted:

- Adding `SLOTH_JSONL_VERSION` to `sensor_health` is an additive record
  field, so `tests/replay/golden.jsonl` is regenerated with `make
  replay-golden` in the same commit (`agents/AGENTS.md`, 7052c71).
- A non-additive change to any of the four contracts becomes an
  external-contract break — a stop-and-ask under
  `agents/dark-factory.md` §4.3 — rather than a decision inside a
  repository.
- Five versions appear in one envelope, which is five chances to read
  one for another. Naming each in the `contract` block rather than
  flattening them into a single string is what keeps them separable.
- `bundle_schema` 1.1.0 is additive, so a consumer pinned to the 1.0
  series keeps working.

Paid for by:

- Four version bumps to get right per release instead of one, and two
  lock files to move.

`OPEN — needs owner ruling`: nothing in this record. #184 names the four
contracts, their owners and the reporting requirement. The starting value
of `SLOTH_JSONL_VERSION`, the `bundle_schema` arithmetic and
`sloth-comint`'s version macro name are code-level choices for the slice
that writes them (`agents/dark-factory.md` §4.1), not owner rulings.

## Related pages

- [ADR index](README.md)
- [ADR 0004 — libsloth-wire](0004-libsloth-wire.md) — the pinned artifact.
- [Pack schema v1](../pack-schema.md)
- [JSONL schema](../jsonl-schema.md)
- [SQLite schema](../sqlite-schema.md)
- [Release checklist](../release-checklist.md)
