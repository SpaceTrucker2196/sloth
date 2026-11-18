---
title: Intelligence is files; compiled snapshots guarantee offline operation
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 3) and C6, §1 item 3, §3 Stages 1 and 2; owner ruling on #184 §5 item 2 of 2026-11-04 (the vendor research workflow moves to sloth-comint)
---

# ADR 0003 — Intelligence is files; compiled snapshots guarantee offline operation

## Context

Knowledge about the world's devices and adversary tooling is scattered
across the tree (#184 §1 item 3). Some of it is hand-kept C in `src/`;
some is committed CSV and Markdown in `web/data/` compiled into
`build/web/` at build time by five generators. Every row of it is the
same for every sloth installation, and none of it is a fact about a frame
or about an operator.

Two constraints bound any answer. The sensor must run on a host with no
network at all (`MISSION.md` §2, #184 §1 item 1), so it cannot fetch what
it needs to identify a device. And `web/data/` is already committed by
the owner's ruling of 2026-10-26 for exactly that reason: a fresh clone
builds the full vendor table without a download.

## Decision

Intelligence becomes **files** (#184 §2, decision 3; C6):

- A **pack** is a versioned directory with a manifest carrying a schema
  version, a pack version, and a per-file SHA-256 with its source. See
  [pack-schema.md](../pack-schema.md) for v1.
- `sloth-comint` publishes packs. Generators turn a pack into C tables
  for `sloth` and for `sloth-dash` — one generator per consumer.
- **Both consuming repositories commit a pinned pack snapshot**, so each
  builds offline, exactly as `web/data/` is committed today.
- The generated C tables are build output and are never committed, the
  way `build/web/` is not committed today.
- **Runtime refresh is optional and opt-in.** Nothing in this decision
  gives the sensor a network dependency. Stage 2 adds no runtime network
  use at all; the cross-installation work is ADR 6 and Stage 6, off by
  default.
- Every finding names the intelligence it used: `intel_pack` (version
  and hash) in JSONL `sensor_health` and on every alert whose rule
  consulted a table, modelled on the way alerts already carry the
  `inventory` content hash (#184 §2 C6, §3 Stage 2).

The proof that a move changed nothing is **byte parity**: the
generators, run on the golden pack, reproduce today's tables
byte-identical — `src/oui.c`'s table, the attacker OUIs, the camera
vendors, and `sloth-dash`'s `web_oui_table.c`, `web_btsig_table.c` and
`web_vendorkb_table.c`. A diff of one row is a stop (#184 §3 Stage 1
item 4, §6).

The owner's ruling of 2026-11-04 places the **vendor research workflow**
— the researched OUI-holder entries and their generator — in
`sloth-comint` (#184 §5 item 2).

`OPEN — needs owner ruling`: **which tables move.** #184 §1 item 3 names
`src/oui.c`, `src/wifi_oui_attacker.c`, `src/camera_vendor.c`,
`src/vendor_watchlist.c`, `src/tool_fingerprint.c`, the #151 known-stack
table, the BLE watchlist categories and the surveillance-vendor
endpoints. Measured against the tree
([architecture-split.md](../architecture-split.md) §3), that list has
three problems the owner needs to rule on:

- Nine further tables in `src/` meet this decision's own definition and
  are in no stage brief — among them `src/dot11_ie.c`'s vendor-IE OUI
  names, `src/captive_portal.c`'s connectivity-check sentinels and
  phishing-kit needles, `src/ble_flood.c`'s advertisement-spam families,
  `src/ip_owner.c`, `src/services.c` and `src/reg_table.c`'s regulatory
  rows.
- Two of the named tables have nothing to move: the BLE watchlist ships
  zero rows, and the #151 known-stack table does not exist (#151 is
  open, waiting on rig captures).
- Two of the named-by-grep tables — `src/dot11_ie.c` and
  `src/wifi_freq.c` — are already compiled into slothweb through
  `WEB_CORE_SRCS`, so ADR 4 has a claim on them as well as this one.

## Consequences

Accepted:

- Offline builds and offline operation are unchanged in both consuming
  repositories, because the snapshot is committed. The guarantee is a
  committed file, not a promise about a server.
- A pack release becomes a third thing to version and pin, with its own
  schema version (ADR 7).
- Every alert that consulted a table gains a field, so
  `tests/replay/golden.jsonl` has to be regenerated in the same commit
  (`agents/AGENTS.md`: additive record fields change the golden).
- The lookup *functions* and their tests do not change — only the row
  data behind them (#184 §3 Stage 2 item 2). That is what keeps the
  parity proof meaningful.
- `sloth` and `sloth-dash` each get a build-time dependency on a
  generator owned by a third repository, vendored as a script or fetched
  at a pinned tag.

Paid for by:

- Three copies of the same rows in flight at once during a transition:
  the pack, `sloth`'s snapshot and `sloth-dash`'s snapshot. The manifest
  hashes are what makes a mismatch visible rather than silent.

## Related pages

- [ADR index](README.md)
- [ADR 0002 — the corpus stays](0002-research-corpus-stays.md) — what is not intelligence in this sense.
- [ADR 0006 — sharing is opt-in](0006-sharing-is-opt-in.md) — how a pack grows from several installations.
- [Pack schema v1](../pack-schema.md)
- [Architecture split inventory](../architecture-split.md)
