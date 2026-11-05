---
title: No component depends on another at run time
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 5) and C8, §4 (the independence table), §3 Stage 5
---

# ADR 0005 — No component depends on another at run time

## Context

Today one `install` target refuses to run without `./slothweb`
(`Makefile:1489`), and the tree ships systemd units that assume they
were installed together. Split into three repositories and installed as
three packages, that assumption becomes an outage: a sensor that will
not start because a dashboard is absent is a worse sensor than today's.

The sensor's case is the strongest. `MISSION.md` §2 and #184 §1 item 1
both require it to run on one host with no network, no browser and no
other service. A run-time dependency on a dashboard or an intelligence
daemon would contradict the charter, not just the architecture.

## Decision

No component requires another at run time (#184 §2, decision 5):

- **The sensor never depends on `sloth-dash` or `sloth-comint` at run
  time.**
- **`sloth-dash` runs without a sensor and without `sloth-comint`.**
- **`sloth-comintd` runs alone.**

What each does without the others (#184 §4):

| Component | Alone it |
|---|---|
| `sloth` | is exactly today's CLI and TUI sensor; tables come from the pinned pack snapshot; no network use |
| `sloth-dash` | serves the page, browses a `sloth.db` copy, shows `not_observing` and `intel_source: snapshot` |
| `sloth-comintd` | serves packs and lookups to any client; holds `comint.db` |

Packaging carries the decision (#184 §2 C8, §3 Stage 5):

- three packages, three units: `sloth-sensor.service`,
  `sloth-dash.service`, `sloth-comintd.service`;
- `After=` and `Wants=` only — **never `Requires=`**;
- one `sloth` user and group, one sysusers file owned by `sloth` and
  depended on by the other two, `/run/sloth` from `RuntimeDirectory=`;
- the `install` target's `./slothweb` requirement goes away (#184 §3
  Stage 4).

Each degraded mode gets a test, and the five together are the content of
`tests/deploy/test_three_repos.sh`: sensor alone; dash alone; comint
alone; dash without comint (`intel_source: snapshot`); dash with comint
(`intel_source: comintd`) (#184 §3 Stage 5 item 2).

`OPEN — needs owner ruling`: **where `sloth-ble-scan` goes.**
`packaging/systemd/` holds three units today —
`sloth-sensor.service`, `slothweb.service` and
`sloth-ble-scan.service` — plus `sloth-sensor.service.d/` and
`sloth.sysusers.conf`. #184 C8 counts two units and assigns
`sloth-ble-scan` to no repository. It is a sensor-side helper by
function, which would put it in `sloth`, but that is an inference and
not something #184 says. See
[architecture-split.md](../architecture-split.md) §5 item 4.

## Consequences

Accepted:

- `sloth-dash` has to have a meaningful empty state for every surface
  that reads live data, and say which source it used rather than
  guessing. `intel_source` and `not_observing` are that, reported through
  `/api/health`.
- Degradation becomes a tested property with five named modes, not an
  assumption. The script runs on a clean Debian 13 image first and on the
  appliance second, one deploy at a time (`agents/AGENTS.md`).
- `Wants=` without `Requires=` means a missing peer is a quiet
  degradation rather than a failed boot — which is the intent, and also
  means an operator can have a half-installed system that looks healthy.
  Naming the source in `/api/health` is what makes that visible.
- Existing hosts need a migration note: paths, the `slothweb` symlink,
  the unit rename (#184 §3 Stage 5 item 4).

## Related pages

- [ADR index](README.md)
- [ADR 0003 — intelligence is files](0003-intelligence-is-files.md) — the snapshot that makes the sensor's independence real.
- [ADR 0006 — sharing is opt-in](0006-sharing-is-opt-in.md)
- [Deployment](../deployment.md)
- [Architecture split inventory](../architecture-split.md)
