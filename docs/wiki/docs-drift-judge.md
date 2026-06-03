---
name: docs-drift judge
description: LLM-as-judge GitHub Action that audits per-view docs against their source files
type: factory
---

# docs-drift judge

A GitHub Action that asks an LLM judge whether each
`(src/views/X.c, docs/views/X.md)` pair is still in sync. Advisory
only — the action never fails the build.

## Why this exists

[`CLAUDE.md`](../../CLAUDE.md) requires per-view docs to stay
synchronized with the implementation. Until now this was enforced
only by human discipline at PR-review time — easy to miss when a
column rename or a key-binding change lands without touching the
doc. The judge runs out-of-band, flags drift candidates, and lets a
human decide whether to fix or dismiss.

The judge does **not** propose patches. It surfaces evidence and a
verdict; rewriting docs is the operator's job.

## How it runs

- **Weekly cron sweep** (Mondays 09:00 UTC). Audits every
  configured pair. For each pair the judge classifies as `stale`,
  opens a GitHub issue labelled `docs-drift`. Existing open
  `docs-drift` issues are not duplicated — the dedup key is the
  issue title.
- **Pull-request trigger**. Audits only the pairs the PR's diff
  touched. Findings land as a single PR review comment. Reviewers
  see the verdict next to the change.
- **Manual `workflow_dispatch`** for ad-hoc runs.

Both triggers are no-ops on forks / contributors without the
`OPENAI_API_KEY` secret — the workflow logs "skipped" and exits 0.

## What the judge looks for

From the project's perspective the four interesting drift
categories are:

| Category | Example |
|----------|---------|
| `missing-field` | Code emits a new column the doc never mentions |
| `stale-mockup` | The ASCII view mockup in the doc no longer resembles what the view actually renders |
| `key-binding-mismatch` | Doc says `[c]` clears, code says `[x]` clears |
| `wrong-threshold` | Doc hard-codes `0.25` for `BD_MAX_JITTER_RATIO` but the code now uses something else |

The judge can also return `uncertain` when the source file is too
big to fit in context or when a behaviour the doc references isn't
visible in the audited source alone. Uncertain verdicts do **not**
open issues.

## How to dismiss a false positive

The judge will sometimes be wrong — especially on synthesis views
(`alerts.md`, `dashboard.md`) where the doc describes cross-module
behaviour that no single source file exposes.

For a cron-issue:
1. Read the finding. If the doc really is in sync, close the issue
   with a comment like `verified in sync 2026-06-04`.
2. The next weekly sweep will not reopen — but if the judge still
   sees drift in the same pair, it will open a fresh issue. That's
   intentional: the judge is stateless on purpose so its verdict
   stays a function of the current files, not of prior history.

For a PR comment:
- Reply to the comment thread with your reasoning. The judge does
  not auto-update the comment when you push more commits; if you
  fix the drift, the next run on the same PR replaces the comment.

## What the judge will not do

- Open patches. Findings are advisory; a human writes the fix.
- Auto-close prior issues. Stale issues from earlier weeks are not
  managed by the judge.
- Block the build. The workflow always exits 0. CI gating on doc
  drift would compromise the project's hermetic-CI posture for
  offline development.
- Read secrets, `.env`, CI config, or anything outside
  `src/views/`, `src/`-engine pairs listed in `EXTRA_PAIRS`, and
  `docs/views/`.

## Configuration

| File | Purpose |
|------|---------|
| `.github/workflows/docs-drift.yml` | Workflow definition (triggers, env, secrets) |
| `.github/scripts/docs_drift.py`    | Pair discovery, API call, output rendering |
| `.github/scripts/docs_drift_prompt.md` | Source-of-truth prompt (system + user template) |

To add a new pair (e.g. a synthesis doc whose source isn't in
`src/views/`), append one line to the `EXTRA_PAIRS` map at the top
of `docs_drift.py`.

## Costs

About 42 pairs in the catalogue today. At one API call per pair
weekly the cost is comfortably under $1/month. PR runs are bounded
by the changed-file set (typically 1–3 pairs).

## Related pages

- [[architecture]] — how docs fit alongside the per-view source
  files.
- [[mutation-testing]] — the deterministic sibling. Together with
  the docs-drift judge it covers both *does the code do what the
  tests say* and *do the docs say what the code does*.
