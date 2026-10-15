---
name: wiki-maintenance
description: How the sloth wiki stays complete and in sync — source of truth, the GitHub mirror, and the standing duty on every agent that changes sloth
type: reference
---

# Wiki maintenance

**Summary**: `docs/wiki/` is the single source of truth and the complete
information source for sloth. The [GitHub wiki](https://github.com/SpaceTrucker2196/sloth/wiki)
is a **render** of it, published automatically. This page states how the
sync works and the standing rule: an agent that changes sloth's behaviour
updates the wiki in the same change.

**Sources**: `.github/scripts/wiki_sync.sh`,
`.github/workflows/wiki-sync.yml`, `docs/CLAUDE.md`, `agents/AGENTS.md`.

**Last updated**: 2026-10-15.

---

## Source of truth

Edit `docs/wiki/*.md`. Never edit pages in the GitHub wiki UI — they are
overwritten on the next push. The GitHub wiki carries a `_Footer.md`
saying exactly this.

## How the sync works

`.github/scripts/wiki_sync.sh` renders `docs/wiki/` into a checkout of
`sloth.wiki.git`. It is mechanical and idempotent:

- `index.md` → `Home.md` (GitHub's landing page name).
- YAML front matter is stripped.
- `](../views/…)`, `](../personas/…)`, `](../../…)` become absolute
  `blob/main` URLs (the wiki has no repo tree beside it).
- `](sibling.md)` → `](sibling)` (wiki page links).
- `[[wiki-links]]` are left as-is — GitHub's wiki resolves them.
- `_Sidebar.md` is generated from `index.md`'s headings and `[[links]]`.
- A page deleted from `docs/wiki/` is deleted from the wiki.

`.github/workflows/wiki-sync.yml` runs it on every push to `main` that
touches `docs/wiki/**`. So the wiki can never drift from the repo by more
than one push. To publish by hand:

```sh
git clone https://github.com/SpaceTrucker2196/sloth.wiki.git /tmp/wiki
sh .github/scripts/wiki_sync.sh docs/wiki /tmp/wiki          # push
sh .github/scripts/wiki_sync.sh docs/wiki /tmp/wiki --no-push  # dry preview
```

## The standing duty (do agents keep the wiki updated? — yes)

This is the answer to "do agents keep the wiki update": it is a rule, not
a hope. From `agents/AGENTS.md` and `docs/CLAUDE.md`:

- **A behaviour change updates its page in the same change.** New view →
  [[views-catalog]] + a per-view doc. New alert → [[alerts]] and a
  `research/` citation ([[research-corpus]], enforced by
  `tests/test_research_corpus.c`). New or changed flag → [[cli-reference]].
  New WiFi vuln or generation → [[wifi-state-of-the-art]].
- **Part of it is machine-enforced, in `make test`.**
  `tests/test_docs_consistency.c` fails on a dead `[[wikilink]]`, a
  broken relative link, a page unreachable from `index.md`, a stale view
  or alert-rule count on any page, a missing alert rule-table row, and —
  since #103 — a long option parsed in `src/main.c` that
  [[cli-reference]] does not backtick, an option the page documents that
  `src/main.c` no longer parses, a view-selection key the page does not
  list, and a `sloth_views.def`/label key-set disagreement. Since #117
  the view and rule counts on the pages are generated: `make
  docs-counts` rewrites every `<!-- count:views -->N<!-- /count -->` /
  `<!-- count:rules -->` marker, and a stale one fails the suite with
  that command in its message.
  `tests/test_research_corpus.c` fails on an uncited detector. What is
  still rule-only: whether a *changed* behaviour's prose was updated, and
  page format.
- **Two further layers.** The risk gate scores any touch of `agents/` at
  +40 (`agents/FACTORY.md` §10.3), and the [[docs-drift-judge]] GitHub
  Action audits per-view docs against their source files (advisory — it
  never fails the build). The wiki-sync workflow keeps the published copy
  honest.
- **Page format** (`docs/CLAUDE.md`): every page carries `**Summary**`,
  `**Sources**`, `**Last updated**`, content, then `## Related pages`;
  after any change, update `index.md` and append to `log.md`.

## Lint (on request)

Check for: contradictions between pages, orphan pages (no inbound
`[[link]]`), concepts mentioned but lacking a page, pages drifted from
the code they cite, and format violations. Report as a numbered list with
fixes. See `docs/CLAUDE.md`.

## Related pages

- [[what-sloth-does]] — the top of the reference this wiki completes.
- [[docs-drift-judge]] — the per-view doc auditor.
- [[research-corpus]] — the enforced citation half of the same discipline.
