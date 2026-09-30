# sloth docs wiki — maintenance instructions

`docs/wiki/` is a concept-oriented knowledge base about sloth itself
(architecture, engines, detectors) and the **complete information source
for sloth**. Based on the LLM-wiki pattern.

**Source of truth.** `docs/wiki/` is authoritative. The
[GitHub wiki](https://github.com/SpaceTrucker2196/sloth/wiki) is a render
of it, published automatically by `.github/workflows/wiki-sync.yml` on
every push to `main` that touches `docs/wiki/**`. Never edit the GitHub
wiki UI — it is overwritten. Full mechanism: `wiki/wiki-maintenance.md`.

## Structure

```
wiki/                 -- concept pages, maintained by agents
wiki/index.md         -- table of contents for the entire wiki
wiki/wiki-maintenance -- how the wiki stays complete and synced
wiki/log.md           -- append-only record of all operations
../views/             -- per-view deep dives; immutable source material here
```

## Rules

- Treat `docs/views/*.md` as source material — never modify them from
  wiki work (they have their own template, see `docs/views/README.md`).
- Page names lowercase-with-hyphens; link related concepts with
  `[[wiki-links]]`.
- Every page: `**Summary**`, `**Sources**` (the src/docs files it draws
  from), `**Last updated**`, then content, then `## Related pages`.
- After any change: update `wiki/index.md` and append to `wiki/log.md`.
- Claims cite their source file (`src/...` or `docs/views/...`); flag
  contradictions between pages explicitly.
- **Keep it complete and current.** A change to sloth's behaviour updates
  its wiki page in the *same* change: a new/changed flag → `cli-reference.md`;
  a new view → `views-catalog.md`; a new alert → `alerts.md`; a new Wi-Fi
  vulnerability or generation → `wifi-state-of-the-art.md`. This is a
  standing duty on every agent, not a follow-up. See
  `wiki/wiki-maintenance.md` and `agents/AGENTS.md` "Wiki".

## Lint (on request)

Check for contradictions, orphan pages (no inbound links), concepts
mentioned but lacking a page, pages drifted from the code they cite,
and format violations. Report as a numbered list with suggested fixes.
