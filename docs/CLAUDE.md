# sloth docs wiki — maintenance instructions

`docs/wiki/` is a concept-oriented knowledge base about sloth itself
(architecture, engines, detectors). Based on the LLM-wiki pattern.

## Structure

```
wiki/          -- concept pages, maintained by agents
wiki/index.md  -- table of contents for the entire wiki
wiki/log.md    -- append-only record of all operations
../views/      -- per-view deep dives; immutable source material here
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

## Lint (on request)

Check for contradictions, orphan pages (no inbound links), concepts
mentioned but lacking a page, pages drifted from the code they cite,
and format violations. Report as a numbered list with suggested fixes.
