# The research corpus

**Issue:** [#73](https://github.com/SpaceTrucker2196/sloth/issues/73) ·
**Built by:** `make research-index` · **Guard:** `tests/test_research_corpus.c`

`agents/AGENTS.md` § Discipline says every detector names its basis. The
citations exist — in issue bodies, wiki pages and the rule table — but
they are prose scattered across three places, so an operator looking at
a CRIT cannot ask *"what backs this"* without a browser and the git log.

This is the machine-readable version of that habit: one curated markdown
document per source, indexed into SQLite FTS5, queryable at runtime.

## Layout

```
research/
  cert/vu-871675.md              CERT/CC advisories
  cve/2023-52160.md              NVD records
  mitre/T1557.md                 ATT&CK techniques
  ieee/802.11-2020-9.6.14.md     clause-annotated summaries
  papers/bl0ck-2302.05899.md     academic sources
  tools/                         tool documentation
```

Each document opens with frontmatter:

```yaml
---
source_url: https://www.kb.cert.org/vuls/id/871675
retrieved: 2026-08-31
topics: [wpa3, dragonblood, pmf]
alert_kinds: [ALERT_TYPE_WPA_DOWNGRADE]
citation: CERT/CC VU#871675
---
```

`source_url` and `retrieved` are **required**. Without them a search hit
says "something backs this" and cannot say what or when, which is not a
citation. `topics`, `alert_kinds` and `citation` are optional.

## Why a YAML subset, not YAML

The parser accepts scalars and single-line bracketed lists, nothing
else. A full YAML parser is a large dependency and a large attack
surface for a format we control at both ends — and the failure mode of a
permissive parser here is specific and bad: a document that silently
indexes under the wrong alert kind, or under none, with nothing
downstream to notice.

So the parser **refuses rather than half-accepts**. A line inside the
frontmatter with no colon is an error, not an ignored line — because a
typo'd `alert_kinds` key means a document that never surfaces for any
detector, and that failure is invisible. Likewise an over-long list is
refused rather than truncated: a silently dropped alert kind is a
document that covers fewer detectors than it claims.

`research_ingest` exits non-zero on any unparseable document, so
`make research-index` fails loudly rather than quietly shipping a corpus
missing the file you just added.

## Sections, not files

Documents are split on `## ` headings, one FTS5 row per section, with
anything before the first heading attributed to the `# ` title. A BM25
hit on a 400-line advisory should point at the paragraph that matched,
not at the file.

## Why the index is committed

`research.db` is in the repository. That is unusual for a generated
artifact and it is deliberate: it is small, it is **byte-for-byte
reproducible** (documents are visited in sorted path order, so repeated
builds are identical — verified, not assumed), and committing it means
the runtime query works from a fresh clone with no build step.

Regenerate with `make research-index` after editing anything under
`research/`. `.gitattributes` marks it binary so git does not attempt
line diffs or CRLF conversion on it.

## The guard, and why it is half-enforced

`tests/test_research_corpus.c` checks two directions. Only one can be
enforced today.

**Enforced — no document cites an alert kind that does not exist.**
Frontmatter names kinds as strings, so a renamed or deleted
`ALERT_TYPE_*` leaves documents pointing at nothing and the runtime
query returns zero hits with no indication why. The match is
whole-token: `ALERT_TYPE_ROGUE` must not pass by being a prefix of
`ALERT_TYPE_ROGUE_RA`.

**Warning-only — every alert kind has at least one document.** This is
the direction #73 ultimately wants, and it needs the content pass first.
At the time of writing that is **13 of 49** kinds cited. Failing on it now would
mean a red suite until the corpus is finished, which turns a guard into
something to be worked around rather than satisfied.

The suite prints the coverage every run, so the gap stays visible rather
than being discovered when somebody goes looking. Flip the check to
failing in the same commit that closes it — the same shape as
[#68's empty signature table](tool-fingerprints.md).

## Adding a document

1. Write `research/<class>/<slug>.md` with the frontmatter above.
2. `make research-index`.
3. `make test` — the guard will reject an alert kind that does not
   exist, and the coverage line will tick up.
4. Commit both the document and the regenerated `research.db`.

## Querying it

`research/query.c` implements the four operations #73 specifies —
`search`, `for_alert`, `cite`, `recent` — as a **library**, not only as
an MCP server. sloth links it directly:

```
sloth --with-research research.db
```

That is a departure from the issue, which has sloth spawn a subprocess
and speak JSON-RPC to ask about its own data file. One implementation,
two front doors: sloth links it, and the MCP server below is a transport
wrapper for the external consumers MCP is actually for — Claude sessions
and scheduled tasks querying a corpus they did not build.

**Additive by construction.** A corpus that is missing, unreadable or
carrying the wrong schema logs one line and leaves sloth running with no
research context:

```
sloth: research corpus unavailable: cannot open /nope/x.db — continuing without it
```

Every entry point tolerates a NULL handle and returns zero results, and
the no-SQLite build stubs the whole layer to no-ops. Nothing in the
capture path may depend on research context.

### Two things the tokenizer forces

**Alert-kind lookup cannot use FTS5 MATCH.** `unicode61` splits on
underscores, so `alert_kinds MATCH 'ALERT_TYPE_EVIL_TWIN'` needs only
the tokens *alert*, *type*, *evil*, *twin* to be present — and a
document naming **only** `ALERT_TYPE_EVIL_TWIN_PROXIMITY` contains every
one. The References block for one alert would cite a document about a
different one, which is worse than citing nothing because it looks
right. `rq_for_alert` and `rq_cite` use delimiter-wrapped `LIKE`
against the stored list instead, which is exact.

Free-text `search` still goes through MATCH — fuzzy is the point there.
Only its *filter* is exact.

**`for_alert` returns documents, not sections.** The index stores a row
per heading, so a document with four matching sections would otherwise
appear four times in a References block and read as four citations.

### Ordering is stable on purpose

`for_alert` and `cite` order by retrieved date and path, never by BM25.
A `--report` regenerated tomorrow must be byte-identical to today's, and
relevance scores shift as the corpus grows.

## The MCP server

`sloth-research-mcp` exposes the same four functions over MCP, for
consumers that are not sloth. It is not part of `all`:

```
make research-mcp
./sloth-research-mcp --db research.db
```

Register it with an MCP client:

```json
{ "mcpServers": {
    "sloth-research": {
      "command": "/path/to/sloth/sloth-research-mcp",
      "args": ["--db", "/path/to/sloth/research.db"]
    } } }
```

Four tools: `research_search`, `research_for_alert`, `research_cite`,
`research_recent`. Their descriptions say explicitly that `for_alert`
wants the enum name and not the display title, because that distinction
already cost three bugs on sloth's own side of the same query layer.

**A missing corpus is not a startup failure.** The server still answers
`initialize` and `tools/list`, and every tool call reports why it has
nothing. A client that cannot start its server sees a connection error,
which says far less than "the corpus is not built".

### Where the code lives, and why it is split

| file | what it owns |
|---|---|
| `research/mcp/json.c` | reading JSON |
| `research/mcp/mcp.c` | one request → one response |
| `research/mcp/main.c` | the pipe, and nothing else |

`mcp_handle()` is a pure function of (corpus, request, clock), so the
protocol has real tests. A dispatcher that only existed inside a read
loop could only be tested by spawning a process and talking to it —
slower, flakier, and it catches less.

### The JSON reader

This tree had no JSON *parser*: `jsonl.c` writes and cannot read. The
two options were vendoring one into a codebase that has carried no
third-party source, or scanning the raw text for `"key":`.

The scan is wrong in a way that matters here. A request whose
*arguments* contain the string `"name"` — a search for `alert "name"
field`, say — would have its tool name read out of the user's own query.
Input arriving over a pipe from something other than us is exactly where
that stops being hypothetical. So: a bounded recursive-descent parser,
no allocation, ~300 lines, with the subset MCP needs.

What it deliberately refuses rather than accepts loosely:

- `\u` escapes above U+00FF — refused, not folded to `?` or split into
  a broken byte pair.
- Raw control characters inside strings. The transport is
  newline-delimited, so a raw newline would let one request masquerade
  as two.
- Leading zeros, `+1`, `nan`, `inf` — all of which `strtod` accepts and
  JSON does not.
- Trailing content after the root value. `{...} {...}` on one line means
  the framing already went wrong upstream.
- Anything past the node, text or depth caps — an error, never a
  truncation.

A half-parsed request answered as if it were whole is the failure mode
worth engineering against.

### Errors: protocol vs tool

| situation | shape |
|---|---|
| unparseable, no method, unknown method, unknown tool | JSON-RPC `error` |
| missing argument, corpus unavailable | `result` with `isError: true` |
| nothing matched | `result` with `isError: false` |

The middle row is the MCP convention and it is the useful one: the model
sees the reason and can correct itself, instead of the transport
failing. The last row matters just as much — reporting "no results" as a
failure would train a client to retry a query that will never succeed.

A message with no `id` is a notification and draws no reply at all.

## `--report` References

With a corpus loaded, the report gains a References section listing the
sources behind each alert that fired:

```markdown
## References

**BTM_ABUSE**

- [IEEE 802.11-2020 §9.6.14 — BSS Transition Management](https://…) — retrieved 2026-08-31
```

The lookup key is `alert_type_name()`, **not** the alert's display
title. Titles are capped at `ALERT_TITLE_LEN` and abbreviated to fit —
`BLOCKACK_ATK` for `ALERT_TYPE_BLOCKACK_ATTACK`, `PEAP_NO_CERT` for
`ALERT_TYPE_PEAP_NO_SERVER_CERT` — so keying on them silently loses
citations for every alert whose title was shortened, and a partly-empty
References block looks exactly like a complete one.

An alert with no documents emits nothing rather than an empty heading.
That is most of them: 13 of 49 kinds are cited.

## What is not here yet

- **Slice 3** — a Research view.
- **Coverage.** 13 of 49 alert kinds have a document. The guard stays
  warning-only until the rest are written.

The view key is **`[f]`**, not the `[q]` the issue proposed: `q` is the
quit key, checked before the view switch as an absolute global. `c` and
`f` are the only free letters.
