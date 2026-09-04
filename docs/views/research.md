# `[f]` Research

**Issue:** [#73](https://github.com/SpaceTrucker2196/sloth/issues/73) ·
**Code:** [`src/views/research.c`](../../src/views/research.c),
[`research/coverage.c`](../../research/coverage.c) ·
**See also:** [`alerts.md`](alerts.md),
[the corpus notes](../wiki/research-corpus.md)

## Protocol

None. This view reads no packets.

It is the one view whose subject is **sloth itself**: for each alert
kind that has fired, what does the research corpus say backs it? The
`[v]` Alerts view tells you what happened; this one tells you why you
should believe it.

## What sloth captures

Nothing new. `research/coverage.c` runs after `alerts_update()` on each
poll, walks the alert table, and asks the corpus — through the same
`rq_for_alert()` the `--report` References block uses — what documents
name each alert kind.

The corpus itself is a committed FTS5 index built from `research/**.md`
by `make research-index`. It is loaded with `--with-research PATH`;
without it, this view still lists every fired kind, with no sources.

That distinction is deliberate. *"Nothing is cited"* and *"no corpus is
loaded"* look identical if the table is simply empty, so the header says
which it is.

## Mockup

```
 Research corpus: loaded  cited 3/5 fired alert kinds
 SEV   ALERT                 HITS  DOCS  KIND
 ----  --------------------  ----  ----  --------------------
>CRIT  FRAG_AMSDU               1     1  ALERT_TYPE_FRAG_AMSDU
 CRIT  EVIL_TWIN                2     1  ALERT_TYPE_EVIL_TWIN
 CRIT  BLOCKACK_ATK             1     1  ALERT_TYPE_BLOCKACK_ATTACK
 WARN  PORT_SCAN                7     -  ALERT_TYPE_PORT_SCAN
 WARN  RF_DEGRADED              3     -  ALERT_TYPE_RF_DEGRADED

 ── sources for ALERT_TYPE_FRAG_AMSDU ──
  FragAttacks — Vanhoef, USENIX Security 2021
    https://papers.mathyvanhoef.com/usenix2021.pdf  (retrieved 2026-09-03)
```

`↑`/`↓` move the selection; the pane below shows that kind's sources.

Note the `KIND` column shows the **enum name**, not the display title.
`BLOCKACK_ATK` is a column-width abbreviation of
`ALERT_TYPE_BLOCKACK_ATTACK`, and the enum name is what you would pass
to `research_for_alert` over the MCP server or grep for in
`research/**.md`.

## Normal

Most kinds show `-`. At the time of writing the corpus covers 18 of 54
alert kinds, so an ordinary session shows more uncited rows than cited
ones.

That is not a defect in the view. It is the view working.

## Suspicious

There is no suspicious state here — the view reports on sloth, not on
the network. What it surfaces instead is a **question about a finding**:

A `CRIT` with `-` in the DOCS column is a rule firing on a behavioural
threshold with nothing cited behind it. `agents/AGENTS.md` requires
every detector to name what it detects *from* — the CVE, the CERT
advisory, the MITRE technique, the IEEE clause, the paper — because a
threshold with no cited basis is indistinguishable from a guess, and the
operator deciding whether to act needs to know which it is.

So an uncited `CRIT` is not necessarily wrong. It is a finding you
should weigh differently from one with a paper behind it, and this view
is where you find out which you are looking at.

The uncited rows are also the work list. `docs/wiki/research-corpus.md`
explains how to add a document.

## Ordering

Worst severity first, then occurrence count, then kind name — stable
across polls, because the selection is an index and two equal rows
swapping would move the cursor onto a different alert without the
operator touching anything.

One row per *kind*, not per alert: two `PORT_SCAN` alerts against
different hosts cite the same document, and listing it twice would make
the corpus look better covered than it is.

## See also

- [`alerts.md`](alerts.md) — the alerts this view explains
- [the corpus notes](../wiki/research-corpus.md) — schema, ingest, the
  MCP server, and how to add a document
- `sloth --report` carries the same citations as a References section
