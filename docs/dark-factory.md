# The Dark Factory Repo

A pattern for running a software project at **Level 5 agent autonomy** —
the code is written, tested, and reviewed by agents; the human is the
customer and the final acceptance reviewer, not the engineer.

This document is two things at once:

1. A teaching artifact for anyone trying to understand or adopt the
   dark-factory pattern.
2. The operating contract for this repo (sloth) specifically.

If you only want the pattern, read §§1–4. If you are an agent picking
up sloth, read all of it.

---

## 1. Where the name comes from

In manufacturing, a **dark factory** ("lights-out manufacturing") is a
plant that runs without humans on the floor. The lights are literally
off because no human eyes need to see. The plant is designed end-to-end
so that the machines feed each other, inspect each other, and call for
help only on exception.

Apply that to a software repo. A **dark factory repo** is a repo
designed so the entire build / test / review loop can run with no
human in the inner loop. Agents commit, agents test, agents review,
agents merge. The human shows up at the edges: to set direction, to
accept the result, and to handle the exceptions the agents bounce up.

The repo is the factory. The mission file is the production order. The
agents are the machines.

---

## 2. Autonomy levels for software dev

Borrowed from the SAE driving-autonomy levels. Useful for being honest
about which level your project is actually at.

| Level | Name | Who writes the code | Who runs the tests | Who reviews | Who decides scope |
|------|------|---------------------|--------------------|-------------|------|
| 0 | Manual | Human | Human | Human | Human |
| 1 | Assisted | Human (with completions) | Human | Human | Human |
| 2 | Partial automation | Human + agent (pair) | Human | Human | Human |
| 3 | Conditional automation | Agent (human-supervised) | Agent + human | Human | Human |
| 4 | High automation | Agent | Agent | Agent (human spot-check) | Human |
| 5 | Full automation | Agent | Agent | Agent | Agent (within mission) |

Most "AI-assisted coding" today lives at Level 2 or 3. A dark factory
repo is the substrate that makes Level 4 / Level 5 *possible* for a
given project — it doesn't guarantee the agent is good enough yet, but
it removes every reason the agent would have to stop and ask.

Sloth targets **Level 5 within the bounds of [`MISSION.md`](../MISSION.md) §2**.
Outside those bounds (rewriting the mission, breaking external
contracts, touching anything outside the repo) the level drops to 3:
agent proposes, human decides.

---

## 3. What makes a repo Level-5-ready

The pattern is a checklist. A repo is dark-factory-ready when it can
answer "yes" to all of these from a fresh clone, on a fresh machine,
with an agent that has never seen the project before.

### 3.1 The mission is in-tree

There is a `MISSION.md` (or equivalent) at the root that states:

- **Why the software exists** in one paragraph.
- **What it must never become** — the non-negotiable rules. Ethical,
  legal, and architectural lines that an agent is not allowed to cross
  even if the change would be useful.
- **Where the project is right now** — current state, grounded in what
  is actually in the tree, not aspirations.
- **Direction** — where the gravity is, and what is explicitly out of
  scope. Out-of-scope is as important as in-scope, because the agent
  needs to know what *not* to suggest.

If the mission is in someone's head, in a Slack channel, or in a
private Notion doc, you are not Level 5 — you are Level 3 with a
brittle dependency on that person being available.

### 3.2 The conventions are in-tree

A `CLAUDE.md` (or `AGENTS.md`, `CONTRIBUTING.md` — whatever the agent
is taught to read first) covers:

- Build and test commands.
- Project structure and where new files belong.
- Coding style and comment policy.
- "How to add a *thing*" recipes for the kinds of changes that recur
  (in sloth: how to add a view, how to add an alert rule).
- Hard "don'ts" — destructive git operations, force-pushes, files that
  must never be staged, hooks that must not be bypassed.

The test for whether the conventions doc is good enough: a brand-new
agent should be able to add a routine feature without inventing a
single convention. If it has to guess, the doc has a gap — close it
as part of the work.

### 3.3 The tests are the ground truth

- `make test` (or equivalent) is the oracle. Green means ship-ready.
- Tests are hand-crafted from first principles. Never write a test
  that feeds a parser its own output — that loop passes even when
  both halves are wrong.
- Bug fixes ship with a test that would have caught the bug. This is
  how the factory learns: every escape becomes a new inspection step.
- Builds are warning-clean. Warnings are the agent's only signal that
  something compiled but is wrong; if you treat warnings as
  background noise, you lose the signal.

If the test suite is "yeah it mostly catches things," you are still at
Level 3 — the human is the actual oracle.

In this repo the merge gate is the **local green suite, enforced
pre-push**: work lands on `main` only after `make test` returns 0 and
`make` is warning-clean on the machine doing the work. CI plus the AI
code-review and docs-drift workflows re-run as post-hoc judges — they
catch escapes, they are not the gate. The converge loop
(`.claude/commands/converge.md`) automates exactly this: iterate until
the local oracle is green, then push.

### 3.4 Per-feature documentation is in-tree

For every non-trivial feature, there is a doc the agent can read to
understand the *protocol*, the *constraints*, and the *expected
shape* of normal vs. anomalous input. In sloth this is
`docs/views/*.md` — one file per view, following a template.

This is what lets the agent extend a feature without bothering the
human: it can read the existing contract and add to it.

### 3.5 The repo is the working directory

Nothing the agent needs lives outside the repo. No `~/.config` setup,
no environment variables only the human knows, no licence keys in a
password manager, no "you have to run this script first" tribal
knowledge. If something is needed, it is checked in or it is generated
by `make`.

Per-machine agent state (memory, scratch files, cached IDs) is
*allowed* outside the repo, but the repo must not *depend on it*.
A fresh clone on a fresh machine should build, test, and run.

### 3.6 The autonomy boundary is written down

This is the single piece most projects miss. The mission says what the
software does. The conventions say how to build it. Neither tells the
agent *when it must stop and ask*. Without that, the agent will either
ask about everything (Level 2 in disguise) or decide everything
(Level 5 with no brakes).

The boundary belongs in this file. See §5.

---

## 4. The autonomy contract

This is the explicit "when does the agent decide, when does it
escalate" rule set. Adapt it for your own repo; the shape generalises
even if the specifics don't.

### 4.1 Agent decides (no escalation)

- Code-level implementation choices: naming, structure, helper
  extraction, which std-lib function to use, which test to write
  first, how to factor a parser.
- Bug fixes whose root cause and remedy are obvious from the
  evidence.
- Adding a feature that fits an existing pattern (in sloth: a new
  view, a new alert rule, a new protocol parser) when the mission and
  conventions already describe how.
- Refactors that don't change the public contract.
- Test additions, comment cleanups, doc updates that match what the
  code already does.
- Picking up the next thing from the mission's direction list when
  the current task is done.

### 4.2 Agent decides, but flags the decision

These are calls the agent is allowed to make, but the commit message
or PR body must say *what was decided* and *why*, so the human
reviewer sees it without digging.

- Picking between two reasonable architectural approaches.
- Disabling a test (must explain why and link a follow-up).
- Adding a new dependency.
- Changing a default that has been stable for a while.
- Anything that the agent itself was uncertain about and resolved by
  judgement.

### 4.3 Agent stops and asks

- **Mission-level changes.** Anything that would require editing
  `MISSION.md` §2 (the non-negotiable rules) is not the agent's call.
  Ever. Even if the change seems obviously beneficial.
- **External-contract breaks.** Renaming a CLI flag, changing the
  JSONL schema in a non-additive way, breaking the output format a
  downstream tool depends on.
- **Destructive operations.** `git push --force`, `git reset --hard`
  on shared branches, deleting branches, dropping tables,
  overwriting unreviewed work.
- **Actions outside the repo.** Modifying the user's shell config,
  installing global packages, calling external APIs that cost money
  or send messages, anything that affects shared infrastructure.
- **Scope expansion.** The user asked for X; the agent thinks Y would
  also be valuable. Y is a separate proposal, not a silent addition
  to X.
- **The agent's own uncertainty is structural, not tactical.** "I
  don't know how to centre this `div`" is tactical — figure it out.
  "I don't know whether this feature belongs in this tool at all" is
  structural — ask.

The shorthand: **decisions inside the mission are yours; decisions
about the mission are not.**

---

## 5. How sloth implements the pattern

Concrete pointers, so an agent reading this can see the pattern in
the actual tree:

| Checklist item | File / location |
|----------------|-----------------|
| Mission              | [`MISSION.md`](../MISSION.md) |
| Non-negotiable rules | [`MISSION.md`](../MISSION.md) §2 |
| Conventions          | [`CLAUDE.md`](../CLAUDE.md) |
| Build / test         | `make`, `make test` (both warning-clean / green required) |
| Architecture         | [`CLAUDE.md`](../CLAUDE.md) "Architecture" section |
| Recipes              | [`CLAUDE.md`](../CLAUDE.md) "How to add a new view" / "How to add an alert rule" |
| Per-feature docs     | [`docs/views/*.md`](views/) — one per view, common template in [`docs/views/README.md`](views/README.md) |
| Cross-cutting docs   | [`docs/wiki/*.md`](wiki/) — architecture, alerts catalogue, IP palette, attack map, etc. |
| Tests as oracle      | `tests/` — ~1950 assertions, fake platform in `tests/fake_platform.c` |
| Autonomy contract    | this file, §4 |
| Cold-start procedure | [`MISSION.md`](../MISSION.md) §5 |

What the repo deliberately does *not* depend on:

- **Per-agent memory.** Some agents maintain a memory store outside
  the repo. Sloth treats that as a convenience, not a source of
  truth. Anything important must end up in the tree.
- **External services.** No fetch from a private API, no CI secrets
  beyond what's needed to push, no licence server.
- **Human-side setup beyond a C toolchain and libpcap.** The
  embedded build doesn't even need libpcap.

---

## 6. Applying the pattern to your own repo

If you want to convert an existing repo to a dark factory:

1. **Write the mission first.** One paragraph of *why*, a numbered
   list of non-negotiable rules, an honest description of current
   state, a direction list. If you can't write the non-negotiables,
   you don't yet know what your project is — and an agent definitely
   won't.

2. **Write the conventions second.** Build commands. File layout.
   Hard don'ts. The "how to add a *X*" recipes for whatever recurs in
   your project. Test it by handing the doc to an agent and asking
   it to add a routine feature without you in the room. Every
   question the agent has to ask is a gap in the doc — close it.

3. **Make the tests the oracle.** If `make test` doesn't actually
   tell you whether the code works, the dark factory has no
   inspection station. Invest here before you invest in agent
   autonomy.

4. **Write the autonomy contract.** Decide explicitly which classes
   of decisions the agent owns and which it must escalate. Put it in
   the repo. Without this, the agent will either ask too much
   (Level 2 in disguise) or too little (Level 5 with no brakes).

5. **Run a cold-start drill.** Clone the repo onto a fresh machine.
   Hand it to an agent that has never seen the project. Tell it to
   land one real feature. Whatever it has to ask you, that's the next
   doc to write.

You are at Level 5 when the drill succeeds.

---

## 7. The one-line summary

> A dark factory repo is one where the mission, the conventions, the
> tests, and the autonomy boundary are all in-tree, so an agent can
> walk in cold and continue building without a human in the inner
> loop.
