# sloth — agent instructions

Canonical agent instructions live in `agents/AGENTS.md`.

That folder is plaintext and public. It was git-crypt encrypted until
2026-07-28; the encryption was removed because it protected the wrong
thing. `agents/` holds operating procedure — how to converge an issue,
how the risk gate scores a diff, what the autonomy boundary is — not
secrets, and `agents/dark-factory.md` is explicitly written as a
teaching artifact for anyone adopting the pattern.

The original rationale was preventing prompt-injection contamination of
the files that steer agent behavior. Encryption did not really deliver
that: it stopped third parties *reading* the instructions, but an agent
working this repo also reads issue text, PR bodies, code comments and
README prose, all of which are wide open and are a far larger injection
surface. Hiding one small surface while leaving the large one exposed
bought little and cost every reader — including a fresh agent on a
machine without the key — the ability to see the rules it is being held
to.

The real defence is the one already in place: agent-instruction changes
are a reviewed, high-signal event. `agents/risk_score.sh` weights any
diff touching `agents/` at +40 precisely so such a change cannot arrive
quietly inside a feature commit.

@agents/AGENTS.md
