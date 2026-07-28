---
name: personas
description: UX test personas — grounded operator profiles plus the executable scenario suite each one drives
type: reference
---

# Personas & UX test suites

A persona here is not marketing copy. It is a **test fixture for the
operator experience**: a specific person, doing a specific job, with a
specific set of questions, against which sloth's views and flags can be
scored the way `make test` scores the parsers.

Each persona file carries two halves:

1. **The persona** — who they are, what hardware they carry, what
   deliverable they owe someone else, and the handful of questions they
   actually sit down to answer. Written concretely enough that a
   scenario either serves them or doesn't.
2. **A scenario suite** — numbered, executable steps with observable
   pass criteria, plus the *current* result of running them. A scenario
   that fails is not a bug report; it is a gap in the operator
   experience, which may be closed by a feature, a default, a keybind,
   or a doc.

## Why this exists separately from `tests/`

`make test` proves the code does what it says. It cannot tell you
whether what it says is the thing the operator needed. A parser can be
byte-perfect against the RFC and still leave a surveyor unable to answer
"is that AP a repeater or a rogue?" — because the answer was never
synthesised into a view. These suites are the inspection step for that
class of failure.

## Running a suite

Most WiFi SIGINT scenarios need Linux, monitor mode, and
`CAP_NET_ADMIN`; they cannot be exercised on a laptop running the BSD
platform backend. Each scenario states its requirements. Record results
inline in the persona file, dated, rather than in a side channel — the
scored table *is* the artifact.

Scenario verdicts:

| Verdict | Meaning |
|---------|---------|
| `PASS`    | The persona gets the answer, unaided, from a view or flag sloth already has. |
| `PARTIAL` | The raw observation exists but the persona has to synthesise the answer by hand across views. |
| `FAIL`    | The answer is not derivable from what sloth surfaces. |
| `WRONG`   | sloth answers, and the answer misleads. Ranked above `FAIL` — a confident wrong answer costs more than a gap. |

## Personas

- [wifi-surveyor](wifi-surveyor.md) — independent RF security
  researcher running site surveys and surveillance-detection sweeps.
