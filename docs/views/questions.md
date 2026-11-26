# Questions view `[!]`

The site questions (#244): what the operator wants to know, each tied to
the alert kinds that answer it, with an answer derived from the open
findings and the coverage status of those kinds. The concept page is
[site-questions](../wiki/site-questions.md).

## Protocol / data source

None of its own. The view reads two things sloth already holds:

- the alert snapshot (`sloth_state_t.alerts`): the open findings;
- the coverage status of each alert kind (`src/rule_coverage_live.h`,
  [coverage-assessment](../wiki/coverage-assessment.md)): whether the
  rule behind it can fire with the sensor's radios, sources and
  designations.

The questions are the seven defaults of `include/sloth_questions.def`,
or the operator's `--questions PATH` file. `q_live_answers()`
(`src/questions_live.c`) derives the answers on every draw.

## What sloth captures

Per question this daemon answers (a question none of whose kinds
sloth-wifi raises is left out):

| Column | Content |
|---|---|
| Id | `Q1` .. `Q7`, or the file's id |
| Pri | priority, 1 most urgent; rows are sorted by it, then in set order |
| Status | `finding`, `no_finding`, `no_finding_partly`, `not_observable`, `not_assessed` |
| Why / found | the kinds with a finding, or the first blind (else partly) indicator's reason |
| Question | the question as written |

Below the table, for the selected question: its decision, its
indicators' coverage counts (or "not assessed"), and with findings their
kinds and incident ids. Never an address, SSID or name.

## View

As `tests/test_questions_view.c` renders it: one `EVIL_TWIN` finding,
before the first coverage sample.

```
 Site questions: 7  with a finding: 1  defaults  [up/dn] select
 coverage not assessed: no status sample has been taken yet
 Id       Pri Status            Why / found      Question
 Q1       1   finding           EVIL_TWIN        Is a device impersonating one of my networks?
 Q2       1   not_assessed      -                Is a device that I do not know on my network?
 Q3       1   not_assessed      -                Is a device collecting key material near my site?
 Q7       1   not_assessed      -                Is the sensor able to see what it must see?
 Q4       2   not_assessed      -                Is a device or a person surveying my site again and again?
 Q6       2   not_assessed      -                Is the radio environment being denied or degraded?
 Q5       3   not_assessed      -                Is my site revealing information?

 Q1: Is a device impersonating one of my networks?
 Decision: Warn users off the network and find the transmitter.
 Indicators: 16, not assessed
 Findings: 1 (EVIL_TWIN); incidents 00000000000000e1
```

With coverage assessed, the Why column names the first blind (else
partly) indicator's reason, `no_own_net` or `hop` for example, and the
Indicators line gives the observable, partly and blind counts.

## What's normal

- Q7 `no_finding` or `no_finding_partly`: the sensor is up.
- Most questions `no_finding_partly` on a single hopping radio: a
  rate or exchange rule loses the time the radio spends on other
  channels.
- `not_assessed` everywhere in a `--replay` run, or for the first
  second after start: no coverage status exists yet.

## What's suspicious

- Q1, Q2 or Q3 `finding`: the decision on the row below is the one the
  question was written for; open the Alerts view `[v]` on the kinds
  named.
- Q7 `finding`: the sensor cannot see what it must; every `no_finding`
  above it is weaker than it reads.
- `not_observable` on a question the operator relies on: the reason
  names what to fix (`no_own_net`: designate the network with
  `--my-ssid`; `no_source`: the input is not configured).

## See also

- [site-questions](../wiki/site-questions.md) — the questions, the map, the status, the file format
- [alerts.md](alerts.md) — the kinds
- [coverage-assessment](../wiki/coverage-assessment.md)
