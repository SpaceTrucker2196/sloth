---
name: cleartext credential guardrail
description: Why sloth records credential exposure facts but never stores or exports password material
type: reference
---

# Cleartext credential guardrail

**Summary**: The cleartext-credential pipeline records only the fact that a username and optional password crossed the wire; it never stores, hashes, truncates, or re-exports the password material itself.

**Sources**: `src/cleartext_creds.c`, `src/jsonl.c`, `src/db_schema.c`, `src/db.c`, `src/posture.c`, `README.md`, `MISSION.md`.

**Last updated**: 2026-09-18.

---

sloth treats cleartext credentials as an exposure finding, not as loot.
That distinction is enforced in the data structures, the JSONL wire
format, the SQLite schema, and the shutdown report.

## What is retained

Every cleartext-credential observation reduces to these fields:

- source IP
- destination IP
- destination port
- protocol label (`HTTP-Basic`, `FTP`, `POP3`, `IMAP`, `SMTP`, ...)
- username
- `pw_observed` — a boolean saying whether a password value crossed the wire
- timestamps / counts needed to deduplicate and retain the exposure event

That is enough to answer the operational question: *which device exposed
credentials, to what service, and did the exchange include a password?*

## What is explicitly not retained

- the password value
- a hash of the password value
- a truncated or masked copy of the password value
- protocol-specific crackable material disguised as a credential field

`src/cleartext_creds.c` records the username and flips `pw_observed` when
it sees the password half of the exchange. There is no password slot in
`cleartext_cred_t` to accidentally populate later.

## Why the split matters

A passive monitor may report that a secret was exposed without becoming a
secret store itself. That keeps sloth on the right side of its mission:
it observes what crossed the wire, but it does not turn an exposure event
into a credential-harvesting product.

The same boundary shows up elsewhere in the tree. `--eapol-dir` writes
explicitly requested handshake material for offline cracking, while the
SQLite artifact and the JSONL stream keep only the metadata that says a
capture happened.

## Where the guardrail is enforced

| Surface | Enforcement |
|---|---|
| in-memory ring | `cleartext_cred_t` stores username + `pw_observed`, never password bytes |
| JSONL | `cleartext_cred` records carry `username` and `pw_observed` only |
| SQLite | `cleartext_creds` table omits any password column by design |
| `--report` / `--report-json` | reports exposure facts back to the operator without replaying the secret |
| tests | schema and report tests fail if password material is introduced |

## Operator meaning

If `CLEARTEXT_CRED` fires, the response is to fix the network or service
that allowed the cleartext exchange, rotate the exposed secret if needed,
and treat the event as evidence. The password itself should already be
considered compromised; storing another copy of it does not improve the
finding.

## Related pages

- [[posture-report]] — the human-readable and JSON shutdown artifact that summarizes these exposures.
- [[jsonl-schema]] — the `cleartext_cred` streaming record shape.
- [[sqlite-schema]] — retained storage rules, retention tiers, and schema guardrails.
- [[research-corpus]] — the source-backed explanations the report can attach to alerts without carrying secrets.
