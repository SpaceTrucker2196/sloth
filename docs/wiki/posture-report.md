---
name: posture-report
description: --report / --report-json write a session summary at exit
---

# Posture report export

**Skill**: post-hoc summary of everything sloth observed during a
session. Not a live view — one file at shutdown.

## Flags

- `--report FILE.md` — Markdown, for hand-audit.
- `--report-json FILE.json` — JSON, for SIEM diff / CI compare.

Both can be set at the same time.

## What's in it

- Session start / end timestamps and duration.
- Alert counts by severity (LOW / WARN / CRIT).
- MITRE ATT&CK technique breakdown — one row per unique technique
  observed during the session, with hit counts. Posture-only alerts
  like `NO_MONITOR_MODE` are correctly *omitted* (they have no
  technique).
- Cleartext credential exposures — src, dst, protocol, username, and
  whether a password was on the wire. **Never the password value.**
  The Markdown report includes a reminder note to the reader.
- High-risk devices — the `[g]` Devices view is dedup'd to just the
  rows in `HIGH` and `CRIT` buckets, with the risk signal bitmask
  next to each.

## Cadence

Written once, at process exit, after the main loop has drained. This
means the file is a session record — not a mid-run snapshot. If sloth
exits abnormally (SIGKILL, panic), the file isn't produced. `SIGINT`
and `SIGTERM` go through the normal shutdown path and produce the
report.

## Mission alignment

Everything in the report is derived from tables sloth already
maintains. No new observation surface, no probes, no writes to the
wire. The report closes the loop between "we saw X" and "here's a
sign-off document."

## Related pages

- [[alerts]] — where the ATT&CK tag on each alert comes from.
- [[jsonl-schema]] — the streaming event log the report summarises.
- [[cleartext-cred-guardrail]] — the "no password field, ever" rule.
