---
name: posture-report
description: --report / --report-json write a session summary at exit, optionally a live copy while running and one record per session
---

# Posture report export

**Skill**: post-hoc summary of everything sloth observed during a
session. One signed-off file at shutdown; optionally a live file while
running and one record per session (#190).

## Flags

- `--report FILE.md` — Markdown, for hand-audit.
- `--report-json FILE.json` — JSON, for SIEM diff / CI compare.

Both can be set at the same time.

- `--report-interval SECS` — also write the report every SECS seconds
  (0..86400, default 0 = off) to `report.live.md` / `report.live.json`
  beside the report path. The live file is the same rollup, marked as
  still running, written to a temporary sibling and renamed into place.
- `--report-history` — on exit, also keep this session's report as
  `report.<UTC session start>.md` (and `.json`), created 0600 and never
  over an existing name, so a restart does not replace an earlier
  session's record. sloth does not prune these.

A session that is killed never signs off, so its live file is its only
record. A later session sets it aside as `report.<UTC mtime>.unclean.md`
before reusing the live name.

The report names credential exposures and high-risk devices, so it is
written **0600** whatever the umask (#87). An existing file at the path
is validated *before* it is truncated: a symlink, another user's file,
a multiply-linked file or one with any group/other bit is refused and
left untouched (`could not open --report …: … refusing (report
skipped)`). A write that fails at close is reported instead of
announced as written.

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
  next to each. Since #191 a device reaches `HIGH` only on evidence
  (a cleartext credential, bit 16, or an active alert naming its IP,
  bit 32) and `CRIT` only on both: the four anonymity bits (1, 2, 4,
  8 — randomised MAC, unknown vendor, no hostname, probe-only) are one
  point between them and stop at `MED`, so a passing phone is no
  longer listed. Bit 64 (`SELF`) marks one of the sensor's own
  interfaces or a rostered device; it carries no points, so such a
  device appears here only when it has evidence against it. The
  table is in `docs/views/devices.md`, "Risk bucket".

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
- [`cleartext_cred` in the JSONL schema](jsonl-schema.md#cleartext_cred) —
  the "no password field, ever" rule.
