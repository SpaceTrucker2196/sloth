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
  With `--snapshot-out snapshot.txt` the same interval also keeps
  `snapshot.live.txt`, the AP inventory so far, written the same way
  and marked `# session<TAB>running`. `--report-interval` with only
  `--snapshot-out` is allowed.
- `--report-history` — on exit, also keep this session's report as
  `report.<UTC session start>.md` (and `.json`), created 0600 and never
  over an existing name, so a restart does not replace an earlier
  session's record.
- `--tune report.retain_days=N` (default 90, `0..3650`, 0 = forever) —
  per-session records (`report.<stamp>.md`, `report.<stamp>.unclean.md`
  and their `_N` variants) last modified N or more days ago are deleted
  at start and at shutdown. Only on a run with `--report-interval` or
  `--report-history`; only names of exactly that shape, regular files
  owned by sloth's user, nothing followed. The report itself, the live
  file and anything else in the directory are never touched.

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

| File | When | Written how |
|------|------|-------------|
| `report.md` / `.json` | at exit, after the main loop has drained | truncated in place after the existing file is validated (#87) |
| `report.<start>.md` / `.json` | at exit, with `--report-history` | `O_EXCL`, never replaced |
| `report.live.md` / `.json`, `snapshot.live.txt` | every `--report-interval` seconds, and at once on `SIGUSR1` | hidden `.NAME.tmp` (0600, `O_EXCL`), `fsync`, `rename(2)` over the live name |
| `snapshot.txt` (`--snapshot-out`) | at exit | as `report.md` |

The signed-off `report.md` is a session record, not a mid-run snapshot.
If sloth exits abnormally (SIGKILL, OOM, power loss) it is not
produced, and the live file is that session's only record. `SIGINT`
and `SIGTERM` go through the normal shutdown path and produce the
report; the live files are then removed.

**Off the capture path.** The live write runs on the main thread,
after `poll_data()` has copied each capture module's table into the
state under that module's lock, the same point the TUI draws from. The
capture threads never wait on it and it never reads their tables
directly; `tests/test_posture.c ::
test_live_writes_do_not_race_the_capture_thread` drives a real beacon
writer thread against forced live writes and is run under
`-fsanitize=thread`. A slow disk delays the next poll by the write
time (a few hundred KB at most, once an interval), never a frame.

**SIGUSR1** only sets a `sig_atomic_t` flag; the next tick does the
write. The signal is always handled, so it cannot kill a sensor that
was started without a report path.

**`--baseline-in` and `--snapshot-out` on the same file**, as the
shipped unit has them: the live snapshot is a separate file, so the
baseline still moves only when a session signs off, and a killed
session never replaces it.

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
