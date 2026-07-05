# Sloth — Claude project instructions

These instructions configure how Claude (Claude Code, Claude Projects, or
any future agent) should work inside this repo.

## What sloth is

A terminal-based **passive** network monitor for Linux, written in C99.
It never injects packets, never scans, never modifies kernel state. It
reads `/proc`, `/sys`, netlink (rtnetlink / nl80211 / INET_DIAG) and a
pcap stream, then surfaces what it sees through 24 ncurses views, six
alert rules, an embedded threat-intel matcher, optional per-alert pcap
dumps, and an optional JSONL forensic log.

Single binary `sloth`. Test binary `sloth_test`.

## Architecture

- `include/sloth.h` — central header: shared structs, the `view_t` enum.
- `src/main.c` — CLI, signal handlers, main poll loop.
- `src/tui.c` + `tui.h` — ncurses rendering, colour pair init, key polling.
  ANSI fallback when built without ncurses.
- `src/platform/linux*.c` — Linux backends (rtnetlink, nl80211, /proc
  readers, INET_DIAG).
- `src/capture/capture.c` — libpcap thread; dispatches per-protocol
  parsers (decode_ipv4/v6 → TCP/UDP → DNS/TLS/HTTP/QUIC/NTP/ICMP).
- `src/{dns,tls,quic,http,ntp,icmp,dns}_log.c` — ring buffers + per-record
  snapshot.
- `src/{alerts,beacon_detect,devices,threat_intel,filter,jsonl,alert_pcap,
  top_hosts,ip_color,ip_owner}.c` — synthesis + export.
- `src/views/*.c` — one file per VIEW_*. The dashboard composites several
  panels into one grid.
- `src/md5.c` — embedded MD5 for JA3 (verified against RFC 1321 vectors).
- `tests/` — unit tests, fake platform, scenarios. ~1664 assertions.
- `docs/views/*.md` — per-view deep dives. Linked from README tables.

## Discipline

- **Tests must pass.** `make test` returns 0. Never commit a red test.
- **Builds must be warning-clean.** `make` produces no warnings.
- **VIEW_COUNT must be kept in sync** across `include/sloth.h`,
  `tests/test_state.c`, and `tests/test_arp.c` whenever a view is added
  or removed.
- **Hand-crafted protocol tests.** Parsers are tested with raw byte
  arrays built from first principles per RFC. Don't write circular tests
  (parser feeding its own output back).
- **No mocks of real-data interfaces.** The fake platform in
  `tests/fake_platform.c` lives there for a reason.
- **Per-view docs follow the template** in `docs/views/README.md`:
  protocol → what sloth captures → text mockup → normal → suspicious →
  see-also.

## Conventions

- **Sprint cadence.** Early work was numbered weekly sprints ("Week N:
  …"); now it's feature-named commits.
- **Commit messages.** Imperative subject line, blank line, optional
  body explaining the *why*. End with the `Co-Authored-By` trailer.
- **Branches.** Work on `main`. No long-running feature branches.
- **Pushes.** Push after each green commit. The user reviews on GitHub.
- **`git add` specific files.** **Never** `git add -A` or `git add .`.
  There is a local `wifi-sigint/` directory that must never be staged or
  pushed.

## UI conventions

- Terminal **backgrounds are disabled** — rows render on the terminal
  default. Don't reintroduce row tints without asking.
- **IP palette = Fallout phosphor**: 8 hash-derived colours orbiting the
  project's teal phosphor base. Same IP → same colour everywhere. IPs
  appearing in ≥2 dashboard sources render **bold**.
- **SSIDs** use the same 8-colour palette via a separate hash.
- **Brand colourisation** in hostnames:
  - `google` → G-o-o-g-l-e in blue/red/yellow/blue/green/red (logo).
  - `firefox` → orange. `cloudflare` → red. `example.org` → grey.
  - Implemented as case-insensitive substring matches
    (`tui_brand_addstr`).
- **Box-drawing**: panel titles use `── name ──` (U+2500). `->` is `→`
  (U+2192). Fira Code or any decent UTF-8 monospace renders these
  cleanly. Reserved macros `G_VERT`, `G_TL/TR/BL/BR` are available for
  future framing.
- **Sparklines** are heat-graded by level (cool phosphor → peak red)
  with `_` for zero / missing samples. They stretch to fill any width.
- **Dashboard layout** is a 7-band tile filling the terminal:
  iface (height = iface_count), conn + top-hosts (= 2H), packets (= 2H),
  three 3-panel rows at H each, dns/icmp at H. Min terminal 100×33.

## Hard "don't"s

- Don't run destructive git ops (`reset --hard`, `push --force`, branch
  delete) without explicit user authorisation.
- Don't add new files at repo root; everything has a home (`src/`,
  `tests/`, `docs/`, `include/`).
- Don't stage `wifi-sigint/`, `sloth`, or `sloth_test`.
- Don't reintroduce coloured row backgrounds (deliberately removed).
- Don't bypass git hooks (`--no-verify` etc.) unless explicitly asked.
- Don't push directly to a branch other than `main` without asking.

## How to add a new view

1. Define `VIEW_* = N` in `include/sloth.h` enum; bump `VIEW_COUNT`.
2. Add state fields (ring buffer + count + sel) on `sloth_state_t`.
3. Add the data type / log entry struct.
4. Create `src/views/<name>.c` + `.h` with `view_<name>_draw` and
   `view_<name>_key`.
5. Pick a key in `src/main.c`, add to the case statement.
6. Add to `view_labels[]` and the dispatch switch in `src/tui.c`.
7. Update the Makefile SRCS and TEST_SRCS.
   - If the new view has any *view-local* action bound to a letter
     that the global switch already uses (see `src/main.c`
     view-switch cases), add a claim entry in
     `src/view_route.c :: view_claims_key()` — otherwise the global
     switch silently swallows the key before the view sees it. Cover
     the new claim in `tests/test_state.c`. See issue #13 for the
     original shadow bug.
8. Update `VIEW_COUNT` and the tab-cycle assertions in
   `tests/test_state.c` and `tests/test_arp.c`.
9. Write a `tests/test_<name>.c` with at least: empty-state,
   populated-state render, nav, and any protocol-specific parse tests.
10. Write a `docs/views/<name>.md` and link it from `README.md` and
    `docs/views/README.md`.
11. `make test && make` clean before committing.

## How to add an alert rule

1. Add `ALERT_TYPE_<NAME>` to the enum in `include/sloth.h`.
2. Write a `rule_<name>(state, now)` function in `src/alerts.c` that
   calls `fire(...)`.
3. Add the call from `alerts_update()`.
4. If the alert has a known target IP, pass `match_ip` + `match_port` to
   `fire()` so per-alert pcap export works.
5. Add a row to the rule table in `docs/views/alerts.md`.
6. Test: seed state that should trigger the rule, run `alerts_update`,
   assert `find_alert(type) >= 0`.

## Style preferences

- Terse, technical, no marketing language in code or docs.
- Comments explain *why*, never *what* (the code shows what).
- C99 only. No GNU extensions unless gated and explained.
- Variable column widths in views should flex with panel width — fixed
  widths are a smell.
- Errors at boundaries only (user input, syscalls, parsing). Trust
  internal code.

## When you don't know

- Read `docs/views/<view>.md` for protocol context.
- Read the existing `tests/test_<x>.c` for the canonical usage of `<x>`.
- The platform vtable (`platform_ops_t` in `sloth.h`) is the seam to the
  kernel; views must never call platform ops directly — they read from
  `sloth_state_t`.

## Token / Cost Ledger (billing-grade)

The owner bills clients from `LEDGER.md` at this repo's root. Entries must be **exact, not estimated**.

### How to record a commit

After every substantive commit you author:

```bash
~/.claude/billing/ledger.py --append --summary "<short description>"
git add LEDGER.md
git commit -m "chore(ledger): $(git rev-parse --short HEAD~0)"
```

The script:

- Reads token usage from the JSONL transcripts under `~/.claude/projects/<encoded-cwd>/`.
- Sums assistant turns in the window `(last ledger row's date, HEAD commit time]`, normalized to UTC.
- Prices each turn against `~/.claude/billing/pricing.json` (per-model, per-tier, long-context aware, service-tier aware, server-tool aware).
- **Aborts with exit code 3 if it encounters an unknown model or service tier.** A missing row is fine; a wrong row is not.
- Exits 2 with no row if no usage was found in the window (e.g. a human-only commit).

Use `--dry-run` to preview without writing. Use `--commit <sha>` to ledger a specific commit rather than HEAD. See `~/.claude/billing/ledger.py --help` for all flags.

### Rules

- **Never bypass the script.** Do not hand-author rows, estimate tokens, or fabricate costs. If the script can't produce a row (unknown model, missing transcript, session ran from a different cwd), stop and surface the problem to the owner.
- **Append-only.** Never rewrite, reorder, or delete past rows. Correct mistakes by adding a new row whose `summary` notes the correction.
- **Separate commits.** The ledger update lands as its own `chore(ledger): <short-sha>` commit. Never amend the substantive commit.
- **Keep pricing current.** If you notice Anthropic pricing has changed, update `~/.claude/billing/pricing.json` in its own commit before running the ledger again. Past rows correctly preserve historical pricing.
- **Multi-machine work** isn't aggregated automatically — transcripts live on whichever machine ran the session. Surface this if relevant.
