---
name: ip-palette
description: UI convention — Fallout phosphor IP palette, brand colourisation, sparkline heat grading
type: reference
---

# IP palette and TUI conventions

**Summary**: Sloth's terminal UI uses a deliberate, restrained colour vocabulary. IPs and SSIDs hash to one of 8 Fallout-phosphor colours; brand names get logo colourisation; sparklines are heat-graded; row backgrounds are never tinted.

**Sources**: `CLAUDE.md`, `docs/views/dashboard.md`, `docs/views/dns.md`, `docs/views/beacons.md`, `docs/views/tls.md`.

**Last updated**: 2026-05-25.

---

## Palette

- 8 colours orbiting the project's teal phosphor base.
- IPs hash to a colour deterministically — **same IP, same colour
  everywhere**. Implemented in `src/ip_color.c`.
- SSIDs use the same 8 colours via a **separate hash** so a hostname
  and an SSID can't accidentally collide.

## Cross-panel cues

- IPs visible in **≥ 2 dashboard sources** render **bold**. Instant
  cross-reference cue on the [[dashboard]].
- Row backgrounds are **off**. Don't reintroduce them without asking —
  they were deliberately removed.

## Brand colourisation

Implemented in `tui_brand_addstr` as case-insensitive substring
matches in hostnames / SSIDs:

| Substring     | Colour |
|---------------|--------|
| `google`      | G-o-o-g-l-e in blue/red/yellow/blue/green/red (the logo) |
| `firefox`     | orange |
| `cloudflare`  | red |
| `example.org` | grey |

DNS, TLS SNI, and Top hosts all run hostnames through this.

## Sparklines

- Heat-graded by level: 1–2 cool phosphor, 3–4 amber, 5–6 orange,
  7–8 peak red.
- `_` represents zero / missing samples.
- Stretch to fill any column width — fixed widths are a smell.

## Box-drawing

- Panel titles use `── name ──` (U+2500).
- `->` renders as `→` (U+2192).
- Reserved macros `G_VERT`, `G_TL/TR/BL/BR` available for future
  framing.
- Fira Code or any decent UTF-8 monospace renders these cleanly.

## Severity heat

Three-tier alert palette (yellow → orange → red), driven by
`alert_sev_t`. Cross-panel: any IP that has appeared in an alert
within the last hour renders in its severity colour everywhere it
shows up (`tui_alert_hot_attr(sev)`). Promotion only — a later LOW
does not downgrade an earlier CRIT.

| Tier | Hue    | xterm | Bold | Used for                       |
|------|--------|-------|------|--------------------------------|
| LOW  | yellow | 220   | no   | recon: port scan, NXDOMAIN burst, probe flood |
| WARN | orange | 208   | yes  | suspicious: deauth flood, beaconing, weak TLS |
| CRIT | red    | 196   | yes  | IOC hit, active attack                 |

Other heat usages keep the original gradient:

- TLS 1.0 / 1.1 (deprecated 2020) → heat-orange row.
- Standalone heat sparklines use the full CP_HEAT_LO/MID/HI/PEAK ramp
  independent of alert tiers.

## Two render backends

`src/tui.c` has an ncurses implementation and an ANSI fallback used when
built with `WITH_NCURSES=0` (`make embedded`, headless appliance
builds). Both must render the same phosphor, so the xterm-256 palette
lives in `src/tui_palette.c` — the ncurses backend feeds it to
`init_pair()`, the fallback emits it as `SGR 38;5;N`. Adding a colour
means adding it there, not in either backend.

Before issue #48 the colour helpers (`tui_ip_addstr`,
`tui_brand_addstr`, `tui_alert_hot_attr`, …) called `attrset` / `addstr`
unconditionally, so `WITH_NCURSES=0` did not compile at all. They now go
through a small set of backend-neutral primitives.

The degraded 8-colour path (terminals reporting `COLORS < 256`) is
ncurses-only and keeps its own approximation table.

## Colour policy and headless operation

`--no-color`, or a non-empty `NO_COLOR` environment variable
([no-color.org](https://no-color.org)), disables every escape sequence
the renderers emit: SGR under the ANSI backend, and `start_color()`
under ncurses. It does **not** stop drawing — that is `--headless`.

The two are separate because "I am reading this over a serial console"
and "nothing is reading this" are different situations. `--headless`
never touches the terminal at all: no draw, no screen clear, no
raw-mode termios change, no key read.

The policy lives in `src/tui_palette.c` rather than `tui.c` because it
is a property of the palette rather than of either renderer — and
because `tui.c` is swapped for a stub in the test build, which would
leave it untestable.

## Minimum geometry

- Dashboard minimum: 100×33.
- Below that, the seven-band tiling collapses and some panels go
  unreadable.

## Related pages

- [[dashboard]] — the panel that puts all of this on display at once.
- [[sloth]] — the broader "what sloth is" page.
