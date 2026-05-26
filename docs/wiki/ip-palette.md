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

- `CRIT` alerts → heat-1.0 red.
- `WARN` alerts → heat-0.7 orange.
- TLS 1.0 / 1.1 (deprecated 2020) → heat-orange.
- NXDOMAIN → heat-orange.

## Minimum geometry

- Dashboard minimum: 100×33.
- Below that, the seven-band tiling collapses and some panels go
  unreadable.

## Related pages

- [[dashboard]] — the panel that puts all of this on display at once.
- [[sloth]] — the broader "what sloth is" page.
