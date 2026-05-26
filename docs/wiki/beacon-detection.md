---
name: beacon-detection
description: Periodicity detector for C2 / implant beaconing — jitter/mean ratio, sample threshold
type: reference
---

# Beacon detection

**Summary**: Detects flows that contact the same remote on a regular interval — the classic command-and-control "phone home" signature. Lives in `src/beacon_detect.c`; fires `ALERT_BEACONING` (WARN).

**Sources**: `docs/views/alerts.md`, `docs/views/packets.md`, `docs/views/connections.md`.

**Last updated**: 2026-05-25.

---

## Trigger

A flow fires `BEACONING` when **all** hold:

- ≥ 5 samples (callouts to the same remote IP:port).
- mean inter-callout interval ≥ 10 s (so we don't false-positive on
  bursty interactive traffic).
- jitter / mean ratio ≤ 0.25 (low variance → regular interval).

The alert key is `beacon:<remote>:<port>`. The footer shows the
computed cadence, e.g. `every 60s (jitter=1.2s, n=12)`.

## Why these thresholds

- **5 samples** is the smallest number that gives a defensible jitter
  estimate. Fewer than that and you're computing variance on noise.
- **10 s mean** filters out things like web heartbeats and AJAX
  polling. Real C2 implants typically check in every 30 s – 1 hr.
- **jitter/mean ≤ 0.25** is a soft "regular enough" line. Most
  legitimate periodic clients (NTP, mDNS, dhclient renewals) sit well
  above this either because they're more bursty or because they
  scatter with random delay.

## What this misses

- **Jittered C2** — modern frameworks (Cobalt Strike, Sliver) jitter
  the callout interval deliberately to evade exactly this kind of
  detector. Aggressive jitter (50%+) pushes the ratio above 0.25.
- **Domain-fronted C2** where the apparent remote changes — sloth
  groups by remote IP:port, so a domain-fronted implant looks like
  many short flows to one CDN edge.

## Pairing with other signals

- A `BEACONING` row whose host looks legitimate (`*.cloudflare.com` in
  Top hosts) but whose [[ja3-fingerprinting]] JA3 doesn't match a known
  browser = strong implant signal.
- `BEACONING` + a [[threat-intel]] domain hit on the same flow = case
  closed.

## Related pages

- [[alerts]]
- [[ja3-fingerprinting]]
- [[threat-intel]]
- [[attack-map]] — "Implant / C2 fingerprint" entry
