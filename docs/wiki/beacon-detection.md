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

A flow fires `BEACONING` when **either** detector returns non-zero.
Both run on the same 16-slot per-flow sample ring (`bd_track_t`).

### v1 — classic low-jitter (stddev / mean)

- ≥ 5 samples (callouts to the same remote IP:port).
- mean inter-callout interval ≥ 10 s (so we don't false-positive on
  bursty interactive traffic).
- jitter / mean ratio ≤ 0.25 (low variance → regular interval).

The alert detail shows `every 60s (jitter=1.2s, n=12)`.

### v2 — gap concentration (jittered C2)

- ≥ 12 samples (more data needed to separate periodic-with-jitter
  from random gap distributions).
- median gap ≥ 10 s.
- fraction of gaps within ±30 % of the median ≥ 0.60.

v2 lets us catch the modern C2 frameworks the v1 stddev/mean test
ruled out: Cobalt Strike at the documented "interactive" 30 % jitter
setting, Sliver at default 30 %, and most custom implants up to ~40 %
additive jitter. The alert detail shows
`every ~60s jittered (concentration=0.73, n=16)`.

## Why these thresholds

- **5 samples (v1)** is the smallest number that gives a defensible
  jitter estimate.
- **10 s mean / median** filters out web heartbeats and AJAX polling.
  Real C2 implants typically check in every 30 s – 1 hr.
- **jitter/mean ≤ 0.25 (v1)** is a soft "regular enough" line. Most
  legitimate periodic clients (NTP, mDNS, dhclient renewals) sit well
  above this either because they're more bursty or because they
  scatter with random delay.
- **12 samples (v2)** is the smallest count that keeps the
  uniform-random false-positive rate under ~0.1 % at the 0.60
  concentration threshold.
- **concentration ≥ 0.60 (v2)** is chosen to cover up to ~40 %
  additive jitter. Setting it higher (e.g. 0.75) tightens to ~30 %
  but starts missing real Cobalt deployments; lower (0.50) starts
  flagging well-clustered bursty traffic.

## What this misses

- **Sliver "low-and-slow"** at 50 %+ jitter — statistical separation
  from random gap distributions isn't reliable with only 16 samples.
  The practical mitigation is longer flow histories: a session that
  persists long enough for the v1 mean stability to assert itself
  still fires, just later.
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
