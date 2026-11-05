---
title: Cross-installation sharing is opt-in and sanitised
date: 2026-11-05
status: Accepted
authority: issue #184 §2 (decision 6) and C10, §3 Stage 6, §6 ("Sharing leaks")
---

# ADR 0006 — Cross-installation sharing is opt-in and sanitised

## Context

The reason to carve intelligence out at all is Stage 6: several sensors
feeding one `sloth-comint`, so that what one operator learns, the others
can see. The input #151 is missing — a fingerprint nobody has captured
alone, but which several installations have seen — is exactly what
sharing produces.

It is also the part of the programme that can leak. A sensor's state
holds probe SSIDs and preferred-network lists, client MACs, EAPOL
material and credentials seen in the clear. `MISSION.md` §2's standing
rule is that every network-using service is opt-in and announced, and
sloth already has the discipline that keeps a field off the wire: the
allow-list in `web/src/web_secret.h`.

## Decision

Sharing across installations is **opt-in, sanitised, and never carries a
secret** (#184 §2, decision 6):

- **Opt-in.** A `--no-share` default; the sync client runs on a timer
  only when an operator turns it on, and is announced in `sensor_health`
  like every other network-using service (`MISSION.md` §2, #184 §3 Stage
  6 item 2).
- **Sanitised through the same allow-list discipline as
  `web_secret.h`**, applied at ingest rather than only at egress.
- **Never a credential, never a username, never a raw SSID.**

What may be shared, and in what shape (#184 §3 Stage 6 item 1):

- `POST /v1/sightings` — BSSID or fingerprint hash, OUI, PHY, vendor-IE
  and IE-order hashes, WPS vendor strings, first and last seen. **No
  SSID in the clear, no client MACs.**
- `POST /v1/verdicts` — a triage state with its assessment basis and the
  alert type, **keyed by fingerprint, not by address**.
- `GET /v1/community/<fingerprint>` — the aggregate.
- A per-installation key; retention.

`sloth-comintd`'s v1 surface is loopback by default, under the same
allow-list discipline slothweb uses (#184 §2 C10). `sloth-dash` uses it
when present and its compiled snapshot when not, and says which through
`intel_source`.

The refusal is tested, not documented: a test feeds a credential, a
username and a raw SSID to each endpoint and asserts refusal (#184 §3
Stage 6, §6). A community verdict is shown beside the local
recommendation **labelled as such** — it is someone else's judgement, not
this sensor's.

## Consequences

Accepted:

- Sharing is off on every installation until an operator turns it on, so
  the common intelligence database is empty by default and grows slowly.
  That is the intended trade: a passive tool that quietly starts
  transmitting is the failure `MISSION.md` §2 exists to prevent.
- A fingerprint hash is still an identifier. Keying verdicts by
  fingerprint rather than by address is what keeps a shared verdict from
  being a shared location history; it does not make the hash
  meaningless, and the retention rule is what bounds it.
- The allow-list has to be applied at ingest on the server, not only at
  egress on the sensor, because `sloth-comintd` will accept from clients
  it does not control.
- Promoting a community-confirmed fingerprint into the known-stack table
  requires provenance travelling with it, or it reintroduces the
  unsourced row that plan #145's second ruling forbids and that
  [attack-hardware-fingerprints](../attack-hardware-fingerprints.md)
  records as the reason #151 is still open.
- The OUI-gap report — an OUI no pack knows, seen by several
  installations, becoming a pack issue automatically — is the first thing
  sharing buys (#184 §3 Stage 6 item 4).

## Related pages

- [ADR index](README.md)
- [ADR 0003 — intelligence is files](0003-intelligence-is-files.md) — what sharing feeds.
- [ADR 0005 — no runtime dependency](0005-no-runtime-dependency.md) — why a missing comint is not a failure.
- [Data socket exposure](../data-socket-exposure.md)
- [Attack-hardware fingerprints](../attack-hardware-fingerprints.md)
