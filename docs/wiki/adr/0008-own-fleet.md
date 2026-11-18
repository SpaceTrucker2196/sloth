---
title: The owner's own sensors share at full fidelity over the tailnet
date: 2026-11-10
status: Accepted
authority: owner rulings of 2026-11-10 on issue #192; amends ADR 0006 for one case
---

# ADR 0008 — The owner's own sensors share at full fidelity over the tailnet

## Context

ADR 0006 governs sharing *across installations*: several operators
feeding one `sloth-comint`, where nothing may carry a raw SSID or a
client MAC, because one operator's sightings would otherwise become
another operator's location history of strangers.

Issue #192 is a different case. One operator runs several sensors (in
2026-11: W9FJC with GPS and Wi-Fi, beta-site with ADS-B), and the inferences that
justify a second location need exactly the fields ADR 0006 removes:

- a client MAC heard at both sites (a device that follows the operator);
- a probe list at one site naming the other site's SSID;
- the other site's own SSID or BSSID broadcast here.

A hashed SSID cannot be matched against the other site's inventory without
handing every peer the inventory, which is the same disclosure by another
route.

## Decision

Between sensors **the same operator runs**, sharing is **full fidelity,
opt-in, peer-authenticated and pull-only** (owner, 2026-11-10):

- **What travels.** Devices, BLE devices, APs and their SSIDs, probe
  lists, alert summaries, triage verdicts, the sensor's position and its
  GNSS summary. **Never** a credential, a username, EAPOL or handshake
  material, or any field `web/src/web_secret.h` already keeps off the
  wire; a test feeds each one to the export and asserts it is refused.
- **Where it runs.** slothweb pulls its peers' slothweb API and keeps the
  result in `slothweb.db`. The sensor and `sloth.db` do not change, and
  slothweb still never writes `sloth.db` (ADR 0005: the sensor runs with
  no network and no peer).
- **Transport.** The operator's WireGuard tailnet. A tailnet address is
  bound to a node key, so a peer's source address is authenticated, and
  each side admits only its listed peers (`--web-allow`, `--peer`). sloth
  adds no cryptography of its own and no TLS library (consistent with the
  #100 ruling on the data socket). A peer URL outside `100.64.0.0/10` is
  refused unless forced, and a forced one is announced.
- **Opt-in and announced** (`MISSION.md` §2). Nothing is pulled until an
  operator names a peer with `--peer`; the export answers only allow-listed
  addresses; both appear in `/api/health` and on stderr. Pulling is an
  optional service over a path the operator configured, never a frame on a
  monitored segment.

ADR 0006 is unchanged for its own case: anything leaving the operator's
own fleet (community sharing, #184 Stage 6) stays sanitised, hashed and
free of SSIDs and client MACs.

## Consequences

Accepted:

- A peer's `slothweb.db` holds the other site's device history. Every
  sensor in the fleet is therefore as sensitive as the most sensitive
  site, and gets the same host protection.
- Trust in a peer's address is trust in the tailnet's key distribution. A
  compromised tailnet node on the allow list reads the export. The
  allow list is per address, never per subnet, for that reason.
- Fleet inferences are slothweb findings, not sloth alerts: they are not
  in `sloth.db`, not in JSONL, and not in a sensor-only deployment.
- Each inference still carries its cited basis, as a detector does.

## Related pages

- [ADR index](README.md)
- [ADR 0005 — no runtime dependency](0005-no-runtime-dependency.md) — why the pull lives in slothweb.
- [ADR 0006 — sharing is opt-in and sanitised](0006-sharing-is-opt-in.md) — the community case this amends for one operator.
- [Location](../location.md) — the sensor positions the inferences use.
- [Data socket exposure](../data-socket-exposure.md)
