---
source_url: https://docs.oasis-open.org/ws-dd/discovery/1.1/os/wsdd-discovery-1.1-spec-os.html
retrieved: 2026-10-06
topics: [onvif, ws-discovery, camera, iot, discovery, unauthenticated]
alert_kinds: [ALERT_TYPE_CAM_WS_DISCOVERY]
citation: OASIS Standard, "Web Services Dynamic Discovery (WS-Discovery) Version 1.1", 1 July 2009; ONVIF Core Specification, device discovery
---
# WS-Discovery 1.1 + ONVIF Core Specification — passive camera discovery

What `ALERT_TYPE_CAM_WS_DISCOVERY` (#106 slice 1) detects from, and why
the alert is the *presence* of the finding, not an attack.

## The protocol, read off the OASIS standard

WS-Discovery is a multicast discovery protocol: a **Target Service**
(an ONVIF camera, for sloth's purposes) makes itself locatable without
a directory server by speaking SOAP-over-UDP to a well-known multicast
group — `239.255.255.250` for IPv4, `ff02::c` for IPv6, UDP port
**3702**. Four message shapes matter here, all of them things the
Target Service says about *itself*, unprompted or in answer to anyone
who asked:

- **Hello** — sent once, multicast, when the service joins the network.
- **Bye** — a best-effort multicast sent when the service leaves. It
  carries only the service's `EndpointReference`; it does not restate
  `Types`/`Scopes`/`XAddrs`.
- **Probe / ProbeMatches** — a client multicasts a Probe; every
  matching service answers with a unicast `ProbeMatches` naming itself.
- **Resolve / ResolveMatches** — the same shape, for a client that
  already has an endpoint reference and wants its current address.

None of this carries authentication. A Hello is multicast to the
segment unconditionally; a ProbeMatches is sent to whoever's Probe
matched, with no credential check. Retrieved 2026-10-06; several
primary OASIS/ONVIF spec PDFs (onvif.org, docs.oasis-open.org) were not
reachable from this environment (network egress block) and are not
quoted verbatim below — the mechanism above is corroborated by a live
search of a third-party implementation note (EdgeX Foundry's
device-onvif-camera documentation) showing an actual Hello response
with `Types` containing `dn:NetworkVideoTransmitter` and `Scopes`
carrying `onvif://www.onvif.org/...` URIs, consistent with the ONVIF
Core Specification's device-discovery section.

## What `src/onvif_discovery.c` reads from this

Four fields from whichever of Hello / Bye / ProbeMatches / ResolveMatches
sloth overhears on UDP/3702:

- `EndpointReference`/`Address` — `urn:uuid:...`, the stable identity
  a DHCP lease change does not disturb.
- `Types` — a space-separated list of QNames. An ONVIF Network Video
  Transmitter (an IP camera speaking the ONVIF device-management
  profile) names itself here as `(prefix:)NetworkVideoTransmitter`.
- `Scopes` — `onvif://www.onvif.org/...` URIs (hardware, name,
  location, service type).
- `XAddrs` — the device service URL an ONVIF client would call next.

A plain client **Probe** is deliberately not recognised: it carries no
`XAddrs`/`Types` of its own, so it identifies the asker, not a camera.

## The finding, and why it is WARN with no ATT&CK technique

`ALERT_TYPE_CAM_WS_DISCOVERY` fires once per distinct camera (keyed by
its `EndpointReference`, or its IP when a malformed message carries
none) that names itself a `NetworkVideoTransmitter`. What is reported
is that **the camera told the whole segment it exists**, unauthenticated,
in a protocol with no access control of any kind — not that anyone
attacked it. Severity is WARN, the same level `ALERT_TYPE_OPEN_SETUP_AP`
(#80) uses for an analogous victim-side exposure, because a camera that
is supposed to be there (and most are) still produces this same signal:
the operator's job is to recognise their own inventory, not to treat
every row as an incident.

`alert_technique()` returns `""`. ATT&CK T1046 (Network Service
Discovery) is the closest-sounding technique, but it describes an
*adversary enumerating services* — sending probes, reading responses.
sloth sent nothing: the camera volunteered everything in a Hello (or
answered a Probe sloth merely overheard, sent by something else on the
segment — possibly the operator's own management tooling, possibly not).
Naming T1046 would claim an active step that did not happen on sloth's
part. `research/papers/nist-sp1800-36-onboarding.md` (ALERT_TYPE_OPEN_SETUP_AP)
and `ALERT_TYPE_NO_MONITOR_MODE` settled the same shape of question
before this: a cited basis with no ATT&CK ID is still a real basis.

## What this does not say

This is not "an unconfigured camera" and not "a rogue camera" — those
are the questions the issue's later slices (default-credential RTSP/HTTP,
setup-mode mDNS/SSDP signals) narrow toward. A WS-Discovery Hello fires
on every boot of a perfectly legitimate, fully-configured camera, not
only during initial setup; this slice reports *that a camera exists
and is discoverable*, which is the strongest and least ambiguous signal
in the issue precisely because it needs no judgement call about state.
Whether a given camera belongs on the network is the operator's to
decide, same as `OPEN_SETUP_AP` leaves "is this mid-setup or abandoned"
to the operator.

## Related

- `docs/views/alerts.md` — `CAM_WS_DISCOVERY` row.
- `research/papers/nist-sp1800-36-onboarding.md` — the `OPEN_SETUP_AP`
  precedent for an exposure finding with no ATT&CK technique.
