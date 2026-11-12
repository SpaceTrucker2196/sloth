---
title: Fleet sharing carries monitor data only and names its host
date: 2026-11-12
status: Accepted
authority: owner hard rule of 2026-11-12; supersedes the "What travels" clause of ADR 0008
---

# ADR 0009 — Fleet sharing carries monitor data only and names its host

## Context

[ADR 0008](0008-own-fleet.md) (2026-11-10) let the owner's own sensors
share "at full fidelity": devices, APs and SSIDs, probe lists, alert
summaries, triage verdicts and, from #192 I2-I4, each site's own networks
(`own_net`). Full fidelity carried more than what the monitor radio
heard. A `devices` row is a synthesis of every source sloth has, so the
export sent hosts known only from ARP and DHCP on the sensor's own LAN,
the AP the sensor's managed card is associated to and the stations on
that network, alerts of the IP capture (DNS, HTTP, ARP, DHCP, flows) and
the operator's own SSIDs and BSSIDs.

The owner's rule, verbatim (2026-11-12):

> when sloth shares data include the local host name and also only share
> passively monitored data, do not share information on the local wifi
> network the client is connected to via authenticated wifi. only share
> monitor data by a hard rule in the agent instructions. local network
> data should only be stored on local clients on the local network.

## Decision

ADR 0008's transport, opt-in, allow lists and pull model stand. Its
"What travels" clause is replaced by this one.

- **Only what was heard passively over the air travels**: by the monitor
  radio, the BLE receivers, the GNSS receiver and the ADS-B SDR. Nothing
  learned through the host's managed or authenticated interface or the
  wire, and nothing of this host's local network. Fail closed: a field
  whose provenance cannot be determined is not sent; when the local
  network cannot be read, no `sloth.db` row and no verdict is sent and
  those kinds say they are cut.
- **The local network** is what `web_fleet_local_build()` reads: the
  managed card's joined networks (`wifi_aps.status >= 0`), its station
  dump (`wifi_stas`), every BSSID that carried a joined SSID, every MAC
  the neighbour table ever held, slothweb's `--my-ssid` / `--my-bssid`,
  this host's own radios and the roster (`DEV_RISK_SELF`). A device, AP,
  probed SSID, alert or verdict that names it is withheld whole.
- **Alerts by type**, from an explicit allow-list in
  `web/src/web_fleetshare.c`, decided by each rule's capture input: the
  802.11, BLE, ADS-B and GNSS rules travel; the IP capture's, the
  operator's-network ones (`MY_NETWORK_RECON`, `UNKNOWN_DEVICE`) and
  sloth's own state do not. A new type is withheld until classified, and
  a test fails until it is. An alert travels with no address.
- **`own_net` never travels**, nor `own_macs`. slothweb's own networks
  stay local: they find what peers send, and they are part of the rule.
- **Every export names its host** (`hostname`, `/api/health`'s) and
  states the rule (`share_rule: "monitor_only"`).
- **The importer applies the same rule** to every peer: forbidden kinds
  and members are refused, counted and never stored; `wifi`, `ap` and
  `probe` rows from an answer that does not state the rule are refused.
  What an earlier build stored is purged once at start.

## Consequences

Accepted:

- A pre-rule importer refuses a post-rule export whole (it does not know
  `hostname` or `share_rule`), and a post-rule importer keeps only the
  allow-listed alerts, verdicts, BLE, GNSS and aircraft of a pre-rule
  peer. A fleet is upgraded together.
- The cross-site identity findings that took a peer's own networks as
  their baseline (I2, I3 with the peer as owner) answer not applicable,
  `no_own_networks_shared`. With this site as the owner they still run
  on what the peers send.
- I5 loses its own-radio calibration from peers: their radios are not
  named. Ranges are reported uncalibrated.
- A device the monitor heard that is also on the LAN is withheld: it is
  a station of the local network (or of the wire), and sloth cannot
  tell which.
- Fleet rows of a busy sensor are read through the Monitor scope's
  per-device subqueries; a read that runs out of its budget is a cut,
  paged later as before.

## Related pages

- [ADR index](README.md)
- [ADR 0008 — the owner's own fleet](0008-own-fleet.md) — the decision this narrows.
- [ADR 0006 — sharing is opt-in and sanitised](0006-sharing-is-opt-in.md)
- [Fleet](../fleet.md) — what travels and what never does, by kind and member.
