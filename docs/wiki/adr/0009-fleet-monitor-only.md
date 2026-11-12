---
title: Fleet sharing carries monitor data only and names its host
date: 2026-11-12
status: Accepted
authority: owner hard rule of 2026-11-12, and the owner's clarification of the same day; supersedes the "What travels" clause of ADR 0008
---

# ADR 0009 — Fleet sharing carries monitor data only and names its host

## Context

[ADR 0008](0008-own-fleet.md) (2026-11-10) let the owner's own sensors
share "at full fidelity": devices, APs and SSIDs, probe lists, alert
summaries, triage verdicts and, from #192 I2-I4, each site's own networks
(`own_net`). Full fidelity carried more than what the monitor radio
heard. A `devices` row is a synthesis of every source sloth has, so the
export sent hosts known only from ARP and DHCP on the sensor's own LAN,
alerts of the IP capture (DNS, HTTP, ARP, DHCP, flows), and first and
last seen times the ARP table had moved.

The owner's rule, verbatim (2026-11-12):

> when sloth shares data include the local host name and also only share
> passively monitored data, do not share information on the local wifi
> network the client is connected to via authenticated wifi. only share
> monitor data by a hard rule in the agent instructions. local network
> data should only be stored on local clients on the local network.

The first implementation (`share_rule: "monitor_only"`) read "the local
wifi network" by subject: it withheld the joined network whole, its APs
and its stations as the monitor radio heard them included, the
operator's `--my-ssid` / `--my-bssid` and the host's own radios. Asked
the same day whether the joined network's APs and stations heard over
the air may travel, the owner answered, verbatim:

> yes anything that is thru monitor mode is game

and, on the break with peers of the first cut:

> upgrade together

## Decision

ADR 0008's transport, opt-in, allow lists and pull model stand. Its
"What travels" clause is replaced by this one. The rule is
**provenance, not subject**.

- **Everything sloth heard in monitor mode travels**: the monitor
  radio's beacons, probes, associations and 802.11 findings, the BLE
  receivers, the GNSS receiver and the ADS-B SDR. That includes the
  joined network's APs and its stations as heard over the air (and every
  BSSID that carried a joined SSID), probes for the local SSIDs, and a
  device the LAN also knows, sent with what the radio heard of it alone.
- **Nothing learned through the managed (authenticated) interface or the
  wire travels**: ARP, DHCP, mDNS, NBNS, DNS, the flows, IP addresses,
  host names, the managed card's scan (`wifi_aps`, its status) and
  station dump (`wifi_stas`). A row known only that way never travels.
  Devices are read in the Monitor scope (`web/src/web_scope.h`: no
  address, no name, the radio's sources, the radio's own first and last
  seen and signal); one whose radio sources are empty is withheld, and
  so is one carrying an address or a name.
- **The host's own interfaces and the roster** (`DEV_RISK_SELF`) never
  travel as device rows: sloth's knowledge of them, not the radio's.
- **`own_net` travels** (ident=1): the operator's own networks are
  configuration about what the radio hears, and the cross-site identity
  findings (I2, I3) take them as their baseline.
- **`own_macs` names the monitor radios only** (own=1): an interface in
  monitor mode by its link type (`/sys/class/net/<if>/type` 801-803), with
  an address no other interface holds. The managed card (this host's
  station on the joined network, an identity the network gave it), a
  wired port and an interface whose role cannot be read are withheld.
  Bluetooth controllers are not in `/sys/class/net` and are not named.
- **Alerts by type**, from an explicit allow-list in
  `web/src/web_fleetshare.c`, decided by each rule's capture input: the
  802.11, BLE, ADS-B and GNSS rules travel (`MY_NETWORK_RECON` and
  `UNKNOWN_DEVICE` with them: their frames are the radio's); the IP
  capture's and sloth's own state do not. A new type is withheld until
  classified, and a test fails until it is. An alert travels with no
  address (`ip` always null); a verdict never on an IP address.
- **Every export names its host** (`hostname`, `/api/health`'s) and
  states the rule (`share_rule: "monitor_only/2"`).
- **The importer applies the same rule** to every peer: forbidden kinds
  and members are refused, counted and never stored; `wifi`, `ap` and
  `probe` rows and `own_macs` from an answer that states neither
  `"monitor_only/2"` nor `"monitor_only"` are refused. At start, a store
  no build of the rule purged loses what the rule forbids; every store
  has each peer's clock and backfill reset once (meta
  `fleet.rule.monitor_only.v2`), so peers are asked again from the start
  for what the rule now lets travel. Nothing it allows is deleted.

## Consequences

Accepted:

- A pre-rule importer refuses a post-rule export whole (it does not know
  `hostname` or `share_rule`), and a post-rule importer keeps only the
  allow-listed alerts, verdicts, own networks, BLE, GNSS and aircraft of
  a pre-rule peer. The fleet is upgraded together (the owner's
  "upgrade together").
- A peer of the first cut (`"monitor_only"`) is attested and its rows
  kept; it sends no `own_net`, no `own_macs` and none of the joined
  network until it is upgraded.
- I2 and I3 with a peer as the owner run again on the networks the peer
  names; a peer that names none answers not applicable,
  `no_own_networks_shared`.
- I5 calibration works again from the peers' monitor radios. A host
  whose only radio is its managed card names none and stays
  uncalibrated.
- Fleet rows of a busy sensor are read through the Monitor scope's
  per-device subqueries; a read that runs out of its budget is a cut,
  paged later as before.

## Related pages

- [ADR index](README.md)
- [ADR 0008 — the owner's own fleet](0008-own-fleet.md) — the decision this narrows.
- [ADR 0006 — sharing is opt-in and sanitised](0006-sharing-is-opt-in.md)
- [Fleet](../fleet.md) — what travels and what never does, by kind and member.
