# PNL  `[k]`

Per-MAC Preferred Network List aggregation — fingerprints clients by
the set of WiFi networks they've connected to before.

## Protocol

Before associating, an 802.11 client broadcasts probe requests asking
"is `<SSID>` here?" for each entry in its Preferred Network List. The
PNL is the list of every SSID the client has joined since the last
factory reset. It's normally invisible to the user but trivially
observable on the air.

Most operating systems randomise the source MAC of probe requests
(see [Probe](probe.md) for the locally-administered bit), but the SSID
list itself is leaked verbatim. The PNL is therefore an extremely
strong fingerprint — across MAC rotations, the same device probes for
the same set of SSIDs.

## What sloth captures

Per client (keyed on MAC): the unique set of SSIDs probed for, total
probe count, first-seen / last-seen timestamps, randomised-MAC flag.
Wildcard probes (broadcast / empty SSID) are dropped — they leak no
PNL info.

Storage is capped at `MAX_PNL_CLIENTS = 128` clients × 16 SSIDs each;
LRU eviction by `last_seen`.

## View

```
 PNL clients: 6 (3 real / 3 randomized)  [up/dn] navigate  [c] clear

 MAC                vendor          #    age   hits  preferred networks
 -----------------  --------------  ---  ----  ----  ----------------------
 a0:b1:c2:d3:e4:f5  Apple           4    7s    47    HomeWiFi, Starbucks, Acme-Corp, eduroam
 02:11:22:33:44:55  (random)        2    12s   8     HomeWiFi, ACME-Guest
 02:aa:bb:cc:dd:ee  (random)        3    34s   12    Starbucks, eduroam, BA-Lounge
 b8:27:eb:00:11:22  Raspberry Pi    1    1m    3     LabNetwork
```

## What's normal

- Many devices in radio range, each probing 1-10 SSIDs.
- Randomised MACs (locally-administered bit) for unassociated devices.
- Common consumer SSIDs (xfinitywifi, attwifi, eduroam, Starbucks).

## What's interesting (SIGINT-wise)

- **Two MACs with identical PNLs** — almost certainly the same device
  across a MAC rotation. Cross-reference with the [Seqnum](seqnum.md)
  view's correlation table.
- **A randomised MAC probing for a corporate / employer SSID** — links
  the operator of that device to that organisation.
- **PNL containing both a personal SSID and a corporate SSID** — the
  device has been on both networks.
- **PNL containing transient SSIDs** (`SFO-FreeWifi`, `DeltaSky`,
  hotel SSIDs) — travel history.

## What's suspicious

- **Devices probing for SSIDs that don't exist locally** — normal in
  isolation, but if the SSIDs are unusual (`evil-twin-target`) it can
  indicate an attacker's PNL.
- **A device whose PNL grows over time without it associating to
  anything visible** — possibly a Pwnagotchi-style sniffer being moved
  through the environment.

## See also

- [probe.md](probe.md) — raw probe-request feed (the data source)
- [seqnum.md](seqnum.md) — correlate randomised MACs to the same
  physical radio
- [beacons.md](beacons.md) — the AP side of the conversation
- KARMA / mana attacks use PNL to spoof every requested SSID
