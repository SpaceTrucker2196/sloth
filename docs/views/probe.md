# Probe  `[7]`

802.11 probe-request sniffer — devices looking for networks to join.

## Protocol

Before associating to a known SSID, 802.11 clients broadcast probe
requests asking "is `<SSID>` here?". This leaks:

- The device's MAC (unless randomised — see below).
- A list of SSIDs the device remembers (its "PNL", preferred network
  list).
- Signal strength → rough distance.

Modern OSes (iOS, Android 8+, macOS) randomise the probing MAC for
unassociated traffic, but the SSID list itself is still leaked
verbatim.

## What sloth captures

Per client: MAC, last probed SSID, signal (dBm), channel, last-seen
timestamp, frame count.

## View

```
 ── Probe clients ──────────────────────────────────────────────
 MAC                SSID            sig
 de:ad:be:ef:00:01  Starbucks       -55     ← someone here visits Starbucks
 de:ad:be:ef:00:02  HomeNetwork     -42     ← strong signal — very close
 aa:bb:cc:dd:ee:ff  (any)           -78     ← broadcast probe (no specific SSID)
 aa:bb:cc:dd:ee:00  CONF-2019       -60     ← old conference; "data exfil"
```

## What's normal

- Many devices in radio range, each probing a few SSIDs.
- Randomised MACs (locally-administered bit set on the first byte —
  e.g. `02:`, `06:`, `0a:`, `0e:`) for devices not currently associated.
- Broadcast probes (`(any)` SSID) — devices that scan first, ask later.

## What's suspicious

- **PNL containing internal/sensitive SSIDs** in a public space —
  `ACME-CORP-WIFI` showing up at a café reveals that one of ACME's
  employees was here recently (or still is).
- **Same MAC probing for 20+ distinct SSIDs** — device tracking,
  "war-walking" reconnaissance, or sloppy auto-connect lists.
- **Active probes from a stationary "device"** that never associates
  — could be a Wi-Fi
  [Pineapple](https://shop.hak5.org/products/wifi-pineapple) or
  similar pen-test gear collecting PNLs.
- **Constant unchanged MAC** in an area where everyone else's
  randomises — old device, or someone deliberately not randomising
  (uncommon).

## Operational tips

- Set the probe-capture interface from `[1] Interfaces` (`m` key).
  Requires a card / driver that supports monitor mode (tested with
  rtl88XXau on Linux).
- The PNL is gold for social engineering. Treat it as sensitive.

## See also

- Capture path: [`src/capture/probe.c`](../../src/capture/probe.c).
- See [`beacons.md`](beacons.md) for the complementary AP-side view.
- Background on PNL leakage:
  [SSID Stripping](https://datatracker.ietf.org/doc/draft-mraihi-mac-randomization/).
