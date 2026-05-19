# Beacons  `[b]`

Passive 802.11 beacon sniffer — the APs visible to a monitor-mode iface.

## Protocol

APs send beacon frames periodically (typically every 100 ms) to
advertise their SSID, BSSID, supported rates, security, and other
parameters. The frames are unencrypted (the SSID could be "hidden" /
"cloaked" but that's mostly cosmetic — any associated client reveals
it via probe responses).

## What sloth captures

Per AP: SSID, BSSID (6-byte MAC), signal (dBm), channel, encryption
(`OPEN` / `WEP` / `WPA` / `WPA2` / `WPA3`), beacon interval (ms),
last-seen, frame count.

## View

```
 ── Beacons ────────────────────────────────────────────────────
 SSID             sig  ch
 home_5g          -42  36     ← bright green channel → strong + WPA3
 neighbor_24      -67  11
 (hidden)         -71  6      ← cloaked SSID; still visible by BSSID
 FBI-Surveillance -58  1      ← funny name on a coffee-shop AP
```

SSID names are coloured via the same hash-palette as Probe — same SSID
gets the same colour wherever it appears.

## What's normal

- Stable neighbour APs with consistent signal +/- a few dB.
- Beacon interval of 100 ms (= 102.4 ms, the standard).
- WPA2 / WPA3 encryption.

## What's suspicious

- **Twin SSID** with different BSSID and stronger signal than the real
  AP — classic [evil-twin
  attack](https://en.wikipedia.org/wiki/Evil_twin_(wireless_networks)).
  An attacker is impersonating a network the target trusts so they
  associate to it instead.
- **OPEN encryption on a network that should be secured** — see also
  [karma attack](https://en.wikipedia.org/wiki/MAC_filtering#KARMA).
- **WEP** still in use. WEP has been broken since 2001.
- **Excessive beacon interval drift** — usually noise but could
  indicate a rogue AP with cheap/buggy firmware.
- **Hundreds of APs appearing at once** — see
  [mdk3 beacon flood](https://github.com/aircrack-ng/mdk4). Used to
  hide a real attack in noise.
- **Sudden signal jump** (an existing SSID's signal goes from -80 to
  -40) — someone planted a copy of your network closer to the target.

## See also

- Parser: [`src/beacon_snoop.c`](../../src/beacon_snoop.c).
- Probe-side counterpart: [`probe.md`](probe.md).
- Deauth-flood prelude: [`deauth.md`](deauth.md) (attackers often
  knock clients off the real AP to force them onto the evil twin).
