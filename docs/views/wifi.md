# WiFi  `[3]`

Nearby APs from a kernel-driven nl80211 scan, plus the station we're
currently associated to.

## Protocol

This view uses the
[nl80211](https://wireless.wiki.kernel.org/en/developers/Documentation/nl80211)
netlink interface to ask the kernel for its current scan results — no
monitor mode required. (Compare to `[b] Beacons`, which uses pcap +
monitor mode to capture raw beacon frames live.)

## What sloth captures

Per AP: SSID, BSSID (string form), signal (dBm), channel,
encryption (`OPEN` / `WEP` / `WPA` / `WPA2` / `WPA3`), association
status. Plus, for the WiFi station details panel: link rate,
connected duration, RX/TX bytes.

## View

```
 ── WiFi APs ───────────────────────────────────────────────────
 SSID                  BSSID              sig  ch  enc
 home_5g               a4:b1:c2:d3:e4:f5  -42  36  WPA3   ← associated
 home_24               a4:b1:c2:d3:e4:f6  -50  6   WPA3
 neighbor_24           dc:a6:32:11:22:33  -67  11  WPA2
 (hidden)              aa:bb:cc:dd:ee:ff  -71  6   WPA2
```

The associated AP is highlighted; press Enter for the station detail
(signal history sparkline, RX/TX rate, connected uptime).

## What's normal

- A stable set of neighbours.
- Your own AP showing up with `WPA2` or `WPA3` encryption.
- Channel distribution that matches your region's regulatory plan.

## What's suspicious

- **Twin SSID** on a different BSSID (especially with stronger signal
  than the real AP) — evil-twin attack. See [`beacons.md`](beacons.md).
- **OPEN encryption** on a network that should be WPA.
- **WEP** in 2026.
- **WPS PIN enabled** on a target network — vulnerable to
  [Reaver](https://github.com/t6x/reaver-wps-fork-t6x).
- **Vendor mismatch**: your AP's BSSID OUI maps to a vendor that
  doesn't match the box on your shelf.

## See also

- Backend: [`src/platform/linux_wifi.c`](../../src/platform/linux_wifi.c)
  (nl80211 + netlink).
- For raw beacon capture (much more detail): [`beacons.md`](beacons.md).
- For unassociated devices in the area: [`probe.md`](probe.md).
