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

## Security posture columns (roadmap B3b)

The list carries **AKM/MFP** and **PHY** alongside `Enc`:

| Column | Meaning |
|---|---|
| `Enc` | WPA3 / WPA2 / WPA / WEP / Open |
| `AKM/MFP` | key-management suite, with an MFP suffix |
| `PHY` | Wi-Fi 7 / 6 / 5 / 4 / legacy |

The MFP suffix is the field an assessor scans this column for:

- `+MFP` — management-frame protection **required**
- `~mfp` — **capable but not required**, rendered hot. This is the
  transition-mode posture a downgrade attack exploits, and the
  distinction from "required" is the finding — burying it in a detail
  pane would hide it.
- no suffix — MFP off

WPS-enabled APs render their PHY cell hot, since WPS remains a
practical attack surface on SOHO gear.

### Why this only appeared recently

sloth had **two** Wi-Fi code paths of very different depth: the
monitor-mode engine (`src/capture/probe.c` + `src/beacon_snoop.c`) with
a full RSN/WPS/RNR/11k/QBSS/vendor IE parser, and this view's
managed-mode nl80211 scan path (`src/platform/linux_wifi.c`) whose
parser yielded an SSID plus three booleans. **The same AP reported far
less detail depending on which interface mode observed it** — a
correctness inconsistency rather than a missing feature.

`beacon_parse_ies()` is now the single source of truth both paths call.
The seam is the IE blob rather than a frame, because that is what
nl80211 hands over (`NL80211_BSS_INFORMATION_ELEMENTS`).

> **Two spellings survive on purpose.** The nl80211 path reports a
> hidden SSID as `<hidden>` and open as `Open`, where the beacon parser
> uses `""` and `OPEN`. Those strings reach the JSONL `wifi_ap` record,
> so unifying them is a wire-format change and belongs in a deliberate
> schema decision rather than arriving as a side effect of sharing a
> parser. The mapping happens at the call site in `linux_wifi.c`.

802.11k neighbour reports are deliberately **not** mirrored into
`wifi_ap_t`: they are an AP-topology record belonging with the monitor
table's `beacon_ap_t`, and copying the array into every scan result
would cost ~7 KB of state for a view with nowhere to show it.

## See also

- Backend: [`src/platform/linux_wifi.c`](../../src/platform/linux_wifi.c)
  (nl80211 + netlink).
- For raw beacon capture (much more detail): [`beacons.md`](beacons.md).
- For unassociated devices in the area: [`probe.md`](probe.md).
