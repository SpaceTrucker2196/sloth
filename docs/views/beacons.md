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

When the AP advertises a **QBSS Load** element (802.11e, tag 11), sloth
also records its self-reported occupancy: associated **station count**
and **channel utilisation** (0–255, a fraction of 255 — e.g. 128 ≈ 50 %
busy). This is a free congestion signal — no airtime maths, just what
the AP itself is broadcasting — and appears as `qbss_stations` /
`qbss_chan_util` in the `beacon` JSONL record (omitted when the IE is
absent, so consumers can tell "no data" from a genuine zero).

## View

```
 SSID                    BSSID               Sig   Ch  Enc    Pairwise   posture   AKM         WPS  Vendor     PHY       Last
 home_5g                 c8:0a:a9:1b:2c:3d   -42   36  WPA3   CCMP       REQ       SAE         -    Apple      Wi-Fi 6   2s
 corp-wifi               00:11:22:33:44:55   -55    6  WPA3   CCMP       WPA2+3    SAE,PSK     -    Cisco      Wi-Fi 6   1s
 legacy-net              de:ad:be:ef:00:01   -60   11  WPA2   CCMP       WPA1+RSN  PSK         ON   ?          Wi-Fi 4   4s
 (hidden)                d8:5d:4c:5e:6f:70   -71    6  WPA2   CCMP       cap       PSK         -    ?          Wi-Fi 5   9s
```

SSID names are coloured via the same hash-palette as Probe — same SSID
gets the same colour wherever it appears.

### The `posture` column

This column used to show MFP alone (`REQ` / `cap` / `-`). It still does
when the AP's posture is clean — but when the AP advertises a **weaker
lane beside its primary one** the column names that instead, heat-
coloured, because that is the finding (#62):

| Shown | Meaning |
|---|---|
| `WPA1+RSN` | a legacy WPA1 IE beside the RSN IE — TKIP still on offer |
| `WPA2+3` | PSK and SAE both in the AKM list — WPA3 transition mode |
| `OWE-tr` | an OWE BSS with a paired open companion BSS |
| `MFP-opt` | SAE with MFP capable-but-not-required — the Dragonblood primitive |
| `REQ` / `cap` / `-` | no downgrade lane; the MFP state as before |

Worst-first when several apply — the column has room for one, and an AP
still offering TKIP is a bigger problem than one whose MFP is merely
optional. The `[v]` Alerts view carries one `WPA_DOWNGRADE` alert per
lane, so nothing is lost by the column showing only the worst.

**None of these is an attack.** Each is a configuration the AP is
broadcasting about itself, and each is the prerequisite an attacker
needs: CVE-2023-52424 (SSID Confusion) and the Dragonblood family both
depend on the AP having offered the weak lane in the first place.

## What's normal

- Stable neighbour APs with consistent signal +/- a few dB.
- Beacon interval of 100 ms (= 102.4 ms, the standard).
- WPA2 / WPA3 encryption.

## What's suspicious

- **A heat-coloured `posture` cell.** See the table above. A migration
  window is a legitimate reason to run WPA3 transition mode; a posture
  that has been there for weeks is a compliance finding. sloth reports
  the live state — "this AP is *currently* offering a downgrade path" —
  and leaves the duration judgement to the operator, since the AP table
  does not persist across runs unless `--db` is on.

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
