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

## Channel width (#66)

The `Ch` column shows the primary channel and the **operating width**:
`36/80` is a very different amount of spectrum from `36`. `80+`
means 80+80 MHz non-contiguous.

Until the operation IEs were decoded sloth treated every AP as 20 MHz,
which makes any airtime or occupancy answer wrong by up to a factor of
sixteen. Width comes from HT Operation (tag 61), VHT Operation (tag
192), HE Operation (255 ext 36) and EHT Operation (255 ext 106) — the
*operation* IEs, which say what the BSS is doing, as opposed to the
*capability* IEs, which say what the radio could do.

Two distinctions the parser is careful about, because both are easy to
get wrong in the direction that overstates:

- **40 MHz needs both** the HT width bit *and* a non-zero secondary
  channel offset. The width bit alone means "may use more than 20".
- **160 MHz and 80+80 are different.** Two 80 MHz segments whose centres
  are 8 apart are one contiguous 160; further apart is genuinely
  non-contiguous. Reporting the second as the first overstates
  contiguous spectrum by a factor of two.

A blank width means no operation IE was decoded — which is not the same
as 20 MHz, and the JSONL `operating_width` is `0` rather than `20` for
exactly that reason.

### The durable 6 GHz channel fix

The beacon channel used to come from the DS Parameter Set (tag 3),
which **much 6 GHz and HE gear omits entirely**. HE Operation's 6 GHz
Operation Info carries the authoritative primary channel, and it now
wins when both are present. The JSONL record carries `channel_source`
so a wrong channel is attributable rather than mysterious.

## Pending channel switches (#63)

When an AP is announcing a **Channel Switch**, the `PHY` cell is
replaced by `CSA>N` — the channel it is moving to — heat-coloured while
the switch is in flight. It is transient and the more urgent fact; the
PHY tier will still be there after the AP has moved.

A legitimate switch is DFS doing its job: the AP heard radar, it has to
leave, and it tells its clients where it is going. The abuse cases are
in `ALERT_TYPE_CSA_ABUSE` — a forged transmitter, several distinct
targets in a minute, or a destination channel that happens to host a
known rogue. Clients honour CSA, which is what makes it a quieter
alternative to a deauth flood, and it works on firmware that ignores
deauth entirely.

## RRM surveys (#61)

A footer line appears when 802.11k **Beacon Requests** have been seen:

```
 RRM surveys: 7 targeted requests in the last 300s, 3 reported back
```

A Beacon Request asks a client to scan and report what it can hear —
BSSIDs, channels, RSSIs. The client obliges, because that is what
802.11k is for. It is also how an AP enumerates the airspace *through
someone else's radio*, from a position its own antenna cannot reach,
and the report that comes back is precisely the input needed to build a
convincing evil twin.

The distinction the footer draws is between **targeted** requests (which
name a specific SSID in a subelement) and broadcast ones (which do not).
Only the first is a signal. `ALERT_TYPE_RRM_SURVEY_ABUSE` fires when the
asker has been heard beaconing *something* but has never advertised the
SSID it is asking about — a legitimate AP asks about its own networks.

The "has been heard beaconing something" half is the `--hop` guard: on a
channel-hopping sensor the AP inventory is a sample, so a BSSID we have
never heard tells us nothing about what it does or does not advertise.

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
