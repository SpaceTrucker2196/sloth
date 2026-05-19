# Deauth  `[a]`

802.11 deauthentication / disassociation frames, plus per-target flood
detection.

## Protocol

Deauth (subtype 12) and Disassoc (subtype 10) are 802.11 management
frames sent **unencrypted** (until 802.11w / Protected Management
Frames is in use). They tell a station "you are no longer associated
to this AP" — useful for legitimate roaming, devastating as an attack.

Anyone within radio range can spoof a deauth frame claiming to be the
AP. The target drops its connection and tries to reconnect, exposing
the WPA handshake to capture and offline brute-force.

## What sloth captures

Per event: src MAC, dst MAC, BSSID, 802.11 reason code, frame count,
flood flag. Captured via the monitor-mode pcap (requires a wireless
adapter that can do `ARPHRD_IEEE80211_RADIOTAP` and a driver that
supports monitor mode).

## View

```
 ── Deauth ─────────────────────────────────────────────────────
 target            reason  flood
 aa:bb:cc:dd:ee:ff    7    FLOOD     ← red — sustained attack
 11:22:33:44:55:66    3
 ff:ff:ff:ff:ff:ff    7    FLOOD     ← broadcast deauth = "kill everyone"
```

`FLOOD` is set when ≥5 frames hit the same target in a 5 s window.

## What's normal

- A handful per day during legitimate roaming, channel switches, or
  client wake-ups. Reason codes 4 (inactivity), 6 (class-2 frame from
  unauth), and 8 (assoc leaving) are routine.

## What's suspicious

- **Sustained flood** to one target → `ALERT_DEAUTH_FLOOD` fires WARN.
  This is the classic
  [aireplay-ng deauth](https://www.aircrack-ng.org/doku.php?id=deauthentication)
  signature — used to force handshake re-capture (WPA1/WPA2 PSK
  cracking precursor) or to knock a target offline (e.g., a security
  camera).
- **Broadcast deauth** (`ff:ff:ff:ff:ff:ff` target): also called
  "kill 'em all". Affects every client on the BSSID at once. Usually
  malicious.
- **Reason code 1 ("unspecified")** in bulk: lazy attacker.
- **Repeated targeting of the same MAC** over hours — someone is
  actively trying to keep a specific device off the network. Surface
  it: check `[8] ARP` to identify whose MAC it is.

## Defences

- Enable 802.11w (Protected Management Frames) on your AP. Modern
  WPA3 networks have this by default.
- WPA3 also kills the WPA-handshake-capture angle.

## See also

- Parser: [`src/deauth_snoop.c`](../../src/deauth_snoop.c).
- Reason code reference:
  [IEEE 802.11 Status / Reason codes](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fsdk_nrf5_v17.0.2%2Fgroup__wlan__defines__reason__codes.html).
