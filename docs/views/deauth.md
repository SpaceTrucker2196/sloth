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

## BTM steering (802.11v)

Below the deauth table the view lists **BSS Transition Management**
steering — the 802.11v mechanism an AP uses to ask a client to move to
a different BSS.

```
 ── BTM steering (802.11v) ──
 AP                 STA                 Reqs  Force  Timer  Candidate          Last
 aa:bb:cc:dd:ee:30  12:34:56:78:9a:bc      7      4     10  aa:bb:cc:dd:ee:31   3s
 aa:bb:cc:dd:ee:30  12:34:56:78:9a:c1      2      0      0  aa:bb:cc:dd:ee:32  41s
```

- **Reqs** — every BTM Request seen for that AP/client pair.
- **Force** — the subset carrying **Disassociation Imminent**: "you are
  about to be dropped". This is the column that matters. Row heat
  tracks it, not the total, so a chatty AP doing legitimate steering
  does not read as an attack.
- **Timer** — the disassociation timer, in beacon intervals.
- **Candidate** — the first BSSID the AP is pointing the client at,
  with `+n` when more were offered.

**This section is why the view is worth opening with an empty deauth
table.** A BTM Request with Disassociation Imminent moves a client
without a single deauth frame, so `DEAUTH_FLOOD` never sees it and the
table above stays clean while clients are being pushed around.

The attack is documented in
[Ali & Kulkarni (2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823001712):
because 802.11v steering carries no RSSI proximity constraint, an
attacker can force a roam onto their own AP from further away than a
deauth-and-lure would allow, and against clients whose firmware ignores
deauth entirely. See [BTM abuse](../wiki/btm-abuse.md) for the full
detection write-up.

## Defences


- Enable 802.11w (Protected Management Frames) on your AP. Modern
  WPA3 networks have this by default.
- WPA3 also kills the WPA-handshake-capture angle.

- 802.11w does **not** stop BTM abuse the way it stops deauth spoofing.
  Protected Management Frames authenticate the Action frame, so a PMF
  network rejects a forged BTM Request from an outsider — but a rogue
  AP a client has genuinely associated to can still steer it, and
  clients on transition-mode or PMF-optional BSSs are unprotected.
  Check the `MFP` posture in `[b]`.

## See also

- Parsers: [`src/deauth_snoop.c`](../../src/deauth_snoop.c),
  [`src/action_snoop.c`](../../src/action_snoop.c) (BTM).
- Reason code reference:
  [IEEE 802.11 Status / Reason codes](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fsdk_nrf5_v17.0.2%2Fgroup__wlan__defines__reason__codes.html).
