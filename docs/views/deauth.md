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

Two tables, both fed from the monitor-mode pcap (requires a wireless
adapter that can do `ARPHRD_IEEE80211_RADIOTAP` and a driver that
supports monitor mode).

**Observation rows** — one per `(BSSID, transmitter, receiver,
subtype)`: Address 3, Address 2, Address 1, deauth vs disassoc. Per row:
the latest reason code *and whether it was decoded*, frames observed,
of which retransmissions / protected / truncated, the latest Frame
Control flags, first/last seen, and a per-row flood flag. Deauth and
disassoc between the same addresses are separate rows, and the same
addresses under two BSSIDs are two rows — neither overwrites the
other's BSSID (#88; before that rows were keyed `(src, dst)` and the
BSSID was whatever the last frame said).

**Victim aggregates** — one per `(BSSID, victim)`: every distinct
frame acting on one station inside one BSS, whichever transmitter
address it claims, in either direction, deauth or disassoc. The victim
is Address 1, except that a frame *to* the AP (Address 1 = BSSID) acts
on its transmitter — "this station is leaving", which is exactly what a
spoofing tool forges. A broadcast Address 1 stays broadcast: it names
every station of the BSS. Spoofing tools alternate AP→STA and STA→AP,
so a per-row count sees half the attack; the aggregate sees all of it.
This is what `DEAUTH_FLOOD` fires on.

### Reason codes

The Reason Code (IEEE 802.11-2020 9.4.1.7) is decoded only from a
cleartext body:

- **Protected Frame bit set** (802.11w / PMF, individually addressed):
  the body is CCMP/GCMP ciphertext and the two octets after the header
  are packet-number bytes. sloth does **not** decode them — the column
  shows `encrypted`, JSONL carries `reason_valid: 0`, the DB stores
  `NULL`. (A parser that ignored the bit reported plausible-looking
  codes such as 7, "Class 3 frame", from the PN.)
- **Group-addressed under PMF** (BIP, 12.5.4): not encrypted — the
  reason is in clear, followed by an MMIE — and it is decoded.
- **Header only / one body octet**: counted as observed, flagged
  truncated, reason `none` — not "reason 0", which is a real code.
- **+HTC** (Order bit set in a management frame): the 4-octet HT
  Control field is skipped before reading the body.

### Flood: the window

`FLOOD` means **at least 5 distinct frames inside some 5-second sliding
window** (`DEAUTH_FLOOD_THRESH`, `DEAUTH_FLOOD_WIN_SECS`). The window is
half-open, `(t − 5 s, t]`: five frames whose first and last are
4.999 s apart flood, 5.000 s apart do not. It is implemented as the
last K frame times per row / aggregate, so frames at t = 0, 4, 8, 12,
16 s never flood — no 5 s interval holds more than two of them. (Until
#88 the counter reset only when the gap since the *previous* frame
exceeded 5 s, so that sequence did flood.)

- **Retransmissions do not count.** A frame with the Retry bit set and
  the same sequence number as the previous frame in its row is the same
  MPDU sent again; the receiver's duplicate filter discards it
  (10.3.2.14), so it cannot add impact. It is still counted as observed
  (`Count`, JSONL `retries`).
- **Durations run on the monotonic clock.** An NTP step or a manual
  date change neither creates a flood, breaks one up, nor ages a live
  row out. Wall-clock time is evidence only (first/last seen,
  `flood_last`).
- **Flood status decays by itself.** It stays set for
  `DEAUTH_FLOOD_HOLD_SECS` = 10 s after the threshold was last met and
  then clears, whether or not another frame arrives. Ten seconds is
  longer than the window so a 1 s poll cannot miss a short burst.
  `flood_last` keeps when it last happened; the SQLite `flood` column
  latches (an episode that flooded once stays marked).
- Rows and aggregates age out after 60 s of monotonic idle time.

## View

```
 Deauth/Disassoc events: 3  [up/dn] navigate  [c] clear  iface: alfa0
 !! DEAUTH FLOOD OBSERVED -- 12:34:56:78:9a:bc in aa:bb:cc:dd:ee:30: 14 frames, peak 9/5s
    sender addresses unverified; disruption not confirmed
 Src                Dst                BSSID              Type      Reason         Count  Last
 aa:bb:cc:dd:ee:30  12:34:56:78:9a:bc  aa:bb:cc:dd:ee:30  DEAUTH    Class3-frame       7  0s
 12:34:56:78:9a:bc  aa:bb:cc:dd:ee:30  aa:bb:cc:dd:ee:30  DEAUTH    Leaving            7  0s
 aa:bb:cc:dd:ee:40  66:55:44:33:22:11  aa:bb:cc:dd:ee:40  DEAUTH    encrypted          1  12s
```

The banner comes from the victim aggregates. In the example neither
row reached five frames in a window on its own — the two directions
together did. `[FLOOD]` on a row means that one stream flooded by
itself.

### What this is evidence of — and what it is not

A flood is an **observed-frame count**. Two things it does not
establish:

- **Who sent the frames.** Address 2 is whatever the frame claims. A
  deauth "from the AP" is exactly what a spoofing tool transmits; the
  view shows the claimed address and nothing more.
- **Whether anyone was disconnected.** A passive receiver sees frames,
  not their effect. A PMF-associated station drops unprotected
  deauths; a station may ignore them in firmware; the frames may not
  have reached it at all. The alert says `sender unverified, disruption
  not confirmed` for that reason. Look for the effect elsewhere — the
  client re-associating (`[b]`/assoc table), EAPOL handshakes restarting,
  or `SA_QUERY_FLOOD` (the AP's own reaction to spoofed disassociations
  on a PMF network).

## What's normal

- A handful per day during legitimate roaming, channel switches, or
  client wake-ups. Reason codes 4 (inactivity), 6 (class-2 frame from
  unauth), and 8 (assoc leaving) are routine.
- A roaming station can put several frames on the air in under a
  second — its own "leaving" deauth plus retries, then the old AP's
  Class-3 deauths. Retries are not distinct frames, and that sequence
  stays below the threshold.

## What's suspicious

- **Flood on one victim** → `DEAUTH_FLOOD` fires WARN (CRIT when the
  BSSID is `--my-bssid`). This is the classic
  [aireplay-ng deauth](https://www.aircrack-ng.org/doku.php?id=deauthentication)
  signature — used to force handshake re-capture (WPA1/WPA2 PSK
  cracking precursor) or to knock a target offline (e.g., a security
  camera). One alert per `(victim, BSSID)`, key
  `deauth:<victim>@<bssid>`.
- **Broadcast deauth** (`ff:ff:ff:ff:ff:ff` victim): also called
  "kill 'em all". Addressed to every client on the BSSID at once.
  Usually malicious. Two APs' broadcast deauths are two aggregates and
  two alerts, not one.
- **Floods that only appear in the aggregate** (rows below threshold,
  banner set): frames alternating direction or deauth/disassoc — the
  shape spoofing tools produce, not the shape of a real AP.
- **Reason code 1 ("unspecified")** in bulk: lazy attacker.
- **Repeated targeting of the same MAC** over hours — someone is
  actively trying to keep a specific device off the network. Surface
  it: check `[8] ARP` to identify whose MAC it is.
- **Unprotected deauths at a station that negotiated PMF**: once PMF
  is in force the real AP protects them, so these deserve suspicion —
  and the station is also likely to discard them. Both halves matter.

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
- Window: [`src/flood_window.c`](../../src/flood_window.c) — shared with
  the probe-request flood ([`probe.md`](probe.md)).
- Tests: [`tests/test_deauth_snoop.c`](../../tests/test_deauth_snoop.c) —
  hand-built frames per IEEE 802.11-2020 on an injected clock (#88).
- Reason code reference:
  [IEEE 802.11 Status / Reason codes](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fsdk_nrf5_v17.0.2%2Fgroup__wlan__defines__reason__codes.html).
