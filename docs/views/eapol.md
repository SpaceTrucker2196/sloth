# EAPOL  `[e]`

Captured EAPOL-Key frames + the 4-way handshake state machine. Two
SIGINT-relevant artefacts come out of every observed (BSSID, STA) pair:
PMKID (modern single-frame crack vector) and the full WPA 4-way
handshake (ANonce + SNonce + MIC).

## Protocol

When a WPA2/WPA3 client (re)associates to an AP, both sides run the
**4-way handshake** to derive the PTK / GTK from the PSK and two
nonces. The four messages are 802.11 data frames carrying an EAPOL-Key
payload (ethertype `0x888E`):

| Msg | Direction | Carries |
|-----|-----------|---------|
| M1  | AP → STA  | ANonce, optional PMKID KDE |
| M2  | STA → AP  | SNonce + MIC + RSN IE |
| M3  | AP → STA  | ANonce again + MIC + GTK KDE (encrypted) |
| M4  | STA → AP  | confirmation + MIC |

Two ways to crack the PSK offline:

- **PMKID** — when the AP advertises a PMKID in M1's Key Data field,
  one frame is enough for offline brute-force (no STA needed). Modern
  AP firmware almost always emits this. `hashcat -m 22000`.
- **4-way handshake** — M1's ANonce + M2's SNonce + M2's MIC are
  sufficient to derive a PMK candidate and verify the MIC against any
  passphrase guess. Same hashcat mode.

## What sloth captures

Per observed EAPOL-Key frame:

- BSSID, STA MAC, SSID (if known), timestamp, signal, channel
- Message number (1-4)
- ANonce / SNonce / MIC fields
- PMKID (if M1 carried one)
- `handshake_complete` set on M2 if its matching M1 was already seen

Per (BSSID, STA) pair the state machine tracks pending M1 → M2 chains;
when both arrive, the M2 event is flagged `handshake_complete=1`.

`--eapol-dir DIR` appends each captured PMKID and full handshake to
`DIR/eapol.22000` in hashcat 22000 mixed format
(`WPA*01*...` for PMKIDs, `WPA*02*...` for 4-way handshakes with MIC
field zeroed per spec).

## View

```
 EAPOL events: 5 (2 PMKID / 1 full handshake)  [up/dn] navigate  [c] clear

 age       msg  BSSID              STA                ch   sig  notes
 --------  ---  -----------------  -----------------  ---  ----  --------------------------------
 12s       M2   c8:0a:a9:1b:2c:3d  a0:b1:c2:d3:e4:f5  6    -52  PMKID + full handshake
 13s       M1   c8:0a:a9:1b:2c:3d  a0:b1:c2:d3:e4:f5  6    -52  PMKID (offline-crackable M1)
 47s       M1   d8:5d:4c:5e:6f:70  ff:ff:ff:ff:ff:ff  11   -71  M1: AP advertised ANonce
 2m        M2   00:11:22:33:44:55  02:aa:bb:cc:dd:ee  1    -64  M2: STA replied (need M1 for cracking)
```

Prize rows (PMKID, complete handshake) render in heat-red so they
stand out.

## What's normal

- Periodic M1/M2 frames whenever a client associates or roams. Most
  clients don't do this often, so steady-state should be quiet.
- M3 / M4 frames in WPA2/3 networks (these aren't independently
  crackable but confirm the handshake completed).

## What's interesting (SIGINT-wise)

- **PMKID-bearing M1** = the AP's PSK is offline-crackable with no
  client interaction required. The bar is very low.
- **Full 4-way handshake** = the PSK is crackable against this exact
  client. Particularly valuable when paired with a captured ESSID +
  the [Beacons](beacons.md) view's WPA3 / MFP fields (some AKM suites
  resist this).
- **A high deauth rate from one BSSID + many M1/M2 captures shortly
  after** = someone is actively running an aireplay-style deauth +
  rejoin loop to harvest handshakes. Check the [Deauth](deauth.md)
  view in parallel.

## What's suspicious (defensive)

- **Repeated M1+M2 captures from many different STAs to one BSSID** —
  legitimate (busy AP with many clients) but also the signature of a
  rogue AP harvesting handshakes from clients that probed for the
  spoofed SSID.

## See also

- [beacons.md](beacons.md) — RSN cipher + MFP status (MFP=req
  prevents deauth-driven re-handshake harvesting)
- [deauth.md](deauth.md) — deauth frames that force re-handshakes
- [pnl.md](pnl.md) — which clients are advertising which SSIDs
- hashcat `-m 22000` documentation
