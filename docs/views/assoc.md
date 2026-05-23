# Assoc  `[w]`

Client ↔ AP association inventory. Answers "who is currently on which
WiFi network?" using explicit on-air evidence.

## Protocol

Three kinds of frames confirm that a STA is associated with a given
BSSID:

| Signal              | 802.11 subtype | Strength |
|---------------------|----------------|----------|
| EAPOL 4-way handshake completed | M2 with prior M1 | **Definitive** |
| Association Response, status=0  | subtype 1        | Strong    |
| Reassociation Response, status=0 | subtype 3       | Strong    |

Conversely, disassociation (subtype 10) and deauth (subtype 12) tear
the relationship down.

The view records each (BSSID, STA) pair we've seen confirmation for,
remembering the strongest evidence source (EAPOL > Reassoc ≥ Assoc).
Disassoc / deauth removes the entry.

## What sloth captures

Per (BSSID, STA) pair:

- BSSID + SSID (looked up from the beacon table, backfilled if the
  beacon arrives after the assoc)
- STA MAC, OUI vendor (or `(random)` for locally-administered MACs)
- Source of the confirmation (`EAPOL` / `AssocResp` / `ReassocResp`)
- Channel and last signal-dbm at confirmation time
- First-seen, last-seen, frame count

Storage is capped at `MAX_ASSOC_ENTRIES = 128`, LRU-evicted by
`last_seen`.

## View

```
 Associated clients: 4   [up/dn] navigate  [c] clear

 BSSID              SSID                  STA                vendor          ch  rnd   sig  via          age
 -----------------  --------------------  -----------------  --------------  --  ---   ----  -----------  ----
 c8:0a:a9:1b:2c:3d  HomeWiFi              a0:b1:c2:d3:e4:f5  Apple           6   -    -52  EAPOL        5s
 c8:0a:a9:1b:2c:3d  HomeWiFi              b8:27:eb:00:11:22  Raspberry Pi    6   -    -64  AssocResp    20s
 d8:5d:4c:5e:6f:70  CoffeeShop            02:11:22:33:44:55  (random)        11  Y    -71  AssocResp    1m
 00:11:22:33:44:55  ACME-Guest            de:ad:be:ef:00:01  Cisco           1   -    -68  ReassocResp  3m
```

EAPOL rows are rendered with bright `via=EAPOL` since that's the
definitive evidence.

## What's normal

- One STA per (residential) AP — your own laptop / phone.
- Many STAs on enterprise / coffee shop APs.
- Routine reassoc-response entries as devices roam between APs of the
  same ESSID.

## What's interesting (SIGINT-wise)

- **Same STA appearing on multiple BSSIDs over a short window** —
  roaming, but also indicates a portable device tracking through a
  multi-AP environment. The age column lets you see the order.
- **A randomised STA's association source = EAPOL** — you have a full
  handshake against a known device on a known SSID. Pair with
  [EAPOL](eapol.md).
- **A burned-in STA MAC associated to a non-employer SSID at an
  employer location** — possible BYOD / shadow-IT (defensive) or
  personal-device deanonymisation (offensive).
- **An OS-known vendor (Apple, Samsung, Intel) on a guest network when
  the owner is supposed to be at a desk** — operator location intel.

## What's suspicious (defensive)

- **A flood of assoc-responses from one BSSID with status=0 to many
  random STA MACs** — could be a rogue AP / KARMA box answering to
  every probe (compare [PNL](pnl.md) with the BSSID's traffic).
- **A burned-in STA MAC that suddenly disappears (deauth) and
  reappears (assoc) repeatedly** — deauth + rejoin loop, typically
  someone trying to harvest [EAPOL](eapol.md) handshakes.

## See also

- [eapol.md](eapol.md) — handshakes that promote rows to `via=EAPOL`
- [beacons.md](beacons.md) — the BSSID's SSID + RSN inventory
- [deauth.md](deauth.md) — events that tear down rows in this view
- [pnl.md](pnl.md) — what each STA's prior PNL says about it
