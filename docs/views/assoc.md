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
- **What the client asked for** (#60) — the AKM suites, cipher and MFP
  level from its association *request*, paired with the grant by
  `(BSSID, STA)`

Storage is capped at `MAX_ASSOC_ENTRIES = 128`, LRU-evicted by
`last_seen`.

## View

```
 Associated clients: 4   [up/dn] navigate  [c] clear

 BSSID              SSID              STA                vendor          ch  rnd   sig  asked     via          age
 -----------------  ----------------  -----------------  --------------  --  ---   ----  --------  -----------  ----
 c8:0a:a9:1b:2c:3d  HomeWiFi          a0:b1:c2:d3:e4:f5  Apple           6   -    -52  SAE       EAPOL        5s
 c8:0a:a9:1b:2c:3d  HomeWiFi          b8:27:eb:00:11:22  Raspberry Pi    6   -    -64  PSK       AssocResp    20s
 d8:5d:4c:5e:6f:70  CoffeeShop        02:11:22:33:44:55  (random)        11  Y    -71  PSK       AssocResp    1m  ∆ SAE->PSK
 00:11:22:33:44:55  ACME-Guest        de:ad:be:ef:00:01  Cisco           1   -    -68  802.1X    ReassocResp  3m
```

### The `asked` column, and why there is no `granted` beside it

`asked` is the AKM lane the client requested: `SAE`, `PSK`, `802.1X`,
`OWE`, `open`, or `SAE+PSK` for a client offering both. Roaming
variants collapse into their family — `FT-SAE` and `SAE-EXT-KEY` both
read `SAE` — because the question the column answers is which lane the
client is on.

There is deliberately **no "granted AKM" column**, and that is a fact
about the protocol rather than a gap. An association *response* carries
no RSN Element outside the FT and OWE cases (IEEE 802.11-2020
§9.3.3.7): the AP does not restate the cipher suite when it accepts.
The client's request is the only place its choice appears on the air.

### The `∆` marker

A downgrade rides as a trailing marker rather than a permanent column,
because it is the exception and a `prev_akm` column would read `-` on
almost every row. It shows **what was given up**:

| Marker | Meaning |
|---|---|
| `∆ SAE->PSK` | the client re-requested with a weaker AKM |
| `∆ MFP2->0` | management-frame protection went from required to off |
| `∆ cipher` | a weaker pairwise cipher appeared (TKIP where CCMP was) |

The delta is measured **across successive requests from the same
client**, not between request and response — see above for why the
response cannot supply the other half. So a downgrade here reads: *this
client asked for something, did not get on, and came back asking for
less*. That is what being moved onto a weaker lane actually looks like
on the air, and it is the runtime signature of
[CVE-2023-52424](https://nvd.nist.gov/vuln/detail/CVE-2023-52424)
(SSID Confusion) from the client side. The AP-side prerequisite is
`ALERT_TYPE_SSID_CONFUSION`.

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

- **A `∆` marker on any row.** A client that gave up SAE for PSK, or
  MFP-required for MFP-off, did not choose to. Check `[b]` for whether
  the BSSID is advertising a transition-mode posture that offers the
  downgrade lane, and `[v]` for a matching `SSID_CONFUSION`.

- **A flood of assoc-responses from one BSSID with status=0 to many
  random STA MACs** — could be a rogue AP / KARMA box answering to
  every probe (compare [PNL](pnl.md) with the BSSID's traffic).
- **A burned-in STA MAC that suddenly disappears (deauth) and
  reappears (assoc) repeatedly** — deauth + rejoin loop, typically
  someone trying to harvest [EAPOL](eapol.md) handshakes.

## Export

- **JSONL**: `assoc` records (the grant) and `wifi_assoc_req` records
  (the ask), paired by `bssid` + `sta_mac`. `downgrade_flags` uses the
  `ASSOC_DG_*` bits; `akm_bits` / `prev_akm_bits` are 00-0F-AC suite-type
  bitmaps.
- **SQLite**: `assocs` and `assoc_reqs`. `downgrade_flags`
  OR-accumulates — a client recovering to strong parameters does not
  erase having been moved onto weak ones.
- **`--report`**: an *Association requests* section listing every
  downgrade with what was lost.

## See also

- [eapol.md](eapol.md) — handshakes that promote rows to `via=EAPOL`
- [beacons.md](beacons.md) — the BSSID's SSID + RSN inventory
- [deauth.md](deauth.md) — events that tear down rows in this view
- [pnl.md](pnl.md) — what each STA's prior PNL says about it
