# Probe  `[7]`

802.11 probe-request sniffer — devices looking for networks to join.

## Protocol

Before associating to a known SSID, 802.11 clients broadcast probe
requests asking "is `<SSID>` here?". This leaks:

- The device's MAC (unless randomised — see below).
- A list of SSIDs the device remembers (its "PNL", preferred network
  list).
- Signal strength → rough distance.

Modern OSes (iOS, Android 8+, macOS) randomise the probing MAC for
unassociated traffic, but the SSID list itself is still leaked
verbatim.

## What sloth captures

Per client: MAC, last probed SSID, signal (dBm), channel, last-seen
timestamp, frame count (lifetime — it says nothing about rate), and the
probe-flood window below.

## View

```
 ── Probe clients ──────────────────────────────────────────────
 MAC                SSID            sig
 de:ad:be:ef:00:01  Starbucks       -55     ← someone here visits Starbucks
 de:ad:be:ef:00:02  HomeNetwork     -42     ← strong signal — very close
 aa:bb:cc:dd:ee:ff  (any)           -78     ← broadcast probe (no specific SSID)
 aa:bb:cc:dd:ee:00  CONF-2019       -60     ← old conference; "data exfil"
```

## What's normal

- Many devices in radio range, each probing a few SSIDs.
- Randomised MACs (locally-administered bit set on the first byte —
  e.g. `02:`, `06:`, `0a:`, `0e:`) for devices not currently associated.
- Broadcast probes (`(any)` SSID) — devices that scan first, ask later.

## What's suspicious

- **PNL containing internal/sensitive SSIDs** in a public space —
  `ACME-CORP-WIFI` showing up at a café reveals that one of ACME's
  employees was here recently (or still is).
- **Same MAC probing for 20+ distinct SSIDs** — device tracking,
  "war-walking" reconnaissance, or sloppy auto-connect lists.
- **Active probes from a stationary "device"** that never associates
  — could be a Wi-Fi
  [Pineapple](https://shop.hak5.org/products/wifi-pineapple) or
  similar pen-test gear collecting PNLs.
- **Constant unchanged MAC** in an area where everyone else's
  randomises — old device, or someone deliberately not randomising
  (uncommon).
- **Probe flood** → `PROBE_FLOOD` (LOW). See below.

## Probe-request flood

`PROBE_FLOOD` fires for one transmitter address that sends **at least
30 probe requests inside some 5-second sliding window**
(`PROBE_FLOOD_FRAMES`, `PROBE_FLOOD_WIN_SECS`) — a rate of ≥ 6/s held
across the whole window. The window is half-open, `(t − 5 s, t]`:
30 requests whose first and last are 4.999 s apart fire, 5.000 s apart
do not.

- **It is a rate, not a total.** 30 probes over 300 s do not fire;
  30 over 3 s do. Until #88 the rule gated on the lifetime
  `frame_count ≥ 30` and `last_seen − first_seen ≥ 5 s` and never
  compared the rate it computed, so both fired alike — and a burst
  shorter than 5 s could never fire at all. A long slow history also
  no longer dilutes a later burst.
- The rule re-checks the rate on the window's own evidence
  (`burst_frames / 5 s ≥ 6/s`, span under 5 s) rather than trusting
  the flag alone. The detail reports the burst actually seen:
  `02:12:34:56:78:9a sent 30 probes in 3.0s (10.0/s, >= 6/s over 5s)`.
- **Durations run on the monotonic clock**; a wall-clock step inside a
  burst changes nothing. Wall time is kept as evidence (`flood_last`).
- **Flood status decays by itself** `PROBE_FLOOD_HOLD_SECS` = 10 s after
  the threshold was last met, with no further frame needed.
- JSONL `probe_client` carries `flood`, `flood_last`, `burst_frames`,
  `burst_span_ms`.

Why 6/s: a client scans in bursts — a few requests per channel per
scan, then a pause — and a monitor parked on one channel hears only its
share of each scan. Six per second from one address, sustained for five
seconds on one channel, is scanning tools (`hcxdumptool`, `wifite`),
PNL-walking, or a stuck client looping.

What it is not: evidence of *who* is probing. The source address is
what the frame claims — randomised on modern phones, and trivially
set by a tool — so the alert names an address, not a device.

## Operational tips

- Set the probe-capture interface from `[1] Interfaces` (`m` key).
  Requires a card / driver that supports monitor mode (tested with
  rtl88XXau on Linux).
- The PNL is gold for social engineering. Treat it as sensitive.

## Presence classification (#53)

The **Presence** column separates emitters that were *present* from
emitters that were *passing*. A surveyor working near a road hears a few
hundred client MACs in an afternoon and only a fraction belong to the
site; without this they are indistinguishable.

| Value | Meaning |
|---|---|
| `resident` | present a long time (≥ 15 min), no transit shape |
| `visitor`  | present for minutes (≥ 2 min) |
| `passing`  | approached, peaked and receded — moved through RF range |
| `?`        | too little evidence to say |

The primitive is **trajectory shape**, not dwell. Dwell alone is
confounded by channel hopping: a resident device the radio happened to
hear once looks brief. A vehicle leaves an unmistakable signature.

```
  passing                       arrived and stayed
   -40      ▁▃▅█▅▃▁              -40        ▁▃▅███████████
   -80  ▁▁▁▁       ▁▁▁▁          -80  ▁▁▁▁▁▁
        └── ~20 s ──┘                 └──── minutes ────┘
```

Both the rise into the peak and the fall out of it must reach 8 dB. A
one-sided move is not a pass — a rise with no fall is a device waking,
a fall with no rise is one sleeping, and neither moved.

**The asymmetry is deliberate.** Dwell alone may promote an emitter to
`visitor` or `resident`, because "was here a while" is a weak claim a
long observation span already supports. Calling something `passing`
asserts that it *moved*, which is the strong claim, so it requires
trajectory evidence. A device heard once is `?`, never `passing` — the
column is meant to be defensible in front of a client.

Backed by `rssi_ring_t` on `probe_client_t` (16 samples / 60 s), pushed
from `record_probe()`. The classifier is pure and lives in
`src/presence.c`; it is unit-tested against hand-built trajectories
rather than captured ones.

The class is persisted to `probe_clients.presence` in the [[sqlite-schema]]
sink at its strongest-ever verdict, so a pass survives in the record
after the trajectory ages out of the live ring.

**Not yet**: counting *recurring* transients — the same device passing
three times in two hours, the signature of someone circling. That needs
episode tracking on top of this and is tracked as S3.2 in
`docs/personas/wifi-surveyor.md`.

## See also

- Capture path: [`src/capture/probe.c`](../../src/capture/probe.c).
- See [`beacons.md`](beacons.md) for the complementary AP-side view.
- Background on PNL leakage:
  [SSID Stripping](https://datatracker.ietf.org/doc/draft-mraihi-mac-randomization/).
