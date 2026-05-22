# Seqnum  `[j]`

Sequence-number-based MAC-randomisation deanonymisation. Pairs up
"different" MACs that are really the same physical radio across a MAC
rotation.

## Protocol

Every 802.11 frame carries a 16-bit **Sequence Control** field; the
upper 12 bits are a per-station sequence number that increments on
each frame. The counter lives at the chipset level — below the OS's
MAC-randomisation logic. Most popular stacks (iOS, Android, macOS,
Windows, Linux) do **not** reset or randomise the seqnum across the
MAC rotation; they emit a monotonic counter across "different" MACs.

If two MACs we observe emit frames whose seqnum trails fall on the
same monotonic counter (within a small drift window), they are almost
certainly the same physical radio. The deanonymisation is reliable
against the default randomisation behaviour of every major consumer
OS; only the small fraction of devices that explicitly reset the
seqnum (rare) defeat it.

## What sloth captures

Per source MAC observed in any 802.11 probe-request frame:

- The most recent 8 sequence numbers + their timestamps (newest-first
  ring).
- Total frame count, first/last seen, randomised-MAC flag.

On snapshot, every pair of clients is scanned against each other; a
pair is reported when their seqnum trails contain at least one pair
within 64 seqnums and 30 seconds of each other. Pairs are sorted by
ascending gap (smallest gap = strongest match).

## View

```
 Seqnum tracker: 6 clients, 2 correlations  [up/dn] correlations  [c] clear

 Likely-same-device pairs (sorted by smallest seqnum gap)
 MAC A             rnd   MAC B             rnd     gap      dt  verdict
 ----------------- ---   ----------------- ---     ----  ------  -----------------
 a0:b1:c2:d3:e4:f5 -     02:aa:bb:cc:dd:ee Y          1      4s  LIKELY SAME DEVICE
 02:aa:bb:cc:dd:ee Y     02:11:22:33:44:55 Y          3     12s  LIKELY SAME DEVICE

 Per-MAC seqnum history (newest left)
 MAC                vendor          rnd   age   recent seqnums
 -----------------  --------------  ----  ----  -----------------------------------
 a0:b1:c2:d3:e4:f5  Apple           -     5s    1247 1246 1245 1244 1243 1242
 02:aa:bb:cc:dd:ee  (random)        Y     9s    1252 1251 1250 1249 1248
 02:11:22:33:44:55  (random)        Y     19s  1260 1259 1258
```

"LIKELY SAME DEVICE" rows render in heat-red when at least one MAC is
randomised and the gap ≤ 8. These are the SIGINT prizes.

## What's normal

- A handful of clients in radio range, each with their own seqnum
  trail.
- Real (burned-in) MACs that don't correlate with anyone.

## What's interesting (SIGINT-wise)

- **A randomised MAC correlating tightly with a burned-in MAC**:
  identifies the device that's randomising. Especially powerful when
  the burned-in MAC has a known vendor (Apple, Intel, Samsung).
- **Two randomised MACs correlating with each other**: the same
  randomising device across two rotations. Watch the [PNL](pnl.md)
  view in parallel — both MACs probably share an SSID list too.
- **A chain of randomised MACs correlating in sequence**
  (A→B→C→D over time): traces the rotation cadence of a single
  device.

## What this misses

- Devices that randomise the seqnum (rare, mostly custom firmware /
  research builds / certain Linux drivers with patches).
- Devices that go quiet between MAC rotations long enough for the
  30 s window to expire.
- Cross-channel correlations when the sniffer only sees one channel
  at a time.

## See also

- [pnl.md](pnl.md) — confirm a correlation with shared PNL contents
- [probe.md](probe.md) — raw probe stream that feeds the tracker
- "Why MAC Address Randomisation is not Enough" (Vanhoef et al.) — the
  paper that originally exposed the seqnum leak
