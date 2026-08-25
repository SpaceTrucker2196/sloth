# `[m]` Channel — per-channel spectrum occupancy and health

## Protocol / data source

Derived, not captured. Every observation the monitor radio makes carries
a channel — beacons from `src/beacon_snoop.c`, associations from
`src/assoc_track.c`, and every 802.11 frame that reaches the capture
callback. This view folds them into one row per channel.

Two independent signals feed it:

- **Occupancy** — how many APs beacon here, how many stations are
  associated, and how strong the best AP is. Rebuilt each poll by
  `channel_summary_update()`.
- **Health** — what fraction of frames on the channel are retries or
  failed their FCS. Accumulated by `src/rf_quality.c` from the 802.11
  Frame Control retry bit and the radiotap FCS-failed flag.

Frequency-to-channel mapping is shared with the managed-mode nl80211
path (`radiotap_freq_to_channel()`), so a monitor capture and a scan
cannot disagree about what channel an AP is on. 2.4, 5 and 6 GHz.

## What sloth captures

| Column | Source |
|---|---|
| `Ch` / `Band` | frequency, mapped |
| `APs` | distinct BSSIDs beaconing on the channel |
| `STAs` | associations whose BSSID resolves here |
| `Best` | strongest AP signal, dBm |
| `Top SSID` | SSID of that AP, hash-coloured |
| `retry` | retry ratio over the last 5 minutes |
| `ctrl` | observed control frames (RTS / CTS / ACK / Block-Ack) on the channel |
| `age` | since the most recent observation |
| `activity` | bar, relative to the busiest channel |

## View

```
 Ch     Band     APs  STAs  Best  Top SSID               retry    ctrl   age  activity
 -----  -------  ---- ----  ----  --------------------  ------  ----  --------
 6      2.4GHz      7    12   -41  CorpWiFi                 61%    2s  ████████████████████████
 1      2.4GHz      4     3   -58  Guest-Net                14%    3s  ██████████
 11     2.4GHz      3     1   -67  BT-Hub-4A                 8%    5s  ██████
 36     5GHz        5     9   -49  CorpWiFi-5                3%    2s  ████████████████
 149    5GHz        2     0   -71  (hidden)                   -   19s  ██
 37     6GHz        1     0   -74  CorpWiFi-6E                -   41s  █
```

## Control-frame volume (#64)

The **ctrl** column counts RTS, CTS, ACK and Block-Ack frames seen on
the channel. Control frames dominate real airtime, so this is the
*measured* half of channel occupancy — as distinct from the QBSS Load
element, which is what an AP reports about itself.

The cell is heat-coloured on the **RTS share**, not the raw count. A
busy channel has plenty of ACKs and that is entirely normal; a channel
that is mostly RTS is one being *reserved*, which is the shape
`ALERT_TYPE_RTS_FLOOD` fires on.

`-` means none counted. On a channel with APs on it that usually means
the `--hop` sweep has not dwelt here long, rather than that the channel
is quiet.

### Why this is per-channel and not per-AP

RTS, PS-Poll and the Block-Ack pair carry a transmitter address. **CTS
and ACK carry only a Receiver Address** — no TA, no BSSID. They can be
attributed to the channel they were heard on and to nothing finer.
Rather than invent an attribution the frame does not carry, the
per-source table holds only the frames that name a source, and the
per-channel totals hold everything.

That distinction is easy to lose: a captured CTS includes a 4-byte FCS,
so it arrives long enough that a length-based guess at "is there a
transmitter here" would read six bytes past the Receiver Address and
invent one out of the checksum.

## Retry ratio (roadmap B3)

The **retry** column is the fraction of frames on that channel carrying
the 802.11 retry bit, over a rolling 5-minute window.

| Shown | Meaning |
|---|---|
| `-` | fewer than 100 frames — **not enough to say** |
| `0-19%` | ordinary; 802.11 retries constantly |
| `20-39%` | elevated, amber |
| `≥ 40%` | degraded, hot — raises [`RF_DEGRADED`](alerts.md) |

`-` is not the same as `0%`. **A quiet channel is not a clean one**, and
conflating the two would let a single retried frame paint a channel as
degraded — one retry out of three is 33% and means nothing.

Counters reset when the window rolls rather than decaying, so a channel
that was congested an hour ago and is fine now reads fine. A weighted
memory would keep it amber for something the operator can no longer act
on.

**This is an observation, not an attribution.** A high retry ratio is
equally consistent with a microwave oven, a client at the edge of range,
a hidden node, and a deliberate jammer. sloth reports the ratio and the
sample size; the operator supplies the context. The alert is WARN and
says as much in its detail line.

## What's normal

- **2.4 GHz crowded on 1 / 6 / 11.** Those are the only non-overlapping
  channels; everything piles onto them.
- **Retries in the 5-15% band.** 802.11 is a contention protocol on a
  shared medium — retries are how it works, not a fault.
- **5 GHz spread thin.** More channels, fewer APs each, lower retries.
- **6 GHz nearly empty**, and only visible if the radio can tune there.
- **`-` on channels the radio only glanced at.** With `--hop`, a channel
  the scheduler dwelt on briefly will not reach the sample floor.

## What's suspicious

- **Sustained retry ratio ≥ 40% on a channel with real traffic.**
  Interference, a hidden node, or a jammer. Correlate with the
  `activity` bar: high retries *and* high volume is contention; high
  retries and *low* volume is more consistent with a noise source.
- **A retry spike confined to one channel** while its neighbours stay
  clean. Broadband interference (a microwave, a faulty PSU) tends to
  smear across adjacent channels; a single-channel spike is more
  interesting.
- **Many APs suddenly appearing on one channel.** Cross-reference
  [beacons.md](beacons.md) and the `BEACON_FLOOD` alert — mdk-style
  floods concentrate.
- **A busy channel with zero associations.** Traffic with no clients is
  either a channel you are hearing from far away, or something that is
  not an ordinary network.

## See also

- [beacons.md](beacons.md) — the AP inventory feeding `APs` / `Top SSID`.
- [assoc.md](assoc.md) — the associations feeding `STAs`.
- [alerts.md](alerts.md) — `RF_DEGRADED` and the flood rules.
- `docs/wiki/wifi-sigint.md` — how channel hopping affects coverage.
