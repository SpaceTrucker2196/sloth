---
name: multi-radio-sensing
description: Several sensor radios (--monitor-iface repeated) — extra monitor-mode radios whose frames feed the same detectors as the first; cross-radio de-duplication, the hop list split between radios, what happens when a radio leaves the bus, the mon_rK_* members of sensor_health
type: reference
---

# Several sensor radios (`--monitor-iface`, repeated)

**Summary**: `sloth-wifi --monitor-iface A --monitor-iface B [...]`
opens up to four monitor-mode radios as **sensor radios**. The first is
radio 0, the radio sloth has always opened; each further one is another
receiver for the same 802.11 path: its frames reach the same parsers,
detectors, device and AP tables, evidence ring and alerts
(`src/capture/mon_radio.c`, `src/capture/probe.c`). A frame two radios
both hear is delivered once (`src/mon_radios.c`). Under `--hop` the
channel list is dealt out between the radios, so they listen on
different channels at the same moment. A radio that cannot be opened is
announced and left out; one that leaves the bus mid-run ends its own
thread and the rest carry on. **Receive-only** (MISSION §2): the one
kernel write is the retune `--hop` already makes, now on each of sloth's
own sensor radios. This is not [[direction-finding]], whose
`--df-iface` radios are read for a signal level and nothing else.

**Sources**: `src/mon_radios.h`, `src/mon_radios.c`,
`src/capture/mon_radio.h`, `src/capture/mon_radio.c`,
`src/capture/probe.c` (`probe_radio_frame()`, the dispatch lock),
`src/wifi_chanhop.c` (`chanhop_split()`, `chanhop_step()`),
`src/probe_latency.c`, `src/main.c`
(`--monitor-iface`, `chanhop_drive()`), `src/poll.c`, `src/jsonl.c`
(`sensor_health`), `tests/test_mon_radios.c`.

**Last updated**: 2026-11-24 (owner ruling: the cue limit is over all radios, with a per-radio floor), 2026-11-24 (#248 review: such refusals are `share_small`, not a limit), 2026-11-24 (#248: which radio serves a `--cue` cue, and why three radios on the default list refuse them), 2026-11-16 (new; JSONL `2.3.0`)

## Running it

```
sloth-wifi --headless --hop \
    --monitor-iface alfa0 --monitor-iface alfa1 --monitor-iface alfa2
```

- The first `--monitor-iface` is radio 0 and behaves exactly as a single
  one always did ([[cli-reference]]): pinned, no fallback to discovery.
- Each further one, at most three, is another sensor radio. Every radio
  is prepared by the operator: sloth puts no interface into monitor mode
  ([[monitor-mode]]). The shipped unit's helper prepares `SLOTH_IFACE`
  only ([[deployment]] §3.2).
- Refused at startup, exit 2, one line: a name given twice, more than
  three beside the first, a name that is not an interface name, a raw
  HCI device `bluetoothN`, a further radio together with `--replay`, in
  a `WITH_PCAP=0` build, or also named by `--df-iface`.
- A further radio that is absent, not type 803, or not radiotap when
  sloth starts is named on stderr with the reason and left out. The run
  continues with the others. `sensor_health` keeps its block, state
  `not_open`, with the reason.
- If radio 0 itself cannot be opened, no further radio is opened and
  the run has no 802.11 capture, as with one radio. The monitor stream's
  health, its freshness and `monitor_iface` are radio 0's.

## One frame, heard twice

Two radios in range of a transmission each deliver it. Without a rule,
every flood window, counter, sequence tracker and evidence record would
see the frame once per radio. So each frame is looked up **before**
anything else reads it (`mon_radio_frame()`, called from
`src/capture/probe.c` straight after the frame is decoded): if an
identical frame was delivered from a **different** radio within 5 ms of
this one's capture time, it is a duplicate. It is counted against the
radio that brought it (`mon_rK_dup_dropped`) and goes no further: no
counter, ring, parser or detector sees it.

- **Identical** means the whole 802.11 frame after the radiotap header
  with the FCS off: a 64-bit hash of every octet and, compared exactly
  beside it, the length, Frame Control, Sequence Control and the
  transmitter address (the receiver address of a frame with no
  transmitter).
- **A retransmission is not a duplicate.** It carries the Retry bit
  (IEEE 802.11-2020 §9.2.4.1.7) where the original does not, so its
  Frame Control differs and it is delivered whichever radio heard it.
- **Frames from one radio are never compared with each other.** With one
  radio nothing is looked up or counted and the run is byte for byte the
  run it was (`make replay-check` is unchanged but for the version
  string and `mon_extra_radios`).
- **The first radio to deliver a frame owns it for the window.** Only
  the other radios' copies are dropped, so N identical frames that two
  radios each heard are delivered N times: not 2N, and not once. This is
  the rule for frames with **no sequence number**. Control frames (RTS,
  CTS, ACK, Block Ack) cannot be told from their own repeats; an RTS
  flood (`RTS_FLOOD`, `src/ctrl_frames.c`) is still counted at the rate
  one radio heard it and is not doubled by a second radio.
- **What that costs.** A repeat of an identical control frame, or a
  second identical retransmission, that only a non-owning radio heard
  inside the window is dropped. The count is the owning radio's: never
  the sum of the radios, and not always their union.
- **A damaged copy is not a duplicate.** A frame one radio received with
  a failed FCS has different octets. It is counted where a failed FCS is
  counted (`rf_quality`, the `fcs_failed` parse fault), once per radio
  that received it damaged, and its content is not parsed.

### The window

Measured on beta-site, 2026-11-16: three RTL8821AU adapters
(`rtw88_8821au`) on one hub, 8 s of capture on each at once, 657 frames
that two of the radios both delivered. The capture timestamps of the two
copies differed by at most 78 µs (median 4 to 27 µs by pair). The
nearest octet-identical repeat on a **single** radio, a second
retransmission, came 203 µs after the first. The window is 5 ms, sixty
times the first figure, for a host under load. Those adapters deliver no
control frames in monitor mode, so the control-frame rule above is
tested with hand-built frames only.

Each reader thread takes frames from libpcap in blocks (a 100 ms buffer
timeout), so one radio's copy can be **processed** well after the
other's although their capture times agree. The table is therefore keyed
by capture time and not by arrival: an entry lives in the bucket of its
hash and its 5 ms time slot, and a lookup reads that slot and both
neighbours. Nothing is expired by a clock. Memory is fixed (4096 buckets
of 4, about 512 KiB) and nothing is allocated per frame. A full bucket
evicts its oldest entry; when that entry was under a second old the
eviction is counted (`mon_dedup_evicted`), because a duplicate of an
evicted frame is delivered.

## One path, several threads

Each radio has its own capture handle and reader thread. The 802.11
path was written for one thread (the frame ring, a shared de-padding
buffer, observers that assume frames arrive in sequence), so the whole
callback runs under one lock, `g_dispatch_mu` in `src/capture/probe.c`:
one frame at a time, whichever radio brought it. The lock is taken
before any module's own and by nothing but the capture callbacks. With
one radio it is uncontended.

What stays radio 0's, on purpose:

- **The monitor stream's health and freshness** (`monitor_*` in
  `sensor_health`, `SENSOR_SOURCE_DOWN`): another radio still delivering
  must not make a dead radio 0 read as fresh.
- **Probe-response latency** (`src/probe_latency.c`): it numbers dwells from
  the order frequencies change in and times a pair on one radio's TSFT.
  Neither means anything across radios on different channels with
  unrelated clocks, so only radio 0's frames are shown to it. A pair
  another radio heard is not measured.
- **Radio 0's level in the direction-finding table**
  ([[direction-finding]]): noted from radio 0's own copy of a frame even
  when another radio's copy was the one delivered. The further sensor
  radios are not in that table: under `--hop` they sit on other
  channels, where a level cannot be compared with radio 0's.

What is shared: every table. An AP or station row does not record which
radio heard it. A signal level in a row is the level of the newest frame
from whichever radio delivered it, and two radios do not read alike (the
beta-site pair sat 7.5 dB apart). Under `--hop` each channel belongs to
one radio, so an AP's beacons come from one radio; a station that probes
on every channel is heard by all of them, and its RSSI history mixes
their readings.

## Hopping

Under `--hop` the list is dealt out (`chanhop_split()`): with R radios
alive, radio k takes entries k, k+R, k+2R, … of the list. With the
built-in list and three radios:

| radio | channels |
|---|---|
| 0 | 1, 36, 48, 157 |
| 1 | 6, 40, 149, 161 |
| 2 | 11, 44, 153 |

The shares are disjoint and together are the whole list, so no two
radios sit on one channel, every channel is visited once a cycle, and
each waits the same number of dwells for its revisit: a cycle is 4
dwells instead of 11. (A split by band would leave the three 2.4 GHz
channels on one radio revisited every 3 dwells and the eight 5 GHz ones
every 4 on two; the deal is even instead.) Each radio keeps its own
scheduler and its own adaptive dwell, fed only the frames that radio
delivered (`chanhop_step()`, `mon_hop_service()`).

Radio 0's hop state is where it always was (`chan_*`, `hop_*` in
`sensor_health`); the others report `mon_rK_chan`,
`mon_rK_hop_channels` and `mon_rK_retune_failures`. A radio with more
radios than channels ahead of it gets an empty share and is not retuned.
`--df-iface` radios follow radio 0's channel as before.

Without `--hop` nothing is retuned; one stderr line says so, and each
radio listens where the operator parked it. Parked on one channel they
hear the same frames and the de-duplication does the work; parked on
different channels they cover those channels all the time.

**Every use of "the current channel" was audited**, since with several
radios a frame's channel must come from the frame:

| place | reads | result |
|---|---|---|
| `src/capture/probe.c` `on_radio_frame()` | `rt.channel`, `rt.freq_mhz` from the frame's own radiotap header | already per frame; passed to `rf_quality_observe()`, `ctrl_observe_frame()`, `eapol_observe_frame()`, `assoc_observe()`, `assoc_request_observe()`, `csa_observe()`, `record_probe()`, `beacon_parse_frame()`, the evidence ring |
| `src/probe_latency.c` | radiotap frequency, to number dwells | radio 0's frames only (above) |
| `src/df.c` `df_note()` | the frame's radiotap channel | unchanged; radio 0 and the `--df-iface` radios only |
| `src/main.c` `chanhop_drive()` | `s->chan_confirmed`, `chanhop_current_freq()` for the `--df-iface` follow | radio 0's, which is the radio they follow |
| `src/main.c` `chanhop_drive()` | `mon_frame_total()` as the dwell's activity | all radios' total with several radios; radio 0's scheduler is now fed radio 0's own count |
| `src/wifi_chanhop.c` `chanhop_service()` | publishes `chan_requested`, `chan_confirmed`, `scan_chans`, `scan_cur_idx`, `hop_activity`, `hop_dwell` | radio 0's scheduler, radio 0's share of the list |
| `src/jsonl.c` `sensor_health` | `chan_*`, `hop_*` | radio 0's, as documented; the others have `mon_rK_*` |
| `src/views/iface.c` | `scan_chans`, `scan_cur_idx`, `chan_requested`/`chan_confirmed`, `hop_activity`, `hop_dwell` | draws radio 0's share and position only; the other radios are not drawn (no view work in this slice) |
| `src/poll.c` sensors | `mon_frame_total()` as the Wi-Fi sensor's count | radio 0's own count with several radios; each further radio is its own `sensor` row |

No detector reads the hop state: a frame's channel always came from its
radiotap header.

**Passive cueing** (`--cue`, #248, [[passive-cueing]]): a cue is served
by the radio whose share holds the cued channel (`mon_hop_sched_rw()`).
The 50 % limit is over the sensor radios together, and each radio keeps
a floor: its rotation with cues at most twice as long, so its other
channels keep at least half their share (owner ruling, 2026-11-24). With
the default 11 channels over three radios (4/4/3) two cues run at once;
a radio of two channels or fewer cannot take one (`share_small`, not a
limit, no input to `suppressed:cue`). After a re-deal the next poll cues
the channel wherever it now sits.

## Losing a radio

A USB adapter that drops off the bus makes its reader's
`pcap_dispatch()` fail. That thread ends, the radio's state becomes
`lost` with libpcap's text as the reason, and nothing else stops or
waits: radio 0 and the other radios keep delivering. Under `--hop` the
next poll deals the list again among the radios left, so the lost
radio's channels are covered by the others (the schedulers start again;
their lifetime visit and dwell figures restart with them).

A lost radio is **not** opened again when the adapter returns. By then
the run has dropped the capability an open needs (#140, the same reason
`[m]` cannot retarget after the drop); restart the service. Losing radio
0 is what it always was: `monitor_running` 0 and `SENSOR_SOURCE_DOWN`.
The other radios keep feeding the tables, radio 0's share of the hop
list is not dealt out, and the monitor stream reads stale.

## What is recorded

`sensor_health` ([[jsonl-schema]], JSONL `2.3.0`):

- `mon_extra_radios`: how many radios were named beside the first. `0`
  is the one-radio run, and nothing below is written.
- `mon_dup_dropped`, `mon_dedup_evicted`: all radios' duplicates, and
  the evictions described above.
- For each radio K (0 is the first): `mon_rK_iface`, `mon_rK_state`
  (`not_open`, `open`, `running`, `lost`, `stopped`), `mon_rK_err`,
  `mon_rK_freq` (the frequency of the last frame it received),
  `mon_rK_chan` (the channel its last retune confirmed),
  `mon_rK_hop_channels`, `mon_rK_frames` (delivered),
  `mon_rK_dup_dropped`, `mon_rK_retune_failures`.

The record is change-only. Its signature takes the radio count and, per
radio, the state, whether it has a share of the hop list, whether a
retune has ever failed or ever been confirmed, and the duplicate count
as a decade (0, 1-9, 10-99, …); never a frame count, a frequency or a
channel, which move every tick or every dwell.

Each further radio that was opened is also a `sensor` record of kind
`wifi` with its interface name and its delivered count, after radio 0's
(which keeps id 0). slothweb reads the monitor radios' names from those
records. Nothing else changed: no `--db` schema change, no new record
type, no slothweb view.

## Fleet sharing

The further sensor radios are monitor radios, so what they hear may
travel ([ADR 0009](adr/0009-fleet-monitor-only.md)). No enforcement
point was changed. The export decides which of the host's own addresses
are monitor radios from each interface's link type in sysfs
(`own_is_monitor()`, `web/src/web_fleet.c`), not from sloth's flags, so
any number of them classify as before; the device and alert tests look
at where a row came from, and a row from any sensor radio is a monitor
row.

## Tests

`tests/test_mon_radios.c`: the same frame on two radios is delivered
once in either order; twice on one radio is twice; a Retry copy, the
next sequence number, another transmitter or another body is delivered;
the window's edges, both ways and across a time slot; a reader 100 ms
behind still finds its duplicates; control frames with no sequence
number; a table driven past its size; the split for 1, 2, 3 and 4 radios
covering every channel once; three radios hopping through the fake
platform, never two on one channel; a lost radio's channels dealt out
again; per-radio retune failures; the CLI refusals; the real 802.11
callback fed by three threads at once (the ThreadSanitizer run); and the
`sensor_health` members with their change-only behaviour. Frames are
hand-built octet arrays.

## Related pages

- [[direction-finding]] — `--df-iface`, the other use of a second radio
- [[wifi-sigint]] — the 802.11 path the radios feed, `--hop`
- [[monitor-mode]] — preparing a radio; sloth never does
- [[cli-reference]] — `--monitor-iface`
- [[jsonl-schema]] — `sensor_health`, `mon_rK_*`
- [[deployment]] — adding radios to `SLOTH_ARGS`
