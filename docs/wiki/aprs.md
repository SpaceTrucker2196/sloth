---
name: aprs
description: APRS stations — --aprs tails the packet log a local Dire Wolf decoder already writes, on the APRS channel of the region the GNSS fix is in (144.390 MHz in North America); --aprs-freq and the silent-decoder check; the sample-rate trap that makes an SDRplay front end demodulate hundreds of kHz off the channel while every process reports success (#210), how to measure it and the open front-end choice; the CSV parser, the station table and its one-hour expiry, the aprs sensor, sensor_health's aprs_* fields, the aprs_packet and change-only aprs_station records, sloth.db v13's aprs_stations / aprs_packets, and slothweb's APRS tab
type: reference
---

# APRS stations (`--aprs`, `aprs_packet`, `aprs_station`)

**Summary**: `--aprs SPEC` points sloth at the packet log that a local,
already-running Dire Wolf writes (`direwolf -L FILE`): one CSV line per
APRS packet it decoded off the region's APRS channel (144.390 MHz in
North America, 144.800 in IARU Region 1; sloth derives which from its
GNSS position and checks it against the operator's `--aprs-freq`). sloth turns each line into a
typed packet and keeps one row per source callsign heard: last heard,
packets, heard direct or through which digipeater, audio level, the
position, speed, course and altitude it reported, its symbol, comment,
status and system. sloth is **receive-only and file-only**: it never
opens, tunes or talks to the radio, the SDR or Dire Wolf, and uses no
network. It writes an `aprs_packet` record per packet and a change-only
`aprs_station` record per station, keeps both in sloth.db (schema v13)
with `--db`, and slothweb shows them on its APRS tab. It also says
when the decoder has gone **silent** (the log readable, no packet for
6 h by default) and when the declared frequency is not the region's
channel. No TUI view and no alert rule.

**Sources**: `src/aprs.h`, `src/aprs.c` (line parser, spec, station
table, packet ring, cell and signature), `src/capture/aprs_reader.h`,
`src/capture/aprs_reader.c` (the tail), `include/sloth.h`
(`aprs_packet_t`, `aprs_station_t`, `aprs_health_t`, `SENSOR_APRS`),
`src/poll_rf.c` (`aprs_health_poll()` in the `health_rf` stage,
`SENSOR_APRS` in the `sensors_rf` stage), `src/jsonl_rf.c` (`jsonl_emit_aprs()`, the `aprs_*`
appends in `jsonl_emit_sensor_health()`), `src/db.c` (`write_aprs()`),
`src/db_schema.c` (v13), `src/main.c` (`--aprs`, `--aprs-freq`,
`--aprs-silent-hours`); slothweb
`web/src/web_aprs.c`, `web/src/web_aprshist.c`, `web/src/web_slothdb.c`,
`web/ui/aprs.js`; tests `tests/test_aprs.c`, `tests/test_db.c`,
`tests/fuzz/fuzz_aprs_line.c`, `web/tests/test_aprs.c`. Format
references: the Dire Wolf User Guide ("Logging") and `src/log.c`
(wb2osz/direwolf, release 1.7); the APRS Protocol Reference 1.0.1
(APRS101.pdf) for the data type indicators (ch. 5), objects and items
(ch. 11) and the symbol tables (ch. 20, appendix 2). § The sample-rate
trap is from the W9FJC measurements recorded in #210 — no file in this
repo runs, configures or describes `rx_fm`, so that section cites the
issue and the host's own `aprs.service`, not the tree.

**Last updated**: 2026-11-18 (#210: the sample-rate trap — `rx_fm` derives its fs/4 LO offset from the rate it requested and rotates by a quarter of the rate the device delivered, so an SDRplay host that ignores `-s` demodulates hundreds of kHz off the channel and the pipeline reports success all the way down; how to measure the stdout rate without a second radio, W9FJC's host-side workaround and why it is fragile, the open front-end choice. Also: the 144.894 MHz LO in § The channel is no longer presented as evidence of a working chain); 2026-11-15 (#216, the cutover: `--aprs`, `--aprs-freq` and `--aprs-silent-hours` are `sloth-rf`'s alone; `sloth-wifi` refuses them); 2026-11-13 (the positions panel as an ATC-style radar scope centred on the sensor); 2026-11-13 (#204: the APRS region and channel derived from the GNSS position, `--aprs-freq` and its mismatch, the silent decoder after `--aprs-silent-hours` (default 6), the `sensor_health` fields and the APRS tab's notices; the beta-site log sat at 0 bytes from 2026-11-11 with nothing saying so); 2026-11-06 (the Radar tab: stations and, by name, objects and items as entities of their own, kept for the `APRS for` window after their newest packet, with status, comment and a moving one's 24 h trail, from `/api/aprs/tracks`); 2026-11-05 (shipped: the feed, the table, JSONL, sloth.db v13, slothweb's APRS tab and history).

**Which daemon (since the cutover, #216).** The APRS decoder source is **`sloth-rf`'s**:
`--aprs` (with `--aprs-freq` and `--aprs-silent-hours` is its flag, and the reader, the table, the `aprs_station` and `aprs_packet` records,
the `aprs_*` block of `sensor_health`, the `aprs` row of
`source_status` and the `aprs_stations` / `aprs_packets` tables are in its stream and its database
(`/run/sloth-rf/sloth-rf.sock`, `/var/lib/sloth-rf/sloth-rf.db`) and
nowhere else. `sloth-wifi` (the Wi-Fi daemon; `sloth` is a symlink to
it) took this flag until JSONL 2.0.0 and now refuses it with exit 2 and
a line naming `sloth-rf` and `sloth-migrate-rf` ([[deployment]] §11.4,
[[cli-reference]] § Refused); it links none of this code. Where the
rest of this page says "sloth" reads, keeps or writes something, the
daemon is `sloth-rf`. slothweb's tab is fed by `--rf-socket`; against
a 2.x `sloth-wifi` with no `--rf-socket` it says the RF daemon's
stream is not configured ([[slothweb]] § The RF stream's state). An
unsplit `1.x` sensor is still read as before
([ADR 0010](adr/0010-wifi-rf-daemons.md), [[jsonl-schema]] § 1.x to
2.0.0).

The region check reads the sensor's position, which is now
`sloth-rf`'s own reader's: give it `--gps` or `--location` too.

---

## Where it sits against the seven questions

[[non-ip-sensors]] asks every family seven questions:

1. **Observable passively**: what Dire Wolf already decoded off the
   region's APRS channel (below; 144.390 MHz in North America): AX.25 UI frames
   carrying APRS position, status, message, object and telemetry
   reports - the lines in its packet log.
2. **Hardware**: a receiver Dire Wolf demodulates (on the reference
   host an SDRplay through `rx_fm`, `aprs.service`), which the operator
   runs; sloth needs only the file.
3. **State**: `aprs_station_t` keyed by source callsign, a ring of the
   newest `aprs_packet_t`, and `aprs_health_t` (`include/sloth.h`).
4. **View**: slothweb's APRS tab (below); no TUI view.
5. **JSONL / --db**: `aprs_packet` and `aprs_station`, `aprs_*` on
   `sensor_health`, a `sensor` record of kind `aprs`; with `--db`,
   `aprs_stations` and `aprs_packets` (v13).
6. **Out of scope**: transmitting anything (sloth holds no licence and
   no transmit path; Dire Wolf is run receive-only), configuring or
   talking to Dire Wolf (KISS, AGW and its ports are not used), APRS-IS,
   igating, decoding the radio audio itself.
7. **Testing**: hand-written log lines in Dire Wolf's shape with
   invented calls and positions (`tests/test_aprs.c`), temporary files
   for the reader (appends, copytruncate, rename rotation, a file that
   appears later), a libFuzzer harness; no captured log.

## The source

`--aprs /var/lib/direwolf/aprs.log` or
`--aprs file:///var/lib/direwolf/aprs.log`. Only an absolute local path:
a relative path, a directory path, `file://HOST/` and any other scheme
exit 2, as does `--aprs` with `--replay`. The file need not exist when
sloth starts.

Dire Wolf opens its log with `fopen(..., "a")` once, writes one record
per decoded packet as a single `fprintf` and flushes it, and writes the
header line only when it creates the file (with its first packet:
until then there is no file). logrotate's `copytruncate` empties the
same inode in place. So every second (`APRS_POLL_MS`) the reader
(`src/capture/aprs_reader.c`, a worker started after the privilege
drop) opens the path read-only (`O_RDONLY | O_NONBLOCK | O_CLOEXEC`, a
regular file only), `fstat()`s it and keeps (device, inode, offset):

| what it finds | what it does |
|---|---|
| the first look, a file already there | starts at its **end**: what Dire Wolf wrote before this run is not replayed (sloth.db already holds what an earlier run read) |
| a file where the last poll found none | reads it from the start (Dire Wolf just created it) |
| a different inode | a rotation by rename: the new file from the start (`aprs_rotations`) |
| a size below the offset | a truncation (`copytruncate`): from 0 (`aprs_truncations`) |
| more bytes | the new bytes, at most 256 KiB a poll (`APRS_POLL_BYTES`); a partial last line waits for the next poll |

One case the size test cannot see: a truncation followed, before the
next poll (1 s), by Dire Wolf writing past the old offset. The reader
then reads on from the old offset and the packets between 0 and there
are skipped, the next line read may start mid-record and is refused as
bad. On a 1200 bit/s channel that needs more than one second of
packets in the instant logrotate runs; it is accepted, not handled.

A line over 1024 bytes (`APRS_MAX_LINE`) is one bad line, skipped to its
newline. Blank lines (Dire Wolf leaves them between records) and the
header are skipped and are not bad. A missing file is a state
(`waiting`), not an error; an unreadable path or one that is not a
regular file is `error`, counted.

## The channel (#204)

APRS has no single frequency: each region chose one 2 m channel, and a
decoder on another one hears nothing at all. sloth reads a file, so it
cannot see which channel Dire Wolf is on. Instead it derives which
channel it **should** be from where the sensor is, and the operator may
declare which one it **is**.

| region (`aprs_region`) | channel |
|---|---|
| `north-america` | 144.390 MHz |
| `iaru-r1` (Europe, Africa, the Middle East, Russia) | 144.800 MHz |
| `australia` | 145.175 MHz |
| `new-zealand` | 144.575 MHz |
| `japan` | 144.640 MHz |
| `brazil` | 145.570 MHz |
| `unknown` (a position in none of them) | none: sloth names no default |
| `none` (no position this run) | none |

`aprs_region_of()` (`src/aprs.c`) is a pure function over coarse
latitude / longitude rectangles, checked most specific first (New
Zealand, Australia, Japan, Brazil, North America, Region 1). Inside a
region it is right; near a border it is approximate (a point in
Paraguay can read `brazil`, one on Ulleungdo `japan`), and
`tests/test_aprs.c` pins both sides of every edge. The position is the
one every other stamp uses, `s->gps`'s arbitrated `loc_*` (a fresh fix,
else `--location`), read through sloth's own GNSS path, so no gpsd
client tool (`gpspipe`) is needed. Without a position the region last
derived this run is held: a sensor does not change continent between
fixes. **Only the region's name and channel are kept and written,
never the position it came from**; sloth records no location beyond
what `sensor_health`'s `loc_*` already carried.

`--aprs-freq HZ` declares what the decoder is **configured** for, in
Hz. On the reference host that is `APRS_FREQ` in `/etc/default/aprs`
(read by the host's own `aprs.service`, `rx_fm | direwolf`, which is not
in this repo): pass the same number, e.g. `--aprs-freq 144390000`. It
is **not** `rx_fm`'s reported hardware tune: that sits fs/4 above the
target (2.016 MS/s / 4 = 504 kHz, so about 144.894 MHz for 144.390), so
comparing it would flag a decoder whose configuration is right. But **an
offset LO is not by itself evidence that the chain works**: #210 (below,
§ The sample-rate trap) found `rx_fm` deriving that offset from a rate
the device never delivered and demodulating 246 kHz off the channel, and
the 144.894 MHz reading named here is beta-site's, read at the time as a
benign fs/4 offset on a chain that has decoded nothing since
2026-11-11. The declared-frequency check is a check of the operator's
*configuration*, not of the receive chain. When both are known and more than 6.25 kHz apart (half the
narrowest 2 m channel spacing) `aprs_freq_mismatch` is 1 and slothweb
says "frequency mismatch". sloth never changes the decoder's frequency
and ships no tool that does: receive-only, file-only, as before.

## The sample-rate trap (#210)

A decoder on the right channel can still demodulate the wrong
frequency, because the front end computed its tuning from a sample rate
the device never gave it. This is written down here because it is
invisible from everything sloth can see: it took W9FJC's APRS feed with
no process reporting a fault, and it fits beta-site's silence since
2026-11-11 as well.

**Symptom.** `aprs_state` is `live`, the log is readable, and no packet
ever arrives — then, six hours in, `aprs_silent` goes to 1 (§ Silent).
Every process in the chain reports success: the SDR opens, `rx_fm`
streams, Dire Wolf reads samples and writes nothing, and logrotate
rotates a 0-byte file. On W9FJC (2026-11-14) `rx_fm -d driver=sdrplay …
-f 144.390M -s 22050 | direwolf -r 22050` on an SDRplay RSPdx-R2
decoded nothing while a handheld beside the antenna read S8–S9 on
144.390 MHz, and an NESDR into the same Dire Wolf decoded that same
handheld at level 70–74. Nothing in sloth's health block distinguishes
this from a genuinely quiet channel: sloth reads a file, and the file
was fine.

**Mechanism.** `rx_fm` derives two numbers from the sample rate, and
they stop agreeing the moment the device does not deliver the rate it
was asked for.

- `-s 22050` asks the device for 22050 × 46 = **1,014,300 Hz**
  (`rx_fm`'s fixed ÷46 decimation).
- SoapySDRPlay3 0.5.3 hands back the RSPdx-R2's native **2 MS/s**
  instead. `rx_fm` keeps its ÷46, so its stdout runs at
  2,000,000 ÷ 46 = **43,478 samples/s** (43,520 measured over a short
  window), not 22,050 — and Dire Wolf, told `-r 22050`, reads a stream
  arriving at nearly twice the rate it was declared.
- `rx_fm` offsets the LO by a quarter of the rate it **requested**
  (1,014,300 ÷ 4 = 253.575 kHz, so LO 144.643575 MHz) and then rotates
  the stream down by a quarter of the rate it was **given** (500 kHz).
  What it demodulated was 144.643575 − 0.500 = **144.143575 MHz**, about
  246 kHz below the channel: flat discriminator noise.

Accepting a different rate from the one requested is not an error on
any of these interfaces, so no process in the pipeline has anything to
report. The symptom is silence, not a failure.

**Verifying it, with no second radio.** Measure `rx_fm`'s own output
rate and compare it with the `-s` value it was given.

- Bytes per second off its stdout: `rx_fm … -s 22050 | pv -r >
  /dev/null`, or a byte count over a known interval
  (`timeout 10 rx_fm … 2>/dev/null | wc -c`, divided by 10).
- Samples per second is that divided by the bytes per sample.
  **Establish the divisor before dividing it**: this repo runs no part
  of that pipeline and records no sample format for `rx_fm` anywhere in
  the tree, so take it from the `rx_fm` build in use (`rx_fm --help`)
  and from the format Dire Wolf is told to expect on stdin. The
  reference chain's is 2 (16-bit signed mono), i.e. samples/s =
  bytes/s ÷ 2.
- Or run the test **format-free**: change `-s` and see whether the
  output rate changes with it. A device honouring the request moves in
  proportion; one ignoring it does not move at all.

**Pass condition**: the measured stdout rate is the `-s` value, within
a per cent or so. A rate off by an integer-ish factor is the signature
of this fault — 43,478 / 22,050 ≈ 1.97, which is
2,000,000 / 1,014,300 — and means the device kept its own rate and the
LO offset is wrong by a quarter of the difference. Where a second
receiver exists (the NESDR above), the other check is to compare what
Dire Wolf reports for one known local transmitter on each: a chain
demodulating the wrong frequency reports no packet at all, not a weak
one.

**The workaround in place on W9FJC — host config, not in this repo.**
`aprs.service` since 2026-11-14 (sloth ships no tool that reads or
edits it; § The channel):

    rx_fm … -f 144.636425M -s 22050    # 144.636425 + 0.253575 = 144.890 LO, − 0.500 = 144.390
    direwolf -r 43478                  # 2,000,000 / 46

The handheld decodes at level 71. **It is correct only while both rates
stay exactly as measured.** It compensates with two different rates at
once — the LO offset from the rate `rx_fm` *requests*, the rotation
from the rate the device *delivers* — so a SoapySDRPlay3 that starts
honouring the requested rate, or that picks a different native rate,
moves the demodulated frequency by hundreds of kHz. The failure mode is
again silence rather than an error, and the only thing that would say
so is `aprs_silent`, six hours later. Re-measure the output rate after
any change to the SDR stack.

**The proper fix is still open** (#210). The options, none of them
chosen here:

- Ask for a rate the device provides natively and resample —
  `rx_fm -s 2000000 -r 22050`, or a 2 MS/s capture with an explicit
  decimation chain — checking the actual output rate either way.
- A different front end on SDRplay hosts: SoapySDR + `csdr`, or
  GNU Radio.

Which front end runs on a sensor, and what its unit files say, is the
operator's call and not this repo's
([`agents/dark-factory.md`](../../agents/dark-factory.md) §4.3, actions
outside the repo). sloth never opens, tunes or spawns the decoder —
`grep -rnE 'execv|execl|popen|system\(|fork\(' src/main.c src/aprs.c
src/capture/aprs_reader.c` is empty — it reads the log Dire Wolf
writes, and documents what feeds it. beta-site's chain is still to be
checked the same way.

## Silent

A quiet hour is normal (a fixed station beacons every 10 to 30
minutes), which is why `aprs_state` stays `live` whatever the file
holds. A receive chain that died (an antenna port, a gain setting, a
wrong channel) looks exactly the same, and on 2026-11-13 the reference
host's log had been 0 bytes since the 2026-11-11 rotation with nothing
saying so. So `aprs_silent` is 1 when the state is `live` and no packet
arrived for `--aprs-silent-hours` (default **6**; 0 off, at most 168),
counted from `aprs_quiet_since`: the newest packet's `utime`, or this
run's first good read when that is later. The reader starts at the
file's end, so a restart re-arms the clock rather than inheriting a
silence it did not watch. Six hours is six times the quiet hour the
state already tolerates, long enough that a rural site hearing one
digipeater's half-hourly beacon never trips it, and short enough to
catch a dead chain the same day. A missing file (`waiting`, Dire Wolf
not yet having written its first packet) and an `error` are said by
the state, not by `silent`.

## The parser

`aprs_line_parse()` reads one line as `log_write()` writes it: 22 fields
in the header's order -

    chan,utime,isotime,source,heard,level,error,dti,name,symbol,
    latitude,longitude,speed,course,altitude,frequency,offset,tone,
    system,status,telemetry,comment

The text fields pass through Dire Wolf's `quote_for_csv()`: quoted only
when they hold a `,` or a `"`, an inner `"` doubled, nothing else
escaped. `source` and `heard` are written raw. A line is **refused
whole** (`aprs_bad_lines`) when it is not exactly 22 fields, a quote is
out of place (not closed, bare inside an unquoted field, text after a
closing quote), the channel is not 0..255, `utime` is not an integer in
2000..2100, `source` is not a callsign, or `heard` is present and not a
callsign. A callsign is AX.25's as APRS writes it: 1 to 6 of `[A-Z0-9]`,
then optionally `-` and 1 or 2 of `[A-Z0-9]` (the SSID; APRS-IS admits
letters).

Every other field, present but malformed or out of range, is
**absent**, never clamped: `level` (the leading integer of `50(14/14)`,
Dire Wolf's audio level), `error`, `dti` (exactly one printable byte),
`name` (the object or item name, else the source; printable, at most 9
once trailing spaces go), `symbol` (exactly two printable bytes: table,
code), latitude / longitude (only as a pair inside ±90 / ±180), speed
(knots, 0..2000; log.c converts from mph), course (0..360), altitude
(metres, -1000..100000; log.c converts from feet, so 1234 ft is logged
376.1), and frequency / offset / tone (kept as written when they look
like `%.3f` MHz, `%+d` kHz, `%.1f` Hz or a `D023` DCS code). Numbers are
read with a locale-free digit walk (no `strtod`, no exponent). The free
text - `system` (the sender's software or device, from its destination
or Mic-E code), `status` (Mic-E status), `telemetry`, `comment` - keeps
printable ASCII; any other byte becomes `?`; it is cut at 64 bytes, the
comment at 128.

**What a line can forge.** The comment is free text from anyone with a
transmitter, and Dire Wolf escapes nothing in it but `,` and `"`: a CR
or LF inside one splits its record. A fragment that does not parse is a
bad line. A fragment that does parse cannot be told from a record, so a
sender can make a whole extra line appear: one with a `heard`, `level`
or `chan` of its choosing, which an over-the-air packet cannot set.
APRS itself authenticates nothing, so the source callsign and the
position were never proof of anything; the forgeable part is "heard
direct" and the level. The docs and the page say "as reported".

## The station table

`aprs_feed_packet()` (`src/aprs.c`, one mutex: the reader feeds, the
poll copies) keys stations by `source`, at most 512
(`APRS_MAX_STATIONS`; a new call past it is refused and counted in
`aprs_overflow`, its packet still recorded). The merge is sticky: a
position, with the speed, course and altitude that came with it (absent
ones included), is replaced only by a packet that carries one; the
symbol, comment, status and system only by a non-empty one. `via` is
the newest packet's `heard`; `heard_direct` is set once any packet's
`heard` is the source itself; `best_level` is the highest level heard.
**An object or item** (dti `;` or `)`, APRS101 ch. 11) describes the
thing it names, not its sender: its position, symbol and comment do not
touch the sending station; the `aprs_packet` record and the
`aprs_packets` row carry them (with `name`). Objects are not stations
of their own here.

A station unheard for **3600 s** (`APRS_EXPIRE_S`, on the monotonic
clock: a fixed station beacons every 10 to 30 minutes) is retired once
as "gone"; heard again, it is a new visit with a new `first_seen`.

Every packet also enters a ring of the newest 256 (`APRS_PKT_RING`),
each with a sequence number. The poll copies the ring onto
`sloth_state_t`; the JSONL writer and the sloth.db writer each keep
their own cursor, so each writes every packet once at its own pace
(`--db-interval-secs` included). A sink more than 256 packets behind
loses the oldest; at 1200 bit/s that is a stall of about a minute.

## State

| state | when |
|---|---|
| `none` | no `--aprs` |
| `waiting` | configured, the file not read yet or not there (`aprs_missing` 1) |
| `live` | the last poll read the file (whatever it held: a quiet channel is live) |
| `error` | the last poll failed: unreadable, not a regular file |

The registry's `aprs` sensor is `error` in the error state, `active`
once a packet was parsed, else `present`; it observes the packet count.

## JSONL

`aprs_packet`, one per packet: `src`, `seq`, `chan`, `utime`,
`source`, then each of `heard` (with `direct`), `level`, `error`,
`dti`, `name`, `symbol`, `lat` / `lon` (6 dp), `speed_kt`, `course`,
`alt_m`, `freq`, `offset`, `tone`, `system`, `status`, `telemetry`,
`comment` only when the line carried it - never a 0 or `""` standing in
for absent. An event record: the channel's rate bounds it. With no sink
open the cursor still moves, so a consumer that connects later is not
handed old packets.

`aprs_station`, change-only on `aprs_station_sig()`: the call,
`first_seen`, the held 0.01° position cell (about 1.1 km, held until
the position leaves it by 0.001°, about 110 m, so a fixed station's GPS
wander on an edge writes nothing), whether it has a position, the
symbol, and `heard_direct`. Never the packet count, last heard, level,
via, speed, course, altitude or comment: each moves with every packet,
and every packet is its own record already. Plus the 300 s heartbeat,
and one `"state":"gone"` record on expiry. [[jsonl-schema]] lists the
fields.

`sensor_health` carries `aprs_*` only with `--aprs`: `aprs_state`,
`aprs_src`, `aprs_missing`, `aprs_last_read`, `aprs_last_packet`,
`aprs_stations`, `aprs_bytes`, `aprs_lines`, `aprs_packets`,
`aprs_bad_lines`, `aprs_overflow`, `aprs_expired`, `aprs_truncations`,
`aprs_rotations`, `aprs_read_errors`, `aprs_err`; and, after the
`twin193_*` block (#204), `aprs_region`, `aprs_region_hz`,
`aprs_freq_hz`, `aprs_freq_mismatch`, `aprs_silent`,
`aprs_silent_after_s`, `aprs_quiet_since`. The signature takes the
state, the missing flag, none/some bands of the read errors, bad lines,
overflow and the error text, the region, the mismatch and the silent
flag; the counts and times are written, not signed.

## `--db`: `aprs_stations` and `aprs_packets` (schema v13)

With `--db` and `--aprs`, `write_aprs()` (`src/db.c`) writes each packet
past its cursor as one `aprs_packets` row (observation tier: `last_seen`
= Dire Wolf's `utime`, source, heard, dti, name, symbol, position,
speed, course, altitude, level, status, comment; no key, since one
packet is often heard twice in a second, direct and through a digi) and
one upsert of the `aprs_stations` inventory row for its source (entity
tier: earliest first seen, latest last seen, `visits` - one more each
time sloth's own `first_seen` moves - packets, the newest via, dti,
symbol, position and its time, comment, status and system, whether any
packet was heard direct, the best level). An object's position, symbol
and comment stay out of its sender's row. The v12 → v13 step is a
stamp; nothing is backfilled. [[sqlite-schema]] has the columns.

## slothweb

The APRS tab (after ADS-B) reads `aprs_packet`, `aprs_station` and the
`aprs_*` block of `sensor_health` off the data socket and keeps them in
memory (`web/src/web_aprs.c`): up to 1024 stations, a gone one kept
30 minutes, a live one with no record for 660 s aged out, each with its
last 32 positions and its last 16 packets (time, type, via, level, the
comment cut to 48). `/api/aprs?limit=` serves the list (live before
gone, the most recently heard first; as many as fit the 64 KB answer,
`cut` when the buffer stopped it) and `/api/aprs?call=` one station
with its track and recent packets. From sloth.db
(`web/src/web_aprshist.c`): `/api/aprs/seen?days=&limit=&offset=&q=`,
the stations heard in the window (100 a page, `q` a callsign prefix of
`[0-9A-Za-z-]`), and `/api/aprs/station?call=&days=`, one station's row
and its packets (oldest first, the newest 400 that fit, `cut` when the
oldest were left out). The page (`web/ui/aprs.js`) draws the decoder's
health line, the station table, a radar scope centred on the sensor's
GNSS position (ATC style, owner request 2026-11-13: range rings, a
bearing rose, a sweep with afterglow, velocity leaders and data blocks;
no map tiles, nothing fetched; the selected station's track solid, its
recorded positions dotted; the fitted north-up plot when there is no
position), a detail panel and the "stations seen" table. The
health line names the region and its channel (or the declared
frequency), and a notice says "silent for Xh" or "frequency mismatch"
when `sensor_health` does. Dire
Wolf's receiver is a passive radio, so all of it is Monitor's and
Hybrid's; under Local the routes check the query and answer
`out_of_scope`. Full description in
sloth-mesh's `README.md`.

**The Radar tab** (2026-11-06) draws APRS on its dome. Its entities are
the stations (by source call) and, as entities of their own, the
**objects and items** (`dti` `;` / `)`, keyed by their name, shown as
`NAME (obj via CALL)`): the `aprs_station` table above folds an object
into its sender, the Radar does not. They come from sloth.db over 24 h
(`/api/aprs/tracks?hours=`, `web/src/web_aprshist.c`, one newest-first
range scan of `aprs_packets` on its `last_seen` index) merged with the
live stations. An entity stays on the dome for the `APRS for` window
(default 1 h) after its newest packet of **any** kind, so an object
that keeps sending status stays, at its last known position, and one
silent for the whole window clears; it carries its newest status and
comment, and a moving one (two 0.001° cells or a speed above 0 in the
24 h) its trail of at most 48 points. [[slothweb]] has the rest.

## Privacy

APRS positions are public broadcasts by licensed amateurs, but a table
of who was heard and from where, kept over months, is still a record of
people's movements, and the receiver's own position follows from what
it hears. The records go to the operator's own sinks only. Tests and
documentation use invented calls (`N0TEST-n`, `N0CALL-n`) and invented
positions, never a station heard on the air.

## Pending

A TUI view; objects and items as rows of their own; a `--aprs` source
other than Dire Wolf's log.

## Related pages

- [[non-ip-sensors]] — the family roadmap and the seven questions.
- [[adsb]] — the ADS-B family, built the same way.
- [[jsonl-schema]] — `aprs_packet`, `aprs_station`, `sensor_health`'s `aprs_*`.
- [[sqlite-schema]] — `aprs_stations`, `aprs_packets` (v13).
- [[cli-reference]] — `--aprs`, `--aprs-freq`, `--aprs-silent-hours`.
- [[gnss]] — the position the region is derived from.
- [[slothweb]] — the APRS tab.
