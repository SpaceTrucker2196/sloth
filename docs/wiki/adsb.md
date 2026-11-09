---
name: adsb
description: ADS-B aircraft (#26 slice 1) — --adsb tails the aircraft.json a local readsb / dump1090-fa decoder already writes, or reads its SBS / BaseStation TCP output read-only; the parser, the aircraft table, freshness and expiry, the adsb sensor, the adsb_* sensor_health fields and the change-only adsb_aircraft record with its altitude bands and position cells
type: reference
---

# ADS-B aircraft (`--adsb`, `adsb_aircraft`)

**Summary**: `--adsb SPEC` points sloth at the `aircraft.json` that a
local, already-running Mode S / ADS-B decoder (readsb, dump1090-fa)
writes, and turns it into typed rows: one per address the decoder
lists, with callsign, squawk, emergency status, category, altitude,
speed, track, rates, position, RSSI and message count. sloth **never
opens, tunes or talks to the SDR**. The source is a file it re-reads
about once a second, using no network, or (2026-11-09) the decoder's
SBS / BaseStation output on a loopback TCP port, read by a client that
never writes a byte to the socket, or its Beast binary output on
another, where sloth frames and decodes the Mode S messages itself
(CRC, ghost suppression, CPR). Slice 1 is the core only:
the parser, the table, the source's health in the sensor registry and
`sensor_health`, and the change-only `adsb_aircraft` JSONL record; the
`[^]` TUI view, slothweb's tab and the `--db` tables followed, then
one alert rule, `ADSB_EMERGENCY` (#186): an emergency squawk or status,
flag only. `sbs://` and then `beast://` input closed the family's
last open items.

**Sources**: `src/adsb.h`, `src/adsb.c` (parser, spec, table, bands,
signature), `src/capture/adsb_reader.h`, `src/capture/adsb_reader.c`
(the per-poll file read), `include/sloth.h` (`adsb_aircraft_t`,
`adsb_health_t`), `src/poll.c` (`adsb_health_poll()` in the health
stage, `SENSOR_ADSB` in the sensors stage), `src/jsonl.c`
(`jsonl_emit_adsb()`, the `adsb_*` appends in
`jsonl_emit_sensor_health()`), `src/main.c` (`--adsb`); tests
`tests/test_adsb.c`, `tests/fuzz/fuzz_adsb_doc.c`; the alert
`src/alerts/rules_adsb.c`, `tests/test_adsb_rules.c`,
`research/adsb/emergency-squawks.md`; for `sbs://`
`tests/fuzz/fuzz_adsb_sbs.c` and the SBS cases in the three test files;
for `beast://` `src/adsb_beast.h`, `src/adsb_beast.c` (framer, Mode S
decoder, CPR), `tests/test_adsb_beast.c`, `tests/fuzz/fuzz_adsb_beast.c`.
Format references: readsb's `README-json.md` (wiedehopf/readsb;
dump1090-fa documents the same `aircraft.json`); for SBS, readsb's own
writer, `modesSendSBSOutput()` in `net_io.c` (read at bf8f8fd), its
heartbeat (`sbs_heartbeat`, `MODES_NET_HEARTBEAT_INTERVAL` 60 s), and
its idle rule (`serviceReconnectCallback()`), which drops a silent peer
only on readsb's own outbound connectors that expect an inbound
heartbeat - the SBS output expects none, so a client that never writes,
as sloth's never does, is not dropped. That function cites the BaseStation socket-data reference
it was checked against (`Barebones42_Socket_Data.htm`); that page was
**not** read first-hand here, only through readsb's code, and the live
readsb 3.16 on the reference host's port 30003 was looked at to
confirm the shape. For Beast, readsb's `net_io.c` (bf8f8fd):
`modesSendBeastOutput()`, `netTimestamp()`, `readBeast()`,
`decodeBinMessage()`, `beast_heartbeat_msg`, `sendFiveHeartbeats()`,
`handleBeastCommand()` and the forwarding rule in `outputMessage()`; `mode_s.c` `decodeModesMessage()`,
`decodeExtendedSquitter()`, `decodeESIdentAndCategory()`,
`decodeESAirbornePosition()`, `decodeESAirborneVelocity()`,
`decodeESAircraftStatus()`, `decodeID13Field()`, `decodeAC13Field()`,
`decodeAC12Field()`; `crc.c` (the generator); `cpr.c`
`decodeCPRairborne()`, `decodeCPRrelative()`, `cprNLFunction()`;
`track.c` `cpr_global_airborne_max_elapsed()`; `track.h`
`getSignal()`; `icao_filter.c` with `readsb.c`'s flip every
`MODES_ICAO_FILTER_TTL`. And J. Sun, *The 1090 Megahertz Riddle*
(2nd ed., mode-s.org, open access), its chapters on ADS-B
identification, airborne position, airborne velocity, error control
and Mode S surveillance, whose example messages are the known-answer
tests. ICAO Annex 10 Vol. IV and RTCA DO-260B were **not** read; what
is said here of them comes through those two.

**Last updated**: 2026-11-09 (#186: `--adsb beast://`, the decoder's Beast output, decoded in sloth: CRC, ghost suppression, CPR, the TC 28 emergency word); 2026-11-09 (#186: `--adsb sbs://`, the decoder's SBS output, loopback, read-only; the `AF_INET` drop-in note); 2026-11-08 (#186: `ADSB_EMERGENCY`, flag only; slothweb's ADS-B tab marks an aircraft with an open one; the `packaging/` note on `/run/readsb`); 2026-11-07 (the `[^]` TUI aircraft view, the `adsb` health-strip token, and `gps_bearing_deg()` beside `gps_distance_m()`); 2026-11-05 (`--db`: schema v12, `adsb_aircraft` and `adsb_sightings`; slothweb's "aircraft seen" history and each aircraft's recorded track and altitude profile); 2026-11-05 (slothweb: the ADS-B tab and `/api/adsb`, `web/src/web_adsb.c`, `web/ui/adsb.js`); 2026-11-05 (review: a file already stale when first read is `stale` and takes no rows; the help names `beast://`); 2026-11-05 (slice 1 shipped: feed, state, JSONL).

---

## Where it sits against the seven questions

[[non-ip-sensors]] asks every family seven questions. Slice 1's answers:

1. **Observable passively**: what the decoder already decoded from
   1090 MHz Mode S / ADS-B (and, for readsb, MLAT and TIS-B) — the
   records in `aircraft.json`, the lines on its SBS port, or the raw
   Mode S frames on its Beast port.
2. **Hardware**: an RTL-SDR (or similar) on 1090 MHz feeding readsb or
   dump1090-fa, which the operator runs; sloth needs only the file or
   the port.
3. **State**: `adsb_aircraft_t` keyed by (24-bit address, non-ICAO
   flag), and `adsb_health_t` (`include/sloth.h`).
4. **View**: the `[^]` TUI view (below) and slothweb's ADS-B tab (below).
5. **JSONL / --db**: `adsb_aircraft`, plus `adsb_*` fields on `sensor_health`;
   with `--db`, the `adsb_aircraft` and `adsb_sightings` tables (v12, below)
   and a `sensor` record of kind `adsb`.
6. **Out of scope**: transmitting or interrogating (active radar),
   driving the SDR, writing anything to the decoder, a non-loopback
   SBS or Beast source, and correcting bit errors in a frame.
7. **Testing**: hand-written JSON documents from `README-json.md`
   (`tests/test_adsb.c`), SBS lines written from readsb's
   `modesSendSBSOutput()`, Beast frames built field by field and the
   published examples of *The 1090 Megahertz Riddle*
   (`tests/test_adsb_beast.c`), a temporary file and a loopback
   listener of the test's own for the reader, three libFuzzer
   harnesses; no captured `aircraft.json` and no recorded SBS or Beast
   stream.

## The source

`--adsb /run/readsb/aircraft.json` or
`--adsb file:///run/readsb/aircraft.json`. Only an absolute local path:
`file://HOST/...`, a relative path, any other scheme and a trailing `/`
exit 2. `sbs://` and `beast://` are their own sources (next
sections). Refused with `--replay` (a savefile is not a live decoder). The file need not
exist at startup: a decoder starting after sloth is normal, and reads
as the `error` state until it appears.

The decoder writes the file to a temporary name and renames it over the
old one about once a second (README-json.md), so a reader never sees a
half-written document. The reader (`src/capture/adsb_reader.c`), a
worker started after the privilege drop, therefore **opens the path
afresh every `ADSB_POLL_MS` (1 s)** — a descriptor kept open would keep
reading the replaced inode — `fstat()`s it, refuses anything that is
not a regular file or is over `ADSB_MAX_DOC` (2 MiB), reads it whole and
parses it. A file whose device, inode, size and mtime are all unchanged
since the last read is not parsed again: the decoder has not written.
`O_RDONLY | O_NONBLOCK`: a FIFO placed at the path cannot hang the
worker, and is refused as not a regular file.

## The SBS source (`sbs://`)

`--adsb sbs://127.0.0.1:30003` (or `sbs://`, the same; `sbs://[::1]:PORT`
for IPv6). `HOST` must be a numeric loopback address (`127.0.0.0/8`,
`::1`): a name, a routable address (exit 2, "not loopback") or a port
outside 1..65535 is refused. The decoder is local, as the file one is;
reading a remote decoder is a later decision with its own flag, as
`--gps-allow-remote` is for gpsd, not a default. On startup sloth
announces on stderr that it will connect, to where, and that it sends
nothing (MISSION.md §2: a network-using input is opt-in and
announced).

**Read-only.** The worker (`src/capture/adsb_reader.c`), started after
the privilege drop, makes a non-blocking connect bounded at 3 s and
then only reads: no `send()`, `write()` or `shutdown()` is ever called
on the socket (the connect's handshake is the only thing sloth's side
puts on it). readsb's SBS output ignores what a client sends anyway
(`READ_MODE_IGNORE`). `tests/test_adsb.c ::
test_sbs_reader_session` pins that nothing arrives at the listener.

**Reconnect.** A refused or timed-out connect is a read error (`adsb_err`
"connect: ..."), retried after 2 s, doubling to 30 s while it keeps
failing. A session the decoder closes ("decoder closed the connection")
or a read error is a read error, retried after 2 s. A successful
connect clears the error. Rows stand until they expire, as they do when
`aircraft.json` goes missing.

**Framing.** CRLF-ended lines (a bare LF is taken too), at most
`ADSB_SBS_MAX_LINE` (512) bytes; readsb's are under 260 even with its
extra fields. A partial line waits for the next read. A longer line is
one parse error and is discarded up to its newline, however many reads
it spans. The main thread never touches the socket.

**The line** (`adsb_sbs_parse()`), per readsb's writer: 22 comma-separated
fields, 24 with `--sbs-extra-fields`; anything else is malformed.

| Field | Content | Kept as |
|---|---|---|
| 0 | `MSG` (the other BaseStation records `SEL`, `ID`, `AIR`, `STA`, `CLK` are ignored, not errors; readsb sends none) | - |
| 1 | transmission type 1..8 | the line's type; outside 1..8 is malformed |
| 4 | hex ident, 6 hex digits, `~` prefix for a non-ICAO address | the row key (address, non-ICAO), as `hex` |
| 6, 7 | date and time generated, `YYYY/MM/DD`, `HH:MM:SS.mmm`, UTC | the message time (below) |
| 10 | callsign, 8 characters space padded | `flight`, trimmed |
| 11 | altitude, ft; a trailing `H` is GNSS | `alt_baro`, or `alt_geom` with `H` |
| 12, 13 | ground speed kt, track deg | `gs`, `track` |
| 14, 15 | lat, lon | the position, only as a pair inside ±90 / ±180 |
| 16 | vertical rate ft/min; `H` is GNSS | `baro_rate`, or `geom_rate` with `H` |
| 17 | squawk, 4 digits | `squawk`, only as 4 octal digits |
| 18, 19, 20 | squawk-change alert, squawk emergency, SPI flags | not kept (below) |
| 21 | on ground, `-1` ground / `0` airborne | `on_ground`; a barometric altitude on a ground line is dropped, as aircraft.json's `"ground"` is |
| 22, 23 | RSSI dBFS, category (`A3`), extra fields only | `rssi`, `category` |

readsb fills only what each message carried (1 identification, 2
surface position, 3 airborne position, 4 velocity, 5 surveillance
altitude, 6 surveillance identity, 7 air-to-air, 8 all-call). A number
or date that does not parse is malformed; a well-formed value out of
range leaves its field absent, as in `aircraft.json`. Numbers are
walked digit by digit, never `strtod()`. A malformed line is counted in
`adsb_parse_errors` and sets `adsb_err` until the next good line; it
never stops the reader.

**Merge.** Every MSG line goes through the same sticky merge as an
`aircraft.json` entry, into the same table under the same 256-row cap
and the same expiry. So an MSG,3 position and an MSG,1 callsign for one
address make **one row**, and an empty field never clears a kept one.
The row's `seen` is the read time minus the line's generated time
(never negative; 0 without a time), so `last_seen`, `last_mono_ms`,
the expiry and `ADSB_EMERGENCY`'s hold all run on the aircraft's
message time exactly as they do from `aircraft.json`'s `seen`. A
decoder replaying hour-old lines therefore makes rows that expire on
the next poll.

**What SBS does not carry, and the mapping chosen:**

- **No emergency status word.** Field 19 is a flag, and readsb sets it
  from the 7500 / 7600 / 7700 squawk on the same line (or passes
  another SBS feed's flag through); on MLAT lines readsb reuses fields
  18 and 19 for the receiver count and error estimate. So the flag is
  not read: the squawk is the evidence, and `ADSB_EMERGENCY` fires on
  it as it does for `aircraft.json` (`tests/test_adsb_rules.c ::
  test_sbs_emergency_squawk_fires`). An SBS row's `emergency` stays
  absent - "general" would claim a DO-260B status the aircraft never
  sent - so the view's `emerg` count and the status-word form of the
  rule never see SBS rows. A flag of -1 on an ordinary squawk fires
  nothing (`test_sbs_flag_alone_does_not_fire`).
- **No RSSI** unless readsb runs with `--sbs-extra-fields`.
- **No per-aircraft message count.** A row's `messages` counts the MSG
  lines sloth received for it, and `adsb_messages` the MSG lines in
  all, not the decoder's lifetime Mode S count.
- **No `type`** (`adsb_icao`, `mlat`, ...): `source_type` is written `""`.
- **No airborne transition without an altitude**: a row on the ground
  becomes airborne when a barometric altitude arrives.

**Freshness** for a stream is a line arriving, any line, readsb's
heartbeat (`\r\n` alone, every 60 s to an idle client) included: so an
empty sky stays `live`. `stale` is no line for `ADSB_SBS_STALE_S`
(130 s, past two of readsb's 60 s heartbeat intervals):
connected, but the decoder is hung. `waiting` is configured with no
line yet; `error` as for the file. `adsb_reads` counts MSG lines, and
the `[^]` header labels it `lines` instead of `docs`.

## The Beast source (`beast://`)

`--adsb beast://127.0.0.1:30005` (or `beast://`; readsb's
`--net-bo-port`). The spec, the loopback rule, the announcement, the
read-only client, the 3 s connect and the 2..30 s backoff are the SBS
source's, unchanged (one parser, one reader thread; only the bytes'
consumer differs). readsb's Beast output does read commands from a
client (`READ_MODE_BEAST_COMMAND`, `handleBeastCommand()`: ping,
Mode A/C on/off, a rate reduction); sloth sends none, so it gets the
defaults. `tests/test_adsb_beast.c :: test_beast_reader_session` pins
that nothing arrives at the listener.

**Why decode here at all.** `aircraft.json` and SBS are readsb's
merged view; Beast is the raw frames readsb forwards (`--net-bo-port`
sends what readsb accepted, corrected by at most one bit). Decoding
them gives a second, independent reading of the same air: sloth's own
CRC, its own ghost filter, its own CPR. Where the two disagree, that is
worth seeing. It is also what a Beast-only receiver offers.

**Framing** (`adsb_beast_feed()`, per `modesSendBeastOutput()` and
`readBeast()`): `0x1A`, a type byte, then for `'1'` (Mode A/C), `'2'`
(Mode S short) and `'3'` (Mode S long) a 6-byte big-endian timestamp
of the receiver's 12 MHz clock, one signal byte and 2 / 7 / 14 payload
bytes; every `0x1A` after the type byte is sent doubled. `0x1A 0xE3`
and 8 bytes (a receiver id, only with `--net-receiver-id`) and
`0x1A '5'` and 21 bytes (a Radarcape position, an input-side type in
readsb) are skipped. Any other type, and readsb has no `'4'` on this
path, is one parse error, and the framer hunts for the next `0x1A`. A
run of bytes before a `0x1A` is one parse error. A `0x1A` followed by
anything but `0x1A` inside a frame means the frame was cut short: one
parse error, and that `0x1A` starts the next frame, as `readBeast()`
does. The framer holds at most one frame body (21 bytes) across reads,
so a frame split at any byte, or fed a byte at a time, decodes the
same (`test_framer_escapes_and_splits`).

**Heartbeat and freshness.** readsb's Beast heartbeat is a `'1'` frame
of zeros (`beast_heartbeat_msg`), sent every `--net-heartbeat` seconds
(60 by default) to an idle client and five times on connect
(`sendFiveHeartbeats()`; the five were seen on the reference host).
Mode A/C frames are counted and otherwise ignored. Any frame keeps the
source `live`, so the window is the SBS one: `stale` after 130 s
without a frame.

**What is decoded** (`adsb_beast_decode()`; `mode_s.c` and the Riddle):

| Frame | Taken | Notes |
|---|---|---|
| CRC-24, generator `0x1FFF409` | remainder over the whole frame | 0 for an intact DF11 (II 0), DF17, DF18; for DF4/5/20/21 it is the sender's address. **No bit is ever corrected.** |
| DF17 | only with remainder 0 | confirms its address (below); type `adsb_icao` |
| DF18 | only with remainder 0; CF 0 `adsb_icao_nt`, 1 `adsb_other` (non-ICAO), 2 `tisb_icao` (IMF set: `tisb_trackfile`, non-ICAO), 5 `tisb_other`, 6 `adsr_icao` (IMF: `adsr_other`) | CF 3, 4, 7 not decoded. The IMF bit is read only where readsb reads it (TC 0/9-18/20-22 bit 8, 5-8 bit 21, 19 subtypes 1-4 bit 9, 28 subtype 1 bit 56, 29 bit 51, 31 bit 56); elsewhere it is data. Does **not** confirm an address. |
| DF11 | only with remainder 0 | confirms its address; makes no row. A remainder within the low 7 bits is the interrogator code of the radar it answered (readsb: `IID = crc & 0x7f`): ignored, neither an error nor a confirmation; above them it is a CRC failure. The first live run counted such a reply as `bad` until this was fixed. |
| DF4 / DF20 | only from a confirmed address | the 13-bit AC with Q = 1 (25 ft); Q = 0 (Gillham, 100 ft) and M = 1 (metres) leave the altitude absent |
| DF5 / DF21 | only from a confirmed address | the 13-bit identity, C1 A1 C2 A2 C4 A4 X B1 D1 B2 D2 B4 D4, as the squawk; all zero leaves it absent |
| TC 1-4 | callsign (letters, digits, space; any other code and the callsign is not taken), category (TC 4 `A`, 3 `B`, 2 `C`, 1 `D`, then CA) | |
| TC 5-8 | `on_ground` only | movement and the surface CPR are not decoded |
| TC 9-18 | barometric altitude (Q = 1 only), CPR | |
| TC 20-22 | GNSS altitude as `alt_geom`, CPR | the 12-bit field decoded as readsb does (`decodeAC12Field()`); the Riddle's chapter was not checked on this point |
| TC 19 | subtypes 1/2: ground speed, track; all four: vertical rate (`baro_rate` when the source bit is 1, else `geom_rate`) | subtypes 3/4's heading and airspeed are not kept (the table has no field for them) |
| TC 28 subtype 1 | the emergency/priority word (readsb's `emergency_t`: none, general, lifeguard, minfuel, nordo, unlawful, downed, reserved, which is `ADSB_EMERG_*`) and the Mode A code | |
| DF0, DF16, Comm-D, other TCs | nothing | a DF17 frame of another TC still counts as heard for its row |

**Ghost suppression.** The address/parity replies (DF4/5/20/21) carry
no address of their own: the remainder of the CRC *is* the address,
so any corrupted reply yields a plausible address that never existed.
They are therefore taken only for an address a clean DF17, or a DF11
with remainder 0, vouched for in the last `ADSB_BEAST_CONFIRM_MS`
(60 s). That is readsb's `icaoFilterAdd()` rule (`mode_s.c`, the only
place readsb adds an address); readsb keeps an address 60-120 s (two
tables flipped every `MODES_ICAO_FILTER_TTL`). DF18 does not vouch:
readsb's own comment, "a DF18 transmitter doesn't necessarily have a
Mode S transponder". An address seen only through DF11 and DF4/5 reads
`mode_s`, as in `aircraft.json`; one that has sent ADS-B keeps its
ADS-B type. The suppressed frames are counted in the decoder, not in
`sensor_health` (readsb drops them silently too).

**CPR** (airborne only). A position message stores its even or odd
half. With the other half read within `ADSB_BEAST_CPR_PAIR_MS` (10 s),
the pair is decoded globally (the Riddle's algorithm, NL by its closed
form), and refused when the two latitudes fall in different NL zones.
Otherwise, if the aircraft's own last position is at most 60 s old, the
message is decoded locally against it. Every result, global or local,
is refused when it lies farther from that last position than
0.6 km/s (about 1170 kt) times the seconds elapsed plus 5 km - a
corrupted half that decodes elsewhere does not move the aircraft. A
refused position still counts the frame for its row. readsb widens the
pair window with ground speed up to 30 s
(`cpr_global_airborne_max_elapsed()`); 10 s is the textbook bound. The
sensor's own position (`--gps`, `--location`) is deliberately **not**
used as a reference: a receiver-relative decode is unambiguous only
within 180 NM, and a receiver hears farther, so an aircraft's first
position always comes from a pair.

**Time, RSSI, counts.** The 6-byte timestamp is the receiver's clock,
not the wall, and is never used as a time: a row's `seen` is 0 at the
read (readsb flushes the Beast output every `--net-ro-interval`, 50 ms
on the reference host). The one value read from it is readsb's
`MAGIC_MLAT_TIMESTAMP`, which marks an MLAT result (only with
`--forward-mlat`): such a row's type is `mlat`. RSSI follows readsb:
the signal byte is `round(sqrt(power) * 255)`, read back as
`power = (b / 255)^2`, and the row's `rssi` is
`10 log10(mean power + 1.125e-5)` over its last up to 8 frames with a
non-zero byte (readsb reports the floor until it has 4; sloth does
not). A row's `messages` counts the frames sloth took for it,
`adsb_reads` / `adsb_messages` the frames taken in all (the `[^]`
header labels them `frames`), `adsb_bad_entries` the frames refused by
their CRC, and `adsb_parse_errors` garbage, unknown types and cut
frames.

**Emergency.** A Beast row has a real emergency word, from TC 28, and
a squawk from DF5/21 or TC 28; `ADSB_EMERGENCY` fires on either
(`tests/test_adsb_beast.c :: test_emergency_alert_from_beast`), and a
7700 from an unconfirmed DF5 raises nothing.

**`source_type`** is the type of the frames sloth itself took for the
row, not readsb's best source over the aircraft's history: an address
readsb lists as `mode_s` reads `adsb_icao` here once one clean DF17
from it arrived.

**Checked live** (2026-11-09, reference host, readsb 3.16 on
`127.0.0.1:30005`, 20 s and 60 s runs as uid 1000 against
`aircraft.json` read at the same moment): addresses, callsigns,
squawks, categories, barometric altitudes and speeds matched; a
position matched `aircraft.json` to 1e-5 deg; RSSI within about 3 dB
(different averaging windows over few frames). `adsb_parse_errors` 0.

**Under systemd** the same `AF_INET` drop-in as `sbs://` (below).

## The parser

`adsb_doc_parse()` reads one document: top-level `now`, `messages` and
`aircraft[]`; anything else is skipped. Per aircraft it keeps `hex`
(6 hex digits; a leading `~` is a non-ICAO address such as TIS-B, kept
and flagged, a separate key from the same 24 bits without it), `type`,
`flight` (trailing spaces trimmed; all-blank or over 8 characters is
absent), `squawk` (exactly four octal digits), `alt_baro` (feet, or the
string `"ground"`), `alt_geom`, `gs`, `track`, `baro_rate`,
`geom_rate`, `lat` / `lon` (only as a pair inside ±90 / ±180),
`category` (`A0`..`D7`), `emergency` (one of `none`, `general`,
`lifeguard`, `minfuel`, `nordo`, `unlawful`, `downed`, `reserved`),
`seen`, `seen_pos`, `rssi`, `messages`. A `null`, a value of the wrong
type or one out of range leaves the field absent. Nested arrays and
objects (`mlat`, `tisb`, `nav_modes`, `acas_ra`, `lastPosition`, ...)
are skipped by depth, so `lastPosition`'s stale coordinates are never
taken for the aircraft's. Numbers are walked digit by digit, never
`strtod()` (LC_NUMERIC; the TUI calls `setlocale()`).

Bounds: a document over 2 MiB is a read error. At most
`ADSB_MAX_AIRCRAFT` (256) aircraft are kept; entries past that are
still parsed (the document must balance) and counted in
`adsb_overflow`. An entry with no or a bad `hex`, or one that is not an
object, is counted in `adsb_bad_entries`. A malformed document is
refused whole and counted in `adsb_parse_errors`, once per distinct
file, and the table stands as it was.

## The table, freshness and expiry

Rows are keyed by (address, non-ICAO). The merge is **sticky**: a key
the newest document carries overwrites the row, a key it omits keeps
the row's last value — the decoder already ages its own fields, and a
key flickering out of one document is not news. `first_seen` is the
wall time of the first document that listed the row; `last_seen` is the
read time minus the aircraft's `seen`, so an aircraft the decoder still
lists but last heard 50 s ago is 50 s old here too; `pos_ts` likewise
from `seen_pos`.

**Expiry**: a row unheard for `ADSB_EXPIRE_S` (60 s, the window in
which readsb keeps an aircraft in `aircraft.json` at all) is retired,
on sloth's monotonic clock, in the poll's health stage, and reported
once as `"state":"gone"`. A table full at 256 rows refuses a new
address and counts it in `adsb_overflow`. **A stale file at startup
takes no rows**: an unchanged file is never re-read, so without this
the aircraft a hung decoder last listed would each be written as
`live` (with `last_seen` read time minus `seen`, hours wrong) and
`gone` a minute later. Its rows come in with the first document whose
clock has moved.

**Freshness** is the decoder's own clock: the document's `now` (or,
in a document without one, the file's mtime) moving forward. States:

| `adsb_state` | Meaning |
|---|---|
| `waiting` | configured; no document parsed yet and no failure |
| `live` | the decoder's clock advanced within `ADSB_STALE_S` (10 s); the first document counts as an advance when its clock is at most 10 s behind the host's |
| `stale` | it has not for longer: the file is readable but the decoder stopped writing. Also a first document already more than 10 s old: a decoder that hung before sloth started (`adsb_age_s` -1) |
| `error` | the last attempt failed: missing or unreadable file, not a regular file, over 2 MiB, malformed. Clears on the next good document |

For `sbs://` the clock is a line arriving, and `live` lasts 130 s, not
10 (the SBS section above).

The registry's `adsb` sensor (name "ADS-B decoder", iface the source
label `file:/path` or `sbs:127.0.0.1:30003`, `observed` the documents parsed) reads `error` for
`stale` and `error`, `active` once a document has parsed, `present`
before.

## JSONL: `adsb_aircraft`

One record per aircraft row, keyed by `hex` (`~`-prefixed for a
non-ICAO address). Written on first sight, on a **meaningful** change,
on the 300 s heartbeat while listed, and once as `"state":"gone"` on
expiry. **Never once a second**: the signature (`adsb_row_sig()`) takes
the identity, `first_seen` (a row that expired and came back is new),
the held altitude band, the held position cell, whether there is a
position, squawk, emergency, callsign and category — never the raw
altitude, position, speed, track, rates, RSSI, `seen` or message count,
each of which moves every second. `source_type` is written, not signed:
readsb's best source flips between `adsb_icao`, `mlat` and `mode_s` as
coverage comes and goes.

**Altitude bands** (`alt_band`; barometric altitude, else geometric):

| Band | Altitude |
|---|---|
| -2 | on the ground (`alt_baro` `"ground"`) |
| -1 | unknown |
| 0..9 | below 9,750 ft: `floor((alt + 250) / 1000)`, one band per 1,000 ft with edges at x,750 ft (below -250 ft is 0) |
| 10.. | from 9,750 ft: `10 + (alt - 9750) / 4000`, one band per 4,000 ft, edges at 13,750, 17,750, ... |

Every edge sits 250 ft from both the whole thousands (IFR levels) and
the x,500 levels (VFR cruising), where aircraft fly level for a long
time. On top of that the band is **held with 100 ft hysteresis**
(`ADSB_ALT_HYST_FT`): it moves only once the altitude is past the old
band's edge by 100 ft, so 25 ft altitude quanta dithering on an edge do
not write a line each. A jump of several bands, and to or from the
ground, moves at once. A climb from the ground to FL370 is about 15
records.

**Position cells**: 0.1° of latitude and of longitude (about 11 km of
latitude), held until the position leaves the held cell grown by
0.01° (about 1 km) on every side (`ADSB_CELL_HYST_DEG`). A jet at
cruise crosses a cell every one to two minutes.

So the rate is bounded by movement, not by the decoder's cadence: an
aircraft holding level and course in one cell is one record per 300 s
heartbeat. `tests/test_adsb.c` pins it: five documents with speed,
track, RSSI, message count and `now` moving every second, the altitude
wiggling ±25 ft and once 50 ft past an edge, the position moving inside
its cell — one record.

Fields: `hex`, `non_icao`, `state` (`live` / `gone`), `src` (the source
label), `source_type`, `flight`, `squawk`, `category`, `emergency` (`""`
when the decoder sent none), `on_ground`, `alt_baro`, `alt_geom` (ft,
each only when known), `alt_band`, `gs` (kt), `track` (°), `baro_rate`,
`geom_rate` (ft/min), `lat` / `lon` (five decimals) with `pos_ts`, `rssi`
(dBFS), `messages`, `first_seen`, `last_seen`. Absent figures are
omitted, never written as 0. Without `%f` (locale). Full row in
[[jsonl-schema]].

## `sensor_health`

Appended, and present **only** with `--adsb`: `adsb_state`, `adsb_src`,
`adsb_age_s` (since the decoder's clock last advanced, -1 never),
`adsb_last_read`, `adsb_aircraft` (rows now), `adsb_messages` (the
decoder's lifetime Mode S count), `adsb_reads`, `adsb_read_errors`,
`adsb_parse_errors`, `adsb_overflow`, `adsb_bad_entries`,
`adsb_expired`, `adsb_err`. The signature takes `adsb_state` and
none/some bands of the four tallies and of the error; the age, the
counts and the decoder's message total move every second and are
written, not signed.

## Privacy

The receiver's position is the operator's to protect: aircraft near the
receiver locate it roughly. The records go to the operator's own JSONL
sink only. Tests and documentation carry invented addresses, callsigns
and positions, never a receiver's.

## slothweb

The ADS-B tab (2026-11-05) reads the `adsb_aircraft` records and the
`adsb_*` block of `sensor_health` off the data socket and keeps them in
memory (`web/src/web_adsb.c`, `/api/adsb`): up to 512 rows, a gone row
kept dimmed for 600 s, a live row with no record for 660 s dropped as
aged, each row's last 32 positions as its track. The page
(`web/ui/adsb.js`) draws the decoder's health line, the aircraft table,
a north-up position plot with the tracks coloured by altitude (no map
tiles, nothing fetched) and a detail panel. Because the records are
change-only, a row's altitude and position are as of its last record:
within its band and cell, not the decoder's latest second. The SDR is a
passive radio, so the records are Monitor's, as BLE's are; under Local
the tab shows its scope note. Full description in
[`web/README.md`](../../web/README.md#ads-b).

## `--db`: `adsb_aircraft` and `adsb_sightings` (schema v12)

With `--db` and `--adsb`, `write_adsb()` (`src/db.c`) records the
aircraft on the record's own change-only rule (`adsb_row_sig()`, or the
300 s heartbeat), with its own change memory: one `adsb_sightings` row
per write (time, the decoder's last-heard time, callsign, squawk,
emergency, category, on-ground, both altitudes, band, speed, track,
vertical rate, position, RSSI, messages, source) and one upsert of the
`adsb_aircraft` inventory row for the address: earliest first seen,
latest last seen, `visits` (one more each time sloth's own `first_seen`
moves, i.e. the row expired and the address came back), `sightings`,
the newest non-empty callsign, squawk, category and source, the
altitude range, top ground speed, strongest RSSI, whether a position
or an emergency was ever reported. `adsb_sightings` is in the
observation tier, `adsb_aircraft` in the entity tier (3× retention).
The v11 → v12 step is a stamp; [[sqlite-schema]] has the columns.

slothweb reads them (`web/src/web_rfhist.c`, through the allow-list):
`/api/adsb/seen?days=&limit=&offset=&q=` the inventory rows last seen
in the window (7 days by default, up to 400; 100 a page; `q` a hex or
callsign prefix, letters and digits only) and
`/api/adsb/aircraft?hex=&days=` one aircraft's row and its sightings
(at most 400, oldest first, compact rows named in `cols`). The ADS-B
tab shows the first as the "aircraft seen" table and the second in the
detail panel: the inventory figures, every callsign and squawk it used,
an altitude profile over time (emergencies ringed), and the recorded
track dashed on the positions plot, also for an aircraft the decoder no
longer lists. Monitor's and Hybrid's, as the live panel is.

## The `[^]` TUI view

`[^]` draws the table (`src/views/adsb.c`,
[`docs/views/adsb.md`](../views/adsb.md) has the mockup and the
column notes): one row per address, **freshest first** by the
decoder's own last-heard time with the address as the tie-break, over
a header of the decoder's state, the aircraft count, the aircraft
reporting an `emergency`, the decoder's lifetime message total, how
long since its clock last advanced, the source label and the read /
parse / overflow / bad / expired tallies. Columns: ICAO, callsign,
squawk, altitude (barometric, else geometric, else `ground`), ground
speed, track, RSSI, age, and a width-flexing RSSI bar over -30..0
dBFS. A row the decoder still lists but has not heard from for 30 s or
more is dim. The cursor follows the aircraft across the re-sort, not
the row index. The key is `^` because every letter and digit already
selects a view, `*` is BLE and `#` is GNSS.

**Distance and bearing are drawn only when the sensor's own position
is known** — `gps_location_current()` returning a stamp, so a
`--location` or a fresh `--gps` fix. Range is `gps_distance_m()` in
kilometres and direction `gps_bearing_deg()` (added beside it,
2026-11-07: the initial great-circle bearing in degrees true, with
identical, antipodal and dateline-crossing pairs pinned in
`tests/test_gps.c`). Without a sensor position the two columns are
absent rather than drawn empty, and the legend says why; with one, a
row the decoder has sent no position for reads `-` in both while the
columns stand, because what is missing there is the aircraft's
position and not the sensor's.

The view is **observation**: it grades nothing and counts the
`emergency` rows rather than judging them. `--adsb` also adds an
`adsb` token to the Interfaces health strip beside `gps` — opt-in,
the state always, the aircraft count while live, the stalled age and
the reader's error on fault — because a feed that stopped looks the
same as quiet sky at the terminal.

## `ADSB_EMERGENCY` (#186)

An aircraft listed while the source is `live` with squawk **7500**,
**7600** or **7700** (SERA.13005: unlawful interference,
radio-communication failure, emergency), or an emergency/priority status
other than `none` (`general`, `lifeguard`, `minfuel`, `nordo`,
`unlawful`, `downed`, `reserved`), raises `ADSB_EMERGENCY`
(`src/alerts/rules_adsb.c`). One incident per address and condition -
the code when there is one, else the status word - so a code change
re-fires and a steady one does not. LOW on first sight, WARN once the
condition has held `adsb.emerg_hold_s` (10 s) of the aircraft's own
message time, never CRIT.

**Flag only.** sloth surfaces the declaration and never acts on it. It
is a third party's state, not the operator's network's, and ADS-B is
unauthenticated: a false alarm can be injected (Schäfer et al. 2013
§3.2) and one receiver cannot tell it from a real one. The view above
still counts emergency rows without judging them; the judgement is the
rule's. Basis and the persistence argument: [[alerts]] § ADS-B,
`research/adsb/emergency-squawks.md`, and the assessment
`alert-assessments/ADSB_EMERGENCY.md`.

## Running beside readsb under systemd

No unit change: `sloth-sensor.service`'s `ProtectSystem=strict` leaves
`/run` readable, and the reference host's readsb leaves `/run/readsb`
0755 and `aircraft.json` 0644 (checked 2026-11-08), so the `sloth` user
reads it. Add `--adsb /run/readsb/aircraft.json` to `SLOTH_ARGS` in
`/etc/default/sloth` (`packaging/default/sloth` says the same). A
decoder writing under `/home` would need `ProtectHome=` relaxed in a
drop-in.

`sbs://` and `beast://` **do** need a unit change: the shipped unit's
`RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_PACKET` has no IP
family, so the connect fails with `socket: Address family not
supported by protocol` (a read error, retried) until a drop-in adds
`RestrictAddressFamilies=AF_INET` (`AF_INET6` too for `[::1]`). The
lists merge, so it widens the unit by exactly that. The `gps.conf`
drop-in's commented gpsd block is that line
(`packaging/systemd/sloth-sensor.service.d/gps.conf`, installed inert
at `/usr/local/share/sloth/sloth-sensor-gps.conf`); uncommented and
copied to `/etc/systemd/system/sloth-sensor.service.d/`, it serves
`--adsb sbs://` and `beast://` as well. The unit sets no `IPAddressDeny=`, so nothing
else is needed. `packaging/default/sloth` says the same.

## Pending (later slices)

An opt-in for a non-loopback SBS or Beast source; from Beast, the
surface position (TC 5-8 movement and CPR), Gillham (Q = 0) altitudes,
DF0/DF16 (ACAS) and Comm-B (DF20/21 MB) contents, and a receiver-relative
CPR decode bounded by a configured range.

## Related pages

- [[non-ip-sensors]] — the family roadmap and the seven questions.
- [[jsonl-schema]] — the `adsb_aircraft` record and `sensor_health`'s `adsb_*` fields.
- [[cli-reference]] — `--adsb`.
- [[gnss]] / [[location]] — the GPS family this one follows.
