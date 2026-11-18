#ifndef SLOTH_APRS_H
#define SLOTH_APRS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* ── APRS stations: --aprs (2026-11-05) ───────────────────────────
 *
 * sloth tails the packet log a local, already-running Dire Wolf writes
 * (`direwolf -L FILE`) and turns each line into a typed packet
 * (aprs_packet_t, include/sloth.h) and a per-station row. It never
 * opens, tunes or talks to the radio, the SDR or Dire Wolf, and uses no
 * network: the source is a file path. Receive-only, as the decoder is.
 *
 *   --aprs /var/lib/direwolf/aprs.log
 *   --aprs file:///var/lib/direwolf/aprs.log
 *
 * This file is the pure half - the line parser, the spec parser, and
 * the table the reader (src/capture/aprs_reader.c) feeds and the poll
 * copies out. Nothing here does I/O.
 *
 * Source: Dire Wolf User Guide ("Logging") and src/log.c (wb2osz/
 * direwolf, 1.7). log_write() writes one record per decoded packet as
 * a single fprintf of 22 comma-separated fields and "\n", then
 * fflush(); a header line names them once, when the file is created:
 *
 *   chan,utime,isotime,source,heard,level,error,dti,name,symbol,
 *   latitude,longitude,speed,course,altitude,frequency,offset,tone,
 *   system,status,telemetry,comment
 *
 * The text fields (name, symbol, dti, system, status, telemetry,
 * comment) pass through quote_for_csv(): wrapped in double quotes only
 * when they hold a ',' or a '"', an embedded '"' doubled, nothing else
 * escaped. source and heard are written raw. speed is knots ("%.1f",
 * converted from mph), course degrees, altitude metres (converted from
 * feet), latitude / longitude "%.6f"; an unknown field is empty. The
 * data type indicator (dti) and the two-byte symbol (table, code) are
 * APRS 1.0.1's (APRS101.pdf, ch. 5 and ch. 20 / appendix 2).
 *
 * Every line is hostile: the comment is free text from anyone with a
 * transmitter, and since nothing but ',' and '"' is escaped a CR or LF
 * inside one splits its record. A fragment that does not parse is a
 * bad line, counted. A fragment that does parse cannot be told from a
 * record (docs/wiki/aprs.md says what that lets a sender forge: the
 * heard, level and channel columns; APRS itself authenticates
 * nothing, so the source and position were never proof anyway). */

#define APRS_EXPIRE_S    3600  /* a station unheard this long is retired ("gone") */
#define APRS_POLL_MS     1000  /* the reader checks the file this often */
#define APRS_POLL_BYTES  (256u * 1024u)  /* read at most this much a poll */
#define APRS_MAX_LINE    1024  /* a longer line is bad, skipped to its newline */
#define APRS_FIELDS      22

/* ── One line ──────────────────────────────────────────────────── */

/* Parse one line (no newline; a trailing CR is ignored) into *out.
 * 1 a packet, 0 a line to skip (blank, or Dire Wolf's header), -1 bad:
 * not exactly APRS_FIELDS fields, a quote out of place, a channel or
 * utime out of range, a source (or a non-empty heard) that is not a
 * callsign. A field that is present but out of range or malformed is
 * absent, never clamped: lat / lon only as a pair inside -90..90 /
 * -180..180, speed 0..2000 kt, course 0..360, altitude -1000..100000 m,
 * symbol exactly two printable bytes, dti one. Text fields keep
 * printable ASCII (0x20-0x7e), every other byte becomes '?', and are
 * cut at APRS_TEXT_MAX (comment APRS_COMMENT_MAX). Locale-free: no
 * strtod. */
int  aprs_line_parse(const char *line, size_t n, aprs_packet_t *out);

/* An AX.25 callsign as APRS writes it: 1-6 of [A-Z0-9], then optionally
 * '-' and 1-2 of [A-Z0-9] (the SSID; APRS-IS allows letters). */
int  aprs_call_ok(const char *s);

/* ── The --aprs SPEC ───────────────────────────────────────────── */

/* An absolute path, or file:///absolute/path (file://HOST/ refused);
 * any other scheme or a relative path is refused. 0 with the path, -1
 * with a reason in err. */
int  aprs_spec_parse(const char *spec, char *path, size_t pathsz,
                     char *err, size_t errsz);

/* ── The table ─────────────────────────────────────────────────── *
 * One mutex: the reader feeds, the main thread polls. */

/* Declare the source and its label ("file:/var/lib/direwolf/aprs.log");
 * the state is WAITING until the file is read. */
void aprs_set_source(const char *label);

/* One complete line read at host `wall` / `mono_ms`: counted, parsed,
 * and a packet fed. Returns aprs_line_parse()'s answer. */
int  aprs_feed_line(const char *line, size_t n, time_t wall, uint64_t mono_ms);

/* A parsed packet: into the ring (APRS_PKT_RING, the newest kept, each
 * given the next seq) and merged into its station, keyed by source. A
 * new station past APRS_MAX_STATIONS is refused and counted; its packet
 * still reaches the ring. Sticky merge: a position (with the speed,
 * course and altitude it came with) is replaced only by a packet that
 * carries one, a symbol, comment, status or system only by a non-empty
 * one. An object or item (dti ';' or ')', APRS101 ch. 11) describes the
 * thing it names, not its sender, so its position, symbol and comment
 * do not touch the sending station; the packet carries them. */
void aprs_feed_packet(const aprs_packet_t *p, time_t wall, uint64_t mono_ms);

/* The reader's poll outcome. A good poll clears the error and the
 * missing flag; `missing` is the file not there (Dire Wolf creates it
 * on its first packet), a state, not an error; a read error counts. */
void aprs_note_read(time_t wall, uint64_t bytes, int rotated, int truncated);
void aprs_note_missing(void);
void aprs_note_read_error(const char *err);
/* An overlong line, skipped by the reader: one bad line. */
void aprs_note_bad_line(void);

/* Retire stations unheard for APRS_EXPIRE_S (by the monotonic clock),
 * then copy the health, the table, the stations just retired and the
 * packet ring into s. PH_PLATFORM, beside adsb_health_poll(), and after
 * gps_health_poll(): the region comes from this tick's s->gps (the
 * arbitrated position: a fresh fix, else --location). Only the region
 * and its frequency are kept, never the position. With no position the
 * region last derived this run is held (a sensor does not change
 * continent between fixes, and a GPS dropout must not flap it). */
void aprs_health_poll(sloth_state_t *s, time_t wall, uint64_t mono_ms);

/* ── The region and the decoder's frequency (#204, 2026-11-13) ────
 *
 * APRS has no one channel: each region's national societies chose one
 * 2 m frequency, and a decoder on the wrong one hears nothing at all.
 * sloth cannot tell which one Dire Wolf is on (it reads a file), so it
 * derives what the channel SHOULD be from where the sensor is, and the
 * operator may declare what the decoder IS configured for
 * (--aprs-freq). A disagreement is reported, never acted on: sloth
 * never touches the radio.
 *
 * The table is the owner's (#204): the regional APRS channels as
 * aprs.org's frequency list and the national band plans give them
 * (ARRL / TAPR, the IARU Region 1 VHF band plan, WIA, NZART, JARL,
 * LABRE). Anywhere else has no entry: sloth names no default rather
 * than guess one.
 *
 * The boxes are coarse rectangles, checked most specific first. They
 * are right in the interior of each region and approximate near a
 * border (a point in Paraguay can read "brazil", one on Ulleungdo
 * "japan"); a sensor near a border is what --aprs-freq is for. */
typedef enum {
    APRS_REGION_NONE = 0,      /* no position: nothing to derive from */
    APRS_REGION_UNKNOWN,       /* a position outside every box: no default */
    APRS_REGION_NA,            /* North America, 144.390 */
    APRS_REGION_IARU1,         /* IARU Region 1 (Europe, Africa, the Middle East, Russia), 144.800 */
    APRS_REGION_AU,            /* Australia, 145.175 */
    APRS_REGION_NZ,            /* New Zealand, 144.575 */
    APRS_REGION_JP,            /* Japan, 144.640 */
    APRS_REGION_BR             /* Brazil, 145.570 */
} aprs_region_t;

/* The region a position falls in. Pure: has_fix 0, or a latitude /
 * longitude that is not finite or outside +-90 / +-180, is NONE; a
 * position in no box is UNKNOWN. */
int         aprs_region_of(int has_fix, double lat, double lon);
/* Its APRS frequency in Hz; 0 for NONE and UNKNOWN. */
uint32_t    aprs_region_hz(int region);
/* "none", "unknown", "north-america", "iaru-r1", "australia",
 * "new-zealand", "japan", "brazil". Part of the sensor_health
 * contract. */
const char *aprs_region_name(int region);

/* --aprs-freq HZ: what the decoder is configured for, in the 2 m band
 * (144..148 MHz), or 0. The CONFIGURED value (/etc/default/aprs's
 * APRS_FREQ on the reference host), not rx_fm's hardware tune, which
 * sits fs/4 above it and is normal. */
#define APRS_FREQ_MIN_HZ   144000000u
#define APRS_FREQ_MAX_HZ   148000000u
/* A declared frequency within this of the region's is the same channel.
 * Half of 12.5 kHz, the narrowest 2 m channel spacing in the six band
 * plans: anything further off is another channel. */
#define APRS_FREQ_TOL_HZ   6250u
/* Parse an --aprs-freq argument: decimal Hz only, in range. 0 or -1. */
int  aprs_freq_parse(const char *s, uint32_t *out);
/* 1 when both are known and further apart than APRS_FREQ_TOL_HZ. */
int  aprs_freq_mismatch(uint32_t declared_hz, uint32_t region_hz);

/* A silent decoder: the log configured and readable (live) and no
 * packet for this long.
 *
 * Why 6 h: the existing state says an hour of quiet is normal (a fixed
 * station beacons every 10 to 30 minutes, the New-N paradigm's
 * guidance for a fixed station being 30 minutes; a rural site can hear
 * one station). Digipeaters and igates beacon
 * their own position on that cadence all day, so a receiver that hears
 * even one of them hears something in any 6 h window. Six hours is six
 * times the quiet hour sloth already tolerates, short enough to catch a
 * dead receive chain the same day, and far from a single quiet night
 * hour. The reference host's log sat at 0 bytes for two days
 * (2026-11-11 to 13) and nothing said so. --aprs-silent-hours sets it;
 * 0 turns it off. */
#define APRS_SILENT_S_DEFAULT  (6 * 3600)
#define APRS_SILENT_H_MAX      168   /* a week */

/* The run's settings: the declared frequency (0 none) and the silence
 * threshold in seconds (0 off). Before the reader starts; aprs_reset()
 * restores the defaults (0 Hz, APRS_SILENT_S_DEFAULT). */
void aprs_set_expect(uint32_t freq_hz, int silent_after_s);

/* Back to nothing configured. Tests and sloth_reset_all(). */
void aprs_reset(void);

/* "none", "waiting", "live", "error". */
const char *aprs_state_name(int state);

/* ── Change-only (agents/AGENTS.md: a continuous value enters a
 * signature as its band, never itself) ─────────────────────────────
 *
 * Position: a 0.01 degree cell (about 1.1 km of latitude), held until
 * the position leaves the held cell grown by APRS_CELL_HYST_DEG (0.001,
 * about 110 m) on every side, so a fixed station's GPS wander on a cell
 * edge writes nothing. */
#define APRS_CELL_HYST_DEG 0.001

/* The aprs_station record's change signature: the call, first_seen (a
 * station that expired and came back is a new row), the held cell,
 * has_pos, the symbol, and heard_direct. Never the packet count, the
 * last-heard time, the level, the via, speed, course, altitude or the
 * comment: each can move with every packet, and every packet is its
 * own aprs_packet record already. */
uint64_t aprs_station_sig(const aprs_station_t *a);

#endif /* SLOTH_APRS_H */
