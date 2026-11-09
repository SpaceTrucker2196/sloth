#ifndef SLOTH_ADSB_H
#define SLOTH_ADSB_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"

/* ── ADS-B aircraft: --adsb (#26 slice 1, 2026-11-05) ─────────────
 *
 * sloth tails the aircraft.json a local, already-running decoder
 * (readsb, dump1090-fa) writes, and turns it into typed rows
 * (adsb_aircraft_t, include/sloth.h). It never opens, tunes or talks to
 * the SDR, and it uses no network: the source is a file path.
 *
 *   --adsb /run/readsb/aircraft.json
 *   --adsb file:///run/readsb/aircraft.json
 *   --adsb sbs://127.0.0.1:30003     (2026-11-09, below)
 *
 * sbs:// is the decoder's SBS / BaseStation TCP output, read by a
 * client that never writes a byte to the socket, loopback only. Beast
 * (beast://) is refused with a "not yet supported" error.
 *
 * This file is the pure half - the document parser, the spec parser,
 * and the table the reader (src/capture/adsb_reader.c) feeds and the
 * poll copies out. Nothing here does I/O.
 *
 * Source: readsb's README-json.md (wiedehopf/readsb; dump1090-fa's
 * README-json.md documents the same aircraft.json): a single JSON
 * object with "now" (unix seconds, fractional), "messages" (the
 * decoder's lifetime Mode S message count) and "aircraft", an array of
 * objects whose keys "will be omitted if data is not available": hex
 * (24-bit address as 6 hex digits, a leading '~' marking a non-ICAO
 * address such as TIS-B), type, flight (8 chars, space padded),
 * alt_baro (feet, OR the string "ground"), alt_geom, gs (knots), track
 * (degrees), baro_rate / geom_rate (ft/min), squawk (4 octal digits),
 * emergency (none, general, lifeguard, minfuel, nordo, unlawful,
 * downed, reserved), category (A0..D7), lat / lon, seen / seen_pos
 * (seconds before "now"), messages, rssi (dBFS, always negative). The
 * file is written to a temporary name and renamed into place about
 * once a second, so a reader sees a whole document; an aircraft is
 * listed only while a message from it arrived in the last 60 s. */

#define ADSB_MAX_DOC     (2u * 1024u * 1024u)  /* bytes; a larger file is a read error */
#define ADSB_EXPIRE_S    60    /* a row unheard this long is retired ("gone") */
#define ADSB_STALE_S     10    /* the decoder's clock not advancing this long is stale */
#define ADSB_POLL_MS     1000  /* the reader re-reads the file this often */

/* ── The document ──────────────────────────────────────────────── */

typedef struct {
    int      has_now;
    double   now;
    int      has_messages;
    uint64_t messages;
    int      n;                 /* rows kept in ac[] */
    int      overflow;          /* valid entries past ADSB_MAX_AIRCRAFT, parsed and dropped */
    int      bad;               /* entries refused: not an object, no or bad hex */
    adsb_aircraft_t ac[ADSB_MAX_AIRCRAFT];
} adsb_doc_t;

/* Parse one aircraft.json document in buf[0..n). 0 on success, -1 when
 * it is not one balanced JSON object or is over ADSB_MAX_DOC. Unknown
 * keys are skipped, nested arrays and objects (mlat, tisb, nav_modes,
 * acas_ra, lastPosition, ...) by depth; a null, or a value of the wrong
 * type or out of range, leaves the field absent. lat / lon are kept
 * only as a pair inside -90..90 / -180..180. Locale-free: no strtod. A
 * malformed document is refused whole - the decoder renames complete
 * files into place, so a broken one is not worth half-reading. */
int  adsb_doc_parse(const char *buf, size_t n, adsb_doc_t *out);

/* "a1b2c3" or "~a1b2c3" (either case). 0 with the address and the
 * non-ICAO flag, -1 otherwise. */
int  adsb_hex_parse(const char *s, uint32_t *icao, int *non_icao);

/* The emergency names in README-json.md; "" for ADSB_EMERG_ABSENT. */
const char *adsb_emergency_name(int e);

/* ── The --adsb SPEC ───────────────────────────────────────────── */

enum { ADSB_SPEC_FILE = 1, ADSB_SPEC_SBS };

#define ADSB_SBS_DEFAULT_PORT 30003

typedef struct {
    int  kind;                  /* ADSB_SPEC_* */
    char path[256];             /* FILE */
    char host[64];              /* SBS: a numeric loopback address */
    int  port;                  /* SBS */
} adsb_spec_t;

/* An absolute path, or file:///absolute/path (file://HOST/ refused), or
 * sbs://[HOST[:PORT]] with HOST a numeric loopback address (127.0.0.0/8,
 * [::1]; default 127.0.0.1:30003): the decoder is local, as the file
 * one is, and a remote one is a later decision, not a default.
 * beast:// is refused as not yet supported, any other scheme or a
 * relative path as malformed. 0 with out filled, -1 with a reason in
 * err. */
int  adsb_spec_parse(const char *spec, adsb_spec_t *out,
                     char *err, size_t errsz);

/* "file:/run/readsb/aircraft.json" / "sbs:127.0.0.1:30003" /
 * "sbs:[::1]:30003": the source label sensor_health and the registry
 * carry. */
void adsb_spec_label(const adsb_spec_t *sp, char *out, size_t outsz);

/* ── SBS / BaseStation lines (sbs://) ──────────────────────────────
 *
 * Source: readsb net_io.c modesSendSBSOutput() (wiedehopf/readsb,
 * read at bf8f8fd), which cites the BaseStation socket-data reference
 * it was checked against (Barebones42_Socket_Data.htm). One CRLF-ended
 * line per decoded message, comma separated, 0-based fields:
 *
 *   0 "MSG"  1 transmission type 1..8  2 session id  3 aircraft id
 *   4 hex ident (6 hex digits, readsb prefixes '~' for a non-ICAO
 *     address)  5 flight id  6 date generated (YYYY/MM/DD, UTC)
 *   7 time generated (HH:MM:SS.mmm, UTC)  8 date logged  9 time logged
 *   10 callsign (8 chars, space padded)  11 altitude ft (a trailing 'H'
 *   is geometric, readsb with GNSS altitudes on, else barometric)
 *   12 ground speed kt  13 track deg  14 lat  15 lon  16 vertical rate
 *   ft/min ('H' as for altitude)  17 squawk (4 digits)  18 squawk-change
 *   alert flag  19 squawk emergency flag  20 SPI (ident) flag
 *   21 on-ground flag (-1 ground, 0 airborne)
 *   readsb --sbs-extra-fields adds 22 RSSI dBFS and 23 category ("A3").
 *
 * A field is empty when the message did not carry it. Flags are -1 for
 * true. readsb overloads 18 and 19 with the MLAT receiver count and
 * error estimate on MLAT lines, so neither is read here: 18/20 carry
 * nothing the table keeps, and 19 is readsb's own derivation of the
 * 7500/7600/7700 squawk on the same line (or a passthrough of another
 * SBS feed's flag) - the squawk is taken instead, and the emergency
 * status word aircraft.json has (general, lifeguard, ...) is never
 * invented from it: SBS rows carry emergency ABSENT. SBS has no RSSI
 * (unless extra fields) and no per-aircraft message count: the row's
 * messages counts the MSG lines sloth received for it.
 *
 * readsb writes "
" alone as a heartbeat to an idle SBS client every
 * 60 s by default (net_io.c sbs_heartbeat, MODES_NET_HEARTBEAT_INTERVAL)
 * and itself drops a client silent for twice that. */
#define ADSB_SBS_MAX_LINE 512   /* bytes, newline excluded; readsb's are under 260 */
#define ADSB_SBS_STALE_S  130   /* past 2 x readsb's 60 s heartbeat: a live
                                 * decoder sends a line, if only that,
                                 * within it even under an empty sky */

typedef struct {
    adsb_aircraft_t ac;         /* the fields the line carried */
    int     type;               /* 1..8 */
    int     has_time;
    int64_t time_ms;            /* fields 6/7, unix ms (UTC) */
} adsb_sbs_msg_t;

/* One line, without its newline (a trailing '\r' is allowed). 1 for a
 * MSG line parsed into out; 0 for a line carrying nothing for the
 * table - empty (readsb's heartbeat) or another BaseStation record
 * (SEL, ID, AIR, STA, CLK); -1 malformed: not 22..24 fields, a type
 * outside 1..8, a bad hex ident, a number or date that does not parse.
 * A well-formed value out of range leaves its field absent, as in
 * aircraft.json. Locale-free. */
int  adsb_sbs_parse(const char *line, size_t n, adsb_sbs_msg_t *out);

/* The reader's line framer: bytes in, whole lines out, each parsed and
 * fed to the table at host `wall_ms` / `mono_ms`. A line over
 * ADSB_SBS_MAX_LINE is one parse error and is discarded to its newline;
 * a partial line waits for the next read. Worker-owned. */
typedef struct {
    char   buf[ADSB_SBS_MAX_LINE + 1];
    size_t len;
    int    overlong;
    adsb_sbs_msg_t msg;
} adsb_sbs_lines_t;

void adsb_sbs_lines_init(adsb_sbs_lines_t *l);
void adsb_sbs_lines_feed(adsb_sbs_lines_t *l, const uint8_t *data, size_t n,
                         int64_t wall_ms, uint64_t mono_ms);

/* ── The table ─────────────────────────────────────────────────── *
 * One mutex: the reader feeds, the main thread polls. */

/* Declare the source and its label ("file:/run/readsb/aircraft.json");
 * the state is WAITING until a document parses. */
void adsb_set_source(const char *label);
/* The same for an SBS stream: freshness is then a line (any line,
 * heartbeat included) arriving within ADSB_SBS_STALE_S, not a document
 * clock advancing within ADSB_STALE_S. */
void adsb_set_source_sbs(const char *label);

/* One SBS MSG line read at `wall_ms` / `mono_ms`: merged into its row
 * (created as adsb_feed_doc() creates one, under the same cap) with the
 * same sticky rule, so an MSG,1 callsign and an MSG,3 position for one
 * address make one row. The row's seen is the read time minus the
 * line's generated time (fields 6/7), never negative; without a time,
 * 0. Counts a read, marks the source alive and clears the error. */
void adsb_feed_sbs(const adsb_sbs_msg_t *m, int64_t wall_ms, uint64_t mono_ms);
/* A line that carried nothing for the table (heartbeat, other record):
 * the source is alive. Clears the error. */
void adsb_note_sbs_alive(int64_t wall_ms, uint64_t mono_ms);
/* The SBS session opened: clears the error the last failure left (the
 * state is then waiting or stale until a line arrives). */
void adsb_note_connected(void);

/* Merge a parsed document read at host `wall` / `mono_ms`. Each row is
 * keyed by (icao, non_icao); last_seen is wall - seen, so a decoder
 * still listing an aircraft it has not heard for 50 s does not keep it
 * young. A new address past ADSB_MAX_AIRCRAFT rows is refused and
 * counted. The decoder's clock ("now", else `stamp`, the file's mtime)
 * advancing is what keeps the source LIVE. The first document has shown
 * no advance: if its clock is already more than ADSB_STALE_S behind
 * `wall` (the decoder is local, so the clock is the host's) it was left
 * by a decoder that stopped before sloth started - the source reads
 * STALE and no row is taken until the clock moves. Clears the error. */
void adsb_feed_doc(const adsb_doc_t *d, double stamp, time_t wall,
                   uint64_t mono_ms);

/* The reader's failures: a read error (missing, unreadable, not a
 * regular file, oversize) or a document that would not parse. Both
 * leave the table as it was and set the error the state reports. */
void adsb_note_read_error(const char *err);
void adsb_note_parse_error(const char *err);

/* Retire rows unheard for ADSB_EXPIRE_S (by the monotonic clock), then
 * copy the health and the table into s (s->adsb, s->adsb_rows /
 * adsb_count, and the rows just retired as s->adsb_gone /
 * adsb_gone_count). PH_PLATFORM, beside gps_health_poll(). */
void adsb_health_poll(sloth_state_t *s, time_t wall, uint64_t mono_ms);

/* Back to nothing configured. Tests and sloth_reset_all(). */
void adsb_reset(void);

/* "none", "waiting", "live", "stale", "error". */
const char *adsb_state_name(int state);

/* ── Change-only bands (agents/AGENTS.md: a continuous value enters a
 * signature as its band, never itself) ─────────────────────────────
 *
 * Altitude: -2 on the ground, -1 unknown; below 9,750 ft one band per
 * 1,000 ft, floor((alt + 250) / 1000), so the edges sit at x,750 ft;
 * from 9,750 ft one band per 4,000 ft, 10 + (alt - 9750) / 4000, edges
 * at 13,750, 17,750, ... Every edge sits 250 ft from both the IFR
 * levels (whole thousands) and the VFR ones (x,500), where an aircraft
 * flies level. The table holds the band with a 100 ft hysteresis
 * (ADSB_ALT_HYST_FT): a held band moves only once the altitude is
 * beyond the old band's edge by that much, so 25 ft altitude quanta
 * dithering on an edge do not write a line each.
 *
 * Position: a 0.1 degree cell (about 11 km of latitude), held until the
 * position leaves the held cell grown by ADSB_CELL_HYST_DEG (0.01, about
 * 1 km) on every side. */
#define ADSB_ALT_HYST_FT    100
#define ADSB_CELL_HYST_DEG  0.01

int  adsb_alt_band(int on_ground, int has_alt, int alt_ft);
/* The held band after a new altitude: `held` is the band so far
 * (INT16_MIN for none). */
int  adsb_alt_band_held(int held, int on_ground, int has_alt, int alt_ft);

/* The record's change signature: identity, first_seen (a row that
 * expired and came back is a new row), the held altitude band, the held
 * cell, has_pos, squawk, emergency, callsign, category. Never the raw
 * altitude, position, speed, track, rate, RSSI, seen or message count,
 * each of which moves every second. type is written, not signed:
 * readsb's best source flips between adsb_icao, mlat and mode_s as
 * coverage comes and goes. */
uint64_t adsb_row_sig(const adsb_aircraft_t *a);

#endif /* SLOTH_ADSB_H */
