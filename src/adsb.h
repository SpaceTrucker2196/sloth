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
 *
 * sbs:// (BaseStation port 30003) and Beast sockets are refused with a
 * "not yet supported" error: they are network sources, a later slice.
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

/* An absolute path, or file:///absolute/path (file://HOST/ refused).
 * sbs:// and beast:// are refused as not yet supported, any other
 * scheme or a relative path as malformed. 0 with the path, -1 with a
 * reason in err. */
int  adsb_spec_parse(const char *spec, char *path, size_t pathsz,
                     char *err, size_t errsz);

/* ── The table ─────────────────────────────────────────────────── *
 * One mutex: the reader feeds, the main thread polls. */

/* Declare the source and its label ("file:/run/readsb/aircraft.json");
 * the state is WAITING until a document parses. */
void adsb_set_source(const char *label);

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
