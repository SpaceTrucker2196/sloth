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
 * packet ring into s. PH_PLATFORM, beside adsb_health_poll(). */
void aprs_health_poll(sloth_state_t *s, time_t wall, uint64_t mono_ms);

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
