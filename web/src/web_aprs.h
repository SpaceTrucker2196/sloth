/* slothweb's APRS panel (2026-11-05, docs/wiki/aprs.md): the stations a
 * local Dire Wolf decodes on its region's APRS channel (sloth derives
 * the region from its GNSS position and names it and the channel in
 * sensor_health's aprs_region / aprs_region_hz; the operator may
 * declare the decoder's configured frequency with --aprs-freq, #204),
 * as sloth reports them, kept by slothweb from the stream.
 *
 * sloth writes one `aprs_packet` record per decoded packet and one
 * change-only `aprs_station` record per station (src/jsonl.c
 * jsonl_emit_aprs()): on first sight, on a change of its held 0.01
 * degree position cell, its symbol or its first direct packet, on the
 * 300 s heartbeat, and once as "state":"gone" when it has not been
 * heard for an hour; plus the aprs_* members of `sensor_health` when
 * sloth runs with --aprs. Every field read here was read from the
 * emitter; docs/wiki/jsonl-schema.md says what each is. A station's
 * last heard, via, level, comment and position follow its packets; its
 * first_seen and packet count its station records (plus the packets
 * since the newest one).
 *
 * In memory only: WEB_APRS_ROWS stations keyed by callsign, the least
 * recently reported evicted and counted when a new one arrives. A gone
 * station is kept, marked, for WEB_APRS_GONE_TTL_S; a live one with no
 * record for WEB_APRS_TTL_S (two heartbeats and a margin: its gone
 * record was lost, or sloth stopped) is dropped and counted. Each keeps
 * its last WEB_APRS_PTS positions as a track and its last
 * WEB_APRS_RECENT packets (time, type, via, level, the comment cut to
 * WEB_APRS_RECENT_CM). History is sloth.db's (web_aprshist.h).
 *
 * Scope: Dire Wolf's radio is a passive receiver, as the BLE receivers
 * are, so the records are Monitor's (web_scope.c); under Local the
 * route checks the query and answers out_of_scope.
 *
 * Every string is hostile - an APRS comment is free text from anyone
 * with a transmitter. A callsign must be an AX.25 call (1-6 of [A-Z0-9],
 * optionally '-' and 1-2 more), else the record is rejected and counted;
 * the symbol two printable bytes, the type one; text printable ASCII
 * within sloth's caps, else absent. Every number is range checked and
 * absent outside, never clamped.
 *
 * One mutex guards everything: the ingest thread writes, the HTTP
 * thread reads. */
#ifndef SLOTHWEB_APRS_H
#define SLOTHWEB_APRS_H

#include <pthread.h>
#include <stddef.h>

#include "web_json.h"
#include "web_jsonl.h"

/* sloth keeps APRS_MAX_STATIONS (512) live stations; the gone ones kept
 * beside them need room of their own. */
#define WEB_APRS_ROWS        1024
#define WEB_APRS_PTS         32
#define WEB_APRS_RECENT      16
#define WEB_APRS_RECENT_CM   48
#define WEB_APRS_CALL_MAX    9
#define WEB_APRS_TEXT_MAX    64      /* sloth's APRS_TEXT_MAX */
#define WEB_APRS_COMMENT_MAX 128     /* sloth's APRS_COMMENT_MAX */
#define WEB_APRS_SRC_MAX     63
#define WEB_APRS_ERR_MAX     95
#define WEB_APRS_TTL_S       660
#define WEB_APRS_GONE_TTL_S  1800
/* A station row's worst-case JSON (every text member at its cap, each
 * byte a six-byte escape): the list stops before a row that might not
 * fit and says "cut". */
#define WEB_APRS_ROW_WORST   2600

typedef struct {
    long long ts;
    char      dti;
    char      via[WEB_APRS_CALL_MAX + 1];
    int       direct, level;          /* level -1 absent */
    int       has_pos;
    char      comment[WEB_APRS_RECENT_CM + 1];
} web_aprs_pkt_t;

typedef struct {
    int       used;
    char      call[WEB_APRS_CALL_MAX + 1];
    int       gone;
    long long first_seen, last_seen;
    long long ts, gone_ts;            /* the newest record's ts */
    long long packets_at;             /* the newest station record's count */
    long long since;                  /* packet records after it */
    unsigned  records;
    char      via[WEB_APRS_CALL_MAX + 1];
    int       direct, heard_direct;
    int       level, best_level;      /* -1 absent */
    char      dti;
    char      symbol[3];
    int       has_pos, has_speed, has_course, has_alt;
    double    lat, lon, speed_kt, course, alt_m;
    long long pos_ts;
    char      system[WEB_APRS_TEXT_MAX + 1];
    char      status[WEB_APRS_TEXT_MAX + 1];
    char      comment[WEB_APRS_COMMENT_MAX + 1];
    int       npts, phead;
    long long pts_ts[WEB_APRS_PTS];
    float     pts_lat[WEB_APRS_PTS], pts_lon[WEB_APRS_PTS];
    int       nrecent, rhead;
    web_aprs_pkt_t recent[WEB_APRS_RECENT];
} web_aprs_row_t;

typedef struct {
    int       seen;
    long long ts;
    char      state[12];     /* waiting / live / error, else "other" */
    char      src[WEB_APRS_SRC_MAX + 1];
    int       missing;
    long long last_read, last_packet, stations, bytes, lines, packets;
    long long bad_lines, overflow, expired, truncations, rotations, read_errors;
    char      err[WEB_APRS_ERR_MAX + 1];
    /* #204: the region sloth derived from its GNSS position and its
     * channel, the decoder's declared frequency, and the two findings.
     * region "" when the line carried none (an older sloth) or a name
     * not in sloth's list; the Hz 0 when absent or outside 144..148 MHz.
     * No position: sloth writes none in these fields. */
    char      region[16];
    long long region_hz, freq_hz;
    int       freq_mismatch, silent;
    long long silent_after_s, quiet_since;
} web_aprs_sh_t;

typedef struct web_aprs {
    pthread_mutex_t mu;
    web_aprs_row_t *rows;
    web_aprs_sh_t   sh;
    char            src[WEB_APRS_SRC_MAX + 1];
    unsigned long   records, packets, evictions, aged, rejected;
} web_aprs_t;

int  web_aprs_init(web_aprs_t *a);
void web_aprs_destroy(web_aprs_t *a);

/* Every decoded record; aprs_packet, aprs_station and sensor_health
 * apply, the rest return. */
void web_aprs_record(web_aprs_t *a, const web_jrec_t *r, long long now_ms);

/* An AX.25 callsign as sloth writes one (src/aprs.c aprs_call_ok()). */
int  web_aprs_call_ok(const char *s);

/* /api/aprs?limit=&call=: the sensor block and up to `limit` (default
 * and most WEB_APRS_ROWS) stations without their tracks, live before
 * gone, the most recently heard first, as many as fit ("cut" when the
 * buffer stopped the list); with call=, that one station with its track
 * and its recent packets ("station": null when not kept). A 400 names
 * an unknown parameter or a bad value. With none_here (Local) the query
 * is checked and the caller answers web_aprs_out_of_scope_json()
 * instead. 0 with *len / *status set, -1 when the body did not fit. */
int web_aprs_route(web_aprs_t *a, const char *query, long long now_s, int none_here,
                   char *body, size_t cap, size_t *len, int *status);
size_t web_aprs_out_of_scope_json(char *body, size_t cap);

/* The /api/health member: counts only. */
void web_aprs_health_json(web_aprs_t *a, web_jw_t *w);

/* Does the table hold this station now, live or gone (web_notes.h)? */
int  web_aprs_has(web_aprs_t *a, const char *call);

#endif /* SLOTHWEB_APRS_H */
