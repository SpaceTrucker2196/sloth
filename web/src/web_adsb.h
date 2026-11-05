/* slothweb's ADS-B panel (#26 slice "slothweb table", 2026-11-05,
 * docs/wiki/adsb.md): the aircraft a local decoder lists, as sloth
 * reports them, kept by slothweb from the stream.
 *
 * sloth writes one change-only `adsb_aircraft` record per aircraft row
 * (src/jsonl.c jsonl_emit_adsb()): on first sight, on a change of its
 * held altitude band, position cell, squawk, emergency, callsign or
 * category, on the 300 s heartbeat, and once as "state":"gone" when the
 * row expires; plus the adsb_* members of `sensor_health` when sloth
 * runs with --adsb. Every field read here was read from the emitter;
 * docs/wiki/jsonl-schema.md says what each is. So a row's figures are
 * as of its last record, not of the decoder's last second: altitude is
 * within its band, the position within its cell, and the page says so.
 *
 * In memory only: WEB_ADSB_ROWS rows keyed by `hex` (a leading `~` is
 * a non-ICAO address, a separate key), the least recently reported
 * evicted and counted when a new one arrives. A gone row is kept,
 * marked, for WEB_ADSB_GONE_TTL_S so the table shows what just left;
 * a live row not reported for WEB_ADSB_TTL_S (two heartbeats and a
 * margin: its gone record was lost, or sloth stopped) is dropped and
 * counted. Each row keeps its last WEB_ADSB_PTS positions (one per
 * record whose position moved) so the page draws a track. Nothing is
 * persisted: sloth.db has no ADS-B table yet.
 *
 * Scope: the decoder's SDR is a passive radio, as the BLE receivers
 * are, so the records are Monitor's (web_scope.c); under Local the
 * route checks the query and answers out_of_scope, as the BLE routes do.
 *
 * Every string is hostile. hex is `~`? and six lower-case hex digits,
 * else the record is rejected and counted; callsign printable ASCII of
 * at most 8, squawk four octal digits, category A0..D7, emergency one
 * of sloth's eight words (src/adsb.c k_emerg), source type lower-case
 * letters and '_'; anything else is absent. Every number is range
 * checked and anything outside is absent, never clamped.
 *
 * One mutex guards everything: the ingest thread writes, the HTTP
 * thread reads. */
#ifndef SLOTHWEB_ADSB_H
#define SLOTHWEB_ADSB_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"

/* sloth keeps ADSB_MAX_AIRCRAFT (256) live rows; the gone rows kept
 * beside them need room of their own. */
#define WEB_ADSB_ROWS        512
#define WEB_ADSB_PTS         32
#define WEB_ADSB_SRC_MAX     63
#define WEB_ADSB_ERR_MAX     95
#define WEB_ADSB_TTL_S       660
#define WEB_ADSB_GONE_TTL_S  600
/* The emergency words, in sloth's order (src/adsb.c k_emerg). */
#define WEB_ADSB_EMERG_COUNT 8

typedef struct {
    int       used;
    char      hex[8];
    int       non_icao;
    int       gone;
    char      source_type[16];
    char      flight[9];
    char      squawk[5];
    char      category[3];
    int       emergency;     /* -1 absent, 0..7 (0 "none") */
    int       on_ground;
    int       has_alt_baro, has_alt_geom;
    int       alt_baro, alt_geom, alt_band;
    int       has_gs, has_track, has_baro_rate, has_geom_rate;
    double    gs, track;
    int       baro_rate, geom_rate;
    int       has_pos;
    double    lat, lon;
    long long pos_ts;
    int       has_rssi;
    double    rssi;
    long long messages;      /* -1 absent */
    long long first_seen, last_seen;
    long long ts;            /* the newest record's ts */
    long long gone_ts;
    unsigned  records;
    int       npts, phead;
    long long pts_ts[WEB_ADSB_PTS];
    float     pts_lat[WEB_ADSB_PTS], pts_lon[WEB_ADSB_PTS];
    int       pts_alt[WEB_ADSB_PTS];   /* INT32_MIN unknown, -1 on the ground */
} web_adsb_row_t;

typedef struct {
    int       seen;
    long long ts;
    char      state[12];     /* waiting / live / stale / error, else "other" */
    char      src[WEB_ADSB_SRC_MAX + 1];
    long long age_s, last_read, aircraft, messages, reads;
    long long read_errors, parse_errors, overflow, bad_entries, expired;
    char      err[WEB_ADSB_ERR_MAX + 1];
} web_adsb_sh_t;

typedef struct web_adsb {
    pthread_mutex_t mu;
    web_adsb_row_t *rows;
    web_adsb_sh_t   sh;
    char            src[WEB_ADSB_SRC_MAX + 1];
    unsigned long   records, evictions, aged, rejected;
} web_adsb_t;

int  web_adsb_init(web_adsb_t *a);
void web_adsb_destroy(web_adsb_t *a);

/* Every decoded record; adsb_aircraft and sensor_health apply, the rest
 * return. */
void web_adsb_record(web_adsb_t *a, const web_jrec_t *r, long long now_ms);

/* sloth's emergency word e (0..7), or "" (src/adsb.c
 * adsb_emergency_name()). */
const char *web_adsb_emergency_name(int e);

/* /api/adsb?limit=: the sensor block and up to `limit` (default and
 * most WEB_ADSB_ROWS) rows with their tracks, an emergency first, then
 * live before gone, then the most recently heard; a 400 names an
 * unknown parameter. With none_here (Local) the query is checked and
 * the caller answers web_adsb_out_of_scope_json() instead. 0 with
 * *len / *status set, -1 when the body did not fit. */
int web_adsb_route(web_adsb_t *a, const char *query, long long now_s, int none_here,
                   char *body, size_t cap, size_t *len, int *status);
size_t web_adsb_out_of_scope_json(char *body, size_t cap);

/* The /api/health member: counts only. */
void web_adsb_health_json(web_adsb_t *a, web_jw_t *w);

#endif /* SLOTHWEB_ADSB_H */
