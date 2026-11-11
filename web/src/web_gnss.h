/* slothweb's GNSS panel (2026-11-02, docs/wiki/gnss.md): the host's own
 * receiver as sloth reports it, kept by slothweb from the stream.
 *
 * sloth writes three change-only records off the gpsd stream it already
 * reads for its position (src/jsonl.c jsonl_emit_gnss()): `gnss_fix`
 * (the newest TPV: mode, status, DOPs, position, speed, the receiver's
 * clock against the host's), `gnss_sky` (the pass's summary: counts,
 * DOPs, the C/N0 statistics) and one `gnss_sat` per satellite in view
 * (constellation, svid, PRN, elevation, azimuth, C/N0, used, health),
 * plus the gnss_* members of `sensor_health`. Every field read here was
 * read from the emitter; docs/wiki/jsonl-schema.md says what each is.
 *
 * In memory only: WEB_GNSS_SATS satellite rows keyed (gnssid, prn), the
 * least recently reported evicted and counted when a new one arrives
 * and a row not reported for WEB_GNSS_SAT_TTL_S dropped (a satellite
 * that set); each row keeps its last WEB_GNSS_PTS (ts, C/N0) points so
 * the page draws the signal's history without a per-satellite series
 * in the rollup; WEB_GNSS_FIXES gnss_fix records in a ring; one copy of
 * the newest gnss_sky and of sensor_health's gnss_* members. Nothing is
 * persisted: the receiver's sky is live state, and sloth.db's
 * gnss_fixes / gnss_sightings (schema v10) hold the history.
 *
 * Scope: the receiver is the host's own, neither the monitor radio's
 * nor the IP capture's; its records are sloth's own state (web_scope.c
 * tags them META, as sensor_health), so the panel is served under
 * every scope and says so.
 *
 * Every string is hostile. The constellation is kept as gpsd's gnssid
 * and named from sloth's own table (src/gps.c gnss_name()); a gnssid
 * outside 0..7 is "other", counted; the source label is kept only when
 * it is printable ASCII. Every number is range checked and anything
 * outside is absent, never clamped.
 *
 * One mutex guards everything: the ingest thread writes, the HTTP
 * thread reads. */
#ifndef SLOTHWEB_GNSS_H
#define SLOTHWEB_GNSS_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"
#include "web_loc.h"

#define WEB_GNSS_SATS      64
#define WEB_GNSS_PTS       16
#define WEB_GNSS_FIXES     512
#define WEB_GNSS_SRC_MAX   47
/* Two of the emitter's 300 s heartbeats and a margin: a row quiet for
 * that long is a satellite that set, whatever was missed. */
#define WEB_GNSS_SAT_TTL_S 660
/* A page of the fix ring: the answer is built in the connection's 64 KB
 * output buffer (web_server.h WEB_SSE_MAX_UNSENT) and a row is some
 * 330 bytes; the page walks the ring with since= (gnss.js fixes(): from
 * 0, then from the last row's ts while a page comes back full). */
#define WEB_GNSS_LIMIT_MAX 128
/* el / az absent: a value outside -90..90 / 0..360, never -1, which
 * is a satellite one degree under the horizon (gpsd lists them). */
#define WEB_GNSS_NO_ANGLE  (-999)

typedef struct {
    int       used;
    int       gnssid;        /* -1 absent, 0..7 gpsd's, 8 other */
    int       svid, prn, sigid;   /* -1 absent */
    int       el, az;        /* degrees, el -90..90; WEB_GNSS_NO_ANGLE absent */
    int       has_cn0;
    double    cn0;
    int       in_fix;        /* the record's `used` */
    int       health;        /* -1 absent, 0..2 */
    long long ts;            /* the newest record's ts */
    long long first_ts;
    long long sky_ts;
    unsigned  records;
    int       npts, phead;
    long long pts_ts[WEB_GNSS_PTS];
    float     pts_cn0[WEB_GNSS_PTS];
} web_gnss_sat_t;

typedef struct {
    long long ts, fix_ts;
    int       mode, status, nsat, usat;
    double    hdop, vdop, pdop;
    int       has_pos, has_alt, has_eph, has_epv, has_speed, has_track;
    double    lat, lon, alt_m, eph, epv, speed, track;
    int       has_time_off;
    long long time_off_ms;
    int       leap, jam;
    long long tpv_count;
} web_gnss_fix_t;

typedef struct {
    int       seen;
    long long ts, sky_ts;
    int       nsat, usat, rows, overflow, cn0_n;
    double    hdop, vdop, pdop, gdop, tdop, cn0_mean, cn0_max, cn0_sd;
    long long passes;
} web_gnss_sky_t;

typedef struct {
    int       seen;
    long long ts;
    char      gps_state[16];
    int       sats_in_view, sats_used;
    double    cn0_mean;
    int       has_time_off;
    long long time_off_ms;
    int       jam;
} web_gnss_sh_t;

typedef struct web_gnss {
    pthread_mutex_t mu;
    web_gnss_sat_t *sats;
    web_gnss_fix_t *fixes;
    int             fix_n, fix_head;
    web_gnss_sky_t  sky;
    web_gnss_sh_t   sh;
    /* Where the sensor is (2026-11-06): sensor_health's loc_* members,
     * the arbitrated GPS-else---location stamp, range-checked by
     * web_loc_set(); cleared by a sensor_health without them (the
     * position was lost or never configured). The Radar view's centre;
     * served as /api/gnss "loc". */
    web_loc_t       loc;
    char            src[WEB_GNSS_SRC_MAX + 1];
    unsigned long   records, evictions, aged, rejected;
} web_gnss_t;

int  web_gnss_init(web_gnss_t *g);
void web_gnss_destroy(web_gnss_t *g);

/* Every decoded record; the four types above apply, the rest return. */
void web_gnss_record(web_gnss_t *g, const web_jrec_t *r, long long now_ms);

/* The name sloth gives gpsd's gnssid (src/gps.c gnss_name()). */
const char *web_gnss_name(int gnssid);

/* /api/gnss?limit=: the sensor block, the newest fix and sky, up to
 * `limit` (default and most WEB_GNSS_SATS) satellite rows with their
 * points, sorted by C/N0 (strongest first); a 400 names an unknown
 * parameter. /api/gnss/fixes?since=&limit=: the fix ring oldest first,
 * after `since` (unix seconds), at most WEB_GNSS_LIMIT_MAX rows (the
 * page continues from the last row's ts). Both answer under every
 * scope. 0 with *len / *status set, -1 when the body did not fit. */
int web_gnss_route(web_gnss_t *g, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status);
int web_gnss_fixes_route(web_gnss_t *g, const char *query, long long now_s,
                         char *body, size_t cap, size_t *len, int *status);

/* The /api/health member: counts only. */
void web_gnss_health_json(web_gnss_t *g, web_jw_t *w);

/* The sensor's position (sensor_health's loc_*, has 0 when none) and
 * sensor_health's gnss_* summary (seen 0 when none), copied under the
 * lock: the fleet export's site block (web_fleet.h). */
void web_gnss_site(web_gnss_t *g, web_loc_t *loc, web_gnss_sh_t *sh);

/* Does the table hold a row of this satellite now (web_notes.h)? */
int  web_gnss_has(web_gnss_t *g, int gnssid, int prn);

#endif /* SLOTHWEB_GNSS_H */
