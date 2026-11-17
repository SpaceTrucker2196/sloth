/* slothweb: direction finding across monitor radios, as sloth reports
 * it (docs/wiki/direction-finding.md; src/df.h for what the numbers can
 * and cannot say).
 *
 * sloth-wifi writes two change-only records when it runs with
 * --df-iface (JSONL 2.2.0): `df_radio` per radio (radio 0 is the sensor
 * radio) and `wifi_df` per transmitter two or more radios hold a fresh
 * level for. Each is written when what it says moves and on the 300 s
 * heartbeat. Neither has a `gone` form: a transmitter the radios stop
 * agreeing on is simply not written again.
 *
 * Kept here in memory, newest record per key: WEB_DF_RADIOS radios
 * (sloth's DF_MAX_RADIOS) and WEB_DF_EMITTERS transmitters (sloth's
 * DF_MAX_EMITTERS). sloth's own table recycles its rows, so over a day
 * this one meets more transmitters than it holds: a new one takes a
 * free row, then a stale one, then the row written longest ago. A row
 * not refreshed for two heartbeats and a minute is left out of answers,
 * never shown as current.
 *
 * What is kept of a `wifi_df` is its scalars. The `rssi` and `level`
 * arrays are not: the stream decoder (web_jsonl.h) checks a nested
 * array and skips it. The loudest radio, the margin and the point along
 * the baseline are what the card shows.
 *
 * "Off" is told from "not known": sloth writes nothing without a second
 * radio, so an empty table means something only from a stream that
 * writes these records at all. The stream's contract version
 * (`jsonl_version` on `sensor_health`) is kept for that: from 2.2.0 no
 * radios is "sloth runs without --df-iface" (or has not written its
 * heartbeat since slothweb connected, at most 300 s), before it "this
 * sloth does not report these", and with no sensor_health yet "not
 * known".
 *
 * A record past the bounds below or with a malformed member is refused
 * whole and counted. Strings (an interface name) leave only through
 * web_jw_str(). The monitor radio's, so Monitor's and Hybrid's
 * (web_scope.h); /api/df answers out_of_scope under Local.
 *
 * A data point for an analyst, as in sloth: nothing here is a verdict,
 * and no alert reads it. */
#ifndef SLOTHWEB_DF_H
#define SLOTHWEB_DF_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "web_json.h"
#include "web_jsonl.h"

#define WEB_DF_RADIOS    4      /* sloth: DF_MAX_RADIOS */
#define WEB_DF_EMITTERS  512    /* sloth: DF_MAX_EMITTERS */
#define WEB_DF_OUT       128    /* transmitters in one answer */
/* Two of sloth's 300 s heartbeats and a minute. */
#define WEB_DF_STALE_MS  (660LL * 1000)
#define WEB_DF_IFACE_MAX 15     /* sloth: df_radio_t.iface[16] */
#define WEB_DF_COUNT_MAX 1000000000000LL
#define WEB_DF_POS_MAX   1000.0 /* sloth: df_parse_spec()'s +/-1000 m */
#define WEB_DF_DB_MAX    200.0  /* a margin or a bias, dB */

enum { WEB_DF_Q_NONE, WEB_DF_Q_WEAK, WEB_DF_Q_LEAN };

typedef struct {
    int       used;
    long long ts, rx_ms;
    char      iface[WEB_DF_IFACE_MAX + 1];
    int       sensor;            /* role "sensor", else "df" */
    int       has_pos, has_bias, has_aux;
    double    pos_m, bias_db;
    long long open, running, noted;
    long long frames, rejects, retune_failures;   /* has_aux */
} web_df_radio_t;

typedef struct {
    int       used;
    uint8_t   mac[6];
    long long ts, rx_ms;
    long long channel, heard_by, best_radio, last_seen;
    int       quality;           /* WEB_DF_Q_* */
    char      best_iface[WEB_DF_IFACE_MAX + 1];   /* "" none */
    double    margin_db;
    int       has_along;
    double    along_m;
} web_df_em_t;

typedef struct web_df {
    pthread_mutex_t mu;
    web_df_radio_t  radio[WEB_DF_RADIOS];
    web_df_em_t     em[WEB_DF_EMITTERS];
    /* sensor_health's jsonl_version, MAJOR.MINOR.PATCH; 0 0 0 unknown */
    int             ver_seen, ver[3];
    unsigned long   records, rejected, evicted;
} web_df_t;

int  web_df_init(web_df_t *d);
void web_df_destroy(web_df_t *d);

/* Every decoded record of sloth-wifi's stream: `df_radio` and `wifi_df`
 * apply, and sensor_health's jsonl_version is noted; the rest return. */
void web_df_record(web_df_t *d, const web_jrec_t *r, long long now_ms);

/* 1 the stream writes these records (2.2.0 or later), 0 it does not,
 * -1 not known (no sensor_health with a version yet). */
int  web_df_reported(web_df_t *d);

/* /api/df: no parameters. 0 with *status and *len set (400 for a
 * parameter, 503 with no table), -1 when the answer did not fit.
 * `radios` in radio order; `emitters` the fresh rows, `lean` before
 * `weak`, widest margin first, at most WEB_DF_OUT of them (`held` says
 * how many were fresh). none_here: Local's, the query checked and *len
 * 1 for the caller's out_of_scope answer. */
int  web_df_route(web_df_t *d, const char *query, long long now_s,
                  long long now_ms, int none_here, char *body, size_t cap,
                  size_t *len, int *status);
size_t web_df_out_of_scope_json(char *body, size_t cap);

#endif /* SLOTHWEB_DF_H */
