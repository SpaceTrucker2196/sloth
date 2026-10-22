/* slothweb anomaly rules (#161, M3): docs/web-ui-spec.md §6, run once a
 * minute against the baseline (web_baseline.h) and the rollup/store.
 *
 * Shipped this slice, none needing sloth.db (M4, #162, has not landed):
 *
 *   A1  rate out of band   any non-presence keyed metric whose latest
 *                          minute bucket scores |z| >= threshold for
 *                          WEB_ANOM_STREAK_MIN consecutive minutes.
 *                          Run over every metric the catalogue has, this
 *                          also covers what §6 calls A7 ("talks to
 *                          many"): host.conns is one of the scanned
 *                          metrics, so a host fanning out further than
 *                          its own hour-of-week baseline fires here,
 *                          under the A1 kind.
 *   A3  off-hours presence a device's dev.present minute value is 1
 *                          while its baseline mean for this hour of the
 *                          week is below WEB_ANOM_A3_MEAN_MAX, with at
 *                          least WEB_ANOM_A3_MIN_N samples (not
 *                          warming).
 *   A8  chatty DNS         a host's NXDOMAIN share over the last 10
 *                          minutes is above WEB_ANOM_A8_NX_SHARE, with
 *                          at least WEB_ANOM_A8_MIN_Q queries.
 *   A9  protocol first use a host's flow.{ssh,rdp,smb,snmp,mqtt} minute
 *                          value is nonzero and the baseline has never
 *                          been fed for that (metric, key) — the
 *                          baseline's own "never scored" case doubles
 *                          as "first time we've seen this host use
 *                          this protocol" for roughly the key's first
 *                          hour, since a baseline entry is created at
 *                          the first hourly feed.
 *   A10 sensor silence     the data socket is connected but no record
 *                          has arrived for WEB_ANOM_A10_SILENCE_S.
 *
 * Deferred to #162 (M4) because they are lookups against sloth.db or
 * the lookup module that does not exist yet: A2 (new device), A4
 * (vendor unknown), A5 (randomised MAC with a stable name), A6 (name
 * disagreement). Building a second, narrower sloth.db reader just for
 * these ahead of M4 would duplicate what M4 is for.
 *
 * An episode (web_anom_ep_t) is one row per (kind, metric, key) that
 * advances rather than refires every tick, like a sloth alert. A
 * candidate has to hold for req_streak(kind) consecutive minutes
 * before it is "open" (visible on /api/anomalies); A1's three-minute
 * requirement is where that matters, everything else opens on the
 * first minute it holds. An open episode closes after
 * WEB_ANOM_CLEAR_TICKS consecutive minutes where the condition no
 * longer holds. The table is flat and capped; a closed episode is
 * first in line to be evicted for a new one. */
#ifndef SLOTHWEB_ANOMALY_H
#define SLOTHWEB_ANOMALY_H

#include <pthread.h>

#include "web_baseline.h"
#include "web_live.h"
#include "web_rollup.h"
#include "web_store.h"

enum {
    WEB_ANOM_A1_RATE = 0,
    WEB_ANOM_A3_HOURS,
    WEB_ANOM_A8_DNS,
    WEB_ANOM_A9_PROTO,
    WEB_ANOM_A10_SENSOR,
    WEB_ANOM_KIND_COUNT
};

#define WEB_ANOM_CAP            512
#define WEB_ANOM_EVIDENCE_MAX   160
#define WEB_ANOM_CLEAR_TICKS    2
#define WEB_ANOM_STREAK_MIN     3
#define WEB_ANOM_Z_THRESHOLD    3.0
#define WEB_ANOM_A3_MEAN_MAX    0.1
#define WEB_ANOM_A3_MIN_N       4
#define WEB_ANOM_A8_MIN_Q       20
#define WEB_ANOM_A8_NX_SHARE    0.30
#define WEB_ANOM_A8_WINDOW_S    600
#define WEB_ANOM_A10_SILENCE_S  60
#define WEB_ANOM_SCAN_MAX       256

typedef struct {
    int       used;
    int       kind;
    int       metric;              /* WM_*, or -1 (A10: not metric-keyed) */
    char      key[WEB_KEY_MAX + 1];
    double    score;               /* 0..100 */
    char      evidence[WEB_ANOM_EVIDENCE_MAX];
    long long first_seen, last_seen;
    int       open;
    int       hit_streak;          /* consecutive firing minutes so far */
    int       clear_streak;        /* consecutive quiet minutes so far */
} web_anom_ep_t;

typedef struct {
    pthread_mutex_t mu;
    web_anom_ep_t  *ep;
    int             cap, n;
    unsigned long   opened, closed;
    long long       last_minute;    /* last now_s/60 stepped, -1 none yet */
    long long       last_hour;      /* last now_s/3600 fed to baseline */
} web_anomaly_t;

int  web_anomaly_init(web_anomaly_t *a, int cap);
void web_anomaly_destroy(web_anomaly_t *a);

/* One pass at now_s (unix seconds, for the hour and minute boundaries
 * every rule but A10 uses): feeds the baseline from newly closed hour
 * buckets (at most once per hour) and evaluates every rule (at most
 * once per minute). A no-op between boundaries, so calling this every
 * second from the tick thread is cheap. store may be NULL (no
 * SQLite): every rule but A10 needs the minute or hour tier, so only
 * A10 can still fire. now_ms is a monotonic clock reading, passed
 * through to web_live_summary() for A10's "no record for N ms" check
 * — the same clock convention web_live.h's own callers use, and kept
 * a parameter (rather than read here) so a test can hold it fixed. */
void web_anomaly_step(web_anomaly_t *a, web_baseline_t *bl, web_rollup_t *ru,
                     web_store_t *store, web_live_t *live, long long now_s,
                     long long now_ms);

/* Render {"anomalies":[...]} : open episodes, then closed ones whose
 * last_seen is within WEB_ANOM_RECENT_S of now_s. 0 if it did not fit. */
#define WEB_ANOM_RECENT_S 3600
size_t web_anomaly_json(web_anomaly_t *a, long long now_s, char *out,
                        size_t cap);

#endif
