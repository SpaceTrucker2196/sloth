/* slothweb /api/series, /api/keys and /api/metrics (#160, M2).
 *
 *   /api/series?metric=M&key=K&tier=T&from=F&to=E
 *       buckets of one series with F <= t < E, as
 *       {"metric":..,"points":[[t,value,min,max,n],...]} oldest first.
 *       value is the bucket's mean for a gauge, its sum for a counter,
 *       its max for presence. tier is fine (10 s, default), minute or
 *       hour. to defaults to the end of the current bucket, from to one
 *       hour (fine), one day (minute) or thirty days (hour) before it.
 *   /api/keys?metric=M
 *       the keys holding a series of M, most recently seen first.
 *   /api/metrics
 *       the metric catalogue and the tiers this build can serve.
 *
 * Parameters are validated before anything reads a series, and only
 * ever bound into SQL, never written into it:
 *   - the query is name=value pairs joined by '&', nothing else; a name
 *     is [a-z]+ and one of the route's own, each at most once, so an
 *     unknown, repeated or empty parameter is a 400;
 *   - a value is percent-decoded (RFC 3986 §2.1) and must then be
 *     1..63 bytes of printable ASCII;
 *   - metric is a catalogue name; key passes the metric's canonicaliser
 *     (web_metrics.h) and must be absent for a global metric;
 *   - from and to are decimal seconds, from < to, to no more than a day
 *     ahead of now, and the span no longer than the tier keeps (24 h,
 *     --web-retain-days, 400 days);
 *   - minute and hour need the store: without it (no SQLite, or none
 *     opened) they are a 400 "tier_unavailable".
 * A result is at most WEB_SERIES_MAX_POINTS buckets, the newest ones;
 * "more":true and "next_to" say where to ask for the older ones. */
#ifndef SLOTHWEB_SERIES_H
#define SLOTHWEB_SERIES_H

#include <stddef.h>

#include "web_baseline.h"
#include "web_rollup.h"
#include "web_tsdb.h"

/* A point is at most 69 bytes: a 10-digit t, three %.7g values of at
 * most 14 bytes, a count capped at 2^32 - 1, brackets and commas. 900
 * of them are 62,100 bytes, inside the 64,512 an answer has behind its
 * header (web_routes.h); test_series.c builds that worst case. */
#define WEB_SERIES_MAX_POINTS 900
#define WEB_KEYS_MAX          256
#define WEB_PARAM_MAX         63

/* One parameter of a route's query, as every route but /api/query
 * parses it (the rules above): name=value pairs and nothing else, each
 * name [a-z]+, one of the route's own and at most once; a value
 * percent-decoded to 1..WEB_PARAM_MAX bytes of printable ASCII. */
typedef struct {
    const char *name;
    char        val[WEB_PARAM_MAX + 1];
    int         seen;
} web_param_t;

/* 0, or -1 with the reason word in err. Shared by the M5 routes. */
int    web_params_parse(const char *query, web_param_t *ps, int np,
                        char *err, size_t errsz);
/* Decimal seconds, 1..11 digits. 0, or -1. */
int    web_param_secs(const char *s, long long *out);

typedef struct {
    int       metric, tier;
    char      key[WEB_KEY_MAX + 1];
    long long from, to;
} web_series_q_t;

/* 0, or -1 with a short reason ("unknown_parameter", "bad_key", ...) in
 * err. store_on says whether minute and hour can be served. */
int    web_series_parse(const char *query, long long now_s, int retain_days,
                        int store_on, web_series_q_t *q, char *err,
                        size_t errsz);
/* The answer's JSON into out. 0 if it did not fit. */
size_t web_series_json(web_tsdb_t *t, const web_series_q_t *q, char *out,
                       size_t cap);

/* The buckets of (metric, key) in tier with from <= t < to, newest
 * first, at most max into out: the store's and, for the fine tier, the
 * ring's, one point per bucket (web_series_json()'s merge, shared with
 * M5's waterfall). *more when max cut it; *store_err when the store
 * read failed (the ring's are still there). Count, or -1 (memory). */
int    web_series_points(web_tsdb_t *t, int tier, int metric, const char *key,
                         long long from, long long to, web_point_t *out,
                         int max, int *more, int *store_err);

int    web_keys_parse(const char *query, int *metric, char *err, size_t errsz);
size_t web_keys_json(web_tsdb_t *t, int metric, char *out, size_t cap);

/* Only an empty query is accepted. */
int    web_metrics_parse(const char *query, char *err, size_t errsz);
size_t web_metrics_json(web_tsdb_t *t, char *out, size_t cap);

/* {"error":"reason"} */
size_t web_series_error_json(const char *reason, char *out, size_t cap);

/* /api/anomalies?since=S&kind=K (M3): since defaults to an hour ago and
 * is raised to the oldest a closed episode is kept (WEB_ANOM_KEEP_S);
 * kind is one of §6's kinds. *kind is -1 for every kind. */
int    web_anomalies_parse(const char *query, long long now_s,
                           long long *since, int *kind, char *err,
                           size_t errsz);

/* /api/baseline?metric=M&key=K (M3): the 168 hour-of-week cells of one
 * series, [mean, sd, n] each, Monday 00:00 local first; sd floored as a
 * score floors it; "cells":null for a pair never fed. The value scale
 * is the baseline's (web_bl_value()): a counter per minute. */
int    web_baseline_parse(const char *query, int *metric, char *key,
                          char *err, size_t errsz);
size_t web_baseline_json(web_baseline_t *b, int metric, const char *key,
                         long long now_s, char *out, size_t cap);

#endif
