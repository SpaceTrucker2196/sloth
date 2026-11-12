/* slothweb routes (#158 M0, #159 M1): the exact-match table and the
 * bytes each route sends. No socket and no clock of their own: the
 * caller passes the time and the live state, so every answer can be
 * checked byte for byte (web/tests/test_routes.c).
 *
 *   /             the embedded page; ETag, If-None-Match gives 304
 *   /api/health   JSON: uptime, streams, the data socket's state
 *   /api/live     JSON: the live state (web_live.h)
 *   /api/series   JSON: one series' buckets (web_series.h, M2)
 *   /api/keys     JSON: the keys of one metric
 *   /api/series/all JSON: every key of one metric, each in at most
 *                 cols cells, a page of keys to an answer (web_allkeys.h)
 *   /api/metrics  JSON: the metric catalogue and tiers
 *   /api/anomalies JSON: open and recently closed anomaly episodes (M3),
 *                 ?since= and ?kind= (web_series.h)
 *   /api/baseline JSON: one series' 168 hour-of-week cells (M3)
 *   /api/devices  JSON: sloth.db's devices matching ?q= (M4, web_devices.h)
 *   /api/device/{mac} JSON: one device, everything known
 *   /api/lookup   JSON: ?q= a MAC or an IP: vendor, passive names, record
 *   /api/wifi/channels, /api/wifi/deauth, /api/wifi/aps
 *                 JSON: the WiFi view (M5, web_wifi.h)
 *   /api/history/overview, /api/history/devices, /api/history/alerts,
 *   /api/history/flows, /api/sessions, /api/sessions/new
 *                 JSON: the History view (M5, web_history.h)
 *   /api/alerts, /api/alert JSON: the Alerts view (web_alerts.h), GET only
 *   /api/pcap/frames JSON: an alert's capture decoded, and
 *   /api/pcap     its bytes, an attachment (web_evidence.h), GET only
 *   /api/query    JSON: the SQL box (M5, web_sqlbox.h), GET only, and
 *   /api/recipes  JSON: its recipes; both 404 unless --web-allow-sql
 *   /api/ble, /api/ble/alerts, /api/ble/{addr}
 *                 JSON: the BLE view (web_ble.h); out_of_scope under Local
 *   /api/radar    JSON: the Radar view's Wi-Fi and BLE band census
 *                 (web_radar.h); out_of_scope under Local
 *   /api/bundle   JSON: a detail view's whole answer for the page's
 *                 "copy JSON" (web_bundle.h), GET only; a heap body
 *   /api/fleet/export JSON Lines: what this sensor has seen since
 *                 ?since=, for the owner's other slothwebs (web_fleet.h),
 *                 GET only; a heap body
 *   /api/fleet/peers JSON: the peers --peer pulls and what each reported
 *   /api/fleet/overview JSON: this site and each peer, their health and
 *                 the distances between them (the Fleet tab)
 *   /api/fleet/shared JSON: ?kind=&limit=, keys seen here and at a peer,
 *                 GET only; a heap body
 *   /api/fleet/locate JSON: ?kind=wifi|ap|ble&limit=, emitters two or
 *                 more sites heard, located (web_locate.h); GET only;
 *                 a heap body
 *   /events       Server-Sent Events: tick, record, anomaly, ping
 *   anything else 404
 *
 * Before the table: no Host, or two, is 400; a Host (or absolute-form
 * authority) that is not localhost or an IP literal is 421.
 *
 * The capture scope (web_scope.h): every /api route but /api/health and
 * /api/query takes scope=monitor|hybrid|local beside its own
 * parameters, taken out of the query before the route's own parser
 * sees it. Anything else is a 400 "bad_scope". Without it the answer is
 * Hybrid's, byte for byte as before; with it (hybrid included) a JSON
 * answer's first member is "scope". /api/query is never scoped: the SQL
 * box runs what it is given.
 *
 * The merged views (web_fleetview.h): /api/devices, /api/device/{mac},
 * /api/wifi/aps, /api/ble, /api/ble/{addr}, /api/probes/clients and
 * /api/probes/ssids take fleet=0|1 the same way (/api/probes/shared and
 * /api/probes/groups never merge: the similarity is this sensor's), taken out before the route's parser. fleet=0 is the route's own
 * answer byte for byte; otherwise, with a --peer configured and the
 * request Hybrid, the peers' rows are merged into it. Anything else is
 * a 400 "bad_fleet".
 *
 *   /api/frrs/...  triage and the FRRS record (web_frrs.h): GET and HEAD
 *                 to its read paths, POST to its write paths only
 *
 * GET and HEAD reach the router, and POST to the write paths
 * (web_http_post_path()); web_http.c has already answered every other
 * method, and a POST anywhere else, 405. A GET to a write path, or a
 * POST to a read path, is 405 here. */
#ifndef SLOTHWEB_ROUTES_H
#define SLOTHWEB_ROUTES_H

#include <stddef.h>

#include "web_anomaly.h"
#include "web_ble.h"
#include "web_adsb.h"
#include "web_aprs.h"
#include "web_sysstat.h"
#include "web_lure.h"
#include "web_gnss.h"
#include "web_devices.h"
#include "web_http.h"
#include "web_live.h"
#include "web_sqlbox.h"
#include "web_tsdb.h"

/* EventSource reconnect delay sent at the start of every stream. */
#define WEB_SSE_RETRY_MS 3000

typedef struct {
    long long     uptime_s;
    unsigned      sse_clients;
    unsigned long tick_seq;
    web_live_t   *live;       /* NULL: no data socket configured */
    long long     now_ms;     /* the monotonic clock, for ages in live */
    web_tsdb_t   *tsdb;       /* NULL: no time series (M2) */
    long long     wall_s;     /* unix seconds, for the series routes */
    web_anomaly_t *anomaly;   /* NULL: no baseline/anomaly engine (M3) */
    const web_m4_t *m4;       /* NULL: no Devices or Lookup (M4) */
    web_sqlbox_t  *sql;       /* NULL or disabled: no SQL box (M5) */
    const web_scope_ctx_t *sc; /* the request's capture scope; NULL Hybrid
                                  (set by web_route() itself) */
    web_ble_t     *ble;       /* NULL: no BLE tables (web_ble.h) */
    web_gnss_t    *gnss;      /* NULL: no GNSS panel (web_gnss.h) */
    web_adsb_t    *adsb;      /* NULL: no ADS-B panel (web_adsb.h) */
    web_aprs_t    *aprs;      /* NULL: no APRS panel (web_aprs.h) */
    web_sys_t     *sys;       /* NULL: no host status (web_sysstat.h) */
    web_lure_t    *lure;      /* NULL: no lure evidence (web_lure.h) */
    int            fleet_merge; /* merge the peers' rows (web_fleetview.h);
                                   set by the router on its own copy, and
                                   read only on the merged routes */
} web_health_t;

/* /api/live and the series routes are built into the connection's
 * output buffer behind their header; this much is kept free for it. */
#define WEB_LIVE_HDR_RESERVE 1024

/* WEB_R_SQL: the statement was handed to the SQL box's thread
 * (web_sqlbox_submit()); out holds nothing and the server sends the
 * box's answer when it is ready. */
enum { WEB_R_ONESHOT = 0, WEB_R_SSE, WEB_R_SQL };

typedef struct {
    int                  kind;      /* WEB_R_ONESHOT or WEB_R_SSE */
    int                  status;
    size_t               out_len;   /* header, plus any small body, in out */
    const unsigned char *body;      /* a static body sent after out, or NULL */
    size_t               body_len;
    int                  body_free; /* body is malloc'd: the caller frees it */
    /* body is this heap block, the route's to give away: the server
     * frees it when the connection is done with it (a pcap download,
     * /api/bundle: answers too large for out). NULL for a static body. */
    unsigned char       *body_owned;
} web_resp_t;

/* Route rq. sse_room is 0 when every event-stream slot is in use, which
 * makes /events a 503. Returns 0, or -1 if out is too small. */
int    web_route(const web_req_t *rq, const web_health_t *h, int sse_room,
                 char *out, size_t outsz, web_resp_t *r);

/* One "tick" event: id, event name and a JSON data line, with the live
 * summary when h->live is set. 0 if out is too small. */
size_t web_sse_tick(char *out, size_t outsz, unsigned long seq, long long ts,
                    const web_health_t *h);

/* One "record" event for the ticker. No id: the ticks carry the ids,
 * and a reconnecting page re-reads /api/live rather than replaying. */
size_t web_sse_record(char *out, size_t outsz, const web_live_rec_t *e);

/* The keep-alive comment. */
size_t web_sse_ping(char *out, size_t outsz);

/* One "anomaly" event (§7.1): an episode opened, advanced or closed,
 * as /api/anomalies renders it. No id, like "record". */
size_t web_sse_anomaly(char *out, size_t outsz, const web_anom_ep_t *e);

#endif
