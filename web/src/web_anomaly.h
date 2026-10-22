/* slothweb anomaly rules (#161, M3): docs/web-ui-spec.md §6, run once a
 * minute on the store thread against the baselines (web_baseline.h), the
 * buckets that just closed, and the identity tables (web_ident.h).
 *
 * Where the numbers come from. The engine does not ask the store
 * whether a bucket has arrived: web_tsdb hands it every minute and hour
 * row as the row leaves the rollup's queue (web_tsdb_set_rows_hook),
 * and a step that crosses a minute boundary flushes first, so the
 * minute pass at the first step of minute m+1 has every row of minute m
 * that the boundary closed. Rows are merged per (tier, metric, key, t),
 * since an eviction and a return can close one bucket in two parts.
 * The hour pass feeds each closed hour once, from its merged rows,
 * keyed by the row's own t; a counter or presence entry the hour did
 * not feed is fed 0 (web_baseline_zero_missing()). An hour slothweb did
 * not observe is not fed at all: fewer than WEB_ANOM_COVER_MIN of its
 * minutes had the socket connected and a record within
 * WEB_ANOM_A10_SILENCE_S, or slothweb was not running for all of it. A
 * minute it did not observe is not scored: neither a hit nor a quiet
 * minute for any episode.
 *
 * The rules, and exactly what each measures:
 *
 *   A1  rate     a keyed, non-presence metric whose minute value (a
 *                counter's count in the minute, a gauge's mean) has
 *                |z| >= WEB_ANOM_Z_THRESHOLD against its own cell for
 *                this hour of the week, in WEB_ANOM_STREAK_MIN
 *                consecutive observed minutes. A counter with a baseline
 *                and no row this minute counted 0 and is scored as 0; a
 *                gauge with no row was not measured and breaks the
 *                streak. A counter must also pass the MAD ratio (§5.3,
 *                below) when the store has the history for it.
 *   A2  new      a MAC whose own first_seen (the probe_client,
 *                pnl_client or assoc row's, from sloth) is within
 *                WEB_ANOM_A2_WINDOW_S of now, reported once per MAC (the
 *                reported set outlives a restart). Randomised MACs are
 *                left out: every rotation is new by construction, and
 *                A5 is the rule about them. A MAC sloth first saw long
 *                ago is not new however recently slothweb connected.
 *   A3  hours    a MAC present in this minute (dev.present) whose
 *                presence cell for this hour of the week has mean below
 *                WEB_ANOM_A3_MEAN_MAX over WEB_ANOM_A3_MIN_N or more
 *                samples.
 *   A5  ident    a randomised MAC whose DHCP or mDNS hostname is also
 *                the name of another MAC (web_ident_named()).
 *   A6  ident    an IP whose current DHCP hostname, mDNS host and NBNS
 *                name, two or more of them, do not agree in normal form
 *                (an NBNS name against the first 15 bytes of another).
 *   A7  fanout   §6 asks for distinct peers in 10 min. sloth's stream
 *                has no per-host peer list: top_host is a remote IP the
 *                sensor host talks to and conn_count the number of
 *                distinct flows between the two in one poll
 *                (src/top_hosts.c). So A7 measures that: the largest
 *                host.conns sample in each 10-minute window, against
 *                the host's own p95 of that window value (a decaying
 *                16-bin histogram, half-life WEB_ANOM_A7_HALFLIFE_W
 *                windows, at least WEB_ANOM_A7_MIN_WINDOWS of them). It
 *                fires when the value exceeds both
 *                WEB_ANOM_A7_FACTOR x p95 and p95 + WEB_ANOM_A7_MIN_EXCESS:
 *                a bare "above p95" is true of one window in twenty by
 *                definition, and would fire on a quiet stream.
 *   A8  dns      a client IP with at least WEB_ANOM_A8_MIN_Q queries in
 *                the last WEB_ANOM_A8_WINDOW_S and more than
 *                WEB_ANOM_A8_NX_SHARE of them answered NXDOMAIN. The
 *                answer is joined to the client by qname
 *                (web_ident.h): dns.nxdomain is keyed by the responder,
 *                which is why the previous slice's A8, dividing it by
 *                the same key's queries, could not fire for a client.
 *   A9  proto    a host's flow.{ssh,rdp,smb,snmp,mqtt} minute row with
 *                no row of that (metric, key) before it in the minute or
 *                hour tier: the first use the store has ever recorded.
 *                Needs the store; a memory-only build skips it.
 *   A10 sensor   the socket is connected and nothing has arrived for
 *                WEB_ANOM_A10_SILENCE_S, counted from the later of the
 *                last record and the connection itself, so a connection
 *                that never sends fires and a fresh one does not.
 *
 * A4 (vendor unknown) needs the full IEEE OUI table, which arrives with
 * #162 (M4); it is not here.
 *
 * MAD ratio (§5.3): for an A1 candidate on a counter, the last
 * WEB_ANOM_MAD_N hour rows of the same hour of the week are read from
 * the hour tier (one primary-key lookup each), and the candidate stands
 * only if Iglewicz and Hoaglin's modified z, 0.6745 |x - median| / MAD,
 * is at least WEB_ANOM_MAD_THRESHOLD; one loud week moves the mean and
 * the variance but not the median. Fewer than WEB_ANOM_MAD_MIN rows: no
 * claim, z alone decides. An hour with no row is not in the sample (the
 * file cannot tell a quiet hour from an unobserved one). Computed once
 * per series per hour (a small cache), at most WEB_ANOM_MAD_PER_MIN
 * series a minute; past that z alone decides and the skip is counted.
 * A memory-only build has no hour tier and skips MAD.
 *
 * An episode is one row per (rule, metric, key) that advances, like a
 * sloth alert. It is building until its rule has held for
 * req_streak(rule) consecutive evaluated buckets, open after that, and
 * closed after WEB_ANOM_CLEAR_TICKS evaluated buckets in which its rule
 * did not hold; one bucket counts once, however often it is scored. A
 * building episode that misses a bucket is dropped. A closed episode is
 * kept for WEB_ANOM_KEEP_S (listed by /api/anomalies within its
 * window); if its rule holds again, a new episode starts and has to
 * earn its streak afresh. The table holds WEB_ANOM_CAP: a new episode
 * takes a free slot, else the oldest closed one; an open or building
 * episode is never pushed out (the new one is dropped and counted).
 *
 * Threads: the rows hook and the step hook run on the store thread,
 * which alone writes the engine's state. The rules are evaluated
 * without the episode lock; it is taken only to apply the minute's
 * candidates, so /api/anomalies never waits on a rule's SQLite. Open and
 * recently closed episodes, the baselines, A7's histograms and A2's
 * reported set are written to slothweb.db (v3) by the store thread and
 * restored at start; a memory-only build keeps them in memory and loses
 * them at exit. */
#ifndef SLOTHWEB_ANOMALY_H
#define SLOTHWEB_ANOMALY_H

#include <pthread.h>

#include "web_baseline.h"
#include "web_ident.h"
#include "web_json.h"
#include "web_live.h"
#include "web_rollup.h"
#include "web_store.h"
#include "web_tsdb.h"

enum {
    WEB_ANOM_A1_RATE = 0,
    WEB_ANOM_A2_NEW,
    WEB_ANOM_A3_HOURS,
    WEB_ANOM_A5_IDENT,
    WEB_ANOM_A6_NAMES,
    WEB_ANOM_A7_FANOUT,
    WEB_ANOM_A8_DNS,
    WEB_ANOM_A9_PROTO,
    WEB_ANOM_A10_SENSOR,
    WEB_ANOM_RULE_COUNT
};

enum { WEB_EP_FREE = 0, WEB_EP_BUILDING, WEB_EP_OPEN, WEB_EP_CLOSED };

#define WEB_ANOM_CAP            512
#define WEB_ANOM_EVIDENCE_MAX   WEB_STORE_EV_MAX
#define WEB_ANOM_CLEAR_TICKS    2
#define WEB_ANOM_STREAK_MIN     3
#define WEB_ANOM_Z_THRESHOLD    3.0
#define WEB_ANOM_MAD_THRESHOLD  3.5
#define WEB_ANOM_MAD_N          28
#define WEB_ANOM_MAD_MIN        6
#define WEB_ANOM_MAD_PER_MIN    32
#define WEB_ANOM_A2_WINDOW_S    86400
#define WEB_ANOM_A2_SKEW_S      300
#define WEB_ANOM_A3_MEAN_MAX    0.1
#define WEB_ANOM_A3_MIN_N       4
#define WEB_ANOM_A7_WINDOW_S    600
#define WEB_ANOM_A7_MIN_WINDOWS 144
#define WEB_ANOM_A7_HALFLIFE_W  1008
#define WEB_ANOM_A7_FACTOR      2.0
#define WEB_ANOM_A7_MIN_EXCESS  5.0
#define WEB_ANOM_A7_BINS        16
#define WEB_ANOM_A8_MIN_Q       20
#define WEB_ANOM_A8_NX_SHARE    0.30
#define WEB_ANOM_A8_WINDOW_S    (WEB_ID_DNS_MINUTES * 60)
#define WEB_ANOM_A10_SILENCE_S  60
#define WEB_ANOM_COVER_MIN      45
/* Closed episodes are kept this long; /api/anomalies lists those whose
 * last_seen is within ?since (an hour by default). */
#define WEB_ANOM_KEEP_S         86400
#define WEB_ANOM_RECENT_S       3600
/* The largest one episode can render to (web_anomaly_json): every byte
 * of the evidence and the key at WEB_JW_EXPAND, the rest fixed. */
#define WEB_ANOM_EP_JSON_MAX \
    ((WEB_ANOM_EVIDENCE_MAX + WEB_KEY_MAX) * WEB_JW_EXPAND + 320)

typedef struct {
    long long id;
    int       state;
    int       rule;
    int       metric;              /* WM_*, or -1 */
    char      key[WEB_KEY_MAX + 1];
    double    score, peak;         /* 0..100 */
    char      evidence[WEB_ANOM_EVIDENCE_MAX + 1];
    long long first_seen, last_seen;
    long long last_bucket;         /* the last bucket that advanced it */
    int       hit_streak, clear_streak;
    unsigned long long seq;        /* of its last visible change */
    int       dirty;               /* to be written to the store */
} web_anom_ep_t;

typedef struct {
    unsigned long opened, closed, dropped, evicted_closed;
    unsigned long candidates_dropped, rows_dropped, late_rows;
    unsigned long hours_fed, hours_unobserved, minutes_unobserved;
    unsigned long mad_queries, mad_skipped, a9_queries, a9_errors;
    unsigned long fanout_evictions, reported_evictions, known_evictions;
    unsigned long persist_errors;
    int           open, building, closed_kept, fanout, reported;
} web_anom_stats_t;

typedef long long (*web_mono_fn)(void *ctx);

typedef struct {
    web_baseline_t *bl;
    web_store_t    *store;     /* NULL: memory only */
    web_live_t     *live;      /* NULL: every minute counts as observed */
    web_ident_t    *ident;     /* NULL: A2, A5, A6 and A8 have no input */
    web_mono_fn     mono;      /* web_live's clock; NULL: CLOCK_MONOTONIC */
    void           *mono_ctx;
    int             max_keys;  /* --web-max-keys, for the table sizes */
} web_anom_cfg_t;

struct web_anom_priv;

typedef struct web_anomaly {
    pthread_mutex_t     mu;       /* guards ep[], seq, st */
    web_anom_ep_t      *ep;
    int                 cap;
    unsigned long long  seq;
    web_anom_stats_t    st;
    web_anom_cfg_t      cfg;
    struct web_anom_priv *p;      /* the store thread's own state */
} web_anomaly_t;

/* 0, or -1 (memory). cap is WEB_ANOM_CAP in slothweb. */
int  web_anomaly_init(web_anomaly_t *a, int cap, const web_anom_cfg_t *cfg);
void web_anomaly_destroy(web_anomaly_t *a);

/* Hook a into t: the rows hook and the step hook. Before
 * web_tsdb_start(). */
void web_anomaly_attach(web_anomaly_t *a, web_tsdb_t *t);

/* Load the baselines, episodes, A7 histograms and A2's reported set
 * from the store, if there is one. Before any thread starts. Episodes
 * whose last_seen is older than now_s - WEB_ANOM_KEEP_S are dropped.
 * 0, or -1 (the store refused a read; the engine starts empty). */
int  web_anomaly_restore(web_anomaly_t *a, long long now_s);

/* The two hooks (also called directly by the tests). */
void web_anomaly_rows(void *a, const web_qrow_t *rows, size_t n);
void web_anomaly_step(web_anomaly_t *a, long long now_s);

/* Spec §6 kind of a rule ("rate", "new", "hours", "ident", "fanout",
 * "dns", "proto", "sensor"), and the rule's own name ("A1".."A10"). */
const char *web_anomaly_kind(int rule);
const char *web_anomaly_rule(int rule);
/* A kind name to match against, or -1. */
int         web_anomaly_kind_find(const char *kind);

/* {"now":..,"since":..,"anomalies":[...],"more":..,"omitted":..}: open
 * episodes first, highest score first, then closed ones with last_seen
 * >= since, newest first; kind -1 for all, else one kind. When the next
 * episode might not fit, the list stops there with "more":true and
 * "omitted" counting what was left out, so the answer always fits in
 * cap (cap must exceed WEB_ANOM_EP_JSON_MAX + 128). 0 only if cap is
 * smaller than that. */
size_t web_anomaly_json(web_anomaly_t *a, long long now_s, long long since,
                        int kind, char *out, size_t cap);

/* One episode as JSON (the SSE "anomaly" event's data). */
void   web_anomaly_ep_json(web_jw_t *w, const web_anom_ep_t *e);

/* Episodes whose last visible change is newer than after, oldest change
 * first, at most max (the newest max when more changed); *latest gets
 * the newest seq. Returns how many. */
int    web_anomaly_changes(web_anomaly_t *a, unsigned long long after,
                           web_anom_ep_t *out, int max,
                           unsigned long long *latest);

int    web_anomaly_open_count(web_anomaly_t *a);
void   web_anomaly_stats(web_anomaly_t *a, web_anom_stats_t *out);

#endif
