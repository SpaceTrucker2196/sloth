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
 *                consecutive observed minutes. The z of a minute uses
 *                the cell's minute spread, sqrt(var + wvar)
 *                (web_baseline.h): the week-to-week spread of the hour
 *                plus the spread of minutes inside it, which the engine
 *                learns from the minute rows it scores (summed per
 *                series per hour, handed over when the hour is fed). A
 *                counter with a baseline and no row this minute counted
 *                0 and is scored as 0; a gauge with no row was not
 *                measured and breaks the streak. A counter must also
 *                pass the MAD ratio (§5.3, below) when the store has
 *                the history for it.
 *   A2  new      a MAC whose own first_seen (the probe_client,
 *                pnl_client or assoc row's, from sloth) is within
 *                WEB_ANOM_A2_WINDOW_S of now, and of which slothweb
 *                holds nothing older than that window: no dev.present
 *                or dev.frames baseline entry first fed before it, and
 *                no minute or hour row of either in the store before it.
 *                sloth sets first_seen to now whenever it makes a client
 *                entry (at its restart, src/capture/probe.c), so its
 *                first_seen alone is not "new". Reported once per MAC
 *                while slothweb remembers it: the reported set (it
 *                outlives a restart) is keyed by first_seen and holds
 *                --web-max-keys MACs; full, it forgets the one with the
 *                oldest first_seen (counted, reported_evicted on
 *                /api/health), which moves to the set of MACs not to
 *                report one by one, and a MAC both sets have let go may
 *                be reported a second time. That is the accepted cost: a
 *                duplicate "new device" is better than a hidden one, and
 *                the re-reports are at most the evictions. A MAC is
 *                judged new once: the scan puts it in one set or the
 *                other as it counts it, so nothing is offered twice
 *                while those sets hold it (the not-one-by-one set holds
 *                as many MACs as the identity tables, so only a churn
 *                past them makes it judge one afresh). A MAC is marked
 *                reported only once its episode exists: one the table
 *                cannot take is counted (dropped) and judged afresh the
 *                next minute, so a full table delays a report, never
 *                loses it. More than WEB_ANOM_A2_BURST new
 *                MACs in one minute, or more than WEB_ANOM_A2_HOUR_MAX
 *                in a rolling hour (each MAC counted in the minute it
 *                was judged new, in memory: a restart starts it at 0),
 *                are one episode keyed "", held while the hour is over,
 *                not one each, and are not put in the reported set. Its
 *                evidence counts the MACs judged new in that minute or
 *                that hour, exactly, and names at most two, whole. The
 *                stated cost of the fold: a real device that arrives
 *                inside a spoofed trickle or burst is one of the MACs
 *                folded into the "" episode and is not reported on its
 *                own. At most WEB_ANOM_A2_CHECKS_PER_MIN store lookups a
 *                minute; the rest wait a minute (counted, and not yet
 *                judged). Randomised MACs are left out: every rotation
 *                is new by construction, and A5 is the rule about them.
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
 *                A row released late (a host new to the stream has its
 *                first minute held until its key is established) is
 *                checked as it arrives, at its own t. Needs the store;
 *                a memory-only build skips it.
 *   A10 sensor   the socket is connected and nothing has arrived for
 *                WEB_ANOM_A10_SILENCE_S, counted from the later of the
 *                last record and the connection itself, so a connection
 *                that never sends fires and a fresh one does not.
 *
 *   A4  vendor   (M4, #162) a MAC present this minute (dev.present)
 *                that is globally administered and unicast and whose
 *                OUI the full IEEE table (web_oui.h) does not hold in
 *                any of its MA-L, MA-M or MA-S blocks. Only with a table
 *                built from the IEEE MA-L registry: sloth's 117-entry
 *                fallback misses most vendors by design, so with it the
 *                rule is off and /api/health says why (a4_reason). Its
 *                episode is held while the MAC stays present. More than
 *                WEB_ANOM_A4_BURST such MACs in one minute are one
 *                episode keyed "", as A2's burst: spoofed addresses with
 *                made-up OUIs would otherwise take the table.
 *
 * A2's durable source (M4). With --sloth-db, sloth.db is asked as well:
 * the earliest first_seen it holds for the MAC (devices, probe_clients,
 * pnl_clients, assocs), which sloth keeps as MIN() across its own
 * restarts (src/db.c). Older than the window, the MAC is not new
 * whatever the stream's first_seen says; within it, the MAC is judged
 * as before (slothweb's own memory still has a say). sloth.db also
 * names candidates the stream cannot: a MAC whose devices.first_seen is
 * within the window (a wired device, learnt from ARP, carries no
 * first_seen on the stream), at most WEB_ANOM_A2_SDB_NEW a minute. A
 * MAC sloth.db does not hold, or no sloth.db, is the stream path as it
 * was. At most WEB_ANOM_A2_CHECKS_PER_MIN lookups a minute, one
 * connection for the pass, closed after it.
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
 * takes a free slot, else its own rule's oldest closed one, else (while
 * its rule holds less than cap / rules) the oldest closed one of a rule
 * holding more than that; never another rule's otherwise, so one rule's
 * flood cannot erase the others' history. An open or building episode
 * is never pushed out (the new one is dropped and counted).
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
#include "web_oui.h"
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
    WEB_ANOM_A4_VENDOR,
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
#define WEB_ANOM_A2_BURST       8
#define WEB_ANOM_A2_HOUR_MAX    16
#define WEB_ANOM_A2_CHECKS_PER_MIN 256
#define WEB_ANOM_A2_SDB_NEW     64
#define WEB_ANOM_A4_BURST       8
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
    unsigned long fanout_evictions, reported_evicted, known_evictions;
    unsigned long persist_errors;
    unsigned long a2_queries, a2_errors, a2_not_new, a2_deferred;
    unsigned long ident_truncated, a2_in_burst;
    unsigned long a2_sdb_queries, a2_sdb_old, a2_sdb_errors, a2_sdb_new;
    unsigned long a4_checked, a4_unknown, a4_in_burst;
    int           open, building, closed_kept, fanout, reported;
} web_anom_stats_t;

typedef long long (*web_mono_fn)(void *ctx);

struct web_slothdb;
struct web_ptr;

typedef struct {
    web_baseline_t *bl;
    web_store_t    *store;     /* NULL: memory only */
    web_live_t     *live;      /* NULL: every minute counts as observed */
    web_ident_t    *ident;     /* NULL: A2, A5, A6 and A8 have no input */
    web_mono_fn     mono;      /* web_live's clock; NULL: CLOCK_MONOTONIC */
    void           *mono_ctx;
    int             max_keys;  /* --web-max-keys, for the table sizes */
    /* M4 (#162): each may be NULL. */
    const web_oui_tab_t *oui;  /* A4 runs only when web_oui_full() */
    struct web_slothdb  *sdb;  /* A2's durable first_seen */
    struct web_ptr      *ptr;  /* the passive PTR cache, persisted here */
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

/* One episode as web_anomaly_restore() takes it from the store, with
 * the same checks (a bad id, time, state, kind or metric is dropped;
 * scores are clamped to 0..100). For the tests, which can hand it
 * values the store's reader never produces. */
void web_anomaly_restore_episode(web_anomaly_t *a, const web_store_ep_t *s);

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
/* The episodes a capture scope holds (web_scope.h): A1 by its metric and
 * key, A2 Monitor (a probe, PNL or association), A3 and A4 where the
 * MAC has presence of the scope's own in ru (they score every source's,
 * and say so), A5-A9 Local, A10 every scope. sc NULL is Hybrid. */
size_t web_anomaly_json_scoped(web_anomaly_t *a, long long now_s,
                               long long since, int kind,
                               const web_scope_ctx_t *sc, web_rollup_t *ru,
                               char *out, size_t cap);
int    web_anomaly_ep_tag(const web_anom_ep_t *e, const web_scope_ctx_t *sc,
                          web_rollup_t *ru);

/* One episode as JSON (the SSE "anomaly" event's data). */
void   web_anomaly_ep_json(web_jw_t *w, const web_anom_ep_t *e);

/* Episodes whose last visible change is newer than after, oldest change
 * first, at most max (the newest max when more changed); *latest gets
 * the newest seq. Returns how many. */
int    web_anomaly_changes(web_anomaly_t *a, unsigned long long after,
                           web_anom_ep_t *out, int max,
                           unsigned long long *latest);

int    web_anomaly_open_count(web_anomaly_t *a);

/* M4's readers (HTTP thread): the |z| A1 last scored for a device key
 * (the largest over its metrics) in the last WEB_ANOM_Z_FRESH_S, 1 with
 * it in *z or 0; the open and recent episodes keyed key, of one kind
 * (web_anomaly_kind_find()'s index) or all (-1); and up to max of them,
 * open first, newest first. */
#define WEB_ANOM_Z_FRESH_S 180
int    web_anomaly_device_z(web_anomaly_t *a, const char *key, long long now_s,
                            double *z);
int    web_anomaly_key_count(web_anomaly_t *a, const char *key, int kind);
int    web_anomaly_key_list(web_anomaly_t *a, const char *key,
                            web_anom_ep_t *out, int max);

/* Why A4 is off, or NULL when it runs. */
const char *web_anomaly_a4_reason(const web_anomaly_t *a);
void   web_anomaly_stats(web_anomaly_t *a, web_anom_stats_t *out);

#endif
