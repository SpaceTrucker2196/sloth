/* slothweb.db (#160, M2; #161, M3): slothweb's own SQLite file. Never
 * sloth.db.
 *
 * The file holds the closed rollup buckets: a series table naming each
 * (metric, key), and one table per tier with sum, count, min and max
 * per bucket, keyed (series, t) and indexed on t. Since v3 it also
 * holds the anomaly engine's state (the baselines, the episodes, A7's
 * histograms and A2's reported MACs; web_anomaly.h). Keys are canonical
 * MACs, IPs, interface names, channels and alert types (web_metrics.h),
 * so no string a peer chose is ever stored as it was sent as a key; the
 * one free text is an episode's evidence, slothweb's own sentence with
 * any stream name in it cut to a code-point boundary. No column can
 * hold a credential (web/tests/test_store.c keeps sloth's test_db.c
 * guardrail).
 *
 * Opening it follows sloth's own rules for its database (src/db.c,
 * src/secure_file.c), re-implemented here because no src/ file is
 * compiled into slothweb: the path is opened by descriptor with
 * O_NOFOLLOW and created 0600; an existing file must be a regular file
 * owned by the effective uid with no group or other bits and one link;
 * the -wal, -shm and -journal files, when present, pass the same test;
 * SQLite then opens it with SQLITE_OPEN_NOFOLLOW and DEFENSIVE on.
 *
 * Before anything is written the file is identified, on a read-only
 * connection: a read-write one that closes last on a WAL database
 * checkpoints the WAL into it, which would rewrite a refused sloth.db.
 * A WAL-mode file with no -wal is read there as an immutable URI, so
 * that a refusal leaves no -wal or -shm behind either. Only a file
 * found ours or empty is opened read-write, and identified again there.
 * An empty file is new: no schema object, and application_id and
 * user_version both 0, so a file another program has only stamped is
 * not taken for one. A new store is stamped with slothweb's own
 * application_id (WEB_STORE_APP_ID), and a file carrying any other
 * non-zero one is refused. A file whose meta table names it a slothweb store is ours, at
 * the schema version recorded beside it. Anything else (sloth.db, any
 * other database) is refused untouched. A version newer than this
 * build's is refused untouched. An older one is brought forward one
 * step at a time (the 2026-10-21 owner rule): each step additive, in
 * one BEGIN IMMEDIATE transaction with its own version stamp, so a
 * failure leaves the file at the version it last fully reached. A new
 * file is stamped v0 first and takes the same path, so the chain from
 * v0 runs on every first start.
 *
 * Writes come only from the store thread (web_tsdb.c), batched, never
 * from the HTTP thread; queries come only from the HTTP thread, over a
 * second, read-only connection, with every parameter bound. WAL lets
 * the two run side by side.
 *
 * Built without WITH_SQLITE, every call is a stub: open fails with
 * "built without SQLite", and /api/series serves the in-memory fine
 * tier only. */
#ifndef SLOTHWEB_STORE_H
#define SLOTHWEB_STORE_H

#include <pthread.h>
#include <stddef.h>

#include "web_baseline.h"
#include "web_rollup.h"

/* The version this build writes. */
#define WEB_STORE_SCHEMA   3
#define WEB_STORE_ERR_MAX  320
#define WEB_DEFAULT_STORE  "./slothweb.db"
/* --web-max-mb: the ceiling on the store's used pages. */
#define WEB_DEFAULT_MAX_MB 256
#define WEB_MAX_MB_MAX     1048576
/* PRAGMA application_id of a slothweb store: "SLWE". Stores made
 * before it was stamped carry 0 and are still ours by their meta. */
#define WEB_STORE_APP_ID   0x534c5745
/* What one transaction of upkeep may change, so that none grows the
 * WAL much past a few MB (a single delete of everything a long stop
 * expired grew it to the size of the file): a ceiling slice deletes the
 * WEB_STORE_SLICE_ROWS oldest rows of its class; an expiry tile the
 * expired rows of WEB_STORE_EXPIRE_SERIES series within
 * WEB_STORE_EXPIRE_STEPS buckets of t; incremental_vacuum frees
 * WEB_STORE_VACUUM_PAGES pages at a time. */
#define WEB_STORE_SLICE_ROWS    2048
#define WEB_STORE_EXPIRE_SERIES 256
#define WEB_STORE_EXPIRE_STEPS  256
#define WEB_STORE_VACUUM_PAGES  256

#define WEB_STORE_AN_STMTS 16

struct sqlite3;
struct sqlite3_stmt;

typedef struct {
    int           open;
    int           schema;
    long long     rows[WEB_TIER_COUNT];   /* rows stored: the writer counts
                                             inserts, not merges; recounted
                                             at open and each compaction */
    long long     bytes;                  /* used pages x page size */
    long long     file_bytes;             /* page_count x page size */
    unsigned long batches, rows_written, write_errors;
    unsigned long compactions;
    unsigned long long dropped_expired, dropped_ceiling;
    unsigned long ceiling_runs;           /* passes that dropped rows */
    unsigned long ceiling_raised;         /* passes that trimmed the time
                                             series to the history
                                             allowance, the analysis state
                                             leaving less than it under
                                             the ceiling */
    long long     analysis_bytes;         /* its pages when last measured
                                             (dbstat), -1 not measurable */
    unsigned long bl_rows_reused;         /* baseline rows a new entry
                                             took over (a delete that
                                             had not reached the file) */
    long long     last_compact;           /* unix s, 0 never */
    char          last_error[WEB_STORE_ERR_MAX];
} web_store_stats_t;

typedef struct {
    struct sqlite3      *db;      /* the store thread's */
    struct sqlite3      *rd;      /* the HTTP thread's, read-only */
    struct sqlite3_stmt *ins_series, *get_series, *ins_row[WEB_TIER_COUNT];
    struct sqlite3_stmt *upd_row[WEB_TIER_COUNT];
    struct sqlite3_stmt *q_row[WEB_TIER_COUNT];
    struct sqlite3_stmt *an[WEB_STORE_AN_STMTS];  /* the analysis state's */
    long long            an_bl;     /* the baseline tables' pages */
    int                  an_fresh;  /* an_bl is current; cleared by every
                                       baseline write */
    long long            hist_allow; /* the history allowance, bytes */
    pthread_mutex_t      mu;      /* guards st */
    pthread_mutex_t      rmu;     /* serialises rd */
    int                  mu_init;
    web_store_stats_t    st;
    char                 path[4096];
} web_store_t;

/* 1 when this build has SQLite. */
int  web_store_available(void);

/* Open (creating, identifying, migrating) the store at path. 0, or -1
 * with err; a refused file is left as it was found. Call
 * web_store_close() either way. */
int  web_store_open(web_store_t *s, const char *path, char *err, size_t errsz);
void web_store_close(web_store_t *s);

/* The rows, in one transaction. Their (series, t) may already be on
 * disk (a bucket closed early by an eviction or a shutdown, then
 * finished): that row is merged, sum and count added, min and max
 * widened, and is not counted again in rows[]. 0, or -1 (counted, and
 * the reason kept). */
int  web_store_write(web_store_t *s, const web_qrow_t *rows, size_t n);

/* The --web-max-mb ceiling, run after every batch write (so it bounds
 * the file within one flush interval, not one compaction) and inside
 * every compaction. Cheap when under: the used size is three PRAGMAs.
 * Over it, slices are dropped until it is under: the oldest
 * WEB_STORE_SLICE_ROWS fine rows (any series) until no fine row is
 * left, then the oldest keyed minute rows, then the oldest keyed hour
 * rows, and only then the same for the global series. Each slice is
 * the head of the t index and its own transaction. The series rows
 * left with no bucket are swept once after, and free pages go back to
 * the file system, WEB_STORE_VACUUM_PAGES at a time. Rows dropped, or
 * -1.
 *
 * The ceiling is the whole file's used pages, the analysis state (v3's
 * baseline, baseline_cell, episode, fanout and reported tables)
 * included, but only time-series rows can be dropped. So the bound a
 * pass enforces is
 *
 *     used <= max(max_bytes, analysis + hist_allow)
 *
 * with analysis the analysis state's own pages (dbstat) and hist_allow
 * the history allowance (web_store_set_history_allowance()): when the
 * analysis state leaves less than the allowance under the ceiling, the
 * time series is trimmed to the allowance instead of to the ceiling,
 * and the pass is counted in ceiling_raised (/api/health
 * store_ceiling_raised). The time series is never erased to make room
 * the analysis state takes, and never kept without a limit either: it
 * is bounded by the allowance while the analysis state stays over. Each
 * bound holds to within one slice and the series rows the sweep frees.
 * slothweb refuses at start a --web-max-mb below
 * web_store_analysis_max_bytes() plus the allowance
 * (web_config_check()), so at the configured caps only an analysis
 * state beyond the estimate gets here.
 *
 * The baseline tables (nearly all of the analysis state) are measured
 * when a pass first needs the figure and kept until the next baseline
 * write (web_store_bl_put, web_store_bl_del, web_store_bl_load); the
 * episode, fanout and reported tables are bounded at a few hundred KB
 * and are measured afresh on every pass that needs the figure (dbstat
 * reads only the b-trees it is named), so no write leaves the figure
 * stale past the next pass. A library without dbstat cannot measure it
 * (analysis_bytes -1): the allowance is then not applied, and the pass
 * drops until under max_bytes or out of rows. */
long long web_store_ceiling(web_store_t *s, long long max_bytes);

/* The time series the ceiling keeps when the analysis state alone
 * would leave less: 0 (the default) keeps none. slothweb sets
 * web_store_history_bytes() of its baseline capacity after the open. */
void web_store_set_history_allowance(web_store_t *s, long long bytes);

/* An estimate of the most the analysis state can take in the file:
 * bl_cap baseline entries with every one of their 168 cells, ep_cap
 * episodes, hosts fan-out histograms and macs reported MACs, at the
 * row sizes below (payload, b-tree overhead and the UNIQUE index; pages
 * about three quarters full). Not a measurement: the order of
 * magnitude a ceiling has to clear. */
#define WEB_STORE_EST_CELL_B  56
#define WEB_STORE_EST_ROW_B   160
#define WEB_STORE_EST_EP_B    400
#define WEB_STORE_EST_FAN_B   200
#define WEB_STORE_EST_REP_B   80
long long web_store_analysis_max_bytes(int bl_cap, int ep_cap, int hosts,
                                       int macs);

/* The history allowance: WEB_STORE_HIST_HOURS hour rows for each of
 * bl_cap series, at WEB_STORE_EST_TSROW_B a row. A week of hour rows
 * for every series the baselines can hold is the least history in
 * which each hour-of-week cell has one row behind it: what A9's "any
 * row before" and the MAD ratio's same-hour reads stand on. 64 bytes a
 * row is measured: 828,240 hour rows (4,930 series, the baselines at
 * the default --web-max-keys, for 168 hours, written hour by hour as
 * slothweb writes them) took 51,748,864 bytes of 4 KB pages with the t
 * index, 62.5 bytes each. About 51 MB at the default --web-max-keys,
 * 760 MB at 8,192 (MB here and in the refusal are 2^20 bytes). */
#define WEB_STORE_HIST_HOURS  168
#define WEB_STORE_EST_TSROW_B 64
long long web_store_history_bytes(int bl_cap);

/* Hourly upkeep: drop rows past each tier's retention (fine 24 h,
 * minute retain_days, hour 400 d), a tile of series and t at a time;
 * then the ceiling as above; then return free pages and truncate the
 * WAL. 0, or -1. */
int  web_store_compact(web_store_t *s, long long now_s, int retain_days,
                       long long max_bytes);

/* Buckets of (metric, key) in tier with from <= t < to, newest first,
 * at most max; *more is set when there were more. Read-only connection,
 * parameters bound. Returns the count, or -1 on an error. */
int  web_store_query(web_store_t *s, int tier, int metric, const char *key,
                     long long from, long long to, web_point_t *out, int max,
                     int *more);

void web_store_stats(web_store_t *s, web_store_stats_t *out);

/* Rows in tier, counted now (tests and the recount). -1 on error. */
long long web_store_count(web_store_t *s, int tier);

/* ── the analysis state (v3, #161) ───────────────────────────────────
 *
 * Everything below runs on the writer connection, so only from the
 * thread that owns it: the store thread, or the main thread before any
 * thread starts (the restore). Each call that writes is one
 * transaction. Every string read back is checked again by its caller as
 * if it came off the wire: a key passes its canonicaliser, a metric and
 * a kind must be a catalogue name, evidence is cut on a code-point
 * boundary. Built without SQLite every call returns -1. */

/* Restore the baseline: the cap most recently active entries, with
 * their cells, into b; the rows of any entry beyond the cap are
 * deleted. Entries loaded, or -1. */
int  web_store_bl_load(web_store_t *s, web_baseline_t *b);
/* Write n dirty records (web_baseline_take_dirty()); an entry new to
 * the file gets its row id given back to b. 0, or -1. */
int  web_store_bl_put(web_store_t *s, web_baseline_t *b,
                      const web_bl_rec_t *recs, int n);
/* Delete entries by row id, with their cells. 0, or -1. */
int  web_store_bl_del(web_store_t *s, const long long *ids, int n);

#define WEB_STORE_KIND_MAX 15
#define WEB_STORE_EV_MAX   159
typedef struct {
    long long id;
    char      kind[WEB_STORE_KIND_MAX + 1];
    int       metric;                 /* -1 none */
    char      key[WEB_KEY_MAX + 1];
    int       state;
    double    score, peak;
    char      evidence[WEB_STORE_EV_MAX + 1];
    long long first_seen, last_seen;
    int       hit_streak, clear_streak;
    long long last_bucket;
} web_store_ep_t;

/* Every episode with last_seen >= since, to fn. Rows, or -1. */
int  web_store_ep_load(web_store_t *s, long long since,
                       void (*fn)(void *ctx, const web_store_ep_t *e),
                       void *ctx);
int  web_store_ep_put(web_store_t *s, const web_store_ep_t *e, int n);
int  web_store_ep_del(web_store_t *s, const long long *ids, int n);

#define WEB_STORE_HIST_MAX 255
typedef struct {
    char key[WEB_KEY_MAX + 1];
    long windows;
    char hist[WEB_STORE_HIST_MAX + 1];
} web_store_fan_t;
int  web_store_fan_load(web_store_t *s,
                        void (*fn)(void *ctx, const web_store_fan_t *f),
                        void *ctx);
int  web_store_fan_put(web_store_t *s, const web_store_fan_t *f, int n);
int  web_store_fan_del(web_store_t *s, const char (*keys)[WEB_KEY_MAX + 1],
                       int n);

typedef struct {
    char      kind[WEB_STORE_KIND_MAX + 1];
    char      key[WEB_KEY_MAX + 1];
    long long t;
} web_store_rep_t;
/* Rows with t >= since, to fn; rows older than since are deleted
 * first. */
int  web_store_rep_load(web_store_t *s, long long since,
                        void (*fn)(void *ctx, const web_store_rep_t *r),
                        void *ctx);
int  web_store_rep_put(web_store_t *s, const web_store_rep_t *r, int n);
int  web_store_rep_prune(web_store_t *s, long long before);

/* Whether (metric, key) has any minute row with t < before, or any hour
 * row with t < before rounded down to its hour: 1, 0, or -1. */
int  web_store_any_before(web_store_t *s, int metric, const char *key,
                          long long before);
/* The hour rows of (metric, key) at each of the n hour starts ts[];
 * out[i].t is ts[i] when there was one and -1 when not. Rows found, or
 * -1. */
int  web_store_hours_at(web_store_t *s, int metric, const char *key,
                        const long long *ts, int n, web_point_t *out);

/* Test seams (web/tests/test_store.c); NULL and 0 in slothweb itself.
 * web_store_test_between_opens runs after the read-only identify and
 * before the read-write open, so a test can swap the file there as
 * another process could. web_store_test_no_defensive makes open_db()
 * read DEFENSIVE back as off, as a library ignoring it would.
 * web_store_test_after_commit runs after every transaction the
 * compaction and the ceiling commit, where the WAL is at its largest,
 * so a test can measure it there. None is set anywhere but the tests.
 * SQLite builds only. */
extern void (*web_store_test_between_opens)(const char *path);
extern int    web_store_test_no_defensive;
extern void (*web_store_test_after_commit)(const char *path);

/* The DDL of the version this build writes, and the step from version
 * from to from + 1 (NULL past the end). For the guardrail tests. */
const char *web_store_meta_sql(void);
const char *web_store_step_sql(int from);

#endif
