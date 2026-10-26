#include "web_store.h"

#include "web_json.h"
#include "web_metrics.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The schema, as text, exists in every build: the guardrail tests read
 * it whether or not SQLite is linked. */

static const char META_SQL[] =
    "CREATE TABLE meta (\n"
    "  name  TEXT PRIMARY KEY,\n"
    "  value TEXT NOT NULL\n"
    ");\n";

/* v0 -> v1: the rollup tables. Plain CREATE TABLE, not IF NOT EXISTS: an
 * object already holding one of these names is not ours to reuse, and
 * the step must fail (leaving the file at v0) rather than adopt it. */
static const char STEP_V1_SQL[] =
    "CREATE TABLE series (\n"
    "  id     INTEGER PRIMARY KEY,\n"
    "  metric TEXT NOT NULL,\n"
    "  key    TEXT NOT NULL,\n"
    "  UNIQUE (metric, key)\n"
    ");\n"
    "CREATE TABLE fine (\n"
    "  series INTEGER NOT NULL,\n"
    "  t      INTEGER NOT NULL,\n"
    "  sum    REAL NOT NULL,\n"
    "  n      INTEGER NOT NULL,\n"
    "  min    REAL NOT NULL,\n"
    "  max    REAL NOT NULL,\n"
    "  PRIMARY KEY (series, t)\n"
    ") WITHOUT ROWID;\n"
    "CREATE TABLE minute (\n"
    "  series INTEGER NOT NULL,\n"
    "  t      INTEGER NOT NULL,\n"
    "  sum    REAL NOT NULL,\n"
    "  n      INTEGER NOT NULL,\n"
    "  min    REAL NOT NULL,\n"
    "  max    REAL NOT NULL,\n"
    "  PRIMARY KEY (series, t)\n"
    ") WITHOUT ROWID;\n"
    "CREATE TABLE hour (\n"
    "  series INTEGER NOT NULL,\n"
    "  t      INTEGER NOT NULL,\n"
    "  sum    REAL NOT NULL,\n"
    "  n      INTEGER NOT NULL,\n"
    "  min    REAL NOT NULL,\n"
    "  max    REAL NOT NULL,\n"
    "  PRIMARY KEY (series, t)\n"
    ") WITHOUT ROWID;\n";

/* v1 -> v2: an index on t in each tier. Retention, the --web-max-mb
 * ceiling's oldest-slice deletes and its MIN(t) all select on t alone,
 * and without these each was a full scan of the tier: at the 256 MB
 * ceiling one trim took 4.8 s on the store thread. Additive: a new
 * index changes no row. */
static const char STEP_V2_SQL[] =
    "CREATE INDEX fine_t ON fine (t);\n"
    "CREATE INDEX minute_t ON minute (t);\n"
    "CREATE INDEX hour_t ON hour (t);\n";

/* v2 -> v3 (#161, M3): the analysis state that has to outlive a
 * restart. baseline names a (metric, key) and when it was last active
 * and last fed; baseline_cell holds its hour-of-week cells, keyed
 * (cell, id) so that the hourly write, which changes the same cell of
 * every entry, touches a run of adjacent rows rather than a page per
 * entry. episode holds the open and recently closed anomaly episodes;
 * fanout A7's per-host window histograms (the weights as text, so that
 * no column is a blob); reported the MACs A2 has reported, so that each
 * is reported once across a restart. Additive: five new tables, nothing
 * that exists is changed. */
static const char STEP_V3_SQL[] =
    "CREATE TABLE baseline (\n"
    "  id          INTEGER PRIMARY KEY,\n"
    "  metric      TEXT NOT NULL,\n"
    "  key         TEXT NOT NULL,\n"
    "  last_active INTEGER NOT NULL,\n"
    "  last_fed    INTEGER NOT NULL,\n"
    "  first_fed   INTEGER NOT NULL DEFAULT -1,\n"
    "  UNIQUE (metric, key)\n"
    ");\n"
    "CREATE TABLE baseline_cell (\n"
    "  cell INTEGER NOT NULL,\n"
    "  id   INTEGER NOT NULL,\n"
    "  mean REAL NOT NULL,\n"
    "  var  REAL NOT NULL,\n"
    "  n    INTEGER NOT NULL,\n"
    "  wvar REAL NOT NULL DEFAULT 0,\n"
    "  wn   INTEGER NOT NULL DEFAULT 0,\n"
    "  PRIMARY KEY (cell, id)\n"
    ") WITHOUT ROWID;\n"
    "CREATE TABLE episode (\n"
    "  id           INTEGER PRIMARY KEY,\n"
    "  kind         TEXT NOT NULL,\n"
    "  metric       TEXT NOT NULL,\n"
    "  key          TEXT NOT NULL,\n"
    "  state        INTEGER NOT NULL,\n"
    "  score        REAL NOT NULL,\n"
    "  peak         REAL NOT NULL,\n"
    "  evidence     TEXT NOT NULL,\n"
    "  first_seen   INTEGER NOT NULL,\n"
    "  last_seen    INTEGER NOT NULL,\n"
    "  hit_streak   INTEGER NOT NULL,\n"
    "  clear_streak INTEGER NOT NULL,\n"
    "  last_bucket  INTEGER NOT NULL\n"
    ");\n"
    "CREATE TABLE fanout (\n"
    "  key     TEXT PRIMARY KEY,\n"
    "  windows INTEGER NOT NULL,\n"
    "  hist    TEXT NOT NULL\n"
    ") WITHOUT ROWID;\n"
    "CREATE TABLE reported (\n"
    "  kind TEXT NOT NULL,\n"
    "  key  TEXT NOT NULL,\n"
    "  t    INTEGER NOT NULL,\n"
    "  PRIMARY KEY (kind, key)\n"
    ") WITHOUT ROWID;\n";

/* v3 -> v4 (#162, M4): the passive PTR cache (docs/web-ui-spec.md
 * §9.3): a PTR answer seen on the wire names the address it was asked
 * about, so the cache fills without slothweb sending a query. One row
 * per address, the latest name; bounded (web_store_ptr_put() keeps the
 * WEB_PTR_CAP most recently seen and counts what it drops). A name is
 * not a credential, and the address is canonical (web_key_ip). Additive:
 * one new table and its index, nothing that exists is changed. */
static const char STEP_V4_SQL[] =
    "CREATE TABLE passive_ptr (\n"
    "  ip         TEXT PRIMARY KEY,\n"
    "  name       TEXT NOT NULL,\n"
    "  first_seen INTEGER NOT NULL,\n"
    "  last_seen  INTEGER NOT NULL\n"
    ") WITHOUT ROWID;\n"
    "CREATE INDEX passive_ptr_last ON passive_ptr (last_seen);\n";

/* v4 -> v5: the WiFi view's channel mix (web_chmix.h): per channel
 * and closed minute or hour bucket (tier 1 or 2), the frames of each of
 * its top transmitters (tx a canonical MAC, kind 1 an AP, 2 a client)
 * and of the rest (tx '', kind 0). The kind is in the key, as it is in
 * memory: a MAC that both beacons and probes is two transmitters, and
 * neither's frames are added to the other's row. The key is canonical text and the
 * rest are numbers: no SSID, nor any other string a peer chose, is
 * stored. Indexed on (tier, t), which retention, the row cap, the
 * ceiling and the grid all select on. Additive: one new table and its
 * index, nothing that exists is changed. */
static const char STEP_V5_SQL[] =
    "CREATE TABLE chmix (\n"
    "  tier    INTEGER NOT NULL,\n"
    "  channel TEXT NOT NULL,\n"
    "  t       INTEGER NOT NULL,\n"
    "  tx      TEXT NOT NULL,\n"
    "  kind    INTEGER NOT NULL,\n"
    "  frames  INTEGER NOT NULL,\n"
    "  PRIMARY KEY (tier, channel, t, tx, kind)\n"
    ") WITHOUT ROWID;\n"
    "CREATE INDEX chmix_t ON chmix (tier, t);\n";

typedef struct {
    int         from;
    const char *sql;
    const char *what;
} web_step_t;

static const web_step_t STEPS[] = {
    { 0, STEP_V1_SQL, "created series, fine, minute and hour" },
    { 1, STEP_V2_SQL, "indexed fine, minute and hour on t" },
    { 2, STEP_V3_SQL, "created baseline, baseline_cell, episode, fanout "
                      "and reported" },
    { 3, STEP_V4_SQL, "created passive_ptr" },
    { 4, STEP_V5_SQL, "created chmix" },
};
#define STEP_N ((int)(sizeof(STEPS) / sizeof(STEPS[0])))

/* The chain starts at v0 and must end at the version this build writes. */
typedef char web_store_steps_reach_current[
    (STEP_N == WEB_STORE_SCHEMA) ? 1 : -1];

const char *web_store_meta_sql(void) { return META_SQL; }

const char *web_store_step_sql(int from) {
    for (int i = 0; i < STEP_N; i++)
        if (STEPS[i].from == from) return STEPS[i].sql;
    return NULL;
}

long long web_store_analysis_max_bytes(int bl_cap, int ep_cap, int hosts,
                                       int macs) {
    long long b = 0;
    if (bl_cap > 0)
        b += (long long)bl_cap *
             (WEB_STORE_EST_ROW_B + (long long)WEB_BL_CELLS * WEB_STORE_EST_CELL_B);
    if (ep_cap > 0) b += (long long)ep_cap * WEB_STORE_EST_EP_B;
    if (hosts > 0) b += (long long)hosts * WEB_STORE_EST_FAN_B;
    if (macs > 0) b += (long long)macs * WEB_STORE_EST_REP_B;
    return b;
}

long long web_store_history_bytes(int bl_cap) {
    return bl_cap > 0
        ? (long long)bl_cap * WEB_STORE_HIST_HOURS * WEB_STORE_EST_TSROW_B : 0;
}

#ifndef WITH_SQLITE

int  web_store_available(void) { return 0; }

int web_store_open(web_store_t *s, const char *path, char *err, size_t errsz) {
    memset(s, 0, sizeof(*s));
    snprintf(err, errsz, "%s: slothweb was built without SQLite "
                         "(WITH_SQLITE=0); no store", path ? path : "?");
    return -1;
}

void web_store_close(web_store_t *s) { (void)s; }

int web_store_write(web_store_t *s, const web_qrow_t *rows, size_t n) {
    (void)s; (void)rows; (void)n;
    return -1;
}

int web_store_compact(web_store_t *s, long long now_s, int retain_days,
                      long long max_bytes) {
    (void)s; (void)now_s; (void)retain_days; (void)max_bytes;
    return -1;
}

long long web_store_ceiling(web_store_t *s, long long max_bytes) {
    (void)s; (void)max_bytes;
    return -1;
}

void web_store_set_history_allowance(web_store_t *s, long long bytes) {
    (void)s; (void)bytes;
}

int web_store_query(web_store_t *s, int tier, int metric, const char *key,
                    long long from, long long to, web_point_t *out, int max,
                    int *more) {
    (void)s; (void)tier; (void)metric; (void)key; (void)from; (void)to;
    (void)out; (void)max;
    *more = 0;
    return -1;
}

int web_store_keys(web_store_t *s, int tier, int metric, long long from,
                   long long to, char (*out)[WEB_KEY_MAX + 1], int max) {
    (void)s; (void)tier; (void)metric; (void)from; (void)to; (void)out;
    (void)max;
    return -1;
}

void web_store_stats(web_store_t *s, web_store_stats_t *out) {
    (void)s;
    memset(out, 0, sizeof(*out));
}

long long web_store_count(web_store_t *s, int tier) {
    (void)s; (void)tier;
    return -1;
}

int web_store_bl_load(web_store_t *s, web_baseline_t *b) {
    (void)s; (void)b;
    return -1;
}

int web_store_bl_put(web_store_t *s, web_baseline_t *b,
                     const web_bl_rec_t *recs, int n) {
    (void)s; (void)b; (void)recs; (void)n;
    return -1;
}

int web_store_bl_del(web_store_t *s, const long long *ids, int n) {
    (void)s; (void)ids; (void)n;
    return -1;
}

int web_store_ep_load(web_store_t *s, long long since,
                      void (*fn)(void *ctx, const web_store_ep_t *e),
                      void *ctx) {
    (void)s; (void)since; (void)fn; (void)ctx;
    return -1;
}

int web_store_ep_put(web_store_t *s, const web_store_ep_t *e, int n) {
    (void)s; (void)e; (void)n;
    return -1;
}

int web_store_ep_del(web_store_t *s, const long long *ids, int n) {
    (void)s; (void)ids; (void)n;
    return -1;
}

int web_store_fan_load(web_store_t *s,
                       void (*fn)(void *ctx, const web_store_fan_t *f),
                       void *ctx) {
    (void)s; (void)fn; (void)ctx;
    return -1;
}

int web_store_fan_put(web_store_t *s, const web_store_fan_t *f, int n) {
    (void)s; (void)f; (void)n;
    return -1;
}

int web_store_fan_del(web_store_t *s, const char (*keys)[WEB_KEY_MAX + 1],
                      int n) {
    (void)s; (void)keys; (void)n;
    return -1;
}

int web_store_rep_load(web_store_t *s, long long since,
                       void (*fn)(void *ctx, const web_store_rep_t *r),
                       void *ctx) {
    (void)s; (void)since; (void)fn; (void)ctx;
    return -1;
}

int web_store_rep_put(web_store_t *s, const web_store_rep_t *r, int n) {
    (void)s; (void)r; (void)n;
    return -1;
}

int web_store_rep_prune(web_store_t *s, long long before) {
    (void)s; (void)before;
    return -1;
}

int web_store_any_before(web_store_t *s, int metric, const char *key,
                         long long before) {
    (void)s; (void)metric; (void)key; (void)before;
    return -1;
}

int web_store_hours_at(web_store_t *s, int metric, const char *key,
                       const long long *ts, int n, web_point_t *out) {
    (void)s; (void)metric; (void)key; (void)ts; (void)n; (void)out;
    return -1;
}

int web_store_ptr_load(web_store_t *s, int cap,
                       void (*fn)(void *ctx, const web_store_ptr_t *r),
                       void *ctx) {
    (void)s; (void)cap; (void)fn; (void)ctx;
    return -1;
}

int web_store_ptr_put(web_store_t *s, const web_store_ptr_t *r, int n,
                      int cap, long long *evicted) {
    (void)s; (void)r; (void)n; (void)cap;
    if (evicted) *evicted = 0;
    return -1;
}

int web_store_presence(web_store_t *s, int tier, int metric, const char *key,
                       long long from, long long to, int ncell, int cell_s,
                       unsigned char *bits) {
    (void)s; (void)tier; (void)metric; (void)key; (void)from; (void)to;
    (void)ncell; (void)cell_s; (void)bits;
    return -1;
}

int web_store_mix_write(web_store_t *s, const web_mix_row_t *rows, size_t n) {
    (void)s; (void)rows; (void)n;
    return -1;
}

int web_store_mix_query(web_store_t *s, int tier, long long from, long long to,
                        long long max, web_store_mix_fn fn, void *ctx,
                        int *more) {
    (void)s; (void)tier; (void)from; (void)to; (void)max; (void)fn; (void)ctx;
    *more = 0;
    return -1;
}

long long web_store_mix_count(web_store_t *s) {
    (void)s;
    return -1;
}

#else

#include <sqlite3.h>

/* SQLITE_OPEN_NOFOLLOW is the guard the side-file checks lean on (they
 * are advisory: a symlink can appear between lstat() and SQLite's own
 * open), and it arrived in 3.31.0. Same floor as sloth (src/db.c). */
#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER < 3031000
#error "slothweb needs sqlite3 >= 3.31.0 (SQLITE_OPEN_NOFOLLOW)"
#endif

/* Constant SQL per tier: a table name cannot be a bound parameter, so
 * each statement is spelled out here and nothing from a request is
 * ever part of one. */
/* A row is inserted, or, when its (series, t) is already there, merged
 * by the UPDATE. Two statements rather than one upsert so that the
 * writer knows which happened and counts only the rows it added. */
static const char *const INS_ROW[WEB_TIER_COUNT] = {
    "INSERT OR IGNORE INTO fine (series,t,sum,n,min,max)"
    " VALUES (?1,?2,?3,?4,?5,?6)",
    "INSERT OR IGNORE INTO minute (series,t,sum,n,min,max)"
    " VALUES (?1,?2,?3,?4,?5,?6)",
    "INSERT OR IGNORE INTO hour (series,t,sum,n,min,max)"
    " VALUES (?1,?2,?3,?4,?5,?6)",
};
static const char *const UPD_ROW[WEB_TIER_COUNT] = {
    "UPDATE fine SET sum=sum+?3, n=n+?4, min=min(min,?5), max=max(max,?6)"
    " WHERE series=?1 AND t=?2",
    "UPDATE minute SET sum=sum+?3, n=n+?4, min=min(min,?5), max=max(max,?6)"
    " WHERE series=?1 AND t=?2",
    "UPDATE hour SET sum=sum+?3, n=n+?4, min=min(min,?5), max=max(max,?6)"
    " WHERE series=?1 AND t=?2",
};
static const char *const Q_ROW[WEB_TIER_COUNT] = {
    "SELECT r.t,r.sum,r.n,r.min,r.max FROM fine r JOIN series s"
    " ON s.id=r.series WHERE s.metric=?1 AND s.key=?2 AND r.t>=?3"
    " AND r.t<?4 ORDER BY r.t DESC LIMIT ?5",
    "SELECT r.t,r.sum,r.n,r.min,r.max FROM minute r JOIN series s"
    " ON s.id=r.series WHERE s.metric=?1 AND s.key=?2 AND r.t>=?3"
    " AND r.t<?4 ORDER BY r.t DESC LIMIT ?5",
    "SELECT r.t,r.sum,r.n,r.min,r.max FROM hour r JOIN series s"
    " ON s.id=r.series WHERE s.metric=?1 AND s.key=?2 AND r.t>=?3"
    " AND r.t<?4 ORDER BY r.t DESC LIMIT ?5",
};
/* Retention in tiles: WEB_STORE_EXPIRE_SERIES series (consecutive ids)
 * by WEB_STORE_EXPIRE_STEPS buckets of t, one transaction each. A tier
 * is keyed (series, t) and indexed on t, so a delete in t order
 * scatters over the key's pages and one in series order over the
 * index's; a tile is a run of each, and changes about
 * series x (steps/P + 2) key pages and steps x (series/Q + 2) index
 * pages (P, Q the rows a page holds), some 2,000 pages, whatever the
 * size of the store. One delete of every expired row in one
 * transaction changed every page holding one and after a long stop
 * grew the WAL to the size of the file. EXP_NEXT is a series' oldest
 * t, a seek on the key, so a batch with nothing expired costs one seek
 * per series and the tile's start is the least of them. Read off the t
 * index instead (the oldest expired t of the batch's id range), an
 * empty batch walked every expired row of the tier: at 100,000 series
 * with the expired rows on the last 5,000, 5.9 s of 371 such walks. */
static const char *const EXP_DEL[WEB_TIER_COUNT] = {
    "DELETE FROM fine WHERE series=?1 AND t>=?2 AND t<?3",
    "DELETE FROM minute WHERE series=?1 AND t>=?2 AND t<?3",
    "DELETE FROM hour WHERE series=?1 AND t>=?2 AND t<?3",
};
static const char *const EXP_NEXT[WEB_TIER_COUNT] = {
    "SELECT t FROM fine WHERE series=?1 ORDER BY t LIMIT 1",
    "SELECT t FROM minute WHERE series=?1 ORDER BY t LIMIT 1",
    "SELECT t FROM hour WHERE series=?1 ORDER BY t LIMIT 1",
};
/* Whether a tier has any row older than ?1 at all: one seek on the t
 * index, so a tier with nothing expired (the minute and hour tiers on
 * most compactions) costs no per-series seek. */
static const char *const EXP_ANY[WEB_TIER_COUNT] = {
    "SELECT 1 FROM fine WHERE t<?1 LIMIT 1",
    "SELECT 1 FROM minute WHERE t<?1 LIMIT 1",
    "SELECT 1 FROM hour WHERE t<?1 LIMIT 1",
};
/* The ceiling drops the oldest slice of one class of rows at a time,
 * in this order: fine rows (any series; the 24 h tier is the one the
 * spec gives up first), then the channel mix's minute and hour rows (a
 * view's detail, which no baseline reads), then the minute and hour
 * rows of keyed series,
 * and only then those of the global series (the network-wide totals,
 * one series per metric, which no key churn can multiply). A class is
 * left only once it is empty. A slice is the WEB_STORE_SLICE_ROWS
 * oldest rows of its class, read off the head of the t index: small,
 * so that a ceiling met under load trims rather than wipes, and so that
 * no slice's transaction can grow the WAL by more than that many pages
 * of each b-tree. */
#define KEYED  "series IN (SELECT id FROM series WHERE key<>'')"
#define GLOBAL "series IN (SELECT id FROM series WHERE key='')"
#define SLICE(tier, cls) \
    "DELETE FROM " tier " WHERE (series,t) IN (SELECT series,t FROM " tier \
    cls " ORDER BY t LIMIT ?1)"
/* Whole buckets: every row of each (channel, t) the oldest rows fall
 * in, so a bucket is never left part drawn as a whole cell. That passes
 * the slice by at most the rest of the buckets at its last t. */
#define MIX_SLICE(tier) \
    "DELETE FROM chmix WHERE tier=" tier " AND (channel,t) IN (SELECT channel,t" \
    " FROM chmix WHERE tier=" tier " ORDER BY t LIMIT ?1)"
static const char *const CEIL_STEP[] = {
    SLICE("fine", ""),
    MIX_SLICE("1"),
    MIX_SLICE("2"),
    SLICE("minute", " WHERE " KEYED),
    SLICE("hour", " WHERE " KEYED),
    SLICE("minute", " WHERE " GLOBAL),
    SLICE("hour", " WHERE " GLOBAL),
};
#undef SLICE
#undef MIX_SLICE
#undef KEYED
#undef GLOBAL
#define CEIL_STEPS ((int)(sizeof(CEIL_STEP) / sizeof(CEIL_STEP[0])))
/* A probe of each tier's (series, t) key per series row, not a set
 * built from every row of every tier. */
static const char SWEEP_SERIES[] =
    "DELETE FROM series WHERE"
    " NOT EXISTS (SELECT 1 FROM fine WHERE fine.series=series.id) AND"
    " NOT EXISTS (SELECT 1 FROM minute WHERE minute.series=series.id) AND"
    " NOT EXISTS (SELECT 1 FROM hour WHERE hour.series=series.id)";
static const char *const COUNT_ROWS[WEB_TIER_COUNT] = {
    "SELECT COUNT(*) FROM fine",
    "SELECT COUNT(*) FROM minute",
    "SELECT COUNT(*) FROM hour",
};

/* The analysis state's statements (v3), prepared once on the writer. */
enum {
    AN_BL_INS = 0, AN_BL_UPD, AN_CELL_PUT, AN_BL_DEL, AN_CELL_DEL,
    AN_EP_PUT, AN_EP_DEL, AN_FAN_PUT, AN_FAN_DEL, AN_REP_PUT, AN_REP_PRUNE,
    AN_ANY_MIN, AN_ANY_HOUR, AN_HOUR_AT, AN_BL_FIND, AN_EP_EXPIRE,
    AN_PTR_PUT, AN_PTR_PRUNE
};
static const char *const AN_SQL[WEB_STORE_AN_STMTS] = {
    [AN_BL_INS]    = "INSERT INTO baseline (metric,key,last_active,last_fed,"
                     "first_fed) VALUES (?1,?2,?3,?4,?5)",
    [AN_BL_UPD]    = "UPDATE baseline SET last_active=?2, last_fed=?3,"
                     " first_fed=?4 WHERE id=?1",
    [AN_CELL_PUT]  = "INSERT OR REPLACE INTO baseline_cell (cell,id,mean,var,n,"
                     "wvar,wn) VALUES (?1,?2,?3,?4,?5,?6,?7)",
    [AN_BL_DEL]    = "DELETE FROM baseline WHERE id=?1",
    [AN_CELL_DEL]  = "DELETE FROM baseline_cell WHERE cell=?1 AND id=?2",
    [AN_EP_PUT]    = "INSERT OR REPLACE INTO episode (id,kind,metric,key,"
                     "state,score,peak,evidence,first_seen,last_seen,"
                     "hit_streak,clear_streak,last_bucket) VALUES"
                     " (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
    [AN_EP_DEL]    = "DELETE FROM episode WHERE id=?1",
    [AN_FAN_PUT]   = "INSERT OR REPLACE INTO fanout (key,windows,hist)"
                     " VALUES (?1,?2,?3)",
    [AN_FAN_DEL]   = "DELETE FROM fanout WHERE key=?1",
    [AN_REP_PUT]   = "INSERT OR REPLACE INTO reported (kind,key,t)"
                     " VALUES (?1,?2,?3)",
    [AN_REP_PRUNE] = "DELETE FROM reported WHERE t<?1",
    [AN_ANY_MIN]   = "SELECT 1 FROM minute r JOIN series s ON s.id=r.series"
                     " WHERE s.metric=?1 AND s.key=?2 AND r.t<?3 LIMIT 1",
    [AN_ANY_HOUR]  = "SELECT 1 FROM hour r JOIN series s ON s.id=r.series"
                     " WHERE s.metric=?1 AND s.key=?2 AND r.t<?3 LIMIT 1",
    [AN_HOUR_AT]   = "SELECT r.sum,r.n,r.min,r.max FROM hour r JOIN series s"
                     " ON s.id=r.series WHERE s.metric=?1 AND s.key=?2"
                     " AND r.t=?3",
    [AN_BL_FIND]   = "SELECT id FROM baseline WHERE metric=?1 AND key=?2",
    [AN_EP_EXPIRE] = "DELETE FROM episode WHERE last_seen<?1",
    /* first_seen is the first sight of the address's current name: a
     * new name for it starts again. */
    [AN_PTR_PUT]   = "INSERT INTO passive_ptr (ip,name,first_seen,last_seen)"
                     " VALUES (?1,?2,?3,?4) ON CONFLICT(ip) DO UPDATE SET"
                     " first_seen=CASE WHEN passive_ptr.name=excluded.name"
                     " THEN MIN(passive_ptr.first_seen,excluded.first_seen)"
                     " ELSE excluded.first_seen END,"
                     " name=excluded.name,"
                     " last_seen=MAX(passive_ptr.last_seen,excluded.last_seen)",
    [AN_PTR_PRUNE] = "DELETE FROM passive_ptr WHERE ip IN (SELECT ip FROM"
                     " passive_ptr ORDER BY last_seen DESC, ip LIMIT -1"
                     " OFFSET ?1)",
};

int web_store_available(void) { return 1; }

void (*web_store_test_between_opens)(const char *path) = NULL;
int    web_store_test_no_defensive = 0;
long long web_store_test_mix_cap = 0;
void (*web_store_test_after_commit)(const char *path) = NULL;

static void after_commit(web_store_t *s) {
    if (web_store_test_after_commit) web_store_test_after_commit(s->path);
}

static void set_err(web_store_t *s, const char *what, sqlite3 *db) {
    pthread_mutex_lock(&s->mu);
    snprintf(s->st.last_error, sizeof(s->st.last_error), "%s: %s", what,
             db ? sqlite3_errmsg(db) : "?");
    pthread_mutex_unlock(&s->mu);
}

/* ── the file, before SQLite sees it ─────────────────────────────────── */

static int check_stat(const char *path, const struct stat *st, char *err,
                      size_t errsz) {
    if (!S_ISREG(st->st_mode)) {
        snprintf(err, errsz, "%s: not a regular file", path);
        return -1;
    }
    if (st->st_uid != geteuid()) {
        snprintf(err, errsz, "%s: owned by uid %lu, not this user", path,
                 (unsigned long)st->st_uid);
        return -1;
    }
    if (st->st_mode & 077) {
        snprintf(err, errsz, "%s: mode %03o gives group or other access; "
                             "it must be 0600 (not repaired)", path,
                 (unsigned)(st->st_mode & 0777));
        return -1;
    }
    if (st->st_nlink != 1) {
        snprintf(err, errsz, "%s: has %lu links; it must have one", path,
                 (unsigned long)st->st_nlink);
        return -1;
    }
    return 0;
}

/* Create the main file 0600 by descriptor, or validate the one there. */
static int private_main(const char *path, char *err, size_t errsz) {
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
                  0600);
    if (fd < 0) {
        snprintf(err, errsz, "%s: %s%s", path, strerror(errno),
                 errno == ELOOP ? " (a symlink is refused)" : "");
        return -1;
    }
    struct stat st;
    int rc = fstat(fd, &st) == 0 ? check_stat(path, &st, err, errsz) : -1;
    if (rc != 0 && !err[0]) snprintf(err, errsz, "%s: fstat: %s", path, strerror(errno));
    close(fd);
    return rc;
}

/* SQLite's side files: absent is fine, present must pass too. */
static int private_side(const char *path, char *err, size_t errsz) {
    static const char *const side[] = { "-wal", "-shm", "-journal" };
    for (size_t i = 0; i < sizeof(side) / sizeof(side[0]); i++) {
        char p[4200];
        struct stat st;
        snprintf(p, sizeof(p), "%s%s", path, side[i]);
        if (lstat(p, &st) != 0) {
            if (errno == ENOENT) continue;
            snprintf(err, errsz, "%s: %s", p, strerror(errno));
            return -1;
        }
        if (S_ISLNK(st.st_mode)) {
            snprintf(err, errsz, "%s: a symlink is refused", p);
            return -1;
        }
        if (check_stat(p, &st, err, errsz) != 0) return -1;
    }
    return 0;
}

/* ── SQL helpers ─────────────────────────────────────────────────────── */

static int exec(sqlite3 *db, const char *sql, char *err, size_t errsz,
                const char *what) {
    char *m = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &m) == SQLITE_OK) return 0;
    snprintf(err, errsz, "%s: %s", what, m ? m : sqlite3_errmsg(db));
    sqlite3_free(m);
    return -1;
}

/* One integer from a constant query; -1 on error. */
static long long q_int(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    long long v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return v;
}

/* The meta value for name: 1 found (copied), 0 absent, -1 error. */
static int meta_get(sqlite3 *db, const char *name, char *out, size_t outsz) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT value FROM meta WHERE name=?1", -1,
                           &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const unsigned char *v = sqlite3_column_text(st, 0);
        snprintf(out, outsz, "%s", v ? (const char *)v : "");
        rc = 1;
    }
    sqlite3_finalize(st);
    return rc;
}

static int parse_version(const char *v) {
    size_t n = strlen(v);
    if (n == 0 || n > 4) return -1;
    for (size_t i = 0; i < n; i++) if (v[i] < '0' || v[i] > '9') return -1;
    return atoi(v);
}

/* What the file is, before anything is written to it: its version (0
 * and up) when it is a slothweb store, -2 when it is empty (new), or
 * -1 with err when it is refused. */
static int identify(sqlite3 *db, const char *path, char *err, size_t errsz) {
    long long objects = q_int(db, "SELECT COUNT(*) FROM sqlite_master");
    if (objects < 0) {
        snprintf(err, errsz, "%s: not a readable SQLite database (%s); "
                             "refused, left as it is", path, sqlite3_errmsg(db));
        return -1;
    }
    /* Empty means nothing anyone has written: no object, and neither
     * header field another program stamps a file with before its first
     * table. */
    long long app = q_int(db, "PRAGMA application_id");
    long long uv = q_int(db, "PRAGMA user_version");
    if (objects == 0 && app == 0 && uv == 0) return -2;
    if (app != 0 && app != WEB_STORE_APP_ID) {
        snprintf(err, errsz, "%s: application_id %lld is another program's "
                             "database; refused, left as it is. Use a "
                             "separate --store", path, app);
        return -1;
    }
    char store[64] = "", ver[64] = "";
    if (q_int(db, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                  " AND name='meta'") != 1 ||
        meta_get(db, "store", store, sizeof(store)) != 1 ||
        strcmp(store, "slothweb") != 0) {
        snprintf(err, errsz, "%s: not a slothweb store (another program's "
                             "database, sloth.db perhaps); refused, left as "
                             "it is. Use a separate --store", path);
        return -1;
    }
    int v = meta_get(db, "schema_version", ver, sizeof(ver)) == 1
          ? parse_version(ver) : -1;
    if (v < 0) {
        snprintf(err, errsz, "%s: slothweb store with no readable schema "
                             "version; refused, left as it is", path);
        return -1;
    }
    if (v > WEB_STORE_SCHEMA) {
        snprintf(err, errsz, "%s: written by a newer slothweb (schema v%d; "
                             "this build writes v%d); refused, left as it "
                             "is. Use a separate --store", path, v,
                 WEB_STORE_SCHEMA);
        return -1;
    }
    return v;
}

static int migrate(web_store_t *s, int have, char *err, size_t errsz) {
    for (int i = 0; i < STEP_N; i++) {
        if (STEPS[i].from < have) continue;
        char stamp[96];
        snprintf(stamp, sizeof(stamp), "UPDATE meta SET value='%d' WHERE "
                 "name='schema_version'", STEPS[i].from + 1);
        char e2[WEB_STORE_ERR_MAX] = "";
        if (exec(s->db, "BEGIN IMMEDIATE", err, errsz, "migration begin") != 0)
            return -1;
        if (exec(s->db, STEPS[i].sql, e2, sizeof(e2), "schema step") != 0 ||
            exec(s->db, stamp, e2, sizeof(e2), "migration stamp") != 0 ||
            exec(s->db, "COMMIT", e2, sizeof(e2), "migration commit") != 0) {
            char ignore[64];
            exec(s->db, "ROLLBACK", ignore, sizeof(ignore), "rollback");
            snprintf(err, errsz, "%s: schema v%d could not be migrated to "
                     "v%d (%s); the file is unchanged from v%d", s->path,
                     STEPS[i].from, STEPS[i].from + 1, e2, STEPS[i].from);
            return -1;
        }
        fprintf(stderr, "slothweb: store schema v%d migrated to v%d (%s; no "
                "existing value changed)\n", STEPS[i].from, STEPS[i].from + 1,
                STEPS[i].what);
    }
    return 0;
}

static void refresh_size(web_store_t *s) {
    long long pc = q_int(s->db, "PRAGMA page_count");
    long long fl = q_int(s->db, "PRAGMA freelist_count");
    long long ps = q_int(s->db, "PRAGMA page_size");
    pthread_mutex_lock(&s->mu);
    if (pc >= 0 && fl >= 0 && ps > 0) {
        s->st.bytes = (pc - fl) * ps;
        s->st.file_bytes = pc * ps;
    }
    pthread_mutex_unlock(&s->mu);
}

static void recount(web_store_t *s) {
    long long r[WEB_TIER_COUNT];
    for (int t = 0; t < WEB_TIER_COUNT; t++) r[t] = q_int(s->db, COUNT_ROWS[t]);
    long long mx = q_int(s->db, "SELECT COUNT(*) FROM chmix");
    pthread_mutex_lock(&s->mu);
    for (int t = 0; t < WEB_TIER_COUNT; t++) if (r[t] >= 0) s->st.rows[t] = r[t];
    if (mx >= 0) s->st.mix_rows = mx;
    pthread_mutex_unlock(&s->mu);
}

/* 1 when path is a WAL-mode database (header bytes 18 and 19 are 2)
 * with no -wal beside it: all it holds is in the main file. */
static int wal_clean(const char *path) {
    unsigned char h[20];
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) return 0;
    ssize_t n = pread(fd, h, sizeof(h), 0);
    close(fd);
    if (n != (ssize_t)sizeof(h) || memcmp(h, "SQLite format 3", 16) != 0 ||
        h[18] != 2 || h[19] != 2)
        return 0;
    char w[4200];
    struct stat st;
    snprintf(w, sizeof(w), "%s-wal", path);
    return lstat(w, &st) != 0 && errno == ENOENT;
}

/* path as a read-only, immutable SQLite URI, percent-encoded so that
 * no character of it reads as URI syntax. */
static void immutable_uri(const char *path, char *out, size_t outsz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t o = (size_t)snprintf(out, outsz, "file:");
    for (size_t i = 0; path[i] && o + 4 < outsz; i++) {
        unsigned char c = (unsigned char)path[i];
        /* A second leading slash would start a URI authority. */
        int keep = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                    c == '-' || c == '~' || c == '/') &&
                   !(i == 1 && c == '/');
        if (keep) {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        }
    }
    out[o] = '\0';
    snprintf(out + o, outsz - o, "?mode=ro&immutable=1");
}

/* immutable: open path read-only as an immutable URI (no lock, no
 * side file). */
static int open_db(const char *path, int flags, int immutable, sqlite3 **out,
                   char *err, size_t errsz) {
    *out = NULL;
    char uri[3 * 4096 + 64];
    const char *name = path;
    if (immutable) {
        immutable_uri(path, uri, sizeof(uri));
        name = uri;
        flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI;
    }
    if (sqlite3_open_v2(name, out, flags | SQLITE_OPEN_NOFOLLOW, NULL)
            != SQLITE_OK) {
        snprintf(err, errsz, "%s: %s", path, *out ? sqlite3_errmsg(*out) : "?");
        sqlite3_close(*out);
        *out = NULL;
        return -1;
    }
    /* DEFENSIVE shuts writable_schema and shadow-table writes, which a
     * store never needs. Read back, so a library that ignores it fails
     * the open instead of passing it. */
    int on = -1;
    int rc = sqlite3_db_config(*out, SQLITE_DBCONFIG_DEFENSIVE, 1, &on);
    if (web_store_test_no_defensive) on = 0;
    if (rc != SQLITE_OK || on != 1) {
        snprintf(err, errsz, "%s: SQLITE_DBCONFIG_DEFENSIVE refused", path);
        sqlite3_close(*out);
        *out = NULL;
        return -1;
    }
    sqlite3_busy_timeout(*out, 200);
    return 0;
}

int web_store_open(web_store_t *s, const char *path, char *err, size_t errsz) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->mu, NULL);
    pthread_mutex_init(&s->rmu, NULL);
    s->mu_init = 1;
    err[0] = '\0';
    if (!path || !path[0] || strlen(path) >= sizeof(s->path) - 16) {
        snprintf(err, errsz, "--store: empty or too long a path");
        return -1;
    }
    snprintf(s->path, sizeof(s->path), "%s", path);
    /* The headers were checked at compile time; this is the library the
     * dynamic linker actually loaded. */
    if (sqlite3_libversion_number() < 3031000) {
        snprintf(err, errsz, "%s: libsqlite3 %s is older than 3.31.0", path,
                 sqlite3_libversion());
        return -1;
    }
    if (private_main(path, err, errsz) != 0) return -1;
    if (private_side(path, err, errsz) != 0) return -1;
    /* Identify on a read-only connection. The last read-write
     * connection to close on a WAL database checkpoints the WAL into
     * the main file and deletes it, so a refusal made on one would
     * rewrite the file it refused: a sloth.db that sloth left with an
     * unflushed WAL would be checkpointed by slothweb. A read-only
     * connection never checkpoints.
     *
     * It does make an absent -wal (empty) and -shm (32 KB) on a WAL
     * database, which a refusal would leave behind beside a cleanly
     * closed sloth.db. With no -wal there are no frames to read, so
     * that file is identified as immutable, which opens no side file.
     * Unlinking them afterwards instead would race sloth opening its
     * own file and could take a -shm it had just attached to. A sloth
     * starting between the lstat() and the read can only make the file
     * look emptier than it is (its first tables still in a new WAL),
     * and the writer's own identify below sees the WAL and refuses. A
     * -wal left with no -shm (a crash that lost only the -shm) still
     * gets a -shm made: there are frames to read, so not immutable. */
    sqlite3 *ro = NULL;
    if (open_db(path, SQLITE_OPEN_READONLY, wal_clean(path), &ro, err, errsz)
            != 0)
        return -1;
    int v = identify(ro, path, err, errsz);
    sqlite3_close(ro);
    if (v == -1) return -1;
    if (web_store_test_between_opens) web_store_test_between_opens(path);
    if (open_db(path, SQLITE_OPEN_READWRITE, 0, &s->db, err, errsz) != 0)
        return -1;
    /* Once more on the writer: what was identified is what it opened. */
    if (identify(s->db, path, err, errsz) != v) {
        if (!err[0])
            snprintf(err, errsz, "%s: changed while it was being opened; "
                                 "refused", path);
        return -1;
    }
    if (v == -2) {
        /* auto_vacuum only takes on a file with no table yet. */
        if (exec(s->db, "PRAGMA auto_vacuum=INCREMENTAL", err, errsz,
                 "auto_vacuum") != 0)
            return -1;
    }
    /* WAL so the HTTP thread's reads never wait on the writer.
     * synchronous=NORMAL syncs at checkpoint, not per commit (the cost of
     * a power cut is the last few seconds of rollups). The WAL is
     * checkpointed past 1 MB and cut back to 1 MB at the next write, so
     * between transactions it is about 1 MB; within one it grows by the
     * pages that transaction changes, which is why every write, slice,
     * tile and vacuum step is kept small (web_store.h). --web-max-mb
     * bounds the main file only. */
    if (exec(s->db, "PRAGMA journal_mode=WAL", err, errsz, "WAL") != 0 ||
        exec(s->db, "PRAGMA synchronous=NORMAL", err, errsz, "synchronous") != 0 ||
        exec(s->db, "PRAGMA wal_autocheckpoint=256", err, errsz, "checkpoint") != 0 ||
        exec(s->db, "PRAGMA journal_size_limit=1048576", err, errsz,
             "journal_size_limit") != 0)
        return -1;
    if (v == -2) {
        char stamp[512];
        snprintf(stamp, sizeof(stamp),
                 "BEGIN IMMEDIATE; PRAGMA application_id=%d; %s INSERT INTO"
                 " meta (name,value) VALUES ('store','slothweb'),"
                 "('schema_version','0'); COMMIT;", WEB_STORE_APP_ID, META_SQL);
        if (exec(s->db, stamp, err, errsz, "new store") != 0) {
            char ignore[64];
            exec(s->db, "ROLLBACK", ignore, sizeof(ignore), "rollback");
            return -1;
        }
        v = 0;
    }
    if (migrate(s, v, err, errsz) != 0) return -1;
    s->st.schema = WEB_STORE_SCHEMA;

    if (sqlite3_prepare_v2(s->db,
            "INSERT OR IGNORE INTO series (metric,key) VALUES (?1,?2)", -1,
            &s->ins_series, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(s->db,
            "SELECT id FROM series WHERE metric=?1 AND key=?2", -1,
            &s->get_series, NULL) != SQLITE_OK) {
        snprintf(err, errsz, "%s: prepare: %s", path, sqlite3_errmsg(s->db));
        return -1;
    }
    for (int t = 0; t < WEB_TIER_COUNT; t++)
        if (sqlite3_prepare_v2(s->db, INS_ROW[t], -1, &s->ins_row[t], NULL)
                != SQLITE_OK ||
            sqlite3_prepare_v2(s->db, UPD_ROW[t], -1, &s->upd_row[t], NULL)
                != SQLITE_OK) {
            snprintf(err, errsz, "%s: prepare: %s", path, sqlite3_errmsg(s->db));
            return -1;
        }
    for (int i = 0; i < WEB_STORE_AN_STMTS; i++)
        if (sqlite3_prepare_v2(s->db, AN_SQL[i], -1, &s->an[i], NULL)
                != SQLITE_OK) {
            snprintf(err, errsz, "%s: prepare: %s", path, sqlite3_errmsg(s->db));
            return -1;
        }
    if (private_side(path, err, errsz) != 0) return -1;
    if (open_db(path, SQLITE_OPEN_READONLY, 0, &s->rd, err, errsz) != 0)
        return -1;
    for (int t = 0; t < WEB_TIER_COUNT; t++)
        if (sqlite3_prepare_v2(s->rd, Q_ROW[t], -1, &s->q_row[t], NULL)
                != SQLITE_OK) {
            snprintf(err, errsz, "%s: prepare: %s", path, sqlite3_errmsg(s->rd));
            return -1;
        }
    recount(s);
    refresh_size(s);
    s->st.analysis_bytes = -1;
    s->st.open = 1;
    return 0;
}

void web_store_close(web_store_t *s) {
    if (!s->mu_init) return;
    sqlite3_finalize(s->ins_series);
    sqlite3_finalize(s->get_series);
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        sqlite3_finalize(s->ins_row[t]);
        sqlite3_finalize(s->upd_row[t]);
        sqlite3_finalize(s->q_row[t]);
        s->ins_row[t] = s->upd_row[t] = s->q_row[t] = NULL;
    }
    s->ins_series = s->get_series = NULL;
    for (int i = 0; i < WEB_STORE_AN_STMTS; i++) {
        sqlite3_finalize(s->an[i]);
        s->an[i] = NULL;
    }
    if (s->rd) sqlite3_close(s->rd);
    if (s->db) sqlite3_close(s->db);
    s->rd = s->db = NULL;
    s->st.open = 0;
    pthread_mutex_destroy(&s->mu);
    pthread_mutex_destroy(&s->rmu);
    s->mu_init = 0;
}

static long long series_id(web_store_t *s, int metric, const char *key) {
    const char *name = web_metric_defs[metric].name;
    sqlite3_reset(s->ins_series);
    sqlite3_bind_text(s->ins_series, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(s->ins_series, 2, key, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(s->ins_series) != SQLITE_DONE) return -1;
    sqlite3_reset(s->get_series);
    sqlite3_bind_text(s->get_series, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(s->get_series, 2, key, -1, SQLITE_TRANSIENT);
    long long id = -1;
    if (sqlite3_step(s->get_series) == SQLITE_ROW)
        id = sqlite3_column_int64(s->get_series, 0);
    sqlite3_reset(s->get_series);
    return id;
}

int web_store_write(web_store_t *s, const web_qrow_t *rows, size_t n) {
    if (!s->db || !n) return s->db ? 0 : -1;
    char err[WEB_STORE_ERR_MAX];
    long long added[WEB_TIER_COUNT] = { 0, 0, 0 };
    if (exec(s->db, "BEGIN IMMEDIATE", err, sizeof(err), "begin") != 0) {
        pthread_mutex_lock(&s->mu);
        s->st.write_errors++;
        snprintf(s->st.last_error, sizeof(s->st.last_error), "%s", err);
        pthread_mutex_unlock(&s->mu);
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        const web_qrow_t *r = &rows[i];
        if (r->tier < 0 || r->tier >= WEB_TIER_COUNT ||
            r->metric < 0 || r->metric >= WM_COUNT)
            continue;
        long long id = series_id(s, r->metric, r->key);
        if (id < 0) goto fail;
        for (int u = 0; u < 2; u++) {
            sqlite3_stmt *st = u ? s->upd_row[r->tier] : s->ins_row[r->tier];
            sqlite3_reset(st);
            sqlite3_bind_int64(st, 1, id);
            sqlite3_bind_int64(st, 2, r->t);
            sqlite3_bind_double(st, 3, r->sum);
            sqlite3_bind_int64(st, 4, (sqlite3_int64)r->n);
            sqlite3_bind_double(st, 5, r->min);
            sqlite3_bind_double(st, 6, r->max);
            if (sqlite3_step(st) != SQLITE_DONE) goto fail;
            sqlite3_reset(st);
            if (!u && sqlite3_changes(s->db) == 1) {
                added[r->tier]++;
                break;
            }
        }
    }
    if (exec(s->db, "COMMIT", err, sizeof(err), "commit") != 0) goto fail_msg;
    pthread_mutex_lock(&s->mu);
    s->st.batches++;
    s->st.rows_written += (unsigned long)n;
    for (int t = 0; t < WEB_TIER_COUNT; t++) s->st.rows[t] += added[t];
    pthread_mutex_unlock(&s->mu);
    refresh_size(s);
    return 0;
fail:
    snprintf(err, sizeof(err), "write: %s", sqlite3_errmsg(s->db));
fail_msg:
    {
        char ignore[64];
        for (int t = 0; t < WEB_TIER_COUNT; t++) {
            sqlite3_reset(s->ins_row[t]);
            sqlite3_reset(s->upd_row[t]);
        }
        exec(s->db, "ROLLBACK", ignore, sizeof(ignore), "rollback");
    }
    pthread_mutex_lock(&s->mu);
    s->st.write_errors++;
    snprintf(s->st.last_error, sizeof(s->st.last_error), "%s", err);
    pthread_mutex_unlock(&s->mu);
    return -1;
}

static long long run_del(sqlite3 *db, const char *sql, int bind, long long v) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (bind) sqlite3_bind_int64(st, 1, v);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? sqlite3_changes(db) : -1;
}

static long long used_bytes(sqlite3 *db) {
    long long pc = q_int(db, "PRAGMA page_count");
    long long fl = q_int(db, "PRAGMA freelist_count");
    long long ps = q_int(db, "PRAGMA page_size");
    if (pc < 0 || fl < 0 || ps <= 0) return -1;
    return (pc - fl) * ps;
}

/* The pages of the named tables and their indexes, from dbstat (which
 * reads only the b-trees named); -1 when the library has no dbstat. */
static long long pages_of(web_store_t *s, const char *sql) {
    sqlite3_stmt *st = NULL;
    long long b = -1;
    if (sqlite3_prepare_v2(s->db, sql, -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        b = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return b;
}

#define AN_PAGES(tables) \
    "SELECT COALESCE(SUM(pgsize),0) FROM dbstat WHERE name IN" \
    " (SELECT name FROM sqlite_schema WHERE tbl_name IN (" tables "))"

/* The analysis state's pages: the baseline tables' as last measured
 * (kept until the next baseline write), the episode, fanout and
 * reported tables' measured now (web_store.h). */
static long long analysis_bytes(web_store_t *s) {
    if (!s->an_fresh) {
        s->an_bl = pages_of(s, AN_PAGES("'baseline','baseline_cell'"));
        s->an_fresh = 1;
    }
    long long small = pages_of(s, AN_PAGES("'episode','fanout','reported',"
                                           "'passive_ptr'"));
    long long b = s->an_bl < 0 || small < 0 ? -1 : s->an_bl + small;
    pthread_mutex_lock(&s->mu);
    s->st.analysis_bytes = b;
    pthread_mutex_unlock(&s->mu);
    return b;
}

#undef AN_PAGES

void web_store_set_history_allowance(web_store_t *s, long long bytes) {
    s->hist_allow = bytes > 0 ? bytes : 0;
}

/* The ceiling's loop, inside no transaction: each slice is its own,
 * and after each commit the WAL is checkpointed (wal_autocheckpoint)
 * and, at the next write, cut back to journal_size_limit, so what the
 * WAL holds at a time is one slice. Rows dropped, or -1. Bounded, so a
 * file that will not shrink cannot spin: every pass either deletes a
 * slice or moves on a class. The series rows of what went are swept
 * once, after the loop: under key churn they are as much of the file
 * as the buckets, but a sweep per slice cost more than the slice. The
 * loop does not count what the sweep will free, so it may take one
 * slice more than it needed. The target is max_bytes, raised to the
 * analysis state plus the history allowance when that is more
 * (web_store.h); *raised says it was. Dropping rows does not change the
 * analysis state, so it is measured once a pass. */
static long long ceiling_loop(web_store_t *s, long long max_bytes, int *raised) {
    long long dropped = 0, target = max_bytes;
    int step = 0, measured = 0;
    *raised = 0;
    for (int guard = 0; max_bytes > 0 && step < CEIL_STEPS && guard < 1000000;
         guard++) {
        long long used = used_bytes(s->db);
        if (used < 0) return -1;
        if (used <= target) break;
        if (!measured) {
            measured = 1;
            long long an = analysis_bytes(s);
            if (an >= 0 && an + s->hist_allow > max_bytes) {
                target = an + s->hist_allow;
                *raised = 1;
                if (used <= target) break;
            }
        }
        long long d = run_del(s->db, CEIL_STEP[step], 1, WEB_STORE_SLICE_ROWS);
        if (d < 0) return -1;
        after_commit(s);
        if (d == 0) { step++; continue; }
        dropped += d;
    }
    if (dropped > 0) {
        if (run_del(s->db, SWEEP_SERIES, 0, 0) < 0) return -1;
        after_commit(s);
    }
    return dropped;
}

/* Free pages back to the file system, WEB_STORE_VACUUM_PAGES to a
 * transaction: one incremental_vacuum of a freelist a long stop left
 * moves as many pages as it frees, all in one WAL. */
static int vacuum_slices(web_store_t *s) {
    char q[64];
    snprintf(q, sizeof(q), "PRAGMA incremental_vacuum(%d)", WEB_STORE_VACUUM_PAGES);
    long long prev = -1;
    for (int guard = 0; guard < 1000000; guard++) {
        long long fl = q_int(s->db, "PRAGMA freelist_count");
        if (fl < 0) return -1;
        if (fl == 0 || fl == prev) break;
        prev = fl;
        if (sqlite3_exec(s->db, q, NULL, NULL, NULL) != SQLITE_OK) return -1;
        after_commit(s);
    }
    return 0;
}

static void note_fail(web_store_t *s, const char *what) {
    pthread_mutex_lock(&s->mu);
    s->st.write_errors++;
    snprintf(s->st.last_error, sizeof(s->st.last_error), "%s: %s", what,
             sqlite3_errmsg(s->db));
    pthread_mutex_unlock(&s->mu);
}

long long web_store_ceiling(web_store_t *s, long long max_bytes) {
    if (!s->db) return -1;
    if (max_bytes <= 0) return 0;
    /* The cheap test first: three PRAGMAs, no table read. */
    long long used = used_bytes(s->db);
    if (used >= 0 && used <= max_bytes) return 0;
    int raised;
    long long d = ceiling_loop(s, max_bytes, &raised);
    if (d < 0) { note_fail(s, "ceiling"); return -1; }
    if (d > 0) {
        if (vacuum_slices(s) != 0) { note_fail(s, "vacuum"); return -1; }
        recount(s);
    }
    refresh_size(s);
    pthread_mutex_lock(&s->mu);
    s->st.dropped_ceiling += (unsigned long long)d;
    if (d > 0) s->st.ceiling_runs++;
    if (raised) s->st.ceiling_raised++;
    pthread_mutex_unlock(&s->mu);
    return d;
}

/* The prepared statements of one tier's expiry. */
typedef struct {
    sqlite3_stmt *del, *next, *any;
} web_exp_t;

/* The oldest t of series id if it is older than cutoff, else LLONG_MAX
 * (nothing expired, or no row). */
static long long exp_next(sqlite3_stmt *st, long long id, long long cutoff,
                          int *bad) {
    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, id);
    long long t = LLONG_MAX;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) t = sqlite3_column_int64(st, 0);
    else if (rc != SQLITE_DONE) *bad = 1;
    sqlite3_reset(st);
    return t < cutoff ? t : LLONG_MAX;
}

/* Whether a tier has a row older than cutoff. */
static int exp_any(sqlite3_stmt *st, long long cutoff, int *bad) {
    sqlite3_reset(st);
    sqlite3_bind_int64(st, 1, cutoff);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_ROW && rc != SQLITE_DONE) *bad = 1;
    sqlite3_reset(st);
    return rc == SQLITE_ROW;
}

/* Every row of every tier older than its cutoff, tile by tile (see
 * EXP_DEL). nx[i] is batch[i]'s oldest expired t; a tile starts at the
 * least of them, deletes only in the series with a row in it, and seeks
 * again only those. Rows dropped, or -1. */
static long long expire(web_store_t *s, const long long cutoff[WEB_TIER_COUNT]) {
    web_exp_t ex[WEB_TIER_COUNT];
    sqlite3_stmt *ids = NULL;
    memset(ex, 0, sizeof(ex));
    long long total = 0, last = 0;
    int bad = 0, nlive = 0, live[WEB_TIER_COUNT] = { 0, 0, 0 };
    long long batch[WEB_STORE_EXPIRE_SERIES], nx[WEB_STORE_EXPIRE_SERIES];
    if (sqlite3_prepare_v2(s->db, "SELECT id FROM series WHERE id>?1 ORDER BY id"
                           " LIMIT ?2", -1, &ids, NULL) != SQLITE_OK)
        bad = 1;
    for (int t = 0; t < WEB_TIER_COUNT && !bad; t++)
        if (sqlite3_prepare_v2(s->db, EXP_DEL[t], -1, &ex[t].del, NULL) != SQLITE_OK ||
            sqlite3_prepare_v2(s->db, EXP_NEXT[t], -1, &ex[t].next, NULL)
                != SQLITE_OK ||
            sqlite3_prepare_v2(s->db, EXP_ANY[t], -1, &ex[t].any, NULL)
                != SQLITE_OK)
            bad = 1;
    for (int t = 0; t < WEB_TIER_COUNT && !bad; t++) {
        live[t] = exp_any(ex[t].any, cutoff[t], &bad);
        nlive += live[t];
    }
    while (!bad && nlive) {
        int n = 0;
        sqlite3_reset(ids);
        sqlite3_bind_int64(ids, 1, last);
        sqlite3_bind_int64(ids, 2, WEB_STORE_EXPIRE_SERIES);
        while (n < WEB_STORE_EXPIRE_SERIES && sqlite3_step(ids) == SQLITE_ROW)
            batch[n++] = sqlite3_column_int64(ids, 0);
        sqlite3_reset(ids);
        if (n == 0) break;
        last = batch[n - 1];
        for (int t = 0; t < WEB_TIER_COUNT && !bad; t++) {
            if (!live[t]) continue;
            const long long span = (long long)WEB_STORE_EXPIRE_STEPS * web_tier_step(t);
            long long lo = LLONG_MAX;
            for (int i = 0; i < n && !bad; i++) {
                nx[i] = exp_next(ex[t].next, batch[i], cutoff[t], &bad);
                if (nx[i] < lo) lo = nx[i];
            }
            while (!bad && lo != LLONG_MAX) {
                long long hi = lo + span < cutoff[t] ? lo + span : cutoff[t];
                if (sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                        != SQLITE_OK) { bad = 1; break; }
                for (int i = 0; i < n && !bad; i++) {
                    if (nx[i] >= hi) continue;
                    sqlite3_reset(ex[t].del);
                    sqlite3_bind_int64(ex[t].del, 1, batch[i]);
                    sqlite3_bind_int64(ex[t].del, 2, lo);
                    sqlite3_bind_int64(ex[t].del, 3, hi);
                    if (sqlite3_step(ex[t].del) != SQLITE_DONE) bad = 1;
                    else total += sqlite3_changes(s->db);
                    sqlite3_reset(ex[t].del);
                }
                if (bad || sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL)
                               != SQLITE_OK) {
                    bad = 1;
                    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
                    break;
                }
                after_commit(s);
                long long next = LLONG_MAX;
                for (int i = 0; i < n && !bad; i++) {
                    if (nx[i] < hi)
                        nx[i] = exp_next(ex[t].next, batch[i], cutoff[t], &bad);
                    if (nx[i] < next) next = nx[i];
                }
                lo = next;
            }
        }
    }
    sqlite3_finalize(ids);
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        sqlite3_finalize(ex[t].del);
        sqlite3_finalize(ex[t].next);
        sqlite3_finalize(ex[t].any);
    }
    return bad ? -1 : total;
}

/* Delete the buckets of tier older than before that the oldest limit
 * (at most WEB_STORE_SLICE_ROWS) rows fall in, whole, in one
 * transaction: a bucket is up to WEB_CHMIX_TOP + 1 rows sharing one t,
 * and one left in part would be drawn as a whole cell with its shares
 * wrong. So it deletes at least limit rows when there are that many,
 * and passes it by at most the rest of the buckets at its last t.
 * Rows, or -1. */
static long long mix_slice(web_store_t *s, int tier, long long before,
                           long long limit) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db,
            "DELETE FROM chmix WHERE tier=?1 AND (channel,t) IN (SELECT "
            "channel,t FROM chmix WHERE tier=?1 AND t<?2 ORDER BY t LIMIT ?3)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, tier);
    sqlite3_bind_int64(st, 2, before);
    sqlite3_bind_int64(st, 3, limit < WEB_STORE_SLICE_ROWS ? limit
                                                           : WEB_STORE_SLICE_ROWS);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc != SQLITE_DONE) return -1;
    long long d = sqlite3_changes(s->db);
    after_commit(s);
    return d;
}

/* The mix's retention: minute rows to minute_cut, hour rows to
 * hour_cut, a slice at a time. Rows, or -1. */
static long long mix_expire(web_store_t *s, long long minute_cut,
                            long long hour_cut) {
    long long total = 0;
    const long long cut[2] = { minute_cut, hour_cut };
    for (int k = 0; k < 2; k++)
        for (int guard = 0; guard < 100000; guard++) {
            long long d = mix_slice(s, WEB_TIER_MINUTE + k, cut[k],
                                    WEB_STORE_SLICE_ROWS);
            if (d < 0) return -1;
            total += d;
            if (d < WEB_STORE_SLICE_ROWS) break;
        }
    pthread_mutex_lock(&s->mu);
    s->st.mix_rows = s->st.mix_rows > total ? s->st.mix_rows - total : 0;
    pthread_mutex_unlock(&s->mu);
    return total;
}

int web_store_compact(web_store_t *s, long long now_s, int retain_days,
                      long long max_bytes) {
    if (!s->db) return -1;
    if (retain_days < 1) retain_days = 1;
    if (retain_days > WEB_RETAIN_DAYS_MAX) retain_days = WEB_RETAIN_DAYS_MAX;
    const long long cutoff[WEB_TIER_COUNT] = {
        now_s - WEB_FINE_KEEP_S, now_s - (long long)retain_days * 86400,
        now_s - WEB_HOUR_KEEP_S
    };
    char err[WEB_STORE_ERR_MAX];
    long long expired = expire(s, cutoff);
    if (expired < 0) goto fail;
    long long mx_exp = mix_expire(s, now_s - WEB_STORE_MIX_MINUTE_KEEP_S,
                                  cutoff[WEB_TIER_HOUR]);
    if (mx_exp < 0) goto fail;
    int raised;
    long long ceiling = ceiling_loop(s, max_bytes, &raised);
    if (ceiling < 0) goto fail;
    if (run_del(s->db, SWEEP_SERIES, 0, 0) < 0)
        goto fail;
    after_commit(s);
    if (vacuum_slices(s) != 0) goto fail;
    /* TRUNCATE can be refused while a reader holds the WAL; that is
     * harmless, the next compaction tries again. */
    sqlite3_exec(s->db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);
    recount(s);
    refresh_size(s);
    pthread_mutex_lock(&s->mu);
    s->st.compactions++;
    s->st.dropped_expired += (unsigned long long)expired;
    s->st.mix_dropped_expired += (unsigned long long)mx_exp;
    s->st.dropped_ceiling += (unsigned long long)ceiling;
    if (ceiling > 0) s->st.ceiling_runs++;
    if (raised) s->st.ceiling_raised++;
    s->st.last_compact = now_s;
    pthread_mutex_unlock(&s->mu);
    return 0;
fail:
    snprintf(err, sizeof(err), "compact: %s", sqlite3_errmsg(s->db));
    pthread_mutex_lock(&s->mu);
    s->st.write_errors++;
    snprintf(s->st.last_error, sizeof(s->st.last_error), "%s", err);
    pthread_mutex_unlock(&s->mu);
    return -1;
}

int web_store_query(web_store_t *s, int tier, int metric, const char *key,
                    long long from, long long to, web_point_t *out, int max,
                    int *more) {
    *more = 0;
    if (!s->rd || tier < 0 || tier >= WEB_TIER_COUNT || metric < 0 ||
        metric >= WM_COUNT || max <= 0)
        return -1;
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *st = s->q_row[tier];
    sqlite3_reset(st);
    sqlite3_bind_text(st, 1, web_metric_defs[metric].name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, from);
    sqlite3_bind_int64(st, 4, to);
    sqlite3_bind_int64(st, 5, (sqlite3_int64)max + 1);
    int n = 0, rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        if (n == max) { *more = 1; break; }
        web_point_t *p = &out[n++];
        p->t = sqlite3_column_int64(st, 0);
        p->sum = sqlite3_column_double(st, 1);
        long long cnt = sqlite3_column_int64(st, 2);
        p->n = cnt > 0 ? (unsigned long)cnt : 0;
        p->min = sqlite3_column_double(st, 3);
        p->max = sqlite3_column_double(st, 4);
    }
    int bad = rc != SQLITE_ROW && rc != SQLITE_DONE;
    sqlite3_reset(st);
    pthread_mutex_unlock(&s->rmu);
    if (bad) {
        set_err(s, "query", s->rd);
        return -1;
    }
    return n;
}

int web_store_keys(web_store_t *s, int tier, int metric, long long from,
                   long long to, char (*out)[WEB_KEY_MAX + 1], int max) {
    static const char *const TBL[WEB_TIER_COUNT] = { "fine", "minute", "hour" };
    if (!s->rd || tier < 0 || tier >= WEB_TIER_COUNT || metric < 0 ||
        metric >= WM_COUNT || max <= 0)
        return -1;
    char sql[320];
    /* The tier's table name is one of three constants; every value is
     * bound. One range read of the t index, grouped by series. */
    snprintf(sql, sizeof(sql), "SELECT x.key, max(r.t) m FROM %s r JOIN series x"
             " ON x.id = r.series WHERE x.metric = ?1 AND r.t >= ?2 AND"
             " r.t < ?3 GROUP BY x.id ORDER BY m DESC, x.key LIMIT ?4",
             TBL[tier]);
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->rd, sql, -1, &st, NULL);
    int n = 0;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(st, 1, web_metric_defs[metric].name, -1, SQLITE_STATIC);
        sqlite3_bind_int64(st, 2, from);
        sqlite3_bind_int64(st, 3, to);
        sqlite3_bind_int(st, 4, max);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && n < max) {
            const unsigned char *k = sqlite3_column_text(st, 0);
            size_t kl = k ? strlen((const char *)k) : 0;
            /* Written by this store from a canonical key; a longer one
             * is not ours and is skipped rather than cut. */
            if (!k || kl == 0 || kl > WEB_KEY_MAX) continue;
            memcpy(out[n], k, kl + 1);
            n++;
        }
    }
    int bad = rc != SQLITE_DONE && rc != SQLITE_ROW;
    sqlite3_finalize(st);
    pthread_mutex_unlock(&s->rmu);
    if (bad) {
        set_err(s, "keys", s->rd);
        return -1;
    }
    return n;
}

/* ── the channel mix (v5) ────────────────────────────────────────────── */

int web_store_mix_write(web_store_t *s, const web_mix_row_t *rows, size_t n) {
    if (!s->db || !n) return s->db ? 0 : -1;
    static const char INS[] =
        "INSERT OR IGNORE INTO chmix (tier,channel,t,tx,kind,frames)"
        " VALUES (?1,?2,?3,?4,?5,?6)";
    static const char UPD[] =
        "UPDATE chmix SET frames=MIN(frames+?6,4294967295)"
        " WHERE tier=?1 AND channel=?2 AND t=?3 AND tx=?4 AND kind=?5";
    char err[WEB_STORE_ERR_MAX];
    sqlite3_stmt *st[2] = { NULL, NULL };
    long long added = 0;
    if (sqlite3_prepare_v2(s->db, INS, -1, &st[0], NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(s->db, UPD, -1, &st[1], NULL) != SQLITE_OK) {
        snprintf(err, sizeof(err), "mix: %s", sqlite3_errmsg(s->db));
        goto fail_msg;
    }
    if (exec(s->db, "BEGIN IMMEDIATE", err, sizeof(err), "mix begin") != 0)
        goto fail_msg;
    for (size_t i = 0; i < n; i++) {
        const web_mix_row_t *r = &rows[i];
        if (r->tier != WEB_TIER_MINUTE && r->tier != WEB_TIER_HOUR) continue;
        int nt = r->n < 0 ? 0 : r->n > WEB_CHMIX_TOP ? WEB_CHMIX_TOP : r->n;
        for (int k = 0; k <= nt; k++) {
            char tx[18] = "";
            int kind = WEB_TX_OTHER;
            long long f;
            if (k < nt) {
                web_mix_mac_text(r->tx[k].mac, tx);
                kind = r->tx[k].kind;
                f = r->tx[k].frames;
            } else {
                f = r->other;
            }
            if (f <= 0) continue;
            for (int u = 0; u < 2; u++) {
                sqlite3_reset(st[u]);
                sqlite3_bind_int(st[u], 1, r->tier);
                sqlite3_bind_text(st[u], 2, r->chan, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(st[u], 3, r->t);
                sqlite3_bind_text(st[u], 4, tx, -1, SQLITE_TRANSIENT);
                sqlite3_bind_int(st[u], 5, kind);
                sqlite3_bind_int64(st[u], 6, f);
                if (sqlite3_step(st[u]) != SQLITE_DONE) goto fail;
                if (!u && sqlite3_changes(s->db) == 1) { added++; break; }
            }
        }
    }
    sqlite3_reset(st[0]);
    sqlite3_reset(st[1]);
    if (exec(s->db, "COMMIT", err, sizeof(err), "mix commit") != 0) goto fail_rb;
    sqlite3_finalize(st[0]);
    sqlite3_finalize(st[1]);
    /* The row cap: the oldest minute rows first, then the oldest hour
     * rows, a slice at a time. */
    long long have, cut = 0;
    long long cap = web_store_test_mix_cap > 0 ? web_store_test_mix_cap
                                               : WEB_STORE_MIX_ROWS;
    pthread_mutex_lock(&s->mu);
    s->st.mix_rows += added;
    have = s->st.mix_rows;
    pthread_mutex_unlock(&s->mu);
    for (int tier = WEB_TIER_MINUTE; tier <= WEB_TIER_HOUR; tier++)
        for (int guard = 0; have > cap && guard < 100000; guard++) {
            long long d = mix_slice(s, tier, (long long)1 << 62, have - cap);
            if (d < 0) {
                snprintf(err, sizeof(err), "mix cap: %s", sqlite3_errmsg(s->db));
                goto fail_count;
            }
            if (d == 0) break;
            have -= d;
            cut += d;
        }
    pthread_mutex_lock(&s->mu);
    s->st.mix_rows = have;
    s->st.mix_dropped_cap += (unsigned long long)cut;
    pthread_mutex_unlock(&s->mu);
    refresh_size(s);
    return 0;
fail:
    snprintf(err, sizeof(err), "mix write: %s", sqlite3_errmsg(s->db));
fail_rb:
    {
        char ignore[64];
        sqlite3_reset(st[0]);
        sqlite3_reset(st[1]);
        exec(s->db, "ROLLBACK", ignore, sizeof(ignore), "rollback");
    }
fail_msg:
    sqlite3_finalize(st[0]);
    sqlite3_finalize(st[1]);
fail_count:
    pthread_mutex_lock(&s->mu);
    s->st.write_errors++;
    snprintf(s->st.last_error, sizeof(s->st.last_error), "%s", err);
    pthread_mutex_unlock(&s->mu);
    return -1;
}

int web_store_mix_query(web_store_t *s, int tier, long long from, long long to,
                        long long max, web_store_mix_fn fn, void *ctx,
                        int *more) {
    *more = 0;
    if (!s->rd || (tier != WEB_TIER_MINUTE && tier != WEB_TIER_HOUR) || max <= 0)
        return -1;
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->rd,
        "SELECT channel,t,tx,kind,frames FROM chmix WHERE tier=?1 AND t>=?2"
        " AND t<?3 ORDER BY t LIMIT ?4", -1, &st, NULL);
    long long n = 0;
    if (rc == SQLITE_OK) {
        sqlite3_bind_int(st, 1, tier);
        sqlite3_bind_int64(st, 2, from);
        sqlite3_bind_int64(st, 3, to);
        sqlite3_bind_int64(st, 4, max + 1);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            if (n >= max) { *more = 1; rc = SQLITE_DONE; break; }
            const char *ch = (const char *)sqlite3_column_text(st, 0);
            const char *tx = (const char *)sqlite3_column_text(st, 2);
            n++;
            if (fn(ctx, ch ? ch : "", sqlite3_column_int64(st, 1), tx ? tx : "",
                   sqlite3_column_int(st, 3), sqlite3_column_int64(st, 4))) {
                rc = SQLITE_DONE;
                break;
            }
        }
    }
    int bad = rc != SQLITE_DONE;
    sqlite3_finalize(st);
    pthread_mutex_unlock(&s->rmu);
    if (bad) {
        set_err(s, "mix", s->rd);
        return -1;
    }
    return (int)n;
}

long long web_store_mix_count(web_store_t *s) {
    if (!s->db) return -1;
    return q_int(s->db, "SELECT COUNT(*) FROM chmix");
}

void web_store_stats(web_store_t *s, web_store_stats_t *out) {
    if (!s->mu_init) { memset(out, 0, sizeof(*out)); return; }
    pthread_mutex_lock(&s->mu);
    *out = s->st;
    pthread_mutex_unlock(&s->mu);
}

long long web_store_count(web_store_t *s, int tier) {
    if (!s->db || tier < 0 || tier >= WEB_TIER_COUNT) return -1;
    return q_int(s->db, COUNT_ROWS[tier]);
}


/* ── the analysis state (v3) ─────────────────────────────────────────── */

static void an_reset(web_store_t *s) {
    for (int i = 0; i < WEB_STORE_AN_STMTS; i++)
        if (s->an[i]) sqlite3_reset(s->an[i]);
}

static int an_begin(web_store_t *s) {
    if (!s->db) return -1;
    if (sqlite3_exec(s->db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        note_fail(s, "analysis begin");
        return -1;
    }
    return 0;
}

static int an_commit(web_store_t *s) {
    an_reset(s);
    if (sqlite3_exec(s->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        note_fail(s, "analysis commit");
        sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
        return -1;
    }
    return 0;
}

static int an_fail(web_store_t *s, const char *what) {
    note_fail(s, what);
    an_reset(s);
    sqlite3_exec(s->db, "ROLLBACK", NULL, NULL, NULL);
    return -1;
}

static int an_step_done(sqlite3_stmt *st) {
    int rc = sqlite3_step(st);
    sqlite3_reset(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* A column's text, cut to max bytes on a code-point boundary. */
static void col_text(sqlite3_stmt *st, int col, char *out, size_t max) {
    const unsigned char *v = sqlite3_column_text(st, col);
    web_utf8_copy(out, max, v ? (const char *)v : "");
}

/* A key read back from the file is held to the same rule as one off
 * the wire: it must be what its canonicaliser makes of it. */
static int key_ok(int metric, const char *key) {
    char c[WEB_KEY_MAX + 1];
    if (metric < 0) return key[0] == '\0' || web_key_mac(key, c) == 0 ||
                           web_key_ip(key, c) == 0;
    return web_key_canon(metric, key, c) == 0 && !strcmp(c, key);
}

typedef struct {
    long long id;
    int       metric;
    char      key[WEB_KEY_MAX + 1];
} bl_map_t;

static int cmp_map(const void *a, const void *b) {
    const bl_map_t *x = a, *y = b;
    return x->id < y->id ? -1 : x->id > y->id;
}

static int bl_del_slices(web_store_t *s, const long long *ids, size_t n,
                         const char *what);

int web_store_bl_load(web_store_t *s, web_baseline_t *b) {
    if (!s->db) return -1;
    s->an_fresh = 0;
    sqlite3_stmt *st = NULL;
    int cap = b->cap;
    bl_map_t *map = malloc((size_t)cap * sizeof(*map));
    size_t badcap = 1024, nbad = 0;
    long long *bad = malloc(badcap * sizeof(*bad));
    if (!map || !bad) { free(map); free(bad); return -1; }
    int n = 0;
    /* Most recently active first: the first cap valid rows are kept
     * (each goes to the tail of the LRU list, one step); a row that is
     * not valid, or past the cap, is deleted, so the file never holds a
     * row the table does not, which a new entry for the same pair would
     * collide with. */
    if (sqlite3_prepare_v2(s->db,
            "SELECT id,metric,key,last_active,last_fed,first_fed FROM baseline"
            " ORDER BY last_active DESC, id DESC", -1, &st, NULL) != SQLITE_OK) {
        free(map);
        free(bad);
        note_fail(s, "baseline load");
        return -1;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        char mname[64], key[WEB_KEY_MAX + 1];
        long long id = sqlite3_column_int64(st, 0);
        col_text(st, 1, mname, sizeof(mname) - 1);
        col_text(st, 2, key, WEB_KEY_MAX);
        int metric = web_metric_find(mname);
        if (n >= cap || metric < 0 || !key_ok(metric, key) ||
            web_baseline_load(b, metric, key, id, sqlite3_column_int64(st, 3),
                              sqlite3_column_int64(st, 4),
                              sqlite3_column_int64(st, 5)) != 0) {
            if (nbad == badcap) {
                long long *nb = realloc(bad, badcap * 2 * sizeof(*bad));
                if (!nb) continue;
                bad = nb;
                badcap *= 2;
            }
            bad[nbad++] = id;
            continue;
        }
        map[n].id = id;
        map[n].metric = metric;
        snprintf(map[n].key, sizeof(map[n].key), "%s", key);
        n++;
    }
    sqlite3_finalize(st);
    qsort(map, (size_t)n, sizeof(*map), cmp_map);
    if (sqlite3_prepare_v2(s->db, "SELECT cell,id,mean,var,n,wvar,wn FROM"
                           " baseline_cell", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            bl_map_t k;
            memset(&k, 0, sizeof(k));
            k.id = sqlite3_column_int64(st, 1);
            const bl_map_t *m = bsearch(&k, map, (size_t)n, sizeof(*map), cmp_map);
            if (!m) continue;
            web_baseline_load_cell(b, m->metric, m->key, sqlite3_column_int(st, 0),
                                   sqlite3_column_double(st, 2),
                                   sqlite3_column_double(st, 3),
                                   (long)sqlite3_column_int64(st, 4),
                                   sqlite3_column_double(st, 5),
                                   (long)sqlite3_column_int64(st, 6));
        }
        sqlite3_finalize(st);
    }
    free(map);
    /* The rows left out go in slices, each its own transaction with the
     * WAL checkpointed between (after_commit), as the ceiling's do: a
     * restore after --web-max-keys shrank can leave hundreds of
     * thousands of rows and 168 cells each, and one transaction of all
     * of them would grow the WAL by the whole of it. */
    int rc = bl_del_slices(s, bad, nbad, "baseline prune");
    free(bad);
    return rc != 0 ? -1 : n;
}

/* Delete the rows ids[0..n) and their cells, BL_DEL_SLICE rows to a
 * transaction (each row is itself and 168 cells). 0, or -1. */
#define BL_DEL_SLICE (WEB_STORE_SLICE_ROWS / (WEB_BL_CELLS + 1) > 0 \
                      ? WEB_STORE_SLICE_ROWS / (WEB_BL_CELLS + 1) : 1)

static int bl_del_one(web_store_t *s, long long id) {
    sqlite3_stmt *d = s->an[AN_BL_DEL];
    sqlite3_bind_int64(d, 1, id);
    if (an_step_done(d) != 0) return -1;
    for (int c = 0; c < WEB_BL_CELLS; c++) {
        sqlite3_stmt *dc = s->an[AN_CELL_DEL];
        sqlite3_bind_int(dc, 1, c);
        sqlite3_bind_int64(dc, 2, id);
        if (an_step_done(dc) != 0) return -1;
    }
    return 0;
}

static int bl_del_slices(web_store_t *s, const long long *ids, size_t n,
                         const char *what) {
    for (size_t at = 0; at < n; at += BL_DEL_SLICE) {
        size_t end = at + BL_DEL_SLICE < n ? at + BL_DEL_SLICE : n;
        if (an_begin(s) != 0) return -1;
        for (size_t i = at; i < end; i++)
            if (bl_del_one(s, ids[i]) != 0) return an_fail(s, what);
        if (an_commit(s) != 0) return -1;
        after_commit(s);
    }
    return 0;
}

int web_store_bl_put(web_store_t *s, web_baseline_t *b,
                     const web_bl_rec_t *recs, int n) {
    if (!s->db) return -1;
    s->an_fresh = 0;
    if (n <= 0) return 0;
    long long *ids = malloc((size_t)n * sizeof(*ids));
    if (!ids) return -1;
    if (an_begin(s) != 0) { free(ids); return -1; }
    long long cur = -1;
    for (int i = 0; i < n; i++) {
        const web_bl_rec_t *r = &recs[i];
        ids[i] = -1;
        if (r->metric < 0 || r->metric >= WM_COUNT) continue;
        const char *mname = web_metric_defs[r->metric].name;
        if (r->cell < 0) {
            if (r->db_id >= 0) {
                sqlite3_stmt *u = s->an[AN_BL_UPD];
                sqlite3_bind_int64(u, 1, r->db_id);
                sqlite3_bind_int64(u, 2, r->last_active);
                sqlite3_bind_int64(u, 3, r->last_fed);
                sqlite3_bind_int64(u, 4, r->first_fed);
                if (an_step_done(u) != 0) { free(ids); return an_fail(s, "baseline update"); }
                cur = r->db_id;
            } else {
                /* A pair new to the table may still have a row: the
                 * entry was evicted and came back before its delete
                 * reached the file, or the delete was lost. A plain
                 * insert then hits UNIQUE (metric, key) and rolls the
                 * whole batch back, every hour. The old row is taken
                 * over instead, its cells cleared: they were the old
                 * entry's, and the new one writes every cell it has. */
                sqlite3_stmt *f = s->an[AN_BL_FIND];
                sqlite3_bind_text(f, 1, mname, -1, SQLITE_STATIC);
                sqlite3_bind_text(f, 2, r->key, -1, SQLITE_TRANSIENT);
                int frc = sqlite3_step(f);
                long long old = frc == SQLITE_ROW ? sqlite3_column_int64(f, 0) : -1;
                sqlite3_reset(f);
                if (frc != SQLITE_ROW && frc != SQLITE_DONE) {
                    free(ids);
                    return an_fail(s, "baseline find");
                }
                if (old >= 0) {
                    sqlite3_stmt *u = s->an[AN_BL_UPD];
                    sqlite3_bind_int64(u, 1, old);
                    sqlite3_bind_int64(u, 2, r->last_active);
                    sqlite3_bind_int64(u, 3, r->last_fed);
                    sqlite3_bind_int64(u, 4, r->first_fed);
                    if (an_step_done(u) != 0) { free(ids); return an_fail(s, "baseline update"); }
                    for (int c = 0; c < WEB_BL_CELLS; c++) {
                        sqlite3_stmt *dc = s->an[AN_CELL_DEL];
                        sqlite3_bind_int(dc, 1, c);
                        sqlite3_bind_int64(dc, 2, old);
                        if (an_step_done(dc) != 0) { free(ids); return an_fail(s, "baseline reuse"); }
                    }
                    cur = old;
                    pthread_mutex_lock(&s->mu);
                    s->st.bl_rows_reused++;
                    pthread_mutex_unlock(&s->mu);
                } else {
                    sqlite3_stmt *ins = s->an[AN_BL_INS];
                    sqlite3_bind_text(ins, 1, mname, -1, SQLITE_STATIC);
                    sqlite3_bind_text(ins, 2, r->key, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(ins, 3, r->last_active);
                    sqlite3_bind_int64(ins, 4, r->last_fed);
                    sqlite3_bind_int64(ins, 5, r->first_fed);
                    if (an_step_done(ins) != 0) { free(ids); return an_fail(s, "baseline insert"); }
                    cur = sqlite3_last_insert_rowid(s->db);
                }
                ids[i] = cur;
            }
            continue;
        }
        long long id = r->db_id >= 0 ? r->db_id : cur;
        if (id < 0) continue;
        sqlite3_stmt *c = s->an[AN_CELL_PUT];
        sqlite3_bind_int(c, 1, r->cell);
        sqlite3_bind_int64(c, 2, id);
        sqlite3_bind_double(c, 3, r->mean);
        sqlite3_bind_double(c, 4, r->var);
        sqlite3_bind_int(c, 5, r->n);
        sqlite3_bind_double(c, 6, r->wvar);
        sqlite3_bind_int(c, 7, r->wn);
        if (an_step_done(c) != 0) { free(ids); return an_fail(s, "baseline cell"); }
    }
    if (an_commit(s) != 0) { free(ids); return -1; }
    for (int i = 0; i < n; i++)
        if (ids[i] >= 0)
            web_baseline_set_dbid(b, recs[i].metric, recs[i].key, ids[i]);
    free(ids);
    return 0;
}

int web_store_bl_del(web_store_t *s, const long long *ids, int n) {
    if (!s->db) return -1;
    s->an_fresh = 0;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++)
        if (bl_del_one(s, ids[i]) != 0) return an_fail(s, "baseline delete");
    return an_commit(s);
}

int web_store_ep_load(web_store_t *s, long long since,
                      void (*fn)(void *ctx, const web_store_ep_t *e),
                      void *ctx) {
    if (!s->db) return -1;
    sqlite3_stmt *st = NULL;
    sqlite3_stmt *x = s->an[AN_EP_EXPIRE];
    sqlite3_bind_int64(x, 1, since);
    if (an_step_done(x) != 0) {
        note_fail(s, "episode expiry");
        return -1;
    }
    if (sqlite3_prepare_v2(s->db,
            "SELECT id,kind,metric,key,state,score,peak,evidence,first_seen,"
            "last_seen,hit_streak,clear_streak,last_bucket FROM episode"
            " ORDER BY id", -1, &st, NULL) != SQLITE_OK) {
        note_fail(s, "episode load");
        return -1;
    }
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        web_store_ep_t e;
        memset(&e, 0, sizeof(e));
        char mname[64];
        e.id = sqlite3_column_int64(st, 0);
        col_text(st, 1, e.kind, WEB_STORE_KIND_MAX);
        col_text(st, 2, mname, sizeof(mname) - 1);
        e.metric = mname[0] ? web_metric_find(mname) : -1;
        if (mname[0] && e.metric < 0) continue;
        col_text(st, 3, e.key, WEB_KEY_MAX);
        if (!key_ok(e.metric, e.key)) continue;
        e.state = sqlite3_column_int(st, 4);
        e.score = sqlite3_column_double(st, 5);
        e.peak = sqlite3_column_double(st, 6);
        col_text(st, 7, e.evidence, WEB_STORE_EV_MAX);
        e.first_seen = sqlite3_column_int64(st, 8);
        e.last_seen = sqlite3_column_int64(st, 9);
        e.hit_streak = sqlite3_column_int(st, 10);
        e.clear_streak = sqlite3_column_int(st, 11);
        e.last_bucket = sqlite3_column_int64(st, 12);
        fn(ctx, &e);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int web_store_ep_put(web_store_t *s, const web_store_ep_t *e, int n) {
    if (!s->db) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *p = s->an[AN_EP_PUT];
        sqlite3_bind_int64(p, 1, e[i].id);
        sqlite3_bind_text(p, 2, e[i].kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(p, 3, e[i].metric >= 0 && e[i].metric < WM_COUNT
                                ? web_metric_defs[e[i].metric].name : "",
                          -1, SQLITE_STATIC);
        sqlite3_bind_text(p, 4, e[i].key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(p, 5, e[i].state);
        sqlite3_bind_double(p, 6, e[i].score);
        sqlite3_bind_double(p, 7, e[i].peak);
        sqlite3_bind_text(p, 8, e[i].evidence, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(p, 9, e[i].first_seen);
        sqlite3_bind_int64(p, 10, e[i].last_seen);
        sqlite3_bind_int(p, 11, e[i].hit_streak);
        sqlite3_bind_int(p, 12, e[i].clear_streak);
        sqlite3_bind_int64(p, 13, e[i].last_bucket);
        if (an_step_done(p) != 0) return an_fail(s, "episode write");
    }
    return an_commit(s);
}

int web_store_ep_del(web_store_t *s, const long long *ids, int n) {
    if (!s->db) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *d = s->an[AN_EP_DEL];
        sqlite3_bind_int64(d, 1, ids[i]);
        if (an_step_done(d) != 0) return an_fail(s, "episode delete");
    }
    return an_commit(s);
}

int web_store_fan_load(web_store_t *s,
                       void (*fn)(void *ctx, const web_store_fan_t *f),
                       void *ctx) {
    if (!s->db) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT key,windows,hist FROM fanout", -1,
                           &st, NULL) != SQLITE_OK) {
        note_fail(s, "fanout load");
        return -1;
    }
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        web_store_fan_t f;
        col_text(st, 0, f.key, WEB_KEY_MAX);
        char c[WEB_KEY_MAX + 1];
        if (web_key_ip(f.key, c) != 0 || strcmp(c, f.key)) continue;
        f.windows = (long)sqlite3_column_int64(st, 1);
        col_text(st, 2, f.hist, WEB_STORE_HIST_MAX);
        fn(ctx, &f);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int web_store_fan_put(web_store_t *s, const web_store_fan_t *f, int n) {
    if (!s->db) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *p = s->an[AN_FAN_PUT];
        sqlite3_bind_text(p, 1, f[i].key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(p, 2, f[i].windows);
        sqlite3_bind_text(p, 3, f[i].hist, -1, SQLITE_TRANSIENT);
        if (an_step_done(p) != 0) return an_fail(s, "fanout write");
    }
    return an_commit(s);
}

int web_store_fan_del(web_store_t *s, const char (*keys)[WEB_KEY_MAX + 1],
                      int n) {
    if (!s->db) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *d = s->an[AN_FAN_DEL];
        sqlite3_bind_text(d, 1, keys[i], -1, SQLITE_TRANSIENT);
        if (an_step_done(d) != 0) return an_fail(s, "fanout delete");
    }
    return an_commit(s);
}

int web_store_rep_load(web_store_t *s, long long since,
                       void (*fn)(void *ctx, const web_store_rep_t *r),
                       void *ctx) {
    if (!s->db) return -1;
    if (web_store_rep_prune(s, since) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT kind,key,t FROM reported", -1, &st,
                           NULL) != SQLITE_OK) {
        note_fail(s, "reported load");
        return -1;
    }
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        web_store_rep_t r;
        col_text(st, 0, r.kind, WEB_STORE_KIND_MAX);
        col_text(st, 1, r.key, WEB_KEY_MAX);
        char c[WEB_KEY_MAX + 1];
        if (web_key_mac(r.key, c) != 0 || strcmp(c, r.key)) continue;
        r.t = sqlite3_column_int64(st, 2);
        fn(ctx, &r);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int web_store_rep_put(web_store_t *s, const web_store_rep_t *r, int n) {
    if (!s->db) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *p = s->an[AN_REP_PUT];
        sqlite3_bind_text(p, 1, r[i].kind, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(p, 2, r[i].key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(p, 3, r[i].t);
        if (an_step_done(p) != 0) return an_fail(s, "reported write");
    }
    return an_commit(s);
}

int web_store_rep_prune(web_store_t *s, long long before) {
    if (!s->db) return -1;
    sqlite3_stmt *d = s->an[AN_REP_PRUNE];
    sqlite3_bind_int64(d, 1, before);
    if (an_step_done(d) != 0) {
        note_fail(s, "reported prune");
        return -1;
    }
    return 0;
}

static int any_row(sqlite3_stmt *st, int metric, const char *key, long long t) {
    sqlite3_bind_text(st, 1, web_metric_defs[metric].name, -1, SQLITE_STATIC);
    sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, t);
    int rc = sqlite3_step(st);
    sqlite3_reset(st);
    return rc == SQLITE_ROW ? 1 : rc == SQLITE_DONE ? 0 : -1;
}

int web_store_any_before(web_store_t *s, int metric, const char *key,
                         long long before) {
    if (!s->db || metric < 0 || metric >= WM_COUNT || !key) return -1;
    int r = any_row(s->an[AN_ANY_MIN], metric, key, before);
    if (r != 0) return r;
    long long h = before - before % WEB_HOUR_S;
    return any_row(s->an[AN_ANY_HOUR], metric, key, h);
}

int web_store_hours_at(web_store_t *s, int metric, const char *key,
                       const long long *ts, int n, web_point_t *out) {
    if (!s->db || metric < 0 || metric >= WM_COUNT || !key) return -1;
    sqlite3_stmt *st = s->an[AN_HOUR_AT];
    int found = 0;
    for (int i = 0; i < n; i++) {
        out[i].t = -1;
        sqlite3_bind_text(st, 1, web_metric_defs[metric].name, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, ts[i]);
        int rc = sqlite3_step(st);
        if (rc == SQLITE_ROW) {
            out[i].t = ts[i];
            out[i].sum = sqlite3_column_double(st, 0);
            long long c = sqlite3_column_int64(st, 1);
            out[i].n = c > 0 ? (unsigned long)c : 0;
            out[i].min = sqlite3_column_double(st, 2);
            out[i].max = sqlite3_column_double(st, 3);
            found++;
        }
        sqlite3_reset(st);
        if (rc != SQLITE_ROW && rc != SQLITE_DONE) {
            note_fail(s, "hour lookup");
            return -1;
        }
    }
    return found;
}

/* ── the passive PTR cache (v4, #162) ────────────────────────────────── */

/* A name read back is held to the cache's own rule (web_ptr.h). */
int web_store_ptr_load(web_store_t *s, int cap,
                       void (*fn)(void *ctx, const web_store_ptr_t *r),
                       void *ctx) {
    if (!s->db || cap <= 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(s->db, "SELECT ip,name,first_seen,last_seen FROM"
                           " passive_ptr ORDER BY last_seen DESC, ip LIMIT ?1",
                           -1, &st, NULL) != SQLITE_OK) {
        note_fail(s, "passive_ptr load");
        return -1;
    }
    sqlite3_bind_int(st, 1, cap);
    int n = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        web_store_ptr_t r;
        col_text(st, 0, r.ip, WEB_KEY_MAX);
        col_text(st, 1, r.name, WEB_STORE_PTR_NAME_MAX);
        r.first_seen = sqlite3_column_int64(st, 2);
        r.last_seen = sqlite3_column_int64(st, 3);
        char c[WEB_KEY_MAX + 1];
        if (web_key_ip(r.ip, c) != 0 || strcmp(c, r.ip)) continue;
        fn(ctx, &r);
        n++;
    }
    sqlite3_finalize(st);
    return n;
}

int web_store_ptr_put(web_store_t *s, const web_store_ptr_t *r, int n,
                      int cap, long long *evicted) {
    if (evicted) *evicted = 0;
    if (!s->db || cap <= 0) return -1;
    if (n <= 0) return 0;
    if (an_begin(s) != 0) return -1;
    for (int i = 0; i < n; i++) {
        sqlite3_stmt *p = s->an[AN_PTR_PUT];
        sqlite3_bind_text(p, 1, r[i].ip, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(p, 2, r[i].name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(p, 3, r[i].first_seen);
        sqlite3_bind_int64(p, 4, r[i].last_seen);
        if (an_step_done(p) != 0) return an_fail(s, "passive_ptr write");
    }
    sqlite3_stmt *d = s->an[AN_PTR_PRUNE];
    sqlite3_bind_int(d, 1, cap);
    if (an_step_done(d) != 0) return an_fail(s, "passive_ptr prune");
    long long gone = sqlite3_changes(s->db);
    if (an_commit(s) != 0) return -1;
    if (evicted) *evicted = gone;
    return 0;
}

/* The presence cells of (metric, key) from tier (minute or hour): bit
 * i of bits (LSB first in each byte) is set when a row of that tier
 * starting in [from + i * cell_s, from + (i + 1) * cell_s) and before
 * to has a max of 0.5 or more. One grouped range read of the (series,
 * t) key; the read-only connection, parameters bound. Cells set, or
 * -1. */
static const char *const Q_PRESENCE[WEB_TIER_COUNT] = {
    NULL,
    "SELECT (r.t - ?3) / ?4 FROM minute r JOIN series x ON x.id=r.series"
    " WHERE x.metric=?1 AND x.key=?2 AND r.t>=?3 AND r.t<?5"
    " AND r.max>=0.5 GROUP BY 1",
    "SELECT (r.t - ?3) / ?4 FROM hour r JOIN series x ON x.id=r.series"
    " WHERE x.metric=?1 AND x.key=?2 AND r.t>=?3 AND r.t<?5"
    " AND r.max>=0.5 GROUP BY 1",
};

int web_store_presence(web_store_t *s, int tier, int metric, const char *key,
                       long long from, long long to, int ncell, int cell_s,
                       unsigned char *bits) {
    if (!s->rd || tier < 0 || tier >= WEB_TIER_COUNT || !Q_PRESENCE[tier] ||
        metric < 0 || metric >= WM_COUNT || !key || ncell <= 0 || cell_s <= 0)
        return -1;
    long long end = from + (long long)ncell * cell_s;
    if (to < end) end = to;
    pthread_mutex_lock(&s->rmu);
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(s->rd, Q_PRESENCE[tier], -1, &st, NULL);
    int set = 0;
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(st, 1, web_metric_defs[metric].name, -1, SQLITE_STATIC);
        sqlite3_bind_text(st, 2, key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 3, from);
        sqlite3_bind_int(st, 4, cell_s);
        sqlite3_bind_int64(st, 5, end);
        while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
            long long c = sqlite3_column_int64(st, 0);
            if (c < 0 || c >= ncell) continue;
            if (!(bits[c / 8] & (1u << (c % 8)))) set++;
            bits[c / 8] |= (unsigned char)(1u << (c % 8));
        }
    }
    int bad = rc != SQLITE_DONE;
    sqlite3_finalize(st);
    pthread_mutex_unlock(&s->rmu);
    if (bad) {
        set_err(s, "presence", s->rd);
        return -1;
    }
    return set;
}

#endif /* WITH_SQLITE */
