#include "web_store.h"

#include <errno.h>
#include <fcntl.h>
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

typedef struct {
    int         from;
    const char *sql;
    const char *what;
} web_step_t;

static const web_step_t STEPS[] = {
    { 0, STEP_V1_SQL, "created series, fine, minute and hour" },
    { 1, STEP_V2_SQL, "indexed fine, minute and hour on t" },
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

int web_store_query(web_store_t *s, int tier, int metric, const char *key,
                    long long from, long long to, web_point_t *out, int max,
                    int *more) {
    (void)s; (void)tier; (void)metric; (void)key; (void)from; (void)to;
    (void)out; (void)max;
    *more = 0;
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

#else

#include <sqlite3.h>

/* SQLITE_OPEN_NOFOLLOW is the guard the side-file checks lean on (they
 * are advisory: a symlink can appear between lstat() and SQLite's own
 * open), and it arrived in 3.31.0; the upsert in web_store_write()
 * needs 3.24. Same floor as sloth (src/db.c). */
#if defined(SQLITE_VERSION_NUMBER) && SQLITE_VERSION_NUMBER < 3031000
#error "slothweb needs sqlite3 >= 3.31.0 (SQLITE_OPEN_NOFOLLOW)"
#endif

/* Constant SQL per tier: a table name cannot be a bound parameter, so
 * each statement is spelled out here and nothing from a request is
 * ever part of one. */
static const char *const INS_ROW[WEB_TIER_COUNT] = {
    "INSERT INTO fine (series,t,sum,n,min,max) VALUES (?1,?2,?3,?4,?5,?6)"
    " ON CONFLICT (series,t) DO UPDATE SET sum=sum+excluded.sum,"
    " n=n+excluded.n, min=min(min,excluded.min), max=max(max,excluded.max)",
    "INSERT INTO minute (series,t,sum,n,min,max) VALUES (?1,?2,?3,?4,?5,?6)"
    " ON CONFLICT (series,t) DO UPDATE SET sum=sum+excluded.sum,"
    " n=n+excluded.n, min=min(min,excluded.min), max=max(max,excluded.max)",
    "INSERT INTO hour (series,t,sum,n,min,max) VALUES (?1,?2,?3,?4,?5,?6)"
    " ON CONFLICT (series,t) DO UPDATE SET sum=sum+excluded.sum,"
    " n=n+excluded.n, min=min(min,excluded.min), max=max(max,excluded.max)",
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
static const char *const DEL_EXPIRED[WEB_TIER_COUNT] = {
    "DELETE FROM fine WHERE t<?1",
    "DELETE FROM minute WHERE t<?1",
    "DELETE FROM hour WHERE t<?1",
};
/* The ceiling drops the oldest slice of one class of rows at a time,
 * in this order: fine rows (any series; the 24 h tier is the one the
 * spec gives up first), then the minute and hour rows of keyed series,
 * and only then those of the global series (the network-wide totals,
 * one series per metric, which no key churn can multiply). A class is
 * left only once it is empty. The slices are small so that a ceiling
 * met under load trims rather than wipes. */
#define KEYED  "series IN (SELECT id FROM series WHERE key<>'')"
#define GLOBAL "series IN (SELECT id FROM series WHERE key='')"
static const char *const CEIL_STEP[] = {
    "DELETE FROM fine WHERE t<(SELECT MIN(t) FROM fine)+300",
    "DELETE FROM minute WHERE " KEYED " AND t<(SELECT MIN(t) FROM minute"
    " WHERE " KEYED ")+3600",
    "DELETE FROM hour WHERE " KEYED " AND t<(SELECT MIN(t) FROM hour"
    " WHERE " KEYED ")+86400",
    "DELETE FROM minute WHERE " GLOBAL " AND t<(SELECT MIN(t) FROM minute"
    " WHERE " GLOBAL ")+3600",
    "DELETE FROM hour WHERE " GLOBAL " AND t<(SELECT MIN(t) FROM hour"
    " WHERE " GLOBAL ")+86400",
};
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

int web_store_available(void) { return 1; }

void (*web_store_test_between_opens)(const char *path) = NULL;
int    web_store_test_no_defensive = 0;

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
    if (objects == 0) return -2;
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
    pthread_mutex_lock(&s->mu);
    for (int t = 0; t < WEB_TIER_COUNT; t++) if (r[t] >= 0) s->st.rows[t] = r[t];
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
     * a power cut is the last few seconds of rollups). The WAL is kept
     * small: a 1 MB checkpoint and a 1 MB size limit, so the file and
     * its WAL together stay near the ceiling --web-max-mb sets. */
    if (exec(s->db, "PRAGMA journal_mode=WAL", err, errsz, "WAL") != 0 ||
        exec(s->db, "PRAGMA synchronous=NORMAL", err, errsz, "synchronous") != 0 ||
        exec(s->db, "PRAGMA wal_autocheckpoint=256", err, errsz, "checkpoint") != 0 ||
        exec(s->db, "PRAGMA journal_size_limit=1048576", err, errsz,
             "journal_size_limit") != 0)
        return -1;
    if (v == -2) {
        char stamp[512];
        snprintf(stamp, sizeof(stamp),
                 "BEGIN IMMEDIATE; %s INSERT INTO meta (name,value) VALUES"
                 " ('store','slothweb'),('schema_version','0'); COMMIT;",
                 META_SQL);
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
    s->st.open = 1;
    return 0;
}

void web_store_close(web_store_t *s) {
    if (!s->mu_init) return;
    sqlite3_finalize(s->ins_series);
    sqlite3_finalize(s->get_series);
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        sqlite3_finalize(s->ins_row[t]);
        sqlite3_finalize(s->q_row[t]);
        s->ins_row[t] = s->q_row[t] = NULL;
    }
    s->ins_series = s->get_series = NULL;
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
        sqlite3_stmt *st = s->ins_row[r->tier];
        if (id < 0) goto fail;
        sqlite3_reset(st);
        sqlite3_bind_int64(st, 1, id);
        sqlite3_bind_int64(st, 2, r->t);
        sqlite3_bind_double(st, 3, r->sum);
        sqlite3_bind_int64(st, 4, (sqlite3_int64)r->n);
        sqlite3_bind_double(st, 5, r->min);
        sqlite3_bind_double(st, 6, r->max);
        if (sqlite3_step(st) != SQLITE_DONE) goto fail;
        sqlite3_reset(st);
        added[r->tier]++;
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
        for (int t = 0; t < WEB_TIER_COUNT; t++) sqlite3_reset(s->ins_row[t]);
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

/* The ceiling's loop, inside no transaction (each DELETE is its own).
 * Rows dropped, or -1. Bounded, so a file that will not shrink cannot
 * spin: every pass either deletes a slice or moves on a class. The
 * series rows of what went are swept once, after the loop: under key
 * churn they are as much of the file as the buckets, but a sweep per
 * slice cost more than the slice. The loop does not count what the
 * sweep will free, so it may take one slice more than it needed. */
static long long ceiling_loop(web_store_t *s, long long max_bytes) {
    long long dropped = 0;
    int step = 0;
    for (int guard = 0; max_bytes > 0 && step < CEIL_STEPS && guard < 100000;
         guard++) {
        long long used = used_bytes(s->db);
        if (used < 0) return -1;
        if (used <= max_bytes) break;
        long long d = run_del(s->db, CEIL_STEP[step], 0, 0);
        if (d < 0) return -1;
        if (d == 0) { step++; continue; }
        dropped += d;
    }
    if (dropped > 0 && run_del(s->db, SWEEP_SERIES, 0, 0) < 0) return -1;
    return dropped;
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
    long long d = ceiling_loop(s, max_bytes);
    if (d < 0) { note_fail(s, "ceiling"); return -1; }
    if (d > 0) {
        sqlite3_exec(s->db, "PRAGMA incremental_vacuum", NULL, NULL, NULL);
        recount(s);
    }
    refresh_size(s);
    pthread_mutex_lock(&s->mu);
    s->st.dropped_ceiling += (unsigned long long)d;
    if (d > 0) s->st.ceiling_runs++;
    pthread_mutex_unlock(&s->mu);
    return d;
}

int web_store_compact(web_store_t *s, long long now_s, int retain_days,
                      long long max_bytes) {
    if (!s->db) return -1;
    if (retain_days < 1) retain_days = 1;
    if (retain_days > WEB_RETAIN_DAYS_MAX) retain_days = WEB_RETAIN_DAYS_MAX;
    const long long keep[WEB_TIER_COUNT] = {
        WEB_FINE_KEEP_S, (long long)retain_days * 86400, WEB_HOUR_KEEP_S
    };
    char err[WEB_STORE_ERR_MAX];
    unsigned long long expired = 0;
    long long ceiling = 0;
    if (exec(s->db, "BEGIN IMMEDIATE", err, sizeof(err), "compact begin") != 0)
        goto fail;
    for (int t = 0; t < WEB_TIER_COUNT; t++) {
        long long d = run_del(s->db, DEL_EXPIRED[t], 1, now_s - keep[t]);
        if (d < 0) goto fail_rb;
        expired += (unsigned long long)d;
    }
    if (exec(s->db, "COMMIT", err, sizeof(err), "compact commit") != 0)
        goto fail_rb_msg;

    ceiling = ceiling_loop(s, max_bytes);
    if (ceiling < 0) goto fail;
    if (run_del(s->db, SWEEP_SERIES, 0, 0) < 0)
        goto fail;
    if (exec(s->db, "PRAGMA incremental_vacuum", err, sizeof(err), "vacuum") != 0)
        goto fail_msg;
    /* TRUNCATE can be refused while a reader holds the WAL; that is
     * harmless, the next compaction tries again. */
    sqlite3_exec(s->db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL);
    recount(s);
    refresh_size(s);
    pthread_mutex_lock(&s->mu);
    s->st.compactions++;
    s->st.dropped_expired += expired;
    s->st.dropped_ceiling += (unsigned long long)ceiling;
    if (ceiling > 0) s->st.ceiling_runs++;
    s->st.last_compact = now_s;
    pthread_mutex_unlock(&s->mu);
    return 0;
fail_rb:
    snprintf(err, sizeof(err), "compact: %s", sqlite3_errmsg(s->db));
fail_rb_msg:
    {
        char ignore[64];
        exec(s->db, "ROLLBACK", ignore, sizeof(ignore), "rollback");
    }
    goto fail_msg;
fail:
    snprintf(err, sizeof(err), "compact: %s", sqlite3_errmsg(s->db));
fail_msg:
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

#endif /* WITH_SQLITE */
