/* slothweb.db (#160, M2): slothweb's own SQLite file. Never sloth.db.
 *
 * The file holds the closed rollup buckets and nothing else: a series
 * table naming each (metric, key), and one table per tier with sum,
 * count, min and max per bucket, keyed (series, t) and indexed on t. Keys are canonical MACs, IPs,
 * interface names, channels and alert types (web_metrics.h), so no
 * string a peer chose is ever stored as it was sent; no column can hold
 * a credential (web/tests/test_store.c keeps sloth's test_db.c
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
 * found ours or empty is opened read-write, and identified again there. An empty file is
 * new. A file whose meta table names it a slothweb store is ours, at
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

#include "web_rollup.h"

/* The version this build writes. */
#define WEB_STORE_SCHEMA   2
#define WEB_STORE_ERR_MAX  320
#define WEB_DEFAULT_STORE  "./slothweb.db"
/* --web-max-mb: the ceiling on the store's used pages. */
#define WEB_DEFAULT_MAX_MB 256
#define WEB_MAX_MB_MAX     1048576

struct sqlite3;
struct sqlite3_stmt;

typedef struct {
    int           open;
    int           schema;
    long long     rows[WEB_TIER_COUNT];   /* kept by the writer; recounted
                                             at open and each compaction */
    long long     bytes;                  /* used pages x page size */
    long long     file_bytes;             /* page_count x page size */
    unsigned long batches, rows_written, write_errors;
    unsigned long compactions;
    unsigned long long dropped_expired, dropped_ceiling;
    unsigned long ceiling_runs;           /* passes that dropped rows */
    long long     last_compact;           /* unix s, 0 never */
    char          last_error[WEB_STORE_ERR_MAX];
} web_store_stats_t;

typedef struct {
    struct sqlite3      *db;      /* the store thread's */
    struct sqlite3      *rd;      /* the HTTP thread's, read-only */
    struct sqlite3_stmt *ins_series, *get_series, *ins_row[WEB_TIER_COUNT];
    struct sqlite3_stmt *q_row[WEB_TIER_COUNT];
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
 * widened. 0, or -1 (counted, and the reason kept). */
int  web_store_write(web_store_t *s, const web_qrow_t *rows, size_t n);

/* The --web-max-mb ceiling, run after every batch write (so it bounds
 * the file within one flush interval, not one compaction) and inside
 * every compaction. Cheap when under: the used size is three PRAGMAs.
 * Over it, slices are dropped until it is under: the oldest 5 min of
 * fine rows (any series) until no fine row is left, then the oldest
 * hour of keyed minute rows, then the oldest day of keyed hour rows,
 * and only then the same for the global series. Each slice is a range
 * of the t index. The series rows left with no bucket are swept once
 * after, and free pages go back to the file system. Rows dropped, or
 * -1. */
long long web_store_ceiling(web_store_t *s, long long max_bytes);

/* Hourly upkeep: drop rows past each tier's retention (fine 24 h,
 * minute retain_days, hour 400 d), then the ceiling as above; then
 * return free pages and truncate the WAL. 0, or -1. */
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

/* Test seams (web/tests/test_store.c); NULL and 0 in slothweb itself.
 * web_store_test_between_opens runs after the read-only identify and
 * before the read-write open, so a test can swap the file there as
 * another process could. web_store_test_no_defensive makes open_db()
 * read DEFENSIVE back as off, as a library ignoring it would. Neither
 * is set anywhere but the tests. SQLite builds only. */
extern void (*web_store_test_between_opens)(const char *path);
extern int    web_store_test_no_defensive;

/* The DDL of the version this build writes, and the step from version
 * from to from + 1 (NULL past the end). For the guardrail tests. */
const char *web_store_meta_sql(void);
const char *web_store_step_sql(int from);

#endif
