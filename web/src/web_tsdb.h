/* slothweb time-series store thread (#160, M2).
 *
 * The rollup (web_rollup.h) and the store (web_store.h) meet here. One
 * thread, never the HTTP one, wakes once a second and:
 *   - closes every bucket whose interval has passed, so a series that
 *     went quiet still gets its last bucket;
 *   - every WEB_FLUSH_S, writes the closed buckets to slothweb.db in one
 *     transaction;
 *   - every WEB_COMPACT_S (and once at start), compacts: retention per
 *     tier, the --web-max-mb ceiling, free pages back, the WAL truncated.
 * On stop it closes every open bucket and flushes, so a restart merges
 * the partial buckets with the rest of them.
 *
 * Everything is driven by web_tsdb_step(now): the thread passes the
 * wall clock, the tests a pinned one. With no store (a build without
 * SQLite, or none configured) the step still closes buckets into the
 * in-memory ring. */
#ifndef SLOTHWEB_TSDB_H
#define SLOTHWEB_TSDB_H

#include <pthread.h>

#include "web_metrics.h"
#include "web_rollup.h"
#include "web_store.h"

#define WEB_FLUSH_S    10
#define WEB_COMPACT_S  3600
#define WEB_FLUSH_MAX  4096    /* rows per take from the queue */

typedef struct {
    web_rollup_t *ru;
    web_store_t  *store;          /* NULL: memory only */
    int           retain_days;
    long long     max_bytes;
    long long     next_flush, next_compact;
    int           started;        /* step has run once */
    web_qrow_t   *batch;
    web_clock_fn  clock;
    void         *clock_ctx;
    int           stop[2];
    pthread_t     th;
    int           running;
} web_tsdb_t;

/* store may be NULL. max_mb and retain_days are --web-max-mb and
 * --web-retain-days. clock NULL means time(). 0, or -1 (memory). */
int  web_tsdb_init(web_tsdb_t *t, web_rollup_t *ru, web_store_t *store,
                   int retain_days, int max_mb, web_clock_fn clock,
                   void *clock_ctx);
void web_tsdb_destroy(web_tsdb_t *t);

/* One pass at now_s. */
void web_tsdb_step(web_tsdb_t *t, long long now_s);
/* Close every bucket and write everything queued (shutdown, tests). */
void web_tsdb_flush_all(web_tsdb_t *t);

int  web_tsdb_start(web_tsdb_t *t, char *err, size_t errsz);
/* Stop and join the thread, then web_tsdb_flush_all(). */
void web_tsdb_stop(web_tsdb_t *t);

#endif
