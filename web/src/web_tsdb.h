/* slothweb time-series store thread (#160, M2).
 *
 * The rollup (web_rollup.h) and the store (web_store.h) meet here. One
 * thread, never the HTTP one, wakes once a second and:
 *   - closes every bucket whose interval has passed, so a series that
 *     went quiet still gets its last bucket;
 *   - every WEB_FLUSH_S, or sooner once WEB_FLUSH_HIGH rows are
 *     queued, writes the closed buckets to slothweb.db, WEB_FLUSH_MAX
 *     to a transaction, then applies the --web-max-mb ceiling, so the
 *     store is bounded within one flush interval;
 *   - every WEB_COMPACT_S (and once at start), compacts: retention per
 *     tier, the --web-max-mb ceiling, free pages back, the WAL truncated.
 * On stop it writes what is queued, closes every open bucket and
 * flushes again, so a restart merges the partial buckets with the rest
 * of them.
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
#define WEB_FLUSH_HIGH (WEB_QUEUE_ROWS / 2)   /* queued rows: flush now */

/* Two optional hooks (web_anomaly.h is the one user). The rows hook
 * sees every batch taken off the rollup's queue, after it is written
 * to the store, so a consumer reads the buckets that closed rather than
 * asking the store whether they have arrived. The step hook runs at the
 * end of every step. A step that crosses a minute boundary flushes the
 * queue before calling it, whatever the flush cadence: every bucket that
 * the boundary closed has then been through the rows hook, so a minute
 * pass never runs ahead of its own minute's rows. ctx is opaque to
 * web_tsdb. */
typedef void (*web_tsdb_hook_fn)(void *ctx, long long now_s);
typedef void (*web_tsdb_rows_fn)(void *ctx, const web_qrow_t *rows, size_t n);

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
    web_tsdb_hook_fn hook;
    void         *hook_ctx;
    web_tsdb_rows_fn rows_hook;
    void         *rows_ctx;
    long long     last_minute;    /* now_s / 60 of the last step */
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

/* Call hook(ctx, now_s) at the end of every web_tsdb_step(), once
 * attached. NULL hook detaches. Call before web_tsdb_start(). */
void web_tsdb_set_hook(web_tsdb_t *t, web_tsdb_hook_fn hook, void *ctx);
/* Pass every batch taken off the queue to fn as well. The rollup must
 * queue (store_on 1 or WEB_ROLLUP_Q_LONG) for there to be any. Call
 * before web_tsdb_start(). */
void web_tsdb_set_rows_hook(web_tsdb_t *t, web_tsdb_rows_fn fn, void *ctx);

/* One pass at now_s. */
void web_tsdb_step(web_tsdb_t *t, long long now_s);
/* Close every bucket and write everything queued (shutdown, tests). */
void web_tsdb_flush_all(web_tsdb_t *t);

int  web_tsdb_start(web_tsdb_t *t, char *err, size_t errsz);
/* Stop and join the thread, then web_tsdb_flush_all(). */
void web_tsdb_stop(web_tsdb_t *t);

#endif
