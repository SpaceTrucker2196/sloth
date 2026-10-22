#include "web_tsdb.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static long long wall(void *ctx) {
    (void)ctx;
    return (long long)time(NULL);
}

int web_tsdb_init(web_tsdb_t *t, web_rollup_t *ru, web_store_t *store,
                  int retain_days, int max_mb, web_clock_fn clock,
                  void *clock_ctx) {
    memset(t, 0, sizeof(*t));
    t->ru = ru;
    t->store = store;
    t->retain_days = retain_days;
    t->max_bytes = (long long)max_mb * 1024 * 1024;
    t->clock = clock ? clock : wall;
    t->clock_ctx = clock_ctx;
    t->stop[0] = t->stop[1] = -1;
    t->last_minute = -1;
    t->batch = calloc(WEB_FLUSH_MAX, sizeof(*t->batch));
    return t->batch ? 0 : -1;
}

void web_tsdb_destroy(web_tsdb_t *t) {
    free(t->batch);
    t->batch = NULL;
}

void web_tsdb_set_hook(web_tsdb_t *t, web_tsdb_hook_fn hook, void *ctx) {
    t->hook = hook;
    t->hook_ctx = ctx;
}

void web_tsdb_set_rows_hook(web_tsdb_t *t, web_tsdb_rows_fn fn, void *ctx) {
    t->rows_hook = fn;
    t->rows_ctx = ctx;
}

static void flush(web_tsdb_t *t) {
    if (!t->store && !t->rows_hook) return;
    size_t n;
    int wrote = 0;
    while ((n = web_rollup_take(t->ru, t->batch, WEB_FLUSH_MAX)) > 0) {
        if (t->store) web_store_write(t->store, t->batch, n);
        if (t->rows_hook) t->rows_hook(t->rows_ctx, t->batch, n);
        wrote = 1;
        if (n < WEB_FLUSH_MAX) break;
    }
    /* The ceiling after every batch, not only at the hourly compaction:
     * key churn can write millions of rows in an hour. */
    if (wrote && t->store) web_store_ceiling(t->store, t->max_bytes);
}

void web_tsdb_step(web_tsdb_t *t, long long now_s) {
    if (!t->started) {
        t->started = 1;
        t->next_flush = now_s + WEB_FLUSH_S;
        /* A compaction at start trims what a long stop left behind. */
        if (t->store)
            web_store_compact(t->store, now_s, t->retain_days, t->max_bytes);
        t->next_compact = now_s + WEB_COMPACT_S;
    }
    web_rollup_close_due(t->ru, now_s);
    /* Early when the queue is past its high-water mark, so a burst of
     * evictions is written rather than left to fill it; and at every
     * minute boundary when a hook reads the rows, so its minute pass
     * sees the minute that just closed (web_tsdb.h). */
    long long minute = now_s / WEB_MINUTE_S;
    int crossed = t->rows_hook && minute != t->last_minute;
    t->last_minute = minute;
    if (now_s >= t->next_flush || crossed ||
        (t->store && web_rollup_queued(t->ru) >= WEB_FLUSH_HIGH)) {
        flush(t);
        t->next_flush = now_s + WEB_FLUSH_S;
    }
    if (now_s >= t->next_compact) {
        /* After the write, like sloth's db_maintain(). */
        flush(t);
        if (t->store)
            web_store_compact(t->store, now_s, t->retain_days, t->max_bytes);
        t->next_compact = now_s + WEB_COMPACT_S;
    }
    if (t->hook) t->hook(t->hook_ctx, now_s);
}

/* What is queued goes first, so close_all() starts from an empty
 * queue: the per-series bound the queue is sized by (web_rollup.h)
 * counts the shutdown's rows on their own. */
void web_tsdb_flush_all(web_tsdb_t *t) {
    flush(t);
    web_rollup_close_all(t->ru);
    flush(t);
}

static void *tsdb_main(void *arg) {
    web_tsdb_t *t = arg;
    for (;;) {
        web_tsdb_step(t, t->clock(t->clock_ctx));
        struct pollfd p = { t->stop[0], POLLIN, 0 };
        int r = poll(&p, 1, 1000);
        if (r > 0) break;
        if (r < 0 && errno != EINTR) break;
    }
    return NULL;
}

int web_tsdb_start(web_tsdb_t *t, char *err, size_t errsz) {
    if (pipe(t->stop) < 0) {
        snprintf(err, errsz, "pipe: %s", strerror(errno));
        t->stop[0] = t->stop[1] = -1;
        return -1;
    }
    fcntl(t->stop[0], F_SETFD, FD_CLOEXEC);
    fcntl(t->stop[1], F_SETFD, FD_CLOEXEC);
    if (pthread_create(&t->th, NULL, tsdb_main, t) != 0) {
        snprintf(err, errsz, "pthread_create failed");
        close(t->stop[0]);
        close(t->stop[1]);
        t->stop[0] = t->stop[1] = -1;
        return -1;
    }
    t->running = 1;
    return 0;
}

void web_tsdb_stop(web_tsdb_t *t) {
    if (t->running) {
        char b = 1;
        ssize_t w = write(t->stop[1], &b, 1);
        (void)w;
        pthread_join(t->th, NULL);
        close(t->stop[0]);
        close(t->stop[1]);
        t->stop[0] = t->stop[1] = -1;
        t->running = 0;
    }
    web_tsdb_flush_all(t);
}
