#include "web_sqlbox.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "web_json.h"

static long long box_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── state and thread ─────────────────────────────────────────────────── */

int web_sqlbox_init(web_sqlbox_t *b, web_slothdb_t *sdb, int enabled) {
    memset(b, 0, sizeof(*b));
    b->notify[0] = b->notify[1] = -1;
    b->sdb = sdb;
    b->timeout_ms = WEB_SQL_TIMEOUT_MS;
    b->row_cap = WEB_SQL_ROW_CAP;
    b->out_max = WEB_SQL_OUT_MAX;
    pthread_mutex_init(&b->mu, NULL);
    /* The rest between statements is timed on the monotonic clock. */
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&b->cv, &ca);
    pthread_condattr_destroy(&ca);
    if (!enabled) return 0;
    b->out = malloc(WEB_SQL_HDR + b->out_max);
    if (!b->out) return -1;
    if (pipe(b->notify) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(b->notify[i], F_GETFL);
        if (fl < 0 || fcntl(b->notify[i], F_SETFL, fl | O_NONBLOCK) < 0 ||
            fcntl(b->notify[i], F_SETFD, FD_CLOEXEC) < 0)
            return -1;
    }
    b->enabled = 1;
    return 0;
}

/* The rest (web_sqlbox.h): a statement that held sloth.db open for t ms
 * is followed by t ms with no box reader at all, so sloth's commits in
 * between can checkpoint and restart its WAL. A box reader keeps a WAL
 * read mark for as long as it runs, and a client sending statements
 * back to back would otherwise hold one without a gap, and sloth.db-wal
 * would grow at sloth's full write rate for as long as it kept on. */
static void *worker(void *arg) {
    web_sqlbox_t *b = arg;
    long long rest_until = 0;
    pthread_mutex_lock(&b->mu);
    for (;;) {
        while (!b->stop && b->state != WEB_SQLB_QUEUED)
            pthread_cond_wait(&b->cv, &b->mu);
        while (!b->stop && box_mono_ms() < rest_until) {
            struct timespec ts = { (time_t)(rest_until / 1000),
                                   (long)(rest_until % 1000) * 1000000L };
            pthread_cond_timedwait(&b->cv, &b->mu, &ts);
        }
        if (b->stop) break;
        b->state = WEB_SQLB_RUNNING;
        /* sql, now_s and out are this thread's until DONE: submit()
         * refuses while the state is not IDLE. */
        pthread_mutex_unlock(&b->mu);
        int status = 503;
        size_t off = 0;
        long long t0 = box_mono_ms();
        size_t n = web_sqlbox_query(b, b->sql, b->sql_len, b->now_s, b->out,
                                    WEB_SQL_HDR + b->out_max, &off, &status);
        long long held = box_mono_ms() - t0;
        rest_until = box_mono_ms() + (held < b->timeout_ms ? held : b->timeout_ms);
        if (n == 0) {
            static const char busy[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "Content-Length: 20\r\n"
                "Cache-Control: no-store\r\n"
                "X-Content-Type-Options: nosniff\r\n"
                "Content-Security-Policy: default-src 'none'\r\n"
                "Connection: close\r\n"
                "\r\n"
                "service unavailable\n";
            memcpy(b->out, busy, sizeof(busy) - 1);
            off = 0;
            n = sizeof(busy) - 1;
            status = 503;
        }
        pthread_mutex_lock(&b->mu);
        b->resp_off = off;
        b->resp_len = n;
        b->status = status;
        b->state = WEB_SQLB_DONE;
        char x = 1;
        ssize_t w = write(b->notify[1], &x, 1);
        (void)w;   /* a full pipe already says "look" */
    }
    pthread_mutex_unlock(&b->mu);
    return NULL;
}

int web_sqlbox_start(web_sqlbox_t *b, char *err, size_t errsz) {
    if (!b->enabled) return 0;
    if (pthread_create(&b->th, NULL, worker, b) != 0) {
        snprintf(err, errsz, "SQL box: cannot start its thread");
        return -1;
    }
    b->running = 1;
    return 0;
}

void web_sqlbox_stop(web_sqlbox_t *b) {
    if (!b->running) return;
    pthread_mutex_lock(&b->mu);
    b->stop = 1;
    pthread_cond_broadcast(&b->cv);
    pthread_mutex_unlock(&b->mu);
    pthread_join(b->th, NULL);
    b->running = 0;
}

void web_sqlbox_destroy(web_sqlbox_t *b) {
    web_sqlbox_stop(b);
    for (int i = 0; i < 2; i++)
        if (b->notify[i] >= 0) close(b->notify[i]);
    b->notify[0] = b->notify[1] = -1;
    free(b->out);
    b->out = NULL;
    pthread_cond_destroy(&b->cv);
    pthread_mutex_destroy(&b->mu);
}

int web_sqlbox_submit(web_sqlbox_t *b, const char *sql, size_t len,
                      long long now_s) {
    pthread_mutex_lock(&b->mu);
    if (!b->enabled || b->state != WEB_SQLB_IDLE || len > WEB_SQL_MAX_BYTES) {
        b->st.busy++;
        pthread_mutex_unlock(&b->mu);
        return 1;
    }
    memcpy(b->sql, sql, len);
    b->sql[len] = '\0';
    b->sql_len = len;
    b->now_s = now_s;
    b->state = WEB_SQLB_QUEUED;
    pthread_cond_signal(&b->cv);
    pthread_mutex_unlock(&b->mu);
    return 0;
}

int web_sqlbox_fd(const web_sqlbox_t *b) {
    return b && b->enabled ? b->notify[0] : -1;
}

int web_sqlbox_take(web_sqlbox_t *b, const unsigned char **resp, size_t *len,
                    int *status) {
    char sink[16];
    while (read(b->notify[0], sink, sizeof(sink)) > 0) { }
    pthread_mutex_lock(&b->mu);
    int done = b->state == WEB_SQLB_DONE;
    if (done) {
        *resp = (const unsigned char *)b->out + b->resp_off;
        *len = b->resp_len;
        *status = b->status;
    }
    pthread_mutex_unlock(&b->mu);
    return done;
}

void web_sqlbox_release(web_sqlbox_t *b) {
    pthread_mutex_lock(&b->mu);
    if (b->state == WEB_SQLB_DONE) b->state = WEB_SQLB_IDLE;
    pthread_mutex_unlock(&b->mu);
}

int web_sqlbox_busy(web_sqlbox_t *b) {
    pthread_mutex_lock(&b->mu);
    int busy = b->state != WEB_SQLB_IDLE;
    pthread_mutex_unlock(&b->mu);
    return busy;
}

void web_sqlbox_stats(web_sqlbox_t *b, web_sqlbox_stats_t *out) {
    pthread_mutex_lock(&b->mu);
    *out = b->st;
    pthread_mutex_unlock(&b->mu);
}

/* The header, written right before the body that starts at out + hdr:
 * the response is then contiguous at out + *off. */
static size_t frame(char *out, size_t hdr, size_t bl, int status,
                    size_t *off) {
    char h[WEB_SQL_HDR];
    int n = snprintf(h, sizeof(h),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
        "Connection: close\r\n"
        "\r\n", status,
        status == 200 ? "OK" : status == 400 ? "Bad Request"
                             : "Service Unavailable", bl);
    if (n < 0 || (size_t)n > hdr) return 0;
    *off = hdr - (size_t)n;
    memcpy(out + *off, h, (size_t)n);
    return (size_t)n + bl;
}

#ifndef WITH_SQLITE

size_t web_sqlbox_query(web_sqlbox_t *b, const char *sql, size_t len,
                        long long now_s, char *out, size_t cap, size_t *off,
                        int *status) {
    (void)b; (void)sql; (void)len; (void)now_s;
    *status = 503;
    if (cap <= WEB_SQL_HDR) return 0;
    size_t bl = web_sqlbox_error(out + WEB_SQL_HDR, cap - WEB_SQL_HDR, "unbuilt",
                           "slothweb was built without SQLite");
    return bl ? frame(out, WEB_SQL_HDR, bl, 503, off) : 0;
}

#else

static void count(web_sqlbox_t *b, const web_sqlbox_res_t *r) {
    pthread_mutex_lock(&b->mu);
    b->st.queries++;
    if (r->why) b->st.refused++;
    if (r->truncated == 3) b->st.timeouts++;
    if (r->truncated) b->st.truncated++;
    pthread_mutex_unlock(&b->mu);
}

/* What the tail of the answer needs, whatever was cut before it. */
#define TAIL 512

size_t web_sqlbox_query(web_sqlbox_t *b, const char *sql, size_t len,
                        long long now_s, char *out, size_t cap, size_t *off,
                        int *status) {
    *status = 503;
    if (cap <= WEB_SQL_HDR + TAIL) return 0;
    char *body = out + WEB_SQL_HDR;
    size_t bcap = cap - WEB_SQL_HDR;
    web_sqlbox_res_t res;
    memset(&res, 0, sizeof(res));
    web_sdb_conn_t c;
    char err[WEB_SDB_ERR_MAX];
    size_t bl;
    if (!b->sdb || web_slothdb_open_box(b->sdb, &c, b->timeout_ms, now_s, err,
                                        sizeof(err)) != 0) {
        web_sdb_stats_t ss;
        char why[48];
        memset(&ss, 0, sizeof(ss));
        if (b->sdb) web_slothdb_stats(b->sdb, &ss);
        snprintf(why, sizeof(why), "sloth_db_%s",
                 web_slothdb_state_word(b->sdb ? ss.state : WEB_SDB_NONE));
        if (b->sdb) web_slothdb_close(&c);
        res.status = 503;
        res.why = "sloth_db";
        bl = web_sqlbox_error(body, bcap, why, b->sdb ? err : "no --sloth-db");
    } else {
        web_sqlbox_lim_t lim = { b->timeout_ms, b->row_cap,
                                 bcap < b->out_max ? bcap : b->out_max };
        if (lim.out_cap > TAIL) lim.out_cap -= TAIL;
        bl = web_sqlbox_run_db(c.db, sql, len, &lim, body, bcap, &res);
        web_slothdb_close(&c);
    }
    count(b, &res);
    if (bl == 0) return 0;
    *status = res.status;
    return frame(out, WEB_SQL_HDR, bl, res.status, off);
}

#endif /* WITH_SQLITE */
