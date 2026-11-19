#include "web_posts.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_json.h"

const char *const web_post_type_names[WEB_PT_COUNT] = {
    "ios_post", "ble_contact", "imu_sample", "wifi_self", "geo_fix", "radio_scan",
};

int web_post_type(const char *t) {
    if (!t) return -1;
    for (int i = 0; i < WEB_PT_COUNT; i++)
        if (!strcmp(t, web_post_type_names[i])) return i;
    return -1;
}

int web_post_type_travels(const char *t) {
    return web_post_type(t) == WEB_PT_BLE_CONTACT;
}

int web_post_parse(const char *s, web_sockspec_t *out, char *err, size_t errsz) {
    char spec[96], why[160];
    if (!s || !s[0] || strlen(s) > 64) {
        snprintf(err, errsz, "want A.B.C.D:PORT or [V6]:PORT");
        return -1;
    }
    snprintf(spec, sizeof(spec), "tcp:%s", s);
    if (web_sockspec_parse_flag("--post", spec, out, why, sizeof(why)) != 0) {
        snprintf(err, errsz, "want A.B.C.D:PORT or [V6]:PORT, a literal "
                             "address (names are not resolved)");
        return -1;
    }
    return 0;
}

int web_post_in_tailnet(const web_sockspec_t *sp) {
    static const uint8_t ts6[6] = { 0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0 };
    if (sp->kind != WEB_SOCKSPEC_TCP) return 0;
    if (sp->family == AF_INET6) return !memcmp(sp->addr, ts6, sizeof(ts6));
    return sp->addr[0] == 100 && (sp->addr[1] & 0xc0) == 64;
}

/* ── the roster ──────────────────────────────────────────────────────── */

int web_posts_init(web_posts_t *s, const web_sockspec_t *specs, int n) {
    memset(s, 0, sizeof(*s));
    s->stop[0] = s->stop[1] = -1;
    s->backoff_min_ms = WEB_POST_BACKOFF_MIN_MS;
    s->backoff_max_ms = WEB_POST_BACKOFF_MAX_MS;
    s->connect_ms = WEB_POST_CONNECT_MS;
    if (n < 0) n = 0;
    if (n > WEB_POSTS_MAX) n = WEB_POSTS_MAX;
    if (pthread_mutex_init(&s->mu, NULL) != 0) return -1;
    if (n) {
        s->p = calloc((size_t)n, sizeof(*s->p));
        if (!s->p) {
            pthread_mutex_destroy(&s->mu);
            return -1;
        }
    }
    s->n = n;
    for (int i = 0; i < n; i++) {
        web_post_t *p = &s->p[i];
        p->spec = specs[i];
        p->set = s;
        p->relatch = 1;
        p->id.charging = -1;
        p->id.uptime_s = -1;
        snprintf(p->last_error, sizeof(p->last_error), "not yet tried");
    }
    return 0;
}

void web_posts_destroy(web_posts_t *s) {
    web_posts_stop(s);
    free(s->p);
    s->p = NULL;
    s->n = 0;
    pthread_mutex_destroy(&s->mu);
}

void web_posts_connected(web_posts_t *s, int i) {
    if (i < 0 || i >= s->n) return;
    web_post_t *p = &s->p[i];
    p->relatch = 1;
    p->len = 0;
    p->discarding = 0;
}

static void copy_str(const web_jrec_t *r, const char *k, char *out, size_t max) {
    const char *v = web_jl_str(r, k);
    if (v) web_utf8_copy(out, max, v);
}

/* One decoded record, under the lock. Every record must carry the
 * envelope's "post"; the first after a connect names the post this
 * connection serves, and a record naming another is counted and
 * dropped (one connection is one post). */
static void apply(web_post_t *p, const web_jrec_t *r, long long now_ms) {
    const char *t = web_jl_str(r, "type");
    const char *who = web_jl_str(r, "post");
    if (!who || !who[0] || strlen(who) > WEB_POST_ID_MAX) {
        p->foreign++;
        return;
    }
    if (p->relatch) {
        if (strcmp(p->id.post, who)) {
            /* Another post on this address, or this one's identity
             * rotated: its identity starts over. */
            memset(&p->id, 0, sizeof(p->id));
            p->id.charging = -1;
            p->id.uptime_s = -1;
            snprintf(p->id.post, sizeof(p->id.post), "%s", who);
        }
        p->relatch = 0;
    } else if (strcmp(p->id.post, who)) {
        p->foreign++;
        return;
    }
    p->heard_ms = now_ms;
    int k = web_post_type(t);
    if (k < 0) {
        p->other++;
        return;
    }
    p->count[k]++;
    if (k != WEB_PT_IOS_POST) return;
    web_post_ident_t *id = &p->id;
    copy_str(r, "name", id->name, WEB_POST_NAME_MAX);
    copy_str(r, "role", id->role, sizeof(id->role) - 1);
    copy_str(r, "platform", id->platform, sizeof(id->platform) - 1);
    copy_str(r, "app_ver", id->app_ver, sizeof(id->app_ver) - 1);
    double b;
    id->has_battery = web_jl_num(r, "battery", &b) && b >= 0.0 && b <= 1.0;
    id->battery = id->has_battery ? b : 0.0;
    const web_jfield_t *c = web_jl_get(r, "charging");
    id->charging = c && c->kind == WEB_J_BOOL ? (int)c->i : -1;
    const web_jfield_t *u = web_jl_get(r, "uptime_s");
    id->uptime_s = u && u->kind == WEB_J_INT && u->i >= 0 ? u->i : -1;
    id->ts = web_jl_int(r, "ts", 0);
}

static void one_line(web_post_t *p, long long now_ms) {
    size_t n = p->len;
    if (n == 0 || (n == 1 && p->line[0] == '\r')) return;
    int e = web_jl_parse(p->line, n, &p->rec);
    pthread_mutex_lock(&p->set->mu);
    p->lines++;
    if (e == WEB_JL_OK) apply(p, &p->rec, now_ms);
    else                p->decode_errors++;
    pthread_mutex_unlock(&p->set->mu);
}

size_t web_posts_feed(web_posts_t *s, int i, const char *buf, size_t n,
                      long long now_ms) {
    if (i < 0 || i >= s->n) return 0;
    web_post_t *p = &s->p[i];
    size_t lines = 0;
    pthread_mutex_lock(&s->mu);
    p->bytes += n;
    pthread_mutex_unlock(&s->mu);
    while (n) {
        const char *nl = memchr(buf, '\n', n);
        size_t take = nl ? (size_t)(nl - buf) : n;
        if (p->discarding) {
            /* counted when the line went over */
        } else if (p->len + take > WEB_JL_MAX_LINE) {
            p->discarding = 1;
            p->len = 0;
            pthread_mutex_lock(&s->mu);
            p->decode_errors++;
            pthread_mutex_unlock(&s->mu);
        } else {
            memcpy(p->line + p->len, buf, take);
            p->len += take;
        }
        if (!nl) break;
        if (!p->discarding) one_line(p, now_ms);
        lines++;
        p->len = 0;
        p->discarding = 0;
        buf = nl + 1;
        n -= take + 1;
    }
    return lines;
}

/* ── the readers ─────────────────────────────────────────────────────── */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void set_state(web_post_t *p, int st, const char *err) {
    pthread_mutex_lock(&p->set->mu);
    p->state = st;
    if (st == WEB_POST_ST_CONNECTING) p->attempts++;
    if (st == WEB_POST_ST_CONNECTED) p->connects++;
    if (err) snprintf(p->last_error, sizeof(p->last_error), "%s", err);
    pthread_mutex_unlock(&p->set->mu);
}

/* 1 when a stop was asked for within ms. */
static int wait_stop(int fd, int ms) {
    struct pollfd q = { fd, POLLIN, 0 };
    long long end = mono_ms() + ms;
    for (;;) {
        long long left = end - mono_ms();
        if (left < 0) left = 0;
        int r = poll(&q, 1, (int)left);
        if (r > 0) return 1;
        if (r == 0) return 0;
        if (errno != EINTR) return 0;
    }
}

/* Read until the post closes or a stop: 1 on stop. The socket is only
 * ever read; nothing is sent, not even a shutdown. */
static int pump(web_post_t *p, int fd, char *err, size_t errsz, size_t *lines) {
    struct pollfd q[2] = { { fd, POLLIN, 0 }, { p->set->stop[0], POLLIN, 0 } };
    *lines = 0;
    for (;;) {
        int r = poll(q, 2, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errsz, "poll: %s", strerror(errno));
            return 0;
        }
        if (q[1].revents) return 1;
        if (!q[0].revents) continue;
        ssize_t n = recv(fd, p->rbuf, sizeof(p->rbuf), 0);
        if (n > 0) {
            *lines += web_posts_feed(p->set, (int)(p - p->set->p), p->rbuf,
                                     (size_t)n, mono_ms());
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (n == 0) snprintf(err, errsz, "the post closed the stream");
        else        snprintf(err, errsz, "recv: %s", strerror(errno));
        return 0;
    }
}

static void *post_main(void *arg) {
    web_post_t *p = arg;
    web_posts_t *s = p->set;
    int backoff = 0;
    char err[128];
    for (;;) {
        set_state(p, WEB_POST_ST_CONNECTING, NULL);
        int stopped;
        err[0] = '\0';
        int fd = web_sock_dial(&p->spec, s->connect_ms, s->stop[0], err,
                               sizeof(err), &stopped);
        if (stopped) break;
        if (fd >= 0) {
            web_posts_connected(s, (int)(p - s->p));
            set_state(p, WEB_POST_ST_CONNECTED, "");
            size_t lines;
            int stop = pump(p, fd, err, sizeof(err), &lines);
            close(fd);
            p->len = 0;
            p->discarding = 0;
            if (stop) break;
            /* A post that accepts and closes at once is not redialled in
             * a tight loop. */
            if (lines) backoff = 0;
        }
        backoff = web_backoff_next(backoff, s->backoff_min_ms, s->backoff_max_ms);
        set_state(p, WEB_POST_ST_WAITING, err);
        if (wait_stop(s->stop[0], backoff)) break;
    }
    set_state(p, WEB_POST_ST_WAITING, "stopped");
    return NULL;
}

int web_posts_start(web_posts_t *s, char *err, size_t errsz) {
    if (!s->n) return 0;
    if (pipe(s->stop) < 0) {
        snprintf(err, errsz, "pipe: %s", strerror(errno));
        s->stop[0] = s->stop[1] = -1;
        return -1;
    }
    fcntl(s->stop[0], F_SETFD, FD_CLOEXEC);
    fcntl(s->stop[1], F_SETFD, FD_CLOEXEC);
    for (int i = 0; i < s->n; i++) {
        if (pthread_create(&s->p[i].th, NULL, post_main, &s->p[i]) != 0) {
            snprintf(err, errsz, "pthread_create failed");
            web_posts_stop(s);
            return -1;
        }
        s->p[i].running = 1;
    }
    return 0;
}

void web_posts_stop(web_posts_t *s) {
    if (s->stop[1] < 0) return;
    char b = 1;
    ssize_t w = write(s->stop[1], &b, 1);
    (void)w;
    for (int i = 0; i < s->n; i++) {
        if (!s->p[i].running) continue;
        pthread_join(s->p[i].th, NULL);
        s->p[i].running = 0;
    }
    close(s->stop[0]);
    close(s->stop[1]);
    s->stop[0] = s->stop[1] = -1;
}

/* ── /api/posts ──────────────────────────────────────────────────────── */

static void jstr_or_null(web_jw_t *w, const char *k, const char *v) {
    web_jw_key(w, k);
    if (v && v[0]) web_jw_str(w, v);
    else           web_jw_raw(w, "null");
}

size_t web_posts_json(web_posts_t *s, long long now_ms, char *out, size_t cap) {
    static const char *const ST[] = { "waiting", "connecting", "connected" };
    web_jw_t w;
    char num[48];
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{");
    /* The fleet-share rule for post records (web_posts.h): what may ever
     * travel, stated with the roster so the page need not know it. */
    web_jw_key(&w, "travels");
    web_jw_raw(&w, "[");
    int first = 1;
    for (int k = 0; k < WEB_PT_COUNT; k++) {
        if (!web_post_type_travels(web_post_type_names[k])) continue;
        if (!first) web_jw_raw(&w, ",");
        web_jw_str(&w, web_post_type_names[k]);
        first = 0;
    }
    web_jw_raw(&w, "],");
    web_jw_key(&w, "posts");
    web_jw_raw(&w, "[");
    pthread_mutex_lock(&s->mu);
    for (int i = 0; i < s->n; i++) {
        const web_post_t *p = &s->p[i];
        char ep[INET6_ADDRSTRLEN + 16];
        web_sockspec_format(&p->spec, ep, sizeof(ep));
        if (i) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{");
        /* "tcp:" is the sockspec's word, not the operator's. */
        web_jw_key(&w, "endpoint");
        web_jw_str(&w, !strncmp(ep, "tcp:", 4) ? ep + 4 : ep);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "state");
        web_jw_str(&w, ST[p->state >= 0 && p->state <= 2 ? p->state : 0]);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "attempts");
        web_jw_int(&w, (long long)p->attempts);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "connects");
        web_jw_int(&w, (long long)p->connects);
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "last_error", p->last_error);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "heard_age_s");
        if (p->heard_ms) web_jw_int(&w, now_ms > p->heard_ms ? (now_ms - p->heard_ms) / 1000 : 0);
        else             web_jw_raw(&w, "null");
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "post", p->id.post);
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "name", p->id.name);
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "role", p->id.role);
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "platform", p->id.platform);
        web_jw_raw(&w, ",");
        jstr_or_null(&w, "app_ver", p->id.app_ver);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "battery");
        if (p->id.has_battery) {
            snprintf(num, sizeof(num), "%.2f", p->id.battery);
            web_jw_raw(&w, num);
        } else {
            web_jw_raw(&w, "null");
        }
        web_jw_raw(&w, ",");
        web_jw_key(&w, "charging");
        web_jw_raw(&w, p->id.charging < 0 ? "null" : p->id.charging ? "true" : "false");
        web_jw_raw(&w, ",");
        web_jw_key(&w, "uptime_s");
        if (p->id.uptime_s >= 0) web_jw_int(&w, p->id.uptime_s);
        else                     web_jw_raw(&w, "null");
        web_jw_raw(&w, ",");
        web_jw_key(&w, "records");
        web_jw_raw(&w, "{");
        for (int k = 0; k < WEB_PT_COUNT; k++) {
            if (k) web_jw_raw(&w, ",");
            web_jw_key(&w, web_post_type_names[k]);
            web_jw_int(&w, (long long)p->count[k]);
        }
        web_jw_raw(&w, "},");
        web_jw_key(&w, "other");
        web_jw_int(&w, (long long)p->other);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "foreign");
        web_jw_int(&w, (long long)p->foreign);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "decode_errors");
        web_jw_int(&w, (long long)p->decode_errors);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "lines");
        web_jw_int(&w, (long long)p->lines);
        web_jw_raw(&w, ",");
        web_jw_key(&w, "bytes");
        web_jw_int(&w, (long long)p->bytes);
        web_jw_raw(&w, "}");
    }
    pthread_mutex_unlock(&s->mu);
    web_jw_raw(&w, "]}");
    if (w.overflow) return 0;
    return w.len;
}
