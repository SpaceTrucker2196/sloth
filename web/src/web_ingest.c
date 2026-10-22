#include "web_ingest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "web_acl.h"

/* ── --socket ────────────────────────────────────────────────────────── */

int web_sockspec_parse(const char *s, web_sockspec_t *out,
                       char *err, size_t errsz) {
    memset(out, 0, sizeof(*out));
    if (!s) s = "";
    if (!strncmp(s, "unix:", 5)) {
        const char *p = s + 5;
        size_t n = strlen(p);
        if (n == 0 || n > WEB_SOCK_PATH_MAX) {
            snprintf(err, errsz, "--socket %s: the path must be 1..%d bytes",
                     s, WEB_SOCK_PATH_MAX);
            return -1;
        }
        out->kind = WEB_SOCKSPEC_UNIX;
        memcpy(out->path, p, n + 1);
        return 0;
    }
    if (strncmp(s, "tcp:", 4)) {
        snprintf(err, errsz, "--socket %s: want unix:PATH or tcp:ADDR:PORT", s);
        return -1;
    }
    const char *h = s + 4, *colon;
    char host[INET6_ADDRSTRLEN + 1];
    size_t hl;
    int v6 = h[0] == '[';
    if (v6) {
        const char *rb = strchr(h, ']');
        if (!rb || rb[1] != ':') {
            snprintf(err, errsz, "--socket %s: want tcp:[V6]:PORT", s);
            return -1;
        }
        hl = (size_t)(rb - h - 1);
        if (hl >= sizeof(host)) hl = sizeof(host);   /* refused below */
        else memcpy(host, h + 1, hl);
        colon = rb + 1;
    } else {
        colon = strchr(h, ':');
        if (!colon || strchr(colon + 1, ':')) {
            snprintf(err, errsz, "--socket %s: want tcp:A.B.C.D:PORT or "
                                 "tcp:[V6]:PORT", s);
            return -1;
        }
        hl = (size_t)(colon - h);
        if (hl < sizeof(host)) memcpy(host, h, hl);
    }
    if (hl == 0 || hl >= sizeof(host)) {
        snprintf(err, errsz, "--socket %s: bad address", s);
        return -1;
    }
    host[hl] = '\0';
    /* inet_pton, never getaddrinfo: slothweb resolves nothing. */
    if (inet_pton(v6 ? AF_INET6 : AF_INET, host, out->addr) != 1) {
        snprintf(err, errsz, "--socket %s: not a literal %s address "
                             "(names are not resolved)", s, v6 ? "IPv6" : "IPv4");
        return -1;
    }
    const char *pp = colon + 1;
    size_t pl = strlen(pp);
    int bad = pl == 0 || pl > 5;
    for (size_t i = 0; i < pl; i++)
        if (pp[i] < '0' || pp[i] > '9') bad = 1;
    long port = bad ? -1 : strtol(pp, NULL, 10);
    if (port <= 0 || port > 65535) {
        snprintf(err, errsz, "--socket %s: bad port", s);
        return -1;
    }
    out->kind = WEB_SOCKSPEC_TCP;
    out->family = v6 ? AF_INET6 : AF_INET;
    out->port = (uint16_t)port;
    return 0;
}

void web_sockspec_format(const web_sockspec_t *sp, char *buf, size_t sz) {
    if (sp->kind == WEB_SOCKSPEC_UNIX) {
        snprintf(buf, sz, "unix:%s", sp->path);
        return;
    }
    char host[INET6_ADDRSTRLEN];
    if (!inet_ntop(sp->family, sp->addr, host, sizeof(host)))
        snprintf(host, sizeof(host), "?");
    if (sp->family == AF_INET6) snprintf(buf, sz, "tcp:[%s]:%u", host, (unsigned)sp->port);
    else                        snprintf(buf, sz, "tcp:%s:%u", host, (unsigned)sp->port);
}

int web_sockspec_is_local(const web_sockspec_t *sp) {
    if (sp->kind == WEB_SOCKSPEC_UNIX) return 1;
    return web_addr_is_loopback(sp->family, sp->addr);
}

int web_backoff_next(int cur, int min_ms, int max_ms) {
    if (cur <= 0) return min_ms < max_ms ? min_ms : max_ms;
    if (cur >= max_ms / 2) return max_ms;
    return cur * 2;
}

/* ── the framer ──────────────────────────────────────────────────────── */

void web_feed_reset(web_feed_t *f) {
    f->len = 0;
    f->discarding = 0;
}

static void one_line(web_feed_t *f, web_live_t *l, long long now_ms) {
    /* An empty line is not a record and not an error. */
    size_t n = f->len;
    if (n == 0 || (n == 1 && f->line[0] == '\r')) return;
    int e = web_jl_parse(f->line, n, &f->rec);
    if (e == WEB_JL_OK) web_live_apply(l, &f->rec, now_ms);
    else                web_live_decode_error(l, e, now_ms);
}

size_t web_feed_bytes(web_feed_t *f, web_live_t *l, const char *buf,
                      size_t n, long long now_ms) {
    size_t lines = 0;
    while (n) {
        const char *nl = memchr(buf, '\n', n);
        size_t take = nl ? (size_t)(nl - buf) : n;
        if (f->discarding) {
            /* already counted when the line went over */
        } else if (f->len + take > WEB_JL_MAX_LINE) {
            f->discarding = 1;
            f->len = 0;
            web_live_decode_error(l, WEB_JL_ELONG, now_ms);
        } else {
            memcpy(f->line + f->len, buf, take);
            f->len += take;
        }
        if (!nl) break;
        if (!f->discarding) one_line(f, l, now_ms);
        lines++;
        f->len = 0;
        f->discarding = 0;
        buf = nl + 1;
        n -= take + 1;
    }
    return lines;
}

void web_feed_eof(web_feed_t *f, web_live_t *l) {
    if (f->len && !f->discarding) web_live_truncated(l);
    web_feed_reset(f);
}

/* ── the thread ──────────────────────────────────────────────────────── */

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait ms on the stop pipe. 1 when a stop was asked for. */
static int wait_stop(web_ingest_t *g, int ms) {
    struct pollfd p = { g->stop[0], POLLIN, 0 };
    long long end = mono_ms() + ms;
    for (;;) {
        long long left = end - mono_ms();
        if (left < 0) left = 0;
        int r = poll(&p, 1, (int)left);
        if (r > 0) return 1;
        if (r == 0) return 0;
        if (errno != EINTR) return 0;
    }
}

/* Connect, bounded by connect_ms and the stop pipe. fd, or -1 with err
 * (and *stopped when a stop cut it short). */
static int dial(web_ingest_t *g, char *err, size_t errsz, int *stopped) {
    struct sockaddr_storage ss;
    socklen_t sl;
    int family;
    memset(&ss, 0, sizeof(ss));
    *stopped = 0;
    if (g->spec.kind == WEB_SOCKSPEC_UNIX) {
        struct sockaddr_un *u = (struct sockaddr_un *)&ss;
        u->sun_family = AF_UNIX;
        memcpy(u->sun_path, g->spec.path, strlen(g->spec.path) + 1);
        sl = (socklen_t)sizeof(*u);
        family = AF_UNIX;
    } else if (g->spec.family == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(g->spec.port);
        memcpy(&a->sin6_addr, g->spec.addr, 16);
        sl = (socklen_t)sizeof(*a);
        family = AF_INET6;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(g->spec.port);
        memcpy(&a->sin_addr, g->spec.addr, 4);
        sl = (socklen_t)sizeof(*a);
        family = AF_INET;
    }
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, errsz, "socket: %s", strerror(errno));
        return -1;
    }
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
        fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
        snprintf(err, errsz, "fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&ss, sl) == 0) return fd;
    if (errno != EINPROGRESS) {
        snprintf(err, errsz, "connect: %s", strerror(errno));
        close(fd);
        return -1;
    }
    struct pollfd p[2] = { { fd, POLLOUT, 0 }, { g->stop[0], POLLIN, 0 } };
    long long end = mono_ms() + g->connect_ms;
    for (;;) {
        long long left = end - mono_ms();
        if (left <= 0) {
            snprintf(err, errsz, "connect: timed out after %d ms", g->connect_ms);
            close(fd);
            return -1;
        }
        int r = poll(p, 2, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) {
            snprintf(err, errsz, "poll: %s", strerror(errno));
            close(fd);
            return -1;
        }
        if (p[1].revents) { *stopped = 1; close(fd); return -1; }
        if (p[0].revents) break;
    }
    int soerr = 0;
    socklen_t el = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &el) < 0) soerr = errno;
    if (soerr) {
        snprintf(err, errsz, "connect: %s", strerror(soerr));
        close(fd);
        return -1;
    }
    return fd;
}

/* Read until the peer closes or a stop. Returns 1 on stop. *lines gets
 * the complete lines this connection delivered. */
static int pump(web_ingest_t *g, int fd, char *err, size_t errsz,
                size_t *lines) {
    struct pollfd p[2] = { { fd, POLLIN, 0 }, { g->stop[0], POLLIN, 0 } };
    *lines = 0;
    for (;;) {
        int r = poll(p, 2, -1);
        if (r < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errsz, "poll: %s", strerror(errno));
            return 0;
        }
        if (p[1].revents) return 1;
        if (!p[0].revents) continue;
        ssize_t n = recv(fd, g->rbuf, sizeof(g->rbuf), 0);
        if (n > 0) {
            web_live_sock_bytes(g->live, (size_t)n);
            *lines += web_feed_bytes(&g->feed, g->live, g->rbuf, (size_t)n,
                                     mono_ms());
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
            continue;
        if (n == 0) snprintf(err, errsz, "peer closed the stream");
        else        snprintf(err, errsz, "recv: %s", strerror(errno));
        return 0;
    }
}

static void *ingest_main(void *arg) {
    web_ingest_t *g = arg;
    int backoff = 0;
    char err[WEB_LIVE_ERR_MAX];
    for (;;) {
        web_live_sock_attempt(g->live, mono_ms());
        int stopped;
        int fd = dial(g, err, sizeof(err), &stopped);
        if (stopped) break;
        if (fd >= 0) {
            web_live_sock_connected(g->live, mono_ms());
            web_feed_reset(&g->feed);
            size_t lines;
            int stop = pump(g, fd, err, sizeof(err), &lines);
            web_feed_eof(&g->feed, g->live);
            close(fd);
            if (stop) break;
            /* A peer that accepts and closes at once (sloth's per-peer
             * cap, say) must not be redialled in a tight loop. */
            if (lines) backoff = 0;
        }
        backoff = web_backoff_next(backoff, g->backoff_min_ms, g->backoff_max_ms);
        web_live_sock_failed(g->live, err, backoff, mono_ms());
        if (wait_stop(g, backoff)) break;
    }
    return NULL;
}

int web_ingest_start(web_ingest_t *g, const web_sockspec_t *spec,
                     int backoff_min_ms, int backoff_max_ms,
                     web_live_t *live, char *err, size_t errsz) {
    g->spec = *spec;
    g->backoff_min_ms = backoff_min_ms;
    g->backoff_max_ms = backoff_max_ms;
    g->connect_ms = WEB_SOCK_CONNECT_MS;
    g->live = live;
    g->running = 0;
    web_feed_reset(&g->feed);
    if (pipe(g->stop) < 0) {
        snprintf(err, errsz, "pipe: %s", strerror(errno));
        g->stop[0] = g->stop[1] = -1;
        return -1;
    }
    fcntl(g->stop[0], F_SETFD, FD_CLOEXEC);
    fcntl(g->stop[1], F_SETFD, FD_CLOEXEC);
    if (pthread_create(&g->th, NULL, ingest_main, g) != 0) {
        snprintf(err, errsz, "pthread_create failed");
        close(g->stop[0]);
        close(g->stop[1]);
        g->stop[0] = g->stop[1] = -1;
        return -1;
    }
    g->running = 1;
    return 0;
}

void web_ingest_stop(web_ingest_t *g) {
    if (!g->running) return;
    char b = 1;
    ssize_t w = write(g->stop[1], &b, 1);
    (void)w;
    pthread_join(g->th, NULL);
    close(g->stop[0]);
    close(g->stop[1]);
    g->stop[0] = g->stop[1] = -1;
    g->running = 0;
}
