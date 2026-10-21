#include "web_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_routes.h"

enum { C_FREE = 0, C_READ, C_WRITE, C_LINGER, C_SSE };

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int set_flags(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return -1;
    int fd_fl = fcntl(fd, F_GETFD);
    if (fd_fl < 0 || fcntl(fd, F_SETFD, fd_fl | FD_CLOEXEC) < 0) return -1;
    return 0;
}

#define STAT_INC(s, field) do {              \
        pthread_mutex_lock(&(s)->mu);        \
        (s)->stats.field++;                  \
        pthread_mutex_unlock(&(s)->mu);      \
    } while (0)

int web_server_socket(int family, char *err, size_t errsz) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(err, errsz, "socket: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* [::] means IPv6 only. A dual-stack listener would make "which
     * peers can reach this" depend on a sysctl, so a failure to set it
     * is a failure to open, not a silent fallback to dual-stack. */
    if (family == AF_INET6 &&
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)) < 0) {
        snprintf(err, errsz, "IPV6_V6ONLY: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int web_server_open(web_server_t *s, const web_config_t *cfg,
                    char *err, size_t errsz) {
    memset(s, 0, sizeof(*s));
    s->lfd = -1;
    s->wake[0] = s->wake[1] = -1;
    for (int i = 0; i < WEB_MAX_CONNS; i++) s->conns[i].fd = -1;
    s->cfg = *cfg;
    pthread_mutex_init(&s->mu, NULL);
    s->start_ms = now_ms();
    s->next_tick_ms = s->start_ms + cfg->tick_ms;
    s->next_ping_ms = s->start_ms + cfg->ping_ms;

    if (web_config_check(cfg, err, errsz) != 0) return -1;

    struct sockaddr_storage ss;
    socklen_t sl;
    memset(&ss, 0, sizeof(ss));
    if (cfg->bind_family == AF_INET6) {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)&ss;
        a6->sin6_family = AF_INET6;
        a6->sin6_port   = htons(cfg->bind_port);
        memcpy(&a6->sin6_addr, cfg->bind_addr, 16);
        sl = sizeof(*a6);
    } else {
        struct sockaddr_in *a4 = (struct sockaddr_in *)&ss;
        a4->sin_family = AF_INET;
        a4->sin_port   = htons(cfg->bind_port);
        memcpy(&a4->sin_addr, cfg->bind_addr, 4);
        sl = sizeof(*a4);
    }

    int fd = web_server_socket(cfg->bind_family, err, errsz);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&ss, sl) < 0 || listen(fd, 16) < 0 ||
        set_flags(fd) < 0) {
        snprintf(err, errsz, "bind: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) {
        s->port = ntohs(cfg->bind_family == AF_INET6
                        ? ((struct sockaddr_in6 *)&ss)->sin6_port
                        : ((struct sockaddr_in *)&ss)->sin_port);
    }
    if (pipe(s->wake) < 0 || set_flags(s->wake[0]) < 0 ||
        set_flags(s->wake[1]) < 0) {
        snprintf(err, errsz, "pipe: %s", strerror(errno));
        close(fd);
        return -1;
    }
    s->lfd = fd;
    return 0;
}

uint16_t web_server_port(const web_server_t *s) { return s->port; }

void web_server_stop(web_server_t *s) {
    char b = 1;
    ssize_t r = write(s->wake[1], &b, 1);
    (void)r;      /* a full pipe already holds a stop request */
}

void web_server_stats(web_server_t *s, web_stats_t *out) {
    pthread_mutex_lock(&s->mu);
    *out = s->stats;
    pthread_mutex_unlock(&s->mu);
}

static void conn_close(web_server_t *s, web_conn_t *c) {
    if (c->state == C_SSE && s->sse_count > 0) s->sse_count--;
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->state = C_FREE;
    c->body = NULL;
    c->out_len = c->out_off = c->body_len = c->body_off = 0;
}

static void count_status(web_server_t *s, int status) {
    pthread_mutex_lock(&s->mu);
    switch (status) {
    case 200: s->stats.status_200++; break;
    case 304: s->stats.status_304++; break;
    case 503: s->stats.status_503++; break;
    case 404: s->stats.status_404++; break;
    case 405: s->stats.status_405++; break;
    case 431: s->stats.status_431++; break;
    case 400: s->stats.status_400++; break;
    default: break;
    }
    pthread_mutex_unlock(&s->mu);
}

static void conn_respond(web_server_t *s, web_conn_t *c, int status,
                         int is_head) {
    c->out_len = web_http_response(status, is_head, c->out, sizeof(c->out));
    c->out_off = 0;
    c->body = NULL;
    c->body_len = c->body_off = 0;
    c->state = C_WRITE;
    c->deadline_ms = now_ms() + s->cfg.timeout_ms;
    count_status(s, status);
}

static void health_now(const web_server_t *s, web_health_t *h) {
    h->uptime_s    = (now_ms() - s->start_ms) / 1000;
    h->sse_clients = s->sse_count;
    h->tick_seq    = s->tick_seq;
}

/* Send what a stream has queued. A client that went away is closed and
 * counted; one that is merely slow keeps its bytes queued. */
static void sse_flush(web_server_t *s, web_conn_t *c) {
    while (c->out_off < c->out_len) {
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off,
                         MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            conn_close(s, c);
            STAT_INC(s, sse_closed);
            return;
        }
        c->out_off += (size_t)n;
    }
    c->out_off = c->out_len = 0;
}

/* Queue one event on a stream. The unsent total is what the client has
 * not taken; past WEB_SSE_MAX_UNSENT it is dropped rather than buffered
 * without bound, and the browser's EventSource reconnects by itself if
 * it was only briefly stalled. */
static void sse_queue(web_server_t *s, web_conn_t *c, const char *ev,
                      size_t n) {
    size_t unsent = c->out_len - c->out_off;
    if (unsent + n > WEB_SSE_MAX_UNSENT) {
        conn_close(s, c);
        STAT_INC(s, sse_dropped);
        return;
    }
    if (c->out_len + n > sizeof(c->out)) {
        memmove(c->out, c->out + c->out_off, unsent);
        c->out_off = 0;
        c->out_len = unsent;
    }
    memcpy(c->out + c->out_len, ev, n);
    c->out_len += n;
    sse_flush(s, c);
}

static void sse_broadcast(web_server_t *s, const char *ev, size_t n) {
    for (int i = 0; i < WEB_MAX_CONNS; i++)
        if (s->conns[i].fd >= 0 && s->conns[i].state == C_SSE)
            sse_queue(s, &s->conns[i], ev, n);
}

static size_t tick_event(const web_server_t *s, char *out, size_t sz) {
    web_health_t h;
    health_now(s, &h);
    return web_sse_tick(out, sz, s->tick_seq, (long long)time(NULL), &h);
}

/* The loop's timers. A late wake-up sends one tick, not a burst to
 * catch up: the counter is a heartbeat, not a clock. */
static void run_timers(web_server_t *s, long long now) {
    char ev[256];
    if (now >= s->next_tick_ms) {
        s->tick_seq++;
        STAT_INC(s, ticks);
        size_t n = tick_event(s, ev, sizeof(ev));
        if (n) sse_broadcast(s, ev, n);
        s->next_tick_ms = now + s->cfg.tick_ms;
    }
    if (now >= s->next_ping_ms) {
        size_t n = web_sse_ping(ev, sizeof(ev));
        if (n) sse_broadcast(s, ev, n);
        s->next_ping_ms = now + s->cfg.ping_ms;
    }
}

static void conn_write(web_server_t *s, web_conn_t *c);

static void conn_route(web_server_t *s, web_conn_t *c, const web_req_t *rq) {
    web_health_t h;
    health_now(s, &h);
    web_resp_t r;
    if (web_route(rq, &h, s->sse_count < WEB_MAX_SSE, c->out, sizeof(c->out),
                  &r) != 0) {
        conn_close(s, c);
        return;
    }
    count_status(s, r.status);
    c->out_len = r.out_len;
    c->out_off = 0;
    if (r.kind == WEB_R_SSE) {
        int sz = WEB_SSE_SNDBUF;
        setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
        c->state = C_SSE;
        s->sse_count++;
        STAT_INC(s, sse_opened);
        /* The current count at once, so a new page does not sit on "-"
         * for up to a tick. */
        char ev[256];
        size_t n = tick_event(s, ev, sizeof(ev));
        if (n) sse_queue(s, c, ev, n);
        else   sse_flush(s, c);
        return;
    }
    c->body = r.body;
    c->body_len = r.body_len;
    c->body_off = 0;
    c->state = C_WRITE;
    c->deadline_ms = now_ms() + s->cfg.timeout_ms;
    conn_write(s, c);
}

static void accept_ready(web_server_t *s) {
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof(peer);
        int fd = accept(s->lfd, (struct sockaddr *)&peer, &pl);
        if (fd < 0) {
            /* Out of descriptors or kernel memory: the peer stays in the
             * backlog and the listener stays readable, so polling it
             * again at once would spin. Stop polling it for a moment.
             * Anything else (EAGAIN, a peer that already left) just ends
             * this pass. */
            if (errno == EMFILE || errno == ENFILE || errno == ENOBUFS ||
                errno == ENOMEM) {
                s->accept_resume_ms = now_ms() + WEB_ACCEPT_BACKOFF_MS;
                STAT_INC(s, accept_paused);
            }
            return;
        }

        /* The allow list is applied before anything else touches the
         * connection: no read, no write, no slot. */
        if (!web_acl_permits(&s->cfg.acl, (struct sockaddr *)&peer, pl)) {
            close(fd);
            STAT_INC(s, refused);
            continue;
        }
        STAT_INC(s, accepted);

        web_conn_t *c = NULL;
        for (int i = 0; i < WEB_MAX_CONNS; i++)
            if (s->conns[i].fd < 0) { c = &s->conns[i]; break; }
        if (!c || set_flags(fd) < 0) {
            close(fd);
            STAT_INC(s, busy);
            continue;
        }
        c->fd = fd;
        c->state = C_READ;
        c->len = 0;
        c->deadline_ms = now_ms() + s->cfg.timeout_ms;
    }
}

static void conn_write(web_server_t *s, web_conn_t *c) {
    for (;;) {
        const char *p;
        size_t left;
        if (c->out_off < c->out_len) {
            p = c->out + c->out_off;
            left = c->out_len - c->out_off;
        } else if (c->body && c->body_off < c->body_len) {
            p = (const char *)c->body + c->body_off;
            left = c->body_len - c->body_off;
        } else {
            break;
        }
        ssize_t n = send(c->fd, p, left, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                return;
            conn_close(s, c);
            return;
        }
        if (c->out_off < c->out_len) c->out_off += (size_t)n;
        else                         c->body_off += (size_t)n;
    }
    STAT_INC(s, served);
    /* Half-close and drain: closing with unread request bytes queued
     * (a body, or the tail of an oversize header) makes the kernel send
     * RST, which can destroy the response before the client reads it. */
    shutdown(c->fd, SHUT_WR);
    c->state = C_LINGER;
    c->deadline_ms = now_ms() + s->cfg.linger_ms;
}

static void conn_read(web_server_t *s, web_conn_t *c) {
    if (c->state == C_SSE) {
        /* A stream client has nothing to say; anything it sends is
         * dropped. This read is how its departure is noticed when no
         * event is due. */
        char sink[512];
        for (;;) {
            ssize_t n = recv(c->fd, sink, sizeof(sink), 0);
            if (n > 0) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                          errno == EINTR))
                return;
            conn_close(s, c);
            STAT_INC(s, sse_closed);
            return;
        }
    }
    if (c->state == C_LINGER) {
        char sink[4096];
        for (;;) {
            ssize_t n = recv(c->fd, sink, sizeof(sink), 0);
            if (n > 0) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                          errno == EINTR))
                return;
            conn_close(s, c);
            return;
        }
    }

    ssize_t n = recv(c->fd, c->buf + c->len, sizeof(c->buf) - c->len, 0);
    if (n == 0) { conn_close(s, c); return; }
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            conn_close(s, c);
        return;
    }
    c->len += (size_t)n;

    web_req_t rq;
    int status = web_http_parse(c->buf, c->len, &rq);
    if (status == 0) return;
    if (status == WEB_HTTP_ROUTE) { conn_route(s, c, &rq); return; }
    conn_respond(s, c, status, rq.is_head);
    conn_write(s, c);
}

static void conn_timeout(web_server_t *s, web_conn_t *c) {
    if (c->state == C_LINGER) { conn_close(s, c); return; }
    STAT_INC(s, timeouts);
    if (c->state == C_READ) {
        /* One best-effort 408. A client too slow to send a header is
         * not owed a write budget for the answer. */
        char out[512];
        size_t n = web_http_response(408, 0, out, sizeof(out));
        ssize_t w = send(c->fd, out, n, MSG_NOSIGNAL);
        (void)w;
    }
    conn_close(s, c);
}

int web_server_run(web_server_t *s) {
    struct pollfd pfd[2 + WEB_MAX_CONNS];
    int           idx[2 + WEB_MAX_CONNS];

    for (;;) {
        int np = 0;
        long long now = now_ms();
        run_timers(s, now);
        long long next = s->next_tick_ms < s->next_ping_ms
                       ? s->next_tick_ms : s->next_ping_ms;

        pfd[np].fd = s->wake[0]; pfd[np].events = POLLIN; idx[np++] = -1;
        /* A negative fd is skipped by poll(): the listener sits out an
         * accept back-off while existing connections carry on. */
        int paused = s->accept_resume_ms > now;
        pfd[np].fd = paused ? -1 : s->lfd;
        pfd[np].events = POLLIN; idx[np++] = -2;
        if (paused && s->accept_resume_ms < next) next = s->accept_resume_ms;
        for (int i = 0; i < WEB_MAX_CONNS; i++) {
            web_conn_t *c = &s->conns[i];
            if (c->fd < 0) continue;
            if (c->state == C_SSE) {
                /* No deadline: a stream lasts until the client leaves or
                 * falls too far behind. */
                pfd[np].fd = c->fd;
                pfd[np].events = (short)(POLLIN |
                    (c->out_off < c->out_len ? POLLOUT : 0));
                idx[np++] = i;
                continue;
            }
            if (c->deadline_ms <= now) { conn_timeout(s, c); continue; }
            if (c->deadline_ms < next) next = c->deadline_ms;
            pfd[np].fd = c->fd;
            pfd[np].events = c->state == C_WRITE ? POLLOUT : POLLIN;
            idx[np++] = i;
        }

        int wait = next <= now ? 0 : (int)(next - now);
        int r = poll(pfd, (nfds_t)np, wait);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (pfd[0].revents) {
            char b[16];
            while (read(s->wake[0], b, sizeof(b)) > 0) { }
            return 0;
        }
        if (pfd[1].revents & POLLIN) accept_ready(s);
        for (int k = 2; k < np; k++) {
            if (!pfd[k].revents) continue;
            web_conn_t *c = &s->conns[idx[k]];
            if (c->fd < 0) continue;
            if (c->state == C_SSE) {
                if (pfd[k].revents & (POLLERR | POLLNVAL)) {
                    conn_close(s, c);
                    STAT_INC(s, sse_closed);
                    continue;
                }
                if (pfd[k].revents & (POLLIN | POLLHUP)) conn_read(s, c);
                if (c->fd >= 0 && c->state == C_SSE &&
                    (pfd[k].revents & POLLOUT))
                    sse_flush(s, c);
                continue;
            }
            if (c->state == C_WRITE) {
                if (pfd[k].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                    conn_close(s, c);
                    continue;
                }
                conn_write(s, c);
            } else {
                /* POLLHUP with data still queued is read first; recv()
                 * then reports the EOF. */
                conn_read(s, c);
            }
        }
    }
}

void web_server_close(web_server_t *s) {
    for (int i = 0; i < WEB_MAX_CONNS; i++) conn_close(s, &s->conns[i]);
    if (s->lfd >= 0) close(s->lfd);
    if (s->wake[0] >= 0) close(s->wake[0]);
    if (s->wake[1] >= 0) close(s->wake[1]);
    s->lfd = s->wake[0] = s->wake[1] = -1;
    pthread_mutex_destroy(&s->mu);
}
