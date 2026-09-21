/* Read-only JSONL data socket. See data_socket.h for the contract.
 *
 * Locking: a single mutex protects the listening fd, the client array,
 * and the bookkeeping path. Callers (the main poll loop's tick, the
 * jsonl.c emit_line path) are short and never block inside the
 * critical section — all socket I/O is non-blocking.
 *
 * Framing (#93): a record reaches the wire only as one contiguous
 * `payload\n` span in the client's queue, and the queue is written from
 * a saved offset. The old writer sent the delimiter as a second send()
 * and forgot it on EAGAIN, so the next record was glued onto the last. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "data_socket.h"
#include "jsonl.h"
#include "formatter.h"

#define MAX_CLIENTS  16

/* Per-client queue of complete records. buf[off..len) is unsent; the
 * record at `off` may be partly on the wire, everything after it is
 * untouched and so is the only thing that may be dropped. */
typedef struct {
    int                fd;
    char              *buf;
    size_t             cap, len, off;
    unsigned long long seq;           /* records offered (sent + dropped) */
    unsigned long long gap;           /* dropped since the last marker */
    unsigned long long dropped;       /* dropped over the connection */
    time_t             progress;      /* last time bytes moved, or queued */
} ds_client_t;

static int             g_listen_fd = -1;
static ds_client_t     g_clients[MAX_CLIENTS];
static int             g_client_n  = 0;
static unsigned long long g_dropped_total = 0;
static char            g_unix_path[256];     /* for cleanup unlink */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static time_t mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/* Syscall indirection. Default to the real libc functions; tests can
 * swap in fakes via data_socket_test_set_*_fn. One predictable branch
 * per call in production. */
static data_socket_send_fn   g_send_fn   = send;
static data_socket_accept_fn g_accept_fn = accept;
static data_socket_clock_fn  g_clock_fn  = mono_now;

void data_socket_test_set_send_fn(data_socket_send_fn fn) {
    pthread_mutex_lock(&g_mu);
    g_send_fn = fn ? fn : send;
    pthread_mutex_unlock(&g_mu);
}

void data_socket_test_set_accept_fn(data_socket_accept_fn fn) {
    pthread_mutex_lock(&g_mu);
    g_accept_fn = fn ? fn : accept;
    pthread_mutex_unlock(&g_mu);
}

void data_socket_test_set_clock_fn(data_socket_clock_fn fn) {
    pthread_mutex_lock(&g_mu);
    g_clock_fn = fn ? fn : mono_now;
    pthread_mutex_unlock(&g_mu);
}

unsigned long long data_socket_dropped_total(void) {
    pthread_mutex_lock(&g_mu);
    unsigned long long n = g_dropped_total;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Internal: replace the current listener (if any) with a new fd.
 * Caller holds g_mu. */
static void install_listener(int fd, const char *unix_path) {
    if (g_listen_fd >= 0) close(g_listen_fd);
    g_listen_fd = fd;
    if (unix_path && unix_path[0])
        snprintf(g_unix_path, sizeof(g_unix_path), "%s", unix_path);
    else
        g_unix_path[0] = '\0';
}

/* Bind a UNIX-domain stream socket at `path`. Unlinks any stale entry
 * at the same path first (a fresh start always wins). */
static int init_unix(const char *path) {
    if (!path || !path[0]) {
        fprintf(stderr, "data-socket: empty unix path\n");
        return -1;
    }
    /* sockaddr_un.sun_path is fixed-size; respect it. */
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        fprintf(stderr, "data-socket: unix path too long\n");
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("data-socket: socket"); return -1; }

    unlink(path);   /* clean any stale entry — fresh start each run */

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("data-socket: bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("data-socket: listen");
        close(fd);
        unlink(path);
        return -1;
    }
    set_nonblock(fd);

    pthread_mutex_lock(&g_mu);
    install_listener(fd, path);
    pthread_mutex_unlock(&g_mu);
    return 0;
}

/* Bind a TCP listener at HOST:PORT. HOST must be a literal IPv4 address
 * (no DNS resolution — keeps the contract trivial and avoids surprise
 * lookups at startup). 0.0.0.0 is allowed but only if the operator
 * passes it explicitly. */
static int init_tcp(const char *host_port) {
    const char *colon = strrchr(host_port, ':');
    if (!colon || colon == host_port) {
        fprintf(stderr, "data-socket: tcp spec needs HOST:PORT\n");
        return -1;
    }
    char host[64];
    size_t hlen = (size_t)(colon - host_port);
    if (hlen >= sizeof(host)) {
        fprintf(stderr, "data-socket: tcp host too long\n");
        return -1;
    }
    memcpy(host, host_port, hlen);
    host[hlen] = '\0';

    long port = strtol(colon + 1, NULL, 10);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "data-socket: bad port %ld\n", port);
        return -1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("data-socket: socket"); return -1; }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "data-socket: bad host %s\n", host);
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("data-socket: bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0) {
        perror("data-socket: listen");
        close(fd);
        return -1;
    }
    set_nonblock(fd);

    pthread_mutex_lock(&g_mu);
    install_listener(fd, NULL);
    pthread_mutex_unlock(&g_mu);
    return 0;
}

int data_socket_init(const char *spec) {
    if (!spec || !spec[0]) return -1;
    if (strncmp(spec, "unix:", 5) == 0) return init_unix(spec + 5);
    if (strncmp(spec, "tcp:",  4) == 0) return init_tcp (spec + 4);
    fprintf(stderr,
            "data-socket: spec must be 'unix:/path' or 'tcp:HOST:PORT'\n");
    return -1;
}

/* Close client i and compact (swap-with-last). Caller holds g_mu.
 * Whatever is still queued is lost with the connection — including the
 * tail of a started record, which the consumer sees as an unterminated
 * fragment before EOF and must discard. */
static void drop_client(int i) {
    close(g_clients[i].fd);
    free(g_clients[i].buf);
    g_clients[i] = g_clients[--g_client_n];
}

/* Write as much of client i's queue as the kernel takes. Returns 0 to
 * keep the client, -1 if it was closed. Caller holds g_mu. */
static int flush_client(int i, time_t now) {
    ds_client_t *c = &g_clients[i];
    while (c->off < c->len) {
        /* MSG_NOSIGNAL: a closed peer is EPIPE here, not SIGPIPE. */
        ssize_t n = g_send_fn(c->fd, c->buf + c->off, c->len - c->off,
                              MSG_NOSIGNAL);
        if (n > 0) {                 /* short writes just loop; errno is
                                      * meaningless on a positive return */
            c->off += (size_t)n;
            c->progress = now;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;                /* wait for writability */
        drop_client(i);              /* 0 or a real error: terminal */
        return -1;
    }
    c->off = c->len = 0;
    return 0;
}

/* Append `s` + '\n' to client c's queue if the whole thing fits under
 * DATA_SOCKET_QUEUE_MAX. Returns 0, or -1 with the queue unchanged. */
static int enqueue(ds_client_t *c, const char *s, size_t n, time_t now) {
    size_t need = n + 1;
    if ((c->len - c->off) + need > DATA_SOCKET_QUEUE_MAX) return -1;
    if (c->len + need > c->cap && c->off > 0) {
        memmove(c->buf, c->buf + c->off, c->len - c->off);
        c->len -= c->off;
        c->off  = 0;
    }
    if (c->len + need > c->cap) {
        size_t cap = c->cap ? c->cap : 16384;
        while (cap < c->len + need) cap *= 2;
        if (cap > DATA_SOCKET_QUEUE_MAX) cap = DATA_SOCKET_QUEUE_MAX;
        char *nb = realloc(c->buf, cap);
        if (!nb) return -1;
        c->buf = nb;
        c->cap = cap;
    }
    if (c->off == c->len) c->progress = now;   /* stall clock starts now */
    memcpy(c->buf + c->len, s, n);
    c->buf[c->len + n] = '\n';
    c->len += need;
    return 0;
}

/* Queue one record for client c, preceded by a socket_gap marker if
 * records were dropped since the last one. Marker and record go in
 * together or not at all, so the marker always sits directly before
 * the first record after the gap. Caller holds g_mu. */
static void offer(ds_client_t *c, const char *line, size_t len, time_t now) {
    if (c->gap) {
        char js[160], out[512];
        const char *m = js;
        snprintf(js, sizeof(js),
                 "{\"type\":\"socket_gap\",\"ts\":%lld,\"seq\":%llu,"
                 "\"dropped\":%llu,\"dropped_total\":%llu}",
                 (long long)time(NULL), c->seq, c->gap, c->dropped);
        if (formatter_get() != OUT_FMT_JSONL &&
            formatter_transform(js, out, (int)sizeof(out)) >= 0)
            m = out;
        size_t mlen = strlen(m);
        if ((c->len - c->off) + mlen + 1 + len + 1 <= DATA_SOCKET_QUEUE_MAX &&
            enqueue(c, m, mlen, now) == 0) {
            if (enqueue(c, line, len, now) == 0) {
                c->gap = 0;
                c->seq++;
                return;
            }
            c->len -= mlen + 1;                /* unwind the marker */
        }
    } else if (enqueue(c, line, len, now) == 0) {
        c->seq++;
        return;
    }
    c->seq++;
    c->gap++;
    c->dropped++;
    g_dropped_total++;
}

void data_socket_tick(void) {
    if (g_listen_fd < 0) return;
    int accepted = 0;
    pthread_mutex_lock(&g_mu);
    time_t now = g_clock_fn();
    while (g_client_n < MAX_CLIENTS) {
        int c = g_accept_fn(g_listen_fd, NULL, NULL);
        if (c < 0) break;       /* EAGAIN or real error — stop draining */
        set_nonblock(c);
        /* Keepalive helps the kernel reap iOS clients that vanish when
         * the device sleeps. No-op on UNIX-domain (setsockopt accepts
         * but ignores it for AF_UNIX). */
        int one = 1;
        setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        memset(&g_clients[g_client_n], 0, sizeof(g_clients[0]));
        g_clients[g_client_n].fd       = c;
        g_clients[g_client_n].progress = now;
        g_client_n++;
        accepted++;
    }

    /* Queued bytes also drain here, so a quiet stream still finishes
     * the records it started. A client holding bytes the kernel has
     * refused for DATA_SOCKET_STALL_SECS is closed: a peer that stops
     * reading can hold a TCP window at zero indefinitely without ever
     * producing EPIPE, and its queue would sit full forever. */
    int i = 0;
    while (i < g_client_n) {
        if (flush_client(i, now) < 0) continue;
        ds_client_t *c = &g_clients[i];
        if (c->off < c->len && now - c->progress >= DATA_SOCKET_STALL_SECS) {
            drop_client(i);
            continue;
        }
        i++;
    }
    pthread_mutex_unlock(&g_mu);

    /* A newly accepted client is a fresh sink, exactly like a reopened
     * file — so it needs the same full baseline jsonl_open() grants.
     * Without this the client sees only entities that happen to change
     * after it connects; steady-state rows stay invisible until their
     * next heartbeat (#47).
     *
     * Only on an actual accept: resetting every tick would re-emit the
     * whole baseline continuously and undo #42. The reset is outside
     * g_mu — jsonl has its own lock and emit_line() releases it before
     * calling data_socket_emit(), so neither direction nests. */
    if (accepted) jsonl_dedup_reset();
}

void data_socket_emit(const char *line) {
    if (g_listen_fd < 0 || !line) return;
    size_t len = strlen(line);
    if (len == 0) return;

    pthread_mutex_lock(&g_mu);
    time_t now = g_clock_fn();
    int i = 0;
    while (i < g_client_n) {
        /* Flush first: space freed now is space the new record can use
         * instead of being dropped. */
        if (flush_client(i, now) < 0) continue;
        offer(&g_clients[i], line, len, now);
        if (flush_client(i, now) < 0) continue;
        i++;
    }
    pthread_mutex_unlock(&g_mu);
}

int data_socket_has_clients(void) {
    if (g_listen_fd < 0) return 0;
    pthread_mutex_lock(&g_mu);
    int ok = (g_client_n > 0);
    pthread_mutex_unlock(&g_mu);
    return ok;
}

void data_socket_cleanup(void) {
    pthread_mutex_lock(&g_mu);
    while (g_client_n > 0) drop_client(g_client_n - 1);
    if (g_listen_fd >= 0) {
        close(g_listen_fd);
        g_listen_fd = -1;
    }
    if (g_unix_path[0]) {
        unlink(g_unix_path);
        g_unix_path[0] = '\0';
    }
    pthread_mutex_unlock(&g_mu);
}
