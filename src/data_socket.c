/* Read-only JSONL data socket. See data_socket.h for the contract.
 *
 * Locking: a single mutex protects the listening fd, the client array,
 * and the bookkeeping path. Callers (the main poll loop's tick, the
 * jsonl.c emit_line path) are short and never block inside the
 * critical section — all socket I/O is non-blocking. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "data_socket.h"
#include "jsonl.h"

#define MAX_CLIENTS  16

static int             g_listen_fd = -1;
static int             g_clients[MAX_CLIENTS];
static int             g_client_n  = 0;
static char            g_unix_path[256];     /* for cleanup unlink */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Syscall indirection. Default to the real libc functions; tests can
 * swap in fakes via data_socket_test_set_*_fn. One predictable branch
 * per call in production. */
static data_socket_send_fn   g_send_fn   = send;
static data_socket_accept_fn g_accept_fn = accept;

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

void data_socket_tick(void) {
    if (g_listen_fd < 0) return;
    int accepted = 0;
    pthread_mutex_lock(&g_mu);
    while (g_client_n < MAX_CLIENTS) {
        int c = g_accept_fn(g_listen_fd, NULL, NULL);
        if (c < 0) break;       /* EAGAIN or real error — stop draining */
        set_nonblock(c);
        /* Keepalive helps the kernel reap iOS clients that vanish when
         * the device sleeps. No-op on UNIX-domain (setsockopt accepts
         * but ignores it for AF_UNIX). */
        int one = 1;
        setsockopt(c, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
        g_clients[g_client_n++] = c;
        accepted++;
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
    int i = 0;
    while (i < g_client_n) {
        /* Write the line + a trailing '\n'. MSG_NOSIGNAL prevents
         * SIGPIPE if the peer has closed; we detect that as EPIPE
         * from send() instead. */
        ssize_t n1 = g_send_fn(g_clients[i], line, len, MSG_NOSIGNAL);
        int ok = (n1 == (ssize_t)len);
        if (ok) {
            ssize_t n2 = g_send_fn(g_clients[i], "\n", 1, MSG_NOSIGNAL);
            ok = (n2 == 1);
        }
        if (!ok) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* Slow client — drop this line for them. The next
                 * emit retries; if they're chronically slow they'll
                 * eventually get their connection reset by EPIPE. */
                i++;
                continue;
            }
            /* Broken pipe, reset, or any other unrecoverable: close
             * and compact. Swap-with-last to avoid a memmove. */
            close(g_clients[i]);
            g_clients[i] = g_clients[--g_client_n];
            continue;
        }
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
    for (int i = 0; i < g_client_n; i++) close(g_clients[i]);
    g_client_n = 0;
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
