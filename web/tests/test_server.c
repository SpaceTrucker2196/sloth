/* The listener over real sockets: loopback only, ephemeral ports only,
 * the server on its own thread and the test as the client.
 *
 * A test cannot originate from a non-loopback address, so "a peer
 * outside the list is refused" is driven by narrowing the list instead:
 * 127.0.0.1 and ::1 are real peers, and a list that leaves them out
 * must close them at accept() exactly as it would close 192.168.1.5.
 * test_acl.c covers the non-loopback addresses themselves. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_server.h"
#include "wtest.h"

typedef struct {
    web_server_t *s;
    pthread_t     th;
    int           rc;
} running_t;

static void *server_main(void *arg) {
    running_t *r = arg;
    r->rc = web_server_run(r->s);
    return NULL;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* An ephemeral loopback config. */
static void base_cfg(web_config_t *c, int family) {
    web_config_defaults(c);
    c->bind_port = 0;
    if (family == AF_INET6) {
        c->bind_family = AF_INET6;
        memset(c->bind_addr, 0, 16);
        c->bind_addr[15] = 1;
    }
    c->timeout_ms = 2000;
    c->linger_ms  = 200;
}

static int start(running_t *r, const web_config_t *cfg) {
    char err[256];
    r->s = calloc(1, sizeof(*r->s));
    if (!r->s) return -1;
    if (web_server_open(r->s, cfg, err, sizeof(err)) != 0) {
        fprintf(stderr, "    open failed: %s\n", err);
        web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    if (pthread_create(&r->th, NULL, server_main, r) != 0) {
        web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    return 0;
}

static void stop(running_t *r, web_stats_t *st) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    WT_EQ(r->rc, 0);
    web_server_stats(r->s, st);
    web_server_close(r->s);
    free(r->s);
    r->s = NULL;
}

static int dial(int family, uint16_t port) {
    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int rc;
    if (family == AF_INET6) {
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6;
        a.sin6_port   = htons(port);
        a.sin6_addr   = in6addr_loopback;
        rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family      = AF_INET;
        a.sin_port        = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rc = connect(fd, (struct sockaddr *)&a, sizeof(a));
    }
    if (rc != 0) { close(fd); return -1; }
    return fd;
}

static void send_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) return;   /* the server may have answered and closed */
        p += w;
        n -= (size_t)w;
    }
}

/* Read to EOF (or reset, or the 3 s receive timeout). Returns bytes
 * read; out is NUL-terminated. */
static size_t read_all(int fd, char *out, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, out + n, cap - 1 - n, 0);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = '\0';
    return n;
}

/* One request on a fresh connection; the response in out. */
static size_t exchange(int family, uint16_t port, const char *req,
                       size_t reqlen, char *out, size_t cap) {
    out[0] = '\0';
    int fd = dial(family, port);
    if (fd < 0) return 0;
    send_all(fd, req, reqlen);
    size_t n = read_all(fd, out, cap);
    close(fd);
    return n;
}

static void test_open_binds_loopback_by_default(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    WT_ASSERT(web_server_port(r.s) != 0);

    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    WT_EQ(getsockname(r.s->lfd, (struct sockaddr *)&a, &al), 0);
    WT_EQ(a.sin_family, AF_INET);
    WT_EQ(ntohl(a.sin_addr.s_addr), INADDR_LOOPBACK);
    web_stats_t st;
    stop(&r, &st);
}

/* The server re-applies the policy: a caller that builds a config by
 * hand gets the same refusal as the CLI, before socket() is reached.
 * 192.0.2.1 (TEST-NET-1) is not assigned to this host, so if the check
 * were missing the bind itself would fail -- with a different message.
 * The assertion on the message is what tells the two apart; seen red
 * with the web_config_check() call removed from web_server_open(). */
static void test_open_refuses_remote_bind(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.bind_addr[0] = 192; c.bind_addr[1] = 0; c.bind_addr[2] = 2;
    c.bind_addr[3] = 1;
    web_server_t *s = calloc(1, sizeof(*s));
    char err[512] = "";
    WT_EQ(web_server_open(s, &c, err, sizeof(err)), -1);
    WT_HAS(err, "--web-allow-remote");
    WT_EQ(s->lfd, -1);
    web_server_close(s);

    c.allow_remote = 1;
    c.strict = 1;
    err[0] = '\0';
    WT_EQ(web_server_open(s, &c, err, sizeof(err)), -1);
    WT_HAS(err, "--strict");
    WT_EQ(s->lfd, -1);
    web_server_close(s);
    free(s);
}

static void test_get_head_404_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    char out[4096];

    static const char get[] = "GET /api/health HTTP/1.1\r\nHost: x\r\n\r\n";
    size_t n = exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
    WT_ASSERT(n > 0);
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    WT_ASSERT(n >= 10 && !strcmp(out + n - 10, "not found\n"));

    static const char head[] = "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n";
    n = exchange(AF_INET, port, head, sizeof(head) - 1, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    WT_ASSERT(n >= 4 && !strcmp(out + n - 4, "\r\n\r\n"));
    WT_LACKS(out, "not found\n");

    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.accepted, 2);
    WT_EQ(st.refused, 0);
    WT_EQ(st.served, 2);
    WT_EQ(st.status_404, 2);
}

static void test_write_methods_405_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    static const char *const methods[] = { "POST", "PUT", "DELETE", "PATCH" };
    for (size_t i = 0; i < 4; i++) {
        char req[256], out[4096];
        /* With a body nobody reads: the lingering close is what keeps
         * the unread bytes from turning the answer into a reset. */
        int rl = snprintf(req, sizeof(req),
            "%s /api/query HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n"
            "\r\n{\"sql\":\"x\"}", methods[i]);
        exchange(AF_INET, port, req, (size_t)rl, out, sizeof(out));
        WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
        WT_HAS(out, "Allow: GET, HEAD\r\n");
    }
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_405, 4);
}

static void test_oversize_header_431_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);

    size_t big = 3 * WEB_HDR_MAX;
    char *req = malloc(big);
    static const char head[] = "GET / HTTP/1.1\r\nX: ";
    memcpy(req, head, sizeof(head) - 1);
    memset(req + sizeof(head) - 1, 'a', big - (sizeof(head) - 1));
    char out[4096];
    exchange(AF_INET, port, req, big, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 431 Request Header Fields Too Large\r\n");

    /* Exactly WEB_HDR_MAX bytes including the empty line still fits. */
    memset(req, 'a', WEB_HDR_MAX);
    memcpy(req, head, sizeof(head) - 1);
    memcpy(req + WEB_HDR_MAX - 4, "\r\n\r\n", 4);
    exchange(AF_INET, port, req, WEB_HDR_MAX, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    free(req);

    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_431, 1);
    WT_EQ(st.status_404, 1);
}

/* A refused peer is closed before anything is read from or written to
 * it: the client sees the connection end with zero bytes, and the
 * refusal is counted. Seen red (the 404 arrives, refused stays 0) with
 * the web_acl_permits() test in accept_ready() forced true. */
static void refused_case(int family, const char *only) {
    web_config_t c;
    base_cfg(&c, family);
    memset(&c.acl, 0, sizeof(c.acl));
    web_acl_entry_t e;
    char err[128];
    WT_EQ(web_acl_parse_entry(only, &e, err, sizeof(err)), 0);
    WT_EQ(web_acl_add(&c.acl, &e), 0);

    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    char out[4096];
    static const char get[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    size_t n = exchange(family, web_server_port(r.s), get, sizeof(get) - 1,
                        out, sizeof(out));
    WT_EQ(n, 0);
    n = exchange(family, web_server_port(r.s), get, sizeof(get) - 1,
                 out, sizeof(out));
    WT_EQ(n, 0);

    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.refused, 2);
    WT_EQ(st.accepted, 0);
    WT_EQ(st.served, 0);
}

static void test_refused_peer_v4(void) {
    /* 127.0.0.1 connects; only 127.0.0.2 is listed. */
    refused_case(AF_INET, "127.0.0.2");
}

static void test_refused_peer_v6(void) {
    /* ::1 connects; only IPv4 loopback is listed. */
    refused_case(AF_INET6, "127.0.0.0/8");
}

static void test_admitted_peer_v6(void) {
    web_config_t c;
    base_cfg(&c, AF_INET6);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    char out[4096];
    static const char get[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    exchange(AF_INET6, web_server_port(r.s), get, sizeof(get) - 1,
             out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.accepted, 1);
    WT_EQ(st.refused, 0);
}

/* A client that connects and sends nothing is answered 408 and closed
 * once the budget runs out. */
static void test_idle_client_times_out(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.timeout_ms = 200;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    int fd = dial(AF_INET, web_server_port(r.s));
    WT_ASSERT(fd >= 0);
    if (fd < 0) { web_stats_t st; stop(&r, &st); return; }
    long long t0 = mono_ms();
    char out[1024];
    read_all(fd, out, sizeof(out));
    long long dt = mono_ms() - t0;
    close(fd);
    WT_HAS(out, "HTTP/1.1 408 Request Timeout\r\n");
    WT_ASSERT(dt >= 150 && dt < 2000);
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.timeouts, 1);
    WT_EQ(st.served, 0);
}

/* A client trickling one header byte every 40 ms never completes the
 * block. The budget is absolute from accept(), so it is cut off at
 * ~200 ms although bytes keep arriving. Seen red with the deadline
 * reset on every successful recv() in conn_read(): the client then
 * keeps the connection alive for its whole 1.5 s run. */
static void test_slow_client_times_out(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.timeout_ms = 200;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    int fd = dial(AF_INET, web_server_port(r.s));
    WT_ASSERT(fd >= 0);
    if (fd < 0) { web_stats_t st; stop(&r, &st); return; }
    long long t0 = mono_ms();
    send_all(fd, "GET / HTTP/1.1\r\n", 16);
    int got = 0;
    while (mono_ms() - t0 < 1500) {
        if (send(fd, "a", 1, MSG_NOSIGNAL) != 1) break;
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 40) > 0) { got = 1; break; }
    }
    char out[1024];
    read_all(fd, out, sizeof(out));
    long long dt = mono_ms() - t0;
    close(fd);
    WT_ASSERT(got);
    WT_HAS(out, "HTTP/1.1 408 Request Timeout\r\n");
    WT_ASSERT(dt < 1000);
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.timeouts, 1);
}

/* Every slot held by an idle client: the next peer is admitted by the
 * list but closed as busy, and the server recovers once they time out. */
static void test_slots_exhausted(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.timeout_ms = 300;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    int fds[WEB_MAX_CONNS];
    for (int i = 0; i < WEB_MAX_CONNS; i++) fds[i] = dial(AF_INET, port);
    /* Give the loop time to accept all of them into slots. */
    struct timespec ts = { 0, 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    char out[1024];
    static const char get[] = "GET / HTTP/1.1\r\n\r\n";
    size_t n = exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
    WT_EQ(n, 0);
    for (int i = 0; i < WEB_MAX_CONNS; i++) if (fds[i] >= 0) close(fds[i]);
    nanosleep(&ts, NULL);
    exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.busy, 1);
    WT_EQ(st.refused, 0);
}

void run_server_tests(void) {
    WT_RUN(test_open_binds_loopback_by_default);
    WT_RUN(test_open_refuses_remote_bind);
    WT_RUN(test_get_head_404_over_socket);
    WT_RUN(test_write_methods_405_over_socket);
    WT_RUN(test_oversize_header_431_over_socket);
    WT_RUN(test_refused_peer_v4);
    WT_RUN(test_refused_peer_v6);
    WT_RUN(test_admitted_peer_v6);
    WT_RUN(test_idle_client_times_out);
    WT_RUN(test_slow_client_times_out);
    WT_RUN(test_slots_exhausted);
}
