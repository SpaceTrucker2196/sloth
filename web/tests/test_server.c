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
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_assets.h"
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

/* Stop the loop and join its thread, leaving every connection open:
 * after this the test may read the server's sockets without racing it. */
static void halt(running_t *r) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    WT_EQ(r->rc, 0);
}

static void stop(running_t *r, web_stats_t *st) {
    halt(r);
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

/* read_all(), also reporting how the stream ended: 0 for an orderly
 * EOF (the peer's FIN), otherwise the errno of the failing recv(). */
static size_t read_all_end(int fd, char *out, size_t cap, int *end) {
    size_t n = 0;
    *end = 0;
    while (n + 1 < cap) {
        ssize_t r = recv(fd, out + n, cap - 1 - n, 0);
        if (r == 0) break;
        if (r < 0) { *end = errno; break; }
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

    static const char get[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    size_t n = exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
    WT_ASSERT(n > 0);
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    WT_ASSERT(n >= 10 && !strcmp(out + n - 10, "not found\n"));

    static const char head[] = "HEAD /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
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
        int rl = snprintf(req, sizeof(req),
            "%s /api/query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 11\r\n"
            "\r\n{\"sql\":\"x\"}", methods[i]);
        exchange(AF_INET, port, req, (size_t)rl, out, sizeof(out));
        WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
        WT_HAS(out, "Allow: GET, HEAD\r\n");
    }
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_405, 4);
}

/* A body far larger than one recv() is still unread when the answer
 * goes out. Closing then would make the kernel send RST; the half-close
 * and drain end the connection with a FIN instead.
 *
 * What this does NOT show is a response lost to the reset. On Linux the
 * response is already in the client's receive queue when the RST lands,
 * and recv() hands queued data over before reporting ECONNRESET, so the
 * 405 arrives either way (seen: identical with the drain removed). The
 * loss is a property of other stacks and of real links where the RST
 * can overtake retransmitted data, and loopback cannot reproduce it.
 * The assertion is therefore on how the stream ends: seen red
 * (ECONNRESET instead of EOF) with conn_write() closing straight after
 * the send. */
static void test_unread_body_ends_with_fin_not_reset(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    enum { BODY = 64 * 1024 };
    static const char head[] =
        "POST /api/query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 65536\r\n\r\n";
    size_t rl = sizeof(head) - 1 + BODY;
    char *req = malloc(rl);
    memcpy(req, head, sizeof(head) - 1);
    memset(req + sizeof(head) - 1, 'b', BODY);

    int fd = dial(AF_INET, web_server_port(r.s));
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        send_all(fd, req, rl);
        char out[4096];
        int end = -1;
        read_all_end(fd, out, sizeof(out), &end);
        close(fd);
        WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
        WT_EQ(end, 0);
    }
    free(req);
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_405, 1);
}

/* [::] must not quietly become dual-stack on a host whose
 * net.ipv6.bindv6only is 0 (the Linux default). Checked on the unbound
 * socket: binding [::] here would open a port on every interface, and
 * binding [::1] proves nothing because Linux sets V6ONLY itself on a
 * bind to a specific v6 address (seen: the open-and-read-back version
 * of this test stayed green with the setsockopt removed). This one was
 * seen red (0) with the setsockopt removed. */
static void test_v6_listener_is_v6only(void) {
    char err[128];
    int fd = web_server_socket(AF_INET6, err, sizeof(err));
    WT_ASSERT(fd >= 0);
    if (fd < 0) return;
    int v = -1;
    socklen_t vl = sizeof(v);
    WT_EQ(getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, &vl), 0);
    WT_EQ(v, 1);
    close(fd);
}

static double cpu_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

/* accept() failing with EMFILE leaves the peer in the backlog and the
 * listener readable. The server must back off rather than spin, and must
 * serve the waiting peer once descriptors free up. The process's own
 * descriptor table is filled (under a lowered soft limit) after the
 * client has dialled, so the server thread's accept() is the call that
 * fails. Seen red (~300 ms of CPU in a 300 ms window) with the
 * back-off in accept_ready() removed. */
static void test_accept_emfile_backs_off(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);

    struct rlimit old;
    WT_EQ(getrlimit(RLIMIT_NOFILE, &old), 0);
    int probe = dup(0);
    WT_ASSERT(probe >= 0);
    if (probe < 0) { web_stats_t st; stop(&r, &st); return; }
    close(probe);
    struct rlimit low = old;
    low.rlim_cur = (rlim_t)probe + 64;
    if (low.rlim_cur > old.rlim_cur) low.rlim_cur = old.rlim_cur;
    WT_EQ(setrlimit(RLIMIT_NOFILE, &low), 0);

    enum { MAXFILL = 4096 };
    static int fill[MAXFILL];
    int nfill = 0;
    while (nfill < MAXFILL) {
        int d = dup(0);
        if (d < 0) break;
        fill[nfill++] = d;
    }
    WT_ASSERT(nfill > 0);
    if (nfill > 0) close(fill[--nfill]);      /* exactly one slot, for the client */
    int fd = dial(AF_INET, port);
    WT_ASSERT(fd >= 0);
    WT_ASSERT(dup(0) < 0);                    /* the table is full */

    double c0 = cpu_ms();
    struct timespec ts = { 0, 300 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    double used = cpu_ms() - c0;

    web_stats_t mid;
    web_server_stats(r.s, &mid);
    while (nfill > 0) close(fill[--nfill]);
    WT_EQ(setrlimit(RLIMIT_NOFILE, &old), 0);

    WT_ASSERT(mid.accept_paused >= 1);
    WT_EQ(mid.accepted, 0);
    if (used >= 100.0)
        fprintf(stderr, "    accept back-off: %.0f ms CPU in 300 ms\n", used);
    WT_ASSERT(used < 100.0);

    if (fd >= 0) {
        static const char get[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        send_all(fd, get, sizeof(get) - 1);
        char out[4096];
        read_all(fd, out, sizeof(out));
        close(fd);
        WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    }
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.accepted, 1);
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
    static const char head[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\nX: ";
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
    static const char get[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
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
    static const char get[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
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
 * list but closed as busy, and the server recovers once they go.
 *
 * Waits on the server's own counters, not a fixed sleep: under load
 * (parallel ASan runs) a 100 ms nap did not cover the accepts, and a
 * 300 ms idle timeout freed a slot before the extra peer arrived, so
 * it was served (n 219, busy 0). The timeout is now well past every
 * wait here, and recovery is retried until it shows. */
static void test_slots_exhausted(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.timeout_ms = 5000;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    int fds[WEB_MAX_CONNS];
    for (int i = 0; i < WEB_MAX_CONNS; i++) fds[i] = dial(AF_INET, port);
    web_stats_t st;
    long long t0 = mono_ms();
    do {
        web_server_stats(r.s, &st);
        if (st.accepted >= WEB_MAX_CONNS) break;
        struct timespec ts = { 0, 2 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    } while (mono_ms() - t0 < 3000);
    WT_EQ(st.accepted, WEB_MAX_CONNS);
    WT_EQ(st.busy, 0);
    char out[1024];
    static const char get[] = "GET /nope HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    size_t n = exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
    WT_EQ(n, 0);
    /* The loop closes the extra peer before it counts it. */
    t0 = mono_ms();
    do {
        web_server_stats(r.s, &st);
        if (st.busy) break;
        struct timespec ts = { 0, 2 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    } while (mono_ms() - t0 < 1000);
    WT_EQ(st.busy, 1);
    for (int i = 0; i < WEB_MAX_CONNS; i++) if (fds[i] >= 0) close(fds[i]);
    /* The loop frees the slots as it reads each EOF; until it has, a
     * peer is busy again, which is not what is under test here. */
    t0 = mono_ms();
    do {
        exchange(AF_INET, port, get, sizeof(get) - 1, out, sizeof(out));
        if (strstr(out, "HTTP/1.1 404 Not Found\r\n")) break;
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    } while (mono_ms() - t0 < 3000);
    WT_HAS(out, "HTTP/1.1 404 Not Found\r\n");
    stop(&r, &st);
    WT_ASSERT(st.busy >= 1);
    WT_EQ(st.refused, 0);
}

/* ── M0 routes over a real connection (#158) ──────────────────────────── */

/* Read from fd into buf (NUL-terminated, appending at *len) until needle
 * appears or ms pass. 1 when it appeared. */
static int wait_for(int fd, char *buf, size_t cap, size_t *len,
                    const char *needle, int ms) {
    long long end = mono_ms() + ms;
    for (;;) {
        buf[*len] = '\0';
        if (strstr(buf, needle)) return 1;
        long long left = end - mono_ms();
        if (left <= 0 || *len + 1 >= cap) return 0;
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, (int)left) <= 0) continue;
        ssize_t r = recv(fd, buf + *len, cap - 1 - *len, 0);
        if (r <= 0) { buf[*len] = '\0'; return strstr(buf, needle) != NULL; }
        *len += (size_t)r;
    }
}

static const char *ci_strstr(const char *h, const char *n) {
    size_t nl = strlen(n);
    for (; *h; h++) {
        size_t k = 0;
        while (k < nl && h[k] &&
               (h[k] | 0x20) == (n[k] | 0x20))
            k++;
        if (k == nl) return h;
    }
    return NULL;
}

/* Wait until the server's stats satisfy pred, or ms pass. */
static int wait_stats(web_server_t *s, int (*pred)(const web_stats_t *),
                      int ms, web_stats_t *st) {
    long long end = mono_ms() + ms;
    for (;;) {
        web_server_stats(s, st);
        if (pred(st)) return 1;
        if (mono_ms() >= end) return 0;
        struct timespec ts = { 0, 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
}

static int one_closed(const web_stats_t *st)  { return st->sse_closed >= 1; }
static int one_dropped(const web_stats_t *st) { return st->sse_dropped >= 1; }

static void get(uint16_t port, const char *path, const char *extra,
                char *out, size_t cap) {
    char req[512];
    int n = snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%s\r\n",
                     path, extra);
    exchange(AF_INET, port, req, (size_t)n, out, cap);
}

/* The page as the browser gets it: every byte of the embedded array, an
 * ETag that turns the next load into a 304, and no URL anywhere in the
 * response (spec §12, M0 acceptance; test_routes.c has the full list
 * and the mutations it was seen red under). */
static void test_page_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    size_t cap = web_page_len + 8192;
    char *out = malloc(cap);

    get(port, "/", "", out, cap);
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    char *body = strstr(out, "\r\n\r\n");
    WT_ASSERT(body != NULL);
    if (body) {
        body += 4;
        WT_EQ(strlen(body), web_page_len);
        WT_ASSERT(!memcmp(body, web_page, web_page_len));
    }
    WT_ASSERT(ci_strstr(out, "http://") == NULL);
    WT_ASSERT(ci_strstr(out, "https://") == NULL);

    char inm[128];
    snprintf(inm, sizeof(inm), "If-None-Match: %s\r\n", web_page_etag);
    get(port, "/", inm, out, cap);
    WT_HAS(out, "HTTP/1.1 304 Not Modified\r\n");
    body = strstr(out, "\r\n\r\n");
    WT_ASSERT(body && body[4] == '\0');

    static const char head[] = "HEAD / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    size_t n = exchange(AF_INET, port, head, sizeof(head) - 1, out, cap);
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    WT_ASSERT(n >= 4 && !strcmp(out + n - 4, "\r\n\r\n"));
    free(out);

    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_200, 2);
    WT_EQ(st.status_304, 1);
    WT_EQ(st.served, 3);
}

static void test_health_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    char out[4096];
    get(web_server_port(r.s), "/api/health", "", out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    WT_HAS(out, "Content-Type: application/json\r\n");
    WT_HAS(out, "\r\n\r\n{\"service\":\"slothweb\",\"milestone\":\"M5\",");
    WT_HAS(out, "\"sse_clients\":0,");
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_200, 1);
}

/* Every "id: N" line in buf, in order, must count up by one: ticks are
 * neither skipped nor sent twice to one client. Returns the count. */
static int ids_in_order(const char *buf, long *last) {
    int n = 0;
    long prev = -1;
    for (const char *p = buf; (p = strstr(p, "\nid: ")) != NULL; p++) {
        long v = strtol(p + 5, NULL, 10);
        if (prev >= 0 && v != prev + 1) {
            fprintf(stderr, "    id %ld after %ld\n", v, prev);
            return -1;
        }
        prev = v;
        n++;
    }
    *last = prev;
    return n;
}

/* A stream: the headers, the retry hint, a tick at once and then one per
 * tick_ms with consecutive ids, and the keep-alive comment. The client
 * then leaves mid-stream; the server notices, frees the slot and stops
 * counting it. Seen red ("sse_clients":1 after the close) with the
 * sse_count decrement removed from conn_close(). */
static void test_events_stream_ticks_and_pings(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.tick_ms = 50;
    c.ping_ms = 130;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);

    int fd = dial(AF_INET, port);
    WT_ASSERT(fd >= 0);
    if (fd < 0) { web_stats_t st; stop(&r, &st); return; }
    static const char ev[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                             "Accept: text/event-stream\r\n\r\n";
    send_all(fd, ev, sizeof(ev) - 1);
    static char buf[65536];
    size_t len = 0;
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, "\r\n\r\nretry: 3000\n\n", 2000));
    WT_HAS(buf, "HTTP/1.1 200 OK\r\n");
    WT_HAS(buf, "Content-Type: text/event-stream; charset=utf-8\r\n");
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, "event: tick\n", 2000));
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, ": ping\n\n", 3000));
    /* Four ticks after the ping is due, so at least five in all. */
    long last = -1;
    long long end = mono_ms() + 3000;
    while (mono_ms() < end) {
        wait_for(fd, buf, sizeof(buf), &len, "\x01", 60);   /* just read */
        if (ids_in_order(buf, &last) >= 5) break;
    }
    int nids = ids_in_order(buf, &last);
    WT_ASSERT(nids >= 5);
    WT_HAS(buf, "\"sse_clients\":1}");

    char out[4096];
    get(port, "/api/health", "", out, sizeof(out));
    WT_HAS(out, "\"sse_clients\":1,");

    close(fd);
    web_stats_t st;
    WT_ASSERT(wait_stats(r.s, one_closed, 2000, &st));
    get(port, "/api/health", "", out, sizeof(out));
    WT_HAS(out, "\"sse_clients\":0,");

    stop(&r, &st);
    WT_EQ(st.sse_opened, 1);
    WT_EQ(st.sse_closed, 1);
    WT_EQ(st.sse_dropped, 0);
    WT_ASSERT(st.ticks >= 4);
}

/* A client that opens a stream and never reads is dropped once
 * WEB_SSE_MAX_UNSENT bytes are waiting for it, instead of being
 * buffered for without bound; the server carries on. A 1 ms tick fills
 * the kernel buffers (the server's SO_SNDBUF is capped, the client's
 * receive buffer is shrunk before connect) and then ours. Seen red
 * (sse_dropped 0 after 20 s) with sse_queue() discarding the event
 * instead of dropping the client. */
static void test_slow_events_client_dropped(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.tick_ms = 1;
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int small = 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(connect(fd, (struct sockaddr *)&a, sizeof(a)), 0);
    static const char ev[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    send_all(fd, ev, sizeof(ev) - 1);

    web_stats_t st;
    WT_ASSERT(wait_stats(r.s, one_dropped, 20000, &st));
    /* The drop happens at the threshold, not somewhere past it: what was
     * waiting is within one event (well under 256 bytes) of
     * WEB_SSE_MAX_UNSENT and not over it. Seen red (a backlog of
     * ~262000) with the threshold in sse_queue() raised to four times
     * WEB_SSE_MAX_UNSENT, a mutant that also writes past out[] into the
     * next slot unseen by ASan; the typedef in web_server.c is what
     * stops out[] shrinking below the threshold (seen: a compile error
     * with out[] halved). */
    if (st.sse_drop_backlog > WEB_SSE_MAX_UNSENT)
        fprintf(stderr, "    dropped with %lu unsent\n", st.sse_drop_backlog);
    WT_ASSERT(st.sse_drop_backlog <= WEB_SSE_MAX_UNSENT);
    WT_ASSERT(st.sse_drop_backlog > WEB_SSE_MAX_UNSENT - 256);

    char out[4096];
    get(port, "/api/health", "", out, sizeof(out));
    WT_HAS(out, "\"sse_clients\":0,");
    close(fd);

    stop(&r, &st);
    WT_EQ(st.sse_opened, 1);
    WT_EQ(st.sse_dropped, 1);
    WT_EQ(st.sse_closed, 0);
}

/* Open a stream with tick and ping a minute away, so nothing the loop
 * does on a timer can be mistaken for what is being tested. Returns the
 * client fd with the stream's first bytes in buf, or -1. */
static int open_quiet_stream(running_t *r, char *buf, size_t cap,
                             size_t *len) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.tick_ms = 60000;
    c.ping_ms = 60000;
    if (start(r, &c) != 0 || !r->s) return -1;
    int fd = dial(AF_INET, web_server_port(r->s));
    if (fd < 0) return -1;
    static const char ev[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    send_all(fd, ev, sizeof(ev) - 1);
    *len = 0;
    if (!wait_for(fd, buf, cap, len, "retry: 3000\n\n", 2000)) {
        close(fd);
        return -1;
    }
    return fd;
}

/* A new stream gets the current tick at once rather than a minute
 * later. Seen red (no tick in the window) with the initial
 * sse_queue() removed from conn_route(). The stream's socket also
 * carries the options the server sets: TCP_NODELAY (seen red, 0, with
 * its setsockopt removed from accept_ready()) and the capped SO_SNDBUF,
 * compared against what this kernel grants for the same request,
 * because Linux doubles the value it is given (seen red, the kernel's
 * default instead, with that setsockopt removed from conn_route()). */
static void test_events_first_tick_at_once(void) {
    running_t r;
    char buf[4096];
    size_t len;
    int fd = open_quiet_stream(&r, buf, sizeof(buf), &len);
    WT_ASSERT(fd >= 0);
    if (fd < 0) { if (r.s) { web_stats_t st; stop(&r, &st); } return; }
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, "event: tick\n", 500));
    WT_HAS(buf, "retry: 3000\n\nid: 0\nevent: tick\n");

    halt(&r);
    int sfd = -1, nopen = 0;
    for (int i = 0; i < WEB_MAX_CONNS; i++)
        if (r.s->conns[i].fd >= 0) { sfd = r.s->conns[i].fd; nopen++; }
    WT_EQ(nopen, 1);
    if (sfd >= 0) {
        int v = -1;
        socklen_t vl = sizeof(v);
        WT_EQ(getsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &v, &vl), 0);
        WT_ASSERT(v != 0);

        int probe = socket(AF_INET, SOCK_STREAM, 0);
        int want = WEB_SSE_SNDBUF, granted = -1, got = -2;
        setsockopt(probe, SOL_SOCKET, SO_SNDBUF, &want, sizeof(want));
        vl = sizeof(granted);
        getsockopt(probe, SOL_SOCKET, SO_SNDBUF, &granted, &vl);
        close(probe);
        vl = sizeof(got);
        WT_EQ(getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &got, &vl), 0);
        WT_EQ(got, granted);
    }
    web_stats_t st;
    web_server_stats(r.s, &st);
    web_server_close(r.s);
    free(r.s);
    close(fd);
    WT_EQ(st.sse_opened, 1);
    WT_EQ(st.ticks, 0);
}

/* A stream client that leaves is noticed on the read side, at once,
 * not when the next event fails to send. With no event due for a
 * minute, only the read path can see it. Seen red (sse_closed 0 at the
 * deadline) with conn_close() removed from conn_read()'s stream EOF
 * branch; that mutant also spins, the closed socket staying readable. */
static void test_events_client_eof_noticed_on_read(void) {
    running_t r;
    char buf[4096];
    size_t len;
    int fd = open_quiet_stream(&r, buf, sizeof(buf), &len);
    WT_ASSERT(fd >= 0);
    if (fd < 0) { if (r.s) { web_stats_t st; stop(&r, &st); } return; }
    close(fd);
    web_stats_t st;
    WT_ASSERT(wait_stats(r.s, one_closed, 1000, &st));
    char out[4096];
    get(web_server_port(r.s), "/api/health", "", out, sizeof(out));
    WT_HAS(out, "\"sse_clients\":0,");
    stop(&r, &st);
    WT_EQ(st.sse_closed, 1);
    WT_EQ(st.sse_dropped, 0);
    WT_EQ(st.ticks, 0);
}

/* DNS rebinding over a real connection: what curl -H 'Host:
 * attacker.example' -H 'Origin: http://attacker.example' got before the
 * Host check (a 200 with the health JSON) is now a 421 with nothing of
 * slothweb's in it, on every route, while a writing method is still
 * the same 405. Seen red with the web_http_host_ok() test removed from
 * web_route(). */
static void test_foreign_host_refused_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    static const char *const paths[] = { "/", "/api/health", "/events" };
    for (size_t i = 0; i < 3; i++) {
        char req[256], out[4096];
        int rl = snprintf(req, sizeof(req),
            "GET %s HTTP/1.1\r\nHost: attacker.example:%u\r\n"
            "Origin: http://attacker.example:%u\r\n\r\n",
            paths[i], (unsigned)port, (unsigned)port);
        exchange(AF_INET, port, req, (size_t)rl, out, sizeof(out));
        WT_HAS(out, "HTTP/1.1 421 Misdirected Request\r\n");
        WT_LACKS(out, "slothweb");
        WT_LACKS(out, "event:");
        WT_LACKS(out, "Access-Control");
    }
    char out[4096];
    static const char post[] = "POST /api/health HTTP/1.1\r\n"
                               "Host: attacker.example\r\n\r\n";
    exchange(AF_INET, port, post, sizeof(post) - 1, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
    static const char nohost[] = "GET /api/health HTTP/1.1\r\n\r\n";
    exchange(AF_INET, port, nohost, sizeof(nohost) - 1, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 400 Bad Request\r\n");

    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_421, 3);
    WT_EQ(st.status_405, 1);
    WT_EQ(st.status_400, 1);
    WT_EQ(st.status_200, 0);
    WT_EQ(st.sse_opened, 0);
}

/* Streams may hold WEB_MAX_SSE slots, not all of them: the next stream
 * is refused 503 while the page can still be loaded. */
static void test_events_slots_capped(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    static const char ev[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    int fds[WEB_MAX_SSE];
    int opened = 0;
    for (int i = 0; i < WEB_MAX_SSE; i++) {
        fds[i] = dial(AF_INET, port);
        if (fds[i] < 0) continue;
        send_all(fds[i], ev, sizeof(ev) - 1);
        char buf[1024];
        size_t len = 0;
        opened += wait_for(fds[i], buf, sizeof(buf), &len, "retry: ", 2000);
    }
    WT_EQ(opened, WEB_MAX_SSE);

    char out[8192];
    exchange(AF_INET, port, ev, sizeof(ev) - 1, out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 503 Service Unavailable\r\n");
    get(port, "/api/health", "", out, sizeof(out));
    WT_HAS(out, "HTTP/1.1 200 OK\r\n");
    char want[32];
    snprintf(want, sizeof(want), "\"sse_clients\":%d,", WEB_MAX_SSE);
    WT_HAS(out, want);

    for (int i = 0; i < WEB_MAX_SSE; i++) if (fds[i] >= 0) close(fds[i]);
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.sse_opened, WEB_MAX_SSE);
    WT_EQ(st.status_503, 1);
}

/* The routes add nothing a writing method can reach. */
/* The anomaly push end to end: an engine attached before the loop
 * runs, a stream client, then an episode that opens. It reaches the
 * client as one "event: anomaly" within a tick, and is counted once
 * however many ticks pass. Seen red with the send_anomalies() call
 * removed from run_timers(). */
static void test_events_carry_anomalies(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    c.tick_ms = 50;
    web_baseline_t bl;
    web_anomaly_t an;
    WT_EQ(web_baseline_init(&bl, 4), 0);
    web_anom_cfg_t ac;
    memset(&ac, 0, sizeof(ac));
    ac.bl = &bl;
    ac.max_keys = 16;
    WT_EQ(web_anomaly_init(&an, 4, &ac), 0);
    running_t r;
    char err[256];
    r.s = calloc(1, sizeof(*r.s));
    WT_ASSERT(r.s != NULL);
    if (!r.s) return;
    WT_EQ(web_server_open(r.s, &c, err, sizeof(err)), 0);
    web_server_set_anomaly(r.s, &an);
    WT_EQ(pthread_create(&r.th, NULL, server_main, &r), 0);

    int fd = dial(AF_INET, web_server_port(r.s));
    WT_ASSERT(fd >= 0);
    web_stats_t st;
    if (fd < 0) {
        stop(&r, &st);
        web_anomaly_destroy(&an);
        web_baseline_destroy(&bl);
        return;
    }
    static const char ev[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    send_all(fd, ev, sizeof(ev) - 1);
    static char buf[65536];
    size_t len = 0;
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, "event: tick\n", 2000));
    WT_LACKS(buf, "event: anomaly\n");
    /* As the engine opens one: under its lock, with a new seq. */
    pthread_mutex_lock(&an.mu);
    an.ep[0] = (web_anom_ep_t){ .id = 7, .state = WEB_EP_OPEN,
        .rule = WEB_ANOM_A6_NAMES, .metric = -1, .key = "10.0.0.9",
        .score = 40, .peak = 40, .evidence = "names disagree",
        .first_seen = 1792627200, .last_seen = 1792627200 };
    an.ep[0].seq = ++an.seq;
    pthread_mutex_unlock(&an.mu);
    WT_ASSERT(wait_for(fd, buf, sizeof(buf), &len, "\"key\":\"10.0.0.9\"", 2000));
    WT_HAS(buf, "event: anomaly\ndata: {\"id\":7,\"rule\":\"A6\"");
    /* Several ticks more: still one. */
    wait_for(fd, buf, sizeof(buf), &len, "\x01", 300);
    close(fd);
    stop(&r, &st);
    WT_EQ(st.anomalies_sent, 1UL);
    web_anomaly_destroy(&an);
    web_baseline_destroy(&bl);
}

static void test_routes_405_for_writes_over_socket(void) {
    web_config_t c;
    base_cfg(&c, AF_INET);
    running_t r;
    WT_EQ(start(&r, &c), 0);
    if (!r.s) return;
    uint16_t port = web_server_port(r.s);
    static const char *const paths[] = { "/", "/api/health", "/events" };
    for (size_t i = 0; i < 3; i++) {
        char req[256], out[4096];
        int rl = snprintf(req, sizeof(req),
            "POST %s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\n{}",
            paths[i]);
        exchange(AF_INET, port, req, (size_t)rl, out, sizeof(out));
        WT_HAS(out, "HTTP/1.1 405 Method Not Allowed\r\n");
        WT_HAS(out, "Allow: GET, HEAD\r\n");
    }
    web_stats_t st;
    stop(&r, &st);
    WT_EQ(st.status_405, 3);
    WT_EQ(st.status_200, 0);
    WT_EQ(st.sse_opened, 0);
}

void run_server_tests(void) {
    WT_RUN(test_open_binds_loopback_by_default);
    WT_RUN(test_open_refuses_remote_bind);
    WT_RUN(test_get_head_404_over_socket);
    WT_RUN(test_write_methods_405_over_socket);
    WT_RUN(test_unread_body_ends_with_fin_not_reset);
    WT_RUN(test_v6_listener_is_v6only);
    WT_RUN(test_accept_emfile_backs_off);
    WT_RUN(test_oversize_header_431_over_socket);
    WT_RUN(test_refused_peer_v4);
    WT_RUN(test_refused_peer_v6);
    WT_RUN(test_admitted_peer_v6);
    WT_RUN(test_idle_client_times_out);
    WT_RUN(test_slow_client_times_out);
    WT_RUN(test_slots_exhausted);
    WT_RUN(test_page_over_socket);
    WT_RUN(test_health_over_socket);
    WT_RUN(test_events_stream_ticks_and_pings);
    WT_RUN(test_slow_events_client_dropped);
    WT_RUN(test_events_first_tick_at_once);
    WT_RUN(test_events_client_eof_noticed_on_read);
    WT_RUN(test_foreign_host_refused_over_socket);
    WT_RUN(test_events_slots_capped);
    WT_RUN(test_routes_405_for_writes_over_socket);
    WT_RUN(test_events_carry_anomalies);
}
