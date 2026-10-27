/* The data-socket client over real sockets: a unix socket in a fresh
 * temporary directory, or a loopback TCP port, with the test playing
 * sloth. The fake writes hand-written JSONL in the order and shape
 * src/jsonl.c does, including the lines a socket can deliver that
 * sloth would not: truncated, overlong, invalid UTF-8, hostile.
 *
 * The test thread is the fake sloth; the ingest thread is the client;
 * where HTTP is involved the server runs on a third thread. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "web_ingest.h"
#include "web_live.h"
#include "web_server.h"
#include "wtest.h"

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nap(int ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static web_live_t   g_live;
static web_ingest_t g_ing;

/* ── the fake sloth's end ─────────────────────────────────────────── */

static char g_dir[64];
static char g_path[128];

static int tmp_dir(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-test-XXXXXX");
    if (!mkdtemp(g_dir)) return -1;
    snprintf(g_path, sizeof(g_path), "%s/sloth.sock", g_dir);
    return 0;
}

static void tmp_dir_done(void) {
    unlink(g_path);
    rmdir(g_dir);
}

static int unix_listen(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un u;
    memset(&u, 0, sizeof(u));
    u.sun_family = AF_UNIX;
    snprintf(u.sun_path, sizeof(u.sun_path), "%s", path);
    unlink(path);
    if (bind(fd, (struct sockaddr *)&u, sizeof(u)) < 0 || listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_listen(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof(a);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 8) < 0 ||
        getsockname(fd, (struct sockaddr *)&a, &sl) < 0) {
        close(fd);
        return -1;
    }
    *port = ntohs(a.sin_port);
    return fd;
}

/* accept() within ms, or -1. */
static int accept_within(int lfd, int ms) {
    struct pollfd p = { lfd, POLLIN, 0 };
    if (poll(&p, 1, ms) <= 0) return -1;
    return accept(lfd, NULL, NULL);
}

static void put(int fd, const char *s, size_t n) {
    while (n) {
        ssize_t w = send(fd, s, n, MSG_NOSIGNAL);
        if (w <= 0) return;
        s += w;
        n -= (size_t)w;
    }
}

static void puts_fd(int fd, const char *s) { put(fd, s, strlen(s)); }

/* One snapshot batch the way jsonl_emit_state_snapshots() orders it:
 * iface rows, the tables before devices, n device rows (field order of
 * jsonl_emit_devices()), then beacons and sensor_health. host is the
 * hostname every device row carries. */
static void sloth_batch_cut(int fd, int n, long long ts, const char *host,
                            int dns_at);
static void sloth_batch(int fd, int n, long long ts, const char *host) {
    sloth_batch_cut(fd, n, ts, host, -1);
}

/* The same, with one capture-thread dns record landing before device
 * row dns_at, as it can when the capture thread writes mid-pass. */
static void sloth_batch_cut(int fd, int n, long long ts, const char *host,
                            int dns_at) {
    static char b[1 << 20];
    size_t o = 0;
    o += (size_t)snprintf(b + o, sizeof(b) - o,
        "{\"type\":\"iface\",\"ts\":%lld,\"name\":\"lo\",\"rx_bytes\":1,\"tx_bytes\":1,"
        "\"rx_packets\":1,\"tx_packets\":1,\"rx_errors\":0,\"rx_drops\":0,"
        "\"tx_errors\":0,\"tx_drops\":0,\"rx_rate\":0.0,\"tx_rate\":0.0,"
        "\"mtu\":65536,\"speed_mbps\":0}\n"
        "{\"type\":\"arp\",\"ts\":%lld,\"mac\":\"02:00:00:00:00:01\",\"ip\":\"10.0.0.1\","
        "\"iface\":\"eth0\"}\n"
        "{\"type\":\"top_host\",\"ts\":%lld,\"ip\":\"10.0.0.1\",\"hostname\":\"\","
        "\"owner\":\"\",\"first_seen\":1,\"last_seen\":1,\"conn_count\":1,"
        "\"rx_rate\":0.0,\"tx_rate\":0.0,\"rx_bytes\":0,\"tx_bytes\":0}\n",
        ts, ts, ts);
    for (int i = 0; i < n; i++) {
        if (i == dns_at)
            o += (size_t)snprintf(b + o, sizeof(b) - o,
                "{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.9\",\"dst\":\"10.0.0.1\","
                "\"qname\":\"mid-pass.example\",\"qtype\":1,\"rcode\":0,\"answers\":1}\n", ts);
        o += (size_t)snprintf(b + o, sizeof(b) - o,
            "{\"type\":\"device\",\"ts\":%lld,\"mac\":\"02:00:00:00:%02x:%02x\","
            "\"ip\":\"10.0.%d.%d\",\"hostname\":\"%s\",\"vendor\":\"\",\"last_ssid\":\"\","
            "\"is_ap\":0,\"signal_dbm\":-61,\"probe_count\":0,\"sources\":1,"
            "\"last_seen\":%lld,\"risk\":\"low\",\"risk_signals\":0,"
            "\"device_class\":\"unknown\",\"camera_vendor\":\"\",\"camera_model\":\"\","
            "\"setup_mode\":0,\"cam_signals\":0,\"cam_score\":0,\"cam_evidence\":\"\","
            "\"cam_vetoes\":\"\",\"cam_conflict\":0,\"dhcp_prl\":\"\",\"dhcp_vci\":\"\"}\n",
            ts, i / 256, i % 256, i / 256, i % 256, host, ts);
    }
    o += (size_t)snprintf(b + o, sizeof(b) - o,
        "{\"type\":\"beacon\",\"ts\":%lld,\"ssid\":\"<svg onload=alert(1)>\","
        "\"bssid\":\"02:00:00:00:ff:01\",\"signal_dbm\":-50,\"channel\":6}\n"
        "{\"type\":\"sensor_health\",\"ts\":%lld,\"capture_iface\":\"any\","
        "\"monitor_iface\":\"\",\"capture_open\":1,\"capture_running\":1,"
        "\"monitor_open\":0,\"monitor_running\":0,\"scope\":\"none\","
        "\"scope_not_enforced\":0}\n", ts, ts);
    put(fd, b, o);
}

/* ── waiting on the client ────────────────────────────────────────── */

static int wait_sum(int (*pred)(const web_live_sum_t *, long), long arg,
                    int ms, web_live_sum_t *s) {
    long long end = mono_ms() + ms;
    for (;;) {
        web_live_summary(&g_live, s, mono_ms());
        if (pred(s, arg)) return 1;
        if (mono_ms() >= end) return 0;
        nap(2);
    }
}

static int is_connected(const web_live_sum_t *s, long a) {
    (void)a;
    return s->sock_state == WEB_SOCK_CONNECTED;
}
static int has_devices(const web_live_sum_t *s, long n) {
    return s->dev_known && !s->dev_stale && s->devices == n;
}
static int has_records(const web_live_sum_t *s, long n) {
    return s->records >= (unsigned long long)n;
}

static unsigned long live_ul(const unsigned long *field) {
    pthread_mutex_lock(&g_live.mu);
    unsigned long v = *field;
    pthread_mutex_unlock(&g_live.mu);
    return v;
}

static int start_unix(int bmin, int bmax) {
    web_sockspec_t sp;
    char err[256];
    char spec[160];
    snprintf(spec, sizeof(spec), "unix:%s", g_path);
    if (web_sockspec_parse(spec, &sp, err, sizeof(err)) != 0) return -1;
    web_live_init(&g_live, spec);
    if (web_ingest_start(&g_ing, &sp, bmin, bmax, &g_live, err, sizeof(err))) {
        fprintf(stderr, "    ingest: %s\n", err);
        web_live_destroy(&g_live);
        return -1;
    }
    return 0;
}

static void stop_ingest(void) {
    web_ingest_stop(&g_ing);
    web_live_destroy(&g_live);
}

/* ── the HTTP side ────────────────────────────────────────────────── */

typedef struct {
    web_server_t *s;
    pthread_t     th;
} srv_t;

static void *srv_main(void *arg) {
    srv_t *r = arg;
    web_server_run(r->s);
    return NULL;
}

static int srv_start(srv_t *r, int tick_ms) {
    web_config_t c;
    char err[256];
    web_config_defaults(&c);
    c.bind_port = 0;
    c.tick_ms = tick_ms;
    r->s = calloc(1, sizeof(*r->s));
    if (!r->s || web_server_open(r->s, &c, err, sizeof(err)) != 0) {
        if (r->s) web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    web_server_set_live(r->s, &g_live);
    if (pthread_create(&r->th, NULL, srv_main, r) != 0) {
        web_server_close(r->s);
        free(r->s);
        r->s = NULL;
        return -1;
    }
    return 0;
}

static void srv_stop(srv_t *r) {
    web_server_stop(r->s);
    pthread_join(r->th, NULL);
    web_server_close(r->s);
    free(r->s);
    r->s = NULL;
}

static int dial_http(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 3, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

static char g_http[WEB_SSE_MAX_UNSENT + 4096];

static const char *http_get(uint16_t port, const char *path) {
    g_http[0] = '\0';
    int fd = dial_http(port);
    if (fd < 0) return g_http;
    char rq[256];
    int n = snprintf(rq, sizeof(rq), "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", path);
    put(fd, rq, (size_t)n);
    size_t len = 0;
    for (;;) {
        ssize_t r = recv(fd, g_http + len, sizeof(g_http) - 1 - len, 0);
        if (r <= 0) break;
        len += (size_t)r;
    }
    g_http[len] = '\0';
    close(fd);
    return g_http;
}

/* "\"devices\":N," in the body of /api/live. */
static long http_devices(uint16_t port) {
    const char *b = strstr(http_get(port, "/api/live"), "\r\n\r\n");
    if (!b) return -2;
    const char *d = strstr(b, "\"devices\":");
    if (!d) return -2;
    d += 10;
    if (!strncmp(d, "null", 4)) return -1;
    if (!strstr(b, "\"devices_stale\":false")) return -3;
    return strtol(d, NULL, 10);
}

/* ── tests ────────────────────────────────────────────────────────── */

static void test_sockspec(void) {
    web_sockspec_t sp;
    char err[256];
    WT_EQ(web_sockspec_parse("unix:/run/sloth/sloth.sock", &sp, err, sizeof(err)), 0);
    WT_EQ(sp.kind, WEB_SOCKSPEC_UNIX);
    WT_ASSERT(!strcmp(sp.path, "/run/sloth/sloth.sock"));
    WT_EQ(web_sockspec_is_local(&sp), 1);
    WT_EQ(web_sockspec_parse("tcp:127.0.0.1:8765", &sp, err, sizeof(err)), 0);
    WT_EQ(sp.kind, WEB_SOCKSPEC_TCP);
    WT_EQ(sp.port, 8765);
    WT_EQ(web_sockspec_is_local(&sp), 1);
    WT_EQ(web_sockspec_parse("tcp:[::1]:8765", &sp, err, sizeof(err)), 0);
    WT_EQ(sp.family, AF_INET6);
    WT_EQ(web_sockspec_is_local(&sp), 1);
    WT_EQ(web_sockspec_parse("tcp:192.168.1.5:8765", &sp, err, sizeof(err)), 0);
    WT_EQ(web_sockspec_is_local(&sp), 0);
    char f[64];
    web_sockspec_format(&sp, f, sizeof(f));
    WT_ASSERT(!strcmp(f, "tcp:192.168.1.5:8765"));

    /* Names are never resolved: refused, and the reason says so. */
    WT_EQ(web_sockspec_parse("tcp:localhost:8765", &sp, err, sizeof(err)), -1);
    WT_HAS(err, "names are not resolved");
    WT_EQ(web_sockspec_parse("tcp:sensor.lan:8765", &sp, err, sizeof(err)), -1);
    WT_EQ(web_sockspec_parse("tcp:[sensor]:8765", &sp, err, sizeof(err)), -1);
    static const char *const bad[] = {
        "", "unix:", "/run/sloth.sock", "udp:127.0.0.1:1", "tcp:127.0.0.1",
        "tcp:127.0.0.1:", "tcp:127.0.0.1:0", "tcp:127.0.0.1:65536",
        "tcp:127.0.0.1:12a", "tcp:127.0.0.1:123456", "tcp:::1:80",
        "tcp:[::1]80", "tcp::80",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = web_sockspec_parse(bad[i], &sp, err, sizeof(err));
        if (rc == 0) fprintf(stderr, "    accepted --socket %s\n", bad[i]);
        WT_EQ(rc, -1);
    }
    char longp[200];
    memset(longp, 'a', sizeof(longp) - 1);
    longp[sizeof(longp) - 1] = '\0';
    memcpy(longp, "unix:/", 6);
    WT_EQ(web_sockspec_parse(longp, &sp, err, sizeof(err)), -1);
}

/* The wait before the next attempt doubles from the floor and never
 * passes the cap, however many attempts have failed. */
static void test_backoff_bound(void) {
    int b = 0;
    static const int want[] = { 250, 500, 1000, 2000, 4000, 4000, 4000 };
    for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
        b = web_backoff_next(b, WEB_SOCK_BACKOFF_MIN_MS, WEB_SOCK_BACKOFF_MAX_MS);
        WT_EQ(b, want[i]);
    }
    b = 0;
    for (int i = 0; i < 100; i++) {
        b = web_backoff_next(b, 3, 1000);
        WT_ASSERT(b >= 3 && b <= 1000);
    }
    WT_EQ(b, 1000);
    WT_EQ(web_backoff_next(0, 500, 100), 100);
    WT_EQ(web_backoff_next(700, 10, 1000), 1000);
    /* spec §12: a restarted sloth is back on the page within 5 s, so
     * the longest wait must leave room for the connect and a pass. */
    WT_ASSERT(WEB_SOCK_BACKOFF_MAX_MS <= 4000);
}

/* test_device_count_matches_what_sloth_sent(), once the fake is
 * connected on fd and the server listens on port. */
static void device_passes(int fd, uint16_t port) {
    WT_EQ(http_devices(port), -1);    /* nothing yet: null, not 0 */

    static const int counts[] = { 3, 12, 300, 0, 7 };
    long long ts = 1700000000;
    for (size_t k = 0; k < sizeof(counts) / sizeof(counts[0]); k++) {
        long long t0 = mono_ms();
        /* Three ticks of the same table, as sloth sends one per poll. */
        for (int rep = 0; rep < 3; rep++)
            sloth_batch(fd, counts[k], ts++, "<img src=x onerror=alert(1)>");
        long got = -9;
        while (mono_ms() - t0 < 5000) {
            got = http_devices(port);
            if (got == counts[k]) break;
            nap(10);
        }
        long long took = mono_ms() - t0;
        if (got != counts[k])
            fprintf(stderr, "    sent %d devices, /api/live says %ld\n",
                    counts[k], got);
        WT_EQ(got, counts[k]);
        WT_ASSERT(took < 5000);
    }

    /* The hostname carried markup on every row: the API never hands it
     * back as markup. */
    const char *j = http_get(port, "/api/live");
    WT_HAS(j, "HTTP/1.1 200 OK\r\n");
    WT_HAS(j, "\\u003cimg src=x onerror=alert(1)\\u003e");
    WT_HAS(j, "\\u003csvg onload=alert(1)\\u003e");
    const char *body = strstr(j, "\r\n\r\n");
    WT_ASSERT(body && !strchr(body, '<') && !strchr(body, '>'));

    const char *h = http_get(port, "/api/health");
    WT_HAS(h, "\"socket\":\"connected\"");
    WT_HAS(h, "\"socket_connects\":1,");
    WT_HAS(h, "\"socket_decode_errors\":0,");

    /* The capture thread's records land inside a pass on a real sloth
     * (no lock spans one): the count is still the rows sent. Seen red
     * (150, 290, then 1 for the dns before the last row) with the poll_type() return removed from
     * web_live.c devices_step(). */
    static const int at[] = { 150, 10, 299 };
    for (size_t k = 0; k < sizeof(at) / sizeof(at[0]); k++) {
        long long t0 = mono_ms();
        for (int rep = 0; rep < 3; rep++)
            sloth_batch_cut(fd, 300, ts++, "h", at[k]);
        long got = -9;
        while (mono_ms() - t0 < 5000) {
            got = http_devices(port);
            if (got == 300) break;
            nap(10);
        }
        if (got != 300)
            fprintf(stderr, "    dns at row %d: /api/live says %ld\n", at[k], got);
        WT_EQ(got, 300);
        /* then a pass of another size, so the next 300 is not stale */
        sloth_batch(fd, 1, ts++, "h");
        sloth_batch(fd, 1, ts++, "h");
        t0 = mono_ms();
        while (mono_ms() - t0 < 5000 && http_devices(port) != 1) nap(10);
        WT_EQ(http_devices(port), 1);
    }
}

/* Spec §12, M1 acceptance: "Overview shows the same device count as
 * the TUI within 5 s". The TUI's count is s->device_count, and sloth
 * writes exactly that many device records per pass; so the fake writes
 * N of them per pass as sloth would, and /api/live (what the Overview
 * tile reads) must say N within 5 s of the pass, for counts going up,
 * down, to zero and back. */
static void test_device_count_matches_what_sloth_sent(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    WT_ASSERT(lfd >= 0);
    if (lfd < 0 || start_unix(20, 200) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    srv_t srv;
    WT_EQ(srv_start(&srv, 50), 0);
    int fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    if (fd >= 0 && srv.s) device_passes(fd, web_server_port(srv.s));
    if (fd >= 0) close(fd);
    if (srv.s) srv_stop(&srv);
    stop_ingest();
    if (lfd >= 0) close(lfd);
    tmp_dir_done();
}

/* The ticker over /events: record events reach a page with the
 * stream's markup escaped, one data line each. */
static void test_events_carry_escaped_records(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    if (lfd < 0 || start_unix(20, 200) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    srv_t srv;
    WT_EQ(srv_start(&srv, 30), 0);
    int fd = accept_within(lfd, 3000);
    int ev = srv.s ? dial_http(web_server_port(srv.s)) : -1;
    WT_ASSERT(fd >= 0 && ev >= 0);
    if (fd >= 0 && ev >= 0) {
        static const char rq[] = "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        put(ev, rq, sizeof(rq) - 1);
        nap(100);
        puts_fd(fd, "{\"type\":\"dns\",\"ts\":5,\"src\":\"10.0.0.9\","
                    "\"qname\":\"<script>alert(1)</script>.example\"}\n");
        static char buf[65536];
        size_t len = 0;
        long long end = mono_ms() + 4000;
        while (mono_ms() < end && len + 1 < sizeof(buf)) {
            struct pollfd p = { ev, POLLIN, 0 };
            if (poll(&p, 1, 50) <= 0) continue;
            ssize_t r = recv(ev, buf + len, sizeof(buf) - 1 - len, 0);
            if (r <= 0) break;
            len += (size_t)r;
            buf[len] = '\0';
            if (strstr(buf, "event: record\n")) {
                const char *e = strstr(buf, "event: record\n");
                if (strstr(e, "\n\n")) break;
            }
        }
        buf[len] = '\0';
        WT_HAS(buf, "event: record\ndata: {\"seq\":1,\"type\":\"dns\",\"ts\":5,"
                    "\"text\":\"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e.example"
                    "  10.0.0.9\",\"sc\":2}\n\n");
        WT_LACKS(buf, "<script");
        WT_HAS(buf, "\"socket\":\"connected\"");
    }
    if (ev >= 0) close(ev);
    if (fd >= 0) close(fd);
    if (srv.s) srv_stop(&srv);
    stop_ingest();
    close(lfd);
    tmp_dir_done();
}

/* sloth goes away and comes back: the client notices the close, waits
 * its back-off, reconnects, and the count follows the new stream. */
static void test_reconnect_after_peer_closes(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    if (lfd < 0 || start_unix(20, 100) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    web_live_sum_t s;
    int fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        sloth_batch(fd, 4, 100, "a");
        sloth_batch(fd, 4, 101, "a");
        WT_ASSERT(wait_sum(has_devices, 4, 3000, &s));
        close(fd);
    }
    /* A second connection arrives without anything prompting it. */
    long long t0 = mono_ms();
    fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    WT_ASSERT(mono_ms() - t0 < 1000);
    if (fd >= 0) {
        WT_ASSERT(wait_sum(is_connected, 0, 3000, &s));
        /* stale until the new stream delivers a pass */
        web_live_summary(&g_live, &s, mono_ms());
        WT_EQ(s.dev_stale, 1);
        sloth_batch(fd, 9, 200, "b");
        sloth_batch(fd, 9, 201, "b");
        WT_ASSERT(wait_sum(has_devices, 9, 3000, &s));
        WT_EQ(live_ul(&g_live.connects), 2);
        WT_EQ(live_ul(&g_live.closes), 1);
        char hb[4096];
        web_jw_t w;
        web_jw_init(&w, hb, sizeof(hb));
        web_live_health_members(&g_live, &w, mono_ms());
        WT_HAS(hb, "\"socket_reconnects\":1,");
        WT_HAS(hb, "\"socket_last_error\":\"peer closed the stream\"");
        close(fd);
    }
    stop_ingest();
    close(lfd);
    tmp_dir_done();
}

/* No sloth at all: the client keeps trying at the capped interval, not
 * faster and not slower, and connects as soon as one appears. */
static void test_backoff_without_a_peer(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    if (start_unix(10, 40) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    int max_retry = 0;
    long long end = mono_ms() + 600;
    while (mono_ms() < end) {
        pthread_mutex_lock(&g_live.mu);
        if (g_live.retry_ms > max_retry) max_retry = g_live.retry_ms;
        pthread_mutex_unlock(&g_live.mu);
        nap(3);
    }
    unsigned long fails = live_ul(&g_live.failures);
    unsigned long tries = live_ul(&g_live.attempts);
    /* 600 ms at 10, 20, 40, 40, ... ms: about 16; allow a slow box. */
    WT_ASSERT(fails >= 5);
    WT_ASSERT(tries <= 600 / 10 + 2);
    WT_EQ(max_retry, 40);
    char hb[4096];
    web_jw_t w;
    web_jw_init(&w, hb, sizeof(hb));
    web_live_health_members(&g_live, &w, mono_ms());
    WT_HAS(hb, "\"socket\":\"");
    WT_HAS(hb, "\"socket_last_error\":\"connect: No such file or directory\"");

    int lfd = unix_listen(g_path);
    long long t0 = mono_ms();
    int fd = lfd >= 0 ? accept_within(lfd, 2000) : -1;
    WT_ASSERT(fd >= 0);
    WT_ASSERT(mono_ms() - t0 < 500);
    if (fd >= 0) close(fd);
    stop_ingest();
    if (lfd >= 0) close(lfd);
    tmp_dir_done();
}

/* A peer that accepts and closes at once (sloth refusing a client over
 * its per-peer cap does exactly that) delivered nothing, so it does not
 * reset the back-off. Seen red (more than 14 connects in 500 ms) with
 * the reset made unconditional in ingest_main(). */
static void test_instant_close_is_backed_off(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    if (lfd < 0 || start_unix(20, 80) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    int n = 0;
    long long end = mono_ms() + 500;
    while (mono_ms() < end) {
        int fd = accept_within(lfd, 20);
        if (fd >= 0) { n++; close(fd); }
    }
    /* 20, 40, 80, 80, ...: about 8 in 500 ms. */
    if (n > 14) fprintf(stderr, "    %d connects in 500 ms\n", n);
    WT_ASSERT(n >= 3 && n <= 14);
    stop_ingest();
    close(lfd);
    tmp_dir_done();
}

/* tcp: with a literal loopback address. */
static void test_tcp_loopback(void) {
    uint16_t port;
    int lfd = tcp_listen(&port);
    WT_ASSERT(lfd >= 0);
    if (lfd < 0) return;
    char spec[64], err[256];
    snprintf(spec, sizeof(spec), "tcp:127.0.0.1:%u", (unsigned)port);
    web_sockspec_t sp;
    WT_EQ(web_sockspec_parse(spec, &sp, err, sizeof(err)), 0);
    web_live_init(&g_live, spec);
    WT_EQ(web_ingest_start(&g_ing, &sp, 20, 100, &g_live, err, sizeof(err)), 0);
    int fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        sloth_batch(fd, 2, 1, "h");
        sloth_batch(fd, 2, 2, "h");
        web_live_sum_t s;
        WT_ASSERT(wait_sum(has_devices, 2, 3000, &s));
        close(fd);
    }
    stop_ingest();
    close(lfd);
}

/* A connect that never completes gives up at connect_ms and backs off,
 * rather than hanging the client. The listener's accept queue is full
 * (backlog 0, one connection held unaccepted), so Linux drops the next
 * SYN and the client's non-blocking connect stays EINPROGRESS. Costs
 * WEB_SOCK_CONNECT_MS of wall time. Seen red (no "timed out" error in
 * 2x WEB_SOCK_CONNECT_MS) with the deadline branch in dial() disabled;
 * a stop still ended the run, through the stop pipe. */
static void test_connect_timeout(void) {
    uint16_t port;
    int lfd = tcp_listen(&port);
    WT_ASSERT(lfd >= 0);
    if (lfd < 0) return;
    WT_EQ(listen(lfd, 0), 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    int fill[4];
    for (int i = 0; i < 4; i++) {
        fill[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fill[i] >= 0) (void)connect(fill[i], (struct sockaddr *)&a, sizeof(a));
    }
    nap(50);
    char spec[64], err[256];
    snprintf(spec, sizeof(spec), "tcp:127.0.0.1:%u", (unsigned)port);
    web_sockspec_t sp;
    WT_EQ(web_sockspec_parse(spec, &sp, err, sizeof(err)), 0);
    web_live_init(&g_live, spec);
    long long t0 = mono_ms();
    WT_EQ(web_ingest_start(&g_ing, &sp, 20, 100, &g_live, err, sizeof(err)), 0);
    char want[64];
    snprintf(want, sizeof(want), "connect: timed out after %d ms", WEB_SOCK_CONNECT_MS);
    int seen = 0;
    while (!seen && mono_ms() - t0 < 2 * WEB_SOCK_CONNECT_MS) {
        pthread_mutex_lock(&g_live.mu);
        seen = g_live.last_error_ms >= 0 && !strcmp(g_live.last_error, want);
        pthread_mutex_unlock(&g_live.mu);
        if (!seen) nap(20);
    }
    long long took = mono_ms() - t0;
    WT_ASSERT(seen);
    WT_ASSERT(took >= WEB_SOCK_CONNECT_MS - 50);
    WT_EQ(live_ul(&g_live.connects), 0);
    stop_ingest();
    for (int i = 0; i < 4; i++) if (fill[i] >= 0) close(fill[i]);
    close(lfd);
}

/* The lines a socket can deliver that sloth would not write, mixed in
 * with ones it would. Each bad line costs itself and nothing else. */
static void test_hostile_stream(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    if (lfd < 0 || start_unix(20, 100) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    int fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        puts_fd(fd, "{\"type\":\"dns\",\"qname\":\"ok.example\"}\n");
        puts_fd(fd, "{\"type\":\"dns\",\"qname\":\"\xff\xfe\"}\n");          /* utf8 */
        puts_fd(fd, "{\"type\":\"dns\",\"qname\":\"\xc0\xbc\"}\n");          /* overlong '<' */
        puts_fd(fd, "{\"type\":\"dns\",\"qname\":\"\\udc00\"}\n");          /* lone half */
        puts_fd(fd, "{\"type\":\"dns\",\"type\":\"device\"}\n");            /* dup */
        puts_fd(fd, "not json at all\n");
        puts_fd(fd, "{\"type\":\"dns\",\"qname\":\"cut\n");                 /* syntax */
        static char big[WEB_JL_MAX_LINE + 64];
        memset(big, 'A', sizeof(big));
        memcpy(big, "{\"type\":\"device\",\"x\":\"", 22);
        put(fd, big, sizeof(big));
        puts_fd(fd, "\"}\n");                                              /* overlong */
        puts_fd(fd, "{\"type\":\"tls\",\"host\":\"<b>bold</b>\"}\n");
        put(fd, "\x01\x02\x7f\n", 4);                                   /* not an object */
        puts_fd(fd, "{\"type\":\"quic\",\"host\":\"half");                  /* truncated */
        web_live_sum_t s;
        WT_ASSERT(wait_sum(has_records, 2, 3000, &s));
        close(fd);
    }
    /* Wait for the client to see the close, then read the counters. */
    long long end = mono_ms() + 3000;
    while (mono_ms() < end && live_ul(&g_live.closes) < 1) nap(5);
    pthread_mutex_lock(&g_live.mu);
    WT_EQ(g_live.records, 2);
    WT_EQ(g_live.dec_by[WEB_JL_EUTF8], 3);
    WT_EQ(g_live.dec_by[WEB_JL_EDUP], 1);
    WT_EQ(g_live.dec_by[WEB_JL_ENOTOBJ], 2);
    WT_EQ(g_live.dec_by[WEB_JL_ESYNTAX], 1);
    WT_EQ(g_live.dec_by[WEB_JL_ELONG], 1);
    WT_EQ(g_live.truncated, 1);
    pthread_mutex_unlock(&g_live.mu);
    static char j[WEB_SSE_MAX_UNSENT];
    WT_ASSERT(web_live_json(&g_live, j, sizeof(j), mono_ms()) > 0);
    WT_HAS(j, "\"types\":{\"dns\":1,\"tls\":1}");
    WT_LACKS(j, "<");
    stop_ingest();
    close(lfd);
    tmp_dir_done();
}

/* The stream is one-way: slothweb never sends sloth a byte. Seen red
 * (one byte read) with a send() of one byte added after connect in
 * ingest_main(). */
static void test_client_never_writes(void) {
    if (tmp_dir() != 0) { WT_ASSERT(0); return; }
    int lfd = unix_listen(g_path);
    if (lfd < 0 || start_unix(20, 100) != 0) { WT_ASSERT(0); tmp_dir_done(); return; }
    int fd = accept_within(lfd, 3000);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) {
        sloth_batch(fd, 3, 1, "x");
        web_live_sum_t s;
        WT_ASSERT(wait_sum(has_records, 5, 3000, &s));
        nap(50);
        stop_ingest();
        /* Everything the client ever sent is queued here by now, and
         * its close follows it: EOF with no byte first. */
        char b[16];
        struct timeval tv = { 2, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t r = recv(fd, b, sizeof(b), 0);
        WT_EQ(r, 0);
        close(fd);
    } else {
        stop_ingest();
    }
    close(lfd);
    tmp_dir_done();
}

void run_ingest_tests(void) {
    WT_RUN(test_sockspec);
    WT_RUN(test_backoff_bound);
    WT_RUN(test_device_count_matches_what_sloth_sent);
    WT_RUN(test_events_carry_escaped_records);
    WT_RUN(test_reconnect_after_peer_closes);
    WT_RUN(test_backoff_without_a_peer);
    WT_RUN(test_instant_close_is_backed_off);
    WT_RUN(test_tcp_loopback);
    WT_RUN(test_connect_timeout);
    WT_RUN(test_hostile_stream);
    WT_RUN(test_client_never_writes);
}
