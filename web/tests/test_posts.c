/* sloth-ios sensor posts (#205 slice 1, web_posts.h): --post and its
 * refusals, the per-type fleet-share rule the owner ruled on 2026-11-19,
 * the framer over the six record types of docs/wiki/post-protocol.md
 * (ver=1.0), /api/posts, and a fake post on loopback that the reader
 * connects to, reads, never writes to, and redials when it goes away.
 *
 * The records are written by hand from the protocol's table, not
 * captured from a phone. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "web_config.h"
#include "web_posts.h"
#include "web_routes.h"
#include "wtest.h"

#define UUID  "7C1E2A9B-4F3D-4E21-9A55-0B6C1D2E3F40"
#define UUID2 "11111111-2222-4333-8444-555555555555"

static const char IOS_POST[] =
    "{\"type\":\"ios_post\",\"ts\":1800000000,\"post\":\"" UUID "\",\"name\":\"pocket\","
    "\"role\":\"mobile\",\"platform\":\"ios\",\"app_ver\":\"1.0\",\"battery\":0.82,"
    "\"charging\":false,\"uptime_s\":3600}\n";
static const char BLE[] =
    "{\"type\":\"ble_contact\",\"ts\":1800000001,\"post\":\"" UUID "\","
    "\"addr\":\"5A0C3E4B-1D2F-4A6B-8C7D-9E0F1A2B3C4D\",\"addr_type\":\"random\","
    "\"name\":null,\"rssi\":-67,\"tx_power\":null,\"services\":[\"FE9F\"],\"count\":3}\n";
static const char IMU[] =
    "{\"type\":\"imu_sample\",\"ts\":1800000001,\"post\":\"" UUID "\",\"heading_deg\":271.5,"
    "\"field_mag_uT\":48.2,\"field_x\":12.1,\"field_y\":-40.3,\"field_z\":22.0,"
    "\"pitch_deg\":1.2,\"roll_deg\":-0.4,\"yaw_deg\":88.0}\n";
static const char WIFI_SELF[] =
    "{\"type\":\"wifi_self\",\"ts\":1800000001,\"post\":\"" UUID "\",\"ssid\":\"homenet\","
    "\"bssid\":\"02:00:00:00:00:01\",\"rssi\":-50,\"band\":null}\n";
static const char GEO[] =
    "{\"type\":\"geo_fix\",\"ts\":1800000001,\"post\":\"" UUID "\",\"lat\":45.1,\"lon\":-93.2,"
    "\"alt_m\":250.0,\"h_acc_m\":12.0,\"course_deg\":null,\"speed_mps\":0.0}\n";
static const char SCAN[] =
    "{\"type\":\"radio_scan\",\"ts\":1800000001,\"post\":\"" UUID "\",\"available\":false,"
    "\"reason\":\"needs com.apple.wifi.manager-access\",\"aps\":[]}\n";

static char g_out[65536];

static web_sockspec_t loop_spec(uint16_t port) {
    web_sockspec_t sp;
    memset(&sp, 0, sizeof(sp));
    sp.kind = WEB_SOCKSPEC_TCP;
    sp.family = AF_INET;
    sp.addr[0] = 127;
    sp.addr[3] = 1;
    sp.port = port;
    return sp;
}

static size_t feed(web_posts_t *s, const char *t) {
    return web_posts_feed(s, 0, t, strlen(t), 1000000);
}

static const char *roster(web_posts_t *s, long long now_ms) {
    size_t n = web_posts_json(s, now_ms, g_out, sizeof(g_out));
    g_out[n < sizeof(g_out) ? n : 0] = '\0';
    return g_out;
}

/* ── the fleet-share rule ─────────────────────────────────────────────── */

/* Owner rulings 2026-11-19 on #205: ble_contact travels; wifi_self,
 * geo_fix, imu_sample, radio_scan stay; ios_post and anything unnamed
 * stay too (fail closed). Seen red with wifi_self added to travels. */
static void test_only_ble_contact_travels(void) {
    WT_EQ(web_post_type_travels("ble_contact"), 1);
    WT_EQ(web_post_type_travels("wifi_self"), 0);
    WT_EQ(web_post_type_travels("geo_fix"), 0);
    WT_EQ(web_post_type_travels("imu_sample"), 0);
    WT_EQ(web_post_type_travels("radio_scan"), 0);
    WT_EQ(web_post_type_travels("ios_post"), 0);
    WT_EQ(web_post_type_travels("ble_contact_v2"), 0);
    WT_EQ(web_post_type_travels(""), 0);
    WT_EQ(web_post_type_travels(NULL), 0);
    int n = 0;
    for (int k = 0; k < WEB_PT_COUNT; k++) n += web_post_type_travels(web_post_type_names[k]);
    WT_EQ(n, 1);
    WT_EQ(web_post_type("radio_scan"), WEB_PT_RADIO_SCAN);
    WT_EQ(web_post_type("RADIO_SCAN"), -1);
}

/* ── --post ───────────────────────────────────────────────────────────── */

typedef struct { int rc; web_config_t cfg; char *err, *ann; } run_t;

static void parse(run_t *r, const char *const *args) {
    char *argv[16];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args[i] && argc < 15; i++) argv[argc++] = (char *)args[i];
    argv[argc] = NULL;
    char *out = NULL;
    size_t ol = 0, el = 0, al = 0;
    r->err = r->ann = NULL;
    FILE *o = open_memstream(&out, &ol);
    FILE *e = open_memstream(&r->err, &el);
    r->rc = web_config_parse(&r->cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    free(out);
    FILE *a = open_memstream(&r->ann, &al);
    if (r->rc == 0) web_config_announce(&r->cfg, a);
    fclose(a);
}

static void done(run_t *r) {
    free(r->err);
    free(r->ann);
}

static void test_post_flag(void) {
    run_t r;
    { const char *a[] = { NULL }; parse(&r, a); }
    WT_EQ(r.rc, 0);
    WT_EQ(r.cfg.npost, 0);
    done(&r);

    { const char *a[] = { "--post", "100.101.102.103:7781", "--post", "[fd7a:115c:a1e0::5]:9000", NULL };
      parse(&r, a); }
    WT_EQ(r.rc, 0);
    WT_EQ(r.cfg.npost, 2);
    WT_EQ(r.cfg.post[0].port, 7781);
    WT_EQ(r.cfg.post[1].family, AF_INET6);
    WT_EQ(web_post_in_tailnet(&r.cfg.post[0]), 1);
    WT_EQ(web_post_in_tailnet(&r.cfg.post[1]), 1);
    /* Both inside the tailnet: nothing announced as a warning. */
    WT_LACKS(r.ann, "--post");
    done(&r);

    /* A LAN address is refused unless forced, and announced when it is. */
    { const char *a[] = { "--post", "192.168.1.20:7781", NULL }; parse(&r, a); }
    WT_EQ(r.rc, -1);
    WT_HAS(r.err, "--post 192.168.1.20:7781 is outside the tailnet");
    WT_HAS(r.err, "--post-allow-outside-tailnet");
    done(&r);
    { const char *a[] = { "--post", "192.168.1.20:7781", "--post-allow-outside-tailnet", NULL };
      parse(&r, a); }
    WT_EQ(r.rc, 0);
    WT_HAS(r.ann, "WARNING: --post 192.168.1.20:7781 is outside the tailnet");
    done(&r);
    /* 100.128.0.1 is past 100.64.0.0/10. */
    { const char *a[] = { "--post", "100.128.0.1:7781", NULL }; parse(&r, a); }
    WT_EQ(r.rc, -1);
    done(&r);

    /* Strict refuses any post (owner ruling 2026-11-19, point 4), even a
     * forced one. */
    { const char *a[] = { "--strict", "--post", "100.101.102.103:7781", NULL }; parse(&r, a); }
    WT_EQ(r.rc, -1);
    WT_HAS(r.err, "--strict refuses --post.");
    done(&r);
    { const char *a[] = { "--post", "192.168.1.20:7781", "--post-allow-outside-tailnet",
                          "--strict", NULL }; parse(&r, a); }
    WT_EQ(r.rc, -1);
    WT_HAS(r.err, "--strict refuses --post.");
    done(&r);

    /* Names are never resolved; a port is required. */
    static const char *const BAD[] = {
        "phone.tailnet.ts.net:7781", "100.101.102.103", "100.101.102.103:0",
        "100.101.102.103:65536", "100.101.102.103:77a", "tcp:100.101.102.103:7781",
        "unix:/tmp/x", "", NULL,
    };
    for (int i = 0; BAD[i]; i++) {
        const char *a[] = { "--post", BAD[i], NULL };
        parse(&r, a);
        WT_EQ(r.rc, -1);
        WT_HAS(r.err, "want A.B.C.D:PORT or [V6]:PORT");
        done(&r);
    }
    { const char *a[] = { "--post", NULL }; parse(&r, a); }
    WT_EQ(r.rc, -1);
    WT_HAS(r.err, "--post needs an argument");
    done(&r);

    { const char *a[] = { "--post", "100.101.102.103:7781", "--post", "100.101.102.103:7781", NULL };
      parse(&r, a); }
    WT_EQ(r.rc, -1);
    WT_HAS(r.err, "that post is given twice");
    done(&r);

}

static void test_post_cap(void) {
    char *argv[2 * WEB_POSTS_MAX + 4];
    char addr[WEB_POSTS_MAX + 1][32];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; i <= WEB_POSTS_MAX; i++) {
        snprintf(addr[i], sizeof(addr[i]), "100.64.0.1:%d", 7000 + i);
        argv[argc++] = (char *)"--post";
        argv[argc++] = addr[i];
    }
    argv[argc] = NULL;
    web_config_t cfg;
    char *out = NULL, *err = NULL;
    size_t ol = 0, el = 0;
    FILE *o = open_memstream(&out, &ol);
    FILE *e = open_memstream(&err, &el);
    int rc = web_config_parse(&cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    WT_EQ(rc, -1);
    WT_HAS(err, "--post: at most 8 posts");
    free(out);
    free(err);
}

/* ── the framer and the roster ────────────────────────────────────────── */

static void test_six_types_counted(void) {
    web_posts_t s;
    web_sockspec_t sp = loop_spec(7781);
    WT_EQ(web_posts_init(&s, &sp, 1), 0);
    const char *j = roster(&s, 1000000);
    /* Before anything is heard: the post is named, nothing else known. */
    WT_HAS(j, "\"travels\":[\"ble_contact\"]");
    WT_HAS(j, "\"endpoint\":\"127.0.0.1:7781\"");
    WT_HAS(j, "\"heard_age_s\":null");
    WT_HAS(j, "\"post\":null");
    WT_HAS(j, "\"battery\":null");

    WT_EQ(feed(&s, IOS_POST), 1);
    WT_EQ(feed(&s, BLE), 1);
    WT_EQ(feed(&s, BLE), 1);
    WT_EQ(feed(&s, IMU), 1);
    WT_EQ(feed(&s, WIFI_SELF), 1);
    WT_EQ(feed(&s, GEO), 1);
    WT_EQ(feed(&s, SCAN), 1);
    j = roster(&s, 1004000);
    WT_HAS(j, "\"post\":\"" UUID "\"");
    WT_HAS(j, "\"name\":\"pocket\"");
    WT_HAS(j, "\"role\":\"mobile\"");
    WT_HAS(j, "\"platform\":\"ios\"");
    WT_HAS(j, "\"app_ver\":\"1.0\"");
    WT_HAS(j, "\"battery\":0.82");
    WT_HAS(j, "\"charging\":false");
    WT_HAS(j, "\"uptime_s\":3600");
    WT_HAS(j, "\"heard_age_s\":4");
    WT_HAS(j, "\"records\":{\"ios_post\":1,\"ble_contact\":2,\"imu_sample\":1,"
              "\"wifi_self\":1,\"geo_fix\":1,\"radio_scan\":1}");
    WT_HAS(j, "\"other\":0,\"foreign\":0,\"decode_errors\":0,\"lines\":7");
    /* Counts only: no record's contents but the post's own heartbeat. */
    WT_LACKS(j, "homenet");
    WT_LACKS(j, "02:00:00:00:00:01");
    WT_LACKS(j, "45.1");
    WT_LACKS(j, "271.5");
    WT_LACKS(j, "5A0C3E4B");
    web_posts_destroy(&s);
}

static void test_bad_lines(void) {
    web_posts_t s;
    web_sockspec_t sp = loop_spec(7781);
    WT_EQ(web_posts_init(&s, &sp, 1), 0);
    WT_EQ(feed(&s, IOS_POST), 1);
    /* A record of a type the protocol does not name: counted, kept out
     * of the six. */
    WT_EQ(feed(&s, "{\"type\":\"nfc_tag\",\"ts\":1,\"post\":\"" UUID "\"}\n"), 1);
    /* No envelope "post", and another post on this connection. */
    WT_EQ(feed(&s, "{\"type\":\"ble_contact\",\"ts\":1,\"rssi\":-50}\n"), 1);
    WT_EQ(feed(&s, "{\"type\":\"ble_contact\",\"ts\":1,\"post\":\"" UUID2 "\"}\n"), 1);
    WT_EQ(feed(&s, "{\"type\":\"ble_contact\",\"ts\":1,\"post\":7}\n"), 1);
    /* Not JSON; a duplicate key; split across two reads; blank lines. */
    WT_EQ(feed(&s, "{\"type\":\"ios_post\",\"post\":\n"), 1);
    WT_EQ(feed(&s, "{\"type\":\"ios_post\",\"type\":\"ble_contact\",\"post\":\"" UUID "\"}\n"), 1);
    WT_EQ(feed(&s, "{\"type\":\"ble_contact\",\"ts\":1,"), 0);
    WT_EQ(feed(&s, "\"post\":\"" UUID "\"}\n\n\r\n"), 3);
    /* Over the line bound: one error, then the next line reads. */
    size_t big = WEB_JL_MAX_LINE + 100;
    char *b = malloc(big + 1);
    WT_ASSERT(b != NULL);
    if (b) {
        memset(b, 'x', big);
        b[big - 1] = '\n';
        b[big] = '\0';
        WT_EQ(web_posts_feed(&s, 0, b, big, 1000000), 1);
        free(b);
    }
    WT_EQ(feed(&s, BLE), 1);
    /* Battery out of 0..1 and charging not a boolean: unknown. */
    WT_EQ(feed(&s, "{\"type\":\"ios_post\",\"ts\":2,\"post\":\"" UUID "\",\"name\":\"pocket\","
                   "\"battery\":82,\"charging\":\"yes\",\"uptime_s\":-5}\n"), 1);
    const char *j = roster(&s, 1000000);
    WT_HAS(j, "\"ble_contact\":2");
    WT_HAS(j, "\"ios_post\":2");
    WT_HAS(j, "\"other\":1,\"foreign\":3,\"decode_errors\":3");
    WT_HAS(j, "\"battery\":null,\"charging\":null,\"uptime_s\":null");

    /* A name with markup is escaped, and cut to the bound. */
    char line[512];
    snprintf(line, sizeof(line), "{\"type\":\"ios_post\",\"ts\":3,\"post\":\"" UUID "\","
             "\"name\":\"<b>%s\"}\n",
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    WT_EQ(feed(&s, line), 1);
    j = roster(&s, 1000000);
    WT_LACKS(j, "<b>");
    WT_HAS(j, "\\u003cb\\u003e");

    /* A new connection from a post with another identity: it starts
     * over, and the old uuid is now the foreign one. */
    web_posts_connected(&s, 0);
    WT_EQ(feed(&s, "{\"type\":\"ios_post\",\"ts\":4,\"post\":\"" UUID2 "\",\"name\":\"rotated\"}\n"), 1);
    WT_EQ(feed(&s, BLE), 1);
    j = roster(&s, 1000000);
    WT_HAS(j, "\"post\":\"" UUID2 "\"");
    WT_HAS(j, "\"name\":\"rotated\"");
    WT_HAS(j, "\"foreign\":4");
    web_posts_destroy(&s);
}

static void test_route(void) {
    web_posts_t s;
    web_sockspec_t sp = loop_spec(7781);
    WT_EQ(web_posts_init(&s, &sp, 1), 0);
    feed(&s, IOS_POST);
    for (int with = 0; with < 2; with++) {
        web_health_t h;
        memset(&h, 0, sizeof(h));
        h.posts = with ? &s : NULL;
        h.wall_s = 1800000005;
        h.now_ms = 1000000;
        web_req_t *rq = calloc(1, sizeof(*rq));
        WT_ASSERT(rq != NULL);
        if (!rq) break;
        snprintf(rq->path, sizeof(rq->path), "%s", "/api/posts");
        snprintf(rq->host, sizeof(rq->host), "127.0.0.1:8770");
        rq->host_count = 1;
        web_resp_t r;
        int rc = web_route(rq, &h, 1, g_out, sizeof(g_out), &r);
        free(rq);
        WT_EQ(rc, 0);
        if (rc) continue;
        g_out[r.out_len] = '\0';
        WT_EQ(r.status, 200);
        WT_HAS(g_out, "\"travels\":[\"ble_contact\"]");
        if (with) WT_HAS(g_out, "\"name\":\"pocket\"");
        else      WT_HAS(g_out, "\"posts\":[]");
    }
    web_posts_destroy(&s);
}

/* ── a fake post on loopback ──────────────────────────────────────────── */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int accept_within(int lfd, int ms) {
    struct pollfd p = { lfd, POLLIN, 0 };
    if (poll(&p, 1, ms) <= 0) return -1;
    return accept(lfd, NULL, NULL);
}

/* Poll the roster until it holds needle, or ms pass. */
static int wait_for(web_posts_t *s, const char *needle, int ms) {
    long long end = now_ms() + ms;
    while (now_ms() < end) {
        if (strstr(roster(s, now_ms()), needle)) return 1;
        struct timespec d = { 0, 10 * 1000000L };
        nanosleep(&d, NULL);
    }
    return 0;
}

static void test_fake_post(void) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    WT_ASSERT(lfd >= 0);
    if (lfd < 0) return;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t al = sizeof(a);
    int ok = bind(lfd, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(lfd, 4) == 0 &&
             getsockname(lfd, (struct sockaddr *)&a, &al) == 0;
    WT_ASSERT(ok);
    if (!ok) { close(lfd); return; }

    web_posts_t s;
    web_sockspec_t sp = loop_spec(ntohs(a.sin_port));
    WT_EQ(web_posts_init(&s, &sp, 1), 0);
    s.backoff_min_ms = 20;
    s.backoff_max_ms = 40;
    char err[128];
    WT_EQ(web_posts_start(&s, err, sizeof(err)), 0);

    int c = accept_within(lfd, 5000);
    WT_ASSERT(c >= 0);
    if (c >= 0) {
        /* The snapshot burst, then the tail, one write per record. */
        const char *recs[] = { IOS_POST, BLE, IMU, WIFI_SELF, GEO, SCAN, BLE };
        for (size_t i = 0; i < sizeof(recs) / sizeof(recs[0]); i++) {
            ssize_t w = send(c, recs[i], strlen(recs[i]), 0);
            WT_EQ(w, (ssize_t)strlen(recs[i]));
        }
        /* The last record sent is the second ble_contact. */
        WT_ASSERT(wait_for(&s, "\"ble_contact\":2", 5000));
        const char *j = roster(&s, now_ms());
        WT_HAS(j, "\"state\":\"connected\"");
        WT_HAS(j, "\"radio_scan\":1}");
        WT_HAS(j, "\"name\":\"pocket\"");
        /* One-way: the reader never sent a byte. */
        char b[8];
        ssize_t n = recv(c, b, sizeof(b), MSG_DONTWAIT);
        WT_ASSERT(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        close(c);
    }
    /* The post goes away (the app left the foreground): the reader
     * waits and comes back. */
    c = accept_within(lfd, 5000);
    WT_ASSERT(c >= 0);
    if (c >= 0) {
        ssize_t w = send(c, BLE, strlen(BLE), 0);
        WT_EQ(w, (ssize_t)strlen(BLE));
        WT_ASSERT(wait_for(&s, "\"ble_contact\":3", 5000));
        const char *j = roster(&s, now_ms());
        WT_HAS(j, "\"connects\":2");
        /* The same post: its identity is kept across the reconnect. */
        WT_HAS(j, "\"name\":\"pocket\"");
        WT_HAS(j, "\"foreign\":0");
        close(c);
    }
    web_posts_stop(&s);
    WT_HAS(roster(&s, now_ms()), "\"last_error\":\"stopped\"");
    web_posts_destroy(&s);
    close(lfd);

    /* Nothing listening: refused, counted, retried, and a stop ends it. */
    WT_EQ(web_posts_init(&s, &sp, 1), 0);
    s.backoff_min_ms = 20;
    s.backoff_max_ms = 40;
    WT_EQ(web_posts_start(&s, err, sizeof(err)), 0);
    WT_ASSERT(wait_for(&s, "connect: ", 5000));
    WT_ASSERT(wait_for(&s, "\"connects\":0", 100));
    web_posts_destroy(&s);
}

void run_posts_tests(void) {
    WT_RUN(test_only_ble_contact_travels);
    WT_RUN(test_post_flag);
    WT_RUN(test_post_cap);
    WT_RUN(test_six_types_counted);
    WT_RUN(test_bad_lines);
    WT_RUN(test_route);
    WT_RUN(test_fake_post);
}
