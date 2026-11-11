/* The owner's fleet (#192 F1, web_fleet.h; ADR 0008): the peer URL
 * rule, the member allow-list held to web_secret.h, the export over a
 * sloth.db generated from sloth's own DDL with a credential, a
 * username, EAPOL rows and a RADIUS identity seeded and held out of it,
 * `since`, and the pull from a loopback server answering canned bytes:
 * a good answer stored and widened by a second, and every refused
 * answer (oversize, cut short, malformed, an unknown member, a wrong
 * count, no end line, a non-200) leaving every sighting as it was. The
 * v7 -> v8 migration and its failure are test_store.c's, beside the
 * other steps (make_v6() lives there). */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "web_config.h"
#include "web_fleet.h"
#include "web_frrs.h"
#include "web_jsonl.h"
#include "web_routes.h"
#include "web_secret.h"
#include "web_store.h"
#include "wtest.h"
#include "wt_tmp.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#include "sdb_gen.h"
#endif

/* ── the peer list ──────────────────────────────────────────────────── */

/* Seen red with web_fleet_in_tailnet() testing the second octet against
 * 0x80 (100.128.0.0 then taken as the tailnet) and with the port's
 * range check dropped (":0" taken). */
static void test_peer_urls(void) {
    web_fleet_peer_cfg_t p;
    char err[200];
    WT_EQ(web_fleet_parse_peer("w9fjc=http://100.64.1.2:8770", &p, err, sizeof(err)), 0);
    WT_ASSERT(!strcmp(p.name, "w9fjc"));
    WT_ASSERT(!strcmp(p.url, "http://100.64.1.2:8770"));
    WT_EQ(p.port, 8770);
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    WT_EQ(web_fleet_parse_peer("beta-site=http://100.127.255.254/", &p, err, sizeof(err)), 0);
    WT_EQ(p.port, 80);
    WT_ASSERT(!strcmp(p.url, "http://100.127.255.254:80"));
    WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), 0);
    /* Routable, and the edges of 100.64.0.0/10: refused unless forced. */
    static const char *const outside[] = {
        "x=http://8.8.8.8:8770", "x=http://100.63.255.255:8770",
        "x=http://100.128.0.1:8770", "x=http://127.0.0.1:8770",
        "x=http://192.168.1.10:8770",
    };
    for (size_t i = 0; i < sizeof(outside) / sizeof(outside[0]); i++) {
        WT_EQ(web_fleet_parse_peer(outside[i], &p, err, sizeof(err)), 0);
        WT_EQ(web_fleet_check_peer(&p, 0, err, sizeof(err)), -1);
        WT_HAS(err, "outside the tailnet");
        WT_EQ(web_fleet_check_peer(&p, 1, err, sizeof(err)), 0);
    }
    static const char *const bad[] = {
        "nourl", "=http://100.64.0.1", "bad name=http://100.64.0.1",
        "x=https://100.64.0.1", "x=http://host.example:80", "x=http://100.64.0.1:0",
        "x=http://100.64.0.1:70000", "x=http://100.64.0.1/api/fleet/export",
        "x=http://100.64.0.1:80x", "x=http://100.64.0.1:", "x=http://[::1]:80",
        "x=http://100.64.0.1.5:80", "x=", "x=http://",
        "a234567890123456789012345678901234=http://100.64.0.1",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int rc = web_fleet_parse_peer(bad[i], &p, err, sizeof(err));
        if (rc != -1) fprintf(stderr, "    taken: %s\n", bad[i]);
        WT_EQ(rc, -1);
    }
}

typedef struct {
    web_config_t cfg;
    int          rc;
    char        *err, *ann;
} parsed_t;

static void parse(parsed_t *p, const char *const *args) {
    char *argv[24];
    int argc = 0;
    argv[argc++] = (char *)"slothweb";
    for (int i = 0; args[i] && argc < 23; i++) argv[argc++] = (char *)args[i];
    argv[argc] = NULL;
    char *out = NULL;
    size_t ol = 0, el = 0, al = 0;
    p->err = p->ann = NULL;
    FILE *o = open_memstream(&out, &ol);
    FILE *e = open_memstream(&p->err, &el);
    p->rc = web_config_parse(&p->cfg, argc, argv, o, e);
    fclose(o);
    fclose(e);
    free(out);
    FILE *a = open_memstream(&p->ann, &al);
    if (p->rc == 0) web_config_announce(&p->cfg, a);
    fclose(a);
}

static void done(parsed_t *p) {
    free(p->err);
    free(p->ann);
}

/* The flags. A tailnet peer is quiet; one outside is refused, and with
 * the flag announced; --strict refuses any. */
static void test_peer_flags(void) {
    parsed_t p;
#ifdef WITH_SQLITE
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770",
                                       "--peer-interval-secs", "30", NULL };
    parse(&p, one);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 1);
    WT_EQ(p.cfg.peer_interval_s, 30);
    WT_LACKS(p.ann, "--peer");
    done(&p);
    static const char *const out[] = { "--peer", "x=http://192.0.2.7:8770", NULL };
    parse(&p, out);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer x: http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    /* The flag after the peer: the rule is applied to the whole line. */
    static const char *const forced[] = { "--peer", "x=http://192.0.2.7:8770",
                                          "--peer-allow-outside-tailnet", NULL };
    parse(&p, forced);
    WT_EQ(p.rc, 0);
    WT_HAS(p.ann, "WARNING: --peer x at http://192.0.2.7:8770 is outside the tailnet");
    done(&p);
    static const char *const strict[] = { "--peer", "lab=http://100.80.0.9", "--strict", NULL };
    parse(&p, strict);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--strict refuses --peer.");
    done(&p);
    static const char *const twice[] = { "--peer", "a=http://100.80.0.9", "--peer",
                                         "a=http://100.80.0.10", NULL };
    parse(&p, twice);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "given twice");
    done(&p);
    static const char *const many[] = {
        "--peer", "a=http://100.80.0.1", "--peer", "b=http://100.80.0.2",
        "--peer", "c=http://100.80.0.3", "--peer", "d=http://100.80.0.4",
        "--peer", "e=http://100.80.0.5", "--peer", "f=http://100.80.0.6",
        "--peer", "g=http://100.80.0.7", "--peer", "h=http://100.80.0.8",
        "--peer", "i=http://100.80.0.9", NULL };
    parse(&p, many);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer: at most 8 peers");
    done(&p);
#else
    static const char *const one[] = { "--peer", "lab=http://100.80.0.9:8770", NULL };
    parse(&p, one);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "--peer needs SQLite");
    done(&p);
#endif
    static const char *const iv[] = { "--peer-interval-secs", "5", NULL };
    parse(&p, iv);
    WT_EQ(p.rc, -1);
    WT_HAS(p.err, "want a whole number from 10 to 3600");
    done(&p);
    static const char *const none[] = { NULL };
    parse(&p, none);
    WT_EQ(p.rc, 0);
    WT_EQ(p.cfg.npeer, 0);
    WT_EQ(p.cfg.peer_interval_s, WEB_FLEET_INTERVAL_DEF);
    done(&p);
}

/* Every member a fleet line may carry is a name web_secret.h does not
 * withhold; the positive control is a name it does. Seen red with
 * "username" added to the wifi line's members. */
static void test_members_are_not_secret(void) {
    int names = 0;
    for (size_t i = 0; i < web_fleet_members_n; i++) {
        const char *const *m = web_fleet_members[i];
        WT_ASSERT(web_fleet_members_of(m[0]) == m);
        for (int k = 1; m[k]; k++) {
            names++;
            if (web_sdb_is_secret("fleet", m[k], "TEXT"))
                fprintf(stderr, "    %s.%s is a withheld name\n", m[0], m[k]);
            WT_ASSERT(!web_sdb_is_secret("fleet", m[k], "TEXT"));
        }
    }
    WT_ASSERT(names > 50);
    WT_ASSERT(web_sdb_is_secret("fleet", "username", "TEXT"));
    WT_ASSERT(web_sdb_is_secret("fleet", "pmkid", "TEXT"));
    WT_ASSERT(web_fleet_members_of("eapol") == NULL);
    WT_ASSERT(web_fleet_members_of("cleartext_creds") == NULL);
}

#ifdef WITH_SQLITE

#define T SDB_NOW
#define HR 3600LL
#define DY 86400LL

static char g_dir[TEST_TMP_MAX];
static char g_db[TEST_TMP_MAX + 32], g_store[TEST_TMP_MAX + 32];
static web_store_t   S;
static web_slothdb_t SDB;
static web_frrs_t    FR;

static void rm_dir(void) {
    static const char *const names[] = {
        "sloth.db", "sloth.db-wal", "sloth.db-shm", "sloth.db-journal",
        "slothweb.db", "slothweb.db-wal", "slothweb.db-shm", "slothweb.db-journal",
    };
    char p[TEST_TMP_MAX + 32];
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        snprintf(p, sizeof(p), "%s/%s", g_dir, names[i]);
        unlink(p);
    }
    rmdir(g_dir);
}

static int sql_on(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    int rc = sqlite3_open(path, &h);
    if (rc == SQLITE_OK) rc = sqlite3_exec(h, sql, NULL, NULL, NULL);
    if (rc != SQLITE_OK) fprintf(stderr, "    sql: %s\n", sqlite3_errmsg(h));
    sqlite3_close(h);
    return rc == SQLITE_OK ? 0 : -1;
}

static long long q1(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        else
            fprintf(stderr, "    q1: %s\n", sqlite3_errmsg(h));
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

/* A sloth.db with sdb_seed()'s scenario (its cleartext credential among
 * it: the username alice-secret-user in cleartext_creds, in an alert's
 * key and in its detail) and, in the tables no export statement may
 * read, the other things that must never travel: EAPOL rows, a RADIUS
 * identity, an MQTT username, an RDP cookie. slothweb.db with a triage
 * decision whose note and author must stay here. */
static void up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-fleet-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(sdb_seed(g_db), 0);
    char sql[2048];
    snprintf(sql, sizeof(sql),
        "INSERT INTO eapol_events (bssid,sta_mac,ts,msg_num,ssid,has_pmkid,"
        "handshake_complete,first_seen,last_seen) VALUES"
        " ('0e:ee:ee:ee:ee:01','02:ee:ee:ee:ee:02',%lld,2,'eapol-marker-ssid',1,1,%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,identity_leaks,last_identity,first_seen,"
        "last_seen) VALUES ('0e:ee:ee:ee:ee:03',1,'radius-identity-marker',%lld,%lld);"
        "INSERT INTO mqtt_flows (src_ip,dst_ip,connect_count,last_username,first_seen,"
        "last_seen) VALUES ('10.0.4.1','10.0.4.2',1,'mqtt-user-marker',%lld,%lld);"
        "INSERT INTO rdp_flows (src_ip,dst_ip,connect_req_count,last_cookie,proto_mask,"
        "first_seen,last_seen) VALUES ('10.0.4.3','10.0.4.4',1,'mstshash=rdp-marker',1,"
        "%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,technique,"
        "match_ip,match_port,count) VALUES ('pmkid:0e:ee:ee:ee:ee:01:deadbeefcafe',%lld,"
        "%lld,5,1,'PMKID exposed','pmkid=deadbeefcafe0123','T1557',NULL,NULL,1);",
        T - 50, T - 50, T - 50, T - 45, T - 44, T - 40, T - 30, T - 40, T - 30, T - 70,
        T - 60);
    WT_EQ(sdb_exec(g_db, sql), 0);
    web_slothdb_init(&SDB, g_db, NULL);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    snprintf(sql, sizeof(sql),
        "INSERT INTO triage (subject,finding,type,addr,port,first_seen,state,ts,note,"
        "who,peer) VALUES ('x12:%lld',NULL,12,'10.0.1.5',21,%lld,4,%lld,"
        "'triage-note-marker','op-marker','127.0.0.1'),"
        " ('x0:%lld',NULL,0,'10.0.0.7',0,%lld,1,%lld,'','','127.0.0.1');",
        T - 100, T - 100, T - 90, T - 30 * DY, T - 30 * DY, T - 20 * DY);
    WT_EQ(sql_on(g_store, sql), 0);
    WT_EQ(web_frrs_init(&FR, &S, NULL, 1, err, sizeof(err)), 0);
}

static void down(void) {
    web_frrs_destroy(&FR);
    web_slothdb_destroy(&SDB);
    web_store_close(&S);
    rm_dir();
}

static char *export(long long since_q, const char *query, int *status) {
    web_fleet_src_t src = { &SDB, NULL, NULL, &FR };
    char q[64];
    if (!query) snprintf(q, sizeof(q), "since=%lld", since_q);
    char *body = NULL;
    size_t len = 0;
    WT_EQ(web_fleet_export_route(&src, query ? query : q, T, &body, &len, status), 0);
    if (!body) return NULL;
    char *t = realloc(body, len + 1);
    if (!t) { free(body); return NULL; }
    t[len] = '\0';
    return t;
}

/* The export over the seeded files: the device, its association and its
 * probe list, the AP, the alerts by type, title and fingerprint, the
 * verdict by descriptor and state; and nothing it must not carry. Every
 * line decodes, every member is listed, and the importer takes it.
 * The username's absence was seen red with web_sdb_alerts_between()'s
 * statement selecting alerts.detail in place of the title and
 * alerts.detail put on M4's allow-list (the reader's two guards changed
 * together: either alone still holds it out), "alice-detail" then in the
 * body; the note's with web_frrs_verdicts() reading note into addr. */
static void test_export_withholds_secrets(void) {
    up();
    int st = 0;
    char *b = export(0, NULL, &st);
    WT_EQ(st, 200);
    WT_ASSERT(b != NULL);
    if (!b) { down(); return; }
    WT_HAS(b, "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":");
    WT_HAS(b, ",\"sloth_db\":\"open\",\"lat\":null,");
    WT_HAS(b, "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\","
              "\"ssid\":\"HomeNet\",\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\","
              "\"is_ap\":false,");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"HomeNet\",");
    WT_HAS(b, "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"CafeFree\",");
    WT_HAS(b, "{\"type\":\"alert\",\"alert_type\":");
    WT_HAS(b, ",\"title\":\"FTP login in cleartext\",\"ip\":\"10.0.1.5\",\"sev\":2,\"count\":3,");
    WT_HAS(b, ",\"title\":\"PMKID exposed\",");
    WT_HAS(b, "{\"type\":\"verdict\",\"alert_type\":");
    WT_HAS(b, ",\"addr\":\"10.0.1.5\",\"port\":21,");
    WT_HAS(b, ",\"state\":\"known\",");
    WT_HAS(b, "\"complete\":true}\n");
    /* The things that must never travel. */
    static const char *const never[] = {
        "alice", "cred:", "user=", "eapol-marker", "02:ee:ee:ee:ee:02",
        "radius-identity", "mqtt-user", "mstshash", "rdp-marker", "deadbeef",
        "pmkid:", "triage-note-marker", "op-marker", "127.0.0.1",
    };
    for (size_t i = 0; i < sizeof(never) / sizeof(never[0]); i++) WT_LACKS(b, never[i]);
    /* Every line decodes and lists only its own members. */
    web_jrec_t *rec = malloc(sizeof(*rec));
    int lines = 0;
    for (char *p = b; rec && *p;) {
        char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        WT_EQ(web_jl_parse(p, n, rec), WEB_JL_OK);
        const char *const *m = web_fleet_members_of(web_jl_str(rec, "type"));
        WT_ASSERT(m != NULL);
        for (int i = 0; m && i < rec->n; i++) {
            int ok = !strcmp(rec->f[i].key, "type");
            for (int k = 1; m[k] && !ok; k++) ok = !strcmp(m[k], rec->f[i].key);
            WT_ASSERT(ok);
        }
        lines++;
        p = nl ? nl + 1 : p + n;
    }
    free(rec);
    WT_ASSERT(lines >= 15);
    /* The importer takes what the exporter writes. */
    web_fleet_t f;
    web_fleet_peer_cfg_t pc;
    char err[200];
    WT_EQ(web_fleet_parse_peer("self=http://100.64.0.1:8770", &pc, err, sizeof(err)), 0);
    web_fleet_init(&f, &pc, 1, 60, 0, &S);
    long long rows = 0, rts = 0;
    int rc = web_fleet_ingest(&f, 0, b, strlen(b), T, 0, &rows, &rts, err, sizeof(err));
    if (rc) fprintf(stderr, "    ingest: %s\n", err);
    WT_EQ(rc, 0);
    WT_EQ(rts, T);
    WT_ASSERT(rows >= 12);
    web_fleet_destroy(&f);
    free(b);
    down();
}

/* `since`: a row last seen before it is not sent; the parameter is
 * checked. Seen red with the export reading from 0 whatever since
 * says. */
static void test_export_since(void) {
    up();
    int st = 0;
    char *b = export(T - 2 * HR, NULL, &st);
    WT_EQ(st, 200);
    if (b) {
        WT_HAS(b, "\"mac\":\"da:a1:19:00:00:01\"");       /* seen 1 h ago */
        WT_HAS(b, "\"mac\":\"00:11:22:33:44:55\"");       /* 10 s ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:02\"");     /* 30 h ago */
        WT_LACKS(b, "\"mac\":\"f2:11:22:00:00:06\"");     /* 23 h ago */
        WT_LACKS(b, "\"mac\":\"da:a1:19:00:00:07\"");     /* 24 h ago */
        WT_LACKS(b, "\"state\":\"false\"");               /* decided 20 d ago */
        WT_HAS(b, "\"state\":\"known\"");
    }
    free(b);
    b = export(0, "since=12x", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "bad_since");
    free(b);
    b = export(0, "since=1&limit=2", &st);
    WT_EQ(st, 400);
    if (b) WT_HAS(b, "unknown_parameter");
    free(b);
    b = export(0, "from=1", &st);
    WT_EQ(st, 400);
    free(b);
    b = export(0, "", &st);
    WT_EQ(st, 200);
    if (b) WT_HAS(b, "\"mac\":\"da:a1:19:00:00:02\"");
    free(b);
    /* Through the route table: JSON Lines, GET only. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.sdb = &SDB;
    m4.frrs = &FR;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/export");
    snprintf(rq.query, sizeof(rq.query), "since=%lld", T - 60);
    snprintf(rq.host, sizeof(rq.host), "100.64.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 200);
    out[r.out_len] = '\0';
    WT_HAS(out, "Content-Type: application/x-ndjson\r\n");
    WT_ASSERT(r.body_owned != NULL && r.body_len > 0);
    free(r.body_owned);
    rq.is_head = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 405);
    down();
}

/* ── the pull, from a loopback server ───────────────────────────────── */

typedef struct {
    int         lfd;
    const char *resp;
    size_t      len;
    char        req[512];
} srv_t;

static void *serve_once(void *arg) {
    srv_t *s = arg;
    int fd = accept(s->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    size_t n = 0;
    while (n + 1 < sizeof(s->req)) {
        ssize_t k = recv(fd, s->req + n, sizeof(s->req) - 1 - n, 0);
        if (k <= 0) break;
        n += (size_t)k;
        s->req[n] = '\0';
        if (strstr(s->req, "\r\n\r\n")) break;
    }
    for (size_t o = 0; o < s->len;) {
        ssize_t k = send(fd, s->resp + o, s->len - o, MSG_NOSIGNAL);
        if (k <= 0) break;
        o += (size_t)k;
    }
    close(fd);
    return NULL;
}

static web_fleet_t F;

/* One pull of peer 0 against a server answering resp (headers added
 * here unless raw). The pull's return. */
static int pull_with(const char *resp, int raw, char *req, size_t reqsz) {
    srv_t s;
    memset(&s, 0, sizeof(s));
    s.lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    WT_EQ(bind(s.lfd, (struct sockaddr *)&sa, sizeof(sa)), 0);
    WT_EQ(listen(s.lfd, 1), 0);
    socklen_t sl = sizeof(sa);
    getsockname(s.lfd, (struct sockaddr *)&sa, &sl);
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    char *full = NULL;
    if (raw) {
        s.resp = resp;
        s.len = strlen(resp);
    } else {
        size_t bl = strlen(resp);
        full = malloc(bl + 256);
        int hl = snprintf(full, 256, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n"
                          "Content-Length: %zu\r\nConnection: close\r\n\r\n", bl);
        memcpy(full + hl, resp, bl + 1);
        s.resp = full;
        s.len = (size_t)hl + bl;
    }
    pthread_t th;
    pthread_create(&th, NULL, serve_once, &s);
    int rc = web_fleet_pull_one(&F, 0, T);
    pthread_join(th, NULL);
    close(s.lfd);
    free(full);
    if (req) snprintf(req, reqsz, "%s", s.req);
    return rc;
}

#define HDR(gen) "{\"type\":\"fleet_export\",\"fleet_export_version\":1,\"generated\":" #gen \
    ",\"since\":0,\"site_label\":\"beta-site\",\"slothweb_version\":\"1.8.6\"," \
    "\"sloth_version\":null,\"sloth_db\":\"open\",\"lat\":41.8781136,\"lon\":-87.6297982," \
    "\"alt_m\":181.0,\"pos_source\":\"fixed\",\"pos_ts\":" #gen ",\"pos_age_s\":0}\n"

static const char GOOD[] =
    HDR(1792627000)
    "{\"type\":\"gnss\",\"gps_state\":\"fixed\",\"sats_in_view\":12,\"sats_used\":9,"
    "\"cn0_mean\":38.5,\"time_offset_ms\":null,\"jam\":3,\"ts\":1792626990}\n"
    "{\"type\":\"wifi\",\"mac\":\"DA:A1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"HomeNet\","
    "\"rssi\":-48,\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false,\"first_seen\":1792600000,"
    "\"last_seen\":1792626000}\n"
    "{\"type\":\"ble\",\"addr\":\"c0:ff:ee:00:00:01\",\"addr_type\":\"r\",\"name\":\"tag\","
    "\"class\":\"tag\",\"rssi\":-70,\"first_seen\":1792620000,\"last_seen\":1792626500}\n"
    "{\"type\":\"ap\",\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"ssid\":\"HomeNet\",\"channel\":6,"
    "\"enc\":\"WPA2\",\"vendor\":null,\"rssi\":-40,\"first_seen\":1792500000,"
    "\"last_seen\":1792626900}\n"
    "{\"type\":\"probe\",\"mac\":\"da:a1:19:00:00:01\",\"ssid\":\"W9FJC-home\","
    "\"first_seen\":1792610000,\"last_seen\":1792626000}\n"
    "{\"type\":\"alert\",\"alert_type\":\"EVIL_TWIN\",\"ty\":18,\"fingerprint\":"
    "\"0123456789abcdef\",\"title\":\"Evil twin\",\"ip\":null,\"sev\":1,\"count\":4,"
    "\"first_seen\":1792620000,\"last_seen\":1792626000}\n"
    "{\"type\":\"verdict\",\"alert_type\":\"EVIL_TWIN\",\"addr\":\"aa:bb:cc:dd:ee:ff\","
    "\"port\":0,\"alert_first_seen\":1792620000,\"state\":\"known\",\"ts\":1792626100}\n"
    "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:99\",\"vendor\":null,\"ssid\":null,"
    "\"rssi\":null,\"bssid\":null,\"is_ap\":false,\"first_seen\":1700000000,"
    "\"last_seen\":1700000000}\n"
    "{\"type\":\"fleet_end\",\"rows\":7,\"wifi\":2,\"ble\":1,\"ap\":1,\"probe\":1,\"alert\":1,"
    "\"verdict\":1,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

/* The second answer: the device again, heard earlier and later than the
 * first said, and nothing else. */
static const char GOOD2[] =
    HDR(1792627600)
    "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"CafeFree\","
    "\"rssi\":-60,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792500000,"
    "\"last_seen\":1792627500}\n"
    "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
    "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
    "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
    "\"complete\":true}\n";

static void pull_up(void) {
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-pull-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_store, sizeof(g_store), "%s/slothweb.db", g_dir);
    char err[512];
    WT_EQ(web_store_open(&S, g_store, err, sizeof(err)), 0);
    web_fleet_peer_cfg_t pc;
    WT_EQ(web_fleet_parse_peer("beta=http://127.0.0.1:1", &pc, err, sizeof(err)), 0);
    web_fleet_init(&F, &pc, 1, 60, 1, &S);
    F.connect_ms = 2000;
    F.read_ms = 5000;
    /* The pull thread's connection, without the thread: the tests step
     * the pull themselves. */
    WT_EQ(web_store_open_aux(&S, &F.wr, err, sizeof(err)), 0);
}

static void pull_down(void) {
    web_fleet_destroy(&F);
    web_store_close(&S);
    rm_dir();
}

static long long sightings(void) {
    return q1(g_store, "SELECT COUNT(*) FROM peer_sightings");
}

/* A good answer is stored whole: the site and its position, each kind
 * keyed canonically (the upper-case MAC lower-cased), a row older than
 * WEB_FLEET_KEEP_S by the peer's own clock dropped by the bound; the
 * first request asks since=0. The second asks from the peer's clock
 * less the overlap, and widens the device's first and last seen while
 * taking its newest label. Seen red with the upsert's first_seen CASE
 * replaced by excluded.first_seen (and with the age bound's DELETE
 * removed: 02:..:99 kept). */
static void test_pull_good_and_upsert(void) {
    pull_up();
    char req[512];
    int rc = pull_with(GOOD, 0, req, sizeof(req));
    if (rc) fprintf(stderr, "    pull: %s\n", F.peer[0].last_error);
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=0 HTTP/1.1\r\n");
    WT_HAS(req, "Host: 127.0.0.1:");
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE peer='beta' AND"
                      " label='beta-site' AND pos_source='fixed' AND lat>41.87 AND"
                      " lat<41.88 AND remote_ts=1792627000 AND rows_last=7 AND"
                      " last_error='' AND last_ok>0"), 1);
    WT_EQ(sightings(), 7);    /* 6 kinds and the receiver; 02:..:99 aged out */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='HomeNet' AND vendor='Apple'"
                      " AND rssi=-48 AND first_seen=1792600000 AND last_seen=1792626000"
                      " AND extra='{\"bssid\":\"aa:bb:cc:dd:ee:ff\",\"is_ap\":false}'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key='02:00:00:00:00:99'"), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='probe' AND"
                      " key='da:a1:19:00:00:01|W9FJC-home'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='verdict' AND"
                      " key='EVIL_TWIN|aa:bb:cc:dd:ee:ff|0|1792620000' AND label='known'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='gnss' AND"
                      " key='receiver' AND label='fixed'"), 1);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='alert' AND"
                      " key='0123456789abcdef' AND label='Evil twin'"), 1);

    rc = pull_with(GOOD2, 0, req, sizeof(req));
    WT_EQ(rc, 0);
    WT_HAS(req, "GET /api/fleet/export?since=1792626880 HTTP/1.1\r\n");
    WT_EQ(sightings(), 7);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND label='CafeFree' AND rssi=-60"
                      " AND first_seen=1792500000 AND last_seen=1792627500"), 1);
    /* An answer reporting less (an older last seen, a later first seen)
     * narrows nothing. */
    static const char OLD[] =
        HDR(1792627700)
        "{\"type\":\"wifi\",\"mac\":\"da:a1:19:00:00:01\",\"vendor\":\"Apple\",\"ssid\":\"x\","
        "\"rssi\":-61,\"bssid\":null,\"is_ap\":false,\"first_seen\":1792610000,"
        "\"last_seen\":1792611000}\n"
        "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,"
        "\"verdict\":0,\"truncated_wifi\":false,\"truncated_ble\":false,\"truncated_ap\":false,"
        "\"truncated_probe\":false,\"truncated_alert\":false,\"truncated_verdict\":false,"
        "\"complete\":true}\n";
    WT_EQ(pull_with(OLD, 0, NULL, 0), 0);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE kind='wifi' AND"
                      " key='da:a1:19:00:00:01' AND first_seen=1792500000 AND"
                      " last_seen=1792627500"), 1);
    /* /api/health and /api/fleet/peers. */
    web_m4_t m4;
    memset(&m4, 0, sizeof(m4));
    m4.fleet = &F;
    web_health_t h;
    memset(&h, 0, sizeof(h));
    h.wall_s = T + 30;
    h.m4 = &m4;
    static char out[65536];
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/health");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1:8770");
    rq.host_count = 1;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, ",\"fleet\":{\"export\":true,\"export_version\":1,\"interval_s\":60,"
                "\"outside_tailnet\":true,\"peers\":[{\"name\":\"beta\",\"url\":"
                "\"http://127.0.0.1:1\",\"last_ok_age_s\":30,\"last_attempt_age_s\":30,"
                "\"last_error\":null,\"rows\":1,\"pulls\":3,\"failures\":0}]}");
    snprintf(rq.path, sizeof(rq.path), "/api/fleet/peers");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_EQ(r.status, 200);
    WT_HAS(out, "{\"export\":true,\"interval_s\":60,\"store\":true,\"peers\":[{\"name\":"
                "\"beta\",\"configured\":true,\"url\":\"http://127.0.0.1:1\",\"label\":"
                "\"beta-site\",");
    WT_HAS(out, ",\"lat\":41.8781136,\"lon\":-87.6297982,\"alt_m\":181.0,\"pos_source\":"
                "\"fixed\",");
    WT_HAS(out, ",\"counts\":{\"alert\":1,\"ap\":1,\"ble\":1,\"gnss\":1,\"probe\":1,"
                "\"verdict\":1,\"wifi\":1}}");
    snprintf(rq.query, sizeof(rq.query), "x=1");
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    WT_EQ(r.status, 400);
    pull_down();
}

/* Each refused answer leaves every sighting and the last good pull as
 * they were, and says why. Seen red with the response-size checks in
 * http_get() removed (the oversize answer stored), with the ingest's
 * "no end line" refusal removed (that answer stored) and with
 * members_ok() returning 1 (the username line taken). */
static void test_pull_refusals(void) {
    pull_up();
    WT_EQ(pull_with(GOOD, 0, NULL, 0), 0);
    long long before = sightings();
    WT_EQ(before, 7);
    static const char FP[] = "SELECT COUNT(*) FROM peer_sites WHERE remote_ts=1792627000"
                             " AND rows_last=7 AND last_ok=" "1792627200";
    WT_EQ(q1(g_store, FP), 1);
    char line[512];
    struct { const char *what, *resp; int raw; const char *why; } cases[] = {
        { "malformed", HDR(1792627900) "{\"type\":\"wifi\",\"mac\":\n", 0, "line 2" },
        { "username member", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"username\":\"u-marker\","
          "\"first_seen\":1,\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":1,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "may not carry" },
        { "no end line", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n", 0, "no end line" },
        { "count", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"02:00:00:00:00:01\",\"first_seen\":1,"
          "\"last_seen\":2}\n"
          "{\"type\":\"fleet_end\",\"rows\":1,\"wifi\":2,\"ble\":0,\"ap\":0,\"probe\":0,"
          "\"alert\":0,\"verdict\":0,\"complete\":true}\n", 0, "wifi count" },
        { "version", "{\"type\":\"fleet_export\",\"fleet_export_version\":2,"
          "\"generated\":1792627900}\n{\"type\":\"fleet_end\",\"rows\":0,\"wifi\":0,"
          "\"ble\":0,\"ap\":0,\"probe\":0,\"alert\":0,\"verdict\":0,\"complete\":true}\n",
          0, "no fleet_export header" },
        { "bad mac", HDR(1792627900)
          "{\"type\":\"wifi\",\"mac\":\"not-a-mac\",\"first_seen\":1,\"last_seen\":2}\n", 0,
          "out of range" },
        { "status", "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n", 1,
          "HTTP status 503" },
        { "cut short", "HTTP/1.1 200 OK\r\nContent-Length: 9999\r\n\r\n"
          HDR(1792627900), 1, "cut short" },
        { "not http", "SSH-2.0-OpenSSH_9.6\r\n", 1, "not an HTTP response" },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        int rc = pull_with(cases[i].resp, cases[i].raw, NULL, 0);
        if (rc == 0) fprintf(stderr, "    taken: %s\n", cases[i].what);
        WT_EQ(rc, -1);
        snprintf(line, sizeof(line), "%s", F.peer[0].last_error);
        if (!strstr(line, cases[i].why))
            fprintf(stderr, "    %s: \"%s\"\n", cases[i].what, line);
        WT_HAS(line, cases[i].why);
        WT_EQ(sightings(), before);
        WT_EQ(q1(g_store, FP), 1);
        WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                          " key LIKE '02:00:00:00:00:01%'"), 0);
    }
    /* The refusal is kept beside the last good pull. */
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sites WHERE last_error LIKE"
                      " '%not an HTTP response%'"), 1);
    /* Oversize: past resp_max, refused, never cut to fit. */
    /* A well-formed answer of 60 probe lines, some 7 KB: only its size
     * is wrong. */
    F.resp_max = 1024;
    char *huge = malloc(16384);
    size_t o = (size_t)snprintf(huge, 16384, "%s", HDR(1792627900));
    for (int i = 0; i < 60; i++)
        o += (size_t)snprintf(huge + o, 16384 - o, "{\"type\":\"probe\",\"mac\":"
                              "\"02:00:00:00:00:01\",\"ssid\":\"net-%02d\",\"first_seen\":1792620000,"
                              "\"last_seen\":1792626000}\n", i);
    snprintf(huge + o, 16384 - o, "{\"type\":\"fleet_end\",\"rows\":60,\"wifi\":0,"
             "\"ble\":0,\"ap\":0,\"probe\":60,\"alert\":0,\"verdict\":0,"
             "\"complete\":true}\n");
    WT_ASSERT(strlen(huge) > 4096);
    WT_EQ(pull_with(huge, 0, NULL, 0), -1);
    WT_HAS(F.peer[0].last_error, "over 1024 bytes");
    WT_EQ(sightings(), before);
    WT_EQ(q1(g_store, "SELECT COUNT(*) FROM peer_sightings WHERE"
                      " key LIKE '02:00:00:00:00:01%'"), 0);
    free(huge);
    F.resp_max = WEB_FLEET_RESP_MAX;
    /* And a good one after them all is stored. */
    WT_EQ(pull_with(GOOD2, 0, NULL, 0), 0);
    WT_EQ(F.peer[0].last_error[0], '\0');
    WT_EQ(F.peer[0].failures, 10);
    pull_down();
}

/* No peer reachable: a refused connection is an error in words, and the
 * thread's start and stop are clean with a peer configured (the pull
 * runs at once and fails, the stop is prompt). */
static void test_pull_unreachable_and_thread(void) {
    pull_up();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(s, (struct sockaddr *)&sa, sizeof(sa));
    socklen_t sl = sizeof(sa);
    getsockname(s, (struct sockaddr *)&sa, &sl);
    close(s);                         /* nothing listens there now */
    F.peer[0].cfg.port = ntohs(sa.sin_port);
    WT_EQ(web_fleet_pull_one(&F, 0, T), -1);
    WT_HAS(F.peer[0].last_error, "connect: ");
    WT_EQ(sightings(), 0);
    web_fleet_destroy(&F);
    web_fleet_peer_cfg_t pc = F.peer[0].cfg;
    web_fleet_init(&F, &pc, 1, 3600, 1, &S);
    char err[256];
    WT_EQ(web_fleet_start(&F, err, sizeof(err)), 0);
    WT_EQ(F.started, 1);
    unsigned long pulls = 0;
    for (int i = 0; i < 500 && !pulls; i++) {
        pthread_mutex_lock(&F.mu);
        pulls = F.peer[0].pulls;
        pthread_mutex_unlock(&F.mu);
        if (!pulls) usleep(10000);
    }
    WT_ASSERT(pulls >= 1);
    web_fleet_stop(&F);
    WT_EQ(F.started, 0);
    pull_down();
}

#endif

void run_fleet_tests(void) {
    WT_RUN(test_peer_urls);
    WT_RUN(test_peer_flags);
    WT_RUN(test_members_are_not_secret);
#ifdef WITH_SQLITE
    WT_RUN(test_export_withholds_secrets);
    WT_RUN(test_export_since);
    WT_RUN(test_pull_good_and_upsert);
    WT_RUN(test_pull_refusals);
    WT_RUN(test_pull_unreachable_and_thread);
#endif
}
