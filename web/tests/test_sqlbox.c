/* The SQL box (#163, M5; web_sqlbox.h) and spec §12's M5 acceptance:
 *
 *   - the text rules (one sql= parameter, decoded; SELECT or WITH
 *     first; valid UTF-8; no control byte; the length cap), pure;
 *   - without --web-allow-sql there is no /api/query or /api/recipes
 *     (404) and the page keeps the box hidden;
 *   - the acceptance: a sloth.db GENERATED from src/db_schema.c in a
 *     fresh mkdtemp() directory (never a committed fixture), seeded so
 *     every recipe docs/wiki/sqlite-schema.md holds returns rows; each
 *     recipe run through /api/query over a real loopback socket and
 *     through the sqlite3 C API directly on the same file, the two
 *     answers identical; and through the sqlite3 command-line shell as
 *     well when one is on PATH (CI may not have it; the library is the
 *     honest stand-in). The two recipes that read a withheld column
 *     (alerts.detail, cleartext_creds.username) and the one that reads
 *     dbstat are refused naming it;
 *   - every write, every DDL, PRAGMA, ATTACH, a CTE with a DML tail and
 *     a second statement refused, and the file byte for byte and its
 *     directory as they were afterwards;
 *   - the withheld columns: every word of tests/test_db.c's guardrail
 *     is on the list, every TEXT/BLOB column of sloth's live schema
 *     named for one is refused, the explicit ones too, and the
 *     integer flags and counts that carry those words are not;
 *   - the limits: 10,000 rows, the byte bound, the 5 s budget (a short
 *     one here), a value over the length limit, the function list;
 *   - one query at a time: a second /api/query while one runs is a
 *     503 "busy", the box is free again once the answer is sent, and a
 *     client that leaves while its statement runs frees it too, as does
 *     a slot the server timed out before the answer came;
 *   - the rest after each statement, and a writer at sloth's pace whose
 *     -wal stays within twice its no-reader size while a client loops
 *     the box. */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "sdb_gen.h"
#include "web_assets.h"
#include "web_recipes.h"
#include "web_routes.h"
#include "web_secret.h"
#include "web_server.h"
#include "web_sqlbox.h"
#include "wtest.h"
#include "wt_tmp.h"

/* ── the text (every build) ─────────────────────────────────────────── */

static void test_param(void) {
    char sql[WEB_SQL_MAX_BYTES + 1];
    size_t n;
    const char *why;
    WT_EQ(web_sqlbox_param("sql=SELECT%201", sql, sizeof(sql), &n, &why), 0);
    WT_ASSERT(!strcmp(sql, "SELECT 1"));
    WT_EQ(n, 8);
    WT_EQ(web_sqlbox_param("sql=SELECT+mac+FROM+devices", sql, sizeof(sql), &n, &why), 0);
    WT_ASSERT(!strcmp(sql, "SELECT mac FROM devices"));
    WT_EQ(web_sqlbox_param("sql=1%2B1", sql, sizeof(sql), &n, &why), 0);
    WT_ASSERT(!strcmp(sql, "1+1"));
    static const char *const bad[][2] = {
        { "", "missing_sql" }, { "q=SELECT", "unknown_parameter" },
        { "sql=a&sql=b", "repeated_parameter" }, { "sql=%zz", "bad_escape" },
        { "sql=%4", "bad_escape" }, { "sql=", "empty_value" },
        { "sql", "bad_query" }, { "sql=a&", "bad_query" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        why = NULL;
        WT_EQ(web_sqlbox_param(bad[i][0], sql, sizeof(sql), &n, &why), -1);
        WT_ASSERT(why && !strcmp(why, bad[i][1]));
    }
    /* One byte past the cap, decoded. */
    static char q[3 * WEB_SQL_MAX_BYTES + 16];
    size_t o = (size_t)snprintf(q, sizeof(q), "sql=");
    for (int i = 0; i <= WEB_SQL_MAX_BYTES; i++) q[o++] = 'a';
    q[o] = '\0';
    WT_EQ(web_sqlbox_param(q, sql, sizeof(sql), &n, &why), -1);
    WT_ASSERT(!strcmp(why, "too_long"));
    q[o - 1] = '\0';
    WT_EQ(web_sqlbox_param(q, sql, sizeof(sql), &n, &why), 0);
    WT_EQ(n, WEB_SQL_MAX_BYTES);
}

/* Each refusal seen red: "not_select" with keyword_at() answering 1,
 * the comment cases with skip_blank() not skipping "--" comments, and
 * "control_byte" with the control test removed. */
static void test_precheck(void) {
    static const char *const ok[] = {
        "SELECT 1", "select 1", "  \n\tSELECT 1", "WITH x AS (SELECT 1) SELECT * FROM x",
        "-- a comment\nSELECT 1", "/* c */ SELECT 1", "/**/select(1)",
        "SELECT 'caf\xc3\xa9'",
    };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++) {
        const char *why = NULL;
        int rc = web_sqlbox_precheck(ok[i], strlen(ok[i]), &why);
        if (rc) fprintf(stderr, "    refused: %s (%s)\n", ok[i], why);
        WT_EQ(rc, 0);
    }
    static const char *const no[][2] = {
        { "INSERT INTO devices VALUES (1)", "not_select" },
        { "PRAGMA writable_schema=1", "not_select" },
        { "EXPLAIN SELECT 1", "not_select" },
        { "ATTACH DATABASE 'x' AS y", "not_select" },
        { "VACUUM", "not_select" }, { "BEGIN", "not_select" },
        { "SELECTX 1", "not_select" }, { "WITHOUT", "not_select" },
        { "-- SELECT 1", "not_select" }, { "/* SELECT 1 */", "not_select" },
        { "/* SELECT", "not_select" }, { " ;SELECT 1", "not_select" },
        { "SELECT '\x01'", "control_byte" }, { "SELECT 1\x7f", "control_byte" },
        { "SELECT '\xc3'", "bad_utf8" }, { "SELECT '\xed\xa0\x80'", "bad_utf8" },
    };
    for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++) {
        const char *why = NULL;
        WT_EQ(web_sqlbox_precheck(no[i][0], strlen(no[i][0]), &why), -1);
        if (!why || strcmp(why, no[i][1]))
            fprintf(stderr, "    %s: %s, not %s\n", no[i][0], why ? why : "-", no[i][1]);
        WT_ASSERT(why && !strcmp(why, no[i][1]));
    }
    const char *why = NULL;
    WT_EQ(web_sqlbox_precheck("SELECT 1\0; DROP", 15, &why), -1);   /* a NUL */
    WT_ASSERT(why && !strcmp(why, "control_byte"));
    WT_EQ(web_sqlbox_blank("  -- x\n /* y */ \n", 17), 1);
    WT_EQ(web_sqlbox_blank(" ; ", 3), 0);
    WT_EQ(web_sqlbox_blank(" /* open", 8), 1);
}

/* Without --web-allow-sql: no route, and the page's box stays hidden.
 * The 404s seen red with route_query() reached without the enabled
 * test; the hidden attribute with it removed from index.html. */
static void test_off_by_default(void) {
    web_health_t h;
    memset(&h, 0, sizeof(h));
    web_sqlbox_t off;
    WT_EQ(web_sqlbox_init(&off, NULL, 0), 0);
    static char out[65536];
    static const char *const paths[] = { "/api/query", "/api/recipes" };
    for (int with = 0; with < 2; with++) {
        h.sql = with ? &off : NULL;
        for (size_t i = 0; i < 2; i++) {
            web_req_t rq;
            web_resp_t r;
            memset(&rq, 0, sizeof(rq));
            snprintf(rq.path, sizeof(rq.path), "%s", paths[i]);
            snprintf(rq.query, sizeof(rq.query), "sql=SELECT%%201");
            snprintf(rq.host, sizeof(rq.host), "127.0.0.1");
            rq.host_count = 1;
            WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
            WT_EQ(r.status, 404);
            WT_EQ(r.kind, WEB_R_ONESHOT);
        }
    }
    WT_EQ(web_sqlbox_busy(&off), 0);
    web_sqlbox_destroy(&off);
    const char *p = (const char *)web_page;
    WT_HAS(p, "<section class=\"panel\" id=\"h-sql\" hidden>");
    WT_HAS(p, "Q.on = !!(h.sql && typeof h.sql === \"object\");");
    WT_HAS(p, "$(\"h-sql\").hidden = !Q.on;");
    WT_HAS(p, "if (Q.on) recipes();");
    /* /api/health says "sql":false. */
    web_req_t rq;
    web_resp_t r;
    memset(&rq, 0, sizeof(rq));
    snprintf(rq.path, sizeof(rq.path), "/api/health");
    snprintf(rq.host, sizeof(rq.host), "127.0.0.1");
    rq.host_count = 1;
    h.sql = NULL;
    WT_EQ(web_route(&rq, &h, 1, out, sizeof(out), &r), 0);
    out[r.out_len] = '\0';
    WT_HAS(out, ",\"sql\":false,");
}

/* The page's box: its elements and the fetches it makes. Seen red with
 * q-run renamed in index.html. */
static void test_page_carries_the_box(void) {
    const char *p = (const char *)web_page;
    static const char *const ids[] = { "h-sql", "q-recipe", "q-sql", "q-run",
                                       "q-out", "q-note" };
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        char want[64], a[64], b[64];
        snprintf(want, sizeof(want), "id=\"%s\"", ids[i]);
        WT_HAS(p, want);
        snprintf(a, sizeof(a), "$(\"%s\")", ids[i]);
        snprintf(b, sizeof(b), "set(\"%s\",", ids[i]);
        WT_ASSERT(strstr(p, a) || strstr(p, b));
    }
    WT_HAS(p, "fetch(\"/api/query?sql=\" + encodeURIComponent(sql), { cache: \"no-store\" })");
    WT_HAS(p, "getJSON(\"/api/recipes\")");
    /* Results are cells of text. */
    WT_HAS(p, "r.appendChild(el(\"td\", v === null ? \"nul\" : \"\", cellText(v)));");
}

#ifndef WITH_SQLITE

void run_sqlbox_tests(void) {
    WT_RUN(test_param);
    WT_RUN(test_precheck);
    WT_RUN(test_off_by_default);
    WT_RUN(test_page_carries_the_box);
}

#else

#include <sqlite3.h>

static char g_dir[TEST_TMP_MAX];
static char g_db[128];

/* 2026-07-28 02:00 and 04:00 UTC: the "who was here" recipe's window. */
#define WWH_FROM 1785204000LL
#define WWH_TO   1785211200LL

/* The acceptance file: sloth's own DDL (rollback-journal mode, so a
 * read-only reader leaves no side file), and rows for every recipe. */
static int seed_recipes(const char *path) {
    char sql[8192];
    const long long N = SDB_NOW, H = 3600, D = 86400;
    int n = snprintf(sql, sizeof(sql),
        "INSERT INTO sessions (id, started, ended, site_label) VALUES"
        " (1, %lld, %lld, 'first'), (2, %lld, %lld, 'second'),"
        " (3, %lld, NULL, 'now');"
        "INSERT INTO devices (mac,ip,hostname,vendor,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:01','10.0.0.1','<b>\"x\"</b>','Acme',%lld,%lld),"
        " ('02:00:00:00:00:02',NULL,NULL,'Apple',%lld,%lld),"
        " ('02:00:00:00:00:03',NULL,'old','Old Co',%lld,%lld),"
        " ('02:00:00:00:00:04',NULL,'night','Owl',%lld,%lld);"
        "INSERT INTO pnl_ssids (mac,ssid,first_seen,last_seen) VALUES"
        " ('02:00:00:00:00:02','CorpWiFi',%lld,%lld),"
        " ('02:00:00:00:00:03','CorpWiFi',%lld,%lld),"
        " ('02:00:00:00:00:03','Home',%lld,%lld);"
        "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,"
        "technique,match_ip,match_port,count) VALUES"
        " ('cred:10.0.0.1:10.0.0.9:21:ftp:alice-secret-user',%lld,%lld,12,1,"
        "'CLEARTEXT_CRED','ftp user alice-secret-user in the clear','T1040',"
        "'10.0.0.1',21,2),"
        " ('scan:10.0.0.7',%lld,%lld,0,0,'PORT_SCAN','42 ports','T1046',"
        "'10.0.0.7',NULL,5);"
        "INSERT INTO beacon_aps (bssid,ssid,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','Cafe',%lld,%lld);"
        "INSERT INTO beacon_ap_ssids (bssid,ssid,first_seen,last_seen) VALUES"
        " ('0a:00:00:00:00:01','Cafe',%lld,%lld),"
        " ('0a:00:00:00:00:01','FreeWiFi',%lld,%lld),"
        " ('0a:00:00:00:00:01','attwifi',%lld,%lld),"
        " ('0a:00:00:00:00:02','Lone',%lld,%lld);"
        "INSERT INTO karma_candidates (bssid,ssid_count,pnl_overlap,pnl_best,"
        "pnl_jaccard_ppm,ie_uniform,deauth_chain,score,top_ssid,first_seen,"
        "last_seen) VALUES"
        " ('0a:00:00:00:00:01',3,2,2,500000,1,0,80,'FreeWiFi',%lld,%lld),"
        " ('0a:00:00:00:00:03',2,1,1,250000,0,1,40,'x',%lld,%lld);"
        "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
        "pw_observed,first_seen,last_seen) VALUES"
        " (%lld,'10.0.0.1','10.0.0.9',21,'ftp','alice-secret-user',1,%lld,%lld);"
        "INSERT INTO rogue_radius (bssid,last_identity,first_seen,last_seen)"
        " VALUES ('0a:00:00:00:00:09','bob@corp-secret',%lld,%lld);",
        N - 10 * D, N - 9 * D, N - 2 * D, N - 2 * D + H, N - H,
        N - 30 * 60, N - 60, N - D, N - 600, N - 20 * D, N - 19 * D,
        WWH_FROM - H, WWH_FROM + H,
        N - D, N - 600, N - 20 * D, N - 19 * D, N - 20 * D, N - 20 * D,
        N - 300, N - 200, N - 3 * D, N - 2 * D,
        N - D, N - 60,
        N - D, N - 60, N - D, N - 120, N - 2 * D, N - D, N - D, N - 60,
        N - D, N - 60, N - 2 * D, N - D,
        N - 100, N - 100, N - 100, N - D, N - D);
    if (n < 0 || (size_t)n >= sizeof(sql)) return -1;
    if (sdb_exec(path, sql) != 0) return -1;
    /* 25 ARP rows: 25^3 is past the row cap, 25^5 past any budget. */
    char arp[4096];
    size_t o = (size_t)snprintf(arp, sizeof(arp), "INSERT INTO arp (ip,mac,iface,"
                                "first_seen,last_seen) VALUES");
    for (int i = 0; i < 25; i++)
        o += (size_t)snprintf(arp + o, sizeof(arp) - o, "%s('10.1.0.%d',"
                              "'02:01:00:00:00:%02x','eth0',%lld,%lld)",
                              i ? "," : "", i + 1, i, N - D, N - 60);
    snprintf(arp + o, sizeof(arp) - o, ";");
    return sdb_exec(path, arp);
}

/* ── an independent rendering of a result, from the C API ───────────── */

/* The value rules of web_sqlbox.h, written again here: the box's JSON
 * must be this. */
static void jv(web_jw_t *w, sqlite3_stmt *st, int i) {
    char b[64];
    switch (sqlite3_column_type(st, i)) {
    case SQLITE_INTEGER:
        snprintf(b, sizeof(b), "%lld", (long long)sqlite3_column_int64(st, i));
        web_jw_raw(w, b);
        break;
    case SQLITE_FLOAT:
        snprintf(b, sizeof(b), "%.17g", sqlite3_column_double(st, i));
        if (!strpbrk(b, ".eE")) strcat(b, ".0");
        web_jw_raw(w, b);
        break;
    case SQLITE_TEXT:
        web_jw_strn(w, (const char *)sqlite3_column_text(st, i),
                    (size_t)sqlite3_column_bytes(st, i));
        break;
    case SQLITE_BLOB: {
        const unsigned char *p = sqlite3_column_blob(st, i);
        int n = sqlite3_column_bytes(st, i);
        web_jw_raw(w, "{\"blob\":\"");
        for (int k = 0; k < n; k++) {
            snprintf(b, sizeof(b), "%02x", p[k]);
            web_jw_raw(w, b);
        }
        web_jw_raw(w, "\"}");
        break;
    }
    default:
        web_jw_raw(w, "null");
    }
}

typedef struct {
    char *cols, *rows;      /* "columns":[...] and "rows":[...] */
    char *text;             /* the shell's list-mode rendering */
    long long n;
} expect_t;

static void expect_free(expect_t *e) {
    free(e->cols); free(e->rows); free(e->text);
    memset(e, 0, sizeof(*e));
}

/* sql on path through the C API, no authorizer: what sqlite3 says. */
static int capi(const char *path, const char *sql, expect_t *e) {
    memset(e, 0, sizeof(*e));
    sqlite3 *h = NULL;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        sqlite3_close(h);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "    capi: %s\n", sqlite3_errmsg(h));
        sqlite3_close(h);
        return -1;
    }
    size_t cap = 1 << 20;
    e->cols = malloc(cap); e->rows = malloc(cap); e->text = malloc(cap);
    web_jw_t c, r;
    web_jw_init(&c, e->cols, cap);
    web_jw_init(&r, e->rows, cap);
    size_t to = 0;
    int nc = sqlite3_column_count(st);
    web_jw_raw(&c, "\"columns\":[");
    for (int i = 0; i < nc; i++) {
        if (i) web_jw_raw(&c, ",");
        web_jw_str(&c, sqlite3_column_name(st, i));
    }
    web_jw_raw(&c, "]");
    web_jw_raw(&r, "\"rows\":[");
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
        web_jw_raw(&r, e->n++ ? ",[" : "[");
        for (int i = 0; i < nc; i++) {
            if (i) web_jw_raw(&r, ",");
            jv(&r, st, i);
            const unsigned char *t = sqlite3_column_text(st, i);
            to += (size_t)snprintf(e->text + to, cap - to, "%s%s", i ? "\x1f" : "",
                                   t ? (const char *)t : "\x01");
        }
        web_jw_raw(&r, "]");
        to += (size_t)snprintf(e->text + to, cap - to, "\x1e");
    }
    web_jw_raw(&r, "]");
    sqlite3_finalize(st);
    sqlite3_close(h);
    return rc == SQLITE_DONE && !c.overflow && !r.overflow ? 0 : -1;
}

/* The shell on path, list mode with unit and record separators, no rc
 * file. 1 with its output, 0 when there is no sqlite3 on PATH, -1 when
 * it ran and failed. Run with no other thread alive: fork() then
 * exec(). */
static int shell(const char *path, const char *sql, char *out, size_t cap) {
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        dup2(pfd[1], 1);
        close(pfd[0]);
        close(pfd[1]);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, 2);
        char *const argv[] = {
            "sqlite3", "-init", "/dev/null", "-readonly", "-batch", "-noheader",
            "-list", "-separator", "\x1f", "-newline", "\x1e", "-nullvalue",
            "\x01", (char *)path, (char *)sql, NULL
        };
        execvp("sqlite3", argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap && (r = read(pfd[0], out + n, cap - 1 - n)) > 0) n += (size_t)r;
    out[n] = '\0';
    close(pfd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 127) return 0;
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 1 : -1;
}

/* ── the server ──────────────────────────────────────────────────────── */

static web_slothdb_t g_sdb;
static web_m4_t g_m4;
static web_sqlbox_t g_box;
static web_server_t *g_srv;
static pthread_t g_th;
static int g_run_rc;

static void *serve(void *arg) {
    (void)arg;
    g_run_rc = web_server_run(g_srv);
    return NULL;
}

/* The server over db, the box's timeout box_ms, the server's own
 * per-answer timeout conn_ms. */
static int srv_up_at(const char *db, int box_ms, int conn_ms) {
    int timeout_ms = box_ms;
    web_config_t c;
    web_config_defaults(&c);
    c.bind_port = 0;
    c.timeout_ms = conn_ms;
    c.linger_ms = 200;
    c.allow_sql = 1;
    snprintf(c.sloth_db, sizeof(c.sloth_db), "%s", db);
    web_slothdb_init(&g_sdb, db, NULL);
    memset(&g_m4, 0, sizeof(g_m4));
    g_m4.sdb = &g_sdb;
    char err[256] = "";
    if (web_sqlbox_init(&g_box, &g_sdb, 1) != 0) return -1;
    g_box.timeout_ms = timeout_ms;
    if (web_sqlbox_start(&g_box, err, sizeof(err)) != 0) return -1;
    g_srv = calloc(1, sizeof(*g_srv));
    if (!g_srv || web_server_open(g_srv, &c, err, sizeof(err)) != 0) {
        fprintf(stderr, "    open: %s\n", err);
        return -1;
    }
    web_server_set_m4(g_srv, &g_m4);
    web_server_set_sqlbox(g_srv, &g_box);
    return pthread_create(&g_th, NULL, serve, NULL) == 0 ? 0 : -1;
}

static int srv_up(int timeout_ms) { return srv_up_at(g_db, timeout_ms, 8000); }

static void srv_down(void) {
    web_server_stop(g_srv);
    pthread_join(g_th, NULL);
    WT_EQ(g_run_rc, 0);
    web_server_close(g_srv);
    free(g_srv);
    g_srv = NULL;
    web_sqlbox_destroy(&g_box);
    web_slothdb_destroy(&g_sdb);
}

static int dial(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 10, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(web_server_port(g_srv));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) { close(fd); return -1; }
    return fd;
}

static void urlenc(const char *s, char *out, size_t cap) {
    static const char hx[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && o + 4 < cap; p++) {
        int keep = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                   (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' ||
                   *p == '.' || *p == '~';
        if (keep) out[o++] = (char)*p;
        else { out[o++] = '%'; out[o++] = hx[*p >> 4]; out[o++] = hx[*p & 15]; }
    }
    out[o] = '\0';
}

static int send_query(const char *sql) {
    static char enc[3 * WEB_SQL_MAX_BYTES + 8];
    static char rq[3 * WEB_SQL_MAX_BYTES + 256];
    urlenc(sql, enc, sizeof(enc));
    int n = snprintf(rq, sizeof(rq), "GET /api/query?sql=%s HTTP/1.1\r\n"
                     "Host: 127.0.0.1\r\n\r\n", enc);
    int fd = dial();
    if (fd < 0) return -1;
    if (send(fd, rq, (size_t)n, MSG_NOSIGNAL) != n) { close(fd); return -1; }
    return fd;
}

static size_t read_all(int fd, char *out, size_t cap) {
    size_t n = 0;
    ssize_t r;
    while (n + 1 < cap && (r = recv(fd, out + n, cap - 1 - n, 0)) > 0) n += (size_t)r;
    out[n] = '\0';
    close(fd);
    return n;
}

static char *g_resp;
#define RESP_CAP (WEB_SQL_OUT_MAX + 8192)

/* GET /api/query for sql; the status, the body at *body. */
static int query(const char *sql, const char **body) {
    int fd = send_query(sql);
    *body = "";
    if (fd < 0) return -1;
    read_all(fd, g_resp, RESP_CAP);
    int st = 0;
    if (sscanf(g_resp, "HTTP/1.1 %d", &st) != 1) return -1;
    const char *b = strstr(g_resp, "\r\n\r\n");
    *body = b ? b + 4 : "";
    return st;
}

/* ── the acceptance ──────────────────────────────────────────────────── */

/* The recipes that read a withheld column, by title, and the column the
 * refusal must name. Every other recipe must run and return rows. */
static const char *refused_column(const char *title) {
    if (!strncmp(title, "Findings by severity", 20)) return "alerts.detail";
    if (!strncmp(title, "Cleartext credential exposures", 30))
        return "cleartext_creds.username";
    if (!strncmp(title, "What is actually taking the space", 33)) return "dbstat";
    return NULL;
}

static size_t g_file_n;
static unsigned char *g_file;
static char g_listing[1024];

static void snapshot(void) {
    g_file = malloc(1 << 22);
    g_file_n = g_file ? sdb_slurp(g_db, g_file, 1 << 22) : 0;
    sdb_listing(g_dir, g_listing, sizeof(g_listing));
}

static void left_as_it_was(void) {
    unsigned char *now = malloc(1 << 22);
    size_t n = now ? sdb_slurp(g_db, now, 1 << 22) : 0;
    WT_ASSERT(g_file_n > 4096);
    WT_EQ(n, g_file_n);
    WT_ASSERT(n == g_file_n && !memcmp(now, g_file, n));
    char ls[1024];
    sdb_listing(g_dir, ls, sizeof(ls));
    if (strcmp(ls, g_listing)) fprintf(stderr, "    listing: %s / %s\n", ls, g_listing);
    WT_ASSERT(!strcmp(ls, g_listing));
    free(now);
}

/* The recipes the page offers, counted without the extractor's own
 * rule: every line of any fenced block (```sh, ```bash, ```console or
 * none) whose command is sqlite3, however it is written, and every
 * ```sql block. recipes.c takes only ```sh blocks and stops the build on
 * a sqlite3 line in any other fence, so a recipe cannot be dropped by
 * its fence. */
static size_t page_recipes(const char *md) {
    size_t count = 0;
    int fence = 0;   /* 0 none, 1 sh, 2 another */
    for (const char *line = md; *line;) {
        const char *nl = strchr(line, '\n');
        size_t ll = nl ? (size_t)(nl - line) : strlen(line);
        size_t i = 0;
        while (i < ll && (line[i] == ' ' || line[i] == '\t')) i++;
        if (ll - i >= 3 && !strncmp(line + i, "```", 3)) {
            if (fence) fence = 0;
            else {
                fence = ll - i >= 5 && !strncmp(line + i + 3, "sh", 2) ? 1 : 2;
                if (ll - i >= 6 && !strncmp(line + i + 3, "sql", 3)) count++;
            }
        } else if (fence && ll - i >= 8 && !strncmp(line + i, "sqlite3", 7) &&
                   (line[i + 7] == ' ' || line[i + 7] == '\t')) {
            count++;
        }
        line += ll + (nl ? 1 : 0);
    }
    return count;
}

/* Every recipe is the page's own: as many as the page offers, each one
 * verbatim in it. Seen red with recipes.c keeping seven (the count), with
 * it writing a newline as a space (the verbatim check), and with a
 * single-quoted sqlite3 line added to the page and recipes.c's check for
 * one removed (the count: 9 offered, 8 taken). */
static void test_recipes_are_the_pages(void) {
    FILE *f = fopen(web_recipes_source, "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char md[1 << 20];
    size_t n = fread(md, 1, sizeof(md) - 1, f);
    fclose(f);
    md[n] = '\0';
    WT_EQ(web_recipes_n, page_recipes(md));
    WT_ASSERT(web_recipes_n >= 8);
    for (size_t i = 0; i < web_recipes_n; i++) {
        WT_HAS(md, web_recipes[i].sql);
        WT_HAS(md, web_recipes[i].title);
    }
}

static void test_acceptance(void) {
    /* The shell first, while this is the only thread: fork() then. */
    static char sh[1 << 16];
    int have_shell = -1;
    expect_t *ex = calloc(web_recipes_n, sizeof(*ex));
    int *shell_ok = calloc(web_recipes_n, sizeof(int));
    WT_ASSERT(ex && shell_ok);
    if (!ex || !shell_ok) { free(ex); free(shell_ok); return; }
    for (size_t i = 0; i < web_recipes_n; i++) {
        WT_EQ(capi(g_db, web_recipes[i].sql, &ex[i]), 0);
        if (!refused_column(web_recipes[i].title)) {
            if (ex[i].n < 1) fprintf(stderr, "    no rows: %s\n", web_recipes[i].title);
            WT_ASSERT(ex[i].n >= 1);   /* seeded so every recipe has rows */
        }
        int s = shell(g_db, web_recipes[i].sql, sh, sizeof(sh));
        if (have_shell < 0) have_shell = s != 0;
        if (s == 0) continue;
        WT_EQ(s, 1);
        if (ex[i].text && strcmp(sh, ex[i].text))
            fprintf(stderr, "    the shell differs on: %s\n", web_recipes[i].title);
        WT_ASSERT(ex[i].text && !strcmp(sh, ex[i].text));
        shell_ok[i] = 1;
    }
    fprintf(stderr, "    sqlite3 shell %s\n", have_shell > 0
            ? "on PATH: every recipe compared with it as well"
            : "not on PATH: compared with the sqlite3 C API only");
    WT_EQ(srv_up(WEB_SQL_TIMEOUT_MS), 0);
    int matched = 0, refused = 0;
    for (size_t i = 0; i < web_recipes_n; i++) {
        const char *b;
        int st = query(web_recipes[i].sql, &b);
        const char *col = refused_column(web_recipes[i].title);
        if (col) {
            WT_EQ(st, 400);
            WT_HAS(b, "{\"error\":\"denied\",\"detail\":\"withheld: ");
            WT_HAS(b, col);
            WT_LACKS(b, "alice");
            refused++;
            continue;
        }
        if (st != 200) fprintf(stderr, "    %d %s for: %s\n", st, b, web_recipes[i].title);
        WT_EQ(st, 200);
        WT_ASSERT(ex[i].cols && strstr(b, ex[i].cols) == b + 1);
        WT_HAS(b, ex[i].rows);
        char tail[96];
        snprintf(tail, sizeof(tail), "],\"row_count\":%lld,\"truncated\":false,", ex[i].n);
        WT_HAS(b, tail);
        if (ex[i].rows && strstr(b, ex[i].rows)) matched++;
    }
    WT_EQ(refused, 3);
    WT_EQ(matched + refused, (int)web_recipes_n);
    /* The recipes' values went out escaped: the markup hostname is in a
     * row the "between the last two visits" recipe does not read, so a
     * statement of the operator's own reads it. */
    const char *b;
    WT_EQ(query("SELECT hostname FROM devices WHERE mac='02:00:00:00:00:01'", &b), 200);
    WT_HAS(b, "\"rows\":[[\"\\u003cb\\u003e\\\"x\\\"\\u003c/b\\u003e\"]]");
    WT_LACKS(b, "<b>");
    WT_EQ(query("SELECT x'00ff7f', 1.5, 2.0, NULL, -0.25", &b), 200);
    WT_HAS(b, "\"rows\":[[{\"blob\":\"00ff7f\"},1.5,2.0,null,-0.25]]");
    srv_down();
    for (size_t i = 0; i < web_recipes_n; i++) expect_free(&ex[i]);
    free(ex);
    free(shell_ok);
}

/* Writes in every disguise, refused, and the file byte for byte and
 * its directory as they were. Seen red: "one_statement_only" with the
 * tail check removed (the first statement ran: a 200); the DML-tail
 * CTEs with box_authz() answering SQLITE_OK by default (they prepared
 * and the read-only check refused them instead); the withheld-column
 * queries with the authorizer's withheld test removed (they ran). The
 * "not_select" words are test_precheck's. The sqlite3_stmt_readonly()
 * check alone cannot be isolated: removed, every write here is still
 * refused by the precheck or the authorizer, and the suite stays green.
 * Nor can the byte-for-byte check: no single guard's removal lets a
 * write through (the opener is read-only and query_only as well), so it
 * was seen red with a write added to the test just before it. */
static void test_writes_refused(void) {
    WT_EQ(srv_up(WEB_SQL_TIMEOUT_MS), 0);
    static const char *const no[][2] = {
        { "INSERT INTO devices (mac,first_seen,last_seen) VALUES ('x',1,1)", "not_select" },
        { "UPDATE devices SET vendor='x'", "not_select" },
        { "DELETE FROM devices", "not_select" },
        { "DROP TABLE devices", "not_select" },
        { "ATTACH DATABASE ':memory:' AS x", "not_select" },
        { "PRAGMA writable_schema=1", "not_select" },
        { "PRAGMA journal_mode=WAL", "not_select" },
        { "CREATE TEMP TABLE t (a)", "not_select" },
        { "VACUUM", "not_select" },
        { "WITH x AS (SELECT 1) DELETE FROM devices", "denied" },
        { "WITH x AS (SELECT 1) INSERT INTO devices (mac,first_seen,last_seen)"
          " SELECT 'y',1,1", "denied" },
        { "WITH x AS (SELECT 1) UPDATE devices SET vendor='x'", "denied" },
        { "SELECT 1; DELETE FROM devices", "one_statement_only" },
        { "SELECT 1; SELECT 2", "one_statement_only" },
        { "SELECT 1;;", "one_statement_only" },
        { "SELECT name FROM pragma_table_info('devices')", "denied" },
        { "SELECT * FROM sqlite_dbpage", "denied" },
        { "SELECT load_extension('x')", "denied" },
        { "SELECT writefile('x', 'y')", "sql_error" },
        { "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r)"
          " SELECT n FROM r", "denied" },
        { "SELECT * FROM main.devices, temp.sqlite_master", "denied" },
    };
    for (size_t i = 0; i < sizeof(no) / sizeof(no[0]); i++) {
        const char *b;
        int st = query(no[i][0], &b);
        char want[64];
        snprintf(want, sizeof(want), "{\"error\":\"%s\"", no[i][1]);
        /* A SQLite built without the dbpage table (Ubuntu 24.04's 3.45)
         * refuses it before the authorizer is asked: no such table. */
        if (!strcmp(no[i][0], "SELECT * FROM sqlite_dbpage") &&
            strstr(b, "no such table: sqlite_dbpage"))
            snprintf(want, sizeof(want), "{\"error\":\"sql_error\"");
        if (st != 400 || !strstr(b, want))
            fprintf(stderr, "    %d %s for: %s\n", st, b, no[i][0]);
        WT_EQ(st, 400);
        WT_HAS(b, want);
    }
    /* And a recipe-shaped query naming a withheld column, every way in. */
    static const char *const sec[][2] = {
        { "SELECT datetime(ts,'unixepoch'), src, dst, protocol, username,"
          " pw_observed FROM cleartext_creds", "cleartext_creds.username" },
        { "SELECT src FROM cleartext_creds WHERE username LIKE 'a%'",
          "cleartext_creds.username" },
        { "SELECT * FROM cleartext_creds", "cleartext_creds.username" },
        { "SELECT title, detail FROM alerts ORDER BY sev DESC", "alerts.detail" },
        { "SELECT count(*) FROM alerts GROUP BY key", "alerts.key" },
        { "SELECT bssid, last_identity FROM rogue_radius", "rogue_radius.last_identity" },
        { "SELECT * FROM rdp_flows", "rdp_flows.last_cookie" },
        { "SELECT src_ip, last_username FROM mqtt_flows", "mqtt_flows.last_username" },
        { "SELECT mac FROM devices WHERE mac IN (SELECT username FROM cleartext_creds)",
          "cleartext_creds.username" },
        { "WITH c AS (SELECT username u FROM cleartext_creds) SELECT u FROM c",
          "cleartext_creds.username" },
    };
    for (size_t i = 0; i < sizeof(sec) / sizeof(sec[0]); i++) {
        const char *b;
        int st = query(sec[i][0], &b);
        WT_EQ(st, 400);
        WT_HAS(b, "{\"error\":\"denied\"");
        WT_HAS(b, sec[i][1]);
        WT_LACKS(b, "alice");
        WT_LACKS(b, "corp-secret");
    }
    /* dbstat: a withheld column's length, from its table's payload (or
     * its index's) less its readable siblings'. Seen red with "dbstat"
     * off denied_table()'s list (each a 200 with the sizes). A library
     * without it answers "no such table". */
    static const char *const stat[] = {
        "SELECT name, payload FROM dbstat WHERE name='cleartext_creds'",
        "SELECT name, payload FROM dbstat('main',1) WHERE name LIKE 'sqlite_autoindex_alerts%'",
        "SELECT sum(pgsize) FROM dbstat",
    };
    int have_dbstat = sqlite3_compileoption_used("ENABLE_DBSTAT_VTAB");
    for (size_t i = 0; i < sizeof(stat) / sizeof(stat[0]); i++) {
        const char *b;
        WT_EQ(query(stat[i], &b), 400);
        WT_HAS(b, have_dbstat ? "{\"error\":\"denied\",\"detail\":\"withheld: dbstat\"}"
                              : "{\"error\":\"sql_error\"");
    }
    /* The functions outside the list. */
    static const char *const fn[] = {
        "SELECT hex(mac) FROM devices", "SELECT randomblob(8)",
        "SELECT zeroblob(1000000)", "SELECT char(65)", "SELECT sqlite_version()",
    };
    for (size_t i = 0; i < sizeof(fn) / sizeof(fn[0]); i++) {
        const char *b;
        WT_EQ(query(fn[i], &b), 400);
        WT_HAS(b, "not allowed: the function");
    }
    srv_down();
    left_as_it_was();
}

/* The live schema against the list: every TEXT/BLOB column named for a
 * secret or a credential refused, the explicit ones too, the integer
 * flags and counts carrying the same words read. Every such column of
 * today's schema is on the explicit list too, so the word rule is shown
 * on a table a later sloth might add. Seen red with web_sdb_is_secret()'s
 * word loop removed (session_token read) and with can_hold_text()
 * answering 1 (the integer flags refused). */
static void test_withheld_columns(void) {
    /* tests/test_db.c's guardrail words, read out of that file. */
    FILE *f = fopen("tests/test_db.c", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char buf[1 << 18];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    const char *fnp = strstr(buf, "test_no_column_can_hold_secret_material(void)");
    const char *arr = fnp ? strstr(fnp, "forbidden[] = {") : NULL;
    const char *end = arr ? strstr(arr, "};") : NULL;
    WT_ASSERT(end != NULL);
    int words = 0;
    for (const char *p = arr; end && p < end; p++) {
        if (*p != '"') continue;
        const char *q = strchr(p + 1, '"');
        if (!q || q > end) break;
        char w[32];
        size_t o = 0;
        for (const char *c = p + 1; c < q && o < 31; c++) if (*c != '%') w[o++] = *c;
        w[o] = '\0';
        int found = 0;
        for (int k = 0; web_sdb_secret_words[k]; k++)
            if (!strcmp(web_sdb_secret_words[k], w)) found = 1;
        if (!found) fprintf(stderr, "    guardrail word %s not withheld\n", w);
        WT_ASSERT(found);
        words++;
        p = q;
    }
    WT_ASSERT(words >= 8);
    /* And the credential words test_slothdb.c holds M4's allow-list to,
     * pinned here: the list is the one both readers use. */
    static const char *const cred[] = {
        "user", "identity", "pass", "pw_", "cred", "token", "psk", "pmk",
        "key_material", "secret", "auth", "login", "cookie", "hash",
    };
    for (size_t i = 0; i < sizeof(cred) / sizeof(cred[0]); i++) {
        int found = 0;
        for (int k = 0; web_sdb_secret_words[k]; k++)
            if (!strcmp(web_sdb_secret_words[k], cred[i])) found = 1;
        if (!found) fprintf(stderr, "    credential word %s not withheld\n", cred[i]);
        WT_ASSERT(found);
    }

    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open_v2(g_db, &h, SQLITE_OPEN_READONLY, NULL), SQLITE_OK);
    sqlite3 *chk = NULL;
    WT_EQ(sqlite3_open_v2(g_db, &chk, SQLITE_OPEN_READONLY, NULL), SQLITE_OK);
    sqlite3_stmt *st = NULL;
    WT_EQ(sqlite3_prepare_v2(h, "SELECT m.name, c.name, c.type FROM sqlite_schema m,"
                             " pragma_table_info(m.name) c WHERE m.type='table'",
                             -1, &st, NULL), SQLITE_OK);
    static char out[1 << 16];
    web_sqlbox_lim_t lim = { 1000, 100, sizeof(out) - 1024 };
    int refused = 0, read_ok = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        const char *c = (const char *)sqlite3_column_text(st, 1);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        int texty = !ty || !ty[0] || strstr(ty, "TEXT") || strstr(ty, "BLOB") ||
                    strstr(ty, "CHAR");
        int named = 0;
        for (int k = 0; web_sdb_secret_words[k]; k++) {
            /* case-insensitive enough: sloth's names are lower case */
            if (strstr(c, web_sdb_secret_words[k])) named = 1;
        }
        int expl = 0;
        for (size_t k = 0; k < web_sdb_secret_n; k++)
            if (!strcmp(web_sdb_secret[k].table, t) && !strcmp(web_sdb_secret[k].column, c))
                expl = 1;
        char sql[256];
        snprintf(sql, sizeof(sql), "SELECT \"%s\" FROM \"%s\"", c, t);
        web_sqlbox_res_t res;
        web_sqlbox_run_db(chk, sql, strlen(sql), &lim, out, sizeof(out), &res);
        int denied = res.why && !strcmp(res.why, "denied");
        if ((named && texty) || expl) {
            if (!denied) fprintf(stderr, "    read: %s.%s\n", t, c);
            WT_ASSERT(denied);
            refused++;
        } else {
            if (res.status != 200) fprintf(stderr, "    refused: %s.%s %s\n", t, c, out);
            WT_EQ(res.status, 200);
            read_ok++;
        }
    }
    sqlite3_finalize(st);
    WT_ASSERT(refused >= 6);   /* username, last_username, last_identity, last_cookie, key, detail */
    WT_ASSERT(read_ok > 200);
    /* The words on an INTEGER are flags and counts, read on purpose. */
    static const char *const ints[] = {
        "SELECT deauth_chain FROM karma_candidates", "SELECT community_count FROM snmp_flows",
        "SELECT pw_observed FROM cleartext_creds", "SELECT has_pmkid FROM eapol_events",
        "SELECT identity_leaks FROM rogue_radius",
    };
    for (size_t i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
        web_sqlbox_res_t res;
        web_sqlbox_run_db(chk, ints[i], strlen(ints[i]), &lim, out, sizeof(out), &res);
        WT_EQ(res.status, 200);
    }
    sqlite3_close(chk);
    sqlite3_close(h);
    /* A column a later sloth might add: withheld by its name and type
     * alone, the day it appears, with no list to edit. */
    char sp[160];
    snprintf(sp, sizeof(sp), "%s/later.db", g_dir);
    WT_EQ(sdb_exec(sp, "CREATE TABLE later (session_token TEXT, password_hint,"
                       " note TEXT, auth_failures INTEGER);"
                       "INSERT INTO later VALUES ('t0k3n', 'hint', 'n', 3);"), 0);
    WT_EQ(sqlite3_open_v2(sp, &chk, SQLITE_OPEN_READONLY, NULL), SQLITE_OK);
    static const char *const later[][2] = {
        { "SELECT session_token FROM later", "denied" },
        { "SELECT password_hint FROM later", "denied" },   /* no type: can hold text */
        { "SELECT note FROM later", NULL },
        { "SELECT auth_failures FROM later", NULL },
    };
    for (size_t i = 0; i < sizeof(later) / sizeof(later[0]); i++) {
        web_sqlbox_res_t res;
        web_sqlbox_run_db(chk, later[i][0], strlen(later[i][0]), &lim, out, sizeof(out), &res);
        if (later[i][1]) {
            WT_ASSERT(res.why && !strcmp(res.why, later[i][1]));
            WT_LACKS(out, "t0k3n");
        } else {
            WT_EQ(res.status, 200);
        }
    }
    sqlite3_close(chk);
    unlink(sp);
}

/* Each cap: rows (15,625 asked, 10,000 given), bytes, time, a value over
 * the length limit. Each seen red with its check removed. */
static void test_limits(void) {
    web_slothdb_t s;
    web_slothdb_init(&s, g_db, NULL);
    web_sqlbox_t b;
    WT_EQ(web_sqlbox_init(&b, &s, 0), 0);
    char *out = malloc(WEB_SQL_HDR + WEB_SQL_OUT_MAX);
    WT_ASSERT(out != NULL);
    if (!out) return;
    size_t off = 0;
    int status = 0;
    const char *q = "SELECT a.ip, b.ip, c.ip FROM arp a, arp b, arp c";
    size_t n = web_sqlbox_query(&b, q, strlen(q), SDB_NOW, out,
                                WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    WT_ASSERT(n > 0);
    out[off + n] = '\0';
    WT_EQ(status, 200);
    WT_HAS(out + off, "\"row_count\":10000,\"truncated\":true,\"truncated_by\":\"rows\"");
    /* bytes */
    b.out_max = 8192;
    n = web_sqlbox_query(&b, q, strlen(q), SDB_NOW, out,
                         WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    out[off + n] = '\0';
    WT_EQ(status, 200);
    WT_HAS(out + off, "\"truncated\":true,\"truncated_by\":\"bytes\"");
    WT_ASSERT(n < 8192 + WEB_SQL_HDR);
    b.out_max = WEB_SQL_OUT_MAX;
    /* time: a short budget against 25^5 rows counted */
    b.timeout_ms = 150;
    const char *slow = "SELECT count(*) FROM arp a, arp b, arp c, arp d, arp e, arp f";
    n = web_sqlbox_query(&b, slow, strlen(slow), SDB_NOW, out,
                         WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    out[off + n] = '\0';
    WT_EQ(status, 200);
    WT_HAS(out + off, "\"row_count\":0,\"truncated\":true,\"truncated_by\":\"timeout\"");
    b.timeout_ms = WEB_SQL_TIMEOUT_MS;
    /* a value past SQLITE_LIMIT_LENGTH */
    const char *big = "SELECT printf('%.*c', 100000, 'x')";
    n = web_sqlbox_query(&b, big, strlen(big), SDB_NOW, out,
                         WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    out[off + n] = '\0';
    /* Past SQLITE_LIMIT_LENGTH, SQLite 3.53 fails the statement and 3.45
     * (CI's Ubuntu 24.04) yields an empty value: either way no value of
     * 100000 bytes reaches the answer, which is the bound held here. */
    int big_refused = status == 400;
    if (big_refused) {
        WT_HAS(out + off, "{\"error\":\"sql_error\"");
    } else {
        WT_EQ(status, 200);
        WT_ASSERT(n < 4096);
    }
    /* A sort past the page cache: refused at its first spill, not run
     * for the whole budget writing a temporary file. Seen red with
     * box_open() passing temporary files through (a 200, "truncated_by":
     * "timeout", after 1 s of writing to the temporary directory). */
    b.timeout_ms = 1000;
    const char *sort = "SELECT printf('%.*c', 60000, a.name) v FROM sqlite_schema a,"
                       " sqlite_schema b, sqlite_schema c ORDER BY v DESC, a.name";
    n = web_sqlbox_query(&b, sort, strlen(sort), SDB_NOW, out,
                         WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    out[off + n] = '\0';
    WT_EQ(status, 400);
    WT_HAS(out + off, "{\"error\":\"temp_space\"");
    b.timeout_ms = WEB_SQL_TIMEOUT_MS;
    web_sqlbox_stats_t st;
    web_sqlbox_stats(&b, &st);
    WT_EQ(st.queries, 5);
    WT_EQ(st.timeouts, 1);
    WT_EQ(st.truncated, 3);
    WT_EQ(st.refused, 1UL + (unsigned long)big_refused);
    /* No sloth.db: a 503 naming its state. */
    web_slothdb_t none;
    char miss[160];
    snprintf(miss, sizeof(miss), "%s/absent.db", g_dir);
    web_slothdb_init(&none, miss, NULL);
    b.sdb = &none;
    n = web_sqlbox_query(&b, "SELECT 1", 8, SDB_NOW, out,
                         WEB_SQL_HDR + WEB_SQL_OUT_MAX, &off, &status);
    out[off + n] = '\0';
    WT_EQ(status, 503);
    WT_HAS(out + off, "HTTP/1.1 503 Service Unavailable\r\n");
    WT_HAS(out + off, "{\"error\":\"sloth_db_missing\"");
    web_slothdb_destroy(&none);
    free(out);
    web_sqlbox_destroy(&b);
    web_slothdb_destroy(&s);
}

static int wait_busy(int want, int ms) {
    for (int i = 0; i < ms / 5; i++) {
        if (web_sqlbox_busy(&g_box) == want) return 1;
        struct timespec ts = { 0, 5 * 1000000L };
        nanosleep(&ts, NULL);
    }
    return web_sqlbox_busy(&g_box) == want;
}

static long long t_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* One at a time. Seen red with web_sqlbox_submit() not checking the
 * state (the second ran: a 200), with the release in conn_write()
 * removed (the box still busy once the answer was read), with the
 * worker's rest removed (the statement after the 400 ms one answered at
 * once), and with sql_ready()'s release of an answer nobody waits for
 * removed (the box busy for good once the server had timed the slot
 * out). */
static void test_one_at_a_time(void) {
    WT_EQ(srv_up(400), 0);
    const char *slow = "SELECT count(*) FROM arp a, arp b, arp c, arp d, arp e, arp f";
    int fd1 = send_query(slow);
    WT_ASSERT(fd1 >= 0);
    WT_ASSERT(wait_busy(1, 3000));
    const char *b;
    WT_EQ(query("SELECT 1", &b), 503);
    WT_HAS(b, "{\"error\":\"busy\"}");
    read_all(fd1, g_resp, RESP_CAP);
    WT_HAS(g_resp, "HTTP/1.1 200 OK\r\n");
    WT_HAS(g_resp, "\"truncated_by\":\"timeout\"");
    WT_EQ(web_sqlbox_busy(&g_box), 0);
    /* The rest: the 400 ms statement is followed by 400 ms with no box
     * reader, so the next statement waits most of that (the answer
     * was read in the meantime) before it runs. */
    long long t0 = t_mono_ms();
    WT_EQ(query("SELECT 1", &b), 200);
    long long waited = t_mono_ms() - t0;
    if (waited < 200) fprintf(stderr, "    answered after %lld ms\n", waited);
    WT_ASSERT(waited >= 200);
    WT_HAS(b, "\"rows\":[[1]]");
    /* A client that leaves while its statement runs: the server does not
     * poll a slot waiting on the box, so it learns of it when the answer
     * is written, and that write's failure frees the box. */
    int fd2 = send_query(slow);
    WT_ASSERT(fd2 >= 0);
    WT_ASSERT(wait_busy(1, 3000));
    close(fd2);
    WT_ASSERT(wait_busy(0, 5000));
    WT_EQ(query("SELECT 2", &b), 200);
    /* GET only. */
    int fd = dial();
    static const char head[] = "HEAD /api/query?sql=SELECT%201 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    WT_ASSERT(send(fd, head, sizeof(head) - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof(head) - 1));
    read_all(fd, g_resp, RESP_CAP);
    WT_HAS(g_resp, "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\n");
    /* The recipes route answers with the box on. */
    fd = dial();
    static const char rr[] = "GET /api/recipes HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    WT_ASSERT(send(fd, rr, sizeof(rr) - 1, MSG_NOSIGNAL) == (ssize_t)(sizeof(rr) - 1));
    read_all(fd, g_resp, RESP_CAP);
    WT_HAS(g_resp, "{\"source\":\"docs/wiki/sqlite-schema.md\",\"recipes\":[{\"title\":");
    web_sqlbox_stats_t st;
    web_sqlbox_stats(&g_box, &st);
    WT_ASSERT(st.busy >= 1);
    srv_down();
    /* The server times the slot out before the box answers: here the box
     * is held (its lock taken, so its worker cannot post the answer)
     * past the slot's deadline, 200 ms + 2 x 400 ms, and the server
     * closes the connection with nothing written. The answer then
     * arrives for a slot that is gone, and sql_ready() must release
     * the box itself: nobody else holds it. */
    WT_EQ(srv_up_at(g_db, 400, 200), 0);
    int fd3 = send_query(slow);
    WT_ASSERT(fd3 >= 0);
    WT_ASSERT(wait_busy(1, 3000));
    pthread_mutex_lock(&g_box.mu);
    size_t got = read_all(fd3, g_resp, RESP_CAP);   /* until the server closes */
    pthread_mutex_unlock(&g_box.mu);
    WT_EQ(got, 0);
    WT_ASSERT(wait_busy(0, 5000));
    WT_EQ(query("SELECT 3", &b), 200);
    WT_HAS(b, "\"rows\":[[3]]");
    srv_down();
}

/* sloth's writer as sloth runs it (src/db.c: WAL, synchronous NORMAL, a
 * busy timeout), in a child process of its own: a 40 KB commit every
 * 25 ms for ms milliseconds, with auto-checkpoints every 250 pages. The
 * largest sloth.db-wal it saw after a commit, and its commits and BUSY
 * answers, written to fd. Forked while this process has no other
 * thread. */
typedef struct { long long wal_max, commits, busy; } wal_obs_t;

static pid_t wal_writer(const char *path, int ms, int fd) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    wal_obs_t o = { 0, 0, 0 };
    char w[192];
    snprintf(w, sizeof(w), "%s-wal", path);
    sqlite3 *h = NULL;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) _exit(1);
    sqlite3_busy_timeout(h, 1000);
    sqlite3_exec(h, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
                    "PRAGMA wal_autocheckpoint=250", NULL, NULL, NULL);
    long long end = t_mono_ms() + ms;
    while (t_mono_ms() < end) {
        int rc = sqlite3_exec(h, "BEGIN IMMEDIATE; INSERT INTO w VALUES"
                                 " (zeroblob(40000)); COMMIT", NULL, NULL, NULL);
        if (rc == SQLITE_OK) o.commits++;
        else { o.busy++; sqlite3_exec(h, "ROLLBACK", NULL, NULL, NULL); }
        struct stat sb;
        if (stat(w, &sb) == 0 && sb.st_size > o.wal_max) o.wal_max = sb.st_size;
        struct timespec ts = { 0, 25 * 1000000L };
        nanosleep(&ts, NULL);
    }
    sqlite3_close(h);
    ssize_t wr = write(fd, &o, sizeof(o));
    _exit(wr == (ssize_t)sizeof(o) ? 0 : 1);
}

static int wal_collect(pid_t pid, int fd, wal_obs_t *o) {
    memset(o, 0, sizeof(*o));
    ssize_t r = read(fd, o, sizeof(*o));
    int st = 0;
    waitpid(pid, &st, 0);
    return r == (ssize_t)sizeof(*o) && WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : -1;
}

/* A client sending statements back to back does not stop sloth from
 * restarting its WAL: with a writer at sloth's pace, the largest
 * sloth.db-wal while a client loops the box (each statement running to
 * its 300 ms timeout) stays within twice the largest with no reader at
 * all, while the writer appends several times that. Seen red with the
 * worker's rest removed (the -wal grew with every commit, to about
 * what was written). A statement may meet the writer's checkpoint and
 * answer 503 (the box's reader opens with a busy timeout and gives up
 * rather than wait on sloth), which is the promised behaviour; any
 * other status fails. CI's runner showed one 503 in five (382ab40). */
static void test_box_lets_the_wal_restart(void) {
    char p[160];
    snprintf(p, sizeof(p), "%s/wal.db", g_dir);
    WT_EQ(sdb_make(p, db_schema_version(), 1), 0);
    WT_EQ(seed_recipes(p), 0);
    WT_EQ(sdb_exec(p, "CREATE TABLE w (b BLOB)"), 0);
    const int ms = 3000;
    int pfd[2];
    WT_EQ(pipe(pfd), 0);
    /* The control: the writer alone. */
    wal_obs_t ctl, box;
    pid_t pid = wal_writer(p, ms, pfd[1]);
    WT_ASSERT(pid > 0);
    WT_EQ(wal_collect(pid, pfd[0], &ctl), 0);
    /* The writer with the box looped (the child first: no thread yet). */
    pid = wal_writer(p, ms, pfd[1]);
    WT_ASSERT(pid > 0);
    WT_EQ(srv_up_at(p, 300, 8000), 0);
    const char *slow = "SELECT count(*) FROM arp a, arp b, arp c, arp d, arp e, arp f";
    int answers = 0, other = 0, unavail = 0, other_st = 0;
    long long end = t_mono_ms() + ms;
    while (t_mono_ms() < end) {
        const char *b;
        int st = query(slow, &b);
        if (st == 200) answers++;
        else if (st == 503) unavail++;
        else { other++; other_st = st; }
    }
    srv_down();
    WT_EQ(wal_collect(pid, pfd[0], &box), 0);
    close(pfd[0]);
    close(pfd[1]);
    long long written = box.commits * 40000;
    fprintf(stderr, "    -wal max %lld B alone, %lld B with %d box answers (%d 503, %d other"
            " [last %d]); %lld B written, %lld BUSY\n", ctl.wal_max, box.wal_max,
            answers, unavail, other, other_st, written, box.busy);
    WT_ASSERT(answers >= 3);
    WT_EQ(other, 0);
    WT_ASSERT(ctl.wal_max > 0);
    WT_ASSERT(written > 3 * ctl.wal_max);     /* unbounded growth would show */
    WT_ASSERT(box.wal_max <= 2 * ctl.wal_max);
    char s[192];
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p); unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p); unlink(s);
}

void run_sqlbox_tests(void) {
    WT_RUN(test_param);
    WT_RUN(test_precheck);
    WT_RUN(test_off_by_default);
    WT_RUN(test_page_carries_the_box);
    WT_RUN(test_recipes_are_the_pages);
    snprintf(g_dir, sizeof(g_dir), "%s/slothweb-sql-XXXXXX", test_tmpdir());
    WT_ASSERT(mkdtemp(g_dir) != NULL);
    snprintf(g_db, sizeof(g_db), "%s/sloth.db", g_dir);
    WT_EQ(sdb_make(g_db, db_schema_version(), 0), 0);
    WT_EQ(seed_recipes(g_db), 0);
    snapshot();
    g_resp = malloc(RESP_CAP);
    WT_ASSERT(g_resp != NULL);
    if (g_resp) {
        WT_RUN(test_acceptance);
        WT_RUN(test_writes_refused);
        WT_RUN(test_withheld_columns);
        WT_RUN(test_limits);
        WT_RUN(test_one_at_a_time);
        WT_RUN(test_box_lets_the_wal_restart);
        left_as_it_was();
    }
    free(g_resp);
    free(g_file);
    unlink(g_db);
    rmdir(g_dir);
}

#endif
