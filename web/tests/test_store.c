/* slothweb.db (#160, M2): the schema guardrail copied from sloth's
 * tests/test_db.c, the identification and migration rules (the
 * 2026-10-21 owner rule), the file rules, writes, compaction and the
 * ceiling. Every file lives in a fresh mkdtemp() directory under /tmp. */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "web_jsonl.h"
#include "web_metrics.h"
#include "web_rollup.h"
#include "web_store.h"
#include "web_tsdb.h"
#include "wtest.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

static int ci_has(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < n && p[i] && tolower((unsigned char)p[i]) == needle[i]) i++;
        if (i == n) return 1;
    }
    return 0;
}

/* The words test_db.c forbids, and the ones a web store could be
 * tempted by (a session token, a cookie, a login name). */
static const char *const FORBIDDEN[] = {
    "pmkid", "nonce", "mic", "password", "passwd", "community", "secret",
    "key_material", "token", "cookie", "username", "credential",
};
#define NFORBIDDEN (sizeof(FORBIDDEN) / sizeof(FORBIDDEN[0]))

/* The DDL text, in every build: nothing named for a secret, and every
 * migration step is additive (CREATE TABLE or CREATE INDEX only:
 * nothing rewritten, nothing dropped). "mic" is checked as a column
 * name only, since "minute" contains no such word but other prose
 * might. */
static void test_schema_text_guardrail(void) {
    const char *meta = web_store_meta_sql();
    const char *v1 = web_store_step_sql(0);
    const char *v2 = web_store_step_sql(1);
    WT_ASSERT(meta && v1 && v2);
    WT_ASSERT(web_store_step_sql(2) == NULL);     /* v2 is current */
    WT_EQ(WEB_STORE_SCHEMA, 2);
    const char *both[3] = { meta, v1, v2 };
    for (int k = 0; k < 3; k++) {
        for (size_t i = 0; i < NFORBIDDEN; i++) {
            if (!strcmp(FORBIDDEN[i], "mic")) {
                WT_ASSERT(strstr(both[k], "  mic ") == NULL);
                continue;
            }
            WT_ASSERT(!ci_has(both[k], FORBIDDEN[i]));
        }
        WT_ASSERT(strstr(both[k], "UPDATE") == NULL);
        WT_ASSERT(strstr(both[k], "DELETE") == NULL);
        WT_ASSERT(strstr(both[k], "DROP") == NULL);
        WT_ASSERT(strstr(both[k], "ALTER") == NULL);
        WT_ASSERT(strstr(both[k], "BLOB") == NULL);
    }
    int creates = 0, semis = 0;
    for (const char *p = v1; (p = strstr(p, "CREATE TABLE ")); p++) creates++;
    for (const char *p = v1; *p; p++) semis += *p == ';';
    WT_EQ(creates, 4);
    WT_EQ(semis, 4);
    creates = semis = 0;
    for (const char *p = v2; (p = strstr(p, "CREATE INDEX ")); p++) creates++;
    for (const char *p = v2; *p; p++) semis += *p == ';';
    WT_EQ(creates, 3);
    WT_EQ(semis, 3);
    /* Not IF NOT EXISTS: a step must fail on a name already taken. */
    WT_ASSERT(strstr(v1, "IF NOT EXISTS") == NULL);
    WT_ASSERT(strstr(v2, "IF NOT EXISTS") == NULL);
}

#ifndef WITH_SQLITE

static void test_no_sqlite_build(void) {
    WT_EQ(web_store_available(), 0);
    web_store_t s;
    char err[256];
    WT_EQ(web_store_open(&s, "/nonexistent/slothweb.db", err, sizeof(err)), -1);
    WT_HAS(err, "built without SQLite");
    web_store_close(&s);
    /* Nothing was created. */
    struct stat st;
    WT_EQ(stat("/nonexistent/slothweb.db", &st), -1);
}

void run_store_tests(void) {
    WT_RUN(test_schema_text_guardrail);
    WT_RUN(test_no_sqlite_build);
}

#else

static char g_dir[64];

static int mkdir_tmp(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/slothweb-store-XXXXXX");
    return mkdtemp(g_dir) ? 0 : -1;
}

static void path_in(char *out, size_t sz, const char *name) {
    snprintf(out, sz, "%s/%s", g_dir, name);
}

static void rm_store(const char *p) {
    char s[256];
    unlink(p);
    snprintf(s, sizeof(s), "%s-wal", p);     unlink(s);
    snprintf(s, sizeof(s), "%s-shm", p);     unlink(s);
    snprintf(s, sizeof(s), "%s-journal", p); unlink(s);
}

static web_store_t S;

static long long raw_int(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    long long v = -1;
    if (sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(h, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(h);
    return v;
}

static void raw_exec(const char *path, const char *sql) {
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open(path, &h), SQLITE_OK);
    char *m = NULL;
    int rc = sqlite3_exec(h, sql, NULL, NULL, &m);
    if (rc != SQLITE_OK) fprintf(stderr, "  raw_exec: %s\n", m ? m : "?");
    WT_EQ(rc, SQLITE_OK);
    sqlite3_free(m);
    sqlite3_close(h);
    chmod(path, 0600);
}

/* The whole file, for byte-for-byte "left as it is". */
static size_t slurp(const char *path, unsigned char *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static int file_has(const char *path, const char *needle) {
    static unsigned char buf[8 << 20];
    size_t n = slurp(path, buf, sizeof(buf));
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= n; i++)
        if (!memcmp(buf + i, needle, nl)) return 1;
    return 0;
}

static void test_fresh_store(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "fresh.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_store_stats_t st;
    web_store_stats(&S, &st);
    WT_EQ(st.open, 1);
    WT_EQ(st.schema, WEB_STORE_SCHEMA);
    web_store_close(&S);
    struct stat sb;
    WT_EQ(stat(p, &sb), 0);
    WT_EQ(sb.st_mode & 0777, 0600);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"),
          WEB_STORE_SCHEMA);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM meta WHERE name='store' AND"
                     " value='slothweb'"), 1);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                     " AND name IN ('series','fine','minute','hour')"), 4);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
                     " AND name IN ('fine_t','minute_t','hour_t')"), 3);
    WT_EQ(raw_int(p, "PRAGMA auto_vacuum"), 2);   /* INCREMENTAL */
    /* Reopening a current file runs no step again. */
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"),
          WEB_STORE_SCHEMA);
    rm_store(p);
}

/* test_db.c's guardrail, against the live schema: nothing named for a
 * secret may be TEXT or BLOB. The positive control lists the TEXT
 * columns there are, so the sweep is seen to see them. */
static void test_no_column_can_hold_secret_material(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "guard.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_store_close(&S);
    for (size_t i = 0; i < NFORBIDDEN; i++) {
        char sql[512];
        snprintf(sql, sizeof(sql),
            "SELECT COUNT(*) FROM sqlite_master m, pragma_table_info(m.name) c"
            " WHERE m.type='table' AND c.name LIKE '%%%s%%'"
            " AND UPPER(c.type) IN ('TEXT','BLOB')", FORBIDDEN[i]);
        WT_EQ(raw_int(p, sql), 0);
    }
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master m,"
                     " pragma_table_info(m.name) c WHERE m.type='table'"
                     " AND UPPER(c.type)='TEXT'"), 4);   /* name value metric key */
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master m,"
                     " pragma_table_info(m.name) c WHERE m.type='table'"
                     " AND UPPER(c.type)='BLOB'"), 0);
    rm_store(p);
}

/* The strongest form, as test_db.c has it: secrets on the stream never
 * reach the file by any path. The records carry an SNMP community, an
 * MQTT user name and a cleartext credential; the file is scanned. The
 * positive control is a key written directly, found by the same scan. */
static void feed_line(web_metrics_t *m, const char *s) {
    static web_jrec_t rec;
    WT_EQ(web_jl_parse(s, strlen(s), &rec), WEB_JL_OK);
    web_metrics_record(m, &rec);
}

static long long g_clock = 1792627200;
static long long clock_fn(void *ctx) { (void)ctx; return g_clock; }

static void test_secrets_never_reach_disk(void) {
    char p[128], w[160], err[512];
    path_in(p, sizeof(p), "secret.db");
    snprintf(w, sizeof(w), "%s-wal", p);
    static web_rollup_t ru;
    static web_metrics_t mx;
    static web_tsdb_t ts;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 64, 1, err, sizeof(err)), 0);
    WT_EQ(web_metrics_init(&mx, &ru, clock_fn, NULL), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, 256, clock_fn, NULL), 0);
    for (int i = 0; i < 3; i++, g_clock += 10) {
        char b[512];
        snprintf(b, sizeof(b), "{\"type\":\"snmp_flow\",\"ts\":%lld,\"src_ip\":"
                 "\"10.0.0.7\",\"dst_ip\":\"10.0.0.4\",\"get_count\":%d,"
                 "\"last_community\":\"SECRETCOMMUNITY42\",\"first_seen\":1}",
                 g_clock, i + 1);
        feed_line(&mx, b);
        snprintf(b, sizeof(b), "{\"type\":\"mqtt_flow\",\"ts\":%lld,\"src_ip\":"
                 "\"10.0.0.7\",\"dst_ip\":\"10.0.0.5\",\"connect_count\":%d,"
                 "\"last_username\":\"SECRETUSER42\",\"first_seen\":1}",
                 g_clock, i + 1);
        feed_line(&mx, b);
        snprintf(b, sizeof(b), "{\"type\":\"cleartext_cred\",\"ts\":%lld,"
                 "\"src\":\"10.0.0.7\",\"dst\":\"10.0.0.6\",\"proto\":\"ftp\","
                 "\"user\":\"SECRETUSER42\",\"pass\":\"SECRETPASS42\"}", g_clock);
        feed_line(&mx, b);
        snprintf(b, sizeof(b), "{\"type\":\"dns\",\"ts\":%lld,\"src\":\"10.0.0.7\","
                 "\"qname\":\"SECRETQNAME42.example\",\"is_resp\":0}", g_clock);
        feed_line(&mx, b);
        /* The control: a key the scan must find. */
        web_rollup_add(&ru, WM_IFACE_RX, "PROBECONTROL42", 1, g_clock);
        web_tsdb_step(&ts, g_clock);
    }
    web_tsdb_flush_all(&ts);
    WT_ASSERT(web_store_count(&S, WEB_TIER_FINE) > 0);
    const char *const bad[] = {
        "SECRETCOMMUNITY42", "SECRETUSER42", "SECRETPASS42", "SECRETQNAME42",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        WT_EQ(file_has(p, bad[i]) + file_has(w, bad[i]), 0);
    WT_ASSERT(file_has(p, "PROBECONTROL42") + file_has(w, "PROBECONTROL42") > 0);
    WT_ASSERT(file_has(p, "10.0.0.7") + file_has(w, "10.0.0.7") > 0);
    web_tsdb_destroy(&ts);
    web_metrics_destroy(&mx);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    rm_store(p);
}

static void test_v0_file_is_migrated(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "v0.db");
    raw_exec(p, "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO meta VALUES ('store','slothweb'),"
                "('schema_version','0'),('note','kept');");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"), 2);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM meta WHERE name='note' AND"
                     " value='kept'"), 1);              /* nothing rewritten */
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                     " AND name IN ('series','fine','minute','hour')"), 4);
    rm_store(p);
}

/* The failure that leaves it unchanged: a v0 file whose step cannot
 * apply (a pre-release layout holding the name `hour` already) stays at
 * v0 with its own table and row, and gets none of the step's tables.
 * Seen red with the step's ROLLBACK replaced by COMMIT (series, fine
 * and minute were left behind at v0). */
static void test_v0_failed_step_leaves_file_unchanged(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "v0bad.db");
    raw_exec(p, "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO meta VALUES ('store','slothweb'),('schema_version','0');"
                "CREATE TABLE hour (x INTEGER); INSERT INTO hour VALUES (7);");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "unchanged from v0");
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"), 0);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
                     " AND name IN ('series','fine','minute')"), 0);
    WT_EQ(raw_int(p, "SELECT x FROM hour"), 7);
    rm_store(p);
}

/* A file built at v1 (by the v1 step itself, as the build before this
 * one wrote it) with rows in it: brought to v2, every row as it was. */
static void make_v1(const char *p, const char *extra) {
    char sql[4096];
    snprintf(sql, sizeof(sql), "%s INSERT INTO meta VALUES ('store','slothweb'),"
             "('schema_version','1'); %s"
             "INSERT INTO series VALUES (1,'host.rx_rate','10.0.0.1');"
             "INSERT INTO fine VALUES (1,1000,5,2,1,4);"
             "INSERT INTO minute VALUES (1,960,7,3,1,4);"
             "INSERT INTO hour VALUES (1,0,9,4,1,4); %s",
             web_store_meta_sql(), web_store_step_sql(0), extra);
    raw_exec(p, sql);
}

static void test_v1_file_is_migrated(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "v1.db");
    make_v1(p, "");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_point_t pt[4];
    int more;
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 0, 5000,
                          pt, 4, &more), 1);
    WT_ASSERT(pt[0].t == 1000 && pt[0].sum == 5 && pt[0].n == 2);
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"), 2);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
                     " AND name IN ('fine_t','minute_t','hour_t')"), 3);
    WT_EQ(raw_int(p, "SELECT sum FROM minute WHERE series=1 AND t=960"), 7);
    WT_EQ(raw_int(p, "SELECT sum FROM hour WHERE series=1 AND t=0"), 9);
    rm_store(p);
}

/* The v1 step's failure: a v1 file already holding the name hour_t
 * stays at v1 with its rows and that table, and gets neither of the
 * step's other two indexes. Seen red with the step's ROLLBACK replaced
 * by COMMIT (fine_t and minute_t were left behind at v1). */
static void test_v1_failed_step_leaves_file_unchanged(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "v1bad.db");
    make_v1(p, "CREATE TABLE hour_t (x INTEGER); INSERT INTO hour_t VALUES (7);");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "unchanged from v1");
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT value FROM meta WHERE name='schema_version'"), 1);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
                     " AND name IN ('fine_t','minute_t')"), 0);
    WT_EQ(raw_int(p, "SELECT x FROM hour_t"), 7);
    WT_EQ(raw_int(p, "SELECT sum FROM fine WHERE series=1 AND t=1000"), 5);
    rm_store(p);
}

static void refused_untouched(const char *p, const char *want) {
    static unsigned char before[1 << 16], after[1 << 16];
    size_t nb = slurp(p, before, sizeof(before));
    struct stat s0, s1;
    stat(p, &s0);
    char err[512];
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, want);
    web_store_close(&S);
    size_t na = slurp(p, after, sizeof(after));
    stat(p, &s1);
    WT_EQ(na, nb);
    WT_ASSERT(nb > 0 && !memcmp(before, after, nb));
    WT_EQ(s1.st_mode, s0.st_mode);
}

/* Only a file from a newer build is refused among our own, and it is
 * left exactly as it was. */
static void test_newer_file_refused(void) {
    char p[128];
    path_in(p, sizeof(p), "v3.db");
    raw_exec(p, "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO meta VALUES ('store','slothweb'),('schema_version','3');"
                "CREATE TABLE future (x INTEGER);");
    refused_untouched(p, "newer slothweb");
    rm_store(p);
}

/* sloth.db (its meta is key/value with a schema_version), any other
 * database, a file with no meta, and a file that is not SQLite at all:
 * refused, untouched. */
static void test_foreign_files_refused(void) {
    char p[128];
    path_in(p, sizeof(p), "sloth.db");
    raw_exec(p, "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                "INSERT INTO meta VALUES ('schema_version','6');"
                "CREATE TABLE devices (mac TEXT PRIMARY KEY);"
                "INSERT INTO devices VALUES ('aa:bb:cc:dd:ee:ff');");
    refused_untouched(p, "not a slothweb store");
    rm_store(p);

    path_in(p, sizeof(p), "other.db");
    raw_exec(p, "CREATE TABLE things (x INTEGER); INSERT INTO things VALUES (1);");
    refused_untouched(p, "not a slothweb store");
    rm_store(p);

    path_in(p, sizeof(p), "meta-other.db");
    raw_exec(p, "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL);"
                "INSERT INTO meta VALUES ('store','someone-else'),"
                "('schema_version','1');");
    refused_untouched(p, "not a slothweb store");
    rm_store(p);

    path_in(p, sizeof(p), "garbage.db");
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
    WT_ASSERT(fd >= 0);
    static const char junk[] = "this is not an SQLite file, just 64 bytes of text..";
    if (fd >= 0) {
        WT_EQ(write(fd, junk, sizeof(junk)), (long long)sizeof(junk));
        close(fd);
    }
    refused_untouched(p, "not a readable SQLite database");
    rm_store(p);
}

/* A WAL-mode sloth.db that sloth left with frames never checkpointed
 * (it exited uncleanly, or is simply between checkpoints): refused, and
 * neither the file nor its WAL is touched. sloth.db is WAL (src/db.c),
 * and the last read-write connection to close on a WAL database
 * checkpoints it into the main file and deletes the WAL; identifying on
 * a read-only connection is what prevents that. The writer here closes
 * with SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, which leaves the WAL as a
 * crashed process would. Seen red with identify() run on the
 * read-write connection again (the main file grew from 4096 to 20480
 * bytes and the WAL was gone). */
static void test_foreign_wal_left_as_it_is(void) {
    char p[128], w[160];
    path_in(p, sizeof(p), "sloth-wal.db");
    snprintf(w, sizeof(w), "%s-wal", p);
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) close(fd);
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open_v2(p, &h, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    char *m = NULL;
    WT_EQ(sqlite3_exec(h, "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;"
                          "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                          "INSERT INTO meta VALUES ('schema_version','6');"
                          "CREATE TABLE devices (mac TEXT PRIMARY KEY);"
                          "INSERT INTO devices VALUES ('aa:bb:cc:dd:ee:ff');",
                       NULL, NULL, &m), SQLITE_OK);
    sqlite3_free(m);
    int off = -1;
    WT_EQ(sqlite3_db_config(h, SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, 1, &off),
          SQLITE_OK);
    WT_EQ(off, 1);
    sqlite3_close(h);

    static unsigned char mb[1 << 16], ma[1 << 16], wb[1 << 17], wa[1 << 17];
    size_t nmb = slurp(p, mb, sizeof(mb)), nwb = slurp(w, wb, sizeof(wb));
    WT_ASSERT(nwb > 0);                      /* frames really are pending */
    WT_ASSERT(nwb < sizeof(wb));
    char err[512];
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "not a slothweb store");
    web_store_close(&S);
    size_t nma = slurp(p, ma, sizeof(ma)), nwa = slurp(w, wa, sizeof(wa));
    WT_EQ(nma, nmb);
    WT_ASSERT(nmb > 0 && !memcmp(mb, ma, nmb));
    WT_EQ(nwa, nwb);
    WT_ASSERT(!memcmp(wb, wa, nwb));
    rm_store(p);
}

/* sloth's secure_file rules: a symlink, group or other access, two
 * links, a directory, and the same for a side file, are refused and
 * never repaired. Seen red with O_NOFOLLOW dropped from private_main():
 * SQLite's own SQLITE_OPEN_NOFOLLOW still refused the link, but without
 * the reason, so this asserts the reason as well as the refusal.
 *
 * The owner rule (a file owned by another uid is refused) is not
 * covered here: making a file another uid owns needs privilege a test
 * must not ask for, and removing the uid check from check_stat() leaves
 * this suite green. It is held by code reading only. The DEFENSIVE
 * read-back and the writer's second identify are covered through test
 * seams: test_defensive_read_back, test_file_swapped_between_opens.
 *
 * DEFENSIVE is asserted by what it forbids: on the store's own handle,
 * writable_schema is ignored and sqlite_master cannot be written. Seen
 * red with the sqlite3_db_config() call removed from open_db() (the
 * UPDATE went through). */
static void test_file_rules(void) {
    char p[128], q[160], err[512];
    path_in(p, sizeof(p), "target.db");
    path_in(q, sizeof(q), "link.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_ASSERT(sqlite3_exec(S.db, "PRAGMA writable_schema=ON; UPDATE sqlite_master"
                                 " SET sql=sql WHERE name='meta'",
                           NULL, NULL, NULL) != SQLITE_OK);
    sqlite3_exec(S.db, "PRAGMA writable_schema=OFF", NULL, NULL, NULL);
    /* The positive control: the same handle does write its own tables. */
    WT_EQ(sqlite3_exec(S.db, "UPDATE meta SET value=value WHERE name='store'",
                       NULL, NULL, NULL), SQLITE_OK);
    web_store_close(&S);
    WT_EQ(symlink(p, q), 0);
    WT_EQ(web_store_open(&S, q, err, sizeof(err)), -1);
    WT_HAS(err, "symlink");
    web_store_close(&S);
    unlink(q);

    chmod(p, 0640);
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "0600");
    web_store_close(&S);
    struct stat sb;
    stat(p, &sb);
    WT_EQ(sb.st_mode & 0777, 0640);                  /* not repaired */
    chmod(p, 0600);

    WT_EQ(link(p, q), 0);
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "links");
    web_store_close(&S);
    unlink(q);

    char wal[200];
    snprintf(wal, sizeof(wal), "%s-wal", p);
    unlink(wal);
    WT_EQ(symlink("/dev/null", wal), 0);
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "symlink is refused");
    web_store_close(&S);
    unlink(wal);
    int fd = open(wal, O_WRONLY | O_CREAT | O_EXCL, 0644);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) close(fd);
    chmod(wal, 0644);
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "-wal");
    web_store_close(&S);
    unlink(wal);
    rm_store(p);

    path_in(p, sizeof(p), "adir");
    WT_EQ(mkdir(p, 0700), 0);
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    web_store_close(&S);
    rmdir(p);
}

/* The DEFENSIVE read-back: a library that takes the call but leaves
 * DEFENSIVE off fails the open, and the new file it made is left with
 * no table. Seen red with "|| on != 1" removed from open_db() (the
 * open succeeded). */
static void test_defensive_read_back(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "nodef.db");
    web_store_test_no_defensive = 1;
    int rc = web_store_open(&S, p, err, sizeof(err));
    web_store_test_no_defensive = 0;
    WT_EQ(rc, -1);
    WT_HAS(err, "DEFENSIVE");
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM sqlite_master"), 0);
    rm_store(p);
}

static char g_swap_from[160];
static void swap_in(const char *path) {
    WT_EQ(rename(g_swap_from, path), 0);
}

/* The writer's identify: a file identified as new and empty on the
 * read-only connection, then replaced before the read-write open by
 * another program's database, is refused, and that database is left
 * byte for byte. Seen red with the writer's identify check removed
 * from web_store_open() (the store stamped its meta table into it and
 * opened). */
static void test_file_swapped_between_opens(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "swap.db");
    path_in(g_swap_from, sizeof(g_swap_from), "swap-other.db");
    raw_exec(g_swap_from, "CREATE TABLE things (x INTEGER);"
                          "INSERT INTO things VALUES (1);");
    static unsigned char before[1 << 16], after[1 << 16];
    size_t nb = slurp(g_swap_from, before, sizeof(before));
    WT_ASSERT(nb > 0);
    web_store_test_between_opens = swap_in;
    int rc = web_store_open(&S, p, err, sizeof(err));
    web_store_test_between_opens = NULL;
    WT_EQ(rc, -1);
    WT_HAS(err, "not a slothweb store");
    web_store_close(&S);
    size_t na = slurp(p, after, sizeof(after));
    WT_EQ(na, nb);
    WT_ASSERT(!memcmp(before, after, nb));
    WT_EQ(raw_int(p, "SELECT x FROM things"), 1);
    rm_store(p);
}

/* A cleanly closed WAL-mode sloth.db (no -wal or -shm beside it) is
 * refused and the directory is left as it was: no empty -wal, no
 * -shm. A read-only connection makes both on a WAL database; the clean
 * one is identified as immutable instead. Seen red with wal_clean()'s
 * answer ignored in web_store_open() (sloth.db-wal and sloth.db-shm
 * were left behind). */
static int cmp_name(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

static int dir_list(const char *dir, char *out, size_t outsz) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    static char names[32][256];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < 32) {
        if (e->d_name[0] == '.') continue;
        snprintf(names[n++], sizeof(names[0]), "%.255s", e->d_name);
    }
    closedir(d);
    qsort(names, (size_t)n, sizeof(names[0]), cmp_name);
    out[0] = '\0';
    for (int i = 0; i < n; i++) {
        strncat(out, names[i], outsz - strlen(out) - 2);
        strncat(out, " ", outsz - strlen(out) - 1);
    }
    return n;
}

static void test_clean_wal_refused_leaves_dir_unchanged(void) {
    char dir[96], p[160], err[512];
    snprintf(dir, sizeof(dir), "%s/cleanwal", g_dir);
    WT_EQ(mkdir(dir, 0700), 0);
    snprintf(p, sizeof(p), "%s/sloth.db", dir);
    int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
    WT_ASSERT(fd >= 0);
    if (fd >= 0) close(fd);
    sqlite3 *h = NULL;
    WT_EQ(sqlite3_open_v2(p, &h, SQLITE_OPEN_READWRITE, NULL), SQLITE_OK);
    WT_EQ(sqlite3_exec(h, "PRAGMA journal_mode=WAL;"
                          "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                          "INSERT INTO meta VALUES ('schema_version','6');",
                       NULL, NULL, NULL), SQLITE_OK);
    sqlite3_close(h);                         /* checkpointed, WAL removed */
    char la[512], lb[512];
    WT_EQ(dir_list(dir, lb, sizeof(lb)), 1);
    WT_HAS(lb, "sloth.db ");
    static unsigned char mb[1 << 16], ma[1 << 16];
    size_t nmb = slurp(p, mb, sizeof(mb));
    WT_ASSERT(nmb > 0 && mb[18] == 2 && mb[19] == 2);      /* WAL mode */
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), -1);
    WT_HAS(err, "not a slothweb store");
    web_store_close(&S);
    WT_EQ(dir_list(dir, la, sizeof(la)), 1);
    WT_ASSERT(!strcmp(la, lb));
    if (strcmp(la, lb)) fprintf(stderr, "  before: %s\n  after:  %s\n", lb, la);
    size_t nma = slurp(p, ma, sizeof(ma));
    WT_EQ(nma, nmb);
    WT_ASSERT(!memcmp(mb, ma, nmb));
    rm_store(p);
    rmdir(dir);
}

static web_qrow_t row(int tier, int metric, const char *key, long long t,
                      double sum, unsigned long n, double mn, double mx) {
    web_qrow_t r;
    memset(&r, 0, sizeof(r));
    r.tier = tier;
    r.metric = metric;
    snprintf(r.key, sizeof(r.key), "%s", key);
    r.t = t;
    r.sum = sum;
    r.n = n;
    r.min = mn;
    r.max = mx;
    return r;
}

/* A bucket written twice (split by an eviction or a restart) is merged;
 * queries are newest first, bounded, and bind their parameters: a key
 * that reads as SQL finds nothing and breaks nothing. */
static void test_write_merge_query(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "rw.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    web_qrow_t r[40];
    int n = 0;
    for (int i = 0; i < 30; i++)
        r[n++] = row(WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 1000 + i * 10,
                     i, 1, i, i);
    r[n++] = row(WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 1000, 5, 2, -1, 9);
    r[n++] = row(WEB_TIER_MINUTE, WM_HOST_RX, "10.0.0.1", 960, 7, 7, 1, 1);
    WT_EQ(web_store_write(&S, r, (size_t)n), 0);
    WT_EQ(web_store_count(&S, WEB_TIER_FINE), 30);
    WT_EQ(web_store_count(&S, WEB_TIER_MINUTE), 1);
    web_point_t pt[64];
    int more;
    int k = web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 0, 5000,
                            pt, 64, &more);
    WT_EQ(k, 30);
    WT_EQ(more, 0);
    WT_EQ(pt[0].t, 1290);
    WT_EQ(pt[29].t, 1000);
    WT_EQ(pt[29].n, 3);
    WT_ASSERT(pt[29].sum == 5 && pt[29].min == -1 && pt[29].max == 9);
    k = web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 0, 5000,
                        pt, 10, &more);
    WT_EQ(k, 10);
    WT_EQ(more, 1);
    k = web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1", 1010, 1030,
                        pt, 64, &more);
    WT_EQ(k, 2);                                      /* [from, to) */
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "' OR 1=1 --", 0,
                          5000, pt, 64, &more), 0);
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_HOST_TX, "10.0.0.1", 0, 5000,
                          pt, 64, &more), 0);
    WT_EQ(web_store_query(&S, WEB_TIER_MINUTE, WM_HOST_RX, "10.0.0.1", 0, 5000,
                          pt, 64, &more), 1);
    web_store_stats_t st;
    web_store_stats(&S, &st);
    WT_EQ(st.batches, 1);
    WT_EQ(st.write_errors, 0);
    web_store_close(&S);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM series"), 1);
    rm_store(p);
}

/* Retention per tier: fine 24 h, minute --web-retain-days, hour 400 d. */
static void test_compaction_retention(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "keep.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    const long long now = 1792627200;
    web_qrow_t r[6] = {
        row(WEB_TIER_FINE,   WM_CONNS_TOTAL, "", now - 86400 - 10, 1, 1, 1, 1),
        row(WEB_TIER_FINE,   WM_CONNS_TOTAL, "", now - 100, 1, 1, 1, 1),
        row(WEB_TIER_MINUTE, WM_CONNS_TOTAL, "", now - 8 * 86400, 1, 1, 1, 1),
        row(WEB_TIER_MINUTE, WM_CONNS_TOTAL, "", now - 6 * 86400, 1, 1, 1, 1),
        row(WEB_TIER_HOUR,   WM_CONNS_TOTAL, "", now - 401 * 86400, 1, 1, 1, 1),
        row(WEB_TIER_HOUR,   WM_CONNS_TOTAL, "", now - 399 * 86400, 1, 1, 1, 1),
    };
    WT_EQ(web_store_write(&S, r, 6), 0);
    WT_EQ(web_store_compact(&S, now, 7, 256LL << 20), 0);
    WT_EQ(web_store_count(&S, WEB_TIER_FINE), 1);
    WT_EQ(web_store_count(&S, WEB_TIER_MINUTE), 1);
    WT_EQ(web_store_count(&S, WEB_TIER_HOUR), 1);
    web_store_stats_t st;
    web_store_stats(&S, &st);
    WT_EQ(st.dropped_expired, 3);
    WT_EQ(st.dropped_ceiling, 0);
    WT_EQ(st.compactions, 1);
    WT_EQ(st.rows[WEB_TIER_FINE], 1);
    web_store_close(&S);
    rm_store(p);
}

/* --web-max-mb: over the ceiling, the oldest fine rows go first and the
 * minute and hour tiers are left alone while fine rows remain. Seen red
 * with the ceiling loop's tier order reversed (the minute rows went). */
static void test_ceiling_drops_oldest_fine_first(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "ceil.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    const long long now = 1792627200;
    static web_qrow_t r[4000];
    char k[32];
    for (int s = 0; s < 20; s++) {
        snprintf(k, sizeof(k), "10.0.%d.1", s);
        int n = 0;
        for (int b = 0; b < 4000; b++)       /* 11 h of 10 s buckets */
            r[n++] = row(WEB_TIER_FINE, WM_HOST_RX, k, now - 40000 + b * 10,
                         b * 1.5, 3, 0.25, b * 2.0);
        WT_EQ(web_store_write(&S, r, (size_t)n), 0);
        r[0] = row(WEB_TIER_MINUTE, WM_HOST_RX, k, now - 40000, 1, 1, 1, 1);
        WT_EQ(web_store_write(&S, r, 1), 0);
    }
    web_store_stats_t st;
    web_store_stats(&S, &st);
    WT_ASSERT(st.bytes > 2LL << 20);
    const long long cap = 1LL << 20;
    WT_EQ(web_store_compact(&S, now, 30, cap), 0);
    web_store_stats(&S, &st);
    WT_ASSERT(st.bytes <= cap);
    WT_ASSERT(st.dropped_ceiling > 0);
    WT_EQ(web_store_count(&S, WEB_TIER_MINUTE), 20);
    long long left = web_store_count(&S, WEB_TIER_FINE);
    WT_ASSERT(left > 0 && left < 80000);
    web_point_t pt[2];
    int more;
    /* The newest bucket survived; the oldest did not. */
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1",
                          now - 10, now, pt, 2, &more), 1);
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_HOST_RX, "10.0.0.1",
                          now - 40000, now - 39990, pt, 2, &more), 0);
    web_store_close(&S);
    /* Pages went back to the file system and the WAL was truncated. */
    struct stat sb;
    WT_EQ(stat(p, &sb), 0);
    WT_ASSERT(sb.st_size <= cap + (256 << 10));
    char wal[200];
    snprintf(wal, sizeof(wal), "%s-wal", p);
    if (stat(wal, &sb) == 0) WT_ASSERT(sb.st_size <= (1 << 20));
    rm_store(p);
}

static long long disk_bytes(const char *p) {
    char w[200];
    struct stat sb;
    long long b = 0;
    if (stat(p, &sb) == 0) b += sb.st_size;
    snprintf(w, sizeof(w), "%s-wal", p);
    if (stat(w, &sb) == 0) b += sb.st_size;
    return b;
}

/* --web-max-mb bounds the store within one flush interval, not one
 * compaction: key churn (200 new source IPs a second, as a scan of the
 * LAN or a DNS flood from spoofed sources would give) through the real
 * rollup, store and store thread step, on a pinned clock, for 400 s
 * with a 4 MB ceiling. After every step the used size is under the ceiling and the
 * file and its WAL within the WAL's 1 MB cap of it; the ceiling ran
 * between compactions (only the start one ran); the churn keys' minute
 * and hour rows were never written (evicted before established); the global
 * series kept all of its minute rows and its newest fine ones. Seen red
 * with the ceiling call removed from web_tsdb.c's flush() (the used
 * size reached 6.8 MB, 7.7 MB on disk, before the first hourly
 * compaction). */
static void test_ceiling_holds_under_key_churn(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "churn.db");
    static web_rollup_t ru;
    static web_tsdb_t ts;
    const long long T = 1792627200;
    const int max_mb = 4;
    const long long cap = (long long)max_mb << 20;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 256, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, max_mb, NULL, NULL), 0);
    long long worst_used = 0, worst_disk = 0;
    unsigned ip = 0;
    for (int sec = 0; sec < 400; sec++) {
        long long now = T + sec;
        web_rollup_add(&ru, WM_CONNS_TOTAL, "", 15, now);
        for (int i = 0; i < 200; i++, ip++) {
            char k[32];
            snprintf(k, sizeof(k), "10.%u.%u.%u", (ip >> 16) & 0xff,
                     (ip >> 8) & 0xff, ip & 0xff);
            web_rollup_add(&ru, WM_DNS_QUERIES, k, 1, now);
        }
        web_tsdb_step(&ts, now);
        web_store_stats_t st;
        web_store_stats(&S, &st);
        if (st.bytes > worst_used) worst_used = st.bytes;
        long long d = disk_bytes(p);
        if (d > worst_disk) worst_disk = d;
    }
    fprintf(stderr, "  churn: worst used %lld, worst on disk %lld (cap %lld)\n",
            worst_used, worst_disk, cap);
    WT_ASSERT(worst_used <= cap);
    WT_ASSERT(worst_disk <= cap + (5LL << 18));
    web_store_stats_t st;
    web_store_stats(&S, &st);
    WT_EQ(st.compactions, 1);
    WT_ASSERT(st.ceiling_runs > 0);
    WT_ASSERT(st.dropped_ceiling > 0);
    WT_EQ(st.write_errors, 0);
    web_rollup_stats_t rs;
    web_rollup_stats(&ru, &rs);
    WT_EQ(rs.q_dropped, 0);
    WT_ASSERT(rs.churn_dropped > 0);
    WT_ASSERT(rs.evictions[WEB_KC_HOST] > 70000);

    web_tsdb_flush_all(&ts);
    web_point_t pt[16];
    int more;
    /* Six closed minutes and the one in progress; the hour; the newest
     * minute of fine rows. */
    WT_EQ(web_store_query(&S, WEB_TIER_MINUTE, WM_CONNS_TOTAL, "", T, T + 3600,
                          pt, 16, &more), 7);
    WT_EQ(web_store_query(&S, WEB_TIER_HOUR, WM_CONNS_TOTAL, "", T, T + 3600,
                          pt, 16, &more), 1);
    WT_EQ(web_store_query(&S, WEB_TIER_FINE, WM_CONNS_TOTAL, "", T + 340, T + 400,
                          pt, 16, &more), 6);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    rm_store(p);
}

/* Key churn with more than one sample per key, through the real
 * rollup, store thread step and store: 20 new source IPs a second for
 * 400 s, each seen `samples` times two seconds apart (a spoofed source
 * sending two or three queries, a scanned host in two or three
 * top_hosts passes), so each lives 2 or 4 s and crosses minute
 * boundaries throughout. None of them was ever seen across a minute,
 * so while slothweb runs not one of their minute or hour rows reaches
 * the file, and their fine rows do. A control host seen every second
 * is established after a minute and has its minute rows. At shutdown
 * the keys still resident (at most the 128 of the host class) write
 * what they held, at most two rows a tier each. Seen red with
 * key_flush() emitting unestablished keys' long tiers (7,933 churn
 * minute rows and 7,693 hour rows on disk before shutdown with two
 * samples a key, 8,225 and 7,745 with three). */
static void churn_samples(int samples) {
    char p[128], err[512];
    snprintf(err, sizeof(err), "churn%d.db", samples);
    path_in(p, sizeof(p), err);
    static web_rollup_t ru;
    static web_tsdb_t ts;
    const long long T = 1792627200;
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    WT_EQ(web_rollup_init(&ru, 256, 1, err, sizeof(err)), 0);
    WT_EQ(web_tsdb_init(&ts, &ru, &S, 30, 256, NULL, NULL), 0);
    for (int sec = 0; sec < 400; sec++) {
        long long now = T + sec;
        web_rollup_add(&ru, WM_DNS_QUERIES, "192.168.0.1", 1, now);
        for (int j = 0; j < samples; j++) {
            int born = sec - 2 * j;           /* keys born at second `born` */
            if (born < 0) continue;
            for (int i = 0; i < 20; i++) {
                unsigned ip = (unsigned)born * 20 + (unsigned)i;
                char k[32];
                snprintf(k, sizeof(k), "10.%u.%u.%u", (ip >> 16) & 0xff,
                         (ip >> 8) & 0xff, ip & 0xff);
                web_rollup_add(&ru, WM_DNS_QUERIES, k, 1, now);
            }
        }
        web_tsdb_step(&ts, now);
    }
    web_rollup_stats_t rs;
    web_rollup_stats(&ru, &rs);
    WT_ASSERT(rs.evictions[WEB_KC_HOST] > 7000);
    WT_ASSERT(rs.churn_dropped > 7000);
    WT_EQ(rs.q_dropped, 0);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM minute m JOIN series s ON"
                     " s.id=m.series WHERE s.key LIKE '10.%'"), 0);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM hour m JOIN series s ON"
                     " s.id=m.series WHERE s.key LIKE '10.%'"), 0);
    WT_ASSERT(raw_int(p, "SELECT COUNT(*) FROM fine m JOIN series s ON"
                         " s.id=m.series WHERE s.key LIKE '10.%'") > 7000);
    WT_ASSERT(raw_int(p, "SELECT COUNT(*) FROM minute m JOIN series s ON"
                         " s.id=m.series WHERE s.key='192.168.0.1'") >= 5);
    web_tsdb_flush_all(&ts);
    long long held = raw_int(p, "SELECT COUNT(*) FROM minute m JOIN series s"
                                " ON s.id=m.series WHERE s.key LIKE '10.%'");
    WT_ASSERT(held > 0 && held <= 2 * 128);
    WT_ASSERT(raw_int(p, "SELECT COUNT(*) FROM hour m JOIN series s ON"
                         " s.id=m.series WHERE s.key LIKE '10.%'") <= 2 * 128);
    web_tsdb_destroy(&ts);
    web_rollup_destroy(&ru);
    web_store_close(&S);
    rm_store(p);
}

static void test_churn_two_samples_not_in_long_tiers(void) { churn_samples(2); }
static void test_churn_three_samples_not_in_long_tiers(void) { churn_samples(3); }

/* Past the fine tier, the ceiling takes keyed minute and hour rows
 * before any row of a global series: those are one series per metric
 * whatever the traffic, and the long view of the whole network. Seen
 * red with the ceiling's steps reordered to take global rows first
 * (the global minute rows went while keyed ones were left). */
static void test_ceiling_spares_global_series(void) {
    char p[128], err[512];
    path_in(p, sizeof(p), "ceilg.db");
    WT_EQ(web_store_open(&S, p, err, sizeof(err)), 0);
    const long long now = 1792627200;
    static web_qrow_t r[3000];
    char k[32];
    for (int s = 0; s < 12; s++) {
        snprintf(k, sizeof(k), "10.0.%d.1", s);
        for (int b = 0; b < 3000; b++)
            r[b] = row(WEB_TIER_MINUTE, WM_HOST_RX, k, now - 200000 + b * 60,
                       b, 1, b, b);
        WT_EQ(web_store_write(&S, r, 3000), 0);
    }
    for (int b = 0; b < 3000; b++)
        r[b] = row(WEB_TIER_MINUTE, WM_CONNS_TOTAL, "", now - 200000 + b * 60,
                   b, 1, b, b);
    WT_EQ(web_store_write(&S, r, 3000), 0);
    web_store_stats_t st;
    web_store_stats(&S, &st);
    const long long cap = 512LL << 10;
    WT_ASSERT(st.bytes > cap);
    WT_ASSERT(web_store_ceiling(&S, cap) > 0);
    web_store_stats(&S, &st);
    WT_ASSERT(st.bytes <= cap);
    WT_EQ(st.ceiling_runs, 1);
    WT_EQ(raw_int(p, "SELECT COUNT(*) FROM minute m JOIN series s ON s.id="
                     "m.series WHERE s.key=''"), 3000);
    long long keyed = raw_int(p, "SELECT COUNT(*) FROM minute m JOIN series s"
                                 " ON s.id=m.series WHERE s.key<>''");
    WT_ASSERT(keyed > 0 && keyed < 36000);
    /* Under the ceiling, a second call is the cheap test and nothing. */
    WT_EQ(web_store_ceiling(&S, cap), 0);
    web_store_stats(&S, &st);
    WT_EQ(st.ceiling_runs, 1);
    web_store_close(&S);
    rm_store(p);
}

void run_store_tests(void) {
    if (mkdir_tmp() != 0) {
        WT_ASSERT(!"mkdtemp");
        return;
    }
    WT_EQ(web_store_available(), 1);
    WT_RUN(test_schema_text_guardrail);
    WT_RUN(test_fresh_store);
    WT_RUN(test_no_column_can_hold_secret_material);
    WT_RUN(test_v0_file_is_migrated);
    WT_RUN(test_v0_failed_step_leaves_file_unchanged);
    WT_RUN(test_v1_file_is_migrated);
    WT_RUN(test_v1_failed_step_leaves_file_unchanged);
    WT_RUN(test_newer_file_refused);
    WT_RUN(test_foreign_files_refused);
    WT_RUN(test_foreign_wal_left_as_it_is);
    WT_RUN(test_file_rules);
    WT_RUN(test_defensive_read_back);
    WT_RUN(test_file_swapped_between_opens);
    WT_RUN(test_clean_wal_refused_leaves_dir_unchanged);
    WT_RUN(test_write_merge_query);
    WT_RUN(test_compaction_retention);
    WT_RUN(test_ceiling_drops_oldest_fine_first);
    WT_RUN(test_ceiling_spares_global_series);
    WT_RUN(test_ceiling_holds_under_key_churn);
    WT_RUN(test_churn_two_samples_not_in_long_tiers);
    WT_RUN(test_churn_three_samples_not_in_long_tiers);
    WT_RUN(test_secrets_never_reach_disk);
    rmdir(g_dir);
}

#endif /* WITH_SQLITE */
