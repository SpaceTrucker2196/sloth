#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer smoke target for slothweb's SQL box guard (#163, M5):
 * web_sqlbox_run_db() (web/src/web_sqlguard.c), the text rules, the
 * one-statement check, the authorizer, the limits and the runner, over
 * an in-memory database with sloth's own schema (src/db_schema.c, in
 * libsloth_core.a) and rows that hold the values the box must never
 * serve.
 *
 * slothweb is a separate binary whose sources libsloth_core.a does not
 * carry (and must not), so the three translation units the guard needs
 * are included here directly, as fuzz_web_query.c does.
 *
 * Beyond memory safety, three properties are checked on every input,
 * each an abort() (a crash to libFuzzer) when broken:
 *   - nothing is written: total_changes() and the schema cookie are
 *     what they were after the seed;
 *   - an accepted statement reads no withheld column: it is prepared
 *     again under an authorizer of the harness's own that records every
 *     read, and none may be a column the harness itself works out to be
 *     withheld (web_sdb_secret[] or TEXT/BLOB named for a word);
 *   - an accepted statement's text starts, after blanks and comments,
 *     with SELECT or WITH, and is one statement.
 * An input whose first byte is below 8 has it replaced by one of the
 * prefixes below, 8..15 by "SELECT * FROM " and one of sloth's tables
 * (the next byte picks it), 16 by a complete first statement, so that
 * the mutations spend their time past the first keyword, where the
 * authorizer and the tail check are, rather than on it. Without them a
 * minute of fuzzing found neither a withheld column let through nor a
 * second statement accepted, each planted on purpose. */
#include "../../web/src/web_json.c"
#include "../../web/src/web_secret.c"
#include "../../web/src/web_sqlguard.c"

const char *db_schema_sql(void);
const char *db_schema_meta_sql(void);

static sqlite3 *g_db;
static int      g_ready;
static long long g_changes;
static int      g_cookie;
static char     g_out[1 << 16];

typedef struct { char t[64], c[64]; } col_t;
static col_t g_deny[512];
static int   g_ndeny;
static char  g_tables[64][64];
static int   g_ntables;
static int   g_bad_read;

static int cookie(void) {
    sqlite3_stmt *st = NULL;
    int v = -1;
    sqlite3_set_authorizer(g_db, NULL, NULL);
    if (sqlite3_prepare_v2(g_db, "PRAGMA schema_version", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW)
        v = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return v;
}

static int words_hit(const char *c) {
    for (int k = 0; web_sdb_secret_words[k]; k++) {
        const char *w = web_sdb_secret_words[k];
        size_t n = strlen(w);
        for (const char *p = c; *p; p++) {
            size_t i = 0;
            while (i < n && p[i] && ((p[i] | 32) == (w[i] | 32))) i++;
            if (i == n) return 1;
        }
    }
    return 0;
}

static void setup(void) {
    if (sqlite3_open(":memory:", &g_db) != SQLITE_OK) abort();
    if (sqlite3_exec(g_db, db_schema_meta_sql(), NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(g_db, db_schema_sql(), NULL, NULL, NULL) != SQLITE_OK ||
        sqlite3_exec(g_db,
            "INSERT INTO devices (mac,vendor,first_seen,last_seen) VALUES"
            " ('02:00:00:00:00:01','Acme',1,2),('02:00:00:00:00:02',NULL,3,4);"
            "INSERT INTO cleartext_creds (ts,src,dst,dst_port,protocol,username,"
            "pw_observed,first_seen,last_seen) VALUES (1,'a','b',21,'ftp','u1',1,1,1);"
            "INSERT INTO alerts (key,first_seen,last_seen,type,sev,title,detail,count)"
            " VALUES ('cred:u1',1,1,12,1,'T','d u1',1);"
            "INSERT INTO rogue_radius (bssid,last_identity,first_seen,last_seen)"
            " VALUES ('x','id1',1,1);", NULL, NULL, NULL) != SQLITE_OK)
        abort();
    /* The withheld columns, worked out here from the schema. */
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(g_db, "SELECT m.name, c.name, c.type FROM sqlite_schema m,"
                           " pragma_table_info(m.name) c WHERE m.type='table'",
                           -1, &st, NULL) != SQLITE_OK)
        abort();
    while (sqlite3_step(st) == SQLITE_ROW && g_ndeny < 512) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        const char *c = (const char *)sqlite3_column_text(st, 1);
        const char *ty = (const char *)sqlite3_column_text(st, 2);
        if (g_ntables < 64 && (!g_ntables || strcmp(g_tables[g_ntables - 1], t)))
            snprintf(g_tables[g_ntables++], 64, "%s", t);
        int texty = !ty || !ty[0] || strstr(ty, "TEXT") || strstr(ty, "BLOB") ||
                    strstr(ty, "CHAR") || strstr(ty, "CLOB");
        int expl = 0;
        for (size_t k = 0; k < web_sdb_secret_n; k++)
            if (!strcmp(web_sdb_secret[k].table, t) && !strcmp(web_sdb_secret[k].column, c))
                expl = 1;
        if (expl || (texty && words_hit(c))) {
            snprintf(g_deny[g_ndeny].t, 64, "%s", t);
            snprintf(g_deny[g_ndeny].c, 64, "%s", c);
            g_ndeny++;
        }
    }
    sqlite3_finalize(st);
    if (g_ndeny < 4) abort();
    g_changes = sqlite3_total_changes64(g_db);
    g_cookie = cookie();
    g_ready = 1;
}

static int record(void *ud, int action, const char *a1, const char *a2,
                  const char *db, const char *trig) {
    (void)ud; (void)db; (void)trig;
    if (action == SQLITE_READ && a1 && a2 && a2[0])
        for (int i = 0; i < g_ndeny; i++)
            if (!sqlite3_stricmp(g_deny[i].t, a1) && !sqlite3_stricmp(g_deny[i].c, a2))
                g_bad_read = 1;
    return SQLITE_OK;
}

static const char *const PREFIX[8] = {
    "SELECT ", "SELECT * FROM ", "WITH x AS (SELECT ", "SELECT mac FROM devices WHERE ",
    "SELECT count(*) FROM alerts WHERE ", "SELECT a.* FROM cleartext_creds a JOIN ",
    "SELECT (SELECT ", "WITH RECURSIVE ",
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_ready) setup();
    static char sql[WEB_SQL_MAX_BYTES + 64];
    size_t o = 0;
    if (size && data[0] < 8) {
        o = strlen(PREFIX[data[0]]);
        memcpy(sql, PREFIX[data[0]], o);
        data++;
        size--;
    } else if (size >= 2 && data[0] < 16) {
        o = (size_t)snprintf(sql, sizeof(sql), "SELECT * FROM %s ",
                             g_tables[data[1] % g_ntables]);
        data += 2;
        size -= 2;
    } else if (size && data[0] == 16) {
        o = (size_t)snprintf(sql, sizeof(sql), "SELECT 1;");
        data++;
        size--;
    }
    if (o + size > WEB_SQL_MAX_BYTES) return 0;
    memcpy(sql + o, data, size);
    size += o;
    sql[size] = '\0';
    web_sqlbox_lim_t lim = { 20, 50, sizeof(g_out) - 1024 };
    web_sqlbox_res_t res;
    web_sqlbox_run_db(g_db, sql, size, &lim, g_out, sizeof(g_out), &res);
    if (sqlite3_total_changes64(g_db) != g_changes) abort();
    if (cookie() != g_cookie) abort();
    if (res.status != 200) return 0;
    const char *why;
    if (web_sqlbox_precheck(sql, size, &why) != 0) abort();
    /* Prepared again, every read recorded. */
    sqlite3_set_authorizer(g_db, record, NULL);
    sqlite3_stmt *st = NULL;
    const char *tail = NULL;
    g_bad_read = 0;
    if (sqlite3_prepare_v2(g_db, sql, (int)size, &st, &tail) == SQLITE_OK && st) {
        if (tail && !web_sqlbox_blank(tail, size - (size_t)(tail - sql))) abort();
        if (!sqlite3_stmt_readonly(st)) abort();
    }
    sqlite3_finalize(st);
    sqlite3_set_authorizer(g_db, NULL, NULL);
    if (g_bad_read) abort();
    return 0;
}
