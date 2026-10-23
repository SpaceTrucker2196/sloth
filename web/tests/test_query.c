/* The device query language (#162, M4; docs/web-ui-spec.md §9.1): the
 * parser's bounds and per-prefix forms, and the compiler's one
 * statement, whose text holds nothing of the query (every value is a
 * bound parameter, a LIKE pattern escaped). Running the statement
 * against a sloth.db is test_slothdb.c's. */
#include <stdio.h>
#include <string.h>

#include "sloth.h"
#include "web_anomaly.h"
#include "web_query.h"
#include "wtest.h"

#define NOW 1792627200LL     /* 2026-10-22 00:00:00 UTC */

static web_query_t Q;
static web_qsql_t  S;

static int parse(const char *q, char *err) {
    err[0] = '\0';
    return web_query_parse(q, NOW, &Q, err, 64);
}

/* The terms of the acceptance query, as the parser takes them. */
static void test_acceptance_terms(void) {
    char err[64];
    WT_EQ(parse("vendor:apple random:yes seen:<24h", err), 0);
    WT_EQ(Q.n, 3);
    WT_EQ(Q.t[0].kind, WEB_QT_VENDOR);
    WT_ASSERT(!strcmp(Q.t[0].text, "apple"));
    WT_EQ(Q.t[1].kind, WEB_QT_RANDOM);
    WT_EQ(Q.t[1].num, 1);
    WT_EQ(Q.t[2].kind, WEB_QT_SEEN);
    WT_EQ(Q.t[2].op, WEB_QOP_GT);
    WT_EQ(Q.t[2].num, NOW - 86400);
}

/* Every prefix of §9.1, one example each, as the spec writes them. */
static void test_every_prefix(void) {
    char err[64];
    WT_EQ(parse("vendor:apple mac:b8:27:eb ip:192.168.1. ssid:CorpWiFi "
                "name:printer random:no", err), 0);
    WT_EQ(Q.n, 6);
    WT_ASSERT(!strcmp(Q.t[1].text, "b8:27:eb"));
    WT_ASSERT(!strcmp(Q.t[2].text, "192.168.1."));
    WT_EQ(Q.t[5].num, 0);
    WT_EQ(parse("seen:>2026-09-29 first:<7d risk:>0 z:>3 src:probe has:pnl", err), 0);
    WT_EQ(Q.n, 6);
    WT_EQ(Q.t[0].op, WEB_QOP_GE);
    WT_EQ(Q.t[0].num, 1790640000);             /* 2026-09-29 00:00 UTC */
    WT_EQ(Q.t[1].kind, WEB_QT_FIRST);
    WT_EQ(Q.t[1].op, WEB_QOP_GT);
    WT_EQ(Q.t[1].num, NOW - 7 * 86400);
    WT_EQ(Q.t[2].op, WEB_QOP_GT);
    WT_EQ(Q.t[2].num, 0);
    WT_EQ(Q.t[3].op, WEB_QOP_GT);
    WT_ASSERT(Q.t[3].z == 3.0);
    WT_EQ(Q.t[4].num, DEV_SRC_PROBE);
    WT_EQ(Q.t[5].num, WEB_HAS_PNL);
    WT_EQ(parse("has:alert anomaly:hours seen:>7d seen:2026-10-21 seen:<2026-10-21", err), 0);
    WT_EQ(Q.t[1].kind, WEB_QT_ANOMALY);
    WT_EQ(Q.t[1].num, web_anomaly_kind_find("hours"));
    WT_EQ(Q.t[2].op, WEB_QOP_LT);              /* last seen over 7 d ago */
    WT_EQ(Q.t[2].num, NOW - 7 * 86400);
    WT_EQ(Q.t[3].op, WEB_QOP_EQ);              /* on that day */
    WT_EQ(Q.t[3].num, NOW - 86400);
    WT_EQ(Q.t[3].num2, NOW);
    WT_EQ(Q.t[4].op, WEB_QOP_LT);
    WT_EQ(Q.t[4].num, NOW - 86400);            /* before that day */
    WT_EQ(parse("seen:<=2026-10-21 seen:>=2026-10-21 first:<=1d", err), 0);
    WT_EQ(Q.t[0].op, WEB_QOP_LT);              /* to the day's end */
    WT_EQ(Q.t[0].num, NOW);
    WT_EQ(Q.t[1].op, WEB_QOP_GE);              /* from its start, as > */
    WT_EQ(Q.t[1].num, NOW - 86400);
    WT_EQ(Q.t[2].op, WEB_QOP_GT);
    WT_EQ(Q.t[2].num, NOW - 86400);
    WT_EQ(parse("risk:<=2 risk:3 z:<1.25 z:2", err), 0);
    WT_EQ(Q.t[0].op, WEB_QOP_LE);
    WT_EQ(Q.t[1].op, WEB_QOP_EQ);
    WT_EQ(Q.t[1].num, 3);
    WT_EQ(Q.t[2].op, WEB_QOP_LT);
    WT_ASSERT(Q.t[2].z == 1.25);
    WT_EQ(Q.t[3].op, WEB_QOP_GE);
}

/* Free text, negation, quotes, and a word before ':' that is no prefix
 * (a MAC fragment) taken as text. */
static void test_text_negation_quotes(void) {
    char err[64];
    WT_EQ(parse("-name:printer \"living room\" b8:27:eb ab:cd -laptop", err), 0);
    WT_EQ(Q.n, 5);
    WT_EQ(Q.t[0].neg, 1);
    WT_EQ(Q.t[0].kind, WEB_QT_NAME);
    WT_EQ(Q.t[1].kind, WEB_QT_FREE);
    WT_ASSERT(!strcmp(Q.t[1].text, "living room"));
    WT_EQ(Q.t[2].kind, WEB_QT_FREE);
    WT_ASSERT(!strcmp(Q.t[2].text, "b8:27:eb"));
    WT_EQ(Q.t[3].kind, WEB_QT_FREE);
    WT_ASSERT(!strcmp(Q.t[3].text, "ab:cd"));
    WT_EQ(Q.t[4].neg, 1);
    WT_EQ(Q.t[4].kind, WEB_QT_FREE);
    WT_EQ(parse("ssid:\"Corp WiFi\"", err), 0);
    WT_ASSERT(!strcmp(Q.t[0].text, "Corp WiFi"));
    WT_EQ(parse("mac:B8-27-EB", err), 0);
    WT_ASSERT(!strcmp(Q.t[0].text, "b8:27:eb"));
    WT_EQ(parse("", err), 0);
    WT_EQ(Q.n, 0);
    WT_EQ(parse("   ", err), 0);
    WT_EQ(Q.n, 0);
    WT_EQ(parse("name:caf\xc3\xa9", err), 0);
}

/* Every refusal and its reason. A MAC without its separators seen red
 * with mac_value()'s separator check removed. */
static void test_refusals(void) {
    static const char *const bad[][2] = {
        { "vendor:", "empty_value" }, { "-", "empty_value" },
        { "\"\"", "empty_value" },
        { "mac:zz", "bad_mac" }, { "mac:b827eb", "bad_mac" },
        { "mac:b8:27:eb:12:34:56:78", "bad_mac" }, { "mac::b8", "bad_mac" },
        { "ip:10.0.0.1;", "bad_ip" }, { "ip:%", "bad_ip" },
        { "random:maybe", "bad_random" },
        { "seen:24", "bad_time" }, { "seen:<24y", "bad_time" },
        { "seen:<1234567h", "bad_time" }, { "seen:2026-02-30", "bad_time" },
        { "seen:1969-12-31", "bad_time" }, { "seen:2026-1-01", "bad_time" },
        { "seen:>", "bad_time" },
        { "risk:4", "bad_risk" }, { "risk:>x", "bad_risk" }, { "risk:12", "bad_risk" },
        { "z:abc", "bad_z" }, { "z:=3", "bad_z" }, { "z:12345", "bad_z" },
        { "z:1.234", "bad_z" }, { "z:1.", "bad_z" },
        { "src:wifi", "bad_src" }, { "has:everything", "bad_has" },
        { "anomaly:vendors", "bad_anomaly" },
        { "ssid:\"open", "bad_quote" }, { "a\"b", "bad_quote" },
        { "\"ab\"c", "bad_quote" },
        { "name:a\x01" "b", "bad_text" }, { "x\xc2\x85y", "bad_text" },
        { "x\xff", "bad_text" }, { "x\x7f", "bad_text" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char err[64];
        int rc = parse(bad[i][0], err);
        if (rc == 0 || strcmp(err, bad[i][1]))
            fprintf(stderr, "    \"%s\": rc %d err %s\n", bad[i][0], rc, err);
        WT_EQ(rc, -1);
        WT_ASSERT(!strcmp(err, bad[i][1]));
    }
}

/* The bounds: the query's length, the number of terms, a term's. */
static void test_bounds(void) {
    char q[WEB_Q_LEN + 8], err[64];
    memset(q, 'a', WEB_Q_LEN);
    q[WEB_Q_LEN] = '\0';
    WT_EQ(parse(q, err), -1);                  /* one term of 256 bytes */
    WT_ASSERT(!strcmp(err, "term_too_long"));
    q[WEB_Q_TERM_LEN] = '\0';
    WT_EQ(parse(q, err), 0);                   /* 64 is the limit */
    q[WEB_Q_TERM_LEN] = 'a';
    q[WEB_Q_TERM_LEN + 1] = '\0';
    WT_EQ(parse(q, err), -1);
    memset(q, 'a', WEB_Q_LEN + 1);
    q[WEB_Q_LEN + 1] = '\0';
    WT_EQ(parse(q, err), -1);
    WT_ASSERT(!strcmp(err, "query_too_long"));
    char many[256] = "";
    for (int i = 0; i < WEB_Q_TERMS; i++) strcat(many, "x ");
    WT_EQ(parse(many, err), 0);
    WT_EQ(Q.n, WEB_Q_TERMS);
    strcat(many, "y");
    WT_EQ(parse(many, err), -1);
    WT_ASSERT(!strcmp(err, "too_many_terms"));
    char quoted[WEB_Q_TERM_LEN + 8];
    quoted[0] = '"';
    memset(quoted + 1, 'b', WEB_Q_TERM_LEN + 1);
    quoted[WEB_Q_TERM_LEN + 2] = '"';
    quoted[WEB_Q_TERM_LEN + 3] = '\0';
    WT_EQ(parse(quoted, err), -1);
    WT_ASSERT(!strcmp(err, "term_too_long"));
}

static int has_param_beyond(const web_qsql_t *s) {
    /* Every ?N names a bind that exists. */
    for (const char *p = s->sql; (p = strchr(p, '?')); p++) {
        int n = 0;
        const char *d = p + 1;
        while (*d >= '0' && *d <= '9') n = n * 10 + (*d++ - '0');
        if (n < 1 || n > s->nb) return 1;
    }
    return 0;
}

/* The statement holds no byte of the query: a value that is SQL stays a
 * bound parameter, its LIKE metacharacters escaped, and the text is the
 * same whatever the values are. Seen red with bind_like()'s escape
 * removed (the pattern kept a bare %) and with term()'s FREE case
 * writing t->text into the statement instead of a parameter. */
static void test_compiled_statement_holds_no_input(void) {
    char err[64];
    WT_EQ(parse("\"x' OR 1=1; DROP TABLE devices; --\" name:50%_off\\", err), 0);
    WT_EQ(web_query_compile(&Q, ~0u, WEB_QS_LAST, 100, 0, &S), 0);
    WT_LACKS(S.sql, "DROP");
    WT_LACKS(S.sql, "1=1");
    WT_LACKS(S.sql, "50");
    WT_EQ(has_param_beyond(&S), 0);
    WT_EQ(S.nb, 4);                            /* two terms, limit, offset */
    WT_EQ(S.b[0].type, 0);
    WT_ASSERT(!strcmp(S.b[0].s, "%x' OR 1=1; DROP TABLE devices; --%"));
    WT_ASSERT(!strcmp(S.b[1].s, "%50\\%\\_off\\\\%"));
    WT_EQ(S.b[2].type, 1);
    WT_EQ(S.b[2].i, 100);
    WT_EQ(S.b[3].i, 0);
    char first[WEB_Q_SQL_MAX];
    snprintf(first, sizeof(first), "%s", S.sql);
    WT_EQ(parse("a name:b", err), 0);
    WT_EQ(web_query_compile(&Q, ~0u, WEB_QS_LAST, 7, 3, &S), 0);
    WT_ASSERT(!strcmp(first, S.sql));          /* the text is the shape */
    /* mac: and ip: are prefixes: no leading %. */
    WT_EQ(parse("mac:b8:27 ip:10.0.", err), 0);
    WT_EQ(web_query_compile(&Q, ~0u, WEB_QS_MAC, 1, 0, &S), 0);
    WT_ASSERT(!strcmp(S.b[0].s, "b8:27%"));
    WT_ASSERT(!strcmp(S.b[1].s, "10.0.%"));
    WT_HAS(S.sql, " ORDER BY d.mac LIMIT ?3 OFFSET ?4");
}

/* Negation, the AND, the day range's two parameters, and a table the
 * file lacks reading as false rather than named (seen red with has:pnl
 * ignoring the feature bits). */
static void test_compiled_shape(void) {
    char err[64];
    WT_EQ(parse("-random:yes seen:2026-10-20 has:pnl ssid:x", err), 0);
    WT_EQ(web_query_compile(&Q, 0, WEB_QS_RISK, 10, 0, &S), 0);
    WT_HAS(S.sql, " WHERE 1 AND NOT (substr(d.mac,2,1) IN");
    WT_HAS(S.sql, "(d.last_seen >= ?1 AND d.last_seen < ?2)");
    WT_HAS(S.sql, " AND (0) AND ");            /* has:pnl, no pnl tables */
    WT_LACKS(S.sql, "pnl_ssids");
    WT_LACKS(S.sql, "dhcp_leases");
    WT_HAS(S.sql, "ORDER BY d.risk_level DESC, d.last_seen DESC, d.mac");
    WT_EQ(S.nb, 5);
    WT_EQ(web_query_compile(&Q, WEB_QF_PNL, WEB_QS_LAST, 10, 0, &S), 0);
    WT_HAS(S.sql, "EXISTS (SELECT 1 FROM pnl_ssids s WHERE s.mac = d.mac)");
    /* The worst case fits: twelve name: terms with every table. */
    char q[WEB_Q_LEN + 1] = "";
    for (int i = 0; i < WEB_Q_TERMS; i++) strcat(q, "-name:x ");
    WT_EQ(parse(q, err), 0);
    WT_EQ(web_query_compile(&Q, ~0u, WEB_QS_LAST, 200, 100000, &S), 0);
    WT_EQ(has_param_beyond(&S), 0);
    WT_EQ(S.nb, WEB_Q_TERMS + 2);
}

/* The two lists that must agree: the query's anomaly kinds and the
 * engine's, and src: and sloth's DEV_SRC_* bits (include/sloth.h). */
static void test_lists_agree(void) {
    int n = 0;
    for (int i = 0; web_query_anomaly_kinds[i]; i++, n++)
        WT_EQ(web_anomaly_kind_find(web_query_anomaly_kinds[i]), i);
    WT_EQ(n, 9);
    WT_EQ(web_anomaly_kind_find("x"), -1);
    static const struct { const char *w; int bit; } src[] = {
        { "src:arp", DEV_SRC_ARP }, { "src:dhcp", DEV_SRC_DHCP },
        { "src:mdns", DEV_SRC_MDNS }, { "src:beacon", DEV_SRC_BEACON },
        { "src:probe", DEV_SRC_PROBE }, { "src:sta", DEV_SRC_STA },
        { "src:camera", DEV_SRC_CAMERA },
    };
    for (size_t i = 0; i < sizeof(src) / sizeof(src[0]); i++) {
        char err[64];
        WT_EQ(parse(src[i].w, err), 0);
        WT_EQ(Q.t[0].num, src[i].bit);
    }
    WT_EQ(web_query_sort_find("last"), WEB_QS_LAST);
    WT_EQ(web_query_sort_find("risk"), WEB_QS_RISK);
    WT_EQ(web_query_sort_find("rowid"), -1);
    WT_EQ(web_query_sort_find(NULL), -1);
}

void run_query_tests(void) {
    WT_RUN(test_acceptance_terms);
    WT_RUN(test_every_prefix);
    WT_RUN(test_text_negation_quotes);
    WT_RUN(test_refusals);
    WT_RUN(test_bounds);
    WT_RUN(test_compiled_statement_holds_no_input);
    WT_RUN(test_compiled_shape);
    WT_RUN(test_lists_agree);
}
