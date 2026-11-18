#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* libFuzzer smoke target for slothweb's device query language (#162,
 * M4): web_query_parse() and web_query_compile() (web/src/web_query.c).
 *
 * slothweb is a separate binary whose sources libsloth_core.a does not
 * carry (and must not: no web/ file is part of sloth), so the two
 * translation units the parser needs are included here directly, with
 * web_scope.c (the capture scope's tables the compiler reads). All
 * are pure (no SQLite, no lock, no clock): the parser takes the time
 * as an argument.
 *
 * Beyond memory safety, two properties the parser's contract states
 * are checked on every input that parses: the compiled statement never
 * names a parameter it does not bind, and it holds no byte that the
 * compiler's own constant fragments do not (the query's values are
 * bound, never written into the text). Either broken is an abort(),
 * which libFuzzer reports as a crash. */
#include "../../web/src/web_json.c"
#include "../../web/src/web_query.c"
#include "../../web/src/web_scope.c"

static unsigned char g_alphabet[256];
static int g_ready;

/* Every byte the fragments can write: the statement of a query using
 * every prefix with every table present, in every sort. */
static void learn_alphabet(void) {
    static const char *const q =
        "x vendor:a mac:b8 ip:10. ssid:s name:n random:yes -random:no "
        "seen:2026-10-21 first:<7d";
    static const char *const q2 =
        "risk:>=2 z:>3 src:probe has:pnl has:alert has:anomaly has:name "
        "has:ip has:ssid anomaly:hours seen:>1h";
    static web_query_t wq;
    static web_qsql_t s;
    char err[64];
    for (int k = 0; k < 2; k++) {
        if (web_query_parse(k ? q2 : q, 1792627200LL, &wq, err, sizeof(err)) != 0)
            abort();
        /* Every capture scope (web_scope.h), each in both directions:
         * the scoped statements' fragments are the compiler's too. */
        for (int scope = 0; scope < 3; scope++)
            for (int sort = 0; sort < WEB_QS_COUNT; sort++)
                for (int dir = 0; dir < 3; dir++) {
                    if (web_query_compile_scoped(&wq, ~0u, scope,
                                                 WEB_SORT_PACK(sort, dir), 200,
                                                 100000, &s) != 0)
                        abort();
                    for (const unsigned char *p = (const unsigned char *)s.sql; *p; p++)
                        g_alphabet[*p] = 1;
                }
    }
    /* Digits of every parameter number. */
    for (int c = '0'; c <= '9'; c++) g_alphabet[c] = 1;
    g_ready = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!g_ready) learn_alphabet();
    if (size > 1024) return 0;
    char q[1025];
    memcpy(q, data, size);
    q[size] = '\0';
    static web_query_t wq;
    static web_qsql_t s;
    char err[64];
    unsigned feats = size ? data[0] : 0;
    if (size > 1) feats |= (unsigned)data[1] << 8;
    if (web_query_parse(q, 1792627200LL, &wq, err, sizeof(err)) != 0) return 0;
    if (web_query_compile_scoped(&wq, feats, (int)(size % 3),
                                 (int)(size % WEB_QS_COUNT), 200, 7, &s) != 0)
        abort();
    for (const char *p = s.sql; (p = strchr(p, '?')) != NULL; p++) {
        int n = 0;
        const char *d = p + 1;
        while (*d >= '0' && *d <= '9') n = n * 10 + (*d++ - '0');
        if (n < 1 || n > s.nb) abort();
    }
    for (const unsigned char *p = (const unsigned char *)s.sql; *p; p++)
        if (!g_alphabet[*p]) abort();
    return 0;
}
