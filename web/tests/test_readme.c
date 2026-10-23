/* web/README.md held to the source (#164, M6): every message slothweb's
 * start-up path can print is quoted in its Troubleshooting section,
 * scraped from web/src/ rather than listed here, so a new refusal that
 * nobody documented fails the suite and names itself; the Security
 * section states each point #164 asks of it; and every screenshot the
 * README shows is a PNG under docs/assets/slothweb/ within the size
 * bound, with sloth's README and the wiki page linking here. Runs from
 * the top of the tree, as the suite does. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wtest.h"

#define SHOT_MAX (250 * 1024)

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 1 << 16, n = 0;
    char *b = malloc(cap + 1);
    size_t r;
    while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
        n += r;
        if (n == cap) {
            char *nb = realloc(b, cap * 2 + 1);
            if (!nb) { free(b); b = NULL; break; }
            b = nb;
            cap *= 2;
        }
    }
    fclose(f);
    if (!b) return NULL;
    b[n] = '\0';
    if (len) *len = n;
    return b;
}

/* The text between "\n## <title>\n" and the next "\n## ", as a new
 * string, or NULL. */
static char *section(const char *doc, const char *title) {
    char head[96];
    snprintf(head, sizeof(head), "\n## %s\n", title);
    const char *a = strstr(doc, head);
    if (!a) return NULL;
    const char *b = strstr(a + strlen(head), "\n## ");
    size_t n = b ? (size_t)(b - a) : strlen(a);
    char *s = malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, a, n);
    s[n] = '\0';
    return s;
}

/* The adjacent string literals from the first '"' after p (before any
 * ';'), escapes left as written; "" when the call has none. */
static void literal(const char *p, char *out, size_t cap) {
    size_t o = 0;
    while (*p && *p != '"' && *p != ';') p++;
    for (;;) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (*p != '"') break;
        for (p++; *p && *p != '"'; p++) {
            if (*p == '\\' && p[1]) {
                if (o + 2 < cap) { out[o++] = p[0]; out[o++] = p[1]; }
                p++;
                continue;
            }
            if (o + 1 < cap) out[o++] = *p;
        }
        if (*p == '"') p++;
    }
    out[o] = '\0';
}

static int trim_char(char c) {
    return c == ' ' || c == ':' || c == '.' || c == ',' || c == ';' ||
           c == '(' || c == ')';
}

/* Every literal run of the message's first line between its printf
 * conversions, trimmed, of four bytes or more, must be in doc. The
 * count of runs checked, and of runs missing (each printed). */
static void check_runs(const char *file, const char *msg, const char *doc,
                       int *runs, int *missing) {
    char seg[512];
    size_t o = 0;
    for (const char *p = msg;; p++) {
        int end = !*p || (p[0] == '\\' && p[1] == 'n');
        int conv = *p == '%' && p[1] != '%';
        if (end || conv) {
            seg[o] = '\0';
            char *s = seg, *e = seg + o;
            while (s < e && trim_char(*s)) s++;
            while (e > s && trim_char(e[-1])) e--;
            *e = '\0';
            if (e - s >= 4) {
                (*runs)++;
                if (!strstr(doc, s)) {
                    (*missing)++;
                    fprintf(stderr, "    %s: \"%s\" not in Troubleshooting (from \"%s\")\n",
                            file, s, msg);
                }
            }
            o = 0;
            if (end) break;
            /* Skip the conversion: flags, width, precision, length. */
            p++;
            while (*p && strchr("-+ #0123456789.*hlLqjzt", *p)) p++;
            if (!*p) break;
            continue;
        }
        if (*p == '%') p++;               /* "%%" */
        if (o + 1 < sizeof(seg)) seg[o++] = *p;
    }
}

/* The start-up path's messages: what main.c prints and the reasons the
 * functions it calls before serving write into its err buffer. Lines
 * that are not problems (the start-up notices) are passed over by
 * their opening words, and so are a few files' reasons that only the
 * running threads produce: the stream client's connect and read errors
 * go to /api/health (socket_last_error), never to stderr, and the
 * store thread's write and compaction errors to its counters. */
static const char *const FILES[] = {
    "main.c", "web_config.c", "web_acl.c", "web_ingest.c", "web_server.c",
    "web_store.c", "web_slothdb.c", "web_sqlbox.c", "web_tsdb.c",
};
static const char *const CALLS[] = {
    "snprintf(err, errsz,", "fprintf(err,", "fprintf(stderr,",
    "set_err(err, errsz,", "fail(c, WEB_SDB_",
};
static const char *const NOTICE[] = {
    "listening on ", "SQL box on ", "vendor table: ", "reading ",
    "time series in ", "baselines (", "stopped: ", "store schema v",
    "sloth.db %s: schema v",
};
static const struct { const char *file, *start; } RUNTIME[] = {
    { "web_ingest.c", "socket: " }, { "web_ingest.c", "fcntl: " },
    { "web_ingest.c", "connect: " }, { "web_ingest.c", "poll: " },
    { "web_ingest.c", "recv: " }, { "web_ingest.c", "peer closed" },
    { "web_store.c", "write: " }, { "web_store.c", "compact: " },
};

static int passed_over(const char *file, const char *m) {
    for (size_t i = 0; i < sizeof(NOTICE) / sizeof(NOTICE[0]); i++)
        if (!strncmp(m, NOTICE[i], strlen(NOTICE[i]))) return 1;
    for (size_t i = 0; i < sizeof(RUNTIME) / sizeof(RUNTIME[0]); i++)
        if (!strcmp(file, RUNTIME[i].file) &&
            !strncmp(m, RUNTIME[i].start, strlen(RUNTIME[i].start)))
            return 1;
    return 0;
}

/* Seen red with the README's "--strict refuses --web-allow-sql." row
 * removed (that message named), and with a new
 * fprintf(stderr, "slothweb: frobnicated\n") added to main.c. */
static void test_every_start_message_is_documented(void) {
    char *doc = slurp("web/README.md", NULL);
    WT_ASSERT(doc != NULL);
    if (!doc) return;
    char *ts = section(doc, "Troubleshooting");
    WT_ASSERT(ts != NULL);
    int msgs = 0, runs = 0, missing = 0, saw_bind = 0;
    for (size_t f = 0; ts && f < sizeof(FILES) / sizeof(FILES[0]); f++) {
        char path[64];
        snprintf(path, sizeof(path), "web/src/%s", FILES[f]);
        char *src = slurp(path, NULL);
        WT_ASSERT(src != NULL);
        if (!src) continue;
        for (size_t c = 0; c < sizeof(CALLS) / sizeof(CALLS[0]); c++) {
            for (const char *p = strstr(src, CALLS[c]); p; p = strstr(p + 1, CALLS[c])) {
                char lit[2048];
                literal(p + strlen(CALLS[c]), lit, sizeof(lit));
                const char *m = lit;
                if (!strncmp(m, "slothweb: ", 10)) m += 10;
                if (!*m || passed_over(FILES[f], m)) continue;
                int before = runs;
                check_runs(FILES[f], m, ts, &runs, &missing);
                if (runs > before) msgs++;
                if (strstr(m, "refusing to bind")) saw_bind = 1;
            }
        }
        free(src);
    }
    WT_EQ(missing, 0);
    /* The positive control: the scrape found the messages (today 97,
     * from all nine files), not nothing. */
    WT_ASSERT(msgs >= 80);
    WT_ASSERT(runs >= 120);
    WT_ASSERT(saw_bind);
    free(ts);
    free(doc);
}

/* The Security section states each point #164 lists. Seen red with the
 * Host bullet removed. */
static void test_security_section(void) {
    char *doc = slurp("web/README.md", NULL);
    WT_ASSERT(doc != NULL);
    if (!doc) return;
    char *s = section(doc, "Security");
    WT_ASSERT(s != NULL);
    static const char *const points[] = {
        "**Loopback by default.**", "`--web-allow-remote`", "`--web-allow CIDR`",
        "**GET and HEAD only.**", "**No authentication.**",
        "Whoever can reach the port reads everything", "**The Host check.**",
        "**CSP and no external requests.**", "Content-Security-Policy",
        "**Read-only towards sloth.db.**", "In WAL mode", "never checkpoints",
        "**Secret columns withheld everywhere.**", "inside the SQL box",
        "**`--web-allow-sql`.**", "**`--strict`**", "**No name resolution, ever.**",
        "**Third-party data.**", "MAC", "SSIDs",
    };
    for (size_t i = 0; s && i < sizeof(points) / sizeof(points[0]); i++) {
        if (!strstr(s, points[i])) fprintf(stderr, "    Security lacks %s\n", points[i]);
        WT_ASSERT(strstr(s, points[i]) != NULL);
    }
    free(s);
    /* Its order: the five minutes, Troubleshooting, Security, then the
     * reference. */
    const char *a = strstr(doc, "\n## Five minutes\n"), *b = strstr(doc, "\n## Troubleshooting\n");
    const char *c = strstr(doc, "\n## Security\n"), *d = strstr(doc, "\n## Reference\n");
    WT_ASSERT(a && b && c && d && a < b && b < c && c < d);
    /* The quick start the check follows. */
    WT_HAS(doc, "<!-- quickstart:begin -->\n```sh\nmake web web-demo\n");
    WT_HAS(doc, "--sloth-db sloth.db --store slothweb.db\n```\n<!-- quickstart:end -->");
    free(doc);
}

/* Every screenshot the README shows: a PNG, present, under the bound;
 * each main view among them; sloth's README and the wiki page link
 * here. Seen red with flows.png renamed. */
static void test_screenshots(void) {
    char *doc = slurp("web/README.md", NULL);
    WT_ASSERT(doc != NULL);
    if (!doc) return;
    static const char REF[] = "](../docs/assets/slothweb/";
    int n = 0;
    for (const char *p = strstr(doc, REF); p; p = strstr(p + 1, REF)) {
        const char *nm = p + strlen(REF), *e = strchr(nm, ')');
        if (!e || e - nm > 60) { WT_ASSERT(0); continue; }
        char path[128];
        snprintf(path, sizeof(path), "docs/assets/slothweb/%.*s", (int)(e - nm), nm);
        size_t len = 0;
        char *png = slurp(path, &len);
        if (!png) fprintf(stderr, "    %s is missing\n", path);
        WT_ASSERT(png != NULL);
        if (png) {
            WT_ASSERT(len > 8 && !memcmp(png, "\x89PNG\r\n\x1a\n", 8));
            if (len > SHOT_MAX) fprintf(stderr, "    %s is %zu bytes\n", path, len);
            WT_ASSERT(len <= SHOT_MAX);
            free(png);
        }
        n++;
    }
    WT_ASSERT(n >= 8);
    static const char *const views[] = {
        "overview", "activity", "devices", "anomalies", "wifi", "flows",
        "history", "lookup",
    };
    for (size_t i = 0; i < sizeof(views) / sizeof(views[0]); i++) {
        char want[96];
        snprintf(want, sizeof(want), "%s%s.png)", REF, views[i]);
        WT_HAS(doc, want);
    }
    free(doc);
    char *top = slurp("README.md", NULL);
    WT_ASSERT(top != NULL);
    if (top) {
        WT_HAS(top, "](web/README.md)");
        WT_HAS(top, "](docs/assets/slothweb/");
        free(top);
    }
    char *wiki = slurp("docs/wiki/slothweb.md", NULL);
    WT_ASSERT(wiki != NULL);
    if (wiki) {
        WT_HAS(wiki, "web/README.md");
        free(wiki);
    }
}

void run_readme_tests(void) {
    WT_RUN(test_every_start_message_is_documented);
    WT_RUN(test_security_section);
    WT_RUN(test_screenshots);
}
