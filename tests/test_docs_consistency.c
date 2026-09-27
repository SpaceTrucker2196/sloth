#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "tui.h"
#include "views/help.h"

/*
 * Docs-consistency guard — issue #96.
 *
 * README.md, SECURITY.md and the help text make three claims the code
 * can contradict: which version this is (SLOTH_VERSION), how many views
 * exist (VIEW_COUNT) and how many alert rules exist (ALERT_TYPE_COUNT,
 * one rule per ALERT_TYPE_*). Each of those has drifted before — the
 * #96 sweep found "27 views", "six alert rules" and a SECURITY.md table
 * claiming 1.4.x — and after that sweep SECURITY.md still named
 * `v1.8.0 and below` as the archived set once v1.8.1 was tagged, leaving
 * v1.8.1 in no row at all. A reader cannot tell a stale number from a
 * true one; the build can, so it does.
 *
 * Deterministic by construction: the claims are extracted with a fixed
 * word-level grammar, not a model, and compared to the compiled
 * constants. Scope is deliberately those three surfaces. MISSION.md and
 * the agents/ tree are owner-reviewed text and are not checked here.
 *
 * Rules:
 *   - every "<N> [live|passive|ncurses|alert]* views" claim == VIEW_COUNT
 *   - every "<N> [..]* rules" claim == ALERT_TYPE_COUNT
 *   - SECURITY.md names no MAJOR.MINOR.PATCH other than SLOTH_VERSION,
 *     so its supported-versions table cannot strand a tag between rows
 *   - README.md and the help text name no version newer than
 *     SLOTH_VERSION (historical release links are legitimate)
 * Each scanned document must yield at least the claims it is known to
 * carry, so rewording a sentence past the grammar fails loudly instead
 * of turning the check vacuous.
 */

#define DC_MAX_CLAIMS 32

typedef struct {
    int views[DC_MAX_CLAIMS];  int n_views;
    int rules[DC_MAX_CLAIMS];  int n_rules;
    int ver[DC_MAX_CLAIMS][3]; int n_ver;
} dc_claims_t;

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    buf[got] = '\0';
    fclose(f);
    return buf;
}

/* Words are runs of alphanumerics; markdown emphasis, backticks and line
 * breaks between them are separators, so "**61 passive\nalert rules**"
 * reads as 61 / passive / alert / rules. */
static const char *next_word(const char *p, char *out, int sz,
                             const char **start) {
    while (*p && !isalnum((unsigned char)*p)) p++;
    if (start) *start = p;
    int n = 0;
    while (*p && isalnum((unsigned char)*p)) {
        if (n < sz - 1) out[n++] = (char)tolower((unsigned char)*p);
        p++;
    }
    out[n] = '\0';
    return p;
}

static int all_digits(const char *w) {
    if (!*w) return 0;
    for (; *w; w++) if (!isdigit((unsigned char)*w)) return 0;
    return 1;
}

/* Adjectives the docs put between a count and its noun. Kept closed so
 * "6 with named types" or "1 set type" is never read as a claim. */
static int is_count_adjective(const char *w) {
    return !strcmp(w, "live") || !strcmp(w, "passive") ||
           !strcmp(w, "ncurses") || !strcmp(w, "alert");
}

static void scan_counts(const char *text, dc_claims_t *c) {
    char w[64], nx[64];
    const char *p = text, *ws = text;
    while (*p) {
        p = next_word(p, w, sizeof(w), &ws);
        if (!all_digits(w) || strlen(w) > 6) continue;
        /* A digit run inside a dotted token (an address or a version) is
         * not a count: "1.8.2 views" never occurs, "10.0.0.5" often does. */
        if (*p == '.' && isdigit((unsigned char)p[1])) continue;
        if (ws > text && ws[-1] == '.') continue;
        int n = atoi(w);
        const char *q = p;
        for (int hop = 0; hop < 4; hop++) {
            q = next_word(q, nx, sizeof(nx), NULL);
            if (is_count_adjective(nx)) continue;
            if (!strcmp(nx, "views") && c->n_views < DC_MAX_CLAIMS)
                c->views[c->n_views++] = n;
            else if (!strcmp(nx, "rules") && c->n_rules < DC_MAX_CLAIMS)
                c->rules[c->n_rules++] = n;
            break;
        }
    }
}

/* MAJOR.MINOR.PATCH with exactly three components, so dotted-quad
 * addresses (four) and "1.0" licence names (two) are not versions. */
static void scan_versions(const char *text, dc_claims_t *c) {
    const char *p = text;
    while (*p) {
        if (!isdigit((unsigned char)*p) ||
            (p > text && (isdigit((unsigned char)p[-1]) || p[-1] == '.'))) {
            p++;
            continue;
        }
        int part[4] = {0, 0, 0, 0}, np = 0;
        const char *q = p;
        for (;;) {
            if (!isdigit((unsigned char)*q)) break;
            long v = 0;
            while (isdigit((unsigned char)*q)) {
                if (v < 100000) v = v * 10 + (*q - '0');
                q++;
            }
            if (np < 4) part[np] = (int)v;
            np++;
            if (*q == '.' && isdigit((unsigned char)q[1])) { q++; continue; }
            break;
        }
        if (np == 3 && c->n_ver < DC_MAX_CLAIMS) {
            c->ver[c->n_ver][0] = part[0];
            c->ver[c->n_ver][1] = part[1];
            c->ver[c->n_ver][2] = part[2];
            c->n_ver++;
        }
        p = q;
    }
}

static void scan_all(const char *text, dc_claims_t *c) {
    memset(c, 0, sizeof(*c));
    scan_counts(text, c);
    scan_versions(text, c);
}

static void current_version(int out[3]) {
    dc_claims_t c;
    memset(&c, 0, sizeof(c));
    scan_versions(SLOTH_VERSION, &c);
    ASSERT_EQ(c.n_ver, 1);
    for (int i = 0; i < 3; i++) out[i] = c.n_ver ? c.ver[0][i] : -1;
}

static int ver_cmp(const int a[3], const int b[3]) {
    for (int i = 0; i < 3; i++)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

static void check_counts(const char *doc, const dc_claims_t *c) {
    for (int i = 0; i < c->n_views; i++) {
        if (c->views[i] != VIEW_COUNT)
            fprintf(stderr, "    %s claims %d views; VIEW_COUNT is %d\n",
                    doc, c->views[i], (int)VIEW_COUNT);
        ASSERT_EQ(c->views[i], (int)VIEW_COUNT);
    }
    for (int i = 0; i < c->n_rules; i++) {
        if (c->rules[i] != ALERT_TYPE_COUNT)
            fprintf(stderr, "    %s claims %d alert rules; "
                    "ALERT_TYPE_COUNT is %d\n",
                    doc, c->rules[i], (int)ALERT_TYPE_COUNT);
        ASSERT_EQ(c->rules[i], (int)ALERT_TYPE_COUNT);
    }
}

static void check_no_future_version(const char *doc, const dc_claims_t *c) {
    int cur[3];
    current_version(cur);
    for (int i = 0; i < c->n_ver; i++) {
        int newer = ver_cmp(c->ver[i], cur) > 0;
        if (newer)
            fprintf(stderr, "    %s names %d.%d.%d; SLOTH_VERSION is %s\n",
                    doc, c->ver[i][0], c->ver[i][1], c->ver[i][2],
                    SLOTH_VERSION);
        ASSERT(!newer);
    }
}

/* ── the grammar itself, on hand-written input ── */

static void test_scanner_reads_counts_across_markup(void) {
    dc_claims_t c;
    scan_all("into **35 live views** and **61 passive\nalert rules**, "
             "and **61 rules** feed it", &c);
    ASSERT_EQ(c.n_views, 1);
    ASSERT_EQ(c.views[0], 35);
    ASSERT_EQ(c.n_rules, 2);
    ASSERT_EQ(c.rules[0], 61);
    ASSERT_EQ(c.rules[1], 61);
}

static void test_scanner_ignores_non_claims(void) {
    dc_claims_t c;
    /* Real README phrases that sit near the nouns but claim nothing. */
    scan_all("ICMPv4 + ICMPv6 with named types; 1 set type; per-view docs; "
             "10.0.0.5 views; see 3 other views of it", &c);
    ASSERT_EQ(c.n_views, 0);
    ASSERT_EQ(c.n_rules, 0);
}

static void test_scanner_versions_exclude_addresses(void) {
    dc_claims_t c;
    scan_all("tag `v1.8.0`, src 10.0.0.5, License 1.0, 127.0.0.0/8, "
             "release 12.34.5.", &c);
    ASSERT_EQ(c.n_ver, 2);
    ASSERT(c.ver[0][0] == 1 && c.ver[0][1] == 8 && c.ver[0][2] == 0);
    ASSERT(c.ver[1][0] == 12 && c.ver[1][1] == 34 && c.ver[1][2] == 5);
}

/* ── the documents ── */

static void test_readme_counts_match_build(void) {
    char *t = slurp("README.md");
    ASSERT(t != NULL);
    if (!t) return;
    dc_claims_t c;
    scan_all(t, &c);
    /* README states each count at least once today (lede + alerts
     * section); losing one means the sentence moved past the grammar. */
    ASSERT_GE(c.n_views, 1);
    ASSERT_GE(c.n_rules, 2);
    check_counts("README.md", &c);
    check_no_future_version("README.md", &c);
    free(t);
}

static void test_security_names_only_current_version(void) {
    char *t = slurp("SECURITY.md");
    ASSERT(t != NULL);
    if (!t) return;
    dc_claims_t c;
    scan_all(t, &c);
    check_counts("SECURITY.md", &c);

    /* Any other version in the supported-versions policy is a row that
     * has to be edited on every tag — and #96 showed it will not be. */
    int cur[3];
    current_version(cur);
    ASSERT_GE(c.n_ver, 2);
    for (int i = 0; i < c.n_ver; i++) {
        int same = ver_cmp(c.ver[i], cur) == 0;
        if (!same)
            fprintf(stderr, "    SECURITY.md names %d.%d.%d; "
                    "SLOTH_VERSION is %s\n",
                    c.ver[i][0], c.ver[i][1], c.ver[i][2], SLOTH_VERSION);
        ASSERT(same);
    }

    char want[64];
    snprintf(want, sizeof(want), "Current release: `%s`", SLOTH_VERSION);
    ASSERT(strstr(t, want) != NULL);
    snprintf(want, sizeof(want), "newest tag (`v%s`)", SLOTH_VERSION);
    ASSERT(strstr(t, want) != NULL);
    /* The archived row is defined relative to the newest tag, so cutting
     * a tag cannot leave the previous one in no row. */
    ASSERT(strstr(t, "every tag before the newest") != NULL);
    free(t);
}

static void capture_help(char *buf, int sz) {
    sloth_state_t *s = calloc(1, sizeof(*s));
    if (!s) { buf[0] = '\0'; return; }
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    if (saved < 0 || !tmp) {
        if (tmp) fclose(tmp);
        if (saved >= 0) close(saved);
        free(s);
        buf[0] = '\0';
        return;
    }
    dup2(fileno(tmp), fileno(stdout));
    view_help_draw(s);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, (size_t)sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
    free(s);
}

/* The help card derives its view list and version from the constants,
 * so today it carries no literal claim; this pins that a hard-coded
 * count or version added later still has to agree. */
static void test_help_card_agrees_with_build(void) {
    char buf[16384];
    capture_help(buf, sizeof(buf));
    ASSERT(buf[0] != '\0');
    dc_claims_t c;
    scan_all(buf, &c);
    check_counts("help card", &c);
    check_no_future_version("help card", &c);
}

/* `sloth --help` lives in main.c, which the test binary does not link,
 * so the usage text is read from source: print_usage() up to its
 * closing brace. */
static void test_usage_text_agrees_with_build(void) {
    char *t = slurp("src/main.c");
    ASSERT(t != NULL);
    if (!t) return;
    char *start = strstr(t, "static void print_usage(");
    ASSERT(start != NULL);
    if (!start) { free(t); return; }
    char *end = strstr(start, "\n}\n");
    ASSERT(end != NULL);
    if (end) end[1] = '\0';
    ASSERT(strstr(start, "usage:") != NULL);
    dc_claims_t c;
    scan_all(start, &c);
    check_counts("sloth --help", &c);
    check_no_future_version("sloth --help", &c);
    free(t);
}

void run_docs_consistency_tests(void) {
    TEST_SUITE("docs consistency (#96)");
    RUN_TEST(test_scanner_reads_counts_across_markup);
    RUN_TEST(test_scanner_ignores_non_claims);
    RUN_TEST(test_scanner_versions_exclude_addresses);
    RUN_TEST(test_readme_counts_match_build);
    RUN_TEST(test_security_names_only_current_version);
    RUN_TEST(test_help_card_agrees_with_build);
    RUN_TEST(test_usage_text_agrees_with_build);
}
