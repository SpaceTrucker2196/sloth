#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
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

/* docs/wiki states the same counts README does, and nothing checked it
 * — which is exactly how it drifted. When the WPS rules took
 * ALERT_TYPE_COUNT past 61, README, SECURITY and --help were corrected
 * (the tests above assert them) and five wiki pages were not, so main
 * carried "61 alert rules" and "65 alert rules" simultaneously, with
 * docs/wiki/log.md still advertising 24 views against a VIEW_COUNT of
 * 35.
 *
 * Every page is scanned rather than a listed few: a NEW page claiming a
 * count is the case a hand-kept list would miss, and that is the failure
 * mode being fixed. docs/wiki is the single source of truth per
 * agents/AGENTS.md, so a count it states has to be the real one.
 *
 * Note what this does not police: an assertion count. Those were removed
 * from the public docs in the same change rather than pinned here — the
 * number tells a reader nothing they can act on and is wrong within a
 * week, so "make test is green" is the honest claim. docs/wiki/log.md
 * keeps its historical ones, which were true when written. */
static void test_wiki_counts_match_build(void) {
    const char *dir = "docs/wiki";
    DIR *d = opendir(dir);
    ASSERT(d != NULL);
    if (!d) return;
    int pages = 0, with_claims = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl < 4 || strcmp(e->d_name + nl - 3, ".md") != 0) continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%.200s", dir, e->d_name);
        char *t = slurp(path);
        if (!t) continue;
        pages++;
        dc_claims_t c;
        scan_all(t, &c);
        if (c.n_views || c.n_rules) with_claims++;
        check_counts(path, &c);
        free(t);
    }
    closedir(d);
    /* The walk actually found pages: a wrong relative path would
       otherwise pass this test by checking nothing at all. */
    ASSERT_GE(pages, 40);
    ASSERT_GE(with_claims, 1);
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

/*
 * Usage-text honesty — issue #84.
 *
 * print_usage() does not only carry counts; it makes claims about what
 * sloth writes and what it can put on the wire, and two of them were
 * false against the code:
 *
 *   - --hop was "the only kernel-state write sloth performs". It is not:
 *     linux_wifi_prepare_scan_trigger() builds an NL80211_CMD_TRIGGER_SCAN
 *     whenever observe_active_allowed() (--allow-active), which is a
 *     second kernel-state write on a second opt-in.
 *   - --strict's mDNS suppression was "the one thing the default profile
 *     still permits". It is not: main() gates nothing but the observation
 *     policy on --strict, so an opted-in routable --data-socket still
 *     reaches data_socket_init_ex() and serves, and --hop still retunes.
 *
 * Asserting the corrected sentence verbatim would pass on any reword, so
 * each check pins both halves inside the option's own block: the
 * superlative must be ABSENT and the qualifying cross-reference must be
 * PRESENT. Dropping the qualification fails even if the old words are
 * never typed again.
 */

/* Unescape a C string-literal body, appending at *o. \n and \t collapse
 * to a space; \\ and \" yield the bare character. */
static void dc_unescape(const char *in, size_t len, char *out, size_t sz,
                        size_t *o) {
    for (size_t i = 0; i < len && *o + 1 < sz; i++) {
        char c = in[i];
        if (c == '\\' && i + 1 < len) {
            char e = in[++i];
            c = (e == 'n' || e == 't') ? ' ' : e;
        }
        out[(*o)++] = c;
    }
    out[*o] = '\0';
}

/* Collect one option's block out of print_usage() and whitespace-collapse
 * it, so a phrase that wrapped across two string literals reads as one
 * run of words. Blocks are delimited by the file's own layout: an entry
 * is a literal whose text starts at column 2 with "--"; every
 * continuation line is indented past that, so it can never open a block.
 * Returns 1 when `flag` has a block, 0 otherwise. */
static int usage_option_block_from(const char *csrc, const char *flag,
                                   char *out, size_t sz) {
    out[0] = '\0';
    char *t = malloc(strlen(csrc) + 1);
    if (!t) return 0;
    strcpy(t, csrc);

    char *start = strstr(t, "static void print_usage(");
    char *end   = start ? strstr(start, "\n}\n") : NULL;
    if (!start || !end) { free(t); return 0; }
    end[1] = '\0';

    char   raw[4096];
    size_t o = 0, flen = strlen(flag);
    int    in_block = 0, found = 0;
    raw[0] = '\0';

    for (char *line = start; line && *line; ) {
        char  *nl   = strchr(line, '\n');
        size_t llen = nl ? (size_t)(nl - line) : strlen(line);

        /* The literal body is between the first and the last quote on the
         * line — argv0 and the trailing `);` sit outside both. */
        char *q1 = memchr(line, '"', llen), *q2 = NULL;
        for (size_t i = llen; q1 && i > (size_t)(q1 - line) + 1; i--)
            if (line[i - 1] == '"') { q2 = line + i - 1; break; }

        if (q1 && q2 && q2 > q1) {
            char   body[512];
            size_t bo = 0;
            dc_unescape(q1 + 1, (size_t)(q2 - q1 - 1), body, sizeof(body), &bo);

            if (bo >= 4 && body[0] == ' ' && body[1] == ' ' &&
                body[2] == '-' && body[3] == '-') {
                if (in_block) break;            /* next entry ends ours */
                in_block = !strncmp(body + 2, flag, flen) &&
                           (body[2 + flen] == ' ' || body[2 + flen] == '\0');
                if (in_block) found = 1;
            }
            if (in_block && o + bo + 1 < sizeof(raw)) {
                memcpy(raw + o, body, bo);
                o += bo;
                raw[o] = '\0';
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    free(t);
    if (!found) return 0;

    size_t w = 0;
    int    sp = 1;
    for (size_t i = 0; i < o && w + 1 < sz; i++) {
        unsigned char c = (unsigned char)raw[i];
        if (isspace(c)) { if (!sp) { out[w++] = ' '; sp = 1; } }
        else            { out[w++] = (char)c;        sp = 0; }
    }
    while (w > 0 && out[w - 1] == ' ') w--;
    out[w] = '\0';
    return 1;
}

static int usage_option_block(const char *flag, char *out, size_t sz) {
    out[0] = '\0';
    char *t = slurp("src/main.c");
    if (!t) return 0;
    int rc = usage_option_block_from(t, flag, out, sz);
    free(t);
    return rc;
}

/* Case-insensitive substring — the usage text capitalises for emphasis
 * ("LOCK", "NOT"), which must not decide whether a claim is found. */
static int has_ci(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0) return 1;
    for (size_t i = 0; hay[i]; i++) {
        size_t j = 0;
        while (j < nl && hay[i + j] &&
               tolower((unsigned char)hay[i + j]) ==
               tolower((unsigned char)needle[j])) j++;
        if (j == nl) return 1;
    }
    return 0;
}

static void test_usage_block_extractor(void) {
    static const char src[] =
        "static void print_usage(const char *argv0) {\n"
        "    fprintf(stderr,\n"
        "            \"usage: %s [--hop]\\n\"\n"
        "            \"  --hop              retune sloth's own\\n\"\n"
        "            \"                     monitor interface. One of\\n\"\n"
        "            \"                     two writes.\\n\"\n"
        "            \"  --strict           locks \\\"it\\\"\\n\",\n"
        "            argv0);\n"
        "}\n";
    char b[256];
    ASSERT_EQ(usage_option_block_from(src, "--hop", b, sizeof(b)), 1);
    ASSERT_STR(b, "--hop retune sloth's own monitor interface. "
                  "One of two writes.");
    ASSERT_EQ(usage_option_block_from(src, "--strict", b, sizeof(b)), 1);
    ASSERT_STR(b, "--strict locks \"it\"");
    /* The synopsis line mentions --hop too, and must not be mistaken for
     * an entry; an absent flag reports absent rather than empty-and-true. */
    ASSERT_EQ(usage_option_block_from(src, "--allow-active", b, sizeof(b)), 0);
}

static void test_has_ci(void) {
    ASSERT(has_ci("It does NOT close every path", "not close"));
    ASSERT(!has_ci("It does NOT close every path", "not opened"));
    ASSERT(has_ci("abc", ""));
}

/* --hop is one of two kernel-state writes, not the only one. */
static void test_usage_hop_claims_no_sole_kernel_state_write(void) {
    char b[2048];
    ASSERT_EQ(usage_option_block("--hop", b, sizeof(b)), 1);
    ASSERT(!has_ci(b, "only kernel-state write"));
    ASSERT(!has_ci(b, "only kernel state write"));
    ASSERT(!has_ci(b, "the only kernel-state"));
    ASSERT(!has_ci(b, "only write"));
    /* The qualification: the block names the other write's opt-in, so a
     * reword that quietly drops it is red as well. */
    ASSERT(has_ci(b, "--allow-active"));
    ASSERT(has_ci(b, "kernel-state"));
}

/* --strict suppresses the advertisement only; it closes neither an
 * opted-in routable data socket nor --hop. */
static void test_usage_strict_claims_no_total_coverage(void) {
    char b[2048];
    ASSERT_EQ(usage_option_block("--strict", b, sizeof(b)), 1);
    ASSERT(!has_ci(b, "the one thing"));
    ASSERT(!has_ci(b, "one thing the default profile"));
    ASSERT(!has_ci(b, "default profile still permits"));
    /* The qualification: the remaining paths are named where the operator
     * reads about the lock, not only in README. */
    ASSERT(has_ci(b, "--data-socket"));
    ASSERT(has_ci(b, "--hop"));
    ASSERT(has_ci(b, "--no-discovery"));
}

/*
 * Header-comment honesty — issue #84.
 *
 * 6c33228 corrected the "only kernel-state write" claim in
 * print_usage() and named these headers as out of scope at the time, so
 * the same claim stayed in the comments a reader of the code hits
 * first. src/platform/linux_wifi.h contradicted itself inside thirty
 * lines: the set_channel comment claimed sole ownership while the
 * TRIGGER_SCAN block below it documented a second write.
 *
 * What is pinned is the absence of a TOTAL, not the presence of a
 * particular number — because the first fix for this replaced "the only
 * kernel-state write" with "one of two" and that was false too:
 * opening a capture handle sets promiscuous mode (pcap_set_promisc in
 * src/capture/capture.c, promisc=1 on every pcap_open_live), which is a
 * kernel-state write on whatever interface libpcap opened, behind no
 * opt-in at all. Counting them in a comment is the thing that keeps
 * going stale, so a counted claim is now as red as a sole claim.
 *
 * The presence half asks only that the file still discusses the subject
 * and points somewhere fuller. It deliberately does not require the
 * literal "--allow-active": review found that satisfied by unrelated
 * pre-existing text in two of these files, which is a vacuous
 * assertion, and it forces every comment to re-enumerate rather than
 * cross-reference.
 */
static void check_file_claims_no_sole_kernel_state_write(const char *path) {
    char *t = slurp(path);
    ASSERT(t != NULL);
    if (!t) return;
    /* No sole claim. */
    ASSERT(!has_ci(t, "only kernel-state write"));
    ASSERT(!has_ci(t, "only kernel state write"));
    ASSERT(!has_ci(t, "the only kernel-state"));
    /* No UNSCOPED total either — the second thing that went stale. A
       scoped count is fine and include/sloth.h makes a true one ("two
       kernel-state writes reachable through this vtable": set_channel
       and wifi_scan, since promiscuous mode is set by libpcap and not
       through the vtable). What is banned is a claim about sloth as a
       whole, which is what cannot be kept current. */
    ASSERT(!has_ci(t, "kernel-state writes sloth can make"));
    ASSERT(!has_ci(t, "kernel-state writes sloth performs"));
    ASSERT(!has_ci(t, "kernel-state writes sloth makes"));
    /* Still discusses the subject... */
    ASSERT(has_ci(t, "kernel-state"));
    /* ...and points at a fuller account rather than re-counting. */
    ASSERT(has_ci(t, "--allow-active") || has_ci(t, "linux_wifi.h") ||
           has_ci(t, "MISSION"));
    free(t);
}

static void test_set_channel_comments_claim_no_total(void) {
    check_file_claims_no_sole_kernel_state_write("src/platform/linux_wifi.h");
    check_file_claims_no_sole_kernel_state_write("src/wifi_chanhop.h");
    check_file_claims_no_sole_kernel_state_write("include/sloth.h");
    check_file_claims_no_sole_kernel_state_write("src/main.c");
}

/*
 * Wiki and rule-table integrity — issue #103.
 *
 * Wave 2 repaired four dead wikilinks, an orphan page and a stale rule
 * count by hand. Every one of them was found by a human-or-agent pass
 * that nobody runs on a schedule, so the next regression would have sat
 * in main until somebody happened to look. The counts are already
 * pinned (test_wiki_counts_match_build above); these pin the structural
 * properties beside them.
 *
 * Four walks, four floors. A scanner whose source document is reworded
 * or moved stops checking silently — a walk over zero pages passes
 * every assertion it never makes — so each one asserts a lower bound on
 * what it found as well as zero failures.
 *
 * Deliberately not checked: external http links, which would put
 * network access in `make test`; anchor fragments inside a page; and
 * documents outside docs/wiki and the alerts rule table.
 * docs/progress-archive.md, for one, carries two repo-root-relative
 * links that do not resolve from its own directory — it is a frozen
 * record of shipped work, so widening the walk to it would assert a
 * property the file was never written to hold.
 */

#define DC_WIKI_DIR   "docs/wiki"
#define DC_MAX_PAGES  256
#define DC_PAGE_LEN   128

/* Blank every fenced block and inline code span in place, preserving
 * length and line structure. Two traps wave 2 hit live here: a
 * `[[link]]` inside backticks is a syntax *example* — wiki-maintenance.md
 * carries `[[wiki-links]]`, `[[links]]` and `[[link]]`, none of which
 * are pages — while a wikilink carrying a slash or dot
 * (`[[../views/http]]`) is dead, because the wiki namespace is flat.
 * Blanking code first makes the first case invisible and leaves the
 * second to fail the page-exists test like any other bad target.
 *
 * Inline spans are paired within one line only: an unpaired backtick is
 * a literal, not a span running to end of file. */
static void dc_blank_code(char *t) {
    int fenced = 0;
    for (char *line = t; line && *line; ) {
        char  *nl  = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        size_t i   = 0;
        while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
        if (len - i >= 3 && !strncmp(line + i, "```", 3)) {
            fenced = !fenced;
            memset(line, ' ', len);
        } else if (fenced) {
            memset(line, ' ', len);
        } else {
            for (size_t j = 0; j < len; j++) {
                if (line[j] != '`') continue;
                size_t k = j + 1;
                while (k < len && line[k] != '`') k++;
                if (k >= len) break;
                memset(line + j, ' ', k - j + 1);
                j = k;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
}

static int dc_wiki_pages(char names[DC_MAX_PAGES][DC_PAGE_LEN]) {
    DIR *d = opendir(DC_WIKI_DIR);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl < 4 || nl > DC_PAGE_LEN - 1) continue;
        if (strcmp(e->d_name + nl - 3, ".md") != 0) continue;
        if (n >= DC_MAX_PAGES) break;
        memcpy(names[n], e->d_name, nl - 3);
        names[n][nl - 3] = '\0';
        n++;
    }
    closedir(d);
    return n;
}

static int dc_is_page(char names[DC_MAX_PAGES][DC_PAGE_LEN], int n,
                      const char *tgt) {
    for (int i = 0; i < n; i++) if (!strcmp(names[i], tgt)) return 1;
    return 0;
}

/* Append the first `len` bytes of `s` as a page name, dropping anything
 * that cannot be one. */
static void dc_push_name(char names[DC_MAX_PAGES][DC_PAGE_LEN], int *n,
                         const char *s, size_t len) {
    if (*n >= DC_MAX_PAGES || len == 0 || len >= DC_PAGE_LEN) return;
    memcpy(names[*n], s, len);
    names[*n][len] = '\0';
    (*n)++;
}

/* Copy the target of the wikilink opening at `p` ("[[" included) into
 * `out`, trimmed and cut at a `|` display-text separator. Returns the
 * position just past "]]", or NULL when the link never closes. */
static const char *dc_wikilink(const char *p, char *out, size_t sz) {
    const char *e = strstr(p + 2, "]]");
    if (!e) return NULL;
    const char *s = p + 2;
    const char *bar = memchr(s, '|', (size_t)(e - s));
    const char *stop = bar ? bar : e;
    while (s < stop && isspace((unsigned char)*s)) s++;
    while (stop > s && isspace((unsigned char)stop[-1])) stop--;
    size_t n = (size_t)(stop - s);
    if (n > sz - 1) n = sz - 1;
    memcpy(out, s, n);
    out[n] = '\0';
    return e + 2;
}

/* Copy the destination of the markdown link opening at `p` ("](" included)
 * into `out`: everything up to the first whitespace (a link title) or the
 * closing paren, with any `#fragment` dropped. Returns the position just
 * past the destination, or NULL when it never closes. */
static const char *dc_md_link(const char *p, char *out, size_t sz) {
    const char *s = p + 2, *q = s;
    while (*q && *q != ')' && !isspace((unsigned char)*q)) q++;
    if (!*q) return NULL;
    size_t n = (size_t)(q - s);
    if (n > sz - 1) n = sz - 1;
    memcpy(out, s, n);
    out[n] = '\0';
    char *hash = strchr(out, '#');
    if (hash) *hash = '\0';
    return q;
}

static int dc_link_is_external(const char *u) {
    return !*u || *u == '#' ||
           !strncmp(u, "http", 4) || !strncmp(u, "mailto:", 7);
}

/* ── the scanners, on hand-written input ── */

static void test_wiki_link_scanner_skips_code(void) {
    char t[] = "see [[alerts]] and `[[link]]`\n"
               "```\n[[in-a-fence]]\n```\n"
               "a stray ` backtick, [[dashboard]] too\n";
    dc_blank_code(t);
    char tgt[160];
    int n = 0;
    char found[4][160];
    for (const char *p = t; (p = strstr(p, "[[")) != NULL; ) {
        p = dc_wikilink(p, tgt, sizeof(tgt));
        if (!p) break;
        if (n < 4) snprintf(found[n], sizeof(found[n]), "%s", tgt);
        n++;
    }
    ASSERT_EQ(n, 2);
    ASSERT_STR(found[0], "alerts");
    ASSERT_STR(found[1], "dashboard");
}

static void test_wikilink_target_parse(void) {
    char tgt[160];
    ASSERT(dc_wikilink("[[ alerts ]]x", tgt, sizeof(tgt)) != NULL);
    ASSERT_STR(tgt, "alerts");
    ASSERT(dc_wikilink("[[alerts|the engine]]", tgt, sizeof(tgt)) != NULL);
    ASSERT_STR(tgt, "alerts");
    /* A namespaced target survives parsing so the page-exists check can
     * reject it: the wiki is flat, so this is a dead link, not a path. */
    ASSERT(dc_wikilink("[[../views/http]]", tgt, sizeof(tgt)) != NULL);
    ASSERT_STR(tgt, "../views/http");
    ASSERT(dc_wikilink("[[unclosed", tgt, sizeof(tgt)) == NULL);
}

static void test_md_link_target_parse(void) {
    char u[256];
    ASSERT(dc_md_link("](log.md)", u, sizeof(u)) != NULL);
    ASSERT_STR(u, "log.md");
    ASSERT(dc_md_link("](../views/probe.md#flood)", u, sizeof(u)) != NULL);
    ASSERT_STR(u, "../views/probe.md");
    ASSERT(dc_md_link("](foo.md \"title\")", u, sizeof(u)) != NULL);
    ASSERT_STR(u, "foo.md");
    ASSERT(dc_md_link("](unterminated", u, sizeof(u)) == NULL);
    ASSERT(dc_link_is_external("https://example.org"));
    ASSERT(dc_link_is_external("#anchor"));
    ASSERT(!dc_link_is_external("../views/probe.md"));
}

/* ── the wiki ── */

static void test_wiki_wikilinks_resolve(void) {
    char pages[DC_MAX_PAGES][DC_PAGE_LEN];
    int  np = dc_wiki_pages(pages);
    ASSERT_GE(np, 40);
    if (np <= 0) return;
    int links = 0, dead = 0;
    for (int i = 0; i < np; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%.120s.md", DC_WIKI_DIR, pages[i]);
        char *t = slurp(path);
        if (!t) continue;
        dc_blank_code(t);
        char tgt[160];
        for (const char *p = t; (p = strstr(p, "[[")) != NULL; ) {
            const char *nx = dc_wikilink(p, tgt, sizeof(tgt));
            if (!nx) break;
            p = nx;
            links++;
            if (dc_is_page(pages, np, tgt)) continue;
            dead++;
            fprintf(stderr, "    %s: [[%s]] names no page in %s\n",
                    path, tgt, DC_WIKI_DIR);
        }
        free(t);
    }
    /* Floor: the wiki cross-links heavily, so a walk finding almost none
     * means the scan broke, not that the links went away. */
    ASSERT_GE(links, 300);
    ASSERT_EQ(dead, 0);
}

static void test_wiki_relative_links_resolve(void) {
    char pages[DC_MAX_PAGES][DC_PAGE_LEN];
    int  np = dc_wiki_pages(pages);
    ASSERT_GE(np, 40);
    if (np <= 0) return;
    int links = 0, broken = 0;
    for (int i = 0; i < np; i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%.120s.md", DC_WIKI_DIR, pages[i]);
        char *t = slurp(path);
        if (!t) continue;
        dc_blank_code(t);
        char u[256];
        for (const char *p = t; (p = strstr(p, "](")) != NULL; ) {
            const char *nx = dc_md_link(p, u, sizeof(u));
            if (!nx) break;
            p = nx;
            if (dc_link_is_external(u)) continue;
            links++;
            char full[768];
            snprintf(full, sizeof(full), "%s/%.250s", DC_WIKI_DIR, u);
            if (access(full, F_OK) == 0) continue;
            broken++;
            fprintf(stderr, "    %s: (%s) resolves to no file\n", path, u);
        }
        free(t);
    }
    ASSERT_GE(links, 100);
    ASSERT_EQ(broken, 0);
}

/* index.md generates the per-page sidebar, so a page it does not name is
 * a page a reader can only reach by already knowing its filename. */
static void test_wiki_pages_reachable_from_index(void) {
    char pages[DC_MAX_PAGES][DC_PAGE_LEN];
    int  np = dc_wiki_pages(pages);
    ASSERT_GE(np, 40);
    if (np <= 0) return;
    char *t = slurp(DC_WIKI_DIR "/index.md");
    ASSERT(t != NULL);
    if (!t) return;
    dc_blank_code(t);

    char named[DC_MAX_PAGES][DC_PAGE_LEN];
    int  nn = 0;
    char tgt[160];
    for (const char *p = t; (p = strstr(p, "[[")) != NULL; ) {
        const char *nx = dc_wikilink(p, tgt, sizeof(tgt));
        if (!nx) break;
        p = nx;
        dc_push_name(named, &nn, tgt, strlen(tgt));
    }
    /* log.md is referenced as an ordinary relative link rather than a
     * wikilink, and is still indexed; a bare `name.md` counts. */
    char u[256];
    for (const char *p = t; (p = strstr(p, "](")) != NULL; ) {
        const char *nx = dc_md_link(p, u, sizeof(u));
        if (!nx) break;
        p = nx;
        size_t ul = strlen(u);
        if (ul < 4) continue;
        if (strchr(u, '/') || strcmp(u + ul - 3, ".md")) continue;
        dc_push_name(named, &nn, u, ul - 3);
    }
    free(t);
    ASSERT_GE(nn, 40);

    int orphans = 0;
    for (int i = 0; i < np; i++) {
        if (!strcmp(pages[i], "index")) continue;
        if (dc_is_page(named, nn, pages[i])) continue;
        orphans++;
        fprintf(stderr, "    %s/%s.md is not linked from index.md\n",
                DC_WIKI_DIR, pages[i]);
    }
    ASSERT_EQ(orphans, 0);
}

/* ── the alerts rule table ── */

#define DC_MAX_ROWS 128
#define DC_ROW_LEN  64

/* Collect the Rule column of the rule table in docs/views/alerts.md: the
 * run of `| `NAME` |` lines under "## Rules", stopped at the next
 * heading so the severity-tier and counter tables above it, or anything
 * added below, can never be mistaken for coverage. */
static int dc_alert_rule_rows(const char *doc, char rows[DC_MAX_ROWS][DC_ROW_LEN]) {
    const char *p = strstr(doc, "\n## Rules\n");
    if (!p) return -1;
    p += strlen("\n## Rules\n");
    int n = 0;
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 3 && !strncmp(p, "## ", 3)) break;
        if (len > 3 && !strncmp(p, "| `", 3)) {
            size_t i = 3;
            while (i < len && (isupper((unsigned char)p[i]) ||
                               isdigit((unsigned char)p[i]) || p[i] == '_')) i++;
            if (i > 3 && i < len && p[i] == '`' && i - 3 < DC_ROW_LEN &&
                n < DC_MAX_ROWS) {
                memcpy(rows[n], p + 3, i - 3);
                rows[n][i - 3] = '\0';
                n++;
            }
        }
        p = nl ? nl + 1 : NULL;
    }
    return n;
}

/* The row label an ALERT_TYPE_* suffix is documented under. The Rule
 * column names most kinds by their enum suffix, but a row may instead
 * carry the short `fire()` title — titles are display strings bounded by
 * ALERT_TITLE_LEN and abbreviated, so they do not always match the enum.
 * Such a row is correct as it stands: it names what the operator reads
 * in the view. So the mapping lives here, not in the document. */
static const char *dc_rule_row_label(const char *kind) {
    if (!strcmp(kind, "MY_NETWORK_RECON")) return "MY_NET_RECON";
    return kind;
}

/* Every ALERT_TYPE_* has a rule-table row and every row has a kind.
 * agents/AGENTS.md makes the row step 5 of adding a rule; nothing
 * checked it, so the only evidence a rule was documented was that
 * somebody had looked. Both directions matter: a missing row hides a
 * live detector from the operator, a surviving row advertises one that
 * no longer exists. */
static void test_every_alert_kind_has_a_rule_row(void) {
    char *t = slurp("docs/views/alerts.md");
    ASSERT(t != NULL);
    if (!t) return;
    char rows[DC_MAX_ROWS][DC_ROW_LEN];
    int  nr = dc_alert_rule_rows(t, rows);
    free(t);
    ASSERT_GE(nr, 60);
    if (nr <= 0) return;

    int used[DC_MAX_ROWS] = {0};
    int matched = 0;
    for (int ty = 0; ty < (int)ALERT_TYPE_COUNT; ty++) {
        const char *full = alert_type_name((alert_type_t)ty);
        int named = strncmp(full, "ALERT_TYPE_", 11) == 0;
        ASSERT(named);
        if (!named) continue;
        const char *want = dc_rule_row_label(full + 11);
        int hit = -1;
        for (int i = 0; i < nr && hit < 0; i++)
            if (!used[i] && !strcmp(rows[i], want)) hit = i;
        if (hit < 0) {
            fprintf(stderr, "    docs/views/alerts.md has no rule row "
                            "`%s` for %s\n", want, full);
            continue;
        }
        used[hit] = 1;
        matched++;
    }
    ASSERT_EQ(matched, (int)ALERT_TYPE_COUNT);

    int stale = 0;
    for (int i = 0; i < nr; i++) {
        if (used[i]) continue;
        stale++;
        fprintf(stderr, "    docs/views/alerts.md rule row `%s` names no "
                        "ALERT_TYPE_*\n", rows[i]);
    }
    ASSERT_EQ(stale, 0);
}

static void test_alert_rule_row_scanner(void) {
    static const char doc[] =
        "## Severity tiers\n"
        "| `count` | evaluations |\n"   /* another table's field name */
        "| LOW | yellow |\n"
        "\n## Rules\n"
        "| Rule | Sev |\n"
        "|------|-----|\n"
        "| `PORT_SCAN` | LOW | one source |\n"
        "| `MY_NET_RECON` | LOW/WARN | a PNL |\n"
        "\n## Cross-panel coloring\n"
        "| `NOT_A_RULE` | x |\n";
    char rows[DC_MAX_ROWS][DC_ROW_LEN];
    int  n = dc_alert_rule_rows(doc, rows);
    ASSERT_EQ(n, 2);
    ASSERT_STR(rows[0], "PORT_SCAN");
    ASSERT_STR(rows[1], "MY_NET_RECON");
    ASSERT_EQ(dc_alert_rule_rows("no heading here\n", rows), -1);
}

void run_docs_consistency_tests(void) {
    TEST_SUITE("docs consistency (#96)");
    RUN_TEST(test_scanner_reads_counts_across_markup);
    RUN_TEST(test_scanner_ignores_non_claims);
    RUN_TEST(test_scanner_versions_exclude_addresses);
    RUN_TEST(test_readme_counts_match_build);
    RUN_TEST(test_wiki_counts_match_build);
    RUN_TEST(test_security_names_only_current_version);
    RUN_TEST(test_help_card_agrees_with_build);
    RUN_TEST(test_usage_text_agrees_with_build);
    TEST_SUITE("usage-text honesty (#84)");
    RUN_TEST(test_usage_block_extractor);
    RUN_TEST(test_has_ci);
    RUN_TEST(test_usage_hop_claims_no_sole_kernel_state_write);
    RUN_TEST(test_usage_strict_claims_no_total_coverage);
    RUN_TEST(test_set_channel_comments_claim_no_total);
    TEST_SUITE("wiki + rule-table integrity (#103)");
    RUN_TEST(test_wiki_link_scanner_skips_code);
    RUN_TEST(test_wikilink_target_parse);
    RUN_TEST(test_md_link_target_parse);
    RUN_TEST(test_alert_rule_row_scanner);
    RUN_TEST(test_wiki_wikilinks_resolve);
    RUN_TEST(test_wiki_relative_links_resolve);
    RUN_TEST(test_wiki_pages_reachable_from_index);
    RUN_TEST(test_every_alert_kind_has_a_rule_row);
}
