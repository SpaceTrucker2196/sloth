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
#include "persist_health.h"

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
 * constants.
 *
 * Scope was originally those three surfaces, on the grounds that
 * MISSION.md and the agents/ tree are owner-reviewed text. That
 * reasoning did not survive contact: agents/ joined the gate in 52509db
 * after all three of its files sat three thousand assertions stale
 * while one of them instructed readers never to quote a recalled count,
 * and MISSION.md joined on 2026-10-13 after its "70 alert rules" was
 * caught by hand during a slice that took the count to 71. Review is
 * not a mechanism; it is a person remembering. Both surfaces state the
 * counts in prose a reader will act on, so both are checked.
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

/* True when the digit run ending at `end` is a POSITION rather than a
 * quantity: a markdown ordered-list marker or a numbered heading.
 *
 * Nothing but spaces and '#' back to the line start, then a '.' or ')'
 * and whitespace after. Two shapes in this repo:
 *
 *   "5. Views read from `sloth_state_t`"  — agents/FACTORY.md recipe
 *   "## 2. Rules of engagement"           — MISSION.md section heading
 *
 * The heading case is why '#' is allowed. Without it, MISSION.md's §2
 * title reads as a claim of "2 rules" against an ALERT_TYPE_COUNT of
 * 71 — a false alarm on the charter's own table of contents, found the
 * moment MISSION.md came under this gate. */
static int is_list_marker(const char *text, const char *ws, const char *end) {
    const char *b = ws;
    while (b > text && b[-1] != '\n') {
        if (b[-1] != ' ' && b[-1] != '\t' && b[-1] != '#') return 0;
        b--;
    }
    if (*end != '.' && *end != ')') return 0;
    return end[1] == ' ' || end[1] == '\t' || end[1] == '\n' || end[1] == '\0';
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
        /* A markdown ordered-list marker is a position, not a quantity.
         * The recipes in agents/ are numbered lists, so "5. Views read
         * from `sloth_state_t`" reads as "5 views" under the rule above
         * and fails against VIEW_COUNT — a false alarm about a sentence
         * that claims nothing. Prose counts never start a line with the
         * number, so requiring non-list context costs no real claim. */
        if (is_list_marker(text, ws, p)) continue;
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

static void test_scanner_ignores_ordered_list_markers(void) {
    dc_claims_t c;
    /* Shape taken from agents/FACTORY.md's add-a-platform-backend
       recipe, which is where this false alarm came from. */
    scan_all("4. Write the test that drives the new fake.\n"
             "5. Views read from `sloth_state_t`.\n"
             "6) Rules live in src/alerts.c\n", &c);
    ASSERT_EQ(c.n_views, 0);
    ASSERT_EQ(c.n_rules, 0);
    /* An indented list item is still a list item. */
    scan_all("   5. Views read from state\n", &c);
    ASSERT_EQ(c.n_views, 0);
    /* And a numbered markdown heading is a position too — MISSION.md's
       own section title, which is what found this gap. */
    scan_all("## 2. Rules of engagement (non-negotiable)\n", &c);
    ASSERT_EQ(c.n_rules, 0);
    scan_all("### 7. Views and what they show\n", &c);
    ASSERT_EQ(c.n_views, 0);
    /* But a real claim that merely happens to start a line still
       counts — the exclusion keys on the '. ' or ') ', not on column
       zero, so dropping that detail would silently blind the gate. */
    scan_all("35 views are rendered\n", &c);
    ASSERT_EQ(c.n_views, 1);
    ASSERT_EQ(c.views[0], 35);
    /* And mid-sentence prose is untouched. */
    scan_all("renders 35 views and 70 alert rules", &c);
    ASSERT_EQ(c.n_views, 1);
    ASSERT_EQ(c.n_rules, 1);
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
        /* log.md is exempt from the COUNT check, and from that alone.
         *
         * It is an append-only historical record: an entry reading
         * "70 -> 71 alert rules" states what changed on a dated day and
         * stays true forever, whereas this check asks whether a page
         * describes the CURRENT build. Without the exemption every
         * count bump leaves a permanent failure behind it and the only
         * way to go green is to reword history — which is the wrong
         * direction, and would have bitten five times in one session as
         * the rule count went 70 -> 75.
         *
         * Same reasoning already applied to the assertion counts there,
         * noted in this function's own header comment. Nothing else is
         * skipped: a stale count on any other wiki page still fails. */
        if (strcmp(e->d_name, "log.md") != 0) check_counts(path, &c);
        free(t);
    }
    closedir(d);
    /* The walk actually found pages: a wrong relative path would
       otherwise pass this test by checking nothing at all. */
    ASSERT_GE(pages, 40);
    ASSERT_GE(with_claims, 1);
}

/* agents/ states the same counts, and until now nothing checked it
 * either — README and docs/wiki were gated above while the files that
 * steer every agent were left to diligence. That is the wrong way
 * round: risk_score.sh weights any diff under agents/ at +40 precisely
 * because a wrong line there propagates into work, so those files
 * deserve at least the gate the public docs get.
 *
 * The gap was not hypothetical. On 2026-10-13 agents/AGENTS.md,
 * agents/FACTORY.md and agents/dark-factory.md each carried "9304
 * assertions" against a real 14143 — three thousand stale, in the same
 * file that tells readers an assertion count is measured and never
 * recalled. Those three were deleted rather than refreshed, for the
 * reason given above test_wiki_counts_match_build: the number tells a
 * reader nothing actionable and is wrong within a week. The view and
 * rule counts are different — they are the shape of the program and an
 * agent plans against them — so they stay, and this pins them.
 *
 * Versions are deliberately NOT checked here, unlike README and
 * SECURITY.md. agents/FACTORY.md is a build runbook, so most versions
 * in it belong to other people's software — `Cppcheck 2.13.0` is the
 * pinned CI analyser, and check_no_future_version read it as sloth
 * 2.13.0 and failed. The scanner cannot tell whose version a
 * three-component number is, and teaching it to would mean a list of
 * third-party tool names that rots. That check earns its place where
 * every version named IS sloth's; here it would only cry wolf. */
static void test_agent_docs_counts_match_build(void) {
    const char *dir = "agents";
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
    /* Four .md files live there today (AGENTS, FACTORY, dark-factory,
       converge). A wrong path would otherwise check nothing and pass. */
    ASSERT_GE(pages, 4);
    /* And at least one really does state a count — without this the
       test would still pass if the claims were silently dropped, which
       is half the drift it exists to catch. */
    ASSERT_GE(with_claims, 1);
}

/* MISSION.md is the charter and states both counts — four times, in the
 * overview and in its own counts section. It was unchecked until
 * 2026-10-13, and the drift that prompted adding it was real: a slice
 * raising ALERT_TYPE_COUNT to 71 found "70 alert rules" here and fixed
 * it by hand, which is exactly the mechanism this file exists to
 * replace.
 *
 * Counts only, not versions — same call as the agents/ tree. MISSION.md
 * may legitimately cite a historical release, and check_no_future_version
 * earns its place only where every version named is sloth's own. */
static void test_mission_counts_match_build(void) {
    char *t = slurp("MISSION.md");
    ASSERT(t != NULL);
    if (!t) return;
    dc_claims_t c;
    scan_all(t, &c);
    /* Floors rather than exact counts, so a reworded sentence that slips
       past the grammar fails loudly instead of turning this check
       vacuous.
       
       Views is 1, not 2: MISSION.md's other mention is "35 panels", and
       the grammar reads "views" and "rules" only. Widening it to
       "panels" was the alternative and was rejected — the noun set is
       deliberately closed, and "panel" appears in this repo's prose for
       dashboard tiles as well as for views, so admitting it would trade
       a false negative here for false positives elsewhere. */
    ASSERT_GE(c.n_views, 1);
    ASSERT_GE(c.n_rules, 2);
    check_counts("MISSION.md", &c);
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

/* The tab-bar badge is operator-facing surface the wiki has to carry:
 * an operator who sees `!persist eapol:4` on the bar has nowhere to
 * look it up unless cli-reference.md spells the form out. The wave-6
 * slice shipped the badge and skipped the page — the literal
 * `!persist` existed nowhere under docs/ — which is the AGENTS.md
 * "a behaviour change updates the wiki in the same change" duty going
 * unpaid, on the issue whose whole subject is docs drifting from code.
 *
 * Asserted against what the formatter actually emits, not against a
 * sentence: a badge is rendered from a seeded snapshot, then every
 * token of it has to appear in the page. Renaming the prefix or any
 * sink token in src/persist_health.c therefore fails here and names
 * the page, which a prose-matching test could not do. The token
 * prefixes are matched rather than the whole badge because the page
 * documents the `N` placeholder form; it also carries this exact
 * worked example, so the full string is checked too. */
static void test_persist_badge_documented(void) {
#define DC_PAGE "docs/wiki/cli-reference.md"   /* DC_WIKI_DIR is defined below */
    persist_health_t p;
    memset(&p, 0, sizeof(p));
    p.jsonl = 3; p.alert_pcap = 1; p.eapol = 2;
    char badge[96];
    ASSERT_EQ(persist_badge(&p, badge, sizeof(badge)), 6);
    ASSERT_STR(badge, "!persist jsonl:3 pcap:1 eapol:2");

    char *t = slurp(DC_PAGE);
    ASSERT(t != NULL);
    if (!t) return;

    /* The prefix, the worked example verbatim, and each sink token up
     * to its colon (the page writes the count as N). */
    ASSERT(strstr(t, "!persist") != NULL);
    ASSERT(strstr(t, badge) != NULL);
    int toks = 0;
    for (const char *sp = strchr(badge, ' '); sp; sp = strchr(sp, ' ')) {
        const char *tok = sp + 1;
        const char *colon = strchr(tok, ':');
        if (!colon) break;
        char want[32];
        size_t n = (size_t)(colon - tok) + 1;          /* include ':' */
        if (n >= sizeof(want)) break;
        memcpy(want, tok, n);
        want[n] = '\0';
        toks++;
        if (!strstr(t, want))
            fprintf(stderr, "    %s does not document "
                            "the badge token \"%s\" emitted by "
                            "persist_badge()\n", DC_PAGE, want);
        ASSERT(strstr(t, want) != NULL);
        sp = tok;
    }
    /* One token per sink: a scan that found none would pass vacuously. */
    ASSERT_EQ(toks, 3);
    free(t);

    /* The page's FIRST documented behaviour is "only failing sinks
     * appear", and the scan above never exercises it — every token is
     * present because every count was non-zero. Review found the gap
     * with a surviving mutation: deleting the `p->jsonl > 0` /
     * `p->alert_pcap > 0` / `p->eapol > 0` guards in
     * src/persist_health.c so that every sink always prints left the
     * suite green, which means the documented sentence could become
     * false without a red build. These three cases close it.
     *
     * The badge matters precisely because of this: `jsonl:0` would tell
     * an operator a sink had failed zero times, which is a strange way
     * to say "fine", and the point of the badge is that its presence
     * means something is wrong. */
    memset(&p, 0, sizeof(p));
    p.jsonl = 2;
    ASSERT_EQ(persist_badge(&p, badge, sizeof(badge)), 2);
    ASSERT_STR(badge, "!persist jsonl:2");

    memset(&p, 0, sizeof(p));
    p.eapol = 7;
    ASSERT_EQ(persist_badge(&p, badge, sizeof(badge)), 7);
    ASSERT_STR(badge, "!persist eapol:7");

    /* The middle sink alone, so a guard deleted from only the first or
     * only the last is still caught. */
    memset(&p, 0, sizeof(p));
    p.alert_pcap = 1;
    ASSERT_EQ(persist_badge(&p, badge, sizeof(badge)), 1);
    ASSERT_STR(badge, "!persist pcap:1");

    /* And no failures at all emits nothing, so a healthy run shows no
     * badge rather than an empty one. */
    memset(&p, 0, sizeof(p));
    badge[0] = 'X';
    ASSERT_EQ(persist_badge(&p, badge, sizeof(badge)), 0);
#undef DC_PAGE
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

/*
 * CLI surface vs. the wiki reference — issue #103.
 *
 * agents/AGENTS.md ties one surface to one page: "new or changed CLI
 * flag / keybinding -> docs/wiki/cli-reference.md". Nothing enforced it.
 * The #103 triage comment checked the flag half by hand and found it
 * complete — and quoted "37 of them", which was already stale by seven
 * options the next time anyone measured (44). That is the whole case for
 * a guard: the hand check does not run again, and its own number rotted
 * faster than the thing it was checking.
 *
 * Flags are checked both ways, because the two failures differ. A flag
 * parsed in src/main.c and absent from the page is an undocumented
 * flag; a flag on the page that src/main.c no longer parses is advice
 * that exits non-zero. Keys are checked one way only: the page's global
 * and per-view tables also document `Tab`, `/`, `\`, `n`, `q` and
 * `Enter`, which are not view selections, so a reverse walk would pin
 * an exception list rather than the bindings.
 *
 * src/main.c is not in TEST_SRCS — the test binary has its own main() —
 * so both scanners read it as text, the way test_usage_text_agrees_with_build
 * above already does. That also means these check the *parser*, not
 * print_usage(): the two disagree today (`--no-colour` and `--help` have
 * no usage line), and reconciling them is not this guard's job.
 *
 * Floors on every walk, for the reason the wiki walks have them: a
 * scanner that matches nothing passes every assertion it never makes.
 *
 * Not checked: short options (`-o`, `-V`, `-h`), which the page does
 * document; `?`, which reaches VIEW_HELP from an if rather than the
 * switch; and whether a documented flag's described *behaviour* is
 * right, which is the docs-drift judge's advisory territory.
 */

#define DC_CLI_REF       "docs/wiki/cli-reference.md"
#define DC_MAX_OPTS      128
#define DC_OPT_LEN       48
/* Measured, not recalled: src/main.c parses 44 distinct long options and
 * DC_CLI_REF backticks all 44 (both directions, zero missing). */
#define DC_MIN_LONG_OPTS 44

/* The long-option name charset.
 *
 * `_` and upper case are included even though no flag uses them today,
 * because the point of the forward walk is to catch an UNDOCUMENTED
 * flag and a narrow charset silently exempts the ones that do not match
 * house style. Review proved it: `--mutant_flag` and `--MutantFlag`
 * were both added to src/main.c's argv loop, both genuinely parsed,
 * both absent from the reference page, and the suite stayed green
 * because the scanner could not see them. A guard that only sees
 * conforming names pins the convention, not the parser.
 *
 * The glob in a prose mention such as `--wps-*` is still rejected, and
 * not by this charset — dc_scan_* requires the closing delimiter
 * IMMEDIATELY after the name, and `*` is neither an option character
 * nor the close, so the occurrence is dropped whole rather than
 * truncated to a plausible-looking `--wps-`. Widening the charset does
 * not re-admit globs; that was the original comment's claim and it was
 * wrong about which check does the work. */
static int dc_opt_char(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

#define DC_ARGV_OPEN "strcmp(argv[i], \"--"
#define DC_DOC_OPEN  "`--"

/* Store one name if it is new. Shared by both walks. */
static int dc_opt_push(char out[DC_MAX_OPTS][DC_OPT_LEN], int n,
                       const char *s, size_t len) {
    if (len == 0 || len >= DC_OPT_LEN || n >= DC_MAX_OPTS) return n;
    for (int i = 0; i < n; i++)
        if (!strncmp(out[i], s, len) && out[i][len] == '\0') return n;
    memcpy(out[n], s, len);
    out[n][len] = '\0';
    return n + 1;
}

/* The PARSER side: every long option the argv loop actually compares.
 *
 * Anchored on `strcmp(argv[i]` and then tolerant of whatever separates
 * it from the string literal, rather than matching one literal spelling
 * with one space in it. Review proved the literal version vacuous by
 * deleting a single space — `strcmp(argv[i],"--mutant-fmt")` parsed
 * fine and the scanner never saw it. Anything that reformats main.c,
 * including a formatter nobody ran deliberately, would have silently
 * disabled this guard. */
static int dc_scan_argv_opts(const char *t,
                             char out[DC_MAX_OPTS][DC_OPT_LEN]) {
    static const char anchor[] = "strcmp(argv[i]";
    int n = 0;
    for (const char *p = t; (p = strstr(p, anchor)) != NULL; ) {
        const char *q = p + sizeof(anchor) - 1;
        p = q;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != ',') continue;
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (strncmp(q, "\"--", 3) != 0) continue;
        const char *name = q + 3;
        size_t len = 0;
        while (dc_opt_char((unsigned char)name[len])) len++;
        if (name[len] != '"') continue;
        n = dc_opt_push(out, n, name, len);
    }
    return n;
}

/* The DOCUMENTATION side: only the first cell of a table row counts.
 *
 * A backticked flag ANYWHERE on the page used to count, which made the
 * reverse walk fire on prose that mentions a flag in order to say it
 * does not exist. That is not hypothetical — docs/wiki/cli-reference.md
 * says "the storage floors are knobs and not `--min-free-mb`", and with
 * the old scanner this test went red on current main while the page was
 * entirely correct. A red test on correct documentation trains the next
 * reader to delete the test.
 *
 * The flag table's first cell is the one place a row DECLARES a flag,
 * so that is what the reverse direction asks about. Prose may then
 * mention any flag, real or not, without the suite having an opinion.
 * A prose allowlist was the alternative and would rot on the first
 * paragraph nobody remembered to update. */
static int dc_scan_doc_opts(const char *t,
                            char out[DC_MAX_OPTS][DC_OPT_LEN]) {
    int n = 0;
    for (const char *line = t; line && *line; ) {
        const char *eol = strchr(line, '\n');
        const char *p   = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '|') {
            p++;
            /* The first cell only: everything up to the next pipe, or
             * the end of the line. A row documenting one flag may name
             * another in a later cell, and that is a mention. */
            const char *cell_end = p;
            while (*cell_end && *cell_end != '|' &&
                   (!eol || cell_end < eol)) cell_end++;
            /* Every backticked flag IN that cell, not just the first:
             * the page writes `| `-o`, `--out` |` and
             * `| `--no-color`, `--no-colour` |`, so an alias pair
             * declares two flags in one cell and taking only the first
             * loses the second. */
            for (const char *q = p; q + 3 < cell_end; q++) {
                if (strncmp(q, "`--", 3) != 0) continue;
                const char *name = q + 3;
                size_t len = 0;
                while (dc_opt_char((unsigned char)name[len])) len++;
                /* Closed by a backtick, or by a space — the page writes
                 * `| `--tune NAME=VALUE` |`, where the backtick spans
                 * the name AND its argument, so demanding a backtick
                 * immediately after the name drops a genuinely declared
                 * flag. A glob such as `--wps-*` is still rejected: `*`
                 * is neither an option character nor either terminator,
                 * so the occurrence is dropped whole. */
                if (name + len <= cell_end &&
                    (name[len] == '`' || name[len] == ' '))
                    n = dc_opt_push(out, n, name, len);
                q = name + len;
            }
        }
        line = eol ? eol + 1 : NULL;
    }
    return n;
}

static void test_cli_opt_extractor(void) {
    /* Hand-written, covering what the real file puts near a flag name:
     * a second parse of the same option, a short option, the usage text
     * (which is not the parser) and a prose mention in a comment. */
    static const char src[] =
        "    if (!strcmp(argv[i], \"--iface\") && i + 1 < argc) {\n"
        "    } else if (!strcmp(argv[i], \"-o\") ||\n"
        "               !strcmp(argv[i], \"--iface\")) {\n"
        "        fprintf(stderr, \"  --hop   retune the radio\\n\");\n"
        "    /* --tune is handled before the loop */\n";
    char opts[DC_MAX_OPTS][DC_OPT_LEN];
    ASSERT_EQ(dc_scan_argv_opts(src, opts), 1);
    ASSERT_STR(opts[0], "iface");

    /* The three spellings review proved invisible to the old literal
       scanner, each a genuinely parsed option: no space after the
       comma, an underscore, and upper case. All three must be seen now,
       because the walk exists to catch an undocumented flag and these
       are three easy ways to add one. */
    static const char odd[] =
        "    if (!strcmp(argv[i],\"--tight-fmt\")) {\n"
        "    } else if (!strcmp(argv[i], \"--under_score\")) {\n"
        "    } else if (!strcmp(argv[i],\n               \"--MixedCase\")) {\n";
    ASSERT_EQ(dc_scan_argv_opts(odd, opts), 3);
    ASSERT_STR(opts[0], "tight-fmt");
    ASSERT_STR(opts[1], "under_score");
    ASSERT_STR(opts[2], "MixedCase");

    /* And a usage-text line is still not a parse, even spaced oddly. */
    static const char usage[] =
        "        fprintf(stderr, \"  --not-parsed  explains itself\\n\");\n";
    ASSERT_EQ(dc_scan_argv_opts(usage, opts), 0);

    /* The documentation side, and the glob the charset must not eat. */
    static const char doc[] =
        "| `--iface` | ... |\n"
        "The `--wps-*` thresholds are listed below.\n"
        "| `--db` | ... |\n"
        "A bare --db outside backticks is prose, not a reference row.\n";
    ASSERT_EQ(dc_scan_doc_opts(doc, opts), 2);
    ASSERT_STR(opts[0], "iface");
    ASSERT_STR(opts[1], "db");

    /* The case that turned the suite red on correct documentation: a
       backticked flag in PROSE, mentioned in order to say it does not
       exist. It is not a table row's first cell, so it declares
       nothing and the reverse walk must not see it. Taken verbatim in
       shape from docs/wiki/cli-reference.md. */
    static const char prose[] =
        "| `--tune` | name=value | Move one knob. |\n"
        "The registry is the contract: adding a tunable adds a row\n"
        "there, not a new flag — which is why the storage floors are\n"
        "knobs and not `--min-free-mb`.\n";
    ASSERT_EQ(dc_scan_doc_opts(prose, opts), 1);
    ASSERT_STR(opts[0], "tune");

    /* A backticked flag in a LATER cell of a row is also a mention, not
       a declaration — a row documenting one flag may name another. */
    static const char later[] =
        "| `--strict` | — | Refuses `--allow-active`. |\n";
    ASSERT_EQ(dc_scan_doc_opts(later, opts), 1);
    ASSERT_STR(opts[0], "strict");
}

static void test_every_cli_flag_is_in_wiki_reference(void) {
    char *src = slurp("src/main.c");
    char *ref = slurp(DC_CLI_REF);
    ASSERT(src != NULL);
    ASSERT(ref != NULL);
    if (!src || !ref) { free(src); free(ref); return; }
    char opts[DC_MAX_OPTS][DC_OPT_LEN];
    int  n = dc_scan_argv_opts(src, opts);
    ASSERT_GE(n, DC_MIN_LONG_OPTS);
    int missing = 0;
    for (int i = 0; i < n; i++) {
        char want[DC_OPT_LEN + 8];
        snprintf(want, sizeof(want), "`--%s`", opts[i]);
        if (strstr(ref, want)) continue;
        missing++;
        fprintf(stderr, "    src/main.c parses --%s; %s does not "
                        "document it\n", opts[i], DC_CLI_REF);
    }
    ASSERT_EQ(missing, 0);
    free(src);
    free(ref);
}

static void test_wiki_reference_documents_no_dead_flag(void) {
    char *src = slurp("src/main.c");
    char *ref = slurp(DC_CLI_REF);
    ASSERT(src != NULL);
    ASSERT(ref != NULL);
    if (!src || !ref) { free(src); free(ref); return; }
    char opts[DC_MAX_OPTS][DC_OPT_LEN];
    int  n = dc_scan_doc_opts(ref, opts);
    ASSERT_GE(n, DC_MIN_LONG_OPTS);
    /* Membership in the parsed SET, not a search for one literal
     * spelling of the strcmp call. The literal form carried exactly the
     * spacing fragility dc_scan_argv_opts() exists to avoid, so a
     * reformatted main.c would have made every documented flag look
     * dead at once. */
    char parsed[DC_MAX_OPTS][DC_OPT_LEN];
    int  pn = dc_scan_argv_opts(src, parsed);
    int dead = 0;
    for (int i = 0; i < n; i++) {
        int found = 0;
        for (int j = 0; j < pn && !found; j++)
            if (!strcmp(parsed[j], opts[i])) found = 1;
        if (found) continue;
        dead++;
        fprintf(stderr, "    %s documents --%s; src/main.c parses no "
                        "such option\n", DC_CLI_REF, opts[i]);
    }
    ASSERT_EQ(dead, 0);
    free(src);
    free(ref);
}

#define DC_MAX_KEYS      64
/* Measured: the global switch binds 34 keys to a view (ten digits plus
 * 24 letters), and the keybinding tables backtick all 34. */
#define DC_MIN_VIEW_KEYS 34

/* Collect the keys the global switch binds to a view, upper-case aliases
 * folded onto their lower-case key because that is how the reference
 * tables write them.
 *
 * An arm counts only when a `case 'x':` label and the `s->active_view =`
 * assignment share one line, which is src/main.c's layout for every view
 * selection. That excludes the Tab cycle two ways over: its label sits on
 * its own line today, and the escape's leading backslash is not
 * alphanumeric, so a folded `case '\t':` arm is still skipped (the
 * extractor test below feeds both forms). The closing-quote check is
 * redundant against that input and is kept only so the scanner reads a
 * character literal rather than any text starting `case '`. Keys bound to
 * something other than a view (`n` toggles DNS resolution) never match,
 * because their arms assign no view.
 *
 * `?` is absent by design: VIEW_HELP is toggled by an absolute-global
 * `if` above the switch, not by a case arm. */
static int dc_view_keys(const char *src, char *out, int max) {
    int n = 0;
    for (const char *line = src; line && *line; ) {
        const char *nl   = strchr(line, '\n');
        size_t      llen = nl ? (size_t)(nl - line) : strlen(line);
        char        buf[1024];
        size_t      cl = llen < sizeof(buf) - 1 ? llen : sizeof(buf) - 1;
        memcpy(buf, line, cl);
        buf[cl] = '\0';
        line = nl ? nl + 1 : NULL;
        if (!strstr(buf, "s->active_view =")) continue;
        for (const char *p = buf; (p = strstr(p, "case '")) != NULL; ) {
            p += 6;
            if (!isalnum((unsigned char)p[0]) || p[1] != '\'') continue;
            char k   = (char)tolower((unsigned char)p[0]);
            int  dup = 0;
            for (int i = 0; i < n && !dup; i++) if (out[i] == k) dup = 1;
            if (!dup && n < max) out[n++] = k;
        }
    }
    return n;
}

static void test_view_key_extractor(void) {
    static const char src[] =
        "    case '1': s->active_view = VIEW_IFACE;   return;\n"
        "    case 'd': case 'D': s->active_view = VIEW_DHCP; return;\n"
        "    case '\\t':\n"
        "        s->active_view = (view_t)((s->active_view + 1) % VIEW_COUNT);\n"
        "        return;\n"
        /* The same arm folded onto one line: the one-line rule alone
         * would admit it, so this pins the alphanumeric test. */
        "    case '\\t': s->active_view = (view_t)(s->active_view + 1); return;\n"
        "    case 'n': case 'N':\n"
        "        s->dns_enabled = !s->dns_enabled;\n"
        "        return;\n";
    char keys[DC_MAX_KEYS];
    ASSERT_EQ(dc_view_keys(src, keys, DC_MAX_KEYS), 2);
    ASSERT_EQ(keys[0], '1');
    ASSERT_EQ(keys[1], 'd');
}

/* The switch and view_labels[] must bind the same key set. This is the
 * half of the keybinding duty with real teeth: view_labels[] feeds the
 * tab bar and the [?] help card, so a key the switch gains and the label
 * table does not is a view the operator can reach and cannot see named,
 * and a key the label table keeps after the switch drops it advertises a
 * key that does nothing.
 *
 * `?` is in view_labels[] and not in the switch — VIEW_HELP is toggled by
 * the absolute-global `if` above the switch — so it is the one expected
 * difference and is excluded by name rather than by a tolerance. */
static void test_view_keys_match_view_labels(void) {
    char *src = slurp("src/main.c");
    ASSERT(src != NULL);
    if (!src) return;
    char keys[DC_MAX_KEYS];
    int  n = dc_view_keys(src, keys, DC_MAX_KEYS);
    ASSERT_GE(n, DC_MIN_VIEW_KEYS);

    char lab[DC_MAX_KEYS];
    int  nl = 0;
    for (int v = 0; v < (int)VIEW_COUNT; v++) {
        const char *s = view_label((view_t)v);
        if (s[0] != '[' || s[2] != ']') continue;
        if (s[1] == '?') continue;
        if (nl < DC_MAX_KEYS) lab[nl++] = (char)tolower((unsigned char)s[1]);
    }
    ASSERT_EQ(nl, (int)VIEW_COUNT - 1);

    int only_switch = 0, only_label = 0;
    for (int i = 0; i < n; i++) {
        int hit = 0;
        for (int j = 0; j < nl && !hit; j++) if (lab[j] == keys[i]) hit = 1;
        if (hit) continue;
        only_switch++;
        fprintf(stderr, "    src/main.c binds '%c' to a view; "
                        "view_labels[] has no such key\n", keys[i]);
    }
    for (int j = 0; j < nl; j++) {
        int hit = 0;
        for (int i = 0; i < n && !hit; i++) if (keys[i] == lab[j]) hit = 1;
        if (hit) continue;
        only_label++;
        fprintf(stderr, "    view_labels[] advertises '%c'; the global "
                        "switch in src/main.c binds no such key\n", lab[j]);
    }
    ASSERT_EQ(only_switch, 0);
    ASSERT_EQ(only_label, 0);
    free(src);
}

/* The weaker half, and worth stating: every alphanumeric character is
 * already backticked somewhere in DC_CLI_REF (measured — all 36), so this
 * cannot fail on a key *added* to the switch. What it does catch is the
 * page losing a key: a table rewritten or a row dropped. It also does not
 * check which view a key is documented against, because the page's own
 * names ("Dashboard", "Rogue RADIUS") are longer than the view_labels[]
 * names ("Dash", "RADIUS") and matching them would pin the wording.
 * test_view_keys_match_view_labels above is the binding-level guard. */
static void test_every_view_key_is_in_wiki_reference(void) {
    char *src = slurp("src/main.c");
    char *ref = slurp(DC_CLI_REF);
    ASSERT(src != NULL);
    ASSERT(ref != NULL);
    if (!src || !ref) { free(src); free(ref); return; }
    char keys[DC_MAX_KEYS];
    int  n = dc_view_keys(src, keys, DC_MAX_KEYS);
    ASSERT_GE(n, DC_MIN_VIEW_KEYS);
    int missing = 0;
    for (int i = 0; i < n; i++) {
        char want[8];
        snprintf(want, sizeof(want), "`%c`", keys[i]);
        if (strstr(ref, want)) continue;
        missing++;
        fprintf(stderr, "    src/main.c binds '%c' to a view; %s does "
                        "not list it\n", keys[i], DC_CLI_REF);
    }
    ASSERT_EQ(missing, 0);
    free(src);
    free(ref);
}

void run_docs_consistency_tests(void) {
    TEST_SUITE("docs consistency (#96)");
    RUN_TEST(test_scanner_reads_counts_across_markup);
    RUN_TEST(test_scanner_ignores_non_claims);
    RUN_TEST(test_scanner_ignores_ordered_list_markers);
    RUN_TEST(test_scanner_versions_exclude_addresses);
    RUN_TEST(test_readme_counts_match_build);
    RUN_TEST(test_wiki_counts_match_build);
    RUN_TEST(test_agent_docs_counts_match_build);
    RUN_TEST(test_mission_counts_match_build);
    RUN_TEST(test_security_names_only_current_version);
    RUN_TEST(test_help_card_agrees_with_build);
    RUN_TEST(test_usage_text_agrees_with_build);
    RUN_TEST(test_persist_badge_documented);
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
    TEST_SUITE("CLI surface vs. wiki reference (#103)");
    RUN_TEST(test_cli_opt_extractor);
    RUN_TEST(test_every_cli_flag_is_in_wiki_reference);
    RUN_TEST(test_wiki_reference_documents_no_dead_flag);
    RUN_TEST(test_view_key_extractor);
    RUN_TEST(test_view_keys_match_view_labels);
    RUN_TEST(test_every_view_key_is_in_wiki_reference);
}
