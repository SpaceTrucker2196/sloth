#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "runner.h"
#include "sloth.h"
#include "posture.h"
#include "sloth_clock.h"
#include "query.h"
#include "tmp_dir.h"

/* Roadmap #16 phase 5 — posture report export.
 *
 * These are golden-shape tests, not byte-for-byte comparisons: the
 * timestamps in the output vary per run, so we assert *structural*
 * invariants (headings present, alert counts correct, ATT&CK table
 * present when techniques are tagged, cleartext section present when
 * a cred was observed). */

static int contains(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

static void seed_alert(sloth_state_t *s, alert_type_t type, alert_sev_t sev,
                       const char *title, const char *tech, const char *match_ip)
{
    if (s->alert_count >= MAX_ALERTS) return;
    alert_t *a = &s->alerts[s->alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = type;
    a->sev  = sev;
    a->count = 1;
    snprintf(a->title,     sizeof(a->title),     "%s", title);
    snprintf(a->technique, sizeof(a->technique), "%s", tech);
    if (match_ip)
        snprintf(a->match_ip, sizeof(a->match_ip), "%s", match_ip);
    a->first_seen = a->last_seen = 1700000000;
}

static void test_md_header_and_alert_summary(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");
    seed_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_WARN,
               "SSH_BRUTE_FORCE", "T1110.001", "203.0.113.5");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT(fp);
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "# sloth posture report"));
    ASSERT(contains(buf, "## Alert summary"));
    ASSERT(contains(buf, "| CRIT | 0 |"));
    ASSERT(contains(buf, "| WARN | 1 |"));
    ASSERT(contains(buf, "| LOW  | 1 |"));
}

static void test_md_lists_techniques(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_WARN,
               "SSH_BRUTE", "T1110.001", "1.2.3.4");
    seed_alert(&s, ALERT_TYPE_RDP_BRUTE_FORCE, ALERT_SEV_WARN,
               "RDP_BRUTE", "T1110.001", "1.2.3.5");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "MITRE ATT&CK"));
    /* Two brute rules, same technique → one row, count 2. */
    ASSERT(contains(buf, "`T1110.001` | 2"));
}

static void test_md_lists_cleartext_creds(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    cleartext_cred_t *c = &s.cleartext_creds[s.cleartext_cred_count++];
    snprintf(c->src, sizeof(c->src), "10.0.0.5");
    snprintf(c->dst, sizeof(c->dst), "192.0.2.10");
    c->dst_port = 80;
    snprintf(c->protocol, sizeof(c->protocol), "HTTP-Basic");
    snprintf(c->username, sizeof(c->username), "alice");
    c->password_observed = 1;

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "Cleartext credential"));
    ASSERT(contains(buf, "alice"));
    /* Guardrail note visible in the report — the reader should see
     * explicitly that no password value is stored. */
    ASSERT(contains(buf, "Passwords are never stored"));
}

static void test_md_lists_high_risk_devices_only(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* Two devices: one LOW (should be omitted from High-risk section),
     * one CRIT (should appear). */
    device_t *d1 = &s.devices[s.device_count++];
    memset(d1, 0, sizeof(*d1));
    snprintf(d1->hostname, sizeof(d1->hostname), "printer.local");
    snprintf(d1->ip,       sizeof(d1->ip),       "10.0.0.20");
    d1->risk_level = DEV_RISK_LOW;

    device_t *d2 = &s.devices[s.device_count++];
    memset(d2, 0, sizeof(*d2));
    snprintf(d2->hostname, sizeof(d2->hostname), "unknown-host");
    snprintf(d2->ip,       sizeof(d2->ip),       "10.0.0.99");
    d2->risk_level = DEV_RISK_CRIT;

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);

    ASSERT(contains(buf, "High-risk devices"));
    ASSERT(contains(buf, "unknown-host"));
    ASSERT(contains(buf, "**CRIT**"));
    /* LOW device must not appear in the High-risk section. */
    ASSERT(!contains(buf, "printer.local"));
    /* d2 has no MAC (an IP-only camera record has none, #106 round 2):
     * "-", not an all-zero address. Seen to fail with posture_mac()'s
     * zero test removed. */
    ASSERT(contains(buf, "| `-` | `10.0.0.99` |"));
    ASSERT(!contains(buf, "00:00:00:00:00:00"));
}

static void test_json_shape(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");

    char buf[8192]; FILE *fp = fmemopen(buf, sizeof(buf), "w");
    posture_render_json(fp, &s, 1700000000);
    fclose(fp);

    ASSERT(contains(buf, "\"type\": \"posture_report\""));
    ASSERT(contains(buf, "\"crit\": 0"));
    ASSERT(contains(buf, "\"low\":  1"));
    ASSERT(contains(buf, "\"techniques\":"));
    ASSERT(contains(buf, "T1046"));
}


/* ── References block from the research corpus (#73) ──────── */

/* Distinct from seed_alert() above: that one takes a severity and a
 * detail, this one takes the title, because these tests are about the
 * type-to-name mapping and the title is the thing that must NOT be
 * used for it. */
static void seed_titled_alert(sloth_state_t *s, alert_type_t t,
                              const char *title) {
    alert_t *a = &s->alerts[s->alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev  = ALERT_SEV_WARN;
    snprintf(a->title,  sizeof(a->title),  "%s", title);
    snprintf(a->detail, sizeof(a->detail), "seeded");
    a->first_seen = a->last_seen = 1700000000;
    a->count = 1;
}

static char *render_with(sloth_state_t *s, struct rq_handle *h, char *buf,
                         size_t cap) {
    FILE *fp = tmpfile();
    if (!fp) return NULL;
    posture_render_md(fp, s, 1700000000, h);
    fflush(fp);
    rewind(fp);
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

static void test_no_corpus_means_no_references_block(void) {
    /* The additive contract: without --with-research the report is
     * exactly what it was before #73. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    static char buf[65536];
    ASSERT(render_with(&s, NULL, buf, sizeof(buf)) != NULL);
    ASSERT(strstr(buf, "## References") == NULL);
}

static void test_references_block_cites_the_alert(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    ASSERT(render_with(&s, h, buf, sizeof(buf)) != NULL);
    ASSERT(strstr(buf, "## References") != NULL);
    ASSERT(strstr(buf, "standards.ieee.org") != NULL);
    ASSERT(strstr(buf, "retrieved 2026-08-31") != NULL);
    rq_close(h);
}

static void test_lookup_uses_the_enum_name_not_the_title(void) {
    /* The bug this test exists for: alert titles are display strings
     * abbreviated to fit ALERT_TITLE_LEN, so BLOCKACK_ATK is the title
     * for ALERT_TYPE_BLOCKACK_ATTACK. Building the lookup key as
     * "ALERT_TYPE_" + title silently finds nothing for every alert
     * whose title was shortened — and a References block that is
     * quietly incomplete looks exactly like one that is complete.
     *
     * Seeded with a deliberately wrong title to prove the lookup does
     * not depend on it. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_WPA_DOWNGRADE, "NOT_THE_ENUM_NAME");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    ASSERT(strstr(buf, "## References") != NULL);
    ASSERT(strstr(buf, "kb.cert.org") != NULL);
    rq_close(h);
}

static void test_uncited_alert_produces_no_block(void) {
    /* An alert with no documents must not emit an empty References
     * heading.
     *
     * Driven from a synthetic empty corpus rather than the shipped one.
     * That is not a mock: it is a real FTS5 file the query layer runs
     * against unmodified. It is needed because the shipped corpus now
     * cites 59 of 60 kinds, so no real alert reaches this path — and
     * the path is still live, because a detector added tomorrow starts
     * uncited.
     *
     * Built via the sqlite3 C API this binary already links, not by
     * shelling out to the `sqlite3` CLI (#114) — the old `system()` call
     * returned non-zero and silently skipped the whole test, with zero
     * assertions run, on any host without that CLI installed (this
     * sandbox included: libsqlite3-dev ships the library, not the
     * binary). A skip that executes no ASSERT is indistinguishable from
     * a pass until something makes it visible. */
    char tmp[TEST_TMP_MAX];
    test_tmp_path(tmp, sizeof(tmp), "sloth_posture_sparse.db");
    unlink(tmp);
    sqlite3 *db = NULL;
    ASSERT_EQ(sqlite3_open(tmp, &db), SQLITE_OK);
    int rc = sqlite3_exec(db,
        "CREATE VIRTUAL TABLE research USING fts5("
        "title, body, source_url UNINDEXED, retrieved UNINDEXED, topics,"
        " alert_kinds, path UNINDEXED, tokenize = 'porter unicode61');",
        NULL, NULL, NULL);
    ASSERT_EQ(rc, SQLITE_OK);
    sqlite3_close(db);
    if (rc != SQLITE_OK) { unlink(tmp); return; }

    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_PORT_SCAN, "PORT_SCAN");
    rq_handle_t *h = rq_open(tmp);
    ASSERT(h != NULL);
    if (!h) { unlink(tmp); return; }
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    ASSERT(strstr(buf, "## References") == NULL);
    rq_close(h);
    unlink(tmp);
}

static void test_repeated_alerts_cited_once(void) {
    /* An alert firing against three BSSIDs is three rows and one set of
     * sources. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    seed_titled_alert(&s, ALERT_TYPE_BTM_ABUSE, "BTM_ABUSE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char buf[65536];
    render_with(&s, h, buf, sizeof(buf));
    const char *p = strstr(buf, "standards.ieee.org");
    ASSERT(p != NULL);
    ASSERT(strstr(p + 1, "standards.ieee.org") == NULL);
    rq_close(h);
}

/* The report header stamps sloth_wall() (posture.c, the session end), so
 * two real renders straddling a second boundary differ. That made this
 * test flaky under TSan's slowdown (CI run on 65afe2c). Pin the wall
 * clock: what is being asserted is the corpus ordering, not the time. */
static time_t posture_fixed_wall(void) { return 1700000100; }

static void test_report_is_reproducible(void) {
    /* Two renders of the same state and corpus must be identical —
     * that is why rq_for_alert orders by retrieved and path rather than
     * by BM25, which shifts as the corpus grows. */
    sloth_clock_test_set(NULL, posture_fixed_wall);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_titled_alert(&s, ALERT_TYPE_WPA_DOWNGRADE, "WPA_DOWNGRADE");
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    static char a[65536], b[65536];
    render_with(&s, h, a, sizeof(a));
    render_with(&s, h, b, sizeof(b));
    ASSERT_EQ(strcmp(a, b), 0);
    rq_close(h);
    sloth_clock_test_set(NULL, NULL);
}

static void test_every_alert_type_has_a_name(void) {
    /* alert_type_name() is a table generated from
     * include/sloth_alerts.def (#117), with the enum's spelling
     * stringized. A blank or missing entry loses that alert's citations
     * silently, so the guard is here rather than in a comment. Names
     * are also distinct: the corpus keys on them, and two types sharing
     * one would merge their citations. */
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) {
        const char *n = alert_type_name((alert_type_t)t);
        ASSERT(n != NULL);
        if (!n) continue;
        ASSERT(n[0] != '\0');
        ASSERT(strncmp(n, "ALERT_TYPE_", 11) == 0);
        ASSERT(strlen(n) > 11);
        int dup = 0;
        for (int u = 0; u < t; u++)
            if (!strcmp(n, alert_type_name((alert_type_t)u))) dup++;
        ASSERT_EQ(dup, 0);
    }
    /* Spot rows across the list, so an expansion that shifted names off
     * their enum values reads as wrong rather than merely non-empty. */
    ASSERT_STR(alert_type_name(ALERT_TYPE_PORT_SCAN), "ALERT_TYPE_PORT_SCAN");
    ASSERT_STR(alert_type_name(ALERT_TYPE_BLOCKACK_ATTACK),
               "ALERT_TYPE_BLOCKACK_ATTACK");
    ASSERT_STR(alert_type_name(ALERT_TYPE_QUEUE_EVICT),
               "ALERT_TYPE_QUEUE_EVICT");
    ASSERT_STR(alert_type_name(ALERT_TYPE_COUNT), "");
    ASSERT_STR(alert_type_name((alert_type_t)-1), "");
    ASSERT_STR(alert_technique(ALERT_TYPE_COUNT), "");
    ASSERT_STR(alert_technique((alert_type_t)-1), "");
}

/* ── Live report and per-session records (#190) ──────────────────────
 *
 * Time is driven through the clock seam: the interval is a duration, so
 * it runs on the monotonic stub and no test sleeps. Files are real, in
 * a 0700 directory under the run's $TMPDIR; nothing is mocked.
 *
 * The absence assertions were each seen red against a mutated
 * src/posture.c (2026-11-11), then restored:
 *   interval 0 writes nothing        dropped `interval_s == 0 ||`
 *   nothing before the interval      dropped the elapsed comparison
 *   a failed write keeps the old     wrote the live name in place
 *     file                             (SFILE_TRUNC, no rename)
 *   no temporary after a failed      dropped the unlink after rename
 *     rename
 *   a killed session's live file     skipped adopt_orphan()
 *     survives
 *   a non-regular live name is       dropped the S_ISREG refusal
 *     left alone
 *   a session record is never        sfile_fopen_unique -> SFILE_TRUNC
 *     replaced
 *   the shutdown report carries      wrappers passed live=1
 *     no live marker
 *   retire leaves the report         unlinked `path` instead of `live`
 *   retire keeps a killed            skipped adopt_orphan() in
 *     session's live file              posture_live_retire()
 * Not isolated: "no report path writes nothing even when asked". With
 * no path there is nothing to iterate, so the early return in
 * posture_live_tick() can be removed without that assertion noticing. */

static uint64_t g_pl_mono_ms;
static time_t   g_pl_wall;
static uint64_t pl_mono(void) { return g_pl_mono_ms; }
static time_t   pl_wall(void) { return g_pl_wall; }

typedef struct {
    char dir[TEST_TMP_MAX];
    char md[TEST_TMP_MAX + 32];
    char json[TEST_TMP_MAX + 32];
    char live_md[TEST_TMP_MAX + 40];
    char live_json[TEST_TMP_MAX + 40];
    char tmp_md[TEST_TMP_MAX + 48];
} pl_env_t;

static int pl_open(pl_env_t *e) {
    memset(e, 0, sizeof(*e));
    if (test_tmp_path(e->dir, sizeof(e->dir), "pl_XXXXXX") != 0 ||
        !mkdtemp(e->dir))
        return -1;
    snprintf(e->md,        sizeof(e->md),        "%s/report.md",   e->dir);
    snprintf(e->json,      sizeof(e->json),      "%s/report.json", e->dir);
    snprintf(e->live_md,   sizeof(e->live_md),   "%s/report.live.md",   e->dir);
    snprintf(e->live_json, sizeof(e->live_json), "%s/report.live.json", e->dir);
    snprintf(e->tmp_md,    sizeof(e->tmp_md),    "%s/.report.live.md.tmp",
             e->dir);
    g_pl_mono_ms = 5000;
    g_pl_wall    = 1700000000;
    sloth_clock_test_set(pl_mono, pl_wall);
    return 0;
}

static void pl_close(pl_env_t *e) {
    sloth_clock_test_set(NULL, NULL);
    ASSERT_EQ(test_rm_tree(e->dir), 0);
}

static int pl_exists(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0;
}

/* The whole file as a string; "" when it cannot be read. */
static const char *pl_slurp(const char *path) {
    static char buf[16384];
    buf[0] = '\0';
    FILE *fp = fopen(path, "r");
    if (!fp) return buf;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return buf;
}

/* Entries in the directory, and (when `needle` is given) the first name
 * containing it copied to `found`. */
static int pl_count(const char *dir, const char *needle,
                    char *found, size_t fsz) {
    int n = 0;
    if (found && fsz) found[0] = '\0';
    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        n++;
        if (needle && found && !found[0] && strstr(de->d_name, needle))
            snprintf(found, fsz, "%s/%s", dir, de->d_name);
    }
    closedir(d);
    return n;
}

static int pl_ends_with(const char *s, const char *tail) {
    size_t a = strlen(s), b = strlen(tail);
    return a >= b && strcmp(s + a - b, tail) == 0;
}

static void test_live_and_session_names(void) {
    char out[128];
    ASSERT_EQ(posture_live_path("/var/lib/sloth/report.md", out, sizeof(out)), 0);
    ASSERT_STR(out, "/var/lib/sloth/report.live.md");
    ASSERT_EQ(posture_live_path("report.json", out, sizeof(out)), 0);
    ASSERT_STR(out, "report.live.json");
    /* No extension, a leading dot, and a dot that belongs to a
     * directory: none of them is an extension to split on. */
    ASSERT_EQ(posture_live_path("report", out, sizeof(out)), 0);
    ASSERT_STR(out, "report.live");
    ASSERT_EQ(posture_live_path(".report", out, sizeof(out)), 0);
    ASSERT_STR(out, ".report.live");
    ASSERT_EQ(posture_live_path("a.d/report", out, sizeof(out)), 0);
    ASSERT_STR(out, "a.d/report.live");
    /* Refused, not clamped: no file name, and a result that would not
     * fit (a truncated path names some other file). */
    ASSERT_EQ(posture_live_path("dir/", out, sizeof(out)), -1);
    ASSERT_EQ(posture_live_path("", out, sizeof(out)), -1);
    ASSERT_EQ(posture_live_path("report.md", out, 14), -1);
    ASSERT_EQ(posture_live_path("report.md", out, 15), 0);

    /* 1700000000 is 2023-11-14T22:13:20Z. */
    ASSERT_EQ(posture_session_path("/x/report.md", 1700000000,
                                   out, sizeof(out)), 0);
    ASSERT_STR(out, "/x/report.20231114T221320Z.md");
    ASSERT_EQ(posture_session_path("/x/", 1700000000, out, sizeof(out)), -1);
}

static void test_final_report_is_not_marked_running(void) {
    /* The shutdown renderers are the pre-#190 ones: no live marker. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    static char buf[8192];
    memset(buf, 0, sizeof(buf));
    FILE *fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT(fp);
    if (!fp) return;
    posture_render_md(fp, &s, 1700000000, NULL);
    fclose(fp);
    ASSERT(contains(buf, "- **Session end**:   `"));
    ASSERT(!contains(buf, "(running)"));
    ASSERT(!contains(buf, "As of"));
    memset(buf, 0, sizeof(buf));
    fp = fmemopen(buf, sizeof(buf), "w");
    ASSERT(fp);
    if (!fp) return;
    posture_render_json(fp, &s, 1700000000);
    fclose(fp);
    ASSERT(contains(buf, "\"session_end\":   \""));
    ASSERT(!contains(buf, "running"));
    ASSERT(!contains(buf, "as_of"));
}

static void test_live_interval_zero_writes_nothing(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    posture_live_t L;
    posture_live_init(&L, e.md, e.json, 0, 1700000000, NULL);
    /* Eleven days of ticks with the interval off. */
    for (int i = 0; i < 1000; i++) {
        g_pl_mono_ms += 1000000;
        ASSERT_EQ(posture_live_tick(&L, &s, 0), 0);
    }
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 0);
    /* No report path at all: nothing even when asked. */
    posture_live_t N;
    posture_live_init(&N, NULL, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 61000;
    ASSERT_EQ(posture_live_tick(&N, &s, 1), 0);
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 0);
    /* SIGUSR1 is the one thing that writes with the interval off, and
     * it writes each file once. */
    ASSERT_EQ(posture_live_tick(&L, &s, 1), 2);
    ASSERT(pl_exists(e.live_md));
    ASSERT(pl_exists(e.live_json));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 2);
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 0);
    pl_close(&e);
}

static void test_live_tick_past_interval_writes_a_complete_report(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");
    /* The previous session's signed-off report sits at the operator
     * path; a live write must leave it alone. */
    FILE *fp = fopen(e.md, "w");
    ASSERT(fp);
    if (fp) { fputs("SIGNED OFF\n", fp); fclose(fp); }

    posture_live_t L;
    posture_live_init(&L, e.md, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 59999;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 0);
    ASSERT(!pl_exists(e.live_md));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 1);

    g_pl_mono_ms += 1;
    g_pl_wall    += 60;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    const char *r = pl_slurp(e.live_md);
    ASSERT(contains(r, "# sloth posture report"));
    ASSERT(contains(r, "- **Session start**: `2023-11-14T22:13:20Z`"));
    ASSERT(contains(r, "- **Session end**:   (running)"));
    ASSERT(contains(r, "- **As of**:         `2023-11-14T22:14:20Z`"));
    ASSERT(contains(r, "- **Duration**:      `60s`"));
    ASSERT(contains(r, "| LOW  | 1 |"));
    /* Complete: the renderer's last line is the file's last line. */
    ASSERT(pl_ends_with(r, "altering kernel state.\n"));
    struct stat st;
    ASSERT_EQ(stat(e.live_md, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 0777), 0600);
    /* Exactly the old report and the live one: no temporary. */
    ASSERT(!pl_exists(e.tmp_md));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 2);
    ASSERT_STR(pl_slurp(e.md), "SIGNED OFF\n");

    /* One write per interval, not one per tick. */
    g_pl_mono_ms += 59999;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 0);
    g_pl_mono_ms += 1;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 2);
    pl_close(&e);
}

static void test_live_json_is_marked_running(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    posture_live_t L;
    posture_live_init(&L, NULL, e.json, 30, 1700000000, NULL);
    g_pl_mono_ms += 30000;
    g_pl_wall    += 30;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    const char *r = pl_slurp(e.live_json);
    ASSERT(contains(r, "\"type\": \"posture_report\""));
    ASSERT(contains(r, "\"session_end\":   null,"));
    ASSERT(contains(r, "\"running\":       true,"));
    ASSERT(contains(r, "\"as_of\":         \"2023-11-14T22:13:50Z\","));
    ASSERT(contains(r, "\"duration_s\":    30,"));
    ASSERT(pl_ends_with(r, "]\n}\n"));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 1);
    pl_close(&e);
}

static void test_live_write_failure_keeps_the_old_file(void) {
    /* Root ignores directory modes, so the refusal cannot be staged. */
    if (geteuid() == 0) return;
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");
    posture_live_t L;
    posture_live_init(&L, e.md, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    ASSERT(contains(pl_slurp(e.live_md), "| LOW  | 1 |"));

    /* The state moves on and the directory stops taking new names. An
     * existing file in it can still be opened and truncated, so a
     * writer that rewrote the live file in place would pass the open
     * and destroy the old report: the content check below is what
     * tells the two apart. */
    seed_alert(&s, ALERT_TYPE_SSH_BRUTE_FORCE, ALERT_SEV_LOW,
               "SSH_BRUTE_FORCE", "T1110.001", "203.0.113.5");
    ASSERT_EQ(chmod(e.dir, 0500), 0);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), -1);
    ASSERT_EQ(L.fail.failures, 1);
    ASSERT(contains(L.fail.last, ".report.live.md.tmp"));
    /* Counted once an interval, not once a poll. */
    g_pl_mono_ms += 1000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 0);
    ASSERT_EQ(L.fail.failures, 1);
    ASSERT_EQ(chmod(e.dir, 0700), 0);

    const char *r = pl_slurp(e.live_md);
    ASSERT(contains(r, "| LOW  | 1 |"));
    ASSERT(pl_ends_with(r, "altering kernel state.\n"));
    ASSERT(!pl_exists(e.tmp_md));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 1);

    /* And the sensor is still writing once the directory recovers. */
    g_pl_mono_ms += 59000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    ASSERT(contains(pl_slurp(e.live_md), "| LOW  | 2 |"));
    pl_close(&e);
}

static void test_live_rename_failure_leaves_no_temporary(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    posture_live_t L;
    posture_live_init(&L, e.md, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    /* A directory at the live name: the temporary is created and
     * written, and the rename over it is what fails. */
    ASSERT_EQ(unlink(e.live_md), 0);
    ASSERT_EQ(mkdir(e.live_md, 0700), 0);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), -1);
    ASSERT(contains(L.fail.last, "rename failed"));
    ASSERT(!pl_exists(e.tmp_md));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 1);
    pl_close(&e);
}

static void test_live_write_replaces_a_stale_temporary(void) {
    /* A crash mid-write leaves the temporary behind. It is ours and is
     * replaced; were it not, O_EXCL would refuse every later write. */
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    FILE *fp = fopen(e.tmp_md, "w");
    ASSERT(fp);
    if (fp) { fputs("half a rep", fp); fclose(fp); }
    posture_live_t L;
    posture_live_init(&L, e.md, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&L, &s, 0), 1);
    ASSERT(!pl_exists(e.tmp_md));
    ASSERT(pl_ends_with(pl_slurp(e.live_md), "altering kernel state.\n"));
    pl_close(&e);
}

static void test_killed_session_live_report_survives_the_next(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));

    /* Session A writes a live report and is killed: no shutdown write,
     * no retire. */
    posture_live_t A;
    posture_live_init(&A, e.md, NULL, 60, 1700000000, NULL);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&A, &s, 0), 1);
    ASSERT(contains(pl_slurp(e.live_md), "2023-11-14T22:13:20Z"));

    /* Session B starts 500 s later. Its first live write takes the live
     * name; A's report is still there, under a name of its own. */
    posture_live_t B;
    g_pl_wall = 1700000500;
    posture_live_init(&B, e.md, NULL, 60, 1700000500, NULL);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&B, &s, 0), 1);
    ASSERT(contains(pl_slurp(e.live_md), "2023-11-14T22:21:40Z"));
    char kept[TEST_TMP_MAX + 96];
    ASSERT_EQ(pl_count(e.dir, ".unclean.md", kept, sizeof(kept)), 2);
    ASSERT(kept[0] != '\0');
    const char *r = pl_slurp(kept);
    ASSERT(contains(r, "- **Session start**: `2023-11-14T22:13:20Z`"));
    ASSERT(contains(r, "(running)"));
    ASSERT(pl_ends_with(r, "altering kernel state.\n"));
    struct stat st;
    ASSERT_EQ(stat(kept, &st), 0);
    ASSERT_EQ((int)st.st_nlink, 1);
    ASSERT_EQ((int)(st.st_mode & 0777), 0600);

    /* B's own later writes replace B's file and set nothing aside. */
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&B, &s, 0), 1);
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 2);

    /* A live name that is not a regular file is never linked aside or
     * replaced. */
    posture_live_t C;
    posture_live_init(&C, e.md, NULL, 60, 1700001000, NULL);
    ASSERT_EQ(unlink(e.live_md), 0);
    ASSERT_EQ(symlink(kept, e.live_md), 0);
    g_pl_mono_ms += 60000;
    ASSERT_EQ(posture_live_tick(&C, &s, 0), -1);
    ASSERT(contains(C.fail.last, "not a regular file"));
    ASSERT(contains(pl_slurp(kept), "2023-11-14T22:13:20Z"));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 2);
    pl_close(&e);
}

static void test_session_records_are_never_overwritten(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    char a[POSTURE_PATH_MAX], b[POSTURE_PATH_MAX], c[POSTURE_PATH_MAX];
    char want[TEST_TMP_MAX + 64], err[SFILE_ERR_MAX];

    /* Session one signs off with one LOW alert. */
    seed_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,
               "PORT_SCAN", "T1046", "10.0.0.99");
    g_pl_wall = 1700000100;
    ASSERT_EQ(posture_session_record(e.md, 0, &s, 1700000000, NULL,
                                     a, sizeof(a), err, sizeof(err)), 0);
    snprintf(want, sizeof(want), "%s/report.20231114T221320Z.md", e.dir);
    ASSERT_STR(a, want);
    ASSERT(contains(pl_slurp(a), "| LOW  | 1 |"));
    ASSERT(contains(pl_slurp(a), "- **Session end**:   `2023-11-14T22:15:00Z`"));
    struct stat st;
    ASSERT_EQ(stat(a, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 0777), 0600);

    /* Session two, a restart later, has seen nothing. Its record is a
     * second file and the first is as it was. */
    sloth_state_t s2; memset(&s2, 0, sizeof(s2));
    g_pl_wall = 1700000700;
    ASSERT_EQ(posture_session_record(e.md, 0, &s2, 1700000500, NULL,
                                     b, sizeof(b), err, sizeof(err)), 0);
    snprintf(want, sizeof(want), "%s/report.20231114T222140Z.md", e.dir);
    ASSERT_STR(b, want);
    ASSERT(contains(pl_slurp(b), "| LOW  | 0 |"));
    ASSERT(contains(pl_slurp(a), "| LOW  | 1 |"));

    /* Two sessions started in the same second (a --ticks batch run
     * twice): the later one takes _2, it does not replace the earlier. */
    ASSERT_EQ(posture_session_record(e.md, 0, &s2, 1700000000, NULL,
                                     c, sizeof(c), err, sizeof(err)), 0);
    snprintf(want, sizeof(want), "%s/report.20231114T221320Z_2.md", e.dir);
    ASSERT_STR(c, want);
    ASSERT(contains(pl_slurp(a), "| LOW  | 1 |"));
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 3);

    /* The JSON record, beside --report-json. */
    ASSERT_EQ(posture_session_record(e.json, 1, &s, 1700000000, NULL,
                                     c, sizeof(c), err, sizeof(err)), 0);
    snprintf(want, sizeof(want), "%s/report.20231114T221320Z.json", e.dir);
    ASSERT_STR(c, want);
    ASSERT(contains(pl_slurp(c), "\"session_end\":   \"2023-11-14T22:25:00Z\""));
    pl_close(&e);
}

static void test_retire_removes_only_the_live_file(void) {
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    FILE *fp = fopen(e.md, "w");
    ASSERT(fp);
    if (fp) { fputs("SIGNED OFF\n", fp); fclose(fp); }
    posture_live_t L;
    posture_live_init(&L, e.md, NULL, 60, 1700000000, NULL);
    ASSERT_EQ(posture_live_tick(&L, &s, 1), 1);
    ASSERT(pl_exists(e.live_md));
    posture_live_retire(&L, 0);
    ASSERT(!pl_exists(e.live_md));
    ASSERT_STR(pl_slurp(e.md), "SIGNED OFF\n");
    /* Nothing to retire is not an error, and a format that was never
     * configured is not touched. */
    posture_live_retire(&L, 0);
    posture_live_retire(&L, 1);
    ASSERT_EQ(pl_count(e.dir, NULL, NULL, 0), 1);
    pl_close(&e);
}

static void test_retire_keeps_a_killed_sessions_live_report(void) {
    /* Found end to end, not by a unit test: session A is killed with a
     * live report on disk; session B runs with no interval, writes no
     * live report, and signs off. B's retire found a file at the live
     * name and removed it, which was A's only record. */
    pl_env_t e;
    ASSERT_EQ(pl_open(&e), 0);
    if (!e.dir[0]) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    posture_live_t A;
    posture_live_init(&A, e.md, NULL, 0, 1700000000, NULL);
    ASSERT_EQ(posture_live_tick(&A, &s, 1), 1);

    posture_live_t B;
    posture_live_init(&B, e.md, NULL, 0, 1700000500, NULL);
    posture_live_retire(&B, 0);
    ASSERT(!pl_exists(e.live_md));
    char kept[TEST_TMP_MAX + 96];
    ASSERT_EQ(pl_count(e.dir, ".unclean.md", kept, sizeof(kept)), 1);
    ASSERT(contains(pl_slurp(kept),
                    "- **Session start**: `2023-11-14T22:13:20Z`"));
    struct stat st;
    ASSERT_EQ(stat(kept, &st), 0);
    ASSERT_EQ((int)st.st_nlink, 1);
    pl_close(&e);
}

void run_posture_tests(void) {
    TEST_SUITE("posture: live report and session records (#190)");
    RUN_TEST(test_live_and_session_names);
    RUN_TEST(test_final_report_is_not_marked_running);
    RUN_TEST(test_live_interval_zero_writes_nothing);
    RUN_TEST(test_live_tick_past_interval_writes_a_complete_report);
    RUN_TEST(test_live_json_is_marked_running);
    RUN_TEST(test_live_write_failure_keeps_the_old_file);
    RUN_TEST(test_live_rename_failure_leaves_no_temporary);
    RUN_TEST(test_live_write_replaces_a_stale_temporary);
    RUN_TEST(test_killed_session_live_report_survives_the_next);
    RUN_TEST(test_session_records_are_never_overwritten);
    RUN_TEST(test_retire_removes_only_the_live_file);
    RUN_TEST(test_retire_keeps_a_killed_sessions_live_report);

    TEST_SUITE("posture report — Markdown");
    RUN_TEST(test_md_header_and_alert_summary);
    RUN_TEST(test_md_lists_techniques);
    RUN_TEST(test_md_lists_cleartext_creds);
    RUN_TEST(test_md_lists_high_risk_devices_only);

    TEST_SUITE("posture report — JSON");
    RUN_TEST(test_json_shape);
    TEST_SUITE("posture: research References block (#73)");
    RUN_TEST(test_no_corpus_means_no_references_block);
    RUN_TEST(test_references_block_cites_the_alert);
    RUN_TEST(test_lookup_uses_the_enum_name_not_the_title);
    RUN_TEST(test_uncited_alert_produces_no_block);
    RUN_TEST(test_repeated_alerts_cited_once);
    RUN_TEST(test_report_is_reproducible);
    RUN_TEST(test_every_alert_type_has_a_name);
}
