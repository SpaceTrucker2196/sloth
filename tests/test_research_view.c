#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "coverage.h"
#include "query.h"
#include "views/research.h"
#include "alerts.h"

/*
 * Research corpus view — issue #73 slice 3.
 *
 * Two layers. research/coverage.c turns the alert table into one row
 * per alert *kind* with the sources behind it; src/views/research.c
 * renders that. The coverage layer is where the judgement is, so it
 * gets most of the tests.
 *
 * The corpus-backed assertions run against the committed research.db —
 * a fixture would test the join and not the data, and the point of the
 * view is what the real corpus does and does not cover.
 */

static void add_alert(sloth_state_t *s, alert_type_t type, alert_sev_t sev,
                      const char *title, int count) {
    if (s->alert_count >= MAX_ALERTS) return;
    alert_t *a = &s->alerts[s->alert_count++];
    memset(a, 0, sizeof(*a));
    a->type  = type;
    a->sev   = sev;
    a->count = count;
    snprintf(a->title, sizeof(a->title), "%s", title);
}

static const research_cov_t *find_kind(const sloth_state_t *s,
                                       const char *kind) {
    for (int i = 0; i < s->research_cov_count; i++)
        if (strcmp(s->research_cov[i].kind, kind) == 0)
            return &s->research_cov[i];
    return NULL;
}

/* ── coverage ───────────────────────────────────────────────────────── */

static void test_no_alerts_is_no_rows(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_cov_count, 0);
    ASSERT_EQ(s.research_open, 0);
    view_research_draw(&s);            /* must not crash on empty */
}

static void test_null_state_is_safe(void) {
    research_coverage_snapshot(NULL, NULL);
    ASSERT(1);
}

static void test_one_row_per_kind_not_per_alert(void) {
    /* Two PORT_SCAN alerts against different hosts cite the same
     * document. Listing it twice makes the corpus look better covered
     * than it is. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "PORT_SCAN", 3);
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "PORT_SCAN", 2);
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "EVIL_TWIN", 1);
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_cov_count, 2);
    const research_cov_t *c = find_kind(&s, "ALERT_TYPE_PORT_SCAN");
    ASSERT(c != NULL);
    /* Occurrences accumulate across the merged alerts. */
    if (c) ASSERT_EQ(c->fired, 5);
}

static void test_kind_takes_the_worst_severity(void) {
    /* A WARN and a CRIT of one kind sort by the CRIT — the row stands
     * for the kind, and the operator scans by severity. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW,  "SCAN_LOW",  1);
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_CRIT, "SCAN_CRIT", 1);
    research_coverage_snapshot(&s, NULL);
    const research_cov_t *c = find_kind(&s, "ALERT_TYPE_PORT_SCAN");
    ASSERT(c != NULL);
    if (c) {
        ASSERT_EQ(c->severity, (int)ALERT_SEV_CRIT);
        ASSERT_STR(c->label, "SCAN_CRIT");
    }
}

static void test_rows_sort_worst_first(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_PORT_SCAN,  ALERT_SEV_LOW,  "LOW",  1);
    add_alert(&s, ALERT_TYPE_EVIL_TWIN,  ALERT_SEV_CRIT, "CRIT", 1);
    add_alert(&s, ALERT_TYPE_DNS_TUNNEL, ALERT_SEV_WARN, "WARN", 1);
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_cov_count, 3);
    ASSERT_EQ(s.research_cov[0].severity, (int)ALERT_SEV_CRIT);
    ASSERT_EQ(s.research_cov[1].severity, (int)ALERT_SEV_WARN);
    ASSERT_EQ(s.research_cov[2].severity, (int)ALERT_SEV_LOW);
}

static void test_ordering_is_stable_across_polls(void) {
    /* The selection is an index. If two equal-severity rows swap
     * between polls the cursor lands on a different alert without the
     * operator touching anything. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "A", 1);
    add_alert(&s, ALERT_TYPE_KARMA_AP,  ALERT_SEV_CRIT, "B", 1);
    add_alert(&s, ALERT_TYPE_ROGUE_RA,  ALERT_SEV_CRIT, "C", 1);
    research_coverage_snapshot(&s, NULL);
    char first[3][48];
    for (int i = 0; i < 3 && i < s.research_cov_count; i++)
        snprintf(first[i], sizeof(first[i]), "%s", s.research_cov[i].kind);
    for (int pass = 0; pass < 5; pass++) {
        research_coverage_snapshot(&s, NULL);
        for (int i = 0; i < 3 && i < s.research_cov_count; i++)
            ASSERT_STR(s.research_cov[i].kind, first[i]);
    }
}

static void test_selection_is_clamped(void) {
    /* Alerts age out, and a selection past the end would index off the
     * array in the detail pane. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "A", 1);
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "B", 1);
    research_coverage_snapshot(&s, NULL);
    s.research_sel = 1;

    s.alert_count = 1;                 /* one aged out */
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_cov_count, 1);
    ASSERT_EQ(s.research_sel, 0);

    s.alert_count = 0;
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_sel, 0);
    view_research_draw(&s);
}

static void test_table_is_bounded(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int t = 0; t < (int)ALERT_TYPE_COUNT && s.alert_count < MAX_ALERTS; t++)
        add_alert(&s, (alert_type_t)t, ALERT_SEV_WARN, "x", 1);
    research_coverage_snapshot(&s, NULL);
    ASSERT(s.research_cov_count <= MAX_RESEARCH_COV);
    ASSERT(s.research_cov_count > 0);
}

static void test_unnamed_alert_types_are_skipped(void) {
    /* alert_type_name() returns "" for ALERT_TYPE_COUNT. A row keyed on
     * an empty string would merge every such alert into one and query
     * the corpus for nothing. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_COUNT, ALERT_SEV_CRIT, "bogus", 1);
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_cov_count, 0);
}

/* ── against the shipped corpus ─────────────────────────────────────── */

static void test_corpus_backed_rows_carry_provenance(void) {
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* A kind the corpus does cover, and one it does not. Both must
     * appear — the uncited row is the finding. */
    add_alert(&s, ALERT_TYPE_FRAG_AMSDU, ALERT_SEV_CRIT, "FRAG_AMSDU", 1);
    add_alert(&s, ALERT_TYPE_PORT_SCAN,  ALERT_SEV_WARN, "PORT_SCAN",  1);
    research_coverage_snapshot(&s, h);
    ASSERT_EQ(s.research_open, 1);
    ASSERT_EQ(s.research_cov_count, 2);

    const research_cov_t *cited = find_kind(&s, "ALERT_TYPE_FRAG_AMSDU");
    ASSERT(cited != NULL);
    if (cited) {
        ASSERT(cited->doc_count > 0);
        for (int d = 0; d < cited->doc_count; d++) {
            /* A document that cannot say where it came from is not a
             * citation. */
            ASSERT(cited->docs[d].title[0]      != '\0');
            ASSERT(cited->docs[d].source_url[0] != '\0');
            ASSERT(cited->docs[d].retrieved[0]  != '\0');
        }
    }
    view_research_draw(&s);
    rq_close(h);
}

/* A corpus with exactly one document, citing exactly one kind. Used to
 * reach the uncited-detector path, which the shipped corpus no longer
 * offers: 59 of 60 kinds are cited and the sixtieth has no external
 * basis by design.
 *
 * That path has not become unreachable in production — a detector added
 * tomorrow starts uncited, which is precisely the case this view exists
 * to show — so it keeps its test rather than losing one to the corpus
 * having got better. Returns NULL if the sqlite3 CLI is unavailable. */
static rq_handle_t *sparse_corpus(const char *path) {
    unlink(path);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "sqlite3 %s \"CREATE VIRTUAL TABLE research USING fts5("
        "title, body, source_url UNINDEXED, retrieved UNINDEXED, topics,"
        " alert_kinds, path UNINDEXED, tokenize = 'porter unicode61');\""
        " >/dev/null 2>&1", path);
    if (system(cmd) != 0) return NULL;
    snprintf(cmd, sizeof(cmd),
        "sqlite3 %s \"INSERT INTO research VALUES('only doc','body',"
        "'https://example.org/1','2026-09-07','t',"
        "'ALERT_TYPE_EVIL_TWIN','research/x/1.md');\" >/dev/null 2>&1", path);
    if (system(cmd) != 0) { unlink(path); return NULL; }
    return rq_open(path);
}

static void test_uncovered_kinds_still_get_a_row(void) {
    /* The whole argument for this view. A kind with no sources must be
     * visible, not filtered out — an operator deciding whether to act
     * on a CRIT needs to know the threshold has no cited basis. */
    const char *tmp = "/tmp/sloth_cov_sparse.db";
    rq_handle_t *h = sparse_corpus(tmp);
    if (!h) return;                              /* no sqlite3 CLI; skip */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "EVIL_TWIN", 1);
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "PORT_SCAN", 1);
    research_coverage_snapshot(&s, h);
    ASSERT_EQ(s.research_cov_count, 2);
    const research_cov_t *gap = find_kind(&s, "ALERT_TYPE_PORT_SCAN");
    ASSERT(gap != NULL);
    if (gap) {
        ASSERT_EQ(gap->doc_count, 0);
        /* An uncited *detector* is a gap, not a deliberate absence. */
        ASSERT_EQ(gap->no_basis, 0);
    }
    const research_cov_t *ok = find_kind(&s, "ALERT_TYPE_EVIL_TWIN");
    ASSERT(ok && ok->doc_count > 0);
    view_research_draw(&s);
    rq_close(h);
    unlink(tmp);
}

static void test_no_basis_kinds_are_not_counted_as_gaps(void) {
    /* alert_technique() returns "" for a rule reporting sloth's own
     * posture rather than an adversary. Counting those against coverage
     * makes the number unreachable — 59 of 60 forever — and a target
     * that cannot be met stops being read. */
    rq_handle_t *h = rq_open("research.db");
    ASSERT(h != NULL);
    if (!h) return;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_NO_MONITOR_MODE, ALERT_SEV_LOW, "NO_MONITOR", 1);
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "EVIL_TWIN", 1);
    research_coverage_snapshot(&s, h);

    const research_cov_t *nm = find_kind(&s, "ALERT_TYPE_NO_MONITOR_MODE");
    ASSERT(nm != NULL);
    if (nm) {
        ASSERT_EQ(nm->no_basis, 1);
        ASSERT_EQ(nm->doc_count, 0);
    }
    /* A rule that *does* have a technique is never no_basis, whether or
     * not the corpus happens to cite it. */
    const research_cov_t *et = find_kind(&s, "ALERT_TYPE_EVIL_TWIN");
    ASSERT(et && et->no_basis == 0);
    view_research_draw(&s);

    /* The ratio the header shows: the no-basis kind is in neither half.
     * Counting it as an uncovered gap makes coverage unreachable —
     * 59 of 60 forever — and a target that cannot be met stops being
     * read at all. */
    int cited = 0;
    int citable = research_coverage_ratio(&s, &cited);
    ASSERT_EQ(citable, 1);
    ASSERT_EQ(cited, 1);
    rq_close(h);
}

static void test_coverage_ratio_edges(void) {
    ASSERT_EQ(research_coverage_ratio(NULL, NULL), 0);
    int cited = 99;
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ASSERT_EQ(research_coverage_ratio(&s, &cited), 0);
    ASSERT_EQ(cited, 0);
}

static void test_missing_corpus_and_loaded_corpus_differ(void) {
    /* "Nothing is cited" and "no corpus is loaded" look identical if
     * the table is simply empty, so research_open carries the
     * difference and the header renders it. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_FRAG_AMSDU, ALERT_SEV_CRIT, "FRAG_AMSDU", 1);
    research_coverage_snapshot(&s, NULL);
    ASSERT_EQ(s.research_open, 0);
    ASSERT_EQ(s.research_cov_count, 1);
    ASSERT_EQ(s.research_cov[0].doc_count, 0);

    rq_handle_t *h = rq_open("research.db");
    if (!h) return;
    research_coverage_snapshot(&s, h);
    ASSERT_EQ(s.research_open, 1);
    ASSERT(s.research_cov[0].doc_count > 0);
    rq_close(h);
}

static void test_more_documents_than_fit_are_reported(void) {
    /* MAX_RESEARCH_DOCS is 8 and the shipped corpus holds six documents
     * in total, so this path is unreachable against the real data — and
     * an unreported truncation is exactly the failure that hides: a row
     * showing eight documents when the corpus holds twelve reads as
     * complete coverage of a kind that has more to say.
     *
     * So a synthetic corpus, built with the same DDL research_ingest
     * uses. Not a mock of the query layer: this is a real FTS5 file
     * that rq_open and rq_for_alert run against unmodified. */
    const char *tmp = "/tmp/sloth_cov_trunc.db";
    unlink(tmp);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "sqlite3 %s \"CREATE VIRTUAL TABLE research USING fts5("
        "title, body, source_url UNINDEXED, retrieved UNINDEXED, topics,"
        " alert_kinds, path UNINDEXED, tokenize = 'porter unicode61');\""
        " >/dev/null 2>&1", tmp);
    if (system(cmd) != 0) return;                /* no sqlite3 CLI; skip */

    for (int i = 0; i < MAX_RESEARCH_DOCS + 4; i++) {
        snprintf(cmd, sizeof(cmd),
            "sqlite3 %s \"INSERT INTO research VALUES('doc%d','body',"
            "'https://example.org/%d','2026-09-04','t',"
            "'ALERT_TYPE_PORT_SCAN','research/x/%02d.md');\" >/dev/null 2>&1",
            tmp, i, i, i);
        if (system(cmd) != 0) { unlink(tmp); return; }
    }

    rq_handle_t *h = rq_open(tmp);
    ASSERT(h != NULL);
    if (!h) { unlink(tmp); return; }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "PORT_SCAN", 1);
    research_coverage_snapshot(&s, h);
    ASSERT_EQ(s.research_cov_count, 1);
    ASSERT_EQ(s.research_cov[0].doc_count, MAX_RESEARCH_DOCS);
    ASSERT_EQ(s.research_cov[0].docs_truncated, 1);
    view_research_draw(&s);
    rq_close(h);
    unlink(tmp);
}

/* ── the view ───────────────────────────────────────────────────────── */

static void test_nav_clamps_at_both_ends(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT, "A", 1);
    add_alert(&s, ALERT_TYPE_PORT_SCAN, ALERT_SEV_WARN, "B", 1);
    research_coverage_snapshot(&s, NULL);

    view_research_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.research_sel, 0);
    view_research_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.research_sel, 1);
    view_research_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.research_sel, 1);       /* clamped at the end */
    view_research_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.research_sel, 0);
    view_research_key(&s, 'q');         /* unhandled key changes nothing */
    ASSERT_EQ(s.research_sel, 0);
}

static void test_nav_on_an_empty_table_is_safe(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_research_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.research_sel, 0);
    view_research_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.research_sel, 0);
}

static void test_draw_at_every_selection(void) {
    /* The detail pane indexes research_cov[research_sel]; every
     * reachable value must render. */
    sloth_state_t s; memset(&s, 0, sizeof(s));
    add_alert(&s, ALERT_TYPE_EVIL_TWIN,  ALERT_SEV_CRIT, "A", 1);
    add_alert(&s, ALERT_TYPE_PORT_SCAN,  ALERT_SEV_WARN, "B", 1);
    add_alert(&s, ALERT_TYPE_DNS_TUNNEL, ALERT_SEV_LOW,  "C", 1);
    research_coverage_snapshot(&s, NULL);
    for (int i = 0; i < s.research_cov_count; i++) {
        s.research_sel = i;
        view_research_draw(&s);
    }
    ASSERT(1);
}

void run_research_view_tests(void);
void run_research_view_tests(void) {
    TEST_SUITE("research view: coverage (#73 slice 3)");
    RUN_TEST(test_no_alerts_is_no_rows);
    RUN_TEST(test_null_state_is_safe);
    RUN_TEST(test_one_row_per_kind_not_per_alert);
    RUN_TEST(test_kind_takes_the_worst_severity);
    RUN_TEST(test_rows_sort_worst_first);
    RUN_TEST(test_ordering_is_stable_across_polls);
    RUN_TEST(test_selection_is_clamped);
    RUN_TEST(test_table_is_bounded);
    RUN_TEST(test_unnamed_alert_types_are_skipped);

    TEST_SUITE("research view: against the corpus (#73 slice 3)");
    RUN_TEST(test_corpus_backed_rows_carry_provenance);
    RUN_TEST(test_uncovered_kinds_still_get_a_row);
    RUN_TEST(test_no_basis_kinds_are_not_counted_as_gaps);
    RUN_TEST(test_coverage_ratio_edges);
    RUN_TEST(test_missing_corpus_and_loaded_corpus_differ);
    RUN_TEST(test_more_documents_than_fit_are_reported);

    TEST_SUITE("research view: navigation (#73 slice 3)");
    RUN_TEST(test_nav_clamps_at_both_ends);
    RUN_TEST(test_nav_on_an_empty_table_is_safe);
    RUN_TEST(test_draw_at_every_selection);
}
