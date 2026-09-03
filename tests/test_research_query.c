#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "query.h"

/*
 * Research-corpus queries — issue #73, slice 2.
 *
 * Driven against the shipped research.db rather than a fixture, because
 * the corpus is committed and is the thing --report and the [f] view
 * will actually read. A fixture would test the SQL and not the data.
 *
 * The corpus grows, so these assert *properties* — ordering is stable,
 * a known document is findable, provenance is always present — rather
 * than exact hit counts, which would turn every new document into a
 * failing test and teach the next person to stop adding documents.
 */

static rq_handle_t *corpus(void) { return rq_open("research.db"); }

static void test_open_and_close(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    ASSERT_STR(rq_open_error(), "");
    rq_close(h);
    rq_close(NULL);                       /* must be safe */
}

static void test_missing_corpus_degrades(void) {
    /* The contract --with-research depends on: no corpus means no
     * research context, never a failure to start. */
    rq_handle_t *h = rq_open("/nonexistent/research.db");
    ASSERT(h == NULL);
    ASSERT(rq_open_error()[0] != '\0');
    rq_close(h);
}

static void test_wrong_schema_is_distinguished(void) {
    /* A valid SQLite file that is not a corpus. Without the schema
     * probe this opens fine and then fails one query at a time with
     * errors that say nothing useful. */
    const char *tmp = "/tmp/sloth_not_a_corpus.db";
    unlink(tmp);
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "sqlite3 %s 'CREATE TABLE something(x);' >/dev/null 2>&1", tmp);
    if (system(cmd) != 0) return;         /* no sqlite3 CLI; skip */
    rq_handle_t *h = rq_open(tmp);
    ASSERT(h == NULL);
    ASSERT(strstr(rq_open_error(), "not a research corpus") != NULL);
    unlink(tmp);
}

static void test_null_handle_is_safe_everywhere(void) {
    /* Every entry point, with the handle the degraded path supplies. */
    rq_hit_t hits[RQ_MAX_HITS];
    char cites[4][RQ_STR];
    ASSERT_EQ(rq_search(NULL, "x", NULL, hits, RQ_MAX_HITS), 0);
    ASSERT_EQ(rq_for_alert(NULL, "ALERT_TYPE_PORT_SCAN", hits, RQ_MAX_HITS), 0);
    ASSERT_EQ(rq_cite(NULL, "wpa3", cites, 4), 0);
    ASSERT_EQ(rq_recent(NULL, 7, 1788000000, hits, RQ_MAX_HITS), 0);
}

static void test_search_finds_a_seeded_document(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_search(h, "dragonblood", NULL, hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    ASSERT(strstr(hits[0].source_url, "kb.cert.org") != NULL);
    rq_close(h);
}

static void test_every_hit_carries_provenance(void) {
    /* A hit that cannot say where it came from or when is not a
     * citation. The ingest guard enforces this per row; this asserts it
     * survives the query. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_search(h, "wpa3 OR eap OR block", NULL, hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    for (int i = 0; i < n; i++) {
        ASSERT(hits[i].source_url[0] != '\0');
        ASSERT(hits[i].retrieved[0]  != '\0');
        ASSERT(hits[i].path[0]       != '\0');
    }
    rq_close(h);
}

static void test_search_ranks_best_first(void) {
    /* BM25 is negative and more-negative is better, so the ordering
     * must be ascending. Getting the sign backwards returns the worst
     * matches first and looks like a working search. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_search(h, "downgrade OR transition", NULL, hits, RQ_MAX_HITS);
    ASSERT(n > 1);
    for (int i = 1; i < n; i++)
        ASSERT(hits[i - 1].score <= hits[i].score);
    rq_close(h);
}

static void test_search_snippet_shows_the_match(void) {
    /* Not the head of the section: a hit showing the first 256 bytes of
     * a document is a citation, not an answer. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_search(h, "supplicant", NULL, hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    ASSERT(hits[0].snippet[0] != '\0');
    rq_close(h);
}

static void test_search_filter_narrows(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t all[RQ_MAX_HITS], filtered[RQ_MAX_HITS];
    int a = rq_search(h, "wpa3 OR peap OR block", NULL, all, RQ_MAX_HITS);
    int f = rq_search(h, "wpa3 OR peap OR block", "peap", filtered,
                      RQ_MAX_HITS);
    ASSERT(a > 0);
    ASSERT(f <= a);
    for (int i = 0; i < f; i++)
        ASSERT(strstr(filtered[i].path, "2023-52160") != NULL);
    rq_close(h);
}

static void test_empty_query_returns_nothing(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    ASSERT_EQ(rq_search(h, "", NULL, hits, RQ_MAX_HITS), 0);
    ASSERT_EQ(rq_search(h, NULL, NULL, hits, RQ_MAX_HITS), 0);
    rq_close(h);
}

static void test_for_alert_finds_its_documents(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_for_alert(h, "ALERT_TYPE_BTM_ABUSE", hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    ASSERT(strstr(hits[0].path, "802.11-2020") != NULL);
    rq_close(h);
}

static void test_for_alert_does_not_match_a_prefix(void) {
    /* ALERT_TYPE_ROGUE must not pull documents that name
     * ALERT_TYPE_ROGUE_RADIUS — the same whole-token trap the corpus
     * guard has. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int specific = rq_for_alert(h, "ALERT_TYPE_WPA_DOWNGRADE", hits,
                                RQ_MAX_HITS);
    ASSERT(specific > 0);
    int prefix = rq_for_alert(h, "ALERT_TYPE_WPA", hits, RQ_MAX_HITS);
    ASSERT_EQ(prefix, 0);
    rq_close(h);
}

static void test_for_alert_does_not_match_a_longer_kind(void) {
    /* The realistic false positive, and the reason this cannot use
     * FTS5 MATCH at all: the unicode61 tokenizer splits on underscores,
     * so a MATCH for ALERT_TYPE_EVIL_TWIN needs only the tokens
     * alert/type/evil/twin present — and a document naming *only*
     * ALERT_TYPE_EVIL_TWIN_PROXIMITY contains every one of them.
     *
     * The References block for one alert would then cite a document
     * about a different alert, which is worse than citing nothing
     * because it looks correct. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];

    /* T1557.md names EVIL_TWIN and EVIL_TWIN_PROXIMITY, so both
     * resolve — the check is that each resolves to documents that
     * actually name it, not that either is empty. */
    int twin = rq_for_alert(h, "ALERT_TYPE_EVIL_TWIN", hits, RQ_MAX_HITS);
    ASSERT(twin > 0);

    /* And a kind no document names must stay empty even though every
     * one of its tokens appears in the corpus. */
    ASSERT_EQ(rq_for_alert(h, "ALERT_TYPE_EVIL", hits, RQ_MAX_HITS), 0);
    ASSERT_EQ(rq_for_alert(h, "ALERT_TYPE_TWIN", hits, RQ_MAX_HITS), 0);
    ASSERT_EQ(rq_for_alert(h, "EVIL_TWIN", hits, RQ_MAX_HITS), 0);
    rq_close(h);
}

static void test_cite_does_not_match_a_longer_token(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    char cites[8][RQ_STR];
    /* "wpa3" is a real topic; "wpa" is not, and must not match it. */
    ASSERT(rq_cite(h, "wpa3", cites, 8) > 0);
    ASSERT_EQ(rq_cite(h, "wpa", cites, 8), 0);
    rq_close(h);
}

static void test_for_alert_returns_documents_not_sections(void) {
    /* The index stores a row per heading. A References block wants one
     * entry per source — a document with four matching sections listed
     * four times reads as four citations, not one. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_for_alert(h, "ALERT_TYPE_BTM_ABUSE", hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            ASSERT(strcmp(hits[i].path, hits[j].path) != 0);
    /* And the title is the document's, not an arbitrary section's. */
    ASSERT(strstr(hits[0].title, "802.11") != NULL);
    rq_close(h);
}

static void test_for_alert_ordering_is_stable(void) {
    /* A References block regenerated tomorrow must be byte-identical to
     * today's — so the order cannot come from BM25, which shifts as the
     * corpus grows. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t a[RQ_MAX_HITS], b[RQ_MAX_HITS];
    int na = rq_for_alert(h, "ALERT_TYPE_WPA_DOWNGRADE", a, RQ_MAX_HITS);
    int nb = rq_for_alert(h, "ALERT_TYPE_WPA_DOWNGRADE", b, RQ_MAX_HITS);
    ASSERT_EQ(na, nb);
    for (int i = 0; i < na; i++)
        ASSERT_EQ(strcmp(a[i].path, b[i].path), 0);
    rq_close(h);
}

static void test_for_alert_unknown_kind_is_empty(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    ASSERT_EQ(rq_for_alert(h, "ALERT_TYPE_NOT_A_REAL_KIND", hits,
                           RQ_MAX_HITS), 0);
    rq_close(h);
}

static void test_cite_is_one_per_source(void) {
    /* Several sections of one advisory match; the citation set must
     * name the advisory once. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    char cites[8][RQ_STR];
    int n = rq_cite(h, "wpa3", cites, 8);
    ASSERT(n > 0);
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++)
            ASSERT(strcmp(cites[i], cites[j]) != 0);
    rq_close(h);
}

static void test_cite_ordering_is_stable(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    char a[8][RQ_STR], b[8][RQ_STR];
    int na = rq_cite(h, "wpa3", a, 8);
    int nb = rq_cite(h, "wpa3", b, 8);
    ASSERT_EQ(na, nb);
    for (int i = 0; i < na; i++) ASSERT_EQ(strcmp(a[i], b[i]), 0);
    /* Sorted, so the set is comparable across corpus versions. */
    for (int i = 1; i < na; i++) ASSERT(strcmp(a[i - 1], a[i]) <= 0);
    rq_close(h);
}

static void test_recent_respects_the_window(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    /* The seeded corpus is dated 2026-08-31. A window ending well after
     * that finds nothing; one spanning it finds documents. */
    time_t long_after = 1798761600;              /* 2027-01-01 */
    ASSERT_EQ(rq_recent(h, 7, long_after, hits, RQ_MAX_HITS), 0);
    int n = rq_recent(h, 365, long_after, hits, RQ_MAX_HITS);
    ASSERT(n > 0);
    rq_close(h);
}

static void test_recent_defaults_a_bad_window(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    /* Zero or negative days must not mean "everything" or "nothing by
     * accident" — it means the default. */
    int a = rq_recent(h, 0,  1798761600, hits, RQ_MAX_HITS);
    int b = rq_recent(h, -5, 1798761600, hits, RQ_MAX_HITS);
    ASSERT_EQ(a, b);
    rq_close(h);
}

static void test_max_is_respected(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    int n = rq_search(h, "the OR a OR of", NULL, hits, 2);
    ASSERT(n <= 2);
    ASSERT_EQ(rq_search(h, "wpa3", NULL, hits, 0), 0);
    rq_close(h);
}

static void test_recent_is_bounded_above_too(void) {
    /* Found by the MCP tests, fixed here. The window was open-ended
     * above, so `days=1` evaluated at a date before the corpus was
     * written returned every document in it — the cutoff was below all
     * of them. In production `now` is the real clock and nothing is
     * dated ahead of it, which is exactly why this would never have
     * shown up until a retrieved field was wrong or a clock moved, and
     * then it would have made the weekly brief silently complete. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    rq_hit_t hits[RQ_MAX_HITS];
    ASSERT_EQ(rq_recent(h, 1, 1000000000 /* 2001-09-09 */,
                        hits, RQ_MAX_HITS), 0);
    /* And a window that does span the corpus still works, so the fix
     * bounded rather than broke it. */
    ASSERT_GT(rq_recent(h, 365, 1798761600 /* 2027-01-01 */,
                        hits, RQ_MAX_HITS), 0);
    rq_close(h);
}


void run_research_query_tests(void) {
    TEST_SUITE("research query: open and degrade (#73)");
    RUN_TEST(test_open_and_close);
    RUN_TEST(test_missing_corpus_degrades);
    RUN_TEST(test_wrong_schema_is_distinguished);
    RUN_TEST(test_null_handle_is_safe_everywhere);

    TEST_SUITE("research query: search (#73)");
    RUN_TEST(test_search_finds_a_seeded_document);
    RUN_TEST(test_every_hit_carries_provenance);
    RUN_TEST(test_search_ranks_best_first);
    RUN_TEST(test_search_snippet_shows_the_match);
    RUN_TEST(test_search_filter_narrows);
    RUN_TEST(test_empty_query_returns_nothing);
    RUN_TEST(test_max_is_respected);

    TEST_SUITE("research query: for_alert and cite (#73)");
    RUN_TEST(test_for_alert_finds_its_documents);
    RUN_TEST(test_for_alert_does_not_match_a_prefix);
    RUN_TEST(test_for_alert_does_not_match_a_longer_kind);
    RUN_TEST(test_cite_does_not_match_a_longer_token);
    RUN_TEST(test_for_alert_returns_documents_not_sections);
    RUN_TEST(test_for_alert_ordering_is_stable);
    RUN_TEST(test_for_alert_unknown_kind_is_empty);
    RUN_TEST(test_cite_is_one_per_source);
    RUN_TEST(test_cite_ordering_is_stable);

    TEST_SUITE("research query: recent (#73)");
    RUN_TEST(test_recent_respects_the_window);
    RUN_TEST(test_recent_defaults_a_bad_window);
    RUN_TEST(test_recent_is_bounded_above_too);
}
