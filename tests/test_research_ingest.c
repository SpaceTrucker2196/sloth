#include <string.h>
#include "runner.h"
#include "research_ingest.h"

/*
 * Research-corpus document parsing — issue #73, slice 1.
 *
 * The parser is pure — no filesystem, no SQLite — so these drive the
 * shipped code directly rather than a copy of its logic. The binary
 * that walks the tree is a thin wrapper over it.
 *
 * What matters here is not that well-formed documents parse. It is that
 * malformed ones are *refused rather than half-accepted*: a document
 * that indexes under the wrong alert kind, or under none, is worse than
 * one that fails loudly, because nothing downstream would ever say so.
 */

static const char *GOOD =
    "---\n"
    "source_url: https://www.kb.cert.org/vuls/id/871675\n"
    "retrieved: 2026-08-31\n"
    "topics: [wpa3, dragonblood, pmf]\n"
    "alert_kinds: [ALERT_TYPE_WPA_DOWNGRADE]\n"
    "citation: CERT/CC VU#871675\n"
    "---\n"
    "# Dragonblood\n"
    "Intro paragraph.\n"
    "\n"
    "## MFP optional\n"
    "The downgrade primitive.\n"
    "\n"
    "## Transition mode\n"
    "PSK beside SAE.\n";

static void test_well_formed_document(void) {
    ri_doc_t d;
    ASSERT_EQ(ri_parse(GOOD, &d), RI_OK);
    ASSERT_STR(d.fm.source_url, "https://www.kb.cert.org/vuls/id/871675");
    ASSERT_STR(d.fm.retrieved, "2026-08-31");
    ASSERT_STR(d.fm.citation, "CERT/CC VU#871675");
    ASSERT_EQ(d.fm.topic_count, 3);
    ASSERT_STR(d.fm.topics[1], "dragonblood");
    ASSERT_EQ(d.fm.alert_kind_count, 1);
    ASSERT_STR(d.fm.alert_kinds[0], "ALERT_TYPE_WPA_DOWNGRADE");
}

static void test_h1_names_the_preamble_section(void) {
    /* A hit in the intro should cite the document, not a section
     * called "(preamble)". */
    ri_doc_t d;
    ri_parse(GOOD, &d);
    ASSERT_EQ(d.section_count, 3);
    ASSERT_STR(d.sections[0].title, "Dragonblood");
    ASSERT(strstr(d.sections[0].body, "Intro paragraph") != NULL);
}

static void test_sections_split_on_h2(void) {
    ri_doc_t d;
    ri_parse(GOOD, &d);
    ASSERT_STR(d.sections[1].title, "MFP optional");
    ASSERT(strstr(d.sections[1].body, "downgrade primitive") != NULL);
    /* And a section must not absorb the next one's text. */
    ASSERT(strstr(d.sections[1].body, "PSK beside SAE") == NULL);
    ASSERT_STR(d.sections[2].title, "Transition mode");
}

static void test_missing_frontmatter_refused(void) {
    /* A README that wandered into the tree. Indexing it produces hits
     * with no provenance. */
    ri_doc_t d;
    ASSERT_EQ(ri_parse("# Just a document\n\nNo fence.\n", &d),
              RI_ERR_NO_FRONTMATTER);
    ASSERT_EQ(d.section_count, 0);
}

static void test_unterminated_frontmatter_refused(void) {
    ri_doc_t d;
    ASSERT_EQ(ri_parse("---\nsource_url: http://x\nretrieved: 2026-01-01\n",
                       &d), RI_ERR_FRONTMATTER);
}

static void test_line_without_colon_refused(void) {
    /* A typo'd key must not vanish silently — for `alert_kinds` that
     * means a document that never surfaces for any detector. */
    ri_doc_t d;
    const char *bad =
        "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
        "alert_kinds ALERT_TYPE_PORT_SCAN\n---\n# T\n";
    ASSERT_EQ(ri_parse(bad, &d), RI_ERR_FRONTMATTER);
}

static void test_required_fields_enforced(void) {
    /* Without a URL and a date a hit says "something backs this" and
     * cannot say what or when. */
    ri_doc_t d;
    ASSERT_EQ(ri_parse("---\nretrieved: 2026-01-01\n---\n# T\n", &d),
              RI_ERR_MISSING_FIELD);
    ASSERT_EQ(ri_parse("---\nsource_url: http://x\n---\n# T\n", &d),
              RI_ERR_MISSING_FIELD);
}

static void test_malformed_list_refused(void) {
    ri_doc_t d;
    const char *nobracket =
        "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
        "topics: wpa3, pmf\n---\n# T\n";
    ASSERT_EQ(ri_parse(nobracket, &d), RI_ERR_FRONTMATTER);
    const char *unclosed =
        "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
        "topics: [wpa3, pmf\n---\n# T\n";
    ASSERT_EQ(ri_parse(unclosed, &d), RI_ERR_FRONTMATTER);
}

static void test_overlong_list_refused_not_truncated(void) {
    /* Refused rather than truncated: a silently dropped alert kind is
     * a document that indexes under fewer detectors than it claims,
     * and nothing downstream would ever report it. */
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
                     "alert_kinds: [");
    for (int i = 0; i < RI_MAX_ALERT_KINDS + 2; i++)
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "%sK%d",
                      i ? "," : "", i);
    snprintf(buf + n, sizeof(buf) - (size_t)n, "]\n---\n# T\n");
    ri_doc_t d;
    ASSERT_EQ(ri_parse(buf, &d), RI_ERR_TOO_MANY);
}

static void test_empty_list_is_legal(void) {
    ri_doc_t d;
    const char *t =
        "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
        "topics: []\nalert_kinds: []\n---\n# T\n";
    ASSERT_EQ(ri_parse(t, &d), RI_OK);
    ASSERT_EQ(d.fm.topic_count, 0);
    ASSERT_EQ(d.fm.alert_kind_count, 0);
}

static void test_unknown_keys_tolerated(void) {
    /* The corpus should survive a document carrying metadata a later
     * slice gives meaning to. */
    ri_doc_t d;
    const char *t =
        "---\nsource_url: http://x\nretrieved: 2026-01-01\n"
        "severity: high\nreviewed_by: someone\n---\n# T\n";
    ASSERT_EQ(ri_parse(t, &d), RI_OK);
}

static void test_comments_and_blanks_inside_frontmatter(void) {
    ri_doc_t d;
    const char *t =
        "---\n# a note\n\nsource_url: http://x\n\nretrieved: 2026-01-01\n---\n# T\n";
    ASSERT_EQ(ri_parse(t, &d), RI_OK);
    ASSERT_STR(d.fm.source_url, "http://x");
}

static void test_crlf_tolerated(void) {
    /* A document edited on Windows must not be silently unparseable. */
    ri_doc_t d;
    const char *t =
        "---\r\nsource_url: http://x\r\nretrieved: 2026-01-01\r\n---\r\n# T\r\n";
    ASSERT_EQ(ri_parse(t, &d), RI_OK);
    ASSERT_STR(d.fm.source_url, "http://x");
    ASSERT_STR(d.fm.retrieved, "2026-01-01");
}

static void test_section_overflow_is_flagged(void) {
    char buf[8192];
    int n = snprintf(buf, sizeof(buf),
                     "---\nsource_url: http://x\nretrieved: 2026-01-01\n---\n# T\n");
    for (int i = 0; i < RI_MAX_SECTIONS + 5; i++)
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "## S%d\nbody\n", i);
    ri_doc_t d;
    ASSERT_EQ(ri_parse(buf, &d), RI_OK);
    ASSERT_EQ(d.section_count, RI_MAX_SECTIONS);
    ASSERT_EQ(d.sections_truncated, 1);
}

static void test_output_zeroed_on_failure(void) {
    /* A failed parse must leave nothing behind — a half-populated doc
     * reaching the indexer is how a row gets the wrong provenance. */
    ri_doc_t d;
    memset(&d, 0xff, sizeof(d));
    ASSERT_EQ(ri_parse("garbage", &d), RI_ERR_NO_FRONTMATTER);
    ASSERT_EQ(d.section_count, 0);
    ASSERT_EQ(d.fm.topic_count, 0);
    ASSERT_EQ((int)d.fm.source_url[0], 0);
}

static void test_null_inputs_are_safe(void) {
    ri_doc_t d;
    ASSERT_EQ(ri_parse(NULL, &d), RI_ERR_NO_FRONTMATTER);
    ASSERT_EQ(ri_parse(GOOD, NULL), RI_ERR_FRONTMATTER);
}

static void test_every_status_has_a_label(void) {
    ASSERT_STR(ri_status_str(RI_OK), "");
    ASSERT(ri_status_str(RI_ERR_NO_FRONTMATTER)[0] != '\0');
    ASSERT(ri_status_str(RI_ERR_FRONTMATTER)[0]    != '\0');
    ASSERT(ri_status_str(RI_ERR_MISSING_FIELD)[0]  != '\0');
    ASSERT(ri_status_str(RI_ERR_TOO_MANY)[0]       != '\0');
}

void run_research_ingest_tests(void) {
    TEST_SUITE("research corpus: well-formed documents (#73)");
    RUN_TEST(test_well_formed_document);
    RUN_TEST(test_h1_names_the_preamble_section);
    RUN_TEST(test_sections_split_on_h2);
    RUN_TEST(test_empty_list_is_legal);
    RUN_TEST(test_unknown_keys_tolerated);
    RUN_TEST(test_comments_and_blanks_inside_frontmatter);
    RUN_TEST(test_crlf_tolerated);

    TEST_SUITE("research corpus: refusal over half-acceptance (#73)");
    RUN_TEST(test_missing_frontmatter_refused);
    RUN_TEST(test_unterminated_frontmatter_refused);
    RUN_TEST(test_line_without_colon_refused);
    RUN_TEST(test_required_fields_enforced);
    RUN_TEST(test_malformed_list_refused);
    RUN_TEST(test_overlong_list_refused_not_truncated);
    RUN_TEST(test_section_overflow_is_flagged);
    RUN_TEST(test_output_zeroed_on_failure);
    RUN_TEST(test_null_inputs_are_safe);
    RUN_TEST(test_every_status_has_a_label);
}
