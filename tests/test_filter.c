#include "runner.h"
#include "filter.h"

static void test_empty_needle_matches(void) {
    ASSERT(filter_match("",       "anything"));
    ASSERT(filter_match(NULL,     "anything"));
}

static void test_empty_haystack_no_match(void) {
    ASSERT(!filter_match("x", ""));
    ASSERT(!filter_match("x", NULL));
}

static void test_exact_substring(void) {
    ASSERT(filter_match("foo", "foobar"));
    ASSERT(filter_match("bar", "foobar"));
    ASSERT(filter_match("oob", "foobar"));
}

static void test_case_insensitive(void) {
    ASSERT(filter_match("FOO", "fooBAR"));
    ASSERT(filter_match("BaR", "FoObAr"));
}

static void test_no_match(void) {
    ASSERT(!filter_match("baz", "foobar"));
}

static void test_needle_longer_than_haystack(void) {
    ASSERT(!filter_match("foobar", "foo"));
}

/* Kills the line-10 `nlen > hlen` boundary mutation (`>` → `>=`):
 * when needle and haystack are the exact same length and contents,
 * the match must succeed. Under the mutation, equal lengths would
 * return 0 (false) without ever entering the search loop. */
static void test_needle_exact_length_match(void) {
    ASSERT(filter_match("foo", "foo"));
    ASSERT(filter_match("hello",   "hello"));
    ASSERT(filter_match("Mixed",   "MIXED"));  /* + case-insensitive */
}

static void test_match_any_with_nulls(void) {
    /* needle matches second field; first is NULL */
    ASSERT(filter_match_any("foo", NULL, "foobar", NULL, NULL, NULL));
    /* needle matches fifth field */
    ASSERT(filter_match_any("end", "a", "b", "c", "d", "endgame"));
    /* matches nothing */
    ASSERT(!filter_match_any("xyz", "a", "b", "c", "d", "e"));
}

static void test_match_any_empty_needle(void) {
    ASSERT(filter_match_any("",   NULL, NULL, NULL, NULL, NULL));
    ASSERT(filter_match_any(NULL, NULL, NULL, NULL, NULL, NULL));
}

void run_filter_tests(void) {
    TEST_SUITE("filter");
    RUN_TEST(test_empty_needle_matches);
    RUN_TEST(test_empty_haystack_no_match);
    RUN_TEST(test_exact_substring);
    RUN_TEST(test_case_insensitive);
    RUN_TEST(test_no_match);
    RUN_TEST(test_needle_longer_than_haystack);
    RUN_TEST(test_needle_exact_length_match);
    RUN_TEST(test_match_any_with_nulls);
    RUN_TEST(test_match_any_empty_needle);
}
