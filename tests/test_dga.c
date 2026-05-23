#include <string.h>
#include "runner.h"
#include "dga.h"

/* The heuristic is intentionally conservative — these tests cover
 * obvious-DGA strings and obvious non-DGA strings; the gray zone is
 * left to operator review. */

static void test_short_label_never_flagged(void) {
    ASSERT_EQ(dga_is_suspicious(""),                0);
    ASSERT_EQ(dga_is_suspicious("a.com"),           0);
    ASSERT_EQ(dga_is_suspicious("abc.example.com"), 0);
    ASSERT_EQ(dga_is_suspicious(NULL),              0);
}

static void test_real_hostnames_not_flagged(void) {
    ASSERT_EQ(dga_is_suspicious("www.example.com"),       0);
    ASSERT_EQ(dga_is_suspicious("github.com"),            0);
    ASSERT_EQ(dga_is_suspicious("amazonaws.com"),         0);
    ASSERT_EQ(dga_is_suspicious("anthropic.com"),         0);
    ASSERT_EQ(dga_is_suspicious("googleusercontent.com"), 0);
    ASSERT_EQ(dga_is_suspicious("stackoverflow.com"),     0);
}

static void test_known_dga_patterns_flagged(void) {
    /* High entropy + consonant clusters — classic Conficker style. */
    ASSERT_EQ(dga_is_suspicious("xbqfkzpqvwj.com"),   1);
    /* Mixed alphanum, long — Cryptolocker style. */
    ASSERT_EQ(dga_is_suspicious("a8x9b2zqp4kvw.net"), 1);
    /* Long consonant cluster + many digits. */
    ASSERT_EQ(dga_is_suspicious("xyzqwrpzkqv9384.io"), 1);
}

static void test_entropy_calculation(void) {
    /* Uniform 26 chars => max entropy 4.7 bits/char approximately. */
    double h = dga_label_entropy("abcdefghijklmnopqrstuvwxyz.com");
    ASSERT(h > 4.5);
    /* Single repeated char => 0 entropy. */
    double h2 = dga_label_entropy("aaaaaaaaaa.com");
    ASSERT_EQ((int)(h2 * 10), 0);
    /* Empty => 0. */
    ASSERT_EQ((int)(dga_label_entropy("") * 10), 0);
}

static void test_leftmost_label_only(void) {
    /* The heuristic considers the leftmost label, so a high-entropy
     * leftmost label still trips even if subdomains look normal. */
    ASSERT_EQ(dga_is_suspicious("xbqfkzpqvwj.example.com"), 1);
    /* Whereas a clean leftmost label with garbage parent stays
     * unflagged (parent isn't inspected). */
    ASSERT_EQ(dga_is_suspicious("login.xbqfkzpqvwj.com"),   0);
}

void run_dga_tests(void) {
    TEST_SUITE("dga heuristic");
    RUN_TEST(test_short_label_never_flagged);
    RUN_TEST(test_real_hostnames_not_flagged);
    RUN_TEST(test_known_dga_patterns_flagged);
    RUN_TEST(test_entropy_calculation);
    RUN_TEST(test_leftmost_label_only);
}
