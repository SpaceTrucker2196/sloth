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

/* Kills `len < 10` boundary mutations (`<` → `<=` and `10 → 11`):
 * a leftmost label of exactly 10 chars must be eligible for analysis. */
static void test_dga_label_exactly_ten_chars_flagged(void) {
    /* "kjxbqzpqvw" — 10 chars, all consonants. entropy log2(10)≈3.32
     * (high_entropy), cluster=10 (long_cluster), digits=0. Two signals
     * trip; flagged. If the length guard moved to <=10 or 11 the label
     * would short-circuit and never see the analysis. */
    ASSERT_EQ(dga_is_suspicious("kjxbqzpqvw.com"), 1);
}

/* Kills `cons >= 4` cluster boundary (`>=` → `>` and `4 → 5`):
 * a label whose only-other signal is dense_digits, with consonant
 * cluster *exactly* 4, must still flag. Constructed so high_entropy
 * stays below 3.0 (kept 'a','1','2' repeated to deflate entropy). */
static void test_dga_consonant_cluster_exactly_four(void) {
    /* "aakjxqe1212" — 11 chars. Walk: aa vowel, kjxq=4 cluster, e vowel,
     * digits reset. cluster=4 exactly. digits=4/11≈36% (dense_digits).
     * 8 distinct chars w/ repeats → entropy ≈ 2.91 (NOT high_entropy).
     * Signals: 0+1+1 = 2  →  flagged. */
    ASSERT_EQ(dga_is_suspicious("aakjxqe1212.com"), 1);
}

/* Kills `digs * 100 / len >= 30` boundary in the `30 -> 31` direction:
 * a label with exactly 30% digits (3/10) must trip dense_digits. */
static void test_dga_digit_density_exactly_thirty_percent(void) {
    /* "abcdefg123" — 10 chars, 3 digits (30% exact). All 10 chars
     * distinct → entropy log2(10)=3.32 (high_entropy). cluster=3
     * ("bcd"; "fg" only 2). Signals: 1+0+1 = 2  →  flagged. If the
     * threshold moved to 31, dense_digits would drop and we'd see
     * hits=1 only. */
    ASSERT_EQ(dga_is_suspicious("abcdefg123.com"), 1);
}

/* Kills the line-17 ASCII case-conversion mutations (`+ 32` arith and
 * `32 -> 31/33` const): an uppercase input must reach the analyser
 * normalised. The 10-char label is the same as the boundary test, so
 * if uppercase normalisation breaks, the label looks like control
 * chars or shifted letters and the consonant/digit detectors miss it. */
static void test_dga_uppercase_label_normalized(void) {
    ASSERT_EQ(dga_is_suspicious("KJXBQZPQVW.COM"), 1);
    /* And entropy must match the lowercase version after normalisation. */
    double h_upper = dga_label_entropy("KJXBQZPQVW.COM");
    double h_lower = dga_label_entropy("kjxbqzpqvw.com");
    /* equal to ~6 digits — float identity is fine here since the input
     * size and histogram are identical post-normalisation. */
    ASSERT(h_upper == h_lower);
    /* Boundary chars A and Z must also be normalised — kills the
     * line-17 `c >= 'A'` and `c <= 'Z'` char-range mutations.
     * "AKJXBQZPQVZ" — leftmost 11 chars, cluster=10, entropy ~3.10
     * post-normalisation; "Akjxbqzpqvz" without normalisation drops
     * 'A' from the entropy histogram, entropy ~2.92, hits=1, NOT flagged. */
    ASSERT_EQ(dga_is_suspicious("AKJXBQZPQVZ.com"), 1);
}

void run_dga_tests(void) {
    TEST_SUITE("dga heuristic");
    RUN_TEST(test_short_label_never_flagged);
    RUN_TEST(test_real_hostnames_not_flagged);
    RUN_TEST(test_known_dga_patterns_flagged);
    RUN_TEST(test_entropy_calculation);
    RUN_TEST(test_leftmost_label_only);
    RUN_TEST(test_dga_label_exactly_ten_chars_flagged);
    RUN_TEST(test_dga_consonant_cluster_exactly_four);
    RUN_TEST(test_dga_digit_density_exactly_thirty_percent);
    RUN_TEST(test_dga_uppercase_label_normalized);
}
