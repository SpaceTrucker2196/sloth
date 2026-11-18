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

/* ── #222: the score has to scale with the label ────────────────────
 *
 * Field data from the beta site (24 h to 2026-11-16 07:00 MST): WARN
 * fired 538 times across 8 incidents on
 * `http-intake.logs.us5.datadoghq.com` — a SaaS log-intake name the
 * sensor host queries itself — while `x7kq2mzp9vbd`, a label of the
 * same length with no linguistic structure at all, did not fire.
 * The pre-#222 rule took any two of {entropy > 3.0, consonant run
 * >= 4, >= 30% digits}, and none of the three scaled with length, so
 * an 11-character label holding `http` and some varied letters scored
 * two while a 12-character random scored one.
 *
 * The replacement is a weighted score over five length-aware signals,
 * evaluated per `-`-separated sub-label; the constants and their
 * basis are in `src/dga.c`. */

/* Hyphenated labels are human naming, not generation: each piece is a
 * word-sized token, and a token too short to analyse cannot carry the
 * score on its own. All three of these fired before #222. */
static void test_dga_hyphenated_service_labels_not_flagged(void) {
    /* The reported false positive: sub-labels "http" (4) and "intake"
     * (6), neither long enough to score. */
    ASSERT_EQ(dga_is_suspicious("http-intake.logs.us5.datadoghq.com"), 0);
    /* "update" (6) + "https" (5): `https` is a 5-consonant run, which
     * is exactly the token the old flat `cons >= 4` rewarded. */
    ASSERT_EQ(dga_is_suspicious("update-https.example.com"),            0);
    /* Named in the issue's table as already clean (score 1 of 3) —
     * asserted so the sub-label split cannot regress it. */
    ASSERT_EQ(dga_is_suspicious("browser-intake.logs.datadoghq.com"),   0);
}

/* A single-token real word with all-distinct characters. This is the
 * case length-normalised entropy cannot fix on its own: `h / log2(len)`
 * is exactly 1.0 for any label whose characters are all distinct, so
 * `schwarzkopf` and `x7kq2mzp9vbd` are indistinguishable by entropy at
 * any threshold and any length. What separates them is vowel structure
 * (2 of 11 vs 0 of 9 letters) and the consonant-run tier (4 vs 3 with
 * 25% digits). */
static void test_dga_wordlike_label_not_flagged(void) {
    ASSERT_EQ(dga_is_suspicious("schwarzkopf.de"), 0);
    /* Same shape, other real labels of 10+ characters that the tiered
     * consonant run and the vowel ratio have to keep clean. */
    ASSERT_EQ(dga_is_suspicious("bootstrapcdn.com"),   0);
    ASSERT_EQ(dga_is_suspicious("cloudfunctions.net"), 0);
    ASSERT_EQ(dga_is_suspicious("safebrowsing.net"),   0);
    ASSERT_EQ(dga_is_suspicious("doubleclick.net"),    0);
}

/* The issue's own missed random, plus a published sample. */
static void test_dga_short_random_labels_flagged(void) {
    /* #222's named false negative: 12 chars, 0 vowels in 9 letters,
     * 25% digits. Scored 1 of 3 before (entropy only). */
    ASSERT_EQ(dga_is_suspicious("x7kq2mzp9vbd.com"), 1);
    /* Observed CryptoLocker C2 label, 2013-11 — 15 lowercase letters,
     * consonant run 5 ("wwrdv"). Source: F. Denis, "Getting prepared
     * for the next Cryptolocker DGA", 2013-11-05,
     * https://00f.net/2013/11/05/cryptolocker-dga — the capture there
     * shows `uqxypfdjiwwrdvi.info` among seven 15-character labels
     * over .info/.com/.net/.biz/.ru/.org/.co.uk, 1000 names a day.
     * This one fired before #222 as well; it is asserted here because
     * raising the consonant bar from 4 to a tier is what could have
     * dropped it. */
    ASSERT_EQ(dga_is_suspicious("uqxypfdjiwwrdvi.info"), 1);
}

/* Real labels of 10+ characters that the pre-#222 rule flagged. Each
 * one fired for the same reason as `http-intake`: all-or-mostly
 * distinct characters put entropy over the flat 3.0, and some
 * ordinary cluster or index digits supplied the second signal. On a
 * 98-label corpus of real DNS labels the old rule fired on 16; this
 * rule fires on 3 (two CloudFront distribution ids and one contrived
 * compound). The ones below are the fixed cases.
 *
 * `cdnjs-cloudflare` and `registry-npmjs` are also the only two
 * vectors in this file that prove the per-sub-label split: both hold a
 * 5-consonant token ("cdnjs", "npmjs") that is under the 10-character
 * floor on its own but supplies a run of 5 to the whole label, which
 * with the length signal reaches 3. Scored whole they fire; scored per
 * sub-label neither piece is long enough to be scored at all. Every
 * other vector here is fixed by the length-aware signals alone. */
static void test_dga_real_labels_that_used_to_fire(void) {
    ASSERT_EQ(dga_is_suspicious("postgresql.example.com"),    0);
    ASSERT_EQ(dga_is_suspicious("subscriptions.example.com"), 0);
    ASSERT_EQ(dga_is_suspicious("cloudflareinsights.com"),    0);
    ASSERT_EQ(dga_is_suspicious("contentsquare.net"),         0);
    ASSERT_EQ(dga_is_suspicious("registry-npmjs.org"),        0);
    ASSERT_EQ(dga_is_suspicious("cdnjs-cloudflare.com"),      0);
    ASSERT_EQ(dga_is_suspicious("smtp-relay.gmail.com"),      0);
    ASSERT_EQ(dga_is_suspicious("appspot-preview.com"),       0);
    /* Host-index labels: the digits are a trailing counter, not
     * payload, and the letters are a word. */
    ASSERT_EQ(dga_is_suspicious("node-00123.example.com"),    0);
    ASSERT_EQ(dga_is_suspicious("vm-prod-0042.example.com"),  0);
}

/* 12-16 character randoms, the length band the issue asks for. These
 * are uniform draws over [a-z], not hand-picked shapes: an LCG seeded
 * 20261117 (constants in the commit message) produced 24 labels of
 * which 14 fire, and these are three of the 14. Measured over 20,000
 * draws the rule detects 59.1% of uniform [a-z] labels of 12-16
 * characters and 72.3% of [a-z0-9] ones, against 83.7% and 76.9% for
 * the pre-#222 rule — the letters-only figure is the recall this
 * change pays for its precision, and it is bought back by volume
 * rather than by name: CryptoLocker computed 1000 names a day, and at
 * 59% per name the chance of missing 20 of them is 0.41^20. */
static void test_dga_random_12_to_16_char_labels_flagged(void) {
    /* "jptopgzkpsldja" — 14 chars: run 9 ("pgzkpsldj") = 2, vowels
     * 2/14 = 14% = 2, length >= 14 = 1. Score 5; h/log2(14) is 0.87
     * and contributes nothing, which is the point — the signal the old
     * rule leaned on hardest is the one that says least here. */
    ASSERT_EQ(dga_is_suspicious("jptopgzkpsldja.com"), 1);
    /* "lhllvsvtphcpt" — 13 chars, no vowels at all: run 13 = 2, vowel
     * ratio 0% = 2. Score 4, with an entropy ratio of only 0.73
     * because the repeats deflate it. */
    ASSERT_EQ(dga_is_suspicious("lhllvsvtphcpt.com"), 1);
    /* "svfxqumzumhfkav" — 15 chars. Run 5 ("svfxq") = 2, length = 1.
     * Score 3 exactly, and the vowel ratio (20%) is above the cut-off,
     * so this is a label caught without the vowel signal at all. */
    ASSERT_EQ(dga_is_suspicious("svfxqumzumhfkav.com"), 1);
}

/* Pins the two constants nothing else isolates.
 *
 * Digit density moved from 30% to 25% because `x7kq2mzp9vbd` is 3 in
 * 12, but that label scores 5 and would still fire at 30%, so it does
 * not prove the move; the move is worth 10 points of recall on
 * [a-z0-9] randoms (72.3% against 62.2% at 30%, same 20,000 draws) and
 * needs a vector that depends on it.
 *
 * "aakjxqell121" — 12 chars, measured: 3 digits = 25% exactly (2),
 * consonant run 4 "kjxq" (1), and nothing else — 33% vowels, entropy
 * ratio 0.86, under 14 long. Score 3, on the nose. Synthetic, built
 * for this boundary: at a 30% digit cut-off it scores 1, and if the
 * `cons == 4` tier is dropped it scores 2. */
static void test_dga_digit_density_twentyfive_percent_with_short_run(void) {
    ASSERT_EQ(dga_is_suspicious("aakjxqell121.com"), 1);
}

/* The gap, pinned rather than described. A random label with an
 * English-like vowel ratio and no digits cannot reach 3:
 * `rankhydwgovdetm` is a published CryptoLocker label (same 2013-11-05
 * capture as the one above) and scores 2 — entropy ratio 0.966 and
 * length >= 14, with a longest run of 3 and 26% vowels. It was
 * missed before #222 as well, so this is a documented limit and not a
 * regression; it is the 41% tail of the recall figure above.
 *
 * Closing it needs what FANCI calls feature #20, an n-gram model over
 * a benign-domain corpus, because the separation from a real word is
 * bigram improbability and nothing cheaper: `rankhydwgovdetm` has 6
 * rare English bigrams of 14 and `schwarzkopf` has 4 of 10, so no
 * vowel, run or entropy threshold can order them. Proposed as a
 * follow-up on #222 rather than done here.
 *
 * If a later change closes this, flip the assertion — do not delete
 * it, and say in the commit which feature earned the flip. */
static void test_dga_vowel_normal_random_is_a_known_miss(void) {
    ASSERT_EQ(dga_is_suspicious("rankhydwgovdetm.co.uk"), 0);
    /* One of the 10 misses from the same 24 uniform draws, one signal
     * short by a different route: 13 chars, run 7 ("mrxlwbg") = 2, but
     * 23% vowels, no digits, h/log2(13) = 0.92 and under 14 long. */
    ASSERT_EQ(dga_is_suspicious("mrxlwbgioemfb.com"), 0);
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
    RUN_TEST(test_dga_hyphenated_service_labels_not_flagged);
    RUN_TEST(test_dga_wordlike_label_not_flagged);
    RUN_TEST(test_dga_short_random_labels_flagged);
    RUN_TEST(test_dga_real_labels_that_used_to_fire);
    RUN_TEST(test_dga_random_12_to_16_char_labels_flagged);
    RUN_TEST(test_dga_digit_density_twentyfive_percent_with_short_run);
    RUN_TEST(test_dga_vowel_normal_random_is_a_known_miss);
}
