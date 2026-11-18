#include <ctype.h>
#include <math.h>
#include <string.h>
#include "dga.h"

/* Extract the leftmost label of `qname` (everything before the first
 * dot) into out[0..out_sz-1] in lowercase ASCII. Returns label length
 * (capped at out_sz - 1). */
static int leftmost_label(const char *qname, char *out, int out_sz) {
    if (!qname || !out || out_sz <= 0) {
        if (out && out_sz > 0) out[0] = '\0';
        return 0;
    }
    int n = 0;
    for (int i = 0; qname[i] && qname[i] != '.' && n < out_sz - 1; i++) {
        unsigned char c = (unsigned char)qname[i];
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        out[n++] = (char)c;
    }
    out[n] = '\0';
    return n;
}

/* Shannon entropy in bits per character over s[0..n-1], counting only
 * the 37 characters a DNS label can hold (a-z, 0-9, '-'). */
static double entropy_of(const char *s, int n) {
    /* histogram over the 37 chars we care about (a-z, 0-9, '-') */
    int hist[40] = {0};
    int total = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        int idx;
        if      (c >= 'a' && c <= 'z') idx = c - 'a';
        else if (c >= '0' && c <= '9') idx = 26 + (c - '0');
        else if (c == '-')              idx = 36;
        else                            continue;
        hist[idx]++;
        total++;
    }
    if (total < 1) return 0.0;

    double h = 0.0;
    for (int i = 0; i < 37; i++) {
        if (hist[i] == 0) continue;
        double p = (double)hist[i] / (double)total;
        h -= p * (log(p) / log(2.0));
    }
    return h;
}

double dga_label_entropy(const char *qname) {
    char label[64];
    int n = leftmost_label(qname, label, sizeof(label));
    if (n < 1) return 0.0;
    return entropy_of(label, n);
}

static int is_vowel(char c) {
    /* 'y' counts as a vowel, as it did for the consonant run before
     * #222: it carries the syllable in "rhythm", "myth", "dwyn", and
     * treating it as a consonant turns those into 4-6 character runs. */
    return c == 'a' || c == 'e' || c == 'i' ||
           c == 'o' || c == 'u' || c == 'y';
}

/* Longest run of consecutive consonants (an a-z character that is not
 * a vowel) in s[0..n-1] — DGAs love consonant clusters like "kjxqp".
 * Digits and '-' break a run rather than extending it. */
static int max_consonant_run(const char *s, int n) {
    int cur = 0, best = 0;
    for (int i = 0; i < n; i++) {
        char c = s[i];
        int is_consonant = (c >= 'a' && c <= 'z') && !is_vowel(c);
        if (is_consonant) {
            cur++;
            if (cur > best) best = cur;
        } else {
            cur = 0;
        }
    }
    return best;
}

static int digit_count(const char *s, int n) {
    int k = 0;
    for (int i = 0; i < n; i++)
        if (s[i] >= '0' && s[i] <= '9') k++;
    return k;
}

/* Vowels as a percentage of the alphabetic characters in s[0..n-1],
 * or -1 when there are none to divide by. */
static int vowel_pct(const char *s, int n) {
    int alpha = 0, vowels = 0;
    for (int i = 0; i < n; i++) {
        char c = s[i];
        if (c < 'a' || c > 'z') continue;
        alpha++;
        if (is_vowel(c)) vowels++;
    }
    if (alpha < 1) return -1;
    return vowels * 100 / alpha;
}

/* ── Scoring (#222) ──────────────────────────────────────────────────
 *
 * Before #222 the rule was: label >= 10 characters, then any TWO of
 * {entropy > 3.0 bits/char, consonant run >= 4, >= 30% digits}. None
 * of the three scaled with the label, which broke both ways. The
 * absolute entropy floor is the headline: Shannon entropy over a
 * single short string measures only how little it repeats, so ANY
 * label whose characters are all distinct sits at log2(len) — 3.46 for
 * 11 characters, 3.58 for 12 — and clears 3.0 on length alone. Pair
 * that with a flat `cons >= 4`, which `http`, `https` and `schw` all
 * satisfy, and an ordinary hyphenated service name scored two. The
 * beta site reported 538 fires / 8 incidents in 24 h on
 * `http-intake.logs.us5.datadoghq.com`, and `bootstrapcdn` was a
 * second instance of the same shape; meanwhile `x7kq2mzp9vbd`, which
 * has no linguistic structure at all, scored one and was missed.
 *
 * The replacement is a weighted score over five signals, every one of
 * them either length-relative or tiered, evaluated per `-`-separated
 * sub-label. The feature family is the standard lexical set: FANCI
 * (S. Schüppen, D. Teubert, P. Herrmann, U. Meyer, "FANCI:
 * Feature-based Automated NXDomain Classification and Intelligence",
 * 27th USENIX Security Symposium, 2018) scores NXDOMAINs on 21
 * features including #14 Vowel Ratio, #18 Ratio of Consecutive
 * Consonants, #19 Ratio of Consecutive Digits and #21 Entropy — the
 * four used here. FANCI's #20, the n-gram frequency distribution, is
 * the one feature not implemented, and its absence is what the
 * "cannot" note below is about.
 *
 * The weights and cut-offs are not from any paper; they are fitted to
 * the vectors in tests/test_dga.c and to the issue's own measurements,
 * and the arithmetic for each is in the test comments. */

#define DGA_MIN_LABEL_LEN  10   /* shorter sub-labels are too noisy  */
#define DGA_LONG_LABEL_LEN 14   /* "longer than a hostname needs"    */
#define DGA_ENTROPY_PCT    95   /* of log2(len), i.e. near-no repeats */
#define DGA_DIGIT_PCT      25   /* 3 digits in 12 is already odd      */
#define DGA_VOWEL_PCT      15   /* a-z random expects ~23% (6/26)     */
#define DGA_FIRE_SCORE      3

/* No single signal is worth more than 2, and the bar is 3, so at least
 * two of the five must agree before anything fires. That is the one
 * precision property carried over unchanged from the pre-#222 rule's
 * "any TWO of three", and it is why the weights stop at 2. */

static int sublabel_score(const char *s, int n) {
    int score = 0;

    /* Entropy, relative to the most a label of this length could have.
     * log2(len) is the ceiling (every character distinct), so the
     * ratio asks "how close to no repeats at all", which is what the
     * absolute 3.0 was accidentally asking at len >= 10. Worth 1: on
     * its own it is the weakest of the five, because real words of
     * 10-13 distinct characters (schwarzkopf, stackoverflow) sit at
     * the top of the range too. */
    double h   = entropy_of(s, n);
    double cap = log((double)n) / log(2.0);
    if (cap > 0.0 && h * 100.0 > (double)DGA_ENTROPY_PCT * cap) score += 1;

    /* Consonant run, tiered rather than flat. A run of 4 is ordinary
     * English and ordinary web vocabulary — "schw", "ngth", "http" —
     * so it is worth 1 where the old rule gave it the same weight as
     * everything else; 5 and over is worth 2. It does not rise beyond
     * 2: acronym-formed labels reach 6 and 7 honestly ("sfdcstatic" is
     * 6, "lengthscheck" 7), so a long run alone must never fire. */
    int cons = max_consonant_run(s, n);
    if      (cons >= 5) score += 2;
    else if (cons == 4) score += 1;

    /* Digit density, 25% rather than 30%: a 12-character label with 3
     * digits (the issue's `x7kq2mzp9vbd`) is already outside how
     * hostnames use digits, which is as a short trailing index. */
    if (digit_count(s, n) * 100 / n >= DGA_DIGIT_PCT) score += 2;

    /* Vowel ratio. This is the signal that separates a real word with
     * all-distinct characters from a random of the same length, which
     * no entropy threshold can do: `schwarzkopf` is 2 vowels in 11
     * letters (18%) and `x7kq2mzp9vbd` is 0 in 9. A uniform draw from
     * a-z expects ~23% (6 of 26 counting 'y'), so 15% is set below the
     * random mean on purpose — it buys precision at the cost of recall
     * and fires only on the vowel-starved tail. */
    int vpct = vowel_pct(s, n);
    if (vpct >= 0 && vpct < DGA_VOWEL_PCT) score += 2;

    /* Length. Generated names run longer than a name a human picked
     * and has to type (research/mitre/T1071-004.md: "more entropy and
     * length than a hostname needs"). Worth 1, so it can corroborate
     * but never decide. */
    if (n >= DGA_LONG_LABEL_LEN) score += 1;

    return score;
}

/* What this does NOT catch, stated so the next reader does not assume
 * it: a random label with an ordinary vowel ratio and no digits. The
 * published CryptoLocker label `rankhydwgovdetm` (15 letters, 4
 * vowels, longest consonant run 3) scores 2 and is missed — it was
 * missed before #222 too. Separating that from a German or Slavic
 * proper noun needs FANCI's #20, an n-gram model over a benign-domain
 * corpus, which this detector has no corpus for. Conficker is out of
 * reach for a different and older reason: .A/.B generate 8-11
 * character names and .C generates 4-9 (Honeynet Project, Werner &
 * Leder, "Know Your Enemy: Containing Conficker", 2009-03-30), so
 * everything below DGA_MIN_LABEL_LEN never reaches the score at all. */
int dga_is_suspicious(const char *qname) {
    if (!qname || !qname[0]) return 0;

    char label[64];
    int len = leftmost_label(qname, label, sizeof(label));
    if (len < DGA_MIN_LABEL_LEN) return 0;

    /* Score each `-`-separated piece on its own. A hyphenated label is
     * how humans name things — `http-intake`, `browser-intake`,
     * `update-https` — and each piece is then a word-sized token too
     * short to score, where the concatenation looked like one long
     * random blob. A generated label is a single blob, so for any
     * label without a hyphen this is exactly the whole label and the
     * split changes nothing. */
    int start = 0;
    for (int i = 0; i <= len; i++) {
        if (i < len && label[i] != '-') continue;
        int n = i - start;
        if (n >= DGA_MIN_LABEL_LEN &&
            sublabel_score(&label[start], n) >= DGA_FIRE_SCORE)
            return 1;
        start = i + 1;
    }
    return 0;
}
