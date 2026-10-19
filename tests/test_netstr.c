#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "netstr.h"
#include "tui.h"

/* The render/ingest choke point (#138). Inputs are literal octets and
 * the expected strings are literals: nothing here is produced by the
 * code under test. UTF-8 per RFC 3629 §4; the C1 range and the bidi
 * controls per Unicode (U+009B is CSI, which a VT100-class terminal
 * acts on exactly as it does ESC '['). */

static void sanitized(const char *in, char *out, size_t n) {
    snprintf(out, n, "%s", in);
    display_sanitize(out);
}

/* ── display_sanitize ─────────────────────────────────────── */

static void test_display_sanitize_replaces_esc(void) {
    char b[64];
    sanitized("a\x1b[2Jb", b, sizeof b);
    ASSERT_STR(b, "a?[2Jb");
    ASSERT(strchr(b, 0x1b) == NULL);
}

/* Mutation-proved: skipping the C1 test in netstr_is_display_control()
 * (`cp >= 0x80 && cp <= 0x9f` → `0`) leaves "\xc2\x9b" intact and
 * reddens both assertions below. */
static void test_display_sanitize_replaces_utf8_c1_csi(void) {
    char b[64];
    sanitized("x\xc2\x9b" "2Jy", b, sizeof b);
    ASSERT_STR(b, "x?2Jy");
    sanitized("\xc2\x80\xc2\x9f", b, sizeof b);
    ASSERT_STR(b, "??");
}

/* U+00A0 is the first code point past C1 and is ordinary text. */
static void test_display_sanitize_keeps_first_code_point_after_c1(void) {
    char b[64];
    sanitized("a\xc2\xa0z", b, sizeof b);
    ASSERT_STR(b, "a\xc2\xa0z");
}

static void test_display_sanitize_invalid_octets_each_become_one_mark(void) {
    char b[64];
    sanitized("a\x80z", b, sizeof b);          /* lone continuation */
    ASSERT_STR(b, "a?z");
    sanitized("a\xc0\xafz", b, sizeof b);      /* overlong '/' */
    ASSERT_STR(b, "a??z");
    sanitized("a\xed\xa0\x80z", b, sizeof b);  /* surrogate U+D800 */
    ASSERT_STR(b, "a???z");
    sanitized("a\xe2\x82", b, sizeof b);       /* truncated at the end */
    ASSERT_STR(b, "a??");
    sanitized("\xff\xfe", b, sizeof b);
    ASSERT_STR(b, "??");
}

static void test_display_sanitize_replaces_bidi_controls(void) {
    char b[64];
    sanitized("abc\xe2\x80\xae" "fdp.exe", b, sizeof b);   /* RLO U+202E */
    ASSERT_STR(b, "abc?fdp.exe");
    sanitized("\xe2\x81\xa6x\xe2\x81\xa9", b, sizeof b);   /* LRI .. PDI */
    ASSERT_STR(b, "?x?");
    sanitized("\xe2\x80\xa9", b, sizeof b);                /* U+2029: text */
    ASSERT_STR(b, "\xe2\x80\xa9");
}

static void test_display_sanitize_replaces_tab_cr_bs_del(void) {
    char b[64];
    sanitized("a\tb\rc\bd\x7f" "e", b, sizeof b);
    ASSERT_STR(b, "a?b?c?d?e");
}

static void test_display_sanitize_keeps_newline_and_valid_utf8(void) {
    char b[64];
    const char *in = "caf\xc3\xa9 \xe2\x94\x80 \xf0\x9f\x90\xa2\n";
    sanitized(in, b, sizeof b);
    ASSERT_STR(b, in);
    ASSERT_EQ((int)display_sanitize(b), 0);
}

static void test_display_sanitize_counts_substitutions(void) {
    char b[] = "\x1b\xc2\x9b\xff";
    ASSERT_EQ((int)display_sanitize(b), 3);
    ASSERT_STR(b, "???");
}

/* ── netstr_utf8_decode ───────────────────────────────────── */

static void test_utf8_decode_boundaries(void) {
    uint32_t cp = 0;
    ASSERT_EQ(netstr_utf8_decode((const uint8_t *)"\xf4\x8f\xbf\xbf", 4, &cp), 4);
    ASSERT_EQ((long)cp, 0x10ffffL);
    ASSERT_EQ(netstr_utf8_decode((const uint8_t *)"\xf4\x90\x80\x80", 4, &cp), 0);
    ASSERT_EQ(netstr_utf8_decode((const uint8_t *)"\xe0\x9f\xbf", 3, &cp), 0);
    ASSERT_EQ(netstr_utf8_decode((const uint8_t *)"\xe0\xa0\x80", 3, &cp), 3);
    ASSERT_EQ((long)cp, 0x800L);
    ASSERT_EQ(netstr_utf8_decode((const uint8_t *)"\xc3\xa9", 1, &cp), 0);
    ASSERT_EQ(netstr_utf8_decode(NULL, 0, &cp), 0);
}

/* ── netstr_copy ──────────────────────────────────────────── */

/* Mutation-proved: replacing the mapping in netstr_copy() with a plain
 * octet copy leaves '\n' and DEL in place and reddens the first
 * assertion. */
static void test_netstr_copy_maps_c0_and_del(void) {
    char d[16];
    static const uint8_t in[] = { 'x', 0x0a, 'y', 0x7f };
    ASSERT_EQ((int)netstr_copy(d, sizeof d, in, sizeof in), 4);
    ASSERT_STR(d, "x?y?");
}

/* An SSID is an opaque octet string: high octets are kept so it still
 * compares equal to the same SSID typed into --my-ssid or the baseline. */
static void test_netstr_copy_keeps_high_octets(void) {
    char d[16];
    static const uint8_t in[] = { 0xff, 0xc2, 0x9b, 'A' };
    netstr_copy(d, sizeof d, in, sizeof in);
    ASSERT_EQ(memcmp(d, in, sizeof in), 0);
    ASSERT_EQ(d[4], '\0');
}

static void test_netstr_copy_stops_at_nul_and_bounds(void) {
    char d[4];
    static const uint8_t hidden[] = { 0, 0, 0 };
    ASSERT_EQ((int)netstr_copy(d, sizeof d, hidden, sizeof hidden), 0);
    ASSERT_STR(d, "");
    ASSERT_EQ((int)netstr_copy(d, sizeof d, (const uint8_t *)"abcdef", 6), 3);
    ASSERT_STR(d, "abc");
    d[0] = 'Z';
    ASSERT_EQ((int)netstr_copy(d, 0, (const uint8_t *)"abc", 3), 0);
    ASSERT_EQ(d[0], 'Z');
}

static void test_netstr_scrub_in_place(void) {
    char s[] = "a\rb\x1b" "c\xc3\xa9";
    netstr_scrub(s);
    ASSERT_STR(s, "a?b?c\xc3\xa9");
}

/* ── render: both backends ────────────────────────────────── */

/* The ANSI sink. The test binary is built WITH_NCURSES, so the ANSI
 * t_puts() is not in it; tui_fputs_sanitized() is the function that
 * t_puts / t_putn / tui_printf call in the ANSI build, compiled in both.
 * Mutation-proved: fputs() of the caller's string instead of the
 * sanitised copy reddens both assertions; so does dropping the C1 test
 * from netstr_is_display_control(), through the "\xc2\x9b". */
static void test_ansi_sink_writes_no_escape(void) {
    int fds[2];
    ASSERT_EQ(pipe(fds), 0);
    FILE *w = fdopen(fds[1], "w");
    ASSERT(w != NULL);
    if (!w) { close(fds[0]); close(fds[1]); return; }
    tui_fputs_sanitized(w, "a\x1b[2Jb\xc2\x9b" "c", -1);
    tui_fputs_sanitized(w, "|de\x07zzz", 4);       /* n bounds the copy */
    fclose(w);
    char got[64] = "";
    ssize_t n = read(fds[0], got, sizeof got - 1);
    close(fds[0]);
    ASSERT(n > 0);
    if (n > 0) got[n] = '\0';
    ASSERT(memchr(got, 0x1b, sizeof got) == NULL);
    ASSERT_STR(got, "a?[2Jb?c|de?");
}

/* The ncurses backend, read back from the offscreen screen. Without the
 * sanitiser ncurses draws ESC as "^[" and acts on '\r' — it returns the
 * cursor to column 0 and the tail overwrites the row's start, which is
 * the row-spoofing shape. Mutation-proved: t_emit() calling addstr(s)
 * directly reddens both line assertions. */
static void test_tui_printf_sanitizes_on_screen(void) {
    tui_test_erase();
    tui_printf("%s", "row\x1b[2Jspoof\rX");
    ASSERT_LINE_HAS(0, "row?[2Jspoof?X");
    tui_test_erase();
    tui_addstr("ssid\bZ");
    ASSERT_LINE_HAS(0, "ssid?Z");
}

/* A formatted row longer than the stack buffer is emitted whole. */
static void test_tui_printf_long_row_is_not_cut(void) {
    char big[1500];
    memset(big, 'q', sizeof big - 2);
    big[sizeof big - 2] = 'E';
    big[sizeof big - 1] = '\0';
    tui_test_erase();
    tui_printf("%s", big);
    char screen[8192];
    ASSERT(tui_test_screen(screen, sizeof screen) > 0);
    ASSERT(strchr(screen, 'E') != NULL);
}

void run_netstr_tests(void) {
    TEST_SUITE("netstr — render/ingest sanitisation choke point (#138)");
    RUN_TEST(test_display_sanitize_replaces_esc);
    RUN_TEST(test_display_sanitize_replaces_utf8_c1_csi);
    RUN_TEST(test_display_sanitize_keeps_first_code_point_after_c1);
    RUN_TEST(test_display_sanitize_invalid_octets_each_become_one_mark);
    RUN_TEST(test_display_sanitize_replaces_bidi_controls);
    RUN_TEST(test_display_sanitize_replaces_tab_cr_bs_del);
    RUN_TEST(test_display_sanitize_keeps_newline_and_valid_utf8);
    RUN_TEST(test_display_sanitize_counts_substitutions);
    RUN_TEST(test_utf8_decode_boundaries);
    RUN_TEST(test_netstr_copy_maps_c0_and_del);
    RUN_TEST(test_netstr_copy_keeps_high_octets);
    RUN_TEST(test_netstr_copy_stops_at_nul_and_bounds);
    RUN_TEST(test_netstr_scrub_in_place);
    RUN_TEST(test_ansi_sink_writes_no_escape);
    RUN_TEST(test_tui_printf_sanitizes_on_screen);
    RUN_TEST(test_tui_printf_long_row_is_not_cut);
}
