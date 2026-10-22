/* The JSON writer's escaping (web_json.c), byte for byte. Every string
 * slothweb sends that came off the data socket passes through
 * web_jw_str(), so this is where "a hostname with markup in it renders
 * as text" starts. */
#include <string.h>

#include "web_json.h"
#include "wtest.h"

static const char *esc(const char *in, size_t n) {
    static char out[1024];
    web_jw_t w;
    web_jw_init(&w, out, sizeof(out));
    web_jw_strn(&w, in, n);
    return w.overflow ? "(overflow)" : out;
}

#define ESC(lit) esc((lit), sizeof(lit) - 1)

/* RFC 8259 §7 plus the HTML-inert set. Seen red ("<img" passed through)
 * with '<' and '>' removed from the escape condition in web_jw_strn(). */
static void test_markup_is_escaped(void) {
    const char *o = ESC("<img src=x onerror=alert(1)>");
    WT_ASSERT(!strcmp(o, "\"\\u003cimg src=x onerror=alert(1)\\u003e\""));
    WT_LACKS(o, "<");
    WT_LACKS(o, ">");
    WT_ASSERT(!strcmp(ESC("</script>"), "\"\\u003c/script\\u003e\""));
    WT_ASSERT(!strcmp(ESC("a&b'c"), "\"a\\u0026b\\u0027c\""));
    WT_ASSERT(!strcmp(ESC("\"\\"), "\"\\\"\\\\\""));
}

static void test_controls_and_line_ends(void) {
    WT_ASSERT(!strcmp(ESC("a\nb\rc\td"), "\"a\\nb\\rc\\td\""));
    WT_ASSERT(!strcmp(ESC("\x01\x1f\x7f"), "\"\\u0001\\u001f\\u007f\""));
    /* C1 as UTF-8 (U+009B is CSI), and the two JavaScript line ends. */
    WT_ASSERT(!strcmp(ESC("\xc2\x9b"), "\"\\u009b\""));
    WT_ASSERT(!strcmp(ESC("\xe2\x80\xa8\xe2\x80\xa9"), "\"\\u2028\\u2029\""));
    /* The escaped form never holds a raw CR or LF, so an SSE data line
     * built from it is one line. */
    WT_LACKS(ESC("x\ny\rz"), "\n");
    WT_LACKS(ESC("x\ny\rz"), "\r");
}

static void test_utf8_kept_and_invalid_replaced(void) {
    /* Valid multibyte text passes as itself. */
    WT_ASSERT(!strcmp(ESC("caf\xc3\xa9 \xf0\x9f\xa6\xa5"),
                      "\"caf\xc3\xa9 \xf0\x9f\xa6\xa5\""));
    /* Each ill-formed byte is one U+FFFD: a stray continuation, an
     * overlong NUL, a surrogate, a cut sequence, F5. */
    WT_ASSERT(!strcmp(ESC("\x80"), "\"\\ufffd\""));
    WT_ASSERT(!strcmp(ESC("\xc0\x80"), "\"\\ufffd\\ufffd\""));
    WT_ASSERT(!strcmp(ESC("\xed\xa0\x80"), "\"\\ufffd\\ufffd\\ufffd\""));
    WT_ASSERT(!strcmp(ESC("\xe2\x82"), "\"\\ufffd\\ufffd\""));
    WT_ASSERT(!strcmp(ESC("\xf5"), "\"\\ufffd\""));
}

static void test_overflow_is_sticky(void) {
    char b[8];
    web_jw_t w;
    web_jw_init(&w, b, sizeof(b));
    web_jw_str(&w, "<<<<");    /* 2 + 4 * 6 bytes: does not fit */
    WT_EQ(w.overflow, 1);
    web_jw_raw(&w, "x");
    WT_EQ(w.overflow, 1);
    web_jw_init(&w, b, sizeof(b));
    web_jw_int(&w, -42);
    WT_EQ(w.overflow, 0);
    WT_ASSERT(!strcmp(b, "-42"));
}

static void test_utf8_copy_cuts_on_a_boundary(void) {
    char out[8];
    /* "ab" then a three-byte euro sign; a cut at 4 would split it. */
    web_utf8_copy(out, 4, "ab\xe2\x82\xac");
    WT_ASSERT(!strcmp(out, "ab"));
    web_utf8_copy(out, 5, "ab\xe2\x82\xac");
    WT_ASSERT(!strcmp(out, "ab\xe2\x82\xac"));
    web_utf8_copy(out, 3, "abcdef");
    WT_ASSERT(!strcmp(out, "abc"));
    web_utf8_copy(out, 7, "");
    WT_ASSERT(!strcmp(out, ""));
}

static void test_utf8_seq(void) {
    unsigned cp;
    WT_EQ(web_utf8_seq((const unsigned char *)"\xf4\x8f\xbf\xbf", 4, &cp), 4);
    WT_EQ(cp, 0x10FFFF);
    WT_EQ(web_utf8_seq((const unsigned char *)"\xf4\x90\x80\x80", 4, &cp), 0);
    WT_EQ(web_utf8_seq((const unsigned char *)"\xe0\x9f\xbf", 3, &cp), 0);
    WT_EQ(web_utf8_seq((const unsigned char *)"\xc1\xbf", 2, &cp), 0);
    WT_EQ(web_utf8_seq((const unsigned char *)"\xef\xbf\xbd", 3, &cp), 3);
    WT_EQ(cp, 0xFFFD);
    WT_EQ(web_utf8_seq((const unsigned char *)"", 0, &cp), 0);
}

void run_json_tests(void) {
    WT_RUN(test_markup_is_escaped);
    WT_RUN(test_controls_and_line_ends);
    WT_RUN(test_utf8_kept_and_invalid_replaced);
    WT_RUN(test_overflow_is_sticky);
    WT_RUN(test_utf8_copy_cuts_on_a_boundary);
    WT_RUN(test_utf8_seq);
}
