/* The stream decoder (web_jsonl.c) on hand-written lines: the shapes
 * sloth writes (docs/wiki/jsonl-schema.md), and the truncated, invalid
 * and hostile ones a socket can deliver instead. RFC 8259 for the
 * grammar, RFC 3629 for UTF-8. */
#include <stdlib.h>
#include <string.h>

#include "web_jsonl.h"
#include "wtest.h"

static web_jrec_t g_rec;   /* ~25 KB: not on the stack */

static int parse(const char *s) { return web_jl_parse(s, strlen(s), &g_rec); }
#define PARSEN(lit) web_jl_parse((lit), sizeof(lit) - 1, &g_rec)

static void test_sloth_shapes(void) {
    WT_EQ(parse("{\"type\":\"dns\",\"ts\":1700000000,\"src\":\"192.168.1.5\","
                "\"qname\":\"example.com\",\"qtype\":\"A\","
                "\"answer\":\"93.184.216.34\",\"is_resp\":1}"), WEB_JL_OK);
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "type"), "dns"));
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "qname"), "example.com"));
    WT_EQ(web_jl_int(&g_rec, "ts", 0), 1700000000LL);
    WT_EQ(web_jl_int(&g_rec, "is_resp", 0), 1);
    WT_EQ(g_rec.n, 7);
    WT_ASSERT(web_jl_str(&g_rec, "missing") == NULL);
    WT_EQ(web_jl_int(&g_rec, "qname", -5), -5);   /* a string is not an int */

    /* Nested members are checked and skipped; booleans, null, reals. */
    WT_EQ(parse("{\"type\":\"seqnum_client\",\"ts\":1,\"hist\":[1,2,[3,{\"a\":4}]],"
                "\"validated\":false,\"x\":null,\"rx_rate\":12.5e3}\n"), WEB_JL_OK);
    WT_EQ(web_jl_get(&g_rec, "hist")->kind, WEB_J_NEST);
    WT_EQ(web_jl_get(&g_rec, "validated")->kind, WEB_J_BOOL);
    WT_EQ(web_jl_int(&g_rec, "validated", 7), 0);
    WT_EQ(web_jl_get(&g_rec, "x")->kind, WEB_J_NULL);
    WT_EQ(web_jl_get(&g_rec, "rx_rate")->kind, WEB_J_REAL);

    /* sloth's escapes decode to the bytes they name. */
    WT_EQ(parse("{\"type\":\"beacon\",\"ssid\":\"a\\\"b\\\\c\\/d\\n\\u00e9\\ud83e\\udda5\"}"),
          WEB_JL_OK);
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "ssid"),
                      "a\"b\\c/d\n\xc3\xa9\xf0\x9f\xa6\xa5"));
    WT_EQ(web_jl_get(&g_rec, "ssid")->slen, 14);
    /* Raw UTF-8 is kept as is. */
    WT_EQ(parse("{\"type\":\"device\",\"hostname\":\"caf\xc3\xa9\"}"), WEB_JL_OK);
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "hostname"), "caf\xc3\xa9"));
    /* Whitespace anywhere the grammar allows, and a trailing CR. */
    WT_EQ(parse(" { \"type\" : \"x\" , \"ts\" : -3 } \r"), WEB_JL_OK);
    WT_EQ(web_jl_int(&g_rec, "ts", 0), -3);
}

/* A hostile value may hold the text of a member; it is still one
 * string, and the record's type is the real member's. */
static void test_member_text_inside_a_string_is_a_string(void) {
    WT_EQ(parse("{\"type\":\"dns\",\"qname\":\"\\\",\\\"type\\\":\\\"device\"}"),
          WEB_JL_OK);
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "type"), "dns"));
    WT_ASSERT(!strcmp(web_jl_str(&g_rec, "qname"), "\",\"type\":\"device"));
}

static void test_truncated_lines(void) {
    static const char *const cut[] = {
        "", "{", "{\"type\"", "{\"type\":", "{\"type\":\"dns",
        "{\"type\":\"dns\"", "{\"type\":\"dns\",", "{\"type\":\"dns\",\"ts\":1",
        "{\"type\":\"dns\",\"ts\":-", "{\"type\":\"dns\",\"a\":[1,2",
        "{\"type\":\"dns\",\"a\":{\"b\":1", "{\"type\":\"d\\u00e",
        "{\"type\":\"d\\", "{\"type\":\"dns\",\"ok\":tru",
    };
    for (size_t i = 0; i < sizeof(cut) / sizeof(cut[0]); i++) {
        int e = parse(cut[i]);
        if (e == WEB_JL_OK) fprintf(stderr, "    accepted: %s\n", cut[i]);
        WT_ASSERT(e != WEB_JL_OK);
    }
}

static void test_syntax_errors(void) {
    static const struct { const char *s; int e; } bad[] = {
        { "[1,2]",                               WEB_JL_ENOTOBJ },
        { "\"type\"",                            WEB_JL_ENOTOBJ },
        { "{\"type\":\"a\"} x",                  WEB_JL_ESYNTAX },
        { "{\"type\":\"a\"}{\"type\":\"b\"}",    WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",}",                   WEB_JL_ESYNTAX },
        { "{\"type\":'a'}",                      WEB_JL_ESYNTAX },
        { "{type:\"a\"}",                        WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":01}",           WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":1.}",           WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":.5}",           WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":1e}",           WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":+1}",           WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"n\":NaN}",          WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"s\":\"\\x41\"}",    WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"s\":\"\\u12G4\"}",  WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"s\":\"tab\there\"}", WEB_JL_ESYNTAX },
        { "{\"type\":\"a\",\"s\":[1 2]}",        WEB_JL_ESYNTAX },
        { "{\"ts\":1}",                          WEB_JL_ETYPE },
        { "{\"type\":1}",                        WEB_JL_ETYPE },
        { "{\"type\":null}",                     WEB_JL_ETYPE },
        { "{}",                                  WEB_JL_ETYPE },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        int e = parse(bad[i].s);
        if (e != bad[i].e)
            fprintf(stderr, "    %s: %s, want %s\n", bad[i].s,
                    web_jl_error_name(e), web_jl_error_name(bad[i].e));
        WT_EQ(e, bad[i].e);
    }
}

/* RFC 3629 §3/§4 and RFC 8259 §8.2. Seen red (accepted) with the
 * web_utf8_seq() check in string() replaced by a one-byte copy. */
static void test_invalid_utf8_refused(void) {
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\x80\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xc0\xaf\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xe0\x80\xaf\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xed\xa0\x80\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xf4\x90\x80\x80\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xf5\x80\x80\x80\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xe2\x82\"}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"hostname\":\"\xff\"}"), WEB_JL_EUTF8);
    /* In a member name and inside a nested value too. */
    WT_EQ(PARSEN("{\"type\":\"device\",\"\xff\":1}"), WEB_JL_EUTF8);
    WT_EQ(PARSEN("{\"type\":\"device\",\"a\":[\"\xff\"]}"), WEB_JL_EUTF8);
    /* Escaped: lone surrogates either way round, a high half followed
     * by something else, and NUL. */
    WT_EQ(parse("{\"type\":\"d\",\"s\":\"\\udc00\"}"), WEB_JL_EUTF8);
    WT_EQ(parse("{\"type\":\"d\",\"s\":\"\\ud800\"}"), WEB_JL_EUTF8);
    WT_EQ(parse("{\"type\":\"d\",\"s\":\"\\ud800x\"}"), WEB_JL_EUTF8);
    WT_EQ(parse("{\"type\":\"d\",\"s\":\"\\ud800\\u0041\"}"), WEB_JL_EUTF8);
    WT_EQ(parse("{\"type\":\"d\",\"s\":\"a\\u0000b\"}"), WEB_JL_EUTF8);
}

/* Which "type" wins is what a hostile line would choose. Seen red
 * (WEB_JL_OK) with the duplicate scan removed from web_jl_parse(). */
static void test_duplicate_member_refused(void) {
    WT_EQ(parse("{\"type\":\"dns\",\"type\":\"device\"}"), WEB_JL_EDUP);
    WT_EQ(parse("{\"type\":\"dns\",\"a\":1,\"a\":2}"), WEB_JL_EDUP);
    /* Nested objects are not the record's members. */
    WT_EQ(parse("{\"type\":\"dns\",\"a\":{\"type\":1,\"type\":2}}"), WEB_JL_OK);
}

static void test_caps(void) {
    /* Depth: WEB_JL_MAX_DEPTH levels including the record, then one
     * more. */
    char deep[256];
    for (int extra = 0; extra < 2; extra++) {
        int lv = WEB_JL_MAX_DEPTH - 1 + extra;
        size_t n = (size_t)snprintf(deep, sizeof(deep), "{\"type\":\"a\",\"x\":");
        for (int i = 0; i < lv; i++) deep[n++] = '[';
        for (int i = 0; i < lv; i++) deep[n++] = ']';
        deep[n++] = '}';
        deep[n] = '\0';
        WT_EQ(parse(deep), extra ? WEB_JL_EDEPTH : WEB_JL_OK);
    }

    /* Members: the cap, then one more. */
    size_t cap = 16 * (WEB_JL_MAX_FIELDS + 2);
    char *s = malloc(cap);
    for (int extra = 0; extra < 2 && s; extra++) {
        size_t n = (size_t)snprintf(s, cap, "{\"type\":\"a\"");
        for (int i = 1; i < WEB_JL_MAX_FIELDS + extra; i++)
            n += (size_t)snprintf(s + n, cap - n, ",\"k%d\":%d", i, i);
        snprintf(s + n, cap - n, "}");
        WT_EQ(parse(s), extra ? WEB_JL_EFIELDS : WEB_JL_OK);
    }
    free(s);

    /* Integers: the range edges, and one past them is a real. */
    WT_EQ(parse("{\"type\":\"a\",\"m\":9223372036854775807,"
                "\"n\":-9223372036854775808,\"o\":9223372036854775808,\"z\":-0}"),
          WEB_JL_OK);
    WT_EQ(web_jl_int(&g_rec, "m", 0), 9223372036854775807LL);
    WT_EQ(web_jl_int(&g_rec, "n", 0), -9223372036854775807LL - 1);
    WT_EQ(web_jl_get(&g_rec, "o")->kind, WEB_J_REAL);
    WT_EQ(web_jl_int(&g_rec, "z", 1), 0);

    /* A line over the limit is refused before a byte is looked at. */
    WT_EQ(web_jl_parse("{}", WEB_JL_MAX_LINE + 1, &g_rec), WEB_JL_ELONG);
}

void run_jsonl_tests(void) {
    WT_RUN(test_sloth_shapes);
    WT_RUN(test_member_text_inside_a_string_is_a_string);
    WT_RUN(test_truncated_lines);
    WT_RUN(test_syntax_errors);
    WT_RUN(test_invalid_utf8_refused);
    WT_RUN(test_duplicate_member_refused);
    WT_RUN(test_caps);
}
