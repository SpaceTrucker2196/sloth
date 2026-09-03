#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "json.h"
#include "mcp.h"
#include "query.h"

/*
 * MCP transport — issue #73, slice 2.
 *
 * Two layers, tested separately because they fail differently. json.c
 * is a parser and gets the treatment every parser in this tree gets:
 * hand-built input including the truncated, the malformed and the
 * adversarial. mcp.c is a dispatcher and gets asserted on the wire
 * shapes a client actually depends on — that an id round-trips, that a
 * notification draws no reply, that an empty result is a result and not
 * an error.
 *
 * The dispatcher tests run against the committed research.db for the
 * same reason the query tests do: a fixture would test the plumbing and
 * not the corpus. They assert properties, never counts.
 */

/* ── json.c ─────────────────────────────────────────────────────────── */

static void test_parse_flat_object(void) {
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, "{\"a\":\"x\",\"b\":7,\"c\":true,\"d\":null}"), 0);
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "a")), "x");
    ASSERT_NEAR(json_num(&d, json_obj_get(&d, 0, "b"), -1), 7.0, 1e-9);
    ASSERT_EQ(json_obj_get(&d, 0, "missing"), -1);
    /* A present-but-not-a-string member reads as absent, which is what
     * every caller in mcp.c wants: both mean "no usable value here". */
    ASSERT(json_str(&d, json_obj_get(&d, 0, "b")) == NULL);
    ASSERT(json_str(&d, json_obj_get(&d, 0, "d")) == NULL);
}

static void test_parse_nested_object(void) {
    json_doc_t d;
    const char *req = "{\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_cite\",\"arguments\":"
                      "{\"topic\":\"802.11v\"}}}";
    ASSERT_EQ(json_parse(&d, req), 0);
    int p = json_obj_get(&d, 0, "params");
    ASSERT_STR(json_str(&d, json_obj_get(&d, p, "name")), "research_cite");
    int a = json_obj_get(&d, p, "arguments");
    ASSERT_STR(json_str(&d, json_obj_get(&d, a, "topic")), "802.11v");
}

static void test_key_lookup_is_structural_not_textual(void) {
    /* The whole reason this file exists instead of a strstr for
     * "\"name\":". The tool name here is research_cite; a scanner
     * would read `evil` out of the user's own argument. */
    json_doc_t d;
    const char *req = "{\"method\":\"tools/call\",\"params\":"
                      "{\"arguments\":{\"topic\":\"\\\"name\\\":\\\"evil\\\"\"},"
                      "\"name\":\"research_cite\"}}";
    ASSERT_EQ(json_parse(&d, req), 0);
    int p = json_obj_get(&d, 0, "params");
    ASSERT_STR(json_str(&d, json_obj_get(&d, p, "name")), "research_cite");
}

static void test_absent_container_lookup_is_safe(void) {
    /* json_obj_get(d, -1, k) has to work, because the dispatcher chains
     * lookups: params may be absent and arguments looked up inside it. */
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, "{\"method\":\"tools/call\"}"), 0);
    int p = json_obj_get(&d, 0, "params");
    ASSERT_EQ(p, -1);
    ASSERT_EQ(json_obj_get(&d, p, "name"), -1);
    ASSERT(json_str(&d, json_obj_get(&d, p, "name")) == NULL);
    /* A non-object is not a container either. */
    ASSERT_EQ(json_obj_get(&d, json_obj_get(&d, 0, "method"), "x"), -1);
}

static void test_key_lookup_is_exact_not_a_prefix(void) {
    /* A prefix match would find "nameservers" when asked for "name" —
     * and the caller cannot tell, because it gets a plausible string
     * back. The same shape as the FTS5 tokenizer bug on the query side:
     * a near-match that reads as a hit. */
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, "{\"nameservers\":\"x\",\"methodical\":1}"), 0);
    ASSERT_EQ(json_obj_get(&d, 0, "name"), -1);
    ASSERT_EQ(json_obj_get(&d, 0, "method"), -1);
    ASSERT_EQ(json_obj_get(&d, 0, "nameservers"), 1);
}

static void test_escapes_decode(void) {
    json_doc_t d;
    ASSERT_EQ(json_parse(&d,
        "{\"s\":\"a\\\"b\\\\c\\nd\\te\\u0041f\\/g\"}"), 0);
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "s")), "a\"b\\c\nd\teAf/g");
}

static void test_malformed_is_refused(void) {
    /* Refuses rather than half-accepts — the same rule the ingest
     * parser follows. A request parsed to "as much as we could read"
     * gets answered as if it were whole. */
    json_doc_t d;
    static const char *bad[] = {
        "",                       /* nothing */
        "{",                      /* truncated object */
        "{\"a\":}",               /* no value */
        "{\"a\" \"b\"}",          /* no colon */
        "{\"a\":1,}",             /* trailing comma */
        "{a:1}",                  /* unquoted key */
        "{\"a\":\"unterminated",  /* truncated string */
        "{\"a\":tru}",            /* truncated literal */
        "{\"a\":01}",             /* not JSON, and strtod would take it */
        "{\"a\":+1}",             /* strtod accepts this; JSON does not */
        "{\"a\":nan}",            /* likewise */
        "{\"a\":inf}",            /* likewise */
        "{\"a\":1} {\"b\":2}",    /* two values, one line: framing broke */
        "{\"a\":\"\\q\"}",        /* invalid escape */
        "{\"a\":\"\\u00\"}",      /* truncated \u */
        "{\"a\":\"\\uZZZZ\"}",    /* non-hex \u */
        "{\"a\":\"\\u2603\"}",    /* above Latin-1: refused, not mangled */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ASSERT_EQ(json_parse(&d, bad[i]), -1);
}

static void test_raw_control_char_is_refused(void) {
    /* Over a newline-delimited transport a raw newline inside a string
     * means the framing has already gone wrong; accepting it would let
     * one request masquerade as two. */
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, "{\"a\":\"x\ny\"}"), -1);
}

static void test_depth_and_size_caps_refuse(void) {
    char deep[4 * JSON_MAX_DEPTH + 64];
    size_t o = 0;
    deep[o++] = '{'; deep[o++] = '"'; deep[o++] = 'a'; deep[o++] = '"';
    deep[o++] = ':';
    for (int i = 0; i < JSON_MAX_DEPTH + 2; i++) deep[o++] = '[';
    deep[o++] = '1';
    for (int i = 0; i < JSON_MAX_DEPTH + 2; i++) deep[o++] = ']';
    deep[o++] = '}';
    deep[o] = '\0';
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, deep), -1);

    /* Text cap: one string longer than the whole buffer. */
    char *big = malloc(JSON_MAX_TEXT + 64);
    ASSERT(big != NULL);
    if (!big) return;
    memset(big, 'x', JSON_MAX_TEXT + 63);
    big[0] = '{'; big[1] = '"'; big[2] = 'a'; big[3] = '"'; big[4] = ':';
    big[5] = '"';
    big[JSON_MAX_TEXT + 60] = '"';
    big[JSON_MAX_TEXT + 61] = '}';
    big[JSON_MAX_TEXT + 62] = '\0';
    ASSERT_EQ(json_parse(&d, big), -1);
    free(big);
}

static void test_esc_append_round_trips(void) {
    char out[128] = "";
    ASSERT_EQ(json_esc_append(out, sizeof(out), "a\"b\\c\nd\te"), 0);
    ASSERT_STR(out, "\"a\\\"b\\\\c\\nd\\te\"");
    /* What we emit, we must be able to read back. */
    char doc[192];
    snprintf(doc, sizeof(doc), "{\"v\":%s}", out);
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, doc), 0);
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "v")), "a\"b\\c\nd\te");
}

static void test_esc_append_refuses_to_truncate(void) {
    /* Truncated JSON is not a shorter answer, it is an unparseable one,
     * so the escaper reports failure and the caller abandons the
     * response. */
    char out[8] = "";
    ASSERT_EQ(json_esc_append(out, sizeof(out), "aaaaaaaaaaaaaaaa"), -1);
}

static void test_esc_append_escapes_raw_controls(void) {
    char out[64] = "";
    char in[4] = { 'a', 0x01, 'b', 0 };
    ASSERT_EQ(json_esc_append(out, sizeof(out), in), 0);
    ASSERT_STR(out, "\"a\\u0001b\"");
    /* And what it emits parses. A \u escape we cannot read back would
     * make our own output unusable to us. */
    char doc[96];
    snprintf(doc, sizeof(doc), "{\"v\":%s}", out);
    json_doc_t d;
    ASSERT_EQ(json_parse(&d, doc), 0);
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "v")), in);
}

/* ── mcp.c ──────────────────────────────────────────────────────────── */

static char g_out[MCP_OUT_MAX];

static mcp_result_t call(rq_handle_t *rq, const char *req) {
    g_out[0] = '\0';
    return mcp_handle(rq, req, 1788000000, g_out, sizeof(g_out));
}

/* Every response must parse. Asserting on substrings alone would let a
 * malformed message pass as long as it contained the right text. */
static int parsed(json_doc_t *d) { return json_parse(d, g_out) == 0; }

static void test_initialize(void) {
    ASSERT_EQ(call(NULL, "{\"jsonrpc\":\"2.0\",\"id\":1,"
                         "\"method\":\"initialize\",\"params\":{}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (!parsed(&d)) return;
    int r = json_obj_get(&d, 0, "result");
    ASSERT_STR(json_str(&d, json_obj_get(&d, r, "protocolVersion")),
               MCP_PROTOCOL_VERSION);
    int si = json_obj_get(&d, r, "serverInfo");
    ASSERT_STR(json_str(&d, json_obj_get(&d, si, "name")), "sloth-research");
    ASSERT(json_obj_get(&d, json_obj_get(&d, r, "capabilities"),
                        "tools") >= 0);
}

static void test_notification_draws_no_reply(void) {
    /* A JSON-RPC message with no id is a notification and answering it
     * is a protocol violation — the client is not reading. This is how
     * notifications/initialized is handled, and it must hold for any
     * method, since a client may send one at any time. */
    ASSERT_EQ(call(NULL, "{\"jsonrpc\":\"2.0\","
                         "\"method\":\"notifications/initialized\"}"),
              MCP_NO_RESPONSE);
    ASSERT_STR(g_out, "");
    ASSERT_EQ(call(NULL, "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}"),
              MCP_NO_RESPONSE);
}

static void test_id_round_trips_by_type(void) {
    json_doc_t d;

    /* An integral id must not come back as 1.000000: a client pairing
     * responses by string equality would never match it. */
    ASSERT_EQ(call(NULL, "{\"id\":42,\"method\":\"tools/list\"}"), MCP_OK);
    ASSERT(strstr(g_out, "\"id\":42,") != NULL);
    ASSERT(parsed(&d));

    ASSERT_EQ(call(NULL, "{\"id\":\"abc\",\"method\":\"tools/list\"}"), MCP_OK);
    ASSERT(parsed(&d));
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "id")), "abc");

    /* A string id needs escaping like any other string. */
    ASSERT_EQ(call(NULL, "{\"id\":\"a\\\"b\",\"method\":\"tools/list\"}"),
              MCP_OK);
    ASSERT(parsed(&d));
    ASSERT_STR(json_str(&d, json_obj_get(&d, 0, "id")), "a\"b");

    /* At 1e17 the %.17g fallback switches to exponent form and emits
     * "1e+17" — valid JSON, but not the string the client sent, so a
     * client pairing responses by string equality loses the reply.
     * (1e16 is not enough: 17 significant digits still fit.) */
    ASSERT_EQ(call(NULL, "{\"id\":100000000000000000,\"method\":\"tools/list\"}"),
              MCP_OK);
    ASSERT(strstr(g_out, "\"id\":100000000000000000,") != NULL);
    ASSERT(strstr(g_out, "e+") == NULL);

    ASSERT_EQ(call(NULL, "{\"id\":null,\"method\":\"tools/list\"}"), MCP_OK);
    ASSERT(parsed(&d));
    ASSERT(json_obj_get(&d, 0, "result") >= 0);
}

static void test_protocol_errors(void) {
    json_doc_t d;
    struct { const char *req; int code; } cases[] = {
        { "not json",                                       -32700 },
        { "{\"id\":1}",                                     -32600 },
        { "{\"id\":1,\"method\":9}",                        -32600 },
        { "{\"id\":1,\"method\":\"nope\"}",                 -32601 },
        { "{\"id\":1,\"method\":\"tools/call\",\"params\":{}}", -32602 },
        { "{\"id\":1,\"method\":\"tools/call\",\"params\":"
          "{\"name\":\"rm_rf\"}}",                          -32602 },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ASSERT_EQ(call(NULL, cases[i].req), MCP_OK);
        ASSERT(parsed(&d));
        if (!parsed(&d)) continue;
        int e = json_obj_get(&d, 0, "error");
        ASSERT(e >= 0);
        ASSERT_EQ((int)json_num(&d, json_obj_get(&d, e, "code"), 0),
                  cases[i].code);
        ASSERT(json_obj_get(&d, 0, "result") == -1);
    }
}

static void test_unparseable_request_still_answers(void) {
    /* A parse error has no id to echo — the id is inside the message we
     * could not read — so it must be null, not omitted. */
    json_doc_t d;
    ASSERT_EQ(call(NULL, "{\"id\":1,"), MCP_OK);
    ASSERT(parsed(&d));
    ASSERT_EQ(d.nodes[json_obj_get(&d, 0, "id")].type, JSON_NULL);
}

static void test_tools_list_advertises_four(void) {
    ASSERT_EQ(call(NULL, "{\"id\":1,\"method\":\"tools/list\"}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (!parsed(&d)) return;
    int tools = json_obj_get(&d, json_obj_get(&d, 0, "result"), "tools");
    ASSERT(tools >= 0);
    int n = 0;
    for (int i = d.nodes[tools].child; i >= 0; i = d.nodes[i].next) {
        ASSERT(json_str(&d, json_obj_get(&d, i, "name")) != NULL);
        ASSERT(json_str(&d, json_obj_get(&d, i, "description")) != NULL);
        /* A tool with no schema is a tool a model must guess at. */
        ASSERT(json_obj_get(&d, i, "inputSchema") >= 0);
        n++;
    }
    ASSERT_EQ(n, 4);
}

static void test_advertised_tools_are_all_callable(void) {
    /* The list and the dispatcher are written out separately, so
     * nothing but this stops them drifting apart — an advertised tool
     * that answers -32602 is worse than one that was never offered. */
    ASSERT_EQ(call(NULL, "{\"id\":1,\"method\":\"tools/list\"}"), MCP_OK);
    json_doc_t list;
    ASSERT(json_parse(&list, g_out) == 0);
    if (json_parse(&list, g_out) != 0) return;
    int tools = json_obj_get(&list, json_obj_get(&list, 0, "result"), "tools");

    char names[8][RQ_STR];
    int n = 0;
    for (int i = list.nodes[tools].child; i >= 0 && n < 8;
         i = list.nodes[i].next) {
        const char *nm = json_str(&list, json_obj_get(&list, i, "name"));
        if (nm) snprintf(names[n++], RQ_STR, "%s", nm);
    }
    for (int i = 0; i < n; i++) {
        char req[256];
        snprintf(req, sizeof(req),
                 "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                 "{\"name\":\"%s\",\"arguments\":{}}}", names[i]);
        ASSERT_EQ(call(NULL, req), MCP_OK);
        json_doc_t d;
        ASSERT(parsed(&d));
        ASSERT(json_obj_get(&d, 0, "error") == -1);
    }
}

static void test_no_corpus_reports_inside_a_result(void) {
    /* An unavailable corpus is a tool-level failure, not a transport
     * one: the model has to see the reason to act on it. */
    ASSERT_EQ(call(NULL, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                         "{\"name\":\"research_search\","
                         "\"arguments\":{\"query\":\"wpa3\"}}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (!parsed(&d)) return;
    ASSERT(json_obj_get(&d, 0, "error") == -1);
    int r = json_obj_get(&d, 0, "result");
    ASSERT_EQ(d.nodes[json_obj_get(&d, r, "isError")].boolean, 1);
    int c = json_obj_get(&d, r, "content");
    const char *text = json_str(&d, json_obj_get(&d, d.nodes[c].child, "text"));
    ASSERT(text != NULL);
    ASSERT(text && strstr(text, "unavailable") != NULL);
    ASSERT(text && strstr(text, "make research-index") != NULL);
}

static void test_missing_argument_is_a_tool_error(void) {
    ASSERT_EQ(call(NULL, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                         "{\"name\":\"research_for_alert\","
                         "\"arguments\":{}}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (!parsed(&d)) return;
    /* MCP puts tool failures in a successful result with isError so the
     * model can correct itself; only protocol faults become -32xxx. */
    ASSERT(json_obj_get(&d, 0, "error") == -1);
    int r = json_obj_get(&d, 0, "result");
    ASSERT_EQ(d.nodes[json_obj_get(&d, r, "isError")].boolean, 1);
}

/* The corpus-backed half. Skipped rather than failed when research.db
 * is absent, so a tree built before `make research-index` is not red. */
static rq_handle_t *corpus(void) { return rq_open("research.db"); }

static const char *result_text(json_doc_t *d) {
    int r = json_obj_get(d, 0, "result");
    int c = json_obj_get(d, r, "content");
    if (c < 0) return NULL;
    return json_str(d, json_obj_get(d, d->nodes[c].child, "text"));
}

static void test_search_returns_hits_with_provenance(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    ASSERT_EQ(call(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_search\","
                      "\"arguments\":{\"query\":\"dragonblood\"}}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (parsed(&d)) {
        int r = json_obj_get(&d, 0, "result");
        ASSERT_EQ(d.nodes[json_obj_get(&d, r, "isError")].boolean, 0);
        const char *t = result_text(&d);
        ASSERT(t != NULL);
        /* A hit that cannot say where it came from is not a citation. */
        ASSERT(t && strstr(t, "source: ") != NULL);
        ASSERT(t && strstr(t, "retrieved: ") != NULL);
    }
    rq_close(h);
}

static void test_no_match_is_a_result_not_an_error(void) {
    /* Reporting "nothing found" as a tool failure would train a client
     * to retry a query that will never succeed. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    ASSERT_EQ(call(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_for_alert\",\"arguments\":"
                      "{\"alert_kind\":\"ALERT_TYPE_NOT_A_REAL_KIND\"}}}"),
              MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (parsed(&d)) {
        int r = json_obj_get(&d, 0, "result");
        ASSERT_EQ(d.nodes[json_obj_get(&d, r, "isError")].boolean, 0);
        const char *t = result_text(&d);
        ASSERT(t && strstr(t, "No documents") != NULL);
    }
    rq_close(h);
}

static void test_for_alert_is_exact_over_the_wire(void) {
    /* The tokenizer trap from the query layer, asserted at the
     * transport boundary too: a client asking about one alert kind must
     * never be handed documents about a longer one. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    ASSERT_EQ(call(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_for_alert\",\"arguments\":"
                      "{\"alert_kind\":\"ALERT_TYPE\"}}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (parsed(&d)) {
        const char *t = result_text(&d);
        ASSERT(t && strstr(t, "No documents") != NULL);
    }
    rq_close(h);
}

static void test_cite_lists_sources(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    ASSERT_EQ(call(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_cite\","
                      "\"arguments\":{\"topic\":\"wpa3\"}}}"), MCP_OK);
    json_doc_t d;
    ASSERT(parsed(&d));
    if (parsed(&d)) {
        const char *t = result_text(&d);
        ASSERT(t != NULL);
        ASSERT(t && (strstr(t, "- http") != NULL ||
                     strstr(t, "No sources") != NULL));
    }
    rq_close(h);
}

static void test_recent_window_is_honoured(void) {
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    /* A window ending long before the corpus was written must be empty;
     * mcp_handle takes `now` for exactly this reason. */
    g_out[0] = '\0';
    mcp_handle(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                  "{\"name\":\"research_recent\",\"arguments\":{\"days\":1}}}",
               1000000000 /* 2001 */, g_out, sizeof(g_out));
    json_doc_t d;
    ASSERT(parsed(&d));
    if (parsed(&d)) {
        const char *t = result_text(&d);
        ASSERT(t && strstr(t, "No documents") != NULL);
    }
    rq_close(h);
}

static void test_response_never_contains_a_raw_newline(void) {
    /* The transport is newline-delimited, so a raw newline in a
     * response splits one message into two unparseable ones. Document
     * bodies are full of newlines, which makes this the failure the
     * framing is one bad escape away from. */
    rq_handle_t *h = corpus();
    ASSERT(h != NULL);
    if (!h) return;
    ASSERT_EQ(call(h, "{\"id\":1,\"method\":\"tools/call\",\"params\":"
                      "{\"name\":\"research_search\","
                      "\"arguments\":{\"query\":\"wpa3 OR eap OR beacon\"}}}"),
              MCP_OK);
    ASSERT(strchr(g_out, '\n') == NULL);
    ASSERT(strchr(g_out, '\r') == NULL);
    rq_close(h);
}

static void test_tiny_buffer_overflows_rather_than_truncates(void) {
    char small[16];
    mcp_result_t r = mcp_handle(NULL, "{\"id\":1,\"method\":\"tools/list\"}",
                                1788000000, small, sizeof(small));
    ASSERT_EQ(r, MCP_OVERFLOW);
}

static void test_output_is_never_partially_written(void) {
    /* The invariant that matters, asserted independently of where any
     * particular buffer happens to run out: at *every* size, the answer
     * is either MCP_OVERFLOW or a complete, parseable message. A
     * builder that truncated instead of failing would pass a test
     * pinned to one size — it would simply overflow on the next append
     * — and produce half a message whenever the last append was the one
     * that did not fit. */
    static const char *req =
        "{\"id\":7,\"method\":\"tools/call\",\"params\":"
        "{\"name\":\"research_search\",\"arguments\":{\"query\":\"wpa3\"}}}";
    rq_handle_t *h = corpus();
    char buf[MCP_OUT_MAX];
    int seen_ok = 0, seen_over = 0;
    for (size_t cap = 1; cap <= 1200; cap++) {
        buf[0] = '\0';
        mcp_result_t r = mcp_handle(h, req, 1788000000, buf, cap);
        if (r == MCP_OVERFLOW) { seen_over = 1; continue; }
        ASSERT_EQ(r, MCP_OK);
        json_doc_t d;
        ASSERT(json_parse(&d, buf) == 0);
        if (json_parse(&d, buf) != 0) break;   /* one report, not 1200 */
        ASSERT(json_obj_get(&d, 0, "id") >= 0);
        seen_ok = 1;
    }
    /* Both outcomes must actually occur in the swept range, or the
     * sweep proves nothing. */
    ASSERT(seen_over == 1);
    ASSERT(seen_ok == 1);
    rq_close(h);
}

void run_research_mcp_tests(void);
void run_research_mcp_tests(void) {
    TEST_SUITE("research mcp: json reader (#73)");
    RUN_TEST(test_parse_flat_object);
    RUN_TEST(test_parse_nested_object);
    RUN_TEST(test_key_lookup_is_structural_not_textual);
    RUN_TEST(test_absent_container_lookup_is_safe);
    RUN_TEST(test_key_lookup_is_exact_not_a_prefix);
    RUN_TEST(test_escapes_decode);
    RUN_TEST(test_malformed_is_refused);
    RUN_TEST(test_raw_control_char_is_refused);
    RUN_TEST(test_depth_and_size_caps_refuse);
    RUN_TEST(test_esc_append_round_trips);
    RUN_TEST(test_esc_append_refuses_to_truncate);
    RUN_TEST(test_esc_append_escapes_raw_controls);

    TEST_SUITE("research mcp: protocol (#73)");
    RUN_TEST(test_initialize);
    RUN_TEST(test_notification_draws_no_reply);
    RUN_TEST(test_id_round_trips_by_type);
    RUN_TEST(test_protocol_errors);
    RUN_TEST(test_unparseable_request_still_answers);
    RUN_TEST(test_tools_list_advertises_four);
    RUN_TEST(test_advertised_tools_are_all_callable);
    RUN_TEST(test_no_corpus_reports_inside_a_result);
    RUN_TEST(test_missing_argument_is_a_tool_error);
    RUN_TEST(test_tiny_buffer_overflows_rather_than_truncates);
    RUN_TEST(test_output_is_never_partially_written);

    TEST_SUITE("research mcp: against the corpus (#73)");
    RUN_TEST(test_search_returns_hits_with_provenance);
    RUN_TEST(test_no_match_is_a_result_not_an_error);
    RUN_TEST(test_for_alert_is_exact_over_the_wire);
    RUN_TEST(test_cite_lists_sources);
    RUN_TEST(test_recent_window_is_honoured);
    RUN_TEST(test_response_never_contains_a_raw_newline);
}
