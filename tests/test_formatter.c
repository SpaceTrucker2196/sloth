#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "runner.h"
#include "formatter.h"

/* Shared input — a typical alert record. Covers the cases the
 * transform has to handle: top-level scalar string, integer,
 * keys with numeric values, plus the special `type` and `sev`
 * keys that the CEF formatter promotes into the header. */
static const char *ALERT_JSONL =
    "{\"type\":\"alert\",\"ts\":1700000000,"
    "\"title\":\"THREAT_DOMAIN\","
    "\"detail\":\"10.0.0.5 queried malware.test\","
    "\"key\":\"threat-d:malware.test\","
    "\"sev\":2,\"ty\":3,\"count\":1}";

/* ── format selection ───────────────────────────────────── */

static void test_parse_name_jsonl(void) {
    out_format_t f = (out_format_t)999;
    ASSERT_EQ(formatter_parse_name("jsonl", &f), 1);
    ASSERT_EQ((int)f, (int)OUT_FMT_JSONL);
}
static void test_parse_name_cef(void) {
    out_format_t f = (out_format_t)999;
    ASSERT_EQ(formatter_parse_name("cef", &f), 1);
    ASSERT_EQ((int)f, (int)OUT_FMT_CEF);
}
static void test_parse_name_syslog(void) {
    out_format_t f = (out_format_t)999;
    ASSERT_EQ(formatter_parse_name("syslog", &f), 1);
    ASSERT_EQ((int)f, (int)OUT_FMT_SYSLOG);
}
static void test_parse_name_unknown(void) {
    out_format_t f = (out_format_t)42;
    ASSERT_EQ(formatter_parse_name("ndjson", &f), 0);
    ASSERT_EQ((int)f, 42);   /* untouched on failure */
}

/* ── JSONL passthrough ─────────────────────────────────── */

static void test_jsonl_is_passthrough(void) {
    formatter_set(OUT_FMT_JSONL);
    char out[1024];
    int n = formatter_transform(ALERT_JSONL, out, sizeof(out));
    ASSERT(n > 0);
    ASSERT_EQ(strcmp(out, ALERT_JSONL), 0);
}

/* ── CEF ───────────────────────────────────────────────── */

static void test_cef_header_shape(void) {
    formatter_set(OUT_FMT_CEF);
    char out[1024];
    int n = formatter_transform(ALERT_JSONL, out, sizeof(out));
    ASSERT(n > 0);
    /* CEF:0|sloth-net|sloth|1|alert|alert|<sev>|<extensions> */
    ASSERT(strncmp(out, "CEF:0|sloth-net|sloth|1|alert|alert|", 36) == 0);
}

static void test_cef_extension_pairs(void) {
    formatter_set(OUT_FMT_CEF);
    char out[1024];
    formatter_transform(ALERT_JSONL, out, sizeof(out));
    /* Header keys (type, sev) must NOT reappear in extensions — they
     * are special-cased into the header / severity field. Other keys
     * land as `key=value` pairs separated by spaces. */
    ASSERT(strstr(out, "ts=1700000000")            != NULL);
    ASSERT(strstr(out, "title=THREAT_DOMAIN")      != NULL);
    ASSERT(strstr(out, "key=threat-d:malware.test")!= NULL);
    ASSERT(strstr(out, "count=1")                  != NULL);
    ASSERT(strstr(out, "type=alert")               == NULL);
    ASSERT(strstr(out, "sev=2")                    == NULL);
}

/* The CEF Severity field is the integer after the 6th '|'. ALERT_SEV_CRIT
 * (sev=2) maps to CEF severity 9 per the mapping table in formatter.c. */
static void test_cef_severity_mapping(void) {
    formatter_set(OUT_FMT_CEF);
    char out[1024];
    formatter_transform(ALERT_JSONL, out, sizeof(out));
    /* Find the 6th '|' and read the digit(s) before the 7th. */
    int pipes = 0;
    const char *p = out;
    const char *sev_start = NULL;
    while (*p) {
        if (*p == '|') {
            pipes++;
            if (pipes == 6) sev_start = p + 1;
            if (pipes == 7) {
                int slen = (int)(p - sev_start);
                char sev[8];
                int copy = slen < (int)sizeof(sev) - 1 ? slen : (int)sizeof(sev) - 1;
                memcpy(sev, sev_start, (size_t)copy);
                sev[copy] = '\0';
                ASSERT_EQ(atoi(sev), 9);
                return;
            }
        }
        p++;
    }
    ASSERT(0);   /* fewer than 7 pipes — malformed CEF */
}

/* CEF requires backslash-escaping `=` in extension values and `\` in
 * extension values; spaces and other characters pass through as-is. */
static void test_cef_extension_escapes_equals(void) {
    formatter_set(OUT_FMT_CEF);
    const char *in = "{\"type\":\"dns\",\"qname\":\"key=val.example.com\"}";
    char out[1024];
    formatter_transform(in, out, sizeof(out));
    ASSERT(strstr(out, "qname=key\\=val.example.com") != NULL);
}

/* ── syslog ────────────────────────────────────────────── */

static void test_syslog_header_shape(void) {
    formatter_set(OUT_FMT_SYSLOG);
    char out[2048];
    int n = formatter_transform(ALERT_JSONL, out, sizeof(out));
    ASSERT(n > 0);
    /* <134>1 <ts> <host> sloth <pid> alert [sloth@32473 …] <msg> */
    ASSERT(strncmp(out, "<134>1 ", 7) == 0);
    /* MSGID = record type. */
    ASSERT(strstr(out, " sloth ") != NULL);   /* APP-NAME */
    ASSERT(strstr(out, " alert ") != NULL);   /* MSGID */
    ASSERT(strstr(out, "[sloth@32473")            != NULL);
    ASSERT(strstr(out, " title=\"THREAT_DOMAIN\"")!= NULL);
    /* MSG carries the original JSON verbatim for parser-fidelity. */
    ASSERT(strstr(out, ALERT_JSONL)               != NULL);
}

/* Nested arrays / objects in the record (beacons carry both) must
 * not appear inside structured-data — RFC 5424 forbids them in
 * SD-PARAM values. Full fidelity is preserved via the MSG. */
static void test_syslog_strips_nested_from_sd(void) {
    formatter_set(OUT_FMT_SYSLOG);
    const char *in =
        "{\"type\":\"beacon\",\"ts\":1700000000,"
        "\"ssid\":\"Cafe\",\"ssid_history\":[\"Cafe\",\"Old\"],"
        "\"neighbors\":[]}";
    char out[2048];
    formatter_transform(in, out, sizeof(out));
    /* Structured-data segment must NOT mention the arrays. */
    const char *sd_start = strstr(out, "[sloth@32473");
    const char *sd_end   = strstr(sd_start ? sd_start : "", "]");
    ASSERT(sd_start != NULL && sd_end != NULL);
    int sd_len = (int)(sd_end - sd_start);
    char sd[1024];
    int copy = sd_len < (int)sizeof(sd) - 1 ? sd_len : (int)sizeof(sd) - 1;
    memcpy(sd, sd_start, (size_t)copy);
    sd[copy] = '\0';
    ASSERT(strstr(sd, "ssid_history") == NULL);
    ASSERT(strstr(sd, "neighbors")    == NULL);
    /* And the MSG portion (after the closing `]`) still has them. */
    ASSERT(strstr(sd_end, "ssid_history") != NULL);
}

/* ── malformed input ───────────────────────────────────── */

static void test_malformed_returns_neg(void) {
    formatter_set(OUT_FMT_CEF);
    char out[256];
    /* Not a JSON object at all. */
    ASSERT_EQ(formatter_transform("hello world", out, sizeof(out)), -1);
    /* Object without `type` key — CEF needs it for the header. */
    ASSERT_EQ(formatter_transform("{\"ts\":1}", out, sizeof(out)), -1);
}

void run_formatter_tests(void) {
    TEST_SUITE("formatter: name parsing");
    RUN_TEST(test_parse_name_jsonl);
    RUN_TEST(test_parse_name_cef);
    RUN_TEST(test_parse_name_syslog);
    RUN_TEST(test_parse_name_unknown);

    TEST_SUITE("formatter: jsonl passthrough");
    RUN_TEST(test_jsonl_is_passthrough);

    TEST_SUITE("formatter: CEF");
    RUN_TEST(test_cef_header_shape);
    RUN_TEST(test_cef_extension_pairs);
    RUN_TEST(test_cef_severity_mapping);
    RUN_TEST(test_cef_extension_escapes_equals);

    TEST_SUITE("formatter: syslog");
    RUN_TEST(test_syslog_header_shape);
    RUN_TEST(test_syslog_strips_nested_from_sd);

    TEST_SUITE("formatter: malformed");
    RUN_TEST(test_malformed_returns_neg);

    /* Restore default for any later tests that look at the global. */
    formatter_set(OUT_FMT_JSONL);
}
