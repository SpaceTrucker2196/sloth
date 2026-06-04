#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "ldap_snoop.h"

/* LDAP messages are ASN.1 BER per RFC 4511. We construct minimal
 * but valid frames here, never feeding the parser output of an
 * encoder it owns. */

/* ── Hand-rolled BER builders ────────────────────────────── */

/* Build an LDAP BindRequest. dn_len = 0 → anonymous bind.
 *
 * Layout:
 *   30 OUTERLEN              -- SEQUENCE
 *     02 01 01               -- messageID = 1
 *     60 OPLEN               -- [APPLICATION 0] BindRequest
 *       02 01 03             -- version = 3
 *       04 LEN <dn bytes>    -- name OCTET STRING
 *       80 00                -- simple [0] empty password
 */
static int build_bind_request(uint8_t *out, const char *dn, int dn_len) {
    /* Op body: version (3 bytes) + name + auth (2 bytes simple). */
    int dn_field = 2 + dn_len;
    int auth_field = 2;
    int op_body = 3 + dn_field + auth_field;
    /* Outer body: msgid (3 bytes) + op tag + op len byte + op body. */
    int outer_body = 3 + 2 + op_body;

    int o = 0;
    out[o++] = 0x30;             /* SEQUENCE */
    out[o++] = (uint8_t)outer_body;
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = 0x01;   /* messageID */
    out[o++] = 0x60;             /* BindRequest */
    out[o++] = (uint8_t)op_body;
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = 0x03;   /* version=3 */
    out[o++] = 0x04;             /* OCTET STRING (name) */
    out[o++] = (uint8_t)dn_len;
    if (dn_len) { memcpy(out + o, dn, (size_t)dn_len); o += dn_len; }
    out[o++] = 0x80; out[o++] = 0x00;                    /* simple "" */
    return o;
}

/* Build an LDAP SearchRequest. Body content is filler — the
 * parser only cares about the [APPLICATION 3] = 0x63 tag. */
static int build_search_request(uint8_t *out) {
    int o = 0;
    out[o++] = 0x30; out[o++] = 0x10;          /* SEQUENCE */
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = 0x02;   /* msgid = 2 */
    out[o++] = 0x63; out[o++] = 0x0B;          /* SearchRequest */
    /* 11 bytes of filler body. */
    for (int i = 0; i < 11; i++) out[o++] = 0x00;
    return o;
}

/* Build an LDAP SearchResultReference ([APPLICATION 19] = 0x73). */
static int build_search_result_ref(uint8_t *out) {
    int o = 0;
    out[o++] = 0x30; out[o++] = 0x10;
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = 0x03;
    out[o++] = 0x73; out[o++] = 0x0B;
    for (int i = 0; i < 11; i++) out[o++] = 0x00;
    return o;
}

/* Build a SearchResultEntry ([APPLICATION 4] = 0x64). The parser
 * should ignore this — it isn't tracked. Used to verify
 * unrecognised ops don't accidentally increment counters. */
static int build_search_result_entry(uint8_t *out) {
    int o = 0;
    out[o++] = 0x30; out[o++] = 0x10;
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = 0x04;
    out[o++] = 0x64; out[o++] = 0x0B;
    for (int i = 0; i < 11; i++) out[o++] = 0x00;
    return o;
}

/* ── Detection ──────────────────────────────────────────── */

static void test_detects_authenticated_bind(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_bind_request(buf, "CN=Alice,DC=ex,DC=com", 21);
    ASSERT_EQ(ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389,
                                  buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_event_count, 1);
    ASSERT_STR(s.ldap_events[0].src_ip, "10.0.0.5");
    ASSERT_EQ(s.ldap_events[0].bind_count,      1);
    ASSERT_EQ(s.ldap_events[0].bind_anon_count, 0);
}

static void test_detects_anonymous_bind(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_bind_request(buf, "", 0);
    ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_events[0].bind_count,      1);
    ASSERT_EQ(s.ldap_events[0].bind_anon_count, 1);
}

static void test_detects_search_request(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_events[0].search_count, 1);
}

static void test_detects_search_result_reference(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_result_ref(buf);
    ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_events[0].search_ref_count, 1);
}

/* Unrecognised protocolOp (SearchResultEntry, BindResponse, etc.)
 * must NOT increment any tracked counter — keeps the search-flood
 * threshold from being inflated by entry responses. */
static void test_search_result_entry_ignored(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_result_entry(buf);
    ASSERT_EQ(ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389,
                                  buf, n), 0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_event_count, 0);
}

/* ── Port / client-side inference ───────────────────────── */

static void test_server_src_port_inferred(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    /* Server replying — src_port=389. The client side is the
     * other endpoint, which is the attribution we record. */
    ldap_snoop_observe("10.0.0.10", 389, "10.0.0.5", 49152, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_STR(s.ldap_events[0].src_ip, "10.0.0.5");
}

static void test_global_catalog_port_works(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3268, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_event_count, 1);
    ASSERT_EQ(s.ldap_events[0].search_count, 1);
}

static void test_non_ldap_port_rejected(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    ASSERT_EQ(ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 8080,
                                  buf, n), 0);
}

/* ── Aggregation ────────────────────────────────────────── */

static void test_repeated_searches_accumulate(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    for (int i = 0; i < 10; i++)
        ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_event_count, 1);
    ASSERT_EQ(s.ldap_events[0].search_count, 10);
}

static void test_two_sources_tracked_separately(void) {
    ldap_snoop_clear();
    uint8_t buf[64];
    int n = build_search_request(buf);
    ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389, buf, n);
    ldap_snoop_observe("10.0.0.6", 49152, "10.0.0.10", 389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    ldap_snoop_snapshot(&s);
    ASSERT_EQ(s.ldap_event_count, 2);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_non_ldap_payload_rejected(void) {
    ldap_snoop_clear();
    static const uint8_t HTTP[] = "GET / HTTP/1.1\r\n";
    ASSERT_EQ(ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389,
                                  HTTP, sizeof(HTTP) - 1), 0);
}

static void test_truncated_envelope_rejected(void) {
    ldap_snoop_clear();
    uint8_t buf[3] = { 0x30, 0x80, 0x00 };   /* indefinite length */
    ASSERT_EQ(ldap_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 389,
                                  buf, sizeof(buf)), 0);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_ldap_snoop_tests(void) {
    TEST_SUITE("ldap_snoop: detection");
    RUN_TEST(test_detects_authenticated_bind);
    RUN_TEST(test_detects_anonymous_bind);
    RUN_TEST(test_detects_search_request);
    RUN_TEST(test_detects_search_result_reference);
    RUN_TEST(test_search_result_entry_ignored);

    TEST_SUITE("ldap_snoop: port / client-side inference");
    RUN_TEST(test_server_src_port_inferred);
    RUN_TEST(test_global_catalog_port_works);
    RUN_TEST(test_non_ldap_port_rejected);

    TEST_SUITE("ldap_snoop: aggregation");
    RUN_TEST(test_repeated_searches_accumulate);
    RUN_TEST(test_two_sources_tracked_separately);

    TEST_SUITE("ldap_snoop: negative cases");
    RUN_TEST(test_non_ldap_payload_rejected);
    RUN_TEST(test_truncated_envelope_rejected);
}
