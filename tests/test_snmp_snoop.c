#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "snmp_snoop.h"

/* SNMP v1/v2c messages built from raw ASN.1 BER per RFC 1157 §4.1
 * and RFC 1901 §3. We never feed the parser its own encoder output.
 *
 *   Message ::= SEQUENCE {
 *       version   INTEGER,
 *       community OCTET STRING,
 *       data      ANY (PDU)
 *   }
 *
 * BER tags used:
 *   30 = SEQUENCE
 *   02 = INTEGER
 *   04 = OCTET STRING
 *   A0..A8 = PDU [APPLICATION 0..8] context-specific constructed
 *
 * The PDU body itself is a SEQUENCE of request-id + error-status +
 * error-index + varbinds. The parser only looks at the leading PDU
 * tag, so we stuff in a small filler body for byte-count accounting. */
static int build_snmp_msg(uint8_t *out,
                          int version, const char *community,
                          uint8_t pdu_tag) {
    int comm_len = (int)strlen(community);
    /* PDU body: SEQUENCE wrapping minimal contents. We build a fake
     * 10-byte body — the parser doesn't decode beyond the tag, so
     * its contents don't matter, only the outer envelope length. */
    int pdu_body_len = 10;

    /* Inner layout:
     *   02 01 <ver>             -- INTEGER version
     *   04 <clen> <community>   -- OCTET STRING community
     *   <pdu_tag> <pbl> <body>  -- PDU TLV
     */
    int inner = 3 + 2 + comm_len + 2 + pdu_body_len;

    int o = 0;
    out[o++] = 0x30;
    out[o++] = (uint8_t)inner;
    out[o++] = 0x02; out[o++] = 0x01; out[o++] = (uint8_t)version;
    out[o++] = 0x04; out[o++] = (uint8_t)comm_len;
    memcpy(out + o, community, (size_t)comm_len); o += comm_len;
    out[o++] = pdu_tag;
    out[o++] = (uint8_t)pdu_body_len;
    for (int i = 0; i < pdu_body_len; i++) out[o++] = 0x00;
    return o;
}

/* ── PDU type detection ────────────────────────────────── */

static void test_detects_get_request(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 0, "public", 0xA0);
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161,
                                  buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flow_count, 1);
    ASSERT_EQ(s.snmp_flows[0].get_count, 1);
    ASSERT_STR(s.snmp_flows[0].last_community, "public");
    ASSERT_EQ(s.snmp_flows[0].version, 0);
}

static void test_detects_getnext_request(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "public", 0xA1);
    snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].getnext_count, 1);
}

static void test_detects_getbulk_request(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "public", 0xA5);
    snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].getbulk_count, 1);
}

static void test_detects_set_request(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "private", 0xA3);
    snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].set_count, 1);
    ASSERT_STR(s.snmp_flows[0].last_community, "private");
}

static void test_detects_response_attributes_to_querier(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 0, "public", 0xA2);
    /* Agent replying — src_port=161. Attribution flips: the
     * querier (the OTHER endpoint) is the flow's src_ip. */
    snmp_snoop_observe("10.0.0.10", 161, "10.0.0.5", 49152, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_STR(s.snmp_flows[0].src_ip, "10.0.0.5");
    ASSERT_EQ(s.snmp_flows[0].response_count, 1);
}

static void test_detects_v2trap(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "public", 0xA7);
    snmp_snoop_observe("10.0.0.10", 49152, "10.0.0.5", 162, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].trap_count, 1);
}

/* ── Community-string tracking ──────────────────────────── */

static void test_repeated_same_community_counts_once(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "public", 0xA0);
    for (int i = 0; i < 5; i++)
        snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].community_count, 1);
    ASSERT_EQ(s.snmp_flows[0].get_count, 5);
}

static void test_distinct_communities_accumulate(void) {
    snmp_snoop_clear();
    const char *words[] = { "public", "private", "cisco",
                            "community", "admin", "test" };
    uint8_t buf[64];
    for (int i = 0; i < 6; i++) {
        int n = build_snmp_msg(buf, 1, words[i], 0xA0);
        snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].community_count, 6);
    ASSERT_STR(s.snmp_flows[0].last_community, "test");
}

/* Community-list cap protects the array bound. Past
 * MAX_SNMP_COMMUNITIES, last_community still updates but the
 * unique-list stops growing. */
static void test_community_list_capped(void) {
    snmp_snoop_clear();
    char comm[8];
    uint8_t buf[64];
    for (int i = 0; i < MAX_SNMP_COMMUNITIES + 3; i++) {
        snprintf(comm, sizeof(comm), "c%d", i);
        int n = build_snmp_msg(buf, 1, comm, 0xA0);
        snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161, buf, n);
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flows[0].community_count, MAX_SNMP_COMMUNITIES);
}

/* ── Port gating ───────────────────────────────────────── */

static void test_non_snmp_port_rejected(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    int n = build_snmp_msg(buf, 1, "public", 0xA0);
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 8161,
                                  buf, n), 0);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_non_snmp_payload_rejected(void) {
    snmp_snoop_clear();
    static const uint8_t JUNK[] = "Hello, world!";
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161,
                                  JUNK, (int)sizeof(JUNK) - 1), 0);
}

static void test_truncated_rejected(void) {
    snmp_snoop_clear();
    uint8_t buf[6] = { 0x30, 0x04, 0x02, 0x01, 0x00, 0x04 };
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161,
                                  buf, (int)sizeof(buf)), 0);
}

static void test_unknown_pdu_tag_rejected(void) {
    snmp_snoop_clear();
    uint8_t buf[64];
    /* Tag 0xAF is in the [APPLICATION 15] range — not a defined
     * PDU. Parser should reject. */
    int n = build_snmp_msg(buf, 1, "public", 0xAF);
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161,
                                  buf, n), 0);
}

/* Embedded NUL byte in community — sanitization must drop the
 * community string entirely so a non-printable byte can't poison
 * a JSONL line. The packet is still observed (parse succeeds) but
 * the community list stays empty. */
static void test_community_with_nul_byte_rejected(void) {
    snmp_snoop_clear();
    uint8_t buf[64]; int o = 0;
    buf[o++] = 0x30; buf[o++] = 0x13;                     /* SEQUENCE  */
    buf[o++] = 0x02; buf[o++] = 0x01; buf[o++] = 0x01;    /* ver=v2c   */
    buf[o++] = 0x04; buf[o++] = 0x05;                     /* OCTSTRING */
    buf[o++] = 'p'; buf[o++] = 'u'; buf[o++] = 0x00;
    buf[o++] = 'b'; buf[o++] = 'c';
    buf[o++] = 0xA0; buf[o++] = 0x07;                     /* GetRequest */
    for (int i = 0; i < 7; i++) buf[o++] = 0x00;
    ASSERT_EQ(snmp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 161,
                                  buf, o), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    snmp_snoop_snapshot(&s);
    ASSERT_EQ(s.snmp_flow_count, 1);
    ASSERT_EQ(s.snmp_flows[0].community_count, 0);
    ASSERT_EQ(s.snmp_flows[0].get_count, 1);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_snmp_snoop_tests(void) {
    TEST_SUITE("snmp_snoop: PDU-type detection");
    RUN_TEST(test_detects_get_request);
    RUN_TEST(test_detects_getnext_request);
    RUN_TEST(test_detects_getbulk_request);
    RUN_TEST(test_detects_set_request);
    RUN_TEST(test_detects_response_attributes_to_querier);
    RUN_TEST(test_detects_v2trap);

    TEST_SUITE("snmp_snoop: community-string tracking");
    RUN_TEST(test_repeated_same_community_counts_once);
    RUN_TEST(test_distinct_communities_accumulate);
    RUN_TEST(test_community_list_capped);

    TEST_SUITE("snmp_snoop: port gating");
    RUN_TEST(test_non_snmp_port_rejected);

    TEST_SUITE("snmp_snoop: negative cases");
    RUN_TEST(test_non_snmp_payload_rejected);
    RUN_TEST(test_truncated_rejected);
    RUN_TEST(test_unknown_pdu_tag_rejected);
    RUN_TEST(test_community_with_nul_byte_rejected);
}
