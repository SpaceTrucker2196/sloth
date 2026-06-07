#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "rdp_snoop.h"

/* RDP X.224 Connection Request frames built from first principles
 * per RFC 1006 (TPKT) + X.224 (T.0) + MS-RDPBCGR §2.2.1.1.
 *
 * Layout for the no-user-data case (a minimal valid CR TPDU):
 *   03 00 00 0B    -- TPKT version 3, length 11 (4 + 7)
 *   06             -- X.224 LI = 6 (bytes 1..7 below)
 *   E0             -- CR code
 *   00 00          -- DST-REF
 *   00 00          -- SRC-REF
 *   00             -- class/options */
static int build_minimal_cr(uint8_t *out) {
    out[0] = 0x03; out[1] = 0x00; out[2] = 0x00; out[3] = 0x0B;
    out[4] = 0x06;
    out[5] = 0xE0;
    out[6] = 0x00; out[7] = 0x00;
    out[8] = 0x00; out[9] = 0x00;
    out[10] = 0x00;
    return 11;
}

/* Build a CR TPDU carrying a cookie + RDP_NEG_REQ user-data
 * field. The cookie is "Cookie: mstshash=<user>\r\n" and the
 * neg-req is 8 bytes of TLV: 01 flags 08 00 protos(LE u32). */
static int build_cr_with_cookie_and_neg(uint8_t *out, const char *user,
                                         uint32_t protos) {
    int user_len = (int)strlen(user);
    const char  prefix[] = "Cookie: mstshash=";
    int prefix_len = (int)sizeof(prefix) - 1;
    int cookie_total = prefix_len + user_len + 2;   /* + CRLF */
    int neg_total = 8;
    int user_data = cookie_total + neg_total;
    int li = 6 + user_data;                          /* fixed CR header + ud */
    int tpkt_len = 4 + 1 + li;                       /* TPKT + LI byte + body */

    int o = 0;
    out[o++] = 0x03; out[o++] = 0x00;
    out[o++] = (uint8_t)((tpkt_len >> 8) & 0xFF);
    out[o++] = (uint8_t)(tpkt_len & 0xFF);
    out[o++] = (uint8_t)li;
    out[o++] = 0xE0;
    out[o++] = 0x00; out[o++] = 0x00;
    out[o++] = 0x00; out[o++] = 0x00;
    out[o++] = 0x00;
    /* Cookie field */
    memcpy(out + o, prefix, (size_t)prefix_len); o += prefix_len;
    memcpy(out + o, user,   (size_t)user_len);   o += user_len;
    out[o++] = '\r'; out[o++] = '\n';
    /* RDP_NEG_REQ TLV */
    out[o++] = 0x01;
    out[o++] = 0x00;
    out[o++] = 0x08; out[o++] = 0x00;
    out[o++] = (uint8_t)(protos        & 0xFF);
    out[o++] = (uint8_t)((protos >>  8)& 0xFF);
    out[o++] = (uint8_t)((protos >> 16)& 0xFF);
    out[o++] = (uint8_t)((protos >> 24)& 0xFF);
    return o;
}

/* ── Detection ──────────────────────────────────────────── */

static void test_detects_minimal_cr(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389,
                                buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_EQ(s.rdp_flow_count, 1);
    ASSERT_STR(s.rdp_flows[0].src_ip, "10.0.0.5");
    ASSERT_STR(s.rdp_flows[0].dst_ip, "10.0.0.10");
    ASSERT_EQ(s.rdp_flows[0].connect_req_count, 1);
}

static void test_extracts_cookie_username(void) {
    rdp_snoop_clear();
    uint8_t buf[128];
    int n = build_cr_with_cookie_and_neg(buf, "alice",
                                          RDP_PROTO_SSL | RDP_PROTO_HYBRID);
    rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_STR(s.rdp_flows[0].last_cookie, "alice");
}

static void test_extracts_neg_req_protocols(void) {
    rdp_snoop_clear();
    uint8_t buf[128];
    int n = build_cr_with_cookie_and_neg(buf, "bob",
                                          RDP_PROTO_HYBRID | RDP_PROTO_HYBRID_EX);
    rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_EQ((int)s.rdp_flows[0].proto_mask,
              (int)(RDP_PROTO_HYBRID | RDP_PROTO_HYBRID_EX));
}

/* Subsequent CR with a different cookie updates last_cookie but
 * keeps proto_mask accumulating (bitwise-OR). */
static void test_proto_mask_accumulates(void) {
    rdp_snoop_clear();
    uint8_t buf[128];
    int n1 = build_cr_with_cookie_and_neg(buf, "alice", RDP_PROTO_SSL);
    rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n1);
    int n2 = build_cr_with_cookie_and_neg(buf, "alice", RDP_PROTO_HYBRID);
    rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n2);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_EQ((int)s.rdp_flows[0].proto_mask,
              (int)(RDP_PROTO_SSL | RDP_PROTO_HYBRID));
}

/* ── Aggregation ────────────────────────────────────────── */

static void test_repeated_crs_accumulate(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    for (int i = 0; i < 12; i++)
        rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_EQ(s.rdp_flow_count, 1);
    ASSERT_EQ(s.rdp_flows[0].connect_req_count, 12);
}

static void test_two_clients_tracked_separately(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389, buf, n);
    rdp_snoop_observe("10.0.0.6", 49152, "10.0.0.10", 3389, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    rdp_snoop_snapshot(&s);
    ASSERT_EQ(s.rdp_flow_count, 2);
}

/* ── Port gating ───────────────────────────────────────── */

static void test_non_rdp_port_rejected(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 8080,
                                buf, n), 0);
}

/* Server→client direction has src_port=3389 — even if the bytes
 * look right we don't count it as a CR (the X.224 code would be
 * Connection Confirm 0xD0, not CR 0xE0). */
static void test_server_side_rejected(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    ASSERT_EQ(rdp_snoop_observe("10.0.0.10", 3389, "10.0.0.5", 49152,
                                buf, n), 0);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_bad_tpkt_version_rejected(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    buf[0] = 0x05;                /* not 0x03 */
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389,
                                buf, n), 0);
}

static void test_non_cr_tpdu_rejected(void) {
    rdp_snoop_clear();
    uint8_t buf[64];
    int n = build_minimal_cr(buf);
    buf[5] = 0xD0;                /* Connection Confirm, not CR */
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389,
                                buf, n), 0);
}

static void test_truncated_rejected(void) {
    rdp_snoop_clear();
    uint8_t buf[8] = { 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00 };
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389,
                                buf, (int)sizeof(buf)), 0);
}

static void test_non_rdp_payload_rejected(void) {
    rdp_snoop_clear();
    static const uint8_t HTTP[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    ASSERT_EQ(rdp_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 3389,
                                HTTP, (int)sizeof(HTTP) - 1), 0);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_rdp_snoop_tests(void) {
    TEST_SUITE("rdp_snoop: X.224 Connection Request detection");
    RUN_TEST(test_detects_minimal_cr);
    RUN_TEST(test_extracts_cookie_username);
    RUN_TEST(test_extracts_neg_req_protocols);
    RUN_TEST(test_proto_mask_accumulates);

    TEST_SUITE("rdp_snoop: aggregation");
    RUN_TEST(test_repeated_crs_accumulate);
    RUN_TEST(test_two_clients_tracked_separately);

    TEST_SUITE("rdp_snoop: port gating");
    RUN_TEST(test_non_rdp_port_rejected);
    RUN_TEST(test_server_side_rejected);

    TEST_SUITE("rdp_snoop: negative cases");
    RUN_TEST(test_bad_tpkt_version_rejected);
    RUN_TEST(test_non_cr_tpdu_rejected);
    RUN_TEST(test_truncated_rejected);
    RUN_TEST(test_non_rdp_payload_rejected);
}
