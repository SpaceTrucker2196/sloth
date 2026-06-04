#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "bgp_snoop.h"

/* BGP-4 (RFC 4271 §4.1) — 19-byte common header:
 *   bytes  0..15  Marker (16 × 0xFF)
 *   bytes 16..17  Length (network byte order; total incl. header)
 *   byte     18   Type (1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE)
 *
 * Tests build raw byte arrays from these constants. We never feed
 * the parser the output of an encoder it owns. */

static int build_msg(uint8_t *out, uint8_t type, int total_len) {
    if (total_len < 19) total_len = 19;
    memset(out, 0xFF, 16);
    out[16] = (uint8_t)((total_len >> 8) & 0xFF);
    out[17] = (uint8_t)(total_len & 0xFF);
    out[18] = type;
    for (int i = 19; i < total_len; i++) out[i] = 0x00;
    return total_len;
}

/* ── Detection ──────────────────────────────────────────── */

static void test_detects_keepalive(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    ASSERT_EQ(bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179,
                                buf, n), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_session_count, 1);
    ASSERT_EQ(s.bgp_sessions[0].keepalive_count, 1);
    ASSERT_EQ(s.bgp_sessions[0].notification_count, 0);
}

static void test_detects_open(void) {
    bgp_snoop_clear();
    uint8_t buf[64];
    int n = build_msg(buf, 1, 29);
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_sessions[0].open_count, 1);
}

static void test_detects_update(void) {
    bgp_snoop_clear();
    uint8_t buf[64];
    int n = build_msg(buf, 2, 23);
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_sessions[0].update_count, 1);
}

static void test_detects_notification(void) {
    bgp_snoop_clear();
    uint8_t buf[64];
    int n = build_msg(buf, 3, 21);
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_sessions[0].notification_count, 1);
}

/* ── Multi-message segments ─────────────────────────────── */

/* A real TCP segment can carry several back-to-back BGP messages.
 * The parser must walk them all and count each independently. */
static void test_back_to_back_messages(void) {
    bgp_snoop_clear();
    uint8_t buf[128]; int o = 0;
    o += build_msg(buf + o, 1, 29);   /* OPEN */
    o += build_msg(buf + o, 4, 19);   /* KEEPALIVE */
    o += build_msg(buf + o, 2, 23);   /* UPDATE */
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, o);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_sessions[0].open_count,      1);
    ASSERT_EQ(s.bgp_sessions[0].keepalive_count, 1);
    ASSERT_EQ(s.bgp_sessions[0].update_count,    1);
}

static void test_notification_burst_accumulates(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 3, 19);
    for (int i = 0; i < 5; i++)
        bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_session_count, 1);
    ASSERT_EQ(s.bgp_sessions[0].notification_count, 5);
}

/* ── Peer-pair canonicalisation ─────────────────────────── */

/* Messages between A and B in either direction should fold into
 * one session entry, with peer_a < peer_b lexically. */
static void test_peer_pair_canonical(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    bgp_snoop_observe("10.0.0.2", 179, "10.0.0.1", 33333, buf, n);
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_session_count, 1);
    ASSERT_STR(s.bgp_sessions[0].peer_a, "10.0.0.1");
    ASSERT_STR(s.bgp_sessions[0].peer_b, "10.0.0.2");
    ASSERT_EQ(s.bgp_sessions[0].keepalive_count, 2);
}

static void test_two_pairs_tracked_separately(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    bgp_snoop_observe("10.0.0.1", 179, "10.0.0.2", 33333, buf, n);
    bgp_snoop_observe("10.0.0.3", 179, "10.0.0.4", 33333, buf, n);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_session_count, 2);
}

/* ── Port gating ───────────────────────────────────────── */

static void test_non_bgp_port_rejected(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    ASSERT_EQ(bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 8080,
                                buf, n), 0);
}

static void test_either_endpoint_on_179(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    /* src_port=179 (server-side) should still be observed. */
    ASSERT_EQ(bgp_snoop_observe("10.0.0.2", 179, "10.0.0.1", 33333,
                                buf, n), 1);
}

/* ── Negative cases ─────────────────────────────────────── */

static void test_bad_marker_rejected(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    buf[3] = 0x00;                 /* corrupt the marker */
    ASSERT_EQ(bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179,
                                buf, n), 0);
}

static void test_undersize_rejected(void) {
    bgp_snoop_clear();
    uint8_t buf[18];
    memset(buf, 0xFF, sizeof(buf));
    ASSERT_EQ(bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179,
                                buf, (int)sizeof(buf)), 0);
}

static void test_oversize_length_rejected(void) {
    bgp_snoop_clear();
    uint8_t buf[19];
    int n = build_msg(buf, 4, 19);
    /* Encoded length 5000 — above the 4096 RFC ceiling. */
    buf[16] = 0x13; buf[17] = 0x88;
    ASSERT_EQ(bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179,
                                buf, n), 0);
}

static void test_unknown_type_stops_walk(void) {
    bgp_snoop_clear();
    /* First msg = OPEN, second msg = type 99 (unknown). The walker
     * should record the OPEN and then stop on the unknown type. */
    uint8_t buf[128]; int o = 0;
    o += build_msg(buf + o, 1, 29);
    o += build_msg(buf + o, 99, 19);
    bgp_snoop_observe("10.0.0.1", 33333, "10.0.0.2", 179, buf, o);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    bgp_snoop_snapshot(&s);
    ASSERT_EQ(s.bgp_session_count, 1);
    ASSERT_EQ(s.bgp_sessions[0].open_count, 1);
}

/* ── Suite ──────────────────────────────────────────────── */

void run_bgp_snoop_tests(void) {
    TEST_SUITE("bgp_snoop: message-type detection");
    RUN_TEST(test_detects_keepalive);
    RUN_TEST(test_detects_open);
    RUN_TEST(test_detects_update);
    RUN_TEST(test_detects_notification);

    TEST_SUITE("bgp_snoop: multi-message segments");
    RUN_TEST(test_back_to_back_messages);
    RUN_TEST(test_notification_burst_accumulates);

    TEST_SUITE("bgp_snoop: peer-pair canonicalisation");
    RUN_TEST(test_peer_pair_canonical);
    RUN_TEST(test_two_pairs_tracked_separately);

    TEST_SUITE("bgp_snoop: port gating");
    RUN_TEST(test_non_bgp_port_rejected);
    RUN_TEST(test_either_endpoint_on_179);

    TEST_SUITE("bgp_snoop: negative cases");
    RUN_TEST(test_bad_marker_rejected);
    RUN_TEST(test_undersize_rejected);
    RUN_TEST(test_oversize_length_rejected);
    RUN_TEST(test_unknown_type_stops_walk);
}
