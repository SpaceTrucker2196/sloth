#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "smb_snoop.h"

/* Construct minimal SMB-shaped payloads. We only need the magic at
 * the right offset — the parser's contract is "detect dialect from
 * the first 4 bytes (or after a NetBIOS Session Service header)",
 * everything else is bookkeeping. */

/* Direct SMB1: payload starts with 0xFF 'S' 'M' 'B'. */
static const uint8_t SMB1_DIRECT[] = {
    0xff, 'S', 'M', 'B',
    0x72, 0x00, 0x00, 0x00,        /* command + status placeholder */
    0x00, 0x00, 0x00, 0x00         /* flags / flags2 placeholder */
};

/* Direct SMB2: payload starts with 0xFE 'S' 'M' 'B'. */
static const uint8_t SMB2_DIRECT[] = {
    0xfe, 'S', 'M', 'B',
    0x40, 0x00, 0x00, 0x00,        /* structure size */
    0x00, 0x00, 0x00, 0x00
};

/* NBSS-framed SMB1: 4-byte NetBIOS header then the SMB magic. */
static const uint8_t SMB1_NBSS[] = {
    0x00, 0x00, 0x00, 0x40,        /* NBSS type=session, len=0x40 */
    0xff, 'S', 'M', 'B',
    0x72, 0x00, 0x00, 0x00
};

/* NBSS-framed SMB2. */
static const uint8_t SMB2_NBSS[] = {
    0x00, 0x00, 0x00, 0x40,
    0xfe, 'S', 'M', 'B',
    0x40, 0x00, 0x00, 0x00
};

/* Non-SMB TCP payload — HTTP request. The parser should ignore it
 * cleanly without recording a session. */
static const uint8_t NOT_SMB[] = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

/* ── Direct (port 445, no NBSS framing) ──────────────────── */

static void test_direct_smb1_recorded(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                                SMB1_DIRECT, sizeof(SMB1_DIRECT));
    ASSERT_EQ(ok, 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_STR(s.smb_sessions[0].client_ip, "10.0.0.5");
    ASSERT_STR(s.smb_sessions[0].server_ip, "10.0.0.10");
    ASSERT_EQ((int)s.smb_sessions[0].server_port, 445);
    ASSERT_STR(s.smb_sessions[0].dialect, "SMB1");
}

static void test_direct_smb2_recorded(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                                SMB2_DIRECT, sizeof(SMB2_DIRECT));
    ASSERT_EQ(ok, 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_STR(s.smb_sessions[0].dialect, "SMB2");
}

/* ── NBSS-framed (port 139) ─────────────────────────────── */

static void test_nbss_framed_smb1_recorded(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 139,
                                SMB1_NBSS, sizeof(SMB1_NBSS));
    ASSERT_EQ(ok, 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_EQ((int)s.smb_sessions[0].server_port, 139);
    ASSERT_STR(s.smb_sessions[0].dialect, "SMB1");
}

static void test_nbss_framed_smb2_recorded(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 139,
                                SMB2_NBSS, sizeof(SMB2_NBSS));
    ASSERT_EQ(ok, 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_STR(s.smb_sessions[0].dialect, "SMB2");
}

/* ── Client/server inference ────────────────────────────── */

/* When src_port is 445 (server replying), the parser should
 * correctly identify the OTHER side as the client. */
static void test_server_side_src_port_inferred(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.10", 445, "10.0.0.5", 49152,
                                SMB2_DIRECT, sizeof(SMB2_DIRECT));
    ASSERT_EQ(ok, 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_STR(s.smb_sessions[0].server_ip, "10.0.0.10");
    ASSERT_STR(s.smb_sessions[0].client_ip, "10.0.0.5");
}

/* ── SMB1 stickiness ────────────────────────────────────── */

/* Once a flow has been observed using SMB1, subsequent SMB2 frames
 * MUST NOT downgrade the recorded dialect. Attackers can force a
 * v1 negotiation mid-flow; the alert needs to remember it. */
static void test_smb1_is_sticky_across_observations(void) {
    smb_snoop_clear();
    smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                       SMB1_DIRECT, sizeof(SMB1_DIRECT));
    smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                       SMB2_DIRECT, sizeof(SMB2_DIRECT));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 1);
    ASSERT_STR(s.smb_sessions[0].dialect, "SMB1");
    /* Both observations counted. */
    ASSERT_EQ(s.smb_sessions[0].count, 2);
}

/* ── Negative cases ────────────────────────────────────── */

static void test_non_smb_payload_ignored(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                                NOT_SMB, sizeof(NOT_SMB) - 1);
    ASSERT_EQ(ok, 0);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 0);
}

static void test_short_payload_ignored(void) {
    smb_snoop_clear();
    uint8_t short_buf[3] = { 0xff, 'S', 'M' };
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                                short_buf, sizeof(short_buf));
    ASSERT_EQ(ok, 0);
}

/* Neither port is SMB — defensive return. */
static void test_no_smb_port_ignored(void) {
    smb_snoop_clear();
    int ok = smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 8080,
                                SMB1_DIRECT, sizeof(SMB1_DIRECT));
    ASSERT_EQ(ok, 0);
}

/* ── Two distinct sessions ──────────────────────────────── */

static void test_two_distinct_sessions_tracked_separately(void) {
    smb_snoop_clear();
    smb_snoop_observe("10.0.0.5", 49152, "10.0.0.10", 445,
                       SMB1_DIRECT, sizeof(SMB1_DIRECT));
    smb_snoop_observe("10.0.0.6", 49153, "10.0.0.11", 445,
                       SMB2_DIRECT, sizeof(SMB2_DIRECT));
    sloth_state_t s; memset(&s, 0, sizeof(s));
    smb_snoop_snapshot(&s);
    ASSERT_EQ(s.smb_session_count, 2);
}

void run_smb_snoop_tests(void) {
    TEST_SUITE("smb_snoop: detection");
    RUN_TEST(test_direct_smb1_recorded);
    RUN_TEST(test_direct_smb2_recorded);
    RUN_TEST(test_nbss_framed_smb1_recorded);
    RUN_TEST(test_nbss_framed_smb2_recorded);
    RUN_TEST(test_server_side_src_port_inferred);
    RUN_TEST(test_smb1_is_sticky_across_observations);
    RUN_TEST(test_two_distinct_sessions_tracked_separately);

    TEST_SUITE("smb_snoop: negative cases");
    RUN_TEST(test_non_smb_payload_ignored);
    RUN_TEST(test_short_payload_ignored);
    RUN_TEST(test_no_smb_port_ignored);
}
