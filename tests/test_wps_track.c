#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "wps_track.h"
#include "eap_parse.h"
#include "sensor_health.h"

/* ── WPS session table — issue #82, wave 7 ──────────────────
 *
 * Hand-built EAP-WSC frames per RFC 3748 §5.7 + WSC 2.0 §7.7/§12 (the
 * same first-principles construction test_eap_parse.c uses — no
 * captures). Each frame is Version+MessageType TLVs; op and msg vary
 * per step, so a session's whole M1→M3→NACK life can be replayed
 * byte-honestly through the same entry point the capture path uses. */

static const uint8_t BSSID[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t STA_A[6] = { 0x02, 0xAA, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t STA_B[6] = { 0x02, 0xBB, 0x00, 0x00, 0x00, 0x02 };

/* op = WSC_OP_*, msg = WSC_MSG_* or 0 to omit the attribute. */
static void wsc_feed(const uint8_t sta[6], int op, int msg, time_t now) {
    uint8_t f[] = {
        0x01, 0x20, 0x00, 0x18, 0xFE,             /* Request, Expanded  */
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01, /* WFA / SimpleConfig */
        0x00, 0x00,                               /* Op, Flags          */
        0x10, 0x4A, 0x00, 0x01, 0x10,             /* Version 1.0        */
        0x10, 0x22, 0x00, 0x01, 0x00,             /* Message Type       */
    };
    f[12] = (uint8_t)op;
    if (msg) f[23] = (uint8_t)msg;
    else     f[3]  = 0x13;                        /* drop the last TLV  */
    wps_track_observe(BSSID, sta, f, msg ? 24 : 19, now);
}

static void test_session_created_and_keyed(void) {
    wps_track_clear();
    wsc_feed(STA_A, WSC_OP_MSG, WSC_MSG_M1, 1000);
    ASSERT_EQ(wps_track_count(), 1);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.state, WPS_S_M1_SEEN);
    ASSERT_EQ(s.last_msg, WSC_MSG_M1);
    ASSERT_EQ((long long)s.first_seen, 1000);
    ASSERT_EQ(wps_track_session(BSSID, STA_B, &s), 0);
    /* A second STA is a second session, not an update. */
    wsc_feed(STA_B, WSC_OP_MSG, WSC_MSG_M1, 1001);
    ASSERT_EQ(wps_track_count(), 2);
    wps_track_clear();
}

static void test_state_machine_and_cycles(void) {
    wps_track_clear();
    /* Two full Reaver-style attempts: M1 M2 M3 M4 NACK, twice. */
    for (int c = 0; c < 2; c++) {
        wsc_feed(STA_A, WSC_OP_MSG,  WSC_MSG_M1,  2000 + c * 10);
        wsc_feed(STA_A, WSC_OP_MSG,  WSC_MSG_M2,  2001 + c * 10);
        wsc_feed(STA_A, WSC_OP_MSG,  WSC_MSG_M3,  2002 + c * 10);
        wsc_feed(STA_A, WSC_OP_MSG,  WSC_MSG_M4,  2003 + c * 10);
        wsc_feed(STA_A, WSC_OP_NACK, WSC_MSG_NACK, 2004 + c * 10);
    }
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.state, WPS_S_NACKED);
    ASSERT_EQ(s.cycle_count, 2);
    ASSERT_EQ((int)(s.msg_bits & 0x1E), 0x1E);   /* M1..M4 seen */
    ASSERT_EQ((long long)s.first_seen, 2000);
    ASSERT_EQ((long long)s.last_seen, 2014);
    wps_track_clear();
}

static void test_nack_without_m3_is_not_a_cycle(void) {
    wps_track_clear();
    /* M1 then NACK — an M2D-style refusal, not a brute-force unit. */
    wsc_feed(STA_A, WSC_OP_MSG,  WSC_MSG_M1,  3000);
    wsc_feed(STA_A, WSC_OP_NACK, WSC_MSG_NACK, 3001);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.state, WPS_S_NACKED);
    ASSERT_EQ(s.cycle_count, 0);
    wps_track_clear();
}

static void test_done_and_m8_complete(void) {
    wps_track_clear();
    wsc_feed(STA_A, WSC_OP_MSG, WSC_MSG_M1, 4000);
    wsc_feed(STA_A, WSC_OP_MSG, WSC_MSG_M8, 4001);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.state, WPS_S_DONE);
    wsc_feed(STA_B, WSC_OP_MSG,  WSC_MSG_M1, 4002);
    wsc_feed(STA_B, WSC_OP_DONE, 0,          4003);
    ASSERT_EQ(wps_track_session(BSSID, STA_B, &s), 1);
    ASSERT_EQ(s.state, WPS_S_DONE);
    wps_track_clear();
}

static void test_uuid_e_kept_from_m1(void) {
    wps_track_clear();
    /* The full M1 from test_eap_parse.c, UUID-E and all. */
    uint8_t f[] = {
        0x02, 0x07, 0x00, 0x36, 0xFE,
        0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
        0x04, 0x00,
        0x10, 0x4A, 0x00, 0x01, 0x10,
        0x10, 0x22, 0x00, 0x01, 0x04,
        0x10, 0x47, 0x00, 0x10,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        0x10, 0x20, 0x00, 0x06,
        0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,
    };
    wps_track_observe(BSSID, STA_A, f, (int)sizeof(f), 5000);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.has_uuid, 1);
    ASSERT_EQ(s.uuid_e[0], 0x11);
    ASSERT_EQ(s.uuid_e[15], 0x00);
    wps_track_clear();
}

static void test_non_wsc_frames_ignored(void) {
    wps_track_clear();
    uint8_t identity[] = { 0x02, 0x01, 0x00, 0x05, 0x01 };
    wps_track_observe(BSSID, STA_A, identity, (int)sizeof(identity), 6000);
    ASSERT_EQ(wps_track_count(), 0);
    wps_track_observe(BSSID, STA_A, NULL, 0, 6001);
    ASSERT_EQ(wps_track_count(), 0);
    wps_track_clear();
}

static void test_lru_eviction_reaches_tally(void) {
    wps_track_clear();
    sh_evict_reset();
    uint8_t sta[6] = { 0x02, 0xCC, 0, 0, 0, 0 };
    for (int i = 0; i < MAX_WPS_SESSIONS + 3; i++) {
        sta[4] = (uint8_t)(i >> 8);
        sta[5] = (uint8_t)i;
        /* Feed via a local copy of wsc_feed's frame with this STA. */
        uint8_t f[] = {
            0x01, 0x20, 0x00, 0x18, 0xFE,
            0x00, 0x37, 0x2A, 0x00, 0x00, 0x00, 0x01,
            0x04, 0x00,
            0x10, 0x4A, 0x00, 0x01, 0x10,
            0x10, 0x22, 0x00, 0x01, 0x04,
        };
        wps_track_observe(BSSID, sta, f, (int)sizeof(f),
                          (time_t)(7000 + i));
    }
    ASSERT_EQ(wps_track_count(), MAX_WPS_SESSIONS);
    ASSERT_EQ((long long)sh_evict_count(SH_EVICT_WPS_SESSION), 3);
    /* The oldest sessions went; the newest is resident. */
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, sta, &s), 1);
    sta[4] = 0; sta[5] = 0;
    ASSERT_EQ(wps_track_session(BSSID, sta, &s), 0);
    wps_track_clear();
    sh_evict_reset();
}

void run_wps_track_tests(void) {
    TEST_SUITE("wps track — session table (#82 wave 7)");
    RUN_TEST(test_session_created_and_keyed);
    RUN_TEST(test_state_machine_and_cycles);
    RUN_TEST(test_nack_without_m3_is_not_a_cycle);
    RUN_TEST(test_done_and_m8_complete);
    RUN_TEST(test_uuid_e_kept_from_m1);
    RUN_TEST(test_non_wsc_frames_ignored);
    RUN_TEST(test_lru_eviction_reaches_tally);
}
