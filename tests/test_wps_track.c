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

/* ── Windowed cycle rate + snapshot (#82 wave 8) ──────────
 *
 * The rate is the whole point: a session that accumulated five cycles
 * over an afternoon is not the same observation as one that did it in
 * a minute, and cycle_count alone cannot tell them apart. */

/* One completed M1→M3→NACK restart cycle at `at`. */
static void cycle_at(const uint8_t sta[6], time_t at) {
    wsc_feed(sta, WSC_OP_MSG,  WSC_MSG_M1,   at);
    wsc_feed(sta, WSC_OP_MSG,  WSC_MSG_M3,   at);
    wsc_feed(sta, WSC_OP_NACK, WSC_MSG_NACK, at);
}

static void test_cycles_since_counts_only_the_window(void) {
    wps_track_clear();
    /* Three cycles well over an hour ago, two just now. */
    for (int i = 0; i < 3; i++) cycle_at(STA_A, 9000 + i);
    for (int i = 0; i < 2; i++) cycle_at(STA_A, 13600 + i);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.cycle_count, 5);                              /* lifetime */
    ASSERT_EQ(wps_track_cycles_since(&s, 13601, 60), 2);      /* windowed */
    ASSERT_EQ(wps_track_cycles_since(&s, 13601, 3600), 2);
    ASSERT_EQ(wps_track_cycles_since(&s, 13601, 7200), 5);
    /* A window that predates every cycle counts none, and a
     * nonsensical window is not a free pass. */
    ASSERT_EQ(wps_track_cycles_since(&s, 20000, 60), 0);
    ASSERT_EQ(wps_track_cycles_since(&s, 13601, 0), 0);
    ASSERT_EQ(wps_track_cycles_since(NULL, 13601, 60), 0);
    wps_track_clear();
}

static void test_cycles_since_is_inclusive_at_the_edge(void) {
    /* A cycle exactly `window_s` old is inside the window. An
     * exclusive bound here would make the documented "5 in 60 s"
     * silently mean 5 in 59. */
    wps_track_clear();
    cycle_at(STA_A, 1000);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(wps_track_cycles_since(&s, 1060, 60), 1);
    ASSERT_EQ(wps_track_cycles_since(&s, 1061, 60), 0);
    wps_track_clear();
}

static void test_cycle_ring_saturates_without_overcounting(void) {
    /* More cycles than the ring holds: the lifetime count keeps
     * rising, the windowed answer saturates at the ring size. Under-
     * reporting is the safe direction for a floor — a brute force that
     * overran the ring has already fired. */
    wps_track_clear();
    for (int i = 0; i < WPS_CYCLE_RING + 5; i++) cycle_at(STA_A, 2000 + i);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.cycle_count, WPS_CYCLE_RING + 5);
    ASSERT_EQ(wps_track_cycles_since(&s, 2020, 60), WPS_CYCLE_RING);
    /* Wrapped slots hold the NEWEST stamps, not the oldest: a window
     * covering only the last few cycles must still find them. */
    ASSERT_EQ(wps_track_cycles_since(&s, 2012, 3), 4);
    wps_track_clear();
}

static void test_a_session_with_no_cycles_reports_none(void) {
    wps_track_clear();
    wsc_feed(STA_A, WSC_OP_MSG, WSC_MSG_M1, 3000);
    wps_session_t s;
    ASSERT_EQ(wps_track_session(BSSID, STA_A, &s), 1);
    ASSERT_EQ(s.cycle_count, 0);
    ASSERT_EQ(wps_track_cycles_since(&s, 3000, 86400), 0);
    wps_track_clear();
}

static void test_an_unwritten_ring_slot_is_not_the_epoch(void) {
    /* wps_track_cycles_since reads a caller-supplied copy, so it is
     * answerable for what it does with one whose stamps disagree with
     * its count — a slot holding 0 is unwritten, not a cycle that
     * completed in 1970. Without the guard, a window reaching back
     * past the epoch (now - window_s < 0) counts every empty slot and
     * manufactures a brute force out of a session that had none. */
    wps_session_t s;
    memset(&s, 0, sizeof(s));
    s.cycle_count = 3;                 /* claims 3, carries no stamps */
    ASSERT_EQ(wps_track_cycles_since(&s, 100, 86400), 0);
    s.cycle_ts[1] = 90;                /* one real stamp among them */
    ASSERT_EQ(wps_track_cycles_since(&s, 100, 86400), 1);
    ASSERT_EQ(wps_track_cycles_since(&s, 100, 5), 0);
}

static void test_snapshot_copies_every_live_session(void) {
    wps_track_clear();
    wsc_feed(STA_A, WSC_OP_MSG, WSC_MSG_M1, 4000);
    wsc_feed(STA_B, WSC_OP_MSG, WSC_MSG_M1, 4001);
    wps_session_t out[MAX_WPS_SESSIONS];
    ASSERT_EQ(wps_track_snapshot(out, MAX_WPS_SESSIONS), 2);
    int saw_a = 0, saw_b = 0;
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(memcmp(out[i].bssid, BSSID, 6), 0);
        if (memcmp(out[i].sta, STA_A, 6) == 0) saw_a = 1;
        if (memcmp(out[i].sta, STA_B, 6) == 0) saw_b = 1;
    }
    ASSERT_EQ(saw_a, 1);
    ASSERT_EQ(saw_b, 1);
    /* Bounded by the caller's buffer, and safe at the edges. */
    ASSERT_EQ(wps_track_snapshot(out, 1), 1);
    ASSERT_EQ(wps_track_snapshot(out, 0), 0);
    ASSERT_EQ(wps_track_snapshot(NULL, 4), 0);
    wps_track_clear();
    ASSERT_EQ(wps_track_snapshot(out, MAX_WPS_SESSIONS), 0);
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

    TEST_SUITE("wps track — cycle rate + snapshot (#82 wave 8)");
    RUN_TEST(test_cycles_since_counts_only_the_window);
    RUN_TEST(test_cycles_since_is_inclusive_at_the_edge);
    RUN_TEST(test_cycle_ring_saturates_without_overcounting);
    RUN_TEST(test_a_session_with_no_cycles_reports_none);
    RUN_TEST(test_an_unwritten_ring_slot_is_not_the_epoch);
    RUN_TEST(test_snapshot_copies_every_live_session);
}
