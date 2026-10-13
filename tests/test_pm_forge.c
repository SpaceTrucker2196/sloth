#include <string.h>
#include "runner.h"
#include "pm_forge.h"
#include "beacon_snoop.h"
#include "sensor_health.h"

/*
 * PM-bit forgery (#107 shape A, Framing Frames CVE-2022-47522).
 *
 * Hand-built 802.11 data-frame headers per IEEE 802.11-2020
 * §9.2.4.1.7 (Frame Control: ToDS, PwrMgt) and §9.3.2.1 (address
 * fields for STA->AP). No payload is needed: pm_forge_observe() reads
 * only the header, so a frame is just FC + Duration + three
 * addresses + Sequence Control, plus QoS Control for QoS subtypes.
 */

#define SUB_DATA     0x0
#define SUB_QOS_DATA 0x8
#define SUB_NULL     0x4
#define SUB_QOS_NULL 0xC

static const uint8_t BSSID[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t STA_A[6] = { 0x02, 0xAA, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t STA_B[6] = { 0x02, 0xBB, 0x00, 0x00, 0x00, 0x02 };

/* STA -> AP frame: ToDS=1, FromDS=0. addr1=BSSID addr2=STA addr3=BSSID
 * (the DA is irrelevant to this module). tid is only written into the
 * QoS Control field for a QoS subtype; it is ignored otherwise. */
static int build_sta_frame(uint8_t *f, int sub, int pm,
                           const uint8_t bssid[6], const uint8_t sta[6],
                           int tid) {
    memset(f, 0, 32);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = (uint8_t)(0x01 | (pm ? 0x10 : 0));
    memcpy(f + 4,  bssid, 6);
    memcpy(f + 10, sta,   6);
    memcpy(f + 16, bssid, 6);
    int len = 24;
    if (sub & 0x08) {
        f[24] = (uint8_t)(tid & 0x0f);
        len = 26;
    }
    return len;
}

static void setup(uint16_t beacon_ms) {
    pm_forge_clear();
    beacon_clear();
    sh_evict_reset();
    if (beacon_ms)
        beacon_record(BSSID, "TestNet", -50, 6, "WPA2", beacon_ms, NULL);
}

static void test_no_entries_initially(void) {
    setup(100);
    ASSERT_EQ(pm_forge_count(), 0);
    pm_forge_t out;
    ASSERT_EQ(pm_forge_lookup(STA_A, &out), 0);
}

static void test_contradiction_within_beacon_interval(void) {
    setup(100);   /* 100 ms beacon interval */
    uint8_t f[32];
    int len;

    /* PM=1 QoS-Null on TID 0 at t=1000.000000. */
    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 0);

    /* PM=0 QoS data on TID 5, 50 ms later — inside the 100 ms window,
     * a different TID: the station kept transmitting after it had
     * just told the AP it was going to sleep. */
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 50000);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 1);
}

static void test_no_contradiction_outside_window(void) {
    setup(100);
    uint8_t f[32];
    int len;

    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 0);

    /* 150 ms later — past the 100 ms beacon interval. A station that
     * genuinely slept and was woken by new traffic falls here, and it
     * must not be flagged as a forgery. */
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 150000);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 0);
}

static void test_no_contradiction_same_tid(void) {
    setup(100);
    uint8_t f[32];
    int len;

    /* Same TID before and after: an ordinary immediate wake for more
     * traffic on the same access category, not two radios disagreeing
     * about the station's state. */
    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 0);
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 10000);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 0);
}

static void test_no_contradiction_without_known_beacon_interval(void) {
    setup(0);   /* BSSID never heard beacon — interval unknown */
    uint8_t f[32];
    int len;

    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 0);
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 10000);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    /* Not a guess: without the AP's own schedule there is no window
     * to test the gap against, so nothing is asserted either way. */
    ASSERT_EQ((int)e.contradiction_count, 0);
}

static void test_pm0_before_pm1_does_not_retroactively_count(void) {
    setup(100);
    uint8_t f[32];
    int len;

    /* PM=0 data arrives first, with no prior sleep declaration on
     * file — ordinary traffic. */
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 0);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 0);

    /* The sleep declaration comes after. On its own this is not a
     * contradiction — nothing has contradicted it yet. */
    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 10000);
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 0);

    /* Only a PM=0 data frame arriving AFTER the Null, on a different
     * TID, within the window, is the forgery shape. */
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 6);
    pm_forge_observe(f, len, 1000, 20000);
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 1);
}

static void test_out_of_order_pm0_does_not_count(void) {
    setup(100);
    uint8_t f[32];
    int len;

    /* The PM=1 Null is recorded first... */
    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 50000);

    /* ...but the PM=0 data frame that follows is stamped EARLIER —
     * out-of-order delivery, which a capture pipeline can produce.
     * A frame timestamped before the sleep declaration existed cannot
     * have been caused by it, whatever order the two reached this
     * function in. */
    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((long long)e.last_pm1_null_us, 1000050000LL);

    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 10000);

    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 0);
}

static void test_plain_null_function_tid_is_zero(void) {
    setup(100);
    uint8_t f[32];
    /* Non-QoS Null carries no QoS Control field at all; dot11_data_tid()
     * reports an implicit single queue (TID 0). A QoS data frame on
     * any other TID shortly after must still be caught. */
    int len = build_sta_frame(f, SUB_NULL, 1, BSSID, STA_A, 0);
    ASSERT_EQ(len, 24);
    pm_forge_observe(f, len, 2000, 0);

    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 3);
    pm_forge_observe(f, len, 2000, 40000);

    pm_forge_t e;
    ASSERT_EQ(pm_forge_lookup(STA_A, &e), 1);
    ASSERT_EQ((int)e.contradiction_count, 1);
}

static void test_ap_to_sta_frames_ignored(void) {
    setup(100);
    uint8_t f[32];
    memset(f, 0, 32);
    f[0] = (uint8_t)((SUB_QOS_NULL << 4) | (2 << 2));
    f[1] = 0x12;   /* FromDS=1 (bit1), PM=1 — AP never sets this, but
                    * the frame must still be ignored by direction. */
    memcpy(f + 4,  STA_A, 6);     /* DA  */
    memcpy(f + 10, BSSID, 6);     /* SA  */
    memcpy(f + 16, BSSID, 6);     /* BSSID */
    pm_forge_observe(f, 26, 1000, 0);
    ASSERT_EQ(pm_forge_count(), 0);
}

static void test_non_data_type_ignored(void) {
    setup(100);
    uint8_t f[32];
    memset(f, 0, 32);
    f[0] = 0x00;   /* type 0 (management), not type 2 */
    f[1] = 0x11;
    pm_forge_observe(f, 26, 1000, 0);
    ASSERT_EQ(pm_forge_count(), 0);
}

static void test_distinct_stations_isolated(void) {
    setup(100);
    uint8_t f[32];
    int len;

    len = build_sta_frame(f, SUB_QOS_NULL, 1, BSSID, STA_A, 0);
    pm_forge_observe(f, len, 1000, 0);
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_A, 5);
    pm_forge_observe(f, len, 1000, 10000);

    /* STA_B never sent a sleep declaration, so its own PM=0 traffic
     * must not borrow STA_A's. */
    len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, STA_B, 5);
    pm_forge_observe(f, len, 1000, 10000);

    ASSERT_EQ(pm_forge_count(), 2);
    pm_forge_t a, b;
    ASSERT_EQ(pm_forge_lookup(STA_A, &a), 1);
    ASSERT_EQ(pm_forge_lookup(STA_B, &b), 1);
    ASSERT_EQ((int)a.contradiction_count, 1);
    ASSERT_EQ((int)b.contradiction_count, 0);
}

static void test_eviction_counted_and_floor_safe(void) {
    setup(100);
    uint8_t f[32];
    uint8_t sta[6] = { 0x02, 0, 0, 0, 0, 0 };

    for (int i = 0; i < MAX_PM_FORGE_ENTRIES; i++) {
        sta[5] = (uint8_t)i;
        int len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, sta, 1);
        pm_forge_observe(f, len, 1000 + i, 0);
    }
    ASSERT_EQ(pm_forge_count(), MAX_PM_FORGE_ENTRIES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PM_FORGE), 0);

    /* One more distinct station overflows the table; the
     * least-recently-seen entry (sta[5]==0, stamped at t=1000) is the
     * one that must go. */
    sta[5] = (uint8_t)MAX_PM_FORGE_ENTRIES;
    int len = build_sta_frame(f, SUB_QOS_DATA, 0, BSSID, sta, 1);
    pm_forge_observe(f, len, 1000 + MAX_PM_FORGE_ENTRIES, 0);

    ASSERT_EQ(pm_forge_count(), MAX_PM_FORGE_ENTRIES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_PM_FORGE), 1);

    uint8_t gone[6] = { 0x02, 0, 0, 0, 0, 0 };
    pm_forge_t out;
    ASSERT_EQ(pm_forge_lookup(gone, &out), 0);
}

void run_pm_forge_tests(void) {
    TEST_SUITE("pm_forge — PM-bit forgery (#107 shape A)");
    RUN_TEST(test_no_entries_initially);
    RUN_TEST(test_contradiction_within_beacon_interval);
    RUN_TEST(test_no_contradiction_outside_window);
    RUN_TEST(test_no_contradiction_same_tid);
    RUN_TEST(test_no_contradiction_without_known_beacon_interval);
    RUN_TEST(test_pm0_before_pm1_does_not_retroactively_count);
    RUN_TEST(test_out_of_order_pm0_does_not_count);
    RUN_TEST(test_plain_null_function_tid_is_zero);
    RUN_TEST(test_ap_to_sta_frames_ignored);
    RUN_TEST(test_non_data_type_ignored);
    RUN_TEST(test_distinct_stations_isolated);
    RUN_TEST(test_eviction_counted_and_floor_safe);
}
