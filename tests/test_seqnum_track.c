#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "seqnum_track.h"

static void mac(uint8_t out[6], uint8_t la, uint8_t b1, uint8_t b2,
                                  uint8_t b3, uint8_t b4, uint8_t b5) {
    out[0] = la; out[1] = b1; out[2] = b2;
    out[3] = b3; out[4] = b4; out[5] = b5;
}

static void test_empty(void) {
    seqnum_clear();
    ASSERT_EQ(seqnum_client_count(), 0);
}

static void test_multicast_skipped(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01);  /* mcast */
    seqnum_track_observe(m, 1000);
    ASSERT_EQ(seqnum_client_count(), 0);
}

static void test_single_client_history(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe(m, 100);
    seqnum_track_observe(m, 101);
    seqnum_track_observe(m, 102);
    ASSERT_EQ(seqnum_client_count(), 1);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_count, 1);
    /* Newest first. */
    ASSERT_EQ((int)s.seqnum_clients[0].hist[0], 102);
    ASSERT_EQ((int)s.seqnum_clients[0].hist[1], 101);
    ASSERT_EQ((int)s.seqnum_clients[0].hist[2], 100);
    ASSERT_EQ(s.seqnum_clients[0].hist_n, 3);
    ASSERT_EQ(s.seqnum_clients[0].frame_count, 3);
}

static void test_random_flag(void) {
    seqnum_clear();
    uint8_t real[6];   mac(real,   0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t random[6]; mac(random, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55);
    seqnum_track_observe(real,   100);
    seqnum_track_observe(random, 200);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_count, 2);
    /* Find each by MAC. */
    int found_real = 0, found_random = 0;
    for (int i = 0; i < s.seqnum_count; i++) {
        if (memcmp(s.seqnum_clients[i].mac, real, 6) == 0) {
            ASSERT_EQ(s.seqnum_clients[i].mac_random, 0); found_real = 1;
        } else if (memcmp(s.seqnum_clients[i].mac, random, 6) == 0) {
            ASSERT_EQ(s.seqnum_clients[i].mac_random, 1); found_random = 1;
        }
    }
    ASSERT_EQ(found_real,   1);
    ASSERT_EQ(found_random, 1);
}

static void test_correlation_detects_adjacent_seqnums(void) {
    seqnum_clear();
    uint8_t real[6];   mac(real,   0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t random[6]; mac(random, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    /* Same physical device burning monotonic seqnums across a MAC
     * rotation: 100, 101 (real) then 102, 103 (randomised). */
    seqnum_track_observe(real,   100);
    seqnum_track_observe(real,   101);
    seqnum_track_observe(random, 102);
    seqnum_track_observe(random, 103);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_correlation_count, 1);
    const seqnum_correlation_t *c = &s.seqnum_correlations[0];
    /* Gap between 101 (newest of real) and 102 (oldest of random) = 1.
     * try_correlate looks across all pairs; it could be even less. */
    ASSERT_LT(c->gap, 5);
    /* At least one side is randomised. */
    ASSERT(c->mac_a_random || c->mac_b_random);
}

static void test_no_correlation_when_far_apart(void) {
    seqnum_clear();
    uint8_t a[6]; mac(a, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    uint8_t b[6]; mac(b, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee);
    seqnum_track_observe(a, 100);
    /* gap 2000 — well outside the 64-seqnum window. */
    seqnum_track_observe(b, 2100);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_correlation_count, 0);
}

static void test_history_caps_at_ring_size(void) {
    seqnum_clear();
    uint8_t m[6]; mac(m, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    for (int i = 0; i < SEQNUM_HISTORY_LEN + 5; i++) {
        seqnum_track_observe(m, (uint16_t)(1000 + i));
    }
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seqnum_snapshot(&s);
    ASSERT_EQ(s.seqnum_clients[0].hist_n, SEQNUM_HISTORY_LEN);
    /* Newest = last value pushed. */
    int last = 1000 + SEQNUM_HISTORY_LEN + 5 - 1;
    ASSERT_EQ((int)s.seqnum_clients[0].hist[0], last);
}

void run_seqnum_track_tests(void) {
    TEST_SUITE("seqnum_track");
    RUN_TEST(test_empty);
    RUN_TEST(test_multicast_skipped);
    RUN_TEST(test_single_client_history);
    RUN_TEST(test_random_flag);
    RUN_TEST(test_correlation_detects_adjacent_seqnums);
    RUN_TEST(test_no_correlation_when_far_apart);
    RUN_TEST(test_history_caps_at_ring_size);
}
