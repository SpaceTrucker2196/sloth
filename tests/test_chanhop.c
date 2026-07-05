#include "runner.h"
#include "wifi_chanhop.h"

/* Channel → frequency mapping across both supported bands. */
static void test_freq_mapping(void) {
    ASSERT_EQ(chanhop_freq(1),   2412);
    ASSERT_EQ(chanhop_freq(6),   2437);
    ASSERT_EQ(chanhop_freq(11),  2462);
    ASSERT_EQ(chanhop_freq(14),  2484);
    ASSERT_EQ(chanhop_freq(36),  5180);
    ASSERT_EQ(chanhop_freq(161), 5805);
    ASSERT_EQ(chanhop_freq(0),   0);     /* invalid */
    ASSERT_EQ(chanhop_freq(200), 0);     /* out of range */
}

static void test_init_default(void) {
    chanhop_t h;
    int n = chanhop_init_default(&h);
    ASSERT_EQ(n, 11);
    ASSERT_EQ(h.count, 11);
    ASSERT_EQ(chanhop_current_channel(&h), 1);   /* first default channel */
    ASSERT_EQ(h.started, 0);                      /* no retune issued yet */
}

/* init skips channels that don't map to a frequency. */
static void test_init_skips_unknown(void) {
    chanhop_t h;
    int chans[] = { 6, 9999, 36 };
    int n = chanhop_init(&h, chans, 3);
    ASSERT_EQ(n, 2);
    ASSERT_EQ(h.slots[0].channel, 6);
    ASSERT_EQ(h.slots[1].channel, 36);
}

/* First tick parks on channel[0]; the dwell must elapse before advancing. */
static void test_first_tick_then_dwell(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);

    ASSERT_EQ(chanhop_tick(&h, 1000), 1);          /* first retune */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    ASSERT_EQ(chanhop_current_freq(&h), 2412);

    ASSERT_EQ(chanhop_tick(&h, 1050), 0);          /* base 250ms not elapsed */
    ASSERT_EQ(chanhop_current_channel(&h), 1);

    ASSERT_EQ(chanhop_tick(&h, 1000 + 250), 1);    /* dwell elapsed → advance */
    ASSERT_EQ(chanhop_current_channel(&h), 6);
}

/* Rotation guarantees every channel is revisited each cycle. */
static void test_rotation_revisits_all(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    uint64_t t = 0;
    chanhop_tick(&h, t);                            /* → ch 1 */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    for (int i = 0; i < 3; i++) t += 250, chanhop_tick(&h, t);  /* full cycle */
    ASSERT_EQ(chanhop_current_channel(&h), 1);      /* back to the start */
}

/* A busy channel earns a longer dwell than a quiet one. */
static void test_activity_lengthens_dwell(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;

    chanhop_tick(&h, t);                            /* park on ch 1 (quiet) */
    /* pile activity onto ch 1 while dwelling */
    chanhop_observe(&h, 300);                       /* >> ms_per_obs*n saturates */

    t += 250; chanhop_tick(&h, t);                  /* ch 1 quiet-dwell elapsed → ch 6 */
    ASSERT_EQ(chanhop_current_channel(&h), 6);
    t += 250; chanhop_tick(&h, t);                  /* ch 6 base dwell → back to ch 1 */
    ASSERT_EQ(chanhop_current_channel(&h), 1);

    /* ch 1 carried heavy (decayed) activity, so its dwell now exceeds base:
     * after base+1 ms it must still be dwelling. */
    ASSERT_EQ(chanhop_tick(&h, t + 251), 0);        /* still on ch 1 — longer dwell */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    /* but the cap bounds it: it releases by max_dwell. */
    ASSERT_EQ(chanhop_tick(&h, t + h.max_dwell_ms), 1);
    ASSERT_EQ(chanhop_current_channel(&h), 6);
}

/* Activity decays each visit so an old burst doesn't hold a long dwell
 * forever. */
static void test_activity_decays(void) {
    chanhop_t h;
    int chans[] = { 1 };                            /* single channel: revisits itself */
    chanhop_init(&h, chans, 1);
    chanhop_tick(&h, 0);
    chanhop_observe(&h, 1000);
    uint32_t a0 = h.slots[0].activity;              /* 1000 */
    chanhop_tick(&h, h.max_dwell_ms);               /* leave → halve */
    uint32_t a1 = h.slots[0].activity;
    ASSERT_LT((int)a1, (int)a0);
    ASSERT_EQ((int)a1, 500);
}

void run_chanhop_tests(void) {
    TEST_SUITE("wifi channel hopper");
    RUN_TEST(test_freq_mapping);
    RUN_TEST(test_init_default);
    RUN_TEST(test_init_skips_unknown);
    RUN_TEST(test_first_tick_then_dwell);
    RUN_TEST(test_rotation_revisits_all);
    RUN_TEST(test_activity_lengthens_dwell);
    RUN_TEST(test_activity_decays);
}
