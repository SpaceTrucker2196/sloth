#include "runner.h"
#include "wifi_chanhop.h"
#include <string.h>

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

/* Export the channel list + current index for the UI scan bar. */
static void test_export(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    int out[8], cur;

    int n = chanhop_export(&h, out, 8, &cur);
    ASSERT_EQ(n, 3);
    ASSERT_EQ(out[0], 1); ASSERT_EQ(out[1], 6); ASSERT_EQ(out[2], 11);
    ASSERT_EQ(cur, -1);                 /* not started yet */

    chanhop_tick(&h, 0);                /* park on channel[0] */
    chanhop_export(&h, out, 8, &cur);
    ASSERT_EQ(cur, 0);

    chanhop_tick(&h, 1000);            /* dwell elapsed → advance */
    chanhop_export(&h, out, 8, &cur);
    ASSERT_EQ(cur, 1);
}

/* ── retune result bookkeeping (issue #91 slice 1) ──────────
 * chanhop_drive() used to call set_channel() and discard the return
 * code, so a failed retune was indistinguishable from a healthy quiet
 * radio. chanhop_record_retune() is the pure logic pulled out of that
 * caller so it's testable without a live radio or main.c's g_platform. */

static void test_retune_success_confirms_channel(void) {
    int requested = 0, confirmed = 0, failures = 0;
    chanhop_record_retune(11, 1, &requested, &confirmed, &failures);
    ASSERT_EQ(requested, 11);
    ASSERT_EQ(confirmed, 11);
    ASSERT_EQ(failures, 0);
}

static void test_retune_failure_leaves_confirmed_behind(void) {
    /* Radio was last confirmed on channel 6; a failed request to move to
     * 11 must record the request but NOT advance confirmed — the radio
     * may still be sitting on 6. */
    int requested = 6, confirmed = 6, failures = 0;
    chanhop_record_retune(11, 0, &requested, &confirmed, &failures);
    ASSERT_EQ(requested, 11);
    ASSERT_EQ(confirmed, 6);      /* unchanged */
    ASSERT_EQ(failures, 1);
}

static void test_retune_failures_accumulate_across_successes(void) {
    /* The failure counter is a lifetime tally (issue #91: sensor health
     * should stay visible), so a later success must not reset it. */
    int requested = 0, confirmed = 0, failures = 0;
    chanhop_record_retune(1, 0, &requested, &confirmed, &failures);
    chanhop_record_retune(6, 0, &requested, &confirmed, &failures);
    ASSERT_EQ(failures, 2);
    ASSERT_EQ(confirmed, 0);      /* never confirmed yet */
    chanhop_record_retune(11, 1, &requested, &confirmed, &failures);
    ASSERT_EQ(failures, 2);       /* success doesn't clear prior failures */
    ASSERT_EQ(confirmed, 11);
    chanhop_record_retune(36, 0, &requested, &confirmed, &failures);
    ASSERT_EQ(failures, 3);       /* keeps counting after a success too */
    ASSERT_EQ(confirmed, 11);     /* still the last confirmed channel */
}

static void test_retune_null_outputs_do_not_crash(void) {
    chanhop_record_retune(11, 1, NULL, NULL, NULL);
    chanhop_record_retune(11, 0, NULL, NULL, NULL);
}

/* ââ hop activity (#91 wave 7) âââââââââââââââââââââ */

static void test_activity_counts_visits_and_frames(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    chanhop_activity_t a;

    /* Before the first tick nothing has been visited. */
    chanhop_activity(&h, &a);
    ASSERT_EQ(a.channels, 3);
    ASSERT_EQ((long long)a.visits, 0);
    ASSERT_EQ((long long)a.frames, 0);
    ASSERT_EQ(a.silent_channels, 0);   /* unvisited != silent */

    uint64_t t = 0;
    chanhop_tick(&h, t);               /* -> ch 1, visit 1 */
    chanhop_observe(&h, 40);
    t += 250; chanhop_tick(&h, t);     /* -> ch 6, visit 2 */
    chanhop_observe(&h, 2);
    chanhop_activity(&h, &a);
    ASSERT_EQ((long long)a.visits, 2);
    ASSERT_EQ((long long)a.frames, 42);
    ASSERT_EQ((long long)a.cur_visits, 1);
    ASSERT_EQ((long long)a.cur_frames, 2);
    ASSERT_EQ(a.silent_channels, 0);
}

static void test_activity_frames_survive_decay(void) {
    /* The scheduler's `activity` halves each time it leaves a channel;
       the lifetime frame tally must not, or the operator's "did this
       channel ever produce anything" answer would erode on its own. */
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;
    chanhop_tick(&h, t);
    chanhop_observe(&h, 100);
    for (int i = 0; i < 4; i++) { t += 2000; chanhop_tick(&h, t); }
    chanhop_activity_t a;
    chanhop_activity(&h, &a);
    ASSERT_EQ((long long)a.frames, 100);
}

static void test_activity_flags_silent_visited_channel(void) {
    /* The "tuned but deaf" shape: every channel visited, one of them
       never producing a frame. */
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;
    chanhop_tick(&h, t);               /* -> ch 1 */
    chanhop_observe(&h, 7);
    t += 2000; chanhop_tick(&h, t);    /* -> ch 6, hears nothing */
    chanhop_activity_t a;
    chanhop_activity(&h, &a);
    ASSERT_EQ(a.silent_channels, 1);
    ASSERT_EQ((long long)a.cur_frames, 0);
    ASSERT_GT((long long)a.cur_visits, 0);
    /* Once it hears something it is no longer silent. */
    chanhop_observe(&h, 1);
    chanhop_activity(&h, &a);
    ASSERT_EQ(a.silent_channels, 0);
}

static void test_activity_null_and_empty_are_zero(void) {
    chanhop_activity_t a;
    chanhop_activity(NULL, &a);
    ASSERT_EQ(a.channels, 0);
    ASSERT_EQ((long long)a.visits, 0);
    chanhop_t h;
    memset(&h, 0, sizeof(h));
    chanhop_activity(&h, &a);          /* initialised but no channels */
    ASSERT_EQ(a.channels, 0);
    chanhop_activity(&h, NULL);        /* no crash */
}

/* ââ measured vs configured dwell (#91 wave 7) ââââââââ */

static void test_dwell_measures_exact_service(void) {
    /* Ticked precisely when each dwell expires: measured == planned and
       nothing overshoots. The baseline the divergence case is read
       against. */
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    uint64_t t = 0;
    chanhop_tick(&h, t);                 /* start dwell 1, planned 250 */
    for (int i = 0; i < 3; i++) { t += 250; chanhop_tick(&h, t); }
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 3);
    ASSERT_EQ((long long)d.last_planned_ms, 250);
    ASSERT_EQ((long long)d.last_measured_ms, 250);
    ASSERT_EQ((long long)d.mean_planned_ms, 250);
    ASSERT_EQ((long long)d.mean_measured_ms, 250);
    ASSERT_EQ((long long)d.worst_overshoot_ms, 0);
}

static void test_dwell_records_poll_interval_overshoot(void) {
    /* The bug this slice exists for: a 250 ms plan serviced by a 1 s
       poll loop means the radio actually sits for 1 s, and the
       scheduler's airtime model is wrong by 4x with nothing saying so. */
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    uint64_t t = 0;
    chanhop_tick(&h, t);
    for (int i = 0; i < 3; i++) { t += 1000; chanhop_tick(&h, t); }
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 3);
    ASSERT_EQ((long long)d.mean_planned_ms, 250);
    ASSERT_EQ((long long)d.mean_measured_ms, 1000);
    ASSERT_EQ((long long)d.worst_overshoot_ms, 750);
}

static void test_dwell_worst_overshoot_is_a_high_water_mark(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;
    chanhop_tick(&h, t);
    t += 900;  chanhop_tick(&h, t);      /* overshoot 650 */
    t += 250;  chanhop_tick(&h, t);      /* on time */
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.last_measured_ms, 250);
    ASSERT_EQ((long long)d.last_planned_ms, 250);
    ASSERT_EQ((long long)d.worst_overshoot_ms, 650);   /* not reset */
}

static void test_dwell_plan_follows_activity(void) {
    /* A busy channel earns a longer plan, and the measurement follows
       the plan rather than a fixed base. */
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;
    chanhop_tick(&h, t);                 /* on ch 1, plan 250 */
    chanhop_observe(&h, 50);
    t += 250; chanhop_tick(&h, t);       /* -> ch 6, plan 250 */
    t += 250; chanhop_tick(&h, t);       /* -> ch 1; activity halved to
                                            25 on departure, so the new
                                            plan is 250 + 25*8 = 450 */
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    /* last_* describe the dwell that ENDED, so the boosted plan is not
       visible until the longer dwell itself completes. */
    ASSERT_EQ((long long)d.last_planned_ms, 250);
    ASSERT_EQ((long long)d.completed, 2);

    t += 450; chanhop_tick(&h, t);
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.last_planned_ms, 450);
    ASSERT_EQ((long long)d.last_measured_ms, 450);
    ASSERT_EQ((long long)d.completed, 3);
    ASSERT_EQ((long long)d.worst_overshoot_ms, 0);
}

static void test_dwell_zero_before_first_completion(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 0);
    ASSERT_EQ((long long)d.mean_planned_ms, 0);   /* no division by zero */
    ASSERT_EQ((long long)d.mean_measured_ms, 0);
    chanhop_tick(&h, 0);                 /* started, none ended yet */
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 0);
    chanhop_dwell(NULL, &d);
    ASSERT_EQ((long long)d.completed, 0);
    chanhop_dwell(&h, NULL);             /* no crash */
}

void run_chanhop_tests(void) {
    TEST_SUITE("wifi channel hopper");
    RUN_TEST(test_export);
    RUN_TEST(test_freq_mapping);
    RUN_TEST(test_init_default);
    RUN_TEST(test_init_skips_unknown);
    RUN_TEST(test_first_tick_then_dwell);
    RUN_TEST(test_rotation_revisits_all);
    RUN_TEST(test_activity_lengthens_dwell);
    RUN_TEST(test_activity_decays);
    RUN_TEST(test_retune_success_confirms_channel);
    RUN_TEST(test_retune_failure_leaves_confirmed_behind);
    RUN_TEST(test_retune_failures_accumulate_across_successes);
    RUN_TEST(test_retune_null_outputs_do_not_crash);

    TEST_SUITE("wifi channel hopper: hop activity (#91)");
    RUN_TEST(test_activity_counts_visits_and_frames);
    RUN_TEST(test_activity_frames_survive_decay);
    RUN_TEST(test_activity_flags_silent_visited_channel);
    RUN_TEST(test_activity_null_and_empty_are_zero);

    TEST_SUITE("wifi channel hopper: measured vs configured dwell (#91)");
    RUN_TEST(test_dwell_measures_exact_service);
    RUN_TEST(test_dwell_records_poll_interval_overshoot);
    RUN_TEST(test_dwell_worst_overshoot_is_a_high_water_mark);
    RUN_TEST(test_dwell_plan_follows_activity);
    RUN_TEST(test_dwell_zero_before_first_completion);
}
