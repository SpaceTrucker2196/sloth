#include "runner.h"
#include "wifi_chanhop.h"
#include "fake_platform.h"
#include <errno.h>
#include <string.h>

#if defined(PLATFORM_LINUX) && defined(WITH_WIFI)
#include <linux/netlink.h>
#include "platform/linux_wifi.h"
#endif

/* One tick against a radio that acknowledges every retune. Since #91
 * tick only proposes and chanhop_confirm_retune() commits, so the
 * scheduler tests below — written when tick did both — drive it through
 * this. Returns tick's own answer. */
static int hop(chanhop_t *h, uint64_t now_ms) {
    int r = chanhop_tick(h, now_ms);
    if (r) chanhop_confirm_retune(h, 1, now_ms);
    return r;
}

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

    ASSERT_EQ(hop(&h, 1000), 1);          /* first retune */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    ASSERT_EQ(chanhop_current_freq(&h), 2412);

    ASSERT_EQ(hop(&h, 1050), 0);          /* base 250ms not elapsed */
    ASSERT_EQ(chanhop_current_channel(&h), 1);

    ASSERT_EQ(hop(&h, 1000 + 250), 1);    /* dwell elapsed → advance */
    ASSERT_EQ(chanhop_current_channel(&h), 6);
}

/* Rotation guarantees every channel is revisited each cycle. */
static void test_rotation_revisits_all(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    uint64_t t = 0;
    hop(&h, t);                            /* → ch 1 */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    for (int i = 0; i < 3; i++) t += 250, hop(&h, t);  /* full cycle */
    ASSERT_EQ(chanhop_current_channel(&h), 1);      /* back to the start */
}

/* A busy channel earns a longer dwell than a quiet one. */
static void test_activity_lengthens_dwell(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    uint64_t t = 0;

    hop(&h, t);                            /* park on ch 1 (quiet) */
    /* pile activity onto ch 1 while dwelling */
    chanhop_observe(&h, 300);                       /* >> ms_per_obs*n saturates */

    t += 250; hop(&h, t);                  /* ch 1 quiet-dwell elapsed → ch 6 */
    ASSERT_EQ(chanhop_current_channel(&h), 6);
    t += 250; hop(&h, t);                  /* ch 6 base dwell → back to ch 1 */
    ASSERT_EQ(chanhop_current_channel(&h), 1);

    /* ch 1 carried heavy (decayed) activity, so its dwell now exceeds base:
     * after base+1 ms it must still be dwelling. */
    ASSERT_EQ(hop(&h, t + 251), 0);        /* still on ch 1 — longer dwell */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    /* but the cap bounds it: it releases by max_dwell. */
    ASSERT_EQ(hop(&h, t + h.max_dwell_ms), 1);
    ASSERT_EQ(chanhop_current_channel(&h), 6);
}

/* Activity decays each visit so an old burst doesn't hold a long dwell
 * forever. */
static void test_activity_decays(void) {
    chanhop_t h;
    int chans[] = { 1 };                            /* single channel: revisits itself */
    chanhop_init(&h, chans, 1);
    hop(&h, 0);
    chanhop_observe(&h, 1000);
    uint32_t a0 = h.slots[0].activity;              /* 1000 */
    hop(&h, h.max_dwell_ms);               /* leave → halve */
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

    hop(&h, 0);                /* park on channel[0] */
    chanhop_export(&h, out, 8, &cur);
    ASSERT_EQ(cur, 0);

    hop(&h, 1000);            /* dwell elapsed → advance */
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
    /* chanhop_record_retune is pure logic with no state of its own —
     * every observable lives in the caller's out-params, so with all
     * three NULL there is nothing left to assert except that it
     * returned at all. ASSERT(1) marks that deliberately rather than
     * leaving the test with zero recorded assertions (#114). */
    chanhop_record_retune(11, 1, NULL, NULL, NULL);
    chanhop_record_retune(11, 0, NULL, NULL, NULL);
    ASSERT(1);
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
    hop(&h, t);               /* -> ch 1, visit 1 */
    chanhop_observe(&h, 40);
    t += 250; hop(&h, t);     /* -> ch 6, visit 2 */
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
    hop(&h, t);
    chanhop_observe(&h, 100);
    for (int i = 0; i < 4; i++) { t += 2000; hop(&h, t); }
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
    hop(&h, t);               /* -> ch 1 */
    chanhop_observe(&h, 7);
    t += 2000; hop(&h, t);    /* -> ch 6, hears nothing */
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
    hop(&h, t);                 /* start dwell 1, planned 250 */
    for (int i = 0; i < 3; i++) { t += 250; hop(&h, t); }
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
    hop(&h, t);
    for (int i = 0; i < 3; i++) { t += 1000; hop(&h, t); }
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
    hop(&h, t);
    t += 900;  hop(&h, t);      /* overshoot 650 */
    t += 250;  hop(&h, t);      /* on time */
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
    hop(&h, t);                 /* on ch 1, plan 250 */
    chanhop_observe(&h, 50);
    t += 250; hop(&h, t);       /* -> ch 6, plan 250 */
    t += 250; hop(&h, t);       /* -> ch 1; activity halved to
                                            25 on departure, so the new
                                            plan is 250 + 25*8 = 450 */
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    /* last_* describe the dwell that ENDED, so the boosted plan is not
       visible until the longer dwell itself completes. */
    ASSERT_EQ((long long)d.last_planned_ms, 250);
    ASSERT_EQ((long long)d.completed, 2);

    t += 450; hop(&h, t);
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
    hop(&h, 0);                 /* started, none ended yet */
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 0);
    chanhop_dwell(NULL, &d);
    ASSERT_EQ((long long)d.completed, 0);
    chanhop_dwell(&h, NULL);             /* no crash */
}

/* ── Retune handshake (#91) ──────────────────────────────────────────
 *
 * The dwell used to be stamped inside chanhop_tick(), before the caller
 * had issued the retune, so a refused retune still gave the unreached
 * channel a visit, a dwell and every frame heard afterwards. */

static void test_tick_proposes_without_moving(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    ASSERT_EQ(chanhop_target_channel(&h), 0);      /* nothing asked yet */
    hop(&h, 0);                                    /* on ch 1 */
    ASSERT_EQ(chanhop_tick(&h, 250), 1);
    ASSERT_EQ(chanhop_target_channel(&h), 6);
    ASSERT_EQ(chanhop_target_freq(&h), 2437);
    /* Not answered yet: the radio is still on 1, and 6 has nothing. */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    ASSERT_EQ((long long)h.slots[1].visits, 0);
    /* Asked again, the same target — an unanswered proposal is not
     * skipped past. */
    ASSERT_EQ(chanhop_tick(&h, 260), 1);
    ASSERT_EQ(chanhop_target_channel(&h), 6);
    chanhop_confirm_retune(&h, 1, 260);
    ASSERT_EQ(chanhop_current_channel(&h), 6);
    ASSERT_EQ(chanhop_target_channel(&h), 0);
    ASSERT_EQ((long long)h.slots[1].visits, 1);
}

static void test_refused_retune_accrues_nothing_on_target(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    hop(&h, 0);                                    /* on ch 1 */
    chanhop_observe(&h, 5);
    ASSERT_EQ(chanhop_tick(&h, 250), 1);           /* asks for 6 */
    chanhop_confirm_retune(&h, 0, 250);            /* driver says no */

    /* The radio never reached 6: no visit, no frames, no dwell closed. */
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    ASSERT_EQ((long long)h.slots[1].visits, 0);
    ASSERT_EQ((long long)h.slots[1].refusals, 1);
    chanhop_observe(&h, 7);                        /* heard on 1, still */
    ASSERT_EQ((long long)h.slots[0].frames, 12);
    ASSERT_EQ((long long)h.slots[1].frames, 0);
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 0);
    int out[3], cur = -2;
    chanhop_export(&h, out, 3, &cur);
    ASSERT_EQ(cur, 0);                             /* scan bar marks 1 */
    chanhop_activity_t a;
    chanhop_activity(&h, &a);
    ASSERT_EQ((long long)a.visits, 1);
    ASSERT_EQ(a.silent_channels, 0);               /* 6 was never visited */
}

static void test_refused_channel_is_skipped_and_dwell_spans_it(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    chanhop_init(&h, chans, 3);
    hop(&h, 0);
    chanhop_tick(&h, 250);
    chanhop_confirm_retune(&h, 0, 250);            /* 6 refused */
    /* Retry waits min_dwell_ms, not a poll: a radio refusing everything
     * must not be asked every tick. */
    ASSERT_EQ(chanhop_tick(&h, 250 + h.min_dwell_ms - 1), 0);
    ASSERT_EQ(chanhop_tick(&h, 250 + h.min_dwell_ms), 1);
    ASSERT_EQ(chanhop_target_channel(&h), 11);     /* skips the refused one */
    chanhop_confirm_retune(&h, 1, 350);
    ASSERT_EQ(chanhop_current_channel(&h), 11);
    /* The dwell on 1 ran until the radio actually left it, refused
     * attempt included. */
    chanhop_dwell_t d;
    chanhop_dwell(&h, &d);
    ASSERT_EQ((long long)d.completed, 1);
    ASSERT_EQ((long long)d.last_measured_ms, 350);
    ASSERT_EQ((long long)d.last_planned_ms, 250);
    ASSERT_EQ((long long)d.worst_overshoot_ms, 100);
}

static void test_refused_first_retune_leaves_radio_untuned(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    ASSERT_EQ(chanhop_tick(&h, 0), 1);
    chanhop_confirm_retune(&h, 0, 0);
    /* Nothing was ever acknowledged, so nothing is attributed: the
     * frames below were heard on whatever channel the radio was left
     * on, which need not be 1. */
    chanhop_observe(&h, 9);
    ASSERT_EQ((long long)h.slots[0].frames, 0);
    ASSERT_EQ((long long)h.slots[0].activity, 0);
    ASSERT_EQ((long long)h.slots[0].visits, 0);
    int out[2], cur = -2;
    chanhop_export(&h, out, 2, &cur);
    ASSERT_EQ(cur, -1);
    ASSERT_EQ(chanhop_tick(&h, h.min_dwell_ms), 1);
    ASSERT_EQ(chanhop_target_channel(&h), 6);
}

static void test_confirm_without_pending_is_a_noop(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    chanhop_init(&h, chans, 2);
    chanhop_confirm_retune(&h, 1, 100);            /* nothing asked */
    ASSERT_EQ((long long)h.slots[0].visits, 0);
    ASSERT_EQ(h.tuned, 0);
    hop(&h, 0);
    chanhop_confirm_retune(&h, 1, 50);             /* answered already */
    ASSERT_EQ((long long)h.slots[0].visits, 1);
    ASSERT_EQ(chanhop_current_channel(&h), 1);
    chanhop_confirm_retune(NULL, 1, 0);            /* no crash */
    ASSERT_EQ(chanhop_target_channel(NULL), 0);
    ASSERT_EQ(chanhop_target_freq(NULL), 0);
}

static void test_record_retune_err_keeps_reason_across_success(void) {
    int req = 0, conf = 0, fail = 0, err = 0;
    chanhop_record_retune_err(6, EBUSY, &req, &conf, &fail, &err);
    ASSERT_EQ(req, 6);
    ASSERT_EQ(conf, 0);
    ASSERT_EQ(fail, 1);
    ASSERT_EQ(err, EBUSY);
    chanhop_record_retune_err(11, 0, &req, &conf, &fail, &err);
    ASSERT_EQ(conf, 11);
    ASSERT_EQ(fail, 1);
    ASSERT_EQ(err, EBUSY);   /* names what the count is counting */
    chanhop_record_retune_err(1, EINVAL, &req, &conf, &fail, &err);
    ASSERT_EQ(err, EINVAL);
    ASSERT_EQ(fail, 2);
    chanhop_record_retune_err(1, EPERM, NULL, NULL, NULL, NULL);
}

static void test_retune_reason_vocabulary(void) {
    ASSERT_STR(chanhop_retune_reason(0),          "none");
    ASSERT_STR(chanhop_retune_reason(EBUSY),      "EBUSY");
    ASSERT_STR(chanhop_retune_reason(EINVAL),     "EINVAL");
    ASSERT_STR(chanhop_retune_reason(EPERM),      "EPERM");
    ASSERT_STR(chanhop_retune_reason(ENODEV),     "ENODEV");
    ASSERT_STR(chanhop_retune_reason(EOPNOTSUPP), "EOPNOTSUPP");
    ASSERT_STR(chanhop_retune_reason(ETIMEDOUT),  "ETIMEDOUT");
    ASSERT_STR(chanhop_retune_reason(EMFILE),     "other");
    ASSERT_STR(chanhop_retune_reason(-1),         "other");
}

/* ── chanhop_service() through the fake platform (#91) ─────────────── */

static sloth_state_t g_hs;

static void service_setup(chanhop_t *h, const int *chans, int n) {
    fake_net_reset();
    memset(&g_hs, 0, sizeof(g_hs));
    snprintf(g_hs.probe_iface, sizeof(g_hs.probe_iface), "mon0");
    chanhop_init(h, chans, n);
}

static void check_injected_errno(int e, const char *name) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    service_setup(&h, chans, 3);
    g_fake_net.set_channel_rc = -e;
    chanhop_service(&h, &g_hs, 0, 0);
    ASSERT_EQ(g_fake_net.set_channel_calls, 1);
    ASSERT_EQ(g_fake_net.set_channel_last_freq, 2412);
    ASSERT_STR(g_fake_net.set_channel_last_iface, "mon0");
    ASSERT_EQ(g_hs.chan_requested, 1);
    ASSERT_EQ(g_hs.chan_confirmed, 0);
    ASSERT_EQ(g_hs.chan_retune_failures, 1);
    ASSERT_EQ(g_hs.chan_retune_last_errno, e);
    ASSERT_STR(chanhop_retune_reason(g_hs.chan_retune_last_errno), name);
    ASSERT_EQ(g_hs.scan_cur_idx, -1);              /* never got anywhere */
    ASSERT_EQ((long long)g_hs.hop_activity.visits, 0);
    /* The operator sees the reason, not just a number. */
    char strip[256];
    iface_fmt_health_strip(&g_hs, strip, (int)sizeof(strip));
    char want[48];
    snprintf(want, sizeof(want), "retune-fail 1 %s", name);
    ASSERT(strstr(strip, want) != NULL);
    char bar[128];
    iface_fmt_scan_bar(&g_hs, bar, (int)sizeof(bar));
    ASSERT(strstr(bar, "[") == NULL);              /* no channel marked live */
}

static void test_service_carries_ebusy(void)  { check_injected_errno(EBUSY,  "EBUSY"); }
static void test_service_carries_einval(void) { check_injected_errno(EINVAL, "EINVAL"); }
static void test_service_carries_eperm(void)  { check_injected_errno(EPERM,  "EPERM"); }

static void test_service_refused_channel_never_attributed(void) {
    /* The driver will not take channel 6 (EINVAL); the others work.
     * Several full rotations with traffic every poll: 6 must end with a
     * refusal per attempt and nothing else, and every frame must land
     * on a channel the radio actually reached. */
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    service_setup(&h, chans, 3);
    g_fake_net.refuse_freq_mhz = 2437;
    g_fake_net.refuse_rc       = -EINVAL;
    uint64_t heard = 0;
    for (uint64_t t = 0; t <= 5000; t += 50) {
        chanhop_service(&h, &g_hs, t, 3);
        heard += 3;
        ASSERT(g_hs.chan_confirmed != 6);
    }
    ASSERT(h.slots[1].refusals >= 3);
    ASSERT_EQ((long long)h.slots[1].visits, 0);
    ASSERT_EQ((long long)h.slots[1].frames, 0);
    ASSERT(h.slots[0].visits >= 3);
    ASSERT(h.slots[2].visits >= 3);
    /* Everything heard after the first ack is attributed; the first
     * poll's frames arrive before any retune and belong to nobody. */
    ASSERT_EQ((long long)(h.slots[0].frames + h.slots[2].frames),
              (long long)(heard - 3));
    ASSERT_EQ(g_hs.chan_retune_last_errno, EINVAL);
    ASSERT_EQ(g_hs.chan_retune_failures, (int)h.slots[1].refusals);
    ASSERT_EQ((long long)g_hs.hop_activity.silent_channels, 0);
}

static void test_service_persistent_refusal_retries_at_bounded_rate(void) {
    /* EPERM on everything — no CAP_NET_ADMIN. 1 s of 10 ms polls must
     * not mean 100 retunes: the retry waits min_dwell_ms (100). */
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    service_setup(&h, chans, 3);
    g_fake_net.set_channel_rc = -EPERM;
    for (uint64_t t = 0; t < 1000; t += 10)
        chanhop_service(&h, &g_hs, t, 1);
    ASSERT_EQ(g_fake_net.set_channel_calls, 10);
    ASSERT_EQ(g_hs.chan_retune_failures, 10);
    ASSERT_EQ(g_hs.chan_confirmed, 0);
    ASSERT_EQ((long long)g_hs.hop_activity.frames, 0);
}

static void test_service_missing_set_channel_is_eopnotsupp(void) {
    chanhop_t h;
    int chans[] = { 1 };
    service_setup(&h, chans, 1);
    platform_ops_t saved = g_platform;
    g_platform.set_channel = NULL;
    chanhop_service(&h, &g_hs, 0, 0);
    g_platform = saved;
    ASSERT_EQ(g_hs.chan_retune_last_errno, EOPNOTSUPP);
    ASSERT_EQ(g_hs.chan_retune_failures, 1);
}

/* The vtable contract is 0 or a negative errno. A positive return is a
 * broken backend, and reading it as success would credit a channel the
 * radio may never have reached - the exact misattribution #91 removed. */
static void test_service_positive_rc_is_eio_not_success(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    service_setup(&h, chans, 2);
    g_fake_net.set_channel_rc = 1;
    chanhop_service(&h, &g_hs, 0, 5);
    chanhop_service(&h, &g_hs, 50, 5);   /* still pending-free; no retry yet */
    ASSERT_EQ(g_hs.chan_retune_last_errno, EIO);
    ASSERT_EQ(g_hs.chan_retune_failures, 1);
    ASSERT_EQ(g_hs.chan_confirmed, 0);
    ASSERT_EQ((long long)h.slots[0].visits, 0);
    ASSERT_EQ((long long)h.slots[0].refusals, 1);
    ASSERT_EQ((long long)g_hs.hop_activity.visits, 0);
    ASSERT_EQ((long long)g_hs.hop_activity.frames, 0);
    ASSERT_EQ(g_hs.scan_cur_idx, -1);
}

/* The refused-slot mask the sensor_health signature keys on: exactly
 * the slots that refused, and sticky once set. */
static void test_service_refused_mask_names_only_refusing_slot(void) {
    chanhop_t h;
    int chans[] = { 1, 6, 11 };
    service_setup(&h, chans, 3);
    ASSERT_EQ((long long)g_hs.chan_refused_mask, 0);
    g_fake_net.refuse_freq_mhz = 2437;
    g_fake_net.refuse_rc       = -EBUSY;
    for (uint64_t t = 0; t <= 3000; t += 50)
        chanhop_service(&h, &g_hs, t, 1);
    ASSERT_EQ((long long)g_hs.chan_refused_mask, 1LL << 1);
    g_fake_net.refuse_freq_mhz = 0;               /* driver relents */
    for (uint64_t t = 3050; t <= 6000; t += 50)
        chanhop_service(&h, &g_hs, t, 1);
    ASSERT(h.slots[1].visits > 0);
    ASSERT_EQ((long long)g_hs.chan_refused_mask, 1LL << 1);
}

static void test_service_success_confirms_and_marks(void) {
    chanhop_t h;
    int chans[] = { 1, 6 };
    service_setup(&h, chans, 2);
    chanhop_service(&h, &g_hs, 0, 0);
    ASSERT_EQ(g_hs.chan_requested, 1);
    ASSERT_EQ(g_hs.chan_confirmed, 1);
    ASSERT_EQ(g_hs.chan_retune_failures, 0);
    ASSERT_EQ(g_hs.chan_retune_last_errno, 0);
    ASSERT_EQ(g_hs.scan_cur_idx, 0);
    ASSERT_EQ(g_hs.scan_chan_count, 2);
    chanhop_service(&h, &g_hs, 100, 4);             /* still dwelling */
    ASSERT_EQ(g_fake_net.set_channel_calls, 1);
    ASSERT_EQ((long long)g_hs.hop_activity.cur_frames, 4);
}

#if defined(PLATFORM_LINUX) && defined(WITH_WIFI)
/* The nl80211 ack, hand-built: one NLMSG_ERROR header (16 bytes, RFC
 * 3549 §2.3.2.2 layout as linux/netlink.h defines it) and a struct
 * nlmsgerr whose `error` is 0 for an ACK or the negated errno. */
static long build_ack(uint8_t *buf, size_t cap, int error, uint16_t type,
                      uint32_t claimed_len) {
    size_t need = NLMSG_HDRLEN + sizeof(struct nlmsgerr);
    if (cap < need) return -1;
    memset(buf, 0, need);
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    h->nlmsg_len  = claimed_len ? claimed_len : (uint32_t)need;
    h->nlmsg_type = type;
    struct nlmsgerr e;
    memset(&e, 0, sizeof(e));
    e.error = error;
    memcpy(buf + NLMSG_HDRLEN, &e, sizeof(e));
    return (long)need;
}

static void test_ack_result_carries_kernel_errno(void) {
    uint8_t b[NLMSG_HDRLEN + sizeof(struct nlmsgerr)];
    long n = build_ack(b, sizeof(b), 0, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), 0);
    n = build_ack(b, sizeof(b), -EBUSY, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EBUSY);
    n = build_ack(b, sizeof(b), -EINVAL, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EINVAL);
    n = build_ack(b, sizeof(b), -EPERM, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EPERM);
}

static void test_ack_result_rejects_malformed(void) {
    uint8_t b[NLMSG_HDRLEN + sizeof(struct nlmsgerr)];
    long n = build_ack(b, sizeof(b), 0, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n - 1), -EIO);         /* short read */
    ASSERT_EQ(linux_wifi_ack_result(NULL, n), -EIO);
    n = build_ack(b, sizeof(b), 0, NLMSG_DONE, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EIO);             /* not an ack */
    n = build_ack(b, sizeof(b), 0, NLMSG_ERROR, (uint32_t)sizeof(b) + 4);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EIO);             /* overlong */
    n = build_ack(b, sizeof(b), 5, NLMSG_ERROR, 0);
    ASSERT_EQ(linux_wifi_ack_result(b, n), -EIO);             /* positive: not an errno */
}
#endif

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

    TEST_SUITE("wifi channel hopper: retune handshake and reason (#91)");
    RUN_TEST(test_tick_proposes_without_moving);
    RUN_TEST(test_refused_retune_accrues_nothing_on_target);
    RUN_TEST(test_refused_channel_is_skipped_and_dwell_spans_it);
    RUN_TEST(test_refused_first_retune_leaves_radio_untuned);
    RUN_TEST(test_confirm_without_pending_is_a_noop);
    RUN_TEST(test_record_retune_err_keeps_reason_across_success);
    RUN_TEST(test_retune_reason_vocabulary);
    RUN_TEST(test_service_carries_ebusy);
    RUN_TEST(test_service_carries_einval);
    RUN_TEST(test_service_carries_eperm);
    RUN_TEST(test_service_refused_channel_never_attributed);
    RUN_TEST(test_service_persistent_refusal_retries_at_bounded_rate);
    RUN_TEST(test_service_missing_set_channel_is_eopnotsupp);
    RUN_TEST(test_service_positive_rc_is_eio_not_success);
    RUN_TEST(test_service_refused_mask_names_only_refusing_slot);
    RUN_TEST(test_service_success_confirms_and_marks);
#if defined(PLATFORM_LINUX) && defined(WITH_WIFI)
    RUN_TEST(test_ack_result_carries_kernel_errno);
    RUN_TEST(test_ack_result_rejects_malformed);
#endif
}
