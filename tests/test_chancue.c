#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "runner.h"
#include "tmp_dir.h"
#include "fake_platform.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "wifi_chanhop.h"
#include "chancue.h"
#include "cue_live.h"
#include "mon_radios.h"
#include "evidence_ring.h"
#include "jsonl.h"
#include "db.h"

/*
 * Passive cueing, scheduler dwell only (#248; owner rulings 2026-11-23).
 *
 * The policy (src/chancue.c) and the scheduler's cued dwell
 * (src/wifi_chanhop.c) are driven on a synthetic monotonic clock in
 * 10 ms steps, so a planned dwell and its measured span agree and the
 * scheduler's own dwell accounting (chanhop_slot_time_ms(), the slots'
 * dwell_ms and visits) is the measurement. The live side
 * (src/cue_live.c) is driven with hand-built alert_t rows citing frames
 * in the evidence ring, through the fake platform.
 *
 * Every absence assertion names the mutation it was seen red under
 * (agents/AGENTS.md).
 */

TEST_STATE(g_s);

/* The default --hop list: 11 channels. */
static const int k_def[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };
#define N_DEF ((int)(sizeof(k_def) / sizeof(k_def[0])))

/* A longer list for the caps the share limit would otherwise reach
 * first: 2.4 GHz 1-13 and 12 5 GHz channels, 25. */
static const int k_long[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                              36, 40, 44, 48, 52, 56, 60, 64, 149, 153, 157, 161 };
#define N_LONG ((int)(sizeof(k_long) / sizeof(k_long[0])))

static int mhz_of(int ch) { return chanhop_freq(ch); }

/* Run one scheduler from `from` to `to` in 10 ms polls: the cue table's
 * tick, then the scheduler's step against the fake platform. */
static void drive(chancue_t *c, chanhop_t *h, uint64_t from, uint64_t to) {
    chanhop_t *sched[1] = { h };
    for (uint64_t t = from; t < to; t += 10) {
        if (c) chancue_tick(c, sched, 1, t);
        chanhop_step(h, "mon0", t, 0, NULL, NULL);
    }
}

static uint64_t total_ms(const chanhop_t *h, uint64_t now) {
    uint64_t t = 0;
    for (int i = 0; i < h->count; i++) t += chanhop_slot_time_ms(h, i, now);
    return t;
}

/* ── the kinds ────────────────────────────────────────────────────── */

/* Exactly the six kinds of ruling 4, and no own-state or wired kind.
 * Seen red with ALERT_TYPE_SENSOR_SUPPRESSED added to the switch. */
static void test_kinds_are_the_six(void) {
    static const alert_type_t six[] = {
        ALERT_TYPE_EVIL_TWIN, ALERT_TYPE_KARMA_AP, ALERT_TYPE_KARMA_PROBE_FORGE,
        ALERT_TYPE_DEAUTH_FLOOD, ALERT_TYPE_PMKID_HARVEST, ALERT_TYPE_HANDSHAKE_HARVEST,
    };
    int n = 0;
    for (int t = 0; t < ALERT_TYPE_COUNT; t++) n += chancue_kind_cues((alert_type_t)t);
    ASSERT_EQ(n, 6);
    for (size_t i = 0; i < sizeof(six) / sizeof(six[0]); i++)
        ASSERT_EQ(chancue_kind_cues(six[i]), 1);
    ASSERT_EQ(chancue_kind_cues(ALERT_TYPE_SENSOR_SUPPRESSED), 0);
    ASSERT_EQ(chancue_kind_cues(ALERT_TYPE_NO_MONITOR_MODE), 0);
    ASSERT_EQ(chancue_kind_cues(ALERT_TYPE_ARP_SPOOF), 0);
    /* A kind that does not cue does nothing: not counted, no event. */
    chancue_t c;
    chancue_init(&c);
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chanhop_t *sched[1] = { &h };
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_ARP_SPOOF, 2437, "x", 0),
              CUE_NOT_CUEING);
    ASSERT_EQ((int)c.refused, 0);
    ASSERT_EQ(c.nev, 0);
}

/* ── the dwell ────────────────────────────────────────────────────── */

/* A cue on channel 6: its dwell is 4x the normal plan for 120 s, then
 * back; every other channel keeps its dwell and is still visited. */
static void test_cued_dwell_is_four_times_for_120_s(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    drive(&c, &h, 0, 10000);
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_EVIL_TWIN, mhz_of(6), "i1", 10000),
              CUE_STARTED);
    ASSERT_EQ(chancue_active(&c), 1);
    int s6 = chanhop_find_freq(&h, mhz_of(6));
    ASSERT_EQ(s6, 1);
    uint32_t v0 = h.slots[s6].visits;
    uint64_t d0 = h.slots[s6].dwell_ms;
    uint32_t o0 = h.slots[2].visits;
    uint64_t od0 = h.slots[2].dwell_ms;
    drive(&c, &h, 10000, 10000 + CUE_DURATION_MS);
    /* Mean of the cued visits: 4 x 250 ms. */
    uint32_t v = h.slots[s6].visits - v0;
    ASSERT_GT(v, 20);
    /* Means over the span; the dwell open at either end makes a visit
     * counted before its time is, hence the tolerance. */
    ASSERT_NEAR((double)(h.slots[s6].dwell_ms - d0) / v, 1000.0, 60.0);
    ASSERT_NEAR((double)(h.slots[2].dwell_ms - od0) / (h.slots[2].visits - o0), 250.0, 20.0);
    for (int i = 0; i < h.count; i++) ASSERT_GT(h.slots[i].visits, v0);
    ASSERT_GT(h.cued_dwells, 20);

    /* Ended at 120 s: an event, the slot no longer cued, the dwell back. */
    drive(&c, &h, 10000 + CUE_DURATION_MS, 10000 + CUE_DURATION_MS + 20000);
    ASSERT_EQ(chancue_active(&c), 0);
    ASSERT_EQ((int)c.ended, 1);
    ASSERT_EQ(chanhop_slot_cued(&h, s6, 10000 + CUE_DURATION_MS + 20000), 0);
    uint32_t v1 = h.slots[s6].visits;
    uint64_t d1 = h.slots[s6].dwell_ms;
    drive(&c, &h, 10000 + CUE_DURATION_MS + 20000, 10000 + CUE_DURATION_MS + 50000);
    ASSERT_NEAR((double)(h.slots[s6].dwell_ms - d1) / (h.slots[s6].visits - v1), 250.0, 40.0);

    cue_event_t ev[CUE_EVENTS_MAX];
    int n = chancue_drain(&c, ev, CUE_EVENTS_MAX);
    ASSERT_EQ(n, 2);
    ASSERT_EQ(ev[0].state, CUE_EV_STARTED);
    ASSERT_EQ(ev[0].channel, 6);
    ASSERT_EQ(ev[0].radio, 0);
    ASSERT_EQ((int)ev[0].duration_s, 120);
    ASSERT_EQ(ev[1].state, CUE_EV_ENDED);
    ASSERT_EQ((int)ev[1].duration_s, 120);
    ASSERT_STR(ev[1].incident_id, "i1");
}

/* A cue on the channel the radio is on now lengthens the dwell under
 * way, from when it began. */
static void test_cue_extends_the_open_dwell(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chanhop_step(&h, "mon0", 0, 0, NULL, NULL);       /* on slot 0 */
    ASSERT_EQ(h.cur, 0);
    ASSERT_EQ(h.dwell_until_ms, 250);
    chanhop_set_cue(&h, 0, 100000, 100);
    ASSERT_EQ(h.dwell_cued, 1);
    ASSERT_EQ(h.dwell_until_ms, 1000);
    ASSERT_EQ(chanhop_tick(&h, 900), 0);               /* still there */
    ASSERT_EQ(chanhop_tick(&h, 1000), 1);
}

/* The clamp: a cue admitted when its neighbours were busy cannot take
 * more than they leave once their activity decays. Seen red with
 * cued_plan() returning `want` unclamped. */
static void test_cued_plan_is_clamped_to_the_budget(void) {
    static const int ch[] = { 1, 6, 11, 36, 40 };
    chanhop_t h;
    chanhop_init(&h, ch, 5);
    for (int i = 1; i < 5; i++) h.slots[i].activity = 200;   /* 1850 ms each */
    ASSERT_EQ(chanhop_cue_fits(&h, 0, 0), 1);
    chanhop_set_cue(&h, 0, 1000000, 0);
    for (int i = 1; i < 5; i++) h.slots[i].activity = 0;     /* 250 ms each */
    h.slots[0].activity = 10;                                 /* 330 normal */
    ASSERT_EQ(chanhop_cue_fits(&h, 0, 0), 0);  /* 1320 > 1000: refused now */
    h.pending = 0;
    h.started = 1;
    chanhop_confirm_retune(&h, 1, 10);
    ASSERT_EQ(h.dwell_cued, 1);
    /* Four uncued channels at 250 leave 1000; 4 x 330 = 1320 wanted. */
    ASSERT_EQ(h.dwell_planned_ms, 1000);
    h.slots[0].activity = 200;          /* halved as it leaves: 1050 normal */
    h.pending = 0;
    chanhop_confirm_retune(&h, 1, 2000);
    /* Wanted 4200; the budget is 1000, below its normal plan: normal. */
    ASSERT_EQ(h.dwell_planned_ms, 1050);
}

/* ── the limits ───────────────────────────────────────────────────── */

/* Ruling 3's proof: every channel cued at once. The share limit admits
 * what fits in half the radio's time and refuses the rest, counted as
 * limit refusals; over the cue's 120 s the cued channels take at most
 * 50 % of the measured time and every other channel keeps at least
 * half of its normal share (1/22 of the radio), never zero. Seen red
 * with chanhop_cue_fits() returning 1 (all 11 admitted: the uncued
 * share reads 0). */
static void test_cue_every_channel_keeps_every_channel(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    drive(&c, &h, 0, 3000);
    int started = 0, share = 0;
    for (int i = 0; i < N_DEF; i++) {
        cue_result_t r = chancue_request(&c, sched, 1, ALERT_TYPE_DEAUTH_FLOOD,
                                         mhz_of(k_def[i]), "x", 3000);
        started += r == CUE_STARTED;
        share   += r == CUE_REFUSE_SHARE;
    }
    ASSERT_EQ(started, 2);
    ASSERT_EQ(share, 9);
    ASSERT_EQ((int)c.refused_limit, 9);
    uint64_t t0[CHANHOP_MAX], tot0 = total_ms(&h, 3000);
    for (int i = 0; i < h.count; i++) t0[i] = chanhop_slot_time_ms(&h, i, 3000);
    const uint64_t end = 3000 + CUE_DURATION_MS;
    drive(&c, &h, 3000, end);
    uint64_t tot = total_ms(&h, end) - tot0, cued = 0;
    ASSERT_GT(tot, CUE_DURATION_MS - 1000);
    for (int i = 0; i < h.count; i++) {
        uint64_t ti = chanhop_slot_time_ms(&h, i, end) - t0[i];
        if (i < 2) { cued += ti; continue; }
        ASSERT_GT(ti, 0);
        ASSERT_GE(ti * 2 * N_DEF, tot);          /* >= half of 1/11 */
    }
    ASSERT(cued * 2 <= tot);
}

/* The issue's acceptance: false triggers on 10 channels reach the limit
 * and every other channel's share stays above the minimum. */
static void test_false_triggers_on_ten_channels(void) {
    fake_net_reset();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    drive(&c, &h, 0, 3000);
    for (int i = 1; i < N_DEF; i++)
        (void)chancue_request(&c, sched, 1, ALERT_TYPE_KARMA_PROBE_FORGE,
                              mhz_of(k_def[i]), "f", 3000);
    ASSERT_EQ((int)c.started, 2);
    ASSERT_EQ((int)c.refused_limit, 8);
    /* One refused record per channel and reason, not per trigger. */
    for (int i = 1; i < N_DEF; i++)
        (void)chancue_request(&c, sched, 1, ALERT_TYPE_KARMA_PROBE_FORGE,
                              mhz_of(k_def[i]), "f", 4000);
    ASSERT_EQ((int)c.refused_limit, 16);
    int refused_ev = 0;
    for (int i = 0; i < c.nev; i++) refused_ev += c.ev[i].state == CUE_EV_REFUSED;
    ASSERT_EQ(refused_ev, 8);
    uint64_t t0[CHANHOP_MAX], tot0 = total_ms(&h, 3000);
    for (int i = 0; i < h.count; i++) t0[i] = chanhop_slot_time_ms(&h, i, 3000);
    drive(&c, &h, 3000, 3000 + CUE_DURATION_MS);
    uint64_t tot = total_ms(&h, 3000 + CUE_DURATION_MS) - tot0;
    for (int i = 0; i < h.count; i++) {
        if (chanhop_slot_cued(&h, i, 3000 + CUE_DURATION_MS - 10)) continue;
        uint64_t ti = chanhop_slot_time_ms(&h, i, 3000 + CUE_DURATION_MS) - t0[i];
        ASSERT_GE(ti * 2 * N_DEF, tot);
    }
}

/* At most CUE_MAX_ACTIVE at once, with room under the share limit.
 * Seen red with the active check removed. */
static void test_active_cap(void) {
    chanhop_t h;
    chanhop_init(&h, k_long, N_LONG);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    for (int i = 0; i < CUE_MAX_ACTIVE; i++)
        ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_PMKID_HARVEST,
                                  mhz_of(k_long[i]), "a", 100), CUE_STARTED);
    ASSERT_EQ(chanhop_cue_fits(&h, CUE_MAX_ACTIVE, 100), 1);   /* share has room */
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_PMKID_HARVEST,
                              mhz_of(k_long[CUE_MAX_ACTIVE]), "a", 100),
              CUE_REFUSE_ACTIVE);
    ASSERT_EQ(chancue_active(&c), CUE_MAX_ACTIVE);
    ASSERT_EQ((int)c.refused_limit, 1);
    ASSERT_STR(chancue_reason_name(CUE_REFUSE_ACTIVE), "active_cap");
}

/* At most CUE_RATE_MAX started in any CUE_RATE_WINDOW_MS. Seen red with
 * the rate check removed (the ninth started). */
static void test_rate_cap(void) {
    chanhop_t h;
    chanhop_init(&h, k_long, N_LONG);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    uint64_t t = 1000;
    for (int round = 0; round < 2; round++) {
        for (int i = 0; i < 4; i++)
            ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_HANDSHAKE_HARVEST,
                                      mhz_of(k_long[round * 4 + i]), "r", t),
                      CUE_STARTED);
        t += CUE_DURATION_MS;
        chancue_tick(&c, sched, 1, t);
        ASSERT_EQ(chancue_active(&c), 0);
    }
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_HANDSHAKE_HARVEST,
                              mhz_of(k_long[9]), "r", t), CUE_REFUSE_RATE);
    /* The window slides: the first starts age out. */
    t = 1000 + CUE_RATE_WINDOW_MS;
    chancue_tick(&c, sched, 1, t);
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_HANDSHAKE_HARVEST,
                              mhz_of(k_long[9]), "r", t), CUE_STARTED);
}

/* Refusals that are no limit, and a finding on a cued channel. None
 * counts toward SENSOR_SUPPRESSED. Seen red with chancue_is_limit()
 * returning 1. */
static void test_not_limits(void) {
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[1] = { &h };
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_EVIL_TWIN, 0, "n", 5),
              CUE_REFUSE_NO_CHANNEL);
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_EVIL_TWIN, mhz_of(13), "n", 5),
              CUE_REFUSE_NOT_HOPPED);
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_EVIL_TWIN, mhz_of(6), "n", 5),
              CUE_STARTED);
    ASSERT_EQ(chancue_request(&c, sched, 1, ALERT_TYPE_KARMA_AP, mhz_of(6), "m", 6),
              CUE_ABSORBED);
    ASSERT_EQ((int)c.refused, 2);
    ASSERT_EQ((int)c.refused_limit, 0);
    ASSERT_EQ((int)c.started, 1);
    ASSERT_EQ(c.nev, 3);                         /* two refused, one started */
    ASSERT_STR(chancue_reason_name(c.ev[0].reason), "no_channel");
    ASSERT_STR(chancue_reason_name(c.ev[1].reason), "not_hopped");
    ASSERT_EQ(c.ev[1].channel, 13);
}

/* ── several radios ──────────────────────────────────────────────── */

/* A cue is served by the radio whose share holds its channel. */
static void test_cue_served_by_the_holding_radio(void) {
    chanhop_t full, a, b;
    chanhop_init(&full, k_long, N_LONG);
    chanhop_split(&a, &full, 2, 0);              /* 1, 3, 5, ... */
    chanhop_split(&b, &full, 2, 1);              /* 2, 4, 6, ... */
    chancue_t c;
    chancue_init(&c);
    chanhop_t *sched[2] = { &a, &b };
    ASSERT_EQ(chancue_request(&c, sched, 2, ALERT_TYPE_EVIL_TWIN, mhz_of(6), "s", 1),
              CUE_STARTED);
    ASSERT_EQ(c.ev[0].radio, 1);
    ASSERT_EQ(chanhop_slot_cued(&b, chanhop_find_freq(&b, mhz_of(6)), 2), 1);
    for (int i = 0; i < a.count; i++) ASSERT_EQ(chanhop_slot_cued(&a, i, 2), 0);
    /* Re-dealt (one radio lost): the next tick cues it where it sits. */
    chanhop_t only;
    chanhop_split(&only, &full, 1, 0);
    chanhop_t *one[2] = { &only, NULL };
    chancue_tick(&c, one, 2, 10);
    ASSERT_EQ(chanhop_slot_cued(&only, chanhop_find_freq(&only, mhz_of(6)), 11), 1);
    ASSERT_EQ(c.cue[0].radio, 0);

    /* The cap is over all radios (owner ruling of 2026-11-24): the
     * default 11 channels dealt among three radios leave shares of 4, 4
     * and 3. One cue on a radio of 4 takes 4/7 of it, on the radio of 3
     * 4/6; the first two radios' cues fit (8/7 of the 3/2 the radios
     * allow), the third radio's would make 1.81 and is refused
     * share_cap, a limit. A second cue on a radio of 4 breaks its floor
     * (2 x 2 > 2) and is refused share_cap too. Seen red under the
     * per-radio cap restored (share_small on the first). */
    chanhop_t def, r0, r1, r2;
    chanhop_init(&def, k_def, N_DEF);
    chanhop_split(&r0, &def, 3, 0);
    chanhop_split(&r1, &def, 3, 1);
    chanhop_split(&r2, &def, 3, 2);
    ASSERT_EQ(r0.count, 4);
    ASSERT_EQ(r1.count, 4);
    ASSERT_EQ(r2.count, 3);
    chancue_t c3;
    chancue_init(&c3);
    chanhop_t *three[3] = { &r0, &r1, &r2 };
    ASSERT_EQ(chancue_request(&c3, three, 3, ALERT_TYPE_EVIL_TWIN,
                              r0.slots[0].freq_mhz, "t0", 1), CUE_STARTED);
    ASSERT_EQ(chancue_request(&c3, three, 3, ALERT_TYPE_EVIL_TWIN,
                              r1.slots[0].freq_mhz, "t1", 1), CUE_STARTED);
    ASSERT_EQ(chancue_request(&c3, three, 3, ALERT_TYPE_EVIL_TWIN,
                              r2.slots[0].freq_mhz, "t2", 1), CUE_REFUSE_SHARE);
    ASSERT_EQ(chancue_request(&c3, three, 3, ALERT_TYPE_EVIL_TWIN,
                              r0.slots[1].freq_mhz, "t3", 1), CUE_REFUSE_SHARE);
    ASSERT_EQ((int)c3.started, 2);
    ASSERT_EQ((int)c3.refused_limit, 2);
    /* The parts handed to the clamp: the two cued radios keep their
     * 4/7 and more, the three together within half their time. */
    ASSERT(r0.cue_cap_pm >= 571 && r1.cue_cap_pm >= 571);
    ASSERT(r0.cue_cap_pm + r1.cue_cap_pm + r2.cue_cap_pm <= 1500);

    /* A layout too small for any cue: six channels over three radios,
     * two each - one at 4x would make its rotation three times as long
     * (6 against 2), past the floor whatever else runs. share_small,
     * the layout's and not load's, so not a limit and no input to
     * SENSOR_SUPPRESSED (#248 review). Seen red with the structural
     * check removed (share_cap, six limit refusals). */
    static const int k6[] = { 1, 6, 11, 36, 40, 44 };
    chanhop_t six, s0, s1, s2;
    chanhop_init(&six, k6, 6);
    chanhop_split(&s0, &six, 3, 0);
    chanhop_split(&s1, &six, 3, 1);
    chanhop_split(&s2, &six, 3, 2);
    chancue_t c6;
    chancue_init(&c6);
    chanhop_t *three6[3] = { &s0, &s1, &s2 };
    for (int i = 0; i < 6; i++)
        ASSERT_EQ(chancue_request(&c6, three6, 3, ALERT_TYPE_EVIL_TWIN,
                                  mhz_of(k6[i]), "t", 1), CUE_REFUSE_SHARE_SMALL);
    ASSERT_EQ((int)c6.refused, 6);
    ASSERT_EQ((int)c6.refused_limit, 0);
    ASSERT_EQ(chancue_is_limit(CUE_REFUSE_SHARE_SMALL), 0);
    ASSERT_STR(chancue_reason_name(CUE_REFUSE_SHARE_SMALL), "share_small");
    ASSERT_EQ(c6.ev[0].reason, CUE_REFUSE_SHARE_SMALL);
    /* One radio with room for one cue alone: a second that does not fit
     * beside it is the limit, share_cap, counted. */
    chanhop_t five;
    static const int k5[] = { 1, 6, 11, 36, 40 };
    chanhop_init(&five, k5, 5);
    chancue_t c5;
    chancue_init(&c5);
    chanhop_t *one5[1] = { &five };
    ASSERT_EQ(chancue_request(&c5, one5, 1, ALERT_TYPE_EVIL_TWIN, mhz_of(1), "u", 1),
              CUE_STARTED);
    ASSERT_EQ(chancue_request(&c5, one5, 1, ALERT_TYPE_EVIL_TWIN, mhz_of(6), "v", 1),
              CUE_REFUSE_SHARE);
    ASSERT_EQ((int)c5.refused_limit, 1);
}

/* The cap over all radios and each radio's floor, measured by the
 * schedulers' own dwell accounting: three radios on the default 11
 * channels (4/4/3), a finding on every channel at once, two minutes.
 * The cued channels together take at most half of the three radios'
 * time, and every uncued channel keeps at least half the share it
 * would have with no cue. Seen red with share_out() handing every
 * radio 999 and cap_ok() always 1 (cued time past half). */
static void test_cap_is_over_all_radios(void) {
    chanhop_t def, r[3];
    chanhop_init(&def, k_def, N_DEF);
    for (int k = 0; k < 3; k++) chanhop_split(&r[k], &def, 3, k);
    chanhop_t *sched[3] = { &r[0], &r[1], &r[2] };
    chancue_t c;
    chancue_init(&c);
    int started = 0;
    for (int i = 0; i < N_DEF; i++)
        started += chancue_request(&c, sched, 3, ALERT_TYPE_DEAUTH_FLOOD,
                                   mhz_of(k_def[i]), "a", 0) == CUE_STARTED;
    ASSERT_EQ(started, 2);
    const uint64_t end = CUE_DURATION_MS - 10;
    for (uint64_t t = 0; t < end; t += 10) {
        chancue_tick(&c, sched, 3, t);
        for (int k = 0; k < 3; k++) {
            char ifn[8];
            snprintf(ifn, sizeof(ifn), "mon%d", k);
            chanhop_step(&r[k], ifn, t, 0, NULL, NULL);
        }
    }
    uint64_t all = 0, cued = 0;
    for (int k = 0; k < 3; k++) {
        uint64_t radio = total_ms(&r[k], end);
        all += radio;
        for (int i = 0; i < r[k].count; i++) {
            uint64_t ms = chanhop_slot_time_ms(&r[k], i, end);
            if (chanhop_slot_cued(&r[k], i, end)) { cued += ms; continue; }
            /* Normal share at equal dwell is radio / count; at least
             * half of it, less one dwell for where the window cuts. */
            ASSERT_GT(ms * 2 * (uint64_t)r[k].count + 2 * 250u * r[k].count, radio);
        }
    }
    /* The two cued radios take 4/7 each at full plans, 38 % of the
     * three radios' time; held to each radio's own half (the per-radio
     * rule) they would get 3/6, 33 %. Seen red with share_out() never
     * called. */
    ASSERT_GT(cued * 100, all * 36);
    ASSERT(cued * 2 <= all + 3 * 1000u);   /* half, within one dwell a radio */
}

/* ── the live side ───────────────────────────────────────────────── */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t pin_mono(void) { return g_mono; }
static time_t   pin_wall(void) { return g_wall; }
static char     g_path[256];
static char     g_buf[65536];

static void live_begin(void) {
    g_mono = 1000;
    g_wall = (time_t)1800000000;
    sloth_clock_test_set(pin_mono, pin_wall);
    fake_net_reset();
    mon_radios_reset();
    cue_live_reset();
    evidence_ring_shutdown();
    ASSERT_EQ(evidence_ring_init(256 * 1024), 0);
    memset(&g_s, 0, sizeof(g_s));
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
}

static void live_end(void) {
    jsonl_close();
    cue_live_reset();
    mon_radios_reset();
    evidence_ring_shutdown();
    fake_net_reset();
    sloth_clock_test_set(NULL, NULL);
}

static uint64_t note(int freq) {
    static const uint8_t f[40] = { 0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x80 };
    uint64_t id = evidence_ring_note_radio(f, sizeof(f), sizeof(f), g_wall, 0,
                                           (uint16_t)freq, -50, 0);
    ASSERT(id != 0);
    return id;
}

/* A hand-built open incident citing one frame heard on freq. */
static void finding(alert_type_t t, const char *id, int freq) {
    alert_t *a = &g_s.alerts[g_s.alert_count++];
    memset(a, 0, sizeof(*a));
    a->type = t;
    a->sev = ALERT_SEV_CRIT;
    snprintf(a->incident_id, sizeof(a->incident_id), "%s", id);
    if (freq) {
        a->evidence_ids[0] = note(freq);
        a->evidence_id_count = 1;
    }
}

/* One poll of the hop stage as main.c's chanhop_drive() runs it. */
static void live_poll(chanhop_t *h, uint64_t t) {
    cue_live_step(&g_s, h, t);
    chanhop_service(h, &g_s, t, 0);
    (void)mon_hop_service(h, t);
}

static uint64_t ch6_ms_over(int cue_on, uint64_t span) {
    live_begin();
    cue_live_enable(cue_on);
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    for (uint64_t t = 0; t < 5000; t += 10) live_poll(&h, t);
    finding(ALERT_TYPE_EVIL_TWIN, "twin0001", mhz_of(6));
    int s6 = chanhop_find_freq(&h, mhz_of(6));
    uint64_t before = chanhop_slot_time_ms(&h, s6, 5000);
    for (uint64_t t = 5000; t < 5000 + span; t += 10) live_poll(&h, t);
    uint64_t ms = chanhop_slot_time_ms(&h, s6, 5000 + span) - before;
    live_end();
    return ms;
}

/* The issue's acceptance: a twin on one channel under --hop --cue shows
 * a longer dwell there, by the scheduler's own dwell accounting, than
 * the same run without --cue. 11 channels at 250 ms: channel 6 has
 * 1/11 of the radio without a cue and 1000/3500 with one. Seen red with
 * cue_live_enable() ignored (both 10.9 s). */
static void test_twin_lengthens_its_channel(void) {
    uint64_t off = ch6_ms_over(0, CUE_DURATION_MS);
    uint64_t on  = ch6_ms_over(1, CUE_DURATION_MS);
    ASSERT_NEAR((double)off, 120000.0 / 11, 300.0);
    ASSERT_NEAR((double)on, 120000.0 * 1000 / 3500, 1100.0);
    ASSERT_GT(on, 3 * off);
}

/* The finding's channel is its first cited frame's radiotap frequency;
 * none cited, none. */
static void test_finding_channel(void) {
    live_begin();
    finding(ALERT_TYPE_EVIL_TWIN, "a", 5180);
    finding(ALERT_TYPE_KARMA_AP, "b", 0);
    ASSERT_EQ(cue_live_finding_mhz(&g_s.alerts[0]), 5180);
    ASSERT_EQ(cue_live_finding_mhz(&g_s.alerts[1]), 0);
    live_end();
}

static void sink_open(void) {
    g_path[0] = '\0';
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_cue_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    db_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
}

static const char *sink_read(void) {
    jsonl_close();
    g_buf[0] = '\0';
    FILE *fp = fopen(g_path, "r");
    if (fp) {
        size_t n = fread(g_buf, 1, sizeof(g_buf) - 1, fp);
        g_buf[n] = '\0';
        fclose(fp);
    }
    unlink(g_path);
    return g_buf;
}

static int count_of(const char *hay, const char *needle) {
    int n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) n++;
    return n;
}

/* The `cue` records and sensor_health's cue_* fields. An incident is
 * offered once, however many polls it stays open; a resolved one never.
 * Seen red with first_sight() returning 1 for every named incident (the
 * channel-less finding refused again on every poll). */
static void test_cue_records(void) {
    live_begin();
    cue_live_enable(1);
    sink_open();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    live_poll(&h, 0);
    finding(ALERT_TYPE_DEAUTH_FLOOD, "dddd0001", mhz_of(11));
    finding(ALERT_TYPE_HANDSHAKE_HARVEST, "hhhh0001", 0);
    finding(ALERT_TYPE_EVIL_TWIN, "eeee0001", mhz_of(36));
    g_s.alerts[2].resolved = 1;
    for (uint64_t t = 10; t < 2000; t += 10) live_poll(&h, t);
    ASSERT_EQ(g_s.cue.on, 1);
    ASSERT_EQ(g_s.cue.active, 1);
    ASSERT_EQ((int)g_s.cue.started, 1);
    ASSERT_EQ((int)g_s.cue.refused, 1);
    ASSERT_EQ((int)g_s.cue.refused_limit, 0);
    jsonl_emit_sensor_health(&g_s);
    g_mono += CUE_DURATION_MS;
    live_poll(&h, CUE_DURATION_MS + 10);
    const char *b = sink_read();
    ASSERT_EQ(count_of(b, "\"type\":\"cue\""), 3);
    ASSERT(strstr(b, "\"kind\":\"DEAUTH_FLOOD\",\"state\":\"started\",\"channel\":11,"
                     "\"freq_mhz\":2462,\"band\":\"2.4\",\"duration_s\":120,\"radio\":0,"
                     "\"incident_id\":\"dddd0001\"") != NULL);
    ASSERT(strstr(b, "\"kind\":\"HANDSHAKE_HARVEST\",\"state\":\"refused\",\"channel\":0,"
                     "\"freq_mhz\":0,\"band\":\"unknown\",\"duration_s\":0,"
                     "\"reason\":\"no_channel\"") != NULL);
    ASSERT(strstr(b, "\"state\":\"ended\"") != NULL);
    ASSERT(strstr(b, "eeee0001") == NULL);
    ASSERT(strstr(b, "\"cue_active\":1,\"cue_started\":1,\"cue_refused\":1,"
                     "\"cue_refused_limit\":0,\"cue_cued_ms\":") != NULL);
    /* No address on a cue record. */
    ASSERT(strstr(b, "\"bssid\"") == NULL);
    live_end();
}

/* An incident asks once while it stays open, however many other
 * incidents open and close meanwhile: 200 channel-less findings pass
 * through one slot while a twin stays open, and the twin is never
 * offered again (#248 review). Seen red with the old 128-entry ring of
 * seen ids (started 2, the twin re-offered once its id left the ring). */
static void test_incident_offered_once_under_churn(void) {
    live_begin();
    cue_live_enable(1);
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    live_poll(&h, 0);
    finding(ALERT_TYPE_EVIL_TWIN, "xxxx0001", mhz_of(6));
    live_poll(&h, 10);
    ASSERT_EQ((int)g_s.cue.started, 1);
    uint64_t t = CUE_DURATION_MS + 100;
    live_poll(&h, t);
    ASSERT_EQ(g_s.cue.active, 0);
    for (int i = 0; i < 200; i++) {
        char id[ALERT_INCIDENT_ID_LEN];
        snprintf(id, sizeof(id), "f%07d", i);
        g_s.alert_count = 1;
        finding(ALERT_TYPE_DEAUTH_FLOOD, id, 0);
        live_poll(&h, t += 10);
    }
    g_s.alert_count = 1;
    live_poll(&h, t += 10);
    ASSERT_EQ((int)g_s.cue.started, 1);
    ASSERT_EQ((int)g_s.cue.refused, 200);
    ASSERT_EQ((int)g_s.cue.refused_limit, 0);
    ASSERT_EQ(g_s.cue.active, 0);
    live_end();
}

/* Every event of one poll reaches the stream: 40 distinct refusals and
 * a start in the same poll are 41 records, the start among them (#248
 * review). Seen red with the events drained once after all requests
 * (the queue of 32 full, the start dropped). */
static void test_no_event_lost_in_a_burst(void) {
    static const int off[] = { 2, 3, 4, 5, 7, 8, 9, 10, 12, 13, 52, 56, 60, 64,
                               100, 104, 108, 112, 116, 120, 124, 128, 132,
                               136, 140, 144, 165 };
    static const alert_type_t kinds[] = { ALERT_TYPE_KARMA_AP,
                                          ALERT_TYPE_PMKID_HARVEST };
    const int noff = (int)(sizeof(off) / sizeof(off[0]));
    live_begin();
    cue_live_enable(1);
    sink_open();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    live_poll(&h, 0);
    for (int i = 0; i < 40; i++) {
        char id[ALERT_INCIDENT_ID_LEN];
        snprintf(id, sizeof(id), "b%07d", i);
        finding(kinds[i / noff], id, mhz_of(off[i % noff]));
    }
    finding(ALERT_TYPE_EVIL_TWIN, "last0001", mhz_of(6));
    live_poll(&h, 10);
    const char *b = sink_read();
    ASSERT_EQ(count_of(b, "\"state\":\"refused\""), 40);
    ASSERT_EQ(count_of(b, "\"state\":\"started\""), 1);
    ASSERT(strstr(b, "last0001") != NULL);
    live_end();
}

/* cue_cued_ms is lifetime: a re-deal of the shares (a sensor radio
 * lost) resets radio 0's scheduler, not the count (#248 review). Seen
 * red with deal() not carrying radio 0's cued totals over (the count
 * fell to 0 at the re-deal). */
static void test_cued_ms_survives_a_redeal(void) {
    live_begin();
    cue_live_enable(1);
    mon_radios_add("mon0");
    mon_radios_add("mon1");
    mon_radios_set_state(0, MON_RADIO_RUNNING, "");
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    chanhop_t h;
    chanhop_init(&h, k_long, N_LONG);
    ASSERT_EQ(mon_hop_setup(&h), 2);
    finding(ALERT_TYPE_EVIL_TWIN, "rdl00001", mhz_of(1));   /* radio 0's */
    uint64_t prev = 0, t = 0;
    for (; t < 30000; t += 10) {
        live_poll(&h, t);
        ASSERT_GE(g_s.cue.cued_ms, prev);
        prev = g_s.cue.cued_ms;
    }
    ASSERT_GT(prev, 0);
    mon_radios_set_state(1, MON_RADIO_LOST, "gone");
    for (; t < 60000; t += 10) {
        live_poll(&h, t);
        ASSERT_GE(g_s.cue.cued_ms, prev);
        prev = g_s.cue.cued_ms;
    }
    ASSERT_EQ(h.count, N_LONG);                  /* re-dealt: all on radio 0 */
    live_end();
}

/* With --cue on, sensor_health carries the cue_* members even while no
 * monitor interface runs the scheduler (cue_live_step() never called):
 * main.c's chanhop_drive() publishes before its probe_iface guard
 * (#248 review). */
static void test_cue_fields_without_a_monitor(void) {
    live_begin();
    g_s.probe_iface[0] = '\0';
    cue_live_enable(1);
    sink_open();
    cue_live_publish(&g_s);
    ASSERT_EQ(g_s.cue.on, 1);
    jsonl_emit_sensor_health(&g_s);
    const char *b = sink_read();
    ASSERT(strstr(b, "\"cue_active\":0,\"cue_started\":0,\"cue_refused\":0,"
                     "\"cue_refused_limit\":0,\"cue_cued_ms\":0") != NULL);
    live_end();
}

/* Without --cue: no request, no record, no cue_* field. Seen red with
 * the g.on test in cue_live_step() removed. */
static void test_off_by_default(void) {
    live_begin();
    sink_open();
    chanhop_t h;
    chanhop_init(&h, k_def, N_DEF);
    finding(ALERT_TYPE_EVIL_TWIN, "eeee0002", mhz_of(6));
    for (uint64_t t = 0; t < 1000; t += 10) live_poll(&h, t);
    jsonl_emit_sensor_health(&g_s);
    const char *b = sink_read();
    ASSERT_EQ(count_of(b, "\"type\":\"cue\""), 0);
    ASSERT(strstr(b, "cue_active") == NULL);
    ASSERT_EQ(g_s.cue.on, 0);
    for (int i = 0; i < h.count; i++) ASSERT_EQ(h.slots[i].cue_until_ms, 0);
    live_end();
}

/* ── receive-only proof ──────────────────────────────────────────── */

/* A platform whose every op is a tripwire except set_channel, which
 * answers 0 and keeps the interface it was asked for. */
static int  g_trip_other;
static int  g_trip_set;
static int  g_trip_bad_iface;

static int  trip_ifaces(iface_stat_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_conns(conn_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_scan(wifi_ap_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_stas(wifi_sta_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_arp(arp_entry_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_dhcp(dhcp_lease_t *o, int m) { (void)o; (void)m; g_trip_other++; return 0; }
static void trip_init(void) { g_trip_other++; }
static void trip_cleanup(void) { g_trip_other++; }
static int  trip_sys_read(const char *p, char *b, int c) { (void)p; (void)b; (void)c; g_trip_other++; return -1; }
static int  trip_sys_list(const char *d, char *n, int s, int m) { (void)d; (void)n; (void)s; (void)m; g_trip_other++; return -1; }
static int  trip_self(uint8_t (*o)[6], int m) { (void)o; (void)m; g_trip_other++; return 0; }
static int  trip_set(const char *iface, int mhz) {
    (void)mhz;
    g_trip_set++;
    if (!iface || (strcmp(iface, "mon0") && strcmp(iface, "mon1") && strcmp(iface, "mon2")))
        g_trip_bad_iface++;
    return 0;
}

/* Cues driven through the whole hop stage, three sensor radios, two
 * minutes and more: the only platform call is set_channel, and only on
 * sloth's own monitor interfaces. No op that reads the network, scans
 * (the nl80211 trigger behind --allow-active is wifi_scan's) or could
 * reach a transmit path is called. Seen red with a deliberate
 * g_platform.wifi_scan(NULL, 0) added to cue_live_step(). */
static void test_cue_is_receive_only(void) {
    live_begin();
    cue_live_enable(1);
    platform_ops_t saved = g_platform;
    platform_ops_t trip = {
        .get_ifaces = trip_ifaces, .get_conns = trip_conns, .wifi_scan = trip_scan,
        .get_wifi_stations = trip_stas, .get_arp = trip_arp, .get_dhcp = trip_dhcp,
        .init = trip_init, .cleanup = trip_cleanup, .set_channel = trip_set,
        .sys_read = trip_sys_read, .sys_list = trip_sys_list, .get_self_macs = trip_self,
    };
    g_trip_other = g_trip_set = g_trip_bad_iface = 0;
    mon_radios_add("mon0");
    mon_radios_add("mon1");
    mon_radios_add("mon2");
    mon_radios_set_state(0, MON_RADIO_RUNNING, "");
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_RUNNING, "");
    chanhop_t h;
    chanhop_init(&h, k_long, N_LONG);           /* shares of 9, 8, 8 */
    ASSERT_EQ(mon_hop_setup(&h), 3);
    g_platform = trip;
    for (int i = 0; i < N_LONG; i++) {
        char id[ALERT_INCIDENT_ID_LEN];
        snprintf(id, sizeof(id), "c%07d", i);
        finding(i % 2 ? ALERT_TYPE_EVIL_TWIN : ALERT_TYPE_DEAUTH_FLOOD, id, mhz_of(k_long[i]));
    }
    for (uint64_t t = 0; t < CUE_DURATION_MS + 10000; t += 10) live_poll(&h, t);
    g_platform = saved;
    ASSERT_GT(g_trip_set, 100);
    ASSERT_EQ(g_trip_bad_iface, 0);
    ASSERT_EQ(g_trip_other, 0);
    /* Shares of 9, 8 and 8 at equal dwell: under the all-radios cap
     * (2026-11-24) four cues fit - two on one radio - and the active
     * cap (CUE_MAX_ACTIVE) stops the rest. */
    ASSERT_EQ((int)g_s.cue.started, CUE_MAX_ACTIVE);
    ASSERT_EQ(g_s.cue.active, 0);               /* all ended */
    live_end();
}

void run_chancue_tests(void) {
    TEST_SUITE("passive cueing, scheduler dwell (#248)");
    RUN_TEST(test_kinds_are_the_six);
    RUN_TEST(test_cued_dwell_is_four_times_for_120_s);
    RUN_TEST(test_cue_extends_the_open_dwell);
    RUN_TEST(test_cued_plan_is_clamped_to_the_budget);
    RUN_TEST(test_cue_every_channel_keeps_every_channel);
    RUN_TEST(test_false_triggers_on_ten_channels);
    RUN_TEST(test_active_cap);
    RUN_TEST(test_rate_cap);
    RUN_TEST(test_not_limits);
    RUN_TEST(test_cue_served_by_the_holding_radio);
    RUN_TEST(test_cap_is_over_all_radios);
    RUN_TEST(test_finding_channel);
    RUN_TEST(test_twin_lengthens_its_channel);
    RUN_TEST(test_cue_records);
    RUN_TEST(test_off_by_default);
    RUN_TEST(test_incident_offered_once_under_churn);
    RUN_TEST(test_no_event_lost_in_a_burst);
    RUN_TEST(test_cued_ms_survives_a_redeal);
    RUN_TEST(test_cue_fields_without_a_monitor);
    RUN_TEST(test_cue_is_receive_only);
}
