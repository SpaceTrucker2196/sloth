#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "alert_quality.h"
#include "alert_quality_capture.h"
#include "beacon_snoop.h"
#include "capture_side.h"
#include "cov_interval_capture.h"
#include "cov_timeline.h"
#include "deauth_snoop.h"
#include "evidence_ring.h"
#include "fake_platform.h"
#include "jsonl.h"
#include "mon_radios.h"
#include "posture.h"
#include "rule_coverage_live.h"
#include "sloth_clock.h"
#include "sys_status.h"
#include "tmp_dir.h"
#include "wifi_chanhop.h"
#include "views/alerts.h"
#ifdef WITH_PCAP
#include "capture/probe.h"
#include "frame_build.h"
#endif

/*
 * Quality fields on each finding (#246, src/alert_quality.h): complete
 * and its word, latency_ms, corroboration and src_state, as fire_inv()
 * stamps them, as the stream, the TUI's alert detail and --report carry
 * them, and the dwell and drop history (src/cov_timeline.h) they are
 * judged on.
 *
 * Every tick runs the poll's health stage (sys_status_poll, then
 * cov_live_poll) before any rule fires, as the poll loop does; the
 * coverage environment is the source rows of a monitor radio seeded by
 * hand, as tests/test_rule_coverage_live.c does. Every clock is pinned,
 * the wall clock in milliseconds too, so a latency is exact.
 * Evidence-ring records are what the monitor path stores; the
 * multi-radio acceptance case drives hand-built deauthentication
 * frames (IEEE 802.11-2020 9.3.3.12) through the real callback from
 * two radios. Every absence assertion names the mutation it was seen
 * red under (agents/AGENTS.md).
 */

TEST_STATE(g_s);

static uint64_t g_mono;
static time_t   g_wall;
static int64_t  g_wall_ms;
static uint64_t pin_mono(void)    { return g_mono; }
static time_t   pin_wall(void)    { return g_wall; }
static int64_t  pin_wall_ms(void) { return g_wall_ms; }

#define T0_S   1800000000
#define T0_MS  ((int64_t)T0_S * 1000)

static void set_wall_ms(int64_t ms) {
    g_wall_ms = ms;
    g_wall = (time_t)(ms / 1000);
}

static void begin(void) {
    capture_side_install();
    g_mono = 5000000;
    set_wall_ms(T0_MS - 10000);
    sloth_clock_test_set(pin_mono, pin_wall);
    sloth_clock_test_set_wall_ms(pin_wall_ms);
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    cov_tl_reset();
    alerts_clear();
    beacon_clear();
    deauth_clear();
    mon_radios_reset();
    evidence_ring_shutdown();
    ASSERT_EQ(evidence_ring_init(256 * 1024), 0);
    memset(&g_s, 0, sizeof(g_s));
}

static void end(void) {
    jsonl_close();
    alerts_clear();
    beacon_clear();
    deauth_clear();
    mon_radios_reset();
    evidence_ring_shutdown();
    cov_tl_reset();
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    capture_side_install();
    sloth_clock_test_set(NULL, NULL);
}

/* The health stage, as the poll runs it, at the pinned clocks. */
static void health(void) {
    g_mono += 1000;
    sys_status_poll(&g_s, g_wall, g_mono);
    cov_live_poll(&g_s);
}

static void monitor_up(void) {
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    g_s.mon_health.open = 1;
    g_s.mon_health.running = 1;
    g_s.mon_health.stale_secs = 0;
}

static void capture_up(void) {
    snprintf(g_s.pkt_iface, sizeof(g_s.pkt_iface), "eth0");
    g_s.pkt_linktype = 1;
    g_s.cap_health.open = 1;
    g_s.cap_health.running = 1;
}

/* --hop 1,6,11: the scan list the hop stage publishes. */
static void hopping(void) {
    static const int ch[] = { 1, 6, 11 };
    g_s.scan_chan_count = 3;
    for (int i = 0; i < 3; i++) g_s.scan_chans[i] = ch[i];
}

/* One frame into the evidence ring as the monitor path stores it, at
 * `ms` on the wall clock, on `freq`, from `radio`. The bytes are a
 * radiotap header and a beacon's first octets; nothing here reads them. */
static uint64_t note(int64_t ms, int freq, int radio) {
    static const uint8_t f[40] = { 0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x80 };
    uint64_t id = evidence_ring_note_radio(f, sizeof(f), sizeof(f),
                                           (time_t)(ms / 1000),
                                           (long)((ms % 1000) * 1000),
                                           (uint16_t)freq, -50, radio);
    ASSERT(id != 0);
    return id;
}

static int find_key(const char *prefix) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (!strncmp(g_s.alerts[i].key, prefix, strlen(prefix)) &&
            !g_s.alerts[i].resolved)
            return i;
    return -1;
}

static int find_type(alert_type_t t) {
    for (int i = 0; i < g_s.alert_count; i++)
        if (g_s.alerts[i].type == t && !g_s.alerts[i].resolved) return i;
    return -1;
}

/* ── the judge ─────────────────────────────────────────────────────── */

static aq_complete_t judge(cov_status_t st, cov_reason_t why, int hop,
                           int window, int64_t unc, int drops,
                           cov_reason_t *out) {
    aq_in_t in;
    memset(&in, 0, sizeof(in));
    in.st = st; in.why = why; in.hopping = hop; in.window = window;
    in.uncovered_ms = unc; in.drops = drops;
    return aq_judge(&in, out);
}

static void test_judge_precedence(void) {
    cov_reason_t w = COV_R_BAND;
    ASSERT_EQ(aq_judge(NULL, &w), AQ_COMPLETE_NONE);
    ASSERT_EQ(w, COV_R_NONE);
    /* The source first, then SENSOR_SUPPRESSED, then drops, then hop. */
    ASSERT_EQ(judge(COV_BLIND, COV_R_SOURCE_DOWN, 1, 1, 9999, 1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_SOURCE_DOWN);
    ASSERT_EQ(judge(COV_PARTLY, COV_R_SOURCE_STALE, 1, 1, 9999, 1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_SOURCE_STALE);
    ASSERT_EQ(judge(COV_PARTLY, COV_R_SUPPRESSED, 1, 1, 9999, 1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_SUPPRESSED);
    ASSERT_EQ(judge(COV_PARTLY, COV_R_HOP, 1, 1, 9999, 1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_DROPS);
    ASSERT_EQ(judge(COV_OBSERVABLE, COV_R_NONE, 1, 1, COV_TL_SLACK_MS + 1, 0, &w),
              AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_HOP);
    /* A window the history does not reach is not shown covered. */
    ASSERT_EQ(judge(COV_OBSERVABLE, COV_R_NONE, 1, 1, -1, -1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_HOP);
    /* The window decides over the rule's own `partly, hop`. */
    ASSERT_EQ(judge(COV_PARTLY, COV_R_HOP, 1, 1, COV_TL_SLACK_MS, 0, &w), AQ_COMPLETE_FULL);
    ASSERT_EQ(w, COV_R_NONE);
    ASSERT_EQ(judge(COV_PARTLY, COV_R_HOP, 1, 1, 0, -1, &w), AQ_COMPLETE_FULL);
    /* Not hopping: no hop question, whatever the history says. */
    ASSERT_EQ(judge(COV_PARTLY, COV_R_FIXED_CHANNEL, 0, 1, -1, 0, &w), AQ_COMPLETE_FULL);
    /* No window: the rule's status is the grain. */
    ASSERT_EQ(judge(COV_PARTLY, COV_R_HOP, 1, 0, -1, -1, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_HOP);
    ASSERT_EQ(judge(COV_PARTLY, COV_R_FIXED_CHANNEL, 0, 0, -1, -1, &w), AQ_COMPLETE_FULL);
    ASSERT_EQ(judge(COV_OBSERVABLE, COV_R_NONE, 1, 0, -1, -1, &w), AQ_COMPLETE_FULL);
    /* drops 0 or unknown is not a loss. */
    ASSERT_EQ(judge(COV_OBSERVABLE, COV_R_NONE, 0, 1, 0, -1, &w), AQ_COMPLETE_FULL);
    /* Blind for anything but a down source: no claim. */
    ASSERT_EQ(judge(COV_BLIND, COV_R_BAND, 1, 1, 0, 0, &w), AQ_COMPLETE_NONE);
    ASSERT_EQ(w, COV_R_NONE);
    ASSERT_EQ(judge(COV_BLIND, COV_R_NO_SOURCE, 0, 0, 0, 0, &w), AQ_COMPLETE_NONE);

    /* A cited frame has left the ring (review fix): the window the rest
     * span is not the incident's, so a clean-looking window does not
     * make it full. Seen red with the `lost` branch removed from
     * aq_judge() (full). The source words, which need no window, still
     * decide, and so does the rule's own `partly, hop`. */
    aq_in_t in;
    memset(&in, 0, sizeof(in));
    in.st = COV_OBSERVABLE; in.why = COV_R_NONE; in.window = 1; in.lost = 1;
    in.uncovered_ms = 0; in.drops = 0;
    ASSERT_EQ(aq_judge(&in, &w), AQ_COMPLETE_NONE);
    ASSERT_EQ(w, COV_R_NONE);
    in.window = 0;
    ASSERT_EQ(aq_judge(&in, &w), AQ_COMPLETE_NONE);
    in.st = COV_PARTLY; in.why = COV_R_HOP; in.hopping = 1;
    ASSERT_EQ(aq_judge(&in, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_HOP);
    in.why = COV_R_SOURCE_STALE;
    ASSERT_EQ(aq_judge(&in, &w), AQ_COMPLETE_PARTIAL);
    ASSERT_EQ(w, COV_R_SOURCE_STALE);
}

/* ── the dwell and drop history ───────────────────────────────────── */

static void test_timeline_uncovered(void) {
    cov_tl_reset();
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 0, 10), -1);
    cov_tl_hop_note(0, 2412, 1000);
    cov_tl_hop_note(0, 2437, 1450);
    cov_tl_hop_note(0, 2462, 2000);
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1000, 1400), 0);
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1000, 1700), 250);
    ASSERT_EQ(cov_tl_uncovered_ms(2437, 1500, 1900), 0);
    ASSERT_EQ(cov_tl_uncovered_ms(2437, 1500, 2100), 100);
    /* The newest dwell runs to the window's end. */
    ASSERT_EQ(cov_tl_uncovered_ms(2462, 2000, 9000), 0);
    /* Before the oldest dwell the ring holds: uncovered. */
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 500, 1200), 500);
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1200, 1200), 0);
    ASSERT_EQ(cov_tl_uncovered_ms(5180, 1000, 1100), 100);

    /* A second radio on the same channel, overlapping: the union, not
     * the sum. Seen red with the pieces summed instead of merged (the
     * overlap 1400..1450 counted twice: -50). The notes in time order,
     * as the hop stage makes them. */
    cov_tl_reset();
    cov_tl_hop_note(0, 2412, 1000);
    cov_tl_hop_note(1, 2412, 1400);
    cov_tl_hop_note(0, 2437, 1450);
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1000, 1700), 0);
    /* Dealt out at 1600: its dwell stops there. Seen red with the
     * freq-0 entry skipped as a dwell boundary (radio 1 kept 2412 to
     * the window's end: 0). */
    cov_tl_hop_note(1, 0, 1600);
    cov_tl_hop_note(0, 2462, 2000);
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1000, 1700), 100);
    int f = -1; int64_t ms = 0;
    ASSERT_EQ(cov_tl_radio_last(1, &f, &ms), 1);
    ASSERT_EQ(f, 0);
    ASSERT_EQ(ms, 1600);
    ASSERT_EQ(cov_tl_radio_last(3, &f, &ms), 0);

    /* A wall step back is stored at the previous note's time. */
    cov_tl_hop_note(0, 2412, 500);
    ASSERT_EQ(cov_tl_radio_last(0, &f, &ms), 1);
    ASSERT_EQ(ms, 2000);
    ASSERT_EQ(f, 2412);

    /* Bounded. */
    for (int i = 0; i < COV_TL_DWELLS + 5; i++)
        cov_tl_hop_note(i % 2, 2412 + 25 * (i % 3), 3000 + i);
    ASSERT_EQ(cov_tl_dwell_count(), COV_TL_DWELLS);
    cov_tl_hop_note(COV_TL_RADIOS, 2412, 99999);
    ASSERT_EQ(cov_tl_dwell_count(), COV_TL_DWELLS);
    ASSERT_EQ(cov_tl_radio_last(COV_TL_RADIOS, &f, &ms), 0);
    cov_tl_reset();
    ASSERT_EQ(cov_tl_dwell_count(), 0);

    /* Many pieces from two radios (the review fix reverses the newest-
     * first walk before the sort): radio 0 on 2412 at +0 of each 200 ms
     * cycle, radio 1 at +50, each 100 ms; 150 of every 200 ms covered,
     * 100 cycles, 200 pieces. */
    for (int k = 0; k < 100; k++) {
        cov_tl_hop_note(0, 2412, 1000 + 200 * k);
        cov_tl_hop_note(1, 2412, 1050 + 200 * k);
        cov_tl_hop_note(0, 2437, 1100 + 200 * k);
        cov_tl_hop_note(1, 2462, 1150 + 200 * k);
    }
    ASSERT_EQ(cov_tl_uncovered_ms(2412, 1000, 21000), 5000);
    ASSERT_EQ(cov_tl_uncovered_ms(2437, 1000, 21000), 10000);
    cov_tl_reset();
}

static void test_timeline_drops(void) {
    cov_tl_reset();
    ASSERT_EQ(cov_tl_drops_in(0, 10), -1);
    cov_tl_drops_note(1000, 5);
    cov_tl_drops_note(2000, 5);
    cov_tl_drops_note(3000, 9);
    ASSERT_EQ(cov_tl_drops_in(1000, 1900), 0);
    ASSERT_EQ(cov_tl_drops_in(1500, 2500), 1);
    ASSERT_EQ(cov_tl_drops_in(2000, 2999), 1);   /* the tick holding the edge */
    /* No sample before the window: not known. */
    ASSERT_EQ(cov_tl_drops_in(500, 1500), -1);
    /* None after its start: not known. */
    ASSERT_EQ(cov_tl_drops_in(3000, 3500), -1);
    /* Past the newest sample, the newest is the end. */
    ASSERT_EQ(cov_tl_drops_in(1000, 9000), 1);
    for (int i = 0; i < COV_TL_DROPS + 3; i++) cov_tl_drops_note(4000 + i, 9);
    ASSERT_EQ(cov_tl_drop_count(), COV_TL_DROPS);
    cov_tl_reset();
}

/* The capture side's reader: times, channels and radios of the frames
 * the ring still holds; an evicted citation adds nothing. */
static void test_capture_reader(void) {
    begin();
    uint64_t ids[3];
    ids[0] = note(T0_MS + 300, 2437, 1);
    ids[1] = note(T0_MS + 100, 2412, 0);
    ids[2] = 999999;                       /* never issued */
    aq_evidence_t ev;
    ASSERT_EQ(aq_capture_evidence(ids, 3, 0, &ev), 2);
    ASSERT_EQ(ev.first_ms, T0_MS + 100);
    ASSERT_EQ(ev.last_ms, T0_MS + 300);
    ASSERT_EQ(ev.radio_mask, 0x3);
    ASSERT_EQ(ev.uncovered_ms, -1);        /* not asked */
    ASSERT_EQ(ev.drops, -1);
    cov_tl_hop_note(0, 2412, T0_MS);
    cov_tl_hop_note(0, 2437, T0_MS + 200);
    ASSERT_EQ(aq_capture_evidence(ids, 3, 1, &ev), 2);
    /* 2412 is left at +200, 2437 not reached before +200: 100 each. */
    ASSERT_EQ(ev.uncovered_ms, 100);
    ASSERT_EQ(aq_capture_evidence(ids + 2, 1, 1, &ev), 0);
    ASSERT_EQ(ev.radio_mask, 0);
    end();
}

/* ── acceptance 1: a twin under a hop plan that misses the window ──── */

static const uint8_t WEAK[6]   = {0x02,0x46,0x00,0x00,0x00,0x01};
static const uint8_t STRONG[6] = {0x00,0x46,0x00,0x00,0x00,0x02};

/* An OPEN copy of a WPA2 network (the weak/strong twin of
 * tests/test_evidence_cite.c), three beacons a half, each cited by the
 * evidence-ring record the monitor path stored for it. */
static void twin(int64_t weak_ms, int weak_freq, int64_t strong_ms, int strong_freq) {
    for (int k = 0; k < 3; k++) {
        uint64_t id = note(weak_ms + 100 * k, weak_freq, 0);
        beacon_record_ev(WEAK, "Corp", -50, weak_freq == 2412 ? 1 : 6,
                         "OPEN", 100, NULL, id);
    }
    for (int k = 0; k < 3; k++) {
        uint64_t id = note(strong_ms + 100 * k, strong_freq, 0);
        beacon_record_ev(STRONG, "Corp", -50, strong_freq == 2412 ? 1 : 6,
                         "WPA2", 100, NULL, id);
    }
}

static const alert_t *fire_twin(void) {
    health();
    beacon_snapshot(&g_s);
    alerts_update(&g_s);
    int i = find_key("twin:");
    ASSERT(i >= 0);
    return i >= 0 ? &g_s.alerts[i] : NULL;
}

/* One radio hopping 1, 6, 11. The weak half beacons on channel 1 at
 * +0..+200 ms, the strong half on channel 6 at +500..+700; the radio
 * left channel 1 at +450 for channel 6. The window +0..+700 had no
 * radio on channel 1 for 250 ms: partial, hop. EVIL_TWIN's own status
 * under --hop is observable (a beacon repeats), so this is the window's
 * verdict, not the rule's. */
static void test_twin_under_a_hop_that_misses_the_window_is_partial(void) {
    begin();
    monitor_up();
    hopping();
    cov_tl_hop_note(0, 2412, T0_MS - 1000);
    cov_tl_hop_note(0, 2437, T0_MS + 450);
    twin(T0_MS, 2412, T0_MS + 500, 2437);
    set_wall_ms(T0_MS + 1700);
    const alert_t *a = fire_twin();
    if (a) {
        cov_status_t st; cov_reason_t why;
        ASSERT_EQ(cov_live_get(ALERT_TYPE_EVIL_TWIN, &st, &why), 1);
        ASSERT_EQ(st, COV_OBSERVABLE);
        ASSERT_EQ(a->quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(a->quality.complete_why, COV_R_HOP);
        ASSERT_EQ(a->quality.has_latency, 1);
        ASSERT_EQ((long long)a->quality.latency_ms, 1700);
        ASSERT_EQ(aq_corroboration(&a->quality), 1);
        ASSERT_EQ(a->quality.src_state, AQ_SRC_OK);
        /* Evidence only: the title and severity the rule gave. */
        ASSERT_STR(a->title, "EVIL_TWIN");
    }
    end();
}

/* The same twin with both halves on channel 6 and the radio there from
 * before the first beacon to after the last: full. Seen red with the
 * judge's hop test reading `uncovered_ms >= 0` (any window under --hop
 * partial). */
static void test_twin_inside_one_dwell_is_full(void) {
    begin();
    monitor_up();
    hopping();
    cov_tl_hop_note(0, 2437, T0_MS - 50);
    cov_tl_hop_note(0, 2462, T0_MS + 900);
    twin(T0_MS, 2437, T0_MS + 400, 2437);
    set_wall_ms(T0_MS + 1200);
    const alert_t *a = fire_twin();
    if (a) {
        ASSERT_EQ(a->quality.complete, AQ_COMPLETE_FULL);
        ASSERT_EQ(a->quality.complete_why, COV_R_NONE);
        ASSERT_EQ((long long)a->quality.latency_ms, 1200);
    }
    end();
}

/* A frame captured a little before its dwell was stamped (the retune
 * is confirmed after the driver call returns) is inside the slack. */
static void test_a_frame_just_before_its_dwell_stamp_is_inside_the_slack(void) {
    begin();
    monitor_up();
    hopping();
    cov_tl_hop_note(0, 2412, T0_MS - 5000);
    cov_tl_hop_note(0, 2437, T0_MS + 40);
    twin(T0_MS, 2437, T0_MS + 300, 2437);
    set_wall_ms(T0_MS + 900);
    const alert_t *a = fire_twin();
    if (a) ASSERT_EQ(a->quality.complete, AQ_COMPLETE_FULL);
    end();
}

/* Once partial, partial with its first word: a later evaluation whose
 * citations sit inside one dwell does not make the incident full. Seen
 * red with the `complete != PARTIAL` guard dropped from the stamp. */
static void test_partial_stays_partial(void) {
    begin();
    monitor_up();
    hopping();
    cov_tl_hop_note(0, 2412, T0_MS - 1000);
    cov_tl_hop_note(0, 2437, T0_MS + 450);
    twin(T0_MS, 2412, T0_MS + 500, 2437);
    set_wall_ms(T0_MS + 1700);
    const alert_t *a = fire_twin();
    ASSERT(a && a->quality.complete == AQ_COMPLETE_PARTIAL);
    /* The newest beacons of both halves, now all on channel 6 inside
     * one dwell: enough of them that every beacon the rule cites is a
     * new one (BEACON_EVIDENCE_IDS a half). */
    cov_tl_hop_note(0, 2437, T0_MS + 5000);
    for (int k = 0; k < BEACON_EVIDENCE_IDS; k++) {
        beacon_record_ev(WEAK, "Corp", -50, 6, "OPEN", 100, NULL,
                         note(T0_MS + 5100 + 10 * k, 2437, 0));
        beacon_record_ev(STRONG, "Corp", -50, 6, "WPA2", 100, NULL,
                         note(T0_MS + 5300 + 10 * k, 2437, 0));
    }
    set_wall_ms(T0_MS + 6000);
    a = fire_twin();
    if (a) {
        ASSERT_EQ(a->quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(a->quality.complete_why, COV_R_HOP);
        /* Taken once, as the incident opened. */
        ASSERT_EQ((long long)a->quality.latency_ms, 1700);
    }
    end();
}

/* ── acceptance 2: the same finding from two radios ───────────────── */

#ifdef WITH_PCAP
static const uint8_t STA[6]   = {0x02,0x46,0x55,0x66,0x77,0x01};
static const uint8_t BSSID[6] = {0x06,0x46,0xbb,0xcc,0xdd,0x02};

/* Radiotap (CHANNEL, antenna signal) and a deauthentication frame, IEEE
 * 802.11-2020 9.3.3.12: FC 0x00c0, duration, addr1 the victim, addr2 and
 * addr3 the BSSID, Sequence Control seq << 4, Reason Code 7. */
static int rt_deauth(uint8_t *f, int cap, uint16_t seq, uint16_t freq) {
    fb_t b; fb_init(&b, f, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof(rt));
    rt.has_channel = 1; rt.freq_mhz = freq;
    rt.has_signal  = 1; rt.dbm = -45;
    fb_radiotap(&b, &rt);
    fb_u8(&b, 0xc0); fb_u8(&b, 0x00);
    fb_le16(&b, 0x013a);
    fb_mac(&b, STA); fb_mac(&b, BSSID); fb_mac(&b, BSSID);
    fb_le16(&b, (uint16_t)(seq << 4));
    fb_le16(&b, 7);
    return fb_ok(&b) ? b.len : -1;
}

static int dispatch(int radio, const uint8_t *f, int len, int64_t ms) {
    const uint8_t *fs[1] = { f };
    int ls[1] = { len };
    uint32_t sec = (uint32_t)(ms / 1000), usec = (uint32_t)((ms % 1000) * 1000);
    return probe_test_dispatch_radio(radio, fs, ls, &sec, &usec, 1);
}

static const alert_t *fire_deauth(void) {
    health();
    deauth_snapshot(&g_s);
    alerts_update(&g_s);
    int i = find_type(ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(i >= 0);
    return i >= 0 ? &g_s.alerts[i] : NULL;
}

/* Two sensor radios on one channel each deliver part of a deauth flood
 * (different frames: each sequence number is heard by one): the cited
 * frames came from both, corroboration 2. */
static void test_a_flood_two_radios_delivered_is_corroborated_twice(void) {
    begin();
    monitor_up();
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    ASSERT_EQ(mon_radios_add("mon1"), 1);
    uint8_t f[96];
    for (int k = 0; k < 8; k++) {
        int n = rt_deauth(f, sizeof(f), (uint16_t)(100 + k), 2437);
        ASSERT(n > 0);
        ASSERT_EQ(dispatch(k % 2, f, n, T0_MS + 50 * k), 1);
    }
    set_wall_ms(T0_MS + 1000);
    const alert_t *a = fire_deauth();
    if (a) {
        ASSERT(a->evidence_id_count >= 2);
        ASSERT_EQ(aq_corroboration(&a->quality), 2);
        ASSERT_EQ(a->quality.radio_mask, 0x3);
        /* Not hopping, a fixed radio: the window was watched whole. */
        ASSERT_EQ(a->quality.complete, AQ_COMPLETE_FULL);
        ASSERT_EQ(a->quality.has_latency, 1);
    }
    end();
}

/* Both radios hear every frame, and radio 1's copies lose the
 * cross-radio de-duplication: only radio 0 delivered, corroboration 1.
 * The count is the radios that delivered, a lower bound on the radios
 * that heard (src/alert_quality.h). Seen red with probe.c noting every
 * frame as radio 1 (corroboration counted radio 1 only: mask 0x2). */
static void test_copies_dropped_as_duplicates_are_not_counted(void) {
    begin();
    monitor_up();
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    ASSERT_EQ(mon_radios_add("mon1"), 1);
    uint8_t f[96];
    for (int k = 0; k < 8; k++) {
        int n = rt_deauth(f, sizeof(f), (uint16_t)(200 + k), 2437);
        ASSERT_EQ(dispatch(0, f, n, T0_MS + 50 * k), 1);
        ASSERT_EQ(dispatch(1, f, n, T0_MS + 50 * k), 1);
    }
    set_wall_ms(T0_MS + 1000);
    const alert_t *a = fire_deauth();
    if (a) {
        ASSERT_EQ(aq_corroboration(&a->quality), 1);
        ASSERT_EQ(a->quality.radio_mask, 0x1);
    }
    end();
}
#endif

/* ── the source, drops, a rule with no frames ─────────────────────── */

static void test_source_stale_and_down(void) {
    begin();
    monitor_up();
    g_s.mon_health.stale_secs = 3600;
    health();
    alerts_fire_for_test(ALERT_TYPE_HANDSHAKE_HARVEST, ALERT_SEV_WARN,
                         "q:stale", "x", NULL, 0);
    alerts_update(&g_s);
    int i = find_key("q:stale");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(g_s.alerts[i].quality.complete_why, COV_R_SOURCE_STALE);
        ASSERT_EQ(g_s.alerts[i].quality.src_state, AQ_SRC_STALE);
    }
    g_s.mon_health.running = 0;
    g_s.mon_health.open = 0;
    health();
    alerts_fire_for_test(ALERT_TYPE_HANDSHAKE_HARVEST, ALERT_SEV_WARN,
                         "q:down", "x", NULL, 0);
    alerts_update(&g_s);
    i = find_key("q:down");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.src_state, AQ_SRC_DOWN);
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(g_s.alerts[i].quality.complete_why, COV_R_SOURCE_DOWN);
    }
    end();
}

/* An EXCHANGE rule that cites no frame, under --hop: its own status
 * (partly, hop) is the finest grain there is. An IP rule beside it is
 * full, its source the capture. */
static void test_a_rule_with_no_frames_takes_its_status(void) {
    begin();
    monitor_up();
    capture_up();
    hopping();
    health();
    alerts_fire_for_test(ALERT_TYPE_HANDSHAKE_HARVEST, ALERT_SEV_WARN,
                         "q:hs", "x", NULL, 0);
    alerts_fire_for_test(ALERT_TYPE_THREAT_DOMAIN, ALERT_SEV_WARN,
                         "q:td", "x", NULL, 0);
    alerts_update(&g_s);
    int i = find_key("q:hs"), j = find_key("q:td");
    ASSERT(i >= 0 && j >= 0);
    if (i >= 0 && j >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(g_s.alerts[i].quality.complete_why, COV_R_HOP);
        ASSERT_EQ(g_s.alerts[j].quality.complete, AQ_COMPLETE_FULL);
        ASSERT_EQ(g_s.alerts[j].quality.src_state, AQ_SRC_OK);
        /* Seen red with `ev.n > 0` dropped from the latency condition
         * (a latency from capture time 0). */
        ASSERT_EQ(g_s.alerts[i].quality.has_latency, 0);
    }
    end();
}

/* The monitor handle dropped frames in the tick the cited frames span:
 * partial, drops, even with the radio on the channel throughout. */
static void test_drops_inside_the_window(void) {
    begin();
    monitor_up();
    health();
    cov_tl_drops_note(T0_MS - 500, 10);
    cov_tl_drops_note(T0_MS + 500, 10);
    cov_tl_drops_note(T0_MS + 1500, 12);
    uint64_t ids[2] = { note(T0_MS + 800, 2437, 0), note(T0_MS + 1200, 2437, 0) };
    set_wall_ms(T0_MS + 1600);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:drop",
                            "x", NULL, 0, ids, 2);
    /* A second incident whose frames lie before the rise. */
    uint64_t early[2] = { note(T0_MS - 400, 2437, 0), note(T0_MS - 100, 2437, 0) };
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:nodrop",
                            "x", NULL, 0, early, 2);
    alerts_update(&g_s);
    int i = find_key("q:drop"), j = find_key("q:nodrop");
    ASSERT(i >= 0 && j >= 0);
    if (i >= 0 && j >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_PARTIAL);
        ASSERT_EQ(g_s.alerts[i].quality.complete_why, COV_R_DROPS);
        ASSERT_EQ((long long)g_s.alerts[i].quality.latency_ms, 800);
        ASSERT_EQ(g_s.alerts[j].quality.complete, AQ_COMPLETE_FULL);
    }
    end();
}

/* ── not assessed ─────────────────────────────────────────────────── */

/* Before the first status sample, and in a --replay run, nothing is
 * judged: no complete, no src_state, no latency. Before the sample the
 * radios that delivered the cited frames are still known; in a replay
 * they are not this sensor's radios. Seen red with the stamp's
 * `assessed` forced to 1 (complete full, src_state empty word). */
static void test_not_assessed_before_a_sample_or_on_replay(void) {
    begin();
    monitor_up();
    uint64_t ids[1] = { note(T0_MS, 2437, 0) };
    set_wall_ms(T0_MS + 300);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:pend",
                            "x", NULL, 0, ids, 1);
    alerts_update(&g_s);
    int i = find_key("q:pend");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_NONE);
        ASSERT_EQ(g_s.alerts[i].quality.src_state, AQ_SRC_NONE);
        ASSERT_EQ(g_s.alerts[i].quality.has_latency, 0);
        ASSERT_EQ(aq_corroboration(&g_s.alerts[i].quality), 1);
    }
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "replay");
    health();
    ASSERT_EQ(cov_live_state(), COV_LIVE_DECLINED);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:replay",
                            "x", NULL, 0, ids, 1);
    alerts_update(&g_s);
    i = find_key("q:replay");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_NONE);
        ASSERT_EQ(g_s.alerts[i].quality.has_latency, 0);
        /* A replayed frame's radio is not one of this sensor's: no
         * corroboration (review fix). Seen red with the stamp ORing the
         * mask whatever the live state (1). */
        ASSERT_EQ(aq_corroboration(&g_s.alerts[i].quality), 0);
    }
    end();
}


/* ── review fixes: a judged incident keeps its word; lost frames ──── */

/* An incident judged full stays full when a later evaluation cannot
 * judge (here the monitor source is no longer configured: blind, no
 * source), as sloth.db's upsert keeps it. Seen red with the stamp
 * writing aq_judge()'s NONE back (complete 0). */
static void test_full_stays_full_when_the_rule_goes_blind(void) {
    begin();
    monitor_up();
    health();
    uint64_t ids[1] = { note(T0_MS, 2437, 0) };
    set_wall_ms(T0_MS + 300);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:full",
                            "x", NULL, 0, ids, 1);
    alerts_update(&g_s);
    int i = find_key("q:full");
    ASSERT(i >= 0);
    if (i >= 0) ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_FULL);
    g_s.probe_iface[0] = '\0';
    memset(&g_s.mon_health, 0, sizeof(g_s.mon_health));
    health();
    cov_status_t st = COV_OBSERVABLE; cov_reason_t why = COV_R_NONE;
    ASSERT_EQ(cov_live_get(ALERT_TYPE_DEAUTH_FLOOD, &st, &why), 1);
    ASSERT_EQ(st, COV_BLIND);
    ASSERT(why != COV_R_SOURCE_DOWN);
    set_wall_ms(T0_MS + 1300);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:full",
                            "x", NULL, 0, ids, 1);
    alerts_update(&g_s);
    i = find_key("q:full");
    ASSERT(i >= 0);
    if (i >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_FULL);
        ASSERT_EQ(g_s.alerts[i].quality.complete_why, COV_R_NONE);
    }
    end();
}

/* A finding some of whose cited frames have left the evidence ring is
 * not stamped full: the frames still held span a window that is not
 * the incident's, and a flood that turns the ring over must not hide a
 * drop or a hop gap behind `full`. No latency either: the oldest held
 * frame is not the oldest cited. A never-issued id misses exactly as an
 * evicted one does (evidence_ring_get()'s range test). Seen red with
 * `lost` forced to 0 in the stamp (both full, the first with a 300 ms
 * latency). */
static void test_cited_frames_gone_from_the_ring_are_not_full(void) {
    begin();
    monitor_up();
    health();
    uint64_t some[2] = { 999990, note(T0_MS, 2437, 0) };
    uint64_t none[1] = { 999991 };
    set_wall_ms(T0_MS + 300);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:some",
                            "x", NULL, 0, some, 2);
    alerts_fire_ev_for_test(ALERT_TYPE_DEAUTH_FLOOD, ALERT_SEV_WARN, "q:none",
                            "x", NULL, 0, none, 1);
    alerts_update(&g_s);
    int i = find_key("q:some"), j = find_key("q:none");
    ASSERT(i >= 0 && j >= 0);
    if (i >= 0 && j >= 0) {
        ASSERT_EQ(g_s.alerts[i].quality.complete, AQ_COMPLETE_NONE);
        ASSERT_EQ(g_s.alerts[i].quality.has_latency, 0);
        ASSERT_EQ(g_s.alerts[j].quality.complete, AQ_COMPLETE_NONE);
        /* Still assessed: the source is known. */
        ASSERT_EQ(g_s.alerts[i].quality.src_state, AQ_SRC_OK);
        /* The held frame's radio still delivered it. */
        ASSERT_EQ(aq_corroboration(&g_s.alerts[i].quality), 1);
    }
    end();
}

/* The capture stage writes the monitor handle's drop total each tick,
 * ps_drop plus ps_ifdrop, only while pcap_stats() answers. Seen red
 * with the cov_tl_drops_note() call removed from cov_iv_capture_poll()
 * (count 0), with ps_ifdrop left out of the sum (the rise at +1500 not
 * seen: 0), and with the stats_ok() guard removed (a fourth entry). */
static void test_the_capture_stage_writes_the_drop_totals(void) {
    begin();
    cov_iv_capture_reset();
    monitor_up();
    g_s.mon_health.stats_valid = 1;
    g_s.mon_health.ps_drop = 10;
    set_wall_ms(T0_MS - 500);
    cov_iv_capture_poll(&g_s, g_wall, g_mono += 1000);
    set_wall_ms(T0_MS + 500);
    cov_iv_capture_poll(&g_s, g_wall, g_mono += 1000);
    g_s.mon_health.ps_ifdrop = 3;
    set_wall_ms(T0_MS + 1500);
    cov_iv_capture_poll(&g_s, g_wall, g_mono += 1000);
    ASSERT_EQ(cov_tl_drop_count(), 3);
    ASSERT_EQ(cov_tl_drops_in(T0_MS - 400, T0_MS - 100), 0);
    ASSERT_EQ(cov_tl_drops_in(T0_MS + 800, T0_MS + 1200), 1);
    g_s.mon_health.stats_valid = 0;
    g_s.mon_health.ps_drop = 50;
    set_wall_ms(T0_MS + 2500);
    cov_iv_capture_poll(&g_s, g_wall, g_mono += 1000);
    ASSERT_EQ(cov_tl_drop_count(), 3);
    cov_iv_capture_reset();
    end();
}

/* ── the hop stage feeds the history ──────────────────────────────── */

static sloth_state_t g_hs;

/* Radio 0 through chanhop_service() and radio 1 through
 * mon_hop_service(), against the fake platform: each confirmed retune
 * is a dwell at the wall clock. A radio dealt out is marked gone. Seen
 * red with either cov_tl_hop_note() call removed (no entry for that
 * radio), and with deal()'s gone mark removed (radio 2 kept its last
 * channel). */
static void test_the_hop_stage_writes_each_radios_dwells(void) {
    begin();
    memset(&g_hs, 0, sizeof(g_hs));
    snprintf(g_hs.probe_iface, sizeof(g_hs.probe_iface), "mon0");
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    ASSERT_EQ(mon_radios_add("mon1"), 1);
    ASSERT_EQ(mon_radios_add("mon2"), 2);
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_RUNNING, "");
    chanhop_t h0;
    chanhop_init_default(&h0);
    ASSERT_EQ(mon_hop_setup(&h0), 3);
    for (uint64_t t = 0; t <= 2000; t += 50) {
        set_wall_ms(T0_MS + (int64_t)t);
        chanhop_service(&h0, &g_hs, t, mon_hop_radio0_delta());
        mon_hop_service(&h0, t);
    }
    int f = 0; int64_t ms = 0;
    ASSERT_EQ(cov_tl_radio_last(0, &f, &ms), 1);
    ASSERT_EQ(f, chanhop_current_freq(&h0));
    ASSERT_EQ(cov_tl_radio_last(1, &f, &ms), 1);
    ASSERT_EQ(f, chanhop_current_freq(mon_hop_sched(1)));
    ASSERT(ms >= T0_MS && ms <= T0_MS + 2000);
    ASSERT_EQ(cov_tl_radio_last(2, &f, &ms), 1);
    ASSERT(f > 0);
    mon_radios_set_state(2, MON_RADIO_LOST, "gone");
    set_wall_ms(T0_MS + 2050);
    ASSERT_EQ(mon_hop_service(&h0, 2050), 1);
    ASSERT_EQ(cov_tl_radio_last(2, &f, &ms), 1);
    ASSERT_EQ(f, 0);
    ASSERT_EQ(ms, T0_MS + 2050);
    end();
}

/* ── the stream ───────────────────────────────────────────────────── */

static char g_path[TEST_TMP_MAX];
static char g_buf[1 << 17];

static void sink_open(void) {
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_aq_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
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

/* The line of `type` for `key`, copied into out. */
static int line_of(const char *body, const char *type, const char *key,
                   char *out, size_t sz) {
    char t[48], k[96];
    snprintf(t, sizeof(t), "{\"type\":\"%s\"", type);
    snprintf(k, sizeof(k), "\"key\":\"%s\"", key);
    for (const char *p = body; p && *p; ) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        if (n < sz && !strncmp(p, t, strlen(t))) {
            memcpy(out, p, n);
            out[n] = '\0';
            if (strstr(out, k)) return 1;
        }
        p = nl ? nl + 1 : NULL;
    }
    out[0] = '\0';
    return 0;
}

/* `alert` and `alert.create` carry the five fields, and a finding that
 * was not assessed carries none of them. Seen red with emit_quality()
 * writing `complete` and `src_state` whatever their value ("complete":""
 * on the unassessed line) and with its call removed from the lifecycle
 * emitter. */
static void test_the_stream_carries_the_fields(void) {
    begin();
    monitor_up();
    hopping();
    cov_tl_hop_note(0, 2412, T0_MS - 1000);
    cov_tl_hop_note(0, 2437, T0_MS + 450);
    twin(T0_MS, 2412, T0_MS + 500, 2437);
    set_wall_ms(T0_MS + 1700);
    sink_open();
    const alert_t *a = fire_twin();
    char key[ALERT_KEY_LEN];
    snprintf(key, sizeof(key), "%s", a ? a->key : "");
    const char *body = sink_read();
    static char line[8192];
    ASSERT_EQ(line_of(body, "alert", key, line, sizeof(line)), 1);
    ASSERT(strstr(line, "\"complete\":\"partial\",\"complete_why\":\"hop\","
                        "\"latency_ms\":1700,\"corroboration\":1,"
                        "\"src_state\":\"ok\"") != NULL);
    ASSERT_EQ(line_of(body, "alert.create", key, line, sizeof(line)), 1);
    ASSERT(strstr(line, "\"complete\":\"partial\",\"complete_why\":\"hop\","
                        "\"latency_ms\":1700,\"corroboration\":1,"
                        "\"src_state\":\"ok\"") != NULL);
    end();

    begin();
    sink_open();
    alerts_fire_for_test(ALERT_TYPE_PORT_SCAN, ALERT_SEV_LOW, "q:bare", "x", NULL, 0);
    body = sink_read();
    ASSERT_EQ(line_of(body, "alert", "q:bare", line, sizeof(line)), 1);
    ASSERT(strstr(line, "\"complete") == NULL);
    ASSERT(strstr(line, "\"latency_ms\"") == NULL);
    ASSERT(strstr(line, "\"corroboration\"") == NULL);
    ASSERT(strstr(line, "\"src_state\"") == NULL);
    ASSERT_EQ(line_of(body, "alert.create", "q:bare", line, sizeof(line)), 1);
    ASSERT(strstr(line, "\"complete") == NULL);
    ASSERT(strstr(line, "\"src_state\"") == NULL);
    end();
}

/* ── where a person reads it ──────────────────────────────────────── */

static void test_the_line_and_the_title_tag(void) {
    alert_quality_t q;
    memset(&q, 0, sizeof(q));
    char buf[160], tag[48];
    ASSERT_EQ(alert_quality_line(&q, buf, sizeof(buf)), 0);
    ASSERT_STR(buf, "");
    ASSERT_STR(alert_quality_title_tag(&q, tag, sizeof(tag)), "");
    q.complete = AQ_COMPLETE_PARTIAL;
    q.complete_why = COV_R_HOP;
    q.has_latency = 1;
    q.latency_ms = 1240;
    q.radio_mask = 0x5;
    q.src_state = AQ_SRC_OK;
    alert_quality_line(&q, buf, sizeof(buf));
    ASSERT_STR(buf, "complete partial (hop), latency 1240 ms, "
                    "corroboration 2 radios, source ok");
    ASSERT_STR(alert_quality_title_tag(&q, tag, sizeof(tag)), " (partial: hop)");
    q.complete = AQ_COMPLETE_FULL;
    q.complete_why = COV_R_NONE;
    q.has_latency = 0;
    q.radio_mask = 0x1;
    q.src_state = AQ_SRC_NONE;
    alert_quality_line(&q, buf, sizeof(buf));
    ASSERT_STR(buf, "complete full, corroboration 1 radio");
    /* A full finding's title line says nothing more. */
    ASSERT_STR(alert_quality_title_tag(&q, tag, sizeof(tag)), "");
    /* Truncates, terminated. */
    q.complete = AQ_COMPLETE_PARTIAL; q.complete_why = COV_R_SOURCE_STALE;
    ASSERT_EQ(alert_quality_line(&q, buf, 12), 11);
    ASSERT_STR(buf, "complete pa");
    ASSERT_STR(aq_complete_name(0), "");
    ASSERT_STR(aq_complete_name(9), "");
    ASSERT_STR(aq_src_name(AQ_SRC_DOWN), "down");
    ASSERT_STR(aq_src_name(7), "");
    ASSERT_STR(cov_reason_name(COV_R_DROPS), "drops");
}

static void quality_alert(alert_t *a) {
    memset(a, 0, sizeof(*a));
    a->type = ALERT_TYPE_EVIL_TWIN;
    a->sev  = ALERT_SEV_WARN;
    a->count = 1;
    snprintf(a->title, sizeof(a->title), "EVIL_TWIN");
    snprintf(a->key, sizeof(a->key), "twin:q");
    snprintf(a->detail, sizeof(a->detail), "a twin");
    snprintf(a->incident_id, sizeof(a->incident_id), "00000000000000d1");
    a->first_seen = a->last_seen = a->first_detected = (time_t)1700000000;
    a->quality.complete = AQ_COMPLETE_PARTIAL;
    a->quality.complete_why = COV_R_HOP;
    a->quality.has_latency = 1;
    a->quality.latency_ms = 1700;
    a->quality.radio_mask = 0x1;
    a->quality.src_state = AQ_SRC_OK;
}

/* The TUI's alert detail: the title line says partial, the alert's
 * title field does not change, and the four fields are one line. */
static void test_the_alert_detail_shows_them(void) {
    memset(&g_s, 0, sizeof(g_s));
    quality_alert(&g_s.alerts[0]);
    g_s.alert_count = 1;
    g_s.alert_sel = 0;
    g_s.alert_detail = 1;
    static char buf[16384];
    tui_test_erase();
    view_alerts_draw(&g_s);
    tui_test_screen(buf, sizeof(buf));
    ASSERT(strstr(buf, "WARN  EVIL_TWIN (partial: hop)") != NULL);
    ASSERT(strstr(buf, "Quality:    complete partial (hop), latency 1700 ms, "
                       "corroboration 1 radio, source ok") != NULL);
    ASSERT_STR(g_s.alerts[0].title, "EVIL_TWIN");
    /* Nothing known: said, not left blank. */
    memset(&g_s.alerts[0].quality, 0, sizeof(g_s.alerts[0].quality));
    tui_test_erase();
    view_alerts_draw(&g_s);
    tui_test_screen(buf, sizeof(buf));
    ASSERT(strstr(buf, "Quality:    (not assessed)") != NULL);
    /* Seen red with the tag taken whatever `complete` is. */
    ASSERT(strstr(buf, "(partial") == NULL);
}

static char *render(void (*fn)(FILE *, const sloth_state_t *)) {
    static char out[16384];
    out[0] = '\0';
    FILE *fp = tmpfile();
    ASSERT(fp != NULL);
    if (!fp) return out;
    fn(fp, &g_s);
    rewind(fp);
    size_t n = fread(out, 1, sizeof(out) - 1, fp);
    out[n] = '\0';
    fclose(fp);
    return out;
}

/* --report: one line per finding, partial in its title line; the JSON
 * report's `findings` carries the stream's keys. */
static void test_the_report_shows_them(void) {
    memset(&g_s, 0, sizeof(g_s));
    quality_alert(&g_s.alerts[0]);
    quality_alert(&g_s.alerts[1]);
    memset(&g_s.alerts[1].quality, 0, sizeof(g_s.alerts[1].quality));
    snprintf(g_s.alerts[1].incident_id, sizeof(g_s.alerts[1].incident_id),
             "00000000000000d2");
    g_s.alerts[1].sev = ALERT_SEV_LOW;
    g_s.alert_count = 2;
    const char *md = render(posture_findings_md);
    ASSERT(strstr(md, "## Finding quality\n") != NULL);
    ASSERT(strstr(md, "- **WARN** `EVIL_TWIN` (partial: hop), incident "
                      "`00000000000000d1`: complete partial (hop), latency "
                      "1700 ms, corroboration 1 radio, source ok\n") != NULL);
    ASSERT(strstr(md, "- **LOW** `EVIL_TWIN`, incident `00000000000000d2`: "
                      "not assessed\n") != NULL);
    const char *js = render(posture_findings_json);
    ASSERT(strstr(js, "  \"findings\": [{\"incident_id\":\"00000000000000d1\","
                      "\"title\":\"EVIL_TWIN\",\"sev\":1,\"complete\":\"partial\","
                      "\"complete_why\":\"hop\",\"latency_ms\":1700,"
                      "\"corroboration\":1,\"src_state\":\"ok\"},"
                      "{\"incident_id\":\"00000000000000d2\","
                      "\"title\":\"EVIL_TWIN\",\"sev\":0}],\n") != NULL);
    /* No alerts: no section. Seen red with the alert_count guard
     * removed (an empty heading). */
    g_s.alert_count = 0;
    md = render(posture_findings_md);
    ASSERT_STR(md, "");
    js = render(posture_findings_json);
    ASSERT_STR(js, "  \"findings\": [],\n");
}

void run_alert_quality_tests(void) {
    TEST_SUITE("finding quality fields (#246)");
    RUN_TEST(test_judge_precedence);
    RUN_TEST(test_timeline_uncovered);
    RUN_TEST(test_timeline_drops);
    RUN_TEST(test_capture_reader);
    RUN_TEST(test_twin_under_a_hop_that_misses_the_window_is_partial);
    RUN_TEST(test_twin_inside_one_dwell_is_full);
    RUN_TEST(test_a_frame_just_before_its_dwell_stamp_is_inside_the_slack);
    RUN_TEST(test_partial_stays_partial);
#ifdef WITH_PCAP
    RUN_TEST(test_a_flood_two_radios_delivered_is_corroborated_twice);
    RUN_TEST(test_copies_dropped_as_duplicates_are_not_counted);
#endif
    RUN_TEST(test_source_stale_and_down);
    RUN_TEST(test_a_rule_with_no_frames_takes_its_status);
    RUN_TEST(test_drops_inside_the_window);
    RUN_TEST(test_not_assessed_before_a_sample_or_on_replay);
    RUN_TEST(test_full_stays_full_when_the_rule_goes_blind);
    RUN_TEST(test_cited_frames_gone_from_the_ring_are_not_full);
    RUN_TEST(test_the_capture_stage_writes_the_drop_totals);
    RUN_TEST(test_the_hop_stage_writes_each_radios_dwells);
    RUN_TEST(test_the_stream_carries_the_fields);
    RUN_TEST(test_the_line_and_the_title_tag);
    RUN_TEST(test_the_alert_detail_shows_them);
    RUN_TEST(test_the_report_shows_them);
}
