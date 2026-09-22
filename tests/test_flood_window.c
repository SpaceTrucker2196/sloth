#include <string.h>
#include <stdint.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "flood_window.h"

/* Sliding flood window + probe-request flood (#88). Everything runs on
 * an injected clock: no sleeps, and the same inputs give the same
 * verdict on every run. */

static uint64_t g_mono;
static time_t   g_wall;
static uint64_t fake_mono(void) { return g_mono; }
static time_t   fake_wall(void) { return g_wall; }

#define WALL0 ((time_t)1790000000)

static void clock_reset(void) {
    g_mono = 5000000;
    g_wall = WALL0;
    flood_test_set_clock(fake_mono, fake_wall);
}

/* ── flood_window_t ──────────────────────────────────────── */

static void test_window_counts_only_inside(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    ASSERT_EQ(flood_window_note(&w, 1000, 3, 5000), 0);
    ASSERT_EQ(flood_window_note(&w, 2000, 3, 5000), 0);
    ASSERT_EQ(flood_window_note(&w, 5999, 3, 5000), 1);   /* 1000..5999 */
    ASSERT_EQ(flood_window_count(&w, 5999, 5000), 3);
    ASSERT_EQ(flood_window_count(&w, 6000, 5000), 2);     /* 1000 left */
    ASSERT_EQ(flood_window_count(&w, 11000, 5000), 0);
}

static void test_window_half_open_edge(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    flood_window_note(&w, 0 + 100, 2, 5000);
    ASSERT_EQ(flood_window_note(&w, 5100, 2, 5000), 0);   /* exactly W apart */
    memset(&w, 0, sizeof(w));
    flood_window_note(&w, 100, 2, 5000);
    ASSERT_EQ(flood_window_note(&w, 5099, 2, 5000), 1);
}

/* A chain of sub-window gaps never trips on gaps alone. */
static void test_window_chain_does_not_trip(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    int any = 0;
    for (int i = 0; i < 20; i++)
        any |= flood_window_note(&w, 1000 + (uint64_t)i * 4000, 5, 5000);
    ASSERT_EQ(any, 0);
    ASSERT_EQ(w.tripped, 0);
}

static void test_window_active_decays(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    for (int i = 0; i < 5; i++) flood_window_note(&w, 1000 + (uint64_t)i * 10, 5, 5000);
    ASSERT_EQ(flood_window_active(&w, 1040, 10000), 1);
    ASSERT_EQ(flood_window_active(&w, 11039, 10000), 1);
    ASSERT_EQ(flood_window_active(&w, 11040, 10000), 0);
    /* Never tripped is never active, whatever the clock says. */
    flood_window_t z; memset(&z, 0, sizeof(z));
    ASSERT_EQ(flood_window_active(&z, 0, 10000), 0);
}

/* The ring wraps; count stays exact up to the cap and the threshold
 * still sees the right K-th frame. */
static void test_window_wraps(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    for (int i = 0; i < FLOOD_WIN_CAP * 3; i++)
        flood_window_note(&w, 1000 + (uint64_t)i * 1000, 30, 5000);
    uint64_t last = 1000 + (uint64_t)(FLOOD_WIN_CAP * 3 - 1) * 1000;
    ASSERT_EQ(flood_window_count(&w, last, 5000), 5);
    ASSERT_EQ(w.tripped, 0);
    for (int i = 0; i < FLOOD_WIN_CAP + 4; i++)
        flood_window_note(&w, last + 1 + (uint64_t)i, 30, 5000);
    ASSERT_EQ(w.tripped, 1);
    ASSERT_EQ(flood_window_count(&w, last + FLOOD_WIN_CAP + 4, 5000), FLOOD_WIN_CAP);
}

/* A threshold larger than the ring is clamped, not read out of bounds. */
static void test_window_thresh_clamped(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    int hit = 0;
    for (int i = 0; i < FLOOD_WIN_CAP; i++)
        hit = flood_window_note(&w, 100 + (uint64_t)i, 1000, 5000);
    ASSERT_EQ(hit, 1);
    memset(&w, 0, sizeof(w));
    ASSERT_EQ(flood_window_note(&w, 100, 0, 5000), 1);   /* clamped to 1 */
}

/* A timestamp behind the newest (caller mixed clocks) reads as age 0,
 * not as a 584-million-year age. */
static void test_window_clock_backwards_safe(void) {
    flood_window_t w; memset(&w, 0, sizeof(w));
    flood_window_note(&w, 9000, 5, 5000);
    ASSERT_EQ(flood_window_count(&w, 8000, 5000), 1);
}

static void test_clock_seam_restores(void) {
    clock_reset();
    ASSERT_EQ(flood_mono_ms(), (uint64_t)5000000);
    ASSERT_EQ((long)flood_wall(), (long)WALL0);
    flood_test_set_clock(NULL, NULL);
    uint64_t a = flood_mono_ms();
    uint64_t b = flood_mono_ms();
    ASSERT(b >= a);
    ASSERT((long)flood_wall() > (long)WALL0 - 86400L * 365 * 10);
}

/* ── Probe-request flood ─────────────────────────────────── */

/* Mirrors record_probe() in src/capture/probe.c (libpcap-only, so not
 * in the test build): lifetime counters, then the shared flood note. */
static void probe_hit(probe_client_t *c) {
    if (c->frame_count == 0) c->first_seen = g_wall;
    c->last_seen = g_wall;
    c->frame_count++;
    probe_flood_note(c, g_mono, g_wall);
}

static void advance(uint64_t ms) {
    g_wall += (time_t)((g_mono % 1000 + ms) / 1000);
    g_mono += ms;
}

/* n probes, first to last spanning span_ms, evenly spaced. */
static void burst(probe_client_t *c, int n, uint64_t span_ms) {
    for (int i = 0; i < n; i++) {
        probe_hit(c);
        if (i < n - 1) {
            uint64_t next = span_ms * (uint64_t)(i + 1) / (uint64_t)(n - 1);
            uint64_t cur  = span_ms * (uint64_t)i       / (uint64_t)(n - 1);
            advance(next - cur);
        }
    }
}

static const uint8_t PMAC[6] = {0x02,0x12,0x34,0x56,0x78,0x9a};

static void new_client(probe_client_t *c) {
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, PMAC, 6);
    c->signal_dbm = -55;
    c->channel    = 6;
}

static int run_rule(const probe_client_t *c) {
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_clients[0] = *c;
    probe_flood_refresh(&s.probe_clients[0], g_mono);
    s.probe_count = 1;
    alerts_clear();
    alerts_update(&s);
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_PROBE_FLOOD) return i + 1;
    return 0;
}

/* The issue's case: 30 over 300 s passed the old "frames >= 30 and
 * elapsed >= 5 s" gates exactly like 30 over 5 s. */
static void test_probe_slow_30_over_300s_no_fire(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 300000);
    ASSERT_EQ(c.frame_count, 30);
    ASSERT_EQ(c.flood, 0);
    ASSERT_EQ(run_rule(&c), 0);
    flood_test_set_clock(NULL, NULL);
}

/* A burst is exactly what the rule is for — the old "too brief" gate
 * silenced it. */
static void test_probe_burst_30_over_3s_fires(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 3000);
    ASSERT_EQ(c.flood, 1);
    ASSERT_EQ(c.burst_frames, PROBE_FLOOD_FRAMES);
    ASSERT_EQ((int)c.burst_span_ms, 3000);
    ASSERT_EQ((long)c.flood_last, (long)g_wall);
    int hit = run_rule(&c);
    ASSERT(hit > 0);
    flood_test_set_clock(NULL, NULL);
}

static void test_probe_alert_detail_and_severity(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 3000);
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_clients[0] = c;
    s.probe_count = 1;
    probe_flood_refresh(&s.probe_clients[0], g_mono);
    alerts_clear();
    alerts_update(&s);
    int idx = -1;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_PROBE_FLOOD) idx = i;
    ASSERT(idx >= 0);
    if (idx >= 0) {
        ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_LOW);
        ASSERT(strstr(s.alerts[idx].key, "probe_flood:02:12:34:56:78:9a") != NULL);
        ASSERT(strstr(s.alerts[idx].detail, "02:12:34:56:78:9a") != NULL);
        ASSERT(strstr(s.alerts[idx].detail, "30 probes in 3.0s") != NULL);
        ASSERT(strstr(s.alerts[idx].detail, "10.0/s") != NULL);
    }
    flood_test_set_clock(NULL, NULL);
}

/* Boundary: 30 frames spanning 4.999 s are inside one 5 s window, 30
 * spanning exactly 5.000 s are not; 29 in a second are one short. */
static void test_probe_window_boundaries(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 4999);
    ASSERT_EQ(c.flood, 1);
    ASSERT(run_rule(&c) > 0);

    clock_reset(); new_client(&c);
    burst(&c, 30, 5000);
    ASSERT_EQ(c.flood, 0);
    ASSERT_EQ(run_rule(&c), 0);

    clock_reset(); new_client(&c);
    burst(&c, 29, 1000);
    ASSERT_EQ(c.flood, 0);
    ASSERT_EQ(run_rule(&c), 0);
    flood_test_set_clock(NULL, NULL);
}

/* A long slow history does not dilute a burst: lifetime average was
 * the wrong quantity in both directions. */
static void test_probe_burst_after_long_quiet_fires(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 40, 600000);      /* 40 over 10 min */
    ASSERT_EQ(c.flood, 0);
    advance(10000);
    burst(&c, 30, 2000);
    ASSERT_EQ(c.flood, 1);
    ASSERT(run_rule(&c) > 0);
    flood_test_set_clock(NULL, NULL);
}

/* Flood status decays with time alone. */
static void test_probe_flood_decays(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 2000);
    time_t tripped = g_wall;
    advance(PROBE_FLOOD_HOLD_SECS * 1000 - 1);
    probe_flood_refresh(&c, g_mono);
    ASSERT_EQ(c.flood, 1);
    ASSERT(run_rule(&c) > 0);
    advance(1);
    probe_flood_refresh(&c, g_mono);
    ASSERT_EQ(c.flood, 0);
    ASSERT_EQ((long)c.flood_last, (long)tripped);
    ASSERT_EQ(run_rule(&c), 0);
    flood_test_set_clock(NULL, NULL);
}

/* The rule's own rate predicate: a flag without the evidence behind it
 * (stale or hand-edited state) does not fire. */
static void test_probe_rule_requires_rate(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    burst(&c, 30, 2000);
    c.burst_frames = 10;                /* 10 frames cannot be >= 6/s over 5 s */
    static sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_clients[0] = c;
    s.probe_count = 1;
    s.probe_clients[0].flood = 1;
    alerts_clear();
    alerts_update(&s);
    int hit = 0;
    for (int i = 0; i < s.alert_count; i++)
        if (s.alerts[i].type == ALERT_TYPE_PROBE_FLOOD) hit = 1;
    ASSERT_EQ(hit, 0);
    flood_test_set_clock(NULL, NULL);
}

/* Wall-clock steps inside a burst change nothing. */
static void test_probe_wall_jump(void) {
    clock_reset();
    probe_client_t c; new_client(&c);
    for (int i = 0; i < 30; i++) {
        probe_hit(&c);
        g_mono += 100;
        if (i == 10) g_wall += 7200;
        if (i == 20) g_wall -= 7200 * 2;
    }
    ASSERT_EQ(c.flood, 1);

    clock_reset(); new_client(&c);
    for (int i = 0; i < 30; i++) {       /* wall frozen, 10 s apart */
        probe_hit(&c);
        g_mono += 10000;
    }
    ASSERT_EQ(c.flood, 0);
    flood_test_set_clock(NULL, NULL);
}

void run_flood_window_tests(void) {
    TEST_SUITE("flood_window (#88)");
    RUN_TEST(test_window_counts_only_inside);
    RUN_TEST(test_window_half_open_edge);
    RUN_TEST(test_window_chain_does_not_trip);
    RUN_TEST(test_window_active_decays);
    RUN_TEST(test_window_wraps);
    RUN_TEST(test_window_thresh_clamped);
    RUN_TEST(test_window_clock_backwards_safe);
    RUN_TEST(test_clock_seam_restores);
    RUN_TEST(test_probe_slow_30_over_300s_no_fire);
    RUN_TEST(test_probe_burst_30_over_3s_fires);
    RUN_TEST(test_probe_alert_detail_and_severity);
    RUN_TEST(test_probe_window_boundaries);
    RUN_TEST(test_probe_burst_after_long_quiet_fires);
    RUN_TEST(test_probe_flood_decays);
    RUN_TEST(test_probe_rule_requires_rate);
    RUN_TEST(test_probe_wall_jump);
    flood_test_set_clock(NULL, NULL);
}
