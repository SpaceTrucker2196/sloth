#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "beacon_detect.h"
#include "alerts.h"

/* ── bd_observe / stats ──────────────────────────────── */

static void test_no_track_returns_zero(void) {
    bd_clear();
    double mean = 0, jitter = 0;
    int n = bd_stats("203.0.113.7", 443, &mean, &jitter);
    ASSERT_EQ(n, 0);
}

static void test_regular_30s_interval_is_strong(void) {
    bd_clear();
    time_t base = 1700000000;
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 443, base + i * 30);

    double mean = 0, jitter = 0;
    int n = bd_stats("203.0.113.7", 443, &mean, &jitter);
    ASSERT_EQ(n, 5);
    ASSERT_NEAR(mean, 30.0, 0.001);
    ASSERT_NEAR(jitter, 0.0, 0.001);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 1);
}

static void test_below_min_samples_not_strong(void) {
    bd_clear();
    time_t base = 1700000000;
    for (int i = 0; i < BD_MIN_SAMPLES - 1; i++)
        bd_observe("203.0.113.7", 443, base + i * 30);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 0);
}

static void test_below_min_interval_not_strong(void) {
    bd_clear();
    /* 5 samples at 4s interval — way below BD_MIN_INTERVAL_S */
    time_t base = 1700000000;
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 443, base + i * 4);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 0);
}

static void test_high_jitter_not_strong(void) {
    bd_clear();
    /* intervals: 30, 10, 90, 25, 80 — high stddev */
    time_t pts[] = { 0, 30, 40, 130, 155, 235 };
    for (int i = 0; i < (int)(sizeof(pts) / sizeof(pts[0])); i++)
        bd_observe("203.0.113.7", 443, 1700000000 + pts[i]);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 0);
}

static void test_distinct_flows_tracked_independently(void) {
    bd_clear();
    time_t base = 1700000000;
    for (int i = 0; i < 5; i++) {
        bd_observe("203.0.113.7", 443, base + i * 30);
        bd_observe("198.51.100.9", 8080, base + i * 60);
    }
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443),  1);
    ASSERT_EQ(bd_is_strong("198.51.100.9", 8080), 1);

    double m1 = 0, m2 = 0;
    bd_stats("203.0.113.7", 443,  &m1, NULL);
    bd_stats("198.51.100.9", 8080, &m2, NULL);
    ASSERT_NEAR(m1, 30.0, 0.5);
    ASSERT_NEAR(m2, 60.0, 0.5);
}

/* ── bd_update via conns ─────────────────────────────── */

static void seed_conn(sloth_state_t *s, const char *remote, uint16_t port) {
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", remote);
    c->local_port  = 12345;
    c->remote_port = port;
    c->proto       = PROTO_TCP;
}

static void test_update_records_one_per_session(void) {
    bd_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "203.0.113.7", 443);

    /* poll once now; then again 1s later — still inside BD_GAP_S = 5s, so
       no new sample should be added the second time. */
    time_t base = 1700000000;
    bd_update(&s, base);
    bd_update(&s, base + 1);
    /* fast-forward past gap — a new sample should land */
    bd_update(&s, base + 60);
    bd_update(&s, base + 120);
    bd_update(&s, base + 180);
    bd_update(&s, base + 240);

    double mean = 0;
    int n = bd_stats("203.0.113.7", 443, &mean, NULL);
    ASSERT_EQ(n, 5);
    ASSERT_NEAR(mean, 60.0, 0.5);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 1);
}

/* ── Alerts integration ──────────────────────────────────── */

static void test_alert_fires_for_strong_beacon(void) {
    bd_clear();
    alerts_clear();
    time_t base = 1700000000;
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 443, base + i * 30);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    alerts_update(&s);

    int found = 0;
    for (int i = 0; i < s.alert_count; i++) {
        if (s.alerts[i].type == ALERT_TYPE_BEACONING) {
            found = 1;
            break;
        }
    }
    ASSERT_EQ(found, 1);
}

static void test_alert_does_not_fire_for_weak(void) {
    bd_clear();
    alerts_clear();
    /* only 3 samples → below threshold */
    time_t base = 1700000000;
    for (int i = 0; i < 3; i++)
        bd_observe("203.0.113.7", 443, base + i * 30);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    alerts_update(&s);

    for (int i = 0; i < s.alert_count; i++)
        ASSERT(s.alerts[i].type != ALERT_TYPE_BEACONING);
}

void run_beacon_detect_tests(void) {
    TEST_SUITE("beacon_detect stats");
    RUN_TEST(test_no_track_returns_zero);
    RUN_TEST(test_regular_30s_interval_is_strong);
    RUN_TEST(test_below_min_samples_not_strong);
    RUN_TEST(test_below_min_interval_not_strong);
    RUN_TEST(test_high_jitter_not_strong);
    RUN_TEST(test_distinct_flows_tracked_independently);

    TEST_SUITE("beacon_detect update");
    RUN_TEST(test_update_records_one_per_session);

    TEST_SUITE("beacon_detect alerts hook");
    RUN_TEST(test_alert_fires_for_strong_beacon);
    RUN_TEST(test_alert_does_not_fire_for_weak);
}
