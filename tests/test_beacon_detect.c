#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "beacon_detect.h"
#include "alerts.h"

/* ── Helpers ─────────────────────────────────────────── */

static void seed_conn(sloth_state_t *s, const char *remote, uint16_t port) {
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", remote);
    c->local_port  = 12345;
    c->remote_port = port;
    c->proto       = PROTO_TCP;
}

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

/* Kills find()'s port/IP AND mutation (line 11 `&&` → `||`):
 * two tracks sharing one of (port, ip) but differing in the other
 * must not alias. */
static void test_bd_find_distinguishes_port_from_ip(void) {
    bd_clear();
    time_t base = 1700000000;
    /* Same IP, different ports. */
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 443, base + i * 30);
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 8080, base + i * 60);
    /* Querying (ip, port=443) must find the 30s-cadence track,
     * not the 60s-cadence one. Under the && → || mutation, the
     * 8080 track would match (same ip) and return its mean=60. */
    double m = 0;
    int n = bd_stats("203.0.113.7", 443, &m, NULL);
    ASSERT_EQ(n, 5);
    ASSERT_NEAR(m, 30.0, 0.5);
}

/* Kills bd_observe's NULL/empty guard mutation (line 41 `||` → `&&`):
 * an empty remote_ip must be a no-op. Under the mutation, only
 * NULL && empty[0] would short-circuit — empty string would proceed
 * and create a track keyed on "". */
static void test_bd_observe_empty_ip_is_noop(void) {
    bd_clear();
    bd_observe("", 443, 1700000000);
    bd_observe("", 443, 1700000030);
    /* No track should exist; bd_stats on "" returns 0. */
    double m = 0;
    int n = bd_stats("", 443, &m, NULL);
    ASSERT_EQ(n, 0);
}

/* Kills bd_update's port-zero guard mutation (line 54 `||` → `&&`):
 * a conn entry with valid ip but port == 0 must be skipped. */
static void test_bd_update_skips_zero_port_conn(void) {
    bd_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* one valid + one with port=0 — only the valid one creates a track */
    conn_t *c1 = &s.conns[s.conn_count++];
    memset(c1, 0, sizeof(*c1));
    snprintf(c1->remote_addr, sizeof(c1->remote_addr), "203.0.113.7");
    c1->remote_port = 443;
    c1->proto = PROTO_TCP;

    conn_t *c2 = &s.conns[s.conn_count++];
    memset(c2, 0, sizeof(*c2));
    snprintf(c2->remote_addr, sizeof(c2->remote_addr), "198.51.100.9");
    c2->remote_port = 0;
    c2->proto = PROTO_TCP;

    bd_update(&s, 1700000000);
    /* The zero-port conn must not have produced a track. */
    double m = 0;
    int n = bd_stats("198.51.100.9", 0, &m, NULL);
    ASSERT_EQ(n, 0);
}

/* Kills BD_GAP_S boundary in bd_update (line 56 `>=` → `>`):
 * exactly-at-gap counts as a new session sample, not a same-session
 * touch. With `>` only strictly past the gap would create a sample. */
static void test_bd_update_at_exact_gap_records_new_sample(void) {
    bd_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "203.0.113.7", 443);
    time_t base = 1700000000;
    bd_update(&s, base);
    bd_update(&s, base + BD_GAP_S);   /* exactly at the gap boundary */
    /* Expect two samples: the first observation, plus the second
     * that crossed the >= boundary. */
    double m = 0;
    int n = bd_stats("203.0.113.7", 443, &m, NULL);
    ASSERT_EQ(n, 2);
}

/* Kills bd_stats's `n < 2` early-return mutation (line 82 `<` → `<=`,
 * `2 -> 3`): two samples have one gap; the mean must be that gap. */
static void test_bd_stats_two_samples_computes_mean(void) {
    bd_clear();
    bd_observe("203.0.113.7", 443, 1700000000);
    bd_observe("203.0.113.7", 443, 1700000040);
    double mean = 0, jitter = 0;
    int n = bd_stats("203.0.113.7", 443, &mean, &jitter);
    ASSERT_EQ(n, 2);
    ASSERT_NEAR(mean, 40.0, 0.001);
    ASSERT_NEAR(jitter, 0.0, 0.001);
}

/* Kills BD_MIN_INTERVAL_S boundary in bd_is_strong (line 106
 * `<` → `<=`): exactly-at-min-interval must count as strong. */
static void test_bd_is_strong_at_exact_min_interval(void) {
    bd_clear();
    time_t base = 1700000000;
    for (int i = 0; i < 5; i++)
        bd_observe("203.0.113.7", 443, base + i * BD_MIN_INTERVAL_S);
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 1);
}

/* Kills the jitter ratio threshold mutation (line 108 `>` → `>=`):
 * jitter/mean exactly at BD_MAX_JITTER_RATIO must still count as
 * strong (the rule is *strictly above* rejects). Construct intervals
 * with ratio == 0.25: gaps [30, 20, 30, 20] -> mean=25, gaps' stddev
 * computed against gaps=4 -> sqrt(((5)^2+(-5)^2+(5)^2+(-5)^2)/4)
 * = sqrt(100/4) = 5. ratio = 5/25 = 0.20 — too low.
 * For exactly 0.25 with mean=20: stddev=5, ratios must be 5.
 * Use gaps [25, 15, 25, 15] -> mean=20, stddev=5. Ratio=0.25 exact. */
static void test_bd_is_strong_at_exact_max_jitter_ratio(void) {
    bd_clear();
    time_t t = 1700000000;
    bd_observe("203.0.113.7", 443, t);            /* t */
    bd_observe("203.0.113.7", 443, t += 25);      /* +25 */
    bd_observe("203.0.113.7", 443, t += 15);      /* +15 */
    bd_observe("203.0.113.7", 443, t += 25);      /* +25 */
    bd_observe("203.0.113.7", 443, t += 15);      /* +15 */
    double mean = 0, jitter = 0;
    int n = bd_stats("203.0.113.7", 443, &mean, &jitter);
    ASSERT_EQ(n, 5);
    ASSERT_NEAR(mean, 20.0, 0.001);
    ASSERT_NEAR(jitter, 5.0, 0.001);
    /* ratio = 5/20 = 0.25 — exactly the threshold; strict-greater
     * means we stay strong. */
    ASSERT_EQ(bd_is_strong("203.0.113.7", 443), 1);
}

/* ── bd_update via conns ─────────────────────────────── */

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
    RUN_TEST(test_bd_find_distinguishes_port_from_ip);
    RUN_TEST(test_bd_observe_empty_ip_is_noop);
    RUN_TEST(test_bd_stats_two_samples_computes_mean);
    RUN_TEST(test_bd_is_strong_at_exact_min_interval);
    RUN_TEST(test_bd_is_strong_at_exact_max_jitter_ratio);

    TEST_SUITE("beacon_detect update");
    RUN_TEST(test_update_records_one_per_session);
    RUN_TEST(test_bd_update_skips_zero_port_conn);
    RUN_TEST(test_bd_update_at_exact_gap_records_new_sample);

    TEST_SUITE("beacon_detect alerts hook");
    RUN_TEST(test_alert_fires_for_strong_beacon);
    RUN_TEST(test_alert_does_not_fire_for_weak);
}
