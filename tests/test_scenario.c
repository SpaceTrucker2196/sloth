#include <string.h>
#include <math.h>
#include <stdio.h>

#include "runner.h"
#include "ntop.h"
#include "fake_platform.h"
#include "scenarios.h"
#include "views/iface.h"
#include "views/conns.h"
#include "views/wifi.h"
#include "views/packets.h"

/* Helper: run one full poll against the fake platform */
static void do_poll(ntop_state_t *s) {
    s->iface_count = g_platform.get_ifaces(s->ifaces, MAX_IFACES);
    s->conn_count  = g_platform.get_conns(s->conns,   MAX_CONNS);
    s->ap_count    = g_platform.wifi_scan(s->aps,      MAX_WIFI_APS);
}

/* ── scenario: empty ────────────────────────────────────── */

void test_scenario_empty_yields_zero_counts(void) {
    fake_net_reset();
    scenario_empty();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_EQ(s.iface_count, 0);
    ASSERT_EQ(s.conn_count,  0);
    ASSERT_EQ(s.ap_count,    0);
}

/* ── scenario: idle ─────────────────────────────────────── */

void test_scenario_idle_iface_count(void) {
    fake_net_reset();
    scenario_idle();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_GT(s.iface_count, 0);
    ASSERT_GT(s.ifaces[0].rx_rate, 0.0);
    ASSERT_GT(s.ifaces[0].rx_bytes, 0ULL);
}

void test_scenario_idle_conn_count(void) {
    fake_net_reset();
    scenario_idle();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_GT(s.conn_count, 0);
}

void test_scenario_idle_wifi_aps(void) {
    fake_net_reset();
    scenario_idle();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_GT(s.ap_count, 0);
    ASSERT_LT(s.aps[0].signal_dbm, 0);   /* dBm is always negative */
}

/* ── scenario: busy ─────────────────────────────────────── */

void test_scenario_busy_saturated_rate(void) {
    fake_net_reset();
    scenario_busy();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_EQ(s.iface_count, 1);
    ASSERT_GT(s.ifaces[0].rx_rate, 900e6);  /* close to 1 Gbps */
    ASSERT_GT(s.conn_count, 100);
}

/* ── scenario: many_conns ───────────────────────────────── */

void test_scenario_many_conns_count(void) {
    fake_net_reset();
    scenario_many_conns();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_GT(s.conn_count, 400);
    ASSERT_LT(s.conn_count, MAX_CONNS + 1);
}

void test_scenario_many_conns_mixed_protocols(void) {
    fake_net_reset();
    scenario_many_conns();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    int tcp = 0, udp = 0;
    for (int i = 0; i < s.conn_count; i++) {
        if (s.conns[i].proto == PROTO_TCP) tcp++;
        if (s.conns[i].proto == PROTO_UDP) udp++;
    }
    ASSERT_GT(tcp, 0);
    ASSERT_GT(udp, 0);
}

/* ── scenario: wifi_crowded ─────────────────────────────── */

void test_scenario_wifi_crowded_count(void) {
    fake_net_reset();
    scenario_wifi_crowded();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    ASSERT_EQ(s.ap_count, 20);
}

void test_scenario_wifi_crowded_signal_range(void) {
    fake_net_reset();
    scenario_wifi_crowded();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    for (int i = 0; i < s.ap_count; i++) {
        ASSERT_LT(s.aps[i].signal_dbm,  0);     /* always negative */
        ASSERT_GT(s.aps[i].signal_dbm, -110);   /* within realistic range */
        ASSERT_GT(s.aps[i].channel, 0);
    }
}

/* ── render smoke tests ──────────────────────────────────── */
/* These call the real view draw functions (printing to stdout).
   They exist to catch crashes and format-string bugs. */

void test_render_idle_all_views(void) {
    fake_net_reset();
    scenario_idle();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    /* redirect stdout to /dev/null to suppress output in test run */
    FILE *devnull = fopen("/dev/null", "w");
    FILE *old_stdout = stdout;
    (void)old_stdout;   /* suppress unused-variable warning on some compilers */
    if (devnull) {
        stdout = devnull;
        view_iface_draw(&s);
        view_conns_draw(&s);
        view_wifi_draw(&s);
        view_packets_draw(&s);
        stdout = old_stdout;
        fclose(devnull);
    }
    ASSERT_GT(s.iface_count, 0);   /* sanity: data was present */
}

void test_render_empty_all_views(void) {
    fake_net_reset();
    scenario_empty();

    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    do_poll(&s);

    FILE *devnull = fopen("/dev/null", "w");
    FILE *old_stdout = stdout;
    if (devnull) {
        stdout = devnull;
        view_iface_draw(&s);   /* should print "(no interfaces found)" */
        view_conns_draw(&s);   /* should print "(no connections)" */
        view_wifi_draw(&s);    /* should print "scanning..." */
        view_packets_draw(&s);
        stdout = old_stdout;
        fclose(devnull);
    }
    ASSERT_EQ(s.iface_count, 0);
}

/* ── simulation ──────────────────────────────────────────── */

void test_simulation_rates_oscillate(void) {
    fake_net_reset();
    scenario_idle();

    /* run 20 simulation steps and verify rates are non-constant */
    double first = g_fake_net.ifaces[0].rx_rate;
    double min_r = first, max_r = first;

    for (int i = 0; i < 20; i++) {
        scenario_simulate_step();
        double r = g_fake_net.ifaces[0].rx_rate;
        if (r < min_r) min_r = r;
        if (r > max_r) max_r = r;
    }

    /* oscillation should produce at least 10% swing over 20 steps */
    double swing = (max_r - min_r) / (max_r + 1.0);
    ASSERT_GT(swing, 0.1);
}

void test_simulation_tick_advances(void) {
    fake_net_reset();
    scenario_idle();
    ASSERT_EQ(g_fake_net.tick, 0);
    scenario_simulate_step();
    ASSERT_EQ(g_fake_net.tick, 1);
    scenario_simulate_step();
    ASSERT_EQ(g_fake_net.tick, 2);
}

void test_simulation_bytes_accumulate(void) {
    fake_net_reset();
    scenario_idle();
    uint64_t start_bytes = g_fake_net.ifaces[0].rx_bytes;
    for (int i = 0; i < 5; i++)
        scenario_simulate_step();
    ASSERT_GT(g_fake_net.ifaces[0].rx_bytes, start_bytes);
}

void run_scenario_tests(void) {
    TEST_SUITE("scenario: empty");
    RUN_TEST(test_scenario_empty_yields_zero_counts);

    TEST_SUITE("scenario: idle");
    RUN_TEST(test_scenario_idle_iface_count);
    RUN_TEST(test_scenario_idle_conn_count);
    RUN_TEST(test_scenario_idle_wifi_aps);

    TEST_SUITE("scenario: busy");
    RUN_TEST(test_scenario_busy_saturated_rate);

    TEST_SUITE("scenario: many_conns");
    RUN_TEST(test_scenario_many_conns_count);
    RUN_TEST(test_scenario_many_conns_mixed_protocols);

    TEST_SUITE("scenario: wifi_crowded");
    RUN_TEST(test_scenario_wifi_crowded_count);
    RUN_TEST(test_scenario_wifi_crowded_signal_range);

    TEST_SUITE("render smoke tests");
    RUN_TEST(test_render_idle_all_views);
    RUN_TEST(test_render_empty_all_views);

    TEST_SUITE("simulation");
    RUN_TEST(test_simulation_rates_oscillate);
    RUN_TEST(test_simulation_tick_advances);
    RUN_TEST(test_simulation_bytes_accumulate);
}
