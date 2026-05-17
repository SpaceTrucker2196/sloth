#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "views/stats.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void push_iface(sloth_state_t *s, const char *name,
                       uint64_t rx, uint64_t tx,
                       uint64_t rxp, uint64_t txp) {
    if (s->iface_count >= MAX_IFACES) return;
    iface_stat_t *ifc = &s->ifaces[s->iface_count++];
    memset(ifc, 0, sizeof(*ifc));
    strncpy(ifc->name, name, sizeof(ifc->name) - 1);
    ifc->rx_bytes   = rx;
    ifc->tx_bytes   = tx;
    ifc->rx_packets = rxp;
    ifc->tx_packets = txp;
}

/* ── Baseline tests ──────────────────────────────────────── */

static void test_baseline_taken_once(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "eth0", 1000, 500, 10, 5);

    ASSERT_EQ(s.stats_init, 0);
    stats_take_baseline(&s);
    ASSERT_EQ(s.stats_init, 1);
    ASSERT_EQ(s.stats_base_count, 1);
}

static void test_baseline_stores_values(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "eth0", 9999, 4444, 100, 50);
    stats_take_baseline(&s);
    ASSERT_EQ((int)s.stats_base_rx[0],  9999);
    ASSERT_EQ((int)s.stats_base_tx[0],  4444);
    ASSERT_EQ((int)s.stats_base_rxp[0], 100);
    ASSERT_EQ((int)s.stats_base_txp[0], 50);
}

static void test_baseline_stores_name(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "lo", 0, 0, 0, 0);
    stats_take_baseline(&s);
    ASSERT(strcmp(s.stats_base_name[0], "lo") == 0);
}

static void test_baseline_multiple_ifaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "eth0", 100, 50, 1, 1);
    push_iface(&s, "lo",   200, 200, 2, 2);
    stats_take_baseline(&s);
    ASSERT_EQ(s.stats_base_count, 2);
}

static void test_reset_clears_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "eth0", 100, 50, 1, 1);
    stats_take_baseline(&s);
    ASSERT_EQ(s.stats_init, 1);
    /* simulate 'r' key reset */
    s.stats_init = 0;
    ASSERT_EQ(s.stats_init, 0);
    /* re-take with higher counters */
    s.ifaces[0].rx_bytes = 200;
    stats_take_baseline(&s);
    ASSERT_EQ((int)s.stats_base_rx[0], 200);
}

/* ── key handler tests ───────────────────────────────────── */

static void test_r_key_clears_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.stats_init = 1;
    view_stats_key(&s, 'r');
    ASSERT_EQ(s.stats_init, 0);
}

static void test_R_key_clears_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.stats_init = 1;
    view_stats_key(&s, 'R');
    ASSERT_EQ(s.stats_init, 0);
}

static void test_other_key_noop(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.stats_init = 1;
    view_stats_key(&s, 'x');
    ASSERT_EQ(s.stats_init, 1);
}

/* ── draw smoke tests ────────────────────────────────────── */

static void test_draw_empty_no_crash(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_stats_draw(&s);
    ASSERT(1);
}

static void test_draw_with_ifaces_no_crash(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_iface(&s, "eth0", 5000000, 2000000, 5000, 2000);
    push_iface(&s, "lo",   1000,    1000,    10,   10);
    stats_take_baseline(&s);
    /* simulate some traffic */
    s.ifaces[0].rx_bytes = 6000000;
    s.ifaces[0].tx_bytes = 2500000;
    view_stats_draw(&s);
    ASSERT(1);
}

static void test_draw_with_conns_no_crash(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* add a few conns */
    for (int i = 0; i < 5; i++) {
        s.conns[i].proto = (i % 2 == 0) ? PROTO_TCP : PROTO_UDP;
        s.conns[i].state = 1;
    }
    s.conn_count = 5;
    stats_take_baseline(&s);
    view_stats_draw(&s);
    ASSERT(1);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_stats_tests(void) {
    TEST_SUITE("stats baseline");
    RUN_TEST(test_baseline_taken_once);
    RUN_TEST(test_baseline_stores_values);
    RUN_TEST(test_baseline_stores_name);
    RUN_TEST(test_baseline_multiple_ifaces);
    RUN_TEST(test_reset_clears_init);

    TEST_SUITE("stats key handler");
    RUN_TEST(test_r_key_clears_init);
    RUN_TEST(test_R_key_clears_init);
    RUN_TEST(test_other_key_noop);

    TEST_SUITE("stats draw");
    RUN_TEST(test_draw_empty_no_crash);
    RUN_TEST(test_draw_with_ifaces_no_crash);
    RUN_TEST(test_draw_with_conns_no_crash);
}
