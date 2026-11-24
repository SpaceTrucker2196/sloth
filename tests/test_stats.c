#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "views/stats.h"
#include "tui.h"
#include "sloth_clock.h"
#include "fake_platform.h"
#include "sys_status.h"
#include "capture_side.h"
#include "ownership.h"
#include "rule_coverage_live.h"

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
    /* Uptime reads the real clock and is not asserted. */
    ASSERT_LINE_HAS(0, "Session Statistics");
    ASSERT_SCREEN_HAS("(no interfaces)");
    ASSERT_SCREEN_HAS("Connections (0 total)");
    ASSERT_SCREEN_HAS("(no connections tracked)");
    ASSERT_SCREEN_HAS("Captured: 0");
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
    /* Session columns are the delta from the baseline, not the totals:
     * 1,000,000 B in, 500,000 B out, no packets either way. Seen to fail
     * with the baseline subtraction removed (eth0 then reads its total). */
    int y = runner_screen_find(" eth0 ");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "976.56 KB       488.28 KB       0             0");
    ASSERT_LINE_HAS(runner_screen_find(" lo "), "0 B             0 B");
    ASSERT_SCREEN_LACKS("(no interfaces)");
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
    /* 3 of 5 TCP: twelve of the bar's twenty cells. */
    ASSERT_SCREEN_HAS("Connections (5 total)");
    ASSERT_SCREEN_HAS("[############========]  TCP: 3  UDP: 2");
}

/* ── Collection gaps (#242 item 3) ───────────────────────────
 *
 * The status is driven as the poll drives it (capture filler, a system
 * sample, cov_live_poll()) from hand-seeded source fields, the way
 * tests/test_rule_coverage_live.c does; both clocks pinned. */

TEST_STATE(g_gs);
static uint64_t g_gmono;
static time_t   g_gwall;
static uint64_t gpin_mono(void) { return g_gmono; }
static time_t   gpin_wall(void) { return g_gwall; }

static void gaps_begin(void) {
    capture_side_install();
    g_gmono = 5000000;
    g_gwall = (time_t)1800000000;
    sloth_clock_test_set(gpin_mono, gpin_wall);
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    memset(&g_gs, 0, sizeof(g_gs));
}

static void gaps_end(void) {
    fake_net_reset();
    sys_status_reset();
    cov_live_reset();
    ownership_clear();
    sloth_clock_test_set(NULL, NULL);
}

/* One monitor radio on the default --hop list, nothing else. */
static void gaps_one_hopping_radio(void) {
    static const int ch[] = { 1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161 };
    snprintf(g_gs.probe_iface, sizeof(g_gs.probe_iface), "mon0");
    g_gs.mon_health.open = 1;
    g_gs.mon_health.running = 1;
    g_gs.scan_chan_count = (int)(sizeof(ch) / sizeof(*ch));
    for (int i = 0; i < g_gs.scan_chan_count; i++) g_gs.scan_chans[i] = ch[i];
    g_gmono += 1000;
    g_gwall += 1;
    sys_status_poll(&g_gs, g_gwall, g_gmono);
    cov_live_poll(&g_gs);
}

static void test_gaps_not_assessed(void) {
    gaps_begin();
    view_stats_draw(&g_gs);
    int y = runner_screen_find("Collection gaps");
    ASSERT(y > 0);
    ASSERT_LINE_HAS(y + 1, "  not assessed: no status sample has been taken yet");
    /* No count: zero blind rules would read as full coverage. Seen red
     * with draw_gaps()'s VALID test made always true ("0 rules: 0
     * observable"). */
    ASSERT_SCREEN_LACKS("observable  ");
    ASSERT_SCREEN_LACKS("rules: ");
    /* The sections after it are still drawn. */
    ASSERT_SCREEN_HAS("Connections (0 total)");

    /* A replay says why it is not assessed. */
    snprintf(g_gs.probe_iface, sizeof(g_gs.probe_iface), "replay");
    sys_status_poll(&g_gs, g_gwall + 1, g_gmono + 1000);
    cov_live_poll(&g_gs);
    tui_test_erase();
    view_stats_draw(&g_gs);
    ASSERT_SCREEN_HAS("not assessed: a --replay run reads files");
    gaps_end();
}

static void test_gaps_populated(void) {
    gaps_begin();
    gaps_one_hopping_radio();
    ASSERT_EQ(cov_live_valid(), 1);
    int ob = 0, pa = 0, bl = 0;
    cov_live_counts(&ob, &pa, &bl);

    alert_t *a = &g_gs.alerts[g_gs.alert_count++];
    a->type = ALERT_TYPE_SENSOR_SUPPRESSED;
    snprintf(a->key, sizeof(a->key), "suppressed:silent");
    a = &g_gs.alerts[g_gs.alert_count++];
    a->type = ALERT_TYPE_SENSOR_SUPPRESSED;
    a->resolved = 1;
    snprintf(a->key, sizeof(a->key), "suppressed:evict");

    view_stats_draw(&g_gs);
    int y = runner_screen_find("Collection gaps");
    ASSERT(y > 0);
    char want[160];
    snprintf(want, sizeof(want), "  %d rules: %d observable  %d partly  %d blind"
             "    radios 1  channels 11  hopping  bands 2.4,5", ob + pa + bl, ob, pa, bl);
    ASSERT_LINE_HAS(y + 1, want);

    /* By reason, blind first, the kinds grouped by their input. */
    int ysrc  = runner_screen_find("  blind no_source (");
    int yband = runner_screen_find("  blind band (1)  dot11: DFS_MASKING");
    int yhop  = runner_screen_find("  partly hop (");
    ASSERT(ysrc == y + 2);
    ASSERT(yband > ysrc && yhop > yband);
    ASSERT_LINE_HAS(ysrc, "  ip: NXDOMAIN_BURST THREAT_DOMAIN");
    /* Inputs in cov_input_t order; the group wraps between words, so
     * these are on whichever row they land, a label with its first
     * kind. */
    ASSERT_SCREEN_HAS("ble_adv: BLE_ADV_FLOOD");
    ASSERT_SCREEN_HAS("BLE_WATCHLIST  ble_hci: BT_OWN_TRANSMIT");
    ASSERT_LINE_HAS(yhop, "  dot11: DEAUTH_FLOOD");
    ASSERT_SCREEN_HAS("  blind no_own_net (3)  dot11: MY_NETWORK_RECON UNKNOWN_DEVICE");
    /* An observable kind is in no group. Seen red with cov_live_gaps()
     * given an {observable, none} group. */
    ASSERT_SCREEN_LACKS("COUNTRY_ABSENT");

    /* The open incident and not the resolved one. Seen red with the
     * resolved test removed from draw_gaps(). */
    ASSERT_SCREEN_HAS("  SENSOR_SUPPRESSED open: suppressed:silent");
    ASSERT_SCREEN_LACKS("suppressed:evict");
    for (int i = 0; i < COV_LIMIT_COUNT; i++) {
        snprintf(want, sizeof(want), "  %.60s", cov_limits[i]);
        ASSERT_SCREEN_HAS(want);
    }
    gaps_end();
}

static void test_gaps_wrap_at_the_terminal_width(void) {
    /* A long group is broken at the edge, its continuation indented
     * under the reason, so nothing is cut at the 100-column minimum. */
    gaps_begin();
    gaps_one_hopping_radio();
    ASSERT_EQ(tui_init_offscreen(60, 100), 0);
    tui_test_erase();
    view_stats_draw(&g_gs);
    int ysrc = runner_screen_find("  blind no_source (");
    ASSERT(ysrc > 0);
    char line[512];
    ASSERT(tui_test_line(ysrc, line, sizeof(line)) > 0);
    ASSERT(strlen(line) <= 99);
    ASSERT(tui_test_line(ysrc + 1, line, sizeof(line)) > 6);
    ASSERT(strncmp(line, "      ", 6) == 0 && line[6] != ' ');
    /* Broken between words: every kind of the group is whole on some
     * row, the long ones included. Seen red with gap_put() replaced by
     * the per-character tui_addstr_wrapped() (SNMP_COMMUNITY_BRUTE split
     * across two rows at 100 columns). */
    for (int r = ysrc; r < ysrc + 8; r++) {
        if (tui_test_line(r, line, sizeof(line)) < 0) break;
        ASSERT(strlen(line) <= 99);
    }
    ASSERT_SCREEN_HAS("BLE_WATCHLIST");
    ASSERT_SCREEN_HAS("BGP_NOTIFICATION_BURST");
    ASSERT_SCREEN_HAS("SNMP_COMMUNITY_BRUTE");
    ASSERT_SCREEN_HAS("MQTT_BROKER_BRUTE");
    ASSERT_SCREEN_HAS("CAM_WS_DISCOVERY");
    ASSERT_EQ(tui_test_overflow(), 0);
    gaps_end();
}

/* At the 100x33 minimum (AGENTS.md) the view does not scroll, and the
 * traffic sections under the gaps were there before them. A hopping
 * sensor's full list (the hop group wraps to six rows, the limits to
 * four) would push Connections, Top 5, the geography and the capture
 * count below the last row; there the gaps are one count per reason
 * and the report is named for the rest. The view is drawn from row 2,
 * under the tab bar and its rule, as tui_draw() places it. */
static void stats_33_fill(void) {
    push_iface(&g_gs, "eth0", 1, 1, 1, 1);
    push_iface(&g_gs, "wlan0", 1, 1, 1, 1);
    push_iface(&g_gs, "mon0", 1, 1, 1, 1);
    push_iface(&g_gs, "lo", 1, 1, 1, 1);
    for (int i = 0; i < 3; i++) {
        g_gs.conns[i].proto = PROTO_TCP;
        g_gs.conns[i].state = 1;
    }
    g_gs.conn_count = 3;
}

static void test_gaps_short_screen_keeps_the_traffic(void) {
    gaps_begin();
    gaps_one_hopping_radio();
    stats_33_fill();
    ASSERT_EQ(tui_init_offscreen(33, 100), 0);
    tui_test_erase();
    move(2, 0);
    view_stats_draw(&g_gs);
    int ob = 0, pa = 0, bl = 0;
    cov_live_counts(&ob, &pa, &bl);
    char want[160];
    snprintf(want, sizeof(want), "  blind no_source 30, no_own_net 3, no_db 1, band 1"
             "   partly hop %d", pa);
    ASSERT_SCREEN_HAS(want);
    ASSERT_SCREEN_HAS("(kinds and limits: --report)");
    /* Every section under the gaps is on the screen and nothing is
     * dropped below it. Seen red with gap_budget() returning 1 << 30
     * (the full list: Top 5, the geography and the capture count
     * fell below the last row). */
    ASSERT_SCREEN_HAS("Connections (3 total)");
    ASSERT_SCREEN_HAS("Top 5 by bandwidth");
    ASSERT_SCREEN_HAS("(no connections tracked)");
    ASSERT_SCREEN_HAS("Connection geography");
#ifdef WITH_PCAP
    ASSERT_SCREEN_HAS("Captured: 0");
#endif
    ASSERT_EQ(tui_test_overflow(), 0);
    /* The names wait for the report; seen red under the same mutation. */
    ASSERT_SCREEN_LACKS("DEAUTH_FLOOD");
    ASSERT_SCREEN_LACKS("Observable means");

    /* With the rows to spare, the whole list. */
    ASSERT_EQ(tui_init_offscreen(80, 100), 0);
    tui_test_erase();
    move(2, 0);
    view_stats_draw(&g_gs);
    ASSERT_SCREEN_HAS("  dot11: DEAUTH_FLOOD");
    ASSERT_SCREEN_HAS("  Observable means");
    ASSERT_SCREEN_LACKS("(kinds and limits: --report)");
    ASSERT_SCREEN_HAS("Connection geography");
    ASSERT_EQ(tui_test_overflow(), 0);
    gaps_end();
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

    TEST_SUITE("stats: collection gaps (#242 item 3)");
    RUN_TEST(test_gaps_not_assessed);
    RUN_TEST(test_gaps_populated);
    RUN_TEST(test_gaps_wrap_at_the_terminal_width);
    RUN_TEST(test_gaps_short_screen_keeps_the_traffic);
}
