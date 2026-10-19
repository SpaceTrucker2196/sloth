#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "views/probe.h"
#include "tui.h"
#include "capture/probe.h"
#include "fake_platform.h"
#include "scenarios.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void inject_client(sloth_state_t *s, const char *mac_str,
                          const char *ssid, int8_t sig, int ch) {
    if (s->probe_count >= MAX_PROBE_CLIENTS) return;
    probe_client_t *c = &s->probe_clients[s->probe_count++];
    memset(c, 0, sizeof(*c));
    unsigned b0,b1,b2,b3,b4,b5;
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &b0,&b1,&b2,&b3,&b4,&b5) == 6) {
        c->mac[0]=(uint8_t)b0; c->mac[1]=(uint8_t)b1; c->mac[2]=(uint8_t)b2;
        c->mac[3]=(uint8_t)b3; c->mac[4]=(uint8_t)b4; c->mac[5]=(uint8_t)b5;
    }
    strncpy(c->ssid, ssid, sizeof(c->ssid) - 1);
    c->signal_dbm  = sig;
    c->channel     = ch;
    c->last_seen   = time(NULL);
    c->frame_count = 1;
}

static void inject_aged(sloth_state_t *s, const char *mac_str,
                        const char *ssid, int8_t sig, int ch,
                        time_t age_secs, int frames) {
    if (s->probe_count >= MAX_PROBE_CLIENTS) return;
    probe_client_t *c = &s->probe_clients[s->probe_count++];
    memset(c, 0, sizeof(*c));
    unsigned b0,b1,b2,b3,b4,b5;
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &b0,&b1,&b2,&b3,&b4,&b5) == 6) {
        c->mac[0]=(uint8_t)b0; c->mac[1]=(uint8_t)b1; c->mac[2]=(uint8_t)b2;
        c->mac[3]=(uint8_t)b3; c->mac[4]=(uint8_t)b4; c->mac[5]=(uint8_t)b5;
    }
    strncpy(c->ssid, ssid, sizeof(c->ssid) - 1);
    c->signal_dbm  = sig;
    c->channel     = ch;
    c->last_seen   = time(NULL) - age_secs;
    c->frame_count = frames;
}

/* ── Draw ─────────────────────────────────────────────────── *
 *
 * These were ASSERT(1) smoke tests until #116 gave the suite a screen to
 * read. Each now asserts what the view put in the cells. Ages that feed
 * the "(N active)" count (< 5 s) are seeded with seconds of margin, so a
 * slow CI step cannot move a row across the line; no test asserts the
 * Seen column, which reads the real clock. */

/* Row of the first line naming `needle`, asserted present. */
static int row_of(const char *needle) {
    int y = runner_screen_find(needle);
    if (y < 0) {
        fprintf(stderr, "    no row with \"%s\"\n", needle);
        tui_test_dump(stderr);
    }
    ASSERT(y >= 0);
    return y;
}

/* Colour pair of the Pkts cell on row y: the last digit of `count`
 * just before the Presence column. */
static int pkts_pair(int y, const char *count_then_presence) {
    int col = runner_find_col(y, count_then_presence);
    ASSERT(col >= 0);
    return col < 0 ? -1 : tui_test_pair(y, col);
}

static void test_probe_draw_empty_no_crash(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_probe_draw(&s);
    ASSERT_LINE_HAS(0, "Probe clients: 0");
    ASSERT_LINE_HAS(1, "MAC                Vendor        Signal   Ch   Seen   Pkts");
}

static void test_probe_draw_no_iface_message(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_iface[0] = '\0';
    view_probe_draw(&s);
    ASSERT_LINE_HAS(0, "(no monitor interface)");
    ASSERT_SCREEN_HAS("(no monitor-mode interface found");
    ASSERT_SCREEN_LACKS("(listening");
}

static void test_probe_draw_listening_message(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    view_probe_draw(&s);
    ASSERT_LINE_HAS(0, "iface: wlan1mon");
    ASSERT_SCREEN_HAS("(listening");
    ASSERT_SCREEN_LACKS("(no monitor-mode interface found");
}

static void test_probe_draw_with_clients(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:01", "homenet", -67, 6);
    inject_client(&s, "11:22:33:44:55:66", "",        -82, 1);
    inject_client(&s, "de:ad:be:ef:00:01", "office",  -55, 11);
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 3);
    ASSERT_LINE_HAS(0, "Probe clients: 3");
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "homenet");
    ASSERT_LINE_HAS(row_of("11:22:33:44:55:66"), "(wildcard)");
    ASSERT_LINE_HAS(row_of("de:ad:be:ef:00:01"), "office");
}

static void test_probe_draw_wildcard_ssid(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:ff", "", -70, 6);
    view_probe_draw(&s);
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:ff"), "(wildcard)");
}

/* ── Active count ────────────────────────────────────────── */

static void test_probe_active_count_all_fresh(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    /* all 3 well within 5 seconds */
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "a", -55, 6, 0, 1);
    inject_aged(&s, "aa:bb:cc:dd:ee:02", "b", -60, 6, 1, 2);
    inject_aged(&s, "aa:bb:cc:dd:ee:03", "c", -65, 6, 2, 3);
    ASSERT_EQ(s.probe_count, 3);
    view_probe_draw(&s);
    ASSERT_LINE_HAS(0, "Probe clients: 3  (3 active)");
}

static void test_probe_active_count_mixed(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "fresh",  -50, 6,  2, 5);  /* active */
    inject_aged(&s, "aa:bb:cc:dd:ee:02", "medium", -60, 6, 10, 3);  /* not active */
    inject_aged(&s, "aa:bb:cc:dd:ee:03", "stale",  -70, 6, 60, 1);  /* not active */
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 3);
    ASSERT_LINE_HAS(0, "Probe clients: 3  (1 active)");
}

static void test_probe_active_count_none(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "stale", -60, 6, 30, 5);
    inject_aged(&s, "aa:bb:cc:dd:ee:02", "stale", -65, 6, 45, 2);
    view_probe_draw(&s);
    /* Seen to fail with the `active > 0` guard dropped: "(0 active)". */
    ASSERT_LINE_HAS(0, "Probe clients: 2");
    ASSERT(!runner_line_has(0, "active"));
}

/* ── Signal bar extremes ─────────────────────────────────── */

static void test_probe_signal_floor(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "weak", -95, 6, 0, 1);
    view_probe_draw(&s);  /* -95 dBm → 0 bars filled */
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91");
}

static void test_probe_signal_ceiling(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "strong", -25, 6, 0, 1);
    view_probe_draw(&s);  /* -25 dBm → 6 bars filled */
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88");
}

static void test_probe_signal_mid(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "mid", -60, 6, 0, 1);
    view_probe_draw(&s);  /* -60 dBm → 3 bars (50%) */
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x91\xe2\x96\x91\xe2\x96\x91");
}

/* ── Frame count heat thresholds ─────────────────────────── */

static void test_probe_frame_heat_zero(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "x", -60, 6, 0, 0);
    s.probe_sel = -1;   /* the selected row is reverse video, not heat */
    view_probe_draw(&s);  /* 0 frames → frac = 0, cold tui_heat */
    int y = row_of("aa:bb:cc:dd:ee:01");
    ASSERT_EQ(pkts_pair(y, "0  resident"), CP_HEAT_LO);
}

static void test_probe_frame_heat_half(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "x", -60, 6, 0, 25);
    s.probe_sel = -1;   /* the selected row is reverse video, not heat */
    view_probe_draw(&s);  /* 25 frames → frac = 0.5 */
    int y = row_of("aa:bb:cc:dd:ee:01");
    ASSERT_EQ(pkts_pair(y, "25  resident"), CP_HEAT_HI);
}

static void test_probe_frame_heat_max(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "x", -60, 6, 0, 50);
    s.probe_sel = -1;   /* the selected row is reverse video, not heat */
    view_probe_draw(&s);  /* 50 frames → frac = 1.0 */
    int y = row_of("aa:bb:cc:dd:ee:01");
    ASSERT_EQ(pkts_pair(y, "50  resident"), CP_HEAT_PEAK);
}

static void test_probe_frame_heat_overflow(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_aged(&s, "aa:bb:cc:dd:ee:01", "x", -60, 6, 0, 200);
    s.probe_sel = -1;   /* the selected row is reverse video, not heat */
    view_probe_draw(&s);  /* >50 frames → clamped to frac = 1.0, no crash */
    int y = row_of("aa:bb:cc:dd:ee:01");
    ASSERT_EQ(pkts_pair(y, "200  resident"), CP_HEAT_PEAK);
}

/* ── Named vs wildcard SSID ──────────────────────────────── */

static void test_probe_named_ssid(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:01", "TargetNetwork", -55, 6);
    ASSERT(s.probe_clients[0].ssid[0] != '\0');
    view_probe_draw(&s);
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "TargetNetwork");
    ASSERT_SCREEN_LACKS("(wildcard)");
}

static void test_probe_wildcard_ssid(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:01", "", -55, 6);
    ASSERT(s.probe_clients[0].ssid[0] == '\0');
    view_probe_draw(&s);
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:01"), "(wildcard)");
}

static void test_probe_mixed_ssid(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    inject_client(&s, "aa:bb:cc:dd:ee:01", "Named",   -55, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "",        -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:03", "Another", -65, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:04", "",        -70, 6);
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 4);
}

/* ── Selection / viewport ────────────────────────────────── */

static void test_probe_sel_at_top(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    for (int i = 0; i < 40; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:%02x:%02x:%02x", i>>4, i&0xf, i);
        inject_client(&s, mac, "ssid", -60, 6);
    }
    s.probe_sel = 0;
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 40);
    int y = row_of("aa:bb:cc:00:00:00");
    ASSERT_EQ(tui_test_is_reverse(y, 1), 1);
    ASSERT_EQ(tui_test_is_reverse(y == 3 ? 4 : 3, 1), 0);
}

static void test_probe_sel_at_middle(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    for (int i = 0; i < 40; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:%02x:%02x:%02x", i>>4, i&0xf, i);
        inject_client(&s, mac, "ssid", -60, 6);
    }
    s.probe_sel = 20;
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 40);
    int y = row_of("aa:bb:cc:01:04:14");
    ASSERT_EQ(tui_test_is_reverse(y, 1), 1);
    ASSERT_EQ(tui_test_is_reverse(y == 3 ? 4 : 3, 1), 0);
}

static void test_probe_sel_at_bottom(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    for (int i = 0; i < 40; i++) {
        char mac[18];
        snprintf(mac, sizeof(mac), "aa:bb:cc:%02x:%02x:%02x", i>>4, i&0xf, i);
        inject_client(&s, mac, "ssid", -60, 6);
    }
    s.probe_sel = 39;
    view_probe_draw(&s);
    ASSERT_EQ(s.probe_count, 40);
    int y = row_of("aa:bb:cc:02:07:27");
    ASSERT_EQ(tui_test_is_reverse(y, 1), 1);
    ASSERT_EQ(tui_test_is_reverse(y == 3 ? 4 : 3, 1), 0);
}

/* ── Key handler tests ───────────────────────────────────── */

static void test_probe_nav_down(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 0;
    view_probe_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 1);
}

static void test_probe_nav_up(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 1;
    view_probe_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_top_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    s.probe_sel = 0;
    view_probe_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_bottom_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    s.probe_sel = 0;
    view_probe_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_nav_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.probe_sel = 0;
    view_probe_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 0);
}

static void test_probe_clear_key(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    inject_client(&s, "aa:bb:cc:dd:ee:02", "b", -65, 6);
    s.probe_sel = 1;
    view_probe_key(&s, 'c');
    ASSERT_EQ(s.probe_count, 0);
    ASSERT_EQ(s.probe_sel,   0);
}

static void test_probe_clear_key_upper(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    inject_client(&s, "aa:bb:cc:dd:ee:01", "a", -60, 6);
    view_probe_key(&s, 'C');
    ASSERT_EQ(s.probe_count, 0);
}

/* ── Monitor environment (scenario integration) ──────────── */

static void test_probe_monitor_scenario_draw(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    ASSERT_EQ(s.probe_count, 8);
    ASSERT(s.probe_iface[0] != '\0');
    view_probe_draw(&s);
    ASSERT_LINE_HAS(0, "Probe clients: 8");
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:07"), "TargetSSID");
    ASSERT_LINE_HAS(row_of("aa:bb:cc:dd:ee:08"), "IoT_Device");
}

static void test_probe_monitor_scenario_iface(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    ASSERT_STR(s.probe_iface, "wlan1mon");
}

static void test_probe_monitor_scenario_client_count(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    ASSERT_EQ(s.probe_count, 8);
}

static void test_probe_monitor_scenario_named_clients(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    /* scenario has 6 named SSIDs and 2 wildcards */
    int named = 0, wildcard = 0;
    for (int i = 0; i < s.probe_count; i++) {
        if (s.probe_clients[i].ssid[0]) named++;
        else                             wildcard++;
    }
    ASSERT_EQ(named,    6);
    ASSERT_EQ(wildcard, 2);
}

static void test_probe_monitor_scenario_signal_range(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    /* strongest = -30, weakest = -90 */
    int8_t min_sig = 0, max_sig = -127;
    for (int i = 0; i < s.probe_count; i++) {
        if (s.probe_clients[i].signal_dbm > max_sig)
            max_sig = s.probe_clients[i].signal_dbm;
        if (s.probe_clients[i].signal_dbm < min_sig)
            min_sig = s.probe_clients[i].signal_dbm;
    }
    ASSERT_EQ(max_sig, -30);
    ASSERT_EQ(min_sig, -90);
}

static void test_probe_monitor_scenario_frame_counts(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    /* at least one client with >= 50 frames (max heat) */
    int has_max = 0;
    for (int i = 0; i < s.probe_count; i++) {
        if (s.probe_clients[i].frame_count >= 50) { has_max = 1; break; }
    }
    ASSERT(has_max);
    /* at least one with 0 frames */
    int has_zero = 0;
    for (int i = 0; i < s.probe_count; i++) {
        if (s.probe_clients[i].frame_count == 0) { has_zero = 1; break; }
    }
    ASSERT(has_zero);
}

static void test_probe_monitor_scenario_nav(void) {
    scenario_monitor_env();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    fake_net_apply_probe(&s);
    s.probe_sel = 0;
    view_probe_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 1);
    view_probe_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.probe_sel, 2);
    view_probe_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.probe_sel, 1);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_probe_tests(void) {
    TEST_SUITE("probe draw");
    RUN_TEST(test_probe_draw_empty_no_crash);
    RUN_TEST(test_probe_draw_no_iface_message);
    RUN_TEST(test_probe_draw_listening_message);
    RUN_TEST(test_probe_draw_with_clients);
    RUN_TEST(test_probe_draw_wildcard_ssid);

    TEST_SUITE("probe active count");
    RUN_TEST(test_probe_active_count_all_fresh);
    RUN_TEST(test_probe_active_count_mixed);
    RUN_TEST(test_probe_active_count_none);

    TEST_SUITE("probe signal bar");
    RUN_TEST(test_probe_signal_floor);
    RUN_TEST(test_probe_signal_ceiling);
    RUN_TEST(test_probe_signal_mid);

    TEST_SUITE("probe frame heat");
    RUN_TEST(test_probe_frame_heat_zero);
    RUN_TEST(test_probe_frame_heat_half);
    RUN_TEST(test_probe_frame_heat_max);
    RUN_TEST(test_probe_frame_heat_overflow);

    TEST_SUITE("probe ssid");
    RUN_TEST(test_probe_named_ssid);
    RUN_TEST(test_probe_wildcard_ssid);
    RUN_TEST(test_probe_mixed_ssid);

    TEST_SUITE("probe viewport");
    RUN_TEST(test_probe_sel_at_top);
    RUN_TEST(test_probe_sel_at_middle);
    RUN_TEST(test_probe_sel_at_bottom);

    TEST_SUITE("probe key handler");
    RUN_TEST(test_probe_nav_down);
    RUN_TEST(test_probe_nav_up);
    RUN_TEST(test_probe_nav_top_bound);
    RUN_TEST(test_probe_nav_bottom_bound);
    RUN_TEST(test_probe_nav_empty);
    RUN_TEST(test_probe_clear_key);
    RUN_TEST(test_probe_clear_key_upper);

    TEST_SUITE("probe monitor scenario");
    RUN_TEST(test_probe_monitor_scenario_draw);
    RUN_TEST(test_probe_monitor_scenario_iface);
    RUN_TEST(test_probe_monitor_scenario_client_count);
    RUN_TEST(test_probe_monitor_scenario_named_clients);
    RUN_TEST(test_probe_monitor_scenario_signal_range);
    RUN_TEST(test_probe_monitor_scenario_frame_counts);
    RUN_TEST(test_probe_monitor_scenario_nav);
}
