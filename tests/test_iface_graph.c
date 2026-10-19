#include <string.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "history.h"
#include "views/iface.h"

/* ── Helpers ─────────────────────────────────────────────── */

static sloth_state_t make_state(int n_ifaces) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    static const char *names[] = { "eth0", "wlan0", "lo", "tun0" };
    s.iface_count = (n_ifaces < 4) ? n_ifaces : 4;
    for (int i = 0; i < s.iface_count; i++) {
        memcpy(s.ifaces[i].name, names[i], strlen(names[i]) + 1);
        s.ifaces[i].rx_rate = (double)(i + 1) * 1e6;
        s.ifaces[i].tx_rate = (double)(i + 1) * 0.5e6;
    }
    return s;
}

static void push_history(sloth_state_t *s, const char *name, int n_samples) {
    for (int i = 0; i < s->iface_count; i++) {
        if (strcmp(s->ifaces[i].name, name) == 0) {
            for (int k = 0; k < n_samples; k++) {
                s->ifaces[i].rx_rate = (double)(k + 1) * 1e6;
                s->ifaces[i].tx_rate = (double)(k + 1) * 0.3e6;
                history_update(s);
            }
            return;
        }
    }
}

/* ── Key handler tests ───────────────────────────────────── */

static void test_graph_enter_opens(void) {
    sloth_state_t s = make_state(1);
    ASSERT_EQ(s.iface_graph, 0);
    view_iface_key(&s, '\r');
    ASSERT_EQ(s.iface_graph, 1);
}

static void test_graph_enter_newline_opens(void) {
    sloth_state_t s = make_state(1);
    view_iface_key(&s, '\n');
    ASSERT_EQ(s.iface_graph, 1);
}

static void test_graph_esc_closes(void) {
    sloth_state_t s = make_state(1);
    s.iface_graph = 1;
    view_iface_key(&s, '\033');
    ASSERT_EQ(s.iface_graph, 0);
}

static void test_graph_enter_noop_no_ifaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_iface_key(&s, '\r');
    ASSERT_EQ(s.iface_graph, 0);
}

static void test_graph_keys_absorbed_in_graph_mode(void) {
    sloth_state_t s = make_state(3);
    s.iface_graph = 1;
    s.iface_sel = 1;
    /* nav keys must NOT change iface_sel while graph is open */
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, 't');
    ASSERT_EQ(s.iface_hidden_count, 0);
}

static void test_graph_non_esc_keeps_graph_open(void) {
    sloth_state_t s = make_state(1);
    s.iface_graph = 1;
    view_iface_key(&s, 'x');
    ASSERT_EQ(s.iface_graph, 1);
}

/* ── Draw smoke tests ────────────────────────────────────── */

static void test_graph_draw_no_crash_no_ifaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_LINE_HAS(0, "(no interfaces)");
}

static void test_graph_draw_no_crash_no_history(void) {
    sloth_state_t s = make_state(1);
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_LINE_HAS(0, "eth0  [Esc] back");
    /* No samples: the axis floors at 1B/s and no column is filled. */
    ASSERT_SCREEN_HAS("RX  (peak: 1B/s)");
    ASSERT_SCREEN_LACKS("\xe2\x96\x88");
}

static void test_graph_draw_no_crash_with_history(void) {
    sloth_state_t s = make_state(1);
    push_history(&s, "eth0", 10);
    s.iface_graph = 1;
    view_iface_draw(&s);
    /* Ten samples rising 1..10 MB/s: the peak labels the top of the
     * axis, the newest column (rightmost) is full height. */
    ASSERT_SCREEN_HAS("RX  (peak: 10.0MB/s)");
    ASSERT_SCREEN_HAS("TX  (peak: 3.0MB/s)");
    int y = runner_screen_find("10.0MB/s \xe2\x94\xa4");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "\xe2\x96\x88\xe2\x96\x88");
}

static void test_graph_draw_no_crash_full_history(void) {
    sloth_state_t s = make_state(1);
    push_history(&s, "eth0", HIST_LEN + 5);  /* overfill ring */
    s.iface_graph = 1;
    view_iface_draw(&s);
    /* Overfilled by 5: the peak is the last sample written, and the
     * oldest five fell off the ring rather than wrapping in. */
    char want[64];
    snprintf(want, sizeof(want), "RX  (peak: %.1fMB/s)",
             (double)(HIST_LEN + 5));   /* rates render in 10^6 B */
    ASSERT_SCREEN_HAS(want);
}

static void test_graph_draw_second_iface(void) {
    sloth_state_t s = make_state(2);
    push_history(&s, "wlan0", 15);
    s.iface_sel  = 1;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_LINE_HAS(0, "wlan0  [Esc] back");
    ASSERT_SCREEN_LACKS("eth0  [Esc] back");
    ASSERT_SCREEN_HAS("RX  (peak: 15.0MB/s)");
}

static void test_normal_draw_not_affected(void) {
    sloth_state_t s = make_state(2);
    s.iface_graph = 0;
    view_iface_draw(&s);  /* normal table view */
    ASSERT_LINE_HAS(0, "Interface  Mode Vendor");
    ASSERT_LINE_HAS(runner_screen_find(" eth0 "), "1.0MB/s");
    ASSERT_LINE_HAS(runner_screen_find(" wlan0 "), "2.0MB/s");
    ASSERT_SCREEN_LACKS("[Esc] back");
}

/* ── Detail stats field tests ────────────────────────────── */

static void test_detail_fields_default_zero(void) {
    sloth_state_t s = make_state(1);
    ASSERT_EQ(s.ifaces[0].rx_errors, 0ULL);
    ASSERT_EQ(s.ifaces[0].rx_drops,  0ULL);
    ASSERT_EQ(s.ifaces[0].tx_errors, 0ULL);
    ASSERT_EQ(s.ifaces[0].tx_drops,  0ULL);
    ASSERT_EQ(s.ifaces[0].mtu,       0U);
}

static void test_detail_draw_with_errors(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].rx_errors  = 3;
    s.ifaces[0].rx_drops   = 7;
    s.ifaces[0].tx_errors  = 1;
    s.ifaces[0].tx_drops   = 0;
    s.ifaces[0].mtu        = 1500;
    s.ifaces[0].speed_mbps = 1000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_SCREEN_HAS("Speed: 1 Gbps   MTU: 1500");
    /* tx_drops is 0, which reads as unknown, not as a clean zero. */
    ASSERT_SCREEN_HAS("Errors rx: 3 drop: 7  tx: 1 drop: --");
}

static void test_detail_draw_no_errors(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].mtu        = 9000;
    s.ifaces[0].speed_mbps = 10000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_SCREEN_HAS("Speed: 10 Gbps   MTU: 9000");
    ASSERT_SCREEN_HAS("Errors: --");
}

static void test_detail_draw_unknown_speed_mtu(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].speed_mbps = -1;
    s.ifaces[0].mtu        = 0;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_SCREEN_HAS("Speed: --   MTU: --");
}

static void test_detail_draw_with_packets(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].rx_bytes   = 1024ULL * 1024 * 500;
    s.ifaces[0].tx_bytes   = 1024ULL * 1024 * 100;
    s.ifaces[0].rx_packets = 500000;
    s.ifaces[0].tx_packets = 200000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_SCREEN_HAS("Total RX: 524.3MB");
    ASSERT_SCREEN_HAS("TX: 104.9MB");
    ASSERT_SCREEN_HAS("pkts rx/tx: 500.0KB / 200.0KB");
}

static void test_detail_gigabit_speed_label(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].speed_mbps = 1000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT_SCREEN_HAS("Speed: 1 Gbps");
    ASSERT_SCREEN_LACKS("1000 Mbps");
}

/* ── Scan interface indicator tests ──────────────────────── */

/* Since #116 the suite links the real probe, so [m] reaches the real
 * probe_set_iface() and would pcap_open_live() the selected name on the
 * host, promiscuous. An allow-list naming only another interface stops
 * it at the #85 boundary, before any open, and the refusal names the
 * interface the key handed over — which is what these assert. */
static void test_scan_key_m_hands_the_selected_row_to_the_probe(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 1;
    iface_allow_add(&s, "eth0");
    view_iface_key(&s, 'm');
    ASSERT(strstr(s.probe_err, "wlan0 not in --iface allow-list") != NULL);
    ASSERT_STR(s.probe_iface, "");
    s.probe_err[0] = '\0';
    view_iface_key(&s, 'M');
    ASSERT(strstr(s.probe_err, "wlan0 not in --iface allow-list") != NULL);
}

static void test_scan_key_m_with_no_ifaces_calls_nothing(void) {
    /* A stale name past iface_count stands in for a row that is gone; an
     * [m] that ignored the count would hand it over and be refused by
     * name. Seen to fail with the iface_count guard in view_iface_key()
     * removed. */
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    snprintf(s.ifaces[0].name, sizeof(s.ifaces[0].name), "ghost0");
    iface_allow_add(&s, "eth0");
    view_iface_key(&s, 'm');
    ASSERT_STR(s.probe_err, "");
    ASSERT_STR(s.probe_iface, "");
}

static void test_scan_indicator_draw_selected(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 0;
    memcpy(s.probe_iface, "eth0", 5);
    view_iface_draw(&s);   /* selected row should show [scanning] */
    int y = runner_screen_find("seth0");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "[scanning]");
    ASSERT_EQ(tui_test_is_reverse(y, 2), 1);
}

static void test_scan_indicator_draw_unselected(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 0;
    memcpy(s.probe_iface, "wlan0", 6);  /* wlan0 is row 1, not selected */
    view_iface_draw(&s);   /* unselected row with 's' prefix */
    int y = runner_screen_find("swlan0");
    ASSERT(y >= 0);
    ASSERT_LINE_HAS(y, "[scanning]");
    ASSERT_EQ(tui_test_is_reverse(y, 2), 0);
    ASSERT_SCREEN_LACKS("seth0");
}

static void test_scan_indicator_no_probe_iface(void) {
    sloth_state_t s = make_state(2);
    s.probe_iface[0] = '\0';
    view_iface_draw(&s);   /* no scan marker anywhere */
    /* Seen to fail with the probe_iface match forced true. */
    ASSERT_SCREEN_HAS(" eth0 ");
    ASSERT_SCREEN_LACKS("[scanning]");
    ASSERT_SCREEN_LACKS("seth0");
    ASSERT_SCREEN_LACKS("swlan0");
}

/* ── Entry point ─────────────────────────────────────────── */

/* The monitor row's scan bar renders with a live hop channel list. */
static void test_scan_bar_renders(void) {
    sloth_state_t s = make_state(2);   /* eth0, wlan0 */
    memcpy(s.probe_iface, "wlan0", 6);
    s.iface_sel = 1;
    s.scan_chans[0] = 1; s.scan_chans[1] = 6; s.scan_chans[2] = 11;
    s.scan_chan_count = 3;
    s.scan_cur_idx = 1;                /* currently on channel 6 */
    view_iface_draw(&s);
    /* The current hop channel is bracketed; the others are not. */
    ASSERT_LINE_HAS(runner_screen_find("swlan0"), "ch: 1 [6] 11");
}

/* #25: with a monitor radio present, every other interface is hidden;
 * the monitor radio and (if set) the IP-capture iface stay visible. */
static void test_hide_non_monitor(void) {
    sloth_state_t s = make_state(4);   /* eth0, wlan0, lo, tun0 */
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan0");
    iface_hide_non_monitor(&s);
    ASSERT(iface_is_hidden(&s, "eth0"));
    ASSERT(iface_is_hidden(&s, "lo"));
    ASSERT(iface_is_hidden(&s, "tun0"));
    ASSERT(!iface_is_hidden(&s, "wlan0"));
}

/* A managed Wi-Fi station stays visible alongside the monitor radio —
 * both adapters (and the network the station is joined to) are the
 * default picture, only wired/loopback/virtual noise is hidden. */
static void test_hide_non_monitor_keeps_wifi_station(void) {
    sloth_state_t s = make_state(4);   /* eth0, wlan0, lo, tun0 */
    s.ifaces[1].mode = IFACE_MODE_WIFI;          /* wlan0 = managed station */
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan1mon");
    iface_hide_non_monitor(&s);
    ASSERT(!iface_is_hidden(&s, "wlan0"));
    ASSERT(iface_is_hidden(&s, "eth0"));
    ASSERT(iface_is_hidden(&s, "lo"));
    ASSERT(iface_is_hidden(&s, "tun0"));
}

static void test_hide_non_monitor_keeps_capture_iface(void) {
    sloth_state_t s = make_state(4);
    snprintf(s.probe_iface, sizeof(s.probe_iface), "wlan0");
    snprintf(s.pkt_iface,   sizeof(s.pkt_iface),   "eth0");
    iface_hide_non_monitor(&s);
    ASSERT(!iface_is_hidden(&s, "wlan0"));
    ASSERT(!iface_is_hidden(&s, "eth0"));
    ASSERT(iface_is_hidden(&s, "lo"));
    ASSERT(iface_is_hidden(&s, "tun0"));
}

void run_iface_graph_tests(void) {
    TEST_SUITE("iface graph / key");
    RUN_TEST(test_graph_enter_opens);
    RUN_TEST(test_graph_enter_newline_opens);
    RUN_TEST(test_graph_esc_closes);
    RUN_TEST(test_graph_enter_noop_no_ifaces);
    RUN_TEST(test_graph_keys_absorbed_in_graph_mode);
    RUN_TEST(test_graph_non_esc_keeps_graph_open);

    TEST_SUITE("iface graph / draw");
    RUN_TEST(test_graph_draw_no_crash_no_ifaces);
    RUN_TEST(test_graph_draw_no_crash_no_history);
    RUN_TEST(test_graph_draw_no_crash_with_history);
    RUN_TEST(test_graph_draw_no_crash_full_history);
    RUN_TEST(test_graph_draw_second_iface);
    RUN_TEST(test_normal_draw_not_affected);

    TEST_SUITE("iface detail panel");
    RUN_TEST(test_detail_fields_default_zero);
    RUN_TEST(test_detail_draw_with_errors);
    RUN_TEST(test_detail_draw_no_errors);
    RUN_TEST(test_detail_draw_unknown_speed_mtu);
    RUN_TEST(test_detail_draw_with_packets);
    RUN_TEST(test_detail_gigabit_speed_label);

    TEST_SUITE("iface scan indicator");
    RUN_TEST(test_scan_key_m_hands_the_selected_row_to_the_probe);
    RUN_TEST(test_scan_key_m_with_no_ifaces_calls_nothing);
    RUN_TEST(test_scan_indicator_draw_selected);
    RUN_TEST(test_scan_indicator_draw_unselected);
    RUN_TEST(test_scan_indicator_no_probe_iface);
    RUN_TEST(test_scan_bar_renders);
    RUN_TEST(test_hide_non_monitor);
    RUN_TEST(test_hide_non_monitor_keeps_wifi_station);
    RUN_TEST(test_hide_non_monitor_keeps_capture_iface);
}
