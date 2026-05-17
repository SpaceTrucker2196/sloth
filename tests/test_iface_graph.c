#include <string.h>
#include "runner.h"
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
    ASSERT(1);
}

static void test_graph_draw_no_crash_no_history(void) {
    sloth_state_t s = make_state(1);
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_graph_draw_no_crash_with_history(void) {
    sloth_state_t s = make_state(1);
    push_history(&s, "eth0", 10);
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_graph_draw_no_crash_full_history(void) {
    sloth_state_t s = make_state(1);
    push_history(&s, "eth0", HIST_LEN + 5);  /* overfill ring */
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_graph_draw_second_iface(void) {
    sloth_state_t s = make_state(2);
    push_history(&s, "wlan0", 15);
    s.iface_sel  = 1;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_normal_draw_not_affected(void) {
    sloth_state_t s = make_state(2);
    s.iface_graph = 0;
    view_iface_draw(&s);  /* normal table view */
    ASSERT(1);
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
    ASSERT(1);
}

static void test_detail_draw_no_errors(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].mtu        = 9000;
    s.ifaces[0].speed_mbps = 10000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_detail_draw_unknown_speed_mtu(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].speed_mbps = -1;
    s.ifaces[0].mtu        = 0;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_detail_draw_with_packets(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].rx_bytes   = 1024ULL * 1024 * 500;
    s.ifaces[0].tx_bytes   = 1024ULL * 1024 * 100;
    s.ifaces[0].rx_packets = 500000;
    s.ifaces[0].tx_packets = 200000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

static void test_detail_gigabit_speed_label(void) {
    sloth_state_t s = make_state(1);
    s.ifaces[0].speed_mbps = 1000;
    s.iface_graph = 1;
    view_iface_draw(&s);
    ASSERT(1);
}

/* ── Scan interface indicator tests ──────────────────────── */

static void test_scan_key_m_no_crash(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 1;
    /* probe_set_iface is a no-op in test build (no WITH_PCAP); must not crash */
    view_iface_key(&s, 'm');
    view_iface_key(&s, 'M');
    ASSERT(1);
}

static void test_scan_key_m_no_crash_no_ifaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_iface_key(&s, 'm');
    ASSERT(1);
}

static void test_scan_indicator_draw_selected(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 0;
    memcpy(s.probe_iface, "eth0", 5);
    view_iface_draw(&s);   /* selected row should show [scanning] */
    ASSERT(1);
}

static void test_scan_indicator_draw_unselected(void) {
    sloth_state_t s = make_state(2);
    s.iface_sel = 0;
    memcpy(s.probe_iface, "wlan0", 6);  /* wlan0 is row 1, not selected */
    view_iface_draw(&s);   /* unselected row with 's' prefix */
    ASSERT(1);
}

static void test_scan_indicator_no_probe_iface(void) {
    sloth_state_t s = make_state(2);
    s.probe_iface[0] = '\0';
    view_iface_draw(&s);   /* no scan marker anywhere */
    ASSERT(1);
}

/* ── Entry point ─────────────────────────────────────────── */

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
    RUN_TEST(test_scan_key_m_no_crash);
    RUN_TEST(test_scan_key_m_no_crash_no_ifaces);
    RUN_TEST(test_scan_indicator_draw_selected);
    RUN_TEST(test_scan_indicator_draw_unselected);
    RUN_TEST(test_scan_indicator_no_probe_iface);
}
