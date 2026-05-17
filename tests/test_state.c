#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "history.h"

/* Tests for sloth_state_t logic — view switching, ring buffer, etc. */

/* ── view switching ──────────────────────────────────────── */

void test_view_tab_cycles_forward(void) {
    view_t v = VIEW_IFACE;
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_CONNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_WIFI);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PACKETS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PROCS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_STATS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PROBE);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ARP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_MDNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_NBNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DHCP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_SSDP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_BEACON);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DEAUTH);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_HTTP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_TLS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_QUIC);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_NTP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ICMP);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_ALERTS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_DEVICES);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_IFACE);   /* wraps */
}

void test_view_direct_key_select(void) {
    view_t v = VIEW_PACKETS;
    /* simulating '1' key */
    v = VIEW_IFACE;   ASSERT_EQ(v, VIEW_IFACE);
    v = VIEW_CONNS;   ASSERT_EQ(v, VIEW_CONNS);
    v = VIEW_WIFI;    ASSERT_EQ(v, VIEW_WIFI);
    v = VIEW_PACKETS; ASSERT_EQ(v, VIEW_PACKETS);
}

void test_view_count_matches_labels(void) {
    /* VIEW_COUNT must stay in sync with actual views */
    ASSERT_EQ(VIEW_COUNT, 22);
}

/* ── packet ring buffer ──────────────────────────────────── */

static void push_packet(sloth_state_t *s, uint32_t ts_sec) {
    int slot = s->pkt_head % MAX_PACKETS;
    memset(&s->packets[slot], 0, sizeof(packet_info_t));
    s->packets[slot].ts_sec = ts_sec;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS)
        s->pkt_count++;
}

void test_ring_buffer_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.pkt_count, 0);
    ASSERT_EQ(s.pkt_head, 0);
}

void test_ring_buffer_single_push(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packet(&s, 1001);
    ASSERT_EQ(s.pkt_count, 1);
    ASSERT_EQ(s.pkt_head, 1);
    ASSERT_EQ((int)s.packets[0].ts_sec, 1001);
}

void test_ring_buffer_fills(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(2000 + i));
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);
    ASSERT_EQ(s.pkt_head, 0);   /* wrapped back to slot 0 */
}

void test_ring_buffer_overwrites_oldest(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    /* fill completely */
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(3000 + i));
    /* push one more — overwrites slot 0 (the oldest) */
    push_packet(&s, 9999);
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);   /* count stays capped */
    ASSERT_EQ((int)s.packets[0].ts_sec, 9999);  /* slot 0 now has newest */
    ASSERT_EQ(s.pkt_head, 1);
}

void test_ring_oldest_start_when_full(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(4000 + i));
    /* When full, oldest entry is at pkt_head (next write slot) */
    int oldest_slot = s.pkt_head;
    ASSERT_EQ((int)s.packets[oldest_slot].ts_sec, 4000);
}

/* ── state field defaults ────────────────────────────────── */

void test_state_zero_init(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.iface_count, 0);
    ASSERT_EQ(s.conn_count,  0);
    ASSERT_EQ(s.ap_count,    0);
    ASSERT_EQ(s.pkt_count,   0);
    ASSERT_EQ((int)s.active_view, 0);
}

/* ── iface history ───────────────────────────────────────── */

void test_history_find_new_slot(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_STR(h->name, "eth0");
    ASSERT_EQ(h->count, 0);
}

void test_history_find_same_slot(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    iface_hist_t *a = history_find(&s, "eth0");
    iface_hist_t *b = history_find(&s, "eth0");
    ASSERT(a == b);   /* same pointer */
}

void test_history_update_pushes_rates(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));

    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);
    s.ifaces[0].rx_rate = 10e6;
    s.ifaces[0].tx_rate =  5e6;

    history_update(&s);

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_EQ(h->count, 1);
    /* head advanced to 1; last-written slot is head-1 = 0 */
    ASSERT_NEAR(h->rx[0], 10e6, 1.0);
    ASSERT_NEAR(h->tx[0],  5e6, 1.0);
}

void test_history_update_multiple_polls(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);

    for (int i = 0; i < HIST_LEN; i++) {
        s.ifaces[0].rx_rate = (double)(i * 1000);
        history_update(&s);
    }

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT(h != NULL);
    ASSERT_EQ(h->count, HIST_LEN);
    ASSERT_EQ(h->head, 0);   /* wrapped back to 0 */
}

void test_history_update_wraps_ring(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 1;
    memcpy(s.ifaces[0].name, "eth0", 5);

    /* overfill by 5 */
    for (int i = 0; i < HIST_LEN + 5; i++) {
        s.ifaces[0].rx_rate = (double)(i);
        history_update(&s);
    }

    iface_hist_t *h = history_find(&s, "eth0");
    ASSERT_EQ(h->count, HIST_LEN);   /* capped */
    /* newest value is HIST_LEN+4, stored at head-1 */
    int last = (h->head - 1 + HIST_LEN) % HIST_LEN;
    ASSERT_NEAR(h->rx[last], (double)(HIST_LEN + 4), 0.5);
}

void test_history_multiple_interfaces(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.iface_count = 2;
    memcpy(s.ifaces[0].name, "eth0",  5);
    memcpy(s.ifaces[1].name, "wlan0", 6);
    s.ifaces[0].rx_rate = 100e6;
    s.ifaces[1].rx_rate =  50e6;

    history_update(&s);

    iface_hist_t *h0 = history_find(&s, "eth0");
    iface_hist_t *h1 = history_find(&s, "wlan0");
    ASSERT(h0 != h1);
    ASSERT_NEAR(h0->rx[0], 100e6, 1.0);
    ASSERT_NEAR(h1->rx[0],  50e6, 1.0);
}

/* ── iface toggle ────────────────────────────────────────── */

#include "views/iface.h"

static sloth_state_t make_state_with_ifaces(int n) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    static const char *names[] = { "eth0", "wlan0", "lo", "tun0" };
    s.iface_count = n < 4 ? n : 4;
    for (int i = 0; i < s.iface_count; i++)
        memcpy(s.ifaces[i].name, names[i], strlen(names[i]) + 1);
    return s;
}

void test_toggle_hide(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;   /* eth0 selected */
    view_iface_key(&s, 't');
    ASSERT_EQ(s.iface_hidden_count, 1);
    ASSERT_STR(s.iface_hidden[0], "eth0");
}

void test_toggle_unhide(void) {
    sloth_state_t s = make_state_with_ifaces(2);
    s.iface_sel = 0;
    view_iface_key(&s, 't');   /* hide eth0 */
    view_iface_key(&s, 't');   /* unhide eth0 */
    ASSERT_EQ(s.iface_hidden_count, 0);
}

void test_toggle_navigation(void) {
    sloth_state_t s = make_state_with_ifaces(3);
    ASSERT_EQ(s.iface_sel, 0);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 2);
    view_iface_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.iface_sel, 2);   /* clamped at max */
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 1);
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 0);
    view_iface_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.iface_sel, 0);   /* clamped at 0 */
}

void test_toggle_hides_selected(void) {
    sloth_state_t s = make_state_with_ifaces(3);
    view_iface_key(&s, SLOTH_KEY_DOWN);   /* sel = 1 (wlan0) */
    view_iface_key(&s, 't');
    ASSERT_EQ(s.iface_hidden_count, 1);
    ASSERT_STR(s.iface_hidden[0], "wlan0");
}

void run_state_tests(void) {
    TEST_SUITE("view switching");
    RUN_TEST(test_view_tab_cycles_forward);
    RUN_TEST(test_view_direct_key_select);
    RUN_TEST(test_view_count_matches_labels);

    TEST_SUITE("packet ring buffer");
    RUN_TEST(test_ring_buffer_empty);
    RUN_TEST(test_ring_buffer_single_push);
    RUN_TEST(test_ring_buffer_fills);
    RUN_TEST(test_ring_buffer_overwrites_oldest);
    RUN_TEST(test_ring_oldest_start_when_full);

    TEST_SUITE("state defaults");
    RUN_TEST(test_state_zero_init);

    TEST_SUITE("iface history");
    RUN_TEST(test_history_find_new_slot);
    RUN_TEST(test_history_find_same_slot);
    RUN_TEST(test_history_update_pushes_rates);
    RUN_TEST(test_history_update_multiple_polls);
    RUN_TEST(test_history_update_wraps_ring);
    RUN_TEST(test_history_multiple_interfaces);

    TEST_SUITE("iface toggle + navigation");
    RUN_TEST(test_toggle_hide);
    RUN_TEST(test_toggle_unhide);
    RUN_TEST(test_toggle_navigation);
    RUN_TEST(test_toggle_hides_selected);
}
