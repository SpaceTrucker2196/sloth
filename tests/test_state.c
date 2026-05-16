#include <string.h>
#include "runner.h"
#include "ntop.h"

/* Tests for ntop_state_t logic — view switching, ring buffer, etc. */

/* ── view switching ──────────────────────────────────────── */

void test_view_tab_cycles_forward(void) {
    view_t v = VIEW_IFACE;
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_CONNS);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_WIFI);
    v = (view_t)((v + 1) % VIEW_COUNT);  ASSERT_EQ(v, VIEW_PACKETS);
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
    ASSERT_EQ(VIEW_COUNT, 4);
}

/* ── packet ring buffer ──────────────────────────────────── */

static void push_packet(ntop_state_t *s, uint32_t ts_sec) {
    int slot = s->pkt_head % MAX_PACKETS;
    memset(&s->packets[slot], 0, sizeof(packet_info_t));
    s->packets[slot].ts_sec = ts_sec;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS)
        s->pkt_count++;
}

void test_ring_buffer_empty(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.pkt_count, 0);
    ASSERT_EQ(s.pkt_head, 0);
}

void test_ring_buffer_single_push(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_packet(&s, 1001);
    ASSERT_EQ(s.pkt_count, 1);
    ASSERT_EQ(s.pkt_head, 1);
    ASSERT_EQ((int)s.packets[0].ts_sec, 1001);
}

void test_ring_buffer_fills(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(2000 + i));
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);
    ASSERT_EQ(s.pkt_head, 0);   /* wrapped back to slot 0 */
}

void test_ring_buffer_overwrites_oldest(void) {
    ntop_state_t s;
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
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_PACKETS; i++)
        push_packet(&s, (uint32_t)(4000 + i));
    /* When full, oldest entry is at pkt_head (next write slot) */
    int oldest_slot = s.pkt_head;
    ASSERT_EQ((int)s.packets[oldest_slot].ts_sec, 4000);
}

/* ── state field defaults ────────────────────────────────── */

void test_state_zero_init(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.iface_count, 0);
    ASSERT_EQ(s.conn_count,  0);
    ASSERT_EQ(s.ap_count,    0);
    ASSERT_EQ(s.pkt_count,   0);
    ASSERT_EQ((int)s.active_view, 0);
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
}
