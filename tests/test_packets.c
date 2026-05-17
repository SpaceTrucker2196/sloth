#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/packets.h"

/* Push n synthetic packets into the ring buffer. */
static void push_packets(sloth_state_t *s, int n) {
    for (int i = 0; i < n; i++) {
        packet_info_t p;
        memset(&p, 0, sizeof(p));
        p.ts_sec  = (uint32_t)(1000 + i);
        p.len     = (uint32_t)(60 + i);
        p.proto   = 6;
        snprintf(p.src,  sizeof(p.src),  "10.0.0.%d", i & 0xff);
        snprintf(p.dst,  sizeof(p.dst),  "8.8.8.%d",  i & 0xff);
        snprintf(p.info, sizeof(p.info), "TCP SYN %d", i);

        s->packets[s->pkt_head] = p;
        s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
        if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
    }
}

/* ── Pause / unpause ─────────────────────────────────────── */

void test_pause_toggle(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    ASSERT_EQ(s.pkt_paused, 0);

    view_packets_key(&s, 'p');
    ASSERT_EQ(s.pkt_paused, 1);

    view_packets_key(&s, 'p');
    ASSERT_EQ(s.pkt_paused, 0);
}

void test_pause_space_key(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 3);

    view_packets_key(&s, ' ');
    ASSERT_EQ(s.pkt_paused, 1);
    view_packets_key(&s, ' ');
    ASSERT_EQ(s.pkt_paused, 0);
}

void test_pause_jumps_to_newest(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 10);
    s.pkt_sel = 0;  /* at oldest */

    view_packets_key(&s, 'p');  /* pause → jump to newest */
    ASSERT_EQ(s.pkt_sel, 9);
}

/* ── Navigation (only when paused) ──────────────────────── */

void test_nav_up_when_paused(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_sel    = 3;

    view_packets_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.pkt_sel, 2);
}

void test_nav_down_when_paused(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_sel    = 2;

    view_packets_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.pkt_sel, 3);
}

void test_nav_ignored_when_live(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 0;
    s.pkt_sel    = 2;

    view_packets_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.pkt_sel, 2);   /* unchanged — navigation blocked */
    view_packets_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.pkt_sel, 2);
}

void test_nav_top_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 3);
    s.pkt_paused = 1;
    s.pkt_sel    = 0;

    view_packets_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.pkt_sel, 0);  /* stays at top */
}

void test_nav_bottom_bound(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 3);
    s.pkt_paused = 1;
    s.pkt_sel    = 2;  /* last */

    view_packets_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.pkt_sel, 2);  /* stays at bottom */
}

/* ── Ring buffer overflow ────────────────────────────────── */

void test_ring_overflows_correctly(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, MAX_PACKETS + 10);

    /* pkt_count is capped at MAX_PACKETS (ring size) */
    ASSERT_EQ(s.pkt_count, MAX_PACKETS);
    /* head advanced 10 past the wrap point */
    ASSERT_EQ(s.pkt_head, 10);
}

/* ── BPF filter input state machine ─────────────────────── */

void test_filter_slash_enters_mode(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    ASSERT_EQ(s.pkt_filter_mode, 0);
    view_packets_key(&s, '/');
    ASSERT_EQ(s.pkt_filter_mode, 1);
}

void test_filter_f_key_enters_mode(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, 'f');
    ASSERT_EQ(s.pkt_filter_mode, 1);
}

void test_filter_prefills_active_filter(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.pkt_filter, "port 80", sizeof(s.pkt_filter) - 1);
    view_packets_key(&s, '/');
    s.pkt_filter_buf[s.pkt_filter_len] = '\0';
    ASSERT_EQ(strcmp(s.pkt_filter_buf, "port 80"), 0);
    ASSERT_EQ(s.pkt_filter_len, 7);
}

void test_filter_type_appends_chars(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, '/');
    view_packets_key(&s, 'p');
    view_packets_key(&s, 'o');
    view_packets_key(&s, 'r');
    view_packets_key(&s, 't');
    ASSERT_EQ(s.pkt_filter_len, 4);
    s.pkt_filter_buf[s.pkt_filter_len] = '\0';
    ASSERT_EQ(strcmp(s.pkt_filter_buf, "port"), 0);
}

void test_filter_backspace_removes_char(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, '/');
    view_packets_key(&s, 'a');
    view_packets_key(&s, 'b');
    ASSERT_EQ(s.pkt_filter_len, 2);
    view_packets_key(&s, SLOTH_KEY_BACKSPACE);
    ASSERT_EQ(s.pkt_filter_len, 1);
}

void test_filter_backspace_at_zero_is_noop(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, '/');
    ASSERT_EQ(s.pkt_filter_len, 0);
    view_packets_key(&s, SLOTH_KEY_BACKSPACE);
    ASSERT_EQ(s.pkt_filter_len, 0);
}

void test_filter_esc_cancels(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.pkt_filter, "port 80", sizeof(s.pkt_filter) - 1);
    view_packets_key(&s, '/');
    view_packets_key(&s, 'x');
    view_packets_key(&s, '\033');
    ASSERT_EQ(s.pkt_filter_mode, 0);
    /* active filter unchanged */
    ASSERT_EQ(strcmp(s.pkt_filter, "port 80"), 0);
}

void test_filter_enter_applies(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, '/');
    view_packets_key(&s, 'p');
    view_packets_key(&s, '4');
    /* Enter — no pcap handle, so capture_set_filter is a no-op stub */
    view_packets_key(&s, '\r');
    ASSERT_EQ(s.pkt_filter_mode, 0);
    s.pkt_filter[sizeof(s.pkt_filter) - 1] = '\0';
    ASSERT_EQ(strcmp(s.pkt_filter, "p4"), 0);
}

void test_filter_normal_keys_blocked_in_mode(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 0;
    view_packets_key(&s, '/');
    /* 'p' should add to buffer, not toggle pause */
    view_packets_key(&s, 'p');
    ASSERT_EQ(s.pkt_paused, 0);
    ASSERT_EQ(s.pkt_filter_len, 1);
}

void test_filter_buf_limit(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_key(&s, '/');
    /* fill to max (255 chars) */
    for (int i = 0; i < 300; i++)
        view_packets_key(&s, 'a');
    ASSERT_EQ(s.pkt_filter_len, (int)sizeof(s.pkt_filter_buf) - 1);
}

void test_filter_clear_x(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    strncpy(s.pkt_filter, "port 443", sizeof(s.pkt_filter) - 1);
    view_packets_key(&s, 'x');
    ASSERT_EQ(s.pkt_filter[0], '\0');
    ASSERT_EQ(s.pkt_filter_err[0], '\0');
}

void test_filter_draw_in_filter_mode(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 3);
    view_packets_key(&s, '/');
    view_packets_key(&s, 'u');
    view_packets_draw(&s);
    ASSERT(1);
}

/* ── Draw smoke test ─────────────────────────────────────── */

void test_draw_no_crash_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_packets_draw(&s);
    ASSERT(1);
}

void test_draw_no_crash_with_packets(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_sel    = 2;
    view_packets_draw(&s);
    ASSERT(1);
}

/* ── Detail panel ────────────────────────────────────────── */

void test_detail_open_when_paused(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_sel    = 2;
    ASSERT_EQ(s.pkt_detail, 0);
    view_packets_key(&s, '\r');
    ASSERT_EQ(s.pkt_detail, 1);
}

void test_detail_not_open_when_live(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 0;
    view_packets_key(&s, '\r');
    ASSERT_EQ(s.pkt_detail, 0);
}

void test_detail_not_open_when_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    s.pkt_paused = 1;
    view_packets_key(&s, '\r');
    ASSERT_EQ(s.pkt_detail, 0);
}

void test_detail_close_on_enter(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_detail = 1;
    view_packets_key(&s, '\r');
    ASSERT_EQ(s.pkt_detail, 0);
}

void test_detail_close_on_esc(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_detail = 1;
    view_packets_key(&s, '\033');
    ASSERT_EQ(s.pkt_detail, 0);
}

void test_detail_blocks_nav(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 5);
    s.pkt_paused = 1;
    s.pkt_sel    = 2;
    s.pkt_detail = 1;
    view_packets_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.pkt_sel, 2);  /* unchanged */
    view_packets_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.pkt_sel, 2);  /* unchanged */
}

void test_detail_draw_no_crash(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    push_packets(&s, 3);
    s.pkt_paused = 1;
    s.pkt_sel    = 1;
    s.pkt_detail = 1;
    view_packets_draw(&s);
    ASSERT(1);
}

void run_packets_tests(void) {
    TEST_SUITE("view_packets_key/pause");
    RUN_TEST(test_pause_toggle);
    RUN_TEST(test_pause_space_key);
    RUN_TEST(test_pause_jumps_to_newest);

    TEST_SUITE("view_packets_key/nav");
    RUN_TEST(test_nav_up_when_paused);
    RUN_TEST(test_nav_down_when_paused);
    RUN_TEST(test_nav_ignored_when_live);
    RUN_TEST(test_nav_top_bound);
    RUN_TEST(test_nav_bottom_bound);

    TEST_SUITE("packets/ring");
    RUN_TEST(test_ring_overflows_correctly);

    TEST_SUITE("view_packets_key/filter");
    RUN_TEST(test_filter_slash_enters_mode);
    RUN_TEST(test_filter_f_key_enters_mode);
    RUN_TEST(test_filter_prefills_active_filter);
    RUN_TEST(test_filter_type_appends_chars);
    RUN_TEST(test_filter_backspace_removes_char);
    RUN_TEST(test_filter_backspace_at_zero_is_noop);
    RUN_TEST(test_filter_esc_cancels);
    RUN_TEST(test_filter_enter_applies);
    RUN_TEST(test_filter_normal_keys_blocked_in_mode);
    RUN_TEST(test_filter_buf_limit);
    RUN_TEST(test_filter_clear_x);

    TEST_SUITE("view_packets_draw");
    RUN_TEST(test_draw_no_crash_empty);
    RUN_TEST(test_draw_no_crash_with_packets);
    RUN_TEST(test_filter_draw_in_filter_mode);

    TEST_SUITE("view_packets_key/detail");
    RUN_TEST(test_detail_open_when_paused);
    RUN_TEST(test_detail_not_open_when_live);
    RUN_TEST(test_detail_not_open_when_empty);
    RUN_TEST(test_detail_close_on_enter);
    RUN_TEST(test_detail_close_on_esc);
    RUN_TEST(test_detail_blocks_nav);
    RUN_TEST(test_detail_draw_no_crash);
}
