#include <string.h>
#include "runner.h"
#include "ntop.h"
#include "views/conns.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void add_tcp(ntop_state_t *s, uint16_t lport, uint32_t rtt_us,
                    uint32_t retrans) {
    if (s->conn_count >= MAX_CONNS) return;
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    c->proto      = PROTO_TCP;
    c->state      = 1;  /* ESTABLISHED */
    c->local_port = lport;
    c->rtt_us     = rtt_us;
    c->retrans    = retrans;
    snprintf(c->local_addr,  sizeof(c->local_addr),  "10.0.0.1");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "8.8.8.8");
}

static void add_udp(ntop_state_t *s, uint16_t lport) {
    if (s->conn_count >= MAX_CONNS) return;
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    c->proto      = PROTO_UDP;
    c->state      = 7;
    c->local_port = lport;
    c->rtt_us     = 0;
    c->retrans    = 0;
}

/* ── conn_t field tests ──────────────────────────────────── */

static void test_conn_rtt_zero_at_init(void) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    ASSERT_EQ((int)c.rtt_us, 0);
}

static void test_conn_retrans_zero_at_init(void) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    ASSERT_EQ((int)c.retrans, 0);
}

static void test_conn_rtt_field_assigned(void) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    c.rtt_us = 12345u;
    ASSERT_EQ((int)c.rtt_us, 12345);
}

static void test_conn_retrans_field_assigned(void) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    c.retrans = 7u;
    ASSERT_EQ((int)c.retrans, 7);
}

/* ── CONN_SORT_RTT ───────────────────────────────────────── */

static void test_sort_rtt_orders_descending(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 1001,  5000, 0);   /* 5ms */
    add_tcp(&s, 1002, 50000, 0);   /* 50ms — should sort first */
    add_tcp(&s, 1003,  1000, 0);   /* 1ms */
    s.conn_sort   = CONN_SORT_RTT;
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);
    /* highest RTT first */
    ASSERT_EQ(s.conn_idx[0], 1);   /* 50ms */
    ASSERT_EQ(s.conn_idx[1], 0);   /* 5ms  */
    ASSERT_EQ(s.conn_idx[2], 2);   /* 1ms  */
}

static void test_sort_rtt_zero_last(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 1001,     0, 0);   /* unknown (0) */
    add_tcp(&s, 1002, 10000, 0);   /* 10ms */
    s.conn_sort   = CONN_SORT_RTT;
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx[0], 1);   /* 10ms first */
    ASSERT_EQ(s.conn_idx[1], 0);   /* 0 last */
}

static void test_sort_rtt_enum_value(void) {
    ASSERT_EQ((int)CONN_SORT_RTT, 5);
    ASSERT_EQ((int)CONN_SORT_COUNT, 6);
}

/* ── Draw smoke tests ────────────────────────────────────── */

static void test_draw_no_conns(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    view_conns_draw(&s);
    ASSERT(1);
}

static void test_draw_tcp_with_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 443, 12500, 3);   /* 12.5ms, 3 retransmits */
    s.conn_sort   = CONN_SORT_STATE;
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
    ASSERT_EQ(s.conn_count, 1);
}

static void test_draw_tcp_no_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 22, 0, 0);   /* unknown RTT */
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
    ASSERT(1);
}

static void test_draw_udp_no_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_udp(&s, 5353);
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
    ASSERT(1);
}

static void test_draw_mixed_conns(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 443,  8000, 0);
    add_tcp(&s, 80,  85000, 5);   /* 85ms, 5 retransmits */
    add_udp(&s, 5353);
    add_tcp(&s, 22,      0, 0);   /* listening, no RTT */
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
    ASSERT_EQ(s.conn_count, 4);
}

static void test_draw_sort_by_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    add_tcp(&s, 443, 3000, 0);
    add_tcp(&s, 80,  9000, 2);
    s.conn_sort   = CONN_SORT_RTT;
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);
    view_conns_draw(&s);
    ASSERT_EQ(s.conn_idx[0], 1);  /* 9ms first */
}

/* ── Key handler: RTT sort cycle ─────────────────────────── */

static void test_sort_cycles_include_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.conn_sort   = CONN_SORT_BW;
    s.conn_filter = CONN_FILTER_ALL;
    view_conns_key(&s, 's');
    ASSERT_EQ((int)s.conn_sort, (int)CONN_SORT_RTT);
}

static void test_sort_wraps_after_rtt(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.conn_sort   = CONN_SORT_RTT;
    s.conn_filter = CONN_FILTER_ALL;
    view_conns_key(&s, 's');
    ASSERT_EQ((int)s.conn_sort, (int)CONN_SORT_STATE);
}

/* ── Retransmit parsing boundary ─────────────────────────── */

static void test_retrans_large_value(void) {
    conn_t c;
    memset(&c, 0, sizeof(c));
    c.retrans = 65535u;
    ASSERT_EQ((int)c.retrans, 65535);
}

static void test_rtt_sub_ms(void) {
    /* RTT < 1ms (< 1000us) should still be stored */
    conn_t c;
    memset(&c, 0, sizeof(c));
    c.rtt_us = 500u;
    ASSERT_EQ((int)c.rtt_us, 500);
}

/* ── Entry point ─────────────────────────────────────────── */

void run_rtt_tests(void) {
    TEST_SUITE("rtt/fields");
    RUN_TEST(test_conn_rtt_zero_at_init);
    RUN_TEST(test_conn_retrans_zero_at_init);
    RUN_TEST(test_conn_rtt_field_assigned);
    RUN_TEST(test_conn_retrans_field_assigned);
    RUN_TEST(test_retrans_large_value);
    RUN_TEST(test_rtt_sub_ms);

    TEST_SUITE("rtt/sort");
    RUN_TEST(test_sort_rtt_enum_value);
    RUN_TEST(test_sort_rtt_orders_descending);
    RUN_TEST(test_sort_rtt_zero_last);

    TEST_SUITE("rtt/draw");
    RUN_TEST(test_draw_no_conns);
    RUN_TEST(test_draw_tcp_with_rtt);
    RUN_TEST(test_draw_tcp_no_rtt);
    RUN_TEST(test_draw_udp_no_rtt);
    RUN_TEST(test_draw_mixed_conns);
    RUN_TEST(test_draw_sort_by_rtt);

    TEST_SUITE("rtt/key");
    RUN_TEST(test_sort_cycles_include_rtt);
    RUN_TEST(test_sort_wraps_after_rtt);
}
