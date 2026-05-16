#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "ntop.h"
#include "views/conns.h"

/* Build a state with n_tcp TCP and n_udp UDP connections.
   TCP ports 1000..1000+n_tcp-1, UDP ports 5000..5000+n_udp-1.
   PIDs assigned sequentially starting at 100. */
static void make_test_state(ntop_state_t *s, int n_tcp, int n_udp) {
    memset(s, 0, sizeof(*s));
    int n = 0;
    for (int i = 0; i < n_tcp && n < MAX_CONNS; i++, n++) {
        s->conns[n].proto      = PROTO_TCP;
        s->conns[n].state      = (i % 2 == 0) ? 0x0A : 0x01; /* LISTEN / ESTABLISHED */
        s->conns[n].local_port = (uint16_t)(1000 + i);
        s->conns[n].pid        = 100 + i;
    }
    for (int i = 0; i < n_udp && n < MAX_CONNS; i++, n++) {
        s->conns[n].proto      = PROTO_UDP;
        s->conns[n].state      = 7;
        s->conns[n].local_port = (uint16_t)(5000 + i);
        s->conns[n].pid        = 200 + i;
    }
    s->conn_count  = n;
    s->conn_sort   = CONN_SORT_STATE;
    s->conn_filter = CONN_FILTER_ALL;
}

/* ── conn_rebuild_idx filter tests ──────────────────────── */

void test_rebuild_filter_all(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 2);
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 5);
}

void test_rebuild_filter_tcp(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 2);
    s.conn_filter = CONN_FILTER_TCP;
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 3);
    for (int i = 0; i < s.conn_idx_count; i++)
        ASSERT_EQ(s.conns[s.conn_idx[i]].proto, PROTO_TCP);
}

void test_rebuild_filter_udp(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 2);
    s.conn_filter = CONN_FILTER_UDP;
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 2);
    for (int i = 0; i < s.conn_idx_count; i++)
        ASSERT_EQ(s.conns[s.conn_idx[i]].proto, PROTO_UDP);
}

void test_rebuild_empty(void) {
    ntop_state_t s;
    make_test_state(&s, 0, 0);
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 0);
    ASSERT_EQ(s.conn_sel, 0);
}

/* ── conn_rebuild_idx sort tests ─────────────────────────── */

void test_sort_by_lport(void) {
    ntop_state_t s;
    make_test_state(&s, 4, 0);
    s.conns[0].local_port = 1003;
    s.conns[1].local_port = 1001;
    s.conns[2].local_port = 1002;
    s.conns[3].local_port = 1000;
    s.conn_sort = CONN_SORT_LPORT;
    conn_rebuild_idx(&s);

    ASSERT_EQ(s.conn_idx_count, 4);
    ASSERT_EQ(s.conns[s.conn_idx[0]].local_port, 1000);
    ASSERT_EQ(s.conns[s.conn_idx[1]].local_port, 1001);
    ASSERT_EQ(s.conns[s.conn_idx[2]].local_port, 1002);
    ASSERT_EQ(s.conns[s.conn_idx[3]].local_port, 1003);
}

void test_sort_by_pid(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 0);
    s.conns[0].pid = 300;
    s.conns[1].pid = 100;
    s.conns[2].pid = 200;
    s.conn_sort = CONN_SORT_PID;
    conn_rebuild_idx(&s);

    ASSERT_EQ(s.conns[s.conn_idx[0]].pid, 100);
    ASSERT_EQ(s.conns[s.conn_idx[1]].pid, 200);
    ASSERT_EQ(s.conns[s.conn_idx[2]].pid, 300);
}

void test_sort_by_proto(void) {
    ntop_state_t s;
    make_test_state(&s, 2, 2);
    s.conn_sort = CONN_SORT_PROTO;
    conn_rebuild_idx(&s);

    /* TCP (6) before UDP (17) */
    ASSERT_EQ(s.conns[s.conn_idx[0]].proto, PROTO_TCP);
    ASSERT_EQ(s.conns[s.conn_idx[1]].proto, PROTO_TCP);
    ASSERT_EQ(s.conns[s.conn_idx[2]].proto, PROTO_UDP);
    ASSERT_EQ(s.conns[s.conn_idx[3]].proto, PROTO_UDP);
}

/* ── conn_sel clamping ───────────────────────────────────── */

void test_conn_sel_clamped_on_filter(void) {
    ntop_state_t s;
    make_test_state(&s, 5, 5);
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);
    s.conn_sel = 8;  /* valid in 10-entry list */

    s.conn_filter = CONN_FILTER_UDP;  /* now only 5 entries */
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 5);
    ASSERT(s.conn_sel < 5);
}

/* ── view_conns_key tests ────────────────────────────────── */

void test_key_sort_cycles(void) {
    ntop_state_t s;
    make_test_state(&s, 2, 0);
    s.conn_sort = CONN_SORT_STATE;
    conn_rebuild_idx(&s);

    /* pressing 's' CONN_SORT_COUNT times wraps back to the start */
    for (int i = 0; i < (int)CONN_SORT_COUNT; i++)
        view_conns_key(&s, 's');
    ASSERT_EQ((int)s.conn_sort, (int)CONN_SORT_STATE);
}

void test_key_filter_cycles(void) {
    ntop_state_t s;
    make_test_state(&s, 2, 2);
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);

    for (int i = 0; i < (int)CONN_FILTER_COUNT; i++)
        view_conns_key(&s, 'f');
    ASSERT_EQ((int)s.conn_filter, (int)CONN_FILTER_ALL);
}

void test_key_nav_down_up(void) {
    ntop_state_t s;
    make_test_state(&s, 5, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 0;

    view_conns_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 1);
    view_conns_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);
}

void test_key_nav_up_at_top(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 0;

    view_conns_key(&s, NTOP_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);  /* stays at top */
}

void test_key_nav_down_at_bottom(void) {
    ntop_state_t s;
    make_test_state(&s, 3, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 2;  /* last entry */

    view_conns_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 2);  /* stays at bottom */
}

void run_conns_tests(void) {
    TEST_SUITE("conn_rebuild_idx/filter");
    RUN_TEST(test_rebuild_filter_all);
    RUN_TEST(test_rebuild_filter_tcp);
    RUN_TEST(test_rebuild_filter_udp);
    RUN_TEST(test_rebuild_empty);

    TEST_SUITE("conn_rebuild_idx/sort");
    RUN_TEST(test_sort_by_lport);
    RUN_TEST(test_sort_by_pid);
    RUN_TEST(test_sort_by_proto);

    TEST_SUITE("conn_rebuild_idx/clamp");
    RUN_TEST(test_conn_sel_clamped_on_filter);

    TEST_SUITE("view_conns_key");
    RUN_TEST(test_key_sort_cycles);
    RUN_TEST(test_key_filter_cycles);
    RUN_TEST(test_key_nav_down_up);
    RUN_TEST(test_key_nav_up_at_top);
    RUN_TEST(test_key_nav_down_at_bottom);
}
