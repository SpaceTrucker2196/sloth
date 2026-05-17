#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "views/conns.h"

/* Build a state with n_tcp TCP and n_udp UDP connections.
   TCP ports 1000..1000+n_tcp-1, UDP ports 5000..5000+n_udp-1.
   PIDs assigned sequentially starting at 100. */
static void make_test_state(sloth_state_t *s, int n_tcp, int n_udp) {
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

static void make_conn(conn_t *c, const char *laddr, uint16_t lport,
                      const char *raddr, uint16_t rport,
                      int proto, int state, int pid, const char *proc) {
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr, sizeof(c->local_addr), "%s", laddr);
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", raddr);
    c->local_port  = lport;
    c->remote_port = rport;
    c->proto       = proto;
    c->state       = state;
    c->pid         = pid;
    if (proc) snprintf(c->proc, sizeof(c->proc), "%s", proc);
}

static void add_bw_entry(sloth_state_t *s, int idx, const conn_t *c,
                         double rx_rate, double tx_rate) {
    conn_bw_t *bw = &s->conn_bw[idx];
    memset(bw, 0, sizeof(*bw));
    snprintf(bw->local_addr, sizeof(bw->local_addr), "%s", c->local_addr);
    snprintf(bw->remote_addr, sizeof(bw->remote_addr), "%s", c->remote_addr);
    bw->local_port  = c->local_port;
    bw->remote_port = c->remote_port;
    bw->proto       = c->proto;
    bw->rx_rate     = rx_rate;
    bw->tx_rate     = tx_rate;
    bw->rx_hist[0]  = (float)rx_rate;
    bw->tx_hist[0]  = (float)tx_rate;
    bw->hist_head   = 1;
    bw->hist_count  = 1;
}

/* ── conn_rebuild_idx filter tests ──────────────────────── */

void test_rebuild_filter_all(void) {
    sloth_state_t s;
    make_test_state(&s, 3, 2);
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 5);
}

void test_rebuild_filter_tcp(void) {
    sloth_state_t s;
    make_test_state(&s, 3, 2);
    s.conn_filter = CONN_FILTER_TCP;
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 3);
    for (int i = 0; i < s.conn_idx_count; i++)
        ASSERT_EQ(s.conns[s.conn_idx[i]].proto, PROTO_TCP);
}

void test_rebuild_filter_udp(void) {
    sloth_state_t s;
    make_test_state(&s, 3, 2);
    s.conn_filter = CONN_FILTER_UDP;
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 2);
    for (int i = 0; i < s.conn_idx_count; i++)
        ASSERT_EQ(s.conns[s.conn_idx[i]].proto, PROTO_UDP);
}

void test_rebuild_empty(void) {
    sloth_state_t s;
    make_test_state(&s, 0, 0);
    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx_count, 0);
    ASSERT_EQ(s.conn_sel, 0);
}

/* ── conn_rebuild_idx sort tests ─────────────────────────── */

void test_sort_by_lport(void) {
    sloth_state_t s;
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
    sloth_state_t s;
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
    sloth_state_t s;
    make_test_state(&s, 2, 2);
    s.conn_sort = CONN_SORT_PROTO;
    conn_rebuild_idx(&s);

    /* TCP (6) before UDP (17) */
    ASSERT_EQ(s.conns[s.conn_idx[0]].proto, PROTO_TCP);
    ASSERT_EQ(s.conns[s.conn_idx[1]].proto, PROTO_TCP);
    ASSERT_EQ(s.conns[s.conn_idx[2]].proto, PROTO_UDP);
    ASSERT_EQ(s.conns[s.conn_idx[3]].proto, PROTO_UDP);
}

void test_sort_by_bw(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    make_conn(&s.conns[0], "10.0.0.1", 1000, "203.0.113.10", 80, PROTO_TCP, 1, 101, "a");
    make_conn(&s.conns[1], "10.0.0.1", 1001, "203.0.113.11", 80, PROTO_TCP, 1, 102, "b");
    make_conn(&s.conns[2], "10.0.0.1", 1002, "203.0.113.12", 80, PROTO_TCP, 1, 103, "c");
    s.conn_count = 3;
    s.conn_sort = CONN_SORT_BW;
    s.conn_filter = CONN_FILTER_ALL;
    s.conn_bw_count = 3;
    add_bw_entry(&s, 0, &s.conns[0], 100.0, 0.0);
    add_bw_entry(&s, 1, &s.conns[1], 400.0, 100.0);
    add_bw_entry(&s, 2, &s.conns[2], 150.0, 50.0);

    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx[0], 1);
    ASSERT_EQ(s.conn_idx[1], 2);
    ASSERT_EQ(s.conn_idx[2], 0);
}

void test_sort_by_rtt(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    make_conn(&s.conns[0], "10.0.0.1", 2000, "8.8.8.8", 443, PROTO_TCP, 1, 201, "alpha");
    make_conn(&s.conns[1], "10.0.0.1", 2001, "1.1.1.1", 443, PROTO_TCP, 1, 202, "bravo");
    make_conn(&s.conns[2], "10.0.0.1", 2002, "9.9.9.9", 443, PROTO_TCP, 1, 203, "charlie");
    s.conns[0].rtt_us = 1200;
    s.conns[1].rtt_us = 5000;
    s.conns[2].rtt_us = 400;
    s.conn_count = 3;
    s.conn_sort = CONN_SORT_RTT;
    s.conn_filter = CONN_FILTER_ALL;

    conn_rebuild_idx(&s);
    ASSERT_EQ(s.conn_idx[0], 1);
    ASSERT_EQ(s.conn_idx[1], 0);
    ASSERT_EQ(s.conn_idx[2], 2);
}

/* ── conn_sel clamping ───────────────────────────────────── */

void test_conn_sel_clamped_on_filter(void) {
    sloth_state_t s;
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
    sloth_state_t s;
    make_test_state(&s, 2, 0);
    s.conn_sort = CONN_SORT_STATE;
    conn_rebuild_idx(&s);

    /* pressing 's' CONN_SORT_COUNT times wraps back to the start */
    for (int i = 0; i < (int)CONN_SORT_COUNT; i++)
        view_conns_key(&s, 's');
    ASSERT_EQ((int)s.conn_sort, (int)CONN_SORT_STATE);
}

void test_key_filter_cycles(void) {
    sloth_state_t s;
    make_test_state(&s, 2, 2);
    s.conn_filter = CONN_FILTER_ALL;
    conn_rebuild_idx(&s);

    for (int i = 0; i < (int)CONN_FILTER_COUNT; i++)
        view_conns_key(&s, 'f');
    ASSERT_EQ((int)s.conn_filter, (int)CONN_FILTER_ALL);
}

void test_key_nav_down_up(void) {
    sloth_state_t s;
    make_test_state(&s, 5, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 0;

    view_conns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 1);
    view_conns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);
}

void test_key_nav_up_at_top(void) {
    sloth_state_t s;
    make_test_state(&s, 3, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 0;

    view_conns_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.conn_sel, 0);  /* stays at top */
}

void test_key_nav_down_at_bottom(void) {
    sloth_state_t s;
    make_test_state(&s, 3, 0);
    conn_rebuild_idx(&s);
    s.conn_sel = 2;  /* last entry */

    view_conns_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.conn_sel, 2);  /* stays at bottom */
}

void test_draw_scan_banner_and_rates(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    make_conn(&s.conns[0], "10.0.0.5", 3000, "203.0.113.10", 443, PROTO_TCP, 1, 301, "curl");
    s.conns[0].rtt_us = 500;
    s.conns[0].retrans = 2;
    make_conn(&s.conns[1], "10.0.0.5", 3001, "8.8.8.8", 53, PROTO_UDP, 0, 0, "");
    s.conns[1].rtt_us = 5000;
    make_conn(&s.conns[2], "10.0.0.5", 3002, "2001:db8::1", 80, PROTO_TCP, 12, 302, "svc");
    s.conns[2].rtt_us = 5000000;
    s.conn_count = 3;
    s.conn_bw_count = 2;
    add_bw_entry(&s, 0, &s.conns[0], 2000.0, 1000.0);
    add_bw_entry(&s, 1, &s.conns[2], 0.0, 0.0);

    s.scan_count = 5;
    for (int i = 0; i < s.scan_count; i++) {
        snprintf(s.scan_entries[i].ip, sizeof(s.scan_entries[i].ip), "198.51.100.%d", 10 + i);
        s.scan_entries[i].flagged = 1;
        s.scan_entries[i].port_count = 10 + i;
    }
    snprintf(s.scan_entries[0].ip, sizeof(s.scan_entries[0].ip), "%s", s.conns[0].remote_addr);

    FILE *devnull = fopen("/dev/null", "w");
    FILE *old_stdout = stdout;
    if (devnull) stdout = devnull;

    s.conn_filter = CONN_FILTER_ALL;
    s.conn_sort = CONN_SORT_STATE;
    s.dns_enabled = 1;
    conn_rebuild_idx(&s);
    view_conns_draw(&s);

    s.conn_filter = CONN_FILTER_TCP;
    s.dns_enabled = 0;
    conn_rebuild_idx(&s);
    view_conns_draw(&s);

    if (devnull) {
        stdout = old_stdout;
        fclose(devnull);
    }
    ASSERT(1);
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
    RUN_TEST(test_sort_by_bw);
    RUN_TEST(test_sort_by_rtt);

    TEST_SUITE("conn_rebuild_idx/clamp");
    RUN_TEST(test_conn_sel_clamped_on_filter);

    TEST_SUITE("view_conns_key");
    RUN_TEST(test_key_sort_cycles);
    RUN_TEST(test_key_filter_cycles);
    RUN_TEST(test_key_nav_down_up);
    RUN_TEST(test_key_nav_up_at_top);
    RUN_TEST(test_key_nav_down_at_bottom);

    TEST_SUITE("view_conns_draw");
    RUN_TEST(test_draw_scan_banner_and_rates);
}
