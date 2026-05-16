#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "ntop.h"
#include "views/procs.h"

static void push_conn(ntop_state_t *s, int pid, const char *proc, int proto, uint16_t rport) {
    if (s->conn_count >= MAX_CONNS) return;
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    c->pid = pid;
    strncpy(c->proc, proc, sizeof(c->proc) - 1);
    c->proto = proto;
    c->remote_port = rport;
    c->state = 1;
}

/* ── procs_aggregate tests ────────────────────────────── */

void test_procs_empty(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 0);
}

void test_procs_single_pid(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 42, "nginx", PROTO_TCP, 80);
    push_conn(&s, 42, "nginx", PROTO_TCP, 443);
    push_conn(&s, 42, "nginx", PROTO_TCP, 8080);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].conn_count, 3);
    ASSERT_EQ(out[0].pid, 42);
}

void test_procs_multi_pid(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 10, "curl",  PROTO_TCP, 80);
    push_conn(&s, 20, "sshd",  PROTO_TCP, 22);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 2);
}

void test_procs_sorted_by_count(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    /* pid A: 1 conn, pid B: 3 conns — B should be first */
    push_conn(&s, 1, "procA", PROTO_TCP, 80);
    push_conn(&s, 2, "procB", PROTO_TCP, 443);
    push_conn(&s, 2, "procB", PROTO_TCP, 8080);
    push_conn(&s, 2, "procB", PROTO_TCP, 8443);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 2);
    ASSERT_EQ(out[0].pid, 2);
    ASSERT_EQ(out[0].conn_count, 3);
    ASSERT_EQ(out[1].pid, 1);
    ASSERT_EQ(out[1].conn_count, 1);
}

void test_procs_tcp_udp_counts(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 5, "daemon", PROTO_TCP, 80);
    push_conn(&s, 5, "daemon", PROTO_TCP, 443);
    push_conn(&s, 5, "daemon", PROTO_UDP, 53);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].tcp_count, 2);
    ASSERT_EQ(out[0].udp_count, 1);
    ASSERT_EQ(out[0].conn_count, 3);
}

void test_procs_unresolved_pid_zero(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 0, "", PROTO_TCP, 80);
    push_conn(&s, 0, "", PROTO_UDP, 53);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].pid, -1);
    ASSERT_EQ(out[0].conn_count, 2);
}

void test_procs_port_dedup(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 7, "app", PROTO_TCP, 80);
    push_conn(&s, 7, "app", PROTO_TCP, 80);   /* duplicate port */
    push_conn(&s, 7, "app", PROTO_TCP, 443);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].conn_count, 3);
    ASSERT_EQ(out[0].port_count, 2);  /* 80 and 443 only */
}

void test_procs_port_cap(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    /* 10 unique remote ports — should be capped at MAX_PROC_PORTS */
    uint16_t ports[] = {1,2,3,4,5,6,7,8,9,10};
    for (int i = 0; i < 10; i++)
        push_conn(&s, 9, "stress", PROTO_TCP, ports[i]);
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(out[0].conn_count, 10);
    ASSERT_EQ(out[0].port_count, MAX_PROC_PORTS);
}

void test_procs_unresolved_last(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s,  0, "",      PROTO_TCP, 80);   /* unresolved */
    push_conn(&s, 10, "nginx", PROTO_TCP, 443);  /* known */
    push_conn(&s, 20, "sshd",  PROTO_TCP, 22);   /* known */
    proc_stat_t out[MAX_PROCS];
    int n = procs_aggregate(&s, out, MAX_PROCS);
    ASSERT_EQ(n, 3);
    /* last entry should be unresolved */
    ASSERT_EQ(out[n - 1].pid, -1);
}

/* ── view_procs_draw smoke tests ─────────────────────── */

void test_procs_draw_empty(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    view_procs_draw(&s);
    ASSERT(1);
}

void test_procs_draw_with_data(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 100, "curl",  PROTO_TCP, 443);
    push_conn(&s, 100, "curl",  PROTO_TCP, 80);
    push_conn(&s, 200, "sshd",  PROTO_TCP, 22);
    push_conn(&s,   0, "",      PROTO_UDP, 53);
    view_procs_draw(&s);
    ASSERT(1);
}

/* ── detail panel key handler tests ──────────────────── */

void test_proc_detail_open_on_enter(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 42, "nginx", PROTO_TCP, 80);
    s.proc_sel = 0;
    view_procs_draw(&s);          /* populate g_procs */
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 1);
}

void test_proc_detail_not_open_for_unresolved(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 0, "", PROTO_TCP, 80);  /* goes to unresolved bucket */
    view_procs_draw(&s);
    s.proc_sel = 0;               /* unresolved is at index 0 */
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 0);
}

void test_proc_detail_not_open_when_empty(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    view_procs_draw(&s);
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 0);
}

void test_proc_detail_close_on_esc(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.proc_detail = 1;
    view_procs_key(&s, '\033');
    ASSERT_EQ(s.proc_detail, 0);
}

void test_proc_detail_close_on_enter(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    s.proc_detail = 1;
    view_procs_key(&s, '\r');
    ASSERT_EQ(s.proc_detail, 0);
}

void test_proc_detail_blocks_nav(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 1, "a", PROTO_TCP, 80);
    push_conn(&s, 2, "b", PROTO_TCP, 443);
    view_procs_draw(&s);
    s.proc_sel    = 0;
    s.proc_detail = 1;
    view_procs_key(&s, NTOP_KEY_DOWN);
    ASSERT_EQ(s.proc_sel, 0);    /* nav key consumed, sel unchanged */
}

void test_proc_detail_draw_no_crash(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 99, "test", PROTO_TCP, 443);
    s.proc_sel    = 0;
    s.proc_detail = 1;
    view_procs_draw(&s);
    ASSERT(1);
}

void test_proc_detail_draw_back_to_list(void) {
    ntop_state_t s;
    memset(&s, 0, sizeof(s));
    push_conn(&s, 7, "daemon", PROTO_TCP, 22);
    view_procs_draw(&s);
    view_procs_key(&s, '\r');     /* open */
    ASSERT_EQ(s.proc_detail, 1);
    view_procs_draw(&s);          /* draw detail panel */
    view_procs_key(&s, '\033');   /* close */
    ASSERT_EQ(s.proc_detail, 0);
}

void run_procs_tests(void) {
    TEST_SUITE("procs_aggregate");
    RUN_TEST(test_procs_empty);
    RUN_TEST(test_procs_single_pid);
    RUN_TEST(test_procs_multi_pid);
    RUN_TEST(test_procs_sorted_by_count);
    RUN_TEST(test_procs_tcp_udp_counts);
    RUN_TEST(test_procs_unresolved_pid_zero);
    RUN_TEST(test_procs_port_dedup);
    RUN_TEST(test_procs_port_cap);
    RUN_TEST(test_procs_unresolved_last);

    TEST_SUITE("view_procs_draw");
    RUN_TEST(test_procs_draw_empty);
    RUN_TEST(test_procs_draw_with_data);

    TEST_SUITE("proc detail panel");
    RUN_TEST(test_proc_detail_open_on_enter);
    RUN_TEST(test_proc_detail_not_open_for_unresolved);
    RUN_TEST(test_proc_detail_not_open_when_empty);
    RUN_TEST(test_proc_detail_close_on_esc);
    RUN_TEST(test_proc_detail_close_on_enter);
    RUN_TEST(test_proc_detail_blocks_nav);
    RUN_TEST(test_proc_detail_draw_no_crash);
    RUN_TEST(test_proc_detail_draw_back_to_list);
}
