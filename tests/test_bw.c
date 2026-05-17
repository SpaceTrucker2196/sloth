#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "bandwidth.h"

/* ── Helpers ─────────────────────────────────────────────── */

static void make_conn(conn_t *c, const char *la, uint16_t lp,
                       const char *ra, uint16_t rp, int proto) {
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr,  sizeof(c->local_addr),  "%s", la);
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", ra);
    c->local_port  = lp;
    c->remote_port = rp;
    c->proto       = proto;
    c->state       = 1;  /* ESTABLISHED */
}

static void make_pkt(packet_info_t *p, const char *src, uint16_t sp,
                     const char *dst, uint16_t dp, int proto, uint32_t len) {
    memset(p, 0, sizeof(*p));
    snprintf(p->src,  sizeof(p->src),  "%s", src);
    snprintf(p->dst,  sizeof(p->dst),  "%s", dst);
    p->src_port = sp;
    p->dst_port = dp;
    p->proto    = proto;
    p->len      = len;
    p->ts_sec   = 1000;
}

/* Push a packet into the ring, advancing pkt_head. */
static void push_pkt(sloth_state_t *s, const packet_info_t *p) {
    s->packets[s->pkt_head] = *p;
    s->pkt_head = (s->pkt_head + 1) % MAX_PACKETS;
    if (s->pkt_count < MAX_PACKETS) s->pkt_count++;
}

/* ── Tests ───────────────────────────────────────────────── */

void test_bw_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();
    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 0);
}

void test_bw_new_conn_zero_rate(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();
    make_conn(&s.conns[0], "192.168.1.1", 12345, "8.8.8.8", 443, PROTO_TCP);
    s.conn_count = 1;
    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 1);
    ASSERT_EQ((int)s.conn_bw[0].rx_rate, 0);
    ASSERT_EQ((int)s.conn_bw[0].tx_rate, 0);
}

void test_bw_lookup_found(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();
    make_conn(&s.conns[0], "10.0.0.1", 9999, "1.2.3.4", 80, PROTO_TCP);
    s.conn_count = 1;
    bw_update(&s);
    const conn_bw_t *bw = bw_lookup(&s, &s.conns[0]);
    ASSERT(bw != NULL);
}

void test_bw_lookup_not_found(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();
    s.conn_bw_count = 0;  /* empty snapshot */
    conn_t c;
    make_conn(&c, "10.0.0.1", 9999, "1.2.3.4", 80, PROTO_TCP);
    const conn_bw_t *bw = bw_lookup(&s, &c);
    ASSERT(bw == NULL);
}

void test_bw_conn_evicted_when_gone(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    make_conn(&s.conns[0], "192.168.1.1", 11111, "5.5.5.5", 443, PROTO_TCP);
    s.conn_count = 1;
    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 1);

    /* remove the connection */
    s.conn_count = 0;
    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 0);
}

void test_bw_sparkline_fills(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    make_conn(&s.conns[0], "172.16.0.1", 5000, "9.9.9.9", 53, PROTO_UDP);
    s.conn_count = 1;

    for (int i = 0; i < 5; i++)
        bw_update(&s);

    ASSERT_EQ(s.conn_bw_count, 1);
    ASSERT(s.conn_bw[0].hist_count >= 2);  /* at least 2 samples after 5 updates */
}

void test_bw_sparkline_caps_at_hist_len(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    make_conn(&s.conns[0], "172.16.0.1", 5000, "9.9.9.9", 53, PROTO_UDP);
    s.conn_count = 1;

    for (int i = 0; i < CONN_BW_HIST + 10; i++)
        bw_update(&s);

    ASSERT_EQ(s.conn_bw[0].hist_count, CONN_BW_HIST);
}

void test_bw_identity_preserved_across_polls(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    make_conn(&s.conns[0], "10.1.1.1", 4321, "2.2.2.2", 8080, PROTO_TCP);
    make_conn(&s.conns[1], "10.1.1.1", 4322, "2.2.2.2", 8080, PROTO_TCP);
    s.conn_count = 2;

    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 2);

    /* second poll — same connections */
    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 2);
}

void test_bw_fmt_rate_dash_for_zero(void) {
    char buf[16];
    bw_fmt_rate(0.0, buf, sizeof(buf));
    ASSERT_EQ(strcmp(buf, "--"), 0);
}

void test_bw_fmt_rate_bytes(void) {
    char buf[16];
    bw_fmt_rate(500.0, buf, sizeof(buf));
    ASSERT_EQ(strcmp(buf, "500B"), 0);
}

void test_bw_fmt_rate_kilo(void) {
    char buf[16];
    bw_fmt_rate(1500.0, buf, sizeof(buf));
    /* expect "1.5K" */
    ASSERT(buf[0] == '1');
    ASSERT(buf[strlen(buf) - 1] == 'K');
}

void test_bw_fmt_rate_mega(void) {
    char buf[16];
    bw_fmt_rate(2.5e6, buf, sizeof(buf));
    ASSERT(buf[strlen(buf) - 1] == 'M');
}

void test_bw_multiple_conns_independent(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    make_conn(&s.conns[0], "192.168.0.1", 1111, "8.8.8.8",   53,  PROTO_UDP);
    make_conn(&s.conns[1], "192.168.0.1", 2222, "1.1.1.1",   443, PROTO_TCP);
    make_conn(&s.conns[2], "192.168.0.1", 3333, "9.9.9.9",   80,  PROTO_TCP);
    s.conn_count = 3;

    bw_update(&s);
    ASSERT_EQ(s.conn_bw_count, 3);

    const conn_bw_t *b0 = bw_lookup(&s, &s.conns[0]);
    const conn_bw_t *b1 = bw_lookup(&s, &s.conns[1]);
    const conn_bw_t *b2 = bw_lookup(&s, &s.conns[2]);
    ASSERT(b0 != NULL);
    ASSERT(b1 != NULL);
    ASSERT(b2 != NULL);
    /* they are separate entries */
    ASSERT(b0 != b1);
    ASSERT(b1 != b2);
}

/* ── Packet attribution tests (pcap ring, no WITH_PCAP needed) ── */

void test_bw_cursor_advances(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    packet_info_t p;
    make_pkt(&p, "10.0.0.1", 5000, "8.8.8.8", 53, PROTO_UDP, 100);
    push_pkt(&s, &p);

    make_conn(&s.conns[0], "10.0.0.1", 5000, "8.8.8.8", 53, PROTO_UDP);
    s.conn_count = 1;

    bw_update(&s);
    /* cursor should advance to current pkt_head */
    ASSERT_EQ(s.pkt_bw_cursor, s.pkt_head);
}

void test_bw_no_double_count(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    bw_reset();

    packet_info_t p;
    make_pkt(&p, "10.0.0.1", 5000, "8.8.8.8", 53, PROTO_UDP, 200);
    push_pkt(&s, &p);

    make_conn(&s.conns[0], "10.0.0.1", 5000, "8.8.8.8", 53, PROTO_UDP);
    s.conn_count = 1;

    bw_update(&s);
    int cursor_after_first = s.pkt_bw_cursor;

    /* second update — no new packets */
    bw_update(&s);
    ASSERT_EQ(s.pkt_bw_cursor, cursor_after_first);  /* cursor unchanged */
}

void run_bw_tests(void) {
    TEST_SUITE("bandwidth/basic");
    RUN_TEST(test_bw_empty);
    RUN_TEST(test_bw_new_conn_zero_rate);
    RUN_TEST(test_bw_lookup_found);
    RUN_TEST(test_bw_lookup_not_found);
    RUN_TEST(test_bw_conn_evicted_when_gone);
    RUN_TEST(test_bw_identity_preserved_across_polls);
    RUN_TEST(test_bw_multiple_conns_independent);

    TEST_SUITE("bandwidth/sparkline");
    RUN_TEST(test_bw_sparkline_fills);
    RUN_TEST(test_bw_sparkline_caps_at_hist_len);

    TEST_SUITE("bandwidth/fmt_rate");
    RUN_TEST(test_bw_fmt_rate_dash_for_zero);
    RUN_TEST(test_bw_fmt_rate_bytes);
    RUN_TEST(test_bw_fmt_rate_kilo);
    RUN_TEST(test_bw_fmt_rate_mega);

    TEST_SUITE("bandwidth/cursor");
    RUN_TEST(test_bw_cursor_advances);
    RUN_TEST(test_bw_no_double_count);
}
