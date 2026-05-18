#include <string.h>
#include "runner.h"
#include "sloth.h"
#include "top_hosts.h"
#include "dns.h"

static void seed_conn(sloth_state_t *s, const char *remote, uint16_t rport) {
    if (s->conn_count >= MAX_CONNS) return;
    conn_t *c = &s->conns[s->conn_count++];
    memset(c, 0, sizeof(*c));
    snprintf(c->local_addr,  sizeof(c->local_addr),  "192.168.1.5");
    snprintf(c->remote_addr, sizeof(c->remote_addr), "%s", remote);
    c->remote_port = rport;
    c->proto       = PROTO_TCP;
}

static void seed_bw(sloth_state_t *s, const char *remote, uint16_t rport,
                    double rx, double tx) {
    if (s->conn_bw_count >= MAX_CONNS) return;
    conn_bw_t *b = &s->conn_bw[s->conn_bw_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->local_addr,  sizeof(b->local_addr),  "192.168.1.5");
    snprintf(b->remote_addr, sizeof(b->remote_addr), "%s", remote);
    b->remote_port = rport;
    b->proto       = PROTO_TCP;
    b->rx_rate     = rx;
    b->tx_rate     = tx;
}

static int find_host(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->top_host_count; i++)
        if (strcmp(s->top_hosts[i].ip, ip) == 0) return i;
    return -1;
}

/* ── Aggregation ─────────────────────────────────────────── */

static void test_empty_state_yields_zero(void) {
    top_hosts_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    top_hosts_update(&s);
    ASSERT_EQ(s.top_host_count, 0);
}

static void test_single_remote_creates_entry(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 443);
    top_hosts_update(&s);
    ASSERT_EQ(s.top_host_count, 1);
    int idx = find_host(&s, "8.8.8.8");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.top_hosts[idx].conn_count, 1);
}

static void test_private_address_skipped(void) {
    top_hosts_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "192.168.1.100", 443);
    seed_conn(&s, "10.0.0.5",      80);
    seed_conn(&s, "127.0.0.1",     22);
    top_hosts_update(&s);
    ASSERT_EQ(s.top_host_count, 0);
}

static void test_multiconn_aggregates(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 443);
    seed_conn(&s, "8.8.8.8", 80);
    seed_conn(&s, "8.8.8.8", 8080);
    top_hosts_update(&s);
    int idx = find_host(&s, "8.8.8.8");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.top_hosts[idx].conn_count, 3);
}

static void test_bw_summed_per_ip(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "1.1.1.1", 443);
    seed_bw  (&s, "1.1.1.1", 443, 1000.0, 500.0);
    seed_bw  (&s, "1.1.1.1", 80,  2000.0, 750.0);   /* second flow same IP */
    top_hosts_update(&s);
    int idx = find_host(&s, "1.1.1.1");
    ASSERT(idx >= 0);
    ASSERT_NEAR(s.top_hosts[idx].rx_rate, 3000.0, 1.0);
    ASSERT_NEAR(s.top_hosts[idx].tx_rate, 1250.0, 1.0);
}

static void test_first_seen_persists_across_polls(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 443);
    top_hosts_update(&s);
    int idx1 = find_host(&s, "8.8.8.8");
    ASSERT(idx1 >= 0);
    time_t fs1 = s.top_hosts[idx1].first_seen;
    ASSERT(fs1 > 0);

    /* Second update with a fresh state object — module's internal table
     * survives, first_seen should be unchanged. */
    sloth_state_t s2; memset(&s2, 0, sizeof(s2));
    seed_conn(&s2, "8.8.8.8", 443);
    top_hosts_update(&s2);
    int idx2 = find_host(&s2, "8.8.8.8");
    ASSERT(idx2 >= 0);
    ASSERT_EQ((int)s2.top_hosts[idx2].first_seen, (int)fs1);
}

static void test_owner_resolved_for_known_prefix(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 53);    /* Google DNS — embedded prefix */
    top_hosts_update(&s);
    int idx = find_host(&s, "8.8.8.8");
    ASSERT(idx >= 0);
    ASSERT_STR(s.top_hosts[idx].owner, "Google DNS");
}

static void test_owner_unknown_left_blank(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    /* Routable EU /8 address that's not in our embedded owner table */
    seed_conn(&s, "80.10.20.30", 443);
    top_hosts_update(&s);
    int idx = find_host(&s, "80.10.20.30");
    ASSERT(idx >= 0);
    ASSERT_EQ((int)s.top_hosts[idx].owner[0], 0);
}

static void test_hostname_picked_up_when_cached(void) {
    top_hosts_clear();
    dns_reset();
    dns_set_resolved("8.8.8.8", "dns.google");
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 53);
    top_hosts_update(&s);
    int idx = find_host(&s, "8.8.8.8");
    ASSERT(idx >= 0);
    ASSERT_STR(s.top_hosts[idx].hostname, "dns.google");
}

/* ── Sorting ─────────────────────────────────────────────── */

static void test_top_entries_sorted_by_activity(void) {
    top_hosts_clear();
    dns_reset();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_conn(&s, "8.8.8.8", 443);
    seed_conn(&s, "1.1.1.1", 443);
    seed_bw  (&s, "8.8.8.8", 443,  500.0,  200.0);
    seed_bw  (&s, "1.1.1.1", 443, 5000.0, 2500.0);  /* much higher */
    top_hosts_update(&s);
    /* 1.1.1.1 should land first */
    ASSERT_STR(s.top_hosts[0].ip, "1.1.1.1");
    ASSERT_STR(s.top_hosts[1].ip, "8.8.8.8");
}

void run_top_hosts_tests(void) {
    TEST_SUITE("top_hosts aggregation");
    RUN_TEST(test_empty_state_yields_zero);
    RUN_TEST(test_single_remote_creates_entry);
    RUN_TEST(test_private_address_skipped);
    RUN_TEST(test_multiconn_aggregates);
    RUN_TEST(test_bw_summed_per_ip);
    RUN_TEST(test_first_seen_persists_across_polls);

    TEST_SUITE("top_hosts resolution");
    RUN_TEST(test_owner_resolved_for_known_prefix);
    RUN_TEST(test_owner_unknown_left_blank);
    RUN_TEST(test_hostname_picked_up_when_cached);

    TEST_SUITE("top_hosts sorting");
    RUN_TEST(test_top_entries_sorted_by_activity);
}
