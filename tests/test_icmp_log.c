#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "icmp_log.h"
#include "views/icmp.h"

/* Hand-crafted ICMP messages (header only — payload not needed for parsing).
 *
 * ICMP header (8 bytes for Echo):
 *   0    1    2 3       4 5       6 7
 *  type code checksum    id        seq
 */

static void build_icmp4_echo(uint8_t *buf, uint8_t type,
                              uint16_t id, uint16_t seq) {
    memset(buf, 0, 8);
    buf[0] = type;
    buf[1] = 0;
    /* checksum bytes 2..3 left zero — parser does not validate */
    buf[4] = (uint8_t)(id  >> 8);
    buf[5] = (uint8_t)(id  & 0xFF);
    buf[6] = (uint8_t)(seq >> 8);
    buf[7] = (uint8_t)(seq & 0xFF);
}

static void build_icmp4_unreach(uint8_t *buf, uint8_t code) {
    memset(buf, 0, 8);
    buf[0] = 3;       /* dest unreachable */
    buf[1] = code;
}

/* ── payload_len (ICMP-tunnel signal, #40) ───────────────── */

static void test_payload_len_echo(void) {
    /* 8-byte header + 100-byte payload → payload_len 100. */
    uint8_t pkt[108];
    memset(pkt, 0, sizeof(pkt));
    build_icmp4_echo(pkt, 8, 0x1, 1);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
    ASSERT_EQ((int)e.payload_len, 100);
}

static void test_payload_len_header_only(void) {
    /* Bare 8-byte echo → no payload. */
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 8, 0x1, 1);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
    ASSERT_EQ((int)e.payload_len, 0);
}

static void test_payload_len_v6_echo(void) {
    uint8_t pkt[8 + 200];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 128;  /* v6 echo request */
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "fe80::1", "fe80::2", 1, &e));
    ASSERT_EQ((int)e.payload_len, 200);
}

/* ── ICMPv4 parse ────────────────────────────────────────── */

static void test_v4_echo_request(void) {
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 8, 0x1234, 42);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "192.168.1.5", "8.8.8.8", 0, &e));
    ASSERT_EQ((int)e.type, 8);
    ASSERT_EQ((int)e.seq, 42);
    ASSERT_EQ((int)e.is_v6, 0);
    ASSERT_STR(e.desc, "Echo Req");
    ASSERT_STR(e.src, "192.168.1.5");
    ASSERT_STR(e.dst, "8.8.8.8");
}

static void test_v4_echo_reply(void) {
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 0, 0xABCD, 100);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "8.8.8.8", "192.168.1.5", 0, &e));
    ASSERT_EQ((int)e.type, 0);
    ASSERT_EQ((int)e.seq, 100);
    ASSERT_STR(e.desc, "Echo Reply");
}

static void test_v4_dest_unreachable_codes(void) {
    uint8_t pkt[8];
    build_icmp4_unreach(pkt, 1);  /* host unreachable */
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
    ASSERT_STR(e.desc, "Unreachable");
    ASSERT_EQ((int)e.code, 1);
    /* Seq not meaningful for non-echo */
    ASSERT_EQ((int)e.seq, 0);
}

static void test_v4_ttl_exceeded(void) {
    uint8_t pkt[8] = {0};
    pkt[0] = 11;
    pkt[1] = 0;
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "1.1.1.1", "1.2.3.4", 0, &e));
    ASSERT_STR(e.desc, "TTL Exceeded");
}

static void test_v4_unknown_type(void) {
    uint8_t pkt[8] = {0};
    pkt[0] = 200;
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
    ASSERT_STR(e.desc, "ICMP");
}

/* ── ICMPv6 parse ────────────────────────────────────────── */

static void test_v6_echo_request(void) {
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 128, 0x4242, 7);  /* same wire layout */
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "fe80::1", "fe80::2", 1, &e));
    ASSERT_EQ((int)e.type, 128);
    ASSERT_EQ((int)e.seq, 7);
    ASSERT_EQ((int)e.is_v6, 1);
    ASSERT_STR(e.desc, "Echo Req");
}

static void test_v6_neighbor_solicit(void) {
    uint8_t pkt[8] = {0};
    pkt[0] = 135;
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 1, &e));
    ASSERT_STR(e.desc, "Neigh Sol");
}

static void test_v6_router_adv(void) {
    uint8_t pkt[8] = {0};
    pkt[0] = 134;
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 1, &e));
    ASSERT_STR(e.desc, "Router Adv");
}

static void test_v6_unknown_type(void) {
    uint8_t pkt[8] = {0};
    pkt[0] = 250;
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 1, &e));
    ASSERT_STR(e.desc, "ICMPv6");
}

/* ── rejection ───────────────────────────────────────────── */

static void test_parse_rejects_short(void) {
    uint8_t pkt[2] = { 8, 0 };
    icmp_log_entry_t e;
    ASSERT(!icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
}

static void test_parse_null_ips_ok(void) {
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 8, 1, 1);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), NULL, NULL, 0, &e));
    ASSERT_EQ((int)e.src[0], 0);
}

/* ── ring buffer ─────────────────────────────────────────── */

static void test_record_and_snapshot(void) {
    icmp_log_clear();
    uint8_t pkt[8];
    for (int i = 0; i < 4; i++) {
        build_icmp4_echo(pkt, 8, 1, (uint16_t)(i + 1));
        icmp_log_entry_t e;
        ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
        icmp_log_record(&e);
    }
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    icmp_log_snapshot(&s);
    ASSERT_EQ(s.icmp_log_count, 4);
    ASSERT_EQ((int)s.icmp_log[0].seq, 4);  /* newest */
    ASSERT_EQ((int)s.icmp_log[3].seq, 1);  /* oldest */
}

static void test_clear_empties(void) {
    icmp_log_clear();
    uint8_t pkt[8];
    build_icmp4_echo(pkt, 8, 1, 1);
    icmp_log_entry_t e;
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
    icmp_log_record(&e);

    icmp_log_clear();
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    icmp_log_snapshot(&s);
    ASSERT_EQ(s.icmp_log_count, 0);
}

/* ── view ────────────────────────────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    view_icmp_draw(&s);
    ASSERT(1);
}

static void test_view_draw_populated(void) {
    icmp_log_clear();
    uint8_t pkt[8];
    icmp_log_entry_t e;

    /* echo request, echo reply, unreachable, v6 neighbor solicit */
    build_icmp4_echo(pkt, 8, 1, 1);
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "192.168.1.5", "8.8.8.8", 0, &e));
    icmp_log_record(&e);

    build_icmp4_echo(pkt, 0, 1, 1);
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "8.8.8.8", "192.168.1.5", 0, &e));
    icmp_log_record(&e);

    build_icmp4_unreach(pkt, 3); /* port unreachable */
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "10.0.0.1", "192.168.1.5", 0, &e));
    icmp_log_record(&e);

    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 135;  /* neighbor solicitation */
    ASSERT(icmp_log_parse(pkt, sizeof(pkt), "fe80::1", "fe80::2", 1, &e));
    icmp_log_record(&e);

    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    icmp_log_snapshot(&s);
    ASSERT_EQ(s.icmp_log_count, 4);
    view_icmp_draw(&s);
}

static void test_view_key_nav_and_clear(void) {
    icmp_log_clear();
    uint8_t pkt[8];
    for (int i = 0; i < 3; i++) {
        build_icmp4_echo(pkt, 8, 1, (uint16_t)(i + 1));
        icmp_log_entry_t e;
        ASSERT(icmp_log_parse(pkt, sizeof(pkt), "a", "b", 0, &e));
        icmp_log_record(&e);
    }
    sloth_state_t s;
    memset(&s, 0, sizeof(s));
    icmp_log_snapshot(&s);
    ASSERT_EQ(s.icmp_log_sel, 0);
    view_icmp_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.icmp_log_sel, 1);
    view_icmp_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.icmp_log_sel, 0);

    view_icmp_key(&s, 'c');
    ASSERT_EQ(s.icmp_log_count, 0);
}

void run_icmp_log_tests(void) {
    TEST_SUITE("icmp_log v4 parse");
    RUN_TEST(test_v4_echo_request);
    RUN_TEST(test_v4_echo_reply);
    RUN_TEST(test_v4_dest_unreachable_codes);
    RUN_TEST(test_v4_ttl_exceeded);
    RUN_TEST(test_v4_unknown_type);

    TEST_SUITE("icmp_log v6 parse");
    RUN_TEST(test_v6_echo_request);
    RUN_TEST(test_v6_neighbor_solicit);
    RUN_TEST(test_v6_router_adv);
    RUN_TEST(test_v6_unknown_type);

    TEST_SUITE("icmp_log rejection");
    RUN_TEST(test_parse_rejects_short);
    RUN_TEST(test_parse_null_ips_ok);

    TEST_SUITE("icmp_log payload_len (#40)");
    RUN_TEST(test_payload_len_echo);
    RUN_TEST(test_payload_len_header_only);
    RUN_TEST(test_payload_len_v6_echo);

    TEST_SUITE("icmp_log ring buffer");
    RUN_TEST(test_record_and_snapshot);
    RUN_TEST(test_clear_empties);

    TEST_SUITE("view_icmp draw");
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_populated);

    TEST_SUITE("view_icmp key");
    RUN_TEST(test_view_key_nav_and_clear);
}
