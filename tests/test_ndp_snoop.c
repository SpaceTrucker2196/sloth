#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "ndp_snoop.h"

/* RFC 4861 §4.2 Router Advertisement layout, plus §4.6 options.
 * We build raw byte arrays by hand and feed them to ndp_snoop_ra,
 * never letting the snooper consume anything it produced itself. */

/* ── Helpers ──────────────────────────────────────────────── */

static void ra_header(uint8_t *buf, uint8_t cur_hop, uint8_t flags,
                       uint16_t lifetime) {
    buf[0]  = 134;                  /* type = Router Advertisement */
    buf[1]  = 0;                    /* code */
    buf[2]  = 0; buf[3]  = 0;       /* checksum (parser ignores) */
    buf[4]  = cur_hop;
    buf[5]  = flags;
    buf[6]  = (uint8_t)(lifetime >> 8);
    buf[7]  = (uint8_t)(lifetime & 0xff);
    memset(buf + 8, 0, 8);          /* reachable + retrans, unused here */
}

/* Append a Source Link-Layer Address option. RFC 4861 §4.6.1:
 *   type=1, len=1 (8-byte unit), [6-byte MAC]. */
static int append_slla(uint8_t *buf, int off, const uint8_t mac[6]) {
    buf[off + 0] = 1;
    buf[off + 1] = 1;
    memcpy(buf + off + 2, mac, 6);
    return off + 8;
}

/* Append a Prefix Information Option. RFC 4861 §4.6.2:
 *   type=3, len=4 (=32 bytes), prefix_len, flags, valid, preferred,
 *   reserved, prefix(16). */
static int append_pio(uint8_t *buf, int off, uint8_t prefix_len,
                       const uint8_t prefix[16]) {
    buf[off + 0] = 3;
    buf[off + 1] = 4;
    buf[off + 2] = prefix_len;
    buf[off + 3] = 0xc0;            /* L=1, A=1 typical RA flags */
    memset(buf + off + 4, 0, 12);
    memcpy(buf + off + 16, prefix, 16);
    return off + 32;
}

static int find_ra(const sloth_state_t *s, const char *ip) {
    for (int i = 0; i < s->ndp_ra_count; i++)
        if (strcmp(s->ndp_ras[i].src_ip, ip) == 0) return i;
    return -1;
}

/* ── Tests ────────────────────────────────────────────────── */

/* Minimal RA — header only, no options. Tracker should record the
 * router with the advertised lifetime and zero prefixes. */
static void test_minimal_ra_recorded(void) {
    ndp_snoop_clear();
    uint8_t buf[16];
    ra_header(buf, 64, 0x00, 1800);
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, sizeof(buf)), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    ASSERT_EQ(s.ndp_ra_count, 1);
    int idx = find_ra(&s, "fe80::1");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.ndp_ras[idx].cur_hop_limit,   64);
    ASSERT_EQ(s.ndp_ras[idx].router_lifetime, 1800);
    ASSERT_EQ(s.ndp_ras[idx].prefix_count,    0);
    ASSERT_EQ(s.ndp_ras[idx].has_src_mac,     0);
    ASSERT_EQ(s.ndp_ras[idx].count,           1);
}

/* RA with the Source Link-Layer Address option — the parser must
 * extract the MAC and set has_src_mac = 1. */
static void test_ra_with_slla_extracts_mac(void) {
    ndp_snoop_clear();
    uint8_t buf[24];
    ra_header(buf, 64, 0x00, 1800);
    uint8_t mac[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    int off = append_slla(buf, 16, mac);
    ASSERT_EQ(off, 24);
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, off), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    int idx = find_ra(&s, "fe80::1");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.ndp_ras[idx].has_src_mac, 1);
    ASSERT(memcmp(s.ndp_ras[idx].src_mac, mac, 6) == 0);
}

/* RA carrying a Prefix Information Option — the formatted prefix
 * string should appear in prefixes[0]. */
static void test_ra_with_pio_formats_prefix(void) {
    ndp_snoop_clear();
    uint8_t buf[16 + 32];
    ra_header(buf, 64, 0x00, 1800);
    uint8_t prefix[16] = {
        0x20,0x01,0x0d,0xb8,0,0,0,0,
        0,0,0,0,0,0,0,0,
    };
    int off = append_pio(buf, 16, 64, prefix);
    ASSERT_EQ(off, 48);
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, off), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    int idx = find_ra(&s, "fe80::1");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.ndp_ras[idx].prefix_count, 1);
    /* Lowercase, RFC-5952 short form. */
    ASSERT(strcmp(s.ndp_ras[idx].prefixes[0], "2001:db8::/64") == 0);
}

/* Two distinct routers — both tracked, counted separately. */
static void test_two_routers_tracked_independently(void) {
    ndp_snoop_clear();
    uint8_t buf[16];
    ra_header(buf, 64, 0x00, 1800);
    ndp_snoop_ra("fe80::1", buf, sizeof(buf));
    ndp_snoop_ra("fe80::2", buf, sizeof(buf));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    ASSERT_EQ(s.ndp_ra_count, 2);
    ASSERT(find_ra(&s, "fe80::1") >= 0);
    ASSERT(find_ra(&s, "fe80::2") >= 0);
}

/* Repeated RAs from the same router update count + last_seen
 * without inflating ndp_ra_count. */
static void test_repeated_ra_increments_count(void) {
    ndp_snoop_clear();
    uint8_t buf[16];
    ra_header(buf, 64, 0x00, 1800);
    for (int i = 0; i < 5; i++) ndp_snoop_ra("fe80::1", buf, sizeof(buf));

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    ASSERT_EQ(s.ndp_ra_count, 1);
    int idx = find_ra(&s, "fe80::1");
    ASSERT_EQ(s.ndp_ras[idx].count, 5);
}

/* router_lifetime == 0 means "I'm an RA-emitter but NOT a default
 * router". The tracker still records it (the rogue-RA rule does
 * the lifetime filtering) but lifetime is preserved as zero. */
static void test_zero_lifetime_recorded_as_zero(void) {
    ndp_snoop_clear();
    uint8_t buf[16];
    ra_header(buf, 64, 0x00, 0);
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, sizeof(buf)), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    int idx = find_ra(&s, "fe80::1");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.ndp_ras[idx].router_lifetime, 0);
}

/* ── Negative cases ───────────────────────────────────────── */

static void test_non_ra_icmpv6_rejected(void) {
    ndp_snoop_clear();
    uint8_t buf[16];
    memset(buf, 0, sizeof(buf));
    buf[0] = 135;   /* Neighbor Solicitation, not RA */
    buf[1] = 0;
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, sizeof(buf)), 0);
}

static void test_truncated_payload_rejected(void) {
    ndp_snoop_clear();
    uint8_t buf[12];
    memset(buf, 0, sizeof(buf));
    buf[0] = 134;
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, sizeof(buf)), 0);
}

/* Option with len=0 must terminate the walk rather than loop
 * forever. RFC 4861 §4.6 says implementations SHOULD ignore
 * options with length zero — we treat it as end-of-options. */
static void test_zero_length_option_terminates_walk(void) {
    ndp_snoop_clear();
    uint8_t buf[24];
    ra_header(buf, 64, 0x00, 1800);
    buf[16] = 99;       /* unrecognised type */
    buf[17] = 0;        /* len = 0 — must NOT loop */
    memset(buf + 18, 0, 6);
    ASSERT_EQ(ndp_snoop_ra("fe80::1", buf, sizeof(buf)), 1);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    ndp_snoop_snapshot(&s);
    int idx = find_ra(&s, "fe80::1");
    ASSERT(idx >= 0);
    ASSERT_EQ(s.ndp_ras[idx].prefix_count, 0);
}

/* ── Suite ────────────────────────────────────────────────── */

void run_ndp_snoop_tests(void) {
    TEST_SUITE("ndp_snoop: parse + track");
    RUN_TEST(test_minimal_ra_recorded);
    RUN_TEST(test_ra_with_slla_extracts_mac);
    RUN_TEST(test_ra_with_pio_formats_prefix);
    RUN_TEST(test_two_routers_tracked_independently);
    RUN_TEST(test_repeated_ra_increments_count);
    RUN_TEST(test_zero_lifetime_recorded_as_zero);

    TEST_SUITE("ndp_snoop: negative cases");
    RUN_TEST(test_non_ra_icmpv6_rejected);
    RUN_TEST(test_truncated_payload_rejected);
    RUN_TEST(test_zero_length_option_terminates_walk);
}
