#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "dns_wire.h"

/* RFC 1035 §3.1 / §4.1.4 name decoding (#131). Messages are built by
 * hand: a 12-octet header the reader never looks at, then names. The
 * reader takes an offset, so the header is padding here — it is kept so
 * pointer targets carry the offsets they would in a real message. */

static const uint8_t hdr12[12] = { 0x12,0x34, 0x01,0x00, 0x00,0x01,
                                   0x00,0x00, 0x00,0x00, 0x00,0x00 };

/* "www.example.org" uncompressed at 12 (17 octets: 3 www 7 example
 * 3 org 0), then at 29 a second name "mail" + a pointer to 16
 * ("example.org"), then two octets of trailing data the resume offset
 * must land on. */
static int build_two_names(uint8_t *m) {
    int o;
    memcpy(m, hdr12, 12); o = 12;
    static const uint8_t n1[] = { 3,'w','w','w', 7,'e','x','a','m','p','l','e',
                                  3,'o','r','g', 0 };
    memcpy(m + o, n1, sizeof n1); o += (int)sizeof n1;     /* o = 29 */
    static const uint8_t n2[] = { 4,'m','a','i','l', 0xC0, 16 };
    memcpy(m + o, n2, sizeof n2); o += (int)sizeof n2;     /* o = 36 */
    m[o++] = 0xAA; m[o++] = 0xBB;
    return o;
}

static void test_read_plain_name(void) {
    uint8_t m[64]; int n = build_two_names(m);
    char buf[64];
    ASSERT_EQ(dns_read_name(m, n, 12, buf, sizeof buf), 29);
    ASSERT_STR(buf, "www.example.org");
}

/* The resume offset is the octet after the *first* pointer, not after
 * the name the pointer led to: the record continues from there. */
static void test_read_compressed_name_resumes_after_pointer(void) {
    uint8_t m[64]; int n = build_two_names(m);
    char buf[64];
    ASSERT_EQ(dns_read_name(m, n, 29, buf, sizeof buf), 36);
    ASSERT_STR(buf, "mail.example.org");
    ASSERT_EQ(m[36], 0xAA);
}

static void test_read_root_name_is_empty(void) {
    uint8_t m[13]; memcpy(m, hdr12, 12); m[12] = 0;
    char buf[8] = "junk";
    ASSERT_EQ(dns_read_name(m, 13, 12, buf, sizeof buf), 13);
    ASSERT_STR(buf, "");
}

/* `C0 0C` at offset 12 points at itself. Only the hop bound ends it. */
static void test_read_self_pointer_loop_rejected(void) {
    uint8_t m[14]; memcpy(m, hdr12, 12); m[12] = 0xC0; m[13] = 0x0C;
    char buf[64];
    ASSERT_EQ(dns_read_name(m, 14, 12, buf, sizeof buf), -1);
}

/* A chain of `hops` pointers from 12, each to the next pair, ending at
 * the label "x". Built per pointer, so the two edges differ by exactly
 * one pointer and nothing else. */
static int build_chain(uint8_t *m, int hops) {
    memcpy(m, hdr12, 12);
    int o = 12;
    for (int k = 0; k < hops; k++) {
        int target = 12 + 2 * (k + 1);
        m[o++] = (uint8_t)(0xC0 | (target >> 8));
        m[o++] = (uint8_t)(target & 0xFF);
    }
    m[o++] = 1; m[o++] = 'x'; m[o++] = 0;
    return o;
}

/* Both edges of the bound, asserted separately and written as literals
 * so that moving DNS_NAME_MAX_HOPS reddens behaviour, not a constant
 * pin: `>` -> `>=` reddens the first, the bound raised by one reddens
 * the second. 20 pointers followed is accepted, the 21st refused. */
static void test_read_chain_at_hop_limit_accepted(void) {
    uint8_t m[128]; int n = build_chain(m, 20);
    char buf[16];
    ASSERT_EQ(dns_read_name(m, n, 12, buf, sizeof buf), 14);
    ASSERT_STR(buf, "x");
}

static void test_read_chain_one_past_hop_limit_rejected(void) {
    uint8_t m[128]; int n = build_chain(m, 21);
    char buf[16] = "untouched";
    ASSERT_EQ(dns_read_name(m, n, 12, buf, sizeof buf), -1);
}

/* Label types 01 and 10 are reserved (RFC 1035 §4.1.4; 01 was EDNS0's
 * extended label, withdrawn by RFC 6891). A length octet of 0x40 is not
 * a 64-octet label — labels stop at 63 (§2.3.4). The readers this one
 * replaced refused only 10, so 0x40..0x7F read as lengths 64..127. */
static void test_read_reserved_label_types_rejected(void) {
    uint8_t m[200]; memcpy(m, hdr12, 12);
    memset(m + 12, 'a', sizeof m - 12);
    m[12] = 0x40;               /* 01 000000 */
    m[12 + 65] = 0;
    char buf[256];
    ASSERT_EQ(dns_read_name(m, (int)sizeof m, 12, buf, sizeof buf), -1);
    m[12] = 0x80;               /* 10 000000 */
    ASSERT_EQ(dns_read_name(m, (int)sizeof m, 12, buf, sizeof buf), -1);
    m[12] = 0x3F;               /* 63: the longest legal label */
    m[12 + 64] = 0;
    ASSERT_EQ(dns_read_name(m, (int)sizeof m, 12, buf, sizeof buf), 12 + 65);
    ASSERT_EQ((int)strlen(buf), 63);
}

static void test_read_label_past_end_rejected(void) {
    uint8_t m[64]; int n = build_two_names(m);
    char buf[64];
    /* "www.example.org" needs 17 octets from 12; give it 16. */
    ASSERT_EQ(dns_read_name(m, 28, 12, buf, sizeof buf), -1);
    ASSERT_EQ(dns_read_name(m, n, n, buf, sizeof buf), -1);   /* off == len */
    ASSERT_EQ(dns_read_name(m, n, -1, buf, sizeof buf), -1);
}

/* A pointer's first octet as the message's last: no second octet. */
static void test_read_truncated_pointer_rejected(void) {
    uint8_t m[13]; memcpy(m, hdr12, 12); m[12] = 0xC0;
    char buf[16];
    ASSERT_EQ(dns_read_name(m, 13, 12, buf, sizeof buf), -1);
}

static void test_read_pointer_past_end_rejected(void) {
    uint8_t m[14]; memcpy(m, hdr12, 12); m[12] = 0xC0; m[13] = 0x40;
    char buf[16];
    ASSERT_EQ(dns_read_name(m, 14, 12, buf, sizeof buf), -1);
}

/* A name longer than the buffer is truncated, terminated, and the
 * resume offset is still the wire one. */
static void test_read_truncates_into_small_buffer(void) {
    uint8_t m[64]; int n = build_two_names(m);
    char buf[6];
    ASSERT_EQ(dns_read_name(m, n, 12, buf, sizeof buf), 29);
    ASSERT_STR(buf, "www.e");
    char one[1] = { 'z' };
    ASSERT_EQ(dns_read_name(m, n, 12, one, 1), 29);
    ASSERT_EQ(one[0], '\0');
}

/* The reader copies label octets raw; marking belongs to the store that
 * keeps the name (#138) — see test_dns_snoop and test_mdns_snoop. */
static void test_read_copies_octets_raw(void) {
    uint8_t m[20]; memcpy(m, hdr12, 12);
    m[12] = 3; m[13] = 'a'; m[14] = 0x1b; m[15] = 'c'; m[16] = 0;
    char buf[16];
    ASSERT_EQ(dns_read_name(m, 17, 12, buf, sizeof buf), 17);
    ASSERT_EQ((uint8_t)buf[1], 0x1b);
}

static void test_read_rejects_bad_arguments(void) {
    uint8_t m[64]; int n = build_two_names(m);
    char buf[8] = "junk";
    ASSERT_EQ(dns_read_name(m, n, 12, buf, 0), -1);
    ASSERT_EQ(dns_read_name(m, n, 12, NULL, 8), -1);
    ASSERT_EQ(dns_read_name(NULL, n, 12, buf, sizeof buf), -1);
    ASSERT_STR(buf, "");
}

/* ── dns_skip_name ─────────────────────────────────────────── */

static void test_skip_agrees_with_read(void) {
    uint8_t m[64]; int n = build_two_names(m);
    ASSERT_EQ(dns_skip_name(m, n, 12), 29);
    ASSERT_EQ(dns_skip_name(m, n, 29), 36);
}

/* A skip stops at the pointer and does not follow it, so the
 * self-pointer that dns_read_name refuses is two octets to a skip. */
static void test_skip_does_not_follow_pointer(void) {
    uint8_t m[14]; memcpy(m, hdr12, 12); m[12] = 0xC0; m[13] = 0x0C;
    ASSERT_EQ(dns_skip_name(m, 14, 12), 14);
    ASSERT_EQ(dns_skip_name(m, 13, 12), -1);     /* pointer cut in half */
}

static void test_skip_rejects_reserved_and_overrun(void) {
    uint8_t m[200]; memcpy(m, hdr12, 12);
    memset(m + 12, 'a', sizeof m - 12);
    m[12] = 0x40; m[12 + 65] = 0;
    ASSERT_EQ(dns_skip_name(m, (int)sizeof m, 12), -1);
    m[12] = 0x80;
    ASSERT_EQ(dns_skip_name(m, (int)sizeof m, 12), -1);
    m[12] = 5; m[13] = 'a';
    ASSERT_EQ(dns_skip_name(m, 14, 12), -1);     /* label runs past end */
    ASSERT_EQ(dns_skip_name(m, 12, 12), -1);     /* nothing there */
    ASSERT_EQ(dns_skip_name(NULL, 12, 0), -1);
}

void run_dns_wire_tests(void) {
    TEST_SUITE("dns_wire read_name");
    RUN_TEST(test_read_plain_name);
    RUN_TEST(test_read_compressed_name_resumes_after_pointer);
    RUN_TEST(test_read_root_name_is_empty);
    RUN_TEST(test_read_self_pointer_loop_rejected);
    RUN_TEST(test_read_chain_at_hop_limit_accepted);
    RUN_TEST(test_read_chain_one_past_hop_limit_rejected);
    RUN_TEST(test_read_reserved_label_types_rejected);
    RUN_TEST(test_read_label_past_end_rejected);
    RUN_TEST(test_read_truncated_pointer_rejected);
    RUN_TEST(test_read_pointer_past_end_rejected);
    RUN_TEST(test_read_truncates_into_small_buffer);
    RUN_TEST(test_read_copies_octets_raw);
    RUN_TEST(test_read_rejects_bad_arguments);

    TEST_SUITE("dns_wire skip_name");
    RUN_TEST(test_skip_agrees_with_read);
    RUN_TEST(test_skip_does_not_follow_pointer);
    RUN_TEST(test_skip_rejects_reserved_and_overrun);
}
