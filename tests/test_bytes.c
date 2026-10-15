#include <stdint.h>
#include <string.h>
#include "runner.h"
#include "bytes.h"

/* ── src/bytes.h — the one bounded reader and TLV iterator (#126) ──
 *
 * Every 802.11 element walk in sloth now runs through tlv_next(), so the
 * edge cases below are the edge cases of all of them at once: a body
 * that fits to the last octet, a body one octet too long, a header with
 * no room for its length octet. Inputs are hand-built per the element
 * framing of IEEE 802.11-2020 §9.4.2.1 (Element ID, Length, body) and,
 * for the 2+2 form, the WPS attribute framing of the Wi-Fi Simple
 * Configuration Technical Specification (2-octet Type, 2-octet Length,
 * both big-endian). */

static void test_fixed_width_loads(void) {
    static const uint8_t b[8] = { 0x01, 0x02, 0x03, 0x04,
                                  0x05, 0x06, 0x07, 0x08 };
    ASSERT_EQ(be16(b), 0x0102);
    ASSERT_EQ(le16(b), 0x0201);
    ASSERT_EQ(be32(b), 0x01020304u);
    ASSERT_EQ(le32(b), 0x04030201u);
    ASSERT(le48(b) == 0x060504030201ull);
    /* High bit set: a sign-extension slip in any helper shows here. */
    static const uint8_t h[6] = { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa };
    ASSERT_EQ(be16(h), 0xfffe);
    ASSERT_EQ(le16(h), 0xfeff);
    ASSERT_EQ(be32(h), 0xfffefdfcu);
    ASSERT_EQ(le32(h), 0xfcfdfeffu);
    ASSERT(le48(h) == 0xfafbfcfdfeffull);
}

static void test_reader_reads_in_order(void) {
    static const uint8_t b[] = { 0xaa, 0x34, 0x12, 0x12, 0x34,
                                 0x78, 0x56, 0x34, 0x12,
                                 0x12, 0x34, 0x56, 0x78, 0xee };
    rd_t r; rd_init(&r, b, (int)sizeof b);
    ASSERT_EQ(rd_rem(&r), (int)sizeof b);
    ASSERT_EQ(rd_u8(&r), 0xaa);
    ASSERT_EQ(rd_le16(&r), 0x1234);
    ASSERT_EQ(rd_be16(&r), 0x1234);
    ASSERT_EQ(rd_le32(&r), 0x12345678u);
    ASSERT_EQ(rd_be32(&r), 0x12345678u);
    ASSERT_EQ(rd_rem(&r), 1);
    ASSERT_EQ(rd_u8(&r), 0xee);
    ASSERT_EQ(rd_rem(&r), 0);
    ASSERT_EQ(r.fault, 0);
}

/* The contract every short read shares: 0 back, `fault` set, `off`
 * unchanged. One reader per helper so each is seen to fail on its own
 * rather than riding on a fault an earlier call already set. */
static void test_short_reads_fault_and_do_not_advance(void) {
    static const uint8_t b[3] = { 0x11, 0x22, 0x33 };
    rd_t r;
    const uint8_t *v = b;

    rd_init(&r, b, 0);
    ASSERT_EQ(rd_u8(&r), 0);    ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    rd_init(&r, b, 1);
    ASSERT_EQ(rd_le16(&r), 0);  ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);
    rd_init(&r, b, 1);
    ASSERT_EQ(rd_be16(&r), 0);  ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    rd_init(&r, b, 3);
    ASSERT_EQ(rd_le32(&r), 0u); ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);
    rd_init(&r, b, 3);
    ASSERT_EQ(rd_be32(&r), 0u); ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    rd_init(&r, b, 3);
    ASSERT_EQ(rd_bytes(&r, 4, &v), 0);
    ASSERT(v == NULL); ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    rd_init(&r, b, 3);
    ASSERT_EQ(rd_skip(&r, 4), 0); ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    /* A negative count is a caller's arithmetic gone wrong, never a
       request to step backwards. */
    rd_init(&r, b, 3);
    ASSERT_EQ(rd_skip(&r, -1), 0); ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);

    rd_t sub; sub.len = 99;
    rd_init(&r, b, 3);
    ASSERT_EQ(rd_sub(&r, 4, &sub), 0);
    ASSERT_EQ(r.off, 0); ASSERT_EQ(r.fault, 1);
    ASSERT_EQ(sub.len, 0); ASSERT_EQ(rd_rem(&sub), 0);
}

/* Reads that fit exactly are not faults — the off-by-one the bound
 * check would most plausibly carry. */
static void test_exact_fit_reads_succeed(void) {
    static const uint8_t b[4] = { 0x01, 0x02, 0x03, 0x04 };
    rd_t r; rd_init(&r, b, 4);
    ASSERT_EQ(rd_be32(&r), 0x01020304u);
    ASSERT_EQ(r.fault, 0); ASSERT_EQ(r.off, 4);

    const uint8_t *v = NULL;
    rd_init(&r, b, 4);
    ASSERT_EQ(rd_bytes(&r, 4, &v), 1);
    ASSERT(v == b); ASSERT_EQ(r.fault, 0); ASSERT_EQ(rd_rem(&r), 0);

    rd_init(&r, b, 4);
    ASSERT_EQ(rd_skip(&r, 4), 1); ASSERT_EQ(r.fault, 0);
    /* Zero-length operations at the end are legal: an empty field. */
    ASSERT_EQ(rd_skip(&r, 0), 1); ASSERT_EQ(r.fault, 0);
}

/* Sticky: a read that would fit after a fault still fails, because the
 * offset it would read from is one the frame never described. */
static void test_fault_is_sticky(void) {
    static const uint8_t b[3] = { 0x11, 0x22, 0x33 };
    rd_t r; rd_init(&r, b, 3);
    ASSERT_EQ(rd_le32(&r), 0u);
    ASSERT_EQ(r.fault, 1);
    ASSERT_EQ(rd_u8(&r), 0);    /* one byte is there; still refused */
    ASSERT_EQ(r.off, 0);
    ASSERT_EQ(rd_skip(&r, 0), 0);
}

static void test_sub_reader_is_bounded_to_its_carve(void) {
    /* 2-byte length-prefixed field of 3 bytes, then a trailer the
       sub-reader must not reach. */
    static const uint8_t b[] = { 0x00, 0x03, 0xa1, 0xa2, 0xa3, 0xff };
    rd_t r; rd_init(&r, b, (int)sizeof b);
    int n = rd_be16(&r);
    rd_t sub;
    ASSERT_EQ(rd_sub(&r, n, &sub), 1);
    ASSERT_EQ(rd_rem(&sub), 3);
    ASSERT_EQ(rd_u8(&sub), 0xa1);
    ASSERT_EQ(rd_le16(&sub), 0xa3a2);
    ASSERT_EQ(rd_u8(&sub), 0);           /* the 0xff is outside the carve */
    ASSERT_EQ(sub.fault, 1);
    ASSERT_EQ(r.fault, 0);               /* parent unaffected */
    ASSERT_EQ(rd_u8(&r), 0xff);
}

static void test_reader_tolerates_null_and_negative(void) {
    rd_t r;
    rd_init(&r, NULL, 10);
    ASSERT_EQ(rd_rem(&r), 0);
    ASSERT_EQ(rd_u8(&r), 0);
    ASSERT_EQ(r.fault, 1);
    static const uint8_t b[1] = { 0x5a };
    rd_init(&r, b, -4);
    ASSERT_EQ(rd_rem(&r), 0);
}

/* ── TLV iterator ─────────────────────────────────────────── */

/* Element-ID 0 claiming 5 body octets with only 1 present (the issue's
 * named input). Nothing may be yielded: the element does not fit. */
static void test_tlv_overrun_yields_nothing(void) {
    static const uint8_t b[] = { 0x00, 0x05, 'a' };
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    uint16_t tag = 0xbeef; int blen = -7; const uint8_t *body = NULL;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OVERRUN);
    ASSERT_EQ(tag, 0xbeef);
    ASSERT_EQ(blen, -7);
    ASSERT(body == NULL);
    ASSERT_EQ(it.status, TLV_OVERRUN);
    /* Left at the element that did not fit, so a caller can report it. */
    ASSERT_EQ(it.off, 0);
    ASSERT(!tlv_exact(&it));
    /* Terminal. */
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OVERRUN);
}

/* One clean element, then a 1-octet tail: one yield, then OVERRUN. A
 * single octet cannot be an element header, and nothing defines padding
 * between elements, so it is the previous lengths failing to tile. */
static void test_tlv_one_element_then_one_byte_tail(void) {
    static const uint8_t b[] = { 0x00, 0x01, 'a', 0xdd };
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 0);
    ASSERT_EQ(blen, 1);
    ASSERT(body == b + 2);
    ASSERT_EQ(body[0], 'a');
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OVERRUN);
    ASSERT_EQ(it.off, 3);
    ASSERT(!tlv_exact(&it));
}

/* An element whose body ends on the region's last octet fits. Pins the
 * `off + hdr + blen > len` comparison: `>=` would refuse it. */
static void test_tlv_exact_fit_element_is_yielded(void) {
    static const uint8_t b[] = { 0x30, 0x02, 0x01, 0x00,     /* RSN, 2 */
                                 0xdd, 0x03, 0x00, 0x50, 0xf2 };
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 48); ASSERT_EQ(blen, 2);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 221); ASSERT_EQ(blen, 3);
    ASSERT(body + blen == b + sizeof b);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    ASSERT(tlv_exact(&it));
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);   /* terminal */
}

/* A zero-length element as the very last two octets: the header fits
 * exactly and there is no body. Pins `off + hdr <= len`: `<` would call
 * this an overrun. An empty SSID element is the everyday instance — a
 * wildcard probe request ends this way. */
static void test_tlv_zero_length_final_element(void) {
    static const uint8_t b[] = { 0x01, 0x01, 0x82, 0x00, 0x00 };
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 1);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 0);
    ASSERT_EQ(blen, 0);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    ASSERT(tlv_exact(&it));
}

static void test_tlv_empty_region_is_a_clean_end(void) {
    tlv_it_t it;
    uint16_t tag; int blen; const uint8_t *body;
    static const uint8_t b[1] = { 0 };
    tlv_init(&it, b, 0);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    ASSERT(tlv_exact(&it));
    tlv_init(&it, NULL, 5);                /* no buffer, no elements */
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    tlv_init(&it, b, -3);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
}

/* A maximal body (255) is a length octet, not a sign: read unsigned. */
static void test_tlv_length_octet_is_unsigned(void) {
    uint8_t b[2 + 255];
    memset(b, 0x41, sizeof b);
    b[0] = 221; b[1] = 0xff;
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(blen, 255);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    /* One octet short of that claim is an overrun. */
    tlv_init(&it, b, (int)sizeof b - 1);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OVERRUN);
}

/* NULL out-parameters are allowed: a walker that only validates. */
static void test_tlv_accepts_null_outputs(void) {
    static const uint8_t b[] = { 0x00, 0x01, 'x' };
    tlv_it_t it; tlv_init(&it, b, (int)sizeof b);
    ASSERT_EQ(tlv_next(&it, NULL, NULL, NULL), TLV_OK);
    ASSERT_EQ(tlv_next(&it, NULL, NULL, NULL), TLV_END);
}

/* 2+2 big-endian: WPS attributes. Version (0x104A, len 1) then
 * Wi-Fi Simple Config State (0x1044, len 1). */
static void test_tlv16_big_endian(void) {
    static const uint8_t b[] = { 0x10, 0x4a, 0x00, 0x01, 0x10,
                                 0x10, 0x44, 0x00, 0x01, 0x02 };
    tlv_it_t it; tlv_init16(&it, b, (int)sizeof b, 1);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 0x104a); ASSERT_EQ(blen, 1); ASSERT_EQ(body[0], 0x10);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 0x1044); ASSERT_EQ(body[0], 0x02);
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_END);
    ASSERT(tlv_exact(&it));
}

static void test_tlv16_little_endian_and_short_header(void) {
    static const uint8_t b[] = { 0x4a, 0x10, 0x01, 0x00, 0x10,
                                 0x44, 0x10, 0x01 };  /* 3-byte tail */
    tlv_it_t it; tlv_init16(&it, b, (int)sizeof b, 0);
    uint16_t tag; int blen; const uint8_t *body;
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OK);
    ASSERT_EQ(tag, 0x104a); ASSERT_EQ(blen, 1);
    /* Three octets left: not a 4-octet header. */
    ASSERT_EQ(tlv_next(&it, &tag, &blen, &body), TLV_OVERRUN);
    ASSERT_EQ(it.off, 5);
}

/* A 2+2 length is 16 bits wide: 0xFFFF must be compared as 65535, not
 * truncated or sign-extended into something that fits. */
static void test_tlv16_large_length_overruns(void) {
    static const uint8_t b[] = { 0x10, 0x4a, 0xff, 0xff, 0x00, 0x00 };
    tlv_it_t it; tlv_init16(&it, b, (int)sizeof b, 1);
    ASSERT_EQ(tlv_next(&it, NULL, NULL, NULL), TLV_OVERRUN);
    ASSERT_EQ(it.off, 0);
}

void run_bytes_tests(void) {
    TEST_SUITE("bytes.h — bounded reader + TLV iterator (#126)");
    RUN_TEST(test_fixed_width_loads);
    RUN_TEST(test_reader_reads_in_order);
    RUN_TEST(test_short_reads_fault_and_do_not_advance);
    RUN_TEST(test_exact_fit_reads_succeed);
    RUN_TEST(test_fault_is_sticky);
    RUN_TEST(test_sub_reader_is_bounded_to_its_carve);
    RUN_TEST(test_reader_tolerates_null_and_negative);
    RUN_TEST(test_tlv_overrun_yields_nothing);
    RUN_TEST(test_tlv_one_element_then_one_byte_tail);
    RUN_TEST(test_tlv_exact_fit_element_is_yielded);
    RUN_TEST(test_tlv_zero_length_final_element);
    RUN_TEST(test_tlv_empty_region_is_a_clean_end);
    RUN_TEST(test_tlv_length_octet_is_unsigned);
    RUN_TEST(test_tlv_accepts_null_outputs);
    RUN_TEST(test_tlv16_big_endian);
    RUN_TEST(test_tlv16_little_endian_and_short_header);
    RUN_TEST(test_tlv16_large_length_overruns);
}
