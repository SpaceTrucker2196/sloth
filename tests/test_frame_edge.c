/* The pcap-edge input gate (#141), pure.
 *
 * frame_view_init() takes the four numbers a libpcap record header
 * carries and either admits them or refuses the frame before a byte of
 * it is read. frame_view_radiotap() is the monitor DLT's second half,
 * shared by both capture callbacks. Both are libpcap-free, so the cases
 * here are the numbers and hand-built radiotap + 802.11 bytes and
 * nothing else; tests/test_capture_path.c drives the same gate through
 * the real pcap_dispatch() callbacks.
 *
 * Radiotap per https://www.radiotap.org: it_version (1), it_pad (1),
 * it_len (2, LE), it_present (4, LE), then the present fields. */

#include <string.h>
#include <stdint.h>

#include "runner.h"
#include "frame_build.h"
#include "capture/frame_edge.h"

#define DLT_RADIO 127   /* DLT_IEEE802_11_RADIO, pcap-linktype(7) */

/* ── frame_view_init() ─────────────────────────────────────── */

static void test_init_admits_a_wellformed_header(void) {
    static const uint8_t d[4] = { 1, 2, 3, 4 };
    frame_view_t f;
    ASSERT_EQ(frame_view_init(&f, d, 4, 1500, 1700000000L, 999999L, 1), 1);
    ASSERT(f.data == d);
    ASSERT_EQ(f.caplen, 4);
    ASSERT_EQ((long long)f.origlen, 1500);
    ASSERT_EQ((long long)f.ts_sec, 1700000000LL);
    ASSERT_EQ((long long)f.ts_usec, 999999);
    ASSERT_EQ(f.dlt, 1);
}

static void test_init_admits_the_snaplen_exactly(void) {
    static uint8_t big[FRAME_CAPLEN_MAX];
    frame_view_t f;
    ASSERT_EQ(frame_view_init(&f, big, FRAME_CAPLEN_MAX, FRAME_CAPLEN_MAX,
                              1, 0, 1), 1);
    ASSERT_EQ(f.caplen, 65535);
}

/* Each refusal leaves the view zeroed, so a caller that ignored the
 * return still has nothing to read. */
static void assert_refused(frame_view_t *f) {
    ASSERT(f->data == NULL);
    ASSERT_EQ(f->caplen, 0);
}

static void test_init_refuses_each_lying_header(void) {
    static uint8_t big[FRAME_CAPLEN_MAX + 1];
    frame_view_t f;
    memset(&f, 0x5A, sizeof f);
    /* NULL data. */
    ASSERT_EQ(frame_view_init(&f, NULL, 10, 10, 1, 0, 1), 0);
    assert_refused(&f);
    /* caplen 0: nothing was captured. */
    memset(&f, 0x5A, sizeof f);
    ASSERT_EQ(frame_view_init(&f, big, 0, 10, 1, 0, 1), 0);
    assert_refused(&f);
    /* caplen 65536: one past our snaplen, which no handle we open
     * produces. */
    memset(&f, 0x5A, sizeof f);
    ASSERT_EQ(frame_view_init(&f, big, FRAME_CAPLEN_MAX + 1u,
                              FRAME_CAPLEN_MAX + 1u, 1, 0, 1), 0);
    assert_refused(&f);
    /* caplen > origlen: more copied than was on the wire. */
    memset(&f, 0x5A, sizeof f);
    ASSERT_EQ(frame_view_init(&f, big, 61, 60, 1, 0, 1), 0);
    assert_refused(&f);
    /* A caplen that would be negative as an int — the cast both
     * callbacks used to make. */
    ASSERT_EQ(frame_view_init(&f, big, 0x80000000u, 0xFFFFFFFFu, 1, 0, 1), 0);
    /* Microseconds out of range, either side. */
    ASSERT_EQ(frame_view_init(&f, big, 10, 10, 1, 1000000L, 1), 0);
    ASSERT_EQ(frame_view_init(&f, big, 10, 10, 1, -1L, 1), 0);
    /* NULL view: refused, not a crash. */
    ASSERT_EQ(frame_view_init(NULL, big, 10, 10, 1, 0, 1), 0);
}

static void test_init_does_not_judge_the_seconds(void) {
    /* ts <= 0 is probe.c's bad-clock tally (#92), which counts and
     * keeps the frame; the edge must not pre-empt that policy. */
    static const uint8_t d[1] = { 0 };
    frame_view_t f;
    ASSERT_EQ(frame_view_init(&f, d, 1, 1, 0, 0, 1), 1);
    ASSERT_EQ(frame_view_init(&f, d, 1, 1, -5, 0, 1), 1);
    ASSERT_EQ((long long)f.ts_sec, -5);
}

/* ── frame_view_radiotap() ─────────────────────────────────── */

/* Bare 8-octet radiotap (fb_radiotap, empty present word) followed by
 * `dot11_len` octets of 802.11 starting 0xD4 0x00 (an ACK's Frame
 * Control). Returns the total. */
static int rt_plus(uint8_t *buf, int cap, int dot11_len) {
    fb_t b; fb_init(&b, buf, cap);
    fb_radiotap(&b, NULL);
    for (int i = 0; i < dot11_len; i++) fb_u8(&b, i == 0 ? 0xD4 : 0x00);
    return fb_ok(&b) ? b.len : -1;
}

static void test_radiotap_admits_header_plus_ten(void) {
    uint8_t buf[64];
    int n = rt_plus(buf, sizeof buf, 10);
    ASSERT_EQ(n, 18);
    frame_view_t f;
    ASSERT_EQ(frame_view_init(&f, buf, (uint32_t)n, (uint32_t)n, 1, 0,
                              DLT_RADIO), 1);
    radiotap_info_t rti; const uint8_t *d = NULL; int dl = -1;
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_OK);
    ASSERT(d == buf + 8);
    ASSERT_EQ(dl, 10);
    ASSERT_EQ(rti.hdr_len, 8);
}

static void test_radiotap_refuses_an_it_len_below_eight(void) {
    /* The defect #123 fixed in probe.c, now in the shared gate: an
     * it_len of 4 makes the "802.11 frame" begin inside it_present.
     * Mutation-proved: dropping `rt_len < 8` from radiotap_parse()
     * (src/radiotap.c) admits it and reddens the verdict assertion;
     * the inverse edit restores green. */
    uint8_t buf[64];
    int n = rt_plus(buf, sizeof buf, 20);
    buf[2] = 4; buf[3] = 0;
    frame_view_t f;
    ASSERT_EQ(frame_view_init(&f, buf, (uint32_t)n, (uint32_t)n, 1, 0,
                              DLT_RADIO), 1);
    radiotap_info_t rti; const uint8_t *d = buf; int dl = 99;
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_BAD);
    ASSERT(d == NULL);
    ASSERT_EQ(dl, 0);
    ASSERT_EQ(rti.signal_dbm, -100);   /* defaults, not garbage */
}

static void test_radiotap_refuses_an_it_len_past_caplen(void) {
    uint8_t buf[64];
    int n = rt_plus(buf, sizeof buf, 10);
    buf[2] = (uint8_t)(n + 1);
    frame_view_t f;
    frame_view_init(&f, buf, (uint32_t)n, (uint32_t)n, 1, 0, DLT_RADIO);
    radiotap_info_t rti; const uint8_t *d; int dl;
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_BAD);
}

static void test_radiotap_with_no_frame_behind_it_is_a_runt(void) {
    /* it_len == caplen: a well-formed header with nothing after it. Not
     * a bad header — the monitor stream counts it as dot11_runt, as it
     * did before the gate moved. */
    uint8_t buf[16];
    int n = rt_plus(buf, sizeof buf, 0);
    ASSERT_EQ(n, 8);
    frame_view_t f;
    frame_view_init(&f, buf, 8, 8, 1, 0, DLT_RADIO);
    radiotap_info_t rti; const uint8_t *d; int dl;
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_RUNT);
    ASSERT(d == NULL);
    /* Nine octets of 802.11 is one short of FC + Duration + Address 1. */
    uint8_t b2[32];
    n = rt_plus(b2, sizeof b2, 9);
    frame_view_init(&f, b2, (uint32_t)n, (uint32_t)n, 1, 0, DLT_RADIO);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_RUNT);
}

/* Radiotap with FLAGS = FCS present (it_len 9), `body` octets of
 * 802.11, then a 4-octet trailer. */
static int rt_fcs(uint8_t *buf, int cap, int body) {
    fb_t b; fb_init(&b, buf, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof rt);
    rt.has_flags = 1; rt.flags = RT_F_FCS;
    fb_radiotap(&b, &rt);
    for (int i = 0; i < body; i++) fb_u8(&b, i == 0 ? 0xD4 : 0x00);
    fb_u8(&b, 0xF1); fb_u8(&b, 0xF2); fb_u8(&b, 0xF3); fb_u8(&b, 0xF4);
    return fb_ok(&b) ? b.len : -1;
}

static void test_radiotap_strips_the_fcs_against_origlen(void) {
    uint8_t buf[64];
    int n = rt_fcs(buf, sizeof buf, 10);
    ASSERT_EQ(n, 9 + 10 + 4);
    frame_view_t f;
    radiotap_info_t rti; const uint8_t *d; int dl;

    /* Whole trailer captured: all four go. */
    frame_view_init(&f, buf, (uint32_t)n, (uint32_t)n, 1, 0, DLT_RADIO);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_OK);
    ASSERT_EQ(dl, 10);

    /* Snapped two octets short: two of the trailer are in hand. */
    frame_view_init(&f, buf, (uint32_t)(n - 2), (uint32_t)n, 1, 0,
                    DLT_RADIO);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_OK);
    ASSERT_EQ(dl, 10);

    /* An origlen far past caplen — the whole trailer was cut, and the
     * difference does not fit an int. Nothing is stripped and nothing
     * wraps. */
    frame_view_init(&f, buf, (uint32_t)n, 0xFFFFFFFFu, 1, 0, DLT_RADIO);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_OK);
    ASSERT_EQ(dl, 14);

    /* The strip leaves a runt: 9 + 6 + 4, six octets of 802.11. */
    n = rt_fcs(buf, sizeof buf, 6);
    frame_view_init(&f, buf, (uint32_t)n, (uint32_t)n, 1, 0, DLT_RADIO);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, &d, &dl), FRAME_RT_RUNT);
}

static void test_radiotap_null_arguments(void) {
    radiotap_info_t rti; const uint8_t *d = (const uint8_t *)&rti; int dl = 7;
    ASSERT_EQ(frame_view_radiotap(NULL, &rti, &d, &dl), FRAME_RT_BAD);
    ASSERT(d == NULL);
    ASSERT_EQ(dl, 0);
    ASSERT_EQ(rti.signal_dbm, -100);
    frame_view_t f; memset(&f, 0, sizeof f);
    ASSERT_EQ(frame_view_radiotap(&f, NULL, NULL, NULL), FRAME_RT_BAD);
    ASSERT_EQ(frame_view_radiotap(&f, &rti, NULL, NULL), FRAME_RT_BAD);
}

void run_frame_edge_tests(void) {
    TEST_SUITE("frame edge: record header gate (#141)");
    RUN_TEST(test_init_admits_a_wellformed_header);
    RUN_TEST(test_init_admits_the_snaplen_exactly);
    RUN_TEST(test_init_refuses_each_lying_header);
    RUN_TEST(test_init_does_not_judge_the_seconds);

    TEST_SUITE("frame edge: the shared radiotap gate (#141)");
    RUN_TEST(test_radiotap_admits_header_plus_ten);
    RUN_TEST(test_radiotap_refuses_an_it_len_below_eight);
    RUN_TEST(test_radiotap_refuses_an_it_len_past_caplen);
    RUN_TEST(test_radiotap_with_no_frame_behind_it_is_a_runt);
    RUN_TEST(test_radiotap_strips_the_fcs_against_origlen);
    RUN_TEST(test_radiotap_null_arguments);
}
