#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "pcap_format.h"

/* ── The libpcap savefile layout, asserted as literal bytes ───────
 *
 * This module replaced four independent copies of the format in
 * src/pcap_write.c, src/alert_pcap.c, src/eapol_log.c and
 * src/evidence_export.c. The copies had already drifted: three wrote
 * little-endian and one wrote native byte order.
 *
 * So these tests assert the exact bytes, not a round trip through the
 * module's own reader (there isn't one, and a round trip would be the
 * circular shape agents/AGENTS.md forbids). Expected arrays are written
 * from the savefile format itself:
 *
 *   file header, 24 bytes: magic u32, major u16, minor u16, thiszone
 *   i32, sigfigs u32, snaplen u32, network u32
 *   record header, 16 bytes: ts_sec u32, ts_usec u32, caplen u32,
 *   origlen u32
 *
 * Asserting literal bytes is also what makes the little-endian policy
 * testable at all: a native-order writer would pass any assertion
 * phrased in terms of its own helpers, and fail these on a big-endian
 * host — which is the property we want. */

static int mem_cmp_report(const uint8_t *got, const uint8_t *want, size_t n,
                          const char *what) {
    if (memcmp(got, want, n) == 0) return 1;
    fprintf(stderr, "    %s mismatch\n      got: ", what);
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x ", got[i]);
    fprintf(stderr, "\n     want: ");
    for (size_t i = 0; i < n; i++) fprintf(stderr, "%02x ", want[i]);
    fprintf(stderr, "\n");
    return 0;
}

static void test_file_header_is_little_endian_bytes(void) {
    uint8_t h[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(h, PCAP_DLT_EN10MB, PCAP_SNAPLEN_FRAME);
    const uint8_t want[PCAP_FILE_HDR_LEN] = {
        0xd4, 0xc3, 0xb2, 0xa1,   /* magic 0xa1b2c3d4, LE on the wire */
        0x02, 0x00,               /* version major 2 */
        0x04, 0x00,               /* version minor 4 */
        0x00, 0x00, 0x00, 0x00,   /* thiszone: UTC */
        0x00, 0x00, 0x00, 0x00,   /* sigfigs */
        0xff, 0xff, 0x00, 0x00,   /* snaplen 65535 */
        0x01, 0x00, 0x00, 0x00    /* network: DLT_EN10MB */
    };
    ASSERT(mem_cmp_report(h, want, sizeof(want), "file header"));
}

static void test_file_header_carries_the_callers_dlt_and_snaplen(void) {
    /* The evidence ring's pair (#92): radiotap, and a snaplen an order
       of magnitude larger than the frame sinks'. 262144 = 0x00040000. */
    uint8_t h[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(h, PCAP_DLT_RADIOTAP, PCAP_SNAPLEN_LARGE);
    const uint8_t want_tail[8] = {
        0x00, 0x00, 0x04, 0x00,   /* snaplen 262144 */
        0x7f, 0x00, 0x00, 0x00    /* network 127: radiotap */
    };
    ASSERT(mem_cmp_report(h + 16, want_tail, sizeof(want_tail), "dlt/snaplen"));

    /* And the handshake sink's: raw 802.11, DLT 105 = 0x69. */
    pcap_fmt_file_hdr(h, PCAP_DLT_IEEE802_11, PCAP_SNAPLEN_FRAME);
    ASSERT_EQ(h[20], 0x69);
    ASSERT_EQ(h[21], 0x00);
}

static void test_record_header_is_little_endian_bytes(void) {
    uint8_t r[PCAP_REC_HDR_LEN];
    /* 0x5F5E1000 and 0x000F4240 chosen so every one of the four bytes
       differs — a byte-order bug in any lane shows up. */
    pcap_fmt_rec_hdr(r, 0x5F5E1000u, 0x000F4240u, 0x40, 0x5DC);
    const uint8_t want[PCAP_REC_HDR_LEN] = {
        0x00, 0x10, 0x5e, 0x5f,   /* ts_sec  */
        0x40, 0x42, 0x0f, 0x00,   /* ts_usec */
        0x40, 0x00, 0x00, 0x00,   /* caplen  64   */
        0xdc, 0x05, 0x00, 0x00    /* origlen 1500 */
    };
    ASSERT(mem_cmp_report(r, want, sizeof(want), "record header"));
}

static void test_origlen_below_caplen_is_clamped_up(void) {
    /* The reason this module exists as a function rather than a macro.
       A record claiming fewer original than captured bytes is malformed,
       and because each record's length tells a reader where the next one
       begins, ONE such record silently misparses every record after it —
       the reader does not fail, it produces wrong packets. */
    uint8_t r[PCAP_REC_HDR_LEN];
    pcap_fmt_rec_hdr(r, 1, 2, 1500, 64);
    /* caplen untouched... */
    ASSERT_EQ(r[8],  0xdc);
    ASSERT_EQ(r[9],  0x05);
    /* ...and origlen raised to meet it, not caplen lowered: the bytes
       really are present in the file, so shrinking caplen would discard
       data that was captured. */
    ASSERT_EQ(r[12], 0xdc);
    ASSERT_EQ(r[13], 0x05);

    /* Equal is already valid and must pass through untouched. */
    pcap_fmt_rec_hdr(r, 1, 2, 64, 64);
    ASSERT_EQ(r[8],  0x40);
    ASSERT_EQ(r[12], 0x40);

    /* A larger origlen is the normal truncated-capture case and must
       NOT be clamped down — that is the whole point of the two fields. */
    pcap_fmt_rec_hdr(r, 1, 2, 64, 9000);
    ASSERT_EQ(r[8],  0x40);
    ASSERT_EQ(r[12], 0x28);   /* 9000 = 0x2328 */
    ASSERT_EQ(r[13], 0x23);
}

static void test_dlt_default_is_ethernet(void) {
    ASSERT_EQ((long long)pcap_fmt_dlt_or_default(0), (long long)PCAP_DLT_EN10MB);
    ASSERT_EQ((long long)pcap_fmt_dlt_or_default(PCAP_DLT_RADIOTAP),
              (long long)PCAP_DLT_RADIOTAP);
    ASSERT_EQ((long long)pcap_fmt_dlt_or_default(105), 105);
}

static void test_null_output_is_safe(void) {
    /* ASan is the real assertion. The callers always pass a real buffer,
       but a serialiser that writes through NULL is a crash waiting for
       the first caller that gets an early-return path wrong. */
    pcap_fmt_file_hdr(NULL, PCAP_DLT_EN10MB, PCAP_SNAPLEN_FRAME);
    pcap_fmt_rec_hdr(NULL, 1, 2, 3, 4);
    pcap_fmt_put_file_hdr(NULL, PCAP_DLT_EN10MB, PCAP_SNAPLEN_FRAME);
    pcap_fmt_put_rec(NULL, 1, 2, "x", 1, 1);
    ASSERT(1);
}

static void test_stream_writer_emits_header_then_payload(void) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    FILE *f = fmemopen(buf, sizeof(buf), "wb");
    ASSERT(f != NULL);
    if (!f) return;
    pcap_fmt_put_file_hdr(f, PCAP_DLT_EN10MB, PCAP_SNAPLEN_FRAME);
    const uint8_t payload[4] = { 0xde, 0xad, 0xbe, 0xef };
    pcap_fmt_put_rec(f, 7, 8, payload, 4, 60);
    fclose(f);

    /* 24 + 16 + 4 = 44 bytes, in that order. */
    uint8_t want_hdr[PCAP_FILE_HDR_LEN];
    pcap_fmt_file_hdr(want_hdr, PCAP_DLT_EN10MB, PCAP_SNAPLEN_FRAME);
    ASSERT(mem_cmp_report(buf, want_hdr, sizeof(want_hdr), "stream file header"));
    ASSERT_EQ(buf[24], 0x07);                       /* ts_sec  */
    ASSERT_EQ(buf[28], 0x08);                       /* ts_usec */
    ASSERT_EQ(buf[32], 0x04);                       /* caplen  */
    ASSERT_EQ(buf[36], 0x3c);                       /* origlen 60 */
    ASSERT(mem_cmp_report(buf + 40, payload, 4, "stream payload"));
}

static void test_stream_writer_refuses_a_record_with_no_payload(void) {
    /* A header for bytes that do not follow is the same corruption as a
       bad origlen, reached from the other side: the reader consumes
       caplen bytes of whatever comes next. Nothing is written at all. */
    uint8_t buf[64];
    memset(buf, 0xAA, sizeof(buf));
    FILE *f = fmemopen(buf, sizeof(buf), "wb");
    ASSERT(f != NULL);
    if (!f) return;
    pcap_fmt_put_rec(f, 1, 2, NULL, 10, 10);
    const uint8_t payload[2] = { 1, 2 };
    pcap_fmt_put_rec(f, 1, 2, payload, 0, 0);
    long pos = ftell(f);
    fclose(f);
    ASSERT_EQ((long long)pos, 0);
    ASSERT_EQ(buf[0], 0xAA);   /* untouched */
}

void run_pcap_format_tests(void) {
    TEST_SUITE("pcap savefile format (one writer, four sinks)");
    RUN_TEST(test_file_header_is_little_endian_bytes);
    RUN_TEST(test_file_header_carries_the_callers_dlt_and_snaplen);
    RUN_TEST(test_record_header_is_little_endian_bytes);
    RUN_TEST(test_origlen_below_caplen_is_clamped_up);
    RUN_TEST(test_dlt_default_is_ethernet);
    RUN_TEST(test_null_output_is_safe);
    RUN_TEST(test_stream_writer_emits_header_then_payload);
    RUN_TEST(test_stream_writer_refuses_a_record_with_no_payload);
}
