/* Radiotap header decoding (roadmap B3).
 *
 * Headers are built byte by byte from the radiotap layout rather than
 * captured and replayed — the same rule the 802.11 and IP parsers
 * follow. A replayed capture would prove only that the parser agrees
 * with itself.
 *
 * This parser had no coverage at all before being extracted from
 * src/capture/probe.c, which is compiled only under WITH_PCAP and is
 * not in the test build. */

#include <string.h>
#include "runner.h"
#include "radiotap.h"

/* Build a header: version 0, pad 0, len, one present word, then body. */
static int rt_build(uint8_t *buf, uint32_t present,
                    const uint8_t *body, int blen) {
    int len = 8 + blen;
    buf[0] = 0;                       /* version */
    buf[1] = 0;                       /* pad     */
    buf[2] = (uint8_t)(len & 0xff);
    buf[3] = (uint8_t)(len >> 8);
    buf[4] = (uint8_t)(present & 0xff);
    buf[5] = (uint8_t)((present >> 8) & 0xff);
    buf[6] = (uint8_t)((present >> 16) & 0xff);
    buf[7] = (uint8_t)((present >> 24) & 0xff);
    if (blen > 0) memcpy(buf + 8, body, (size_t)blen);
    return len;
}

/* ── field decoding ──────────────────────────────────────── */

static void test_signal_only(void) {
    uint8_t body[1] = { (uint8_t)(int8_t)-42 };
    uint8_t buf[64];
    int len = rt_build(buf, 1u << RT_BIT_DBM_ANTSIGNAL, body, 1);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ((int)rt.signal_dbm, -42);
    ASSERT_EQ(rt.has_signal, 1);
}

/* CHANNEL is u16 freq + u16 flags, 2-byte aligned. */
static void test_channel_maps_frequency(void) {
    uint8_t body[4] = { 0x6c, 0x09, 0x00, 0x00 };   /* 2412 MHz */
    uint8_t buf[64];
    int len = rt_build(buf, 1u << RT_BIT_CHANNEL, body, 4);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ(rt.freq_mhz, 2412);
    ASSERT_EQ(rt.channel, 1);
}

/* The FCS-failed bit is the whole reason FLAGS stopped being skipped. */
static void test_flags_bad_fcs(void) {
    uint8_t body[1] = { RT_F_BADFCS };
    uint8_t buf[64];
    int len = rt_build(buf, 1u << RT_BIT_FLAGS, body, 1);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ(rt.has_flags, 1);
    ASSERT_EQ(rt.bad_fcs, 1);

    /* Other flag bits must not be mistaken for it. */
    uint8_t clean[1] = { RT_F_FCS | RT_F_SHORTPRE | RT_F_WEP };
    len = rt_build(buf, 1u << RT_BIT_FLAGS, clean, 1);
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ(rt.bad_fcs, 0);
}

/* RATE is in 500 kbps units. */
static void test_rate_units(void) {
    uint8_t body[1] = { 12 };            /* 12 * 500 kbps = 6 Mbps */
    uint8_t buf[64];
    int len = rt_build(buf, 1u << RT_BIT_RATE, body, 1);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ(rt.rate_kbps, 6000);
}

/* Fields appear in bit order with natural alignment; a header carrying
 * several must land each one correctly, not just the first. */
static void test_multiple_fields_in_bit_order(void) {
    /* FLAGS(1) RATE(1) CHANNEL(pad to 2, then 4) ANTSIGNAL(1) */
    uint8_t body[8];
    body[0] = RT_F_BADFCS;               /* FLAGS  @ 8  */
    body[1] = 12;                        /* RATE   @ 9  */
    body[2] = 0x3c; body[3] = 0x14;      /* CHANNEL@10 → 5180 MHz */
    body[4] = 0x00; body[5] = 0x00;
    body[6] = (uint8_t)(int8_t)-67;      /* SIGNAL @14 */
    uint8_t buf[64];
    uint32_t pres = (1u << RT_BIT_FLAGS) | (1u << RT_BIT_RATE) |
                    (1u << RT_BIT_CHANNEL) | (1u << RT_BIT_DBM_ANTSIGNAL);
    int len = rt_build(buf, pres, body, 7);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ(rt.bad_fcs, 1);
    ASSERT_EQ(rt.rate_kbps, 6000);
    ASSERT_EQ(rt.freq_mhz, 5180);
    ASSERT_EQ(rt.channel, 36);
    ASSERT_EQ((int)rt.signal_dbm, -67);
}

/* TSFT is 8-byte aligned, which shifts everything after it. Getting
 * the padding wrong silently misreads every later field. */
static void test_tsft_alignment_shifts_later_fields(void) {
    uint8_t body[16];
    memset(body, 0, sizeof(body));       /* TSFT @8..15 */
    body[8] = (uint8_t)(int8_t)-55;      /* SIGNAL @16  */
    uint8_t buf[64];
    uint32_t pres = (1u << RT_BIT_TSFT) | (1u << RT_BIT_DBM_ANTSIGNAL);
    int len = rt_build(buf, pres, body, 9);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ((int)rt.signal_dbm, -55);
}

/* ── extended present bitmaps ────────────────────────────── */

/* The regression this extraction was worth doing for. Drivers that
 * emit an extended present bitmap set bit 31 on the first word; the
 * fields then start after the extra word. The original loop in
 * probe.c re-tested the *first* word's bit 31 forever and advanced to
 * the end of the header, so every field was skipped and the frame
 * arrived with no signal and no channel. */
static void test_extended_present_bitmap_is_skipped_correctly(void) {
    uint8_t buf[64];
    /* word0: EXT | ANTSIGNAL   word1: (no ext)   then the signal byte */
    uint32_t w0 = (1u << RT_BIT_EXT) | (1u << RT_BIT_DBM_ANTSIGNAL);
    int len = 8 + 4 + 1;
    buf[0] = 0; buf[1] = 0;
    buf[2] = (uint8_t)len; buf[3] = 0;
    buf[4] = (uint8_t)(w0 & 0xff);
    buf[5] = (uint8_t)((w0 >> 8) & 0xff);
    buf[6] = (uint8_t)((w0 >> 16) & 0xff);
    buf[7] = (uint8_t)((w0 >> 24) & 0xff);
    buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;   /* word1, no ext */
    buf[12] = (uint8_t)(int8_t)-71;

    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ((int)rt.signal_dbm, -71);   /* was -100 before the fix */
    ASSERT_EQ(rt.has_signal, 1);
}

/* Two chained extended words. */
static void test_two_extended_bitmaps(void) {
    uint8_t buf[64];
    uint32_t w0 = (1u << RT_BIT_EXT) | (1u << RT_BIT_DBM_ANTSIGNAL);
    uint32_t w1 = (1u << RT_BIT_EXT);
    int len = 8 + 4 + 4 + 1;
    buf[0] = 0; buf[1] = 0; buf[2] = (uint8_t)len; buf[3] = 0;
    buf[4] = (uint8_t)(w0 & 0xff); buf[5] = (uint8_t)((w0 >> 8) & 0xff);
    buf[6] = (uint8_t)((w0 >> 16) & 0xff); buf[7] = (uint8_t)((w0 >> 24) & 0xff);
    buf[8] = (uint8_t)(w1 & 0xff); buf[9] = 0; buf[10] = 0;
    buf[11] = (uint8_t)((w1 >> 24) & 0xff);
    buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 0;  /* word2, no ext */
    buf[16] = (uint8_t)(int8_t)-80;

    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ((int)rt.signal_dbm, -80);
}

/* An extended bitmap that runs off the end must be rejected, not
 * walked past. */
static void test_truncated_extended_bitmap_rejected(void) {
    uint8_t buf[12];
    uint32_t w0 = (1u << RT_BIT_EXT);
    buf[0] = 0; buf[1] = 0; buf[2] = 10; buf[3] = 0;   /* claims 10 bytes */
    buf[4] = (uint8_t)(w0 & 0xff); buf[5] = 0; buf[6] = 0;
    buf[7] = (uint8_t)((w0 >> 24) & 0xff);
    buf[8] = 0; buf[9] = 0;
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, 10, &rt), 0);
}

/* ── malformed input ─────────────────────────────────────── */

static void test_malformed_headers_rejected(void) {
    radiotap_info_t rt;
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    ASSERT_EQ(radiotap_parse(NULL, 32, &rt), 0);
    ASSERT_EQ(radiotap_parse(buf, 0, &rt), 0);
    ASSERT_EQ(radiotap_parse(buf, 4, &rt), 0);      /* shorter than header */
    ASSERT_EQ(radiotap_parse(buf, 8, NULL), 0);     /* no output */

    /* rt_len smaller than the fixed header */
    buf[2] = 4; buf[3] = 0;
    ASSERT_EQ(radiotap_parse(buf, 32, &rt), 0);

    /* rt_len longer than the buffer */
    buf[2] = 200; buf[3] = 0;
    ASSERT_EQ(radiotap_parse(buf, 32, &rt), 0);
}

/* A failed parse must still leave usable defaults, because the caller
 * uses the struct either way. */
static void test_failed_parse_leaves_defaults(void) {
    radiotap_info_t rt;
    memset(&rt, 0x5a, sizeof(rt));
    ASSERT_EQ(radiotap_parse(NULL, 0, &rt), 0);
    ASSERT_EQ((int)rt.signal_dbm, -100);
    ASSERT_EQ(rt.channel, 0);
    ASSERT_EQ(rt.bad_fcs, 0);
    ASSERT_EQ(rt.rate_kbps, 0);
}

/* A field present in the bitmap but truncated in the body must not be
 * read past the end. */
static void test_field_past_header_end_not_read(void) {
    uint8_t buf[16];
    /* Declares ANTSIGNAL present but rt_len leaves no room for it. */
    int len = rt_build(buf, 1u << RT_BIT_DBM_ANTSIGNAL, NULL, 0);
    radiotap_info_t rt;
    ASSERT_EQ(radiotap_parse(buf, len, &rt), 1);
    ASSERT_EQ((int)rt.signal_dbm, -100);   /* absent, not garbage */
    ASSERT_EQ(rt.has_signal, 0);
}

/* ── frequency mapping ───────────────────────────────────── */

/* Shared with the nl80211 path so a monitor capture and a managed-mode
 * scan cannot disagree about a channel number. */
static void test_freq_to_channel_all_bands(void) {
    ASSERT_EQ(radiotap_freq_to_channel(2412), 1);
    ASSERT_EQ(radiotap_freq_to_channel(2437), 6);
    ASSERT_EQ(radiotap_freq_to_channel(2472), 13);
    ASSERT_EQ(radiotap_freq_to_channel(2484), 14);   /* Japan special case */
    ASSERT_EQ(radiotap_freq_to_channel(5180), 36);
    ASSERT_EQ(radiotap_freq_to_channel(5745), 149);
    ASSERT_EQ(radiotap_freq_to_channel(5955), 1);    /* 6 GHz ch 1 */
    ASSERT_EQ(radiotap_freq_to_channel(6175), 45);
    ASSERT_EQ(radiotap_freq_to_channel(7115), 233);
}

static void test_freq_to_channel_unmapped_is_zero(void) {
    ASSERT_EQ(radiotap_freq_to_channel(0),    0);
    ASSERT_EQ(radiotap_freq_to_channel(900),  0);
    ASSERT_EQ(radiotap_freq_to_channel(2400), 0);
    ASSERT_EQ(radiotap_freq_to_channel(5000), 0);
    ASSERT_EQ(radiotap_freq_to_channel(9000), 0);
}

void run_radiotap_tests(void) {
    TEST_SUITE("radiotap: field decoding");
    RUN_TEST(test_signal_only);
    RUN_TEST(test_channel_maps_frequency);
    RUN_TEST(test_flags_bad_fcs);
    RUN_TEST(test_rate_units);
    RUN_TEST(test_multiple_fields_in_bit_order);
    RUN_TEST(test_tsft_alignment_shifts_later_fields);

    TEST_SUITE("radiotap: extended present bitmaps");
    RUN_TEST(test_extended_present_bitmap_is_skipped_correctly);
    RUN_TEST(test_two_extended_bitmaps);
    RUN_TEST(test_truncated_extended_bitmap_rejected);

    TEST_SUITE("radiotap: malformed input");
    RUN_TEST(test_malformed_headers_rejected);
    RUN_TEST(test_failed_parse_leaves_defaults);
    RUN_TEST(test_field_past_header_end_not_read);

    TEST_SUITE("radiotap: frequency mapping");
    RUN_TEST(test_freq_to_channel_all_bands);
    RUN_TEST(test_freq_to_channel_unmapped_is_zero);
}
