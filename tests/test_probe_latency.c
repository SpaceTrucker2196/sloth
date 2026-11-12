/* Probe-response latency (#187 S3): src/probe_latency.c.
 *
 * Every frame is built per IEEE 802.11-2020 with tests/frame_build.h:
 * the management header of §9.3.3.1 (A1 = DA, A2 = SA, A3 = BSSID,
 * Sequence Control with the sequence number in bits 4..15), the Probe
 * Request body of §9.3.3.10 (elements only), the Probe Response fixed
 * fields of §9.3.3.11 (Timestamp, Beacon Interval, Capability), the SSID
 * element of §9.4.2.2 (a zero-length one is the wildcard), and the Retry
 * flag of Frame Control octet 1 (FB_RETRY). The clock each frame was
 * "captured" with is the test's own plat_clock_t, so latencies are
 * exact. No pcap fixtures. */

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "runner.h"
#include "probe_latency.h"
#include "dot11_frame.h"
#include "frame_build.h"

static const uint8_t BC[6]   = {0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t STA[6]  = {0x02,0x00,0x5e,0x10,0x00,0x01};
static const uint8_t STA2[6] = {0x02,0x00,0x5e,0x10,0x00,0x02};
static const uint8_t AP1[6]  = {0x02,0x00,0x5e,0x20,0x00,0x01};
static const uint8_t AP2[6]  = {0x02,0x00,0x5e,0x20,0x00,0x02};

#define F24 2437
#define F11 2462

static uint8_t g_buf[128];
static int     g_len;

static void mk_preq(const uint8_t sta[6], const uint8_t a3[6],
                    const char *ssid, int seq, uint8_t flags) {
    fb_t b; fb_init(&b, g_buf, (int)sizeof g_buf);
    fb_mgmt(&b, 4, flags, a3, sta, a3, (uint16_t)(seq << 4), 0);
    fb_ssid(&b, ssid);
    static const uint8_t rates[4] = {0x02, 0x04, 0x0b, 0x16};
    fb_ie(&b, 1, rates, 4);
    ASSERT(fb_ok(&b));
    g_len = b.len;
}

static void mk_presp(const uint8_t da[6], const uint8_t bssid[6],
                     const char *ssid, int seq, uint8_t flags) {
    fb_t b; fb_init(&b, g_buf, (int)sizeof g_buf);
    fb_mgmt(&b, 5, flags, da, bssid, bssid, (uint16_t)(seq << 4), 0);
    fb_beacon_fixed(&b, 0x1122334455667788ULL, 100, 0x0001);
    fb_ssid(&b, ssid);
    ASSERT(fb_ok(&b));
    g_len = b.len;
}

/* Feed the frame in g_buf. tsft 0 means "no TSFT field". */
static void feed_full(int freq, uint64_t tsft, int64_t pcap_us, int bad_fcs) {
    dot11_rt_hints_t h = { 0, 0, bad_fcs };
    dot11_frame_t fr;
    dot11_frame_decode(g_buf, g_len, &h, &fr);
    plat_clock_t c;
    memset(&c, 0, sizeof c);
    c.freq_mhz = freq;
    c.has_tsft = tsft != 0;
    c.tsft_us  = tsft;
    c.ts_sec   = (long)(pcap_us / 1000000);
    c.ts_usec  = (long)(pcap_us % 1000000);
    probe_latency_observe(&fr, &c);
}

static void feed(int freq, uint64_t tsft, int64_t pcap_us) {
    feed_full(freq, tsft, pcap_us, 0);
}

#define T0 1700000000000000LL   /* pcap µs: an ordinary epoch time */

static plat_counters_t ct(void) {
    plat_counters_t c; probe_latency_counters(&c); return c;
}

/* Directed request, answered 2.5 ms later on the receiver's TSF. The
 * pcap stamps say 9 ms, so the figure shows which clock was used. */
static void test_directed_pair_uses_tsft(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 5000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 5002500, T0 + 9000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ(r.src, PLAT_SRC_TSFT);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].n, 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].med_us, 2500);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].n, 0);
    ASSERT_EQ((int)ct().pairs, 1);
}

/* No TSFT on either frame, or on only one of them: both ends come from
 * the pcap stamp, never one from each clock. */
static void test_pcap_fallback_and_no_mixing(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 0, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 0, T0 + 4100);
    mk_preq(STA2, BC, "corp-net", 200, 0);         feed(F24, 7000000, T0 + 50000);
    mk_presp(STA2, AP2, "corp-net", 8, 0);         feed(F24, 0, T0 + 53300);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ(r.src, PLAT_SRC_PCAP);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].med_us, 4100);
    ASSERT_EQ(probe_latency_get(AP2, &r), 1);
    ASSERT_EQ(r.src, PLAT_SRC_PCAP);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].med_us, 3300);
}

/* A wildcard request is answered by every AP in range; each BSSID gets
 * its own wildcard sample, and a directed sample is not recorded. */
static void test_wildcard_pairs_with_every_bssid(void) {
    mk_preq(STA, BC, "", 100, 0);                  feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1001000, T0 + 1000);
    mk_presp(STA, AP2, "guest", 9, 0);             feed(F24, 1003000, T0 + 3000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].n, 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].med_us, 1000);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].n, 0);
    ASSERT_EQ(probe_latency_get(AP2, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].med_us, 3000);
}

/* The response must name the requested SSID, and a request addressed
 * to one BSSID is that BSSID's to answer. Seen red with the SSID
 * comparison removed from on_response() (the "other-net" answer then
 * paired). */
static void test_ssid_and_bssid_must_match(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "other-net", 7, 0);         feed(F24, 1001000, T0 + 1000);
    mk_preq(STA2, AP1, "corp-net", 300, 0);        feed(F24, 1100000, T0 + 100000);
    mk_presp(STA2, AP2, "corp-net", 8, 0);         feed(F24, 1101000, T0 + 101000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ(probe_latency_get(AP2, &r), 0);
    ASSERT_EQ((int)ct().resp_unpaired, 2);
    ASSERT_EQ((int)ct().pairs, 0);
}

/* A response with Retry set is a retransmission: its latency includes
 * the lost first copy, so it is never paired — not even when the first
 * copy was not heard. Seen red with the Retry check removed. */
static void test_response_retry_is_ignored(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, FB_RETRY);   feed(F24, 1004000, T0 + 4000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().resp_retry, 1);
    /* Control: a first transmission to a fresh request (outside the
     * first one's horizon) does pair. */
    mk_preq(STA, BC, "corp-net", 101, 0);          feed(F24, 1300000, T0 + 300000);
    mk_presp(STA, AP1, "corp-net", 8, 0);          feed(F24, 1302000, T0 + 302000);
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].med_us, 2000);
}

/* The same request heard twice under one sequence number (a directed
 * probe is acknowledged and so retried): which copy the AP answered is
 * unknowable, so the pair is void. Seen red with the dup flag ignored
 * in on_response() (the answer then paired against the first copy). */
static void test_request_retransmission_voids_the_pair(void) {
    mk_preq(STA, AP1, "corp-net", 100, 0);         feed(F24, 1000000, T0);
    mk_preq(STA, AP1, "corp-net", 100, FB_RETRY);  feed(F24, 1001500, T0 + 1500);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1003000, T0 + 3000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().req_dup, 1);
    ASSERT_EQ((int)ct().resp_ambiguous, 1);
}

/* hostapd-mana answers one wildcard probe with a response per
 * remembered SSID; airbase-ng sends a broadcast-probe answer three
 * times. Only the first answer from a BSSID to a request is a latency.
 * Seen red with the last-answered check removed (n and the extra tally
 * both wrong). */
static void test_extra_answers_are_not_latencies(void) {
    mk_preq(STA, BC, "", 100, 0);                  feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "home", 7, 0);              feed(F24, 1001000, T0 + 1000);
    mk_presp(STA, AP1, "work", 8, 0);              feed(F24, 1001400, T0 + 1400);
    mk_presp(STA, AP1, "cafe", 9, 0);              feed(F24, 1001800, T0 + 1800);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].n, 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_WILDCARD].med_us, 1000);
    ASSERT_EQ((int)ct().resp_extra, 2);
}

/* Two live requests the one response could answer: no pair. */
static void test_two_candidates_are_ambiguous(void) {
    mk_preq(STA, BC, "", 100, 0);                  feed(F24, 1000000, T0);
    mk_preq(STA, BC, "corp-net", 101, 0);          feed(F24, 1000300, T0 + 300);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1002000, T0 + 2000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().resp_ambiguous, 1);
}

/* --hop: a retune between request and response voids the pair, even
 * when the radio comes back to the same channel inside the pairing
 * horizon. Seen red with the dwell comparison removed from
 * on_response(). */
static void test_channel_retune_invalidates(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    /* Any frame heard on another channel marks the dwell boundary. */
    mk_presp(STA2, AP2, "x", 5, 0);                feed(F11, 1030000, T0 + 30000);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1060000, T0 + 60000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().dwells, 2);
    ASSERT_EQ((int)ct().pairs, 0);

    /* Response heard on the other channel outright: also no pair. */
    probe_latency_reset();
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F11, 1002000, T0 + 2000);
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);

    /* Control: the same pair inside one dwell does pair. */
    probe_latency_reset();
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1060000, T0 + 60000);
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
}

/* A frame with no radiotap frequency cannot be placed in a dwell. */
static void test_no_frequency_never_pairs(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(0, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(0, 1002000, T0 + 2000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().no_freq, 2);
}

/* An FCS-failed frame still marks the dwell (its frequency is the
 * radio's) but is never paired. */
static void test_bad_fcs_marks_dwell_but_never_pairs(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed_full(F24, 1000000, T0, 1);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 1002000, T0 + 2000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    mk_presp(STA2, AP2, "x", 5, 0);                feed_full(F11, 1003000, T0 + 3000, 1);
    ASSERT_EQ((int)ct().dwells, 1);
}

/* The pairing horizon is inclusive at PLAT_PAIR_MAX_US. Seen red with
 * the horizon widened by 1 µs (the 200001 µs answer then paired). */
static void test_pairing_horizon(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);
    feed(F24, 1000000 + PLAT_PAIR_MAX_US, T0 + PLAT_PAIR_MAX_US);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ(r.kind[PLAT_KIND_DIRECTED].med_us, PLAT_PAIR_MAX_US);

    probe_latency_reset();
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);
    feed(F24, 1000001 + PLAT_PAIR_MAX_US, T0 + PLAT_PAIR_MAX_US + 1);
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
}

/* A response stamped before its request on the receiver's TSF is not a
 * negative latency. */
static void test_tsft_backwards_is_refused(void) {
    mk_preq(STA, BC, "corp-net", 100, 0);          feed(F24, 1000000, T0);
    mk_presp(STA, AP1, "corp-net", 7, 0);          feed(F24, 999000, T0 + 1000);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 0);
    ASSERT_EQ((int)ct().clock_backwards, 1);
}

static void pair_once(const uint8_t ap[6], int i, uint32_t us, int tsft) {
    int64_t t = T0 + (int64_t)i * 300000;
    mk_preq(STA, BC, "corp-net", i & 0xfff, 0);
    feed(F24, tsft ? (uint64_t)t : 0, t);
    mk_presp(STA, ap, "corp-net", i & 0xfff, 0);
    feed(F24, tsft ? (uint64_t)t + us : 0, t + us);
}

/* Nearest-rank statistics over the window, and the window's bound. */
static void test_stats_and_window(void) {
    for (int i = 1; i <= 10; i++) pair_once(AP1, i, (uint32_t)(i * 1000), 1);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    const plat_stats_t *d = &r.kind[PLAT_KIND_DIRECTED];
    ASSERT_EQ((int)d->n, 10);
    ASSERT_EQ((int)d->min_us, 1000);
    ASSERT_EQ((int)d->p10_us, 1000);
    ASSERT_EQ((int)d->med_us, 5000);
    ASSERT_EQ((int)d->p90_us, 9000);

    probe_latency_reset();
    for (int i = 1; i <= PLAT_SAMPLES + 8; i++)
        pair_once(AP1, i, (uint32_t)(i * 100), 1);
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].n, PLAT_SAMPLES);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].min_us, 900);
    ASSERT_EQ((int)r.pairs_total, PLAT_SAMPLES + 8);
}

/* One clock per BSSID: TSFT replaces a PCAP history, a PCAP sample is
 * refused by a TSFT row. */
static void test_one_clock_per_row(void) {
    pair_once(AP1, 1, 4000, 0);
    pair_once(AP1, 2, 4000, 0);
    pair_once(AP1, 3, 1500, 1);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ(r.src, PLAT_SRC_TSFT);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].n, 1);
    ASSERT_EQ((int)ct().src_switch, 1);
    pair_once(AP1, 4, 4000, 0);
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].n, 1);
    ASSERT_EQ((int)ct().src_mismatch, 1);
}

/* Both tables are bounded and every loss is tallied. Seen red with the
 * evict_bss bump removed (tally 0). */
static void test_tables_are_bounded(void) {
    for (int i = 0; i <= PLAT_MAX_BSS; i++) {
        uint8_t ap[6] = {0x02, 0x00, 0x5e, 0x30, (uint8_t)(i >> 8), (uint8_t)i};
        pair_once(ap, i + 1, 1000, 1);
    }
    probe_latency_row_t rows[PLAT_MAX_BSS + 4];
    ASSERT_EQ(probe_latency_snapshot(rows, PLAT_MAX_BSS + 4), PLAT_MAX_BSS);
    ASSERT_EQ((int)ct().evict_bss, 1);
    const uint8_t first[6] = {0x02, 0x00, 0x5e, 0x30, 0, 0};
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(first, &r), 0);

    /* PLAT_PENDING + 1 live, unanswered requests from distinct
     * stations inside one horizon: one is overwritten and counted. */
    probe_latency_reset();
    for (int i = 0; i <= PLAT_PENDING; i++) {
        uint8_t sta[6] = {0x02, 0x00, 0x5e, 0x40, 0, (uint8_t)i};
        mk_preq(sta, BC, "corp-net", i, 0);
        feed(F24, 1000000 + (uint64_t)i * 10, T0 + i * 10);
    }
    ASSERT_EQ((int)ct().evict_pending, 1);
}

/* The capture thread writes while the poll thread reads. Seen red under
 * -fsanitize=thread with the lock removed from probe_latency_snapshot()
 * (four data-race reports); the plain build asserts only the totals,
 * which a race need not disturb. */
#define MT_ROUNDS 400
static void *mt_writer(void *arg) {
    (void)arg;
    for (int i = 1; i <= MT_ROUNDS; i++) {
        uint8_t buf[128];
        int64_t t = T0 + (int64_t)i * 300000;
        dot11_frame_t fr;
        plat_clock_t c = { F24, 1, (uint64_t)t, (long)(t / 1000000),
                           (long)(t % 1000000) };
        fb_t b; fb_init(&b, buf, (int)sizeof buf);
        fb_mgmt(&b, 4, 0, BC, STA, BC, (uint16_t)((i & 0xfff) << 4), 0);
        fb_ssid(&b, "corp-net");
        dot11_frame_decode(buf, b.len, NULL, &fr);
        probe_latency_observe(&fr, &c);
        fb_init(&b, buf, (int)sizeof buf);
        fb_mgmt(&b, 5, 0, STA, AP1, AP1, (uint16_t)((i & 0xfff) << 4), 0);
        fb_beacon_fixed(&b, 0, 100, 1);
        fb_ssid(&b, "corp-net");
        dot11_frame_decode(buf, b.len, NULL, &fr);
        c.tsft_us += 1234; c.ts_usec += 1234;
        if (c.ts_usec >= 1000000) { c.ts_sec++; c.ts_usec -= 1000000; }
        probe_latency_observe(&fr, &c);
    }
    return NULL;
}

static void test_reader_and_writer_threads(void) {
    pthread_t th;
    ASSERT_EQ(pthread_create(&th, NULL, mt_writer, NULL), 0);
    probe_latency_row_t rows[4];
    for (int k = 0; k < 2000; k++) {
        int n = probe_latency_snapshot(rows, 4);
        if (n == 1 && rows[0].kind[PLAT_KIND_DIRECTED].n > 0 &&
            rows[0].kind[PLAT_KIND_DIRECTED].med_us != 1234) break;
    }
    pthread_join(th, NULL);
    probe_latency_row_t r;
    ASSERT_EQ(probe_latency_get(AP1, &r), 1);
    ASSERT_EQ((int)r.pairs_total, MT_ROUNDS);
    ASSERT_EQ((int)r.kind[PLAT_KIND_DIRECTED].med_us, 1234);
    ASSERT_EQ((int)ct().pairs, MT_ROUNDS);
}

void run_probe_latency_tests(void) {
    RUN_TEST(test_directed_pair_uses_tsft);
    RUN_TEST(test_pcap_fallback_and_no_mixing);
    RUN_TEST(test_wildcard_pairs_with_every_bssid);
    RUN_TEST(test_ssid_and_bssid_must_match);
    RUN_TEST(test_response_retry_is_ignored);
    RUN_TEST(test_request_retransmission_voids_the_pair);
    RUN_TEST(test_extra_answers_are_not_latencies);
    RUN_TEST(test_two_candidates_are_ambiguous);
    RUN_TEST(test_channel_retune_invalidates);
    RUN_TEST(test_no_frequency_never_pairs);
    RUN_TEST(test_bad_fcs_marks_dwell_but_never_pairs);
    RUN_TEST(test_pairing_horizon);
    RUN_TEST(test_tsft_backwards_is_refused);
    RUN_TEST(test_stats_and_window);
    RUN_TEST(test_one_clock_per_row);
    RUN_TEST(test_tables_are_bounded);
    RUN_TEST(test_reader_and_writer_threads);
}
