#include <string.h>
#include <stdlib.h>
#include "runner.h"
#include "ctrl_frames.h"

/*
 * 802.11 control frames (type 1) — issue #64.
 *
 * Frames are built byte by byte from IEEE 802.11-2020 §9.3.1 per
 * agents/AGENTS.md. Control frames are short and their layouts differ
 * from each other, which is the whole hazard: RTS carries RA then TA,
 * CTS and ACK stop after RA, and PS-Poll puts an AID where the Duration
 * field otherwise sits.
 *
 * Frame Control byte 0 = (subtype << 4) | (type << 2) | version, so a
 * type-1 subtype-11 (RTS) frame starts 0xB4.
 */

static const uint8_t TA_A[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t RA_A[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

static uint8_t fc0(int subtype) {
    return (uint8_t)((subtype << 4) | (1 << 2));
}

/* RTS: FC(2) Duration(2) RA(6) TA(6) = 16 bytes before the FCS. */
static int build_rts(uint8_t *f, const uint8_t ta[6], uint16_t nav) {
    memset(f, 0, 16);
    f[0] = fc0(CTRL_SUB_RTS);
    f[2] = (uint8_t)(nav & 0xff);
    f[3] = (uint8_t)(nav >> 8);
    memcpy(f + 4,  RA_A, 6);
    memcpy(f + 10, ta,   6);
    return 16;
}

/* CTS / ACK: FC(2) Duration(2) RA(6) = 10 bytes. No transmitter. */
static int build_cts_or_ack(uint8_t *f, int subtype, uint16_t nav) {
    memset(f, 0, 10);
    f[0] = fc0(subtype);
    f[2] = (uint8_t)(nav & 0xff);
    f[3] = (uint8_t)(nav >> 8);
    memcpy(f + 4, RA_A, 6);
    return 10;
}

static void test_rts_counted_per_source_and_channel(void) {
    ctrl_clear();
    uint8_t f[24];
    int n = build_rts(f, TA_A, 100);
    ctrl_observe(f, n, 6, 1000);
    ASSERT_EQ(ctrl_source_count(TA_A, CTRL_SUB_RTS), 1);
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_RTS), 1);
    ASSERT_EQ(ctrl_channel_total(6), 1);
    ctrl_clear();
}

static void test_cts_and_ack_have_no_source(void) {
    /* The addressing constraint that shapes the whole module: CTS and
     * ACK carry only a Receiver Address. Attributing them to a
     * transmitter would mean inventing one — most likely by reading the
     * six bytes after RA, which in a 10-byte frame is off the end. */
    ctrl_clear();
    uint8_t f[16];
    int n = build_cts_or_ack(f, CTRL_SUB_CTS, 200);
    ctrl_observe(f, n, 6, 1000);
    n = build_cts_or_ack(f, CTRL_SUB_ACK, 0);
    ctrl_observe(f, n, 6, 1000);

    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_CTS), 1);
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_ACK), 1);
    ASSERT_EQ(ctrl_channel_total(6), 2);
    /* No source rows at all — not a row with a zero count. */
    ASSERT_EQ(ctrl_source_table_count(), 0);

    /* And the case that actually bites: a captured CTS carries a
     * 4-byte FCS, so it arrives at 14 bytes, and some drivers pad
     * further. A length-based guess at "is there a TA here" reads six
     * bytes past RA and invents a transmitter out of the checksum.
     * Attribution has to come from the subtype, not from the length. */
    memset(f, 0, sizeof(f));
    build_cts_or_ack(f, CTRL_SUB_CTS, 200);
    f[10] = 0xde; f[11] = 0xad; f[12] = 0xbe;
    f[13] = 0xef; f[14] = 0x00; f[15] = 0x01;
    ctrl_observe(f, 16, 6, 1000);
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_CTS), 2);
    ASSERT_EQ(ctrl_source_table_count(), 0);
    ctrl_clear();
}

static void test_management_and_data_frames_ignored(void) {
    ctrl_clear();
    uint8_t f[32];
    memset(f, 0, sizeof(f));
    f[0] = 0x80;                       /* beacon: type 0 */
    ctrl_observe(f, 32, 6, 1000);
    f[0] = 0x08;                       /* data: type 2   */
    ctrl_observe(f, 32, 6, 1000);
    ASSERT_EQ(ctrl_channel_total(6), 0);
    ctrl_clear();
}

static void test_group_addressed_transmitter_rejected(void) {
    ctrl_clear();
    static const uint8_t BCAST[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    uint8_t f[24];
    int n = build_rts(f, BCAST, 100);
    ctrl_observe(f, n, 6, 1000);
    /* Still counted for the channel — the airtime was spent either
     * way — but not attributed to a transmitter that cannot exist. */
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_RTS), 1);
    ASSERT_EQ(ctrl_source_table_count(), 0);
    ctrl_clear();
}

static void test_channels_counted_separately(void) {
    ctrl_clear();
    uint8_t f[24];
    int n = build_rts(f, TA_A, 100);
    ctrl_observe(f, n, 1,  1000);
    ctrl_observe(f, n, 11, 1000);
    ctrl_observe(f, n, 11, 1000);
    ASSERT_EQ(ctrl_channel_total(1),  1);
    ASSERT_EQ(ctrl_channel_total(11), 2);
    ctrl_clear();
}

static void test_unknown_channel_still_counts_the_source(void) {
    /* Channel 0 means the radiotap header carried no channel. The frame
     * was still transmitted by someone, and dropping it would make the
     * flood rule blind on captures with no channel information. */
    ctrl_clear();
    uint8_t f[24];
    int n = build_rts(f, TA_A, 100);
    ctrl_observe(f, n, 0, 1000);
    ASSERT_EQ(ctrl_source_count(TA_A, CTRL_SUB_RTS), 1);
    ASSERT_EQ(ctrl_channel_total(0), 0);
    ctrl_clear();
}

static void test_truncated_frames_are_safe(void) {
    ctrl_clear();
    uint8_t f[24];
    build_rts(f, TA_A, 100);
    /* One byte short of carrying a TA. Must count the channel and read
     * nothing past the end. */
    ctrl_observe(f, 15, 6, 1000);
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_RTS), 1);
    ASSERT_EQ(ctrl_source_table_count(), 0);
    /* Shorter than the Duration field. */
    ctrl_observe(f, 3, 6, 1000);
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_RTS), 1);
    ctrl_clear();
}

/* ── the flood rule's query ── */

static void feed_rts(const uint8_t ta[6], int n, uint16_t nav,
                     time_t start, time_t end) {
    uint8_t f[24];
    int len = build_rts(f, ta, nav);
    for (int i = 0; i < n; i++) {
        time_t t = (n == 1) ? start
                            : start + (time_t)((end - start) * i / (n - 1));
        ctrl_observe(f, len, 6, t);
    }
}

static void test_rts_flood_fires_at_rate_and_sustain(void) {
    ctrl_clear();
    int secs = RTS_FLOOD_SUSTAIN_S;
    feed_rts(TA_A, RTS_FLOOD_RATE * secs, 300, 1000, 1000 + secs);
    uint8_t ta[6]; int nav = 0, dur = 0;
    int n = ctrl_rts_flood(1000 + secs, 60, RTS_FLOOD_RATE,
                           RTS_FLOOD_SUSTAIN_S, ta, &nav, &dur);
    ASSERT(n >= RTS_FLOOD_RATE * secs);
    ASSERT(memcmp(ta, TA_A, 6) == 0);
    ASSERT_EQ(nav, 300);
    ASSERT_EQ(dur, secs);
    ctrl_clear();
}

static void test_rts_burst_shorter_than_sustain_is_quiet(void) {
    /* A client fighting interference emits RTS hard for a moment. The
     * sustain requirement is the whole difference between that and a
     * flood, so a burst at well above the rate must stay silent. */
    ctrl_clear();
    feed_rts(TA_A, RTS_FLOOD_RATE * 10, 300, 1000, 1001);
    ASSERT_EQ(ctrl_rts_flood(1001, 60, RTS_FLOOD_RATE,
                             RTS_FLOOD_SUSTAIN_S, NULL, NULL, NULL), 0);
    ctrl_clear();
}

static void test_rts_below_rate_is_quiet(void) {
    ctrl_clear();
    feed_rts(TA_A, RTS_FLOOD_RATE, 300, 1000, 1000 + RTS_FLOOD_SUSTAIN_S * 2);
    ASSERT_EQ(ctrl_rts_flood(1010, 60, RTS_FLOOD_RATE,
                             RTS_FLOOD_SUSTAIN_S, NULL, NULL, NULL), 0);
    ctrl_clear();
}

static void test_rts_flood_reports_the_highest_nav(void) {
    /* The NAV is what makes an RTS flood silence a channel rather than
     * merely occupy it, and a value above the legal maximum cannot come
     * from a conforming radio. */
    ctrl_clear();
    int secs = RTS_FLOOD_SUSTAIN_S;
    feed_rts(TA_A, RTS_FLOOD_RATE * secs, 100, 1000, 1000 + secs);
    uint8_t f[24];
    int len = build_rts(f, TA_A, CTRL_NAV_MAX_LEGAL + 1);
    ctrl_observe(f, len, 6, 1000 + secs);
    int nav = 0;
    ctrl_rts_flood(1000 + secs, 60, RTS_FLOOD_RATE, RTS_FLOOD_SUSTAIN_S,
                   NULL, &nav, NULL);
    ASSERT(nav > CTRL_NAV_MAX_LEGAL);
    ctrl_clear();
}

static void test_rts_flood_window_expires(void) {
    ctrl_clear();
    int secs = RTS_FLOOD_SUSTAIN_S;
    feed_rts(TA_A, RTS_FLOOD_RATE * secs, 300, 1000, 1000 + secs);
    ASSERT_EQ(ctrl_rts_flood(1000 + secs + 61, 60, RTS_FLOOD_RATE,
                             RTS_FLOOD_SUSTAIN_S, NULL, NULL, NULL), 0);
    ctrl_clear();
}

static void test_source_table_evicts_the_stalest(void) {
    ctrl_clear();
    uint8_t f[24], ta[6];
    memcpy(ta, TA_A, 6);
    for (int i = 0; i < CTRL_MAX_SOURCES + 8; i++) {
        ta[5] = (uint8_t)i;
        int n = build_rts(f, ta, 100);
        ctrl_observe(f, n, 6, 1000 + i);
    }
    ASSERT_EQ(ctrl_source_table_count(), CTRL_MAX_SOURCES);
    ctrl_clear();
}

static void test_snapshot_annotates_existing_rows_only(void) {
    /* The channel summary is rebuilt each poll from the frame ring.
     * Creating a row here would show a channel with no APs and no
     * clients on it — a channel nothing is actually using. */
    ctrl_clear();
    uint8_t f[24];
    int n = build_rts(f, TA_A, 100);
    ctrl_observe(f, n, 11, 1000);

    sloth_state_t *s = calloc(1, sizeof(*s));
    ASSERT(s != NULL);
    ctrl_snapshot(s);
    ASSERT_EQ(s->channel_count, 0);

    s->channels[0].channel = 11;
    s->channel_count = 1;
    ctrl_snapshot(s);
    ASSERT_EQ((int)s->channels[0].ctrl_rts, 1);
    ASSERT_EQ((int)s->channels[0].ctrl_total, 1);
    free(s);
    ctrl_clear();
}


/* ── Block-Ack paralysis (Bl0ck) — #70 ───────────────────── */

/* BAR: FC(2) Duration(2) RA(6) TA(6) BAR-Control(2) SSC(2) = 20 bytes.
 * BAR Control bits 12-15 are the TID; the Starting Sequence Control
 * puts the fragment number in bits 0-3 and the SSN in bits 4-15. */
static int build_bar(uint8_t *f, const uint8_t ra[6], const uint8_t ta[6],
                     int tid, uint16_t ssn, int multi_tid) {
    memset(f, 0, 20);
    f[0] = fc0(CTRL_SUB_BLOCKACK_REQ);
    memcpy(f + 4,  ra, 6);
    memcpy(f + 10, ta, 6);
    uint16_t ctl = (uint16_t)((tid << 12) | (multi_tid ? 0x0002 : 0));
    f[16] = (uint8_t)(ctl & 0xff);
    f[17] = (uint8_t)(ctl >> 8);
    uint16_t ssc = (uint16_t)(ssn << 4);
    f[18] = (uint8_t)(ssc & 0xff);
    f[19] = (uint8_t)(ssc >> 8);
    return 20;
}

static void test_ssn_forward_distance_basic(void) {
    ASSERT_EQ(bar_ssn_forward_distance(100, 150), 50);
    ASSERT_EQ(bar_ssn_forward_distance(100, 100), 0);
}

static void test_ssn_forward_distance_wraps(void) {
    /* The hazard the whole module rests on. SSN is 12 bits, so a
     * station transmitting steadily wraps roughly every 4096 frames —
     * which is often. A plain subtraction here gives -4080, and any
     * "jump > 128" test written on it either never fires or always
     * does, depending on the sign convention. */
    ASSERT_EQ(bar_ssn_forward_distance(4090, 10), 16);
    ASSERT_EQ(bar_ssn_forward_distance(4095, 0),  1);
    /* Backwards is a large forward distance, not a negative one — the
     * sequence space is a circle and there is no "behind". */
    ASSERT_EQ(bar_ssn_forward_distance(10, 4090), 4080);
}

static void test_bar_first_frame_sets_the_baseline(void) {
    /* Every connection sloth joins is joined mid-flight. Treating the
     * first observed SSN as a jump would flag all of them. */
    ctrl_clear();
    uint8_t f[24];
    int n = build_bar(f, RA_A, TA_A, 3, 2000, 0);
    ctrl_observe(f, n, 6, 1000);
    sloth_bar_state_t b;
    ASSERT_EQ(bar_find(RA_A, TA_A, 3, &b), 1);
    ASSERT_EQ((int)b.total_bars, 1);
    ASSERT_EQ((int)b.suspicious_bars, 0);
    ASSERT_EQ((int)b.last_ssn, 2000);
    ctrl_clear();
}

static void test_bar_ordinary_advance_is_not_suspicious(void) {
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 2000, 0), 6, 1000);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 2020, 0), 6, 1001);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 2064, 0), 6, 1002);
    sloth_bar_state_t b;
    bar_find(RA_A, TA_A, 3, &b);
    ASSERT_EQ((int)b.total_bars, 3);
    ASSERT_EQ((int)b.suspicious_bars, 0);
    ctrl_clear();
}

static void test_bar_large_jump_is_suspicious(void) {
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 2000, 0), 6, 1000);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3,
                              (uint16_t)(2000 + BAR_SUSPICIOUS_JUMP + 1),
                              0), 6, 1001);
    sloth_bar_state_t b;
    bar_find(RA_A, TA_A, 3, &b);
    ASSERT_EQ((int)b.suspicious_bars, 1);
    ASSERT_EQ((int)b.last_jump, BAR_SUSPICIOUS_JUMP + 1);
    ctrl_clear();
}

static void test_bar_wrap_is_not_a_jump(void) {
    /* The false-positive case that matters. 4090 -> 10 is a forward
     * advance of 16 frames across the wrap, not a jump of 4080. */
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 4090, 0), 6, 1000);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 10,   0), 6, 1001);
    sloth_bar_state_t b;
    bar_find(RA_A, TA_A, 3, &b);
    ASSERT_EQ((int)b.total_bars, 2);
    ASSERT_EQ((int)b.suspicious_bars, 0);
    ctrl_clear();
}

static void test_bar_state_is_per_tid(void) {
    /* Different traffic classes have independent sequence spaces.
     * Sharing state across TIDs would read every interleaved voice and
     * best-effort BAR as a jump. */
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 0, 100,  0), 6, 1000);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 6, 3000, 0), 6, 1000);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 0, 120,  0), 6, 1001);
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 6, 3020, 0), 6, 1001);
    ASSERT_EQ(bar_pair_count(), 2);
    sloth_bar_state_t b;
    bar_find(RA_A, TA_A, 0, &b);
    ASSERT_EQ((int)b.suspicious_bars, 0);
    bar_find(RA_A, TA_A, 6, &b);
    ASSERT_EQ((int)b.suspicious_bars, 0);
    ctrl_clear();
}

static void test_bar_multi_tid_skipped(void) {
    /* A multi-TID BAR carries a list rather than one TID. Reading its
     * layout as the single-TID one would invent both a TID and an SSN. */
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 2000, 1), 6, 1000);
    ASSERT_EQ(bar_pair_count(), 0);
    /* Still counted as a control frame — the airtime was spent. */
    ASSERT_EQ(ctrl_channel_subtype(6, CTRL_SUB_BLOCKACK_REQ), 1);
    ctrl_clear();
}

static void test_bar_worst_offender_and_window(void) {
    ctrl_clear();
    uint8_t f[24];
    ctrl_observe(f, build_bar(f, RA_A, TA_A, 3, 100, 0), 6, 1000);
    for (int i = 1; i <= 3; i++)
        ctrl_observe(f, build_bar(f, RA_A, TA_A, 3,
                                  (uint16_t)(100 + i * 500), 0), 6, 1000 + i);
    sloth_bar_state_t b;
    ASSERT_EQ(bar_worst_offender(1010, 300, &b), 3);
    ASSERT_EQ(b.tid, 3);
    ASSERT(memcmp(b.sta, TA_A, 6) == 0);
    /* Past the window there is nothing to report. */
    ASSERT_EQ(bar_worst_offender(1003 + 301, 300, NULL), 0);
    ctrl_clear();
}

static void test_bar_truncated_frame_is_safe(void) {
    ctrl_clear();
    uint8_t f[24];
    build_bar(f, RA_A, TA_A, 3, 2000, 0);
    ctrl_observe(f, 19, 6, 1000);      /* one byte short of the SSC */
    ASSERT_EQ(bar_pair_count(), 0);
    ctrl_clear();
}

void run_ctrl_frames_tests(void) {
    TEST_SUITE("control-frame counting (#64)");
    RUN_TEST(test_rts_counted_per_source_and_channel);
    RUN_TEST(test_cts_and_ack_have_no_source);
    RUN_TEST(test_management_and_data_frames_ignored);
    RUN_TEST(test_group_addressed_transmitter_rejected);
    RUN_TEST(test_channels_counted_separately);
    RUN_TEST(test_unknown_channel_still_counts_the_source);
    RUN_TEST(test_truncated_frames_are_safe);

    TEST_SUITE("RTS flood detection (#64)");
    RUN_TEST(test_rts_flood_fires_at_rate_and_sustain);
    RUN_TEST(test_rts_burst_shorter_than_sustain_is_quiet);
    RUN_TEST(test_rts_below_rate_is_quiet);
    RUN_TEST(test_rts_flood_reports_the_highest_nav);
    RUN_TEST(test_rts_flood_window_expires);
    RUN_TEST(test_source_table_evicts_the_stalest);
    RUN_TEST(test_snapshot_annotates_existing_rows_only);
    TEST_SUITE("Block-Ack paralysis / Bl0ck (#70)");
    RUN_TEST(test_ssn_forward_distance_basic);
    RUN_TEST(test_ssn_forward_distance_wraps);
    RUN_TEST(test_bar_first_frame_sets_the_baseline);
    RUN_TEST(test_bar_ordinary_advance_is_not_suspicious);
    RUN_TEST(test_bar_large_jump_is_suspicious);
    RUN_TEST(test_bar_wrap_is_not_a_jump);
    RUN_TEST(test_bar_state_is_per_tid);
    RUN_TEST(test_bar_multi_tid_skipped);
    RUN_TEST(test_bar_worst_offender_and_window);
    RUN_TEST(test_bar_truncated_frame_is_safe);
}
