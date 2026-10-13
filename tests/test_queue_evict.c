#include <string.h>
#include "runner.h"
#include "queue_evict.h"
#include "sensor_health.h"

/*
 * Transmit-queue release after a session change — #107 shape B,
 * Framing Frames CVE-2022-47522.
 *
 * Hand-built 802.11 data-frame headers per IEEE 802.11-2020 §9.2.4.1
 * (Frame Control: type, subtype, ToDS/FromDS) and §9.3.2.1 Table 9-26
 * (which address field is which in each direction). No payload is
 * needed: queue_evict_observe_downlink() reads the header only, so a
 * frame is FC + Duration + three addresses + Sequence Control, plus
 * QoS Control for a QoS subtype. No pcap fixtures.
 *
 * The session-change half takes addresses directly rather than a
 * frame, so these cases cover the module. The probe.c wiring that
 * supplies those addresses — in particular the status==0 gate on a
 * reassociation response, and which of addr1/addr2 is the station on a
 * deauth — is not reachable from this binary (src/capture/probe.c is
 * absent from TEST_SRCS); it is covered in tests/test_capture_path.c,
 * which links the real callback.
 */

#define SUB_DATA     0x0
#define SUB_QOS_DATA 0x8
#define SUB_NULL     0x4
#define SUB_QOS_NULL 0xC

static const uint8_t BSSID[6]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t BSSID2[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x66 };
static const uint8_t STA_A[6]  = { 0x02, 0xAA, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t STA_B[6]  = { 0x02, 0xBB, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t BCAST[6]  = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/* AP -> STA: ToDS=0, FromDS=1. addr1=DA addr2=BSSID addr3=SA. */
/* `seq` is the 12-bit Sequence Number (§9.2.4.4) in the high 12 bits of
 * Sequence Control at offset 22; `retry` sets the Retry bit (§9.2.4.1.6).
 *
 * Both are parameters because the threshold counts DISTINCT frames. The
 * first version of this helper built one frame and the burst helper fed
 * it n times, so every frame in every test carried sequence 0 and no
 * Retry bit — which meant the suite reached the threshold with n copies
 * of one frame and could not have noticed that ordinary retransmission
 * did the same thing on a real radio. The test harness was reproducing
 * the defect it was supposed to be checking for. */
static int build_downlink_seq(uint8_t *f, int sub, const uint8_t bssid[6],
                              const uint8_t da[6], int seq, int retry) {
    memset(f, 0, 32);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = (uint8_t)(0x02 | (retry ? 0x08 : 0));   /* FromDS [| Retry] */
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, bssid, 6);
    memcpy(f + 16, bssid, 6);          /* SA — the AP's own address */
    f[22] = (uint8_t)((seq & 0x0f) << 4);
    f[23] = (uint8_t)((seq >> 4) & 0xff);
    return (sub & 0x08) ? 26 : 24;
}

static int build_downlink(uint8_t *f, int sub, const uint8_t bssid[6],
                          const uint8_t da[6]) {
    return build_downlink_seq(f, sub, bssid, da, 0, 0);
}

/* STA -> AP: ToDS=1, FromDS=0. addr1=BSSID addr2=SA addr3=DA. */
static int build_uplink(uint8_t *f, int sub, const uint8_t bssid[6],
                        const uint8_t sta[6]) {
    memset(f, 0, 32);
    f[0] = (uint8_t)((sub << 4) | (2 << 2));
    f[1] = 0x01;                       /* ToDS */
    memcpy(f + 4,  bssid, 6);
    memcpy(f + 10, sta,   6);
    memcpy(f + 16, bssid, 6);
    return (sub & 0x08) ? 26 : 24;
}

static void setup(void) {
    queue_evict_clear();
    sh_evict_reset();
}

/* n downlink frames to `da`, the first `first_ms` after t=1000.000000
 * and one every `step_ms` after that. */
static void downlink_burst(const uint8_t bssid[6], const uint8_t da[6],
                           int n, int first_ms, int step_ms) {
    uint8_t f[32];
    for (int i = 0; i < n; i++) {
        /* A DISTINCT frame each time — an incrementing sequence number,
           which is what a real burst of released frames looks like. */
        int len = build_downlink_seq(f, SUB_QOS_DATA, bssid, da, 100 + i, 0);
        queue_evict_observe_downlink(f, len, 1000,
                                     (long)(first_ms + i * step_ms) * 1000);
    }
}

/* The same frame over and over: one MSDU the AP keeps retrying. */
static void downlink_retries(const uint8_t bssid[6], const uint8_t da[6],
                             int n, int first_ms, int step_ms, int retry_bit) {
    uint8_t f[32];
    int len = build_downlink_seq(f, SUB_QOS_DATA, bssid, da, 100, retry_bit);
    for (int i = 0; i < n; i++)
        queue_evict_observe_downlink(f, len, 1000,
                                     (long)(first_ms + i * step_ms) * 1000);
}

/* ── The threshold counts DISTINCT frames (#107) ───────────
 *
 * QUEUE_EVICT_MIN_FRAMES is the detector's only discriminating
 * constant, and review measured it as non-discriminating: 802.11
 * retransmits an unacknowledged MSDU with the same Sequence Number, so
 * one frame retried twice reached the threshold. On a lossy link that is
 * ordinary behaviour, not a queued-frame release.
 *
 * Both guards are tested because they answer the same question by
 * different means and either alone leaves a gap: the Retry bit is the
 * transmitter saying "this is a repeat", and the sequence number is the
 * authoritative identity of the MSDU for a driver that rebuilds the
 * frame without setting it. */
static void test_retried_frames_do_not_reach_the_threshold(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Five deliveries of ONE frame, Retry set — a lossy link. */
    downlink_retries(BSSID, STA_A, 5, 10, 10, 1);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 1);
    ASSERT_EQ((long long)out.release_count, 0);
    ASSERT_EQ((long long)out.burst_frames, 0);
}

static void test_repeated_sequence_without_retry_bit_is_one_frame(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Same sequence number, Retry CLEAR — the driver-rebuild case the
       Retry test alone would miss. It is still one MSDU. */
    downlink_retries(BSSID, STA_A, 5, 10, 10, 0);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 1);
    ASSERT_EQ((long long)out.burst_frames, 1);
    ASSERT_EQ((long long)out.release_count, 0);
}

static void test_sequence_zero_is_a_real_first_frame(void) {
    /* burst_last_seq starts at -1, not the memset's 0, because sequence
       number 0 is legal. Zeroed, the first frame of a burst would look
       like a repeat of itself and no release could ever be recorded
       after a wrap. */
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    uint8_t f[32];
    for (int i = 0; i < 3; i++) {
        int len = build_downlink_seq(f, SUB_QOS_DATA, BSSID, STA_A, i, 0);
        queue_evict_observe_downlink(f, len, 1000, (long)(10 + i * 10) * 1000);
    }
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 1);
    ASSERT_EQ((long long)out.burst_frames, 3);
    ASSERT_EQ((long long)out.release_count, 1);
}

static void test_a_new_session_change_forgets_the_last_sequence(void) {
    /* Otherwise a second release that happens to open on the sequence
       number the previous burst ended on loses its first frame. */
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    uint8_t f[32];
    int len = build_downlink_seq(f, SUB_QOS_DATA, BSSID, STA_A, 77, 0);
    queue_evict_observe_downlink(f, len, 1000, 10000);

    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1001, 0);
    /* Same sequence number as the previous burst's last frame. */
    queue_evict_observe_downlink(f, len, 1001, 10000);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 1);
    ASSERT_EQ((long long)out.burst_frames, 1);
}

/* ── The AP->STA direction guard (#107) ───────────────────
 *
 * Review found it completely untested: `if (0 && (to_ds || !from_ds))`
 * left BOTH suites green. The existing uplink case could not catch it,
 * because build_uplink() sets addr3 = BSSID and under ToDS=1 addr3 is
 * the DA, so find_pair(bssid, da) looked up (BSSID, BSSID) and missed
 * whether or not the guard ran.
 *
 * This builds an uplink whose DA really is the tracked station, so the
 * lookup WOULD match if the guard were removed. An uplink frame is the
 * station talking; it says nothing about the AP's buffer. */
static void test_uplink_addressed_to_the_station_is_still_ignored(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    uint8_t f[32];
    memset(f, 0, sizeof(f));
    f[0] = (uint8_t)((SUB_QOS_DATA << 4) | (2 << 2));
    f[1] = 0x01;                        /* ToDS only — uplink */
    memcpy(f + 4,  BSSID, 6);           /* addr1 = BSSID */
    memcpy(f + 10, STA_A, 6);           /* addr2 = SA    */
    memcpy(f + 16, STA_A, 6);           /* addr3 = DA — the tracked STA */
    f[22] = 0x10;                       /* seq 1 */
    for (int i = 0; i < 5; i++)
        queue_evict_observe_downlink(f, 26, 1000, (long)(10 + i * 10) * 1000);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 1);
    ASSERT_EQ((long long)out.burst_frames, 0);
    ASSERT_EQ((long long)out.release_count, 0);
}

static void test_no_rows_initially(void) {
    setup();
    ASSERT_EQ(queue_evict_count(), 0);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 0);
}

static void test_downlink_without_a_session_change_creates_no_row(void) {
    setup();
    /* Ordinary downlink traffic to a station whose session sloth never
     * saw change. If this created a row, the table would churn through
     * every client on the air and the eviction tally would be noise. */
    downlink_burst(BSSID, STA_A, 10, 0, 1);
    ASSERT_EQ(queue_evict_count(), 0);
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &out), 0);
}

static void test_burst_after_reassociation_is_recorded(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Five unicast downlink frames at +10, +20, +30, +40, +50 ms — all
     * inside the 100 ms window. */
    downlink_burst(BSSID, STA_A, 5, 10, 10);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 5);
    ASSERT_EQ((int)e.release_count, 1);
    ASSERT_EQ((int)e.last_release_frames, 5);
    /* Span of the burst: +10 ms to +50 ms. */
    ASSERT_EQ(e.last_release_span_ms, 40);
    ASSERT_EQ(e.last_release_src, QUEUE_EVICT_SRC_REASSOC);
    ASSERT_EQ((long long)e.last_release_ts, 1000LL);
}

static void test_burst_outside_the_window_is_not_recorded(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* The same five frames, 150 ms after the event. An AP that has just
     * admitted a roaming station keeps sending to it for seconds; only
     * the immediate flush is the shape this module is about. */
    downlink_burst(BSSID, STA_A, 5, 150, 10);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
    ASSERT_EQ((int)e.release_count, 0);
}

static void test_the_window_edge_is_inclusive(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* +98, +99, +100 ms: the last one lands exactly on the bound. */
    downlink_burst(BSSID, STA_A, 3, 98, 1);
    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 3);
    ASSERT_EQ((int)e.release_count, 1);

    /* +101 ms is outside, so it neither counts nor opens a second
     * release. */
    downlink_burst(BSSID, STA_A, 1, 101, 1);
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 3);
    ASSERT_EQ((int)e.release_count, 1);
}

static void test_group_addressed_downlink_is_not_counted(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Broadcast/multicast downlink traffic is buffered against the
     * BSS's DTIM schedule, not against one station's queue.
     *
     * **This case cannot be isolated and does not claim to be.**
     * Disabling `dot11_is_group_addr(da)` in the observer leaves the
     * whole suite green (measured, not assumed), because a row is only
     * ever created for a non-group station, so the (BSSID, group-DA)
     * lookup finds nothing either way. What is asserted below is the
     * property that does hold: group traffic neither reaches STA_A's
     * burst nor conjures a row of its own. */
    downlink_burst(BSSID, BCAST, 5, 10, 10);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
    ASSERT_EQ((int)e.release_count, 0);
    /* And it did not conjure a row of its own either. */
    ASSERT_EQ(queue_evict_count(), 1);
}

static void test_uplink_in_the_window_is_not_counted(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* The station transmitting is not the AP emptying a buffer. On a
     * ToDS frame addr2 is the station, so a direction bug here would
     * read the station's own traffic as a release. */
    uint8_t f[32];
    int len = build_uplink(f, SUB_QOS_DATA, BSSID, STA_A);
    for (int i = 0; i < 5; i++)
        queue_evict_observe_downlink(f, len, 1000, (long)(10 + i * 10) * 1000);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
}

static void test_payloadless_downlink_is_not_counted(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Null and QoS-Null carry nothing: an AP polling or keeping the
     * session alive delivered no queued frame. */
    uint8_t f[32];
    int len = build_downlink(f, SUB_QOS_NULL, BSSID, STA_A);
    for (int i = 0; i < 3; i++)
        queue_evict_observe_downlink(f, len, 1000, (long)(10 + i * 10) * 1000);
    len = build_downlink(f, SUB_NULL, BSSID, STA_A);
    for (int i = 0; i < 3; i++)
        queue_evict_observe_downlink(f, len, 1000, (long)(50 + i * 10) * 1000);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
}

static void test_below_threshold_burst_is_not_a_release(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_ASSOC,
                                    1000, 0);
    /* Two frames after an association is an ARP reply and a DHCP ACK. */
    downlink_burst(BSSID, STA_A, QUEUE_EVICT_MIN_FRAMES - 1, 10, 10);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, QUEUE_EVICT_MIN_FRAMES - 1);
    ASSERT_EQ((int)e.release_count, 0);
    ASSERT_EQ((int)e.last_release_frames, 0);
}

static void test_out_of_order_downlink_does_not_count(void) {
    setup();
    /* Session change stamped at +50 ms... */
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 50000);
    /* ...and the downlink frames stamped EARLIER, which out-of-order
     * capture delivery does produce. A frame that was already on the
     * air before the session changed cannot be part of what that change
     * released, whatever order the two reached the module in. */
    downlink_burst(BSSID, STA_A, 5, 10, 5);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
    ASSERT_EQ((int)e.release_count, 0);
}

static void test_distinct_pairs_stay_isolated(void) {
    setup();
    queue_evict_note_session_change(BSSID,  STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    queue_evict_note_session_change(BSSID,  STA_B, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    /* Same station, different BSS: a separate row, because the queue
     * being emptied belongs to one AP. */
    queue_evict_note_session_change(BSSID2, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    ASSERT_EQ(queue_evict_count(), 3);

    downlink_burst(BSSID, STA_A, 4, 10, 10);

    queue_evict_t a, b, a2;
    ASSERT_EQ(queue_evict_lookup(BSSID,  STA_A, &a),  1);
    ASSERT_EQ(queue_evict_lookup(BSSID,  STA_B, &b),  1);
    ASSERT_EQ(queue_evict_lookup(BSSID2, STA_A, &a2), 1);
    ASSERT_EQ((int)a.release_count,  1);
    ASSERT_EQ((int)b.burst_frames,   0);
    ASSERT_EQ((int)a2.burst_frames,  0);
}

static void test_a_new_session_change_resets_the_burst(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    downlink_burst(BSSID, STA_A, 5, 10, 10);

    /* A second event one second later, followed by too little traffic
     * to be a release. The recorded evidence must still describe the
     * burst that actually was one. */
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_DISCONNECT,
                                    1001, 0);
    uint8_t f[32];
    int len = build_downlink(f, SUB_QOS_DATA, BSSID, STA_A);
    queue_evict_observe_downlink(f, len, 1001, 10000);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 1);
    ASSERT_EQ((int)e.release_count, 1);
    ASSERT_EQ((int)e.last_release_frames, 5);
    ASSERT_EQ(e.last_release_src, QUEUE_EVICT_SRC_REASSOC);
    ASSERT_EQ(e.event_src, QUEUE_EVICT_SRC_DISCONNECT);
}

static void test_disconnect_opens_a_window_too(void) {
    setup();
    /* The other route in the paper: the AP has already torn the key out
     * of its key store but still transmits what it queued. */
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_DISCONNECT,
                                    1000, 0);
    downlink_burst(BSSID, STA_A, 3, 5, 5);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.release_count, 1);
    ASSERT_EQ(e.last_release_src, QUEUE_EVICT_SRC_DISCONNECT);
}

static void test_a_group_addressed_station_opens_no_window(void) {
    setup();
    /* A broadcast deauth ends every session on the BSS and names none
     * of them. One ff:ff:ff:ff:ff:ff row would collect the downlink
     * traffic of every station on the network. */
    queue_evict_note_session_change(BSSID, BCAST, QUEUE_EVICT_SRC_DISCONNECT,
                                    1000, 0);
    ASSERT_EQ(queue_evict_count(), 0);
}

static void test_an_unknown_source_opens_no_window(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, 99, 1000, 0);
    queue_evict_note_session_change(BSSID, STA_A, -1,  1000, 0);
    ASSERT_EQ(queue_evict_count(), 0);
}

static void test_short_and_non_data_frames_are_ignored(void) {
    setup();
    queue_evict_note_session_change(BSSID, STA_A, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    uint8_t f[32];
    int len = build_downlink(f, SUB_QOS_DATA, BSSID, STA_A);
    for (int i = 0; i < 4; i++) {
        queue_evict_observe_downlink(NULL, len, 1000, 10000);
        queue_evict_observe_downlink(f, 23, 1000, 10000);   /* below 24 */
    }
    /* Management frame framing, same addresses. */
    uint8_t m[32];
    memcpy(m, f, 32);
    m[0] = 0x00;                       /* type 0, subtype 0 */
    for (int i = 0; i < 4; i++)
        queue_evict_observe_downlink(m, 24, 1000, 10000);

    queue_evict_t e;
    ASSERT_EQ(queue_evict_lookup(BSSID, STA_A, &e), 1);
    ASSERT_EQ((int)e.burst_frames, 0);
}

static void test_table_full_evicts_the_stalest_and_counts_it(void) {
    setup();
    uint8_t sta[6] = { 0x02, 0, 0, 0, 0, 0 };
    for (int i = 0; i < MAX_QUEUE_EVICT_ENTRIES; i++) {
        sta[5] = (uint8_t)i;
        queue_evict_note_session_change(BSSID, sta, QUEUE_EVICT_SRC_REASSOC,
                                        1000 + i, 0);
    }
    ASSERT_EQ(queue_evict_count(), MAX_QUEUE_EVICT_ENTRIES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_QUEUE_EVICT), 0);

    /* One more pair overflows; the least-recently-seen row (sta[5]==0,
     * stamped t=1000) is the one that goes, and the table does not grow
     * past its cap. */
    sta[5] = (uint8_t)MAX_QUEUE_EVICT_ENTRIES;
    queue_evict_note_session_change(BSSID, sta, QUEUE_EVICT_SRC_REASSOC,
                                    1000 + MAX_QUEUE_EVICT_ENTRIES, 0);
    ASSERT_EQ(queue_evict_count(), MAX_QUEUE_EVICT_ENTRIES);
    ASSERT_EQ((int)sh_evict_count(SH_EVICT_QUEUE_EVICT), 1);

    uint8_t gone[6] = { 0x02, 0, 0, 0, 0, 0 };
    queue_evict_t out;
    ASSERT_EQ(queue_evict_lookup(BSSID, gone, &out), 0);
    sta[5] = (uint8_t)MAX_QUEUE_EVICT_ENTRIES;
    ASSERT_EQ(queue_evict_lookup(BSSID, sta, &out), 1);
}

static void test_snapshot_and_src_names(void) {
    setup();
    queue_evict_note_session_change(BSSID,  STA_A, QUEUE_EVICT_SRC_ASSOC,
                                    1000, 0);
    queue_evict_note_session_change(BSSID2, STA_B, QUEUE_EVICT_SRC_REASSOC,
                                    1000, 0);
    queue_evict_t out[4];
    ASSERT_EQ(queue_evict_snapshot(out, 4), 2);
    ASSERT_EQ(queue_evict_snapshot(out, 1), 1);
    ASSERT_EQ(queue_evict_snapshot(NULL, 4), 0);
    ASSERT_EQ(queue_evict_snapshot(out, 0), 0);

    ASSERT_STR(queue_evict_src_name(QUEUE_EVICT_SRC_ASSOC),      "association");
    ASSERT_STR(queue_evict_src_name(QUEUE_EVICT_SRC_REASSOC),    "reassociation");
    ASSERT_STR(queue_evict_src_name(QUEUE_EVICT_SRC_DISCONNECT), "disassoc/deauth");
    ASSERT_STR(queue_evict_src_name(42), "");

    queue_evict_clear();
    ASSERT_EQ(queue_evict_count(), 0);
}

void run_queue_evict_tests(void) {
    TEST_SUITE("queue_evict — queued-frame release (#107 shape B)");
    RUN_TEST(test_retried_frames_do_not_reach_the_threshold);
    RUN_TEST(test_repeated_sequence_without_retry_bit_is_one_frame);
    RUN_TEST(test_sequence_zero_is_a_real_first_frame);
    RUN_TEST(test_a_new_session_change_forgets_the_last_sequence);
    RUN_TEST(test_uplink_addressed_to_the_station_is_still_ignored);
    RUN_TEST(test_no_rows_initially);
    RUN_TEST(test_downlink_without_a_session_change_creates_no_row);
    RUN_TEST(test_burst_after_reassociation_is_recorded);
    RUN_TEST(test_burst_outside_the_window_is_not_recorded);
    RUN_TEST(test_the_window_edge_is_inclusive);
    RUN_TEST(test_group_addressed_downlink_is_not_counted);
    RUN_TEST(test_uplink_in_the_window_is_not_counted);
    RUN_TEST(test_payloadless_downlink_is_not_counted);
    RUN_TEST(test_below_threshold_burst_is_not_a_release);
    RUN_TEST(test_out_of_order_downlink_does_not_count);
    RUN_TEST(test_distinct_pairs_stay_isolated);
    RUN_TEST(test_a_new_session_change_resets_the_burst);
    RUN_TEST(test_disconnect_opens_a_window_too);
    RUN_TEST(test_a_group_addressed_station_opens_no_window);
    RUN_TEST(test_an_unknown_source_opens_no_window);
    RUN_TEST(test_short_and_non_data_frames_are_ignored);
    RUN_TEST(test_table_full_evicts_the_stalest_and_counts_it);
    RUN_TEST(test_snapshot_and_src_names);
}
