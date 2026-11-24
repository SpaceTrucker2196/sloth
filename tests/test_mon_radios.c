/* Several sensor radios (src/mon_radios.h): the cross-radio
 * de-duplication, the hop-list split, the CLI rules, and the 802.11
 * path taking frames from more than one radio (through
 * probe_test_dispatch_radio(), the real callback).
 *
 * Frames are hand-built octet arrays (IEEE 802.11-2020 section 9.2.3 for
 * the header, 9.3.3.9 for a Probe Request, 9.3.1.4 for an ACK); no
 * capture file. Each "is not delivered / is not counted" assertion
 * below was seen red under the mutation its comment names. */
#include "runner.h"
#include "mon_radios.h"
#include "wifi_chanhop.h"
#include "fake_platform.h"
#include "frame_build.h"
#include "capture/probe.h"
#include "capture/mon_radio.h"
#include "df.h"
#include "probe_latency.h"
#include "jsonl.h"
#include "poll.h"
#include "tmp_dir.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const uint8_t BCAST[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t STA_A[6] = {0x02,0x00,0x00,0xaa,0x00,0x01};
static const uint8_t STA_B[6] = {0x02,0x00,0x00,0xbb,0x00,0x02};

#define T0 1700000000000000LL        /* a capture time, microseconds */

/* A Probe Request, no radiotap: FC 0x0040 (management, subtype 4),
 * duration 0, DA and BSSID broadcast, SA `sa`, Sequence Control
 * seq << 4, then SSID "lab" and Supported Rates. `fc1` is Frame Control
 * octet 1: 0x08 is the Retry bit. Returns the length (37). */
static int probe_req(uint8_t *f, const uint8_t *sa, uint16_t seq, uint8_t fc1) {
    fb_t b; fb_init(&b, f, 64);
    fb_u8(&b, 0x40); fb_u8(&b, fc1);
    fb_le16(&b, 0);
    fb_mac(&b, BCAST); fb_mac(&b, sa); fb_mac(&b, BCAST);
    fb_le16(&b, (uint16_t)(seq << 4));
    static const uint8_t ies[] = { 0x00, 0x03, 'l', 'a', 'b',
                                   0x01, 0x04, 0x02, 0x04, 0x0b, 0x16 };
    fb_bytes(&b, ies, (int)sizeof(ies));
    return b.len;
}

/* An ACK: FC 0x00d4 (control, subtype 13), duration, RA. Ten octets, no
 * transmitter address and no Sequence Control. */
static int ack(uint8_t *f, const uint8_t *ra) {
    fb_t b; fb_init(&b, f, 16);
    fb_u8(&b, 0xd4); fb_u8(&b, 0x00);
    fb_le16(&b, 0);
    fb_mac(&b, ra);
    return b.len;
}

static void two_radios(void) {
    mon_radios_reset();
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    ASSERT_EQ(mon_radios_add("mon1"), 1);
}

static void three_radios(void) {
    two_radios();
    ASSERT_EQ(mon_radios_add("mon2"), 2);
}

static uint64_t frames_of(int k) {
    mon_radio_t r;
    return mon_radios_get(k, &r) ? r.frames : 0;
}

static uint64_t dups_of(int k) {
    mon_radio_t r;
    return mon_radios_get(k, &r) ? r.dup_dropped : 0;
}

/* ── Registry ─────────────────────────────────────────────── */

static void test_registry_is_bounded_and_unique(void) {
    mon_radios_reset();
    ASSERT_EQ(mon_radios_active(), 0);
    ASSERT_EQ(mon_radios_extra(), 0);
    ASSERT_EQ(mon_radios_add("r0"), 0);
    ASSERT_EQ(mon_radios_active(), 0);            /* one radio: off */
    ASSERT_EQ(mon_radios_add("r0"), -1);
    ASSERT_EQ(mon_radios_add(""), -1);
    ASSERT_EQ(mon_radios_add("sixteen-chars-xx"), -1);
    ASSERT_EQ(mon_radios_add("r1"), 1);
    ASSERT_EQ(mon_radios_active(), 1);
    ASSERT_EQ(mon_radios_add("r2"), 2);
    ASSERT_EQ(mon_radios_add("r3"), 3);
    ASSERT_EQ(mon_radios_add("r4"), -1);          /* MON_RADIO_MAX */
    ASSERT_EQ(mon_radios_count(), MON_RADIO_MAX);
    ASSERT_EQ(mon_radios_extra(), MON_RADIO_MAX - 1);
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(3, &r), 1);
    ASSERT_STR(r.iface, "r3");
    ASSERT_STR(mon_radio_state_name(r.state), "not_open");
    ASSERT_EQ(mon_radios_get(4, &r), 0);
    mon_radios_set_state(3, MON_RADIO_LOST, "The interface disappeared");
    ASSERT_EQ(mon_radios_get(3, &r), 1);
    ASSERT_STR(mon_radio_state_name(r.state), "lost");
    ASSERT_STR(r.err, "The interface disappeared");
    ASSERT_EQ(mon_radio_alive(MON_RADIO_RUNNING), 1);
    ASSERT_EQ(mon_radio_alive(MON_RADIO_LOST), 0);
    mon_radios_reset();
    ASSERT_EQ(mon_radios_count(), 0);
    ASSERT_EQ(mon_radios_active(), 0);
}

/* ── De-duplication ───────────────────────────────────────── */

/* With one radio (nothing registered, or radio 0 alone) the call
 * delivers every frame and keeps no count: the one-radio run is the
 * run it was. */
static void test_one_radio_is_untouched(void) {
    uint8_t f[64];
    int n = probe_req(f, STA_A, 7, 0);
    mon_radios_reset();
    for (int i = 0; i < 3; i++)
        ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    ASSERT_EQ(mon_radios_add("mon0"), 0);
    for (int i = 0; i < 3; i++)
        ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    ASSERT_EQ((long long)frames_of(0), 0);
    ASSERT_EQ((long long)mon_radios_dup_total(), 0);
}

/* The same frame on two radios is delivered once, whichever radio's
 * copy is processed first and whichever carries the earlier stamp
 * (78 us was the largest difference measured on the reference host).
 * Red under: dd_check() returning 0 for `theirs`. */
static void test_same_frame_on_two_radios_is_delivered_once(void) {
    uint8_t f[64];
    int n = probe_req(f, STA_A, 7, 0);
    two_radios();
    ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 78, 2437), 0);
    ASSERT_EQ((long long)frames_of(0), 1);
    ASSERT_EQ((long long)frames_of(1), 0);
    ASSERT_EQ((long long)dups_of(1), 1);
    ASSERT_EQ((long long)dups_of(0), 0);
    /* The other order, and the later-processed copy stamped earlier. */
    int m = probe_req(f, STA_A, 8, 0);
    ASSERT_EQ(mon_radio_frame(1, f, m, T0 + 1000, 2437), 1);
    ASSERT_EQ(mon_radio_frame(0, f, m, T0 + 1000 - 78, 2437), 0);
    ASSERT_EQ((long long)dups_of(0), 1);
    ASSERT_EQ((long long)mon_radios_dup_total(), 2);
    /* A third radio's copy of either is a duplicate too. */
    ASSERT_EQ(mon_radios_add("mon2"), 2);
    ASSERT_EQ(mon_radio_frame(2, f, m, T0 + 1010, 2437), 0);
    /* Where each radio is: the frequency of the last frame it received,
     * a dropped one included. */
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(2, &r), 1);
    ASSERT_EQ(r.freq_mhz, 2437);
}

/* Frames from ONE radio are never held against each other: the same
 * octets twice at the same instant are two frames. And what two radios
 * each heard N times is delivered N times, not 2N: the first radio to
 * deliver owns the window. */
static void test_same_frame_twice_on_one_radio_is_delivered_twice(void) {
    uint8_t f[64];
    int n = probe_req(f, STA_A, 7, 0);
    two_radios();
    ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    ASSERT_EQ(mon_radio_frame(0, f, n, T0 + 200, 2437), 1);
    ASSERT_EQ((long long)frames_of(0), 3);
    ASSERT_EQ((long long)dups_of(0), 0);
    for (int i = 0; i < 3; i++)
        ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 40 + 100 * i, 2437), 0);
    ASSERT_EQ((long long)frames_of(1), 0);
    ASSERT_EQ((long long)dups_of(1), 3);
}

/* A retransmission (Retry set, IEEE 802.11-2020 section 9.2.4.1.7) heard
 * on another radio is not a duplicate of the original: its Frame
 * Control differs. Nor is the next sequence number, another
 * transmitter, or a different body. */
static void test_a_retry_or_a_different_frame_is_delivered(void) {
    uint8_t f[64], g[64];
    int n = probe_req(f, STA_A, 7, 0);
    two_radios();
    ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2437), 1);
    int m = probe_req(g, STA_A, 7, 0x08);                 /* Retry */
    ASSERT_EQ(m, n);
    ASSERT_EQ(mon_radio_frame(1, g, m, T0 + 300, 2437), 1);
    m = probe_req(g, STA_A, 8, 0);                        /* next seq */
    ASSERT_EQ(mon_radio_frame(1, g, m, T0 + 310, 2437), 1);
    m = probe_req(g, STA_B, 7, 0);                        /* another TA */
    ASSERT_EQ(mon_radio_frame(1, g, m, T0 + 320, 2437), 1);
    m = probe_req(g, STA_A, 7, 0);
    g[m - 1] ^= 0x01;                                     /* another body */
    ASSERT_EQ(mon_radio_frame(1, g, m, T0 + 330, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, g, m - 1, T0 + 340, 2437), 1);  /* shorter */
    ASSERT_EQ((long long)dups_of(1), 0);
    ASSERT_EQ((long long)frames_of(1), 5);
    /* And the retry's own copy on radio 0 is the duplicate of it. */
    m = probe_req(g, STA_A, 7, 0x08);
    ASSERT_EQ(mon_radio_frame(0, g, m, T0 + 305, 2437), 0);
}

/* The window is on capture time, both ways, and across the table's
 * time-slot boundaries. One microsecond past it the frame is its own. */
static void test_window_expiry(void) {
    uint8_t f[64];
    int n = probe_req(f, STA_A, 7, 0);
    two_radios();
    /* Stamps placed so the pair straddles a slot boundary. */
    const int64_t edge = (T0 / MON_DEDUP_WINDOW_US + 1) * MON_DEDUP_WINDOW_US;
    ASSERT_EQ(mon_radio_frame(0, f, n, edge - 10, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, edge + 10, 2437), 0);
    ASSERT_EQ(mon_radio_frame(1, f, n, edge - 10 + MON_DEDUP_WINDOW_US, 2437), 0);
    ASSERT_EQ(mon_radio_frame(1, f, n, edge - 10 - MON_DEDUP_WINDOW_US, 2437), 0);
    /* Past it, later and earlier: delivered, and radio 1 now owns those
     * instants. */
    ASSERT_EQ(mon_radio_frame(1, f, n, edge - 10 + MON_DEDUP_WINDOW_US + 1, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, edge - 10 - MON_DEDUP_WINDOW_US - 1, 2437), 1);
    ASSERT_EQ((long long)dups_of(1), 3);
    ASSERT_EQ((long long)frames_of(1), 2);
    /* Radio 0 again, 3 ms after its own first frame and inside the
     * window of radio 1's later one too: its own radio's window comes
     * first, so it is delivered (red under: dd_check() testing `theirs`
     * before `mine`). */
    ASSERT_EQ(mon_radio_frame(0, f, n, edge - 10 + 3000, 2437), 1);
    ASSERT_EQ((long long)dups_of(0), 0);
    /* A frame a second later is not held against the first at all. */
    ASSERT_EQ(mon_radio_frame(1, f, n, edge + 1000000, 2437), 1);
    /* A capture with no usable clock is delivered unexamined. */
    ASSERT_EQ(mon_radio_frame(0, f, n, 0, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, 0, 2437), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, -5, 2437), 1);
}

/* The reader threads take frames in blocks, so radio 1's copies can be
 * processed after radio 0 has moved 100 ms on. The table is keyed by
 * capture time, not arrival: all of them are still duplicates, and a
 * frame repeated on radio 0 every 30 ms is matched instant by
 * instant. */
static void test_a_late_reader_still_finds_its_duplicates(void) {
    uint8_t f[64];
    two_radios();
    for (int i = 0; i < 200; i++) {
        int n = probe_req(f, STA_A, (uint16_t)i, 0);
        ASSERT_EQ(mon_radio_frame(0, f, n, T0 + 500 * i, 5180), 1);
    }
    uint8_t a[16];
    int an = ack(a, STA_B);
    for (int i = 0; i < 4; i++)
        ASSERT_EQ(mon_radio_frame(0, a, an, T0 + 30000 * i, 5180), 1);
    for (int i = 0; i < 200; i++) {
        int n = probe_req(f, STA_A, (uint16_t)i, 0);
        ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 500 * i + 30, 5180), 0);
    }
    for (int i = 0; i < 4; i++)
        ASSERT_EQ(mon_radio_frame(1, a, an, T0 + 30000 * i - 20, 5180), 0);
    ASSERT_EQ((long long)dups_of(1), 204);
    ASSERT_EQ((long long)mon_dedup_evicted(), 0);
}

/* Control frames carry no sequence number (an ACK is FC, duration and
 * a receiver address). The same ACK on two radios is one ACK; a run of
 * identical ones both radios heard is the run one radio heard. */
static void test_control_frames_without_a_sequence_number(void) {
    uint8_t a[16];
    int an = ack(a, STA_A);
    ASSERT_EQ(an, 10);
    two_radios();
    ASSERT_EQ(mon_radio_frame(0, a, an, T0, 2412), 1);
    ASSERT_EQ(mon_radio_frame(1, a, an, T0 + 50, 2412), 0);
    /* An ACK to someone else is not it. */
    uint8_t b[16];
    int bn = ack(b, STA_B);
    ASSERT_EQ(mon_radio_frame(1, b, bn, T0 + 60, 2412), 1);
    /* Ten identical ones 300 us apart, heard by both. */
    mon_radios_reset();
    two_radios();
    for (int i = 0; i < 10; i++)
        ASSERT_EQ(mon_radio_frame(0, a, an, T0 + 300 * i, 2412), 1);
    for (int i = 0; i < 10; i++)
        ASSERT_EQ(mon_radio_frame(1, a, an, T0 + 300 * i + 40, 2412), 0);
    ASSERT_EQ((long long)(frames_of(0) + frames_of(1)), 10);
}

/* Bounded: more distinct frames at one instant than the table holds.
 * Nothing is allocated and nothing is written out of bounds (the
 * sanitizer runs say so); the evictions are counted; a duplicate of an
 * evicted frame is delivered (fails open) and one of a surviving frame
 * is still dropped. */
static void test_table_wrap_and_bounds(void) {
    two_radios();
    const int total = MON_DEDUP_BUCKETS * MON_DEDUP_WAYS + 4000;
    uint8_t f[64];
    for (int i = 0; i < total; i++) {
        uint8_t sa[6] = { 0x02, 0x10, (uint8_t)(i >> 16), (uint8_t)(i >> 8),
                          (uint8_t)i, 0x01 };
        int n = probe_req(f, sa, (uint16_t)(i & 0xfff), 0);
        (void)mon_radio_frame(0, f, n, T0, 2437);
    }
    ASSERT_EQ((long long)frames_of(0), total);     /* every one delivered */
    ASSERT((long long)mon_dedup_evicted() >= 4000);
    long long dup = 0, delivered = 0;
    for (int i = 0; i < total; i++) {
        uint8_t sa[6] = { 0x02, 0x10, (uint8_t)(i >> 16), (uint8_t)(i >> 8),
                          (uint8_t)i, 0x01 };
        int n = probe_req(f, sa, (uint16_t)(i & 0xfff), 0);
        if (mon_radio_frame(1, f, n, T0 + 20, 2437)) delivered++; else dup++;
    }
    ASSERT_EQ(dup + delivered, (long long)total);
    ASSERT(dup > 0);
    ASSERT(delivered >= 4000);          /* at least the evicted ones */
    ASSERT(dup <= (long long)MON_DEDUP_BUCKETS * MON_DEDUP_WAYS);
    /* A reset empties it. */
    mon_radios_reset();
    two_radios();
    int n = probe_req(f, STA_A, 1, 0);
    ASSERT_EQ(mon_dedup_is_dup(1, f, n, T0 + 20), 0);
    ASSERT_EQ((long long)mon_dedup_evicted(), 0);
}

/* ── Hop split ────────────────────────────────────────────── */

/* For 1, 2, 3 and 4 radios, the shares of the default list are
 * disjoint and together are the whole list: every channel once a
 * cycle, no channel given to two radios. */
static void test_hop_split_covers_every_channel_once(void) {
    chanhop_t full;
    int total = chanhop_init_default(&full);
    ASSERT(total >= 8);
    for (int radios = 1; radios <= 4; radios++) {
        int seen[CHANHOP_MAX];
        memset(seen, 0, sizeof(seen));
        int sum = 0, biggest = 0, smallest = CHANHOP_MAX;
        for (int k = 0; k < radios; k++) {
            chanhop_t h;
            int n = chanhop_split(&h, &full, radios, k);
            ASSERT_EQ(n, h.count);
            sum += n;
            if (n > biggest)  biggest = n;
            if (n < smallest) smallest = n;
            for (int i = 0; i < n; i++) {
                int at = -1;
                for (int j = 0; j < total; j++)
                    if (full.slots[j].freq_mhz == h.slots[i].freq_mhz) at = j;
                ASSERT(at >= 0);
                ASSERT_EQ(at % radios, k);
                ASSERT_EQ((int)h.slots[i].band, (int)full.slots[at].band);
                if (at >= 0) seen[at]++;
            }
            ASSERT_EQ(h.pending, -1);
            ASSERT_EQ(h.started, 0);
            ASSERT_EQ((int)h.base_dwell_ms, (int)full.base_dwell_ms);
        }
        ASSERT_EQ(sum, total);
        for (int j = 0; j < total; j++) ASSERT_EQ(seen[j], 1);
        ASSERT(biggest - smallest <= 1);   /* an even deal */
    }
    /* More radios than channels: the ones past the end get nothing. */
    int two[] = { 1, 6 };
    chanhop_t small, h;
    chanhop_init(&small, two, 2);
    ASSERT_EQ(chanhop_split(&h, &small, 3, 2), 0);
    ASSERT_EQ(chanhop_tick(&h, 0), 0);
    ASSERT_EQ(chanhop_split(&h, &small, 0, 0), 0);
    ASSERT_EQ(chanhop_split(&h, &small, 2, 2), 0);
}

static sloth_state_t g_hs;

/* One poll of every scheduler, as main.c's chanhop_drive() makes it. */
static int hop_poll(chanhop_t *h0, uint64_t t) {
    chanhop_service(h0, &g_hs, t, mon_hop_radio0_delta());
    return mon_hop_service(h0, t);
}

static int chan_of(int k) {
    mon_radio_t r;
    if (k == 0) return g_hs.chan_confirmed;
    return mon_radios_get(k, &r) ? r.chan_confirmed : 0;
}

/* Three radios hopping through the fake platform: at every poll no two
 * sit on one channel, each is retuned by its own name, and between
 * them every channel of the list is visited. */
static void test_hopping_radios_sit_on_different_channels(void) {
    fake_net_reset();
    memset(&g_hs, 0, sizeof(g_hs));
    snprintf(g_hs.probe_iface, sizeof(g_hs.probe_iface), "mon0");
    three_radios();
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_RUNNING, "");
    chanhop_t h0, full;
    int total = chanhop_init_default(&full);
    chanhop_init_default(&h0);
    ASSERT_EQ(mon_hop_setup(&h0), 3);
    ASSERT_EQ(h0.count, (total + 2) / 3);
    int visited[CHANHOP_MAX];
    memset(visited, 0, sizeof(visited));
    for (uint64_t t = 0; t <= 6000; t += 50) {
        ASSERT_EQ(hop_poll(&h0, t), 0);
        int c[3] = { chan_of(0), chan_of(1), chan_of(2) };
        ASSERT(c[0] && c[1] && c[2]);
        ASSERT(c[0] != c[1] && c[0] != c[2] && c[1] != c[2]);
        for (int k = 0; k < 3; k++)
            for (int j = 0; j < total; j++)
                if (full.slots[j].channel == c[k]) {
                    visited[j]++;
                    ASSERT_EQ(j % 3, k);     /* only its own share */
                }
    }
    for (int j = 0; j < total; j++) ASSERT(visited[j] > 0);
    /* Three retunes on the first poll, one per radio, by name. */
    ASSERT(g_fake_net.set_channel_calls >= 3 * 4);
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(2, &r), 1);
    ASSERT_EQ(r.hop_channels, total / 3);
    ASSERT_EQ(r.retune_failures, 0);
    ASSERT_EQ(r.chan_requested, r.chan_confirmed);
}

/* A radio that is lost mid-run: the next poll deals the list again
 * among the ones left, the lost radio is not retuned any more, and the
 * two survivors cover every channel between them. A radio that was
 * never opened is never dealt in. */
static void test_a_lost_radio_has_its_channels_dealt_out_again(void) {
    fake_net_reset();
    memset(&g_hs, 0, sizeof(g_hs));
    snprintf(g_hs.probe_iface, sizeof(g_hs.probe_iface), "mon0");
    three_radios();
    ASSERT_EQ(mon_radios_add("mon3"), 3);        /* named, never opened */
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_RUNNING, "");
    chanhop_t h0, full;
    int total = chanhop_init_default(&full);
    chanhop_init_default(&h0);
    ASSERT_EQ(mon_hop_setup(&h0), 3);
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(3, &r), 1);
    ASSERT_EQ(r.hop_channels, 0);
    for (uint64_t t = 0; t <= 1000; t += 50) ASSERT_EQ(hop_poll(&h0, t), 0);
    ASSERT_EQ(chan_of(3), 0);

    mon_radios_set_state(2, MON_RADIO_LOST, "The interface disappeared");
    ASSERT_EQ(hop_poll(&h0, 1050), 1);           /* dealt again */
    ASSERT_EQ(hop_poll(&h0, 1100), 0);           /* once */
    ASSERT_EQ(mon_radios_get(2, &r), 1);
    ASSERT_EQ(r.hop_channels, 0);
    ASSERT_EQ(r.chan_confirmed, 0);
    ASSERT_EQ(h0.count, (total + 1) / 2);
    ASSERT_EQ(mon_radios_get(1, &r), 1);
    ASSERT_EQ(r.hop_channels, total / 2);
    int visited[CHANHOP_MAX];
    memset(visited, 0, sizeof(visited));
    for (uint64_t t = 1150; t <= 9000; t += 50) {
        ASSERT_EQ(hop_poll(&h0, t), 0);
        /* Red under: deal() leaving a lost radio in the mask. */
        ASSERT(strcmp(g_fake_net.set_channel_last_iface, "mon2") != 0);
        ASSERT(chan_of(0) != chan_of(1));
        for (int k = 0; k < 2; k++)
            for (int j = 0; j < total; j++)
                if (full.slots[j].channel == chan_of(k)) visited[j]++;
    }
    for (int j = 0; j < total; j++) ASSERT(visited[j] > 0);
}

/* A refused retune is that radio's own failure, with its errno; radio
 * 0's figures do not move. Frames are attributed per radio. */
static void test_hop_failures_and_frames_are_per_radio(void) {
    fake_net_reset();
    memset(&g_hs, 0, sizeof(g_hs));
    snprintf(g_hs.probe_iface, sizeof(g_hs.probe_iface), "mon0");
    two_radios();
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    chanhop_t h0;
    int chans[] = { 1, 6 };
    chanhop_init(&h0, chans, 2);
    ASSERT_EQ(mon_hop_setup(&h0), 2);
    g_fake_net.refuse_freq_mhz = 2437;           /* channel 6: radio 1's */
    g_fake_net.refuse_rc       = -EBUSY;
    uint8_t f[64];
    for (uint64_t t = 0; t <= 1000; t += 50) {
        /* Five frames on radio 1 each poll, none on radio 0. */
        for (int i = 0; i < 5; i++) {
            int n = probe_req(f, STA_A, (uint16_t)((t / 50 * 5 + (uint64_t)i) & 0xfff), 0);
            ASSERT_EQ(mon_radio_frame(1, f, n, T0 + (int64_t)t * 1000 + i * 100, 2437), 1);
        }
        hop_poll(&h0, t);
    }
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(1, &r), 1);
    ASSERT(r.retune_failures >= 2);
    ASSERT_EQ(r.retune_last_errno, EBUSY);
    ASSERT_EQ(r.chan_requested, 6);
    ASSERT_EQ(r.chan_confirmed, 0);
    ASSERT_EQ(g_hs.chan_retune_failures, 0);
    ASSERT_EQ(g_hs.chan_confirmed, 1);
    /* Radio 1's frames did not count as radio 0's channel's (red under:
     * mon_hop_radio0_delta() summing every radio's frames). */
    ASSERT_EQ((long long)g_hs.hop_activity.frames, 0);
}

/* With one radio mon_hop_setup() leaves the scheduler alone and the
 * service does nothing. */
static void test_hop_with_one_radio_is_untouched(void) {
    fake_net_reset();
    mon_radios_reset();
    chanhop_t h0, before;
    chanhop_init_default(&h0);
    before = h0;
    ASSERT_EQ(mon_hop_setup(&h0), 1);
    ASSERT_EQ(memcmp(&h0, &before, sizeof(h0)), 0);
    ASSERT_EQ(mon_hop_service(&h0, 100), 0);
    ASSERT_EQ(g_fake_net.set_channel_calls, 0);
}

/* ── Command line ─────────────────────────────────────────── */

static void test_cli_names(void) {
    mon_cli_t c;
    char why[200];
    memset(&c, 0, sizeof(c));
    ASSERT_EQ(mon_cli_add(&c, "alfa0", why, sizeof(why)), 1);
    ASSERT_STR(why, "");
    ASSERT_EQ(c.n, 1);
    ASSERT_STR(c.name[0], "alfa0");
    /* Not interface names. */
    ASSERT_EQ(mon_cli_add(&c, "", why, sizeof(why)), 0);
    ASSERT(strstr(why, "not an interface name") != NULL);
    ASSERT_EQ(mon_cli_add(&c, "sixteen-chars-xx", why, sizeof(why)), 0);
    ASSERT(strstr(why, "not an interface name") != NULL);
    ASSERT_EQ(mon_cli_add(&c, "a/b", why, sizeof(why)), 0);
    ASSERT(strstr(why, "not an interface name") != NULL);
    /* A raw HCI device, first or later. */
    ASSERT_EQ(mon_cli_add(&c, "bluetooth0", why, sizeof(why)), 0);
    ASSERT(strstr(why, "raw HCI device") != NULL);
    /* The same radio twice. */
    ASSERT_EQ(mon_cli_add(&c, "alfa0", why, sizeof(why)), 0);
    ASSERT_STR(why, "sloth: --monitor-iface alfa0 given twice; a radio is "
                    "named once");
    ASSERT_EQ(c.n, 1);                              /* nothing was added */
    ASSERT_EQ(mon_cli_add(&c, "alfa1", why, sizeof(why)), 1);
    ASSERT_EQ(mon_cli_add(&c, "alfa1", why, sizeof(why)), 0);
    ASSERT_EQ(mon_cli_add(&c, "alfa2", why, sizeof(why)), 1);
    ASSERT_EQ(mon_cli_add(&c, "alfa3", why, sizeof(why)), 1);
    /* Three beside the first, no more. */
    ASSERT_EQ(mon_cli_add(&c, "alfa4", why, sizeof(why)), 0);
    ASSERT_STR(why, "sloth: too many --monitor-iface radios (max 3 beside "
                    "the first)");
    ASSERT_EQ(c.n, MON_RADIO_MAX);
}

static void test_cli_refusals(void) {
    mon_cli_t one, two;
    char why[200];
    memset(&one, 0, sizeof(one));
    memset(&two, 0, sizeof(two));
    mon_cli_add(&one, "alfa0", why, sizeof(why));
    mon_cli_add(&two, "alfa0", why, sizeof(why));
    mon_cli_add(&two, "alfa1", why, sizeof(why));
    const char *df_other[] = { "alfa2" };
    const char *df_clash[] = { "alfa2", "alfa1" };
    const char *df_first[] = { "alfa0" };

    /* Two radios, a live run with libpcap, no clash: accepted. */
    ASSERT_EQ(mon_cli_check(&two, NULL, 0, 0, 1, why, sizeof(why)), 1);
    ASSERT_STR(why, "");
    ASSERT_EQ(mon_cli_check(&two, df_other, 1, 0, 1, why, sizeof(why)), 1);
    /* --replay. */
    ASSERT_EQ(mon_cli_check(&two, NULL, 0, 1, 1, why, sizeof(why)), 0);
    ASSERT_STR(why, "sloth: --monitor-iface names live radios; it cannot be "
                    "combined with --replay");
    /* WITH_PCAP=0. */
    ASSERT_EQ(mon_cli_check(&two, NULL, 0, 0, 0, why, sizeof(why)), 0);
    ASSERT_STR(why, "sloth: --monitor-iface needs a build with libpcap "
                    "(this one is WITH_PCAP=0)");
    /* A further sensor radio that is also a --df-iface radio. */
    ASSERT_EQ(mon_cli_check(&two, df_clash, 2, 0, 1, why, sizeof(why)), 0);
    ASSERT_STR(why, "sloth: alfa1 is named by --monitor-iface and by "
                    "--df-iface; a radio is a sensor radio or a "
                    "direction-finding radio, not both");
    /* The first radio named to --df-iface is --df-iface's own case
     * (announced and left out, main.c), as it was. */
    ASSERT_EQ(mon_cli_check(&two, df_first, 1, 0, 1, why, sizeof(why)), 1);
    /* One radio: every refusal is main()'s, worded as before. */
    ASSERT_EQ(mon_cli_check(&one, df_first, 1, 1, 0, why, sizeof(why)), 1);
    ASSERT_EQ(mon_cli_check(NULL, NULL, 0, 1, 0, why, sizeof(why)), 1);
}

/* ── The 802.11 path with several radios ──────────────────── */

static sloth_state_t g_s;

/* probe_test_dispatch_radio() and the other probe_test_*() seams are
 * declared only under WITH_PCAP (probe.h); the link-only no-flag build
 * leaves these out, as tests/test_dot11_frame.c does. */
#ifdef WITH_PCAP
/* radiotap with CHANNEL and the antenna signal, then the frame. */
static int rt_probe_req(uint8_t *f, int cap, const uint8_t *sa, uint16_t seq,
                        uint8_t fc1, uint16_t freq) {
    fb_t b; fb_init(&b, f, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof(rt));
    rt.has_channel = 1; rt.freq_mhz = freq;
    rt.has_signal  = 1; rt.dbm = -48;
    fb_radiotap(&b, &rt);
    uint8_t d[64];
    int n = probe_req(d, sa, seq, fc1);
    fb_bytes(&b, d, n);
    return fb_ok(&b) ? b.len : -1;
}

static int dispatch1(int radio, const uint8_t *f, int len, uint32_t sec,
                     uint32_t usec) {
    const uint8_t *fs[1] = { f };
    int ls[1] = { len };
    return probe_test_dispatch_radio(radio, fs, ls, &sec, &usec, 1);
}

static int client_frames(const uint8_t *mac) {
    probe_snapshot(&g_s);
    for (int i = 0; i < g_s.probe_count; i++)
        if (memcmp(g_s.probe_clients[i].mac, mac, 6) == 0)
            return (int)g_s.probe_clients[i].frame_count;
    return 0;
}

/* The same Probe Request arriving on radio 0 and radio 1 reaches the
 * probe table, the frame ring's counter and the flood window once; the
 * same frame twice on radio 0 reaches them twice; a Retry copy on
 * radio 1 is its own frame.
 * Red under: on_radio_frame() ignoring mon_radio_frame()'s verdict. */
static void test_path_delivers_a_frame_two_radios_heard_once(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    two_radios();
    uint8_t f[96];
    int n = rt_probe_req(f, sizeof(f), STA_A, 100, 0, 2437);
    ASSERT(n > 0);
    uint64_t before = mon_frame_total();
    ASSERT_EQ(dispatch1(0, f, n, 1700000000, 1000), 1);
    ASSERT_EQ(dispatch1(1, f, n, 1700000000, 1060), 1);   /* pcap gave it */
    ASSERT_EQ((long long)(mon_frame_total() - before), 1);
    ASSERT_EQ(client_frames(STA_A), 1);
    ASSERT_EQ((long long)dups_of(1), 1);
    ASSERT_EQ((long long)frames_of(0), 1);

    /* Twice on one radio: two frames. */
    ASSERT_EQ(dispatch1(0, f, n, 1700000000, 1300), 1);
    ASSERT_EQ((long long)(mon_frame_total() - before), 2);
    ASSERT_EQ(client_frames(STA_A), 2);

    /* The retransmission, heard by radio 1 only. */
    uint8_t g[96];
    int m = rt_probe_req(g, sizeof(g), STA_A, 100, 0x08, 2437);
    ASSERT_EQ(dispatch1(1, g, m, 1700000000, 1500), 1);
    ASSERT_EQ((long long)(mon_frame_total() - before), 3);
    ASSERT_EQ(client_frames(STA_A), 3);
    ASSERT_EQ((long long)frames_of(1), 1);

    /* Radio 1 on another channel hears a frame radio 0 never did: it is
     * delivered, and the row says which channel. */
    int k = rt_probe_req(g, sizeof(g), STA_B, 5, 0, 5180);
    ASSERT_EQ(dispatch1(1, g, k, 1700000001, 0), 1);
    ASSERT_EQ(client_frames(STA_B), 1);
    for (int i = 0; i < g_s.probe_count; i++)
        if (memcmp(g_s.probe_clients[i].mac, STA_B, 6) == 0)
            ASSERT_EQ(g_s.probe_clients[i].channel, 36);
}

/* With one radio (no registry) the path is as it was: the same frame
 * twice is two frames, whatever the stamps. */
static void test_path_with_one_radio_is_as_it_was(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    mon_radios_reset();
    uint8_t f[96];
    int n = rt_probe_req(f, sizeof(f), STA_A, 100, 0, 2437);
    uint64_t before = mon_frame_total();
    ASSERT_EQ(dispatch1(0, f, n, 1700000000, 1000), 1);
    ASSERT_EQ(dispatch1(0, f, n, 1700000000, 1000), 1);
    ASSERT_EQ((long long)(mon_frame_total() - before), 2);
    ASSERT_EQ(client_frames(STA_A), 2);
    ASSERT_EQ((long long)mon_radios_dup_total(), 0);
}

/* Radio 0's own figures stay radio 0's: a frame from another sensor
 * radio does not refresh the monitor stream's freshness (a dead radio 0
 * must not read as fresh), is not shown to the probe-latency dwell
 * counter (frequencies interleaved across radios are not dwells), and
 * is not radio 0's reading in the direction-finding table. Radio 0's
 * copy still is its reading when another radio's copy was delivered
 * first.
 * Red under: dropping each `radio == 0` test in probe.c in turn. */
static void test_radio0_figures_are_radio0s(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    probe_latency_reset();
    probe_test_reset_freshness();
    two_radios();
    df_reset();
    ASSERT_EQ(df_radio_add("mon0", 0, 0), 0);
    ASSERT_EQ(df_radio_add("dfx", 0, 0), 1);       /* a --df-iface radio */
    ASSERT_EQ(df_active(), 1);

    uint8_t f[96];
    int n = rt_probe_req(f, sizeof(f), STA_A, 100, 0, 2437);
    ASSERT_EQ(dispatch1(1, f, n, 1700000000, 1000), 1);
    int m = rt_probe_req(f, sizeof(f), STA_A, 101, 0, 5180);
    ASSERT_EQ(dispatch1(1, f, m, 1700000000, 9000), 1);
    ASSERT_EQ(client_frames(STA_A), 2);            /* they were delivered */

    capture_health_t h;
    memset(&h, 0, sizeof(h));
    probe_health_poll(&h);
    ASSERT_EQ(h.stale_secs, -1);                   /* radio 0 never delivered */
    plat_counters_t pc;
    probe_latency_counters(&pc);
    ASSERT_EQ((long long)pc.dwells, 0);
    df_radio_t d0;
    ASSERT_EQ(df_radio_get(0, &d0), 1);
    ASSERT_EQ((long long)d0.frames, 0);
    ASSERT_EQ(df_emitter_count(), 0);

    /* Radio 0's copy of the first frame: a duplicate to the detectors,
     * and still radio 0's level for that transmitter. */
    n = rt_probe_req(f, sizeof(f), STA_A, 100, 0, 2437);
    ASSERT_EQ(dispatch1(0, f, n, 1700000000, 1040), 1);
    ASSERT_EQ(client_frames(STA_A), 2);
    ASSERT_EQ((long long)dups_of(0), 1);
    ASSERT_EQ(df_radio_get(0, &d0), 1);
    ASSERT_EQ((long long)d0.frames, 1);
    /* And a frame radio 0 delivers moves its freshness. */
    n = rt_probe_req(f, sizeof(f), STA_A, 102, 0, 2437);
    ASSERT_EQ(dispatch1(0, f, n, 1700000002, 0), 1);
    probe_health_poll(&h);
    ASSERT(h.stale_secs >= 0);
    df_reset();
}

/* Three reader threads, one per radio. Each brings the same 300 Probe
 * Requests at the same stamps: 300 are delivered and 600 dropped,
 * whatever the interleaving. Each also brings 100 QoS data frames of
 * its own (its own transmitter, so none is a duplicate) with
 * RT_F_DATAPAD set, which the path copies through its one static
 * de-padding buffer: under -fsanitize=thread that is the write the
 * dispatch lock serialises (seen: with the lock taken out of
 * probe_radio_frame() ThreadSanitizer reports the race here). */
#define THR_FRAMES 300
#define THR_DATA   100
static uint8_t  g_tf[THR_FRAMES][96];
static int      g_tl[THR_FRAMES];
static const uint8_t *g_tp[THR_FRAMES];
static uint8_t  g_df[3][THR_DATA][96];
static int      g_dl[3][THR_DATA];
static const uint8_t *g_dp[3][THR_DATA];

/* QoS data, STA -> AP (ToDS), 26-octet header padded to 28 as the
 * radiotap DATAPAD flag (0x20) says, then LLC/SNAP for IPv4 and four
 * payload octets. */
static int rt_padded_data(uint8_t *f, int cap, const uint8_t *sa, uint16_t seq) {
    static const uint8_t ap[6] = {0x02,0x00,0x00,0xcc,0x00,0x09};
    fb_t b; fb_init(&b, f, cap);
    fb_rt_t rt; memset(&rt, 0, sizeof(rt));
    rt.has_flags = 1; rt.flags = 0x20;
    rt.has_channel = 1; rt.freq_mhz = 5180;
    int rtl = fb_radiotap(&b, &rt);
    fb_hdr_t h; memset(&h, 0, sizeof(h));
    h.type = 2; h.subtype = 8; h.flags = FB_TODS;
    h.a1 = ap; h.a2 = sa; h.a3 = ap; h.qos_present = 1;
    h.seq_ctl = (uint16_t)(seq << 4);
    fb_dot11_hdr(&b, &h);
    fb_datapad_to4(&b, rtl);
    fb_llc_snap(&b, 0x0800);
    fb_le16(&b, seq); fb_le16(&b, 0x5a5a);
    return fb_ok(&b) ? b.len : -1;
}

static void *radio_thread(void *arg) {
    int radio = (int)(intptr_t)arg;
    /* In blocks, as a reader takes them from libpcap. */
    for (int at = 0; at < THR_FRAMES; at += 30) {
        uint32_t sec[30], usec[30];
        for (int i = 0; i < 30; i++) {
            sec[i]  = 1700000000u;
            usec[i] = (uint32_t)((at + i) * 400 + radio * 20);
        }
        if (probe_test_dispatch_radio(radio, g_tp + at, g_tl + at, sec, usec, 30) != 30)
            return (void *)1;
        int d = at / 3;
        for (int i = 0; i < 10; i++) {
            sec[i]  = 1700000001u;
            usec[i] = (uint32_t)((d + i) * 400);
        }
        if (probe_test_dispatch_radio(radio, g_dp[radio] + d, g_dl[radio] + d,
                                      sec, usec, 10) != 10)
            return (void *)1;
    }
    return NULL;
}

static void test_three_reader_threads_deliver_each_frame_once(void) {
    memset(&g_s, 0, sizeof(g_s));
    probe_clear();
    three_radios();
    for (int i = 0; i < THR_FRAMES; i++) {
        g_tl[i] = rt_probe_req(g_tf[i], sizeof(g_tf[i]), STA_A, (uint16_t)i, 0, 2437);
        g_tp[i] = g_tf[i];
    }
    for (int k = 0; k < 3; k++) {
        const uint8_t sa[6] = { 0x02, 0x00, 0x00, 0xdd, 0x00, (uint8_t)k };
        for (int i = 0; i < THR_DATA; i++) {
            g_dl[k][i] = rt_padded_data(g_df[k][i], sizeof(g_df[k][i]), sa, (uint16_t)i);
            ASSERT(g_dl[k][i] > 0);
            g_dp[k][i] = g_df[k][i];
        }
    }
    uint64_t before = mon_frame_total();
    pthread_t th[3];
    for (int k = 0; k < 3; k++)
        ASSERT_EQ(pthread_create(&th[k], NULL, radio_thread, (void *)(intptr_t)k), 0);
    for (int k = 0; k < 3; k++) {
        void *rv = (void *)1;
        ASSERT_EQ(pthread_join(th[k], &rv), 0);
        ASSERT(rv == NULL);
    }
    ASSERT_EQ((long long)(mon_frame_total() - before), THR_FRAMES + 3 * THR_DATA);
    ASSERT_EQ(client_frames(STA_A), THR_FRAMES);
    ASSERT_EQ((long long)(frames_of(0) + frames_of(1) + frames_of(2)),
              THR_FRAMES + 3 * THR_DATA);
    ASSERT_EQ((long long)mon_radios_dup_total(), 2 * THR_FRAMES);
}

#endif /* WITH_PCAP */

/* ── sensor_health ────────────────────────────────────────── */

static char g_path[TEST_TMP_MAX];

static void open_fresh(void) {
    int fd = mkstemp(test_tmp_tpl(g_path, sizeof(g_path), "sloth_monr_XXXXXX"));
    if (fd >= 0) close(fd);
    jsonl_close();
    unlink(g_path);
    ASSERT(jsonl_open(g_path));
}

static char g_body[32768];

static int read_back(void) {
    jsonl_close();
    FILE *fp = fopen(g_path, "r");
    if (!fp) return -1;
    size_t n = fread(g_body, 1, sizeof(g_body) - 1, fp);
    g_body[n] = '\0';
    fclose(fp);
    unlink(g_path);
    int lines = 0;
    for (const char *p = g_body; *p; p++) if (*p == '\n') lines++;
    return lines;
}

/* One radio: the count and nothing else, so a consumer can tell the
 * mode is off rather than unreported. */
static void test_sensor_health_with_one_radio(void) {
    memset(&g_s, 0, sizeof(g_s));
    mon_radios_reset();
    open_fresh();
    jsonl_emit_sensor_health(&g_s);
    ASSERT_EQ(read_back(), 1);
    ASSERT(strstr(g_body, "\"mon_extra_radios\":0") != NULL);
    ASSERT(strstr(g_body, "mon_r0_") == NULL);
    ASSERT(strstr(g_body, "mon_dup_dropped") == NULL);
    ASSERT(strstr(g_body, "\"jsonl_version\":\"2.9.0\"") != NULL);
}

/* Three radios, one of which could not be opened: each has its block,
 * and the line is written again on a state change but not on a frame,
 * a retune or one more duplicate inside the same decade. */
static void test_sensor_health_reports_each_radio(void) {
    memset(&g_s, 0, sizeof(g_s));
    snprintf(g_s.probe_iface, sizeof(g_s.probe_iface), "mon0");
    g_s.chan_confirmed = 11;
    three_radios();
    mon_radios_set_state(0, MON_RADIO_RUNNING, "");
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_NAMED, "monitor iface mon2 not found");
    uint8_t f[64];
    int n = probe_req(f, STA_A, 1, 0);
    ASSERT_EQ(mon_radio_frame(0, f, n, T0, 2462), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 30, 2462), 0);
    n = probe_req(f, STA_A, 2, 0);
    ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 900, 5180), 1);

    open_fresh();
    jsonl_emit_sensor_health(&g_s);                /* 1 */
    /* More frames, and a second duplicate (the 1-9 decade still). */
    n = probe_req(f, STA_A, 3, 0);
    ASSERT_EQ(mon_radio_frame(0, f, n, T0 + 2000, 2462), 1);
    ASSERT_EQ(mon_radio_frame(1, f, n, T0 + 2030, 2462), 0);
    g_s.chan_confirmed = 1;
    jsonl_emit_sensor_health(&g_s);                /* suppressed */
    mon_radios_set_state(1, MON_RADIO_LOST, "The interface disappeared");
    jsonl_emit_sensor_health(&g_s);                /* 2: a radio was lost */
    jsonl_emit_sensor_health(&g_s);                /* suppressed */
    ASSERT_EQ(read_back(), 2);

    ASSERT(strstr(g_body, "\"mon_extra_radios\":2") != NULL);
    ASSERT(strstr(g_body, "\"mon_dup_dropped\":1") != NULL);
    ASSERT(strstr(g_body, "\"mon_r0_iface\":\"mon0\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r0_state\":\"running\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r0_chan\":11") != NULL);
    ASSERT(strstr(g_body, "\"mon_r0_freq\":2462") != NULL);
    ASSERT(strstr(g_body, "\"mon_r0_frames\":1") != NULL);
    ASSERT(strstr(g_body, "\"mon_r1_iface\":\"mon1\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r1_state\":\"running\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r1_freq\":5180") != NULL);
    ASSERT(strstr(g_body, "\"mon_r1_frames\":1") != NULL);
    ASSERT(strstr(g_body, "\"mon_r1_dup_dropped\":1") != NULL);
    ASSERT(strstr(g_body, "\"mon_r2_iface\":\"mon2\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r2_state\":\"not_open\"") != NULL);
    ASSERT(strstr(g_body, "\"mon_r2_err\":\"monitor iface mon2 not found\"") != NULL);
    ASSERT(strstr(g_body, "mon_r3_") == NULL);
    /* The second line: the loss, with its reason and the counts as they
     * then stood. */
    const char *second = strchr(g_body, '\n');
    ASSERT(second != NULL);
    if (second) {
        ASSERT(strstr(second, "\"mon_r1_state\":\"lost\"") != NULL);
        ASSERT(strstr(second, "\"mon_r1_err\":\"The interface disappeared\"") != NULL);
        ASSERT(strstr(second, "\"mon_r1_dup_dropped\":2") != NULL);
        ASSERT(strstr(second, "\"mon_r0_chan\":1,") != NULL);
    }
}

#ifdef WITH_PCAP
/* Opening a further radio, over a fake /sys/class/net tree as the
 * --monitor-iface pin tests do (tests/test_capture_path.c): absent,
 * typeless and not-in-monitor-mode radios are refused in radio 0's
 * words and nothing is opened; a type-803 name no host has gets as far
 * as pcap_open_live() and fails there, which is what says the type test
 * passed. Its state stays what the caller recorded. */
static void test_a_radio_that_cannot_be_opened_is_refused(void) {
    char root[256], p[400];
    snprintf(root, sizeof(root), "%s/sloth_monr_XXXXXX", test_tmpdir());
    ASSERT(mkdtemp(root) != NULL);
    static const struct { const char *name, *type; } dev[] = {
        { "zzq_mon_b", "803" }, { "zzq_eth0", "1" }, { "zzq_notype", NULL },
    };
    for (int i = 0; i < 3; i++) {
        snprintf(p, sizeof(p), "%s/%s", root, dev[i].name);
        ASSERT_EQ(mkdir(p, 0700), 0);
        if (!dev[i].type) continue;
        snprintf(p, sizeof(p), "%s/%s/type", root, dev[i].name);
        FILE *fp = fopen(p, "w");
        ASSERT(fp != NULL);
        if (fp) { fprintf(fp, "%s\n", dev[i].type); fclose(fp); }
    }
    probe_test_set_sysfs_net(root);
    two_radios();
    char why[96];
    ASSERT_EQ(mon_radio_open(1, "zzq_absent", why, sizeof(why)), 0);
    ASSERT_STR(why, "monitor iface zzq_absent not found");
    ASSERT_EQ(mon_radio_open(1, "zzq_eth0", why, sizeof(why)), 0);
    ASSERT_STR(why, "monitor iface zzq_eth0 is not in monitor mode (type 1)");
    ASSERT_EQ(mon_radio_open(1, "zzq_notype", why, sizeof(why)), 0);
    ASSERT_STR(why, "monitor iface zzq_notype: type unreadable");
    ASSERT_EQ(mon_radio_open(1, "zzq_mon_b", why, sizeof(why)), 0);
    ASSERT_EQ(strncmp(why, "pcap(zzq_mon_b)", 15), 0);
    /* Radio 0 is probe.c's to open, and there is no radio 4. */
    ASSERT_EQ(mon_radio_open(0, "zzq_mon_b", why, sizeof(why)), 0);
    ASSERT_EQ(mon_radio_open(MON_RADIO_MAX, "zzq_mon_b", why, sizeof(why)), 0);
    mon_radio_t r;
    ASSERT_EQ(mon_radios_get(1, &r), 1);
    ASSERT_EQ((int)r.state, (int)MON_RADIO_NAMED);
    /* Nothing was opened, so there is nothing to run or stop. */
    mon_radio_run();
    mon_radio_stop();
    ASSERT_EQ(mon_radios_get(1, &r), 1);
    ASSERT_EQ((int)r.state, (int)MON_RADIO_NAMED);
    probe_test_set_sysfs_net(NULL);
    for (int i = 0; i < 3; i++) {
        snprintf(p, sizeof(p), "%s/%s/type", root, dev[i].name);
        (void)remove(p);
        snprintf(p, sizeof(p), "%s/%s", root, dev[i].name);
        (void)rmdir(p);
    }
    (void)rmdir(root);
}
#endif /* WITH_PCAP */

/* Each further sensor radio that was opened is a `sensor` row of its
 * own, after radio 0's (which keeps slot 0), counting the frames that
 * radio delivered; radio 0's row counts radio 0's. One that was never
 * opened is not a sensor, and a one-radio run registers none.
 * Red under: the `r.state == MON_RADIO_NAMED` skip removed. */
static void test_each_opened_radio_is_a_sensor(void) {
    static sloth_state_t ps;
    memset(&ps, 0, sizeof(ps));
    snprintf(ps.probe_iface, sizeof(ps.probe_iface), "mon0");
    three_radios();
    mon_radios_set_state(1, MON_RADIO_RUNNING, "");
    mon_radios_set_state(2, MON_RADIO_NAMED, "monitor iface mon2 not found");
    uint8_t f[64];
    for (int i = 0; i < 5; i++) {
        int n = probe_req(f, STA_A, (uint16_t)i, 0);
        ASSERT_EQ(mon_radio_frame(i < 2 ? 0 : 1, f, n, T0 + 9000 * i, 2437), 1);
    }
    poll_ctx_t ctx;
    for (int pass = 0; pass < 2; pass++) {
        poll_ctx_init(&ctx);
        poll_tick(&g_poll_wifi, &ps, &ctx);
        ASSERT_EQ(ps.sensor_count, 2);
        ASSERT_EQ(ps.sensors[0].kind, SENSOR_WIFI);
        ASSERT_STR(ps.sensors[0].iface, "mon0");
        ASSERT_EQ((long long)ps.sensors[0].observed, 2);
        ASSERT_EQ(ps.sensors[1].kind, SENSOR_WIFI);
        ASSERT_STR(ps.sensors[1].iface, "mon1");
        ASSERT_EQ((long long)ps.sensors[1].observed, 3);
    }
    /* One radio: the row there always was, and no other. */
    memset(&ps, 0, sizeof(ps));
    snprintf(ps.probe_iface, sizeof(ps.probe_iface), "mon0");
    mon_radios_reset();
    poll_ctx_init(&ctx);
    poll_tick(&g_poll_wifi, &ps, &ctx);
    ASSERT_EQ(ps.sensor_count, 1);
    ASSERT_STR(ps.sensors[0].iface, "mon0");
}

void run_mon_radios_tests(void) {
    TEST_SUITE("mon_radios - several sensor radios");
    RUN_TEST(test_registry_is_bounded_and_unique);
    RUN_TEST(test_one_radio_is_untouched);
    RUN_TEST(test_same_frame_on_two_radios_is_delivered_once);
    RUN_TEST(test_same_frame_twice_on_one_radio_is_delivered_twice);
    RUN_TEST(test_a_retry_or_a_different_frame_is_delivered);
    RUN_TEST(test_window_expiry);
    RUN_TEST(test_a_late_reader_still_finds_its_duplicates);
    RUN_TEST(test_control_frames_without_a_sequence_number);
    RUN_TEST(test_table_wrap_and_bounds);
    RUN_TEST(test_hop_split_covers_every_channel_once);
    RUN_TEST(test_hopping_radios_sit_on_different_channels);
    RUN_TEST(test_a_lost_radio_has_its_channels_dealt_out_again);
    RUN_TEST(test_hop_failures_and_frames_are_per_radio);
    RUN_TEST(test_hop_with_one_radio_is_untouched);
    RUN_TEST(test_cli_names);
    RUN_TEST(test_cli_refusals);
#ifdef WITH_PCAP
    RUN_TEST(test_path_delivers_a_frame_two_radios_heard_once);
    RUN_TEST(test_path_with_one_radio_is_as_it_was);
    RUN_TEST(test_radio0_figures_are_radio0s);
    RUN_TEST(test_three_reader_threads_deliver_each_frame_once);
    RUN_TEST(test_a_radio_that_cannot_be_opened_is_refused);
#endif
    RUN_TEST(test_each_opened_radio_is_a_sensor);
    RUN_TEST(test_sensor_health_with_one_radio);
    RUN_TEST(test_sensor_health_reports_each_radio);
}
