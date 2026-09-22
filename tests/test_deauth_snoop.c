#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "alerts.h"
#include "deauth_snoop.h"
#include "flood_window.h"
#include "views/deauth.h"

/*
 * Frames here are built byte by byte from IEEE 802.11-2020, never from
 * a capture (agents/AGENTS.md "No pcap fixtures").
 *
 * Management frame header, 9.3.3.2 (24 bytes; 28 with +HTC):
 *   [0]     FC byte 0: (subtype<<4)|(type<<2)|protocol version
 *   [1]     FC byte 1 (9.2.4.1): 0x08 Retry, 0x40 Protected Frame,
 *                                0x80 +HTC/Order
 *   [2-3]   Duration
 *   [4-9]   Address 1 = RA/DA (receiver)
 *   [10-15] Address 2 = TA/SA (transmitter, as claimed)
 *   [16-21] Address 3 = BSSID
 *   [22-23] Sequence Control, little-endian: frag (4 bits) | seq << 4
 *   [24-27] HT Control, only when +HTC is set (9.2.4.7)
 * Body of Deauthentication (9.3.3.12) / Disassociation (9.3.3.5):
 *   Reason Code, 2 octets little-endian (9.4.1.7), then optional
 *   elements (e.g. the MMIE of BIP on group-addressed robust frames).
 *
 * Deauth:  FC0 = (12<<4)|(0<<2)|0 = 0xC0
 * Disassoc: FC0 = (10<<4)|(0<<2)|0 = 0xA0
 */

#define FC1_RETRY     0x08
#define FC1_PROTECTED 0x40
#define FC1_HTC       0x80

static const uint8_t SRC_A[6]  = {0xaa,0xbb,0xcc,0x11,0x22,0x33};
static const uint8_t SRC_B[6]  = {0xde,0xad,0xbe,0xef,0x00,0x01};
static const uint8_t DST_STA[6]= {0x11,0x22,0x33,0x44,0x55,0x66};
static const uint8_t BCAST[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t BSSID_A[6]= {0x00,0x11,0x22,0x33,0x44,0x55};
static const uint8_t BSSID_B[6]= {0x00,0x11,0x22,0x33,0x44,0x66};
static const uint8_t STA_X[6]  = {0x12,0x34,0x56,0x78,0x9a,0xbc};

/* ── Deterministic clock ─────────────────────────────────── */

/* Monotonic ms and wall seconds move independently so a test can make
 * the wall clock jump while monotonic time runs on. */
static uint64_t g_mono;
static time_t   g_wall;
static uint64_t fake_mono(void) { return g_mono; }
static time_t   fake_wall(void) { return g_wall; }

#define WALL0 ((time_t)1790000000)   /* 2026-09 */

static void clock_reset(void) {
    g_mono = 1000000;   /* not 0: a zero timestamp must not look special */
    g_wall = WALL0;
    flood_test_set_clock(fake_mono, fake_wall);
}

/* Advance both clocks together. */
static void tick_ms(uint64_t ms) {
    g_wall += (time_t)((g_mono % 1000 + ms) / 1000);
    g_mono += ms;
}

/* ── Frame builders ──────────────────────────────────────── */

/* Writes a 26-byte deauth/disassoc (header + Reason Code). */
static int build(uint8_t *f, uint8_t sub, uint8_t fc1,
                 const uint8_t da[6], const uint8_t sa[6],
                 const uint8_t bssid[6], uint16_t seq, uint16_t reason) {
    f[0] = (uint8_t)(sub << 4);  /* type 0 = management */
    f[1] = fc1;
    f[2] = 0x3a; f[3] = 0x01;    /* Duration 314 us — any value */
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, sa,    6);
    memcpy(f + 16, bssid, 6);
    uint16_t sc = (uint16_t)(seq << 4);   /* fragment 0 */
    f[22] = (uint8_t)(sc & 0xff);
    f[23] = (uint8_t)(sc >> 8);
    f[24] = (uint8_t)(reason & 0xff);
    f[25] = (uint8_t)(reason >> 8);
    return 26;
}

/* Build, parse and record — the path capture takes. */
static void feed(uint8_t sub, uint8_t fc1, const uint8_t da[6],
                 const uint8_t sa[6], const uint8_t bssid[6],
                 uint16_t seq, uint16_t reason) {
    uint8_t f[26];
    int n = build(f, sub, fc1, da, sa, bssid, seq, reason);
    deauth_frame_t df;
    ASSERT_EQ(deauth_parse(f, n, &df), 1);
    deauth_record(&df);
}

/* Distinct frames 100 ms apart — for tests that only need rows. */
static uint16_t g_seq = 1;
static void rec(const uint8_t *src, const uint8_t *dst,
                const uint8_t *bssid, uint16_t reason, uint8_t sub) {
    feed(sub, 0, dst, src, bssid, g_seq++, reason);
    tick_ms(100);
}

static void snap(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    deauth_snapshot(s);
}

static const deauth_victim_t *find_victim(const sloth_state_t *s,
                                          const uint8_t bssid[6],
                                          const uint8_t victim[6]) {
    for (int i = 0; i < s->deauth_victim_count; i++)
        if (memcmp(s->deauth_victims[i].bssid,  bssid,  6) == 0 &&
            memcmp(s->deauth_victims[i].victim, victim, 6) == 0)
            return &s->deauth_victims[i];
    return NULL;
}

static int any_row_flood(const sloth_state_t *s) {
    for (int i = 0; i < s->deauth_count; i++)
        if (s->deauth_events[i].flood) return 1;
    return 0;
}

static int count_alerts(const sloth_state_t *s, alert_type_t t) {
    int n = 0;
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) n++;
    return n;
}

static int find_alert_t(const sloth_state_t *s, alert_type_t t) {
    for (int i = 0; i < s->alert_count; i++)
        if (s->alerts[i].type == t) return i;
    return -1;
}

/* ── deauth_parse ────────────────────────────────────────── */

static void test_parse_deauth(void) {
    uint8_t f[26]; build(f, 12, 0, DST_STA, SRC_A, BSSID_A, 0x123, 1);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 1);
    ASSERT_EQ(d.subtype, 12);
    ASSERT_EQ(d.reason, 1);
    ASSERT_EQ(d.reason_valid, 1);
    ASSERT_EQ(d.protected_, 0);
    ASSERT_EQ(d.truncated, 0);
    ASSERT_EQ(d.retry, 0);
    ASSERT_EQ(d.seq, 0x123);
    ASSERT_EQ(d.frag, 0);
    ASSERT_EQ(memcmp(d.src,   SRC_A,   6), 0);
    ASSERT_EQ(memcmp(d.dst,   DST_STA, 6), 0);
    ASSERT_EQ(memcmp(d.bssid, BSSID_A, 6), 0);
}

static void test_parse_disassoc(void) {
    uint8_t f[26]; build(f, 10, 0, DST_STA, SRC_A, BSSID_A, 7, 4);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 1);
    ASSERT_EQ(d.subtype, 10);
    ASSERT_EQ(d.reason, 4);
}

static void test_parse_broadcast_dst(void) {
    uint8_t f[26]; build(f, 12, 0, BCAST, SRC_A, BSSID_A, 7, 1);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 1);
    ASSERT_EQ(memcmp(d.dst, BCAST, 6), 0);
}

static void test_parse_rejects_probe_request(void) {
    uint8_t f[26]; build(f, 4, 0, DST_STA, SRC_A, BSSID_A, 7, 1);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 0);
}

static void test_parse_rejects_data_frame(void) {
    uint8_t f[26]; build(f, 12, 0, DST_STA, SRC_A, BSSID_A, 7, 1);
    f[0] = 0x08;   /* type 2 data, subtype 0 */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 0);
}

static void test_parse_rejects_too_short(void) {
    uint8_t f[26]; build(f, 12, 0, DST_STA, SRC_A, BSSID_A, 7, 1);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 20, &d), 0);
    ASSERT_EQ(deauth_parse(f, 23, &d), 0);
}

/* A header with no body was on the air, but it carries no reason. Old
 * behaviour reported reason 0 as if decoded. */
static void test_parse_header_only_is_truncated(void) {
    uint8_t f[26]; build(f, 12, 0, DST_STA, SRC_A, BSSID_A, 7, 3);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 24, &d), 1);
    ASSERT_EQ(d.truncated, 1);
    ASSERT_EQ(d.reason_valid, 0);
    ASSERT_EQ(d.reason, 0);
    /* One body octet is still not a Reason Code. */
    ASSERT_EQ(deauth_parse(f, 25, &d), 1);
    ASSERT_EQ(d.truncated, 1);
    ASSERT_EQ(d.reason_valid, 0);
}

static void test_parse_reason_code_15(void) {
    uint8_t f[26]; build(f, 12, 0, DST_STA, SRC_A, BSSID_A, 7, 15);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 1);
    ASSERT_EQ(d.reason, 15);
    ASSERT_EQ(d.reason_valid, 1);
}

/* PMF (802.11w) individually addressed deauth: Protected Frame set, the
 * body is CCMP-encrypted (12.5.3.2): 8-octet CCMP header
 *   PN0 PN1 rsvd (KeyID<<6 | ExtIV 0x20) PN2 PN3 PN4 PN5
 * then the encrypted Reason Code, then an 8-octet MIC. Bytes 24..25 are
 * PN0/PN1. PN0 = 0x07 is chosen on purpose: a parser that ignores the
 * flag reports "reason 7, Class 3 frame from nonassociated STA" — the
 * most plausible-looking wrong answer. */
static void test_parse_protected_reason_not_decoded(void) {
    uint8_t f[42]; memset(f, 0, sizeof(f));
    build(f, 12, FC1_PROTECTED, DST_STA, SRC_A, BSSID_A, 0x40, 0);
    f[24] = 0x07; f[25] = 0x00;          /* PN0, PN1 */
    f[26] = 0x00; f[27] = 0x20;          /* reserved, ExtIV, KeyID 0 */
    f[28] = 0x00; f[29] = 0x00; f[30] = 0x00; f[31] = 0x00; /* PN2..5 */
    f[32] = 0x9c; f[33] = 0x5e;          /* encrypted Reason Code */
    memset(f + 34, 0xa5, 8);             /* MIC */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 42, &d), 1);
    ASSERT_EQ(d.protected_, 1);
    ASSERT_EQ(d.reason_valid, 0);
    ASSERT_EQ(d.reason, 0);
    ASSERT_EQ(d.truncated, 0);
    ASSERT_EQ(d.fc_flags, FC1_PROTECTED);
}

/* Group-addressed robust management frames under PMF are not encrypted:
 * BIP (12.5.4) appends an MMIE (element 76, length 16: Key ID 2, IPN 6,
 * MIC 8) and leaves the Reason Code in clear. Protected Frame stays 0,
 * so the reason is genuinely decodable. */
static void test_parse_bip_broadcast_reason_decoded(void) {
    uint8_t f[44]; memset(f, 0, sizeof(f));
    build(f, 12, 0, BCAST, SRC_A, BSSID_A, 0x41, 3);
    f[26] = 76; f[27] = 16;              /* MMIE */
    f[28] = 0x04; f[29] = 0x00;          /* Key ID 4 */
    f[30] = 0x01;                        /* IPN */
    memset(f + 36, 0x5a, 8);             /* MIC */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 44, &d), 1);
    ASSERT_EQ(d.protected_, 0);
    ASSERT_EQ(d.reason_valid, 1);
    ASSERT_EQ(d.reason, 3);
}

/* +HTC (Order bit in a management frame, 9.2.4.1.10) inserts a 4-octet
 * HT Control field before the body, so the Reason Code is at 28. */
static void test_parse_htc_shifts_body(void) {
    uint8_t f[30]; memset(f, 0, sizeof(f));
    build(f, 12, FC1_HTC, DST_STA, SRC_A, BSSID_A, 9, 0);
    f[24] = 0x01; f[25] = 0x02; f[26] = 0x03; f[27] = 0x04;  /* HT Control */
    f[28] = 0x08; f[29] = 0x00;          /* Reason 8 */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 30, &d), 1);
    ASSERT_EQ(d.reason_valid, 1);
    ASSERT_EQ(d.reason, 8);
    /* Header complete, body missing. */
    ASSERT_EQ(deauth_parse(f, 28, &d), 1);
    ASSERT_EQ(d.truncated, 1);
    ASSERT_EQ(d.reason_valid, 0);
    /* +HTC header itself cut short. */
    ASSERT_EQ(deauth_parse(f, 26, &d), 0);
}

static void test_parse_retry_seq_frag(void) {
    uint8_t f[26]; build(f, 12, FC1_RETRY, DST_STA, SRC_A, BSSID_A, 0xabc, 1);
    f[22] |= 0x03;                       /* fragment number 3 */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 26, &d), 1);
    ASSERT_EQ(d.retry, 1);
    ASSERT_EQ(d.seq, 0xabc);
    ASSERT_EQ(d.frag, 3);
    ASSERT_EQ(d.fc_flags, FC1_RETRY);
}

/* ── Rows ────────────────────────────────────────────────── */

static void test_record_new_entry(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);

    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(memcmp(s.deauth_events[0].src,   SRC_A,   6), 0);
    ASSERT_EQ(memcmp(s.deauth_events[0].dst,   DST_STA, 6), 0);
    ASSERT_EQ(memcmp(s.deauth_events[0].bssid, BSSID_A, 6), 0);
    ASSERT_EQ(s.deauth_events[0].reason,  1);
    ASSERT_EQ(s.deauth_events[0].reason_valid, 1);
    ASSERT_EQ(s.deauth_events[0].subtype, 12);
    ASSERT_EQ(s.deauth_events[0].count,   1);
    ASSERT_EQ(s.deauth_events[0].flood,   0);
    ASSERT_EQ((long)s.deauth_events[0].first_seen, (long)WALL0);
    ASSERT_EQ((long)s.deauth_events[0].flood_last, 0L);
    flood_test_set_clock(NULL, NULL);
}

static void test_record_update_existing(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);

    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_events[0].count, 2);
    flood_test_set_clock(NULL, NULL);
}

static void test_record_distinct_pairs(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    rec(SRC_B, BCAST,   BSSID_A, 1, 12);

    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);
    flood_test_set_clock(NULL, NULL);
}

/* Subtype is part of the observation key: deauth and disassoc between
 * the same addresses are different frames with different effects. */
static void test_record_subtype_is_part_of_key(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    rec(SRC_A, DST_STA, BSSID_A, 8, 10);
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);
    flood_test_set_clock(NULL, NULL);
}

/* ── Window semantics (#88 regression list) ──────────────── */

/* The issue's headline case. Adjacent gaps of 4 s are each under the
 * old 5 s reset, so a chain counter reached 5; no 5 s interval holds
 * more than two of these frames. */
static void test_five_spaced_4s_no_flood(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        if (i < 4) tick_ms(4000);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_events[0].count, 5);
    ASSERT_EQ(s.deauth_events[0].flood, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, DST_STA);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->flood, 0); ASSERT_EQ(v->frames, 5); }
    alerts_update(&s);
    ASSERT_EQ(find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD), -1);
    flood_test_set_clock(NULL, NULL);
}

static void test_five_within_2s_floods(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        if (i < 4) tick_ms(500);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    ASSERT_EQ(s.deauth_events[0].win_count, 5);
    ASSERT_EQ((long)s.deauth_events[0].flood_last, (long)g_wall);
    ASSERT_EQ(s.deauth_flood_active, 1);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, DST_STA);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->flood, 1); ASSERT_EQ(v->win_count, 5); }
    alerts_update(&s);
    int idx = find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    if (idx >= 0) {
        ASSERT(strstr(s.alerts[idx].key,
                      "deauth:11:22:33:44:55:66@00:11:22:33:44:55") != NULL);
        /* Evidence wording: frames observed, not clients disconnected. */
        ASSERT(strstr(s.alerts[idx].detail, "observed 5") != NULL);
        ASSERT(strstr(s.alerts[idx].detail, "reason=7") != NULL);
        ASSERT(strstr(s.alerts[idx].detail, "unverified") != NULL);
    }
    flood_test_set_clock(NULL, NULL);
}

/* Window edge: half-open (now - 5 s, now]. Five frames whose first and
 * last are exactly 5.000 s apart are not "in 5 s"; 4.999 s is. */
static void test_window_boundary(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        if (i < 4) tick_ms(1250);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 0);

    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        if (i < 4) tick_ms(i == 3 ? 1249 : 1250);
    }
    snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    flood_test_set_clock(NULL, NULL);
}

/* A slow chain that at some point *does* squeeze five into the window
 * floods from that frame on — and not before. */
static void test_sliding_window_trips_mid_chain(void) {
    clock_reset(); deauth_clear();
    static const uint32_t gaps[] = { 4000, 4000, 300, 300, 300, 300 };
    feed(12, 0, DST_STA, BSSID_A, BSSID_A, 1, 7);
    sloth_state_t s;
    for (int i = 0; i < 6; i++) {
        tick_ms(gaps[i]);
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(2 + i), 7);
        snap(&s);
        /* frames at 0,4,8,8.3,8.6,8.9,9.2: the fifth inside (t-5, t]
         * first appears at 8.9 (4, 8, 8.3, 8.6, 8.9). */
        ASSERT_EQ(s.deauth_events[0].flood, i >= 4 ? 1 : 0);
    }
    flood_test_set_clock(NULL, NULL);
}

/* Flood status decays with time alone — no further frame needed — and
 * the evidence of when it happened survives the decay. */
static void test_flood_decays_without_new_frames(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, BCAST, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        if (i < 4) tick_ms(200);
    }
    time_t tripped_at = g_wall;
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_flood_active, 1);

    tick_ms(DEAUTH_FLOOD_HOLD_SECS * 1000 - 1);    /* just inside hold */
    snap(&s);
    ASSERT_EQ(s.deauth_flood_active, 1);
    ASSERT_EQ(s.deauth_events[0].win_count, 0);    /* window itself emptied */

    tick_ms(1);                                    /* hold elapsed */
    snap(&s);
    ASSERT_EQ(s.deauth_count, 1);                  /* row still aged-in */
    ASSERT_EQ(s.deauth_events[0].flood, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
    ASSERT_EQ((long)s.deauth_events[0].flood_last, (long)tripped_at);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, BCAST);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->flood, 0); ASSERT_EQ((long)v->flood_last, (long)tripped_at); }
    alerts_update(&s);
    ASSERT_EQ(find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD), -1);
    flood_test_set_clock(NULL, NULL);
}

/* A station roaming away (IEEE 802.11-2020 11.3.5): it tells its old AP
 * it is leaving (reason 3), the frame is retried twice for want of an
 * ACK, and the old AP answers late traffic with Class-3 deauths
 * (reason 7). Five frames on the air in under a second, all about one
 * station in one BSS — three distinct transmissions. Not a flood. */
static void test_benign_roaming_no_flood(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    feed(12, 0,         BSSID_A, STA_X, BSSID_A, 200, 3);  tick_ms(5);
    feed(12, FC1_RETRY, BSSID_A, STA_X, BSSID_A, 200, 3);  tick_ms(5);
    feed(12, FC1_RETRY, BSSID_A, STA_X, BSSID_A, 200, 3);  tick_ms(300);
    feed(12, 0,         STA_X, BSSID_A, BSSID_A, 900, 7);  tick_ms(300);
    feed(12, 0,         STA_X, BSSID_A, BSSID_A, 901, 7);
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);                /* two directions */
    ASSERT_EQ(any_row_flood(&s), 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
    ASSERT_EQ(s.deauth_victim_count, 1);         /* one station, one BSS */
    const deauth_victim_t *v = find_victim(&s, BSSID_A, STA_X);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->frames, 3); ASSERT_EQ(v->streams, 2); }
    alerts_update(&s);
    ASSERT_EQ(find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD), -1);
    flood_test_set_clock(NULL, NULL);
}

/* Retransmissions: Retry=1 repeating the previous sequence number is the
 * same MPDU again, discarded by the receiver's duplicate filter
 * (10.3.2.14). Observed, counted as observed, never counted as impact. */
static void test_retransmissions_not_distinct(void) {
    clock_reset(); deauth_clear();
    feed(12, 0, DST_STA, BSSID_A, BSSID_A, 55, 7);
    for (int i = 0; i < 6; i++) {
        tick_ms(50);
        feed(12, FC1_RETRY, DST_STA, BSSID_A, BSSID_A, 55, 7);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].count, 7);
    ASSERT_EQ(s.deauth_events[0].retries, 6);
    ASSERT_EQ(s.deauth_events[0].flood, 0);
    ASSERT_EQ(s.deauth_events[0].win_count, 1);
    ASSERT_EQ(s.deauth_flood_active, 0);
    flood_test_set_clock(NULL, NULL);
}

/* Retry=1 with a *new* sequence number is a retransmission of a frame
 * we missed — a distinct MPDU, and it counts. */
static void test_retry_with_new_seq_counts(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, FC1_RETRY, DST_STA, BSSID_A, BSSID_A, (uint16_t)(60 + i), 7);
        tick_ms(100);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].retries, 0);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    flood_test_set_clock(NULL, NULL);
}

/* The window runs on the monotonic clock. A wall-clock step forward in
 * the middle of a burst (NTP sync) must not break it up... */
static void test_wall_jump_forward_keeps_flood(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        tick_ms(300);
        if (i == 1) g_wall += 3600;
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    flood_test_set_clock(NULL, NULL);
}

/* ...a wall-clock step backwards must not either... */
static void test_wall_jump_backward_keeps_flood(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        tick_ms(300);
        if (i == 2) g_wall -= 3600;
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    flood_test_set_clock(NULL, NULL);
}

/* ...a frozen wall clock must not compress a slow sequence into one...*/
static void test_frozen_wall_slow_frames_no_flood(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        g_mono += 4000;             /* wall does not move */
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 0);
    flood_test_set_clock(NULL, NULL);
}

/* ...and a step forward must not age a live flood out of the table. */
static void test_wall_jump_does_not_age_out(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, DST_STA, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        tick_ms(200);
    }
    g_wall += 3600;
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_victim_count, 1);
    ASSERT_EQ(s.deauth_flood_active, 1);
    /* Monotonic idle time is what ages rows. */
    tick_ms(DEAUTH_AGE_SECS * 1000 + 1000);
    snap(&s);
    ASSERT_EQ(s.deauth_count, 0);
    ASSERT_EQ(s.deauth_victim_count, 0);
    flood_test_set_clock(NULL, NULL);
}

/* Same addresses under two BSSIDs are two observations, and neither
 * overwrites the other's BSSID. Three frames each is below threshold
 * for each BSS; merged they would have been six. */
static void test_multiple_bssids_not_merged(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 3; i++) {
        feed(12, 0, DST_STA, SRC_A, BSSID_A, (uint16_t)(10 + i), 7); tick_ms(150);
        feed(12, 0, DST_STA, SRC_A, BSSID_B, (uint16_t)(20 + i), 7); tick_ms(150);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);
    int seen_a = 0, seen_b = 0;
    for (int i = 0; i < s.deauth_count; i++) {
        if (memcmp(s.deauth_events[i].bssid, BSSID_A, 6) == 0) seen_a = s.deauth_events[i].count;
        if (memcmp(s.deauth_events[i].bssid, BSSID_B, 6) == 0) seen_b = s.deauth_events[i].count;
    }
    ASSERT_EQ(seen_a, 3);
    ASSERT_EQ(seen_b, 3);
    ASSERT_EQ(any_row_flood(&s), 0);
    ASSERT_EQ(s.deauth_victim_count, 2);
    ASSERT_EQ(s.deauth_flood_active, 0);
    alerts_update(&s);
    ASSERT_EQ(find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD), -1);
    flood_test_set_clock(NULL, NULL);
}

/* Broadcast deauths from two APs share Address 1. Keyed on the
 * destination alone they merged into one "deauth:ff:ff:ff:ff:ff:ff"
 * alert; keyed on (BSSID, victim) only the flooded BSS alerts. */
static void test_broadcast_per_bssid(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 5; i++) {
        feed(12, 0, BCAST, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7);
        tick_ms(100);
        if (i < 2) {
            feed(12, 0, BCAST, BSSID_B, BSSID_B, (uint16_t)(30 + i), 3);
            tick_ms(100);
        }
    }
    sloth_state_t s; snap(&s);
    const deauth_victim_t *va = find_victim(&s, BSSID_A, BCAST);
    const deauth_victim_t *vb = find_victim(&s, BSSID_B, BCAST);
    ASSERT(va != NULL); ASSERT(vb != NULL);
    if (va) ASSERT_EQ(va->flood, 1);
    if (vb) ASSERT_EQ(vb->flood, 0);
    alerts_update(&s);
    ASSERT_EQ(count_alerts(&s, ALERT_TYPE_DEAUTH_FLOOD), 1);
    int idx = find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD);
    if (idx >= 0)
        ASSERT(strstr(s.alerts[idx].key, "@00:11:22:33:44:55") != NULL);
    flood_test_set_clock(NULL, NULL);
}

/* Spoofing tools alternate AP→STA and STA→AP. Each stream carries three
 * frames, the station is hit by six: the aggregate floods where no
 * single stream does. */
static void test_direction_split_floods_victim(void) {
    clock_reset(); deauth_clear(); alerts_clear();
    for (int i = 0; i < 3; i++) {
        feed(12, 0, STA_X, BSSID_A, BSSID_A, (uint16_t)(10 + i), 7); tick_ms(150);
        feed(12, 0, BSSID_A, STA_X, BSSID_A, (uint16_t)(50 + i), 7); tick_ms(150);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);
    ASSERT_EQ(any_row_flood(&s), 0);
    ASSERT_EQ(s.deauth_victim_count, 1);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, STA_X);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->flood, 1); ASSERT_EQ(v->streams, 2); ASSERT_EQ(v->frames, 6); }
    ASSERT_EQ(s.deauth_flood_active, 1);
    alerts_update(&s);
    int idx = find_alert_t(&s, ALERT_TYPE_DEAUTH_FLOOD);
    ASSERT(idx >= 0);
    if (idx >= 0)
        ASSERT(strstr(s.alerts[idx].key, "deauth:12:34:56:78:9a:bc@") != NULL);
    flood_test_set_clock(NULL, NULL);
}

/* Deauth and disassoc at one station add up for impact. */
static void test_subtype_split_floods_victim(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < 3; i++) {
        feed(12, 0, STA_X, BSSID_A, BSSID_A, (uint16_t)(10 + 2*i), 7); tick_ms(100);
        feed(10, 0, STA_X, BSSID_A, BSSID_A, (uint16_t)(11 + 2*i), 8); tick_ms(100);
    }
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 2);
    ASSERT_EQ(any_row_flood(&s), 0);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, STA_X);
    ASSERT(v != NULL);
    if (v) ASSERT_EQ(v->flood, 1);
    flood_test_set_clock(NULL, NULL);
}

/* A PMF-protected deauth is recorded — it was observed — but its
 * reason stays undecoded through the row and the aggregate, and the DB
 * / JSONL / view read reason_valid rather than a fake code. */
static void test_protected_deauth_recorded_without_reason(void) {
    clock_reset(); deauth_clear();
    uint8_t f[42]; memset(f, 0, sizeof(f));
    build(f, 12, FC1_PROTECTED, STA_X, BSSID_A, BSSID_A, 0x40, 0);
    f[24] = 0x07; f[27] = 0x20;
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 42, &d), 1);
    deauth_record(&d);
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_events[0].reason_valid, 0);
    ASSERT_EQ(s.deauth_events[0].reason, 0);
    ASSERT_EQ(s.deauth_events[0].protected_count, 1);
    ASSERT_EQ(s.deauth_events[0].fc_flags, FC1_PROTECTED);
    const deauth_victim_t *v = find_victim(&s, BSSID_A, STA_X);
    ASSERT(v != NULL);
    if (v) { ASSERT_EQ(v->reason_valid, 0); ASSERT_EQ(v->protected_count, 1); }
    flood_test_set_clock(NULL, NULL);
}

/* A header-only frame is kept as observed, flagged truncated, and its
 * reason reported as unknown rather than 0. */
static void test_header_only_counts_truncated(void) {
    clock_reset(); deauth_clear();
    uint8_t f[26]; build(f, 12, 0, STA_X, BSSID_A, BSSID_A, 5, 0);
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 24, &d), 1);
    deauth_record(&d);
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].truncated_count, 1);
    ASSERT_EQ(s.deauth_events[0].reason_valid, 0);
    flood_test_set_clock(NULL, NULL);
}

static void test_victim_of_frame_to_ap_is_sender(void) {
    clock_reset(); deauth_clear();
    feed(10, 0, BSSID_A, STA_X, BSSID_A, 3, 8);   /* STA → AP, leaving */
    sloth_state_t s; snap(&s);
    ASSERT(find_victim(&s, BSSID_A, STA_X) != NULL);
    ASSERT(find_victim(&s, BSSID_A, BSSID_A) == NULL);
    flood_test_set_clock(NULL, NULL);
}

static void test_flood_active_with_multiple_entries(void) {
    clock_reset(); deauth_clear();
    rec(SRC_B, DST_STA, BSSID_A, 1, 12);            /* benign */
    for (int i = 0; i < DEAUTH_FLOOD_THRESH; i++)
        rec(SRC_A, BCAST, BSSID_A, 1, 12);          /* flood */
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_flood_active, 1);
    flood_test_set_clock(NULL, NULL);
}

static void test_no_flood_below_threshold(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH - 1; i++)
        rec(SRC_A, BCAST, BSSID_A, 1, 12);
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_events[0].flood, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
    flood_test_set_clock(NULL, NULL);
}

static void test_clear_empties_table(void) {
    clock_reset();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    deauth_clear();
    sloth_state_t s; snap(&s);
    ASSERT_EQ(s.deauth_count, 0);
    ASSERT_EQ(s.deauth_victim_count, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
    flood_test_set_clock(NULL, NULL);
}

static void test_snapshot_clamps_sel(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.deauth_sel = 99;
    deauth_snapshot(&s);
    ASSERT_EQ(s.deauth_sel, 0);
    flood_test_set_clock(NULL, NULL);
}

/* ── view_deauth_draw smoke tests ────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_deauth_draw(&s);
    ASSERT(1);
}

static void test_view_draw_normal(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1,  12);
    rec(SRC_B, BCAST,   BSSID_A, 15, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT(1);
}

static void test_view_draw_with_flood(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH + 2; i++)
        rec(SRC_A, BCAST, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT(s.deauth_flood_active);
}

static void test_view_draw_disassoc(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 4, 10);  /* disassoc reason 4 */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT_EQ(s.deauth_events[0].subtype, 10);
}


/* ── BTM section in the deauth view (#59) ────────────────── */

static void seed_btm_row(sloth_state_t *s, int imminent) {
    btm_steer_t *b = &s->btm_steers[s->btm_steer_count++];
    memset(b, 0, sizeof(*b));
    b->bssid[0] = 0xaa; b->bssid[5] = 0x30;
    b->sta[0]   = 0x12; b->sta[5]   = 0xbc;
    b->candidates[0][0] = 0xaa; b->candidates[0][5] = 0x31;
    b->candidate_count  = 1;
    b->req_count        = imminent + 2;
    b->imminent_count   = imminent;
    b->last_seen        = time(NULL);
}

/* TPRINT is printf in the test build, so the view's output can be
 * captured and asserted on rather than smoke-tested. Same technique as
 * test_help.c. Without this the empty-deauth case below would "pass"
 * against a draw that renders nothing at all. */
static void capture_deauth(const sloth_state_t *s, char *buf, int sz) {
    fflush(stdout);
    int saved = dup(fileno(stdout));
    FILE *tmp = tmpfile();
    dup2(fileno(tmp), fileno(stdout));
    view_deauth_draw(s);
    fflush(stdout);
    dup2(saved, fileno(stdout));
    close(saved);
    rewind(tmp);
    int n = (int)fread(buf, 1, sz - 1, tmp);
    buf[n < 0 ? 0 : n] = '\0';
    fclose(tmp);
}

/* A protected frame's reason column must say it is encrypted, not
 * render the CCMP packet number as a reason name. */
static void test_view_draw_protected_reason(void) {
    clock_reset(); deauth_clear();
    uint8_t f[42]; memset(f, 0, sizeof(f));
    build(f, 12, FC1_PROTECTED, STA_X, BSSID_A, BSSID_A, 0x40, 0);
    f[24] = 0x07; f[27] = 0x20;          /* PN0 = 7 would read "Class3-frame" */
    deauth_frame_t d;
    ASSERT_EQ(deauth_parse(f, 42, &d), 1);
    deauth_record(&d);
    sloth_state_t s; snap(&s);
    char buf[8192];
    capture_deauth(&s, buf, sizeof(buf));
    ASSERT(strstr(buf, "encrypted") != NULL);
    ASSERT(strstr(buf, "Class3-frame") == NULL);
}

static void test_view_draw_btm_section(void) {
    clock_reset(); deauth_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_btm_row(&s, BTM_ABUSE_THRESH);
    char buf[8192];
    capture_deauth(&s, buf, sizeof(buf));
    ASSERT(strstr(buf, "BTM steering") != NULL);
    ASSERT(strstr(buf, "aa:00:00:00:00:30") != NULL);   /* the AP   */
    ASSERT(strstr(buf, "12:00:00:00:00:bc") != NULL);   /* the STA  */
    ASSERT(strstr(buf, "aa:00:00:00:00:31") != NULL);   /* candidate */
}

static void test_view_draw_btm_with_no_deauths(void) {
    /* The case the section exists for: 802.11v moves a client without a
     * deauth frame, so an empty deauth table must not short-circuit the
     * draw. An early return here would show the operator "nothing is
     * throwing clients off" at the moment something is. */
    clock_reset(); deauth_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    seed_btm_row(&s, BTM_ABUSE_THRESH);
    ASSERT_EQ(s.deauth_count, 0);
    char buf[8192];
    capture_deauth(&s, buf, sizeof(buf));
    ASSERT(strstr(buf, "no deauth/disassoc frames") != NULL);
    ASSERT(strstr(buf, "BTM steering") != NULL);
    ASSERT(strstr(buf, "aa:00:00:00:00:30") != NULL);
}

static void test_view_draw_no_btm_section_when_empty(void) {
    /* No steering, no section — the view must not grow a header for a
     * table with nothing in it. */
    clock_reset(); deauth_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    char buf[8192];
    capture_deauth(&s, buf, sizeof(buf));
    ASSERT(strstr(buf, "BTM steering") == NULL);
}

static void test_view_draw_btm_table_full(void) {
    /* Row budget: a steering table larger than the screen must not run
     * off the end or index past the array. */
    clock_reset(); deauth_clear();
    sloth_state_t s; memset(&s, 0, sizeof(s));
    for (int i = 0; i < MAX_BTM_PAIRS; i++) seed_btm_row(&s, i % 5);
    ASSERT_EQ(s.btm_steer_count, MAX_BTM_PAIRS);
    view_deauth_draw(&s);
    ASSERT(1);
}

/* ── view_deauth_key tests ───────────────────────────────── */

static void test_view_key_nav(void) {
    clock_reset(); deauth_clear();
    rec(SRC_A, DST_STA, BSSID_A, 1, 12);
    rec(SRC_B, BCAST,   BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    s.deauth_sel = 0;

    view_deauth_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.deauth_sel, 1);

    view_deauth_key(&s, SLOTH_KEY_DOWN);  /* at end */
    ASSERT_EQ(s.deauth_sel, 1);

    view_deauth_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.deauth_sel, 0);

    view_deauth_key(&s, SLOTH_KEY_UP);    /* at top */
    ASSERT_EQ(s.deauth_sel, 0);
}

static void test_view_key_clear(void) {
    clock_reset(); deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH; i++)
        rec(SRC_A, BCAST, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    ASSERT_EQ(s.deauth_flood_active, 1);

    view_deauth_key(&s, 'c');
    ASSERT_EQ(s.deauth_count,        0);
    ASSERT_EQ(s.deauth_sel,          0);
    ASSERT_EQ(s.deauth_flood_active, 0);
}

/* ── Suite entry point ───────────────────────────────────── */

void run_deauth_snoop_tests(void) {
    TEST_SUITE("deauth_snoop");
    RUN_TEST(test_parse_deauth);
    RUN_TEST(test_parse_disassoc);
    RUN_TEST(test_parse_broadcast_dst);
    RUN_TEST(test_parse_rejects_probe_request);
    RUN_TEST(test_parse_rejects_data_frame);
    RUN_TEST(test_parse_rejects_too_short);
    RUN_TEST(test_parse_header_only_is_truncated);
    RUN_TEST(test_parse_reason_code_15);
    RUN_TEST(test_parse_protected_reason_not_decoded);
    RUN_TEST(test_parse_bip_broadcast_reason_decoded);
    RUN_TEST(test_parse_htc_shifts_body);
    RUN_TEST(test_parse_retry_seq_frag);
    RUN_TEST(test_record_new_entry);
    RUN_TEST(test_record_update_existing);
    RUN_TEST(test_record_distinct_pairs);
    RUN_TEST(test_record_subtype_is_part_of_key);
    RUN_TEST(test_five_spaced_4s_no_flood);
    RUN_TEST(test_five_within_2s_floods);
    RUN_TEST(test_window_boundary);
    RUN_TEST(test_sliding_window_trips_mid_chain);
    RUN_TEST(test_flood_decays_without_new_frames);
    RUN_TEST(test_benign_roaming_no_flood);
    RUN_TEST(test_retransmissions_not_distinct);
    RUN_TEST(test_retry_with_new_seq_counts);
    RUN_TEST(test_wall_jump_forward_keeps_flood);
    RUN_TEST(test_wall_jump_backward_keeps_flood);
    RUN_TEST(test_frozen_wall_slow_frames_no_flood);
    RUN_TEST(test_wall_jump_does_not_age_out);
    RUN_TEST(test_multiple_bssids_not_merged);
    RUN_TEST(test_broadcast_per_bssid);
    RUN_TEST(test_direction_split_floods_victim);
    RUN_TEST(test_subtype_split_floods_victim);
    RUN_TEST(test_protected_deauth_recorded_without_reason);
    RUN_TEST(test_header_only_counts_truncated);
    RUN_TEST(test_victim_of_frame_to_ap_is_sender);
    RUN_TEST(test_no_flood_below_threshold);
    RUN_TEST(test_flood_active_with_multiple_entries);
    RUN_TEST(test_clear_empties_table);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_normal);
    RUN_TEST(test_view_draw_with_flood);
    RUN_TEST(test_view_draw_disassoc);
    RUN_TEST(test_view_draw_protected_reason);
    RUN_TEST(test_view_draw_btm_section);
    RUN_TEST(test_view_draw_btm_with_no_deauths);
    RUN_TEST(test_view_draw_no_btm_section_when_empty);
    RUN_TEST(test_view_draw_btm_table_full);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
    flood_test_set_clock(NULL, NULL);
}
