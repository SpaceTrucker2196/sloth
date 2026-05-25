#include <string.h>
#include <stdint.h>
#include "runner.h"
#include "sloth.h"
#include "deauth_snoop.h"
#include "views/deauth.h"

/*
 * 802.11 management frame layout (24-byte header):
 *   [0]    FC byte 0: (subtype<<4)|(type<<2)|proto
 *   [1]    FC byte 1
 *   [2-3]  Duration
 *   [4-9]  DA (destination)
 *   [10-15] SA (source)
 *   [16-21] BSSID
 *   [22-23] Sequence control
 *   [24-25] Reason code (little-endian) — frame body
 *
 * Deauth:  FC0 = (12<<4)|(0<<2)|0 = 0xC0
 * Disassoc: FC0 = (10<<4)|(0<<2)|0 = 0xA0
 */

static const uint8_t SRC_A[6]  = {0xaa,0xbb,0xcc,0x11,0x22,0x33};
static const uint8_t SRC_B[6]  = {0xde,0xad,0xbe,0xef,0x00,0x01};
static const uint8_t DST_STA[6]= {0x11,0x22,0x33,0x44,0x55,0x66};
static const uint8_t BCAST[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
static const uint8_t BSSID_A[6]= {0x00,0x11,0x22,0x33,0x44,0x55};

static void fill_frame(uint8_t *f, uint8_t fc0,
                       const uint8_t da[6], const uint8_t sa[6],
                       const uint8_t bssid[6], uint16_t reason)
{
    f[0] = fc0; f[1] = 0x00;
    f[2] = f[3] = 0x00;
    memcpy(f + 4,  da,    6);
    memcpy(f + 10, sa,    6);
    memcpy(f + 16, bssid, 6);
    f[22] = f[23] = 0x00;
    f[24] = (uint8_t)(reason & 0xff);
    f[25] = (uint8_t)(reason >> 8);
}

/* ── deauth_parse tests ──────────────────────────────────── */

static void test_parse_deauth(void) {
    uint8_t f[26]; fill_frame(f, 0xC0, DST_STA, SRC_A, BSSID_A, 1);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -60, src, dst, bssid, &reason, &sub), 1);
    ASSERT_EQ(sub, 12);
    ASSERT_EQ(reason, 1);
    ASSERT_EQ(memcmp(src,   SRC_A,   6), 0);
    ASSERT_EQ(memcmp(dst,   DST_STA, 6), 0);
    ASSERT_EQ(memcmp(bssid, BSSID_A, 6), 0);
}

static void test_parse_disassoc(void) {
    uint8_t f[26]; fill_frame(f, 0xA0, DST_STA, SRC_A, BSSID_A, 4);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -55, src, dst, bssid, &reason, &sub), 1);
    ASSERT_EQ(sub, 10);
    ASSERT_EQ(reason, 4);
}

static void test_parse_broadcast_dst(void) {
    uint8_t f[26]; fill_frame(f, 0xC0, BCAST, SRC_A, BSSID_A, 1);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -70, src, dst, bssid, &reason, &sub), 1);
    ASSERT_EQ(memcmp(dst, BCAST, 6), 0);
}

static void test_parse_rejects_probe_request(void) {
    uint8_t f[26]; fill_frame(f, 0x40, DST_STA, SRC_A, BSSID_A, 1);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -60, src, dst, bssid, &reason, &sub), 0);
}

static void test_parse_rejects_data_frame(void) {
    uint8_t f[26]; fill_frame(f, 0x08, DST_STA, SRC_A, BSSID_A, 1); /* data */
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -60, src, dst, bssid, &reason, &sub), 0);
}

static void test_parse_rejects_too_short(void) {
    uint8_t f[20]; memset(f, 0, sizeof(f)); f[0] = 0xC0;
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 20, -60, src, dst, bssid, &reason, &sub), 0);
}

static void test_parse_no_reason_code(void) {
    /* frame exactly 24 bytes — no reason code present, should still succeed */
    uint8_t f[26]; fill_frame(f, 0xC0, DST_STA, SRC_A, BSSID_A, 0);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 24, -60, src, dst, bssid, &reason, &sub), 1);
    ASSERT_EQ(reason, 0);  /* defaults to 0 when body absent */
}

static void test_parse_reason_code_15(void) {
    uint8_t f[26]; fill_frame(f, 0xC0, DST_STA, SRC_A, BSSID_A, 15);
    uint8_t src[6], dst[6], bssid[6]; uint16_t reason; uint8_t sub;
    ASSERT_EQ(deauth_parse(f, 26, -50, src, dst, bssid, &reason, &sub), 1);
    ASSERT_EQ(reason, 15);
}

/* ── deauth_record / deauth_snapshot tests ───────────────── */

static void test_record_new_entry(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(memcmp(s.deauth_events[0].src,   SRC_A,   6), 0);
    ASSERT_EQ(memcmp(s.deauth_events[0].dst,   DST_STA, 6), 0);
    ASSERT_EQ(memcmp(s.deauth_events[0].bssid, BSSID_A, 6), 0);
    ASSERT_EQ(s.deauth_events[0].reason,  1);
    ASSERT_EQ(s.deauth_events[0].subtype, 12);
    ASSERT_EQ(s.deauth_events[0].count,   1);
    ASSERT_EQ(s.deauth_events[0].flood,   0);
}

static void test_record_update_existing(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_events[0].count, 2);
}

static void test_record_distinct_pairs(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);
    deauth_record(SRC_B, BCAST,   BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_count, 2);
}

static void test_flood_detection(void) {
    deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH; i++)
        deauth_record(SRC_A, BCAST, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_count, 1);
    ASSERT_EQ(s.deauth_events[0].flood, 1);
    ASSERT_EQ(s.deauth_flood_active, 1);
}

static void test_no_flood_below_threshold(void) {
    deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH - 1; i++)
        deauth_record(SRC_A, BCAST, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_events[0].flood, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
}

static void test_flood_active_with_multiple_entries(void) {
    deauth_clear();
    deauth_record(SRC_B, DST_STA, BSSID_A, 1, 12);  /* benign */
    for (int i = 0; i < DEAUTH_FLOOD_THRESH; i++)
        deauth_record(SRC_A, BCAST, BSSID_A, 1, 12); /* flood */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_flood_active, 1);
}

static void test_clear_empties_table(void) {
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);
    deauth_clear();

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_count, 0);
    ASSERT_EQ(s.deauth_flood_active, 0);
}

static void test_snapshot_clamps_sel(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    s.deauth_sel = 99;
    deauth_snapshot(&s);

    ASSERT_EQ(s.deauth_sel, 0);
}

/* ── view_deauth_draw smoke tests ────────────────────────── */

static void test_view_draw_empty(void) {
    sloth_state_t s; memset(&s, 0, sizeof(s));
    view_deauth_draw(&s);
    ASSERT(1);
}

static void test_view_draw_normal(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1,  12);
    deauth_record(SRC_B, BCAST,   BSSID_A, 15, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT(1);
}

static void test_view_draw_with_flood(void) {
    deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH + 2; i++)
        deauth_record(SRC_A, BCAST, BSSID_A, 1, 12);

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT(s.deauth_flood_active);
}

static void test_view_draw_disassoc(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 4, 10);  /* disassoc reason 4 */

    sloth_state_t s; memset(&s, 0, sizeof(s));
    deauth_snapshot(&s);
    view_deauth_draw(&s);
    ASSERT_EQ(s.deauth_events[0].subtype, 10);
}

/* ── view_deauth_key tests ───────────────────────────────── */

static void test_view_key_nav(void) {
    deauth_clear();
    deauth_record(SRC_A, DST_STA, BSSID_A, 1, 12);
    deauth_record(SRC_B, BCAST,   BSSID_A, 1, 12);

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
    deauth_clear();
    for (int i = 0; i < DEAUTH_FLOOD_THRESH; i++)
        deauth_record(SRC_A, BCAST, BSSID_A, 1, 12);

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
    RUN_TEST(test_parse_no_reason_code);
    RUN_TEST(test_parse_reason_code_15);
    RUN_TEST(test_record_new_entry);
    RUN_TEST(test_record_update_existing);
    RUN_TEST(test_record_distinct_pairs);
    RUN_TEST(test_flood_detection);
    RUN_TEST(test_no_flood_below_threshold);
    RUN_TEST(test_flood_active_with_multiple_entries);
    RUN_TEST(test_clear_empties_table);
    RUN_TEST(test_snapshot_clamps_sel);
    RUN_TEST(test_view_draw_empty);
    RUN_TEST(test_view_draw_normal);
    RUN_TEST(test_view_draw_with_flood);
    RUN_TEST(test_view_draw_disassoc);
    RUN_TEST(test_view_key_nav);
    RUN_TEST(test_view_key_clear);
}
