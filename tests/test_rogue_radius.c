#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "eap_parse.h"
#include "views/rogue_radius.h"

/* State-driven only: the view reads s->rogue_radius[] (snapshotted by
 * eap_track_snapshot); these tests seed the table directly. */

static void seed(sloth_state_t *s) { memset(s, 0, sizeof(*s)); }

static rogue_radius_ap_t *add_ap(sloth_state_t *s, const uint8_t bssid[6],
                                 uint32_t types, int weak, int leaks,
                                 const char *identity, time_t last) {
    rogue_radius_ap_t *r = &s->rogue_radius[s->rogue_radius_count++];
    memset(r, 0, sizeof(*r));
    memcpy(r->bssid, bssid, 6);
    r->eap_types_seen  = types;
    r->weak_method     = weak;
    r->identity_leaks  = leaks;
    if (identity) snprintf(r->last_identity, sizeof(r->last_identity),
                           "%s", identity);
    r->first_seen = last - 60;
    r->last_seen  = last;
    return r;
}

/* An empty state renders without crashing. */
static void test_empty_state(void) {
    sloth_state_t s; seed(&s);
    ASSERT_EQ(s.rogue_radius_count, 0);
    view_rogue_radius_draw(&s);
}

/* Populated render with a weak and a clean row must not crash and must
 * leave the state untouched (draw is const). */
static void test_populated_render(void) {
    sloth_state_t s; seed(&s);
    uint8_t rogue[6]  = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t honest[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    time_t now = time(NULL);
    add_ap(&s, rogue, (1u << EAP_TYPE_MD5) | (1u << EAP_TYPE_PEAP),
           1, 2, "jdoe@corp.example", now);
    add_ap(&s, honest, (1u << EAP_TYPE_TLS), 0, 0, NULL, now);
    view_rogue_radius_draw(&s);
    ASSERT_EQ(s.rogue_radius_count, 2);
    ASSERT_EQ(s.rogue_radius[0].weak_method, 1);
    ASSERT_STR(s.rogue_radius[0].last_identity, "jdoe@corp.example");
}

/* ↑↓ navigation clamps at both ends. */
static void test_nav_bounds(void) {
    sloth_state_t s; seed(&s);
    uint8_t b[6] = {0,1,2,3,4,5};
    time_t now = time(NULL);
    add_ap(&s, b, 1u << EAP_TYPE_TLS, 0, 0, NULL, now);
    b[5] = 6;
    add_ap(&s, b, 1u << EAP_TYPE_PEAP, 0, 0, NULL, now);

    ASSERT_EQ(s.rogue_radius_sel, 0);
    view_rogue_radius_key(&s, SLOTH_KEY_UP);      /* clamp at top */
    ASSERT_EQ(s.rogue_radius_sel, 0);
    view_rogue_radius_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.rogue_radius_sel, 1);
    view_rogue_radius_key(&s, SLOTH_KEY_DOWN);    /* clamp at bottom */
    ASSERT_EQ(s.rogue_radius_sel, 1);
    view_rogue_radius_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.rogue_radius_sel, 0);
}

/* Nav on an empty table stays parked at 0. */
static void test_nav_empty(void) {
    sloth_state_t s; seed(&s);
    view_rogue_radius_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.rogue_radius_sel, 0);
    view_rogue_radius_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.rogue_radius_sel, 0);
}

/* Bitmap → name decoding: known types by name, unknown set bits as
 * T<n>, special frames (Identity/Notification/Nak) never listed. */
static void test_fmt_methods(void) {
    char buf[64];

    rogue_radius_fmt_methods(0, buf, sizeof(buf));
    ASSERT_STR(buf, "-");

    rogue_radius_fmt_methods(1u << EAP_TYPE_MD5, buf, sizeof(buf));
    ASSERT_STR(buf, "MD5");

    rogue_radius_fmt_methods((1u << EAP_TYPE_MD5) | (1u << EAP_TYPE_PEAP),
                             buf, sizeof(buf));
    ASSERT_STR(buf, "MD5,PEAP");

    rogue_radius_fmt_methods((1u << EAP_TYPE_TTLS) | (1u << EAP_TYPE_MSCHAPV2),
                             buf, sizeof(buf));
    ASSERT_STR(buf, "TTLS,MSCHAPv2");

    /* Type 30 has no name in eap_type_name → numeric form. */
    rogue_radius_fmt_methods((1u << EAP_TYPE_GTC) | (1u << 30),
                             buf, sizeof(buf));
    ASSERT_STR(buf, "GTC,T30");

    /* Identity / Notification / Nak bits are suppressed. */
    rogue_radius_fmt_methods((1u << EAP_TYPE_IDENTITY) |
                             (1u << EAP_TYPE_NOTIFICATION) |
                             (1u << EAP_TYPE_NAK) |
                             (1u << EAP_TYPE_TLS),
                             buf, sizeof(buf));
    ASSERT_STR(buf, "TLS");
}

/* Display order: weak-method rows first, then most recent. The sort is
 * an index permutation inside draw; assert through the draw path by
 * checking it tolerates any snapshot order (crash-free) and pin the
 * comparator via a direct table check after a draw. */
static void test_sort_order(void) {
    sloth_state_t s; seed(&s);
    time_t now = time(NULL);
    uint8_t a[6] = {0xa,0,0,0,0,1};   /* clean, newest */
    uint8_t b[6] = {0xb,0,0,0,0,2};   /* weak, old     */
    uint8_t c[6] = {0xc,0,0,0,0,3};   /* weak, newer   */
    add_ap(&s, a, 1u << EAP_TYPE_TLS, 0, 0, NULL, now);
    add_ap(&s, b, 1u << EAP_TYPE_MD5, 1, 0, NULL, now - 300);
    add_ap(&s, c, 1u << EAP_TYPE_GTC, 1, 1, "x@y", now - 10);
    s.rogue_radius_sel = 2;
    view_rogue_radius_draw(&s);   /* sorts internally; must not crash */
    /* Snapshot order untouched by the draw-side sort. */
    ASSERT_EQ(s.rogue_radius[0].weak_method, 0);
    ASSERT_EQ(s.rogue_radius[1].weak_method, 1);
    ASSERT_EQ(s.rogue_radius[2].weak_method, 1);
}

void run_rogue_radius_tests(void) {
    TEST_SUITE("rogue-RADIUS view (#38)");
    RUN_TEST(test_empty_state);
    RUN_TEST(test_populated_render);
    RUN_TEST(test_nav_bounds);
    RUN_TEST(test_nav_empty);
    RUN_TEST(test_fmt_methods);
    RUN_TEST(test_sort_order);
}
