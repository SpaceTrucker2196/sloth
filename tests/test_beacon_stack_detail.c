#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "sloth_clock.h"
#include "tui.h"
#include "views/beacon.h"

/* [b] detail screen: the STACK MEASUREMENTS block (#77) — ie_order_hash
 * and TBTT jitter, with the zero-reading rules docs/wiki/jsonl-schema.md
 * already states for the same fields. A bare 0 is ambiguous for both
 * (hash: "not decoded"; jitter: "too few samples" vs a real 0 µs), so
 * the screen must never print one without saying which it is.
 *
 * State is seeded by hand on a snapshot: the block reads beacon_ap_t
 * and nothing else, and the parse/accumulate path that fills those
 * fields has its own frame-level tests in test_beacon_snoop.c. */

static time_t fixed_wall(void) { return (time_t)1700000000; }

static void seed(sloth_state_t *s) {
    memset(s, 0, sizeof(*s));
    s->beacon_count = 1;
    beacon_ap_t *ap = &s->beacon_aps[0];
    static const uint8_t b[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
    memcpy(ap->bssid, b, 6);
    snprintf(ap->ssid, sizeof(ap->ssid), "stack-test");
    ap->last_seen    = fixed_wall();
    s->beacon_detail = 1;
    s->beacon_sel    = 0;
}

static void draw(const sloth_state_t *s, char *out, int sz) {
    sloth_clock_test_set(NULL, fixed_wall);
    tui_test_erase();
    view_beacon_draw(s);
    tui_test_screen(out, (size_t)sz);
    sloth_clock_test_set(NULL, NULL);
}

/* Static: sloth_state_t is large, and every case needs one. */
static sloth_state_t g_s;
static char g_out[16384];

static void test_stack_block_hash_decoded(void) {
    seed(&g_s);
    g_s.beacon_aps[0].fp.ie_order_hash  = 0x1a2b3c4du;
    g_s.beacon_aps[0].fp.ie_order_count = 14;
    draw(&g_s, g_out, sizeof(g_out));
    ASSERT(strstr(g_out, "STACK MEASUREMENTS") != NULL);
    ASSERT(strstr(g_out, "IE order:    0x1a2b3c4d") != NULL);
    ASSERT(strstr(g_out, "14 elements") != NULL);
    /* The decimal form is what a JSONL consumer greps for. */
    ASSERT(strstr(g_out, "ie_order_hash 439041101") != NULL);
    ASSERT(strstr(g_out, "not decoded") == NULL);
}

static void test_stack_block_hash_zero_is_not_decoded(void) {
    seed(&g_s);
    draw(&g_s, g_out, sizeof(g_out));
    ASSERT(strstr(g_out, "IE order:    not decoded") != NULL);
    /* 0 is "not decoded", never a hash value. */
    ASSERT(strstr(g_out, "0x00000000") == NULL);
    ASSERT(strstr(g_out, "ie_order_hash 0") == NULL);
}

static void test_stack_block_jitter_below_minimum_is_not_measured(void) {
    /* 0 and 1 samples: beacon_tbtt_jitter() returns 0 and a 0 stddev.
     * Printing that as "0 us" would claim a perfectly scheduled AP. */
    for (uint32_t n = 0; n < TBTT_JITTER_MIN_SAMPLES; n++) {
        seed(&g_s);
        g_s.beacon_aps[0].tbtt.samples  = n;
        g_s.beacon_aps[0].tbtt.sumsq_us = n ? 250000u : 0u;
        draw(&g_s, g_out, sizeof(g_out));
        char want[64];
        snprintf(want, sizeof(want), "not measured (%u/%d samples",
                 (unsigned)n, TBTT_JITTER_MIN_SAMPLES);
        ASSERT(strstr(g_out, want) != NULL);
        ASSERT(strstr(g_out, " us stddev") == NULL);
    }
}

static void test_stack_block_jitter_real_zero_is_a_reading(void) {
    /* Four residuals, all 0: a real 0 µs, and it must read as one. */
    seed(&g_s);
    g_s.beacon_aps[0].tbtt.samples = 4;
    draw(&g_s, g_out, sizeof(g_out));
    ASSERT(strstr(g_out, "TBTT jitter: 0 us stddev over 4 samples") != NULL);
    ASSERT(strstr(g_out, "not measured") == NULL);
}

static void test_stack_block_jitter_value_and_resets(void) {
    /* Residuals +300 and -300: mean 0, population stddev 300 µs. */
    seed(&g_s);
    g_s.beacon_aps[0].tbtt.samples  = 2;
    g_s.beacon_aps[0].tbtt.sum_us   = 0;
    g_s.beacon_aps[0].tbtt.sumsq_us = 2u * 300u * 300u;
    g_s.beacon_aps[0].tbtt.resets   = 3;
    draw(&g_s, g_out, sizeof(g_out));
    ASSERT(strstr(g_out, "300 us stddev over 2 samples") != NULL);
    ASSERT(strstr(g_out, "3 TSF resets") != NULL);
    ASSERT(strstr(g_out, "no threshold") != NULL);

    /* No resets: the reset clause is absent rather than "0 TSF resets". */
    g_s.beacon_aps[0].tbtt.resets = 0;
    draw(&g_s, g_out, sizeof(g_out));
    ASSERT(strstr(g_out, "TSF reset") == NULL);
}

void run_beacon_stack_detail_tests(void) {
    TEST_SUITE("[b] detail stack measurements (#77)");
    RUN_TEST(test_stack_block_hash_decoded);
    RUN_TEST(test_stack_block_hash_zero_is_not_decoded);
    RUN_TEST(test_stack_block_jitter_below_minimum_is_not_measured);
    RUN_TEST(test_stack_block_jitter_real_zero_is_a_reading);
    RUN_TEST(test_stack_block_jitter_value_and_resets);
}
