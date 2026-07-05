#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "karma_detect.h"
#include "views/karma.h"

/* State-driven only: karma_update reads the beacon table, client PNLs,
 * and the deauth ring, and writes s->karma_aps[]. */

static void seed(sloth_state_t *s) { memset(s, 0, sizeof(*s)); }

/* A BSSID beaconing `n` distinct SSIDs (via ssid_history). */
static void add_multi_ssid_ap(sloth_state_t *s, const uint8_t bssid[6],
                              const char *const *ssids, int n) {
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    memcpy(b->bssid, bssid, 6);
    int cap = n < MAX_AP_SSID_HISTORY ? n : MAX_AP_SSID_HISTORY;
    for (int i = 0; i < cap; i++)
        snprintf(b->ssid_history[i], 33, "%s", ssids[i]);
    b->ssid_history_n = cap;
    if (cap > 0) snprintf(b->ssid, sizeof(b->ssid), "%s", ssids[cap - 1]);
    b->last_seen = time(NULL);
}

static void add_pnl_client(sloth_state_t *s, const uint8_t mac[6],
                           const char *const *ssids, int n) {
    pnl_client_t *c = &s->pnl_clients[s->pnl_count++];
    memset(c, 0, sizeof(*c));
    memcpy(c->mac, mac, 6);
    int cap = n < MAX_PNL_SSIDS_PER_CLI ? n : MAX_PNL_SSIDS_PER_CLI;
    for (int i = 0; i < cap; i++)
        snprintf(c->ssids[i], 33, "%s", ssids[i]);
    c->ssid_count = cap;
}

/* An empty state produces an empty karma table — and the view renders it
 * without crashing. */
static void test_empty_state(void) {
    sloth_state_t s; seed(&s);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 0);
    view_karma_draw(&s);   /* must not crash on empty */
}

/* A BSSID beaconing >= threshold distinct SSIDs becomes a candidate;
 * one below threshold does not. */
static void test_threshold(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t benign[6] = {0x66,0x77,0x88,0x99,0xaa,0xbb};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    const char *few[]  = { "office", "office-guest" };
    add_multi_ssid_ap(&s, lure, many, 3);
    add_multi_ssid_ap(&s, benign, few, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_aps[0].ssid_count, 3);
    ASSERT_EQ(memcmp(s.karma_aps[0].bssid, lure, 6), 0);
}

/* PNL overlap is counted, and it raises the score. */
static void test_pnl_overlap_and_score(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "homewifi", "ACME-Corp" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_aps[0].pnl_overlap, 2);
    ASSERT_EQ(s.karma_aps[0].score, 1 + 2);   /* base + overlap */
}

/* Jaccard(advertised, PNL-union) in ppm. AP advertises {a,b,c} (|A|=3),
 * the PNL union is {a,b} (|B|=2), intersection {a,b} (2). Union = 3, so
 * Jaccard = 2/3 = 666666 ppm. A full-overlap lure trends toward 1e6. */
static void test_jaccard_ppm(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].pnl_jaccard_ppm, 666666);
}

static void test_jaccard_full_overlap(void) {
    /* AP advertises exactly the PNL union → Jaccard = 1.0 (1e6). */
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b", "c" };
    add_pnl_client(&s, cli, pnl, 3);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].pnl_jaccard_ppm, 1000000);
}

/* IE-uniformity: all SSIDs from one BSSID carry an identical IE
 * fingerprint (the PineAP tell) -> ie_uniform set, +1 to score. */
static void test_ie_uniform(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, lure, adv, 3);
    /* Same non-zero fingerprint across every SSID. */
    for (int i = 0; i < 3; i++) s.beacon_aps[0].ssid_history_fp[i] = 0xABCD1234u;
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 1);
    ASSERT_EQ(s.karma_aps[0].score, 1 + 1);   /* base + ie_uniform */
}

static void test_ie_varied_not_uniform(void) {
    /* A legit multi-VAP AP varies its per-VAP IE tuple -> not uniform. */
    sloth_state_t s; seed(&s);
    uint8_t ap[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, ap, adv, 3);
    s.beacon_aps[0].ssid_history_fp[0] = 0x11111111u;
    s.beacon_aps[0].ssid_history_fp[1] = 0x22222222u;
    s.beacon_aps[0].ssid_history_fp[2] = 0x33333333u;
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 0);
}

static void test_ie_unknown_fp_not_uniform(void) {
    /* All-zero (unknown) fingerprints must not read as "uniform". */
    sloth_state_t s; seed(&s);
    uint8_t ap[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *adv[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, ap, adv, 3);   /* fp left 0 */
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].ie_uniform, 0);
}

/* A concurrent deauth flood sets the chain flag and adds to the score. */
static void test_deauth_chain(void) {
    sloth_state_t s; seed(&s);
    uint8_t lure[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    const char *many[] = { "homewifi", "Starbucks", "ACME-Corp" };
    add_multi_ssid_ap(&s, lure, many, 3);
    deauth_event_t *e = &s.deauth_events[s.deauth_count++];
    memset(e, 0, sizeof(*e));
    e->flood = 1;
    e->last_seen = time(NULL);
    karma_update(&s);
    ASSERT_EQ(s.karma_aps[0].deauth_chain, 1);
    ASSERT_EQ(s.karma_aps[0].score, 1 + 3);   /* base + deauth chain */
}

/* Candidates are ranked strongest-first. */
static void test_ranking(void) {
    sloth_state_t s; seed(&s);
    uint8_t weak[6]   = {0x00,0x11,0x22,0x33,0x44,0x01};
    uint8_t strong[6] = {0x00,0x11,0x22,0x33,0x44,0x02};
    const char *weak_ssids[]   = { "x", "y", "z" };   /* not in any PNL */
    const char *strong_ssids[] = { "a", "b", "c" };   /* a,b probed for */
    add_multi_ssid_ap(&s, weak, weak_ssids, 3);
    add_multi_ssid_ap(&s, strong, strong_ssids, 3);
    uint8_t cli[6] = {0x02,0xaa,0xbb,0xcc,0xdd,0xee};
    const char *pnl[] = { "a", "b" };
    add_pnl_client(&s, cli, pnl, 2);
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 2);
    /* strong (overlap>0) must sort ahead of weak (overlap==0). */
    ASSERT(s.karma_aps[0].score >= s.karma_aps[1].score);
    ASSERT_EQ(memcmp(s.karma_aps[0].bssid, strong, 6), 0);
}

/* Selection stays in bounds when the table shrinks between polls. */
static void test_sel_clamps(void) {
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x00,0x11,0x22,0x33,0x44,0x01};
    uint8_t b[6] = {0x00,0x11,0x22,0x33,0x44,0x02};
    const char *many[] = { "a", "b", "c" };
    add_multi_ssid_ap(&s, a, many, 3);
    add_multi_ssid_ap(&s, b, many, 3);
    karma_update(&s);
    s.karma_sel = 1;
    view_karma_key(&s, SLOTH_KEY_DOWN);   /* already at last */
    ASSERT_EQ(s.karma_sel, 1);
    /* Next poll only one candidate — sel must clamp. */
    s.beacon_count = 1;
    karma_update(&s);
    ASSERT_EQ(s.karma_count, 1);
    ASSERT_EQ(s.karma_sel, 0);
    view_karma_draw(&s);
}

void run_karma_tests(void) {
    TEST_SUITE("KARMA/PineAP view (#30)");
    RUN_TEST(test_empty_state);
    RUN_TEST(test_threshold);
    RUN_TEST(test_pnl_overlap_and_score);
    RUN_TEST(test_jaccard_ppm);
    RUN_TEST(test_jaccard_full_overlap);
    RUN_TEST(test_ie_uniform);
    RUN_TEST(test_ie_varied_not_uniform);
    RUN_TEST(test_ie_unknown_fp_not_uniform);
    RUN_TEST(test_deauth_chain);
    RUN_TEST(test_ranking);
    RUN_TEST(test_sel_clamps);
}
