#include <stdio.h>
#include <string.h>
#include <time.h>
#include "runner.h"
#include "sloth.h"
#include "twins.h"
#include "alerts.h"
#include "views/twins.h"

/* Tests are state-driven only — twins_snapshot reads beacon_ap_t and
 * the taint tracker. add_beacon mirrors the helper from test_alerts.c. */

static void seed(sloth_state_t *s) { memset(s, 0, sizeof(*s)); }

static void add_beacon(sloth_state_t *s, const char *ssid,
                        const uint8_t bssid[6], const char *enc,
                        int8_t signal_dbm) {
    if (s->beacon_count >= MAX_BEACON_APS) return;
    beacon_ap_t *b = &s->beacon_aps[s->beacon_count++];
    memset(b, 0, sizeof(*b));
    snprintf(b->ssid, sizeof(b->ssid), "%s", ssid);
    memcpy(b->bssid, bssid, 6);
    snprintf(b->enc, sizeof(b->enc), "%s", enc);
    b->channel    = 6;
    b->signal_dbm = signal_dbm;
    b->last_seen  = time(NULL);
    b->fp.oui[0]  = bssid[0];
    b->fp.oui[1]  = bssid[1];
    b->fp.oui[2]  = bssid[2];
}

/* Make `ap_bssid` advertise `neighbor_bssid` as an 802.11k neighbor. */
static void add_neighbor(sloth_state_t *s, const uint8_t ap_bssid[6],
                         const uint8_t neighbor_bssid[6]) {
    for (int i = 0; i < s->beacon_count; i++) {
        beacon_ap_t *ap = &s->beacon_aps[i];
        if (memcmp(ap->bssid, ap_bssid, 6) != 0) continue;
        if (ap->neighbor_count >= MAX_AP_NEIGHBORS) return;
        ap_neighbor_t *n = &ap->neighbors[ap->neighbor_count++];
        memcpy(n->bssid, neighbor_bssid, 6);
        n->channel  = ap->channel;
        n->phy_type = 0;
        return;
    }
}

/* ── snapshot: episode materialisation ───────────────────── */

static void test_twins_empty_state_no_episodes(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);
}

static void test_twins_same_cipher_diff_oui_produces_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT(strcmp(s.twin_episodes[0].ssid, "Cafe-Net") == 0);
    ASSERT(strcmp(s.twin_episodes[0].enc,  "WPA2")     == 0);
}

static void test_twins_same_oui_no_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x02};  /* same OUI */
    add_beacon(&s, "Mesh", a, "WPA2", -70);
    add_beacon(&s, "Mesh", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);
}

static void test_twins_open_no_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0x11,0x22,0x33,0x00,0x00,0x02};
    add_beacon(&s, "Airport", a, "OPEN", -70);
    add_beacon(&s, "Airport", b, "OPEN", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);
}

/* Lower-RSSI = "real" (background AP), higher-RSSI = "twin" (closer
 * suspected rogue). This is the default assignment when no taint
 * override exists. */
static void test_twins_lower_rssi_is_real(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t weaker[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};  /* -80 */
    uint8_t closer[6] = {0x11,0x22,0x33,0x44,0x55,0x66};  /* -45 */
    add_beacon(&s, "Cafe-Net", weaker, "WPA2", -80);
    add_beacon(&s, "Cafe-Net", closer, "WPA2", -45);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, weaker, 6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, closer, 6) == 0);
}

/* Hash mismatch flag — both sides have non-zero hashes that differ. */
static void test_twins_hash_mismatch_flag(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xcafef00du;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch, 1);
}

/* Attacker OUI flag — when the twin side's OUI is Hak5 / Espressif. */
static void test_twins_attacker_oui_flag(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t pin[6]   = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2", -75);
    add_beacon(&s, "Cafe-Net", pin,   "WPA2", -40);      /* closer = twin */
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attacker_oui, 1);
    /* Twin is the Hak5-OUI AP. */
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, pin, 6) == 0);
}

/* RSSI swing is taken from the twin side's 60s window. */
static void test_twins_rssi_swing_from_twin_side(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", legit, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", rogue, "WPA2", -45);
    s.beacon_aps[1].rssi_min_60s = -80;
    s.beacon_aps[1].rssi_max_60s = -50;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].rssi_swing_dbm, 30);
}

/* Taint marker — when the chain rule has tainted a BSSID, the
 * other half becomes the "real" side regardless of RSSI. */
static void test_twins_taint_overrides_rssi_assignment(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};  /* tainted, weaker */
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};  /* clean,    closer */
    /* Without taint, the closer BSSID b would be the twin. With a
     * tainted, the closer one b is "real" and a (the tainted) is twin. */
    add_beacon(&s, "Cafe-Net", a, "WPA2", -80);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -45);
    /* Seed a deauth flood targeting `b` so the chain rule taints `a`. */
    deauth_event_t *e = &s.deauth_events[s.deauth_count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, b, 6);
    e->flood     = 1;
    e->last_seen = time(NULL);
    alerts_update(&s);
    ASSERT_EQ(evil_twin_bssid_is_tainted(a), 1);

    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, b, 6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, a, 6) == 0);
    ASSERT_EQ(s.twin_episodes[0].attack_in_progress, 1);
}

/* Snapshot is idempotent — calling twice produces the same count
 * (not duplicated). */
static void test_twins_snapshot_idempotent(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
}

/* ── view rendering ──────────────────────────────────────── */

static void test_view_twins_empty_does_not_crash(void) {
    sloth_state_t s; seed(&s);
    view_twins_draw(&s);
    ASSERT(1);
}

static void test_view_twins_populated_does_not_crash(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    view_twins_draw(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
}

/* j/k navigation walks the selection within bounds. */
static void test_view_twins_key_navigation(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a1[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b1[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t a2[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x04};
    uint8_t b2[6] = {0x11,0x22,0x33,0x44,0x55,0x67};
    add_beacon(&s, "Net-A", a1, "WPA2", -70);
    add_beacon(&s, "Net-A", b1, "WPA2", -50);
    add_beacon(&s, "Net-B", a2, "WPA2", -70);
    add_beacon(&s, "Net-B", b2, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT(s.twin_episode_count >= 2);

    s.twin_episode_sel = 0;
    view_twins_key(&s, SLOTH_KEY_DOWN);
    ASSERT_EQ(s.twin_episode_sel, 1);
    view_twins_key(&s, SLOTH_KEY_DOWN);
    /* Cap at count-1 — never overruns. */
    ASSERT(s.twin_episode_sel < s.twin_episode_count);
    view_twins_key(&s, SLOTH_KEY_UP);
    /* Up moves toward 0 from wherever we landed. */
    s.twin_episode_sel = 1;
    view_twins_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.twin_episode_sel, 0);
    view_twins_key(&s, SLOTH_KEY_UP);
    ASSERT_EQ(s.twin_episode_sel, 0);  /* clamp at 0 */
}

/* #51: cross-vendor infrastructure produces no episode, so the view and
 * the alert agree. Without this the [x] Twins view would keep listing a
 * range extender the alert engine has already exonerated. */
static void test_twins_infrastructure_peers_no_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t router[6]   = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t extender[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", router,   "WPA2", -70);
    add_beacon(&s, "CorpWiFi", extender, "WPA2", -45);
    add_neighbor(&s, router,   extender);
    add_neighbor(&s, extender, router);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);
}

/* ...and an unrelated cross-vendor pair still produces one. */
static void test_twins_unrelated_neighbors_still_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t real[6]      = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]     = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t elsewhere[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_beacon(&s, "CorpWiFi", real,  "WPA2", -70);
    add_beacon(&s, "CorpWiFi", rogue, "WPA2", -45);
    add_neighbor(&s, real, elsewhere);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
}

void run_twins_tests(void) {
    TEST_SUITE("twins snapshot");
    RUN_TEST(test_twins_empty_state_no_episodes);
    RUN_TEST(test_twins_same_cipher_diff_oui_produces_episode);
    RUN_TEST(test_twins_same_oui_no_episode);
    RUN_TEST(test_twins_open_no_episode);
    RUN_TEST(test_twins_lower_rssi_is_real);
    RUN_TEST(test_twins_hash_mismatch_flag);
    RUN_TEST(test_twins_attacker_oui_flag);
    RUN_TEST(test_twins_rssi_swing_from_twin_side);
    RUN_TEST(test_twins_taint_overrides_rssi_assignment);
    RUN_TEST(test_twins_snapshot_idempotent);
    RUN_TEST(test_twins_infrastructure_peers_no_episode);
    RUN_TEST(test_twins_unrelated_neighbors_still_episode);

    TEST_SUITE("twins view");
    RUN_TEST(test_view_twins_empty_does_not_crash);
    RUN_TEST(test_view_twins_populated_does_not_crash);
    RUN_TEST(test_view_twins_key_navigation);
}
