#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include "runner.h"
#include "sloth.h"
#include "twins.h"
#include "alerts.h"
#include "views/twins.h"
#include "ownership.h"
#include "inventory.h"
#include "wired_attach.h"

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

/* Same OUI and no other signal — no positive impersonation evidence, so
 * no episode. Not because a matching OUI vouches for the pair (#89): add
 * one positive signal and the same pair materialises, see below. */
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

/* #89: a same-OUI clone whose vendor-IE fingerprint contradicts its
 * twin does materialise, so the view and the alert agree about it. */
static void test_twins_same_oui_clone_with_ie_mismatch_produces_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xaa,0xbb,0xcc,0x99,0x99,0x99};  /* copied OUI */
    add_beacon(&s, "Mesh", a, "WPA2", -70);
    add_beacon(&s, "Mesh", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0x1111u;
    s.beacon_aps[1].fp.vendor_ies_hash = 0x2222u;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch, 1);
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

/* #89: RSSI is not ownership and no longer picks the impostor.
 *
 * The old rule called the stronger-signal AP the twin, on the theory
 * that a freshly-placed rogue is closer than the real AP. That is a
 * guess about furniture, not evidence about identity — and it is wrong
 * in the most common case, where the operator's own AP is the closest
 * thing in the room. With no ownership, taint or attacker-tool signal
 * the pair is left UNATTRIBUTED and ordered canonically, so the view
 * shows two candidates instead of naming a culprit it cannot identify.
 *
 * Flipping the signals must not change which BSSID lands in which
 * field: that is what "RSSI no longer decides" means. */
static void test_twins_rssi_does_not_decide_sides(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t lo[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t hi[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    add_beacon(&s, "Cafe-Net", hi, "WPA2", -80);
    add_beacon(&s, "Cafe-Net", lo, "WPA2", -45);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
    /* Canonical order: lower BSSID first. */
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, lo, 6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, hi, 6) == 0);

    /* Invert the RSSIs — identical assignment. */
    alerts_clear();
    sloth_state_t t; seed(&t);
    add_beacon(&t, "Cafe-Net", hi, "WPA2", -45);
    add_beacon(&t, "Cafe-Net", lo, "WPA2", -80);
    twins_snapshot(&t);
    ASSERT_EQ(t.twin_episode_count, 1);
    ASSERT_EQ(t.twin_episodes[0].attributed, 0);
    ASSERT(memcmp(t.twin_episodes[0].real_bssid, lo, 6) == 0);
    ASSERT(memcmp(t.twin_episodes[0].twin_bssid, hi, 6) == 0);
}

/* An unattributed episode carries the same confidence the alert does,
 * so the [x] Twins view can show how sure sloth is without the operator
 * reading it as a verdict. */
static void test_twins_episode_carries_confidence(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].confidence, TWIN_W_DIFF_OUI);
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

/* Attacker OUI flag — and it is now what *attributes* the pair. An OUI
 * in the Hak5 / Espressif tables is an observed device identity, not a
 * signal-strength guess, so it can name the impostor where RSSI cannot.
 * Note the Hak5 BSSID is the numerically LOWER one here: canonical
 * ordering would have put it in real_bssid, and the attribution
 * overrides that. */
static void test_twins_attacker_oui_attributes_the_impostor(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t pin[6]   = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2", -75);
    add_beacon(&s, "Cafe-Net", pin,   "WPA2", -40);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attacker_oui, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed,   1);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, pin,   6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, legit, 6) == 0);
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

/* Taint marker — when the chain rule has tainted a BSSID, that BSSID is
 * the twin and the pair is attributed.
 *
 * The tainted BSSID here is the numerically *lower* one, so canonical
 * pair ordering alone would have put it in `real_bssid`. The assertion
 * therefore proves the attribution is doing the work, not the ordering
 * (#89) — and taint is observed behaviour, not a signal-strength guess. */
static void test_twins_taint_overrides_rssi_assignment(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t rogue[6] = {0x11,0x22,0x33,0x44,0x55,0x66};  /* tainted, lower */
    uint8_t real[6]  = {0xaa,0xbb,0xcc,0x01,0x02,0x03};  /* clean,   higher */
    add_beacon(&s, "Cafe-Net", rogue, "WPA2", -80);
    add_beacon(&s, "Cafe-Net", real,  "WPA2", -45);
    /* Seed a deauth flood targeting `real` so the chain rule taints the
     * other half. The chain reads the (BSSID, victim) aggregate (#88). */
    deauth_victim_t *v = &s.deauth_victims[s.deauth_victim_count++];
    memset(v, 0, sizeof(*v));
    memcpy(v->bssid, real, 6);
    memset(v->victim, 0xff, 6);
    v->flood      = 1;
    v->flood_last = time(NULL);
    alerts_update(&s);
    ASSERT_EQ(evil_twin_bssid_is_tainted(rogue), 1);

    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT(memcmp(s.twin_episodes[0].real_bssid, real,  6) == 0);
    ASSERT(memcmp(s.twin_episodes[0].twin_bssid, rogue, 6) == 0);
    ASSERT_EQ(s.twin_episodes[0].attack_in_progress, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed, 1);
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

/* #51 as amended by #89: a mutual 802.11k claim no longer removes the
 * episode — it lowers its confidence. The view and the alert still
 * agree, because both read twin_evidence_score(); what changed is that
 * neither of them lets an unauthenticated frame erase a candidate. */
static void test_twins_infrastructure_peers_lower_confidence_not_erased(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t router[6]   = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t extender[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", router,   "WPA2", -70);
    add_beacon(&s, "CorpWiFi", extender, "WPA2", -45);
    add_neighbor(&s, router,   extender);
    add_neighbor(&s, extender, router);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].confidence, TWIN_CONF_MIN);
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
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


/* #52: an operator-designated BSSID is never named the impostor.
 * The RSSI heuristic would get this backwards in the common case —
 * the operator's own AP is usually the closest, which rule 2 reads as
 * the rogue. */
static void test_twins_designated_bssid_is_always_real(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t mine[6]  = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    /* Mine is the STRONGER signal — without the designation the
     * lower-RSSI rule would call it the twin. */
    add_beacon(&s, "CorpWiFi", mine,  "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue, "WPA2", -75);
    ownership_add_bssid("aa:bb:cc:01:02:03");
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(memcmp(s.twin_episodes[0].real_bssid, mine,  6), 0);
    ASSERT_EQ(memcmp(s.twin_episodes[0].twin_bssid, rogue, 6), 0);
    ownership_clear();
}

/* ── the approved inventory attributes the pair (#89 slice 2) ──
 *
 * An inventory entry is the same kind of statement as --my-bssid: a
 * human asserting ownership out-of-band. So it settles the same
 * question, and it settles it against the RSSI the old rule used — the
 * declared radio here is the closer one, which the pre-#89 view would
 * have called the rogue. */
static void test_twins_inventory_approved_bssid_is_never_the_impostor(void) {
    static char tmp[] = "/tmp/sloth_twins_inv_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    if (!f) return;
    const char *body =
        "{\"networks\":[{\"ssid\":\"CorpWiFi\","
        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}";
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    ASSERT_EQ(inventory_load(tmp, NULL, 0), 1);

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]    = {0x11,0x22,0x33,0x44,0x55,0x66};
    /* The declared radio is the STRONGER signal — the pre-#89 rule
     * would have named it the twin. */
    add_beacon(&s, "CorpWiFi", declared, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue,    "WPA2", -75);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed, 1);
    ASSERT_EQ(memcmp(s.twin_episodes[0].real_bssid, declared, 6), 0);
    ASSERT_EQ(memcmp(s.twin_episodes[0].twin_bssid, rogue,    6), 0);

    /* Inverting the RSSIs does not move the assignment. */
    sloth_state_t t; seed(&t);
    add_beacon(&t, "CorpWiFi", declared, "WPA2", -75);
    add_beacon(&t, "CorpWiFi", rogue,    "WPA2", -40);
    twins_snapshot(&t);
    ASSERT_EQ(t.twin_episode_count, 1);
    ASSERT_EQ(memcmp(t.twin_episodes[0].real_bssid, declared, 6), 0);

    inventory_clear();
    unlink(tmp);
}

/* Both halves declared: legitimate infrastructure, so there is no
 * candidate pair left to materialise. The [x] Twins view and the alert
 * share one scorer and must agree about that. */
static void test_twins_both_inventory_approved_no_episode(void) {
    static char tmp[] = "/tmp/sloth_twins_inv2_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    if (!f) return;
    const char *body =
        "{\"networks\":[{\"ssid\":\"CorpWiFi\","
        "\"bssids\":[\"aa:bb:cc:01:02:03\",\"11:22:33:44:55:66\"]}]}";
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    ASSERT_EQ(inventory_load(tmp, NULL, 0), 1);

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", a, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", b, "WPA2", -75);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xA11CE;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xB0B;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);

    inventory_clear();
    unlink(tmp);
}

/* Control: same geometry, no designation -> the pair is unattributed.
 * This is what makes the test above meaningful — the designation is the
 * only thing that produced a verdict. */
static void test_twins_without_designation_pair_is_unattributed(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t strong[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t weak[6]   = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", strong, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", weak,   "WPA2", -75);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
}

/* Both designated -> no basis to pick between them; fall through to the
 * existing heuristics rather than pretending to know. */
static void test_twins_both_designated_falls_through(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", a, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", b, "WPA2", -75);
    ownership_add_bssid("aa:bb:cc:01:02:03");
    ownership_add_bssid("11:22:33:44:55:66");
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    /* Same outcome as the no-designation control: unattributed, in
     * canonical order. */
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
    ASSERT_EQ(memcmp(s.twin_episodes[0].real_bssid, b, 6), 0);
    ownership_clear();
}

/* ── #89 slice 3: what kind of AP, and is it on the wire ───
 *
 * Two axes with different evidence requirements. The class is decidable
 * from RF plus the approved inventory; wired attachment is not decidable
 * from RF at all and must stay UNKNOWN until something that can see the
 * wire answers. These tests pin both, and pin that neither one is ever
 * allowed to gate a finding. */

/* Write `body` to a temp inventory and load it. Returns the path so the
 * caller can unlink it. */
static void load_inventory(char *path, const char *body) {
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL);
    if (!f) return;
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    ASSERT_EQ(inventory_load(path, NULL, 0), 1);
}

/* The regression that matters most for an operator on day one: with no
 * inventory configured, slice 3 must not change a single thing they
 * already see. The pair still materialises, the attribution and the
 * confidence are untouched, and the two new axes both read "nothing
 * established" rather than guessing a label from RF. */
static void test_twins_no_inventory_class_is_unknown_and_nothing_lost(void) {
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].confidence, TWIN_W_DIFF_OUI);
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_UNKNOWN);
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_UNKNOWN);
}

/* Over-the-air impersonator: the operator declared this SSID and one
 * half is not one of the BSSIDs they approved for it. The strongest
 * claim available, and the only one an attacker cannot reach — it comes
 * out of a file a human wrote, not out of a frame. */
static void test_twins_inventory_mismatch_classifies_impersonator(void) {
    static char tmp[] = "/tmp/sloth_twins_cls1_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]    = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", declared, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue,    "WPA2", -75);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_IMPERSONATOR);
    /* And still nothing about the wire — an inventory says whose radio
     * it is, never what it is plugged into. */
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_UNKNOWN);

    inventory_clear();
    unlink(tmp);
}

/* Neighbouring AP: an inventory is loaded, so there is a declared
 * estate — and this SSID is not in it. That is the noise half of #89:
 * a mixed-vendor deployment two floors down is not an attack on
 * anything the operator owns. Needs the inventory; see the no-inventory
 * test above for the same geometry staying UNKNOWN. */
static void test_twins_ssid_outside_declared_estate_is_neighbor(void) {
    static char tmp[] = "/tmp/sloth_twins_cls2_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x02,0x22,0x33,0x44,0x55,0x66};
    uint8_t b[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);   /* not declared at all */
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_NEIGHBOR);

    inventory_clear();
    unlink(tmp);
}

/* A hard RF signal carries the impersonator claim without an inventory.
 * Admissible here and nowhere near the wired axis, and the asymmetry is
 * the point: impersonation is an over-the-air behaviour, so RF can
 * evidence it. What a radio is plugged into is not, so RF cannot. */
static void test_twins_attacker_oui_is_impersonator_without_inventory(void) {
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    sloth_state_t s; seed(&s);
    uint8_t legit[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t pin[6]   = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2", -75);
    add_beacon(&s, "Cafe-Net", pin,   "WPA2", -40);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_IMPERSONATOR);
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_UNKNOWN);
}

/* A neighbour claim is one unauthenticated frame and must not move the
 * class, any more than slice 1 let it erase the finding. Same geometry
 * as the mismatch test, plus a spoofed 802.11k advertisement from the
 * rogue naming the AP it is impersonating — the exact erase-the-finding
 * move the issue describes. */
static void test_twins_spoofed_neighbor_does_not_downgrade_class(void) {
    static char tmp[] = "/tmp/sloth_twins_cls3_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]    = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", declared, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue,    "WPA2", -75);
    add_neighbor(&s, rogue, declared);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_IMPERSONATOR);

    inventory_clear();
    unlink(tmp);
}

static wired_attach_t twin_is_on_the_wire(const uint8_t bssid[6], void *ctx) {
    (void)bssid;
    (void)ctx;
    return WIRED_ATTACH_ATTACHED;
}

/* The hook, end to end: register a correlator and the accused half's
 * wired state reaches the episode. This is the seam a future
 * controller/switch/DHCP integration fills, and the only path by which
 * `wired_attach` can ever become non-UNKNOWN. */
static void test_twins_registered_correlator_reaches_the_episode(void) {
    static char tmp[] = "/tmp/sloth_twins_cls4_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6]    = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", declared, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue,    "WPA2", -75);

    /* Before: nobody is looking. */
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_UNKNOWN);

    wired_attach_register(twin_is_on_the_wire, NULL);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_ATTACHED);
    /* The class did not move: what the AP is plugged into is a separate
     * question from whether it is impersonating anything. */
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_IMPERSONATOR);

    wired_attach_clear();
    inventory_clear();
    unlink(tmp);
}

/* An unattributed pair gets no wired verdict even with a correlator
 * that answers ATTACHED for everything. `real_bssid`/`twin_bssid` are
 * only canonical order there, so asking about `twin_bssid` would pin a
 * wired-attachment claim on whichever BSSID sorted higher — the same
 * shape of mistake as letting RSSI name the impostor. */
static void test_twins_unattributed_pair_gets_no_wired_verdict(void) {
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    wired_attach_register(twin_is_on_the_wire, NULL);
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xaa,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].attributed, 0);
    ASSERT_EQ((int)s.twin_episodes[0].wired_attach, (int)WIRED_ATTACH_UNKNOWN);
    wired_attach_clear();
}

/* Classification is a label, never a gate. `neighbor` is the class most
 * tempting to treat as "safe, drop it" — and dropping it would be a new
 * sole suppressor, the bug class this whole issue opened on. The
 * episode survives with its confidence intact. */
static void test_twins_neighbor_class_does_not_suppress_the_episode(void) {
    static char tmp[] = "/tmp/sloth_twins_cls5_XXXXXX";
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(tmp); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"aa:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x02,0x22,0x33,0x44,0x55,0x66};
    uint8_t b[6] = {0x99,0x88,0x77,0x66,0x55,0x44};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xA11CE;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xB0B;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ((int)s.twin_episodes[0].ap_class, (int)TWIN_CLASS_NEIGHBOR);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch, 1);
    ASSERT_EQ((int)s.twin_episodes[0].confidence,
              TWIN_W_DIFF_OUI + TWIN_W_IE_HASH);

    inventory_clear();
    unlink(tmp);
}

/* twin_classify itself, on hand-built evidence rather than through a
 * snapshot — the truth table, including the precedence between
 * inv_approved and a hard signal. */
static void test_twin_classify_truth_table(void) {
    twin_evidence_t ev;

    ASSERT_EQ((int)twin_classify(NULL), (int)TWIN_CLASS_UNKNOWN);

    memset(&ev, 0, sizeof(ev));
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_UNKNOWN);

    memset(&ev, 0, sizeof(ev));
    ev.inv_consulted = 1;
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_NEIGHBOR);

    memset(&ev, 0, sizeof(ev));
    ev.inv_consulted = 1; ev.inv_mismatch = 1; ev.hard = 1;
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_IMPERSONATOR);

    memset(&ev, 0, sizeof(ev));
    ev.hard = 1; ev.attacker_oui = 1;
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_IMPERSONATOR);

    memset(&ev, 0, sizeof(ev));
    ev.inv_consulted = 1; ev.inv_approved = 1;
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_DECLARED);

    /* Precedence: two radios the operator declared are their own
     * infrastructure even when the air looks alarming. A hard signal
     * here is a statement about an approved pair, not an accusation
     * against one — and the weak/strong branch still reports the
     * downgrade lane, it just stops calling it impersonation. */
    memset(&ev, 0, sizeof(ev));
    ev.inv_consulted = 1; ev.inv_approved = 1; ev.hard = 1;
    ev.attacker_oui = 1;
    ASSERT_EQ((int)twin_classify(&ev), (int)TWIN_CLASS_DECLARED);

    /* Labels — these strings are the column and the export value. */
    ASSERT(strcmp(twin_class_label(TWIN_CLASS_UNKNOWN),      "?")        == 0);
    ASSERT(strcmp(twin_class_label(TWIN_CLASS_IMPERSONATOR), "impostor") == 0);
    ASSERT(strcmp(twin_class_label(TWIN_CLASS_NEIGHBOR),     "neighbor") == 0);
    ASSERT(strcmp(twin_class_label(TWIN_CLASS_DECLARED),     "declared") == 0);
    ASSERT(strcmp(twin_class_label((twin_class_t)42),        "?")        == 0);
}

/* Enum numbering is a cross-file contract: twin_episode_t and alert_t
 * store the class as a plain uint8_t because include/sloth.h does not
 * include module headers from src/. */
static void test_twin_class_enum_values_are_pinned(void) {
    ASSERT_EQ((int)TWIN_CLASS_UNKNOWN,      0);
    ASSERT_EQ((int)TWIN_CLASS_IMPERSONATOR, 1);
    ASSERT_EQ((int)TWIN_CLASS_NEIGHBOR,     2);
    ASSERT_EQ((int)TWIN_CLASS_DECLARED,     3);
}

void run_twins_tests(void) {
    TEST_SUITE("twins snapshot");
    RUN_TEST(test_twins_empty_state_no_episodes);
    RUN_TEST(test_twins_same_cipher_diff_oui_produces_episode);
    RUN_TEST(test_twins_same_oui_no_episode);
    RUN_TEST(test_twins_same_oui_clone_with_ie_mismatch_produces_episode);
    RUN_TEST(test_twins_open_no_episode);
    RUN_TEST(test_twins_rssi_does_not_decide_sides);
    RUN_TEST(test_twins_episode_carries_confidence);
    RUN_TEST(test_twins_hash_mismatch_flag);
    RUN_TEST(test_twins_attacker_oui_attributes_the_impostor);
    RUN_TEST(test_twins_rssi_swing_from_twin_side);
    RUN_TEST(test_twins_taint_overrides_rssi_assignment);
    RUN_TEST(test_twins_snapshot_idempotent);
    RUN_TEST(test_twins_infrastructure_peers_lower_confidence_not_erased);
    RUN_TEST(test_twins_unrelated_neighbors_still_episode);
    RUN_TEST(test_twins_designated_bssid_is_always_real);
    RUN_TEST(test_twins_without_designation_pair_is_unattributed);
    RUN_TEST(test_twins_both_designated_falls_through);
    RUN_TEST(test_twins_inventory_approved_bssid_is_never_the_impostor);
    RUN_TEST(test_twins_both_inventory_approved_no_episode);

    TEST_SUITE("twins classification (#89 slice 3)");
    RUN_TEST(test_twin_class_enum_values_are_pinned);
    RUN_TEST(test_twin_classify_truth_table);
    RUN_TEST(test_twins_no_inventory_class_is_unknown_and_nothing_lost);
    RUN_TEST(test_twins_inventory_mismatch_classifies_impersonator);
    RUN_TEST(test_twins_ssid_outside_declared_estate_is_neighbor);
    RUN_TEST(test_twins_attacker_oui_is_impersonator_without_inventory);
    RUN_TEST(test_twins_spoofed_neighbor_does_not_downgrade_class);
    RUN_TEST(test_twins_registered_correlator_reaches_the_episode);
    RUN_TEST(test_twins_unattributed_pair_gets_no_wired_verdict);
    RUN_TEST(test_twins_neighbor_class_does_not_suppress_the_episode);

    TEST_SUITE("twins view");
    RUN_TEST(test_view_twins_empty_does_not_crash);
    RUN_TEST(test_view_twins_populated_does_not_crash);
    RUN_TEST(test_view_twins_key_navigation);
}
