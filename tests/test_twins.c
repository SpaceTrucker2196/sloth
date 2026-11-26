#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include "runner.h"
#include "tui.h"
#include "sloth.h"
#include "twins.h"
#include "alerts.h"
#include "views/twins.h"
#include "ownership.h"
#include "inventory.h"
#include "wired_attach.h"
#include "tmp_dir.h"

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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xa8,0xbb,0xcc,0x00,0x00,0x02};  /* same OUI */
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x00,0x00,0x01};
    uint8_t b[6] = {0xa8,0xbb,0xcc,0x99,0x99,0x99};  /* copied OUI */
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x00,0x00,0x01};
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
    uint8_t hi[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xcafef00du;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch, 1);
}

/* #228 step 5: the evidence snapshot array is a parallel of the episode
 * array, same count, same index, carrying the full vector the episode's
 * confidence was built from. Seen red with the write in twins_snapshot()
 * removed (count stayed 0, confidence and hashes_differ both 0). */
static void test_twins_evidence_snapshot_mirrors_the_episode(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xcafef00du;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_evidence_snap_count, 1);
    ASSERT(strcmp(s.twin_evidence_snaps[0].ssid, "Cafe-Net") == 0);
    ASSERT_EQ((int)s.twin_evidence_snaps[0].confidence,
              (int)s.twin_episodes[0].confidence);
    ASSERT_EQ(s.twin_evidence_snaps[0].hashes_differ, 1);
    ASSERT_EQ(s.twin_evidence_snaps[0].diff_oui, 1);
    ASSERT_EQ((int)s.twin_evidence_snaps[0].positive,
              TWIN_W_DIFF_OUI + TWIN_W_IE_HASH);
}

/* The snapshot is overwritten every poll, not accumulated: a pair that
 * stops showing a signal loses it from the vector on the very next
 * snapshot, unlike twin_episode_t's latched flags. Seen red with the
 * memset in twins_snapshot() dropped (the stale attacker_oui from the
 * first poll survived into the second, read-back array). */
static void test_twins_evidence_snapshot_reflects_latest_poll_only(void) {
    alerts_clear(); ownership_clear();
    sloth_state_t s; seed(&s);
    uint8_t legit[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t pin[6]   = {0x00,0x13,0x37,0x44,0x55,0x66};  /* Hak5 OUI */
    add_beacon(&s, "Cafe-Net", legit, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", pin,   "WPA2", -50);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_evidence_snap_count, 1);
    ASSERT_EQ(s.twin_evidence_snaps[0].attacker_oui, 1);

    /* The attacker's BSSID leaves earshot; a same-SSID, same-cipher,
     * diff-OUI pair with no Hak5/Espressif OUI remains. 0x11 is
     * globally administered (bit 0x02 clear), same as the "second
     * vendor" bssid other tests in this file use — a locally
     * administered replacement would make neither OUI comparable
     * (twin_evidence_score) and drop the episode entirely instead of
     * exercising the overwrite this test is for. */
    memcpy(s.beacon_aps[1].bssid, (uint8_t[]){0x11,0x22,0x33,0x44,0x55,0x66}, 6);
    s.beacon_aps[1].fp.oui[0] = 0x11;
    s.beacon_aps[1].fp.oui[1] = 0x22;
    s.beacon_aps[1].fp.oui[2] = 0x33;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_evidence_snap_count, 1);
    ASSERT_EQ(s.twin_evidence_snaps[0].attacker_oui, 0);
}

/* Late-arrival flag (#188, ruling 3b): the episode carries what the
 * scorer counted, so the view's `>` and the JSONL field cannot say
 * something the alert's "+late-arrival" does not. A copy on a locally
 * administered address ten minutes after the original, one band,
 * different vendor IEs; and the same pair a minute apart, where the
 * flag is off and the confidence is the 35 it was. */
static void test_twins_late_arrival_flag(void) {
    alerts_clear();
    time_t now = time(NULL);
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x02,0x9a,0x3c,0x71,0x5e,0x08};
    add_beacon(&s, "Cafe-Net", a, "WPA2", -70);
    add_beacon(&s, "Cafe-Net", b, "WPA2", -50);
    s.beacon_aps[0].fp.vendor_ies_hash = 0xdeadbeefu;
    s.beacon_aps[1].fp.vendor_ies_hash = 0xcafef00du;
    s.beacon_aps[0].first_seen = now - 1200;
    s.beacon_aps[1].first_seen = now - 600;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].late_arrival, 1);
    ASSERT_EQ(s.twin_episodes[0].hash_mismatch, 1);
    ASSERT_EQ((int)s.twin_episodes[0].confidence,
              TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL);

    s.beacon_aps[1].first_seen = now - 1140;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
    ASSERT_EQ(s.twin_episodes[0].late_arrival, 0);
    ASSERT_EQ((int)s.twin_episodes[0].confidence, TWIN_W_IE_HASH);
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
    uint8_t legit[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t legit[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t real[6]  = {0xa8,0xbb,0xcc,0x01,0x02,0x03};  /* clean,   higher */
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    ASSERT_LINE_HAS(0, "Evil-twin episodes: 0 / max 64");
    ASSERT_SCREEN_HAS("(no twin pairs observed");
}

static void test_view_twins_populated_does_not_crash(void) {
    alerts_clear();
    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a1[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b1[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint8_t a2[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x04};
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
    uint8_t router[6]   = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t real[6]      = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t mine[6]  = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t rogue[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    /* Mine is the STRONGER signal — without the designation the
     * lower-RSSI rule would call it the twin. */
    add_beacon(&s, "CorpWiFi", mine,  "WPA2", -40);
    add_beacon(&s, "CorpWiFi", rogue, "WPA2", -75);
    ownership_add_bssid("a8:bb:cc:01:02:03");
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_inv_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    if (!f) return;
    const char *body =
        "{\"networks\":[{\"ssid\":\"CorpWiFi\","
        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}";
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    ASSERT_EQ(inventory_load(tmp, NULL, 0), 1);

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_inv2_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    FILE *f = fopen(tmp, "w");
    ASSERT(f != NULL);
    if (!f) return;
    const char *body =
        "{\"networks\":[{\"ssid\":\"CorpWiFi\","
        "\"bssids\":[\"a8:bb:cc:01:02:03\",\"11:22:33:44:55:66\"]}]}";
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    ASSERT_EQ(inventory_load(tmp, NULL, 0), 1);

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t strong[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
    uint8_t b[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    add_beacon(&s, "CorpWiFi", a, "WPA2", -40);
    add_beacon(&s, "CorpWiFi", b, "WPA2", -75);
    ownership_add_bssid("a8:bb:cc:01:02:03");
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_cls1_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_cls2_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x00,0x22,0x33,0x44,0x55,0x66};
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
    uint8_t legit[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_cls3_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_cls4_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t declared[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    uint8_t a[6] = {0xa8,0xbb,0xcc,0x01,0x02,0x03};
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
    static char tmp[TEST_TMP_MAX];
    static int  made;
    alerts_clear(); ownership_clear(); inventory_clear(); wired_attach_clear();
    if (!made) { int fd = mkstemp(test_tmp_tpl(tmp, sizeof(tmp), "sloth_twins_cls5_XXXXXX")); if (fd >= 0) close(fd); made = 1; }
    load_inventory(tmp, "{\"networks\":[{\"ssid\":\"CorpWiFi\","
                        "\"bssids\":[\"a8:bb:cc:01:02:03\"]}]}");

    sloth_state_t s; seed(&s);
    uint8_t a[6] = {0x00,0x22,0x33,0x44,0x55,0x66};
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

/* #188: the view takes its pairs from the same scorer as the rule, so
 * one device's 2.4 and 5 GHz radios are no more an episode than they
 * are an alert. The steer from an unrelated address is what would have
 * made them one: it is hard evidence on a real pair, and the only
 * signal here that the band rule and the U/L bit do not already excuse.
 * Mutation (2026-11-11): twin_pair_is_sibling() returning 0 turned the
 * count below to 1. The second half is the control: the same radios
 * first heard a minute apart are a pair again. */
static void test_twins_dual_band_radios_of_one_device_are_no_episode(void) {
    alerts_clear(); ownership_clear(); inventory_clear();
    time_t t0 = time(NULL) - 900;
    uint8_t r24[6]  = {0x28,0x25,0x5f,0x10,0x20,0x14};
    uint8_t r5[6]   = {0x28,0x25,0x5f,0x10,0x20,0x1c};
    uint8_t mesh[6] = {0x3c,0x52,0xa1,0x01,0x02,0x03};

    static sloth_state_t s; seed(&s);
    add_beacon(&s, "HomeNet", r24, "WPA2", -60);
    add_beacon(&s, "HomeNet", r5,  "WPA2", -64);
    s.beacon_aps[0].channel = 6;   s.beacon_aps[0].first_seen = t0;
    s.beacon_aps[1].channel = 157; s.beacon_aps[1].first_seen = t0 + 2;
    btm_steer_t *st = &s.btm_steers[s.btm_steer_count++];
    memset(st, 0, sizeof(*st));
    memcpy(st->bssid, mesh, 6);
    st->req_count = 1;
    st->imminent_count = 3;
    memcpy(st->candidates[0], r5, 6);
    st->candidate_count = 1;
    st->first_seen = st->last_seen = time(NULL);
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 0);

    s.beacon_aps[1].first_seen = t0 + 60;
    twins_snapshot(&s);
    ASSERT_EQ(s.twin_episode_count, 1);
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

/* ── A mesh's guest VAPs (#227) ────────────────────────────────
 *
 * The issue's field shape, hand-built: a neighbour's 3-node TP-Link
 * style mesh, every node with its main SSID on a globally administered
 * BSSID and its guest SSID on a locally administered copy of it
 * (98:.. -> 9e:.., the low five octets kept). All ten addresses share
 * the first four octets. On 2.4 GHz channel 4 node A is faint (-90 dBm,
 * 11 beacons over the hour), B is at -86 (6), C at -82 (419) and was
 * first heard five minutes after A; on 5 GHz channel 48, A and C with
 * one and three beacons. Each node's guest VAP carries its own vendor
 * IEs. Before #227 the A/C guest pair was CRIT at 55: vendor-IE +
 * late-arrival. */

#define MESH_GUEST "Neighbour-Guest"
#define MESH_MAIN  "Neighbour"

typedef struct {
    uint8_t lo5[5];          /* octets 1-5, shared by main and guest */
    int     channel;
    int8_t  dbm;
    int     frames;
    int     first_after;     /* seconds after t0 */
    uint32_t hash;
} mesh_radio_t;

static const mesh_radio_t MESH_RADIOS[] = {
    { {0xda,0xc4,0x10,0x5e,0xee},  4, -90,  11,   0, 0xa000u },  /* A */
    { {0xda,0xc4,0x10,0x5e,0xef}, 48, -90,   1,   0, 0xa500u },  /* A 5G */
    { {0xda,0xc4,0x10,0x5f,0xae},  4, -86,   6,  60, 0xb000u },  /* B */
    { {0xda,0xc4,0x10,0x69,0x86},  4, -82, 419, 300, 0xc000u },  /* C */
    { {0xda,0xc4,0x10,0x69,0x87}, 48, -88,   3, 300, 0xc500u },  /* C 5G */
};
#define MESH_N ((int)(sizeof(MESH_RADIOS) / sizeof(MESH_RADIOS[0])))

static beacon_ap_t *mesh_vap(sloth_state_t *s, const char *ssid,
                             uint8_t octet0, const mesh_radio_t *r,
                             time_t t0) {
    uint8_t b[6];
    b[0] = octet0;
    memcpy(b + 1, r->lo5, 5);
    add_beacon(s, ssid, b, "WPA2", r->dbm);
    beacon_ap_t *ap = &s->beacon_aps[s->beacon_count - 1];
    ap->channel     = r->channel;
    ap->frame_count = r->frames;
    ap->first_seen  = t0 + r->first_after;
    ap->rssi_max_60s = r->dbm;
    ap->fp.vendor_ies_hash = r->hash;
    return ap;
}

/* The guest VAPs first, A then C then the rest, so the rule (which
 * fires one pair per first half and moves on) fires the A/C pair; then
 * each node's main BSSID with its own vendor IEs. Returns the guest
 * halves of A and C through `ga` / `gc`. */
static void mesh_fixture(sloth_state_t *s, time_t t0, int with_mains,
                         beacon_ap_t **ga, beacon_ap_t **gc) {
    seed(s);
    static const int order[] = { 0, 3, 2, 1, 4 };
    for (int k = 0; k < MESH_N; k++) {
        beacon_ap_t *ap = mesh_vap(s, MESH_GUEST, 0x9e,
                                   &MESH_RADIOS[order[k]], t0);
        if (order[k] == 0 && ga) *ga = ap;
        if (order[k] == 3 && gc) *gc = ap;
    }
    if (!with_mains) return;
    for (int k = 0; k < MESH_N; k++) {
        beacon_ap_t *ap = mesh_vap(s, MESH_MAIN, 0x98, &MESH_RADIOS[k], t0);
        ap->fp.vendor_ies_hash ^= 0x0101u;
    }
}

static int twins_worst(const sloth_state_t *s, int *conf) {
    int worst = -1;
    if (conf) *conf = -1;
    for (int k = 0; k < s->alert_count; k++) {
        if (s->alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        if ((int)s->alerts[k].sev > worst) {
            worst = (int)s->alerts[k].sev;
            if (conf) *conf = s->alerts[k].confidence;
        }
    }
    return worst;
}

/* The `twin-fp` row of one pair, by its key (alert_pair_key), or -1. A
 * pair-specific lookup because other pairs in a fixture score on their
 * own terms (a main BSSID moved to another first octet is a second
 * vendor beside the other mains). */
static int twins_pair_alert(const sloth_state_t *s, const beacon_ap_t *a,
                            const beacon_ap_t *b) {
    char ka[20], kb[20];
    const uint8_t *x = a->bssid, *y = b->bssid;
    snprintf(ka, sizeof(ka), "%02x:%02x:%02x:%02x:%02x:%02x",
             x[0], x[1], x[2], x[3], x[4], x[5]);
    snprintf(kb, sizeof(kb), "%02x:%02x:%02x:%02x:%02x:%02x",
             y[0], y[1], y[2], y[3], y[4], y[5]);
    for (int k = 0; k < s->alert_count; k++) {
        if (s->alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        if (strncmp(s->alerts[k].key, "twin-fp:", 8) != 0) continue;
        if (strstr(s->alerts[k].key, ka) && strstr(s->alerts[k].key, kb))
            return k;
    }
    return -1;
}

/* The issue's fixture end to end: WARN at most, no CRIT. Both #227
 * changes hold the A/C pair down here (A is unsteady and the pair is a
 * mesh's), so this block alone cannot go red under one mutation; the
 * two tests after it isolate each, and their mutations are listed
 * there. Under both mutations together this block read CRIT at 55. */
static void test_twins_mesh_guest_vaps_are_not_crit(void) {
    alerts_clear(); ownership_clear(); inventory_clear();
    time_t t0 = time(NULL) - 3600;
    static sloth_state_t s;
    beacon_ap_t *ga = NULL, *gc = NULL;
    mesh_fixture(&s, t0, 1, &ga, &gc);
    ASSERT(ga != NULL && gc != NULL);
    if (!ga || !gc) return;

    twin_evidence_t ev;
    ASSERT_EQ(twin_evidence_score(&s, ga, gc, time(NULL), &ev), 1);
    ASSERT_EQ(ev.hashes_differ, 1);
    ASSERT_EQ(ev.mesh_vap, 1);
    ASSERT_EQ(ev.late_arrival, 0);          /* A is not heard steadily */
    ASSERT_EQ(ev.faint, 0);                 /* as in the field */
    ASSERT_EQ(ev.hard, 0);

    alerts_update(&s);
    int conf = -1;
    int worst = twins_worst(&s, &conf);
    ASSERT(worst >= 0);                     /* still a row, not muted away */
    ASSERT(worst <= (int)ALERT_SEV_WARN);
    for (int k = 0; k < s.alert_count; k++) {
        if (s.alerts[k].type != ALERT_TYPE_EVIL_TWIN) continue;
        ASSERT(s.alerts[k].sev != ALERT_SEV_CRIT);
        ASSERT(s.alerts[k].confidence < TWIN_CRIT_MIN_CONF);
    }

    twins_snapshot(&s);
    for (int k = 0; k < s.twin_episode_count; k++)
        ASSERT((int)s.twin_episodes[k].confidence < TWIN_CRIT_MIN_CONF);
}

/* The deduction on its own: node A heard steadily (one frame a second),
 * so the late arrival counts, 35 + 20 = 55, and the mesh shape takes it
 * to 20, WARN. Then each condition of the shape removed in turn, every
 * one back to CRIT at 55: no main SSIDs at all (a lone locally
 * administered copy), C's main on another channel, C's main under the
 * guest SSID, C's main from another first octet (the first four octets
 * no longer shared), C's guest copied from A's main but not on A's
 * address, a copy of A's guest VAP itself on first octet 9a (one
 * parent for both halves), C's main under another SSID than A's. And a
 * hard signal is not deducted away: a steer from an unrelated address
 * at the pair is CRIT with the shape in place.
 *
 * Mutations (2026-11-17), each red here: `if (ev.mesh_vap) ev.context
 * += TWIN_C_MESH_VAP` removed (the first block read CRIT at 55);
 * twin_pair_mesh_vap() returning 1 for every pair (every negative block
 * read WARN 20); the channel test dropped from twin_mesh_parent() (its
 * block WARN 20); the SSID test dropped (its block WARN 20); the
 * `want0` filter dropped, so the first four octets are not compared
 * (its block WARN 20). Review (2026-11-17): the low-five-octets
 * inequality dropped from twin_pair_mesh_vap() (the 9a block read WARN
 * 20); the parents' SSID comparison dropped (the IoT block read WARN
 * 20). */
static void test_twins_mesh_vap_is_context(void) {
    alerts_clear(); ownership_clear(); inventory_clear();
    time_t t0 = time(NULL) - 3600;
    time_t now = time(NULL);
    static sloth_state_t s;
    beacon_ap_t *ga = NULL, *gc = NULL;
    twin_evidence_t ev;

#define MESH_STEADY_A() do { ga->frame_count = 3600; \
    for (int k_ = 0; k_ < s.beacon_count; k_++) \
        if (memcmp(s.beacon_aps[k_].bssid + 1, ga->bssid + 1, 5) == 0) \
            s.beacon_aps[k_].frame_count = 3600; } while (0)

    mesh_fixture(&s, t0, 1, &ga, &gc);
    MESH_STEADY_A();
    ASSERT_EQ(twin_evidence_score(&s, ga, gc, now, &ev), 1);
    ASSERT_EQ(ev.late_arrival, 1);
    ASSERT_EQ(ev.mesh_vap, 1);
    ASSERT_EQ(ev.positive, TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL);
    ASSERT_EQ(ev.context, TWIN_C_MESH_VAP);
    ASSERT_EQ(ev.confidence,
              TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL - TWIN_C_MESH_VAP);
    alerts_update(&s);
    int idx = twins_pair_alert(&s, ga, gc);
    ASSERT(idx >= 0);
    if (idx >= 0) {
        ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_WARN);
        ASSERT_EQ(s.alerts[idx].confidence,
                  TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL - TWIN_C_MESH_VAP);
        ASSERT(strstr(s.alerts[idx].detail, " +late-arrival +mesh VAP")
               != NULL);
    }
    ASSERT(twins_worst(&s, NULL) <= (int)ALERT_SEV_WARN);

    /* Each condition removed: the late copy is CRIT at 55 again. */
    for (int c = 0; c < 7; c++) {
        alerts_clear();
        mesh_fixture(&s, t0, c != 0, &ga, &gc);
        MESH_STEADY_A();
        beacon_ap_t *mc = NULL;
        for (int k = 0; k < s.beacon_count; k++)
            if (s.beacon_aps[k].bssid[0] == 0x98 &&
                memcmp(s.beacon_aps[k].bssid + 1, gc->bssid + 1, 5) == 0)
                mc = &s.beacon_aps[k];
        if (c == 1 && mc) mc->channel = 1;
        if (c == 2 && mc) snprintf(mc->ssid, sizeof(mc->ssid), "%s", MESH_GUEST);
        if (c == 3 && mc) mc->bssid[0] = 0x90;
        if (c == 4) gc->bssid[4] ^= 0x40;   /* no main shares its low octets */
        /* A copy of A's own guest VAP on another locally administered
         * first octet: A's main is the parent of both halves. */
        if (c == 5) {
            gc->bssid[0] = 0x9a;
            memcpy(gc->bssid + 1, ga->bssid + 1, 5);
        }
        /* C's main under another SSID: two of one box's VAPs, not two
         * nodes of one network. */
        if (c == 6 && mc) snprintf(mc->ssid, sizeof(mc->ssid), "%s", "Neighbour-IoT");
        if (c != 0) ASSERT(mc != NULL);
        twin_evidence_score(&s, ga, gc, now, &ev);
        if (ev.mesh_vap != 0)
            fprintf(stderr, "    mesh case %d: mesh_vap %d\n", c, ev.mesh_vap);
        ASSERT_EQ(ev.mesh_vap, 0);
        ASSERT_EQ(ev.confidence, TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL);
        alerts_update(&s);
        idx = twins_pair_alert(&s, ga, gc);
        ASSERT(idx >= 0);
        if (idx < 0) continue;
        ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
        ASSERT_EQ(s.alerts[idx].confidence,
                  TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL);
        ASSERT(strstr(s.alerts[idx].detail, "mesh VAP") == NULL);
    }

    /* A hard signal survives the deduction. */
    alerts_clear();
    mesh_fixture(&s, t0, 1, &ga, &gc);
    MESH_STEADY_A();
    btm_steer_t *st = &s.btm_steers[s.btm_steer_count++];
    memset(st, 0, sizeof(*st));
    static const uint8_t steerer[6] = {0x5c,0x11,0x22,0x33,0x44,0x55};
    memcpy(st->bssid, steerer, 6);
    st->req_count = 1;
    st->imminent_count = 3;
    memcpy(st->candidates[0], gc->bssid, 6);
    st->candidate_count = 1;
    st->first_seen = st->last_seen = time(NULL);
    twin_evidence_score(&s, ga, gc, now, &ev);
    ASSERT_EQ(ev.mesh_vap, 1);
    ASSERT_EQ(ev.hard, 1);
    alerts_update(&s);
    idx = twins_pair_alert(&s, ga, gc);
    ASSERT(idx >= 0);
    if (idx >= 0) ASSERT_EQ((int)s.alerts[idx].sev, (int)ALERT_SEV_CRIT);
#undef MESH_STEADY_A
}

/* Late arrival needs a steadily heard original (#227). #193's case, a
 * single locally administered copy with no main network beside it,
 * first heard ten minutes after an original on a vendor's address, one
 * band, other vendor IEs: CRIT at 55 when the original has been heard
 * once a second, and at the floor of TWIN_STEADY_FRAME_S (60 frames in
 * the hour). One frame fewer, or the field's 11, and the gap is
 * sloth's: no late arrival, WARN at 35. A frame_count of 0 is a
 * hand-built entry and "cannot say", so it still counts.
 *
 * Mutations (2026-11-17), each red here: the `!twin_ap_steady(early)`
 * test removed from twin_pair_late_arrival() (the 59- and 11-frame
 * blocks read CRIT 55); `>=` in twin_ap_steady() made `>` (the 60-frame
 * block read WARN 35); the frame_count 0 escape removed (the 0 block
 * read WARN 35). */
static void test_twins_late_arrival_needs_a_steady_original(void) {
    alerts_clear(); ownership_clear(); inventory_clear();
    time_t now = time(NULL);
    time_t t0  = now - 3600;
    uint8_t orig[6] = {0x00,0x11,0x22,0x33,0x44,0x55};
    uint8_t copy[6] = {0x02,0x9a,0x3c,0x71,0x5e,0x08};
    static const struct { int frames, late, sev, conf; } C[] = {
        { 3600, 1, ALERT_SEV_CRIT, TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL },
        {   60, 1, ALERT_SEV_CRIT, TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL },
        {   59, 0, ALERT_SEV_WARN, TWIN_W_IE_HASH },
        {   11, 0, ALERT_SEV_WARN, TWIN_W_IE_HASH },
        {    0, 1, ALERT_SEV_CRIT, TWIN_W_IE_HASH + TWIN_W_LATE_ARRIVAL },
    };
    static sloth_state_t s;
    for (size_t c = 0; c < sizeof(C) / sizeof(C[0]); c++) {
        alerts_clear();
        seed(&s);
        add_beacon(&s, "CorpWiFi", orig, "WPA2", -60);
        add_beacon(&s, "CorpWiFi", copy, "WPA2", -60);
        beacon_ap_t *o = &s.beacon_aps[0], *k = &s.beacon_aps[1];
        o->first_seen = t0;        o->last_seen = now;
        k->first_seen = t0 + 600;  k->last_seen = now;
        o->frame_count = C[c].frames;
        k->frame_count = 500;
        o->fp.vendor_ies_hash = 0x1111u;
        k->fp.vendor_ies_hash = 0x2222u;
        twin_evidence_t ev;
        twin_evidence_score(&s, o, k, now, &ev);
        alerts_update(&s);
        int conf = -1;
        int sev = twins_worst(&s, &conf);
        if (ev.late_arrival != C[c].late || sev != C[c].sev ||
            conf != C[c].conf)
            fprintf(stderr, "    %d frames: late %d sev %d conf %d\n",
                    C[c].frames, ev.late_arrival, sev, conf);
        ASSERT_EQ(ev.late_arrival, C[c].late);
        ASSERT_EQ(ev.mesh_vap, 0);
        ASSERT_EQ(sev, C[c].sev);
        ASSERT_EQ(conf, C[c].conf);
    }
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
    RUN_TEST(test_twins_evidence_snapshot_mirrors_the_episode);
    RUN_TEST(test_twins_evidence_snapshot_reflects_latest_poll_only);
    RUN_TEST(test_twins_late_arrival_flag);
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
    RUN_TEST(test_twins_dual_band_radios_of_one_device_are_no_episode);

    TEST_SUITE("twins: a mesh's guest VAPs (#227)");
    RUN_TEST(test_twins_mesh_guest_vaps_are_not_crit);
    RUN_TEST(test_twins_mesh_vap_is_context);
    RUN_TEST(test_twins_late_arrival_needs_a_steady_original);

    TEST_SUITE("twins view");
    RUN_TEST(test_view_twins_empty_does_not_crash);
    RUN_TEST(test_view_twins_populated_does_not_crash);
    RUN_TEST(test_view_twins_key_navigation);
}
