/* Impersonation rules: the evil-twin family (pair, proximity, attack
 * chain), SSID confusion, KARMA, open onboarding and camera setup
 * SSIDs, captive portals, WPA downgrade, SAE/PSK split and regression,
 * and FragAttacks. Also the pair scoring the Twins view shares
 * (twin_choose_sides, twin_evidence_score, twin_classify, alert_pair_key
 * — public API in src/alerts.h), so the rule and the view keep one
 * implementation.
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static, and
 * btm_candidate_is_twin() is shared with rule_btm_abuse in
 * rules_wifi_mgmt.c. The order dependencies this family has (the taint
 * the chain rule writes for rule_evil_twin to read next tick, the
 * deauth flood the chain's finding cites) are stated in
 * src/alerts/rules_table.c and pinned by tests/test_alert_rules.c. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "alerts.h"
#include "tune.h"   /* operator-tunable thresholds (#82) */
#include "beacon_snoop.h"
#include "db.h"
#include "assoc_track.h"
#include "wifi_assess.h"
#include "tool_fingerprint.h"
#include "karma_detect.h"
#include "captive_portal.h"
#include "fragattack.h"
#include "wifi_oui_attacker.h"
#include "ownership.h"
#include "inventory.h"
#include "wired_attach.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* Is this BSSID the rogue half of a detected twin pair? twin_episodes
 * is the materialised evil-twin candidate set (twins_snapshot runs
 * ahead of alerts_update in the poll loop), so this is a direct read
 * rather than a second derivation of the twin rule. Only the twin half
 * matches: the real half being offered as a roam target is what a
 * legitimate steer looks like. */
/* Was `bssid` named as a destination in a recent BTM Request that
 * carried Disassociation Imminent — issue #76's chain, as a marker
 * rather than a sixth alert.
 *
 * Every link in that chain already fires: a BTM burst raises
 * BTM_ABUSE, a deauth flood raises DEAUTH_FLOOD, a new same-SSID BSSID
 * raises EVIL_TWIN, an RSSI jump raises EVIL_TWIN_PROXIMITY. A separate
 * chain alert would be a fifth row describing the same seconds of air,
 * and five alerts for one event teaches an operator to ignore all five.
 * KARMA_AP already settled this shape with its +deauth-then-lure
 * marker; this follows it.
 *
 * The link is deliberately tight. Not "a steer happened and a twin
 * appeared" — that is two things in the same minute — but "the steer
 * named *this* BSSID as where the client should go". A candidate list
 * pointing at a known twin is the AP telling a client to associate to
 * the rogue, which is the whole attack in one field.
 *
 * Imminent-only for the same reason rule_btm_abuse counts only those: a
 * Request without B2 set cannot force anything, and a load-balancing
 * controller emits exactly those all day.
 *
 * Returns the steering AP's index in s->btm_steers[], or -1. */
#define TWIN_STEER_WINDOW_S ((int)tune_val(TUNE_TWIN_STEER_WINDOW_S))

static int btm_steered_to(const sloth_state_t *s, const uint8_t bssid[6],
                          time_t now) {
    for (int i = 0; i < s->btm_steer_count; i++) {
        const btm_steer_t *st = &s->btm_steers[i];
        if (st->imminent_count <= 0) continue;
        if (st->last_seen && now - st->last_seen > TWIN_STEER_WINDOW_S)
            continue;
        for (int c = 0; c < st->candidate_count && c < MAX_AP_NEIGHBORS; c++)
            if (memcmp(st->candidates[c], bssid, 6) == 0) return i;
    }
    return -1;
}

int btm_candidate_is_twin(const sloth_state_t *s,
                          const uint8_t bssid[6]) {
    for (int i = 0; i < s->twin_episode_count; i++) {
        const twin_episode_t *e = &s->twin_episodes[i];
        if (memcmp(e->twin_bssid, bssid, 6) == 0) return 1;
        /* An unattributed pair has no impostor half to single out (#89):
         * `real_bssid`/`twin_bssid` are just the pair in canonical
         * order. Steering a client at *either* half of a live candidate
         * pair is the thing worth escalating, and picking one of them
         * because it sorted higher would be arbitrary. */
        if (!e->attributed && memcmp(e->real_bssid, bssid, 6) == 0) return 1;
    }
    return 0;
}

/* ── Canonical pair key + weighted twin evidence (#89) ─────────
 * Contract, weights and the reasoning behind each one: src/alerts.h. */

void twin_pair_order(const beacon_ap_t *a, const beacon_ap_t *b,
                     const beacon_ap_t **lo, const beacon_ap_t **hi) {
    if (!a || !b || !lo || !hi) return;
    if (memcmp(a->bssid, b->bssid, 6) <= 0) { *lo = a; *hi = b; }
    else                                    { *lo = b; *hi = a; }
}

/* Attribution ladder — contract and ranking rationale in alerts.h.
 * Moved here from twins.c in #89 slice 3 so the rule and the view share
 * one implementation rather than two copies that can drift. */
int twin_choose_sides(const beacon_ap_t *a, const beacon_ap_t *b,
                      const beacon_ap_t **real_out,
                      const beacon_ap_t **twin_out) {
    if (!a || !b || !real_out || !twin_out) return 0;

    /* inventory_verdict already unions --my-bssid into the approved
     * set, so the two operator statements are read together here
     * rather than ranked against each other. */
    int a_mine = ownership_is_my_bssid(a->bssid) ||
                 inventory_verdict(a->ssid, a->bssid) == INV_APPROVED;
    int b_mine = ownership_is_my_bssid(b->bssid) ||
                 inventory_verdict(b->ssid, b->bssid) == INV_APPROVED;
    if (a_mine && !b_mine) { *real_out = a; *twin_out = b; return 1; }
    if (b_mine && !a_mine) { *real_out = b; *twin_out = a; return 1; }

    int a_tainted = evil_twin_bssid_is_tainted(a->bssid);
    int b_tainted = evil_twin_bssid_is_tainted(b->bssid);
    if (a_tainted && !b_tainted) { *real_out = b; *twin_out = a; return 1; }
    if (b_tainted && !a_tainted) { *real_out = a; *twin_out = b; return 1; }

    int a_tool = oui_is_hak5(a->fp.oui) || oui_is_espressif(a->fp.oui);
    int b_tool = oui_is_hak5(b->fp.oui) || oui_is_espressif(b->fp.oui);
    if (a_tool && !b_tool) { *real_out = b; *twin_out = a; return 1; }
    if (b_tool && !a_tool) { *real_out = a; *twin_out = b; return 1; }

    twin_pair_order(a, b, real_out, twin_out);
    return 0;
}

/* ── Pair classification (#89 slice 3) ─────────────────────────
 * Why "unauthorized AP on the wired network" is deliberately not one of
 * these values: alerts.h, and src/wired_attach.h at length. */

twin_class_t twin_classify(const twin_evidence_t *ev) {
    if (!ev) return TWIN_CLASS_UNKNOWN;
    /* Checked first: two declared radios are the operator's own
     * infrastructure whatever else the air says about them, which is
     * the mixed-vendor case the issue lists as a false positive. */
    if (ev->inv_approved)  return TWIN_CLASS_DECLARED;
    /* A written statement that this radio is not approved for a name
     * the operator does declare. The strongest impersonation evidence
     * available, and the only one an attacker cannot reach. */
    if (ev->inv_mismatch)  return TWIN_CLASS_IMPERSONATOR;
    /* Hard RF evidence — an attacker-tool OUI, a BTM steer aimed at the
     * pair. These establish an over-the-air behaviour, which is what
     * this axis is about, so they carry it without an inventory. */
    if (ev->hard)          return TWIN_CLASS_IMPERSONATOR;
    /* An inventory was consulted, it declares an estate, and this SSID
     * is not in it — somebody else's network. Without a loaded
     * inventory there is no estate to be outside of, so the same pair
     * stays UNKNOWN rather than being called a neighbour on no basis. */
    if (ev->inv_consulted) return TWIN_CLASS_NEIGHBOR;
    return TWIN_CLASS_UNKNOWN;
}

const char *twin_class_label(twin_class_t c) {
    switch (c) {
    case TWIN_CLASS_IMPERSONATOR: return "impostor";
    case TWIN_CLASS_NEIGHBOR:     return "neighbor";
    case TWIN_CLASS_DECLARED:     return "declared";
    case TWIN_CLASS_UNKNOWN:
    default:                      return "?";
    }
}

void alert_pair_key(char *out, size_t n, const char *rule_id,
                    const uint8_t bssid_a[6], const uint8_t bssid_b[6],
                    const char *site, const char *security_profile) {
    if (!out || n == 0) return;
    out[0] = '\0';
    if (!rule_id || !bssid_a || !bssid_b) return;

    const uint8_t *lo = bssid_a, *hi = bssid_b;
    if (memcmp(bssid_a, bssid_b, 6) > 0) { lo = bssid_b; hi = bssid_a; }

    char lo_s[20], hi_s[20];
    mac_to_str(lo, lo_s, sizeof(lo_s));
    mac_to_str(hi, hi_s, sizeof(hi_s));
    /* Fixed-width BSSIDs keep the field boundaries unambiguous even
     * when site is empty, which it is until #89 slice 2 lands. */
    snprintf(out, n, "%.16s:%s:%s:%.32s:%.24s", rule_id, lo_s, hi_s,
             site ? site : "", security_profile ? security_profile : "");
}

/* The pair's shared security posture, ordered with the BSSIDs so the
 * key is stable. Two BSSIDs disagreeing about security under one SSID
 * is a different finding from two agreeing, which is why it is part of
 * the identity and not just the detail. */
static void twin_profile(char *out, size_t n,
                         const beacon_ap_t *lo, const beacon_ap_t *hi) {
    snprintf(out, n, "%.9s/%.9s",
             lo->enc[0] ? lo->enc : "?", hi->enc[0] ? hi->enc : "?");
}

static int clamp_conf(int v) {
    if (v < TWIN_CONF_MIN) return TWIN_CONF_MIN;
    if (v > TWIN_CONF_MAX) return TWIN_CONF_MAX;
    return v;
}

int twin_evidence_score(const sloth_state_t *s, const beacon_ap_t *a,
                        const beacon_ap_t *b, time_t now,
                        twin_evidence_t *out) {
    twin_evidence_t ev;
    memset(&ev, 0, sizeof(ev));
    if (!a || !b) { if (out) *out = ev; return 0; }

    ev.diff_oui = memcmp(a->bssid, b->bssid, 3) != 0;
    ev.same_oui = !ev.diff_oui;

    /* Both sides emitted a usable vendor hash and they disagree →
     * firmware mismatch. Works on a same-OUI pair too, which is the
     * point: a clone that copied the OUI cannot also reproduce the
     * victim's vendor IEs byte for byte. */
    ev.hashes_differ = a->fp.vendor_ies_hash && b->fp.vendor_ies_hash &&
                       a->fp.vendor_ies_hash != b->fp.vendor_ies_hash;

    ev.attacker_oui = oui_is_hak5     (a->fp.oui) || oui_is_hak5     (b->fp.oui) ||
                      oui_is_espressif(a->fp.oui) || oui_is_espressif(b->fp.oui);

    if (s) ev.steered = btm_steered_to(s, a->bssid, now) >= 0 ||
                        btm_steered_to(s, b->bssid, now) >= 0;

    ev.nbr_claim = ap_infrastructure_peers(a, b);

    /* The approved inventory (#89 slice 2) — the one input here the
     * attacker cannot reach, because a human wrote it out-of-band.
     * Reasoning for why this is allowed to settle a pair either way,
     * when an OUI and a neighbour report are not, is in alerts.h. */
    inv_verdict_t va = inventory_verdict(a->ssid, a->bssid);
    inv_verdict_t vb = inventory_verdict(b->ssid, b->bssid);
    ev.inv_mismatch = (va == INV_MISMATCH || vb == INV_MISMATCH);
    ev.inv_approved = (va == INV_APPROVED && vb == INV_APPROVED);
    /* Not an evidence weight — it never touches `positive` or
     * `context`. It records whether there was an estate to compare
     * against at all, which twin_classify needs to tell "outside the
     * declared estate" from "nothing declared" (#89 slice 3). */
    ev.inv_consulted = inventory_loaded();

    if (ev.diff_oui)      ev.positive += TWIN_W_DIFF_OUI;
    if (ev.hashes_differ) ev.positive += TWIN_W_IE_HASH;
    if (ev.attacker_oui) { ev.positive += TWIN_W_ATTACKER_OUI; ev.hard = 1; }
    if (ev.steered)      { ev.positive += TWIN_W_BTM_STEER;    ev.hard = 1; }
    /* Hard: an operator's written statement that this radio is not one
     * of theirs. An attacker can advertise a neighbour report or copy
     * an OUI; it cannot edit the file. This is what keeps a spoofed
     * neighbour claim from erasing an inventory mismatch. */
    if (ev.inv_mismatch) { ev.positive += TWIN_W_INV_MISMATCH; ev.hard = 1; }

    if (ev.nbr_claim) ev.context += TWIN_C_NBR_CLAIM;
    if (ev.same_oui)  ev.context += TWIN_C_SAME_OUI;

    ev.confidence = clamp_conf(ev.positive - ev.context);
    if (out) *out = ev;
    /* Both halves declared by the operator: legitimate infrastructure,
     * whatever the radios look like to each other. This is the
     * mixed-vendor case the issue names — differing OUIs and
     * contradicting vendor-IE hashes are the strongest observed signals
     * in this file and both are simply wrong about a deployment sloth
     * has been told about. Caller keeps the filled `ev` so the CRIT
     * weak/strong branch, which does not gate on this return, can still
     * read `inv_approved`. */
    if (ev.inv_approved) return 0;
    /* No positive evidence is not the same as an exoneration — it means
     * there is nothing to report. That distinction is the whole of #89:
     * silence here comes from an empty evidence set, never from
     * treating an observed OUI or a neighbour claim as proof. */
    return ev.positive > 0;
}

/* One short, bounded phrase per context signal. ALERT_DETAIL_LEN is 256
 * and the SSID + two BSSIDs + cipher already take ~60 of it. The BTM
 * steer is not here: it gets its own note naming the steering AP, which
 * is the actionable half. */
static void twin_evidence_note(char *out, size_t n, const twin_evidence_t *ev) {
    snprintf(out, n, "%s%s%s",
             ev->inv_mismatch ? " +not in inventory"           : "",
             ev->same_oui     ? " +same-vendor-OUI"            : "",
             ev->nbr_claim    ? " +802.11k claim (unverified)" : "");
}

/* Wired-attachment state of the half something has actually accused
 * (#89 slice 3), or UNKNOWN when nothing has.
 *
 * Asking about an unattributed pair would attach a wired verdict to
 * whichever BSSID sorted higher, which is the shape of mistake slice 1
 * removed when it stopped letting RSSI name the impostor. And with no
 * correlator registered this is UNKNOWN for every pair, attributed or
 * not — RF cannot see a switch port. */
static wired_attach_t twin_accused_wired(const beacon_ap_t *a,
                                         const beacon_ap_t *b) {
    const beacon_ap_t *real = NULL, *twin = NULL;
    if (!twin_choose_sides(a, b, &real, &twin) || !twin)
        return WIRED_ATTACH_UNKNOWN;
    return wired_attach_lookup(twin->bssid);
}

/* The two pair axes, rendered for the alert detail.
 *
 * `wired=?` is printed on every row it applies to rather than omitted,
 * and that is the point of the whole slice: a reader who sees
 * "impostor" and no attachment field will fill the gap in themselves,
 * usually with the worst reading ("rogue on our LAN"), and act on it.
 * Saying `wired=?` out loud costs eight characters and is the
 * difference between a detector that does not know and one that has
 * been understood to have answered. */
static void twin_pair_axes_note(char *out, size_t n, twin_class_t cls,
                                wired_attach_t wired) {
    snprintf(out, n, " [class=%s wired=%s]",
             twin_class_label(cls), wired_attach_label(wired));
}


/* Captive-portal interception (#69).
 *
 * Every modern OS probes a fixed URL to decide whether it is behind a
 * captive portal, and expects a published, byte-exact answer. That
 * probe is deliberately unauthenticated and deliberately plaintext —
 * which is what makes it work, and what makes it hijackable. A rogue AP
 * answers with something else, and the victim's OS obligingly opens a
 * browser at the attacker's page.
 *
 * This is not a heuristic. The expected answer is documented and fixed,
 * so anything else on that host and path is an interception. The only
 * hard part is knowing whether the whole answer was seen, which is what
 * #71's body_complete is for.
 *
 * One alert type with a kind bitfield rather than the seven types the
 * issue proposes, following ALERT_TYPE_WPA_DOWNGRADE: seven types for
 * one detector would put seven rows in the rule table for what an
 * operator reads as a single finding, and the dedup key already
 * separates them per host. Flagged as a §4.2 departure. */
void rule_captive_portal(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->cp_event_count; i++) {
        const cp_event_t *e = &s->cp_events[i];
        if (!e->kind) continue;
        /* Events are a rolling ring; only recent ones are findings. */
        if (e->ts && now - e->ts > 600) continue;

        /* Which BSSID is the client on? A portal is hosted by whatever
         * the client associated to, and naming it turns "someone
         * intercepted this" into "that AP intercepted this". */
        char bss[20] = "";
        int  on_twin = 0;
        for (int a = 0; a < s->assoc_count; a++) {
            if (!s->assocs[a].sta_mac[0] && !s->assocs[a].sta_mac[5]) continue;
            /* The association table is keyed by MAC and the portal
             * event by IP, so this only resolves when a single client
             * is associated — enough to name the AP in the common
             * single-client-under-test case, and silent otherwise
             * rather than guessing. */
            if (s->assoc_count != 1) break;
            mac_to_str(s->assocs[a].bssid, bss, sizeof(bss));
            on_twin = btm_candidate_is_twin(s, s->assocs[a].bssid);
            break;
        }

        /* host came off the wire (#112): a remote component, so two
         * hosts sharing a 30-byte prefix are no longer one finding. */
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "portal");
        akey_remote(&k, e->host, 40);
        akey_u(&k, e->kind);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "%.30s intercepted for %.15s - %s%s%s%s%s",
                 e->host, e->src[0] ? e->src : "?",
                 cp_kind_label(e->kind),
                 e->evidence[0] ? " (" : "",
                 e->evidence[0] ? e->evidence : "",
                 e->evidence[0] ? ")" : "",
                 on_twin ? " - AP is a known evil twin" : "");

        /* DNS_UNEXPECTED is the soft one: these operators' addressing
         * changes, and being wrong about a CDN range must not produce a
         * CRIT. Everything else is unambiguous — a sentinel resolving
         * into private space or answering with the wrong bytes is not
         * something that happens by accident. */
        alert_sev_t sev = (e->kind == CP_KIND_DNS_UNEXPECTED)
                          ? ALERT_SEV_WARN : ALERT_SEV_CRIT;
        fire(ALERT_TYPE_CAPTIVE_PORTAL, sev,
             "CAPTIVE_PORTAL", detail, key, NULL, 0, now);
    }
}

/* FragAttacks slice 1 — issue #75. Reads fragattack.c directly rather
 * than a snapshot on sloth_state_t, the same shape rule_rts_flood uses
 * for ctrl_frames.c: there is no view yet, and copying a table into
 * state so one rule can read it is plumbing with no reader.
 *
 * Per row, a *copy* taken under fragattack's lock (#111), not a pointer
 * into the live table: the probe thread rewrites a row in place on
 * eviction, and the eight snprintf()s below would otherwise read a
 * BSSID from one row and a last_sa from the row that replaced it. */
void rule_fragattack(const sloth_state_t *s, time_t now) {
    (void)s;
    for (int i = 0; i < frag_bss_count(); i++) {
        frag_bss_t row;
        if (!frag_bss_copy(i, &row)) continue;
        const frag_bss_t *b = &row;

        char bss[20], sa[20], da[20];
        mac_to_str(b->bssid,   bss, sizeof(bss));
        mac_to_str(b->last_sa, sa,  sizeof(sa));
        mac_to_str(b->last_da, da,  sizeof(da));

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];

        if (b->plaintext_unicast > 0) {
            snprintf(key, sizeof(key), "fragplain:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u unprotected data frame%s on %.17s after key install"
                     " - last %.17s -> %.17s (CVE-2020-26140/-26143)",
                     b->plaintext_unicast,
                     b->plaintext_unicast == 1 ? "" : "s", bss, sa, da);
            /* CRIT on the first one. This is not a threshold detector:
             * a station whose encrypted traffic we have already seen
             * has no legitimate reason to send one plaintext non-EAPOL
             * frame, so the count is evidence volume, not confidence. */
            fire(ALERT_TYPE_FRAG_PLAINTEXT, ALERT_SEV_CRIT,
                 "FRAG_PLAINTEXT", detail, key, NULL, 0, now);
        }

        if (b->plaintext_bcast_frag > 0) {
            snprintf(key, sizeof(key), "fragbcast:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u plaintext broadcast fragment%s on %.17s"
                     " - broadcast reassembly is not permitted in an RSN"
                     " (CVE-2020-26145)",
                     b->plaintext_bcast_frag,
                     b->plaintext_bcast_frag == 1 ? "" : "s", bss);
            fire(ALERT_TYPE_FRAG_BCAST, ALERT_SEV_CRIT,
                 "FRAG_BCAST", detail, key, NULL, 0, now);
        }

        /* Completing the family — issue #75. */

        if (b->pn_gap > 0) {
            snprintf(key, sizeof(key), "fragpn:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u encrypted reassembl%s on %.17s with non-consecutive"
                     " packet numbers - last %.17s -> %.17s (CVE-2020-26146)",
                     b->pn_gap, b->pn_gap == 1 ? "y" : "ies", bss, sa, da);
            fire(ALERT_TYPE_FRAG_PN_GAP, ALERT_SEV_CRIT,
                 "FRAG_PN_GAP", detail, key, NULL, 0, now);
        }

        if (b->eapol_relay > 0) {
            snprintf(key, sizeof(key), "fragrelay:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u EAPOL frame%s forwarded between stations on %.17s"
                     " - last %.17s -> %.17s, neither is the AP"
                     " (CVE-2020-26139)",
                     b->eapol_relay, b->eapol_relay == 1 ? "" : "s",
                     bss, sa, da);
            fire(ALERT_TYPE_FRAG_EAPOL_RELAY, ALERT_SEV_CRIT,
                 "FRAG_EAPOL_RELAY", detail, key, NULL, 0, now);
        }

        /* Slice 3 — issue #75. */

        if (b->amsdu_flip > 0) {
            snprintf(key, sizeof(key), "fragamsdu:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u protected MPDU%s on %.17s replayed with the A-MSDU"
                     " bit flipped - last %.17s -> %.17s (CVE-2020-24588)",
                     b->amsdu_flip, b->amsdu_flip == 1 ? "" : "s",
                     bss, sa, da);
            /* CRIT on the first. A CCMP packet number is never reused
             * under one key, so a repeat is already outside the
             * protocol before the flipped bit is considered — this is
             * not a threshold detector and the count is evidence
             * volume, not confidence. */
            fire(ALERT_TYPE_FRAG_AMSDU, ALERT_SEV_CRIT,
                 "FRAG_AMSDU", detail, key, NULL, 0, now);
        }

        /* Slice 4 — issue #75. */

        if (b->amsdu_eapol_spoof > 0) {
            snprintf(key, sizeof(key), "fragamsdueapol:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u plaintext A-MSDU frame%s on %.17s whose first"
                     " subframe claims to carry EAPOL - last %.17s -> %.17s"
                     " (CVE-2020-26144)",
                     b->amsdu_eapol_spoof, b->amsdu_eapol_spoof == 1 ? "" : "s",
                     bss, sa, da);
            /* CRIT on the first. EAPOL is never legitimately aggregated
             * — it is always its own MPDU — so a sub-frame claiming
             * otherwise has no benign reading, only the mixed-content-
             * confusion bug the CVE describes. */
            fire(ALERT_TYPE_FRAG_AMSDU_EAPOL, ALERT_SEV_CRIT,
                 "FRAG_AMSDU_EAPOL", detail, key, NULL, 0, now);
        }

        /* Slice 2 — issue #75. */

        if (b->cache_poison > 0) {
            snprintf(key, sizeof(key), "fragcache:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u fragment reassembly%s on %.17s completed after a"
                     " (re)association - last %.17s -> %.17s"
                     " (CVE-2020-24586)",
                     b->cache_poison, b->cache_poison == 1 ? "" : "ies",
                     bss, sa, da);
            /* CRIT: the fragment cache should be empty at that boundary
             * by construction, so a completion that straddles it has no
             * benign reading, only a range of buggy ones. */
            fire(ALERT_TYPE_FRAG_CACHE, ALERT_SEV_CRIT,
                 "FRAG_CACHE", detail, key, NULL, 0, now);
        }

        if (b->mixed_protect > 0) {
            snprintf(key, sizeof(key), "fragmixed:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u reassembly%s on %.17s mixed an encrypted fragment"
                     " with a plaintext one - last %.17s -> %.17s"
                     " (CVE-2020-26147)",
                     b->mixed_protect, b->mixed_protect == 1 ? "" : "ies",
                     bss, sa, da);
            fire(ALERT_TYPE_FRAG_MIXED, ALERT_SEV_CRIT,
                 "FRAG_MIXED", detail, key, NULL, 0, now);
        }

        /* Slice 4 — issue #75, CVE-2020-24587. */

        if (b->mixed_key > 0) {
            snprintf(key, sizeof(key), "fragmixkey:%.17s", bss);
            snprintf(detail, sizeof(detail),
                     "%u reassembly%s on %.17s spanned a completed key"
                     " rotation - last %.17s -> %.17s (CVE-2020-24587)",
                     b->mixed_key, b->mixed_key == 1 ? "" : "ies",
                     bss, sa, da);
            /* CRIT: a fragment cache that survives a PTK rekey and
             * completes a reassembly across it has no benign reading —
             * the two fragments were never encrypted under the same key. */
            fire(ALERT_TYPE_FRAG_MIXKEY, ALERT_SEV_CRIT,
                 "FRAG_MIXKEY", detail, key, NULL, 0, now);
        }
    }
}

/* One SSID, two BSSIDs, incompatible AKM — issue #74 Detector B, the
 * concurrent half.
 *
 * rule_evil_twin has two branches and this falls between them. Its CRIT
 * branch needs a *weak* enc (OPEN/WEP) beside a strong one, and WPA2 is
 * not weak. Its WARN branch needs the same cipher and a different
 * vendor OUI, and these two do not have the same cipher. So an SSID
 * advertised as SAE-only by one BSSID and PSK-only by another — the
 * exact shape a rogue AP takes when it mirrors an SSID at the security
 * level it can actually crack — produced nothing.
 *
 * Not transition mode. An AP offering PSK *and* SAE together is
 * ALERT_TYPE_WPA_DOWNGRADE (#62); each side here must offer one family
 * and not the other, so a transition-mode AP is neither side and this
 * stays silent on it. The two rules answer different questions: one AP
 * offering a weak lane, versus two APs disagreeing about which lane
 * exists.
 *
 * Note what this does *not* cover: the same BSSID changing from SAE to
 * PSK over time. That is #74's config-regression case and it needs
 * persisted AKM history, which sloth does not keep — `beacon_aps` rows
 * are upserted, so yesterday's posture is overwritten by today's. */
void rule_sae_psk_split(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (!a->ssid[0]) continue;          /* hidden -> cannot correlate */

        int a_sae = (a->akm_bits & RSN_AKM_SAE_FAMILY) &&
                   !(a->akm_bits & RSN_AKM_PSK_FAMILY);
        if (!a_sae) continue;               /* walk from the SAE side only */

        for (int j = 0; j < s->beacon_count; j++) {
            if (i == j) continue;
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (strcmp(a->ssid, b->ssid) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (!(b->akm_bits & RSN_AKM_PSK_FAMILY)) continue;
            if (b->akm_bits & RSN_AKM_SAE_FAMILY)    continue;

            /* Did a client actually take the weak lane? An assoc
             * request naming PSK to the PSK-only BSSID is
             * offered-*and*-taken, which is the difference between a
             * misconfiguration and an incident. */
            int taken = 0;
            for (int k = 0; k < s->assoc_req_count; k++) {
                const assoc_req_t *r = &s->assoc_reqs[k];
                if (memcmp(r->bssid, b->bssid, 6) != 0) continue;
                if (!(r->akm_bits & RSN_AKM_PSK_FAMILY)) continue;
                if (r->akm_bits & RSN_AKM_SAE_FAMILY)    continue;
                taken = 1;
                break;
            }
            /* Different vendor OUI means this is not the same physical
             * AP's other radio, which is the one benign explanation for
             * a split. Same OUI stays WARN: a dual-band unit configured
             * inconsistently is a real finding but not an intrusion. */
            int diff_oui = memcmp(a->bssid, b->bssid, 3) != 0;

            char a_bssid[20], b_bssid[20];
            mac_to_str(a->bssid, a_bssid, sizeof(a_bssid));
            mac_to_str(b->bssid, b_bssid, sizeof(b_bssid));
            /* The SSID is whatever the AP (or an impostor) beacons
             * (#112): a remote component, sanitised and hashed whole. */
            char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
            akey_t k;
            akey_begin(&k, key, sizeof(key), "saesplit");
            akey_remote(&k, a->ssid, 32);
            if (!akey_end(&k)[0]) break;
            snprintf(detail, sizeof(detail),
                     "'%.16s' is SAE-only on %s and PSK-only on %s%s%s",
                     a->ssid, a_bssid, b_bssid,
                     diff_oui ? " - different vendor" : "",
                     taken ? " - a client associated with PSK" : "");
            fire(ALERT_TYPE_SAE_PSK_SPLIT,
                 (taken || diff_oui) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
                 "SAE_PSK_SPLIT", detail, key, NULL, 0, now);
            break;
        }
    }
}

/* One BSSID that sustained SAE-only and now advertises PSK-only —
 * issue #74 Detector B, the temporal half.
 *
 * The sibling of rule_sae_psk_split. That one compares two BSSIDs at
 * one moment; this compares one BSSID against its own past, which no
 * amount of in-memory state can answer — wifi_baseline.c is a single
 * session-scoped snapshot with no time dimension, and beacon_aps.akm_bits
 * is OR'd on conflict, so it records that an AP has *ever* offered both
 * families and cannot tell transition mode from a regression.
 *
 * So the evidence is a persisted table and the query lives in db.c,
 * making this the first rule to read from the database. Without
 * WITH_SQLITE db_akm_regressions() returns 0 and the rule is silent —
 * correct, because without a file there is no past to compare against.
 *
 * T1562.004 rather than T1557: nothing here says an adversary is
 * present. What it says is that a network's posture was lowered and
 * stayed lowered, which is a finding whether the cause was an intruder
 * or an administrator. */
void rule_sae_psk_regression(const sloth_state_t *s, time_t now) {
    (void)s;
    db_akm_regression_t regs[DB_MAX_AKM_REGRESSIONS];
    int n = db_akm_regressions(regs, DB_MAX_AKM_REGRESSIONS);
    for (int i = 0; i < n; i++) {
        const db_akm_regression_t *r = &regs[i];
        long days = (long)((r->was_last_seen - r->was_first_seen) / 86400);
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "saereg:%.40s:%.17s", r->ssid, r->bssid);
        snprintf(detail, sizeof(detail),
                 "'%.16s' on %.17s was SAE-only for %ldd and now advertises"
                 " PSK-only - WPA3 protection lost on this BSSID",
                 r->ssid, r->bssid, days);
        fire(ALERT_TYPE_SAE_PSK_REGRESSION, ALERT_SEV_CRIT,
             "SAE_PSK_REGRESSION", detail, key, NULL, 0, now);
    }
}

void rule_wpa_downgrade(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];

        /* A single beacon caught mid-hop is a sample, not a
         * configuration. Without this floor --hop would alert on every
         * AP it brushes past. */
        if (!a->first_seen ||
            now - a->first_seen < WPA_DOWNGRADE_MIN_OBSERVED_S) continue;

        /* Filled by wifi_downgrade_update() at the top of
         * alerts_update, so the [b] view reads the same field rather
         * than deriving it a second time. */
        uint8_t flags = a->downgrade_flags;
        if (!flags) continue;

        int mine = ownership_is_my_bssid(a->bssid);

        /* Escalate when a client has actually been moved onto the weak
         * lane rather than merely offered it (#60). An assoc-request
         * downgrade recorded against this BSSID is that evidence — the
         * offer being taken up is a different severity from the offer
         * standing open. */
        int exercised = 0;
        for (int k = 0; k < s->assoc_req_count; k++) {
            const assoc_req_t *r = &s->assoc_reqs[k];
            if (!r->downgrade_flags) continue;
            if (memcmp(r->bssid, a->bssid, 6) != 0) continue;
            if (r->ts && now - r->ts > 3600) continue;
            exercised = 1;
            break;
        }

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));

        /* One alert per (BSSID, kind): an AP offering two lanes is two
         * things to fix, and collapsing them would hide whichever the
         * operator did not read. */
        for (int b = 0; b < 4; b++) {
            uint8_t kind = (uint8_t)(1u << b);
            if (!(flags & kind)) continue;

            char key[ALERT_KEY_LEN];
            char detail[ALERT_DETAIL_LEN];
            snprintf(key, sizeof(key), "wpadg:%.17s:%u", bss, kind);
            snprintf(detail, sizeof(detail),
                     "%.17s \"%.20s\" posture=%s (observed %lds)%s%s",
                     bss, a->ssid[0] ? a->ssid : "<hidden>",
                     wifi_downgrade_label(kind),
                     (long)(now - a->first_seen),
                     exercised ? " - a client took the weak lane" : "",
                     mine ? " - YOUR network" : "");
            fire(ALERT_TYPE_WPA_DOWNGRADE,
                 (mine || exercised) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
                 "WPA_DOWNGRADE", detail, key, NULL, 0, now);
        }
    }
}

/* KARMA / Pineapple-style rogue AP: a single BSSID emitting beacons
 * (or probe responses) for many distinct SSIDs. Legitimate APs pick
 * one ESSID and stick to it. Rogue tools (Wifi Pineapple's PineAP,
 * mana, hostapd-wpe) impersonate every SSID a victim probes for, so
 * one MAC ends up advertising 3, 5, 20 different network names.
 *
 * Threshold: KARMA_SSID_THRESH distinct SSIDs from one BSSID, defined
 * in karma_detect.h. False positives are possible (some captive-portal
 * gear cycles SSIDs) but the operator almost always wants to look.
 *
 * The constant used to be defined here as well, with the same value —
 * two definitions of one threshold, either of which could be retuned
 * without the other. Consolidated when #68 needed a third reader. */

/* KARMA_AP severity and confidence (#90). A bare SSID-count crossing
 * KARMA_SSID_THRESH is a *candidate* signal, not a finding on its own:
 * a long-lived AP that legitimately renamed itself a few times over a
 * session racks up the same count as an active PineAP lure. Severity
 * escalates to CRIT only when something ties the pattern to *this*
 * candidate specifically, rather than coincidental global activity:
 *
 *   - one nearby station's PNL asks for at least KARMA_PNL_CORROB_MIN
 *     of the SSIDs this BSSID beacons (the actual PineAP
 *     Beacon-Response mechanism: a lure answers a station's probes for
 *     its whole remembered list). The *union* over all clients is
 *     reported but no longer escalates — a single common name in one
 *     passer-by's list is a fact about the neighbourhood, not about
 *     this radio, and that was the false positive #90 reported — or
 *   - a shared-victim deauth-then-lure chain (karma_deauth_lure_victim,
 *     #90 — ties the flood to a station this candidate can be shown to
 *     be luring, not any unrelated flood in range), or
 *   - a verified (capture-backed) tool signature match.
 *
 * An UNVERIFIED tool guess and an unattributed PMKID are informational:
 * neither corroborates on its own — the tool guess has no capture
 * behind it, and PMKID harvesting is normal in legitimate
 * 802.11r/PMK-caching roaming, not a third-party-listener tell. */
void rule_karma_ap(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->ssid_history_n < KARMA_SSID_THRESH) continue;

        char bssid_str[20];
        snprintf(bssid_str, sizeof(bssid_str),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 a->bssid[0], a->bssid[1], a->bssid[2],
                 a->bssid[3], a->bssid[4], a->bssid[5]);
        /* Union: reported only. Single-station best: the gate. */
        uint8_t pnl_sta[6];
        int overlap    = karma_pnl_union_hits(s, a);
        int pnl_best   = karma_pnl_client_hits(s, a, pnl_sta);
        int pnl_corrob = pnl_best >= KARMA_PNL_CORROB_MIN;
        int deauth     = karma_deauth_lure_victim(s, a, now, NULL);

        /* Has a PMKID been harvested from this BSSID (#68)? Unlike a
         * tool's beacon quirks, this is a *protocol* observable — an AP
         * that solicits PMKIDs is doing something hcxdumptool-shaped
         * regardless of which binary is doing it — so it needs no
         * signature table and ships working. It stays informational
         * (#90): a legitimate 802.11r/PMK-caching exchange produces one
         * too, and a passive listener never reveals itself by doing so.
         *
         * Name the tool when the signature table can. Both shipped rows
         * are UNVERIFIED research rows (see tool_fingerprint.h), so a
         * match here is provisional by construction: it is labelled so
         * in the detail and exported with `validated:false` (#90). */
        int pmkid = 0;
        sloth_tool_conf_t conf = TOOL_CONF_NONE;
        const sloth_tool_sig_t *tool_row = karma_tool_match(s, a, &conf,
                                                            &pmkid);
        int tool_unverified = tool_row && tool_row->unverified;
        int tool_verified   = tool_row && !tool_row->unverified;

        alert_sev_t sev = ALERT_SEV_WARN;
        if (pnl_corrob || deauth || tool_verified) sev = ALERT_SEV_CRIT;

        int confidence = KARMA_W_SSID_THRESH;
        /* Confidence keys on the same measure as severity. Paying the
         * weight for a bare union hit would make a coincidence read as
         * 45% sure of a lure, which is the overstatement this rule is
         * being narrowed to avoid. */
        if (pnl_corrob) confidence += KARMA_W_PNL_OVERLAP;
        if (deauth)     confidence += KARMA_W_DEAUTH_VICTIM;
        if (tool_row)
            confidence += tool_unverified ? KARMA_W_TOOL_UNVERIF
                                          : KARMA_W_TOOL_VERIFIED;
        if (pmkid) confidence += KARMA_W_PMKID;
        if (confidence < KARMA_CONF_MIN) confidence = KARMA_CONF_MIN;
        if (confidence > KARMA_CONF_MAX) confidence = KARMA_CONF_MAX;

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        char pnl_note[64]   = "";
        char chain_note[24] = "";
        char tool_note[56]  = "";
        char pmkid_note[16] = "";
        if (pnl_corrob)   /* implies overlap >= KARMA_PNL_CORROB_MIN */
            /* Name the station that corroborated, so the operator can
             * go look at it in [k] rather than trust the count. */
            snprintf(pnl_note, sizeof(pnl_note),
                     ", %d in client PNLs (%d on "
                     "%02x:%02x:%02x:%02x:%02x:%02x)",
                     overlap, pnl_best, pnl_sta[0], pnl_sta[1], pnl_sta[2],
                     pnl_sta[3], pnl_sta[4], pnl_sta[5]);
        else if (overlap > 0)
            snprintf(pnl_note, sizeof(pnl_note),
                     ", %d in client PNLs", overlap);
        if (deauth)
            snprintf(chain_note, sizeof(chain_note),
                     " +deauth-then-lure");
        if (pmkid)
            snprintf(pmkid_note, sizeof(pmkid_note), " +PMKID");
        if (tool_row) {
            /* "?" plus the word "provisional" flags an UNVERIFIED
             * signature (#90) — rendered by the helper the [y] view
             * uses too, so the two surfaces say the same thing. */
            char attr[48];
            tool_attribution_format(attr, sizeof(attr), tool_row, conf);
            snprintf(tool_note, sizeof(tool_note), " [%s]", attr);
        }
        /* Shared with the dashboard badge, which looks this alert up by
         * key to read its severity (#90). Built in one place so the two
         * cannot drift — see karma_alert_key(). */
        karma_alert_key(a->bssid, key, sizeof(key));
        snprintf(detail, sizeof(detail),
                 "KARMA BSSID %s: %d SSIDs%s%s%s%s, conf %d%%%s",
                 bssid_str, a->ssid_history_n, pnl_note, chain_note,
                 pmkid_note, tool_note, confidence,
                 sev == ALERT_SEV_WARN ? " - candidate, uncorroborated" : "");
        fire_inv(ALERT_TYPE_KARMA_AP, sev, confidence, NULL,
                 TWIN_CLASS_UNKNOWN, WIRED_ATTACH_UNKNOWN, tool_row, NULL, 0,
                 "KARMA_AP", detail, key, NULL, 0, now);
    }
}

/* ── Open device-onboarding SoftAP (#80) ──────────────────
 *
 * An unconfigured consumer/IoT device brings up an *open* SoftAP so a
 * phone can reach its setup surface. Everyone else in RF range can
 * reach that surface too: provision the device onto a network of their
 * choosing, read or rewrite its configuration, or stand up the same
 * SSID and collect the WLAN passphrase the owner types into it.
 *
 * What it is detected *from* — NIST SP 1800-36 (Nov 2025), Volume A:
 * "Wi-Fi is sometimes used to provide credentials over an open (i.e.,
 * unencrypted) network, but this onboarding method risks credential
 * disclosure." The Wi-Fi Easy Connect / DPP programme exists to
 * replace exactly this shape. See
 * research/papers/nist-sp1800-36-onboarding.md.
 *
 * WARN, not CRIT: the observable is an exposure sitting in the open,
 * not an attack under way. Nobody gets paged for a printer.
 *
 * The rule under-flags on purpose. A curated prefix table gated behind
 * a hotspot allowlist will miss vendor SSIDs nobody has written down;
 * the alternative — matching anything that looks setup-shaped — fires
 * on every café in a city and teaches the operator to ignore the type.
 */

static int ascii_lower(int c) {
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

/* Case-insensitive ASCII compares, local rather than strcasecmp /
 * strncasecmp: those are POSIX <strings.h> and this file also builds
 * on the embedded and BSD targets. SSIDs are bytes, not text, so
 * locale-aware folding would be wrong here anyway. */
static int ascii_ieq(const char *a, const char *b) {
    int i = 0;
    for (; a[i] && b[i]; i++)
        if (ascii_lower((unsigned char)a[i]) != ascii_lower((unsigned char)b[i]))
            return 0;
    return a[i] == b[i];
}

/* Stops at the first mismatch, so a `hay` shorter than `prefix` hits
 * its NUL and returns 0 without reading past it. */
static int ascii_iprefix(const char *hay, const char *prefix) {
    for (int i = 0; prefix[i]; i++)
        if (ascii_lower((unsigned char)hay[i]) !=
            ascii_lower((unsigned char)prefix[i])) return 0;
    return 1;
}

static int ascii_icontains(const char *hay, const char *needle) {
    for (int i = 0; hay[i]; i++)
        if (ascii_iprefix(hay + i, needle)) return 1;
    return 0;
}

/* Open by design, and not a device management surface: carrier / ISP
 * roaming SSIDs, venue hotspots, guest VLANs. Prefix-matched because
 * these ship with per-site suffixes ("CoxWiFi_5G", "@Reyee-1234").
 *
 * This list is the guardrail, and it is checked *before* the pattern
 * table so a hotspot can never reach it. */
static const char *const g_open_hotspot_ssids[] = {
    "xfinitywifi",      /* Comcast's public roaming SSID */
    "XFINITY",          /* and its authenticated sibling */
    "attwifi",          /* AT&T Wi-Fi hotspots */
    "CoxWiFi",          /* Cox */
    "Cox Mobile",
    "CableWiFi",        /* the cable operators' shared roaming SSID */
    "optimumwifi",      /* Optimum / Altice */
    "SpectrumWiFi",     /* Charter */
    "Google Starbucks", /* venue hotspot */
    "Boingo",           /* airport / venue aggregator */
    "@Reyee",           /* Reyee / Ruijie mesh guest SSID */
};

static int ssid_is_public_hotspot(const char *ssid) {
    for (size_t i = 0;
         i < sizeof(g_open_hotspot_ssids) / sizeof(g_open_hotspot_ssids[0]);
         i++)
        if (ascii_iprefix(ssid, g_open_hotspot_ssids[i])) return 1;
    /* Guest networks are deliberately open on a great many sites, and
     * they name themselves. A "guest" token anywhere in the SSID is
     * enough to stay quiet — under-flagging is the stated preference. */
    return ascii_icontains(ssid, "guest");
}

/* Onboarding SSID patterns. Small and evidence-based: each row says
 * what the name means and the entry exists because that claim is
 * checkable, not because the shape looked plausible. */
typedef struct {
    const char *prefix;
    const char *what;      /* rendered into the alert detail */
} setup_ssid_pat_t;

static const setup_ssid_pat_t g_setup_ssid_pats[] = {
    /* Generic consumer onboarding SSID — "SETUP-" and a serial
     * fragment. Observed in range on the passive run that motivated
     * #80, alongside the printer and DIRECT- names below. */
    { "SETUP-",           "device setup SSID" },
    /* HP printers advertise "HP-Setup>xx-<model>" until they are joined
     * to a WLAN; HP's own support threads show it listed as unsecured. */
    { "HP-Setup",         "HP printer setup" },
    /* Same family, the print / Wi-Fi Direct SoftAP. */
    { "HP-Print-",        "HP print SoftAP" },
    /* Wi-Fi P2P Technical Specification v1.5 §3.2.1 requires every P2P
     * Group SSID to begin with "DIRECT-" *and* requires WPA2-PSK on the
     * group. An OPEN one is therefore a device operating outside the
     * protection its own spec mandates — which is the finding. */
    { "DIRECT-",          "Wi-Fi Direct group, unprotected" },
    /* Robot vacuum in provisioning mode. */
    { "roborock-vacuum-", "robot vacuum provisioning" },
    /* Range extender that has never been configured. */
    { "NETGEAR_EXT",      "range extender unconfigured" },
};

void rule_open_setup_ap(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];

        /* Hidden / broadcast SSID — no name to match, and nothing an
         * operator could go find in the room. */
        if (!a->ssid[0]) continue;

        /* Unencrypted, or nothing parsed. The beacon parser always
         * fills enc, so empty means the row came from a path that did
         * not decide — the same treatment rule_evil_twin and twins.c
         * already give it. Compared case-insensitively because the
         * managed-scan path renders the value "Open", not "OPEN"
         * (src/platform/linux_wifi.c). */
        if (a->enc[0] && !ascii_ieq(a->enc, "OPEN")) continue;

        /* Guardrail ahead of the pattern match, always. */
        if (ssid_is_public_hotspot(a->ssid)) continue;

        const char *what = NULL;
        for (size_t p = 0;
             p < sizeof(g_setup_ssid_pats) / sizeof(g_setup_ssid_pats[0]);
             p++)
            if (ascii_iprefix(a->ssid, g_setup_ssid_pats[p].prefix)) {
                what = g_setup_ssid_pats[p].what;
                break;
            }
        if (!what) continue;

        char bssid_str[20];
        mac_to_str(a->bssid, bssid_str, sizeof(bssid_str));

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* Per BSSID: a device left in setup mode for an hour is one
         * alert with a rising count, not one per poll. */
        snprintf(key, sizeof(key), "opensetup:%s", bssid_str);
        snprintf(detail, sizeof(detail),
                 "open %s: SSID %.32s BSSID %s ch %d, unauthenticated setup surface",
                 what, a->ssid, bssid_str, a->channel);
        fire(ALERT_TYPE_OPEN_SETUP_AP, ALERT_SEV_WARN,
             "OPEN_SETUP_AP", detail, key, NULL, 0, now);
    }
}

/* ── CAM_SETUP_SSID (#106 slice 2) ──────────────────────────
 *
 * #80 answers "an open SoftAP exists". This answers "a Hikvision
 * camera is still in setup mode", which is the sentence #106 asks for
 * and the one an operator can act on: a camera that has never been
 * joined to a WLAN is also a camera whose admin password has never
 * been changed, and the SoftAP is the surface that reaches it.
 *
 * Deliberately NOT gated on OPEN, unlike rule_open_setup_ap. The two
 * largest vendors' setup APs are WPA-protected, so an OPEN gate would
 * make the issue's own headline case unreachable: Hikvision's `HAP_`
 * AP wants the last 8 characters of the serial number, which is
 * printed on the device label the camera is mounted on, and EZVIZ's
 * wants the verification code from the same label. A key that ships
 * on the outside of the chassis is not a key. What this rule reports
 * is the provisioning *state*, with the encryption recorded in the
 * detail so the operator can tell the two situations apart rather
 * than having the rule decide for them.
 *
 * Additive to OPEN_SETUP_AP: that rule's table and this one share no
 * prefix today, so in practice they fire on disjoint sets — but
 * neither suppresses the other, and a future SSID matching both
 * should produce both rows (the generic one is the audit trail, the
 * camera one is the finding).
 *
 * Every row cites the vendor's own onboarding documentation — see
 * research/papers/camera-setup-softap.md. Rows whose SSID shape could
 * not be sourced to a vendor document were left out rather than
 * guessed; see that document's "considered and not shipped" section.
 */
typedef struct {
    const char *prefix;
    const char *vendor;    /* rendered into the alert detail */
} cam_setup_ssid_pat_t;

static const cam_setup_ssid_pat_t g_camera_setup_ssid_pats[] = {
    /* "Hikvision Access Point". SSID is HAP_ + the verification code
     * from the device label; the AP key is the last 8 characters of
     * the serial number, also on the label. */
    { "HAP_",      "Hikvision camera" },
    /* "Dahua Access Point", DAP-<serial fragment>. Amcrest is a Dahua
     * OEM and uses the same prefix (DAP-AMC...), so one row covers
     * both brands — which is why the label says the OEM, not Amcrest. */
    { "DAP-",      "Dahua/Amcrest camera" },
    /* EZVIZ is Hikvision's consumer brand; AP mode broadcasts
     * EZVIZ_<9-digit serial>, keyed on the label's verification code. */
    { "EZVIZ_",    "EZVIZ camera" },
    /* TP-Link Tapo camera setup SoftAP: Tapo_Cam_<last 4 of MAC>.
     * Prefix includes the trailing underscore so it cannot collide
     * with a Tapo plug or bulb, which are not cameras. */
    { "Tapo_Cam_", "TP-Link Tapo camera" },
};

void rule_cam_setup_ssid(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];

        /* Hidden / broadcast SSID — no name to match. */
        if (!a->ssid[0]) continue;

        /* Guardrail ahead of the pattern match, always — same ordering
         * rule_open_setup_ap uses.
         *
         * It DOES change current outcomes, four of them, and an earlier
         * version of this comment said otherwise. ssid_is_public_hotspot()
         * matches on the substring `guest`, not only on a closed list of
         * hotspot names, so any camera setup SSID containing it is
         * suppressed today — review proved it by deleting this line and
         * watching four cases go red. That is a live false-NEGATIVE path,
         * not a placeholder for future rows: a vendor shipping
         * `HAP_guest…` would be invisible.
         *
         * Kept in this order anyway, and the trade stated rather than
         * hidden: an SSID a human called "guest" is a network someone
         * intended to be open, and firing a camera-exposure WARN on it
         * is the kind of noise that teaches an operator to mute the
         * type. Narrowing the `guest` branch so a vendor prefix wins
         * over it is a change to shared hotspot logic that
         * rule_open_setup_ap also depends on, so it belongs in its own
         * slice rather than here. */
        if (ssid_is_public_hotspot(a->ssid)) continue;

        const char *vendor = NULL;
        for (size_t p = 0;
             p < sizeof(g_camera_setup_ssid_pats) /
                 sizeof(g_camera_setup_ssid_pats[0]);
             p++)
            if (ascii_iprefix(a->ssid, g_camera_setup_ssid_pats[p].prefix)) {
                vendor = g_camera_setup_ssid_pats[p].vendor;
                break;
            }
        if (!vendor) continue;

        char bssid_str[20];
        mac_to_str(a->bssid, bssid_str, sizeof(bssid_str));

        /* Reported, not judged. An empty enc means the path that
         * produced the row did not decide — not that the AP is open —
         * so it reads "unknown" rather than implying either answer,
         * and a protected setup AP names its cipher rather than
         * carrying a claim about where its key is printed (that is
         * per-vendor, and belongs in the rule's doc row). */
        char encdesc[32];
        if (!a->enc[0])
            snprintf(encdesc, sizeof(encdesc), "enc unknown");
        else if (ascii_ieq(a->enc, "OPEN"))
            snprintf(encdesc, sizeof(encdesc), "OPEN, unauthenticated");
        else
            snprintf(encdesc, sizeof(encdesc), "enc %.12s", a->enc);

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* Per BSSID, same reasoning as opensetup: a camera left in
         * setup mode is one alert with a rising count. */
        snprintf(key, sizeof(key), "camsetup:%s", bssid_str);
        /* "advertising its setup SSID", not "in setup mode" and not
         * "not yet joined to a WLAN". The only input is an SSID prefix
         * on a beacon; nothing here observes whether the camera is
         * provisioned, and a configured device can advertise this name
         * after a factory reset, during a re-pair, or because its
         * installer left the AP enabled. The same issue's
         * CAM_WS_DISCOVERY row one slice earlier explicitly refused the
         * equivalent claim, and #90 is open about exactly this class of
         * overstatement — so the detail reports the observable and lets
         * the operator draw the inference. */
        snprintf(detail, sizeof(detail),
                 "%s advertising its documented setup SSID: %.32s"
                 " BSSID %s ch %d, %s"
                 " (provisioning state not observed)",
                 vendor, a->ssid, bssid_str, a->channel, encdesc);
        fire(ALERT_TYPE_CAM_SETUP_SSID, ALERT_SEV_WARN,
             "CAM_SETUP_SSID", detail, key, NULL, 0, now);
    }
}

/* Evil-twin AP: same SSID broadcast under more than one BSSID, where
 * one of the BSSIDs has weak/no security (OPEN, WEP) and another has
 * strong security (WPA / WPA2 / WPA3). This is the classic credential
 * harvesting setup — a rogue AP impersonating the real network on an
 * open channel so victims joining the "right name" get MITM'd.
 *
 * Legitimate mesh / enterprise deployments where all BSSIDs share the
 * same security level produce no alert. */
static int enc_is_weak(const char *enc) {
    return strcmp(enc, "OPEN") == 0 || strcmp(enc, "WEP") == 0;
}
static int enc_is_strong(const char *enc) {
    return strcmp(enc, "WPA")  == 0 || strcmp(enc, "WPA2") == 0 ||
           strcmp(enc, "WPA3") == 0;
}

void rule_evil_twin(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (!a->ssid[0]) continue;      /* hidden -> can't correlate */

        /* CRIT branch — classic weak-vs-strong twin (OPEN/WEP next to
         * WPA/WPA2/WPA3 under the same SSID). Asymmetric: only walks
         * from the weak side, one fire per weak BSSID. */
        if (enc_is_weak(a->enc)) {
            for (int j = 0; j < s->beacon_count; j++) {
                if (i == j) continue;
                const beacon_ap_t *b = &s->beacon_aps[j];
                if (strcmp(a->ssid, b->ssid) != 0) continue;
                if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
                if (!enc_is_strong(b->enc)) continue;

                char a_bssid[20], b_bssid[20];
                fmt_bssid(a_bssid, a->bssid);
                fmt_bssid(b_bssid, b->bssid);
                char key[ALERT_KEY_LEN];
                char detail[ALERT_DETAIL_LEN];
                /* Already CRIT, so the marker only annotates here —
                 * but naming the steering AP is the actionable half:
                 * the operator learns which radio is pushing clients
                 * at the rogue, not just that a rogue exists. */
                char steer_note[40] = "";
                int steer = btm_steered_to(s, a->bssid, now);
                if (steer < 0) steer = btm_steered_to(s, b->bssid, now);
                if (steer >= 0) {
                    char steerer[20];
                    mac_to_str(s->btm_steers[steer].bssid, steerer,
                               sizeof(steerer));
                    snprintf(steer_note, sizeof(steer_note),
                             " +btm-steered by %.17s", steerer);
                }
                /* Canonical pair key (#89): before this, every pair
                 * under one SSID collapsed onto `twin:<ssid>`, so a
                 * second OPEN clone of one protected name overwrote the
                 * first one's detail instead of standing beside it. */
                const beacon_ap_t *lo = NULL, *hi = NULL;
                twin_pair_order(a, b, &lo, &hi);
                char profile[24];
                twin_profile(profile, sizeof(profile), lo, hi);
                alert_pair_key(key, sizeof(key), "twin", a->bssid, b->bssid,
                               inventory_site(), profile);

                /* An OPEN/WEP clone of a protected SSID has no
                 * vendor-diversity explanation, so this branch starts
                 * from a high base — but it is still an inference from
                 * beacons, so it is reported as suspected with a
                 * confidence, not as established fact. */
                twin_evidence_t ev;
                twin_evidence_score(s, a, b, now, &ev);
                int conf = clamp_conf(TWIN_W_WEAK_CLONE + ev.positive -
                                      ev.context);
                char note[64];
                twin_evidence_note(note, sizeof(note), &ev);

                /* Both radios declared by the operator (#89 slice 2).
                 * That is not an impersonation — but unlike the
                 * same-security branch it is not nothing either: an
                 * OPEN BSS beside a protected one under a single name
                 * is a downgrade lane whoever owns it. So the finding
                 * is demoted and relabelled rather than withdrawn. The
                 * inventory answers "whose radio is that", never "is
                 * that configuration safe". */
                alert_sev_t sev = ALERT_SEV_CRIT;
                const char *verdict = "suspected impersonation";
                if (ev.inv_approved) {
                    sev     = ALERT_SEV_WARN;
                    verdict = "inventory-approved pair, weak/strong split";
                }
                /* The two pair axes (#89 slice 3). `wired` is asked
                 * only of the half something has accused, and is
                 * UNKNOWN for every row until a correlator that can see
                 * the wire is registered — RF cannot establish it. */
                twin_class_t   cls   = twin_classify(&ev);
                wired_attach_t wired = twin_accused_wired(a, b);
                char cls_note[28];
                twin_pair_axes_note(cls_note, sizeof(cls_note), cls, wired);
                snprintf(detail, sizeof(detail),
                         "'%.16s' on %s[%.6s] AND %s[%.6s]"
                         " - %s, conf %d%%%s%s%s",
                         a->ssid, a_bssid, a->enc, b_bssid, b->enc,
                         verdict, conf, note, steer_note, cls_note);
                fire_inv(ALERT_TYPE_EVIL_TWIN, sev, conf,
                         inventory_hash(), (int)cls, (int)wired, NULL, NULL, 0,
                         "EVIL_TWIN", detail, key, NULL, 0, now);
                break;
            }
        }

        /* Same-security branch — same SSID, same cipher, weighted
         * evidence. Catches the modern Pineapple / ESP32 evil-twin
         * pattern where the attacker mirrors the legit AP's security to
         * defeat the weak/strong mismatch check above.
         *
         * #89 removed the two sole suppressors this branch used to open
         * with, and that is the substance of the change:
         *
         *   - A matching vendor OUI used to `continue` before any other
         *     evidence was read. An OUI is three bytes of a frame the
         *     attacker writes; every rogue-AP tool can set them. The
         *     pair is now scored, and a same-OUI pair whose vendor-IE
         *     fingerprints contradict each other fires.
         *   - An 802.11k neighbour report from *either* side used to
         *     `continue` as well, on the reading that the deployment was
         *     asserting membership (#51). Nothing authenticates that
         *     assertion: an attacker advertises the AP it is
         *     impersonating and the finding disappeared. It is now a
         *     confidence deduction that can demote a soft-signal
         *     severity and nothing more.
         *
         * What replaces them is a requirement for *positive* evidence
         * (twin_evidence_score returns 0 without it), so a legitimate
         * single-vendor multi-BSSID deployment stays quiet because there
         * is nothing to report — not because any observed value was
         * taken as proof of ownership.
         *
         * Skip OPEN — legit OPEN networks at airports / cafes routinely
         * present same-SSID-different-OUI siblings (multi-vendor hotspot
         * deployments), and there's no shared secret to defend, so the
         * twin signal is meaningless. */
        if (!a->enc[0] || strcmp(a->enc, "OPEN") == 0) continue;
        for (int j = i + 1; j < s->beacon_count; j++) {
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (strcmp(a->ssid, b->ssid) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (strcmp(a->enc, b->enc) != 0) continue;

            twin_evidence_t ev;
            if (!twin_evidence_score(s, a, b, now, &ev)) continue;

            char a_bssid[20], b_bssid[20];
            fmt_bssid(a_bssid, a->bssid);
            fmt_bssid(b_bssid, b->bssid);

            alert_sev_t sev = ALERT_SEV_WARN;
            const char *reason = ev.diff_oui ? "vendor OUI differs"
                                             : "same vendor OUI";
            /* Both sides emitted a usable vendor hash and they disagree
             * → firmware mismatch. Legit dual-vendor co-located mesh is
             * vanishingly rare; raise to CRIT. Soft: forgeable in
             * principle, so a neighbour claim may demote it below. */
            if (ev.hashes_differ) {
                sev    = ALERT_SEV_CRIT;
                reason = "vendor-IE fingerprint differs";
            }
            /* Attacker-OUI bump — one tier higher. WARN→CRIT; CRIT
             * stays at CRIT. Hard: an attacker does not get to advertise
             * its way out of having been identified as a rogue-AP tool. */
            if (ev.attacker_oui) {
                if (sev < ALERT_SEV_CRIT) sev = ALERT_SEV_CRIT;
                reason = "attacker-tool OUI present";
            }
            /* The approved inventory outranks every observed signal as
             * the stated reason, because it is the only one the
             * operator can be held to. It is also the only way the
             * same-OUI clone in this issue's regression list is
             * visible at all: three matching bytes and nothing else is
             * an empty evidence set, not an accusation. */
            if (ev.inv_mismatch) {
                sev    = ALERT_SEV_CRIT;
                reason = "BSSID not in the approved inventory";
            }

            /* #76's chain, as a marker. A twin a BTM Request actively
             * steered a client toward under Disassociation Imminent is
             * not an ambiguous same-SSID sighting — it is a rogue with
             * traffic being pushed at it, so the marker escalates as
             * well as annotates. That escalation is the whole value of
             * the chain, delivered without a separate alert. */
            char steer_note[40] = "";
            int steer_a = btm_steered_to(s, a->bssid, now);
            int steer_b = btm_steered_to(s, b->bssid, now);
            int steer = steer_a >= 0 ? steer_a : steer_b;
            if (steer >= 0) {
                char steerer[20];
                mac_to_str(s->btm_steers[steer].bssid, steerer,
                           sizeof(steerer));
                snprintf(steer_note, sizeof(steer_note),
                         " +btm-steered by %.17s", steerer);
                if (sev < ALERT_SEV_CRIT) sev = ALERT_SEV_CRIT;
            }

            /* A neighbour claim is one unauthenticated frame. It lowers
             * confidence always (already folded into ev.confidence), and
             * it demotes a severity resting only on soft signals — but
             * never one backed by a hard signal, or advertising your
             * target becomes a severity lever for the attacker. */
            if (ev.nbr_claim && !ev.hard && sev > ALERT_SEV_WARN)
                sev = ALERT_SEV_WARN;

            char key[ALERT_KEY_LEN];
            char detail[ALERT_DETAIL_LEN];
            char note[64];
            /* Canonical pair key (#89). `twin-fp` stays the rule id so
             * the CRIT `twin` key for the same pair still coexists, but
             * the identity is now the ordered BSSID pair rather than the
             * SSID — two candidate pairs under one name both survive
             * instead of overwriting each other in one engine slot. */
            const beacon_ap_t *lo = NULL, *hi = NULL;
            twin_pair_order(a, b, &lo, &hi);
            char profile[24];
            twin_profile(profile, sizeof(profile), lo, hi);
            alert_pair_key(key, sizeof(key), "twin-fp", a->bssid, b->bssid,
                           inventory_site(), profile);
            twin_evidence_note(note, sizeof(note), &ev);
            /* The two pair axes (#89 slice 3) — see the weak/strong
             * branch above. `wired` stays UNKNOWN here too until
             * something that can see the wire answers. */
            twin_class_t   cls   = twin_classify(&ev);
            wired_attach_t wired = twin_accused_wired(a, b);
            char cls_note[28];
            twin_pair_axes_note(cls_note, sizeof(cls_note), cls, wired);
            snprintf(detail, sizeof(detail),
                     "'%.16s' on %s AND %s [%.6s]"
                     " - suspected impersonation, conf %d%% - %s%s%s%s",
                     a->ssid, a_bssid, b_bssid, a->enc,
                     ev.confidence, reason, note, steer_note, cls_note);
            fire_inv(ALERT_TYPE_EVIL_TWIN, sev, ev.confidence,
                     inventory_hash(), (int)cls, (int)wired, NULL, NULL, 0,
                     "EVIL_TWIN", detail, key, NULL, 0, now);
            break;
        }
    }
}

/* SSID Confusion / RSN-downgrade twin — CVE-2023-52424 (issue #32).
 *
 * The SSID is not bound into PMK derivation, so a rogue AP can spoof a
 * trusted network name while advertising a *weaker* RSN posture and the
 * client will still associate. The on-air fingerprint is a downgrade
 * delta: the same SSID appearing on a second BSSID with weaker crypto
 * than the strongest posture we've seen for that SSID. A legit
 * multi-VAP controller does NOT downgrade its own security across
 * BSSIDs for the same SSID, so this is high-signal.
 *
 * Complementary to rule_evil_twin: that rule keys on OPEN/WEP-vs-strong
 * (weak side unprotected) and on same-cipher-different-OUI. This rule
 * keys on the subtler RSN-posture downgrade between two *protected*
 * BSSIDs — WPA3->WPA2, MFP required->off, GCMP->CCMP — which the twin
 * rule's equal-cipher requirement steps over.
 *
 * Baseline note: the CVE-2023-52424 research gates on a multi-hour SSID
 * baseline + BSSID age. Sloth has no persistent cross-session AKM
 * baseline yet (that is the follow-on to the session baseline in #23),
 * so this rule scores the downgrade against the strongest posture in
 * the *current* beacon snapshot. Age/baseline gating is deferred. */

/* WPA generation rank — higher is stronger. OPEN/unknown = 0. */
static int wpa_gen_rank(const char *enc) {
    if (strcmp(enc, "WPA3") == 0) return 4;
    if (strcmp(enc, "WPA2") == 0) return 3;
    if (strcmp(enc, "WPA")  == 0) return 2;
    if (strcmp(enc, "WEP")  == 0) return 1;
    return 0;
}

/* Downgrade score of `weak` relative to `strong` (same SSID). Positive
 * means `weak` is a security downgrade of `strong`. Weights follow the
 * CVE-2023-52424 write-up. */
static int rsn_downgrade_score(const beacon_ap_t *strong,
                               const beacon_ap_t *weak) {
    int score = 0;
    int gs = wpa_gen_rank(strong->enc);
    int gw = wpa_gen_rank(weak->enc);
    /* Weak side must still be a protected WPA network. OPEN/WEP as the
     * weak side is rule_evil_twin's territory — and an unprotected AP
     * trivially has mfp=0 / no cipher, which would otherwise inflate the
     * MFP/cipher deltas below into a false SSID-confusion hit. */
    if (gw < 2) return 0;
    /* Generational drop among protected networks (WPA3->WPA2 etc.). */
    if (gs > gw) score += 3;
    /* Management-frame-protection downgrade. */
    if (strong->mfp == 2 && weak->mfp == 1) score += 2;   /* required -> capable */
    if (strong->mfp == 2 && weak->mfp == 0) score += 4;   /* required -> disabled */
    if (strong->mfp == 1 && weak->mfp == 0) score += 2;   /* capable  -> disabled */
    /* Pairwise-cipher downgrade. */
    if (strncmp(strong->pairwise, "GCMP", 4) == 0 &&
        (strcmp(weak->pairwise, "CCMP") == 0 ||
         strcmp(weak->pairwise, "TKIP") == 0)) score += 1;
    if (strcmp(strong->pairwise, "CCMP") == 0 &&
        strcmp(weak->pairwise, "TKIP") == 0)     score += 1;
    /* Enterprise (802.1X) AKM downgraded to a pre-shared-key AKM under
     * the same SSID — the eaphammer / hostapd-wpe rogue-RADIUS lure
     * fingerprint (#31's same_ssid_alt_akm sub-signal). Fires even when
     * the enc generation matches (WPA2-Enterprise cloned as WPA2-PSK),
     * which the generational check above misses. The deeper EAP
     * inner-method / server-cert fingerprinting is a follow-on. */
    if (strstr(strong->akm, "802.1X") && weak->akm[0] &&
        !strstr(weak->akm, "802.1X")) score += 3;
    return score;
}

#define SSID_CONFUSION_THRESH ((int)tune_val(TUNE_SSID_CONFUSION_THRESH))

void rule_ssid_confusion(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *weak = &s->beacon_aps[i];
        if (!weak->ssid[0]) continue;           /* hidden -> can't correlate */

        /* Find the strongest same-SSID sibling and score the downgrade
         * of `weak` against it. Fire once per (SSID, weak BSSID). */
        int best_score = 0;
        const beacon_ap_t *strong_hit = NULL;
        for (int j = 0; j < s->beacon_count; j++) {
            if (i == j) continue;
            const beacon_ap_t *strong = &s->beacon_aps[j];
            if (strcmp(weak->ssid, strong->ssid) != 0) continue;
            if (memcmp(weak->bssid, strong->bssid, 6) == 0) continue;
            int sc = rsn_downgrade_score(strong, weak);
            if (sc > best_score) { best_score = sc; strong_hit = strong; }
        }
        if (best_score < SSID_CONFUSION_THRESH || !strong_hit) continue;

        char w_bssid[20], s_bssid[20];
        fmt_bssid(w_bssid, weak->bssid);
        fmt_bssid(s_bssid, strong_hit->bssid);
        /* SSID is attacker-chosen in exactly this attack (#112): a
         * remote component, so a 30-byte shared prefix is no longer
         * one finding. */
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "ssidconf");
        akey_remote(&k, weak->ssid, 32);
        akey_mac(&k, weak->bssid);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "'%.16s' downgraded on %s [%.6s/mfp%d] vs %s [%.6s/mfp%d] - SSID confusion",
                 weak->ssid, w_bssid, weak->enc, weak->mfp,
                 s_bssid, strong_hit->enc, strong_hit->mfp);
        fire(ALERT_TYPE_SSID_CONFUSION, ALERT_SEV_CRIT,
             "SSID_CONFUSION", detail, key, NULL, 0, now);
    }
}

/* Evil-twin proximity — Phase 3. A single BSSID whose RSSI jumps
 * ≥15 dBm within the 60s sliding window (no roam — same BSSID, same
 * channel) is a strong tell for either (a) an attacker AP moving
 * closer/being switched on nearby, or (b) signal-level deception. We
 * fire at WARN: it's noisy on its own (mobile devices roaming past
 * the sniffer also cause big swings), but combined with a twin-fp
 * alert it's a strong attack-in-progress signal that Phase 4 will
 * correlate. */
#define EVIL_TWIN_PROXIMITY_DBM ((int)tune_val(TUNE_EVIL_TWIN_PROXIMITY_DBM))

void rule_evil_twin_proximity(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        /* 0 in either bound means "no signal yet" — the ring hasn't
         * accumulated samples or all samples aged out. Don't fire. */
        if (a->rssi_min_60s == 0 || a->rssi_max_60s == 0) continue;
        int delta = a->rssi_max_60s - a->rssi_min_60s;
        if (delta < EVIL_TWIN_PROXIMITY_DBM) continue;

        char bssid[20];
        fmt_bssid(bssid, a->bssid);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "twin-prox:%s", bssid);
        snprintf(detail, sizeof(detail),
                 "%s '%.16s' RSSI swing %d dBm (%d → %d) in 60s",
                 bssid, a->ssid, delta,
                 (int)a->rssi_min_60s, (int)a->rssi_max_60s);
        fire(ALERT_TYPE_EVIL_TWIN_PROXIMITY, ALERT_SEV_WARN,
             "EVIL_TWIN_PROXIMITY", detail, key, NULL, 0, now);
    }
}

/* Evil-twin attack-chain correlation — Phase 4. When a same-cipher
 * twin-fp pair is present AND a recent DEAUTH_FLOOD targets one half
 * within DEAUTH_TWIN_WIN_SECS, conclude the deauthed AP is the legit
 * one (the attacker is driving clients away from it) and the OTHER
 * half is the rogue. Fire EVIL_TWIN at CRIT with "attack-in-progress"
 * and mark the rogue's BSSID as tainted so subsequent EAPOL captures
 * against it get a provenance marker in the .22000 export.
 *
 * Same-cipher pair criteria mirror the WARN branch in rule_evil_twin.
 * We deliberately re-derive them rather than tracking pairs separately
 * — the cost is one extra O(n²) walk per poll over MAX_BEACON_APS=256,
 * which is fine at ≈1 Hz. */
#define DEAUTH_TWIN_WIN_SECS ((int)tune_val(TUNE_DEAUTH_TWIN_WIN_SECS))

void rule_evil_twin_attack_chain(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (!a->ssid[0]) continue;
        if (!a->enc[0] || strcmp(a->enc, "OPEN") == 0) continue;
        /* Is BSSID `a` currently being deauth-flooded? */
        int deauthed = 0;
        for (int k = 0; k < s->deauth_victim_count; k++) {
            const deauth_victim_t *v = &s->deauth_victims[k];
            if (!v->flood || !v->flood_last) continue;
            if (memcmp(v->bssid, a->bssid, 6) != 0) continue;
            if (now - v->flood_last > DEAUTH_TWIN_WIN_SECS) continue;
            deauthed = 1;
            break;
        }
        if (!deauthed) continue;
        /* Find a same-SSID + same-cipher + diff-OUI sibling — that's
         * the rogue half. Loop covers both i<j and j<i so a deauth
         * targeting either AP picks up its twin partner. */
        for (int j = 0; j < s->beacon_count; j++) {
            if (i == j) continue;
            const beacon_ap_t *b = &s->beacon_aps[j];
            if (strcmp(a->ssid, b->ssid) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 6) == 0) continue;
            if (strcmp(a->enc, b->enc) != 0) continue;
            if (memcmp(a->bssid, b->bssid, 3) == 0) continue;

            taint_mark(b->bssid, now);

            char a_bssid[20], b_bssid[20];
            fmt_bssid(a_bssid, a->bssid);
            fmt_bssid(b_bssid, b->bssid);
            /* The SSID is the one thing a twin copies on purpose
             * (#112): a remote component, sanitised and hashed whole. */
            char key[ALERT_KEY_LEN];
            char detail[ALERT_DETAIL_LEN];
            akey_t k;
            akey_begin(&k, key, sizeof(key), "twin-chain");
            akey_remote(&k, a->ssid, 32);
            if (!akey_end(&k)[0]) break;
            snprintf(detail, sizeof(detail),
                     "'%.16s' attack-in-progress: real=%s twin=%s [%.6s]",
                     a->ssid, a_bssid, b_bssid, a->enc);
            fire(ALERT_TYPE_EVIL_TWIN, ALERT_SEV_CRIT,
                 "EVIL_TWIN", detail, key, NULL, 0, now);
            break;
        }
    }
}
