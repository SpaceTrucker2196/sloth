#ifndef ALERTS_H
#define ALERTS_H

#include "sloth.h"

/* Walk the current state for trigger conditions, dedupe against any
 * previously-fired alerts, and copy the resulting set into s->alerts.
 * Safe to call once per poll. */
void alerts_update(sloth_state_t *s);

/* Drop all known alerts (clears engine state, not just the snapshot). */
void alerts_clear(void);

/* ── Tainted-BSSID tracker (evil-twin Phase 4) ─────────────────
 *
 * Maintained by rule_evil_twin_attack_chain when it correlates a
 * twin-fp pair with a DEAUTH_FLOOD targeting one half. The other
 * half (the rogue) is recorded here so downstream forensic exports
 * — currently the hashcat .22000 EAPOL writer — can mark the
 * provenance of any subsequent handshake against the tainted BSSID.
 *
 * Entries expire after EVIL_TWIN_TAINT_TTL_SECS. The tracker is
 * read-only outside alerts.c; the API is exposed here so eapol_log.c
 * can query it without taking a dep on alert internals. */
#define EVIL_TWIN_TAINT_TTL_SECS 300

int  evil_twin_bssid_is_tainted(const uint8_t bssid[6]);
/* Test-only: drop all tainted entries. */
void evil_twin_taint_clear(void);
/* Test-only: mark a BSSID tainted with the current wall clock — gives
 * tests a way to exercise downstream code paths (eapol provenance,
 * Twins view glyphs) without driving the full chain rule. */
void evil_twin_taint_mark_for_test(const uint8_t bssid[6]);

/* ── Canonical pair key (#89) ──────────────────────────────────
 *
 * Two APs are one finding whichever of them sloth heard first, so the
 * dedup key is built from the *pair*, not from the SSID. Before #89
 * every BSSID pair under one SSID collapsed onto `twin:<ssid>` /
 * `twin-fp:<ssid>`, so a second candidate pair on the same name
 * overwrote the first one's detail instead of standing beside it.
 *
 * Shape: `<rule_id>:<bssid_lo>:<bssid_hi>:<site>:<security_profile>`,
 * BSSIDs in memcmp order so (A,B) and (B,A) produce one key. Shares
 * the engine's dedup/incident keying from #98 — there is one keying
 * scheme in this file, not two.
 *
 * `site` is the operator's inventory label and is empty until the JSON
 * inventory lands (#89 slice 2). It must NEVER be derived from an
 * observed SSID or BSSID: a trust input taken from unauthenticated
 * over-the-air data is the whole bug class #89 exists to remove. */
#define TWIN_SITE_UNSET ""

void alert_pair_key(char *out, size_t n, const char *rule_id,
                    const uint8_t bssid_a[6], const uint8_t bssid_b[6],
                    const char *site, const char *security_profile);

/* ── Weighted twin evidence (#89) ──────────────────────────────
 *
 * Every signal below is *context*. None of them removes a finding on
 * its own, which is precisely what an 802.11k neighbour report and a
 * matching vendor OUI used to do: a neighbour advertisement is an
 * unauthenticated frame, so an attacker could name the AP it was
 * impersonating and erase the finding outright, and a clone can copy
 * an OUI in one line of config.
 *
 * `positive` is impersonation evidence; `context` is benign
 * explanation, subtracted from confidence. The pair is a candidate
 * when `positive` is non-zero — a same-OUI pair with nothing else is
 * not *trusted*, it is evidence-free, which is how a legitimate
 * multi-BSSID deployment stays quiet without any observed value being
 * treated as proof of ownership.
 *
 * `hard` marks a signal an attacker cannot advertise away (an
 * attacker-tool OUI, a BTM steer aimed at the pair). A neighbour claim
 * may demote a severity that rests only on soft signals; it may never
 * demote one backed by a hard signal, or advertising your target
 * becomes a severity lever.
 *
 * `confidence` is how sure sloth is, in percent, clamped to
 * [TWIN_CONF_MIN, TWIN_CONF_MAX]. It is never 100 and it is *not* the
 * severity: severity is how bad the finding is if true, confidence is
 * how likely it is to be true. They are different numbers that move
 * independently and the operator needs both. */
#define TWIN_W_DIFF_OUI      20   /* cross-vendor: weak, and forgeable */
#define TWIN_W_IE_HASH       35   /* vendor-IE fingerprints disagree */
#define TWIN_W_ATTACKER_OUI  40   /* Hak5 / Espressif OUI present */
#define TWIN_W_BTM_STEER     25   /* 802.11v steer aimed at the pair */
#define TWIN_W_WEAK_CLONE    85   /* OPEN/WEP beside strong under one SSID —
                                   * no vendor-diversity explanation exists */
#define TWIN_C_NBR_CLAIM     30   /* 802.11k neighbour claim — unauthenticated */
#define TWIN_C_SAME_OUI      15   /* same vendor, or a copied OUI */
#define TWIN_CONF_MIN         5
#define TWIN_CONF_MAX        95

typedef struct {
    int diff_oui;
    int same_oui;
    int hashes_differ;
    int attacker_oui;
    int steered;
    int nbr_claim;       /* either side advertises the other (802.11k) */
    int positive;        /* summed impersonation evidence */
    int context;         /* summed benign explanation */
    int hard;            /* a signal an attacker cannot advertise away */
    int confidence;      /* percent, TWIN_CONF_MIN..TWIN_CONF_MAX */
} twin_evidence_t;

/* Score a same-SSID AP pair. Returns 1 when the pair is a candidate
 * (`positive` non-zero), 0 when there is no impersonation evidence.
 * `out` is always filled when non-NULL. */
int  twin_evidence_score(const sloth_state_t *s, const beacon_ap_t *a,
                         const beacon_ap_t *b, time_t now,
                         twin_evidence_t *out);

/* Deterministic pair ordering — memcmp on the BSSID. Shared so the
 * alert key, the Twins view and the `twin_episodes` primary key all
 * order a pair the same way. */
void twin_pair_order(const beacon_ap_t *a, const beacon_ap_t *b,
                     const beacon_ap_t **lo, const beacon_ap_t **hi);

/* ── KARMA_AP confidence (#90) ──────────────────────────────
 *
 * A bare SSID count crossing KARMA_SSID_THRESH is a candidate signal,
 * not a finding: a long-lived AP that legitimately renamed itself a
 * few times over a session accumulates the same count as an active
 * PineAP lure. Severity therefore escalates to CRIT only when
 * something ties the pattern to this *specific* candidate rather than
 * coincidence — see rule_karma_ap() in alerts.c for which signals
 * qualify. `confidence` is the separate, non-gating number: how sure
 * sloth is, not how bad it would be if true. */
#define KARMA_W_SSID_THRESH   20   /* base: SSID count met the threshold */
#define KARMA_W_PNL_OVERLAP   25   /* advertised SSID answers a nearby PNL */
#define KARMA_W_DEAUTH_VICTIM 30   /* shared-victim deauth-then-lure chain */
#define KARMA_W_TOOL_VERIFIED 30   /* a capture-backed tool signature match */
#define KARMA_W_TOOL_UNVERIF  10   /* an UNVERIFIED signature guess only */
#define KARMA_W_PMKID         10   /* PMKID observed — informational, not
                                    * an attack implication: legitimate
                                    * 802.11r/PMK-caching also produces one */
#define KARMA_CONF_MIN         5
#define KARMA_CONF_MAX        95

#endif /* ALERTS_H */
