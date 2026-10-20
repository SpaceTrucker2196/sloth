/* Enterprise-authentication rules: a rogue RADIUS server, PEAP with no
 * server certificate, and the WPS attack verdicts (PIN brute force,
 * lockout cycling, PBC race, and the two Pixie-Dust rules) with their
 * --tune accessors.
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "alerts.h"
#include "tune.h"   /* operator-tunable thresholds (#82) */
#include "beacon_snoop.h"
#include "ownership.h"
#include "wps_track.h"
#include "alert_key.h"
#include "rules.h"
#include "engine_internal.h"

/* ── WPS attack rules (#82 wave 8) ─────────────────────────
 *
 * Waves 6 and 7 shipped the measurement and deliberately stopped
 * short of the verdicts, because the thresholds were the owner's call
 * and an ALERT_TYPE_* without a research-corpus source turns
 * test_every_citable_alert_kind_is_cited red. Both are settled now
 * (owner decision 2026-09-30; research/cert/vu-723755.md), so the
 * rules land here, reading substrate that is already on file.
 *
 * All three are knobbed — see the WPS_* block in alerts.h for the
 * mechanism and for why the counts are tunable and the windows are
 * not. The current values live behind accessors rather than being
 * read as constants, so a rule cannot quietly ignore an override. */

/* These three were module statics until 2026-10-05. They now read and
 * write the --tune registry instead, so there is one source of truth
 * for every detector threshold rather than two mechanisms answering the
 * same owner decision. The accessor/setter signatures are unchanged, so
 * --wps-pin-brute-cycles and friends keep working exactly as shipped.
 *
 * The bug this closes is not tidiness. A threshold moved through the
 * old statics reached no export at all, so `--wps-pin-brute-cycles 900`
 * silenced WPS_PIN_BRUTE while sensor_health still read tuned_count 0
 * and the health strip showed nothing — a detuned sensor
 * indistinguishable from a quiet one, which is the exact confusion
 * `tuned` was added to resolve. Routing them through the registry means
 * either spelling is recorded. */
int alerts_set_wps_pin_brute_cycles(int cycles) {
    return tune_set_id(TUNE_WPS_PIN_BRUTE_CYCLES, cycles);
}
int alerts_set_wps_lockout_cycles(int cycles) {
    return tune_set_id(TUNE_WPS_LOCKOUT_CYCLES, cycles);
}
int alerts_set_wps_pbc_concurrent(int sessions) {
    return tune_set_id(TUNE_WPS_PBC_CONCURRENT, sessions);
}
int alerts_wps_pin_brute_cycles(void) {
    return (int)tune_val(TUNE_WPS_PIN_BRUTE_CYCLES);
}
int alerts_wps_lockout_cycles(void) {
    return (int)tune_val(TUNE_WPS_LOCKOUT_CYCLES);
}
int alerts_wps_pbc_concurrent(void) {
    return (int)tune_val(TUNE_WPS_PBC_CONCURRENT);
}

/* Hex of a UUID-E, truncated — enough to key an incident and to let an
 * operator match two findings by eye, short of printing 32 characters
 * into a detail line that has 320 to spend. */
static void wps_uuid_hex(char out[17], const uint8_t uuid[16]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        out[i * 2]     = hx[(uuid[i] >> 4) & 0xF];
        out[i * 2 + 1] = hx[uuid[i] & 0xF];
    }
    out[16] = '\0';
}

/* WPS external-registrar PIN brute force — CERT/CC VU#723755.
 *
 * The countable unit is the *restart cycle*: M1→M3→EAP-NACK, which is
 * one PIN guess refused. wps_track.c already refuses to count a NACK
 * that did not follow M3, so ordinary M2D refusals never accumulate
 * here — that distinction is what makes a rate threshold mean
 * anything.
 *
 * Two shapes, deliberately two findings. A single STA grinding the
 * registrar is the default Reaver/Bully run. The same enrollee behind
 * rotating MACs is the evasion, and the handle is UUID-E: the attacker
 * rotates the MAC the AP rate-limits on and leaves the enrollee
 * identity inside M1 alone. The rotating case needs >= 2 STAs, so a
 * single-MAC session cannot be reported twice. */
void rule_wps_pin_brute(const sloth_state_t *s, time_t now) {
    (void)s;
    wps_session_t sess[MAX_WPS_SESSIONS];
    int n = wps_track_snapshot(sess, MAX_WPS_SESSIONS);
    if (n <= 0) return;
    const int thresh = alerts_wps_pin_brute_cycles();

    for (int i = 0; i < n; i++) {
        int c = wps_track_cycles_since(&sess[i], now, WPS_PIN_BRUTE_WINDOW_S);
        if (c < thresh) continue;

        char bss[20], sta[20];
        mac_to_str(sess[i].bssid, bss, sizeof(bss));
        mac_to_str(sess[i].sta,   sta, sizeof(sta));
        int mine = ownership_is_my_bssid(sess[i].bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "wpsbrute:%s:%s", bss, sta);
        snprintf(detail, sizeof(detail),
                 "%d WPS PIN attempts (M1-M3-NACK) from %s at %s in %ds "
                 "- external-registrar brute force, VU#723755%s",
                 c, sta, bss, WPS_PIN_BRUTE_WINDOW_S,
                 mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_PIN_BRUTE, ALERT_SEV_CRIT,
             "WPS_PIN_BRUTE", detail, key, NULL, 0, now);
    }

    for (int i = 0; i < n; i++) {
        if (!sess[i].has_uuid) continue;
        /* Report a group from its first member only, or an N-session
         * group fires N times under N keys. */
        int lead = 1;
        for (int j = 0; j < i && lead; j++)
            if (sess[j].has_uuid &&
                memcmp(sess[j].bssid, sess[i].bssid, 6) == 0 &&
                memcmp(sess[j].uuid_e, sess[i].uuid_e, 16) == 0) lead = 0;
        if (!lead) continue;

        int stas = 0, cycles = 0;
        for (int j = i; j < n; j++) {
            if (!sess[j].has_uuid) continue;
            if (memcmp(sess[j].bssid, sess[i].bssid, 6) != 0) continue;
            if (memcmp(sess[j].uuid_e, sess[i].uuid_e, 16) != 0) continue;
            stas++;
            cycles += wps_track_cycles_since(&sess[j], now,
                                             WPS_PIN_BRUTE_WINDOW_S);
        }
        if (stas < 2 || cycles < thresh) continue;

        char bss[20], uhex[17];
        mac_to_str(sess[i].bssid, bss, sizeof(bss));
        wps_uuid_hex(uhex, sess[i].uuid_e);
        int mine = ownership_is_my_bssid(sess[i].bssid);

        /* UUID-E is chosen by the enrollee, i.e. the attacker (#112).
         * The key carries all 16 bytes: the 8-byte display prefix in
         * the detail merged two tools whose UUIDs agree that far. */
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "wpsbrute-uuid");
        akey_mac(&k, sess[i].bssid);
        akey_hex(&k, sess[i].uuid_e, sizeof(sess[i].uuid_e));
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "%d WPS PIN attempts at %s in %ds from %d MACs sharing "
                 "UUID-E %s.. - rotating-MAC brute force, VU#723755%s",
                 cycles, bss, WPS_PIN_BRUTE_WINDOW_S, stas, uhex,
                 mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_PIN_BRUTE, ALERT_SEV_CRIT,
             "WPS_PIN_BRUTE", detail, key, NULL, 0, now);
    }
}

/* AP Setup Locked sawtooth — the lockout a PIN brute trips.
 *
 * VU#723755's own text is that many routers implement no lockout at
 * all; the ones that *do* answer a brute force by locking, then
 * releasing on a timer. So repeated locked->unlocked cycling is
 * evidence of the attack even when every PIN attempt itself was
 * missed, which on a hopping radio is the normal case — the beacon is
 * on the air continuously and the EAP exchange is not.
 *
 * An AP that locks once and stays locked produces no cycle and no
 * alert: that is a configured posture, not an attack. */
void rule_wps_lockout_cycling(const sloth_state_t *s, time_t now) {
    const int thresh = alerts_wps_lockout_cycles();
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->wps_lock_cycles <= 0) continue;        /* cheap reject */
        int c = wps_lock_cycles_in_window(a, now, WPS_LOCKOUT_WINDOW_S);
        if (c < thresh) continue;

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));
        int mine = ownership_is_my_bssid(a->bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "wpslockout:%s", bss);
        snprintf(detail, sizeof(detail),
                 "%d WPS lockout cycles on %s (SSID %.32s) in %dh "
                 "- AP is repeatedly locking out registrar attempts, "
                 "VU#723755%s",
                 c, bss, a->ssid[0] ? a->ssid : "<hidden>",
                 WPS_LOCKOUT_WINDOW_S / 3600,
                 mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_LOCKOUT_CYCLING,
             mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "WPS_LOCKOUT_CYCLE", detail, key, NULL, 0, now);
    }
}

/* Concurrent PBC enrollees inside the walk time.
 *
 * Push-Button Configuration authenticates by physical proximity and
 * nothing else: for the walk-time window, whoever is in range can
 * enrol. WSC closes that with the session-overlap rule — a registrar
 * that sees PBC enrollees from more than one device must abort, and
 * the protocol carries a Configuration Error for it (12, Multiple PBC
 * sessions detected). More than one *other* enrollee racing the
 * person at the button is therefore an abort condition by the
 * protocol's own account, and `mdk4 w` is the tool that manufactures
 * it on purpose.
 *
 * Gated on the AP's own beacon advertising Device Password ID 0x0004,
 * which the wave-5 slice already parses and deliberately keeps
 * non-sticky: the window has to be open *now* for a race to be
 * possible, and a latched flag would turn every later session into a
 * finding. */
void rule_wps_pbc_race(const sloth_state_t *s, time_t now) {
    wps_session_t sess[MAX_WPS_SESSIONS];
    int n = wps_track_snapshot(sess, MAX_WPS_SESSIONS);
    if (n <= 0) return;
    const int thresh = alerts_wps_pbc_concurrent();

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (a->wps_device_pwd_id != WPS_DEV_PWD_ID_PBC) continue;

        int live = 0;
        for (int j = 0; j < n; j++) {
            if (memcmp(sess[j].bssid, a->bssid, 6) != 0) continue;
            /* A finished registration is not racing anything. */
            if (sess[j].state == WPS_S_DONE) continue;
            if (sess[j].last_seen < now - (time_t)WPS_PBC_WALK_TIME_S) continue;
            live++;
        }
        if (live <= thresh) continue;

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));
        int mine = ownership_is_my_bssid(a->bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "wpspbc:%s", bss);
        snprintf(detail, sizeof(detail),
                 "%d concurrent WPS PBC enrollees at %s (SSID %.32s) in the "
                 "%ds walk time - session overlap, registrar must abort%s",
                 live, bss, a->ssid[0] ? a->ssid : "<hidden>",
                 WPS_PBC_WALK_TIME_S, mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_PBC_RACE, ALERT_SEV_CRIT,
             "WPS_PBC_RACE", detail, key, NULL, 0, now);
    }
}

/* ── Pixie-Dust (#82, owner ruling 2026-10-19) ───────────────
 *
 * Bongard, "Offline bruteforce attack on WiFi Protected Setup"
 * (Hack.lu 2014; research/papers/bongard-pixie-dust-2014.md). The
 * attack, in the slides' own steps: "Do the WPS protocol up to message
 * M3 / Get the Nonce from M1 / Bruteforce the state of the PRNG /
 * Compute E-S1 and E-S2 from the state / Bruteforce PSK1 / PSK2 from
 * E-Hash1 / E-Hash2 / Do the full WPS protocol to get the credentials".
 *
 * Two of those steps are on the air and the rest are offline, so there
 * are two rules. Neither can see the PRNG — whether this AP's nonces
 * were weak is exactly what a passive sensor cannot know — so both
 * report a sequence that corroborates the attack, never one that
 * confirms it (owner standard, #145 ruling 2). */

/* "Up to message M3", then stop. M4 is the registrar's next message
 * and carries R-Hash1, which an online brute force has to send — it is
 * the guess. A registrar that took M3 and sent no M4 wanted
 * E-Hash1/E-Hash2 and nothing else. The silence window (--tune
 * wps.pixie_silence_s) is what separates "left" from "slow". WARN: a
 * channel-hopping receiver that missed every frame after M3 produces
 * the same shape, which is why it is not CRIT. */
void rule_wps_pixie_probe(const sloth_state_t *s, time_t now) {
    (void)s;
    wps_session_t sess[MAX_WPS_SESSIONS];
    int n = wps_track_snapshot(sess, MAX_WPS_SESSIONS);
    if (n <= 0) return;
    const int silence = (int)tune_val(TUNE_WPS_PIXIE_SILENCE_S);

    for (int i = 0; i < n; i++) {
        time_t m3 = 0;
        int quiet = 0;
        if (!wps_track_m3_abandon(&sess[i], now, &m3, &quiet)) continue;
        if (quiet < silence) continue;

        char bss[20], sta[20];
        mac_to_str(sess[i].bssid, bss, sizeof(bss));
        mac_to_str(sess[i].sta,   sta, sizeof(sta));
        int mine = ownership_is_my_bssid(sess[i].bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "wpspixie");
        akey_mac(&k, sess[i].bssid);
        akey_mac(&k, sess[i].sta);
        if (!akey_end(&k)[0]) continue;
        /* The threshold, not the live silence, goes in the detail: the
         * detail signature is what makes a re-evaluation an observation,
         * and a figure that ticks every second would make every tick
         * one. */
        snprintf(detail, sizeof(detail),
                 "WPS run %s -> %s stopped after M3 (E-Hash1/E-Hash2 sent, "
                 "no M4) and stayed silent >= %ds - Pixie-Dust offline-PIN "
                 "shape, Bongard 2014; corroborates, does not confirm%s",
                 sta, bss, silence, mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_PIXIE_PROBE, ALERT_SEV_WARN,
             "WPS_PIXIE_PROBE", detail, key, NULL, 0, now);
    }
}

/* "Do the full WPS protocol to get the credentials." A registration at
 * the same AP that reached M7 (the enrollee's second commitment and the
 * network credentials, per the slides' "E -> R M7"), M8 or Done, within
 * --tune wps.pixie_success_window_s after a run that stopped at M3.
 *
 * Deliberately reads the abandoned *shape*, not the WPS_PIXIE_PROBE
 * verdict: the silence window does not apply here. pixiewps recovers a
 * weak-PRNG PIN in seconds, and a tool that reruns with it at once
 * leaves no minute of silence — so gating on the probe rule would miss
 * the most direct form of the attack, where the completion itself is
 * the corroboration. Any station counts as the completer, because the
 * rerun need not use the MAC that probed.
 *
 * CRIT — the ruling's "HIGH"; sloth's scale tops out at CRIT. If it is
 * right, the PSK is gone and changing it is the only remedy; if it is
 * wrong, it is a legitimate enrolment that followed a receiver gap, and
 * the detail names both runs so an operator can tell which. */
void rule_wps_pixie_likely_success(const sloth_state_t *s, time_t now) {
    (void)s;
    wps_session_t sess[MAX_WPS_SESSIONS];
    int n = wps_track_snapshot(sess, MAX_WPS_SESSIONS);
    if (n <= 0) return;
    const long window = tune_val(TUNE_WPS_PIXIE_SUCCESS_WINDOW_S);

    for (int c = 0; c < n; c++) {
        if (!sess[c].cred_ts) continue;
        int probe = -1;
        time_t probe_m3 = 0;
        for (int p = 0; p < n; p++) {
            if (memcmp(sess[p].bssid, sess[c].bssid, 6) != 0) continue;
            time_t m3 = 0;
            if (!wps_track_m3_abandon(&sess[p], now, &m3, NULL)) continue;
            if (m3 >= sess[c].cred_ts) continue;       /* came after */
            if ((long)(sess[c].cred_ts - m3) > window) continue;
            /* The newest qualifying run is the one the detail names. */
            if (probe < 0 || m3 > probe_m3) { probe = p; probe_m3 = m3; }
        }
        if (probe < 0) continue;

        char bss[20], sta[20], psta[20];
        mac_to_str(sess[c].bssid,     bss,  sizeof(bss));
        mac_to_str(sess[c].sta,       sta,  sizeof(sta));
        mac_to_str(sess[probe].sta,   psta, sizeof(psta));
        int mine = ownership_is_my_bssid(sess[c].bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "wpspixieok");
        akey_mac(&k, sess[c].bssid);
        akey_mac(&k, sess[c].sta);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "WPS registration %s -> %s reached the credentials "
                 "(M7/M8/Done) %lds after a run from %s stopped at M3 - "
                 "Pixie-Dust likely succeeded, Bongard 2014; corroborated "
                 "by sequence, not confirmed: treat the PSK as exposed%s",
                 sta, bss, (long)(sess[c].cred_ts - probe_m3), psta,
                 mine ? " - YOUR network" : "");
        fire(ALERT_TYPE_WPS_PIXIE_LIKELY_SUCCESS, ALERT_SEV_CRIT,
             "WPS_PIXIE_SUCCESS", detail, key, NULL, 0, now);
    }
}

/* Rogue-RADIUS / weak-EAP — issue #31. eaphammer / hostapd-wpe stand up
 * a rogue 802.1X AP that offers a weak inner method (EAP-MD5 / EAP-GTC)
 * to harvest offline-crackable challenge/response pairs, and often
 * surfaces the client's real username when the supplicant lacks an
 * anonymous outer identity. Both are decoded on the air by the EAP
 * inner-frame parser and accumulated per BSSID by eap_track.
 *
 * CRIT when a weak method was offered; WARN when only an identity leaked
 * (still notable — a correctly configured enterprise supplicant sends an
 * anonymous outer identity). */
void rule_rogue_radius(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->rogue_radius_count; i++) {
        const rogue_radius_ap_t *r = &s->rogue_radius[i];
        if (!r->weak_method && r->identity_leaks == 0) continue;

        char bssid[20];
        fmt_bssid(bssid, r->bssid);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "rogueradius:%s", bssid);
        if (r->weak_method)
            snprintf(detail, sizeof(detail),
                     "BSSID %s offered weak EAP (MD5/GTC), %d identity leak(s)"
                     " - rogue-RADIUS lure", bssid, r->identity_leaks);
        else
            snprintf(detail, sizeof(detail),
                     "BSSID %s leaked %d real EAP identity(ies) - check outer"
                     " identity", bssid, r->identity_leaks);
        fire(ALERT_TYPE_ROGUE_RADIUS,
             r->weak_method ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "ROGUE_RADIUS", detail, key, NULL, 0, now);
    }
}


/* CVE-2023-52160 — a TLS-in-EAP session that reached EAP-Success with
 * no server identity presented (#65).
 *
 * ROGUE_RADIUS above says "this AP offers a weak method": it warns the
 * operator about attacker infrastructure. This says something different
 * and more uncomfortable — *a client here accepted a server that never
 * proved who it was*. That is a property of the client's supplicant
 * configuration, and it stays silent until a device actually does it.
 *
 * Both are needed. The AP-side rule fires on infrastructure the
 * operator may not control; this one fires on their own fleet. */
void rule_peap_no_server_cert(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->rogue_radius_count; i++) {
        const rogue_radius_ap_t *r = &s->rogue_radius[i];
        if (r->nocert_sessions <= 0) continue;

        char bssid[20], sta[20];
        fmt_bssid(bssid, r->bssid);
        mac_to_str(r->last_nocert_sta, sta, sizeof(sta));

        int mine     = ownership_is_my_bssid(r->bssid);
        int rostered = ownership_is_known_device(r->last_nocert_sta);

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "peapnocert:%s", bssid);
        snprintf(detail, sizeof(detail),
                 "%.17s -> %.17s EAP-Success with no %s (%d session%s)%s%s",
                 sta, bssid,
                 /* Which half was missing changes how much to trust it.
                  * No ServerHello at all means the AP never started a
                  * TLS handshake — unambiguous. A ServerHello without a
                  * Certificate is the same finding, but a large cert
                  * chain can also cross an EAP fragment boundary we do
                  * not reassemble, so the wording is weaker. */
                 r->nocert_no_hello > 0 ? "TLS ServerHello"
                                        : "Certificate observed",
                 r->nocert_sessions, r->nocert_sessions == 1 ? "" : "s",
                 mine     ? " - YOUR network" : "",
                 rostered ? " - rostered client" : "");

        /* CRIT on the operator's own network or their own device: in
         * both cases this is their fleet demonstrating it would fall for
         * a rogue enterprise AP, which is the CVE's actual population. */
        fire(ALERT_TYPE_PEAP_NO_SERVER_CERT,
             (mine || rostered) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "PEAP_NO_CERT", detail, key, NULL, 0, now);
    }
}
