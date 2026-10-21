/* Rules over the 802.11 management and control planes, and over what
 * the radio says about sloth itself: the deauth/beacon/auth/assoc
 * floods, BTM, CSA, RRM, RTS, SA Query, MFP, Block Ack, malformed
 * management frames, probe floods and recon against the operator's
 * networks, recurring transit, unknown devices, RF degradation, the
 * missing monitor radio, PM forgery, queue release and TPC.
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static. When a
 * rule runs is src/alerts/rules_table.c's business, not this file's. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "tune.h"   /* operator-tunable thresholds (#82) */
#include "beacon_snoop.h"
#include "auth_track.h"
#include "assoc_track.h"
#include "action_snoop.h"
#include "ctrl_frames.h"
#include "ownership.h"
#include "rf_quality.h"
#include "pm_forge.h"
#include "queue_evict.h"
#include "rules.h"
#include "engine_internal.h"
#include "wired_attach.h"
#include "sloth_compat.h"

/* Every detector's citation array hands over whole: the engine clamps to
 * ALERT_EVIDENCE_IDS, and a detector keeping more than that would lose
 * its newest ids silently (#92 slice 4). */
SLOTH_STATIC_ASSERT(PM_FORGE_EVIDENCE_IDS <= ALERT_EVIDENCE_IDS,
                    pm_forge_cites_within_the_alert);
SLOTH_STATIC_ASSERT(QUEUE_EVICT_EVIDENCE_IDS <= ALERT_EVIDENCE_IDS,
                    queue_evict_cites_within_the_alert);

/* Deauth/disassoc flood (#88). Fires per (BSSID, victim) impact
 * aggregate while its sliding window is flooded: at least
 * DEAUTH_FLOOD_THRESH distinct frames inside some DEAUTH_FLOOD_WIN_SECS
 * window that closed within the last DEAUTH_FLOOD_HOLD_SECS.
 *
 * The detail reports what was observed and stops there. The transmitter
 * address is whatever the frame claims, so it never names the sender;
 * and a passive receiver cannot see whether any station acted on the
 * frames (a PMF-associated one drops unprotected ones). */
void rule_deauth_flood(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->deauth_victim_count; i++) {
        const deauth_victim_t *v = &s->deauth_victims[i];
        if (!v->flood) continue;
        char tgt[20];
        mac_to_str(v->victim, tgt, sizeof(tgt));
        char bss[20];
        mac_to_str(v->bssid, bss, sizeof(bss));
        char rsn[16];
        if (v->reason_valid) snprintf(rsn, sizeof(rsn), "%u", v->reason);
        else                 snprintf(rsn, sizeof(rsn), "%s",
                                      v->protected_count ? "encrypted" : "unknown");
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* A flood aimed at a network the operator designated as theirs
         * is not the same event as one aimed at the cafe next door
         * (#52). Same detector, higher stakes. */
        int mine = ownership_is_my_bssid(v->bssid);
        snprintf(key,    sizeof(key),    "deauth:%s@%s", tgt, bss);
        snprintf(detail, sizeof(detail),
                 "victim=%s bssid=%s observed %d frames, peak %d in %ds, "
                 "reason=%s, %d stream%s%s; sender unverified, "
                 "disruption not confirmed",
                 tgt, bss, v->frames, v->peak_win,
                 (int)tune_val(TUNE_DEAUTH_FLOOD_WINDOW_S),
                 rsn, v->streams, v->streams == 1 ? "" : "s",
                 mine ? " - YOUR network" : "");
        /* The first wireless detection to cite its own frames (#92).
         * There is no IP to export on — a deauth is 802.11 management —
         * so the ring's event IDs are the only path from this alert
         * back to the bytes that caused it. */
        fire_ev(ALERT_TYPE_DEAUTH_FLOOD,
                mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
                v->evidence_ids, v->evidence_id_count,
                "DEAUTH_FLOOD", detail, key, NULL, 0, now);
    }
}

void rule_beacon_flood(const sloth_state_t *s, time_t now) {
    /* mdk3/mdk4 spray dozens of fake APs per second; a real RF
     * neighbourhood gains BSSIDs slowly. We key on the *rate* of
     * first-seen BSSIDs, not the table size, so a merely-dense area (many
     * stable APs) doesn't trip it. */
    (void)s;
    const int win    = (int)tune_val(TUNE_BEACON_FLOOD_WINDOW_S);
    const int thresh = (int)tune_val(TUNE_BEACON_FLOOD_THRESH);
    int n = beacon_recent_new_bssids(now, win);
    if (n < thresh) return;
    char detail[ALERT_DETAIL_LEN];
    snprintf(detail, sizeof(detail),
             "%d new BSSIDs in %ds (mdk-style beacon flood)",
             n, win);
    /* The first beacon of each of the newest BSSIDs (#92 slice 4): the
     * finding is their arrival, so the frame that introduced each one
     * is the evidence. */
    uint64_t ev[ALERT_EVIDENCE_IDS];
    int ev_n = beacon_flood_evidence(now, win, ev, ALERT_EVIDENCE_IDS);
    fire_ev(ALERT_TYPE_BEACON_FLOOD, ALERT_SEV_WARN, ev, ev_n,
            "BEACON_FLOOD", detail, "beacon_flood", NULL, 0, now);
}

void rule_auth_flood(const sloth_state_t *s, time_t now) {
    /* A burst of auth frames at one BSSID = association-table exhaustion
     * DoS (mdk3 'a'). Keyed per-AP so a busy roaming environment doesn't
     * trip it — only a genuine outlier does. */
    (void)s;
    uint8_t bssid[6];
    const int win    = (int)tune_val(TUNE_AUTH_FLOOD_WINDOW_S);
    const int thresh = (int)tune_val(TUNE_AUTH_FLOOD_THRESH);
    int n = auth_flood_bssid(now, win, thresh, bssid);
    if (n < thresh) return;
    char bss[20];
    mac_to_str(bssid, bss, sizeof(bss));
    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    int mine = ownership_is_my_bssid(bssid);   /* #52 — see rule_deauth_flood */
    snprintf(key,    sizeof(key),    "authflood:%s", bss);
    snprintf(detail, sizeof(detail),
             "%d auth frames to %s in %ds (assoc-table DoS)%s",
             n, bss, win, mine ? " - YOUR network" : "");
    /* The newest counted frames (#92 slice 4): an auth frame has no IP,
     * so the evidence ring is the route back to the flood's bytes. */
    uint64_t ev[ALERT_EVIDENCE_IDS];
    int ev_n = auth_flood_evidence(bssid, now, win, ev, ALERT_EVIDENCE_IDS);
    fire_ev(ALERT_TYPE_AUTH_FLOOD,
            mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
            ev, ev_n, "AUTH_FLOOD", detail, key, NULL, 0, now);
}

void rule_assoc_flood(const sloth_state_t *s, time_t now) {
    /* Association-request flood — the missing member of the flood set
     * (beacon, deauth, probe and auth are already covered). Rate is
     * per-BSSID so a busy AP with many ordinary clients doesn't trip
     * it; only an outlier does.
     *
     * The distinct-STA count shapes the message rather than gating the
     * alert. Few STAs at high rate is a targeted or broken client; many
     * STAs at high rate is a spoofed-MAC flood, which is what the
     * common tooling actually emits. Gating on either number would
     * blind the rule to the other attack. */
    (void)s;
    uint8_t bssid[6];
    int distinct = 0;
    const int win    = (int)tune_val(TUNE_ASSOC_FLOOD_WINDOW_S);
    const int thresh = (int)tune_val(TUNE_ASSOC_FLOOD_THRESH);
    int n = assoc_flood_bssid(now, win, thresh, bssid, &distinct);
    if (n < thresh) return;

    char bss[20];
    mac_to_str(bssid, bss, sizeof(bss));
    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    int mine = ownership_is_my_bssid(bssid);   /* #52 — see rule_deauth_flood */
    snprintf(key,    sizeof(key),    "assocflood:%s", bss);
    snprintf(detail, sizeof(detail),
             "%d assoc reqs to %s from %d STA%s in %ds%s%s",
             n, bss, distinct, distinct == 1 ? "" : "s",
             win,
             distinct > 3 ? " (spoofed-MAC flood)" : " (few sources)",
             mine ? " - YOUR network" : "");
    uint64_t ev[ALERT_EVIDENCE_IDS];   /* #92 slice 4 — see rule_auth_flood */
    int ev_n = assoc_flood_evidence(bssid, now, win, ev, ALERT_EVIDENCE_IDS);
    fire_ev(ALERT_TYPE_ASSOC_FLOOD,
            mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
            ev, ev_n, "ASSOC_FLOOD", detail, key, NULL, 0, now);
}

/* Has this BSSID ever been heard beaconing? A legitimate AP steering
 * its own clients has, by definition, been advertising the BSS it is
 * moving them off. A transmitter address that has never emitted a
 * beacon is claiming an authority we have no evidence it holds.
 *
 * Reads the snapshot rather than beacon_snoop's live table so the rule
 * stays a pure function of state, which is what makes it testable.
 *
 * The honest limit: on a channel-hopping sensor, "never beaconed" means
 * "not while we were listening". The tell is therefore reported in the
 * detail rather than used to escalate severity on its own. */
static int btm_source_ever_beaconed(const sloth_state_t *s,
                                    const uint8_t bssid[6]) {
    for (int i = 0; i < s->beacon_count; i++)
        if (memcmp(s->beacon_aps[i].bssid, bssid, 6) == 0) return 1;
    return 0;
}

/* BTM forcing (#59) — the 802.11v deauth-equivalent.
 *
 * A BSS Transition Management Request with Disassociation Imminent set
 * tells a client it is about to be dropped and should go elsewhere.
 * One is a legitimate "this radio is going down". Four to the same
 * client in a minute is an AP that will not take no for an answer, and
 * it moves the client without a single deauth frame — which is why
 * ALERT_TYPE_DEAUTH_FLOOD never sees this attack. */
void rule_btm_abuse(const sloth_state_t *s, time_t now) {
    uint8_t bssid[6], sta[6];
    int total = 0;
    const int win    = (int)tune_val(TUNE_BTM_ABUSE_WINDOW_S);
    const int thresh = (int)tune_val(TUNE_BTM_ABUSE_THRESH);
    int imminent = btm_forcing_pair(now, win, thresh, bssid, sta, &total);
    if (imminent < thresh) return;

    char bss[20], stastr[20];
    mac_to_str(bssid, bss,    sizeof(bss));
    mac_to_str(sta,   stastr, sizeof(stastr));

    /* Where is the client being sent? The durable row carries the
     * candidate list from the most recent Request. */
    btm_steer_t row;
    int have_row = btm_find(bssid, sta, &row);
    int twin_target = 0;
    int fabricated = 0;
    char cand[64];
    int  coff = 0;
    cand[0] = '\0';
    if (have_row) {
        for (int i = 0; i < row.candidate_count && i < MAX_AP_NEIGHBORS; i++) {
            if (btm_candidate_is_twin(s, row.candidates[i])) twin_target = 1;
            /* A candidate we have never heard beacon is a destination
             * that may not exist. Real steering points at real APs; a
             * fabricated candidate list is how a forced roam is aimed
             * somewhere the client cannot verify. Same hop-mode caveat
             * as the source tell — reported, not escalated on. */
            if (!btm_source_ever_beaconed(s, row.candidates[i])) fabricated = 1;
            /* Name the first two only. The list can hold eight, the
             * detail field is shared with every other rule, and #58
             * landed because an unbounded address in a detail string
             * tripped -Wformat-truncation. Two is enough to recognise
             * the destination; the full list is in the [a] view. */
            if (i < 2) {
                char c[20];
                mac_to_str(row.candidates[i], c, sizeof(c));
                coff += snprintf(cand + coff, sizeof(cand) - (size_t)coff,
                                 "%s%.17s", coff ? "," : "", c);
                if (coff >= (int)sizeof(cand)) { coff = (int)sizeof(cand) - 1; break; }
            }
        }
        if (row.candidate_count > 2 || row.candidates_truncated)
            snprintf(cand + coff, sizeof(cand) - (size_t)coff, ",+%d",
                     row.candidate_count - 2);
    }

    int mine    = ownership_is_my_bssid(bssid);
    int rostered = ownership_is_known_device(sta);
    int no_beacon = !btm_source_ever_beaconed(s, bssid);

    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "btm:%.17s->%.17s", bss, stastr);
    snprintf(detail, sizeof(detail),
             "BTM force: %.17s -> %.17s %d/%d req %ds, candidates=%.40s, "
             "evil-twin=%s%s%s%s%s",
             bss, stastr, imminent, total, win,
             cand[0] ? cand : "none",
             twin_target ? "yes" : "no",
             no_beacon ? ", source never beaconed" : "",
             fabricated ? ", candidate never beaconed" : "",
             mine     ? " - YOUR network" : "",
             rostered ? " - rostered client" : "");

    /* CRIT when the destination is a known rogue (the forcing has an
     * identified landing site), or when the operator has told us this
     * network or this client is theirs. */
    /* The Disassociation-Imminent Requests the threshold counted (#92
     * slice 4). */
    uint64_t ev[ALERT_EVIDENCE_IDS];
    int ev_n = btm_forcing_evidence(bssid, sta, now, win, ev,
                                    ALERT_EVIDENCE_IDS);
    fire_ev(ALERT_TYPE_BTM_ABUSE,
            (twin_target || mine || rostered) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
            ev, ev_n, "BTM_ABUSE", detail, key, NULL, 0, now);
}


/* WPA / PMF downgrade posture (#62).
 *
 * Fires on an AP advertising a lane weaker than the one it is also
 * advertising. Nothing here is an attack — every condition is a
 * configuration the AP broadcasts about itself — but each is the
 * prerequisite an attacker needs, and a client takes the weak lane if
 * the AP offers it. CVE-2023-52424 and the Dragonblood family both
 * depend on the AP having offered one.
 *
 * The seam is deliberate: the parser sets the per-BSS facts, this reads
 * the AP table and fires. beacon_parse_ies() is a pure function reached
 * by both the monitor-mode and nl80211 paths, and giving it a side
 * effect on global alert state would be the wrong shape — plus the
 * observation floor below needs per-BSSID history a per-frame parser
 * does not have. Flagged as a §4.2 departure from the issue's wording.
 */

/* Channel Switch Announcement abuse (#63).
 *
 * CSA is how an AP moves its clients to a new channel, and clients
 * honour it — which is the point, and the problem. A spoofed
 * announcement claiming the legitimate BSSID moves every associated STA
 * onto a channel the attacker chose, with no deauth frame and without
 * having to out-signal anything. It also works on firmware that ignores
 * deauth, because roaming support is a certification checkbox.
 *
 * Three shapes, in descending confidence:
 *
 *   spoofed  — the transmitter is not the BSS it claims to speak for.
 *              In a genuine announcement addr2 == addr3.
 *   storm    — several distinct target channels from one BSSID inside
 *              a minute. A legitimate AP picks one and commits.
 *   steering — the target channel is where a known rogue is sitting.
 */

/* 802.11k survey abuse (#61).
 *
 * A Beacon Request asks a client to scan and report what it can hear.
 * The client obliges — that is the protocol working. It is also how an
 * AP enumerates the airspace *through someone else's radio*, from a
 * position its own antenna cannot reach, and the report that comes back
 * is exactly the input needed to build a convincing evil twin.
 *
 * The discriminator is not the rate on its own. A legitimate AP steering
 * its own clients asks about networks *it* advertises; an outsider asks
 * about SSIDs it has never beaconed. */

/* RTS flood (#64) — airtime denial of service.
 *
 * An RTS asks every radio in earshot to stay quiet for the NAV
 * reservation it carries. That is the mechanism that makes 802.11 work
 * around hidden nodes, and it is also a way to silence a channel
 * without transmitting anything a flood detector was watching for: no
 * deauth, no beacon, no association, just a request to be quiet
 * repeated faster than anyone can talk between the gaps.
 *
 * The sustain requirement is what separates this from a retry burst. A
 * client fighting interference emits RTS hard for a moment; a flood
 * keeps going. */

/* Block-Ack paralysis — the Bl0ck attack (#70, arXiv 2302.05899).
 *
 * A spoofed Block-Ack Request sent on behalf of a legitimate station
 * forces its peer to advance the Block-Ack receive window past frames
 * that are still queued. Everything in the skipped range is discarded
 * and the connection stalls.
 *
 * It is quiet by design: no deauth, no flood, nothing the rate rules
 * watch for. What the operator sees is a client that stopped working.
 *
 * The corroborating retry burst is reported, not required. A stalled
 * connection usually retries hard, but requiring it would make the rule
 * depend on rf_quality having sampled the right channel at the right
 * moment — and on a hopping sensor that is a coin flip. */
void rule_blockack_attack(const sloth_state_t *s, time_t now) {
    sloth_bar_state_t b;
    memset(&b, 0, sizeof(b));
    if (bar_worst_offender(now, 300, &b) <= 0) return;

    int mine = ownership_is_my_bssid(b.bssid);

    /* Is the receiving side visibly struggling? rf_quality tracks the
     * retry ratio per channel; a stalled Block-Ack window shows up
     * there as sustained retries. Evidence for the operator, not a
     * gate on the alert. */
    int degraded = 0;
    for (int i = 0; i < s->channel_count; i++)
        if (s->channels[i].retry_pct >= RF_RETRY_DEGRADED_PCT) degraded = 1;

    char rx[20], tx[20];
    mac_to_str(b.bssid, rx, sizeof(rx));
    mac_to_str(b.sta,   tx, sizeof(tx));

    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "bl0ck:%.17s:%.17s:%u", rx, tx, b.tid);
    snprintf(detail, sizeof(detail),
             "Bl0ck: %.17s -> %.17s TID %u SSN jump %u, %u suspicious of "
             "%u BARs%s%s",
             tx, rx, b.tid, b.last_jump, b.suspicious_bars, b.total_bars,
             degraded ? " (channel retrying hard)" : "",
             mine ? " - YOUR network" : "");

    fire(ALERT_TYPE_BLOCKACK_ATTACK,
         mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
         "BLOCKACK_ATK", detail, key, NULL, 0, now);
}

/* SA-Query storm — issue #76.
 *
 * Not an attack on the client. SA Query is management-frame
 * protection's own mechanism: an AP that receives an *unprotected*
 * disassociation claiming to be from an associated station does not act
 * on it, it asks the station whether it is still there. So a storm is
 * the visible symptom of someone spraying spoofed disassociations at an
 * MFP-protected network — which is what deauth flooding becomes once
 * MFP takes the direct route away.
 *
 * The attacker's own frames may never be heard: they are aimed at the
 * AP and sloth may be on another channel or out of range of the
 * transmitter. The AP's response is sent on the BSS's own channel and
 * is heard. Detecting the answer rather than the question is the whole
 * reason this rule earns its place beside the deauth flood rule. */
void rule_sa_query_flood(const sloth_state_t *s, time_t now) {
    (void)s;
    uint8_t bssid[6], sta[6];
    int count = 0;
    const int win = (int)tune_val(TUNE_SAQ_FLOOD_WINDOW_S);
    if (!saq_flood_pair(now, win, (int)tune_val(TUNE_SAQ_FLOOD_THRESH),
                        bssid, sta, &count)) return;

    char bss[20], stastr[20];
    mac_to_str(bssid, bss,    sizeof(bss));
    mac_to_str(sta,   stastr, sizeof(stastr));
    char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "saqflood:%.17s:%.17s", bss, stastr);
    snprintf(detail, sizeof(detail),
             "%d SA-Query frames in %ds between %.17s and %.17s"
             " - the AP is refusing spoofed disassociations",
             count, win, bss, stastr);
    /* CRIT: a legitimate exchange is a handful of frames over a few
     * hundred milliseconds (§11.13). Sustained means the AP is fending
     * something off, and MFP is doing its job — which is worth telling
     * the operator precisely because nothing else will. */
    /* The AP's answers, not the attacker's questions — the frames this
     * rule actually heard and counted (#92 slice 4). */
    uint64_t ev[ALERT_EVIDENCE_IDS];
    int ev_n = saq_flood_evidence(bssid, sta, now, win, ev,
                                  ALERT_EVIDENCE_IDS);
    fire_ev(ALERT_TYPE_SA_QUERY_FLOOD, ALERT_SEV_CRIT,
            ev, ev_n, "SA_QUERY_FLOOD", detail, key, NULL, 0, now);
}

/* Unprotected robust action frame on an MFP-required BSS — issue #76,
 * CVE-2019-16275.
 *
 * The BSS's own beacon says management frames must be protected, and
 * one arrived that was not. Either the stack is non-conforming or the
 * frame was injected, and the CVE is the first being exploitable as the
 * second. Sloth cannot tell them apart and does not claim to. */
void rule_mfp_unprotected(const sloth_state_t *s, time_t now) {
    (void)s;
    uint8_t bssid[6], cat[1] = { 0 };
    int count = 0;
    if (action_mfp_violations(bssid, &count, cat) <= 0 || count <= 0) return;

    char bss[20];
    mac_to_str(bssid, bss, sizeof(bss));
    char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "mfpunprot:%.17s", bss);
    snprintf(detail, sizeof(detail),
             "%d unprotected robust action frame%s on %.17s"
             " (category %u) - this BSS advertises MFP required"
             " (CVE-2019-16275)",
             count, count == 1 ? "" : "s", bss, (unsigned)cat[0]);
    fire(ALERT_TYPE_MFP_UNPROTECTED, ALERT_SEV_CRIT,
         "MFP_UNPROTECTED", detail, key, NULL, 0, now);
}

void rule_rts_flood(const sloth_state_t *s, time_t now) {
    (void)s;
    uint8_t ta[6];
    int max_nav = 0, dur = 0;
    int n = ctrl_rts_flood(now, 60, (int)tune_val(TUNE_RTS_FLOOD_RATE),
                           (int)tune_val(TUNE_RTS_FLOOD_SUSTAIN_S),
                           ta, &max_nav, &dur);
    if (n <= 0) return;

    /* A Duration above the legal maximum cannot come from a conforming
     * radio, so it is not "a busy client" under any reading — it is a
     * generated frame. That is a different claim from a high rate, and
     * it is the one worth escalating on. */
    int illegal_nav = max_nav > CTRL_NAV_MAX_LEGAL;
    int mine        = ownership_is_my_bssid(ta);

    char src[20];
    mac_to_str(ta, src, sizeof(src));
    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "rtsflood:%.17s", src);
    snprintf(detail, sizeof(detail),
             "%.17s sent %d RTS over %ds (~%d/s), max NAV %dus%s%s",
             src, n, dur, dur > 0 ? n / dur : n, max_nav,
             illegal_nav ? " - above the legal maximum" : "",
             mine ? " - YOUR network" : "");
    fire(ALERT_TYPE_RTS_FLOOD,
         (illegal_nav || mine) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
         "RTS_FLOOD", detail, key, NULL, 0, now);
}

void rule_rrm_survey_abuse(const sloth_state_t *s, time_t now) {
    uint8_t bssid[6], sta[6];
    int reqs = rrm_busiest_pair(now, RRM_SURVEY_WIN_SECS,
                                RRM_SURVEY_THRESH, bssid, sta);
    if (reqs < RRM_SURVEY_THRESH) return;

    sloth_rrm_pair_t pair;
    if (!rrm_find(bssid, sta, &pair)) return;

    /* Has the asker ever been heard beaconing at all, and if so, the
     * SSID it is asking about?
     *
     * The two questions are separate on purpose. With --hop the AP
     * inventory is a sample, so "we have never heard this BSSID" tells
     * us nothing about what it does or does not advertise — inferring
     * from that would make hop mode fire on every AP the sweep missed.
     * Only a BSSID we *have* heard beaconing can be said to be asking
     * about something it does not advertise. */
    int asker_beacons = 0, asks_own_ssid = 0;
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        if (memcmp(a->bssid, bssid, 6) != 0) continue;
        asker_beacons = 1;
        if (pair.last_ssid[0] && strcmp(a->ssid, pair.last_ssid) == 0)
            asks_own_ssid = 1;
        /* Multi-VAP: the same radio may advertise the SSID under a
         * different BSSID in its own history. */
        for (int h = 0; h < a->ssid_history_n; h++)
            if (pair.last_ssid[0] &&
                strcmp(a->ssid_history[h], pair.last_ssid) == 0)
                asks_own_ssid = 1;
    }
    int fishing = asker_beacons && !asks_own_ssid;

    /* The strongest condition in the issue: an outsider surveying the
     * operator's own network through the operator's own clients. */
    int my_ssid  = pair.last_ssid[0] && ownership_is_my_ssid(pair.last_ssid);
    int my_bssid = ownership_is_my_bssid(bssid);
    int outsider_on_my_net = my_ssid && !my_bssid;

    if (!fishing && !outsider_on_my_net) return;

    int twin = btm_candidate_is_twin(s, bssid);

    char bss[20], stastr[20];
    mac_to_str(bssid, bss,    sizeof(bss));
    mac_to_str(sta,   stastr, sizeof(stastr));

    char key[ALERT_KEY_LEN];
    char detail[ALERT_DETAIL_LEN];
    snprintf(key, sizeof(key), "rrm:%.17s->%.17s", bss, stastr);
    snprintf(detail, sizeof(detail),
             "RRM survey: %.17s -> %.17s asked for SSID='%.20s' "
             "%d req/%ds, %d reported back, evil-twin=%s%s%s",
             bss, stastr, pair.last_ssid[0] ? pair.last_ssid : "(any)",
             reqs, RRM_SURVEY_WIN_SECS, pair.reports_seen,
             twin ? "yes" : "no",
             fishing ? ", asker never beaconed that SSID" : "",
             outsider_on_my_net ? " - surveying YOUR network" : "");

    fire(ALERT_TYPE_RRM_SURVEY_ABUSE,
         (outsider_on_my_net || twin) ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
         "RRM_SURVEY", detail, key, NULL, 0, now);
}

void rule_csa_abuse(const sloth_state_t *s, time_t now) {
    /* One pass per BSSID that announced anything recently.
     *
     * This is work-saving, not correctness: fire() already dedups on the
     * key, so without it an AP announcing on every beacon still produces
     * one alert — it would just re-scan the ring once per event to get
     * there. Mutation testing established that, and the comment used to
     * claim otherwise. */
    uint8_t done[SLOTH_CSA_MAX_EVENTS][6];
    int done_n = 0;

    for (int i = 0; i < s->csa_count; i++) {
        const sloth_csa_event_t *e = &s->csa_events[i];
        if (!e->ts || now - e->ts > CSA_STORM_WIN_SECS) continue;

        int seen = 0;
        for (int d = 0; d < done_n; d++)
            if (memcmp(done[d], e->bssid, 6) == 0) { seen = 1; break; }
        if (seen) continue;
        if (done_n < SLOTH_CSA_MAX_EVENTS) memcpy(done[done_n++], e->bssid, 6);

        /* Spoof: addr2 != addr3. Only meaningful for Action frames —
         * a beacon's addresses are the same by construction, so a
         * mismatch there means the frame was misread, not forged. */
        int spoofed = (e->source == CSA_SRC_ACTION) &&
                      memcmp(e->ta, e->bssid, 6) != 0;

        int targets = csa_distinct_targets(e->bssid, now, CSA_STORM_WIN_SECS);
        int storm   = targets >= CSA_STORM_THRESH;

        /* Is the destination somewhere a known rogue is sitting? The
         * twin episodes are the materialised evil-twin set, and an AP
         * on the target channel that is the rogue half of a pair is the
         * landing site this announcement is aiming at. */
        int to_twin = 0, to_downgrade = 0;
        for (int j = 0; j < s->beacon_count; j++) {
            const beacon_ap_t *a = &s->beacon_aps[j];
            if (a->channel != e->new_channel) continue;
            if (btm_candidate_is_twin(s, a->bssid)) to_twin = 1;
            /* Composes with #62: landing clients on an AP that offers a
             * downgrade lane is worse than landing them anywhere else. */
            if (a->downgrade_flags) to_downgrade = 1;
        }

        if (!spoofed && !storm && !to_twin) continue;

        int mine = ownership_is_my_bssid(e->bssid);
        char bss[20], ta[20];
        mac_to_str(e->bssid, bss, sizeof(bss));
        mac_to_str(e->ta,    ta,  sizeof(ta));

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "csa:%.17s", bss);
        snprintf(detail, sizeof(detail),
                 "%.17s -> chan %u (op_class %u) mode=%u src=%s%s%s%s%s%s",
                 bss, e->new_channel, e->new_op_class, e->switch_mode,
                 e->source == CSA_SRC_ACTION ? "action" : "beacon",
                 spoofed ? ", forged TA " : "",
                 spoofed ? ta : "",
                 storm ? ", storm" : "",
                 to_twin ? ", target hosts a known twin" : "",
                 mine ? " - YOUR network" : "");
        if (storm && !spoofed && !to_twin)
            snprintf(detail + strlen(detail),
                     sizeof(detail) - strlen(detail),
                     " (%d distinct targets/%ds)", targets, CSA_STORM_WIN_SECS);

        fire(ALERT_TYPE_CSA_ABUSE,
             (spoofed || to_twin || to_downgrade || mine) ? ALERT_SEV_CRIT
                                                          : ALERT_SEV_WARN,
             "CSA_ABUSE", detail, key, NULL, 0, now);
    }
}

/* Spectrum-management elements absent on a designated 5 GHz BSS
 * (#101 slice 3).
 *
 * IEEE 802.11-2020 §11.8 is how an AP publishes the power it is allowed
 * to use: the Country element carries the regulatory maximum, the Power
 * Constraint element (§9.4.2.13) the local reduction below it, and the
 * TPC Report element (§9.4.2.16) the power actually in use. In the
 * 5 GHz plan 802.11h was written for, an AP that sends neither of the
 * latter two has published no ceiling at all. That is the shape a
 * stripped build leaves: hostapd with `ieee80211d=0` / `ieee80211h=0`
 * omits both, and a kit assembled that way keeps the 20 dBm default
 * whatever the local cap is.
 *
 * Scoped to a designated BSS (--my-bssid / --my-ssid), which is how the
 * issue scopes it. Ungated it fires on every third-party 5 GHz AP in RF
 * range — where sloth has no standing to call a posture wrong and the
 * operator has nothing to fix. WARN and never CRIT: the finding is the
 * operator's own equipment being misconfigured, not an attack on them.
 *
 * Three suppressions, each for a different reason:
 *
 *  - 2.4 GHz, where §11.8 does not apply at all.
 *
 *  - 6 GHz, where the element that carries the power limit is the
 *    Transmit Power Envelope (tag 195), not either of these two. Tag
 *    195 is parsed and retained since #101 slice B (reg_6g.h) but this
 *    rule does not read it: the absence of 32 and 35 there is the wrong
 *    element being missing and not a finding. ap_band_label() is
 *    what separates 5 from 6: the channel numbers overlap outright, and
 *    only channel_source settles it (#66, #91).
 *
 *  - phy "legacy", the exemption the issue itself asks for. Pre-802.11h
 *    802.11a gear predates the requirement, so its silence is not
 *    evidence of anything.
 *
 * Absence is read from the retained envelope, which reg_ie_merge()
 * never clears (include/reg_ie.h). That stickiness is what this rule
 * needs rather than something it works around: a *_present flag set by
 * any beacon ever heard from this BSSID stays set, so "absent" means
 * "no beacon from this BSSID has ever carried one" and not "the last
 * one did not". The observation floor is the other half of the same
 * guard - see TPC_ABSENT_MIN_OBSERVED_S.
 *
 * What this does NOT do: it makes no claim about whether the power the
 * AP uses is legal where it stands, and none about whether the country
 * it names is the one it is in. Both need the regulatory table, which
 * is a later slice and gated on an owner decision about how a
 * compiled-in claim about law is framed. It also does not read the
 * Spectrum Management bit in Capability Information (§9.4.1.4), which
 * would turn this from "no ceiling published" into "the AP said it does
 * spectrum management and then did not" - sloth does not retain the
 * capability field, so that corroborator is unavailable today.
 */
void rule_tpc_absent_high_band(const sloth_state_t *s, time_t now) {
    if (!ownership_any()) return;      /* nothing designated - inert */

    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];

        if (!ownership_is_my_bssid(a->bssid) &&
            !ownership_is_my_ssid(a->ssid)) continue;

        if (strcmp(ap_band_label(a->channel, a->channel_source),
                   "5 GHz") != 0) continue;
        if (strcmp(a->phy, "legacy") == 0) continue;

        /* An observation floor has to count OBSERVATIONS. Wall-clock age
         * alone is satisfied by one beacon plus sixty seconds of hearing
         * nothing: on a --hop run sloth can take a single beacon from a
         * designated 5 GHz AP, hop away, never return, and then fire on
         * an entry whose regulatory fields were read exactly once —
         * which is the false positive this floor is documented to
         * prevent. Review supplied that input. So both: enough time AND
         * enough beacons, the second read from a->frame_count, which
         * src/beacon_snoop.c increments per beacon. */
        if (!a->first_seen ||
            now - a->first_seen < TPC_ABSENT_MIN_OBSERVED_S) continue;
        if (a->frame_count < TPC_ABSENT_MIN_BEACONS) continue;

        if (a->reg.power_constraint_present || a->reg.tpc_present) continue;

        char bss[20];
        mac_to_str(a->bssid, bss, sizeof(bss));

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        /* Per BSSID, not per SSID: two designated APs on one ESS are two
         * devices to reconfigure, and one key would hide whichever the
         * operator did not read. */
        snprintf(key, sizeof(key), "tpcabsent:%.17s", bss);
        /* "YOUR network" only when the BSSID matched.
         *
         * The gate above accepts a BSSID match OR an SSID match, and an
         * SSID is a value an attacker writes into a frame — #89 removed
         * it as proof of ownership for exactly this reason. Printed
         * unconditionally, as this shipped, an evil twin beaconing the
         * operator's ESSID from a stripped hostapd gets labelled their
         * own equipment. That population is what the evil-twin rules
         * exist to flag, and the no-tag-32/no-tag-35 shape is this
         * rule's own description of a rogue kit, so the label was
         * actively wrong on the case most worth getting right.
         *
         * An SSID-only match says so instead, and says what it rests
         * on. The rule still fires — the operator may genuinely have an
         * AP sloth has no BSSID for — but the detail no longer asserts
         * ownership the evidence does not carry. */
        const int bssid_known = ownership_is_my_bssid(a->bssid);
        snprintf(detail, sizeof(detail),
                 "%.17s \"%.20s\" ch%d: no Power Constraint (32) and no "
                 "TPC Report (35) in %lds observed over %u beacons - "
                 "Country element %s%s",
                 bss, a->ssid[0] ? a->ssid : "<hidden>", a->channel,
                 (long)(now - a->first_seen),
                 (unsigned)a->frame_count,
                 a->reg.country_present ? a->reg.country : "absent too",
                 bssid_known
                     ? " - YOUR network"
                     : " - matched on SSID only, so this BSSID is not"
                       " confirmed yours");
        fire(ALERT_TYPE_TPC_ABSENT_HIGH_BAND, ALERT_SEV_WARN,
             "TPC_ABSENT", detail, key, NULL, 0, now);
    }
}

/* Fires once when we've seen at least one interface but no WiFi radio
 * is in monitor mode — a WARN that WiFi-SIGINT views (Probe, Beacons,
 * EAPOL, Deauth) will be blind for this session. The single dedup key
 * `nomon:global` prevents re-firing every poll; if the operator later
 * flips a radio into monitor mode, the alert row stays but stops
 * counting up. Passive: we only *observe* the current iface mode. */
void rule_no_monitor_mode(const sloth_state_t *s, time_t now) {
    if (s->iface_count == 0) return;   /* wait until we have iface data */
    for (int i = 0; i < s->iface_count; i++) {
        if (s->ifaces[i].mode == IFACE_MODE_MONITOR) return;
    }
    fire(ALERT_TYPE_NO_MONITOR_MODE, ALERT_SEV_WARN,
         "NO_MONITOR_MODE",
         "no WiFi radio in monitor mode — WiFi SIGINT views will be empty",
         "nomon:global", NULL, 0, now);
}

/* Probe-request flood: single client MAC emitting probe requests at
 * an abnormally high rate. Operationally interesting because:
 *   - active recon tools (kismet, hcxdumptool, wifite) burst probes
 *   - misbehaving / stuck devices DoS themselves with probe loops
 *   - KARMA-baiting attackers may walk a PNL by probing each entry
 *
 * Threshold (#88): PROBE_FLOOD_FRAMES (30) requests inside one sliding
 * PROBE_FLOOD_WIN_SECS (5 s) window — a rate of >= 6/s across the
 * whole window. Normal clients emit a few probes per channel per scan
 * and pause between scans, so 6+/s for 5 s is solidly anomalous. The
 * lifetime frame_count / first_seen / last_seen say nothing about rate:
 * 30 probes over 300 s and 30 over 5 s look identical through them. */
void rule_probe_flood(const sloth_state_t *s, time_t now) {
    /* probe.flood_frames / probe.flood_window_s (#120). The rate is
     * derived from the pair the window detector was run with, so moving
     * either knob moves the predicate here with it. */
    const int    win_s    = (int)tune_val(TUNE_PROBE_FLOOD_WINDOW_S);
    const double min_rate = (double)tune_val(TUNE_PROBE_FLOOD_FRAMES) / win_s;
    for (int i = 0; i < s->probe_count; i++) {
        const probe_client_t *p = &s->probe_clients[i];
        if (!p->flood) continue;                        /* decayed / never */
        /* The rate predicate itself, on the window's evidence: the
         * frames that met the threshold, averaged over the full window
         * they had to fit in. */
        double win_rate = (double)p->burst_frames / win_s;
        if (win_rate < min_rate)                                 continue;
        if (p->burst_span_ms >= (uint32_t)win_s * 1000u)         continue;
        double span_s = p->burst_span_ms / 1000.0;
        double rate   = p->burst_frames / (span_s > 0.001 ? span_s : 0.001);
        char mac_buf[20];
        snprintf(mac_buf, sizeof(mac_buf),
                 "%02x:%02x:%02x:%02x:%02x:%02x",
                 p->mac[0], p->mac[1], p->mac[2],
                 p->mac[3], p->mac[4], p->mac[5]);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key,    sizeof(key),    "probe_flood:%s", mac_buf);
        snprintf(detail, sizeof(detail),
                 "%s sent %d probes in %.1fs (%.1f/s, >= %.0f/s over %ds)"
                 " - active recon / stuck client",
                 mac_buf, p->burst_frames, span_s, rate,
                 min_rate, win_s);
        /* LOW: a probe-happy client is recon noise — same tier as
         * port-scan. Real harm is in PNL leakage, not the probing. */
        fire(ALERT_TYPE_PROBE_FLOOD, ALERT_SEV_LOW,
             "PROBE_FLOOD", detail, key, NULL, 0, now);
    }
}

/* Probing for an operator-designated network (#52, honesty pass #94).
 *
 * A client's PNL is the list of networks it remembers and probes for by
 * name. When one of those is a network the operator designated as
 * theirs, and the client is *not* associated to it, sloth has observed
 * one thing: **this radio asked for your network by name and is not on
 * it.** That is the whole observation, and #94 is about not reporting
 * more than it.
 *
 * The bare observation has at least four innocent explanations, all of
 * which satisfy it exactly: a returning employee whose phone still
 * remembers the SSID, a device roaming between the operator's own APs,
 * a capture that simply did not see the association, and a handset
 * probing with a rotating address while associated under its per-network
 * one. Calling that "reconnaissance" names an intent the evidence does
 * not carry, and these records are the kind that get quoted in a
 * personnel file. So:
 *
 *   - uncorroborated it is LOW with a low confidence, and the detail
 *     says what was seen ("probed for") rather than what it means;
 *   - the reconnaissance framing requires **positive corroboration** —
 *     the same doctrine #89 applied to the evil-twin family: with no
 *     positive evidence, no claim.
 *
 * Association is the exoneration, checked by designated BSSID *or* SSID
 * so --my-ssid alone is enough — the operator does not have to enumerate
 * every BSSID of their own multi-AP deployment. #94 adds the two
 * exonerations that were missing: a correlated sibling address that *is*
 * associated, and the operator's own roster.
 *
 * Deliberately NOT corroborated by a randomised MAC. Probe-request MAC
 * randomisation is default behaviour on current iOS and Android, so it
 * describes the phone population, not the adversary. */

/* How long a device must keep asking before repetition is evidence of
 * anything. A passer-by's phone probes in a burst as it crosses the
 * area; a device that is still asking ten minutes later is doing
 * something else. */
#define RECON_SUSTAIN_S ((int)tune_val(TUNE_RECON_SUSTAIN_S))
#define RECON_SUSTAIN_PROBES ((int)tune_val(TUNE_RECON_SUSTAIN_PROBES))

/* Confidence terms. The ceiling stays well under 100 — every input here
 * is circumstantial and the operator is the one who decides. */
#define RECON_CONF_BASE      25
#define RECON_CONF_SUSTAINED 30
#define RECON_CONF_MULTI     25

static int sta_is_associated_to_designated(const sloth_state_t *s,
                                           const uint8_t mac[6]) {
    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *a = &s->assocs[i];
        if (memcmp(a->sta_mac, mac, 6) != 0) continue;
        if (ownership_is_my_bssid(a->bssid)) return 1;
        if (ownership_is_my_ssid(a->ssid))   return 1;
    }
    return 0;
}

/* The randomised-probe / real-association case. A handset scans with a
 * rotating address and joins with the stable per-SSID one, so matching
 * the exact MAC accused a device that was sitting on the network the
 * whole time. Any reported correlation counts here: for an exoneration
 * the safe error is to stay quiet, so this does not wait for a strong
 * score the way a positive claim would. */
static int correlated_sibling_is_associated(const sloth_state_t *s,
                                            const uint8_t mac[6]) {
    for (int i = 0; i < s->seqnum_correlation_count; i++) {
        const seqnum_correlation_t *c = &s->seqnum_correlations[i];
        const uint8_t *sibling = NULL;
        if      (memcmp(c->mac_a, mac, 6) == 0) sibling = c->mac_b;
        else if (memcmp(c->mac_b, mac, 6) == 0) sibling = c->mac_a;
        if (!sibling) continue;
        if (sta_is_associated_to_designated(s, sibling)) return 1;
    }
    return 0;
}

void rule_my_network_recon(const sloth_state_t *s, time_t now) {
    if (!ownership_any()) return;      /* nothing designated — no work */
    for (int i = 0; i < s->pnl_count; i++) {
        const pnl_client_t *p = &s->pnl_clients[i];

        const char *hit = NULL;
        int designated_hits = 0;
        int n = p->ssid_count;
        if (n > MAX_PNL_SSIDS_PER_CLI) n = MAX_PNL_SSIDS_PER_CLI;
        for (int k = 0; k < n; k++) {
            if (!ownership_is_my_ssid(p->ssids[k])) continue;
            if (!hit) hit = p->ssids[k];
            designated_hits++;
        }
        if (!hit) continue;
        if (sta_is_associated_to_designated(s, p->mac))  continue;
        if (correlated_sibling_is_associated(s, p->mac)) continue;
        /* The operator wrote this one down as theirs. That is the answer
         * to "returning employee" and it outranks every inference. */
        if (ownership_is_known_device(p->mac))           continue;

        /* Corroborators. Both are positive observations; absence of
         * evidence is never one of them — an incomplete capture is the
         * benign explanation this rule exists to respect, so "no
         * association seen anywhere" deliberately does not count. */
        long span = (p->last_seen > p->first_seen)
                  ? (long)(p->last_seen - p->first_seen) : 0;
        int sustained = (span >= RECON_SUSTAIN_S &&
                         p->probe_count >= RECON_SUSTAIN_PROBES);
        int multi     = (designated_hits >= 2);

        int conf = RECON_CONF_BASE;
        if (sustained) conf += RECON_CONF_SUSTAINED;
        if (multi)     conf += RECON_CONF_MULTI;

        char mac_buf[20];
        mac_to_str(p->mac, mac_buf, sizeof(mac_buf));
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "myrecon:%s", mac_buf);

        if (sustained || multi) {
            /* Corroborated: the reconnaissance reading is now supported
             * by something observed, and the detail names which one so
             * the operator can weigh it instead of trusting the label.
             * Still "possible" — corroboration is not proof of intent. */
            snprintf(detail, sizeof(detail),
                     "%s probed for designated network '%.32s' without "
                     "associating - %d probes over %lds - possible recon"
                     "naissance: %s%s%s",
                     mac_buf, hit, p->probe_count, span,
                     sustained ? "sustained probing" : "",
                     (sustained && multi) ? ", " : "",
                     multi ? "names 2+ designated networks" : "");
            /* WARN, not CRIT: a former guest's phone left on a desk in
             * the car park produces this honestly too. */
            fire_conf(ALERT_TYPE_MY_NETWORK_RECON, ALERT_SEV_WARN, conf,
                      "MY_NET_RECON", detail, key, NULL, 0, now);
        } else {
            snprintf(detail, sizeof(detail),
                     "%s probed for designated network '%.32s' without "
                     "associating - %d probes - uncorroborated, benign "
                     "explanations include a returning device or an "
                     "unobserved association",
                     mac_buf, hit, p->probe_count);
            /* LOW: same tier as PROBE_FLOOD. It names the operator's
             * network, which is why it is reported at all, but on its own
             * it is a lead and not a finding. */
            fire_conf(ALERT_TYPE_MY_NETWORK_RECON, ALERT_SEV_LOW, conf,
                      "MY_NET_RECON", detail, key, NULL, 0, now);
        }
    }
}

/* Recurring transit (#54).
 *
 * One device driving past is traffic. The same device driving past
 * three times inside two hours is a circuit, and it is the observation
 * an operator cannot make unaided — nobody remembers which of two
 * hundred MACs they saw forty minutes ago.
 *
 * Severity is WARN, not CRIT: a delivery van on a round, or a neighbour
 * with a short commute, produces this honestly. It is a lead, not a
 * conclusion, and the detail line carries the pass count and closest
 * approach so the operator can judge. */
void rule_recurring_transit(const sloth_state_t *s, time_t now) {
    const long window = tune_val(TUNE_TRANSIT_WINDOW_SECS);
    const int  thresh = (int)tune_val(TUNE_TRANSIT_RECUR_THRESH);
    for (int i = 0; i < s->transit_count; i++) {
        const transit_device_t *d = &s->transits[i];
        int passes = 0;
        for (int k = 0; k < d->pass_n; k++) {
            long age = (long)(now - d->pass_ts[k]);
            if (age < 0) age = 0;
            if (age <= window) passes++;
        }
        if (passes < thresh) continue;

        char mac_buf[20];
        mac_to_str(d->mac, mac_buf, sizeof(mac_buf));
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "transit:%s", mac_buf);
        long span = (long)(d->last_seen - d->pass_ts[0]);
        if (span < 0) span = 0;
        snprintf(detail, sizeof(detail),
                 "%s passed %d times in %ldm (closest %ddBm) - circling",
                 mac_buf, passes, span / 60, (int)d->best_rssi);
        fire(ALERT_TYPE_RECURRING_TRANSIT, ALERT_SEV_WARN,
             "RECURRING_TRANSIT", detail, key, NULL, 0, now);
    }
}

/* Unknown device on a designated network (#55).
 *
 * The payoff from combining the roster with #52's designation: a device
 * associated to a network the operator called theirs, which is not on
 * the roster of devices they recognise. "Someone I do not know is on my
 * client's WiFi" is actionable in a way that neither half is alone.
 *
 * Requires BOTH inputs, so it is silent unless the operator opted into
 * each — and cannot fire noise at anyone who configured neither. It
 * keys on association rather than probing on purpose: per-SSID MAC
 * randomisation is stable across reconnects, so a rostered device keeps
 * its address, whereas probe randomisation rotates constantly and would
 * make every passing handset "unknown".
 *
 * WARN: a contractor's laptop the operator forgot to roster produces
 * this honestly, and the fix is to add it. */
void rule_unknown_device(const sloth_state_t *s, time_t now) {
    if (ownership_known_count() == 0) return;   /* no roster — inert */
    if (!ownership_any())             return;   /* no designation — inert */

    for (int i = 0; i < s->assoc_count; i++) {
        const assoc_t *a = &s->assocs[i];
        int mine = ownership_is_my_bssid(a->bssid) ||
                   ownership_is_my_ssid(a->ssid);
        if (!mine) continue;
        if (ownership_is_known_device(a->sta_mac)) continue;

        char sta[20], bss[20];
        mac_to_str(a->sta_mac, sta, sizeof(sta));
        mac_to_str(a->bssid,   bss, sizeof(bss));
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "unknowndev:%s", sta);
        snprintf(detail, sizeof(detail),
                 "%s on '%.16s' [%s] not in roster%s",
                 sta, a->ssid[0] ? a->ssid : "?", bss,
                 a->sta_random ? " (randomised MAC)" : "");
        fire(ALERT_TYPE_UNKNOWN_DEVICE, ALERT_SEV_WARN,
             "UNKNOWN_DEVICE", detail, key, NULL, 0, now);
    }
}

/* Channel RF degradation (roadmap B3).
 *
 * A sustained retry ratio is the passive signature of a channel that is
 * not working. It is deliberately NOT called "jamming": the same
 * measurement is produced by a microwave oven, a distant client at the
 * edge of range, a hidden node, and a deliberate jammer. sloth reports
 * the observable and leaves attribution to the operator — the detail
 * line carries the ratio and the sample size so they can judge.
 *
 * WARN, not CRIT, for the same reason. And it needs RF_MIN_FRAMES of
 * traffic before it will say anything at all, so a channel the radio
 * merely glanced at cannot trip it. */
void rule_rf_degraded(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->channel_count; i++) {
        const channel_summary_t *c = &s->channels[i];
        if (c->retry_pct < RF_RETRY_DEGRADED_PCT) continue;   /* -1 too */

        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "rfdegraded:%d", c->channel);
        snprintf(detail, sizeof(detail),
                 "ch %d: %d%% retries, %d%% bad-FCS over %u frames "
                 "- interference, hidden node or jamming",
                 c->channel, c->retry_pct,
                 c->badfcs_pct < 0 ? 0 : c->badfcs_pct,
                 (unsigned)c->frames);
        fire(ALERT_TYPE_RF_DEGRADED, ALERT_SEV_WARN,
             "RF_DEGRADED", detail, key, NULL, 0, now);
    }
}

/* PM-bit forgery — Framing Frames, CVE-2022-47522 (#107 shape A).
 *
 * pm_forge_observe() (capture thread) has already found the
 * contradiction: this station sent a PM=0 data frame on one TID
 * within its AP's own beacon interval of a PM=1 Null/QoS-Null it (or
 * something claiming to be it) sent on a different TID. One honest
 * half-duplex radio cannot be both declaring itself asleep and
 * actively transmitting inside that window, so this rule only has to
 * ask whether the lifetime count is non-zero.
 *
 * Deliberately WARN, not CRIT, with no ownership match: sloth has no
 * key and no location fix, so it cannot tell attacker from victim —
 * only that the two declarations disagree. Escalated to CRIT only
 * when the BSSID is operator-designated, per the issue's own
 * correlation rule and the wording discipline #90 established:
 * "pattern consistent with", never "attacker is". */
void rule_pm_forge(const sloth_state_t *s, time_t now) {
    (void)s;
    pm_forge_t tbl[MAX_PM_FORGE_ENTRIES];
    int n = pm_forge_snapshot(tbl, MAX_PM_FORGE_ENTRIES);
    for (int i = 0; i < n; i++) {
        if (tbl[i].contradiction_count == 0) continue;

        char bss[20], sta[20];
        mac_to_str(tbl[i].bssid, bss, sizeof(bss));
        mac_to_str(tbl[i].sta,   sta, sizeof(sta));
        int mine = ownership_is_my_bssid(tbl[i].bssid);

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "pmforge:%s", sta);
        snprintf(detail, sizeof(detail),
                 "%s at %s: PM=0 data contradicted a PM=1 sleep "
                 "declaration %d time(s) - pattern consistent with "
                 "Framing Frames queue manipulation, CVE-2022-47522%s",
                 sta, bss, tbl[i].contradiction_count,
                 mine ? " - YOUR network" : "");
        /* Cites the frame pairs that formed the contradiction (#92):
         * a data frame has no flow sloth can export on for this — the
         * queue manipulation is the 802.11 header — so the evidence
         * ring is the only route back to the bytes. */
        uint64_t ev[PM_FORGE_EVIDENCE_IDS];
        int ev_n = pm_forge_evidence(&tbl[i], ev, PM_FORGE_EVIDENCE_IDS);
        fire_ev(ALERT_TYPE_PM_FORGE, mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
                ev, ev_n, "PM_FORGE", detail, key, NULL, 0, now);
    }
}

/* ── Transmit-queue release after a session change ──
 * #107 shape B, Framing Frames CVE-2022-47522.
 *
 * queue_evict_observe_downlink() (capture thread) has already counted
 * the burst: unicast downlink frames to one station inside
 * QUEUE_EVICT_WINDOW_MS of a session change for that (BSSID, STA), at
 * least QUEUE_EVICT_MIN_FRAMES of them. So this rule only has to ask
 * whether release_count is non-zero — and then how much to claim.
 *
 * That second question is the whole rule. **A bare post-reassociation
 * downlink burst is ordinary roaming**: an AP that has just admitted a
 * station has traffic for it, and on a busy network this fires on every
 * client, all day. The observable is identical to the attack's. So the
 * severity ladder is built on corroboration rather than on the burst,
 * the doctrine #94 wrote down for MY_NET_RECON and docs/wiki/alerts.md
 * §"Corroboration before intent" states generally:
 *
 *   - uncorroborated → LOW at 25 %, reporting the observation with the
 *     benign explanations named. The detail does not use the word
 *     attack, and names no party.
 *   - corroborated by shape A — a PM-bit contradiction for the same
 *     station within QUEUE_EVICT_CORROB_SECS of the release, which is
 *     the issue's own A+B rule — → WARN at 70 %. Something made the AP
 *     buffer this station's traffic, and then the buffer came out
 *     across a session change.
 *   - corroborated AND the BSSID is operator-designated (#52) → CRIT.
 *
 * Ownership deliberately does NOT escalate on its own, which is where
 * this departs from PM_FORGE. The PM-bit contradiction is a thing one
 * honest radio cannot produce, so it is worth a CRIT the moment it is
 * on your own network. A downlink burst after a roam is the single most
 * common event on an operator's own network, and promoting that to CRIT
 * would bury the alert type in exactly the place the operator cares
 * most — the OPEN_SETUP_AP reasoning about not teaching the operator to
 * ignore a type, applied to severity. */
#define QUEUE_EVICT_CORROB_SECS 10

void rule_queue_evict(const sloth_state_t *s, time_t now) {
    (void)s;
    queue_evict_t tbl[MAX_QUEUE_EVICT_ENTRIES];
    int n = queue_evict_snapshot(tbl, MAX_QUEUE_EVICT_ENTRIES);
    for (int i = 0; i < n; i++) {
        const queue_evict_t *q = &tbl[i];
        if (q->release_count == 0) continue;
        /* Recency bound. release_count is a LIFETIME figure that only
         * resets in queue_evict_clear(), so without this one roam fires
         * this key for the rest of the run, and a site with normal
         * roaming saturates the engine: the table holds
         * MAX_QUEUE_EVICT_ENTRIES rows and MAX_ALERTS is the same
         * number, which review measured as alert_count == 128 from 128
         * distinct (BSSID,STA) releases, evicting every other rule's
         * findings. Same defect class as #105's dedup key, reached from
         * the other direction — there the fan-out was remote-chosen,
         * here it is unbounded in time.
         *
         * Keyed on the most recent release rather than on a decaying
         * count: "this happened in the last QUEUE_EVICT_REPORT_SECS" is
         * the question an operator is asking, and a station that keeps
         * doing it keeps re-firing with a rising count, which is what
         * the alert engine's own dedup is for. */
        if (q->last_release_ts <= 0 ||
            now - q->last_release_ts > tune_val(TUNE_QUEUE_EVICT_REPORT_SECS))
            continue;

        /* Shape A for the same station, close enough in time to be
         * about the same session. Absolute difference on purpose: the
         * PM forgery normally precedes the release, but sloth hops
         * channels and may well have heard the two out of order. */
        int corrob = 0;
        long corrob_gap = 0;
        pm_forge_t pf;
        if (pm_forge_lookup(q->sta, &pf) && pf.contradiction_count > 0 &&
            pf.last_contradiction_ts > 0) {
            long d = (long)(pf.last_contradiction_ts > q->last_release_ts
                            ? pf.last_contradiction_ts - q->last_release_ts
                            : q->last_release_ts - pf.last_contradiction_ts);
            if (d <= QUEUE_EVICT_CORROB_SECS) { corrob = 1; corrob_gap = d; }
        }

        int mine = ownership_is_my_bssid(q->bssid);
        alert_sev_t sev = corrob ? (mine ? ALERT_SEV_CRIT : ALERT_SEV_WARN)
                                 : ALERT_SEV_LOW;
        int conf = corrob ? 70 : 25;

        char bss[20], sta[20];
        mac_to_str(q->bssid, bss, sizeof(bss));
        mac_to_str(q->sta,   sta, sizeof(sta));

        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "qevict:%s@%s", sta, bss);
        if (corrob)
            snprintf(detail, sizeof(detail),
                     "%s at %s: %u downlink frames in %d ms after %s, "
                     "x%u - corroborated by a PM-bit contradiction %lds "
                     "away (PM_FORGE) - pattern consistent with Framing "
                     "Frames transmit-queue release, CVE-2022-47522%s",
                     sta, bss, q->last_release_frames,
                     q->last_release_span_ms,
                     queue_evict_src_name(q->last_release_src),
                     q->release_count, corrob_gap,
                     mine ? " - YOUR network" : "");
        else
            snprintf(detail, sizeof(detail),
                     "%s at %s: %u downlink frames in %d ms after %s, "
                     "x%u - uncorroborated, benign explanations include an "
                     "ordinary roam or a buffered-traffic flush; see "
                     "CVE-2022-47522%s",
                     sta, bss, q->last_release_frames,
                     q->last_release_span_ms,
                     queue_evict_src_name(q->last_release_src),
                     q->release_count,
                     mine ? " - YOUR network" : "");
        /* The session-change frame and the released burst (#92). The
         * confidence ladder above is the reason this is fire_inv() and
         * not fire_ev(): an uncorroborated release is reported at 25 %,
         * and dropping that to cite frames would trade one honesty for
         * another. */
        fire_inv(ALERT_TYPE_QUEUE_EVICT, sev, conf, NULL,
                 TWIN_CLASS_UNKNOWN, WIRED_ATTACH_UNKNOWN, NULL,
                 q->release_ids, q->release_id_count,
                 "QUEUE_EVICT", detail, key, NULL, 0, now);
    }
}

/* Management-frame fuzzing / malformed-IE beacons — issue #33.
 *
 * mdk4 mode m, crafted aireplay-ng frames, and BroadPwn-class malformed
 * vendor-IE probes all produce beacons whose IEs don't parse cleanly:
 * an IE length that runs off the frame end, an SSID longer than the
 * 32-byte maximum, or a truncated RSN IE. beacon_parse counts these per
 * frame; beacon_record accumulates them per BSSID. A well-formed AP
 * leaves all three at zero, so any accumulation is signal.
 *
 * Score = ie_overruns + oversize_ssid + truncated_rsn (each capped so a
 * single pathological BSSID can't dominate). WARN at >=3, CRIT at >=5. */
#define MGMT_FUZZ_WARN ((int)tune_val(TUNE_MGMT_FUZZ_WARN))
#define MGMT_FUZZ_CRIT ((int)tune_val(TUNE_MGMT_FUZZ_CRIT))

void rule_mgmt_fuzz(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->beacon_count; i++) {
        const beacon_ap_t *a = &s->beacon_aps[i];
        int score = (int)a->fuzz_ie_overruns +
                    (int)a->fuzz_oversize_ssid +
                    (int)a->fuzz_truncated_rsn;
        if (score < MGMT_FUZZ_WARN) continue;

        char bssid[20];
        fmt_bssid(bssid, a->bssid);
        char key[ALERT_KEY_LEN];
        char detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mgmtfuzz:%s", bssid);
        snprintf(detail, sizeof(detail),
                 "BSSID %s malformed IEs: %u overrun / %u oversize-SSID / "
                 "%u truncated-RSN - 802.11 mgmt fuzzing",
                 bssid, a->fuzz_ie_overruns, a->fuzz_oversize_ssid,
                 a->fuzz_truncated_rsn);
        fire(ALERT_TYPE_MGMT_FUZZ,
             score >= MGMT_FUZZ_CRIT ? ALERT_SEV_CRIT : ALERT_SEV_WARN,
             "MGMT_FUZZ", detail, key, NULL, 0, now);
    }
}
