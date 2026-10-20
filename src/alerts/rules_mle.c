/* 802.11be Multi-Link Element rules (src/mle.c holds the parser).
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rules.h"
#include "engine_internal.h"
#include "alert_key.h"

/* Multi-Link Element Per-STA Profile link_id out of range or repeated —
 * CVE-2026-58374 / w1.fi 2026-1 (#104). hostapd_process_ml_assoc_req()'s
 * links[] storage has no slot for a link_id of 15; a frame that claims
 * one, or that names the same link_id twice inside one MLE, is exactly
 * the shape of the crash. mle_parse() flags this per frame and
 * mle_observe() accumulates it onto the MLD's persisted entry, so this
 * rule only has to ask whether that lifetime count is non-zero. One
 * frame is enough to report: there is no benign reason a conformant
 * MLD would ever send it. */
void rule_mle_invalid_link_id(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *m = &s->mlds[i];
        if (!m->malformed_link_id_total) continue;

        char mac[20];
        mac_to_str(m->mld_mac, mac, sizeof(mac));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mle_link_id:%s", mac);
        snprintf(detail, sizeof(detail),
                 "MLD %s sent a Multi-Link Element Per-STA Profile with "
                 "link_id=%u (valid range is 0-14; %u such frame(s) seen) "
                 "- CVE-2026-58374",
                 mac, (unsigned)m->bad_link_id,
                 (unsigned)m->malformed_link_id_total);
        fire(ALERT_TYPE_MLE_INVALID_LINK_ID, ALERT_SEV_WARN,
             "MLE_INVALID_LINK_ID", detail, key, NULL, 0, now);
    }
}

/* MLE Common Info Length mismatch — CVE-2026-58374 / w1.fi 2026-1
 * (#104 slice 2). The Common Info Length field covers itself plus the
 * mandatory MLD MAC (minimum 7) and bounds where Link Info starts; a
 * declared value that violates either is the buffer-overread shape the
 * advisory's eight parsing gaps share — trusting it blindly to find
 * Link Info would read past the element. mle_parse() flags this per
 * frame and mle_observe() accumulates it onto the MLD's persisted
 * entry, so this rule only has to ask whether that lifetime count is
 * non-zero. WARN, same as the sibling link_id rule: one frame is
 * enough, and there is no benign reason a conformant MLD ever sends a
 * length this shape. */
void rule_mle_common_info_len_bad(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *m = &s->mlds[i];
        if (!m->malformed_common_info_len_total) continue;

        char mac[20];
        mac_to_str(m->mld_mac, mac, sizeof(mac));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mle_common_info_len:%s", mac);
        snprintf(detail, sizeof(detail),
                 "MLD %s sent a Multi-Link Element with Common Info "
                 "Length=%u (must be >=7 and fit inside the element; "
                 "%u such frame(s) seen) - CVE-2026-58374 class",
                 mac, (unsigned)m->bad_common_info_len,
                 (unsigned)m->malformed_common_info_len_total);
        fire(ALERT_TYPE_MLE_COMMON_INFO_LEN_BAD, ALERT_SEV_WARN,
             "MLE_COMMON_INFO_LEN_BAD", detail, key, NULL, 0, now);
    }
}

/* MLE Link Info subelement bounds overrun — CVE-2026-58374 / w1.fi
 * 2026-1 (#104 slice 3). The subelement chain must tile Link Info
 * exactly; a declared subelement length that reaches past the enclosing
 * element, or a trailing fragment too short to hold a subelement header,
 * means the summed lengths exceed the container.
 *
 * CRIT where the two sibling MLE rules are WARN, and the difference is
 * real rather than a severity preference: those report a length *shaped*
 * to cause an overread, this one reports the overrun itself — the
 * subelement chain already extends past the buffer the sender declared,
 * so a parser that walked it without this bound has read off the end.
 * There is no benign reading of it: no padding is defined between MLE
 * subelements, so a conformant sender cannot produce either shape. */
void rule_mle_subelem_overrun(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *m = &s->mlds[i];
        if (!m->malformed_subelem_len_total) continue;

        char mac[20];
        mac_to_str(m->mld_mac, mac, sizeof(mac));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mle_subelem_overrun:%s", mac);
        snprintf(detail, sizeof(detail),
                 "MLD %s sent a Multi-Link Element whose Link Info "
                 "subelement chain overruns the element by %u byte(s) "
                 "(declared subelement length=%u; %u such frame(s) seen) "
                 "- CVE-2026-58374 class",
                 mac, (unsigned)m->subelem_overrun_bytes,
                 (unsigned)m->bad_subelem_len,
                 (unsigned)m->malformed_subelem_len_total);
        fire(ALERT_TYPE_MLE_SUBELEM_OVERRUN, ALERT_SEV_CRIT,
             "MLE_SUBELEM_OVERRUN", detail, key, NULL, 0, now);
    }
}

/* MLD MAC collision — IEEE 802.11be §9.4.2.312 (#104 slice 4). A
 * Per-STA Profile link_id names one specific affiliated radio of the
 * MLD, and its address is stable for the life of the association.
 * mle_observe() keeps the first address bound to a (MLD MAC, link_id)
 * pair and counts, rather than merges, any later frame that names the
 * same pair with a different address — that is not a new subset of one
 * device's links, it is two radios claiming the same link identity
 * under the same stable MLD MAC. CRIT: unlike the sibling CVE-2026-58374
 * rules, this is not a value shaped to crash a parser — it is one
 * identity, actively contested by two different addresses, which is
 * either an MLD impersonation attempt or a real address collision
 * either way worth immediate attention. */
void rule_mld_mac_collision(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *m = &s->mlds[i];
        if (!m->mac_collision_total) continue;

        char mac[20], coll[20];
        mac_to_str(m->mld_mac, mac, sizeof(mac));
        mac_to_str(m->collision_mac, coll, sizeof(coll));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mld_mac_collision:%s", mac);
        snprintf(detail, sizeof(detail),
                 "MLD %s link_id %u was bound to one affiliated address, "
                 "then reported with a different one (%s) - two radios "
                 "claiming one Multi-Link identity (%u such frame(s) seen) "
                 "- IEEE 802.11be 9.4.2.312",
                 mac, (unsigned)m->collision_link_id, coll,
                 (unsigned)m->mac_collision_total);
        fire(ALERT_TYPE_MLD_MAC_COLLISION, ALERT_SEV_CRIT,
             "MLD_MAC_COLLISION", detail, key, NULL, 0, now);
    }
}

/* Cross-link cipher / PMF downgrade inside one Multi-Link element
 * (#104 slice 5, IEEE 802.11be §9.4.2.312, MITRE T1557).
 *
 * A Multi-Link Device runs several radios under one identity and a
 * benign one runs one security posture across all of them. Two Per-STA
 * Profiles of a single MLE that each carry their own explicit RSNE and
 * disagree — one requiring management-frame protection while another
 * does not, or one offering GCMP-256/CCMP-256 while another tops out at
 * CCMP-128/TKIP — advertise the weaker radio as a lane worth taking,
 * which is exactly what an adversary-in-the-middle needs a client to do.
 *
 * WARN, not CRIT, and the distinction is the same structural one slice 3
 * drew: this is a posture mismatch being advertised, not an overrun that
 * has already happened. Nothing here says a client took the weak lane.
 *
 * The parse side compares only links with an explicit RSNE — an omitted
 * one is inherited from the reporting AP under 802.11be inheritance, so
 * absence is not weakness. See src/mle.c. */
void rule_mle_cross_link_cipher_downgrade(const sloth_state_t *s,
                                          time_t now) {
    for (int i = 0; i < s->mld_count; i++) {
        const sloth_mld_t *m = &s->mlds[i];
        if (!m->cross_link_cipher_downgrade_total) continue;

        char mac[20];
        mac_to_str(m->mld_mac, mac, sizeof(mac));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        snprintf(key, sizeof(key), "mle_cipher_downgrade:%s", mac);
        /* The cipher mismatch is the finding and names its own pair.
         * The PMF mismatch rides along as CONTEXT with its own pair, and
         * the text says the standard permits it — otherwise an operator
         * reads two clauses as two problems. The two arms carry separate
         * link pairs because they can involve different links; they used
         * to share one, and whichever branch ran second overwrote it
         * while both flags stayed set, so the pair printed was false of
         * one of the clauses. */
        char pmf_note[128] = "";
        if (m->downgrade_pmf_mismatch)
            snprintf(pmf_note, sizeof(pmf_note),
                     " - also: link_id %u negotiates PMF where link_id %u "
                     "requires it, which the standard permits and is not "
                     "itself a downgrade",
                     (unsigned)m->pmf_mismatch_link_id,
                     (unsigned)m->pmf_mismatch_peer_link_id);
        snprintf(detail, sizeof(detail),
                 "MLD %s advertises link_id %u with a weaker pairwise "
                 "cipher than its sibling link_id %u in the same "
                 "Multi-Link element - %u such frame(s) seen%s"
                 " - IEEE 802.11be 9.4.2.312",
                 mac, (unsigned)m->downgrade_link_id,
                 (unsigned)m->downgrade_peer_link_id,
                 (unsigned)m->cross_link_cipher_downgrade_total,
                 pmf_note);
        fire(ALERT_TYPE_MLE_CROSS_LINK_CIPHER_DOWNGRADE, ALERT_SEV_WARN,
             "MLE_CROSS_LINK_CIPHER_DOWNGRADE", detail, key, NULL, 0, now);
    }
}

/* Reconfiguration Multi-Link element from a BSSID that has never
 * advertised a Basic MLE (#104 slice 6, IEEE 802.11be-2024 §9.4.2.322,
 * MITRE T1669).
 *
 * A Reconfiguration MLE announces that an AP MLD is changing its set of
 * affiliated APs — in a Beacon or Probe Response, that an affiliated AP
 * is about to be removed, with a countdown. Clients act on it by moving
 * off the link. Only an AP affiliated with an AP MLD has such a change
 * to announce, and that AP states its membership with a Basic MLE in the
 * same frames. A BSSID that sends the announcement without ever having
 * made the claim is not describing itself: the shape is a forged
 * announcement aimed at steering clients off a link.
 *
 * WARN, and the detail says "corroborates", not "confirms": sloth hears
 * the frame, not what any client did about it. Sticky per BSSID like the
 * sibling MLE rules, and cites the frame from the evidence ring. */
void rule_mle_reconfig_no_mlo(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mle_bss_count; i++) {
        const sloth_mle_bss_t *b = &s->mle_bss[i];
        if (!b->reconfig_no_mlo_total) continue;

        char bssid[20];
        mac_to_str(b->bssid, bssid, sizeof(bssid));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "mle_reconfig_no_mlo");
        akey_mac(&k, b->bssid);
        if (!akey_end(&k)[0]) continue;
        snprintf(detail, sizeof(detail),
                 "BSSID %s sent a Reconfiguration Multi-Link element in a "
                 "%s without ever advertising a Basic Multi-Link element "
                 "(%u such frame(s) seen) - corroborates a forged AP MLD "
                 "reconfiguration, does not confirm one - IEEE 802.11be-2024 "
                 "9.4.2.322",
                 bssid,
                 b->reconfig_no_mlo_subtype == 5 ? "Probe Response" : "Beacon",
                 (unsigned)b->reconfig_no_mlo_total);
        const uint64_t ev[1] = { b->reconfig_no_mlo_ev };
        fire_ev(ALERT_TYPE_MLE_RECONFIG_NO_MLO, ALERT_SEV_WARN,
                ev, ev[0] ? 1 : 0,
                "MLE_RECONFIG_NO_MLO", detail, key, NULL, 0, now);
    }
}

/* A BSSID's Probe Response names a different AP MLD than its Beacon
 * (#104 slice 6, IEEE 802.11be-2024 §9.4.2.322, MITRE T1669).
 *
 * Both frames are one BSS describing its own membership of an AP MLD,
 * so the two fields both carry for that — the Basic MLE's MLD MAC
 * Address and the BSS's own Link ID — cannot differ between them while
 * the AP MLD is unchanged. Two answers for one BSSID inside
 * MLE_PR_BEACON_WIN_SECS is the shape of a second transmitter answering
 * probes under that BSSID with another MLD identity.
 *
 * What is NOT compared is the point of the rule's shape: Per-STA
 * Profiles (a multi-link Probe Response carries complete ones, a Beacon
 * none), an AP MLD ID (present only in some Probe Responses), and the
 * BSS Parameters Change Count (moves on every critical update). See
 * src/mle.c. WARN; the detail names both sides and does not say which
 * is genuine, because sloth cannot tell. */
void rule_mle_pr_beacon_diff(const sloth_state_t *s, time_t now) {
    for (int i = 0; i < s->mle_bss_count; i++) {
        const sloth_mle_bss_t *b = &s->mle_bss[i];
        if (!b->pr_beacon_diff_total) continue;

        char bssid[20], bmac[20], pmac[20];
        mac_to_str(b->bssid, bssid, sizeof(bssid));
        mac_to_str(b->diff_beacon_mld_mac, bmac, sizeof(bmac));
        mac_to_str(b->diff_pr_mld_mac, pmac, sizeof(pmac));
        char key[ALERT_KEY_LEN], detail[ALERT_DETAIL_LEN];
        akey_t k;
        akey_begin(&k, key, sizeof(key), "mle_pr_beacon_diff");
        akey_mac(&k, b->bssid);
        if (!akey_end(&k)[0]) continue;
        char what[112];
        if (b->diff_mld_mac && b->diff_link_id)
            snprintf(what, sizeof(what),
                     "MLD %s link_id %u in its Beacon but MLD %s link_id %u",
                     bmac, (unsigned)b->diff_beacon_link_id,
                     pmac, (unsigned)b->diff_pr_link_id);
        else if (b->diff_mld_mac)
            snprintf(what, sizeof(what),
                     "MLD %s in its Beacon but MLD %s", bmac, pmac);
        else
            snprintf(what, sizeof(what),
                     "link_id %u in its Beacon but link_id %u",
                     (unsigned)b->diff_beacon_link_id,
                     (unsigned)b->diff_pr_link_id);
        snprintf(detail, sizeof(detail),
                 "BSSID %s names %s in a Probe Response within %ds "
                 "(%u such frame(s) seen) - corroborates a second "
                 "transmitter for this BSSID, not which one is genuine - "
                 "IEEE 802.11be-2024 9.4.2.322",
                 bssid, what, MLE_PR_BEACON_WIN_SECS,
                 (unsigned)b->pr_beacon_diff_total);
        uint64_t ev[2];
        int ev_n = 0;
        if (b->diff_beacon_ev) ev[ev_n++] = b->diff_beacon_ev;
        if (b->diff_pr_ev)     ev[ev_n++] = b->diff_pr_ev;
        fire_ev(ALERT_TYPE_MLE_PR_BEACON_DIFF, ALERT_SEV_WARN, ev, ev_n,
                "MLE_PR_BEACON_DIFF", detail, key, NULL, 0, now);
    }
}
