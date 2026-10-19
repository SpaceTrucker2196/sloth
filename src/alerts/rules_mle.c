/* 802.11be Multi-Link Element rules (src/mle.c holds the parser).
 *
 * Moved out of src/alerts.c unchanged (#118) bar linkage: each rule is
 * reached through g_alert_rules[], so it is no longer static. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "rules.h"
#include "engine_internal.h"

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
