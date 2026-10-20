#include <string.h>
#include <pthread.h>

#include "mle.h"
#include "bytes.h"
#include "rsn_ie.h"
#include "sensor_health.h"

static sloth_mld_t     g_mld[SLOTH_MLD_MAX];
static int             g_mld_n;
/* Per-BSSID Multi-Link advertisement (#104 slice 6), under the same
 * lock: both tables are written from the monitor thread and read by
 * one snapshot. */
static sloth_mle_bss_t g_bss[SLOTH_MLE_BSS_MAX];
static int             g_bss_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static int mac_is_usable(const uint8_t m[6]) {
    if (m[0] & 0x01) return 0;
    for (int i = 0; i < 6; i++) if (m[i]) return 1;
    return 0;
}

/* Extract the strongest pairwise cipher and the MFPR bit from the RSNE
 * in an element list. Returns 1 only when the chain tiles `len`
 * **exactly** and carries a readable RSNE.
 *
 * Exact tiling is the guard, not a nicety — see the caller. Any
 * internal inconsistency (a declared element body past the end, an RSNE
 * whose own counts walk off its length) returns 0: a posture read from
 * a chain that does not add up is worse than no posture at all, and the
 * bounds faults in this element already have their own three rules.
 *
 * The RSNE itself is decoded by rsn_ie_parse() (#128) — this file kept
 * its own copy, with its own cipher-rank table and an unvalidated AKM
 * skip, until then. An RSNE with an undefined Version, a truncated
 * field, or no RSN Capabilities is unusable here: Capabilities is
 * optional in the element's grammar, and a link that omits it has not
 * said MFPR=0, it has said nothing. */
static int sta_profile_rsn(const uint8_t *p, int len,
                           int *best_rank, int *mfpr) {
    int found = 0, rank = 0, req = 0;

    tlv_it_t it;
    uint16_t tag; int tln; const uint8_t *body;
    tlv_init(&it, p, len);
    while (tlv_next(&it, &tag, &tln, &body) == TLV_OK) {
        if (tag == 48 && tln >= 8) {
            rsn_ie_t r;
            if (!rsn_ie_parse(body, tln, &r) || r.truncated || !r.has_caps)
                return 0;
            int cr = rsn_cipher_rank_best(r.pairwise_bits);
            if (cr > rank) rank = cr;
            req   = r.mfpr;
            found = 1;
        }
    }
    /* The chain must tile the region exactly (tlv_exact): an element
     * running past the end, or a trailing octet too short to begin one,
     * means it never tiled — which is also what a wrong fixed-field
     * prefix looks like from here.
     *
     * Deliberately NOT a parse fault (#126). An association request's
     * per-STA profile carries a different prefix than the beacon form
     * this assumes, so a non-tiling chain is the expected result on a
     * well-formed frame there, and counting it would report a fault on
     * every Wi-Fi 7 association. */
    if (!tlv_exact(&it) || !found) return 0;
    *best_rank = rank;
    *mfpr      = req;
    return 1;
}

int mle_parse(const uint8_t *ie_body, int len, sloth_mld_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    /* ExtID(1) + Control(2) + CommonInfoLen(1) + MLD MAC(6) */
    if (!ie_body || len < 10) return 0;
    if (ie_body[0] != MLE_EXT_ID) return 0;

    uint16_t ctl  = (uint16_t)(ie_body[1] | (ie_body[2] << 8));
    int      type = ctl & 0x0007;
    /* Only the Basic variant carries an MLD MAC in this position. The
     * other variants share the container and mean different things;
     * reading one as Basic takes an "MLD address" from a field that is
     * not one, which is worse than not decoding it at all. */
    if (type != MLE_TYPE_BASIC) return 0;

    /* Control bits 4-15 are the Presence Bitmap, and in the Basic
     * variant bit 4 is Link ID Info Present — NOT "MLD MAC Address
     * Present" (#129). The Basic MLE's MLD MAC Address is unconditional:
     * the first subfield of Common Info after Common Info Length.
     * "MLD MAC Address Present" is a Probe Request / Reconfiguration
     * variant bit, and those variants are refused above.
     *
     * Until #129 this function refused a Basic MLE with bit 4 clear.
     * AP MLDs set it in Beacon/Probe Response, so the AP side worked;
     * a non-AP MLD's (Re)Association Request MLE leaves it clear, so
     * the client path in src/assoc_track.c never recorded a client MLD.
     *
     * Bit assignments from hostapd src/common/ieee802_11_defs.h
     * (BASIC_MULTI_LINK_CTRL_PRES_LINK_ID 0x0010, then BSS Parameters
     * Change Count 0x0020, Medium Synchronization Delay 0x0040, EML
     * Capabilities 0x0080, MLD Capabilities 0x0100, AP MLD ID 0x0200)
     * and Wireshark epan/dissectors/packet-ieee80211.c ("Link ID Info
     * Present" mask 0x0010; Common Info reads MLD MAC unconditionally,
     * then Link ID Info when present). The two agree; the paywalled
     * IEEE 802.11be-2024 text itself was not read.
     *
     * The Link ID Info octet is not decoded here: Link Info is found
     * through the declared Common Info Length below, which already
     * steps over it and every other optional field the bitmap names. */

    int common_off = 3;                 /* after ExtID + Control */

    /* The MLD MAC Address always sits at this fixed offset in a Basic
     * MLE — its position does not depend on the Common Info Length
     * value or the Presence Bitmap, so reading it is safe whatever
     * those attacker-controlled bytes claim. `len >= 10` (checked above)
     * guarantees the six bytes exist regardless of what follows. */
    memcpy(out->mld_mac, ie_body + common_off + 1, 6);
    if (!mac_is_usable(out->mld_mac)) return 0;

    int common_len = ie_body[common_off];

    /* CVE-2026-58374 / w1.fi 2026-1 (#104 slice 2): the length covers
     * itself, so it must at least hold itself plus the mandatory MLD
     * MAC (7), and it must not claim a Link Info start past the
     * element's own bounds. Either shape is the buffer-overread
     * signature the advisory's other parsing gaps share — flag it and
     * stop. We already have identity (the MAC above); we do not have a
     * safe offset to continue into Link Info. */
    if (common_len < 7 || common_off + common_len > len) {
        out->malformed_common_info_len = 1;
        out->bad_common_info_len = (uint8_t)common_len;
        sh_parse_fault_note(SH_PF_MLE_MALFORMED);
        return 1;
    }

    /* Link Info starts where Common Info ends. Using the declared
     * length rather than summing the optional fields present means a
     * later amendment adding one does not silently shift every link
     * address that follows. */
    int off = common_off + common_len;
    unsigned seen_link_ids = 0;   /* bitmask over the 0-15 field width */

    /* Cross-link posture accumulators (#104 slice 5). Only extremes are
     * kept rather than a per-link array: the finding is that two links
     * of one MLE disagree, so the weakest and the strongest answer it
     * for any number of links, including more than the three the roster
     * can store. */
    int rsn_links = 0;              /* links carrying an explicit RSNE */
    int lo_rank = 0, hi_rank = 0;
    int lo_rank_link = 0, hi_rank_link = 0;
    int mfpr_set_link = -1, mfpr_clear_link = -1;

    /* The subelement chain runs on the shared iterator (#126), whose
     * overrun policy — stop, yield nothing further — is exactly the
     * rule this element needs; the two fault shapes it reports are
     * classified after the loop. */
    tlv_it_t it;
    uint16_t sid; int slen; const uint8_t *sbody;
    tlv_init(&it, ie_body + off, len - off);
    while (tlv_next(&it, &sid, &slen, &sbody) == TLV_OK) {
        if (sid == MLE_SUBELEM_PER_STA && slen >= 3) {
            const uint8_t *p = sbody;
            /* STA Control(2): bits 0-3 Link ID, bit 5 MAC Address
             * Present. Then STA Info Length(1), then the affiliated
             * address when present. */
            uint16_t sc = (uint16_t)(p[0] | (p[1] << 8));
            int link_id = sc & 0x000f;
            int mac_present = (sc & 0x0020) != 0;
            int info_len = p[2];

            /* CVE-2026-58374 / w1.fi 2026-1: the sanctioned range is
             * 0-14 — hostapd's own links[] storage has no slot 15, and
             * a link_id repeated inside one MLE names the same link
             * twice. Checked unconditionally, independent of whether a
             * MAC follows: the vulnerable field is Link ID itself, not
             * whatever comes after it. */
            if (link_id >= 15 || (seen_link_ids & (1u << link_id))) {
                out->malformed_link_id = 1;
                out->bad_link_id = (uint8_t)link_id;
            } else {
                seen_link_ids |= (1u << link_id);
            }
            /* #104 slice 5: the STA Profile field follows the STA Info
             * field, whose declared length counts itself — the same
             * declared-length skip Common Info uses above, and
             * draft-revision-proof for the same reason.
             *
             * Only a Complete Profile (STA Control bit 4) is read. A
             * partial profile is a delta against the reporting AP and
             * says nothing about that link's posture on its own.
             *
             * In a Beacon or Probe Response the STA Profile begins with
             * a 2-octet Capability Information field and then the
             * element list; that is what cfg80211's
             * cfg80211_parse_ml_elem_sta_data reads, and it is the only
             * frame type whose prefix we are prepared to assert. sloth
             * also hands association-request MLEs to this parser
             * (src/assoc_track.c), and those carry a different fixed
             * prefix, so sta_profile_rsn() requires the element chain to
             * tile the remainder *exactly*: a wrong prefix then yields
             * no finding instead of a wrong one. Profiles fragmented
             * across Fragment subelements are not reassembled and fail
             * the same check. */
            int complete = (sc & 0x0010) != 0;
            int prof_off = 2 + info_len;
            /* The `prof_off + 2 <= slen` arm is belt-and-braces, stated
             * because it reads like the bound that keeps the read in
             * range and is not: a declared STA Info Length past the
             * subelement's end yields a non-positive region length,
             * which sta_profile_rsn()'s tiling check already rejects
             * without dereferencing anything. Removing this arm leaves
             * the suite green and ASan quiet (measured, #104 slice 5) —
             * it is kept for the explicit bound, not for a fault it is
             * the only thing catching. */
            if (complete && info_len >= 1 && prof_off + 2 <= (int)slen) {
                int rank = 0, mfpr = 0;
                if (sta_profile_rsn(p + prof_off + 2,
                                    (int)slen - prof_off - 2,
                                    &rank, &mfpr)) {
                    rsn_links++;
                    if (mfpr) { if (mfpr_set_link   < 0) mfpr_set_link   = link_id; }
                    else      { if (mfpr_clear_link < 0) mfpr_clear_link = link_id; }
                    if (rank) {
                        if (!lo_rank || rank < lo_rank) {
                            lo_rank = rank; lo_rank_link = link_id;
                        }
                        if (rank > hi_rank) {
                            hi_rank = rank; hi_rank_link = link_id;
                        }
                    }
                }
            }

            if (mac_present && info_len >= 7 && slen >= 3 + 6) {
                const uint8_t *lm = p + 3;
                if (mac_is_usable(lm)) {
                    if (out->link_count < SLOTH_MLD_MAX_LINKS) {
                        memcpy(out->link_mac[out->link_count], lm, 6);
                        out->link_id[out->link_count] = (uint8_t)link_id;
                        out->link_count++;
                    } else {
                        out->links_truncated = 1;
                    }
                }
            }
        }
    }
    if (it.status == TLV_OVERRUN) {
        /* CVE-2026-58374 / w1.fi 2026-1 (#104 slice 3): the chain has to
         * tile Link Info exactly. `at` is where the subelement that did
         * not fit begins; the iterator leaves its offset there. */
        const int at = off + it.off;
        out->malformed_subelem_len = 1;
        if (at + 2 > len) {
            /* A tail too short to hold even the 2-byte ID/length header
             * — no padding is defined between subelements, so this is
             * already a chain whose declared lengths overshot. */
            out->subelem_overrun_bytes = (uint16_t)(at + 2 - len);
        } else {
            /* ...and the common case of the same fault: a declared body
             * that reaches past the element's end, which is the
             * successful overread a trusting parser would perform. There
             * is no safe offset to continue from. */
            const uint8_t bad = ie_body[at + 1];
            out->bad_subelem_len = bad;
            out->subelem_overrun_bytes = (uint16_t)(at + 2 + (int)bad - len);
        }
    }

    /* Two or more links of ONE Multi-Link element, each with its own
     * explicit RSNE, that disagree on management-frame protection or on
     * pairwise-cipher strength. A benign MLD runs one posture across
     * its radios; a weaker link is the lane an adversary-in-the-middle
     * wants a client steered onto.
     *
     * Links without an RSNE are not compared at all. Under 802.11be
     * profile inheritance an omitted element is inherited from the
     * reporting AP, so absence means "same as the AP" — reading it as
     * "insecure" is the false positive this rule exists to avoid.
     *
     * Not evaluated on a frame that already overran its subelement
     * chain: posture inferred from a chain whose declared lengths do
     * not add up would be a claim about bytes we are not sure we read.
     *
     * Deliberately narrow. Two links whose pairwise bitmaps differ but
     * whose strongest suite and MFPR bit agree are not flagged — that
     * is a differing offer, not a downgrade, and the operator decision
     * this rule feeds is "is one radio weaker", not "are the lists
     * identical". A Non-Inheritance element (ext ID 56) explicitly
     * refusing the AP's RSNE is also not decoded, so a link that
     * suppresses inheritance without supplying its own RSNE reads here
     * as an inheriting link. */
    /* `rsn_links >= 2` is redundant — both conditions below already
     * require two distinct RSNE-bearing links — and is kept only
     * because it states the precondition the rule is about. No test
     * distinguishes its removal, and none claims to. */
    /* Also gated on malformed_link_id, not only on malformed_subelem_len.
     * A frame carrying the SAME link_id twice already fires
     * MLE_INVALID_LINK_ID, and reading a posture across it produces a
     * finding whose "weaker link" and its "sibling" are the same link —
     * review built that input (two Complete Profiles, both link_id 3)
     * and got downgrade_link_id == downgrade_peer_link_id. A comparison
     * between two links needs two links. */
    if (!out->malformed_subelem_len && !out->malformed_link_id &&
        rsn_links >= 2) {
        /* The CIPHER arm is the downgrade finding. A link offering a
         * weaker pairwise cipher than its sibling in the same element
         * is the attack shape: a client steered onto the weak link gets
         * the weaker cipher, and nothing in the standard asks for that
         * asymmetry. */
        if (lo_rank && hi_rank && lo_rank < hi_rank) {
            out->cross_link_cipher_downgrade = 1;
            out->downgrade_cipher_mismatch   = 1;
            out->downgrade_link_id           = (uint8_t)lo_rank_link;
            out->downgrade_peer_link_id      = (uint8_t)hi_rank_link;
        }

        /* The PMF arm is an OBSERVATION, not a downgrade, and that is
         * the owner ruling of 2026-10-13 rather than a hedge.
         *
         * MFPR=1 on one link and MFPR=0 on another is the posture pair
         * the standard MANDATES for a tri-band AP where one band
         * requires PMF and the others negotiate it. Review supplied the
         * firing input — links 0 and 1 with CCMP-128/MFPC=1/MFPR=0, link
         * 2 with CCMP-128/MFPR=1 — which is a conformant Wi-Fi 7 AP and
         * nothing else. A rule that reports a downgrade there is not a
         * detector; it is a reason to mute the type, and on an issue
         * about Wi-Fi 7 that case is the common one rather than an edge.
         *
         * So the mismatch is still RECORDED, because PMF genuinely
         * absent on one link of an MLD is worth seeing, and still
         * carries its own link pair. It no longer sets
         * cross_link_cipher_downgrade on its own, so it cannot raise the
         * alert by itself; the rule reports it as context when the
         * cipher arm fires, and src/alerts/rules_mle.c states that the standard
         * permits the asymmetry.
         *
         * The two arms also keep SEPARATE link pairs now. They used to
         * share one, and whichever ran second overwrote it while both
         * flags stayed set — so the single pair reported was false of
         * one of the two clauses in the detail string. */
        if (mfpr_set_link >= 0 && mfpr_clear_link >= 0) {
            out->downgrade_pmf_mismatch   = 1;
            out->pmf_mismatch_link_id     = (uint8_t)mfpr_clear_link;
            out->pmf_mismatch_peer_link_id = (uint8_t)mfpr_set_link;
        }
    }
    /* One count per element that broke any of its three bounds rules
     * (#126) — the common-info case counts at its own early return.
     * A subelement overrun is counted here as an MLE fault, not as an
     * IE_OVERRUN: this element has its own CVE-specific detector, and
     * the kind says which parser saw it. */
    if (out->malformed_subelem_len || out->malformed_link_id)
        sh_parse_fault_note(SH_PF_MLE_MALFORMED);
    return 1;
}

void mle_observe(const sloth_mld_t *m, time_t now) {
    if (!m || !mac_is_usable(m->mld_mac)) return;
    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_mld_n; i++)
        if (memcmp(g_mld[i].mld_mac, m->mld_mac, 6) == 0) { idx = i; break; }
    if (idx < 0) {
        if (g_mld_n < SLOTH_MLD_MAX) {
            idx = g_mld_n++;
        } else {
            idx = 0;
            for (int i = 1; i < SLOTH_MLD_MAX; i++)
                if (g_mld[i].last_seen < g_mld[idx].last_seen) idx = i;
        }
        memset(&g_mld[idx], 0, sizeof(g_mld[idx]));
        memcpy(g_mld[idx].mld_mac, m->mld_mac, 6);
        g_mld[idx].first_seen = now;
    }
    sloth_mld_t *e = &g_mld[idx];
    e->last_seen = now;

    /* Merge rather than replace. A device advertises different subsets
     * of its links depending on which band the frame was heard on, so
     * replacing would make the link set flap and the canonical lookup
     * intermittent — which is worse than not having it.
     *
     * A link_id already bound to a *different* address is not another
     * subset of the same device — IEEE 802.11be ties one link_id to one
     * stable affiliated address for the association's life (#104 slice
     * 4). That is a collision, not a merge: count it and keep the
     * first-seen binding, rather than letting a second device's address
     * displace or duplicate it in the roster. */
    for (int i = 0; i < m->link_count; i++) {
        int known = 0, conflict = 0;
        for (int j = 0; j < e->link_count; j++) {
            if (memcmp(e->link_mac[j], m->link_mac[i], 6) == 0) { known = 1; break; }
            if (e->link_id[j] == m->link_id[i]) conflict = 1;
        }
        if (known) continue;
        if (conflict) {
            e->mac_collision_total++;
            e->collision_link_id = m->link_id[i];
            memcpy(e->collision_mac, m->link_mac[i], 6);
            e->mac_collision_last_seen = now;
            continue;
        }
        if (e->link_count < SLOTH_MLD_MAX_LINKS) {
            memcpy(e->link_mac[e->link_count], m->link_mac[i], 6);
            e->link_id[e->link_count] = m->link_id[i];
            e->link_count++;
        } else {
            e->links_truncated = 1;
        }
    }
    if (m->links_truncated) e->links_truncated = 1;

    /* Lifetime signal, never cleared by a later clean frame — an MLD
     * that once sent an invalid or repeated link_id stays reportable,
     * the same way a one-off CVE-shaped frame should not be forgotten
     * because the next hundred frames from the same device are fine. */
    if (m->malformed_link_id) {
        e->malformed_link_id_total++;
        e->bad_link_id = m->bad_link_id;
        e->malformed_link_id_last_seen = now;
    }
    if (m->malformed_common_info_len) {
        e->malformed_common_info_len_total++;
        e->bad_common_info_len = m->bad_common_info_len;
        e->malformed_common_info_len_last_seen = now;
    }
    if (m->malformed_subelem_len) {
        e->malformed_subelem_len_total++;
        e->bad_subelem_len = m->bad_subelem_len;
        e->subelem_overrun_bytes = m->subelem_overrun_bytes;
        e->malformed_subelem_len_last_seen = now;
    }
    if (m->cross_link_cipher_downgrade) {
        e->cross_link_cipher_downgrade_total++;
        e->downgrade_link_id          = m->downgrade_link_id;
        e->downgrade_peer_link_id     = m->downgrade_peer_link_id;
        e->downgrade_pmf_mismatch     = m->downgrade_pmf_mismatch;
        e->downgrade_cipher_mismatch  = m->downgrade_cipher_mismatch;
        e->cross_link_cipher_downgrade_last_seen = now;
    }

    pthread_mutex_unlock(&g_mu);
}

int mle_canonical(const uint8_t mac[6], uint8_t out[6]) {
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_mld_n && !hit; i++) {
        /* The MLD address itself resolves to itself — a caller that
         * already has the canonical form must not be told there is no
         * mapping and fall back to a seqnum guess. */
        if (memcmp(g_mld[i].mld_mac, mac, 6) == 0) hit = 1;
        for (int j = 0; !hit && j < g_mld[i].link_count; j++)
            if (memcmp(g_mld[i].link_mac[j], mac, 6) == 0) hit = 1;
        if (hit && out) memcpy(out, g_mld[i].mld_mac, 6);
    }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

void mle_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    int n = g_mld_n;
    memcpy(s->mlds, g_mld, (size_t)n * sizeof(g_mld[0]));
    s->mld_count = n;
    int b = g_bss_n;
    memcpy(s->mle_bss, g_bss, (size_t)b * sizeof(g_bss[0]));
    s->mle_bss_count = b;
    pthread_mutex_unlock(&g_mu);
}

int mle_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_mld_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int mle_bss_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_bss_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void mle_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_mld, 0, sizeof(g_mld));
    g_mld_n = 0;
    memset(g_bss, 0, sizeof(g_bss));
    g_bss_n = 0;
    pthread_mutex_unlock(&g_mu);
}

/* ── Per-BSSID Multi-Link advertisement (#104 slice 6) ──────────────
 *
 * What one Beacon or Probe Response says about its BSS's Multi-Link
 * membership, gathered over every Multi-Link element in the frame. A
 * frame can legitimately carry more than one: hostapd's
 * hostapd_eid_eht_ml_beacon() emits the Basic MLE and then, while an
 * affiliated AP is being removed, a Reconfiguration MLE, and its Probe
 * Response builder emits the requested AP MLD's Basic MLE (with AP MLD
 * ID) ahead of its own (without). */
typedef struct {
    int     basic;        /* any Basic MLE, well-formed or not */
    int     reconf;       /* any Reconfiguration MLE */
    int     own;          /* the identity below was read */
    uint8_t mld_mac[6];
    int     has_link_id;
    uint8_t link_id;
} mle_frame_scan_t;

static void mle_frame_scan(const uint8_t *ies, int n, mle_frame_scan_t *o) {
    memset(o, 0, sizeof(*o));
    tlv_it_t it;
    uint16_t tag; int tln; const uint8_t *e;
    tlv_init(&it, ies, n);
    while (tlv_next(&it, &tag, &tln, &e) == TLV_OK) {
        /* Element ID Extension: ExtID(1), then Multi-Link Control(2). The
         * Type subfield is the one thing every variant shares at a fixed
         * position, which is why it is all a Reconfiguration MLE is read
         * for: its Common Info layout is variant-specific and its
         * Presence Bitmap bits are not the Basic variant's. */
        if (tag != 255 || tln < 3 || e[0] != MLE_EXT_ID) continue;
        const uint16_t ctl  = (uint16_t)(e[1] | (e[2] << 8));
        const int      type = ctl & 0x0007;
        if (type == MLE_TYPE_RECONFIG) { o->reconf = 1; continue; }
        if (type != MLE_TYPE_BASIC) continue;
        o->basic = 1;
        /* The identity is the first Basic MLE WITHOUT an AP MLD ID. With
         * one, the element describes an AP MLD of a multiple-BSSID set
         * (hostapd sets it for the requested MLD of an ML probe), so its
         * MLD MAC need not be this BSS's own and is never compared. */
        if (o->own || (ctl & MLE_BASIC_PRES_AP_MLD_ID)) continue;
        /* ExtID(1) Control(2) CommonInfoLength(1) MLD MAC(6) [LinkID(1)].
         * A Common Info Length that cannot hold the MAC, or that runs
         * past the element, is MLE_COMMON_INFO_LEN_BAD's finding; an
         * identity is not taken from it. */
        if (tln < 10) continue;
        const int cil = e[3];
        if (cil < 7 || 3 + cil > tln) continue;
        if (!mac_is_usable(e + 4)) continue;
        memcpy(o->mld_mac, e + 4, 6);
        o->own = 1;
        /* Link ID Info is the first optional Common Info subfield, so
         * its offset does not depend on any other presence bit. */
        if ((ctl & MLE_BASIC_PRES_LINK_ID) && cil >= 8) {
            o->has_link_id = 1;
            o->link_id = (uint8_t)(e[10] & 0x0f);
        }
    }
}

/* Caller holds g_mu. */
static sloth_mle_bss_t *bss_slot(const uint8_t bssid[6], time_t now) {
    for (int i = 0; i < g_bss_n; i++)
        if (memcmp(g_bss[i].bssid, bssid, 6) == 0) return &g_bss[i];
    int idx;
    if (g_bss_n < SLOTH_MLE_BSS_MAX) {
        idx = g_bss_n++;
    } else {
        /* Least recently heard. An AP MLD beacons ten times a second, so
         * the row a flood of one-off BSSIDs evicts is never a live one
         * for long — and losing a row loses only history, which the
         * same-frame Basic MLE check below does not depend on. */
        idx = 0;
        for (int i = 1; i < SLOTH_MLE_BSS_MAX; i++)
            if (g_bss[i].last_seen < g_bss[idx].last_seen) idx = i;
    }
    memset(&g_bss[idx], 0, sizeof(g_bss[idx]));
    memcpy(g_bss[idx].bssid, bssid, 6);
    g_bss[idx].first_seen = now;
    return &g_bss[idx];
}

void mle_bss_observe_frame(const dot11_frame_t *f, time_t now) {
    if (!f || f->proto != 0 || f->type != 0) return;
    if (f->subtype != 8 && f->subtype != 5) return;
    if (!f->bssid || !mac_is_usable(f->bssid)) return;
    const uint8_t *body; int blen;
    /* Timestamp(8) Beacon Interval(2) Capability(2), in both frames
     * (IEEE 802.11-2020 §9.3.3.2 / §9.3.3.10). */
    if (!dot11_frame_body(f, &body, &blen) || blen < 12) return;

    mle_frame_scan_t sc;
    mle_frame_scan(body + 12, blen - 12, &sc);
    if (!sc.basic && !sc.reconf) return;

    const int beacon = (f->subtype == 8);
    pthread_mutex_lock(&g_mu);
    sloth_mle_bss_t *e = bss_slot(f->bssid, now);
    e->last_seen = now;
    if (sc.basic) e->basic_mle_seen = 1;

    /* MLE_RECONFIG_NO_MLO. A Reconfiguration MLE announces a change to
     * an AP MLD's affiliated APs, so only an AP affiliated with an AP MLD
     * has one to send — and that AP carries a Basic MLE in its Beacons
     * and Probe Responses, the same frames the Reconfiguration MLE rides
     * in (hostapd emits the two together). The Basic MLE seen in THIS
     * frame counts, set just above, so a conformant AP MLD whose history
     * sloth lacks — first frame heard, or its row evicted — does not
     * fire. */
    if (sc.reconf && !e->basic_mle_seen) {
        e->reconfig_no_mlo_total++;
        e->reconfig_no_mlo_subtype   = f->subtype;
        e->reconfig_no_mlo_last_seen = now;
        e->reconfig_no_mlo_ev        = f->event_id;
    }

    if (sc.own && beacon) {
        e->beacon_ident       = 1;
        memcpy(e->beacon_mld_mac, sc.mld_mac, 6);
        e->beacon_has_link_id = (uint8_t)sc.has_link_id;
        e->beacon_link_id     = sc.link_id;
        e->beacon_ident_ts    = now;
        e->beacon_ev          = f->event_id;
    } else if (sc.own && e->beacon_ident) {
        /* MLE_PR_BEACON_DIFF. Both frames are the same BSS describing its
         * own AP MLD membership, so the MLD MAC and this BSS's own Link
         * ID cannot differ between them. Per-STA Profiles, AP MLD ID,
         * BSS Parameters Change Count and the capability subfields are
         * NOT compared: the first two legitimately appear only in a
         * multi-link Probe Response, the third moves on every critical
         * update. Both directions of the age test, so a replayed or
         * reordered capture cannot compare against a Beacon from the
         * future by underflow. */
        const time_t age = now >= e->beacon_ident_ts
                         ? now - e->beacon_ident_ts
                         : e->beacon_ident_ts - now;
        if (age <= MLE_PR_BEACON_WIN_SECS) {
            const int mac_diff = memcmp(sc.mld_mac, e->beacon_mld_mac, 6) != 0;
            const int lid_diff = sc.has_link_id && e->beacon_has_link_id &&
                                 sc.link_id != e->beacon_link_id;
            if (mac_diff || lid_diff) {
                e->pr_beacon_diff_total++;
                e->diff_mld_mac = (uint8_t)mac_diff;
                e->diff_link_id = (uint8_t)lid_diff;
                memcpy(e->diff_beacon_mld_mac, e->beacon_mld_mac, 6);
                e->diff_beacon_link_id = e->beacon_link_id;
                memcpy(e->diff_pr_mld_mac, sc.mld_mac, 6);
                e->diff_pr_link_id = sc.link_id;
                e->pr_beacon_diff_last_seen = now;
                e->diff_beacon_ev = e->beacon_ev;
                e->diff_pr_ev     = f->event_id;
            }
        }
    }
    pthread_mutex_unlock(&g_mu);
}
