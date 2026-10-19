#include <string.h>

#include "rsn_ie.h"
#include "bytes.h"

/* Room for the next optional field of `n` octets? 1 when it is all
 * there; 0 at a clean end (nothing left — the field and everything
 * after it are omitted, which §9.4.2.24 allows); 0 with `truncated` set
 * when some but not all of it is there. */
static int field_ok(const rd_t *r, int n, rsn_ie_t *out) {
    int rem = rd_rem(r);
    if (rem >= n) return 1;
    if (rem > 0) out->truncated = 1;
    return 0;
}

/* A 2-octet count followed by that many 4-octet suite selectors. The
 * count comes off the air and may overstate the list, so the bound is
 * checked per suite: the suites that fit are taken, and the first one
 * that does not ends the walk with `truncated` set. Returns 0 when the
 * element ended (cleanly or not) and nothing after the list can be
 * read. */
static int suite_list(rd_t *r, rsn_ie_t *out, int *count,
                      const uint8_t **list, uint32_t *bits,
                      uint32_t *first) {
    if (!field_ok(r, 2, out)) return 0;
    int n = rd_le16(r);
    *list = r->p + r->off;
    for (int k = 0; k < n; k++) {
        if (!(r->off + 4 <= r->len)) { out->truncated = 1; return 0; }
        /* OUI then type, transmitted in that order: big-endian as a
         * whole selector. */
        uint32_t sel = be32(r->p + r->off);
        uint8_t  t   = RSN_SEL_TYPE(sel);
        if (k == 0) *first = sel;
        if (RSN_SEL_STD(sel) && t < 32) *bits |= RSN_SUITE_BIT(t);
        r->off += 4;
        (*count)++;
    }
    return 1;
}

int rsn_ie_parse(const uint8_t *body, int len, rsn_ie_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));
    rd_t r;
    rd_init(&r, body, len);

    /* Version is the one mandatory field. */
    if (rd_rem(&r) < 2) { out->truncated = 1; return 0; }
    out->version = rd_le16(&r);
    if (out->version != 1) return 0;

    if (!field_ok(&r, 4, out)) return 1;
    out->has_group = 1;
    out->group_sel = rd_be32(&r);

    if (!suite_list(&r, out, &out->pairwise_count, &out->pairwise,
                    &out->pairwise_bits, &out->first_pairwise_sel))
        return 1;
    if (!suite_list(&r, out, &out->akm_count, &out->akm,
                    &out->akm_bits, &out->first_akm_sel))
        return 1;

    if (!field_ok(&r, 2, out)) return 1;
    out->has_caps = 1;
    out->caps     = rd_le16(&r);
    out->mfpr     = (out->caps >> 6) & 1;
    out->mfpc     = (out->caps >> 7) & 1;

    if (!field_ok(&r, 2, out)) return 1;
    out->has_pmkids = 1;
    int np = rd_le16(&r);
    out->pmkids = r.p + r.off;
    for (int k = 0; k < np; k++) {
        if (!(r.off + RSN_PMKID_LEN <= r.len)) {
            out->truncated = 1;
            return 1;
        }
        r.off += RSN_PMKID_LEN;
        out->pmkid_count++;
    }

    if (!field_ok(&r, 4, out)) return 1;
    out->has_group_mgmt = 1;
    out->group_mgmt_sel = rd_be32(&r);
    /* Octets past Group Management Cipher are not a fault: the RSNE is
     * an extensible element (§10.28.9), so a later amendment's field is
     * allowed to follow and is ignored here. */
    return 1;
}

/* Cipher OUI 00-0F-AC type names (IEEE 802.11-2020 Table 9-149). */
const char *rsn_cipher_name(uint8_t t) {
    switch (t) {
    case 0:  return "GROUP";
    case 1:  return "WEP-40";
    case 2:  return "TKIP";
    case 4:  return "CCMP";
    case 5:  return "WEP-104";
    case 6:  return "BIP";
    case 8:  return "GCMP";
    case 9:  return "GCMP-256";
    case 10: return "CCMP-256";
    default: return "?";
    }
}

/* AKM OUI 00-0F-AC type names (IEEE 802.11-2020 Table 9-151). */
const char *rsn_akm_name(uint8_t t) {
    switch (t) {
    case 1:  return "802.1X";
    case 2:  return "PSK";
    case 3:  return "FT-802.1X";
    case 4:  return "FT-PSK";
    case 5:  return "802.1X-SHA256";
    case 6:  return "PSK-SHA256";
    case 8:  return "SAE";
    case 9:  return "FT-SAE";
    case 11: return "Suite-B";
    case 12: return "Suite-B-192";
    case 18: return "OWE";
    case 19: return "FT-PSK-SHA384";
    /* WPA3 R3 / 802.11be. Named because the transition-mode rule
     * treats PSK alongside SAE-EXT-KEY as a downgrade path exactly as
     * it treats PSK alongside plain SAE (#62). */
    case 24: return "SAE-EXT-KEY";
    case 25: return "FT-SAE-EXT-KEY";
    default: return "?";
    }
}

int rsn_cipher_rank(uint8_t t) {
    switch (t) {
    case 1:  return 1;   /* WEP-40   */
    case 2:  return 1;   /* TKIP     */
    case 5:  return 1;   /* WEP-104  */
    case 4:  return 2;   /* CCMP-128 */
    case 8:  return 2;   /* GCMP-128 */
    case 9:  return 3;   /* GCMP-256 */
    case 10: return 3;   /* CCMP-256 */
    default: return 0;
    }
}

int rsn_cipher_rank_best(uint32_t bits) {
    int best = 0;
    for (int t = 0; t < 32; t++) {
        if (!(bits & RSN_SUITE_BIT(t))) continue;
        int r = rsn_cipher_rank((uint8_t)t);
        if (r > best) best = r;
    }
    return best;
}
