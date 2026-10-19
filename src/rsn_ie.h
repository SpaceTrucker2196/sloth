/* RSN element, parsed once (#128).
 *
 * Before this module the RSNE (IEEE 802.11-2020 §9.4.2.24) was decoded
 * in two places with no shared code: inline in beacon_parse_ies(), and
 * in mle.c's per-STA-profile reader with its own cipher-rank table. The
 * two had already drifted, and the beacon copy disagreed with itself:
 * `akm_bits` counted SAE-EXT-KEY (AKM 24/25) as SAE while the `enc`
 * label only recognised AKM 8/9, so a BSS offering SAE-EXT-KEY alone
 * read "WPA2" in one field and SAE in the next.
 *
 * Layout after the element header (§9.4.2.24, Figure 9-286):
 *
 *   2 Version | 4 Group Data Cipher | 2 N | 4N Pairwise |
 *   2 M | 4M AKM | 2 RSN Capabilities | 2 P | 16P PMKID |
 *   4 Group Management Cipher
 *
 * Everything after Version is optional, but only from the end: a field
 * may be omitted only when every field after it is omitted too. So the
 * element may legitimately stop at any field boundary, and stopping
 * anywhere else — one stray octet, or a count whose list does not fit —
 * is a truncation.
 *
 * Selectors are kept whole (OUI << 8 | type) rather than reduced to the
 * type octet, because a vendor suite with type 4 is not CCMP and the
 * reduction is where that mistake would be made. The bitmaps take only
 * 00-0F-AC suites, which is what every rule that reads them means. */

#ifndef SLOTH_RSN_IE_H
#define SLOTH_RSN_IE_H

#include <stdint.h>

/* Suite-type bit for a 00-0F-AC selector (IEEE 802.11-2020 Table 9-151
 * for AKM, Table 9-149 for ciphers). Types >= 32 have no bit. */
#define RSN_SUITE_BIT(t)  (1u << (t))

/* AKM selectors worth naming, because the downgrade rules ask about the
 * family rather than one selector. Keep these in sync with
 * rsn_akm_name(). */
#define RSN_AKM_PSK          RSN_SUITE_BIT(2)
#define RSN_AKM_FT_PSK       RSN_SUITE_BIT(4)
#define RSN_AKM_PSK_SHA256   RSN_SUITE_BIT(6)
#define RSN_AKM_SAE          RSN_SUITE_BIT(8)
#define RSN_AKM_FT_SAE       RSN_SUITE_BIT(9)
#define RSN_AKM_OWE          RSN_SUITE_BIT(18)
#define RSN_AKM_SAE_EXT      RSN_SUITE_BIT(24)
#define RSN_AKM_FT_SAE_EXT   RSN_SUITE_BIT(25)

/* Any PSK-based AKM — the WPA2 lane of a transition-mode BSS. */
#define RSN_AKM_PSK_FAMILY \
    (RSN_AKM_PSK | RSN_AKM_FT_PSK | RSN_AKM_PSK_SHA256)

/* Any SAE-based AKM — the WPA3 lane. SAE-EXT-KEY (24, 25) is SAE with
 * a group-dependent key length (WPA3 R3 / 802.11be); it is WPA3, not a
 * third thing. */
#define RSN_AKM_SAE_FAMILY \
    (RSN_AKM_SAE | RSN_AKM_FT_SAE | RSN_AKM_SAE_EXT | RSN_AKM_FT_SAE_EXT)

/* The one test for "this BSS offers SAE". The `enc` label goes through
 * it, so the label and the bitmap come from one predicate and cannot
 * disagree again. */
#define RSN_AKM_FAMILY_SAE(bits) (((bits) & RSN_AKM_SAE_FAMILY) != 0)

/* Pairwise ciphers the posture rules care about. */
#define RSN_CIPHER_TKIP      RSN_SUITE_BIT(2)
#define RSN_CIPHER_CCMP      RSN_SUITE_BIT(4)

/* Whole-selector helpers: OUI in the high 24 bits, type in the low 8. */
#define RSN_OUI_IEEE         0x000FACu
#define RSN_SEL_OUI(sel)     ((uint32_t)(sel) >> 8)
#define RSN_SEL_TYPE(sel)    ((uint8_t)((sel) & 0xffu))
#define RSN_SEL_STD(sel)     (RSN_SEL_OUI(sel) == RSN_OUI_IEEE)

#define RSN_PMKID_LEN        16

typedef struct {
    uint16_t version;

    int      has_group;
    uint32_t group_sel;                /* Group Data Cipher Suite */

    /* Suites that fit in the element — never the declared count when
     * the declared count overran. The lists point into the caller's
     * buffer, `count` four-octet selectors each. */
    int            pairwise_count;
    const uint8_t *pairwise;
    uint32_t       pairwise_bits;      /* 00-0F-AC types < 32 only */
    uint32_t       first_pairwise_sel; /* list position 0; 0 when empty */

    int            akm_count;
    const uint8_t *akm;
    uint32_t       akm_bits;           /* 00-0F-AC types < 32 only */
    uint32_t       first_akm_sel;      /* list position 0; 0 when empty */

    int      has_caps;
    uint16_t caps;
    int      mfpc, mfpr;               /* RSN Capabilities bits 7 and 6 */

    int            has_pmkids;
    int            pmkid_count;        /* that fit */
    const uint8_t *pmkids;             /* pmkid_count * RSN_PMKID_LEN */

    int      has_group_mgmt;
    uint32_t group_mgmt_sel;

    /* A field was cut off: a declared count ran past the element, or
     * the element ended part-way through a fixed field. Decoding stops
     * at the cut; what was decoded before it is kept. */
    int truncated;
} rsn_ie_t;

/* Parse an RSNE body (after Element ID and Length). Never reads past
 * `len`. Returns 1 when the element carried Version 1 — the only
 * version §9.4.2.24 defines — and 0 otherwise. On 0, `version` holds
 * what was read (0 when absent, with `truncated` set) and nothing else
 * is decoded: the layout of an undefined version is not known, so
 * reading suites out of it would be a guess. `out` is always fully
 * written. Pure: tallies nothing, so a caller that may be reading the
 * wrong bytes on purpose (mle.c) does not report faults it caused. */
int rsn_ie_parse(const uint8_t *body, int len, rsn_ie_t *out);

/* Display names for 00-0F-AC types (Tables 9-149 and 9-151). "?" for a
 * type this build does not name. */
const char *rsn_cipher_name(uint8_t type);
const char *rsn_akm_name(uint8_t type);

/* Pairwise-cipher strength rank for a 00-0F-AC type. Only the ordering
 * is load-bearing. 0 means "not a suite whose strength we are willing
 * to rank": type 0 is Use-Group-Cipher and anything else is a selector
 * newer than this table — ranking an unknown suite as weak would turn
 * every future cipher into an alert. */
int rsn_cipher_rank(uint8_t type);

/* Highest rsn_cipher_rank() over a pairwise bitmap; 0 when none ranks. */
int rsn_cipher_rank_best(uint32_t pairwise_bits);

#endif /* SLOTH_RSN_IE_H */
