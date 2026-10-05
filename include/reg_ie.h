#ifndef SLOTH_REG_IE_H
#define SLOTH_REG_IE_H

#include <stdint.h>

/* Regulatory information elements (issue #101, slices 1-2).
 *
 * Three elements carry the regulatory envelope an AP claims to operate
 * in. Sloth ignored all three until now, which meant the most basic
 * non-compliance signal there is — a 5 GHz AP that names no country at
 * all, the hostapd / OpenWrt stripped-build default — was invisible.
 *
 *   Country          tag 7   IEEE 802.11-2020 §9.4.2.8  (802.11d-2016)
 *   Power Constraint tag 32  §9.4.2.13
 *   TPC Report       tag 35  §9.4.2.16                  (802.11h)
 *
 * This layer parses and retains, and nothing else. Slice 2 gave the
 * parse a home: beacon_ap_t carries one reg_ie_t per BSSID, folded in
 * by beacon_record via reg_ie_merge(). It still builds no regulatory
 * table, decides no channel legality, fires no alert, and exports
 * nothing to JSONL, SQLite or a view — those are later slices of #101.
 * Reading a claim is not the same as judging it, and the judging half
 * needs a versioned regulatory table this half must not pre-empt.
 *
 * Lives in include/ rather than src/ because beacon_ap_t embeds
 * reg_ie_t, so every translation unit that sees sloth.h must see this
 * header too — including the ones built without -Isrc. */

/* Country elements in the wild carry one to eight triplets. The cap is
 * well above that and well below the 84 a hostile 255-octet element
 * could claim; the surplus is dropped and flagged rather than stored. */
#define REG_MAX_COUNTRY_TRIPLETS 16

/* Third octet of the Country String (§9.4.2.8). Four ASCII forms, plus
 * the binary Annex E Operating Class table number. Anything else is
 * REG_ENV_UNKNOWN: an AP that emits an octet the clause does not define
 * has made no environment claim, and inventing one for it would put a
 * regulatory assertion in the record that never went over the air. */
enum reg_env {
    REG_ENV_ABSENT = 0,      /* no Country element in the frame      */
    REG_ENV_ANY,             /* ' ' — all environments               */
    REG_ENV_INDOOR,          /* 'I'                                  */
    REG_ENV_OUTDOOR,         /* 'O'                                  */
    REG_ENV_NON_COUNTRY,     /* 'X' — non-country entity, code "XX"  */
    REG_ENV_OPCLASS_TABLE,   /* binary Annex E table number          */
    REG_ENV_UNKNOWN          /* defined by no form in the clause     */
};

/* One 3-octet triplet. Which three fields are meaningful is decided by
 * the first octet, not by position in the element: >= 201 is the
 * Operating Extension Identifier, so the triplet is an operating
 * triplet. The unused half stays zero — a caller that reads the wrong
 * one gets an obvious 0 rather than a fabricated channel or power. */
typedef struct {
    uint8_t is_operating;

    /* Subband triplet (is_operating == 0). */
    uint8_t first_channel;
    uint8_t num_channels;
    int8_t  max_tx_power_dbm;   /* signed per §9.4.2.8 */

    /* Operating triplet (is_operating == 1). */
    uint8_t ext_id;             /* >= 201 */
    uint8_t operating_class;
    uint8_t coverage_class;
} reg_triplet_t;

typedef struct {
    uint8_t country_present;
    /* ISO 3166-1 alpha-2, verbatim and NUL-terminated; "" when absent.
     * Stored as the AP sent it — whether the pair names a real country,
     * and whether the channel is legal there, is the regulatory table's
     * question, not the parser's. */
    char    country[3];
    uint8_t env;                /* enum reg_env */
    uint8_t env_raw;            /* the third octet verbatim */

    uint8_t triplet_count;
    uint8_t triplets_truncated; /* element held more than the store */
    reg_triplet_t triplets[REG_MAX_COUNTRY_TRIPLETS];

    uint8_t power_constraint_present;
    uint8_t power_constraint_db; /* unsigned dB of reduction (§9.4.2.13) */

    uint8_t tpc_present;
    int8_t  tpc_tx_power_dbm;   /* signed dBm  */
    int8_t  tpc_link_margin_db; /* signed dB   */

    /* Per-element malformed counts, in the same spirit as
     * beacon_rsn_t's ie_overruns / truncated_rsn: a crafted or
     * truncated regulatory element is itself a signal, so it is counted
     * rather than silently skipped. */
    int malformed_country;
    int malformed_power_constraint;
    int malformed_tpc;
} reg_ie_t;

/* Zero every field. "Absent" has to mean absent, so callers reset
 * before a frame rather than after. */
void reg_ie_reset(reg_ie_t *out);

/* Offer one element body to the regulatory parsers. `body` points past
 * the tag and length octets and `len` is the declared length, already
 * proven present by the caller's element walk.
 *
 * Returns 1 when the element was one of ours and parsed; 0 when the tag
 * is not regulatory, or when it is and the body did not conform — in
 * which case the matching malformed counter is bumped and no field is
 * written. Never reads beyond `len`. `out` may not be NULL. */
int reg_ie_element(reg_ie_t *out, uint8_t tag, const uint8_t *body, int len);

/* Fold one frame's parse (`src`) into a retained per-BSSID envelope
 * (`dst`). Both may be any reg_ie_t; neither may be NULL.
 *
 * Per element, not per struct: a frame that omits the Country element
 * leaves whatever country `dst` already held, and a frame that omits
 * all three changes nothing but the malformed counts. Assigning the
 * whole struct instead would turn every beacon without a TPC Report
 * into a stored tpc_tx_power_dbm of 0 — a real claim of 0 dBm, which
 * the AP never made. The *_present flags are the only thing that can
 * tell those apart, so the merge is driven by them.
 *
 * The corollary is that a retained envelope is sticky: an AP that
 * stops advertising a Country element keeps the last one it sent. That
 * is deliberate — on a hopping radio a missing element usually means
 * the beacon that carried it was not heard, not that the AP retracted
 * it. A detector that wants to see the retraction needs per-element
 * recency, which is a later slice's field, not a reason to drop the
 * value now.
 *
 * The three malformed counters accumulate (saturating at INT_MAX): in
 * a per-frame parse they count within one frame, in a retained
 * envelope they count across every frame from that BSSID, the same way
 * beacon_ap_t's fuzz_* counters relate to beacon_rsn_t's. */
void reg_ie_merge(reg_ie_t *dst, const reg_ie_t *src);

#endif /* SLOTH_REG_IE_H */
