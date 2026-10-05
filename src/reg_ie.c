#include <limits.h>
#include <string.h>
#include "reg_ie.h"

/* Regulatory IE parsers — see reg_ie.h for the clause map and for why
 * this layer stops at parsing. */

/* §9.4.2.8: "If the value of the first octet ... is 201 or greater, the
 * triplet is an Operating Triplet." Below it, the octet is a channel
 * number. Nothing in the element declares which kind comes next, so the
 * test is per triplet and not per element. */
#define REG_OPERATING_EXT_ID_MIN 201

void reg_ie_reset(reg_ie_t *out) {
    if (out) memset(out, 0, sizeof(*out));
}

/* Third octet of the Country String. The four ASCII forms are listed in
 * §9.4.2.8; the fifth form is "the binary representation of the
 * Operating Class table number currently in use" (Annex E), which is
 * what hostapd emits as 0x04 when it advertises global operating
 * classes. Table numbers are small integers, so they are separable from
 * the ASCII forms by being below the printable range — and anything
 * that is neither is left explicitly unknown. */
static uint8_t decode_env(uint8_t octet) {
    switch (octet) {
    case ' ': return REG_ENV_ANY;
    case 'I': return REG_ENV_INDOOR;
    case 'O': return REG_ENV_OUTDOOR;
    case 'X': return REG_ENV_NON_COUNTRY;
    default:  break;
    }
    if (octet < 0x20) return REG_ENV_OPCLASS_TABLE;
    return REG_ENV_UNKNOWN;
}

static int parse_country(reg_ie_t *out, const uint8_t *body, int len) {
    /* Country String(3) is the whole mandatory part — an element that
     * cannot hold it is not a short country, it is not a country. */
    if (len < 3) {
        out->malformed_country++;
        return 0;
    }

    /* Zero the array, not just the count. A frame may carry two Country
     * elements; parse_country() is called once per element on the same
     * struct, so without this a shorter second element leaves the
     * longer first one's triplets readable past the new count — and
     * reg_ie_merge() copies the whole array on the stated invariant
     * that the tail is already zero. Review found that invariant was
     * false for exactly this case, so it is made true here rather than
     * weakened there. */
    memset(out->triplets, 0, sizeof(out->triplets));
    out->triplets_truncated = 0;

    out->country_present = 1;
    out->country[0] = (char)body[0];
    out->country[1] = (char)body[1];
    out->country[2] = '\0';
    out->env_raw    = body[2];
    out->env        = decode_env(body[2]);

    int off   = 3;
    int count = 0;
    while (len - off >= 3) {
        const uint8_t *t = body + off;
        if (count < REG_MAX_COUNTRY_TRIPLETS) {
            reg_triplet_t *d = &out->triplets[count];
            if (t[0] >= REG_OPERATING_EXT_ID_MIN) {
                d->is_operating    = 1;
                d->ext_id          = t[0];
                d->operating_class = t[1];
                d->coverage_class  = t[2];
            } else {
                d->first_channel    = t[0];
                d->num_channels     = t[1];
                d->max_tx_power_dbm = (int8_t)t[2];
            }
            count++;
        } else {
            out->triplets_truncated = 1;
        }
        off += 3;
    }
    out->triplet_count = (uint8_t)count;

    /* A single leftover octet is the Pad field (802.11-2007 §7.3.2.9),
     * present when 3 + 3n is odd so the element length stays even.
     * Two leftover octets are produced by no encoding of this element,
     * so they are flagged — while the triplets that were fully present
     * are kept, because they were read inside the declared length. */
    int leftover = (len - 3) % 3;
    if (leftover == 2) {
        out->malformed_country++;
        /* country_present and the triplets read inside the declared
         * length are deliberately KEPT, not rolled back: what a rogue
         * AP claimed is the evidence, and discarding it would lose the
         * observation this issue exists to make. The consequence a
         * consumer must respect — raised in review and stated here
         * because no detector exists yet to get it wrong: a frame can
         * be both country_present and malformed_country > 0, so
         * country_present alone is NOT "a valid regulatory claim". A
         * rule that treats it that way will accept a deliberately
         * malformed element as conforming. malformed_* is a
         * per-envelope count, so with one good and one bad element it
         * says only that something was wrong, not which. */
        return 0;
    }
    return 1;
}

int reg_ie_element(reg_ie_t *out, uint8_t tag, const uint8_t *body, int len) {
    if (!out) return 0;

    switch (tag) {
    case 7:
        return parse_country(out, body, len);

    case 32:
        /* Local Power Constraint(1), unsigned dB below the regulatory
         * maximum. Exactly one octet — there is no longer form. */
        if (len != 1) {
            out->malformed_power_constraint++;
            return 0;
        }
        out->power_constraint_present = 1;
        out->power_constraint_db      = body[0];
        return 1;

    case 35:
        /* Transmit Power(1) and Link Margin(1), both signed. Link
         * Margin is reserved (0) in a beacon or probe response; it is
         * read anyway because the same element arrives in TPC Report
         * action frames, where it carries a real value. */
        if (len != 2) {
            out->malformed_tpc++;
            return 0;
        }
        out->tpc_present         = 1;
        out->tpc_tx_power_dbm    = (int8_t)body[0];
        out->tpc_link_margin_db  = (int8_t)body[1];
        return 1;

    default:
        return 0;
    }
}

/* Saturating add. A hostile transmitter can send malformed elements
 * indefinitely; signed overflow is undefined behaviour, and a wrapped
 * count would read as "clean" at the worst possible moment. */
static void add_sat(int *dst, int add) {
    if (add <= 0) return;
    *dst = (*dst > INT_MAX - add) ? INT_MAX : *dst + add;
}

void reg_ie_merge(reg_ie_t *dst, const reg_ie_t *src) {
    if (!dst || !src) return;

    if (src->country_present) {
        dst->country_present = 1;
        memcpy(dst->country, src->country, sizeof(dst->country));
        dst->env     = src->env;
        dst->env_raw = src->env_raw;
        /* The whole triplet array, not the first triplet_count of it:
         * a shorter Country element must not leave the tail of a longer
         * previous one readable below the new count. src's tail is
         * zero because parse_country() memsets the array per element,
         * which is what makes this whole-array copy safe — before that
         * fix, two Country elements in one frame broke it. */
        memcpy(dst->triplets, src->triplets, sizeof(dst->triplets));
        dst->triplet_count      = src->triplet_count;
        dst->triplets_truncated = src->triplets_truncated;
    }

    if (src->power_constraint_present) {
        dst->power_constraint_present = 1;
        dst->power_constraint_db      = src->power_constraint_db;
    }

    if (src->tpc_present) {
        dst->tpc_present        = 1;
        dst->tpc_tx_power_dbm   = src->tpc_tx_power_dbm;
        dst->tpc_link_margin_db = src->tpc_link_margin_db;
    }

    add_sat(&dst->malformed_country,          src->malformed_country);
    add_sat(&dst->malformed_power_constraint, src->malformed_power_constraint);
    add_sat(&dst->malformed_tpc,              src->malformed_tpc);
}
