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
