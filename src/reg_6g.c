#include <limits.h>
#include <string.h>

#include "reg_6g.h"

/* 6 GHz regulatory claims — see include/reg_6g.h for the clauses. */

void reg_6g_reset(reg_6g_t *out) {
    if (out) memset(out, 0, sizeof(*out));
}

int reg_tpe_is_psd(uint8_t interp) {
    return interp == REG_TPE_LOCAL_EIRP_PSD ||
           interp == REG_TPE_REG_CLIENT_EIRP_PSD;
}

const char *reg_6g_info_name(uint8_t reg_info) {
    switch (reg_info) {
    case REG_6G_INDOOR_AP:   return "indoor";
    case REG_6G_STANDARD_AP: return "standard_power";
    default:                 return "reserved";
    }
}

const char *reg_tpe_interp_name(uint8_t interp) {
    switch (interp) {
    case REG_TPE_LOCAL_EIRP:          return "local_eirp";
    case REG_TPE_LOCAL_EIRP_PSD:      return "local_eirp_psd";
    case REG_TPE_REG_CLIENT_EIRP:     return "reg_client_eirp";
    case REG_TPE_REG_CLIENT_EIRP_PSD: return "reg_client_eirp_psd";
    default:                          return "reserved";
    }
}

/* Number of value octets a TPE announces, or -1 when the interpretation
 * or the count is reserved and the list therefore has no defined length.
 * EIRP and PSD count differently, and reading one as the other gives a
 * list of the wrong length that still looks plausible: Count 2 is three
 * EIRP values (20/40/80 MHz) but two PSD values, and Count 4 is eight
 * PSD values where an EIRP reading would call it reserved. */
static int tpe_value_count(uint8_t interp, uint8_t count) {
    switch (interp) {
    case REG_TPE_LOCAL_EIRP:
    case REG_TPE_REG_CLIENT_EIRP:
        return count <= 3 ? count + 1 : -1;
    case REG_TPE_LOCAL_EIRP_PSD:
    case REG_TPE_REG_CLIENT_EIRP_PSD:
        if (count == 0) return 1;
        return count <= 4 ? 1 << (count - 1) : -1;
    default:
        return -1;
    }
}

/* Store `e` keyed by (interp, category): a repeat replaces, a new pair
 * appends, and a pair past the cap is dropped and flagged. Within one
 * frame the last element of a pair wins, the same as Country in
 * reg_ie.c. */
static void tpe_store(reg_6g_t *out, const reg_tpe_t *e) {
    for (int i = 0; i < out->tpe_count; i++) {
        if (out->tpe[i].interp == e->interp &&
            out->tpe[i].category == e->category) {
            out->tpe[i] = *e;
            return;
        }
    }
    if (out->tpe_count < REG_6G_MAX_TPE) {
        out->tpe[out->tpe_count++] = *e;
        return;
    }
    out->tpe_truncated = 1;
}

static int parse_tpe(reg_6g_t *out, const uint8_t *body, int len) {
    if (len < 1) {
        out->malformed_tpe++;
        return 0;
    }
    reg_tpe_t e;
    memset(&e, 0, sizeof(e));
    e.info_raw = body[0];
    e.count    = body[0] & 0x07;
    e.interp   = (body[0] >> 3) & 0x07;
    e.category = (body[0] >> 6) & 0x03;

    int n = tpe_value_count(e.interp, e.count);
    if (n < 0) {
        /* Well-formed as far as the clause can say; the values just have
         * no defined length. Recorded so the claim is visible, but no
         * octet after the Information field is read as a power. */
        e.reserved = 1;
        tpe_store(out, &e);
        return 1;
    }
    if (len < 1 + n) {
        out->malformed_tpe++;
        return 0;
    }
    e.n_values = (uint8_t)n;
    for (int i = 0; i < n; i++)
        e.values_half_db[i] = (int8_t)body[1 + i];
    int extra = len - 1 - n;
    e.ext_octets = (uint8_t)(extra > 255 ? 255 : extra);
    tpe_store(out, &e);
    return 1;
}

/* HE Operation (§9.4.2.249), body after the Element ID Extension octet
 * at body[0]: HE Operation Parameters(3), BSS Color Information(1),
 * Basic HE-MCS And NSS Set(2), then — each only when flagged, and in
 * this order — VHT Operation Information(3, Parameters B14), Max
 * Co-Hosted BSSID Indicator(1, B15), 6 GHz Operation Information(5,
 * B17). Get the order wrong and the Control octet is read from the
 * wrong offset, which yields a plausible Regulatory Info value rather
 * than an obvious failure. Same walk as beacon_parse_ies() uses for the
 * 6 GHz primary channel. */
static int parse_he_op(reg_6g_t *out, const uint8_t *body, int len) {
    if (len < 7) {
        out->malformed_he6++;
        return 0;
    }
    int vht    = (body[2] & 0x40) != 0;   /* Parameters B14 */
    int cohost = (body[2] & 0x80) != 0;   /* B15 */
    int six    = (body[3] & 0x02) != 0;   /* B17 */
    if (!six) return 0;                   /* not a 6 GHz claim; nothing to read */
    int off = 1 + 3 + 1 + 2;
    if (vht)    off += 3;
    if (cohost) off += 1;
    if (off + 5 > len) {
        out->malformed_he6++;
        return 0;
    }
    /* 6 GHz Operation Information: Primary Channel(1), Control(1),
     * CCFS0(1), CCFS1(1), Minimum Rate(1). Control B0-B1 Channel Width,
     * B2 Duplicate Beacon, B3-B5 Regulatory Info, B6-B7 reserved. */
    uint8_t ctrl = body[off + 1];
    out->he6_present     = 1;
    out->he6_control_raw = ctrl;
    out->he6_reg_info    = (ctrl >> 3) & 0x07;
    return 1;
}

int reg_6g_element(reg_6g_t *out, uint8_t tag, const uint8_t *body, int len) {
    if (!out || len < 0) return 0;
    if (tag == 195) return parse_tpe(out, body, len);
    if (tag == 255 && len >= 1 && body[0] == 36)
        return parse_he_op(out, body, len);
    return 0;
}

static void add_sat(int *dst, int add) {
    if (add <= 0) return;
    *dst = (*dst > INT_MAX - add) ? INT_MAX : *dst + add;
}

void reg_6g_merge(reg_6g_t *dst, const reg_6g_t *src) {
    if (!dst || !src) return;
    if (src->he6_present) {
        dst->he6_present     = 1;
        dst->he6_control_raw = src->he6_control_raw;
        dst->he6_reg_info    = src->he6_reg_info;
    }
    for (int i = 0; i < src->tpe_count && i < REG_6G_MAX_TPE; i++)
        tpe_store(dst, &src->tpe[i]);
    if (src->tpe_truncated) dst->tpe_truncated = 1;
    add_sat(&dst->malformed_he6, src->malformed_he6);
    add_sat(&dst->malformed_tpe, src->malformed_tpe);
}
