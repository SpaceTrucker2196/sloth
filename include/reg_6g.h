#ifndef SLOTH_REG_6G_H
#define SLOTH_REG_6G_H

#include <stdint.h>

/* 6 GHz regulatory claims (issue #101 slice B).
 *
 * Two places in a beacon carry the regulatory envelope a 6 GHz BSS
 * claims, and neither is one of the three reg_ie.c reads:
 *
 *   Regulatory Info   bits 3-5 of the Control octet in the HE Operation
 *                     element's 6 GHz Operation Information field
 *                     (Element ID 255, extension 36), IEEE 802.11ax-2021
 *                     §9.4.2.249. 0 = Indoor AP (low-power indoor),
 *                     1 = Standard Power AP; 2-7 reserved in that text.
 *   Transmit Power    tag 195, §9.4.2.161 as 802.11ax-2021 amends it:
 *   Envelope (TPE)    one Transmit Power Information octet, then the
 *                     maximum transmit power values it announces.
 *
 * On 6 GHz these replace Power Constraint / TPC Report as the power
 * ceiling (research/ieee/802.11-2020-11.8-spectrum-management.md), which
 * is why the 5 GHz TPC_ABSENT rule stays silent there.
 *
 * Kept apart from reg_ie_t on purpose: reg_ie_t is the 802.11d/h trio
 * and the channel-legality slice builds on it, while this file is the
 * 802.11ax half. Same contract as reg_ie.h — parse, retain per BSSID,
 * judge nothing. No alert reads these fields. */

/* Transmit Power Information (§9.4.2.161):
 *   B0-B2 Maximum Transmit Power Count
 *   B3-B5 Maximum Transmit Power Interpretation
 *   B6-B7 Maximum Transmit Power Category (added by 802.11ax) */
enum reg_tpe_interp {
    REG_TPE_LOCAL_EIRP         = 0,
    REG_TPE_LOCAL_EIRP_PSD     = 1,
    REG_TPE_REG_CLIENT_EIRP    = 2,
    REG_TPE_REG_CLIENT_EIRP_PSD = 3
    /* 4-7 reserved */
};

enum reg_tpe_category {
    REG_TPE_CAT_DEFAULT     = 0,
    REG_TPE_CAT_SUBORDINATE = 1
    /* 2-3 reserved */
};

/* HE 6 GHz Operation Information Control, B3-B5 (802.11ax-2021). */
enum reg_6g_info {
    REG_6G_INDOOR_AP   = 0,
    REG_6G_STANDARD_AP = 1
    /* 2-7 reserved in 802.11ax-2021 */
};

/* EIRP: Count + 1 values (20, 40, 80, 160 MHz), Count 0-3.
 * PSD:  Count 0 is one value for every 20 MHz; 1-4 is 1, 2, 4 or 8
 *       values, one per 20 MHz subchannel. */
#define REG_TPE_MAX_VALUES 8

/* Distinct (interpretation, category) pairs retained per BSSID. A 6 GHz
 * AP typically sends two to four TPE elements; 32 pairs are encodable,
 * so the surplus is flagged rather than stored. */
#define REG_6G_MAX_TPE 8

typedef struct {
    uint8_t info_raw;      /* the Transmit Power Information octet  */
    uint8_t interp;        /* B3-B5, raw (enum reg_tpe_interp)       */
    uint8_t category;      /* B6-B7, raw (enum reg_tpe_category)     */
    uint8_t count;         /* B0-B2, raw                             */
    /* 1 when the interpretation or the count is a value the clause
     * reserves: the element is well-formed but its value list has no
     * defined length, so none is read and n_values stays 0. */
    uint8_t reserved;
    uint8_t n_values;
    /* Signed 2's complement in 0.5 dB steps — dBm for the EIRP
     * interpretations, dBm/MHz for the PSD ones. Raw: the sentinel
     * encodings a later revision attaches to some values are not
     * interpreted here. */
    int8_t  values_half_db[REG_TPE_MAX_VALUES];
    /* Octets past the values (802.11be's 320 MHz extension field). Not
     * decoded and not malformed — recorded so a reader can tell. */
    uint8_t ext_octets;
} reg_tpe_t;

typedef struct {
    /* HE Operation carried a 6 GHz Operation Information field. */
    uint8_t he6_present;
    uint8_t he6_control_raw;
    uint8_t he6_reg_info;  /* Control B3-B5 (enum reg_6g_info), raw  */

    uint8_t tpe_count;
    uint8_t tpe_truncated; /* more distinct pairs than REG_6G_MAX_TPE */
    reg_tpe_t tpe[REG_6G_MAX_TPE];

    /* Same spirit as reg_ie_t's malformed_* counts: a crafted element
     * is a signal, so it is counted, never silently skipped.
     *   malformed_he6  HE Operation shorter than its 6-octet fixed part,
     *                  or flagging a 6 GHz field the element does not
     *                  hold
     *   malformed_tpe  TPE with no Information octet, or fewer value
     *                  octets than its Count announces */
    int malformed_he6;
    int malformed_tpe;
} reg_6g_t;

void reg_6g_reset(reg_6g_t *out);

/* Offer one element body (past tag and length; `len` already proven
 * present). Handles tag 195 and tag 255 extension 36; returns 1 when
 * such an element parsed, 0 otherwise (a malformed one bumps its
 * counter and writes no field). Never reads beyond `len`. */
int reg_6g_element(reg_6g_t *out, uint8_t tag, const uint8_t *body, int len);

/* Fold one frame's parse into a retained per-BSSID record, per element
 * like reg_ie_merge(): a frame without the 6 GHz field leaves the stored
 * Regulatory Info alone, and TPE entries are replaced by
 * (interpretation, category), so a frame carrying only the regulatory
 * client PSD envelope does not erase the local EIRP one. Malformed
 * counts accumulate, saturating. */
void reg_6g_merge(reg_6g_t *dst, const reg_6g_t *src);

/* "indoor", "standard_power", or "reserved". */
const char *reg_6g_info_name(uint8_t reg_info);
/* "local_eirp", "local_eirp_psd", "reg_client_eirp",
 * "reg_client_eirp_psd", or "reserved". */
const char *reg_tpe_interp_name(uint8_t interp);

/* 1 for the two PSD interpretations (values in dBm/MHz). */
int reg_tpe_is_psd(uint8_t interp);

#endif /* SLOTH_REG_6G_H */
