#include <stdio.h>
#include <string.h>
#include "bredr_bb.h"

/* Contract and sources in bredr_bb.h. */

static uint32_t le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16);
}

int bredr_lap_is_iac(uint32_t lap) {
    return lap >= BREDR_IAC_FIRST && lap <= BREDR_IAC_LAST;
}

int bredr_bb_parse(const uint8_t *rec, size_t len, bredr_bb_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!rec || len < BREDR_BB_HDR_LEN) return -1;
    if (rec[0] >= BREDR_RF_CHANNELS) return -1;
    out->rf_channel      = rec[0];
    out->signal_dbm      = (int8_t)rec[1];
    out->noise_dbm       = (int8_t)rec[2];
    out->lap             = le24(rec + 8);     /* octet 11 is reserved */
    out->iac             = (uint8_t)bredr_lap_is_iac(out->lap);
    out->flags           = (uint16_t)(rec[20] | (rec[21] << 8));
    out->signal_valid    = (out->flags & BREDR_F_SIGNAL_VALID) != 0;
    out->noise_valid     = (out->flags & BREDR_F_NOISE_VALID) != 0;
    out->payload_present = (out->flags & BREDR_F_PAYLOAD) != 0;
    out->ref_lap_valid   = (out->flags & BREDR_F_REF_LAP_VALID) != 0;
    if (out->ref_lap_valid) out->ref_lap = le24(rec + 12);
    /* The tool's reference UAP is kept only when the flag says the tool
     * had one; without it octet 15 means nothing. */
    out->ref_uap_tool = (out->flags & BREDR_F_REF_UAP_VALID) != 0;
    if (out->ref_uap_tool) out->ref_uap = rec[15];
    return 0;
}

void bredr_lap_format(uint32_t lap, char *buf, size_t sz) {
    if (!buf || sz == 0) return;
    snprintf(buf, sz, "LAP %06x", (unsigned)(lap & 0xFFFFFFu));
}
