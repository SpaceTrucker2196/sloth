#include <string.h>
#include "reg_table.h"

/* The rows. docs/wiki/regulatory-table.md is the human-readable copy of
 * exactly these and names the same sources; tests/test_reg_table.c pins
 * every channel set, flag and CAC to the values that page states, so a
 * change here that the page does not also describe goes red.
 *
 * Every row is a 20 MHz channel. Wider operation is made of these, and
 * an 80 MHz BSS whose primary is 36 still occupies 52-64 if it is
 * centred at 58 — a width-aware caller must look up each 20 MHz piece,
 * which this table makes possible and does not do for it. */

/* ── FCC: 47 CFR §15.407 (U-NII), read 2026-10-20 ─────────────
 *
 * (a)(1) U-NII-1   5150-5250 MHz   36-48    no radar detection
 * (a)(2) U-NII-2A  5250-5350 MHz   52-64    DFS, §15.407(h)(2)
 * (a)(2) U-NII-2C  5470-5725 MHz   100-144  DFS, §15.407(h)(2)
 * (a)(3) U-NII-3   5725-5850 MHz   149-165  no radar detection
 *
 * Channel 144 (5710-5730 MHz) straddles 5725 and is listed because the
 * U-NII-2C/U-NII-3 boundary straddle is permitted; its 5470-5725 part
 * is what makes it DFS. The 60 s channel availability check is not in
 * §15.407 itself but in the FCC's DFS test procedure, KDB 905462 D02.
 * U-NII-4 (5850-5895 MHz) is not here: it was not verified for this
 * table, and an unverified row is what the table refuses to carry. */
#define FCC_U1  "47 CFR 15.407(a)(1)"
#define FCC_U2  "47 CFR 15.407(a)(2), (h)(2); CAC per KDB 905462 D02"
#define FCC_U3  "47 CFR 15.407(a)(3)"

static const reg_chan_row_t g_fcc_rows[] = {
    {  36, 5180, 0,          0, FCC_U1 },
    {  40, 5200, 0,          0, FCC_U1 },
    {  44, 5220, 0,          0, FCC_U1 },
    {  48, 5240, 0,          0, FCC_U1 },
    {  52, 5260, REG_CH_DFS, 60, FCC_U2 },
    {  56, 5280, REG_CH_DFS, 60, FCC_U2 },
    {  60, 5300, REG_CH_DFS, 60, FCC_U2 },
    {  64, 5320, REG_CH_DFS, 60, FCC_U2 },
    { 100, 5500, REG_CH_DFS, 60, FCC_U2 },
    { 104, 5520, REG_CH_DFS, 60, FCC_U2 },
    { 108, 5540, REG_CH_DFS, 60, FCC_U2 },
    { 112, 5560, REG_CH_DFS, 60, FCC_U2 },
    { 116, 5580, REG_CH_DFS, 60, FCC_U2 },
    { 120, 5600, REG_CH_DFS, 60, FCC_U2 },
    { 124, 5620, REG_CH_DFS, 60, FCC_U2 },
    { 128, 5640, REG_CH_DFS, 60, FCC_U2 },
    { 132, 5660, REG_CH_DFS, 60, FCC_U2 },
    { 136, 5680, REG_CH_DFS, 60, FCC_U2 },
    { 140, 5700, REG_CH_DFS, 60, FCC_U2 },
    { 144, 5720, REG_CH_DFS, 60, FCC_U2 },
    { 149, 5745, 0,          0, FCC_U3 },
    { 153, 5765, 0,          0, FCC_U3 },
    { 157, 5785, 0,          0, FCC_U3 },
    { 161, 5805, 0,          0, FCC_U3 },
    { 165, 5825, 0,          0, FCC_U3 },
};

/* ── ETSI: EN 301 893 V2.1.1 (2017-05), read 2026-10-20 ───────
 *
 * The harmonised standard for 5 GHz RLAN under Directive 2014/53/EU,
 * with the band plan of Commission Decision 2005/513/EC as amended by
 * 2007/90/EC. It covers two sub-bands only:
 *
 *   5150-5350 MHz   36-64    DFS on 52-64 (5250-5350)
 *   5470-5725 MHz   100-140  DFS throughout
 *
 * §4.2.6 sets the channel availability check at 60 s, and at 10 min on
 * any channel touching 5600-5650 MHz (weather radar): 120, 124, 128 at
 * 20 MHz. 144 is not listed — 5710-5730 MHz runs past 5725 — and nor is
 * 149-165, which EN 301 893 does not cover (other ETSI documents and
 * national rules do; a missing row here is "not in this source"). */
#define ETSI_LO  "EN 301 893 V2.1.1, 5150-5250 MHz"
#define ETSI_MID "EN 301 893 V2.1.1, 5250-5350 MHz, DFS §4.2.6"
#define ETSI_HI  "EN 301 893 V2.1.1, 5470-5725 MHz, DFS §4.2.6"
#define ETSI_WX  "EN 301 893 V2.1.1, 5600-5650 MHz, DFS §4.2.6, 10 min CAC"

static const reg_chan_row_t g_etsi_rows[] = {
    {  36, 5180, 0,          0, ETSI_LO },
    {  40, 5200, 0,          0, ETSI_LO },
    {  44, 5220, 0,          0, ETSI_LO },
    {  48, 5240, 0,          0, ETSI_LO },
    {  52, 5260, REG_CH_DFS, 60, ETSI_MID },
    {  56, 5280, REG_CH_DFS, 60, ETSI_MID },
    {  60, 5300, REG_CH_DFS, 60, ETSI_MID },
    {  64, 5320, REG_CH_DFS, 60, ETSI_MID },
    { 100, 5500, REG_CH_DFS, 60, ETSI_HI },
    { 104, 5520, REG_CH_DFS, 60, ETSI_HI },
    { 108, 5540, REG_CH_DFS, 60, ETSI_HI },
    { 112, 5560, REG_CH_DFS, 60, ETSI_HI },
    { 116, 5580, REG_CH_DFS, 60, ETSI_HI },
    { 120, 5600, REG_CH_DFS | REG_CH_WEATHER, 600, ETSI_WX },
    { 124, 5620, REG_CH_DFS | REG_CH_WEATHER, 600, ETSI_WX },
    { 128, 5640, REG_CH_DFS | REG_CH_WEATHER, 600, ETSI_WX },
    { 132, 5660, REG_CH_DFS, 60, ETSI_HI },
    { 136, 5680, REG_CH_DFS, 60, ETSI_HI },
    { 140, 5700, REG_CH_DFS, 60, ETSI_HI },
};

static const reg_table_t g_tables[REG_JUR_COUNT] = {
    [REG_JUR_NONE] = { REG_JUR_NONE, "", "", NULL, 0 },
    [REG_JUR_FCC]  = { REG_JUR_FCC, "FCC",
                       "47 CFR 15.407 (eCFR, read " REG_TABLE_AS_OF ")",
                       g_fcc_rows,
                       (int)(sizeof(g_fcc_rows) / sizeof(g_fcc_rows[0])) },
    [REG_JUR_ETSI] = { REG_JUR_ETSI, "ETSI",
                       "ETSI EN 301 893 V2.1.1 (2017-05)",
                       g_etsi_rows,
                       (int)(sizeof(g_etsi_rows) / sizeof(g_etsi_rows[0])) },
};

/* EU member states as listed on europa.eu ("EU countries"), read on
 * REG_TABLE_AS_OF — the territory in which Directive 2014/53/EU makes
 * EN 301 893 the harmonised standard. ISO 3166-1 alpha-2, so Greece is
 * "GR", not the EU's own "EL". EEA states and the UK apply the same or
 * a derived standard by their own instruments, which were not read, so
 * they are not here. */
static const char *const g_eu_members[] = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
    "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU",
    "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
};

const reg_table_t *reg_table_get(reg_jurisdiction_t j) {
    if (j <= REG_JUR_NONE || j >= REG_JUR_COUNT) return NULL;
    return &g_tables[j];
}

reg_jurisdiction_t reg_jurisdiction_for_country(const char *cc) {
    /* strcmp against two-letter codes rejects "", "U" and "USA" alike. */
    if (!cc) return REG_JUR_NONE;
    if (strcmp(cc, "US") == 0) return REG_JUR_FCC;
    for (size_t i = 0; i < sizeof(g_eu_members) / sizeof(g_eu_members[0]); i++)
        if (strcmp(cc, g_eu_members[i]) == 0) return REG_JUR_ETSI;
    return REG_JUR_NONE;
}

const reg_chan_row_t *reg_table_lookup(reg_jurisdiction_t j, int channel) {
    const reg_table_t *t = reg_table_get(j);
    if (!t) return NULL;
    for (int i = 0; i < t->n_rows; i++)
        if (t->rows[i].channel == channel) return &t->rows[i];
    return NULL;
}

int reg_channel_is_dfs(const char *cc, int channel,
                       reg_jurisdiction_t *which, int *cac_s) {
    reg_jurisdiction_t j = reg_jurisdiction_for_country(cc);
    if (which) *which = j;
    if (cac_s) *cac_s = 0;

    if (j != REG_JUR_NONE) {
        const reg_chan_row_t *r = reg_table_lookup(j, channel);
        if (!r || !(r->flags & REG_CH_DFS)) return 0;
        if (cac_s) *cac_s = r->cac_s;
        return 1;
    }

    /* No mapped country: the union. DFS if any source requires it, and
     * the longest CAC any of them would impose. */
    int dfs = 0, cac = 0;
    for (int t = REG_JUR_NONE + 1; t < REG_JUR_COUNT; t++) {
        const reg_chan_row_t *r = reg_table_lookup((reg_jurisdiction_t)t,
                                                   channel);
        if (!r || !(r->flags & REG_CH_DFS)) continue;
        dfs = 1;
        if (r->cac_s > cac) cac = r->cac_s;
    }
    if (cac_s) *cac_s = cac;
    return dfs;
}
