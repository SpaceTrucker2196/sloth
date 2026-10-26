/* The 802.11 band plan. Contract and history in wifi_freq.h (#167). */

#include <stddef.h>

#include "wifi_freq.h"

/* One row per band: the assignable channel-number span and the datum
 * the 5 MHz channel grid is measured from, so a centre frequency is
 * `datum_mhz + 5 * channel` and the band's frequency span falls out of
 * the same two numbers. This table is the only place a frequency or
 * channel range is written down.
 *
 * The 5 GHz span is the reconciliation #167 asks for, and it is neither
 * of the two bounds that disagreed. 5160 MHz is channel 32, the lowest
 * 20 MHz centre Annex E Table E-4 assigns (the 5150-5170 slot), with
 * channel 34 the 802.11j legacy centre just above it; the nl80211
 * path's 5180 floor reported channel 0 for an AP on either. 5885 MHz is
 * channel 177, the highest centre the table assigns — it is U-NII-4's
 * top 20 MHz channel, spanning 5875-5895, so radiotap's old 5895
 * ceiling and nl80211's 5900 were both band EDGES rather than centres
 * and both answered with channel numbers (179, 180) that no 802.11
 * device can report. 32..177 is also what the forward converters in
 * reg_obs.c and ap_band_label() already used, so the two directions now
 * round-trip instead of holding a fourth opinion. */
typedef struct {
    wifi_band_t band;
    int         lo_ch;      /* lowest assignable channel number */
    int         hi_ch;      /* highest assignable channel number */
    int         datum_mhz;  /* centre = datum_mhz + 5 * channel */
} band_plan_t;

static const band_plan_t PLAN[] = {
    { WIFI_BAND_2GHZ,  1,  13, 2407 },
    { WIFI_BAND_5GHZ, 32, 177, 5000 },
    { WIFI_BAND_6GHZ,  1, 233, 5950 },
};

#define PLAN_N (sizeof(PLAN) / sizeof(PLAN[0]))

/* The two centres that are not on their band's datum grid: 2.4 GHz
 * channel 14 sits 12 MHz above channel 13 instead of 5, and 6 GHz
 * channel 2 is assigned out of order at 5935 MHz, below channel 1's
 * 5955 (802.11ax-2021 §27.3.23.2). Both are real 20 MHz channels, so
 * they are table rows rather than arithmetic. */
typedef struct {
    wifi_band_t band;
    int         channel;
    int         mhz;
} band_exception_t;

static const band_exception_t EXCEPTIONS[] = {
    { WIFI_BAND_2GHZ, 14, 2484 },
    { WIFI_BAND_6GHZ,  2, 5935 },
};

#define EXCEPTIONS_N (sizeof(EXCEPTIONS) / sizeof(EXCEPTIONS[0]))

static const band_plan_t *plan_for(wifi_band_t band) {
    for (size_t i = 0; i < PLAN_N; i++)
        if (PLAN[i].band == band) return &PLAN[i];
    return NULL;
}

wifi_band_t wifi_freq_band(int mhz) {
    for (size_t i = 0; i < EXCEPTIONS_N; i++)
        if (EXCEPTIONS[i].mhz == mhz) return EXCEPTIONS[i].band;

    for (size_t i = 0; i < PLAN_N; i++) {
        const band_plan_t *p = &PLAN[i];
        if (mhz >= p->datum_mhz + 5 * p->lo_ch &&
            mhz <= p->datum_mhz + 5 * p->hi_ch)
            return p->band;
    }
    return WIFI_BAND_UNKNOWN;
}

int wifi_freq_channel(int mhz, wifi_band_t *band_out) {
    wifi_band_t band = wifi_freq_band(mhz);
    if (band_out) *band_out = band;
    if (band == WIFI_BAND_UNKNOWN) return 0;

    for (size_t i = 0; i < EXCEPTIONS_N; i++)
        if (EXCEPTIONS[i].mhz == mhz) return EXCEPTIONS[i].channel;

    const band_plan_t *p = plan_for(band);
    if (!p) return 0;
    int ch = (mhz - p->datum_mhz) / 5;

    /* Refuse the frequency the datum arithmetic steals from an
     * out-of-order channel. 5960 MHz would compute 6 GHz channel 2,
     * which actually sits 25 MHz lower at 5935, so answering 2 here
     * would name the wrong frequency; 5960 is not a 20 MHz centre in
     * its own right either, so nothing is lost and the mapping stays
     * invertible. The band is still reported — being inside 6 GHz and
     * not being a channel centre are different facts. */
    for (size_t i = 0; i < EXCEPTIONS_N; i++)
        if (EXCEPTIONS[i].band == band && EXCEPTIONS[i].channel == ch)
            return 0;

    return ch;
}

int wifi_freq_mhz(wifi_band_t band, int channel) {
    if (channel <= 0) return 0;

    for (size_t i = 0; i < EXCEPTIONS_N; i++)
        if (EXCEPTIONS[i].band == band && EXCEPTIONS[i].channel == channel)
            return EXCEPTIONS[i].mhz;

    const band_plan_t *p = plan_for(band);
    if (!p) return 0;
    if (channel < p->lo_ch || channel > p->hi_ch) return 0;
    return p->datum_mhz + 5 * channel;
}

wifi_band_t wifi_freq_infer_band(int channel) {
    if (channel <= 0) return WIFI_BAND_UNKNOWN;

    for (size_t i = 0; i < EXCEPTIONS_N; i++)
        if (EXCEPTIONS[i].band != WIFI_BAND_6GHZ &&
            EXCEPTIONS[i].channel == channel)
            return EXCEPTIONS[i].band;

    for (size_t i = 0; i < PLAN_N; i++) {
        const band_plan_t *p = &PLAN[i];
        if (p->band == WIFI_BAND_6GHZ) continue;
        if (channel >= p->lo_ch && channel <= p->hi_ch) return p->band;
    }
    return WIFI_BAND_UNKNOWN;
}
