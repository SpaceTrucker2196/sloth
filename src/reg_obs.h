#ifndef SLOTH_REG_OBS_H
#define SLOTH_REG_OBS_H

#include <stddef.h>
#include "sloth.h"

/* Operator-facing readings of the regulatory claims (#101 slice B): the
 * REG column on the [b] beacon list and the observed-vs-claimed power
 * delta on its detail screen. Pure functions of beacon_ap_t, so the view
 * stays a renderer and the arithmetic is testable without a screen.
 *
 * Neither is a verdict. No alert reads them, and the power delta in
 * particular is an observation with its assumption stated, because
 * received strength minus claimed transmit power is a distance the
 * sensor does not know. */

/* 1 when any regulatory element has ever been parsed from this BSSID —
 * including a malformed one, which is itself worth showing. */
int reg_obs_any(const reg_ie_t *r, const reg_6g_t *g);

/* Compact status for a column `width` cells wide (`sz` must exceed it).
 * Tokens in priority order, each added only while the whole still fits,
 * the first that does not fit ending the list:
 *
 *   CC[/E]  Country code, filtered to [A-Za-z0-9] ('?' otherwise), with
 *           the environment: /I indoor, /O outdoor, /X non-country,
 *           /T Annex E table, /? undefined octet, none for "any";
 *           "--" when other elements arrived but no Country element
 *   MAL     some regulatory element from this BSSID was malformed
 *   6G:IN / 6G:SP / 6G:Rn   HE 6 GHz Regulatory Info
 *   TPCn    TPC Report transmit power, dBm
 *   PCn     Power Constraint, dB
 *   TPEn    n Transmit Power Envelope entries retained
 *
 * "-" when nothing regulatory was ever parsed. The country token alone
 * is truncated to the width rather than dropped. */
void reg_obs_column(const reg_ie_t *r, const reg_6g_t *g, int width,
                    char *out, size_t sz);

typedef enum {
    REG_PWR_SRC_NONE = 0,
    REG_PWR_SRC_TPC,        /* TPC Report: power this frame was sent at */
    REG_PWR_SRC_TPE         /* TPE local EIRP, 20 MHz: the BSS ceiling   */
} reg_pwr_src_t;

/* Free-space path loss at 1 m, in dB, for `freq_mhz`:
 * FSPL = 20 log10(d_m) + 20 log10(f_MHz) - 27.55 with d = 1. */
double reg_obs_fspl_1m_db(int freq_mhz);

/* Centre frequency of a primary channel, 0 when the band is unknown.
 * Same band rule as ap_band_label(): 6 GHz only on channel_source. */
int reg_obs_freq_mhz(int channel, uint8_t channel_source);

typedef struct {
    reg_pwr_src_t src;
    double claimed_dbm;     /* TPC power, or TPE 20 MHz EIRP ceiling      */
    int    heard_dbm;       /* signal_dbm, the most recent reading        */
    int    freq_mhz;
    double fspl_1m_db;
    /* claimed - heard: what the path would have to lose for the claim to
     * hold, antenna gains taken as 0 dBi. */
    double apparent_loss_db;
    /* fspl_1m - apparent_loss. Positive means the AP was heard stronger
     * than a transmitter at the claimed power could produce at 1 m in
     * free space — the claim and the reading cannot both be true without
     * antenna gain, or the sensor sitting within a metre of the AP. */
    double excess_db;
} reg_power_obs_t;

/* 1 and `out` filled when the AP has a power claim (TPC Report first,
 * else a decoded default-category local EIRP TPE), a signal reading
 * (signal_dbm < 0) and a known band; 0 otherwise, `out` zeroed. */
int reg_obs_power(const beacon_ap_t *ap, reg_power_obs_t *out);

#endif /* SLOTH_REG_OBS_H */
