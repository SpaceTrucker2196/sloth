/* Distance from received signal strength, as a data point.
 *
 * Owner request 2026-10-26: "use rf signal strength to estimate distance
 * as a data point". An estimate from signal strength: walls and
 * reflections dominate, and it is not a location. No alert rule reads
 * anything here — a behavioural threshold on a figure whose typical
 * indoor error is a factor of two to five would be a guess.
 *
 * Every number below is cited in research/papers/rssi-distance-
 * estimation.md; the ones that are sloth's own choices say so there and
 * here. In short:
 *
 *   d = 10 ^ ((P_tx - RSSI - (20 log10 f - 28) - offset) / N)
 *
 * is ITU-R P.1238-10 eq. (1) solved for d on one floor (Lf = 0), with
 * L(d0 = 1 m) = 20 log10 f - 28 (f in MHz) and N the distance power
 * loss coefficient from its Table 2. P_tx is what the device announced
 * (802.11 TPC Report, else the Country element's ceiling, flagged as an
 * upper bound; BLE extended-header TxPower, else the TX Power Level AD
 * type), else an assumed per-radio default flagged "assumed". RSSI is
 * the median of the last K samples. The interval combines P.1238-10
 * Table 4's shadow-fading sigma, the samples' own spread, and an
 * assumed-power term, in quadrature - on both sides for an assumed
 * P_tx, on the low side only for a Country ceiling, which can only be
 * too high.
 *
 * Everything that takes numbers is a pure function of its arguments so
 * the tests can pin it with fixed values. The two impure corners are
 * the tune registry reads in rf_track_observe() and the calibration
 * offsets, which the poll loop sets from the operator's own AP and the
 * capture threads read (one mutex private to rf_distance.c, a leaf). */

#ifndef SLOTH_RF_DISTANCE_H
#define SLOTH_RF_DISTANCE_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "sloth.h"      /* rf_track_t, reg_ie_t, sloth_state_t */
#include "wifi_freq.h"

/* Which radio heard it: picks N, sigma and the calibration slot. BLE
 * shares 2.4 GHz propagation but never a Wi-Fi calibration — its
 * controller is a different receiver with a different gain. */
typedef enum {
    RF_RADIO_NONE = 0,
    RF_RADIO_WIFI_2G,
    RF_RADIO_WIFI_5G,
    RF_RADIO_WIFI_6G,
    RF_RADIO_BLE,
    RF_RADIO_COUNT
} rf_radio_t;

typedef enum {
    RF_PTX_NONE = 0,
    RF_PTX_TPC_REPORT,     /* 802.11-2020 §9.4.2.16: the frame's own power */
    RF_PTX_COUNTRY_MAX,    /* §9.4.2.8 (- §9.4.2.13): a ceiling, upper bound */
    RF_PTX_BLE_EXT,        /* Core v6.0 Vol 4 Part E §7.7.65.13 TX_Power */
    RF_PTX_BLE_AD,         /* Core Supplement v11 Part A §1.5 */
    RF_PTX_ASSUMED         /* nothing announced: a sloth default */
} rf_ptx_source_t;

typedef enum {
    RF_DIST_NONE = 0,
    RF_DIST_IMMEDIATE,     /* <  RF_BAND_IMMEDIATE_M */
    RF_DIST_NEAR,          /* <  RF_BAND_NEAR_M      */
    RF_DIST_ROOM,          /* <  RF_BAND_ROOM_M      */
    RF_DIST_BUILDING,      /* <  RF_BAND_BUILDING_M  */
    RF_DIST_FAR
} rf_dist_band_t;

typedef enum {
    RF_TREND_UNKNOWN = 0,  /* too few points to say */
    RF_TREND_APPROACHING,  /* RSSI rising */
    RF_TREND_STEADY,
    RF_TREND_LEAVING       /* RSSI falling */
} rf_trend_t;

/* ── Coefficients (research/papers/rssi-distance-estimation.md) ── */

/* N x 10, ITU-R P.1238-10 Table 2: 2.4 GHz residential 28; 5.2 GHz
 * residential (apartment) 30; 6 GHz has no row and takes the 5.2 GHz
 * value. --tune rf.path_loss_n_{2g,5g,6g}; BLE uses the 2g knob. */
#define RF_N_2G_X10        28
#define RF_N_5G_X10        30
#define RF_N_6G_X10        30
#define RF_N_X10_LO        16   /* below P.1238's corridor ~18 */
#define RF_N_X10_HI        60   /* above its worst ~44 */

/* Shadow-fading sigma, dB, P.1238-10 Table 4: 1.8-2 GHz residential 8
 * (no 2.4 GHz row); 5.2 GHz office 12 (no residential row). */
#define RF_SIGMA_2G_DB      8.0
#define RF_SIGMA_5G_DB     12.0
#define RF_SIGMA_6G_DB     12.0

/* Assumed transmit powers, dBm, and the extra sigma an assumption
 * costs. sloth's choices, no cited basis: that is what "assumed" says. */
#define RF_PTX_AP_ASSUMED   20
#define RF_PTX_STA_ASSUMED  15
#define RF_PTX_BLE_ASSUMED   0
#define RF_ASSUMED_SIGMA_DB 6.0

/* Robust statistic: median of the last K samples inside the window. */
#define RF_MEDIAN_K          8     /* --tune rf.median_k, 1..RF_RAW_MAX */
#define RF_WINDOW_S         60

/* Band boundaries, metres. immediate / near are the iBeacon zones as
 * Zafari et al. arXiv:1709.01015 §III-B describe them (<1 m, 1-3 m);
 * room is sloth's cut; building ends at 30 m, the top of ITU-R
 * P.1238-13 Table 2's office NLoS fit range (4-30 m).
 *
 * A band changes only when the estimate is past the boundary by a
 * margin in dB, and stays past it for RF_BAND_HOLD_S. The margin is
 * RF_BAND_HYST_DB or RF_BAND_HYST_SE standard errors of the median
 * (1.2533 x spread / sqrt(samples)), whichever is larger, so a noisier
 * row needs a larger move. A fixed 25 % in metres (2.7 dB at N 2.8)
 * was crossed by the median of a stationary advertiser several times a
 * minute at sigma 4-6 dB; the band is signed into the change-only
 * ble_device record, so every crossing was a record. sloth's choices,
 * sized by the seeded-noise test in tests/test_rf_distance.c. */
#define RF_BAND_IMMEDIATE_M  1.0
#define RF_BAND_NEAR_M       3.0
#define RF_BAND_ROOM_M      10.0
#define RF_BAND_BUILDING_M  30.0
#define RF_BAND_HYST_DB      3.0
#define RF_BAND_HYST_SE      2.0
#define RF_BAND_HOLD_S      10

/* Trend: one median point per >= STEP s, window WINDOW s, at least
 * MIN_PTS points spanning MIN_SPAN s. Slope in dB per 10 s, enter at
 * ENTER and hold while beyond EXIT. sloth's choices, not cited. */
#define RF_TREND_STEP_S      2
#define RF_TREND_WINDOW_S   30
#define RF_TREND_MIN_PTS     4
#define RF_TREND_MIN_SPAN_S  6
#define RF_TREND_ENTER_DB10  3.0
#define RF_TREND_EXIT_DB10   1.5

/* Calibration (--tune rf.ref_dist_dm with --my-bssid): bound on the
 * offset, dB. A reference that wants more than this is not a gain
 * correction; it is a wrong distance or a wall, and is refused. */
#define RF_CAL_MAX_DB       20.0
#define RF_REF_DIST_DM_HI 1000

/* Cell widths for the TUI distance column: "~150m bldg ↘" and "~150m↘". */
#define RF_CELL_FULL        12
#define RF_CELL_SHORT        6

/* What the estimate needs to know about the row. Build it with one of
 * the rf_ctx_* helpers. freq_mhz 0 means the band is unknown: no
 * estimate, rather than one computed at a guessed frequency. */
typedef struct {
    rf_radio_t radio;
    int        freq_mhz;
    int        ptx_dbm;
    uint8_t    ptx_source;   /* rf_ptx_source_t */
} rf_ctx_t;

/* Radio and centre frequency for a Wi-Fi channel. `band` may be
 * WIFI_BAND_UNKNOWN, in which case the number decides (wifi_freq.h's
 * inference: 6 GHz is never inferred from a number alone). */
void rf_ctx_wifi(rf_ctx_t *c, int channel, wifi_band_t band);

/* An AP row: TPC Report, else the Country ceiling for `channel` less
 * any Power Constraint when it is at most RF_PTX_AP_ASSUMED and the
 * band is not 6 GHz, else RF_PTX_AP_ASSUMED. `reg` may be NULL. A
 * ceiling estimate is an upper bound; its interval widens downward
 * only (rf_track_observe()). */
void rf_ctx_ap(rf_ctx_t *c, const reg_ie_t *reg, int channel, wifi_band_t band);

/* A row whose transmitter announced nothing: `ptx_dbm` assumed. */
void rf_ctx_assumed(rf_ctx_t *c, int channel, wifi_band_t band, int ptx_dbm);

/* A BLE row. Extended-header TX_Power is preferred to the AD type: it
 * is the controller's statement about this PDU (§7.7.65.13), where the
 * AD structure is whatever the host wrote into the payload. */
void rf_ctx_ble(rf_ctx_t *c, int has_ext, int ext_dbm, int has_ad, int ad_dbm);

/* The Country element's ceiling for `channel`, less any Power
 * Constraint: 1 and *dbm on a subband triplet covering the channel, 0
 * otherwise. Triplets step 1 channel below 15 and 4 above: 2.4 and
 * 5 GHz numbering, so a 6 GHz caller must not ask (rf_ctx_ap() does
 * not). */
int rf_country_max_dbm(const reg_ie_t *reg, int channel, int *dbm);

/* ── Pure arithmetic ───────────────────────────────────────────── */

/* Median and spread (MAD x 1.4826, rounded) of v[0..n). Sorts a copy;
 * v is untouched. Returns n, 0 for n <= 0 (outputs untouched). */
int rf_median_spread(const int8_t *v, int n, int *median, int *spread_db);

/* Free-space loss at 1 m, dB, for f in MHz: 20 log10 f - 28. */
double rf_ref_loss_db(int freq_mhz);

/* Metres for one P_tx / RSSI pair, or -1 when an input is unusable
 * (freq <= 0, n_x10 <= 0, rssi == 0). Not clamped. */
double rf_distance_m(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double offset_db);

/* The offset that makes the model put a reference AP at ref_m. 1 and
 * *offset when |offset| <= RF_CAL_MAX_DB, else 0. */
int rf_ref_offset_db(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double ref_m, double *offset);

/* The band `m` lies in, without and with hysteresis against `prev`:
 * leaving `prev` needs `m` past the boundary by `hyst_db` of path loss
 * at exponent n_x10 / 10, a factor of 10 ^ (hyst_db / n_x10) in metres.
 * No hold: rf_track_observe() adds that. */
rf_dist_band_t rf_band_of(double m);
rf_dist_band_t rf_band_hyst(rf_dist_band_t prev, double m, double hyst_db,
                            int n_x10);

/* The margin for a median of `n` samples with spread `spread_db`:
 * max(RF_BAND_HYST_DB, RF_BAND_HYST_SE x 1.2533 x spread / sqrt(n)). */
double rf_band_hyst_db(int spread_db, int n);

/* Least-squares slope of dbm[] over ts[], in dB per 10 s. 0 for fewer
 * than two points or no time span. */
double rf_slope_db10(const int8_t *dbm, const time_t *ts, int n);

/* Trend with hysteresis. `enough` 0 means too few points: UNKNOWN. */
rf_trend_t rf_trend_hyst(rf_trend_t prev, double slope_db10, int enough);

/* Export quantisation: 0.5 m below 10 m, 1 m below 100 m, 10 m above.
 * A third party's proximity never leaves the process finer than that. */
double rf_quantise_m(double m);

/* Sigma and N (x10, the tune registry's current value) for a radio. */
double rf_sigma_db(rf_radio_t r);
int    rf_n_x10(rf_radio_t r);

/* ── The per-row track ────────────────────────────────────────── */

/* Record one sample and recompute the row's estimate. An RSSI of 0, or
 * outside -127..+20 dBm, records nothing and leaves the previous output
 * as it was; so does a ctx with no frequency. */
void rf_track_observe(rf_track_t *t, int rssi_dbm, time_t ts, const rf_ctx_t *c);

/* Labels. Stable slugs: they are the JSONL values. */
const char *rf_band_name(int band);         /* "immediate" .. "far", "" */
const char *rf_band_short(int band);        /* "imm" "near" "room" "bldg" "far" */
const char *rf_trend_name(int trend);       /* "approaching" "steady" "leaving" "unknown" */
const char *rf_trend_glyph(int trend);      /* U+2198 / U+2192 / U+2197, " " */
const char *rf_ptx_source_name(int src);    /* "tpc_report" ... "assumed", "" */

/* The TUI cell: exactly `width` terminal cells (>= RF_CELL_SHORT),
 * NUL-terminated in buf. Full form at width >= RF_CELL_FULL, short form
 * below; "-" when the track has no estimate. Returns the cells. */
int rf_dist_cell(const rf_track_t *t, char *buf, size_t n, int width);

/* "~4.5m (2.0-10m) room steady, Ptx 20 assumed" for detail panes, at
 * most 60 octets; "no estimate" when there is none. "ceiling" marks a
 * Country-element P_tx, whose distance is an upper bound. */
void rf_dist_describe(const rf_track_t *t, char *buf, size_t n);

/* ── Calibration ──────────────────────────────────────────────── */

/* Offsets per radio. Set by rf_calibration_update(); read by
 * rf_track_observe() on every capture thread. */
void rf_calibration_set(rf_radio_t r, int valid, double offset_db);
int  rf_calibration_get(rf_radio_t r, double *offset_db);
void rf_calibration_reset(void);

/* Poll loop, after beacon_snapshot(): with rf.ref_dist_dm off, clear
 * every offset; with it on, derive one per Wi-Fi radio from the
 * strongest --my-bssid beacon row with an estimate, and clear any radio
 * that has none. Never touches the BLE slot. */
void rf_calibration_update(const sloth_state_t *s);

#endif /* SLOTH_RF_DISTANCE_H */
