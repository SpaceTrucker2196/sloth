/* The RSSI path-loss model's numbers and pure arithmetic, as a leaf:
 * no sloth.h, so slothweb links the same code (the fleet's multi-sensor
 * location, web/src/web_locate.h) and the sensor and the dashboard
 * cannot disagree about a range. src/rf_distance.h builds the sensor's
 * per-row tracks on it; the contract and every source are there and in
 * research/papers/rssi-distance-estimation.md.
 *
 *   d = 10 ^ ((P_tx - RSSI - (20 log10 f - 28) - offset) / N)
 *
 * is ITU-R P.1238-10 eq. (1) solved for d on one floor. */
#ifndef SLOTH_RF_MODEL_H
#define SLOTH_RF_MODEL_H

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

/* BLE's centre frequency for the model, MHz: the 2.4 GHz band's middle. */
#define RF_BLE_MHZ        2440

/* Calibration: bound on the offset, dB. A reference that wants more
 * than this is not a gain correction; it is a wrong distance or a wall,
 * and is refused. */
#define RF_CAL_MAX_DB       20.0

/* Free-space loss at 1 m, dB, for f in MHz: 20 log10 f - 28. */
double rf_ref_loss_db(int freq_mhz);

/* Metres for one P_tx / RSSI pair, or -1 when an input is unusable
 * (freq <= 0, n_x10 <= 0, rssi == 0). Not clamped. */
double rf_distance_m(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double offset_db);

/* The offset that would put a reference transmitter at ref_m, dB, with
 * no bound: rf_ref_offset_db() applies RF_CAL_MAX_DB. 0 for an unusable
 * input (as rf_distance_m()), else 1 and *offset. */
int rf_ref_offset_raw(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                      double ref_m, double *offset);

/* The offset that makes the model put a reference AP at ref_m. 1 and
 * *offset when |offset| <= RF_CAL_MAX_DB, else 0. */
int rf_ref_offset_db(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double ref_m, double *offset);

/* Export quantisation: 0.5 m below 10 m, 1 m below 100 m, 10 m above.
 * A third party's proximity never leaves the process finer than that. */
double rf_quantise_m(double m);

#endif /* SLOTH_RF_MODEL_H */
