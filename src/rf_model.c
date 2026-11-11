/* The path-loss model's pure arithmetic (rf_model.h). A leaf: linked by
 * sloth and by slothweb. */
#include <math.h>

#include "rf_model.h"

double rf_ref_loss_db(int freq_mhz) {
    return 20.0 * log10((double)freq_mhz) - 28.0;
}

double rf_distance_m(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double offset_db) {
    if (freq_mhz <= 0 || n_x10 <= 0 || rssi_dbm == 0) return -1.0;
    double excess = (double)(ptx_dbm - rssi_dbm) - rf_ref_loss_db(freq_mhz) - offset_db;
    return pow(10.0, excess / (double)n_x10);
}

int rf_ref_offset_raw(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                      double ref_m, double *offset) {
    if (freq_mhz <= 0 || n_x10 <= 0 || rssi_dbm == 0 || ref_m <= 0) return 0;
    double model = rf_ref_loss_db(freq_mhz) + (double)n_x10 * log10(ref_m);
    if (offset) *offset = (double)(ptx_dbm - rssi_dbm) - model;
    return 1;
}

int rf_ref_offset_db(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double ref_m, double *offset) {
    double off = 0;
    if (!rf_ref_offset_raw(ptx_dbm, rssi_dbm, freq_mhz, n_x10, ref_m, &off)) return 0;
    if (off > RF_CAL_MAX_DB || off < -RF_CAL_MAX_DB) return 0;
    if (offset) *offset = off;
    return 1;
}

double rf_quantise_m(double m) {
    if (m < 0)     return m;
    if (m < 10.0)  return floor(m * 2.0 + 0.5) / 2.0;
    if (m < 100.0) return floor(m + 0.5);
    return floor(m / 10.0 + 0.5) * 10.0;
}
