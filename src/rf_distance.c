/* Distance from received signal strength. Contract, sources and the
 * choices that are sloth's own: rf_distance.h and
 * research/papers/rssi-distance-estimation.md. */

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rf_distance.h"
#include "ownership.h"
#include "tune.h"

/* ── Context ─────────────────────────────────────────────────── */

void rf_ctx_wifi(rf_ctx_t *c, int channel, wifi_band_t band) {
    memset(c, 0, sizeof(*c));
    if (channel <= 0) return;
    if (band == WIFI_BAND_UNKNOWN) band = wifi_freq_infer_band(channel);
    int mhz = wifi_freq_mhz(band, channel);
    if (mhz <= 0) return;
    c->freq_mhz = mhz;
    c->radio = band == WIFI_BAND_2GHZ ? RF_RADIO_WIFI_2G
             : band == WIFI_BAND_5GHZ ? RF_RADIO_WIFI_5G
             :                          RF_RADIO_WIFI_6G;
}

int rf_country_max_dbm(const reg_ie_t *reg, int channel, int *dbm) {
    if (!reg || !reg->country_present || channel <= 0) return 0;
    for (int i = 0; i < reg->triplet_count && i < REG_MAX_COUNTRY_TRIPLETS; i++) {
        const reg_triplet_t *t = &reg->triplets[i];
        if (t->is_operating || t->num_channels == 0) continue;
        int step = t->first_channel <= 14 ? 1 : 4;
        int last = t->first_channel + (t->num_channels - 1) * step;
        if (channel < t->first_channel || channel > last) continue;
        if ((channel - t->first_channel) % step) continue;
        int p = t->max_tx_power_dbm;
        if (reg->power_constraint_present) p -= reg->power_constraint_db;
        *dbm = p;
        return 1;
    }
    return 0;
}

void rf_ctx_ap(rf_ctx_t *c, const reg_ie_t *reg, int channel, wifi_band_t band) {
    rf_ctx_wifi(c, channel, band);
    int p;
    if (reg && reg->tpc_present) {
        c->ptx_dbm    = reg->tpc_tx_power_dbm;
        c->ptx_source = RF_PTX_TPC_REPORT;
    } else if (rf_country_max_dbm(reg, channel, &p)) {
        c->ptx_dbm    = p;
        c->ptx_source = RF_PTX_COUNTRY_MAX;
    } else {
        c->ptx_dbm    = RF_PTX_AP_ASSUMED;
        c->ptx_source = RF_PTX_ASSUMED;
    }
}

void rf_ctx_assumed(rf_ctx_t *c, int channel, wifi_band_t band, int ptx_dbm) {
    rf_ctx_wifi(c, channel, band);
    c->ptx_dbm    = ptx_dbm;
    c->ptx_source = RF_PTX_ASSUMED;
}

void rf_ctx_ble(rf_ctx_t *c, int has_ext, int ext_dbm, int has_ad, int ad_dbm) {
    memset(c, 0, sizeof(*c));
    c->radio = RF_RADIO_BLE;
    /* The advertising channels are 2402, 2426 and 2480 MHz; 2440 is
     * their middle, and the 0.3 dB the choice can move L(d0) is far
     * inside the 8 dB the model already carries. */
    c->freq_mhz = 2440;
    if (has_ext) {
        c->ptx_dbm = ext_dbm; c->ptx_source = RF_PTX_BLE_EXT;
    } else if (has_ad) {
        c->ptx_dbm = ad_dbm;  c->ptx_source = RF_PTX_BLE_AD;
    } else {
        c->ptx_dbm = RF_PTX_BLE_ASSUMED; c->ptx_source = RF_PTX_ASSUMED;
    }
}

/* ── Pure arithmetic ─────────────────────────────────────────── */

static int cmp_i(const void *a, const void *b) {
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

/* Median of a sorted int array: the mean of the middle pair, rounded
 * half away from zero, for an even count. */
static double sorted_median(const int *v, int n) {
    if (n & 1) return v[n / 2];
    return (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

static int round_i(double x) { return (int)(x < 0 ? x - 0.5 : x + 0.5); }

int rf_median_spread(const int8_t *v, int n, int *median, int *spread_db) {
    if (!v || n <= 0) return 0;
    if (n > RF_RAW_MAX) n = RF_RAW_MAX;
    int a[RF_RAW_MAX] = {0}, d[RF_RAW_MAX] = {0};
    for (int i = 0; i < n; i++) a[i] = v[i];
    qsort(a, (size_t)n, sizeof(a[0]), cmp_i);
    double med = sorted_median(a, n);
    /* MAD on doubled values so a half-dB median stays exact. */
    for (int i = 0; i < n; i++) d[i] = abs(2 * a[i] - (int)(2 * med));
    qsort(d, (size_t)n, sizeof(d[0]), cmp_i);
    double mad = sorted_median(d, n) / 2.0;
    if (median)    *median    = round_i(med);
    if (spread_db) {
        int sp = round_i(mad * 1.4826);
        *spread_db = sp > 255 ? 255 : sp;
    }
    return n;
}

double rf_ref_loss_db(int freq_mhz) {
    return 20.0 * log10((double)freq_mhz) - 28.0;
}

double rf_distance_m(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double offset_db) {
    if (freq_mhz <= 0 || n_x10 <= 0 || rssi_dbm == 0) return -1.0;
    double excess = (double)(ptx_dbm - rssi_dbm) - rf_ref_loss_db(freq_mhz) - offset_db;
    return pow(10.0, excess / (double)n_x10);
}

int rf_ref_offset_db(int ptx_dbm, int rssi_dbm, int freq_mhz, int n_x10,
                     double ref_m, double *offset) {
    if (freq_mhz <= 0 || n_x10 <= 0 || rssi_dbm == 0 || ref_m <= 0) return 0;
    double model = rf_ref_loss_db(freq_mhz) + (double)n_x10 * log10(ref_m);
    double off   = (double)(ptx_dbm - rssi_dbm) - model;
    if (off > RF_CAL_MAX_DB || off < -RF_CAL_MAX_DB) return 0;
    if (offset) *offset = off;
    return 1;
}

rf_dist_band_t rf_band_of(double m) {
    if (m < 0)                   return RF_DIST_NONE;
    if (m < RF_BAND_IMMEDIATE_M) return RF_DIST_IMMEDIATE;
    if (m < RF_BAND_NEAR_M)      return RF_DIST_NEAR;
    if (m < RF_BAND_ROOM_M)      return RF_DIST_ROOM;
    if (m < RF_BAND_BUILDING_M)  return RF_DIST_BUILDING;
    return RF_DIST_FAR;
}

rf_dist_band_t rf_band_hyst(rf_dist_band_t prev, double m) {
    rf_dist_band_t raw = rf_band_of(m);
    if (prev == RF_DIST_NONE || raw == RF_DIST_NONE || raw == prev) return raw;
    /* Moving out of `prev` needs the estimate to be past the boundary
     * by RF_BAND_HYST, so a device sitting on a boundary holds a band. */
    if (raw > prev) {
        rf_dist_band_t b = rf_band_of(m / RF_BAND_HYST);
        return b > prev ? b : prev;
    }
    rf_dist_band_t b = rf_band_of(m * RF_BAND_HYST);
    return b < prev ? b : prev;
}

double rf_slope_db10(const int8_t *dbm, const time_t *ts, int n) {
    if (!dbm || !ts || n < 2) return 0.0;
    /* Relative to the first point, so a large epoch costs no precision. */
    double sx = 0, sy = 0, sxx = 0, sxy = 0;
    for (int i = 0; i < n; i++) {
        double x = (double)(ts[i] - ts[0]);
        double y = (double)dbm[i];
        sx += x; sy += y; sxx += x * x; sxy += x * y;
    }
    double den = n * sxx - sx * sx;
    if (den <= 0) return 0.0;
    return 10.0 * (n * sxy - sx * sy) / den;
}

rf_trend_t rf_trend_hyst(rf_trend_t prev, double slope, int enough) {
    if (!enough) return RF_TREND_UNKNOWN;
    switch (prev) {
    case RF_TREND_APPROACHING:
        if (slope >= RF_TREND_EXIT_DB10)    return RF_TREND_APPROACHING;
        if (slope <= -RF_TREND_ENTER_DB10)  return RF_TREND_LEAVING;
        return RF_TREND_STEADY;
    case RF_TREND_LEAVING:
        if (slope <= -RF_TREND_EXIT_DB10)   return RF_TREND_LEAVING;
        if (slope >= RF_TREND_ENTER_DB10)   return RF_TREND_APPROACHING;
        return RF_TREND_STEADY;
    default:
        if (slope >= RF_TREND_ENTER_DB10)   return RF_TREND_APPROACHING;
        if (slope <= -RF_TREND_ENTER_DB10)  return RF_TREND_LEAVING;
        return RF_TREND_STEADY;
    }
}

double rf_quantise_m(double m) {
    if (m < 0)     return m;
    if (m < 10.0)  return floor(m * 2.0 + 0.5) / 2.0;
    if (m < 100.0) return floor(m + 0.5);
    return floor(m / 10.0 + 0.5) * 10.0;
}

double rf_sigma_db(rf_radio_t r) {
    switch (r) {
    case RF_RADIO_WIFI_5G: return RF_SIGMA_5G_DB;
    case RF_RADIO_WIFI_6G: return RF_SIGMA_6G_DB;
    default:               return RF_SIGMA_2G_DB;
    }
}

int rf_n_x10(rf_radio_t r) {
    switch (r) {
    case RF_RADIO_WIFI_5G: return (int)tune_val(TUNE_RF_PATH_LOSS_N_5G);
    case RF_RADIO_WIFI_6G: return (int)tune_val(TUNE_RF_PATH_LOSS_N_6G);
    default:               return (int)tune_val(TUNE_RF_PATH_LOSS_N_2G);
    }
}

/* ── Calibration ─────────────────────────────────────────────── */

static pthread_mutex_t g_cal_mu = PTHREAD_MUTEX_INITIALIZER;
static int    g_cal_valid[RF_RADIO_COUNT];
static double g_cal_off[RF_RADIO_COUNT];

void rf_calibration_set(rf_radio_t r, int valid, double offset_db) {
    if ((int)r <= RF_RADIO_NONE || r >= RF_RADIO_COUNT) return;
    pthread_mutex_lock(&g_cal_mu);
    g_cal_valid[r] = valid ? 1 : 0;
    g_cal_off[r]   = valid ? offset_db : 0.0;
    pthread_mutex_unlock(&g_cal_mu);
}

int rf_calibration_get(rf_radio_t r, double *offset_db) {
    if ((int)r <= RF_RADIO_NONE || r >= RF_RADIO_COUNT) return 0;
    pthread_mutex_lock(&g_cal_mu);
    int v = g_cal_valid[r];
    double o = g_cal_off[r];
    pthread_mutex_unlock(&g_cal_mu);
    if (v && offset_db) *offset_db = o;
    return v;
}

void rf_calibration_reset(void) {
    pthread_mutex_lock(&g_cal_mu);
    memset(g_cal_valid, 0, sizeof(g_cal_valid));
    memset(g_cal_off, 0, sizeof(g_cal_off));
    pthread_mutex_unlock(&g_cal_mu);
}

void rf_calibration_update(const sloth_state_t *s) {
    long ref_dm = tune_val(TUNE_RF_REF_DIST_DM);
    for (int r = RF_RADIO_WIFI_2G; r <= RF_RADIO_WIFI_6G; r++) {
        const beacon_ap_t *best = NULL;
        if (ref_dm > 0 && s) {
            for (int i = 0; i < s->beacon_count; i++) {
                const beacon_ap_t *ap = &s->beacon_aps[i];
                if (!ap->dist.valid || ap->dist.radio != r) continue;
                if (!ownership_is_my_bssid(ap->bssid)) continue;
                if (!best || ap->dist.rssi_med > best->dist.rssi_med) best = ap;
            }
        }
        double off = 0;
        int ok = 0;
        if (best) {
            rf_ctx_t c;
            rf_ctx_ap(&c, &best->reg, best->channel,
                      best->channel_source == CH_SRC_HE_6GHZ ? WIFI_BAND_6GHZ
                                                             : WIFI_BAND_UNKNOWN);
            ok = c.freq_mhz > 0 &&
                 rf_ref_offset_db(best->dist.ptx_dbm, best->dist.rssi_med,
                                  c.freq_mhz, rf_n_x10((rf_radio_t)r),
                                  (double)ref_dm / 10.0, &off);
        }
        rf_calibration_set((rf_radio_t)r, ok, off);
    }
}

/* ── The track ───────────────────────────────────────────────── */

static uint16_t to_dm(double m) {
    double dm = m * 10.0 + 0.5;
    if (dm < 1.0)      return 1;
    if (dm > 65535.0)  return 65535;
    return (uint16_t)dm;
}

/* The newest `k` raw samples within RF_WINDOW_S of the newest one,
 * oldest first in out[]. */
static int recent_raw(const rf_track_t *t, int k, int8_t *out) {
    if (t->raw_n == 0) return 0;
    int newest = (t->raw_head + RF_RAW_MAX - 1) % RF_RAW_MAX;
    time_t tn = t->raw_ts[newest];
    int got = 0;
    int8_t rev[RF_RAW_MAX];
    for (int i = 0; i < t->raw_n && got < k; i++) {
        int idx = (newest + RF_RAW_MAX - i) % RF_RAW_MAX;
        if (tn - t->raw_ts[idx] > RF_WINDOW_S) break;
        rev[got++] = t->raw_dbm[idx];
    }
    for (int i = 0; i < got; i++) out[i] = rev[got - 1 - i];
    return got;
}

void rf_track_observe(rf_track_t *t, int rssi_dbm, time_t ts, const rf_ctx_t *c) {
    if (!t || !c) return;
    /* 0 is "unseen" on every Wi-Fi row, and the HCI range is -127..+20;
     * a sample outside either is not evidence of anything. */
    if (rssi_dbm == 0 || rssi_dbm < -127 || rssi_dbm > 20) return;
    if (c->freq_mhz <= 0 || c->radio == RF_RADIO_NONE) return;

    t->raw_dbm[t->raw_head] = (int8_t)rssi_dbm;
    t->raw_ts [t->raw_head] = ts;
    t->raw_head = (uint8_t)((t->raw_head + 1) % RF_RAW_MAX);
    if (t->raw_n < RF_RAW_MAX) t->raw_n++;

    int k = (int)tune_val(TUNE_RF_MEDIAN_K);
    if (k < 1) k = 1;
    if (k > RF_RAW_MAX) k = RF_RAW_MAX;
    int8_t win[RF_RAW_MAX];
    int n = recent_raw(t, k, win);
    int med = 0, spread = 0;
    if (!rf_median_spread(win, n, &med, &spread)) return;

    double off = 0;
    int cal = c->radio != RF_RADIO_BLE && rf_calibration_get(c->radio, &off);
    int n10 = rf_n_x10(c->radio);
    double m = rf_distance_m(c->ptx_dbm, med, c->freq_mhz, n10, off);
    if (m < 0) return;

    double sig = rf_sigma_db(c->radio);
    double var = sig * sig + (double)spread * spread;
    if (c->ptx_source == RF_PTX_ASSUMED) var += RF_ASSUMED_SIGMA_DB * RF_ASSUMED_SIGMA_DB;
    double f = pow(10.0, sqrt(var) / (double)n10);

    t->band       = (uint8_t)rf_band_hyst(t->valid ? (rf_dist_band_t)t->band
                                                   : RF_DIST_NONE, m);
    t->valid      = 1;
    t->ptx_source = c->ptx_source;
    t->ptx_dbm    = (int8_t)(c->ptx_dbm < -128 ? -128 : c->ptx_dbm > 127 ? 127 : c->ptx_dbm);
    t->rssi_med   = (int8_t)med;
    t->spread_db  = (uint8_t)spread;
    t->samples    = (uint8_t)n;
    t->calibrated = (uint8_t)cal;
    t->radio      = (uint8_t)c->radio;
    t->est_dm     = to_dm(m);
    t->lo_dm      = to_dm(m / f);
    t->hi_dm      = to_dm(m * f);

    /* Trend points are medians, one per RF_TREND_STEP_S at most. */
    int pnew = (t->pt_head + RF_PTS_MAX - 1) % RF_PTS_MAX;
    if (t->pt_n == 0 || ts - t->pt_ts[pnew] >= RF_TREND_STEP_S) {
        t->pt_dbm[t->pt_head] = (int8_t)med;
        t->pt_ts [t->pt_head] = ts;
        t->pt_head = (uint8_t)((t->pt_head + 1) % RF_PTS_MAX);
        if (t->pt_n < RF_PTS_MAX) t->pt_n++;
    }
    int8_t py[RF_PTS_MAX];
    time_t px[RF_PTS_MAX];
    int np = 0;
    for (int i = t->pt_n - 1; i >= 0; i--) {   /* oldest first */
        int idx = (t->pt_head + RF_PTS_MAX - 1 - i) % RF_PTS_MAX;
        if (ts - t->pt_ts[idx] > RF_TREND_WINDOW_S) continue;
        py[np] = t->pt_dbm[idx];
        px[np] = t->pt_ts[idx];
        np++;
    }
    int enough = np >= RF_TREND_MIN_PTS &&
                 px[np - 1] - px[0] >= RF_TREND_MIN_SPAN_S;
    t->trend = (uint8_t)rf_trend_hyst((rf_trend_t)t->trend,
                                      enough ? rf_slope_db10(py, px, np) : 0.0,
                                      enough);
}

/* ── Labels and cells ────────────────────────────────────────── */

const char *rf_band_name(int b) {
    switch (b) {
    case RF_DIST_IMMEDIATE: return "immediate";
    case RF_DIST_NEAR:      return "near";
    case RF_DIST_ROOM:      return "room";
    case RF_DIST_BUILDING:  return "building";
    case RF_DIST_FAR:       return "far";
    default:                return "";
    }
}

const char *rf_band_short(int b) {
    switch (b) {
    case RF_DIST_IMMEDIATE: return "imm";
    case RF_DIST_NEAR:      return "near";
    case RF_DIST_ROOM:      return "room";
    case RF_DIST_BUILDING:  return "bldg";
    case RF_DIST_FAR:       return "far";
    default:                return "";
    }
}

const char *rf_trend_name(int tr) {
    switch (tr) {
    case RF_TREND_APPROACHING: return "approaching";
    case RF_TREND_STEADY:      return "steady";
    case RF_TREND_LEAVING:     return "leaving";
    default:                   return "unknown";
    }
}

const char *rf_trend_glyph(int tr) {
    switch (tr) {
    case RF_TREND_APPROACHING: return "\xe2\x86\x98";   /* ↘ distance falling */
    case RF_TREND_STEADY:      return "\xe2\x86\x92";   /* → */
    case RF_TREND_LEAVING:     return "\xe2\x86\x97";   /* ↗ distance rising */
    default:                   return " ";
    }
}

const char *rf_ptx_source_name(int src) {
    switch (src) {
    case RF_PTX_TPC_REPORT:  return "tpc_report";
    case RF_PTX_COUNTRY_MAX: return "country_max";
    case RF_PTX_BLE_EXT:     return "ble_ext_tx_power";
    case RF_PTX_BLE_AD:      return "ble_ad_tx_power";
    case RF_PTX_ASSUMED:     return "assumed";
    default:                 return "";
    }
}

static void metres_str(double m, char *out, size_t n) {
    if (m < 1.0)         snprintf(out, n, "<1m");
    else if (m < 999.5)  snprintf(out, n, "%dm", (int)(m + 0.5));
    else                 snprintf(out, n, ">1km");
}

int rf_dist_cell(const rf_track_t *t, char *buf, size_t n, int width) {
    if (!buf || n == 0) return 0;
    buf[0] = '\0';
    if (width < RF_CELL_SHORT) width = RF_CELL_SHORT;
    char body[32];
    int cells;
    if (!t || !t->valid) {
        snprintf(body, sizeof(body), "-");
        cells = 1;
    } else {
        char ms[8];
        metres_str(t->est_dm / 10.0, ms, sizeof(ms));
        int known = t->trend != RF_TREND_UNKNOWN;
        const char *g = known ? rf_trend_glyph(t->trend) : "";
        if (width >= RF_CELL_FULL) {
            snprintf(body, sizeof(body), "~%s %s%s%s", ms, rf_band_short(t->band),
                     known ? " " : "", g);
            cells = 1 + (int)strlen(ms) + 1 + (int)strlen(rf_band_short(t->band)) +
                    (known ? 2 : 0);
        } else {
            snprintf(body, sizeof(body), "~%s%s", ms, g);
            cells = 1 + (int)strlen(ms) + (known ? 1 : 0);
        }
    }
    int pad = width - cells;
    if (pad < 0) pad = 0;
    snprintf(buf, n, "%s%*s", body, pad, "");
    return cells + pad;
}

static void m_str(double m, char *out, size_t n) {
    if (m < 10.0) snprintf(out, n, "%.1f", m);
    else          snprintf(out, n, "%d", (int)(m + 0.5));
}

static const char *ptx_short(int src) {
    switch (src) {
    case RF_PTX_TPC_REPORT:  return "tpc";
    case RF_PTX_COUNTRY_MAX: return "ceiling";
    case RF_PTX_BLE_EXT:     return "ext-hdr";
    case RF_PTX_BLE_AD:      return "ad";
    default:                 return "assumed";
    }
}

void rf_dist_describe(const rf_track_t *t, char *buf, size_t n) {
    if (!buf || n == 0) return;
    if (!t || !t->valid) { snprintf(buf, n, "no estimate"); return; }
    char e[12], lo[12], hi[12];
    m_str(t->est_dm / 10.0, e, sizeof(e));
    m_str(t->lo_dm / 10.0, lo, sizeof(lo));
    m_str(t->hi_dm / 10.0, hi, sizeof(hi));
    snprintf(buf, n, "~%sm (%s-%sm) %s %s, Ptx %d %s%s", e, lo, hi,
             rf_band_short(t->band), rf_trend_name(t->trend), (int)t->ptx_dbm,
             ptx_short(t->ptx_source), t->calibrated ? " cal" : "");
}
