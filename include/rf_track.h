#ifndef SLOTH_RF_TRACK_H
#define SLOTH_RF_TRACK_H

#include <stdint.h>
#include <time.h>

/* Per-row RSSI distance track (owner request 2026-10-26: "use rf signal
 * strength to estimate distance as a data point").
 *
 * The struct only. The arithmetic and its sources are src/rf_distance.h
 * and research/papers/rssi-distance-estimation.md. It lives in include/
 * for the reg_ie.h reason: beacon_ap_t, probe_client_t, assoc_t and
 * ble_device_t embed one, so every translation unit that sees sloth.h
 * must see this too.
 *
 * A data point and nothing else: no alert rule reads it. Everything
 * here is recomputed by rf_track_observe() each time the row hears a
 * frame with a usable RSSI, so the output fields describe the row as of
 * its last usable sample. `valid` is the only thing that says an
 * estimate exists — every other output field is meaningless while it
 * is 0, and an RSSI of 0 or "not available" never sets it. */

/* Raw samples kept, and the most a median may take (rf.median_k). */
#define RF_RAW_MAX   16
/* Points in the trend series (one median per RF_TREND_STEP_S). */
#define RF_PTS_MAX    8

typedef struct {
    /* Inputs: a ring of raw samples and a ring of trend points. Read
     * them only through rf_distance.c; the head arithmetic is not part
     * of the contract. */
    int8_t   raw_dbm[RF_RAW_MAX];
    time_t   raw_ts [RF_RAW_MAX];
    uint8_t  raw_head, raw_n;
    int8_t   pt_dbm[RF_PTS_MAX];
    time_t   pt_ts [RF_PTS_MAX];
    uint8_t  pt_head, pt_n;

    /* Output. Distances in decimetres, saturating at UINT16_MAX. */
    uint8_t  valid;
    uint8_t  band;        /* rf_dist_band_t, with hysteresis */
    uint8_t  trend;       /* rf_trend_t, with hysteresis */
    uint8_t  ptx_source;  /* rf_ptx_source_t */
    int8_t   ptx_dbm;     /* the P_tx the estimate used */
    int8_t   rssi_med;    /* median of the samples used, dBm */
    uint8_t  spread_db;   /* MAD x 1.4826 of those samples, dB */
    uint8_t  samples;     /* how many the median took */
    uint8_t  calibrated;  /* an --my-bssid reference offset was applied */
    uint8_t  radio;       /* rf_radio_t the estimate was made for */
    uint16_t est_dm;
    uint16_t lo_dm;
    uint16_t hi_dm;
} rf_track_t;

#endif /* SLOTH_RF_TRACK_H */
