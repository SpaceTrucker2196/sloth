/* Locating an emitter from two or more of the owner's sensors (#192 I5;
 * docs/wiki/fleet.md "Locating emitters").
 *
 * Each site that heard a key (a Wi-Fi client, an AP, a BLE advertiser)
 * gives a range from its RSSI by sloth's own model (src/rf_model.h: ITU-R
 * P.1238-10 eq. (1), its Table 2 exponent and Table 4 shadow-fading
 * sigma; research/papers/rssi-distance-estimation.md), with the band
 * that sigma gives, widened for an assumed transmit power and for an
 * uncalibrated receiver. Two sites: the two range circles' crossings (0,
 * 1 or 2 candidates) and always which site the emitter is nearer, by how
 * many dB of path loss. Three or more: a weighted least-squares fix and
 * its residual. Positions in east/north metres on a plane tangent at the
 * sites' centroid, and as latitude and longitude.
 *
 * Only readings close in time are paired: a peer's value is its last
 * RSSI as of its last_seen, so every site used must have last_seen within
 * WEB_LOC_WINDOW_S of the newest, on this site's clock (the peer's less
 * its measured skew), and the newest within WEB_LOC_MAX_AGE_S of now.
 *
 * Calibration. A site's own radios (web_fleet.h, own=1) are transmitters
 * at a known position. A receiver that hears another site's own radio
 * has one link of known length, which gives that receiver's offset (as
 * --my-bssid with rf.ref_dist_dm does for the sensor: the gain of its
 * antenna and receive chain, and the error in the assumed power),
 * bounded by RF_CAL_MAX_DB. One length fixes the offset, not the
 * exponent: N stays P.1238's. The offset is a 2.4 GHz Wi-Fi receiver's:
 * it is applied to Wi-Fi rows on 2.4 GHz only, never to 5/6 GHz (a
 * different gain) or BLE (a different receiver), as rf_distance.h keeps
 * its calibration per radio.
 *
 * It is an estimate from signal strength. Indoors a wall moves the
 * reading as much as a fivefold change in distance (the research
 * document), and the band says so: "coarse" is set when the band's
 * half-width exceeds the baseline between the sites, in which case only
 * the nearer site is meaningful, not the point. */
#ifndef SLOTHWEB_LOCATE_H
#define SLOTHWEB_LOCATE_H

#include <stddef.h>

#include "web_fleet.h"
#include "web_json.h"

/* Pairing and freshness (sloth's choices: two default pull intervals;
 * a quarter hour for "now"); a calibration link at most a day old. */
#define WEB_LOC_WINDOW_S       120
#define WEB_LOC_MAX_AGE_S      900
#define WEB_LOC_CAL_MAX_AGE_S  86400
/* A site farther than this from every other is not paired: no indoor
 * emitter reaches two receivers that far apart. sloth's choice. */
#define WEB_LOC_BASELINE_MAX_M 2000.0
/* The rows listed: default, most. */
#define WEB_LOC_DEF            50
#define WEB_LOC_MAX            200
/* Sites at most: this one and every peer. */
#define WEB_LOC_SITES_MAX      (WEB_FLEET_PEERS + 1)
/* A Wi-Fi client's frequency when nothing names its channel: 2.4 GHz
 * channel 6 (a probing station is mostly heard on 2.4 GHz). sloth's
 * choice; across the band the free-space term moves 0.2 dB. */
#define WEB_LOC_WIFI_MHZ       2437
/* Two circles crossing at angle theta: the candidate's radius is the
 * bands' half-widths combined over sin(theta), never over less than
 * this (a tangent crossing is spread along the line, not a point).
 * sloth's choice. */
#define WEB_LOC_MIN_SIN        0.25
/* Iterations for a least-squares fix at most; one that has not settled
 * by then is no fix. */
#define WEB_LOC_LSQ_ITER       500

enum { WEB_LOC_WIFI = 0, WEB_LOC_AP, WEB_LOC_BLE };

/* The model for one row: assumed power, frequency, exponent (x10) and
 * shadow-fading sigma, and whether a 2.4 GHz Wi-Fi calibration applies.
 * channel <= 0: unknown (a client at WEB_LOC_WIFI_MHZ, an AP likewise). */
typedef struct {
    int    ptx_dbm, freq_mhz, n_x10, cal_ok;
    double sigma_db;
} web_loc_model_t;
void web_loc_model(int kind, int channel, web_loc_model_t *m);

/* 1 when a reading's channel is 2.4 GHz or unknown (<= 0): the band a
 * Wi-Fi row without a channel is modelled at and the calibration is
 * for; 0 for 5 or 6 GHz. */
int web_loc_chan_24(int channel);

/* One site's range: metres and its one-sigma band, from an RSSI and the
 * receiver's offset. sigma_db out: the band's sigma, shadow fading with
 * the assumed-power term and, uncalibrated, the receiver term (each
 * RF_ASSUMED_SIGMA_DB), in quadrature. -1 when the RSSI is not a reading. */
double web_loc_range(const web_loc_model_t *m, int rssi, int calibrated,
                     double offset_db, double *lo, double *hi, double *sigma_db);

/* A plane tangent at (lat0, lon0): east and north metres, and back.
 * Equirectangular on the IUGG mean radius: at a few kilometres the error
 * is far below a metre, far below any RSSI band. */
void web_loc_enu(double lat0, double lon0, double lat, double lon, double *e, double *n);
void web_loc_geo(double lat0, double lon0, double e, double n, double *lat, double *lon);

/* The crossings of circle A (ax, ay, ra) and B: 0 (apart, or one inside
 * the other), 1 (tangent, within 1e-9 of the baseline), 2; -1 for the
 * same centre. out[i] = {x, y}. */
int web_loc_circles(double ax, double ay, double ra, double bx, double by, double rb,
                    double out[2][2]);

/* Weighted least squares over n >= 3 circles (x, y, r, w: the range's
 * one-sigma half-width): Levenberg-Marquardt (Gauss-Newton, damped
 * until the weighted cost does not rise) from the centroid weighted by
 * 1/r. 0 with the
 * point, the rms residual (metres, unweighted) and the radius (the fix's
 * one-sigma, from the normal equations); -1 when the geometry gives no
 * fix (collinear sites, a singular system) or the iteration has not
 * settled within WEB_LOC_LSQ_ITER steps. */
int web_loc_lsq(const double *x, const double *y, const double *r, const double *w, int n,
                double *px, double *py, double *resid, double *radius);

/* A receiver's calibration from its links (offsets of each link, dB,
 * unbounded; ok when within RF_CAL_MAX_DB): state 1 calibrated, the
 * median of the accepted; 2 refused (links, none within the bound;
 * *offset the median of all); 0 none. */
int web_loc_calibrate(const double *off, int n, double *offset);

/* "calibration":[...] for /api/fleet/overview: each site's state, its
 * offset and its links. */
void web_loc_cal_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                      web_jw_t *w);

/* GET /api/fleet/locate?kind=wifi|ap|ble&limit=N (50, 1..200). A heap
 * body the caller frees; 0 with *status, -1 out of memory. */
int web_fleet_locate_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                           long long now_s, char **body, size_t *len, int *status);

#endif
