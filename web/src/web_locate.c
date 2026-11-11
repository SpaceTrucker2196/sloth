/* Locating an emitter from two or more of the owner's sensors (#192 I5).
 * Contract and sources: web_locate.h, docs/wiki/fleet.md,
 * research/papers/rssi-distance-estimation.md. */
#include "web_locate.h"

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rf_model.h"
#include "wifi_freq.h"
#include "web_ble.h"
#include "web_devices.h"
#include "web_gnss.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define R_EARTH 6371008.8
#define DEG     (3.14159265358979323846 / 180.0)

/* ── the model ─────────────────────────────────────────────────────── */

void web_loc_model(int kind, int channel, web_loc_model_t *m) {
    memset(m, 0, sizeof(*m));
    m->n_x10 = RF_N_2G_X10;
    m->sigma_db = RF_SIGMA_2G_DB;
    if (kind == WEB_LOC_BLE) {
        m->ptx_dbm = RF_PTX_BLE_ASSUMED;
        m->freq_mhz = RF_BLE_MHZ;
        return;                       /* a BLE controller: no Wi-Fi calibration */
    }
    m->ptx_dbm = kind == WEB_LOC_AP ? RF_PTX_AP_ASSUMED : RF_PTX_STA_ASSUMED;
    m->freq_mhz = WEB_LOC_WIFI_MHZ;
    m->cal_ok = 1;
    if (channel > 0) {
        wifi_band_t b = wifi_freq_infer_band(channel);
        int f = wifi_freq_mhz(b, channel);
        if (f > 0) m->freq_mhz = f;
        if (b == WIFI_BAND_5GHZ || b == WIFI_BAND_6GHZ) {
            m->n_x10 = b == WIFI_BAND_5GHZ ? RF_N_5G_X10 : RF_N_6G_X10;
            m->sigma_db = b == WIFI_BAND_5GHZ ? RF_SIGMA_5G_DB : RF_SIGMA_6G_DB;
            m->cal_ok = 0;            /* the calibration is a 2.4 GHz gain */
        }
    }
}

int web_loc_chan_24(int channel) {
    if (channel <= 0) return 1;
    wifi_band_t b = wifi_freq_infer_band(channel);
    return b != WIFI_BAND_5GHZ && b != WIFI_BAND_6GHZ;
}

double web_loc_range(const web_loc_model_t *m, int rssi, int calibrated,
                     double offset_db, double *lo, double *hi, double *sigma_db) {
    if (rssi >= 0) return -1;
    double off = calibrated ? offset_db : 0;
    double d = rf_distance_m(m->ptx_dbm, rssi, m->freq_mhz, m->n_x10, off);
    if (d <= 0) return -1;
    /* Every row's power is assumed; an uncalibrated receiver's gain is an
     * unknown of the same size. */
    double s2 = m->sigma_db * m->sigma_db + RF_ASSUMED_SIGMA_DB * RF_ASSUMED_SIGMA_DB;
    if (!calibrated) s2 += RF_ASSUMED_SIGMA_DB * RF_ASSUMED_SIGMA_DB;
    double s = sqrt(s2), k = pow(10.0, s / (double)m->n_x10);
    if (lo) *lo = d / k;
    if (hi) *hi = d * k;
    if (sigma_db) *sigma_db = s;
    return d;
}

/* ── geometry ──────────────────────────────────────────────────────── */

void web_loc_enu(double lat0, double lon0, double lat, double lon, double *e, double *n) {
    *e = (lon - lon0) * DEG * R_EARTH * cos(lat0 * DEG);
    *n = (lat - lat0) * DEG * R_EARTH;
}

void web_loc_geo(double lat0, double lon0, double e, double n, double *lat, double *lon) {
    *lat = lat0 + n / (R_EARTH * DEG);
    double c = cos(lat0 * DEG);
    *lon = lon0 + (c > 1e-12 ? e / (R_EARTH * DEG * c) : 0);
}

int web_loc_circles(double ax, double ay, double ra, double bx, double by, double rb,
                    double out[2][2]) {
    double dx = bx - ax, dy = by - ay, d = hypot(dx, dy);
    if (d < 1e-9) return -1;
    if (d > ra + rb + 1e-9 * d || d < fabs(ra - rb) - 1e-9 * d) return 0;
    double a = (ra * ra - rb * rb + d * d) / (2 * d);
    double h2 = ra * ra - a * a;
    double mx = ax + a * dx / d, my = ay + a * dy / d;
    if (h2 <= 1e-9 * d * d) {
        out[0][0] = mx;
        out[0][1] = my;
        return 1;
    }
    double h = sqrt(h2);
    out[0][0] = mx + h * dy / d;
    out[0][1] = my - h * dx / d;
    out[1][0] = mx - h * dy / d;
    out[1][1] = my + h * dx / d;
    return 2;
}

/* The weighted sum of squares the fix minimises. */
static double lsq_cost(const double *x, const double *y, const double *r, const double *w,
                       int n, double X, double Y) {
    double c = 0;
    for (int i = 0; i < n; i++) {
        double f = hypot(X - x[i], Y - y[i]) - r[i];
        c += f * f / (w[i] * w[i] > 1e-6 ? w[i] * w[i] : 1e-6);
    }
    return c;
}

int web_loc_lsq(const double *x, const double *y, const double *r, const double *w, int n,
                double *px, double *py, double *resid, double *radius) {
    if (n < 3) return -1;
    double sx = 0, sy = 0, sw = 0;
    for (int i = 0; i < n; i++) {
        double k = 1.0 / (r[i] > 0.5 ? r[i] : 0.5);
        sx += k * x[i];
        sy += k * y[i];
        sw += k;
    }
    double X = sx / sw, Y = sy / sw;
    double a11 = 0, a12 = 0, a22 = 0, cost = lsq_cost(x, y, r, w, n, X, Y), lam = -1;
    int conv = 0;
    for (int it = 0; it < WEB_LOC_LSQ_ITER && !conv; it++) {
        double b1 = 0, b2 = 0;
        a11 = a12 = a22 = 0;
        for (int i = 0; i < n; i++) {
            double dx = X - x[i], dy = Y - y[i], d = hypot(dx, dy);
            if (d < 1e-6) { dx = 1e-6; d = 1e-6; }
            double jx = dx / d, jy = dy / d, f = d - r[i];
            double wi = 1.0 / (w[i] * w[i] > 1e-6 ? w[i] * w[i] : 1e-6);
            a11 += wi * jx * jx; a12 += wi * jx * jy; a22 += wi * jy * jy;
            b1 += wi * jx * f;   b2 += wi * jy * f;
        }
        double det = a11 * a22 - a12 * a12;
        if (!(fabs(det) > 1e-12 * (a11 * a22 + 1e-30))) return -1;
        /* Levenberg-Marquardt: a full Gauss-Newton step overshoots when
         * the ranges disagree (#192 I5 review: a third of random
         * inconsistent sets were still oscillating after 50 full steps,
         * and the last step was reported as the fix). The damping grows
         * until the cost does not rise and shrinks after each step taken;
         * a step too small to matter is convergence. */
        double lam_lo = 1e-12 * (a11 + a22);
        if (lam < lam_lo) lam = lam < 0 ? 1e-3 * (a11 + a22) : lam_lo;
        for (int k = 0;; k++) {
            double m11 = a11 + lam, m22 = a22 + lam, dm = m11 * m22 - a12 * a12;
            double ux = (m22 * b1 - a12 * b2) / dm, uy = (m11 * b2 - a12 * b1) / dm;
            /* 4^60 of damping and still no descent: a minimum to the
             * arithmetic's precision. */
            if (hypot(ux, uy) < 1e-6 * (1.0 + hypot(X, Y)) || k >= 60) { conv = 1; break; }
            double nx = X - ux, ny = Y - uy, c2 = lsq_cost(x, y, r, w, n, nx, ny);
            if (c2 <= cost) {
                X = nx;
                Y = ny;
                cost = c2;
                lam /= 3;
                break;
            }
            lam *= 4;
        }
    }
    /* Not settled within the bound: no fix rather than wherever the
     * iteration stopped. */
    if (!conv) return -1;
    double det = a11 * a22 - a12 * a12;
    if (!(fabs(det) > 1e-12 * (a11 * a22 + 1e-30)) || !isfinite(X) || !isfinite(Y)) return -1;
    double ss = 0;
    for (int i = 0; i < n; i++) {
        double f = hypot(X - x[i], Y - y[i]) - r[i];
        ss += f * f;
    }
    *px = X;
    *py = Y;
    *resid = sqrt(ss / n);
    /* (J'WJ)^-1's trace: the fix's one-sigma from the bands alone. */
    *radius = sqrt((a22 + a11) / det);
    return 0;
}

static int by_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

static double median_of(double *v, int n) {
    qsort(v, (size_t)n, sizeof(*v), by_double);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

int web_loc_calibrate(const double *off, int n, double *offset) {
    double ok[64], all[64];
    int no = 0, na = 0;
    for (int i = 0; i < n && i < 64; i++) {
        all[na++] = off[i];
        if (off[i] <= RF_CAL_MAX_DB && off[i] >= -RF_CAL_MAX_DB) ok[no++] = off[i];
    }
    if (no) { *offset = median_of(ok, no); return 1; }
    if (na) { *offset = median_of(all, na); return 2; }
    *offset = 0;
    return 0;
}

/* ── the sites ─────────────────────────────────────────────────────── */

typedef struct {
    char      name[WEB_FLEET_NAME_MAX + 1];
    int       is_self, has_pos, too_far;
    double    lat, lon, e, n;
    long long skew;                  /* the peer's clock less this one's */
    int       nown;
    char      own[WEB_FLEET_OWN_MAX][WEB_FLEET_MAC_SZ];
    /* Calibration, as this site's receiver. */
    int       cal;                   /* 0 none, 1 calibrated, 2 refused */
    double    cal_off;
    int       nlink;
    struct {
        int       from;
        char      mac[WEB_FLEET_MAC_SZ];
        int       rssi;
        double    dist, off;
        long long age;
    } link[16];
} lsite_t;

typedef struct {
    lsite_t   s[WEB_LOC_SITES_MAX];
    int       n, store, origin;
    double    lat0, lon0;
    web_sdb_conn_t c;
    int       have_c;
    const char *sdb_word;
} lctx_t;

static void jfix(web_jw_t *w, double v, int dp) {
    char b[48];
    snprintf(b, sizeof(b), "%.*f", dp, v);
    web_jw_raw(w, b);
}

/* Metres as sloth quantises a third party's proximity (rf_quantise_m()). */
static void jm(web_jw_t *w, double m) {
    jfix(w, rf_quantise_m(m), 1);
}

/* This site and every peer with a position (peer_sites), their own
 * radios and the skews; the local plane; sloth.db opened. */
static void sites_load(web_fleet_t *f, const web_fleet_src_t *src, long long now_s, lctx_t *x) {
    memset(x, 0, sizeof(*x));
    x->sdb_word = "none";
    web_loc_t loc;
    web_gnss_sh_t sh;
    web_gnss_site(src->gnss, &loc, &sh);
    lsite_t *me = &x->s[x->n++];
    snprintf(me->name, sizeof(me->name), "self");
    me->is_self = 1;
    me->has_pos = loc.has;
    me->lat = loc.lat;
    me->lon = loc.lon;
    if (f) {
        me->nown = f->nown;
        memcpy(me->own, f->own, sizeof(me->own));
    }
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        x->store = 1;
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(s->rd, "SELECT peer,lat,lon,remote_ts,last_ok FROM peer_sites"
                               " WHERE lat IS NOT NULL AND lon IS NOT NULL ORDER BY peer"
                               " LIMIT 32", -1, &q, NULL) == SQLITE_OK) {
            while (x->n < WEB_LOC_SITES_MAX && sqlite3_step(q) == SQLITE_ROW) {
                const char *nm = (const char *)sqlite3_column_text(q, 0);
                if (!nm || strlen(nm) > WEB_FLEET_NAME_MAX || !strcmp(nm, "self")) continue;
                lsite_t *o = &x->s[x->n++];
                snprintf(o->name, sizeof(o->name), "%s", nm);
                o->has_pos = 1;
                o->lat = sqlite3_column_double(q, 1);
                o->lon = sqlite3_column_double(q, 2);
                long long rts = sqlite3_column_int64(q, 3), ok = sqlite3_column_int64(q, 4);
                o->skew = rts > 0 && ok > 0 ? rts - ok : 0;
            }
        }
        sqlite3_finalize(q);
        pthread_mutex_unlock(&s->rmu);
    }
#endif
    if (f) {
        pthread_mutex_lock(&f->mu);
        for (int j = 1; j < x->n; j++)
            for (int i = 0; i < f->npeer; i++)
                if (!strcmp(f->peer[i].cfg.name, x->s[j].name) && f->peer[i].own_at > 0) {
                    x->s[j].nown = f->peer[i].nown;
                    memcpy(x->s[j].own, f->peer[i].own, sizeof(x->s[j].own));
                }
        pthread_mutex_unlock(&f->mu);
    }
    /* A site with no other within WEB_LOC_BASELINE_MAX_M shares no
     * emitter; the plane is the centroid of the rest. */
    int np = 0;
    for (int i = 0; i < x->n; i++) {
        if (!x->s[i].has_pos) continue;
        int near = 0;
        for (int j = 0; j < x->n && !near; j++)
            near = j != i && x->s[j].has_pos &&
                   web_fleet_dist_m(x->s[i].lat, x->s[i].lon, x->s[j].lat, x->s[j].lon) <=
                       WEB_LOC_BASELINE_MAX_M;
        x->s[i].too_far = !near;
        if (near) {
            x->lat0 += x->s[i].lat;
            x->lon0 += x->s[i].lon;
            np++;
        }
    }
    if (np) {
        x->origin = 1;
        x->lat0 /= np;
        x->lon0 /= np;
        for (int i = 0; i < x->n; i++)
            if (x->s[i].has_pos)
                web_loc_enu(x->lat0, x->lon0, x->s[i].lat, x->s[i].lon, &x->s[i].e, &x->s[i].n);
    }
    if (src->sdb && src->sdb->configured && me->has_pos) {
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &x->c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) == 0) {
            x->have_c = 1;
            x->sdb_word = "open";
        } else {
            web_slothdb_close(&x->c);
            memset(&x->c, 0, sizeof(x->c));
            x->sdb_word = "unavailable";
        }
    }
}

static void sites_done(lctx_t *x) {
    if (x->have_c) web_slothdb_close(&x->c);
    x->have_c = 0;
}

#ifdef WITH_SQLITE
/* The channel member of a peer row's extra JSON (an AP's), or 0. */
static int extra_channel(const char *ex) {
    const char *p = ex ? strstr(ex, "\"channel\":") : NULL;
    if (!p) return 0;
    p += 10;
    int c = 0;
    while (*p >= '0' && *p <= '9' && c < 1000) c = c * 10 + (*p++ - '0');
    return c;
}
#endif

/* Site r's Wi-Fi reading of mac: 1 with rssi, its time on this site's
 * clock and its channel (0 unknown). */
static int wifi_reading(web_fleet_t *f, lctx_t *x, int r, const char *mac, int *rssi,
                        long long *ts, int *chan) {
    lsite_t *R = &x->s[r];
    *chan = 0;
    if (R->is_self) {
        web_sdb_item_t it;
        if (!x->have_c || web_sdb_seen(&x->c, WEB_SEEN_DEVICE, mac, NULL, &it) != 1 || !it.has_n3)
            return 0;
        *rssi = (int)it.n3;
        *ts = it.n2;
        *chan = (int)it.n1;
        return 1;
    }
    int got = 0;
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(s->rd, "SELECT rssi,last_seen,extra FROM peer_sightings WHERE"
                               " peer=?1 AND kind='wifi' AND key=?2 AND rssi < 0",
                               -1, &q, NULL) == SQLITE_OK) {
            sqlite3_bind_text(q, 1, R->name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(q, 2, mac, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(q) == SQLITE_ROW) {
                *rssi = sqlite3_column_int(q, 0);
                *ts = sqlite3_column_int64(q, 1) - R->skew;
                *chan = extra_channel((const char *)sqlite3_column_text(q, 2));
                got = 1;
            }
        }
        sqlite3_finalize(q);
        pthread_mutex_unlock(&s->rmu);
    }
#else
    (void)f; (void)mac; (void)rssi; (void)ts;
#endif
    return got;
}

/* 1 when a site other than t names mac as its own: an address two
 * sites claim has no known position, and is no link for either. */
static int own_claimed_elsewhere(const lctx_t *x, int t, const char *mac) {
    for (int u = 0; u < x->n; u++)
        for (int k = 0; u != t && k < x->s[u].nown; k++)
            if (!strcmp(x->s[u].own[k], mac)) return 1;
    return 0;
}

/* Each receiver's links to another site's own radios, and its offset.
 * What a peer names as its own is the peer's word: it chooses which
 * transmitter a receiver is calibrated by, and RF_CAL_MAX_DB is what
 * bounds the offset that buys it. */
static void calibrate_all(web_fleet_t *f, lctx_t *x, long long now_s) {
    for (int r = 0; r < x->n; r++) {
        lsite_t *R = &x->s[r];
        if (!R->has_pos || R->too_far) continue;
        double offs[16];
        int no = 0;
        for (int t = 0; t < x->n; t++) {
            lsite_t *Tt = &x->s[t];
            if (t == r || !Tt->has_pos || Tt->too_far) continue;
            double d = web_fleet_dist_m(R->lat, R->lon, Tt->lat, Tt->lon);
            if (d < 1.0) continue;    /* the model holds from 1 m (P.1238) */
            for (int m = 0; m < Tt->nown && R->nlink < 16; m++) {
                if (own_claimed_elsewhere(x, t, Tt->own[m])) continue;
                int rssi = 0, chan = 0;
                long long ts = 0;
                if (!wifi_reading(f, x, r, Tt->own[m], &rssi, &ts, &chan)) continue;
                /* The offset is a 2.4 GHz receiver's (web_loc_model());
                 * a reading heard on 5 or 6 GHz is no link for it. */
                if (!web_loc_chan_24(chan)) continue;
                long long age = now_s > ts ? now_s - ts : 0;
                if (age > WEB_LOC_CAL_MAX_AGE_S) continue;
                double off = 0;
                if (!rf_ref_offset_raw(RF_PTX_STA_ASSUMED, rssi, WEB_LOC_WIFI_MHZ, RF_N_2G_X10,
                                       d, &off))
                    continue;
                int k = R->nlink++;
                R->link[k].from = t;
                memcpy(R->link[k].mac, Tt->own[m], WEB_FLEET_MAC_SZ);
                R->link[k].rssi = rssi;
                R->link[k].dist = d;
                R->link[k].off = off;
                R->link[k].age = age;
                offs[no++] = off;
            }
        }
        R->cal = web_loc_calibrate(offs, no, &R->cal_off);
    }
}

static const char *cal_word(int c) {
    return c == 1 ? "calibrated" : c == 2 ? "refused" : "none";
}

static void cal_site_json(const lctx_t *x, const lsite_t *s, web_jw_t *w) {
    web_jw_raw(w, "{\"state\":");
    web_jw_str(w, cal_word(s->cal));
    web_jw_raw(w, ",\"offset_db\":");
    if (s->cal) jfix(w, s->cal_off, 1); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"exponent_x10\":");
    web_jw_int(w, RF_N_2G_X10);
    web_jw_raw(w, ",\"links\":[");
    for (int k = 0; k < s->nlink; k++) {
        web_jw_raw(w, k ? ",{\"from\":" : "{\"from\":");
        web_jw_str(w, x->s[s->link[k].from].name);
        web_jw_raw(w, ",\"mac\":");       web_jw_str(w, s->link[k].mac);
        web_jw_raw(w, ",\"rssi\":");      web_jw_int(w, s->link[k].rssi);
        web_jw_raw(w, ",\"dist_m\":");    jfix(w, s->link[k].dist, 1);
        web_jw_raw(w, ",\"offset_db\":"); jfix(w, s->link[k].off, 1);
        web_jw_raw(w, ",\"accepted\":");
        web_jw_raw(w, fabs(s->link[k].off) <= RF_CAL_MAX_DB ? "true" : "false");
        web_jw_raw(w, ",\"age_s\":");     web_jw_int(w, s->link[k].age);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
}

void web_loc_cal_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                      web_jw_t *w) {
    lctx_t *x = calloc(1, sizeof(*x));
    web_jw_raw(w, "\"calibration\":[");
    if (x) {
        sites_load(f, src, now_s, x);
        calibrate_all(f, x, now_s);
        sites_done(x);
        int k = 0;
        for (int i = 0; i < x->n; i++) {
            const lsite_t *s = &x->s[i];
            if (!s->has_pos) continue;
            web_jw_raw(w, k++ ? ",{\"site\":" : "{\"site\":");
            web_jw_str(w, s->name);
            web_jw_raw(w, ",\"own_radios\":");
            web_jw_int(w, s->nown);
            web_jw_raw(w, ",\"receiver\":");
            cal_site_json(x, s, w);
            web_jw_raw(w, "}");
        }
        free(x);
    }
    web_jw_raw(w, "]");
}

/* ── the route ─────────────────────────────────────────────────────── */

typedef struct {
    char      key[2 * WEB_FLEET_STR_MAX + 4];
    char      label[WEB_FLEET_STR_MAX + 1];
    int       site, rssi, channel;
    long long ts;                    /* on this site's clock */
} lrow_t;

typedef struct {
    int       at, n;
    int       local;                 /* this site's row in rows[], -1 none */
    long long t0;
} lgroup_t;

static int by_key(const void *pa, const void *pb) {
    const lrow_t *a = pa, *b = pb;
    int c = strcmp(a->key, b->key);
    if (c) return c;
    return a->ts > b->ts ? -1 : a->ts < b->ts;
}

static int by_t0(const void *pa, const void *pb) {
    const lgroup_t *a = pa, *b = pb;
    if (a->t0 != b->t0) return a->t0 > b->t0 ? -1 : 1;
    return a->at - b->at;
}

static int parse_q(const char *q, int *kind, int *limit, const char **why) {
    *kind = WEB_LOC_WIFI;
    *limit = WEB_LOC_DEF;
    int sk = 0, sl = 0;
    for (const char *p = q ? q : ""; *p;) {
        size_t n = strcspn(p, "&");
        const char *eq = memchr(p, '=', n);
        if (!eq) { *why = "unknown_parameter"; return -1; }
        size_t kl = (size_t)(eq - p), vl = n - kl - 1;
        const char *v = eq + 1;
        if (kl == 4 && !strncmp(p, "kind", 4) && !sk) {
            sk = 1;
            if (vl == 4 && !strncmp(v, "wifi", 4)) *kind = WEB_LOC_WIFI;
            else if (vl == 2 && !strncmp(v, "ap", 2)) *kind = WEB_LOC_AP;
            else if (vl == 3 && !strncmp(v, "ble", 3)) *kind = WEB_LOC_BLE;
            else { *why = "bad_kind"; return -1; }
        } else if (kl == 5 && !strncmp(p, "limit", 5) && !sl) {
            sl = 1;
            long v2 = 0;
            if (vl == 0 || vl > 4) { *why = "bad_limit"; return -1; }
            for (size_t i = 0; i < vl; i++) {
                if (v[i] < '0' || v[i] > '9') { *why = "bad_limit"; return -1; }
                v2 = v2 * 10 + (v[i] - '0');
            }
            if (v2 < 1 || v2 > WEB_LOC_MAX) { *why = "bad_limit"; return -1; }
            *limit = (int)v2;
        } else {
            *why = "unknown_parameter";
            return -1;
        }
        p += n;
        if (*p == '&') p++;
    }
    return 0;
}

static const char *const KWORD[] = { "wifi", "ap", "ble" };

static int parse_mac6(const char *s, uint8_t out[6]) {
    char k[WEB_KEY_MAX + 1];
    if (web_key_mac(s, k) != 0) return -1;
    for (int i = 0; i < 6; i++) {
        unsigned v = 0;
        for (int j = 0; j < 2; j++) {
            char c = k[i * 3 + j];
            v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* One located key into w: sites ss[0..n) (indices into rows), each
 * paired. */
static void row_json(web_jw_t *w, const lctx_t *x, int kind, const lrow_t *rows,
                     const int *use, int n, long long now_s, int first) {
    int channel = 0;
    for (int i = 0; i < n && !channel; i++) channel = rows[use[i]].channel;
    web_loc_model_t m;
    web_loc_model(kind, channel, &m);
    double r[WEB_LOC_SITES_MAX], lo[WEB_LOC_SITES_MAX], hi[WEB_LOC_SITES_MAX],
           sg[WEB_LOC_SITES_MAX], ex[WEB_LOC_SITES_MAX], sx[WEB_LOC_SITES_MAX],
           sy[WEB_LOC_SITES_MAX], hw[WEB_LOC_SITES_MAX];
    int cal[WEB_LOC_SITES_MAX];
    long long t0 = 0;
    double band = 0, base = 1e30;
    for (int i = 0; i < n; i++) {
        const lrow_t *rw = &rows[use[i]];
        const lsite_t *S = &x->s[rw->site];
        cal[i] = m.cal_ok && S->cal == 1;
        r[i] = web_loc_range(&m, rw->rssi, cal[i], S->cal_off, &lo[i], &hi[i], &sg[i]);
        ex[i] = (double)(m.ptx_dbm - rw->rssi) - (cal[i] ? S->cal_off : 0);
        sx[i] = S->e;
        sy[i] = S->n;
        hw[i] = (hi[i] - lo[i]) / 2;
        if (hw[i] > band) band = hw[i];
        if (rw->ts > t0) t0 = rw->ts;
        for (int j = 0; j < i; j++) {
            double d = hypot(sx[i] - sx[j], sy[i] - sy[j]);
            if (d < base) base = d;
        }
    }
    const lrow_t *r0 = &rows[use[0]];
    web_jw_raw(w, first ? "{\"key\":" : ",{\"key\":");
    web_jw_str(w, r0->key);
    web_jw_raw(w, ",\"label\":");
    if (r0->label[0]) web_jw_str(w, r0->label); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"age_s\":");     web_jw_int(w, now_s > t0 ? now_s - t0 : 0);
    web_jw_raw(w, ",\"freq_mhz\":");  web_jw_int(w, m.freq_mhz);
    web_jw_raw(w, ",\"ptx_dbm\":");   web_jw_int(w, m.ptx_dbm);
    web_jw_raw(w, ",\"ptx\":\"assumed\",\"exponent_x10\":");
    web_jw_int(w, m.n_x10);
    web_jw_raw(w, ",\"sites\":[");
    for (int i = 0; i < n; i++) {
        const lrow_t *rw = &rows[use[i]];
        web_jw_raw(w, i ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, x->s[rw->site].name);
        web_jw_raw(w, ",\"rssi\":");      web_jw_int(w, rw->rssi);
        web_jw_raw(w, ",\"seen\":");      web_jw_int(w, rw->ts);
        web_jw_raw(w, ",\"range_m\":");   jm(w, r[i]);
        web_jw_raw(w, ",\"lo_m\":");      jm(w, lo[i]);
        web_jw_raw(w, ",\"hi_m\":");      jm(w, hi[i]);
        web_jw_raw(w, ",\"sigma_db\":");  jfix(w, sg[i], 1);
        web_jw_raw(w, ",\"calibrated\":"); web_jw_raw(w, cal[i] ? "true" : "false");
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]");
    /* Nearer by path loss, whatever the geometry gives: the honest
     * answer when the band is wider than the baseline. */
    int a = 0, b = -1;
    for (int i = 1; i < n; i++) if (ex[i] < ex[a]) a = i;
    for (int i = 0; i < n; i++) if (i != a && (b < 0 || ex[i] < ex[b])) b = i;
    web_jw_raw(w, ",\"nearest\":{\"site\":");
    web_jw_str(w, x->s[rows[use[a]].site].name);
    web_jw_raw(w, ",\"by_db\":");
    jfix(w, b >= 0 ? ex[b] - ex[a] : 0, 1);
    web_jw_raw(w, ",\"than\":");
    web_jw_str(w, x->s[rows[use[b >= 0 ? b : a]].site].name);
    /* The difference's one-sigma: the assumed power is the same emitter's
     * at both and cancels; each link's shadow fading and each
     * uncalibrated receiver's term do not. A difference inside it says
     * nothing about which site is nearer. */
    double sd = 0;
    if (b >= 0) {
        sd = 2 * m.sigma_db * m.sigma_db;
        if (!cal[a]) sd += RF_ASSUMED_SIGMA_DB * RF_ASSUMED_SIGMA_DB;
        if (!cal[b]) sd += RF_ASSUMED_SIGMA_DB * RF_ASSUMED_SIGMA_DB;
        sd = sqrt(sd);
    }
    web_jw_raw(w, ",\"sigma_db\":");
    jfix(w, sd, 1);
    web_jw_raw(w, ",\"within_band\":");
    web_jw_raw(w, b < 0 || ex[b] - ex[a] <= sd ? "true" : "false");
    web_jw_raw(w, "},\"candidates\":[");
    int nc = 0;
    double resid = -1;
    const char *method;
    if (n == 2) {
        method = "two_circles";
        double pts[2][2];
        int k = web_loc_circles(sx[0], sy[0], r[0], sx[1], sy[1], r[1], pts);
        for (int i = 0; i < k; i++) {
            double ax = pts[i][0] - sx[0], ay = pts[i][1] - sy[0];
            double bx = pts[i][0] - sx[1], by = pts[i][1] - sy[1];
            double sn = fabs(ax * by - ay * bx) / (r[0] * r[1]);
            if (sn < WEB_LOC_MIN_SIN) sn = WEB_LOC_MIN_SIN;
            double rad = hypot(hw[0], hw[1]) / sn, la, lo2;
            web_loc_geo(x->lat0, x->lon0, pts[i][0], pts[i][1], &la, &lo2);
            web_jw_raw(w, nc++ ? ",{\"lat\":" : "{\"lat\":");
            jfix(w, la, 6);
            web_jw_raw(w, ",\"lon\":");      jfix(w, lo2, 6);
            web_jw_raw(w, ",\"e\":");        jm(w, pts[i][0]);
            web_jw_raw(w, ",\"n\":");        jm(w, pts[i][1]);
            web_jw_raw(w, ",\"radius_m\":"); jm(w, rad);
            web_jw_raw(w, "}");
        }
    } else {
        method = "least_squares";
        double px, py, rad;
        if (web_loc_lsq(sx, sy, r, hw, n, &px, &py, &resid, &rad) == 0) {
            if (resid > rad) rad = resid;
            double la, lo2;
            web_loc_geo(x->lat0, x->lon0, px, py, &la, &lo2);
            web_jw_raw(w, "{\"lat\":");
            jfix(w, la, 6);
            web_jw_raw(w, ",\"lon\":");      jfix(w, lo2, 6);
            web_jw_raw(w, ",\"e\":");        jm(w, px);
            web_jw_raw(w, ",\"n\":");        jm(w, py);
            web_jw_raw(w, ",\"radius_m\":"); jm(w, rad);
            web_jw_raw(w, "}");
            nc = 1;
        }
    }
    web_jw_raw(w, "],\"method\":");     web_jw_str(w, method);
    web_jw_raw(w, ",\"residual_m\":");
    if (resid >= 0) jm(w, resid); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"baseline_m\":");  jfix(w, base, 1);
    web_jw_raw(w, ",\"band_m\":");      jm(w, band);
    /* The band's half-width over the shortest baseline: past 1, the
     * candidates are not a position, only a side. */
    web_jw_raw(w, ",\"coarse\":");      web_jw_raw(w, band > base ? "true" : "false");
    web_jw_raw(w, "}");
}

int web_fleet_locate_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                           long long now_s, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    size_t cap = WEB_FLEET_SHARED_BODY;
    char *buf = malloc(cap);
    if (!buf) return -1;
    int kind, limit;
    const char *why = NULL;
    if (parse_q(query, &kind, &limit, &why) != 0) {
        *status = 400;
        *len = web_series_error_json(why, buf, cap);
        *body = buf;
        return *len ? 0 : -1;
    }
    lctx_t *x = calloc(1, sizeof(*x));
    lrow_t *rows = malloc(sizeof(*rows) * (WEB_FLEET_SHARED_SCAN + WEB_FLEET_SHARED_SCAN));
    if (!x || !rows) { free(x); free(rows); free(buf); return -1; }
    sites_load(f, src, now_s, x);
    calibrate_all(f, x, now_s);
    int nr = 0, partial = 0, looked = 0;
    const char *const pkind = KWORD[kind];
#ifdef WITH_SQLITE
    web_store_t *s = f ? f->store : NULL;
    if (s && s->rd) {
        pthread_mutex_lock(&s->rmu);
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(s->rd,
                "SELECT key,peer,label,rssi,last_seen,extra FROM peer_sightings"
                " WHERE kind=?1 AND rssi < 0 ORDER BY last_seen DESC LIMIT ?2",
                -1, &q, NULL) == SQLITE_OK) {
            sqlite3_bind_text(q, 1, pkind, -1, SQLITE_STATIC);
            sqlite3_bind_int(q, 2, WEB_FLEET_SHARED_SCAN);
            while (nr < WEB_FLEET_SHARED_SCAN && sqlite3_step(q) == SQLITE_ROW) {
                const char *pe = (const char *)sqlite3_column_text(q, 1);
                int si = -1;
                for (int j = 1; pe && j < x->n; j++)
                    if (!strcmp(x->s[j].name, pe)) si = j;
                if (si < 0 || x->s[si].too_far) continue;   /* no position, or alone */
                lrow_t *r = &rows[nr];
                memset(r, 0, sizeof(*r));
                const unsigned char *k = sqlite3_column_text(q, 0), *l = sqlite3_column_text(q, 2);
                snprintf(r->key, sizeof(r->key), "%s", k ? (const char *)k : "");
                snprintf(r->label, sizeof(r->label), "%s", l ? (const char *)l : "");
                r->site = si;
                r->rssi = sqlite3_column_int(q, 3);
                r->ts = sqlite3_column_int64(q, 4) - x->s[si].skew;
                r->channel = extra_channel((const char *)sqlite3_column_text(q, 5));
                nr++;
            }
            if (nr == WEB_FLEET_SHARED_SCAN && sqlite3_step(q) == SQLITE_ROW) partial = 1;
        }
        sqlite3_finalize(q);
        pthread_mutex_unlock(&s->rmu);
    }
#endif
    /* Group by key, newest peer reading first. */
    qsort(rows, (size_t)nr, sizeof(*rows), by_key);
    lgroup_t *g = calloc((size_t)(nr ? nr : 1), sizeof(*g));
    if (!g) { sites_done(x); free(x); free(rows); free(buf); return -1; }
    int ng = 0;
    for (int i = 0; i < nr;) {
        int j = i + 1;
        while (j < nr && !strcmp(rows[j].key, rows[i].key)) j++;
        g[ng].at = i;
        g[ng].n = j - i;
        g[ng].t0 = rows[i].ts;
        g[ng].local = -1;
        ng++;
        i = j;
    }
    qsort(g, (size_t)ng, sizeof(*g), by_t0);
    /* This site's reading of each key, newest first, while the read's
     * budget lasts; appended after the peer rows. */
    int nl = nr, self_ok = x->s[0].has_pos && !x->s[0].too_far;
    for (int i = 0; i < ng && self_ok; i++) {
        const char *key = rows[g[i].at].key;
        lrow_t me;
        memset(&me, 0, sizeof(me));
        int got = 0;
        if (kind == WEB_LOC_BLE) {
            uint8_t a6[6];
            web_ble_cand_t cand;
            if (src->ble && parse_mac6(key, a6) == 0 &&
                web_ble_addr_info(src->ble, a6, &cand) == 1 && cand.has_rssi && cand.rssi < 0) {
                me.rssi = cand.rssi;
                me.ts = cand.last_seen;
                got = 1;
            }
        } else {
            if (!x->have_c) break;
            if (web_sdb_spent(&x->c)) { partial = 1; break; }
            web_sdb_item_t it;
            looked++;
            int rc = web_sdb_seen(&x->c, kind == WEB_LOC_AP ? WEB_SEEN_AP : WEB_SEEN_DEVICE,
                                  key, NULL, &it);
            if (rc < 0) { partial = 1; break; }
            if (rc == 1 && it.has_n3) {
                me.rssi = (int)it.n3;
                me.ts = it.n2;
                /* An AP's beacon channel; a client's probe channel when
                 * its reading came from probe_clients, else unknown. */
                me.channel = (int)it.n1;
                got = 1;
            }
        }
        if (!got) continue;
        memcpy(me.key, key, sizeof(me.key));
        me.site = 0;
        rows[nl] = me;
        g[i].local = nl++;
    }
    web_jw_t w;
    web_jw_init(&w, buf, cap);
    web_jw_raw(&w, "{\"kind\":");     web_jw_str(&w, pkind);
    web_jw_raw(&w, ",\"limit\":");    web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"window_s\":"); web_jw_int(&w, WEB_LOC_WINDOW_S);
    web_jw_raw(&w, ",\"max_age_s\":"); web_jw_int(&w, WEB_LOC_MAX_AGE_S);
    web_jw_raw(&w, ",\"origin\":");
    if (x->origin) {
        web_jw_raw(&w, "{\"lat\":"); jfix(&w, x->lat0, 7);
        web_jw_raw(&w, ",\"lon\":"); jfix(&w, x->lon0, 7);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, ",\"sites\":[");
    int k = 0;
    for (int i = 0; i < x->n; i++) {
        const lsite_t *S = &x->s[i];
        if (!S->has_pos) continue;
        web_jw_raw(&w, k++ ? ",{\"site\":" : "{\"site\":");
        web_jw_str(&w, S->name);
        web_jw_raw(&w, ",\"lat\":"); jfix(&w, S->lat, 7);
        web_jw_raw(&w, ",\"lon\":"); jfix(&w, S->lon, 7);
        web_jw_raw(&w, ",\"e\":");   jfix(&w, S->e, 1);
        web_jw_raw(&w, ",\"n\":");   jfix(&w, S->n, 1);
        web_jw_raw(&w, ",\"too_far\":"); web_jw_raw(&w, S->too_far ? "true" : "false");
        web_jw_raw(&w, ",\"calibration\":");
        cal_site_json(x, S, &w);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"store\":");   web_jw_raw(&w, x->store ? "true" : "false");
    web_jw_raw(&w, ",\"local\":");
    web_jw_str(&w, kind == WEB_LOC_BLE ? (src->ble ? "ble" : "none") : x->sdb_word);
    web_jw_raw(&w, ",\"rows\":[");
    int listed = 0, unpaired = 0, stale = 0;
    for (int i = 0; i < ng && listed < limit && !w.overflow; i++) {
        /* The key's readings: each peer's newest (one row a peer), and
         * this site's when it was found. */
        int use[WEB_LOC_SITES_MAX], nu = 0;
        int seen[WEB_LOC_SITES_MAX] = { 0 };
        if (g[i].local >= 0) {
            use[nu++] = g[i].local;
            seen[0] = 1;
        }
        for (int j = 0; j < g[i].n && nu < WEB_LOC_SITES_MAX; j++) {
            int ri = g[i].at + j;
            if (seen[rows[ri].site]) continue;
            seen[rows[ri].site] = 1;
            use[nu++] = ri;
        }
        if (nu < 2) continue;
        /* Paired in time: within the window of the newest, the newest
         * recent. */
        long long t0 = 0;
        for (int j = 0; j < nu; j++) if (rows[use[j]].ts > t0) t0 = rows[use[j]].ts;
        if (now_s - t0 > WEB_LOC_MAX_AGE_S) { stale++; continue; }
        int m2 = 0;
        for (int j = 0; j < nu; j++)
            if (t0 - rows[use[j]].ts <= WEB_LOC_WINDOW_S) use[m2++] = use[j];
        if (m2 < 2) { unpaired++; continue; }
        /* The label: a peer's, the local row has none. */
        if (!rows[use[0]].label[0])
            for (int j = 1; j < m2; j++)
                if (rows[use[j]].label[0]) {
                    memcpy(rows[use[0]].label, rows[use[j]].label, sizeof(rows[0].label));
                    break;
                }
        row_json(&w, x, kind, rows, use, m2, now_s, listed == 0);
        listed++;
    }
    web_jw_raw(&w, "],\"scanned\":");  web_jw_int(&w, nr);
    web_jw_raw(&w, ",\"keys\":");      web_jw_int(&w, ng);
    web_jw_raw(&w, ",\"looked_up\":"); web_jw_int(&w, looked);
    web_jw_raw(&w, ",\"unpaired\":");  web_jw_int(&w, unpaired);
    web_jw_raw(&w, ",\"stale\":");     web_jw_int(&w, stale);
    web_jw_raw(&w, ",\"partial\":");   web_jw_raw(&w, partial ? "true" : "false");
    web_jw_raw(&w, "}\n");
    sites_done(x);
    free(x);
    free(rows);
    free(g);
    if (w.overflow) {
        *len = web_series_error_json("too_large", buf, cap);
        *status = 503;
    } else {
        *len = w.len;
        *status = 200;
    }
    *body = buf;
    return *len ? 0 : -1;
}
