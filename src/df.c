/* Direction finding across monitor radios; see df.h for what it can and
 * cannot say. Pure but for the mutex: no I/O, no clock of its own. */
#include "df.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DF_ALPHA 0.25            /* weight of a new frame in the mean */

typedef struct {
    int     n;                   /* frames, saturating */
    double  mean;                /* dBm */
    time_t  ts;                  /* newest frame */
} df_cell_t;

typedef struct {
    int       used;
    uint8_t   mac[6];
    time_t    last_seen;
    int       channel;
    int       brg_held;          /* compass point last given + 1; 0 none */
    df_cell_t r[DF_MAX_RADIOS];
} df_emitter_t;

static df_radio_t      g_radios[DF_MAX_RADIOS];
static int             g_nradios;
static df_emitter_t    g_em[DF_MAX_EMITTERS];
static uint64_t        g_dropped;
static volatile int    g_active;        /* two or more radios */
static double          g_bias[DF_MAX_RADIOS];   /* dB above radio 0 */
static int             g_bias_set[DF_MAX_RADIOS];
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

void df_reset(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_radios, 0, sizeof(g_radios));
    memset(g_em, 0, sizeof(g_em));
    g_nradios = 0;
    g_dropped = 0;
    g_active  = 0;
    memset(g_bias, 0, sizeof(g_bias));
    memset(g_bias_set, 0, sizeof(g_bias_set));
    pthread_mutex_unlock(&g_mu);
}

static int radio_find_locked(const char *iface) {
    for (int i = 0; i < g_nradios; i++)
        if (!strcmp(g_radios[i].iface, iface)) return i;
    return -1;
}

static int radio_add(const char *iface, int has_pos, double pos_m,
                     int has_xy, double x_m, double y_m) {
    if (!iface || !iface[0] || strlen(iface) >= sizeof(g_radios[0].iface)) return -1;
    int at = -1;
    pthread_mutex_lock(&g_mu);
    if (g_nradios < DF_MAX_RADIOS && radio_find_locked(iface) < 0) {
        at = g_nradios++;
        memset(&g_radios[at], 0, sizeof(g_radios[at]));
        snprintf(g_radios[at].iface, sizeof(g_radios[at].iface), "%s", iface);
        g_radios[at].has_pos = has_pos ? 1 : 0;
        g_radios[at].pos_m   = has_pos ? pos_m : 0;
        g_radios[at].has_xy  = has_xy;
        g_radios[at].x_m     = x_m;
        g_radios[at].y_m     = y_m;
        g_active = g_nradios > 1;
    }
    pthread_mutex_unlock(&g_mu);
    return at;
}

int df_radio_add(const char *iface, int has_pos, double pos_m) {
    return radio_add(iface, has_pos, pos_m, 0, 0, 0);
}

int df_radio_add_xy(const char *iface, double x_m, double y_m) {
    return radio_add(iface, 0, 0, 1, x_m, y_m);
}

/* g_mu held. Three or more radios placed in two dimensions, and not on
 * one line: across the longest side the array is at least DF_MIN_ASPECT
 * of that side deep. A flatter one is a line with a rounding error, and
 * the direction across it would be read from a level difference that is
 * not there. */
static int array_2d_locked(void) {
    int idx[DF_MAX_RADIOS], n = 0;
    for (int i = 0; i < g_nradios; i++) if (g_radios[i].has_xy) idx[n++] = i;
    if (n < 3) return 0;
    int a = 0, b = 0;
    double len2 = 0;
    for (int i = 0; i < n; i++) {
        for (int j = i + 1; j < n; j++) {
            double dx = g_radios[idx[j]].x_m - g_radios[idx[i]].x_m;
            double dy = g_radios[idx[j]].y_m - g_radios[idx[i]].y_m;
            if (dx * dx + dy * dy > len2) { len2 = dx * dx + dy * dy; a = idx[i]; b = idx[j]; }
        }
    }
    if (len2 <= 0) return 0;
    double ux = g_radios[b].x_m - g_radios[a].x_m, uy = g_radios[b].y_m - g_radios[a].y_m;
    double depth = 0;
    for (int i = 0; i < n; i++) {
        double px = g_radios[idx[i]].x_m - g_radios[a].x_m;
        double py = g_radios[idx[i]].y_m - g_radios[a].y_m;
        double h = fabs(ux * py - uy * px) / sqrt(len2);
        if (h > depth) depth = h;
    }
    return depth >= DF_MIN_ASPECT * sqrt(len2);
}

int df_array_has_bearing(void) {
    pthread_mutex_lock(&g_mu);
    int ok = array_2d_locked();
    pthread_mutex_unlock(&g_mu);
    return ok;
}

/* g_mu held. The compass direction, degrees in [0, 360), from the
 * centroid of the 2D radio positions to their mean weighted by received
 * power; lv[] is one level per 2D radio, all of them. 0 when the two
 * points coincide: no direction. */
static int lean_dir_locked(const double *lv, double *deg) {
    double top = -1e9;
    for (int i = 0; i < g_nradios; i++)
        if (g_radios[i].has_xy && lv[i] > top) top = lv[i];
    double cx = 0, cy = 0, wx = 0, wy = 0, wsum = 0;
    int n = 0;
    for (int i = 0; i < g_nradios; i++) {
        if (!g_radios[i].has_xy) continue;
        /* Against the loudest, so the ratio is all that is used. */
        double w = pow(10.0, (lv[i] - top) / 10.0);
        cx += g_radios[i].x_m; cy += g_radios[i].y_m;
        wx += w * g_radios[i].x_m; wy += w * g_radios[i].y_m;
        wsum += w;
        n++;
    }
    if (n == 0 || wsum <= 0) return 0;
    double dx = wx / wsum - cx / n, dy = wy / wsum - cy / n;
    if (hypot(dx, dy) < 1e-6) return 0;
    double d = atan2(dx, dy) * 180.0 / 3.14159265358979323846;   /* east of north */
    if (d < 0) d += 360.0;
    if (d >= 360.0) d = 0;
    *deg = d;
    return 1;
}

static double ang_diff(double a, double b) {
    double d = fabs(a - b);
    return d > 180.0 ? 360.0 - d : d;
}

/* g_mu held. The bearing for an estimate already filled, or none
 * (df.h: when it is withheld). */
static void bearing_locked(df_emitter_t *e, df_est_t *o) {
    int held = e->brg_held;
    e->brg_held = 0;
    if (o->quality != DF_LEAN || !array_2d_locked()) return;
    double lv[DF_MAX_RADIOS] = { 0 };
    for (int i = 0; i < g_nradios; i++) {
        /* Every placed radio heard it, and no unplaced one did. */
        if (g_radios[i].has_xy != o->has[i]) return;
        lv[i] = o->level[i];
    }
    double dir;
    if (!lean_dir_locked(lv, &dir)) return;
    double err = 0;
    for (int i = 0; i < g_nradios; i++) {
        if (!g_radios[i].has_xy) continue;
        for (int sgn = -1; sgn <= 1; sgn += 2) {
            double was = lv[i], d2;
            lv[i] = was + sgn * DF_BEARING_WANDER_DB;
            int ok = lean_dir_locked(lv, &d2);
            lv[i] = was;
            if (!ok) return;
            if (ang_diff(dir, d2) > err) err = ang_diff(dir, d2);
        }
    }
    if (err > DF_BEARING_MAX_ERR_DEG) return;
    int points = 360 / DF_BEARING_STEP_DEG;
    int bin = (int)floor(dir / DF_BEARING_STEP_DEG + 0.5) % points;
    /* Hysteresis: the point given last stands until the direction is
     * DF_BEARING_HYST_DEG past the edge of its sector. */
    if (held > 0 && ang_diff(dir, (double)(held - 1) * DF_BEARING_STEP_DEG)
                    <= DF_BEARING_STEP_DEG / 2.0 + DF_BEARING_HYST_DEG)
        bin = held - 1;
    e->brg_held = bin + 1;
    o->has_bearing = 1;
    o->bearing_deg = bin * DF_BEARING_STEP_DEG;
    int steps = (int)ceil(err / DF_BEARING_ERR_STEP_DEG - 1e-9);
    o->bearing_err_deg = (steps < 1 ? 1 : steps) * DF_BEARING_ERR_STEP_DEG;
}

int df_radio_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_nradios;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int df_radio_get(int i, df_radio_t *out) {
    int ok = 0;
    pthread_mutex_lock(&g_mu);
    if (out && i >= 0 && i < g_nradios) {
        *out = g_radios[i];
        out->calibrated = i == 0 || g_bias_set[i];
        out->bias_db    = i == 0 ? 0 : g_bias[i];
        ok = 1;
    }
    pthread_mutex_unlock(&g_mu);
    return ok;
}

int df_radio_find(const char *iface) {
    if (!iface) return -1;
    pthread_mutex_lock(&g_mu);
    int i = radio_find_locked(iface);
    pthread_mutex_unlock(&g_mu);
    return i;
}

void df_note(int radio, const uint8_t mac[6], int rssi_dbm, int channel, time_t now) {
    if (!mac || rssi_dbm >= 0 || rssi_dbm < -127) return;
    if (mac[0] & 0x01) return;                   /* group address: not a transmitter */
    pthread_mutex_lock(&g_mu);
    if (radio < 0 || radio >= g_nradios) { pthread_mutex_unlock(&g_mu); return; }
    g_radios[radio].frames++;

    df_emitter_t *e = NULL, *spare = NULL, *oldest = NULL;
    for (int i = 0; i < DF_MAX_EMITTERS; i++) {
        df_emitter_t *x = &g_em[i];
        if (!x->used) { if (!spare) spare = x; continue; }
        if (!memcmp(x->mac, mac, 6)) { e = x; break; }
        if (!oldest || x->last_seen < oldest->last_seen) oldest = x;
    }
    if (!e) {
        e = spare;
        /* Full: the transmitter quiet longest gives way, but only once
         * nothing fresh could still be read from it. */
        if (!e && oldest && now - oldest->last_seen > DF_FRESH_S) e = oldest;
        if (!e) { g_dropped++; pthread_mutex_unlock(&g_mu); return; }
        memset(e, 0, sizeof(*e));
        e->used = 1;
        memcpy(e->mac, mac, 6);
    }
    e->last_seen = now;
    if (channel > 0) e->channel = channel;
    df_cell_t *c = &e->r[radio];
    /* A reading gone stale starts over rather than dragging an old mean
     * toward the new one. */
    if (c->n == 0 || now - c->ts > DF_FRESH_S) { c->n = 0; c->mean = rssi_dbm; }
    else c->mean += DF_ALPHA * (rssi_dbm - c->mean);
    if (c->n < 1000000) c->n++;
    c->ts = now;
    pthread_mutex_unlock(&g_mu);
}

/* g_mu held. */
static void estimate_locked(df_emitter_t *e, time_t now, df_est_t *o) {
    memset(o, 0, sizeof(*o));
    memcpy(o->mac, e->mac, 6);
    o->last_seen  = e->last_seen;
    o->channel    = e->channel;
    o->best_radio = -1;
    double lo = 0, hi = 0, wsum = 0, wx = 0;
    int all_pos = 1;
    for (int i = 0; i < g_nradios; i++) {
        const df_cell_t *c = &e->r[i];
        if (c->n < DF_MIN_SAMPLES || now - c->ts > DF_FRESH_S) continue;
        double lv = c->mean - g_bias[i];         /* df.h: Calibration */
        o->has[i]   = 1;
        o->rssi[i]  = c->mean;
        o->level[i] = lv;
        if (o->heard_by == 0 || lv > hi) { hi = lv; o->best_radio = i; }
        if (o->heard_by == 0 || lv < lo) lo = lv;
        o->heard_by++;
        if (!g_radios[i].has_pos) all_pos = 0;
        /* Received power, linear: the free-space 1/d^2 weight. */
        double w = pow(10.0, lv / 10.0);
        wsum += w;
        wx   += w * g_radios[i].pos_m;
    }
    if (o->heard_by < 2) { o->quality = DF_NONE; e->brg_held = 0; return; }
    o->margin_db = hi - lo;
    o->quality   = o->margin_db >= DF_MIN_MARGIN_DB ? DF_LEAN : DF_WEAK;
    if (all_pos && wsum > 0) { o->has_along = 1; o->along_m = wx / wsum; }
    bearing_locked(e, o);
}

int df_estimate(const uint8_t mac[6], time_t now, df_est_t *out) {
    if (!mac || !out) return 0;
    int ok = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < DF_MAX_EMITTERS; i++) {
        if (!g_em[i].used || memcmp(g_em[i].mac, mac, 6)) continue;
        estimate_locked(&g_em[i], now, out);
        ok = 1;
        break;
    }
    pthread_mutex_unlock(&g_mu);
    return ok;
}

static int by_double(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return x < y ? -1 : x > y;
}

/* g_mu held. Each radio's bias against radio 0 (df.h: Calibration). */
static void calibrate_locked(time_t now) {
    static double d[DF_MAX_EMITTERS];
    for (int r = 1; r < g_nradios; r++) {
        int n = 0;
        for (int i = 0; i < DF_MAX_EMITTERS; i++) {
            const df_emitter_t *e = &g_em[i];
            if (!e->used) continue;
            const df_cell_t *a = &e->r[0], *b = &e->r[r];
            if (a->n < DF_MIN_SAMPLES || b->n < DF_MIN_SAMPLES) continue;
            if (now - a->ts > DF_FRESH_S || now - b->ts > DF_FRESH_S) continue;
            d[n++] = b->mean - a->mean;
        }
        if (n < DF_CAL_MIN) continue;
        qsort(d, (size_t)n, sizeof(d[0]), by_double);
        double med = n & 1 ? d[n / 2] : (d[n / 2 - 1] + d[n / 2]) / 2.0;
        if (!g_bias_set[r]) { g_bias[r] = med; g_bias_set[r] = 1; }
        else g_bias[r] += 0.2 * (med - g_bias[r]);
    }
}

static int by_newest(const void *a, const void *b) {
    const df_est_t *x = a, *y = b;
    if (x->last_seen != y->last_seen) return x->last_seen < y->last_seen ? 1 : -1;
    return memcmp(x->mac, y->mac, 6);
}

int df_snapshot(df_est_t *out, int max, time_t now) {
    if (!out || max < 1) return 0;
    int n = 0;
    pthread_mutex_lock(&g_mu);
    calibrate_locked(now);
    /* Two passes would hold the lock twice; instead keep the newest
     * `max` as they are met, replacing the oldest kept when full. */
    for (int i = 0; i < DF_MAX_EMITTERS; i++) {
        if (!g_em[i].used) continue;
        df_est_t e;
        estimate_locked(&g_em[i], now, &e);
        if (e.heard_by < 2) continue;
        if (n < max) { out[n++] = e; continue; }
        int old = 0;
        for (int k = 1; k < n; k++)
            if (out[k].last_seen < out[old].last_seen) old = k;
        if (e.last_seen > out[old].last_seen) out[old] = e;
    }
    pthread_mutex_unlock(&g_mu);
    qsort(out, (size_t)n, sizeof(out[0]), by_newest);
    return n;
}

int df_emitter_count(void) {
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < DF_MAX_EMITTERS; i++) n += g_em[i].used;
    pthread_mutex_unlock(&g_mu);
    return n;
}

uint64_t df_dropped(void) {
    pthread_mutex_lock(&g_mu);
    uint64_t d = g_dropped;
    pthread_mutex_unlock(&g_mu);
    return d;
}

int df_active(void) { return g_active; }

int df_frame_ta(const uint8_t *dot11, int len, uint8_t ta[6]) {
    /* FC(2) + Duration(2) + Address 1(6) + Address 2(6). */
    if (!dot11 || !ta || len < 16) return 0;
    if ((dot11[0] & 0x03) != 0) return 0;            /* protocol version */
    int type = (dot11[0] >> 2) & 0x03;
    if (type != 0 && type != 2) return 0;            /* management, data */
    memcpy(ta, dot11 + 10, 6);
    return 1;
}

const char *df_quality_name(df_quality_t q) {
    switch (q) {
    case DF_NONE: return "none";
    case DF_WEAK: return "weak";
    case DF_LEAN: return "lean";
    }
    return "none";
}

/* One position number, the whole of s[0..len): finite, within
 * +/-DF_POS_MAX_M. */
static int place_num(const char *s, size_t len, double *out) {
    char b[64];
    if (len == 0 || len >= sizeof(b)) return 0;
    memcpy(b, s, len);
    b[len] = '\0';
    char *end = NULL;
    double v = strtod(b, &end);
    if (end == b || *end != '\0' || !isfinite(v) || v < -DF_POS_MAX_M || v > DF_POS_MAX_M)
        return 0;
    *out = v;
    return 1;
}

int df_parse_place(const char *spec, char *iface, int iface_sz, df_pos_t *pos) {
    if (!spec || !iface || iface_sz < 2 || !pos) return 0;
    memset(pos, 0, sizeof(*pos));
    const char *at = strchr(spec, '@');
    const char *comma = at ? strchr(at + 1, ',') : NULL;
    if (!comma) {
        int hp = 0;
        double m = 0;
        if (!df_parse_spec(spec, iface, iface_sz, &hp, &m)) return 0;
        pos->form = hp ? DF_POS_LINE : DF_POS_NONE;
        pos->a    = m;
        return 1;
    }
    /* The name by the one-number parser's rules. */
    char name_only[32];
    size_t nl = (size_t)(at - spec);
    int hp = 0;
    double m = 0;
    if (nl >= sizeof(name_only)) return 0;
    memcpy(name_only, spec, nl);
    name_only[nl] = '\0';
    if (!df_parse_spec(name_only, iface, iface_sz, &hp, &m)) return 0;
    double x, y;
    if (!place_num(at + 1, (size_t)(comma - at - 1), &x) ||
        !place_num(comma + 1, strlen(comma + 1), &y)) return 0;
    pos->form = DF_POS_XY;
    pos->a = x;
    pos->b = y;
    return 1;
}

int df_cli_add(df_cli_t *c, const char *spec, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!c || !spec || !err) return 0;
    char n[16];
    df_pos_t p;
    if (!df_parse_place(spec, n, (int)sizeof(n), &p)) {
        snprintf(err, errsz, "sloth: --df-iface %s: want NAME, NAME@METRES or "
                             "NAME@X,Y (an interface name of 1..15 chars, "
                             "metres within +/-1000)", spec);
        return 0;
    }
    if (c->n >= DF_MAX_RADIOS - 1) {
        snprintf(err, errsz, "sloth: too many --df-iface radios (max %d "
                             "beside the sensor radio)", DF_MAX_RADIOS - 1);
        return 0;
    }
    snprintf(c->name[c->n], sizeof(c->name[c->n]), "%s", n);
    c->pos[c->n] = p;
    c->n++;
    return 1;
}

int df_cli_origin(df_cli_t *c, const char *arg, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!c || !arg || !err) return 0;
    char n[16], sp[80];
    df_pos_t p;
    int w = snprintf(sp, sizeof(sp), "x@%s", arg);
    if (w < 0 || (size_t)w >= sizeof(sp) || !df_parse_place(sp, n, (int)sizeof(n), &p) ||
        p.form == DF_POS_NONE) {
        snprintf(err, errsz, "sloth: --df-origin %s: want METRES or X,Y, "
                             "metres within +/-1000", arg);
        return 0;
    }
    c->origin_set = 1;
    c->origin = p;
    return 1;
}

static int cli_forms(const df_cli_t *c) {
    int seen = 0;
    if (c->origin_set) seen |= 1 << c->origin.form;
    for (int k = 0; k < c->n; k++) seen |= 1 << c->pos[k].form;
    return seen;
}

int df_cli_check(const df_cli_t *c, char *err, size_t errsz) {
    if (err && errsz) err[0] = '\0';
    if (!c || !err) return 0;
    int seen = cli_forms(c);
    if ((seen & (1 << DF_POS_LINE)) && (seen & (1 << DF_POS_XY))) {
        snprintf(err, errsz, "sloth: --df-iface, --df-origin: positions given "
                             "both as METRES along a line and as X,Y; one "
                             "command line uses one form");
        return 0;
    }
    return 1;
}

df_pos_form_t df_cli_form(const df_cli_t *c) {
    if (!c) return DF_POS_NONE;
    int seen = cli_forms(c);
    if (seen & (1 << DF_POS_XY)) return DF_POS_XY;
    if (seen & (1 << DF_POS_LINE)) return DF_POS_LINE;
    return DF_POS_NONE;
}

int df_parse_spec(const char *spec, char *iface, int iface_sz, int *has_pos, double *pos_m) {
    if (!spec || !iface || iface_sz < 2 || !has_pos || !pos_m) return 0;
    const char *at = strchr(spec, '@');
    size_t nl = at ? (size_t)(at - spec) : strlen(spec);
    if (nl == 0 || nl >= 16 || nl >= (size_t)iface_sz) return 0;
    for (size_t i = 0; i < nl; i++) {
        unsigned char c = (unsigned char)spec[i];
        if (c <= ' ' || c == '/' || c >= 0x7F) return 0;
    }
    memcpy(iface, spec, nl);
    iface[nl] = '\0';
    *has_pos = 0;
    *pos_m   = 0;
    if (!at) return 1;
    char *end = NULL;
    double v = strtod(at + 1, &end);
    if (end == at + 1 || *end != '\0' || !isfinite(v) || v < -DF_POS_MAX_M || v > DF_POS_MAX_M) return 0;
    *has_pos = 1;
    *pos_m   = v;
    return 1;
}
