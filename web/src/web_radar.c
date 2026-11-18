#include "web_radar.h"

#include <stdio.h>
#include <string.h>

#include "web_series.h"

/* One listed device of a band: the BLE row's address, type, sensor and
 * name, or the Wi-Fi row's MAC, kind and SSID; the reading and the
 * record's clock. The name is already in its display form (web_ble.h,
 * web_ssid.h), cut here to WEB_RADAR_NAME_MAX octets. */
typedef struct {
    char      addr[18];
    int       type;                  /* BLE addr_type; Wi-Fi 1 ap, 0 sta */
    int       iface;                 /* BLE WEB_BLE_IF_* */
    char      name[WEB_RADAR_NAME_MAX + 1];
    int       has_rssi, rssi;
    long long ts;
    int       band;                  /* 0..4, -1 none */
    int       has_m;
    double    m;
    char      trend[14];             /* sloth's word, or "" */
} rd_dev_t;

typedef struct {
    int      n;                      /* rows in the band */
    int      kept;                   /* of them listed, at most WEB_RADAR_DEVS */
    rd_dev_t d[WEB_RADAR_DEVS];
} rd_band_t;

typedef struct {
    int       kept;
    rd_dev_t  d[WEB_RADAR_RECENT];
} rd_recent_t;

typedef struct {
    int         total, estimated, none;
    rd_band_t   band[WEB_RADAR_BANDS];
    rd_recent_t recent;
} rd_census_t;

/* sloth's band words in src/rf_distance.h order, by index 0..4
 * (web_ble.h's WEB_BLE_BAND_* less one). */
static const char *const BAND[WEB_RADAR_BANDS] = {
    "immediate", "near", "room", "building", "far",
};

static int band_index(const char *w) {
    for (int i = 0; w && i < WEB_RADAR_BANDS; i++)
        if (!strcmp(BAND[i], w)) return i;
    return -1;
}

/* A reading sorts before none, then the strongest first. */
static int nearer(const rd_dev_t *a, const rd_dev_t *b) {
    if (a->has_rssi != b->has_rssi) return a->has_rssi;
    return a->has_rssi && a->rssi > b->rssi;
}

/* Count d in band i, and keep it among the band's WEB_RADAR_DEVS
 * nearest (an insertion into a sorted list; the furthest falls off).
 * The cap is the plan's "8 of n" and the test's mutation point
 * (test_radar.c: seen red with the cap removed). */
static void band_take(rd_band_t *b, const rd_dev_t *d) {
    b->n++;
    int at = b->kept;
    while (at > 0 && nearer(d, &b->d[at - 1])) at--;
    if (at >= WEB_RADAR_DEVS) return;
    int last = b->kept < WEB_RADAR_DEVS ? b->kept : WEB_RADAR_DEVS - 1;
    for (int k = last; k > at; k--) b->d[k] = b->d[k - 1];
    b->d[at] = *d;
    if (b->kept < WEB_RADAR_DEVS) b->kept++;
}

/* The more recently heard first; a tie the stronger signal, then the
 * lower address, so the list is the same whatever the table order. */
static int newer(const rd_dev_t *a, const rd_dev_t *b) {
    if (a->ts != b->ts) return a->ts > b->ts;
    if (nearer(a, b) || nearer(b, a)) return nearer(a, b);
    return strcmp(a->addr, b->addr) < 0;
}

/* Keep d among the WEB_RADAR_RECENT most recent (an insertion into a
 * sorted list; the oldest falls off). The cap is test_radar.c's
 * mutation point (seen red with it removed). */
static void recent_take(rd_recent_t *r, const rd_dev_t *d) {
    int at = r->kept;
    while (at > 0 && newer(d, &r->d[at - 1])) at--;
    if (at >= WEB_RADAR_RECENT) return;
    int last = r->kept < WEB_RADAR_RECENT ? r->kept : WEB_RADAR_RECENT - 1;
    for (int k = last; k > at; k--) r->d[k] = r->d[k - 1];
    r->d[at] = *d;
    if (r->kept < WEB_RADAR_RECENT) r->kept++;
}

/* One row of either table into its census: counted in total; with a
 * band word, in that band and a candidate for the recent list; with a
 * reading and no band, in none. */
static void census_take(rd_census_t *c, rd_dev_t *d, int band) {
    c->total++;
    d->band = band;
    if (band >= 0 && band < WEB_RADAR_BANDS) {
        c->estimated++;
        band_take(&c->band[band], d);
        recent_take(&c->recent, d);
    } else if (d->has_rssi) {
        c->none++;
    }
}

/* ── BLE: web_ble_t.dev[] under its mutex ─────────────────────────── */

static void ble_census(web_ble_t *b, rd_census_t *c) {
    pthread_mutex_lock(&b->mu);
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        const web_ble_dev_t *x = &b->dev[i];
        if (!x->used) continue;
        rd_dev_t d;
        memset(&d, 0, sizeof(d));
        snprintf(d.addr, sizeof(d.addr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 x->addr[0], x->addr[1], x->addr[2], x->addr[3], x->addr[4], x->addr[5]);
        d.type = x->addr_type;
        d.iface = x->iface;
        web_utf8_copy(d.name, WEB_RADAR_NAME_MAX, x->name);
        d.has_rssi = x->has_rssi;
        d.rssi = x->rssi;
        d.ts = x->last_seen;
        /* est_dist_dm is decimetres, -1 none (web_ble.h). */
        d.has_m = x->est_valid && x->est_dist_dm >= 0 && x->est_dist_dm <= 1000000;
        d.m = d.has_m ? x->est_dist_dm / 10.0 : 0.0;
        if (x->est_valid && x->est_trend >= 0 && x->est_trend < WEB_BLE_TREND_COUNT)
            snprintf(d.trend, sizeof(d.trend), "%s", web_ble_trend_name(x->est_trend));
        /* est_band is WEB_BLE_BAND_* (NONE 0, IMMEDIATE 1 .. FAR 5). */
        int band = x->est_valid ? band_index(web_ble_band_name(x->est_band)) : -1;
        census_take(c, &d, band);
    }
    pthread_mutex_unlock(&b->mu);
}

/* ── Wi-Fi: the FRRS ledger through its census accessor ───────────── */

static void wifi_row(const web_frrs_rf_row_t *r, void *ctx) {
    rd_census_t *c = ctx;
    rd_dev_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.addr, sizeof(d.addr), "%s", r->mac);
    d.type = !strcmp(r->kind, "ap");
    web_utf8_copy(d.name, WEB_RADAR_NAME_MAX, r->ssid);
    d.has_rssi = r->has_rssi;
    d.rssi = r->rssi;
    d.ts = r->ts;
    d.has_m = r->has_m;
    d.m = r->m;
    snprintf(d.trend, sizeof(d.trend), "%s", r->trend ? r->trend : "");
    census_take(c, &d, band_index(r->band));
}

/* ── JSON ───────────────────────────────────────────────────────────── */

static void census_json(web_jw_t *w, const rd_census_t *c, int ble) {
    web_jw_raw(w, "{\"total\":"); web_jw_int(w, c->total);
    web_jw_raw(w, ",\"estimated\":"); web_jw_int(w, c->estimated);
    web_jw_raw(w, ",\"none\":"); web_jw_int(w, c->none);
    web_jw_raw(w, ",\"bands\":{");
    for (int i = 0; i < WEB_RADAR_BANDS; i++) {
        const rd_band_t *b = &c->band[i];
        if (i) web_jw_raw(w, ",");
        web_jw_key(w, BAND[i]);
        web_jw_raw(w, "{\"n\":"); web_jw_int(w, b->n);
        web_jw_raw(w, ",\"devs\":[");
        for (int k = 0; k < b->kept; k++) {
            const rd_dev_t *d = &b->d[k];
            if (k) web_jw_raw(w, ",");
            if (ble) {
                web_jw_raw(w, "{\"addr\":"); web_jw_str(w, d->addr);
                web_jw_raw(w, ",\"addr_type\":"); web_jw_int(w, d->type);
                web_jw_raw(w, ",\"iface\":"); web_jw_str(w, web_ble_iface_name(d->iface));
                web_jw_raw(w, ",\"name\":"); web_jw_str(w, d->name);
                web_jw_raw(w, ",\"rssi\":");
                if (d->has_rssi) web_jw_int(w, d->rssi); else web_jw_raw(w, "null");
                web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, d->ts);
            } else {
                web_jw_raw(w, "{\"mac\":"); web_jw_str(w, d->addr);
                web_jw_raw(w, ",\"kind\":"); web_jw_str(w, d->type ? "ap" : "sta");
                web_jw_raw(w, ",\"ssid\":"); web_jw_str(w, d->name);
                web_jw_raw(w, ",\"rssi\":");
                if (d->has_rssi) web_jw_int(w, d->rssi); else web_jw_raw(w, "null");
                web_jw_raw(w, ",\"ts\":"); web_jw_int(w, d->ts);
            }
            web_jw_raw(w, "}");
        }
        web_jw_raw(w, "]}");
    }
    web_jw_raw(w, "}}");
}

/* One family's recent list: [] without its table. */
static void recent_json(web_jw_t *w, const rd_census_t *c, int have, int ble) {
    web_jw_raw(w, "[");
    for (int k = 0; have && k < c->recent.kept; k++) {
        const rd_dev_t *d = &c->recent.d[k];
        char m[32];
        if (k) web_jw_raw(w, ",");
        web_jw_raw(w, ble ? "{\"addr\":" : "{\"mac\":"); web_jw_str(w, d->addr);
        if (ble) {
            web_jw_raw(w, ",\"addr_type\":"); web_jw_int(w, d->type);
            web_jw_raw(w, ",\"iface\":"); web_jw_str(w, web_ble_iface_name(d->iface));
            web_jw_raw(w, ",\"name\":"); web_jw_str(w, d->name);
        } else {
            web_jw_raw(w, ",\"kind\":"); web_jw_str(w, d->type ? "ap" : "sta");
            web_jw_raw(w, ",\"ssid\":"); web_jw_str(w, d->name);
        }
        web_jw_raw(w, ",\"m\":");
        if (d->has_m) { snprintf(m, sizeof(m), "%.1f", d->m); web_jw_raw(w, m); }
        else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"band\":"); web_jw_str(w, d->band >= 0 && d->band < WEB_RADAR_BANDS ? BAND[d->band] : "");
        web_jw_raw(w, ",\"trend\":"); web_jw_str(w, d->trend);
        web_jw_raw(w, ",\"rssi\":");
        if (d->has_rssi) web_jw_int(w, d->rssi); else web_jw_raw(w, "null");
        web_jw_raw(w, ble ? ",\"last_seen\":" : ",\"ts\":"); web_jw_int(w, d->ts);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]");
}

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *status_out) {
    *status_out = status;
    *len = web_series_error_json(reason, body, cap);
    return *len ? 0 : -1;
}

int web_radar_route(web_ble_t *b, web_frrs_t *f, const char *query, long long now_s,
                    int none_here, char *body, size_t cap, size_t *len, int *status) {
    /* No parameter of its own: every name is unknown. */
    web_param_t none[1] = { { "", "", 0 } };
    char err[48];
    if (web_params_parse(query, none, 0, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }

    static rd_census_t ble, wifi;      /* about 9 KB each: the one HTTP thread's */
    memset(&ble, 0, sizeof(ble));
    memset(&wifi, 0, sizeof(wifi));
    if (b && b->dev) ble_census(b, &ble);
    if (f) web_frrs_rf_census(f, wifi_row, &wifi);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"ble\":");
    if (b && b->dev) census_json(&w, &ble, 1); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"wifi\":");
    if (f && f->led) census_json(&w, &wifi, 0); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"devs\":{\"ble\":");
    recent_json(&w, &ble, b && b->dev, 1);
    web_jw_raw(&w, ",\"wifi\":");
    recent_json(&w, &wifi, f && f->led, 0);
    web_jw_raw(&w, "}}");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_radar_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "the Wi-Fi and BLE distance bands are the passive monitor radio's and "
                   "the BLE receivers'; the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}
