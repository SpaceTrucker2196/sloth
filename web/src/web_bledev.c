#include "web_bledev.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_chmix.h"
#include "web_json.h"
#include "web_metrics.h"
#include "web_series.h"
#include "web_wifi.h"

/* ── the classes (web_bledev.h; research/bluetooth/ble-device-classes.md) */

const web_ble_class_def_t web_ble_classes[WEB_BC_COUNT] = {
    [WEB_BC_PHONE] = { "b:phone", "Phones & computers", "P", 5,
        "Apple Continuity 0x05 AirDrop, 0x0C Handoff, 0x0D/0x0E Instant Hotspot, "
        "0x0F Nearby Action or 0x10 Nearby Info; Microsoft 0x0006 first octet "
        "0x01 (MS-CDP beacon); Appearance Phone or Computer" },
    [WEB_BC_WEAR] = { "b:wear", "Wearables & audio", "W", 4,
        "Apple Continuity 0x07 Proximity Pairing or 0x0B Magic Switch; Fast Pair "
        "Service Data 0xFE2C (the accessory); Samsung 0x0075 first octet 0x42 or "
        "0x01; Appearance of a worn, audio or personal-health category" },
    [WEB_BC_TAG] = { "b:tag", "Trackers", "T", 1,
        "a watch category; Appearance Tag or Keyring; a UUID the SIG registry "
        "assigns to Tile (0xFEED, 0xFEEC, 0xFD84) or CHIPOLO (0xFE33, 0xFE65)" },
    [WEB_BC_HID] = { "b:hid", "Input", "H", 2,
        "sloth's HID bits: Appearance 0x03C0..0x03CA or the HID service 0x1812" },
    [WEB_BC_BCN] = { "b:bcn", "Beacons", "B", 3,
        "Eddystone: Service Data or a listed UUID 0xFEAA" },
    [WEB_BC_IOT] = { "b:iot", "Vehicles & IoT", "I", 6,
        "Apple Continuity 0x06 HomeKit; Appearance of a fixed, home, vehicle or "
        "industrial category" },
    [WEB_BC_UNK] = { "b:unk", "Unknown", "?", 7,
        "none of the above; and all anonymous advertising (Address_Type 0xFF), "
        "whose one row a sensor holds fields several advertisers left" },
};

#define APPLE     0x004C
#define MICROSOFT 0x0006
#define SAMSUNG   0x0075

/* Appearance categories (bits 15..6 of the value; Assigned Numbers
 * §2.6.2, web/data/btsig/appearance_values.csv). Category 0 (Unknown)
 * and 15 (HID, sloth's own bits) are in none. */
static const unsigned char CAT_WEAR[] = {
    3,  /* Watch */          7,  /* Eye-glasses */      13, /* Heart Rate Sensor */
    14, /* Blood Pressure */ 16, /* Glucose Meter */    17, /* Running Walking Sensor */
    18, /* Cycling */        33, /* Audio Sink */       34, /* Audio Source */
    37, /* Wearable Audio Device */ 41, /* Hearing aid */ 49, /* Pulse Oximeter */
    52, /* Continuous Glucose Monitor */ 53, /* Insulin Pump */
    54, /* Medication Delivery */ 55, /* Spirometer */  81, /* Outdoor Sports Activity */
};
static const unsigned char CAT_IOT[] = {
    4,  /* Clock */          5,  /* Display */          6,  /* Remote Control */
    10, /* Media Player */   11, /* Barcode Scanner */  12, /* Thermometer */
    19, /* Control Device */ 20, /* Network Device */   21, /* Sensor */
    22, /* Light Fixtures */ 23, /* Fan */              24, /* HVAC */
    25, /* Air Conditioning */ 26, /* Humidifier */     27, /* Heating */
    28, /* Access Control */ 29, /* Motorized Device */ 30, /* Power Device */
    31, /* Light Source */   32, /* Window Covering */  35, /* Motorized Vehicle */
    36, /* Domestic Appliance */ 38, /* Aircraft */     39, /* AV Equipment */
    40, /* Display Equipment */ 42, /* Gaming */         43, /* Signage */
    50, /* Weight Scale */   51, /* Personal Mobility Device */
    82, /* Industrial Measurement Device */ 83, /* Industrial Tools */
    84, /* Cookware Device */
};

static int in_list(const unsigned char *l, size_t n, int v) {
    for (size_t i = 0; i < n; i++) if (l[i] == v) return 1;
    return 0;
}

static int uuid_is(const web_ble_fields_t *f, int u) {
    return f->uuid16 == u || f->svc_data_uuid16 == u;
}

int web_ble_class_of(const web_ble_fields_t *f) {
    int cat = f->appearance >= 0 ? f->appearance >> 6 : -1;
    int sub = f->mfr_subtype;
    int apple = f->mfr_id == APPLE && sub >= 0;
    /* 1 Trackers */
    if (f->watch || cat == 8 || cat == 9 ||
        uuid_is(f, 0xFEED) || uuid_is(f, 0xFEEC) || uuid_is(f, 0xFD84) ||
        uuid_is(f, 0xFE33) || uuid_is(f, 0xFE65))
        return WEB_BC_TAG;
    /* 2 Input */
    if (f->hid) return WEB_BC_HID;
    /* 3 Beacons */
    if (uuid_is(f, 0xFEAA)) return WEB_BC_BCN;
    /* 4 Wearables & audio */
    if ((apple && (sub == 0x07 || sub == 0x0B)) || f->svc_data_uuid16 == 0xFE2C ||
        (f->mfr_id == SAMSUNG && (sub == 0x42 || sub == 0x01)) ||
        (cat >= 0 && in_list(CAT_WEAR, sizeof(CAT_WEAR), cat)))
        return WEB_BC_WEAR;
    /* 5 Phones & computers */
    if ((apple && (sub == 0x05 || sub == 0x0C || sub == 0x0D || sub == 0x0E ||
                   sub == 0x0F || sub == 0x10)) ||
        (f->mfr_id == MICROSOFT && sub == 0x01) || cat == 1 || cat == 2)
        return WEB_BC_PHONE;
    /* 6 Vehicles & IoT */
    if ((apple && sub == 0x06) || (cat >= 0 && in_list(CAT_IOT, sizeof(CAT_IOT), cat)))
        return WEB_BC_IOT;
    return WEB_BC_UNK;
}

static int ibound(const web_jrec_t *r, const char *k, int lo, int hi) {
    long long v = web_jl_int(r, k, -1);
    return v < lo || v > hi ? -1 : (int)v;
}

int web_ble_class_of_rec(const web_jrec_t *r) {
    /* As web_ble_dev_class(): an anonymous record is its row, every
     * anonymous advertiser that sensor heard, so Unknown. */
    if (web_jl_int(r, "addr_type", -1) == 255) return WEB_BC_UNK;
    const char *cat = web_jl_str(r, "watch_category");
    long long hid = web_jl_int(r, "hid", 0);
    web_ble_fields_t f = {
        ibound(r, "mfr_id", 0, 65535), ibound(r, "mfr_subtype", 0, 255),
        ibound(r, "uuid16", 0, 65535), ibound(r, "svc_data_uuid16", 0, 65535),
        ibound(r, "appearance", 0, 65535), hid > 0 && hid <= 3 ? (int)hid : 0,
        cat && cat[0] ? 1 : 0,
    };
    return web_ble_class_of(&f);
}

int web_ble_class_find(const char *slug) {
    for (int c = 0; slug && c < WEB_BC_COUNT; c++)
        if (!strcmp(web_ble_classes[c].slug, slug)) return c;
    return -1;
}

int web_key_bleclass_text(const char *s, char *out) {
    int c = web_ble_class_find(s);
    if (c < 0) return -1;
    snprintf(out, WEB_KEY_MAX + 1, "%s", web_ble_classes[c].slug);
    return 0;
}

/* ── the proximity grade ─────────────────────────────────────────────── */

double web_ble_prox_edge_at(double metres, double ptx_dbm) {
    double l1 = 20.0 * log10((double)WEB_BLE_PROX_FREQ_MHZ) - 28.0;
    return ptx_dbm - (l1 + WEB_BLE_PROX_N_X10 * log10(metres));
}

int web_ble_prox_band_at(double dbm, double ptx_dbm) {
    /* rf_band_of(): nearer than 1 m is immediate, and so on outward. */
    if (dbm > web_ble_prox_edge_at(1.0, ptx_dbm))  return WEB_BLE_BAND_IMMEDIATE;
    if (dbm > web_ble_prox_edge_at(3.0, ptx_dbm))  return WEB_BLE_BAND_NEAR;
    if (dbm > web_ble_prox_edge_at(10.0, ptx_dbm)) return WEB_BLE_BAND_ROOM;
    if (dbm > web_ble_prox_edge_at(30.0, ptx_dbm)) return WEB_BLE_BAND_BUILDING;
    return WEB_BLE_BAND_FAR;
}

double web_ble_prox_edge(double metres) {
    return web_ble_prox_edge_at(metres, WEB_BLE_PROX_PTX_DBM);
}

int web_ble_prox_band(double dbm) {
    return web_ble_prox_band_at(dbm, WEB_BLE_PROX_PTX_DBM);
}

static const double EDGE_M[4] = { 1.0, 3.0, 10.0, 30.0 };

/* The four edges at ptx, as the answer's "edges". */
static void edges_json(web_jw_t *w, double ptx) {
    web_jw_raw(w, "[");
    for (int e = 0; e < 4; e++) {
        char eb[32];
        if (e) web_jw_raw(w, ",");
        snprintf(eb, sizeof(eb), "%.2f", web_ble_prox_edge_at(EDGE_M[e], ptx));
        web_jw_raw(w, eb);
    }
    web_jw_raw(w, "]");
}

/* ── answers ─────────────────────────────────────────────────────────── */

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

static void fixed1(web_jw_t *w, double v) {
    char b[32];
    snprintf(b, sizeof(b), "%.1f", v);
    web_jw_raw(w, b);
}

/* "now": the header strip's facts. The rows' last_seen is the sensor's
 * clock and now_s slothweb's; on one host they agree. */
typedef struct {
    const web_m4_t *m;
    web_ble_t      *b;
    long long       now_s;
} now_ctx_t;

/* The "now" member at its longest is about 1530 bytes (two sensor
 * iface names at their caps, the nearest device's name and every count
 * at its widest); 2048 leaves room so it is never cut. */
#define NOW_MAX 2048

static void now_json(web_jw_t *w, void *vctx) {
    const now_ctx_t *c = vctx;
    web_ble_cand_t *cs = malloc(WEB_BLEDEV_CANDS * sizeof(*cs));
    int more = 0, n = 0, tags = 0, near = -1, anon = 0;
    if (cs) n = web_ble_candidates(c->b, c->now_s - WEB_BLEDEV_NOW_S, c->now_s + 1, cs,
                                   WEB_BLEDEV_CANDS, &more, &anon);
    /* Nearest by the grade's estimate: the reading less the row's own
     * P_tx (a larger margin is a shorter path), not raw RSSI, so a
     * 10 dBm advertiser at -60 is not taken for nearer than a 0 dBm
     * one at -55. Never anonymous advertising, which is no candidate:
     * its signal is whichever anonymous advertiser was heard last, and
     * it has no address to name or open. */
    for (int i = 0; i < n; i++) {
        if (cs[i].cls == WEB_BC_TAG) tags++;
        if (cs[i].has_rssi &&
            (near < 0 || cs[i].rssi - cs[i].ptx_dbm > cs[near].rssi - cs[near].ptx_dbm))
            near = i;
    }
    web_jw_raw(w, ",\"now\":{\"window_s\":"); web_jw_int(w, WEB_BLEDEV_NOW_S);
    /* Anonymous advertising one advertiser, as ble.class.advertisers. */
    web_jw_raw(w, ",\"advertisers\":"); web_jw_int(w, n + anon);
    web_jw_raw(w, ",\"advertisers_more\":"); web_jw_raw(w, more ? "true" : "false");
    web_jw_raw(w, ",\"trackers\":"); web_jw_int(w, tags);
    web_jw_raw(w, ",\"nearest\":");
    if (near >= 0) {
        const web_ble_cand_t *d = &cs[near];
        char a[18];
        web_mix_mac_text(d->addr, a);
        web_jw_raw(w, "{\"addr\":"); web_jw_str(w, a);
        web_jw_raw(w, ",\"addr_type\":"); web_jw_int(w, d->addr_type);
        web_jw_raw(w, ",\"iface\":"); web_jw_str(w, web_ble_iface_name(d->iface));
        web_jw_raw(w, ",\"name\":");
        if (d->name[0]) web_jw_str(w, d->name); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"name_np\":"); web_jw_raw(w, d->name_np ? "true" : "false");
        web_jw_raw(w, ",\"class\":"); web_jw_str(w, web_ble_classes[d->cls].slug);
        web_jw_raw(w, ",\"rssi\":"); web_jw_int(w, d->rssi);
        web_jw_raw(w, ",\"band\":");
        if (d->est_valid) web_jw_str(w, web_ble_band_name(d->est_band));
        else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"grade\":");
        web_jw_str(w, web_ble_band_name(web_ble_prox_band_at(d->rssi, d->ptx_dbm)));
        web_jw_raw(w, ",\"ptx\":"); web_jw_int(w, d->ptx_dbm);
        web_jw_raw(w, ",\"ptx_source\":"); web_jw_str(w, web_ble_ptx_name(d->ptx_src));
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    free(cs);
    /* sloth's own report count (sensor_health ble_adv_reports, the host
     * stream's), the last minute's fine buckets summed. */
    web_jw_raw(w, ",\"adv_rate\":");
    web_point_t pts[8];
    int pm = 0, serr = 0, np = -1;
    long long to = c->now_s - c->now_s % WEB_FINE_S;
    if (c->m && c->m->tsdb)
        np = web_series_points(c->m->tsdb, WEB_TIER_FINE, WM_BLE_ADV_REPORTS, "",
                               to - WEB_BLEDEV_NOW_S, to, pts, 8, &pm, &serr);
    double sum = 0;
    int got = 0;
    for (int i = 0; i < np; i++) if (pts[i].n) { sum += pts[i].sum; got++; }
    if (got) fixed1(w, sum / WEB_BLEDEV_NOW_S); else web_jw_raw(w, "null");
    /* Which BLE receivers sloth runs, from its latest sensor_health:
     * with neither the page draws "no sensor" rather than a forced
     * Trackers row reading as a listening sensor that heard none, and
     * with --bt-capture alone it says the one-channel samples are not
     * credited to the class mix. seen false: no sensor_health yet. */
    web_ble_sh_t sh;
    memset(&sh, 0, sizeof(sh));
    if (c->b && c->b->dev) web_ble_sensor(c->b, &sh);
    web_jw_raw(w, ",\"sensor\":{\"seen\":"); web_jw_raw(w, sh.seen ? "true" : "false");
    web_jw_raw(w, ",\"btmon_iface\":"); web_jw_str(w, sh.btmon_iface);
    web_jw_raw(w, ",\"btcap_iface\":"); web_jw_str(w, sh.btcap_iface);
    web_jw_raw(w, "}}");
}

/* ── /api/ble/classes ────────────────────────────────────────────────── */

static int ble_mix_key(const char *key, int *rank, long *num) {
    int c = web_ble_class_find(key);
    if (c < 0) return -1;
    *rank = c;
    *num = 0;
    return 0;
}

static void ble_row_extra(web_jw_t *w, const char *key, void *ctx) {
    (void)ctx;
    int c = web_ble_class_find(key);
    web_jw_raw(w, ",\"label\":"); web_jw_str(w, web_ble_classes[c].label);
    web_jw_raw(w, ",\"glyph\":"); web_jw_str(w, web_ble_classes[c].glyph);
}

static void ble_tx_json(web_jw_t *w, const web_m4_t *m, web_sdb_conn_t *conn,
                        const uint8_t mac[6], int kind, void *vctx) {
    (void)m; (void)conn;
    const now_ctx_t *c = vctx;
    char a[18];
    web_ble_cand_t d;
    /* Anonymous advertising (web_chmix.h WEB_TX_BLE_ANON): one entry,
     * its id a word no address can be, always Unknown's (it is credited
     * nowhere else), no row to open. */
    if (kind == WEB_TX_BLE_ANON) {
        web_jw_raw(w, "{\"id\":\"anonymous\",\"kind\":\"anon\",\"name\":null,\"name_np\":false,"
                      "\"class\":\"b:unk\",\"addr_type\":255,\"iface\":null}");
        return;
    }
    web_mix_mac_text(mac, a);
    int known = web_ble_addr_info(c->b, mac, &d);
    /* An address the tables no longer hold (evicted, or never kept: the
     * mix outlives a row) is named by its address alone. */
    web_jw_raw(w, "{\"id\":"); web_jw_str(w, a);
    web_jw_raw(w, ",\"kind\":\"ble\",\"name\":");
    if (known && d.name[0]) web_jw_str(w, d.name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"name_np\":"); web_jw_raw(w, known && d.name_np ? "true" : "false");
    web_jw_raw(w, ",\"class\":");
    if (known) web_jw_str(w, web_ble_classes[d.cls].slug); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"addr_type\":");
    if (known) web_jw_int(w, d.addr_type); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"iface\":");
    if (known) web_jw_str(w, web_ble_iface_name(d.iface)); else web_jw_raw(w, "null");
    web_jw_raw(w, "}");
}

static int by_display(const void *a, const void *b) {
    int x = web_ble_class_find((const char *)a), y = web_ble_class_find((const char *)b);
    return x - y;
}

int web_bledev_classes_route(const web_m4_t *m, web_ble_t *b, const char *query,
                             long long now_s, char *body, size_t cap, size_t *len,
                             int *status) {
    web_param_t ps[5] = {
        { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 },
        { "metric", "", 0 }, { "mix", "", 0 },
    };
    char err[48];
    if (web_params_parse(query, ps, 5, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    int metric = WM_BLE_CLASS_ADVERTISERS;
    if (ps[4].seen) {
        if (strcmp(ps[4].val, "1")) return answer_error(400, "bad_mix", body, cap, len, status);
        if (ps[3].seen) return answer_error(400, "mix_takes_no_metric", body, cap, len, status);
    } else if (ps[3].seen) {
        if (!strcmp(ps[3].val, "advertisers")) metric = WM_BLE_CLASS_ADVERTISERS;
        else if (!strcmp(ps[3].val, "adv")) metric = WM_BLE_CLASS_ADV;
        else return answer_error(400, "unknown_metric", body, cap, len, status);
    }
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", body, cap, len, status);
    web_grid_t g;
    const char *why;
    if (web_grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    now_ctx_t nc = { m, b, now_s };
    if (ps[4].seen) {
        if (!m->tsdb->blemix)
            return answer_error(503, "no_ble_mix", body, cap, len, status);
        web_mix_ops_t ops;
        memset(&ops, 0, sizeof(ops));
        ops.mix = m->tsdb->blemix;
        ops.ns = WEB_MIX_NS_BLE;
        ops.metric = "ble.mix";
        ops.unit = "reports";
        ops.rows_word = "rows";
        ops.kinds = 1u << WEB_TX_BLE | 1u << WEB_TX_BLE_ANON;
        ops.key = ble_mix_key;
        ops.row_extra = ble_row_extra;
        ops.tx_json = ble_tx_json;
        ops.tail = now_json;
        ops.tail_max = NOW_MAX;
        ops.ctx = &nc;
        return web_mix_answer(m, &g, &ops, now_s, body, cap, len, status);
    }
    /* The series grid: every class with a series in the range, in
     * display order, and Trackers whether or not (an empty Trackers row
     * is information). */
    char (*keys)[WEB_KEY_MAX + 1] = malloc(WEB_GRID_KEYS * sizeof(*keys));
    if (!keys) return -1;
    int nk = web_grid_keys(m, metric, &g, keys), n = 0;
    char rows[WEB_BC_COUNT][WEB_KEY_MAX + 1];
    for (int i = 0; i < nk; i++) {
        int c = web_ble_class_find(keys[i]);
        int dup = 0;
        for (int k = 0; k < n && !dup; k++) dup = !strcmp(rows[k], keys[i]);
        if (c >= 0 && !dup && n < WEB_BC_COUNT) snprintf(rows[n++], sizeof(rows[0]), "%s", keys[i]);
    }
    free(keys);
    int have_tag = 0;
    for (int k = 0; k < n; k++) have_tag |= !strcmp(rows[k], web_ble_classes[WEB_BC_TAG].slug);
    if (!have_tag && n < WEB_BC_COUNT)
        snprintf(rows[n++], sizeof(rows[0]), "%s", web_ble_classes[WEB_BC_TAG].slug);
    qsort(rows, (size_t)n, sizeof(rows[0]), by_display);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_grid_head(&w, metric, &g);
    web_jw_raw(&w, ",\"total_keys\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"rows\":[");
    for (int i = 0; i < n; i++) {
        int c = web_ble_class_find(rows[i]);
        double total;
        if (i) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"key\":"); web_jw_str(&w, rows[i]);
        web_jw_raw(&w, ",\"label\":"); web_jw_str(&w, web_ble_classes[c].label);
        web_jw_raw(&w, ",\"glyph\":"); web_jw_str(&w, web_ble_classes[c].glyph);
        web_jw_raw(&w, ",\"cells\":");
        if (web_grid_cells_json(m, metric, &g, rows[i], &w, &total) != 0) return -1;
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"shown\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"more\":false");
    now_json(&w, &nc);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

/* ── /api/ble/proximity ──────────────────────────────────────────────── */

typedef struct {
    int    idx;              /* into the candidates */
    int    samples;
    double best;
} prow_t;

static const web_ble_cand_t *g_pc;

/* Trackers first, then the nearest by the strongest signal in the
 * window less the row's P_tx (rows with none after), then the most
 * reports, then the address. */
static int by_prox(const void *pa, const void *pb) {
    const prow_t *a = pa, *b = pb;
    const web_ble_cand_t *x = &g_pc[a->idx], *y = &g_pc[b->idx];
    int tx = x->cls == WEB_BC_TAG, ty = y->cls == WEB_BC_TAG;
    if (tx != ty) return ty - tx;
    if ((a->samples > 0) != (b->samples > 0)) return b->samples > 0 ? 1 : -1;
    double ma = a->best - x->ptx_dbm, mb = b->best - y->ptx_dbm;
    if (a->samples && b->samples && ma != mb) return ma > mb ? -1 : 1;
    if (x->adv_count != y->adv_count) return x->adv_count > y->adv_count ? -1 : 1;
    return memcmp(x->addr, y->addr, 6);
}

/* A row's worst case: the address, iface and class words, a name at its
 * cut escaped six-fold, and every cell at 7 bytes. */
static size_t prow_max(const web_grid_t *g) {
    return 480 + (size_t)WEB_BLE_NAME_MAX * 6 + (size_t)g->ncol * 7;
}

int web_bledev_proximity_route(const web_m4_t *m, web_ble_t *b, const char *query,
                               long long now_s, char *body, size_t cap, size_t *len,
                               int *status) {
    web_param_t ps[4] = { { "from", "", 0 }, { "to", "", 0 }, { "cols", "", 0 },
                          { "n", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 4, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    int want = WEB_BLEDEV_N;
    if (ps[3].seen) {
        if (!strcmp(ps[3].val, "12")) want = 12;
        else if (!strcmp(ps[3].val, "24")) want = 24;
        else if (!strcmp(ps[3].val, "48")) want = WEB_BLEDEV_N_MAX;
        else return answer_error(400, "bad_n", body, cap, len, status);
    }
    if (!m || !m->tsdb)
        return answer_error(503, "no_time_series", body, cap, len, status);
    web_grid_t g;
    const char *why;
    if (web_grid_of(m, ps, now_s, &g, &why) != 0)
        return answer_error(400, why, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    if (!b || !b->dev) return answer_error(503, "no_ble", body, cap, len, status);

    web_ble_cand_t *cs = malloc(WEB_BLEDEV_CANDS * sizeof(*cs));
    prow_t *pr = malloc(WEB_BLEDEV_CANDS * sizeof(*pr));
    double *sum = calloc((size_t)WEB_BLEDEV_CANDS * (size_t)g.ncol, sizeof(*sum));
    unsigned long *cnt = calloc((size_t)WEB_BLEDEV_CANDS * (size_t)g.ncol, sizeof(*cnt));
    long long maxp = (g.to - g.from) / g.step + 2;
    if (maxp > 12000) maxp = 12000;
    web_point_t *pts = malloc((size_t)maxp * sizeof(*pts));
    if (!cs || !pr || !sum || !cnt || !pts) {
        free(cs); free(pr); free(sum); free(cnt); free(pts);
        return -1;
    }
    int cut = 0, store_err = 0, anon = 0;
    /* Anonymous advertising has no row here (web_bledev.h) and takes no
     * read slot: it has no address to key a signal series by, and its
     * one row per sensor is every anonymous advertiser that sensor
     * heard. Said, not drawn. */
    int n = web_ble_candidates(b, g.from, g.to, cs, WEB_BLEDEV_CANDS, &cut, &anon);
    for (int i = 0; i < n; i++) {
        char a[18];
        web_mix_mac_text(cs[i].addr, a);
        pr[i].idx = i;
        pr[i].samples = 0;
        pr[i].best = 0;
        int more = 0, serr = 0;
        int k = web_series_points(m->tsdb, g.tier, WM_RF_RSSI_BLE, a, g.from, g.to, pts,
                                  (int)maxp, &more, &serr);
        if (serr) store_err = 1;
        for (int j = 0; j < k; j++) {
            if (!pts[j].n || pts[j].t < g.from || pts[j].t >= g.to) continue;
            long long c = (pts[j].t - g.from) / g.col_s;
            if (c < 0 || c >= g.ncol) continue;
            sum[(size_t)i * (size_t)g.ncol + (size_t)c] += pts[j].sum;
            cnt[(size_t)i * (size_t)g.ncol + (size_t)c] += pts[j].n;
            if (!pr[i].samples || pts[j].max > pr[i].best) pr[i].best = pts[j].max;
            pr[i].samples += (int)pts[j].n;
        }
    }
    g_pc = cs;
    qsort(pr, (size_t)n, sizeof(*pr), by_prox);
    g_pc = NULL;

    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"metric\":\"rf.rssi.ble\",\"unit\":\"dBm\",\"tier\":");
    web_jw_str(&w, web_tier_name(g.tier));
    web_jw_raw(&w, ",\"step\":");  web_jw_int(&w, g.step);
    web_jw_raw(&w, ",\"from\":");  web_jw_int(&w, g.from);
    web_jw_raw(&w, ",\"to\":");    web_jw_int(&w, g.to);
    web_jw_raw(&w, ",\"cols\":");  web_jw_int(&w, g.ncol);
    web_jw_raw(&w, ",\"col_s\":"); web_jw_int(&w, g.col_s);
    web_jw_raw(&w, ",\"n\":");     web_jw_int(&w, want);
    web_jw_raw(&w, ",\"candidates\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"anonymous_heard\":"); web_jw_raw(&w, anon ? "true" : "false");
    web_jw_raw(&w, ",\"edges\":");
    edges_json(&w, WEB_BLE_PROX_PTX_DBM);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0, room_cut = 0;
    size_t tail = NOW_MAX + 200;
    for (int r = 0; r < n && shown < want; r++) {
        if (w.len + prow_max(&g) + tail > cap) { room_cut = 1; break; }
        const web_ble_cand_t *d = &cs[pr[r].idx];
        char a[18];
        web_mix_mac_text(d->addr, a);
        if (shown++) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"addr\":"); web_jw_str(&w, a);
        web_jw_raw(&w, ",\"addr_type\":"); web_jw_int(&w, d->addr_type);
        web_jw_raw(&w, ",\"addr_kind\":"); web_jw_str(&w, web_ble_addr_kind(d->addr, d->addr_type));
        web_jw_raw(&w, ",\"iface\":"); web_jw_str(&w, web_ble_iface_name(d->iface));
        web_jw_raw(&w, ",\"name\":");
        if (d->name[0]) web_jw_str(&w, d->name); else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"name_np\":"); web_jw_raw(&w, d->name_np ? "true" : "false");
        web_jw_raw(&w, ",\"class\":"); web_jw_str(&w, web_ble_classes[d->cls].slug);
        web_jw_raw(&w, ",\"best\":");
        if (pr[r].samples) web_jw_int(&w, (long long)floor(pr[r].best + 0.5));
        else web_jw_raw(&w, "null");
        web_jw_raw(&w, ",\"samples\":"); web_jw_int(&w, pr[r].samples);
        web_jw_raw(&w, ",\"adv_count\":"); web_jw_int(&w, (long long)d->adv_count);
        web_jw_raw(&w, ",\"last_seen\":"); web_jw_int(&w, d->last_seen);
        web_jw_raw(&w, ",\"rows\":"); web_jw_int(&w, d->rows);
        web_jw_raw(&w, ",\"ptx\":"); web_jw_int(&w, d->ptx_dbm);
        web_jw_raw(&w, ",\"ptx_source\":"); web_jw_str(&w, web_ble_ptx_name(d->ptx_src));
        web_jw_raw(&w, ",\"edges\":"); edges_json(&w, d->ptx_dbm);
        web_jw_raw(&w, ",\"cells\":[");
        for (int c = 0; c < g.ncol; c++) {
            size_t at = (size_t)pr[r].idx * (size_t)g.ncol + (size_t)c;
            if (c) web_jw_raw(&w, ",");
            if (!cnt[at]) web_jw_raw(&w, "null");
            else fixed1(&w, sum[at] / (double)cnt[at]);
        }
        web_jw_raw(&w, "]}");
    }
    web_jw_raw(&w, "],\"shown\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":");
    web_jw_raw(&w, shown < n || cut ? "true" : "false");
    web_jw_raw(&w, ",\"read_cut\":"); web_jw_raw(&w, cut ? "true" : "false");
    web_jw_raw(&w, ",\"room_cut\":"); web_jw_raw(&w, room_cut ? "true" : "false");
    web_jw_raw(&w, ",\"store_error\":"); web_jw_raw(&w, store_err ? "true" : "false");
    free(cs); free(pr); free(sum); free(cnt); free(pts);
    now_ctx_t nc = { m, b, now_s };
    now_json(&w, &nc);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}
