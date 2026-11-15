#include "web_victron.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"
#include "web_slothdb.h"

/* ── the allow-list: sloth's (src/victron.c VALS[]), name, unit, bound ── */

static const struct {
    const char *name, *unit;
    double lo, hi;
} VALS[WEB_VICTRON_VALS] = {
    /* In sloth.db's victron_readings column order (db_victron_col()),
     * so index i is column i; the enumerations last. */
    { "voltage_v",     "V",   -400,  400 },
    { "aux_voltage_v", "V",   -400,  400 },
    { "mid_voltage_v", "V",      0,  700 },
    { "input_v",       "V",      0,  700 },
    { "output_v",      "V",   -400,  400 },
    { "current_a",     "A", -10000, 10000 },
    { "power_w",       "W", -200000, 200000 },
    { "consumed_ah",   "Ah", -200000, 200000 },
    { "soc_pct",       "%",      0,  100 },
    { "ttg_min",       "min",    0,  65535 },
    { "temperature_c", "C",   -100,  400 },
    { "alarm_reason",  "",       0,  65535 },
    { "aux_input",     "",       0,  3 },
    { "device_state",  "",       0,  255 },
    { "charger_error", "",       0,  255 },
    { "off_reason",    "",       0,  4294967295.0 },
};

const char *web_victron_val_name(int i) {
    return i >= 0 && i < WEB_VICTRON_VALS ? VALS[i].name : NULL;
}

const char *web_victron_val_unit(int i) {
    return i >= 0 && i < WEB_VICTRON_VALS ? VALS[i].unit : NULL;
}

int web_victron_val_index(const char *name) {
    for (int i = 0; name && i < WEB_VICTRON_VALS; i++)
        if (!strcmp(VALS[i].name, name)) return i;
    return -1;
}

/* ── lifecycle ──────────────────────────────────────────────────────── */

int web_victron_init(web_victron_t *a) {
    memset(a, 0, sizeof(*a));
    a->rows = calloc(WEB_VICTRON_ROWS, sizeof(*a->rows));
    if (!a->rows) return -1;
    pthread_mutex_init(&a->mu, NULL);
    return 0;
}

void web_victron_destroy(web_victron_t *a) {
    if (!a->rows) return;
    pthread_mutex_destroy(&a->mu);
    free(a->rows);
    a->rows = NULL;
}

/* ── field readers: a value outside its range is absent ─────────────── */

#define T_MAX (1LL << 40)
#define NOF(x) (sizeof(x) / sizeof((x)[0]))

static int jint(const web_jrec_t *r, const char *k, long long lo, long long hi,
                long long *out) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *out = f->i;
    return 1;
}

/* sloth's own rule for a string it keeps (src/victron.c clean()):
 * [A-Za-z0-9] and " -_.:/()+" only, 1..max bytes. */
static int clean(const char *s, size_t max) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || (c && strchr(" -_.:/()+", c))))
            return 0;
    }
    return 1;
}

static void jtext(const web_jrec_t *r, const char *k, size_t max, char *out) {
    const char *s = web_jl_str(r, k);
    out[0] = '\0';
    if (clean(s, max)) memcpy(out, s, strlen(s) + 1);
}

/* sloth's address form: lower-case aa:bb:cc:dd:ee:ff. */
static int mac_ok(const char *m) {
    if (!m || strlen(m) != 17) return 0;
    for (int i = 0; i < 17; i++) {
        char c = m[i];
        if (i % 3 == 2) { if (c != ':') return 0; }
        else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return 0;
    }
    return 1;
}

/* sloth's service list (src/victron.c services_take()): lower-case
 * [0-9a-f-] joined by ',', at most the cap. */
static void jservices(const web_jrec_t *r, char *out) {
    const char *s = web_jl_str(r, "services");
    out[0] = '\0';
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_VICTRON_SERVICES_MAX) return;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') ||
              s[i] == '-' || s[i] == ','))
            return;
    memcpy(out, s, n + 1);
}

/* ── the table ──────────────────────────────────────────────────────── */

static web_victron_row_t *row_find(web_victron_t *a, const char *mac) {
    for (int i = 0; i < WEB_VICTRON_ROWS; i++)
        if (a->rows[i].used && !strcmp(a->rows[i].mac, mac)) return &a->rows[i];
    return NULL;
}

static web_victron_row_t *row_new(web_victron_t *a, const char *mac) {
    web_victron_row_t *lru = NULL, *fr = NULL;
    for (int i = 0; i < WEB_VICTRON_ROWS; i++) {
        web_victron_row_t *x = &a->rows[i];
        if (!x->used) { if (!fr) fr = x; continue; }
        if (!lru || x->ts < lru->ts) lru = x;
    }
    web_victron_row_t *x = fr;
    if (!x) { a->evictions++; x = lru; }
    memset(x, 0, sizeof(*x));
    x->used = 1;
    snprintf(x->mac, sizeof(x->mac), "%s", mac);
    return x;
}

/* Against the newest record's ts: sloth reports every row it keeps at
 * least once a heartbeat, so a row silent past the TTL is one it no
 * longer keeps. */
static void age_out(web_victron_t *a, long long ts) {
    for (int i = 0; i < WEB_VICTRON_ROWS; i++) {
        web_victron_row_t *x = &a->rows[i];
        if (x->used && ts - x->ts > WEB_VICTRON_TTL_S) {
            x->used = 0;
            a->aged++;
        }
    }
}

static void device_apply(web_victron_t *a, const web_jrec_t *r, long long ts) {
    const char *mac = web_jl_str(r, "mac");
    long long fs;
    if (!mac_ok(mac) || !jint(r, "first_seen", 0, T_MAX, &fs)) {
        a->rejected++;
        return;
    }
    web_victron_row_t *x = row_find(a, mac);
    if (x && x->first_seen != fs) { x->used = 0; x = NULL; }
    if (!x) { x = row_new(a, mac); x->first_seen = fs; }
    long long v;
    x->ts = ts;
    x->records++;
    /* Each record is sloth's whole row, so a member absent here is
     * absent on the row, never kept from an older record. */
    x->last_seen = jint(r, "last_seen", 0, T_MAX, &v) ? v : 0;
    x->last_readout = jint(r, "last_readout", 0, T_MAX, &v) ? v : 0;
    x->last_gatt = jint(r, "last_gatt", 0, T_MAX, &v) ? v : 0;
    x->readings = jint(r, "readings", 0, 1LL << 50, &v) ? v : 0;
    x->sessions = jint(r, "sessions", 0, 1LL << 50, &v) ? v : 0;
    x->has_rssi = jint(r, "rssi", -127, 20, &v);
    x->rssi = x->has_rssi ? (int)v : 0;
    jtext(r, "serial", WEB_VICTRON_SERIAL_MAX, x->serial);
    jtext(r, "model", WEB_VICTRON_MODEL_MAX, x->model);
    jtext(r, "record", WEB_VICTRON_RECORD_MAX, x->record);
    jtext(r, "session", WEB_VICTRON_SESSION_MAX, x->session);
    jservices(r, x->services);
    const char *vs = web_jl_str(r, "values_src");
    x->values_src[0] = '\0';
    if (vs && (!strcmp(vs, "readout") || !strcmp(vs, "gatt")))
        snprintf(x->values_src, sizeof(x->values_src), "%s", vs);
    for (int i = 0; i < WEB_VICTRON_VALS; i++) {
        double d;
        x->has[i] = web_jl_num(r, VALS[i].name, &d) && isfinite(d) &&
                    d >= VALS[i].lo && d <= VALS[i].hi;
        x->v[i] = x->has[i] ? d : 0;
    }
    const char *src = web_jl_str(r, "src");
    if (src && strlen(src) <= WEB_VICTRON_SRC_MAX && clean(src, WEB_VICTRON_SRC_MAX))
        snprintf(a->src, sizeof(a->src), "%s", src);
}

/* sloth's victron_reject_name() order; the keys are victron_rej_<name>. */
static const char *const REJ[WEB_VICTRON_REJ_COUNT] = {
    "oversize", "not_object", "malformed", "not_victron", "no_mac"
};

static void sh_apply(web_victron_t *a, const web_jrec_t *r, long long ts) {
    /* sloth writes the block on every sensor_health while --victron is
     * set and on none without it: a sensor_health without it is a
     * sloth with no reader, so the block clears. */
    if (!web_jl_get(r, "victron_state")) {
        memset(&a->sh, 0, sizeof(a->sh));
        return;
    }
    web_victron_sh_t h;
    memset(&h, 0, sizeof(h));
    h.seen = 1;
    h.ts = ts;
    static const char *const STATES[] = { "none", "waiting", "live", "error" };
    const char *st = web_jl_str(r, "victron_state");
    for (size_t i = 0; st && i < NOF(STATES); i++)
        if (!strcmp(st, STATES[i])) snprintf(h.state, sizeof(h.state), "%s", STATES[i]);
    if (!h.state[0]) snprintf(h.state, sizeof(h.state), "other");
    jtext(r, "victron_src", WEB_VICTRON_SRC_MAX, h.src);
    long long v;
    h.missing = jint(r, "victron_missing", 0, 1, &v) && v == 1;
    h.devices = jint(r, "victron_devices", 0, 1000, &v) ? v : 0;
#define C(name, field, hi) h.field = jint(r, name, 0, hi, &v) ? v : 0
    C("victron_last_read", last_read, T_MAX);
    C("victron_last_rec", last_rec, T_MAX);
    C("victron_bytes", bytes, 1LL << 50);
    C("victron_lines", lines, 1LL << 50);
    C("victron_records", records, 1LL << 50);
    C("victron_bad_lines", bad_lines, 1LL << 50);
    C("victron_bad_values", bad_values, 1LL << 50);
    C("victron_other_keys", other_keys, 1LL << 50);
    C("victron_table_full", table_full, 1LL << 50);
    C("victron_truncations", truncations, 1LL << 50);
    C("victron_rotations", rotations, 1LL << 50);
    C("victron_read_errors", read_errors, 1LL << 50);
#undef C
    for (int k = 0; k < WEB_VICTRON_REJ_COUNT; k++) {
        char key[40];
        snprintf(key, sizeof(key), "victron_rej_%s", REJ[k]);
        h.rej[k] = jint(r, key, 0, 1LL << 50, &v) ? v : 0;
    }
    /* sloth's error text is its own (a strerror), but checked all the
     * same: printable ASCII without quote or backslash, or nothing. */
    const char *e = web_jl_str(r, "victron_err");
    if (e && strlen(e) <= WEB_VICTRON_ERR_MAX) {
        int ok = 1;
        for (const char *p = e; *p; p++)
            if ((unsigned char)*p < 0x20 || (unsigned char)*p > 0x7e || *p == '"' || *p == '\\')
                ok = 0;
        if (ok) snprintf(h.err, sizeof(h.err), "%s", e);
    }
    a->sh = h;
    if (!a->src[0] && h.src[0]) snprintf(a->src, sizeof(a->src), "%s", h.src);
}

void web_victron_record(web_victron_t *a, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!a || !a->rows) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&a->mu);
    if (!strcmp(t, "victron_device")) {
        a->records++;
        device_apply(a, r, ts);
        age_out(a, ts);
    } else if (!strcmp(t, "sensor_health")) {
        sh_apply(a, r, ts);
        age_out(a, ts);
    }
    pthread_mutex_unlock(&a->mu);
}

/* ── JSON ───────────────────────────────────────────────────────────── */

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *status_out) {
    *status_out = status;
    *len = web_series_error_json(reason, body, cap);
    return *len ? 0 : -1;
}

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    if (!s || !*s || strlen(s) > 12) return -1;
    long long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

static void jw_num(web_jw_t *w, double v, int dp) {
    char t[40];
    if (!isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static int by_recent(const void *pa, const void *pb) {
    const web_victron_row_t *x = *(const web_victron_row_t *const *)pa;
    const web_victron_row_t *y = *(const web_victron_row_t *const *)pb;
    if (x->last_seen != y->last_seen) return y->last_seen > x->last_seen ? 1 : -1;
    return strcmp(x->mac, y->mac);
}

static void row_json(web_jw_t *w, const web_victron_row_t *x, long long now_s) {
    web_jw_raw(w, "{\"mac\":"); web_jw_str(w, x->mac);
    web_jw_raw(w, ",\"serial\":"); web_jw_str(w, x->serial);
    web_jw_raw(w, ",\"model\":"); web_jw_str(w, x->model);
    web_jw_raw(w, ",\"record\":"); web_jw_str(w, x->record);
    web_jw_raw(w, ",\"values_src\":"); web_jw_str(w, x->values_src);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, x->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, x->last_seen);
    web_jw_raw(w, ",\"last_readout\":"); web_jw_int(w, x->last_readout);
    web_jw_raw(w, ",\"last_gatt\":"); web_jw_int(w, x->last_gatt);
    /* The age by the host's clock against sloth's read time; a record
     * from the future (a clock step) is age 0, never negative. */
    long long age = x->last_seen > 0 && now_s > x->last_seen ? now_s - x->last_seen : 0;
    long long after = x->last_readout ? WEB_VICTRON_STALE_S : WEB_VICTRON_STALE_GATT_S;
    web_jw_raw(w, ",\"age_s\":");
    if (x->last_seen > 0) web_jw_int(w, age); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"stale_after_s\":"); web_jw_int(w, after);
    web_jw_raw(w, ",\"stale\":");
    web_jw_raw(w, x->last_seen <= 0 || age > after ? "true" : "false");
    web_jw_raw(w, ",\"readings\":"); web_jw_int(w, x->readings);
    web_jw_raw(w, ",\"sessions\":"); web_jw_int(w, x->sessions);
    web_jw_raw(w, ",\"session\":"); web_jw_str(w, x->session);
    web_jw_raw(w, ",\"services\":[");
    /* The list split on ',' (each piece already [0-9a-f-]); an empty
     * piece is dropped, never written as "". */
    const char *p = x->services;
    int k = 0;
    while (*p) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n) {
            if (k++) web_jw_raw(w, ",");
            web_jw_strn(w, p, n);
        }
        p += n + (e ? 1 : 0);
    }
    web_jw_raw(w, "],\"rssi\":");
    if (x->has_rssi) web_jw_int(w, x->rssi); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"values\":{");
    k = 0;
    for (int i = 0; i < WEB_VICTRON_VALS; i++) {
        if (!x->has[i]) continue;
        if (k++) web_jw_raw(w, ",");
        web_jw_str(w, VALS[i].name);
        web_jw_raw(w, ":{\"v\":");
        jw_num(w, x->v[i], VALS[i].unit[0] ? 3 : 0);
        web_jw_raw(w, ",\"unit\":");
        web_jw_str(w, VALS[i].unit);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "},\"ts\":"); web_jw_int(w, x->ts);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, x->records);
    web_jw_raw(w, "}");
}

static void sensor_json(web_jw_t *w, const web_victron_sh_t *h) {
    if (!h->seen) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"ts\":"); web_jw_int(w, h->ts);
    web_jw_raw(w, ",\"state\":"); web_jw_str(w, h->state);
    web_jw_raw(w, ",\"src\":"); web_jw_str(w, h->src);
    web_jw_raw(w, ",\"missing\":"); web_jw_int(w, h->missing);
    web_jw_raw(w, ",\"last_read\":"); web_jw_int(w, h->last_read);
    web_jw_raw(w, ",\"last_rec\":"); web_jw_int(w, h->last_rec);
    web_jw_raw(w, ",\"devices\":"); web_jw_int(w, h->devices);
    web_jw_raw(w, ",\"bytes\":"); web_jw_int(w, h->bytes);
    web_jw_raw(w, ",\"lines\":"); web_jw_int(w, h->lines);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, h->records);
    web_jw_raw(w, ",\"bad_lines\":"); web_jw_int(w, h->bad_lines);
    web_jw_raw(w, ",\"rej\":{");
    for (int k = 0; k < WEB_VICTRON_REJ_COUNT; k++) {
        if (k) web_jw_raw(w, ",");
        web_jw_str(w, REJ[k]);
        web_jw_raw(w, ":");
        web_jw_int(w, h->rej[k]);
    }
    web_jw_raw(w, "},\"bad_values\":"); web_jw_int(w, h->bad_values);
    web_jw_raw(w, ",\"other_keys\":"); web_jw_int(w, h->other_keys);
    web_jw_raw(w, ",\"table_full\":"); web_jw_int(w, h->table_full);
    web_jw_raw(w, ",\"truncations\":"); web_jw_int(w, h->truncations);
    web_jw_raw(w, ",\"rotations\":"); web_jw_int(w, h->rotations);
    web_jw_raw(w, ",\"read_errors\":"); web_jw_int(w, h->read_errors);
    web_jw_raw(w, ",\"err\":"); web_jw_str(w, h->err);
    web_jw_raw(w, "}");
}

int web_victron_route(web_victron_t *a, const char *query, long long now_s, int none_here,
                      char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_VICTRON_ROWS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_VICTRON_ROWS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (!a || !a->rows) return answer_error(503, "no_victron", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }

    const web_victron_row_t *idx[WEB_VICTRON_ROWS];
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&a->mu);
    int n = 0;
    for (int i = 0; i < WEB_VICTRON_ROWS; i++)
        if (a->rows[i].used) idx[n++] = &a->rows[i];
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_recent);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, a->src);
    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)a->records);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)a->evictions);
    web_jw_raw(&w, ",\"aged\":"); web_jw_int(&w, (long long)a->aged);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)a->rejected);
    web_jw_raw(&w, ",\"sensor\":");
    sensor_json(&w, &a->sh);
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"devices\":[");
    int shown = 0, cut = 0;
    for (int i = 0; i < n && i < limit; i++) {
        if (w.len + WEB_VICTRON_ROW_WORST + 64 > cap) { cut = 1; break; }
        if (i) web_jw_raw(&w, ",");
        row_json(&w, idx[i], now_s);
        shown++;
    }
    web_jw_raw(&w, "],\"shown\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"cut\":"); web_jw_raw(&w, cut ? "true" : "false");
    web_jw_raw(&w, "}");
    pthread_mutex_unlock(&a->mu);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_victron_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "Victron devices are sloth-va's file (--victron), read off its "
                   "Bluetooth receiver; the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

/* ── /api/victron/history (sloth.db) ────────────────────────────────── */

static int hist_error(int status, const char *reason, const char *detail,
                      char *body, size_t cap, size_t *len, int *st) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"error\":");
    web_jw_str(&w, reason);
    if (detail) {
        web_jw_raw(&w, ",\"detail\":");
        web_jw_strn(&w, detail, strnlen(detail, 240));
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *st = status;
    return 0;
}

int web_victron_history_route(const web_m4_t *m, const char *query, long long now_s,
                              char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[3] = { { "mac", "", 0 }, { "metric", "", 0 }, { "hours", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 3, err, sizeof(err)) != 0)
        return hist_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen || !mac_ok(ps[0].val))
        return hist_error(400, "bad_mac", NULL, body, cap, len, status);
    int mi = ps[1].seen ? web_victron_val_index(ps[1].val) : -1;
    if (mi < 0)
        return hist_error(400, "bad_metric", NULL, body, cap, len, status);
    long long hours = 24;
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_VICTRON_HOURS_MAX, &hours) != 0)
        return hist_error(400, "bad_hours", NULL, body, cap, len, status);
    /* Checked before the file: under Local the answer is out of scope
     * whether or not there is a sloth.db to read. */
    WEB_M4_CHECKED(m, len, status);
    if (!(web_m4_rfdb(m) && web_m4_rfdb(m)->configured && web_slothdb_available()))
        return hist_error(503, "no_sloth_db",
                          "start slothweb with --sloth-db PATH (a WITH_SQLITE build)",
                          body, cap, len, status);
    long long bucket = hours * 3600 / WEB_VICTRON_HIST_POINTS;
    if (bucket < WEB_VICTRON_BUCKET_MIN) bucket = WEB_VICTRON_BUCKET_MIN;
    long long from = now_s - hours * 3600;
    web_sdb_conn_t conn;
    char oerr[WEB_SDB_ERR_MAX];
    if (web_slothdb_open(web_m4_rfdb(m), &conn, WEB_SDB_HTTP_MS, now_s, oerr, sizeof(oerr)) != 0) {
        web_slothdb_close(&conn);
        web_sdb_stats_t st;
        web_slothdb_stats(web_m4_rfdb(m), &st);
        char r[48];
        snprintf(r, sizeof(r), "sloth_db_%s", web_slothdb_state_word(st.state));
        return hist_error(503, r, oerr, body, cap, len, status);
    }
    /* The window is hours * 3600 and a bucket at least a POINTS-th of
     * it, so it spans POINTS buckets, one more where the epoch-aligned
     * edges straddle: read two over, keep the newest POINTS, say cut. */
    web_sdb_vic_pt_t pts[WEB_VICTRON_HIST_POINTS + 2];
    int n = web_sdb_victron_history(&conn, ps[0].val, VALS[mi].name, from, bucket, pts,
                                    WEB_VICTRON_HIST_POINTS + 2);
    int to = conn.timed_out, schema = conn.schema;
    web_slothdb_close(&conn);
    if (n < 0)
        return hist_error(503, to ? "sloth_db_timeout" : "sloth_db_error", NULL,
                          body, cap, len, status);
    int dp = VALS[mi].unit[0] ? 3 : 0;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"mac\":"); web_jw_str(&w, ps[0].val);
    web_jw_raw(&w, ",\"metric\":"); web_jw_str(&w, VALS[mi].name);
    web_jw_raw(&w, ",\"unit\":"); web_jw_str(&w, VALS[mi].unit);
    web_jw_raw(&w, ",\"hours\":"); web_jw_int(&w, hours);
    web_jw_raw(&w, ",\"from\":"); web_jw_int(&w, from);
    web_jw_raw(&w, ",\"bucket_s\":"); web_jw_int(&w, bucket);
    web_jw_raw(&w, ",\"db_schema\":"); web_jw_int(&w, schema);
    web_jw_raw(&w, ",\"have\":"); web_jw_raw(&w, schema >= 15 ? "true" : "false");
    web_jw_raw(&w, ",\"cols\":[\"t\",\"mean\",\"min\",\"max\",\"n\",\"gatt\"],\"points\":[");
    int shown = n > WEB_VICTRON_HIST_POINTS ? WEB_VICTRON_HIST_POINTS : n;
    /* The newest buckets when there were more: the window's oldest go. */
    int start = n - shown;
    for (int i = start; i < n; i++) {
        if (i > start) web_jw_raw(&w, ",");
        web_jw_raw(&w, "["); web_jw_int(&w, pts[i].t);
        web_jw_raw(&w, ","); jw_num(&w, pts[i].mean, dp ? dp : 2);
        web_jw_raw(&w, ","); jw_num(&w, pts[i].min, dp);
        web_jw_raw(&w, ","); jw_num(&w, pts[i].max, dp);
        web_jw_raw(&w, ","); web_jw_int(&w, pts[i].n);
        web_jw_raw(&w, ","); web_jw_int(&w, pts[i].gatt);
        web_jw_raw(&w, "]");
    }
    web_jw_raw(&w, "],\"total\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"cut\":"); web_jw_raw(&w, start > 0 ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

void web_victron_health_json(web_victron_t *a, web_jw_t *w) {
    if (!a || !a->rows) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&a->mu);
    int n = 0;
    for (int i = 0; i < WEB_VICTRON_ROWS; i++) n += a->rows[i].used != 0;
    web_jw_raw(w, "{\"rows\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)a->records);
    web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)a->evictions);
    web_jw_raw(w, ",\"aged\":"); web_jw_int(w, (long long)a->aged);
    web_jw_raw(w, ",\"rejected\":"); web_jw_int(w, (long long)a->rejected);
    web_jw_raw(w, ",\"sensor_seen\":"); web_jw_int(w, a->sh.seen);
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&a->mu);
}
