#include "web_rtl433.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"

/* ── lifecycle ──────────────────────────────────────────────────────── */

int web_rtl433_init(web_rtl433_t *a) {
    memset(a, 0, sizeof(*a));
    a->rows = calloc(WEB_RTL433_ROWS, sizeof(*a->rows));
    if (!a->rows) return -1;
    pthread_mutex_init(&a->mu, NULL);
    return 0;
}

void web_rtl433_destroy(web_rtl433_t *a) {
    if (!a->rows) return;
    pthread_mutex_destroy(&a->mu);
    free(a->rows);
    a->rows = NULL;
}

/* ── field readers: a value outside its range is absent ─────────────── */

static int jint(const web_jrec_t *r, const char *k, long long lo, long long hi,
                long long *out) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *out = f->i;
    return 1;
}

static int jnum(const web_jrec_t *r, const char *k, double lo, double hi, double *out) {
    double v;
    if (!web_jl_num(r, k, &v) || !isfinite(v) || v < lo || v > hi) return 0;
    *out = v;
    return 1;
}

/* sloth's own rule for an rtl_433 string (src/rtl433.c clean_str()):
 * 1..max bytes of printable ASCII, no quote, no backslash. */
static int clean(const char *s, size_t max) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n == 0 || n > max) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') return 0;
    }
    return 1;
}

/* A string member into out (cap max + 1) when clean, else "". */
static void jtext(const web_jrec_t *r, const char *k, size_t max, char *out) {
    const char *s = web_jl_str(r, k);
    out[0] = '\0';
    if (clean(s, max)) memcpy(out, s, strlen(s) + 1);
}

/* A string member that must be one of a closed set, else "". */
static void jword(const web_jrec_t *r, const char *k, const char *const *set, size_t n,
                  char *out, size_t outsz) {
    const char *s = web_jl_str(r, k);
    out[0] = '\0';
    for (size_t i = 0; s && i < n; i++)
        if (!strcmp(s, set[i])) { snprintf(out, outsz, "%s", set[i]); return; }
}

/* The reading present under exactly one of keys[] (each `<prefix><unit>`
 * with units[] its unit), in [lo, hi]: 1 with the value and unit. Two
 * units of one reading on one record are ambiguous: absent. */
static int junit(const web_jrec_t *r, const char *const *keys, const char *const *units,
                 size_t n, double lo, double hi, double *v, char *unit, size_t unitsz) {
    int hits = 0;
    size_t which = 0;
    for (size_t i = 0; i < n; i++)
        if (web_jl_get(r, keys[i])) { hits++; which = i; }
    unit[0] = '\0';
    if (hits != 1 || !jnum(r, keys[which], lo, hi, v)) return 0;
    snprintf(unit, unitsz, "%s", units[which]);
    return 1;
}

#define T_MAX (1LL << 40)

/* ── the table ──────────────────────────────────────────────────────── */

static web_rtl433_row_t *row_find(web_rtl433_t *a, const char *model, const char *id) {
    for (int i = 0; i < WEB_RTL433_ROWS; i++) {
        web_rtl433_row_t *x = &a->rows[i];
        if (x->used && !strcmp(x->model, model) && !strcmp(x->id, id)) return x;
    }
    return NULL;
}

/* A fresh row, in a free slot or the least recently reported. */
static web_rtl433_row_t *row_new(web_rtl433_t *a, const char *model, const char *id) {
    web_rtl433_row_t *lru = NULL, *fr = NULL;
    for (int i = 0; i < WEB_RTL433_ROWS; i++) {
        web_rtl433_row_t *x = &a->rows[i];
        if (!x->used) { if (!fr) fr = x; continue; }
        if (!lru || x->ts < lru->ts) lru = x;
    }
    web_rtl433_row_t *x = fr;
    if (!x) { a->evictions++; x = lru; }
    memset(x, 0, sizeof(*x));
    x->used = 1;
    snprintf(x->model, sizeof(x->model), "%s", model);
    snprintf(x->id, sizeof(x->id), "%s", id);
    return x;
}

/* Against the newest record's ts (the stream's clock, not the host's):
 * sloth reports every row it keeps at least once a heartbeat, so a row
 * silent past the TTL is one sloth has evicted. */
static void age_out(web_rtl433_t *a, long long ts) {
    for (int i = 0; i < WEB_RTL433_ROWS; i++) {
        web_rtl433_row_t *x = &a->rows[i];
        if (x->used && ts - x->ts > WEB_RTL433_TTL_S) {
            x->used = 0;
            a->aged++;
        }
    }
}

static const char *const MICS[] = { "CRC", "CHECKSUM", "PARITY" };
static const char *const MODS[] = { "ASK", "FSK", "LoRa" };
static const char *const TEMP_KEYS[] = { "temperature_C", "temperature_F" };
static const char *const TEMP_UNITS[] = { "C", "F" };
static const char *const PRES_KEYS[] = { "pressure_kPa", "pressure_hPa", "pressure_psi" };
static const char *const PRES_UNITS[] = { "kPa", "hPa", "psi" };
#define NOF(x) (sizeof(x) / sizeof((x)[0]))

static void device_apply(web_rtl433_t *a, const web_jrec_t *r, long long ts) {
    const char *model = web_jl_str(r, "model"), *id = web_jl_str(r, "id");
    long long fs;
    if (!clean(model, WEB_RTL433_MODEL_MAX) || !clean(id, WEB_RTL433_ID_MAX) ||
        !jint(r, "first_seen", 0, T_MAX, &fs)) {
        a->rejected++;
        return;
    }
    web_rtl433_row_t *x = row_find(a, model, id);
    /* A new first_seen is sloth's new row for the key: start over. */
    if (x && x->first_seen != fs) { x->used = 0; x = NULL; }
    if (!x) { x = row_new(a, model, id); x->first_seen = fs; }
    long long v;
    x->ts = ts;
    x->records++;
    if (jint(r, "last_seen", 0, T_MAX, &v) && v > x->last_seen) x->last_seen = v;
    x->msgs = jint(r, "msgs", 0, 0xffffffffLL, &v) ? v : 0;
    x->other_keys = jint(r, "other_keys", 0, 1LL << 50, &v) ? v : 0;
    /* Each record is sloth's whole row (its merge is sticky), so a field
     * absent here is absent on the row, not kept from an older record. */
    jtext(r, "dev_type", WEB_RTL433_TYPE_MAX, x->dev_type);
    jtext(r, "subtype", WEB_RTL433_TYPE_MAX, x->subtype);
    jtext(r, "channel", WEB_RTL433_ID_MAX, x->channel);
    jword(r, "mic", MICS, NOF(MICS), x->mic, sizeof(x->mic));
    jword(r, "mod", MODS, NOF(MODS), x->mod, sizeof(x->mod));
    x->protocol = jint(r, "protocol", 0, 65535, &v) ? (int)v : -1;
    x->has_freq = jnum(r, "freq_mhz", 0.001, 6000, &x->freq_mhz);
    x->has_freq2 = jnum(r, "freq2_mhz", 0.001, 6000, &x->freq2_mhz);
    x->has_rssi = jnum(r, "rssi", -200, 200, &x->rssi);
    x->has_snr = jnum(r, "snr", -200, 200, &x->snr);
    x->has_noise = jnum(r, "noise", -200, 200, &x->noise);
    x->has_battery = jnum(r, "battery_ok", 0, 1, &x->battery_ok);
    x->has_humidity = jnum(r, "humidity", 0, 100, &x->humidity);
    /* -273.2, not sloth's -273.15: sloth accepts -273.15 and writes it
     * to 1 dp rounding the magnitude half up, as -273.2 (#208 review). */
    x->has_temp = junit(r, TEMP_KEYS, TEMP_UNITS, NOF(TEMP_KEYS), -273.2, 1000,
                        &x->temp, x->temp_unit, sizeof(x->temp_unit));
    x->has_pressure = junit(r, PRES_KEYS, PRES_UNITS, NOF(PRES_KEYS), 0, 1000000,
                            &x->pressure, x->pres_unit, sizeof(x->pres_unit));
    const char *src = web_jl_str(r, "src");
    if (clean(src, WEB_RTL433_SRC_MAX)) snprintf(a->src, sizeof(a->src), "%s", src);
}

/* sloth's rtl433_reject_name() order; the sensor_health keys are
 * rtl433_rej_<name>. */
static const char *const REJ[WEB_RTL433_REJ_COUNT] = {
    "oversize", "not_object", "malformed", "no_model", "no_id"
};

static void sh_apply(web_rtl433_t *a, const web_jrec_t *r, long long ts) {
    /* sloth writes the block on every sensor_health while --rtl433 is
     * set and on none without it, so a sensor_health without it is a
     * sloth with no decoder (restarted without the flag): the block is
     * cleared and the tab says "no decoder", not the old state. */
    if (!web_jl_get(r, "rtl433_state")) {
        memset(&a->sh, 0, sizeof(a->sh));
        return;
    }
    web_rtl433_sh_t h;
    memset(&h, 0, sizeof(h));
    h.seen = 1;
    h.ts = ts;
    static const char *const STATES[] = { "none", "waiting", "live", "error" };
    jword(r, "rtl433_state", STATES, NOF(STATES), h.state, sizeof(h.state));
    if (!h.state[0]) snprintf(h.state, sizeof(h.state), "other");
    jtext(r, "rtl433_src", WEB_RTL433_SRC_MAX, h.src);
    long long v;
    h.missing = jint(r, "rtl433_missing", 0, 1, &v) && v == 1;
    h.devices = jint(r, "rtl433_devices", 0, 100000, &v) ? v : 0;
#define C(name, field) h.field = jint(r, name, 0, T_MAX, &v) ? v : 0
    C("rtl433_last_read", last_read);
    C("rtl433_last_msg", last_msg);
#undef C
#define C(name, field) h.field = jint(r, name, 0, (1LL << 50), &v) ? v : 0
    C("rtl433_bytes", bytes);
    C("rtl433_lines", lines);
    C("rtl433_msgs", msgs);
    C("rtl433_bad_lines", bad_lines);
    C("rtl433_bad_values", bad_values);
    C("rtl433_other_keys", other_keys);
    C("rtl433_evicted", evicted);
    C("rtl433_truncations", truncations);
    C("rtl433_rotations", rotations);
    C("rtl433_read_errors", read_errors);
#undef C
    for (int k = 0; k < WEB_RTL433_REJ_COUNT; k++) {
        char key[32];
        snprintf(key, sizeof(key), "rtl433_rej_%s", REJ[k]);
        h.rej[k] = jint(r, key, 0, (1LL << 50), &v) ? v : 0;
    }
    jtext(r, "rtl433_err", WEB_RTL433_ERR_MAX, h.err);
    a->sh = h;
    if (!a->src[0] && h.src[0]) snprintf(a->src, sizeof(a->src), "%s", h.src);
}

void web_rtl433_record(web_rtl433_t *a, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!a || !a->rows) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&a->mu);
    if (!strcmp(t, "rtl433_device")) {
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

/* The C locale is slothweb's own (it calls no setlocale), so %f writes
 * a point. */
static void jw_num(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static int by_recent(const void *pa, const void *pb) {
    const web_rtl433_row_t *x = *(const web_rtl433_row_t *const *)pa;
    const web_rtl433_row_t *y = *(const web_rtl433_row_t *const *)pb;
    if (x->last_seen != y->last_seen) return y->last_seen > x->last_seen ? 1 : -1;
    int c = strcmp(x->model, y->model);
    return c ? c : strcmp(x->id, y->id);
}

static void row_json(web_jw_t *w, const web_rtl433_row_t *x) {
    web_jw_raw(w, "{\"model\":"); web_jw_str(w, x->model);
    web_jw_raw(w, ",\"id\":"); web_jw_str(w, x->id);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, x->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, x->last_seen);
    web_jw_raw(w, ",\"msgs\":"); web_jw_int(w, x->msgs);
    web_jw_raw(w, ",\"dev_type\":"); web_jw_str(w, x->dev_type);
    web_jw_raw(w, ",\"subtype\":"); web_jw_str(w, x->subtype);
    web_jw_raw(w, ",\"channel\":"); web_jw_str(w, x->channel);
    web_jw_raw(w, ",\"mic\":"); web_jw_str(w, x->mic);
    web_jw_raw(w, ",\"mod\":"); web_jw_str(w, x->mod);
    web_jw_raw(w, ",\"protocol\":");
    if (x->protocol >= 0) web_jw_int(w, x->protocol); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"freq_mhz\":"); jw_num(w, x->has_freq, x->freq_mhz, 3);
    web_jw_raw(w, ",\"freq2_mhz\":"); jw_num(w, x->has_freq2, x->freq2_mhz, 3);
    web_jw_raw(w, ",\"rssi\":"); jw_num(w, x->has_rssi, x->rssi, 1);
    web_jw_raw(w, ",\"snr\":"); jw_num(w, x->has_snr, x->snr, 1);
    web_jw_raw(w, ",\"noise\":"); jw_num(w, x->has_noise, x->noise, 1);
    web_jw_raw(w, ",\"battery_ok\":"); jw_num(w, x->has_battery, x->battery_ok, 1);
    web_jw_raw(w, ",\"temperature\":"); jw_num(w, x->has_temp, x->temp, 1);
    web_jw_raw(w, ",\"temp_unit\":"); web_jw_str(w, x->has_temp ? x->temp_unit : "");
    web_jw_raw(w, ",\"humidity\":"); jw_num(w, x->has_humidity, x->humidity, 1);
    web_jw_raw(w, ",\"pressure\":"); jw_num(w, x->has_pressure, x->pressure, 1);
    web_jw_raw(w, ",\"pres_unit\":"); web_jw_str(w, x->has_pressure ? x->pres_unit : "");
    web_jw_raw(w, ",\"other_keys\":"); web_jw_int(w, x->other_keys);
    web_jw_raw(w, ",\"ts\":"); web_jw_int(w, x->ts);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, x->records);
    web_jw_raw(w, "}");
}

static void sensor_json(web_jw_t *w, const web_rtl433_sh_t *h) {
    if (!h->seen) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"ts\":"); web_jw_int(w, h->ts);
    web_jw_raw(w, ",\"state\":"); web_jw_str(w, h->state);
    web_jw_raw(w, ",\"src\":"); web_jw_str(w, h->src);
    web_jw_raw(w, ",\"missing\":"); web_jw_int(w, h->missing);
    web_jw_raw(w, ",\"last_read\":"); web_jw_int(w, h->last_read);
    web_jw_raw(w, ",\"last_msg\":"); web_jw_int(w, h->last_msg);
    web_jw_raw(w, ",\"devices\":"); web_jw_int(w, h->devices);
    web_jw_raw(w, ",\"bytes\":"); web_jw_int(w, h->bytes);
    web_jw_raw(w, ",\"lines\":"); web_jw_int(w, h->lines);
    web_jw_raw(w, ",\"msgs\":"); web_jw_int(w, h->msgs);
    web_jw_raw(w, ",\"bad_lines\":"); web_jw_int(w, h->bad_lines);
    web_jw_raw(w, ",\"rej\":{");
    for (int k = 0; k < WEB_RTL433_REJ_COUNT; k++) {
        if (k) web_jw_raw(w, ",");
        web_jw_str(w, REJ[k]);
        web_jw_raw(w, ":");
        web_jw_int(w, h->rej[k]);
    }
    web_jw_raw(w, "},\"bad_values\":"); web_jw_int(w, h->bad_values);
    web_jw_raw(w, ",\"other_keys\":"); web_jw_int(w, h->other_keys);
    web_jw_raw(w, ",\"evicted\":"); web_jw_int(w, h->evicted);
    web_jw_raw(w, ",\"truncations\":"); web_jw_int(w, h->truncations);
    web_jw_raw(w, ",\"rotations\":"); web_jw_int(w, h->rotations);
    web_jw_raw(w, ",\"read_errors\":"); web_jw_int(w, h->read_errors);
    web_jw_raw(w, ",\"err\":"); web_jw_str(w, h->err);
    web_jw_raw(w, "}");
}

int web_rtl433_route(web_rtl433_t *a, const char *query, long long now_s, int none_here,
                     char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_RTL433_ROWS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_RTL433_ROWS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (!a || !a->rows) return answer_error(503, "no_rtl433", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }

    const web_rtl433_row_t **idx = malloc(WEB_RTL433_ROWS * sizeof(*idx));
    if (!idx) return -1;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&a->mu);
    int n = 0;
    for (int i = 0; i < WEB_RTL433_ROWS; i++)
        if (a->rows[i].used) idx[n++] = &a->rows[i];
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_recent);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, a->src);
    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)a->records);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)a->evictions);
    web_jw_raw(&w, ",\"aged\":"); web_jw_int(&w, (long long)a->aged);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)a->rejected);
    /* The sensor block: null until a sensor_health carried rtl433_*. */
    web_jw_raw(&w, ",\"sensor\":");
    sensor_json(&w, &a->sh);
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"devices\":[");
    int shown = 0, cut = 0;
    for (int i = 0; i < n && i < limit; i++) {
        /* Stop before a row that might not fit, leaving room to close. */
        if (w.len + WEB_RTL433_ROW_WORST + 64 > cap) { cut = 1; break; }
        if (i) web_jw_raw(&w, ",");
        row_json(&w, idx[i]);
        shown++;
    }
    web_jw_raw(&w, "],\"shown\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"cut\":"); web_jw_raw(&w, cut ? "true" : "false");
    web_jw_raw(&w, "}");
    pthread_mutex_unlock(&a->mu);
    free(idx);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_rtl433_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "rtl_433 devices are the rtl_433 decoder's (--rtl433), a passive "
                   "radio; the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

void web_rtl433_health_json(web_rtl433_t *a, web_jw_t *w) {
    if (!a || !a->rows) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&a->mu);
    int n = 0;
    for (int i = 0; i < WEB_RTL433_ROWS; i++) n += a->rows[i].used != 0;
    web_jw_raw(w, "{\"rows\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)a->records);
    web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)a->evictions);
    web_jw_raw(w, ",\"aged\":"); web_jw_int(w, (long long)a->aged);
    web_jw_raw(w, ",\"rejected\":"); web_jw_int(w, (long long)a->rejected);
    web_jw_raw(w, ",\"sensor_seen\":"); web_jw_int(w, a->sh.seen);
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&a->mu);
}
