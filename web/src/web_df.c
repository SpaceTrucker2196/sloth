#include "web_df.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"

/* Contract and bounds: web_df.h. */

int web_df_init(web_df_t *d) {
    memset(d, 0, sizeof(*d));
    return pthread_mutex_init(&d->mu, NULL) == 0 ? 0 : -1;
}

void web_df_destroy(web_df_t *d) {
    pthread_mutex_destroy(&d->mu);
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly "xx:xx:xx:xx:xx:xx", either case: the form sloth writes. */
static int mac_parse(const char *s, uint8_t out[6]) {
    if (!s || strlen(s) != 17) return -1;
    for (int i = 0; i < 6; i++) {
        int hi = hexv(s[i * 3]), lo = hexv(s[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && s[i * 3 + 2] != ':')) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

static int jint(const web_jrec_t *r, const char *k, long long lo, long long hi,
                long long *v) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *v = f->i;
    return 1;
}

/* A number within +/-lim. 1 taken, 0 absent, -1 present and refused. */
static int jreal(const web_jrec_t *r, const char *k, double lim, double *v) {
    if (!web_jl_get(r, k)) return 0;
    double x;
    if (!web_jl_num(r, k, &x) || x < -lim || x > lim) return -1;
    *v = x;
    return 1;
}

/* An interface name as sloth takes one (df_parse_spec()): 1..15 bytes,
 * printable ASCII, no space and no '/'. */
static int jiface(const web_jrec_t *r, const char *k, char *out) {
    const char *s = web_jl_str(r, k);
    if (!s) return 0;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_DF_IFACE_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= ' ' || c == '/' || c >= 0x7F) return 0;
    }
    memcpy(out, s, n + 1);
    return 1;
}

/* sensor_health's "MAJOR.MINOR.PATCH", each 1..4 digits. */
static int ver_parse(const char *s, int v[3]) {
    if (!s) return -1;
    for (int i = 0; i < 3; i++) {
        int n = 0, dg = 0;
        while (*s >= '0' && *s <= '9' && dg < 4) { n = n * 10 + (*s++ - '0'); dg++; }
        if (!dg || (i < 2 && *s++ != '.')) return -1;
        v[i] = n;
    }
    return *s ? -1 : 0;
}

/* 0 and *t filled, or -1. */
static int radio_parse(const web_jrec_t *r, web_df_radio_t *t, long long *idx) {
    const char *role = web_jl_str(r, "role");
    if (!jint(r, "radio", 0, WEB_DF_RADIOS - 1, idx)) return -1;
    if (!jint(r, "ts", 0, 100000000000LL, &t->ts)) return -1;
    if (!jiface(r, "iface", t->iface)) return -1;
    if (!role) return -1;
    if (!strcmp(role, "sensor")) t->sensor = 1;
    else if (strcmp(role, "df")) return -1;
    /* Radio 0 is the sensor radio and no other is. */
    if (t->sensor != (*idx == 0)) return -1;
    if (!jint(r, "open", 0, 1, &t->open) || !jint(r, "running", 0, 1, &t->running) ||
        !jint(r, "noted", 0, WEB_DF_COUNT_MAX, &t->noted)) return -1;
    int e = jreal(r, "pos_m", WEB_DF_POS_MAX, &t->pos_m);
    if (e < 0) return -1;
    t->has_pos = e;
    /* A place in two dimensions (2.4.0): both numbers or neither, and
     * not beside a place on the baseline. */
    int ex = jreal(r, "x_m", WEB_DF_POS_MAX, &t->x_m);
    int ey = jreal(r, "y_m", WEB_DF_POS_MAX, &t->y_m);
    if (ex < 0 || ey < 0 || ex != ey || (ex && t->has_pos)) return -1;
    t->has_xy = ex;
    e = jreal(r, "bias_db", WEB_DF_DB_MAX, &t->bias_db);
    if (e < 0) return -1;
    t->has_bias = e;
    /* The three counters come together or not at all. */
    int a = web_jl_get(r, "frames") != NULL, b = web_jl_get(r, "rejects") != NULL,
        c = web_jl_get(r, "retune_failures") != NULL;
    if (a != b || b != c) return -1;
    if (a) {
        if (!jint(r, "frames", 0, WEB_DF_COUNT_MAX, &t->frames) ||
            !jint(r, "rejects", 0, WEB_DF_COUNT_MAX, &t->rejects) ||
            !jint(r, "retune_failures", 0, WEB_DF_COUNT_MAX, &t->retune_failures)) return -1;
        t->has_aux = 1;
    }
    return 0;
}

static int em_parse(const web_jrec_t *r, web_df_em_t *t) {
    const char *q = web_jl_str(r, "quality");
    if (mac_parse(web_jl_str(r, "mac"), t->mac) != 0 || !q) return -1;
    if (!strcmp(q, "lean")) t->quality = WEB_DF_Q_LEAN;
    else if (!strcmp(q, "weak")) t->quality = WEB_DF_Q_WEAK;
    else if (!strcmp(q, "none")) t->quality = WEB_DF_Q_NONE;
    else return -1;
    if (!jint(r, "ts", 0, 100000000000LL, &t->ts) ||
        !jint(r, "channel", 0, 1000, &t->channel) ||
        !jint(r, "heard_by", 0, WEB_DF_RADIOS, &t->heard_by) ||
        !jint(r, "best_radio", -1, WEB_DF_RADIOS - 1, &t->best_radio) ||
        !jint(r, "last_seen", 0, 100000000000LL, &t->last_seen)) return -1;
    if (web_jl_get(r, "best_iface") && !jiface(r, "best_iface", t->best_iface)) return -1;
    if (jreal(r, "margin_db", WEB_DF_DB_MAX, &t->margin_db) != 1 || t->margin_db < 0) return -1;
    int e = jreal(r, "along_m", WEB_DF_POS_MAX, &t->along_m);
    if (e < 0) return -1;
    t->has_along = e;
    /* The bearing (2.4.0): a compass point and its error, as sloth
     * writes them (src/df.h), together, and never beside along_m. */
    int a = web_jl_get(r, "bearing_deg") != NULL, b = web_jl_get(r, "bearing_err_deg") != NULL;
    if (a != b) return -1;
    if (a) {
        if (t->has_along ||
            !jint(r, "bearing_deg", 0, 315, &t->bearing_deg) || t->bearing_deg % 45 ||
            !jint(r, "bearing_err_deg", 15, 45, &t->bearing_err_deg) ||
            t->bearing_err_deg % 15) return -1;
        t->has_bearing = 1;
    }
    return 0;
}

void web_df_record(web_df_t *d, const web_jrec_t *r, long long now_ms) {
    const char *ty = web_jl_str(r, "type");
    if (!d || !ty) return;
    if (!strcmp(ty, "sensor_health")) {
        int v[3] = { 0, 0, 0 };
        const char *s = web_jl_str(r, "jsonl_version");
        /* No member: a stream from before 1.0.0. A malformed one says
         * nothing and is ignored. */
        if (s && ver_parse(s, v) != 0) return;
        pthread_mutex_lock(&d->mu);
        d->ver_seen = 1;
        memcpy(d->ver, v, sizeof(v));
        pthread_mutex_unlock(&d->mu);
        return;
    }
    if (!strcmp(ty, "df_radio")) {
        web_df_radio_t t;
        long long idx = 0;
        memset(&t, 0, sizeof(t));
        int bad = radio_parse(r, &t, &idx);
        pthread_mutex_lock(&d->mu);
        d->records++;
        if (bad) d->rejected++;
        else {
            t.used = 1;
            t.rx_ms = now_ms;
            d->radio[idx] = t;
        }
        pthread_mutex_unlock(&d->mu);
        return;
    }
    if (strcmp(ty, "wifi_df")) return;
    web_df_em_t t;
    memset(&t, 0, sizeof(t));
    int bad = em_parse(r, &t);
    pthread_mutex_lock(&d->mu);
    d->records++;
    if (bad) {
        d->rejected++;
        pthread_mutex_unlock(&d->mu);
        return;
    }
    web_df_em_t *dst = NULL, *spare = NULL, *oldest = NULL;
    for (int i = 0; i < WEB_DF_EMITTERS; i++) {
        web_df_em_t *x = &d->em[i];
        if (!x->used) { if (!spare) spare = x; continue; }
        if (!memcmp(x->mac, t.mac, 6)) { dst = x; break; }
        if (!oldest || x->rx_ms < oldest->rx_ms) oldest = x;
    }
    if (!dst) dst = spare;
    if (!dst) {
        /* Full: the row written longest ago gives way (web_df.h). */
        dst = oldest;
        if (now_ms - oldest->rx_ms <= WEB_DF_STALE_MS) d->evicted++;
    }
    t.used = 1;
    t.rx_ms = now_ms;
    *dst = t;
    pthread_mutex_unlock(&d->mu);
}

int web_df_reported(web_df_t *d) {
    if (!d) return -1;
    pthread_mutex_lock(&d->mu);
    int ans = !d->ver_seen ? -1
            : (d->ver[0] > 2 || (d->ver[0] == 2 && d->ver[1] >= 2));
    pthread_mutex_unlock(&d->mu);
    return ans;
}

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *status_out) {
    *status_out = status;
    *len = web_series_error_json(reason, body, cap);
    return *len ? 0 : -1;
}

static void mac_jw(web_jw_t *w, const uint8_t m[6]) {
    static const char hx[] = "0123456789abcdef";
    char s[18];
    for (int i = 0; i < 6; i++) {
        s[i * 3] = hx[m[i] >> 4];
        s[i * 3 + 1] = hx[m[i] & 15];
        s[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
    web_jw_str(w, s);
}

static void kv(web_jw_t *w, const char *k, long long v) {
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    web_jw_int(w, v);
}

/* A value the parser bounded, so "%.2f" is at most eight bytes. */
static void kreal(web_jw_t *w, const char *k, double v) {
    char s[32];
    snprintf(s, sizeof(s), "%.2f", v);
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    web_jw_raw(w, s);
}

static void kbool(web_jw_t *w, const char *k, long long v) {
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    web_jw_raw(w, v ? "true" : "false");
}

static const char *quality_name(int q) {
    return q == WEB_DF_Q_LEAN ? "lean" : q == WEB_DF_Q_WEAK ? "weak" : "none";
}

/* `lean` before `weak`, the widest margin first, then the address. */
static int cmp_em(const void *a, const void *b) {
    const web_df_em_t *x = *(const web_df_em_t *const *)a;
    const web_df_em_t *y = *(const web_df_em_t *const *)b;
    if (x->quality != y->quality) return x->quality > y->quality ? -1 : 1;
    if (x->margin_db != y->margin_db) return x->margin_db > y->margin_db ? -1 : 1;
    return memcmp(x->mac, y->mac, 6);
}

int web_df_route(web_df_t *d, const char *query, long long now_s,
                 long long now_ms, int none_here, char *body, size_t cap,
                 size_t *len, int *status) {
    char err[48];
    if (web_params_parse(query, NULL, 0, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    if (!d) return answer_error(503, "no_df", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }
    int reported = web_df_reported(d);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&d->mu);
    web_jw_raw(&w, "{\"now\":");
    web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"reported\":");
    web_jw_raw(&w, reported < 0 ? "null" : reported ? "true" : "false");
    web_jw_raw(&w, ",\"jsonl_version\":");
    if (d->ver_seen && (d->ver[0] || d->ver[1] || d->ver[2])) {
        char v[16];
        snprintf(v, sizeof(v), "%d.%d.%d", d->ver[0], d->ver[1], d->ver[2]);
        web_jw_str(&w, v);
    } else {
        web_jw_raw(&w, "null");
    }
    int stale = 0, first = 1;
    web_jw_raw(&w, ",\"radios\":[");
    for (int i = 0; i < WEB_DF_RADIOS; i++) {
        const web_df_radio_t *x = &d->radio[i];
        if (!x->used) continue;
        if (now_ms - x->rx_ms > WEB_DF_STALE_MS) { stale++; continue; }
        web_jw_raw(&w, first ? "{\"radio\":" : ",{\"radio\":");
        first = 0;
        web_jw_int(&w, i);
        web_jw_raw(&w, ",\"iface\":");
        web_jw_str(&w, x->iface);
        web_jw_raw(&w, ",\"role\":");
        web_jw_str(&w, x->sensor ? "sensor" : "df");
        if (x->has_pos) kreal(&w, "pos_m", x->pos_m);
        if (x->has_xy) { kreal(&w, "x_m", x->x_m); kreal(&w, "y_m", x->y_m); }
        kbool(&w, "open", x->open);
        kbool(&w, "running", x->running);
        kv(&w, "noted", x->noted);
        if (x->has_bias) kreal(&w, "bias_db", x->bias_db);
        if (x->has_aux) {
            kv(&w, "frames", x->frames);
            kv(&w, "rejects", x->rejects);
            kv(&w, "retune_failures", x->retune_failures);
        }
        kv(&w, "ts", x->ts);
        kv(&w, "age_s", (now_ms - x->rx_ms) / 1000);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"emitters\":[");
    const web_df_em_t *idx[WEB_DF_EMITTERS];
    int m = 0;
    for (int i = 0; i < WEB_DF_EMITTERS; i++) {
        const web_df_em_t *x = &d->em[i];
        if (!x->used) continue;
        if (now_ms - x->rx_ms > WEB_DF_STALE_MS) { stale++; continue; }
        idx[m++] = x;
    }
    if (m > 1) qsort(idx, (size_t)m, sizeof(idx[0]), cmp_em);
    for (int i = 0; i < m && i < WEB_DF_OUT; i++) {
        const web_df_em_t *x = idx[i];
        web_jw_raw(&w, i ? ",{\"mac\":" : "{\"mac\":");
        mac_jw(&w, x->mac);
        kv(&w, "channel", x->channel);
        kv(&w, "heard_by", x->heard_by);
        web_jw_raw(&w, ",\"quality\":");
        web_jw_str(&w, quality_name(x->quality));
        kv(&w, "best_radio", x->best_radio);
        if (x->best_iface[0]) {
            web_jw_raw(&w, ",\"best_iface\":");
            web_jw_str(&w, x->best_iface);
        }
        kreal(&w, "margin_db", x->margin_db);
        if (x->has_along) kreal(&w, "along_m", x->along_m);
        if (x->has_bearing) {
            kv(&w, "bearing_deg", x->bearing_deg);
            kv(&w, "bearing_err_deg", x->bearing_err_deg);
        }
        kv(&w, "last_seen", x->last_seen);
        kv(&w, "age_s", (now_ms - x->rx_ms) / 1000);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "]");
    kv(&w, "held", m);
    kv(&w, "stale", stale);
    kv(&w, "records", (long long)d->records);
    kv(&w, "rejected", (long long)d->rejected);
    kv(&w, "evicted", (long long)d->evicted);
    web_jw_raw(&w, "}\n");
    pthread_mutex_unlock(&d->mu);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_df_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "direction finding is the passive monitor radios'; "
                   "the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}
