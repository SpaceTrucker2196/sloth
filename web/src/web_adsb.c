#include "web_adsb.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_live.h"
#include "web_series.h"

/* ── lifecycle ──────────────────────────────────────────────────────── */

int web_adsb_init(web_adsb_t *a) {
    memset(a, 0, sizeof(*a));
    a->rows = calloc(WEB_ADSB_ROWS, sizeof(*a->rows));
    if (!a->rows) return -1;
    pthread_mutex_init(&a->mu, NULL);
    return 0;
}

void web_adsb_destroy(web_adsb_t *a) {
    if (!a->rows) return;
    pthread_mutex_destroy(&a->mu);
    free(a->rows);
    a->rows = NULL;
}

/* sloth's words (src/adsb.c k_emerg); web/tests/test_adsb.c ::
 * test_adsb_vocabulary_is_sloths holds the two together. */
static const char *const EMERG[WEB_ADSB_EMERG_COUNT] = {
    "none", "general", "lifeguard", "minfuel", "nordo", "unlawful",
    "downed", "reserved"
};

const char *web_adsb_emergency_name(int e) {
    return (e >= 0 && e < WEB_ADSB_EMERG_COUNT) ? EMERG[e] : "";
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

/* A string member of at most max octets, each one ok() accepts,
 * copied into out (cap max + 1); else out is "". */
static void jstr(const web_jrec_t *r, const char *k, size_t max, int (*ok)(int),
                 char *out) {
    out[0] = '\0';
    const char *s = web_jl_str(r, k);
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > max) return;
    for (size_t i = 0; i < n; i++)
        if (!ok((unsigned char)s[i])) return;
    memcpy(out, s, n + 1);
}

static int ok_print(int c) { return c >= 0x20 && c <= 0x7e; }
static int ok_label(int c) { return c >= 0x21 && c <= 0x7e; }
static int ok_type(int c) { return (c >= 'a' && c <= 'z') || c == '_'; }
static int ok_octal(int c) { return c >= '0' && c <= '7'; }
static int ok_hexd(int c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }

/* `~`? and six lower-case hex digits: sloth's own "%s%06x". */
static int hex_ok(const char *s) {
    if (!s) return 0;
    if (*s == '~') s++;
    for (int i = 0; i < 6; i++)
        if (!ok_hexd((unsigned char)s[i])) return 0;
    return s[6] == '\0';
}

/* ── the table ──────────────────────────────────────────────────────── */

static web_adsb_row_t *row_slot(web_adsb_t *a, const char *hex) {
    web_adsb_row_t *lru = NULL, *fr = NULL;
    for (int i = 0; i < WEB_ADSB_ROWS; i++) {
        web_adsb_row_t *x = &a->rows[i];
        if (!x->used) { if (!fr) fr = x; continue; }
        if (!strcmp(x->hex, hex)) return x;
        if (!lru || x->ts < lru->ts) lru = x;
    }
    if (fr) { memset(fr, 0, sizeof(*fr)); return fr; }
    a->evictions++;
    memset(lru, 0, sizeof(*lru));
    return lru;
}

/* Against the newest record's ts (the stream's clock, not the host's):
 * a gone row kept long enough, and a live row whose gone record never
 * came. */
static void age_out(web_adsb_t *a, long long ts) {
    for (int i = 0; i < WEB_ADSB_ROWS; i++) {
        web_adsb_row_t *x = &a->rows[i];
        if (!x->used) continue;
        if (x->gone ? ts - x->gone_ts > WEB_ADSB_GONE_TTL_S
                    : ts - x->ts > WEB_ADSB_TTL_S) {
            x->used = 0;
            if (!x->gone) a->aged++;
        }
    }
}

static void take_src(char *dst, const char *s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_ADSB_SRC_MAX) return;
    for (size_t i = 0; i < n; i++)
        if (!ok_label((unsigned char)s[i])) return;
    memcpy(dst, s, n + 1);
}

static void row_apply(web_adsb_t *a, const web_jrec_t *r, long long ts) {
    const char *hex = web_jl_str(r, "hex");
    const char *st = web_jl_str(r, "state");
    if (!hex_ok(hex) || !st || (strcmp(st, "live") && strcmp(st, "gone"))) {
        a->rejected++;
        return;
    }
    web_adsb_row_t *x = row_slot(a, hex);
    /* The track and the record count carry over while sloth's
     * first_seen is the row's: a row that expired and came back is a
     * new sighting with a new first_seen, and starts afresh. */
    web_adsb_row_t keep = *x;
    memset(x, 0, sizeof(*x));
    x->used = 1;
    snprintf(x->hex, sizeof(x->hex), "%s", hex);
    x->non_icao = hex[0] == '~';
    x->gone = !strcmp(st, "gone");
    x->gone_ts = x->gone ? ts : 0;
    jstr(r, "source_type", sizeof(x->source_type) - 1, ok_type, x->source_type);
    jstr(r, "flight", 8, ok_print, x->flight);
    jstr(r, "squawk", 4, ok_octal, x->squawk);
    if (strlen(x->squawk) != 4) x->squawk[0] = '\0';
    const char *cat = web_jl_str(r, "category");
    if (cat && cat[0] >= 'A' && cat[0] <= 'D' && cat[1] >= '0' && cat[1] <= '7' && !cat[2])
        snprintf(x->category, sizeof(x->category), "%s", cat);
    x->emergency = -1;
    const char *em = web_jl_str(r, "emergency");
    for (int i = 0; em && i < WEB_ADSB_EMERG_COUNT; i++)
        if (!strcmp(em, EMERG[i])) x->emergency = i;
    long long v;
    x->on_ground = jint(r, "on_ground", 0, 1, &v) && v == 1;
    /* Mode S altitude reaches 126,700 ft (25 ft quanta); a bound just
     * past it keeps every real one. */
    if ((x->has_alt_baro = jint(r, "alt_baro", -2000, 130000, &v))) x->alt_baro = (int)v;
    if ((x->has_alt_geom = jint(r, "alt_geom", -2000, 130000, &v))) x->alt_geom = (int)v;
    x->alt_band = jint(r, "alt_band", -2, 40, &v) ? (int)v : -1;
    x->has_gs = jnum(r, "gs", 0, 4000, &x->gs);
    x->has_track = jnum(r, "track", 0, 360, &x->track);
    if ((x->has_baro_rate = jint(r, "baro_rate", -65536, 65536, &v))) x->baro_rate = (int)v;
    if ((x->has_geom_rate = jint(r, "geom_rate", -65536, 65536, &v))) x->geom_rate = (int)v;
    double lat = 0.0, lon = 0.0;
    if (jnum(r, "lat", -90, 90, &lat) && jnum(r, "lon", -180, 180, &lon)) {
        x->has_pos = 1; x->lat = lat; x->lon = lon;
        x->pos_ts = jint(r, "pos_ts", 0, (1LL << 40), &v) ? v : 0;
    }
    x->has_rssi = jnum(r, "rssi", -100, 10, &x->rssi);
    x->messages = jint(r, "messages", 0, (1LL << 50), &v) ? v : -1;
    x->first_seen = jint(r, "first_seen", 0, (1LL << 40), &v) ? v : 0;
    x->last_seen = jint(r, "last_seen", 0, (1LL << 40), &v) ? v : 0;
    x->ts = ts;
    int same = keep.used && keep.first_seen == x->first_seen;
    x->records = same ? keep.records + 1 : 1;
    if (same) {
        x->npts = keep.npts;
        x->phead = keep.phead;
        memcpy(x->pts_ts, keep.pts_ts, sizeof(x->pts_ts));
        memcpy(x->pts_lat, keep.pts_lat, sizeof(x->pts_lat));
        memcpy(x->pts_lon, keep.pts_lon, sizeof(x->pts_lon));
        memcpy(x->pts_alt, keep.pts_alt, sizeof(x->pts_alt));
    }
    if (x->has_pos) {
        int prev = (x->phead + WEB_ADSB_PTS - 1) % WEB_ADSB_PTS;
        if (!x->npts || x->pts_lat[prev] != (float)lat || x->pts_lon[prev] != (float)lon) {
            x->pts_ts[x->phead] = x->pos_ts ? x->pos_ts : ts;
            x->pts_lat[x->phead] = (float)lat;
            x->pts_lon[x->phead] = (float)lon;
            x->pts_alt[x->phead] = x->on_ground ? -1
                                 : x->has_alt_baro ? x->alt_baro
                                 : x->has_alt_geom ? x->alt_geom : INT32_MIN;
            x->phead = (x->phead + 1) % WEB_ADSB_PTS;
            if (x->npts < WEB_ADSB_PTS) x->npts++;
        }
    }
    take_src(a->src, web_jl_str(r, "src"));
}

static void sh_apply(web_adsb_t *a, const web_jrec_t *r, long long ts) {
    /* Only a sensor_health carrying the block: a sloth with no --adsb
     * writes none of it, and the panel then says "no decoder". */
    if (!web_jl_get(r, "adsb_state")) return;
    web_adsb_sh_t h;
    memset(&h, 0, sizeof(h));
    h.seen = 1;
    h.ts = ts;
    const char *st = web_jl_str(r, "adsb_state");
    static const char *const STATES[] = { "waiting", "live", "stale", "error" };
    snprintf(h.state, sizeof(h.state), "other");
    for (size_t i = 0; st && i < sizeof(STATES) / sizeof(STATES[0]); i++)
        if (!strcmp(st, STATES[i])) snprintf(h.state, sizeof(h.state), "%s", STATES[i]);
    take_src(h.src, web_jl_str(r, "adsb_src"));
    long long v;
    h.age_s = jint(r, "adsb_age_s", -1, (1LL << 40), &v) ? v : -1;
    h.last_read = jint(r, "adsb_last_read", 0, (1LL << 40), &v) ? v : 0;
    h.aircraft = jint(r, "adsb_aircraft", 0, 100000, &v) ? v : 0;
    h.messages = jint(r, "adsb_messages", 0, (1LL << 50), &v) ? v : 0;
    h.reads = jint(r, "adsb_reads", 0, (1LL << 50), &v) ? v : 0;
    h.read_errors = jint(r, "adsb_read_errors", 0, (1LL << 50), &v) ? v : 0;
    h.parse_errors = jint(r, "adsb_parse_errors", 0, (1LL << 50), &v) ? v : 0;
    h.overflow = jint(r, "adsb_overflow", 0, (1LL << 50), &v) ? v : 0;
    h.bad_entries = jint(r, "adsb_bad_entries", 0, (1LL << 50), &v) ? v : 0;
    h.expired = jint(r, "adsb_expired", 0, (1LL << 50), &v) ? v : 0;
    jstr(r, "adsb_err", WEB_ADSB_ERR_MAX, ok_print, h.err);
    a->sh = h;
    if (!a->src[0]) take_src(a->src, h.src);
}

void web_adsb_record(web_adsb_t *a, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!a || !a->rows) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&a->mu);
    if (!strcmp(t, "adsb_aircraft")) { a->records++; row_apply(a, r, ts); age_out(a, ts); }
    else if (!strcmp(t, "sensor_health")) { sh_apply(a, r, ts); age_out(a, ts); }
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

static void jw_int_or_null(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

static int emerg_now(const web_adsb_row_t *x) { return x->emergency > 0 && !x->gone; }

static int by_interest(const void *pa, const void *pb) {
    const web_adsb_row_t *x = *(const web_adsb_row_t *const *)pa;
    const web_adsb_row_t *y = *(const web_adsb_row_t *const *)pb;
    if (emerg_now(x) != emerg_now(y)) return emerg_now(y) - emerg_now(x);
    if (x->gone != y->gone) return x->gone - y->gone;
    if (x->last_seen != y->last_seen) return y->last_seen > x->last_seen ? 1 : -1;
    return strcmp(x->hex, y->hex);
}

int web_adsb_alerts(struct web_live_s *l, web_adsb_alert_t *out, int max) {
    if (!l || max <= 0) return 0;
    web_live_inc_t *inc = calloc(WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, sizeof(*inc));
    if (!inc) return 0;
    int nopen = 0, n = 0;
    web_live_incidents(l, inc, WEB_LIVE_INCIDENTS + WEB_LIVE_CLOSED, &nopen);
    for (int i = 0; i < nopen && n < max; i++) {
        const web_live_inc_t *e = &inc[i];
        const web_akb_t *k = web_akb_get(e->type);
        if (!k || strcmp(k->name, "ADSB_EMERGENCY") || !e->hid[0]) continue;
        /* adsbemerg:<6 hex>:<icao|nonicao>: - anything else is not a
         * key this rule wrote, and names no row. */
        const char *p = e->key;
        if (strncmp(p, "adsbemerg:", 10)) continue;
        p += 10;
        char hx[7];
        int ok = 1;
        for (int j = 0; j < 6; j++) {
            if (!ok_hexd((unsigned char)p[j])) { ok = 0; break; }
            hx[j] = p[j];
        }
        hx[6] = '\0';
        if (!ok || p[6] != ':') continue;
        p += 7;
        int non_icao;
        if (!strncmp(p, "icao:", 5)) non_icao = 0;
        else if (!strncmp(p, "nonicao:", 8)) non_icao = 1;
        else continue;
        web_adsb_alert_t *o = &out[n++];
        snprintf(o->hex, sizeof(o->hex), "%s%s", non_icao ? "~" : "", hx);
        snprintf(o->id, sizeof(o->id), "s%s", e->hid);
        o->sev = e->sev < 0 ? 0 : e->sev > 2 ? 2 : e->sev;
    }
    free(inc);
    return n;
}

static void row_json(web_jw_t *w, const web_adsb_row_t *x,
                     const web_adsb_alert_t *al, int nal) {
    web_jw_raw(w, "{\"hex\":"); web_jw_str(w, x->hex);
    web_jw_raw(w, ",\"non_icao\":"); web_jw_int(w, x->non_icao);
    web_jw_raw(w, ",\"state\":"); web_jw_str(w, x->gone ? "gone" : "live");
    web_jw_raw(w, ",\"source_type\":"); web_jw_str(w, x->source_type);
    web_jw_raw(w, ",\"flight\":"); web_jw_str(w, x->flight);
    web_jw_raw(w, ",\"squawk\":"); web_jw_str(w, x->squawk);
    web_jw_raw(w, ",\"category\":"); web_jw_str(w, x->category);
    web_jw_raw(w, ",\"emergency\":"); web_jw_str(w, web_adsb_emergency_name(x->emergency));
    web_jw_raw(w, ",\"on_ground\":"); web_jw_int(w, x->on_ground);
    web_jw_raw(w, ",\"alt_baro\":"); jw_int_or_null(w, x->has_alt_baro, x->alt_baro);
    web_jw_raw(w, ",\"alt_geom\":"); jw_int_or_null(w, x->has_alt_geom, x->alt_geom);
    web_jw_raw(w, ",\"alt_band\":"); web_jw_int(w, x->alt_band);
    web_jw_raw(w, ",\"gs\":"); jw_num(w, x->has_gs, x->gs, 1);
    web_jw_raw(w, ",\"track\":"); jw_num(w, x->has_track, x->track, 1);
    web_jw_raw(w, ",\"baro_rate\":"); jw_int_or_null(w, x->has_baro_rate, x->baro_rate);
    web_jw_raw(w, ",\"geom_rate\":"); jw_int_or_null(w, x->has_geom_rate, x->geom_rate);
    web_jw_raw(w, ",\"lat\":"); jw_num(w, x->has_pos, x->lat, 5);
    web_jw_raw(w, ",\"lon\":"); jw_num(w, x->has_pos, x->lon, 5);
    web_jw_raw(w, ",\"pos_ts\":"); jw_int_or_null(w, x->has_pos && x->pos_ts, x->pos_ts);
    web_jw_raw(w, ",\"rssi\":"); jw_num(w, x->has_rssi, x->rssi, 1);
    web_jw_raw(w, ",\"messages\":"); jw_int_or_null(w, x->messages >= 0, x->messages);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, x->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, x->last_seen);
    web_jw_raw(w, ",\"ts\":"); web_jw_int(w, x->ts);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, x->records);
    /* The open ADSB_EMERGENCY incident naming this address, the page's
     * way to its alert (#186); null with none. */
    web_jw_raw(w, ",\"alert\":");
    const web_adsb_alert_t *hit = NULL;
    for (int j = 0; al && j < nal && !hit; j++)
        if (!strcmp(al[j].hex, x->hex)) hit = &al[j];
    if (hit) {
        web_jw_raw(w, "{\"id\":"); web_jw_str(w, hit->id);
        web_jw_raw(w, ",\"sev\":"); web_jw_int(w, hit->sev);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    /* Oldest first: [ts, lat, lon, alt] with alt null unknown, -1 on
     * the ground. */
    web_jw_raw(w, ",\"track_pts\":[");
    int start = (x->phead + WEB_ADSB_PTS - x->npts) % WEB_ADSB_PTS;
    for (int j = 0; j < x->npts; j++) {
        int at = (start + j) % WEB_ADSB_PTS;
        if (j) web_jw_raw(w, ",");
        web_jw_raw(w, "["); web_jw_int(w, x->pts_ts[at]);
        web_jw_raw(w, ","); jw_num(w, 1, x->pts_lat[at], 5);
        web_jw_raw(w, ","); jw_num(w, 1, x->pts_lon[at], 5);
        web_jw_raw(w, ","); jw_int_or_null(w, x->pts_alt[at] != INT32_MIN, x->pts_alt[at]);
        web_jw_raw(w, "]");
    }
    web_jw_raw(w, "]}");
}

int web_adsb_route(web_adsb_t *a, const char *query, long long now_s, int none_here,
                   const web_adsb_alert_t *al, int nal,
                   char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_ADSB_ROWS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_ADSB_ROWS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (!a || !a->rows) return answer_error(503, "no_adsb", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }

    const web_adsb_row_t **idx = malloc(WEB_ADSB_ROWS * sizeof(*idx));
    if (!idx) return -1;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&a->mu);
    int n = 0, live = 0, pos = 0, emerg = 0;
    for (int i = 0; i < WEB_ADSB_ROWS; i++) {
        const web_adsb_row_t *x = &a->rows[i];
        if (!x->used) continue;
        idx[n++] = x;
        live += !x->gone;
        pos += !x->gone && x->has_pos;
        emerg += emerg_now(x);
    }
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_interest);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, a->src);
    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)a->records);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)a->evictions);
    web_jw_raw(&w, ",\"aged\":"); web_jw_int(&w, (long long)a->aged);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)a->rejected);
    /* The sensor block: null until a sensor_health carried adsb_*. */
    web_jw_raw(&w, ",\"sensor\":");
    if (a->sh.seen) {
        const web_adsb_sh_t *h = &a->sh;
        web_jw_raw(&w, "{\"ts\":"); web_jw_int(&w, h->ts);
        web_jw_raw(&w, ",\"state\":"); web_jw_str(&w, h->state);
        web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, h->src);
        web_jw_raw(&w, ",\"age_s\":"); jw_int_or_null(&w, h->age_s >= 0, h->age_s);
        web_jw_raw(&w, ",\"last_read\":"); web_jw_int(&w, h->last_read);
        web_jw_raw(&w, ",\"aircraft\":"); web_jw_int(&w, h->aircraft);
        web_jw_raw(&w, ",\"messages\":"); web_jw_int(&w, h->messages);
        web_jw_raw(&w, ",\"reads\":"); web_jw_int(&w, h->reads);
        web_jw_raw(&w, ",\"read_errors\":"); web_jw_int(&w, h->read_errors);
        web_jw_raw(&w, ",\"parse_errors\":"); web_jw_int(&w, h->parse_errors);
        web_jw_raw(&w, ",\"overflow\":"); web_jw_int(&w, h->overflow);
        web_jw_raw(&w, ",\"bad_entries\":"); web_jw_int(&w, h->bad_entries);
        web_jw_raw(&w, ",\"expired\":"); web_jw_int(&w, h->expired);
        web_jw_raw(&w, ",\"err\":"); web_jw_str(&w, h->err);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"live\":"); web_jw_int(&w, live);
    web_jw_raw(&w, ",\"with_pos\":"); web_jw_int(&w, pos);
    web_jw_raw(&w, ",\"emergency\":"); web_jw_int(&w, emerg);
    web_jw_raw(&w, ",\"rows\":[");
    for (int i = 0; i < n && i < limit; i++) {
        if (i) web_jw_raw(&w, ",");
        row_json(&w, idx[i], al, nal);
    }
    web_jw_raw(&w, "]}");
    pthread_mutex_unlock(&a->mu);
    free(idx);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_adsb_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "aircraft are the ADS-B decoder's (--adsb), a passive "
                   "radio; the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

void web_adsb_health_json(web_adsb_t *a, web_jw_t *w) {
    if (!a || !a->rows) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&a->mu);
    int n = 0, live = 0;
    for (int i = 0; i < WEB_ADSB_ROWS; i++) {
        n += a->rows[i].used != 0;
        live += a->rows[i].used && !a->rows[i].gone;
    }
    web_jw_raw(w, "{\"rows\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"live\":"); web_jw_int(w, live);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)a->records);
    web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)a->evictions);
    web_jw_raw(w, ",\"aged\":"); web_jw_int(w, (long long)a->aged);
    web_jw_raw(w, ",\"rejected\":"); web_jw_int(w, (long long)a->rejected);
    web_jw_raw(w, ",\"sensor_seen\":"); web_jw_int(w, a->sh.seen);
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&a->mu);
}

int web_adsb_has(web_adsb_t *a, const char *hex) {
    int has = 0;
    pthread_mutex_lock(&a->mu);
    for (int i = 0; i < WEB_ADSB_ROWS && !has; i++)
        has = a->rows[i].used && !strcmp(a->rows[i].hex, hex);
    pthread_mutex_unlock(&a->mu);
    return has;
}
