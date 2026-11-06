#include "web_aprs.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"

/* ── lifecycle ──────────────────────────────────────────────────────── */

int web_aprs_init(web_aprs_t *a) {
    memset(a, 0, sizeof(*a));
    a->rows = calloc(WEB_APRS_ROWS, sizeof(*a->rows));
    if (!a->rows) return -1;
    pthread_mutex_init(&a->mu, NULL);
    return 0;
}

void web_aprs_destroy(web_aprs_t *a) {
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

static int ok_print(int c) { return c >= 0x20 && c <= 0x7e; }
static int ok_label(int c) { return c >= 0x21 && c <= 0x7e; }

/* A string member of at most max octets, each printable, into out (cap
 * max + 1); else out is "". */
static void jtext(const web_jrec_t *r, const char *k, size_t max, char *out) {
    out[0] = '\0';
    const char *s = web_jl_str(r, k);
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > max) return;
    for (size_t i = 0; i < n; i++)
        if (!ok_print((unsigned char)s[i])) return;
    memcpy(out, s, n + 1);
}

static int call_chr(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

int web_aprs_call_ok(const char *s) {
    if (!s) return 0;
    size_t b = 0;
    while (call_chr(s[b])) b++;
    if (b < 1 || b > 6) return 0;
    if (s[b] == '\0') return 1;
    if (s[b] != '-') return 0;
    size_t e = 1;
    while (call_chr(s[b + e])) e++;
    return (e == 2 || e == 3) && s[b + e] == '\0';
}

static char jdti(const web_jrec_t *r) {
    const char *d = web_jl_str(r, "dti");
    return d && ok_print((unsigned char)d[0]) && !d[1] ? d[0] : '\0';
}

static void jsym(const web_jrec_t *r, char out[3]) {
    out[0] = '\0';
    const char *s = web_jl_str(r, "symbol");
    if (s && ok_print((unsigned char)s[0]) && ok_print((unsigned char)s[1]) && !s[2]) {
        out[0] = s[0]; out[1] = s[1]; out[2] = '\0';
    }
}

/* ── the table ──────────────────────────────────────────────────────── */

static web_aprs_row_t *row_find(web_aprs_t *a, const char *call) {
    for (int i = 0; i < WEB_APRS_ROWS; i++)
        if (a->rows[i].used && !strcmp(a->rows[i].call, call)) return &a->rows[i];
    return NULL;
}

/* A fresh row for call, in a free slot or the least recently reported. */
static web_aprs_row_t *row_new(web_aprs_t *a, const char *call) {
    web_aprs_row_t *lru = NULL, *fr = NULL;
    for (int i = 0; i < WEB_APRS_ROWS; i++) {
        web_aprs_row_t *x = &a->rows[i];
        if (!x->used) { if (!fr) fr = x; continue; }
        if (!lru || x->ts < lru->ts) lru = x;
    }
    web_aprs_row_t *x = fr;
    if (!x) { a->evictions++; x = lru; }
    memset(x, 0, sizeof(*x));
    x->used = 1;
    snprintf(x->call, sizeof(x->call), "%s", call);
    x->level = x->best_level = -1;
    return x;
}

/* Against the newest record's ts (the stream's clock, not the host's). */
static void age_out(web_aprs_t *a, long long ts) {
    for (int i = 0; i < WEB_APRS_ROWS; i++) {
        web_aprs_row_t *x = &a->rows[i];
        if (!x->used) continue;
        if (x->gone ? ts - x->gone_ts > WEB_APRS_GONE_TTL_S
                    : ts - x->ts > WEB_APRS_TTL_S) {
            x->used = 0;
            if (!x->gone) a->aged++;
        }
    }
}

static void take_src(char *dst, const char *s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_APRS_SRC_MAX) return;
    for (size_t i = 0; i < n; i++)
        if (!ok_label((unsigned char)s[i])) return;
    memcpy(dst, s, n + 1);
}

#define T_MAX (1LL << 40)

static void point_add(web_aprs_row_t *x, long long ts, double lat, double lon) {
    int prev = (x->phead + WEB_APRS_PTS - 1) % WEB_APRS_PTS;
    if (x->npts && x->pts_lat[prev] == (float)lat && x->pts_lon[prev] == (float)lon)
        return;
    x->pts_ts[x->phead] = ts;
    x->pts_lat[x->phead] = (float)lat;
    x->pts_lon[x->phead] = (float)lon;
    x->phead = (x->phead + 1) % WEB_APRS_PTS;
    if (x->npts < WEB_APRS_PTS) x->npts++;
}

static void packet_apply(web_aprs_t *a, const web_jrec_t *r, long long ts) {
    const char *src = web_jl_str(r, "source");
    long long ut;
    if (!web_aprs_call_ok(src) || !jint(r, "utime", 0, T_MAX, &ut)) {
        a->rejected++;
        return;
    }
    const char *heard = web_jl_str(r, "heard");
    if (heard && !web_aprs_call_ok(heard)) heard = NULL;
    web_aprs_row_t *x = row_find(a, src);
    /* A packet from a station marked gone is its next visit: sloth
     * starts a new row, and so does this. */
    if (x && x->gone) { x->used = 0; x = NULL; }
    if (!x) { x = row_new(a, src); x->first_seen = ut; }
    x->ts = ts;
    x->records++;
    x->since++;
    if (ut > x->last_seen) x->last_seen = ut;
    long long v;
    snprintf(x->via, sizeof(x->via), "%s", heard ? heard : "");
    x->direct = heard && !strcmp(heard, src);
    if (x->direct) x->heard_direct = 1;
    x->level = jint(r, "level", 0, 999, &v) ? (int)v : -1;
    if (x->level > x->best_level) x->best_level = x->level;
    char dti = jdti(r);
    if (dti) x->dti = dti;
    char t[WEB_APRS_TEXT_MAX + 1];
    jtext(r, "system", WEB_APRS_TEXT_MAX, t);
    if (t[0]) memcpy(x->system, t, sizeof(x->system));
    jtext(r, "status", WEB_APRS_TEXT_MAX, t);
    if (t[0]) memcpy(x->status, t, sizeof(x->status));
    char cm[WEB_APRS_COMMENT_MAX + 1];
    jtext(r, "comment", WEB_APRS_COMMENT_MAX, cm);
    double lat = 0, lon = 0;
    int has_pos = jnum(r, "lat", -90, 90, &lat) && jnum(r, "lon", -180, 180, &lon);

    web_aprs_pkt_t *p = &x->recent[x->rhead];
    memset(p, 0, sizeof(*p));
    p->ts = ut;
    p->dti = dti;
    snprintf(p->via, sizeof(p->via), "%s", x->via);
    p->direct = x->direct;
    p->level = x->level;
    p->has_pos = has_pos;
    memcpy(p->comment, cm, WEB_APRS_RECENT_CM);
    p->comment[WEB_APRS_RECENT_CM] = '\0';
    x->rhead = (x->rhead + 1) % WEB_APRS_RECENT;
    if (x->nrecent < WEB_APRS_RECENT) x->nrecent++;

    /* An object or item names something else (APRS101 ch. 11): its
     * position, symbol and comment are not the sender's. */
    if (dti == ';' || dti == ')') return;
    char sym[3];
    jsym(r, sym);
    if (sym[0]) memcpy(x->symbol, sym, sizeof(sym));
    if (cm[0]) memcpy(x->comment, cm, sizeof(x->comment));
    if (has_pos) {
        x->has_pos = 1; x->lat = lat; x->lon = lon; x->pos_ts = ut;
        x->has_speed = jnum(r, "speed_kt", 0, 2000, &x->speed_kt);
        x->has_course = jnum(r, "course", 0, 360, &x->course);
        x->has_alt = jnum(r, "alt_m", -1000, 100000, &x->alt_m);
        point_add(x, ut, lat, lon);
    }
}

static void station_apply(web_aprs_t *a, const web_jrec_t *r, long long ts) {
    const char *call = web_jl_str(r, "call");
    const char *st = web_jl_str(r, "state");
    long long fs;
    if (!web_aprs_call_ok(call) || !st || (strcmp(st, "live") && strcmp(st, "gone")) ||
        !jint(r, "first_seen", 0, T_MAX, &fs)) {
        a->rejected++;
        return;
    }
    web_aprs_row_t *x = row_find(a, call);
    /* A new first_seen is a new visit: the track and packets start over. */
    if (x && x->first_seen != fs) { x->used = 0; x = NULL; }
    if (!x) { x = row_new(a, call); x->first_seen = fs; }
    long long v;
    x->ts = ts;
    x->records++;
    x->gone = !strcmp(st, "gone");
    x->gone_ts = x->gone ? ts : 0;
    if (jint(r, "last_seen", 0, T_MAX, &v) && v > x->last_seen) x->last_seen = v;
    x->packets_at = jint(r, "packets", 0, (1LL << 40), &v) ? v : 0;
    x->since = 0;
    const char *via = web_jl_str(r, "via");
    if (via && web_aprs_call_ok(via)) {
        snprintf(x->via, sizeof(x->via), "%s", via);
        x->direct = jint(r, "direct", 0, 1, &v) && v == 1;
    }
    x->heard_direct = jint(r, "heard_direct", 0, 1, &v) && v == 1;
    x->level = jint(r, "level", 0, 999, &v) ? (int)v : -1;
    x->best_level = jint(r, "best_level", 0, 999, &v) ? (int)v : -1;
    char dti = jdti(r);
    if (dti) x->dti = dti;
    jsym(r, x->symbol);
    double lat = 0, lon = 0;
    if (jnum(r, "lat", -90, 90, &lat) && jnum(r, "lon", -180, 180, &lon)) {
        x->has_pos = 1; x->lat = lat; x->lon = lon;
        x->pos_ts = jint(r, "pos_ts", 0, T_MAX, &v) ? v : 0;
        x->has_speed = jnum(r, "speed_kt", 0, 2000, &x->speed_kt);
        x->has_course = jnum(r, "course", 0, 360, &x->course);
        x->has_alt = jnum(r, "alt_m", -1000, 100000, &x->alt_m);
        point_add(x, x->pos_ts ? x->pos_ts : ts, lat, lon);
    } else {
        x->has_pos = 0;
    }
    jtext(r, "system", WEB_APRS_TEXT_MAX, x->system);
    jtext(r, "status", WEB_APRS_TEXT_MAX, x->status);
    jtext(r, "comment", WEB_APRS_COMMENT_MAX, x->comment);
    take_src(a->src, web_jl_str(r, "src"));
}

static void sh_apply(web_aprs_t *a, const web_jrec_t *r, long long ts) {
    /* Only a sensor_health carrying the block: a sloth with no --aprs
     * writes none of it, and the panel then says "no decoder". */
    if (!web_jl_get(r, "aprs_state")) return;
    web_aprs_sh_t h;
    memset(&h, 0, sizeof(h));
    h.seen = 1;
    h.ts = ts;
    const char *st = web_jl_str(r, "aprs_state");
    static const char *const STATES[] = { "waiting", "live", "error" };
    snprintf(h.state, sizeof(h.state), "other");
    for (size_t i = 0; st && i < sizeof(STATES) / sizeof(STATES[0]); i++)
        if (!strcmp(st, STATES[i])) snprintf(h.state, sizeof(h.state), "%s", STATES[i]);
    take_src(h.src, web_jl_str(r, "aprs_src"));
    long long v;
    h.missing = jint(r, "aprs_missing", 0, 1, &v) && v == 1;
    h.last_read = jint(r, "aprs_last_read", 0, T_MAX, &v) ? v : 0;
    h.last_packet = jint(r, "aprs_last_packet", 0, T_MAX, &v) ? v : 0;
    h.stations = jint(r, "aprs_stations", 0, 100000, &v) ? v : 0;
#define C(name, field) h.field = jint(r, name, 0, (1LL << 50), &v) ? v : 0
    C("aprs_bytes", bytes);
    C("aprs_lines", lines);
    C("aprs_packets", packets);
    C("aprs_bad_lines", bad_lines);
    C("aprs_overflow", overflow);
    C("aprs_expired", expired);
    C("aprs_truncations", truncations);
    C("aprs_rotations", rotations);
    C("aprs_read_errors", read_errors);
#undef C
    jtext(r, "aprs_err", WEB_APRS_ERR_MAX, h.err);
    a->sh = h;
    if (!a->src[0]) take_src(a->src, h.src);
}

void web_aprs_record(web_aprs_t *a, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!a || !a->rows) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&a->mu);
    if (!strcmp(t, "aprs_packet")) {
        a->packets++;
        packet_apply(a, r, ts);
        take_src(a->src, web_jl_str(r, "src"));
        age_out(a, ts);
    } else if (!strcmp(t, "aprs_station")) {
        a->records++;
        station_apply(a, r, ts);
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

static void jw_int_or_null(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

static void jw_chr(web_jw_t *w, char c) {
    char s[2] = { c, '\0' };
    web_jw_str(w, s);
}

static int by_interest(const void *pa, const void *pb) {
    const web_aprs_row_t *x = *(const web_aprs_row_t *const *)pa;
    const web_aprs_row_t *y = *(const web_aprs_row_t *const *)pb;
    if (x->gone != y->gone) return x->gone - y->gone;
    if (x->last_seen != y->last_seen) return y->last_seen > x->last_seen ? 1 : -1;
    return strcmp(x->call, y->call);
}

static void row_body(web_jw_t *w, const web_aprs_row_t *x) {
    web_jw_raw(w, "{\"call\":"); web_jw_str(w, x->call);
    web_jw_raw(w, ",\"state\":"); web_jw_str(w, x->gone ? "gone" : "live");
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, x->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, x->last_seen);
    web_jw_raw(w, ",\"packets\":"); web_jw_int(w, x->packets_at + x->since);
    web_jw_raw(w, ",\"via\":"); web_jw_str(w, x->via);
    web_jw_raw(w, ",\"direct\":"); web_jw_int(w, x->direct);
    web_jw_raw(w, ",\"heard_direct\":"); web_jw_int(w, x->heard_direct);
    web_jw_raw(w, ",\"level\":"); jw_int_or_null(w, x->level >= 0, x->level);
    web_jw_raw(w, ",\"best_level\":"); jw_int_or_null(w, x->best_level >= 0, x->best_level);
    web_jw_raw(w, ",\"dti\":"); jw_chr(w, x->dti);
    web_jw_raw(w, ",\"symbol\":"); web_jw_str(w, x->symbol);
    web_jw_raw(w, ",\"lat\":"); jw_num(w, x->has_pos, x->lat, 5);
    web_jw_raw(w, ",\"lon\":"); jw_num(w, x->has_pos, x->lon, 5);
    web_jw_raw(w, ",\"pos_ts\":"); jw_int_or_null(w, x->has_pos && x->pos_ts, x->pos_ts);
    web_jw_raw(w, ",\"speed_kt\":"); jw_num(w, x->has_pos && x->has_speed, x->speed_kt, 1);
    web_jw_raw(w, ",\"course\":"); jw_num(w, x->has_pos && x->has_course, x->course, 0);
    web_jw_raw(w, ",\"alt_m\":"); jw_num(w, x->has_pos && x->has_alt, x->alt_m, 0);
    web_jw_raw(w, ",\"comment\":"); web_jw_str(w, x->comment);
    web_jw_raw(w, ",\"status\":"); web_jw_str(w, x->status);
    web_jw_raw(w, ",\"system\":"); web_jw_str(w, x->system);
    web_jw_raw(w, ",\"ts\":"); web_jw_int(w, x->ts);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, x->records);
    web_jw_raw(w, ",\"track_n\":"); web_jw_int(w, x->npts);
}

static void sensor_json(web_jw_t *w, const web_aprs_sh_t *h) {
    if (!h->seen) { web_jw_raw(w, "null"); return; }
    web_jw_raw(w, "{\"ts\":"); web_jw_int(w, h->ts);
    web_jw_raw(w, ",\"state\":"); web_jw_str(w, h->state);
    web_jw_raw(w, ",\"src\":"); web_jw_str(w, h->src);
    web_jw_raw(w, ",\"missing\":"); web_jw_int(w, h->missing);
    web_jw_raw(w, ",\"last_read\":"); web_jw_int(w, h->last_read);
    web_jw_raw(w, ",\"last_packet\":"); web_jw_int(w, h->last_packet);
    web_jw_raw(w, ",\"stations\":"); web_jw_int(w, h->stations);
    web_jw_raw(w, ",\"bytes\":"); web_jw_int(w, h->bytes);
    web_jw_raw(w, ",\"lines\":"); web_jw_int(w, h->lines);
    web_jw_raw(w, ",\"packets\":"); web_jw_int(w, h->packets);
    web_jw_raw(w, ",\"bad_lines\":"); web_jw_int(w, h->bad_lines);
    web_jw_raw(w, ",\"overflow\":"); web_jw_int(w, h->overflow);
    web_jw_raw(w, ",\"expired\":"); web_jw_int(w, h->expired);
    web_jw_raw(w, ",\"truncations\":"); web_jw_int(w, h->truncations);
    web_jw_raw(w, ",\"rotations\":"); web_jw_int(w, h->rotations);
    web_jw_raw(w, ",\"read_errors\":"); web_jw_int(w, h->read_errors);
    web_jw_raw(w, ",\"err\":"); web_jw_str(w, h->err);
    web_jw_raw(w, "}");
}

/* One station with its track (oldest first, [ts, lat, lon]) and its
 * recent packets (oldest first, compact, names in "packet_cols"). */
static void station_json(web_jw_t *w, const web_aprs_row_t *x) {
    row_body(w, x);
    web_jw_raw(w, ",\"track_pts\":[");
    int start = (x->phead + WEB_APRS_PTS - x->npts) % WEB_APRS_PTS;
    for (int j = 0; j < x->npts; j++) {
        int at = (start + j) % WEB_APRS_PTS;
        if (j) web_jw_raw(w, ",");
        web_jw_raw(w, "["); web_jw_int(w, x->pts_ts[at]);
        web_jw_raw(w, ","); jw_num(w, 1, x->pts_lat[at], 5);
        web_jw_raw(w, ","); jw_num(w, 1, x->pts_lon[at], 5);
        web_jw_raw(w, "]");
    }
    web_jw_raw(w, "],\"packet_cols\":[\"ts\",\"dti\",\"via\",\"direct\",\"level\","
                  "\"has_pos\",\"comment\"],\"packets_recent\":[");
    start = (x->rhead + WEB_APRS_RECENT - x->nrecent) % WEB_APRS_RECENT;
    for (int j = 0; j < x->nrecent; j++) {
        const web_aprs_pkt_t *p = &x->recent[(start + j) % WEB_APRS_RECENT];
        if (j) web_jw_raw(w, ",");
        web_jw_raw(w, "["); web_jw_int(w, p->ts);
        web_jw_raw(w, ","); jw_chr(w, p->dti);
        web_jw_raw(w, ","); web_jw_str(w, p->via);
        web_jw_raw(w, ","); web_jw_int(w, p->direct);
        web_jw_raw(w, ","); jw_int_or_null(w, p->level >= 0, p->level);
        web_jw_raw(w, ","); web_jw_int(w, p->has_pos);
        web_jw_raw(w, ","); web_jw_str(w, p->comment);
        web_jw_raw(w, "]");
    }
    web_jw_raw(w, "]}");
}

int web_aprs_route(web_aprs_t *a, const char *query, long long now_s, int none_here,
                   char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "limit", "", 0 }, { "call", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_APRS_ROWS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_APRS_ROWS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (ps[1].seen && !web_aprs_call_ok(ps[1].val))
        return answer_error(400, "bad_call", body, cap, len, status);
    if (!a || !a->rows) return answer_error(503, "no_aprs", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }

    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&a->mu);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, a->src);
    if (ps[1].seen) {
        const web_aprs_row_t *x = row_find(a, ps[1].val);
        web_jw_raw(&w, ",\"call\":"); web_jw_str(&w, ps[1].val);
        web_jw_raw(&w, ",\"station\":");
        if (x) station_json(&w, x); else web_jw_raw(&w, "null");
        web_jw_raw(&w, "}");
        pthread_mutex_unlock(&a->mu);
        if (w.overflow) return -1;
        *len = w.len;
        *status = 200;
        return 0;
    }
    const web_aprs_row_t **idx = malloc(WEB_APRS_ROWS * sizeof(*idx));
    if (!idx) { pthread_mutex_unlock(&a->mu); return -1; }
    int n = 0, live = 0, pos = 0, direct = 0;
    for (int i = 0; i < WEB_APRS_ROWS; i++) {
        const web_aprs_row_t *x = &a->rows[i];
        if (!x->used) continue;
        idx[n++] = x;
        live += !x->gone;
        pos += !x->gone && x->has_pos;
        direct += !x->gone && x->heard_direct;
    }
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_interest);
    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)a->records);
    web_jw_raw(&w, ",\"packet_records\":"); web_jw_int(&w, (long long)a->packets);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)a->evictions);
    web_jw_raw(&w, ",\"aged\":"); web_jw_int(&w, (long long)a->aged);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)a->rejected);
    /* The sensor block: null until a sensor_health carried aprs_*. */
    web_jw_raw(&w, ",\"sensor\":");
    sensor_json(&w, &a->sh);
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"live\":"); web_jw_int(&w, live);
    web_jw_raw(&w, ",\"with_pos\":"); web_jw_int(&w, pos);
    web_jw_raw(&w, ",\"heard_direct\":"); web_jw_int(&w, direct);
    web_jw_raw(&w, ",\"stations\":[");
    int shown = 0, cut = 0;
    for (int i = 0; i < n && i < limit; i++) {
        /* Stop before a row that might not fit, leaving room to close. */
        if (w.len + WEB_APRS_ROW_WORST + 64 > cap) { cut = 1; break; }
        if (i) web_jw_raw(&w, ",");
        row_body(&w, idx[i]);
        web_jw_raw(&w, "}");
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

size_t web_aprs_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "APRS stations are the Dire Wolf decoder's (--aprs), a passive "
                   "radio; the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}

void web_aprs_health_json(web_aprs_t *a, web_jw_t *w) {
    if (!a || !a->rows) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&a->mu);
    int n = 0, live = 0;
    for (int i = 0; i < WEB_APRS_ROWS; i++) {
        n += a->rows[i].used != 0;
        live += a->rows[i].used && !a->rows[i].gone;
    }
    web_jw_raw(w, "{\"rows\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"live\":"); web_jw_int(w, live);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)a->records);
    web_jw_raw(w, ",\"packets\":"); web_jw_int(w, (long long)a->packets);
    web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)a->evictions);
    web_jw_raw(w, ",\"aged\":"); web_jw_int(w, (long long)a->aged);
    web_jw_raw(w, ",\"rejected\":"); web_jw_int(w, (long long)a->rejected);
    web_jw_raw(w, ",\"sensor_seen\":"); web_jw_int(w, a->sh.seen);
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&a->mu);
}
