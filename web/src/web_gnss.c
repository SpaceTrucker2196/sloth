#include "web_gnss.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"

/* ── lifecycle ──────────────────────────────────────────────────────── */

int web_gnss_init(web_gnss_t *g) {
    memset(g, 0, sizeof(*g));
    g->sats = calloc(WEB_GNSS_SATS, sizeof(*g->sats));
    g->fixes = calloc(WEB_GNSS_FIXES, sizeof(*g->fixes));
    if (!g->sats || !g->fixes) {
        free(g->sats);
        free(g->fixes);
        g->sats = NULL;
        g->fixes = NULL;
        return -1;
    }
    pthread_mutex_init(&g->mu, NULL);
    return 0;
}

void web_gnss_destroy(web_gnss_t *g) {
    if (!g->sats) return;
    pthread_mutex_destroy(&g->mu);
    free(g->sats);
    free(g->fixes);
    g->sats = NULL;
    g->fixes = NULL;
}

const char *web_gnss_name(int gnssid) {
    /* sloth's table (src/gps.c gnss_name()); test_parity.c holds the
     * two together. */
    switch (gnssid) {
    case 0: return "GPS";
    case 1: return "SBAS";
    case 2: return "Galileo";
    case 3: return "BeiDou";
    case 4: return "IMES";
    case 5: return "QZSS";
    case 6: return "GLONASS";
    case 7: return "NavIC";
    case 8: return "other";
    default: return "?";
    }
}

/* ── field readers: a value outside its range is absent ─────────────── */

/* An integer member in lo..hi, else def. */
static long long jint(const web_jrec_t *r, const char *k, long long lo, long long hi,
                      long long def) {
    long long v = web_jl_int(r, k, def - 1);
    if (v == def - 1) {
        /* Absent, or a non-integer (web_jl_int refuses a fraction). */
        return def;
    }
    return (v < lo || v > hi) ? def : v;
}

/* A number member in lo..hi; 1 with *out, 0 otherwise. */
static int jnum(const web_jrec_t *r, const char *k, double lo, double hi, double *out) {
    double v;
    if (!web_jl_num(r, k, &v) || !isfinite(v) || v < lo || v > hi) return 0;
    *out = v;
    return 1;
}

static void take_src(web_gnss_t *g, const web_jrec_t *r) {
    const char *s = web_jl_str(r, "src");
    if (!s) return;
    size_t n = strlen(s);
    if (n == 0 || n > WEB_GNSS_SRC_MAX) return;
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7e) return;
    memcpy(g->src, s, n + 1);
}

/* ── the satellite table ────────────────────────────────────────────── */

static web_gnss_sat_t *sat_slot(web_gnss_t *g, int gnssid, int prn, long long ts) {
    web_gnss_sat_t *lru = NULL, *fr = NULL;
    for (int i = 0; i < WEB_GNSS_SATS; i++) {
        web_gnss_sat_t *s = &g->sats[i];
        if (!s->used) { if (!fr) fr = s; continue; }
        if (s->gnssid == gnssid && s->prn == prn) return s;
        if (!lru || s->ts < lru->ts) lru = s;
    }
    if (fr) { memset(fr, 0, sizeof(*fr)); fr->first_ts = ts; return fr; }
    g->evictions++;
    memset(lru, 0, sizeof(*lru));
    lru->first_ts = ts;
    return lru;
}

/* A row not reported for the TTL is a satellite that set. Run on every
 * record, against the newest record's ts (the stream's clock, not the
 * host's). */
static void age_out(web_gnss_t *g, long long ts) {
    for (int i = 0; i < WEB_GNSS_SATS; i++) {
        web_gnss_sat_t *s = &g->sats[i];
        if (s->used && ts - s->ts > WEB_GNSS_SAT_TTL_S) {
            s->used = 0;
            g->aged++;
        }
    }
}

static void sat_apply(web_gnss_t *g, const web_jrec_t *r, long long ts) {
    long long gnssid = jint(r, "gnssid", -1, 127, -2);
    long long prn = jint(r, "prn", 0, 32767, -1);
    if (gnssid == -2 || prn < 0) { g->rejected++; return; }
    if (gnssid > 7) gnssid = 8;   /* a constellation sloth does not name */
    web_gnss_sat_t *s = sat_slot(g, (int)gnssid, (int)prn, ts);
    s->used = 1;
    s->gnssid = (int)gnssid;
    s->prn = (int)prn;
    s->svid = (int)jint(r, "svid", 0, 32767, -1);
    s->sigid = (int)jint(r, "sigid", 0, 127, -1);
    s->el = (int)jint(r, "el", 0, 90, -1);
    s->az = (int)jint(r, "az", 0, 360, -1);
    double cn0;
    s->has_cn0 = jnum(r, "cn0", 0.0, 99.0, &cn0);
    s->cn0 = s->has_cn0 ? cn0 : 0.0;
    s->in_fix = jint(r, "used", 0, 1, 0) == 1;
    s->health = (int)jint(r, "health", 0, 2, -1);
    s->ts = ts;
    s->sky_ts = jint(r, "sky_ts", 0, (1LL << 40), 0);
    s->records++;
    if (s->has_cn0) {
        s->pts_ts[s->phead] = ts;
        s->pts_cn0[s->phead] = (float)cn0;
        s->phead = (s->phead + 1) % WEB_GNSS_PTS;
        if (s->npts < WEB_GNSS_PTS) s->npts++;
    }
}

static void sky_apply(web_gnss_t *g, const web_jrec_t *r, long long ts) {
    web_gnss_sky_t k;
    memset(&k, 0, sizeof(k));
    k.seen = 1;
    k.ts = ts;
    k.sky_ts = jint(r, "sky_ts", 0, (1LL << 40), 0);
    k.nsat = (int)jint(r, "nsat", -1, 999, -1);
    k.usat = (int)jint(r, "usat", -1, 999, -1);
    k.rows = (int)jint(r, "rows", 0, 999, 0);
    k.overflow = (int)jint(r, "overflow", 0, 9999, 0);
    k.cn0_n = (int)jint(r, "cn0_n", 0, 999, 0);
    if (!jnum(r, "hdop", 0, 100, &k.hdop)) k.hdop = 0;
    if (!jnum(r, "vdop", 0, 100, &k.vdop)) k.vdop = 0;
    if (!jnum(r, "pdop", 0, 100, &k.pdop)) k.pdop = 0;
    if (!jnum(r, "gdop", 0, 100, &k.gdop)) k.gdop = 0;
    if (!jnum(r, "tdop", 0, 100, &k.tdop)) k.tdop = 0;
    if (!jnum(r, "cn0_mean", 0, 99, &k.cn0_mean)) k.cn0_mean = 0;
    if (!jnum(r, "cn0_max", 0, 99, &k.cn0_max)) k.cn0_max = 0;
    if (!jnum(r, "cn0_sd", 0, 99, &k.cn0_sd)) k.cn0_sd = 0;
    k.passes = jint(r, "passes", 0, (1LL << 60), 0);
    g->sky = k;
    take_src(g, r);
}

static void fix_apply(web_gnss_t *g, const web_jrec_t *r, long long ts) {
    web_gnss_fix_t f;
    memset(&f, 0, sizeof(f));
    f.ts = ts;
    f.fix_ts = jint(r, "fix_ts", 0, (1LL << 40), 0);
    long long mode = jint(r, "mode", 0, 3, -1);
    if (mode < 0) { g->rejected++; return; }
    f.mode = (int)mode;
    f.status = (int)jint(r, "status", -1, 9, -1);
    f.nsat = (int)jint(r, "nsat", -1, 999, -1);
    f.usat = (int)jint(r, "usat", -1, 999, -1);
    if (!jnum(r, "hdop", 0, 100, &f.hdop)) f.hdop = 0;
    if (!jnum(r, "vdop", 0, 100, &f.vdop)) f.vdop = 0;
    if (!jnum(r, "pdop", 0, 100, &f.pdop)) f.pdop = 0;
    double lat, lon;
    if (jnum(r, "lat", -90, 90, &lat) && jnum(r, "lon", -180, 180, &lon)) {
        f.has_pos = 1; f.lat = lat; f.lon = lon;
    }
    f.has_alt = jnum(r, "alt_m", -1000, 20000, &f.alt_m);
    f.has_eph = jnum(r, "eph", 0, 1e5, &f.eph);
    f.has_epv = jnum(r, "epv", 0, 1e5, &f.epv);
    f.has_speed = jnum(r, "speed_mps", 0, 1e4, &f.speed);
    f.has_track = jnum(r, "track_deg", 0, 360, &f.track);
    long long off = jint(r, "time_off_ms", -(1LL << 40), (1LL << 40), (1LL << 41));
    if (off != (1LL << 41)) { f.has_time_off = 1; f.time_off_ms = off; }
    f.leap = (int)jint(r, "leap", -1, 127, -1);
    f.jam = (int)jint(r, "jam", -1, 255, -1);
    f.tpv_count = jint(r, "tpv_count", 0, (1LL << 60), 0);
    g->fixes[g->fix_head] = f;
    g->fix_head = (g->fix_head + 1) % WEB_GNSS_FIXES;
    if (g->fix_n < WEB_GNSS_FIXES) g->fix_n++;
    take_src(g, r);
}

static void sh_apply(web_gnss_t *g, const web_jrec_t *r, long long ts) {
    /* Only a sensor_health carrying the block: a sloth with no --gps
     * writes none of these, and the panel then says "no receiver". */
    if (!web_jl_get(r, "gnss_sats_in_view")) return;
    web_gnss_sh_t h;
    memset(&h, 0, sizeof(h));
    h.seen = 1;
    h.ts = ts;
    const char *st = web_jl_str(r, "gps_state");
    static const char *const STATES[] = { "none", "fixed", "searching", "fix", "stale" };
    snprintf(h.gps_state, sizeof(h.gps_state), "other");
    for (size_t i = 0; st && i < sizeof(STATES) / sizeof(STATES[0]); i++)
        if (!strcmp(st, STATES[i])) snprintf(h.gps_state, sizeof(h.gps_state), "%s", STATES[i]);
    h.sats_in_view = (int)jint(r, "gnss_sats_in_view", 0, 999, 0);
    h.sats_used = (int)jint(r, "gnss_sats_used", 0, 999, 0);
    if (!jnum(r, "gnss_cn0_mean", 0, 99, &h.cn0_mean)) h.cn0_mean = 0;
    long long off = jint(r, "gnss_time_offset_ms", -(1LL << 40), (1LL << 40), (1LL << 41));
    if (off != (1LL << 41)) { h.has_time_off = 1; h.time_off_ms = off; }
    h.jam = (int)jint(r, "gnss_jam", -1, 255, -1);
    g->sh = h;
    const char *src = web_jl_str(r, "gps_src");
    if (src && !g->src[0]) {
        size_t n = strlen(src);
        int ok = n > 0 && n <= WEB_GNSS_SRC_MAX;
        for (size_t i = 0; ok && i < n; i++)
            if ((unsigned char)src[i] < 0x21 || (unsigned char)src[i] > 0x7e) ok = 0;
        if (ok) memcpy(g->src, src, n + 1);
    }
}

void web_gnss_record(web_gnss_t *g, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!g || !g->sats) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&g->mu);
    if (!strcmp(t, "gnss_sat")) { g->records++; sat_apply(g, r, ts); age_out(g, ts); }
    else if (!strcmp(t, "gnss_sky")) { g->records++; sky_apply(g, r, ts); age_out(g, ts); }
    else if (!strcmp(t, "gnss_fix")) { g->records++; fix_apply(g, r, ts); }
    else if (!strcmp(t, "sensor_health")) sh_apply(g, r, ts);
    pthread_mutex_unlock(&g->mu);
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

/* A number with dp decimals, or null. The C locale is slothweb's own
 * (it calls no setlocale), so %f writes a point. */
static void jw_num(web_jw_t *w, int has, double v, int dp) {
    char t[40];
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    snprintf(t, sizeof(t), "%.*f", dp, v);
    web_jw_raw(w, t);
}

static void jw_int_or_null(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

static void fix_json(web_jw_t *w, const web_gnss_fix_t *f) {
    web_jw_raw(w, "{\"ts\":"); web_jw_int(w, f->ts);
    web_jw_raw(w, ",\"fix_ts\":"); web_jw_int(w, f->fix_ts);
    web_jw_raw(w, ",\"mode\":"); web_jw_int(w, f->mode);
    web_jw_raw(w, ",\"status\":"); jw_int_or_null(w, f->status >= 0, f->status);
    web_jw_raw(w, ",\"nsat\":"); jw_int_or_null(w, f->nsat >= 0, f->nsat);
    web_jw_raw(w, ",\"usat\":"); jw_int_or_null(w, f->usat >= 0, f->usat);
    web_jw_raw(w, ",\"hdop\":"); jw_num(w, f->hdop > 0, f->hdop, 1);
    web_jw_raw(w, ",\"vdop\":"); jw_num(w, f->vdop > 0, f->vdop, 1);
    web_jw_raw(w, ",\"pdop\":"); jw_num(w, f->pdop > 0, f->pdop, 1);
    web_jw_raw(w, ",\"lat\":"); jw_num(w, f->has_pos, f->lat, 5);
    web_jw_raw(w, ",\"lon\":"); jw_num(w, f->has_pos, f->lon, 5);
    web_jw_raw(w, ",\"alt_m\":"); jw_num(w, f->has_alt, f->alt_m, 1);
    web_jw_raw(w, ",\"eph\":"); jw_num(w, f->has_eph, f->eph, 1);
    web_jw_raw(w, ",\"epv\":"); jw_num(w, f->has_epv, f->epv, 1);
    web_jw_raw(w, ",\"speed_mps\":"); jw_num(w, f->has_speed, f->speed, 2);
    web_jw_raw(w, ",\"track_deg\":"); jw_num(w, f->has_track, f->track, 1);
    web_jw_raw(w, ",\"time_off_ms\":"); jw_int_or_null(w, f->has_time_off, f->time_off_ms);
    web_jw_raw(w, ",\"leap\":"); jw_int_or_null(w, f->leap >= 0, f->leap);
    web_jw_raw(w, ",\"jam\":"); jw_int_or_null(w, f->jam >= 0, f->jam);
    web_jw_raw(w, ",\"tpv_count\":"); web_jw_int(w, f->tpv_count);
    web_jw_raw(w, "}");
}

static int by_cn0(const void *a, const void *b) {
    const web_gnss_sat_t *x = *(const web_gnss_sat_t *const *)a;
    const web_gnss_sat_t *y = *(const web_gnss_sat_t *const *)b;
    double cx = x->has_cn0 ? x->cn0 : -1, cy = y->has_cn0 ? y->cn0 : -1;
    if (cx != cy) return cy > cx ? 1 : -1;
    if (x->gnssid != y->gnssid) return x->gnssid - y->gnssid;
    return x->prn - y->prn;
}

/* The scope line every answer carries: the receiver is the host's own. */
#define GNSS_SCOPE_NOTE "\"scope_note\":\"every scope: the host's own receiver\""

int web_gnss_route(web_gnss_t *g, const char *query, long long now_s,
                   char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_GNSS_SATS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_GNSS_SATS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (!g || !g->sats) return answer_error(503, "no_gnss", body, cap, len, status);

    const web_gnss_sat_t *idx[WEB_GNSS_SATS];
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&g->mu);
    int n = 0;
    for (int i = 0; i < WEB_GNSS_SATS; i++)
        if (g->sats[i].used) idx[n++] = &g->sats[i];
    if (n > 1) qsort(idx, (size_t)n, sizeof(idx[0]), by_cn0);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, "," GNSS_SCOPE_NOTE);
    web_jw_raw(&w, ",\"src\":"); web_jw_str(&w, g->src);
    web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, (long long)g->records);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)g->evictions);
    web_jw_raw(&w, ",\"aged\":"); web_jw_int(&w, (long long)g->aged);
    web_jw_raw(&w, ",\"rejected\":"); web_jw_int(&w, (long long)g->rejected);
    /* The sensor block: null until a sensor_health carried gnss_*. */
    web_jw_raw(&w, ",\"sensor\":");
    if (g->sh.seen) {
        web_jw_raw(&w, "{\"ts\":"); web_jw_int(&w, g->sh.ts);
        web_jw_raw(&w, ",\"state\":"); web_jw_str(&w, g->sh.gps_state);
        web_jw_raw(&w, ",\"sats_in_view\":"); web_jw_int(&w, g->sh.sats_in_view);
        web_jw_raw(&w, ",\"sats_used\":"); web_jw_int(&w, g->sh.sats_used);
        web_jw_raw(&w, ",\"cn0_mean\":"); jw_num(&w, g->sh.cn0_mean > 0, g->sh.cn0_mean, 1);
        web_jw_raw(&w, ",\"time_off_ms\":"); jw_int_or_null(&w, g->sh.has_time_off, g->sh.time_off_ms);
        web_jw_raw(&w, ",\"jam\":"); jw_int_or_null(&w, g->sh.jam >= 0, g->sh.jam);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, ",\"fix\":");
    if (g->fix_n) fix_json(&w, &g->fixes[(g->fix_head + WEB_GNSS_FIXES - 1) % WEB_GNSS_FIXES]);
    else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"fixes\":"); web_jw_int(&w, g->fix_n);
    web_jw_raw(&w, ",\"sky\":");
    if (g->sky.seen) {
        const web_gnss_sky_t *k = &g->sky;
        web_jw_raw(&w, "{\"ts\":"); web_jw_int(&w, k->ts);
        web_jw_raw(&w, ",\"sky_ts\":"); web_jw_int(&w, k->sky_ts);
        web_jw_raw(&w, ",\"nsat\":"); jw_int_or_null(&w, k->nsat >= 0, k->nsat);
        web_jw_raw(&w, ",\"usat\":"); jw_int_or_null(&w, k->usat >= 0, k->usat);
        web_jw_raw(&w, ",\"rows\":"); web_jw_int(&w, k->rows);
        web_jw_raw(&w, ",\"overflow\":"); web_jw_int(&w, k->overflow);
        web_jw_raw(&w, ",\"hdop\":"); jw_num(&w, k->hdop > 0, k->hdop, 1);
        web_jw_raw(&w, ",\"vdop\":"); jw_num(&w, k->vdop > 0, k->vdop, 1);
        web_jw_raw(&w, ",\"pdop\":"); jw_num(&w, k->pdop > 0, k->pdop, 1);
        web_jw_raw(&w, ",\"gdop\":"); jw_num(&w, k->gdop > 0, k->gdop, 1);
        web_jw_raw(&w, ",\"tdop\":"); jw_num(&w, k->tdop > 0, k->tdop, 1);
        web_jw_raw(&w, ",\"cn0_mean\":"); jw_num(&w, k->cn0_n > 0, k->cn0_mean, 1);
        web_jw_raw(&w, ",\"cn0_max\":"); jw_num(&w, k->cn0_n > 0, k->cn0_max, 1);
        web_jw_raw(&w, ",\"cn0_sd\":"); jw_num(&w, k->cn0_n > 0, k->cn0_sd, 1);
        web_jw_raw(&w, ",\"cn0_n\":"); web_jw_int(&w, k->cn0_n);
        web_jw_raw(&w, ",\"passes\":"); web_jw_int(&w, k->passes);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"sats\":[");
    for (int i = 0; i < n && i < limit; i++) {
        const web_gnss_sat_t *s = idx[i];
        if (i) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"gnss\":"); web_jw_str(&w, web_gnss_name(s->gnssid));
        web_jw_raw(&w, ",\"gnssid\":"); web_jw_int(&w, s->gnssid);
        web_jw_raw(&w, ",\"svid\":"); jw_int_or_null(&w, s->svid >= 0, s->svid);
        web_jw_raw(&w, ",\"prn\":"); web_jw_int(&w, s->prn);
        web_jw_raw(&w, ",\"sigid\":"); jw_int_or_null(&w, s->sigid >= 0, s->sigid);
        web_jw_raw(&w, ",\"el\":"); jw_int_or_null(&w, s->el >= 0, s->el);
        web_jw_raw(&w, ",\"az\":"); jw_int_or_null(&w, s->az >= 0, s->az);
        web_jw_raw(&w, ",\"cn0\":"); jw_num(&w, s->has_cn0, s->cn0, 1);
        web_jw_raw(&w, ",\"used\":"); web_jw_int(&w, s->in_fix);
        web_jw_raw(&w, ",\"health\":"); jw_int_or_null(&w, s->health >= 0, s->health);
        web_jw_raw(&w, ",\"ts\":"); web_jw_int(&w, s->ts);
        web_jw_raw(&w, ",\"first_ts\":"); web_jw_int(&w, s->first_ts);
        web_jw_raw(&w, ",\"sky_ts\":"); web_jw_int(&w, s->sky_ts);
        web_jw_raw(&w, ",\"records\":"); web_jw_int(&w, s->records);
        /* Oldest first. */
        web_jw_raw(&w, ",\"points\":[");
        int start = (s->phead + WEB_GNSS_PTS - s->npts) % WEB_GNSS_PTS;
        for (int j = 0; j < s->npts; j++) {
            int at = (start + j) % WEB_GNSS_PTS;
            if (j) web_jw_raw(&w, ",");
            web_jw_raw(&w, "["); web_jw_int(&w, s->pts_ts[at]);
            web_jw_raw(&w, ","); jw_num(&w, 1, s->pts_cn0[at], 1);
            web_jw_raw(&w, "]");
        }
        web_jw_raw(&w, "]}");
    }
    web_jw_raw(&w, "]}");
    pthread_mutex_unlock(&g->mu);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int web_gnss_fixes_route(web_gnss_t *g, const char *query, long long now_s,
                         char *body, size_t cap, size_t *len, int *status) {
    web_param_t ps[2] = { { "since", "", 0 }, { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long since = 0, limit = WEB_GNSS_LIMIT_MAX;
    if (ps[0].seen && decimal(ps[0].val, 0, (1LL << 40), &since) != 0)
        return answer_error(400, "bad_since", body, cap, len, status);
    if (ps[1].seen && decimal(ps[1].val, 1, WEB_GNSS_LIMIT_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (!g || !g->sats) return answer_error(503, "no_gnss", body, cap, len, status);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&g->mu);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, "," GNSS_SCOPE_NOTE);
    web_jw_raw(&w, ",\"since\":"); web_jw_int(&w, since);
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, g->fix_n);
    web_jw_raw(&w, ",\"rows\":[");
    int start = (g->fix_head + WEB_GNSS_FIXES - g->fix_n) % WEB_GNSS_FIXES;
    int out = 0;
    for (int j = 0; j < g->fix_n && out < limit; j++) {
        const web_gnss_fix_t *f = &g->fixes[(start + j) % WEB_GNSS_FIXES];
        if (f->ts <= since) continue;
        if (out++) web_jw_raw(&w, ",");
        fix_json(&w, f);
    }
    web_jw_raw(&w, "],\"matched\":"); web_jw_int(&w, out);
    web_jw_raw(&w, "}");
    pthread_mutex_unlock(&g->mu);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

void web_gnss_health_json(web_gnss_t *g, web_jw_t *w) {
    if (!g || !g->sats) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&g->mu);
    int n = 0;
    for (int i = 0; i < WEB_GNSS_SATS; i++) n += g->sats[i].used != 0;
    web_jw_raw(w, "{\"sats\":"); web_jw_int(w, n);
    web_jw_raw(w, ",\"fixes\":"); web_jw_int(w, g->fix_n);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)g->records);
    web_jw_raw(w, ",\"evictions\":"); web_jw_int(w, (long long)g->evictions);
    web_jw_raw(w, ",\"aged\":"); web_jw_int(w, (long long)g->aged);
    web_jw_raw(w, ",\"rejected\":"); web_jw_int(w, (long long)g->rejected);
    web_jw_raw(w, ",\"sensor_seen\":"); web_jw_int(w, g->sh.seen);
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&g->mu);
}
