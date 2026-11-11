/* Aircraft across the owner's fleet (#192 I7). Contract and basis:
 * web_fleetadsb.h, docs/wiki/fleet.md "Aircraft across the sites",
 * research/adsb/multi-receiver-verification.md. */
#include "web_fleetadsb.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_adsb.h"
#include "web_gnss.h"
#include "web_jsonl.h"
#include "web_series.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define D2R (3.14159265358979323846 / 180.0)
#define FT_M 0.3048
#define KT_MS 0.514444

/* ── the words ─────────────────────────────────────────────────────── */

static const char *const VERDICT_WORD[WEB_FA_NVERDICT] = {
    "undetermined", "confirmed", "unconfirmed", "out_of_peer_coverage",
};

const char *web_fa_verdict_word(int v) {
    return v >= 0 && v < WEB_FA_NVERDICT ? VERDICT_WORD[v] : "undetermined";
}

static const char *const BSTATE_WORD[WEB_FA_B_NSTATE] = {
    "not_compared", "heard", "should_have_heard", "outside_coverage", "heard_later",
    "pending", "answer_cut", "not_receiving", "no_position", "no_altitude",
    "no_coverage", "reporter",
};

const char *web_fa_bstate_word(int s) {
    return s >= 0 && s < WEB_FA_B_NSTATE ? BSTATE_WORD[s] : "";
}

/* ── the geometry ──────────────────────────────────────────────────── */

double web_fa_bearing(double lat1, double lon1, double lat2, double lon2) {
    double p1 = lat1 * D2R, p2 = lat2 * D2R, dl = (lon2 - lon1) * D2R;
    double y = sin(dl) * cos(p2), x = cos(p1) * sin(p2) - sin(p1) * cos(p2) * cos(dl);
    double b = atan2(y, x) / D2R;
    if (!isfinite(b)) return 0;
    b = fmod(b + 360.0, 360.0);
    return b >= 360.0 ? 0 : b;
}

int web_fa_sector(double bearing_deg) {
    if (!isfinite(bearing_deg)) return 0;
    int s = (int)floor(bearing_deg / WEB_FA_SECTOR_DEG);
    s %= WEB_FA_SECTORS;
    return s < 0 ? s + WEB_FA_SECTORS : s;
}

/* The 4/3-earth radio horizon: d ~ 4.12 sqrt(h) km for h in metres, the
 * two antennas' horizons added (research/adsb/multi-receiver-verification.md). */
double web_fa_horizon_m(double h1_m, double h2_m) {
    if (!isfinite(h1_m) || h1_m < 0) h1_m = 0;
    if (!isfinite(h2_m) || h2_m < 0) h2_m = 0;
    return 4120.0 * (sqrt(h1_m) + sqrt(h2_m));
}

int web_fa_cov_add(web_fa_cov_t *c, double rx_lat, double rx_lon, double lat, double lon) {
    if (!isfinite(lat) || !isfinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180)
        return 0;
    double d = web_fleet_dist_m(rx_lat, rx_lon, lat, lon);
    if (!isfinite(d) || d > web_fa_horizon_m(WEB_FA_RX_AGL_M, WEB_FA_ALT_CEIL_M)) return 0;
    int s = web_fa_sector(web_fa_bearing(rx_lat, rx_lon, lat, lon));
    if (d > c->sec_m[s]) c->sec_m[s] = d;
    if (d > c->max_m) c->max_m = d;
    c->sec_n[s]++;
    c->n++;
    return 1;
}

/* ── the receiver's figures, for the export ────────────────────────── */

static pthread_mutex_t g_rate_mu = PTHREAD_MUTEX_INITIALIZER;
static long long g_rate_ts;
static int g_rate_has;
static double g_rate;
static long long g_prev_ts, g_prev_msgs;

void web_fa_rx_read(struct web_adsb *a, web_fa_rx_t *o) {
    memset(o, 0, sizeof(*o));
    if (!a) return;
    pthread_mutex_lock(&a->mu);
    web_adsb_sh_t sh = a->sh;
    pthread_mutex_unlock(&a->mu);
    if (!sh.seen) return;
    o->seen = 1;
    /* The source's kind: the word before its ':' ("file", "http"),
     * never its path. */
    size_t n = 0;
    while (n < sizeof(o->source) - 1 && sh.src[n] >= 'a' && sh.src[n] <= 'z') n++;
    if (sh.src[n] == ':' || sh.src[n] == '\0') {
        memcpy(o->source, sh.src, n);
        o->source[n] = '\0';
    }
    snprintf(o->state, sizeof(o->state), "%s", sh.state);
    o->ts = sh.ts;
    o->aircraft = sh.aircraft;
    o->messages = sh.messages;
    /* messages/s between this summary and an earlier one 10 .. 900 s
     * before it: one rate a summary, kept until the next. */
    pthread_mutex_lock(&g_rate_mu);
    if (sh.ts != g_rate_ts) {
        long long dt = sh.ts - g_prev_ts, dm = sh.messages - g_prev_msgs;
        if (g_prev_ts > 0 && dt >= 10 && dt <= 900 && dm >= 0) {
            g_rate = (double)dm / (double)dt;
            g_rate_has = isfinite(g_rate);
        } else if (g_prev_ts > 0 && (dt > 900 || dt < 0 || dm < 0)) {
            g_rate_has = 0;
        }
        if (g_prev_ts == 0 || dt >= 10 || dt < 0) {
            g_prev_ts = sh.ts;
            g_prev_msgs = sh.messages;
        }
        g_rate_ts = sh.ts;
    }
    o->has_rate = g_rate_has;
    o->rate = g_rate;
    pthread_mutex_unlock(&g_rate_mu);
}

typedef struct {
    web_fa_cov_t *c;
    double        lat, lon;
} covx_t;

static int cov_one(void *ctx, const web_sdb_apos_t *p) {
    covx_t *x = ctx;
    web_fa_cov_add(x->c, x->lat, x->lon, p->lat, p->lon);
    return 0;
}

void web_fa_cov_read(web_sdb_conn_t *c, double rx_lat, double rx_lon, long long now_s,
                     web_fa_cov_t *o) {
    memset(o, 0, sizeof(*o));
    if (!c || !isfinite(rx_lat) || !isfinite(rx_lon)) return;
    covx_t x = { o, rx_lat, rx_lon };
    int r = web_sdb_adsb_positions(c, now_s - WEB_FA_COV_WINDOW_S, WEB_FA_COV_ROWS, cov_one, &x);
    o->complete = r >= 0 && r < WEB_FA_COV_ROWS && !c->timed_out;
}

/* ── the comparison ────────────────────────────────────────────────── */

static int overlaps(long long a0, long long a1, long long b0, long long b1) {
    return a0 <= b1 && b0 <= a1;
}

/* Heard at overlapping times: each [visit start, last seen + heartbeat]
 * within the window of the other's. */
static int heard_together(const web_fa_obs_t *a, const web_fa_obs_t *b) {
    long long a0 = a->visit_first > 0 ? a->visit_first : a->first;
    long long b0 = b->visit_first > 0 ? b->visit_first : b->first;
    return overlaps(a0, a->last + WEB_FA_HB_S, b0 - WEB_FA_WINDOW_S,
                    b->last + WEB_FA_HB_S + WEB_FA_WINDOW_S);
}

/* Other aircraft B heard within [t0, t1]. */
static int active(const web_fa_site_t *s, long long t0, long long t1) {
    int n = 0;
    for (int i = 0; i < s->nact; i++)
        if (overlaps(s->act_a[i], s->act_b[i] + WEB_FA_HB_S, t0, t1)) n++;
    return n;
}

void web_fa_classify(const web_fa_site_t *sites, int n, const web_fa_obs_t *obs,
                     web_fa_verdict_t *out) {
    memset(out, 0, sizeof(*out));
    out->ref = -1;
    out->inc_a = out->inc_b = -1;
    if (n > WEB_FA_SITES) n = WEB_FA_SITES;
    int nrx = 0;
    for (int i = 0; i < n; i++) if (sites[i].receiver) nrx++;
    /* Two receivers' positions further apart than the aircraft could
     * fly between them. */
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) {
            const web_fa_obs_t *a = &obs[i], *b = &obs[j];
            if (!a->present || !b->present || !a->has_pos || !b->has_pos) continue;
            long long dt = a->pos_ts > b->pos_ts ? a->pos_ts - b->pos_ts : b->pos_ts - a->pos_ts;
            if (dt > WEB_FA_PAIR_DT_S) continue;
            double v = WEB_FA_VMAX_MS;
            if (a->has_gs || b->has_gs) {
                double g = a->has_gs ? a->gs_kt : 0;
                if (b->has_gs && b->gs_kt > g) g = b->gs_kt;
                v = g * KT_MS * 1.25 + 30.0;
            }
            double sep = web_fleet_dist_m(a->lat, a->lon, b->lat, b->lon);
            double allow = v * (double)dt + WEB_FA_POS_TOL_M;
            if (isfinite(sep) && sep > allow && (!out->inconsistent || sep - allow > out->sep_m - out->allow_m)) {
                out->inconsistent = 1;
                out->inc_a = i;
                out->inc_b = j;
                out->sep_m = sep;
                out->allow_m = allow;
            }
        }
    if (nrx < 2) {
        out->single = 1;
        out->verdict = WEB_FA_UNDETERMINED;
        out->why = WEB_FA_B_NONE;
        for (int i = 0; i < n; i++)
            if (obs[i].present) { out->ref = i; out->bstate[i] = WEB_FA_B_REPORTER; break; }
        return;
    }
    /* The reporter: the receiver holding the newest position, else the
     * newest sighting. */
    int ref = -1;
    for (int i = 0; i < n; i++) {
        if (!sites[i].receiver || !obs[i].present) continue;
        if (ref < 0) { ref = i; continue; }
        const web_fa_obs_t *a = &obs[i], *r = &obs[ref];
        if (a->has_pos != r->has_pos ? a->has_pos : a->has_pos ? a->pos_ts > r->pos_ts
                                                              : a->last > r->last)
            ref = i;
    }
    out->ref = ref;
    if (ref < 0) { out->verdict = WEB_FA_UNDETERMINED; return; }
    out->bstate[ref] = WEB_FA_B_REPORTER;
    const web_fa_obs_t *R = &obs[ref];
    int confirmed = 0;
    for (int i = 0; i < n; i++) {
        if (i == ref || !sites[i].receiver || !obs[i].present) continue;
        if (heard_together(R, &obs[i]) || heard_together(&obs[i], R)) {
            out->bstate[i] = WEB_FA_B_HEARD;
            confirmed = 1;
        }
    }
    if (confirmed) {
        out->verdict = WEB_FA_CONFIRMED;
        for (int i = 0; i < n; i++)
            if (i != ref && sites[i].receiver && out->bstate[i] == WEB_FA_B_NONE)
                out->bstate[i] = obs[i].present ? WEB_FA_B_LATER : WEB_FA_B_NONE;
        return;
    }
    int why = 0;
    if (!R->has_pos) why = WEB_FA_B_NOPOS;
    else if (R->on_ground) why = WEB_FA_B_NOALT;
    if (why) {
        out->verdict = WEB_FA_UNDETERMINED;
        out->why = why;
        return;
    }
    long long t = R->pos_ts, t0 = t - WEB_FA_WINDOW_S, t1 = t + WEB_FA_WINDOW_S;
    int any_should = 0, any_out = 0, first_why = 0;
    for (int i = 0; i < n; i++) {
        if (i == ref || !sites[i].receiver) continue;
        const web_fa_site_t *B = &sites[i];
        const web_fa_obs_t *o = &obs[i];
        int st;
        if (o->present && o->last >= t0 - WEB_FA_HB_S) st = WEB_FA_B_LATER;
        else if (B->through < t1) st = WEB_FA_B_PENDING;
        else if (B->cut_at >= t0 - WEB_FA_HB_S) st = WEB_FA_B_CUT;
        else if (active(B, t0, t1) < WEB_FA_HEALTH_MIN) st = WEB_FA_B_QUIET;
        else if (!B->has_pos) st = WEB_FA_B_NOPOS;
        else {
            double d = web_fleet_dist_m(B->lat, B->lon, R->lat, R->lon);
            int s = web_fa_sector(web_fa_bearing(B->lat, B->lon, R->lat, R->lon));
            out->dist_m[i] = d;
            out->sec_max_m[i] = B->cov.sec_m[s];
            if (!R->has_alt) {
                st = WEB_FA_B_NOALT;
            } else {
                double h_ac = R->alt_ft * FT_M - (B->has_alt ? B->alt_m : 0);
                double hz = web_fa_horizon_m(WEB_FA_RX_AGL_M, h_ac);
                out->horizon_m[i] = hz;
                if (B->cov.sec_n[s] < WEB_FA_SECTOR_MIN)
                    st = WEB_FA_B_NOCOV;
                else if (isfinite(d) && d <= WEB_FA_COV_K * B->cov.sec_m[s] &&
                         d <= WEB_FA_COV_K * hz)
                    st = WEB_FA_B_SHOULD;
                else
                    st = WEB_FA_B_OUTSIDE;
            }
        }
        out->bstate[i] = st;
        if (st == WEB_FA_B_SHOULD) any_should = 1;
        else if (st == WEB_FA_B_OUTSIDE || st == WEB_FA_B_NOCOV) any_out = 1;
        else if (!first_why) first_why = st;
    }
    out->verdict = any_should ? WEB_FA_UNCONFIRMED : any_out ? WEB_FA_OUT_OF_COVERAGE
                                                             : WEB_FA_UNDETERMINED;
    out->why = out->verdict == WEB_FA_UNDETERMINED ? first_why : 0;
}

/* ── the sites and their aircraft ──────────────────────────────────── */

typedef struct {
    char         hex[8];
    int          site;
    web_fa_obs_t o;
    char         flight[9], squawk[5], category[3], emergency[12];
    int          has_track, has_rssi, has_msgs;
    double       track, rssi;
    long long    msgs;
} ent_t;

typedef struct {
    char          name[WEB_FLEET_NAME_MAX + 1];
    char          label[WEB_FLEET_STR_MAX + 1];
    web_fa_site_t s;
    web_fa_rx_t   rx;
    int           has_rx;
    long long     rx_age;            /* the summary's age at its answer, -1 none */
    long long     skew;
    int           held;
    long long    *act_a, *act_b;
} asite_t;

typedef struct {
    asite_t   site[WEB_FA_SITES];
    int       n, nrx;
    ent_t    *e;
    int       ne, partial;
    const char *local;
    int       store;
} actx_t;

static void ctx_free(actx_t *x) {
    for (int i = 0; i < x->n; i++) { free(x->site[i].act_a); free(x->site[i].act_b); }
    free(x->e);
}

static ent_t *ent_new(actx_t *x, int site, const char *hex) {
    if (x->ne >= WEB_FA_ROWS_MAX) { x->partial = 1; return NULL; }
    ent_t *e = &x->e[x->ne++];
    memset(e, 0, sizeof(*e));
    snprintf(e->hex, sizeof(e->hex), "%s", hex);
    e->site = site;
    e->o.present = 1;
    return e;
}

static int hex_ok(const char *h) {
    size_t i = h[0] == '~' ? 1 : 0;
    if (strlen(h) != i + 6) return 0;
    for (; h[i]; i++)
        if (!((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'))) return 0;
    return 1;
}

static int self_row(void *ctx, const web_sdb_acf_t *a) {
    actx_t *x = ctx;
    if (!hex_ok(a->hex)) return 0;
    ent_t *e = ent_new(x, 0, a->hex);
    if (!e) return 1;
    e->o.first = a->first_seen;
    e->o.visit_first = a->visit_first;
    e->o.last = a->last_seen;
    e->o.on_ground = a->on_ground;
    if (a->has_pos && isfinite(a->lat) && isfinite(a->lon)) {
        e->o.has_pos = 1;
        e->o.lat = a->lat;
        e->o.lon = a->lon;
        e->o.pos_ts = a->pos_ts;
    }
    int alt_has = a->has_pos ? a->pos_alt_has : a->has_alt;
    int alt = a->has_pos ? a->pos_alt : a->alt;
    if (alt_has) { e->o.has_alt = 1; e->o.alt_ft = alt; }
    if (a->has_gs && isfinite(a->gs)) { e->o.has_gs = 1; e->o.gs_kt = a->gs; }
    snprintf(e->flight, sizeof(e->flight), "%s", a->flight);
    snprintf(e->squawk, sizeof(e->squawk), "%s", a->squawk);
    snprintf(e->category, sizeof(e->category), "%s", a->category);
    snprintf(e->emergency, sizeof(e->emergency), "%s", a->emergency);
    e->has_track = a->has_track && isfinite(a->track);
    e->track = a->track;
    e->has_rssi = a->has_rssi && isfinite(a->rssi);
    e->rssi = a->rssi;
    e->has_msgs = a->has_messages;
    e->msgs = a->messages;
    return 0;
}

#ifdef WITH_SQLITE
/* A stored extra (an object written by the importer) as a record. */
static int extra_rec(const unsigned char *ex, web_jrec_t *rec) {
    if (!ex || ex[0] != '{') return -1;
    char buf[2400];
    int k = snprintf(buf, sizeof(buf), "{\"type\":\"x\"%s%s", ex[1] == '}' ? "" : ",",
                     (const char *)ex + 1);
    if (k < 0 || (size_t)k >= sizeof(buf)) return -1;
    return web_jl_parse(buf, (size_t)k, rec) == WEB_JL_OK ? 0 : -1;
}

static int jnum_in(const web_jrec_t *r, const char *k, double lo, double hi, double *v) {
    return web_jl_num(r, k, v) && isfinite(*v) && *v >= lo && *v <= hi;
}

static void copy_str(const web_jrec_t *r, const char *k, char *out, size_t cap) {
    const char *s = web_jl_str(r, k);
    snprintf(out, cap, "%s", s ? s : "");
}

static void peer_rows(actx_t *x, web_store_t *st, long long now_s) {
    web_jrec_t *rec = malloc(sizeof(*rec));
    if (!rec) { x->partial = 1; return; }
    pthread_mutex_lock(&st->rmu);
    sqlite3_stmt *ps = NULL, *rx = NULL, *ac = NULL, *mt = NULL;
    int ok = sqlite3_prepare_v2(st->rd, "SELECT label,lat,lon,alt,remote_ts,last_ok FROM"
                                " peer_sites WHERE peer=?1", -1, &ps, NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT label,vendor,last_seen,extra FROM peer_sightings"
                                " WHERE peer=?1 AND kind='adsb' AND key='receiver'", -1, &rx,
                                NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT key,label,vendor,first_seen,last_seen,extra FROM"
                                " peer_sightings WHERE peer=?1 AND kind='aircraft' AND"
                                " last_seen>=?2 ORDER BY last_seen DESC LIMIT ?3", -1, &ac,
                                NULL) == SQLITE_OK &&
             sqlite3_prepare_v2(st->rd, "SELECT value FROM meta WHERE name=?1", -1, &mt,
                                NULL) == SQLITE_OK;
    if (!ok) x->partial = 1;
    for (int i = 1; ok && i < x->n; i++) {
        asite_t *g = &x->site[i];
        long long remote_ts = 0, last_ok = 0;
        sqlite3_reset(ps);
        sqlite3_bind_text(ps, 1, g->name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(ps) == SQLITE_ROW) {
            const unsigned char *t = sqlite3_column_text(ps, 0);
            snprintf(g->label, sizeof(g->label), "%s", t ? (const char *)t : "");
            if (sqlite3_column_type(ps, 1) != SQLITE_NULL &&
                sqlite3_column_type(ps, 2) != SQLITE_NULL) {
                g->s.has_pos = 1;
                g->s.lat = sqlite3_column_double(ps, 1);
                g->s.lon = sqlite3_column_double(ps, 2);
                g->s.has_pos = isfinite(g->s.lat) && isfinite(g->s.lon);
            }
            if (sqlite3_column_type(ps, 3) != SQLITE_NULL) {
                g->s.alt_m = sqlite3_column_double(ps, 3);
                g->s.has_alt = isfinite(g->s.alt_m);
            }
            remote_ts = sqlite3_column_int64(ps, 4);
            last_ok = sqlite3_column_int64(ps, 5);
            g->skew = remote_ts > 0 && last_ok > 0 ? remote_ts - last_ok : 0;
        }
        /* Through and cut, from meta, by the peer's clock. */
        char nm[96];
        snprintf(nm, sizeof(nm), "fleet.adsb.%s", g->name);
        sqlite3_reset(mt);
        sqlite3_bind_text(mt, 1, nm, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(mt) == SQLITE_ROW) {
            const unsigned char *v = sqlite3_column_text(mt, 0);
            long long th = 0, cu = 0;
            if (v && sscanf((const char *)v, "%lld %lld", &th, &cu) == 2 && th > 0) {
                g->s.through = th - g->skew - WEB_FA_LAG_S;
                g->s.cut_at = cu > 0 ? cu - g->skew : 0;
            }
        }
        sqlite3_reset(rx);
        sqlite3_bind_text(rx, 1, g->name, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(rx) == SQLITE_ROW) {
            g->s.receiver = 1;
            g->has_rx = 1;
            const unsigned char *l = sqlite3_column_text(rx, 0), *v = sqlite3_column_text(rx, 1);
            snprintf(g->rx.state, sizeof(g->rx.state), "%s", l ? (const char *)l : "");
            snprintf(g->rx.source, sizeof(g->rx.source), "%s", v ? (const char *)v : "");
            g->rx.ts = sqlite3_column_int64(rx, 2);
            /* No state: the peer sent coverage with no decoder summary. */
            g->rx_age = g->rx.state[0] && remote_ts > 0 && remote_ts >= g->rx.ts
                      ? remote_ts - g->rx.ts : -1;
            if (extra_rec(sqlite3_column_text(rx, 3), rec) == 0) {
                double d;
                g->rx.seen = 1;
                if (jnum_in(rec, "aircraft", 0, 1e6, &d)) g->rx.aircraft = (long long)d;
                if (jnum_in(rec, "messages", 0, 1e18, &d)) g->rx.messages = (long long)d;
                if (jnum_in(rec, "msg_rate", 0, 1e6, &d)) { g->rx.has_rate = 1; g->rx.rate = d; }
                if (jnum_in(rec, "positions", 0, 1e12, &d)) g->s.cov.n = (long long)d;
                g->s.cov.complete = web_jl_int(rec, "cov_complete", 0) == 1;
                if (jnum_in(rec, "range_max_m", 0, 2e6, &d)) g->s.cov.max_m = d;
                for (int k = 0; k < WEB_FA_SECTORS; k++) {
                    char kr[16], kn[16];
                    snprintf(kr, sizeof(kr), "r%03d", k * WEB_FA_SECTOR_DEG);
                    snprintf(kn, sizeof(kn), "n%03d", k * WEB_FA_SECTOR_DEG);
                    if (jnum_in(rec, kr, 0, 2e6, &d)) g->s.cov.sec_m[k] = d;
                    if (jnum_in(rec, kn, 0, 1e12, &d)) g->s.cov.sec_n[k] = (long long)d;
                }
            }
        }
        sqlite3_reset(ac);
        sqlite3_bind_text(ac, 1, g->name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(ac, 2, now_s + g->skew - WEB_FA_LIST_S);
        sqlite3_bind_int(ac, 3, WEB_FA_ROWS_PER_PEER);
        while (sqlite3_step(ac) == SQLITE_ROW) {
            const unsigned char *k = sqlite3_column_text(ac, 0);
            if (!k || !hex_ok((const char *)k)) continue;
            ent_t *e = ent_new(x, i, (const char *)k);
            if (!e) break;
            const unsigned char *l = sqlite3_column_text(ac, 1), *v = sqlite3_column_text(ac, 2);
            snprintf(e->flight, sizeof(e->flight), "%s", l ? (const char *)l : "");
            snprintf(e->category, sizeof(e->category), "%s", v ? (const char *)v : "");
            e->o.first = sqlite3_column_int64(ac, 3) - g->skew;
            e->o.last = sqlite3_column_int64(ac, 4) - g->skew;
            e->o.visit_first = e->o.first;
            if (extra_rec(sqlite3_column_text(ac, 5), rec) != 0) continue;
            double d, la, lo;
            if (jnum_in(rec, "visit_first", 1, 4102444800.0, &d) && (long long)d - g->skew >= e->o.first)
                e->o.visit_first = (long long)d - g->skew;
            copy_str(rec, "squawk", e->squawk, sizeof(e->squawk));
            copy_str(rec, "emergency", e->emergency, sizeof(e->emergency));
            e->o.on_ground = web_jl_int(rec, "on_ground", 0) == 1;
            if (jnum_in(rec, "lat", -90, 90, &la) && jnum_in(rec, "lon", -180, 180, &lo) &&
                jnum_in(rec, "pos_ts", 1, 4102444800.0, &d)) {
                e->o.has_pos = 1;
                e->o.lat = la;
                e->o.lon = lo;
                e->o.pos_ts = (long long)d - g->skew;
                if (jnum_in(rec, "pos_alt", -2000, 100000, &d)) { e->o.has_alt = 1; e->o.alt_ft = (int)d; }
            } else if (jnum_in(rec, "alt", -2000, 100000, &d)) {
                e->o.has_alt = 1;
                e->o.alt_ft = (int)d;
            }
            if (jnum_in(rec, "gs", 0, 2000, &d)) { e->o.has_gs = 1; e->o.gs_kt = d; }
            if (jnum_in(rec, "track", 0, 360, &d)) { e->has_track = 1; e->track = d; }
            if (jnum_in(rec, "rssi", -100, 10, &d)) { e->has_rssi = 1; e->rssi = d; }
            if (jnum_in(rec, "messages", 0, 1e15, &d)) { e->has_msgs = 1; e->msgs = (long long)d; }
        }
    }
    sqlite3_finalize(ps);
    sqlite3_finalize(rx);
    sqlite3_finalize(ac);
    sqlite3_finalize(mt);
    pthread_mutex_unlock(&st->rmu);
    free(rec);
}
#endif

static int by_hex_site(const void *pa, const void *pb) {
    const ent_t *a = pa, *b = pb;
    int c = strcmp(a->hex, b->hex);
    return c ? c : a->site - b->site;
}

static int build(web_fleet_t *f, const web_fleet_src_t *src, long long now_s, actx_t *x) {
    memset(x, 0, sizeof(*x));
    x->local = "none";
    x->e = malloc(sizeof(ent_t) * WEB_FA_ROWS_MAX);
    if (!x->e) return -1;
    asite_t *me = &x->site[x->n++];
    snprintf(me->name, sizeof(me->name), "self");
    me->rx_age = -1;
    for (int i = 0; f && i < f->npeer && x->n < WEB_FA_SITES; i++) {
        asite_t *g = &x->site[x->n++];
        snprintf(g->name, sizeof(g->name), "%s", f->peer[i].cfg.name);
        g->rx_age = -1;
    }
    web_loc_t loc;
    memset(&loc, 0, sizeof(loc));
    if (src && src->gnss) {
        web_gnss_sh_t sh;
        web_gnss_site(src->gnss, &loc, &sh);
    }
    if (loc.has && isfinite(loc.lat) && isfinite(loc.lon)) {
        me->s.has_pos = 1;
        me->s.lat = loc.lat;
        me->s.lon = loc.lon;
        if (loc.has_alt && isfinite(loc.alt_m)) { me->s.has_alt = 1; me->s.alt_m = loc.alt_m; }
    }
    if (src && src->adsb) {
        web_fa_rx_read(src->adsb, &me->rx);
        if (me->rx.seen) {
            me->has_rx = 1;
            me->rx_age = now_s >= me->rx.ts ? now_s - me->rx.ts : 0;
        }
    }
    int local_cut = 0;
    if (src && src->sdb && src->sdb->configured) {
        web_sdb_conn_t c;
        memset(&c, 0, sizeof(c));
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) == 0) {
            x->local = "open";
            if (me->s.has_pos) web_fa_cov_read(&c, me->s.lat, me->s.lon, now_s, &me->s.cov);
            int before = x->ne;
            int r = web_sdb_adsb_fleet(&c, now_s - WEB_FA_LIST_S, 0, WEB_FA_ROWS_PER_PEER + 1,
                                       self_row, x);
            local_cut = r < 0 || r > WEB_FA_ROWS_PER_PEER || c.timed_out;
            if (r > WEB_FA_ROWS_PER_PEER && x->ne > before) x->ne--;
            if (local_cut) x->local = "partial";
        } else {
            x->local = "unavailable";
        }
        web_slothdb_close(&c);
    }
    /* This site's data is complete to now, less the writer's lag; a read
     * cut short is a cut. */
    me->s.through = now_s - WEB_FA_LAG_S;
    me->s.cut_at = local_cut ? now_s : 0;
    me->s.receiver = me->has_rx || me->s.cov.n > 0 || x->ne > 0;
#ifdef WITH_SQLITE
    web_store_t *st = f ? f->store : NULL;
    if (st && st->rd && x->n > 1) {
        x->store = 1;
        peer_rows(x, st, now_s);
    } else if (st && st->rd) {
        x->store = 1;
    }
#endif
    qsort(x->e, (size_t)x->ne, sizeof(x->e[0]), by_hex_site);
    /* Each site's activity: every address it held. */
    for (int i = 0; i < x->n; i++) {
        asite_t *g = &x->site[i];
        int c = 0;
        for (int k = 0; k < x->ne; k++) if (x->e[k].site == i) c++;
        g->held = c;
        if (!c) continue;
        g->act_a = malloc(sizeof(long long) * (size_t)c);
        g->act_b = malloc(sizeof(long long) * (size_t)c);
        if (!g->act_a || !g->act_b) { x->partial = 1; continue; }
        int j = 0;
        for (int k = 0; k < x->ne; k++)
            if (x->e[k].site == i) {
                const web_fa_obs_t *o = &x->e[k].o;
                g->act_a[j] = o->visit_first > 0 ? o->visit_first : o->first;
                g->act_b[j] = o->last;
                j++;
            }
        g->s.nact = j;
        g->s.act_a = g->act_a;
        g->s.act_b = g->act_b;
    }
    for (int i = 0; i < x->n; i++) if (x->site[i].s.receiver) x->nrx++;
    return 0;
}

/* One address's group: its rows [at, at + cnt) into per-site
 * observations, and the verdict. */
static void group_verdict(const actx_t *x, int at, int cnt, web_fa_obs_t *obs,
                          web_fa_verdict_t *v) {
    web_fa_site_t sites[WEB_FA_SITES];
    memset(obs, 0, sizeof(web_fa_obs_t) * WEB_FA_SITES);
    for (int i = 0; i < x->n; i++) sites[i] = x->site[i].s;
    for (int k = at; k < at + cnt; k++) obs[x->e[k].site] = x->e[k].o;
    web_fa_classify(sites, x->n, obs, v);
}

typedef struct {
    int       at, cnt;
    long long last;
    web_fa_verdict_t v;
} grp_t;

static int by_rank(const void *pa, const void *pb) {
    const grp_t *a = pa, *b = pb;
    int ra = a->v.verdict == WEB_FA_UNCONFIRMED ? 0 : a->v.inconsistent ? 1 : 2;
    int rb = b->v.verdict == WEB_FA_UNCONFIRMED ? 0 : b->v.inconsistent ? 1 : 2;
    if (ra != rb) return ra - rb;
    if (a->last != b->last) return a->last < b->last ? 1 : -1;
    return a->at - b->at;
}

static grp_t *groups(const actx_t *x, int *ng) {
    *ng = 0;
    grp_t *g = malloc(sizeof(grp_t) * (size_t)(x->ne ? x->ne : 1));
    if (!g) return NULL;
    web_fa_obs_t obs[WEB_FA_SITES];
    for (int k = 0; k < x->ne;) {
        int j = k;
        long long last = 0;
        while (j < x->ne && !strcmp(x->e[j].hex, x->e[k].hex)) {
            if (x->e[j].o.last > last) last = x->e[j].o.last;
            j++;
        }
        grp_t *o = &g[(*ng)++];
        o->at = k;
        o->cnt = j - k;
        o->last = last;
        group_verdict(x, k, j - k, obs, &o->v);
        k = j;
    }
    qsort(g, (size_t)*ng, sizeof(g[0]), by_rank);
    return g;
}

/* ── the answer ────────────────────────────────────────────────────── */

static void jnum(web_jw_t *w, int has, double v, int dp) {
    if (!has || !isfinite(v)) { web_jw_raw(w, "null"); return; }
    char b[48];
    snprintf(b, sizeof(b), "%.*f", dp, v);
    web_jw_raw(w, b);
}

static void jll(web_jw_t *w, int has, long long v) {
    if (has) web_jw_int(w, v); else web_jw_raw(w, "null");
}

static void jstr(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s); else web_jw_raw(w, "null");
}

static void counts_json(web_jw_t *w, const grp_t *g, int ng) {
    int c[WEB_FA_NVERDICT] = { 0 }, inc = 0;
    for (int i = 0; i < ng; i++) { c[g[i].v.verdict]++; inc += g[i].v.inconsistent; }
    for (int v = 0; v < WEB_FA_NVERDICT; v++) {
        web_jw_raw(w, v ? ",\"" : "{\"");
        web_jw_raw(w, VERDICT_WORD[v]);
        web_jw_raw(w, "\":");
        web_jw_int(w, c[v]);
    }
    web_jw_raw(w, ",\"inconsistent\":");
    web_jw_int(w, inc);
    web_jw_raw(w, "}");
}

void web_fa_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                          web_jw_t *w) {
    actx_t *x = malloc(sizeof(*x));
    if (!x) { web_jw_raw(w, "null"); return; }
    if (build(f, src, now_s, x) != 0) { free(x); web_jw_raw(w, "null"); return; }
    int ng = 0;
    grp_t *g = groups(x, &ng);
    web_jw_raw(w, "{\"receivers\":");       web_jw_int(w, x->nrx);
    web_jw_raw(w, ",\"single_receiver\":"); web_jw_raw(w, x->nrx < 2 ? "true" : "false");
    web_jw_raw(w, ",\"aircraft\":");        web_jw_int(w, g ? ng : 0);
    web_jw_raw(w, ",\"counts\":");
    counts_json(w, g, g ? ng : 0);
    web_jw_raw(w, "}");
    free(g);
    ctx_free(x);
    free(x);
}

static void site_json(web_jw_t *w, const actx_t *x, int i, long long now_s) {
    const asite_t *g = &x->site[i];
    const web_fa_site_t *s = &g->s;
    web_jw_raw(w, "{\"site\":");         web_jw_str(w, g->name);
    web_jw_raw(w, ",\"label\":");        jstr(w, g->label);
    web_jw_raw(w, ",\"receiver\":");     web_jw_raw(w, s->receiver ? "true" : "false");
    web_jw_raw(w, ",\"source\":");       jstr(w, g->has_rx ? g->rx.source : NULL);
    web_jw_raw(w, ",\"state\":");        jstr(w, g->has_rx ? g->rx.state : NULL);
    web_jw_raw(w, ",\"summary_age_s\":"); jll(w, g->rx_age >= 0, g->rx_age);
    web_jw_raw(w, ",\"fresh\":");
    web_jw_raw(w, g->rx_age >= 0 && g->rx_age <= WEB_FA_FRESH_S ? "true" : "false");
    web_jw_raw(w, ",\"aircraft_now\":"); jll(w, g->rx.seen, g->rx.aircraft);
    web_jw_raw(w, ",\"messages\":");     jll(w, g->rx.seen, g->rx.messages);
    web_jw_raw(w, ",\"msg_rate\":");     jnum(w, g->rx.seen && g->rx.has_rate, g->rx.rate, 1);
    web_jw_raw(w, ",\"lat\":");          jnum(w, s->has_pos, s->lat, 7);
    web_jw_raw(w, ",\"lon\":");          jnum(w, s->has_pos, s->lon, 7);
    web_jw_raw(w, ",\"alt_m\":");        jnum(w, s->has_alt, s->alt_m, 1);
    web_jw_raw(w, ",\"skew_s\":");       jll(w, i > 0, g->skew);
    web_jw_raw(w, ",\"through_age_s\":");
    jll(w, s->through > 0, now_s > s->through ? now_s - s->through : 0);
    web_jw_raw(w, ",\"cut_age_s\":");
    jll(w, s->cut_at > 0, now_s > s->cut_at ? now_s - s->cut_at : 0);
    web_jw_raw(w, ",\"held\":");         web_jw_int(w, g->held);
    web_jw_raw(w, ",\"positions\":");    web_jw_int(w, s->cov.n);
    web_jw_raw(w, ",\"cov_complete\":"); web_jw_raw(w, s->cov.complete ? "true" : "false");
    web_jw_raw(w, ",\"range_max_m\":");  jnum(w, s->cov.n > 0, s->cov.max_m, 0);
    web_jw_raw(w, ",\"sectors\":[");
    for (int k = 0; k < WEB_FA_SECTORS; k++) {
        web_jw_raw(w, k ? ",{\"from\":" : "{\"from\":");
        web_jw_int(w, k * WEB_FA_SECTOR_DEG);
        web_jw_raw(w, ",\"max_m\":");
        jnum(w, s->cov.sec_n[k] > 0, s->cov.sec_m[k], 0);
        web_jw_raw(w, ",\"n\":");
        web_jw_int(w, s->cov.sec_n[k]);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
}

static void ac_json(web_jw_t *w, const actx_t *x, const grp_t *g) {
    const web_fa_verdict_t *v = &g->v;
    /* The row the summary is taken from: the reporter's, else the
     * newest. */
    const ent_t *best = &x->e[g->at];
    for (int k = g->at; k < g->at + g->cnt; k++) {
        if (v->ref >= 0 && x->e[k].site == v->ref) { best = &x->e[k]; break; }
        if (x->e[k].o.last > best->o.last) best = &x->e[k];
    }
    web_jw_raw(w, "{\"hex\":");        web_jw_str(w, best->hex);
    web_jw_raw(w, ",\"flight\":");     jstr(w, best->flight);
    web_jw_raw(w, ",\"squawk\":");     jstr(w, best->squawk);
    web_jw_raw(w, ",\"category\":");   jstr(w, best->category);
    web_jw_raw(w, ",\"emergency\":");
    jstr(w, strcmp(best->emergency, "none") ? best->emergency : NULL);
    web_jw_raw(w, ",\"alt\":");        jll(w, best->o.has_alt, best->o.alt_ft);
    web_jw_raw(w, ",\"gs\":");         jnum(w, best->o.has_gs, best->o.gs_kt, 1);
    web_jw_raw(w, ",\"track\":");      jnum(w, best->has_track, best->track, 1);
    web_jw_raw(w, ",\"lat\":");        jnum(w, best->o.has_pos, best->o.lat, 5);
    web_jw_raw(w, ",\"lon\":");        jnum(w, best->o.has_pos, best->o.lon, 5);
    web_jw_raw(w, ",\"pos_ts\":");     jll(w, best->o.has_pos, best->o.pos_ts);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, g->last);
    web_jw_raw(w, ",\"verdict\":");    web_jw_str(w, web_fa_verdict_word(v->verdict));
    web_jw_raw(w, ",\"why\":");
    if (v->single) web_jw_str(w, "single_receiver");
    else if (v->verdict == WEB_FA_UNDETERMINED && v->why) web_jw_str(w, web_fa_bstate_word(v->why));
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"ref\":");
    if (v->ref >= 0) web_jw_str(w, x->site[v->ref].name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"inconsistent\":"); web_jw_raw(w, v->inconsistent ? "true" : "false");
    web_jw_raw(w, ",\"separation_m\":"); jnum(w, v->inconsistent, v->sep_m, 0);
    web_jw_raw(w, ",\"allowed_m\":");    jnum(w, v->inconsistent, v->allow_m, 0);
    web_jw_raw(w, ",\"seen\":[");
    for (int k = g->at; k < g->at + g->cnt; k++) {
        const ent_t *e = &x->e[k];
        const asite_t *s = &x->site[e->site];
        web_jw_raw(w, k > g->at ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, s->name);
        web_jw_raw(w, ",\"first_seen\":");  web_jw_int(w, e->o.first);
        web_jw_raw(w, ",\"visit_first\":"); web_jw_int(w, e->o.visit_first);
        web_jw_raw(w, ",\"last_seen\":");   web_jw_int(w, e->o.last);
        web_jw_raw(w, ",\"rssi\":");        jnum(w, e->has_rssi, e->rssi, 1);
        web_jw_raw(w, ",\"messages\":");    jll(w, e->has_msgs, e->msgs);
        web_jw_raw(w, ",\"pos\":");         web_jw_raw(w, e->o.has_pos ? "true" : "false");
        web_jw_raw(w, ",\"range_m\":");
        jnum(w, e->o.has_pos && s->s.has_pos,
             e->o.has_pos && s->s.has_pos ? web_fleet_dist_m(s->s.lat, s->s.lon, e->o.lat, e->o.lon)
                                          : 0, 0);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "],\"peers\":[");
    int np = 0;
    for (int i = 0; i < x->n; i++) {
        if (!x->site[i].s.receiver || i == v->ref) continue;
        web_jw_raw(w, np++ ? ",{\"site\":" : "{\"site\":");
        web_jw_str(w, x->site[i].name);
        web_jw_raw(w, ",\"state\":");      web_jw_str(w, web_fa_bstate_word(v->bstate[i]));
        int geo = v->dist_m[i] > 0;
        web_jw_raw(w, ",\"dist_m\":");     jnum(w, geo, v->dist_m[i], 0);
        web_jw_raw(w, ",\"sector_max_m\":"); jnum(w, geo, v->sec_max_m[i], 0);
        web_jw_raw(w, ",\"horizon_m\":");  jnum(w, v->horizon_m[i] > 0, v->horizon_m[i], 0);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, "]}");
}

static int parse_q(const char *q, int *limit, const char **why) {
    *limit = WEB_FA_LIMIT_DEF;
    if (!q || !q[0]) return 0;
    int seen = 0;
    for (const char *p = q; *p;) {
        size_t n = strcspn(p, "&");
        if (n > 6 && !strncmp(p, "limit=", 6) && !seen) {
            seen = 1;
            long long v = 0;
            for (size_t i = 6; i < n; i++) {
                if (p[i] < '0' || p[i] > '9' || v > 100000) { *why = "bad_limit"; return -1; }
                v = v * 10 + (p[i] - '0');
            }
            if (v < 1 || v > WEB_FA_LIMIT_MAX) { *why = "bad_limit"; return -1; }
            *limit = (int)v;
        } else {
            *why = "unknown_parameter";
            return -1;
        }
        p += n;
        if (*p == '&') p++;
    }
    return 0;
}

#define BODY_MAX (1u << 20)

int web_fleet_aircraft_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
                             long long now_s, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    int limit;
    const char *why = NULL;
    char *buf = malloc(BODY_MAX);
    if (!buf) return -1;
    if (parse_q(query, &limit, &why) != 0) {
        *len = web_series_error_json(why, buf, BODY_MAX);
        *status = 400;
        *body = buf;
        return *len ? 0 : -1;
    }
    actx_t *x = malloc(sizeof(*x));
    if (!x || build(f, src, now_s, x) != 0) {
        if (x) ctx_free(x);
        free(x);
        free(buf);
        return -1;
    }
    int ng = 0;
    grp_t *g = groups(x, &ng);
    if (!g) { ctx_free(x); free(x); free(buf); return -1; }
    web_jw_t w;
    web_jw_init(&w, buf, BODY_MAX);
    web_jw_raw(&w, "{\"now\":");             web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"local\":");           web_jw_str(&w, x->local);
    web_jw_raw(&w, ",\"store\":");           web_jw_raw(&w, x->store ? "true" : "false");
    web_jw_raw(&w, ",\"receivers\":");       web_jw_int(&w, x->nrx);
    web_jw_raw(&w, ",\"single_receiver\":"); web_jw_raw(&w, x->nrx < 2 ? "true" : "false");
    web_jw_raw(&w, ",\"window_s\":");        web_jw_int(&w, WEB_FA_WINDOW_S);
    web_jw_raw(&w, ",\"heartbeat_s\":");     web_jw_int(&w, WEB_FA_HB_S);
    web_jw_raw(&w, ",\"list_s\":");          web_jw_int(&w, WEB_FA_LIST_S);
    web_jw_raw(&w, ",\"cov_window_s\":");    web_jw_int(&w, WEB_FA_COV_WINDOW_S);
    web_jw_raw(&w, ",\"k\":");               jnum(&w, 1, WEB_FA_COV_K, 2);
    web_jw_raw(&w, ",\"rx_agl_m\":");        jnum(&w, 1, WEB_FA_RX_AGL_M, 0);
    web_jw_raw(&w, ",\"sector_min\":");      web_jw_int(&w, WEB_FA_SECTOR_MIN);
    web_jw_raw(&w, ",\"health_min\":");      web_jw_int(&w, WEB_FA_HEALTH_MIN);
    web_jw_raw(&w, ",\"sites\":[");
    for (int i = 0; i < x->n; i++) {
        if (i) web_jw_raw(&w, ",");
        site_json(&w, x, i, now_s);
    }
    web_jw_raw(&w, "],\"counts\":");
    counts_json(&w, g, ng);
    web_jw_raw(&w, ",\"aircraft\":[");
    for (int i = 0; i < ng && i < limit; i++) {
        if (i) web_jw_raw(&w, ",");
        ac_json(&w, x, &g[i]);
    }
    web_jw_raw(&w, "],\"total\":");          web_jw_int(&w, ng);
    web_jw_raw(&w, ",\"partial\":");         web_jw_raw(&w, x->partial ? "true" : "false");
    web_jw_raw(&w, ",\"basis\":{\"unconfirmed\":");
    web_jw_str(&w, "ADS-B carries no authentication, so a transmitter can inject an "
                   "aircraft that does not exist (Costin and Francillon 2012; Schafer, "
                   "Lenders and Martinovic 2013: research/adsb/emergency-squawks.md). "
                   "Strohmeier, Lenders and Martinovic's survey lists, among plausibility "
                   "checks, investigating aircraft that appear well within a receiver's "
                   "range and a per-station model of where it hears aircraft "
                   "(research/adsb/multi-receiver-verification.md): here, a second "
                   "receiver that demonstrably hears that sector and was hearing other "
                   "aircraft did not hear this one. A suspicion, never a detection: "
                   "terrain, the antenna and a weak transponder all shadow a receiver.");
    web_jw_raw(&w, ",\"inconsistent\":");
    web_jw_str(&w, "The survey's mobility check: two receivers' positions for one address "
                   "further apart than the aircraft could fly in the time between them.");
    web_jw_raw(&w, ",\"horizon\":");
    web_jw_str(&w, "d = 4.12 (sqrt h1 + sqrt h2) km, h in metres, the 4/3-earth radio "
                   "horizon (research/adsb/multi-receiver-verification.md); the antenna "
                   "is taken at 10 m and the aircraft's height as its altitude less the "
                   "site's: both choices.");
    web_jw_raw(&w, ",\"thresholds\":");
    web_jw_str(&w, "Choices, no source: 0.8 of the sector's farthest position and of the "
                   "horizon, at least 10 positions in the sector over 24 h, 30-degree "
                   "sectors, at least 2 other aircraft heard in the window, a 120 s "
                   "window plus sloth's 300 s write heartbeat, 2 km and ground speed x "
                   "1.25 + 30 m/s for the mobility check.");
    web_jw_raw(&w, "}}\n");
    free(g);
    ctx_free(x);
    free(x);
    if (w.overflow) {
        *len = web_series_error_json("too_large", buf, BODY_MAX);
        *status = 503;
    } else {
        *len = w.len;
        *status = 200;
    }
    *body = buf;
    return *len ? 0 : -1;
}
