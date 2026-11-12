/* GNSS across the owner's fleet (#192 I6). Contract and basis:
 * web_fleetgnss.h, docs/wiki/fleet.md "GNSS: regional or local",
 * research/gnss/. */
#include "web_fleetgnss.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_alertkb.h"
#include "web_gnss.h"
#include "web_series.h"
#include "web_slothdb.h"
#include "web_store.h"

#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif

#define T_MAX 4102444800LL           /* 2100-01-01 */

/* ── the words ─────────────────────────────────────────────────────── */

static const char *const CLASS_WORD[WEB_FG_NCLASS] = {
    "interference", "spoof", "time", "position",
};

const char *web_fg_class_word(int cls) {
    return cls >= 0 && cls < WEB_FG_NCLASS ? CLASS_WORD[cls] : "";
}

const char *web_fg_verdict_word(int v) {
    return v == WEB_FG_REGIONAL ? "regional" : v == WEB_FG_LOCAL ? "local" : "undetermined";
}

static const struct { const char *type; int cls, alert; } TYPES[] = {
    { "GNSS_JAMMING", WEB_FG_INTERFERENCE, 1 },
    { "GNSS_SPOOF_SUSPECT", WEB_FG_SPOOF, 1 },
    { "GNSS_TIME_JUMP", WEB_FG_TIME, 1 },
    { "GNSS_POSITION_JUMP", WEB_FG_POSITION, 1 },
    { "JAM_IND", WEB_FG_INTERFERENCE, 0 },
    { "CN0_DROP", WEB_FG_INTERFERENCE, 0 },
};

int web_fg_class_of(const char *type) {
    for (size_t i = 0; type && i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
        if (!strcmp(TYPES[i].type, type)) return TYPES[i].cls;
    return -1;
}

int web_fg_is_alert(const char *type) {
    for (size_t i = 0; type && i < sizeof(TYPES) / sizeof(TYPES[0]); i++)
        if (!strcmp(TYPES[i].type, type)) return TYPES[i].alert;
    return 0;
}

/* ── the samples ───────────────────────────────────────────────────── */

web_fg_t *web_fg_new(void) {
    return calloc(1, sizeof(web_fg_t));
}

void web_fg_free(web_fg_t *g) {
    free(g);
}

int web_fg_slot(web_fg_t *g, const char *name) {
    if (!g || !name || !name[0] || strlen(name) > WEB_FLEET_NAME_MAX) return -1;
    int self = !strcmp(name, "self");
    if (self) {
        if (!g->site[0].used) {
            memset(&g->site[0], 0, sizeof(g->site[0]));
            g->site[0].used = 1;
            g->site[0].se_open[0] = g->site[0].se_open[1] = -1;
            snprintf(g->site[0].name, sizeof(g->site[0].name), "self");
        }
        return 0;
    }
    for (int i = 1; i < WEB_FG_SITES; i++)
        if (g->site[i].used && !strcmp(g->site[i].name, name)) return i;
    for (int i = 1; i < WEB_FG_SITES; i++)
        if (!g->site[i].used) {
            memset(&g->site[i], 0, sizeof(g->site[i]));
            g->site[i].used = 1;
            g->site[i].se_open[0] = g->site[i].se_open[1] = -1;
            snprintf(g->site[i].name, sizeof(g->site[i].name), "%s", name);
            return i;
        }
    return -1;
}

/* A sample at t that was observing extends the newest span when that
 * span is still open and t is at most gap after it; otherwise it opens
 * one, the oldest dropped when full. A sample that was not observing
 * closes the newest span, so the next one cannot bridge it. A clock that
 * went back inside the newest span changes nothing. */
static void span_add(long long *s, long long *e, int *n, int *open, int on, long long t,
                     long long gap) {
    if (!on) { *open = 0; return; }
    if (*n > 0 && *open && t >= s[*n - 1] && t <= e[*n - 1]) return;
    if (*n > 0 && *open && t > e[*n - 1] && t - e[*n - 1] <= gap) {
        e[*n - 1] = t;
        return;
    }
    if (*n == WEB_FG_SPANS) {
        memmove(s, s + 1, sizeof(s[0]) * (WEB_FG_SPANS - 1));
        memmove(e, e + 1, sizeof(e[0]) * (WEB_FG_SPANS - 1));
        (*n)--;
    }
    s[*n] = e[*n] = t;
    (*n)++;
    *open = 1;
}

static double med_d(double *v, int n);

/* The sample's flags against the ring before it (the newest of which is
 * the previous sample): JAM_IND, the indicator at or above WEB_FG_JAM_IND;
 * CN0_DROP, the tracked median WEB_FG_CN0_DROP_DB under the median of the
 * hour before, the flagged samples left out of it (so a standing drop is
 * not absorbed into its own reference, as the jamming rule holds its
 * onset baseline). A sample tracking nothing while its sky is listed
 * counts as 0 dB-Hz, the rule's own reading. *cn0_ok: the drop test had
 * its history, so a drop would have shown. */
static unsigned char sample_flag(const web_fg_site_t *fs, const web_fg_sample_t *r,
                                 int *cn0_ok) {
    unsigned char f = 0;
    *cn0_ok = 0;
    if (!r->fresh) return 0;
    if (r->jam >= WEB_FG_JAM_IND) f |= 1;
    if (!r->has_trk || r->sats_view <= 0) return f;
    double hist[WEB_FG_RING];
    int h = 0;
    for (int j = 0; j < fs->n; j++) {
        const web_fg_sample_t *o = &fs->ring[(fs->head + WEB_FG_RING - fs->n + j) % WEB_FG_RING];
        if (o->fresh && o->has_trk && o->sats_view > 0 && !(o->flag & 2) &&
            o->t >= r->t - WEB_FG_HIST_S && o->t < r->t)
            hist[h++] = o->tracked > 0 ? o->cn0_med : 0;
    }
    if (h < WEB_FG_HIST_MIN) return f;
    *cn0_ok = 1;
    double v = r->tracked > 0 ? r->cn0_med : 0;
    if (v <= med_d(hist, h) - WEB_FG_CN0_DROP_DB) f |= 2;
    return f;
}

/* Runs of a word's flagged samples no further apart than the gap are one
 * event; the oldest is dropped when full, and any older than the week. */
static void se_note(web_fg_site_t *s, unsigned char flag, long long t, long long gap) {
    int drop = 0;
    while (drop < s->nse && s->se_b[drop] < t - WEB_FG_EVENTS_S) drop++;
    for (int w = 0; w < 2; w++) {
        int k = s->se_open[w];
        if (!(flag & (1u << w))) { s->se_open[w] = -1; continue; }
        if (k >= 0 && k < s->nse && s->se_w[k] == w && t >= s->se_b[k] &&
            t - s->se_b[k] <= gap) {
            s->se_b[k] = t;
            continue;
        }
        if (s->nse - drop == WEB_FG_SEV) drop++;
        if (drop) {
            memmove(s->se_a, s->se_a + drop, sizeof(s->se_a[0]) * (size_t)(s->nse - drop));
            memmove(s->se_b, s->se_b + drop, sizeof(s->se_b[0]) * (size_t)(s->nse - drop));
            memmove(s->se_w, s->se_w + drop, sizeof(s->se_w[0]) * (size_t)(s->nse - drop));
            s->nse -= drop;
            for (int v = 0; v < 2; v++)
                s->se_open[v] = s->se_open[v] >= drop ? s->se_open[v] - drop : -1;
            drop = 0;
        }
        s->se_a[s->nse] = s->se_b[s->nse] = t;
        s->se_w[s->nse] = (unsigned char)w;
        s->se_open[w] = s->nse++;
    }
}


/* The reference's median against the one last announced (#196): first
 * had, it is the anchor; past WEB_FG_K x eph from it, the move is
 * recorded and the median is the anchor from then. Once a
 * WEB_FG_REF_EVERY_S, so the sort is cheap. */
static void ref_note(web_fg_site_t *s, long long t, double eph) {
    if (s->nref < WEB_FG_REF_MIN) return;
    double *a = malloc(sizeof(double) * (size_t)s->nref);
    double *b = malloc(sizeof(double) * (size_t)s->nref);
    if (a && b) {
        for (int i = 0; i < s->nref; i++) { a[i] = s->ref_lat[i]; b[i] = s->ref_lon[i]; }
        double la = med_d(a, s->nref), lo = med_d(b, s->nref);
        if (isfinite(la) && isfinite(lo)) {
            if (!s->has_anc) {
                s->has_anc = 1;
                s->anc_lat = la;
                s->anc_lon = lo;
            } else {
                double d = web_fleet_dist_m(s->anc_lat, s->anc_lon, la, lo);
                if (d > WEB_FG_K * eph) {
                    s->moved_at = t;
                    s->moved_m = d;
                    s->anc_lat = la;
                    s->anc_lon = lo;
                }
            }
        }
    }
    free(a);
    free(b);
}

void web_fg_add(web_fg_t *g, int slot, const web_fg_sample_t *smp, long long gap_s) {
    if (!g || slot < 0 || slot >= WEB_FG_SITES) return;
    web_fg_site_t *s = &g->site[slot];
    int cn0_ok;
    web_fg_sample_t r = *smp;
    r.flag = sample_flag(s, &r, &cn0_ok);
    s->ring[s->head] = r;
    s->head = (s->head + 1) % WEB_FG_RING;
    if (s->n < WEB_FG_RING) s->n++;
    se_note(s, r.flag, r.t, gap_s);
    span_add(s->rx_s, s->rx_e, &s->nrx, &s->rx_open, cn0_ok, r.t, gap_s);
    span_add(s->ev_s, s->ev_e, &s->nev, &s->ev_open, r.evok, r.t, gap_s);
    if (r.fresh && r.has_fix && r.mode >= 2 && r.has_eph && isfinite(r.eph) && r.eph > 0 &&
        isfinite(r.lat) && isfinite(r.lon) &&
        (s->nref == 0 || r.t - s->last_ref >= WEB_FG_REF_EVERY_S)) {
        s->ref_ts[s->rhead] = r.t;
        s->ref_lat[s->rhead] = r.lat;
        s->ref_lon[s->rhead] = r.lon;
        s->rhead = (s->rhead + 1) % WEB_FG_REF;
        if (s->nref < WEB_FG_REF) s->nref++;
        s->last_ref = r.t;
        ref_note(s, r.t, r.eph);
    }
    s->dirty = 1;
}

/* ── the saved state ───────────────────────────────────────────────── */

int web_fg_state_text(const web_fg_site_t *s, char *out, size_t cap) {
    size_t o = 0;
#define P(...) do { int k_ = snprintf(out + o, o < cap ? cap - o : 0, __VA_ARGS__); \
                    if (k_ < 0 || (size_t)k_ >= (o < cap ? cap - o : 0)) return -1; \
                    o += (size_t)k_; } while (0)
    P("1 rx %d", s->nrx);
    for (int i = 0; i < s->nrx; i++) P(" %lld %lld", s->rx_s[i], s->rx_e[i]);
    P(" ev %d", s->nev);
    for (int i = 0; i < s->nev; i++) P(" %lld %lld", s->ev_s[i], s->ev_e[i]);
    P(" ref %d %lld", s->nref, s->last_ref);
    /* Oldest first, so a parse refills the ring in order. */
    for (int j = 0; j < s->nref; j++) {
        int i = (s->rhead + WEB_FG_REF - s->nref + j) % WEB_FG_REF;
        P(" %lld %.7f %.7f", s->ref_ts[i], s->ref_lat[i], s->ref_lon[i]);
    }
    P(" se %d", s->nse);
    for (int i = 0; i < s->nse; i++) P(" %lld %lld %d", s->se_a[i], s->se_b[i], s->se_w[i]);
#undef P
    return (int)o;
}

static int take_ll(const char **p, long long lo, long long hi, long long *v) {
    char *e;
    if (**p != ' ') return -1;
    long long x = strtoll(*p + 1, &e, 10);
    if (e == *p + 1 || x < lo || x > hi) return -1;
    *p = e;
    *v = x;
    return 0;
}

static int take_d(const char **p, double lo, double hi, double *v) {
    char *e;
    if (**p != ' ') return -1;
    double x = strtod(*p + 1, &e);
    if (e == *p + 1 || !isfinite(x) || x < lo || x > hi) return -1;
    *p = e;
    *v = x;
    return 0;
}

static int take_word(const char **p, const char *w) {
    size_t n = strlen(w);
    if (**p != ' ' || strncmp(*p + 1, w, n) != 0) return -1;
    *p += 1 + n;
    return 0;
}

static int take_spans(const char **p, const char *w, long long *s, long long *e, int *n) {
    long long v;
    if (take_word(p, w) || take_ll(p, 0, WEB_FG_SPANS, &v)) return -1;
    *n = (int)v;
    for (int i = 0; i < *n; i++)
        if (take_ll(p, 0, T_MAX, &s[i]) || take_ll(p, s[i], T_MAX, &e[i]) ||
            (i > 0 && s[i] < e[i - 1]))
            return -1;
    return 0;
}

int web_fg_state_parse(web_fg_site_t *s, const char *text) {
    if (!text || strncmp(text, "1", 1) != 0) return -1;
    web_fg_site_t *t = calloc(1, sizeof(*t));
    if (!t) return -1;
    const char *p = text + 1;
    long long v;
    int ok = take_spans(&p, "rx", t->rx_s, t->rx_e, &t->nrx) == 0 &&
             take_spans(&p, "ev", t->ev_s, t->ev_e, &t->nev) == 0 &&
             take_word(&p, "ref") == 0 && take_ll(&p, 0, WEB_FG_REF, &v) == 0 &&
             take_ll(&p, 0, T_MAX, &t->last_ref) == 0;
    if (ok) t->nref = (int)v;
    for (int i = 0; ok && i < t->nref; i++)
        ok = take_ll(&p, 0, T_MAX, &t->ref_ts[i]) == 0 &&
             take_d(&p, -90, 90, &t->ref_lat[i]) == 0 &&
             take_d(&p, -180, 180, &t->ref_lon[i]) == 0;
    ok = ok && take_word(&p, "se") == 0 && take_ll(&p, 0, WEB_FG_SEV, &v) == 0;
    if (ok) t->nse = (int)v;
    for (int i = 0; ok && i < t->nse; i++) {
        long long w;
        ok = take_ll(&p, 0, T_MAX, &t->se_a[i]) == 0 &&
             take_ll(&p, t->se_a[i], T_MAX, &t->se_b[i]) == 0 && take_ll(&p, 0, 1, &w) == 0;
        if (ok) t->se_w[i] = (unsigned char)w;
    }
    if (ok && *p) ok = 0;
    if (ok) {
        t->rhead = t->nref % WEB_FG_REF;
        memcpy(s->rx_s, t->rx_s, sizeof(s->rx_s));
        memcpy(s->rx_e, t->rx_e, sizeof(s->rx_e));
        memcpy(s->ev_s, t->ev_s, sizeof(s->ev_s));
        memcpy(s->ev_e, t->ev_e, sizeof(s->ev_e));
        s->nrx = t->nrx;
        s->nev = t->nev;
        memcpy(s->ref_ts, t->ref_ts, sizeof(s->ref_ts));
        memcpy(s->ref_lat, t->ref_lat, sizeof(s->ref_lat));
        memcpy(s->ref_lon, t->ref_lon, sizeof(s->ref_lon));
        s->nref = t->nref;
        s->rhead = t->rhead;
        s->last_ref = t->last_ref;
        memcpy(s->se_a, t->se_a, sizeof(s->se_a));
        memcpy(s->se_b, t->se_b, sizeof(s->se_b));
        memcpy(s->se_w, t->se_w, sizeof(s->se_w));
        s->nse = t->nse;
        /* Nothing loaded is extended: the time between the save and now
         * was not seen. */
        s->se_open[0] = s->se_open[1] = -1;
        s->rx_open = s->ev_open = 0;
    }
    free(t);
    return ok ? 0 : -1;
}

int web_fg_ref_text(const web_fg_site_t *s, char *out, size_t cap) {
    if (!s->has_anc) return -1;
    int n = snprintf(out, cap, "%.7f %.7f %lld %.1f", s->anc_lat, s->anc_lon, s->moved_at,
                     s->moved_m);
    return n < 0 || (size_t)n >= cap ? -1 : n;
}

int web_fg_ref_parse(web_fg_site_t *s, const char *text) {
    if (!text || !*text) return -1;
    char *e;
    const char *p = text;
    double la = strtod(p, &e);
    if (e == p || *e != ' ' || !isfinite(la) || la < -90 || la > 90) return -1;
    p = e;
    double lo = strtod(p, &e);
    if (e == p || *e != ' ' || !isfinite(lo) || lo < -180 || lo > 180) return -1;
    p = e;
    long long mt = 0;
    if (take_ll(&p, 0, T_MAX, &mt) != 0) return -1;
    double mm = 0;
    if (take_d(&p, 0, 4.1e7, &mm) != 0 || *p) return -1;
    s->has_anc = 1;
    s->anc_lat = la;
    s->anc_lon = lo;
    s->moved_at = mt;
    s->moved_m = mm;
    return 0;
}

#define STATE_MAX (64u << 10)

void web_fg_meta_load(web_fleet_t *f) {
#ifdef WITH_SQLITE
    if (!f || !f->wr || !f->fg) return;
    sqlite3_stmt *q = NULL;
    if (sqlite3_prepare_v2(f->wr, "SELECT value FROM meta WHERE name=?1", -1, &q,
                           NULL) != SQLITE_OK) {
        sqlite3_finalize(q);
        return;
    }
    for (int i = -1; i < f->npeer; i++) {
        const char *nm = i < 0 ? "self" : f->peer[i].cfg.name;
        char key[64];
        snprintf(key, sizeof(key), "fleet.gnss.%s", nm);
        sqlite3_reset(q);
        sqlite3_bind_text(q, 1, key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(q) != SQLITE_ROW) continue;
        const char *v = (const char *)sqlite3_column_text(q, 0);
        pthread_mutex_lock(&f->mu);
        int sl = web_fg_slot(f->fg, nm);
        if (sl >= 0) web_fg_state_parse(&f->fg->site[sl], v);
        pthread_mutex_unlock(&f->mu);
        /* The announced reference, its own row (#196). */
        snprintf(key, sizeof(key), "fleet.gnssref.%s", nm);
        sqlite3_reset(q);
        sqlite3_bind_text(q, 1, key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(q) != SQLITE_ROW) continue;
        v = (const char *)sqlite3_column_text(q, 0);
        pthread_mutex_lock(&f->mu);
        if (sl >= 0) web_fg_ref_parse(&f->fg->site[sl], v);
        pthread_mutex_unlock(&f->mu);
    }
    sqlite3_finalize(q);
#else
    (void)f;
#endif
}

/* Each site's state to meta at most once a WEB_FG_REF_EVERY_S: a restart
 * loses at most that much coverage. */
static void meta_save(web_fleet_t *f, long long now_s) {
#ifdef WITH_SQLITE
    if (!f->wr || !f->fg) return;
    char *buf = malloc(STATE_MAX);
    if (!buf) return;
    sqlite3_stmt *up = NULL;
    if (sqlite3_prepare_v2(f->wr, "INSERT OR REPLACE INTO meta (name,value) VALUES (?1,?2)",
                           -1, &up, NULL) != SQLITE_OK) {
        sqlite3_finalize(up);
        free(buf);
        return;
    }
    for (int i = 0; i < WEB_FG_SITES; i++) {
        char key[64];
        pthread_mutex_lock(&f->mu);
        web_fg_site_t *s = &f->fg->site[i];
        int go = s->used && s->dirty && (s->saved_at == 0 ||
                                         now_s - s->saved_at >= WEB_FG_REF_EVERY_S);
        int n = go ? web_fg_state_text(s, buf, STATE_MAX) : -1;
        char rv[96], rkey[64];
        int rn = n >= 0 ? web_fg_ref_text(s, rv, sizeof(rv)) : -1;
        if (n >= 0) {
            snprintf(key, sizeof(key), "fleet.gnss.%s", s->name);
            snprintf(rkey, sizeof(rkey), "fleet.gnssref.%s", s->name);
            s->dirty = 0;
            s->saved_at = now_s;
        }
        pthread_mutex_unlock(&f->mu);
        if (n < 0) continue;
        sqlite3_reset(up);
        sqlite3_bind_text(up, 1, key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(up, 2, buf, n, SQLITE_TRANSIENT);
        sqlite3_step(up);
        if (rn < 0) continue;
        sqlite3_reset(up);
        sqlite3_bind_text(up, 1, rkey, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(up, 2, rv, rn, SQLITE_TRANSIENT);
        sqlite3_step(up);
    }
    sqlite3_finalize(up);
    free(buf);
#else
    (void)f; (void)now_s;
#endif
}

void web_fleet_gnss_tick(web_fleet_t *f, long long now_s) {
    if (!f || !f->fg) return;
    web_fg_sample_t s;
    memset(&s, 0, sizeof(s));
    s.t = now_s;
    s.sats_used = s.sats_view = s.jam = -1;
    if (f->gnss) {
        web_loc_t loc;
        web_gnss_sh_t sh;
        web_gnss_site(f->gnss, &loc, &sh);
        web_gnss_fleet_t gf;
        web_gnss_fleet(f->gnss, now_s, &gf);
        if (sh.seen) {
            s.gts = sh.ts;
            s.fresh = sh.ts > 0 && sh.ts <= now_s + 5 && now_s - sh.ts <= WEB_FG_FRESH_S;
            snprintf(s.state, sizeof(s.state), "%s", sh.gps_state);
            s.sats_used = sh.sats_used;
            s.sats_view = sh.sats_in_view;
            s.has_cn0 = sh.cn0_mean > 0;
            s.cn0_mean = sh.cn0_mean;
            s.jam = sh.jam;
            s.has_off = sh.has_time_off;
            s.off_ms = sh.time_off_ms;
        }
        s.has_trk = 1;
        s.tracked = gf.tracked;
        s.cn0_med = gf.cn0_med;
        const web_gnss_fix_t *fx = &gf.fix;
        if (gf.has_fix && fx->has_pos && fx->mode >= 2 && fx->ts > 0 &&
            now_s - fx->ts <= WEB_FG_FRESH_S) {
            s.has_fix = 1;
            s.mode = fx->mode;
            s.lat = fx->lat;
            s.lon = fx->lon;
            s.fix_ts = fx->ts;
            s.has_eph = fx->has_eph;
            s.eph = fx->eph;
            s.has_hdop = fx->hdop > 0;
            s.hdop = fx->hdop;
        }
    }
    /* This site's own incidents are read at the request, from sloth.db:
     * whether that read works is the route's to say. */
    s.evok = s.fresh;
    pthread_mutex_lock(&f->mu);
    web_fg_add(f->fg, web_fg_slot(f->fg, "self"), &s, 2LL * f->interval_s + 30);
    pthread_mutex_unlock(&f->mu);
    meta_save(f, now_s);
}

/* ── the classification ────────────────────────────────────────────── */

int web_fg_covered(const long long *s, const long long *e, int n, long long a, long long b) {
    for (int i = 0; i < n; i++)
        if (s[i] <= a && e[i] >= b) return 1;
    return 0;
}

void web_fg_classify(web_fg_event_t *ev, int n, const web_fg_cov_t *sites, int nsites,
                     long long window_s, long long gap_s, double region_m) {
    for (int i = 0; i < n; i++) {
        web_fg_event_t *e = &ev[i];
        e->with = e->quiet = e->stale = e->far = 0;
        if (e->site < 0 || e->site >= nsites) { e->verdict = WEB_FG_UNDETERMINED; continue; }
        const web_fg_cov_t *S = &sites[e->site];
        /* The whole window, never cut at now: a peer's answer is only as
         * new as its last pull, so an event still inside the window of
         * its end, or not yet pulled past it, has no quiet peer. */
        long long lo = e->a - window_s, hi = e->b + window_s;
        int alert = web_fg_is_alert(e->type);
        for (int p = 0; p < nsites && p < 32; p++) {
            if (p == e->site) continue;
            unsigned bit = 1u << p;
            const web_fg_cov_t *P = &sites[p];
            double d = S->has_pos && P->has_pos
                     ? web_fleet_dist_m(S->lat, S->lon, P->lat, P->lon) : -1;
            if (!(d >= 0 && d <= region_m)) { e->far |= bit; continue; }
            int match = 0;
            for (int j = 0; j < n && !match; j++)
                match = ev[j].site == p && ev[j].cls == e->cls &&
                        ev[j].a <= e->b + window_s && ev[j].b >= e->a - window_s;
            if (match) { e->with |= bit; continue; }
            /* Quiet only where the site was seen observing all of the
             * window: its incidents offered, for an incident; its
             * receiver, with the drop test's history, for interference
             * that lasted a sample's gap (so a sample of the peer fell
             * inside it), which is all a sample event can have. */
            int cov = alert && !P->ev_none && web_fg_covered(P->ev_s, P->ev_e, P->nev, lo, hi);
            if (!cov && e->cls == WEB_FG_INTERFERENCE && e->b - e->a >= gap_s)
                cov = web_fg_covered(P->rx_s, P->rx_e, P->nrx, lo, hi);
            if (cov) e->quiet |= bit;
            else e->stale |= bit;
        }
        e->verdict = e->with ? WEB_FG_REGIONAL : e->quiet ? WEB_FG_LOCAL : WEB_FG_UNDETERMINED;
    }
}

/* ── the request ───────────────────────────────────────────────────── */

static int by_dbl(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static int by_ll(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x > y) - (x < y);
}

static double med_d(double *v, int n) {
    qsort(v, (size_t)n, sizeof(v[0]), by_dbl);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

static long long med_ll(long long *v, int n) {
    qsort(v, (size_t)n, sizeof(v[0]), by_ll);
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

typedef struct {
    char      name[WEB_FLEET_NAME_MAX + 1];
    char      label[WEB_FLEET_STR_MAX + 1];
    int       configured, slot;
    long long skew;                  /* from peer_sites: the clock at the last good pull */
    int       store_pos;
    double    store_lat, store_lon;
    /* From the samples. */
    int       has_now;
    web_fg_sample_t now;
    int       has_ref;
    int       nref;
    double    ref_lat, ref_lon;
    long long moved_at;              /* the reference re-anchored (#196), 0 never */
    double    moved_m;
    int       has_cur;               /* a fresh fix with eph */
    web_fg_sample_t cur;
    double    disp, bound;
    int       outside;
    int       has_tref;
    long long off_ref, off_now, off_step;
    int       stepped;
    int       has_sref;
    long long skew_ref, skew_now, skew_step;     /* s, rounded from the ms */
    long long skew_step_ms, rtt_ms;              /* rtt_ms -1: not measured */
    int       skew_moved;
    int       nrx, nev;
    long long rx_s[WEB_FG_SPANS], rx_e[WEB_FG_SPANS], ev_s[WEB_FG_SPANS], ev_e[WEB_FG_SPANS];
    web_fg_cov_t cov;
} gsite_t;

typedef struct {
    gsite_t        s[WEB_FG_SITES];
    int            n;
    web_fg_event_t ev[WEB_FG_EV_MAX];
    int            nev, ev_cut;
    const char    *local;            /* sloth.db: open, none, unavailable */
    int            store;
    long long      gap;
} gctx_t;

static void add_event(gctx_t *x, int site, const char *type, long long a, long long b,
                      long long count, int sev) {
    int cls = web_fg_class_of(type);
    if (cls < 0) return;
    if (x->nev >= WEB_FG_EV_MAX) { x->ev_cut = 1; return; }
    web_fg_event_t *e = &x->ev[x->nev++];
    memset(e, 0, sizeof(*e));
    e->site = site;
    e->cls = cls;
    snprintf(e->type, sizeof(e->type), "%s", type);
    e->a = a;
    e->b = b < a ? a : b;
    e->count = count;
    e->sev = sev;
}

static int local_incident(void *ctx, const web_sdb_item_t *it) {
    gctx_t *x = ctx;
    const web_akb_t *k = web_akb_get(it->n1 & 0xffff);
    if (k) add_event(x, 0, k->name, it->first_seen, it->last_seen, it->n3,
                     it->n2 < 0 ? 0 : it->n2 > 2 ? 2 : (int)it->n2);
    return x->nev >= WEB_FG_EV_MAX;
}

/* The events a site's samples showed (sample_flag(), se_note()). */
static void sample_events(gctx_t *x, int si, const web_fg_site_t *fs) {
    static const char *const W[2] = { "JAM_IND", "CN0_DROP" };
    for (int i = 0; i < fs->nse; i++)
        add_event(x, si, W[fs->se_w[i] & 1], fs->se_a[i], fs->se_b[i], 0, 1);
}

/* ms to the nearest whole second, halves away from zero. */
static long long round_s(long long ms) {
    return ms >= 0 ? (ms + 500) / 1000 : -((-ms + 500) / 1000);
}

/* One site's figures from its samples, under f->mu. */
static void site_figures(gctx_t *x, int si, const web_fg_site_t *fs) {
    gsite_t *g = &x->s[si];
    g->nrx = fs->nrx;
    g->nev = fs->nev;
    memcpy(g->rx_s, fs->rx_s, sizeof(g->rx_s));
    memcpy(g->rx_e, fs->rx_e, sizeof(g->rx_e));
    memcpy(g->ev_s, fs->ev_s, sizeof(g->ev_s));
    memcpy(g->ev_e, fs->ev_e, sizeof(g->ev_e));
    if (fs->n) {
        g->has_now = 1;
        g->now = fs->ring[(fs->head + WEB_FG_RING - 1) % WEB_FG_RING];
    }
    g->moved_at = fs->moved_at;
    g->moved_m = fs->moved_m;
    if (fs->nref >= WEB_FG_REF_MIN) {
        double *a = malloc(sizeof(double) * (size_t)fs->nref);
        double *b = malloc(sizeof(double) * (size_t)fs->nref);
        if (a && b) {
            for (int i = 0; i < fs->nref; i++) { a[i] = fs->ref_lat[i]; b[i] = fs->ref_lon[i]; }
            g->ref_lat = med_d(a, fs->nref);
            g->ref_lon = med_d(b, fs->nref);
            g->has_ref = isfinite(g->ref_lat) && isfinite(g->ref_lon);
            g->nref = fs->nref;
        }
        free(a);
        free(b);
    }
    /* An eph of 0 is no estimate: the bound would be 0 m and any fix
     * "moved". */
    if (g->has_now && g->now.fresh && g->now.has_fix && g->now.has_eph &&
        isfinite(g->now.eph) && g->now.eph > 0 && isfinite(g->now.lat) &&
        isfinite(g->now.lon)) {
        g->has_cur = 1;
        g->cur = g->now;
    }
    if (g->has_ref && g->has_cur) {
        g->disp = web_fleet_dist_m(g->ref_lat, g->ref_lon, g->cur.lat, g->cur.lon);
        g->bound = WEB_FG_K * g->cur.eph;
        g->outside = g->disp > g->bound;
    }
    /* The clock: the newest fresh offset against the median of the hour
     * before it; the skew the same way. */
    if (g->has_now && g->now.fresh) {
        long long *o = malloc(sizeof(long long) * WEB_FG_RING);
        long long *k = malloc(sizeof(long long) * WEB_FG_RING);
        int no = 0, nk = 0;
        for (int j = 0; o && k && j < fs->n - 1; j++) {
            const web_fg_sample_t *r = &fs->ring[(fs->head + WEB_FG_RING - fs->n + j) % WEB_FG_RING];
            if (!r->fresh || r->t < g->now.t - WEB_FG_HIST_S || r->t >= g->now.t) continue;
            if (r->has_off) o[no++] = r->off_ms;
            k[nk++] = r->has_ms ? r->skew_ms : r->skew * 1000;
        }
        if (g->now.has_off && no >= WEB_FG_HIST_MIN) {
            g->has_tref = 1;
            g->off_ref = med_ll(o, no);
            g->off_now = g->now.off_ms;
            g->off_step = g->off_now - g->off_ref;
            g->stepped = g->off_step >= WEB_FG_TIME_STEP_MS || g->off_step <= -WEB_FG_TIME_STEP_MS;
        }
        /* The skew in ms against its median of the hour before; a step
         * counts at WEB_FG_SKEW_STEP_S plus half the newest request's
         * round trip, the most the request's own time can move it
         * (#196: a slow pull no longer reads as a clock that moved). */
        if (si > 0 && nk >= WEB_FG_HIST_MIN) {
            long long ref = med_ll(k, nk);
            long long now = g->now.has_ms ? g->now.skew_ms : g->now.skew * 1000;
            g->has_sref = 1;
            g->skew_step_ms = now - ref;
            g->rtt_ms = g->now.has_ms ? g->now.rtt_ms : -1;
            g->skew_ref = round_s(ref);
            g->skew_now = round_s(now);
            g->skew_step = g->skew_now - g->skew_ref;
            long long lim = WEB_FG_SKEW_STEP_S * 1000LL + (g->rtt_ms > 0 ? g->rtt_ms / 2 : 0);
            g->skew_moved = g->skew_step_ms >= lim || g->skew_step_ms <= -lim;
        }
        free(o);
        free(k);
    }
}

static void build(web_fleet_t *f, const web_fleet_src_t *src, long long now_s, gctx_t *x) {
    memset(x, 0, sizeof(*x));
    x->local = "none";
    x->gap = 2LL * (f ? f->interval_s : WEB_FLEET_INTERVAL_DEF) + 30;
    gsite_t *me = &x->s[x->n++];
    snprintf(me->name, sizeof(me->name), "self");
    me->configured = 1;
    me->slot = -1;
    for (int i = 0; f && i < f->npeer && x->n < WEB_FG_SITES; i++) {
        gsite_t *g = &x->s[x->n++];
        snprintf(g->name, sizeof(g->name), "%s", f->peer[i].cfg.name);
        g->configured = 1;
        g->slot = -1;
    }
    /* This site's incidents from sloth.db, through the M4 reader. */
    int local_ok = 0;
    if (src && src->sdb && src->sdb->configured) {
        web_sdb_conn_t c;
        memset(&c, 0, sizeof(c));
        char err[WEB_SDB_ERR_MAX];
        if (web_slothdb_open(src->sdb, &c, WEB_SDB_OVERVIEW_MS, now_s, err, sizeof(err)) == 0) {
            x->local = "open";
            int r = web_sdb_gnss_incidents(&c, now_s - WEB_FG_EVENTS_S, 256,
                                           local_incident, x);
            /* All of them or none: a file before v11 has no incident
             * rows, and a read cut short is not all. */
            local_ok = r >= 0 && r < 256 && !c.timed_out;
            if (!local_ok) x->local = r == WEB_SDB_GNSS_NONE ? "no_incidents" : "unavailable";
        } else {
            x->local = "unavailable";
        }
        web_slothdb_close(&c);
    }
    if (src && src->gnss) {
        web_loc_t loc;
        web_gnss_sh_t sh;
        web_gnss_site(src->gnss, &loc, &sh);
        if (loc.has) { me->store_pos = 1; me->store_lat = loc.lat; me->store_lon = loc.lon; }
    }
#ifdef WITH_SQLITE
    web_store_t *st = f ? f->store : NULL;
    if (st && st->rd) {
        x->store = 1;
        pthread_mutex_lock(&st->rmu);
        sqlite3_stmt *ps = NULL, *qe = NULL;
        int ok = sqlite3_prepare_v2(st->rd, "SELECT label,lat,lon,remote_ts,last_ok FROM"
                                    " peer_sites WHERE peer=?1", -1, &ps, NULL) == SQLITE_OK &&
                 sqlite3_prepare_v2(st->rd, "SELECT label,first_seen,last_seen,extra FROM"
                                    " peer_sightings WHERE peer=?1 AND kind='gnss_event' AND"
                                    " last_seen>=?2 ORDER BY last_seen DESC LIMIT 256", -1, &qe,
                                    NULL) == SQLITE_OK;
        for (int i = 1; ok && i < x->n; i++) {
            gsite_t *g = &x->s[i];
            sqlite3_reset(ps);
            sqlite3_bind_text(ps, 1, g->name, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(ps) == SQLITE_ROW) {
                const unsigned char *t = sqlite3_column_text(ps, 0);
                snprintf(g->label, sizeof(g->label), "%s", t ? (const char *)t : "");
                if (sqlite3_column_type(ps, 1) != SQLITE_NULL &&
                    sqlite3_column_type(ps, 2) != SQLITE_NULL) {
                    g->store_pos = 1;
                    g->store_lat = sqlite3_column_double(ps, 1);
                    g->store_lon = sqlite3_column_double(ps, 2);
                }
                long long rts = sqlite3_column_int64(ps, 3), lok = sqlite3_column_int64(ps, 4);
                g->skew = rts > 0 && lok > 0 ? rts - lok : 0;
            }
            sqlite3_reset(qe);
            sqlite3_bind_text(qe, 1, g->name, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(qe, 2, now_s + g->skew - WEB_FG_EVENTS_S);
            while (sqlite3_step(qe) == SQLITE_ROW) {
                const unsigned char *ty = sqlite3_column_text(qe, 0);
                const unsigned char *ex = sqlite3_column_text(qe, 3);
                long long cnt = 0, sev = 0;
                const char *pc = ex ? strstr((const char *)ex, "\"count\":") : NULL;
                const char *pv = ex ? strstr((const char *)ex, "\"sev\":") : NULL;
                if (pc) cnt = strtoll(pc + 8, NULL, 10);
                if (pv) sev = strtoll(pv + 6, NULL, 10);
                if (!ty || !web_fg_is_alert((const char *)ty)) continue;
                add_event(x, i, (const char *)ty, sqlite3_column_int64(qe, 1) - g->skew,
                          sqlite3_column_int64(qe, 2) - g->skew, cnt < 0 ? 0 : cnt,
                          sev < 0 ? 0 : sev > 2 ? 2 : (int)sev);
            }
        }
        sqlite3_finalize(ps);
        sqlite3_finalize(qe);
        pthread_mutex_unlock(&st->rmu);
    }
#endif
    /* The samples, under the pull's lock. */
    if (f && f->fg) {
        pthread_mutex_lock(&f->mu);
        for (int i = 0; i < x->n; i++) {
            const web_fg_site_t *fs = NULL;
            for (int k = 0; k < WEB_FG_SITES && !fs; k++)
                if (f->fg->site[k].used && !strcmp(f->fg->site[k].name, x->s[i].name))
                    fs = &f->fg->site[k];
            if (!fs) continue;
            site_figures(x, i, fs);
            sample_events(x, i, fs);
        }
        pthread_mutex_unlock(&f->mu);
    }
    for (int i = 0; i < x->n; i++) {
        gsite_t *g = &x->s[i];
        web_fg_cov_t *c = &g->cov;
        /* The position the region is measured from: the reference, else
         * the newest fix, else the position the site last stated. */
        if (g->has_ref) { c->has_pos = 1; c->lat = g->ref_lat; c->lon = g->ref_lon; }
        else if (g->has_now && g->now.has_fix) { c->has_pos = 1; c->lat = g->now.lat; c->lon = g->now.lon; }
        else if (g->store_pos) { c->has_pos = 1; c->lat = g->store_lat; c->lon = g->store_lon; }
        c->nrx = g->nrx;
        c->nev = g->nev;
        c->rx_s = g->rx_s;
        c->rx_e = g->rx_e;
        c->ev_s = g->ev_s;
        c->ev_e = g->ev_e;
        /* This site's incidents are only as covered as sloth.db's read. */
        c->ev_none = i == 0 && !local_ok;
    }
    web_fg_cov_t cov[WEB_FG_SITES];
    for (int i = 0; i < x->n; i++) cov[i] = x->s[i].cov;
    web_fg_classify(x->ev, x->nev, cov, x->n, WEB_FG_WINDOW_S, x->gap,
                    f ? f->gnss_region_m : WEB_FG_REGION_KM_DEF * 1000.0);
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

static void site_list(web_jw_t *w, const gctx_t *x, unsigned bits) {
    web_jw_raw(w, "[");
    int k = 0;
    for (int i = 0; i < x->n && i < 32; i++)
        if (bits & (1u << i)) {
            if (k++) web_jw_raw(w, ",");
            web_jw_str(w, x->s[i].name);
        }
    web_jw_raw(w, "]");
}

/* "consistent", "one_site", "several" or "undetermined" over the sites
 * evaluated (two needed), and the one site when one. */
static const char *verdict3(int evaluated, int flagged) {
    if (evaluated < 2) return "undetermined";
    return flagged == 0 ? "consistent" : flagged == 1 ? "one_site" : "several";
}

static void pos_verdict(web_jw_t *w, const gctx_t *x) {
    int ev = 0, fl = 0, one = -1;
    for (int i = 0; i < x->n; i++) {
        if (!(x->s[i].has_ref && x->s[i].has_cur)) continue;
        ev++;
        if (x->s[i].outside) { fl++; one = i; }
    }
    web_jw_raw(w, "{\"verdict\":");
    web_jw_str(w, verdict3(ev, fl));
    web_jw_raw(w, ",\"site\":");
    if (ev >= 2 && fl == 1) web_jw_str(w, x->s[one].name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"evaluated\":");
    web_jw_int(w, ev);
    web_jw_raw(w, "}");
}

static void time_verdict(web_jw_t *w, const gctx_t *x) {
    int ev = 0, fl = 0, one = -1;
    for (int i = 0; i < x->n; i++) {
        if (!x->s[i].has_tref) continue;
        ev++;
        if (x->s[i].stepped) { fl++; one = i; }
    }
    web_jw_raw(w, "{\"verdict\":");
    web_jw_str(w, verdict3(ev, fl));
    web_jw_raw(w, ",\"site\":");
    if (ev >= 2 && fl == 1) web_jw_str(w, x->s[one].name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"evaluated\":");
    web_jw_int(w, ev);
    web_jw_raw(w, "}");
}

static void counts(web_jw_t *w, const gctx_t *x, long long from) {
    int c[3] = { 0, 0, 0 };
    for (int i = 0; i < x->nev; i++)
        if (x->ev[i].b >= from) c[x->ev[i].verdict]++;
    web_jw_raw(w, "{\"regional\":");     web_jw_int(w, c[WEB_FG_REGIONAL]);
    web_jw_raw(w, ",\"local\":");        web_jw_int(w, c[WEB_FG_LOCAL]);
    web_jw_raw(w, ",\"undetermined\":"); web_jw_int(w, c[WEB_FG_UNDETERMINED]);
    web_jw_raw(w, "}");
}

void web_fg_overview_json(web_fleet_t *f, const web_fleet_src_t *src, long long now_s,
                          web_jw_t *w) {
    gctx_t *x = malloc(sizeof(*x));
    if (!x) { web_jw_raw(w, "null"); return; }
    build(f, src, now_s, x);
    web_jw_raw(w, "{\"position\":");
    pos_verdict(w, x);
    web_jw_raw(w, ",\"time\":");
    time_verdict(w, x);
    web_jw_raw(w, ",\"events_24h\":");
    counts(w, x, now_s - 86400);
    web_jw_raw(w, "}");
    free(x);
}

static int by_newest(const void *pa, const void *pb) {
    const web_fg_event_t *a = pa, *b = pb;
    if (a->b != b->b) return a->b < b->b ? 1 : -1;
    if (a->a != b->a) return a->a < b->a ? 1 : -1;
    return a->site - b->site;
}

/* Each class's basis: what the corpus holds, and which numbers are a
 * choice with no source. */
static const char *const BASIS[WEB_FG_NCLASS] = {
    "Interference shows as C/N0 collapsing on every tracked satellite at once; "
    "one receiver cannot locate the source (research/gnss/jamming-detection.md; "
    "docs/wiki/alert-assessments/GNSS_JAMMING.md), and a jammer aimed at one receiver "
    "affects another nearby (FCC 13-106, Bojczak, as quoted there). Two receivers that "
    "see it within the window: one source reaching both, or a wide one; one alone: a "
    "source near it. The drop (10 dB) and the indicator (128) are the GNSS_JAMMING "
    "rule's defaults, themselves judgements: no read source puts a number on either. "
    "JAM_IND and CN0_DROP are slothweb's own tests on samples a pull apart, not the rule: "
    "they cannot see the simultaneity the rule looks for, so a CN0_DROP is interference or "
    "attenuation alike, the C/N0 half that 'cannot tell interference from attenuation' "
    "(research/gnss/jamming-detection.md).",
    "A suspicion from weak observables, never a detection (research/gnss/"
    "spoofing-detection.md; docs/wiki/alert-assessments/GNSS_SPOOF_SUSPECT.md). At both "
    "sites at once: a wide event; at one: that site's receiver.",
    "A step of the receiver's clock (research/gnss/time-and-position-integrity.md; "
    "docs/wiki/alert-assessments/GNSS_TIME_JUMP.md): 1000 ms, from the gpsd HOWTO's "
    "200 ms floor and 'anything below roughly a second is noise'.",
    "A fixed sensor's bound 'collapses to the two error estimates' (research/gnss/"
    "time-and-position-integrity.md); k = 3 is the GNSS_POSITION_JUMP rule's own "
    "default, a judgement because gpsd states no confidence for eph "
    "(docs/wiki/alert-assessments/GNSS_POSITION_JUMP.md).",
};

static void site_json(web_jw_t *w, const gctx_t *x, int i, long long now_s) {
    const gsite_t *g = &x->s[i];
    const web_fg_sample_t *r = &g->now;
    web_jw_raw(w, "{\"site\":");      web_jw_str(w, g->name);
    web_jw_raw(w, ",\"label\":");
    if (g->label[0]) web_jw_str(w, g->label); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"sampled_age_s\":");
    jll(w, g->has_now, now_s > r->t ? now_s - r->t : 0);
    web_jw_raw(w, ",\"fresh\":");     web_jw_raw(w, g->has_now && r->fresh ? "true" : "false");
    web_jw_raw(w, ",\"incidents\":");
    web_jw_raw(w, i == 0 ? (strcmp(x->local, "open") ? "false" : "true")
                         : (g->has_now && r->evok ? "true" : "false"));
    int f = g->has_now && r->fresh;
    web_jw_raw(w, ",\"state\":");
    if (f && r->state[0]) web_jw_str(w, r->state); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"sats_used\":");    jll(w, f && r->sats_used >= 0, r->sats_used);
    web_jw_raw(w, ",\"sats_in_view\":"); jll(w, f && r->sats_view >= 0, r->sats_view);
    web_jw_raw(w, ",\"cn0_mean\":");     jnum(w, f && r->has_cn0, r->cn0_mean, 1);
    web_jw_raw(w, ",\"cn0_med\":");      jnum(w, f && r->tracked > 0, r->cn0_med, 1);
    web_jw_raw(w, ",\"tracked\":");      jll(w, f && r->has_trk, r->tracked);
    web_jw_raw(w, ",\"jam\":");          jll(w, f && r->jam >= 0, r->jam);
    web_jw_raw(w, ",\"time_offset_ms\":"); jll(w, f && r->has_off, r->off_ms);
    web_jw_raw(w, ",\"skew_s\":");       jll(w, i > 0 && g->has_now, r->skew);
    web_jw_raw(w, ",\"fix\":");
    if (g->has_now && r->has_fix) {
        web_jw_raw(w, "{\"lat\":");   jnum(w, 1, r->lat, 7);
        web_jw_raw(w, ",\"lon\":");   jnum(w, 1, r->lon, 7);
        web_jw_raw(w, ",\"mode\":");  web_jw_int(w, r->mode);
        web_jw_raw(w, ",\"eph\":");   jnum(w, r->has_eph, r->eph, 1);
        web_jw_raw(w, ",\"hdop\":");  jnum(w, r->has_hdop, r->hdop, 1);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"reference\":");
    if (g->has_ref) {
        web_jw_raw(w, "{\"n\":");    web_jw_int(w, g->nref);
        web_jw_raw(w, ",\"lat\":");  jnum(w, 1, g->ref_lat, 7);
        web_jw_raw(w, ",\"lon\":");  jnum(w, 1, g->ref_lon, 7);
        web_jw_raw(w, ",\"displacement_m\":"); jnum(w, g->has_cur, g->disp, 1);
        web_jw_raw(w, ",\"bound_m\":");        jnum(w, g->has_cur, g->bound, 1);
        web_jw_raw(w, ",\"outside\":");
        web_jw_raw(w, g->has_cur ? (g->outside ? "true" : "false") : "null");
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    /* When the reference last moved and how far (#196): a move held past
     * half the week becomes the reference, and this says it did. */
    web_jw_raw(w, ",\"reference_moved_at\":"); jll(w, g->moved_at > 0, g->moved_at);
    web_jw_raw(w, ",\"reference_moved_m\":");  jnum(w, g->moved_at > 0, g->moved_m, 1);
    web_jw_raw(w, ",\"time\":");
    if (g->has_tref || g->has_sref) {
        web_jw_raw(w, "{\"ref_ms\":");   jll(w, g->has_tref, g->off_ref);
        web_jw_raw(w, ",\"now_ms\":");   jll(w, g->has_tref, g->off_now);
        web_jw_raw(w, ",\"step_ms\":");  jll(w, g->has_tref, g->off_step);
        web_jw_raw(w, ",\"stepped\":");  web_jw_raw(w, g->has_tref && g->stepped ? "true" : "false");
        web_jw_raw(w, ",\"skew_ref_s\":");  jll(w, g->has_sref, g->skew_ref);
        web_jw_raw(w, ",\"skew_step_s\":"); jll(w, g->has_sref, g->skew_step);
        web_jw_raw(w, ",\"skew_step_ms\":"); jll(w, g->has_sref, g->skew_step_ms);
        web_jw_raw(w, ",\"rtt_ms\":");      jll(w, g->has_sref && g->rtt_ms >= 0, g->rtt_ms);
        web_jw_raw(w, ",\"skew_moved\":");
        web_jw_raw(w, g->has_sref && g->skew_moved ? "true" : "false");
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, ",\"covered_since\":");
    jll(w, g->nev > 0, g->nev > 0 ? g->ev_s[g->nev - 1] : 0);
    web_jw_raw(w, ",\"observed_since\":");
    jll(w, g->nrx > 0, g->nrx > 0 ? g->rx_s[g->nrx - 1] : 0);
    web_jw_raw(w, "}");
}

static int parse_q(const char *q, int *limit, const char **why) {
    *limit = WEB_FG_LIMIT_DEF;
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
            if (v < 1 || v > WEB_FG_LIMIT_MAX) { *why = "bad_limit"; return -1; }
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

#define BODY_MAX (512u << 10)

int web_fleet_gnss_route(web_fleet_t *f, const web_fleet_src_t *src, const char *query,
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
    gctx_t *x = malloc(sizeof(*x));
    if (!x) { free(buf); return -1; }
    build(f, src, now_s, x);
    web_jw_t w;
    web_jw_init(&w, buf, BODY_MAX);
    web_jw_raw(&w, "{\"now\":");              web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"local\":");            web_jw_str(&w, x->local);
    web_jw_raw(&w, ",\"store\":");            web_jw_raw(&w, x->store ? "true" : "false");
    web_jw_raw(&w, ",\"window_s\":");         web_jw_int(&w, WEB_FG_WINDOW_S);
    web_jw_raw(&w, ",\"gap_s\":");            web_jw_int(&w, x->gap);
    web_jw_raw(&w, ",\"region_m\":");
    jnum(&w, 1, f ? f->gnss_region_m : WEB_FG_REGION_KM_DEF * 1000.0, 0);
    web_jw_raw(&w, ",\"fresh_s\":");          web_jw_int(&w, WEB_FG_FRESH_S);
    web_jw_raw(&w, ",\"k\":");                web_jw_int(&w, WEB_FG_K);
    web_jw_raw(&w, ",\"time_step_ms\":");     web_jw_int(&w, WEB_FG_TIME_STEP_MS);
    web_jw_raw(&w, ",\"cn0_drop_db\":");      web_jw_int(&w, WEB_FG_CN0_DROP_DB);
    web_jw_raw(&w, ",\"jam_ind\":");          web_jw_int(&w, WEB_FG_JAM_IND);
    web_jw_raw(&w, ",\"ref_min\":");          web_jw_int(&w, WEB_FG_REF_MIN);
    web_jw_raw(&w, ",\"sites\":[");
    for (int i = 0; i < x->n; i++) {
        if (i) web_jw_raw(&w, ",");
        site_json(&w, x, i, now_s);
    }
    /* Every pair with both references and both fixes: the distance now
     * against the references', bounded by k x (eph_a + eph_b). */
    web_jw_raw(&w, "],\"baseline\":[");
    int nb = 0;
    for (int a = 0; a < x->n; a++)
        for (int b = a + 1; b < x->n; b++) {
            const gsite_t *A = &x->s[a], *B = &x->s[b];
            if (!A->has_now && !B->has_now) continue;
            web_jw_raw(&w, nb++ ? ",{\"a\":" : "{\"a\":");
            web_jw_str(&w, A->name);
            web_jw_raw(&w, ",\"b\":");
            web_jw_str(&w, B->name);
            int refs = A->has_ref && B->has_ref, curs = A->has_cur && B->has_cur;
            double rm = refs ? web_fleet_dist_m(A->ref_lat, A->ref_lon, B->ref_lat, B->ref_lon) : 0;
            double nm = curs ? web_fleet_dist_m(A->cur.lat, A->cur.lon, B->cur.lat, B->cur.lon) : 0;
            double bd = curs ? WEB_FG_K * (A->cur.eph + B->cur.eph) : 0;
            web_jw_raw(&w, ",\"ref_m\":");   jnum(&w, refs, rm, 1);
            web_jw_raw(&w, ",\"now_m\":");   jnum(&w, curs, nm, 1);
            web_jw_raw(&w, ",\"delta_m\":"); jnum(&w, refs && curs, nm - rm, 1);
            web_jw_raw(&w, ",\"bound_m\":"); jnum(&w, curs, bd, 1);
            const char *v = !refs ? "undetermined" : !curs ? "undetermined"
                          : fabs(nm - rm) > bd ? "outside" : "within";
            const char *why2 = !refs ? "no_reference" : !curs ? "no_current_fix" : NULL;
            web_jw_raw(&w, ",\"verdict\":"); web_jw_str(&w, v);
            web_jw_raw(&w, ",\"why\":");
            if (why2) web_jw_str(&w, why2); else web_jw_raw(&w, "null");
            /* Which site moved: each past its own bound from its own
             * reference; neither, when the distance alone changed. */
            unsigned moved = 0;
            if (refs && curs) {
                if (A->outside) moved |= 1u << a;
                if (B->outside) moved |= 1u << b;
            }
            web_jw_raw(&w, ",\"moved\":");
            site_list(&w, x, moved);
            web_jw_raw(&w, "}");
        }
    web_jw_raw(&w, "],\"position\":");
    pos_verdict(&w, x);
    web_jw_raw(&w, ",\"time\":");
    time_verdict(&w, x);
    qsort(x->ev, (size_t)x->nev, sizeof(x->ev[0]), by_newest);
    web_jw_raw(&w, ",\"counts\":");
    counts(&w, x, now_s - WEB_FG_EVENTS_S);
    web_jw_raw(&w, ",\"events\":[");
    for (int i = 0; i < x->nev && i < limit; i++) {
        const web_fg_event_t *e = &x->ev[i];
        if (i) web_jw_raw(&w, ",");
        web_jw_raw(&w, "{\"site\":");      web_jw_str(&w, x->s[e->site].name);
        web_jw_raw(&w, ",\"type\":");      web_jw_str(&w, e->type);
        web_jw_raw(&w, ",\"class\":");     web_jw_str(&w, web_fg_class_word(e->cls));
        web_jw_raw(&w, ",\"source\":");    web_jw_str(&w, web_fg_is_alert(e->type) ? "incident" : "sample");
        web_jw_raw(&w, ",\"first_seen\":"); web_jw_int(&w, e->a);
        web_jw_raw(&w, ",\"last_seen\":"); web_jw_int(&w, e->b);
        web_jw_raw(&w, ",\"count\":");     web_jw_int(&w, e->count);
        web_jw_raw(&w, ",\"sev\":");       web_jw_int(&w, e->sev);
        web_jw_raw(&w, ",\"verdict\":");   web_jw_str(&w, web_fg_verdict_word(e->verdict));
        web_jw_raw(&w, ",\"with\":");      site_list(&w, x, e->with);
        web_jw_raw(&w, ",\"quiet\":");     site_list(&w, x, e->quiet);
        web_jw_raw(&w, ",\"stale\":");     site_list(&w, x, e->stale);
        web_jw_raw(&w, ",\"far\":");       site_list(&w, x, e->far);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"events_total\":"); web_jw_int(&w, x->nev);
    web_jw_raw(&w, ",\"events_cut\":");    web_jw_raw(&w, x->ev_cut ? "true" : "false");
    web_jw_raw(&w, ",\"basis\":{");
    for (int c = 0; c < WEB_FG_NCLASS; c++) {
        if (c) web_jw_raw(&w, ",");
        web_jw_str(&w, CLASS_WORD[c]);
        web_jw_raw(&w, ":");
        web_jw_str(&w, BASIS[c]);
    }
    web_jw_raw(&w, ",\"window\":");
    web_jw_str(&w, "A choice, no source: no read source puts a number on 'simultaneous' "
                   "(research/gnss/jamming-detection.md). 120 s is two default pull "
                   "intervals, past the jamming rule's 30 s indicator hold and 10 s "
                   "collapse window, so one onset seen by two receivers a pull apart "
                   "still pairs.");
    web_jw_raw(&w, ",\"region\":");
    web_jw_str(&w, "A choice, no source (--peer-gnss-region-km, default 50 km): how "
                   "far a ground-level source reaches is not in the corpus.");
    web_jw_raw(&w, "}}\n");
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
