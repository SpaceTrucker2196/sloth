/* The glyph layer's geometry (docs/web-visual-spec.md §5, slice V0).
 *
 * Each glyph is a pure function from data and a size to a list of
 * marks, and a painter that draws the list. The pure half is what a
 * reading of the page depends on, so it is the half that is tested —
 * here, in C, through the embed path (owner ruling 2 of 2026-10-26),
 * so `make web-test` needs no node and no other dependency.
 *
 * The C below is a port of web/ui/glyph.js, line for line, and the JS
 * it ports is pinned verbatim out of the served page: a change on
 * either side fails here. That is test_tui_colors.c's mechanism, and
 * it is the one this repo already uses to keep a C truth and a JS copy
 * honest. web/tools/palette.c's generator is the other shape and does
 * not fit: a palette is static data a tool can emit, a glyph's
 * geometry is a function of data the page only has at run time.
 *
 * What the painter does with a mark list is not tested here; it is
 * canvas calls, and the mark list is what says what the glyph means. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_assets.h"
#include "web_rf.h"
#include "wtest.h"

static const char *page(void) { return (const char *)web_page; }

/* ── the ported mark list ───────────────────────────────────────── */

#define GM_MAX 512

/* txt: a word's text (the JS mark's seventh member), NULL for ink. */
typedef struct { const char *kind; double x, y, w, h; const char *tok; const char *txt; } gmark_t;
typedef struct { gmark_t m[GM_MAX]; int n; char tx[GM_MAX][48]; } gmarks_t;

static void gm_push(gmarks_t *g, const char *kind, double x, double y,
                    double w, double h, const char *tok) {
    if (g->n >= GM_MAX) return;
    g->m[g->n].kind = kind;
    g->m[g->n].x = x; g->m[g->n].y = y;
    g->m[g->n].w = w; g->m[g->n].h = h;
    g->m[g->n].tok = tok;
    g->m[g->n].txt = NULL;
    g->n++;
}
/* A word, its text kept in the list's own buffer. */
static void gm_push_t(gmarks_t *g, const char *kind, double x, double y,
                      double w, double h, const char *tok, const char *txt) {
    if (g->n >= GM_MAX) return;
    gm_push(g, kind, x, y, w, h, tok);
    snprintf(g->tx[g->n - 1], sizeof(g->tx[0]), "%s", txt);
    g->m[g->n - 1].txt = g->tx[g->n - 1];
}

/* How many marks of a kind, and the first of a kind. */
static int gm_count(const gmarks_t *g, const char *kind) {
    int n = 0;
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind)) n++;
    return n;
}
/* The first mark of a kind, by value, and an all-zero mark with an
 * empty kind when there is none: a test that reads a mark it asserts
 * the existence of must not dereference NULL when a mutation removes
 * it, because the crash takes every test after it with it. */
static gmark_t gm_get(const gmarks_t *g, const char *kind) {
    static const gmark_t none = { "", 0, 0, 0, 0, "", NULL };
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind)) return g->m[i];
    return none;
}
/* The last mark of a kind, the same way. */
static gmark_t gm_last(const gmarks_t *g, const char *kind) {
    static const gmark_t none = { "", 0, 0, 0, 0, "", NULL };
    gmark_t out = none;
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind)) out = g->m[i];
    return out;
}
static int near(double a, double b) { return fabs(a - b) < 1e-6; }

/* R10. Every colour token set to one grey, which is what the greyscale
 * tests read the list through: what survives is kind and position. */
static void gm_grey(gmarks_t *g) {
    for (int i = 0; i < g->n; i++) g->m[i].tok = "--faint";
}
static int gm_all_grey(const gmarks_t *g) {
    for (int i = 0; i < g->n; i++) if (strcmp(g->m[i].tok, "--faint")) return 0;
    return g->n > 0;
}

/* draw_sparkline_at()'s level, through app.js's port of it. */
static int gl_level(double v, double max) {
    if (!(v > 0) || !(max > 0)) return 0;
    int l = (int)floor(v / max * 8 + 0.5);
    return l < 1 ? 1 : l > 8 ? 8 : l;
}
static const char *gl_line_token(int l) {
    return l == 0 ? "--tui-dim" : l <= 2 ? "--tui-normal" :
           l <= 4 ? "--heat-1" : l <= 6 ? "--heat-2" : "--heat-3";
}
static const char *gl_heat_token(double f) {
    return f < 0.15 ? "--heat-0" : f < 0.40 ? "--heat-1" :
           f < 0.70 ? "--heat-2" : "--heat-3";
}

static void gl_dur(double s, char *out, size_t sz) {
    double r = floor(s + 0.5);
    if (r < 60) snprintf(out, sz, "%d s", (int)r);
    else if (r < 3600) snprintf(out, sz, "%d min", (int)floor(r / 60 + 0.5));
    else if (r <= 86400) snprintf(out, sz, "%d h", (int)floor(r / 3600 + 0.5));
    else snprintf(out, sz, "%d d", (int)floor(r / 86400 + 0.5));
}

typedef struct { double from, to; int shrunk; char text[80]; } gwin_t;

static gwin_t gl_win(const double (*pts)[2], int n, double from, double to) {
    gwin_t o;
    o.from = from; o.to = to; o.shrunk = 0; o.text[0] = '\0';
    double span = to - from;
    if (n < 2 || !(span > 0)) return o;
    double cover = pts[n - 1][0] - pts[0][0];
    if (!(cover > 0) || cover >= span * 0.1) return o;
    o.from = pts[0][0];
    o.to = pts[n - 1][0];
    o.shrunk = 1;
    char a[32], b[32];
    gl_dur(cover, a, sizeof(a));
    gl_dur(span, b, sizeof(b));
    snprintf(o.text, sizeof(o.text), "%s of %s", a, b);
    return o;
}

/* R11: a y-range that grows and never shrinks. prev NULL for none. */
static void gl_scale(const double (*pts)[2], int n, const double (*band)[4],
                     const int *has, const double *prev, double *lo, double *hi) {
    *lo = 0; *hi = 0;
    for (int i = 0; i < n; i++) {
        if (pts[i][1] > *hi) *hi = pts[i][1];
        if (pts[i][1] < *lo) *lo = pts[i][1];
        if (band && has && has[i]) {
            if (band[i][1] > *hi) *hi = band[i][1];
            if (band[i][0] < *lo) *lo = band[i][0];
        }
    }
    if (prev) {
        if (prev[0] < *lo) *lo = prev[0];
        if (prev[1] > *hi) *hi = prev[1];
    }
    if (!(*hi > *lo)) *hi = *lo + 1;
}

typedef struct {
    const char *source, *window, *tier, *scale, *state;
    double n;
} gcap_t;

static void gl_caption(const gcap_t *c, char *out, size_t sz) {
    out[0] = '\0';
    size_t at = 0;
    const char *p[4] = { c->source, c->window, c->tier, c->scale };
    for (int i = 0; i < 4; i++)
        if (p[i] && *p[i]) at += (size_t)snprintf(out + at, sz - at, "%s%s",
                                                  at ? ", " : "", p[i]);
    at += (size_t)snprintf(out + at, sz - at, "%sn=%d", at ? ", " : "",
                           (int)floor(c->n + 0.5));
    if (c->state && *c->state) snprintf(out + at, sz - at, ", %s", c->state);
}

typedef struct {
    double w, h, from, to, step, sens;
    const double *scale;                       /* NULL for a fresh scale */
    int shade_on;                              /* V1, F13: an episode's window */
    double shade[2];
} gopt_t;

static void gl_dash(gmarks_t *g, double w, double h) {
    gm_push(g, "dash", w * 0.35, h / 2, w * 0.3, 1, "--faint");
}

/* G1, the band sparkline. band/has may be NULL for no band at all;
 * has[i] == 0 is a warming cell. */
static void gl_g1(const double (*pts)[2], int n, const double (*band)[4],
                  const int *has, const gopt_t *o, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    double w = o->w, h = o->h;
    if (n <= 0) { gl_dash(g, w, h); return; }
    double step = o->step > 0 ? o->step : 1;
    double lo, hi;
    gl_scale(pts, n, band, has, o->scale, &lo, &hi);
    double from = o->from, to = o->to;
#define GX(t) (to > from ? ((t) - from) / (to - from) * w : 0)
#define GY(v) (h - ((v) - lo) / (hi - lo) * h)
    if (o->shade_on && to > from) {
        double sa = GX(o->shade[0] > from ? o->shade[0] : from);
        double e = o->shade[1] + step;
        double sb = GX(e < to ? e : to);
        if (sb > sa) gm_push(g, "shade", sa, 0, sb - sa > 1 ? sb - sa : 1, h, "--signal");
    }
    int any = 0, i;
    for (i = 0; band && has && i < n; i++) if (has[i]) any = 1;
    for (i = 0; any && has && i < n; i++) {
        if (!has[i]) continue;
        double bx = GX(pts[i][0]);
        double bw = GX(pts[i][0] + step) - bx;
        if (bw < 1) bw = 1;
        double room = w - bx < 0 ? 0 : w - bx;
        if (bw > room) bw = room;
        if (bw > 0)
            gm_push(g, "band", bx, GY(band[i][1]), bw,
                    GY(band[i][0]) - GY(band[i][1]), "--data");
    }
    double gap = step * 2.5;
    int dots = n < 5;
    double max = 0;
    for (i = 0; i < n; i++) if (pts[i][1] > max) max = pts[i][1];
    for (i = 1; i < n; i++) {
        double xa = GX(pts[i - 1][0]), xb = GX(pts[i][0]);
        if (pts[i][0] - pts[i - 1][0] > gap) {
            gm_push(g, "gap", xa, 0, xb - xa, h, "--faint");
            continue;
        }
        if (dots) continue;
        gm_push(g, "line", xa, GY(pts[i - 1][1]), xb - xa,
                GY(pts[i][1]) - GY(pts[i - 1][1]),
                gl_line_token(gl_level(pts[i][1], max)));
    }
    if (dots)
        for (i = 0; i < n - 1; i++)
            gm_push(g, "dot", GX(pts[i][0]), GY(pts[i][1]), 1.5, 1.5, "--tui-normal");
    if (!any) {
        int xi = 0, ni = 0;
        for (i = 1; i < n; i++) {
            if (pts[i][1] > pts[xi][1]) xi = i;
            if (pts[i][1] < pts[ni][1]) ni = i;
        }
        gm_push(g, "max", GX(pts[xi][0]), GY(pts[xi][1]), 1.5, 1.5, "--faint");
        if (ni != xi)
            gm_push(g, "min", GX(pts[ni][0]), GY(pts[ni][1]), 1.5, 1.5, "--faint");
    }
    int k = n - 1;
    const char *tok = "--ink";
    if (any && has && band && has[k] && band[k][3] > 0 &&
        (pts[k][1] > band[k][1] || pts[k][1] < band[k][0])) {
        double sens = o->sens > 0 ? o->sens : 2;
        double z = fabs(pts[k][1] - band[k][2]) / band[k][3];
        double f = (z - sens) / 4 + 0.15;
        tok = gl_heat_token(f < 1 ? f : 1);
    }
    gm_push(g, "last", GX(pts[k][0]), GY(pts[k][1]), 2.5, 2.5, tok);
#undef GX
#undef GY
}

/* G1's words: the arrow since the previous bucket, or "" for none. */
static const char *gl_trend(const double (*pts)[2], int n) {
    if (n < 2) return "";
    double a = pts[n - 2][1], b = pts[n - 1][1];
    return b > a ? "\xe2\x86\x91" : b < a ? "\xe2\x86\x93" : "\xe2\x86\x92";
}

/* R3, F6: one y-scale across a stack, grown from prev (NULL for none). */
typedef struct { const double (*pts)[2]; int n; const double (*band)[4]; const int *has; } gset_t;
static void gl_shared(const gset_t *sets, int ns, const double *prev, double *lo, double *hi) {
    double r[2];
    int have = prev != NULL;
    if (prev) { r[0] = prev[0]; r[1] = prev[1]; }
    for (int i = 0; i < ns; i++) {
        gl_scale(sets[i].pts, sets[i].n, sets[i].band, sets[i].has, have ? r : NULL, lo, hi);
        r[0] = *lo; r[1] = *hi;
        have = 1;
    }
    if (!have) { r[0] = 0; r[1] = 1; }
    *lo = r[0]; *hi = r[1];
}

/* F6's sort: by |z| when any row has one (rows without after, by
 * value), else by value. The answer's word is "|z|" or "value". */
typedef struct { int id; double cur; int has_z; double z; } grow_t;
static int g_byz;
static int gl_order_cmp(const void *pa, const void *pb) {
    const grow_t *a = pa, *b = pb;
    if (g_byz) {
        if (a->has_z != b->has_z) return a->has_z ? -1 : 1;
        if (a->has_z && fabs(b->z) != fabs(a->z)) return fabs(b->z) > fabs(a->z) ? 1 : -1;
    }
    return b->cur > a->cur ? 1 : b->cur < a->cur ? -1 : 0;
}
static const char *gl_order(grow_t *rows, int n) {
    g_byz = 0;
    for (int i = 0; i < n; i++) if (rows[i].has_z) g_byz = 1;
    qsort(rows, (size_t)n, sizeof(rows[0]), gl_order_cmp);
    return g_byz ? "|z|" : "value";
}

/* G4, the hour-of-week grid. cells NULL, or 168 [mean, sd, n]. */
typedef struct {
    double warm; int warming, fed; double max, n;
    int prov, unseen; double top, pn; int none;
} g4st_t;
static g4st_t gl_g4_stats(const double (*cells)[3], double warm) {
    g4st_t o;
    o.warm = warm; o.warming = 0; o.fed = 0; o.max = 0; o.n = 0;
    o.prov = 0; o.unseen = 0; o.top = 0; o.pn = 0; o.none = !cells;
    for (int i = 0; i < 168; i++) {
        if (cells && cells[i][2] >= o.warm) {
            o.fed++;
            o.n += cells[i][2];
            if (cells[i][0] > o.max) o.max = cells[i][0];
            if (cells[i][0] > o.top) o.top = cells[i][0];
            continue;
        }
        o.warming++;
        if (!cells || !(cells[i][2] >= 1)) { o.unseen++; continue; }
        o.prov++;
        o.pn += cells[i][2];
        if (cells[i][0] > o.top) o.top = cells[i][0];
    }
    return o;
}
static void gl_g4(const double (*cells)[3], double w, double h, double x0, double y0,
                  double warm, int now, int share, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    if (!cells) { gl_dash(g, w, h); return; }
    double cw = (w - x0) / 24, ch = (h - y0) / 7;
    g4st_t st = gl_g4_stats(cells, warm);
    double top = share ? 1 : st.top;
    for (int i = 0; i < 168; i++) {
        double x = x0 + cw * (i % 24), y = y0 + ch * (i / 24);
        if (cells[i][2] >= st.warm) {
            gm_push(g, "cell", x + 1, y + 1, cw - 2, ch - 2,
                    gl_heat_token(st.max > 0 ? cells[i][0] / st.max : 0));
            continue;
        }
        gm_push(g, "warm", x + 1, y + 1, cw - 2, ch - 2, "--rule");
        if (!(cells[i][2] >= 1)) continue;
        double f = top > 0 ? cells[i][0] / top : 0;
        int lv = !(f > 0) ? 0 : f < 0.34 ? 1 : f < 0.67 ? 2 : 3;
        double ph = lv ? (ch - 2) * lv / 4 : 1;
        gm_push(g, "prov", x + 1, y + ch - 1 - ph, cw - 2, ph, "--tui-dim");
    }
    if (now >= 0 && now < 168)
        gm_push(g, "outline", x0 + cw * (now % 24), y0 + ch * (now / 24), cw, ch, "--signal");
}

/* app.js's fmt() and heatCaption(), ported: G4's caption is where its
 * warming cells' meaning is carried in words (R10). */
static void gl_fmt(double v, char *out, size_t sz) {
    if (!isfinite(v)) { snprintf(out, sz, "-"); return; }
    double a = fabs(v);
    if (a >= 1e9) snprintf(out, sz, "%.1fG", v / 1e9);
    else if (a >= 1e6) snprintf(out, sz, "%.1fM", v / 1e6);
    else if (a >= 1e4) snprintf(out, sz, "%.1fk", v / 1e3);
    else if (a >= 100 || v == floor(v + 0.5)) snprintf(out, sz, "%.0f", floor(v + 0.5));
    else snprintf(out, sz, "%.2f", v);
}
static void gl_heat_caption(const char *source, const g4st_t *st, int share,
                            const char *unit, char *out, size_t sz) {
    gcap_t c;
    memset(&c, 0, sizeof(c));
    c.source = source;
    c.window = "hour of week";
    if (st->none) {
        c.state = "no data";
        gl_caption(&c, out, sz);
        return;
    }
    char u[24], sc[200], state[200], num[32];
    size_t at = 0;
    snprintf(u, sizeof(u), "%s%s", unit && *unit ? " " : "", unit ? unit : "");
    sc[0] = '\0';
    state[0] = '\0';
    if (st->fed) {
        gl_fmt(st->max, num, sizeof(num));
        at += (size_t)snprintf(sc + at, sizeof(sc) - at, "ramp 0 to %s%s", num, u);
    }
    if (st->prov) {
        gl_fmt(st->top, num, sizeof(num));
        snprintf(sc + at, sizeof(sc) - at, "%sprovisional bar in thirds of 0 to %s%s",
                 at ? ", " : "", share ? "1" : num, share ? "" : u);
    }
    if (st->warming)
        snprintf(state, sizeof(state), "warming: %d of 168 cells, fed: %d, provisional: %d "
                 "(under %d weeks), not yet observed: %d", st->warming, st->fed, st->prov,
                 (int)st->warm, st->unseen);
    c.scale = sc;
    c.n = st->n + st->pn;
    c.state = state;
    gl_caption(&c, out, sz);
}

/* ── web/ui/sun.js, ported ──────────────────────────────────────── */

#define SUN_PI 3.14159265358979323846
#define SUN_NIGHT_BELOW (-6.0)
#define SUN_DAY_ABOVE 6.0
#define SUN_MAX_CELL_S 3600.0
#define SUN_T_MAX 4102444800.0
#define SUN_CELLS_MAX 1440
static const char *const SUN_TOKENS[4] = { "--sun-night", "--sun-rise", "--sun-day", "--sun-set" };
static const double SUN_RAD = SUN_PI / 180;

typedef struct { double lat, lon; } sunpos_t;

static int sun_leap(int y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

static double sun_elev(double t, double lat, double lon) {
    double day = floor(t / 86400), sec = t - day * 86400;
    int y = 1970;
    double len = 365;
    while (day >= len) { day -= len; y++; len = sun_leap(y) ? 366 : 365; }
    double g = 2 * SUN_PI / len * (day + (sec / 3600 - 12) / 24);
    double eq = 229.18 * (0.000075 + 0.001868 * cos(g) - 0.032077 * sin(g) -
                          0.014615 * cos(2 * g) - 0.040849 * sin(2 * g));
    double dec = 0.006918 - 0.399912 * cos(g) + 0.070257 * sin(g) -
                 0.006758 * cos(2 * g) + 0.000907 * sin(2 * g) -
                 0.002697 * cos(3 * g) + 0.00148 * sin(3 * g);
    double ha = (sec / 60 + eq + 4 * lon) / 4 - 180;
    double s = sin(lat * SUN_RAD) * sin(dec) +
               cos(lat * SUN_RAD) * cos(dec) * cos(ha * SUN_RAD);
    return asin(s < -1 ? -1 : s > 1 ? 1 : s) / SUN_RAD;
}

static int sun_phase(double t, double half, double lat, double lon) {
    double e = sun_elev(t, lat, lon);
    if (e < SUN_NIGHT_BELOW) return 0;
    if (e > SUN_DAY_ABOVE) return 2;
    return sun_elev(t + half, lat, lon) >= sun_elev(t - half, lat, lon) ? 1 : 3;
}

static int sun_ok_pos(double lat, double lon) {
    return isfinite(lat) && isfinite(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;
}

/* phases(): 1 and out[0..n-1] filled, or 0 for the JS's null. The JS
 * keeps its answers by (position, from, cellS, n); a memo of a pure
 * function says nothing, so the port has none. */
static int sun_phases(double from, double cell_s, int n, const sunpos_t *pos, int *out) {
    if (!pos || !sun_ok_pos(pos->lat, pos->lon)) return 0;
    if (!isfinite(from) || from < 0 || !(cell_s > 0) || cell_s > SUN_MAX_CELL_S) return 0;
    if (!(n >= 1) || n > SUN_CELLS_MAX || from + n * cell_s > SUN_T_MAX) return 0;
    double lat = floor(pos->lat * 100 + 0.5) / 100, lon = floor(pos->lon * 100 + 0.5) / 100;
    double half = cell_s / 2;
    for (int i = 0; i < n; i++) out[i] = sun_phase(from + i * cell_s + half, half, lat, lon);
    return 1;
}

/* runs(): [phase, first cell] pairs, the count returned. */
static int sun_runs(const int *ph, int n, int (*out)[2]) {
    int k = 0;
    for (int i = 0; ph && i < n; i++)
        if (!i || ph[i] != ph[i - 1]) { out[k][0] = ph[i]; out[k][1] = i; k++; }
    return k;
}

/* G5, the binary presence strip. cells: 1 present, 0 absent, -1 a gap.
 * from NAN and pos NULL are the JS's undefined. */
static void gl_g5_sun(const int *cells, int n, double w, double h, int first,
                      const int (*ep)[2], int nep, double from, double cell_s,
                      const sunpos_t *pos, gmarks_t *g) {
    static int ph[SUN_CELLS_MAX];
    memset(g, 0, sizeof(*g));
    if (n <= 0) { gl_dash(g, w, h); return; }
    double cw = w / n;
    int has = sun_phases(from, cell_s, n, pos, ph);
    for (int i = 0; i < n; i++) {
        double x = floor(i * cw), cwi = ceil(cw);
        if (cwi < 1) cwi = 1;
        if (cells[i] < 0) gm_push(g, "gap", x, 0, cwi, h, "--faint");
        else if (cells[i] > 0)
            gm_push(g, "cell", x, 0, cwi, h, has ? SUN_TOKENS[ph[i]] : "--tui-normal");
    }
    if (first >= 0 && first < n) {
        double cwi = ceil(cw);
        if (cwi < 1) cwi = 1;
        gm_push(g, "first", floor(first * cw), 0, cwi, h, "--signal");
    }
    for (int i = 0; i < nep; i++) {
        int a = ep[i][0] < 0 ? 0 : ep[i][0], b = ep[i][1] > n - 1 ? n - 1 : ep[i][1];
        if (b < a) continue;
        double wd = ceil((b - a + 1) * cw);
        if (wd < 1) wd = 1;
        gm_push(g, "anom", floor(a * cw), h - 1, wd, 1, "--heat-2");
    }
}
/* A strip given no window and no position: every caller before the
 * 2026-11-11 ruling, and every strip while the sensor has no position. */
static void gl_g5(const int *cells, int n, double w, double h, int first,
                  const int (*ep)[2], int nep, gmarks_t *g) {
    gl_g5_sun(cells, n, w, h, first, ep, nep, NAN, NAN, NULL, g);
}

/* now NAN is the JS's undefined; cells 0 and pos NULL likewise. */
static void gl_g5_ruler_sun(double w, double h, double from, double to, double off,
                            double now, int cells, const sunpos_t *pos, gmarks_t *g) {
    static const double SUN_H[4] = { 1, 2, 3, 2 };
    static int ph[SUN_CELLS_MAX];
    int r[SUN_CELLS_MAX][2];
    memset(g, 0, sizeof(*g));
    if (!(to > from)) return;
    int n = cells >= 1 ? cells : 0;
    int has = n ? sun_phases(from, (to - from) / n, n, pos, ph) : 0;
    int nr = sun_runs(has ? ph : NULL, n, r);
    for (int i = 0; i < nr; i++) {
        int a = r[i][1], b = i + 1 < nr ? r[i + 1][1] : n;
        double sh = SUN_H[r[i][0]];
        gm_push(g, "sun", a * w / n, h - sh, (b - a) * w / n, sh, SUN_TOKENS[r[i][0]]);
    }
    double first = ceil((from + off) / 86400) * 86400 - off;
    for (double t = first; t <= to; t += 86400)
        gm_push(g, "tick", (t - from) / (to - from) * w, 0, 1, h, "--faint");
    if (!isfinite(now)) gm_push(g, "now", w - 1, 0, 1, h, "--signal");
    else if (now >= from && now <= to) {
        double x = (now - from) / (to - from) * w;
        gm_push(g, "now", x < w - 1 ? x : w - 1, 0, 1, h, "--signal");
    }
}
static void gl_g5_ruler(double w, double h, double from, double to, double off,
                        gmarks_t *g) {
    gl_g5_ruler_sun(w, h, from, to, off, NAN, 0, NULL, g);
}

/* G6, the bullet and the count bar. */
static void gl_g6(double v, int have_v, double w, double h, double max,
                  const double *ranges, int nr, double threshold, int have_t,
                  int count, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    if (!have_v) { gl_dash(g, w, h); return; }
    if (!(max > 0)) max = 1;
    if (count) nr = 0;
    for (int i = 0; i < nr; i++) {
        double ra = i ? ranges[i - 1] / max : 0, rb = ranges[i] / max;
        double xa = w * (ra < 1 ? ra : 1), xb = w * (rb < 1 ? rb : 1);
        if (i == 0) xa = 0;
        if (xb > xa) gm_push(g, "range", xa, 0, xb - xa, h, i ? "--rule" : "--faint");
    }
    int hot = have_t && v >= threshold;
    double f = v / max;
    if (f < 0) f = 0;
    if (f > 1) f = 1;
    gm_push(g, "bar", 0, h * 0.25, w * f, h * 0.5,
            count ? "--rule" : hot ? "--sev-warn" : "--ink");
    if (!count && have_t && threshold > 0) {
        double tf = threshold / max;
        gm_push(g, "tick", w * (tf < 1 ? tf : 1), 0, 1, h, "--signal");
    }
}

/* G2, the range sparkline (V2). Fixed scale, -95 to -20 dBm; the
 * -67 dBm rule (ruling 3); one sample is its dot alone. has_w 0: no
 * whisker. */
#define GL_RSSI_LO  (-95.0)
#define GL_RSSI_HI  (-20.0)
#define GL_RSSI_REF (-67.0)
static double gl_g2y(double v, double h) {
    double c = v < GL_RSSI_LO ? GL_RSSI_LO : v > GL_RSSI_HI ? GL_RSSI_HI : v;
    return h - (c - GL_RSSI_LO) / (GL_RSSI_HI - GL_RSSI_LO) * h;
}
static void gl_g2(const double (*pts)[2], int n, double w, double h, double from,
                  double to, double step, int has_w, const double *wk, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    if (n <= 0) { gl_dash(g, w, h); return; }
    if (!(step > 0)) step = 1;
#define GX(t) (to > from ? ((t) - from) / (to - from) * w : w)
    int k = n - 1;
    if (!k) { gm_push(g, "last", GX(pts[0][0]), gl_g2y(pts[0][1], h), 2.5, 2.5, "--ink"); return; }
    gm_push(g, "ref", 0, gl_g2y(GL_RSSI_REF, h), w, 1, "--faint");
    double gap = step * 2.5;
    int dots = n < 5;
    for (int i = 1; i < n; i++) {
        double xa = GX(pts[i - 1][0]), xb = GX(pts[i][0]);
        if (pts[i][0] - pts[i - 1][0] > gap) {
            gm_push(g, "gap", xa, 0, xb - xa, h, "--faint");
            continue;
        }
        if (dots) continue;
        gm_push(g, "line", xa, gl_g2y(pts[i - 1][1], h), xb - xa,
                gl_g2y(pts[i][1], h) - gl_g2y(pts[i - 1][1], h), "--tui-normal");
    }
    if (dots)
        for (int i = 0; i < k; i++)
            gm_push(g, "dot", GX(pts[i][0]), gl_g2y(pts[i][1], h), 1.5, 1.5, "--tui-normal");
    if (has_w && wk[1] >= wk[0]) {
        double d = gl_g2y(wk[0], h) - gl_g2y(wk[1], h);
        gm_push(g, "whisker", GX(pts[k][0]), gl_g2y(wk[1], h), 1, d > 1 ? d : 1, "--tui-normal");
    }
    gm_push(g, "last", GX(pts[k][0]), gl_g2y(pts[k][1], h), 2.5, 2.5, "--ink");
#undef GX
}
static int gl_g2_clamped(const double (*pts)[2], int n) {
    int c = 0;
    for (int i = 0; i < n; i++) if (pts[i][1] > GL_RSSI_HI || pts[i][1] < GL_RSSI_LO) c++;
    return c;
}
/* G2's words: sloth's band and trend, never a slope of the page's. */
typedef struct { char text[16]; int bold; char nearw[24]; } g2w_t;
static g2w_t gl_g2_words(int have_last, double last, const char *band, const char *trend) {
    static const char *const B[][2] = { { "immediate", "imm" }, { "near", "near" },
        { "room", "room" }, { "building", "bldg" }, { "far", "far" } };
    static const char *const T[][2] = { { "approaching", "\xe2\x86\x98" },
        { "steady", "\xe2\x86\x92" }, { "leaving", "\xe2\x86\x97" } };
    g2w_t o;
    memset(&o, 0, sizeof(o));
    if (have_last) snprintf(o.text, sizeof(o.text), "%d", (int)floor(last + 0.5));
    else snprintf(o.text, sizeof(o.text), "-");
    o.bold = trend && !strcmp(trend, "approaching");
    const char *b = "", *t = "";
    for (size_t i = 0; band && i < sizeof(B) / sizeof(B[0]); i++) if (!strcmp(band, B[i][0])) b = B[i][1];
    for (size_t i = 0; trend && i < sizeof(T) / sizeof(T[0]); i++) if (!strcmp(trend, T[i][0])) t = T[i][1];
    if (*b && *t) snprintf(o.nearw, sizeof(o.nearw), "%s %s", b, t);
    else snprintf(o.nearw, sizeof(o.nearw), "%s", *b ? b : t);
    return o;
}
/* ── the S-meter, ported (owner rulings 2026-11-11) ─────────────── */

/* glyph.js's sm*(): the face, the band table, the level, the words,
 * the geometry and the mark list, line for line. A reading is `have`
 * and a value, as the other ports take a number-or-null. */
#define GL_SM_DB       6
#define GL_SM_UNITS    9
#define GL_SM_OVER_DB  10
#define GL_SM_OVER_TOP 27
#define GL_SM_EDGES    24
static const struct { const char *band; double mhz; int s9; } GL_SM_BANDS[] = {
    { "2.4 GHz", 2442, -47 },
    { "5 GHz", 5500, -54 },
    { "6 GHz", 6535, -56 },
};
#define GL_SM_NBANDS ((int)(sizeof(GL_SM_BANDS) / sizeof(GL_SM_BANDS[0])))
#define GL_SM_DEFAULT "2.4 GHz"
typedef struct {
    double lo, hi, edges[GL_SM_EDGES], over;
    int n, knee, unknown;
    const char *band;
} smsc_t;
static smsc_t gl_sm_scale(double lo, double hi, double step, int units, double over) {
    smsc_t sc;
    memset(&sc, 0, sizeof(sc));
    for (int i = 0; i < units && sc.n < GL_SM_EDGES; i++) sc.edges[sc.n++] = lo + i * step;
    for (double v = lo + (units - 1) * step + over; over > 0 && v < hi && sc.n < GL_SM_EDGES; v += over)
        sc.edges[sc.n++] = v;
    sc.lo = lo; sc.hi = hi; sc.knee = units; sc.over = over; sc.band = ""; sc.unknown = 0;
    return sc;
}
static int gl_sm_band_row(const char *band) {
    for (int i = 0; band && i < GL_SM_NBANDS; i++) if (!strcmp(band, GL_SM_BANDS[i].band)) return i;
    return -1;
}
static const char *gl_sm_band(int have_ch, double ch, const char *label) {
    if (gl_sm_band_row(label) >= 0) return GL_SM_BANDS[gl_sm_band_row(label)].band;
    if (have_ch && ch >= 1 && ch <= 14) return "2.4 GHz";
    if (have_ch && ch >= 32 && ch <= 177) return "5 GHz";
    return "";
}
static smsc_t gl_sm_dbm(const char *band) {
    int known = gl_sm_band_row(band) >= 0;
    int s9 = GL_SM_BANDS[gl_sm_band_row(known ? band : GL_SM_DEFAULT)].s9;
    smsc_t sc = gl_sm_scale(s9 - (GL_SM_UNITS - 1) * GL_SM_DB, s9 + GL_SM_OVER_TOP, GL_SM_DB,
                            GL_SM_UNITS, GL_SM_OVER_DB);
    sc.band = known ? GL_SM_BANDS[gl_sm_band_row(band)].band : GL_SM_DEFAULT;
    sc.unknown = !known;
    return sc;
}
static int gl_sm_level(int have, double v, const smsc_t *sc) {
    if (!have) return 0;
    double c = v < sc->lo ? sc->lo : v > sc->hi ? sc->hi : v;
    int n = 0;
    for (int i = 0; i < sc->n; i++) if (c >= sc->edges[i]) n++;
    return n;
}
static int gl_sm_clamped(const double (*pts)[2], int n, const smsc_t *sc) {
    int c = 0;
    for (int i = 0; i < n; i++) if (pts[i][1] > sc->hi || pts[i][1] < sc->lo) c++;
    return c;
}
static void gl_sm_word(int have, double v, const smsc_t *sc, char *out, size_t sz) {
    int n = gl_sm_level(have, v, sc);
    if (!n) { snprintf(out, sz, "-"); return; }
    if (n <= sc->knee) snprintf(out, sz, "S%d", n);
    else snprintf(out, sz, "S%d+%d", sc->knee, (int)((n - sc->knee) * sc->over));
}
static void gl_sm_label(const smsc_t *sc, int i, char *out, size_t sz) {
    if (i < sc->knee) snprintf(out, sz, "%d", i + 1);
    else snprintf(out, sz, "+%d", (int)((i - sc->knee + 1) * sc->over));
}
static void gl_sm_note(char *out, size_t sz) {
    size_t at = 0;
    out[0] = '\0';
    for (int i = 0; i < GL_SM_NBANDS && at < sz; i++)
        at += (size_t)snprintf(out + at, sz - at, "%s%s%d%s at %s", i ? ", " : "", i ? "" : "S9 = ",
                               GL_SM_BANDS[i].s9, i ? "" : " dBm", GL_SM_BANDS[i].band);
    if (at < sz)
        snprintf(out + at, sz - at, ", %d dB per S-unit, by the band heard on; "
                 "a display scale, not the IARU reference", GL_SM_DB);
}
static int gl_sm_range(const double (*pts)[2], int n, double *lo, double *hi) {
    int have = 0;
    for (int i = 0; i < n; i++) {
        if (!have || pts[i][1] < *lo) *lo = pts[i][1];
        if (!have || pts[i][1] > *hi) *hi = pts[i][1];
        have = 1;
    }
    return have;
}
#define GL_SM_GAP  1
#define GL_SM_KNEE 3
typedef struct { int n, k; double sw; } smgeo_t;
static smgeo_t gl_sm_geo(const smsc_t *sc, double w) {
    smgeo_t ge;
    ge.n = sc->n;
    ge.k = sc->knee < sc->n ? GL_SM_KNEE - GL_SM_GAP : 0;
    ge.sw = floor((w - (ge.n - 1) * GL_SM_GAP - ge.k) / ge.n);
    if (ge.sw < 1) ge.sw = 1;
    return ge;
}
static double gl_sm_seg_x(int i, const smsc_t *sc, const smgeo_t *ge) {
    return i * (ge->sw + GL_SM_GAP) + (i >= sc->knee ? ge->k : 0);
}
static double gl_sm_x(double v, const smsc_t *sc, double w) {
    smgeo_t ge = gl_sm_geo(sc, w);
    int i = gl_sm_level(1, v, sc) - 1;
    if (i < 0) i = 0;
    double c = v < sc->lo ? sc->lo : v > sc->hi ? sc->hi : v;
    double top = i + 1 < ge.n ? sc->edges[i + 1] : sc->hi;
    double f = top > sc->edges[i] ? (c - sc->edges[i]) / (top - sc->edges[i]) : 0;
    if (f < 0) f = 0;
    double in = floor(f * ge.sw);
    return gl_sm_seg_x(i, sc, &ge) + (in < ge.sw - 1 ? in : ge.sw - 1);
}
/* have_r 0: no window range (the JS's lo and hi null). */
static void gl_sm(int have, double v, double w, double h, const smsc_t *scale,
                  int have_r, double lo, double hi, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    smsc_t dflt = gl_sm_dbm("");
    const smsc_t *sc = scale ? scale : &dflt;
    if (!have) { gl_dash(g, w, h); return; }
    smgeo_t ge = gl_sm_geo(sc, w);
    int lit = gl_sm_level(have, v, sc);
    for (int i = 0; i < ge.n; i++) {
        if (i < lit)
            gm_push(g, "seg", gl_sm_seg_x(i, sc, &ge), h * 0.25, ge.sw, h * 0.5,
                    i < sc->knee ? "--tui-normal" : "--heat-3");
        else gm_push(g, "off", gl_sm_seg_x(i, sc, &ge), h / 2 - 1, ge.sw, 2, "--rule");
    }
    if (have_r && hi > lo) {
        gm_push(g, "pklo", gl_sm_x(lo, sc, w), 0, 1, h, "--ink");
        gm_push(g, "pkhi", gl_sm_x(hi, sc, w), 0, 1, h, "--ink");
    }
}
static int gl_sm_cells(int have, double v, const smsc_t *sc, const char **out) {
    int lit = gl_sm_level(have, v, sc), n = 0;
    for (int i = 0; lit && i < sc->n; i++)
        out[n++] = i >= lit ? "--tui-dim" : i < sc->knee ? "--tui-normal" : "--heat-3";
    return n;
}

/* F15: new inside the window, and G5's first-seen cell. */
static int gl_is_new(int have, double first, double from) { return have && first >= from; }
static int gl_first_cell(int have, double first, double from, double cell_s, int n) {
    if (!gl_is_new(have, first, from) || !(cell_s > 0)) return -1;
    int c = (int)floor((first - from) / cell_s);
    return c < n ? c : -1;
}

/* ── V3: G3 and G7, ported ──────────────────────────────────────── */

/* G3, the horizon strip. v[i] is a column's value in bands where has[i],
 * else nothing was observed; warm may be NULL. */
static void gl_g3(const double *v, const int *has, const int *warm, int n,
                  double w, double h, int hot, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    int any = 0;
    for (int i = 0; i < n; i++) if (has[i] || (warm && warm[i])) any = 1;
    if (!any) { gl_dash(g, w, h); return; }
    double cw = w / n;
    for (int i = 0; i < n; i++) {
        double x = floor(i * cw), cwi = ceil(cw);
        if (cwi < 1) cwi = 1;
        if (!has[i]) {
            if (warm && warm[i]) gm_push(g, "warm", x, 0, cwi, h, "--rule");
            continue;
        }
        double a = v[i];
        if (!(a > 0)) { gm_push(g, "base", x, h - 1, cwi, 1, "--rule"); continue; }
        double b1 = a < 1 ? a : 1;
        gm_push(g, "hz1", x, h - h * b1, cwi, h * b1, "--data");
        if (a > 1) {
            double b2 = a - 1 < 1 ? a - 1 : 1;
            gm_push(g, "hz2", x, h - h * b2, cwi, h * b2, hot ? "--heat-2" : "--data");
        }
        if (a > 2) gm_push(g, "clip", x, 0, cwi, 1, "--ink");
    }
}

/* G3's columns in bands from a row: cells (has_c), and for a z row its
 * z (has_z); k the slider's, rate the cell's factor, max the scale's
 * top. Out: v, has, warm; the return is hot. */
static int gl_g3_vals(const double *cells, const int *has_c, int zrow, const double *z,
                      const int *has_z, int n, double k, double rate, double max,
                      double *v, int *has, int *warm) {
    for (int i = 0; i < n; i++) {
        warm[i] = 0;
        if (zrow) {
            if (has_z && has_z[i]) {
                v[i] = k > 0 ? (z[i] > 0 ? z[i] : 0) / k : 0;
                has[i] = 1;
            } else {
                v[i] = 0;
                has[i] = 0;
                warm[i] = has_c[i];
            }
        } else if (!has_c[i]) {
            v[i] = 0;
            has[i] = 0;
        } else {
            v[i] = max > 0 ? cells[i] * rate / (max / 2) : 0;
            has[i] = 1;
        }
    }
    return zrow;
}

/* G7, the event rug: nl lanes of n columns each, counts[l][i] (zero is
 * none), one span per lane at most ([a, b], or a > b for none). */
#define G7_N 16
typedef struct { double c[G7_N]; int n; const char *tok; int span[2]; } glane_t;
static double gl_g7_max(const glane_t *ln, int nl) {
    double max = 0;
    for (int j = 0; j < nl; j++)
        for (int i = 0; i < ln[j].n; i++) if (ln[j].c[i] > max) max = ln[j].c[i];
    return max;
}
static void gl_g7(const glane_t *ln, int nl, double w, double h, double L, double gp,
                  const double *marks, int nm, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    double max = gl_g7_max(ln, nl);
    for (int j = 0; j < nl; j++) {
        int n = ln[j].n;
        double cw = n ? w / n : 0, y0 = j * (L + gp);
        for (int i = 0; i < n; i++) {
            if (!(ln[j].c[i] > 0)) continue;
            double th = L * ln[j].c[i] / max;
            if (th < 1) th = 1;
            double tw = ceil(cw) - (cw > 3 ? 1 : 0);
            if (tw < 1) tw = 1;
            gm_push(g, "tick", floor(i * cw), y0 + L - th, tw, th, ln[j].tok);
        }
        if (n && ln[j].span[0] <= ln[j].span[1]) {
            int a = ln[j].span[0] < 0 ? 0 : ln[j].span[0];
            int b = ln[j].span[1] > n - 1 ? n - 1 : ln[j].span[1];
            if (b >= a) {
                double sw = ceil((b - a + 1) * cw);
                if (sw < 1) sw = 1;
                gm_push(g, "span", floor(a * cw), y0 + L, sw, 1, "--sev-crit");
            }
        }
    }
    for (int i = 0; i < nm; i++) gm_push(g, "session", marks[i], 0, 2, h, "--ink");
    if (!g->n) gl_dash(g, w, h);
}

/* ── V4: G8 and the Flows matrix, ported ────────────────────────── */

/* G8's lanes: counts (NULL for a lane without them) of nc columns, and
 * up to four bars [a, b, sev, open] in columns. */
typedef struct { const double *counts; int nc; double bars[4][4]; int nb; } g8lane_t;
typedef struct { int has; double col; int top; const char *word; } g8link_t;
typedef struct { const char *text, *tok; } g8label_t;

static double gl_g8_max(const g8lane_t *ln, int nl, double prev) {
    double max = prev > 0 ? prev : 0;
    for (int j = 0; j < nl; j++)
        for (int i = 0; ln[j].counts && i < ln[j].nc; i++)
            if (ln[j].counts[i] > max) max = ln[j].counts[i];
    return max;
}

static void gl_g8(const g8lane_t *ln, int nl, const g8link_t *lk, int nk,
                  const g8label_t *lb, double w, double L, double gx, int ncol,
                  double prev, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    int n = ncol > 0 ? ncol : 1;
    double gw = w - gx > 1 ? w - gx : 1, cw = gw / n;
    if (!nl) { gl_dash(g, w, L); return; }
    double max = gl_g8_max(ln, nl, prev);
    for (int j = 0; j < nl; j++) {
        double y0 = j * L, mid = y0 + L / 2;
        gm_push(g, "axis", gx, mid, gw, 1, "--rule");
        if (lb && lb[j].text) gm_push_t(g, "label", 2, mid, gx - 4, 10, lb[j].tok, lb[j].text);
        for (int i = 0; max > 0 && ln[j].counts && i < ln[j].nc && i < n; i++) {
            double c = ln[j].counts[i];
            if (!(c > 0)) continue;
            double th = (L - 4) * c / max;
            if (th < 1) th = 1;
            double tw = ceil(cw) - (cw > 3 ? 1 : 0);
            if (tw < 1) tw = 1;
            gm_push(g, "tick", floor(gx + i * cw), y0 + L - 2 - th, tw, th, "--tui-normal");
        }
        for (int i = 0; i < ln[j].nb; i++) {
            double a0 = ln[j].bars[i][0], b0 = ln[j].bars[i][1];
            if (b0 < 0 || a0 > n - 1 || b0 < a0) continue;
            int sv = (int)ln[j].bars[i][2];
            const char *tok = sv == 0 ? "--sev-low" : sv == 2 ? "--sev-crit" : "--sev-warn";
            double xa = gx + (a0 > 0 ? a0 : 0) * cw;
            double xb = gx + ((b0 < n - 1 ? b0 : n - 1) + 1) * cw;
            gm_push(g, "bar", xa, mid - 2, xb - xa > 1 ? xb - xa : 1, 4, tok);
            if (a0 >= 0) gm_push(g, "dot", xa, mid, 2.5, 2.5, tok);
            if (!ln[j].bars[i][3] && b0 <= n - 1) gm_push(g, "dot", xb, mid, 2.5, 2.5, tok);
        }
    }
    /* The words in column order, each after the one before it (a JS
     * sort is stable, so ties keep their order, as this insertion sort
     * does). A word's width is its characters at 6 px, counted as JS
     * counts them: one a code point here, the words being BMP. */
    double wy = nl * L, wx = -1;
    int ord[8], no = 0;
    for (int i = 0; i < nk && no < 8; i++) {
        if (!lk[i].has || lk[i].col < 0 || lk[i].col > n - 1 ||
            !(lk[i].top >= 0 && lk[i].top < nl))
            continue;
        int j = no++;
        while (j > 0 && lk[ord[j - 1]].col > lk[i].col) { ord[j] = ord[j - 1]; j--; }
        ord[j] = i;
    }
    for (int q = 0; q < no; q++) {
        const g8link_t *k = &lk[ord[q]];
        double lx = floor(gx + k->col * cw + cw / 2), ly = k->top * L + L / 2;
        int nch = 0;
        for (const unsigned char *u = (const unsigned char *)k->word; *u; u++)
            if ((*u & 0xc0) != 0x80) nch++;
        double tw = nch * 6, tx = lx + 3 > wx + 6 ? lx + 3 : wx + 6;
        if (tx + tw > w) tx = wx + 6 > w - tw ? wx + 6 : w - tw;
        gm_push(g, "link", lx, ly, 1, wy + 2 - ly, "--faint");
        gm_push_t(g, "word", tx, wy + 6, w - tx > 1 ? w - tx : 1, 10, "--muted", k->word);
        wx = tx + tw;
    }
}

/* g8Lanes: a /api/wifi/chain row (16 cells at most) as G8's lanes. */
typedef struct { double e[4][4]; int n; } glist_t;    /* [first, last, sev, count] */
typedef struct { int has_t; double t; int has_a; double a; int has_c; double c; } gclink_t;
typedef struct {
    double   cells[16];
    int      has_cell[16], ncell;
    glist_t  floods, twin, karma;
    double   assoc[16];
    int      nassoc;
    gclink_t links[2];
    int      nlinks;
} gchrow_t;
typedef struct {
    g8lane_t  lanes[4];
    double    dc[16];
    g8label_t labels[4];
    char      ltext[4][48];
    g8link_t  links[4];
    int       nlinks, stages;
} glanes_t;

static void gl_g8_bars(const glist_t *l, double from, double cs, int n, g8lane_t *o) {
    o->nb = l->n;
    for (int i = 0; i < l->n; i++) {
        double b = floor((l->e[i][1] - from) / cs);
        o->bars[i][0] = floor((l->e[i][0] - from) / cs);
        o->bars[i][1] = b;
        o->bars[i][2] = l->e[i][2];
        o->bars[i][3] = b >= n - 1 ? 1 : 0;
    }
}
static void gl_g8_words(const char *name, const glist_t *l, int have, const char *extra,
                        char *out, size_t sz, const char **tok) {
    double hi = -1;
    for (int i = 0; l && i < l->n; i++) if (l->e[i][2] > hi) hi = l->e[i][2];
    const char *sv = hi == 0 ? " low" : hi == 1 ? " warn" : hi == 2 ? " CRIT" : "";
    if (have) snprintf(out, sz, "%s%s%s", name, sv, extra ? extra : "");
    else snprintf(out, sz, "%s none", name);
    *tok = have ? "--ink" : "--muted";
}
static void gl_g8_lanes(const gchrow_t *r, double from, double cs, int n, glanes_t *o) {
    memset(o, 0, sizeof(*o));
    if (!(cs > 0)) cs = 1;
    int nd = 0, na = 0;
    for (int i = 0; i < r->ncell; i++) {
        o->dc[i] = r->has_cell[i] ? r->cells[i] : 0;
        if (o->dc[i] > 0) nd++;
    }
    for (int i = 0; i < r->nassoc; i++) if (r->assoc[i] > 0) na++;
    int has_conf = 0;
    double conf = 0;
    for (int i = 0; i < r->nlinks; i++) {
        if (r->links[i].has_t)
            o->links[o->nlinks++] = (g8link_t){ 1, floor((r->links[i].t - from) / cs), 0,
                                                "tainted \xe2\x86\x91 5 s" };
        if (r->links[i].has_a)
            o->links[o->nlinks++] = (g8link_t){ 1, floor((r->links[i].a - from) / cs), 1,
                                                "attributed \xe2\x86\x91" };
        if (r->links[i].has_c) { has_conf = 1; conf = r->links[i].c; }
    }
    int lure = r->twin.n + r->karma.n > 0;
    o->stages = (nd || r->floods.n ? 1 : 0) + (r->twin.n ? 1 : 0) + (na && lure ? 1 : 0) +
                (r->karma.n ? 1 : 0);
    o->lanes[0].counts = o->dc;
    o->lanes[0].nc = r->ncell;
    gl_g8_bars(&r->floods, from, cs, n, &o->lanes[0]);
    gl_g8_bars(&r->twin, from, cs, n, &o->lanes[1]);
    o->lanes[2].counts = r->assoc;
    o->lanes[2].nc = r->nassoc;
    gl_g8_bars(&r->karma, from, cs, n, &o->lanes[3]);
    char ex[16] = "";
    if (has_conf) snprintf(ex, sizeof(ex), " %.0f%%", conf);
    gl_g8_words("deauth", &r->floods, nd > 0 || r->floods.n > 0, NULL, o->ltext[0],
                sizeof(o->ltext[0]), &o->labels[0].tok);
    gl_g8_words("twin", &r->twin, r->twin.n > 0, ex, o->ltext[1], sizeof(o->ltext[1]),
                &o->labels[1].tok);
    gl_g8_words("assoc", NULL, na > 0, NULL, o->ltext[2], sizeof(o->ltext[2]),
                &o->labels[2].tok);
    gl_g8_words("karma", &r->karma, r->karma.n > 0, NULL, o->ltext[3], sizeof(o->ltext[3]),
                &o->labels[3].tok);
    for (int i = 0; i < 4; i++) o->labels[i].text = o->ltext[i];
}

/* The matrix: a cell's pair, total, protocols (by name) and SMB1. */
typedef struct { int s, d; double total; const char *protos[4]; int np; int smb1; } gcell_t;

static const char *gl_letter(const char *p) {
    static const char *const T[][2] = { { "ssh", "S" }, { "rdp", "R" }, { "smb", "M" },
                                        { "snmp", "N" }, { "bgp", "B" }, { "ldap", "L" },
                                        { "kerb", "K" } };
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) if (!strcmp(T[i][0], p)) return T[i][1];
    return NULL;
}
/* Math.round is floor(x + 0.5). */
static void gl_mx_num(double v, char *out, size_t sz) {
    if (!(v >= 0)) snprintf(out, sz, "-");
    else if (v < 1000) snprintf(out, sz, "%.0f", floor(v + 0.5));
    else if (v < 1e6) {
        if (v < 1e4) snprintf(out, sz, "%.1fk", v / 1e3);
        else snprintf(out, sz, "%.0fk", floor(v / 1e3 + 0.5));
    } else if (v < 1e7) snprintf(out, sz, "%.1fM", v / 1e6);
    else snprintf(out, sz, "%.0fM", floor(v / 1e6 + 0.5));
}
static double gl_mx_max(const gcell_t *c, int nc, double prev) {
    double max = prev > 0 ? prev : 0;
    for (int i = 0; i < nc; i++) if (c[i].total > max) max = c[i].total;
    return max;
}
static void gl_mx(const int *sg, int ns, const int *dg, int nd, const gcell_t *c, int nc,
                  double x0, double y0, double cw, double ch, double prev, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    double W = x0 + nd * cw, Hh = y0 + ns * ch;
    if (!nc) { gl_dash(g, W > 60 ? W : 60, ch); return; }
    double max = gl_mx_max(c, nc, prev);
    for (int i = 1; i < ns; i++)
        if (sg[i] != sg[i - 1]) gm_push(g, "grp", 0, y0 + i * ch, W, 1, "--rule");
    for (int i = 1; i < nd; i++)
        if (dg[i] != dg[i - 1]) gm_push(g, "grp", x0 + i * cw, 0, 1, Hh, "--rule");
    for (int i = 0; i < nc; i++) {
        double x = x0 + c[i].d * cw, y = y0 + c[i].s * ch;
        double v = c[i].total > 0 ? c[i].total : 0, f = max > 0 ? v / max : 0;
        double bw = (cw - 4) * (f < 1 ? f : 1);
        gm_push(g, "bar", x + 2, y + ch * 0.25, bw > 1 ? bw : 1, ch * 0.5,
                c[i].smb1 ? "--sev-crit" : "--rule");
        char t[24];
        gl_mx_num(v, t, sizeof(t));
        gm_push_t(g, "num", x + 3, y + ch / 2, cw - 6, 10, c[i].smb1 ? "--sev-crit" : "--ink", t);
        char lt[8] = "";
        for (int k = 0; k < c[i].np; k++) {
            const char *l = gl_letter(c[i].protos[k]);
            if (l && strlen(lt) + 1 < sizeof(lt)) strcat(lt, l);
        }
        double nl = (double)strlen(lt);
        if (nl > 0) gm_push_t(g, "proto", x + cw - 2 - 5 * nl, y + 4, 5 * nl, 7, "--muted", lt);
    }
}

/* ── the JS, pinned as served ───────────────────────────────────── */

/* Seen red with web/ui/glyph.js left out of index.html's includes, and
 * again with one character changed in each pinned line. */
static void test_the_page_carries_the_ported_js(void) {
    const char *p = page();
    WT_HAS(p, "var glyph = (function () {");
    WT_HAS(p, "  function level(v, max) {\n"
              "    if (!(v > 0) || !(max > 0)) return 0;\n"
              "    var l = Math.floor(v / max * 8 + 0.5);\n"
              "    return l < 1 ? 1 : l > 8 ? 8 : l;\n"
              "  }");
    WT_HAS(p, "    return l === 0 ? \"--tui-dim\" : l <= 2 ? \"--tui-normal\" :\n"
              "           l <= 4 ? \"--heat-1\" : l <= 6 ? \"--heat-2\" : \"--heat-3\";");
    WT_HAS(p, "    return f < 0.15 ? \"--heat-0\" : f < 0.40 ? \"--heat-1\" :\n"
              "           f < 0.70 ? \"--heat-2\" : \"--heat-3\";");
    WT_HAS(p, "  function dur(s) {\n"
              "    s = Math.round(s);\n"
              "    if (s < 60) return s + \" s\";\n"
              "    if (s < 3600) return Math.round(s / 60) + \" min\";\n"
              "    if (s <= 86400) return Math.round(s / 3600) + \" h\";\n"
              "    return Math.round(s / 86400) + \" d\";\n"
              "  }");
    WT_HAS(p, "    if (!(cover > 0) || cover >= span * WINDOW_SHARE) return o;");
    WT_HAS(p, "    o.text = dur(cover) + \" of \" + dur(span);");
    WT_HAS(p, "    p.push(\"n=\" + (gnum(c.n) ? Math.round(c.n) : 0));");
    WT_HAS(p, "  function dash(w, h) { return [\"dash\", w * 0.35, h / 2, "
              "w * 0.3, 1, \"--faint\"]; }");
    WT_HAS(p, "      if (bw > 0) m.push([\"band\", bx, Y(b[1]), bw, "
              "Y(b[0]) - Y(b[1]), \"--data\"]);");
    WT_HAS(p, "        m.push([\"gap\", xa, 0, xb - xa, h, \"--faint\"]);");
    WT_HAS(p, "      m.push([\"line\", xa, Y(pts[i - 1][1]), xb - xa, "
              "Y(pts[i][1]) - Y(pts[i - 1][1]),\n"
              "              lineToken(level(pts[i][1], max))]);");
    WT_HAS(p, "      m.push([\"max\", X(pts[xi][0]), Y(pts[xi][1]), 1.5, 1.5, "
              "\"--faint\"]);");
    WT_HAS(p, "    m.push([\"last\", X(pts[k][0]), Y(pts[k][1]), 2.5, 2.5, tok]);");
    WT_HAS(p, "      out.push((parseInt(hex.charAt(i >> 2), 16) & (8 >> (i & 3))) "
              "? 1 : 0);");
    /* G5's cell line, and all of g5() and g5Ruler(), are pinned whole in
     * test_the_page_carries_the_sun (the 2026-11-11 ruling). */
    WT_HAS(p, "      if (cells[i] < 0) m.push([\"gap\", x, 0, cwi, h, \"--faint\"]);\n");
    WT_HAS(p, "    var first = Math.ceil((from + off) / 86400) * 86400 - off;");
    WT_HAS(p, "      m.push([\"anom\", Math.floor(a * cw), h - 1,\n"
              "              Math.max(1, Math.ceil((b - a + 1) * cw)), 1, \"--heat-2\"]);");
    /* R4's other half, which is drawing and not a mark list: the band
     * chart's third time label and its now mark, in app.js, and that
     * every band chart on the page is given one. */
    WT_HAS(p, "      var midTxt = hhmmss(Math.round((opt.from + opt.to) / 2));");
    WT_HAS(p, "      if (num(opt.now) && opt.now >= opt.from && opt.now <= opt.to) {\n"
              "        g.fillStyle = T.signal;\n"
              "        g.fillRect(X(opt.now), y1, Math.max(1, dpr), y0 - y1);");
    WT_HAS(p, "color: theme().normal, band: bd, now: now,");
    WT_HAS(p, "color: theme().normal, axes: true, band: bd,\n"
              "                                     now: now });");
    WT_HAS(p, "color: theme().normal, axes: true, band: pbd,\n"
              "                                     now: Math.floor(Date.now() / 1000) });");
    WT_HAS(p, "    m.push([\"bar\", 0, h * 0.25, w * Math.max(0, Math.min(1, v / max)), "
              "h * 0.5,\n"
              "            opt.count ? \"--rule\" : hot ? \"--sev-warn\" : \"--ink\"]);");
    WT_HAS(p, "      if (k === \"gap\") continue;");
    /* V1: G1's words, the episode shade, the shared scale, the sort,
     * G4. */
    WT_HAS(p, "    return b > a ? \"\\u2191\" : b < a ? \"\\u2193\" : \"\\u2192\";");
    WT_HAS(p, "      var sa = X(Math.max(sh[0], from)), sb = X(Math.min(sh[1] + step, to));\n"
              "      if (sb > sa) m.push([\"shade\", sa, 0, Math.max(1, sb - sa), h, \"--signal\"]);");
    WT_HAS(p, "    for (var i = 0; sets && i < sets.length; i++) r = scale(sets[i].pts, sets[i].band, r);\n"
              "    return r || [0, 1];");
    WT_HAS(p, "        if (za !== zb) return za ? -1 : 1;\n"
              "        if (za && Math.abs(b.z) !== Math.abs(a.z)) return Math.abs(b.z) - Math.abs(a.z);");
    WT_HAS(p, "    return { rows: out, by: byz ? \"|z|\" : \"value\" };");
    WT_HAS(p, "      if (c && c[2] >= st.warm) {\n"
              "        m.push([\"cell\", x + 1, y + 1, cw - 2, ch - 2,\n"
              "                heatToken(st.max > 0 ? c[0] / st.max : 0)]);\n"
              "        continue;\n"
              "      }\n"
              "      m.push([\"warm\", x + 1, y + 1, cw - 2, ch - 2, \"--rule\"]);");
    WT_HAS(p, "      m.push([\"outline\", x0 + cw * (nc % 24), y0 + ch * Math.floor(nc / 24), cw, ch, \"--signal\"]);");
    WT_HAS(p, "      if (!c || !(c[2] >= 1)) { o.unseen++; continue; }");
    WT_HAS(p, "      } else if (k === \"band\" || k === \"shade\") {\n"
              "        g.globalAlpha = 0.12;");
    /* The V1 functions whole, not a line of each: a line-only pin let
     * G4's all-warming guard and its stats' max change in the JS with
     * the port, and so the suite, still green (the V1 review, seen
     * green, then red once these were pinned). */
    WT_HAS(p, "  function trend(pts) {\n"
              "    if (!pts || pts.length < 2) return \"\";\n"
              "    var a = pts[pts.length - 2][1], b = pts[pts.length - 1][1];\n"
              "    return b > a ? \"\\u2191\" : b < a ? \"\\u2193\" : \"\\u2192\";\n");
    WT_HAS(p, "  function shared(sets, prev) {\n"
              "    var r = prev ? [prev[0], prev[1]] : null;\n"
              "    for (var i = 0; sets && i < sets.length; i++) r = scale(sets[i].pts, sets[i].band, r);\n"
              "    return r || [0, 1];\n");
    WT_HAS(p, "  function order(rows) {\n"
              "    var out = (rows || []).slice(), byz = false, i;\n"
              "    for (i = 0; i < out.length; i++) if (gnum(out[i].z)) byz = true;\n"
              "    out.sort(function (a, b) {\n"
              "      if (byz) {\n"
              "        var za = gnum(a.z), zb = gnum(b.z);\n"
              "        if (za !== zb) return za ? -1 : 1;\n"
              "        if (za && Math.abs(b.z) !== Math.abs(a.z)) return Math.abs(b.z) - Math.abs(a.z);\n"
              "      }\n"
              "      return (gnum(b.cur) ? b.cur : 0) - (gnum(a.cur) ? a.cur : 0);\n"
              "    });\n"
              "    return { rows: out, by: byz ? \"|z|\" : \"value\" };\n");
    WT_HAS(p, "  function g4(cells, opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, x0 = opt.x0 || 0, y0 = opt.y0 || 0, i;\n"
              "    if (!cells) { m.push(dash(w, h)); return m; }\n"
              "    var cw = (w - x0) / 24, ch = (h - y0) / 7, st = g4Stats(cells, opt.warm);\n"
              "    var top = opt.share ? 1 : st.top;\n"
              "    for (i = 0; i < 168; i++) {\n"
              "      var c = cells[i], x = x0 + cw * (i % 24), y = y0 + ch * Math.floor(i / 24);\n"
              "      if (c && c[2] >= st.warm) {\n"
              "        m.push([\"cell\", x + 1, y + 1, cw - 2, ch - 2,\n"
              "                heatToken(st.max > 0 ? c[0] / st.max : 0)]);\n"
              "        continue;\n"
              "      }\n"
              "      m.push([\"warm\", x + 1, y + 1, cw - 2, ch - 2, \"--rule\"]);\n"
              "      if (!c || !(c[2] >= 1)) continue;\n"
              "      var f = top > 0 ? c[0] / top : 0;\n"
              "      var lv = !(f > 0) ? 0 : f < 0.34 ? 1 : f < 0.67 ? 2 : 3;\n"
              "      var ph = lv ? (ch - 2) * lv / 4 : 1;\n"
              "      m.push([\"prov\", x + 1, y + ch - 1 - ph, cw - 2, ph, \"--tui-dim\"]);\n"
              "    }\n"
              "    var nc = opt.now;\n"
              "    if (gnum(nc) && nc >= 0 && nc < 168)\n"
              "      m.push([\"outline\", x0 + cw * (nc % 24), y0 + ch * Math.floor(nc / 24), cw, ch, \"--signal\"]);\n"
              "    return m;\n"
              "  }\n");
    /* V2: G2, its words and the new mark, whole. Seen red with one
     * character changed in each (the -67 rule's constant, and the
     * approaching word). */
    WT_HAS(p, "  var RSSI_LO = -95, RSSI_HI = -20, RSSI_REF = -67;\n"
              "  function g2Y(v, h) {\n"
              "    var c = v < RSSI_LO ? RSSI_LO : v > RSSI_HI ? RSSI_HI : v;\n"
              "    return h - (c - RSSI_LO) / (RSSI_HI - RSSI_LO) * h;\n"
              "  }\n"
              "  function g2(pts, opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, i;\n"
              "    if (!pts || !pts.length) { m.push(dash(w, h)); return m; }\n"
              "    var step = opt.step > 0 ? opt.step : 1, from = opt.from, to = opt.to;\n"
              "    var X = function (t) { return to > from ? (t - from) / (to - from) * w : w; };\n"
              "    var k = pts.length - 1;\n"
              "    if (!k) { m.push([\"last\", X(pts[0][0]), g2Y(pts[0][1], h), 2.5, 2.5, \"--ink\"]); return m; }\n"
              "    m.push([\"ref\", 0, g2Y(RSSI_REF, h), w, 1, \"--faint\"]);\n"
              "    var gap = step * GAP_STEPS, dots = pts.length < DOTS_BELOW;\n"
              "    for (i = 1; i < pts.length; i++) {\n"
              "      var xa = X(pts[i - 1][0]), xb = X(pts[i][0]);\n"
              "      if (pts[i][0] - pts[i - 1][0] > gap) {\n"
              "        m.push([\"gap\", xa, 0, xb - xa, h, \"--faint\"]);\n"
              "        continue;\n"
              "      }\n"
              "      if (dots) continue;\n"
              "      m.push([\"line\", xa, g2Y(pts[i - 1][1], h), xb - xa,\n"
              "              g2Y(pts[i][1], h) - g2Y(pts[i - 1][1], h), \"--tui-normal\"]);\n"
              "    }\n"
              "    if (dots)\n"
              "      for (i = 0; i < k; i++)\n"
              "        m.push([\"dot\", X(pts[i][0]), g2Y(pts[i][1], h), 1.5, 1.5, \"--tui-normal\"]);\n"
              "    var wk = opt.whisker;\n"
              "    if (wk && gnum(wk[0]) && gnum(wk[1]) && wk[1] >= wk[0])\n"
              "      m.push([\"whisker\", X(pts[k][0]), g2Y(wk[1], h), 1,\n"
              "              Math.max(1, g2Y(wk[0], h) - g2Y(wk[1], h)), \"--tui-normal\"]);\n"
              "    m.push([\"last\", X(pts[k][0]), g2Y(pts[k][1], h), 2.5, 2.5, \"--ink\"]);\n"
              "    return m;\n"
              "  }\n");
    WT_HAS(p, "      if (pts[i][1] > RSSI_HI || pts[i][1] < RSSI_LO) n++;");
    WT_HAS(p, "  var BAND_SHORT = { immediate: \"imm\", near: \"near\", room: \"room\", "
              "building: \"bldg\", far: \"far\" };\n"
              "  var TREND_GLYPH = { approaching: \"\\u2198\", steady: \"\\u2192\", "
              "leaving: \"\\u2197\" };\n"
              "  function g2Words(last, band, trend) {\n"
              "    var own = Object.prototype.hasOwnProperty;\n"
              "    var b = typeof band === \"string\" && own.call(BAND_SHORT, band) ? BAND_SHORT[band] : \"\";\n"
              "    var g = typeof trend === \"string\" && own.call(TREND_GLYPH, trend) ? TREND_GLYPH[trend] : \"\";\n"
              "    return { text: gnum(last) ? String(Math.round(last)) : \"-\",\n"
              "             bold: trend === \"approaching\", near: b && g ? b + \" \" + g : b || g };\n"
              "  }\n");
    WT_HAS(p, "  function isNew(first, from) { return gnum(first) && gnum(from) && first >= from; }\n"
              "  function firstCell(first, from, cellS, n) {\n"
              "    if (!isNew(first, from) || !(cellS > 0)) return -1;\n"
              "    var c = Math.floor((first - from) / cellS);\n"
              "    return c < n ? c : -1;\n"
              "  }\n");
    WT_HAS(p, "  function g4Stats(cells, warm) {\n"
              "    var o = { warm: gnum(warm) ? warm : 3, warming: 0, fed: 0, max: 0, n: 0,\n"
              "              prov: 0, unseen: 0, top: 0, pn: 0, none: !cells };\n"
              "    for (var i = 0; i < 168; i++) {\n"
              "      var c = cells && cells[i];\n"
              "      if (c && c[2] >= o.warm) {\n"
              "        o.fed++;\n"
              "        o.n += c[2];\n"
              "        if (c[0] > o.max) o.max = c[0];\n"
              "        if (c[0] > o.top) o.top = c[0];\n"
              "        continue;\n"
              "      }\n"
              "      o.warming++;\n"
              "      if (!c || !(c[2] >= 1)) { o.unseen++; continue; }\n"
              "      o.prov++;\n"
              "      o.pn += c[2];\n"
              "      if (c[0] > o.top) o.top = c[0];\n"
              "    }\n"
              "    return o;\n"
              "  }\n");
}

/* ── G1, every state §9 asks for ────────────────────────────────── */

static gopt_t g1opt(void) {
    gopt_t o;
    memset(&o, 0, sizeof(o));
    o.w = 100; o.h = 18; o.from = 1000; o.to = 2000; o.step = 10; o.sens = 2;
    o.scale = NULL;
    return o;
}

/* R5's first state: no data is a dash and nothing else, so it can
 * never be read as a flat line at zero. */
static void test_g1_empty_is_a_dash(void) {
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(NULL, 0, NULL, NULL, &o, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    WT_EQ(gm_count(&g, "line"), 0);
    WT_EQ(gm_count(&g, "last"), 0);
    WT_ASSERT(!strcmp(gm_get(&g, "dash").tok, "--faint"));
}

/* R5's second state: warming is the line with no band drawn, which is
 * what tells it apart from a band that happens to be wide. */
static void test_g1_warming_draws_no_band(void) {
    double pts[6][2] = {{1000,1},{1010,2},{1020,3},{1030,4},{1040,5},{1050,6}};
    double band[6][4] = {{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0},{0,0,0,0}};
    int has[6] = {0,0,0,0,0,0};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 6, band, has, &o, &g);
    WT_EQ(gm_count(&g, "band"), 0);
    WT_EQ(gm_count(&g, "line"), 5);
    WT_EQ(gm_count(&g, "last"), 1);
    /* R7: with no band, the range is the only reference, so the min
     * and max dots are drawn. */
    WT_EQ(gm_count(&g, "max"), 1);
    WT_EQ(gm_count(&g, "min"), 1);
}

/* A single point is a point, not a line. */
static void test_g1_one_point(void) {
    double pts[1][2] = {{1500, 7}};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 1, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "line"), 0);
    WT_EQ(gm_count(&g, "dot"), 0);        /* the last-value mark is the point */
    WT_EQ(gm_count(&g, "last"), 1);
    WT_EQ(gm_count(&g, "max"), 1);
    WT_EQ(gm_count(&g, "min"), 0);        /* one point is both; drawn once */
    WT_ASSERT(near(gm_get(&g, "last").x, 50));
}

/* R6: four points draw dots, never a line. Five draw the line. */
static void test_g1_four_points_are_dots(void) {
    double pts[5][2] = {{1000,1},{1010,2},{1020,3},{1030,4},{1040,5}};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 4, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "line"), 0);
    WT_EQ(gm_count(&g, "dot"), 3);        /* the fourth is the last-value mark */
    WT_EQ(gm_count(&g, "last"), 1);
    gl_g1(pts, 5, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "line"), 4);
    WT_EQ(gm_count(&g, "dot"), 0);
}

/* R5's third state: a gap of more than 2.5 steps breaks the line and
 * is said as its own mark, so it cannot be read as a steep slope. */
static void test_g1_a_gap_breaks_the_line(void) {
    double pts[6][2] = {{1000,1},{1010,2},{1020,3},{1100,4},{1110,5},{1120,6}};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 6, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "gap"), 1);
    WT_EQ(gm_count(&g, "line"), 4);       /* five pairs, one of them the gap */
    gmark_t gp = gm_get(&g, "gap");
    WT_ASSERT(near(gp.x, 2.0));           /* t=1020 of 1000..2000 over 100 px */
    WT_ASSERT(near(gp.w, 8.0));           /* to t=1100 */
    /* Two steps is not a gap. */
    double tight[6][2] = {{1000,1},{1010,2},{1020,3},{1040,4},{1050,5},{1060,6}};
    gl_g1(tight, 6, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "gap"), 0);
    WT_EQ(gm_count(&g, "line"), 5);
}

/* In band: the last value's dot is plain ink, and the band is drawn. */
static void test_g1_in_band(void) {
    double pts[5][2] = {{1000,5},{1010,5},{1020,5},{1030,5},{1040,5}};
    double band[5][4] = {{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5}};
    int has[5] = {1,1,1,1,1};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 5, band, has, &o, &g);
    WT_EQ(gm_count(&g, "band"), 5);
    WT_ASSERT(!strcmp(gm_get(&g, "band").tok, "--data"));
    WT_ASSERT(!strcmp(gm_get(&g, "last").tok, "--ink"));
    /* R7: with a band to compare to, no min and max dots. */
    WT_EQ(gm_count(&g, "max"), 0);
    WT_EQ(gm_count(&g, "min"), 0);
}

/* Out of band: the last value's dot takes the heat ramp, by how far
 * out it is. Seen red with the band widened to hold the value. */
static void test_g1_out_of_band(void) {
    double pts[5][2] = {{1000,5},{1010,5},{1020,5},{1030,5},{1040,20}};
    double band[5][4] = {{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5}};
    int has[5] = {1,1,1,1,1};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 5, band, has, &o, &g);
    WT_ASSERT(!strcmp(gm_get(&g, "last").tok, "--heat-3"));   /* z = 30, far out */
    /* The same value inside a wider band is plain ink. */
    for (int i = 0; i < 5; i++) {
        band[i][0] = -100; band[i][1] = 100; band[i][3] = 50;
    }
    gl_g1(pts, 5, band, has, &o, &g);
    WT_ASSERT(!strcmp(gm_get(&g, "last").tok, "--ink"));
    /* A value just outside takes the cool end of the ramp, not the hot
     * one: the ramp says how far out, not that it is out. */
    for (int i = 0; i < 5; i++) {
        band[i][0] = 4; band[i][1] = 6; band[i][2] = 5; band[i][3] = 0.5;
    }
    pts[4][1] = 6.1;                                  /* z = 2.2, sens = 2 */
    gl_g1(pts, 5, band, has, &o, &g);
    WT_ASSERT(!strcmp(gm_get(&g, "last").tok, "--heat-1"));
}

/* Owner ruling 1 of 2026-10-26: G1's line keeps the TUI's level
 * grading, which R1's one ink otherwise forbids. Seen red with
 * lineToken() returning "--tui-normal" for every level. */
static void test_g1_line_grades_like_the_tui(void) {
    double pts[5][2] = {{1000,1},{1010,45},{1020,60},{1030,90},{1040,100}};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 5, NULL, NULL, &o, &g);
    const char *want[4] = { "--heat-1", "--heat-2", "--heat-3", "--heat-3" };
    int at = 0;
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g.m[i].kind, "line")) {
            WT_ASSERT(at < 4 && !strcmp(g.m[i].tok, want[at]));
            at++;
        }
    WT_EQ(at, 4);
    WT_ASSERT(!strcmp(gl_line_token(gl_level(0, 100)), "--tui-dim"));
    WT_ASSERT(!strcmp(gl_line_token(gl_level(10, 100)), "--tui-normal"));
}

/* R10. With every colour token the same grey, the mark list still
 * tells the band, the line, the last value and a severity apart, by
 * kind and by position — so this test reads the list with no colour in
 * it at all, and flattening every token leaves it green while it
 * reddens the out-of-band test. Seen red with the last value pushed as
 * a "dot" like any other point. */
static void test_g1_reads_in_greyscale(void) {
    double pts[5][2] = {{1000,5},{1010,5},{1020,5},{1030,5},{1040,20}};
    double band[5][4] = {{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5},{4,6,5,0.5}};
    int has[5] = {1,1,1,1,1};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 5, band, has, &o, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "band") > 0, 1);
    WT_EQ(gm_count(&g, "line") > 0, 1);
    WT_EQ(gm_count(&g, "last"), 1);
    /* The severity the heat token would have carried is also a
     * position: the last value sits above its own band. */
    gmark_t last = gm_get(&g, "last"), b = gm_last(&g, "band");
    WT_ASSERT(last.y < b.y);
    /* Every kind in the list is one of the glyph's own. */
    for (int i = 0; i < g.n; i++) {
        const char *k = g.m[i].kind;
        WT_ASSERT(!strcmp(k, "band") || !strcmp(k, "line") || !strcmp(k, "gap") ||
                  !strcmp(k, "dot") || !strcmp(k, "max") || !strcmp(k, "min") ||
                  !strcmp(k, "last") || !strcmp(k, "dash"));
    }
}

/* R11: a refresh grows the range and never shrinks it. */
static void test_g1_scale_never_shrinks(void) {
    double big[3][2] = {{1000,0},{1010,100},{1020,50}};
    double small[3][2] = {{1030,1},{1040,2},{1050,3}};
    double lo, hi, keep[2];
    gl_scale(big, 3, NULL, NULL, NULL, &lo, &hi);
    WT_ASSERT(near(hi, 100));
    keep[0] = lo; keep[1] = hi;
    gl_scale(small, 3, NULL, NULL, keep, &lo, &hi);
    WT_ASSERT(near(hi, 100));
    /* It does grow. */
    double bigger[1][2] = {{1060, 400}};
    keep[0] = lo; keep[1] = hi;
    gl_scale(bigger, 1, NULL, NULL, keep, &lo, &hi);
    WT_ASSERT(near(hi, 400));
}

/* R4. Six minutes of data in a 24 h window shrinks the window to the
 * data and says so, in those words. Seen red with WINDOW_SHARE at 0. */
static void test_the_window_rule(void) {
    double pts[2][2] = {{86040, 1}, {86400, 2}};     /* 6 min, at the end */
    gwin_t w = gl_win(pts, 2, 0, 86400);
    WT_ASSERT(w.shrunk);
    WT_ASSERT(near(w.from, 86040));
    WT_ASSERT(near(w.to, 86400));
    WT_ASSERT(!strcmp(w.text, "6 min of 24 h"));
    /* A tenth of the window or more is drawn as asked. */
    double full[2][2] = {{0, 1}, {8640, 2}};
    gwin_t k = gl_win(full, 2, 0, 86400);
    WT_ASSERT(!k.shrunk);
    WT_ASSERT(near(k.from, 0) && near(k.to, 86400));
    WT_ASSERT(!k.text[0]);
    /* One point has no span to shrink to. */
    WT_ASSERT(!gl_win(pts, 1, 0, 86400).shrunk);
}

/* R9. The caption's grammar, in its order, with n always present. */
static void test_the_caption_grammar(void) {
    char out[160];
    gcap_t c;
    memset(&c, 0, sizeof(c));
    c.source = "ap.rssi 02:de:00:00:00:a1";
    c.window = "1 h";
    c.tier = "fine";
    c.scale = "-95 to -20 dBm";
    c.n = 360;
    gl_caption(&c, out, sizeof(out));
    WT_ASSERT(!strcmp(out, "ap.rssi 02:de:00:00:00:a1, 1 h, fine, "
                           "-95 to -20 dBm, n=360"));
    /* The three states ride in the same line, each its own word. */
    c.state = "warming";
    gl_caption(&c, out, sizeof(out));
    WT_HAS(out, ", n=360, warming");
    c.state = "no data";
    c.n = 0;
    gl_caption(&c, out, sizeof(out));
    WT_HAS(out, ", n=0, no data");
    c.state = "6 min of 24 h";
    gl_caption(&c, out, sizeof(out));
    WT_HAS(out, ", 6 min of 24 h");
    /* A panel with nothing but a count still carries n. */
    memset(&c, 0, sizeof(c));
    c.n = 5;
    gl_caption(&c, out, sizeof(out));
    WT_ASSERT(!strcmp(out, "n=5"));
}

/* ── G5 ─────────────────────────────────────────────────────────── */

static void test_g5_cells_from_the_servers_hex(void) {
    /* 144 cells, the first digit's high bit the oldest cell. */
    const char *hex = "800000000000000000000000000000000001";
    int cells[144], n = 0;
    /* the port of cellsFromHex() */
    for (int i = 0; i < 144; i++) {
        int d = 0;
        char ch = hex[i >> 2];
        d = ch <= '9' ? ch - '0' : ch - 'a' + 10;
        cells[n++] = (d & (8 >> (i & 3))) ? 1 : 0;
    }
    WT_EQ(n, 144);
    WT_EQ(cells[0], 1);
    WT_EQ(cells[1], 0);
    WT_EQ(cells[143], 1);
    gmarks_t g;
    gl_g5(cells, 144, 144, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "cell"), 2);
    WT_ASSERT(near(gm_get(&g, "cell").x, 0));
}

static void test_g5_states(void) {
    gmarks_t g;
    /* Empty: a dash, never an empty box. */
    gl_g5(NULL, 0, 144, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "dash"), 1);
    WT_EQ(gm_count(&g, "cell"), 0);
    /* Warming: cells drawn, nothing else; the word is the caption's. */
    int warm[4] = {0, 1, 1, 0};
    gl_g5(warm, 4, 100, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "cell"), 2);
    WT_EQ(gm_count(&g, "gap"), 0);
    WT_EQ(gm_count(&g, "first"), 0);
    /* One cell. */
    int one[1] = {1};
    gl_g5(one, 1, 100, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "cell"), 1);
    WT_ASSERT(near(gm_get(&g, "cell").w, 100));
    /* A gap is its own kind, so it reads as unobserved and not absent. */
    int gapped[4] = {1, -1, -1, 1};
    gl_g5(gapped, 4, 100, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "cell"), 2);
    WT_EQ(gm_count(&g, "gap"), 2);
    WT_ASSERT(!strcmp(gm_get(&g, "gap").tok, "--faint"));
    /* The first-seen mark, when it falls inside the window (F15). */
    int four[4] = {0, 1, 1, 1};
    gl_g5(four, 4, 100, 12, 1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "first"), 1);
    WT_ASSERT(near(gm_get(&g, "first").x, 25));
    WT_ASSERT(!strcmp(gm_get(&g, "first").tok, "--signal"));
    gl_g5(four, 4, 100, 12, -1, NULL, 0, &g);
    WT_EQ(gm_count(&g, "first"), 0);
}

/* F10: the ruler is one object per table, with a tick at each local
 * midnight and one at now. Seen red with the offset ignored. */
static void test_g5_ruler(void) {
    gmarks_t g;
    /* A 24 h window ending at a UTC midnight: one midnight tick, at
     * the right edge, and the now mark. */
    gl_g5_ruler(144, 12, 0, 86400, 0, &g);
    WT_EQ(gm_count(&g, "tick"), 2);       /* 00:00 at both ends */
    WT_EQ(gm_count(&g, "now"), 1);
    WT_ASSERT(near(gm_get(&g, "tick").x, 0));
    /* Shifted by a zone, the midnight moves with it. */
    gl_g5_ruler(144, 12, 0, 86400, 3600, &g);
    WT_EQ(gm_count(&g, "tick"), 1);
    WT_ASSERT(near(gm_get(&g, "tick").x, 144.0 * 82800 / 86400));
    WT_ASSERT(!strcmp(gm_get(&g, "now").tok, "--signal"));
    /* An empty window draws nothing at all. */
    gl_g5_ruler(144, 12, 100, 100, 0, &g);
    WT_EQ(g.n, 0);
}

/* An anomaly episode underlines the cells it covers, clipped to the
 * strip, and leaves the presence reading above it alone. Seen red with
 * the underline left out of the port. */
static void test_g5_anomaly_underline(void) {
    int cells[4] = {1, 1, 1, 1};
    static const int ep[2][2] = { {1, 2}, {3, 9} };
    gmarks_t g;
    gl_g5(cells, 4, 100, 12, -1, ep, 2, &g);
    WT_EQ(gm_count(&g, "cell"), 4);
    WT_EQ(gm_count(&g, "anom"), 2);
    gmark_t a = gm_get(&g, "anom");
    WT_ASSERT(near(a.x, 25));
    WT_ASSERT(near(a.w, 50));
    WT_ASSERT(near(a.y, 11));
    WT_ASSERT(near(a.h, 1));
    WT_ASSERT(!strcmp(a.tok, "--heat-2"));
    /* Clipped to the last cell, never past the strip. */
    gmark_t b = gm_last(&g, "anom");
    WT_ASSERT(near(b.x, 75));
    WT_ASSERT(near(b.w, 25));
    /* An episode that ends before it starts draws nothing. */
    static const int past[1][2] = { {9, 4} };
    gl_g5(cells, 4, 100, 12, -1, past, 1, &g);
    WT_EQ(gm_count(&g, "anom"), 0);
}

/* R10 for G5: grey everywhere still tells present from the first-seen
 * mark and from a gap, because each is its own kind and place. */
static void test_g5_reads_in_greyscale(void) {
    int cells[4] = {1, -1, 1, 1};
    gmarks_t g;
    gl_g5(cells, 4, 100, 12, 2, NULL, 0, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "cell"), 3);
    WT_EQ(gm_count(&g, "gap"), 1);
    WT_EQ(gm_count(&g, "first"), 1);
    WT_ASSERT(near(gm_get(&g, "first").x, 50));
}

/* ── the sun's phase on G5 (web/ui/sun.js, ruling 2026-11-11) ───── */

/* Unix seconds of a UTC civil time, by the days-from-civil count of the
 * proleptic Gregorian calendar (era of 400 years, year from March), not
 * by the port's year walk: the expectations below must not lean on the
 * code they test. */
static double utc(int y, int m, int d, int hh, int mm) {
    y -= m <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    int yoe = y - era * 400;
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return ((double)era * 146097 + doe - 719468) * 86400 + hh * 3600 + mm * 60;
}

/* The first second in [t0, t1) at which the elevation crosses `level`,
 * upward (up 1) or downward (up 0); -1 when it never does. */
static double sun_cross(double lat, double lon, double t0, double t1, double level, int up) {
    double a = sun_elev(t0, lat, lon) - level;
    for (double t = t0 + 1; t <= t1; t += 1) {
        double b = sun_elev(t, lat, lon) - level;
        if (up ? (a < 0 && b >= 0) : (a >= 0 && b < 0)) return t;
        a = b;
    }
    return -1;
}
/* The second of the highest (hi 1) or lowest elevation in [t0, t1). */
static double sun_extreme(double lat, double lon, double t0, double t1, int hi, double *e) {
    double bt = t0, be = sun_elev(t0, lat, lon);
    for (double t = t0 + 10; t < t1; t += 10) {
        double v = sun_elev(t, lat, lon);
        if (hi ? v > be : v < be) { be = v; bt = t; }
    }
    if (e) *e = be;
    return bt;
}
static int within(double got, double want, double tol) { return got >= 0 && fabs(got - want) <= tol; }

/* The almanac. Every time below is the U.S. Naval Observatory's
 * "Complete Sun and Moon Data for One Day" (aa.usno.navy.mil, its
 * api/rstt/oneday with tz=0), read on 2026-11-11, in UTC to the minute.
 * Its rise and set are the upper limb on the horizon with 34' of
 * refraction, the centre 0.8333 degrees below it; its civil twilight is
 * the centre 6 degrees below, which is NIGHT_BELOW itself. hhmm, and
 * the events in the order they fall in the UTC day. */
typedef struct {
    const char *name;
    double lat, lon;
    int y, m, d;
    int civil_begin, rise, transit, set, civil_end;
} almanac_t;
static const almanac_t ALMANAC[] = {
    /* Greenwich's latitude on the June solstice */
    { "London 51.48N 0.00E",        51.48,    0.00, 2026,  6, 21,  255,  343, 1202, 2021, 2109 },
    /* a negative longitude, in November */
    { "New York 40.71N 74.01W",     40.71,  -74.01, 2026, 11, 11, 1109, 1138, 1640, 2142, 2211 },
    /* the southern hemisphere in June: the short day, the sun to the north */
    { "Sydney 33.87S 151.21E",     -33.87,  151.21, 2026,  6, 21, 2032, 2100,  157,  654,  722 },
    /* the equator on the March equinox */
    { "equator 0N 0E",               0.00,    0.00, 2026,  3, 20,  544,  604, 1207, 1811, 1831 },
    /* a tenth of a degree short of the antimeridian (Vanua Levu, Fiji) */
    { "Fiji 16.80S 179.90E",       -16.80,  179.90, 2026,  9, 23, 1727, 1749, 2353,  556,  618 },
};
#define ALMANAC_TOL_S 180.0

/* Sunrise, sunset, both civil twilights and the transit of five places
 * against the almanac, each within three minutes. Seen red with the
 * longitude's sign turned in the port's hour angle (15 assertions:
 * the three places off the prime meridian), with the equation of time
 * left out (15: where it is over three minutes that day), and with the
 * declination's first harmonic's sign turned. */
static void test_sun_against_the_almanac(void) {
    for (size_t i = 0; i < sizeof(ALMANAC) / sizeof(ALMANAC[0]); i++) {
        const almanac_t *a = &ALMANAC[i];
        double t0 = utc(a->y, a->m, a->d, 0, 0), t1 = t0 + 86400;
#define AT(hhmm) (t0 + ((hhmm) / 100) * 3600 + ((hhmm) % 100) * 60)
        fprintf(stderr, "  %s\n", a->name);
        WT_ASSERT(within(sun_cross(a->lat, a->lon, t0, t1, -0.8333, 1), AT(a->rise), ALMANAC_TOL_S));
        WT_ASSERT(within(sun_cross(a->lat, a->lon, t0, t1, -0.8333, 0), AT(a->set), ALMANAC_TOL_S));
        WT_ASSERT(within(sun_cross(a->lat, a->lon, t0, t1, SUN_NIGHT_BELOW, 1), AT(a->civil_begin), ALMANAC_TOL_S));
        WT_ASSERT(within(sun_cross(a->lat, a->lon, t0, t1, SUN_NIGHT_BELOW, 0), AT(a->civil_end), ALMANAC_TOL_S));
        WT_ASSERT(within(sun_extreme(a->lat, a->lon, t0, t1, 1, NULL), AT(a->transit), ALMANAC_TOL_S));
#undef AT
    }
}

/* Noon's elevation is 90 degrees less the latitude plus the
 * declination, and the declination is the obliquity, 23.44 degrees, at
 * a solstice and nothing at an equinox. Seen red with the port's
 * latitude left out of its sine (the equator's line here, and the
 * almanac's), and with the declination's sign turned (the same). */
static void test_sun_noon_elevation(void) {
    double e;
    /* The equator at the equinox: overhead. The equinox itself was at
     * 14:46 UTC, so at the 12:07 transit the sun was a few hundredths
     * of a degree south. */
    sun_extreme(0, 0, utc(2026, 3, 20, 0, 0), utc(2026, 3, 21, 0, 0), 1, &e);
    WT_ASSERT(e > 89.0 && e <= 90.0);
    /* London at the June solstice: 90 - 51.48 + 23.44 = 61.96. */
    sun_extreme(51.48, 0, utc(2026, 6, 21, 0, 0), utc(2026, 6, 22, 0, 0), 1, &e);
    WT_ASSERT(fabs(e - 61.96) < 0.3);
    /* Sydney the same day, the sun to the north: 90 - 33.87 - 23.44 =
     * 32.69, and its day under ten hours (the almanac's 21:00 to 06:54). */
    sun_extreme(-33.87, 151.21, utc(2026, 6, 21, 0, 0), utc(2026, 6, 22, 0, 0), 1, &e);
    WT_ASSERT(fabs(e - 32.69) < 0.3);
    /* The antimeridian is one meridian: 180 east is 180 west. */
    for (double t = utc(2026, 9, 23, 0, 0); t < utc(2026, 9, 24, 0, 0); t += 3600)
        WT_ASSERT(fabs(sun_elev(t, -16.8, 180) - sun_elev(t, -16.8, -180)) < 1e-9);
}

static void count_phases(const int *ph, int n, int c[4]) {
    c[0] = c[1] = c[2] = c[3] = 0;
    for (int i = 0; i < n; i++) c[ph[i]]++;
}

/* Where the sun neither rises nor sets, and where it does not get all
 * the way: no case of its own in the code, so each is asserted. Seen
 * red with the port's rising test turned (>= made <: Reykjavik's and
 * Tromso's orders), and with NIGHT_BELOW made -12 in the port (the
 * polar night's 144 became 133 and one run four). */
static void test_sun_polar_and_twilight(void) {
    int ph[144], c[4], r[144][2];
    /* Longyearbyen, 78.22N 15.63E. December solstice: the sun's highest
     * is 90 - 78.22 - 23.44 = -11.66, under civil twilight all day. */
    sunpos_t lyr = { 78.22, 15.63 };
    double e;
    sun_extreme(lyr.lat, lyr.lon, utc(2026, 12, 21, 0, 0), utc(2026, 12, 22, 0, 0), 1, &e);
    WT_ASSERT(fabs(e - -11.66) < 0.3);
    WT_EQ(sun_phases(utc(2026, 12, 21, 0, 0), 600, 144, &lyr, ph), 1);
    count_phases(ph, 144, c);
    WT_EQ(c[0], 144);
    WT_EQ(sun_runs(ph, 144, r), 1);
    /* June solstice: its lowest is 78.22 + 23.44 - 90 = 11.66, day all
     * night. */
    sun_extreme(lyr.lat, lyr.lon, utc(2026, 6, 21, 0, 0), utc(2026, 6, 22, 0, 0), 0, &e);
    WT_ASSERT(fabs(e - 11.66) < 0.3);
    WT_EQ(sun_phases(utc(2026, 6, 21, 0, 0), 600, 144, &lyr, ph), 1);
    count_phases(ph, 144, c);
    WT_EQ(c[2], 144);
    /* Reykjavik, 64.15N 21.94W, June solstice: the lowest is 64.15 +
     * 23.44 - 90 = -2.41, twilight all night and no night at all. The
     * strip from 00:00 UTC is sunset, sunrise, day, sunset, and sunset
     * turns to sunrise at the sun's lowest: twelve hours from a transit
     * that is London's almanac 12:02 moved 21.94 degrees west at four
     * minutes a degree, so 01:29.8, in cell 8 (01:20 to 01:30) with the
     * turn at the edge of cell 9. */
    sunpos_t rey = { 64.15, -21.94 };
    WT_EQ(sun_phases(utc(2026, 6, 21, 0, 0), 600, 144, &rey, ph), 1);
    count_phases(ph, 144, c);
    WT_EQ(c[0], 0);
    WT_EQ(sun_runs(ph, 144, r), 4);
    WT_EQ(r[0][0], 3); WT_EQ(r[1][0], 1); WT_EQ(r[2][0], 2); WT_EQ(r[3][0], 3);
    WT_ASSERT(abs(r[1][1] - 9) <= 1);
    /* Tromso, 69.65N 18.96E, December solstice: the highest is 90 -
     * 69.65 - 23.44 = -3.09, never day; night, sunrise, sunset, night,
     * the two twilights the same length to a cell. */
    sunpos_t tos = { 69.65, 18.96 };
    WT_EQ(sun_phases(utc(2026, 12, 21, 0, 0), 600, 144, &tos, ph), 1);
    count_phases(ph, 144, c);
    WT_EQ(c[2], 0);
    WT_ASSERT(c[0] > 0 && c[1] > 0 && abs(c[1] - c[3]) <= 1);
    WT_EQ(sun_runs(ph, 144, r), 4);
    WT_EQ(r[0][0], 0); WT_EQ(r[1][0], 1); WT_EQ(r[2][0], 3); WT_EQ(r[3][0], 0);
}

/* A strip present all 24 h at London on 2026-06-21: the four tokens in
 * the order of the day, each count within a cell of the almanac. Night
 * is the almanac's civil twilights: 00:00 to 02:55 and 21:09 to 24:00,
 * 346 min. Day is the sun over +6 degrees, from the spherical triangle
 * with the solstice's declination: cos H = (sin 6 - sin lat sin dec) /
 * (cos lat cos dec), 2H of the day's 360 degrees. Sunrise and sunset
 * split what is left. The first-seen cell and the anomaly underline
 * are the marks they were. Seen red with DAY_ABOVE made 0 in the port
 * (the day and twilight counts) and with NIGHT_BELOW made -12 (the
 * night count). The tolerance is a cell, so this does not tell the
 * cell's midpoint from its start, and does not claim to. */
static void test_g5_sun_phases_at_london(void) {
    int cells[144];
    for (int i = 0; i < 144; i++) cells[i] = 1;
    static const int ep[1][2] = { {30, 40} };
    sunpos_t lon = { 51.48, 0.0 };
    double from = utc(2026, 6, 21, 0, 0);
    gmarks_t g, plain;
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, &lon, &g);
    gl_g5(cells, 144, 144, 12, 5, ep, 1, &plain);
    WT_EQ(g.n, 146);
    WT_EQ(g.n, plain.n);
    int c[4] = { 0, 0, 0, 0 }, order[8], no = 0;
    for (int i = 0; i < 144; i++) {
        WT_ASSERT(!strcmp(g.m[i].kind, "cell"));
        int p = -1;
        for (int k = 0; k < 4; k++) if (!strcmp(g.m[i].tok, SUN_TOKENS[k])) p = k;
        if (p < 0) { WT_ASSERT(p >= 0); continue; }
        c[p]++;
        if (no < 8 && (!no || order[no - 1] != p)) order[no++] = p;
        /* Only the token moved: the geometry is the plain strip's. */
        WT_ASSERT(near(g.m[i].x, plain.m[i].x) && near(g.m[i].w, plain.m[i].w) &&
                  near(g.m[i].h, plain.m[i].h));
    }
    WT_EQ(no, 5);
    WT_EQ(order[0], 0); WT_EQ(order[1], 1); WT_EQ(order[2], 2); WT_EQ(order[3], 3); WT_EQ(order[4], 0);
    double night = (2 * 60 + 55 + 24 * 60 - (21 * 60 + 9)) / 10.0;            /* 34.6 cells */
    double rad = SUN_PI / 180, dec = 23.44 * rad, lat = 51.48 * rad;
    double H = acos((sin(6 * rad) - sin(lat) * sin(dec)) / (cos(lat) * cos(dec))) / rad;
    double day = 2 * H / 360 * 144;                                           /* 89.0 cells */
    double twi = (144 - night - day) / 2;                                     /* 10.2 cells */
    WT_ASSERT(fabs(day - 88.96) < 0.05);
    WT_ASSERT(fabs(c[0] - night) <= 1);
    WT_ASSERT(fabs(c[2] - day) <= 1);
    WT_ASSERT(fabs(c[1] - twi) <= 1);
    WT_ASSERT(fabs(c[3] - twi) <= 1);
    WT_EQ(c[0] + c[1] + c[2] + c[3], 144);
    /* F15's diamond and the anomaly underline: byte for byte the plain
     * strip's, after the cells. */
    for (int i = 144; i < 146; i++) {
        WT_ASSERT(!strcmp(g.m[i].kind, plain.m[i].kind) && !strcmp(g.m[i].tok, plain.m[i].tok));
        WT_ASSERT(near(g.m[i].x, plain.m[i].x) && near(g.m[i].y, plain.m[i].y) &&
                  near(g.m[i].w, plain.m[i].w) && near(g.m[i].h, plain.m[i].h));
    }
    WT_ASSERT(!strcmp(g.m[144].kind, "first") && !strcmp(g.m[144].tok, "--signal"));
    WT_ASSERT(!strcmp(g.m[145].kind, "anom") && !strcmp(g.m[145].tok, "--heat-2"));
    /* A gap stays a gap and an absent cell stays nothing, whatever the
     * phase. */
    cells[20] = -1;
    cells[21] = 0;
    gl_g5_sun(cells, 144, 144, 12, -1, NULL, 0, from, 600, &lon, &g);
    WT_EQ(gm_count(&g, "cell"), 142);
    WT_EQ(gm_count(&g, "gap"), 1);
    WT_ASSERT(!strcmp(gm_get(&g, "gap").tok, "--faint"));
}

static int same_marks(const gmarks_t *a, const gmarks_t *b) {
    if (a->n != b->n) return 0;
    for (int i = 0; i < a->n; i++)
        if (strcmp(a->m[i].kind, b->m[i].kind) || strcmp(a->m[i].tok, b->m[i].tok) ||
            !near(a->m[i].x, b->m[i].x) || !near(a->m[i].y, b->m[i].y) ||
            !near(a->m[i].w, b->m[i].w) || !near(a->m[i].h, b->m[i].h)) return 0;
    return 1;
}
static int count_tok(const gmarks_t *g, const char *kind, const char *tok) {
    int n = 0;
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind) && !strcmp(g->m[i].tok, tok)) n++;
    return n;
}

/* No position, no phase: the strip is the one it was before the ruling,
 * mark for mark, every present cell --tui-normal. The same for a
 * position that is not one, and for a window that is not one. Seen red
 * with the port's `!pos ||` guard taken out and a NULL position read
 * as 0N 0E, which colours anyway (96 --tui-normal cells became 0, and
 * the sameness after it), with okPos's latitude bound made 900 (the
 * 91 degree position), and with the `from < 0` guard dropped (the
 * negative start). */
static void test_g5_no_position_is_one_ink(void) {
    int cells[144];
    for (int i = 0; i < 144; i++) cells[i] = (i % 3) ? 1 : 0;
    static const int ep[1][2] = { {30, 40} };
    double from = utc(2026, 6, 21, 0, 0);
    gmarks_t g, plain;
    gl_g5(cells, 144, 144, 12, 5, ep, 1, &plain);
    WT_EQ(count_tok(&plain, "cell", "--tui-normal"), 96);
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, NULL, &g);
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 96);
    WT_EQ(gm_count(&g, "cell"), 96);
    WT_ASSERT(same_marks(&g, &plain));
    sunpos_t bad_lat = { 91, 0 }, bad_lon = { 10, 180.5 }, nan_lat = { NAN, 0 }, ok = { 51.48, 0 };
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, &bad_lat, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, &bad_lon, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, &nan_lat, &g);
    WT_ASSERT(same_marks(&g, &plain));
    /* A position and no window (a strip whose answer had none). */
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, NAN, 600, &ok, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, -86400, 600, &ok, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 0, &ok, &g);
    WT_ASSERT(same_marks(&g, &plain));
    /* And the control: the same call with all three is not the plain
     * strip, so the sameness above is the guards' doing. */
    gl_g5_sun(cells, 144, 144, 12, 5, ep, 1, from, 600, &ok, &g);
    WT_ASSERT(!same_marks(&g, &plain));
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 0);
}

/* A cell of an hour is one phase; a longer one spans a sunrise too
 * often to be, and keeps the one ink (History's long ranges). Seen red
 * with MAX_CELL_S made 7200 in the port. */
static void test_g5_long_cells_are_one_ink(void) {
    int cells[24];
    for (int i = 0; i < 24; i++) cells[i] = 1;
    sunpos_t lon = { 51.48, 0.0 };
    double from = utc(2026, 6, 21, 0, 0);
    gmarks_t g;
    gl_g5_sun(cells, 24, 144, 12, -1, NULL, 0, from, 3600, &lon, &g);
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 0);
    WT_ASSERT(count_tok(&g, "cell", "--sun-night") > 0 && count_tok(&g, "cell", "--sun-day") > 0);
    gl_g5_sun(cells, 24, 144, 12, -1, NULL, 0, from, 3601, &lon, &g);
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 24);
    gl_g5_sun(cells, 24, 144, 12, -1, NULL, 0, from, 7200, &lon, &g);
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 24);
    /* The BLE drawer's quarter hours are coloured. */
    int q[96];
    for (int i = 0; i < 96; i++) q[i] = 1;
    gl_g5_sun(q, 96, 192, 18, -1, NULL, 0, from, 900, &lon, &g);
    WT_EQ(count_tok(&g, "cell", "--tui-normal"), 0);
    WT_ASSERT(abs(count_tok(&g, "cell", "--sun-night") - 23) <= 1);   /* 346 min of 15 */
}

/* The ruler's band: one "sun" mark a run, under the ticks, each phase
 * its own height as well as its token (R10). With no position, or
 * cells over an hour, the ruler is the one it was. Seen red with the
 * a stray "sun" mark pushed after now in the port (the counts), with
 * SUN_H made all 2 (the heights and the greyscale reading), with a
 * NULL position read as 0N 0E (the no-position sameness) and with
 * MAX_CELL_S made 7200 (the two-hour cells' sameness). */
static void test_g5_ruler_sun_band(void) {
    sunpos_t lon = { 51.48, 0.0 };
    double from = utc(2026, 6, 21, 0, 0), to = from + 86400;
    gmarks_t g, plain;
    gl_g5_ruler(144, 6, from, to, 0, &plain);
    WT_EQ(plain.n, 3);
    gl_g5_ruler_sun(144, 6, from, to, 0, NAN, 144, &lon, &g);
    WT_EQ(gm_count(&g, "sun"), 5);
    WT_EQ(gm_count(&g, "tick"), 2);
    WT_EQ(gm_count(&g, "now"), 1);
    static const char *const want[5] = { "--sun-night", "--sun-rise", "--sun-day", "--sun-set", "--sun-night" };
    static const double hh[5] = { 1, 2, 3, 2, 1 };
    double x = 0;
    for (int i = 0; i < 5; i++) {
        WT_ASSERT(!strcmp(g.m[i].kind, "sun") && !strcmp(g.m[i].tok, want[i]));
        WT_ASSERT(near(g.m[i].h, hh[i]) && near(g.m[i].y, 6 - hh[i]));
        WT_ASSERT(near(g.m[i].x, x));          /* the runs abut, left to right */
        x += g.m[i].w;
    }
    WT_ASSERT(near(x, 144));
    /* The ticks and now are the marks they were, after the band, and
     * taller than any of it. */
    for (int i = 0; i < 3; i++) {
        WT_ASSERT(!strcmp(g.m[5 + i].kind, plain.m[i].kind) && !strcmp(g.m[5 + i].tok, plain.m[i].tok));
        WT_ASSERT(near(g.m[5 + i].x, plain.m[i].x) && near(g.m[5 + i].h, 6));
    }
    /* R10: in one grey, night, twilight and day are three heights, and
     * sunrise is the twilight before the day. */
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_ASSERT(g.m[0].h < g.m[1].h && g.m[1].h < g.m[2].h && g.m[3].h < g.m[2].h);
    WT_ASSERT(g.m[1].x < g.m[2].x && g.m[2].x < g.m[3].x);
    /* No position, an unusable one, or cells over an hour: the plain
     * ruler, mark for mark. */
    gl_g5_ruler_sun(144, 6, from, to, 0, NAN, 144, NULL, &g);
    WT_ASSERT(same_marks(&g, &plain));
    sunpos_t bad = { -95, 0 };
    gl_g5_ruler_sun(144, 6, from, to, 0, NAN, 144, &bad, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_ruler_sun(144, 6, from, to, 0, NAN, 12, &lon, &g);
    WT_ASSERT(same_marks(&g, &plain));
    gl_g5_ruler_sun(144, 6, from, to, 0, NAN, 0, &lon, &g);
    WT_ASSERT(same_marks(&g, &plain));
    /* now, when the page gives it: where it falls, and not at all
     * outside the window (History's past ranges). */
    gl_g5_ruler_sun(144, 6, from, to, 0, from + 43200, 0, NULL, &g);
    WT_ASSERT(near(gm_get(&g, "now").x, 72));
    gl_g5_ruler_sun(144, 6, from, to, 0, to, 0, NULL, &g);
    WT_ASSERT(near(gm_get(&g, "now").x, 143));
    gl_g5_ruler_sun(144, 6, from, to, 0, to + 1, 0, NULL, &g);
    WT_EQ(gm_count(&g, "now"), 0);
    WT_EQ(gm_count(&g, "tick"), 2);
}

/* The position is kept to a hundredth of a degree, so a moving sensor
 * does not ask for a new table at every fix. Seen red with the port's
 * rounding taken out. */
static void test_sun_position_is_rounded(void) {
    static int a[1440], b[1440];
    sunpos_t p = { 51.4849, 0.0049 }, q = { 51.48, 0.0 };
    /* One-second cells across the morning's twilight line (the
     * almanac's 02:55): half a hundredth of a degree moves the crossing
     * by a second or more, so the unrounded positions would disagree in
     * at least one cell. */
    double from = utc(2026, 6, 21, 2, 43);
    WT_EQ(sun_phases(from, 1, 1440, &p, a), 1);
    WT_EQ(sun_phases(from, 1, 1440, &q, b), 1);
    WT_EQ(a[0], 0);
    WT_EQ(a[1439], 1);
    WT_EQ(memcmp(a, b, sizeof(a)), 0);
}

/* ── the ruler's zone and the words (sun.js, ruling 2026-11-11) ──── */

#define SUN_OFF_MAX 64800.0
#define SUN_RUNS_MAX 8
static const char *const SUN_WORDS[4] = { "night", "sunrise", "day", "sunset" };

typedef struct { double off; int sensor; char word[80]; } sunzone_t;

static void sun_zone_word(double off, char *out, size_t sz) {
    int m = (int)floor(fabs(off) / 60 + 0.5), h = m / 60, mm = m % 60;
    if (!m) { snprintf(out, sz, "UTC"); return; }
    if (mm) snprintf(out, sz, "UTC%c%d:%s%d", off < 0 ? '-' : '+', h, mm < 10 ? "0" : "", mm);
    else snprintf(out, sz, "UTC%c%d", off < 0 ? '-' : '+', h);
}
/* NAN is the JS's null or undefined. */
static sunzone_t sun_zone(double sensor_off, double viewer_off) {
    sunzone_t z;
    char w[32];
    z.sensor = isfinite(sensor_off) && fabs(sensor_off) <= SUN_OFF_MAX;
    z.off = z.sensor ? sensor_off
          : isfinite(viewer_off) && fabs(viewer_off) <= SUN_OFF_MAX ? viewer_off : 0;
    sun_zone_word(z.off, w, sizeof(w));
    snprintf(z.word, sizeof(z.word), "%s%s",
             z.sensor ? "sensor time (slothweb's host), "
                      : "your clock (the server gave no sensor offset), ", w);
    return z;
}
static void sun_clock(double t, double off, char *out, size_t sz) {
    int m = (int)fmod(fmod(floor((t + off) / 60), 1440) + 1440, 1440), h = m / 60, mm = m % 60;
    snprintf(out, sz, "%s%d:%s%d", h < 10 ? "0" : "", h, mm < 10 ? "0" : "", mm);
}
/* pos NULL is the JS's null; pos_from its pos.from. */
static void sun_says(double from, double cell_s, int n, const sunpos_t *pos, const char *pos_from,
                     const sunzone_t *z, char *out, size_t sz) {
    static int ph[SUN_CELLS_MAX];
    int r[SUN_CELLS_MAX][2];
    out[0] = '\0';
    if (!isfinite(from) || !(cell_s > 0)) return;
    if (cell_s > SUN_MAX_CELL_S) { snprintf(out, sz, "cells over 1 h: presence in one ink"); return; }
    if (!pos) { snprintf(out, sz, "no sensor position: presence in one ink"); return; }
    int nr = sun_runs(sun_phases(from, cell_s, n, pos, ph) ? ph : NULL, n, r);
    if (!nr) return;
    size_t k = (size_t)snprintf(out, sz, "coloured by the sun at the sensor (%s), %s: ", pos_from, z->word);
    if (nr > SUN_RUNS_MAX) {
        if (k < sz) snprintf(out + k, sz - k, "%s, %s, %s, %s", SUN_WORDS[0], SUN_WORDS[1], SUN_WORDS[2], SUN_WORDS[3]);
        return;
    }
    for (int i = 0; i < nr && k < sz; i++) {
        char c[16] = "";
        if (r[i][1]) sun_clock(from + r[i][1] * cell_s, z->off, c, sizeof(c));
        k += (size_t)snprintf(out + k, sz - k, "%s%s%s%s", i ? ", " : "", SUN_WORDS[r[i][0]],
                              r[i][1] ? " " : "", c);
    }
}
static void sun_ruler_says(const sunzone_t *z, double span, char *out, size_t sz) {
    snprintf(out, sz, "midnight ticks in %s%s%s", z->word,
             span > 86400 ? ", the offset at the range's end throughout" : "",
             z->sensor ? "; every other time on the page is your clock" : "");
}

/* A sensor at UTC-7 looked at from a browser at UTC+1: the ruler's
 * ticks are the sensor's midnights, 07:00 UTC, not the viewer's 23:00.
 * Seen red with the port's zone() taking the viewer's offset first. */
static void test_sun_zone_is_the_sensors(void) {
    sunzone_t z = sun_zone(-7 * 3600, 3600);
    WT_EQ(z.sensor, 1);
    WT_ASSERT(near(z.off, -25200));
    WT_ASSERT(!strcmp(z.word, "sensor time (slothweb's host), UTC-7"));
    double from = utc(2026, 6, 21, 12, 0), to = from + 86400;
    gmarks_t g;
    gl_g5_ruler_sun(144, 6, from, to, z.off, NAN, 0, NULL, &g);
    WT_EQ(gm_count(&g, "tick"), 1);
    /* 2026-06-22 07:00 UTC is 19 h into the window; the viewer's
     * midnight, 23:00 UTC, would be 11 h in, at x 66. */
    WT_ASSERT(near(gm_get(&g, "tick").x, 144.0 * 19 / 24));
    WT_ASSERT(!near(gm_get(&g, "tick").x, 144.0 * 11 / 24));
    /* Three days: three sensor midnights, each 07:00 UTC. */
    gl_g5_ruler_sun(144, 6, from, from + 3 * 86400, z.off, NAN, 0, NULL, &g);
    WT_EQ(gm_count(&g, "tick"), 3);
    WT_ASSERT(near(gm_get(&g, "tick").x, 144.0 * 19 / 72));
}

/* No offset from the server (an older one, an error), or one that is
 * no offset: the viewer's clock, and the word says so. Seen red with
 * the port's fallback word made the sensor's, and with the 18 h bound
 * taken off the sensor's offset (the 1e6 line). */
static void test_sun_zone_fallback_and_names(void) {
    sunzone_t z = sun_zone(NAN, 3600);
    WT_EQ(z.sensor, 0);
    WT_ASSERT(near(z.off, 3600));
    WT_ASSERT(!strcmp(z.word, "your clock (the server gave no sensor offset), UTC+1"));
    z = sun_zone(1e6, -18000);
    WT_EQ(z.sensor, 0);
    WT_ASSERT(near(z.off, -18000));
    z = sun_zone(NAN, NAN);
    WT_EQ(z.sensor, 0);
    WT_ASSERT(near(z.off, 0));
    WT_ASSERT(!strcmp(z.word, "your clock (the server gave no sensor offset), UTC"));
    /* UTC itself is a sensor's zone like any other. */
    z = sun_zone(0, 3600);
    WT_EQ(z.sensor, 1);
    WT_ASSERT(!strcmp(z.word, "sensor time (slothweb's host), UTC"));
    char w[32];
    sun_zone_word(19800, w, sizeof(w));  WT_ASSERT(!strcmp(w, "UTC+5:30"));   /* India */
    sun_zone_word(-12600, w, sizeof(w)); WT_ASSERT(!strcmp(w, "UTC-3:30"));   /* Newfoundland */
    sun_zone_word(20700, w, sizeof(w));  WT_ASSERT(!strcmp(w, "UTC+5:45"));   /* Nepal */
    sun_zone_word(3600, w, sizeof(w));   WT_ASSERT(!strcmp(w, "UTC+1"));
    char c[16];
    sun_clock(0, -3600, c, sizeof(c));   WT_ASSERT(!strcmp(c, "23:00"));      /* before the epoch's day */
    sun_clock(utc(2026, 11, 11, 11, 10), -18000, c, sizeof(c));
    WT_ASSERT(!strcmp(c, "06:10"));
}

/* The words' sunrise and sunset are the sensor's clock. New York on
 * 2026-11-11 (UTC-5), a strip from its local midnight: the almanac's
 * civil twilight begins 11:09 UTC, 06:09 there, so the first sunrise
 * cell is the one whose midpoint is past it, 06:10; it ends 22:11 UTC,
 * 17:11, so night begins with the 17:10 cell. A viewer at UTC+1 with no
 * sensor offset reads the same cells as 12:10 and 23:10, and is told
 * whose clock that is. Seen red with the port's clock() ignoring its
 * offset, and with says() leaving the zone's word out. */
static void test_sun_words_in_sensor_time(void) {
    sunpos_t ny = { 40.71, -74.01 };
    double from = utc(2026, 11, 11, 5, 0);
    sunzone_t z = sun_zone(-18000, 3600);
    char s[400];
    sun_says(from, 600, 144, &ny, "gps fix", &z, s, sizeof(s));
    WT_HAS(s, "coloured by the sun at the sensor (gps fix), sensor time (slothweb's host), UTC-5: "
              "night, sunrise 06:10, day ");
    WT_HAS(s, ", night 17:10");
    WT_LACKS(s, "12:10");
    z = sun_zone(NAN, 3600);
    sun_says(from, 600, 144, &ny, "--location", &z, s, sizeof(s));
    WT_HAS(s, "coloured by the sun at the sensor (--location), your clock (the server gave no "
              "sensor offset), UTC+1: night, sunrise 12:10, day ");
    WT_HAS(s, ", night 23:10");
    /* The states with no times name no zone. */
    z = sun_zone(-18000, 3600);
    sun_says(from, 600, 144, NULL, "", &z, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "no sensor position: presence in one ink"));
    sun_says(from, 7200, 12, &ny, "gps fix", &z, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "cells over 1 h: presence in one ink"));
    sun_says(NAN, 600, 144, &ny, "gps fix", &z, s, sizeof(s));
    WT_ASSERT(!strcmp(s, ""));
    /* Six days of hour cells: more runs than fit, the four words. */
    sun_says(from, 3600, 144, &ny, "gps fix", &z, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "coloured by the sun at the sensor (gps fix), sensor time (slothweb's host), "
                         "UTC-5: night, sunrise, day, sunset"));
    /* The ruler's own words: the one stated exception to the page's
     * clock, and for a range over a day which offset the ticks are at. */
    sun_ruler_says(&z, 86400, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "midnight ticks in sensor time (slothweb's host), UTC-5; "
                         "every other time on the page is your clock"));
    sun_ruler_says(&z, 3 * 86400, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "midnight ticks in sensor time (slothweb's host), UTC-5, the offset at the "
                         "range's end throughout; every other time on the page is your clock"));
    z = sun_zone(NAN, 3600);
    sun_ruler_says(&z, 86400, s, sizeof(s));
    WT_ASSERT(!strcmp(s, "midnight ticks in your clock (the server gave no sensor offset), UTC+1"));
}

/* The zone as served and as the page uses it. The viewer's offset is
 * read in one place, sunZone()'s fallback argument, and nowhere else.
 * Seen red with drawRuler() given getTimezoneOffset for its ticks
 * again (its pin, and the count), with sun.js's zone() preferring the
 * viewer's offset, with clock() ignoring its offset, and with says()
 * giving clock() no offset; and with the Devices call passing no
 * offset. */
static void test_the_page_carries_the_sun_zone(void) {
    const char *p = page();
    WT_HAS(p, "  var OFF_MAX = 64800;\n"
              "  function zoneWord(off) {\n"
              "    var m = Math.round(Math.abs(off) / 60), h = Math.floor(m / 60), mm = m % 60;\n"
              "    if (!m) return \"UTC\";\n"
              "    return \"UTC\" + (off < 0 ? \"-\" : \"+\") + h + (mm ? \":\" + (mm < 10 ? \"0\" : \"\") + mm : \"\");\n"
              "  }\n");
    WT_HAS(p, "  function zone(sensorOff, viewerOff) {\n"
              "    var s = snum(sensorOff) && Math.abs(sensorOff) <= OFF_MAX;\n"
              "    var off = s ? sensorOff : snum(viewerOff) && Math.abs(viewerOff) <= OFF_MAX ? viewerOff : 0;\n"
              "    return { off: off, sensor: s,\n"
              "             word: (s ? \"sensor time (slothweb's host), \" : \"your clock (the server gave no sensor offset), \") +\n"
              "                   zoneWord(off) };\n"
              "  }\n");
    WT_HAS(p, "  function clock(t, off) {\n"
              "    var m = ((Math.floor((t + off) / 60) % 1440) + 1440) % 1440, h = Math.floor(m / 60), mm = m % 60;\n"
              "    return (h < 10 ? \"0\" : \"\") + h + \":\" + (mm < 10 ? \"0\" : \"\") + mm;\n"
              "  }\n");
    WT_HAS(p, "  var RUNS_MAX = 8;\n"
              "  function says(from, cellS, n, pos, z) {\n"
              "    if (!snum(from) || !(cellS > 0)) return \"\";\n"
              "    if (cellS > MAX_CELL_S) return \"cells over 1 h: presence in one ink\";\n"
              "    if (!pos) return \"no sensor position: presence in one ink\";\n"
              "    var r = runs(phases(from, cellS, n, pos));\n"
              "    if (!r.length) return \"\";\n"
              "    var s = \"coloured by the sun at the sensor (\" + pos.from + \"), \" + z.word + \": \";\n"
              "    if (r.length > RUNS_MAX) return s + WORDS.join(\", \");\n"
              "    for (var i = 0; i < r.length; i++)\n"
              "      s += (i ? \", \" : \"\") + WORDS[r[i][0]] + (r[i][1] ? \" \" + clock(from + r[i][1] * cellS, z.off) : \"\");\n"
              "    return s;\n"
              "  }\n");
    WT_HAS(p, "  function rulerSays(z, span) {\n"
              "    return \"midnight ticks in \" + z.word +\n"
              "           (span > 86400 ? \", the offset at the range's end throughout\" : \"\") +\n"
              "           (z.sensor ? \"; every other time on the page is your clock\" : \"\");\n"
              "  }\n");
    int n = 0;
    for (const char *q = p; (q = strstr(q, "getTimezoneOffset")) != NULL; q += 17) n++;
    WT_EQ(n, 1);
    WT_HAS(p, "    return SlothSun.zone(num(off) ? off : SUN.off, -new Date(t * 1000).getTimezoneOffset() * 60);");
    WT_HAS(p, "                                   offset: z.off,\n");
}

/* sun.js as served, whole functions (the #171 V1 review's rule), and
 * the page's half: every G5 caller, the ruler, the words, where the
 * position comes from. Seen red, one pin each, with sun.js's
 * NIGHT_BELOW made -7, its elev()'s longitude sign turned, its
 * phases() colouring with no position, its pos() taking a 1D fix;
 * g5() giving every present cell a sun token; g5Ruler()'s SUN_H made
 * all 2; paintStrip() making up a position, drawRuler() passing none,
 * blePresence() dropping its window, History's call dropping its
 * window, an eighth drawStrip() call added (the count), a token's hex
 * changed; and with sun.js put after glyph.js in index.html (the
 * order assertion). */
static void test_the_page_carries_the_sun(void) {
    const char *p = page();
    const char *s = strstr(p, "var SlothSun = (function () {");
    const char *gl = strstr(p, "var glyph = (function () {");
    WT_ASSERT(s && gl && s < gl);          /* g5() calls it */
    /* web/ui/sun.js */
    WT_HAS(p, "  var NIGHT_BELOW = -6, DAY_ABOVE = 6;\n"
              "  // A cell longer than this spans more than one phase too often to be\n"
              "  // given one: it keeps the single ink.\n"
              "  var MAX_CELL_S = 3600;\n"
              "  // 2100-01-01: the year walk below is bounded by it.\n"
              "  var T_MAX = 4102444800;\n"
              "  var TOKENS = [\"--sun-night\", \"--sun-rise\", \"--sun-day\", \"--sun-set\"];\n"
              "  var WORDS = [\"night\", \"sunrise\", \"day\", \"sunset\"];\n"
              "  var RAD = Math.PI / 180;\n"
              "  function snum(v) { return typeof v === \"number\" && isFinite(v); }\n"
              "  function leap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function elev(t, lat, lon) {\n"
              "    var day = Math.floor(t / 86400), sec = t - day * 86400, y = 1970, len = 365;\n"
              "    while (day >= len) { day -= len; y++; len = leap(y) ? 366 : 365; }\n"
              "    var g = 2 * Math.PI / len * (day + (sec / 3600 - 12) / 24);\n"
              "    var eq = 229.18 * (0.000075 + 0.001868 * Math.cos(g) - 0.032077 * Math.sin(g) -\n"
              "                       0.014615 * Math.cos(2 * g) - 0.040849 * Math.sin(2 * g));\n"
              "    var dec = 0.006918 - 0.399912 * Math.cos(g) + 0.070257 * Math.sin(g) -\n"
              "              0.006758 * Math.cos(2 * g) + 0.000907 * Math.sin(2 * g) -\n"
              "              0.002697 * Math.cos(3 * g) + 0.00148 * Math.sin(3 * g);\n"
              "    var ha = (sec / 60 + eq + 4 * lon) / 4 - 180;\n"
              "    var s = Math.sin(lat * RAD) * Math.sin(dec) +\n"
              "            Math.cos(lat * RAD) * Math.cos(dec) * Math.cos(ha * RAD);\n"
              "    return Math.asin(s < -1 ? -1 : s > 1 ? 1 : s) / RAD;\n"
              "  }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function phase(t, half, lat, lon) {\n"
              "    var e = elev(t, lat, lon);\n"
              "    if (e < NIGHT_BELOW) return 0;\n"
              "    if (e > DAY_ABOVE) return 2;\n"
              "    return elev(t + half, lat, lon) >= elev(t - half, lat, lon) ? 1 : 3;\n"
              "  }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function okPos(lat, lon) {\n"
              "    return snum(lat) && snum(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180;\n"
              "  }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function phases(from, cellS, n, pos) {\n"
              "    if (!pos || !okPos(pos.lat, pos.lon)) return null;\n"
              "    if (!snum(from) || from < 0 || !(cellS > 0) || cellS > MAX_CELL_S) return null;\n"
              "    if (!(n >= 1) || n > 1440 || from + n * cellS > T_MAX) return null;\n"
              "    var lat = Math.round(pos.lat * 100) / 100, lon = Math.round(pos.lon * 100) / 100;\n"
              "    var key = lat + \",\" + lon + \",\" + from + \",\" + cellS + \",\" + n;\n"
              "    if (cache[key]) return cache[key];\n"
              "    var out = [], half = cellS / 2;\n"
              "    for (var i = 0; i < n; i++) out.push(phase(from + i * cellS + half, half, lat, lon));\n"
              "    if (cached >= CACHE_MAX) { cache = {}; cached = 0; }\n"
              "    cache[key] = out;\n"
              "    cached++;\n"
              "    return out;\n"
              "  }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function runs(ph) {\n"
              "    var out = [];\n"
              "    for (var i = 0; ph && i < ph.length; i++)\n"
              "      if (!i || ph[i] !== ph[i - 1]) out.push([ph[i], i]);\n"
              "    return out;\n"
              "  }\n");
    /* web/ui/sun.js */
    WT_HAS(p, "  function pos(j) {\n"
              "    var f = j && j.fix, l = j && j.loc;\n"
              "    if (f && snum(f.mode) && f.mode >= 2 && okPos(f.lat, f.lon))\n"
              "      return { lat: f.lat, lon: f.lon, from: \"gps fix\" };\n"
              "    if (l && okPos(l.lat, l.lon) && (l[\"src\"] === \"gps\" || l[\"src\"] === \"fixed\"))\n"
              "      return { lat: l.lat, lon: l.lon, from: l[\"src\"] === \"gps\" ? \"last gps fix\" : \"--location\" };\n"
              "    return null;\n"
              "  }\n");
    /* web/ui/glyph.js */
    WT_HAS(p, "  function g5(cells, opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, n = cells ? cells.length : 0, i;\n"
              "    if (opt.ground) m.push([\"ground\", 0, 0, w, h, opt.ground]);\n"
              "    if (!n) { m.push(dash(w, h)); return m; }\n"
              "    var cw = w / n, ph = SlothSun.phases(opt.from, opt.cellS, n, opt.pos);\n"
              "    for (i = 0; i < n; i++) {\n"
              "      var x = Math.floor(i * cw), cwi = Math.max(1, Math.ceil(cw));\n"
              "      if (cells[i] < 0) m.push([\"gap\", x, 0, cwi, h, \"--faint\"]);\n"
              "      else if (cells[i] > 0)\n"
              "        m.push([\"cell\", x, 0, cwi, h, ph ? SlothSun.TOKENS[ph[i]] : \"--tui-normal\"]);\n"
              "    }\n"
              "    if (gnum(opt.first) && opt.first >= 0 && opt.first < n)\n"
              "      m.push([\"first\", Math.floor(opt.first * cw), 0, Math.max(1, Math.ceil(cw)), h,\n"
              "              \"--signal\"]);\n"
              "    // An anomaly episode underlines the cells it covers, 1 px, so the\n"
              "    // strip says when the device was here and when it was odd without\n"
              "    // either reading changing the other (R1: colour for out of band).\n"
              "    var ep = opt.episodes || [];\n"
              "    for (i = 0; i < ep.length; i++) {\n"
              "      var a = ep[i][0] < 0 ? 0 : ep[i][0], b = ep[i][1] > n - 1 ? n - 1 : ep[i][1];\n"
              "      if (b < a) continue;\n"
              "      m.push([\"anom\", Math.floor(a * cw), h - 1,\n"
              "              Math.max(1, Math.ceil((b - a + 1) * cw)), 1, \"--heat-2\"]);\n"
              "    }\n"
              "    return m;\n"
              "  }\n");
    /* web/ui/glyph.js */
    WT_HAS(p, "  var SUN_H = [1, 2, 3, 2];\n"
              "  function g5Ruler(opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, from = opt.from, to = opt.to, i;\n"
              "    if (!(to > from)) return m;\n"
              "    var n = opt.cells >= 1 ? Math.floor(opt.cells) : 0;\n"
              "    var ph = n ? SlothSun.phases(from, (to - from) / n, n, opt.pos) : null;\n"
              "    var r = SlothSun.runs(ph);\n"
              "    for (i = 0; i < r.length; i++) {\n"
              "      var a = r[i][1], b = i + 1 < r.length ? r[i + 1][1] : n, sh = SUN_H[r[i][0]];\n"
              "      m.push([\"sun\", a * w / n, h - sh, (b - a) * w / n, sh, SlothSun.TOKENS[r[i][0]]]);\n"
              "    }\n"
              "    var off = gnum(opt.offset) ? opt.offset : 0;\n"
              "    var first = Math.ceil((from + off) / 86400) * 86400 - off;\n"
              "    for (var t = first; t <= to; t += 86400)\n"
              "      m.push([\"tick\", (t - from) / (to - from) * w, 0, 1, h, \"--faint\"]);\n"
              "    if (!gnum(opt.now)) m.push([\"now\", w - 1, 0, 1, h, \"--signal\"]);\n"
              "    else if (opt.now >= from && opt.now <= to)\n"
              "      m.push([\"now\", Math.min(w - 1, (opt.now - from) / (to - from) * w), 0, 1, h, \"--signal\"]);\n"
              "    return m;\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  var SUN = { pos: null, key: \"\", off: null };\n"
              "  var SUN_POLL_MS = 300000;\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function paintStrip(c, cells, first, from, cellS) {\n"
              "    c.g5 = [cells, first, from, cellS];\n"
              "    glyph.paint(c, glyph.g5(cells, { w: c.clientWidth, h: c.clientHeight,\n"
              "                                     first: num(first) ? first : -1, ground: \"--bg\",\n"
              "                                     from: from, cellS: cellS, pos: SUN.pos }), tok);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function drawStrip(c, hex, n, first, from, cellS) {\n"
              "    paintStrip(c, glyph.cellsFromHex(hex, n), first, from, cellS);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function sunZone(off, t) {\n"
              "    if (num(off)) SUN.off = off;\n"
              "    return SlothSun.zone(num(off) ? off : SUN.off, -new Date(t * 1000).getTimezoneOffset() * 60);\n"
              "  }\n");
    WT_HAS(p, "  function drawRuler(c, from, to, cells, off) {\n"
              "    if (!c) return;\n"
              "    c.g5r = [from, to, cells, off];\n"
              "    if (!num(from) || !num(to)) { c.title = \"\"; glyph.paint(c, [], tok); return; }\n"
              "    var z = sunZone(off, to);\n"
              "    c.title = SlothSun.rulerSays(z, to - from);\n"
              "    glyph.paint(c, glyph.g5Ruler({ w: c.clientWidth, h: c.clientHeight, from: from, to: to,\n"
              "                                   offset: z.off,\n"
              "                                   now: Date.now() / 1000, cells: cells, pos: SUN.pos }), tok);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function sunWords(from, cellS, n, off, ruled) {\n"
              "    var z = sunZone(off, from + n * cellS), s = SlothSun.says(from, cellS, n, SUN.pos, z);\n"
              "    if (!ruled || !num(from) || !(cellS > 0)) return s;\n"
              "    return (s ? s + \"; \" : \"\") + SlothSun.rulerSays(z, n * cellS);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function sunNote(e, from, cellS, n, off, ruled) {\n"
              "    if (!e) return;\n"
              "    e.g5w = [from, cellS, n, off, ruled];\n"
              "    e.classList.add(\"sunw\");\n"
              "    e.textContent = sunWords(from, cellS, n, off, ruled);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function sunRepaint() {\n"
              "    var cs = document.querySelectorAll(\"canvas\"), i;\n"
              "    for (i = 0; i < cs.length; i++) {\n"
              "      if (cs[i].g5) paintStrip(cs[i], cs[i].g5[0], cs[i].g5[1], cs[i].g5[2], cs[i].g5[3]);\n"
              "      if (cs[i].g5r) drawRuler(cs[i], cs[i].g5r[0], cs[i].g5r[1], cs[i].g5r[2], cs[i].g5r[3]);\n"
              "    }\n"
              "    var ws = document.querySelectorAll(\".sunw\");\n"
              "    for (i = 0; i < ws.length; i++)\n"
              "      if (ws[i].g5w) sunNote(ws[i], ws[i].g5w[0], ws[i].g5w[1], ws[i].g5w[2], ws[i].g5w[3], ws[i].g5w[4]);\n"
              "  }\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function sunLoad() {\n"
              "    getJSON(\"/api/gnss\").then(function (j) {\n"
              "      var p = SlothSun.pos(j);\n"
              "      if (!p) return;\n"
              "      var k = p.lat.toFixed(2) + \",\" + p.lon.toFixed(2) + \",\" + p.from;\n"
              "      if (k === SUN.key) return;\n"
              "      SUN.pos = p;\n"
              "      SUN.key = k;\n"
              "      sunRepaint();\n"
              "    }).catch(function () { /* no answer: what is held stands, and none is one ink */ });\n"
              "  }\n"
              "  sunLoad();\n"
              "  setInterval(sunLoad, SUN_POLL_MS);\n");
    /* web/ui/app.js */
    WT_HAS(p, "  function blePresence(d, now) {\n"
              "    var c = $(\"bdr-strip\"), p = d.presence, cells = [], first = -1, from = null, cellS = null;\n"
              "    if (p && typeof p.bits === \"string\" && /^[0-9a-f]{24}$/.test(p.bits) && num(p.newest) && num(p.bucket_s)) {\n"
              "      var bs = p.bucket_s, nowB = Math.floor(now / bs), newB = Math.floor(p.newest / bs);\n"
              "      // Cell 0 is the bucket 95 before now's: the strip's start, for\n"
              "      // the sun's phase of each quarter hour.\n"
              "      from = (nowB - 95) * bs;\n"
              "      cellS = bs;\n"
              "      for (var j = 0; j < 96; j++) {\n"
              "        var b = nowB - 95 + j, i = newB - b, on = 0;\n"
              "        if (i >= 0 && i < 96) on = (parseInt(p.bits.charAt(23 - (i >> 2)), 16) >> (i & 3)) & 1;\n"
              "        cells.push(on);\n"
              "        if (num(d.first_seen) && Math.floor(d.first_seen / bs) === b) first = j;\n"
              "      }\n"
              "    }\n"
              "    paintStrip(c, cells, first, from, cellS);\n"
              "    sunNote($(\"bdr-sun\"), from, cellS, 96);\n"
              "    set(\"bdr-strip-note\", cells.length ? \"a quarter hour is set when a record's last_seen fell in it; a heard advertiser's record comes once a 10 s slot and a quiet one's on the 300 s heartbeat, so a quiet quarter can be an unchanged advertiser whose heartbeat fell in the next\"\n"
              "                                       : \"no data\");\n"
              "  }\n");
    /* Every G5 caller gives the window and the cell: Devices, the
     * drawer, Lookup, the WiFi clients, History, the alert page (the
     * BLE drawer's is blePresence(), above). */
    WT_HAS(p, "    drawStrip(r.cv, d.presence, 144, glyph.firstCell(d.first_seen, D.pfrom, 600, 144), D.pfrom, 600);");
    WT_HAS(p, "      drawStrip($(\"dr-strip\"), j.presence, 144,\n"
              "                glyph.firstCell(rec ? rec.first_seen : null, j.presence_from, 600, 144),\n"
              "                j.presence_from, 600);\n"
              "      sunNote($(\"dr-sun\"), j.presence_from, 600, 144, j.week ? j.week.utc_offset_s : null);");
    WT_HAS(p, "        var lb = box.appendChild(el(\"div\", \"label\", \"24 h presence, 10 min cells \"));\n"
              "        sunNote(lb.appendChild(el(\"span\", \"sub\")), j.presence_from, 600, 144);");
    WT_HAS(p, "        drawStrip(sc, j.presence, 144, glyph.firstCell(d ? d.first_seen : null, j.presence_from, 600, 144),\n"
              "                  j.presence_from, 600);");
    WT_HAS(p, "      drawStrip(cv, d.presence, 144, glyph.firstCell(d.first_seen, WF.clFrom, 600, 144), WF.clFrom, 600);");
    WT_HAS(p, "    drawStrip(cv, d.presence, cells, -1, HS.pfrom, HS.cellS);");
    WT_HAS(p, "        drawStrip($(\"ad-strip\"), d.presence, 144, -1, d.presence_from, 600);\n"
              "        sunNote($(\"ad-sun\"), d.presence_from, 600, 144, d.week ? d.week.utc_offset_s : null);");
    WT_HAS(p, "    drawStrip($(\"ad-strip\"), null);\n    sunNote($(\"ad-sun\"));");
    /* ... and there is no other: seven calls and the definition. */
    int calls = 0;
    for (const char *q = p; (q = strstr(q, "drawStrip(")) != NULL; q += 10) calls++;
    WT_EQ(calls, 8);
    int g5s = 0;
    for (const char *q = p; (q = strstr(q, "glyph.g5(")) != NULL; q += 9) g5s++;
    WT_EQ(g5s, 1);                         /* paintStrip()'s, the one painter */
    /* The three tables' rulers and words. */
    WT_HAS(p, "        D.pfrom = num(j.presence_from) ? j.presence_from : null;\n"
              "        drawRuler(DTD.ruler, D.pfrom, D.pfrom + 144 * 600, 144, j.utc_offset_s);\n"
              "        sunNote($(\"d-sun\"), D.pfrom, 600, 144, j.utc_offset_s, true);");
    WT_HAS(p, "      WF.clFrom = num(j.presence_from) ? j.presence_from : null;\n"
              "      drawRuler(DTWL.ruler, WF.clFrom, WF.clFrom + 144 * 600, 144, j.utc_offset_s);\n"
              "      sunNote($(\"w-cl-sun\"), WF.clFrom, 600, 144, j.utc_offset_s, true);");
    WT_HAS(p, "      HS.cells = j.presence_cells;\n"
              "      HS.pfrom = num(j.presence_from) ? j.presence_from : null;\n"
              "      HS.cellS = num(j.presence_cell_s) ? j.presence_cell_s : null;\n"
              "      drawRuler(DTH.ruler, HS.pfrom, HS.pfrom + HS.cells * HS.cellS, HS.cells, j.utc_offset_s);\n"
              "      sunNote($(\"h-sun\"), HS.pfrom, HS.cellS, HS.cells, j.utc_offset_s, true);");
    WT_HAS(p, "        if (c.ruler) {\n"
              "          t.ruler = th.appendChild(el(\"canvas\", \"dt-ruler\"));\n"
              "          t.ruler.ariaHidden = \"true\";\n"
              "          th.classList.add(\"dt-ruled\");\n"
              "        }");
    WT_HAS(p, "      { k: \"pr\", label: \"24 h presence\", px: 146, ruler: true }\n");
    WT_HAS(p, "      { k: \"pr\", label: \"24 h presence\", px: 146, ruler: true },\n");
    WT_HAS(p, "      { k: \"pr\", label: \"presence in the range\", px: 146, ruler: true }\n");
    WT_HAS(p, "canvas.dt-ruler { display: block; flex: none; width: 144px; height: 6px; margin-top: 1px; border-radius: 0; }");
    WT_HAS(p, "<div class=\"sub\" id=\"d-sun\"></div>");
    WT_HAS(p, "<div class=\"sub\" id=\"w-cl-sun\"></div>");
    WT_HAS(p, "<div class=\"sub\" id=\"h-sun\"></div>");
    WT_HAS(p, "<div class=\"label\">24 h presence, 10 min cells <span class=\"sub\" id=\"dr-sun\"></span></div>");
    WT_HAS(p, "<div class=\"label\">24 h presence, 10 min cells <span class=\"sub\" id=\"ad-sun\"></span></div>");
    WT_HAS(p, "<div class=\"sub\" id=\"bdr-sun\"></div>");
    /* The four tokens, both themes, as theme.css writes them
     * (web/tools/palette.c holds them apart and to 3:1 at build time,
     * and prints the figures in web/README.md's table). */
    WT_HAS(p, "  --sun-night: #4a72c4;  --sun-rise: #ffe07a;  --sun-set: #e0569b;\n"
              "  --sun-day: var(--tui-normal);\n");
    WT_HAS(p, "  --sun-night: #5b84d6;  --sun-rise: #8a7a00;  --sun-set: #c2247a;\n");
    /* The sensor's position and nothing else: the page never asks the
     * browser where it is, and never reads a zone's name to guess. Seen
     * red with a navigator.geolocation call added to sunLoad(), and
     * with Intl.DateTimeFormat().resolvedOptions().timeZone read in
     * sunWords(). */
    WT_LACKS(p, "geolocation");
    WT_LACKS(p, "timeZone");
    WT_LACKS(p, "Intl.");
    WT_LACKS(p, "getCurrentPosition");
}

/* ── G6 ─────────────────────────────────────────────────────────── */

static void test_g6_bullet(void) {
    double ranges[3] = {1, 2, 3};
    gmarks_t g;
    /* risk 2 of 3, under the threshold: the bar is plain ink. */
    gl_g6(2, 1, 48, 14, 3, ranges, 3, 3, 1, 0, &g);
    WT_EQ(gm_count(&g, "range"), 3);
    WT_EQ(gm_count(&g, "bar"), 1);
    WT_EQ(gm_count(&g, "tick"), 1);
    WT_ASSERT(!strcmp(gm_get(&g, "bar").tok, "--ink"));
    WT_ASSERT(near(gm_get(&g, "bar").w, 32));
    WT_ASSERT(near(gm_get(&g, "tick").x, 48));
    /* At the threshold the bar takes the severity colour, so the
     * column is grey while all is well. */
    gl_g6(3, 1, 48, 14, 3, ranges, 3, 3, 1, 0, &g);
    WT_ASSERT(!strcmp(gm_get(&g, "bar").tok, "--sev-warn"));
    /* Over the maximum the bar clamps rather than leaving the cell. */
    gl_g6(9, 1, 48, 14, 3, ranges, 3, 3, 1, 0, &g);
    WT_ASSERT(near(gm_get(&g, "bar").w, 48));
}

static void test_g6_count_bar(void) {
    gmarks_t g;
    /* The bar form: no ranges, no threshold tick, the bar behind the
     * number in --rule, on the column's shared scale. */
    gl_g6(64, 1, 48, 14, 128, NULL, 0, 0, 0, 1, &g);
    WT_EQ(gm_count(&g, "range"), 0);
    WT_EQ(gm_count(&g, "tick"), 0);
    WT_ASSERT(!strcmp(gm_get(&g, "bar").tok, "--rule"));
    WT_ASSERT(near(gm_get(&g, "bar").w, 24));
    /* A column maximum of zero does not divide by zero. */
    gl_g6(0, 1, 48, 14, 0, NULL, 0, 0, 0, 1, &g);
    WT_ASSERT(near(gm_get(&g, "bar").w, 0));
}

static void test_g6_states(void) {
    gmarks_t g;
    /* No value is a dash, not a bar of zero: "-" and "0" are different
     * answers (R5). */
    gl_g6(0, 0, 48, 14, 3, NULL, 0, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "dash"), 1);
    WT_EQ(gm_count(&g, "bar"), 0);
    gl_g6(0, 1, 48, 14, 3, NULL, 0, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "dash"), 0);
    WT_EQ(gm_count(&g, "bar"), 1);
    WT_ASSERT(near(gm_get(&g, "bar").w, 0));
}

/* R10 for G6: the measure, its ranges and the threshold are three
 * kinds at three places, so the glyph reads with one grey. */
static void test_g6_reads_in_greyscale(void) {
    double ranges[2] = {50, 100};
    gmarks_t g;
    gl_g6(82, 1, 50, 14, 100, ranges, 2, 60, 1, 0, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "range"), 2);
    gmark_t bar = gm_get(&g, "bar"), tick = gm_get(&g, "tick");
    WT_ASSERT(near(bar.w, 41));
    WT_ASSERT(near(tick.x, 30));
    WT_ASSERT(bar.w > tick.x);            /* over the threshold, by place */
}

/* ── V1: G1's words, the shade, shared scales, the sort, G4 ──────── */

/* G1's words end in the direction since the previous bucket. Seen red
 * with the up and down arrows swapped in the port. */
static void test_g1_words_trend(void) {
    double up[2][2] = {{0, 1}, {10, 2}}, dn[2][2] = {{0, 2}, {10, 1}}, fl[2][2] = {{0, 2}, {10, 2}};
    WT_ASSERT(!strcmp(gl_trend(up, 2), "\xe2\x86\x91"));
    WT_ASSERT(!strcmp(gl_trend(dn, 2), "\xe2\x86\x93"));
    WT_ASSERT(!strcmp(gl_trend(fl, 2), "\xe2\x86\x92"));
    /* One bucket has nothing to be a direction against. */
    WT_ASSERT(!strcmp(gl_trend(up, 1), ""));
    WT_ASSERT(!strcmp(gl_trend(NULL, 0), ""));
}

/* F13: the episode's window is one --signal mark, first, under the
 * band and the line, clipped to the window. The absence for an episode
 * over before the window began was seen red with the `sb > sa` clip
 * taken out of the port, and the clip at the window's start with the
 * `from` bound left out. The absence with no episode at all cannot be
 * isolated by a mutation of the port: with no shade given there is no
 * window to draw (the JS reads opt.shade only when it is there), so it
 * is stated here, not claimed. */
static void test_g1_episode_shade(void) {
    double pts[6][2] = {{1000,1},{1010,2},{1020,3},{1030,4},{1040,5},{1050,6}};
    gmarks_t g;
    gopt_t o = g1opt();
    gl_g1(pts, 6, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "shade"), 0);
    o.shade_on = 1; o.shade[0] = 1500; o.shade[1] = 1690;
    gl_g1(pts, 6, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "shade"), 1);
    WT_ASSERT(!strcmp(g.m[0].kind, "shade"));
    gmark_t sh = gm_get(&g, "shade");
    WT_ASSERT(near(sh.x, 50));
    WT_ASSERT(near(sh.w, 20));            /* to the end of its last bucket */
    WT_ASSERT(near(sh.y, 0) && near(sh.h, 18));
    WT_ASSERT(!strcmp(sh.tok, "--signal"));
    /* Begun before the window: from the window's edge. */
    o.shade[0] = 10; o.shade[1] = 1090;
    gl_g1(pts, 6, NULL, NULL, &o, &g);
    WT_ASSERT(near(gm_get(&g, "shade").x, 0));
    WT_ASSERT(near(gm_get(&g, "shade").w, 10));
    /* Over before the window began: nothing to shade. */
    o.shade[0] = 10; o.shade[1] = 500;
    gl_g1(pts, 6, NULL, NULL, &o, &g);
    WT_EQ(gm_count(&g, "shade"), 0);
    /* The line and the last value are unchanged by it. */
    WT_EQ(gm_count(&g, "line"), 5);
    WT_EQ(gm_count(&g, "last"), 1);
}

/* R3, F6, §9: a shared-scale stack has one maximum, so the small key's
 * line sits low in its cell instead of filling it; and a refresh never
 * shrinks it (R11). Seen red with gl_shared() keeping only the last
 * set's range. */
static void test_shared_scale_has_one_maximum(void) {
    double big[5][2] = {{1000,0},{1010,300},{1020,100},{1030,200},{1040,300}};
    double small[5][2] = {{1000,0},{1010,10},{1020,5},{1030,10},{1040,10}};
    gset_t sets[2] = { { big, 5, NULL, NULL }, { small, 5, NULL, NULL } };
    double lo, hi;
    gl_shared(sets, 2, NULL, &lo, &hi);
    WT_ASSERT(near(lo, 0) && near(hi, 300));
    /* The small key drawn on it: its last value at a thirtieth of the
     * height, not at the top as its own scale would put it. */
    double sc[2] = { lo, hi };
    gmarks_t g;
    gopt_t o = g1opt();
    o.scale = sc;
    gl_g1(small, 5, NULL, NULL, &o, &g);
    WT_ASSERT(near(gm_get(&g, "last").y, 18 - 10.0 / 300 * 18));
    o.scale = NULL;
    gl_g1(small, 5, NULL, NULL, &o, &g);
    WT_ASSERT(near(gm_get(&g, "last").y, 0));
    /* A refresh where the big key went quiet keeps the top. */
    gset_t quiet[1] = { { small, 5, NULL, NULL } };
    gl_shared(quiet, 1, sc, &lo, &hi);
    WT_ASSERT(near(hi, 300));
    /* An empty stack is the empty scale, never NaN. */
    gl_shared(NULL, 0, NULL, &lo, &hi);
    WT_ASSERT(near(lo, 0) && near(hi, 1));
}

/* F6's sort: |z| first, negative or positive, then the rows without a
 * baseline by value; with no baseline anywhere, by value and the word
 * says so. Seen red with fabs() left out of the comparison. */
static void test_multiples_sort(void) {
    grow_t r[4] = { { 0, 50, 0, 0 }, { 1, 1, 1, 0.5 }, { 2, 2, 1, -4 }, { 3, 900, 0, 0 } };
    WT_ASSERT(!strcmp(gl_order(r, 4), "|z|"));
    WT_EQ(r[0].id, 2);                     /* |z| 4, below its band */
    WT_EQ(r[1].id, 1);
    WT_EQ(r[2].id, 3);                     /* no baseline: after, by value */
    WT_EQ(r[3].id, 0);
    grow_t v[3] = { { 0, 5, 0, 0 }, { 1, 50, 0, 0 }, { 2, 0.5, 0, 0 } };
    WT_ASSERT(!strcmp(gl_order(v, 3), "value"));
    WT_EQ(v[0].id, 1);
    WT_EQ(v[2].id, 2);
}

/* The i-th mark by value, and gm_get()'s empty mark past the end: a
 * mutation that draws fewer marks must fail the assertion that reads
 * one, not crash on it. */
static gmark_t g4at(const gmarks_t *g, int i) {
    static const gmark_t none = { "", 0, 0, 0, 0, "", NULL };
    return i >= 0 && i < g->n ? g->m[i] : none;
}

/* F3, R8 and the ruling of 2026-11-11: every cell is drawn. A grid
 * that is all warming with no sample anywhere is 168 plain --rule
 * tiles and the now outline on top; no cells at all is R5's dash and
 * nothing else, the outline included. Seen red with the `st.fed` loop
 * guard put back in the port (1 mark, not 169), with a second "hatch"
 * mark pushed for each warming cell, and with the no-cells dash taken
 * out of the port. */
static void test_g4_warming_is_plain_rule(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    gmarks_t g;
    gl_g4(cells, 272, 84, 32, 14, 3, 30, 1, &g);
    WT_EQ(g.n, 169);
    WT_EQ(gm_count(&g, "warm"), 168);
    WT_EQ(gm_count(&g, "prov"), 0);
    WT_EQ(gm_count(&g, "cell"), 0);
    WT_EQ(gm_count(&g, "outline"), 1);
    for (int i = 0; i < 168; i++) {
        WT_ASSERT(!strcmp(g4at(&g, i).kind, "warm") && !strcmp(g4at(&g, i).tok, "--rule"));
        WT_ASSERT(near(g4at(&g, i).x, 32 + 10.0 * (i % 24) + 1) && near(g4at(&g, i).y, 14 + 10.0 * (i / 24) + 1));
        WT_ASSERT(near(g4at(&g, i).w, 8) && near(g4at(&g, i).h, 8));
    }
    /* The outline is the last mark: drawn on top. */
    gmark_t ol = g4at(&g, g.n - 1);
    WT_ASSERT(!strcmp(ol.kind, "outline"));
    WT_ASSERT(near(ol.x, 32 + 10.0 * 6) && near(ol.y, 14 + 10.0));
    WT_ASSERT(near(ol.w, 10) && near(ol.h, 10));
    WT_ASSERT(!strcmp(ol.tok, "--signal"));
    /* No baseline at all: the dash alone, with or without a now cell. */
    gl_g4(NULL, 272, 84, 32, 14, 3, 30, 1, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    WT_ASSERT(!strcmp(gm_get(&g, "dash").tok, "--faint"));
    WT_EQ(gm_count(&g, "outline"), 0);
    /* One cell fed: every other is a single warming mark. */
    cells[5][0] = 7; cells[5][2] = 3;
    gl_g4(cells, 272, 84, 32, 14, 3, 30, 0, &g);
    WT_EQ(g.n, 169);
    WT_EQ(gm_count(&g, "cell"), 1);
    WT_EQ(gm_count(&g, "warm"), 167);
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g4at(&g, i).kind, "warm")) WT_ASSERT(!strcmp(g4at(&g, i).tok, "--rule"));
    /* The hatch the old heatmap stroked is gone from the page. */
    WT_LACKS(page(), "for (var s = -ch; s < cw; s += 4 * dpr) {");
    WT_LACKS(page(), "grey hatched");
    /* And so is the guard that left an all-warming grid undrawn. */
    WT_LACKS(page(), "st.fed && i < 168");
}

/* Is tok one of the heat ramp's four? */
static int is_heat(const char *tok) { return !strncmp(tok, "--heat-", 7); }

/* The ruling of 2026-11-11: a warming cell with a sample is provisional
 * and says its value so far as a bar in one ink on its --rule tile, by
 * how much of the tile is inked; the ramp is a fed cell's alone. On a
 * share map the steps are fixed over 0..1. Seen red with a provisional
 * cell given heatToken() in the port, with the bar's level-3 height
 * made the whole tile, with the n >= 1 test dropped (a never-sampled
 * cell then draws the observed-absent floor), and with `share` ignored
 * (the bars then scale against the largest mean, 0.5, and the half
 * reads as three quarters). */
static void test_g4_provisional_is_one_ink(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    /* Week one and two of a device: n = 1 present, n = 1 absent, n = 2
     * at one week in two, n = 2 absent; the rest never sampled. No
     * cell is at share 1, so the scale is not the largest mean. */
    cells[0][0] = 0.5; cells[0][2] = 2;
    cells[1][0] = 0;   cells[1][2] = 1;
    cells[2][0] = 0.5; cells[2][2] = 2;
    cells[3][0] = 0;   cells[3][2] = 2;
    cells[30][0] = 0.2; cells[30][2] = 2;
    gmarks_t g;
    gl_g4(cells, 272, 84, 32, 14, 3, 30, 1, &g);
    WT_EQ(gm_count(&g, "warm"), 168);
    WT_EQ(gm_count(&g, "prov"), 5);
    WT_EQ(gm_count(&g, "cell"), 0);
    WT_EQ(gm_count(&g, "outline"), 1);
    WT_EQ(g.n, 174);
    int heat = 0, inks = 0;
    for (int i = 0; i < g.n; i++) {
        if (is_heat(g4at(&g, i).tok)) heat++;
        if (!strcmp(g4at(&g, i).kind, "prov") && strcmp(g4at(&g, i).tok, "--tui-dim")) inks++;
    }
    WT_EQ(heat, 0);
    WT_EQ(inks, 0);
    /* Each bar follows its own tile, sits on the tile's floor, is the
     * tile's width, and is never the tile's height: 1 px for 0 so far,
     * a half for 0.5, a quarter for 0.2 (tile 8 by 8 at y 15..23). */
    WT_ASSERT(!strcmp(g4at(&g, 0).kind, "warm") && !strcmp(g4at(&g, 1).kind, "prov"));
    WT_ASSERT(near(g4at(&g, 1).x, g4at(&g, 0).x) && near(g4at(&g, 1).w, g4at(&g, 0).w));
    WT_ASSERT(near(g4at(&g, 1).h, 4) && near(g4at(&g, 1).y, 19));
    WT_ASSERT(!strcmp(g4at(&g, 3).kind, "prov") && near(g4at(&g, 3).h, 1) && near(g4at(&g, 3).y, 22));
    WT_ASSERT(!strcmp(g4at(&g, 5).kind, "prov") && near(g4at(&g, 5).h, 4));
    WT_ASSERT(!strcmp(g4at(&g, 7).kind, "prov") && near(g4at(&g, 7).h, 1));
    /* Cell 4 was never sampled: its tile and no bar. */
    WT_ASSERT(!strcmp(g4at(&g, 8).kind, "warm") && !strcmp(g4at(&g, 9).kind, "warm"));
    gmark_t last = gm_last(&g, "prov");
    WT_ASSERT(near(last.h, 2) && near(last.y, 31) && near(last.x, 32 + 10.0 * 6 + 1));
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g4at(&g, i).kind, "prov")) WT_ASSERT(g4at(&g, i).h < 8 - 1e-6);
    /* The outline is still last, over the provisional cell it frames. */
    WT_ASSERT(!strcmp(g4at(&g, g.n - 1).kind, "outline"));
    /* A full share is three quarters of the tile, the most a bar gets. */
    cells[0][0] = 1; cells[0][2] = 1;
    gl_g4(cells, 272, 84, 32, 14, 3, -1, 1, &g);
    WT_ASSERT(!strcmp(g4at(&g, 1).kind, "prov") && near(g4at(&g, 1).h, 6) && near(g4at(&g, 1).y, 17));
    /* R10: in one grey, fed, warming, provisional and now are four
     * kinds, and a provisional cell is two marks where a fed one is
     * one. */
    cells[100][0] = 1; cells[100][2] = 3;
    gl_g4(cells, 272, 84, 32, 14, 3, 0, 1, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "cell"), 1);
    WT_EQ(gm_count(&g, "warm"), 167);
    WT_EQ(gm_count(&g, "prov"), 5);
    WT_EQ(gm_count(&g, "outline"), 1);
}

/* G4's ramp is against the largest fed mean: a warming cell's mean,
 * however large, does not set the ramp's top and takes no heat token.
 * A map that is not of shares scales its provisional bars against the
 * largest mean of any sampled cell, fed or provisional. Seen red with
 * the stats' max taken over every cell, with top taken over the fed
 * cells alone, and with a fed cell's token changed. */
static void test_g4_ramp_and_caption_facts(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    cells[0][0] = 100; cells[0][2] = 4;
    cells[1][0] = 50;  cells[1][2] = 3;
    cells[2][0] = 400; cells[2][2] = 2;    /* provisional, the largest */
    cells[3][0] = 200; cells[3][2] = 1;    /* provisional */
    cells[4][0] = 0;   cells[4][2] = 1;    /* provisional, nothing so far */
    g4st_t st = gl_g4_stats(cells, 3);
    WT_EQ(st.fed, 2);
    WT_EQ(st.warming, 166);
    WT_EQ(st.prov, 3);
    WT_EQ(st.unseen, 163);
    WT_EQ(st.none, 0);
    WT_ASSERT(near(st.max, 100));
    WT_ASSERT(near(st.top, 400));
    WT_ASSERT(near(st.n, 7));
    WT_ASSERT(near(st.pn, 4));
    gmarks_t g;
    gl_g4(cells, 272, 84, 32, 14, 3, -1, 0, &g);
    /* Fed cells are what they were: one whole tile each, on the ramp. */
    WT_ASSERT(!strcmp(g4at(&g, 0).kind, "cell") && !strcmp(g4at(&g, 0).tok, "--heat-3"));
    WT_ASSERT(near(g4at(&g, 0).x, 33) && near(g4at(&g, 0).y, 15) && near(g4at(&g, 0).w, 8) && near(g4at(&g, 0).h, 8));
    WT_ASSERT(!strcmp(g4at(&g, 1).kind, "cell") && !strcmp(g4at(&g, 1).tok, "--heat-2"));
    /* 400 of 400 is three quarters, 200 of 400 a half, 0 the floor. */
    WT_ASSERT(!strcmp(g4at(&g, 2).kind, "warm") && !strcmp(g4at(&g, 3).kind, "prov"));
    WT_ASSERT(near(g4at(&g, 3).h, 6) && !strcmp(g4at(&g, 3).tok, "--tui-dim"));
    WT_ASSERT(!strcmp(g4at(&g, 5).kind, "prov") && near(g4at(&g, 5).h, 4));
    WT_ASSERT(!strcmp(g4at(&g, 7).kind, "prov") && near(g4at(&g, 7).h, 1));
    WT_EQ(gm_count(&g, "outline"), 0);
    int heat = 0;
    for (int i = 0; i < g.n; i++) if (is_heat(g4at(&g, i).tok)) heat++;
    WT_EQ(heat, 2);
    /* A fed cell's mean sets the provisional scale too: against 100,
     * 0.5 and 0.25 are both in the first third. */
    cells[2][0] = 0.5; cells[3][0] = 0.25;
    gl_g4(cells, 272, 84, 32, 14, 3, -1, 0, &g);
    WT_ASSERT(near(g4at(&g, 3).h, 2) && near(g4at(&g, 5).h, 2));
    /* Which scale is the caller's word, not the data's: the same cells
     * against their own largest mean, then as shares against 1. */
    cells[0][0] = 0.4; cells[1][0] = 0.1;
    gl_g4(cells, 272, 84, 32, 14, 3, -1, 0, &g);
    WT_ASSERT(near(g4at(&g, 3).h, 6) && near(g4at(&g, 5).h, 4));   /* against top 0.5 */
    gl_g4(cells, 272, 84, 32, 14, 3, -1, 1, &g);
    WT_ASSERT(near(g4at(&g, 3).h, 4) && near(g4at(&g, 5).h, 2));   /* against 1 */
    /* R10: in one grey, fed, warming and now are still their kinds. */
    gl_g4(cells, 272, 84, 32, 14, 3, 0, 0, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "cell"), 2);
    WT_EQ(gm_count(&g, "warm"), 166);
    WT_EQ(gm_count(&g, "outline"), 1);
}

/* The caption says what the tiles cannot (R9, R10): the ramp's top
 * while a cell is fed, the provisional bar's scale while one is
 * provisional (0 to 1 for shares, else the largest mean so far, in the
 * unit), n over both, and the counts: warming, fed, provisional, not
 * yet observed. Seen red with prov and unseen swapped in the port's
 * state, and with the share scale printed as the largest mean. */
static void test_g4_caption_counts(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    char out[400];
    /* No baseline: R5's words, no scale. */
    g4st_t st = gl_g4_stats(NULL, 3);
    WT_EQ(st.none, 1);
    WT_EQ(st.unseen, 168);
    gl_heat_caption("dev.present, share of weeks present", &st, 1, "", out, sizeof(out));
    WT_ASSERT(!strcmp(out, "dev.present, share of weeks present, hour of week, n=0, no data"));
    /* Never sampled anywhere: no scale to name. */
    st = gl_g4_stats(cells, 3);
    gl_heat_caption("s", &st, 1, "", out, sizeof(out));
    WT_ASSERT(!strcmp(out, "s, hour of week, n=0, warming: 168 of 168 cells, fed: 0, "
                           "provisional: 0 (under 3 weeks), not yet observed: 168"));
    /* Week two of a device: 96 cells sampled, 24 of them twice. */
    for (int i = 0; i < 96; i++) { cells[i][0] = i % 2 ? 0.5 : 0; cells[i][2] = i < 24 ? 2 : 1; }
    st = gl_g4_stats(cells, 3);
    gl_heat_caption("dev.present, share of weeks present", &st, 1, "", out, sizeof(out));
    WT_ASSERT(!strcmp(out, "dev.present, share of weeks present, hour of week, "
                           "provisional bar in thirds of 0 to 1, n=120, "
                           "warming: 168 of 168 cells, fed: 0, provisional: 96 "
                           "(under 3 weeks), not yet observed: 72"));
    /* A rate, some fed: both scales, each in the unit. */
    for (int i = 0; i < 12; i++) { cells[i][0] = 1200; cells[i][2] = 3; }
    cells[50][0] = 25000;
    st = gl_g4_stats(cells, 3);
    gl_heat_caption("iface.rx_rate wlan0", &st, 0, "B/s", out, sizeof(out));
    WT_ASSERT(!strcmp(out, "iface.rx_rate wlan0, hour of week, ramp 0 to 1200 B/s, "
                           "provisional bar in thirds of 0 to 25.0k B/s, n=132, "
                           "warming: 156 of 168 cells, fed: 12, provisional: 84 "
                           "(under 3 weeks), not yet observed: 72"));
    /* Every cell fed: the ramp and n, no state. */
    for (int i = 0; i < 168; i++) { cells[i][0] = 0.5; cells[i][2] = 4; }
    st = gl_g4_stats(cells, 3);
    gl_heat_caption("s", &st, 1, "", out, sizeof(out));
    WT_ASSERT(!strcmp(out, "s, hour of week, ramp 0 to 0.50, n=672"));
    /* The page's side of it, whole: the callers and the caption. */
    const char *p = page();
    WT_HAS(p, "  function fmt(v) {\n"
              "    if (!num(v)) return \"-\";\n"
              "    var a = Math.abs(v);\n"
              "    if (a >= 1e9) return (v / 1e9).toFixed(1) + \"G\";\n"
              "    if (a >= 1e6) return (v / 1e6).toFixed(1) + \"M\";\n"
              "    if (a >= 1e4) return (v / 1e3).toFixed(1) + \"k\";\n"
              "    if (a >= 100 || v === Math.round(v)) return String(Math.round(v));\n"
              "    return v.toFixed(2);\n"
              "  }\n");
    WT_HAS(p, "  function heatmap(c, bl) {\n"
              "    var T = theme();\n"
              "    var cells = bl && bl.cells || null;\n"
              "    var warm = bl && num(bl.warm_n) ? bl.warm_n : 3;\n"
              "    var share = !!bl && (bl.share === true || bl.scale === \"share_of_weeks\");\n"
              "    glyph.paint(c, glyph.g4(cells, { w: c.clientWidth, h: c.clientHeight, x0: 32, y0: 14,\n"
              "                                     warm: warm, now: bl ? bl.now_cell : -1,\n"
              "                                     share: share }), tok);\n"
              "    var st = glyph.g4Stats(cells, warm);\n"
              "    st.share = share;\n"
              "    if (!cells) return st;\n"
              "    var dpr = window.devicePixelRatio || 1;\n"
              "    var g = c.getContext(\"2d\");\n"
              "    var cw = (c.width - 32 * dpr) / 24, ch = (c.height - 14 * dpr) / 7;\n"
              "    g.font = (9 * dpr) + \"px \" + css(\"--font-mono\");\n"
              "    g.fillStyle = T.muted;\n"
              "    g.textBaseline = \"middle\";\n"
              "    for (var d = 0; d < 7; d++) g.fillText(DAYS[d], 0, 14 * dpr + ch * (d + 0.5));\n"
              "    g.textBaseline = \"top\";\n"
              "    for (var h = 0; h < 24; h += 3) g.fillText(String(h), 32 * dpr + cw * h, 0);\n"
              "    return st;\n"
              "  }\n");
    WT_HAS(p, "  function heatCaption(source, st, unit) {\n"
              "    if (st.none)\n"
              "      return glyph.caption({ source: source, window: \"hour of week\", n: 0, state: \"no data\" });\n"
              "    var u = unit ? \" \" + unit : \"\", sc = [];\n"
              "    if (st.fed) sc.push(\"ramp 0 to \" + fmt(st.max) + u);\n"
              "    if (st.prov)\n"
              "      sc.push(\"provisional bar in thirds of 0 to \" + (st.share ? \"1\" : fmt(st.top) + u));\n"
              "    return glyph.caption({ source: source, window: \"hour of week\", scale: sc.join(\", \"),\n"
              "      n: st.n + st.pn,\n"
              "      state: st.warming ? \"warming: \" + st.warming + \" of 168 cells, fed: \" + st.fed +\n"
              "             \", provisional: \" + st.prov + \" (under \" + st.warm + \" weeks), not yet observed: \" +\n"
              "             st.unseen : \"\" });\n"
              "  }\n");
    /* Each caller hands the glyph what it needs: the drawer's map is of
     * shares and says so; the Overview's takes /api/baseline's answer,
     * whose "scale" says whether it is. */
    WT_HAS(p, "      var ws = heatmap($(\"dr-week\"), { cells: cells, warm_n: wk.warm_n, now_cell: wk.now_cell,\n"
              "                                       share: true });\n"
              "      set(\"dr-week-note\", heatCaption(\"dev.present, share of weeks present\", ws, \"\"));");
    WT_HAS(p, "          var hs = heatmap($(\"o-heat\"), bl);\n"
              "          set(\"o-heat-note\", heatCaption(\"iface.rx_rate \" + O.key +\n"
              "              \", mean by local hour of the sensor host\", hs, \"B/s\"));");
}

/* F1, ruling 5: the Overview's tiles in urgency order, each with a G1
 * and its words; every network fact in the strip and the footer's
 * drops with a 40 px G1; each fed by its series in facts.js. Seen red
 * with t-tp moved back to the front, and with k-devs-spark removed. */
static void test_tiles_and_strip_carry_g1(void) {
    const char *p = page();
    static const char *const order[] = { "t-alerts", "t-anoms", "t-sensor", "t-tp", "t-devs",
                                         "t-rate", "t-ble" };
    static const char *const spark[] = { "k-alerts-spark", "k-anoms-spark", "k-sensor-spark",
                                         "k-tp-spark", "k-devs-spark", "k-rate-spark", "k-ble-spark" };
    static const char *const words[] = { "k-alerts-w", "k-anoms-w", "k-sensor-w", "k-tp-w",
                                         "k-devs-w", "k-rate-w", "k-ble-w" };
    const char *prev = p;
    for (size_t i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "<a class=\"tile hud\" id=\"%s\"", order[i]);
        const char *t = strstr(p, want);
        WT_ASSERT(t != NULL && t > prev);
        if (!t) continue;
        prev = t;
        const char *end = strstr(t, "</a>");
        WT_ASSERT(end != NULL);
        char sp[64], wd[64];
        snprintf(sp, sizeof(sp), "<canvas class=\"spark\" id=\"%s\"", spark[i]);
        snprintf(wd, sizeof(wd), "<div class=\"sub gw\" id=\"%s\">", words[i]);
        const char *a = strstr(t, sp), *b = strstr(t, wd);
        WT_ASSERT(a != NULL && end != NULL && a < end);
        WT_ASSERT(b != NULL && end != NULL && b < end);
    }
    static const char *const sg[] = { "s-devs-g", "s-ble-g", "s-alerts-g", "s-anoms-g", "s-rate-g",
                                      "f-drops-g" };
    for (size_t i = 0; i < sizeof(sg) / sizeof(sg[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "<canvas class=\"sg\" id=\"%s\"", sg[i]);
        WT_HAS(p, want);
    }
    static const char *const metric[] = { "live.alerts_open", "live.anomalies_open", "sensor.drops",
                                          "live.devices", "records.total", "ble.devices" };
    for (size_t i = 0; i < sizeof(metric) / sizeof(metric[0]); i++) {
        char want[64];
        snprintf(want, sizeof(want), "metric: \"%s\"", metric[i]);
        WT_HAS(p, want);
    }
    WT_HAS(p, "  window.SlothFacts = { init: init, refresh: refresh, paint: paint, words: words };");
}

/* F13 and F6 as the page wires them: a card's G1 is given its band and
 * the episode, and says "series unavailable" in the glyph's place when
 * the read fails; the multiples are one shared scale unless "own" is
 * picked, and the caption names the sort. Seen red with the card's
 * catch emptied back to the old silent one, and with the multiples'
 * shared scale replaced by null. */
static void test_cards_and_multiples_wiring(void) {
    const char *p = page();
    WT_HAS(p, "        shade: [first, num(a.last_seen) ? a.last_seen : now] }), tok);");
    WT_HAS(p, "      cv.hidden = true;\n      note.textContent = \"series unavailable\";");
    WT_LACKS(p, "/* the card stands without it */");
    WT_HAS(p, "      var sh = m.kind === \"presence\" ? null : glyph.shared(ord.rows, "
              "A.ownScale ? null : A.mscale || null);");
    WT_HAS(p, "                : \"shared scale, top \" + fmt(sh[1]) + \" \" + m.unit) + \", sorted by \" + ord.by,");
    WT_HAS(p, "        if (own) cell.appendChild(el(\"div\", \"mx\", \"top \" + fmt(own[1])));");
    /* The heatmap's caption counts the warming cells (F3). */
    WT_HAS(p, "      state: st.warming ? \"warming: \" + st.warming + \" of 168 cells, fed: \" + st.fed +");
}

/* ── V2: G2, its words, the new mark, G6's placements ───────────── */

/* "No whisker" is has_w 0 with a zeroed range, never NULL: a mutation
 * that drops the has_w test must draw a wrong mark, not crash the suite
 * (V0's M4 and M8). */
static const double NOWK[2] = { 0, 0 };

/* G2's states (§5 G2, §9): no data is the dash alone; one sample its
 * dot alone; four are dots; a gap breaks the line; the last value is
 * always marked. Seen red with the one-sample early return taken out
 * of the port (a ref mark appeared). */
static void test_g2_states(void) {
    gmarks_t g;
    gl_g2(NULL, 0, 72, 14, 0, 3600, 60, 0, NOWK, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    double one[1][2] = {{1800, -60}};
    gl_g2(one, 1, 72, 14, 0, 3600, 60, 0, NOWK, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "last"), 1);
    WT_EQ(gm_count(&g, "ref"), 0);
    double four[4][2] = {{0, -80}, {60, -70}, {120, -60}, {180, -50}};
    gl_g2(four, 4, 72, 14, 0, 3600, 60, 0, NOWK, &g);
    WT_EQ(gm_count(&g, "line"), 0);
    WT_EQ(gm_count(&g, "dot"), 3);
    WT_EQ(gm_count(&g, "last"), 1);
    double gp[6][2] = {{0, -80}, {60, -70}, {120, -60}, {600, -50}, {660, -52}, {720, -51}};
    gl_g2(gp, 6, 72, 14, 0, 3600, 60, 0, NOWK, &g);
    WT_EQ(gm_count(&g, "gap"), 1);
    WT_EQ(gm_count(&g, "line"), 4);
    /* One ink (R1): every line segment is --tui-normal, however high. */
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g.m[i].kind, "line")) WT_ASSERT(!strcmp(g.m[i].tok, "--tui-normal"));
}

/* The fixed scale (R3, §9): -20 dBm is the top and -95 the bottom on
 * every G2, whatever the row's own range, so two rows compare; the
 * -67 dBm rule is at its place (ruling 3); a -10 dBm reading clamps to
 * the top and is counted. Seen red with the clamp taken out of gl_g2y
 * (the last value left the glyph) and with the count's upper bound
 * dropped. */
static void test_g2_fixed_scale_and_clamp(void) {
    gmarks_t g;
    double a[5][2] = {{0, -90}, {60, -88}, {120, -86}, {180, -84}, {240, -20}};
    gl_g2(a, 5, 72, 15, 0, 300, 60, 0, NOWK, &g);
    WT_ASSERT(near(gm_get(&g, "last").y, 0));
    WT_ASSERT(near(gm_get(&g, "ref").y, 15 - (-67.0 + 95) / 75 * 15));
    WT_ASSERT(!strcmp(gm_get(&g, "ref").tok, "--faint"));
    double b[5][2] = {{0, -30}, {60, -28}, {120, -26}, {180, -24}, {240, -95}};
    gl_g2(b, 5, 72, 15, 0, 300, 60, 0, NOWK, &g);
    WT_ASSERT(near(gm_get(&g, "last").y, 15));
    double c[5][2] = {{0, -60}, {60, -50}, {120, -40}, {180, -30}, {240, -10}};
    gl_g2(c, 5, 72, 15, 0, 300, 60, 0, NOWK, &g);
    WT_ASSERT(near(gm_get(&g, "last").y, 0));
    WT_EQ(gl_g2_clamped(c, 5), 1);
    WT_EQ(gl_g2_clamped(a, 5), 0);
    double d[1][2] = {{0, -120}};
    WT_EQ(gl_g2_clamped(d, 1), 1);
}

/* The whisker (§5 G2): the range at the last value, drawn from its top
 * down, and only when there is one. The absence with none given was
 * seen red with the has_w test taken out of the port (it drew the
 * whisker of a zeroed range), and with a range out of order. */
static void test_g2_whisker(void) {
    gmarks_t g;
    double p[5][2] = {{0, -70}, {60, -66}, {120, -62}, {180, -58}, {240, -55}};
    double wk[2] = { -65, -50 };
    gl_g2(p, 5, 72, 15, 0, 300, 60, 1, wk, &g);
    WT_EQ(gm_count(&g, "whisker"), 1);
    gmark_t w = gm_get(&g, "whisker");
    WT_ASSERT(near(w.x, gm_get(&g, "last").x));
    WT_ASSERT(near(w.y, 15 - (-50.0 + 95) / 75 * 15));
    WT_ASSERT(near(w.h, 15.0 * 15 / 75));
    double none[2] = { 0, 0 };
    gl_g2(p, 5, 72, 15, 0, 300, 60, 0, none, &g);
    WT_EQ(gm_count(&g, "whisker"), 0);
    double bad[2] = { -50, -65 };
    gl_g2(p, 5, 72, 15, 0, 300, 60, 1, bad, &g);
    WT_EQ(gm_count(&g, "whisker"), 0);
    /* R10: in one grey the rule, the line, the whisker and the last
     * value are four kinds at their own places. */
    gl_g2(p, 5, 72, 15, 0, 300, 60, 1, wk, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "ref"), 1);
    WT_EQ(gm_count(&g, "line"), 4);
    WT_EQ(gm_count(&g, "whisker"), 1);
    WT_EQ(gm_count(&g, "last"), 1);
}

/* G2's words agree with sloth's estimate and fit nothing of their own:
 * bold only when sloth's trend says approaching, whatever the line
 * does, and the band and trend glyph as the TUI's distance cell prints
 * them (rf_band_short, rf_trend_glyph). A climbing trail that sloth
 * calls steady is not bold. Seen red with the port's bold taken from
 * the last value against the first instead (a slope of its own). */
static void test_g2_words_are_sloths(void) {
    g2w_t w = gl_g2_words(1, -45.4, "room", "approaching");
    WT_ASSERT(!strcmp(w.text, "-45"));
    WT_EQ(w.bold, 1);
    WT_ASSERT(!strcmp(w.nearw, "room \xe2\x86\x98"));
    w = gl_g2_words(1, -45, "building", "steady");
    WT_EQ(w.bold, 0);
    WT_ASSERT(!strcmp(w.nearw, "bldg \xe2\x86\x92"));
    w = gl_g2_words(1, -80, "far", "leaving");
    WT_ASSERT(!strcmp(w.nearw, "far \xe2\x86\x97"));
    /* No estimate: no words, never a guess; no value: "-". */
    w = gl_g2_words(0, 0, NULL, NULL);
    WT_ASSERT(!strcmp(w.text, "-"));
    WT_EQ(w.bold, 0);
    WT_ASSERT(!strcmp(w.nearw, ""));
    /* A word that is not sloth's says nothing. */
    w = gl_g2_words(1, -60, "next door", "unknown");
    WT_ASSERT(!strcmp(w.nearw, ""));
    WT_EQ(w.bold, 0);
    /* The page's cells take their bold and words from g2Words() and
     * from the row's own rf words, nowhere else. */
    const char *p = page();
    WT_HAS(p, "    var w = glyph.g2Words(last, rf ? rf.band : null, rf ? rf.trend : null);");
    WT_HAS(p, "    c.appendChild(el(\"span\", w.bold ? \"g2n near\" : \"g2n\", w.text));");
    WT_HAS(p, "if (d.rf && d.rf.trend === \"approaching\") nnear++;");
    WT_HAS(p, "if (a.rf && a.rf.trend === \"approaching\") nnear++;");
}

/* F15: new is first seen inside the window; G5's first-seen cell is
 * where it falls, -1 before the window or past it. Seen red with the
 * port's >= made >. */
static void test_new_mark_and_first_cell(void) {
    WT_EQ(gl_is_new(1, 1000, 1000), 1);
    WT_EQ(gl_is_new(1, 999, 1000), 0);
    WT_EQ(gl_is_new(0, 5000, 1000), 0);
    WT_EQ(gl_first_cell(1, 1000, 1000, 600, 144), 0);
    WT_EQ(gl_first_cell(1, 1000 + 600 * 7 + 5, 1000, 600, 144), 7);
    WT_EQ(gl_first_cell(1, 999, 1000, 600, 144), -1);
    WT_EQ(gl_first_cell(1, 1000 + 600 * 144, 1000, 600, 144), -1);
    /* The strip draws it as G5's "first" mark at that cell. */
    int cells[10] = { 0, 0, 0, 1, 1, 1, 0, 0, 0, 0 };
    gmarks_t g;
    gl_g5(cells, 10, 100, 12, gl_first_cell(1, 1000 + 600 * 3, 1000, 600, 10), NULL, 0, &g);
    WT_EQ(gm_count(&g, "first"), 1);
    WT_ASSERT(near(gm_get(&g, "first").x, 30));
    /* The page passes it: Devices, the drawer and the Lookup card. */
    const char *p = page();
    WT_HAS(p, "    drawStrip(r.cv, d.presence, 144, glyph.firstCell(d.first_seen, D.pfrom, 600, 144), D.pfrom, 600);");
    WT_HAS(p, "                glyph.firstCell(rec ? rec.first_seen : null, j.presence_from, 600, 144),\n"
              "                j.presence_from, 600);");
    WT_HAS(p, "    r.nw = SlothRf.newMark(d.first_seen, D.pfrom);");
    WT_HAS(p, "    var nw = SlothRf.newMark(a.first_seen, WF.newFrom);");
    WT_HAS(p, "    if (!glyph.isNew(first, from)) return null;");
}

/* F9, F17, F20 as the page wires them: G2 in both DBM columns, the
 * drawer and the Lookup card; G6's bullet on risk (sloth's levels, the
 * tick at HIGH), karma (karma_candidates.score, 1 to 7, the tick at 3,
 * the least a corroborated candidate scores), the anomaly score (A1's 60) and the anomaly
 * table; G6's bar on the anom and flow total columns, each on its own
 * column maximum; and the card's rounded score bar gone (R8). Each seen
 * red with its line taken out of the page. */
static void test_v2_wiring(void) {
    const char *p = page();
    WT_HAS(p, "window.SlothRf = { init: function (h) { H = h; keys(); }, cell: cell, block: block, bullet: bullet,");
    WT_HAS(p, "    SlothRf.cell(r.cells[\"c-sig\"], d.rf, num(d.signal) ? d.signal : null);");
    WT_HAS(p, "    SlothRf.cell(sg, a.rf, num(a.signal) ? a.signal : null, a.channel);");
    WT_HAS(p, "      drf.appendChild(SlothRf.block(j.rf, mac));");
    WT_HAS(p, "        box.appendChild(SlothRf.block(j.rf, j.mac));");
    WT_HAS(p, "<div id=\"dr-rf\"></div>");
    /* The theme toggle redraws the Lookup card too, whose strip and G2
     * are canvases now: pixels do not follow a var(). */
    WT_HAS(p, "    if (view !== \"lookup\") show(view, VP);\n"
              "    // The Lookup card has canvases since V2 (F20: its strip and G2), so\n"
              "    // it is asked again rather than shown, which would only focus the\n"
              "    // box and leave the old theme's pixels.\n"
              "    else lookup();\n");
    WT_HAS(p, "{ max: 3, ranges: [1, 2, 3], threshold: 2 }");
    WT_HAS(p, "{ max: 7, ranges: [3, 7], threshold: 3 }");
    /* Not the alert's 0-100 confidence: the column is the [y] score. */
    WT_LACKS(p, "{ max: 100, ranges: [20, 45, 100], threshold: 45 }");
    WT_HAS(p, "    return { max: 100, ranges: [40, 70, 100], threshold: a.rule === \"A1\" ? 60 : null };");
    WT_HAS(p, "    SlothRf.bullet(sb, score, ANOM_G6(a), \"\");");
    WT_HAS(p, "      SlothRf.bullet(row.appendChild(el(\"span\", \"n\")), score, ANOM_G6(a), String(score),");
    WT_HAS(p, "    SlothRf.count(r.cells[\"c-an\"], an, D.anMax, String(an), an > 0 ? heatClass(0.5) : \"d-dim\");");
    WT_HAS(p, "    SlothRf.count(row.appendChild(el(\"span\", \"n\")), f.total, F.totMax, fmt(f.total),");
    WT_HAS(p, "      return glyph.g6(num(v) ? v : null, { w: w, h: h, max: max, count: true });");
    WT_LACKS(p, "var bar = el(\"div\", \"bar\");");
    WT_LACKS(p, ".bar { height: 4px;");
    /* A table's cell reads the whole hour in every row (P4). The block's
     * caption named the -67 dBm rule (ruling 3) until the S-meter took
     * G2's place (owner ruling 2026-11-11): the meter draws no rule. */
    WT_HAS(p, "    var n = rf && rf.cells && rf.cells.length ? rf.cells.length : 60;");
    /* The member's cells are web_rf.h's: the page's fallback is the same
     * count. */
    WT_EQ(WEB_RF_CELLS, 60);
}

/* ── the S-meter (owner rulings 2026-11-11) ─────────────────────── */

static int sm_is(int have, double v, const smsc_t *sc, const char *want) {
    char w[16];
    gl_sm_word(have, v, sc, w, sizeof(w));
    if (strcmp(w, want)) fprintf(stderr, "    %g reads %s, not %s\n", v, w, want);
    return !strcmp(w, want);
}

/* The face and the band table: 6 dB an S-unit, nine of them, then
 * 10 dB segments to 27 dB over S9, on every band; the 2.4 GHz row is
 * the ruled scale (S1 -95, S9 -47, the top -20 dBm, which is R3's old
 * range); the 5 and 6 GHz rows sit lower by the free-space path loss
 * against 2442 MHz at the band's middle, rounded to a whole dB (7 and
 * 9). Seen red with the 5 GHz row's s9 made -47 in the port. */
static void test_sm_constants_and_band_table(void) {
    WT_EQ(GL_SM_DB, 6);
    WT_EQ(GL_SM_UNITS, 9);
    WT_EQ(GL_SM_OVER_DB, 10);
    WT_EQ(GL_SM_OVER_TOP, 27);
    WT_EQ(GL_SM_NBANDS, 3);
    static const int S9[3] = { -47, -54, -56 }, S1[3] = { -95, -102, -104 }, TOP[3] = { -20, -27, -29 };
    for (int i = 0; i < GL_SM_NBANDS; i++) {
        int off = (int)floor(20 * log10(GL_SM_BANDS[i].mhz / 2442.0) + 0.5);
        WT_EQ(GL_SM_BANDS[i].s9, -47 - off);
        WT_EQ(GL_SM_BANDS[i].s9, S9[i]);
        smsc_t sc = gl_sm_dbm(GL_SM_BANDS[i].band);
        WT_EQ(sc.unknown, 0);
        WT_ASSERT(!strcmp(sc.band, GL_SM_BANDS[i].band));
        WT_EQ(sc.n, 11);
        WT_EQ(sc.knee, 9);
        WT_ASSERT(near(sc.lo, S1[i]) && near(sc.edges[0], S1[i]));
        WT_ASSERT(near(sc.edges[8], S9[i]));
        WT_ASSERT(near(sc.edges[9], S9[i] + 10) && near(sc.edges[10], S9[i] + 20));
        WT_ASSERT(near(sc.hi, TOP[i]));
        for (int k = 1; k < 9; k++) WT_ASSERT(near(sc.edges[k] - sc.edges[k - 1], 6));
        /* Each row's S1 and S9 at the edge, and a hair under S9. */
        WT_ASSERT(sm_is(1, S1[i], &sc, "S1"));
        WT_ASSERT(sm_is(1, S9[i], &sc, "S9"));
        WT_ASSERT(sm_is(1, S9[i] - 0.01, &sc, "S8"));
        WT_ASSERT(sm_is(1, S9[i] + 10, &sc, "S9+10"));
    }
    WT_ASSERT(near(GL_SM_BANDS[0].mhz, 2442) && near(GL_SM_BANDS[1].mhz, 5500) &&
              near(GL_SM_BANDS[2].mhz, 6535));
}

/* The reading at every boundary of the 2.4 GHz row: a segment lights
 * when the value has reached its edge, so exactly on an edge is that
 * S-unit, a hundredth under it the one below, a hundredth over it the
 * same. Past S9 the word steps in tens as the face does: -46 is still
 * S9, -37 is S9+10, -27 and the top S9+20. Both ends clamp as g2Y
 * clamps and are counted. Seen red with the port's c >= edge made
 * c > edge (every edge read one S-unit low, -95 read "-"). */
static void test_sm_boundaries_and_readout(void) {
    smsc_t sc = gl_sm_dbm("2.4 GHz");
    for (int k = 1; k <= 9; k++) {
        double e = -95 + (k - 1) * 6;
        char want[8], below[8];
        snprintf(want, sizeof(want), "S%d", k);
        snprintf(below, sizeof(below), "S%d", k > 1 ? k - 1 : 1);
        WT_EQ(gl_sm_level(1, e, &sc), k);
        WT_ASSERT(sm_is(1, e, &sc, want));
        WT_ASSERT(sm_is(1, e + 0.01, &sc, want));
        WT_ASSERT(sm_is(1, e - 0.01, &sc, below));
    }
    WT_ASSERT(sm_is(1, -95, &sc, "S1"));
    WT_ASSERT(sm_is(1, -47, &sc, "S9"));
    WT_ASSERT(sm_is(1, -46, &sc, "S9"));
    WT_ASSERT(sm_is(1, -37.01, &sc, "S9"));
    WT_ASSERT(sm_is(1, -37, &sc, "S9+10"));
    WT_ASSERT(sm_is(1, -36, &sc, "S9+10"));
    WT_ASSERT(sm_is(1, -27.01, &sc, "S9+10"));
    WT_ASSERT(sm_is(1, -27, &sc, "S9+20"));
    WT_ASSERT(sm_is(1, -20, &sc, "S9+20"));
    /* The clamps: under S1 is S1, over the top the last segment. */
    WT_ASSERT(sm_is(1, -96, &sc, "S1"));
    WT_ASSERT(sm_is(1, -120, &sc, "S1"));
    WT_ASSERT(sm_is(1, -19, &sc, "S9+20"));
    WT_ASSERT(sm_is(1, -5, &sc, "S9+20"));
    WT_EQ(gl_sm_level(1, -120, &sc), 1);
    WT_EQ(gl_sm_level(1, -5, &sc), 11);
    /* No reading has no word but the dash's. */
    WT_ASSERT(sm_is(0, 0, &sc, "-"));
    WT_EQ(gl_sm_level(0, -50, &sc), 0);
    /* Counted the way g2Clamped() counts: past either end, not on it. */
    double p[6][2] = {{0, -120}, {1, -95}, {2, -60}, {3, -20}, {4, -19.5}, {5, -5}};
    WT_EQ(gl_sm_clamped(p, 6, &sc), 3);
    WT_EQ(gl_sm_clamped(p + 1, 3, &sc), 0);
    /* The same count on another band's row is that row's ends. */
    smsc_t s5 = gl_sm_dbm("5 GHz");
    double q[3][2] = {{0, -100}, {1, -24}, {2, -103}};
    WT_EQ(gl_sm_clamped(q, 3, &s5), 2);
    WT_EQ(gl_sm_clamped(q, 3, &sc), 2);
    double r[1][2] = {{0, -100}};
    WT_EQ(gl_sm_clamped(r, 1, &s5), 0);
    WT_EQ(gl_sm_clamped(r, 1, &sc), 1);
}

/* The band lookup is live: one reading is a different S on each band's
 * row, the row comes from the row's own words (sloth's band label, else
 * its channel number as ap_band_label() reads one), and a row with
 * neither reads on the 2.4 GHz row and says unknown. Seen red with
 * gl_sm_dbm() forced onto the 2.4 GHz row whatever it was asked (the
 * three bands read alike, and nothing was unknown). */
static void test_sm_reads_on_its_band(void) {
    smsc_t s2 = gl_sm_dbm("2.4 GHz"), s5 = gl_sm_dbm("5 GHz"), s6 = gl_sm_dbm("6 GHz");
    WT_ASSERT(sm_is(1, -55, &s2, "S7"));
    WT_ASSERT(sm_is(1, -55, &s5, "S8"));
    WT_ASSERT(sm_is(1, -55, &s6, "S9"));
    WT_ASSERT(sm_is(1, -47, &s2, "S9"));
    WT_ASSERT(sm_is(1, -47, &s5, "S9"));
    WT_ASSERT(sm_is(1, -44, &s5, "S9+10"));
    WT_ASSERT(sm_is(1, -44, &s2, "S9"));
    WT_ASSERT(sm_is(1, -100, &s6, "S1"));
    WT_ASSERT(sm_is(1, -98, &s6, "S2"));
    WT_ASSERT(sm_is(1, -98, &s5, "S1"));
    /* The band from the row. */
    WT_ASSERT(!strcmp(gl_sm_band(1, 1, NULL), "2.4 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 14, NULL), "2.4 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 32, NULL), "5 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 36, NULL), "5 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 177, NULL), "5 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 0, NULL), ""));
    WT_ASSERT(!strcmp(gl_sm_band(1, 15, NULL), ""));
    WT_ASSERT(!strcmp(gl_sm_band(1, 31, NULL), ""));
    WT_ASSERT(!strcmp(gl_sm_band(1, 178, NULL), ""));
    WT_ASSERT(!strcmp(gl_sm_band(0, 36, NULL), ""));
    /* sloth's own label wins over the number: 6 GHz channel 37 is also
     * a 5 GHz number. A word that is no row's is not a band. */
    WT_ASSERT(!strcmp(gl_sm_band(1, 37, "6 GHz"), "6 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(0, 0, "5 GHz"), "5 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(1, 6, "60 GHz"), "2.4 GHz"));
    WT_ASSERT(!strcmp(gl_sm_band(0, 0, "?"), ""));
    /* Unknown: the 2.4 GHz row, and said. */
    smsc_t u = gl_sm_dbm("");
    WT_EQ(u.unknown, 1);
    WT_ASSERT(!strcmp(u.band, "2.4 GHz"));
    WT_ASSERT(near(u.edges[8], -47));
    WT_ASSERT(sm_is(1, -55, &u, "S7"));
    WT_EQ(gl_sm_dbm("900 MHz").unknown, 1);
    WT_EQ(gl_sm_dbm(NULL).unknown, 1);
    WT_EQ(s5.unknown, 0);
    /* The page prints it, in the cell's title, the canvas's label and
     * the report's line. */
    const char *p = page();
    WT_HAS(p, "    return \"S-meter, \" + (sc.unknown ? \"band unknown: 2.4 GHz scale\" : sc.band + \" scale\") +");
    WT_HAS(p, "           (sc.unknown ? \"; band unknown: 2.4 GHz scale\" : \"; \" + sc.band + \" scale\");");
    WT_HAS(p, "(sc.unknown ? \"band unknown: 2.4 GHz scale\" : sc.band + \" scale\") +\n"
              "                     \", S9 = \" + glyph.SM_BANDS[sc.band].s9 + \" dBm, \" + glyph.SM_DB +");
}

/* The mark list: no reading is R5's dash and no segment at all, lit or
 * unlit; one reading is the eleven segments and no tick; a window that
 * moved adds the two peak-hold ticks. The lit run is --tui-normal to S9
 * and --heat-3 past it, an unlit segment --rule. The absence with no
 * reading was seen red with the port's early return taken out (eleven
 * unlit segments were drawn under the dash), and the no-tick case with
 * hi > lo made hi >= lo (a flat window drew two ticks). */
static void test_sm_states(void) {
    gmarks_t g;
    smsc_t sc = gl_sm_dbm("2.4 GHz");
    gl_sm(0, 0, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    WT_EQ(gm_count(&g, "seg"), 0);
    WT_EQ(gm_count(&g, "off"), 0);
    /* No reading but a window given: still nothing lit, no tick. */
    gl_sm(0, 0, 72, 14, &sc, 1, -70, -40, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "seg") + gm_count(&g, "off") + gm_count(&g, "pklo") + gm_count(&g, "pkhi"), 0);
    /* One reading: the run alone. -62 is S6. */
    gl_sm(1, -62, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(g.n, 11);
    WT_EQ(gm_count(&g, "seg"), 6);
    WT_EQ(gm_count(&g, "off"), 5);
    WT_EQ(gm_count(&g, "pklo") + gm_count(&g, "pkhi"), 0);
    for (int i = 0; i < g.n; i++)
        WT_ASSERT(!strcmp(g.m[i].tok, i < 6 ? "--tui-normal" : "--rule"));
    /* A window of one value (lo == hi) is still the run alone. */
    gl_sm(1, -62, 72, 14, &sc, 1, -62, -62, &g);
    WT_EQ(gm_count(&g, "pklo") + gm_count(&g, "pkhi"), 0);
    /* The scale it is given none is the unknown-band row. */
    gl_sm(1, -62, 72, 14, NULL, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 6);
    /* Past S9 the run is the heat's peak, and only past it. */
    gl_sm(1, -30, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 10);
    for (int i = 0; i < g.n; i++)
        WT_ASSERT(!strcmp(g.m[i].tok, i < 9 ? "--tui-normal" : i < 10 ? "--heat-3" : "--rule"));
    gl_sm(1, -20, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 11);
    WT_EQ(gm_count(&g, "off"), 0);
    gl_sm(1, -47, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 9);
    for (int i = 0; i < g.n; i++) WT_ASSERT(strcmp(g.m[i].tok, "--heat-3") != 0);
    /* Clamped at both ends, drawn at the edge. */
    gl_sm(1, -130, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 1);
    gl_sm(1, 5, 72, 14, &sc, 0, 0, 0, &g);
    WT_EQ(gm_count(&g, "seg"), 11);
}

/* The geometry at the table's 72 by 14: whole-pixel segments 5 wide a
 * pixel apart, three at the S9 boundary, inside the canvas; and the
 * peak-hold ticks, which are what G2's line said about movement: the
 * window's least and greatest, each inside the segment that value
 * would light last, full height, in --ink, on the same band's row as
 * the run. Seen red with the knee's gap made the plain one. */
static void test_sm_geometry_and_ticks(void) {
    gmarks_t g;
    smsc_t sc = gl_sm_dbm("2.4 GHz");
    gl_sm(1, -62, 72, 14, &sc, 1, -70, -40, &g);
    WT_EQ(g.n, 13);
    for (int i = 0; i < 11; i++) {
        WT_ASSERT(near(g.m[i].w, 5));
        WT_ASSERT(near(g.m[i].x, i * 6 + (i >= 9 ? 2 : 0)));
        if (i) WT_ASSERT(near(g.m[i].x - (g.m[i - 1].x + g.m[i - 1].w), i == 9 ? 3 : 1));
    }
    WT_ASSERT(g.m[10].x + g.m[10].w <= 72);
    /* A lit segment is half the height and centred; an unlit one 2 px. */
    WT_ASSERT(near(g.m[0].y, 3.5) && near(g.m[0].h, 7));
    WT_ASSERT(near(g.m[10].y, 6) && near(g.m[10].h, 2));
    gmark_t lo = gm_get(&g, "pklo"), hi = gm_get(&g, "pkhi");
    WT_EQ(gm_count(&g, "pklo"), 1);
    WT_EQ(gm_count(&g, "pkhi"), 1);
    /* -70 is a sixth into S5 (-71..-65): the fifth segment, at 24. */
    WT_ASSERT(near(lo.x, 24));
    /* -40 is 7 of 10 dB into S9's segment (-47..-37): 48 + floor(3.5). */
    WT_ASSERT(near(hi.x, 51));
    WT_ASSERT(near(lo.y, 0) && near(lo.h, 14) && near(lo.w, 1));
    WT_ASSERT(near(hi.y, 0) && near(hi.h, 14) && near(hi.w, 1));
    WT_ASSERT(!strcmp(lo.tok, "--ink") && !strcmp(hi.tok, "--ink"));
    /* The same window on the 5 GHz row is 7 dB further up the face. */
    smsc_t s5 = gl_sm_dbm("5 GHz");
    gl_sm(1, -62, 72, 14, &s5, 1, -70, -40, &g);
    WT_EQ(gm_count(&g, "seg"), 7);
    WT_ASSERT(near(gm_get(&g, "pklo").x, 31));     /* S6 (-72..-66), 2 of 6 dB in */
    WT_ASSERT(near(gm_get(&g, "pkhi").x, 58));     /* +10 (-44..-34), 4 of 10 dB in */
    /* A tick at either clamp stays inside its segment, on the canvas. */
    WT_ASSERT(near(gl_sm_x(-130, &sc, 72), 0));
    WT_ASSERT(near(gl_sm_x(-95, &sc, 72), 0));
    WT_ASSERT(near(gl_sm_x(-20, &sc, 72), 66));
    WT_ASSERT(near(gl_sm_x(5, &sc, 72), 66));
    /* Wider, the segments grow and the gaps do not. */
    gl_sm(1, -62, 300, 18, &sc, 0, 0, 0, &g);
    WT_ASSERT(near(g.m[0].w, 26));
    WT_ASSERT(near(g.m[9].x - (g.m[8].x + g.m[8].w), 3));
    WT_ASSERT(g.m[10].x + g.m[10].w <= 300);
}

/* R10: in one grey the meter still reads. Lit and unlit are two kinds
 * of two heights, the S9 boundary is the wider gap, and the ticks are
 * the only marks of the full height. */
static void test_sm_reads_in_greyscale(void) {
    gmarks_t g;
    smsc_t sc = gl_sm_dbm("2.4 GHz");
    gl_sm(1, -30, 72, 14, &sc, 1, -80, -30, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "seg"), 10);
    WT_EQ(gm_count(&g, "off"), 1);
    WT_ASSERT(gm_get(&g, "seg").h > gm_get(&g, "off").h);
    WT_ASSERT(g.m[9].x - (g.m[8].x + g.m[8].w) > g.m[8].x - (g.m[7].x + g.m[7].w));
    WT_ASSERT(gm_get(&g, "pklo").h > gm_get(&g, "seg").h);
    WT_ASSERT(gm_get(&g, "pklo").x < gm_get(&g, "pkhi").x);
}

/* A strength that is not dBm has no S-units: GNSS C/N0 over 0 to 50
 * dB-Hz and ADS-B's RSSI over -50 to 0 dBFS are the same face in ten
 * equal segments with no second run, so no heat colour and no wider
 * gap. Seen red with the port's edge test made c > edge (a C/N0 on an
 * edge lit one segment fewer). */
static void test_sm_other_units(void) {
    gmarks_t g;
    smsc_t hz = gl_sm_scale(0, 50, 50 / 10.0, 10, 0);
    WT_EQ(hz.n, 10);
    WT_EQ(hz.knee, 10);
    WT_ASSERT(near(hz.edges[0], 0) && near(hz.edges[9], 45));
    WT_EQ(gl_sm_level(1, 23, &hz), 5);
    WT_EQ(gl_sm_level(1, 25, &hz), 6);
    WT_EQ(gl_sm_level(1, 24.99, &hz), 5);
    WT_EQ(gl_sm_level(1, 45, &hz), 10);
    WT_EQ(gl_sm_level(1, 50, &hz), 10);
    WT_EQ(gl_sm_level(1, 70, &hz), 10);
    WT_EQ(gl_sm_level(1, 0.1, &hz), 1);
    gl_sm(1, 50, 72, 14, &hz, 1, 18, 31, &g);
    WT_EQ(gm_count(&g, "seg"), 10);
    for (int i = 0; i < 10; i++) {
        WT_ASSERT(!strcmp(g.m[i].tok, "--tui-normal"));
        WT_ASSERT(near(g.m[i].w, 6));
        if (i) WT_ASSERT(near(g.m[i].x - (g.m[i - 1].x + g.m[i - 1].w), 1));
    }
    /* 18 is 3 of 5 into the fourth segment (15..20), 31 a fifth into
     * the seventh (30..35). */
    WT_ASSERT(near(gm_get(&g, "pklo").x, 3 * 7 + 3));
    WT_ASSERT(near(gm_get(&g, "pkhi").x, 6 * 7 + 1));
    gl_sm(0, 0, 72, 14, &hz, 0, 0, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    smsc_t fs = gl_sm_scale(-50, 0, 50 / 10.0, 10, 0);
    WT_EQ(fs.n, 10);
    WT_EQ(gl_sm_level(1, -50, &fs), 1);
    WT_EQ(gl_sm_level(1, -12.3, &fs), 8);
    WT_EQ(gl_sm_level(1, 0, &fs), 10);
    /* The page builds both from its own constants, and a satellite with
     * no C/N0 (or 0: not tracked) is no reading. */
    const char *p = page();
    WT_HAS(p, "  var SM_DBHZ = glyph.smScale(0, SPAN_DBHZ, SPAN_DBHZ / 10, 10, 0);");
    WT_HAS(p, "  var POLL_MS = 5000, SPAN_DBHZ = 50;");
    WT_HAS(p, "  var SM_DBFS = glyph.smScale(RSSI_LO, 0, -RSSI_LO / 10, 10, 0);");
    WT_HAS(p, "  var POLL_MS = 5000, ALT_SPAN = 45000, RSSI_LO = -50;");
}

/* The words: a legend's label for each segment, the scale said once
 * per table with every band's S9, and the report's character cells: a
 * token a segment, none with no reading. Seen red with the port's
 * cells returned for no reading (eleven unlit cells). */
static void test_sm_words_and_text(void) {
    smsc_t sc = gl_sm_dbm("");
    static const char *const LAB[11] = { "1", "2", "3", "4", "5", "6", "7", "8", "9", "+10", "+20" };
    for (int i = 0; i < sc.n; i++) {
        char l[8];
        gl_sm_label(&sc, i, l, sizeof(l));
        WT_ASSERT(!strcmp(l, LAB[i]));
    }
    char note[200];
    gl_sm_note(note, sizeof(note));
    WT_ASSERT(!strcmp(note, "S9 = -47 dBm at 2.4 GHz, -54 at 5 GHz, -56 at 6 GHz, 6 dB per S-unit, "
                            "by the band heard on; a display scale, not the IARU reference"));
    const char *c[GL_SM_EDGES];
    WT_EQ(gl_sm_cells(0, 0, &sc, c), 0);
    WT_EQ(gl_sm_cells(1, -30, &sc, c), 11);
    for (int i = 0; i < 11; i++)
        WT_ASSERT(!strcmp(c[i], i < 9 ? "--tui-normal" : i < 10 ? "--heat-3" : "--tui-dim"));
    WT_EQ(gl_sm_cells(1, -90, &sc, c), 11);
    WT_ASSERT(!strcmp(c[0], "--tui-normal") && !strcmp(c[1], "--tui-dim"));
    /* The same reading on the 6 GHz row lights more of the line. */
    smsc_t s6 = gl_sm_dbm("6 GHz");
    WT_EQ(gl_sm_cells(1, -55, &s6, c), 11);
    WT_ASSERT(!strcmp(c[8], "--tui-normal") && !strcmp(c[9], "--tui-dim"));
    WT_EQ(gl_sm_cells(1, -55, &sc, c), 11);
    WT_ASSERT(!strcmp(c[6], "--tui-normal") && !strcmp(c[7], "--tui-dim"));
    /* A window's range. */
    double p[4][2] = {{0, -70}, {60, -52}, {120, -81}, {180, -60}};
    double lo = 0, hi = 0;
    WT_EQ(gl_sm_range(p, 4, &lo, &hi), 1);
    WT_ASSERT(near(lo, -81) && near(hi, -52));
    WT_EQ(gl_sm_range(p, 0, &lo, &hi), 0);
}

/* The page carries the S-meter's JS whole, as the port above reads it,
 * and every place a signal's strength was a graphic now calls it: the
 * three DBM columns and the drawer's and Lookup card's block through
 * rf.js, the emitter report's line, the BLE drawer, and the GNSS and
 * ADS-B signal cells on their own units. G2's function stays in
 * glyph.js with no caller. Seen red with one character changed in
 * smLevel()'s edge test in web/ui/glyph.js (>= made >), and each
 * absence with its string put back into the page. */
static void test_sm_page_and_wiring(void) {
    const char *p = page();
    /* glyph.js: the face, the band table and every sm*() whole. */
    WT_HAS(p, "  var SM_DB = 6, SM_UNITS = 9, SM_OVER_DB = 10, SM_OVER_TOP = 27;\n"
              "  var SM_BANDS = {\n"
              "    \"2.4 GHz\": { mhz: 2442, s9: -47 },\n"
              "    \"5 GHz\": { mhz: 5500, s9: -54 },\n"
              "    \"6 GHz\": { mhz: 6535, s9: -56 }\n"
              "  };\n"
              "  var SM_DEFAULT = \"2.4 GHz\";\n");
    WT_HAS(p, "  function smScale(lo, hi, step, units, over) {\n"
              "    var e = [], i, v;\n"
              "    for (i = 0; i < units; i++) e.push(lo + i * step);\n"
              "    for (v = lo + (units - 1) * step + over; over > 0 && v < hi; v += over) e.push(v);\n"
              "    return { lo: lo, hi: hi, edges: e, knee: units, over: over, band: \"\", unknown: false };\n"
              "  }\n");
    WT_HAS(p, "  function smBand(ch, label) {\n"
              "    if (typeof label === \"string\" && Object.prototype.hasOwnProperty.call(SM_BANDS, label)) return label;\n"
              "    if (gnum(ch) && ch >= 1 && ch <= 14) return \"2.4 GHz\";\n"
              "    if (gnum(ch) && ch >= 32 && ch <= 177) return \"5 GHz\";\n"
              "    return \"\";\n"
              "  }\n"
              "  function smDbm(band) {\n"
              "    var known = typeof band === \"string\" && Object.prototype.hasOwnProperty.call(SM_BANDS, band);\n"
              "    var s9 = SM_BANDS[known ? band : SM_DEFAULT].s9;\n"
              "    var sc = smScale(s9 - (SM_UNITS - 1) * SM_DB, s9 + SM_OVER_TOP, SM_DB, SM_UNITS, SM_OVER_DB);\n"
              "    sc.band = known ? band : SM_DEFAULT;\n"
              "    sc.unknown = !known;\n"
              "    return sc;\n"
              "  }\n");
    WT_HAS(p, "  function smLevel(v, sc) {\n"
              "    if (!gnum(v)) return 0;\n"
              "    var c = v < sc.lo ? sc.lo : v > sc.hi ? sc.hi : v, n = 0;\n"
              "    for (var i = 0; i < sc.edges.length; i++) if (c >= sc.edges[i]) n++;\n"
              "    return n;\n"
              "  }\n"
              "  function smClamped(pts, sc) {\n"
              "    var n = 0;\n"
              "    for (var i = 0; pts && i < pts.length; i++)\n"
              "      if (pts[i][1] > sc.hi || pts[i][1] < sc.lo) n++;\n"
              "    return n;\n"
              "  }\n");
    WT_HAS(p, "  function smWord(v, sc) {\n"
              "    var n = smLevel(v, sc);\n"
              "    if (!n) return \"-\";\n"
              "    return n <= sc.knee ? \"S\" + n : \"S\" + sc.knee + \"+\" + (n - sc.knee) * sc.over;\n"
              "  }\n");
    WT_HAS(p, "  function smLabels(sc) {\n"
              "    var out = [];\n"
              "    for (var i = 0; i < sc.edges.length; i++)\n"
              "      out.push(i < sc.knee ? String(i + 1) : \"+\" + (i - sc.knee + 1) * sc.over);\n"
              "    return out;\n"
              "  }\n");
    WT_HAS(p, "  function smNote() {\n"
              "    var p = [];\n"
              "    for (var b in SM_BANDS)\n"
              "      if (Object.prototype.hasOwnProperty.call(SM_BANDS, b))\n"
              "        p.push((p.length ? \"\" : \"S9 = \") + SM_BANDS[b].s9 + (p.length ? \"\" : \" dBm\") + \" at \" + b);\n"
              "    return p.join(\", \") + \", \" + SM_DB + \" dB per S-unit, by the band heard on; \" +\n"
              "           \"a display scale, not the IARU reference\";\n"
              "  }\n");
    WT_HAS(p, "  function smRange(pts) {\n"
              "    var lo = null, hi = null;\n"
              "    for (var i = 0; pts && i < pts.length; i++) {\n"
              "      if (!gnum(pts[i][1])) continue;\n"
              "      if (lo === null || pts[i][1] < lo) lo = pts[i][1];\n"
              "      if (hi === null || pts[i][1] > hi) hi = pts[i][1];\n"
              "    }\n"
              "    return lo === null ? null : [lo, hi];\n"
              "  }\n");
    WT_HAS(p, "  var SM_GAP = 1, SM_KNEE = 3;\n"
              "  function smGeo(sc, w) {\n"
              "    var n = sc.edges.length, k = sc.knee < n ? SM_KNEE - SM_GAP : 0;\n"
              "    return { n: n, k: k, sw: Math.max(1, Math.floor((w - (n - 1) * SM_GAP - k) / n)) };\n"
              "  }\n"
              "  function smSegX(i, sc, ge) { return i * (ge.sw + SM_GAP) + (i >= sc.knee ? ge.k : 0); }\n");
    WT_HAS(p, "  function smX(v, sc, w) {\n"
              "    var ge = smGeo(sc, w), i = Math.max(0, smLevel(v, sc) - 1);\n"
              "    var c = v < sc.lo ? sc.lo : v > sc.hi ? sc.hi : v;\n"
              "    var top = i + 1 < ge.n ? sc.edges[i + 1] : sc.hi;\n"
              "    var f = top > sc.edges[i] ? Math.max(0, (c - sc.edges[i]) / (top - sc.edges[i])) : 0;\n"
              "    return smSegX(i, sc, ge) + Math.min(ge.sw - 1, Math.floor(f * ge.sw));\n"
              "  }\n");
    WT_HAS(p, "  function sm(v, opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, sc = opt.scale || smDbm(\"\"), i;\n"
              "    if (!gnum(v)) { m.push(dash(w, h)); return m; }\n"
              "    var ge = smGeo(sc, w), lit = smLevel(v, sc);\n"
              "    for (i = 0; i < ge.n; i++) {\n"
              "      if (i < lit)\n"
              "        m.push([\"seg\", smSegX(i, sc, ge), h * 0.25, ge.sw, h * 0.5,\n"
              "                i < sc.knee ? \"--tui-normal\" : \"--heat-3\"]);\n"
              "      else m.push([\"off\", smSegX(i, sc, ge), h / 2 - 1, ge.sw, 2, \"--rule\"]);\n"
              "    }\n"
              "    if (gnum(opt.lo) && gnum(opt.hi) && opt.hi > opt.lo) {\n"
              "      m.push([\"pklo\", smX(opt.lo, sc, w), 0, 1, h, \"--ink\"]);\n"
              "      m.push([\"pkhi\", smX(opt.hi, sc, w), 0, 1, h, \"--ink\"]);\n"
              "    }\n"
              "    return m;\n"
              "  }\n");
    WT_HAS(p, "  function smCells(v, sc) {\n");
    WT_HAS(p, "  function smCells(v, sc) {\n"
              "    var out = [], lit = smLevel(v, sc);\n"
              "    for (var i = 0; lit && i < sc.edges.length; i++)\n"
              "      out.push(i >= lit ? \"--tui-dim\" : i < sc.knee ? \"--tui-normal\" : \"--heat-3\");\n"
              "    return out;\n"
              "  }\n");
    WT_HAS(p, "           sm: sm, smScale: smScale, smDbm: smDbm, smBand: smBand, smLevel: smLevel,\n"
              "           smWord: smWord, smLabels: smLabels, smNote: smNote, smRange: smRange,\n"
              "           smClamped: smClamped, smCells: smCells, smX: smX, SM_BANDS: SM_BANDS,\n"
              "           SM_DB: SM_DB,\n");
    /* rf.js: the cell, the block, the generic meter, the legend. */
    WT_HAS(p, "  function smMarks(v, sc, r) {\n"
              "    return function (w, h) {\n"
              "      return glyph.sm(num(v) ? v : null, { w: w, h: h, scale: sc, lo: r ? r[0] : null,\n"
              "                                           hi: r ? r[1] : null });\n"
              "    };\n"
              "  }\n");
    WT_HAS(p, "  function scaleText(sc) {\n"
              "    return \"S-meter, \" + (sc.unknown ? \"band unknown: 2.4 GHz scale\" : sc.band + \" scale\") +\n"
              "           \", S9 = \" + glyph.SM_BANDS[sc.band].s9 + \" dBm\";\n"
              "  }\n");
    WT_HAS(p, "  function say(v, sc, r) {\n"
              "    if (!num(v)) return \"signal strength: no reading\";\n"
              "    return \"signal strength \" + glyph.smWord(v, sc) + \", \" + Math.round(v) + \" dBm\" +\n"
              "           (r && r[1] > r[0] ? \"; over the last hour from \" + glyph.smWord(r[0], sc) + \" to \" +\n"
              "                               glyph.smWord(r[1], sc) + \", \" + Math.round(r[0]) + \" to \" +\n"
              "                               Math.round(r[1]) + \" dBm\" : \"\") +\n"
              "           (sc.unknown ? \"; band unknown: 2.4 GHz scale\" : \"; \" + sc.band + \" scale\");\n"
              "  }\n");
    WT_HAS(p, "  function meter(c, v, o, words) {\n"
              "    var cv = el(\"canvas\", \"g2\");\n"
              "    cv.role = \"img\";\n"
              "    cv.ariaLabel = words;\n"
              "    c.appendChild(cv);\n"
              "    later(cv, smMarks(v, o.scale, num(o.lo) && num(o.hi) ? [o.lo, o.hi] : null));\n"
              "    return cv;\n"
              "  }\n");
    WT_HAS(p, "  function legend() {\n"
              "    var d = el(\"span\", \"smleg\"), sc = glyph.smDbm(\"\"), lab = glyph.smLabels(sc);\n"
              "    d.appendChild(el(\"span\", \"d-dim\", \"S \"));\n"
              "    for (var i = 0; i < lab.length; i++)\n"
              "      d.appendChild(el(\"span\", i < sc.knee ? \"d-normal\" : \"h3\",\n"
              "                       (i === sc.knee ? \" \" : \"\") + \"\\u2588\" + lab[i] + \" \"));\n"
              "    d.appendChild(el(\"span\", \"\", glyph.smNote() + \"; ticks: the hour's least and greatest\"));\n"
              "    return d;\n"
              "  }\n");
    WT_HAS(p, "  function cell(c, rf, dbm, ch) {\n"
              "    clear(c);\n"
              "    var p = pts(rf), last = p.length ? p[p.length - 1][1] : dbm;\n"
              "    var w = glyph.g2Words(last, rf ? rf.band : null, rf ? rf.trend : null);\n"
              "    var sc = glyph.smDbm(glyph.smBand(ch, rf ? rf.radio : null)), r = glyph.smRange(p);\n"
              "    var cv = el(\"canvas\", \"g2\");\n"
              "    cv.role = \"img\";\n"
              "    cv.ariaLabel = say(last, sc, r);\n"
              "    c.appendChild(cv);\n"
              "    if (num(last)) c.appendChild(el(\"span\", \"sms\", glyph.smWord(last, sc) + \" \"));\n"
              "    c.appendChild(el(\"span\", w.bold ? \"g2n near\" : \"g2n\", w.text));\n"
              "    if (w.near) c.appendChild(el(\"span\", \"g2e\", \" \" + w.near));\n"
              "    c.title = (rf ? rf.metric + \", 1 h, fine, n=\" + (num(rf.n) ? rf.n : 0) : \"no signal series\") +\n"
              "              \"; \" + scaleText(sc) + \"; \" + estText(rf);\n"
              "    later(cv, smMarks(last, sc, r));\n"
              "    return w.bold;\n"
              "  }\n");
    WT_HAS(p, "  function block(rf, mac, ch) {\n"
              "    var box = el(\"div\", \"g2b\");\n"
              "    box.appendChild(el(\"div\", \"label\", \"signal, the last hour\"));\n"
              "    if (!rf) {\n"
              "      box.appendChild(el(\"div\", \"sub\", \"no signal series: rf.rssi.* are the monitor radio's, \" +\n"
              "                         \"not shown under this scope, or this slothweb keeps no series\"));\n"
              "      return box;\n"
              "    }\n"
              "    var p = pts(rf), sp = span(rf), gw = glyph.win(p, sp.from, sp.to);\n"
              "    var sc = glyph.smDbm(glyph.smBand(ch, rf ? rf.radio : null)), r = glyph.smRange(p);\n"
              "    var scale = sc.lo + \" to \" + sc.hi + \" dBm\";\n"
              "    if (!p.length) {\n"
              "      box.appendChild(el(\"div\", \"sub\", glyph.caption({ source: rf.metric + \" \" + mac,\n"
              "        window: \"1 h\", tier: \"fine\", scale: scale,\n"
              "        n: 0, state: \"no data\" }) + \"; \" + estText(rf)));\n"
              "      return box;\n"
              "    }\n"
              "    var last = p[p.length - 1][1];\n"
              "    var cv = el(\"canvas\", \"smw\");\n"
              "    cv.role = \"img\";\n"
              "    cv.ariaLabel = say(last, sc, r);\n"
              "    box.appendChild(cv);\n"
              "    var w = glyph.g2Words(last, rf.band, rf.trend);\n"
              "    var cl = glyph.smClamped(p, sc);\n"
              "    var note = el(\"div\", \"sub\");\n"
              "    note.appendChild(el(\"span\", \"sms\", glyph.smWord(last, sc) + \" \"));\n"
              "    note.appendChild(el(\"span\", w.bold ? \"g2n near\" : \"g2n\", w.text + \" dBm\"));\n"
              "    note.appendChild(document.createTextNode((w.near ? \" \" + w.near : \"\") + \"; \" +\n"
              "      (r[1] > r[0] ? \"the hour \" + glyph.smWord(r[0], sc) + \" to \" + glyph.smWord(r[1], sc) +\n"
              "                     \", \" + Math.round(r[0]) + \" to \" + Math.round(r[1]) + \" dBm; \" : \"\") +\n"
              "      glyph.caption({ source: rf.metric + \" \" + mac, window: \"1 h\",\n"
              "        tier: \"fine\", scale: scale,\n"
              "        n: rf.n, state: gw.shrunk ? gw.text : \"\" }) +\n"
              "      (cl ? \", \" + cl + \" clamped\" : \"\") + \"; \" + scaleText(sc) +\n"
              "      \"; \" + estText(rf)));\n"
              "    box.appendChild(note);\n"
              "    box.appendChild(el(\"div\", \"sub\")).appendChild(legend());\n"
              "    later(cv, smMarks(last, sc, r));\n"
              "    return box;\n"
              "  }\n");
    WT_HAS(p, "  function keys() {\n"
              "    var k = document.querySelectorAll(\".smkey\");\n"
              "    for (var i = 0; i < k.length; i++) { clear(k[i]); k[i].appendChild(legend()); }\n"
              "  }\n"
              "\n"
              "  window.SlothRf = { init: function (h) { H = h; keys(); }, cell: cell, block: block, bullet: bullet,\n"
              "                     count: count, colMax: colMax, newMark: newMark, pts: pts,\n"
              "                     meter: meter, legend: legend };\n");
    /* gnss.js and adsb.js: the non-dBm meters. */
    WT_HAS(p, "  var SM_DBHZ = glyph.smScale(0, SPAN_DBHZ, SPAN_DBHZ / 10, 10, 0);\n"
              "  function sigCell(s) {\n"
              "    var sig = cell(\"c-sg\"), cn = num(s.cn0) && s.cn0 > 0 ? s.cn0 : null;\n"
              "    var r = cn === null ? null : glyph.smRange(s.points);\n"
              "    var words = cn === null ? \"C/N0: not tracked\"\n"
              "      : \"C/N0 \" + cn.toFixed(1) + \" dB-Hz on a 0 to \" + SPAN_DBHZ + \" dB-Hz meter\" +\n"
              "        (r && r[1] > r[0] ? \"; the row's last records \" + r[0].toFixed(1) + \" to \" + r[1].toFixed(1) : \"\");\n"
              "    sig.title = words;\n"
              "    if (window.SlothRf) window.SlothRf.meter(sig, cn, { scale: SM_DBHZ, lo: r ? r[0] : null, hi: r ? r[1] : null }, words);\n"
              "    return sig;\n"
              "  }\n");
    WT_HAS(p, "    r.appendChild(sigCell(s));\n");
    WT_HAS(p, "    ordered.forEach(function (s) { body.appendChild(row(s, now, j)); });\n");
    WT_HAS(p, "  var SM_DBFS = glyph.smScale(RSSI_LO, 0, -RSSI_LO / 10, 10, 0);\n"
              "  function sigCell(a) {\n"
              "    var sig = cell(\"c-sg\"), v = num(a.rssi) ? a.rssi : null;\n"
              "    var words = v === null ? \"RSSI: no reading\"\n"
              "      : \"RSSI \" + v.toFixed(1) + \" dBFS on a \" + RSSI_LO + \" to 0 dBFS meter\";\n"
              "    sig.title = words;\n"
              "    if (window.SlothRf) window.SlothRf.meter(sig, v, { scale: SM_DBFS }, words);\n"
              "    return sig;\n"
              "  }\n");
    WT_HAS(p, "    r.appendChild(sigCell(a));\n");
    /* frrs.js: the text meter and the band it reads on. */
    WT_HAS(p, "  var BAND = \"\";\n"
              "  function rssiSpark(s) {\n"
              "    var v = el(\"span\", \"v fr-spark\", \"\");\n"
              "    var cells = Array.isArray(s.cells) ? s.cells : [], i;\n"
              "    var sc = glyph.smDbm(BAND), tk = glyph.smCells(num(s.last_dbm) ? s.last_dbm : null, sc);\n"
              "    var sw = function (x) { return num(x) ? x + \" (\" + glyph.smWord(x, sc) + \")\" : \"-\"; };\n"
              "    var line = el(\"span\", \"fr-spark-g\", \"\");\n"
              "    for (i = 0; i < tk.length; i++)\n"
              "      line.appendChild(el(\"span\", SPARK_CLS[tk[i]] || \"d-normal\",\n"
              "                          (i === sc.knee ? \" \" : \"\") + SPARK[tk[i] === \"--tui-dim\" ? 1 : 8]));\n"
              "    if (!tk.length) line.appendChild(el(\"span\", \"d-dim\", SPARK[0]));\n"
              "    v.appendChild(line);\n"
              "    var span = num(s.from) && num(s.to) && s.to > s.from ? Math.round((s.to - s.from) / 3600) + \" h\" : \"24 h\";\n"
              "    v.appendChild(el(\"span\", \"d-bright\", \"  \" + glyph.smWord(num(s.last_dbm) ? s.last_dbm : null, sc) +\n"
              "                     \" · last \" + (num(s.last_dbm) ? s.last_dbm : \"-\") + \" dBm\" +\n"
              "                     \" · min \" + sw(s.min_dbm) + \" · max \" + sw(s.max_dbm) + \" dBm\"));\n"
              "    v.appendChild(el(\"span\", \"d-dim\",\n"
              "                     (num(s.last_t) && s.last_t > 0 ? \" · last at \" + H.shortStamp(s.last_t) : \"\") +\n"
              "                     \" · n=\" + (num(s.samples) ? s.samples : 0) + \" · \" + span + \" in \" + cells.length +\n"
              "                     \" cells · \" + (sc.unknown ? \"band unknown: 2.4 GHz scale\" : sc.band + \" scale\") +\n"
              "                     \", S9 = \" + glyph.SM_BANDS[sc.band].s9 + \" dBm, \" + glyph.SM_DB +\n"
              "                     \" dB per S-unit; a display scale, not the IARU reference\" +\n"
              "                     \" · a sloth gauge, not a calibrated measurement\" +\n"
              "                     (typeof s.history === \"string\" ? \" · the minute tier: \" + s.history : \"\")));\n"
              "    return v;\n"
              "  }\n");
    WT_HAS(p, "    BAND = e.kind === \"ble\" ? \"2.4 GHz\"\n"
              "         : r.bei && r.bei.band && typeof r.bei.band.v === \"string\" ? r.bei.band.v : \"\";\n");
    /* bledev.js: the drawer's meter, on the 2.4 GHz row. */
    WT_HAS(p, "  function rssiChart(pts) {\n"
              "    var c = $(\"bledev-rssi\"), sc = glyph.smDbm(\"2.4 GHz\"), r = glyph.smRange(pts);\n"
              "    var last = pts.length ? pts[pts.length - 1][1] : null;\n"
              "    glyph.paint(c, glyph.sm(last, { w: c.clientWidth, h: c.clientHeight, scale: sc,\n"
              "                                    lo: r ? r[0] : null, hi: r ? r[1] : null }), H.css);\n"
              "    var words = last === null ? \"no reading\"\n"
              "      : glyph.smWord(last, sc) + \" \" + Math.round(last) + \" dBm\" +\n"
              "        (r[1] > r[0] ? \", the window \" + glyph.smWord(r[0], sc) + \" to \" + glyph.smWord(r[1], sc) +\n"
              "                       \" (\" + Math.round(r[0]) + \" to \" + Math.round(r[1]) + \" dBm)\" : \"\");\n"
              "    c.ariaLabel = \"this address's signal strength: \" + words;\n"
              "    return words;\n"
              "  }\n");
    WT_HAS(p, "      var words = rssiChart(pts);\n"
              "      H.set(\"bledev-rssi-note\", pts.length\n"
              "        ? words + \"; rf.rssi.ble, \" + (r.win >= 86400 ? Math.round(r.win / 86400) + \" d\" : Math.round(r.win / 3600) + \" h\") + \", \" + tier +\n"
              "          \" tier, n=\" + pts.length + \"; ticks: the window's least and greatest; 2.4 GHz scale: \" + glyph.smNote()\n"
              "        : \"no data: no signal sample of this address in the window\");\n");
    /* The call sites app.js keeps: Devices and the clients pass the row's
     * "rf" (whose "radio" is the band), the AP table its channel too. */
    WT_HAS(p, "    SlothRf.cell(r.cells[\"c-sig\"], d.rf, num(d.signal) ? d.signal : null);");
    WT_HAS(p, "    SlothRf.cell(sg, a.rf, num(a.signal) ? a.signal : null, a.channel);");
    WT_HAS(p, "      SlothRf.cell(row.appendChild(el(\"span\", \"c-sig d-dim\")), d.rf, num(d.signal) ? d.signal : null);");
    WT_HAS(p, "      drf.appendChild(SlothRf.block(j.rf, mac));");
    WT_HAS(p, "        box.appendChild(SlothRf.block(j.rf, j.mac));");
    /* The row is the height it was and the meter the width G2 had; the
     * column is wider by the S reading the owner asked for beside it. */
    WT_HAS(p, "canvas.g2, .drow canvas.g2 { display: inline-block; vertical-align: middle; "
              "width: 72px; height: 14px; margin-right: 4px; border-radius: 0; }");
    WT_HAS(p, "canvas.smw { display: block; width: 100%; height: 18px; }");
    WT_HAS(p, "#bdrawer canvas.spark.bledev-rssi { height: 18px; }");
    WT_HAS(p, "{ k: \"sig\", label: \"dBm\", px: 196, min: 3, num: true, type: \"num\", srv: \"signal\", val: dv(\"signal\") },");
    WT_HAS(p, "{ k: \"sig\", label: \"dBm\", px: 196, min: 3, type: \"num\", srv: \"signal\", val: av(\"signal\") },");
    WT_HAS(p, "{ k: \"sig\", label: \"dBm\", px: 196, min: 3, type: \"num\", val: av(\"signal\") },");
    /* The scale is said once per table: a legend placeholder in each of
     * the three tables' caption lines, filled at init. */
    int keys = 0;
    for (const char *q = strstr(p, "<span class=\"smkey\"></span>"); q; q = strstr(q + 1, "<span class=\"smkey\"></span>")) keys++;
    WT_EQ(keys, 3);
    WT_HAS(p, "(C/N0 is dB-Hz, not dBm, so it has no S-units)");
    WT_HAS(p, "(the decoder's level against its own full scale, not dBm, so it has no S-units)");
    /* What the meter replaced is gone from the page, and g2 has no
     * caller left. */
    WT_HAS(p, "  function g2(pts, opt) {\n");
    WT_LACKS(p, "glyph.g2(");
    WT_LACKS(p, "gnss-bar");
    WT_LACKS(p, "adsb-bar");
    WT_LACKS(p, "el(\"canvas\", \"trail\")");
    WT_LACKS(p, "label: \"TRAIL\"");
    WT_LACKS(p, "RSSI_FLOOR");
    WT_LACKS(p, "glyph.level(lift(");
    WT_LACKS(p, "proxColor(proxBand(pts[i][1], E))");
}

/* ── the TUI forms (R12) ────────────────────────────────────────── */

/* R12: a glyph with no character-cell form is not added, so each of
 * the three names its TUI form in web/README.md. Seen red with the G5
 * row's form removed. */
static void test_every_glyph_names_its_tui_form(void) {
    FILE *f = fopen("web/README.md", "rb");
    WT_ASSERT(f != NULL);
    if (!f) return;
    static char doc[600000];
    size_t n = fread(doc, 1, sizeof(doc) - 1, f);
    fclose(f);
    doc[n] = '\0';
    WT_HAS(doc, "### The glyph layer");
    for (int r = 1; r <= 12; r++) {
        char want[16];
        snprintf(want, sizeof(want), "**R%d.", r);
        WT_HAS(doc, want);
    }
    WT_HAS(doc, "G1");
    WT_HAS(doc, "G5");
    WT_HAS(doc, "G6");
    /* Each glyph's TUI form, as R12 demands. */
    WT_HAS(doc, "draw_sparkline_at()");
    WT_HAS(doc, "`\xe2\x96\x81\xe2\x96\x82\xe2\x96\x83\xe2\x96\x84"
                "\xe2\x96\x85\xe2\x96\x86\xe2\x96\x87\xe2\x96\x88`");
    WT_HAS(doc, "\xe2\x96\xae");          /* G5's present cell */
    WT_HAS(doc, "\xe2\x96\x90\xe2\x96\x88");  /* G6's bullet */
    /* G2's row: the S-meter since the owner's ruling of 2026-11-11, its
     * character-cell form the report's, with sloth's own distance cell
     * for the words; the range sparkline's row kept and marked. Seen
     * red with the row removed. And the band table the README prints is
     * glyph.js's. */
    WT_HAS(doc, "| G2 S-meter (signal strength) |");
    WT_HAS(doc, "| G2 as first built: the range sparkline (superseded 2026-11-11;");
    WT_HAS(doc, "#### The S-meter (2026-11-11)");
    for (int i = 0; i < GL_SM_NBANDS; i++) {
        char row[96];
        snprintf(row, sizeof(row), "| %s%s | %d MHz | %d dBm | %d dBm | %d dBm |", GL_SM_BANDS[i].band,
                 i ? "" : " (and BLE)", (int)GL_SM_BANDS[i].mhz, GL_SM_BANDS[i].s9,
                 GL_SM_BANDS[i].s9 - (GL_SM_UNITS - 1) * GL_SM_DB, GL_SM_BANDS[i].s9 + GL_SM_OVER_TOP);
        WT_HAS(doc, row);
    }
    WT_HAS(doc, "`rf_dist_cell()`");
    /* V4: G8's row, its spec form named and its TUI half said to be
     * owed. Seen red with the row removed. */
    WT_HAS(doc, "| G8 chain timeline |");
    WT_HAS(doc, "`\xe2\x94\x81` for an incident's span and `\xe2\x97\x8f` where it began");
}

/* The V1 review's fixes, as the page wires them: the footer's drops
 * carries its number beside its glyph (R7: it has no /api/live figure
 * of its own), a per-bucket counter's words name the bucket, a scope
 * change starts the facts' and the multiples' scales again (R11 holds
 * a scale across refreshes, not across other data), an anomaly card
 * keeps its y-range by episode across the Overview's minute (R11) and
 * reads a window over an hour from the minute tier, and the footer's
 * glyph is painted again when "[" shows it. Each seen red with its
 * line taken out of the page. */
static void test_v1_review_wiring(void) {
    const char *p = page();
    WT_HAS(p, "drops <b id=\"f-drops\">-</b><canvas class=\"sg\" id=\"f-drops-g\"");
    WT_HAS(p, "      H.set(f.num, g && g.pts.length ? H.fmt(g.pts[g.pts.length - 1][1]) : \"-\");");
    WT_HAS(p, "    return f.perBucket && g && g.step > 0 ? f.unit + \" per \" + glyph.dur(g.step) : f.unit;");
    WT_HAS(p, "words: \"k-sensor-w\", scopes: [\"hybrid\"], unit: \"drops\", perBucket: true },");
    WT_HAS(p, "    if (S.scaleOf !== H.scope()) { S.scale = {}; S.scaleOf = H.scope(); }");
    WT_HAS(p, "      var mso = m.name + \"\\u0000\" + SCOPE;\n"
              "      if (A.mscaleOf !== mso) { A.mscale = null; A.mown = {}; A.mscaleOf = mso; }");
    WT_HAS(p, "      ANSC[sk] = glyph.scale(s.points, bd, ANSC[sk] || null);");
    WT_HAS(p, "        from: gw.from, to: gw.to, step: s.step, sens: sens, scale: ANSC[sk],");
    WT_HAS(p, "    var tier = win > 3600 && A.storeOn ? \"minute\" : \"fine\", st = tier === \"minute\" ? 60 : 10;");
    WT_HAS(p, "    if (e.key === \"[\" && window.SlothFacts) SlothFacts.paint();");
}

/* ── V3: G3, G7 and the air picture ─────────────────────────────── */

/* V3's JS, whole: G3, its values, G7 and its maximum, and the
 * painter's two horizon tints. Seen red with one character changed in
 * each (G3's "--heat-2", g3Vals' "max / G3_BANDS", g7's "Math.max(1,",
 * and the 0.35). */
static void test_the_page_carries_v3s_js(void) {
    const char *p = page();
    WT_HAS(p, "  var G3_BANDS = 2;\n"
              "  function g3(v, opt) {\n"
              "    var m = [], w = opt.w, h = opt.h, n = v ? v.length : 0, i, any = false;\n"
              "    var warm = opt.warm || [];\n"
              "    for (i = 0; i < n; i++) if (gnum(v[i]) || warm[i]) any = true;\n"
              "    if (!any) { m.push(dash(w, h)); return m; }\n"
              "    var cw = w / n;\n"
              "    for (i = 0; i < n; i++) {\n"
              "      var x = Math.floor(i * cw), cwi = Math.max(1, Math.ceil(cw)), a = v[i];\n"
              "      if (!gnum(a)) {\n"
              "        if (warm[i]) m.push([\"warm\", x, 0, cwi, h, \"--rule\"]);\n"
              "        continue;\n"
              "      }\n"
              "      if (!(a > 0)) { m.push([\"base\", x, h - 1, cwi, 1, \"--rule\"]); continue; }\n"
              "      var b1 = Math.min(1, a);\n"
              "      m.push([\"hz1\", x, h - h * b1, cwi, h * b1, \"--data\"]);\n"
              "      if (a > 1) {\n"
              "        var b2 = Math.min(1, a - 1);\n"
              "        m.push([\"hz2\", x, h - h * b2, cwi, h * b2, opt.hot ? \"--heat-2\" : \"--data\"]);\n"
              "      }\n"
              "      if (a > G3_BANDS) m.push([\"clip\", x, 0, cwi, 1, \"--ink\"]);\n"
              "    }\n"
              "    return m;\n"
              "  }\n");
    WT_HAS(p, "  function g3Vals(row, k, rate, max) {\n"
              "    var v = [], warm = [], i, sc = row && row.scale, z = !!(sc && sc.kind === \"z\");\n"
              "    var cells = (row && row.cells) || [];\n"
              "    for (i = 0; i < cells.length; i++) {\n"
              "      var c = cells[i];\n"
              "      warm.push(false);\n"
              "      if (z) {\n"
              "        var zi = row.z ? row.z[i] : null;\n"
              "        if (gnum(zi)) v.push(k > 0 ? Math.max(0, zi) / k : 0);\n"
              "        else { v.push(null); warm[i] = gnum(c); }\n"
              "      } else v.push(!gnum(c) ? null : max > 0 ? c * rate / (max / G3_BANDS) : 0);\n"
              "    }\n"
              "    return { v: v, warm: warm, hot: z };\n"
              "  }\n");
    WT_HAS(p, "  function g7Max(lanes) {\n"
              "    var max = 0;\n"
              "    for (var j = 0; lanes && j < lanes.length; j++)\n"
              "      for (var i = 0, c = lanes[j].counts || []; i < c.length; i++)\n"
              "        if (gnum(c[i]) && c[i] > max) max = c[i];\n"
              "    return max;\n"
              "  }\n");
    WT_HAS(p, "  function g7(lanes, opt) {\n"
              "    var m = [], w = opt.w, L = opt.lane, gp = opt.gap || 0, max = g7Max(lanes), i, j;\n"
              "    for (j = 0; lanes && j < lanes.length; j++) {\n"
              "      var c = lanes[j].counts || [], n = c.length, cw = n ? w / n : 0, y0 = j * (L + gp);\n"
              "      for (i = 0; i < n; i++) {\n"
              "        if (!gnum(c[i]) || !(c[i] > 0)) continue;\n"
              "        var th = Math.max(1, L * c[i] / max);\n"
              "        m.push([\"tick\", Math.floor(i * cw), y0 + L - th, Math.max(1, Math.ceil(cw) - (cw > 3 ? 1 : 0)),\n"
              "                th, lanes[j].token]);\n"
              "      }\n"
              "      var sp = lanes[j].spans || [];\n"
              "      for (i = 0; n && i < sp.length; i++) {\n"
              "        var a = sp[i][0] < 0 ? 0 : sp[i][0], b = sp[i][1] > n - 1 ? n - 1 : sp[i][1];\n"
              "        if (b < a) continue;\n"
              "        m.push([\"span\", Math.floor(a * cw), y0 + L, Math.max(1, Math.ceil((b - a + 1) * cw)), 1,\n"
              "                lanes[j].spanToken || \"--sev-crit\"]);\n"
              "      }\n"
              "    }\n"
              "    var sm = opt.marks || [];\n"
              "    for (i = 0; i < sm.length; i++) if (gnum(sm[i])) m.push([\"session\", sm[i], 0, 2, opt.h, \"--ink\"]);\n"
              "    if (!m.length) m.push(dash(w, opt.h));\n"
              "    return m;\n"
              "  }\n");
    WT_HAS(p, "      } else if (k === \"hz1\" || k === \"hz2\") {\n"
              "        g.globalAlpha = k === \"hz1\" ? 0.35 : 0.7;");
}

/* G3's states (§5 G3, R5): nothing observed is the dash; a column
 * nothing was observed in draws nothing; observed and quiet is a 1 px
 * --rule base; warming a --rule cell the strip's height; under one band
 * the first band alone at its share of the height; between one and two
 * the first band full and the second at its share; past two both full
 * and a clip mark along the top. Seen red with the base mark taken out
 * of the port (a quiet column and an unobserved one drew alike), with
 * the clip mark's test moved to a > 1, and, for the column that draws
 * nothing, with the port pushing a gap mark there. */
static void test_g3_states(void) {
    gmarks_t g;
    double v0[3] = { 0, 0, 0 };
    int no[3] = { 0, 0, 0 };
    gl_g3(v0, no, NULL, 3, 90, 16, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    double v[6] = { 0, 0, 0, 0.5, 1.5, 2.5 };
    int has[6] = { 0, 0, 1, 1, 1, 1 };
    int warm[6] = { 0, 1, 0, 0, 0, 0 };
    gl_g3(v, has, warm, 6, 60, 16, 0, &g);
    WT_EQ(gm_count(&g, "dash"), 0);
    WT_EQ(gm_count(&g, "warm"), 1);
    WT_ASSERT(near(gm_get(&g, "warm").x, 10) && near(gm_get(&g, "warm").h, 16));
    WT_ASSERT(!strcmp(gm_get(&g, "warm").tok, "--rule"));
    WT_EQ(gm_count(&g, "base"), 1);
    WT_ASSERT(near(gm_get(&g, "base").x, 20) && near(gm_get(&g, "base").y, 15) &&
              near(gm_get(&g, "base").h, 1));
    WT_EQ(gm_count(&g, "hz1"), 3);
    WT_ASSERT(near(gm_get(&g, "hz1").x, 30) && near(gm_get(&g, "hz1").h, 8) &&
              near(gm_get(&g, "hz1").y, 8));
    WT_EQ(gm_count(&g, "hz2"), 2);
    WT_ASSERT(near(gm_get(&g, "hz2").x, 40) && near(gm_get(&g, "hz2").h, 8));
    WT_ASSERT(near(gm_last(&g, "hz2").h, 16));
    WT_EQ(gm_count(&g, "clip"), 1);
    WT_ASSERT(near(gm_get(&g, "clip").x, 50) && near(gm_get(&g, "clip").y, 0));
    /* Nothing for the column nothing was observed in. */
    for (int i = 0; i < g.n; i++) WT_ASSERT(!near(g.m[i].x, 0));
}

/* F8 and R1: out of band is the heat ramp and only on a z scale, and
 * only the second band. The out-of-band case seen to fail when the band
 * is widened (§9): z 3 at k 2 is in the second band; at k 4 it is not
 * (that absence seen red with the second band's test moved to a > 0.5).
 * Seen red too with the port's second band always --heat-2. */
static void test_g3_out_of_band_only_on_z(void) {
    double cells[1] = { 12 }, z[1] = { 3 }, v[1];
    int hc[1] = { 1 }, hz[1] = { 1 }, has[1], warm[1];
    gmarks_t g;
    int hot = gl_g3_vals(cells, hc, 1, z, hz, 1, 2.0, 1, 0, v, has, warm);
    WT_ASSERT(hot && has[0] && near(v[0], 1.5));
    gl_g3(v, has, warm, 1, 10, 16, hot, &g);
    WT_EQ(gm_count(&g, "hz2"), 1);
    WT_ASSERT(!strcmp(gm_get(&g, "hz2").tok, "--heat-2"));
    WT_ASSERT(!strcmp(gm_get(&g, "hz1").tok, "--data"));
    hot = gl_g3_vals(cells, hc, 1, z, hz, 1, 4.0, 1, 0, v, has, warm);
    gl_g3(v, has, warm, 1, 10, 16, hot, &g);
    WT_EQ(gm_count(&g, "hz2"), 0);
    /* An absolute scale's second band is the same ink as its first. */
    hot = gl_g3_vals(cells, hc, 0, NULL, NULL, 1, 2.0, 1, 16, v, has, warm);
    WT_ASSERT(!hot && near(v[0], 1.5));
    gl_g3(v, has, warm, 1, 10, 16, hot, &g);
    WT_ASSERT(!strcmp(gm_get(&g, "hz2").tok, "--data"));
}

/* G3's values (F8): an absolute scale is the channel's own max in two
 * halves, a counter's cell at its count per minute; a z scale's second
 * band begins at k, a channel quieter than normal is flat (0, not
 * negative), and a z the baseline could not give is warming where the
 * cell has a value and nothing where it has none. Seen red with the
 * rate left out (40 frames in 80 s read 1.33, not 1.0) and with the
 * negative z let through. */
static void test_g3_values(void) {
    double cells[4] = { 5, 7.5, 0, 40 }, v[4];
    int hc[4] = { 1, 1, 0, 1 }, has[4], warm[4];
    gl_g3_vals(cells, hc, 0, NULL, NULL, 3, 2.0, 1, 10, v, has, warm);
    WT_ASSERT(has[0] && near(v[0], 1.0));
    WT_ASSERT(has[1] && near(v[1], 1.5));
    WT_ASSERT(!has[2] && !warm[2]);
    gl_g3_vals(cells + 3, hc + 3, 0, NULL, NULL, 1, 2.0, 60.0 / 80, 60, v, has, warm);
    WT_ASSERT(has[0] && near(v[0], 1.0));
    double z[4] = { -2, 0, 0, 5 };
    int hz[4] = { 1, 0, 0, 1 };
    gl_g3_vals(cells, hc, 1, z, hz, 4, 2.5, 1, 0, v, has, warm);
    WT_ASSERT(has[0] && near(v[0], 0));
    WT_ASSERT(!has[1] && warm[1]);
    WT_ASSERT(!has[2] && !warm[2]);
    WT_ASSERT(has[3] && near(v[3], 2.0));
    /* The JS says the same: z rows hot, absolute not. */
    const char *p = page();
    WT_HAS(p, "        if (gnum(zi)) v.push(k > 0 ? Math.max(0, zi) / k : 0);");
}

/* R10: with every token one grey, a strip's bands, base, warming cell
 * and clip still differ by kind and position. */
static void test_g3_reads_in_greyscale(void) {
    double v[4] = { 0, 0, 0.5, 2.5 };
    int has[4] = { 0, 1, 1, 1 }, warm[4] = { 1, 0, 0, 0 };
    gmarks_t g;
    gl_g3(v, has, warm, 4, 40, 16, 1, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_ASSERT(near(gm_get(&g, "warm").h, 16));
    WT_ASSERT(near(gm_get(&g, "base").h, 1) && near(gm_get(&g, "base").y, 15));
    WT_ASSERT(near(gm_get(&g, "hz1").h, 8));
    WT_EQ(gm_count(&g, "hz2"), 1);
    WT_ASSERT(near(gm_get(&g, "clip").y, 0));
}

/* G7 (F12): one scale for every lane, the tallest column of any lane at
 * the lane's height, so one device first seen beside thirty alerts is a
 * 1 px tick and not as tall as they are; zero draws nothing; a flood
 * span underlines its columns; a session is full height in --ink; no
 * event at all is the dash. Seen red with each lane scaled to its own
 * largest (the device lane's tick at full height), and with the 1 px
 * floor taken out (the device tick 0.8 px). */
static void test_g7_rug(void) {
    glane_t ln[2];
    memset(ln, 0, sizeof(ln));
    ln[0].n = 10; ln[0].tok = "--tui-normal"; ln[0].c[3] = 1; ln[0].span[0] = 1; ln[0].span[1] = 0;
    ln[1].n = 10; ln[1].tok = "--sev-warn"; ln[1].c[3] = 30; ln[1].c[7] = 15;
    ln[1].span[0] = 6; ln[1].span[1] = 8;
    double marks[1] = { 55 };
    gmarks_t g;
    gl_g7(ln, 2, 100, 72, 24, 8, marks, 1, &g);
    WT_EQ(gl_g7_max(ln, 2), 30);
    WT_EQ(gm_count(&g, "tick"), 3);
    gmark_t d = gm_get(&g, "tick");
    WT_ASSERT(!strcmp(d.tok, "--tui-normal") && near(d.h, 1) && near(d.y, 23) && near(d.x, 30));
    gmark_t a = g.m[1];
    WT_ASSERT(!strcmp(a.kind, "tick") && !strcmp(a.tok, "--sev-warn") && near(a.h, 24) && near(a.y, 32));
    WT_ASSERT(near(g.m[2].h, 12));
    WT_EQ(gm_count(&g, "span"), 1);
    WT_ASSERT(near(gm_get(&g, "span").x, 60) && near(gm_get(&g, "span").w, 30) &&
              near(gm_get(&g, "span").y, 56));
    WT_EQ(gm_count(&g, "session"), 1);
    WT_ASSERT(near(gm_get(&g, "session").h, 72) && !strcmp(gm_get(&g, "session").tok, "--ink"));
    WT_EQ(gm_count(&g, "dash"), 0);
    glane_t none[1];
    memset(none, 0, sizeof(none));
    none[0].n = 10; none[0].tok = "--tui-normal"; none[0].span[0] = 1;
    gl_g7(none, 1, 100, 72, 24, 8, NULL, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    /* R10: in one grey, the lanes still differ by position. */
    gl_g7(ln, 2, 100, 72, 24, 8, marks, 1, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_ASSERT(g.m[0].y < 24 && g.m[1].y >= 32);
}

/* §6.3 and §6.7 as the page wires them: the channels panel's horizon is
 * the default and the stacked grid one control away, both fetched so
 * the control redraws without asking again; R11 per channel, reset with
 * the metric or the scope; the drill-in beside the strips; the emitters
 * nearest first with the SSID count as squares; the chains rug that
 * collapses with "0 deauth in the window"; the clients panel's rows
 * from src:probe nearest first; History's strip as G7 with its caption.
 * The two absences seen red with the old "+N ssids" line put back and
 * with a deauthChart() stub added; the rest are the page's own lines. */
static void test_v3_wiring(void) {
    const char *p = page();
    WT_HAS(p, "<option value=\"horizon\" selected>against normal (horizon)</option>");
    WT_HAS(p, "<option value=\"mix\">who transmits (stacked)</option>");
    WT_HAS(p, "    if (hz) horizonGrid(); else mixGrid();");
    WT_HAS(p, "  $(\"w-grid\").addEventListener(\"change\", function () { if (view === \"wifi\") channelGrid(); });");
    WT_HAS(p, "    if (WF.g3of !== of) { WF.g3max = {}; WF.g3of = of; }");
    WT_HAS(p, "        max = o.g3max[r.key] = Math.max(o.g3max[r.key] || 0, num(sc.max) ? sc.max : 0);");
    WT_HAS(p, "      var gv = glyph.g3Vals(row, o.k, rate, max);");
    WT_HAS(p, "    var rate = hz && hz.kind === \"counter\" && hz.col_s > 0 ? 60 / hz.col_s : 1;");
    WT_HAS(p, "    SlothAir.drill($(\"w-drill\"), rows, WF.cur && WF.geo && WF.cur.c < WF.geo.cols ? WF.cur.c : -1);");
    WT_HAS(p, "        g.fillStyle = H.txColor(H.txOf(m[e]));");
    WT_HAS(p, "<option value=\"signal\" selected>signal (near first)</option>");
    WT_HAS(p, "  var AP_SORTS = { \"signal\": 1, \"last\": 1, \"ssids\": 1, \"karma\": 1, \"bssid\": 1 };");
    WT_HAS(p, "\" \" + \"\\u25aa\".repeat(Math.min(8, a.ssid_count)) + (a.ssid_count > 8 ? \"+\" : \"\"));");
    WT_LACKS(p, "\" ssids\"));");
    WT_HAS(p, "    c.hidden = !rows.length;\n    if (!rows.length) return { max: 0, lanes: 0, busy: 0 };");
    WT_HAS(p, "n: j.cols, state: nb ? \"\" : \"0 deauth in the window\" }));");
    WT_HAS(p, "      var rg = SlothAir.rug($(\"w-deauth\"), j), nb = rg.busy;");
    WT_LACKS(p, "function deauthChart(");
    WT_HAS(p, "    var q = \"src:probe seen:<\" + seenWord(r.win);");
    WT_HAS(p, "    getJSON(\"/api/devices?limit=\" + CL_PAGE + \"&sort=signal&q=\" + encodeURIComponent(q))");
    WT_HAS(p, "      SlothRf.cell(row.appendChild(el(\"span\", \"c-sig d-dim\")), d.rf, num(d.signal) ? d.signal : null);");
    WT_HAS(p, "      drawStrip(cv, d.presence, 144, glyph.firstCell(d.first_seen, WF.clFrom, 600, 144), WF.clFrom, 600);");
    WT_HAS(p, "id: \"wclients\"");
    WT_HAS(p, "    glyph.paint(c, glyph.g7(lanes, { w: W, h: Hh, lane: L, gap: HS_GAP, marks: marks }), tok);");
    WT_HAS(p, "scale: \"one scale, tallest \" + fmt(glyph.g7Max(lanes)) +");
    WT_HAS(p, "<div class=\"sub\" id=\"h-strip-note\"></div>");
    WT_HAS(p, "    if (view === \"wifi\") wifi();\n  });");
    /* The four panels in §6.3's order. */
    const char *a = strstr(p, "<canvas class=\"wfall\" id=\"w-heat\"");
    const char *b = strstr(p, "<div class=\"aprow dhead\" id=\"w-aps-head\">");
    const char *c = strstr(p, "<canvas class=\"rug\" id=\"w-deauth\"");
    const char *d = strstr(p, "<canvas class=\"chart\" id=\"w-probe\"");
    const char *e = strstr(p, "<div class=\"dhead\" id=\"w-cl-head\">");
    WT_ASSERT(a && b && c && d && e && a < b && b < c && c < d && d < e);
}

/* The V3 review's fixes, as the page wires them. R3: each G3 strip is
 * on its own scale, so it prints its top beside its key (z for a z
 * strip); the key alone, as before, seen red by putting the old
 * `r.key + (z ? " z" : "")` label back. R4: when the columns any
 * channel was observed in span under a tenth of the window, every strip
 * draws those columns only, through glyph.win()'s rule and words, and a
 * pick maps back through the first column drawn; seen red with the
 * shrink's assignment taken out and with gridPick's c0 offset removed.
 * F16: the probe-client chart is hidden with no points (seen red with
 * the hide removed). A focused clients row opens on Enter like every
 * other row (seen red with clrow left out of the list). */
static void test_v3_review_wiring(void) {
    const char *p = page();
    WT_HAS(p, "      tops.push(sc && sc.kind === \"z\" ? \"z\" : sc ? H.fmt(max) : \"\");");
    WT_HAS(p, "      g.fillText(tops[j], (LABEL - 4) * dpr, ty);");
    WT_HAS(p, "  var ROW = 18, LABEL = 76;");
    WT_LACKS(p, "r.key + (z ? \" z\" : \"\")");
    WT_HAS(p, "      var wn = glyph.win([[hz.from + lo * hz.col_s, 0], [hz.from + (hi + 1) * hz.col_s, 0]],\n"
              "                         hz.from, hz.to);\n"
              "      if (wn.shrunk) { c0 = lo; c1 = hi; out.win = wn; }");
    WT_HAS(p, "      if (row) row = { scale: sc, cells: (row.cells || []).slice(c0, c1 + 1),\n"
              "                       z: row.z ? row.z.slice(c0, c1 + 1) : null };");
    WT_HAS(p, "    var col = Math.floor((px - geo.x0) / geo.cw) + (geo.c0 || 0), row = Math.floor(py / geo.rh);");
    WT_HAS(p, "state: !rows.length ? \"no data\" : [o.win ? o.win.text : \"\",");
    WT_HAS(p, "      $(\"w-probe\").hidden = !s.points.length;\n"
              "      if (s.points.length) draw($(\"w-probe\"), s.points,");
    WT_HAS(p, "t.classList.contains(\"clrow\") || t.classList.contains(\"go\"))) {");
    WT_HAS(p, "    txColor: txColor, txOf: txOf, fmt: fmt });");
}


/* ── V4: G8 and the Flows matrix ────────────────────────────────── */

/* V4's JS, whole: G8, its maximum, its height and its lanes, and the
 * matrix with its number and its maximum; and the painter's words.
 * Seen red with one character changed in each (g8's "L - 2 - th",
 * g8Lanes' "b >= n - 1", mxNum's "1e4", mx's "--sev-crit" bar, and the
 * painter's typeof m[6]). */
static void test_the_page_carries_v4s_js(void) {
    const char *p = page();
    WT_HAS(p, "  var G8_STAGES = [\"deauth\", \"twin\", \"assoc\", \"karma\"];\n"
              "  var G8_WORDS = 12;\n"
              "  // A 10 px monospace character's advance, near enough to lay words out.\n"
              "  var G8_CH = 6;\n"
              "  var SEV_TOKEN = [\"--sev-low\", \"--sev-warn\", \"--sev-crit\"];\n"
              "  function g8Max(lanes, prev) {\n"
              "    var max = gnum(prev) && prev > 0 ? prev : 0;\n"
              "    for (var j = 0; lanes && j < lanes.length; j++)\n"
              "      for (var i = 0, c = lanes[j].counts || []; i < c.length; i++)\n"
              "        if (gnum(c[i]) && c[i] > max) max = c[i];\n"
              "    return max;\n"
              "  }\n");
    WT_HAS(p, "  function g8(lanes, links, labels, opt) {\n"
              "    var m = [], L = opt.lane, gx = opt.gutter || 0, n = opt.ncol > 0 ? opt.ncol : 1, i, j;\n"
              "    var nl = lanes ? lanes.length : 0, gw = Math.max(1, opt.w - gx), cw = gw / n;\n"
              "    if (!nl) { m.push(dash(opt.w, L)); return m; }\n"
              "    var max = g8Max(lanes, opt.max), X = function (c) { return gx + c * cw; };\n"
              "    for (j = 0; j < nl; j++) {\n"
              "      var y0 = j * L, mid = y0 + L / 2, ln = lanes[j];\n"
              "      m.push([\"axis\", gx, mid, gw, 1, \"--rule\"]);\n"
              "      if (labels && labels[j]) m.push([\"label\", 2, mid, gx - 4, 10, labels[j].token, labels[j].text]);\n"
              "      var c = ln.counts || [];\n"
              "      for (i = 0; max > 0 && i < c.length && i < n; i++) {\n"
              "        if (!gnum(c[i]) || !(c[i] > 0)) continue;\n"
              "        var th = Math.max(1, (L - 4) * c[i] / max);\n"
              "        m.push([\"tick\", Math.floor(X(i)), y0 + L - 2 - th, Math.max(1, Math.ceil(cw) - (cw > 3 ? 1 : 0)),\n"
              "                th, \"--tui-normal\"]);\n"
              "      }\n"
              "      var b = ln.bars || [];\n"
              "      for (i = 0; i < b.length; i++) {\n"
              "        var a0 = b[i][0], b0 = b[i][1];\n"
              "        if (!gnum(a0) || !gnum(b0) || b0 < 0 || a0 > n - 1 || b0 < a0) continue;\n"
              "        var tok = SEV_TOKEN[b[i][2] >= 0 && b[i][2] <= 2 ? b[i][2] : 1];\n"
              "        var xa = X(Math.max(0, a0)), xb = X(Math.min(n - 1, b0) + 1);\n"
              "        m.push([\"bar\", xa, mid - 2, Math.max(1, xb - xa), 4, tok]);\n"
              "        if (a0 >= 0) m.push([\"dot\", xa, mid, 2.5, 2.5, tok]);\n"
              "        if (!b[i][3] && b0 <= n - 1) m.push([\"dot\", xb, mid, 2.5, 2.5, tok]);\n"
              "      }\n"
              "    }\n"
              "    // The words in column order, each after the one before it (the\n"
              "    // taint and the attribution it settles are often one record, so\n"
              "    // two connectors share a column and their words would overprint),\n"
              "    // and drawn back from the right edge rather than past it.\n"
              "    var wy = nl * L, wx = -1, ks = [];\n"
              "    for (i = 0; links && i < links.length; i++) {\n"
              "      var k = links[i];\n"
              "      if (!gnum(k.col) || k.col < 0 || k.col > n - 1 || !(k.top >= 0 && k.top < nl)) continue;\n"
              "      ks.push(k);\n"
              "    }\n"
              "    ks.sort(function (a, b) { return a.col - b.col; });\n"
              "    for (i = 0; i < ks.length; i++) {\n"
              "      var lx = Math.floor(X(ks[i].col) + cw / 2), ly = ks[i].top * L + L / 2;\n"
              "      var tw = String(ks[i].word).length * G8_CH, tx = Math.max(lx + 3, wx + G8_CH);\n"
              "      if (tx + tw > opt.w) tx = Math.max(wx + G8_CH, opt.w - tw);\n"
              "      m.push([\"link\", lx, ly, 1, wy + 2 - ly, \"--faint\"]);\n"
              "      m.push([\"word\", tx, wy + G8_WORDS / 2, Math.max(1, opt.w - tx), 10, \"--muted\", ks[i].word]);\n"
              "      wx = tx + tw;\n"
              "    }\n"
              "    return m;\n"
              "  }\n");
    WT_HAS(p, "  function g8Height(nl, links, lane) {\n"
              "    return nl * lane + (links && links.length ? G8_WORDS + 2 : 0);\n"
              "  }\n");
    WT_HAS(p, "  function g8Lanes(row, j) {\n"
              "    var cs = j.col_s > 0 ? j.col_s : 1, n = j.cols > 0 ? j.cols : 0, from = j.from;\n"
              "    var col = function (t) { return Math.floor((t - from) / cs); };\n"
              "    var bars = function (list) {\n"
              "      return (list || []).map(function (e) {\n"
              "        var b = col(e[1]);\n"
              "        return [col(e[0]), b, e[2], b >= n - 1 ? 1 : 0];\n"
              "      });\n"
              "    };\n"
              "    // A lane's words: its name, the highest severity its bars reached\n"
              "    // (R10: the word beside the colour), and \"none\" when it has nothing,\n"
              "    // in --muted, so an empty lane reads as not yet seen.\n"
              "    var words = function (name, list, have, extra) {\n"
              "      var hi = -1;\n"
              "      for (var i = 0; list && i < list.length; i++) if (list[i][2] > hi) hi = list[i][2];\n"
              "      var sv = hi === 0 ? \" low\" : hi === 1 ? \" warn\" : hi === 2 ? \" CRIT\" : \"\";\n"
              "      return { text: name + (have ? sv + (extra || \"\") : \" none\"), token: have ? \"--ink\" : \"--muted\" };\n"
              "    };\n"
              "    var dc = (row.cells || []).map(function (v) { return gnum(v) ? v : 0; });\n"
              "    var ac = row.assoc || [];\n"
              "    var links = [], conf = null;\n"
              "    (row.links || []).forEach(function (k) {\n"
              "      if (gnum(k.tainted)) links.push({ col: col(k.tainted), top: 0, word: \"tainted \\u2191 5 s\" });\n"
              "      if (gnum(k.attributed)) links.push({ col: col(k.attributed), top: 1, word: \"attributed \\u2191\" });\n"
              "      if (gnum(k.confidence)) conf = k.confidence;\n"
              "    });\n"
              "    var nd = 0, na = 0;\n"
              "    for (var i = 0; i < dc.length; i++) if (dc[i] > 0) nd++;\n"
              "    for (i = 0; i < ac.length; i++) if (gnum(ac[i]) && ac[i] > 0) na++;\n"
              "    // An association is a stage only on a BSSID accused or caught\n"
              "    // luring (a twin or a karma row): elsewhere it is a client joining.\n"
              "    var lure = (row.twin || []).length + (row.karma || []).length > 0;\n"
              "    var stages = (nd || (row.floods || []).length ? 1 : 0) + ((row.twin || []).length ? 1 : 0) +\n"
              "                 (na && lure ? 1 : 0) + ((row.karma || []).length ? 1 : 0);\n"
              "    var fl = row.floods || [], tw = row.twin || [], ka = row.karma || [];\n"
              "    return {\n"
              "      lanes: [{ counts: dc, bars: bars(fl) }, { counts: null, bars: bars(tw) },\n"
              "              { counts: ac, bars: null }, { counts: null, bars: bars(ka) }],\n"
              "      labels: [words(\"deauth\", fl, nd > 0 || fl.length > 0),\n"
              "               words(\"twin\", tw, tw.length > 0, conf !== null ? \" \" + conf + \"%\" : \"\"),\n"
              "               words(\"assoc\", null, na > 0), words(\"karma\", ka, ka.length > 0)],\n"
              "      links: links, stages: stages\n"
              "    };\n"
              "  }\n");
    WT_HAS(p, "  var MX_LETTER = { ssh: \"S\", rdp: \"R\", smb: \"M\", snmp: \"N\", bgp: \"B\", ldap: \"L\", kerb: \"K\" };\n"
              "  function mxNum(v) {\n"
              "    if (!gnum(v) || v < 0) return \"-\";\n"
              "    if (v < 1000) return String(Math.round(v));\n"
              "    if (v < 1e6) return (v < 1e4 ? (v / 1e3).toFixed(1) : String(Math.round(v / 1e3))) + \"k\";\n"
              "    return (v < 1e7 ? (v / 1e6).toFixed(1) : String(Math.round(v / 1e6))) + \"M\";\n"
              "  }\n");
    WT_HAS(p, "  function mxMax(mx, prev) {\n"
              "    var max = gnum(prev) && prev > 0 ? prev : 0;\n"
              "    for (var i = 0, c = (mx && mx.cells) || []; i < c.length; i++)\n"
              "      if (gnum(c[i].total) && c[i].total > max) max = c[i].total;\n"
              "    return max;\n"
              "  }\n");
    WT_HAS(p, "  function mx(m, opt) {\n"
              "    var out = [], x0 = opt.x0, y0 = opt.y0, cw = opt.cw, ch = opt.ch, i;\n"
              "    var srcs = (m && m.srcs) || [], dsts = (m && m.dsts) || [], cells = (m && m.cells) || [];\n"
              "    var W = x0 + dsts.length * cw, Hh = y0 + srcs.length * ch;\n"
              "    if (!cells.length) { out.push(dash(Math.max(W, 60), ch)); return out; }\n"
              "    var own = Object.prototype.hasOwnProperty, max = mxMax(m, opt.max);\n"
              "    for (i = 1; i < srcs.length; i++)\n"
              "      if (srcs[i].group !== srcs[i - 1].group) out.push([\"grp\", 0, y0 + i * ch, W, 1, \"--rule\"]);\n"
              "    for (i = 1; i < dsts.length; i++)\n"
              "      if (dsts[i].group !== dsts[i - 1].group) out.push([\"grp\", x0 + i * cw, 0, 1, Hh, \"--rule\"]);\n"
              "    for (i = 0; i < cells.length; i++) {\n"
              "      var c = cells[i], x = x0 + c.d * cw, y = y0 + c.s * ch, hot = c.smb1 === true;\n"
              "      var v = gnum(c.total) && c.total > 0 ? c.total : 0;\n"
              "      out.push([\"bar\", x + 2, y + ch * 0.25, Math.max(1, (cw - 4) * Math.min(1, max > 0 ? v / max : 0)),\n"
              "                ch * 0.5, hot ? \"--sev-crit\" : \"--rule\"]);\n"
              "      out.push([\"num\", x + 3, y + ch / 2, cw - 6, 10, hot ? \"--sev-crit\" : \"--ink\", mxNum(v)]);\n"
              "      var lt = \"\";\n"
              "      for (var k = 0, p = c.protos || []; k < p.length; k++)\n"
              "        if (typeof p[k] === \"string\" && own.call(MX_LETTER, p[k])) lt += MX_LETTER[p[k]];\n"
              "      if (lt) out.push([\"proto\", x + cw - 2 - 5 * lt.length, y + 4, 5 * lt.length, 7, \"--muted\", lt]);\n"
              "    }\n"
              "    return out;\n"
              "  }\n");
    WT_HAS(p, "      if (typeof m[6] === \"string\") {\n"
              "        // A word: its size is the mark's h, its width at most w.\n"
              "        g.font = Math.round(m[4] * dpr) + \"px \" + resolve(\"--font-mono\");\n");
}

/* §5 G8's states (R5): no lane is the dash; four empty lanes are their
 * axes and their words and nothing else, so a stage not yet seen reads
 * as an empty lane, not as a missing one. The absence seen red with the
 * port's tick loop dropping its c > 0 test (a zero drew a 1 px tick). */
static void test_g8_states(void) {
    gmarks_t g;
    gl_g8(NULL, 0, NULL, 0, NULL, 300, 18, 100, 10, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
    double z[10] = { 0 };
    g8lane_t ln[4];
    memset(ln, 0, sizeof(ln));
    ln[0].counts = z; ln[0].nc = 10;
    ln[2].counts = z; ln[2].nc = 10;
    g8label_t lb[4] = { { "deauth none", "--muted" }, { "twin none", "--muted" },
                        { "assoc none", "--muted" }, { "karma none", "--muted" } };
    gl_g8(ln, 4, NULL, 0, lb, 300, 18, 100, 10, 0, &g);
    WT_EQ(gm_count(&g, "axis"), 4);
    WT_EQ(gm_count(&g, "label"), 4);
    WT_EQ(gm_count(&g, "tick"), 0);
    WT_EQ(gm_count(&g, "bar"), 0);
    WT_EQ(gm_count(&g, "dash"), 0);
    WT_ASSERT(near(gm_last(&g, "axis").y, 63) && !strcmp(gm_last(&g, "axis").tok, "--rule"));
    WT_ASSERT(!strcmp(gm_get(&g, "label").txt, "deauth none"));
}

/* R3: every lane with counts is on one scale, so two associations under
 * ten deauth frames are a fifth of their height, not as tall (seen red
 * with the port's maximum taken per lane); R11: a scale the glyph last
 * drew is kept (seen red with prev ignored: the deauth tick full height
 * under a prev of 20). */
static void test_g8_counts_share_one_scale(void) {
    double d[10] = { 0, 5, 0, 10, 0, 0, 0, 0, 0, 0 }, a[10] = { 0, 0, 0, 0, 0, 2, 0, 0, 0, 0 };
    g8lane_t ln[4];
    memset(ln, 0, sizeof(ln));
    ln[0].counts = d; ln[0].nc = 10;
    ln[2].counts = a; ln[2].nc = 10;
    gmarks_t g;
    gl_g8(ln, 4, NULL, 0, NULL, 200, 18, 100, 10, 0, &g);
    WT_EQ(gl_g8_max(ln, 4, 0), 10);
    WT_EQ(gm_count(&g, "tick"), 3);
    WT_ASSERT(near(g.m[2].h, 14) && near(g.m[2].x, 130) && near(g.m[2].y, 2));
    gmark_t at = gm_last(&g, "tick");
    WT_ASSERT(near(at.h, 2.8) && near(at.x, 150) && near(at.y, 36 + 18 - 2 - 2.8));
    gl_g8(ln, 4, NULL, 0, NULL, 200, 18, 100, 10, 20, &g);
    WT_ASSERT(near(g.m[2].h, 7));
}

/* An incident is a bar from its first to its last observation in the
 * severity colour it reached, a dot where it began and one where it
 * closed, each only inside the window: one that began before it has no
 * start dot and starts at the axis (seen red with the port's a0 >= 0
 * test dropped), one still open has no end dot (seen red with the open
 * flag ignored), one wholly after the window is not drawn (seen red
 * with the a0 > n - 1 test dropped). */
static void test_g8_bars(void) {
    g8lane_t ln[2];
    memset(ln, 0, sizeof(ln));
    double b0[4] = { 1, 3, 2, 0 }, b1[4] = { -4, 2, 0, 0 }, b2[4] = { 6, 9, 1, 1 },
           b3[4] = { 12, 14, 2, 0 };
    memcpy(ln[0].bars[0], b0, sizeof(b0));
    memcpy(ln[0].bars[1], b1, sizeof(b1));
    ln[0].nb = 2;
    memcpy(ln[1].bars[0], b2, sizeof(b2));
    memcpy(ln[1].bars[1], b3, sizeof(b3));
    ln[1].nb = 2;
    gmarks_t g;
    gl_g8(ln, 2, NULL, 0, NULL, 200, 18, 100, 10, 0, &g);
    WT_EQ(gm_count(&g, "bar"), 3);
    gmark_t b = gm_get(&g, "bar");
    WT_ASSERT(near(b.x, 110) && near(b.w, 30) && near(b.y, 7) && !strcmp(b.tok, "--sev-crit"));
    WT_ASSERT(near(g.m[4].x, 100) && near(g.m[4].w, 30) && !strcmp(g.m[4].tok, "--sev-low"));
    WT_EQ(gm_count(&g, "dot"), 4);
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g.m[i].kind, "dot")) WT_ASSERT(!near(g.m[i].x, 100));
    gmark_t ob = gm_last(&g, "bar");
    WT_ASSERT(near(ob.x, 160) && near(ob.w, 40) && !strcmp(ob.tok, "--sev-warn"));
    gmark_t od = gm_last(&g, "dot");
    WT_ASSERT(near(od.x, 160) && near(od.y, 27));
}

/* The links sloth made: a --faint connector from its lane down to the
 * words row under the lanes, its reason beside it; one outside the
 * window, or on a lane the glyph has not, is not drawn (each seen red
 * with its test dropped from the port). */
static void test_g8_links(void) {
    g8lane_t ln[4];
    memset(ln, 0, sizeof(ln));
    g8link_t lk[3] = { { 1, 4, 0, "tainted \xe2\x86\x91 5 s" }, { 1, 12, 1, "late" },
                       { 1, 2, 7, "no lane" } };
    gmarks_t g;
    gl_g8(ln, 4, lk, 3, NULL, 200, 18, 100, 10, 0, &g);
    WT_EQ(gm_count(&g, "link"), 1);
    gmark_t l = gm_get(&g, "link");
    WT_ASSERT(near(l.x, 145) && near(l.y, 9) && near(l.h, 72 + 2 - 9) && !strcmp(l.tok, "--faint"));
    WT_EQ(gm_count(&g, "word"), 1);
    WT_ASSERT(!strcmp(gm_get(&g, "word").txt, "tainted \xe2\x86\x91 5 s"));
    WT_ASSERT(near(gm_get(&g, "word").y, 78));
    /* A taint and the attribution it settles are often one record: two
     * connectors in one column, and the second word after the first
     * rather than over it (seen red with each word at its own
     * connector: both at 328); a later link's words in column order,
     * after both (seen red with the links taken in the order given),
     * and a word that would run past the edge drawn back to it (seen
     * red with the edge test dropped). */
    g8link_t lk2[3] = { { 1, 9, 1, "attributed \xe2\x86\x91" },
                        { 1, 4, 0, "tainted \xe2\x86\x91 5 s" },
                        { 1, 4, 1, "attributed \xe2\x86\x91" } };
    gl_g8(ln, 4, lk2, 3, NULL, 600, 18, 100, 10, 0, &g);
    WT_EQ(gm_count(&g, "link"), 3);
    WT_EQ(gm_count(&g, "word"), 3);
    double wx[3];
    int nw = 0;
    for (int i = 0; i < g.n && nw < 3; i++)
        if (!strcmp(g.m[i].kind, "word")) wx[nw++] = g.m[i].x;
    /* 50 px columns: column 4's connector at 325, column 9's at 575;
     * "tainted ↑ 5 s" is 13 characters, "attributed ↑" 12. */
    WT_ASSERT(nw == 3 && near(wx[0], 328) && near(wx[1], 328 + 13 * 6 + 6));
    /* The third, at 578, would end past 600: drawn back to end there. */
    WT_ASSERT(nw == 3 && near(wx[2], 600 - 12 * 6));
    WT_ASSERT(!strcmp(gm_last(&g, "word").txt, "attributed \xe2\x86\x91") &&
              near(gm_last(&g, "link").x, 575));
}

/* g8Lanes: a row's stages, each lane's words with the highest severity
 * its bars reached (R10) and "none" for an empty one, the twin's
 * confidence from the stream, an incident still open at the window's
 * end without its end dot, and the links in columns. A row of nothing
 * is no stage, and an association is one only beside a twin or a karma
 * row. Seen red with the stage count's deauth term reading the floods
 * alone (2, not 3), and with "none" written for a lane that has frames
 * but no flood. */
static void test_g8_lanes(void) {
    gchrow_t r;
    memset(&r, 0, sizeof(r));
    r.ncell = 10;
    r.has_cell[1] = 1; r.cells[1] = 5;
    r.has_cell[3] = 1; r.cells[3] = 10;
    r.twin.n = 1;
    double tw[4] = { 1040, 1099, 2, 1 };
    memcpy(r.twin.e[0], tw, sizeof(tw));
    r.nassoc = 10; r.assoc[5] = 2;
    r.nlinks = 1;
    r.links[0] = (gclink_t){ 1, 1042, 0, 0, 1, 70 };
    glanes_t o;
    gl_g8_lanes(&r, 1000, 10, 10, &o);
    WT_EQ(o.stages, 3);
    WT_ASSERT(!strcmp(o.labels[0].text, "deauth") && !strcmp(o.labels[0].tok, "--ink"));
    WT_ASSERT(!strcmp(o.labels[1].text, "twin CRIT 70%"));
    WT_ASSERT(!strcmp(o.labels[2].text, "assoc"));
    WT_ASSERT(!strcmp(o.labels[3].text, "karma none") && !strcmp(o.labels[3].tok, "--muted"));
    WT_ASSERT(near(o.lanes[1].bars[0][0], 4) && near(o.lanes[1].bars[0][1], 9) &&
              near(o.lanes[1].bars[0][3], 1));
    WT_EQ(o.nlinks, 1);
    WT_ASSERT(near(o.links[0].col, 4) && o.links[0].top == 0);
    gmarks_t g;
    gl_g8(o.lanes, 4, o.links, o.nlinks, o.labels, 200, 18, 100, 10, 0, &g);
    WT_EQ(gm_count(&g, "dot"), 1);
    /* Deauth frames and stations associating with no twin or karma row:
     * an ordinary AP, one stage, the rug's (seen red with the port's
     * association term not asking for a lure: 2). */
    r.twin.n = 0;
    r.nlinks = 0;
    gl_g8_lanes(&r, 1000, 10, 10, &o);
    WT_EQ(o.stages, 1);
    gchrow_t e;
    memset(&e, 0, sizeof(e));
    gl_g8_lanes(&e, 1000, 10, 10, &o);
    WT_EQ(o.stages, 0);
    WT_ASSERT(!strcmp(o.labels[0].text, "deauth none"));
}

/* R10: in one grey, a bar, a tick, a dot and a link still differ by
 * kind and position, and the severity is a word in the lane's label. */
static void test_g8_reads_in_greyscale(void) {
    gchrow_t r;
    memset(&r, 0, sizeof(r));
    r.ncell = 10;
    r.has_cell[2] = 1; r.cells[2] = 4;
    r.floods.n = 1;
    double fl[4] = { 1010, 1035, 2, 9 };
    memcpy(r.floods.e[0], fl, sizeof(fl));
    r.nlinks = 1;
    r.links[0] = (gclink_t){ 1, 1042, 1, 1050, 0, 0 };
    glanes_t o;
    gl_g8_lanes(&r, 1000, 10, 10, &o);
    gmarks_t g;
    gl_g8(o.lanes, 4, o.links, o.nlinks, o.labels, 200, 18, 100, 10, 0, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_ASSERT(near(gm_get(&g, "bar").h, 4) && near(gm_get(&g, "bar").y, 7));
    WT_ASSERT(gm_get(&g, "tick").y + gm_get(&g, "tick").h <= 16 + 1e-9);
    WT_EQ(gm_count(&g, "link"), 2);
    WT_ASSERT(!strcmp(gm_get(&g, "label").txt, "deauth CRIT"));
}

/* The matrix (F11): a --rule line where a subnet changes on each axis;
 * each cell a bar on the matrix's one scale (the largest cell a full
 * cell, seen red with each bar against its own row's largest), behind
 * its count in words; an SMB1 cell in the critical colour, bar and
 * number (R10: the caption says what red is); the protocols as letters
 * in the corner; R11's prev kept; no cell the dash. */
static void test_mx(void) {
    int sg[3] = { 0, 0, 1 }, dg[2] = { 0, 1 };
    gcell_t c[3] = {
        { 0, 0, 64, { "ssh", "smb" }, 2, 0 },
        { 1, 0, 2000, { "smb" }, 1, 1 },
        { 2, 1, 32, { "bgp", "mqtt" }, 2, 0 },
    };
    gmarks_t g;
    gl_mx(sg, 3, dg, 2, c, 3, 100, 50, 40, 18, 0, &g);
    WT_EQ(gm_count(&g, "grp"), 2);
    WT_ASSERT(near(g.m[0].y, 50 + 36) && near(g.m[0].w, 180));
    WT_ASSERT(near(g.m[1].x, 140) && near(g.m[1].h, 104));
    WT_EQ(gm_count(&g, "bar"), 3);
    gmark_t b0 = gm_get(&g, "bar");
    WT_ASSERT(near(b0.x, 102) && near(b0.w, 36 * 64.0 / 2000) && !strcmp(b0.tok, "--rule"));
    WT_ASSERT(!strcmp(g.m[5].kind, "bar") && near(g.m[5].w, 36) && !strcmp(g.m[5].tok, "--sev-crit"));
    WT_ASSERT(!strcmp(g.m[6].txt, "2.0k") && !strcmp(g.m[6].tok, "--sev-crit"));
    WT_ASSERT(!strcmp(gm_get(&g, "num").txt, "64") && !strcmp(gm_get(&g, "num").tok, "--ink"));
    gmark_t pl = gm_get(&g, "proto");
    WT_ASSERT(!strcmp(pl.txt, "SM") && near(pl.x, 100 + 40 - 2 - 10) && !strcmp(pl.tok, "--muted"));
    WT_ASSERT(!strcmp(gm_last(&g, "proto").txt, "B"));
    gl_mx(sg, 3, dg, 2, c, 3, 100, 50, 40, 18, 4000, &g);
    WT_ASSERT(near(g.m[5].w, 18));
    gl_mx(sg, 3, dg, 2, c, 0, 100, 50, 40, 18, 0, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "dash"), 1);
}

/* A cell's count in words: whole below a thousand, then k and M with
 * one decimal under ten of them. */
static void test_mx_num(void) {
    char t[24];
    gl_mx_num(999, t, sizeof(t));     WT_ASSERT(!strcmp(t, "999"));
    gl_mx_num(1234, t, sizeof(t));    WT_ASSERT(!strcmp(t, "1.2k"));
    gl_mx_num(45678, t, sizeof(t));   WT_ASSERT(!strcmp(t, "46k"));
    gl_mx_num(1234567, t, sizeof(t)); WT_ASSERT(!strcmp(t, "1.2M"));
    gl_mx_num(98765432, t, sizeof(t)); WT_ASSERT(!strcmp(t, "99M"));
    gl_mx_num(-1, t, sizeof(t));      WT_ASSERT(!strcmp(t, "-"));
}

/* §6.3, §6.6 and §6.8 as the page wires them. The chains panel asks
 * /api/wifi/chain and draws one G8 per bssid with more than one stage,
 * the rest left to the G7 rug (a bssid with one stage gets a rug, not a
 * G8), collapsing to its caption with none; the alert page draws the
 * chain of the BSSID its device names, in its own section above the
 * device; the drawer draws it only with two stages or more. The Flows
 * panel draws the matrix first (ruling 4): its control kept, matrix
 * selected, the chord hidden until chosen, the matrix asked for in its
 * own form, wider than its box in a scroll box of its own, a click a
 * filter. The two absences seen red with the old chains note put back
 * and with flowGraph()'s direct chord(c, g) call put back; the order
 * seen red with ad-chain moved under ad-device. */
static void test_v4_wiring(void) {
    const char *p = page();
    WT_HAS(p, "window.SlothChain = {");
    WT_HAS(p, "window.SlothFlowMx = {");
    /* The chains panel. */
    WT_HAS(p, "    getJSON(wifiGridPath(\"chain\", \"\", r)).then(function (cj) {");
    WT_HAS(p, "      var ch = SlothChain.list($(\"w-chains\"), cj);");
    WT_HAS(p, "      if (gl.stages < 2) { singles.push(r); return; }");
    WT_HAS(p, "    box.hidden = !chains.length;\n"
              "    return { chains: chains.length, max: max, singles: singles, win: sp ? sp.text : \"\" };");
    /* R4: under a tenth of the window, the columns held only, one span
     * for every chain of a list, and the caption's words. Seen red with
     * the cut taken out of paint() (the whole window drawn under the
     * shrunk caption). */
    WT_HAS(p, "    var wn = glyph.win([[a, 0], [b, 0]], j.from, j.to);\n"
              "    return wn.shrunk ? { lo: acc[0], hi: acc[1], from: a, to: b, text: wn.text } : null;");
    WT_HAS(p, "    if (sp) { cut(gl, sp); cols = sp.hi - sp.lo + 1; from = sp.from; to = sp.to; }");
    WT_HAS(p, "      if (ln.counts) ln.counts = ln.counts.slice(sp.lo, sp.hi + 1);");
    WT_HAS(p, "    var sp = span(acc, j);\n    chains.forEach(function (r) {");
    WT_HAS(p, "                bssids: ch.singles };\n      var rg = SlothAir.rug($(\"w-deauth\"), j), nb = rg.busy;");
    WT_HAS(p, "n: cj.cols, state: (ch.chains ? ch.win : \"no bssid with more than one stage in the window\") +");
    /* The route reads the WEB_WIFI_CHAINS most deauthed; past that the
     * caption says how many it did not (V4 review). Seen red with the
     * clause taken out. */
    WT_HAS(p, "\" of \" + cj.total_keys + \" bssids most deauthed read\"");
    WT_HAS(p, "<div id=\"w-chains\" hidden></div>");
    WT_LACKS(p, "arrive with the chain timeline");
    /* R11 per BSSID, started again with the scope or the window. */
    WT_HAS(p, "    if (S.of !== scaleKey(j)) { S.max = {}; S.of = scaleKey(j); }");
    WT_HAS(p, "    var max = glyph.g8Max(gl.lanes, S.max[key] || 0);\n    S.max[key] = max;");
    /* One BSSID's scale per cell width and scope: the alert page's half
     * hour does not inherit the WiFi panel's day (V4 review). Seen red
     * with the key the BSSID alone, as it was. */
    WT_HAS(p, "    var key = H.scope() + \"\\u0000\" + j.col_s + \"\\u0000\" + String(row.bssid);");
    /* The alert page and the drawer. */
    WT_HAS(p, "    if (window.SlothChain) SlothChain.alert(j);\n    // (g) the device it names");
    WT_HAS(p, "    var b = j && j.device && j.device.bssid;");
    WT_HAS(p, "    var to = Math.min(now, (num(j.last_seen) ? j.last_seen : now) + 300);\n"
              "    var from = (num(j.first_seen) ? j.first_seen : to) - 900;\n"
              "    if (to - from < 1800) from = to - 1800;");
    WT_HAS(p, "      var two = glyph.g8Lanes(row, a).stages > 1;\n      c.hidden = !two;");
    WT_HAS(p, "      if (!row || glyph.g8Lanes(row, a).stages < 2) return;");
    WT_HAS(p, "    if (window.SlothChain) SlothChain.drawer(mac);");
    WT_HAS(p, "<canvas class=\"chain\" id=\"dr-chain-c\"");
    const char *h = strstr(p, "<section class=\"panel\" id=\"ad-history\"");
    if (!h) h = strstr(p, "id=\"ad-history\"");
    const char *c = strstr(p, "<section class=\"panel\" id=\"ad-chain\" hidden");
    const char *d = strstr(p, "<section class=\"panel\" id=\"ad-device\">");
    const char *e = strstr(p, "<section class=\"panel\" id=\"ev-alert\"");
    WT_ASSERT(h && c && d && e && h < c && c < d && d < e);
    /* The Flows matrix, first. */
    WT_HAS(p, "<option value=\"matrix\" selected>who talks to whom (matrix)</option>");
    WT_HAS(p, "<canvas class=\"chord\" id=\"f-chord\" hidden");
    WT_HAS(p, "<div class=\"hscroll\" id=\"f-mx-box\"><canvas class=\"fmx\" id=\"f-matrix\"");
    WT_HAS(p, "  function flowMode() { return $(\"f-mode\").value === \"chord\" ? \"chord\" : \"matrix\"; }");
    WT_HAS(p, "    var q = mode === \"matrix\" ? \"&form=matrix&edges=\" + (narrow ? 40 : 80)\n"
              "                              : \"&nodes=\" + nodes + \"&edges=80\";");
    WT_HAS(p, "    getJSON(\"/api/flows/graph?from=\" + r.from + \"&to=\" + r.to + q).then(function (g) {");
    WT_LACKS(p, "      chord(c, g);\n      flowLegend(g);");
    WT_HAS(p, "    $(\"f-mx-box\").hidden = !st.cells;");
    WT_HAS(p, "    if (F.mxOf !== mk) { SlothFlowMx.reset(); F.mxOf = mk; }");
    WT_HAS(p, "    c.style.width = Math.max(bw, x0 + dsts.length * cw) + \"px\";");
    WT_HAS(p, "    cw = Math.max(CW_MIN, Math.min(CW_MAX, cw));");
    WT_HAS(p, "    G.max = glyph.mxMax(m, G.max);");
    WT_HAS(p, "    var id = SlothFlowMx.hit(e);\n    if (id === null) return;\n    $(\"f-ip\").value = id;");
}

void run_glyph_tests(void) {
    WT_RUN(test_the_page_carries_the_ported_js);
    WT_RUN(test_g1_empty_is_a_dash);
    WT_RUN(test_g1_warming_draws_no_band);
    WT_RUN(test_g1_one_point);
    WT_RUN(test_g1_four_points_are_dots);
    WT_RUN(test_g1_a_gap_breaks_the_line);
    WT_RUN(test_g1_in_band);
    WT_RUN(test_g1_out_of_band);
    WT_RUN(test_g1_line_grades_like_the_tui);
    WT_RUN(test_g1_reads_in_greyscale);
    WT_RUN(test_g1_scale_never_shrinks);
    WT_RUN(test_the_window_rule);
    WT_RUN(test_the_caption_grammar);
    WT_RUN(test_g5_cells_from_the_servers_hex);
    WT_RUN(test_g5_states);
    WT_RUN(test_g5_ruler);
    WT_RUN(test_g5_anomaly_underline);
    WT_RUN(test_g5_reads_in_greyscale);
    WT_RUN(test_sun_against_the_almanac);
    WT_RUN(test_sun_noon_elevation);
    WT_RUN(test_sun_polar_and_twilight);
    WT_RUN(test_sun_position_is_rounded);
    WT_RUN(test_g5_sun_phases_at_london);
    WT_RUN(test_g5_no_position_is_one_ink);
    WT_RUN(test_g5_long_cells_are_one_ink);
    WT_RUN(test_g5_ruler_sun_band);
    WT_RUN(test_the_page_carries_the_sun);
    WT_RUN(test_sun_zone_is_the_sensors);
    WT_RUN(test_sun_zone_fallback_and_names);
    WT_RUN(test_sun_words_in_sensor_time);
    WT_RUN(test_the_page_carries_the_sun_zone);
    WT_RUN(test_g6_bullet);
    WT_RUN(test_g6_count_bar);
    WT_RUN(test_g6_states);
    WT_RUN(test_g6_reads_in_greyscale);
    WT_RUN(test_g1_words_trend);
    WT_RUN(test_g1_episode_shade);
    WT_RUN(test_shared_scale_has_one_maximum);
    WT_RUN(test_multiples_sort);
    WT_RUN(test_g4_warming_is_plain_rule);
    WT_RUN(test_g4_provisional_is_one_ink);
    WT_RUN(test_g4_ramp_and_caption_facts);
    WT_RUN(test_g4_caption_counts);
    WT_RUN(test_tiles_and_strip_carry_g1);
    WT_RUN(test_cards_and_multiples_wiring);
    WT_RUN(test_v1_review_wiring);
    WT_RUN(test_every_glyph_names_its_tui_form);
    WT_RUN(test_g2_states);
    WT_RUN(test_g2_fixed_scale_and_clamp);
    WT_RUN(test_g2_whisker);
    WT_RUN(test_g2_words_are_sloths);
    WT_RUN(test_new_mark_and_first_cell);
    WT_RUN(test_v2_wiring);
    WT_RUN(test_sm_constants_and_band_table);
    WT_RUN(test_sm_boundaries_and_readout);
    WT_RUN(test_sm_reads_on_its_band);
    WT_RUN(test_sm_states);
    WT_RUN(test_sm_geometry_and_ticks);
    WT_RUN(test_sm_reads_in_greyscale);
    WT_RUN(test_sm_other_units);
    WT_RUN(test_sm_words_and_text);
    WT_RUN(test_sm_page_and_wiring);
    WT_RUN(test_the_page_carries_v3s_js);
    WT_RUN(test_g3_states);
    WT_RUN(test_g3_out_of_band_only_on_z);
    WT_RUN(test_g3_values);
    WT_RUN(test_g3_reads_in_greyscale);
    WT_RUN(test_g7_rug);
    WT_RUN(test_v3_wiring);
    WT_RUN(test_v3_review_wiring);
    WT_RUN(test_the_page_carries_v4s_js);
    WT_RUN(test_g8_states);
    WT_RUN(test_g8_counts_share_one_scale);
    WT_RUN(test_g8_bars);
    WT_RUN(test_g8_links);
    WT_RUN(test_g8_lanes);
    WT_RUN(test_g8_reads_in_greyscale);
    WT_RUN(test_mx);
    WT_RUN(test_mx_num);
    WT_RUN(test_v4_wiring);
}
