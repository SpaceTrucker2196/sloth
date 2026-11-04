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
typedef struct { double warm; int warming, fed; double max, n; } g4st_t;
static g4st_t gl_g4_stats(const double (*cells)[3], double warm) {
    g4st_t o;
    o.warm = warm; o.warming = 0; o.fed = 0; o.max = 0; o.n = 0;
    for (int i = 0; i < 168; i++) {
        if (!cells || !(cells[i][2] >= o.warm)) { o.warming++; continue; }
        o.fed++;
        o.n += cells[i][2];
        if (cells[i][0] > o.max) o.max = cells[i][0];
    }
    return o;
}
static void gl_g4(const double (*cells)[3], double w, double h, double x0, double y0,
                  double warm, int now, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    double cw = (w - x0) / 24, ch = (h - y0) / 7;
    g4st_t st = gl_g4_stats(cells, warm);
    for (int i = 0; st.fed && i < 168; i++) {
        double x = x0 + cw * (i % 24), y = y0 + ch * (i / 24);
        if (cells && cells[i][2] >= st.warm)
            gm_push(g, "cell", x + 1, y + 1, cw - 2, ch - 2,
                    gl_heat_token(st.max > 0 ? cells[i][0] / st.max : 0));
        else gm_push(g, "warm", x + 1, y + 1, cw - 2, ch - 2, "--rule");
    }
    if (now >= 0 && now < 168)
        gm_push(g, "outline", x0 + cw * (now % 24), y0 + ch * (now / 24), cw, ch, "--signal");
}

/* G5, the binary presence strip. cells: 1 present, 0 absent, -1 a gap. */
static void gl_g5(const int *cells, int n, double w, double h, int first,
                  const int (*ep)[2], int nep, gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    if (n <= 0) { gl_dash(g, w, h); return; }
    double cw = w / n;
    for (int i = 0; i < n; i++) {
        double x = floor(i * cw), cwi = ceil(cw);
        if (cwi < 1) cwi = 1;
        if (cells[i] < 0) gm_push(g, "gap", x, 0, cwi, h, "--faint");
        else if (cells[i] > 0) gm_push(g, "cell", x, 0, cwi, h, "--tui-normal");
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

static void gl_g5_ruler(double w, double h, double from, double to, double off,
                        gmarks_t *g) {
    memset(g, 0, sizeof(*g));
    if (!(to > from)) return;
    double first = ceil((from + off) / 86400) * 86400 - off;
    for (double t = first; t <= to; t += 86400)
        gm_push(g, "tick", (t - from) / (to - from) * w, 0, 1, h, "--faint");
    gm_push(g, "now", w - 1, 0, 1, h, "--signal");
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
    WT_HAS(p, "      if (cells[i] < 0) m.push([\"gap\", x, 0, cwi, h, \"--faint\"]);\n"
              "      else if (cells[i] > 0) m.push([\"cell\", x, 0, cwi, h, "
              "\"--tui-normal\"]);");
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
    WT_HAS(p, "      if (c && c[2] >= st.warm)\n"
              "        m.push([\"cell\", x + 1, y + 1, cw - 2, ch - 2,\n"
              "                heatToken(st.max > 0 ? c[0] / st.max : 0)]);\n"
              "      else m.push([\"warm\", x + 1, y + 1, cw - 2, ch - 2, \"--rule\"]);");
    WT_HAS(p, "      m.push([\"outline\", x0 + cw * (nc % 24), y0 + ch * Math.floor(nc / 24), cw, ch, \"--signal\"]);");
    WT_HAS(p, "      if (!c || !(c[2] >= o.warm)) { o.warming++; continue; }");
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
              "    var cw = (w - x0) / 24, ch = (h - y0) / 7, st = g4Stats(cells, opt.warm);\n"
              "    for (i = 0; st.fed && i < 168; i++) {\n"
              "      var c = cells && cells[i], x = x0 + cw * (i % 24), y = y0 + ch * Math.floor(i / 24);\n"
              "      if (c && c[2] >= st.warm)\n"
              "        m.push([\"cell\", x + 1, y + 1, cw - 2, ch - 2,\n"
              "                heatToken(st.max > 0 ? c[0] / st.max : 0)]);\n"
              "      else m.push([\"warm\", x + 1, y + 1, cw - 2, ch - 2, \"--rule\"]);\n"
              "    }\n"
              "    var nc = opt.now;\n"
              "    if (gnum(nc) && nc >= 0 && nc < 168)\n"
              "      m.push([\"outline\", x0 + cw * (nc % 24), y0 + ch * Math.floor(nc / 24), cw, ch, \"--signal\"]);\n"
              "    return m;\n");
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
              "    var o = { warm: gnum(warm) ? warm : 3, warming: 0, fed: 0, max: 0, n: 0 };\n"
              "    for (var i = 0; i < 168; i++) {\n"
              "      var c = cells && cells[i];\n"
              "      if (!c || !(c[2] >= o.warm)) { o.warming++; continue; }\n"
              "      o.fed++;\n"
              "      o.n += c[2];\n"
              "      if (c[0] > o.max) o.max = c[0];\n"
              "    }\n"
              "    return o;\n");
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

/* F3, R8: a warming cell is one --rule mark and nothing else, and a
 * grid that is all warming draws only the now outline. Seen red with a
 * second "hatch" mark pushed for each warming cell, and with the
 * all-warming guard taken out of the port. */
static void test_g4_warming_is_plain_rule(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    gmarks_t g;
    gl_g4(cells, 272, 84, 32, 14, 3, 30, &g);
    WT_EQ(g.n, 1);
    WT_EQ(gm_count(&g, "outline"), 1);
    gmark_t ol = gm_get(&g, "outline");
    WT_ASSERT(near(ol.x, 32 + 10.0 * 6) && near(ol.y, 14 + 10.0));
    WT_ASSERT(!strcmp(ol.tok, "--signal"));
    gl_g4(NULL, 272, 84, 32, 14, 3, -1, &g);
    WT_EQ(g.n, 0);
    /* One cell fed: every other is a single warming mark. */
    cells[5][0] = 7; cells[5][2] = 3;
    gl_g4(cells, 272, 84, 32, 14, 3, 30, &g);
    WT_EQ(g.n, 169);
    WT_EQ(gm_count(&g, "cell"), 1);
    WT_EQ(gm_count(&g, "warm"), 167);
    for (int i = 0; i < g.n; i++)
        if (!strcmp(g.m[i].kind, "warm")) WT_ASSERT(!strcmp(g.m[i].tok, "--rule"));
    /* The hatch the old heatmap stroked is gone from the page. */
    WT_LACKS(page(), "for (var s = -ch; s < cw; s += 4 * dpr) {");
    WT_LACKS(page(), "grey hatched");
}

/* G4's ramp is against the largest fed mean: a warming cell's mean,
 * however large, neither sets the top nor is drawn. Seen red with the
 * stats' max taken over every cell. */
static void test_g4_ramp_and_caption_facts(void) {
    static double cells[168][3];
    memset(cells, 0, sizeof(cells));
    cells[0][0] = 100; cells[0][2] = 4;
    cells[1][0] = 50;  cells[1][2] = 3;
    cells[2][0] = 1e6; cells[2][2] = 2;    /* warming */
    g4st_t st = gl_g4_stats(cells, 3);
    WT_EQ(st.fed, 2);
    WT_EQ(st.warming, 166);
    WT_ASSERT(near(st.max, 100));
    WT_ASSERT(near(st.n, 7));
    gmarks_t g;
    gl_g4(cells, 272, 84, 32, 14, 3, -1, &g);
    WT_ASSERT(!strcmp(g.m[0].tok, "--heat-3"));
    WT_ASSERT(!strcmp(g.m[1].tok, "--heat-2"));
    WT_ASSERT(!strcmp(g.m[2].kind, "warm"));
    WT_EQ(gm_count(&g, "outline"), 0);
    /* R10: in one grey, fed, warming and now are still three kinds. */
    gl_g4(cells, 272, 84, 32, 14, 3, 0, &g);
    gm_grey(&g);
    WT_ASSERT(gm_all_grey(&g));
    WT_EQ(gm_count(&g, "cell"), 2);
    WT_EQ(gm_count(&g, "warm"), 166);
    WT_EQ(gm_count(&g, "outline"), 1);
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
    WT_HAS(p, "n: st.n, state: st.warming ? \"warming: \" + st.warming + \" of 168 cells\" : \"\" });");
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
    WT_HAS(p, "    drawStrip(r.cv, d.presence, 144, glyph.firstCell(d.first_seen, D.pfrom, 600, 144));");
    WT_HAS(p, "                glyph.firstCell(rec ? rec.first_seen : null, j.presence_from, 600, 144));");
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
    WT_HAS(p, "window.SlothRf = { init: function (h) { H = h; }, cell: cell, block: block, bullet: bullet,");
    WT_HAS(p, "    SlothRf.cell(r.cells[\"c-sig\"], d.rf, num(d.signal) ? d.signal : null);");
    WT_HAS(p, "    SlothRf.cell(sg, a.rf, num(a.signal) ? a.signal : null);");
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
    /* A table's G2 draws the whole hour in every row (P4); the block's
     * caption says the rule is a rule of thumb (ruling 3). */
    WT_HAS(p, "    var n = rf && rf.cells && rf.cells.length ? rf.cells.length : 60;");
    WT_HAS(p, "\" dBm, a field rule of thumb, not a standard\"");
    /* The member's cells are web_rf.h's: the page's fallback is the same
     * count. */
    WT_EQ(WEB_RF_CELLS, 60);
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
    /* V2: G2's row, its form on the fixed scale with sloth's own
     * distance cell for the words. Seen red with the row removed. */
    WT_HAS(doc, "| G2 range sparkline (RSSI) |");
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
    WT_HAS(p, "      drawStrip(cv, d.presence, 144, glyph.firstCell(d.first_seen, WF.clFrom, 600, 144));");
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
    WT_RUN(test_g6_bullet);
    WT_RUN(test_g6_count_bar);
    WT_RUN(test_g6_states);
    WT_RUN(test_g6_reads_in_greyscale);
    WT_RUN(test_g1_words_trend);
    WT_RUN(test_g1_episode_shade);
    WT_RUN(test_shared_scale_has_one_maximum);
    WT_RUN(test_multiples_sort);
    WT_RUN(test_g4_warming_is_plain_rule);
    WT_RUN(test_g4_ramp_and_caption_facts);
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
