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

typedef struct { const char *kind; double x, y, w, h; const char *tok; } gmark_t;
typedef struct { gmark_t m[GM_MAX]; int n; } gmarks_t;

static void gm_push(gmarks_t *g, const char *kind, double x, double y,
                    double w, double h, const char *tok) {
    if (g->n >= GM_MAX) return;
    g->m[g->n].kind = kind;
    g->m[g->n].x = x; g->m[g->n].y = y;
    g->m[g->n].w = w; g->m[g->n].h = h;
    g->m[g->n].tok = tok;
    g->n++;
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
    static const gmark_t none = { "", 0, 0, 0, 0, "" };
    for (int i = 0; i < g->n; i++) if (!strcmp(g->m[i].kind, kind)) return g->m[i];
    return none;
}
/* The last mark of a kind, the same way. */
static gmark_t gm_last(const gmarks_t *g, const char *kind) {
    static const gmark_t none = { "", 0, 0, 0, 0, "" };
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
}
