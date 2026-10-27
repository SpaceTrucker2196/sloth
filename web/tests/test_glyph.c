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
#include <string.h>

#include "web_assets.h"
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
        if (band && has[i]) {
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
    int any = 0, i;
    for (i = 0; band && i < n; i++) if (has[i]) any = 1;
    for (i = 0; any && i < n; i++) {
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
    if (any && has[k] && band[k][3] > 0 &&
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
    WT_RUN(test_every_glyph_names_its_tui_form);
}
