/* palette css SLOTH_TUI_C THEME_CSS OUT.css
 * palette js  SLOTH_TUI_C OUT.js
 * palette contrast SLOTH_TUI_C THEME_CSS
 *
 * The page's data colours (owner ruling 2026-10-23: "color code all
 * data the same as the sloth cli"), generated at build time from
 * sloth's own sources so that nothing is copied by hand. Build time
 * only; it opens the files it is named and nothing else.
 *
 * The colours come from the TUI's colour-pair table itself: this tool
 * links src/tui_palette.c and asks tui_pair_colors() for every pair the
 * page mirrors (CP_IP_BASE_*, CP_BR_*, CP_INFO_BASE, the phosphor and
 * heat pairs, CP_ALERT_HOT_*, CP_MON_ROW and its background), then
 * turns each xterm-256 index
 * into hex by the standard formula (16 system colours, the 6x6x6 cube
 * on 0/95/135/175/215/255, the 24 greys from 8 in steps of 10). The
 * brand table and the Google letter sequence live inside src/tui.c's
 * find_brand() and tui_brand_addstr() as static data, so they are read
 * out of that file as text, and a table this parser cannot read fails
 * the build rather than shipping a stale copy.
 *
 * The dark theme carries the TUI's values byte for byte. The light
 * theme keeps each hue and darkens it by one rule (light_variant()),
 * against the light --bg and --panel read out of web/ui/theme.css.
 *
 * "contrast" prints web/README.md's contrast tables: every text, data,
 * severity, heat and alert-hot token on --bg and --panel in both
 * themes, the graphics that carry meaning, and how far apart the chart
 * hues are. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip_color.h"
#include "tui.h"
#include "tui_palette.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define FILE_MAX (1024 * 1024)
#define MAX_BRANDS 256
#define MAX_DECLS 160

/* ── colour arithmetic ─────────────────────────────────────────────── */

typedef struct { int r, g, b; } rgb_t;

static rgb_t xterm_rgb(int i) {
    static const unsigned char sys[16][3] = {
        { 0, 0, 0 },       { 128, 0, 0 },     { 0, 128, 0 },   { 128, 128, 0 },
        { 0, 0, 128 },     { 128, 0, 128 },   { 0, 128, 128 }, { 192, 192, 192 },
        { 128, 128, 128 }, { 255, 0, 0 },     { 0, 255, 0 },   { 255, 255, 0 },
        { 0, 0, 255 },     { 255, 0, 255 },   { 0, 255, 255 }, { 255, 255, 255 },
    };
    rgb_t c = { 0, 0, 0 };
    if (i < 0 || i > 255) return c;
    if (i < 16) {
        c.r = sys[i][0]; c.g = sys[i][1]; c.b = sys[i][2];
    } else if (i < 232) {
        static const int lv[6] = { 0, 95, 135, 175, 215, 255 };
        int k = i - 16;
        c.r = lv[k / 36]; c.g = lv[(k / 6) % 6]; c.b = lv[k % 6];
    } else {
        c.r = c.g = c.b = 8 + 10 * (i - 232);
    }
    return c;
}

static double lin(int v) {
    double c = v / 255.0;
    return c <= 0.04045 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4);
}

/* WCAG 2.x relative luminance and contrast ratio. */
static double luminance(rgb_t c) {
    return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
}

static double contrast(rgb_t a, rgb_t b) {
    double la = luminance(a), lb = luminance(b);
    return la > lb ? (la + 0.05) / (lb + 0.05) : (lb + 0.05) / (la + 0.05);
}

static void to_hsl(rgb_t c, double *h, double *s, double *l) {
    double r = c.r / 255.0, g = c.g / 255.0, b = c.b / 255.0;
    double mx = fmax(r, fmax(g, b)), mn = fmin(r, fmin(g, b)), d = mx - mn;
    *l = (mx + mn) / 2;
    *h = 0;
    *s = 0;
    if (d <= 0) return;
    *s = d / (1 - fabs(2 * *l - 1));
    if (mx == r)      *h = fmod((g - b) / d + 6, 6);
    else if (mx == g) *h = (b - r) / d + 2;
    else              *h = (r - g) / d + 4;
    *h *= 60;
}

static int clamp8(double v) {
    int x = (int)lround(v * 255);
    return x < 0 ? 0 : x > 255 ? 255 : x;
}

static rgb_t from_hsl(double h, double s, double l) {
    double c = (1 - fabs(2 * l - 1)) * s, hp = h / 60;
    double x = c * (1 - fabs(fmod(hp, 2) - 1)), m = l - c / 2;
    double r = 0, g = 0, b = 0;
    if (hp < 1)      { r = c; g = x; }
    else if (hp < 2) { r = x; g = c; }
    else if (hp < 3) { g = c; b = x; }
    else if (hp < 4) { g = x; b = c; }
    else if (hp < 5) { r = x; b = c; }
    else             { r = c; b = x; }
    rgb_t o = { clamp8(r + m), clamp8(g + m), clamp8(b + m) };
    return o;
}

/* The light theme's rule for a data colour: keep the hue and the
 * saturation, and lower the HSL lightness in steps of 0.005 until the
 * colour reads at 4.5:1 (WCAG AA, body text) on both the light --bg and
 * the light --panel. A colour that already does is kept as it is. */
#define LIGHT_MIN 4.5
static rgb_t light_variant(rgb_t c, rgb_t bg, rgb_t panel) {
    double h, s, l;
    to_hsl(c, &h, &s, &l);
    rgb_t o = c;
    while ((contrast(o, bg) < LIGHT_MIN || contrast(o, panel) < LIGHT_MIN) && l > 0) {
        l -= 0.005;
        if (l < 0) l = 0;
        o = from_hsl(h, s, l);
    }
    return o;
}

/* The light theme's monitor-row ground: the light --bg scaled toward
 * black, step by step, until it stands off --bg by the same contrast
 * ratio as xterm 236 stands off the dark --bg. */
static rgb_t light_ground(rgb_t dark_ground, rgb_t dark_bg, rgb_t light_bg) {
    double want = contrast(dark_ground, dark_bg);
    rgb_t o = light_bg;
    for (double f = 1.0; f > 0 && contrast(o, light_bg) < want; f -= 0.002) {
        o.r = (int)lround(light_bg.r * f);
        o.g = (int)lround(light_bg.g * f);
        o.b = (int)lround(light_bg.b * f);
    }
    return o;
}

static void hex(rgb_t c, char out[8]) {
    snprintf(out, 8, "#%02x%02x%02x", c.r & 255, c.g & 255, c.b & 255);
}

static int parse_hex(const char *s, rgb_t *c) {
    unsigned r, g, b;
    if (strlen(s) != 7 || s[0] != '#' || sscanf(s + 1, "%2x%2x%2x", &r, &g, &b) != 3)
        return -1;
    c->r = (int)r; c->g = (int)g; c->b = (int)b;
    return 0;
}

/* ── the TUI's pairs ───────────────────────────────────────────────── */

typedef struct {
    char name[24];
    int  xterm;
    char why[48];
} tok_t;

static tok_t g_tok[64];
static int g_ntok;

/* The monitor rows' ground and text (CP_MON_ROW): in the light theme
 * the ground follows light_ground(), and the text the data rule against
 * that ground rather than against --bg. The TUI draws a monitor row's
 * stamp in CP_MON_ROW too (packets.c draw_mon_row()), so the page has
 * no CP_MON_ROW_DIM token. */
#define NMON 2
static rgb_t g_mon[NMON][2];   /* bg, fg; dark, light */
static int g_mon_x[NMON];
static const char *const MON_NAME[NMON] = { "--mon-bg", "--mon-fg" };

static int fg_of(int pair) {
    short f, b;
    if (!tui_pair_colors(pair, &f, &b)) {
        fprintf(stderr, "palette: tui_pair_colors(%d) is unmapped\n", pair);
        exit(1);
    }
    return f;
}

static void add_tok(const char *name, int xterm, const char *why) {
    tok_t *t = &g_tok[g_ntok++];
    snprintf(t->name, sizeof(t->name), "%s", name);
    t->xterm = xterm;
    snprintf(t->why, sizeof(t->why), "%s", why);
}

/* Every category band of a table must give the same foreground: the
 * page has one colour per hash index, which is true only while the
 * TUI's row backgrounds stay retired (tui_pair_colors()). */
static int same_in_bands(const int *bases, int nb, int i) {
    int f = fg_of(bases[0] + i);
    for (int k = 1; k < nb; k++)
        if (fg_of(bases[k] + i) != f) {
            fprintf(stderr, "palette: pair %d differs from pair %d; the page "
                            "colours a hash index one way\n", bases[k] + i, bases[0] + i);
            exit(1);
        }
    return f;
}

static void collect(void) {
    static const int ip_bases[] = { CP_IP_BASE_OTHER, CP_IP_BASE_TCP, CP_IP_BASE_UDP,
        CP_IP_BASE_DNS, CP_IP_BASE_ICMP, CP_IP_BASE_HTTP, CP_IP_BASE_TLS };
    static const int br_bases[] = { CP_BR_BASE_OTHER, CP_BR_BASE_TCP, CP_BR_BASE_UDP,
        CP_BR_BASE_DNS, CP_BR_BASE_ICMP, CP_BR_BASE_HTTP, CP_BR_BASE_TLS };
    char n[24], w[48];
    for (int i = 0; i < IP_NUM_COLORS; i++) {
        snprintf(n, sizeof(n), "--k-%d", i);
        snprintf(w, sizeof(w), "CP_IP_BASE_* + %d", i);
        add_tok(n, same_in_bands(ip_bases, 7, i), w);
    }
    for (int i = 0; i < 16; i++) {
        snprintf(n, sizeof(n), "--br-%d", i);
        if (i < 8) {
            snprintf(w, sizeof(w), "CP_BR_BASE_* + %d", i);
            add_tok(n, same_in_bands(br_bases, 7, i), w);
        } else {
            snprintf(w, sizeof(w), "CP_BR_EXTRA_BASE + %d", i - 8);
            add_tok(n, fg_of(CP_BR_EXTRA_BASE + i - 8), w);
        }
    }
    for (int i = 0; i < 8; i++) {
        snprintf(n, sizeof(n), "--info-%d", i);
        snprintf(w, sizeof(w), "CP_INFO_BASE + %d", i);
        add_tok(n, fg_of(CP_INFO_BASE + i), w);
    }
    add_tok("--tui-bright", fg_of(CP_BRIGHT), "CP_BRIGHT");
    add_tok("--tui-normal", fg_of(CP_NORMAL), "CP_NORMAL");
    add_tok("--tui-dim", fg_of(CP_DIM), "CP_DIM");
    add_tok("--heat-0", fg_of(CP_HEAT_LO), "CP_HEAT_LO");
    add_tok("--heat-1", fg_of(CP_HEAT_MID), "CP_HEAT_MID");
    add_tok("--heat-2", fg_of(CP_HEAT_HI), "CP_HEAT_HI");
    add_tok("--heat-3", fg_of(CP_HEAT_PEAK), "CP_HEAT_PEAK");
    /* tui_alert_hot_attr(): LOW, WARN, CRIT */
    add_tok("--hot-0", fg_of(CP_ALERT_HOT_LOW), "CP_ALERT_HOT_LOW");
    add_tok("--hot-1", fg_of(CP_ALERT_HOT_WARN), "CP_ALERT_HOT_WARN");
    add_tok("--hot-2", fg_of(CP_ALERT_HOT_CRIT), "CP_ALERT_HOT_CRIT");
}

static void mon_pairs(void) {
    short f, b;
    if (!tui_pair_colors(CP_MON_ROW, &f, &b) || b < 0) {
        fprintf(stderr, "palette: CP_MON_ROW has no background\n");
        exit(1);
    }
    g_mon_x[0] = b;
    g_mon_x[1] = f;
}

/* ── files ─────────────────────────────────────────────────────────── */

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "palette: cannot open %s\n", path); return NULL; }
    char *b = malloc(FILE_MAX);
    size_t n = b ? fread(b, 1, FILE_MAX - 1, f) : 0;
    fclose(f);
    if (!b || n >= FILE_MAX - 1) {
        fprintf(stderr, "palette: %s: unreadable or too large\n", path);
        free(b);
        return NULL;
    }
    b[n] = '\0';
    return b;
}

/* ── src/tui.c's brand table, as text ──────────────────────────────── */

static const struct { const char *name; int v; } BR_NAMES[] = {
#define N(x) { #x, x }
    N(BR_GOOGLE_BLUE), N(BR_GOOGLE_RED), N(BR_GOOGLE_YELLOW), N(BR_GOOGLE_GREEN),
    N(BR_FIREFOX), N(BR_CLOUDFLARE), N(BR_EXAMPLE), N(BR_DISCORD),
    N(BR_FACEBOOK), N(BR_SPOTIFY), N(BR_TWITCH), N(BR_AMAZON),
    N(BR_LINKEDIN), N(BR_NETFLIX), N(BR_REDDIT), N(BR_INSTAGRAM),
#undef N
};

static int br_value(const char *s, size_t n) {
    for (size_t i = 0; i < sizeof(BR_NAMES) / sizeof(BR_NAMES[0]); i++)
        if (strlen(BR_NAMES[i].name) == n && !strncmp(BR_NAMES[i].name, s, n))
            return BR_NAMES[i].v;
    fprintf(stderr, "palette: src/tui.c names %.*s, which this tool does not know\n",
            (int)n, s);
    return -1;
}

static int ident_len(const char *p) {
    int n = 0;
    while ((p[n] >= 'A' && p[n] <= 'Z') || (p[n] >= '0' && p[n] <= '9') || p[n] == '_') n++;
    return n;
}

typedef struct { int brand; char sub[40]; } brand_t;
static brand_t g_brand[MAX_BRANDS];
static int g_nbrand;
static int g_gseq[16];
static int g_ngseq;

/* The block of `start` up to its "};", or NULL. */
static const char *block(const char *src, const char *start, const char **end) {
    const char *b = strstr(src, start);
    if (!b) return NULL;
    b += strlen(start);
    *end = strstr(b, "};");
    return *end ? b : NULL;
}

static int read_brands(const char *src) {
    const char *fb = strstr(src, "static int find_brand(");
    const char *e;
    const char *b = fb ? block(fb, "tbl[] = {", &e) : NULL;
    if (!b) { fprintf(stderr, "palette: no find_brand() table in src/tui.c\n"); return -1; }
    for (const char *p = b; p < e; p++) {
        if (p[0] == '/' && p[1] == '*') {          /* a comment */
            const char *c = strstr(p + 2, "*/");
            if (!c || c > e) break;
            p = c + 1;
            continue;
        }
        if (*p != '{') continue;
        p++;
        while (*p == ' ') p++;
        int il = ident_len(p);
        int v = br_value(p, (size_t)il);
        if (v < 0) return -1;
        p += il;
        while (*p == ' ' || *p == ',') p++;
        if (*p != '"') { fprintf(stderr, "palette: unreadable brand row\n"); return -1; }
        const char *q = strchr(p + 1, '"');
        size_t sl = q ? (size_t)(q - p - 1) : 0;
        if (!q || sl == 0 || sl >= sizeof(g_brand[0].sub) || g_nbrand >= MAX_BRANDS) {
            fprintf(stderr, "palette: unreadable brand row\n");
            return -1;
        }
        /* Only what can be a lower-case host name: the JS table is
         * written verbatim, and find_brand() lower-cases only its input. */
        for (size_t k = 0; k < sl; k++) {
            char ch = p[1 + k];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-')) {
                fprintf(stderr, "palette: brand substring %.*s is not a lower-case "
                                "host name part\n", (int)sl, p + 1);
                return -1;
            }
        }
        g_brand[g_nbrand].brand = v;
        memcpy(g_brand[g_nbrand].sub, p + 1, sl);
        g_brand[g_nbrand].sub[sl] = '\0';
        g_nbrand++;
        p = q;
    }
    if (g_nbrand == 0) { fprintf(stderr, "palette: empty brand table\n"); return -1; }

    const char *ab = strstr(src, "void tui_brand_addstr(");
    b = ab ? block(ab, "static const int gseq[] = {", &e) : NULL;
    if (!b || !strstr(ab, "if (brand == BR_GOOGLE_BLUE) {") ||
        !strstr(ab, "int slot = gseq[i % 6];")) {
        fprintf(stderr, "palette: tui_brand_addstr()'s Google sequence has changed shape\n");
        return -1;
    }
    for (const char *p = b; p < e; p++) {
        int il = ident_len(p);
        if (il == 0 || p[0] < 'A' || p[0] > 'Z') continue;
        int v = br_value(p, (size_t)il);
        if (v < 0 || g_ngseq >= 16) return -1;
        g_gseq[g_ngseq++] = v;
        p += il - 1;
    }
    if (g_ngseq != 6) { fprintf(stderr, "palette: want six Google letters\n"); return -1; }
    return 0;
}

/* ── web/ui/theme.css's chrome tokens ──────────────────────────────── */

typedef struct { char name[32]; char val[64]; } decl_t;
typedef struct { decl_t d[MAX_DECLS]; int n; } decls_t;

static int read_decls(const char *css, const char *head, decls_t *out) {
    out->n = 0;
    const char *b = strstr(css, head);
    if (!b) { fprintf(stderr, "palette: theme.css has no \"%s\" block\n", head); return -1; }
    b += strlen(head);
    const char *e = strchr(b, '}');
    if (!e) return -1;
    for (const char *p = b; p < e; p++) {
        if (p[0] == '/' && p[1] == '*') {
            const char *c = strstr(p + 2, "*/");
            if (!c || c > e) break;
            p = c + 1;
            continue;
        }
        if (!(p[0] == '-' && p[1] == '-')) continue;
        const char *colon = strchr(p, ':'), *semi = colon ? strchr(colon, ';') : NULL;
        if (!colon || !semi || semi > e || out->n >= MAX_DECLS) break;
        decl_t *d = &out->d[out->n++];
        snprintf(d->name, sizeof(d->name), "%.*s", (int)(colon - p), p);
        const char *v = colon + 1;
        while (*v == ' ') v++;
        snprintf(d->val, sizeof(d->val), "%.*s", (int)(semi - v), v);
        p = semi;
    }
    return 0;
}

static const char *find_decl(const decls_t *d, const char *name) {
    for (int i = 0; i < d->n; i++)
        if (!strcmp(d->d[i].name, name)) return d->d[i].val;
    return NULL;
}

static decls_t g_dark, g_light;

/* A token's hex in a theme: the light block over the dark one, var()
 * followed, the generated data colours included. -1 if not a hex. */
static int resolve(const char *name, int light, rgb_t *c, int depth);

static rgb_t g_data_dark[64], g_data_light[64];

/* The chart hues (--f-*) are categorical encodings theme.css defines;
 * their light values follow the same rule as the data colours. */
static int g_chart[16], g_nchart;
static rgb_t g_chart_light[16];

static int resolve(const char *name, int light, rgb_t *c, int depth) {
    if (depth > 8) return -1;
    for (int i = 0; i < g_ntok; i++)
        if (!strcmp(g_tok[i].name, name)) {
            *c = light ? g_data_light[i] : g_data_dark[i];
            return 0;
        }
    for (int i = 0; i < NMON; i++)
        if (!strcmp(MON_NAME[i], name)) {
            *c = g_mon[i][light];
            return 0;
        }
    if (light)
        for (int k = 0; k < g_nchart; k++)
            if (!strcmp(g_dark.d[g_chart[k]].name, name)) {
                *c = g_chart_light[k];
                return 0;
            }
    const char *v = light ? find_decl(&g_light, name) : NULL;
    if (!v) v = find_decl(&g_dark, name);
    if (!v) return -1;
    if (!strncmp(v, "var(", 4)) {
        char inner[32];
        const char *e = strchr(v, ')');
        if (!e || e - v - 4 >= (long)sizeof(inner)) return -1;
        snprintf(inner, sizeof(inner), "%.*s", (int)(e - v - 4), v + 4);
        return resolve(inner, light, c, depth + 1);
    }
    return parse_hex(v, c);
}

static rgb_t need(const char *name, int light) {
    rgb_t c;
    if (resolve(name, light, &c, 0) != 0) {
        fprintf(stderr, "palette: theme.css gives %s no hex value%s\n", name,
                light ? " in the light theme" : "");
        exit(1);
    }
    return c;
}


/* ── how far apart the chart hues are ─────────────────────────────── */

/* CIE L*a*b* (D65) of an sRGB colour, and CIEDE2000 (Sharma, Wu and
 * Dalal 2005, eq. 1-17) between two of them. */
typedef struct { double L, a, b; } lab_t;

static double lab_f(double t) { return t > 216.0 / 24389 ? cbrt(t) : (24389.0 / 27 * t + 16) / 116; }

static lab_t to_lab(rgb_t c) {
    double r = lin(c.r), g = lin(c.g), b = lin(c.b);
    double X = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047;
    double Y = 0.2126 * r + 0.7152 * g + 0.0722 * b;
    double Z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883;
    lab_t o = { 116 * lab_f(Y) - 16, 500 * (lab_f(X) - lab_f(Y)), 200 * (lab_f(Y) - lab_f(Z)) };
    return o;
}

static double deg(double r) { return r * 180 / M_PI; }
static double rad(double d) { return d * M_PI / 180; }

static double de2000(rgb_t x, rgb_t y) {
    lab_t p = to_lab(x), q = to_lab(y);
    double C1 = hypot(p.a, p.b), C2 = hypot(q.a, q.b), Cb = (C1 + C2) / 2;
    double G = 0.5 * (1 - sqrt(pow(Cb, 7) / (pow(Cb, 7) + pow(25, 7))));
    double a1 = p.a * (1 + G), a2 = q.a * (1 + G);
    double C1p = hypot(a1, p.b), C2p = hypot(a2, q.b);
    double h1 = C1p == 0 ? 0 : fmod(deg(atan2(p.b, a1)) + 360, 360);
    double h2 = C2p == 0 ? 0 : fmod(deg(atan2(q.b, a2)) + 360, 360);
    double dL = q.L - p.L, dC = C2p - C1p, dh = 0;
    if (C1p * C2p != 0) {
        dh = h2 - h1;
        if (dh > 180) dh -= 360;
        else if (dh < -180) dh += 360;
    }
    double dH = 2 * sqrt(C1p * C2p) * sin(rad(dh / 2));
    double Lb = (p.L + q.L) / 2, Cbp = (C1p + C2p) / 2, hb = h1 + h2;
    if (C1p * C2p != 0) {
        if (fabs(h1 - h2) <= 180) hb = (h1 + h2) / 2;
        else hb = h1 + h2 < 360 ? (h1 + h2 + 360) / 2 : (h1 + h2 - 360) / 2;
    }
    double T = 1 - 0.17 * cos(rad(hb - 30)) + 0.24 * cos(rad(2 * hb)) +
               0.32 * cos(rad(3 * hb + 6)) - 0.20 * cos(rad(4 * hb - 63));
    double dth = 30 * exp(-pow((hb - 275) / 25, 2));
    double RC = 2 * sqrt(pow(Cbp, 7) / (pow(Cbp, 7) + pow(25, 7)));
    double SL = 1 + 0.015 * pow(Lb - 50, 2) / sqrt(20 + pow(Lb - 50, 2));
    double SC = 1 + 0.045 * Cbp, SH = 1 + 0.015 * Cbp * T, RT = -sin(rad(2 * dth)) * RC;
    double l = dL / SL, c = dC / SC, h = dH / SH;
    return sqrt(l * l + c * c + h * h + RT * c * h);
}

/* The Flows chord draws each protocol in its hue and SMB1 in --sev-crit
 * beside them, each named in the legend. Two of them closer than this
 * (CIEDE2000) fail the build in either theme, so the light theme's rule
 * cannot pull two hues together unseen. */
#define CHART_APART_MIN 15.0

static int g_napart;
static struct { const char *a, *b; double d[2]; } g_apart[64];

static int chart_apart(void) {
    const char *nm[17];
    rgb_t c[2][17];
    int n = 0;
    for (int k = 0; k < g_nchart && n < 16; k++, n++) {
        nm[n] = g_dark.d[g_chart[k]].name;
        if (resolve(nm[n], 0, &c[0][n], 0) != 0) return -1;
        c[1][n] = g_chart_light[k];
    }
    nm[n] = "--sev-crit";
    c[0][n] = need(nm[n], 0);
    c[1][n] = need(nm[n], 1);
    n++;
    int bad = 0;
    g_napart = 0;
    for (int i = 0; i < n; i++)
        for (int j = i + 1; j < n; j++) {
            double d0 = de2000(c[0][i], c[0][j]), d1 = de2000(c[1][i], c[1][j]);
            if (d0 < CHART_APART_MIN || d1 < CHART_APART_MIN) {
                fprintf(stderr, "palette: %s and %s are %.1f (dark) / %.1f (light) apart, "
                                "under %.0f\n", nm[i], nm[j], d0, d1, CHART_APART_MIN);
                bad = 1;
            }
            if ((d0 < 30 || d1 < 30) && g_napart < 64) {
                g_apart[g_napart].a = nm[i];
                g_apart[g_napart].b = nm[j];
                g_apart[g_napart].d[0] = d0;
                g_apart[g_napart].d[1] = d1;
                g_napart++;
            }
        }
    return bad ? -1 : 0;
}

static int compute(void) {
    rgb_t lbg = need("--bg", 1), lpanel = need("--panel", 1), dbg = need("--bg", 0);
    for (int i = 0; i < g_ntok; i++) {
        g_data_dark[i] = xterm_rgb(g_tok[i].xterm);
        g_data_light[i] = light_variant(g_data_dark[i], lbg, lpanel);
    }
    g_nchart = 0;
    for (int i = 0; i < g_dark.n && g_nchart < 16; i++) {
        if (strncmp(g_dark.d[i].name, "--f-", 4)) continue;
        rgb_t c;
        /* A hue that names a data token (var(--tui-normal)) is that
         * token in both themes; resolve() reaches it before this entry
         * is counted, so it never finds itself. */
        if (resolve(g_dark.d[i].name, 0, &c, 0) != 0) {
            fprintf(stderr, "palette: %s is not a hex colour or a var() of one\n",
                    g_dark.d[i].name);
            return -1;
        }
        if (!strncmp(g_dark.d[i].val, "var(", 4)) {
            if (resolve(g_dark.d[i].name, 1, &g_chart_light[g_nchart], 0) != 0) return -1;
        } else {
            g_chart_light[g_nchart] = light_variant(c, lbg, lpanel);
        }
        g_chart[g_nchart++] = i;
    }
    mon_pairs();
    for (int i = 0; i < NMON; i++) g_mon[i][0] = xterm_rgb(g_mon_x[i]);
    g_mon[0][1] = light_ground(g_mon[0][0], dbg, lbg);
    for (int i = 1; i < NMON; i++) g_mon[i][1] = light_variant(g_mon[i][0], g_mon[0][1], g_mon[0][1]);
    return chart_apart();
}

/* ── output ────────────────────────────────────────────────────────── */

static int emit_css(FILE *o) {
    rgb_t lbg = need("--bg", 1);
    char h[8], h2[8];
    fprintf(o,
        "/* Generated by web/tools/palette.c from src/tui_palette.c's pair table\n"
        " * (tui_pair_colors(): tui_ip_fg, tui_brand_fg, tui_info_fg, the phosphor\n"
        " * and heat pairs, CP_MON_ROW), each xterm-256 index turned into hex by\n"
        " * the standard formula. Not committed; edit the TUI, not this.\n"
        " * Dark: the TUI's colours byte for byte. Light: the same hue and\n"
        " * saturation, the HSL lightness lowered in 0.005 steps until 4.5:1 on\n"
        " * both the light --bg and --panel (web/README.md, Design). */\n"
        ":root {\n");
    for (int i = 0; i < g_ntok; i++) {
        hex(g_data_dark[i], h);
        fprintf(o, "  %s: %s; /* xterm %d, %s */\n", g_tok[i].name, h, g_tok[i].xterm,
                g_tok[i].why);
    }
    static const char *const MON_WHY[NMON] = { "CP_MON_ROW's background", "CP_MON_ROW" };
    for (int i = 0; i < NMON; i++) {
        hex(g_mon[i][0], h);
        fprintf(o, "  %s: %s; /* xterm %d, %s */\n", MON_NAME[i], h, g_mon_x[i], MON_WHY[i]);
    }
    fprintf(o, "}\n");
    fprintf(o, ":root[data-theme=\"light\"] {\n");
    for (int i = 0; i < g_ntok; i++) {
        hex(g_data_light[i], h);
        hex(g_data_dark[i], h2);
        fprintf(o, "  %s: %s; /* from %s, %.1f:1 on --bg */\n", g_tok[i].name, h, h2,
                contrast(g_data_light[i], lbg));
    }
    for (int k = 0; k < g_nchart; k++) {
        const decl_t *d = &g_dark.d[g_chart[k]];
        if (!strncmp(d->val, "var(", 4)) continue;     /* follows its token */
        hex(g_chart_light[k], h);
        fprintf(o, "  %s: %s; /* chart hue, from %s */\n", d->name, h, d->val);
    }
    hex(g_mon[0][1], h);
    hex(g_mon[0][0], h2);
    fprintf(o, "  --mon-bg: %s; /* %s's contrast step off --bg, from the light --bg */\n",
            h, h2);
    for (int i = 1; i < NMON; i++) {
        hex(g_mon[i][1], h);
        hex(g_mon[i][0], h2);
        fprintf(o, "  %s: %s; /* from %s, %.1f:1 on --mon-bg */\n", MON_NAME[i], h, h2,
                contrast(g_mon[i][1], g_mon[0][1]));
    }
    fprintf(o, "}\n");
    return ferror(o) ? -1 : 0;
}

static int emit_js(FILE *o) {
    fprintf(o,
        "// Generated by web/tools/palette.c from src/tui.c (find_brand()'s table,\n"
        "// tui_brand_addstr()'s Google letters) and src/ip_color.h. Not committed.\n"
        "var SLOTH_PALETTE = {\n"
        "  ip: %d, info: 8, google: %d,\n"
        "  gseq: [", IP_NUM_COLORS, BR_GOOGLE_BLUE);
    for (int i = 0; i < g_ngseq; i++) fprintf(o, "%s%d", i ? ", " : "", g_gseq[i]);
    fprintf(o, "],\n  brands: [\n");
    for (int i = 0; i < g_nbrand; i++)
        fprintf(o, "    [%d, \"%s\"]%s\n", g_brand[i].brand, g_brand[i].sub,
                i + 1 < g_nbrand ? "," : "");
    fprintf(o, "  ]\n};\n");
    return ferror(o) ? -1 : 0;
}

static void row(const char *name, const char *what) {
    rgb_t c[2], bg[2], pn[2];
    for (int t = 0; t < 2; t++) {
        c[t] = need(name, t);
        bg[t] = need("--bg", t);
        pn[t] = need("--panel", t);
    }
    char h0[8], h1[8];
    hex(c[0], h0);
    hex(c[1], h1);
    double r[4] = { contrast(c[0], bg[0]), contrast(c[0], pn[0]),
                    contrast(c[1], bg[1]), contrast(c[1], pn[1]) };
    printf("| `%s` | %s | `%s` | %.2f%s | %.2f%s | `%s` | %.2f%s | %.2f%s |\n", name, what,
           h0, r[0], r[0] < 4.5 ? " *" : "", r[1], r[1] < 4.5 ? " *" : "",
           h1, r[2], r[2] < 4.5 ? " *" : "", r[3], r[3] < 4.5 ? " *" : "");
}

static int emit_contrast(void) {
    static const struct { const char *n, *w; } chrome[] = {
        { "--ink", "body text" }, { "--muted", "secondary text" },
        { "--faint", "disabled controls only" }, { "--brass", "eyebrow labels" },
        { "--phosphor", "chrome accent, no text" }, { "--phosphor-hi", "title" },
        { "--phosphor-mid", "chip text" }, { "--hover", "hover text, live pill" },
        { "--data", "canvas accent, no text" }, { "--signal", "selection edge, no text" },
    };
    printf("| token | use | dark | on --bg | on --panel | light | on --bg | on --panel |\n"
           "|---|---|---|---|---|---|---|---|\n");
    for (size_t i = 0; i < sizeof(chrome) / sizeof(chrome[0]); i++) row(chrome[i].n, chrome[i].w);
    for (int i = 0; i < g_ntok; i++) {
        const char *n = g_tok[i].name;
        const char *w = !strncmp(n, "--k-", 4) ? "IP / SSID hash"
                      : !strncmp(n, "--br-", 5) ? "brand"
                      : !strncmp(n, "--info-", 7) ? "record info"
                      : !strncmp(n, "--heat-", 7) ? "heat, severity"
                      : !strncmp(n, "--hot-", 6) ? "alert-hot address"
                      : "TUI phosphor";
        row(n, w);
    }
    for (int k = 0; k < g_nchart; k++) row(g_dark.d[g_chart[k]].name, "chart hue");
    /* Graphics that carry meaning want 3:1 (WCAG 1.4.11); the dotted
     * rules separate rows that are legible without them. */
    static const struct { const char *fg, *bg, *w; } gfx[] = {
        { "--rule", "--bg", "row rules" }, { "--rule", "--panel", "row rules, the warming cell" },
        { "--muted", "--rule", "the warming hatch, on its cell" },
        { "--muted", "--panel", "the warming hatch, on the panel" },
    };
    printf("\nGraphics (`*` under 3:1):\n\n| graphic | on | use | dark | light |\n"
           "|---|---|---|---|---|\n");
    for (size_t i = 0; i < sizeof(gfx) / sizeof(gfx[0]); i++) {
        double r0 = contrast(need(gfx[i].fg, 0), need(gfx[i].bg, 0));
        double r1 = contrast(need(gfx[i].fg, 1), need(gfx[i].bg, 1));
        printf("| `%s` | `%s` | %s | %.2f%s | %.2f%s |\n", gfx[i].fg, gfx[i].bg, gfx[i].w,
               r0, r0 < 3 ? " *" : "", r1, r1 < 3 ? " *" : "");
    }
    printf("\nChart hues closer than 30 (CIEDE2000) in either theme; under %.0f fails "
           "the build:\n\n| hues | dark | light |\n|---|---|---|\n", CHART_APART_MIN);
    for (int i = 0; i < g_napart; i++)
        printf("| `%s`, `%s` | %.1f | %.1f |\n", g_apart[i].a, g_apart[i].b,
               g_apart[i].d[0], g_apart[i].d[1]);
    printf("\nMonitor rows, on `--mon-bg` (`");
    for (int t = 0; t < 2; t++) {
        char h[8];
        hex(g_mon[0][t], h);
        printf("%s%s", h, t ? "` light)" : "` dark, `");
    }
    printf(":\n\n| token | dark | on --mon-bg | light | on --mon-bg |\n|---|---|---|---|---|\n");
    for (int i = 1; i < NMON; i++) {
        char a[8], b[8];
        hex(g_mon[i][0], a);
        hex(g_mon[i][1], b);
        double r0 = contrast(g_mon[i][0], g_mon[0][0]), r1 = contrast(g_mon[i][1], g_mon[0][1]);
        printf("| `%s` | `%s` | %.2f%s | `%s` | %.2f%s |\n", MON_NAME[i], a, r0,
               r0 < 4.5 ? " *" : "", b, r1, r1 < 4.5 ? " *" : "");
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: palette css TUI_C THEME_CSS OUT.css | js TUI_C OUT.js | "
                        "contrast TUI_C THEME_CSS\n");
        return 2;
    }
    const char *mode = argv[1];
    collect();
    char *tui = slurp(argv[2]);
    if (!tui || read_brands(tui) != 0) { free(tui); return 1; }
    free(tui);
    if (!strcmp(mode, "js") && argc == 4) {
        FILE *o = fopen(argv[3], "w");
        if (!o) { perror(argv[3]); return 1; }
        int rc = emit_js(o);
        if (fclose(o) != 0) rc = -1;
        return rc ? 1 : 0;
    }
    if ((strcmp(mode, "css") || argc != 5) && (strcmp(mode, "contrast") || argc != 4)) {
        fprintf(stderr, "palette: bad arguments\n");
        return 2;
    }
    char *css = slurp(argv[3]);
    if (!css) return 1;
    int ok = read_decls(css, "\n:root {", &g_dark) == 0 &&
             read_decls(css, "\n:root[data-theme=\"light\"] {", &g_light) == 0;
    free(css);
    if (!ok) return 1;
    if (compute() != 0) return 1;
    if (!strcmp(mode, "contrast")) return emit_contrast();
    FILE *o = fopen(argv[4], "w");
    if (!o) { perror(argv[4]); return 1; }
    int rc = emit_css(o);
    if (fclose(o) != 0) rc = -1;
    return rc ? 1 : 0;
}
