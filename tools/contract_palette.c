/* contract_palette json SLOTH_TUI_C OUT.json
 *
 * The contract artifact's palette/palette.json (#185 item 4, #184 C5):
 * the TUI's data colours, as data, for a presentation repository
 * (sloth-mesh) that cannot link src/tui_palette.c or parse src/tui.c.
 * The json half of what was web/tools/palette.c until sloth#235 moved
 * web/ out of this tree; the page's own half (its CSS, its light theme,
 * its contrast tables) is sloth-mesh's tools/palette.c, which reads this
 * file. Build time only; it opens the files it is named and nothing
 * else.
 *
 * The colours come from the TUI's colour-pair table itself: this tool
 * links src/tui_palette.c and asks tui_pair_colors() for every pair the
 * page mirrors (CP_IP_BASE_*, CP_BR_*, CP_INFO_BASE, the phosphor and
 * heat pairs, CP_ALERT_HOT_*, CP_MON_ROW and its background), then
 * turns each xterm-256 index into hex by the standard formula (16
 * system colours, the 6x6x6 cube on 0/95/135/175/215/255, the 24 greys
 * from 8 in steps of 10). The brand table and the Google letter
 * sequence live inside src/tui.c's find_brand() and tui_brand_addstr()
 * as static data, so they are read out of that file as text, and a
 * table this parser cannot read fails the build rather than shipping a
 * stale copy. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ip_color.h"
#include "tui.h"
#include "tui_palette.h"

#define FILE_MAX (1024 * 1024)
#define MAX_BRANDS 256

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

static void hex(rgb_t c, char out[8]) {
    snprintf(out, 8, "#%02x%02x%02x", c.r & 255, c.g & 255, c.b & 255);
}

/* ── the TUI's pairs ───────────────────────────────────────────────── */

typedef struct {
    char name[24];
    int  xterm;
    char why[48];
} tok_t;

static tok_t g_tok[64];
static int g_ntok;

/* The monitor rows' ground and text (CP_MON_ROW). The TUI draws a
 * monitor row's stamp in CP_MON_ROW too (packets.c draw_mon_row()), so
 * there is no CP_MON_ROW_DIM token. */
#define NMON 2
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

/* The contract artifact's palette.json (#185 item 4, #184 C5): what
 * this tool reads out of sloth, as data, so a presentation repository
 * that cannot link src/tui_palette.c or parse src/tui.c gets the same
 * answers. Sloth's side only: each pair's xterm-256 index and its hex
 * (the dark theme, which is the TUI byte for byte), the monitor rows'
 * pair, the brand table and the Google letters. The light variants are
 * not here: they are computed against the page's theme.css, which is
 * sloth-mesh's, not the sensor's. Strings are written through jstr(); every
 * one comes from this file or a brand substring, but the brand table is
 * parsed C source and is not trusted to be JSON-clean. */
static void jstr(FILE *o, const char *s) {
    fputc('"', o);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') fprintf(o, "\\%c", c);
        else if (c < 0x20) fprintf(o, "\\u%04x", c);
        else fputc(c, o);
    }
    fputc('"', o);
}

static int emit_json(FILE *o) {
    char h[8];
    static const char *const MON_WHY[NMON] = { "CP_MON_ROW background", "CP_MON_ROW" };
    mon_pairs();
    fprintf(o, "{\n  \"palette_format\": 1,\n"
               "  \"source\": \"src/tui_palette.c tui_pair_colors(); src/tui.c find_brand(), "
               "tui_brand_addstr(); src/ip_color.h\",\n"
               "  \"ip_colors\": %d,\n  \"info_colors\": 8,\n  \"google\": %d,\n"
               "  \"tokens\": [\n", IP_NUM_COLORS, BR_GOOGLE_BLUE);
    for (int i = 0; i < g_ntok; i++) {
        hex(xterm_rgb(g_tok[i].xterm), h);
        fprintf(o, "    {\"name\": ");
        jstr(o, g_tok[i].name);
        fprintf(o, ", \"xterm\": %d, \"hex\": \"%s\", \"pair\": ", g_tok[i].xterm, h);
        jstr(o, g_tok[i].why);
        fprintf(o, "},\n");
    }
    for (int i = 0; i < NMON; i++) {
        hex(xterm_rgb(g_mon_x[i]), h);
        fprintf(o, "    {\"name\": ");
        jstr(o, MON_NAME[i]);
        fprintf(o, ", \"xterm\": %d, \"hex\": \"%s\", \"pair\": ", g_mon_x[i], h);
        jstr(o, MON_WHY[i]);
        fprintf(o, "}%s\n", i + 1 < NMON ? "," : "");
    }
    fprintf(o, "  ],\n  \"gseq\": [");
    for (int i = 0; i < g_ngseq; i++) fprintf(o, "%s%d", i ? ", " : "", g_gseq[i]);
    fprintf(o, "],\n  \"brands\": [\n");
    for (int i = 0; i < g_nbrand; i++) {
        fprintf(o, "    {\"brand\": %d, \"match\": ", g_brand[i].brand);
        jstr(o, g_brand[i].sub);
        fprintf(o, "}%s\n", i + 1 < g_nbrand ? "," : "");
    }
    fprintf(o, "  ]\n}\n");
    return ferror(o) ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "json")) {
        fprintf(stderr, "usage: contract_palette json TUI_C OUT.json\n");
        return 2;
    }
    collect();
    char *tui = slurp(argv[2]);
    if (!tui || read_brands(tui) != 0) { free(tui); return 1; }
    free(tui);
    FILE *o = fopen(argv[3], "w");
    if (!o) { perror(argv[3]); return 1; }
    int rc = emit_json(o);
    if (fclose(o) != 0) rc = -1;
    return rc ? 1 : 0;
}
