/* btsig_gen OUT.c [--company CSV] [--service CSV] [--appearance CSV]:
 * the Bluetooth SIG assigned-numbers table slothweb is built with
 * (web/src/web_btsig.h). Build time only; it opens the files it is
 * named and nothing else, and never the network.
 *
 * Each CSV is web/data/btsig/'s two-column form (value,name; RFC 4180:
 * a field may be double-quoted, "" is a quote inside one), written by
 * web/tools/update_btsig.sh from the SIG's YAML. A value is 0xHHHH (up
 * to four hex digits); a row whose value is not one, a field past 1 KiB
 * or a file past 8 MiB fails the build: a malformed table should not
 * quietly become a smaller one. A name is trimmed, every byte that is
 * not printable ASCII or well-formed UTF-8 becomes '?', and it is cut
 * to WEB_BTSIG_NAME_MAX bytes on a code-point boundary. The same value
 * twice in one table keeps the first. With no CSV at all the table is
 * empty and its source "none": the page shows the numbers alone. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_btsig.h"

#define MAX_BYTES  (8u << 20)
#define FIELD_MAX  1024
#define TABLES     3

typedef struct {
    web_btsig_ent_t *e;
    size_t           n, cap;
} tab_t;

static char   **g_names;
static size_t   g_nnames, g_names_cap;
static char     g_err[256];

static int utf8_len(const unsigned char *p, size_t n) {
    if (p[0] < 0x80) return p[0] >= 0x20 && p[0] != 0x7f ? 1 : 0;
    if (p[0] >= 0xc2 && p[0] <= 0xdf && n >= 2 && (p[1] & 0xc0) == 0x80) return 2;
    if (p[0] >= 0xe0 && p[0] <= 0xef && n >= 3 && (p[1] & 0xc0) == 0x80 &&
        (p[2] & 0xc0) == 0x80) {
        unsigned cp = ((p[0] & 0xf) << 12) | ((p[1] & 0x3f) << 6) | (p[2] & 0x3f);
        return cp >= 0x800 && (cp < 0xd800 || cp > 0xdfff) ? 3 : 0;
    }
    if (p[0] >= 0xf0 && p[0] <= 0xf4 && n >= 4 && (p[1] & 0xc0) == 0x80 &&
        (p[2] & 0xc0) == 0x80 && (p[3] & 0xc0) == 0x80) {
        unsigned cp = ((p[0] & 7) << 18) | ((p[1] & 0x3f) << 12) |
                      ((p[2] & 0x3f) << 6) | (p[3] & 0x3f);
        return cp >= 0x10000 && cp <= 0x10ffff ? 4 : 0;
    }
    return 0;
}

/* Trim, clean and cut a name in place. */
static void clean(char *s) {
    size_t n = strlen(s), a = 0;
    while (a < n && (s[a] == ' ' || s[a] == '\t')) a++;
    while (n > a && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    char out[FIELD_MAX + 1];
    size_t o = 0;
    for (size_t i = a; i < n;) {
        int l = utf8_len((const unsigned char *)s + i, n - i);
        if (l == 0) { if (o + 1 <= WEB_BTSIG_NAME_MAX) out[o++] = '?'; i++; continue; }
        if (o + (size_t)l > WEB_BTSIG_NAME_MAX) break;
        memcpy(out + o, s + i, (size_t)l);
        o += (size_t)l;
        i += (size_t)l;
    }
    out[o] = '\0';
    memcpy(s, out, o + 1);
}

static long name_index(const char *s) {
    for (size_t i = 0; i < g_nnames; i++)
        if (!strcmp(g_names[i], s)) return (long)i;
    if (g_nnames == g_names_cap) {
        size_t nc = g_names_cap ? g_names_cap * 2 : 1024;
        char **nn = realloc(g_names, nc * sizeof(*nn));
        if (!nn) return -1;
        g_names = nn;
        g_names_cap = nc;
    }
    g_names[g_nnames] = strdup(s);
    if (!g_names[g_nnames]) return -1;
    return (long)g_nnames++;
}

static int hex4(const char *s, long *out) {
    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return -1;
    s += 2;
    if (!*s || strlen(s) > 4) return -1;
    long v = 0;
    for (; *s; s++) {
        int d = *s >= '0' && *s <= '9' ? *s - '0'
              : *s >= 'a' && *s <= 'f' ? *s - 'a' + 10
              : *s >= 'A' && *s <= 'F' ? *s - 'A' + 10 : -1;
        if (d < 0) return -1;
        v = v * 16 + d;
    }
    *out = v;
    return 0;
}

static int add(tab_t *t, long v, long name) {
    for (size_t i = 0; i < t->n; i++) if (t->e[i].value == (uint16_t)v) return 0;
    if (t->n == t->cap) {
        size_t nc = t->cap ? t->cap * 2 : 256;
        web_btsig_ent_t *ne = realloc(t->e, nc * sizeof(*ne));
        if (!ne) return -1;
        t->e = ne;
        t->cap = nc;
    }
    t->e[t->n].value = (uint16_t)v;
    t->e[t->n].name = (uint32_t)name;
    t->n++;
    return 0;
}

/* One RFC 4180 field from p into out; returns the pointer past it (at
 * the comma, the newline or the end), or NULL on a field too long or
 * an unclosed quote. */
static const char *field(const char *p, const char *end, char *out, int *eol) {
    size_t o = 0;
    *eol = 0;
    if (p < end && *p == '"') {
        p++;
        for (;;) {
            if (p >= end) return NULL;
            if (*p == '"') {
                if (p + 1 < end && p[1] == '"') { if (o < FIELD_MAX) out[o++] = '"'; p += 2; continue; }
                p++;
                break;
            }
            if (o >= FIELD_MAX) return NULL;
            out[o++] = *p++;
        }
    } else {
        while (p < end && *p != ',' && *p != '\n') {
            if (o >= FIELD_MAX) return NULL;
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    while (p < end && *p != ',' && *p != '\n') p++;   /* a stray tail */
    if (p >= end || *p == '\n') *eol = 1;
    return p;
}

static int read_csv(tab_t *t, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(g_err, sizeof(g_err), "%s: cannot open", path); return -1; }
    char *buf = malloc(MAX_BYTES + 1);
    if (!buf) { fclose(f); snprintf(g_err, sizeof(g_err), "out of memory"); return -1; }
    size_t n = fread(buf, 1, MAX_BYTES + 1, f);
    fclose(f);
    if (n > MAX_BYTES) { free(buf); snprintf(g_err, sizeof(g_err), "%s: over 8 MiB", path); return -1; }
    const char *p = buf, *end = buf + n;
    if (n >= 3 && !memcmp(p, "\xef\xbb\xbf", 3)) p += 3;
    char a[FIELD_MAX + 1], b[FIELD_MAX + 1];
    int eol, line = 0, rows = 0;
    while (p < end) {
        line++;
        const char *q = field(p, end, a, &eol);
        if (!q) { snprintf(g_err, sizeof(g_err), "%s:%d: bad field", path, line); free(buf); return -1; }
        if (eol) {
            /* A one-field line: blank is skipped, anything else is wrong. */
            if (a[0]) { snprintf(g_err, sizeof(g_err), "%s:%d: one field", path, line); free(buf); return -1; }
            p = q < end ? q + 1 : q;
            continue;
        }
        q = field(q + 1, end, b, &eol);
        if (!q) { snprintf(g_err, sizeof(g_err), "%s:%d: bad field", path, line); free(buf); return -1; }
        if (!eol) { snprintf(g_err, sizeof(g_err), "%s:%d: more than two fields", path, line); free(buf); return -1; }
        p = q < end ? q + 1 : q;
        if (line == 1) {
            if (strcmp(a, "value") || strncmp(b, "name", 4)) {
                snprintf(g_err, sizeof(g_err), "%s: header is not value,name", path);
                free(buf);
                return -1;
            }
            continue;
        }
        long v;
        if (hex4(a, &v) != 0) {
            snprintf(g_err, sizeof(g_err), "%s:%d: value is not 0xHHHH", path, line);
            free(buf);
            return -1;
        }
        clean(b);
        if (!b[0]) continue;
        long ni = name_index(b);
        if (ni < 0 || add(t, v, ni) != 0) {
            snprintf(g_err, sizeof(g_err), "out of memory");
            free(buf);
            return -1;
        }
        rows++;
    }
    free(buf);
    if (rows == 0) { snprintf(g_err, sizeof(g_err), "%s: no row", path); return -1; }
    return 0;
}

static int by_value(const void *a, const void *b) {
    const web_btsig_ent_t *x = a, *y = b;
    return x->value < y->value ? -1 : x->value > y->value ? 1 : 0;
}

static void emit_str(FILE *out, const char *s) {
    fputc('"', out);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { fputc('\\', out); fputc(c, out); }
        /* Octal, never hex: three digits at most, so a digit that follows
         * cannot join the escape. */
        else if (c < 0x20 || c >= 0x7f) fprintf(out, "\\%03o", c);
        else fputc(c, out);
    }
    fputc('"', out);
}

static void emit_tab(FILE *out, const char *name, const tab_t *t) {
    fprintf(out, "static const web_btsig_ent_t btsig_%s[%zu] = {\n", name, t->n ? t->n : 1);
    for (size_t i = 0; i < t->n; i++)
        fprintf(out, "    { 0x%04x, %u },\n", (unsigned)t->e[i].value, (unsigned)t->e[i].name);
    if (!t->n) fprintf(out, "    { 0, 0 },\n");
    fprintf(out, "};\n");
}

int main(int argc, char **argv) {
    if (argc < 2 || (argc % 2) != 0) {
        fprintf(stderr, "usage: btsig_gen OUT.c [--company CSV] [--service CSV] "
                        "[--appearance CSV]\n");
        return 2;
    }
    static const char *const FLAG[TABLES] = { "--company", "--service", "--appearance" };
    static const char *const NAME[TABLES] = { "company", "service", "appearance" };
    tab_t tabs[TABLES];
    memset(tabs, 0, sizeof(tabs));
    int any = 0;
    for (int i = 2; i + 1 < argc; i += 2) {
        int k = -1;
        for (int j = 0; j < TABLES; j++) if (!strcmp(argv[i], FLAG[j])) k = j;
        if (k < 0) { fprintf(stderr, "btsig_gen: unknown flag %s\n", argv[i]); return 2; }
        if (read_csv(&tabs[k], argv[i + 1]) != 0) {
            fprintf(stderr, "btsig_gen: %s\n", g_err);
            return 1;
        }
        any = 1;
    }
    for (int j = 0; j < TABLES; j++)
        qsort(tabs[j].e, tabs[j].n, sizeof(tabs[j].e[0]), by_value);
    FILE *out = fopen(argv[1], "w");
    if (!out) { perror(argv[1]); return 1; }
    fprintf(out, "/* Generated by web/tools/btsig_gen.c from web/data/btsig/; build "
                 "output, never committed. */\n#include \"web_btsig.h\"\n\n");
    fprintf(out, "static const char *const btsig_names[%zu] = {\n", g_nnames ? g_nnames : 1);
    for (size_t i = 0; i < g_nnames; i++) { fputs("    ", out); emit_str(out, g_names[i]); fputs(",\n", out); }
    if (!g_nnames) fputs("    \"\",\n", out);
    fprintf(out, "};\n");
    for (int j = 0; j < TABLES; j++) emit_tab(out, NAME[j], &tabs[j]);
    fprintf(out, "const web_btsig_tab_t web_btsig_generated = {\n"
                 "    btsig_company, %zu, btsig_service, %zu, btsig_appearance, %zu,\n"
                 "    btsig_names, %zu, \"%s\"\n};\n",
            tabs[0].n, tabs[1].n, tabs[2].n, g_nnames, any ? "sig" : "none");
    int rc = fclose(out) == 0 ? 0 : 1;
    fprintf(stderr, "btsig_gen: %s table: %zu companies, %zu services, %zu appearances"
                    "%s\n", any ? "sig" : "none", tabs[0].n, tabs[1].n, tabs[2].n,
            any ? "" : "; no CSV in WEB_BTSIG_DIR: the full table is built from "
                       "web/data/btsig/ (web/data/btsig/SOURCE.md)");
    return rc;
}
