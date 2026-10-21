/* Build-time page embedder (#158). Not part of slothweb.
 *
 *   embed UI_DIR ROOT OUT.c
 *
 * Reads UI_DIR/ROOT and replaces every line that is exactly
 * "@include NAME" (leading blanks allowed) with the bytes of UI_DIR/NAME,
 * so the page is one document with its CSS and JS inline and the server
 * has one thing to serve. Includes do not nest, and NAME is a bare file
 * name: the page can only be assembled from web/ui/ itself.
 *
 * The assembled page must hold exactly one <style> and one <script>
 * element, without attributes. Their contents are hashed into the
 * Content-Security-Policy, so the policy can say default-src 'none' and
 * allow those two blocks and nothing else, instead of 'unsafe-inline'.
 * The ETag is a digest of the whole page.
 *
 * OUT.c is generated under build/ and never committed. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define PAGE_MAX (1024 * 1024)

static char *slurp(const char *dir, const char *name, size_t *len) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "embed: cannot open %s\n", path); return NULL; }
    char *b = malloc(PAGE_MAX);
    size_t n = b ? fread(b, 1, PAGE_MAX, f) : 0;
    int too_big = b && n == PAGE_MAX;
    fclose(f);
    if (!b || too_big) {
        fprintf(stderr, "embed: %s: too large\n", path);
        free(b);
        return NULL;
    }
    *len = n;
    return b;
}

static int bare_name(const char *s, size_t n) {
    if (n == 0 || s[0] == '.') return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int append(char *dst, size_t *dl, const char *src, size_t n) {
    if (*dl + n >= PAGE_MAX) { fprintf(stderr, "embed: page too large\n"); return -1; }
    memcpy(dst + *dl, src, n);
    *dl += n;
    return 0;
}

/* The single element named tag: its content offsets. 0, or -1 when the
 * page has none, more than one, or one with attributes. */
static int one_element(const char *p, size_t len, const char *tag,
                       size_t *start, size_t *end) {
    char open[32], close_[32], any[32];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close_, sizeof(close_), "</%s>", tag);
    snprintf(any, sizeof(any), "<%s", tag);
    int count = 0;
    for (size_t i = 0; i + strlen(any) <= len; i++)
        if (!memcmp(p + i, any, strlen(any))) count++;
    const char *o = strstr(p, open);
    if (count != 1 || !o) {
        fprintf(stderr, "embed: want exactly one <%s> without attributes\n", tag);
        return -1;
    }
    *start = (size_t)(o - p) + strlen(open);
    const char *c = strstr(p + *start, close_);
    if (!c || strstr(c + 1, close_)) {
        fprintf(stderr, "embed: want exactly one </%s>\n", tag);
        return -1;
    }
    *end = (size_t)(c - p);
    return 0;
}

static void hash_b64(const char *p, size_t n, char out[64]) {
    uint8_t d[32];
    web_sha256(p, n, d);
    web_base64(d, 32, out);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: embed UI_DIR ROOT OUT.c\n");
        return 2;
    }
    const char *dir = argv[1];
    size_t rl;
    char *root = slurp(dir, argv[2], &rl);
    if (!root) return 1;
    char *page = malloc(PAGE_MAX);
    if (!page) return 1;
    size_t pl = 0;

    size_t pos = 0;
    while (pos < rl) {
        const char *nl = memchr(root + pos, '\n', rl - pos);
        size_t ll = nl ? (size_t)(nl - (root + pos)) + 1 : rl - pos;
        const char *line = root + pos;
        size_t i = 0;
        while (i < ll && (line[i] == ' ' || line[i] == '\t')) i++;
        if (ll - i > 9 && !memcmp(line + i, "@include ", 9)) {
            const char *nm = line + i + 9;
            size_t nn = ll - i - 9;
            while (nn && (nm[nn - 1] == '\n' || nm[nn - 1] == '\r')) nn--;
            char name[256];
            if (!bare_name(nm, nn) || nn >= sizeof(name)) {
                fprintf(stderr, "embed: bad @include at offset %zu\n", pos);
                return 1;
            }
            memcpy(name, nm, nn);
            name[nn] = '\0';
            size_t il;
            char *inc = slurp(dir, name, &il);
            if (!inc) return 1;
            if (append(page, &pl, inc, il) != 0) return 1;
            if (il && inc[il - 1] != '\n' && append(page, &pl, "\n", 1) != 0)
                return 1;
            free(inc);
        } else if (append(page, &pl, line, ll) != 0) {
            return 1;
        }
        pos += ll;
    }
    page[pl] = '\0';
    if (strlen(page) != pl) { fprintf(stderr, "embed: NUL in page\n"); return 1; }

    size_t ss, se, cs, ce;
    if (one_element(page, pl, "style", &ss, &se) != 0 ||
        one_element(page, pl, "script", &cs, &ce) != 0)
        return 1;
    char style_h[64], script_h[64];
    hash_b64(page + ss, se - ss, style_h);
    hash_b64(page + cs, ce - cs, script_h);

    uint8_t d[32];
    web_sha256(page, pl, d);

    FILE *o = fopen(argv[3], "w");
    if (!o) { fprintf(stderr, "embed: cannot write %s\n", argv[3]); return 1; }
    fprintf(o, "/* GENERATED by web/tools/embed.c from %s/%s.\n"
               " * Do not edit, do not commit: make regenerates it. */\n"
               "#include \"web_assets.h\"\n\n"
               "const unsigned char web_page[] = {\n", dir, argv[2]);
    for (size_t k = 0; k < pl; k++)
        fprintf(o, "0x%02x,%s", (unsigned char)page[k], k % 16 == 15 ? "\n" : "");
    fprintf(o, "0x00\n};\n");
    fprintf(o, "const size_t web_page_len = %zu;\n", pl);
    fprintf(o, "const char web_page_etag[] = \"\\\"");
    for (int k = 0; k < 16; k++) fprintf(o, "%02x", d[k]);
    fprintf(o, "\\\"\";\n");
    fprintf(o, "const char web_page_csp[] =\n"
               "    \"default-src 'none'; script-src 'sha256-%s'; \"\n"
               "    \"style-src 'sha256-%s'; connect-src 'self'; \"\n"
               "    \"base-uri 'none'; form-action 'none'; frame-ancestors 'none'\";\n",
            script_h, style_h);
    if (fclose(o) != 0) return 1;
    free(page);
    free(root);
    return 0;
}
