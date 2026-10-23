#include "oui_csv.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void oui_build_init(oui_build_t *b) { memset(b, 0, sizeof(*b)); }

void oui_build_free(oui_build_t *b) {
    for (size_t i = 0; i < b->nnames; i++) free(b->names[i]);
    free(b->names);
    free(b->e);
    memset(b, 0, sizeof(*b));
}

/* The reason, as "<path>: <what>" or "<path>: row <n>: <what>". */
static int fail(oui_build_t *b, const char *path, unsigned long row,
                const char *what) {
    if (row) snprintf(b->err, sizeof(b->err), "%s: row %lu: %s", path, row, what);
    else     snprintf(b->err, sizeof(b->err), "%s: %s", path, what);
    return -1;
}

/* The whole file, NUL-terminated, at most OUI_CSV_MAX_BYTES. */
static char *slurp(oui_build_t *b, const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(b->err, sizeof(b->err), "%s: %s", path, strerror(errno));
        return NULL;
    }
    size_t cap = 1 << 16, n = 0;
    char *buf = malloc(cap);
    while (buf) {
        if (n + 1 >= cap) {
            if (cap > OUI_CSV_MAX_BYTES) {
                free(buf);
                fclose(f);
                fail(b, path, 0, "larger than 64 MiB");
                return NULL;
            }
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb;
        }
        size_t r = fread(buf + n, 1, cap - 1 - n, f);
        n += r;
        if (r == 0) break;
    }
    int bad = ferror(f);
    fclose(f);
    if (!buf) { fail(b, path, 0, "out of memory"); return NULL; }
    if (bad) { free(buf); fail(b, path, 0, "read error"); return NULL; }
    if (n > OUI_CSV_MAX_BYTES) {
        free(buf);
        fail(b, path, 0, "larger than 64 MiB");
        return NULL;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* Length of the well-formed UTF-8 sequence at p (RFC 3629), 0 if none.
 * The tool links nothing from web/src/, so it has its own. */
static size_t utf8_seq(const unsigned char *p, size_t n) {
    if (!n) return 0;
    unsigned c = p[0];
    size_t len;
    unsigned cp, min;
    if (c < 0x80) return 1;
    if (c >= 0xc2 && c <= 0xdf) { len = 2; cp = c & 0x1f; min = 0x80; }
    else if (c >= 0xe0 && c <= 0xef) { len = 3; cp = c & 0x0f; min = 0x800; }
    else if (c >= 0xf0 && c <= 0xf4) { len = 4; cp = c & 0x07; min = 0x10000; }
    else return 0;
    if (n < len) return 0;
    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xc0) != 0x80) return 0;
        cp = (cp << 6) | (p[i] & 0x3f);
    }
    if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return 0;
    return len;
}

/* The display form of a registry name into out (WEB_OUI_NAME_MAX + 1):
 * trimmed, a control byte or an invalid sequence as '?', cut on a
 * code-point boundary. */
static void clean_name(const char *s, size_t n, char *out) {
    while (n && (*s == ' ' || *s == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) n--;
    size_t o = 0, i = 0;
    while (i < n) {
        const unsigned char *p = (const unsigned char *)s + i;
        size_t l = utf8_seq(p, n - i);
        if (l == 1 && (p[0] < 0x20 || p[0] == 0x7f)) l = 0;
        size_t take = l ? l : 1;
        if (o + take > WEB_OUI_NAME_MAX) break;
        if (l) memcpy(out + o, p, l);
        else out[o] = '?';
        o += take;
        i += l ? l : 1;
    }
    out[o] = '\0';
}

/* ── names, deduplicated ─────────────────────────────────────────────── */

static uint32_t name_hash(const char *s) {
    uint32_t h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

/* A small open-addressed index over b->names, rebuilt as it grows. */
typedef struct {
    uint32_t *slot;   /* name index + 1; 0 empty */
    size_t    cap;
} name_ix_t;

static int ix_grow(name_ix_t *ix, const oui_build_t *b) {
    size_t cap = ix->cap ? ix->cap * 2 : 4096;
    uint32_t *s = calloc(cap, sizeof(*s));
    if (!s) return -1;
    for (size_t i = 0; i < b->nnames; i++) {
        size_t h = name_hash(b->names[i]) & (cap - 1);
        while (s[h]) h = (h + 1) & (cap - 1);
        s[h] = (uint32_t)i + 1;
    }
    free(ix->slot);
    ix->slot = s;
    ix->cap = cap;
    return 0;
}

static long name_id(oui_build_t *b, name_ix_t *ix, const char *name) {
    if ((b->nnames + 1) * 2 > ix->cap && ix_grow(ix, b) != 0) return -1;
    size_t h = name_hash(name) & (ix->cap - 1);
    while (ix->slot[h]) {
        uint32_t k = ix->slot[h] - 1;
        if (!strcmp(b->names[k], name)) return (long)k;
        h = (h + 1) & (ix->cap - 1);
    }
    if (b->nnames == b->names_cap) {
        size_t nc = b->names_cap ? b->names_cap * 2 : 1024;
        char **nn = realloc(b->names, nc * sizeof(*nn));
        if (!nn) return -1;
        b->names = nn;
        b->names_cap = nc;
    }
    char *copy = malloc(strlen(name) + 1);
    if (!copy) return -1;
    memcpy(copy, name, strlen(name) + 1);
    b->names[b->nnames] = copy;
    ix->slot[h] = (uint32_t)b->nnames + 1;
    return (long)b->nnames++;
}

static int add(oui_build_t *b, name_ix_t *ix, uint64_t prefix, int cls,
               const char *name) {
    if (!name[0]) return 0;
    if (b->n == b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        web_oui_ent_t *ne = realloc(b->e, nc * sizeof(*ne));
        if (!ne) return -1;
        b->e = ne;
        b->cap = nc;
    }
    long id = name_id(b, ix, name);
    if (id < 0) return -1;
    b->e[b->n].key = web_oui_key(prefix, cls);
    b->e[b->n].name = (uint32_t)id;
    b->n++;
    return 0;
}

/* ── the registry CSV ────────────────────────────────────────────────── */

typedef struct {
    const char *p, *end;
    char        f[4][OUI_CSV_FIELD_MAX + 1];
    size_t      fl[4];
    int         nf;
} csv_t;

/* The next record's first four fields. 1 a record, 0 the end, -1 a
 * field past OUI_CSV_FIELD_MAX or an unterminated quote. */
static int csv_row(csv_t *c) {
    if (c->p >= c->end) return 0;
    c->nf = 0;
    for (int i = 0; i < 4; i++) { c->fl[i] = 0; c->f[i][0] = '\0'; }
    for (;;) {
        int k = c->nf;
        size_t o = 0;
        char *dst = k < 4 ? c->f[k] : NULL;
        if (c->p < c->end && *c->p == '"') {
            c->p++;
            for (;;) {
                if (c->p >= c->end) return -1;
                if (*c->p == '"') {
                    if (c->p + 1 < c->end && c->p[1] == '"') { c->p++; }
                    else { c->p++; break; }
                }
                if (dst) {
                    if (o >= OUI_CSV_FIELD_MAX) return -1;
                    dst[o++] = *c->p;
                }
                c->p++;
            }
        }
        while (c->p < c->end && *c->p != ',' && *c->p != '\n') {
            if (dst && *c->p != '\r') {
                if (o >= OUI_CSV_FIELD_MAX) return -1;
                dst[o++] = *c->p;
            }
            c->p++;
        }
        if (dst) { dst[o] = '\0'; c->fl[k] = o; }
        c->nf++;
        if (c->p >= c->end) return 1;
        if (*c->p == '\n') { c->p++; return 1; }
        c->p++;                                  /* the comma */
    }
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, size_t n, size_t want, uint64_t *out) {
    if (n != want) return -1;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        int h = hexval((unsigned char)s[i]);
        if (h < 0) return -1;
        v = v * 16 + (uint64_t)h;
    }
    *out = v;
    return 0;
}

int oui_build_csv(oui_build_t *b, const char *path) {
    size_t len = 0;
    char *buf = slurp(b, path, &len);
    if (!buf) return -1;
    name_ix_t ix = { NULL, 0 };
    if (ix_grow(&ix, b) != 0) { free(buf); return fail(b, path, 0, "out of memory"); }
    csv_t *c = malloc(sizeof(*c));
    if (!c) { free(buf); free(ix.slot); return fail(b, path, 0, "out of memory"); }
    c->p = buf;
    c->end = buf + len;
    /* A UTF-8 byte order mark before the header. */
    if (len >= 3 && !memcmp(buf, "\xef\xbb\xbf", 3)) c->p += 3;
    unsigned long row = 0;
    int rc = 0, r;
    while ((r = csv_row(c)) == 1) {
        row++;
        if (row > OUI_CSV_MAX_ROWS) { rc = fail(b, path, 0, "more than 262144 rows"); break; }
        if (c->nf == 1 && c->fl[0] == 0) continue;          /* blank line */
        if (row == 1 && !strcmp(c->f[0], "Registry")) continue;
        int cls;
        size_t want;
        if (!strcmp(c->f[0], "MA-L")) { cls = WEB_OUI_MAL; want = 6; }
        else if (!strcmp(c->f[0], "MA-M")) { cls = WEB_OUI_MAM; want = 7; }
        else if (!strcmp(c->f[0], "MA-S") || !strcmp(c->f[0], "IAB")) { cls = WEB_OUI_MAS; want = 9; }
        else { b->skipped++; continue; }
        uint64_t prefix;
        if (c->nf < 3 || parse_hex(c->f[1], c->fl[1], want, &prefix) != 0) {
            rc = fail(b, path, row, "assignment is not its registry's hex length");
            break;
        }
        char name[WEB_OUI_NAME_MAX + 1];
        clean_name(c->f[2], c->fl[2], name);
        if (add(b, &ix, prefix, cls, name) != 0) { rc = fail(b, path, 0, "out of memory"); break; }
    }
    if (r < 0 && rc == 0)
        rc = fail(b, path, row + 1, "a field past 4 KiB or an unterminated quote");
    free(c);
    free(ix.slot);
    free(buf);
    return rc;
}

/* ── sloth's src/oui.c ───────────────────────────────────────────────── */

int oui_build_sloth(oui_build_t *b, const char *path) {
    size_t len = 0;
    char *buf = slurp(b, path, &len);
    if (!buf) return -1;
    name_ix_t ix = { NULL, 0 };
    if (ix_grow(&ix, b) != 0) { free(buf); return fail(b, path, 0, "out of memory"); }
    int rc = 0;
    for (const char *p = buf; (p = strstr(p, "{ 0x")) != NULL; p += 4) {
        const char *h = p + 4;
        size_t n = 0;
        while (n < 7 && hexval((unsigned char)h[n]) >= 0) n++;
        uint64_t prefix;
        if (parse_hex(h, n, 6, &prefix) != 0) continue;
        const char *q = strchr(h + n, '"');
        const char *nl = strchr(h + n, '\n');
        if (!q || (nl && nl < q)) continue;
        const char *e = strchr(q + 1, '"');
        if (!e || (nl && nl < e)) continue;
        char name[WEB_OUI_NAME_MAX + 1];
        clean_name(q + 1, (size_t)(e - q - 1), name);
        if (add(b, &ix, prefix, WEB_OUI_MAL, name) != 0) { rc = fail(b, path, 0, "out of memory"); break; }
    }
    free(ix.slot);
    free(buf);
    return rc;
}

/* Sort by key, keeping the earliest row of equal keys (qsort is not
 * stable, so a merge sort over row positions), then drop the later
 * duplicates. */
int oui_build_finish(oui_build_t *b, const char *source) {
    size_t n = b->n;
    size_t *pos = malloc((n ? n : 1) * sizeof(*pos));
    size_t *aux = malloc((n ? n : 1) * sizeof(*aux));
    web_oui_ent_t *tmp = malloc((n ? n : 1) * sizeof(*tmp));
    if (!pos || !aux || !tmp) {
        free(pos); free(aux); free(tmp);
        snprintf(b->err, sizeof(b->err), "out of memory");
        return -1;
    }
    for (size_t i = 0; i < n; i++) pos[i] = i;
    for (size_t w = 1; w < n; w *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * w) {
            size_t mid = lo + w < n ? lo + w : n;
            size_t hi = lo + 2 * w < n ? lo + 2 * w : n;
            size_t i = lo, j = mid, k = lo;
            while (i < mid && j < hi)
                aux[k++] = b->e[pos[j]].key < b->e[pos[i]].key ? pos[j++] : pos[i++];
            while (i < mid) aux[k++] = pos[i++];
            while (j < hi) aux[k++] = pos[j++];
        }
        memcpy(pos, aux, n * sizeof(*pos));
    }
    size_t u = 0;
    for (size_t i = 0; i < n; i++) {
        const web_oui_ent_t *e = &b->e[pos[i]];
        if (u && tmp[u - 1].key == e->key) { b->duplicates++; continue; }
        tmp[u++] = *e;
    }
    if (u) memcpy(b->e, tmp, u * sizeof(*tmp));
    free(pos);
    free(aux);
    free(tmp);
    b->n = u;
    memset(b->counts, 0, sizeof(b->counts));
    for (size_t i = 0; i < u; i++) b->counts[b->e[i].key & 3]++;
    b->tab.e = b->e;
    b->tab.n = b->n;
    b->tab.names = (const char *const *)b->names;
    b->tab.nnames = b->nnames;
    b->tab.source = source;
    memcpy(b->tab.counts, b->counts, sizeof(b->counts));
    return 0;
}

/* A C string literal of s: everything but [A-Za-z0-9 .,-] as an octal
 * escape, so no byte of a registry name can end the literal, start a
 * trigraph or a comment, or splice a line. */
static void emit_str(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned c = *p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ' ' || c == '.' || c == ',' ||
            c == '-')
            fputc((int)c, out);
        else
            fprintf(out, "\\%03o", c);
    }
    fputc('"', out);
}

int oui_build_emit(const oui_build_t *b, FILE *out) {
    fprintf(out, "/* GENERATED by web/tools/oui_gen.c: never edit, never commit.\n"
                 " * source %s: %u MA-L, %u MA-M, %u MA-S/IAB assignments,\n"
                 " * %zu names. */\n"
                 "#include \"web_oui.h\"\n\n",
            b->tab.source, b->counts[0], b->counts[1], b->counts[2],
            b->nnames);
    fprintf(out, "static const char *const NAMES[] = {\n");
    if (!b->nnames) fprintf(out, "    \"\",\n");
    for (size_t i = 0; i < b->nnames; i++) {
        fprintf(out, "    ");
        emit_str(out, b->names[i]);
        fprintf(out, ",\n");
    }
    fprintf(out, "};\n\nstatic const web_oui_ent_t ENTS[] = {\n");
    if (!b->n) fprintf(out, "    { 0, 0 },\n");
    for (size_t i = 0; i < b->n; i++)
        fprintf(out, "    { 0x%011llxULL, %lu },\n",
                (unsigned long long)b->e[i].key, (unsigned long)b->e[i].name);
    fprintf(out, "};\n\nconst web_oui_tab_t web_oui_generated = {\n"
                 "    ENTS, %zu, NAMES, %zu, ", b->n, b->nnames);
    emit_str(out, b->tab.source);
    fprintf(out, ", { %u, %u, %u }\n};\n", b->counts[0], b->counts[1],
            b->counts[2]);
    return ferror(out) ? -1 : 0;
}
