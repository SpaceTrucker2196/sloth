/* Build-time alert assessment extractor. Not part of slothweb.
 *
 *   alertasm OUT.c DEF DIR
 *
 * Writes the table web/src/web_alertasm.h describes from every
 * DIR/<TYPE>.md (docs/wiki/alert-assessments/), one entry per document,
 * and the index from each X() row of DEF (include/sloth_alerts.def) to
 * its entry. DIR not existing, or holding no document, writes an empty
 * table: the page then says "no assessment yet" for every type.
 *
 * A document is read as the wiki writes pages (docs/CLAUDE.md): any
 * header lines (**Summary**, **Sources**, **Last updated**) before the
 * first "---"; then, when a "---" line opens one, a front matter of
 * "key: value" lines up to the next "---" ("- item" lines under a key
 * are joined to it with "; "); then the body, "# title" and "## "
 * sections. Every section is kept in order, its text reduced to words
 * (links to "text (url)", emphasis marks dropped, `code spans` and
 * [n] citation marks kept verbatim) except "Related pages", which is
 * the wiki's navigation. The section named Bibliography (or References)
 * becomes the list of entries, one per list item or "[n]" line, as
 * text: no URL is ever a link on the page. A line under an entry is
 * its continuation only when indented and with no blank line between;
 * any other prose there is the Bibliography's note, kept apart from
 * the entries.
 *
 * What stops the build, naming the file:
 *   - a stem that is not an X() row of DEF (a typo would otherwise
 *     ship an assessment no alert can reach);
 *   - a [n] in a section with no Bibliography entry n (entry n is the
 *     one that starts "[n]" or is the list item written "n. ", or the
 *     nth when none is numbered so); a [n] in `code`, or anywhere in
 *     "## Verification notes", is not this document's citation;
 *   - a file that cannot be read, or one past FILE_MAX.
 * web/tests/test_evidence.c :: test_assessment_generator runs this
 * binary on documents it writes and has seen each of the first two
 * fail. OUT.c is generated under build/ and never committed. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_MAX   (512 * 1024)
#define TYPE_MAX   256
#define NAME_MAX_  64
#define DOC_MAX    256
#define SEC_MAX    16
#define FM_MAX     24
#define BIB_MAX    64
#define TEXT_MAX   (64 * 1024)

typedef struct {
    char *heading, *text;
} sec_t;

typedef struct {
    char   name[NAME_MAX_];
    char   path[512];
    char  *title, *updated;
    char  *fk[FM_MAX], *fv[FM_MAX];
    int    nfm;
    sec_t  sec[SEC_MAX];
    int    nsec;
    char  *bib[BIB_MAX];
    int    nbib;
    char  *bib_note;           /* the Bibliography's prose, not an entry */
} doc_t;

static char  K[TYPE_MAX][NAME_MAX_];
static int   nk;
static doc_t D[DOC_MAX];
static int   nd;

static char *xdup(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) { fprintf(stderr, "alertasm: out of memory\n"); exit(1); }
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "alertasm: cannot open %s\n", path); return NULL; }
    char *b = malloc(FILE_MAX + 1);
    if (!b) { fclose(f); return NULL; }
    size_t n = fread(b, 1, FILE_MAX, f);
    int big = n == FILE_MAX;
    fclose(f);
    if (big) { fprintf(stderr, "alertasm: %s: too large\n", path); free(b); return NULL; }
    b[n] = '\0';
    if (strlen(b) != n) { fprintf(stderr, "alertasm: NUL in %s\n", path); free(b); return NULL; }
    return b;
}

static int read_def(const char *path) {
    char *t = slurp(path);
    if (!t) return -1;
    for (char *p = t; p && *p; ) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (!strncmp(p, "X(", 2)) {
            const char *a = p + 2, *c = strchr(a, ',');
            if (!c || (size_t)(c - a) >= NAME_MAX_ || nk == TYPE_MAX) {
                fprintf(stderr, "alertasm: %s: bad row: %s\n", path, p);
                free(t);
                return -1;
            }
            memcpy(K[nk], a, (size_t)(c - a));
            K[nk][c - a] = '\0';
            nk++;
        }
        p = nl ? nl + 1 : NULL;
    }
    free(t);
    if (!nk) { fprintf(stderr, "alertasm: %s has no X() rows\n", path); return -1; }
    return 0;
}

static int type_of(const char *name) {
    for (int i = 0; i < nk; i++)
        if (!strcmp(K[i], name)) return i;
    return -1;
}

/* ── text ─────────────────────────────────────────────────────────── */

typedef struct {
    char  *b;
    size_t n, cap;
} buf_t;

static void put(buf_t *o, const char *s, size_t n) {
    if (o->n + n + 1 > o->cap) {
        size_t c = o->cap ? o->cap * 2 : 256;
        while (c < o->n + n + 1) c *= 2;
        char *b = realloc(o->b, c);
        if (!b) { fprintf(stderr, "alertasm: out of memory\n"); exit(1); }
        o->b = b;
        o->cap = c;
    }
    memcpy(o->b + o->n, s, n);
    o->n += n;
    o->b[o->n] = '\0';
}

/* One line of Markdown as words: [text](url) as "text (url)", the
 * emphasis marks ** and __ dropped, `code` and [n] kept as written. */
static void plain(buf_t *o, const char *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        if (s[i] == '`') {
            const char *e = memchr(s + i + 1, '`', n - i - 1);
            size_t l = e ? (size_t)(e - (s + i)) + 1 : n - i;
            put(o, s + i, l);
            i += l;
        } else if (s[i] == '[') {
            const char *e = memchr(s + i + 1, ']', n - i - 1);
            if (e && (size_t)(e - s) + 1 < n && e[1] == '(') {
                const char *u = memchr(e + 2, ')', n - (size_t)(e + 2 - s));
                if (u) {
                    put(o, s + i + 1, (size_t)(e - (s + i + 1)));
                    put(o, " (", 2);
                    put(o, e + 2, (size_t)(u - (e + 2)));
                    put(o, ")", 1);
                    i = (size_t)(u - s) + 1;
                    continue;
                }
            }
            put(o, s + i, 1);
            i++;
        } else if (i + 1 < n && ((s[i] == '*' && s[i + 1] == '*') || (s[i] == '_' && s[i + 1] == '_'))) {
            i += 2;
        } else {
            put(o, s + i, 1);
            i++;
        }
    }
}

static const char *trim(const char *s, size_t *n) {
    while (*n && (*s == ' ' || *s == '\t')) { s++; (*n)--; }
    while (*n && (s[*n - 1] == ' ' || s[*n - 1] == '\t' || s[*n - 1] == '\r')) (*n)--;
    return s;
}

/* A list item's marker ("- ", "* ", "1. "), or 0. */
static size_t item(const char *s, size_t n) {
    if (n >= 2 && (s[0] == '-' || s[0] == '*') && s[1] == ' ') return 2;
    size_t d = 0;
    while (d < n && s[d] >= '0' && s[d] <= '9') d++;
    if (d && d + 1 < n && s[d] == '.' && s[d + 1] == ' ') return d + 2;
    return 0;
}

static int is_bib(const char *h) {
    return !strcmp(h, "Bibliography") || !strcmp(h, "References");
}

/* ── one document ─────────────────────────────────────────────────── */

static int read_doc(const char *dir, const char *file) {
    if (nd == DOC_MAX) { fprintf(stderr, "alertasm: too many documents\n"); return -1; }
    doc_t *d = &D[nd];
    memset(d, 0, sizeof(*d));
    size_t fl = strlen(file);
    if (fl - 3 >= NAME_MAX_) { fprintf(stderr, "alertasm: %s: name too long\n", file); return -1; }
    memcpy(d->name, file, fl - 3);
    d->name[fl - 3] = '\0';
    snprintf(d->path, sizeof(d->path), "%s/%s", dir, file);
    if (type_of(d->name) < 0) {
        fprintf(stderr, "alertasm: %s: %s is not an alert type in the .def\n", d->path, d->name);
        return -1;
    }
    char *t = slurp(d->path);
    if (!t) return -1;
    /* Lines, in place. */
    char *lines[8192] = { 0 };
    int nl = 0;
    for (char *p = t; p && *p && nl < 8192; ) {
        char *e = strchr(p, '\n');
        if (e) *e = '\0';
        lines[nl++] = p;
        p = e ? e + 1 : NULL;
    }
    int i = 0;
    /* The wiki's header lines, up to the first "---" (if there is one). */
    int first = -1;
    for (int k = 0; k < nl; k++) {
        size_t n = strlen(lines[k]);
        const char *s = trim(lines[k], &n);
        if (n == 3 && !strncmp(s, "---", 3)) { first = k; break; }
        if (n && s[0] == '#') break;          /* the body began: no front matter */
    }
    for (int k = 0; k < (first >= 0 ? first : 0); k++) {
        const char *s = lines[k];
        if (!strncmp(s, "**Last updated**", 16)) {
            const char *v = s + 16;
            while (*v == ':' || *v == ' ') v++;
            size_t n = strlen(v);
            v = trim(v, &n);
            d->updated = xdup(v, n);
        }
    }
    if (first >= 0) {
        i = first + 1;
        int last = -1;
        for (; i < nl; i++) {
            size_t n = strlen(lines[i]);
            const char *s = trim(lines[i], &n);
            if (n == 3 && !strncmp(s, "---", 3)) { i++; break; }
            if (!n || s[0] == '#') continue;
            if (n >= 2 && s[0] == '-' && s[1] == ' ' && last >= 0) {
                buf_t b = { 0, 0, 0 };
                put(&b, d->fv[last], strlen(d->fv[last]));
                if (d->fv[last][0]) put(&b, "; ", 2);
                size_t m = n - 2;
                const char *v = trim(s + 2, &m);
                put(&b, v, m);
                free(d->fv[last]);
                d->fv[last] = b.b;
                continue;
            }
            const char *c = memchr(s, ':', n);
            if (!c || d->nfm == FM_MAX) continue;
            size_t kn = (size_t)(c - s), vn = n - kn - 1;
            const char *v = trim(c + 1, &vn);
            if (vn >= 2 && (v[0] == '"' || v[0] == '\'') && v[vn - 1] == v[0]) { v++; vn -= 2; }
            d->fk[d->nfm] = xdup(s, kn);
            d->fv[d->nfm] = xdup(v, vn);
            if (!strcmp(d->fk[d->nfm], "last_updated") && !d->updated) d->updated = xdup(v, vn);
            last = d->nfm++;
        }
    }
    /* The body. */
    buf_t text = { 0, 0, 0 };
    char *heading = NULL;
    int para = 0, skip = 0;
    #define FLUSH() do { \
        if (heading && !skip) { \
            if (d->nsec == SEC_MAX) { fprintf(stderr, "alertasm: %s: too many sections\n", d->path); free(t); return -1; } \
            d->sec[d->nsec].heading = heading; \
            d->sec[d->nsec].text = text.b ? text.b : xdup("", 0); \
            d->nsec++; \
        } else { free(heading); free(text.b); } \
        heading = NULL; text.b = NULL; text.n = text.cap = 0; para = 0; \
    } while (0)
    for (; i < nl; i++) {
        size_t n = strlen(lines[i]);
        const char *s = trim(lines[i], &n);
        if (n >= 2 && s[0] == '#' && s[1] == ' ') {
            size_t m = n - 2;
            const char *v = trim(s + 2, &m);
            free(d->title);
            d->title = xdup(v, m);
            continue;
        }
        if (heading && !skip && n >= 4 && !strncmp(s, "### ", 4)) {
            /* A sub-heading inside a section: its words, on a paragraph
             * of their own. */
            size_t m = n - 4;
            const char *v = trim(s + 4, &m);
            if (text.n) put(&text, "\n\n", 2);
            para = 1;
            plain(&text, v, m);
            continue;
        }
        if (n >= 3 && !strncmp(s, "## ", 3)) {
            FLUSH();
            size_t m = n - 3;
            const char *v = trim(s + 3, &m);
            heading = xdup(v, m);
            /* The wiki's navigation, and the Bibliography, which is
             * the entries below rather than a section of text. */
            skip = !strcmp(heading, "Related pages") || is_bib(heading);
            continue;
        }
        if (!heading) continue;
        if (!n) { para = 1; continue; }
        if (is_bib(heading)) {
            size_t mk = item(s, n);
            if (mk || s[0] == '[') {
                if (d->nbib == BIB_MAX) { fprintf(stderr, "alertasm: %s: too many entries\n", d->path); free(t); return -1; }
                buf_t b = { 0, 0, 0 };
                /* "7. text" is entry [7]: the assessments number their
                 * lists with gaps (1, 2, 3, 7), and a body's [7] means
                 * the item written 7, not the fourth. */
                if (mk > 2 && s[0] >= '0' && s[0] <= '9') {
                    put(&b, "[", 1);
                    put(&b, s, mk - 2);
                    put(&b, "] ", 2);
                }
                plain(&b, s + mk, n - mk);
                d->bib[d->nbib++] = b.b ? b.b : xdup("", 0);
                para = 0;
            } else if (d->nbib && !para && (lines[i][0] == ' ' || lines[i][0] == '\t')) {
                /* An indented line straight under an entry: its
                 * continuation. */
                buf_t b = { 0, 0, 0 };
                put(&b, d->bib[d->nbib - 1], strlen(d->bib[d->nbib - 1]));
                put(&b, " ", 1);
                plain(&b, s, n);
                free(d->bib[d->nbib - 1]);
                d->bib[d->nbib - 1] = b.b;
            } else {
                /* Prose among the entries, after a blank line or not
                 * indented under one (MY_NETWORK_RECON.md's "(5. and
                 * 6. intentionally unused ...)", the "no public
                 * literature" notes): a note of its own, never a
                 * source's words. */
                buf_t b = { 0, 0, 0 };
                if (d->bib_note) {
                    put(&b, d->bib_note, strlen(d->bib_note));
                    put(&b, para ? "\n\n" : " ", para ? 2 : 1);
                    free(d->bib_note);
                }
                plain(&b, s, n);
                d->bib_note = b.b;
                para = 0;
            }
            continue;
        }
        if (text.n) put(&text, para ? "\n\n" : (item(s, n) ? "\n" : " "), para ? 2 : 1);
        para = 0;
        if (text.n > TEXT_MAX) continue;
        plain(&text, s, n);
    }
    FLUSH();
    #undef FLUSH
    free(t);
    nd++;
    return 0;
}

/* Every [n] outside the Bibliography resolves to an entry. */
static int bib_has(const doc_t *d, long n) {
    char tag[24];
    snprintf(tag, sizeof(tag), "[%ld]", n);
    int numbered = 0;
    for (int i = 0; i < d->nbib; i++) {
        if (d->bib[i][0] == '[') numbered = 1;
        if (!strncmp(d->bib[i], tag, strlen(tag))) return 1;
    }
    return !numbered && n >= 1 && n <= d->nbib;
}

static int check_cites(const doc_t *d) {
    for (int s = 0; s < d->nsec; s++) {
        const char *t = d->sec[s].text;
        /* The verification notes are an audit of the sources, and
         * name the sources' own reference numbers (CSA_ABUSE.md: the
         * KRACK paper's "[70]"); they cite nothing of this document. */
        if (!strcmp(d->sec[s].heading, "Verification notes")) continue;
        int code = 0;
        for (const char *p = t; *p; p++) {
            if (*p == '`') { code = !code; continue; }
            if (code || *p != '[') continue;
            char *e;
            long n = strtol(p + 1, &e, 10);
            if (e == p + 1 || *e != ']' || e[1] == '(') continue;
            if (!bib_has(d, n)) {
                fprintf(stderr, "alertasm: %s: [%ld] in \"%s\" has no Bibliography entry\n",
                        d->path, n, d->sec[s].heading);
                return -1;
            }
        }
    }
    return 0;
}

/* ── output ───────────────────────────────────────────────────────── */

static void c_string(FILE *o, const char *s) {
    if (!s) { fputs("NULL", o); return; }
    fputc('"', o);
    size_t col = 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"' || c == '?') { fprintf(o, "\\%c", c); col += 2; }
        else if (c < 0x20 || c >= 0x7f) { fprintf(o, "\\%03o", c); col += 4; }
        else { fputc(c, o); col++; }
        if (col >= 100 && s[1]) { fputs("\"\n    \"", o); col = 0; }
    }
    fputc('"', o);
}

static int by_name(const void *a, const void *b) {
    return strcmp(((const doc_t *)a)->name, ((const doc_t *)b)->name);
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: alertasm OUT.c DEF DIR\n");
        return 2;
    }
    if (read_def(argv[2]) != 0) return 1;
    DIR *dh = opendir(argv[3]);
    if (dh) {
        struct dirent *de;
        while ((de = readdir(dh)) != NULL) {
            size_t n = strlen(de->d_name);
            if (n < 4 || strcmp(de->d_name + n - 3, ".md") || de->d_name[0] == '.') continue;
            /* The directory's own index, if it keeps one. */
            if (!strcmp(de->d_name, "README.md") || !strcmp(de->d_name, "index.md")) continue;
            if (read_doc(argv[3], de->d_name) != 0) { closedir(dh); return 1; }
        }
        closedir(dh);
    }
    qsort(D, (size_t)nd, sizeof(D[0]), by_name);
    for (int i = 0; i < nd; i++)
        if (check_cites(&D[i]) != 0) return 1;

    FILE *o = fopen(argv[1], "w");
    if (!o) { fprintf(stderr, "alertasm: cannot write %s\n", argv[1]); return 1; }
    fprintf(o, "/* Generated by web/tools/alertasm.c from the .md files of %s. Do not edit. */\n"
               "#include <stddef.h>\n\n#include \"web_alertasm.h\"\n\n", argv[3]);
    for (int i = 0; i < nd; i++) {
        const doc_t *d = &D[i];
        fprintf(o, "static const char *const fk%d[] = {", i);
        for (int k = 0; k < d->nfm; k++) { fputs(k ? ", " : " ", o); c_string(o, d->fk[k]); }
        fprintf(o, "%s};\nstatic const char *const fv%d[] = {", d->nfm ? " " : " NULL ", i);
        for (int k = 0; k < d->nfm; k++) { fputs(k ? ", " : " ", o); c_string(o, d->fv[k]); }
        fprintf(o, "%s};\nstatic const web_asm_sec_t sec%d[] = {", d->nfm ? " " : " NULL ", i);
        for (int k = 0; k < d->nsec; k++) {
            fputs(k ? ",\n    { " : "\n    { ", o);
            c_string(o, d->sec[k].heading);
            fputs(", ", o);
            c_string(o, d->sec[k].text);
            fputs(" }", o);
        }
        fprintf(o, "%s};\nstatic const char *const bib%d[] = {", d->nsec ? "\n" : " { NULL, NULL } ", i);
        for (int k = 0; k < d->nbib; k++) { fputs(k ? ",\n    " : "\n    ", o); c_string(o, d->bib[k]); }
        fprintf(o, "%s};\n\n", d->nbib ? "\n" : " NULL ");
    }
    fprintf(o, "const web_asm_t web_asm[] = {\n");
    for (int i = 0; i < nd; i++) {
        const doc_t *d = &D[i];
        fputs("    { ", o); c_string(o, d->name);
        fputs(", ", o);      c_string(o, d->path);
        fputs(", ", o);      c_string(o, d->title ? d->title : "");
        fputs(", ", o);      c_string(o, d->updated ? d->updated : "");
        fprintf(o, ", fk%d, fv%d, %d, sec%d, %d, bib%d, %d, ", i, i, d->nfm, i, d->nsec, i, d->nbib);
        c_string(o, d->bib_note ? d->bib_note : "");
        fputs(" },\n", o);
    }
    if (!nd) fputs("    { NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, NULL, 0, NULL },\n", o);
    fprintf(o, "};\nconst int web_asm_n = %d;\n\n", nd);
    fprintf(o, "/* The entry of each .def row, by type number; -1 none. */\n"
               "const int web_asm_by_type[] = {");
    for (int t = 0; t < nk; t++) {
        int at = -1;
        for (int i = 0; i < nd; i++)
            if (!strcmp(D[i].name, K[t])) at = i;
        fprintf(o, "%s%d", t ? (t % 16 ? ", " : ",\n    ") : "\n    ", at);
    }
    fprintf(o, "\n};\nconst int web_asm_ntypes = %d;\n", nk);
    if (fclose(o) != 0) { fprintf(stderr, "alertasm: cannot write %s\n", argv[1]); return 1; }
    return 0;
}
