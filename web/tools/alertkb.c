/* Build-time alert knowledge extractor. Not part of slothweb.
 *
 *   alertkb OUT.c DEF RULES.md WIKI.md REMEDIATION.md RESEARCH_DIR
 *
 * Writes the table web_alertkb.h describes, one entry per X() row of
 * DEF (include/sloth_alerts.def), from the rule table of RULES.md
 * (docs/views/alerts.md), the paragraphs of WIKI.md (docs/wiki/alerts.md)
 * that name the type, every research document under RESEARCH_DIR whose
 * frontmatter alert_kinds list it, and the type's section of
 * REMEDIATION.md (docs/wiki/alert-remediation.md). Nothing here is
 * written by hand: an edit to any of those files is what the page shows
 * after the next build.
 *
 * Missing pieces are emitted empty rather than stopping the build, so
 * web/tests/test_alertkb.c can name every type that lacks one; a file
 * that cannot be read, a DEF with no rows or one past TYPE_MAX does stop
 * it. OUT.c is generated under build/ and never committed. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define FILE_MAX   (2 * 1024 * 1024)
#define TYPE_MAX   256
#define NAME_MAX_  64
#define DOC_MAX    256
#define PATH_MAX_  512
#define STEP_MAX   16
#define FSRC_MAX   8
#define PARA_MAX   1200          /* one paragraph, cut on a sentence */
#define PARAS      2             /* paragraphs naming the type, kept */

typedef struct {
    char name[NAME_MAX_], tech[32];
} kind_t;

typedef struct {
    char  path[PATH_MAX_];
    char  citation[1024], url[512];
    char *body;                  /* after the frontmatter */
    char  kinds[1024];           /* the alert_kinds list, as written */
} doc_t;

static kind_t K[TYPE_MAX];
static int    nk;
static doc_t  D[DOC_MAX];
static int    nd;

/* Copy s into d (cap bytes), cut to fit. */
static void scopy(char *d, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    memcpy(d, s, n);
    d[n] = '\0';
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "alertkb: cannot open %s\n", path); return NULL; }
    char *b = malloc(FILE_MAX + 1);
    if (!b) { fclose(f); return NULL; }
    size_t n = fread(b, 1, FILE_MAX, f);
    int big = n == FILE_MAX;
    fclose(f);
    if (big) { fprintf(stderr, "alertkb: %s: too large\n", path); free(b); return NULL; }
    b[n] = '\0';
    if (strlen(b) != n) { fprintf(stderr, "alertkb: NUL in %s\n", path); free(b); return NULL; }
    return b;
}

/* A C string literal: every byte outside printable ASCII as an octal
 * escape, '?' escaped so no trigraph can form under -std=c99. */
static void c_string(FILE *o, const char *s) {
    fputc('"', o);
    size_t col = 0;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '\\' || c == '"' || c == '?') { fprintf(o, "\\%c", c); col += 2; }
        else if (c < 0x20 || c >= 0x7f) { fprintf(o, "\\%03o", c); col += 4; }
        else { fputc(c, o); col++; }
        if (col > 72 && c == ' ') { fputs("\"\n    \"", o); col = 0; }
    }
    fputc('"', o);
}

/* ── Markdown to words ─────────────────────────────────────────────── */

/* In place: [text](url) to text, [[page]] to page, code marks and
 * emphasis dropped, <br> and runs of white space to one space, "\|" to
 * "|". With keep_code a code span stays whole, its backticks and its
 * text verbatim, for the page to render as code. */
static void plain_x(char *s, int keep_code) {
    char *o = s;
    const char *p = s;
    while (*p) {
        if (keep_code && *p == '`' && strchr(p + 1, '`')) {
            const char *e = strchr(p + 1, '`');
            for (; p <= e; p++) *o++ = (*p == '\n' || *p == '\t' || *p == '\r') ? ' ' : *p;
            continue;
        }
        if (p[0] == '[' && p[1] == '[') {
            const char *e = strstr(p + 2, "]]");
            if (e) { for (p += 2; p < e; p++) *o++ = *p; p += 2; continue; }
        }
        if (*p == '[') {
            const char *e = strchr(p + 1, ']');
            if (e && e[1] == '(' && strchr(e + 2, ')')) {
                const char *c = strchr(e + 2, ')');
                /* The link's text, its code and emphasis marks dropped. */
                for (p++; p < e; p++) if (*p != '`' && *p != '*') *o++ = *p;
                p = c + 1;
                continue;
            }
        }
        if (*p == '`') { p++; continue; }
        if (p[0] == '\\' && (p[1] == '|' || p[1] == '*' || p[1] == '_')) {
            *o++ = p[1]; p += 2; continue;
        }
        if (*p == '*') {
            /* Emphasis, not a multiplication sign between spaces. */
            int sp_before = o == s || o[-1] == ' ' || o[-1] == '\n';
            int sp_after = p[1] == ' ' || p[1] == '\n' || p[1] == '\0';
            if (!(sp_before && sp_after)) { p++; continue; }
        }
        if (!strncmp(p, "<br>", 4)) { *o++ = ' '; p += 4; continue; }
        if (*p == '\n' || *p == '\t' || *p == '\r') { *o++ = ' '; p++; continue; }
        *o++ = *p++;
    }
    *o = '\0';
    /* Collapse spaces, trim. */
    char *r = s, *w = s;
    while (*r == ' ') r++;
    for (; *r; r++) {
        if (*r == ' ' && (r[1] == ' ' || r[1] == '\0')) continue;
        *w++ = *r;
    }
    *w = '\0';
}

static void plain(char *s) { plain_x(s, 0); }

/* Cut s to at most max bytes: at the last sentence end inside it, else
 * the last space, with " ..." after. Never inside a UTF-8 sequence. */
static void cut(char *s, size_t max) {
    size_t n = strlen(s);
    if (n <= max) return;
    size_t at = 0;
    for (size_t i = 0; i + 1 < max; i++)
        if (s[i] == '.' && s[i + 1] == ' ') at = i + 1;
    if (at < max / 2) {
        at = max - 4;
        while (at > 0 && s[at] != ' ') at--;
        while (at > 0 && ((unsigned char)s[at] & 0xc0) == 0x80) at--;
        memcpy(s + at, " ...", 5);
        return;
    }
    s[at] = '\0';
}

/* The blocks of a Markdown text: runs of lines separated by blank
 * lines, with fenced code, tables and headings left out. fn sees each
 * block's raw text. */
typedef void (*block_fn)(void *ctx, const char *b, size_t n);
static void blocks(const char *t, block_fn fn, void *ctx) {
    int fence = 0;
    const char *start = NULL;
    for (const char *p = t; ; ) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        const char *q = p;
        while (q < p + ll && *q == ' ') q++;
        int blank = q == p + ll;
        int is_fence = ll - (size_t)(q - p) >= 3 && !strncmp(q, "```", 3);
        int skip = fence || is_fence || *q == '|' || *q == '#' ||
                   (q[0] == '-' && q[1] == '-' && q[2] == '-');
        if (is_fence) fence = !fence;
        if (blank || skip) {
            if (start) fn(ctx, start, (size_t)(p - start));
            start = NULL;
        } else if (!start) {
            start = p;
        }
        if (!nl) { if (start) fn(ctx, start, strlen(start)); break; }
        p = nl + 1;
    }
}

/* Does block b name the type: `NAME`, `ALERT_TYPE_NAME` or **`NAME`**? */
static int names(const char *b, size_t n, const char *name) {
    char a[NAME_MAX_ + 16], c[NAME_MAX_ + 32];
    snprintf(a, sizeof(a), "`%s`", name);
    snprintf(c, sizeof(c), "`ALERT_TYPE_%s`", name);
    char *tmp = malloc(n + 1);
    if (!tmp) return 0;
    memcpy(tmp, b, n);
    tmp[n] = '\0';
    /* Named near its start: a paragraph about the type, not one that
     * mentions it in passing. */
    if (n > 240) tmp[240] = '\0';
    int hit = strstr(tmp, a) || strstr(tmp, c);
    if (n > 240) {
        memcpy(tmp, b, n);
        tmp[n] = '\0';
    }
    /* A block naming many types (the per-tier headline lists, a
     * cross-reference) is about none of them in particular. */
    int kinds = 0;
    for (int k = 0; hit && k < nk; k++) {
        char b2[NAME_MAX_ + 16] = "`";
        strcat(b2, K[k].name);
        strcat(b2, "`");
        if (strstr(tmp, b2)) kinds++;
    }
    free(tmp);
    return hit && kinds <= 3;
}

typedef struct {
    const char *name;
    char        out[PARAS * (PARA_MAX + 8)];
    int         n;
    int         first_only;       /* the lead: the first block, whatever */
} para_t;

static void take_para(void *ctx, const char *b, size_t n) {
    para_t *p = ctx;
    if (p->n >= PARAS || (p->first_only && p->n >= 1)) return;
    if (!p->first_only && !names(b, n, p->name)) return;
    char *t = malloc(n + 1);
    if (!t) return;
    memcpy(t, b, n);
    t[n] = '\0';
    plain(t);
    cut(t, PARA_MAX);
    size_t ol = strlen(p->out);
    snprintf(p->out + ol, sizeof(p->out) - ol, "%s%s", ol ? "\n\n" : "", t);
    p->n++;
    free(t);
}

/* ── the inputs ───────────────────────────────────────────────────── */

static int read_def(const char *path) {
    char *t = slurp(path);
    if (!t) return -1;
    for (char *p = t; p && *p; ) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        if (!strncmp(p, "X(", 2)) {
            if (nk == TYPE_MAX) { fprintf(stderr, "alertkb: too many types\n"); free(t); return -1; }
            const char *a = p + 2, *c = strchr(a, ',');
            const char *q1 = c ? strchr(c, '"') : NULL;
            const char *q2 = q1 ? strchr(q1 + 1, '"') : NULL;
            if (!c || !q2 || (size_t)(c - a) >= NAME_MAX_ || (size_t)(q2 - q1) >= 32) {
                fprintf(stderr, "alertkb: %s: bad row: %s\n", path, p);
                free(t);
                return -1;
            }
            memcpy(K[nk].name, a, (size_t)(c - a));
            K[nk].name[c - a] = '\0';
            memcpy(K[nk].tech, q1 + 1, (size_t)(q2 - q1 - 1));
            K[nk].tech[q2 - q1 - 1] = '\0';
            nk++;
        }
        p = nl ? nl + 1 : NULL;
    }
    free(t);
    if (!nk) { fprintf(stderr, "alertkb: %s has no X() rows\n", path); return -1; }
    return 0;
}

/* The row label a type is documented under in the rule table: the enum
 * suffix, or for one row the fire() title, the same mapping
 * tests/test_docs_consistency.c makes (the row names what the operator
 * reads in the view). */
static const char *row_label(const char *name) {
    if (!strcmp(name, "MY_NETWORK_RECON")) return "MY_NET_RECON";
    return name;
}

/* The cells of one table row, split on '|' outside code spans. */
static int cells(const char *row, size_t n, char out[][4096], int max) {
    int k = -1, code = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        char c = row[i];
        if (c == '`') code = !code;
        if (c == '\\' && i + 1 < n && row[i + 1] == '|') {
            if (k >= 0 && o + 1 < 4096) out[k][o++] = '|';
            i++;
            continue;
        }
        if (c == '|' && !code) {
            if (k >= 0) out[k][o] = '\0';
            if (++k >= max) return max;
            o = 0;
            continue;
        }
        if (k >= 0 && o + 1 < 4096) out[k][o++] = c;
    }
    if (k >= 0 && k < max) out[k][o] = '\0';
    return k;
}

#define SUMMARY_MAX 280      /* web_alertkb.h WEB_AKB_SUMMARY_MAX */

typedef struct {
    char sev[64], what[4096], summary[SUMMARY_MAX + 1], match[512];
    int  found;
} rule_t;

/* Does the '.' at s[i] end a sentence? Followed by a space and a capital,
 * and not the end of an abbreviation the rule table uses. */
static int sentence_end(const char *s, size_t i) {
    if (s[i] != '.' || s[i + 1] != ' ') return 0;
    unsigned char nx = (unsigned char)s[i + 2], pv = i ? (unsigned char)s[i - 1] : 0;
    /* A capital, or a number after a word ("... from it. 802.11d added"). */
    if (!((nx >= 'A' && nx <= 'Z') || (nx >= '0' && nx <= '9' && pv >= 'a' && pv <= 'z')))
        return 0;
    static const char *const ab[] = { "e.g", "i.e", "cf", "vs", "etc", "approx", "No", "Fig", NULL };
    for (int k = 0; ab[k]; k++) {
        size_t n = strlen(ab[k]);
        if (i >= n && !strncmp(s + i - n, ab[k], n) && (i == n || s[i - n - 1] == ' ' ||
                                                        s[i - n - 1] == '('))
            return 0;
    }
    /* "U.S." and the like: a single letter before the dot. */
    if (i >= 2 && s[i - 2] == '.') return 0;
    return 1;
}

/* The trigger's first sentence, without its issue references, at most
 * SUMMARY_MAX bytes: what the page leads with, the whole cell kept for
 * its "details". From the plain text (no code marks). */
static void summarise(const char *what, char *out) {
    char t[4096];
    size_t o = 0;
    /* Drop "(#123 ...)" asides: where a rule came from, not what it is. */
    for (const char *p = what; *p && o + 1 < sizeof(t); ) {
        if (p[0] == '(' && p[1] == '#') {
            const char *e = strchr(p, ')');
            if (e) {
                p = e + 1;
                if (o && t[o - 1] == ' ' && *p == ' ') p++;
                continue;
            }
        }
        t[o++] = *p++;
    }
    t[o] = '\0';
    for (size_t i = 0; t[i]; i++)
        if (sentence_end(t, i)) { t[i + 1] = '\0'; break; }
    /* " ," and " ." left by a dropped aside. */
    char *r = t, *w = t;
    for (; *r; r++) {
        if (*r == ' ' && (r[1] == ',' || r[1] == '.' || r[1] == ';')) continue;
        *w++ = *r;
    }
    *w = '\0';
    cut(t, SUMMARY_MAX);
    scopy(out, SUMMARY_MAX + 1, t);
}
static rule_t R[TYPE_MAX];

static int read_rules(const char *path) {
    char *t = slurp(path);
    if (!t) return -1;
    char *p = strstr(t, "\n## Rules\n");
    if (!p) { fprintf(stderr, "alertkb: %s: no ## Rules\n", path); free(t); return -1; }
    p += 10;
    static char cs[8][4096];
    while (p && *p) {
        char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        if (ll > 3 && !strncmp(p, "## ", 3)) break;
        if (ll > 3 && !strncmp(p, "| `", 3)) {
            int nc = cells(p, ll, cs, 8);
            /* A row may leave its last cell (match_ip / port) out. */
            if (nc >= 4) {
                char label[NAME_MAX_];
                scopy(label, sizeof(label), cs[0]);
                plain(label);
                for (int k = 0; k < nk; k++)
                    if (!R[k].found && !strcmp(label, row_label(K[k].name))) {
                        scopy(R[k].sev, sizeof(R[k].sev), cs[1]);
                        plain(R[k].sev);
                        scopy(R[k].what, sizeof(R[k].what), cs[3]);
                        plain(R[k].what);
                        summarise(R[k].what, R[k].summary);
                        /* The full cell keeps its code spans whole. */
                        scopy(R[k].what, sizeof(R[k].what), cs[3]);
                        plain_x(R[k].what, 1);
                        scopy(R[k].match, sizeof(R[k].match), nc >= 5 ? cs[4] : "");
                        plain(R[k].match);
                        R[k].found = 1;
                        break;
                    }
            }
        }
        p = nl ? nl + 1 : NULL;
    }
    free(t);
    return 0;
}

static int cmp_doc(const void *a, const void *b) {
    return strcmp(((const doc_t *)a)->path, ((const doc_t *)b)->path);
}

/* The value of "key: value" inside the frontmatter fm, or "". */
static void fm_value(const char *fm, const char *key, char *out, size_t cap) {
    out[0] = '\0';
    size_t kl = strlen(key);
    for (const char *p = fm; p && *p; ) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        if (ll > kl && !strncmp(p, key, kl) && p[kl] == ':') {
            const char *v = p + kl + 1;
            while (*v == ' ') v++;
            size_t vl = (size_t)(p + ll - v);
            if (vl >= cap) vl = cap - 1;
            memcpy(out, v, vl);
            out[vl] = '\0';
            return;
        }
        p = nl ? nl + 1 : NULL;
    }
}

static int read_doc(const char *path) {
    if (nd == DOC_MAX) { fprintf(stderr, "alertkb: too many documents\n"); return -1; }
    char *t = slurp(path);
    if (!t) return -1;
    doc_t *d = &D[nd];
    memset(d, 0, sizeof(*d));
    snprintf(d->path, sizeof(d->path), "%s", path);
    char *body = t;
    if (!strncmp(t, "---\n", 4)) {
        char *end = strstr(t + 4, "\n---\n");
        if (end) {
            *end = '\0';
            fm_value(t + 4, "citation", d->citation, sizeof(d->citation));
            fm_value(t + 4, "source_url", d->url, sizeof(d->url));
            fm_value(t + 4, "alert_kinds", d->kinds, sizeof(d->kinds));
            body = end + 5;
        }
    }
    d->body = strdup(body);
    free(t);
    if (!d->body) return -1;
    nd++;
    return 0;
}

/* Every .md under dir, depth first; the order is fixed by the sort. */
static int walk(const char *dir) {
    DIR *dh = opendir(dir);
    if (!dh) { fprintf(stderr, "alertkb: cannot open %s\n", dir); return -1; }
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(dh)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char p[PATH_MAX_];
        if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= (int)sizeof(p)) continue;
        struct stat sb;
        if (lstat(p, &sb) != 0) continue;
        if (S_ISDIR(sb.st_mode)) rc = walk(p);
        else if (S_ISREG(sb.st_mode)) {
            size_t l = strlen(p);
            if (l > 3 && !strcmp(p + l - 3, ".md")) rc = read_doc(p);
        }
    }
    closedir(dh);
    return rc;
}

/* Does the doc's alert_kinds list name ALERT_TYPE_<name> exactly? */
static int cites(const doc_t *d, const char *name) {
    char want[NAME_MAX_ + 16];
    int n = snprintf(want, sizeof(want), "ALERT_TYPE_%s", name);
    for (const char *p = strstr(d->kinds, want); p; p = strstr(p + 1, want)) {
        char after = p[n];
        char before = p == d->kinds ? '[' : p[-1];
        if ((before == '[' || before == ' ' || before == ',') &&
            (after == ']' || after == ',' || after == ' ' || after == '\0'))
            return 1;
    }
    return 0;
}

/* ── the remediation page ─────────────────────────────────────────── */

typedef struct {
    char *inv[STEP_MAX], *fix[STEP_MAX], *src[FSRC_MAX];
    int   ninv, nfix, nsrc;
    char  vendor[2048];
} rem_t;
static rem_t M[TYPE_MAX];

/* A numbered list item and its indented continuation lines, from p;
 * its text in a new string, *next after it. */
static char *item(const char *p, const char **next) {
    const char *q = p;
    while (*q >= '0' && *q <= '9') q++;
    q += 2;                                   /* ". " */
    const char *e = q;
    for (;;) {
        const char *nl = strchr(e, '\n');
        if (!nl) { e += strlen(e); break; }
        const char *n2 = nl + 1;
        if (n2[0] == ' ' && n2[1] == ' ') { e = n2; continue; }
        e = nl;
        break;
    }
    size_t n = (size_t)(e - q);
    char *s = malloc(n + 1);
    if (!s) return NULL;
    memcpy(s, q, n);
    s[n] = '\0';
    plain(s);
    *next = *e ? e + 1 : e;
    return s;
}

static int read_remediation(const char *path) {
    char *t = slurp(path);
    if (!t) return -1;
    for (int k = 0; k < nk; k++) {
        char head[NAME_MAX_ + 16] = "\n## `";
        strcat(head, K[k].name);
        strcat(head, "`\n");
        char *a = strstr(t, head);
        if (!a) continue;
        a += strlen(head);
        char *end = strstr(a, "\n## ");
        size_t sl = end ? (size_t)(end - a) : strlen(a);
        char *sec = malloc(sl + 1);
        if (!sec) { free(t); return -1; }
        memcpy(sec, a, sl);
        sec[sl] = '\0';
        rem_t *r = &M[k];
        int list = 0;                          /* 1 investigate, 2 fix */
        for (const char *p = sec; p && *p; ) {
            if (!strncmp(p, "**Investigate**", 15)) list = 1;
            else if (!strncmp(p, "**Fix**", 7)) list = 2;
            else if (!strncmp(p, "**Vendor fix:**", 15)) {
                const char *v = p + 15;
                const char *e = strstr(v, "\n\n");
                size_t vl = e ? (size_t)(e - v) : strlen(v);
                if (vl >= sizeof(r->vendor)) vl = sizeof(r->vendor) - 1;
                memcpy(r->vendor, v, vl);
                r->vendor[vl] = '\0';
                plain(r->vendor);
                list = 0;
            } else if (!strncmp(p, "Sources:", 8)) {
                const char *nl = strchr(p, '\n');
                const char *e = nl ? nl : p + strlen(p);
                for (const char *b = strchr(p, '`'); b && b < e; ) {
                    const char *c = strchr(b + 1, '`');
                    if (!c || c > e) break;
                    if (r->nsrc < FSRC_MAX) {
                        size_t n = (size_t)(c - b - 1);
                        r->src[r->nsrc] = malloc(n + 1);
                        if (r->src[r->nsrc]) {
                            memcpy(r->src[r->nsrc], b + 1, n);
                            r->src[r->nsrc][n] = '\0';
                            r->nsrc++;
                        }
                    }
                    b = strchr(c + 1, '`');
                }
                list = 0;
            } else if (list && *p >= '1' && *p <= '9') {
                const char *next = NULL;
                char *s = item(p, &next);
                if (s && list == 1 && r->ninv < STEP_MAX) r->inv[r->ninv++] = s;
                else if (s && list == 2 && r->nfix < STEP_MAX) r->fix[r->nfix++] = s;
                else free(s);
                p = next;
                if (!p) break;
                continue;
            }
            const char *nl = strchr(p, '\n');
            p = nl ? nl + 1 : NULL;
        }
        free(sec);
    }
    free(t);
    return 0;
}

/* ── output ───────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "usage: alertkb OUT.c DEF RULES.md WIKI.md REMEDIATION.md RESEARCH_DIR\n");
        return 2;
    }
    if (read_def(argv[2]) || read_rules(argv[3]) || walk(argv[6]) ||
        read_remediation(argv[5]))
        return 1;
    qsort(D, (size_t)nd, sizeof(D[0]), cmp_doc);
    char *wiki = slurp(argv[4]);
    if (!wiki) return 1;

    FILE *o = fopen(argv[1], "w");
    if (!o) { fprintf(stderr, "alertkb: cannot write %s\n", argv[1]); return 1; }
    fprintf(o, "/* GENERATED by web/tools/alertkb.c from %s, %s, %s, %s and\n"
               " * %s/. Do not edit, do not commit: make regenerates it. */\n"
               "#include <string.h>\n\n#include \"web_alertkb.h\"\n\n",
            argv[2], argv[3], argv[4], argv[5], argv[6]);
    static para_t para;
    for (int k = 0; k < nk; k++) {
        int ns = 0;
        fprintf(o, "static const web_akb_src_t src_%d[] = {\n", k);
        for (int i = 0; i < nd; i++) {
            if (!cites(&D[i], K[k].name)) continue;
            memset(&para, 0, sizeof(para));
            para.first_only = 1;
            blocks(D[i].body, take_para, &para);
            fprintf(o, "  { ");
            c_string(o, D[i].path);
            fprintf(o, ",\n    ");
            char cit[1024];
            scopy(cit, sizeof(cit), D[i].citation[0] ? D[i].citation : D[i].path);
            plain(cit);
            c_string(o, cit);
            fprintf(o, ",\n    ");
            c_string(o, D[i].url);
            fprintf(o, ",\n    ");
            c_string(o, para.out);
            memset(&para, 0, sizeof(para));
            para.name = K[k].name;
            blocks(D[i].body, take_para, &para);
            fprintf(o, ",\n    ");
            c_string(o, para.out);
            fprintf(o, " },\n");
            ns++;
        }
        if (!ns) fprintf(o, "  { \"\", \"\", \"\", \"\", \"\" },\n");
        fprintf(o, "};\n");
        rem_t *r = &M[k];
        fprintf(o, "static const char *const inv_%d[] = {", k);
        for (int i = 0; i < r->ninv; i++) { fprintf(o, "\n  "); c_string(o, r->inv[i]); fputc(',', o); }
        fprintf(o, "%s};\n", r->ninv ? "\n" : " \"\" ");
        fprintf(o, "static const char *const fix_%d[] = {", k);
        for (int i = 0; i < r->nfix; i++) { fprintf(o, "\n  "); c_string(o, r->fix[i]); fputc(',', o); }
        fprintf(o, "%s};\n", r->nfix ? "\n" : " \"\" ");
        fprintf(o, "static const char *const fsrc_%d[] = {", k);
        for (int i = 0; i < r->nsrc; i++) { fprintf(o, " "); c_string(o, r->src[i]); fputc(',', o); }
        fprintf(o, "%s};\n\n", r->nsrc ? " " : " \"\" ");
    }
    fprintf(o, "const web_akb_t web_akb[] = {\n");
    for (int k = 0; k < nk; k++) {
        int ns = 0;
        for (int i = 0; i < nd; i++) if (cites(&D[i], K[k].name)) ns++;
        memset(&para, 0, sizeof(para));
        para.name = K[k].name;
        blocks(wiki, take_para, &para);
        fprintf(o, "  { ");
        c_string(o, K[k].name);
        fprintf(o, ", ");
        c_string(o, K[k].tech);
        fprintf(o, ", ");
        c_string(o, R[k].sev);
        fprintf(o, ",\n    ");
        c_string(o, R[k].summary);
        fprintf(o, ",\n    ");
        c_string(o, R[k].what);
        fprintf(o, ",\n    ");
        c_string(o, R[k].match);
        fprintf(o, ",\n    ");
        c_string(o, para.out);
        fprintf(o, ",\n    src_%d, %d, inv_%d, %d, fix_%d, %d,\n    ", k, ns, k,
                M[k].ninv, k, M[k].nfix);
        c_string(o, M[k].vendor);
        fprintf(o, ", fsrc_%d, %d },\n", k, M[k].nsrc);
    }
    fprintf(o, "};\nconst int web_akb_n = %d;\n\nconst char web_akb_inputs[] = ", nk);
    char inputs[2048];
    snprintf(inputs, sizeof(inputs), "%s, %s, %s, %s, %s/", argv[2], argv[3], argv[4],
             argv[5], argv[6]);
    c_string(o, inputs);
    fprintf(o, ";\n\n"
               "const web_akb_t *web_akb_get(long long type) {\n"
               "    return type >= 0 && type < web_akb_n ? &web_akb[type] : NULL;\n"
               "}\n\n"
               "int web_akb_find(const char *name) {\n"
               "    for (int i = 0; name && i < web_akb_n; i++)\n"
               "        if (!strcmp(web_akb[i].name, name)) return i;\n"
               "    return -1;\n"
               "}\n");
    free(wiki);
    for (int i = 0; i < nd; i++) free(D[i].body);
    for (int k = 0; k < nk; k++) {
        for (int i = 0; i < M[k].ninv; i++) free(M[k].inv[i]);
        for (int i = 0; i < M[k].nfix; i++) free(M[k].fix[i]);
        for (int i = 0; i < M[k].nsrc; i++) free(M[k].src[i]);
    }
    return fclose(o) == 0 ? 0 : 1;
}
