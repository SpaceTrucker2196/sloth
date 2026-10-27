/* Build-time vendor research extractor. Not part of slothweb.
 *
 *   vendorkb OUT.c DIR
 *
 * Reads every .md under DIR (web/data/vendors/) as one researched OUI holder
 * in the format docs/wiki/vendor-research.md fixes: a front matter
 * block between "---" lines, a "## Summary" section and a "## Sources"
 * list, and writes the table web_vendorkb.h describes. Nothing here is
 * written by hand: the files are what the drawer shows after the next
 * build.
 *
 * Unlike alertkb.c, a defect stops the build and names the file: a
 * required field missing or misspelt, a value outside its word list, a
 * [n] with no source line n, a cited value with no [n], a source list
 * not numbered 1..n, a file whose name is not the slug of its name
 * field, two files claiming one normalised key. The drawer would
 * otherwise show a guess as research, and the research agents writing
 * the files need the refusal, not a silent gap. OUT.c is generated
 * under build/ and never committed.
 *
 * Front matter grammar (the subset of YAML the format uses):
 *   key: scalar                 to the end of the line, "quotes" dropped
 *   key: [a, b, "c, d"]         items split on commas outside quotes;
 *                               the list may run on over several lines
 *                               until its closing bracket
 *   key: {k: v, k2: v2}         the confidence map
 * A citation is "[" digits, separated by commas or spaces, "]". */
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "web_vendorkb.h"

#define FILE_MAX    (256 * 1024)
#define ENTRY_MAX   1024
#define PATH_MAX_   512
#define LIST_MAX    64
#define SRC_MAX     64
#define VAL_MAX     1024
#define KEY_MAX     32

typedef struct {
    char  key[KEY_MAX];
    char *items[LIST_MAX];       /* a scalar is one item; a list its items */
    int   n;
    int   is_list;
    int   seen;
} field_t;

typedef struct {
    char   path[PATH_MAX_];
    char   base[128];            /* the file name without .md */
    field_t f[16];               /* in REQUIRED order */
    char  *summary;
    char  *src_title[SRC_MAX], *src_url[SRC_MAX], *src_date[SRC_MAX];
    int    nsrc;
    int    cited[SRC_MAX + 1];
} entry_t;

enum {
    F_NAME, F_ALIASES, F_COUNTRY, F_PARENT, F_FOUNDED, F_KIND, F_CLASSES,
    F_FOUND_IN, F_RADIOS, F_SILICON, F_FCC, F_RANDOM, F_SECURITY,
    F_CONFIDENCE, F_RESEARCHED, F_COUNT
};
static const char *const REQUIRED[F_COUNT] = {
    "name", "aliases", "country", "parent", "founded", "kind", "device_classes",
    "found_in", "radios", "silicon", "fcc_grantee", "randomization",
    "security_notes", "confidence", "researched",
};
static const int IS_LIST[F_COUNT] = { 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0 };

static const char *const KINDS[] = {
    "brand", "module-maker", "odm/ems", "chip-vendor", "carrier/isp", "automotive",
    "network-equipment", "other", NULL
};
static const char *const CLASSES[] = {
    "phone", "laptop", "tablet", "wearable", "tv", "speaker", "camera", "iot-sensor",
    "smart-home", "ap/router", "switch", "printer", "console", "automotive-telematics",
    "automotive-infotainment", "drone", "pos", "medical", "industrial",
    "module-in-other-brands", "unknown", NULL
};
static const char *const CONF_KEYS[] = { "country", "silicon", "radios", "found_in",
                                         "randomization", NULL };
static const char *const CONF_WORDS[] = { "documented", "inferred", "unknown", NULL };

static entry_t *E;
static int      ne;
static int      rc;             /* set once anything failed */

static void fail(const entry_t *e, const char *fmt, const char *a, const char *b) {
    fprintf(stderr, "vendorkb: %s: ", e ? e->path : "?");
    fprintf(stderr, fmt, a ? a : "", b ? b : "");
    fputc('\n', stderr);
    rc = 1;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "vendorkb: cannot open %s\n", path); return NULL; }
    char *b = malloc(FILE_MAX + 1);
    if (!b) { fclose(f); return NULL; }
    size_t n = fread(b, 1, FILE_MAX, f);
    int big = n == FILE_MAX;
    fclose(f);
    if (big) { fprintf(stderr, "vendorkb: %s: too large\n", path); free(b); return NULL; }
    b[n] = '\0';
    if (strlen(b) != n) { fprintf(stderr, "vendorkb: NUL in %s\n", path); free(b); return NULL; }
    /* CRLF to LF, so an entry written on another system parses. */
    char *o = b;
    for (const char *p = b; *p; p++) if (*p != '\r') *o++ = *p;
    *o = '\0';
    return b;
}

static char *dupn(const char *s, size_t n) {
    char *d = malloc(n + 1);
    if (!d) { fprintf(stderr, "vendorkb: out of memory\n"); exit(1); }
    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

/* Trim, and drop one pair of enclosing double quotes. */
static char *trimmed(const char *s, size_t n) {
    while (n && (s[0] == ' ' || s[0] == '\t')) { s++; n--; }
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n')) n--;
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') { s++; n -= 2; }
    return dupn(s, n);
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

/* ── citations ────────────────────────────────────────────────────── */

/* Mark every [n] in s cited; a bracket holding anything but digits,
 * commas and spaces is not a citation. Returns the count of marks, or
 * -1 on a number with no source. */
static int cite(entry_t *e, const char *s, const char *where) {
    int marks = 0;
    for (const char *p = strchr(s, '['); p; p = strchr(p + 1, '[')) {
        const char *q = p + 1;
        int any = 0, ok = 1;
        for (; *q && *q != ']'; q++) {
            if (*q >= '0' && *q <= '9') any = 1;
            else if (*q != ',' && *q != ' ') ok = 0;
        }
        if (*q != ']' || !any || !ok) continue;
        for (q = p + 1; *q != ']'; ) {
            while (*q == ',' || *q == ' ') q++;
            if (*q == ']') break;
            int n = 0;
            while (*q >= '0' && *q <= '9') n = n * 10 + (*q++ - '0');
            if (n < 1 || n > e->nsrc) {
                char num[16];
                snprintf(num, sizeof(num), "%d", n);
                fail(e, "%s cites [%s], which has no source line", where, num);
                return -1;
            }
            e->cited[n] = 1;
            marks++;
        }
    }
    return marks;
}

/* The value with its citations removed, for the word-list checks. */
static void uncited(const char *s, char *out, size_t cap) {
    size_t o = 0;
    for (const char *p = s; *p && o + 1 < cap; p++) {
        if (*p == '[') {
            const char *q = p + 1;
            while ((*q >= '0' && *q <= '9') || *q == ',' || *q == ' ') q++;
            if (*q == ']' && q > p + 1) { p = q; continue; }
        }
        out[o++] = *p;
    }
    while (o && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

static int in_list(const char *const *words, const char *w) {
    for (int i = 0; words[i]; i++) if (!strcmp(words[i], w)) return 1;
    return 0;
}

/* ── the front matter ─────────────────────────────────────────────── */

/* Split a bracketed list body into items on commas outside quotes and
 * outside an item's own [n, m] citation brackets. */
static void split_items(entry_t *e, field_t *f, const char *body, size_t n) {
    size_t start = 0;
    int quoted = 0, depth = 0;
    for (size_t i = 0; i <= n; i++) {
        if (i < n && body[i] == '"') quoted = !quoted;
        if (i < n && !quoted && body[i] == '[') depth++;
        if (i < n && !quoted && body[i] == ']' && depth) depth--;
        if (i < n && (body[i] != ',' || quoted || depth)) continue;
        char *it = trimmed(body + start, i - start);
        if (it[0]) {
            if (f->n == LIST_MAX) { fail(e, "%s: more than 64 items", f->key, NULL); free(it); return; }
            f->items[f->n++] = it;
        } else {
            free(it);
        }
        start = i + 1;
    }
}

static int parse_front(entry_t *e, const char *t, const char **body_out) {
    if (strncmp(t, "---\n", 4) != 0) { fail(e, "no front matter (the file must open with ---)", NULL, NULL); return -1; }
    const char *p = t + 4;
    for (;;) {
        if (!*p) { fail(e, "front matter never closed", NULL, NULL); return -1; }
        if (!strncmp(p, "---\n", 4) || !strcmp(p, "---")) { p += *p == '-' && p[3] == '\n' ? 4 : 3; break; }
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        const char *colon = memchr(p, ':', ll);
        if (!colon || colon == p) {
            char line[80];
            snprintf(line, sizeof(line), "%.*s", (int)(ll < 60 ? ll : 60), p);
            fail(e, "not a key: value line: \"%s\"", line, NULL);
            return -1;
        }
        char key[KEY_MAX];
        if ((size_t)(colon - p) >= sizeof(key)) { fail(e, "key too long", NULL, NULL); return -1; }
        snprintf(key, sizeof(key), "%.*s", (int)(colon - p), p);
        int fi = -1;
        for (int i = 0; i < F_COUNT; i++) if (!strcmp(REQUIRED[i], key)) fi = i;
        if (fi < 0) { fail(e, "unknown field \"%s\"", key, NULL); return -1; }
        field_t *f = &e->f[fi];
        if (f->seen) { fail(e, "field \"%s\" given twice", key, NULL); return -1; }
        f->seen = 1;
        snprintf(f->key, sizeof(f->key), "%s", key);
        const char *v = colon + 1;
        while (*v == ' ') v++;
        if (IS_LIST[fi]) {
            char open = fi == F_CONFIDENCE ? '{' : '[', close = fi == F_CONFIDENCE ? '}' : ']';
            if (*v != open) { fail(e, "field \"%s\" must be a bracketed list", key, NULL); return -1; }
            /* To the matching close, over as many lines as it takes;
             * an item's own [n] brackets nest inside a list. */
            const char *q = v + 1;
            int quoted = 0, depth = 1;
            for (; *q; q++) {
                if (*q == '"') quoted = !quoted;
                if (quoted) continue;
                if (*q == open) depth++;
                if (*q == close && --depth == 0) break;
            }
            if (*q != close || depth) { fail(e, "field \"%s\": list never closed", key, NULL); return -1; }
            f->is_list = 1;
            split_items(e, f, v + 1, (size_t)(q - v - 1));
            nl = strchr(q, '\n');
            p = nl ? nl + 1 : q + strlen(q);
            continue;
        }
        f->items[0] = trimmed(v, (size_t)(p + ll - v));
        f->n = 1;
        p = nl ? nl + 1 : p + ll;
    }
    for (int i = 0; i < F_COUNT; i++)
        if (!e->f[i].seen) { fail(e, "required field \"%s\" missing", REQUIRED[i], NULL); return -1; }
    for (int i = 0; i < F_COUNT; i++)
        if (!IS_LIST[i] && !e->f[i].items[0][0]) { fail(e, "field \"%s\" is empty", REQUIRED[i], NULL); return -1; }
    *body_out = p;
    return 0;
}

/* ── the body ─────────────────────────────────────────────────────── */

static int parse_body(entry_t *e, const char *body) {
    const char *s = strstr(body, "## Summary\n");
    const char *z = strstr(body, "## Sources\n");
    if (!s || !z || z < s) { fail(e, "the body needs \"## Summary\" then \"## Sources\"", NULL, NULL); return -1; }
    /* The summary: lines of a paragraph joined by a space, paragraphs
     * by a blank line. */
    char *sum = malloc(FILE_MAX);
    size_t o = 0;
    int in_para = 0;
    for (const char *p = s + 11; p < z; ) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        if (nl && nl > z) ll = (size_t)(z - p);
        const char *q = p;
        while (q < p + ll && *q == ' ') q++;
        if (q == p + ll) {
            if (in_para && o + 2 < FILE_MAX) { sum[o++] = '\n'; sum[o++] = '\n'; }
            in_para = 0;
        } else {
            if (*q == '#') { fail(e, "a heading inside the summary", NULL, NULL); free(sum); return -1; }
            if (in_para && o + 1 < FILE_MAX) sum[o++] = ' ';
            size_t take = (size_t)(p + ll - q);
            while (take && q[take - 1] == ' ') take--;
            if (o + take + 1 >= FILE_MAX) take = FILE_MAX - o - 1;
            memcpy(sum + o, q, take);
            o += take;
            in_para = 1;
        }
        p = nl ? nl + 1 : p + ll;
    }
    while (o && (sum[o - 1] == '\n' || sum[o - 1] == ' ')) o--;
    sum[o] = '\0';
    e->summary = dupn(sum, o);
    free(sum);
    if (!e->summary[0]) { fail(e, "the summary is empty", NULL, NULL); return -1; }

    /* The sources: "N. title - URL (accessed YYYY-MM-DD)", N from 1 up,
     * an indented line continuing the one above. */
    char *lines[SRC_MAX];
    int nl_ = 0;
    for (const char *p = z + 11; *p; ) {
        const char *nl = strchr(p, '\n');
        size_t ll = nl ? (size_t)(nl - p) : strlen(p);
        if (ll && p[0] == ' ' && nl_ > 0) {
            const char *q = p;
            while (q < p + ll && *q == ' ') q++;
            size_t old = strlen(lines[nl_ - 1]);
            char *j = malloc(old + (size_t)(p + ll - q) + 2);
            if (!j) exit(1);
            memcpy(j, lines[nl_ - 1], old);
            j[old] = ' ';
            memcpy(j + old + 1, q, (size_t)(p + ll - q));
            j[old + 1 + (size_t)(p + ll - q)] = '\0';
            free(lines[nl_ - 1]);
            lines[nl_ - 1] = j;
        } else if (ll && p[0] >= '1' && p[0] <= '9') {
            if (nl_ == SRC_MAX) { fail(e, "more than 64 sources", NULL, NULL); return -1; }
            lines[nl_++] = dupn(p, ll);
        } else if (ll && p[0] != ' ') {
            if (!strncmp(p, "## ", 3)) { fail(e, "a section after ## Sources", NULL, NULL); return -1; }
            char line[80];
            snprintf(line, sizeof(line), "%.*s", (int)(ll < 60 ? ll : 60), p);
            fail(e, "not a source line: \"%s\"", line, NULL);
            return -1;
        }
        p = nl ? nl + 1 : p + ll;
    }
    if (!nl_) { fail(e, "no source lines", NULL, NULL); return -1; }
    for (int i = 0; i < nl_; i++) {
        const char *l = lines[i];
        int n = 0;
        const char *q = l;
        while (*q >= '0' && *q <= '9') n = n * 10 + (*q++ - '0');
        if (n != i + 1 || q[0] != '.' || q[1] != ' ') {
            fail(e, "source lines must be numbered 1, 2, ... in order: \"%.60s\"", l, NULL);
            return -1;
        }
        q += 2;
        const char *dash = strstr(q, " - http");
        if (!dash || dash == q) { fail(e, "source without \" - <URL>\": \"%.60s\"", l, NULL); return -1; }
        const char *url = dash + 3, *ue = url;
        while (*ue && *ue != ' ') ue++;
        const char *acc = strstr(ue, " (accessed ");
        if (!acc || acc != ue) { fail(e, "source without \"(accessed YYYY-MM-DD)\": \"%.60s\"", l, NULL); return -1; }
        const char *d = acc + 11;
        int okd = strlen(d) >= 11 && isdigit((unsigned char)d[0]) && isdigit((unsigned char)d[1]) &&
                  isdigit((unsigned char)d[2]) && isdigit((unsigned char)d[3]) && d[4] == '-' &&
                  isdigit((unsigned char)d[5]) && isdigit((unsigned char)d[6]) && d[7] == '-' &&
                  isdigit((unsigned char)d[8]) && isdigit((unsigned char)d[9]) && d[10] == ')' &&
                  (d[11] == '\0' || d[11] == ' ');
        if (!okd) { fail(e, "source date is not YYYY-MM-DD: \"%.60s\"", l, NULL); return -1; }
        e->src_title[i] = trimmed(q, (size_t)(dash - q));
        e->src_url[i] = dupn(url, (size_t)(ue - url));
        e->src_date[i] = dupn(d, 10);
        e->nsrc++;
    }
    for (int i = 0; i < nl_; i++) free(lines[i]);
    return 0;
}

/* ── the rules ────────────────────────────────────────────────────── */

static int plain_text(entry_t *e, const char *s, const char *where) {
    if (strstr(s, "](") || strstr(s, "**") || strchr(s, '`')) {
        fail(e, "%s holds Markdown markup (a link, emphasis or code)", where, NULL);
        return -1;
    }
    return 0;
}

static int is_date(const char *s) {
    return strlen(s) == 10 && isdigit((unsigned char)s[0]) && isdigit((unsigned char)s[1]) &&
           isdigit((unsigned char)s[2]) && isdigit((unsigned char)s[3]) && s[4] == '-' &&
           isdigit((unsigned char)s[5]) && isdigit((unsigned char)s[6]) && s[7] == '-' &&
           isdigit((unsigned char)s[8]) && isdigit((unsigned char)s[9]);
}

/* A scalar that is "unknown" or carries a citation. */
static int cited_or_unknown(entry_t *e, int fi) {
    const char *v = e->f[fi].items[0];
    if (plain_text(e, v, REQUIRED[fi])) return -1;
    if (!strcmp(v, "unknown")) return 0;
    int m = cite(e, v, REQUIRED[fi]);
    if (m < 0) return -1;
    if (!m) { fail(e, "%s is \"%s\" with no [n]: cite it or write unknown", REQUIRED[fi], v); return -1; }
    return 0;
}

/* Every item of a list carries a citation. */
static int cited_list(entry_t *e, int fi) {
    field_t *f = &e->f[fi];
    for (int i = 0; i < f->n; i++) {
        if (plain_text(e, f->items[i], REQUIRED[fi])) return -1;
        int m = cite(e, f->items[i], REQUIRED[fi]);
        if (m < 0) return -1;
        if (!m) { fail(e, "%s item \"%s\" has no [n]", REQUIRED[fi], f->items[i]); return -1; }
    }
    return 0;
}

static int check(entry_t *e) {
    char bare[VAL_MAX];
    /* name: exact, plain; the file is named for it */
    const char *name = e->f[F_NAME].items[0];
    if (plain_text(e, name, "name") || strchr(name, '[')) { fail(e, "name must be the bare IEEE string", NULL, NULL); return -1; }
    char key[WEB_VKB_KEY_MAX + 1], slug[WEB_VKB_KEY_MAX + 1];
    web_vkb_norm(name, key, sizeof(key));
    for (size_t i = 0; key[i]; i++) slug[i] = key[i] == ' ' ? '-' : key[i], slug[i + 1] = '\0';
    if (!key[0]) slug[0] = '\0';
    if (strcmp(slug, e->base) != 0) {
        fail(e, "file should be named %s.md (the slug of \"%s\")", slug, name);
        return -1;
    }
    for (int i = 0; i < e->f[F_ALIASES].n; i++)
        if (plain_text(e, e->f[F_ALIASES].items[i], "aliases") || strchr(e->f[F_ALIASES].items[i], '['))
            { fail(e, "aliases are bare IEEE strings", NULL, NULL); return -1; }
    /* country: unknown, or two capitals and a citation */
    if (cited_or_unknown(e, F_COUNTRY)) return -1;
    uncited(e->f[F_COUNTRY].items[0], bare, sizeof(bare));
    if (strcmp(bare, "unknown") && !(strlen(bare) == 2 && isupper((unsigned char)bare[0]) &&
                                     isupper((unsigned char)bare[1]))) {
        fail(e, "country \"%s\" is not an ISO 3166 alpha-2 code or unknown", bare, NULL);
        return -1;
    }
    if (cited_or_unknown(e, F_PARENT)) return -1;
    if (cited_or_unknown(e, F_FOUNDED)) return -1;
    uncited(e->f[F_FOUNDED].items[0], bare, sizeof(bare));
    if (strcmp(bare, "unknown") && !(strlen(bare) == 4 && isdigit((unsigned char)bare[0]) &&
                                     isdigit((unsigned char)bare[1]) && isdigit((unsigned char)bare[2]) &&
                                     isdigit((unsigned char)bare[3]))) {
        fail(e, "founded \"%s\" is not a year or unknown", bare, NULL);
        return -1;
    }
    /* kind: one word of the list, a citation allowed */
    if (plain_text(e, e->f[F_KIND].items[0], "kind") || cite(e, e->f[F_KIND].items[0], "kind") < 0) return -1;
    uncited(e->f[F_KIND].items[0], bare, sizeof(bare));
    if (!in_list(KINDS, bare)) { fail(e, "kind \"%s\" is not one of the kinds", bare, NULL); return -1; }
    for (int i = 0; i < e->f[F_CLASSES].n; i++) {
        const char *it = e->f[F_CLASSES].items[i];
        if (plain_text(e, it, "device_classes") || cite(e, it, "device_classes") < 0) return -1;
        uncited(it, bare, sizeof(bare));
        if (!in_list(CLASSES, bare)) { fail(e, "device class \"%s\" is not one of the classes", bare, NULL); return -1; }
    }
    if (cited_list(e, F_FOUND_IN) || cited_list(e, F_RADIOS) || cited_list(e, F_SILICON) ||
        cited_list(e, F_FCC) || cited_list(e, F_SECURITY))
        return -1;
    if (cited_or_unknown(e, F_RANDOM)) return -1;
    /* confidence: the five keys, each a word */
    field_t *c = &e->f[F_CONFIDENCE];
    int seen[5] = { 0 };
    for (int i = 0; i < c->n; i++) {
        const char *colon = strchr(c->items[i], ':');
        if (!colon) { fail(e, "confidence item \"%s\" is not key: word", c->items[i], NULL); return -1; }
        char k[32];
        snprintf(k, sizeof(k), "%.*s", (int)(colon - c->items[i] < 31 ? colon - c->items[i] : 31), c->items[i]);
        const char *w = colon + 1;
        while (*w == ' ') w++;
        int ki = -1;
        for (int j = 0; CONF_KEYS[j]; j++) if (!strcmp(CONF_KEYS[j], k)) ki = j;
        if (ki < 0) { fail(e, "confidence names \"%s\", not a field", k, NULL); return -1; }
        if (!in_list(CONF_WORDS, w)) { fail(e, "confidence for %s is \"%s\", not documented, inferred or unknown", k, w); return -1; }
        seen[ki] = 1;
    }
    for (int j = 0; CONF_KEYS[j]; j++)
        if (!seen[j]) { fail(e, "confidence lacks %s", CONF_KEYS[j], NULL); return -1; }
    if (!is_date(e->f[F_RESEARCHED].items[0])) { fail(e, "researched is not YYYY-MM-DD", NULL, NULL); return -1; }
    /* the summary: plain, cited */
    if (plain_text(e, e->summary, "the summary")) return -1;
    int m = cite(e, e->summary, "the summary");
    if (m < 0) return -1;
    if (!m) { fail(e, "the summary cites nothing", NULL, NULL); return -1; }
    for (int i = 0; i < e->nsrc; i++) {
        if (plain_text(e, e->src_title[i], "a source title")) return -1;
        if (!e->cited[i + 1])
            fprintf(stderr, "vendorkb: %s: note: source %d is never cited\n", e->path, i + 1);
    }
    return 0;
}

/* The word of a confidence key. */
static const char *conf_of(const entry_t *e, const char *key) {
    const field_t *c = &e->f[F_CONFIDENCE];
    size_t kl = strlen(key);
    for (int i = 0; i < c->n; i++)
        if (!strncmp(c->items[i], key, kl) && c->items[i][kl] == ':') {
            const char *w = c->items[i] + kl + 1;
            while (*w == ' ') w++;
            return w;
        }
    return "unknown";
}

/* ── the files ────────────────────────────────────────────────────── */

static int cmp_entry(const void *a, const void *b) {
    return strcmp(((const entry_t *)a)->path, ((const entry_t *)b)->path);
}

static int read_dir(const char *dir) {
    DIR *dh = opendir(dir);
    if (!dh) { fprintf(stderr, "vendorkb: cannot open %s\n", dir); return -1; }
    struct dirent *d;
    while ((d = readdir(dh)) != NULL) {
        size_t l = strlen(d->d_name);
        if (d->d_name[0] == '.' || l < 4 || strcmp(d->d_name + l - 3, ".md")) continue;
        if (ne == ENTRY_MAX) { fprintf(stderr, "vendorkb: more than %d entries\n", ENTRY_MAX); closedir(dh); return -1; }
        entry_t *e = &E[ne];
        memset(e, 0, sizeof(*e));
        if (snprintf(e->path, sizeof(e->path), "%s/%s", dir, d->d_name) >= (int)sizeof(e->path) ||
            l - 3 >= sizeof(e->base)) {
            fprintf(stderr, "vendorkb: %s/%s: name too long\n", dir, d->d_name);
            closedir(dh);
            return -1;
        }
        snprintf(e->base, sizeof(e->base), "%.*s", (int)(l - 3), d->d_name);
        struct stat sb;
        if (stat(e->path, &sb) != 0 || !S_ISREG(sb.st_mode)) continue;
        ne++;
    }
    closedir(dh);
    qsort(E, (size_t)ne, sizeof(E[0]), cmp_entry);
    return 0;
}

typedef struct { char key[WEB_VKB_KEY_MAX + 1]; int entry; } key_t_;
static int cmp_key(const void *a, const void *b) {
    return strcmp(((const key_t_ *)a)->key, ((const key_t_ *)b)->key);
}

static void emit_list(FILE *o, const char *nm, int k, const field_t *f) {
    fprintf(o, "static const char *const %s_%d[] = {", nm, k);
    for (int i = 0; i < f->n; i++) { fprintf(o, "\n  "); c_string(o, f->items[i]); fputc(',', o); }
    fprintf(o, "%s};\n", f->n ? "\n" : " \"\" ");
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: vendorkb OUT.c DIR\n"); return 2; }
    E = calloc(ENTRY_MAX, sizeof(*E));
    if (!E || read_dir(argv[2])) return 1;
    for (int k = 0; k < ne; k++) {
        entry_t *e = &E[k];
        char *t = slurp(e->path);
        if (!t) { rc = 1; continue; }
        const char *body = NULL;
        if (parse_front(e, t, &body) == 0 && parse_body(e, body) == 0) check(e);
        free(t);
    }
    if (rc) return 1;

    /* The keys: each entry's name and aliases, normalised; the same key
     * from two files is the error, from one file (a case-only alias)
     * is one key. */
    key_t_ *keys = calloc((size_t)ENTRY_MAX * (LIST_MAX + 1), sizeof(*keys));
    int nkeys = 0;
    for (int k = 0; k < ne; k++) {
        const field_t *al = &E[k].f[F_ALIASES];
        for (int i = -1; i < al->n; i++) {
            const char *s = i < 0 ? E[k].f[F_NAME].items[0] : al->items[i];
            key_t_ kk;
            kk.entry = k;
            web_vkb_norm(s, kk.key, sizeof(kk.key));
            int dup = 0;
            for (int j = 0; j < nkeys; j++)
                if (!strcmp(keys[j].key, kk.key)) {
                    if (keys[j].entry != k) {
                        fail(&E[k], "\"%s\" is also %s's (the same name once spelling is folded)",
                             s, E[keys[j].entry].path);
                        return 1;
                    }
                    dup = 1;
                }
            if (!dup) keys[nkeys++] = kk;
        }
    }
    qsort(keys, (size_t)nkeys, sizeof(keys[0]), cmp_key);

    FILE *o = fopen(argv[1], "w");
    if (!o) { fprintf(stderr, "vendorkb: cannot write %s\n", argv[1]); return 1; }
    fprintf(o, "/* GENERATED by web/tools/vendorkb.c from the .md files under %s/.\n"
               " * Do not edit, do not commit: make regenerates it. */\n"
               "#include \"web_vendorkb.h\"\n\n", argv[2]);
    for (int k = 0; k < ne; k++) {
        const entry_t *e = &E[k];
        emit_list(o, "al", k, &e->f[F_ALIASES]);
        emit_list(o, "cls", k, &e->f[F_CLASSES]);
        emit_list(o, "fin", k, &e->f[F_FOUND_IN]);
        emit_list(o, "rad", k, &e->f[F_RADIOS]);
        emit_list(o, "sil", k, &e->f[F_SILICON]);
        emit_list(o, "fcc", k, &e->f[F_FCC]);
        emit_list(o, "sec", k, &e->f[F_SECURITY]);
        fprintf(o, "static const web_vkb_src_t src_%d[] = {\n", k);
        for (int i = 0; i < e->nsrc; i++) {
            fprintf(o, "  { ");
            c_string(o, e->src_title[i]);
            fprintf(o, ",\n    ");
            c_string(o, e->src_url[i]);
            fprintf(o, ", \"%s\" },\n", e->src_date[i]);
        }
        fprintf(o, "};\n\n");
    }
    fprintf(o, "const web_vkb_t web_vkb[] = {\n");
    for (int k = 0; k < ne; k++) {
        const entry_t *e = &E[k];
        fprintf(o, "  { ");
        c_string(o, e->path);
        fprintf(o, ",\n    ");
        c_string(o, e->f[F_NAME].items[0]);
        fprintf(o, ", al_%d, %d,\n    ", k, e->f[F_ALIASES].n);
        c_string(o, e->f[F_COUNTRY].items[0]);
        fprintf(o, ", ");
        c_string(o, e->f[F_PARENT].items[0]);
        fprintf(o, ", ");
        c_string(o, e->f[F_FOUNDED].items[0]);
        fprintf(o, ",\n    ");
        c_string(o, e->f[F_KIND].items[0]);
        fprintf(o, ",\n    cls_%d, %d, fin_%d, %d, rad_%d, %d, sil_%d, %d, fcc_%d, %d,\n    ",
                k, e->f[F_CLASSES].n, k, e->f[F_FOUND_IN].n, k, e->f[F_RADIOS].n,
                k, e->f[F_SILICON].n, k, e->f[F_FCC].n);
        c_string(o, e->f[F_RANDOM].items[0]);
        fprintf(o, ", sec_%d, %d,\n    ", k, e->f[F_SECURITY].n);
        fprintf(o, "\"%s\", \"%s\", \"%s\", \"%s\", \"%s\",\n    ", conf_of(e, "country"),
                conf_of(e, "silicon"), conf_of(e, "radios"), conf_of(e, "found_in"),
                conf_of(e, "randomization"));
        fprintf(o, "\"%s\",\n    ", e->f[F_RESEARCHED].items[0]);
        c_string(o, e->summary);
        fprintf(o, ",\n    src_%d, %d },\n", k, e->nsrc);
    }
    fprintf(o, "};\nconst int web_vkb_n = %d;\n\n", ne);
    fprintf(o, "const web_vkb_key_t web_vkb_keys[] = {\n");
    for (int i = 0; i < nkeys; i++) {
        fprintf(o, "  { ");
        c_string(o, keys[i].key);
        fprintf(o, ", %d },\n", keys[i].entry);
    }
    if (!nkeys) fprintf(o, "  { \"\", -1 },\n");
    fprintf(o, "};\nconst int web_vkb_nkeys = %d;\n", nkeys);
    return fclose(o) == 0 ? 0 : 1;
}
