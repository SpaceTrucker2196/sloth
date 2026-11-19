/* slothweb's Spectrum tab; web_spectrum.h says what and why. */
#include "web_spectrum.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "web_jsonl.h"

void web_spectrum_init(web_spectrum_t *sp, const char *dir, const char *request) {
    sp->marks[0] = '\0';
    snprintf(sp->dir, sizeof(sp->dir), "%s", dir ? dir : WEB_SPECTRUM_DIR);
    snprintf(sp->request, sizeof(sp->request), "%s", request ? request : WEB_SPECTRUM_REQUEST);
}

void web_spectrum_set_marks(web_spectrum_t *sp, const char *path) {
    snprintf(sp->marks, sizeof(sp->marks), "%s", path ? path : "");
}

/* ── the strict reader ── */

typedef struct {
    const char *p, *e;
    web_jw_t   *w;
    char       *tmp;      /* decoded string scratch, as long as the input */
} jc_t;

static void jc_ws(jc_t *c) {
    while (c->p < c->e && (*c->p == ' ' || *c->p == '\t' || *c->p == '\n' || *c->p == '\r'))
        c->p++;
}

static int hex4(const char *p, unsigned *v) {
    *v = 0;
    for (int i = 0; i < 4; i++) {
        char h = p[i];
        unsigned d = h >= '0' && h <= '9' ? (unsigned)(h - '0')
                   : h >= 'a' && h <= 'f' ? (unsigned)(h - 'a' + 10)
                   : h >= 'A' && h <= 'F' ? (unsigned)(h - 'A' + 10) : 16u;
        if (d > 15) return -1;
        *v = *v << 4 | d;
    }
    return 0;
}

static size_t put_utf8(char *o, unsigned cp) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | cp >> 6); o[1] = (char)(0x80 | (cp & 63)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | cp >> 12); o[1] = (char)(0x80 | ((cp >> 6) & 63));
        o[2] = (char)(0x80 | (cp & 63));
        return 3;
    }
    o[0] = (char)(0xF0 | cp >> 18); o[1] = (char)(0x80 | ((cp >> 12) & 63));
    o[2] = (char)(0x80 | ((cp >> 6) & 63)); o[3] = (char)(0x80 | (cp & 63));
    return 4;
}

/* A string at c->p (its opening quote), decoded into c->tmp: *len. A
 * raw control byte, a bad escape or a lone surrogate refuses it; raw
 * bytes over 0x7f are left for web_jw_strn(), which writes ill-formed
 * UTF-8 as U+FFFD. */
static int jc_string(jc_t *c, size_t *len) {
    if (c->p >= c->e || *c->p != '"') return -1;
    c->p++;
    size_t o = 0;
    while (c->p < c->e) {
        unsigned char ch = (unsigned char)*c->p++;
        if (ch == '"') { *len = o; return 0; }
        if (ch < 0x20) return -1;
        if (ch != '\\') { c->tmp[o++] = (char)ch; continue; }
        if (c->p >= c->e) return -1;
        char x = *c->p++;
        switch (x) {
        case '"': case '\\': case '/': c->tmp[o++] = x; break;
        case 'b': c->tmp[o++] = '\b'; break;
        case 'f': c->tmp[o++] = '\f'; break;
        case 'n': c->tmp[o++] = '\n'; break;
        case 'r': c->tmp[o++] = '\r'; break;
        case 't': c->tmp[o++] = '\t'; break;
        case 'u': {
            unsigned cp, lo;
            if (c->e - c->p < 4 || hex4(c->p, &cp)) return -1;
            c->p += 4;
            if (cp >= 0xDC00 && cp <= 0xDFFF) return -1;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                if (c->e - c->p < 6 || c->p[0] != '\\' || c->p[1] != 'u' ||
                    hex4(c->p + 2, &lo) || lo < 0xDC00 || lo > 0xDFFF)
                    return -1;
                c->p += 6;
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            }
            /* A \u escape is never longer decoded than written (6 bytes
             * for at most 3, 12 for 4), so tmp, as long as the input,
             * holds it. */
            o += put_utf8(c->tmp + o, cp);
            break;
        }
        default: return -1;
        }
    }
    return -1;
}

/* RFC 8259 §6: -? (0 | [1-9][0-9]*) (. [0-9]+)? ([eE] [+-]? [0-9]+)? */
static int jc_number(jc_t *c) {
    const char *s = c->p, *p = c->p, *e = c->e;
    if (p < e && *p == '-') p++;
    if (p >= e) return -1;
    if (*p == '0') p++;
    else if (*p >= '1' && *p <= '9') while (p < e && *p >= '0' && *p <= '9') p++;
    else return -1;
    if (p < e && *p == '.') {
        p++;
        if (p >= e || *p < '0' || *p > '9') return -1;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    if (p < e && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < e && (*p == '+' || *p == '-')) p++;
        if (p >= e || *p < '0' || *p > '9') return -1;
        while (p < e && *p >= '0' && *p <= '9') p++;
    }
    if (p - s > 40) return -1;
    /* Digits, a sign, '.' and 'e' only: inert in any context. */
    char num[48];
    memcpy(num, s, (size_t)(p - s));
    num[p - s] = '\0';
    web_jw_raw(c->w, num);
    c->p = p;
    return 0;
}

static int jc_lit(jc_t *c, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(c->e - c->p) < n || memcmp(c->p, lit, n)) return -1;
    web_jw_raw(c->w, lit);
    c->p += n;
    return 0;
}

static int jc_value(jc_t *c, int depth) {
    jc_ws(c);
    if (c->p >= c->e) return -1;
    size_t len;
    switch (*c->p) {
    case '"':
        if (jc_string(c, &len)) return -1;
        web_jw_strn(c->w, c->tmp, len);
        return 0;
    case 't': return jc_lit(c, "true");
    case 'f': return jc_lit(c, "false");
    case 'n': return jc_lit(c, "null");
    case '{': case '[': {
        char open = *c->p, close = open == '{' ? '}' : ']';
        const char *cs = open == '{' ? "}" : "]";
        if (depth >= WEB_SPECTRUM_DEPTH) return -1;
        c->p++;
        web_jw_raw(c->w, open == '{' ? "{" : "[");
        jc_ws(c);
        if (c->p < c->e && *c->p == close) { c->p++; web_jw_raw(c->w, cs); return 0; }
        for (int first = 1;; first = 0) {
            if (!first) web_jw_raw(c->w, ",");
            if (open == '{') {
                jc_ws(c);
                if (jc_string(c, &len)) return -1;
                web_jw_strn(c->w, c->tmp, len);
                jc_ws(c);
                if (c->p >= c->e || *c->p != ':') return -1;
                c->p++;
                web_jw_raw(c->w, ":");
            }
            if (jc_value(c, depth + 1)) return -1;
            jc_ws(c);
            if (c->p >= c->e) return -1;
            if (*c->p == ',') { c->p++; continue; }
            if (*c->p == close) { c->p++; web_jw_raw(c->w, cs); return 0; }
            return -1;
        }
    }
    default:
        return jc_number(c);
    }
}

int web_spectrum_copy_json(web_jw_t *w, const char *in, size_t n) {
    jc_t c = { in, in + n, w, malloc(n + 1) };
    if (!c.tmp) return -1;
    int rc = jc_value(&c, 0);
    if (rc == 0) {
        jc_ws(&c);
        if (c.p != c.e) rc = -1;
    }
    free(c.tmp);
    return rc == 0 && !w->overflow ? 0 : -1;
}

/* ── the ranges: sloth-sdrsweep's history directory ── */

static const struct { const char *name; long long secs; } RANGES[] = {
    { "last3", 0 }, { "1h", 3600 }, { "5h", 5 * 3600 }, { "12h", 12 * 3600 }, { "24h", 24 * 3600 },
};

int web_spectrum_range(const char *name, long long *secs) {
    for (size_t i = 0; i < sizeof(RANGES) / sizeof(RANGES[0]); i++)
        if (name && !strcmp(name, RANGES[i].name)) { *secs = RANGES[i].secs; return 0; }
    return -1;
}

int web_spectrum_pool(long long rows, long long bins) {
    if (rows < 1 || bins < 1) return 1;
    long long cells = rows * bins;
    long long k = (cells + WEB_SPECTRUM_HIST_CELLS - 1) / WEB_SPECTRUM_HIST_CELLS;
    return k < 1 ? 1 : k > bins ? (int)bins : (int)k;
}

/* The time a record's name carries: digits and ".json" only, as the
 * helper names them (sdrs_hist_name()); -1 for anything else. */
static long long hist_time(const char *name) {
    long long t = 0;
    int d = 0;
    for (; *name >= '0' && *name <= '9'; name++, d++) {
        if (d >= 12) return -1;
        t = t * 10 + (*name - '0');
    }
    return d && !strcmp(name, ".json") ? t : -1;
}

enum {
    K_VERSION = 1 << 0, K_STARTED = 1 << 1, K_ENDED = 1 << 2, K_FLOOR = 1 << 3,
    K_FLO = 1 << 4, K_FHI = 1 << 5, K_BINHZ = 1 << 6, K_BINS = 1 << 7, K_QUANT = 1 << 8,
    K_DATA = 1 << 9, K_ROWS = 1 << 10, K_PEAKS = 1 << 11, K_COMPLETE = 1 << 12,
    K_ANTENNA = 1 << 13,
};
#define K_NEED (K_VERSION | K_STARTED | K_ENDED | K_FLO | K_FHI | K_BINHZ | K_BINS | K_QUANT | \
                K_DATA | K_ROWS)

typedef struct {
    double    started, ended, floor, f_lo, f_hi, bin_hz, qoff, qstep, version;
    double    rows, bins;
    int       complete;
    char     *data;          /* the base64, decoded from its JSON string */
    size_t    dlen;
    size_t    ps, pe;        /* the "peaks" value's span in the file */
    char      antenna[64];
    size_t    alen;
    unsigned  seen;
} hrec_t;

/* A value checked by the strict reader and thrown away: the scratch
 * writer is rewound after it. */
static int jc_skip(jc_t *c, int depth) {
    size_t mark = c->w->len;
    int rc = jc_value(c, depth);
    c->w->len = mark;
    return rc || c->w->overflow ? -1 : 0;
}

/* A finite number (or, when allowed, null as NAN). */
static int jc_num(jc_t *c, double *out, int allow_null) {
    jc_ws(c);
    if (allow_null && c->p < c->e && *c->p == 'n') {
        if (jc_skip(c, WEB_SPECTRUM_DEPTH - 1)) return -1;
        *out = NAN;
        return 0;
    }
    const char *s = c->p;
    size_t mark = c->w->len;
    if (jc_number(c)) return -1;
    c->w->len = mark;
    char num[48];
    size_t n = (size_t)(c->p - s);
    memcpy(num, s, n);
    num[n] = '\0';
    double d = strtod(num, NULL);
    if (isnan(d) || isinf(d)) return -1;
    *out = d;
    return 0;
}

/* The member name at c->p into key (cap bytes): a longer one becomes
 * "" (no member this reader wants is that long). */
static int jc_key(jc_t *c, char *key, size_t cap) {
    size_t len;
    jc_ws(c);
    if (jc_string(c, &len)) return -1;
    if (len < cap && !memchr(c->tmp, '\0', len)) {
        memcpy(key, c->tmp, len);
        key[len] = '\0';
    } else {
        key[0] = '\0';
    }
    jc_ws(c);
    if (c->p >= c->e || *c->p != ':') return -1;
    c->p++;
    return 0;
}

static int hist_quant(jc_t *c, hrec_t *h) {
    jc_ws(c);
    if (c->p >= c->e || *c->p != '{') return -1;
    c->p++;
    int got = 0;
    for (;;) {
        char key[32];
        if (jc_key(c, key, sizeof(key))) return -1;
        if (!strcmp(key, "offset_db")) {
            if (got & 1 || jc_num(c, &h->qoff, 0)) return -1;
            got |= 1;
        } else if (!strcmp(key, "step_db")) {
            if (got & 2 || jc_num(c, &h->qstep, 0)) return -1;
            got |= 2;
        } else if (jc_skip(c, 2)) {
            return -1;
        }
        jc_ws(c);
        if (c->p >= c->e) return -1;
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == '}') { c->p++; return got == 3 ? 0 : -1; }
        return -1;
    }
}

/* One record, whole: every value checked by the strict reader, the ones
 * this answer uses kept. 0, or -1 (h->data is then freed). */
static int hist_parse(const char *text, size_t n, web_jw_t *scratch, hrec_t *h) {
    memset(h, 0, sizeof(*h));
    h->floor = NAN;
    h->complete = 1;
    jc_t c = { text, text + n, scratch, malloc(n + 1) };
    if (!c.tmp) return -1;
    int rc = -1;
    jc_ws(&c);
    if (c.p >= c.e || *c.p != '{') goto out;
    c.p++;
    for (;;) {
        char key[32];
        if (jc_key(&c, key, sizeof(key))) goto out;
        static const struct { const char *k; unsigned bit; } K[] = {
            { "version", K_VERSION }, { "started", K_STARTED }, { "ended", K_ENDED },
            { "floor", K_FLOOR }, { "f_lo", K_FLO }, { "f_hi", K_FHI }, { "bin_hz", K_BINHZ },
            { "bins", K_BINS }, { "quant", K_QUANT }, { "data", K_DATA }, { "rows", K_ROWS },
            { "peaks", K_PEAKS }, { "complete", K_COMPLETE }, { "antenna", K_ANTENNA },
        };
        unsigned bit = 0;
        for (size_t i = 0; i < sizeof(K) / sizeof(K[0]); i++)
            if (!strcmp(key, K[i].k)) bit = K[i].bit;
        /* A member twice is refused: which one counts is what a
         * hostile file would like to choose. */
        if (bit & h->seen) goto out;
        h->seen |= bit;
        int r = 0;
        size_t len;
        switch (bit) {
        case K_VERSION:  r = jc_num(&c, &h->version, 0); break;
        case K_STARTED:  r = jc_num(&c, &h->started, 0); break;
        case K_ENDED:    r = jc_num(&c, &h->ended, 0); break;
        case K_FLOOR:    r = jc_num(&c, &h->floor, 1); break;
        case K_FLO:      r = jc_num(&c, &h->f_lo, 0); break;
        case K_FHI:      r = jc_num(&c, &h->f_hi, 0); break;
        case K_BINHZ:    r = jc_num(&c, &h->bin_hz, 0); break;
        case K_BINS:     r = jc_num(&c, &h->bins, 0); break;
        case K_ROWS:     r = jc_num(&c, &h->rows, 0); break;
        case K_QUANT:    r = hist_quant(&c, h); break;
        case K_COMPLETE:
            jc_ws(&c);
            if (c.e - c.p >= 4 && !memcmp(c.p, "true", 4)) { h->complete = 1; c.p += 4; }
            else if (c.e - c.p >= 5 && !memcmp(c.p, "false", 5)) { h->complete = 0; c.p += 5; }
            else r = -1;
            break;
        case K_ANTENNA:
            jc_ws(&c);
            r = jc_string(&c, &len);
            if (!r) {
                h->alen = len < sizeof(h->antenna) ? len : sizeof(h->antenna) - 1;
                memcpy(h->antenna, c.tmp, h->alen);
            }
            break;
        case K_DATA:
            jc_ws(&c);
            r = jc_string(&c, &len);
            if (!r) {
                /* A repeated "data" key: the last one wins, and the
                 * first is not leaked. */
                free(h->data);
                h->data = malloc(len + 1);
                if (!h->data) { r = -1; break; }
                memcpy(h->data, c.tmp, len);
                h->dlen = len;
            }
            break;
        case K_PEAKS:
            jc_ws(&c);
            h->ps = (size_t)(c.p - text);
            r = c.p < c.e && *c.p == '[' ? jc_skip(&c, 1) : -1;
            h->pe = (size_t)(c.p - text);
            break;
        default:
            r = jc_skip(&c, 1);
        }
        if (r) goto out;
        jc_ws(&c);
        if (c.p >= c.e) goto out;
        if (*c.p == ',') { c.p++; continue; }
        if (*c.p == '}') { c.p++; break; }
        goto out;
    }
    jc_ws(&c);
    if (c.p != c.e || (h->seen & K_NEED) != K_NEED) goto out;
    /* The shape this reader can draw: version 1, a grid that is one,
     * whole numbers where counts are meant. */
    if (h->version != 1 || h->started <= 0 || !(h->f_hi > h->f_lo) || !(h->bin_hz > 0) ||
        !(h->bins >= 1 && h->bins <= WEB_SPECTRUM_BINS_MAX) || h->bins != floor(h->bins) ||
        !(h->rows >= 1 && h->rows <= 1000) || h->rows != floor(h->rows) || !(h->qstep > 0))
        goto out;
    rc = 0;
out:
    free(c.tmp);
    if (rc) { free(h->data); h->data = NULL; }
    return rc;
}

static int b64v(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

int web_spectrum_b64_decode(const char *s, size_t n, uint8_t *out, size_t want) {
    if (n != 4 * ((want + 2) / 3)) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4], pad = 0;
        for (int k = 0; k < 4; k++) {
            unsigned char ch = (unsigned char)s[i + k];
            /* "=" only as the last one or two of the last quantum. */
            if (ch == '=' && i + 4 == n && k >= 2) { v[k] = 0; pad++; continue; }
            if (pad || (v[k] = b64v(ch)) < 0) return -1;
        }
        unsigned x = (unsigned)v[0] << 18 | (unsigned)v[1] << 12 | (unsigned)v[2] << 6 | (unsigned)v[3];
        int bytes = 3 - pad;
        if (o + (size_t)bytes > want) return -1;
        out[o++] = (uint8_t)(x >> 16);
        if (bytes > 1) out[o++] = (uint8_t)(x >> 8);
        if (bytes > 2) out[o++] = (uint8_t)x;
    }
    return o == want ? 0 : -1;
}

static void jw_b64(web_jw_t *w, const uint8_t *in, size_t n) {
    static const char A[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char chunk[4 * 256 + 1];
    size_t o = 0;
    web_jw_raw(w, "\"");
    for (size_t i = 0; i < n; i += 3) {
        unsigned x = (unsigned)in[i] << 16;
        if (i + 1 < n) x |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) x |= in[i + 2];
        chunk[o++] = A[x >> 18 & 63];
        chunk[o++] = A[x >> 12 & 63];
        chunk[o++] = i + 1 < n ? A[x >> 6 & 63] : '=';
        chunk[o++] = i + 2 < n ? A[x & 63] : '=';
        if (o == sizeof(chunk) - 1) { chunk[o] = '\0'; web_jw_raw(w, chunk); o = 0; }
    }
    chunk[o] = '\0';
    web_jw_raw(w, chunk);
    web_jw_raw(w, "\"");
}

/* A number this file computed or checked, written by printf: never the
 * file's own bytes. NAN as null. */
static void jw_dbl(web_jw_t *w, double v, int prec) {
    char b[64];
    if (isnan(v) || isinf(v)) { web_jw_raw(w, "null"); return; }
    snprintf(b, sizeof(b), "%.*f", prec, v);
    web_jw_raw(w, b);
}

typedef struct {
    double t, ended, floor;
    long long rows;
    int complete;
} hrow_t;

static int cmp_ll_desc(const void *a, const void *b) {
    long long x = *(const long long *)a, y = *(const long long *)b;
    return (x < y) - (x > y);
}

/* A regular file in the history directory, by name, never through a
 * link: NULL when it is not one, or is over max. */
static char *slurp_at(int dfd, const char *name, long max, size_t *len) {
    int fd = openat(dfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > max) { close(fd); return NULL; }
    char *b = malloc((size_t)st.st_size + 1);
    size_t n = 0;
    while (b && n < (size_t)st.st_size) {
        ssize_t r = read(fd, b + n, (size_t)st.st_size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (!b) return NULL;
    b[n] = '\0';
    *len = n;
    return b;
}

/* The window's rows into a malloc'd "sweep" object (*out, *outlen), or
 * *out NULL when no record in it could be read. *runs and *skipped
 * count the records used and those refused (unreadable, invalid, or on
 * another grid than the newest). 0, or -1 when out of memory. */
static int hist_window(const web_spectrum_t *sp, const char *rname, long long secs,
                       long long now_s, char **out, size_t *outlen, int *runs, int *skipped) {
    *out = NULL;
    *outlen = 0;
    *runs = 0;
    *skipped = 0;
    char path[1100];
    snprintf(path, sizeof(path), "%s/" WEB_SPECTRUM_HIST_DIR, sp->dir);
    int dfd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dfd < 0) return 0;
    DIR *d = fdopendir(dup(dfd));
    if (!d) { close(dfd); return 0; }
    long long *ts = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    int rc = -1;
    while ((e = readdir(d))) {
        long long t = hist_time(e->d_name);
        /* The window by the name's time; the record's own "started" is
         * checked against it again once read. */
        if (t < 0 || (secs && (t < now_s - secs || t > now_s + 300))) continue;
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 64;
            long long *g = realloc(ts, nc * sizeof(*ts));
            if (!g) { closedir(d); close(dfd); free(ts); return -1; }
            ts = g;
            cap = nc;
        }
        ts[n++] = t;
    }
    closedir(d);
    if (n) qsort(ts, n, sizeof(*ts), cmp_ll_desc);
    /* Newest first, at most WEB_SPECTRUM_HIST_MAX_RUNS of them; last3
     * reads on past bad records, a bounded number of them. */
    size_t want = secs ? n : 3, tries = secs ? n : 3 + 16;
    if (want > WEB_SPECTRUM_HIST_MAX_RUNS) want = WEB_SPECTRUM_HIST_MAX_RUNS;
    if (tries > WEB_SPECTRUM_HIST_MAX_RUNS) tries = WEB_SPECTRUM_HIST_MAX_RUNS;

    hrec_t g0;                       /* the newest good record: the grid */
    char *g0text = NULL;
    memset(&g0, 0, sizeof(g0));
    uint8_t *cells = NULL, *q = NULL;
    hrow_t *meta = NULL;
    char *scratch = NULL;
    size_t scap = 0;
    int k = 1;
    long long ob = 0;                /* bins out */
    int used = 0;
    for (size_t i = 0; i < n && i < tries && (size_t)used < want; i++) {
        char name[32];
        snprintf(name, sizeof(name), "%lld.json", ts[i]);
        size_t tl = 0;
        char *text = slurp_at(dfd, name, WEB_SPECTRUM_HIST_MAX_BYTES, &tl);
        if (!text) { (*skipped)++; continue; }
        size_t need = tl * WEB_JW_EXPAND + 64;
        if (need > scap) {
            char *g = realloc(scratch, need);
            if (!g) { free(text); goto done; }
            scratch = g;
            scap = need;
        }
        web_jw_t sw;
        web_jw_init(&sw, scratch, scap);
        hrec_t h;
        if (hist_parse(text, tl, &sw, &h) != 0) {
            free(text);
            (*skipped)++;
            continue;
        }
        if (secs && (h.started < (double)(now_s - secs) || h.started > (double)(now_s + 300))) {
            /* Parsed, so it owns its data, but outside the window. */
            free(h.data);
            free(text);
            (*skipped)++;
            continue;
        }
        if (!used) {
            /* The newest record sets the grid and the pooling, sized for
             * every candidate so the cells never grow. */
            k = web_spectrum_pool((long long)want, (long long)h.bins);
            ob = ((long long)h.bins + k - 1) / k;
            cells = malloc(want * (size_t)ob);
            q = malloc((size_t)h.bins);
            meta = malloc(want * sizeof(*meta));
            if (!cells || !q || !meta) { free(text); free(h.data); goto done; }
        } else if (h.f_lo != g0.f_lo || h.f_hi != g0.f_hi || h.bin_hz != g0.bin_hz ||
                   h.bins != g0.bins || h.qoff != g0.qoff || h.qstep != g0.qstep) {
            /* Another grid (the operator changed the span): not this
             * window's rows. */
            free(text); free(h.data);
            (*skipped)++;
            continue;
        }
        if (web_spectrum_b64_decode(h.data, h.dlen, q, (size_t)h.bins) != 0) {
            free(text); free(h.data);
            if (!used) { free(cells); free(q); free(meta); cells = NULL; q = NULL; meta = NULL; }
            (*skipped)++;
            continue;
        }
        free(h.data);
        h.data = NULL;
        /* Max-pool k bins into one: a narrow carrier survives the
         * pooling, it only gets wider. */
        uint8_t *row = cells + (size_t)used * (size_t)ob;
        for (long long j = 0; j < ob; j++) {
            uint8_t m = 0;
            long long a = j * k, b = a + k < (long long)h.bins ? a + k : (long long)h.bins;
            for (long long x = a; x < b; x++) if (q[x] > m) m = q[x];
            row[j] = m;
        }
        meta[used] = (hrow_t){ h.started, h.ended, h.floor, (long long)h.rows, h.complete };
        if (!used) { g0 = h; g0text = text; } else free(text);
        used++;
    }
    rc = 0;
    if (!used) goto done;
    /* Every row's base64 and its numbers, the newest record's peaks
     * re-serialised (six-fold at worst) and its antenna. */
    size_t ocap = 4096 + (size_t)used * (4 * ((size_t)ob / 3 + 1) + 256) +
                  (g0.pe - g0.ps) * WEB_JW_EXPAND + sizeof(g0.antenna) * WEB_JW_EXPAND;
    char *o = malloc(ocap);
    if (!o) { rc = -1; goto done; }
    web_jw_t w;
    web_jw_init(&w, o, ocap);
    web_jw_raw(&w, "{\"version\":1,\"mode\":\"history\",\"range\":");
    web_jw_str(&w, rname);
    web_jw_raw(&w, ",\"from\":");
    web_jw_int(&w, secs ? now_s - secs : (long long)floor(meta[used - 1].t));
    web_jw_raw(&w, ",\"to\":");
    web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"runs\":");
    web_jw_int(&w, used);
    web_jw_raw(&w, ",\"skipped\":");
    web_jw_int(&w, *skipped);
    web_jw_raw(&w, ",\"pool\":");
    web_jw_int(&w, k);
    web_jw_raw(&w, ",\"f_lo\":");    jw_dbl(&w, g0.f_lo, 0);
    web_jw_raw(&w, ",\"f_hi\":");    jw_dbl(&w, g0.f_hi, 0);
    web_jw_raw(&w, ",\"bin_hz\":");  jw_dbl(&w, g0.bin_hz * k, 0);
    web_jw_raw(&w, ",\"bins\":");    web_jw_int(&w, ob);
    web_jw_raw(&w, ",\"quant\":{\"offset_db\":"); jw_dbl(&w, g0.qoff, 1);
    web_jw_raw(&w, ",\"step_db\":"); jw_dbl(&w, g0.qstep, 2);
    web_jw_raw(&w, "},\"antenna\":");
    web_jw_strn(&w, g0.antenna, g0.alen);
    web_jw_raw(&w, ",\"started\":"); jw_dbl(&w, meta[used - 1].t, 3);
    web_jw_raw(&w, ",\"ended\":");   jw_dbl(&w, meta[0].ended, 3);
    web_jw_raw(&w, ",\"rows\":[");
    for (int i = used - 1; i >= 0; i--) {           /* oldest first */
        web_jw_raw(&w, i == used - 1 ? "\n{\"t\":" : ",\n{\"t\":");
        jw_dbl(&w, meta[i].t, 3);
        web_jw_raw(&w, ",\"ended\":");
        jw_dbl(&w, meta[i].ended, 3);
        web_jw_raw(&w, ",\"floor\":");
        jw_dbl(&w, meta[i].floor, 1);
        web_jw_raw(&w, ",\"rows\":");
        web_jw_int(&w, meta[i].rows);
        web_jw_raw(&w, meta[i].complete ? ",\"complete\":true,\"data\":" : ",\"complete\":false,\"data\":");
        jw_b64(&w, cells + (size_t)i * (size_t)ob, (size_t)ob);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"peaks\":");
    size_t pmark = w.len;
    if (!(g0.seen & K_PEAKS) || web_spectrum_copy_json(&w, g0text + g0.ps, g0.pe - g0.ps) != 0) {
        w.len = pmark;
        w.overflow = 0;
        o[pmark] = '\0';
        web_jw_raw(&w, "[]");
    }
    web_jw_raw(&w, "}");
    if (w.overflow) { free(o); rc = -1; goto done; }
    *out = o;
    *outlen = w.len;
    *runs = used;
done:
    free(g0text);
    free(cells); free(q); free(meta); free(scratch); free(ts);
    close(dfd);
    return rc;
}

/* ── the state directory ── */

/* A regular file of at most max bytes, NUL-terminated. NULL and *why
 * "absent", "too_large" or "unreadable". Never follows a link: the
 * directory is another account's. */
static char *slurp(const char *path, long max, size_t *len, const char **why) {
    *why = "unreadable";
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { if (errno == ENOENT) *why = "absent"; return NULL; }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return NULL; }
    if (st.st_size > max) { *why = "too_large"; close(fd); return NULL; }
    char *b = malloc((size_t)st.st_size + 1);
    size_t n = 0;
    while (b && n < (size_t)st.st_size) {
        ssize_t r = read(fd, b + n, (size_t)st.st_size - n);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        n += (size_t)r;
    }
    close(fd);
    if (!b) return NULL;
    b[n] = '\0';
    *len = n;
    return b;
}

typedef struct {
    int    installed;
    int    have;            /* status.json read */
    char   state[16], mode[16], antenna[64], error[32];
    double started, updated, ended, next_allowed, cooldown;
    long long row, step, steps;
    int    running, stale;
    int    queued;
    long long queued_since;
} st_t;

static void copy_word(char *dst, size_t cap, const char *s) {
    size_t o = 0;
    for (; s && *s && o + 1 < cap; s++)
        if ((unsigned char)*s >= 0x20 && (unsigned char)*s < 0x7f) dst[o++] = *s;
    dst[o] = '\0';
}

static double num_or(const web_jrec_t *r, const char *k, double def) {
    double d;
    return web_jl_num(r, k, &d) ? d : def;
}

static void read_state(const web_spectrum_t *sp, long long now_s, st_t *s) {
    memset(s, 0, sizeof(*s));
    struct stat st;
    s->installed = stat(sp->dir, &st) == 0 && S_ISDIR(st.st_mode);
    if (lstat(sp->request, &st) == 0) {
        s->queued = 1;
        s->queued_since = (long long)st.st_mtime;
    }
    if (!s->installed) return;
    char path[1100];
    snprintf(path, sizeof(path), "%s/status.json", sp->dir);
    size_t n = 0;
    const char *why;
    char *t = slurp(path, WEB_JL_MAX_LINE, &n, &why);
    if (!t) return;
    web_jrec_t *r = malloc(sizeof(*r));
    if (r) {
        int pr = web_jl_parse(t, n, r);
        if (pr == WEB_JL_OK || pr == WEB_JL_ETYPE) {
            s->have = 1;
            copy_word(s->state, sizeof(s->state), web_jl_str(r, "state"));
            copy_word(s->mode, sizeof(s->mode), web_jl_str(r, "mode"));
            copy_word(s->antenna, sizeof(s->antenna), web_jl_str(r, "antenna"));
            copy_word(s->error, sizeof(s->error), web_jl_str(r, "error"));
            s->started = num_or(r, "started", 0);
            s->updated = num_or(r, "updated", 0);
            s->ended = num_or(r, "ended", 0);
            s->next_allowed = num_or(r, "next_allowed", 0);
            s->cooldown = num_or(r, "cooldown", 0);
            /* slothweb's own floor under the helper's cooldown, so a
             * cooldown the operator set short (or 0) still cannot turn
             * the Run button into a way to hold the receiver. */
            if (s->ended > 0 && s->ended + WEB_SPECTRUM_MIN_GAP_S > s->next_allowed)
                s->next_allowed = s->ended + WEB_SPECTRUM_MIN_GAP_S;
            s->row = web_jl_int(r, "row", 0);
            s->step = web_jl_int(r, "step", 0);
            s->steps = web_jl_int(r, "steps", 0);
            if (!strcmp(s->state, "running")) {
                s->running = now_s - (long long)s->updated <= WEB_SPECTRUM_STALE_S;
                s->stale = !s->running;
            }
        }
        free(r);
    }
    free(t);
}

/* Whether a run may be asked for now: 0, or the refusal's status with
 * its word and, for 429, the seconds to wait. */
static int decide(const st_t *s, long long now_s, const char **why, long long *retry) {
    *retry = 0;
    if (!s->installed) { *why = "not_installed"; return 503; }
    if (s->running) { *why = "running"; return 409; }
    if (s->queued) { *why = "queued"; return 409; }
    if (s->next_allowed > (double)now_s) {
        *retry = (long long)ceil(s->next_allowed - (double)now_s);
        *why = "cooldown";
        return 429;
    }
    *why = NULL;
    return 0;
}

static void jw_num(web_jw_t *w, double v) { web_jw_int(w, (long long)floor(v)); }

static void status_json(web_jw_t *w, const st_t *s, long long now_s) {
    const char *why;
    long long retry;
    int d = decide(s, now_s, &why, &retry);
    web_jw_raw(w, "\"installed\":");
    web_jw_raw(w, s->installed ? "true" : "false");
    web_jw_raw(w, ",\"now\":");
    web_jw_int(w, now_s);
    web_jw_raw(w, ",\"state\":");
    web_jw_str(w, s->stale ? "stale" : s->have && s->state[0] ? s->state : "idle");
    web_jw_raw(w, ",\"running\":");
    web_jw_raw(w, s->running ? "true" : "false");
    web_jw_raw(w, ",\"queued\":");
    web_jw_raw(w, s->queued ? "true" : "false");
    if (s->queued) { web_jw_raw(w, ",\"queued_since\":"); web_jw_int(w, s->queued_since); }
    web_jw_raw(w, ",\"can_run\":");
    web_jw_raw(w, d ? "false" : "true");
    if (why) { web_jw_raw(w, ",\"why_not\":"); web_jw_str(w, why); }
    web_jw_raw(w, ",\"retry_after\":");
    web_jw_int(w, retry);
    if (s->have) {
        web_jw_raw(w, ",\"mode\":");     web_jw_str(w, s->mode);
        web_jw_raw(w, ",\"antenna\":");  web_jw_str(w, s->antenna);
        web_jw_raw(w, ",\"started\":");  jw_num(w, s->started);
        web_jw_raw(w, ",\"updated\":");  jw_num(w, s->updated);
        if (s->ended > 0) { web_jw_raw(w, ",\"ended\":"); jw_num(w, s->ended); }
        if (s->next_allowed > 0) {
            web_jw_raw(w, ",\"next_allowed\":");
            jw_num(w, ceil(s->next_allowed));
        }
        web_jw_raw(w, ",\"cooldown\":"); jw_num(w, s->cooldown);
        web_jw_raw(w, ",\"row\":");      web_jw_int(w, s->row);
        web_jw_raw(w, ",\"step\":");     web_jw_int(w, s->step);
        web_jw_raw(w, ",\"steps\":");    web_jw_int(w, s->steps);
        if (s->error[0]) { web_jw_raw(w, ",\"error\":"); web_jw_str(w, s->error); }
    }
}

/* ── the operator's marks ── */

int web_spectrum_mark_line(const char *line, size_t n, long long *hz, char *name, size_t cap) {
    size_t i = 0;
    while (n && (line[n - 1] == '\r' || line[n - 1] == ' ' || line[n - 1] == '\t')) n--;
    while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
    if (i == n || line[i] == '#') return 0;
    /* The frequency: digits, at most one point, at most six decimals,
     * kept as an integer so no float rounds a channel. */
    long long whole = 0, frac = 0;
    int nd = 0, nf = 0, point = 0;
    for (; i < n && line[i] != ','; i++) {
        char ch = line[i];
        if (ch == '.' && !point) { point = 1; continue; }
        if (ch < '0' || ch > '9') return -1;
        if (!point) {
            if (++nd > 5) return -1;
            whole = whole * 10 + (ch - '0');
        } else {
            if (++nf > 6) return -1;
            frac = frac * 10 + (ch - '0');
        }
    }
    if (!nd || (point && !nf) || i == n) return -1;
    for (; nf < 6; nf++) frac *= 10;
    long long f = whole * 1000000LL + frac;
    if (f < 1000 || f > 30000000000LL) return -1;
    i++;
    while (i < n && (line[i] == ' ' || line[i] == '\t')) i++;
    size_t len = n - i;
    if (!len || len > WEB_SPECTRUM_MARK_NAME || len + 1 > cap) return -1;
    for (size_t k = 0; k < len; k++)
        if ((unsigned char)line[i + k] < 0x20 || (unsigned char)line[i + k] > 0x7e) return -1;
    memcpy(name, line + i, len);
    name[len] = '\0';
    *hz = f;
    return 1;
}

static int marks_json(const web_spectrum_t *sp, char **body, size_t *len) {
    size_t cap = 256 + (size_t)WEB_SPECTRUM_MARKS_MAX * (64 + WEB_SPECTRUM_MARK_NAME * WEB_JW_EXPAND);
    char *out = malloc(cap);
    if (!out) return -1;
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{\"configured\":");
    web_jw_raw(&w, sp->marks[0] ? "true" : "false");
    web_jw_raw(&w, ",\"marks\":[");
    int n = 0, skipped = 0;
    const char *why = NULL;
    if (sp->marks[0]) {
        size_t tl = 0;
        char *text = slurp(sp->marks, WEB_SPECTRUM_MARKS_MAX_BYTES, &tl, &why);
        if (text) {
            why = NULL;
            for (size_t a = 0; a < tl; ) {
                size_t b = a;
                while (b < tl && text[b] != '\n') b++;
                long long hz = 0;
                char name[WEB_SPECTRUM_MARK_NAME + 1];
                int rc = web_spectrum_mark_line(text + a, b - a, &hz, name, sizeof(name));
                if (rc < 0 || (rc > 0 && n >= WEB_SPECTRUM_MARKS_MAX)) skipped++;
                else if (rc > 0) {
                    web_jw_raw(&w, n ? ",{\"f_hz\":" : "{\"f_hz\":");
                    web_jw_int(&w, hz);
                    web_jw_raw(&w, ",\"label\":");
                    web_jw_str(&w, name);
                    web_jw_raw(&w, "}");
                    n++;
                }
                a = b + 1;
            }
            free(text);
        }
    }
    web_jw_raw(&w, "],\"skipped\":");
    web_jw_int(&w, skipped);
    if (why) {
        web_jw_raw(&w, ",\"error\":");
        web_jw_str(&w, why);
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) { free(out); return -1; }
    *body = out;
    *len = w.len;
    return 0;
}

int web_spectrum_get(const web_spectrum_t *sp, const char *query, long long now_s,
                     int out_of_scope, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    int status_only = 0;
    const char *rname = NULL;
    long long secs = 0;
    if (query && query[0]) {
        const char *err = "{\"error\":\"unknown_parameter\"}\n";
        if (!strncmp(query, "range=", 6)) {
            rname = query + 6;
            if (web_spectrum_range(rname, &secs) != 0) err = "{\"error\":\"unknown_range\"}\n";
            else err = NULL;
        } else if (!strcmp(query, "status=1")) {
            status_only = 1;
            err = NULL;
        } else if (!strcmp(query, "marks=1")) {
            *status = 200;
            return marks_json(sp, body, len);
        }
        if (err) {
            size_t el = strlen(err);
            *body = malloc(el + 1);
            if (!*body) return -1;
            memcpy(*body, err, el + 1);
            *len = el;
            *status = 400;
            return 0;
        }
    }
    if (out_of_scope) status_only = 1;
    st_t s;
    read_state(sp, now_s, &s);
    char *doc = NULL;
    size_t dl = 0;
    const char *why = "absent";
    if (rname && !status_only) {
        char *hist = NULL;
        size_t hl = 0;
        int runs = 0, skipped = 0;
        if (s.installed &&
            hist_window(sp, rname, secs, now_s, &hist, &hl, &runs, &skipped) != 0)
            return -1;
        size_t cap = 4096 + hl;
        char *out = malloc(cap);
        if (!out) { free(hist); return -1; }
        web_jw_t w;
        web_jw_init(&w, out, cap);
        web_jw_raw(&w, "{");
        status_json(&w, &s, now_s);
        web_jw_raw(&w, ",\"range\":");
        web_jw_str(&w, rname);
        web_jw_raw(&w, ",\"runs\":");
        web_jw_int(&w, runs);
        web_jw_raw(&w, ",\"skipped\":");
        web_jw_int(&w, skipped);
        web_jw_raw(&w, ",\"sweep\":");
        /* hist is this file's own writer's output (hist_window()):
         * every value in it was re-serialised there. */
        if (hist) web_jw_raw(&w, hist);
        else web_jw_raw(&w, "null");
        web_jw_raw(&w, "}\n");
        free(hist);
        if (w.overflow) { free(out); return -1; }
        *body = out;
        *len = w.len;
        *status = 200;
        return 0;
    }
    if (!status_only && s.installed) {
        char path[1100];
        snprintf(path, sizeof(path), "%s/latest.json", sp->dir);
        doc = slurp(path, WEB_SPECTRUM_MAX_BYTES, &dl, &why);
    }
    /* Every byte of the document can grow six-fold under escaping. */
    size_t cap = 4096 + dl * WEB_JW_EXPAND;
    char *out = malloc(cap);
    if (!out) { free(doc); return -1; }
    web_jw_t w;
    web_jw_init(&w, out, cap);
    web_jw_raw(&w, "{");
    status_json(&w, &s, now_s);
    if (out_of_scope) web_jw_raw(&w, ",\"out_of_scope\":true,\"sweep\":null");
    if (!status_only) {
        web_jw_raw(&w, ",\"sweep\":");
        size_t mark = w.len;
        if (doc && web_spectrum_copy_json(&w, doc, dl) == 0) {
            why = NULL;
        } else {
            if (doc) why = "invalid";
            w.len = mark;
            w.overflow = 0;
            out[mark] = '\0';
            web_jw_raw(&w, "null");
        }
        if (why && strcmp(why, "absent") != 0) {
            web_jw_raw(&w, ",\"sweep_error\":");
            web_jw_str(&w, why);
        }
    }
    web_jw_raw(&w, "}\n");
    free(doc);
    if (w.overflow) { free(out); return -1; }
    *body = out;
    *len = w.len;
    *status = 200;
    return 0;
}

static int answer(web_jw_t *w, char *body, size_t *len, int *status, int code) {
    if (w->overflow) return -1;
    (void)body;
    *len = w->len;
    *status = code;
    return 0;
}

int web_spectrum_run(const web_spectrum_t *sp, long long now_s, char *body, size_t cap,
                     size_t *len, int *status, char *extra, size_t extracap) {
    extra[0] = '\0';
    web_jw_t w;
    web_jw_init(&w, body, cap);
    st_t s;
    read_state(sp, now_s, &s);
    const char *why;
    long long retry;
    int d = decide(&s, now_s, &why, &retry);
    if (d) {
        if (d == 429) snprintf(extra, extracap, "Retry-After: %lld\r\n", retry);
        web_jw_raw(&w, "{\"error\":");
        web_jw_str(&w, why);
        if (d == 429) { web_jw_raw(&w, ",\"retry_after\":"); web_jw_int(&w, retry); }
        web_jw_raw(&w, "}\n");
        return answer(&w, body, len, status, d);
    }
    /* O_EXCL: two POSTs racing make one request, and the second is
     * told so. Empty: the helper reads nothing from it. */
    int fd = open(sp->request, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        int ex = errno == EEXIST;
        web_jw_raw(&w, ex ? "{\"error\":\"queued\"}\n" : "{\"error\":\"request_failed\"}\n");
        return answer(&w, body, len, status, ex ? 409 : 503);
    }
    close(fd);
    web_jw_raw(&w, "{\"queued\":true,\"requested\":");
    web_jw_int(&w, now_s);
    web_jw_raw(&w, "}\n");
    return answer(&w, body, len, status, 202);
}
