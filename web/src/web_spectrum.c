/* slothweb's Spectrum tab; web_spectrum.h says what and why. */
#include "web_spectrum.h"

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
    snprintf(sp->dir, sizeof(sp->dir), "%s", dir ? dir : WEB_SPECTRUM_DIR);
    snprintf(sp->request, sizeof(sp->request), "%s", request ? request : WEB_SPECTRUM_REQUEST);
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

int web_spectrum_get(const web_spectrum_t *sp, const char *query, long long now_s,
                     int out_of_scope, char **body, size_t *len, int *status) {
    *body = NULL;
    *len = 0;
    int status_only = 0;
    if (query && query[0]) {
        if (strcmp(query, "status=1") != 0) {
            static const char E[] = "{\"error\":\"unknown_parameter\"}\n";
            *body = malloc(sizeof(E));
            if (!*body) return -1;
            memcpy(*body, E, sizeof(E));
            *len = sizeof(E) - 1;
            *status = 400;
            return 0;
        }
        status_only = 1;
    }
    if (out_of_scope) status_only = 1;
    st_t s;
    read_state(sp, now_s, &s);
    char *doc = NULL;
    size_t dl = 0;
    const char *why = "absent";
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
