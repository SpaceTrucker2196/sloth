#include "web_jsonl.h"

#include <string.h>

#include "web_json.h"

typedef struct {
    const unsigned char *p, *end;
    web_jrec_t          *r;
    int                  err;
} jp_t;

static int fail(jp_t *j, int e) {
    if (!j->err) j->err = e;
    return -1;
}

static void ws(jp_t *j) {
    while (j->p < j->end &&
           (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n'))
        j->p++;
}

static int hex4(jp_t *j, unsigned *v) {
    if (j->end - j->p < 4) return fail(j, WEB_JL_ESYNTAX);
    unsigned x = 0;
    for (int i = 0; i < 4; i++) {
        unsigned c = j->p[i], d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return fail(j, WEB_JL_ESYNTAX);
        x = (x << 4) | d;
    }
    j->p += 4;
    *v = x;
    return 0;
}

static void emit(jp_t *j, int store, const unsigned char *b, size_t n) {
    if (!store) return;
    memcpy(j->r->text + j->r->tlen, b, n);
    j->r->tlen += n;
}

static void emit_cp(jp_t *j, int store, unsigned cp) {
    unsigned char b[4];
    size_t n;
    if (cp < 0x80)        { b[0] = (unsigned char)cp; n = 1; }
    else if (cp < 0x800)  { b[0] = (unsigned char)(0xC0 | (cp >> 6));
                            b[1] = (unsigned char)(0x80 | (cp & 0x3F)); n = 2; }
    else if (cp < 0x10000){ b[0] = (unsigned char)(0xE0 | (cp >> 12));
                            b[1] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                            b[2] = (unsigned char)(0x80 | (cp & 0x3F)); n = 3; }
    else                  { b[0] = (unsigned char)(0xF0 | (cp >> 18));
                            b[1] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F));
                            b[2] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F));
                            b[3] = (unsigned char)(0x80 | (cp & 0x3F)); n = 4; }
    emit(j, store, b, n);
}

/* A string at j->p (on the opening quote). With store, its decoded
 * bytes and a NUL go to the record's text and *out points at them. */
static int string(jp_t *j, int store, const char **out, size_t *olen) {
    j->p++;                                   /* the quote */
    size_t start = j->r->tlen;
    for (;;) {
        if (j->p >= j->end) return fail(j, WEB_JL_ESYNTAX);
        unsigned c = *j->p;
        if (c == '"') { j->p++; break; }
        if (c < 0x20) return fail(j, WEB_JL_ESYNTAX);   /* raw control */
        if (c == '\\') {
            j->p++;
            if (j->p >= j->end) return fail(j, WEB_JL_ESYNTAX);
            unsigned e = *j->p++;
            unsigned char one;
            switch (e) {
            case '"': case '\\': case '/':
                one = (unsigned char)e; emit(j, store, &one, 1); break;
            case 'b': one = '\b'; emit(j, store, &one, 1); break;
            case 'f': one = '\f'; emit(j, store, &one, 1); break;
            case 'n': one = '\n'; emit(j, store, &one, 1); break;
            case 'r': one = '\r'; emit(j, store, &one, 1); break;
            case 't': one = '\t'; emit(j, store, &one, 1); break;
            case 'u': {
                unsigned cp;
                if (hex4(j, &cp) != 0) return -1;
                if (cp >= 0xDC00 && cp <= 0xDFFF)       /* lone low half */
                    return fail(j, WEB_JL_EUTF8);
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (j->end - j->p < 2 || j->p[0] != '\\' || j->p[1] != 'u')
                        return fail(j, WEB_JL_EUTF8);
                    j->p += 2;
                    if (hex4(j, &lo) != 0) return -1;
                    if (lo < 0xDC00 || lo > 0xDFFF) return fail(j, WEB_JL_EUTF8);
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                if (cp == 0) return fail(j, WEB_JL_EUTF8);
                emit_cp(j, store, cp);
                break;
            }
            default:
                return fail(j, WEB_JL_ESYNTAX);
            }
            continue;
        }
        unsigned cp;
        size_t l = web_utf8_seq(j->p, (size_t)(j->end - j->p), &cp);
        if (l == 0) return fail(j, WEB_JL_EUTF8);
        emit(j, store, j->p, l);
        j->p += l;
    }
    if (store) {
        j->r->text[j->r->tlen] = '\0';
        *out = j->r->text + start;
        *olen = j->r->tlen - start;
        j->r->tlen++;
    }
    return 0;
}

/* RFC 8259 §6 number. *is_int when it has no fraction or exponent and
 * fits a long long. */
static int number(jp_t *j, long long *v, int *is_int) {
    int neg = 0, ok = 1;
    unsigned long long acc = 0;
    if (j->p < j->end && *j->p == '-') { neg = 1; j->p++; }
    if (j->p >= j->end) return fail(j, WEB_JL_ESYNTAX);
    if (*j->p == '0') {
        j->p++;
    } else if (*j->p >= '1' && *j->p <= '9') {
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9') {
            unsigned d = *j->p - '0';
            if (acc > (9223372036854775807ULL + (unsigned)neg - d) / 10) ok = 0;
            else acc = acc * 10 + d;
            j->p++;
        }
    } else {
        return fail(j, WEB_JL_ESYNTAX);
    }
    if (j->p < j->end && *j->p == '.') {
        ok = 0;
        j->p++;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9')
            return fail(j, WEB_JL_ESYNTAX);
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
    }
    if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
        ok = 0;
        j->p++;
        if (j->p < j->end && (*j->p == '+' || *j->p == '-')) j->p++;
        if (j->p >= j->end || *j->p < '0' || *j->p > '9')
            return fail(j, WEB_JL_ESYNTAX);
        while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
    }
    *is_int = ok;
    if (ok) {
        if (neg) *v = acc ? -(long long)(acc - 1) - 1 : 0;
        else     *v = (long long)acc;
    }
    return 0;
}

static int literal(jp_t *j, const char *w) {
    size_t n = strlen(w);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, w, n))
        return fail(j, WEB_JL_ESYNTAX);
    j->p += n;
    return 0;
}

static int value(jp_t *j, int depth, web_jfield_t *f);

static int container(jp_t *j, int depth) {
    if (depth >= WEB_JL_MAX_DEPTH) return fail(j, WEB_JL_EDEPTH);
    unsigned open = *j->p++;
    unsigned close = open == '{' ? '}' : ']';
    ws(j);
    if (j->p < j->end && *j->p == close) { j->p++; return 0; }
    for (;;) {
        ws(j);
        if (open == '{') {
            if (j->p >= j->end || *j->p != '"') return fail(j, WEB_JL_ESYNTAX);
            if (string(j, 0, NULL, NULL) != 0) return -1;
            ws(j);
            if (j->p >= j->end || *j->p != ':') return fail(j, WEB_JL_ESYNTAX);
            j->p++;
            ws(j);
        }
        if (value(j, depth + 1, NULL) != 0) return -1;
        ws(j);
        if (j->p >= j->end) return fail(j, WEB_JL_ESYNTAX);
        if (*j->p == ',') { j->p++; continue; }
        if (*j->p == close) { j->p++; return 0; }
        return fail(j, WEB_JL_ESYNTAX);
    }
}

/* One value. With f (a top-level member) a scalar is kept in it. */
static int value(jp_t *j, int depth, web_jfield_t *f) {
    if (j->p >= j->end) return fail(j, WEB_JL_ESYNTAX);
    unsigned c = *j->p;
    web_jfield_t dummy;
    if (!f) f = &dummy;
    f->str = NULL;
    f->slen = 0;
    f->i = 0;
    if (c == '"') {
        f->kind = WEB_J_STR;
        return string(j, f != &dummy, &f->str, &f->slen);
    }
    if (c == '{' || c == '[') {
        f->kind = WEB_J_NEST;
        return container(j, depth);
    }
    if (c == 't') { f->kind = WEB_J_BOOL; f->i = 1; return literal(j, "true"); }
    if (c == 'f') { f->kind = WEB_J_BOOL; return literal(j, "false"); }
    if (c == 'n') { f->kind = WEB_J_NULL; return literal(j, "null"); }
    int is_int;
    if (number(j, &f->i, &is_int) != 0) return -1;
    f->kind = is_int ? WEB_J_INT : WEB_J_REAL;
    return 0;
}

int web_jl_parse(const char *line, size_t len, web_jrec_t *r) {
    jp_t j;
    j.p = (const unsigned char *)line;
    j.end = j.p + len;
    j.r = r;
    j.err = 0;
    r->n = 0;
    r->tlen = 0;
    if (len > WEB_JL_MAX_LINE) return WEB_JL_ELONG;

    ws(&j);
    if (j.p >= j.end || *j.p != '{') return WEB_JL_ENOTOBJ;
    j.p++;
    ws(&j);
    if (j.p < j.end && *j.p == '}') {
        j.p++;
    } else {
        for (;;) {
            ws(&j);
            if (j.p >= j.end || *j.p != '"') return WEB_JL_ESYNTAX;
            if (r->n >= WEB_JL_MAX_FIELDS) return WEB_JL_EFIELDS;
            web_jfield_t *f = &r->f[r->n];
            size_t kl;
            if (string(&j, 1, &f->key, &kl) != 0) return j.err;
            for (int k = 0; k < r->n; k++)
                if (!strcmp(r->f[k].key, f->key)) return WEB_JL_EDUP;
            ws(&j);
            if (j.p >= j.end || *j.p != ':') return WEB_JL_ESYNTAX;
            j.p++;
            ws(&j);
            const char *key = f->key;
            if (value(&j, 1, f) != 0) return j.err;
            f->key = key;
            r->n++;
            ws(&j);
            if (j.p >= j.end) return WEB_JL_ESYNTAX;
            if (*j.p == ',') { j.p++; continue; }
            if (*j.p == '}') { j.p++; break; }
            return WEB_JL_ESYNTAX;
        }
    }
    ws(&j);
    if (j.p != j.end) return WEB_JL_ESYNTAX;
    const web_jfield_t *t = web_jl_get(r, "type");
    if (!t || t->kind != WEB_J_STR) return WEB_JL_ETYPE;
    return WEB_JL_OK;
}

const web_jfield_t *web_jl_get(const web_jrec_t *r, const char *key) {
    for (int i = 0; i < r->n; i++)
        if (!strcmp(r->f[i].key, key)) return &r->f[i];
    return NULL;
}

const char *web_jl_str(const web_jrec_t *r, const char *key) {
    const web_jfield_t *f = web_jl_get(r, key);
    return f && f->kind == WEB_J_STR ? f->str : NULL;
}

long long web_jl_int(const web_jrec_t *r, const char *key, long long def) {
    const web_jfield_t *f = web_jl_get(r, key);
    if (!f || (f->kind != WEB_J_INT && f->kind != WEB_J_BOOL)) return def;
    return f->i;
}

const char *web_jl_error_name(int e) {
    switch (e) {
    case WEB_JL_OK:      return "ok";
    case WEB_JL_ESYNTAX: return "syntax";
    case WEB_JL_EUTF8:   return "utf8";
    case WEB_JL_EDEPTH:  return "depth";
    case WEB_JL_EFIELDS: return "fields";
    case WEB_JL_ENOTOBJ: return "not_object";
    case WEB_JL_EDUP:    return "duplicate_key";
    case WEB_JL_ETYPE:   return "no_type";
    case WEB_JL_ELONG:   return "overlong";
    default:             return "?";
    }
}
