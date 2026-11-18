#include "mcp_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── the reader ────────────────────────────────────────────────────── */

typedef struct {
    mj_doc_t   *d;
    const char *p, *end;
    int         depth, bad;
} jp_t;

static int parse_value(jp_t *j);

static int at(const jp_t *j) { return j->p < j->end ? (unsigned char)*j->p : -1; }

static void skip_ws(jp_t *j) {
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\n' || *j->p == '\r'))
        j->p++;
}

static int new_node(jp_t *j, mj_type_t t) {
    if (j->d->n >= MJ_MAX_NODES) { j->bad = 1; return -1; }
    int i = j->d->n++;
    mj_node_t *nd = &j->d->nodes[i];
    nd->type = t;
    nd->str = nd->key = -1;
    nd->slen = 0;
    nd->num = 0;
    nd->boolean = 0;
    nd->child = nd->next = -1;
    return i;
}

static int put(jp_t *j, unsigned char c) {
    if (j->d->tlen + 1 >= MJ_MAX_TEXT) { j->bad = 1; return -1; }
    j->d->text[j->d->tlen++] = (char)c;
    return 0;
}

/* Four hex digits at p, or -1. */
static int hex4(const jp_t *j, const char *p) {
    int v = 0;
    if (j->end - p < 4) return -1;
    for (int k = 0; k < 4; k++) {
        char h = p[k];
        int x;
        if      (h >= '0' && h <= '9') x = h - '0';
        else if (h >= 'a' && h <= 'f') x = h - 'a' + 10;
        else if (h >= 'A' && h <= 'F') x = h - 'A' + 10;
        else return -1;
        v = (v << 4) | x;
    }
    return v;
}

static int put_utf8(jp_t *j, unsigned cp) {
    if (cp < 0x80) return put(j, (unsigned char)cp);
    if (cp < 0x800)
        return put(j, (unsigned char)(0xC0 | (cp >> 6))) || put(j, (unsigned char)(0x80 | (cp & 0x3F)));
    if (cp < 0x10000)
        return put(j, (unsigned char)(0xE0 | (cp >> 12))) ||
               put(j, (unsigned char)(0x80 | ((cp >> 6) & 0x3F))) ||
               put(j, (unsigned char)(0x80 | (cp & 0x3F)));
    return put(j, (unsigned char)(0xF0 | (cp >> 18))) ||
           put(j, (unsigned char)(0x80 | ((cp >> 12) & 0x3F))) ||
           put(j, (unsigned char)(0x80 | ((cp >> 6) & 0x3F))) ||
           put(j, (unsigned char)(0x80 | (cp & 0x3F)));
}

/* The offset of the decoded string in doc->text (NUL-terminated there),
 * its length into *len; -1 on error. */
static int parse_string(jp_t *j, int *len) {
    if (at(j) != '"') { j->bad = 1; return -1; }
    j->p++;
    int start = j->d->tlen;
    for (;;) {
        int c = at(j);
        if (c < 0) { j->bad = 1; return -1; }
        if (c == '"') { j->p++; break; }
        /* A raw control character is not legal inside a JSON string
         * (RFC 8259 section 7), and over a newline-delimited transport
         * a raw newline in an argument could not be told from the end
         * of the request. */
        if (c < 0x20) { j->bad = 1; return -1; }
        if (c != '\\') {
            if (put(j, (unsigned char)c)) return -1;
            j->p++;
            continue;
        }
        j->p++;
        int e = at(j);
        int out = -1;
        switch (e) {
        case '"':  out = '"';  break;
        case '\\': out = '\\'; break;
        case '/':  out = '/';  break;
        case 'b':  out = '\b'; break;
        case 'f':  out = '\f'; break;
        case 'n':  out = '\n'; break;
        case 'r':  out = '\r'; break;
        case 't':  out = '\t'; break;
        case 'u': {
            int hi = hex4(j, j->p + 1);
            if (hi < 0) { j->bad = 1; return -1; }
            j->p += 5;
            unsigned cp = (unsigned)hi;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                /* A high surrogate is half a character: its low half
                 * must follow, or the string is not text. */
                int lo = j->end - j->p >= 6 && j->p[0] == '\\' && j->p[1] == 'u' ? hex4(j, j->p + 2) : -1;
                if (lo < 0xDC00 || lo > 0xDFFF) { j->bad = 1; return -1; }
                cp = 0x10000 + ((cp - 0xD800) << 10) + ((unsigned)lo - 0xDC00);
                j->p += 6;
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                j->bad = 1;
                return -1;
            }
            /* The text is handed on as C strings: an escaped NUL would
             * end one early and hide what follows it. */
            if (cp == 0) { j->bad = 1; return -1; }
            if (put_utf8(j, cp)) return -1;
            continue;
        }
        default: j->bad = 1; return -1;
        }
        j->p++;
        if (put(j, (unsigned char)out)) return -1;
    }
    *len = j->d->tlen - start;
    if (j->d->tlen + 1 > MJ_MAX_TEXT) { j->bad = 1; return -1; }
    j->d->text[j->d->tlen++] = '\0';
    return start;
}

static int lit(jp_t *j, const char *word) {
    size_t n = strlen(word);
    if ((size_t)(j->end - j->p) < n || memcmp(j->p, word, n) != 0) { j->bad = 1; return 0; }
    j->p += n;
    return 1;
}

static void parse_members(jp_t *j, int parent, char close, int keyed) {
    j->p++;                                   /* '{' or '[' */
    skip_ws(j);
    if (at(j) == close) { j->p++; return; }
    int last = -1;
    for (;;) {
        int key = -1, klen = 0;
        if (keyed) {
            skip_ws(j);
            key = parse_string(j, &klen);
            if (j->bad) return;
            skip_ws(j);
            if (at(j) != ':') { j->bad = 1; return; }
            j->p++;
        }
        int kid = parse_value(j);
        if (j->bad) return;
        j->d->nodes[kid].key = key;
        if (last < 0) j->d->nodes[parent].child = kid;
        else          j->d->nodes[last].next    = kid;
        last = kid;
        skip_ws(j);
        if (at(j) == ',') { j->p++; continue; }
        if (at(j) == close) { j->p++; return; }
        j->bad = 1;
        return;
    }
}

/* A JSON number at p: its length, or 0. strtod alone takes "inf",
 * "nan", hex, a leading '+' and leading zeros, none of which is JSON,
 * and reads past the buffer's end when it is not NUL-terminated; so
 * the grammar is walked here and strtod sees a bounded copy. */
static size_t number_len(const char *p, const char *end) {
    const char *q = p;
    if (q < end && *q == '-') q++;
    if (q >= end || *q < '0' || *q > '9') return 0;
    if (*q == '0') q++;
    else while (q < end && *q >= '0' && *q <= '9') q++;
    if (q < end && *q == '.') {
        q++;
        if (q >= end || *q < '0' || *q > '9') return 0;
        while (q < end && *q >= '0' && *q <= '9') q++;
    }
    if (q < end && (*q == 'e' || *q == 'E')) {
        q++;
        if (q < end && (*q == '+' || *q == '-')) q++;
        if (q >= end || *q < '0' || *q > '9') return 0;
        while (q < end && *q >= '0' && *q <= '9') q++;
    }
    return (size_t)(q - p);
}

static int parse_value(jp_t *j) {
    skip_ws(j);
    if (++j->depth > MJ_MAX_DEPTH) { j->bad = 1; return -1; }
    int idx = -1;
    switch (at(j)) {
    case '{':
        idx = new_node(j, MJ_OBJ);
        if (idx >= 0) parse_members(j, idx, '}', 1);
        break;
    case '[':
        idx = new_node(j, MJ_ARR);
        if (idx >= 0) parse_members(j, idx, ']', 0);
        break;
    case '"': {
        int len = 0, s = parse_string(j, &len);
        if (j->bad) break;
        idx = new_node(j, MJ_STR);
        if (idx >= 0) { j->d->nodes[idx].str = s; j->d->nodes[idx].slen = len; }
        break;
    }
    case 't':
        if (lit(j, "true"))  { idx = new_node(j, MJ_BOOL);
                               if (idx >= 0) j->d->nodes[idx].boolean = 1; }
        break;
    case 'f':
        if (lit(j, "false")) idx = new_node(j, MJ_BOOL);
        break;
    case 'n':
        if (lit(j, "null"))  idx = new_node(j, MJ_NULL);
        break;
    default: {
        char tmp[48];
        size_t n = number_len(j->p, j->end);
        if (n == 0 || n >= sizeof(tmp)) { j->bad = 1; break; }
        memcpy(tmp, j->p, n);
        tmp[n] = '\0';
        j->p += n;
        idx = new_node(j, MJ_NUM);
        if (idx >= 0) j->d->nodes[idx].num = strtod(tmp, NULL);
        break;
    }
    }
    j->depth--;
    if (idx < 0) j->bad = 1;
    return idx;
}

int mj_parse(mj_doc_t *d, const char *src, size_t n) {
    if (!d || !src) return -1;
    d->n = 0;
    d->tlen = 0;
    jp_t j = { d, src, src + n, 0, 0 };
    int root = parse_value(&j);
    if (j.bad || root != 0) return -1;
    skip_ws(&j);
    /* Trailing content is an error: over a newline-delimited transport
     * two values on one line mean the framing has already gone wrong. */
    return j.p == j.end ? 0 : -1;
}

int mj_get(const mj_doc_t *d, int obj, const char *key) {
    if (!d || !key || obj < 0 || obj >= d->n) return -1;
    if (d->nodes[obj].type != MJ_OBJ) return -1;
    for (int i = d->nodes[obj].child; i >= 0; i = d->nodes[i].next) {
        int k = d->nodes[i].key;
        if (k >= 0 && strcmp(&d->text[k], key) == 0) return i;
    }
    return -1;
}

const char *mj_str(const mj_doc_t *d, int node) {
    if (!d || node < 0 || node >= d->n) return NULL;
    if (d->nodes[node].type != MJ_STR) return NULL;
    return &d->text[d->nodes[node].str];
}

double mj_num(const mj_doc_t *d, int node, double dflt) {
    if (!d || node < 0 || node >= d->n) return dflt;
    if (d->nodes[node].type != MJ_NUM) return dflt;
    return d->nodes[node].num;
}

/* ── the appender ──────────────────────────────────────────────────── */

void mj_sb_init(mj_sb_t *s, char *buf, size_t cap) {
    s->buf = buf;
    s->cap = cap;
    s->len = 0;
    s->over = cap == 0;
    if (cap) buf[0] = '\0';
}

void mj_sb_rawn(mj_sb_t *s, const char *str, size_t n) {
    if (s->over) return;
    if (n >= s->cap - s->len) { s->over = 1; return; }
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}

void mj_sb_raw(mj_sb_t *s, const char *str) { mj_sb_rawn(s, str, strlen(str)); }

void mj_sb_int(mj_sb_t *s, long long v) {
    char t[32];
    int n = snprintf(t, sizeof(t), "%lld", v);
    if (n > 0) mj_sb_rawn(s, t, (size_t)n);
}

void mj_sb_strn(mj_sb_t *s, const char *str, size_t n) {
    static const char hex[] = "0123456789abcdef";
    mj_sb_rawn(s, "\"", 1);
    for (size_t i = 0; i < n && !s->over; i++) {
        unsigned char c = (unsigned char)str[i];
        char e[6];
        if (c == '"' || c == '\\') {
            e[0] = '\\'; e[1] = (char)c;
            mj_sb_rawn(s, e, 2);
        } else if (c < 0x20) {
            e[0] = '\\'; e[1] = 'u'; e[2] = '0'; e[3] = '0';
            e[4] = hex[c >> 4]; e[5] = hex[c & 0xF];
            mj_sb_rawn(s, e, 6);
        } else {
            mj_sb_rawn(s, (const char *)&str[i], 1);
        }
    }
    mj_sb_rawn(s, "\"", 1);
}

void mj_sb_str(mj_sb_t *s, const char *str) {
    if (!str) str = "";
    mj_sb_strn(s, str, strlen(str));
}

/* ── the copier ────────────────────────────────────────────────────── */

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

/* One string, in[*i] its opening quote: copied in its escaped form, at
 * most strcap bytes of it, whole units only (an escape, a UTF-8
 * sequence), then the mark. 0, or -1 malformed. */
static int copy_string(const char *in, size_t n, size_t *i, mj_sb_t *o, size_t strcap, int *cut) {
    size_t p = *i + 1, kept = 0;
    int cutting = 0;
    mj_sb_rawn(o, "\"", 1);
    for (;;) {
        if (p >= n) return -1;
        unsigned char c = (unsigned char)in[p];
        if (c == '"') break;
        if (c < 0x20) return -1;
        size_t unit = 1;
        if (c == '\\') {
            if (p + 1 >= n) return -1;
            char e = in[p + 1];
            if (e == 'u') {
                if (p + 5 >= n || !is_hex(in[p + 2]) || !is_hex(in[p + 3]) || !is_hex(in[p + 4]) ||
                    !is_hex(in[p + 5]))
                    return -1;
                unit = 6;
            } else if (e == '"' || e == '\\' || e == '/' || e == 'b' || e == 'f' || e == 'n' ||
                       e == 'r' || e == 't') {
                unit = 2;
            } else {
                return -1;
            }
        } else if (c >= 0x80) {
            /* A UTF-8 sequence is kept or dropped whole: its lead byte
             * and the continuation bytes after it. */
            while (p + unit < n && ((unsigned char)in[p + unit] & 0xC0) == 0x80 && unit < 4) unit++;
        }
        if (!cutting && kept + unit > strcap) {
            cutting = 1;
            if (cut) (*cut)++;
        }
        if (!cutting) {
            mj_sb_rawn(o, in + p, unit);
            kept += unit;
        }
        p += unit;
    }
    if (cutting) mj_sb_raw(o, MJ_CUT_MARK);
    mj_sb_rawn(o, "\"", 1);
    *i = p + 1;
    return 0;
}

int mj_copy(const char *in, size_t n, mj_sb_t *o, size_t strcap, int *cut) {
    enum { VAL, VAL_OR_END, KEY, KEY_OR_END, COLON, AFTER };
    char stack[MJ_COPY_DEPTH];
    int depth = 0, state = VAL, done = 0;
    size_t i = 0;
    if (cut) *cut = 0;
    for (;;) {
        while (i < n && (in[i] == ' ' || in[i] == '\t' || in[i] == '\n' || in[i] == '\r')) i++;
        if (i >= n) break;
        char c = in[i];
        switch (state) {
        case VAL_OR_END:
            if (c == ']') { depth--; mj_sb_rawn(o, "]", 1); i++; state = AFTER; break; }
            /* fall through */
        case VAL:
            if (c == '{' || c == '[') {
                if (depth >= MJ_COPY_DEPTH) return -1;
                stack[depth++] = c;
                mj_sb_rawn(o, &c, 1);
                i++;
                state = c == '{' ? KEY_OR_END : VAL_OR_END;
            } else if (c == '"') {
                if (copy_string(in, n, &i, o, strcap, cut) != 0) return -1;
                state = AFTER;
            } else if (c == 't' || c == 'f' || c == 'n') {
                const char *w = c == 't' ? "true" : c == 'f' ? "false" : "null";
                size_t wl = strlen(w);
                if (n - i < wl || memcmp(in + i, w, wl) != 0) return -1;
                mj_sb_rawn(o, w, wl);
                i += wl;
                state = AFTER;
            } else {
                size_t l = number_len(in + i, in + n);
                if (l == 0) return -1;
                mj_sb_rawn(o, in + i, l);
                i += l;
                state = AFTER;
            }
            break;
        case KEY_OR_END:
            if (c == '}') { depth--; mj_sb_rawn(o, "}", 1); i++; state = AFTER; break; }
            /* fall through */
        case KEY:
            if (c != '"' || copy_string(in, n, &i, o, strcap, cut) != 0) return -1;
            state = COLON;
            break;
        case COLON:
            if (c != ':') return -1;
            mj_sb_rawn(o, ":", 1);
            i++;
            state = VAL;
            break;
        default: /* AFTER */
            if (depth == 0) return -1;                 /* something after the value */
            if (c == ',') {
                mj_sb_rawn(o, ",", 1);
                i++;
                state = stack[depth - 1] == '{' ? KEY : VAL;
            } else if ((c == '}' && stack[depth - 1] == '{') || (c == ']' && stack[depth - 1] == '[')) {
                depth--;
                mj_sb_rawn(o, &c, 1);
                i++;
            } else {
                return -1;
            }
            break;
        }
        if (state == AFTER && depth == 0) done = 1;
        if (o->over) return -2;
    }
    if (!done || depth != 0 || state != AFTER) return -1;
    return o->over ? -2 : 0;
}
