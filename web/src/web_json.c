#include "web_json.h"

#include <stdio.h>
#include <string.h>

void web_jw_init(web_jw_t *w, char *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = cap == 0;
    if (cap) buf[0] = '\0';
}

static void put(web_jw_t *w, const char *s, size_t n) {
    if (w->overflow) return;
    if (w->len + n >= w->cap) { w->overflow = 1; return; }
    memcpy(w->buf + w->len, s, n);
    w->len += n;
    w->buf[w->len] = '\0';
}

void web_jw_raw(web_jw_t *w, const char *s) { put(w, s, strlen(s)); }

size_t web_utf8_seq(const unsigned char *p, size_t n, unsigned *cp) {
    if (n == 0) return 0;
    unsigned c = p[0];
    if (c < 0x80) { *cp = c; return 1; }
    size_t need;
    unsigned v, lo = 0x80, hi = 0xBF;
    if (c >= 0xC2 && c <= 0xDF) {
        need = 2; v = c & 0x1F;
    } else if (c >= 0xE0 && c <= 0xEF) {
        need = 3; v = c & 0x0F;
        if (c == 0xE0) lo = 0xA0;        /* overlong */
        if (c == 0xED) hi = 0x9F;        /* surrogates */
    } else if (c >= 0xF0 && c <= 0xF4) {
        need = 4; v = c & 0x07;
        if (c == 0xF0) lo = 0x90;        /* overlong */
        if (c == 0xF4) hi = 0x8F;        /* past U+10FFFF */
    } else {
        return 0;                        /* C0, C1, F5..FF, stray continuation */
    }
    if (n < need) return 0;
    for (size_t i = 1; i < need; i++) {
        unsigned b = p[i];
        if (b < lo || b > hi) return 0;
        lo = 0x80; hi = 0xBF;
        v = (v << 6) | (b & 0x3F);
    }
    *cp = v;
    return need;
}

void web_jw_strn(web_jw_t *w, const char *s, size_t n) {
    const unsigned char *p = (const unsigned char *)s;
    char esc[8];
    put(w, "\"", 1);
    size_t i = 0;
    while (i < n) {
        unsigned cp;
        size_t l = web_utf8_seq(p + i, n - i, &cp);
        if (l == 0) { put(w, "\\ufffd", 6); i++; continue; }
        switch (cp) {
        case '"':  put(w, "\\\"", 2); break;
        case '\\': put(w, "\\\\", 2); break;
        case '\n': put(w, "\\n", 2);  break;
        case '\r': put(w, "\\r", 2);  break;
        case '\t': put(w, "\\t", 2);  break;
        default:
            if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F) ||
                cp == '<' || cp == '>' || cp == '&' || cp == '\'' ||
                cp == 0x2028 || cp == 0x2029) {
                snprintf(esc, sizeof(esc), "\\u%04x", cp);
                put(w, esc, 6);
            } else {
                put(w, s + i, l);
            }
        }
        i += l;
    }
    put(w, "\"", 1);
}

void web_jw_str(web_jw_t *w, const char *s) {
    if (!s) s = "";
    web_jw_strn(w, s, strlen(s));
}

void web_jw_int(web_jw_t *w, long long v) {
    char b[32];
    int n = snprintf(b, sizeof(b), "%lld", v);
    if (n > 0) put(w, b, (size_t)n);
}

void web_jw_key(web_jw_t *w, const char *k) {
    web_jw_str(w, k);
    put(w, ":", 1);
}

void web_utf8_copy(char *out, size_t max, const char *s) {
    size_t n = strlen(s);
    if (n > max) {
        n = max;
        /* s[n] is the first byte left out. If it continues a sequence,
         * the cut fell inside a code point: drop that code point. */
        while (n > 0 && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
    }
    memcpy(out, s, n);
    out[n] = '\0';
}
