/* Network-string hygiene (#138). Contract and rationale in netstr.h. */
#include "netstr.h"

#include <string.h>

size_t netstr_copy(char *dst, size_t dstsz, const uint8_t *src, size_t n) {
    if (!dst || dstsz == 0) return 0;
    size_t o = 0;
    if (src) {
        for (size_t i = 0; i < n && o + 1 < dstsz; i++) {
            uint8_t c = src[i];
            if (c == 0) break;
            dst[o++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
        }
    }
    dst[o] = '\0';
    return o;
}

void netstr_scrub(char *s) {
    if (!s) return;
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f) *s = '?';
    }
}

int netstr_utf8_decode(const uint8_t *s, size_t n, uint32_t *cp) {
    if (!s || n == 0) return 0;
    uint8_t b0 = s[0];
    if (b0 < 0x80) { *cp = b0; return 1; }

    int len;
    uint32_t v;
    uint8_t lo = 0x80, hi = 0xbf;      /* bounds on the second octet only */
    if (b0 >= 0xc2 && b0 <= 0xdf) {
        len = 2; v = b0 & 0x1fu;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
        len = 3; v = b0 & 0x0fu;
        if (b0 == 0xe0) lo = 0xa0;     /* overlong */
        if (b0 == 0xed) hi = 0x9f;     /* surrogates */
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
        len = 4; v = b0 & 0x07u;
        if (b0 == 0xf0) lo = 0x90;     /* overlong */
        if (b0 == 0xf4) hi = 0x8f;     /* above U+10FFFF */
    } else {
        return 0;                      /* 0x80..0xc1 (incl. C0/C1 overlong), 0xf5.. */
    }

    if ((size_t)len > n) return 0;
    for (int i = 1; i < len; i++) {
        uint8_t b = s[i];
        uint8_t l = (i == 1) ? lo : 0x80;
        uint8_t h = (i == 1) ? hi : 0xbf;
        if (b < l || b > h) return 0;
        v = (v << 6) | (uint32_t)(b & 0x3f);
    }
    *cp = v;
    return len;
}

int netstr_is_display_control(uint32_t cp) {
    if (cp < 0x20) return cp != '\n';
    if (cp == 0x7f) return 1;
    if (cp >= 0x80 && cp <= 0x9f) return 1;
    if (cp >= 0x202a && cp <= 0x202e) return 1;
    if (cp >= 0x2066 && cp <= 0x2069) return 1;
    return 0;
}

size_t display_sanitize(char *s) {
    if (!s) return 0;
    uint8_t *r = (uint8_t *)s, *w = (uint8_t *)s;
    size_t left = strlen(s), subs = 0;
    while (left > 0) {
        uint32_t cp = 0;
        int len = netstr_utf8_decode(r, left, &cp);
        if (len == 0) {                /* one bad octet, one '?' */
            *w++ = '?'; r++; left--; subs++;
            continue;
        }
        if (netstr_is_display_control(cp)) {
            *w++ = '?'; subs++;
        } else {
            if (w != r) memmove(w, r, (size_t)len);
            w += len;
        }
        r += len; left -= (size_t)len;
    }
    *w = '\0';
    return subs;
}
