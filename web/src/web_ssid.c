#include "web_ssid.h"

#include <stdio.h>
#include <string.h>

static int printable(unsigned cp) {
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) return 0;
    if (cp == 0xad || cp == 0x61c || cp == 0x180e) return 0;
    if (cp >= 0x200b && cp <= 0x200f) return 0;
    if (cp >= 0x2028 && cp <= 0x202e) return 0;
    if (cp >= 0x2060 && cp <= 0x2064) return 0;
    if (cp >= 0x2066 && cp <= 0x206f) return 0;
    if (cp >= 0xe000 && cp <= 0xf8ff) return 0;
    if (cp >= 0xfdd0 && cp <= 0xfdef) return 0;
    if (cp == 0xfeff) return 0;
    if (cp >= 0xfff9 && cp <= 0xfffb) return 0;
    if (cp == 0xfffd) return 0;
    if ((cp & 0xfffe) == 0xfffe) return 0;
    if (cp >= 0xe0000 && cp <= 0xe007f) return 0;
    if (cp >= 0xf0000) return 0;
    return 1;
}

size_t web_ssid_escape(const char *s, size_t n, char *out, size_t cap,
                       int *np) {
    const unsigned char *p = (const unsigned char *)s;
    size_t o = 0, i = 0;
    int esc = 0;
    if (np) *np = 0;
    if (!cap) return 0;
    while (i < n) {
        unsigned cp = 0;
        size_t l = web_utf8_seq(p + i, n - i, &cp);
        if (l && printable(cp)) {
            if (cp == '\\') {
                if (o + 2 >= cap) break;
                out[o++] = '\\';
                out[o++] = '\\';
            } else {
                if (o + l >= cap) break;
                memcpy(out + o, p + i, l);
                o += l;
            }
            i += l;
            continue;
        }
        /* Every octet of a sequence that is not printable; an octet
         * that starts no sequence on its own. */
        if (!l) l = 1;
        if (o + 4 * l >= cap) break;
        for (size_t k = 0; k < l; k++) {
            static const char hx[] = "0123456789abcdef";
            out[o++] = '\\';
            out[o++] = 'x';
            out[o++] = hx[p[i + k] >> 4];
            out[o++] = hx[p[i + k] & 15];
        }
        esc = 1;
        i += l;
    }
    out[o] = '\0';
    if (np) *np = esc;
    return o;
}

int web_ssid_color(const char *s) {
    if (!s || !s[0]) return 0;
    unsigned long h = 5381;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        h = (((h << 5) + h) + *p) & 0xffffffffUL;
    return (int)(h % 8UL);
}

void web_jw_ssid(web_jw_t *w, const char *s) {
    if (!s || !s[0]) { web_jw_raw(w, "null"); return; }
    char d[WEB_SSID_IN_MAX * WEB_SSID_EXPAND + 1];
    size_t n = web_ssid_escape(s, strnlen(s, WEB_SSID_IN_MAX), d, sizeof(d), NULL);
    web_jw_strn(w, d, n);
}

void web_jw_ssid_meta(web_jw_t *w, const char *name, const char *s) {
    char d[WEB_SSID_IN_MAX * WEB_SSID_EXPAND + 1];
    int np = 0;
    if (s && s[0])
        web_ssid_escape(s, strnlen(s, WEB_SSID_IN_MAX), d, sizeof(d), &np);
    web_jw_raw(w, ",\"");
    web_jw_raw(w, name);
    web_jw_raw(w, "_k\":");
    web_jw_int(w, web_ssid_color(s));
    web_jw_raw(w, ",\"");
    web_jw_raw(w, name);
    web_jw_raw(w, "_np\":");
    web_jw_raw(w, np ? "true" : "false");
}
